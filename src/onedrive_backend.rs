use std::fs;
use std::io::Write;
use std::path::{Path, PathBuf};
use std::time::Duration;

use anyhow::{ensure, Context, Result};
use bytes::Bytes;
use futures_util::{Stream, TryFutureExt, TryStreamExt};
use onedrive_api::option::ObjectOption;
use onedrive_api::resource::DriveItemField;
use onedrive_api::{Auth, DriveLocation, FileName, ItemLocation, OneDrive, Permission};
use reqwest::{header, Client, StatusCode};
use serde::{de, Deserialize, Serialize};

use crate::service::Backend;

const USER_AGENT: &str = concat!(env!("CARGO_PKG_NAME"), "/", env!("CARGO_PKG_VERSION"));
const XDG_STATE_DIR_NAME: &str = env!("CARGO_PKG_NAME");
const CREDENTIAL_FILE_NAME: &str = "credential.json";

#[derive(Debug, Clone, PartialEq, Eq, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Config {
    #[serde(deserialize_with = "de_remote_dir")]
    remote_dir: String,
    #[serde(default = "default_state_dir")]
    state_dir: PathBuf,
    #[serde(default = "default_timeout")]
    connect_timeout_sec: u64,
}

fn default_timeout() -> u64 {
    15
}

fn de_remote_dir<'de, D: de::Deserializer<'de>>(de: D) -> Result<String, D::Error> {
    let path = String::deserialize(de)?;
    if ItemLocation::from_path(&path).is_none() {
        return Err(de::Error::custom("invalid path"));
    }
    if path == "/" {
        return Err(de::Error::custom("must not be root"));
    }
    Ok(path)
}

fn default_state_dir() -> PathBuf {
    if let Ok(dir) = std::env::var("STATE_DIRECTORY") {
        return dir.into();
    }
    dirs::state_dir()
        .expect("failed to get XDG state directory")
        .join(XDG_STATE_DIR_NAME)
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct Credential {
    read_write: bool,
    refresh_token: String,
    redirect_uri: String,
    client_id: String,
    client_secret: Option<String>,
}

pub fn init(config: &Config, rt: &tokio::runtime::Runtime) -> Result<Remote> {
    fs::create_dir_all(&config.state_dir)
        .with_context(|| format!("failed to create {}", config.state_dir.display()))?;

    let client = Client::builder()
        // Required by `OneDrive::get_item_download_url`.
        .redirect(reqwest::redirect::Policy::none())
        // This should have no effect on non-JSON responses like downloading ones.
        .gzip(true)
        // Enforce HTTPS for security.
        .https_only(true)
        .user_agent(USER_AGENT)
        .connect_timeout(Duration::from_secs(config.connect_timeout_sec))
        .build()
        .context("failed to build reqwest client")?;

    let access_token = {
        let cred_path = config.state_dir.join(CREDENTIAL_FILE_NAME);
        let mut cred = (|| -> Result<Credential> {
            let content = fs::read_to_string(&cred_path)?;
            Ok(serde_json::from_str(&content)?)
        })()
        .context("failed to load credentials, have you manually it setup?")?;

        log::info!("logining...");
        let perm = Permission::new_read()
            .write(cred.read_write)
            .offline_access(true);
        let auth = Auth::new_with_client(client.clone(), &cred.client_id, perm, &cred.redirect_uri);
        let resp = rt
            .block_on(
                auth.login_with_refresh_token(&cred.refresh_token, cred.client_secret.as_deref()),
            )
            .context("failed to login")?;

        cred.refresh_token = resp.refresh_token.context("missing new refresh token")?;
        safe_write(&cred_path, &cred).context("failed to update refresh token")?;
        resp.access_token
    };
    let drive = OneDrive::new_with_client(client.clone(), access_token, DriveLocation::me());

    // TODO: Geometry validation.
    let remote_dir_id = rt.block_on(async {
        match drive
            .get_item_with_option(
                ItemLocation::from_path(&config.remote_dir).unwrap(),
                ObjectOption::new().select(&[DriveItemField::id]),
            )
            .await
        {
            Ok(item) => item.context("no response")?.id.context("missing id"),
            Err(err) if err.status_code() == Some(StatusCode::NOT_FOUND) => {
                log::info!("remote directory does not exist, creating...");
                let pos = config.remote_dir.rfind('/').unwrap() + 1;
                let parent = ItemLocation::from_path(&config.remote_dir[..pos]).unwrap();
                let child = FileName::new(&config.remote_dir[pos..]).unwrap();
                drive
                    .create_folder(parent, child)
                    .await
                    .context("failed to create remote directory")?
                    .id
                    .context("missing id in creation response")
            }
            Err(err) => Err(err.into()),
        }
    })?;
    log::info!("remote directory id: {}", remote_dir_id.0);

    Ok(Remote::new(drive, config.remote_dir.clone()))
}

/// Write to the file with crash safety, and prevent non-owners from reading.
fn safe_write(path: &Path, data: &impl Serialize) -> Result<()> {
    use std::os::unix::fs::OpenOptionsExt;

    let tmp_path = path.with_extension("tmp");
    {
        let bytes = serde_json::to_vec(data)?;
        let mut f = fs::OpenOptions::new()
            .create(true)
            .write(true)
            .truncate(true)
            // rw-------
            .mode(0o600)
            .open(&tmp_path)?;
        f.write_all(&bytes)?;
        f.sync_data()?;
    }
    fs::rename(tmp_path, path)?;
    Ok(())
}

pub struct Remote {
    drive: OneDrive,
    root_dir: String,
}

impl Remote {
    fn new(drive: OneDrive, root_dir: String) -> Self {
        assert!(root_dir.starts_with('/') && !root_dir.ends_with('/'));
        Self { drive, root_dir }
    }

    fn chunk_path(&self, zid: u32, coff: u32) -> String {
        format!("{}/zones/z{:06x}/c{:08x}", self.root_dir, zid, coff)
    }

    fn zone_path(&self, zid: u32) -> String {
        format!("{}/zones/z{:06x}", self.root_dir, zid)
    }

    fn all_zones_dir_path(&self) -> String {
        format!("{}/zones", self.root_dir)
    }
}

impl Backend for Remote {
    fn download_chunk(
        &self,
        zid: u32,
        coff: u32,
        read_offset: u64,
    ) -> impl Stream<Item = Result<Bytes>> + Send + 'static {
        let drive = OneDrive::new_with_client(
            self.drive.client().clone(),
            self.drive.access_token().to_owned(),
            DriveLocation::me(),
        );
        let path = self.chunk_path(zid, coff);
        let fut = async move {
            log::debug!("downloading chunk {path} starting at {read_offset}B");

            let url = drive
                .get_item_download_url(ItemLocation::from_path(&path).unwrap())
                .await?;

            let range = format!("bytes={}-", read_offset);
            let resp = drive
                .client()
                .get(url)
                .header(header::RANGE, range)
                .send()
                .await?;
            resp.error_for_status_ref()?;
            if read_offset != 0 {
                ensure!(
                    resp.status() == StatusCode::PARTIAL_CONTENT,
                    "response is not partial, got {}",
                    resp.status(),
                );
            }

            // TODO: Retry?
            Ok(resp.bytes_stream().map_err(anyhow::Error::from))
        };
        fut.try_flatten_stream()
    }

    async fn upload_chunk(&self, zid: u32, coff: u32, data: Bytes) -> Result<()> {
        let path = self.chunk_path(zid, coff);
        log::debug!("uploading chunk {path} with {}B", data.len());
        self.drive
            .upload_small(ItemLocation::from_path(&path).unwrap(), data)
            .await?;
        Ok(())
    }

    async fn delete_zone(&self, zid: u64) -> Result<()> {
        let path = self.zone_path(zid as u32);
        log::debug!("deleting {path}");
        self.drive
            .delete(ItemLocation::from_path(&path).unwrap())
            .await?;
        Ok(())
    }

    async fn delete_all_zones(&self) -> Result<()> {
        let path = self.all_zones_dir_path();
        log::debug!("deleting all {path}");
        self.drive
            .delete(ItemLocation::from_path(&path).unwrap())
            .await?;
        Ok(())
    }
}
