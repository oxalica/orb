use std::collections::{BTreeMap, HashMap};
use std::future::{ready, Future};
use std::hash::Hash;
use std::io::Write;
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::Arc;
use std::time::{Duration, SystemTime};
use std::{fmt, fs, mem};

use anyhow::{anyhow, bail, ensure, Context, Result};
use bytes::Bytes;
use bytesize::ByteSize;
use futures_util::{Stream, StreamExt, TryFutureExt, TryStreamExt};
use itertools::Itertools;
use onedrive_api::option::{CollectionOption, DriveItemPutOption};
use onedrive_api::resource::DriveItemField;
use onedrive_api::{
    Auth, ClientCredential, ConflictBehavior, DriveLocation, ItemId, ItemLocation, OneDrive,
    Permission, Tag, Tenant,
};
use parking_lot::Mutex;
use reqwest::{header, Client, StatusCode};
use serde::{de, Deserialize, Serialize};
use serde_inline_default::serde_inline_default;

use crate::service::Backend;

pub mod login;

/// In <https://learn.microsoft.com/en-us/graph/api/driveitem-get-content?view=graph-rest-1.0&tabs=http#response>:
///
/// > Preauthenticated download URLs are only valid for a short period of time (a few minutes) and
/// > don't require an Authorization header to download.
///
/// Though it's discouraged to cache them, we still do it for a relatively safe time (60s) to
/// avoid mass API calls which are rate limited.
const URL_CACHE_DURATION: Duration = Duration::from_secs(60);

const DELTA_PAGE_SIZE: usize = 10_000;

// When Retry-After is specified, it is always used. Otherwise, we first use the default delay,
// then do exponential backoff (2x), thus the wait times are: 1s, 2s, 4s, 8s, 16s.
const SERVER_ERROR_RETRY_CNT: usize = 5;
const SERVER_ERROR_RETRY_DEFAULT_DELAY: Duration = Duration::from_secs(1);

/// Chunks smaller than this is uploaded via upload-small API, otherwise session upload API is
/// used. The maximum valid value is not known. Two documentation sources give conflict results.
/// - 250MB: <https://learn.microsoft.com/en-us/graph/api/driveitem-put-content?view=graph-rest-1.0&tabs=http>
/// - 4MB: <https://learn.microsoft.com/en-us/onedrive/developer/rest-api/api/driveitem_put_content?view=odsp-graph-online>
///
/// Note that the session upload API has higher bandwidth limit than main Microsoft Graph API.
/// We should prefer that unless the request lattency is an issue (session upload requires at least
/// 2 requests per file).
const SESSION_UPLOAD_THRESHOLD: usize = 4_000_000;
const SESSION_UPLOAD_MAX_PART_SIZE: usize = 60 << 20; // 60MiB, aligned to 320KiB.
const SESSION_UPLOAD_ALIGN: usize = 320 << 10; // 320KiB

const USER_AGENT: &str = concat!(env!("CARGO_PKG_NAME"), "/", env!("CFG_RELEASE"));
const XDG_STATE_DIR_NAME: &str = env!("CARGO_PKG_NAME");
/// User's initial refresh token. This is read-only.
const USER_CREDENTIAL_FILE_NAME: &str = "credential.json";
/// Auto-refreshed tokens. On starting, this is used instead if it's `init_time` is newer than
/// `CREDENTIAL_FILE_NAME`'s one.
const AUTO_CREDENTIAL_FILE_NAME: &str = "credential.auto.json";
const STATE_FILE_NAME: &str = "state.json";

const GEOMETRY_FILE_NAME: &str = "geometry.json";
const LOCK_FILE_NAME: &str = "lock.json";

#[serde_inline_default]
#[derive(Debug, Clone, PartialEq, Eq, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Config {
    #[serde(deserialize_with = "de_remote_dir")]
    remote_dir: String,
    #[serde(default = "default_state_dir")]
    state_dir: PathBuf,
    #[serde_inline_default(15)]
    connect_timeout_sec: u64,

    #[serde(deserialize_with = "de_part_max_size")]
    #[serde_inline_default(SESSION_UPLOAD_MAX_PART_SIZE)]
    upload_part_max_size: usize,
}

fn de_part_max_size<'de, D: de::Deserializer<'de>>(de: D) -> Result<usize, D::Error> {
    let size = ByteSize::deserialize(de)?.0;
    Ok((size.clamp(
        SESSION_UPLOAD_THRESHOLD as u64,
        SESSION_UPLOAD_MAX_PART_SIZE as u64,
    ) as usize)
        .next_multiple_of(SESSION_UPLOAD_ALIGN))
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

#[serde_inline_default]
#[derive(Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct Credential {
    // For compatibility.
    #[serde_inline_default(SystemTime::UNIX_EPOCH)]
    init_time: SystemTime,
    read_write: bool,
    refresh_token: String,
    redirect_uri: String,
    client_id: String,
}

impl Credential {
    async fn login(&mut self, client: Client) -> Result<(String, SystemTime)> {
        let perm = Permission::new_read()
            .write(self.read_write)
            .offline_access(true);
        let auth = Auth::new_with_client(
            client,
            &self.client_id,
            perm,
            &self.redirect_uri,
            Tenant::Consumers,
        );
        let login_time = SystemTime::now();
        let mut resp = retry_request(|| {
            auth.login_with_refresh_token(&self.refresh_token, &ClientCredential::None)
        })
        .await
        .context("failed to login")?;
        self.refresh_token = resp
            .refresh_token
            .take()
            .context("missing new refresh token")?;
        let expire_time = login_time + Duration::from_secs(resp.expires_in_secs);
        tracing::info!(
            expire.secs = resp.expires_in_secs,
            expire.time = %humantime::format_rfc3339_seconds(expire_time),
            "logined",
        );
        Ok((resp.access_token, expire_time))
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct Geometry {
    dev_size: u64,
    zone_size: u64,
}

/// The version of chunks state file. When the saved state file has an older version, it would be
/// dropped and metadata is re-enumerated (`track_root_changes_from_initial`).
#[derive(Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
enum WithVersion<T> {
    #[serde(rename = "V1")]
    Inner(T),
}

#[derive(Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct ChunksState {
    delta_url: String,
    root_dir_id: String,
    zones_dir_id: Option<String>,
    items: BTreeMap<String, RemoteItem>,
}

#[derive(Debug, Clone, Copy, Serialize, Deserialize)]
enum RemoteItem {
    Zone { zid: u32 },
    Chunk { zid: u32, coff: u32, size: u64 },
}

impl ChunksState {
    const SELECT_FIELDS: &'static [DriveItemField] = &[
        DriveItemField::id,
        DriveItemField::name,
        DriveItemField::size,
        DriveItemField::parent_reference,
        DriveItemField::file,
        DriveItemField::folder,
        DriveItemField::deleted,
        DriveItemField::root,
    ];

    async fn fetch_and_parse(
        drive: &OneDrive,
        root_dir_id: String,
        prev_state: Option<Self>,
    ) -> Result<Self> {
        let do_incremental = if let Some(Self {
            delta_url,
            root_dir_id: prev_root_id,
            zones_dir_id,
            items,
            ..
        }) = prev_state
        {
            if prev_root_id == root_dir_id {
                tracing::info!("fetching incremental changes");
                match drive.track_root_changes_from_delta_url(&delta_url).await {
                    Ok(fetcher) => Some((fetcher, zones_dir_id, items)),
                    // The documentation says it would return "410 Gone" when re-synchronization is
                    // required. In practice, this may also return:
                    // `400 Bad Request: (invalidRequest) One of the provided arguments is not acceptable.`
                    Err(err)
                        if matches!(
                            err.status_code(),
                            Some(StatusCode::GONE | StatusCode::BAD_REQUEST)
                        ) =>
                    {
                        tracing::info!("delta url gone, re-enumeration is required");
                        None
                    }
                    Err(err) => return Err(err.into()),
                }
            } else {
                tracing::warn!("remote directory changed, re-enumeration is required");
                None
            }
        } else {
            None
        };

        let (mut fetcher, mut zones_dir_id, mut items) = if let Some(st) = do_incremental {
            st
        } else {
            // Unfortunately, the documentation says only root folder can track changes.
            // Tracking sub-folders works for me but it is not sure if it is intended.
            tracing::info!("enumerating remote files");
            let fetcher = drive
                .track_root_changes_from_initial_with_option(
                    CollectionOption::new()
                        .select(ChunksState::SELECT_FIELDS)
                        .page_size(DELTA_PAGE_SIZE),
                )
                .await?;
            (fetcher, None, BTreeMap::new())
        };

        while let Some(page_items) = fetcher.fetch_next_page(drive).await? {
            tracing::info!("fetched {} items", page_items.len());
            for mut item in page_items {
                (|| {
                    let id = item.id.clone().context("missing id")?.0;
                    let is_deleted = item.deleted.is_some();

                    if is_deleted {
                        // NB. When a folder gets deleted, all items recursively inside generate
                        // deleted events in a top-down order. Thus we do not need to explicitly
                        // do recursive remove ourselves.
                        items.remove(&*id);
                        if zones_dir_id == Some(id) {
                            zones_dir_id = None;
                        }
                        return Ok(());
                    }

                    let name = item.name.clone().context("missing name")?;
                    let Some(parent_id) = get_parent_id(item.parent_reference.as_deref_mut())
                    else {
                        // Parent can be missing for root item.
                        ensure!(item.root.is_some(), "missing parentReference");
                        return Ok(());
                    };
                    let trailing_num = name.get(1..).and_then(|s| u32::from_str_radix(s, 16).ok());

                    if parent_id == root_dir_id && item.folder.is_some() && name == "zones" {
                        zones_dir_id = Some(id);
                    } else if Some(&parent_id) == zones_dir_id.as_ref()
                        && item.folder.is_some()
                        && name.starts_with('z')
                    {
                        if let Some(zid) = trailing_num {
                            items.insert(id, RemoteItem::Zone { zid });
                        }
                    } else if name.starts_with('c') && item.file.is_some() {
                        if let Some(coff) = trailing_num {
                            if let Some(&RemoteItem::Zone { zid }) = items.get(&parent_id) {
                                let size: u64 = item.size.context("missing size")?.try_into()?;
                                items.insert(id, RemoteItem::Chunk { zid, coff, size });
                            }
                        }
                    }
                    Ok(())
                })()
                .with_context(|| format!("failed to process item: {item:?}"))?;
            }
        }

        let delta_url = fetcher
            .delta_url()
            .context("missing final delta url")?
            .to_owned();
        Ok(Self {
            delta_url,
            root_dir_id,
            zones_dir_id,
            items,
        })
    }
}

fn get_parent_id(parent: Option<&mut serde_json::Value>) -> Option<String> {
    if let Some(parent) = parent {
        if let Some(serde_json::Value::String(s)) = parent.get_mut("id") {
            return Some(std::mem::take(s));
        }
    }
    None
}

pub fn init(
    config: &Config,
    dev_config: &crate::service::Config,
    rt: &tokio::runtime::Runtime,
) -> Result<(Remote, Vec<(u64, u64)>)> {
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

    let auto_cred_path = config.state_dir.join(AUTO_CREDENTIAL_FILE_NAME);
    let mut cred = {
        let user_cred = load_credential(&config.state_dir.join(USER_CREDENTIAL_FILE_NAME))
            .context("failed to load user credentials, have you manually setup it?")?;
        match load_credential(&auto_cred_path) {
            Ok(auto_cred) if auto_cred.init_time == user_cred.init_time => {
                tracing::info!("user credentials unchanged, use last auto saved tokens");
                auto_cred
            }
            _ => {
                tracing::info!("user credentials changed, use user's new tokens");
                user_cred
            }
        }
    };

    tracing::info!("logging in");
    let (access_token, _) = rt
        .block_on(cred.login(client.clone()))
        .context("failed to login with saved credential")?;
    safe_write(&auto_cred_path, &cred).context("failed to save new refresh token")?;
    let drive =
        OneDrive::new_with_client(client.clone(), access_token.clone(), DriveLocation::me());

    tracing::info!("preparing remote directory");

    // Acquire the lock before any change.
    let lock = rt
        .block_on(RemoteLock::lock(&drive, &config.remote_dir))
        .context("failed to acquire remote lock")?;
    let lock = scopeguard::guard(lock, |lock| {
        tracing::info!("releasing remote lock");
        if let Err(err) = rt.block_on(lock.unlock(&drive)) {
            tracing::error!(%err, "failed to release remote lock");
        }
    });

    // Geometry validation.
    let geometry = Geometry {
        dev_size: dev_config.dev_secs.bytes(),
        zone_size: dev_config.zone_secs.bytes(),
    };
    let root_dir_id = rt.block_on(async {
        let geometry_file_path = format!("{}/{}", config.remote_dir, GEOMETRY_FILE_NAME);
        let geometry_file_path = ItemLocation::from_path(&geometry_file_path).unwrap();
        let new_data = || serde_json::to_vec(&geometry).expect("serialization cannot fail");
        let mut parent = match drive.get_item(geometry_file_path).await {
            Ok(item) => {
                let remote_geometry = client
                    .get(item.download_url.context("missing download url")?)
                    .send()
                    .await?
                    .error_for_status()?
                    .json::<Geometry>()
                    .await?;
                ensure!(
                    geometry.zone_size == remote_geometry.zone_size
                        && geometry.dev_size >= remote_geometry.dev_size,
                    "geometry mismatch, remote: {remote_geometry:?}, config: {geometry:?}",
                );
                if geometry.dev_size > remote_geometry.dev_size {
                    tracing::info!(
                        ?remote_geometry,
                        new_geometry = ?geometry,
                        "changing remote device geometry"
                    );
                    drive.upload_small(geometry_file_path, new_data()).await?;
                }
                item.parent_reference
            }
            Err(err) if err.status_code() == Some(StatusCode::NOT_FOUND) => {
                drive
                    .upload_small(geometry_file_path, new_data())
                    .await?
                    .parent_reference
            }
            Err(err) => return Err(err.into()),
        };
        get_parent_id(parent.as_deref_mut()).context("missing parent id")
    })?;

    tracing::info!(%root_dir_id);

    // Chunk enumeration.
    let state_file_path = config.state_dir.join(STATE_FILE_NAME);
    let prev_state = {
        match fs::read_to_string(&state_file_path) {
            Ok(content) => match serde_json::from_str(&content) {
                Ok(WithVersion::Inner(st)) => Some(st),
                Err(err) => {
                    tracing::warn!(%err, "ignored unparsable chunks state file, assuming program version update");
                    None
                }
            },
            Err(err) if err.kind() == std::io::ErrorKind::NotFound => None,
            Err(err) => {
                return Err(anyhow::Error::from(err).context("failed to read chunks state file"))
            }
        }
    };

    let state = rt.block_on(ChunksState::fetch_and_parse(
        &drive,
        root_dir_id,
        prev_state,
    ))?;
    safe_write(&state_file_path, &WithVersion::Inner(&state))
        .context("failed to save chunks state")?;

    let chunks = {
        let mut chunks = Vec::with_capacity(state.items.len());
        for &item in state.items.values() {
            let RemoteItem::Chunk { zid, coff, size } = item else {
                continue;
            };
            let zone_start = geometry
                .zone_size
                .checked_mul(zid.into())
                .context("zone offset overflow")?;
            let global_off = zone_start
                .checked_add(coff.into())
                .context("chunk offset overflow")?;
            chunks.push((global_off, size));
        }
        // `ChunksState::zones` are ordered by item ids. We need to sort it by offset.
        chunks.sort_unstable();

        let non_empty_zone_cnt = chunks
            .iter()
            .chunk_by(|(global_off, _)| *global_off / geometry.zone_size)
            .into_iter()
            .count();
        tracing::info!(
            zones.total = state.items.len() - chunks.len(),
            zones.non_empty = non_empty_zone_cnt,
            chunks = chunks.len(),
        );
        chunks
    };

    let drive = Arc::new(AutoReloginOnedrive::new(
        cred,
        config.state_dir.clone(),
        client,
        access_token,
    ));
    let remote = Remote::new(
        drive,
        config.clone(),
        scopeguard::ScopeGuard::into_inner(lock),
    );
    Ok((remote, chunks))
}

fn load_credential(path: &Path) -> Result<Credential> {
    let content = fs::read_to_string(path)?;
    Ok(serde_json::from_str::<Credential>(&content)?)
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

#[derive(Debug, Clone, Serialize, Deserialize)]
struct RemoteLockInfo {
    hostname: String,
    timestamp: SystemTime,
    // For human consumption.
    timestamp_str: String,
}

impl RemoteLockInfo {
    fn new() -> Self {
        let timestamp = SystemTime::now();
        let hostname = match hostname::get() {
            Ok(name) => name.to_string_lossy().into_owned(),
            Err(err) => {
                tracing::error!(%err, "failed to get hostname");
                "<unknown>".to_owned()
            }
        };
        Self {
            hostname,
            timestamp,
            timestamp_str: humantime::format_rfc3339(timestamp).to_string(),
        }
    }
}

#[derive(Debug)]
struct RemoteLock {
    item_id: ItemId,
    tag: Tag,
}

impl RemoteLock {
    async fn lock(drive: &OneDrive, remote_dir: &str) -> Result<Self> {
        let lock_file_path_str = format!("{remote_dir}/{LOCK_FILE_NAME}");
        let lock_file_path = ItemLocation::from_path(&lock_file_path_str).unwrap();
        let lock_info =
            serde_json::to_vec(&RemoteLockInfo::new()).expect("serialization cannot fail");

        // Only the session upload API supports conflict behavior.
        let size = lock_info.len() as u64;
        let ret = drive
            .new_upload_session_with_option(
                lock_file_path,
                DriveItemPutOption::new().conflict_behavior(ConflictBehavior::Fail),
            )
            .await;
        let upload_err = match ret {
            Ok((sess, _)) => match sess
                .upload_part(lock_info, 0..size, size, drive.client())
                .await
            {
                Ok(item) => {
                    let item = item.context("unexpected empty response")?;
                    let item_id = item.id.context("missing item id")?;
                    // NB. Using eTag for DELETE somehow always fail with 412 PRECONDITION FAILED,
                    // we have to use cTag here.
                    let tag = item.c_tag.context("missing c_tag")?;
                    return Ok(Self { item_id, tag });
                }
                Err(upload_err) => {
                    if let Err(err) = sess.delete(drive.client()).await {
                        tracing::error!(%err, "failed to delete upload session");
                    }
                    upload_err
                }
            },
            Err(err) => err,
        };
        if upload_err.status_code() != Some(StatusCode::CONFLICT) {
            return Err(upload_err.into());
        }

        // Here we got a conflict. Try to get more information for diagnose.
        let info = async {
            let url = drive.get_item_download_url(lock_file_path).await?;
            let data = drive.client().get(url).send().await?.bytes().await?;
            let info = serde_json::from_slice::<RemoteLockInfo>(&data)?;
            anyhow::Ok(info)
        }
        .await;
        let info = match info {
            Ok(info) => format!("{:?} at {:?}", info.hostname, info.timestamp_str),
            Err(err) => {
                tracing::error!(%err, "failed to read remote lock info");
                "<unknown>".to_owned()
            }
        };
        bail!(
            "The remote directory is locked by {info}. You cannot serve the same directory \
            without risking data corruption. If you are sure it's a false positive and the \
            previous service instance have crashed, please delete {lock_file_path_str:?} \
            manually via OneDrive online <https://onedrive.live.com/>, and then retry.\
            ",
        );
    }

    async fn unlock(&self, drive: &OneDrive) -> onedrive_api::Result<()> {
        match drive
            .delete_with_option(&self.item_id, DriveItemPutOption::new().if_match(&self.tag))
            .await
        {
            Ok(()) => Ok(()),
            Err(err) if err.status_code() == Some(StatusCode::NOT_FOUND) => {
                tracing::warn!(%err, "skip deleting remote lock file because it is already gone");
                Ok(())
            }
            Err(err) if err.status_code() == Some(StatusCode::PRECONDITION_FAILED) => {
                tracing::warn!(
                    %err,
                    "skip deleting remote lock file since it is not locked by us",
                );
                Ok(())
            }
            Err(err) => Err(err),
        }
    }
}

#[derive(Debug)]
pub struct AutoReloginOnedrive {
    state: tokio::sync::RwLock<LoginState>,
    client: Client,
    state_dir: PathBuf,
}

struct LoginState {
    tick: u64,
    access_token: String,
    cred: Credential,
}

impl fmt::Debug for LoginState {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("LoginState")
            .field("tick", &self.tick)
            .finish_non_exhaustive()
    }
}

impl AutoReloginOnedrive {
    fn new(cred: Credential, state_dir: PathBuf, client: Client, access_token: String) -> Self {
        Self {
            state: tokio::sync::RwLock::new(LoginState {
                tick: 0,
                access_token,
                cred,
            }),
            client,
            state_dir,
        }
    }

    fn get(&self, state: &LoginState) -> (OneDrive, u64) {
        let drive = OneDrive::new_with_client(
            self.client.clone(),
            state.access_token.clone(),
            DriveLocation::me(),
        );
        (drive, state.tick)
    }

    async fn with<T, F, Fut>(&self, mut f: F) -> Result<T>
    where
        F: FnMut(OneDrive) -> Fut,
        Fut: Future<Output = onedrive_api::Result<T>>,
    {
        let (drive, tick) = self.get(&*self.state.read().await);
        let req_err = match retry_request(|| f(drive.clone())).await {
            Ok(v) => return Ok(v),
            Err(err) if err.status_code() == Some(StatusCode::UNAUTHORIZED) => err,
            Err(err) => return Err(err.into()),
        };

        // Token expired.

        let mut state = self.state.write().await;
        // If relogin happened between observations, treat it as done.
        if tick == state.tick {
            tracing::info!("token expired, re-logging in");
            let (access_token, _) = match state.cred.login(self.client.clone()).await {
                Ok(resp) => resp,
                Err(login_err) => {
                    tracing::error!(err = %login_err, "relogin failed");
                    return Err(req_err.into());
                }
            };
            let cred = state.cred.clone();

            // Update and release the lock before saving.
            state.access_token = access_token;
            state.tick += 1;

            // Spawn non-delimited task for saving. No ordering is required for it.
            let auto_cred_path = self.state_dir.join(AUTO_CREDENTIAL_FILE_NAME);
            tokio::task::spawn_blocking(move || {
                if let Err(save_err) = safe_write(&auto_cred_path, &cred) {
                    tracing::error!(err = %save_err, "failed to save new refresh token");
                }
            });
        }

        // Retry the request after relogined only once. If the user suspend/resume rapidly
        // between requests, we cannot help them :(.
        let (drive, _) = self.get(&state);
        Ok(retry_request(|| f(drive.clone())).await?)
    }

    pub async fn reload(&self) -> Result<()> {
        let mut user_cred = load_credential(&self.state_dir.join(USER_CREDENTIAL_FILE_NAME))
            .context("failed to load user credentials")?;
        let prev_init_time = self.state.read().await.cred.init_time;
        if user_cred.init_time == prev_init_time {
            tracing::info!("user credentials unchanged, do nothing");
            return Ok(());
        }

        let (access_token, _) = user_cred.login(self.client.clone()).await?;

        // Here, we may get a different `init_time` if another `reload` racing with us.
        // But the SIGHUP handler prevents it. And even in racing case, there is no problem because
        // either access token should be valid.
        let mut state = self.state.write().await;
        state.tick += 1;
        state.access_token = access_token;
        state.cred = user_cred;
        Ok(())
    }
}

#[derive(Debug)]
pub struct Remote {
    config: Config,
    drive: Arc<AutoReloginOnedrive>,
    download_url_cache: Mutex<TimedCache<(u32, u32), CacheCell>>,
    lock: RemoteLock,

    accounting: Accounting,
}

#[derive(Debug, Default)]
struct Accounting {
    url_cache_miss: AtomicU64,
    url_cache_hit: AtomicU64,
}

/// In case of concurrent cache population, only one wins, to avoid redundant API calls.
#[derive(Clone)]
struct CacheCell(Arc<tokio::sync::OnceCell<String>>);

impl fmt::Debug for CacheCell {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("CacheCell")
    }
}

impl Remote {
    fn new(drive: Arc<AutoReloginOnedrive>, config: Config, lock: RemoteLock) -> Self {
        assert!(config.remote_dir.starts_with('/') && !config.remote_dir.ends_with('/'));
        Self {
            config,
            drive,
            download_url_cache: Mutex::new(TimedCache::new(URL_CACHE_DURATION)),
            lock,
            accounting: Accounting::default(),
        }
    }

    pub fn get_drive(&self) -> Arc<AutoReloginOnedrive> {
        self.drive.clone()
    }

    pub async fn unlock(self) -> Result<()> {
        self.drive
            .with(|drive| {
                let lock = &self.lock;
                async move { lock.unlock(&drive).await }
            })
            .await
    }

    fn chunk_path(&self, zid: u32, coff: u32) -> String {
        format!(
            "{}/zones/z{:06x}/c{:08x}",
            self.config.remote_dir, zid, coff
        )
    }

    fn zone_path(&self, zid: u32) -> String {
        format!("{}/zones/z{:06x}", self.config.remote_dir, zid)
    }

    fn all_zones_dir_path(&self) -> String {
        format!("{}/zones", self.config.remote_dir)
    }
}

impl Backend for Remote {
    fn download_chunk(
        &self,
        zid: u32,
        coff: u32,
        read_offset: u64,
    ) -> impl Stream<Item = Result<Bytes>> + Send + 'static {
        use tracing_futures::Instrument;

        let (cell, accounting) = {
            let mut cache = self.download_url_cache.lock();
            if let Some(cell) = cache.get(&(zid, coff)) {
                (cell.clone(), &self.accounting.url_cache_hit)
            } else {
                self.accounting
                    .url_cache_miss
                    .fetch_add(1, Ordering::Relaxed);
                let cell = CacheCell(Arc::new(tokio::sync::OnceCell::new()));
                cache.insert((zid, coff), cell.clone());
                (cell, &self.accounting.url_cache_miss)
            }
        };
        accounting.fetch_add(1, Ordering::Relaxed);

        let path = self.chunk_path(zid, coff);
        let span = tracing::info_span!("download_chunk", zid, coff, read_offset, path);

        let drive = self.drive.clone();
        let fut = async move {
            let loc = ItemLocation::from_path(&path).unwrap();
            let url = cell
                .0
                .get_or_try_init(|| {
                    tracing::trace!("fetching download url");
                    drive.with(|drive| async move { drive.get_item_download_url(loc).await })
                })
                .await?;

            tracing::debug!("downloading chunk");

            let range = format!("bytes={read_offset}-");
            // No authentication required.
            let resp = retry_request(|| async {
                let resp = drive
                    .client
                    .get(url)
                    .header(header::RANGE, range.clone())
                    .send()
                    .await?;
                resp.error_for_status_ref()?;
                Ok(resp)
            })
            .await?;
            if read_offset != 0 {
                ensure!(
                    resp.status() == StatusCode::PARTIAL_CONTENT,
                    "response is not partial, got {}",
                    resp.status(),
                );
            }

            Ok(resp
                .bytes_stream()
                // Treat body reading error as early EOF, so the frontend will do retry.
                // When the connection is stall for too long, the error is:
                // `request or response body error: error reading a body from connection: Connection reset by peer (os error 104)`.
                .take_while(|ret| ready(!matches!(ret, Err(err) if err.is_body())))
                .map_err(anyhow::Error::from))
        };
        fut.try_flatten_stream().instrument(span)
    }

    #[tracing::instrument(skip_all, fields(zid, coff, path = self.chunk_path(zid, coff), data_len = data.len()))]
    async fn upload_chunk(&self, zid: u32, coff: u32, data: Bytes) -> Result<()> {
        tracing::debug!("uploading chunk");

        let path = self.chunk_path(zid, coff);
        let total_len = data.len();
        let loc = ItemLocation::from_path(&path).unwrap();

        let _item = if total_len <= SESSION_UPLOAD_THRESHOLD {
            self.drive
                .with(|drive| {
                    let data = data.clone();
                    async move { drive.upload_small(loc, data).await }
                })
                .await?
        } else {
            assert!(!data.is_empty());

            // The tail chunk may be replaced several times.
            let (sess, _) = self
                .drive
                .with(|drive| async move {
                    let opt =
                        DriveItemPutOption::new().conflict_behavior(ConflictBehavior::Replace);
                    drive.new_upload_session_with_option(loc, opt).await
                })
                .await?;

            let mut rest = data;
            let mut offset = 0u64;
            loop {
                let part_len = rest.len().min(self.config.upload_part_max_size);
                let part = rest.split_to(part_len);
                let new_offset = offset + part_len as u64;
                // No authentication required.
                let ret = retry_request(|| {
                    sess.upload_part(
                        part.clone(),
                        offset..new_offset,
                        total_len as u64,
                        &self.drive.client,
                    )
                })
                .await;

                let err = match (ret, new_offset == total_len as u64) {
                    (Ok(None), false) => {
                        offset = new_offset;
                        continue;
                    }
                    (Ok(Some(item)), true) => break item,
                    (Ok(Some(item)), false) => {
                        // The session is completed, thus no need to delete.
                        bail!("unexpected completion for {path} at {new_offset}/{total_len}: {item:?}");
                    }
                    (Ok(None), true) => {
                        anyhow!("failed to complete uploading for {path} at {new_offset}B")
                    }
                    // In some rare cases, uploading is successful for server but failed for us in
                    // combination of network fluctuation and auto-retrying. We need to re-sync the
                    // stream position.
                    (Err(err), _)
                        if err.status_code() == Some(StatusCode::RANGE_NOT_SATISFIABLE) =>
                    {
                        tracing::warn!("upload session is out of sync, re-syncing");
                        let new_meta = retry_request(|| sess.get_meta(&self.drive.client))
                            .await
                            .context("failed to get out of sync")?;
                        let expected = new_meta.next_expected_ranges;
                        ensure!(
                            // Must return one trailing chunk.
                            expected.len() == 1
                            // Must not revert already uploaded parts.
                            && offset < expected[0].start
                            // Must not end early.
                            && expected[0].end.is_none_or(|end| end == total_len as u64 - 1),
                            "unexpected next_expected_ranges for {path}, \
                            previously at {offset}/{total_len}, \
                            got {expected:?}",
                        );
                        let prev_offset = mem::replace(&mut offset, expected[0].start);
                        rest = rest.slice((offset - prev_offset) as usize..);
                        tracing::info!("upload position skipped from {prev_offset} to {offset}");
                        continue;
                    }
                    (Err(err), _) => err.into(),
                };
                // No authentication required.
                if let Err(err) = sess.delete(&self.drive.client).await {
                    tracing::error!(%err, "failed to delete upload session");
                }
                return Err(err);
            }
        };

        // Invalidate old ones if exists.
        // NB. The download url returned from `item` sometimes has issue on download:
        // it will 302 to `https://login.live.com/login.srv?[..]`.
        // Here we force a re-fetch on the next download.
        self.download_url_cache.lock().remove(&(zid, coff));

        Ok(())
    }

    #[tracing::instrument(skip_all, fields(self, path = self.zone_path(zid)))]
    async fn delete_zone(&self, zid: u32) -> Result<()> {
        tracing::debug!("deleting zone");
        let path = self.zone_path(zid);
        let path = ItemLocation::from_path(&path).unwrap();
        self.drive
            .with(|drive| async move { drive.delete(path).await })
            .await?;
        // No need to clear the cache. Frontend will not download non-existing chunks.
        // When new chunks are uploaded, cache will be updated in `upload_chunk` anyway.
        Ok(())
    }

    #[tracing::instrument(skip_all, fields(path = self.all_zones_dir_path()))]
    async fn delete_all_zones(&self) -> Result<()> {
        tracing::debug!("deleting all zones");
        let path = self.all_zones_dir_path();
        let path = ItemLocation::from_path(&path).unwrap();
        self.drive
            .with(|drive| async move { drive.delete(path).await })
            .await?;
        self.download_url_cache.lock().clear();
        Ok(())
    }
}

#[derive(Debug)]
struct TimedCache<K, V> {
    expire_duration: Duration,
    cleanup_threshold: usize,
    map: HashMap<K, (SystemTime, V)>,
}

impl<K: Eq + Hash, V> TimedCache<K, V> {
    const MIN_CLEANUP_THRESHOLD: usize = 16;

    fn new(expire_duration: Duration) -> Self {
        Self {
            expire_duration,
            cleanup_threshold: Self::MIN_CLEANUP_THRESHOLD,
            map: HashMap::with_capacity(Self::MIN_CLEANUP_THRESHOLD),
        }
    }

    fn get(&self, key: &K) -> Option<&V> {
        match self.map.get(key) {
            Some((time, v)) if SystemTime::now() <= *time => Some(v),
            _ => None,
        }
    }

    fn insert(&mut self, key: K, value: V) {
        use std::collections::hash_map::Entry;

        let now = SystemTime::now();
        let expire_time = now + self.expire_duration;
        match self.map.entry(key) {
            Entry::Occupied(mut ent) => {
                *ent.get_mut() = (expire_time, value);
            }
            Entry::Vacant(ent) => {
                ent.insert((expire_time, value));
                if self.map.len() >= self.cleanup_threshold {
                    self.map.retain(|_, (expire_ts, _)| now < *expire_ts);
                    // O(2N / (2N - N)) = O(1)
                    self.cleanup_threshold = Self::MIN_CLEANUP_THRESHOLD.max(self.map.len() * 2);
                }
            }
        }
    }

    fn remove(&mut self, key: &K) {
        self.map.remove(key);
    }

    fn clear(&mut self) {
        self.map.clear();
        self.cleanup_threshold = Self::MIN_CLEANUP_THRESHOLD;
    }
}

async fn retry_request<T, F, Fut>(mut f: F) -> onedrive_api::Result<T>
where
    F: FnMut() -> Fut,
    Fut: Future<Output = onedrive_api::Result<T>>,
{
    fn should_retry(st: StatusCode) -> bool {
        st == StatusCode::TOO_MANY_REQUESTS
            || !st.is_client_error() && !st.is_success() && !st.is_redirection()
    }

    let mut retry_num = 1usize;
    let mut next_delay = SERVER_ERROR_RETRY_DEFAULT_DELAY;

    loop {
        match f().await {
            Ok(v) => return Ok(v),
            // For HTTP 429 (Too many requests) or on `Retry-After` given, always retry.
            // Otherwise, retry all errors except obvious client errors.
            Err(err)
                if (err.retry_after().is_some() || err.status_code().is_none_or(should_retry))
                    && retry_num <= SERVER_ERROR_RETRY_CNT =>
            {
                let delay = err.retry_after().unwrap_or(next_delay);
                tracing::warn!(
                    retry.cnt = retry_num,
                    retry.max = SERVER_ERROR_RETRY_CNT,
                    retry.delay = ?delay,
                    %err,
                    "retrying on error",
                );
                retry_num += 1;
                tokio::time::sleep(delay).await;
                next_delay = delay * 2;
            }
            Err(err) => return Err(err),
        }
    }
}
