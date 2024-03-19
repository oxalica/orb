use std::collections::{BTreeMap, HashMap};
use std::fs;
use std::hash::Hash;
use std::io::Write;
use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::time::{Duration, SystemTime};

use anyhow::{ensure, Context, Result};
use bytes::Bytes;
use futures_util::{Stream, TryFutureExt, TryStreamExt};
use onedrive_api::option::CollectionOption;
use onedrive_api::resource::DriveItemField;
use onedrive_api::{Auth, DriveLocation, ItemLocation, OneDrive, Permission, TrackChangeFetcher};
use parking_lot::RwLock;
use reqwest::{header, Client, StatusCode};
use serde::{de, Deserialize, Serialize};

use crate::service::Backend;

/// In <https://learn.microsoft.com/en-us/graph/api/driveitem-get-content?view=graph-rest-1.0&tabs=http#response>:
///
/// > Preauthenticated download URLs are only valid for a short period of time (a few minutes) and
/// > don't require an Authorization header to download.
///
/// Though it's discouraged to cache them, we still do it for a relatively safe time (60s) to
/// avoid mass API calls which are rate limited.
const URL_CACHE_DURATION: Duration = Duration::from_secs(60);
const DELTA_PAGE_SIZE: usize = 10_000;

const USER_AGENT: &str = concat!(env!("CARGO_PKG_NAME"), "/", env!("CARGO_PKG_VERSION"));
const XDG_STATE_DIR_NAME: &str = env!("CARGO_PKG_NAME");
const CREDENTIAL_FILE_NAME: &str = "credential.json";
const STATE_FILE_NAME: &str = "state.json";

const GEOMETRY_FILE_NAME: &str = "geometry.json";

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

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct Geometry {
    dev_size: u64,
    zone_size: u64,
}

#[derive(Debug, Default, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct ChunksState {
    delta_url: String,
    zones_dir_id: Option<String>,
    zones: BTreeMap<String, RemoteZone>,
}

#[derive(Debug, Default, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct RemoteZone {
    zid: u64,
    chunks: BTreeMap<u64, u64>,
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
    ];

    async fn update(
        &mut self,
        drive: &OneDrive,
        fetcher: &mut TrackChangeFetcher,
        root_dir_id: &str,
    ) -> Result<()> {
        while let Some(items) = fetcher.fetch_next_page(drive).await? {
            log::info!("fetched {} items", items.len());
            for mut item in items {
                (|| {
                    let id = item.id.clone().context("missing id")?.0;
                    let name = item.name.clone().context("missing name")?;
                    let parent_id = get_parent_id(item.parent_reference.as_deref_mut())
                        .context("missing parent_reference")?;
                    let is_deleted = item.deleted.is_some();
                    let hex_off = name.get(1..).and_then(|s| u64::from_str_radix(s, 16).ok());
                    if parent_id == root_dir_id && item.folder.is_some() && name == "zones" {
                        self.zones_dir_id = (!is_deleted).then_some(id);
                    } else if Some(&parent_id) == self.zones_dir_id.as_ref()
                        && item.folder.is_some()
                        && name.starts_with('z')
                    {
                        if let Some(zid) = hex_off {
                            if is_deleted {
                                self.zones.remove(&id);
                            } else {
                                self.zones.entry(id).or_default().zid = zid;
                            }
                        }
                    } else if name.starts_with('c') && item.file.is_some() {
                        if let (Some(z), Some(coff)) = (self.zones.get_mut(&parent_id), hex_off) {
                            if is_deleted {
                                z.chunks.remove(&coff);
                            } else {
                                let size = item.size.context("missing size")?.try_into()?;
                                z.chunks.insert(coff, size);
                            }
                        }
                    }
                    anyhow::Ok(())
                })()
                .with_context(|| format!("failed to process item: {item:?}"))?;
            }
        }
        self.delta_url = fetcher
            .delta_url()
            .context("missing final delta url")?
            .to_owned();
        Ok(())
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
                    log::info!("changing device geometry from {remote_geometry:?} to {geometry:?}");
                    drive.upload_small(geometry_file_path, new_data()).await?;
                }
                item.parent_reference
            }
            Err(err) if err.status_code() == Some(StatusCode::NOT_FOUND) => {
                log::info!("initializing remote directory...");
                drive
                    .upload_small(geometry_file_path, new_data())
                    .await?
                    .parent_reference
            }
            Err(err) => return Err(err.into()),
        };
        get_parent_id(parent.as_deref_mut()).context("missing parent id")
    })?;

    log::info!("root directory id: {root_dir_id}");

    // Chunk enumeration.
    let state_file_path = config.state_dir.join(STATE_FILE_NAME);
    let state = (|| -> Result<Option<ChunksState>> {
        match fs::read_to_string(&state_file_path) {
            Ok(content) => Ok(Some(serde_json::from_str(&content)?)),
            Err(err) if err.kind() == std::io::ErrorKind::NotFound => Ok(None),
            Err(err) => Err(err.into()),
        }
    })()
    .context("failed to read chunks state file")?;
    let state = rt.block_on(async {
        if let Some(mut state) = state {
            log::info!("fetching remote changes...");
            match drive
                .track_root_changes_from_delta_url(&state.delta_url)
                .await
            {
                Ok(mut fetcher) => {
                    state.update(&drive, &mut fetcher, &root_dir_id).await?;
                    return Ok(state);
                }
                Err(err) if err.status_code() == Some(StatusCode::GONE) => {
                    log::info!("delta url gone, re-enumeration is required");
                }
                Err(err) => return Err(err.into()),
            }
        }

        log::info!("enumerating remote files...");
        let mut fetcher = drive
            .track_root_changes_from_initial_with_option(
                CollectionOption::new()
                    .select(ChunksState::SELECT_FIELDS)
                    .page_size(DELTA_PAGE_SIZE),
            )
            .await?;
        let mut state = ChunksState::default();
        state.update(&drive, &mut fetcher, &root_dir_id).await?;
        anyhow::Ok(state)
    })?;
    safe_write(&state_file_path, &state).context("failed to save chunks state")?;

    let mut chunks = Vec::with_capacity(state.zones.values().map(|z| z.chunks.len()).sum());
    let zone_cnt = state.zones.len();
    for (_, zone) in state.zones {
        let zone_start = geometry
            .zone_size
            .checked_mul(zone.zid)
            .context("zone offset overflow")?;
        for (coff, size) in zone.chunks {
            let global_off = zone_start
                .checked_add(coff)
                .context("chunk offset overflow")?;
            chunks.push((global_off, size));
        }
    }
    // `ChunksState::zones` are ordered by item ids. We need to sort it by offset.
    chunks.sort_unstable();
    log::info!("loaded {} zones, {} chunks", zone_cnt, chunks.len());

    let remote = Remote::new(drive, config.remote_dir.clone());
    Ok((remote, chunks))
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

#[derive(Debug)]
pub struct Remote {
    drive: OneDrive,
    root_dir: String,
    download_url_cache: Arc<RwLock<TimedCache<(u32, u32), String>>>,
}

impl Remote {
    fn new(drive: OneDrive, root_dir: String) -> Self {
        assert!(root_dir.starts_with('/') && !root_dir.ends_with('/'));
        Self {
            drive,
            root_dir,
            download_url_cache: Arc::new(RwLock::new(TimedCache::new(URL_CACHE_DURATION))),
        }
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
        let drive = self.drive.clone();
        let url = self.download_url_cache.read().get(&(zid, coff)).cloned();
        let path = self.chunk_path(zid, coff);
        let cache = Arc::clone(&self.download_url_cache);

        let fut = async move {
            let url = match url {
                Some(url) => url,
                None => {
                    log::debug!("fetching download url of chunk {path}");
                    let now = SystemTime::now();
                    let url = drive
                        .get_item_download_url(ItemLocation::from_path(&path).unwrap())
                        .await?;
                    cache.write().insert((zid, coff), url.clone(), now);
                    url
                }
            };

            log::debug!("downloading chunk {path} starting at {read_offset}B");

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
        let item = self
            .drive
            .upload_small(ItemLocation::from_path(&path).unwrap(), data)
            .await?;

        // Cache the download url returned. It must replace old ones, otherwise the cached content
        // suffers from ABA-problem if it was deleted before.
        let url = item.download_url.context("missing download url")?;
        // NB. This uses timestamp after upload completion, since uploading takes
        // quite some time.
        let now = SystemTime::now();
        self.download_url_cache
            .write()
            .insert((zid, coff), url, now);

        Ok(())
    }

    async fn delete_zone(&self, zid: u64) -> Result<()> {
        let path = self.zone_path(zid as u32);
        log::debug!("deleting {path}");
        self.drive
            .delete(ItemLocation::from_path(&path).unwrap())
            .await?;
        // No need to clear the cache. Frontend will not download non-existing chunks.
        // When new chunks are uploaded, cache will be updated in `upload_chunk` anyway.
        Ok(())
    }

    async fn delete_all_zones(&self) -> Result<()> {
        let path = self.all_zones_dir_path();
        log::debug!("deleting all {path}");
        self.drive
            .delete(ItemLocation::from_path(&path).unwrap())
            .await?;
        self.download_url_cache.write().clear();
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

    fn insert(&mut self, key: K, value: V, now: SystemTime) {
        use std::collections::hash_map::Entry;

        let expire_time = now + self.expire_duration;
        match self.map.entry(key) {
            Entry::Occupied(mut ent) if ent.get().0 < now => {
                *ent.get_mut() = (expire_time, value);
            }
            Entry::Occupied(_) => {}
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

    fn clear(&mut self) {
        self.map.clear();
        self.cleanup_threshold = Self::MIN_CLEANUP_THRESHOLD;
    }
}
