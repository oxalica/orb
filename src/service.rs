//! Zoned block device interface over a object storage backend.
//!
//! 1.  Zones are identified by their index `zid`, that is its starting offset divided by zone size.
//! 2.  Each non-empty zone is represented by a non-empty directory, holding variant-size chunks.
//! 3.  Inside a zone directory, there are chunks identified by its in-zone starting offset `coff`,
//!     that is its starting offset relative to the starting offset of the zone holding the chunk.
//! 4.  For `WRITE` and `ZONE_APPEND`, data is appended to the last chunk, aka. tail chunk. Once it
//!     exceeds `min_chunk_size`, it is sealed and a new chunk is created to become the new tail.
//!     This means:
//!     - In a zone, chunks form a continuous range starting from relative offset 0 (zone start).
//!     - Only tail chunks can change (be re-uploaded), while other chunks are immutable until
//!       deletion.
//! 5.  Tail chunks can have size one more than sector alignment (512B), indicating the zone is
//!     manually `FINISH`ed. `FINISH`ed zones reject all write operations other than `ZONE_RESET`.
//!     The marker byte is not part of data and will never be actually read.
//! 6.  `ZONE_RESET` deletes the whole zone directory as an atomic operation.
//!
//! Example file structure in backend:
//!
//! ```text
//! /
//! |- zone0/       // Zone at offset=0, cond=CLOSED
//! |  |- chunk0 len=2048   // [0, 2048)
//! |  |- chunk4 len=512    // [2048, 2560)
//! |
//! | // zone1 and zone 2 are EMPTY.
//! |
//! |- zone3/       // Zone at offset=(3 * zone_size), cond=FINISH
//!    |- chunk0 len=513    // Chunk [0, 512). The last byte must be zero.
//! ```
//!
//! Note: directory names above are just for demostration and are reference as `(zid, coff)`
//! integer tuple in code.
#![deny(clippy::await_holding_lock)]
use std::collections::BTreeSet;
use std::future::Future;
use std::num::{NonZeroU32, NonZeroUsize};
use std::pin::Pin;
use std::sync::Arc;
use std::{fmt, io};

use anyhow::{ensure, Context, Result};
use bytes::{BufMut, Bytes, BytesMut};
use futures_util::{AsyncBufRead, AsyncReadExt, Stream, StreamExt, TryStreamExt};
use itertools::Itertools;
use lru::LruCache;
use orb_ublk::{
    BlockDevice, DeviceAttrs, DeviceInfo, DeviceParams, IoFlags, ReadBuf, Sector, Stopper,
    WriteBuf, ZoneBuf, ZoneCond, ZoneType, ZonedParams,
};
use parking_lot::Mutex;
use rustix::io::Errno;
use serde::{Deserialize, Serialize};
use serde_inline_default::serde_inline_default;
use tokio::sync::watch;

const MAX_READ_LEN: usize = 1 << 20;
static ZEROES: &[u8] = &[0u8; MAX_READ_LEN];

pub trait Backend: Send + Sync + 'static {
    fn download_chunk(
        &self,
        zid: u32,
        coff: u32,
        read_offset: u64,
    ) -> impl Stream<Item = Result<Bytes>> + Send + 'static;
    fn upload_chunk(
        &self,
        zid: u32,
        coff: u32,
        data: Bytes,
    ) -> impl Future<Output = Result<()>> + Send + '_;
    fn delete_zone(&self, zid: u64) -> impl Future<Output = Result<()>> + Send + '_;
    fn delete_all_zones(&self) -> impl Future<Output = Result<()>> + Send + '_;
}

#[serde_inline_default]
#[derive(Debug, Clone, Copy, PartialEq, Eq, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct Config {
    #[serde(rename = "dev_size", with = "serde_sector")]
    pub dev_secs: Sector,
    #[serde(rename = "zone_size", with = "serde_sector")]
    pub zone_secs: Sector,
    #[serde(deserialize_with = "de_size")]
    pub min_chunk_size: usize,
    #[serde(deserialize_with = "de_size")]
    pub max_chunk_size: usize,

    #[serde_inline_default(NonZeroUsize::new(16).unwrap())]
    pub max_concurrent_streams: NonZeroUsize,
    #[serde_inline_default(NonZeroU32::new(8).unwrap())]
    pub max_concurrent_commits: NonZeroU32,
}

mod serde_sector {
    use orb_ublk::Sector;
    use serde::de::{Deserialize, Deserializer, Error};
    use serde::Serializer;

    pub fn deserialize<'de, D: Deserializer<'de>>(de: D) -> Result<Sector, D::Error> {
        let n = bytesize::ByteSize::deserialize(de)?;
        Sector::try_from_bytes(n.0)
            .ok_or_else(|| D::Error::custom(format_args!("not aligned to 512B sectors: {}", n.0)))
    }

    pub fn serialize<S: Serializer>(n: &Sector, ser: S) -> Result<S::Ok, S::Error> {
        ser.serialize_u64(n.bytes())
    }
}

fn de_size<'de, D: serde::de::Deserializer<'de>>(de: D) -> Result<usize, D::Error> {
    use serde::de::Error;

    let n = bytesize::ByteSize::deserialize(de)?;
    n.0.try_into()
        .map_err(|_| D::Error::custom(format_args!("overflow: {}", n.0)))
}

impl Config {
    pub fn validate(&self) -> Result<()> {
        ensure!(
            self.zone_secs.0.is_power_of_two()
                && self.zone_secs.0.trailing_zeros() + Sector::SHIFT < 31,
            "Zone size must be a power of two less than i32::MAX",
        );
        ensure!(
            self.dev_secs % self.zone_secs == Sector(0),
            "`dev_secs` must be a multiple of `zone_secs`",
        );
        ensure!(
            i32::try_from(self.dev_secs / self.zone_secs).is_ok(),
            "Number of zones must not exceed i32::MAX",
        );
        ensure!(
            1 <= self.min_chunk_size && self.min_chunk_size <= self.max_chunk_size,
            "`min_chunk_secs` must be in range [1, max_chunk_secs]",
        );
        ensure!(
            (self.max_chunk_size as u64) <= self.zone_secs.bytes(),
            "`max_chunk_secs` must not exceed `zone_secs`",
        );

        Ok(())
    }
}

type OnReady = Box<dyn FnOnce(&DeviceInfo, Stopper) -> io::Result<()> + Send>;

/// TODO: Improve concurrency.
pub struct Frontend<B, const LOGICAL_SECTOR_SIZE: u32 = { Sector::SIZE }> {
    config: Config,
    backend: B,
    on_ready: Mutex<Option<OnReady>>,

    /// See docs of `DownloadStream`.
    streams: Mutex<LruCache<u64, DownloadStream>>,
    zones: Box<[Zone]>,
    dirty_zones: Mutex<BTreeSet<u32>>,
    /// The global write fence for exclusive write operations (RESET_ALL) or synchronization
    /// (FLUSH). All remote modification holds a read-guard of this lock.
    exclusive_write_fence: tokio::sync::RwLock<()>,
}

impl<B: fmt::Debug, const LOGICAL_SECTOR_SIZE: u32> fmt::Debug
    for Frontend<B, LOGICAL_SECTOR_SIZE>
{
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        struct Indexed<'a, T>(&'a [T]);
        impl<'a, T: fmt::Debug> fmt::Debug for Indexed<'a, T> {
            fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
                f.debug_map().entries(self.0.iter().enumerate()).finish()
            }
        }

        f.debug_struct("Frontend")
            .field("config", &self.config)
            .field("backend", &self.backend)
            .field("streams", &self.streams)
            .field("zones", &Indexed(&self.zones))
            .field("dirty_zones", &self.dirty_zones)
            .field("exclusive_write_fence", &self.exclusive_write_fence)
            .finish_non_exhaustive()
    }
}

/// Active streams are keyed by global "reserved" stream position, counting all pending reads.
/// This allows multiple read-ahead requests to be queued, without creating new streams.
///
/// ```text
/// |             chunk                     |
///        *stream-pos     *reserved-pos    *chunk-end
///        |<------------->|<-------------->|
///          pending reads   reserved remaining
/// ```
#[derive(Clone, Debug)]
struct DownloadStream {
    /// The remaining bytes starting at the position after all reserved pending reads.
    reserved_remaining: u32,
    /// The zone-relative starting offset of this chunk.
    coff: u32,
    pos: watch::Receiver<u32>,
    state: Arc<Mutex<Option<StreamState>>>,
}

struct StreamState {
    pos_tx: watch::Sender<u32>,
    stream: Pin<Box<dyn AsyncBufRead + Send>>,
}

impl fmt::Debug for StreamState {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("StreamState").finish_non_exhaustive()
    }
}

// `Mutex`es are locked in definition order.
#[derive(Debug)]
struct Zone {
    /// Any remote modification of the zone holds this lock, ie. WRITE, ZONE_APPEND, ZONE_RESET.
    /// Note that any task holding this lock must hold `exclusive_write_fence` first.
    commit_lock: tokio::sync::Mutex<()>,
    cond: Mutex<ZoneCond>,
    /// The end-offset relative to this zone for each chunks, in ascending order.
    /// The tail chunk is excluded.
    chunk_ends: Mutex<Vec<u32>>,
    tail: Mutex<TailChunk>,
}

impl Zone {
    fn reset(&self) {
        let mut cond = self.cond.lock();
        let mut chunks = self.chunk_ends.lock();
        let mut tail = self.tail.lock();
        *cond = ZoneCond::Empty;
        *chunks = Vec::new();
        *tail = TailChunk::empty();
    }
}

enum TailChunk {
    Buffer(BytesMut),
    Uploading(Bytes),
}

impl fmt::Debug for TailChunk {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let (variant, len) = match self {
            Self::Buffer(buf) if buf.is_empty() => return f.write_str("NoTail"),
            Self::Buffer(buf) => ("Buffer", buf.len()),
            Self::Uploading(buf) => ("Uploading", buf.len()),
        };
        f.debug_tuple(variant)
            .field(&format_args!("<{len} bytes>"))
            .finish()
    }
}

impl TailChunk {
    fn empty() -> Self {
        Self::Buffer(BytesMut::new())
    }
}

impl AsRef<[u8]> for TailChunk {
    fn as_ref(&self) -> &[u8] {
        match self {
            TailChunk::Buffer(buf) => buf,
            TailChunk::Uploading(buf) => buf,
        }
    }
}

impl Default for Zone {
    fn default() -> Self {
        Self {
            commit_lock: tokio::sync::Mutex::new(()),
            chunk_ends: Mutex::default(),
            cond: Mutex::new(ZoneCond::Empty),
            tail: Mutex::new(TailChunk::empty()),
        }
    }
}

impl<B: Backend, const LOGICAL_SECTOR_SIZE: u32> Frontend<B, LOGICAL_SECTOR_SIZE> {
    pub fn new(
        config: Config,
        backend: B,
        on_ready: impl FnOnce(&DeviceInfo, Stopper) -> io::Result<()> + Send + 'static,
    ) -> Result<Self> {
        assert!(LOGICAL_SECTOR_SIZE.is_power_of_two() && LOGICAL_SECTOR_SIZE >= Sector::SIZE);

        config.validate().context("invalid configuration")?;
        let nr_zones = usize::try_from(config.dev_secs / config.zone_secs).unwrap();
        let zones = std::iter::repeat_with(Zone::default)
            .take(nr_zones)
            .collect::<Box<[_]>>();
        Ok(Self {
            backend,
            on_ready: Mutex::new(Some(Box::new(on_ready) as _)),

            streams: Mutex::new(LruCache::new(config.max_concurrent_streams)),
            zones,
            dirty_zones: Mutex::default(),
            exclusive_write_fence: tokio::sync::RwLock::with_max_readers(
                (),
                // Clamp to the max supported value for tokio.
                config.max_concurrent_commits.get().min(u32::MAX >> 3),
            ),

            config,
        })
    }

    pub async fn init_chunks(&mut self, all_chunks: &[(u64, u64)]) -> Result<()> {
        ensure!(
            all_chunks.windows(2).all(|w| w[0].0 < w[1].0),
            "chunks are not sorted",
        );

        let mut download_tail_futs = Vec::new();

        let zone_size = self.config.zone_secs.bytes();
        for (zid, mut zone_chunks) in &all_chunks
            .iter()
            .copied()
            .group_by(|(global_off, _)| *global_off / zone_size)
        {
            ensure!(
                zid < self.zones.len() as u64,
                "invalid chunk offset {}",
                zone_chunks.next().expect("group must have element").0,
            );

            let zone = &mut self.zones[zid as usize];
            let zone_start = zid * zone_size;
            let mut is_zone_finished = false;
            let mut chunk_ends = zone_chunks
                .scan(0u32, |coff, (global_off, len)| {
                    let ret = (|| {
                        let expect_global_off = zone_start + *coff as u64;
                        ensure!(
                            global_off == expect_global_off,
                            "offset not continous, expected to be {expect_global_off}",
                        );
                        ensure!(
                            *coff as u64 % LOGICAL_SECTOR_SIZE as u64 == 0,
                            "offset not aligned",
                        );
                        ensure!(len != 0, "chunk is empty");
                        *coff = u64::from(*coff)
                            .checked_add(len)
                            .filter(|&new_coff| new_coff <= zone_size)
                            .and_then(|coff| u32::try_from(coff).ok())
                            .context("offset overflow")?;
                        if *coff & 1 == 1 {
                            *coff -= 1;
                            ensure!(!is_zone_finished, "multiple zone finish markers");
                            is_zone_finished = true;
                        } else if *coff as u64 == zone_size {
                            is_zone_finished = true;
                        }
                        Ok(*coff)
                    })()
                    .with_context(|| {
                        format!("invalid chunk at global_offset={global_off} length={len}")
                    });
                    Some(ret)
                })
                .collect::<Result<Vec<_>>>()?;

            *zone.cond.get_mut() = if is_zone_finished {
                ZoneCond::Full
            } else if chunk_ends.is_empty() {
                ZoneCond::Empty
            } else {
                ZoneCond::Closed
            };

            let (tail_coff, tail_len) = match *chunk_ends {
                [] => (0, 0),
                [end] => (0, end as usize),
                [.., start, end] => (start, (end - start) as usize),
            };
            if !is_zone_finished && tail_len != 0 && tail_len < self.config.min_chunk_size {
                // Exclude the tail chunk.
                chunk_ends.pop();
                let fut = self
                    .backend
                    .download_chunk(zid as u32, tail_coff, 0)
                    .try_collect::<BytesMut>();
                download_tail_futs.push(async move { (zid, tail_coff, tail_len, fut.await) });
            }

            *zone.chunk_ends.get_mut() = chunk_ends;
        }

        let mut ret = Ok(());
        for (zid, coff, len, download_ret) in
            futures_util::future::join_all(download_tail_futs).await
        {
            match download_ret {
                Ok(data) => {
                    assert_eq!(data.len(), len);
                    *self.zones[zid as usize].tail.get_mut() =
                        TailChunk::Buffer(BytesMut::from(&data[..]));
                }
                Err(err) => {
                    let err = err.context(format!(
                        "failed to download tail chunk at zid={zid} tail_coff={coff} len={len}"
                    ));
                    log::debug!("{err}");
                    ret = ret.and(Err(err));
                }
            }
        }
        ret
    }

    pub fn backend(&self) -> &B {
        &self.backend
    }

    pub fn dev_params(&self) -> DeviceParams {
        let mut params = DeviceParams::new();
        params
            .dev_sectors(self.config.dev_secs)
            .logical_block_size(LOGICAL_SECTOR_SIZE as u64)
            // XXX: Chunks should have a 2^k alignment.
            // .physical_block_size(self.config.min_chunk_size.bytes())
            // .io_min_size(self.config.min_chunk_size.bytes())
            // .io_opt_size(self.config.min_chunk_size.bytes())
            .chunk_sectors(self.config.zone_secs)
            // Simulate a rotational device to minimize random I/O (seeks).
            .attrs(DeviceAttrs::Rotational | DeviceAttrs::VolatileCache | DeviceAttrs::Fua)
            .zoned(ZonedParams {
                // TODO: Limit open or active zones.
                max_open_zones: 0,
                max_active_zones: 0,
                max_zone_append_size: Sector::from_bytes(self.config.max_chunk_size as u64),
            });
        params
    }

    fn to_zone_id(&self, off: Sector) -> Result<usize, Errno> {
        usize::try_from(off / self.config.zone_secs)
            .ok()
            .filter(|&zid| zid < self.zones.len())
            .ok_or_else(|| {
                log::error!("invalid offset {off}");
                Errno::INVAL
            })
    }

    fn check_zone_and_range(&self, off: Sector, len: usize) -> Result<(usize, u32), Errno> {
        let zid = self.to_zone_id(off)?;
        (|| {
            let zone_offset = (off % self.config.zone_secs).bytes() as u32;
            let max_len = Ord::min(
                MAX_READ_LEN as u64,
                self.config.zone_secs.bytes() - zone_offset as u64,
            );
            if len as u64 > max_len {
                return None;
            }
            Some((zid, zone_offset))
        })()
        .ok_or_else(|| {
            log::error!("invalid range: offset={off}, length={len}");
            Errno::INVAL
        })
    }

    async fn zone_append_impl(
        &self,
        zid: usize,
        coff: Option<u32>,
        buf: &WriteBuf<'_>,
        fua: bool,
    ) -> Result<u32, Errno> {
        let zone = &self.zones[zid];
        let _fence = self.exclusive_write_fence.read().await;
        let _zone_guard = zone.commit_lock.lock().await;

        let (tail_coff, data, prev_wp, clear_tail) = 'do_commit: {
            let mut cond = zone.cond.lock();
            if *cond == ZoneCond::Full {
                return Err(Errno::IO);
            }

            let chunks = zone.chunk_ends.lock();
            let tail_coff = chunks.last().copied().unwrap_or(0);
            let mut tail = zone.tail.lock();
            drop(chunks);
            let prev_wp = tail_coff + tail.as_ref().len() as u32;
            if let Some(coff) = coff {
                if coff != prev_wp {
                    log::warn!(
                        "nonsequential write: zid={zid} rel_wp={prev_wp} coff={coff} len={}",
                        buf.len()
                    );
                    return Err(Errno::IO);
                }
            }

            let TailChunk::Buffer(tail_buf) = &mut *tail else {
                // Zone poisoned.
                return Err(Errno::IO);
            };

            tail_buf.reserve(buf.len());
            buf.copy_to_uninitialized(&mut tail_buf.spare_capacity_mut()[..buf.len()])?;
            // SAFETY: Initialied.
            unsafe { tail_buf.set_len(tail_buf.len() + buf.len()) };

            // Always dirty the zone. It will be cleared after inline-committed or flushed.
            self.dirty_zones.lock().insert(zid as u32);

            let new_wp = tail_coff + tail_buf.len() as u32;
            if new_wp as u64 == self.config.zone_secs.bytes() {
                // If this write makes the zone full, update `cond` and commit inline.
                *cond = ZoneCond::Full;
            } else {
                if matches!(*cond, ZoneCond::Empty | ZoneCond::Closed) {
                    *cond = ZoneCond::ImpOpen;
                }
                // Buffer small writes, but only if not FUA.
                if tail_buf.len() < self.config.max_chunk_size {
                    if !fua {
                        return Ok(prev_wp);
                    }
                    // Commit inline if FUA, and do not freeze the tail.
                    let data = Bytes::copy_from_slice(tail_buf);
                    break 'do_commit (tail_coff, data, prev_wp, false);
                }
            }

            let data = tail_buf.split().freeze();
            *tail = TailChunk::Uploading(data.clone());
            (tail_coff, data, prev_wp, true)
        };

        self.commit_tail_chunk(zid as u32, tail_coff, data, clear_tail)
            .await?;
        Ok(prev_wp)
    }

    async fn commit_tail_chunk(
        &self,
        zid: u32,
        coff: u32,
        data: Bytes,
        clear_tail: bool,
    ) -> Result<(), Errno> {
        let zone = &self.zones[zid as usize];
        let len = data.len();
        if let Err(err) = self.backend.upload_chunk(zid, coff, data).await {
            log::error!("failed to upload chunk at zid={zid} coff={coff} len={len}: {err}");
            // NB. Intentionally keep it in `TailChunk::Commiting` state,
            // poison all following writes.
            return Err(Errno::IO);
        }

        if clear_tail {
            let mut chunks = zone.chunk_ends.lock();
            let mut tail = zone.tail.lock();
            chunks.push(coff + len as u32);
            *tail = TailChunk::empty();
        }
        self.dirty_zones.lock().remove(&zid);

        Ok(())
    }
}

impl<B: Backend, const LOGICAL_SECTOR_SIZE: u32> BlockDevice for Frontend<B, LOGICAL_SECTOR_SIZE> {
    fn ready(&self, dev_info: &DeviceInfo, stop: Stopper) -> io::Result<()> {
        self.on_ready.lock().take().unwrap()(dev_info, stop)
    }

    async fn read(&self, off: Sector, buf: &mut ReadBuf<'_>, flags: IoFlags) -> Result<(), Errno> {
        let (zid, mut read_start) = self.check_zone_and_range(off, buf.remaining())?;
        let zone = &self.zones[zid];

        // It's rare to read across chunks which are typically >1MiB. Simply loop for that case.
        while buf.remaining() != 0 {
            let global_offset = self.config.zone_secs.bytes() * zid as u64 + read_start as u64;

            let (stream, read_len) = {
                let mut streams = self.streams.lock();
                let mut stream = match streams.pop(&global_offset) {
                    Some(stream) => stream,
                    None => {
                        let chunks = zone.chunk_ends.lock();
                        let tail_start = chunks.last().copied().unwrap_or(0);
                        if let Some(offset_in_tail) = read_start.checked_sub(tail_start) {
                            // Read from tail, or zeros beyond the write pointer.
                            drop(streams);
                            {
                                let tail = zone.tail.lock();
                                drop(chunks);
                                if (offset_in_tail as usize) < tail.as_ref().len() {
                                    let data = &tail.as_ref()[offset_in_tail as usize..];
                                    let len = Ord::min(data.len(), buf.remaining());
                                    buf.put_slice(&data[..len])?;
                                }
                            }
                            if buf.remaining() != 0 {
                                buf.put_slice(&ZEROES[..buf.remaining()])?;
                            }
                            return Ok(());
                        }

                        // The first chunks whose end > `read_end`, covering the first byte to read.
                        let idx = chunks.partition_point(|&end| end <= read_start);
                        assert!(idx < chunks.len());
                        let chunk_start = if idx > 0 { chunks[idx - 1] } else { 0 };
                        let chunk_end = chunks[idx];
                        let offset_in_chunk = read_start - chunk_start;
                        let stream_len = chunk_end - read_start;
                        let stream = self
                            .backend
                            .download_chunk(zid as u32, chunk_start, offset_in_chunk as u64)
                            .map_err(io::Error::other)
                            .into_async_read();
                        let (pos_tx, pos) = watch::channel(offset_in_chunk);
                        DownloadStream {
                            reserved_remaining: stream_len,
                            coff: chunk_start,
                            pos,
                            state: Arc::new(Mutex::new(Some(StreamState {
                                stream: Box::pin(stream) as _,
                                pos_tx,
                            }))),
                        }
                    }
                };

                let read_len = Ord::min(stream.reserved_remaining, buf.remaining() as u32);
                assert_ne!(read_len, 0);
                stream.reserved_remaining -= read_len;
                // Put it back only if if can be reused later.
                if stream.reserved_remaining != 0 {
                    streams.push(global_offset + read_len as u64, stream.clone());
                }

                (stream, read_len)
            };

            let read_start_in_chunk = read_start - stream.coff;
            let Some(mut state) = stream
                .pos
                .clone()
                .wait_for(|&pos| pos >= read_start_in_chunk)
                .await
                .ok()
                .and_then(|_| stream.state.lock().take())
            else {
                log::debug!("stream closed, retrying");
                if flags.contains(IoFlags::FailfastDev) {
                    return Err(Errno::AGAIN);
                }
                continue;
            };

            // If we successfully took the stream state, the previous read must be successful,
            // otherwise the state cell would be left empty. Also that readers queued after us must
            // not grab the lock before us, because of `watch::Receiver::wait_for` condition.
            assert_eq!(*state.pos_tx.borrow(), read_start_in_chunk);

            // The kernel read length is usually quite large (>=512KiB) for read-ahead, while
            // stream read size is quite small (~16KiB). To prevent frequent `pwrite` into kernel,
            // we buffer them locally and submit it into kernel once.
            let mut data = vec![0u8; read_len as usize];
            match state.stream.read_exact(&mut data).await {
                Ok(()) => buf.put_slice(&data)?,
                Err(err) if err.kind() == io::ErrorKind::UnexpectedEof => {
                    log::debug!("stream ended early, retrying");
                    if flags.contains(IoFlags::FailfastDev) {
                        return Err(Errno::AGAIN);
                    }
                    continue;
                }
                Err(err) => {
                    log::error!(
                        "failed to download chunk at zone={zid} coff={coff}: {err}",
                        coff = stream.coff,
                    );
                    return Err(Errno::IO);
                }
            }

            // Update stream position and notify pending readers.
            // NB. We must set state back before sending notification, or the waiting reader
            // may preemptively access the stream state and fail.
            stream
                .state
                .lock()
                .insert(state)
                .pos_tx
                .send_modify(|pos| *pos += read_len);

            read_start += read_len;
        }

        Ok(())
    }

    async fn write(&self, off: Sector, buf: WriteBuf<'_>, flags: IoFlags) -> Result<usize, Errno> {
        let (zid, coff) = self.check_zone_and_range(off, buf.len())?;
        self.zone_append_impl(zid, Some(coff), &buf, flags.contains(IoFlags::Fua))
            .await?;
        Ok(buf.len())
    }

    async fn zone_append(
        &self,
        off: Sector,
        buf: WriteBuf<'_>,
        flags: IoFlags,
    ) -> Result<Sector, Errno> {
        let zid = self.to_zone_id(off)?;
        let prev_wp = self
            .zone_append_impl(zid, None, &buf, flags.contains(IoFlags::Fua))
            .await?;
        let prev_abs_wp = self.config.zone_secs * zid as u64 + Sector::from_bytes(prev_wp.into());
        Ok(prev_abs_wp)
    }

    // This always commits, thus obeys FUA semantic.
    async fn zone_finish(&self, off: Sector, _flags: IoFlags) -> Result<(), Errno> {
        let zid = self.to_zone_id(off)?;
        let zone = &self.zones[zid];
        let _fence = self.exclusive_write_fence.read().await;
        let _zone_guard = zone.commit_lock.lock().await;

        let (tail_coff, data) = {
            let mut cond = zone.cond.lock();
            match *cond {
                ZoneCond::Empty | ZoneCond::ImpOpen | ZoneCond::ExpOpen | ZoneCond::Closed => {}
                ZoneCond::Full => return Ok(()),
                _ => unreachable!(),
            }
            let chunks = zone.chunk_ends.lock();
            let tail_coff = chunks.last().copied().unwrap_or(0);
            let mut tail = zone.tail.lock();

            let TailChunk::Buffer(tail_buf) = &mut *tail else {
                // Zone poisoned.
                return Err(Errno::IO);
            };

            // Mark zone finished.
            tail_buf.put_u8(0u8);

            let data = tail_buf.split().freeze();
            *tail = TailChunk::Uploading(data.clone());
            *cond = ZoneCond::Full;
            (tail_coff, data)
        };

        self.commit_tail_chunk(zid as u32, tail_coff, data, true)
            .await?;
        Ok(())
    }

    async fn report_zones(
        &self,
        off: Sector,
        buf: &mut ZoneBuf<'_>,
        _flags: IoFlags,
    ) -> Result<(), Errno> {
        let zid_start = self.to_zone_id(off)?;

        let zones = self.zones[zid_start..]
            .iter()
            .zip(zid_start..)
            .take(buf.remaining())
            .map(|(zone, zid)| {
                let cond = zone.cond.lock();
                let rel_wp = match *cond {
                    ZoneCond::Empty => Sector(0),
                    ZoneCond::Full => self.config.zone_secs,
                    _ => {
                        let chunks = zone.chunk_ends.lock();
                        let tail_coff = chunks.last().copied().unwrap_or(0);
                        let tail_len = zone.tail.lock().as_ref().len() as u32;
                        Sector::from_bytes((tail_coff + tail_len).into())
                    }
                };
                let zone_start = self.config.zone_secs * zid as u64;
                orb_ublk::Zone::new(
                    zone_start,
                    self.config.zone_secs,
                    rel_wp,
                    ZoneType::SeqWriteReq,
                    *cond,
                )
            })
            .collect::<Vec<_>>();

        buf.report(&zones)?;
        Ok(())
    }

    async fn zone_open(&self, off: Sector, _flags: IoFlags) -> Result<(), Errno> {
        let zid = self.to_zone_id(off)?;
        let mut cond = self.zones[zid].cond.lock();
        match *cond {
            ZoneCond::Empty | ZoneCond::ImpOpen | ZoneCond::Closed => {}
            ZoneCond::ExpOpen => return Ok(()),
            ZoneCond::Full => return Err(Errno::IO),
            _ => unreachable!(),
        }
        *cond = ZoneCond::ExpOpen;
        Ok(())
    }

    async fn zone_close(&self, off: Sector, _flags: IoFlags) -> Result<(), Errno> {
        let zid = self.to_zone_id(off)?;
        let zone = &self.zones[zid];
        let mut cond = zone.cond.lock();
        match *cond {
            ZoneCond::ImpOpen | ZoneCond::ExpOpen => {}
            ZoneCond::Empty | ZoneCond::Closed => return Ok(()),
            ZoneCond::Full => return Err(Errno::IO),
            _ => unreachable!(),
        }
        let chunks = zone.chunk_ends.lock();
        let tail = zone.tail.lock();
        *cond = if chunks.is_empty() && tail.as_ref().is_empty() {
            ZoneCond::Empty
        } else {
            ZoneCond::Closed
        };
        Ok(())
    }

    // This always commits, thus obeys FUA semantic.
    async fn zone_reset(&self, off: Sector, _flags: IoFlags) -> Result<(), Errno> {
        let zid = self.to_zone_id(off)?;
        let zone = &self.zones[zid];
        let _fence = self.exclusive_write_fence.read().await;
        let _zone_guard = zone.commit_lock.lock().await;

        // Fast path for empty (may or may not be opened) zones.
        {
            let mut cond = zone.cond.lock();
            let chunks = zone.chunk_ends.lock();
            let tail = zone.tail.lock();
            if chunks.is_empty() && tail.as_ref().is_empty() {
                *cond = ZoneCond::Empty;
                return Ok(());
            }
        }

        if let Err(err) = self.backend.delete_zone(zid as u64).await {
            log::error!("failed to delete zone {zid}: {err}");
            return Err(Errno::IO);
        }

        zone.reset();
        self.dirty_zones.lock().remove(&(zid as u32));

        Ok(())
    }

    // This always commits, thus obeys FUA semantic.
    async fn zone_reset_all(&self, _flags: IoFlags) -> Result<(), Errno> {
        let _fence = self.exclusive_write_fence.write().await;

        if let Err(err) = self.backend.delete_all_zones().await {
            log::error!("failed to delete all zones: {err}");
            return Err(Errno::IO);
        }
        for zone in self.zones.iter() {
            zone.reset();
        }
        self.dirty_zones.lock().clear();
        Ok(())
    }

    async fn flush(&self, _flags: IoFlags) -> Result<(), Errno> {
        // Wait for all committing tasks to complete.
        let _fence = self.exclusive_write_fence.write().await;

        let mut ret = Ok(());

        let commit_futs = self
            .dirty_zones
            .lock()
            .iter()
            .filter_map(|&zid| {
                let zone = &self.zones[zid as usize];
                let zone_guard = zone
                    .commit_lock
                    .try_lock()
                    .expect("holding exclusive write lock");

                let chunks = zone.chunk_ends.lock();
                let mut tail = zone.tail.lock();
                let tail_coff = chunks.last().copied().unwrap_or(0);
                drop(chunks);
                let TailChunk::Buffer(tail_buf) = &mut *tail else {
                    log::error!("zone {zid} poisoned");
                    ret = Err(Errno::IO);
                    return None;
                };
                assert!(!tail_buf.is_empty());
                let clear_tail = tail_buf.len() >= self.config.min_chunk_size;
                let data = if clear_tail {
                    let data = tail_buf.split().freeze();
                    *tail = TailChunk::Uploading(data.clone());
                    data
                } else {
                    // Small chunks can still grow. Do not freeze it.
                    // This should not cause race because we are holding write locks.
                    Bytes::copy_from_slice(tail_buf)
                };
                Some(async move {
                    let _zone_guard = zone_guard;
                    self.commit_tail_chunk(zid, tail_coff, data, clear_tail)
                        .await
                })
            })
            .collect::<Vec<_>>();

        // XXX: Can we release the write fence here?

        let max_concurrent_commits = self.config.max_concurrent_commits.get() as usize;
        if commit_futs.is_empty() {
            // Do nothing.
        } else if commit_futs.len() <= max_concurrent_commits {
            let commit_ret = futures_util::future::join_all(commit_futs)
                .await
                .into_iter()
                .collect();
            ret = ret.and(commit_ret);
        } else {
            let mut stream =
                futures_util::stream::iter(commit_futs).buffer_unordered(max_concurrent_commits);
            while let Some(r) = stream.next().await {
                ret = ret.and(r);
            }
        }

        ret
    }
}
