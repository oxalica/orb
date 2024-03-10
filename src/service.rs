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
use std::future::Future;
use std::io;

use anyhow::{ensure, Context, Result};
use bytes::Bytes;
use itertools::Itertools;
use orb_ublk::{
    BlockDevice, DeviceInfo, IoFlags, ReadBuf, Sector, Stopper, WriteBuf, ZoneBuf, ZoneCond,
    ZoneType,
};
use parking_lot::Mutex;
use rustix::io::Errno;

// TODO: Configurable.
const LOGICAL_BLOCK_SECS: Sector = Sector(1);

const MAX_READ_LEN: usize = 1 << 20;
static ZEROES: &[u8] = &[0u8; MAX_READ_LEN];

pub trait Backend: Send + Sync + 'static {
    fn download_chunk(
        &self,
        zid: u32,
        coff: u32,
        read_offset: u64,
        len: usize,
    ) -> impl Future<Output = Result<Bytes>> + Send + 'static;
    fn upload_chunk(
        &self,
        zid: u32,
        coff: u32,
        data: Bytes,
    ) -> impl Future<Output = Result<()>> + Send + 'static;
    fn delete_zone(&self, zid: u64) -> impl Future<Output = Result<()>> + Send + 'static;
    fn delete_all_zones(&self) -> impl Future<Output = Result<()>> + Send + 'static;
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Config {
    pub dev_secs: Sector,
    pub zone_secs: Sector,
    pub min_chunk_size: usize,
    pub max_chunk_size: usize,
}

impl Config {
    fn validate(&self) -> Result<()> {
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

/// TODO: Improve concurrency.
pub struct Frontend<B> {
    config: Config,
    backend: B,

    zones: Box<[Zone]>,
    /// The global write fence for exclusive write operations (RESET_ALL) or synchronization
    /// (FLUSH). All remote modification holds a read-guard of this lock.
    exclusive_write_fence: tokio::sync::RwLock<()>,
}

// `Mutex`es are locked in definition order.
#[derive(Debug)]
struct Zone {
    /// Any remote modification of the zone holds this lock, ie. WRITE, ZONE_APPEND, ZONE_RESET.
    /// Note that any task holding this lock must hold `exclusive_write_fence` first.
    commit_lock: tokio::sync::Mutex<()>,
    cond: Mutex<ZoneCond>,
    /// The end-offset relative to this zone for each chunks, in ascending order.
    chunk_ends: Mutex<Vec<u32>>,
}

impl Default for Zone {
    fn default() -> Self {
        Self {
            commit_lock: tokio::sync::Mutex::new(()),
            chunk_ends: Mutex::default(),
            cond: Mutex::new(ZoneCond::Empty),
        }
    }
}

impl<B> Frontend<B> {
    pub fn new(config: Config, all_chunks: &[(u64, u32)], backend: B) -> Result<Self> {
        config.validate().context("invalid configuration")?;
        let nr_zones = usize::try_from(config.dev_secs / config.zone_secs).unwrap();
        let zones = std::iter::repeat_with(Zone::default)
            .take(nr_zones)
            .collect::<Box<[_]>>();

        let mut this = Self {
            config,
            backend,

            zones,
            exclusive_write_fence: tokio::sync::RwLock::new(()),
        };
        this.init_chunks(all_chunks)
            .context("failed to initialize chunks")?;
        Ok(this)
    }

    fn init_chunks(&mut self, all_chunks: &[(u64, u32)]) -> Result<()> {
        ensure!(
            all_chunks.windows(2).all(|w| w[0].0 < w[1].0),
            "chunks are not sorted",
        );

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
            let chunk_ends = zone_chunks
                .scan(0u32, |coff, (global_off, len)| {
                    let ret = (|| {
                        let expect_global_off = zone_start + *coff as u64;
                        ensure!(
                            global_off == expect_global_off,
                            "offset not continous, expected to be {expect_global_off}",
                        );
                        ensure!(
                            *coff as u64 % LOGICAL_BLOCK_SECS.bytes() == 0,
                            "offset not aligned",
                        );
                        ensure!(len != 0, "chunk is empty");
                        *coff = coff
                            .checked_add(len)
                            .filter(|&new_coff| new_coff as u64 <= zone_size)
                            .context("offset overflow")?;
                        if *coff & 1 == 1 {
                            *coff -= 1;
                            ensure!(!is_zone_finished, "multiple zone finish markers");
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
            *zone.chunk_ends.get_mut() = chunk_ends;
        }
        Ok(())
    }

    pub fn backend(&self) -> &B {
        &self.backend
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
}

impl<B: Backend> BlockDevice for Frontend<B> {
    fn ready(&self, dev_info: &DeviceInfo, _stop: Stopper) -> io::Result<()> {
        // TODO: Notification.
        log::info!("device ready at /dev/ublkb{}", dev_info.dev_id());
        Ok(())
    }

    async fn read(&self, off: Sector, buf: &mut ReadBuf<'_>, _flags: IoFlags) -> Result<(), Errno> {
        let (zid, mut read_start) = self.check_zone_and_range(off, buf.remaining())?;
        let zone = &self.zones[zid];

        // It's rare to read across chunks which are typically >1MiB. Simply loop for that case.
        while buf.remaining() != 0 {
            let (chunk_start, chunk_end) = {
                let chunks = zone.chunk_ends.lock();
                // The first chunks whose end > `read_end`, covering the first byte to read.
                let idx = chunks.partition_point(|&end| end <= read_start);
                if idx == chunks.len() {
                    // Read beyond write pointer. Return zeroes.
                    drop(chunks);
                    buf.put_slice(&ZEROES[..buf.remaining()])?;
                    break;
                }
                (if idx > 0 { chunks[idx - 1] } else { 0 }, chunks[idx])
            };

            let offset_in_chunk = read_start - chunk_start;
            let read_len = Ord::min((chunk_end - read_start) as usize, buf.remaining());
            assert_ne!(read_len, 0);

            // TODO: Stream reuse.
            let ret = self
                .backend
                .download_chunk(zid as u32, chunk_start, offset_in_chunk.into(), read_len)
                .await;
            let data = ret.map_err(|err| {
                log::error!(
                    "failed to download chunk at \
                    zone={zid} chunk={chunk_start} offset={offset_in_chunk} length={read_len}: \
                    {err}"
                );
                Errno::IO
            })?;
            assert_eq!(data.len(), read_len);
            buf.put_slice(&data)?;
            read_start += read_len as u32;
        }

        Ok(())
    }

    async fn write(
        &self,
        _off: Sector,
        _buf: WriteBuf<'_>,
        _flags: IoFlags,
    ) -> Result<usize, Errno> {
        // TODO
        Err(Errno::PERM)
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
                    _ => Sector::from_bytes(
                        zone.chunk_ends.lock().last().copied().unwrap_or(0).into(),
                    ),
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
        *cond = if zone.chunk_ends.lock().is_empty() {
            ZoneCond::Empty
        } else {
            ZoneCond::Closed
        };
        Ok(())
    }

    async fn zone_reset(&self, off: Sector, _flags: IoFlags) -> Result<(), Errno> {
        let zid = self.to_zone_id(off)?;
        let zone = &self.zones[zid];
        let _fence = self.exclusive_write_fence.read().await;
        let _zone_guard = zone.commit_lock.lock().await;

        // Fast path for empty (may or may not be opened) zones.
        {
            let mut cond = zone.cond.lock();
            let chunks = zone.chunk_ends.lock();
            if chunks.is_empty() {
                *cond = ZoneCond::Empty;
                return Ok(());
            }
        }

        if let Err(err) = self.backend.delete_zone(zid as u64).await {
            log::error!("failed to delete zone {zid}: {err}");
            return Err(Errno::IO);
        }

        let mut cond = zone.cond.lock();
        let mut chunks = zone.chunk_ends.lock();
        *chunks = Vec::new();
        *cond = ZoneCond::Empty;

        Ok(())
    }

    async fn zone_reset_all(&self, _flags: IoFlags) -> Result<(), Errno> {
        let _fence = self.exclusive_write_fence.write().await;

        if let Err(err) = self.backend.delete_all_zones().await {
            log::error!("failed to delete all zones: {err}");
            return Err(Errno::IO);
        }
        for zone in self.zones.iter() {
            let mut cond = zone.cond.lock();
            *cond = ZoneCond::Empty;
            *zone.chunk_ends.lock() = Vec::new();
        }
        Ok(())
    }

    async fn flush(&self, _flags: IoFlags) -> Result<(), Errno> {
        // Wait for all committing tasks to complete.
        let _fence = self.exclusive_write_fence.write().await;
        Ok(())
    }
}
