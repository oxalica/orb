use std::fs::{self, File};
use std::io;
use std::os::unix::fs::FileExt;
use std::path::PathBuf;
use std::sync::Mutex;

use anyhow::{ensure, Context};
use bytesize::ByteSize;
use clap::Parser;
use orb_ublk::runtime::TokioRuntimeBuilder;
use orb_ublk::{
    BlockDevice, ControlDevice, DeviceAttrs, DeviceBuilder, DeviceInfo, DeviceParams, IoFlags,
    ReadBuf, Sector, Stopper, WriteBuf, Zone, ZoneBuf, ZoneCond, ZoneType, ZonedParams,
};
use rustix::fs::{fallocate, FallocateFlags};
use rustix::io::Errno;
use serde::{Deserialize, Serialize};

/// Example loop device.
#[derive(Debug, Parser)]
struct Cli {
    backing_file: PathBuf,
    metadata_file: PathBuf,

    #[clap(long)]
    dev_id: Option<u32>,
    #[clap(long, default_value = "512")]
    logical_block_size: ByteSize,
    #[clap(long, default_value = "4KiB")]
    physical_block_size: ByteSize,
    #[clap(long, default_value = "512KiB")]
    io_buf_size: ByteSize,

    #[clap(long)]
    zone_size: ByteSize,
    #[clap(long)]
    max_open_zones: u32,
    #[clap(long)]
    max_active_zones: u32,
    #[clap(long, default_value = "1GiB")]
    max_zone_append_size: ByteSize,

    #[clap(long)]
    privileged: bool,
}

#[derive(Debug, Serialize, Deserialize)]
struct ZonesMetadata {
    zone_size: u64,
    zones: Vec<ZoneState>,
}

#[derive(Debug, Clone, Copy)]
struct ZoneState {
    rel_wptr: u64,
    cond: ZoneCond,
}

impl Default for ZoneState {
    fn default() -> Self {
        Self {
            rel_wptr: 0,
            cond: ZoneCond::Empty,
        }
    }
}

impl Serialize for ZoneState {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: serde::Serializer,
    {
        self.rel_wptr.serialize(serializer)
    }
}

impl<'de> Deserialize<'de> for ZoneState {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: serde::Deserializer<'de>,
    {
        let wptr = u64::deserialize(deserializer)?;
        Ok(Self {
            rel_wptr: wptr,
            // Full is processed in main.
            cond: if wptr == 0 {
                ZoneCond::Empty
            } else {
                ZoneCond::Closed
            },
        })
    }
}

fn main() -> anyhow::Result<()> {
    tracing_subscriber::fmt::init();
    let cli = Cli::parse();

    let backing_file = File::options()
        .read(true)
        .write(true)
        .open(cli.backing_file)
        .context("failed to open backing file")?;
    let size = backing_file
        .metadata()
        .context("failed to query backing file")?
        .len();
    let zone_size = cli.zone_size.0;
    let zone_sectors =
        Sector::try_from_bytes(zone_size).context("zone size mut be multiple of sectors")?;
    ensure!(
        size % zone_sectors.bytes() == 0,
        "device size must be multiples of zone size"
    );
    let size_sectors = Sector::try_from_bytes(size).unwrap();
    let zones_cnt = size / zone_sectors.bytes();

    let zones = cli
        .metadata_file
        .exists()
        .then(|| {
            let src = fs::read_to_string(&cli.metadata_file)?;
            let mut meta = serde_json::from_str::<ZonesMetadata>(&src)?;
            ensure!(meta.zone_size == zone_size, "zone size mismatch");
            ensure!(meta.zones.len() as u64 == zones_cnt, "zone number mismatch");
            for (idx, z) in meta.zones.iter_mut().enumerate() {
                ensure!(z.rel_wptr <= zone_size, "invalid wptr for zone {idx}");
                z.cond = if z.rel_wptr == 0 {
                    ZoneCond::Empty
                } else if z.rel_wptr == zone_size {
                    ZoneCond::Full
                } else {
                    ZoneCond::Closed
                };
            }
            Ok(meta)
        })
        .transpose()
        .context("failed to read metadata")?
        .unwrap_or_else(|| ZonesMetadata {
            zone_size: cli.zone_size.0,
            zones: vec![ZoneState::default(); zones_cnt.try_into().unwrap()],
        });

    let ctl = ControlDevice::open()
        .context("failed to open control device, kernel module 'ublk_drv' not loaded?")?;
    let mut builder = DeviceBuilder::new();
    if !cli.privileged {
        builder.unprivileged();
    }
    let mut srv = builder
        .name("ublk-zoned")
        .zoned()
        .io_buf_size(u32::try_from(cli.io_buf_size.0).context("buffer size too large")?)
        .dev_id(cli.dev_id)
        .create_service(&ctl)
        .context("failed to create ublk device")?;
    let zones_cnt_u32 = u32::try_from(zones_cnt).unwrap_or(u32::MAX);
    let params = *DeviceParams::new()
        .dev_sectors(size_sectors)
        .chunk_sectors(zone_sectors)
        .attrs(DeviceAttrs::VolatileCache)
        .logical_block_size(cli.logical_block_size.0)
        .physical_block_size(cli.physical_block_size.0)
        .io_min_size(cli.physical_block_size.0)
        .io_opt_size(cli.physical_block_size.0)
        .io_max_sectors(Sector::from_bytes(cli.io_buf_size.0))
        .set_io_flusher(cli.privileged)
        .zoned(ZonedParams {
            max_open_zones: cli.max_open_zones.min(zones_cnt_u32),
            max_active_zones: cli.max_active_zones.min(zones_cnt_u32),
            max_zone_append_size: Sector::try_from_bytes(cli.max_zone_append_size.0)
                .unwrap()
                .min(size_sectors),
        });
    let handler = ZonedDev {
        file: backing_file,
        size,
        zone_size,
        zones: Mutex::new(zones),
        metadata_path: cli.metadata_file,
    };
    let ret = srv
        .serve(&TokioRuntimeBuilder, &params, &handler)
        .context("service error");
    handler.flush_sync().context("failed to sync")?;
    ret
}

struct ZonedDev {
    file: File,
    size: u64,
    zone_size: u64,
    zones: Mutex<ZonesMetadata>,
    metadata_path: PathBuf,
}

impl ZonedDev {
    fn flush_sync(&self) -> Result<(), Errno> {
        self.file.sync_data().map_err(convert_err)?;
        let content = serde_json::to_vec(&*self.zones.lock().unwrap()).unwrap();
        let tmp_path = self.metadata_path.with_extension("tmp");
        fs::write(&tmp_path, content).map_err(convert_err)?;
        fs::rename(&tmp_path, &self.metadata_path).map_err(convert_err)?;
        Ok(())
    }
}

impl BlockDevice for ZonedDev {
    fn ready(&self, dev_info: &DeviceInfo, stop: Stopper) -> io::Result<()> {
        log::info!(
            "device ready on {}, info: {:?}",
            dev_info.dev_id(),
            dev_info,
        );
        ctrlc::set_handler(move || stop.stop()).expect("failed to set Ctrl-C hook");
        Ok(())
    }

    async fn read(&self, off: Sector, buf: &mut ReadBuf<'_>, _flags: IoFlags) -> Result<(), Errno> {
        let mut buf2 = vec![0u8; buf.remaining()];
        self.file
            .read_exact_at(&mut buf2, off.bytes())
            .map_err(convert_err)?;
        buf.put_slice(&buf2)?;
        Ok(())
    }

    async fn write(&self, off: Sector, buf: WriteBuf<'_>, _flags: IoFlags) -> Result<usize, Errno> {
        let off = off.bytes();
        let zid = off / self.zone_size;
        let mut zones = self.zones.lock().unwrap();
        let z = &mut zones.zones[zid as usize];
        if (zid * self.zone_size + z.rel_wptr) != off {
            return Err(Errno::IO);
        }
        let new_rel_wptr = z
            .rel_wptr
            .checked_add(buf.len() as u64)
            .filter(|&p| p <= self.zone_size)
            .ok_or(Errno::IO)?;
        let mut buf2 = vec![0u8; buf.len()];
        buf.copy_to_slice(&mut buf2)?;
        self.file.write_all_at(&buf2, off).map_err(convert_err)?;
        z.rel_wptr = new_rel_wptr;
        if new_rel_wptr == self.zone_size {
            z.cond = ZoneCond::Full;
        } else if matches!(z.cond, ZoneCond::Closed | ZoneCond::Empty) {
            z.cond = ZoneCond::ImpOpen;
        }
        Ok(buf.len())
    }

    async fn flush(&self, _flags: IoFlags) -> Result<(), Errno> {
        self.flush_sync()
    }

    async fn zone_open(&self, off: Sector, _flags: IoFlags) -> Result<(), Errno> {
        let zid = off.bytes() / self.zone_size;
        let mut zones = self.zones.lock().unwrap();
        let z = &mut zones.zones[zid as usize];
        z.cond = match z.cond {
            ZoneCond::Empty | ZoneCond::ImpOpen | ZoneCond::ExpOpen | ZoneCond::Closed => {
                ZoneCond::ExpOpen
            }
            ZoneCond::Full => return Err(Errno::IO),
            _ => unreachable!(),
        };
        Ok(())
    }

    async fn zone_close(&self, off: Sector, _flags: IoFlags) -> Result<(), Errno> {
        let zid = off.bytes() / self.zone_size;
        let mut zones = self.zones.lock().unwrap();
        let z = &mut zones.zones[zid as usize];
        z.cond = match z.cond {
            ZoneCond::ExpOpen | ZoneCond::ImpOpen => {
                if z.rel_wptr == 0 {
                    ZoneCond::Empty
                } else {
                    ZoneCond::Closed
                }
            }
            ZoneCond::Empty | ZoneCond::Closed => z.cond,
            ZoneCond::Full => return Err(Errno::IO),
            _ => unreachable!(),
        };
        Ok(())
    }

    async fn zone_finish(&self, off: Sector, _flags: IoFlags) -> Result<(), Errno> {
        let zid = off.bytes() / self.zone_size;
        let mut zones = self.zones.lock().unwrap();
        let z = &mut zones.zones[zid as usize];
        z.rel_wptr = self.zone_size;
        z.cond = ZoneCond::Full;
        Ok(())
    }

    async fn zone_reset(&self, off: Sector, _flags: IoFlags) -> Result<(), Errno> {
        let zid = off.bytes() / self.zone_size;
        let mut zones = self.zones.lock().unwrap();
        let z = &mut zones.zones[zid as usize];
        fallocate(
            &self.file,
            FallocateFlags::PUNCH_HOLE | FallocateFlags::KEEP_SIZE,
            off.bytes(),
            self.zone_size,
        )?;
        z.rel_wptr = 0;
        z.cond = ZoneCond::Empty;
        Ok(())
    }

    async fn zone_reset_all(&self, _flags: IoFlags) -> Result<(), Errno> {
        let mut zones = self.zones.lock().unwrap();
        fallocate(
            &self.file,
            FallocateFlags::PUNCH_HOLE | FallocateFlags::KEEP_SIZE,
            0,
            self.size,
        )?;
        zones.zones.fill_with(ZoneState::default);
        Ok(())
    }

    async fn report_zones(
        &self,
        off: Sector,
        buf: &mut ZoneBuf<'_>,
        _flags: IoFlags,
    ) -> Result<(), Errno> {
        let zid = off.bytes() / self.zone_size;
        let zones = self.zones.lock().unwrap();
        let info = zones.zones[zid as usize..][..buf.remaining()]
            .iter()
            .zip(zid..)
            .map(|(z, zid)| {
                Zone::new(
                    Sector::from_bytes(zid * self.zone_size),
                    Sector::from_bytes(self.zone_size),
                    Sector::from_bytes(z.rel_wptr),
                    ZoneType::SeqWriteReq,
                    z.cond,
                )
            })
            .collect::<Vec<_>>();
        buf.report(&info)?;
        Ok(())
    }

    async fn zone_append(
        &self,
        off: Sector,
        buf: WriteBuf<'_>,
        _flags: IoFlags,
    ) -> Result<Sector, Errno> {
        let zid = off.bytes() / self.zone_size;
        let mut zones = self.zones.lock().unwrap();
        let z = &mut zones.zones[zid as usize];
        let new_rel_wptr = z
            .rel_wptr
            .checked_add(buf.len() as u64)
            .filter(|&p| p <= self.zone_size)
            .ok_or(Errno::IO)?;
        let mut buf2 = vec![0u8; buf.len()];
        buf.copy_to_slice(&mut buf2)?;
        let old_wptr = zid * self.zone_size + z.rel_wptr;
        self.file
            .write_all_at(&buf2, old_wptr)
            .map_err(convert_err)?;
        z.rel_wptr = new_rel_wptr;
        if new_rel_wptr == self.zone_size {
            z.cond = ZoneCond::Full;
        } else if matches!(z.cond, ZoneCond::Closed | ZoneCond::Empty) {
            z.cond = ZoneCond::ImpOpen;
        }
        Ok(Sector::from_bytes(old_wptr))
    }
}

#[allow(clippy::needless_pass_by_value)]
fn convert_err(err: io::Error) -> Errno {
    log::error!("{err}");
    Errno::from_io_error(&err).unwrap_or(Errno::IO)
}
