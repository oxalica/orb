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
    ReadBuf, Stopper, WriteBuf, Zone, ZoneBuf, ZoneCond, ZoneType, ZonedParams, SECTOR_SIZE,
};
use rustix::io::Errno;
use serde::{Deserialize, Serialize};

/// Example loop device.
#[derive(Debug, Parser)]
struct Cli {
    backing_file: PathBuf,
    metadata_file: PathBuf,

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
    env_logger::init();
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
    ensure!(
        size % SECTOR_SIZE as u64 == 0,
        "backing file size must be multiples of {SECTOR_SIZE}"
    );
    let zone_size = cli.zone_size.0;
    ensure!(
        size % zone_size == 0,
        "device size is not multiples of zone size"
    );
    let zones_cnt = size / zone_size;

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
    builder.name("ublk-zoned").zoned();
    if !cli.privileged {
        builder.unprivileged();
    }
    let mut srv = builder
        .create_service(&ctl)
        .context("failed to create ublk device")?;
    let params = *DeviceParams::new()
        .size(size)
        .chunk_size(zone_size.try_into().unwrap())
        .attrs(DeviceAttrs::VolatileCache)
        .set_io_flusher(cli.privileged)
        .zoned(ZonedParams {
            max_open_zones: cli.max_open_zones,
            max_active_zones: cli.max_active_zones,
            max_zone_append_size: cli.max_zone_append_size.0.try_into().unwrap(),
        });
    let handler = ZonedDev {
        file: backing_file,
        zone_size,
        zones: Mutex::new(zones),
        metadata_path: cli.metadata_file,
    };
    srv.serve(&TokioRuntimeBuilder, &params, &handler)
        .context("service error")?;
    Ok(())
}

struct ZonedDev {
    file: File,
    zone_size: u64,
    zones: Mutex<ZonesMetadata>,
    metadata_path: PathBuf,
}

impl BlockDevice for ZonedDev {
    fn ready(&self, dev_info: &DeviceInfo, stop: Stopper) -> io::Result<()> {
        log::info!("device ready on {}", dev_info.dev_id());
        ctrlc::set_handler(move || stop.stop()).expect("failed to set Ctrl-C hook");
        Ok(())
    }

    async fn read(&self, off: u64, mut buf: ReadBuf<'_>, _flags: IoFlags) -> Result<usize, Errno> {
        let mut buf2 = vec![0u8; buf.len()];
        self.file
            .read_exact_at(&mut buf2, off)
            .map_err(convert_err)?;
        buf.copy_from(&buf2)?;
        Ok(buf.len())
    }

    async fn write(&self, off: u64, buf: WriteBuf<'_>, _flags: IoFlags) -> Result<usize, Errno> {
        let zid = off / self.zone_size;
        {
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
            buf.copy_to(&mut buf2)?;
            self.file.write_all_at(&buf2, off).map_err(convert_err)?;
            z.rel_wptr = new_rel_wptr;
            if new_rel_wptr == self.zone_size {
                z.cond = ZoneCond::Full;
            } else {
                z.cond = ZoneCond::ImpOpen;
            }
        }

        Ok(buf.len())
    }

    async fn flush(&self, _flags: IoFlags) -> Result<(), Errno> {
        self.file.sync_data().map_err(convert_err)?;
        let content = serde_json::to_vec(&*self.zones.lock().unwrap()).unwrap();
        let tmp_path = self.metadata_path.with_extension("tmp");
        fs::write(&tmp_path, content).map_err(convert_err)?;
        fs::rename(&tmp_path, &self.metadata_path).map_err(convert_err)?;
        Ok(())
    }

    async fn zone_open(&self, off: u64, _flags: IoFlags) -> Result<(), Errno> {
        let zid = off / self.zone_size;
        let mut zones = self.zones.lock().unwrap();
        let z = &mut zones.zones[zid as usize];
        z.cond = match z.cond {
            ZoneCond::Empty | ZoneCond::ImpOpen | ZoneCond::ExpOpen | ZoneCond::Closed => {
                ZoneCond::ExpOpen
            }
            _ => unreachable!(),
        };
        Ok(())
    }

    async fn zone_close(&self, off: u64, _flags: IoFlags) -> Result<(), Errno> {
        let zid = off / self.zone_size;
        let mut zones = self.zones.lock().unwrap();
        let z = &mut zones.zones[zid as usize];
        z.cond = match z.cond {
            ZoneCond::ExpOpen if z.rel_wptr == 0 => ZoneCond::Empty,
            ZoneCond::ExpOpen => ZoneCond::Closed,
            st => st,
        };
        Ok(())
    }

    async fn zone_finish(&self, off: u64, _flags: IoFlags) -> Result<(), Errno> {
        let zid = off / self.zone_size;
        let mut zones = self.zones.lock().unwrap();
        let z = &mut zones.zones[zid as usize];
        z.rel_wptr = self.zone_size;
        z.cond = ZoneCond::Full;
        Ok(())
    }

    async fn zone_reset(&self, off: u64, _flags: IoFlags) -> Result<(), Errno> {
        let zid = off / self.zone_size;
        let mut zones = self.zones.lock().unwrap();
        let z = &mut zones.zones[zid as usize];
        z.rel_wptr = 0;
        z.cond = ZoneCond::Empty;
        Ok(())
    }

    async fn zone_reset_all(&self, _flags: IoFlags) -> Result<(), Errno> {
        let mut zones = self.zones.lock().unwrap();
        zones.zones.fill_with(ZoneState::default);
        Ok(())
    }

    async fn report_zones(
        &self,
        off: u64,
        mut buf: ZoneBuf<'_>,
        _flags: IoFlags,
    ) -> Result<usize, Errno> {
        let zid = off / self.zone_size;
        let zones = self.zones.lock().unwrap();
        let info = zones.zones[zid as usize..][..buf.len()]
            .iter()
            .zip(zid..)
            .map(|(z, zid)| {
                Zone::new(
                    zid * self.zone_size,
                    self.zone_size,
                    z.rel_wptr,
                    ZoneType::SeqWriteReq,
                    z.cond,
                )
            })
            .collect::<Vec<_>>();
        buf.report(&info)
    }

    async fn zone_append(
        &self,
        off: u64,
        buf: WriteBuf<'_>,
        _flags: IoFlags,
    ) -> Result<u64, Errno> {
        let zid = off / self.zone_size;
        let mut zones = self.zones.lock().unwrap();
        let z = &mut zones.zones[zid as usize];
        let new_rel_wptr = z
            .rel_wptr
            .checked_add(buf.len() as u64)
            .filter(|&p| p <= self.zone_size)
            .ok_or(Errno::IO)?;
        let mut buf2 = vec![0u8; buf.len()];
        buf.copy_to(&mut buf2)?;
        let old_wptr = zid * self.zone_size + z.rel_wptr;
        self.file
            .write_all_at(&buf2, old_wptr)
            .map_err(convert_err)?;
        z.rel_wptr = new_rel_wptr;
        if new_rel_wptr == self.zone_size {
            z.cond = ZoneCond::Full;
        } else {
            z.cond = ZoneCond::ImpOpen;
        }
        Ok(old_wptr)
    }
}

#[allow(clippy::needless_pass_by_value)]
fn convert_err(err: io::Error) -> Errno {
    log::error!("{err}");
    Errno::from_io_error(&err).unwrap_or(Errno::IO)
}
