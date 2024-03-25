use std::fs::File;
use std::io;
use std::os::unix::fs::FileExt;
use std::path::PathBuf;

use anyhow::Context;
use clap::Parser;
use orb_ublk::runtime::TokioRuntimeBuilder;
use orb_ublk::{
    BlockDevice, ControlDevice, DeviceAttrs, DeviceBuilder, DeviceInfo, DeviceParams,
    DiscardParams, IoFlags, ReadBuf, Sector, Stopper, WriteBuf,
};
use rustix::fs::{fallocate, FallocateFlags};
use rustix::io::Errno;

/// Example loop device.
#[derive(Debug, Parser)]
struct Cli {
    backing_file: PathBuf,

    #[clap(long)]
    dev_id: Option<u32>,
    #[clap(long, default_value = "512")]
    logical_block_size: u64,
    #[clap(long, default_value = "4096")]
    physical_block_size: u64,

    #[clap(long)]
    discard: bool,
    #[clap(long)]
    user_copy: bool,
    #[clap(long)]
    privileged: bool,
}

fn main() -> anyhow::Result<()> {
    env_logger::init();
    let cli = Cli::parse();

    let file = File::options()
        .read(true)
        .write(true)
        .open(cli.backing_file)
        .context("failed to open backing file")?;
    let size = file
        .metadata()
        .context("failed to query backing file")?
        .len();
    let size_sectors =
        Sector::try_from_bytes(size).context("backing file size must be multiples of sectors")?;

    let ctl = ControlDevice::open()
        .context("failed to open control device, kernel module 'ublk_drv' not loaded?")?;
    let mut builder = DeviceBuilder::new();
    builder.name("ublk-loop");
    if !cli.privileged {
        builder.unprivileged();
    }
    if cli.user_copy {
        builder.user_copy();
    }
    let mut srv = builder
        .name("ublk-loop")
        .dev_id(cli.dev_id)
        .create_service(&ctl)
        .context("failed to create ublk device")?;
    let mut params = *DeviceParams::new()
        .dev_sectors(size_sectors)
        .logical_block_size(cli.logical_block_size)
        .physical_block_size(cli.physical_block_size)
        .io_min_size(cli.physical_block_size)
        .io_opt_size(cli.physical_block_size)
        .attrs(DeviceAttrs::VolatileCache | DeviceAttrs::Fua)
        .set_io_flusher(cli.privileged);
    if cli.discard {
        params.discard(DiscardParams {
            alignment: Sector::SIZE as _,
            granularity: Sector::SIZE as _,
            max_size: Sector(1 << 30),
            max_write_zeroes_size: Sector(1 << 30),
            max_segments: 1,
        });
    }
    let handler = LoopDev { file };
    let ret = srv
        .serve(&TokioRuntimeBuilder, &params, &handler)
        .context("service error");
    handler.file.sync_all().context("failed to sync file")?;
    ret
}

struct LoopDev {
    file: File,
}

impl BlockDevice for LoopDev {
    fn ready(&self, dev_info: &DeviceInfo, stop: Stopper) -> io::Result<()> {
        log::info!("device ready on {}", dev_info.dev_id());
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

    async fn write(&self, off: Sector, buf: WriteBuf<'_>, flags: IoFlags) -> Result<usize, Errno> {
        self.file
            .write_all_at(buf.as_slice().unwrap(), off.bytes())
            .map_err(convert_err)?;
        if flags.contains(IoFlags::Fua) {
            self.file.sync_data().map_err(convert_err)?;
        }
        Ok(buf.len())
    }

    async fn flush(&self, _flags: IoFlags) -> Result<(), Errno> {
        self.file.sync_data().map_err(convert_err)
    }

    async fn discard(&self, off: Sector, len: usize, flags: IoFlags) -> Result<(), Errno> {
        fallocate(
            &self.file,
            FallocateFlags::PUNCH_HOLE,
            off.bytes(),
            len as _,
        )?;
        if flags.contains(IoFlags::Fua) {
            self.file.sync_data().map_err(convert_err)?;
        }
        Ok(())
    }

    async fn write_zeroes(&self, off: Sector, len: usize, flags: IoFlags) -> Result<(), Errno> {
        fallocate(
            &self.file,
            FallocateFlags::PUNCH_HOLE,
            off.bytes(),
            len as _,
        )?;
        if flags.contains(IoFlags::Fua) {
            self.file.sync_data().map_err(convert_err)?;
        }
        Ok(())
    }
}

#[allow(clippy::needless_pass_by_value)]
fn convert_err(err: io::Error) -> Errno {
    Errno::from_io_error(&err).unwrap_or(Errno::IO)
}
