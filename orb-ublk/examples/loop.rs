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
        .create_service(&ctl)
        .context("failed to create ublk device")?;
    let mut params = *DeviceParams::new()
        .dev_sectors(size_sectors)
        .attrs(DeviceAttrs::VolatileCache)
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
    srv.serve(&TokioRuntimeBuilder, &params, &handler)
        .context("service error")?;
    Ok(())
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

    async fn read(
        &self,
        off: Sector,
        mut buf: ReadBuf<'_>,
        _flags: IoFlags,
    ) -> Result<usize, Errno> {
        self.file
            .read_exact_at(buf.as_slice().unwrap(), off.bytes())
            .map_err(convert_err)?;
        Ok(buf.len())
    }

    async fn write(&self, off: Sector, buf: WriteBuf<'_>, _flags: IoFlags) -> Result<usize, Errno> {
        self.file
            .write_all_at(buf.as_slice().unwrap(), off.bytes())
            .map_err(convert_err)?;
        Ok(buf.len())
    }

    async fn flush(&self, _flags: IoFlags) -> Result<(), Errno> {
        self.file.sync_data().map_err(convert_err)
    }

    async fn discard(&self, off: Sector, len: usize, _flags: IoFlags) -> Result<(), Errno> {
        fallocate(
            &self.file,
            FallocateFlags::PUNCH_HOLE,
            off.bytes(),
            len as _,
        )
    }

    async fn write_zeroes(&self, off: Sector, len: usize, _flags: IoFlags) -> Result<(), Errno> {
        fallocate(
            &self.file,
            FallocateFlags::PUNCH_HOLE,
            off.bytes(),
            len as _,
        )
    }
}

#[allow(clippy::needless_pass_by_value)]
fn convert_err(err: io::Error) -> Errno {
    Errno::from_io_error(&err).unwrap_or(Errno::IO)
}
