use std::fs::File;
use std::io;
use std::os::unix::fs::FileExt;
use std::path::PathBuf;

use anyhow::{ensure, Context};
use clap::Parser;
use orb::runtime::TokioRuntimeBuilder;
use orb::ublk::{
    BlockDevice, ControlDevice, DeviceAttrs, DeviceBuilder, DeviceInfo, DeviceParams,
    DiscardParams, IoFlags, ReadBuf, Stopper, Uring, WriteBuf, SECTOR_SIZE,
};
use rustix::fs::{fallocate, FallocateFlags};
use rustix::io::Errno;

/// Example loop device.
#[derive(Debug, Parser)]
struct Cli {
    backing_file: PathBuf,

    #[clap(long)]
    discard: bool,
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
    ensure!(
        size % SECTOR_SIZE as u64 == 0,
        "backing file size must be multiples of {SECTOR_SIZE}"
    );

    let ctl = ControlDevice::open()
        .context("failed to open control device, kernel module 'ublk_drv' not loaded?")?;
    let uring = Uring::new().context("failed to create control io-uring")?;
    let mut srv = DeviceBuilder::new()
        .name("ublk-loop")
        .unprivileged()
        .create_service(ctl, uring)
        .context("failed to create ublk device")?;
    let mut params = *DeviceParams::new()
        .size(size)
        .attrs(DeviceAttrs::VolatileCache);
    if cli.discard {
        params.discard(DiscardParams {
            alignment: SECTOR_SIZE,
            granularity: SECTOR_SIZE,
            max_size: 1 << 30,
            max_write_zeroes_size: 1 << 30,
            max_segments: 1,
        });
    }
    let handler = LoopDev { file };
    srv.run(TokioRuntimeBuilder, &params, handler)
        .context("service error")?;
    Ok(())
}

struct LoopDev {
    file: File,
}

impl BlockDevice for LoopDev {
    fn ready(&self, dev_info: &DeviceInfo, stop: Stopper) {
        log::info!("device ready on {}", dev_info.dev_id());
        // TODO: Make `ready` return a `Result`?
        ctrlc::set_handler(move || stop.stop()).expect("failed to set Ctrl-C hook");
    }

    async fn read(&self, off: u64, mut buf: ReadBuf<'_>, _flags: IoFlags) -> Result<usize, Errno> {
        self.file
            .read_exact_at(buf.as_slice().unwrap(), off)
            .map_err(convert_err)?;
        Ok(buf.len())
    }

    async fn write(&self, off: u64, buf: WriteBuf<'_>, _flags: IoFlags) -> Result<usize, Errno> {
        self.file
            .write_all_at(buf.as_slice().unwrap(), off)
            .map_err(convert_err)?;
        Ok(buf.len())
    }

    async fn flush(&self, _flags: IoFlags) -> Result<(), Errno> {
        self.file.sync_data().map_err(convert_err)
    }

    async fn discard(&self, off: u64, len: usize, _flags: IoFlags) -> Result<(), Errno> {
        fallocate(&self.file, FallocateFlags::PUNCH_HOLE, off, len as _)
    }

    async fn write_zeroes(&self, off: u64, len: usize, _flags: IoFlags) -> Result<(), Errno> {
        fallocate(&self.file, FallocateFlags::PUNCH_HOLE, off, len as _)
    }
}

fn convert_err(err: io::Error) -> Errno {
    Errno::from_io_error(&err).unwrap_or(Errno::IO)
}
