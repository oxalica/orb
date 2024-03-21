use std::num::NonZeroU16;
use std::{fs, io};

use anyhow::{bail, Context, Result};
use clap::Parser;
use cli::{Cli, ServeCmd, StopCmd};
use orb_ublk::runtime::TokioRuntimeBuilder;
use orb_ublk::{ControlDevice, DeviceBuilder, DeviceInfo};
use serde::Deserialize;
use serde_inline_default::serde_inline_default;
use tokio::runtime::Runtime;

mod cli;

fn main() -> Result<()> {
    env_logger::init();
    match Cli::parse() {
        Cli::Serve(cmd) => serve_main(cmd),
        Cli::Stop(cmd) => stop_cmd(cmd),
    }
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct Config {
    ublk: UblkConfig,
    device: orb::service::Config,
    backend: BackendConfig,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields, rename_all = "snake_case")]
enum BackendConfig {
    Memory(orb::memory_backend::Config),
    Onedrive(orb::onedrive_backend::Config),
}

#[serde_inline_default]
#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct UblkConfig {
    #[serde_inline_default(-1)]
    id: i32,
    #[serde(default)]
    unprivileged: bool,
    // TODO: Validate these.
    #[serde_inline_default(1)]
    queues: u16,
    #[serde_inline_default(NonZeroU16::new(64).unwrap())]
    queue_depth: NonZeroU16,
}

fn serve_main(cmd: ServeCmd) -> Result<()> {
    let config = {
        let buf = fs::read_to_string(cmd.config_file).context("failed to read config file")?;
        toml::from_str::<Config>(&buf).context("failed to parse config file")?
    };

    // Fail fast.
    config.device.validate().context("invalid device config")?;
    let ctl = open_ctl_dev()?;

    // XXX: Is there a way to reuse this runtime?
    let rt = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .context("failed to build tokio runtime")?;

    match &config.backend {
        BackendConfig::Memory(_) => {
            let zone_cnt = config.device.dev_secs / config.device.zone_secs;
            let zone_cnt = zone_cnt.try_into().context("zone count overflow")?;
            let memory = orb::memory_backend::Memory::new(zone_cnt);
            serve(&ctl, rt, &config, memory, Vec::new())
        }
        BackendConfig::Onedrive(backend_config) => {
            let (remote, chunks) =
                orb::onedrive_backend::init(backend_config, &config.device, &rt)?;
            serve(&ctl, rt, &config, remote, chunks)
        }
    }
}

fn serve<B: orb::service::Backend>(
    ctl: &ControlDevice,
    rt: Runtime,
    config: &Config,
    backend: B,
    chunks: Vec<(u64, u64)>,
) -> Result<()> {
    let on_ready = |dev_info: &DeviceInfo, stopper: orb_ublk::Stopper| {
        ctrlc::set_handler(move || {
            let _ = sd_notify::notify(false, &[sd_notify::NotifyState::Stopping]);
            log::info!("Signaled to stop, exiting");
            stopper.stop();
        })
        .map_err(|err| io::Error::other(format!("failed to setup signal handler: {err}")))?;
        log::info!("Block device ready at /dev/ublkb{}", dev_info.dev_id());
        let _ = sd_notify::notify(false, &[sd_notify::NotifyState::Ready]);
        Ok(())
    };

    let mut frontend =
        orb::service::Frontend::new(config.device, backend, on_ready).expect("config is validated");
    rt.block_on(frontend.init_chunks(&chunks))
        .context("failed to initialize chunks")?;
    // Free memory.
    drop(chunks);
    // NB. This also drops all the connection pool. Otherwise, new requests may reuse old
    // connections and await old `Future`s, which is in the old runtime thus never polled,
    // resulting a deadlock.
    drop(rt);

    let mut builder = DeviceBuilder::new();
    let mut dev_params = frontend.dev_params();
    if let Ok(id) = u32::try_from(config.ublk.id) {
        builder.id(id);
    }
    if config.ublk.unprivileged {
        builder.unprivileged();
    } else {
        dev_params.set_io_flusher(true);
    }
    let queues = if config.ublk.queues != 0 {
        config.ublk.queues
    } else {
        let n = std::thread::available_parallelism().context("failed to available parallelism")?;
        u16::try_from(n.get()).unwrap_or(u16::MAX)
    };
    builder
        .name("orb")
        .queues(queues)
        .queue_depth(config.ublk.queue_depth.get())
        .zoned()
        .create_service(ctl)
        .context("failed to create ublk device")?
        .serve(&TokioRuntimeBuilder, &dev_params, &frontend)
        .context("service failed")?;

    Ok(())
}

fn stop_cmd(cmd: StopCmd) -> Result<()> {
    let ctl = open_ctl_dev()?;
    if cmd.all {
        for ent in fs::read_dir("/dev").context("failed to read /dev")? {
            if let Some(dev_id) = (|| {
                ent.ok()?
                    .file_name()
                    .to_str()?
                    .strip_prefix("ublkc")?
                    .parse::<u32>()
                    .ok()
            })() {
                ctl.delete_device(dev_id)?;
            }
        }
    } else {
        for &id in &cmd.dev_ids {
            ctl.delete_device(id)?;
        }
    }
    Ok(())
}

fn open_ctl_dev() -> Result<ControlDevice> {
    match ControlDevice::open() {
        Ok(ctl) => Ok(ctl),
        Err(err) => {
            let help = if err.kind() == io::ErrorKind::NotFound {
                ", try loading kernel module via 'modprobe ublk_drv'?"
            } else {
                ""
            };
            bail!("failed to open {}{}", ControlDevice::PATH, help);
        }
    }
}
