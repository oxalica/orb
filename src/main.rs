use std::num::NonZeroU16;
use std::path::PathBuf;
use std::{fs, io};

use anyhow::{bail, Context, Result};
use orb_ublk::runtime::TokioRuntimeBuilder;
use orb_ublk::{ControlDevice, DeviceBuilder, DeviceInfo};
use serde::Deserialize;
use tokio::runtime::Runtime;

#[derive(Debug, clap::Parser)]
enum Cli {
    Serve(ServeCmd),
    Stop(StopCmd),
}

fn main() -> Result<()> {
    env_logger::init();
    let cli = <Cli as clap::Parser>::parse();
    match cli {
        Cli::Serve(cmd) => serve_main(cmd),
        Cli::Stop(cmd) => stop_cmd(cmd),
    }
}

/// Start and run the service in the foreground.
///
/// The block device will be ready on `/dev/ublkbX` where X is the next unused integer starting at
/// 0 . Service configurations are passed via the config file. The service will run until it is
/// signaled to exit via SIGINT (Ctrl-C) or SIGTERM, or the device gets deleted by manual `orb
/// stop`. The block device and the control device are cleaned up when the process is exiting.
/// If it somehow failed to correctly clean up, `orb stop` can also be used to release stall
/// control devices.
#[derive(Debug, clap::Args)]
struct ServeCmd {
    #[clap(long, short)]
    config_file: PathBuf,
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

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct UblkConfig {
    #[serde(default = "default_id")]
    id: i32,
    #[serde(default)]
    unprivileged: bool,
    // TODO: Validate these.
    #[serde(default = "default_queues")]
    queues: u16,
    #[serde(default = "default_queue_depth")]
    queue_depth: NonZeroU16,
}

fn default_id() -> i32 {
    -1
}

fn default_queues() -> u16 {
    1
}

fn default_queue_depth() -> NonZeroU16 {
    NonZeroU16::new(64).unwrap()
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
            serve(&ctl, &rt, &config, memory, Vec::new())
        }
        BackendConfig::Onedrive(backend_config) => {
            let (remote, chunks) =
                orb::onedrive_backend::init(backend_config, &config.device, &rt)?;
            serve(&ctl, &rt, &config, remote, chunks)
        }
    }
}

fn serve<B: orb::service::Backend>(
    ctl: &ControlDevice,
    rt: &Runtime,
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

/// Stop and clean up ublk control and block devices `/dev/ublk{c,b}*`.
///
/// This can be either used to stop a running service, or release resources when the service
/// aborted unexpectedly without a correct clean up.
///
/// If the coresponding devices are created by privileged process, this command also requires
/// root privilege to clean them up.
#[derive(Debug, clap::Args)]
struct StopCmd {
    /// Clean all existing `ublk` devices.
    #[clap(long, exclusive = true)]
    all: bool,
    /// The integer device ids to clean up, ie. the number in the tail of `/dev/ublk{b,c}*`.
    #[clap(required = true)]
    dev_ids: Vec<u32>,
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
