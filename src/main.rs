use std::num::NonZeroU16;
use std::sync::Arc;
use std::{fs, io};

use anyhow::{bail, Context, Result};
use clap::Parser;
use cli::{Cli, LoginCmd, ServeCmd, StopCmd};
use orb_ublk::{ControlDevice, DeviceBuilder, DeviceInfo};
use serde::Deserialize;
use serde_inline_default::serde_inline_default;
use tokio::runtime::Runtime;
use tokio::signal::unix as signal;

#[cfg(not(target_os = "linux"))]
compile_error!("Only Linux is supported because of ublk driver");

mod cli;

const LOGICAL_SECTOR_SIZE: u32 = 4 << 10; // Typical page size.

type Frontend<B> = orb::service::Frontend<B, LOGICAL_SECTOR_SIZE>;

fn main() -> Result<()> {
    env_logger::Builder::from_env(env_logger::Env::default().default_filter_or("info")).init();

    match Cli::parse() {
        Cli::Serve(cmd) => serve_main(cmd),
        Cli::Stop(cmd) => stop_cmd(cmd),
        Cli::Login(cmd) => login_cmd(cmd),
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

    let mut rt = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .context("failed to build tokio runtime")?;

    match &config.backend {
        BackendConfig::Memory(_) => {
            let zone_cnt = config.device.dev_secs / config.device.zone_secs;
            let zone_cnt = zone_cnt.try_into().context("zone count overflow")?;
            let memory = orb::memory_backend::Memory::new(zone_cnt);
            serve(&ctl, &mut rt, &config, memory, Vec::new())?;
        }
        BackendConfig::Onedrive(backend_config) => {
            let (remote, chunks) =
                orb::onedrive_backend::init(backend_config, &config.device, &rt)?;
            let drive = remote.get_drive();
            {
                let _guard = rt.enter();
                register_reload_signal(drive)?;
            }
            let frontend = serve(&ctl, &mut rt, &config, remote, chunks)?;

            log::info!("flushing buffers before exit...");
            rt.block_on(orb_ublk::BlockDevice::flush(
                &frontend,
                orb_ublk::IoFlags::empty(),
            ))
            // Error reasons should be reported inside `flush`, the returned error here is
            // always EIO and carrying no information.
            .inspect_err(|_| log::error!("final flush failed, data may be lost!"))?;
        }
    }
    Ok(())
}

fn register_reload_signal(
    drive: Arc<orb::onedrive_backend::AutoReloginOnedrive>,
) -> io::Result<()> {
    let mut sighup = signal::signal(signal::SignalKind::hangup())?;
    tokio::spawn(async move {
        loop {
            sighup.recv().await.unwrap();
            let ts = rustix::time::clock_gettime(rustix::time::ClockId::Monotonic);
            let ts_usec = ts.tv_sec * 1_000_000 + ts.tv_nsec / 1_000;
            let _ = sd_notify::notify(
                false,
                &[
                    sd_notify::NotifyState::Reloading,
                    sd_notify::NotifyState::Custom(&format!("MONOTONIC_USEC={ts_usec}")),
                ],
            );
            log::info!("signaled to reload...");
            match drive.reload().await {
                Ok(()) => log::info!("reloaded successfully"),
                Err(err) => log::error!("failed to reload credentials: {err}"),
            }
            let _ = sd_notify::notify(false, &[sd_notify::NotifyState::Ready]);
        }
    });
    Ok(())
}

fn serve<B: orb::service::Backend>(
    ctl: &ControlDevice,
    rt: &mut Runtime,
    config: &Config,
    backend: B,
    chunks: Vec<(u64, u64)>,
) -> Result<Frontend<B>> {
    let on_ready = |dev_info: &DeviceInfo, stopper: orb_ublk::Stopper| {
        let mut sigint = signal::signal(signal::SignalKind::interrupt())?;
        let mut sigterm = signal::signal(signal::SignalKind::terminate())?;
        tokio::task::spawn(async move {
            tokio::select! {
                v = sigint.recv() => v,
                v = sigterm.recv() => v,
            }
            .unwrap();
            log::info!("Signaled to stop, exiting");
            let _ = sd_notify::notify(false, &[sd_notify::NotifyState::Stopping]);
            stopper.stop();
        });

        log::info!("Block device ready at /dev/ublkb{}", dev_info.dev_id());
        let _ = sd_notify::notify(false, &[sd_notify::NotifyState::Ready]);
        Ok(())
    };

    let mut frontend =
        Frontend::new(config.device, backend, on_ready).expect("config is validated");
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
    builder
        .name("orb")
        .queues(1)
        .queue_depth(config.ublk.queue_depth.get())
        .zoned()
        .create_service(ctl)
        .context("failed to create ublk device")?
        .serve_local(rt, &dev_params, &frontend)
        .context("service failed")?;

    Ok(frontend)
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

pub fn login_cmd(cmd: LoginCmd) -> Result<()> {
    let state_dir = cmd.state_dir.unwrap_or_else(|| {
        let inst = cmd.systemd.unwrap();
        format!("/var/lib/orb/{inst}").into()
    });
    orb::onedrive_backend::login::interactive_login(state_dir, cmd.client_id)
}
