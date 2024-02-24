use anyhow::{ensure, Context};
use clap::Parser;
use orb::ublk::ControlDevice;

/// Ublk device management.
#[derive(Debug, Parser)]
enum Cli {
    /// Print all features supported by the current kernel driver.
    GetFeatures,
    /// Print the ublk device informantion at `dev_id`.
    GetInfo { dev_id: u32 },
    /// Delete the ublk device at `dev_id`.
    Delete { dev_id: u32 },
    /// Delete all ublk devices.
    DeleteAll,
}

fn main() -> anyhow::Result<()> {
    let cli = Cli::parse();
    let ctl = ControlDevice::open()
        .context("failed to open control device, kernel module 'ublk_drv' not loaded?")?;
    match cli {
        Cli::GetFeatures => {
            let feat = ctl.get_features().context("failed to get features")?;
            println!("{feat:?}");
        }
        Cli::GetInfo { dev_id } => {
            let info = ctl
                .get_device_info(dev_id)
                .context("failed to get device info")?;
            println!("{info:?}");
        }
        Cli::Delete { dev_id } => {
            ctl.delete_device(dev_id)
                .context("failed to delete device")?;
        }
        Cli::DeleteAll => {
            let mut success = true;
            for ent in std::fs::read_dir("/dev").context("failed to read /dev")? {
                if let Some(dev_id) = (|| {
                    ent.ok()?
                        .file_name()
                        .to_str()?
                        .strip_prefix("ublkc")?
                        .parse::<u32>()
                        .ok()
                })() {
                    eprintln!("deleting device {dev_id}");
                    if let Err(err) = ctl.delete_device(dev_id) {
                        eprintln!("{err}");
                        success = false;
                    }
                }
            }
            ensure!(success, "some operations failed");
        }
    }
    Ok(())
}
