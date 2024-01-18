use orb::ublk::{ControlDevice, Uring};

/// Ublk device management.
#[derive(Debug, clap::Parser)]
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

fn main() {
    let cli = <Cli as clap::Parser>::parse();
    let ctl = ControlDevice::open()
        .expect("failed to open control device, kernel module 'ublk_drv' not loaded?");
    let mut uring = Uring::new().expect("failed to create io-uring");
    match cli {
        Cli::GetFeatures => {
            let feat = ctl
                .get_features(&mut uring)
                .expect("failed to get features");
            println!("{feat:?}");
        }
        Cli::GetInfo { dev_id } => {
            let info = ctl
                .get_device_info(&mut uring, dev_id)
                .expect("failed to get device info");
            println!("{info:?}");
        }
        Cli::Delete { dev_id } => {
            ctl.delete_device(&mut uring, dev_id)
                .expect("failed to delete device");
        }
        Cli::DeleteAll => {
            let mut failed = false;
            for ent in std::fs::read_dir("/dev").expect("failed to read /dev") {
                if let Some(dev_id) = (|| {
                    ent.ok()?
                        .file_name()
                        .to_str()?
                        .strip_prefix("ublkc")?
                        .parse::<u32>()
                        .ok()
                })() {
                    eprintln!("deleting device {dev_id}");
                    if let Err(err) = ctl.delete_device(&mut uring, dev_id) {
                        eprintln!("{err}");
                        failed = true;
                    }
                }
            }
            if failed {
                std::process::exit(1);
            }
        }
    }
}
