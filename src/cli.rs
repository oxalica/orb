use std::path::PathBuf;

use clap::builder::TypedValueParser;

#[derive(Debug, clap::Parser)]
pub enum Cli {
    Serve(ServeCmd),
    Stop(StopCmd),
    Login(LoginCmd),
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
pub struct ServeCmd {
    #[clap(long, short)]
    pub config_file: PathBuf,
}

/// Stop and clean up ublk control and block devices `/dev/ublk{c,b}*`.
///
/// This can be either used to stop a running service, or release resources when the service
/// aborted unexpectedly without a correct clean up.
///
/// If the coresponding devices are created by privileged process, this command also requires
/// root privilege to clean them up.
#[derive(Debug, clap::Args)]
pub struct StopCmd {
    /// Clean all existing `ublk` devices.
    #[clap(long, exclusive = true)]
    pub all: bool,
    /// The integer device ids to clean up, ie. the number in the tail of `/dev/ublk{b,c}*`.
    #[clap(required = true)]
    pub dev_ids: Vec<u32>,
}

/// Interactive login Microsoft account and save credential for service use.
///
/// Login can be done while service is running. You can use `systemctl reload` (SIGHUP) to trigger
/// a reload of updated credentials, so that buffered data will not be lost when tokens somehow
/// failed to be refreshed automatically.
/// A successful login always clears existing states (under `state.json`) and enforces a
/// re-synchronization on the next service start.
///
/// WARNING: When the service is running, credentials updating must guarantee that the new one
/// refers to the same account as the old one, otherwise the state will be inconsistent, and all
/// buffered data will be lost!
#[derive(Debug, clap::Args)]
pub struct LoginCmd {
    /// Save credentials for systemd service `orb@<INSTANCE>.service`. This is a shortcut for
    /// `--state-dir /var/lib/orb/<INSTANCE>`.
    ///
    /// INSTANCE should be in systemd-escaped form.
    #[clap(
        long,
        conflicts_with = "state_dir",
        name = "INSTANCE",
        value_parser = clap::builder::StringValueParser::new().try_map(systemd_name_checker),
    )]
    pub systemd: Option<String>,

    /// The state directory to store credentials.
    #[clap(long)]
    pub state_dir: Option<PathBuf>,

    /// The client ID for the registered application.
    #[clap(long)]
    pub client_id: String,
}

fn systemd_name_checker(s: String) -> Result<String, &'static str> {
    if !s.is_empty()
        && !s.starts_with('.')
        && s.bytes()
            .all(|b| b.is_ascii_alphanumeric() || b == b'-' || b == b'\\')
    {
        Ok(s)
    } else {
        Err("invalid escaped systemd instance name")
    }
}
