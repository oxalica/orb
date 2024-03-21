use std::path::PathBuf;

#[derive(Debug, clap::Parser)]
pub enum Cli {
    Serve(ServeCmd),
    Stop(StopCmd),
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
