use std::io;

use orb_ublk::{ControlDevice, FeatureFlags, BDEV_PREFIX, CDEV_PREFIX};
use rustix::io::Errno;

fn main() -> io::Result<()> {
    let path = std::env::args()
        .nth(1)
        .ok_or_else(|| io::Error::other("missing argument"))?;
    let id = path
        .strip_prefix(CDEV_PREFIX)
        .or(path.strip_prefix(BDEV_PREFIX))
        .and_then(|n| n.parse::<u32>().ok())
        .ok_or_else(|| io::Error::other("argument should be /dev/ublk{b,c}NUM"))?;

    // Open the file to prevent racing deletion.
    let f = match std::fs::File::open(&path) {
        Ok(f) => f,
        // `EBUSY` is reported on the control device when is is opened, likely by the program
        // itself with root permission. In this case, we do not need to participate.
        Err(err) if err.raw_os_error() == Some(Errno::BUSY.raw_os_error()) => return Ok(()),
        Err(err) => return Err(err),
    };
    let ctl = ControlDevice::open()?;
    let info = ctl.get_device_info(id)?;
    assert_eq!(info.dev_id(), id);
    if info.flags().contains(FeatureFlags::UnprivilegedDev) {
        std::os::unix::fs::fchown(&f, Some(info.owner_uid()), Some(info.owner_gid()))?;
    }
    Ok(())
}
