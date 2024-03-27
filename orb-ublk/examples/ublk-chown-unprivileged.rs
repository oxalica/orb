use std::io;

use orb_ublk::{ControlDevice, FeatureFlags, BDEV_PREFIX, CDEV_PREFIX};

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
    let f = std::fs::File::open(&path)?;
    let ctl = ControlDevice::open()?;
    let info = ctl.get_device_info(id)?;
    assert_eq!(info.dev_id(), id);
    if info.flags().contains(FeatureFlags::UnprivilegedDev) {
        rustix::fs::fchown(&f, Some(info.owner_uid()), Some(info.owner_gid()))?;
    }
    Ok(())
}
