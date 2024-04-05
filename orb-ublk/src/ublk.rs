use std::alloc::{GlobalAlloc, Layout, System};
use std::fs::File;
use std::marker::PhantomData;
use std::mem::{ManuallyDrop, MaybeUninit};
use std::ops::ControlFlow;
use std::os::fd::{BorrowedFd, RawFd};
use std::ptr::NonNull;
use std::sync::Arc;
use std::time::Duration;
use std::{fmt, io, mem, ptr, thread};

use io_uring::types::{Fd, Fixed};
use io_uring::{cqueue, opcode, squeue, IoUring, SubmissionQueue};
use rustix::event::{EventfdFlags, PollFd, PollFlags};
use rustix::fd::{AsFd, AsRawFd, OwnedFd};
use rustix::fs::{Gid, Uid};
use rustix::io::Errno;
use rustix::mm;
use rustix::process::Pid;

use crate::runtime::{AsyncRuntime, AsyncRuntimeBuilder, AsyncScopeSpawner};
use crate::{sys, Sector};

// This is mentioned in docs of `DeviceAttrs::io_max_sectors`.
const DEFAULT_IO_BUF_SIZE: u32 = 512 << 10;

pub const CDEV_PREFIX: &str = "/dev/ublkc";
pub const BDEV_PREFIX: &str = "/dev/ublkb";

const DEV_ID_AUTO: u32 = !0;

bitflags::bitflags! {
    #[derive(Debug, Clone, Copy, PartialEq, Eq)]
    pub struct FeatureFlags: u64 {
        const SupportZeroCopy = sys::UBLK_F_SUPPORT_ZERO_COPY as u64;
        const UringCmdCompInTask = sys::UBLK_F_URING_CMD_COMP_IN_TASK as u64;
        const NeedGetData = sys::UBLK_F_NEED_GET_DATA as u64;
        const UserRecovery = sys::UBLK_F_USER_RECOVERY as u64;
        const UserRecoveryReissue = sys::UBLK_F_USER_RECOVERY_REISSUE as u64;
        const UnprivilegedDev = sys::UBLK_F_UNPRIVILEGED_DEV as u64;
        const CmdIoctlEncode = sys::UBLK_F_CMD_IOCTL_ENCODE as u64;
        const UserCopy = sys::UBLK_F_USER_COPY as u64;
        const Zoned = sys::UBLK_F_ZONED as u64;
    }

    #[derive(Debug, Clone, Copy, PartialEq, Eq)]
    struct DeviceParamsType: u32 {
        const Basic = sys::UBLK_PARAM_TYPE_BASIC;
        const Discard = sys::UBLK_PARAM_TYPE_DISCARD;
        const Devt = sys::UBLK_PARAM_TYPE_DEVT;
        const Zoned = sys::UBLK_PARAM_TYPE_ZONED;
    }

    #[derive(Debug, Clone, Copy, PartialEq, Eq)]
    pub struct DeviceAttrs: u32 {
        const ReadOnly =  sys::UBLK_ATTR_READ_ONLY;
        const Rotational = sys::UBLK_ATTR_ROTATIONAL;
        const VolatileCache = sys::UBLK_ATTR_VOLATILE_CACHE;
        const Fua = sys::UBLK_ATTR_FUA;
    }

    #[derive(Debug, Clone, Copy, PartialEq, Eq)]
    pub struct IoFlags: u32 {
        const FailfastDev = sys::UBLK_IO_F_FAILFAST_DEV;
        const FailfastTransport = sys::UBLK_IO_F_FAILFAST_TRANSPORT;
        const FailfastDriver = sys::UBLK_IO_F_FAILFAST_DRIVER;
        const Meta = sys::UBLK_IO_F_META;
        const Fua = sys::UBLK_IO_F_FUA;
        const Nounmap = sys::UBLK_IO_F_NOUNMAP;
        const Swap = sys::UBLK_IO_F_SWAP;
    }
}

#[derive(Debug)]
#[repr(transparent)]
struct CdevPath([u8; Self::MAX_LEN]);

impl CdevPath {
    // "/dev/ublkc2147483647".len() = 20
    const MAX_LEN: usize = 24;
    const PREFIX: &'static str = CDEV_PREFIX;

    fn from_id(id: u32) -> Self {
        use std::io::Write;

        let mut buf = [0u8; Self::MAX_LEN];
        write!(&mut buf[..], "{}{}", Self::PREFIX, id).unwrap();
        Self(buf)
    }
}

/// The global control device for ublk-driver `/dev/ublk-control`.
///
/// Since all control commands are sent through a special SQE128 io-uring, a private io-uring is
/// created and held inside.
pub struct ControlDevice {
    fd: File,
    uring: IoUring<squeue::Entry128, cqueue::Entry>,
    _not_send: PhantomData<*mut ()>,
}

impl fmt::Debug for ControlDevice {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("ControlDevice")
            .field("fd", &self.fd)
            .finish_non_exhaustive()
    }
}

#[repr(C)]
union CtrlCmdBuf {
    cmd: [u8; 80],
    data: sys::ublksrv_ctrl_cmd,
}

impl ControlDevice {
    pub const PATH: &'static str = "/dev/ublk-control";
    const URING_ENTRIES: u32 = 4;

    pub fn open() -> io::Result<Self> {
        let fd = File::options().read(true).write(true).open(Self::PATH)?;
        let uring = IoUring::builder()
            .dontfork()
            .setup_single_issuer()
            .build(Self::URING_ENTRIES)?;
        Ok(Self {
            fd,
            uring,
            _not_send: PhantomData,
        })
    }

    unsafe fn execute_ctrl_cmd_opt_cdev<T>(
        &self,
        include_cdev: bool,
        ioctl_op: u32,
        dev_id: u32,
        buf: T,
        mut cmd: sys::ublksrv_ctrl_cmd,
    ) -> io::Result<T> {
        #[repr(C)]
        struct Payload<T>(CdevPath, T);

        cmd.dev_id = dev_id;
        if include_cdev {
            let buf = Payload(CdevPath::from_id(dev_id), buf);
            cmd.dev_path_len = CdevPath::MAX_LEN as _;
            let ret = self.execute_ctrl_cmd(ioctl_op, buf, cmd)?;
            Ok(ret.1)
        } else {
            self.execute_ctrl_cmd(ioctl_op, buf, cmd)
        }
    }

    unsafe fn execute_ctrl_cmd<T>(
        &self,
        ioctl_op: u32,
        mut buf: T,
        mut cmd: sys::ublksrv_ctrl_cmd,
    ) -> io::Result<T> {
        cmd.addr = ptr::addr_of_mut!(buf) as _;
        cmd.len = mem::size_of::<T>() as _;

        let mut cmd_buf = CtrlCmdBuf { cmd: [0; 80] };
        cmd_buf.data = cmd;
        let sqe = opcode::UringCmd80::new(Fd(self.fd.as_raw_fd()), ioctl_op)
            .cmd(cmd_buf.cmd)
            .build();
        // SAFETY: `ControlDevice` is not `Send`, so we are the only thread running this block.
        // And all references in this SQE are valid.
        unsafe {
            self.uring
                .submission_shared()
                .push(&sqe)
                .expect("squeue full");
        }
        rustix::io::retry_on_intr(|| {
            self.uring
                .submit_and_wait(1)
                .map_err(|err| Errno::from_io_error(&err).expect("invalid errno"))
        })
        .expect("failed to submit uring_cmd");
        // SAFETY: Single-threaded. See above.
        let ret = unsafe {
            self.uring
                .completion_shared()
                .next()
                .expect("must be completed")
                .result()
        };
        if ret >= 0 {
            Ok(buf)
        } else {
            Err(io::Error::from_raw_os_error(-ret))
        }
    }

    pub fn get_features(&self) -> io::Result<FeatureFlags> {
        // SAFETY: Valid uring_cmd.
        unsafe {
            self.execute_ctrl_cmd(sys::UBLK_U_CMD_GET_FEATURES, 0u64, Default::default())
                .map(FeatureFlags::from_bits_truncate)
        }
    }

    pub fn get_device_info(&self, dev_id: u32) -> io::Result<DeviceInfo> {
        // SAFETY: Valid uring_cmd.
        unsafe {
            self.execute_ctrl_cmd_opt_cdev::<sys::ublksrv_ctrl_dev_info>(
                // Always include cdev_path.
                true,
                sys::UBLK_U_CMD_GET_DEV_INFO2,
                dev_id,
                mem::zeroed(),
                Default::default(),
            )
            .map(DeviceInfo)
        }
    }

    /// Create raw ublk device.
    ///
    /// This is the raw method and does not have device lifecycle management.
    /// [`DeviceBuilder::create_service`] should be preferred instead.
    pub fn create_device(&self, builder: &DeviceBuilder) -> io::Result<DeviceInfo> {
        // `-1` for auto-allocation.
        let dev_id = builder.dev_id;
        let pid = rustix::process::getpid();
        // SAFETY: Valid uring_cmd.
        unsafe {
            self.execute_ctrl_cmd(
                sys::UBLK_U_CMD_ADD_DEV,
                sys::ublksrv_ctrl_dev_info {
                    nr_hw_queues: builder.nr_hw_queues,
                    queue_depth: builder.queue_depth,
                    max_io_buf_bytes: builder.io_buf_bytes,
                    dev_id,
                    ublksrv_pid: pid.as_raw_nonzero().get() as _,
                    flags: builder.features.bits(),
                    state: DevState::Dead.into_raw(),
                    ublksrv_flags: builder.user_data,
                    // Does not matter here and will always be set by the driver.
                    owner_uid: 0,
                    owner_gid: 0,
                    ..Default::default()
                },
                sys::ublksrv_ctrl_cmd {
                    queue_id: !0,
                    dev_id,
                    ..Default::default()
                },
            )
            .map(DeviceInfo)
        }
    }

    pub fn delete_device(&self, dev_id: u32) -> io::Result<()> {
        log::trace!("delete device {dev_id}");
        // SAFETY: Valid uring_cmd.
        unsafe {
            self.execute_ctrl_cmd_opt_cdev(
                // Carries no data, so just pass cdev_path anyway.
                true,
                sys::UBLK_U_CMD_DEL_DEV,
                dev_id,
                [0u8; 0],
                Default::default(),
            )?;
        }
        Ok(())
    }

    // This cannot be start alone. IO handlers must be started before it,
    // or this would block indefinitely.
    fn start_device(&self, dev_id: u32, pid: Pid) -> io::Result<()> {
        let pid = pid.as_raw_nonzero().get().try_into().unwrap();
        log::trace!("start device {dev_id} on pid {pid}");
        // SAFETY: Valid uring_cmd.
        unsafe {
            self.execute_ctrl_cmd_opt_cdev(
                // Carries no data, so just pass cdev_path anyway.
                true,
                sys::UBLK_U_CMD_START_DEV,
                dev_id,
                [0u8; 0],
                sys::ublksrv_ctrl_cmd {
                    data: [pid],
                    ..Default::default()
                },
            )?;
        }
        Ok(())
    }

    /// Submit a start-device command without blocking.
    /// It must be completed or cancelled later, or it will leave `Self` inconsistent.
    ///
    /// # Safety
    ///
    /// The command must be completed or canceled within the lifetime of `buf`.
    unsafe fn submit_start_device(
        &self,
        dev_id: u32,
        pid: Pid,
        buf: &mut MaybeUninit<CdevPath>,
    ) -> io::Result<()> {
        let pid = pid.as_raw_nonzero().get().try_into().unwrap();
        let mut cmd_buf = CtrlCmdBuf { cmd: [0; 80] };
        // This ioctl carries no data, thus the layout the same for {un,}privileged devices.
        cmd_buf.data = sys::ublksrv_ctrl_cmd {
            dev_id,
            len: CdevPath::MAX_LEN as _,
            dev_path_len: CdevPath::MAX_LEN as _,
            addr: buf.write(CdevPath::from_id(dev_id)) as *mut _ as u64,
            data: [pid],
            ..Default::default()
        };
        log::trace!("start device {dev_id} on pid {pid}");

        let sqe = opcode::UringCmd80::new(Fd(self.fd.as_raw_fd()), sys::UBLK_U_CMD_START_DEV)
            .cmd(cmd_buf.cmd)
            .build();
        // SAFETY: Single-threaded and it is a valid uring_cmd.
        unsafe { self.uring.submission_shared().push(&sqe).unwrap() };
        self.uring.submit()?;
        Ok(())
    }

    pub fn stop_device(&self, dev_id: u32) -> io::Result<()> {
        log::trace!("stop device {dev_id}");
        // SAFETY: Valid uring_cmd.
        unsafe {
            self.execute_ctrl_cmd_opt_cdev(
                // Carries no data, so just pass cdev_path anyway.
                true,
                sys::UBLK_U_CMD_STOP_DEV,
                dev_id,
                [0u8; 0],
                Default::default(),
            )?;
        }
        Ok(())
    }

    fn set_device_param(
        &self,
        dev_id: u32,
        params: &DeviceParams,
        unprivileged: bool,
    ) -> io::Result<()> {
        log::trace!("set parameters of device {dev_id} to {params:?}");
        // SAFETY: Valid uring_cmd.
        unsafe {
            self.execute_ctrl_cmd_opt_cdev::<sys::ublk_params>(
                unprivileged,
                sys::UBLK_U_CMD_SET_PARAMS,
                dev_id,
                params.build(),
                Default::default(),
            )?;
        }
        Ok(())
    }
}

impl AsRawFd for ControlDevice {
    fn as_raw_fd(&self) -> RawFd {
        self.fd.as_raw_fd()
    }
}

impl AsFd for ControlDevice {
    fn as_fd(&self) -> BorrowedFd<'_> {
        self.fd.as_fd()
    }
}

#[derive(Debug)]
pub struct DeviceBuilder {
    name: String,
    dev_id: u32,
    nr_hw_queues: u16,
    queue_depth: u16,
    io_buf_bytes: u32,
    features: FeatureFlags,
    user_data: u64,

    max_retries: u16,
    retry_delay: Duration,
}

impl Default for DeviceBuilder {
    fn default() -> Self {
        Self::new()
    }
}

impl DeviceBuilder {
    /// The maximal allowed queue depth.
    pub const MAX_QUEUE_DEPTH: u16 = sys::UBLK_MAX_QUEUE_DEPTH as u16;

    /// The maximal allowed number of queues.
    pub const MAX_NR_QUEUES: u16 = sys::UBLK_MAX_NR_QUEUES as u16;

    /// The maximal IO buffer size in bytes.
    pub const MAX_IO_BUF_SIZE: u32 = 1 << sys::UBLK_IO_BUF_BITS;

    #[must_use]
    pub fn new() -> Self {
        Self {
            name: String::new(),
            dev_id: DEV_ID_AUTO,
            nr_hw_queues: 1,
            queue_depth: 64,
            io_buf_bytes: DEFAULT_IO_BUF_SIZE,
            features: FeatureFlags::empty(),
            user_data: 0,
            max_retries: 10,
            retry_delay: Duration::from_millis(100),
        }
    }

    pub fn name(&mut self, name: impl Into<String>) -> &mut Self {
        self.name = name.into();
        self
    }

    /// Set the expected ublk id to create, or `None` for auto-allocation.
    ///
    /// The device id is the numeric part in the end of block device path `/dev/ublkbX`.
    ///
    /// # Panics
    ///
    /// Panic if `id` is `Some(u32::MAX)`.
    pub fn dev_id(&mut self, id: Option<u32>) -> &mut Self {
        assert_ne!(id, Some(DEV_ID_AUTO));
        self.dev_id = id.unwrap_or(DEV_ID_AUTO);
        self
    }

    /// # Panics
    ///
    /// Panic if `nr_hw_queues` is zero or exceeds [`Self::MAX_NR_QUEUES`].
    pub fn queues(&mut self, nr_hw_queues: u16) -> &mut Self {
        assert!((1..=Self::MAX_NR_QUEUES).contains(&nr_hw_queues));
        self.nr_hw_queues = nr_hw_queues;
        self
    }

    /// # Panics
    ///
    /// Panic if `queue_depth` is zero or exceeds [`Self::MAX_QUEUE_DEPTH`].
    pub fn queue_depth(&mut self, queue_depth: u16) -> &mut Self {
        assert!((1..=Self::MAX_QUEUE_DEPTH).contains(&queue_depth));
        self.queue_depth = queue_depth;
        self
    }

    /// # Panics
    ///
    /// Panic if `bytes` exceeds [`Self::MAX_IO_BUF_SIZE`] bytes.
    pub fn io_buf_size(&mut self, bytes: u32) -> &mut Self {
        assert!((1..=Self::MAX_IO_BUF_SIZE).contains(&bytes));
        self.io_buf_bytes = bytes;
        self
    }

    pub fn unprivileged(&mut self) -> &mut Self {
        self.features |= FeatureFlags::UnprivilegedDev;
        self
    }

    pub fn user_copy(&mut self) -> &mut Self {
        self.features |= FeatureFlags::UserCopy;
        self
    }

    /// Set this device to be a zoned device.
    ///
    /// Zoned devices are only supported by kernel with `CONFIG_BLK_DEV_ZONED` enabled.
    /// This also automatically set [`FeatureFlags::UserCopy`] which is required by it.
    pub fn zoned(&mut self) -> &mut Self {
        self.features |= FeatureFlags::Zoned | FeatureFlags::UserCopy;
        self
    }

    /// Set feature flags.
    ///
    /// This will replace previous flags set by, eg. [`DeviceBuilder::unprivileged`].
    pub fn flags(&mut self, flags: FeatureFlags) -> &mut Self {
        self.features = flags;
        self
    }

    /// Add feature flags.
    ///
    /// `flags` will be "or"ed to previously set value.
    pub fn add_flags(&mut self, flags: FeatureFlags) -> &mut Self {
        self.features |= flags;
        self
    }

    /// Custom data to store in but invisible to the driver.
    ///
    /// It is stored in `ublksrv_flags` field of `ublksrv_ctrl_dev_info`.
    pub fn user_data(&mut self, data: u64) -> &mut Self {
        self.user_data = data;
        self
    }

    pub fn max_retries(&mut self, n: u16) -> &mut Self {
        self.max_retries = n;
        self
    }

    /// Create a block device service with lifecycle management.
    ///
    /// This will create a ublk device in a RAII manner, so the device will be deleted when the
    /// returned [`Service`] is dropped. Once the device is created, the per-device control file
    /// `/dev/ublkcX` will appear to support parameters and state setting. The user block device
    /// file `/dev/ublkbX` will still not be online before calling [`Service::serve`] or
    /// [`Service::serve_local`].
    pub fn create_service<'ctl>(&self, ctl: &'ctl ControlDevice) -> io::Result<Service<'ctl>> {
        let dev_info = ctl.create_device(self)?;
        let dev_id = dev_info.dev_id();

        // Delete the device if anything goes wrong.
        scopeguard::defer_on_unwind! {
            if let Err(err) = ctl.stop_device(dev_id) {
                // Ignore errors if already deleted.
                if err.kind() != io::ErrorKind::NotFound {
                    log::error!("failed to stop device {dev_id}: {err}");
                }
            }
        }

        let path = format!("{}{}", CdevPath::PREFIX, dev_id);
        let mut retries_left = self.max_retries;
        let cdev = loop {
            match File::options().read(true).write(true).open(&path) {
                Ok(f) => break f,
                Err(err) if err.kind() == io::ErrorKind::PermissionDenied && retries_left > 0 => {
                    log::warn!("failed to open {path}, retries left: {retries_left}");
                    retries_left -= 1;
                    thread::sleep(self.retry_delay);
                }
                Err(err) => return Err(err),
            }
        };

        Ok(Service {
            dev_info,
            ctl,
            cdev: ManuallyDrop::new(cdev),
        })
    }
}

#[derive(Clone, Copy)]
pub struct DeviceInfo(sys::ublksrv_ctrl_dev_info);

impl fmt::Debug for DeviceInfo {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("DeviceInfo")
            .field("nr_hw_queues", &self.nr_queues())
            .field("queue_depth", &self.queue_depth())
            .field("state", &self.state())
            .field("max_io_buf_bytes", &self.0.max_io_buf_bytes)
            .field("dev_id", &self.0.dev_id)
            .field("ublksrv_pid", &self.0.ublksrv_pid)
            .field("flags", &self.flags())
            .field("user_data", &self.user_data())
            .field("owner_uid", &self.0.owner_uid)
            .field("owner_gid", &self.0.owner_gid)
            .finish()
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[non_exhaustive]
#[repr(u8)]
pub enum DevState {
    Dead = sys::UBLK_S_DEV_DEAD as _,
    Live = sys::UBLK_S_DEV_LIVE as _,
    Quiesced = sys::UBLK_S_DEV_QUIESCED as _,
    #[doc(hidden)]
    Unknown(u16),
}

impl DevState {
    fn into_raw(self) -> u16 {
        match self {
            DevState::Dead => sys::UBLK_S_DEV_DEAD as _,
            DevState::Live => sys::UBLK_S_DEV_LIVE as _,
            DevState::Quiesced => sys::UBLK_S_DEV_QUIESCED as _,
            DevState::Unknown(x) => x,
        }
    }
}

impl DeviceInfo {
    #[must_use]
    pub fn dev_id(&self) -> u32 {
        self.0.dev_id
    }

    #[must_use]
    pub fn queue_depth(&self) -> u16 {
        self.0.queue_depth
    }

    #[must_use]
    pub fn state(&self) -> DevState {
        match self.0.state.into() {
            sys::UBLK_S_DEV_DEAD => DevState::Dead,
            sys::UBLK_S_DEV_LIVE => DevState::Live,
            sys::UBLK_S_DEV_QUIESCED => DevState::Quiesced,
            _ => DevState::Unknown(self.0.state),
        }
    }

    #[must_use]
    pub fn nr_queues(&self) -> u16 {
        self.0.nr_hw_queues
    }

    #[must_use]
    pub fn io_buf_size(&self) -> usize {
        self.0.max_io_buf_bytes as _
    }

    #[must_use]
    pub fn flags(&self) -> FeatureFlags {
        FeatureFlags::from_bits_truncate(self.0.flags)
    }

    #[must_use]
    pub fn user_data(&self) -> u64 {
        self.0.ublksrv_flags
    }

    #[must_use]
    pub fn owner_uid(&self) -> Uid {
        // SAFETY: Retrieved from kernel.
        unsafe { Uid::from_raw(self.0.owner_uid) }
    }

    #[must_use]
    pub fn owner_gid(&self) -> Gid {
        // SAFETY: Retrieved from kernel.
        unsafe { Gid::from_raw(self.0.owner_gid) }
    }
}

#[derive(Debug)]
struct IoDescShm(NonNull<[sys::ublksrv_io_desc]>);

impl Drop for IoDescShm {
    fn drop(&mut self) {
        if let Err(err) = unsafe { mm::munmap(self.0.as_ptr().cast(), self.0.len()) } {
            log::error!("failed to unmap shared memory: {err}");
        }
    }
}

impl IoDescShm {
    fn new(cdev: BorrowedFd<'_>, dev_info: &DeviceInfo, thread_id: u16) -> io::Result<Self> {
        let off = u64::try_from(mem::size_of::<sys::ublksrv_io_desc>())
            .unwrap()
            .checked_mul(sys::UBLK_MAX_QUEUE_DEPTH.into())
            .unwrap()
            .checked_mul(thread_id.into())
            .unwrap()
            .checked_add(sys::UBLKSRV_CMD_BUF_OFFSET.into())
            .unwrap();

        assert_ne!(dev_info.queue_depth(), 0);
        // `m{,un}map` will pad the length to the multiple of pages automatically.
        let size = mem::size_of::<sys::ublksrv_io_desc>()
            .checked_mul(dev_info.queue_depth().into())
            .unwrap();

        let ptr = unsafe {
            mm::mmap(
                ptr::null_mut(),
                size,
                mm::ProtFlags::READ,
                mm::MapFlags::SHARED | mm::MapFlags::POPULATE,
                cdev,
                off,
            )?
        };
        let ptr = NonNull::slice_from_raw_parts(
            NonNull::new(ptr.cast::<sys::ublksrv_io_desc>()).unwrap(),
            dev_info.queue_depth().into(),
        );
        Ok(IoDescShm(ptr))
    }

    fn get(&self, tag: u16) -> sys::ublksrv_io_desc {
        unsafe { self.0.as_ref()[tag as usize] }
    }
}

#[derive(Debug)]
pub struct Service<'ctl> {
    dev_info: DeviceInfo,
    ctl: &'ctl ControlDevice,
    /// `/dev/ublkcX` file.
    cdev: ManuallyDrop<File>,
}

impl Drop for Service<'_> {
    fn drop(&mut self) {
        // First, drop all resources derived from the device.
        // SAFETY: This is only called once here, and will not be used later.
        unsafe { ManuallyDrop::drop(&mut self.cdev) }
        let dev_id = self.dev_info().dev_id();
        if let Err(err) = self.ctl.delete_device(dev_id) {
            // Ignore errors if already deleted.
            if !is_device_gone(&err) {
                log::error!("failed to delete device {dev_id}: {err}");
            }
        }
    }
}

/// Check whether the error is caused by that the device is gone by external forces.
fn is_device_gone(err: &io::Error) -> bool {
    matches!(Errno::from_io_error(err), Some(Errno::NOENT | Errno::NODEV))
}

/// Signal all threads when something goes wrong somewhere.
#[derive(Clone)]
struct SignalStopOnDrop<'a>(BorrowedFd<'a>);
impl Drop for SignalStopOnDrop<'_> {
    fn drop(&mut self) {
        rustix::io::write(self.0, &1u64.to_ne_bytes()).unwrap();
    }
}

#[derive(Debug, Clone)]
pub struct Stopper(Arc<OwnedFd>);

impl Stopper {
    pub fn stop(&self) {
        let _: Result<_, _> = rustix::io::write(&self.0, &1u64.to_ne_bytes());
    }
}

impl Service<'_> {
    const SUPPORTED_FLAGS: FeatureFlags = FeatureFlags::UringCmdCompInTask
        .union(FeatureFlags::UnprivilegedDev)
        .union(FeatureFlags::CmdIoctlEncode)
        .union(FeatureFlags::UserCopy)
        .union(FeatureFlags::Zoned);

    #[must_use]
    pub fn dev_info(&self) -> &DeviceInfo {
        &self.dev_info
    }

    fn check_params(&self, params: &DeviceParams) {
        let unsupported_flags = self.dev_info().flags() - Self::SUPPORTED_FLAGS;
        assert!(
            unsupported_flags.is_empty(),
            "flags not supported: {unsupported_flags:?}",
        );
        let dev_is_zoned = self.dev_info.flags().contains(FeatureFlags::Zoned);
        let has_zoned_params = params.zoned.is_some();
        assert_eq!(
            dev_is_zoned, has_zoned_params,
            "device feature has zoned={dev_is_zoned} but parameters zoned={has_zoned_params}",
        );
        if dev_is_zoned {
            assert_ne!(
                params.chunk_sectors,
                Sector(0),
                "`chunk_sectors` must be set for zoned devices",
            );
        }
    }

    /// Start and run the service.
    ///
    /// This will block the current thread and spawn [`queues`](DeviceBuilder::queues) many worker
    /// threads, each handling [`queue_depth`](DeviceBuilder::queue_depth) many concurrent
    /// requests using the per-thread IO-uring, driven by per-thread asynchronous runtime built by
    /// given [`AsyncRuntimeBuilder`].
    ///
    /// The main thread will call [`BlockDevice::ready`] once all worker are initialized and the
    /// block device `/dev/ublkbX` is created.
    ///
    /// When the service is signalled to exit (by [`Stopper::stop`], an error, or being stopped by
    /// another process), it will automatically stop the device `/dev/ublkbX`.
    ///
    /// # Panics
    ///
    /// Panic if the device parameters are invalid.
    pub fn serve<RB, D>(
        &mut self,
        runtime_builder: &RB,
        params: &DeviceParams,
        handler: &D,
    ) -> io::Result<()>
    where
        RB: AsyncRuntimeBuilder + Sync,
        D: BlockDevice + Sync,
    {
        // Sanity check.
        self.check_params(params);
        let dev_id = self.dev_info().dev_id();
        let nr_queues = self.dev_info().nr_queues();
        assert_ne!(nr_queues, 0);

        let unprivileged = self
            .dev_info()
            .flags()
            .contains(FeatureFlags::UnprivilegedDev);
        self.ctl.set_device_param(dev_id, params, unprivileged)?;

        // The guard to stop the device once it's started.
        // This must be outside the thread scope so all resources are released on stopping.
        let mut stop_device_guard = scopeguard::guard(false, |active| {
            if !active {
                return;
            }
            if let Err(err) = self.ctl.stop_device(dev_id) {
                // Ignore errors if already deleted.
                if !is_device_gone(&err) {
                    log::error!("failed to stop device {dev_id}: {err}");
                }
            }
        });

        // No one is actually `read` it, so no need to be a semaphore.
        let exit_fd = Arc::new(rustix::event::eventfd(0, EventfdFlags::CLOEXEC)?);
        thread::scope(|s| {
            // One element gets produced once a thread is initialized and ready for events.
            let (ready_tx, ready_rx) = std::sync::mpsc::sync_channel::<()>(nr_queues.into());

            // This will be dropped inside the scope, so all threads are signaled to exit
            // during force join.
            let thread_stop_guard = SignalStopOnDrop(exit_fd.as_fd());

            let threads = (0..nr_queues)
                .map(|thread_id| {
                    let cdev = self.cdev.as_fd();
                    let dev_info = self.dev_info;
                    let ready_tx = ready_tx.clone();
                    let stop_guard = thread_stop_guard.clone();
                    thread::Builder::new()
                        .name(format!("io-worker-{thread_id}"))
                        .spawn_scoped(s, move || {
                            let mut runtime = runtime_builder.build()?;
                            let mut worker = IoWorker {
                                thread_id,
                                ready_tx: Some(ready_tx),
                                cdev,
                                dev_info: &dev_info,
                                handler,
                                runtime: &mut runtime,
                                set_io_flusher: params.set_io_flusher,
                                wait_device_start: None,
                                stop_guard,
                            };
                            worker.run()
                        })
                })
                .collect::<io::Result<Vec<_>>>()?;

            // NB. Wait for all handler threads to be initialized and ready, or `start_device` will
            // block indefinitely.
            // If the channel gets closed early, there must be some thread failed. Error messages
            // will be collected by the join loop below.
            drop(ready_tx);
            if let Ok(()) = (0..nr_queues).try_for_each(|_| ready_rx.recv()) {
                self.ctl.start_device(dev_id, rustix::process::getpid())?;

                // Now device is started, and `/dev/ublkbX` appears.
                *stop_device_guard = true;
                handler.ready(self.dev_info(), Stopper(Arc::clone(&exit_fd)))?;

                let ret = rustix::io::retry_on_intr(|| {
                    rustix::event::poll(
                        &mut [PollFd::new(&exit_fd, PollFlags::IN)],
                        -1, // INFINITE
                    )
                })?;
                assert_eq!(ret, 1);
            }

            // Collect panics and errors.
            for (thread_id, h) in threads.into_iter().enumerate() {
                match h.join() {
                    Ok(Ok(())) => {}
                    // Device deleted by other thread or process. Treat it as a graceful shutdown.
                    Ok(Err(err)) if err.raw_os_error() == Some(Errno::NODEV.raw_os_error()) => {}
                    Ok(Err(err)) => return Err(err),
                    Err(_) => {
                        return Err(io::Error::other(format!("IO worker {thread_id} panicked")));
                    }
                }
            }
            Ok(())
        })
    }

    /// Start and run the service on current thread.
    ///
    /// Similar to [`Service::serve`] but the asynchronous runtime, IO-uring and request handlers
    /// are all running on the current thread, thus they do not need to be [`Sync`].
    ///
    /// Be aware that [`BlockDevice::ready`] is also called from the current thread. Inside it,
    /// doing any I/O actions to the target block device `/dev/ublkbX` would cause a dead-lock.
    ///
    /// When the service is signalled to exit (by [`Stopper::stop`], an error, or being stopped by
    /// another process), it will automatically stop the device `/dev/ublkbX`.
    ///
    /// # Panics
    ///
    /// Panic if the number of [`queues`](DeviceBuilder::queues) of this device is not one.
    pub fn serve_local<R, D>(
        &mut self,
        runtime: &mut R,
        params: &DeviceParams,
        handler: &D,
    ) -> io::Result<()>
    where
        R: AsyncRuntime,
        D: BlockDevice,
    {
        self.check_params(params);
        let nr_queues = self.dev_info().nr_queues();
        assert_eq!(nr_queues, 1, "`serve_local` requires a single queue");

        let dev_id = self.dev_info().dev_id();
        let unprivileged = self
            .dev_info()
            .flags()
            .contains(FeatureFlags::UnprivilegedDev);
        self.ctl.set_device_param(dev_id, params, unprivileged)?;

        // No one is actually `read` it, so no need to be a semaphore.
        // Note that this fd is kept alive during the service lifespan, so dropping `stopper` will
        // not cause a service stop.
        let exit_fd = Arc::new(rustix::event::eventfd(0, EventfdFlags::CLOEXEC)?);
        let stopper = Stopper(Arc::clone(&exit_fd));

        let worker = IoWorker {
            thread_id: 0,
            ready_tx: None,
            cdev: self.cdev.as_fd(),
            dev_info: &self.dev_info,
            handler,
            runtime,
            set_io_flusher: params.set_io_flusher,
            wait_device_start: Some((&self.ctl.uring, stopper)),
            stop_guard: SignalStopOnDrop(exit_fd.as_fd()),
        };
        let mut worker = scopeguard::guard(worker, |worker| {
            if worker.wait_device_start.is_some() {
                // If the service fails before getting ready, no cleanup is needed.
                return;
            }

            // Cancel the device starting request, and reset it to empty.
            sync_cancel_all(&self.ctl.uring);
            // SAFETY: `ctl` is held only by the current thread, thus it's exclusively to us here.
            unsafe {
                self.ctl.uring.completion_shared().for_each(|_| {});
            }

            if let Err(err) = self.ctl.stop_device(self.dev_info.dev_id()) {
                if !is_device_gone(&err) {
                    log::error!("failed to stop device {} {}", self.dev_info.dev_id(), err);
                }
            }
        });
        let pid = rustix::process::getpid();
        let mut buf = MaybeUninit::uninit();
        // SAFETY: The `Drop` of `worker` ensures the command get completed or cancelled before
        // return.
        unsafe { self.ctl.submit_start_device(dev_id, pid, &mut buf).unwrap() }
        worker.run()?;
        Ok(())
    }
}

/// The aligned buffer to pass data from and to the kernel driver.
/// Each concurrenty task with a distinct tag owns a proportion of it.
struct IoBuffers {
    ptr: NonNull<u8>,
    bufs: usize,
    buf_size: usize,
}

impl IoBuffers {
    const ALIGN: usize = 64;

    fn new(bufs: usize, buf_size: usize) -> Self {
        assert!(bufs != 0 && buf_size != 0);
        let buf_size = buf_size.next_multiple_of(Self::ALIGN);
        let size = bufs.checked_mul(buf_size).unwrap();
        let layout = Layout::from_size_align(size, Self::ALIGN).unwrap();
        match NonNull::new(unsafe { System.alloc(layout) }) {
            None => std::alloc::handle_alloc_error(layout),
            Some(ptr) => Self {
                ptr,
                bufs,
                buf_size,
            },
        }
    }

    fn get(&self, idx: usize) -> NonNull<[u8]> {
        assert!(idx < self.bufs);
        // SAFETY: `ptr` is valid and `idx` is checked above.
        unsafe {
            NonNull::new_unchecked(ptr::slice_from_raw_parts_mut(
                self.ptr.as_ptr().add(idx * self.buf_size),
                self.buf_size,
            ))
        }
    }
}

impl Drop for IoBuffers {
    fn drop(&mut self) {
        // SAFETY: Allocated by us.
        unsafe {
            let layout = Layout::from_size_align_unchecked(self.bufs * self.buf_size, Self::ALIGN);
            System.dealloc(self.ptr.as_ptr().cast(), layout);
        }
    }
}

fn sync_cancel_all<S: squeue::EntryMarker, C: cqueue::EntryMarker>(uring: &IoUring<S, C>) {
    // All ops must be canceled before return, otherwise it's a UB.
    // NB. We must not use `defer_on_unwind` here, otherwise this will abort unconditionally when
    // this is called from `Drop` during unwinding.
    let guard = scopeguard::guard((), |()| std::process::abort());
    if let Err(err) = uring
        .submitter()
        .register_sync_cancel(None, io_uring::types::CancelBuilder::any())
    {
        if err.kind() != io::ErrorKind::NotFound {
            log::error!("failed to cancel inflight ops in io-uring: {}", err);
            // Trigger bomb.
            return;
        }
    }
    // Defuse.
    scopeguard::ScopeGuard::into_inner(guard);
}

struct IoWorker<'a, 'r, B, R> {
    thread_id: u16,
    // Signal the main thread for service readiness. `None` for `serve_local`.
    ready_tx: Option<std::sync::mpsc::SyncSender<()>>,
    cdev: BorrowedFd<'a>,
    dev_info: &'a DeviceInfo,
    handler: &'a B,
    runtime: &'r mut R,
    set_io_flusher: bool,

    // If the worker is running in-place by `Service::serve_local`, we need to wait for the
    // device start command in the control io-uring to finish before sending a `BlockDevice::ready`
    // notification.
    wait_device_start: Option<(&'a IoUring<squeue::Entry128, cqueue::Entry>, Stopper)>,

    // This is dropped last.
    stop_guard: SignalStopOnDrop<'a>,
}

impl<'r, B: BlockDevice, R: AsyncRuntime + 'r> IoWorker<'_, 'r, B, R> {
    // FIXME: Break this up?
    #[allow(clippy::too_many_lines)]
    #[allow(clippy::items_after_statements)]
    fn run(&mut self) -> io::Result<()> {
        let _reset_io_flusher_guard = self
            .set_io_flusher
            .then(|| -> io::Result<_> {
                rustix::process::configure_io_flusher_behavior(true)?;
                log::debug!("set thread as IO_FLUSHER");
                Ok(scopeguard::guard((), |()| {
                    if let Err(err) = rustix::process::configure_io_flusher_behavior(false) {
                        log::error!("failed to reset IO_FLUSHER state: {err}");
                    }
                }))
            })
            .transpose()?;

        let shm = IoDescShm::new(self.cdev, self.dev_info, self.thread_id)?;

        let user_copy = self.dev_info.flags().contains(FeatureFlags::UserCopy);
        // Must define the buffer before the io-uring, see below in `io_uring`.
        let io_bufs = (!user_copy).then(|| {
            IoBuffers::new(
                self.dev_info.queue_depth().into(),
                self.dev_info.io_buf_size(),
            )
        });

        // Plus `PollAdd` for stop guard xor ready hook.
        let ring_size = (u32::from(self.dev_info.queue_depth()) + 1)
            .checked_next_power_of_two()
            .unwrap();
        // NB. Ensure all inflight ops are cancelled before dropping the buffer defined above,
        // otherwise it's a use-after-free.
        let mut io_ring = scopeguard::guard(IoUring::new(ring_size)?, |io_ring| {
            sync_cancel_all(&io_ring);
        });
        io_ring
            .submitter()
            .register_files(&[self.cdev.as_raw_fd()])?;
        const CDEV_FIXED_FD: Fixed = Fixed(0);
        const NOTIFY_USER_DATA: u64 = !0;

        let refill_sqe =
            |sq: &mut SubmissionQueue<'_>, i: u16, result: Option<i32>, zone_append_lba: u64| {
                let cmd = sys::ublksrv_io_cmd {
                    q_id: self.thread_id,
                    tag: i,
                    result: result.unwrap_or(-1),
                    __bindgen_anon_1: match &io_bufs {
                        Some(bufs) => sys::ublksrv_io_cmd__bindgen_ty_1 {
                            addr: bufs.get(i.into()).as_ptr().cast::<u8>() as _,
                        },
                        // If this is not ZONE_APPEND, this is zero and has the same repr as
                        // `{ addr: 0 }`, which is expected by the driver.
                        None => sys::ublksrv_io_cmd__bindgen_ty_1 { zone_append_lba },
                    },
                };
                let cmd_op = if result.is_some() {
                    sys::UBLK_IO_COMMIT_AND_FETCH_REQ
                } else {
                    sys::UBLK_IO_FETCH_REQ
                };
                let sqe = opcode::UringCmd16::new(CDEV_FIXED_FD, cmd_op)
                    .cmd(unsafe { mem::transmute(cmd) })
                    .build()
                    .user_data(i.into());
                unsafe {
                    sq.push(&sqe).expect("squeue should be big enough");
                }
            };

        // SAFETY: `BorrowedFd` is valid.
        let enqueue_poll_in = |sq: &mut SubmissionQueue<'_>, fd: BorrowedFd<'_>| unsafe {
            let sqe = opcode::PollAdd::new(Fd(fd.as_raw_fd()), PollFlags::IN.bits().into())
                .build()
                .user_data(NOTIFY_USER_DATA);
            sq.push(&sqe).unwrap();
        };

        {
            let mut sq = io_ring.submission();
            let fd = if let Some((ctl_uring, _)) = &self.wait_device_start {
                // Workaround: https://github.com/tokio-rs/io-uring/pull/254
                // SAFETY: `ctl_uring` is valid.
                unsafe { BorrowedFd::borrow_raw(ctl_uring.as_raw_fd()) }
            } else {
                self.stop_guard.0
            };
            enqueue_poll_in(&mut sq, fd);
            for i in 0..self.dev_info.queue_depth() {
                refill_sqe(&mut sq, i, None, 0);
            }
        }
        io_ring.submit()?;

        log::debug!("IO worker {} initialized", self.thread_id);
        if let Some(ready_tx) = self.ready_tx.take() {
            if ready_tx.send(()).is_err() {
                // Stopping.
                return Ok(());
            }
        }

        self.runtime.drive_uring(&io_ring, |spawner| {
            // SAFETY: This is the only place to modify the CQ.
            let cq = unsafe { io_ring.completion_shared() };
            for cqe in cq {
                if cqe.user_data() == NOTIFY_USER_DATA {
                    assert!(
                        PollFlags::from_bits_truncate(cqe.result() as _).contains(PollFlags::IN),
                        "unexpected poll result: {}",
                        cqe.result(),
                    );
                    // `wait_device_start` is reset to `None` to mark readiness.
                    // See cleanup in `Service::serve_local`.
                    if let Some((ctl_uring, stopper)) = self.wait_device_start.take() {
                        // Single-threaded worker. Start-device-request completed.
                        let cqe = unsafe { ctl_uring.completion_shared().next().unwrap() };
                        if cqe.result() < 0 {
                            return Err(io::Error::from_raw_os_error(-cqe.result()));
                        }
                        self.handler.ready(self.dev_info, stopper)?;

                        // SAFETY: All SQ writing is done on the same current thread.
                        // See below in `commit_and_fetch`.
                        unsafe {
                            enqueue_poll_in(&mut io_ring.submission_shared(), self.stop_guard.0);
                        }
                        io_ring.submit()?;
                        continue;
                    }

                    // Multi-threaded worker.
                    log::debug!("IO worker signaled to exit");
                    return Ok(ControlFlow::Break(()));
                }

                // Here it must be a FETCH request.
                if cqe.result() < 0 {
                    let err = io::Error::from_raw_os_error(-cqe.result());
                    if is_device_gone(&err) {
                        log::warn!("device gone by external forces, stopping: {err}");
                        return Ok(ControlFlow::Break(()));
                    }
                    log::error!("failed to fetch ublk events: {err}");
                    return Err(err);
                }

                let tag = cqe.user_data() as u16;
                let io_ring = &*io_ring;
                let commit_and_fetch = move |ret: i32, zone_append_lba: u64| {
                    log::trace!("-> respond {ret} {zone_append_lba}");
                    // SAFETY: All futures are executed on the same thread, which is guarantee
                    // by no `Send` bound on parameters of `Runtime::{block_on,spawn_local}`.
                    // So there can only be one future running this block at the same time.
                    unsafe {
                        let mut sq = io_ring.submission_shared();
                        refill_sqe(&mut sq, tag, Some(ret), zone_append_lba);
                    }
                    io_ring.submit().expect("failed to submit");
                };

                let iod = shm.get(tag);
                let flags = IoFlags::from_bits_truncate(iod.op_flags);

                // NB. These fields may contain garbage for ops without them.
                // Use `wrapping_` to ignore errors.
                let off = Sector(iod.start_sector);
                // The 2 variants both have type `u32`.
                let zones = unsafe { iod.__bindgen_anon_1.nr_zones };
                let len = unsafe { iod.__bindgen_anon_1.nr_sectors as usize }
                    .wrapping_mul(Sector::SIZE as usize);
                let pwrite_off = u64::from(sys::UBLKSRV_IO_BUF_OFFSET)
                    + (u64::from(self.thread_id) << sys::UBLK_QID_OFF)
                    + (u64::from(tag) << sys::UBLK_TAG_OFF);
                let get_buf = || {
                    match &io_bufs {
                        // SAFETY: This buffer is exclusive for task of `tag`.
                        Some(bufs) => unsafe {
                            RawBuf::PreCopied(&mut bufs.get(tag.into()).as_mut()[..len])
                        },
                        None => RawBuf::UserCopy {
                            cdev: self.cdev,
                            off: pwrite_off,
                            remaining: len as _,
                        },
                    }
                };

                // Make `async move` only move the reference to the handler.
                let h = self.handler;
                // XXX: Is there a better way to handle panicking here?
                macro_rules! spawn {
                    ($handler:expr) => {
                        spawner.spawn(async move {
                            // Always commit.
                            let mut guard =
                                scopeguard::guard((-Errno::IO.raw_os_error(), 0), |(ret, lba)| {
                                    if std::thread::panicking() {
                                        log::warn!("handler panicked, returning EIO");
                                    }
                                    commit_and_fetch(ret, lba)
                                });
                            let ret = $handler.into_c_result();
                            *guard = ret;
                        })
                    };
                }

                match iod.op_flags & 0xFF {
                    sys::UBLK_IO_OP_READ => {
                        log::trace!("READ offset={off} len={len} flags={flags:?}");
                        let mut buf = ReadBuf(get_buf(), PhantomData);
                        spawn!(h.read(off, &mut buf, flags).await.map(|()| {
                            let read = (len - buf.remaining())
                                .try_into()
                                .expect("buffer size must not exceed i32");
                            (read, 0)
                        }));
                    }
                    sys::UBLK_IO_OP_WRITE => {
                        log::trace!("WRITE offset={off} len={len} flags={flags:?}");
                        let buf = WriteBuf(get_buf(), PhantomData);
                        spawn!(h.write(off, buf, flags).await.inspect(|&written| {
                            assert!(written <= len, "invalid written amount");
                        }));
                    }
                    sys::UBLK_IO_OP_FLUSH => {
                        log::trace!("FLUSH flags={flags:?}");
                        spawn!(h.flush(flags).await);
                    }
                    sys::UBLK_IO_OP_DISCARD => {
                        log::trace!("DISCARD offset={off} len={len} flags={flags:?}");
                        spawn!(h.discard(off, len, flags).await);
                    }
                    sys::UBLK_IO_OP_WRITE_ZEROES => {
                        log::trace!("WRITE_ZEROES offset={off} len={len} flags={flags:?}");
                        spawn!(h.write_zeroes(off, len, flags).await);
                    }
                    sys::UBLK_IO_OP_REPORT_ZONES => {
                        log::trace!("REPORT_ZONES offset={off} zones={zones} flags={flags:?}");
                        let mut buf = ZoneBuf {
                            cdev: self.cdev,
                            off: pwrite_off,
                            remaining_zones: zones,
                            _not_send_invariant: PhantomData,
                        };
                        spawn!(h.report_zones(off, &mut buf, flags).await.map(|()| {
                            // NB. Must calculated from the advance of offset, not
                            // `remaining_zones`. See `ZoneBuf::report` for why.
                            let written = (buf.off - pwrite_off)
                                .try_into()
                                .expect("buffer size must not exceed i32");
                            (written, 0)
                        }));
                    }
                    sys::UBLK_IO_OP_ZONE_APPEND => {
                        log::trace!("ZONE_APPEND offset={off} len={len} flags={flags:?}");
                        let buf = WriteBuf(get_buf(), PhantomData);
                        spawn!(h.zone_append(off, buf, flags).await.map(|lba| (0, lba.0)));
                    }
                    sys::UBLK_IO_OP_ZONE_OPEN => {
                        log::trace!("ZONE_OPEN offset={off} flags={flags:?}");
                        spawn!(h.zone_open(off, flags).await);
                    }
                    sys::UBLK_IO_OP_ZONE_CLOSE => {
                        log::trace!("ZONE_CLOSE offset={off} flags={flags:?}");
                        spawn!(h.zone_close(off, flags).await);
                    }
                    sys::UBLK_IO_OP_ZONE_FINISH => {
                        log::trace!("ZONE_FINISH offset={off} flags={flags:?}");
                        spawn!(h.zone_finish(off, flags).await);
                    }
                    sys::UBLK_IO_OP_ZONE_RESET => {
                        log::trace!("ZONE_RESET offset={off} flags={flags:?}");
                        spawn!(h.zone_reset(off, flags).await);
                    }
                    sys::UBLK_IO_OP_ZONE_RESET_ALL => {
                        log::trace!("ZONE_RESET_ALL flags={flags:?}");
                        spawn!(h.zone_reset_all(flags).await);
                    }
                    op => {
                        log::error!("unsupported op: {op}");
                        commit_and_fetch(-Errno::IO.raw_os_error(), 0);
                    }
                }
            }

            Ok(ControlFlow::Continue(()))
        })
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct DeviceParams {
    set_io_flusher: bool,
    attrs: DeviceAttrs,
    dev_sectors: Sector,
    logical_block_shift: u8,
    physical_block_shift: u8,
    chunk_sectors: Sector,
    io_min_shift: u8,
    io_opt_shift: u8,
    io_max_secs: u32,
    virt_boundary_mask: u64,
    discard: Option<DiscardParams>,
    zoned: Option<ZonedParams>,
}

impl Default for DeviceParams {
    fn default() -> Self {
        Self::new()
    }
}

impl DeviceParams {
    /// Default parameters.
    #[must_use]
    pub const fn new() -> Self {
        // The default values here are somewhat arbitrary.
        Self {
            set_io_flusher: false,
            attrs: DeviceAttrs::empty(),
            dev_sectors: Sector(0),
            logical_block_shift: 512u32.trailing_zeros() as u8,
            physical_block_shift: 4096u32.trailing_zeros() as u8,
            io_min_shift: 4096u32.trailing_zeros() as u8,
            io_opt_shift: 4096u32.trailing_zeros() as u8,
            io_max_secs: Sector::from_bytes(DEFAULT_IO_BUF_SIZE as u64).0 as u32,
            chunk_sectors: Sector(0),
            virt_boundary_mask: 0,
            discard: None,
            zoned: None,
        }
    }

    /// Set the worker threads in [`IO_FLUSHER`] state.
    ///
    /// > This will put the process in the [`IO_FLUSHER`] state, which allows it special treatment
    /// > to make progress when allocating memory.
    ///
    /// It requires `CAP_SYS_RESOURCE` to do so.
    ///
    /// [`IO_FLUSHER`]: https://man7.org/linux/man-pages/man2/prctl.2.html
    pub fn set_io_flusher(&mut self, io_flusher: bool) -> &mut Self {
        self.set_io_flusher = io_flusher;
        self
    }

    /// Set the total size of the block device in [`Sector`]s.
    pub fn dev_sectors(&mut self, sec: Sector) -> &mut Self {
        self.dev_sectors = sec;
        self
    }

    /// Set logical block size in bytes.
    ///
    /// It must be a power of two and not greater than the page size (typically 4096bytes).
    ///
    /// See:
    /// <https://www.kernel.org/doc/html/v6.7/core-api/kernel-api.html#c.blk_queue_logical_block_size>
    ///
    /// # Panics
    ///
    /// Panic if `size` is not a power of two.
    pub fn logical_block_size(&mut self, size: u64) -> &mut Self {
        assert!(size.is_power_of_two());
        self.logical_block_shift = size.trailing_zeros() as u8;
        self
    }

    /// Set physical block size in bytes.
    ///
    /// See:
    /// <https://www.kernel.org/doc/html/v6.7/core-api/kernel-api.html#c.blk_queue_physical_block_size>
    ///
    /// # Panics
    ///
    /// Panic if `size` is not a power of two.
    pub fn physical_block_size(&mut self, size: u64) -> &mut Self {
        assert!(size.is_power_of_two());
        self.physical_block_shift = size.trailing_zeros() as u8;
        self
    }

    /// Set minimum request size for the queue in bytes.
    ///
    /// See:
    /// <https://www.kernel.org/doc/html/v6.7/core-api/kernel-api.html#c.blk_queue_io_min>
    pub fn io_min_size(&mut self, size: u64) -> &mut Self {
        assert!(size.is_power_of_two());
        self.io_min_shift = size.trailing_zeros() as u8;
        self
    }

    /// Set optimal request size for the queue in bytes.
    ///
    /// See:
    /// <https://www.kernel.org/doc/html/v6.7/core-api/kernel-api.html#c.blk_queue_io_opt>
    pub fn io_opt_size(&mut self, size: u64) -> &mut Self {
        assert!(size.is_power_of_two());
        self.io_opt_shift = size.trailing_zeros() as u8;
        self
    }

    /// Set maximum request size for the queue in [`Sector`]s.
    ///
    /// Note that a single request can still only pass at most [`DeviceBuilder::io_buf_size`] bytes
    /// data (which is 512KiB by default). Thus it is recommended to set both parameters together
    /// to make sure it takes effect.
    ///
    /// See:
    /// <https://www.kernel.org/doc/html/v6.7/core-api/kernel-api.html#c.blk_queue_max_hw_sectors>
    pub fn io_max_sectors(&mut self, size: Sector) -> &mut Self {
        assert!(u32::try_from(size.0).is_ok());
        self.io_max_secs = size.0 as u32;
        self
    }

    /// Set size of the chunk for this queue in [`Sector`]s.
    ///
    /// See:
    /// <https://www.kernel.org/doc/html/v6.7/core-api/kernel-api.html#c.blk_queue_chunk_sectors>
    pub fn chunk_sectors(&mut self, sec: Sector) -> &mut Self {
        assert!(u32::try_from(sec.0).is_ok());
        self.chunk_sectors = sec;
        self
    }

    /// Set boundary rules for bio merging.
    ///
    /// See:
    /// <https://www.kernel.org/doc/html/v6.7/core-api/kernel-api.html#c.blk_queue_virt_boundary>
    pub fn virt_boundary_mask(&mut self, mask: u64) -> &mut Self {
        self.virt_boundary_mask = mask;
        self
    }

    pub fn attrs(&mut self, attrs: DeviceAttrs) -> &mut Self {
        self.attrs = attrs;
        self
    }

    /// # Panics
    ///
    /// Panic if `params` is invalid, eg. `max_zone_append_size` is 0.
    pub fn discard(&mut self, params: DiscardParams) -> &mut Self {
        self.discard = Some(params);
        self
    }

    /// Set zone parameters for zoned devices.
    ///
    /// The device must be created with [`FeatureFlags::Zoned`] set, and
    /// [`DeviceParams::chunk_sectors`] must be set to the zone size.
    pub fn zoned(&mut self, params: ZonedParams) -> &mut Self {
        self.zoned = Some(params);
        self
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct DiscardParams {
    pub alignment: u32,
    pub granularity: u32,
    pub max_size: Sector,
    pub max_write_zeroes_size: Sector,
    pub max_segments: u16,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ZonedParams {
    pub max_open_zones: u32,
    pub max_active_zones: u32,
    pub max_zone_append_size: Sector,
}

impl DeviceParams {
    fn build(&self) -> sys::ublk_params {
        let mut attrs = DeviceParamsType::Basic;
        attrs.set(DeviceParamsType::Discard, self.discard.is_some());
        attrs.set(DeviceParamsType::Zoned, self.zoned.is_some());

        sys::ublk_params {
            len: mem::size_of::<sys::ublk_params>() as _,
            types: attrs.bits(),
            basic: sys::ublk_param_basic {
                attrs: self.attrs.bits(),
                logical_bs_shift: self.logical_block_shift,
                physical_bs_shift: self.physical_block_shift,
                io_opt_shift: self.io_opt_shift,
                io_min_shift: self.io_min_shift,
                max_sectors: self.io_max_secs,
                dev_sectors: self.dev_sectors.0,
                chunk_sectors: self.chunk_sectors.0.try_into().unwrap(),
                virt_boundary_mask: self.virt_boundary_mask,
            },
            discard: self
                .discard
                .map_or(Default::default(), |p| sys::ublk_param_discard {
                    discard_alignment: p.alignment,
                    discard_granularity: p.granularity,
                    max_discard_sectors: p.max_size.0.try_into().unwrap(),
                    max_write_zeroes_sectors: p.max_write_zeroes_size.0.try_into().unwrap(),
                    max_discard_segments: p.max_segments,
                    reserved0: 0,
                }),
            zoned: self
                .zoned
                .map_or(Default::default(), |p| sys::ublk_param_zoned {
                    max_open_zones: p.max_open_zones,
                    max_active_zones: p.max_active_zones,
                    max_zone_append_sectors: p.max_zone_append_size.0.try_into().unwrap(),
                    reserved: [0; 20],
                }),
            // This is read-only.
            devt: Default::default(),
        }
    }
}

/// Zone descriptor for [`BlockDevice::report_zones`].
///
/// Aka. `struct blk_zone`.
///
/// See: <https://elixir.bootlin.com/linux/v6.7/source/include/uapi/linux/blkzoned.h#L85>
#[derive(Clone, Copy, PartialEq, Eq)]
#[repr(transparent)]
pub struct Zone(sys::blk_zone);

impl fmt::Debug for Zone {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("Zone")
            .field("start", &self.start())
            .field("len", &self.len())
            .field("wp", &self.wp())
            .field("type", &self.type_())
            .field("cond", &self.cond())
            .finish_non_exhaustive()
    }
}

impl Zone {
    #[must_use]
    pub fn new(
        start: Sector,
        len: Sector,
        rel_write_pointer: Sector,
        type_: ZoneType,
        cond: ZoneCond,
    ) -> Self {
        Self(sys::blk_zone {
            start: start.0,
            len: len.0,
            wp: start.0 + rel_write_pointer.0,
            type_: type_ as _,
            cond: cond as _,
            non_seq: 0,
            reset: 0,
            resv: [0; 4],
            // NB. This struct is passed directly into kernel codes, where many code
            // (like BTRFS) expects `capacity` to be set correctly.
            capacity: len.0,
            reserved: [0; 24],
        })
    }

    #[must_use]
    pub fn with_capacity(mut self, capacity: u64) -> Self {
        self.0.capacity = capacity;
        self
    }

    #[must_use]
    pub fn start(&self) -> Sector {
        Sector(self.0.start)
    }

    #[must_use]
    pub fn len(&self) -> Sector {
        Sector(self.0.len)
    }

    #[must_use]
    pub fn wp(&self) -> Sector {
        Sector(self.0.wp)
    }

    #[must_use]
    pub fn type_(&self) -> ZoneType {
        ZoneType::from_repr(self.0.type_).expect("invalid type")
    }

    #[must_use]
    pub fn cond(&self) -> ZoneCond {
        ZoneCond::from_repr(self.0.cond).expect("invalid cond")
    }
}

/// Type of zones.
///
/// Aka. `enum blk_zone_type`.
/// See: <https://elixir.bootlin.com/linux/v6.7/source/include/uapi/linux/blkzoned.h#L22>
#[derive(Debug, Clone, Copy, PartialEq, Eq, strum::FromRepr)]
#[non_exhaustive]
#[repr(u8)]
pub enum ZoneType {
    /// The zone has no write pointer and can be writen randomly. Zone reset has no effect on the
    /// zone.
    Conventional = sys::BLK_ZONE_TYPE_CONVENTIONAL as u8,
    /// The zone must be written sequentially.
    SeqWriteReq = sys::BLK_ZONE_TYPE_SEQWRITE_REQ as u8,
    /// The zone can be written non-sequentially.
    SeqWritePref = sys::BLK_ZONE_TYPE_SEQWRITE_PREF as u8,
}

/// Condition/state of a zone in a zoned device.
///
/// Aka. `enum blk_zone_cond`.
/// See: <https://elixir.bootlin.com/linux/v6.7/source/include/uapi/linux/blkzoned.h#L38>
#[derive(Debug, Clone, Copy, PartialEq, Eq, strum::FromRepr)]
#[non_exhaustive]
#[repr(u8)]
pub enum ZoneCond {
    /// The zone has no write pointer, it is conventional.
    NotWp = sys::BLK_ZONE_COND_NOT_WP as u8,
    /// The zone is empty.
    Empty = sys::BLK_ZONE_COND_EMPTY as u8,
    /// The zone is open, but not explicitly opened.
    ImpOpen = sys::BLK_ZONE_COND_IMP_OPEN as u8,
    /// The zones was explicitly opened by an OPEN ZONE command.
    ExpOpen = sys::BLK_ZONE_COND_EXP_OPEN as u8,
    /// The zone was *explicitly* closed after writing.
    Closed = sys::BLK_ZONE_COND_CLOSED as u8,
    /// The zone is marked as full, possibly by a zone FINISH ZONE command.
    Full = sys::BLK_ZONE_COND_FULL as u8,
    /// The zone is read-only.
    Readonly = sys::BLK_ZONE_COND_READONLY as u8,
    /// The zone is offline (sectors cannot be read/written).
    Offline = sys::BLK_ZONE_COND_OFFLINE as u8,
}

trait IntoCResult {
    fn into_c_result(self) -> (i32, u64);
}

impl IntoCResult for () {
    fn into_c_result(self) -> (i32, u64) {
        (0, 0)
    }
}

impl IntoCResult for (i32, u64) {
    fn into_c_result(self) -> (i32, u64) {
        self
    }
}

impl IntoCResult for usize {
    fn into_c_result(self) -> (i32, u64) {
        if let Ok(v) = i32::try_from(self) {
            (v, 0)
        } else {
            log::warn!("invalid returning value: {self}");
            (-Errno::IO.raw_os_error(), 0)
        }
    }
}

impl<T: IntoCResult> IntoCResult for Result<T, Errno> {
    fn into_c_result(self) -> (i32, u64) {
        match self {
            Ok(v) => v.into_c_result(),
            Err(err) => (-err.raw_os_error(), 0),
        }
    }
}

// We do suppose to enforce non-`Send` `Future`s.
#[allow(async_fn_in_trait)]
// They are indeed async fns.
#[allow(clippy::unused_async)]
pub trait BlockDevice {
    fn ready(&self, _dev_info: &DeviceInfo, _stop: Stopper) -> io::Result<()> {
        Ok(())
    }

    async fn read(&self, off: Sector, buf: &mut ReadBuf<'_>, flags: IoFlags) -> Result<(), Errno>;

    async fn write(&self, off: Sector, buf: WriteBuf<'_>, flags: IoFlags) -> Result<usize, Errno>;

    async fn flush(&self, _flags: IoFlags) -> Result<(), Errno> {
        Ok(())
    }

    async fn discard(&self, _off: Sector, _len: usize, _flags: IoFlags) -> Result<(), Errno> {
        Err(Errno::OPNOTSUPP)
    }

    async fn write_zeroes(&self, _off: Sector, _len: usize, _flags: IoFlags) -> Result<(), Errno> {
        Err(Errno::OPNOTSUPP)
    }

    async fn zone_append(
        &self,
        _off: Sector,
        _buf: WriteBuf<'_>,
        _flags: IoFlags,
    ) -> Result<Sector, Errno> {
        Err(Errno::OPNOTSUPP)
    }

    async fn zone_open(&self, _off: Sector, _flags: IoFlags) -> Result<(), Errno> {
        Err(Errno::OPNOTSUPP)
    }

    async fn zone_close(&self, _off: Sector, _flags: IoFlags) -> Result<(), Errno> {
        Err(Errno::OPNOTSUPP)
    }

    async fn zone_finish(&self, _off: Sector, _flags: IoFlags) -> Result<(), Errno> {
        Err(Errno::OPNOTSUPP)
    }

    async fn zone_reset(&self, _off: Sector, _flags: IoFlags) -> Result<(), Errno> {
        Err(Errno::OPNOTSUPP)
    }

    async fn zone_reset_all(&self, _flags: IoFlags) -> Result<(), Errno> {
        Err(Errno::OPNOTSUPP)
    }

    async fn report_zones(
        &self,
        _off: Sector,
        _buf: &mut ZoneBuf<'_>,
        _flags: IoFlags,
    ) -> Result<(), Errno> {
        Err(Errno::OPNOTSUPP)
    }
}

#[derive(Debug)]
enum RawBuf<'a> {
    PreCopied(&'a mut [u8]),
    UserCopy {
        cdev: BorrowedFd<'a>,
        off: u64,
        remaining: u32,
    },
}

impl RawBuf<'_> {
    fn remaining(&self) -> usize {
        match self {
            RawBuf::PreCopied(b) => b.len(),
            RawBuf::UserCopy { remaining, .. } => *remaining as _,
        }
    }
}

/// The return buffer for [`BlockDevice::read`].
#[derive(Debug)]
pub struct ReadBuf<'buf>(RawBuf<'buf>, PhantomData<*mut ()>);

impl<'buf> ReadBuf<'buf> {
    /// Create a buffer for testing purpose.
    #[must_use]
    pub fn from_raw(buf: &'buf mut [u8]) -> Self {
        Self(RawBuf::PreCopied(buf), PhantomData)
    }

    /// Returns the number of bytes that have not yet been filled.
    #[must_use]
    pub fn remaining(&self) -> usize {
        self.0.remaining()
    }

    /// Append `data` to the response buffer and advance the write position.
    ///
    /// This method will automatically use the correct way to transfer. In case of
    /// [`FeatureFlags::UserCopy`], `pwrite(2)` is used; otherwise, it does an ordinary memory copy
    /// to the kernel driver buffer.
    ///
    /// Temporary failures like `EINTR` are handled and retried internally.
    ///
    /// # Panics
    ///
    /// Panic if `data.len() > self.remaining()`.
    pub fn put_slice(&mut self, data: &[u8]) -> Result<(), Errno> {
        let len = data.len();
        assert!(len <= self.remaining());
        match &mut self.0 {
            RawBuf::PreCopied(b) => {
                b[..len].copy_from_slice(data);
                *b = &mut mem::take(b)[len..];
                Ok(())
            }
            RawBuf::UserCopy {
                cdev,
                off,
                remaining,
                ..
            } => {
                let prev_off = *off;
                let ret = write_all_at(*cdev, data, off);
                *remaining -= (*off - prev_off) as u32;
                ret
            }
        }
    }
}

/// The input buffer for [`BlockDevice::write`].
#[derive(Debug)]
pub struct WriteBuf<'buf>(RawBuf<'buf>, PhantomData<*mut ()>);

impl<'buf> WriteBuf<'buf> {
    /// Create a buffer for testing purpose.
    #[must_use]
    pub fn from_raw(buf: &'buf mut [u8]) -> Self {
        Self(RawBuf::PreCopied(buf), PhantomData)
    }

    /// Returns the byte length requested for write, which must not be zero.
    // It must not be empty.
    #[allow(clippy::len_without_is_empty)]
    #[must_use]
    pub fn len(&self) -> usize {
        self.0.remaining()
    }

    /// Copy the data to be written into `out`.
    ///
    /// This method will automatically select the correct way to transfer. In case of
    /// [`FeatureFlags::UserCopy`], pread(2) is used; otherwise, it does an ordinary memory copy
    /// from the kernel driver buffer.
    ///
    /// # Panics
    ///
    /// Panic if `out.len()` differs from [`Self::len()`].
    pub fn copy_to_slice(&self, out: &mut [u8]) -> Result<(), Errno> {
        // SAFETY: `&[MaybeUninit<u8>]` has the same repr as `&[u8]`.
        let out = unsafe { mem::transmute::<&mut [u8], &mut [MaybeUninit<u8>]>(out) };
        self.copy_to_uninitialized(out)?;
        Ok(())
    }

    /// Copy the data to be written into `out`.
    ///
    /// Same as [`Self::copy_to_slice`] but accept a maybe-uninitialized slice.
    ///
    /// # Panics
    ///
    /// Panic if `out.len()` differs from [`Self::len()`].
    pub fn copy_to_uninitialized<'a>(
        &self,
        out: &'a mut [MaybeUninit<u8>],
    ) -> Result<&'a mut [u8], Errno> {
        assert_eq!(out.len(), self.len());
        match &self.0 {
            RawBuf::PreCopied(buf) => {
                // SAFETY: `&[MaybeUninit<u8>]` has the same repr as `&[u8]`.
                let buf = unsafe { mem::transmute::<&[u8], &[MaybeUninit<u8>]>(&**buf) };
                out.copy_from_slice(buf);
                // SAFETY: `&[MaybeUninit<u8>]` has the same repr as `&[u8]` and is fully
                // initialized.
                unsafe { Ok(mem::transmute::<&mut [MaybeUninit<u8>], &mut [u8]>(out)) }
            }
            RawBuf::UserCopy { cdev, off, .. } => read_all_uninit_at(*cdev, out, *off),
        }
    }

    /// Try to get the internal buffer as a slice for manual usage.
    ///
    /// It will returns `None` if the device is created with [`FeatureFlags::UserCopy`].
    /// Generally [`Self::copy_to_slice`] should be preferred if applicatable.
    ///
    /// The returned slice (if any) will have the same length as [`Self::len()`].
    #[must_use]
    pub fn as_slice(&self) -> Option<&[u8]> {
        match &self.0 {
            RawBuf::PreCopied(b) => Some(b),
            RawBuf::UserCopy { .. } => None,
        }
    }
}

/// The return buffer for [`BlockDevice::report_zones`].
#[derive(Debug)]
pub struct ZoneBuf<'buf> {
    cdev: BorrowedFd<'buf>,
    off: u64,
    remaining_zones: u32,
    #[allow(clippy::mut_mut)]
    _not_send_invariant: PhantomData<(*mut (), &'buf mut &'buf mut ())>,
}

impl<'buf> ZoneBuf<'buf> {
    /// Create a buffer for testing purpose.
    #[must_use]
    pub fn from_raw(cdev: BorrowedFd<'buf>, off: u64, remaining_zones: u32) -> Self {
        Self {
            cdev,
            off,
            remaining_zones,
            _not_send_invariant: PhantomData,
        }
    }

    /// Returns the remaining number of zones unfilled in this buffer, which must not be zero
    /// initially.
    #[must_use]
    pub fn remaining(&self) -> usize {
        self.remaining_zones as _
    }

    /// Fill buffer with zones informations response and returns the number of zones written.
    ///
    /// This will advance the buffer end pointer. It can be called multiple times and responses
    /// will be concatenated sequentially. Be aware that filling the buffer can do syscalls in case
    /// of [`FeatureFlags::UserCopy`].
    ///
    /// This handles retriable failures like `EINTR`, thus the only reason for returning a number
    /// less than `zones.len()` is the buffer is full.
    pub fn report(&mut self, zones: &[Zone]) -> Result<usize, Errno> {
        let len = self.remaining().min(zones.len());
        let zones = &zones[..len];
        // SAFETY: `Zone` is `repr(transparent)` to `struct blk_zone`.
        let data = unsafe {
            std::slice::from_raw_parts(zones.as_ptr().cast::<u8>(), mem::size_of_val(zones))
        };
        let prev_off = self.off;
        let ret = write_all_at(self.cdev, data, &mut self.off);
        let written = (self.off - prev_off) as usize;
        if written % mem::size_of::<Zone>() == 0 {
            self.remaining_zones -= (written / mem::size_of::<Zone>()) as u32;
        } else {
            // Forbid more writes when partially failed. The result written length is calculated by
            // advance of `off`, which is still correct in that case.
            self.remaining_zones = 0;
        }
        ret.and(Ok(len))
    }
}

fn write_all_at(fd: BorrowedFd<'_>, mut buf: &[u8], offset: &mut u64) -> Result<(), Errno> {
    while !buf.is_empty() {
        let written = rustix::io::pwrite(fd, buf, *offset)?;
        buf = &buf[written..];
        *offset += written as u64;
    }
    Ok(())
}

fn read_all_uninit_at<'a>(
    fd: BorrowedFd<'_>,
    buf: &'a mut [MaybeUninit<u8>],
    mut offset: u64,
) -> Result<&'a mut [u8], Errno> {
    let mut buf_off = 0usize;
    while buf_off < buf.len() {
        match rustix::io::pread_uninit(fd, &mut buf[buf_off..], offset) {
            Ok(([], _)) => return Err(Errno::INVAL),
            Ok((read, _)) => {
                offset += read.len() as u64;
                buf_off += read.len();
            }
            Err(err) if err.kind() == io::ErrorKind::Interrupted => {}
            Err(err) => return Err(err),
        }
    }
    // SAFETY: `&[MaybeUninit<u8>]` has the same repr as `&[u8]` and is initialized.
    Ok(unsafe { mem::transmute::<&mut [MaybeUninit<u8>], &mut [u8]>(buf) })
}
