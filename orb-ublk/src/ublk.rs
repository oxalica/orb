use std::alloc::{GlobalAlloc, Layout, System};
use std::fs::File;
use std::marker::PhantomData;
use std::mem::{ManuallyDrop, MaybeUninit};
use std::ops::ControlFlow;
use std::os::fd::{BorrowedFd, RawFd};
use std::os::unix::fs::FileExt;
use std::ptr::NonNull;
use std::sync::Arc;
use std::time::Duration;
use std::{fmt, io, mem, ptr, thread};

use io_uring::types::{Fd, Fixed};
use io_uring::{cqueue, opcode, squeue, IoUring, SubmissionQueue};
use rustix::event::{EventfdFlags, PollFd, PollFlags};
use rustix::fd::{AsFd, AsRawFd, FromRawFd, OwnedFd};
use rustix::io::Errno;
use rustix::mm;
use rustix::process::Pid;

use crate::runtime::{AsyncRuntime, AsyncRuntimeBuilder, AsyncScopeSpawner};

pub const SECTOR_SIZE: u32 = 512;

const DEFAULT_IO_BUF_SIZE: u32 = 512 << 10;

pub const CDEV_PREFIX: &str = "/dev/ublkc";
pub const BDEV_PREFIX: &str = "/dev/ublkb";

#[allow(warnings)]
mod binding {
    include!(concat!(env!("OUT_DIR"), "/ublk_cmd.rs"));
}

bitflags::bitflags! {
    #[derive(Debug, Clone, Copy, PartialEq, Eq)]
    pub struct FeatureFlags: u64 {
        const SupportZeroCopy = binding::UBLK_F_SUPPORT_ZERO_COPY as u64;
        const UringCmdCompInTask = binding::UBLK_F_URING_CMD_COMP_IN_TASK as u64;
        const NeedGetData = binding::UBLK_F_NEED_GET_DATA as u64;
        const UserRecovery = binding::UBLK_F_USER_RECOVERY as u64;
        const UserRecoveryReissue = binding::UBLK_F_USER_RECOVERY_REISSUE as u64;
        const UnprivilegedDev = binding::UBLK_F_UNPRIVILEGED_DEV as u64;
        const CmdIoctlEncode = binding::UBLK_F_CMD_IOCTL_ENCODE as u64;
        const UserCopy = binding::UBLK_F_USER_COPY as u64;
        const Zoned = binding::UBLK_F_ZONED as u64;
    }

    #[derive(Debug, Clone, Copy, PartialEq, Eq)]
    struct DeviceParamsType: u32 {
        const Basic = binding::UBLK_PARAM_TYPE_BASIC;
        const Discard = binding::UBLK_PARAM_TYPE_DISCARD;
        const Devt = binding::UBLK_PARAM_TYPE_DEVT;
        const Zoned = binding::UBLK_PARAM_TYPE_ZONED;
    }

    #[derive(Debug, Clone, Copy, PartialEq, Eq)]
    pub struct DeviceAttrs: u32 {
        const ReadOnly =  binding::UBLK_ATTR_READ_ONLY;
        const Rotational = binding::UBLK_ATTR_ROTATIONAL;
        const VolatileCache = binding::UBLK_ATTR_VOLATILE_CACHE;
        const Fua = binding::UBLK_ATTR_FUA;
    }

    #[derive(Debug, Clone, Copy, PartialEq, Eq)]
    pub struct IoFlags: u32 {
        const FailfastDev = binding::UBLK_IO_F_FAILFAST_DEV;
        const FailfastTransport = binding::UBLK_IO_F_FAILFAST_TRANSPORT;
        const FailfastDriver = binding::UBLK_IO_F_FAILFAST_DRIVER;
        const Meta = binding::UBLK_IO_F_META;
        const Fua = binding::UBLK_IO_F_FUA;
        const Nounmap = binding::UBLK_IO_F_NOUNMAP;
        const Swap = binding::UBLK_IO_F_SWAP;
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
    data: binding::ublksrv_ctrl_cmd,
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
        mut cmd: binding::ublksrv_ctrl_cmd,
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
        mut cmd: binding::ublksrv_ctrl_cmd,
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
            self.execute_ctrl_cmd(binding::UBLK_U_CMD_GET_FEATURES, 0u64, Default::default())
                .map(FeatureFlags::from_bits_truncate)
        }
    }

    pub fn get_device_info(&self, dev_id: u32) -> io::Result<DeviceInfo> {
        // SAFETY: Valid uring_cmd.
        unsafe {
            self.execute_ctrl_cmd_opt_cdev::<binding::ublksrv_ctrl_dev_info>(
                // Always include cdev_path.
                true,
                binding::UBLK_U_CMD_GET_DEV_INFO2,
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
        let dev_id = builder.id.unwrap_or(!0);
        let pid = rustix::process::getpid();
        // SAFETY: Valid uring_cmd.
        unsafe {
            self.execute_ctrl_cmd(
                binding::UBLK_U_CMD_ADD_DEV,
                binding::ublksrv_ctrl_dev_info {
                    nr_hw_queues: builder.nr_hw_queues,
                    queue_depth: builder.queue_depth,
                    max_io_buf_bytes: builder.io_buf_bytes,
                    dev_id,
                    ublksrv_pid: pid.as_raw_nonzero().get() as _,
                    flags: builder.features.bits(),
                    state: DevState::Dead.into_raw(),
                    // Unused.
                    ublksrv_flags: 0,
                    // Does not matter here and will always be set by the driver.
                    owner_uid: 0,
                    owner_gid: 0,
                    ..Default::default()
                },
                binding::ublksrv_ctrl_cmd {
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
                binding::UBLK_U_CMD_DEL_DEV,
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
                binding::UBLK_U_CMD_START_DEV,
                dev_id,
                [0u8; 0],
                binding::ublksrv_ctrl_cmd {
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
        cmd_buf.data = binding::ublksrv_ctrl_cmd {
            dev_id,
            len: CdevPath::MAX_LEN as _,
            dev_path_len: CdevPath::MAX_LEN as _,
            addr: buf.write(CdevPath::from_id(dev_id)) as *mut _ as u64,
            data: [pid],
            ..Default::default()
        };
        log::trace!("start device {dev_id} on pid {pid}");

        let sqe = opcode::UringCmd80::new(Fd(self.fd.as_raw_fd()), binding::UBLK_U_CMD_START_DEV)
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
                binding::UBLK_U_CMD_STOP_DEV,
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
            self.execute_ctrl_cmd_opt_cdev::<binding::ublk_params>(
                unprivileged,
                binding::UBLK_U_CMD_SET_PARAMS,
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
    id: Option<u32>,
    nr_hw_queues: u16,
    queue_depth: u16,
    io_buf_bytes: u32,
    features: FeatureFlags,

    max_retries: u16,
    retry_delay: Duration,
}

impl Default for DeviceBuilder {
    fn default() -> Self {
        Self::new()
    }
}

impl DeviceBuilder {
    #[must_use]
    pub fn new() -> Self {
        Self {
            name: String::new(),
            id: None,
            nr_hw_queues: 1,
            queue_depth: 64,
            io_buf_bytes: DEFAULT_IO_BUF_SIZE,
            features: FeatureFlags::empty(),
            max_retries: 10,
            retry_delay: Duration::from_millis(100),
        }
    }

    pub fn name(&mut self, name: impl Into<String>) -> &mut Self {
        self.name = name.into();
        self
    }

    /// # Panics
    ///
    /// Panic if `id` is `u32::MAX` which coresponds to automatic id (which is the default).
    pub fn id(&mut self, id: u32) -> &mut Self {
        assert_ne!(id, !0);
        self.id = Some(id);
        self
    }

    /// # Panics
    ///
    /// Panic if `nr_hw_queues` is zero or exceeds `UBLK_QID_BITS` bits, which is `1 << 12 = 4096`.
    pub fn queues(&mut self, nr_hw_queues: u16) -> &mut Self {
        assert!((1..=(1 << binding::UBLK_QID_BITS)).contains(&nr_hw_queues));
        self.nr_hw_queues = nr_hw_queues;
        self
    }

    /// # Panics
    ///
    /// Panic if `queue_depth` is zero or exceeds `UBLK_MAX_QUEUE_DEPTH` which is 4096.
    pub fn queue_depth(&mut self, queue_depth: u16) -> &mut Self {
        assert!((1..=binding::UBLK_MAX_QUEUE_DEPTH as u16).contains(&queue_depth));
        self.queue_depth = queue_depth;
        self
    }

    /// # Panics
    ///
    /// Panic if `bytes` exceeds `UBLK_IO_BUF_BITS` bits, which is `1 << 25` bytes or 32MiB.
    pub fn io_buf_size(&mut self, bytes: u32) -> &mut Self {
        assert!((1..=(1 << binding::UBLK_IO_BUF_BITS)).contains(&bytes));
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
pub struct DeviceInfo(binding::ublksrv_ctrl_dev_info);

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
            .field("owner_uid", &self.0.owner_uid)
            .field("owner_gid", &self.0.owner_gid)
            .finish()
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[non_exhaustive]
#[repr(u8)]
pub enum DevState {
    Dead = binding::UBLK_S_DEV_DEAD as _,
    Live = binding::UBLK_S_DEV_LIVE as _,
    Quiesced = binding::UBLK_S_DEV_QUIESCED as _,
    #[doc(hidden)]
    Unknown(u16),
}

impl DevState {
    fn into_raw(self) -> u16 {
        match self {
            DevState::Dead => binding::UBLK_S_DEV_DEAD as _,
            DevState::Live => binding::UBLK_S_DEV_LIVE as _,
            DevState::Quiesced => binding::UBLK_S_DEV_QUIESCED as _,
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
            binding::UBLK_S_DEV_DEAD => DevState::Dead,
            binding::UBLK_S_DEV_LIVE => DevState::Live,
            binding::UBLK_S_DEV_QUIESCED => DevState::Quiesced,
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
}

#[derive(Debug)]
struct IoDescShm(NonNull<[binding::ublksrv_io_desc]>);

impl Drop for IoDescShm {
    fn drop(&mut self) {
        if let Err(err) = unsafe { mm::munmap(self.0.as_ptr().cast(), self.0.len()) } {
            log::error!("failed to unmap shared memory: {err}");
        }
    }
}

impl IoDescShm {
    fn new(cdev: BorrowedFd<'_>, dev_info: &DeviceInfo, thread_id: u16) -> io::Result<Self> {
        let off = u64::try_from(mem::size_of::<binding::ublksrv_io_desc>())
            .unwrap()
            .checked_mul(binding::UBLK_MAX_QUEUE_DEPTH.into())
            .unwrap()
            .checked_mul(thread_id.into())
            .unwrap()
            .checked_add(binding::UBLKSRV_CMD_BUF_OFFSET.into())
            .unwrap();

        assert_ne!(dev_info.queue_depth(), 0);
        // `m{,un}map` will pad the length to the multiple of pages automatically.
        let size = mem::size_of::<binding::ublksrv_io_desc>()
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
            NonNull::new(ptr.cast::<binding::ublksrv_io_desc>()).unwrap(),
            dev_info.queue_depth().into(),
        );
        Ok(IoDescShm(ptr))
    }

    fn get(&self, tag: u16) -> binding::ublksrv_io_desc {
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
            if err.kind() != io::ErrorKind::NotFound {
                log::error!("failed to delete device {dev_id}: {err}");
            }
        }
    }
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
                params.chunk_size, 0,
                "`chunk_size` must be set for zoned devices",
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
                if err.kind() != io::ErrorKind::NotFound {
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
                    let mut worker = IoWorker {
                        thread_id,
                        ready_tx: Some(ready_tx.clone().clone()),
                        cdev: self.cdev.as_fd(),
                        dev_info: &self.dev_info,
                        handler,
                        runtime_builder,
                        set_io_flusher: params.set_io_flusher,
                        wait_device_start: None,
                        stop_guard: thread_stop_guard.clone(),
                    };
                    thread::Builder::new()
                        .name(format!("io-worker-{thread_id}"))
                        .spawn_scoped(s, move || worker.run())
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
    pub fn serve_local<RB, D>(
        &mut self,
        runtime_builder: &RB,
        params: &DeviceParams,
        handler: &D,
    ) -> io::Result<()>
    where
        RB: AsyncRuntimeBuilder,
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
            runtime_builder,
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
                log::error!("failed to stop device {} {}", self.dev_info.dev_id(), err);
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

struct IoWorker<'a, B, RB> {
    thread_id: u16,
    // Signal the main thread for service readiness. `None` for `serve_local`.
    ready_tx: Option<std::sync::mpsc::SyncSender<()>>,
    cdev: BorrowedFd<'a>,
    dev_info: &'a DeviceInfo,
    handler: &'a B,
    runtime_builder: &'a RB,
    set_io_flusher: bool,

    // If the worker is running in-place by `Service::serve_local`, we need to wait for the
    // device start command in the control io-uring to finish before sending a `BlockDevice::ready`
    // notification.
    wait_device_start: Option<(&'a IoUring<squeue::Entry128, cqueue::Entry>, Stopper)>,

    // This is dropped last.
    stop_guard: SignalStopOnDrop<'a>,
}

impl<B: BlockDevice, RB: AsyncRuntimeBuilder> IoWorker<'_, B, RB> {
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

        let mut runtime = self.runtime_builder.build()?;

        let refill_sqe = |sq: &mut SubmissionQueue<'_>,
                          i: u16,
                          result: Option<i32>,
                          zone_append_lba: Option<u64>| {
            let cmd = binding::ublksrv_io_cmd {
                q_id: self.thread_id,
                tag: i,
                result: result.unwrap_or(-1),
                __bindgen_anon_1: match (&io_bufs, zone_append_lba) {
                    (Some(bufs), _) => binding::ublksrv_io_cmd__bindgen_ty_1 {
                        addr: bufs.get(i.into()).as_ptr().cast::<u8>() as _,
                    },
                    (None, Some(zone_append_lba)) => {
                        binding::ublksrv_io_cmd__bindgen_ty_1 { zone_append_lba }
                    }
                    (None, None) => binding::ublksrv_io_cmd__bindgen_ty_1 { addr: 0 },
                },
            };
            let cmd_op = if result.is_some() {
                binding::UBLK_IO_COMMIT_AND_FETCH_REQ
            } else {
                binding::UBLK_IO_FETCH_REQ
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
                refill_sqe(&mut sq, i, None, None);
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

        runtime.drive_uring(&io_ring, |spawner| {
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
                    log::debug!("failed to fetch ublk events: {err}");
                    return Err(err);
                }

                let tag = cqe.user_data() as u16;
                let io_ring = &*io_ring;
                let commit_and_fetch = move |ret: i32, zone_append_lba: Option<u64>| {
                    log::trace!("-> respond {ret} {zone_append_lba:?}");
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
                // These fields may contain garbage for ops without them.
                let off = iod.start_sector.wrapping_mul(SECTOR_SIZE.into());
                // The 2 variants both have type `u32`.
                let zones = unsafe { iod.__bindgen_anon_1.nr_zones };
                let len = unsafe { iod.__bindgen_anon_1.nr_sectors as usize }
                    .wrapping_mul(SECTOR_SIZE as usize);
                let pwrite_off = u64::from(binding::UBLKSRV_IO_BUF_OFFSET)
                    + (u64::from(self.thread_id) << binding::UBLK_QID_OFF)
                    + (u64::from(tag) << binding::UBLK_TAG_OFF);
                let get_buf = || {
                    match &io_bufs {
                        // SAFETY: This buffer is exclusive for task of `tag`.
                        Some(bufs) => unsafe {
                            RawBuf::PreCopied(&mut bufs.get(tag.into()).as_mut()[..len])
                        },
                        None => RawBuf::UserCopy {
                            cdev: self.cdev,
                            off: pwrite_off,
                            len: len as _,
                        },
                    }
                };

                // Make `async move` only move the reference to the handler.
                let h = self.handler;
                // FIXME: Is there a better way to handle panicking here?
                macro_rules! op {
                    ($tt:tt; $(let $pat:pat_param = $rhs:expr;)* $handle_expr:expr) => {{
                        log::trace!($tt);
                        $(let $pat = $rhs;)*
                        spawner.spawn(async move {
                            // Always commit.
                            let mut guard = scopeguard::guard(-Errno::IO.raw_os_error(), |ret| {
                                if std::thread::panicking() {
                                    log::warn!("handler panicked, returning EIO");
                                }
                                commit_and_fetch(ret, None)
                            });
                            let ret = $handle_expr.await.into_c_result();
                            *guard = ret;
                        });
                    }};
                }

                match iod.op_flags & 0xFF {
                    binding::UBLK_IO_OP_READ => op! {
                        "READ offset={off} len={len} flags={flags:?}";
                        let buf = ReadBuf(get_buf(), PhantomData);
                        h.read(off, buf, flags)
                    },
                    binding::UBLK_IO_OP_WRITE => op! {
                        "WRITE offset={off} len={len} flags={flags:?}";
                        let buf = WriteBuf(get_buf(), PhantomData);
                        h.write(off, buf, flags)
                    },
                    binding::UBLK_IO_OP_FLUSH => op! {
                        "FLUSH flags={flags:?}";
                        h.flush(flags)
                    },
                    binding::UBLK_IO_OP_DISCARD => op! {
                        "DISCARD offset={off} len={len} flags={flags:?}";
                        h.discard(off, len, flags)
                    },
                    binding::UBLK_IO_OP_WRITE_ZEROES => op! {
                        "WRITE_ZEROES offset={off} len={len} flags={flags:?}";
                        h.write_zeroes(off, len, flags)
                    },
                    binding::UBLK_IO_OP_REPORT_ZONES => op! {
                        "REPORT_ZONES offset={off} zones={zones} flags={flags:?}";
                        let buf = ZoneBuf {
                            cdev: self.cdev,
                            off: pwrite_off,
                            zones,
                            _not_send_invariant: PhantomData,
                        };
                        h.report_zones(off, buf, flags)
                    },
                    binding::UBLK_IO_OP_ZONE_APPEND => {
                        // TODO: Ugly special case.
                        log::trace!("ZONE_APPEND offset={off} len={len} flags={flags:?}");
                        let buf = WriteBuf(get_buf(), PhantomData);
                        spawner.spawn(async move {
                            let mut guard =
                                scopeguard::guard((-Errno::IO.raw_os_error(), 0), |(ret, lba)| {
                                    if std::thread::panicking() {
                                        log::warn!("handler panicked, returning EIO");
                                    }
                                    commit_and_fetch(ret, Some(lba));
                                });
                            *guard = match h.zone_append(off, buf, flags).await {
                                Ok(lba) => {
                                    assert_eq!(lba % u64::from(SECTOR_SIZE), 0);
                                    (0, lba)
                                }
                                Err(err) => (err.raw_os_error(), 0),
                            };
                        });
                    }
                    binding::UBLK_IO_OP_ZONE_OPEN => op! {
                        "ZONE_OPEN offset={off} flags={flags:?}";
                        h.zone_open(off, flags)
                    },
                    binding::UBLK_IO_OP_ZONE_CLOSE => op! {
                        "ZONE_CLOSE offset={off} flags={flags:?}";
                        h.zone_close(off, flags)
                    },
                    binding::UBLK_IO_OP_ZONE_FINISH => op! {
                        "ZONE_FINISH offset={off} flags={flags:?}";
                        h.zone_finish(off, flags)
                    },
                    binding::UBLK_IO_OP_ZONE_RESET => op! {
                        "ZONE_RESET offset={off} flags={flags:?}";
                        h.zone_reset(off, flags)
                    },
                    binding::UBLK_IO_OP_ZONE_RESET_ALL => op! {
                        "ZONE_RESET_ALL flags={flags:?}";
                        h.zone_reset_all(flags)
                    },
                    op => {
                        log::error!("unsupported op: {op}");
                        commit_and_fetch(-Errno::IO.raw_os_error(), None);
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
    size: u64,
    logical_block_size: u32,
    physical_block_size: u32,
    chunk_size: u32,
    io_optimal_size: u32,
    io_min_size: u32,
    io_max_size: u32,
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
            size: 0,
            logical_block_size: 512,
            physical_block_size: 4 << 10,
            io_optimal_size: 4 << 10,
            io_min_size: 4 << 10,
            io_max_size: DEFAULT_IO_BUF_SIZE,
            chunk_size: 0,
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

    /// Set the total size of the block device.
    pub fn size(&mut self, size: u64) -> &mut Self {
        assert_eq!(size % SECTOR_SIZE as u64, 0);
        self.size = size;
        self
    }

    /// Set minimum request size for the queue.
    ///
    /// See:
    /// <https://www.kernel.org/doc/html/v6.7/core-api/kernel-api.html#c.blk_queue_io_min>
    pub fn io_max_size(&mut self, size: u32) -> &mut Self {
        assert_eq!(size % SECTOR_SIZE, 0);
        self.io_max_size = size;
        self
    }

    /// Set size of the chunk for this queue.
    ///
    /// See:
    /// <https://www.kernel.org/doc/html/v6.7/core-api/kernel-api.html#c.blk_queue_chunk_sectors>
    pub fn chunk_size(&mut self, size: u32) -> &mut Self {
        assert_eq!(size % SECTOR_SIZE, 0);
        self.chunk_size = size;
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
        assert_eq!(params.max_size % SECTOR_SIZE, 0);
        assert_eq!(params.max_write_zeroes_size % SECTOR_SIZE, 0);
        self.discard = Some(params);
        self
    }

    /// Set zone parameters for zoned devices.
    ///
    /// The device must be created with [`FeatureFlags::Zoned`] set, and
    /// [`DeviceParams::chunk_size`] must be set to the zone size.
    pub fn zoned(&mut self, params: ZonedParams) -> &mut Self {
        assert_eq!(params.max_zone_append_size % SECTOR_SIZE, 0);
        self.zoned = Some(params);
        self
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct DiscardParams {
    pub alignment: u32,
    pub granularity: u32,
    pub max_size: u32,
    pub max_write_zeroes_size: u32,
    pub max_segments: u16,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ZonedParams {
    pub max_open_zones: u32,
    pub max_active_zones: u32,
    pub max_zone_append_size: u32,
}

impl DeviceParams {
    fn build(&self) -> binding::ublk_params {
        let mut attrs = DeviceParamsType::Basic;
        attrs.set(DeviceParamsType::Discard, self.discard.is_some());
        attrs.set(DeviceParamsType::Zoned, self.zoned.is_some());

        binding::ublk_params {
            len: mem::size_of::<binding::ublk_params>() as _,
            types: attrs.bits(),
            basic: binding::ublk_param_basic {
                attrs: self.attrs.bits(),
                logical_bs_shift: self.logical_block_size.trailing_zeros() as _,
                physical_bs_shift: self.physical_block_size.trailing_zeros() as _,
                io_opt_shift: self.io_optimal_size.trailing_zeros() as _,
                io_min_shift: self.io_min_size.trailing_zeros() as _,
                max_sectors: self.io_max_size / SECTOR_SIZE,
                dev_sectors: self.size / u64::from(SECTOR_SIZE),
                chunk_sectors: self.chunk_size / SECTOR_SIZE,
                virt_boundary_mask: self.virt_boundary_mask,
            },
            discard: self
                .discard
                .map_or(Default::default(), |p| binding::ublk_param_discard {
                    discard_alignment: p.alignment,
                    discard_granularity: p.granularity,
                    max_discard_sectors: p.max_size / SECTOR_SIZE,
                    max_write_zeroes_sectors: p.max_write_zeroes_size / SECTOR_SIZE,
                    max_discard_segments: p.max_segments,
                    reserved0: 0,
                }),
            zoned: self
                .zoned
                .map_or(Default::default(), |p| binding::ublk_param_zoned {
                    max_open_zones: p.max_open_zones,
                    max_active_zones: p.max_active_zones,
                    max_zone_append_sectors: p.max_zone_append_size / SECTOR_SIZE,
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
#[derive(Debug, Clone, Copy)]
#[repr(transparent)]
pub struct Zone(binding::blk_zone);

impl Zone {
    #[must_use]
    pub fn new(
        start_bytes: u64,
        len_bytes: u64,
        rel_write_pointer_bytes: u64,
        type_: ZoneType,
        cond: ZoneCond,
    ) -> Self {
        assert_eq!(start_bytes % SECTOR_SIZE as u64, 0);
        assert_eq!(len_bytes % SECTOR_SIZE as u64, 0);
        assert_eq!(rel_write_pointer_bytes % SECTOR_SIZE as u64, 0);
        let start_sec = start_bytes / SECTOR_SIZE as u64;
        Self(binding::blk_zone {
            start: start_sec,
            len: len_bytes / SECTOR_SIZE as u64,
            wp: start_sec + rel_write_pointer_bytes / SECTOR_SIZE as u64,
            type_: type_ as _,
            cond: cond as _,
            non_seq: 0,
            reset: 0,
            resv: [0; 4],
            capacity: 0,
            reserved: [0; 24],
        })
    }
}

/// Type of zones.
///
/// Aka. `enum blk_zone_type`.
/// See: <https://elixir.bootlin.com/linux/v6.7/source/include/uapi/linux/blkzoned.h#L22>
#[derive(Debug, Clone, Copy)]
#[non_exhaustive]
#[repr(u8)]
pub enum ZoneType {
    /// The zone has no write pointer and can be writen randomly. Zone reset has no effect on the
    /// zone.
    Conventional = binding::BLK_ZONE_TYPE_CONVENTIONAL as u8,
    /// The zone must be written sequentially.
    SeqWriteReq = binding::BLK_ZONE_TYPE_SEQWRITE_REQ as u8,
    /// The zone can be written non-sequentially.
    SeqWritePref = binding::BLK_ZONE_TYPE_SEQWRITE_PREF as u8,
}

/// Condition/state of a zone in a zoned device.
///
/// Aka. `enum blk_zone_cond`.
/// See: <https://elixir.bootlin.com/linux/v6.7/source/include/uapi/linux/blkzoned.h#L38>
#[derive(Debug, Clone, Copy)]
#[non_exhaustive]
#[repr(u8)]
pub enum ZoneCond {
    /// The zone has no write pointer, it is conventional.
    NotWp = binding::BLK_ZONE_COND_NOT_WP as u8,
    /// The zone is empty.
    Empty = binding::BLK_ZONE_COND_EMPTY as u8,
    /// The zone is open, but not explicitly opened.
    ImpOpen = binding::BLK_ZONE_COND_IMP_OPEN as u8,
    /// The zones was explicitly opened by an OPEN ZONE command.
    ExpOpen = binding::BLK_ZONE_COND_EXP_OPEN as u8,
    /// The zone was *explicitly* closed after writing.
    Closed = binding::BLK_ZONE_COND_CLOSED as u8,
    /// The zone is marked as full, possibly by a zone FINISH ZONE command.
    Full = binding::BLK_ZONE_COND_FULL as u8,
    /// The zone is read-only.
    Readonly = binding::BLK_ZONE_COND_READONLY as u8,
    /// The zone is offline (sectors cannot be read/written).
    Offline = binding::BLK_ZONE_COND_OFFLINE as u8,
}

trait IntoCResult {
    fn into_c_result(self) -> i32;
}

impl IntoCResult for Result<(), Errno> {
    fn into_c_result(self) -> i32 {
        match self {
            Ok(()) => 0,
            Err(err) => -err.raw_os_error(),
        }
    }
}

impl IntoCResult for Result<usize, Errno> {
    fn into_c_result(self) -> i32 {
        match self {
            Ok(x) => i32::try_from(x).expect("invalid result size"),
            Err(err) => -err.raw_os_error(),
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

    async fn read(&self, off: u64, buf: ReadBuf<'_>, flags: IoFlags) -> Result<usize, Errno>;

    async fn write(&self, off: u64, buf: WriteBuf<'_>, flags: IoFlags) -> Result<usize, Errno>;

    async fn flush(&self, _flags: IoFlags) -> Result<(), Errno> {
        Ok(())
    }

    async fn discard(&self, _off: u64, _len: usize, _flags: IoFlags) -> Result<(), Errno> {
        Err(Errno::OPNOTSUPP)
    }

    async fn write_zeroes(&self, _off: u64, _len: usize, _flags: IoFlags) -> Result<(), Errno> {
        Err(Errno::OPNOTSUPP)
    }

    async fn zone_append(
        &self,
        _off: u64,
        _buf: WriteBuf<'_>,
        _flags: IoFlags,
    ) -> Result<u64, Errno> {
        Err(Errno::OPNOTSUPP)
    }

    async fn zone_open(&self, _off: u64, _flags: IoFlags) -> Result<(), Errno> {
        Err(Errno::OPNOTSUPP)
    }

    async fn zone_close(&self, _off: u64, _flags: IoFlags) -> Result<(), Errno> {
        Err(Errno::OPNOTSUPP)
    }

    async fn zone_finish(&self, _off: u64, _flags: IoFlags) -> Result<(), Errno> {
        Err(Errno::OPNOTSUPP)
    }

    async fn zone_reset(&self, _off: u64, _flags: IoFlags) -> Result<(), Errno> {
        Err(Errno::OPNOTSUPP)
    }

    async fn zone_reset_all(&self, _flags: IoFlags) -> Result<(), Errno> {
        Err(Errno::OPNOTSUPP)
    }

    async fn report_zones(
        &self,
        _off: u64,
        _buf: ZoneBuf<'_>,
        _flags: IoFlags,
    ) -> Result<usize, Errno> {
        Err(Errno::OPNOTSUPP)
    }
}

#[derive(Debug)]
enum RawBuf<'a> {
    PreCopied(&'a mut [u8]),
    UserCopy {
        cdev: BorrowedFd<'a>,
        off: u64,
        len: u32,
    },
}

impl RawBuf<'_> {
    fn len(&self) -> usize {
        match self {
            RawBuf::PreCopied(b) => b.len(),
            RawBuf::UserCopy { len, .. } => *len as _,
        }
    }
}

/// The return buffer for [`BlockDevice::read`].
#[derive(Debug)]
pub struct ReadBuf<'a>(RawBuf<'a>, PhantomData<*mut ()>);

impl ReadBuf<'_> {
    /// Returns the byte length requested for read, which must not be zero.
    // It must not be empty.
    #[allow(clippy::len_without_is_empty)]
    #[must_use]
    pub fn len(&self) -> usize {
        self.0.len()
    }

    /// Reply `data` to fulfill the read request.
    ///
    /// This method will automatically select the correct way to transfer. In case of
    /// [`FeatureFlags::UserCopy`], pwrite(2) is used; otherwise, it does an ordinary memory copy
    /// to the kernel driver buffer.
    ///
    /// # Panics
    ///
    /// Panic if `data.len()` differs from [`Self::len()`].
    pub fn copy_from(&mut self, data: &[u8]) -> Result<(), Errno> {
        assert_eq!(data.len(), self.len());
        match &mut self.0 {
            RawBuf::PreCopied(b) => b.copy_from_slice(data),
            RawBuf::UserCopy { cdev, off, .. } => {
                // SAFETY: The fd is valid and `ManuallyDrop` prevents its close.
                let cdev = unsafe { ManuallyDrop::new(File::from_raw_fd(cdev.as_raw_fd())) };
                cdev.write_all_at(data, *off)
                    .map_err(|e| Errno::from_io_error(&e).unwrap())?;
            }
        }
        Ok(())
    }

    /// Try to get the internal buffer as a mutable slice for manual filling.
    ///
    /// It will returns `None` if the device is created with [`FeatureFlags::UserCopy`].
    /// Generally [`Self::copy_from`] should be preferred if applicatable.
    ///
    /// The returned slice (if any) will have the same length as [`Self::len()`].
    pub fn as_slice(&mut self) -> Option<&'_ mut [u8]> {
        match &mut self.0 {
            RawBuf::PreCopied(b) => Some(b),
            RawBuf::UserCopy { .. } => None,
        }
    }
}

/// The input buffer for [`BlockDevice::write`].
#[derive(Debug)]
pub struct WriteBuf<'a>(RawBuf<'a>, PhantomData<*mut ()>);

impl WriteBuf<'_> {
    /// Returns the byte length requested for write, which must not be zero.
    // It must not be empty.
    #[allow(clippy::len_without_is_empty)]
    #[must_use]
    pub fn len(&self) -> usize {
        self.0.len()
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
    pub fn copy_to(&self, out: &mut [u8]) -> Result<(), Errno> {
        assert_eq!(out.len(), self.len());
        match &self.0 {
            RawBuf::PreCopied(b) => out.copy_from_slice(b),
            RawBuf::UserCopy { cdev, off, .. } => {
                // SAFETY: The fd is valid and `ManuallyDrop` prevents its close.
                let cdev = unsafe { ManuallyDrop::new(File::from_raw_fd(cdev.as_raw_fd())) };
                cdev.read_exact_at(out, *off)
                    .map_err(|e| Errno::from_io_error(&e).unwrap())?;
            }
        }
        Ok(())
    }

    /// Try to get the internal buffer as a slice for manual usage.
    ///
    /// It will returns `None` if the device is created with [`FeatureFlags::UserCopy`].
    /// Generally [`Self::copy_to`] should be preferred if applicatable.
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
pub struct ZoneBuf<'a> {
    cdev: BorrowedFd<'a>,
    off: u64,
    zones: u32,
    #[allow(clippy::mut_mut)]
    _not_send_invariant: PhantomData<(*mut (), &'a mut &'a mut ())>,
}

impl ZoneBuf<'_> {
    /// Returns the number of zones requested, which must not be zero.
    // It must not be empty.
    #[must_use]
    #[allow(clippy::len_without_is_empty)]
    pub fn len(&self) -> usize {
        self.zones as _
    }

    /// Return zones informations as response.
    ///
    /// # Panics
    ///
    /// Panic if `zones.len()` differs from [`Self::len()`].
    pub fn report(&mut self, zones: &[Zone]) -> Result<usize, Errno> {
        assert_eq!(zones.len(), self.zones as _);
        // SAFETY: `Zone` is `repr(transparent)` to `struct blk_zone`.
        let data = unsafe {
            std::slice::from_raw_parts(zones.as_ptr().cast::<u8>(), mem::size_of_val(zones))
        };
        // SAFETY: The fd is valid and `ManuallyDrop` prevents its close.
        let cdev = unsafe { ManuallyDrop::new(File::from_raw_fd(self.cdev.as_raw_fd())) };
        cdev.write_all_at(data, self.off)
            .map_err(|e| Errno::from_io_error(&e).unwrap())?;
        Ok(data.len())
    }
}