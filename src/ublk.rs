#![warn(missing_debug_implementations)]
use std::alloc::{GlobalAlloc, Layout, System};
use std::fs::File;
use std::mem::ManuallyDrop;
use std::os::fd::{BorrowedFd, RawFd};
use std::ptr::NonNull;
use std::sync::Arc;
use std::time::Duration;
use std::{fmt, io, mem, ptr, thread};

use io_uring::types::{Fd, Fixed};
use io_uring::{cqueue, opcode, squeue, IoUring, SubmissionQueue};
use rustix::event::{EventfdFlags, PollFd, PollFlags};
use rustix::fd::{AsFd, AsRawFd, OwnedFd};
use rustix::io::Errno;
use rustix::termios::Pid;
use rustix::{ioctl, mm};

// TODO
const PAGE_SIZE: u32 = 4 << 10;
const SECTOR_SIZE: u32 = 512;

const DEFAULT_IO_BUF_SIZE: u32 = 512 << 10;
const BUFFER_ALIGN: usize = 64;

#[allow(non_camel_case_types, unused)]
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

// FIXME: This struct should not exist.
pub struct Uring {
    uring: IoUring<squeue::Entry128, cqueue::Entry>,
}

impl fmt::Debug for Uring {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("Uring").finish_non_exhaustive()
    }
}

impl Uring {
    pub fn new() -> io::Result<Self> {
        const URING_ENTRIES: u32 = 16;

        let uring = IoUring::builder().build(URING_ENTRIES)?;
        Ok(Self { uring })
    }

    unsafe fn execute_single(&mut self, op: &squeue::Entry128) -> io::Result<i32> {
        self.uring.submission().push(op).expect("squeue full");
        self.uring.submit_and_wait(1)?;
        let ret = self.uring.completion().next().unwrap().result();
        if ret >= 0 {
            Ok(ret)
        } else {
            Err(io::Error::from_raw_os_error(-ret))
        }
    }
}

#[derive(Debug)]
#[repr(transparent)]
struct CdevPath([u8; Self::MAX_LEN]);

impl CdevPath {
    // "/dev/ublkc2147483647".len() = 20
    const MAX_LEN: usize = 24;
    const PREFIX: &'static str = "/dev/ublkc";

    fn from_id(id: u32) -> Self {
        use std::io::Write;

        let mut buf = [0u8; Self::MAX_LEN];
        write!(&mut buf[..], "{}{}", Self::PREFIX, id).unwrap();
        Self(buf)
    }
}

/// The global control device for ublk-driver `/dev/ublk-control`.
#[derive(Debug)]
pub struct ControlDevice(File);

impl ControlDevice {
    pub const PATH: &'static str = "/dev/ublk-control";

    pub fn open() -> io::Result<Self> {
        File::options()
            .read(true)
            .write(true)
            .open(Self::PATH)
            .map(Self)
    }

    pub fn try_clone(&self) -> io::Result<Self> {
        self.0.try_clone().map(Self)
    }

    unsafe fn execute_ctrl_cmd_with_cdev<T>(
        &self,
        uring: &mut Uring,
        direction: ioctl::Direction,
        cmd_op: u32,
        dev_id: u32,
        buf: T,
        mut cmd: binding::ublksrv_ctrl_cmd,
    ) -> io::Result<T> {
        #[repr(C)]
        struct Payload<T>(CdevPath, T);

        let buf = Payload(CdevPath::from_id(dev_id), buf);
        cmd.dev_id = dev_id;
        cmd.dev_path_len = CdevPath::MAX_LEN as _;
        let ret = self.execute_ctrl_cmd(uring, direction, cmd_op, buf, cmd)?;
        Ok(ret.1)
    }

    unsafe fn execute_ctrl_cmd<T>(
        &self,
        uring: &mut Uring,
        direction: ioctl::Direction,
        cmd_op: u32,
        mut buf: T,
        mut cmd: binding::ublksrv_ctrl_cmd,
    ) -> io::Result<T> {
        cmd.addr = &mut buf as *mut T as _;
        cmd.len = mem::size_of::<T>() as _;

        #[repr(C)]
        union CtrlCmdBuf {
            cmd: [u8; 80],
            data: binding::ublksrv_ctrl_cmd,
        }

        let mut cmd_buf = CtrlCmdBuf { cmd: [0; 80] };
        cmd_buf.data = cmd;
        let opcode = ioctl::Opcode::from_components(
            direction,
            b'u',
            // FIXME: Type mismatch?
            cmd_op as u8,
            mem::size_of::<binding::ublksrv_ctrl_cmd>(),
        );
        let sqe = opcode::UringCmd80::new(Fd(self.0.as_raw_fd()), opcode.raw())
            .cmd(cmd_buf.cmd)
            .build();
        uring.execute_single(&sqe)?;

        Ok(buf)
    }

    pub fn get_features(&self, uring: &mut Uring) -> io::Result<FeatureFlags> {
        unsafe {
            self.execute_ctrl_cmd(
                uring,
                ioctl::Direction::Read,
                // FIXME: Not exported by bindgen.
                0x13,
                0u64,
                Default::default(),
            )
            .map(FeatureFlags::from_bits_truncate)
        }
    }

    pub fn get_device_info(&self, uring: &mut Uring, dev_id: u32) -> io::Result<DeviceInfo> {
        unsafe {
            self.execute_ctrl_cmd_with_cdev::<binding::ublksrv_ctrl_dev_info>(
                uring,
                ioctl::Direction::Read,
                binding::UBLK_CMD_GET_DEV_INFO2,
                dev_id,
                mem::zeroed(),
                Default::default(),
            )
            .map(DeviceInfo)
        }
    }

    pub fn create_device(
        &self,
        uring: &mut Uring,
        builder: &DeviceBuilder,
    ) -> io::Result<DeviceInfo> {
        // `-1` for auto-allocation.
        let dev_id = builder.id.unwrap_or(!0);
        let pid = rustix::process::getpid();
        unsafe {
            self.execute_ctrl_cmd(
                uring,
                ioctl::Direction::ReadWrite,
                binding::UBLK_CMD_ADD_DEV,
                binding::ublksrv_ctrl_dev_info {
                    nr_hw_queues: builder.nr_hw_queues,
                    queue_depth: builder.queue_depth,
                    max_io_buf_bytes: builder.io_buf_bytes,
                    dev_id,
                    ublksrv_pid: pid.as_raw_nonzero().get() as _,
                    flags: builder.features.bits(),
                    // TODO
                    // state
                    // ublksrv_flags
                    // owner_uid
                    // owner_gid
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

    pub fn delete_device(&self, uring: &mut Uring, dev_id: u32) -> io::Result<()> {
        log::trace!("delete device {dev_id}");
        unsafe {
            self.execute_ctrl_cmd_with_cdev(
                uring,
                ioctl::Direction::ReadWrite,
                binding::UBLK_CMD_DEL_DEV,
                dev_id,
                [0u8; 0],
                Default::default(),
            )?;
        }
        Ok(())
    }

    // This cannot be start alone. IO handlers must be started before it,
    // or this would block indefinitely.
    fn start_device(&self, uring: &mut Uring, dev_id: u32, pid: Pid) -> io::Result<()> {
        let pid = pid.as_raw_nonzero().get().try_into().unwrap();
        log::trace!("start device {dev_id} on pid {pid}");
        unsafe {
            self.execute_ctrl_cmd_with_cdev(
                uring,
                ioctl::Direction::ReadWrite,
                binding::UBLK_CMD_START_DEV,
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

    pub fn stop_device(&self, uring: &mut Uring, dev_id: u32) -> io::Result<()> {
        log::trace!("stop device {dev_id}");
        unsafe {
            self.execute_ctrl_cmd_with_cdev(
                uring,
                ioctl::Direction::ReadWrite,
                binding::UBLK_CMD_STOP_DEV,
                dev_id,
                [0u8; 0],
                Default::default(),
            )?;
        }
        Ok(())
    }

    pub fn set_device_param(
        &self,
        uring: &mut Uring,
        dev_id: u32,
        params: &DeviceParams,
    ) -> io::Result<()> {
        log::trace!("set parameters of device {dev_id} to {params:?}");
        unsafe {
            self.execute_ctrl_cmd_with_cdev::<binding::ublk_params>(
                uring,
                ioctl::Direction::ReadWrite,
                binding::UBLK_CMD_SET_PARAMS,
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
        self.0.as_raw_fd()
    }
}

impl AsFd for ControlDevice {
    fn as_fd(&self) -> BorrowedFd<'_> {
        self.0.as_fd()
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

    pub fn id(&mut self, id: u32) -> &mut Self {
        assert_ne!(id, !0);
        self.id = Some(id);
        self
    }

    pub fn queues(&mut self, nr_hw_queues: u16) -> &mut Self {
        assert!((1..=(1 << binding::UBLK_QID_BITS)).contains(&nr_hw_queues));
        self.nr_hw_queues = nr_hw_queues;
        self
    }

    pub fn queue_depth(&mut self, queue_depth: u16) -> &mut Self {
        assert!((1..=binding::UBLK_MAX_QUEUE_DEPTH as u16).contains(&queue_depth));
        self.queue_depth = queue_depth;
        self
    }

    pub fn io_buf_size(&mut self, bytes: u32) -> &mut Self {
        assert!((1..=(1 << binding::UBLK_IO_BUF_BITS)).contains(&bytes));
        self.io_buf_bytes = bytes;
        self
    }

    pub fn unprivileged(&mut self) -> &mut Self {
        self.features |= FeatureFlags::UnprivilegedDev;
        self
    }

    pub fn flags(&mut self, flags: FeatureFlags) -> &mut Self {
        self.features = flags;
        self
    }

    pub fn max_retries(&mut self, n: u16) -> &mut Self {
        self.max_retries = n;
        self
    }

    pub fn create_service(&self, ctrl: ControlDevice, mut uring: Uring) -> io::Result<Service> {
        let dev_info = ctrl.create_device(&mut uring, self)?;

        struct StopOnDrop<'a, 'b>(Option<(&'a mut Uring, &'b ControlDevice, u32)>);
        impl Drop for StopOnDrop<'_, '_> {
            fn drop(&mut self) {
                if let Some((uring, ctrl, dev_id)) = &mut self.0 {
                    if let Err(err) = ctrl.stop_device(uring, *dev_id) {
                        // Ignore errors if already deleted.
                        if err.kind() != io::ErrorKind::NotFound {
                            log::error!("failed to stop device {dev_id}: {err}");
                        }
                    }
                }
            }
        }

        let cdev = {
            // Delete the device if anything goes wrong.
            let mut guard = StopOnDrop(Some((&mut uring, &ctrl, dev_info.dev_id())));

            let path = format!("{}{}", CdevPath::PREFIX, dev_info.dev_id());
            let mut retries_left = self.max_retries;
            // NB. `cdev` and `shared_mem` should live here rather than the outer block, so they
            // can be released before `guard`. Otherwise the device may fail to be deleted.
            let cdev = loop {
                match File::options().read(true).write(true).open(&path) {
                    Ok(f) => break f,
                    Err(err)
                        if err.kind() == io::ErrorKind::PermissionDenied && retries_left > 0 =>
                    {
                        log::warn!("failed to open {path}, retries left: {retries_left}");
                        retries_left -= 1;
                        thread::sleep(self.retry_delay);
                    }
                    Err(err) => return Err(err),
                }
            };

            // All success, defuse the guard.
            guard.0 = None;

            cdev
        };

        Ok(Service {
            dev_info,
            ctl_ring: uring,
            ctl: ctrl,
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

#[derive(Debug, Clone, Copy)]
#[non_exhaustive]
#[repr(u8)]
pub enum DevState {
    Dead = binding::UBLK_S_DEV_DEAD as _,
    Live = binding::UBLK_S_DEV_LIVE as _,
    Quiesced = binding::UBLK_S_DEV_QUIESCED as _,
    #[doc(hidden)]
    Unknown(u16),
}

impl DeviceInfo {
    pub fn dev_id(&self) -> u32 {
        self.0.dev_id
    }

    pub fn queue_depth(&self) -> u16 {
        self.0.queue_depth
    }

    pub fn state(&self) -> DevState {
        match self.0.state as u32 {
            binding::UBLK_S_DEV_DEAD => DevState::Dead,
            binding::UBLK_S_DEV_LIVE => DevState::Live,
            binding::UBLK_S_DEV_QUIESCED => DevState::Quiesced,
            _ => DevState::Unknown(self.0.state),
        }
    }

    pub fn nr_queues(&self) -> u16 {
        self.0.nr_hw_queues
    }

    pub fn io_buf_size(&self) -> usize {
        self.0.max_io_buf_bytes.try_into().unwrap()
    }

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
pub struct Service {
    dev_info: DeviceInfo,
    ctl_ring: Uring,
    ctl: ControlDevice,
    /// `/dev/ublkcX` file.
    cdev: ManuallyDrop<File>,
}

impl Drop for Service {
    fn drop(&mut self) {
        // First, drop all resources derived from the device.
        unsafe {
            ManuallyDrop::drop(&mut self.cdev);
        }
        let dev_id = self.dev_info().dev_id();
        if let Err(err) = self.ctl.delete_device(&mut self.ctl_ring, dev_id) {
            if err.kind() != io::ErrorKind::NotFound {
                log::error!("failed to delete device {dev_id}: {err}");
            }
        }
    }
}

/// Signal all threads when something goes wrong somewhere.
struct SignalExitOnDrop<'a>(BorrowedFd<'a>);
impl Drop for SignalExitOnDrop<'_> {
    fn drop(&mut self) {
        rustix::io::write(self.0, &1u64.to_ne_bytes()).unwrap();
    }
}

#[derive(Debug, Clone)]
pub struct Stopper(Arc<OwnedFd>);

impl Stopper {
    pub fn stop(&self) {
        rustix::io::write(&self.0, &1u64.to_ne_bytes()).unwrap();
    }
}

struct AlignedArray<const ALIGN: usize>(NonNull<[u8]>);

impl<const ALIGN: usize> AlignedArray<ALIGN> {
    pub fn new(size: usize) -> Self {
        let layout = Layout::from_size_align(size, ALIGN).unwrap();
        match NonNull::new(unsafe { System.alloc(layout) }) {
            None => std::alloc::handle_alloc_error(layout),
            Some(ptr) => Self(NonNull::slice_from_raw_parts(ptr, size)),
        }
    }
}

impl<const ALIGN: usize> Drop for AlignedArray<ALIGN> {
    fn drop(&mut self) {
        unsafe {
            let layout = Layout::from_size_align_unchecked(self.0.len(), ALIGN);
            System.dealloc(self.0.as_ptr().cast(), layout);
        }
    }
}

impl Service {
    pub fn dev_info(&self) -> &DeviceInfo {
        &self.dev_info
    }

    pub fn run<D: BlockDevice + Sync>(
        &mut self,
        params: &DeviceParams,
        handler: D,
    ) -> io::Result<()> {
        let dev_id = self.dev_info().dev_id();
        self.ctl
            .set_device_param(&mut self.ctl_ring, dev_id, params)?;

        // The guard to stop the device once it's started.
        // This must be outside the thread scope so all resources are released on stopping.
        struct StopOnDrop<'a> {
            this: &'a mut Service,
            active: bool,
        }
        impl Drop for StopOnDrop<'_> {
            fn drop(&mut self) {
                if self.active {
                    let dev_id = self.this.dev_info().dev_id();
                    if let Err(err) = self.this.ctl.stop_device(&mut self.this.ctl_ring, dev_id) {
                        // Ignore errors if already deleted.
                        if err.kind() != io::ErrorKind::NotFound {
                            log::error!("failed to stop device {dev_id}: {err}");
                        }
                    }
                }
            }
        }
        let mut stop_guard = StopOnDrop {
            this: self,
            active: false,
        };
        let this = &mut *stop_guard.this;

        // No one is actually `read` it, so no need to be a semaphore.
        let exit_fd = Arc::new(rustix::event::eventfd(0, EventfdFlags::CLOEXEC)?);
        thread::scope(|s| {
            let _exit_guard = SignalExitOnDrop(exit_fd.as_fd());

            let handles = (0..this.dev_info().nr_queues())
                .map(|thread_id| {
                    let handler = &handler;
                    let exit_fd = exit_fd.as_fd();
                    let cdev = this.cdev.as_fd();
                    let dev_info = &this.dev_info;
                    thread::Builder::new()
                        .name(format!("io-worker-{thread_id}"))
                        .spawn_scoped(s, move || {
                            io_thread(thread_id, exit_fd, cdev, dev_info, handler)
                        })
                })
                .collect::<io::Result<Vec<_>>>()?;

            // NB. Start the device after all handler threads are running,
            // or this will block indefinitely.
            // FIXME: This may still stuck if any thread fail to initialize.
            this.ctl
                .start_device(&mut this.ctl_ring, dev_id, rustix::process::getpid())?;
            stop_guard.active = true;
            // FIXME: It still reports DEAD here.
            handler.ready(this.dev_info(), Stopper(exit_fd.clone()));

            let ret = rustix::io::retry_on_intr(|| {
                rustix::event::poll(&mut [PollFd::new(&exit_fd, PollFlags::IN)], -1)
            })?;
            assert_eq!(ret, 1);

            // Collect panics and errors.
            for (thread_id, h) in handles.into_iter().enumerate() {
                match h.join() {
                    Ok(Ok(())) => {}
                    // Device deleted by other thread or process. Treat it as a graceful shutdown.
                    Ok(Err(err)) if err.raw_os_error() == Some(Errno::NODEV.raw_os_error()) => {}
                    Ok(Err(err)) => return Err(err),
                    Err(_) => {
                        return Err(io::Error::other(format!("IO thread {thread_id} panicked")));
                    }
                }
            }
            Ok(())
        })
    }
}

fn io_thread<D: BlockDevice>(
    thread_id: u16,
    exit_fd: BorrowedFd<'_>,
    cdev: BorrowedFd<'_>,
    dev_info: &DeviceInfo,
    handler: &D,
) -> io::Result<()> {
    let exit_guard = SignalExitOnDrop(exit_fd);

    if let Err(err) = rustix::process::configure_io_flusher_behavior(true) {
        // TODO: Option to make this a hard error?
        log::error!("failed to configure as IO_FLUSHER: {err}");
    }

    let shm = IoDescShm::new(cdev, dev_info, thread_id)?;

    let queue_depth = dev_info.queue_depth();
    let buf_size = dev_info
        .io_buf_size()
        .checked_next_multiple_of(BUFFER_ALIGN)
        .unwrap();
    let total_buf_size = buf_size.checked_mul(queue_depth.into()).unwrap();
    // Must define the buffer before the io-uring, see below.
    let io_buf = AlignedArray::<BUFFER_ALIGN>::new(total_buf_size);
    let io_buf_of = |i: u16| unsafe {
        NonNull::new_unchecked(ptr::slice_from_raw_parts_mut(
            io_buf.0.as_ptr().cast::<u8>().add(i as usize * buf_size),
            buf_size,
        ))
    };

    // NB. Ensure all inflight ops are cancelled before dropping the buffer defined above,
    // otherwise it's a use-after-free.
    struct AutoCancelRing(IoUring);
    impl Drop for AutoCancelRing {
        fn drop(&mut self) {
            if let Err(err) = self
                .0
                .submitter()
                .register_sync_cancel(None, io_uring::types::CancelBuilder::any())
            {
                if err.kind() != io::ErrorKind::NotFound {
                    log::error!("failed to cancel inflight ops in io-uring");
                    std::process::abort();
                }
            }
        }
    }

    // Plus `PollAdd` for notification.
    let ring_size = (queue_depth as u32 + 1)
        .checked_next_power_of_two()
        .unwrap();
    let mut io_ring = AutoCancelRing(IoUring::new(ring_size)?);
    let io_ring = &mut io_ring.0;
    io_ring
        .submitter()
        .register_files(&[cdev.as_raw_fd(), exit_fd.as_raw_fd()])?;
    const CDEV_FIXED_FD: Fixed = Fixed(0);
    const EXIT_FIXED_FD: Fixed = Fixed(1);
    const EXIT_USER_DATA: u64 = !0;

    let refill_sqe = |sq: &mut SubmissionQueue<'_>, i: u16, result: Option<i32>| {
        let cmd = binding::ublksrv_io_cmd {
            q_id: thread_id,
            tag: i,
            result: result.unwrap_or(-1),
            __bindgen_anon_1: binding::ublksrv_io_cmd__bindgen_ty_1 {
                addr: io_buf_of(i).as_ptr().cast::<u8>() as _,
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

    {
        let mut sq = io_ring.submission();
        unsafe {
            let sqe = opcode::PollAdd::new(EXIT_FIXED_FD, PollFlags::IN.bits().into())
                .build()
                .user_data(EXIT_USER_DATA);
            sq.push(&sqe).unwrap();
        }
        for i in 0..queue_depth {
            refill_sqe(&mut sq, i, None);
        }
    }

    log::debug!("IO thread {thread_id} initialized");
    loop {
        io_ring.submit_and_wait(1)?;
        // NB. We should re-get SQ and CQ every time to update pointers.
        let (_submit, mut sq, cq) = io_ring.split();
        for cqe in cq {
            if cqe.user_data() == EXIT_USER_DATA {
                assert!(
                    PollFlags::from_bits_truncate(cqe.result() as _).contains(PollFlags::IN),
                    "unexpected poll result: {}",
                    cqe.result(),
                );
                log::debug!("IO thread {thread_id} signaled to exit");
                // No need to notify more.
                mem::forget(exit_guard);
                return Ok(());
            }

            // Here it must be a FETCH request.
            if cqe.result() < 0 {
                let err = io::Error::from_raw_os_error(-cqe.result());
                log::debug!("IO thread {thread_id} failed fetch: {err}");
                return Err(err);
            }

            let tag = cqe.user_data() as u16;
            let iod = shm.get(tag);
            let local_io_buf = unsafe { io_buf_of(tag).as_mut() };
            let flags = IoFlags::from_bits_truncate(iod.op_flags);
            // These fields may contain garbage for ops without them.
            let off = iod.start_sector.wrapping_mul(SECTOR_SIZE as u64);
            let len = unsafe { iod.__bindgen_anon_1.nr_sectors as usize }
                .wrapping_mul(SECTOR_SIZE as usize);
            let op = iod.op_flags & 0xFF;
            // TODO: Catch unwind.
            let ret = match op {
                binding::UBLK_IO_OP_READ => {
                    log::trace!("READ offset={off} len={len} flags={flags:?}");
                    handler
                        .read(off, &mut local_io_buf[..len], flags)
                        .map(|()| len as _)
                }
                binding::UBLK_IO_OP_WRITE => {
                    log::trace!("WRITE offset={off} len={len} flags={flags:?}");
                    handler
                        .write(off, &local_io_buf[..len], flags)
                        .map(|()| len as _)
                }
                binding::UBLK_IO_OP_FLUSH => {
                    log::trace!("FLUSH flags={flags:?}");
                    handler.flush(flags).map(|()| 0)
                }
                binding::UBLK_IO_OP_DISCARD => {
                    log::trace!("DISCARD offset={off} len={len} flags={flags:?}");
                    handler.discard(off, len, flags).map(|()| 0)
                }
                binding::UBLK_IO_OP_WRITE_ZEROES => {
                    log::trace!("WRITE_ZEROES offset={off} len={len} flags={flags:?}");
                    handler.write_zeroes(off, len, flags).map(|()| 0)
                }
                // binding::UBLK_IO_OP_WRITE_SAME |
                // binding::UBLK_IO_OP_ZONE_OPEN |
                // binding::UBLK_IO_OP_ZONE_CLOSE |
                // binding::UBLK_IO_OP_ZONE_FINISH |
                // binding::UBLK_IO_OP_ZONE_APPEND |
                // binding::UBLK_IO_OP_ZONE_RESET_ALL |
                // binding::UBLK_IO_OP_ZONE_RESET |
                // binding::UBLK_IO_OP_REPORT_ZONES  |
                _ => {
                    log::error!("unsupported op: {op}");
                    Err(Errno::IO)
                }
            };

            let c_ret = match ret {
                Ok(len) => {
                    assert!(len >= 0);
                    len
                }
                Err(err) => -err.raw_os_error(),
            };

            refill_sqe(&mut sq, tag, Some(c_ret));
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct DeviceParams {
    attrs: DeviceAttrs,
    size: u64,
    logical_block_size: u32,
    physical_block_size: u32,
    io_optimal_size: u32,
    io_min_size: u32,
    io_max_size: u32,
    discard: Option<DiscardParams>,
}

impl Default for DeviceParams {
    fn default() -> Self {
        Self::new()
    }
}

impl DeviceParams {
    pub fn new() -> Self {
        Self {
            attrs: DeviceAttrs::empty(),
            size: 0,
            logical_block_size: 512,
            physical_block_size: PAGE_SIZE,
            io_optimal_size: PAGE_SIZE,
            io_min_size: PAGE_SIZE,
            io_max_size: DEFAULT_IO_BUF_SIZE,
            discard: None,
        }
    }

    pub fn size(&mut self, size: u64) -> &mut Self {
        assert_eq!(size % SECTOR_SIZE as u64, 0);
        self.size = size;
        self
    }

    pub fn io_max_size(&mut self, size: u32) -> &mut Self {
        assert_eq!(size % SECTOR_SIZE, 0);
        self.io_max_size = size;
        self
    }

    pub fn attrs(&mut self, attrs: DeviceAttrs) -> &mut Self {
        self.attrs = attrs;
        self
    }

    pub fn discard(&mut self, params: DiscardParams) -> &mut Self {
        assert_ne!(params.granularity, 0);
        assert_eq!(params.max_size % SECTOR_SIZE, 0);
        assert_eq!(params.max_write_zeroes_size % SECTOR_SIZE, 0);
        self.discard = Some(params);
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

impl DeviceParams {
    fn build(&self) -> binding::ublk_params {
        let mut attrs = DeviceParamsType::Basic;
        attrs.set(DeviceParamsType::Discard, self.discard.is_some());

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
                dev_sectors: self.size / SECTOR_SIZE as u64,
                // TODO: What are these?
                chunk_sectors: 0,
                virt_boundary_mask: 0,
            },
            discard: self
                .discard
                .map_or(Default::default(), |p| binding::ublk_param_discard {
                    discard_alignment: p.alignment,
                    discard_granularity: p.granularity,
                    max_discard_sectors: p.max_size / SECTOR_SIZE,
                    max_write_zeroes_sectors: p.max_write_zeroes_size / SECTOR_SIZE,
                    // TODO: What's this?
                    max_discard_segments: p.max_segments,
                    reserved0: 0,
                }),
            zoned: Default::default(),
            // This is read-only.
            devt: Default::default(),
        }
    }
}

pub trait BlockDevice {
    fn ready(&self, dev_info: &DeviceInfo, stop: Stopper);

    fn read(&self, off: u64, buf: &mut [u8], flags: IoFlags) -> Result<(), Errno>;

    fn write(&self, off: u64, buf: &[u8], flags: IoFlags) -> Result<(), Errno>;

    fn flush(&self, _flags: IoFlags) -> Result<(), Errno> {
        Ok(())
    }

    fn discard(&self, _off: u64, _len: usize, _flags: IoFlags) -> Result<(), Errno> {
        Err(Errno::OPNOTSUPP)
    }

    fn write_zeroes(&self, _off: u64, _len: usize, _flags: IoFlags) -> Result<(), Errno> {
        Err(Errno::OPNOTSUPP)
    }
}
