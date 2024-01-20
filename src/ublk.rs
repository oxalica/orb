#![warn(missing_debug_implementations)]
use std::alloc::{GlobalAlloc, Layout, System};
use std::fs::File;
use std::marker::PhantomData;
use std::mem::ManuallyDrop;
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
use rustix::io::Errno;
use rustix::process::Pid;
use rustix::{ioctl, mm};

use crate::runtime::{AsyncRuntime, AsyncRuntimeBuilder, AsyncScopeSpawner};

// TODO
const PAGE_SIZE: u32 = 4 << 10;
pub const SECTOR_SIZE: u32 = 512;

const DEFAULT_IO_BUF_SIZE: u32 = 512 << 10;
const BUFFER_ALIGN: usize = 64;

pub const CDEV_PREFIX: &str = "/dev/ublkc";
pub const BDEV_PREFIX: &str = "/dev/ublkb";

#[allow(non_camel_case_types, non_snake_case, unused)]
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

    unsafe fn execute_ctrl_cmd_with_cdev<T>(
        &self,
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
        let ret = self.execute_ctrl_cmd(direction, cmd_op, buf, cmd)?;
        Ok(ret.1)
    }

    unsafe fn execute_ctrl_cmd<T>(
        &self,
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
        let sqe = opcode::UringCmd80::new(Fd(self.fd.as_raw_fd()), opcode.raw())
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
            self.execute_ctrl_cmd(
                ioctl::Direction::Read,
                // FIXME: Not exported by bindgen.
                0x13,
                0u64,
                Default::default(),
            )
            .map(FeatureFlags::from_bits_truncate)
        }
    }

    pub fn get_device_info(&self, dev_id: u32) -> io::Result<DeviceInfo> {
        // SAFETY: Valid uring_cmd.
        unsafe {
            self.execute_ctrl_cmd_with_cdev::<binding::ublksrv_ctrl_dev_info>(
                ioctl::Direction::Read,
                binding::UBLK_CMD_GET_DEV_INFO2,
                dev_id,
                mem::zeroed(),
                Default::default(),
            )
            .map(DeviceInfo)
        }
    }

    pub fn create_device(&self, builder: &DeviceBuilder) -> io::Result<DeviceInfo> {
        // `-1` for auto-allocation.
        let dev_id = builder.id.unwrap_or(!0);
        let pid = rustix::process::getpid();
        // SAFETY: Valid uring_cmd.
        unsafe {
            self.execute_ctrl_cmd(
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

    pub fn delete_device(&self, dev_id: u32) -> io::Result<()> {
        log::trace!("delete device {dev_id}");
        // SAFETY: Valid uring_cmd.
        unsafe {
            self.execute_ctrl_cmd_with_cdev(
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
    fn start_device(&self, dev_id: u32, pid: Pid) -> io::Result<()> {
        let pid = pid.as_raw_nonzero().get().try_into().unwrap();
        log::trace!("start device {dev_id} on pid {pid}");
        // SAFETY: Valid uring_cmd.
        unsafe {
            self.execute_ctrl_cmd_with_cdev(
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

    pub fn stop_device(&self, dev_id: u32) -> io::Result<()> {
        log::trace!("stop device {dev_id}");
        // SAFETY: Valid uring_cmd.
        unsafe {
            self.execute_ctrl_cmd_with_cdev(
                ioctl::Direction::ReadWrite,
                binding::UBLK_CMD_STOP_DEV,
                dev_id,
                [0u8; 0],
                Default::default(),
            )?;
        }
        Ok(())
    }

    pub fn set_device_param(&self, dev_id: u32, params: &DeviceParams) -> io::Result<()> {
        log::trace!("set parameters of device {dev_id} to {params:?}");
        // SAFETY: Valid uring_cmd.
        unsafe {
            self.execute_ctrl_cmd_with_cdev::<binding::ublk_params>(
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

    pub fn create_service<'ctl>(&self, ctl: &'ctl ControlDevice) -> io::Result<Service<'ctl>> {
        let dev_info = ctl.create_device(self)?;

        // Delete the device if anything goes wrong.
        let delete_device_guard = scopeguard::guard((ctl, dev_info.dev_id()), |(ctl, dev_id)| {
            if let Err(err) = ctl.stop_device(dev_id) {
                // Ignore errors if already deleted.
                if err.kind() != io::ErrorKind::NotFound {
                    log::error!("failed to stop device {dev_id}: {err}");
                }
            }
        });

        let path = format!("{}{}", CdevPath::PREFIX, dev_info.dev_id());
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

        // Success. Defuse the guard.
        scopeguard::ScopeGuard::into_inner(delete_device_guard);

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

impl Service<'_> {
    pub fn dev_info(&self) -> &DeviceInfo {
        &self.dev_info
    }

    pub fn run<RB, D>(
        &mut self,
        runtime_builder: RB,
        params: &DeviceParams,
        handler: D,
    ) -> io::Result<()>
    where
        RB: AsyncRuntimeBuilder + Sync,
        D: BlockDevice + Sync,
    {
        let dev_id = self.dev_info().dev_id();
        let nr_queues = self.dev_info.nr_queues();
        assert_ne!(nr_queues, 0);
        self.ctl.set_device_param(dev_id, params)?;

        // The guard to stop the device once it's started.
        // This must be outside the thread scope so all resources are released on stopping.
        let mut stop_device_guard = scopeguard::guard((self, false), |(this, active)| {
            if !active {
                return;
            }
            let dev_id = this.dev_info().dev_id();
            if let Err(err) = this.ctl.stop_device(dev_id) {
                // Ignore errors if already deleted.
                if err.kind() != io::ErrorKind::NotFound {
                    log::error!("failed to stop device {dev_id}: {err}");
                }
            }
        });
        let (this, stop_device_guard_active) = &mut *stop_device_guard;

        // No one is actually `read` it, so no need to be a semaphore.
        let exit_fd = Arc::new(rustix::event::eventfd(0, EventfdFlags::CLOEXEC)?);
        thread::scope(|s| {
            // One element gets produced once a thread is initialized and ready for events.
            let (ready_tx, ready_rx) = std::sync::mpsc::sync_channel::<()>(nr_queues.into());

            // This will be dropped inside the scope, so all threads are signaled to exit
            // during force join.
            let thread_stop_guard = SignalStopOnDrop(exit_fd.as_fd());

            let handles = (0..nr_queues)
                .map(|thread_id| {
                    let worker = IoWorker {
                        thread_id,
                        ready_tx: Some(ready_tx.clone().clone()),
                        cdev: this.cdev.as_fd(),
                        dev_info: &this.dev_info,
                        handler: &handler,
                        runtime_builder: &runtime_builder,
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
                this.ctl.start_device(dev_id, rustix::process::getpid())?;

                // Now device is started, and `/dev/ublkbX` appears.
                // FIXME: The device status still reports DEAD here.
                *stop_device_guard_active = true;
                handler.ready(this.dev_info(), Stopper(Arc::clone(&exit_fd)));

                let ret = rustix::io::retry_on_intr(|| {
                    rustix::event::poll(
                        &mut [PollFd::new(&exit_fd, PollFlags::IN)],
                        -1, // INFINITE
                    )
                })?;
                assert_eq!(ret, 1);
            }

            // Collect panics and errors.
            for (thread_id, h) in handles.into_iter().enumerate() {
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
}

struct IoWorker<'a, B, RB> {
    thread_id: u16,
    ready_tx: Option<std::sync::mpsc::SyncSender<()>>,
    cdev: BorrowedFd<'a>,
    dev_info: &'a DeviceInfo,
    handler: &'a B,
    runtime_builder: &'a RB,

    // This is dropped last.
    stop_guard: SignalStopOnDrop<'a>,
}

impl<B: BlockDevice, RB: AsyncRuntimeBuilder> IoWorker<'_, B, RB> {
    fn run(mut self) -> io::Result<()> {
        if let Err(err) = rustix::process::configure_io_flusher_behavior(true) {
            // TODO: Option to make this a hard error?
            log::error!("failed to configure as IO_FLUSHER: {err}");
        }

        let shm = IoDescShm::new(self.cdev, self.dev_info, self.thread_id)?;

        let queue_depth = self.dev_info.queue_depth();
        let buf_size = self
            .dev_info
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

        // Plus `PollAdd` for notification.
        let ring_size = (queue_depth as u32 + 1)
            .checked_next_power_of_two()
            .unwrap();
        // NB. Ensure all inflight ops are cancelled before dropping the buffer defined above,
        // otherwise it's a use-after-free.
        let mut io_ring = scopeguard::guard(IoUring::new(ring_size)?, |io_ring| {
            // All ops must be canceled before return, otherwise it's a UB.
            let _guard = scopeguard::guard_on_unwind((), |()| std::process::abort());
            if let Err(err) = io_ring
                .submitter()
                .register_sync_cancel(None, io_uring::types::CancelBuilder::any())
            {
                if err.kind() != io::ErrorKind::NotFound {
                    log::error!("failed to cancel inflight ops in io-uring: {}", err);
                    std::process::abort();
                }
            }
        });
        io_ring
            .submitter()
            .register_files(&[self.cdev.as_raw_fd(), self.stop_guard.0.as_raw_fd()])?;
        const CDEV_FIXED_FD: Fixed = Fixed(0);
        const EXIT_FIXED_FD: Fixed = Fixed(1);
        const EXIT_USER_DATA: u64 = !0;

        let mut runtime = self.runtime_builder.build()?;

        let refill_sqe = |sq: &mut SubmissionQueue<'_>, i: u16, result: Option<i32>| {
            let cmd = binding::ublksrv_io_cmd {
                q_id: self.thread_id,
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
        io_ring.submit()?;

        log::debug!("IO worker {} initialized", self.thread_id);
        if self.ready_tx.take().unwrap().send(()).is_err() {
            // Stopping.
            return Ok(());
        }

        runtime.drive_uring(&io_ring, |spawner| {
            // SAFETY: This is the only place to modify the CQ.
            let cq = unsafe { io_ring.completion_shared() };
            for cqe in cq {
                if cqe.user_data() == EXIT_USER_DATA {
                    assert!(
                        PollFlags::from_bits_truncate(cqe.result() as _).contains(PollFlags::IN),
                        "unexpected poll result: {}",
                        cqe.result(),
                    );
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
                let commit_and_fetch = move |ret: i32| {
                    // SAFETY: All futures are executed on the same thread, which is guarantee
                    // by no `Send` bound on parameters of `Runtime::{block_on,spawn_local}`.
                    // So there can only be one future running this block at the same time.
                    unsafe {
                        let mut sq = io_ring.submission_shared();
                        refill_sqe(&mut sq, tag, Some(ret));
                    }
                    io_ring.submit().expect("failed to submit");
                };

                let iod = shm.get(tag);
                let flags = IoFlags::from_bits_truncate(iod.op_flags);
                // These fields may contain garbage for ops without them.
                let off = iod.start_sector.wrapping_mul(SECTOR_SIZE as u64);
                let len = unsafe { iod.__bindgen_anon_1.nr_sectors as usize }
                    .wrapping_mul(SECTOR_SIZE as usize);
                let op = iod.op_flags & 0xFF;
                // TODO: Catch unwind.
                match op {
                    binding::UBLK_IO_OP_READ => {
                        log::trace!("READ offset={off} len={len} flags={flags:?}");
                        // SAFETY: This buffer is exclusive for task of `tag`.
                        let buf = unsafe { io_buf_of(tag).as_mut() };
                        let buf = ReadBuf(&mut buf[..len], PhantomData);
                        let fut = self.handler.read(off, buf, flags);
                        // TODO: This line is repeated over and over due to distinct Future types.
                        spawner.spawn(async move { commit_and_fetch(fut.await.into_c_result()) });
                    }
                    binding::UBLK_IO_OP_WRITE => {
                        log::trace!("WRITE offset={off} len={len} flags={flags:?}");
                        // SAFETY: This buffer is exclusive for task of `tag`.
                        let buf = unsafe { io_buf_of(tag).as_mut() };
                        let buf = WriteBuf(&buf[..len], PhantomData);
                        let fut = self.handler.write(off, buf, flags);
                        spawner.spawn(async move { commit_and_fetch(fut.await.into_c_result()) });
                    }
                    binding::UBLK_IO_OP_FLUSH => {
                        log::trace!("FLUSH flags={flags:?}");
                        let fut = self.handler.flush(flags);
                        spawner.spawn(async move { commit_and_fetch(fut.await.into_c_result()) });
                    }
                    binding::UBLK_IO_OP_DISCARD => {
                        log::trace!("DISCARD offset={off} len={len} flags={flags:?}");
                        let fut = self.handler.discard(off, len, flags);
                        spawner.spawn(async move { commit_and_fetch(fut.await.into_c_result()) });
                    }
                    binding::UBLK_IO_OP_WRITE_ZEROES => {
                        log::trace!("WRITE_ZEROES offset={off} len={len} flags={flags:?}");
                        let fut = self.handler.write_zeroes(off, len, flags);
                        spawner.spawn(async move { commit_and_fetch(fut.await.into_c_result()) });
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
                        commit_and_fetch(-Errno::IO.raw_os_error());
                    }
                }
            }

            Ok(ControlFlow::Continue(()))
        })
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct DeviceParams {
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
}

impl Default for DeviceParams {
    fn default() -> Self {
        Self::new()
    }
}

impl DeviceParams {
    /// Default parameters.
    pub const fn new() -> Self {
        Self {
            attrs: DeviceAttrs::empty(),
            size: 0,
            logical_block_size: 512,
            physical_block_size: PAGE_SIZE,
            io_optimal_size: PAGE_SIZE,
            io_min_size: PAGE_SIZE,
            io_max_size: DEFAULT_IO_BUF_SIZE,
            chunk_size: 0,
            virt_boundary_mask: 0,
            discard: None,
        }
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
pub trait BlockDevice {
    fn ready(&self, dev_info: &DeviceInfo, stop: Stopper);

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
}

/// The return buffer for [`BlockDevice::read`].
#[derive(Debug)]
pub struct ReadBuf<'a>(&'a mut [u8], PhantomData<*mut ()>);

impl ReadBuf<'_> {
    // It must not be empty.
    #[allow(clippy::len_without_is_empty)]
    pub fn len(&self) -> usize {
        self.0.len()
    }

    pub fn copy_from(&mut self, data: &[u8]) {
        self.0.copy_from_slice(data);
    }

    pub fn fill(&mut self, byte: u8) {
        self.0.fill(byte);
    }

    pub fn as_slice(&mut self) -> Option<&'_ mut [u8]> {
        Some(self.0)
    }
}

/// The input buffer for [`BlockDevice::write`].
#[derive(Debug)]
pub struct WriteBuf<'a>(&'a [u8], PhantomData<*mut ()>);

impl WriteBuf<'_> {
    // It must not be empty.
    #[allow(clippy::len_without_is_empty)]
    pub fn len(&self) -> usize {
        self.0.len()
    }

    pub fn copy_to(&self, out: &mut [u8]) {
        out.copy_from_slice(self.0);
    }

    pub fn as_slice(&self) -> Option<&[u8]> {
        Some(self.0)
    }
}
