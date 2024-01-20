use std::fs;
use std::io::{self, ErrorKind, Read, Write};
use std::path::PathBuf;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Mutex;
use std::time::{Duration, Instant};

use orb::runtime::{SyncRuntimeBuilder, TokioRuntimeBuilder};
use orb::ublk::{
    BlockDevice, ControlDevice, DevState, DeviceAttrs, DeviceBuilder, DeviceInfo, DeviceParams,
    FeatureFlags, IoFlags, ReadBuf, Stopper, WriteBuf, BDEV_PREFIX, SECTOR_SIZE,
};
use rand::rngs::StdRng;
use rand::{Rng, RngCore, SeedableRng};
use rustix::io::Errno;
use xshell::{cmd, Shell};

fn init() -> ControlDevice {
    ControlDevice::open()
        .expect("failed to open control device, kernel module 'ublk_drv' not loaded?")
}

fn retry_on_perm<T>(mut f: impl FnMut() -> io::Result<T>) -> io::Result<T> {
    const RETRY_DELAY: Duration = Duration::from_millis(100);
    let mut retries_left = 10;
    loop {
        match f() {
            Err(err) if err.kind() == ErrorKind::PermissionDenied && retries_left > 0 => {
                eprintln!("permission denied, retries left: {retries_left}");
                retries_left -= 1;
                std::thread::sleep(RETRY_DELAY);
            }
            ret => return ret,
        }
    }
}

#[test]
fn get_features() {
    let ctl = init();
    let feat = ctl.get_features().unwrap();
    println!("{feat:?}");
    assert!(feat.contains(FeatureFlags::UnprivilegedDev));
    // Zero-copy is not supported by upstream yet.
    assert!(!feat.contains(FeatureFlags::SupportZeroCopy));
}

#[test]
fn create_info_delete() {
    let ctl = init();
    let mut builder = DeviceBuilder::new();
    builder
        .name("ublk-test")
        .queues(3)
        .queue_depth(6)
        .io_buf_size(12 << 10)
        .unprivileged();
    let info = ctl.create_device(&builder).unwrap();
    scopeguard::defer_on_unwind! {
        if let Err(err) = retry_on_perm(|| ctl.delete_device(info.dev_id())) {
            if std::thread::panicking() {
                eprintln!("failed to delete device: {err}");
            } else {
                panic!("failed to delete device: {err}");
            }
        }
    }

    assert!(info.dev_id() < i32::MAX as u32);
    assert_eq!(info.nr_queues(), 3);
    assert_eq!(info.queue_depth(), 6);
    assert_eq!(info.io_buf_size(), 12 << 10);
    assert_eq!(info.state(), DevState::Dead);

    let info2 = retry_on_perm(|| ctl.get_device_info(info.dev_id())).unwrap();
    assert_eq!(info.dev_id(), info2.dev_id());
    assert_eq!(info.nr_queues(), info2.nr_queues());
    assert_eq!(info.queue_depth(), info2.queue_depth());
    assert_eq!(info.io_buf_size(), info2.io_buf_size());
    assert_eq!(info.state(), info2.state());

    ctl.delete_device(info.dev_id()).unwrap();
}

#[test]
fn device_attrs() {
    let ctl = init();
    let mut srv = DeviceBuilder::new()
        .name("ublk-test")
        .unprivileged()
        .create_service(&ctl)
        .unwrap();

    const SIZE: u64 = 42 << 10;
    let params = *DeviceParams::new()
        .size(SIZE)
        .attrs(DeviceAttrs::Rotational);

    struct Handler<'a> {
        tested: &'a AtomicBool,
    }
    impl BlockDevice for Handler<'_> {
        fn ready(&self, dev_info: &DeviceInfo, stop: Stopper) {
            let dev_sys_path = PathBuf::from(format!("/sys/block/ublkb{}", dev_info.dev_id()));
            let size = fs::read_to_string(dev_sys_path.join("size"))
                .unwrap()
                .trim()
                .parse::<u64>()
                .unwrap();
            assert_eq!(size * SECTOR_SIZE as u64, SIZE);
            let rotational = fs::read_to_string(dev_sys_path.join("queue/rotational")).unwrap();
            assert_eq!(rotational.trim(), "1");
            let ro = fs::read_to_string(dev_sys_path.join("ro")).unwrap();
            assert_eq!(ro.trim(), "0");

            self.tested.store(true, Ordering::Relaxed);
            stop.stop();
        }

        async fn read(
            &self,
            _off: u64,
            _buf: ReadBuf<'_>,
            _flags: IoFlags,
        ) -> Result<usize, Errno> {
            Err(Errno::IO)
        }

        async fn write(
            &self,
            _off: u64,
            _buf: WriteBuf<'_>,
            _flags: IoFlags,
        ) -> Result<usize, Errno> {
            Err(Errno::IO)
        }
    }

    let tested = AtomicBool::new(false);
    srv.serve(SyncRuntimeBuilder, &params, Handler { tested: &tested })
        .unwrap();
    assert!(tested.load(Ordering::Relaxed));
}

#[test]
fn read_write_kernel_copy() {
    read_write(FeatureFlags::empty())
}

#[test]
fn read_write_user_copy() {
    read_write(FeatureFlags::UserCopy)
}

fn read_write(flags: FeatureFlags) {
    let ctl = init();
    let mut srv = DeviceBuilder::new()
        .name("ublk-test")
        .unprivileged()
        .add_flags(flags)
        .create_service(&ctl)
        .unwrap();

    const SIZE: u64 = 32 << 10;
    const TEST_WRITE_ROUNDS: usize = 32;
    const SEED: u64 = 0xDEAD_BEEF_DEAD_BEEF;

    let mut rng = StdRng::seed_from_u64(SEED);
    let mut data = vec![0u8; SIZE as usize];
    rng.fill_bytes(&mut data);

    struct Handler<'a> {
        tested: &'a AtomicBool,
        data: Mutex<Vec<u8>>,
        rng: StdRng,
    }
    impl BlockDevice for Handler<'_> {
        fn ready(&self, dev_info: &DeviceInfo, stop: Stopper) {
            let dev_path = format!("{}{}", BDEV_PREFIX, dev_info.dev_id());
            let mut rng = self.rng.clone();

            retry_on_perm(|| {
                rustix::fs::access(&dev_path, rustix::fs::Access::WRITE_OK).map_err(|e| e.into())
            })
            .unwrap();

            // NB. Perform I/O in another process to avoid deadlocks.
            let sh = Shell::new().unwrap();
            let mut state = cmd!(sh, "cat {dev_path}").output().unwrap().stdout;
            // The initial data should match.
            assert_eq!(state.len(), SIZE as usize);
            assert_eq!(state, *self.data.lock().unwrap());

            let mut buf = [0u8; SECTOR_SIZE as usize];
            for _ in 0..TEST_WRITE_ROUNDS {
                // Write a random block at random sector.
                let sector_offset = rng.gen_range(0..(SIZE / SECTOR_SIZE as u64));
                rng.fill_bytes(&mut buf);
                let sector_offset_s = sector_offset.to_string();
                cmd!(
                    sh,
                    "dd if=/dev/stdin of={dev_path} bs=512 count=1 oseek={sector_offset_s}"
                )
                .ignore_stderr()
                .stdin(buf)
                .run()
                .unwrap();
                let offset = sector_offset * SECTOR_SIZE as u64;
                state[offset as usize..][..SECTOR_SIZE as usize].copy_from_slice(&buf);

                // Retrieve all data, and they should match.
                let got = cmd!(sh, "cat {dev_path}").output().unwrap().stdout;
                assert_eq!(got, state);
            }

            assert_eq!(*self.data.lock().unwrap(), state);

            self.tested.store(true, Ordering::Relaxed);
            stop.stop();
        }

        async fn read(
            &self,
            off: u64,
            mut buf: ReadBuf<'_>,
            _flags: IoFlags,
        ) -> Result<usize, Errno> {
            buf.copy_from(&self.data.lock().unwrap()[off as usize..][..buf.len()])?;
            Ok(buf.len())
        }

        async fn write(
            &self,
            off: u64,
            buf: WriteBuf<'_>,
            _flags: IoFlags,
        ) -> Result<usize, Errno> {
            let len = buf.len();
            buf.copy_to(&mut self.data.lock().unwrap()[off as usize..][..len])?;
            Ok(len)
        }
    }

    let tested = AtomicBool::new(false);
    srv.serve(
        SyncRuntimeBuilder,
        DeviceParams::new().size(SIZE),
        Handler {
            tested: &tested,
            data: Mutex::new(data),
            rng,
        },
    )
    .unwrap();
    assert!(tested.load(Ordering::Relaxed));
}

#[test]
#[ignore = "spam dmesg"]
fn error() {
    let ctl = init();
    let mut srv = DeviceBuilder::new()
        .name("ublk-test")
        .unprivileged()
        .create_service(&ctl)
        .unwrap();

    const SIZE: u64 = 4 << 10;

    struct Handler<'a> {
        tested: &'a AtomicBool,
    }
    impl BlockDevice for Handler<'_> {
        fn ready(&self, dev_info: &DeviceInfo, stop: Stopper) {
            let dev_path = PathBuf::from(format!("{}{}", BDEV_PREFIX, dev_info.dev_id()));
            let mut file = retry_on_perm(|| {
                fs::OpenOptions::new()
                    .read(true)
                    .write(true)
                    .open(&dev_path)
            })
            .unwrap();

            let err = file.read(&mut [0u8; 64]).unwrap_err();
            assert_eq!(err.raw_os_error(), Some(Errno::IO.raw_os_error()));

            let err = file.write(&[0u8; 64]).unwrap_err();
            assert_eq!(err.raw_os_error(), Some(Errno::IO.raw_os_error()));

            self.tested.store(true, Ordering::Relaxed);
            stop.stop();
        }

        async fn read(
            &self,
            _off: u64,
            _buf: ReadBuf<'_>,
            _flags: IoFlags,
        ) -> Result<usize, Errno> {
            Err(Errno::IO)
        }

        async fn write(
            &self,
            _off: u64,
            _buf: WriteBuf<'_>,
            _flags: IoFlags,
        ) -> Result<usize, Errno> {
            Err(Errno::IO)
        }
    }

    let tested = AtomicBool::new(false);
    srv.serve(
        SyncRuntimeBuilder,
        DeviceParams::new().size(SIZE),
        Handler { tested: &tested },
    )
    .unwrap();
    assert!(tested.load(Ordering::Relaxed));
}

#[test]
fn tokio_null_kernel_copy() {
    tokio_null(FeatureFlags::empty())
}

#[test]
fn tokio_null_user_copy() {
    tokio_null(FeatureFlags::UserCopy)
}

fn tokio_null(flags: FeatureFlags) {
    let ctl = init();
    let mut srv = DeviceBuilder::new()
        .name("ublk-test")
        .unprivileged()
        .add_flags(flags)
        .create_service(&ctl)
        .unwrap();

    const SIZE: u64 = 4 << 10;
    const DELAY: Duration = Duration::from_millis(500);
    const TOLERANCE: Duration = Duration::from_millis(50);

    struct Handler<'a> {
        tested: &'a AtomicBool,
    }
    impl BlockDevice for Handler<'_> {
        fn ready(&self, dev_info: &DeviceInfo, stop: Stopper) {
            let dev_path = format!("{}{}", BDEV_PREFIX, dev_info.dev_id());
            retry_on_perm(|| {
                rustix::fs::access(&dev_path, rustix::fs::Access::WRITE_OK).map_err(|e| e.into())
            })
            .unwrap();

            // NB. Perform I/O in another process to avoid deadlocks.
            let sh = Shell::new().unwrap();
            let inst = Instant::now();
            let out = cmd!(sh, "dd if={dev_path} of=/dev/stdout bs=512 count=1")
                .ignore_stderr()
                .output()
                .unwrap()
                .stdout;
            let elapsed = inst.elapsed();
            assert_eq!(out, [0u8; SECTOR_SIZE as _]);
            assert!(
                DELAY - TOLERANCE <= elapsed && elapsed <= DELAY + TOLERANCE,
                "unexpected delay: {elapsed:?}",
            );

            self.tested.store(true, Ordering::Relaxed);
            stop.stop();
        }

        async fn read(
            &self,
            _off: u64,
            mut buf: ReadBuf<'_>,
            _flags: IoFlags,
        ) -> Result<usize, Errno> {
            tokio::time::sleep(DELAY).await;
            buf.fill(0)?;
            Ok(buf.len())
        }

        async fn write(
            &self,
            _off: u64,
            _buf: WriteBuf<'_>,
            _flags: IoFlags,
        ) -> Result<usize, Errno> {
            Err(Errno::IO)
        }
    }

    let tested = AtomicBool::new(false);
    srv.serve(
        TokioRuntimeBuilder,
        DeviceParams::new().size(SIZE),
        Handler { tested: &tested },
    )
    .unwrap();
    assert!(tested.load(Ordering::Relaxed));
}
