use std::fs;
use std::io::{self, ErrorKind, Read, Write};
use std::path::PathBuf;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

use orb_ublk::runtime::{AsyncRuntimeBuilder, SyncRuntimeBuilder, TokioRuntimeBuilder};
use orb_ublk::{
    BlockDevice, ControlDevice, DevState, DeviceAttrs, DeviceBuilder, DeviceInfo, DeviceParams,
    DiscardParams, FeatureFlags, IoFlags, ReadBuf, Stopper, WriteBuf, Zone, ZoneBuf, ZoneCond,
    ZoneType, ZonedParams, BDEV_PREFIX, SECTOR_SIZE,
};
use rand::rngs::StdRng;
use rand::{Rng, RngCore, SeedableRng};
use rstest::{fixture, rstest};
use rustix::io::Errno;
use xshell::{cmd, Shell};

const QUEUE_DEPTH: u16 = 2;
const MAX_READ_LEN: usize = 1 << 20; // Is there really a limit in Linux?

static ZEROES: [u8; MAX_READ_LEN] = [0; MAX_READ_LEN];

#[fixture]
fn ctl() -> ControlDevice {
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

#[allow(clippy::needless_pass_by_value)]
fn test_service<B: BlockDevice + Sync>(
    ctl: &ControlDevice,
    flags: FeatureFlags,
    queues: u16,
    params: &DeviceParams,
    rt_builder: impl AsyncRuntimeBuilder + Sync,
    handler: impl FnOnce(Arc<AtomicBool>) -> B,
) {
    let mut srv = DeviceBuilder::new()
        .name("ublk-test")
        .unprivileged()
        .add_flags(flags)
        .queues(queues)
        .queue_depth(QUEUE_DEPTH)
        .create_service(ctl)
        .unwrap();
    let tested = Arc::new(AtomicBool::new(false));
    if queues == 1 {
        srv.serve_local(&rt_builder, params, &handler(tested.clone()))
            .unwrap();
    } else {
        srv.serve(&rt_builder, params, &handler(tested.clone()))
            .unwrap();
    }
    assert!(tested.load(Ordering::Relaxed));
}

fn wait_blockdev_ready(info: &DeviceInfo) -> io::Result<String> {
    let path = format!("{}{}", BDEV_PREFIX, info.dev_id());
    retry_on_perm(|| rustix::fs::access(&path, rustix::fs::Access::WRITE_OK).map_err(Into::into))?;
    Ok(path)
}

#[rstest]
fn get_features(ctl: ControlDevice) {
    let feat = ctl.get_features().unwrap();
    println!("{feat:?}");
    assert!(feat.contains(FeatureFlags::UnprivilegedDev));
    // Zero-copy is not supported by upstream yet.
    assert!(!feat.contains(FeatureFlags::SupportZeroCopy));
}

#[rstest]
fn create_info_delete(ctl: ControlDevice) {
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

#[rstest]
#[case::local(1)]
#[case::threaded(1)]
fn device_attrs(ctl: ControlDevice, #[case] queues: u16) {
    const SIZE: u64 = 42 << 10;
    let params = *DeviceParams::new()
        .size(SIZE)
        .attrs(DeviceAttrs::Rotational);

    test_service(
        &ctl,
        FeatureFlags::empty(),
        queues,
        &params,
        SyncRuntimeBuilder,
        |tested| Handler { tested },
    );

    struct Handler {
        tested: Arc<AtomicBool>,
    }
    impl BlockDevice for Handler {
        fn ready(&self, dev_info: &DeviceInfo, stop: Stopper) -> io::Result<()> {
            scopeguard::defer!(stop.stop());

            assert_eq!(
                ControlDevice::open()
                    .unwrap()
                    .get_device_info(dev_info.dev_id())
                    .unwrap()
                    .state(),
                DevState::Live,
            );

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
            Ok(())
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
}

#[rstest]
#[case::default_local(FeatureFlags::empty(), 1)]
#[case::default_threaded(FeatureFlags::empty(), 2)]
#[case::user_copy_local(FeatureFlags::UserCopy, 1)]
#[case::user_copy_threaded(FeatureFlags::UserCopy, 2)]
fn read_write(ctl: ControlDevice, #[case] flags: FeatureFlags, #[case] queues: u16) {
    const SIZE: u64 = 32 << 10;
    const TEST_WRITE_ROUNDS: usize = 32;
    const SEED: u64 = 0xDEAD_BEEF_DEAD_BEEF;

    let mut rng = StdRng::seed_from_u64(SEED);
    let mut data = vec![0u8; SIZE as usize];
    rng.fill_bytes(&mut data);
    let data = Arc::new(Mutex::new(data));

    test_service(
        &ctl,
        flags,
        queues,
        DeviceParams::new().size(SIZE),
        SyncRuntimeBuilder,
        |tested| Handler { tested, data, rng },
    );

    #[derive(Clone)]
    struct Handler {
        tested: Arc<AtomicBool>,
        data: Arc<Mutex<Vec<u8>>>,
        rng: StdRng,
    }
    impl BlockDevice for Handler {
        fn ready(&self, dev_info: &DeviceInfo, stop: Stopper) -> io::Result<()> {
            let dev_info = *dev_info;
            let Handler {
                tested,
                data,
                mut rng,
            } = self.clone();
            std::thread::spawn(move || {
                scopeguard::defer!(stop.stop());

                let dev_path = wait_blockdev_ready(&dev_info).unwrap();

                // NB. Perform I/O in another process to avoid deadlocks.
                let sh = Shell::new().unwrap();
                let mut state = cmd!(sh, "cat {dev_path}").output().unwrap().stdout;
                // The initial data should match.
                assert_eq!(state.len(), SIZE as usize);
                assert_eq!(state, *data.lock().unwrap());

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

                assert_eq!(*data.lock().unwrap(), state);

                tested.store(true, Ordering::Relaxed);
            });
            Ok(())
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
}

#[rstest]
#[ignore = "spam dmesg"]
fn error(ctl: ControlDevice) {
    const SIZE: u64 = 4 << 10;

    test_service(
        &ctl,
        FeatureFlags::empty(),
        1,
        DeviceParams::new().size(SIZE),
        SyncRuntimeBuilder,
        |tested| Handler { tested },
    );

    struct Handler {
        tested: Arc<AtomicBool>,
    }
    impl BlockDevice for Handler {
        fn ready(&self, dev_info: &DeviceInfo, stop: Stopper) -> io::Result<()> {
            let dev_path = PathBuf::from(format!("{}{}", BDEV_PREFIX, dev_info.dev_id()));
            let tested = self.tested.clone();
            std::thread::spawn(move || {
                scopeguard::defer!(stop.stop());

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

                tested.store(true, Ordering::Relaxed);
            });
            Ok(())
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
}

#[rstest]
#[ignore = "spam dmesg"]
#[case::local(1)]
#[ignore = "spam dmesg"]
#[case::threaded(1)]
fn handler_panic(ctl: ControlDevice, #[case] queues: u16) {
    const SIZE: u64 = SECTOR_SIZE as _;
    const TEST_ROUNDS: u16 = QUEUE_DEPTH * 2;

    test_service(
        &ctl,
        FeatureFlags::empty(),
        queues,
        DeviceParams::new().size(SIZE),
        TokioRuntimeBuilder,
        |tested| Handler {
            should_ok: Default::default(),
            tested,
        },
    );

    #[derive(Clone)]
    struct Handler {
        should_ok: Arc<AtomicBool>,
        tested: Arc<AtomicBool>,
    }
    impl BlockDevice for Handler {
        fn ready(&self, dev_info: &DeviceInfo, stop: Stopper) -> io::Result<()> {
            let dev_info = *dev_info;
            let Handler { should_ok, tested } = self.clone();
            std::thread::spawn(move || {
                scopeguard::defer!(stop.stop());

                let dev_path = wait_blockdev_ready(&dev_info).unwrap();
                let sh = Shell::new().unwrap();

                for _ in 0..TEST_ROUNDS {
                    cmd!(sh, "cat {dev_path}")
                        .ignore_stderr()
                        .run()
                        .unwrap_err();
                }

                // Should still work after recovered.
                should_ok.store(true, Ordering::Relaxed);
                for _ in 0..TEST_ROUNDS {
                    let ret = cmd!(sh, "cat {dev_path}").ignore_stderr().read().unwrap();
                    assert_eq!(ret.as_bytes(), [0u8; SECTOR_SIZE as _]);
                }

                tested.store(true, Ordering::Relaxed);
            });
            Ok(())
        }

        async fn read(
            &self,
            _off: u64,
            mut buf: ReadBuf<'_>,
            _flags: IoFlags,
        ) -> Result<usize, Errno> {
            if self.should_ok.load(Ordering::Relaxed) {
                buf.copy_from(&ZEROES[..buf.len()])?;
                Ok(buf.len())
            } else {
                panic!("nooo");
            }
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
}

#[rstest]
#[case::default_local(FeatureFlags::empty(), 1)]
#[case::default_threaded(FeatureFlags::empty(), 2)]
#[case::user_copy_local(FeatureFlags::UserCopy, 1)]
#[case::user_copy_threaded(FeatureFlags::UserCopy, 2)]
fn tokio_null(ctl: ControlDevice, #[case] flags: FeatureFlags, #[case] queues: u16) {
    const SIZE: u64 = 4 << 10;
    const DELAY: Duration = Duration::from_millis(500);
    const TOLERANCE: Duration = Duration::from_millis(50);

    test_service(
        &ctl,
        flags,
        queues,
        DeviceParams::new().size(SIZE),
        TokioRuntimeBuilder,
        |tested| Handler { tested },
    );

    struct Handler {
        tested: Arc<AtomicBool>,
    }
    impl BlockDevice for Handler {
        fn ready(&self, dev_info: &DeviceInfo, stop: Stopper) -> io::Result<()> {
            let dev_info = *dev_info;
            let tested = self.tested.clone();
            std::thread::spawn(move || {
                scopeguard::defer!(stop.stop());

                let dev_path = wait_blockdev_ready(&dev_info).unwrap();

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

                tested.store(true, Ordering::Relaxed);
            });
            Ok(())
        }

        async fn read(
            &self,
            _off: u64,
            mut buf: ReadBuf<'_>,
            _flags: IoFlags,
        ) -> Result<usize, Errno> {
            tokio::time::sleep(DELAY).await;
            buf.copy_from(&ZEROES[..buf.len()])?;
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
}

#[rstest]
fn discard(ctl: ControlDevice) {
    const SIZE: u64 = 4 << 10;
    const GRANULARITY: u32 = 1 << 10;

    test_service(
        &ctl,
        FeatureFlags::empty(),
        1,
        DeviceParams::new().size(SIZE).discard(DiscardParams {
            alignment: GRANULARITY,
            granularity: GRANULARITY,
            max_size: SIZE as _,
            max_write_zeroes_size: SIZE as _,
            max_segments: 1,
        }),
        SyncRuntimeBuilder,
        |tested| Handler {
            tested,
            discarded: Default::default(),
        },
    );

    #[derive(Clone)]
    struct Handler {
        tested: Arc<AtomicBool>,
        discarded: Arc<Mutex<Vec<(bool, u64, usize)>>>,
    }
    impl BlockDevice for Handler {
        fn ready(&self, dev_info: &DeviceInfo, stop: Stopper) -> io::Result<()> {
            let dev_info = *dev_info;
            let Self { tested, discarded } = self.clone();
            std::thread::spawn(move || {
                scopeguard::defer!(stop.stop());
                let dev_path = wait_blockdev_ready(&dev_info).unwrap();

                let sh = Shell::new().unwrap();
                let take_discarded = || std::mem::take(&mut *discarded.lock().unwrap());

                cmd!(sh, "blkdiscard {dev_path}").run().unwrap();
                assert_eq!(take_discarded(), [(false, 0, SIZE as _)]);
                cmd!(sh, "blkdiscard --zeroout {dev_path}").run().unwrap();
                assert_eq!(take_discarded(), [(true, 0, SIZE as _)]);

                cmd!(sh, "blkdiscard -o 1024 -l 2048 {dev_path}")
                    .run()
                    .unwrap();
                assert_eq!(take_discarded(), [(false, 1024, 2048)]);
                cmd!(sh, "blkdiscard --zeroout -o 1024 -l 2048 {dev_path}")
                    .run()
                    .unwrap();
                assert_eq!(take_discarded(), [(true, 1024, 2048)]);

                tested.store(true, Ordering::Relaxed);
            });
            Ok(())
        }

        async fn read(
            &self,
            _off: u64,
            mut buf: ReadBuf<'_>,
            _flags: IoFlags,
        ) -> Result<usize, Errno> {
            buf.copy_from(&ZEROES[..buf.len()])?;
            Ok(buf.len())
        }

        async fn write(
            &self,
            _off: u64,
            buf: WriteBuf<'_>,
            _flags: IoFlags,
        ) -> Result<usize, Errno> {
            Ok(buf.len())
        }

        async fn discard(&self, off: u64, len: usize, _flags: IoFlags) -> Result<(), Errno> {
            self.discarded.lock().unwrap().push((false, off, len));
            Ok(())
        }

        async fn write_zeroes(&self, off: u64, len: usize, _flags: IoFlags) -> Result<(), Errno> {
            self.discarded.lock().unwrap().push((true, off, len));
            Ok(())
        }
    }
}

#[rstest]
fn zoned(ctl: ControlDevice) {
    const SIZE: u64 = 4 << 10;
    const ZONE_SIZE: u32 = 1 << 10;
    const ZONES: u64 = SIZE / ZONE_SIZE as u64;
    const MAX_OPEN_ZONES: u32 = ZONES as u32;
    const MAX_ACTIVE_ZONES: u32 = ZONES as u32;
    const MAX_ZONE_APPEND_SIZE: u32 = 1 << 10;

    let zones = (0..ZONES)
        .map(|i| {
            if i < 2 {
                Zone::new(
                    i * ZONE_SIZE as u64,
                    ZONE_SIZE as u64,
                    0,
                    ZoneType::Conventional,
                    ZoneCond::NotWp,
                )
            } else {
                Zone::new(
                    i * ZONE_SIZE as u64,
                    ZONE_SIZE as u64,
                    i * SECTOR_SIZE as u64,
                    ZoneType::SeqWriteReq,
                    ZoneCond::Empty,
                )
            }
        })
        .collect::<Vec<_>>();

    test_service(
        &ctl,
        FeatureFlags::Zoned | FeatureFlags::UserCopy,
        1,
        DeviceParams::new()
            .size(SIZE)
            .chunk_size(ZONE_SIZE)
            .zoned(ZonedParams {
                max_open_zones: MAX_OPEN_ZONES,
                max_active_zones: MAX_ACTIVE_ZONES,
                max_zone_append_size: MAX_ZONE_APPEND_SIZE,
            }),
        SyncRuntimeBuilder,
        |tested| Handler {
            tested,
            zones: zones.into(),
            ops: Default::default(),
        },
    );

    #[derive(Clone)]
    struct Handler {
        tested: Arc<AtomicBool>,
        zones: Arc<[Zone]>,
        ops: Arc<Mutex<String>>,
    }
    impl BlockDevice for Handler {
        fn ready(&self, dev_info: &DeviceInfo, stop: Stopper) -> io::Result<()> {
            let dev_info = *dev_info;
            let Self { tested, ops, .. } = self.clone();
            std::thread::spawn(move || {
                scopeguard::defer!(stop.stop());
                let dev_path = wait_blockdev_ready(&dev_info).unwrap();
                let sys_queue_path =
                    PathBuf::from(format!("/sys/block/ublkb{}/queue", dev_info.dev_id()));

                let opt_str = |subpath: &str| {
                    fs::read_to_string(sys_queue_path.join(subpath))
                        .unwrap()
                        .trim()
                        .to_owned()
                };
                let opt_u32 = |subpath: &str| opt_str(subpath).parse::<u32>().unwrap();

                assert_eq!(opt_str("zoned"), "host-managed");
                assert_eq!(opt_u32("chunk_sectors"), ZONE_SIZE / SECTOR_SIZE);
                assert_eq!(opt_u32("nr_zones"), SIZE as u32 / ZONE_SIZE);
                assert_eq!(opt_u32("zone_append_max_bytes"), MAX_ZONE_APPEND_SIZE);
                assert_eq!(opt_u32("max_open_zones"), MAX_OPEN_ZONES);
                assert_eq!(opt_u32("max_active_zones"), MAX_ACTIVE_ZONES);

                let sh = Shell::new().unwrap();
                let report = cmd!(sh, "blkzone report {dev_path}").read().unwrap();
                println!("{report}");
                let expect = "
  start: 0x000000000, len 0x000002, cap 0x000000, wptr 0x000000 reset:0 non-seq:0, zcond: 0(nw) [type: 1(CONVENTIONAL)]
  start: 0x000000002, len 0x000002, cap 0x000000, wptr 0x000000 reset:0 non-seq:0, zcond: 0(nw) [type: 1(CONVENTIONAL)]
  start: 0x000000004, len 0x000002, cap 0x000000, wptr 0x000002 reset:0 non-seq:0, zcond: 1(em) [type: 2(SEQ_WRITE_REQUIRED)]
  start: 0x000000006, len 0x000002, cap 0x000000, wptr 0x000003 reset:0 non-seq:0, zcond: 1(em) [type: 2(SEQ_WRITE_REQUIRED)]
                ";
                assert_eq!(report.trim(), expect.trim());

                // The zone with id 2.
                cmd!(sh, "blkzone open {dev_path} --offset 4 --length 2")
                    .run()
                    .unwrap();
                cmd!(sh, "blkzone close {dev_path} --offset 4 --length 2")
                    .run()
                    .unwrap();
                cmd!(sh, "blkzone finish {dev_path} --offset 4 --length 2")
                    .run()
                    .unwrap();
                cmd!(sh, "blkzone reset {dev_path} --offset 4 --length 2")
                    .run()
                    .unwrap();
                cmd!(sh, "blkzone reset {dev_path}").run().unwrap();
                assert_eq!(*ops.lock().unwrap(), "open;close;finish;reset;reset_all;");

                tested.store(true, Ordering::Relaxed);
            });
            Ok(())
        }

        async fn read(
            &self,
            _off: u64,
            mut buf: ReadBuf<'_>,
            _flags: IoFlags,
        ) -> Result<usize, Errno> {
            buf.copy_from(&ZEROES[..buf.len()])?;
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

        async fn report_zones(
            &self,
            off: u64,
            mut buf: ZoneBuf<'_>,
            _flags: IoFlags,
        ) -> Result<usize, Errno> {
            let zid = off / ZONE_SIZE as u64;
            buf.report(&self.zones[zid as usize..][..buf.len()])
        }

        async fn zone_open(&self, off: u64, _flags: IoFlags) -> Result<(), Errno> {
            assert_eq!(off, 2 << 10);
            self.ops.lock().unwrap().push_str("open;");
            Ok(())
        }

        async fn zone_close(&self, off: u64, _flags: IoFlags) -> Result<(), Errno> {
            assert_eq!(off, 2 << 10);
            self.ops.lock().unwrap().push_str("close;");
            Ok(())
        }

        async fn zone_finish(&self, off: u64, _flags: IoFlags) -> Result<(), Errno> {
            assert_eq!(off, 2 << 10);
            self.ops.lock().unwrap().push_str("finish;");
            Ok(())
        }

        async fn zone_reset(&self, off: u64, _flags: IoFlags) -> Result<(), Errno> {
            assert_eq!(off, 2 << 10);
            self.ops.lock().unwrap().push_str("reset;");
            Ok(())
        }

        async fn zone_reset_all(&self, _flags: IoFlags) -> Result<(), Errno> {
            self.ops.lock().unwrap().push_str("reset_all;");
            Ok(())
        }
    }
}
