use std::sync::Mutex;
use std::thread;
use std::time::{Duration, Instant};

use libtest_mimic::{Arguments, Failed, Trial};
use orb_ublk::runtime::{AsyncRuntimeBuilder, SyncRuntimeBuilder};
use orb_ublk::{
    BlockDevice, ControlDevice, DeviceBuilder, DeviceInfo, DeviceParams, IoFlags, ReadBuf, Sector,
    Stopper, WriteBuf,
};
use rustix::io::Errno;
use rustix::process::{kill_process, Pid, Signal};

const DELAY: Duration = Duration::from_millis(200);

static STOPPER: Mutex<Option<Stopper>> = Mutex::new(None);

fn main() -> std::process::ExitCode {
    let mut args = Arguments::from_args();
    // Force run tests in main thread because we do signal handling.
    args.test_threads = Some(1);
    let tests = vec![
        Trial::test("interrupt_local", || interrupt(1)),
        Trial::test("interrupt_threaded", || interrupt(2)),
    ];

    ctrlc::set_handler(move || {
        if let Some(s) = STOPPER.lock().unwrap().take() {
            s.stop();
        }
    })
    .unwrap();

    libtest_mimic::run(&args, tests).exit_code()
}

#[allow(clippy::unnecessary_wraps)]
fn interrupt(queues: u16) -> Result<(), Failed> {
    let ctl = ControlDevice::open().unwrap();

    let mut srv = DeviceBuilder::new()
        .name("ublk-test")
        .queues(queues)
        .unprivileged()
        .create_service(&ctl)
        .unwrap();

    let params = *DeviceParams::new().dev_sectors(Sector(1));
    let inst = Instant::now();
    let h = Handler {
        pid: rustix::process::getpid(),
        thread: Mutex::new(None),
    };
    if queues == 1 {
        srv.serve_local(&mut SyncRuntimeBuilder.build().unwrap(), &params, &h)
            .unwrap();
    } else {
        srv.serve(&SyncRuntimeBuilder, &params, &h).unwrap();
    }
    let elapsed = inst.elapsed();
    assert!(elapsed >= DELAY, "unexpected elapsed time: {elapsed:?}");

    h.thread.lock().unwrap().take().unwrap().join().unwrap();

    Ok(())
}

struct Handler {
    pid: Pid,
    thread: Mutex<Option<thread::JoinHandle<()>>>,
}

impl BlockDevice for Handler {
    fn ready(&self, _dev_info: &DeviceInfo, stop: Stopper) -> std::io::Result<()> {
        *STOPPER.lock().unwrap() = Some(stop);
        let pid = self.pid;
        let j = thread::spawn(move || {
            thread::sleep(DELAY);
            kill_process(pid, Signal::INT).unwrap();
        });
        *self.thread.lock().unwrap() = Some(j);
        Ok(())
    }

    async fn read(
        &self,
        _off: Sector,
        _buf: &mut ReadBuf<'_>,
        _flags: IoFlags,
    ) -> Result<(), Errno> {
        Err(Errno::IO)
    }

    async fn write(
        &self,
        _off: Sector,
        _buf: WriteBuf<'_>,
        _flags: IoFlags,
    ) -> Result<usize, Errno> {
        Err(Errno::IO)
    }
}
