use std::fmt::Write;
use std::fs::File;
use std::future::Future;
use std::io::Read;
use std::num::NonZeroUsize;
use std::time::Duration;
use std::{mem, ptr, slice};

use anyhow::Result;
use bytes::Bytes;
use futures_util::{FutureExt, Stream};
use orb_ublk::{
    BlockDevice, IoFlags, ReadBuf, Sector, WriteBuf, Zone, ZoneBuf, ZoneCond, ZoneType,
};
use parking_lot::Mutex;
use rustix::fd::AsFd;
use rustix::io::Errno;

use crate::memory_backend::Memory;
use crate::service::{Backend, Config, Frontend};

#[derive(Debug)]
pub struct TestBackend {
    inner: Memory,
    log: Mutex<String>,
    delay: Mutex<Duration>,
}

impl TestBackend {
    pub fn new_empty(zone_cnt: usize) -> Self {
        Self {
            inner: Memory::new(zone_cnt),
            log: Mutex::default(),
            delay: Mutex::new(Duration::ZERO),
        }
    }

    #[track_caller]
    pub fn new_with_chunks(
        nr_zones: usize,
        // (zid, cid, data) where cid := coff / SECTOR_SIZE.
        chunks: impl IntoIterator<Item = (u32, u32, Vec<u8>)>,
    ) -> Self {
        let mut this = Self::new_empty(nr_zones);
        for (zid, cid, data) in chunks {
            let coff = cid * Sector::SIZE;
            let prev = this.inner.zones[zid as usize]
                .get_mut()
                .insert(coff, data.into());
            assert!(prev.is_none());
        }
        this
    }

    pub fn drain_log(&self) -> String {
        mem::take(&mut self.log.lock())
    }

    fn delay(&self) -> impl Future<Output = ()> + 'static {
        let delay = *self.delay.lock();
        async move {
            if delay != Duration::ZERO {
                tokio::time::sleep(delay).await;
            }
        }
    }
}

macro_rules! act {
    ($this:expr, $($tt:tt)*) => {
        write!(*$this.log.lock(), "{};", format_args!($($tt)*)).unwrap()
    };
}

impl Backend for TestBackend {
    fn download_chunk(
        &self,
        zid: u32,
        coff: u32,
        read_offset: u64,
    ) -> impl Stream<Item = Result<Bytes>> + Send + 'static {
        assert_eq!(coff % Sector::SIZE, 0);
        assert_eq!(read_offset % Sector::SIZE as u64, 0);
        let cid = coff / Sector::SIZE;
        let read_offset_sec = read_offset / Sector::SIZE as u64;
        act!(self, "download({zid}, {cid}s, {read_offset_sec}s)");
        let delay = self.delay();
        let stream = self.inner.download_chunk(zid, coff, read_offset);
        async move {
            delay.await;
            stream
        }
        .flatten_stream()
    }

    fn upload_chunk(
        &self,
        zid: u32,
        coff: u32,
        data: Bytes,
    ) -> impl Future<Output = Result<()>> + Send + '_ {
        assert_eq!(coff % Sector::SIZE, 0);
        assert!([0, 1].contains(&(data.len() % Sector::SIZE as usize)));
        let cid = coff / Sector::SIZE;
        let len_sec = data.len() as u32 / Sector::SIZE;
        let finish_suffix = if data.len() & 1 != 0 { "+" } else { "" };
        act!(self, "upload({zid}, {cid}s, {len_sec}s{finish_suffix})");
        async move {
            self.delay().await;
            self.inner.upload_chunk(zid, coff, data).await
        }
    }

    fn delete_zone(&self, zid: u64) -> impl Future<Output = Result<()>> + Send + '_ {
        act!(self, "delete_zone({zid})");
        async move {
            self.delay().await;
            self.inner.delete_zone(zid).await
        }
    }

    fn delete_all_zones(&self) -> impl Future<Output = Result<()>> + Send + '_ {
        act!(self, "delete_all_zones()");
        async move {
            self.delay().await;
            self.inner.delete_all_zones().await
        }
    }
}

trait TestFrontend: BlockDevice {
    async fn test_read(&self, off: Sector, len: Sector) -> Result<Vec<u8>, Errno> {
        assert_ne!(len, Sector(0));
        let len = len.bytes() as usize;
        let mut buf = vec![0u8; len];
        let read_len = {
            let mut read_buf = ReadBuf::from_raw(&mut buf);
            self.read(off, &mut read_buf, IoFlags::empty()).await?;
            len - read_buf.remaining()
        };
        buf.truncate(read_len);
        Ok(buf)
    }

    async fn test_write_all(&self, off: Sector, buf: &mut [u8]) -> Result<(), Errno> {
        self.test_write_all_flags(off, buf, IoFlags::empty()).await
    }

    async fn test_write_all_flags(
        &self,
        off: Sector,
        buf: &mut [u8],
        flags: IoFlags,
    ) -> Result<(), Errno> {
        assert!(!buf.is_empty());
        assert_eq!(buf.len() % sec(1), 0);
        let len = buf.len();
        let buf = WriteBuf::from_raw(buf);
        let written = self.write(off, buf, flags).await?;
        assert_eq!(written, len);
        Ok(())
    }

    async fn test_zone_append_all(&self, off: Sector, buf: &mut [u8]) -> Result<Sector, Errno> {
        assert!(!buf.is_empty());
        assert_eq!(buf.len() % sec(1), 0);
        let buf = WriteBuf::from_raw(buf);
        let pos = self.zone_append(off, buf, IoFlags::empty()).await?;
        Ok(pos)
    }

    async fn test_report_zones(&self, off: Sector, zone_cnt: usize) -> Result<Vec<Zone>> {
        assert_ne!(zone_cnt, 0);
        let memfd =
            rustix::fs::memfd_create("zone-report-buf", rustix::fs::MemfdFlags::CLOEXEC).unwrap();
        let mut memfd = File::from(memfd);
        memfd
            .set_len((zone_cnt * mem::size_of::<Zone>()) as u64)
            .unwrap();
        let mut buf = ZoneBuf::from_raw(memfd.as_fd(), 0, zone_cnt as u32);
        self.report_zones(off, &mut buf, IoFlags::empty()).await?;
        let read_cnt = zone_cnt - buf.remaining();

        let mut ret = <Vec<Zone>>::with_capacity(read_cnt);
        // SAFETY: Have enough capacity.
        unsafe { ptr::write_bytes(ret.as_mut_ptr(), 0, read_cnt) };
        // SAFETY: Have enough capacity.
        let spare_buf_u8 = unsafe {
            slice::from_raw_parts_mut(
                ret.as_mut_ptr().cast::<u8>(),
                read_cnt * mem::size_of::<Zone>(),
            )
        };
        memfd.read_exact(spare_buf_u8).unwrap();
        // SAFETY: Initialized `read_cnt` elements, each of which is a valid `Zone`.
        unsafe { ret.set_len(read_cnt) };
        Ok(ret)
    }
}

impl<T: BlockDevice> TestFrontend for T {}

const NR_ZONES: usize = 4;
// 4 x 4KiB zones, min chunk 1KiB, max chunk 2KiB.
const CONFIG: Config = Config {
    dev_secs: Sector(8 * NR_ZONES as u64),
    zone_secs: Sector(8),
    min_chunk_size: 1 << 10,
    max_chunk_size: 2 << 10,
    // Workaround: `Option::unwrap` is not const stable yet.
    max_concurrent_streams: match NonZeroUsize::new(8) {
        Some(n) => n,
        None => unreachable!(),
    },
};

/// Accept `[(zid, cid, data)]`, where `cid := coff / SECTOR_SIZE`.
async fn new_dev(chunks: &[(u32, u32, Vec<u8>)]) -> Frontend<TestBackend> {
    let backend = TestBackend::new_with_chunks(NR_ZONES, chunks.iter().cloned());
    let chunk_meta = chunks
        .iter()
        .map(|(zid, cid, data)| {
            let global_off = *zid as u64 * CONFIG.zone_secs.bytes() + Sector(*cid as u64).bytes();
            (global_off, data.len() as u64)
        })
        .collect::<Vec<_>>();
    let mut dev = Frontend::new(CONFIG, backend, |_, _| Ok(())).unwrap();
    dev.init_chunks(&chunk_meta).await.unwrap();
    dev
}

pub const fn sec(n: usize) -> usize {
    Sector(n as u64).bytes() as _
}

fn zone(i: u64, rel_wp: Sector, cond: ZoneCond) -> Zone {
    Zone::new(
        CONFIG.zone_secs * i,
        CONFIG.zone_secs,
        rel_wp,
        ZoneType::SeqWriteReq,
        cond,
    )
}

#[tokio::test]
async fn report_zones() {
    let dev = new_dev(&[]).await;
    let got_zones = dev.test_report_zones(Sector(0), 8).await.unwrap();
    let expect_zones = (0..NR_ZONES as u64)
        .map(|i| zone(i, Sector(0), ZoneCond::Empty))
        .collect::<Vec<_>>();
    assert_eq!(got_zones, expect_zones);
    assert_eq!(dev.backend().drain_log(), "");
}

#[tokio::test]
async fn init_chunks() {
    let dev = new_dev(&[
        (0, 0, vec![1u8; sec(2)]),
        // Partial tail. Need download.
        (0, 2, vec![2u8; sec(1)]),
        // Manually finished.
        (1, 0, vec![3u8; sec(1) + 1]),
        // Large enough chunk.
        (2, 0, vec![4u8; sec(2)]),
        // Full of data.
        (3, 0, vec![5u8; CONFIG.zone_secs.bytes() as _]),
    ])
    .await;
    assert_eq!(dev.backend().drain_log(), "download(0, 2s, 0s);");

    let got = dev.test_report_zones(Sector(0), 4).await.unwrap();
    let expect = vec![
        zone(0, Sector(3), ZoneCond::Closed),
        zone(1, CONFIG.zone_secs, ZoneCond::Full),
        zone(2, Sector(2), ZoneCond::Closed),
        zone(3, CONFIG.zone_secs, ZoneCond::Full),
    ];
    assert_eq!(got, expect);

    let got = dev.test_read(Sector(0), CONFIG.zone_secs).await.unwrap();
    let mut expect = [0u8; CONFIG.zone_secs.bytes() as _];
    expect[..sec(2)].fill(1u8);
    expect[sec(2)..sec(3)].fill(2u8);
    assert_eq!(got, expect);
    // Only the first chunk is downloaded. The second chunk is prefetched before.
    assert_eq!(dev.backend().drain_log(), "download(0, 0s, 0s);");

    let got = dev
        .test_read(CONFIG.zone_secs, CONFIG.zone_secs)
        .await
        .unwrap();
    // NB. The finish-marker byte will be not read, thus only the first sector is non-zero.
    let mut expect = [0u8; CONFIG.zone_secs.bytes() as _];
    expect[..sec(1)].fill(3u8);
    assert_eq!(got, expect);
    assert_eq!(dev.backend().drain_log(), "download(1, 0s, 0s);");
}

#[tokio::test]
async fn read_stream_reuse() {
    let dev = new_dev(&[
        // [0, 4s)
        (0, 0, vec![1u8; sec(4)]),
        // [4, 8s)
        (0, 4, vec![1u8; sec(4)]),
    ])
    .await;
    // The first zone is full, thus no initial download.
    assert_eq!(dev.backend().drain_log(), "");

    // Read [0s, 2s), stream pos at 2s.
    let got = dev.test_read(Sector(0), Sector(2)).await.unwrap();
    let expect = [1u8; sec(2)];
    assert_eq!(got, expect);
    assert_eq!(dev.backend().drain_log(), "download(0, 0s, 0s);");

    // Read [2s, 6s), drain the first stream, and start another one.
    let got = dev.test_read(Sector(2), Sector(4)).await.unwrap();
    assert_eq!(got, [1u8; sec(4)]);
    assert_eq!(dev.backend().drain_log(), "download(0, 4s, 0s);");

    // Read [6s, 8s), drain the second one.
    let got = dev.test_read(Sector(6), Sector(2)).await.unwrap();
    assert_eq!(got, expect);
    assert_eq!(dev.backend().drain_log(), "");

    // Read [1s, 2s), start at middle.
    let got = dev.test_read(Sector(1), Sector(1)).await.unwrap();
    assert_eq!(got, [1u8; sec(1)]);
    assert_eq!(dev.backend().drain_log(), "download(0, 0s, 1s);");

    // Read [2s, 3s), reuse.
    let got = dev.test_read(Sector(2), Sector(1)).await.unwrap();
    assert_eq!(got, [1u8; sec(1)]);
    assert_eq!(dev.backend().drain_log(), "");
}

/// When reading takes some time, multiple consective reads are serialized and
/// reuse one stream.
#[tokio::test]
async fn read_stream_wait_reuse() {
    // The exact delay time does not matter. Just to ensure all ready futures are polled into
    // Pending state before responding.
    const DELAY: Duration = Duration::from_millis(100);

    let expect = [&[1u8; sec(2)][..], &[2u8; sec(2)]].concat();
    let dev = new_dev(&[
        // [0, 4s)
        (0, 0, expect.clone()),
        // [4, 8s)
        (0, 4, vec![1u8; sec(4)]),
    ])
    .await;
    // The first zone is full, thus no initial download.
    assert_eq!(dev.backend().drain_log(), "");

    *dev.backend().delay.lock() = DELAY;

    // Read [0s, 2s) and [2s, 4s) concurrently, while polling them in order.
    let (got1, got2) = tokio::join!(
        dev.test_read(Sector(0), Sector(2)),
        dev.test_read(Sector(2), Sector(2)),
    );
    let (expect1, expect2) = expect.split_at(expect.len() / 2);
    assert_eq!(got1.unwrap(), expect1);
    assert_eq!(got2.unwrap(), expect2);

    // Only downloads once.
    assert_eq!(dev.backend().drain_log(), "download(0, 0s, 0s);");
}

#[tokio::test]
async fn zone_open_close() {
    let dev = new_dev(&[
        (0, 0, vec![1u8; sec(1)]), // With tail.
        (2, 0, vec![2u8; sec(2)]), // Without tail.
    ])
    .await;
    assert_eq!(dev.backend().drain_log(), "download(0, 0s, 0s);");

    let got = dev.test_report_zones(Sector(0), 4).await.unwrap();
    let expect_init = vec![
        zone(0, Sector(1), ZoneCond::Closed),
        zone(1, Sector(0), ZoneCond::Empty),
        zone(2, Sector(2), ZoneCond::Closed),
        zone(3, Sector(0), ZoneCond::Empty),
    ];
    assert_eq!(got, expect_init);

    // ZONE_OPEN and ZONE_CLOSE are idempotent.
    let open_offsets = [Sector(0), CONFIG.zone_secs].repeat(2);

    for &off in &open_offsets {
        dev.zone_open(off, IoFlags::empty()).await.unwrap();
    }

    let got = dev.test_report_zones(Sector(0), 4).await.unwrap();
    let expect_opened = vec![
        zone(0, Sector(1), ZoneCond::ExpOpen),
        zone(1, Sector(0), ZoneCond::ExpOpen),
        zone(2, Sector(2), ZoneCond::Closed),
        zone(3, Sector(0), ZoneCond::Empty),
    ];
    assert_eq!(got, expect_opened);

    for &off in &open_offsets {
        dev.zone_close(off, IoFlags::empty()).await.unwrap();
    }

    let got = dev.test_report_zones(Sector(0), 4).await.unwrap();
    assert_eq!(got, expect_init);

    assert_eq!(dev.backend().drain_log(), "");
}

#[tokio::test]
async fn reset_zone() {
    let dev = new_dev(&[
        (0, 0, vec![1u8; sec(1)]), // With tail.
        (2, 0, vec![2u8; sec(2)]), // Without tail.
    ])
    .await;
    assert_eq!(dev.backend().drain_log(), "download(0, 0s, 0s);");

    for off in [Sector(0), CONFIG.zone_secs] {
        dev.zone_open(off, IoFlags::empty()).await.unwrap();
    }

    let got = dev.test_report_zones(Sector(0), 4).await.unwrap();
    let expect = vec![
        zone(0, Sector(1), ZoneCond::ExpOpen),
        zone(1, Sector(0), ZoneCond::ExpOpen),
        zone(2, Sector(2), ZoneCond::Closed),
        zone(3, Sector(0), ZoneCond::Empty),
    ];
    assert_eq!(got, expect);

    for i in 0..4 {
        dev.zone_reset(CONFIG.zone_secs * i, IoFlags::empty())
            .await
            .unwrap();
    }

    let got = dev.test_report_zones(Sector(0), 4).await.unwrap();
    let expect = vec![
        zone(0, Sector(0), ZoneCond::Empty),
        zone(1, Sector(0), ZoneCond::Empty),
        zone(2, Sector(0), ZoneCond::Empty),
        zone(3, Sector(0), ZoneCond::Empty),
    ];
    assert_eq!(got, expect);

    // Only non-empty zones are committed to backend.
    assert_eq!(dev.backend().drain_log(), "delete_zone(0);delete_zone(2);");
}

#[tokio::test]
async fn reset_all_zone() {
    let dev = new_dev(&[
        (0, 0, vec![1u8; sec(1)]),     // With tail.
        (2, 0, vec![2u8; sec(1) + 1]), // Full.
    ])
    .await;
    assert_eq!(dev.backend().drain_log(), "download(0, 0s, 0s);");

    dev.zone_reset_all(IoFlags::empty()).await.unwrap();
    let got = dev.test_report_zones(Sector(0), 4).await.unwrap();
    let expect = vec![
        zone(0, Sector(0), ZoneCond::Empty),
        zone(1, Sector(0), ZoneCond::Empty),
        zone(2, Sector(0), ZoneCond::Empty),
        zone(3, Sector(0), ZoneCond::Empty),
    ];
    assert_eq!(got, expect);
    assert_eq!(dev.backend().drain_log(), "delete_all_zones();");
}

#[tokio::test]
async fn bufferred_read_write() {
    let dev = new_dev(&[]).await;

    let got = dev.test_read(Sector(0), CONFIG.zone_secs).await.unwrap();
    let mut expect = [0u8; CONFIG.zone_secs.bytes() as usize];
    assert_eq!(got, expect);

    dev.test_write_all(Sector(0), &mut [42u8; sec(1)])
        .await
        .unwrap();
    let got = dev.test_read(Sector(0), CONFIG.zone_secs).await.unwrap();
    expect[..sec(1)].fill(42u8);
    assert_eq!(got, expect);
    assert_eq!(
        dev.test_report_zones(Sector(0), 1).await.unwrap()[0],
        zone(0, Sector(1), ZoneCond::ImpOpen),
    );

    // No commit before `FLUSH`.
    assert_eq!(dev.backend().drain_log(), "");

    dev.flush(IoFlags::empty()).await.unwrap();
    assert_eq!(dev.backend().drain_log(), "upload(0, 0s, 1s);");

    // `FLUSH` is idempotent and does no redundant work.
    dev.flush(IoFlags::empty()).await.unwrap();
    assert_eq!(dev.backend().drain_log(), "");
}

#[tokio::test]
async fn write_fua() {
    let dev = new_dev(&[]).await;

    let mut expect = [1u8; sec(2)];
    expect[sec(1)..].fill(2u8);

    dev.test_write_all_flags(Sector(0), &mut [1u8; sec(1)], IoFlags::Fua)
        .await
        .unwrap();
    // Should commit it inline.
    assert_eq!(dev.backend().drain_log(), "upload(0, 0s, 1s);");
    let got = dev.test_read(Sector(0), Sector(1)).await.unwrap();
    assert_eq!(got, expect[..expect.len() / 2]);

    // No action on FLUSH.
    assert_eq!(dev.backend().drain_log(), "");

    dev.test_write_all_flags(Sector(1), &mut [2u8; sec(1)], IoFlags::Fua)
        .await
        .unwrap();
    // Also commit inline and replace the chunk.
    assert_eq!(dev.backend().drain_log(), "upload(0, 0s, 2s);");
    let got = dev.test_read(Sector(0), Sector(2)).await.unwrap();
    assert_eq!(got, expect);

    // No action on FLUSH.
    dev.flush(IoFlags::empty()).await.unwrap();
    assert_eq!(dev.backend().drain_log(), "");
}

#[tokio::test]
async fn read_tail() {
    let dev = new_dev(&[]).await;

    let mut buf = [1u8; sec(2)];
    buf[sec(1)..].fill(2u8);

    // Delayed tail.
    dev.test_write_all(Sector(0), &mut buf).await.unwrap();
    assert_eq!(dev.backend().drain_log(), "");

    assert_eq!(
        dev.test_read(Sector(0), Sector(1)).await.unwrap(),
        [1u8; sec(1)],
    );
    assert_eq!(
        dev.test_read(Sector(1), Sector(1)).await.unwrap(),
        [2u8; sec(1)],
    );
    assert_eq!(
        dev.test_read(Sector(2), Sector(1)).await.unwrap(),
        [0u8; sec(1)],
    );

    assert_eq!(
        dev.test_read(Sector(0), Sector(3)).await.unwrap(),
        [&buf[..], &[0u8; sec(1)]].concat(),
    );

    // Read from cache.
    assert_eq!(dev.backend().drain_log(), "");
}

#[tokio::test]
async fn reset_discard_buffer() {
    let dev = new_dev(&[]).await;

    dev.test_write_all(Sector(0), &mut [42u8; sec(1)])
        .await
        .unwrap();
    dev.zone_reset(Sector(0), IoFlags::empty()).await.unwrap();
    dev.flush(IoFlags::empty()).await.unwrap();
    assert_eq!(dev.backend().drain_log(), "delete_zone(0);");

    let got = dev.test_read(Sector(0), CONFIG.zone_secs).await.unwrap();
    assert_eq!(got, [0u8; CONFIG.zone_secs.bytes() as _]);

    dev.test_write_all(Sector(0), &mut [42u8; sec(1)])
        .await
        .unwrap();
    dev.zone_reset_all(IoFlags::empty()).await.unwrap();
    dev.flush(IoFlags::empty()).await.unwrap();
    assert_eq!(dev.backend().drain_log(), "delete_all_zones();");
}

#[tokio::test]
async fn inline_commit() {
    let dev = new_dev(&[]).await;
    let mut off = Sector(0);

    // Immediate inline commit.
    let mut data1 = [3u8; CONFIG.max_chunk_size];
    dev.test_write_all(off, &mut data1).await.unwrap();
    off += Sector::from_bytes(data1.len() as _);
    assert_eq!(dev.backend().drain_log(), "upload(0, 0s, 4s);");
    assert_eq!(
        dev.test_report_zones(Sector(0), 1).await.unwrap()[0],
        zone(0, Sector(4), ZoneCond::ImpOpen),
    );

    // No effect. Chunks are already committed,
    dev.flush(IoFlags::empty()).await.unwrap();
    assert_eq!(dev.backend().drain_log(), "");

    // Buffered.
    let mut data2 = [1u8; sec(1)];
    dev.test_write_all(off, &mut data2).await.unwrap();
    off += Sector::from_bytes(data2.len() as _);
    assert_eq!(dev.backend().drain_log(), "");

    // Append until full, thus trigger another inline commit.
    let mut data3 = vec![2u8; (CONFIG.zone_secs - off).bytes() as _];
    dev.test_write_all(off, &mut data3).await.unwrap();
    off += Sector::from_bytes(data3.len() as _);
    assert_eq!(dev.backend().drain_log(), "upload(0, 4s, 4s);");
    assert_eq!(
        dev.test_report_zones(Sector(0), 1).await.unwrap()[0],
        zone(0, Sector(8), ZoneCond::Full),
    );

    // Validate written data.
    let got = dev.test_read(Sector(0), CONFIG.zone_secs).await.unwrap();
    let expect = [&data1[..], &data2, &data3].concat();
    assert_eq!(got, expect);
}

#[tokio::test]
async fn zone_append() {
    let dev = new_dev(&[]).await;

    let off = Sector(0);
    let mut data1 = [1u8; sec(2)];
    let pos1 = dev.test_zone_append_all(off, &mut data1).await.unwrap();
    assert_eq!(pos1, Sector(0));

    let mut data2 = [2u8; sec(1)];
    let pos2 = dev.test_zone_append_all(off, &mut data2).await.unwrap();
    assert_eq!(pos2, Sector(2));

    assert_eq!(
        dev.test_report_zones(Sector(0), 1).await.unwrap()[0],
        zone(0, Sector(3), ZoneCond::ImpOpen),
    );
}

#[tokio::test]
async fn zone_finish() {
    let dev = new_dev(&[]).await;

    dev.zone_finish(Sector(0), IoFlags::empty()).await.unwrap();
    assert_eq!(dev.backend().drain_log(), "upload(0, 0s, 0s+);");
    assert_eq!(
        dev.test_report_zones(Sector(0), 1).await.unwrap()[0],
        zone(0, CONFIG.zone_secs, ZoneCond::Full),
    );

    let off = CONFIG.zone_secs;
    dev.test_write_all(off, &mut [0u8; sec(1)]).await.unwrap();
    dev.zone_finish(off, IoFlags::empty()).await.unwrap();
    assert_eq!(dev.backend().drain_log(), "upload(1, 0s, 1s+);");
    assert_eq!(
        dev.test_report_zones(off, 1).await.unwrap()[0],
        zone(1, CONFIG.zone_secs, ZoneCond::Full),
    );
}

#[tokio::test]
async fn replace_tail() {
    let dev = new_dev(&[]).await;

    let mut data = [1u8; sec(2)];
    let (lhs, rhs) = data.split_at_mut(sec(1));
    rhs.fill(2u8);

    dev.test_zone_append_all(Sector(0), lhs).await.unwrap();
    dev.flush(IoFlags::empty()).await.unwrap();
    assert_eq!(dev.backend().drain_log(), "upload(0, 0s, 1s);");

    // Should replace the first chunk.
    dev.test_zone_append_all(Sector(0), rhs).await.unwrap();
    dev.flush(IoFlags::empty()).await.unwrap();
    assert_eq!(dev.backend().drain_log(), "upload(0, 0s, 2s);");

    let got = dev.test_read(Sector(0), Sector(2)).await.unwrap();
    assert_eq!(got, data);
    assert_eq!(dev.backend().drain_log(), "download(0, 0s, 0s);");

    // Idempotent.
    dev.flush(IoFlags::empty()).await.unwrap();
    assert_eq!(dev.backend().drain_log(), "");

    // Previous chunk size is over min_chunk_size (1KiB), so this creates a new one.
    dev.test_zone_append_all(Sector(0), &mut [3u8; sec(1)])
        .await
        .unwrap();
    dev.flush(IoFlags::empty()).await.unwrap();
    assert_eq!(dev.backend().drain_log(), "upload(0, 2s, 1s);");
}
