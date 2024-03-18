use std::fmt::Write;
use std::fs::File;
use std::future::Future;
use std::io::Read;
use std::num::NonZeroUsize;
use std::{mem, ptr, slice};

use anyhow::Result;
use bytes::Bytes;
use futures_util::Stream;
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
}

impl TestBackend {
    pub fn new_empty(zone_cnt: usize) -> Self {
        Self {
            inner: Memory::new(zone_cnt),
            log: Mutex::default(),
        }
    }

    #[track_caller]
    pub fn new_with_chunks(
        nr_zones: usize,
        chunks: impl IntoIterator<Item = (usize, u32, Vec<u8>)>,
    ) -> Self {
        let mut this = Self::new_empty(nr_zones);
        for (zid, coff, data) in chunks {
            let prev = this.inner.zones[zid].get_mut().insert(coff, data.into());
            assert!(prev.is_none());
        }
        this
    }

    pub fn drain_log(&self) -> String {
        mem::take(&mut self.log.lock())
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
        act!(self, "download({zid}, {coff}, {read_offset})");
        self.inner.download_chunk(zid, coff, read_offset)
    }

    fn upload_chunk(
        &self,
        zid: u32,
        coff: u32,
        data: Bytes,
    ) -> impl Future<Output = Result<()>> + Send + '_ {
        act!(self, "upload({zid}, {coff}, {})", data.len());
        self.inner.upload_chunk(zid, coff, data)
    }

    fn delete_zone(&self, zid: u64) -> impl Future<Output = Result<()>> + Send + '_ {
        act!(self, "delete_zone({zid})");
        self.inner.delete_zone(zid)
    }

    fn delete_all_zones(&self) -> impl Future<Output = Result<()>> + Send + '_ {
        act!(self, "delete_all_zones()");
        self.inner.delete_all_zones()
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
        assert!(!buf.is_empty());
        assert_eq!(buf.len() % Sector::SIZE as usize, 0);
        let len = buf.len();
        let buf = WriteBuf::from_raw(buf);
        let written = self.write(off, buf, IoFlags::empty()).await?;
        assert_eq!(written, len);
        Ok(())
    }

    async fn test_zone_append_all(&self, off: Sector, buf: &mut [u8]) -> Result<Sector, Errno> {
        assert!(!buf.is_empty());
        assert_eq!(buf.len() % Sector::SIZE as usize, 0);
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

async fn new_dev(chunks: &[(usize, u32, Vec<u8>)]) -> Frontend<TestBackend> {
    let backend = TestBackend::new_with_chunks(NR_ZONES, chunks.iter().cloned());
    let chunk_meta = chunks
        .iter()
        .map(|(zid, coff, data)| {
            let global_off = *zid as u64 * CONFIG.zone_secs.bytes() + *coff as u64;
            (global_off, data.len() as u64)
        })
        .collect::<Vec<_>>();
    let mut dev = Frontend::new(CONFIG, backend, |_, _| Ok(())).unwrap();
    dev.init_chunks(&chunk_meta).await.unwrap();
    dev
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
        (0, 0, vec![1u8; 1024]),
        // Partial tail. Need download.
        (0, 1024, vec![2u8; 512]),
        // Manually finished.
        (1, 0, vec![3u8; 512 + 1]),
        // Large enough chunk.
        (2, 0, vec![4u8; 1024]),
        // Full of data.
        (3, 0, vec![5u8; CONFIG.zone_secs.bytes() as _]),
    ])
    .await;
    assert_eq!(dev.backend().drain_log(), "download(0, 1024, 0);");

    let got = dev.test_report_zones(Sector(0), 4).await.unwrap();
    let expect = vec![
        zone(0, Sector(3), ZoneCond::Closed),
        zone(1, CONFIG.zone_secs, ZoneCond::Full),
        zone(2, Sector(2), ZoneCond::Closed),
        zone(3, CONFIG.zone_secs, ZoneCond::Full),
    ];
    assert_eq!(got, expect);

    let got = dev.test_read(Sector(0), CONFIG.zone_secs).await.unwrap();
    let expect = [&[1u8; 1024][..], &[2u8; 512], &[0u8; 4096 - 1024 - 512]].concat();
    assert_eq!(got, expect);
    // Only the first chunk is downloaded. The second chunk is prefetched before.
    assert_eq!(dev.backend().drain_log(), "download(0, 0, 0);");

    let got = dev
        .test_read(CONFIG.zone_secs, CONFIG.zone_secs)
        .await
        .unwrap();
    // NB. The finish-marker byte will be not read, thus only first 512bytes are non-zero.
    let expect = [&[3u8; 512][..], &[0u8; 4096 - 512]].concat();
    assert_eq!(got, expect);
    assert_eq!(dev.backend().drain_log(), "download(1, 0, 0);");
}

#[tokio::test]
async fn read_stream_reuse() {
    let dev = new_dev(&[
        // [0, 4s)
        (0, 0, vec![1u8; Sector(4).bytes() as _]),
        // [4, 8s)
        (0, 2048, vec![1u8; Sector(4).bytes() as usize]),
    ])
    .await;
    // The first zone is full, thus no initial download.
    assert_eq!(dev.backend().drain_log(), "");

    // Read [0s, 1s), stream pos at 2s.
    let got = dev.test_read(Sector(0), Sector(2)).await.unwrap();
    let expect = [1u8; Sector(2).bytes() as _];
    assert_eq!(got, expect);
    assert_eq!(dev.backend().drain_log(), "download(0, 0, 0);");

    // Read [2s, 6s), drain the first stream, and start another one.
    let got = dev.test_read(Sector(2), Sector(4)).await.unwrap();
    assert_eq!(got, [1u8; Sector(4).bytes() as _]);
    assert_eq!(dev.backend().drain_log(), "download(0, 2048, 0);");

    // Read [6s, 8s), drain the second one.
    let got = dev.test_read(Sector(6), Sector(2)).await.unwrap();
    assert_eq!(got, expect);
    assert_eq!(dev.backend().drain_log(), "");

    // Read [1s, 2s), start at middle.
    let got = dev.test_read(Sector(1), Sector(1)).await.unwrap();
    assert_eq!(got, [1u8; Sector(1).bytes() as _]);
    assert_eq!(dev.backend().drain_log(), "download(0, 0, 512);");

    // Read [2s, 3s), reuse.
    let got = dev.test_read(Sector(2), Sector(1)).await.unwrap();
    assert_eq!(got, [1u8; Sector(1).bytes() as _]);
    assert_eq!(dev.backend().drain_log(), "");
}

#[tokio::test]
async fn zone_open_close() {
    let dev = new_dev(&[
        (0, 0, vec![1u8; 512]),  // With tail.
        (2, 0, vec![2u8; 1024]), // Without tail.
    ])
    .await;
    assert_eq!(dev.backend().drain_log(), "download(0, 0, 0);");

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
        (0, 0, vec![1u8; 512]),  // With tail.
        (2, 0, vec![2u8; 1024]), // Without tail.
    ])
    .await;
    assert_eq!(dev.backend().drain_log(), "download(0, 0, 0);");

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
        (0, 0, vec![1u8; 512]),     // With tail.
        (2, 0, vec![2u8; 512 + 1]), // Full.
    ])
    .await;
    assert_eq!(dev.backend().drain_log(), "download(0, 0, 0);");

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

    dev.test_write_all(Sector(0), &mut [42u8; Sector::SIZE as usize])
        .await
        .unwrap();
    let got = dev.test_read(Sector(0), CONFIG.zone_secs).await.unwrap();
    expect[..Sector::SIZE as usize].fill(42u8);
    assert_eq!(got, expect);
    assert_eq!(
        dev.test_report_zones(Sector(0), 1).await.unwrap()[0],
        zone(0, Sector(1), ZoneCond::ImpOpen),
    );

    // No commit before `FLUSH`.
    assert_eq!(dev.backend().drain_log(), "");

    dev.flush(IoFlags::empty()).await.unwrap();
    assert_eq!(dev.backend().drain_log(), "upload(0, 0, 512);");

    // `FLUSH` is idempotent and does no redundant work.
    dev.flush(IoFlags::empty()).await.unwrap();
    assert_eq!(dev.backend().drain_log(), "");
}

#[tokio::test]
async fn read_tail() {
    let dev = new_dev(&[]).await;

    let mut buf = [1u8; Sector(2).bytes() as _];
    buf[Sector(1).bytes() as _..].fill(2u8);

    // Delayed tail.
    dev.test_write_all(Sector(0), &mut buf).await.unwrap();
    assert_eq!(dev.backend().drain_log(), "");

    assert_eq!(
        dev.test_read(Sector(0), Sector(1)).await.unwrap(),
        [1u8; Sector(1).bytes() as _],
    );
    assert_eq!(
        dev.test_read(Sector(1), Sector(1)).await.unwrap(),
        [2u8; Sector(1).bytes() as _],
    );
    assert_eq!(
        dev.test_read(Sector(2), Sector(1)).await.unwrap(),
        [0u8; Sector(1).bytes() as _],
    );

    assert_eq!(
        dev.test_read(Sector(0), Sector(3)).await.unwrap(),
        [&buf[..], &[0u8; Sector(1).bytes() as _]].concat(),
    );

    // Read from cache.
    assert_eq!(dev.backend().drain_log(), "");
}

#[tokio::test]
async fn reset_discard_buffer() {
    let dev = new_dev(&[]).await;

    dev.test_write_all(Sector(0), &mut [42u8; Sector(1).bytes() as _])
        .await
        .unwrap();
    dev.zone_reset(Sector(0), IoFlags::empty()).await.unwrap();
    dev.flush(IoFlags::empty()).await.unwrap();
    assert_eq!(dev.backend().drain_log(), "delete_zone(0);");

    let got = dev.test_read(Sector(0), CONFIG.zone_secs).await.unwrap();
    assert_eq!(got, [0u8; CONFIG.zone_secs.bytes() as _]);

    dev.test_write_all(Sector(0), &mut [42u8; Sector(1).bytes() as _])
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
    assert_eq!(dev.backend().drain_log(), "upload(0, 0, 2048);");
    assert_eq!(
        dev.test_report_zones(Sector(0), 1).await.unwrap()[0],
        zone(0, Sector(4), ZoneCond::ImpOpen),
    );

    // No effect. Chunks are already committed,
    dev.flush(IoFlags::empty()).await.unwrap();
    assert_eq!(dev.backend().drain_log(), "");

    // Buffered.
    let mut data2 = [1u8; Sector::SIZE as usize];
    dev.test_write_all(off, &mut data2).await.unwrap();
    off += Sector::from_bytes(data2.len() as _);
    assert_eq!(dev.backend().drain_log(), "");

    // Append until full, thus trigger another inline commit.
    let mut data3 = vec![2u8; (CONFIG.zone_secs - off).bytes() as _];
    dev.test_write_all(off, &mut data3).await.unwrap();
    off += Sector::from_bytes(data3.len() as _);
    assert_eq!(dev.backend().drain_log(), "upload(0, 2048, 2048);");
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
    let mut data1 = [1u8; Sector(2).bytes() as _];
    let pos1 = dev.test_zone_append_all(off, &mut data1).await.unwrap();
    assert_eq!(pos1, Sector(0));

    let mut data2 = [2u8; Sector(1).bytes() as _];
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
    assert_eq!(dev.backend().drain_log(), "upload(0, 0, 1);");
    assert_eq!(
        dev.test_report_zones(Sector(0), 1).await.unwrap()[0],
        zone(0, CONFIG.zone_secs, ZoneCond::Full),
    );

    let off = CONFIG.zone_secs;
    dev.test_write_all(off, &mut [0u8; Sector(1).bytes() as _])
        .await
        .unwrap();
    dev.zone_finish(off, IoFlags::empty()).await.unwrap();
    assert_eq!(dev.backend().drain_log(), "upload(1, 0, 513);");
    assert_eq!(
        dev.test_report_zones(off, 1).await.unwrap()[0],
        zone(1, CONFIG.zone_secs, ZoneCond::Full),
    );
}

#[tokio::test]
async fn replace_tail() {
    let dev = new_dev(&[]).await;

    let mut data = [1u8; Sector(2).bytes() as _];
    let (lhs, rhs) = data.split_at_mut(Sector(1).bytes() as _);
    rhs.fill(2u8);

    dev.test_zone_append_all(Sector(0), lhs).await.unwrap();
    dev.flush(IoFlags::empty()).await.unwrap();
    assert_eq!(dev.backend().drain_log(), "upload(0, 0, 512);");

    // Should replace the first chunk.
    dev.test_zone_append_all(Sector(0), rhs).await.unwrap();
    dev.flush(IoFlags::empty()).await.unwrap();
    assert_eq!(dev.backend().drain_log(), "upload(0, 0, 1024);");

    let got = dev.test_read(Sector(0), Sector(2)).await.unwrap();
    assert_eq!(got, data);
    assert_eq!(dev.backend().drain_log(), "download(0, 0, 0);");

    // Idempotent.
    dev.flush(IoFlags::empty()).await.unwrap();
    assert_eq!(dev.backend().drain_log(), "");

    // Previous chunk size is over min_chunk_size (1KiB), so this creates a new one.
    dev.test_zone_append_all(Sector(0), &mut [3u8; Sector(1).bytes() as _])
        .await
        .unwrap();
    dev.flush(IoFlags::empty()).await.unwrap();
    assert_eq!(dev.backend().drain_log(), "upload(0, 1024, 512);");
}
