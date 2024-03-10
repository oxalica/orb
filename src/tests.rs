use std::collections::BTreeMap;
use std::fmt::Write;
use std::fs::File;
use std::future::{ready, Future};
use std::io::Read;
use std::{mem, ptr, slice};

use anyhow::Result;
use bytes::Bytes;
use orb_ublk::{
    BlockDevice, IoFlags, ReadBuf, Sector, WriteBuf, Zone, ZoneBuf, ZoneCond, ZoneType,
};
use parking_lot::Mutex;
use rustix::fd::AsFd;
use rustix::io::Errno;

use crate::service::{Backend, Config, Frontend};

#[derive(Debug)]
pub struct TestBackend {
    chunks: Mutex<Vec<BTreeMap<u32, Bytes>>>,
    log: Mutex<String>,
}

impl TestBackend {
    pub fn new_empty(nr_zones: usize) -> Self {
        Self {
            chunks: vec![BTreeMap::new(); nr_zones].into(),
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
            let prev = this.chunks.get_mut()[zid].insert(coff, data.into());
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
        len: usize,
    ) -> impl Future<Output = Result<Bytes>> + Send + 'static {
        let data = self.chunks.lock()[zid as usize][&coff].clone();
        let data = data.slice(read_offset as usize..).slice(..len);
        act!(self, "download({zid}, {coff}, {read_offset}, {len})");
        ready(Ok(data))
    }

    fn upload_chunk(
        &self,
        zid: u32,
        coff: u32,
        data: Bytes,
    ) -> impl Future<Output = Result<()>> + Send + 'static {
        let len = data.len();
        self.chunks.lock()[zid as usize].insert(coff, data);
        act!(self, "upload({zid}, {coff}, {len})");
        ready(Ok(()))
    }

    fn delete_zone(&self, zid: u64) -> impl Future<Output = Result<()>> + Send + 'static {
        self.chunks.lock()[zid as usize].clear();
        act!(self, "delete_zone({zid})");
        ready(Ok(()))
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
};

fn new_dev(chunks: &[(usize, u32, Vec<u8>)]) -> Frontend<TestBackend> {
    let backend = TestBackend::new_with_chunks(NR_ZONES, chunks.iter().cloned());
    let chunk_meta = chunks
        .iter()
        .map(|(zid, coff, data)| {
            let global_off = *zid as u64 * CONFIG.zone_secs.bytes() + *coff as u64;
            (global_off, data.len() as u32)
        })
        .collect::<Vec<_>>();
    Frontend::new(CONFIG, &chunk_meta, backend).unwrap()
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
    let dev = new_dev(&[]);
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
        (0, 1024, vec![2u8; 512]),
        (1, 0, vec![3u8; 512 + 1]),
    ]);

    let got = dev.test_read(Sector(0), CONFIG.zone_secs).await.unwrap();
    let expect = [&[1u8; 1024][..], &[2u8; 512], &[0u8; 4096 - 1024 - 512]].concat();
    assert_eq!(got, expect);
    assert_eq!(
        dev.backend().drain_log(),
        "download(0, 0, 0, 1024);download(0, 1024, 0, 512);"
    );

    let got = dev
        .test_read(CONFIG.zone_secs, CONFIG.zone_secs)
        .await
        .unwrap();
    // NB. The finish-marker byte will be not read, thus only first 512bytes are non-zero.
    let expect = [&[3u8; 512][..], &[0u8; 4096 - 512]].concat();
    assert_eq!(got, expect);
    assert_eq!(dev.backend().drain_log(), "download(1, 0, 0, 512);");

    let got = dev.test_report_zones(Sector(0), 3).await.unwrap();
    let expect = vec![
        zone(0, Sector(3), ZoneCond::Closed),
        zone(1, CONFIG.zone_secs, ZoneCond::Full),
        zone(2, Sector(0), ZoneCond::Empty),
    ];
    assert_eq!(got, expect);
}
