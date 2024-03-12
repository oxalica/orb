use std::collections::HashMap;
use std::future::{ready, Future};

use anyhow::{anyhow, Result};
use bytes::Bytes;
use parking_lot::RwLock;

use crate::service::Backend;

#[derive(Debug)]
pub struct Memory {
    pub(crate) zones: Box<[RwLock<HashMap<u32, Bytes>>]>,
}

impl Memory {
    pub fn new(zone_cnt: usize) -> Self {
        let zones = (0..zone_cnt).map(|_| RwLock::new(HashMap::new())).collect();
        Self { zones }
    }
}

impl Backend for Memory {
    fn download_chunk(
        &self,
        zid: u32,
        coff: u32,
        read_offset: u64,
        len: usize,
    ) -> impl Future<Output = Result<Bytes>> + Send + 'static {
        let ret = match self.zones[zid as usize].read().get(&coff) {
            Some(data) => {
                let start = read_offset as usize;
                let end = start + len;
                Ok(data.slice(start..end))
            }
            None => Err(anyhow!("chunk not found: zid={zid} coff={coff}")),
        };
        ready(ret)
    }

    fn upload_chunk(
        &self,
        zid: u32,
        coff: u32,
        data: Bytes,
    ) -> impl Future<Output = Result<()>> + Send + 'static {
        self.zones[zid as usize].write().insert(coff, data);
        ready(Ok(()))
    }

    fn delete_zone(&self, zid: u64) -> impl Future<Output = Result<()>> + Send + 'static {
        self.zones[zid as usize].write().clear();
        ready(Ok(()))
    }

    fn delete_all_zones(&self) -> impl Future<Output = Result<()>> + Send + 'static {
        for zone in self.zones.iter() {
            zone.write().clear();
        }
        ready(Ok(()))
    }
}
