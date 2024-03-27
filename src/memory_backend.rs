use std::collections::HashMap;
use std::fmt;
use std::future::{ready, Future};

use anyhow::{anyhow, Result};
use bytes::Bytes;
use futures_util::{stream, Stream};
use parking_lot::RwLock;
use serde::Deserialize;

use crate::service::Backend;

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Config {}

pub struct Memory {
    pub(crate) zones: Box<[RwLock<HashMap<u32, Bytes>>]>,
}

impl fmt::Debug for Memory {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        struct ZonesDebug<'a>(&'a [RwLock<HashMap<u32, Bytes>>]);

        impl fmt::Debug for ZonesDebug<'_> {
            fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
                let mut map = f.debug_map();
                map.entries(self.0.iter().enumerate().map(|(zid, chunks)| {
                    let mut ranges = chunks
                        .read()
                        .iter()
                        .map(|(&coff, data)| coff..(coff + data.len() as u32))
                        .collect::<Vec<_>>();
                    ranges.sort_unstable_by_key(|range| range.start);
                    (zid, ranges)
                }));
                map.finish()
            }
        }

        f.debug_struct("Memory")
            .field("zones", &ZonesDebug(&self.zones))
            .finish()
    }
}

impl Memory {
    #[must_use]
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
    ) -> impl Stream<Item = Result<Bytes>> + Send + 'static {
        let ret = match self.zones[zid as usize].read().get(&coff) {
            Some(data) => Ok(data.slice(read_offset as usize..)),
            None => Err(anyhow!("chunk not found: zid={zid} coff={coff}")),
        };
        stream::iter(Some(ret))
    }

    fn upload_chunk(
        &self,
        zid: u32,
        coff: u32,
        data: Bytes,
    ) -> impl Future<Output = Result<()>> + Send + '_ {
        self.zones[zid as usize].write().insert(coff, data);
        ready(Ok(()))
    }

    fn delete_zone(&self, zid: u64) -> impl Future<Output = Result<()>> + Send + '_ {
        self.zones[zid as usize].write().clear();
        ready(Ok(()))
    }

    fn delete_all_zones(&self) -> impl Future<Output = Result<()>> + Send + '_ {
        for zone in self.zones.iter() {
            zone.write().clear();
        }
        ready(Ok(()))
    }
}
