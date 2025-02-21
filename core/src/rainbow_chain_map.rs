use std::iter;

use crate::{error::CugparckResult, rainbow_table::RainbowChain, CompressedPassword};
use serde::{Deserialize, Serialize};

/// Defines how full the map is.
const LOAD_FACTOR: f64 = 0.7;

/// An HashMap implementation specifically tailored for rainbow chains.
/// I initially wrongfully thought that HashMap insertion was the cause of the slowdown,
/// but it turned out it was disk swapping that was the bottleneck.
///
/// Nevertheless, this implementation is still faster than the standard HashMap because:
/// - We can use (u64::MAX, u64::MAX) as a niche for empy entries
/// - We can use endpoints directly as the hash as it is evenly distributed
/// - We can use linear probing instead of rehasing because endpoints are randomly distributed inside batches.
///
/// This happens to be almost exactly the HashMap implementation described in "Precomputation for Rainbow Tables has Never Been so Fast." Section 5.2.
#[derive(Serialize, Deserialize)]
pub struct RainbowChainMap {
    inner: Vec<RainbowChain>,
    len: usize,
    cap: usize,
}

impl RainbowChainMap {
    pub fn with_startpoints(m0: u64) -> CugparckResult<Self> {
        dbg!("let it be ", m0);
        let mut inner = Vec::new();
        let cap = (m0 as f64 / LOAD_FACTOR) as usize;
        inner.try_reserve_exact(cap)?;
        inner.extend((0..m0).map(|i| RainbowChain {
            startpoint: i,
            endpoint: i,
        }));
        inner.extend(iter::repeat_n(RainbowChain::VACANT, cap - m0 as usize));
        Ok(Self {
            inner,
            len: m0 as usize,
            cap,
        })
    }

    pub fn new(m0: u64) -> CugparckResult<Self> {
        let mut inner = Vec::new();
        let cap = (m0 as f64 / LOAD_FACTOR) as usize;
        inner.try_reserve_exact(cap)?;
        inner.extend(iter::repeat_n(RainbowChain::VACANT, cap));
        Ok(Self { inner, len: 0, cap })
    }

    pub fn clear(&mut self) {
        self.inner.fill(RainbowChain::VACANT);
        self.len = 0;
    }

    #[inline]
    pub fn insert(&mut self, chain: RainbowChain) {
        // let mut index = chain.endpoint as usize % self.cap;
        let mut index = chain.endpoint as usize % self.cap;

        // loop until we find a vacant entry for insertion
        loop {
            let entry = self.inner[index];

            // vacant entry, insert here
            if entry == RainbowChain::VACANT {
                self.inner[index] = chain;
                break;
            }

            // chain collision, discard this chain
            if entry.endpoint == chain.endpoint {
                break;
            }

            // hash collision, try to insert in the next entry
            index = (index + 1) % self.cap;
        }

        self.len += index;
    }

    /// Returns the startpoint associated to an endpoint, if it exists.
    pub fn get(&self, endpoint: CompressedPassword) -> Option<CompressedPassword> {
        let mut index = endpoint as usize % self.cap;

        // Loop until we either find the specified value, or a vacant entry.
        // With our load factor, we should only loop 3 times on average.
        loop {
            let entry = self.inner[index];

            // chain collision, discard this chain
            if entry.endpoint == endpoint {
                return Some(entry.startpoint);
            }

            if entry == RainbowChain::VACANT {
                return None;
            }

            // hash collision, try to get the next entry
            index = (index + 1) % self.cap;
        }
    }

    pub fn len(&self) -> usize {
        self.len
    }
}

impl FromIterator<(u64, u64)> for RainbowChainMap {
    fn from_iter<T: IntoIterator<Item = (u64, u64)>>(iter: T) -> Self {
        let iter = iter.into_iter();
        let len = iter.size_hint().1.unwrap();

        let mut inner = Vec::new();
        let cap = (len as f64 / LOAD_FACTOR) as usize;
        inner.try_reserve_exact(cap).unwrap();
        inner.extend(iter.map(|(startpoint, endpoint)| RainbowChain {
            startpoint,
            endpoint,
        }));

        RainbowChainMap { inner, len, cap }
    }
}

impl<'a> IntoIterator for &'a RainbowChainMap {
    type Item = (CompressedPassword, CompressedPassword);
    type IntoIter = ChainsMapIterator<'a>;

    fn into_iter(self) -> Self::IntoIter {
        ChainsMapIterator {
            chains_map: self,
            idx: 0,
        }
    }
}

pub struct ChainsMapIterator<'a> {
    chains_map: &'a RainbowChainMap,
    idx: u64,
}

impl Iterator for ChainsMapIterator<'_> {
    type Item = (CompressedPassword, CompressedPassword);

    fn next(&mut self) -> Option<Self::Item> {
        let &entry = self.chains_map.inner.get(self.idx as usize)?;

        self.idx += 1;

        if entry == RainbowChain::VACANT {
            self.next()
        } else {
            Some((entry.startpoint, entry.endpoint))
        }
    }

    fn size_hint(&self) -> (usize, Option<usize>) {
        let len = self.chains_map.len();
        (len, Some(len))
    }
}
