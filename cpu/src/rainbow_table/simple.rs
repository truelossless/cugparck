use std::{
    collections::{hash_map::Iter, HashMap},
    hash::BuildHasherDefault,
    thread,
};

use crate::{
    backend::Backend,
    event::{Event, SimpleTableHandle},
    renderer::Renderer,
    FiltrationIterator,
};
use bytecheck::CheckBytes;
use crossbeam_channel::{unbounded, Sender};
use cugparck_commons::{
    ArchivedCompressedPassword, CompressedPassword, RainbowChain, RainbowTableCtx,
};
use nohash_hasher::IntMap;
use rayon::prelude::*;
use rkyv::{collections::hash_map::Iter as RkyvIter, Archive, Deserialize, Infallible, Serialize};

use super::{RainbowTable, RainbowTableStorage};
use crate::error::CugparckResult;

/// A simple rainbow table.
#[derive(Archive, Deserialize, Serialize)]
#[archive_attr(derive(CheckBytes))]
pub struct SimpleTable {
    /// The chains of the table.
    chains: IntMap<CompressedPassword, CompressedPassword>,
    /// The context.
    ctx: RainbowTableCtx,
}

impl SimpleTable {
    /// Creates a new simple rainbow table from a Vec.
    /// The chains must be made of valid startpoints and endpoints.
    pub fn from_vec(chains: Vec<RainbowChain>, ctx: RainbowTableCtx) -> Self {
        Self {
            chains: IntMap::from_iter(
                chains
                    .into_iter()
                    .map(|chain| (chain.endpoint, chain.startpoint)),
            ),
            ctx,
        }
    }

    // Returns the startpoints in a vec.
    fn startpoints(ctx: &RainbowTableCtx) -> Vec<RainbowChain> {
        let mut vec = Vec::new();

        (0..ctx.m0)
            .into_par_iter()
            .map(|i| RainbowChain::from_compressed(i.into(), i.into()))
            .collect_into_vec(&mut vec);

        vec
    }

    /// Creates a new simple rainbow table, asynchronously.
    /// Returns an handle to get events related to the generation and to get the generated table.
    pub fn new_nonblocking<T: Backend>(ctx: RainbowTableCtx) -> CugparckResult<SimpleTableHandle> {
        let (sender, receiver) = unbounded();
        let thread_handle = thread::spawn(move || Self::new::<T>(ctx, Some(sender)));

        Ok(SimpleTableHandle {
            thread_handle,
            receiver,
        })
    }

    /// Creates a new simple rainbow table.
    pub fn new_blocking<T: Backend>(ctx: RainbowTableCtx) -> CugparckResult<Self> {
        Self::new::<T>(ctx, None)
    }

    fn new<T: Backend>(
        ctx: RainbowTableCtx,
        sender: Option<Sender<Event>>,
    ) -> CugparckResult<Self> {
        let renderer = T::renderer()?;

        let mut partial_chains = Self::startpoints(&ctx);
        let mut unique_chains: IntMap<CompressedPassword, CompressedPassword> =
            HashMap::with_capacity_and_hasher(ctx.m0, BuildHasherDefault::default());

        for columns in FiltrationIterator::new(ctx) {
            partial_chains.par_extend(
                unique_chains.par_drain().map(|(endpoint, startpoint)| {
                    RainbowChain::from_compressed(startpoint, endpoint)
                }),
            );

            let batch_iter = renderer.batch_iter(partial_chains.len())?.enumerate();
            let batch_count = batch_iter.len();
            for (batch_number, batch_info) in batch_iter {
                if let Some(sender) = &sender {
                    sender
                        .send(Event::Batch {
                            batch_number: batch_number + 1,
                            batch_count,
                            columns: columns.clone(),
                        })
                        .unwrap();
                }

                let batch_slice = renderer.batch_slice(&mut partial_chains, &batch_info);
                let batch_chains =
                    renderer.run_kernel(batch_slice, &batch_info, columns.clone(), ctx)?;

                unique_chains.par_extend(
                    batch_chains
                        .into_par_iter()
                        .map(|chain| (chain.endpoint, chain.startpoint)),
                );

                if let Some(sender) = &sender {
                    let batch_percent = batch_number as f64 / batch_count as f64;
                    let current_col_progress = columns.len() as f64 * batch_percent;
                    let col_progress = columns.start as f64;
                    let progress = (col_progress + current_col_progress) / ctx.t as f64 * 100.;

                    sender.send(Event::Progress(progress)).unwrap();
                }
            }

            partial_chains.clear();
        }

        unique_chains.shrink_to_fit();
        Ok(Self {
            chains: unique_chains,
            ctx,
        })
    }
}

impl RainbowTable for SimpleTable {
    type Iter<'a> = SimpleTableIterator<'a>;

    fn len(&self) -> usize {
        self.chains.len()
    }

    fn iter(&self) -> Self::Iter<'_> {
        self.into_iter()
    }

    fn search_endpoints(&self, password: CompressedPassword) -> Option<CompressedPassword> {
        self.chains.get(&password).copied()
    }

    fn ctx(&self) -> RainbowTableCtx {
        self.ctx
    }

    fn from_rainbow_table<T: RainbowTable>(table: T) -> Self {
        Self {
            ctx: table.ctx(),
            chains: table
                .iter()
                .map(|chain| (chain.endpoint, chain.startpoint))
                .collect(),
        }
    }
}

impl RainbowTable for ArchivedSimpleTable {
    type Iter<'a> = ArchivedSimpleTableIterator<'a>;

    fn len(&self) -> usize {
        self.chains.len()
    }

    fn iter(&self) -> Self::Iter<'_> {
        self.into_iter()
    }

    fn search_endpoints(&self, password: CompressedPassword) -> Option<CompressedPassword> {
        self.chains
            .get(&password.into())
            .map(|ar| ar.deserialize(&mut Infallible).unwrap())
    }

    fn ctx(&self) -> RainbowTableCtx {
        self.ctx.deserialize(&mut Infallible).unwrap()
    }

    fn from_rainbow_table<T: RainbowTable>(_: T) -> Self {
        panic!("Archived tables cannot be built from other tables")
    }
}

impl<'a> IntoIterator for &'a SimpleTable {
    type Item = RainbowChain;
    type IntoIter = <SimpleTable as RainbowTable>::Iter<'a>;

    fn into_iter(self) -> Self::IntoIter {
        Self::IntoIter::new(self)
    }
}

impl<'a> IntoIterator for &'a ArchivedSimpleTable {
    type Item = RainbowChain;
    type IntoIter = <ArchivedSimpleTable as RainbowTable>::Iter<'a>;

    fn into_iter(self) -> Self::IntoIter {
        Self::IntoIter::new(self)
    }
}

pub struct SimpleTableIterator<'a> {
    inner: Iter<'a, CompressedPassword, CompressedPassword>,
}

pub struct ArchivedSimpleTableIterator<'a> {
    inner: RkyvIter<'a, ArchivedCompressedPassword, ArchivedCompressedPassword>,
}

impl<'a> SimpleTableIterator<'a> {
    pub fn new(table: &'a SimpleTable) -> Self {
        Self {
            inner: table.chains.iter(),
        }
    }
}

impl<'a> ArchivedSimpleTableIterator<'a> {
    pub fn new(table: &'a ArchivedSimpleTable) -> Self {
        Self {
            inner: table.chains.iter(),
        }
    }
}

impl Iterator for SimpleTableIterator<'_> {
    type Item = RainbowChain;

    fn next(&mut self) -> Option<Self::Item> {
        self.inner
            .next()
            .map(|(endpoint, startpoint)| RainbowChain::from_compressed(*startpoint, *endpoint))
    }
}

impl Iterator for ArchivedSimpleTableIterator<'_> {
    type Item = RainbowChain;

    fn next(&mut self) -> Option<Self::Item> {
        self.inner.next().map(|(endpoint, startpoint)| {
            RainbowChain::from_compressed((*startpoint).into(), (*endpoint).into())
        })
    }
}

impl RainbowTableStorage for SimpleTable {}

impl std::fmt::Debug for SimpleTable {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let chains_count = self.chains.len().min(10);
        let some_chains = self.chains.iter().take(chains_count);

        for (endpoint, startpoint) in some_chains {
            writeln!(
                f,
                "{} -> {}",
                core::str::from_utf8(&startpoint.into_password(&self.ctx)).unwrap(),
                core::str::from_utf8(&endpoint.into_password(&self.ctx)).unwrap(),
            )?;
        }
        writeln!(f, "...")
    }
}
