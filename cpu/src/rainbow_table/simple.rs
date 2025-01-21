use std::thread;

use crate::{
    batch::BatchIterator,
    event::{Event, SimpleTableHandle},
    CugparckError, FiltrationIterator,
};

use crossbeam_channel::{unbounded, Sender};
use cubecl::prelude::*;
use cugparck_core::{
    into_password, CompressedPassword, RainbowChain, RainbowTableCtx, RainbowTableCtxLaunch,
};
use cugparck_cubecl::chains_kernel;
use indexmap::{map::Iter, IndexMap};
use nohash_hasher::BuildNoHashHasher;
use rayon::prelude::*;
use serde::{Deserialize, Serialize};

use super::RainbowTable;
use crate::error::CugparckResult;

/// An indexed Hashmap using the endpoint of a rainbow chain as the key (and hash value) and the chain as the value.
type RainbowMap =
    IndexMap<CompressedPassword, CompressedPassword, BuildNoHashHasher<CompressedPassword>>;

/// A simple rainbow table.
#[derive(Serialize, Deserialize)]
pub struct SimpleTable {
    /// The chains of the table.
    chains: RainbowMap,
    /// The context.
    ctx: RainbowTableCtx,
}

impl SimpleTable {
    /// Creates a new simple rainbow table from a Vec.
    /// The chains must be made of valid startpoints and endpoints.
    pub fn from_vec(chains: Vec<RainbowChain>, ctx: RainbowTableCtx) -> Self {
        Self {
            chains: RainbowMap::from_iter(
                chains
                    .into_iter()
                    .map(|chain| (chain.endpoint, chain.startpoint)),
            ),
            ctx,
        }
    }

    // Returns the startpoints in a vec.
    fn startpoints(ctx: &RainbowTableCtx) -> CugparckResult<Vec<CompressedPassword>> {
        let mut vec: Vec<CompressedPassword> = Vec::new();
        vec.try_reserve_exact(ctx.m0 as usize)?;
        vec.extend(0..ctx.m0);
        Ok(vec)
    }

    /// Creates a new simple rainbow table, asynchronously.
    /// Returns an handle to get events related to the generation and to get the generated table.
    pub fn new_nonblocking<T: Runtime>(ctx: RainbowTableCtx) -> CugparckResult<SimpleTableHandle> {
        let (sender, receiver) = unbounded();
        let thread_handle = thread::spawn(move || Self::new::<T>(ctx, Some(sender)));

        Ok(SimpleTableHandle {
            thread_handle,
            receiver,
        })
    }

    /// Creates a new simple rainbow table.
    pub fn new_blocking<Backend: Runtime>(ctx: RainbowTableCtx) -> CugparckResult<Self> {
        Self::new::<Backend>(ctx, None)
    }

    fn new<Backend: Runtime>(
        ctx: RainbowTableCtx,
        sender: Option<Sender<Event>>,
    ) -> CugparckResult<Self> {
        let client = Backend::client(&Default::default());
        let mut startpoints: Vec<CompressedPassword> = Self::startpoints(&ctx)?;
        let mut midpoints: Vec<CompressedPassword> = startpoints.clone();

        let mut unique_chains = RainbowMap::default();
        unique_chains
            .try_reserve(ctx.m0 as usize)
            .map_err(|_| CugparckError::IndexMapOutOfMemory)?;

        let mut batch_buf: Vec<CompressedPassword> = Vec::new();
        // TODO: Fix memory
        batch_buf.try_reserve_exact(1024 * 1024 * 1024)?;

        for columns in FiltrationIterator::new(ctx.clone()) {
            if !unique_chains.is_empty() {
                unique_chains
                    .par_drain(..)
                    .unzip_into_vecs(&mut midpoints, &mut startpoints);
            }

            let batch_iter = BatchIterator::new(midpoints.len())?.enumerate();
            let batch_count = batch_iter.len() as u64;

            for (batch_number, batch_info) in batch_iter {
                if let Some(sender) = &sender {
                    sender
                        .send(Event::Batch {
                            batch_number: batch_number as u64 + 1,
                            batch_count,
                            columns: columns.clone(),
                        })
                        .unwrap();
                }

                let batch = &mut midpoints[batch_info.range.clone()];
                let batch_handle = client.create(u64::as_bytes(batch));

                // run the kernel
                unsafe {
                    let batch_arg = ArrayArg::from_raw_parts::<u64>(&batch_handle, batch.len(), 1);

                    // let charset_arg = ctx.charset.into();
                    // let charset_handle = client.create(u8::as_bytes(&charset_vec));
                    // let charset_arg = SequenceArg::from_raw_parts::<u8>(
                    //     &charset_handle,
                    //     ctx.charset.len() as usize,
                    //     1,
                    // );

                    let mut charset_arg = SequenceArg::new();
                    charset_arg.push(ScalarArg::new(b'a'));
                    charset_arg.push(ScalarArg::new(b'b'));
                    charset_arg.push(ScalarArg::new(b'c'));
                    charset_arg.push(ScalarArg::new(b'd'));

                    // let search_spaces_vec: Vec<u64> = ctx.search_spaces.into_iter().collect();
                    // let search_spaces_handle = client.create(u64::as_bytes(&search_spaces_vec));
                    // let search_spaces_arg = ArrayArg::from_raw_parts::<u64>(
                    //     &search_spaces_handle,
                    //     ctx.search_spaces.len() as usize,
                    //     1,
                    // );

                    let mut search_spaces_arg = SequenceArg::new();
                    for search_space in ctx.search_spaces.clone() {
                        search_spaces_arg.push(ScalarArg::new(search_space));
                    }

                    let launch_ctx = RainbowTableCtxLaunch::new(
                        ScalarArg::new(ctx.m0),
                        charset_arg,
                        ScalarArg::new(ctx.t),
                        ScalarArg::new(ctx.max_password_length),
                        ScalarArg::new(ctx.n),
                        search_spaces_arg,
                        ScalarArg::new(ctx.tn),
                    );

                    // TODO: fix dims
                    chains_kernel::launch_unchecked::<Backend>(
                        &client,
                        CubeCount::Static(1, 1, 1),
                        CubeDim::new(batch.len() as u32, 1, 1),
                        batch_arg,
                        ScalarArg::new(columns.start as u64),
                        ScalarArg::new(columns.end as u64),
                        launch_ctx,
                    );
                }

                let batch_output = client.read_one(batch_handle.binding());
                unique_chains.par_extend(
                    CompressedPassword::from_bytes(&batch_output)
                        .par_iter()
                        .zip(startpoints[batch_info.range.clone()].par_iter()),
                );

                if let Some(sender) = &sender {
                    let batch_percent = batch_number as f64 / batch_count as f64;
                    let current_col_progress = columns.len() as f64 * batch_percent;
                    let col_progress = columns.start as f64;
                    let progress = (col_progress + current_col_progress) / ctx.t as f64 * 100.;

                    sender.send(Event::Progress(progress)).unwrap();
                }
            }
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
        self.ctx.clone()
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

impl<'a> IntoIterator for &'a SimpleTable {
    type Item = RainbowChain;
    type IntoIter = <SimpleTable as RainbowTable>::Iter<'a>;

    fn into_iter(self) -> Self::IntoIter {
        Self::IntoIter::new(self)
    }
}

pub struct SimpleTableIterator<'a> {
    inner: Iter<'a, CompressedPassword, CompressedPassword>,
}

impl<'a> SimpleTableIterator<'a> {
    pub fn new(table: &'a SimpleTable) -> Self {
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

impl std::fmt::Debug for SimpleTable {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let chains_count = self.chains.len().min(10);
        let some_chains = self.chains.iter().take(chains_count);

        for (endpoint, startpoint) in some_chains {
            let startpoint: Vec<u8> = into_password(*startpoint, &self.ctx).into_iter().collect();
            let endpoint: Vec<u8> = into_password(*endpoint, &self.ctx).into_iter().collect();

            writeln!(
                f,
                "{} -> {}",
                core::str::from_utf8(&startpoint).unwrap(),
                core::str::from_utf8(&endpoint).unwrap()
            )?;
        }
        writeln!(f, "...")
    }
}
