use std::{mem, sync::Arc};

use cubecl::prelude::*;
use serde::{Deserialize, Serialize};
use tokio::sync::{
    mpsc::{self, unbounded_channel, UnboundedSender},
    Mutex,
};

use super::{RainbowChain, RainbowTable};
use crate::{
    cpu::counter_to_plaintext,
    ctx::RainbowTableCtx,
    cube::compute::chains_kernel,
    error::CugparckResult,
    event::{Event, SimpleTableHandle},
    rainbow_chain_map::{ChainsMapIterator, RainbowChainMap},
    scheduling::{BatchIterator, FiltrationIterator, Producer},
    CompressedPassword,
};

/// A simple rainbow table.
#[derive(Serialize, Deserialize)]
pub struct SimpleTable {
    /// The chains of the table.
    chains: RainbowChainMap,
    /// The context.
    ctx: RainbowTableCtx,
}

impl SimpleTable {
    /// Creates a new simple rainbow table from a Vec.
    /// The chains must be made of valid startpoints and endpoints.
    pub fn from_vec(chains: Vec<RainbowChain>, ctx: RainbowTableCtx) -> Self {
        Self {
            chains: RainbowChainMap::from_iter(
                chains
                    .into_iter()
                    .map(|chain| (chain.endpoint, chain.startpoint)),
            ),
            ctx,
        }
    }

    /// Creates a new simple rainbow table, asynchronously.
    /// Returns an handle to get events related to the generation and to get the generated table.
    pub async fn new_with_events<Backend: Runtime>(
        ctx: RainbowTableCtx,
    ) -> CugparckResult<SimpleTableHandle> {
        let (sender, receiver) = unbounded_channel();
        let handle =
            tokio::spawn(async move { Self::new_impl::<Backend>(ctx, Some(sender)).await });

        Ok(SimpleTableHandle { handle, receiver })
    }

    /// Creates a new simple rainbow table.
    pub async fn new<Backend: Runtime>(ctx: RainbowTableCtx) -> CugparckResult<Self> {
        Self::new_impl::<Backend>(ctx, None).await
    }

    async fn new_impl<Backend: Runtime>(
        ctx: RainbowTableCtx,
        events: Option<UnboundedSender<Event>>,
    ) -> CugparckResult<Self> {
        // create multiple clients.
        // each client has its own stream, so we can maximize the GPU usage and reduce data transfer overhead.
        // See: https://developer.download.nvidia.com/CUDA/training/StreamsAndConcurrencyWebinar.pdf
        const PRODUCER_COUNT: usize = 4;
        let (producer_sender, mut producer_receiver) = mpsc::channel(PRODUCER_COUNT);
        for _ in 0..PRODUCER_COUNT {
            producer_sender
                .send(Producer::<Backend>::new())
                .await
                .unwrap();
        }

        let mut current_chains = RainbowChainMap::new(ctx.m0)?;
        let next_chains = RainbowChainMap::with_startpoints(ctx.m0)?;
        let next_chains_mutex = Arc::new(Mutex::new(next_chains));

        for columns in FiltrationIterator::new(ctx.clone()) {
            // make the next chains the current chains, and empty next chains
            mem::swap(&mut current_chains, &mut *next_chains_mutex.lock().await);
            next_chains_mutex.lock().await.clear();

            let mut current_chains_iter = current_chains.into_iter();
            let batch_iter = BatchIterator::new(current_chains.len())?.enumerate();
            let batch_count = batch_iter.len() as u64;

            for (batch_number, batch_info) in batch_iter {
                // fetch a producer. This will block until one is available.
                let mut producer = producer_receiver.recv().await.unwrap();
                let events = events.clone();
                let columns = columns.clone();

                if let Some(sender) = &events {
                    sender
                        .send(Event::Batch {
                            batch_number: batch_number as u64 + 1,
                            batch_count,
                            columns: columns.clone(),
                        })
                        .unwrap();
                }

                let (batch_startpoints, batch_midpoints): (
                    Vec<CompressedPassword>,
                    Vec<CompressedPassword>,
                ) = current_chains_iter
                    .by_ref()
                    .take(batch_info.range.len())
                    .unzip();

                let next_chains_mutex = next_chains_mutex.clone();
                let ctx = ctx.clone();
                tokio::spawn(async move {
                    let batch_handle = producer.client.create(u64::as_bytes(&batch_midpoints));
                    producer.startpoints = batch_startpoints;

                    // run the kernel
                    unsafe {
                        let batch_arg = ArrayArg::from_raw_parts::<u64>(
                            &batch_handle,
                            batch_midpoints.len(),
                            1,
                        );
                        let charset_handle = producer.client.create(u8::as_bytes(&ctx.charset));
                        let charset_arg =
                            ArrayArg::from_raw_parts::<u8>(&charset_handle, ctx.charset.len(), 1);

                        let search_spaces_handle =
                            producer.client.create(u64::as_bytes(&ctx.search_spaces));
                        let search_spaces_arg = ArrayArg::from_raw_parts::<u64>(
                            &search_spaces_handle,
                            ctx.search_spaces.len(),
                            1,
                        );

                        let (comptime_ctx, runtime_ctx) =
                            ctx.to_comptime_runtime(charset_arg, search_spaces_arg);

                        chains_kernel::launch_unchecked::<Backend>(
                            &producer.client,
                            CubeCount::Static(batch_info.block_count, 1, 1),
                            CubeDim::new(batch_info.thread_count, 1, 1),
                            batch_arg,
                            ScalarArg::new(columns.start as u64),
                            ScalarArg::new(columns.end as u64),
                            runtime_ctx,
                            comptime_ctx,
                        );
                    }

                    let batch_output = producer.client.read_one_async(batch_handle.binding()).await;
                    let batch_midpoints = CompressedPassword::from_bytes(&batch_output);

                    dbg!("Extending!");
                    let mut next_chains = next_chains_mutex.lock().await;

                    for (&startpoint, &midpoint) in producer.startpoints.iter().zip(batch_midpoints)
                    {
                        next_chains.insert(RainbowChain {
                            startpoint,
                            endpoint: midpoint,
                        });
                    }
                    dbg!("Finished extending!");

                    if let Some(events) = &events {
                        let batch_percent = batch_number as f64 / batch_count as f64;
                        let current_col_progress = columns.len() as f64 * batch_percent;
                        let col_progress = columns.start as f64;
                        let progress = (col_progress + current_col_progress) / ctx.t as f64 * 100.;

                        events.send(Event::Progress(progress)).unwrap();
                    }
                });
            }
        }

        Ok(Self {
            chains: Arc::into_inner(next_chains_mutex).unwrap().into_inner(),
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

    #[inline]
    fn search_endpoints(&self, password: CompressedPassword) -> Option<CompressedPassword> {
        self.chains.get(password)
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
    inner: ChainsMapIterator<'a>,
}

impl<'a> SimpleTableIterator<'a> {
    pub fn new(table: &'a SimpleTable) -> Self {
        Self {
            inner: table.chains.into_iter(),
        }
    }
}

impl Iterator for SimpleTableIterator<'_> {
    type Item = RainbowChain;

    fn next(&mut self) -> Option<Self::Item> {
        self.inner
            .next()
            .map(|(endpoint, startpoint)| RainbowChain {
                startpoint,
                endpoint,
            })
    }
}

impl std::fmt::Debug for SimpleTable {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let chains_count = self.chains.len().min(10);
        let some_chains = self.chains.into_iter().take(chains_count);

        for (endpoint, startpoint) in some_chains {
            let startpoint: Vec<u8> = counter_to_plaintext(startpoint, &self.ctx)
                .into_iter()
                .collect();
            let endpoint: Vec<u8> = counter_to_plaintext(endpoint, &self.ctx)
                .into_iter()
                .collect();

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
