use std::{
    mem,
    sync::{
        mpsc::{channel, Sender},
        Arc, Mutex,
    },
    thread::{self},
};

use cubecl::prelude::*;
use serde::{Deserialize, Serialize};
use tracing::{debug, trace};

use super::{RainbowChain, RainbowTable};
use crate::{
    cpu::counter_to_plaintext,
    ctx::RainbowTableCtx,
    cube::compute::chains_kernel,
    error::CugparckResult,
    event::{BatchStatus, Event, SimpleTableHandle},
    producer::Producer,
    rainbow_chain_map::{RainbowChainMap, RainbowChainMapIterator},
    scheduling::{BatchIterator, FiltrationIterator},
    CompressedPassword, PRODUCER_COUNT,
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

    /// Creates a new simple rainbow table.
    pub fn new<Backend: Runtime>(ctx: RainbowTableCtx) -> CugparckResult<Self> {
        let (sender, _receiver) = channel();
        Self::new_impl::<Backend>(ctx, sender)
    }

    /// Creates a new simple rainbow table, asynchronously.
    /// Returns an handle to get events related to the generation and to get the generated table.
    pub fn new_with_events<Backend: Runtime>(
        ctx: RainbowTableCtx,
    ) -> CugparckResult<SimpleTableHandle> {
        let (sender, receiver) = channel();
        let handle = thread::spawn(|| Self::new_impl::<Backend>(ctx, sender));

        Ok(SimpleTableHandle { handle, receiver })
    }

    /// Actual implementation of the rainbow table generation.
    fn new_impl<Backend: Runtime>(
        ctx: RainbowTableCtx,
        events: Sender<Event>,
    ) -> CugparckResult<Self> {
        // create multiple producers.
        // each producer is a client with its own stream, so we can maximize the GPU usage and reduce data transfer overhead.
        // See: https://developer.download.nvidia.com/CUDA/training/StreamsAndConcurrencyWebinar.pdf
        let (producer_sender, producer_receiver) = channel();

        let mut current_chains = RainbowChainMap::new(ctx.m0)?;
        let next_chains = Arc::new(Mutex::new(RainbowChainMap::with_startpoints(ctx.m0)?));

        let mut producers: Vec<Producer<Backend>> = Vec::with_capacity(PRODUCER_COUNT);
        for i in 0..PRODUCER_COUNT {
            producers.push(Producer::new(i as u8));
        }

        for columns in FiltrationIterator::new(ctx.clone()) {
            debug!("New computation step between columns {columns:?}");
            // make available all producers
            for producer in producers.drain(..) {
                producer_sender.send(producer).unwrap();
            }
            trace!("All producers made available");

            // make the next chains the current chains, and empty next chains
            mem::swap(&mut current_chains, &mut *next_chains.lock().unwrap());
            next_chains.lock().unwrap().clear();

            let mut current_chains_iter = current_chains.into_iter();
            let batch_iter = BatchIterator::new(current_chains.len()).enumerate();

            let batch_count = batch_iter.len() as u64;
            let mut batch_finished = 0;

            events
                .send(Event::ComputationStepStarted {
                    columns: columns.clone(),
                    batch_count,
                })
                .unwrap();

            for (batch_number, batch_info) in batch_iter {
                // wait for a producer. This will block until one is available.
                let producer = producer_receiver.recv().unwrap();

                events
                    .send(Event::Batch {
                        number: batch_number as u64,
                        producer: producer.number,
                        status: BatchStatus::CopyHostToDevice,
                    })
                    .unwrap();

                let (batch_midpoints, batch_startpoints): (
                    Vec<CompressedPassword>,
                    Vec<CompressedPassword>,
                ) = current_chains_iter
                    .by_ref()
                    .take(batch_info.range.len())
                    .unzip();

                let ctx = ctx.clone();
                let columns = columns.clone();
                let next_chains_borrow = next_chains.clone();
                let producer_sender = producer_sender.clone();
                let events = events.clone();
                thread::spawn(move || {
                    trace!("Producer {} started", producer.number);
                    events
                        .send(Event::Batch {
                            number: batch_number as u64,
                            producer: producer.number,
                            status: BatchStatus::ComputationStarted,
                        })
                        .unwrap();

                    let batch_handle = producer.client.create(u64::as_bytes(&batch_midpoints));

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

                    // update table generation progress
                    batch_finished += 1;
                    let batch_percent = batch_finished as f64 / batch_count as f64;
                    let current_col_progress = columns.len() as f64 * batch_percent;
                    let col_progress = columns.start as f64;
                    let overall_progress = (col_progress + current_col_progress) / ctx.t as f64;
                    events.send(Event::Progress(overall_progress)).unwrap();

                    // copy back results to host
                    events
                        .send(Event::Batch {
                            number: batch_number as u64,
                            producer: producer.number,
                            status: BatchStatus::CopyDeviceToHost,
                        })
                        .unwrap();

                    let batch_output = producer.client.read_one(batch_handle);
                    let batch_midpoints = CompressedPassword::from_bytes(&batch_output);

                    // filtrate results
                    events
                        .send(Event::Batch {
                            number: batch_number as u64,
                            producer: producer.number,
                            status: BatchStatus::FiltrationStarted,
                        })
                        .unwrap();

                    let mut next_chains = next_chains_borrow.lock().unwrap();
                    for (&startpoint, &midpoint) in batch_startpoints.iter().zip(batch_midpoints) {
                        next_chains.insert(RainbowChain {
                            startpoint,
                            endpoint: midpoint,
                        });
                    }

                    events
                        .send(Event::Batch {
                            number: batch_number as u64,
                            producer: producer.number,
                            status: BatchStatus::FiltrationFinished,
                        })
                        .unwrap();

                    // release this producer
                    drop(next_chains);
                    drop(next_chains_borrow);
                    trace!("Producer {} finished", producer.number);
                    producer_sender.send(producer).unwrap();
                });
            }

            // wait for all producers to finish before starting next batches
            trace!("All batches dispatched, waiting for all producers");
            for _ in 0..PRODUCER_COUNT {
                producers.push(producer_receiver.recv().unwrap());
            }
            trace!("All producers finished");

            events
                .send(Event::ComputationStepFinished {
                    unique_chains: next_chains.lock().unwrap().len() as u64,
                })
                .unwrap();
        }

        let chains = Arc::into_inner(next_chains).unwrap().into_inner().unwrap();
        Ok(Self { chains, ctx })
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
    inner: RainbowChainMapIterator<'a>,
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

    fn size_hint(&self) -> (usize, Option<usize>) {
        self.inner.size_hint()
    }
}

impl ExactSizeIterator for SimpleTableIterator<'_> {
    fn len(&self) -> usize {
        self.inner.len()
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
