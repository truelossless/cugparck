use std::ops::Range;

use cubecl::{client::ComputeClient, Runtime};

use crate::{
    ctx::RainbowTableCtx, error::CugparckResult, CompressedPassword, DEFAULT_FILTER_COUNT,
};

/// Infornations about a batch.
#[derive(Debug)]
pub struct BatchInfo {
    pub range: Range<usize>,
    pub block_count: u32,
    pub thread_count: u32,
}

/// An iterator that batches the chains to process.
#[derive(Clone)]
pub struct BatchIterator {
    batch_size: usize,
    last_batch_size: usize,
    batch_number: usize,
    batches: usize,
    thread_count: u32,
}

impl BatchIterator {
    /// Creates a new batch iterator where `chains_len` is the total number of chains to generate.
    pub fn new(chains_len: usize) -> CugparckResult<BatchIterator> {
        // This is the number of CUDA cores of a RTX 5090.
        // This is the maximum number of threads that can be run in parallel.
        let cuda_cores = 21_760;

        // Max number of threads per block should range from 512 to 1024.
        // Since threads are executed in warps of 32, the number of threads should be a multiple of 32.
        // We shouldn't experience any performance loss for the same reason.
        let thread_count = 512;

        // Make sure to fill the queues so the SM can work at full capacity.
        // Since we run multiple batches in parallel, we don't need to put this too high.
        let fill_factor = 10;

        // this is the number of batches we need to process all the chains
        let mut batches = chains_len / (cuda_cores * thread_count * fill_factor);

        // don't forget the last batch since integer division is rounding down numbers
        let (batch_size, last_batch_size) = if batches == 0 {
            (chains_len, chains_len)
        } else {
            (chains_len / batches, chains_len % batches)
        };
        batches += 1;

        Ok(BatchIterator {
            batch_size,
            last_batch_size,
            batches,
            batch_number: 0,
            thread_count: thread_count as u32,
        })
    }
}

impl Iterator for BatchIterator {
    type Item = BatchInfo;

    fn next(&mut self) -> Option<Self::Item> {
        if self.batch_number == self.batches {
            return None;
        }

        let size = if self.batch_number == self.batches - 1 {
            self.last_batch_size
        } else {
            self.batch_size
        };

        let block_count = (size as u32).div_ceil(self.thread_count).max(1);
        let range = self.batch_number * self.batch_size..self.batch_number * self.batch_size + size;

        let batch_info = BatchInfo {
            range,
            block_count,
            thread_count: self.thread_count,
        };

        self.batch_number += 1;

        Some(batch_info)
    }

    fn size_hint(&self) -> (usize, Option<usize>) {
        (
            self.batches - self.batch_number,
            Some(self.batches - self.batch_number),
        )
    }
}

impl ExactSizeIterator for BatchIterator {}

/// An iterator to get the columns where a filtration should happen.
pub struct FiltrationIterator {
    i: usize,
    current_col: usize,
    gamma: f64,
    frac: f64,
    ctx: RainbowTableCtx,
}

impl FiltrationIterator {
    /// Creates a new FiltrationIterator.
    pub fn new(ctx: RainbowTableCtx) -> Self {
        // from "Precomputation for Rainbow Tables has Never Been so Fast" theorem 3
        let gamma = 2. * ctx.n as f64 / ctx.m0 as f64;
        let frac = (ctx.t as f64 + gamma - 1.) / gamma;

        Self {
            gamma,
            frac,
            ctx,
            i: 0,
            current_col: 0,
        }
    }
}

impl Iterator for FiltrationIterator {
    type Item = Range<usize>;

    fn next(&mut self) -> Option<Self::Item> {
        if self.i == DEFAULT_FILTER_COUNT {
            self.i += 1;
            return Some(self.current_col..self.ctx.t as usize - 1);
        } else if self.i >= DEFAULT_FILTER_COUNT {
            return None;
        }

        let filter_col = (self.gamma * self.frac.powf(self.i as f64 / DEFAULT_FILTER_COUNT as f64)
            - self.gamma) as usize
            + 2;

        let col = self.current_col;

        self.i += 1;
        self.current_col = filter_col;

        // same filtration column, it can happen with small tables
        if col == filter_col {
            return self.next();
        }

        Some(col..filter_col)
    }
}

pub struct Producer<Backend: Runtime> {
    pub client: ComputeClient<Backend::Server, Backend::Channel>,
    pub startpoints: Vec<CompressedPassword>,
}

impl<Backend: Runtime> Producer<Backend> {
    pub fn new() -> Self {
        Self {
            client: Backend::client(&Default::default()),
            startpoints: Vec::new(),
        }
    }
}

impl<Backend: Runtime> Clone for Producer<Backend> {
    fn clone(&self) -> Self {
        Self {
            client: self.client.clone(),
            startpoints: self.startpoints.clone(),
        }
    }
}
