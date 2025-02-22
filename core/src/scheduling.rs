use std::ops::Range;

use crate::{ctx::RainbowTableCtx, DEFAULT_FILTER_COUNT};

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
    range_start: usize,
    batch_size: usize,
    chains_remainder: usize,
    batch_number: usize,
    batches: usize,
    thread_count: u32,
}

impl BatchIterator {
    /// This is the number of CUDA cores of a RTX 5090.
    /// This is the maximum number of threads that can be run in parallel.
    const CUDA_CORES: usize = 21_760;

    // Max number of threads per block should range from 512 to 1024.
    // Since threads are executed in warps of 32, the number of threads should be a multiple of 32.
    // We shouldn't experience any performance loss for the same reason.
    const THREAD_COUNT: usize = 512;

    /// Make sure to fill the queues so the SM can work at full capacity.
    /// Since we run multiple batches in parallel, we don't need to put this too high.
    const FILL_FACTOR: usize = 1;

    /// This is our magic number of chains per batch, taking into account the preceding
    /// assumptions. A batch size should not be under this value to maximize occupency.
    const DESIRED_CHAINS_PER_BATCH: usize =
        Self::CUDA_CORES * Self::THREAD_COUNT * Self::FILL_FACTOR;

    /// Creates a new batch iterator where `chains_len` is the total number of chains to generate.
    pub fn new(chains_len: usize) -> BatchIterator {
        // this is the number of batches we need to process all the chains, rounded down
        let mut batches = chains_len / Self::DESIRED_CHAINS_PER_BATCH;
        // compute the size of a batch and the chains remainder that should have made the last
        // batch.
        let (batch_size, chains_remainder) = if batches == 0 {
            // we need at least one batch
            batches += 1;
            (chains_len, 0)
        } else {
            (chains_len / batches, chains_len % batches)
        };

        BatchIterator {
            range_start: 0,
            batch_size,
            chains_remainder,
            batches,
            batch_number: 0,
            thread_count: Self::THREAD_COUNT as u32,
        }
    }
}

impl Iterator for BatchIterator {
    type Item = BatchInfo;

    fn next(&mut self) -> Option<Self::Item> {
        if self.batch_number == self.batches {
            return None;
        }

        // Add part of the remainder that should have made the last batch.
        // We don't run the last `chains_remainder` chains in its own batch as it would under-occupy the GPU.
        let batch_size = if self.batch_number < self.chains_remainder {
            self.batch_size + 1
        } else {
            self.batch_size
        };

        // range of the chains in this batch
        let range_end = self.range_start + batch_size;
        let range = self.range_start..range_end;
        self.range_start = range_end;

        // compute the block count needed to satisfy the batch size and the fixed thread count.
        // it does not matter if we overshoot the batch size thanks to the if check in the GPU kernel.
        let block_count = (batch_size as u32).div_ceil(self.thread_count).max(1);

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

#[cfg(test)]
mod tests {
    use itertools::Itertools;

    use crate::scheduling::BatchIterator;

    #[test]
    fn test_batch_iterator_small_batch() {
        let chains_len = 201;
        let mut total_chains = 0;
        let batch_iterator = BatchIterator::new(chains_len);

        // only one small batch
        assert_eq!(1, batch_iterator.len());

        for batch_info in batch_iterator {
            total_chains += batch_info.range.len();
        }

        assert_eq!(chains_len, total_chains);
    }

    #[test]
    fn test_batch_iterator_perfect_batch_size() {
        let chains_len = BatchIterator::DESIRED_CHAINS_PER_BATCH * 2;
        let batch_iterator = BatchIterator::new(chains_len);

        assert_eq!(2, batch_iterator.len());

        for batch_info in batch_iterator {
            // no remainder, this should perfectly match
            assert_eq!(
                batch_info.range.len(),
                BatchIterator::DESIRED_CHAINS_PER_BATCH
            );
        }
    }

    #[test]
    fn test_batch_iterator_remainder() {
        let chains_len = BatchIterator::DESIRED_CHAINS_PER_BATCH * 5 - 1;
        let mut total_chains = 0;
        let batch_iterator = BatchIterator::new(chains_len);

        assert_eq!(4, batch_iterator.len());

        let batches = batch_iterator.collect_vec();
        for batch_info in &batches {
            // the batch size should always be in [DESIRED_CHAINS_PER_BATCH, DESIRED_CHAINS_PER_BATCH*2]
            assert!(
                batch_info.range.len() > BatchIterator::DESIRED_CHAINS_PER_BATCH
                    && batch_info.range.len() < BatchIterator::DESIRED_CHAINS_PER_BATCH * 2
            );
            total_chains += batch_info.range.len();
        }

        // the first batches should have one element more
        assert_eq!(
            batches.first().unwrap().range.len(),
            batches.last().unwrap().range.len() + 1
        );
        assert_eq!(chains_len, total_chains);
    }
}
