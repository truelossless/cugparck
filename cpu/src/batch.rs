use std::ops::Range;

use crate::error::CugparckResult;

/// Infornations about a batch.
#[derive(Debug)]
pub struct BatchInfo {
    pub range: Range<usize>,
    pub block_count: u32,
    pub thread_count: u32,
}

/// An iterator generating multiple batches, regarding the host's and device's available RAM.
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
        // number of batches to do
        // TODO: better estimate
        let mut batches = chains_len / 1_000_000_000;

        // don't forget the last batch since integer division is rounding down numbers
        let (batch_size, last_batch_size) = if batches == 0 {
            (chains_len, chains_len)
        } else {
            (chains_len / batches, chains_len % batches)
        };
        batches += 1;

        let thread_count = 512;

        Ok(BatchIterator {
            batch_size,
            last_batch_size,
            batches,
            batch_number: 0,
            thread_count,
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
