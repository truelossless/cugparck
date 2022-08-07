use std::ops::Range;

use cust::device::Device;
use cust::function::{Function, FunctionAttribute};

use crate::error::CugparckResult;

/// Infornations about a batch.
#[derive(Debug)]
pub struct BatchInfo {
    pub count: usize,
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
    pub fn new(
        chains_len: usize,
        device: &Device,
        kernel: &Function,
    ) -> CugparckResult<BatchIterator> {
        let device_memory = device.total_memory().unwrap() - 50_000;

        // estimate of the memory used by one thread running the kernel
        let kernel_mem = kernel.get_attribute(FunctionAttribute::LocalSizeBytes)? as usize;

        let kernels_per_batch = device_memory / kernel_mem;

        // number of batches to do
        let mut batches = chains_len / kernels_per_batch;

        // don't forget the last batch since integer division is rounding down numbers
        let (batch_size, last_batch_size) = if batches == 0 {
            (chains_len, chains_len)
        } else {
            (chains_len / batches, chains_len % batches)
        };
        batches += 1;

        let (_, thread_count) = kernel.suggested_launch_configuration(0, 0.into())?;

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

        let block_count = ((size as u32 + self.thread_count - 1) / self.thread_count).max(1);
        let range = self.batch_number * self.batch_size..self.batch_number * self.batch_size + size;

        let batch_info = BatchInfo {
            range,
            count: self.batches,
            block_count,
            thread_count: self.thread_count,
        };

        self.batch_number += 1;

        Some(batch_info)
    }
}
