//! CUDA backend using RUST-CUDA.

/// The CUDA PTX containing the GPU code.
const PTX: &str = include_str!("../../../module.ptx");

use super::Backend;
use crate::error::CugparckResult;
use cugparck_commons::{RainbowChain, RainbowTableCtx};
use cust::{function::FunctionAttribute, prelude::*};
use std::{borrow::Cow, ops::Range};

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

pub struct CudaBackend {
    device: Device,
    module: Module,
    stream: Stream,
    _ctx: Context,
}

impl Backend for CudaBackend {
    type BatchIterator = BatchIterator;
    type BatchInfo = BatchInfo;

    fn new() -> CugparckResult<Self> {
        cust::init(CudaFlags::empty())?;
        let device = Device::get_device(0)?;
        let _ctx = Context::new(device)?;
        let module = Module::from_ptx(PTX, &[])?;
        let stream = Stream::new(StreamFlags::NON_BLOCKING, None)?;

        Ok(CudaBackend {
            device,
            module,
            stream,
            _ctx,
        })
    }

    fn batch_iter(&self, chains_len: usize) -> CugparckResult<Self::BatchIterator> {
        let kernel = self.module.get_function("chains_kernel")?;
        BatchIterator::new(chains_len, &self.device, &kernel)
    }

    fn batch_slice<'a>(
        &self,
        chains: &'a mut [cugparck_commons::RainbowChain],
        batch_info: &Self::BatchInfo,
    ) -> &'a mut [cugparck_commons::RainbowChain] {
        &mut chains[batch_info.range.clone()]
    }

    fn run_kernel<'a>(
        &self,
        batch: &'a mut [cugparck_commons::RainbowChain],
        batch_info: &Self::BatchInfo,
        columns: Range<usize>,
        ctx: RainbowTableCtx,
    ) -> CugparckResult<Cow<'a, [RainbowChain]>> {
        let d_batch = DeviceBuffer::from_slice(batch)?;
        let stream = &self.stream;
        let module = &self.module;

        unsafe {
            launch!(
                module.chains_kernel<<<batch_info.block_count, batch_info.thread_count, 0, stream>>>(
                    columns.start,
                    columns.end,
                    d_batch.as_device_ptr(),
                    d_batch.len(),
                    ctx,
                )
            )?
        }
        stream.synchronize()?;

        let mut batch_chains = d_batch.as_host_vec()?;
        batch_chains.truncate(batch_info.range.len());

        Ok(Cow::Owned(batch_chains))
    }
}
