//! CUDA renderer using RUST-CUDA.

/// The CUDA PTX containing the GPU code.
const PTX: &str = include_str!("../../../module.ptx");

use super::{BatchInformation, KernelHandle, Renderer, StagingHandleSync};
use crate::{backend::Backend, error::CugparckResult};
use cugparck_commons::{CompressedPassword, RainbowTableCtx};
use cust::{function::FunctionAttribute, prelude::*};
use std::ops::Range;

/// Infornations about a batch.
#[derive(Debug)]
pub struct BatchInfo {
    pub range: Range<usize>,
    pub block_count: u32,
    pub thread_count: u32,
}

impl BatchInformation for BatchInfo {
    fn range(&self) -> Range<usize> {
        return self.range.clone();
    }
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

        let kernel_memory = kernel.get_attribute(FunctionAttribute::LocalSizeBytes)? as usize;
        let kernels_per_batch = device_memory / kernel_memory;

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

/// A CUDA renderer.
pub struct CudaRenderer {
    device: Device,
    module: Module,
    stream: Stream,
    _ctx: Context,
    staging_buf: DeviceBuffer<CompressedPassword>,
}

impl CudaRenderer {
    fn new(chains_len: usize) -> CugparckResult<Self> {
        cust::init(CudaFlags::empty())?;
        let device = Device::get_device(0)?;
        let _ctx = Context::new(device)?;
        let module = Module::from_ptx(PTX, &[])?;
        let stream = Stream::new(StreamFlags::NON_BLOCKING, None)?;

        // SAFETY: we're not using the staging buffer yet.
        let mut renderer = Self {
            device,
            module,
            stream,
            _ctx,
            staging_buf: unsafe { DeviceBuffer::uninitialized(0)? },
        };

        // get the largest batch possible to initialize the staging buffer
        let largest_batch = renderer.max_staged_buffer_len(chains_len)?;

        // SAFETY: we're never reading from the staging buffer before initializing it.
        renderer.staging_buf = unsafe { DeviceBuffer::uninitialized(largest_batch)? };

        Ok(renderer)
    }
}

impl Renderer for CudaRenderer {
    type BatchIterator = BatchIterator;
    type BatchInfo = BatchInfo;
    type StagingHandle<'a> = StagingHandle<'a>;

    fn batch_iter(&self, chains_len: usize) -> CugparckResult<Self::BatchIterator> {
        let kernel = self.module.get_function("chains_kernel")?;
        BatchIterator::new(chains_len, &self.device, &kernel)
    }

    fn start_kernel<'a>(
        &mut self,
        batch: &'a mut [CompressedPassword],
        batch_info: &Self::BatchInfo,
        columns: Range<usize>,
        ctx: RainbowTableCtx,
    ) -> CugparckResult<KernelHandle<StagingHandle>> {
        self.staging_buf.index(..batch.len()).copy_from(batch)?;
        let stream = &self.stream;
        let module = &self.module;

        unsafe {
            launch!(
                module.chains_kernel<<<batch_info.block_count, batch_info.thread_count, 0, stream>>>(
                    columns.start,
                    columns.end,
                    self.staging_buf.as_device_ptr(),
                    batch.len(),
                    ctx,
                )
            )?
        }

        Ok(KernelHandle::Staged(StagingHandle {
            batch_len: batch.len(),
            stream,
            staging_buf: &self.staging_buf,
        }))
    }

    fn max_staged_buffer_len(&self, chains_len: usize) -> CugparckResult<usize> {
        Ok(self.batch_iter(chains_len)?.batch_size)
    }
}

pub struct StagingHandle<'a> {
    batch_len: usize,
    stream: &'a Stream,
    staging_buf: &'a DeviceBuffer<CompressedPassword>,
}

impl StagingHandleSync for StagingHandle<'_> {
    fn sync(&mut self, batch_buf: &mut Vec<CompressedPassword>) -> CugparckResult<()> {
        self.stream.synchronize()?;

        // SAFETY: the capacity of the staging buffer is always at least as large as the largest batch.
        unsafe { batch_buf.set_len(self.batch_len) }

        self.staging_buf
            .index(..self.batch_len)
            .copy_to(batch_buf)?;

        Ok(())
    }
}

/// A CUDA backend.
pub struct Cuda;

impl Backend for Cuda {
    type Renderer = CudaRenderer;

    fn renderer(chains_len: usize) -> CugparckResult<Self::Renderer> {
        Self::Renderer::new(chains_len)
    }
}
