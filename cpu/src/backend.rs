//! The backend used to generate rainbow tables.

mod cpu;
#[cfg(feature = "cuda")]
mod cuda;
mod wgpu;

pub use cpu::CpuBackend;

#[cfg(feature = "cuda")]
pub use cuda::CudaBackend;

use crate::error::CugparckResult;
use cugparck_commons::{RainbowChain, RainbowTableCtx};
use std::{borrow::Cow, ops::Range};

/// A trait that every backend must implement to generate a rainbow table.
/// The device refers to the GPU or CPU that will be used.
pub trait Backend: Sized {
    /// The type of the batch iterator.
    type BatchIterator: Iterator<Item = Self::BatchInfo> + ExactSizeIterator;

    // Information about a batch.
    type BatchInfo;

    /// Creates the backend.
    fn new() -> CugparckResult<Self>;

    /// Returns an iterator over the batches needed.
    fn batch_iter(&self, chains_len: usize) -> CugparckResult<Self::BatchIterator>;

    /// Returns the slice that makes up this batch.
    fn batch_slice<'a>(
        &self,
        chains: &'a mut [RainbowChain],
        batch_info: &Self::BatchInfo,
    ) -> &'a mut [RainbowChain];

    /// Starts the computation on the device.
    fn run_kernel<'a>(
        &self,
        batch: &'a mut [RainbowChain],
        batch_info: &Self::BatchInfo,
        columns: Range<usize>,
        ctx: RainbowTableCtx,
    ) -> CugparckResult<Cow<'a, [RainbowChain]>>;
}
