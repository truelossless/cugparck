//! The renderers used to generate rainbow tables.

pub mod cpu;
#[cfg(feature = "cuda")]
pub mod cuda;
#[cfg(feature = "wgpu")]
pub mod wgpu;

use crate::error::CugparckResult;
use cugparck_commons::{CompressedPassword, RainbowTableCtx};
use std::ops::Range;

/// A trait that every renderer must implement to generate a rainbow table.
pub trait Renderer: Sized {
    /// The type of the batch iterator.
    type BatchIterator: Iterator<Item = Self::BatchInfo> + ExactSizeIterator;

    /// Information about a batch.
    type BatchInfo: BatchInformation;

    /// Type of the staging handle, for staged rendering.
    /// If the renderer does not support staged rendering, this can be `()`.
    type StagingHandle<'a>: StagingHandleSync
    where
        Self: 'a;

    /// Returns an iterator over the batches needed.
    fn batch_iter(&self, chains_len: usize) -> CugparckResult<Self::BatchIterator>;

    /// Returns the maximum length of the staged buffer if applicable.
    fn max_staged_buffer_len(&self, _chains_len: usize) -> CugparckResult<usize> {
        Ok(0)
    }

    /// Starts the computation.
    fn start_kernel<'a>(
        &mut self,
        batch: &'a mut [CompressedPassword],
        batch_info: &Self::BatchInfo,
        columns: Range<usize>,
        ctx: RainbowTableCtx,
    ) -> CugparckResult<KernelHandle<Self::StagingHandle<'_>>>;
}

/// A handle to a kernel being run.
pub enum KernelHandle<T: StagingHandleSync> {
    /// The kernel is modifying the partial chains synchronously and in place.
    Sync,
    /// The kernel is running asynchronously and the partial chains are being modified in a staging buffer.
    #[allow(unused)]
    Staged(T),
}

/// Trait that every staging handle must implement.
pub trait StagingHandleSync {
    /// Synchronizes the staging buffer.
    /// That is, blocks until the kernel is finished and the data is available to the host.
    fn sync(&mut self, batch_buf: &mut Vec<CompressedPassword>) -> CugparckResult<()>;
}

impl StagingHandleSync for () {
    fn sync(&mut self, _batch_buf: &mut Vec<CompressedPassword>) -> CugparckResult<()> {
        unreachable!()
    }
}

pub trait BatchInformation {
    fn range(&self) -> Range<usize>;
}
