//! The renderers used to generate rainbow tables.

pub mod cpu;
#[cfg(feature = "cuda")]
pub mod cuda;
#[cfg(feature = "wgpu")]
pub mod wgpu;

use crate::error::CugparckResult;
use cugparck_commons::{RainbowChain, RainbowTableCtx};
use std::{borrow::Cow, ops::Range};

/// A trait that every renderer must implement to generate a rainbow table.
pub trait Renderer: Sized {
    /// The type of the batch iterator.
    type BatchIterator: Iterator<Item = Self::BatchInfo> + ExactSizeIterator;

    // Information about a batch.
    type BatchInfo;

    /// Returns an iterator over the batches needed.
    fn batch_iter(&self, chains_len: usize) -> CugparckResult<Self::BatchIterator>;

    /// Returns the slice that makes up this batch.
    fn batch_slice<'a>(
        &self,
        chains: &'a mut [RainbowChain],
        batch_info: &Self::BatchInfo,
    ) -> &'a mut [RainbowChain];

    /// Starts the computation.
    fn run_kernel<'a>(
        &self,
        batch: &'a mut [RainbowChain],
        batch_info: &Self::BatchInfo,
        columns: Range<usize>,
        ctx: RainbowTableCtx,
    ) -> CugparckResult<Cow<'a, [RainbowChain]>>;
}
