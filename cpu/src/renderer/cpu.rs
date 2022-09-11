//! Multithreaded CPU renderer.

use std::{
    iter::{self, Once},
    ops::Range,
};

use cugparck_commons::{CompressedPassword, RainbowTableCtx};
use rayon::prelude::*;

use crate::{backend::Backend, error::CugparckResult};

use super::{BatchInformation, KernelHandle, Renderer};

pub struct BatchInfo {
    pub range: Range<usize>,
}

impl BatchInformation for BatchInfo {
    fn range(&self) -> Range<usize> {
        self.range.clone()
    }
}

pub struct CpuRenderer;

impl CpuRenderer {
    pub fn new() -> CugparckResult<Self> {
        Ok(CpuRenderer)
    }
}

impl Renderer for CpuRenderer {
    type BatchIterator = Once<BatchInfo>;
    type BatchInfo = BatchInfo;
    type StagingHandle<'a> = ();

    fn batch_iter(&self, chains_len: usize) -> CugparckResult<Self::BatchIterator> {
        Ok(iter::once(BatchInfo {
            range: 0..chains_len,
        }))
    }

    fn start_kernel<'a>(
        &mut self,
        batch: &'a mut [CompressedPassword],
        _batch_info: &Self::BatchInfo,
        columns: Range<usize>,
        ctx: RainbowTableCtx,
    ) -> CugparckResult<KernelHandle<()>> {
        batch
            .par_iter_mut()
            .for_each(|midpoint| midpoint.continue_chain(columns.clone(), &ctx));

        Ok(KernelHandle::Sync)
    }
}

/// A multithreaded CPU backend.
pub struct Cpu;

impl Backend for Cpu {
    type Renderer = CpuRenderer;

    fn renderer(_chains_len: usize) -> CugparckResult<Self::Renderer> {
        Self::Renderer::new()
    }
}
