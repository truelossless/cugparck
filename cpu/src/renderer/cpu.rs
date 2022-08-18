//! Multithreaded CPU renderer.

use std::{
    borrow::Cow,
    iter::{self, Once},
    ops::Range,
};

use cugparck_commons::{RainbowChain, RainbowTableCtx};
use rayon::prelude::*;

use crate::error::CugparckResult;

use super::Renderer;

pub struct BatchInfo {
    pub range: Range<usize>,
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

    fn batch_iter(&self, chains_len: usize) -> CugparckResult<Self::BatchIterator> {
        Ok(iter::once(BatchInfo {
            range: 0..chains_len,
        }))
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
        batch: &'a mut [RainbowChain],
        _batch_info: &Self::BatchInfo,
        columns: Range<usize>,
        ctx: RainbowTableCtx,
    ) -> CugparckResult<Cow<'a, [RainbowChain]>> {
        batch
            .par_iter_mut()
            .for_each(|partial_chain| partial_chain.continue_chain(columns.clone(), &ctx));

        Ok(Cow::Borrowed(batch))
    }
}
