#![cfg_attr(
    target_os = "cuda",
    no_std,
    feature(register_attr),
    register_attr(nvvm_internal)
)]
#![allow(improper_ctypes_definitions, clippy::missing_safety_doc)]

use cuda_std::{kernel, thread::index_1d};
use cugparck_commons::{RainbowChain, RainbowTableCtx};

#[kernel]
pub unsafe fn chains_kernel(
    col_start: usize,
    col_end: usize,
    partial_chains: *mut RainbowChain,
    partial_chains_len: usize,
    ctx: RainbowTableCtx,
) {
    let index = index_1d() as usize;

    if index >= partial_chains_len {
        return;
    }

    let partial_chain = &mut *partial_chains.add(index);
    partial_chain.continue_chain(col_start..col_end, &ctx)
}
