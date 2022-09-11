#![cfg_attr(
    target_os = "cuda",
    no_std,
    feature(register_attr),
    register_attr(nvvm_internal)
)]
#![allow(improper_ctypes_definitions, clippy::missing_safety_doc)]

use cuda_std::{kernel, thread::index_1d};
use cugparck_commons::{CompressedPassword, RainbowTableCtx};

#[kernel]
pub unsafe fn chains_kernel(
    col_start: usize,
    col_end: usize,
    midpoints: *mut CompressedPassword,
    midpoints_len: usize,
    ctx: RainbowTableCtx,
) {
    let index = index_1d() as usize;

    if index >= midpoints_len {
        return;
    }

    let midpoint = &mut *midpoints.add(index);
    midpoint.continue_chain(col_start..col_end, &ctx)
}
