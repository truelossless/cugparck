#![cfg_attr(
    target_arch = "spirv",
    feature(register_attr),
    register_attr(spirv),
    no_std
)]

use cugparck_commons::{FullCtx, RainbowChain};
use spirv_std::glam::UVec3;
#[cfg(not(target_arch = "spirv"))]
use spirv_std::macros::spirv;

#[spirv(compute(threads(64)))]
pub fn chains_kernel(
    #[spirv(global_invocation_id)] id: UVec3,
    #[spirv(storage_buffer, descriptor_set = 0, binding = 0)] partial_chains: &mut [RainbowChain],
    #[spirv(ctx_buffer, descriptor_set = 1, binding = 0)] full_ctx: FullCtx,
) {
    let index = id.x as usize;
    partial_chains[index].continue_chain(full_ctx.col_start..full_ctx.col_end, &full_ctx.ctx);
}
