use cubecl::prelude::*;
use cugparck_core::{continue_chain, ComptimeGpuCtx, RuntimeGpuCtx};

#[cube(launch_unchecked)]
pub fn chains_kernel(
    midpoints: &mut Array<u64>,
    col_start: u64,
    col_end: u64,
    runtime_ctx: RuntimeGpuCtx,
    #[comptime] comptime_ctx: ComptimeGpuCtx,
) {
    if ABSOLUTE_POS < midpoints.len() {
        midpoints[ABSOLUTE_POS] = continue_chain(
            midpoints[ABSOLUTE_POS],
            col_start,
            col_end,
            &runtime_ctx,
            comptime_ctx,
        );
    }
}
