use cubecl::prelude::*;
use cugparck_core::{continue_chain, RainbowTableCtx};

#[cube(launch_unchecked)]
pub fn chains_kernel(
    midpoints: &mut Array<u64>,
    col_start: u64,
    col_end: u64,
    ctx: RainbowTableCtx,
) {
    if ABSOLUTE_POS < midpoints.len() {
        midpoints[ABSOLUTE_POS] = continue_chain(midpoints[ABSOLUTE_POS], col_start, col_end, &ctx);
    }
}
