use spirv_builder::SpirvBuilder;
use std::fs;

fn main() {
    let result = SpirvBuilder::new("../spirv", "spirv-unknown-vulkan1.1")
        .build()
        .unwrap();

    fs::copy(result.module.unwrap_single(), "../module.spv").unwrap();
}
