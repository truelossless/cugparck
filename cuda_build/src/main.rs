use cuda_builder::CudaBuilder;

fn main() {
    CudaBuilder::new("../cuda")
        .copy_to("../module.ptx")
        .build()
        .unwrap();
}
