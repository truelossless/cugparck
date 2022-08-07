fn main() {
    #[cfg(not(target_pointer_width = "64"))]
    {
        compile_error!("Sorry, only 64-bit archs are supported.");
    }

    #[cfg(feature = "cuda")]
    {
        cuda_builder::CudaBuilder::new("../gpu")
            .copy_to("../module.ptx")
            .build()
            .unwrap();
    }
}
