use cuda_builder::CudaBuilder;

fn main() {
    #[cfg(not(target_pointer_width = "64"))]
    {
        compile_error!("Sorry, only 64-bit archs are supported.");
    }
    // println!("cargo:rerun-if-changed=../ntlm/constants.cuh");
    // println!("cargo:rerun-if-changed=../ntlm/ntlm.cuh");
    // println!("cargo:rerun-if-changed=../ntlm/ntlm.cu");

    // // C ntlm functions
    // Command::new("nvcc")
    //     .args(&["../ntlm/ntlm.cu", "-ptx", "-o", "../resources/ntlm.ptx"])
    //     .spawn()
    //     .unwrap();

    CudaBuilder::new("../gpu")
        .copy_to("../module.ptx")
        .build()
        .unwrap();
}
