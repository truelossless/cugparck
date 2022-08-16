fn main() {
    #[cfg(not(target_pointer_width = "64"))]
    {
        compile_error!("Sorry, only 64-bit archs are supported.");
    }

    // if CUDA is used, we need to compile the PTX first.
    // However, rustc_codegen_nvvm requires a specific nightly toolchain that is too old for the whole project.
    // We can directly call cargo to compile with the old toolchain, and then use a newer toolchain elsewhere.
    #[cfg(feature = "cuda")]
    {
        println!("cargo:rerun-if-changed=../cuda/src/lib.rs");
        println!("cargo:rerun-if-changed=../cuda_build/src/main.rs");

        let build = std::process::Command::new("rustup")
            .current_dir(std::env::current_dir().unwrap().join("../cuda_build"))
            .args(&["run", "nightly-2021-12-04", "cargo", "run", "--release"])
            .status()
            .unwrap();

        if !build.success() {
            if let Some(code) = build.code() {
                std::process::exit(code);
            } else {
                std::process::exit(1);
            }
        }
    }
}
