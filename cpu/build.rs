use std::{
    env,
    process::{self, Command},
};

#[allow(unused)]
fn compile(name: &str, toolchain: &str) {
    println!("cargo:rerun-if-changed=../{name}/src/lib.rs");
    println!("cargo:rerun-if-changed=../{name}_build/src/main.rs");

    let build = Command::new("rustup")
        .current_dir(env::current_dir().unwrap().join(format!("../{name}_build")))
        .args(&["run", toolchain, "cargo", "run", "--release"])
        .status()
        .unwrap();

    if !build.success() {
        if let Some(code) = build.code() {
            process::exit(code);
        } else {
            process::exit(1);
        }
    }
}

fn main() {
    #[cfg(not(target_pointer_width = "64"))]
    {
        compile_error!("Sorry, only 64-bit archs are supported.");
    }

    #[cfg(all(target_os = "macos", feature = "cuda"))]
    {
        compile_error!("Sorry, CUDA is not supported on macOS.");
    }

    // if CUDA is used, we need to compile the PTX first.
    // However, rustc_codegen_nvvm requires a specific nightly toolchain that is too old for the whole project.
    // We can directly call cargo to compile with the old toolchain, and then use a newer toolchain elsewhere.
    #[cfg(feature = "cuda")]
    {
        compile("cuda", "nightly-2021-12-04");
    }

    // For the SPIRV generation, we essentially do the same trick.
    #[cfg(feature = "wgpu")]
    {
        compile("spirv", "nightly-2022-04-11");
    }
}
