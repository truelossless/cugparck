#[macro_export]
macro_rules! test_hash_function {
    ($hash_function:expr, $digest_size:literal, $input:literal, $expected_digest:expr) => {{
        use cubecl::prelude::*;
        use cubecl_cuda::CudaRuntime;

        #[cube(launch)]
        fn hash_kernel(input: &$crate::GpuPassword, output: &mut $crate::Digest) {
            let digest = $hash_function(input);
            for i in 0..$digest_size {
                output[i] = digest[i]
            }
        }

        let client = CudaRuntime::client(&Default::default());
        let input_handle = client.create($input.as_bytes());
        let output_handle = client.empty($digest_size);

        hash_kernel::launch::<CudaRuntime>(
            &client,
            CubeCount::new_single(),
            CubeDim::new_single(),
            $crate::GpuPasswordLaunch::new(
                unsafe { ArrayArg::from_raw_parts::<u8>(&input_handle, $input.len(), 1) },
                ScalarArg::new($input.len() as u8),
            ),
            unsafe { ArrayArg::from_raw_parts::<u8>(&output_handle, $digest_size, 1) },
        );

        let actual_digest = client.read_one(output_handle.binding());
        // print as hex bytes
        println!("{:x?}", actual_digest.as_slice());
        assert_eq!($expected_digest, actual_digest.as_slice());
    }};
}
