use cubecl::prelude::*;

#[macro_export]
macro_rules! test_hash_function {
    ($hash_function:expr, $digest_size:literal, $input:expr, $expected_digest:expr) => {{
        use cubecl::prelude::*;
        use cubecl_cuda::CudaRuntime;

        #[cube(launch)]
        fn hash_kernel(
            input: &$crate::cube::compute::Password,
            output: &mut $crate::cube::compute::Digest,
        ) {
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
            $crate::cube::compute::PasswordLaunch::new(
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

/// Memcopy polyfill for different integer types.
#[cube]
pub fn memcpy<Dst: Int, Src: Int>(
    destination: &mut Array<Dst>,
    source: &Array<Src>,
    len_bytes: u32,
) {
    if comptime!(Dst::BITS > Src::BITS) {
        memcpy_to_bigger_type(destination, source, len_bytes);
    } else {
        memcpy_to_smaller_type(destination, source, len_bytes);
    }
}

#[cube]
#[expect(clippy::manual_div_ceil)]
pub fn memcpy_to_bigger_type<Dst: Int, Src: Int>(
    destination: &mut Array<Dst>,
    source: &Array<Src>,
    len_bytes: u32,
) {
    let type_ratio = Dst::BITS / Src::BITS;
    let dst_len = (len_bytes + (Dst::BITS / 8) - 1) / (Dst::BITS / 8);

    for i in 0..dst_len {
        destination[i] = Dst::cast_from(0);
        for j in 0..type_ratio {
            destination[i] |= Dst::cast_from(
                Dst::cast_from(source[i * type_ratio + j]) << Dst::cast_from(j * Src::BITS),
            );
        }
    }
}

#[cube]
pub fn memcpy_to_smaller_type<Dst: Int, Src: Int>(
    destination: &mut Array<Dst>,
    source: &Array<Src>,
    len_bytes: u32,
) {
    let type_ratio = Src::BITS / Dst::BITS;
    let src_len = len_bytes / (Src::BITS / 8);

    for i in 0..src_len {
        for j in 0..type_ratio {
            destination[i * type_ratio + j] = Dst::cast_from(
                Dst::cast_from(source[i] >> Src::cast_from(j * Dst::BITS))
                    & Dst::cast_from(Dst::max_value()),
            );
        }
    }
}

#[cube]
pub fn rotate_left(a: u32, n: u32) -> u32 {
    (a << n) | (a >> (32 - n))
}
