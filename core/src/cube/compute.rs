use core::fmt::Debug;
use cube::hash::md4::{md4, ntlm};
use cubecl::prelude::*;
use std::hash::Hash;

use crate::{ctx::RainbowTableCtx, cube, hash::HashFunction, CompressedPassword};

/// The CubeCL kernel.
/// It computes the chains of the rainbow table in parallel.
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

/// An ASCII password stored in a stack-allocated vector that lives on the GPU.
#[derive(CubeType, CubeLaunch)]
pub struct Password {
    pub data: Array<u8>,
    pub len: u8,
}

#[cube]
impl Password {
    pub fn new(#[comptime] max_password_length: u8) -> Self {
        Password {
            data: Array::new(comptime!(max_password_length as u32)),
            len: 0,
        }
    }

    pub fn push(&mut self, c: u8) {
        self.data[self.len as u32] = c;
        self.len += 1;
    }

    pub fn len(&self) -> u32 {
        self.len as u32
    }
}

#[cube]
pub fn continue_chain(
    compressed_password: u64,
    columns_start: u64,
    columns_end: u64,
    runtime_ctx: &RuntimeGpuCtx,
    #[comptime] comptime_ctx: ComptimeGpuCtx,
) -> u64 {
    let mut compressed_password2 = compressed_password;

    for i in columns_start..columns_end {
        let plaintext = counter_to_plaintext(compressed_password2, runtime_ctx, comptime_ctx);

        let digest = match comptime!(comptime_ctx.hash_function) {
            HashFunction::Md4 => md4(&plaintext),
            HashFunction::Ntlm => ntlm(&plaintext, comptime_ctx.max_password_length),
            _ => todo!("Reimplement all hash functions"),
        };

        compressed_password2 = reduce(digest, i, runtime_ctx);
    }

    compressed_password2
}

/// Converts a character from a charset to its ASCII representation.
#[cube]
pub fn charset_to_ascii(n: u64, charset: &Array<u8>) -> u8 {
    charset[n as u32]
}

/// Converts an ASCII character to the given charset.
#[cube]
pub fn ascii_to_charset(c: u8, charset: &Array<u8>) -> u8 {
    let mut i: u32 = 0;
    for _ in 0..charset.len() {
        if c == charset[i] {
            break;
        }
        i += 1;
    }

    i as u8
}

/// A digest stored in an array of bytes.
pub type Digest = Array<u8>;

/// The runtime context of the rainbow table.
#[derive(CubeType, CubeLaunch)]
pub struct RuntimeGpuCtx {
    pub charset: Array<u8>,
    pub n: u64,
    pub search_spaces: Array<u64>,
    pub tn: u8,
}

/// The comptime context of the rainbow table.
/// It is used to store the parameters that are known at compile time.
/// They are used to generate JIT an optimized kernel.
#[derive(CubeType, Clone, Copy, PartialEq, Eq, Debug, Hash)]
pub struct ComptimeGpuCtx {
    pub max_password_length: u8,
    pub digest_size: u16,
    pub hash_function: HashFunction,
}

impl RainbowTableCtx {
    pub fn to_comptime_runtime<'a, Backend: Runtime>(
        &self,
        charset_arg: ArrayArg<'a, Backend>,
        search_spaces_arg: ArrayArg<'a, Backend>,
    ) -> (ComptimeGpuCtx, RuntimeGpuCtxLaunch<'a, Backend>) {
        let comptime_ctx = ComptimeGpuCtx {
            digest_size: self.hash_function.cpu().output_size() as u16,
            max_password_length: self.max_password_length,
            hash_function: self.hash_function,
        };

        let runtime_ctx = RuntimeGpuCtxLaunch::new(
            charset_arg,
            ScalarArg::new(self.n),
            search_spaces_arg,
            ScalarArg::new(self.tn),
        );

        (comptime_ctx, runtime_ctx)
    }
}

/// Reduces a digest into a password.
// Notice how we multiply the table number with the iteration instead of just adding it.
// This allows the reduce functions to be very different from one table to another.
// On 4 tables, it bumps the success rate from 96.5% to 99.9% (way closer to the theoritical bound).
#[cube]
pub fn reduce(digest: Digest, iteration: u64, runtime_ctx: &RuntimeGpuCtx) -> CompressedPassword {
    // we can use the 8 first bytes of the digest as the seed, since it is pseudo-random.
    let mut seed = 0;
    for i in 0..8 {
        seed |= (digest[i as u32] as u64) << (i * 8);
    }

    // (seed + iteration * runtime_ctx.tn as u64) % runtime_ctx.n
    (seed + iteration * runtime_ctx.tn as u64) % runtime_ctx.n
}

/// Creates a plaintext from a counter.
#[cube]
pub fn counter_to_plaintext(
    counter: CompressedPassword,
    runtime_ctx: &RuntimeGpuCtx,
    #[comptime] comptime_ctx: ComptimeGpuCtx,
) -> Password {
    let mut search_space_index = runtime_ctx.search_spaces.len() - 1;
    let mut counter2 = counter;

    loop {
        let space = runtime_ctx.search_spaces[search_space_index];
        if counter2 >= space {
            break;
        }
        search_space_index -= 1;
    }
    let mut plaintext = Password::new(comptime_ctx.max_password_length);

    counter2 -= runtime_ctx.search_spaces[search_space_index];

    for _ in 0..search_space_index {
        plaintext.push(charset_to_ascii(
            counter2 % runtime_ctx.charset.len() as u64,
            &runtime_ctx.charset,
        ));
        counter2 /= runtime_ctx.charset.len() as u64;
    }

    plaintext
}

/// Creates a counter from a plaintext.
#[cube]
fn plaintext_to_counter(plaintext: Password, runtime_ctx: &RuntimeGpuCtx) -> CompressedPassword {
    let mut counter = runtime_ctx.search_spaces[plaintext.len()];
    let mut charset_base = 1;

    for i in 0..plaintext.len() {
        counter += ascii_to_charset(plaintext.data[i], &runtime_ctx.charset) as u64 * charset_base;
        charset_base *= runtime_ctx.charset.len() as u64;
    }

    counter
}

#[cfg(test)]
mod tests {
    use cubecl::prelude::*;
    use cubecl_wgpu::WgpuRuntime;

    use crate::{
        ctx::build_test_ctx,
        cube::compute::{ascii_to_charset, counter_to_plaintext},
        DEFAULT_CHARSET,
    };

    use super::{ComptimeGpuCtx, RuntimeGpuCtx};

    #[cube(launch)]
    fn test_ascii_to_charset_kernel(c: &Array<u8>, charset: &Array<u8>, output: &mut Array<u8>) {
        output[ABSOLUTE_POS] = ascii_to_charset(c[ABSOLUTE_POS], charset);
    }

    #[test]
    fn test_ascii_to_charset() {
        let client = WgpuRuntime::client(&Default::default());
        let c_handle = client.create(b"9_");
        let charset_handle = client.create(DEFAULT_CHARSET);
        let output_handle = client.empty(2);

        test_ascii_to_charset_kernel::launch::<WgpuRuntime>(
            &client,
            CubeCount::new_1d(2),
            CubeDim::new_single(),
            unsafe { ArrayArg::from_raw_parts::<u8>(&c_handle, 2, 1) },
            unsafe { ArrayArg::from_raw_parts::<u8>(&charset_handle, DEFAULT_CHARSET.len(), 1) },
            unsafe { ArrayArg::from_raw_parts::<u8>(&output_handle, 2, 1) },
        );

        let actual_output = client.read_one(output_handle);
        assert_eq!(&[9, 63], actual_output.as_slice());
    }

    #[cube(launch)]
    fn test_counter_to_plaintext_kernel(
        counter: Array<u64>,
        runtime_ctx: RuntimeGpuCtx,
        output: &mut Array<u8>,
        #[comptime] comptime_ctx: ComptimeGpuCtx,
    ) {
        let plaintext = counter_to_plaintext(counter[ABSOLUTE_POS], &runtime_ctx, comptime_ctx);
        for i in 0..plaintext.len() {
            output[i] = plaintext.data[i];
        }

        for i in plaintext.len()..output.len() {
            output[i] = 0;
        }
    }

    #[test]
    fn test_counter_to_plaintext() {
        let ctx = build_test_ctx();
        let client = WgpuRuntime::client(&Default::default());
        let charset_handle = client.create(&ctx.charset);
        let search_spaces_handle = client.create(u64::as_bytes(&ctx.search_spaces));

        let launch_for_i = |i| -> Vec<u8> {
            let counter_handle = client.create(u64::as_bytes(&[i as u64]));
            let counter_arg = unsafe { ArrayArg::from_raw_parts::<u64>(&counter_handle, 1, 1) };

            let (comptime_ctx, runtime_ctx) = ctx.to_comptime_runtime(
                unsafe { ArrayArg::from_raw_parts::<u8>(&charset_handle, ctx.charset.len(), 1) },
                unsafe {
                    ArrayArg::from_raw_parts::<u64>(
                        &search_spaces_handle,
                        ctx.search_spaces.len(),
                        1,
                    )
                },
            );
            let output_handle = client.empty(ctx.max_password_length as usize);

            test_counter_to_plaintext_kernel::launch::<WgpuRuntime>(
                &client,
                CubeCount::new_1d(1),
                CubeDim::new_single(),
                counter_arg,
                runtime_ctx,
                unsafe { ArrayArg::from_raw_parts::<u8>(&output_handle, 10, 1) },
                comptime_ctx,
            );

            client
                .read_one(output_handle)
                .iter()
                .take_while(|c| **c != 0)
                .copied()
                .collect()
        };

        let expected_outputs: &[&[u8]] = &[
            b"", b"a", b"b", b"c", b"aa", b"ba", b"ca", b"ab", b"bb", b"cb", b"ac", b"bc", b"cc",
            b"aaa",
        ];

        for (i, expected_output) in expected_outputs.iter().enumerate() {
            let actual_output = launch_for_i(i);
            assert_eq!(expected_output, &actual_output);
        }
    }
}
