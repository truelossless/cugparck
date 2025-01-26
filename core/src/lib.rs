pub mod hash;
pub mod utils;

use core::fmt::Debug;
use cubecl::{prelude::*, server::Handle};
use hash::{ntlm::md4, HashFunction};
use serde::{Deserialize, Serialize};

/// The default number of filters.
/// "Precomputation for Rainbow Tables has Never Been so Fast" figure 3 shows that 20 is a reasonable number.
pub const DEFAULT_FILTER_COUNT: usize = 20;

/// The default chain length.
pub const DEFAULT_CHAIN_LENGTH: u64 = 10_000;

/// The default maximality factor.
pub const DEFAULT_APLHA: f64 = 0.952;

/// The default maximum password length.
pub const DEFAULT_MAX_PASSWORD_LENGTH: u8 = 6;

/// The default charset.
pub const DEFAULT_CHARSET: &[u8] =
    b"0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz-_";

/// The default table number.
pub const DEFAULT_TABLE_NUMBER: u8 = 8;

/// The maximum password size allowed.
pub const MAX_PASSWORD_LENGTH_ALLOWED: usize = 10;

/// The maximum charset length allowed.
pub const MAX_CHARSET_LENGTH_ALLOWED: usize = 126;

/// An ASCII password stored in a stack-allocated vector.
pub type Password = Sequence<u8>;

/// An ASCII password stored in a stack-allocated vector that lives on the GPU.
#[derive(CubeLaunch)]
pub struct GpuPassword {
    pub data: Array<u8>,
    len: u8,
}

#[cube]
impl GpuPassword {
    pub fn new(#[comptime] comptime_ctx: ComptimeGpuCtx) -> Self {
        GpuPassword {
            data: Array::new(comptime!(comptime_ctx.max_password_length as u32)),
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

/// A compressed password. It doesn´t make any assumption on the charset used, so
/// two compressed passwords from two tables using different charsets
/// are not equal if their inner usize is equal.
pub type CompressedPassword = u64;

#[cube]
pub fn into_gpu_password(
    compressed_password: CompressedPassword,
    runtime_ctx: &RuntimeGpuCtx,
    #[comptime] comptime_ctx: ComptimeGpuCtx,
) -> GpuPassword {
    counter_to_plaintext(compressed_password, runtime_ctx, comptime_ctx)
}

#[cube]
pub fn from_gpu_password(password: GpuPassword, ctx: &RuntimeGpuCtx) -> CompressedPassword {
    plaintext_to_counter(password, ctx)
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
        // TODO: comptime match on the right hash function
        let digest = md4(&plaintext);
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

/// Context used to store all parameters used to generate a rainbow table.
#[derive(Clone, Serialize, Deserialize)]
pub struct RainbowTableCtx {
    /// The number of starting chains to generate.
    pub m0: u64,
    /// The hash function used.
    pub hash_function: HashFunction,
    /// The charset used.
    pub charset: Vec<u8>,
    /// The length of a chain.
    pub t: u64,
    /// The maximum password length.
    pub max_password_length: u8,
    /// The size of the total search space.
    pub n: u64,
    /// A rainbow table has to search through passwords of a variable length.
    /// This is used to determine the search space for each password length.
    pub search_spaces: Vec<u64>,
    /// The table number.
    pub tn: u8,
}

impl RainbowTableCtx {
    pub fn to_comptime_runtime<'a, Backend: Runtime>(
        &self,
        charset_arg: ArrayArg<'a, Backend>,
        search_spaces_arg: ArrayArg<'a, Backend>,
    ) -> (ComptimeGpuCtx, RuntimeGpuCtxLaunch<'a, Backend>) {
        let comptime_ctx = ComptimeGpuCtx {
            digest_size: self.hash_function.digest_size(),
            max_password_length: self.max_password_length,
            hash_function: self.hash_function,
        };

        let runtime_ctx = RuntimeGpuCtxLaunch::new(
            ScalarArg::new(self.m0),
            charset_arg,
            ScalarArg::new(self.t),
            ScalarArg::new(self.n),
            search_spaces_arg,
            ScalarArg::new(self.tn),
        );

        (comptime_ctx, runtime_ctx)
    }
}

#[derive(CubeLaunch)]
pub struct RuntimeGpuCtx {
    pub m0: u64,
    pub charset: Array<u8>,
    pub t: u64,
    pub n: u64,
    pub search_spaces: Array<u64>,
    pub tn: u8,
}

#[derive(CubeType, Clone, Copy, PartialEq, Eq, Debug, Hash)]
pub struct ComptimeGpuCtx {
    pub max_password_length: u8,
    pub digest_size: u16,
    pub hash_function: HashFunction,
}

/// A chain of the rainbow table, made of a startpoint and an endpoint.
#[derive(Clone, Copy, Default, Debug, PartialEq, Eq)]
pub struct RainbowChain {
    pub startpoint: u64,
    pub endpoint: u64,
}

impl RainbowChain {
    pub fn new(
        startpoint: GpuPassword,
        endpoint: GpuPassword,
        ctx: &RuntimeGpuCtx,
    ) -> RainbowChain {
        RainbowChain {
            startpoint: from_gpu_password(startpoint, ctx),
            endpoint: from_gpu_password(endpoint, ctx),
        }
    }

    pub fn from_compressed(startpoint: u64, endpoint: u64) -> RainbowChain {
        RainbowChain {
            startpoint,
            endpoint,
        }
    }
}

/// Reduces a digest into a password.
// Notice how we multiply the table number with the iteration instead of just adding it.
// This allows the reduce functions to be very different from one table to another.
// On 4 tables, it bumps the success rate from 96.5% to 99.9% (way closer to the theorical bound).
#[cube]
pub fn reduce(digest: Digest, iteration: u64, runtime_ctx: &RuntimeGpuCtx) -> u64 {
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
    counter: u64,
    runtime_ctx: &RuntimeGpuCtx,
    #[comptime] comptime_ctx: ComptimeGpuCtx,
) -> GpuPassword {
    let mut search_space_index: u32 = runtime_ctx.search_spaces.len() - 1;
    let mut counter2 = counter;

    loop {
        let space = runtime_ctx.search_spaces[search_space_index];
        if counter2 >= space {
            break;
        }
        search_space_index -= 1;
    }
    let mut plaintext = GpuPassword::new(comptime_ctx);

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
fn plaintext_to_counter(plaintext: GpuPassword, ctx: &RuntimeGpuCtx) -> u64 {
    let mut counter = ctx.search_spaces[plaintext.len()];
    let mut charset_base = 1;

    for i in 0..plaintext.len() {
        counter += ascii_to_charset(plaintext.data[i], &ctx.charset) as u64 * charset_base;
        charset_base *= ctx.charset.len() as u64;
    }

    counter
}

#[cfg(test)]
mod tests {
    use cubecl::prelude::*;
    use cubecl_cuda::CudaRuntime;

    use crate::{
        ascii_to_charset, counter_to_plaintext, plaintext_to_counter, ComptimeGpuCtx, GpuPassword,
        HashFunction, Password, RainbowTableCtx, RuntimeGpuCtx, DEFAULT_CHAIN_LENGTH,
        DEFAULT_CHARSET, DEFAULT_MAX_PASSWORD_LENGTH, DEFAULT_TABLE_NUMBER,
    };

    fn build_ctx() -> RainbowTableCtx {
        RainbowTableCtx {
            hash_function: HashFunction::Ntlm,
            search_spaces: vec![0, 1, 4, 13, 40, 121, 364],
            charset: b"abc".as_slice().into(),
            max_password_length: DEFAULT_MAX_PASSWORD_LENGTH,
            t: DEFAULT_CHAIN_LENGTH,
            tn: DEFAULT_TABLE_NUMBER,
            m0: 0,
            n: 0,
        }
    }

    #[cube(launch)]
    fn test_ascii_to_charset_kernel(c: &Array<u8>, charset: &Array<u8>, output: &mut Array<u8>) {
        output[ABSOLUTE_POS] = ascii_to_charset(c[ABSOLUTE_POS], charset);
    }

    #[test]
    fn test_ascii_to_charset() {
        let client = CudaRuntime::client(&Default::default());
        let c_handle = client.create(b"9_");
        let charset_handle = client.create(DEFAULT_CHARSET);
        let output_handle = client.empty(2);

        test_ascii_to_charset_kernel::launch::<CudaRuntime>(
            &client,
            CubeCount::new_1d(2),
            CubeDim::new_single(),
            unsafe { ArrayArg::from_raw_parts::<u8>(&c_handle, 2, 1) },
            unsafe { ArrayArg::from_raw_parts::<u8>(&charset_handle, DEFAULT_CHARSET.len(), 1) },
            unsafe { ArrayArg::from_raw_parts::<u8>(&output_handle, 2, 1) },
        );

        let actual_output = client.read_one(output_handle.binding());
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
        let ctx = build_ctx();
        let client = CudaRuntime::client(&Default::default());
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

            test_counter_to_plaintext_kernel::launch::<CudaRuntime>(
                &client,
                CubeCount::new_1d(1),
                CubeDim::new_single(),
                counter_arg,
                runtime_ctx,
                unsafe { ArrayArg::from_raw_parts::<u8>(&output_handle, 10, 1) },
                comptime_ctx,
            );

            client
                .read_one(output_handle.binding())
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
            dbg!("ok");
        }
    }

    // #[test]
    // fn test_plaintext_to_counter() {
    //     let ctx = build_ctx();

    //     let counters = [
    //         Password::new(b""),
    //         Password::new(b"a"),
    //         Password::new(b"b"),
    //         Password::new(b"c"),
    //         Password::new(b"aa"),
    //         Password::new(b"ba"),
    //         Password::new(b"ca"),
    //         Password::new(b"ab"),
    //         Password::new(b"bb"),
    //         Password::new(b"cb"),
    //         Password::new(b"ac"),
    //         Password::new(b"bc"),
    //         Password::new(b"cc"),
    //         Password::new(b"aaa"),
    //     ]
    //     .map(|plaintext| plaintext_to_counter(plaintext, &ctx));

    //     let expected = 0..14;

    //     assert!(expected.into_iter().eq(counters));
    // }
}
