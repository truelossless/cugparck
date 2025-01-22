mod ntlm;

use core::fmt::Debug;
use cubecl::prelude::*;
use md4::{Digest as _, Md4};
use md5::Md5;
use serde::{Deserialize, Serialize};
use sha1::Sha1;
use sha2::{Sha224, Sha256, Sha384, Sha512};
use sha3::{Sha3_224, Sha3_256, Sha3_384, Sha3_512};

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

/// The maximum digest size allowed.
pub const MAX_DIGEST_LENGTH_ALLOWED: u16 = 64;

/// The maximum charset length allowed.
pub const MAX_CHARSET_LENGTH_ALLOWED: usize = 126;

/// An ASCII password stored in a stack-allocated vector.
pub type Password = Sequence<u8>;

/// An ASCII password stored in a stack-allocated vector that lives on the GPU.
#[derive(CubeType)]
pub struct GpuPassword {
    pub data: Array<u8>,
    pub len: u8,
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
    // let hash = ctx.hash_type.hash_function();
    let mut compressed_password2 = compressed_password;
    for i in columns_start..columns_end {
        let plaintext = into_gpu_password(compressed_password2, runtime_ctx, comptime_ctx);
        // TODO: reimplement hash functions...
        let mut digest = Digest::new(comptime!(comptime_ctx.digest_size as u32));
        for i in 0..plaintext.len as u32 {
            digest[i] = plaintext.data[i]
        }
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

/// All the supported hash functions.
#[derive(CubeType, Copy, Clone, Debug, Deserialize, Serialize, PartialEq, Eq, Hash)]
pub enum HashType {
    Ntlm,
    Md4,
    Md5,
    Sha1,
    Sha2_224,
    Sha2_256,
    Sha2_384,
    Sha2_512,
    Sha3_224,
    Sha3_256,
    Sha3_384,
    Sha3_512,
}

impl HashType {
    //     /// Gets the right hash function.
    //     pub fn hash_function(&self) -> fn(Password) -> Digest {
    //         // SAFETY: The digests are guaranteed to be smaller or of the same size than the maximum digest size allowed.
    //         unsafe {
    //             match self {
    //                 HashType::Ntlm => {
    //                     |password| ntlm(&password).as_slice().try_into().unwrap_unchecked()
    //                 }
    //                 HashType::Md4 => |password| {
    //                     Md4::digest(password)
    //                         .as_slice()
    //                         .try_into()
    //                         .unwrap_unchecked()
    //                 },
    //                 HashType::Md5 => |password| {
    //                     Md5::digest(password)
    //                         .as_slice()
    //                         .try_into()
    //                         .unwrap_unchecked()
    //                 },
    //                 HashType::Sha1 => |password| {
    //                     Sha1::digest(password)
    //                         .as_slice()
    //                         .try_into()
    //                         .unwrap_unchecked()
    //                 },
    //                 HashType::Sha2_224 => |password| {
    //                     Sha224::digest(password)
    //                         .as_slice()
    //                         .try_into()
    //                         .unwrap_unchecked()
    //                 },
    //                 HashType::Sha2_256 => |password| {
    //                     Sha256::digest(password)
    //                         .as_slice()
    //                         .try_into()
    //                         .unwrap_unchecked()
    //                 },
    //                 HashType::Sha2_384 => |password| {
    //                     Sha384::digest(password)
    //                         .as_slice()
    //                         .try_into()
    //                         .unwrap_unchecked()
    //                 },
    //                 HashType::Sha2_512 => |password| {
    //                     Sha512::digest(password)
    //                         .as_slice()
    //                         .try_into()
    //                         .unwrap_unchecked()
    //                 },
    //                 HashType::Sha3_224 => |password| {
    //                     Sha3_224::digest(password)
    //                         .as_slice()
    //                         .try_into()
    //                         .unwrap_unchecked()
    //                 },
    //                 HashType::Sha3_256 => |password| {
    //                     Sha3_256::digest(password)
    //                         .as_slice()
    //                         .try_into()
    //                         .unwrap_unchecked()
    //                 },
    //                 HashType::Sha3_384 => |password| {
    //                     Sha3_384::digest(password)
    //                         .as_slice()
    //                         .try_into()
    //                         .unwrap_unchecked()
    //                 },
    //                 HashType::Sha3_512 => |password| {
    //                     Sha3_512::digest(password)
    //                         .as_slice()
    //                         .try_into()
    //                         .unwrap_unchecked()
    //                 },
    //             }
    //         }
    //     }

    /// Gets the digest size in bytes.
    pub fn digest_size(&self) -> usize {
        match self {
            HashType::Ntlm => Md4::output_size(),
            HashType::Md4 => Md4::output_size(),
            HashType::Md5 => Md5::output_size(),
            HashType::Sha1 => Sha1::output_size(),
            HashType::Sha2_224 => Sha224::output_size(),
            HashType::Sha2_256 => Sha256::output_size(),
            HashType::Sha2_384 => Sha384::output_size(),
            HashType::Sha2_512 => Sha512::output_size(),
            HashType::Sha3_224 => Sha3_224::output_size(),
            HashType::Sha3_256 => Sha3_256::output_size(),
            HashType::Sha3_384 => Sha3_384::output_size(),
            HashType::Sha3_512 => Sha3_512::output_size(),
        }
    }
}

/// Context used to store all parameters used to generate a rainbow table.
#[derive(Clone, Serialize, Deserialize)]
pub struct RainbowTableCtx {
    /// The number of starting chains to generate.
    pub m0: u64,
    /// The type of the hash function used.
    pub hash_type: HashType,
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
    pub hash_type: HashType,
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
        // SAFETY: The digest is at least 8 bytes long.
        seed |= (digest[i as u32] as u64) << (i * 8);
    }

    (seed + iteration * runtime_ctx.tn as u64) % runtime_ctx.n
}

/// Creates a plaintext from a counter.
#[cube]
pub fn counter_to_plaintext(
    mut counter: u64,
    runtime_ctx: &RuntimeGpuCtx,
    #[comptime] comptime_ctx: ComptimeGpuCtx,
) -> GpuPassword {
    let mut search_space_index: u32 = runtime_ctx.search_spaces.len() - 1u32;

    loop {
        let space = runtime_ctx.search_spaces[search_space_index];
        if counter >= space || search_space_index == 0 {
            break;
        }

        search_space_index -= 1;
    }

    let len = runtime_ctx.search_spaces.len() - search_space_index - 1;
    counter -= runtime_ctx.search_spaces[len];

    let mut plaintext = GpuPassword::new(comptime_ctx);
    for _ in 0..len {
        plaintext.push(charset_to_ascii(
            counter % runtime_ctx.charset.len() as u64,
            &runtime_ctx.charset,
        ));
        counter /= runtime_ctx.charset.len() as u64;
    }

    GpuPassword::new(comptime_ctx)
}

/// Creates a counter from a plaintext.
#[cube]
#[expect(clippy::explicit_counter_loop)]
fn plaintext_to_counter(plaintext: GpuPassword, ctx: &RuntimeGpuCtx) -> u64 {
    let mut counter = ctx.search_spaces[plaintext.len as u32];
    let mut pow = 0;

    for i in 0..plaintext.len as u32 {
        let mut charset_base = ctx.charset.len() as u64;
        for _ in 0..pow {
            charset_base *= charset_base;
        }

        counter += ascii_to_charset(plaintext.data[i], &ctx.charset) as u64 * charset_base;
        pow += 1;
    }

    counter
}

// #[cfg(test)]
// mod tests {
//     use tinyvec::array_vec;
//
//     use crate::{
//         ascii_to_charset, counter_to_plaintext, plaintext_to_counter, HashType, Password,
//         RainbowTableCtx, DEFAULT_CHAIN_LENGTH, DEFAULT_CHARSET, DEFAULT_MAX_PASSWORD_LENGTH,
//         DEFAULT_TABLE_NUMBER,
//     };
//
//     fn build_ctx() -> RainbowTableCtx {
//         RainbowTableCtx {
//             hash_type: HashType::Ntlm,
//             search_spaces: array_vec![0, 1, 4, 13, 40, 121, 364],
//             charset: b"abc".as_slice().try_into().unwrap(),
//             max_password_length: DEFAULT_MAX_PASSWORD_LENGTH as u64,
//             t: DEFAULT_CHAIN_LENGTH,
//             tn: DEFAULT_TABLE_NUMBER as u64,
//             m0: 0,
//             n: 0,
//         }
//     }
//
//     #[test]
//     fn test_ascii_to_charset() {
//         assert_eq!(9, ascii_to_charset(b'9', DEFAULT_CHARSET));
//         assert_eq!(63, ascii_to_charset(b'_', DEFAULT_CHARSET));
//     }
//
//     #[test]
//     fn test_counter_to_plaintext() {
//         let ctx = build_ctx();
//
//         let plaintexts = (0..14).map(|i| counter_to_plaintext(i, &ctx));
//
//         let expected = [
//             Password::new(b""),
//             Password::new(b"a"),
//             Password::new(b"b"),
//             Password::new(b"c"),
//             Password::new(b"aa"),
//             Password::new(b"ba"),
//             Password::new(b"ca"),
//             Password::new(b"ab"),
//             Password::new(b"bb"),
//             Password::new(b"cb"),
//             Password::new(b"ac"),
//             Password::new(b"bc"),
//             Password::new(b"cc"),
//             Password::new(b"aaa"),
//         ];
//
//         assert!(expected.into_iter().eq(plaintexts));
//     }
//
//     #[test]
//     fn test_plaintext_to_counter() {
//         let ctx = build_ctx();
//
//         let counters = [
//             Password::new(b""),
//             Password::new(b"a"),
//             Password::new(b"b"),
//             Password::new(b"c"),
//             Password::new(b"aa"),
//             Password::new(b"ba"),
//             Password::new(b"ca"),
//             Password::new(b"ab"),
//             Password::new(b"bb"),
//             Password::new(b"cb"),
//             Password::new(b"ac"),
//             Password::new(b"bc"),
//             Password::new(b"cc"),
//             Password::new(b"aaa"),
//         ]
//         .map(|plaintext| plaintext_to_counter(plaintext, &ctx));
//
//         let expected = 0..14;
//
//         assert!(expected.into_iter().eq(counters));
//     }
// }
