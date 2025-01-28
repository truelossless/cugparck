mod cpu;
mod ctx;
mod cube;
mod error;
mod event;
mod hash;
mod rainbow_table;
mod scheduling;

pub use {
    cpu::{Digest, Password},
    ctx::{RainbowTableCtx, RainbowTableCtxBuilder},
    cubecl::{cuda::CudaRuntime, wgpu::WgpuRuntime},
    event::Event,
    hash::HashFunction,
    rainbow_table::{ClusterTable, CompressedTable, RainbowTable, SimpleTable},
};

/// The default number of filters.
/// "Precomputation for Rainbow Tables has Never Been so Fast" figure 3 shows that 20 is a reasonable number.
const DEFAULT_FILTER_COUNT: usize = 20;

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
const DEFAULT_TABLE_NUMBER: u8 = 0;

/// The maximum password size allowed.
/// This is currently the maximum md4 length supported by the gpu implementation,
/// divided by 2 because ntlm uses UTF-16.
const MAX_PASSWORD_LENGTH_ALLOWED: usize = 27;

/// A compressed password. It doesn´t make any assumption on the charset used, so
/// two compressed passwords from two tables using different charsets
/// are not equal if their inner usize is equal.
pub type CompressedPassword = u64;
