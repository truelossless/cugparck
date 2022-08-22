#![no_std]

#[cfg(not(any(target_os = "cuda", target_arch = "spirv")))]
extern crate std;

mod ntlm;

use ntlm::ntlm;
pub use tinyvec::ArrayVec;

use core::{
    fmt::{Debug, Display},
    ops::{Deref, DerefMut, Range},
};

use md4::{Digest as _, Md4};
use md5::Md5;
use sha1::Sha1;
use sha2::{Sha224, Sha256, Sha384, Sha512};
use sha3::{Sha3_224, Sha3_256, Sha3_384, Sha3_512};

#[cfg(not(any(target_os = "cuda", target_arch = "spirv")))]
use {
    bytecheck::CheckBytes,
    rkyv::{Archive, Deserialize, Serialize},
};

/// The default number of filters.
/// "Precomputation for Rainbow Tables has Never Been so Fast" figure 3 shows that 20 is a reasonable number.
pub const DEFAULT_FILTER_COUNT: usize = 20;

/// The default chain length.
pub const DEFAULT_CHAIN_LENGTH: usize = 10_000;

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
pub const MAX_DIGEST_LENGTH_ALLOWED: usize = 64;

/// The maximum charset length allowed.
pub const MAX_CHARSET_LENGTH_ALLOWED: usize = 126;

/// An ASCII password stored in a stack-allocated vector.
#[repr(transparent)]
#[derive(Clone, Copy, Default, PartialEq, Eq)]
pub struct Password(ArrayVec<[u8; MAX_PASSWORD_LENGTH_ALLOWED]>);

impl Password {
    /// Creates a new password.
    pub fn new(text: &[u8]) -> Self {
        Password(text.try_into().unwrap())
    }
}

impl AsRef<[u8]> for Password {
    fn as_ref(&self) -> &[u8] {
        &self.0
    }
}

impl Deref for Password {
    type Target = ArrayVec<[u8; MAX_PASSWORD_LENGTH_ALLOWED]>;

    fn deref(&self) -> &Self::Target {
        &self.0
    }
}

impl DerefMut for Password {
    fn deref_mut(&mut self) -> &mut Self::Target {
        &mut self.0
    }
}

impl Display for Password {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        write!(f, "{}", core::str::from_utf8(&self.0).unwrap())?;

        Ok(())
    }
}

impl Debug for Password {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        <Password as Display>::fmt(self, f)
    }
}

/// A compressed password. It doesn´t make any assumption on the charset used, so
/// two compressed passwords from two tables using different charsets
/// are not equal if their inner usize is equal.
#[repr(transparent)]
#[cfg_attr(
    not(any(target_os = "cuda", target_arch = "spirv")),
    derive(Archive, Deserialize, Serialize),
    archive_attr(derive(CheckBytes, PartialEq, Eq, Hash, Clone, Copy))
)]
#[derive(Clone, Copy, Default, Debug, PartialEq, Eq, Hash, PartialOrd, Ord)]
#[cfg_attr(target_arch = "spirv", derive(bytemuck::Zeroable, bytemuck::Pod))]
pub struct CompressedPassword(usize);

impl CompressedPassword {
    #[inline]
    pub fn into_password(self, ctx: &RainbowTableCtx) -> Password {
        counter_to_plaintext(self.0, ctx)
    }

    #[inline]
    pub fn from_password(password: Password, ctx: &RainbowTableCtx) -> Self {
        CompressedPassword(plaintext_to_counter(password, ctx))
    }

    pub fn get(&self) -> usize {
        self.0
    }
}

impl From<usize> for CompressedPassword {
    fn from(password: usize) -> Self {
        CompressedPassword(password)
    }
}

#[cfg(not(any(target_os = "cuda", target_arch = "spirv")))]
impl From<ArchivedCompressedPassword> for CompressedPassword {
    fn from(ar: ArchivedCompressedPassword) -> Self {
        CompressedPassword(ar.0 as usize)
    }
}

#[cfg(not(any(target_os = "cuda", target_arch = "spirv")))]
impl From<CompressedPassword> for ArchivedCompressedPassword {
    fn from(password: CompressedPassword) -> Self {
        ArchivedCompressedPassword(password.0 as u64)
    }
}

#[cfg(not(any(target_os = "cuda", target_arch = "spirv")))]
impl nohash_hasher::IsEnabled for CompressedPassword {}

/// Converts a character from a charset to its ASCII representation.
#[inline]
pub fn charset_to_ascii(n: usize, charset: &[u8]) -> u8 {
    charset[n as usize]
}

/// Converts an ASCII character to the given charset.
#[inline]
pub fn ascii_to_charset(c: u8, charset: &[u8]) -> u8 {
    charset.iter().position(|x| *x == c).unwrap() as u8
}

/// A digest stored in a stack-allocated vector.
pub type Digest = ArrayVec<[u8; MAX_DIGEST_LENGTH_ALLOWED]>;

/// All the supported hash functions.
#[cfg_attr(
    not(any(target_os = "cuda", target_arch = "spirv")),
    derive(Archive, Deserialize, Serialize),
    archive_attr(derive(CheckBytes))
)]
#[repr(usize)]
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
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
    /// Hashes a byte slice using the right hash function.
    #[inline]
    pub fn hash(&self, password: Password) -> ArrayVec<[u8; MAX_DIGEST_LENGTH_ALLOWED]> {
        match self {
            HashType::Ntlm => ntlm(&password).as_slice().try_into().unwrap(),
            HashType::Md4 => Md4::digest(&password).as_slice().try_into().unwrap(),
            HashType::Md5 => Md5::digest(&password).as_slice().try_into().unwrap(),
            HashType::Sha1 => Sha1::digest(&password).as_slice().try_into().unwrap(),
            HashType::Sha2_224 => Sha224::digest(&password).as_slice().try_into().unwrap(),
            HashType::Sha2_256 => Sha256::digest(&password).as_slice().try_into().unwrap(),
            HashType::Sha2_384 => Sha384::digest(&password).as_slice().try_into().unwrap(),
            HashType::Sha2_512 => Sha512::digest(&password).as_slice().try_into().unwrap(),
            HashType::Sha3_224 => Sha3_224::digest(&password).as_slice().try_into().unwrap(),
            HashType::Sha3_256 => Sha3_256::digest(&password).as_slice().try_into().unwrap(),
            HashType::Sha3_384 => Sha3_384::digest(&password).as_slice().try_into().unwrap(),
            HashType::Sha3_512 => Sha3_512::digest(&password).as_slice().try_into().unwrap(),
        }
    }

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
#[repr(C)]
#[cfg_attr(
    not(any(target_os = "cuda", target_arch = "spirv")),
    derive(Archive, Deserialize, Serialize),
    archive_attr(derive(CheckBytes))
)]
#[derive(Clone, Copy, Debug)]
pub struct RainbowTableCtx {
    /// The number of starting chains to generate.
    pub m0: usize,
    /// The type of the hash function used.
    pub hash_type: HashType,
    /// The charset used.
    pub charset: ArrayVec<[u8; MAX_CHARSET_LENGTH_ALLOWED]>,
    /// The length of a chain.
    pub t: usize,
    /// The maximum password length.
    pub max_password_length: usize,
    /// The size of the total search space.
    pub n: usize,
    /// A rainbow table has to search through passwords of a variable length.
    /// This is used to determine the search space for each password length.
    pub search_spaces: ArrayVec<[usize; MAX_PASSWORD_LENGTH_ALLOWED + 1]>,
    /// The table number.
    pub tn: usize,
}

// SAFETY: All fields can be initialized to 0.
#[cfg(target_arch = "spirv")]
unsafe impl bytemuck::Zeroable for RainbowTableCtx {}

// SAFETY: No pointers are used.
// The struct doesn't have padding as all fields are 64-bit aligned.
#[cfg(target_arch = "spirv")]
unsafe impl bytemuck::Pod for RainbowTableCtx {}

// SAFETY: No pointers in the struct.
#[cfg(feature = "cuda")]
unsafe impl cust_core::DeviceCopy for RainbowTableCtx {}

/// A struct that can be passed as a single argument to the GPU and that includes all arguments needed by the kernel.
#[repr(C)]
#[derive(Clone, Copy)]
#[cfg_attr(target_arch = "spirv", derive(bytemuck::Zeroable, bytemuck::Pod))]
pub struct FullCtx {
    /// The start of the column.
    pub col_start: usize,
    /// The end of the column.
    pub col_end: usize,
    /// The context.
    pub ctx: RainbowTableCtx,
}

/// A chain of the rainbow table, made of a startpoint and an endpoint.
#[repr(C)]
#[cfg_attr(
    not(any(target_os = "cuda", target_arch = "spirv")),
    derive(Archive, Deserialize, Serialize),
    archive_attr(derive(CheckBytes))
)]
#[derive(Clone, Copy, Default, Debug, PartialEq, Eq)]
#[cfg_attr(target_arch = "spirv", derive(bytemuck::Zeroable, bytemuck::Pod))]
pub struct RainbowChain {
    pub startpoint: CompressedPassword,
    pub endpoint: CompressedPassword,
}

impl RainbowChain {
    pub fn new(startpoint: Password, endpoint: Password, ctx: &RainbowTableCtx) -> RainbowChain {
        RainbowChain {
            startpoint: CompressedPassword::from_password(startpoint, ctx),
            endpoint: CompressedPassword::from_password(endpoint, ctx),
        }
    }

    pub fn from_compressed(
        startpoint: CompressedPassword,
        endpoint: CompressedPassword,
    ) -> RainbowChain {
        RainbowChain {
            startpoint,
            endpoint,
        }
    }

    pub fn continue_chain(&mut self, columns: Range<usize>, ctx: &RainbowTableCtx) {
        let mut midpoint = self.endpoint.into_password(ctx);

        for i in columns {
            let digest = hash(midpoint, ctx);
            midpoint = reduce(digest, i, ctx);
        }

        self.endpoint = CompressedPassword::from_password(midpoint, ctx);
    }
}

#[cfg(not(any(target_os = "cuda", target_arch = "spirv")))]
impl ArchivedRainbowChain {
    pub fn from_compressed(
        startpoint: CompressedPassword,
        endpoint: CompressedPassword,
    ) -> ArchivedRainbowChain {
        ArchivedRainbowChain {
            startpoint: ArchivedCompressedPassword(startpoint.0 as u64),
            endpoint: ArchivedCompressedPassword(endpoint.0 as u64),
        }
    }
}

// SAFETY: No pointers in the struct.
#[cfg(feature = "cuda")]
unsafe impl cust_core::DeviceCopy for RainbowChain {}

/// Reduces a digest into a password.
// Notice how we multiply the table number with the iteration instead of just adding it.
// This allows the reduce functions to be very different from one table to another.
// On 4 tables, it bumps the success rate from 96.5% to 99.9% (way closer to the theorical bound).
#[inline]
pub fn reduce(digest: Digest, iteration: usize, ctx: &RainbowTableCtx) -> Password {
    // we can use the 8 first bytes of the digest as it is pseudo-random.
    let counter = (usize::from_le_bytes(digest[0..8].try_into().unwrap())
        .wrapping_add(iteration.wrapping_mul(ctx.tn as usize)))
        % ctx.n as usize;
    counter_to_plaintext(counter, ctx)
}

/// Hashes a password into a digest.
#[inline]
pub fn hash(password: Password, ctx: &RainbowTableCtx) -> Digest {
    ctx.hash_type.hash(password)
}

/// Creates a plaintext from a counter.
#[inline]
pub fn counter_to_plaintext(mut counter: usize, ctx: &RainbowTableCtx) -> Password {
    let mut plaintext = Password::default();
    let search_space_rev = ctx
        .search_spaces
        .iter()
        .rev()
        .position(|space| counter >= *space)
        .unwrap();
    let len = ctx.search_spaces.len() - search_space_rev - 1;

    counter -= ctx.search_spaces[len];

    for _ in 0..len {
        plaintext.push(charset_to_ascii(counter % ctx.charset.len(), &ctx.charset));
        counter /= ctx.charset.len();
    }

    plaintext
}

/// Creates a counter from a plaintext.
#[inline]
fn plaintext_to_counter(plaintext: Password, ctx: &RainbowTableCtx) -> usize {
    let mut counter = ctx.search_spaces[plaintext.len()];
    for (i, &c) in plaintext.iter().enumerate() {
        counter += ascii_to_charset(c, &ctx.charset) as usize * ctx.charset.len().pow(i as u32);
    }

    counter
}

#[cfg(test)]
mod tests {
    use tinyvec::array_vec;

    use crate::{
        ascii_to_charset, counter_to_plaintext, plaintext_to_counter, HashType, Password,
        RainbowTableCtx, DEFAULT_CHAIN_LENGTH, DEFAULT_CHARSET, DEFAULT_MAX_PASSWORD_LENGTH,
        DEFAULT_TABLE_NUMBER,
    };

    fn build_ctx() -> RainbowTableCtx {
        RainbowTableCtx {
            hash_type: HashType::Ntlm,
            search_spaces: array_vec![0, 1, 4, 13, 40, 121, 364],
            charset: b"abc".as_slice().try_into().unwrap(),
            max_password_length: DEFAULT_MAX_PASSWORD_LENGTH as usize,
            t: DEFAULT_CHAIN_LENGTH,
            tn: DEFAULT_TABLE_NUMBER as usize,
            m0: 0,
            n: 0,
        }
    }

    #[test]
    fn test_ascii_to_charset() {
        assert_eq!(9, ascii_to_charset(b'9', DEFAULT_CHARSET));
        assert_eq!(63, ascii_to_charset(b'_', DEFAULT_CHARSET));
    }

    #[test]
    fn test_counter_to_plaintext() {
        let ctx = build_ctx();

        let plaintexts = (0..14).map(|i| counter_to_plaintext(i, &ctx));

        let expected = [
            Password::new(b""),
            Password::new(b"a"),
            Password::new(b"b"),
            Password::new(b"c"),
            Password::new(b"aa"),
            Password::new(b"ba"),
            Password::new(b"ca"),
            Password::new(b"ab"),
            Password::new(b"bb"),
            Password::new(b"cb"),
            Password::new(b"ac"),
            Password::new(b"bc"),
            Password::new(b"cc"),
            Password::new(b"aaa"),
        ];

        assert!(expected.into_iter().eq(plaintexts));
    }

    #[test]
    fn test_plaintext_to_counter() {
        let ctx = build_ctx();

        let counters = [
            Password::new(b""),
            Password::new(b"a"),
            Password::new(b"b"),
            Password::new(b"c"),
            Password::new(b"aa"),
            Password::new(b"ba"),
            Password::new(b"ca"),
            Password::new(b"ab"),
            Password::new(b"bb"),
            Password::new(b"cb"),
            Password::new(b"ac"),
            Password::new(b"bc"),
            Password::new(b"cc"),
            Password::new(b"aaa"),
        ]
        .map(|plaintext| plaintext_to_counter(plaintext, &ctx));

        let expected = 0..14;

        assert!(expected.into_iter().eq(counters));
    }
}
