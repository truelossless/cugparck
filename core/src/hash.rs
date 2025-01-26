pub mod ntlm;

use cubecl::prelude::*;
use ntlm::md4;
use serde::{Deserialize, Serialize};

use crate::{Digest, GpuPassword};

/// All the supported hash functions.
#[derive(CubeType, Copy, Clone, Debug, Deserialize, Serialize, PartialEq, Eq, Hash)]
pub enum HashFunction {
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

#[cube]
impl HashFunction {
    pub fn hash(#[comptime] &self, password: &GpuPassword) -> Digest {
        md4(password)
    }
}

impl HashFunction {
    /// Gets the digest size in bytes.
    pub fn digest_size(&self) -> u16 {
        match self {
            Self::Ntlm => 16,
            Self::Md4 => 16,
            Self::Md5 => 16,
            Self::Sha1 => 20,
            Self::Sha2_224 => 28,
            Self::Sha2_256 => 32,
            Self::Sha2_384 => 48,
            Self::Sha2_512 => 64,
            Self::Sha3_224 => 28,
            Self::Sha3_256 => 32,
            Self::Sha3_384 => 48,
            Self::Sha3_512 => 64,
        }
    }
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
