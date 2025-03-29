use std::fmt::Display;

use cubecl::prelude::*;
use digest::{Digest as _, DynDigest};
use md4::Md4;
use serde::{Deserialize, Serialize};

use crate::cube::hash::md4::Ntlm;

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

impl HashFunction {
    /// Returns the CPU implementation of this hash.
    pub fn cpu(&self) -> Box<dyn DynDigest> {
        match self {
            Self::Md4 => Box::new(Md4::new()),
            Self::Ntlm => Box::new(Ntlm::new()),
            _ => todo!("Reimplement all hash functions"),
        }
    }
}

impl Display for HashFunction {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{self:?}")
    }
}
