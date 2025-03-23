use serde::{Deserialize, Serialize};

use crate::{
    error::{CugparckError, CugparckResult},
    hash::HashFunction,
    DEFAULT_APLHA, DEFAULT_CHAIN_LENGTH, DEFAULT_CHARSET, DEFAULT_MAX_PASSWORD_LENGTH,
    DEFAULT_TABLE_NUMBER, MAX_PASSWORD_LENGTH_ALLOWED,
};

/// A builder for a rainbow table context.
#[derive(Clone)]
pub struct RainbowTableCtxBuilder {
    hash_function: HashFunction,
    charset: Vec<u8>,
    t: u64,
    tn: u8,
    max_password_length: u8,
    m0: Option<u64>,
    alpha: f64,
}

impl Default for RainbowTableCtxBuilder {
    fn default() -> Self {
        Self {
            hash_function: HashFunction::Ntlm,
            charset: DEFAULT_CHARSET.to_owned(),
            max_password_length: DEFAULT_MAX_PASSWORD_LENGTH,
            t: DEFAULT_CHAIN_LENGTH,
            tn: DEFAULT_TABLE_NUMBER + 1,
            m0: None,
            alpha: DEFAULT_APLHA,
        }
    }
}

impl RainbowTableCtxBuilder {
    /// Creates a new RainbowTableCtxBuilder.
    pub fn new() -> Self {
        Self::default()
    }

    /// Sets the hash function of the context.
    pub fn hash(mut self, hash_function: HashFunction) -> Self {
        self.hash_function = hash_function;

        self
    }

    /// Sets the charset of the context.
    pub fn charset(mut self, charset: &[u8]) -> Self {
        self.charset = charset.to_owned();

        self
    }

    /// Sets the length of the chain of the context.
    /// Increasing the chain length will reduce the memory used
    /// to store the table but increase the time taken to attack.
    pub fn chain_length(mut self, chain_length: u64) -> Self {
        self.t = chain_length;

        self
    }

    /// Sets the maximum password length of the context.
    pub fn max_password_length(mut self, max_password_length: u8) -> Self {
        self.max_password_length = max_password_length;

        self
    }

    /// Sets the table number of the context.
    pub fn table_number(mut self, table_number: u8) -> Self {
        // table numbers are 1-indexed internally, so that the reduce function
        // has more randomness.
        self.tn = table_number + 1;

        self
    }

    /// Sets the number of startpoints of the context.
    /// It is not recommended to use this method directly unless you know what you are doing.
    /// Prefer using `RainbowTableCtxBuilder::alpha`.
    pub fn startpoints(mut self, startpoints: Option<u64>) -> Self {
        self.m0 = startpoints;

        self
    }

    /// Sets the maximality factor (alpha) of the context.
    /// The maximality factor is used to determine the number of startpoints.
    /// It is an indicator of how well the table will perform compared to a maximum table.
    pub fn alpha(mut self, alpha: f64) -> Self {
        self.alpha = alpha;

        self
    }

    /// Builds a RainbowTableCtx with the specified parameters.
    pub fn build(mut self) -> CugparckResult<RainbowTableCtx> {
        if self.max_password_length > MAX_PASSWORD_LENGTH_ALLOWED as u8 {
            return Err(CugparckError::MaxPasswordLengthExcedeed(
                MAX_PASSWORD_LENGTH_ALLOWED as u8,
            ));
        }

        // create the search spaces
        let mut n: u128 = 0;
        let mut search_spaces = Vec::new();

        search_spaces.push(n as u64);
        for i in 0..self.max_password_length {
            n += self.charset.len().pow(i as u32) as u128;
            search_spaces.push(n as u64);
        }
        n += self.charset.len().pow(self.max_password_length as u32) as u128;

        // make sure the search space is <= 2^64
        if n > u64::MAX as u128 {
            return Err(CugparckError::Space((n as f64).log2().ceil() as u8));
        }

        let n = n as u64;

        // find the number of startpoints
        let m0 = if let Some(m0) = self.m0 {
            m0
        } else {
            let mtmax = (2. * n as f64) / (self.t + 2) as f64;

            if self.alpha == 1. {
                n
            } else {
                let m0 = DEFAULT_APLHA / (1. - DEFAULT_APLHA) * mtmax;
                m0.clamp(1., n as f64) as u64
            }
        };

        self.charset.sort_unstable();

        Ok(RainbowTableCtx {
            search_spaces,
            m0,
            hash_function: self.hash_function,
            n,
            charset: self.charset,
            max_password_length: self.max_password_length,
            t: self.t,
            tn: self.tn,
        })
    }
}

/// Context used to store all parameters used to generate a rainbow table.
#[derive(Clone, Debug, Serialize, Deserialize)]
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

#[cfg(test)]
pub fn build_test_ctx() -> RainbowTableCtx {
    RainbowTableCtx {
        hash_function: HashFunction::Md4,
        search_spaces: vec![0, 1, 4, 13, 40, 121, 364],
        charset: b"abc".to_vec(),
        max_password_length: DEFAULT_MAX_PASSWORD_LENGTH,
        t: DEFAULT_CHAIN_LENGTH,
        tn: DEFAULT_TABLE_NUMBER + 1,
        m0: 0,
        n: 0,
    }
}
