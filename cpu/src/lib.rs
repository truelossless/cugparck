#![feature(generic_associated_types)]

mod batch;
mod bitvec_wrapper;
mod error;
mod event;
mod rainbow_table;
mod table_cluster;

pub use {
    error::CugparckError,
    event::{Event, SimpleTableHandle},
    memmap2::Mmap,
    rainbow_table::{CompressedTable, RainbowTable, RainbowTableStorage, SimpleTable},
    rkyv::{Deserialize, Infallible, Serialize},
    table_cluster::TableCluster,
};

use std::ops::Range;

use cugparck_commons::{
    ArrayVec, HashType, RainbowTableCtx, DEFAULT_APLHA, DEFAULT_CHAIN_LENGTH, DEFAULT_CHARSET,
    DEFAULT_FILTER_COUNT, DEFAULT_MAX_PASSWORD_LENGTH, DEFAULT_TABLE_NUMBER,
    MAX_CHARSET_LENGTH_ALLOWED,
};

use error::CugparckResult;

/// The CUDA PTX containing the GPU code.
const PTX: &str = include_str!("../../module.ptx");

/// A builder for a rainbow table context.
#[derive(Clone, Copy)]
pub struct RainbowTableCtxBuilder {
    hash_type: HashType,
    charset: ArrayVec<[u8; MAX_CHARSET_LENGTH_ALLOWED]>,
    t: usize,
    tn: u8,
    max_password_length: u8,
    m0: Option<usize>,
    alpha: f64,
}

impl Default for RainbowTableCtxBuilder {
    fn default() -> Self {
        Self {
            hash_type: HashType::Ntlm,
            charset: DEFAULT_CHARSET.try_into().unwrap(),
            max_password_length: DEFAULT_MAX_PASSWORD_LENGTH,
            t: DEFAULT_CHAIN_LENGTH,
            tn: DEFAULT_TABLE_NUMBER,
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
    pub fn hash(mut self, hash_type: HashType) -> Self {
        self.hash_type = hash_type;

        self
    }

    /// Sets the charset of the context.
    pub fn charset(mut self, charset: &[u8]) -> Self {
        self.charset = charset.try_into().expect("Charset should be < 128 chars");

        self
    }

    /// Sets the length of the chain of the context.
    /// Increasing the chain length will reduce the memory used
    /// to store the table but increase the time taken to attack.
    pub fn chain_length(mut self, chain_length: usize) -> Self {
        self.t = chain_length;

        self
    }

    /// Sets the maximum password length of the context.
    pub fn max_password_length(mut self, max_password_length: u8) -> Self {
        self.max_password_length = max_password_length;

        self
    }

    /// Sets the table number of the context.
    /// Table numbers are 1-indexed.
    pub fn table_number(mut self, table_number: u8) -> Self {
        self.tn = table_number;

        self
    }

    /// Sets the number of startpoints of the context.
    /// It is not recommended to use this method directly unless you know what you are doing.
    /// Prefer using `RainbowTableCtxBuilder::alpha`.
    pub fn startpoints(mut self, startpoints: Option<usize>) -> Self {
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
    pub fn build(self) -> CugparckResult<RainbowTableCtx> {
        // create the search spaces
        let mut n: u128 = 0;
        let mut search_spaces = ArrayVec::new();

        search_spaces.push(n as usize);
        for i in 0..self.max_password_length {
            n += self.charset.len().pow(i as u32) as u128;
            search_spaces.push(n as usize);
        }
        n += self.charset.len().pow(self.max_password_length as u32) as u128;

        // make sure the search space is <= 2^64
        if n > usize::MAX as u128 {
            return Err(CugparckError::Space((n as f64).log2().ceil() as u8));
        }

        let n = n as usize;

        // find the number of startpoints
        let m0 = if let Some(m0) = self.m0 {
            m0
        } else {
            let mtmax = (2. * n as f64) / (self.t + 2) as f64;

            if self.alpha == 1. {
                n
            } else {
                let m0 = (DEFAULT_APLHA / (1. - DEFAULT_APLHA) * mtmax) as f64;
                m0.clamp(1., n as f64) as usize
            }
        };

        Ok(RainbowTableCtx {
            search_spaces,
            m0,
            n,
            hash_type: self.hash_type,
            charset: self.charset,
            max_password_length: self.max_password_length,
            t: self.t,
            tn: self.tn,
        })
    }
}

/// An iterator to get the columns where a filtration should happen.
struct FiltrationIterator {
    i: usize,
    current_col: usize,
    gamma: f64,
    frac: f64,
    ctx: RainbowTableCtx,
}

impl FiltrationIterator {
    /// Creates a new FiltrationIterator.
    fn new(ctx: RainbowTableCtx) -> Self {
        // from "Precomputation for Rainbow Tables has Never Been so Fast" theorem 3
        let gamma = 2. * ctx.n as f64 / ctx.m0 as f64;
        let frac = (ctx.t as f64 + gamma - 1.) / gamma;

        Self {
            gamma,
            frac,
            ctx,
            i: 0,
            current_col: 0,
        }
    }
}

impl Iterator for FiltrationIterator {
    type Item = Range<usize>;

    fn next(&mut self) -> Option<Self::Item> {
        if self.i == DEFAULT_FILTER_COUNT {
            self.i += 1;
            return Some(self.current_col..self.ctx.t - 1);
        } else if self.i >= DEFAULT_FILTER_COUNT {
            return None;
        }

        let filter_col = (self.gamma * self.frac.powf(self.i as f64 / DEFAULT_FILTER_COUNT as f64)
            - self.gamma) as usize
            + 2;

        let col = self.current_col;

        self.i += 1;
        self.current_col = filter_col;

        // same filtration column, it can happen with small tables
        if col == filter_col {
            return self.next();
        }

        Some(col..filter_col)
    }
}
