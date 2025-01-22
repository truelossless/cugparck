mod compressed_delta_encoding;
mod simple;

use std::{
    fs::File,
    io::{BufReader, BufWriter},
    path::Path,
};

use crate::{error::CugparckResult, CugparckError};

pub use {compressed_delta_encoding::CompressedTable, simple::SimpleTable};

use cubecl::prelude::Array;
use cugparck_core::{
    into_gpu_password, reduce, CompressedPassword, Digest, Password, RainbowChain, RainbowTableCtx,
    MAX_DIGEST_LENGTH_ALLOWED,
};
use rayon::prelude::*;
use serde::{Deserialize, Serialize};

/// Trait that data structures implement to be used as rainbow tables.
pub trait RainbowTable: Sized + Sync + Serialize + for<'a> Deserialize<'a> {
    /// The type of the iterator over the chains of the table.
    type Iter<'a>: Iterator<Item = RainbowChain>
    where
        Self: 'a;

    /// Returns the number of chains stored in the table.
    fn len(&self) -> usize;

    /// Returns true if the table is empty.
    fn is_empty(&self) -> bool {
        self.len() == 0
    }

    /// Returns an iterator over the chains of the table.
    /// The chains are not expected to be returned in a particular order.
    fn iter(&self) -> Self::Iter<'_>;

    /// Searches the endpoints for a password.
    /// Returns startpoint of the chain if the password was found in the endpoints.
    fn search_endpoints(&self, password: CompressedPassword) -> Option<CompressedPassword>;

    /*     /// Searches for a password in a given column.
    #[inline]
    fn search_column(&self, column: u64, digest: &Digest) -> Option<Password> {
        let ctx = self.ctx();
        // TODO: impl hash
        // let hash = ctx.hash_type.hash_function();
        let mut column_digest = digest;
        let mut column_counter;

        // get the reduction corresponding to the current column
        for k in column..ctx.t - 2 {
            column_counter = reduce(column_digest, k, &ctx);
            let column_plaintext = into_gpu_password(column_counter, &ctx);
            // TODO: impl hash
            // column_digest = hash(column_plaintext);
        }
        column_counter = reduce(column_digest, &ctx.t - 2, &ctx);

        let mut chain_plaintext = match self.search_endpoints(column_counter) {
            None => return None,
            Some(found) => into_gpu_password(found, &ctx),
        };
        let chain_digest = Array::new(MAX_DIGEST_LENGTH_ALLOWED);

        // we found a matching endpoint, reconstruct the chain
        for k in 0..column {
            // TODO: impl hash
            // chain_digest = hash(chain_plaintext);
            let chain_counter = reduce(&chain_digest, k, &ctx);
            chain_plaintext = into_gpu_password(chain_counter, &ctx);
        }
        // TODO: impl hash
        // chain_digest = hash(chain_plaintext);

        // the digest was indeed present in the chain, we found a plaintext matching the digest

        for (chain_digest_byte, digest_byte) in chain_digest.zip(digest) {
            if chain_digest_byte != digest_byte {
                return None;
            }
        }

        Some(chain_plaintext)
        // if chain_digest == digest {
        //     Some(chain_plaintext)
        // } else {
        //     None
        // }
    } */

    /*     /// Searches for a password that hashes to the given digest.
    fn search(&self, digest: &Digest) -> Option<Password> {
        let ctx = self.ctx();
        // we use Range<usize> because Range<u64> doesn't implement IndexedParallelIterator.
        (0..ctx.t as usize - 1)
            .into_par_iter()
            .rev()
            .find_map_any(|i| self.search_column(i as u64, digest))
    } */

    /// Returns the context.
    fn ctx(&self) -> RainbowTableCtx;

    /// Returns a new rainbow table created from the table passed as a parameter.
    fn from_rainbow_table<T: RainbowTable>(table: T) -> Self;

    /// Transforms this rainbow table into another rainbow table.
    fn into_rainbow_table<T: RainbowTable>(self) -> T {
        T::from_rainbow_table(self)
    }

    /// Stores this rainbow table to the given path.
    fn store(&self, path: &Path) -> CugparckResult<()> {
        let file = File::options()
            .create(true)
            .write(true)
            .truncate(true)
            .open(path)?;

        let buf_writer = BufWriter::with_capacity(1024 * 1024 * 16, file);
        bincode::serialize_into(buf_writer, self).map_err(|_| CugparckError::Serialize)?;

        Ok(())
    }

    fn load(path: &Path) -> CugparckResult<Self> {
        let file = File::open(path)?;
        let buf_reader = BufReader::with_capacity(1024 * 1024 * 16, file);
        let table =
            bincode::deserialize_from(buf_reader).map_err(|_| CugparckError::Deserialize)?;

        Ok(table)
    }
}
