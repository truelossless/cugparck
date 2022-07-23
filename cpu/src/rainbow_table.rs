mod compressed_delta_encoding;
mod simple;

pub use {compressed_delta_encoding::CompressedTable, simple::SimpleTable};

use std::{fs::File, path::Path};

use bytecheck::CheckBytes;
use cugparck_commons::{
    hash, reduce, CompressedPassword, Digest, Password, RainbowChain, RainbowTableCtx,
};
use rayon::prelude::*;
use rkyv::{
    check_archived_root,
    ser::{
        serializers::{
            AllocScratch, CompositeSerializer, FallbackScratch, HeapScratch, SharedSerializeMap,
            WriteSerializer,
        },
        Serializer,
    },
    validation::validators::DefaultValidator,
    Serialize,
};

use crate::error::{CugparckError, CugparckResult};

const MAX_SCRATCH_SPACE: usize = 4096;
type FileSerializer = CompositeSerializer<
    WriteSerializer<File>,
    FallbackScratch<HeapScratch<MAX_SCRATCH_SPACE>, AllocScratch>,
    SharedSerializeMap,
>;

/// Trait that data structures implement to be used as rainbow tables.
pub trait RainbowTable: Sized + Sync {
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
    fn iter(&self) -> Self::Iter<'_>;

    /// Returns the startpoint at the given index.
    fn startpoint(&self, i: usize) -> CompressedPassword;

    /// Searches the endpoints for a password.
    /// Returns the chain number if the password was found in the endpoints.
    fn search_endpoints(&self, password: CompressedPassword) -> Option<usize>;

    /// Searches for a password in a given column.
    #[inline]
    fn search_column(&self, column: usize, digest: Digest) -> Option<Password> {
        let ctx = self.ctx();
        let mut column_digest = digest;
        let mut column_plaintext;

        // get the reduction corresponding to the current column
        for k in column..ctx.t - 2 {
            column_plaintext = reduce(column_digest, k, &ctx);
            column_digest = hash(column_plaintext, &ctx);
        }
        column_plaintext = reduce(column_digest, &ctx.t - 2, &ctx);

        let mut chain_plaintext = match self
            .search_endpoints(CompressedPassword::from_password(column_plaintext, &ctx))
        {
            None => return None,
            Some(found) => self.startpoint(found).into_password(&ctx),
        };
        let mut chain_digest;

        // we found a matching endpoint, reconstruct the chain
        for k in 0..column {
            chain_digest = hash(chain_plaintext, &ctx);
            chain_plaintext = reduce(chain_digest, k, &ctx);
        }
        chain_digest = hash(chain_plaintext, &ctx);

        // the digest was indeed present in the chain, we found a plaintext matching the digest
        if chain_digest == digest {
            Some(chain_plaintext)
        } else {
            None
        }
    }

    /// Searches for a password that hashes to the given digest.
    fn search(&self, digest: Digest) -> Option<Password> {
        let ctx = self.ctx();
        (0..ctx.t - 1)
            .into_par_iter()
            .rev()
            .find_map_any(|i| self.search_column(i, digest))
    }

    /// Returns the context.
    fn ctx(&self) -> RainbowTableCtx;

    /// Returns a new rainbow table created from the table passed as a parameter.
    fn from_rainbow_table<T: RainbowTable>(table: T) -> Self;

    /// Transforms this rainbow table into another rainbow table.
    fn into_rainbow_table<T: RainbowTable>(self) -> T {
        T::from_rainbow_table(self)
    }
}

/// Trait that rainbow tables implement to be stored and loaded from disk.
pub trait RainbowTableStorage: Sized + Serialize<FileSerializer>
where
    for<'a> Self::Archived: CheckBytes<DefaultValidator<'a>>,
{
    /// Stores the rainbow table to the given path.
    fn store(&self, path: &Path) -> CugparckResult<()> {
        let file = File::options()
            .create(true)
            .write(true)
            .truncate(true)
            .open(path)?;

        let mut serializer = FileSerializer::new(
            WriteSerializer::new(file),
            FallbackScratch::default(),
            SharedSerializeMap::default(),
        );

        serializer
            .serialize_value(self)
            .map_err(|_| CugparckError::Serialize)?;

        Ok(())
    }

    /// Tries to zero-copy load the rainbow table from a byte slice.
    #[inline]
    fn load(bytes: &[u8]) -> CugparckResult<&Self::Archived> {
        check_archived_root::<Self>(bytes).map_err(|_| CugparckError::Check)
    }
}
