use crate::{Digest, Password};

use super::RainbowTable;
use rayon::prelude::*;

/// A cluster of rainbow tables, to improve the success rate.
/// If one table has a success rate of 86.5%, then a cluster of 4 tables have a success rate of 99.96%.
pub struct ClusterTable<'a, T: RainbowTable> {
    tables: &'a [T],
}

impl<'a, T: RainbowTable> ClusterTable<'a, T> {
    /// Creates a new table cluster.
    /// The tables inside the cluster should have the same RainbowTableCtx, except the `tn` field.
    pub fn new(tables: &'a [T]) -> Self {
        Self { tables }
    }

    /// Searches for a password in the table cluster.
    pub fn search(&self, digest: &Digest) -> Option<Password> {
        let t = self.tables[0].ctx().t as usize;

        (0..t - 1).into_par_iter().rev().find_map_any(|i| {
            self.tables
                .iter()
                .find_map(|table| table.search_column(i as u64, digest))
        })
    }
}

#[cfg(test)]
mod tests {
    use cubecl_wgpu::WgpuRuntime;

    use crate::{
        cpu::counter_to_plaintext, CompressedTable, RainbowTable, RainbowTableCtxBuilder,
        SimpleTable,
    };

    #[test]
    fn test_coverage() {
        let ctx = RainbowTableCtxBuilder::new()
            .chain_length(100)
            .max_password_length(4)
            .charset(b"abcdef")
            .build()
            .unwrap();
        let mut hasher = ctx.hash_function.cpu();
        let mut search_hash = vec![0; hasher.output_size()];

        let table: CompressedTable = SimpleTable::new::<WgpuRuntime>(ctx.clone())
            .unwrap()
            .into_rainbow_table();

        let mut found = 0;
        for i in 0..ctx.n {
            let password = counter_to_plaintext(i, &ctx);
            hasher.update(&password);
            hasher.finalize_into_reset(&mut search_hash).unwrap();
            if let Some(plaintext) = table.search(&search_hash) {
                assert_eq!(password, plaintext);
                found += 1;
            }
        }

        // the success rate should be around 85% - 87%
        let success_rate = found as f64 / ctx.n as f64 * 100.;
        assert!(
            (80. ..90.).contains(&success_rate),
            "success rate is only {success_rate}"
        );
    }
}
