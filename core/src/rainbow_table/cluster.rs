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
    use cubecl_cuda::CudaRuntime;
    use futures::future::join_all;

    use crate::{
        cpu::counter_to_plaintext, rainbow_table::cluster::ClusterTable, RainbowTableCtxBuilder,
        SimpleTable,
    };

    #[tokio::test]
    async fn test_coverage() {
        let ctx_builder = RainbowTableCtxBuilder::new()
            .chain_length(100)
            .max_password_length(4)
            .charset(b"abcdef");

        let tables = join_all((0..4).map(async |i| {
            let ctx = ctx_builder.clone().table_number(i).build().unwrap();
            SimpleTable::new::<CudaRuntime>(ctx).await.unwrap()
        }))
        .await;

        let cluster = ClusterTable::new(&tables);

        let mut found = 0;
        let ctx = ctx_builder.build().unwrap();
        let mut hasher = ctx.hash_function.cpu();
        let mut password_hash = vec![0; hasher.output_size()];

        for i in 0..ctx.n {
            let password = counter_to_plaintext(i, &ctx);
            hasher.update(&password);
            hasher.finalize_into_reset(&mut password_hash).unwrap();
            if let Some(plaintext) = cluster.search(&password_hash) {
                assert_eq!(password, plaintext);
                found += 1;
            }
        }

        // the success rate should be around 99.96%.
        // with this test we get 100% as n is small.
        // using a bigger n I got 99.93% which is quite good!
        let success_rate = found as f64 / ctx.n as f64 * 100.;
        assert!(
            (99. ..=100.).contains(&success_rate),
            "success rate is only {success_rate}"
        );
    }
}
