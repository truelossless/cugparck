use super::RainbowTable;
use cugparck_core::{Digest, Password};
use rayon::prelude::*;

/// A cluster of rainbow tables, to improve the success rate.
/// If one table has a success rate of 86.5%, then a cluster of 4 tables have a success rate of 99.96%.
pub struct TableCluster<'a, T: RainbowTable> {
    tables: &'a [T],
}

impl<'a, T: RainbowTable> TableCluster<'a, T> {
    /// Creates a new table cluster.
    /// The tables inside the cluster should have the same RainbowTableCtx, except the `tn` field.
    pub fn new(tables: &'a [T]) -> Self {
        Self { tables }
    }

    /// Searches for a password in the table cluster.
    pub fn search(&self, digest: Digest) -> Option<Password> {
        let t = self.tables[0].ctx().t as usize;

        (0..t - 1).into_par_iter().rev().find_map_any(|i| {
            self.tables
                .iter()
                .find_map(|table| table.search_column(i as u64, &digest))
        })
    }
}

// #[cfg(test)]
// mod tests {
//     use cugparck_commons::CompressedPassword;
//     use itertools::Itertools;
//
//     use crate::{backend::Cpu, RainbowTableCtxBuilder, SimpleTable, TableCluster};
//
//     #[test]
//     fn test_coverage() {
//         let ctx_builder = RainbowTableCtxBuilder::new()
//             .chain_length(100)
//             .max_password_length(4)
//             .charset(b"abcdef");
//
//         let tables = (0..4)
//             .map(|i| {
//                 let ctx = ctx_builder.table_number(i).build().unwrap();
//                 SimpleTable::new_blocking::<Cpu>(ctx).unwrap()
//             })
//             .collect_vec();
//
//         let tables_ref = tables.iter().collect_vec();
//
//         let cluster = TableCluster::new(&tables_ref);
//
//         let mut found = 0;
//         let ctx = ctx_builder.build().unwrap();
//         let hash = ctx.hash_type.hash_function();
//
//         for i in 0..ctx.n {
//             let password = CompressedPassword::from(i).into_password(&ctx);
//             if let Some(plaintext) = cluster.search(hash(password)) {
//                 assert_eq!(password, plaintext);
//                 found += 1;
//             }
//         }
//
//         // the success rate should be around 99.96%.
//         // with this test we get 100% as n is small.
//         // using a bigger n I got 99.93% which is quite good!
//         let success_rate = found as f64 / ctx.n as f64 * 100.;
//         assert!(
//             (99. ..=100.).contains(&success_rate),
//             "success rate is only {success_rate}"
//         );
//     }
// }
