use crate::{create_dir_to_store_tables, get_table_paths_from_dir, Decompress};

use anyhow::{ensure, Result};
use cugparck_core::{CompressedTable, RainbowTable, SimpleTable};

pub fn decompress(args: Decompress) -> Result<()> {
    create_dir_to_store_tables(&args.out_dir)?;

    let (table_paths, is_compressed) = get_table_paths_from_dir(&args.in_dir)?;

    ensure!(is_compressed, "The tables are already decompressed");

    for table_path in table_paths {
        let compressed_table = CompressedTable::load(&table_path)?;
        let out_path = args
            .out_dir
            .join(format!("table_{}.rt", compressed_table.ctx().tn));

        compressed_table
            .into_rainbow_table::<SimpleTable>()
            .store(&out_path)?;
    }

    Ok(())
}
