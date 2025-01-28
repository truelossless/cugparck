use crate::{create_dir_to_store_tables, get_table_paths_from_dir, Compress};

use anyhow::{ensure, Result};
use cugparck_core::{CompressedTable, RainbowTable, SimpleTable};

pub fn compress(args: Compress) -> Result<()> {
    create_dir_to_store_tables(&args.out_dir)?;

    let (table_paths, is_compressed) = get_table_paths_from_dir(&args.in_dir)?;

    ensure!(!is_compressed, "The tables are already compressed");

    for table_path in table_paths {
        let simple_table = SimpleTable::load(&table_path)?;
        let path = args
            .out_dir
            .join(format!("table_{}.rtcde", simple_table.ctx().tn));

        simple_table
            .into_rainbow_table::<CompressedTable>()
            .store(&path)?;
    }

    Ok(())
}
