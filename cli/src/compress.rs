use crate::{create_dir_to_store_tables, load_tables_from_dir, Compress};

use anyhow::{ensure, Context, Result};
use cugparck_cpu::{
    CompressedTable, Deserialize, Infallible, RainbowTable, RainbowTableStorage, SimpleTable,
};

pub fn compress(args: Compress) -> Result<()> {
    create_dir_to_store_tables(&args.out_dir)?;

    let (mmaps, is_compressed) = load_tables_from_dir(&args.in_dir)?;

    ensure!(!is_compressed, "The tables are already compressed");

    for mmap in mmaps {
        let ar = SimpleTable::load(&mmap)?;
        let path = args.out_dir.join(format!("table_{}.rtcde", ar.ctx().tn));

        let table: SimpleTable = ar
            .deserialize(&mut Infallible)
            .context("Unable to deserialize the rainbow table")?;

        table.into_rainbow_table::<CompressedTable>().store(&path)?;
    }

    Ok(())
}
