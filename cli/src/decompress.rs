use crate::{create_dir_to_store_tables, load_tables_from_dir, Decompress};

use anyhow::{ensure, Context, Result};
use cugparck_cpu::{
    CompressedTable, Deserialize, Infallible, RainbowTable, RainbowTableStorage, SimpleTable,
};

pub fn decompress(args: Decompress) -> Result<()> {
    create_dir_to_store_tables(&args.out_dir)?;

    let (mmaps, is_compressed) = load_tables_from_dir(&args.in_dir)?;

    ensure!(is_compressed, "The tables are already decompressed");

    for mmap in mmaps {
        let ar = CompressedTable::load(&mmap)?;
        let path = args.out_dir.join(format!("table_{}.rt", ar.ctx().tn));

        let table: CompressedTable = ar
            .deserialize(&mut Infallible)
            .context("Unable to deserialize the rainbow table")?;

        table.into_rainbow_table::<SimpleTable>().store(&path)?;
    }

    Ok(())
}
