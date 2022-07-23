use crate::{create_dir_to_store_tables, load_tables_from_dir, Decompress};

use color_eyre::{
    eyre::{bail, Context},
    Result,
};
use cugparck_cpu::{
    CompressedTable, Deserialize, Infallible, RainbowTable, RainbowTableStorage, SimpleTable,
};

pub fn decompress(decomp: Decompress) -> Result<()> {
    create_dir_to_store_tables(&decomp.out_dir)?;

    let (mmaps, is_compressed) = load_tables_from_dir(&decomp.in_dir)?;

    if !is_compressed {
        bail!("The tables are already decompressed");
    }

    for mmap in mmaps {
        let ar = CompressedTable::load(&mmap)?;
        let path = decomp.out_dir.join(format!("table_{}.rt", ar.ctx().tn));

        let table: CompressedTable = ar
            .deserialize(&mut Infallible)
            .wrap_err("Unable to deserialize the rainbow table")?;

        table.into_rainbow_table::<SimpleTable>().store(&path)?;
    }

    Ok(())
}
