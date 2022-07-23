use crate::{create_dir_to_store_tables, load_tables_from_dir, Compress};

use color_eyre::{
    eyre::{bail, Context},
    Result,
};
use cugparck_cpu::{
    CompressedTable, Deserialize, Infallible, RainbowTable, RainbowTableStorage, SimpleTable,
};

pub fn compress(comp: Compress) -> Result<()> {
    create_dir_to_store_tables(&comp.out_dir)?;

    let (mmaps, is_compressed) = load_tables_from_dir(&comp.in_dir)?;

    if is_compressed {
        bail!("The tables are already compressed");
    }

    for mmap in mmaps {
        let ar = SimpleTable::load(&mmap)?;
        let path = comp.out_dir.join(format!("table_{}.rtcde", ar.ctx().tn));

        let table: SimpleTable = ar
            .deserialize(&mut Infallible)
            .wrap_err("Unable to deserialize the rainbow table")?;

        table.into_rainbow_table::<CompressedTable>().store(&path)?;
    }

    Ok(())
}
