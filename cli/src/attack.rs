use color_eyre::{eyre::bail, Result};
use cugparck_cpu::{CompressedTable, RainbowTableStorage, SimpleTable, TableCluster};

use crate::{load_tables_from_dir, Attack};

pub fn attack(atk: Attack) -> Result<()> {
    let (mmaps, is_compressed) = load_tables_from_dir(&atk.dir)?;

    let digest = hex::decode(atk.digest)
        .unwrap()
        .as_slice()
        .try_into()
        .or_else(|_| bail!("The provided hexadecimal string is not a valid digest"))?;

    let search = if is_compressed {
        let tables = mmaps
            .iter()
            .map(|mmap| CompressedTable::load(mmap))
            .collect::<Result<Vec<_>, _>>()?;

        TableCluster::new(&tables).search(digest)
    } else {
        let tables = mmaps
            .iter()
            .map(|mmap| SimpleTable::load(mmap))
            .collect::<Result<Vec<_>, _>>()?;

        TableCluster::new(&tables).search(digest)
    };

    if let Some(password) = search {
        println!("{password}");
    } else {
        eprintln!("No password found for the given digest");
    }

    Ok(())
}
