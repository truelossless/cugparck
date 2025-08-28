use anyhow::{bail, Result};
use crossterm::style::{style, Color, Stylize};

use crate::{get_table_paths_from_dir, search_tables, Attack};

pub fn attack(args: Attack) -> Result<()> {
    let digest = hex::decode(args.digest)
        .or_else(|_| bail!("The provided hexadecimal string is not a valid digest"))?;

    let (paths, is_compressed) = get_table_paths_from_dir(&args.dir)?;

    let search = search_tables(digest, &paths, is_compressed, args.low_memory)?;
    if let Some(password) = search {
        println!(
            "{}",
            style(String::from_utf8_lossy(&password)).with(Color::Green)
        );
    } else {
        eprintln!("{}", "No password found for the given digest".red());
    }

    Ok(())
}
