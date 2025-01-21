use anyhow::{bail, Result};
use crossterm::style::{style, Color, Stylize};

use crate::{get_table_paths_from_dir, search_tables, Attack};

pub fn attack(args: Attack) -> Result<()> {
    //TODO: restore
    //
    // let digest = hex::decode(args.digest)
    //     .unwrap()
    //     .as_slice()
    //     .try_into()
    //     .or_else(|_| bail!("The provided hexadecimal string is not a valid digest"))?;
    //
    // let (mmaps, is_compressed) = load_tables_from_dir(&args.dir)?;
    //
    // let search = search_tables(digest, &mmaps, is_compressed, args.low_memory)?;
    //
    // if let Some(password) = search {
    //     println!("{}", style(password).with(Color::Green));
    // } else {
    //     eprintln!("{}", "No password found for the given digest".red());
    // }

    Ok(())
}
