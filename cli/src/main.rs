mod attack;
mod compress;
mod decompress;
mod generate;
mod stealdows;

use std::{
    collections::HashSet,
    fs::{self, File},
    path::{Path, PathBuf},
    string::String,
};

use clap::{clap_derive::ArgEnum, value_parser, Args, Parser, Subcommand};

use anyhow::{ensure, Context, Result};

use crossterm::style::{style, Color, Stylize};
use cugparck_commons::{
    Digest, HashType, Password, DEFAULT_APLHA, DEFAULT_CHAIN_LENGTH, DEFAULT_CHARSET,
    DEFAULT_MAX_PASSWORD_LENGTH,
};
use cugparck_cpu::{
    backend::Renderer, CompressedTable, Mmap, RainbowTable, RainbowTableStorage, SimpleTable,
    TableCluster,
};

use attack::attack;
use compress::compress;
use decompress::decompress;
use generate::generate;
use stealdows::stealdows;

/// All the hash types supported.
#[derive(Copy, Clone, PartialEq, Eq, PartialOrd, Ord, ArgEnum)]
enum HashTypeArg {
    Ntlm,
    Md4,
    Md5,
    Sha1,
    Sha2_224,
    Sha2_256,
    Sha2_384,
    Sha2_512,
    Sha3_224,
    Sha3_256,
    Sha3_384,
    Sha3_512,
}

impl From<HashTypeArg> for HashType {
    fn from(arg: HashTypeArg) -> Self {
        match arg {
            HashTypeArg::Ntlm => HashType::Ntlm,
            HashTypeArg::Md4 => HashType::Md4,
            HashTypeArg::Md5 => HashType::Md5,
            HashTypeArg::Sha1 => HashType::Sha1,
            HashTypeArg::Sha2_224 => HashType::Sha2_224,
            HashTypeArg::Sha2_256 => HashType::Sha2_256,
            HashTypeArg::Sha2_384 => HashType::Sha2_384,
            HashTypeArg::Sha2_512 => HashType::Sha2_512,
            HashTypeArg::Sha3_224 => HashType::Sha3_224,
            HashTypeArg::Sha3_256 => HashType::Sha3_256,
            HashTypeArg::Sha3_384 => HashType::Sha3_384,
            HashTypeArg::Sha3_512 => HashType::Sha3_512,
        }
    }
}

/// Cugparck is a modern rainbow table library & CLI.
#[derive(Parser)]
#[clap(author, version, about, long_about = None)]
struct Cli {
    #[clap(subcommand)]
    commands: Commands,
}

#[derive(Subcommand)]
enum Commands {
    Attack(Attack),
    Generate(Generate),
    Compress(Compress),
    Decompress(Decompress),
    Stealdows(Stealdows),
}

/// Find the password producing a certain hash digest.
#[derive(Args)]
pub struct Attack {
    /// The digest to attack, in hexadecimal.
    #[clap(value_parser = check_hex)]
    digest: String,

    /// The directory containing the rainbow table(s) to use.
    #[clap(value_parser)]
    dir: PathBuf,

    /// Don't load all the tables at the same time to save memory.
    /// This is slower on average than searching with all the tables at once.
    #[clap(long, value_parser)]
    low_memory: bool,
}

/// Compress a set of rainbow tables using compressed delta encoding.
///
/// Tables are smaller on the disk but slower to search.
#[derive(Args)]
pub struct Compress {
    /// The output directory of the compressed rainbow table(s).
    #[clap(value_parser)]
    out_dir: PathBuf,

    /// The input directory containing the rainbow table(s) to compress.
    #[clap(value_parser)]
    in_dir: PathBuf,
}

/// Decompress a set of compressed rainbow tables.
///
/// Decompressed tables are bigger on the disk but faster to search.
#[derive(Args)]
pub struct Decompress {
    /// The output directory of the rainbow table(s).
    #[clap(value_parser)]
    out_dir: PathBuf,

    /// The input directory containing the compressed rainbow table(s) to decompress.
    #[clap(value_parser)]
    in_dir: PathBuf,
}

/// Generate a rainbow table.
#[derive(Args)]
pub struct Generate {
    /// The type of the hash.
    #[clap(value_parser)]
    hash_type: HashTypeArg,

    /// The directory where the generated table(s) should be stored.
    #[clap(value_parser)]
    dir: PathBuf,

    /// The chain length.
    /// Increasing the chain length will reduce the memory used
    /// to store the table but increase the time taken to attack.
    #[clap(short = 't', long, value_parser = value_parser!(u64).range(10..=1_000_000), default_value_t = DEFAULT_CHAIN_LENGTH as u64)]
    chain_length: u64,

    /// The maximum password length in the table.
    #[clap(short = 'l', long, value_parser = value_parser!(u8).range(..=10), default_value_t = DEFAULT_MAX_PASSWORD_LENGTH)]
    max_password_length: u8,

    /// The charset to use.
    #[clap(short, long, value_parser = check_charset, default_value_t = String::from_utf8_lossy(DEFAULT_CHARSET).to_string())]
    charset: String,

    /// The number of tables to generate.
    /// A single table has a theorical success rate of 86.5%.
    /// Generating 4 tables allows to increase the success rate to 99.96%.
    #[clap(short = 'n', long, value_parser = value_parser!(u8).range(1..), default_value_t = 4)]
    table_count: u8,

    /// Start the generation from this table number.
    /// Useful to generate tables in several times, or on multiple computers.
    /// Note that tables are 1-indexed.
    #[clap(short = 'f', long, value_parser = value_parser!(u8).range(1..), default_value_t = 1)]
    start_from: u8,

    /// Optimize the storage of the rainbow table(s) using compressed delta encoding.
    /// Compressed tables are slower to search.
    #[clap(long, value_parser)]
    compress: bool,

    /// Force a backend for the table generation.
    /// If not provided, all the available backends will be benched and the fastest will be used.
    #[clap(short, long, value_parser)]
    backend: Renderer,

    /// Set the maximality factor (alpha).
    /// It is used to determine the number of startpoints.
    /// It is an indicator of how well the table will perform compared to a maximum table.
    #[clap(short, long, value_parser = check_alpha, default_value_t = DEFAULT_APLHA, group = "startpoint")]
    alpha: f64,

    /// The number of startpoints to use.
    /// Prefer using alpha if you don't know what you're doing.
    #[clap(short, long, value_parser = value_parser!(u64).range(1..), group = "startpoint")]
    startpoints: Option<usize>,
}

/// Dump and crack NTLM hashes from Windows accounts.
///
/// Note that this cannot be used on a Windows machine to dump the hashes of the same Windows,
/// because the required files are locked by the OS.
#[derive(Args)]
pub struct Stealdows {
    /// Search for a specific user.
    /// You can specify several users by using multiple times this flag.
    #[clap(short, long, value_parser)]
    user: Vec<String>,

    /// Attempts to crack the hashes dumped using the rainbow table(s) provided as an argument.
    /// The hash type of the table(s) must be NTLM.
    #[clap(long, value_parser, value_name = "TABLES_DIR")]
    crack: Option<PathBuf>,

    #[clap(long, value_parser, requires = "crack")]
    /// Don't load all the tables at the same time to save memory.
    /// This is slower on average than searching with all the tables at once.
    /// Only use this flag when the `crack` flag is used.
    low_memory: bool,

    /// The path to the SAM registry file. If not provided an attempt will be made to find it automatically.
    /// This path is usually `C:\Windows\System32\config\SAM`.
    #[clap(long, value_parser, requires = "system")]
    sam: Option<PathBuf>,

    /// The path to the SYSTEM registry file. If not provided an attempt will be made to find it automatically.
    /// This path is usually `C:\Windows\System32\config\SYSTEM`.
    #[clap(long, value_parser, requires = "sam")]
    system: Option<PathBuf>,
}

/// Checks if the charset is made of ASCII characters.
fn check_charset(charset: &str) -> Result<String> {
    ensure!(
        charset.is_ascii(),
        "The charset can only contain ASCII characters"
    );

    Ok(charset.to_owned())
}

/// Checks if the alpha coefficient is a float between 0 and 1.
fn check_alpha(alpha: &str) -> Result<f64> {
    let alpha = alpha.parse::<f64>().context("Alpha should be a number")?;

    ensure!(
        (0. ..=1.).contains(&alpha),
        "Alpha should be comprised between 0 and 1"
    );

    Ok(alpha)
}

/// Checks if the digest is valid hexadecimal.
fn check_hex(hex: &str) -> Result<String> {
    hex::decode(hex).context("The digest is not valid hexadecimal")?;
    Ok(hex.to_owned())
}

fn main() {
    if let Err(err) = try_main() {
        eprintln!("{}", style(format!("{:?}", err)).with(Color::Red));
        std::process::exit(1);
    }
}

fn try_main() -> Result<()> {
    let cli = Cli::parse();

    match cli.commands {
        Commands::Attack(args) => attack(args)?,
        Commands::Generate(args) => generate(args)?,
        Commands::Compress(args) => compress(args)?,
        Commands::Decompress(args) => decompress(args)?,
        Commands::Stealdows(args) => stealdows(args)?,
    }

    Ok(())
}

/// Helper function to create a directory where will be stored rainbow tables.
fn create_dir_to_store_tables(dir: &Path) -> Result<()> {
    fs::create_dir(dir)
        .context("Unable to create the specified directory to store the rainbow tables")
}

/// Helper function to load rainbow tables from a directory.
/// Returns a vector of memory mapped rainbow tables and true if the tables loaded are compressed.
fn load_tables_from_dir(dir: &Path) -> Result<(Vec<Mmap>, bool)> {
    let mut mmaps = Vec::new();
    let mut is_simple_tables = false;
    let mut is_compressed_tables = false;

    for file in fs::read_dir(&dir).context("Unable to open the specified directory")? {
        let file = file?;

        if file.file_type()?.is_dir() {
            continue;
        }

        match file.path().extension().and_then(|s| s.to_str()) {
            Some("rt") => is_simple_tables = true,
            Some("rtcde") => is_compressed_tables = true,
            _ => continue,
        };

        let file = File::open(file.path()).context("Unable to open a rainbow table")?;

        // SAFETY: the file exists and is not being modified anywhere else
        unsafe { mmaps.push(Mmap::map(&file)?) };
    }

    ensure!(!mmaps.is_empty(), "No table found in the given directory");

    ensure!(
        !(is_simple_tables && is_compressed_tables),
        "All tables in the directory should be of the same type",
    );

    // check that the tables in the directory are all compatible.
    // since we're mmaping our files, we shouldn't run out of memory.
    let all_ctx = if is_compressed_tables {
        mmaps
            .iter()
            .map(|mmap| Ok(CompressedTable::load(mmap)?.ctx()))
            .collect::<Result<Vec<_>>>()?
    } else {
        mmaps
            .iter()
            .map(|mmap| Ok(SimpleTable::load(mmap)?.ctx()))
            .collect::<Result<Vec<_>>>()?
    };

    let table_numbers = all_ctx.iter().map(|ctx| ctx.tn).collect::<HashSet<_>>();

    ensure!(
        table_numbers.len() == mmaps.len(),
        "All tables in the directory should have a different table number",
    );

    let ctx_spaces_and_hash_types = all_ctx
        .iter()
        .map(|ctx| (ctx.charset, ctx.max_password_length, ctx.hash_type))
        .collect::<HashSet<_>>();

    ensure!(
        ctx_spaces_and_hash_types.len() == 1,
        "All tables in the directory should use the same charset, maximum password length and hash function"
    );

    Ok((mmaps, is_compressed_tables))
}

/// Searches for a digest from the tables at a given path, table after table.
/// If `low memory` is true, the tables aren't loaded at the same time to be searched in parallel.
/// This slows the search but saves memory.
fn search_tables(
    digest: Digest,
    mmaps: &[Mmap],
    is_compressed: bool,
    low_memory: bool,
) -> Result<Option<Password>> {
    match (is_compressed, low_memory) {
        (true, true) => {
            for mmap in mmaps {
                if let Some(digest) = CompressedTable::load(mmap)?.search(digest) {
                    return Ok(Some(digest));
                }
            }

            Ok(None)
        }

        (true, false) => {
            let tables = mmaps
                .iter()
                .map(|mmap| CompressedTable::load(mmap))
                .collect::<Result<Vec<_>, _>>()?;

            Ok(TableCluster::new(&tables).search(digest))
        }

        (false, true) => {
            for mmap in mmaps {
                if let Some(digest) = SimpleTable::load(mmap)?.search(digest) {
                    return Ok(Some(digest));
                }
            }

            Ok(None)
        }

        (false, false) => {
            let tables = mmaps
                .iter()
                .map(|mmap| SimpleTable::load(mmap))
                .collect::<Result<Vec<_>, _>>()?;

            Ok(TableCluster::new(&tables).search(digest))
        }
    }
}
