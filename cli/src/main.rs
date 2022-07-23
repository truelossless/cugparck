mod attack;
mod compress;
mod decompress;
mod generate;

use std::{
    fs::{self, File},
    path::{Path, PathBuf},
    string::String,
};

use clap::{clap_derive::ArgEnum, value_parser, Args, Parser, Subcommand};

use color_eyre::eyre::{bail, Context, Result};

use cugparck_commons::{
    HashType, DEFAULT_APLHA, DEFAULT_CHAIN_LENGTH, DEFAULT_CHARSET, DEFAULT_MAX_PASSWORD_LENGTH,
};
use cugparck_cpu::Mmap;

use attack::attack;
use compress::compress;
use decompress::decompress;
use generate::generate;

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

/// Rainbow table application allowing attacks and GPU-accelerated table generation.
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
}

/// Compress a set of rainbow tables using compressed delta encoding.
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

    /// Optimizes the storage of the rainbow table(s) using compressed delta encoding.
    /// Compressed tables are slower to search.
    #[clap(long, value_parser)]
    compress: bool,

    /// Use the CPU for the generation (not recommanded unless your GPU is not CUDA-compatible).
    #[clap(long, value_parser)]
    cpu: bool,

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

/// Checks if the charset is made of ASCII characters.
fn check_charset(charset: &str) -> Result<String> {
    if !charset.is_ascii() {
        bail!("The charset can only contain ASCII characters");
    }

    Ok(charset.to_owned())
}

/// Checks if the alpha coefficient is a float between 0 and 1.
fn check_alpha(alpha: &str) -> Result<f64> {
    let alpha = alpha.parse::<f64>().wrap_err("Alpha should be a number")?;

    if !(0. ..=1.).contains(&alpha) {
        bail!("Alpha should be comprised between 0 and 1");
    }

    Ok(alpha)
}

/// Checks if the digest is valid hexadecimal.
fn check_hex(hex: &str) -> Result<String> {
    hex::decode(hex).wrap_err("The digest is not valid hexadecimal")?;
    Ok(hex.to_owned())
}

fn main() -> Result<()> {
    color_eyre::install()?;
    let cli = Cli::parse();

    match cli.commands {
        Commands::Attack(atk) => attack(atk)?,
        Commands::Generate(gen) => generate(gen)?,
        Commands::Compress(comp) => compress(comp)?,
        Commands::Decompress(decomp) => decompress(decomp)?,
    }

    Ok(())
}

/// Helper function to create a directory where will be stored rainbow tables.
fn create_dir_to_store_tables(dir: &Path) -> Result<()> {
    fs::create_dir(dir)
        .wrap_err("Unable to create the specified directory to store the rainbow tables")
}

/// Helper function to load rainbow tables from a directory.
/// Returns a vector of memory mapped rainbow tables and true if the tables loaded are compressed.
fn load_tables_from_dir(dir: &Path) -> Result<(Vec<Mmap>, bool)> {
    let mut mmaps = Vec::new();
    let mut simple_tables = false;
    let mut compressed_tables = false;

    for file in fs::read_dir(&dir).wrap_err("Unable to open the specified directory")? {
        let file = file?;

        if file.file_type()?.is_dir() {
            continue;
        }

        match file.path().extension().map(|s| s.to_str()).flatten() {
            Some("rt") => simple_tables = true,
            Some("rtcde") => compressed_tables = true,
            _ => continue,
        };

        let file = File::open(file.path()).wrap_err("Unable to open a rainbow table")?;

        // SAFETY: the file exists and is not being modified anywhere else
        unsafe { mmaps.push(Mmap::map(&file)?) };
    }

    if mmaps.is_empty() {
        bail!("No table found in the given directory");
    }

    if simple_tables && compressed_tables {
        bail!("All tables in the directory should be of the same type");
    }

    Ok((mmaps, compressed_tables))
}
