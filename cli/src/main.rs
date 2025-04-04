mod attack;
mod compress;
mod decompress;
mod generate;
// mod stealdows;

use std::{
    fs::{self},
    path::{Path, PathBuf},
    string::String,
};

use anyhow::{ensure, Context, Ok, Result};

use clap::{value_parser, Args, Parser, Subcommand, ValueEnum};

use attack::attack;
use compress::compress;
use cugparck_core::{
    ClusterTable, CompressedTable, Digest, HashFunction, Password, RainbowTable, SimpleTable,
    DEFAULT_APLHA, DEFAULT_CHAIN_LENGTH, DEFAULT_CHARSET, DEFAULT_MAX_PASSWORD_LENGTH,
};
use decompress::decompress;
use generate::generate;
use tracing::{error, level_filters::LevelFilter};
use tracing_subscriber::{layer::SubscriberExt, util::SubscriberInitExt};
use tui_logger::TuiTracingSubscriberLayer;
// use stealdows::stealdows;

/// All the hash types supported.
#[derive(Copy, Clone, PartialEq, Eq, PartialOrd, Ord, ValueEnum)]
enum HashFunctionArg {
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

impl From<HashFunctionArg> for HashFunction {
    fn from(arg: HashFunctionArg) -> Self {
        match arg {
            HashFunctionArg::Ntlm => HashFunction::Ntlm,
            HashFunctionArg::Md4 => HashFunction::Md4,
            HashFunctionArg::Md5 => HashFunction::Md5,
            HashFunctionArg::Sha1 => HashFunction::Sha1,
            HashFunctionArg::Sha2_224 => HashFunction::Sha2_224,
            HashFunctionArg::Sha2_256 => HashFunction::Sha2_256,
            HashFunctionArg::Sha2_384 => HashFunction::Sha2_384,
            HashFunctionArg::Sha2_512 => HashFunction::Sha2_512,
            HashFunctionArg::Sha3_224 => HashFunction::Sha3_224,
            HashFunctionArg::Sha3_256 => HashFunction::Sha3_256,
            HashFunctionArg::Sha3_384 => HashFunction::Sha3_384,
            HashFunctionArg::Sha3_512 => HashFunction::Sha3_512,
        }
    }
}

/// All the backends available on this target, with the current feature flags.
// TODO: Fix feature registration that prevents shader non-vulkan WGPU backends to work
#[derive(Copy, Clone, PartialEq, Eq, PartialOrd, Ord, ValueEnum, Default)]
#[clap(rename_all = "lower")]
pub enum AvailableBackend {
    Cuda,
    Dx12,
    Metal,
    OpenGl,
    #[default]
    Vulkan,
    WebGpu,
}

/// Cugparck is a modern rainbow table library & CLI.
#[derive(Parser)]
#[clap(author, version, about, long_about = None)]
struct Cli {
    #[clap(subcommand)]
    commands: Commands,

    /// The logging level.
    #[arg(long, value_enum, default_value = "info", global = true)]
    log_level: LevelFilter,
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
    /// The hash function to use.
    #[clap(value_parser)]
    hash_function: HashFunctionArg,

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
    /// A single table has a theoritical success rate of 86.5%.
    /// Generating 4 tables allows to increase the success rate to 99.96%.
    #[clap(short = 'n', long, value_parser = value_parser!(u8).range(1..), default_value_t = 4)]
    table_count: u8,

    /// Start the generation from this table number.
    /// Useful to generate tables in several times, or on multiple computers.
    #[clap(short = 'f', long, value_parser = value_parser!(u8).range(0..), default_value_t = 0)]
    start_from: u8,

    /// Optimize the storage of the rainbow table(s) using compressed delta encoding.
    /// Compressed tables are slower to search.
    #[clap(long, value_parser)]
    compress: bool,

    /// Force a backend for the table generation.
    /// If not provided, Vulkan will be used.
    #[clap(short, long, value_enum, default_value_t)]
    backend: AvailableBackend,

    /// Set the maximality factor (alpha).
    /// It is used to determine the number of startpoints.
    /// It is an indicator of how well the table will perform compared to a maximum table.
    #[clap(short, long, value_parser = check_alpha, default_value_t = DEFAULT_APLHA, group = "startpoint")]
    alpha: f64,

    /// The number of startpoints to use.
    /// Prefer using alpha if you don't know what you're doing.
    #[clap(short, long, value_parser = value_parser!(u64).range(1..), group = "startpoint")]
    startpoints: Option<u64>,
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
    let cli = Cli::parse();

    tracing_subscriber::registry()
        .with(TuiTracingSubscriberLayer)
        .with(cli.log_level)
        .init();

    if let Err(err) = try_main(cli) {
        error!("{:?}", err);
        eprintln!("{:?}", err);
        std::process::exit(1);
    }
}

fn try_main(cli: Cli) -> Result<()> {
    match cli.commands {
        Commands::Attack(args) => attack(args)?,
        Commands::Generate(args) => generate(args)?,
        Commands::Compress(args) => compress(args)?,
        Commands::Decompress(args) => decompress(args)?,
        Commands::Stealdows(_args) => todo!(),
    }

    Ok(())
}

/// Helper function to create a directory where will be stored rainbow tables.
fn create_dir_to_store_tables(dir: &Path) -> Result<()> {
    if dir.is_dir() && dir.read_dir()?.next().is_none() {
        return Ok(());
    }

    fs::create_dir(dir)
        .context("An existing, non-empty directory already exists at the specified path")?;

    Ok(())
}

/// Helper function to get the table paths from a directory.
/// Returns a list of paths and true if these tables are compressed.
fn get_table_paths_from_dir(dir: &Path) -> Result<(Vec<PathBuf>, bool)> {
    let mut is_simple_tables = false;
    let mut is_compressed_tables = false;
    let mut table_paths = Vec::new();

    for file in fs::read_dir(dir).context("Unable to open the specified directory")? {
        let file = file?;

        if file.file_type()?.is_dir() {
            continue;
        }

        match file.path().extension().and_then(|s| s.to_str()) {
            Some("rt") => is_simple_tables = true,
            Some("rtcde") => is_compressed_tables = true,
            _ => continue,
        };

        table_paths.push(file.path());
    }

    ensure!(
        !table_paths.is_empty(),
        "No table found in the given directory"
    );

    ensure!(
        !(is_simple_tables && is_compressed_tables),
        "All tables in the directory should be of the same type",
    );

    // check that the tables in the directory are all compatible.
    // since we're mmaping our files, we shouldn't run out of memory.
    // let all_ctx = if is_compressed_tables {
    //     tables
    //         .iter()
    //         .map(|table| Ok(CompressedTable::load(mmap)?.ctx()))
    //         .collect::<Result<Vec<_>>>()?
    // } else {
    //     tables
    //         .iter()
    //         .map(|mmap| Ok(SimpleTable::load(mmap)?.ctx()))
    //         .collect::<Result<Vec<_>>>()?
    // };
    //
    // let table_numbers = all_ctx.iter().map(|ctx| ctx.tn).collect::<HashSet<_>>();

    // ensure!(
    //     table_numbers.len() == tables.len(),
    //     "All tables in the directory should have a different table number",
    // );

    // let ctx_spaces_and_hash_functions = all_ctx
    //     .iter()
    //     .map(|ctx| (ctx.charset, ctx.max_password_length, ctx.hash_function))
    //     .collect::<HashSet<_>>();
    //
    // ensure!(
    //     ctx_spaces_and_hash_functions.len() == 1,
    //     "All tables in the directory should use the same charset, maximum password length and hash function"
    // );

    Ok((table_paths, is_compressed_tables))
}

/// Searches a digest in the tables at a given path.
/// If `low memory` is true, the tables aren't loaded at the same time to be searched in parallel.
/// This slows the search but saves memory.
fn search_tables(
    digest: Digest,
    table_paths: &[PathBuf],
    is_compressed: bool,
    low_memory: bool,
) -> Result<Option<Password>> {
    match (is_compressed, low_memory) {
        (true, true) => {
            for table_path in table_paths {
                if let Some(digest) = CompressedTable::load(table_path)?.search(&digest) {
                    return Ok(Some(digest));
                }
            }

            Ok(None)
        }

        (true, false) => {
            let tables = table_paths
                .iter()
                .map(|path| CompressedTable::load(path))
                .collect::<Result<Vec<_>, _>>()?;

            Ok(ClusterTable::new(&tables).search(&digest))
        }

        (false, true) => {
            for table_path in table_paths {
                if let Some(digest) = SimpleTable::load(table_path)?.search(&digest) {
                    return Ok(Some(digest));
                }
            }

            Ok(None)
        }

        (false, false) => {
            let tables = table_paths
                .iter()
                .map(|table| SimpleTable::load(table))
                .collect::<Result<Vec<_>, _>>()?;

            Ok(ClusterTable::new(&tables).search(&digest))
        }
    }
}
