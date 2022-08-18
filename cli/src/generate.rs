use std::time::Duration;

use anyhow::{Context, Result};
use cugparck_cpu::{
    backend::Cpu, CompressedTable, Event, RainbowTable, RainbowTableCtxBuilder,
    RainbowTableStorage, SimpleTable,
};
use indicatif::{ProgressBar, ProgressStyle};

use crate::{create_dir_to_store_tables, Generate};

pub fn generate(args: Generate) -> Result<()> {
    create_dir_to_store_tables(&args.dir)?;

    let ext = if args.compress { "rtcde" } else { "rt" };

    let ctx_builder = RainbowTableCtxBuilder::new()
        .hash(args.hash_type.into())
        .alpha(args.alpha)
        .startpoints(args.startpoints)
        .chain_length(args.chain_length as usize)
        .charset(args.charset.as_bytes())
        .max_password_length(args.max_password_length);

    for i in args.start_from..args.start_from + args.table_count {
        let ctx = ctx_builder.table_number(i).build()?;
        let table_path = args.dir.clone().join(format!("table_{i}.{ext}"));

        let table_handle = if args.cpu {
            SimpleTable::new_nonblocking::<Cpu>(ctx)?
        } else {
            #[cfg(feature = "cuda")]
            {
                SimpleTable::new_nonblocking::<cugparck_cpu::backend::Cuda>(ctx)?
            }

            #[cfg(not(feature = "cuda"))]
            {
                anyhow::bail!(
                    "Cannot use CUDA as this binary has not been compiled with CUDA support.\n\
                    Suggestion: If you want to use your CPU for the generation use the --cpu flag"
                );
            }
        };

        println!("Generating table {i}");

        let pb = ProgressBar::new(10_000).with_style(
            ProgressStyle::default_bar()
                .template("{spinner:.green} {msg} [{elapsed_precise}] [{wide_bar:.cyan/blue}]")
                .unwrap()
                .progress_chars("#>-"),
        );
        pb.enable_steady_tick(Duration::from_millis(100));

        while let Some(event) = table_handle.recv() {
            match event {
                Event::Progress(progress) => pb.set_position((progress * 100.) as u64),
                Event::Batch {
                    batch_number,
                    batch_count,
                    columns,
                } => pb.set_message(format!(
                    "Running batch {batch_number}/{batch_count} of columns {columns:?}"
                )),
            }
        }

        pb.finish_with_message("Done");
        let simple_table = table_handle.join()?;

        let disk_error = "Unable to store the generated rainbow table to the disk";
        if args.compress {
            simple_table
                .into_rainbow_table::<CompressedTable>()
                .store(&table_path)
                .context(disk_error)?
        } else {
            simple_table.store(&table_path).context(disk_error)?;
        }
    }

    Ok(())
}
