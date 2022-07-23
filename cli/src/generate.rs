use color_eyre::{eyre::Context, Result};
use cugparck_commons::DEFAULT_FILTER_COUNT;
use cugparck_cpu::{
    CompressedTable, Event, RainbowTable, RainbowTableCtxBuilder, RainbowTableStorage, SimpleTable,
};
use indicatif::{ProgressBar, ProgressStyle};

use crate::{create_dir_to_store_tables, Generate};

pub fn generate(gen: Generate) -> Result<()> {
    create_dir_to_store_tables(&gen.dir)?;

    let ext = if gen.compress { "rtcde" } else { "rt" };

    let ctx_builder = RainbowTableCtxBuilder::new()
        .hash(gen.hash_type.into())
        .alpha(gen.alpha)
        .startpoints(gen.startpoints)
        .chain_length(gen.chain_length as usize)
        .charset(gen.charset.as_bytes())
        .max_password_length(gen.max_password_length);

    for i in gen.start_from..gen.start_from + gen.table_count {
        let ctx = ctx_builder.table_number(i).build()?;
        let table_path = gen.dir.clone().join(format!("table_{i}.{ext}"));

        let table_handle = if gen.cpu {
            SimpleTable::new_cpu_nonblocking(ctx)
        } else {
            SimpleTable::new_gpu_nonblocking(ctx)
        };

        println!("Generating table {i}");

        let pb = ProgressBar::new(10_000);
        pb.set_style(
            ProgressStyle::default_bar()
                .template("{spinner:.green} {msg} [{elapsed_precise}] [{wide_bar:.cyan/blue}]")
                .progress_chars("#>-"),
        );
        pb.enable_steady_tick(100);

        while let Some(event) = table_handle.recv() {
            match event {
                Event::Progress(progress) => pb.set_position((progress * 100.) as u64),
                Event::Filtration(i) => pb.set_message(format!(
                    "Running filtration {i}/{}",
                    DEFAULT_FILTER_COUNT + 1
                )),
                Event::GpuBatch {
                    batch_number,
                    batch_count,
                    columns,
                } => pb.set_message(format!(
                    "Running batch {batch_number}/{batch_count} of columns {columns:?}"
                )),
                Event::Cpu(columns) => pb.set_message(format!("Generating columns {columns:?}")),
            }
        }

        pb.finish_with_message("Done");
        let simple_table = table_handle.join()?;

        let disk_error = "Unable to store the generated rainbow table to the disk";
        if gen.compress {
            simple_table
                .into_rainbow_table::<CompressedTable>()
                .store(&table_path)
                .wrap_err(disk_error)?
        } else {
            simple_table.store(&table_path).wrap_err(disk_error)?;
        }
    }

    Ok(())
}
