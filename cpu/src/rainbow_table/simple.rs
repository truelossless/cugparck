use std::thread;

use crate::{
    batch::BatchIterator,
    event::{Event, SimpleTableHandle},
    FiltrationIterator, PTX,
};
use bytecheck::CheckBytes;
use crossbeam_channel::{unbounded, Sender};
use cugparck_commons::{CompressedPassword, RainbowChain, RainbowTableCtx};
use rayon::prelude::*;
use rkyv::{Archive, Deserialize, Infallible, Serialize};

use cust::{
    context::Context,
    device::Device,
    launch,
    memory::DeviceBuffer,
    module::Module,
    prelude::{Stream, StreamFlags},
    CudaFlags,
};

use super::{RainbowTable, RainbowTableStorage};
use crate::error::CugparckResult;

/// A simple rainbow table.
#[derive(Archive, Deserialize, Serialize)]
#[archive_attr(derive(CheckBytes))]
pub struct SimpleTable {
    /// The chains of the table.
    chains: Vec<RainbowChain>,
    /// The context.
    ctx: RainbowTableCtx,
}

impl SimpleTable {
    /// Creates a new simple rainbow table.
    /// The chains must be made of valid startpoints and endpoints.
    pub fn new(chains: Vec<RainbowChain>, ctx: RainbowTableCtx) -> Self {
        Self { chains, ctx }
    }

    // Returns the startpoints in a vec.
    fn startpoints(ctx: &RainbowTableCtx) -> Vec<RainbowChain> {
        (0..ctx.m0)
            .into_par_iter()
            .map(|i| RainbowChain::from_compressed(i.into(), i.into()))
            .collect::<Vec<_>>()
    }

    /// Creates a new simple rainbow table, using the CPU, asynchronously.
    /// Returns an handle to get events related to the generation and to get the generated table.
    pub fn new_cpu_nonblocking(ctx: RainbowTableCtx) -> SimpleTableHandle {
        let (sender, receiver) = unbounded();
        let thread_handle = thread::spawn(move || Self::new_cpu(ctx, Some(sender)));

        SimpleTableHandle {
            thread_handle,
            receiver,
        }
    }

    /// Creates a new simple rainbow table, using the CPU.
    pub fn new_cpu_blocking(ctx: RainbowTableCtx) -> Self {
        Self::new_cpu(ctx, None).unwrap()
    }

    fn new_cpu(ctx: RainbowTableCtx, sender: Option<Sender<Event>>) -> CugparckResult<Self> {
        let mut partial_chains = Self::startpoints(&ctx);

        for (filtration_number, columns) in FiltrationIterator::new(ctx).enumerate() {
            if let Some(sender) = &sender {
                sender.send(Event::Cpu(columns.clone())).unwrap();
            }

            partial_chains
                .par_iter_mut()
                .for_each(|partial_chain| partial_chain.continue_chain(columns.clone(), &ctx));

            if let Some(sender) = &sender {
                let progress = columns.end as f64 / ctx.t as f64 * 100.;
                sender.send(Event::Progress(progress)).unwrap();
                sender
                    .send(Event::Filtration(filtration_number + 1))
                    .unwrap();
            }

            partial_chains.par_sort_unstable_by_key(|chain| chain.endpoint);
            partial_chains.dedup_by_key(|chain| chain.endpoint);
        }

        partial_chains.shrink_to_fit();
        Ok(Self {
            chains: partial_chains,
            ctx,
        })
    }

    /// Creates a new simple rainbow table, using the GPU, asynchronously.
    /// Returns an handle to get events related to the generation and to get the generated table.
    pub fn new_gpu_nonblocking(ctx: RainbowTableCtx) -> SimpleTableHandle {
        let (sender, receiver) = unbounded();
        let thread_handle = thread::spawn(move || Self::new_gpu(ctx, Some(sender)));

        SimpleTableHandle {
            thread_handle,
            receiver,
        }
    }

    /// Creates a new simple rainbow table, using the GPU.
    pub fn new_gpu_blocking(ctx: RainbowTableCtx) -> CugparckResult<Self> {
        Self::new_gpu(ctx, None)
    }

    /// Creates a new simple rainbow table, using the GPU.
    fn new_gpu(ctx: RainbowTableCtx, sender: Option<Sender<Event>>) -> CugparckResult<Self> {
        cust::init(CudaFlags::empty())?;
        let device = Device::get_device(0)?;
        let _cuda_ctx = Context::new(device);
        let module = Module::from_ptx(PTX, &[])?;
        let stream = Stream::new(StreamFlags::NON_BLOCKING, None)?;
        let chains_kernel = module.get_function("chains_kernel")?;

        let mut partial_chains = Self::startpoints(&ctx);

        for (filtration_number, columns) in FiltrationIterator::new(ctx).enumerate() {
            for (batch_number, batch) in
                BatchIterator::new(partial_chains.len(), &device, &chains_kernel)?.enumerate()
            {
                if let Some(sender) = &sender {
                    sender
                        .send(Event::GpuBatch {
                            batch_number: batch_number + 1,
                            batch_count: batch.count,
                            columns: columns.clone(),
                        })
                        .unwrap();
                }

                let d_batch_chains =
                    DeviceBuffer::from_slice(&partial_chains[batch.range.clone()])?;

                unsafe {
                    launch!(
                        chains_kernel<<<batch.block_count, batch.thread_count, 0, stream>>>(
                            columns.start,
                            columns.end,
                            d_batch_chains.as_device_ptr(),
                            d_batch_chains.len(),
                            ctx,
                        )
                    )?
                }
                stream.synchronize()?;

                let mut batch_chains = d_batch_chains.as_host_vec()?;
                batch_chains.truncate(batch.range.len());

                partial_chains.splice(batch.range, batch_chains);

                if let Some(sender) = &sender {
                    let batch_percent = batch_number as f64 / batch.count as f64;
                    let current_col_progress = columns.len() as f64 * batch_percent;
                    let col_progress = columns.start as f64;
                    let progress = (col_progress + current_col_progress) / ctx.t as f64 * 100.;

                    sender.send(Event::Progress(progress)).unwrap();
                }
            }

            if let Some(sender) = &sender {
                sender
                    .send(Event::Filtration(filtration_number + 1))
                    .unwrap();
            }

            partial_chains.par_sort_unstable_by_key(|chain| chain.endpoint);
            partial_chains.dedup_by_key(|chain| chain.endpoint);
        }

        partial_chains.shrink_to_fit();
        Ok(Self {
            chains: partial_chains,
            ctx,
        })
    }
}

impl RainbowTable for SimpleTable {
    type Iter<'a> = SimpleTableIterator<'a>;

    fn len(&self) -> usize {
        self.chains.len()
    }

    fn iter(&self) -> Self::Iter<'_> {
        self.into_iter()
    }

    fn startpoint(&self, i: usize) -> CompressedPassword {
        self.chains[i].startpoint
    }

    fn search_endpoints(&self, password: CompressedPassword) -> Option<usize> {
        self.chains
            .binary_search_by_key(&password, |chain| chain.endpoint)
            .ok()
    }

    fn ctx(&self) -> RainbowTableCtx {
        self.ctx
    }

    fn from_rainbow_table<T: RainbowTable>(table: T) -> Self {
        Self {
            ctx: table.ctx(),
            chains: table.iter().collect(),
        }
    }
}

impl RainbowTable for ArchivedSimpleTable {
    type Iter<'a> = ArchivedSimpleTableIterator<'a>;

    fn len(&self) -> usize {
        self.chains.len()
    }

    fn iter(&self) -> Self::Iter<'_> {
        self.into_iter()
    }

    fn startpoint(&self, i: usize) -> CompressedPassword {
        self.chains[i]
            .startpoint
            .deserialize(&mut Infallible)
            .unwrap()
    }

    fn search_endpoints(&self, password: CompressedPassword) -> Option<usize> {
        self.chains
            .binary_search_by_key(&password, |chain| {
                chain.endpoint.deserialize(&mut Infallible).unwrap()
            })
            .ok()
    }

    fn ctx(&self) -> RainbowTableCtx {
        self.ctx.deserialize(&mut Infallible).unwrap()
    }

    fn from_rainbow_table<T: RainbowTable>(_: T) -> Self {
        panic!("Archived tables cannot be built from other tables")
    }
}

impl<'a> IntoIterator for &'a SimpleTable {
    type Item = RainbowChain;
    type IntoIter = SimpleTableIterator<'a>;

    fn into_iter(self) -> Self::IntoIter {
        Self::IntoIter::new(self)
    }
}

impl<'a> IntoIterator for &'a ArchivedSimpleTable {
    type Item = RainbowChain;
    type IntoIter = ArchivedSimpleTableIterator<'a>;

    fn into_iter(self) -> Self::IntoIter {
        Self::IntoIter::new(self)
    }
}

pub struct SimpleTableIterator<'a> {
    table: &'a SimpleTable,
    i: usize,
}

pub struct ArchivedSimpleTableIterator<'a> {
    table: &'a ArchivedSimpleTable,
    i: usize,
}

impl<'a> SimpleTableIterator<'a> {
    pub fn new(table: &'a SimpleTable) -> Self {
        Self { table, i: 0 }
    }
}

impl<'a> ArchivedSimpleTableIterator<'a> {
    pub fn new(table: &'a ArchivedSimpleTable) -> Self {
        Self { table, i: 0 }
    }
}

impl Iterator for SimpleTableIterator<'_> {
    type Item = RainbowChain;

    fn next(&mut self) -> Option<Self::Item> {
        if self.i >= self.table.chains.len() {
            return None;
        }

        let ret = Some(self.table.chains[self.i]);
        self.i += 1;

        ret
    }
}

impl Iterator for ArchivedSimpleTableIterator<'_> {
    type Item = RainbowChain;

    fn next(&mut self) -> Option<Self::Item> {
        if self.i >= self.table.chains.len() {
            return None;
        }

        let ret = Some(
            self.table.chains[self.i]
                .deserialize(&mut Infallible)
                .unwrap(),
        );
        self.i += 1;

        ret
    }
}

impl RainbowTableStorage for SimpleTable {}

impl std::fmt::Debug for SimpleTable {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let chains_num = self.chains.len().min(10);
        let some_chains = &self.chains[..chains_num];

        for RainbowChain {
            startpoint,
            endpoint,
        } in some_chains
        {
            writeln!(
                f,
                "{} -> {}",
                core::str::from_utf8(&startpoint.into_password(&self.ctx)).unwrap(),
                core::str::from_utf8(&endpoint.into_password(&self.ctx)).unwrap(),
            )?;
        }
        writeln!(f, "...")
    }
}
