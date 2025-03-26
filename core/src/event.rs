use crate::{error::CugparckResult, rainbow_table::SimpleTable};
use std::{ops::Range, sync::mpsc::Receiver, thread::JoinHandle};

/// An event to track the progress of the generation of a rainbow table.
#[derive(Debug)]
pub enum Event {
    FiltrationStep {
        col_start: u64,
        unique_chains: usize,
    },

    /// Overall progress of the rainbow table generation in percent.
    Progress(f64),
    /// The nth batch of chains is being computed.
    Batch {
        batch_number: u64,
        batch_count: u64,
        columns: Range<usize>,
    },
}

pub struct SimpleTableHandle {
    pub handle: JoinHandle<CugparckResult<SimpleTable>>,
    pub receiver: Receiver<Event>,
}
