use crate::{error::CugparckResult, rainbow_table::SimpleTable};
use std::{ops::Range, sync::mpsc::Receiver, thread::JoinHandle};

/// The status of a batch of chains sent to be computed.
#[derive(Debug)]
pub enum BatchStatus {
    // The batch is being copied from the host (CPU RAM) to the device (GPU VRAM).
    CopyHostToDevice,
    /// The batch is being computed.
    ComputationStarted,
    // The batch is being copied from the device (GPU VRAM) to the host (CPU RAM).
    CopyDeviceToHost,
    /// The filtration of the batch started.
    FiltrationStarted,
    /// The filtration of the batch is finished.
    FiltrationFinished,
}

/// An event to track the progress of the generation of a rainbow table.
#[derive(Debug)]
pub enum Event {
    /// A new computation step has started.
    ComputationStepStarted {
        /// The columns of the chains that are being calculated.
        columns: Range<usize>,
        /// The number of batches required.
        batch_count: u64,
    },

    /// The computation step has finished.
    ComputationStepFinished {
        /// The count of unique chains after filtering the results of this step.
        unique_chains: u64,
    },

    Progress(f64),

    Batch {
        number: u64,
        producer: u8,
        status: BatchStatus,
    },
}

pub struct SimpleTableHandle {
    pub handle: JoinHandle<CugparckResult<SimpleTable>>,
    pub receiver: Receiver<Event>,
}
