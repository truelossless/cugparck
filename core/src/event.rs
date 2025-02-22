use crate::{error::CugparckResult, rainbow_table::SimpleTable};
use std::{ops::Range, sync::mpsc::Receiver, thread::JoinHandle};

/// An event to track the progress of the generation of a rainbow table.
pub enum Event {
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
    pub(crate) handle: JoinHandle<CugparckResult<SimpleTable>>,
    pub(crate) receiver: Receiver<Event>,
}

impl SimpleTableHandle {
    /// Returns the generated rainbow table.
    /// Blocks until the table is finished.
    pub fn join(self) -> CugparckResult<SimpleTable> {
        self.handle.join().unwrap()
    }

    /// Blocks until an event is received.
    /// Returns `None` if the rainbow table is finished.
    pub fn recv(&mut self) -> Option<Event> {
        self.receiver.recv().ok()
    }
}
