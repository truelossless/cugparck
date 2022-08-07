use std::io;

use thiserror::Error;

pub type CugparckResult<T> = std::result::Result<T, CugparckError>;

#[derive(Error, Debug)]
pub enum CugparckError {
    #[error("Failed to validate the rainbow table. Is the file corrupted?")]
    Check,

    #[cfg(feature = "cuda")]
    #[error("A CUDA-related error occured")]
    Cuda(#[from] cust::error::CudaError),

    #[error(
        "Unable to access the file at the given path. Make sure the right permissions are available"
    )]
    Io(#[from] io::Error),

    #[error("Failed to serialize the rainbow table")]
    Serialize,

    #[error("Cugparck only supports spaces up to 2^64, but the provided space is {0}")]
    Space(u8),
}
