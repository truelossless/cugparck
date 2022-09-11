//! The different backends that can be used to generate rainbow tables.

#[cfg(feature = "cuda")]
pub use crate::renderer::cuda::Cuda;

#[cfg(feature = "wgpu")]
pub use crate::renderer::wgpu::{Dx11, Dx12, Metal, OpenGL, Vulkan};

pub use crate::renderer::cpu::Cpu;

use crate::{error::CugparckResult, renderer::Renderer};

/// A backend that can be used to generate rainbow tables.
pub trait Backend {
    /// The renderer that produces this backend.
    type Renderer: Renderer;

    /// Returns the renderer.
    fn renderer(chains_len: usize) -> CugparckResult<Self::Renderer>;
}
