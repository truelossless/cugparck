//! The different backends that can be used to generate rainbow tables.

use wgpu::Backends;

use crate::{
    error::CugparckResult,
    renderer::{CpuRenderer, Renderer, WgpuRenderer},
};

/// A backend that can be used to generate rainbow tables.
pub trait Backend {
    /// The renderer that produces this backend.
    type Renderer: Renderer;

    /// Returns the renderer.
    fn renderer() -> CugparckResult<Self::Renderer>;
}

/// A CUDA backend.
#[cfg(feature = "cuda")]
pub struct Cuda;

#[cfg(feature = "cuda")]
impl Backend for Cuda {
    type Renderer = renderer::CudaRenderer;

    fn renderer() -> CugparckResult<Self::Renderer> {
        Self::Renderer::new()
    }
}

/// A multithreaded CPU backend.
pub struct Cpu;

impl Backend for Cpu {
    type Renderer = CpuRenderer;

    fn renderer() -> CugparckResult<Self::Renderer> {
        Self::Renderer::new()
    }
}

/// A Vulkan backend powered by wgpu.
pub struct Vulkan;

impl Backend for Vulkan {
    type Renderer = WgpuRenderer;

    fn renderer() -> CugparckResult<Self::Renderer> {
        Self::Renderer::new(Backends::VULKAN)
    }
}

/// A DirectX 12 backend powered by wgpu.
pub struct Dx12;

impl Backend for Dx12 {
    type Renderer = WgpuRenderer;

    fn renderer() -> CugparckResult<Self::Renderer> {
        Self::Renderer::new(Backends::DX12)
    }
}

/// A Metal backend powered by wgpu.
pub struct Metal;

impl Backend for Metal {
    type Renderer = WgpuRenderer;

    fn renderer() -> CugparckResult<Self::Renderer> {
        Self::Renderer::new(Backends::METAL)
    }
}

/// An OpenGL ES 3 backend powered by wgpu.
pub struct OpenGL;

impl Backend for OpenGL {
    type Renderer = WgpuRenderer;

    fn renderer() -> CugparckResult<Self::Renderer> {
        Self::Renderer::new(Backends::GL)
    }
}

/// A DirectX 11 backend powered by wgpu.
pub struct Dx11;

impl Backend for Dx11 {
    type Renderer = WgpuRenderer;

    fn renderer() -> CugparckResult<Self::Renderer> {
        Self::Renderer::new(Backends::DX11)
    }
}
