//! Renderer using wgpu.
//! Supports the following backends:
//! - Vulkan, DX12, DX11 on Windows
//! - Vulkan, GLES 3 on Linux
//! - Metal on MacOS

use std::{borrow::Cow, iter::Once, mem, ops::Range};

use cugparck_commons::{FullCtx, RainbowChain, RainbowTableCtx};
use pollster::FutureExt;
use wgpu::{
    util::{BufferInitDescriptor, DeviceExt},
    Backends, BindGroupDescriptor, BindGroupEntry, BufferAddress, BufferDescriptor, BufferUsages,
    CommandEncoderDescriptor, ComputePassDescriptor, ComputePipelineDescriptor, Device,
    DeviceDescriptor, Features, Instance, Limits, Maintain, PowerPreference, Queue,
    RequestAdapterOptions, ShaderModule, ShaderModuleDescriptor, ShaderSource,
};

use crate::{error::CugparckResult, CugparckError};

use super::Renderer;

/// A wgpu renderer.
// Most of the code has been taken from the wgpu "hello_compute" example.
pub struct WgpuRenderer {
    device: Device,
    module: ShaderModule,
    queue: Queue,
}

impl WgpuRenderer {
    pub fn new(backend: Backends) -> CugparckResult<Self> {
        Self::new_async(backend).block_on()
    }

    async fn new_async(backend: Backends) -> CugparckResult<Self> {
        let instance = Instance::new(backend);

        let adapter = instance
            .request_adapter(&RequestAdapterOptions {
                power_preference: PowerPreference::HighPerformance,
                ..Default::default()
            })
            .await
            .ok_or(CugparckError::NoGpu)?;

        let (device, queue) = adapter
            .request_device(
                &DeviceDescriptor {
                    label: None,
                    features: Features::empty(),
                    limits: Limits::downlevel_defaults(),
                },
                None,
            )
            .await
            .unwrap();

        let module = device.create_shader_module(ShaderModuleDescriptor {
            label: None,
            source: ShaderSource::SpirV(Cow::Borrowed(include_str!("module.spirv"))),
        });

        Ok(WgpuRenderer {
            device,
            module,
            queue,
        })
    }

    async fn run_kernel_async<'a>(
        &self,
        batch: &'a mut [RainbowChain],
        batch_info: &BatchInfo,
        columns: Range<usize>,
        ctx: RainbowTableCtx,
    ) -> CugparckResult<Cow<'a, [RainbowChain]>> {
        let slice_size = batch.len() * mem::size_of::<RainbowChain>();
        let size = slice_size as BufferAddress;

        let full_ctx = FullCtx {
            col_start: columns.start,
            col_end: columns.end,
            ctx,
        };

        let staging_buffer = self.device.create_buffer(&BufferDescriptor {
            label: Some("Staging Buffer"),
            size,
            usage: BufferUsages::MAP_READ | BufferUsages::COPY_DST,
            mapped_at_creation: false,
        });

        let storage_buffer = self.device.create_buffer_init(&BufferInitDescriptor {
            label: Some("Storage Buffer"),
            contents: bytemuck::cast_slice(batch),
            usage: BufferUsages::STORAGE | BufferUsages::COPY_DST | BufferUsages::COPY_SRC,
        });

        let ctx_buffer = self.device.create_buffer_init(&BufferInitDescriptor {
            label: Some("Ctx Uniform"),
            contents: bytemuck::cast_slice(&ctx),
            usage: BufferUsages::UNIFORM | BufferUsages::COPY_DST,
        });

        let compute_pipeline = self
            .device
            .create_compute_pipeline(&ComputePipelineDescriptor {
                label: None,
                layout: None,
                module: &self.module,
                entry_point: "chains_kernel",
            });

        let storage_bind_group_layout = compute_pipeline.get_bind_group_layout(0);
        let storage_bind_group = self.device.create_bind_group(&BindGroupDescriptor {
            label: None,
            layout: &storage_bind_group_layout,
            entries: &[BindGroupEntry {
                binding: 0,
                resource: storage_buffer.as_entire_binding(),
            }],
        });

        let ctx_bind_group_layout = compute_pipeline.get_bind_group_layout(1);
        let ctx_bind_group = self.device.create_bind_group(&BindGroupDescriptor {
            label: None,
            layout: &ctx_bind_group_layout,
            entries: &[BindGroupEntry {
                binding: 0,
                resource: ctx_buffer.as_entire_binding(),
            }],
        });

        let mut encoder = self
            .device
            .create_command_encoder(&CommandEncoderDescriptor { label: None });
        {
            let mut cpass = encoder.begin_compute_pass(&ComputePassDescriptor { label: None });
            cpass.set_pipeline(&compute_pipeline);
            cpass.set_bind_group(0, &storage_bind_group, &[]);
            cpass.dispatch_workgroups(batch.len() as u32, 1, 1);
        }
        encoder.copy_buffer_to_buffer(&storage_buffer, 0, &staging_buffer, 0, size);

        self.queue.submit(Some(encoder.finish()));

        let buffer_slice = staging_buffer.slice(..);

        let (sender, receiver) = crossbeam_channel::bounded(1);
        buffer_slice.map_async(wgpu::MapMode::Read, move |v| sender.send(v).unwrap());

        self.device.poll(Maintain::Wait);

        match receiver.recv() {
            Ok(Ok(())) => (),
            Ok(Err(e)) => return Err(e.into()),
            _ => unreachable!(),
        }

        let data = buffer_slice.get_mapped_range();
        let result = bytemuck::cast_slice(&data).to_vec();

        drop(data);
        staging_buffer.unmap();

        // Returns data from buffer
        Ok(Cow::Owned(result))
    }
}

impl Renderer for WgpuRenderer {
    type BatchIterator = Once<BatchInfo>;
    type BatchInfo = BatchInfo;

    fn batch_iter(&self, chains_len: usize) -> CugparckResult<Self::BatchIterator> {
        todo!()
    }

    fn batch_slice<'a>(
        &self,
        chains: &'a mut [RainbowChain],
        batch_info: &Self::BatchInfo,
    ) -> &'a mut [RainbowChain] {
        todo!()
    }

    fn run_kernel<'a>(
        &self,
        batch: &'a mut [RainbowChain],
        batch_info: &Self::BatchInfo,
        columns: Range<usize>,
        ctx: RainbowTableCtx,
    ) -> CugparckResult<Cow<'a, [RainbowChain]>> {
        self.run_kernel_async(batch, batch_info, columns, ctx)
            .block_on()
    }
}

pub struct BatchInfo {
    range: Range<usize>,
}
