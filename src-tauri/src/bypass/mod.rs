#![allow(dead_code, unused_imports)]

pub mod context;
pub mod pipeline;
pub mod strategies;
pub mod strategy;

pub use context::BypassContext;
pub use pipeline::BypassPipeline;
pub use strategy::BypassStrategy;

pub fn default_pipeline() -> BypassPipeline {
    BypassPipeline::default()
}
