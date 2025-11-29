// backend/src/compute/mod.rs

use crate::models::{Session, SessionRequest};

pub mod traits;
pub mod types;
pub mod error;
pub mod common;
pub mod providers;

pub use traits::ComputeProvider;
pub use providers::local::provider::{LocalComputeProvider, LocalProviderConfig};
