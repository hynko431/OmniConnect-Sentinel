#![forbid(unsafe_code)]
#![deny(clippy::unwrap_used, clippy::expect_used)]
//! Generated gRPC server bindings for OmniConnect Sentinel CDR service.

pub mod v1 {
    tonic::include_proto!("sentinel.cdr.v1");
}

pub use prost::Message;
pub use v1::*;
