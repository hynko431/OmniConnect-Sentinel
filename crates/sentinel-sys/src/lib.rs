//! Low-level operating system security primitives for OmniConnect Sentinel.
//!
//! Sub-Phase 1.3: Adds process-isolated CDR worker sandbox and Named Pipe ACLs.

pub mod fs_lowlevel;
pub mod mem_guard;
pub mod mount_control;
pub mod sandbox_worker;