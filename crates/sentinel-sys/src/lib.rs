//! Low-level operating system security primitives for OmniConnect Sentinel.
//!
//! Sub-Phase 1.1: Pinned memory locking (mem_guard) and low-level file/disk
//! operations (s_lowlevel).

pub mod fs_lowlevel;
pub mod mem_guard;