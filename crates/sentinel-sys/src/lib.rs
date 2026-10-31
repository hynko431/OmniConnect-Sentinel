//! Low-level operating system security primitives for OmniConnect Sentinel.
//!
//! Sub-Phase 1.2: Adds fail-closed MountMgr & USB volume posture controls.

pub mod fs_lowlevel;
pub mod mem_guard;
pub mod mount_control;