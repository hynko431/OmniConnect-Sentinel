//! Isolated OS FFI boundary crate for OmniConnect-Sentinel (Phase 0.3).
//!
//! All other workspace crates (`sentinel-cdr`, `sentinel-core`, `sentinel-cli`)
//! enforce `#![forbid(unsafe_code)]` and delegate low-level OS interactions here.

#![deny(clippy::unwrap_used, clippy::expect_used)]

pub mod crypto_seal;
pub mod fs_lowlevel;
pub mod mem_guard;
pub mod mount_control;
pub mod sandbox_worker;

pub use crypto_seal::{
    create_sealed_ecdsa_p256_keypair, decrypt_kek_from_soc_escrow, default_soc_rsa_public_blob,
    encrypt_kek_for_soc_escrow, generate_raw_ecdsa_p256_keypair, generate_soc_rsa_keypair,
    is_tpm2_pcp_available, seal_key_bytes, sign_ecdsa_p256_with_private_blob,
    sign_with_sealed_ecdsa_p256, unseal_key_bytes, verify_ecdsa_p256_digest,
    write_protected_key_file, KeyProtectionPosture, SealedEcdsaKeyPair, SealedKeyBlob,
    SocEscrowBlob,
};
pub use fs_lowlevel::{
    apply_system_admin_dacl, classify_media_characteristics, create_restricted_dir_atomic,
    create_restricted_file_atomic, create_restricted_file_handle_atomic,
    ensure_not_symlink_or_reparse_point, enumerate_ntfs_ads, flush_hardware_buffers,
    is_projfs_available, is_reparse_point_or_symlink, issue_file_level_trim,
    normalize_file_attributes, open_no_buffering_write_through, open_untrusted_readonly_nofollow,
    open_write_through, prj_start_virtualizing_root, prj_write_file_data, query_media_type,
    query_sector_alignment, query_sector_alignment_for_path, read_untrusted_to_end_bounded,
    sync_directory, to_verbatim_path, write_mark_of_the_web, AlignedSectorBuffer, MediaType,
    ProjFsInstanceHandle,
};
pub use mem_guard::{zeroize_slice, ZeroizingBytes};
pub use mount_control::{
    apply_autoplay_suppression_policy, apply_usb_storage_and_install_policies,
    cleanup_unapproved_usb_devices, delete_volume_mount_point, disable_device_node,
    disable_usb_interface, enable_device_node, enumerate_usb_pnp_devices, enumerate_usb_volumes,
    get_removable_drives, is_hardware_id_allowed, is_volume_offline, is_volume_readonly,
    purge_stale_mounted_devices, query_automount_disabled, read_registry_dword,
    read_registry_string, register_pnp_notification_watcher, resolve_physical_drive_path,
    set_automount_disabled, set_volume_offline, set_volume_online_readonly, verify_system_posture,
    with_readonly_volume_window, PnpNotificationGuard, PostureReport, UsbPnpDeviceInfo,
    UsbVolumeInfo, BUS_TYPE_USB, IOCTL_MOUNTMGR_QUERY_AUTO_MOUNT, IOCTL_MOUNTMGR_SET_AUTO_MOUNT,
};
pub use sandbox_worker::{
    apply_worker_process_mitigations, assign_child_to_sandbox_job, create_acl_named_pipe_server,
    spawn_sandboxed_worker_process, verify_binary_authenticode_signature,
    verify_named_pipe_client_pid, verify_named_pipe_peer_credentials, JobSandboxConfig,
    JobSandboxGuard, PeerCredentials, SandboxedChildProcess, DEFAULT_NAMED_PIPE_ENDPOINT,
};
