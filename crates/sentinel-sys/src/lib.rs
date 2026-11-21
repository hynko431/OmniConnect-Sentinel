//! Isolated OS FFI boundary crate for OmniConnect-Sentinel (Phase 0.3).
//!
//! All other workspace crates (`sentinel-cdr`, `sentinel-core`, `sentinel-cli`)
//! enforce `#![forbid(unsafe_code)]` and delegate low-level OS interactions here.

#![deny(clippy::unwrap_used, clippy::expect_used)]

pub mod bpf_sandbox;
pub mod crypto_seal;
pub mod fs_lowlevel;
pub mod mem_guard;
pub mod mount_control;
pub mod sandbox_worker;
pub mod windows_service;

pub use bpf_sandbox::{
    generate_seccomp_bpf_filter_aarch64, generate_seccomp_bpf_filter_x86_64,
    landlock_handled_access_fs, simulate_seccomp_filter, SeccompData, SockFilter, SockFprog,
    AARCH64_ALLOWED_SIMPLE_SYSCALLS, AUDIT_ARCH_AARCH64, AUDIT_ARCH_X86_64, PROT_EXEC,
    SECCOMP_RET_ALLOW, SECCOMP_RET_KILL_PROCESS, X32_SYSCALL_BIT, X86_64_ALLOWED_SIMPLE_SYSCALLS,
};

pub use crypto_seal::{
    create_sealed_ecdsa_p256_keypair, decrypt_kek_from_soc_escrow,
    decrypt_kek_from_soc_escrow_hybrid_v3, decrypt_kek_from_soc_escrow_software,
    decrypt_ocescrow3_wire_envelope, encode_ocescrow3_wire, encrypt_kek_for_soc_escrow,
    encrypt_kek_for_soc_escrow_hybrid_v3, encrypt_kek_for_soc_escrow_software,
    evaluate_strict_kiosk_key_posture, export_rsa_private_key_to_cng, export_rsa_public_key_to_cng,
    fips202_sha3_256, generate_ecdsa_p256_keypair_from_seed, generate_hybrid_soc_keypair_v3,
    generate_hybrid_soc_keypair_with_bits, generate_mlkem768_keypair,
    generate_raw_ecdsa_p256_keypair, generate_soc_rsa_3072_keypair_software,
    generate_soc_rsa_keypair, generate_soc_rsa_keypair_software, hkdf_sha256_derive_32,
    is_linux_tpm2_device_present, is_tpm2_pcp_available, parse_rsa_private_key,
    parse_rsa_public_key, resolve_linux_key_sealing_backend, seal_key_bytes,
    sign_ecdsa_p256_with_private_blob, sign_with_sealed_ecdsa_p256, unseal_key_bytes,
    validate_fips203_mlkem768_decapsulation_key, validate_fips203_mlkem768_encapsulation_key,
    validate_p256_uncompressed_point, verify_ecdsa_p256_digest, write_protected_key_file,
    HybridSocEscrowBlobV3, HybridSocPrivateKeyBundle, HybridSocPublicKeyBundle,
    KeyProtectionPosture, SealedEcdsaKeyPair, SealedKeyBlob, SocEscrowBlob, MLKEM768_CT_LEN,
    MLKEM768_DK_LEN, MLKEM768_EK_LEN, OCESCROW3_MAGIC, TPM_OAEP_ALLOWED_ALGORITHMS,
};
pub use fs_lowlevel::{
    apply_readonly_staging_dacl, apply_system_admin_dacl, classify_media_characteristics,
    create_readonly_staging_dir_atomic, create_readonly_staging_file_atomic,
    create_restricted_dir_atomic, create_restricted_file_atomic,
    create_restricted_file_handle_atomic, ensure_not_symlink_or_reparse_point, enumerate_ntfs_ads,
    flush_hardware_buffers, is_projfs_available, is_projfs_reparse_point,
    is_reparse_point_or_symlink, issue_file_level_trim, normalize_file_attributes,
    open_no_buffering_write_through, open_untrusted_readonly_nofollow, open_write_through,
    prj_start_virtualizing_root, prj_write_file_data, query_media_type, query_path_dacl_sddl,
    query_sector_alignment, query_sector_alignment_for_path, read_untrusted_to_end_bounded,
    sync_directory, to_verbatim_path, write_mark_of_the_web, AlignedSectorBuffer, MediaType,
    ProjFsInstanceHandle, ProjFsProjectedEntry, ProjFsVirtualizerBackend, IO_REPARSE_TAG_PROJFS,
    STAGING_DIR_READONLY_USER_SDDL, STAGING_FILE_READONLY_USER_SDDL,
};
pub use mem_guard::{zeroize_slice, ZeroizingBytes};
pub use mount_control::{
    apply_autoplay_suppression_policy, apply_usb_storage_and_install_policies,
    attribute_volume_to_pnp_device, build_windows_scoped_storage_install_policy,
    cleanup_unapproved_usb_devices, collect_linux_mount_points_for_target,
    collect_linux_mount_points_for_volume_and_dev, decode_utf16_reg_sz_bytes,
    delete_volume_mount_point, detect_hardware_write_blocker_state, disable_device_node,
    disable_usb_interface, enable_device_node, enumerate_usb_pnp_devices, enumerate_usb_volumes,
    evaluate_airgap_hardware_clock_attestation, extract_linux_usb_bus_port_from_sysfs_path,
    get_removable_drives, is_hardware_id_allowed, is_valid_linux_usb_bus_port,
    is_valid_linux_usb_interface_id, is_volume_offline, is_volume_readonly,
    normalize_linux_block_device_name, parse_airgap_clock_config_str, parse_w32tm_status_output,
    parse_w32tm_status_output_with_tz_offset, parse_windows_usb_vid_pid_serial,
    purge_stale_mounted_devices, query_automount_disabled, query_ntp_sync_status,
    read_registry_dword, read_registry_string, read_registry_string_from_hive,
    register_pnp_notification_watcher, render_linux_udev_usb_storage_rules,
    resolve_linux_mount_block_device_from_proc_mounts, resolve_linux_usb_authorized_sysfs_path,
    resolve_physical_drive_path, resolve_volume_usb_topology,
    resolve_windows_ancestor_usb_instance, set_automount_disabled, set_volume_offline,
    set_volume_online_readonly, validate_linux_sysfs_leaf_target, verify_linux_udev_rules_content,
    verify_scoped_storage_registry_lists, verify_system_posture, with_readonly_volume_window,
    AirgapHardwareClockAttestation, HardwareWriteBlockerState, NtpSyncStatus, PnpNotificationGuard,
    PostureReport, ScopedStorageInstallPolicySpec, UsbPnpDeviceInfo, UsbTopologyAttribution,
    UsbVolumeInfo, BUS_TYPE_USB, IOCTL_MOUNTMGR_QUERY_AUTO_MOUNT, IOCTL_MOUNTMGR_SET_AUTO_MOUNT,
    IOCTL_STORAGE_GET_DEVICE_NUMBER, LINUX_BLKROSET_IOCTL, LINUX_UDEV_RULES_PATH,
    MAX_REGISTRY_STRING_BYTES, MAX_USB_TOPOLOGY_HOPS, NTP_MAX_STALE_AGE_SECS,
    REMOVABLE_STORAGE_POLICY_CLASS_GUIDS, SCOPED_STORAGE_DENY_CLASS_GUIDS,
    SCOPED_STORAGE_DENY_DEVICE_IDS, SENTINEL_AIRGAP_CLOCK_ATTESTATION_ENV,
    SENTINEL_AIRGAP_CLOCK_CONFIG_ENV, SENTINEL_KIOSK_BAY1_RO_DEVICE_ENV,
    SENTINEL_KIOSK_BAY2_RW_DEVICE_ENV, WPD_DEVICE_SETUP_CLASS_GUID,
};
pub use sandbox_worker::{
    apply_worker_process_mitigations, assign_child_to_sandbox_job, close_raw_kernel_handle,
    create_acl_named_pipe_server, current_process_session_id, evaluate_sandbox_enforcement_failure,
    is_unsafe_dev_sandbox_opt_in, query_kernel_handle_dacl_sddl,
    resolve_appcontainer_strategy_for_session, spawn_sandboxed_worker_process,
    verify_appcontainer_sid_derivation, verify_binary_authenticode_signature,
    verify_named_pipe_client_pid, verify_named_pipe_peer_credentials, AppContainerSessionStrategy,
    JobSandboxConfig, JobSandboxGuard, LocalIpcServer, LocalIpcStream, PeerCredentials,
    SandboxedChildProcess, DEFAULT_CDR_NAMED_PIPE_ENDPOINT, DEFAULT_CDR_UNIX_SOCKET_PATH,
    DEFAULT_NAMED_PIPE_ENDPOINT, NAMED_PIPE_SERVER_SDDL,
};
pub use windows_service::{
    build_scm_status, run_windows_service, scm_control_triggers_shutdown, ScmServiceStatusSnapshot,
    ERROR_SERVICE_SPECIFIC_ERROR, SENTINEL_WINDOWS_SERVICE_NAME, SERVICE_ACCEPT_SHUTDOWN,
    SERVICE_ACCEPT_STOP, SERVICE_CONTROL_INTERROGATE, SERVICE_CONTROL_SHUTDOWN,
    SERVICE_CONTROL_STOP, SERVICE_RUNNING, SERVICE_START_PENDING, SERVICE_STOPPED,
    SERVICE_STOP_PENDING, SERVICE_WIN32_OWN_PROCESS,
};
