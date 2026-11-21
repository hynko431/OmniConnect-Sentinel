#![forbid(unsafe_code)]
#![deny(clippy::unwrap_used, clippy::expect_used)]

use std::path::PathBuf;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;
use std::time::Duration;
use tracing::{info, warn};
use tracing_subscriber::{layer::SubscriberExt, util::SubscriberInitExt};

use sentinel_core::config::SentinelConfig;
use sentinel_core::enterprise::falcon::{CrowdStrikeFalconBridge, FalconTelemetryEvent};
use sentinel_core::enterprise::intune::IntunePolicyManager;
use sentinel_core::enterprise::ledger::{
    get_or_init_global_shared_ledger, tokenize_path_for_ledger, AuditSubsystem, SharedAuditLedger,
};
use sentinel_core::error::SentinelMetrics;
use sentinel_core::events::ConnectionVector;
use sentinel_core::interceptor::{resolve_best_interceptor, PendingDeviceConfirmationManager};
use sentinel_core::scanner::quarantine::QuarantineVault;
use sentinel_core::scanner::tier1_cdr_client::Tier1CdrClient;
use sentinel_core::vfs::resolve_best_vfs_provider_with_ledger;

fn append_system_ledger(shared_ledger: &SharedAuditLedger, event: &str, msg: &str) {
    if let Ok(mut guard) = shared_ledger.lock() {
        let _ = guard.append_subsystem_event(
            AuditSubsystem::System,
            event,
            serde_json::Value::String(msg.to_string()),
        );
    }
}

fn main() -> Result<(), Box<dyn std::error::Error>> {
    let run_as_windows_service = std::env::args().any(|arg| arg == "--service");
    if run_as_windows_service {
        sentinel_sys::run_windows_service(
            sentinel_sys::SENTINEL_WINDOWS_SERVICE_NAME,
            |shutdown_flag| {
                let rt = tokio::runtime::Builder::new_multi_thread()
                    .enable_all()
                    .build()?;
                rt.block_on(run_agent(shutdown_flag))
                    .map_err(|e| std::io::Error::other(e.to_string()))
            },
        )?;
        return Ok(());
    }

    let rt = tokio::runtime::Builder::new_multi_thread()
        .enable_all()
        .build()?;
    rt.block_on(run_agent(Arc::new(AtomicBool::new(false))))
}

async fn run_agent(shutdown_flag: Arc<AtomicBool>) -> Result<(), Box<dyn std::error::Error>> {
    let _ = tracing_subscriber::registry()
        .with(tracing_subscriber::EnvFilter::new(
            std::env::var("RUST_LOG").unwrap_or_else(|_| "info,sentinel_core=debug".into()),
        ))
        .with(tracing_subscriber::fmt::layer())
        .try_init();

    info!("===========================================================");
    info!("   OmniConnect Sentinel - Universal Device Interceptor     ");
    info!("        Zero-Trust Peripheral & Connection Sentry          ");
    info!("===========================================================");

    let config = SentinelConfig::default();
    let shared_ledger = get_or_init_global_shared_ledger(None);
    info!("Loaded Agent Node ID: {}", config.node_id);

    // 1. Synchronize Intune MDM Policies (wired to single-root unified AuditLedger)
    let mut policy_mgr = IntunePolicyManager::new().with_shared_ledger(shared_ledger.clone());
    let intune_policy = policy_mgr.load_active_policy();
    info!(
        "Enforcing Policies: PolicyID={}, CDR Mandatory={}, BlockCompositeHID={}, Mode={}",
        intune_policy.policy_id,
        intune_policy.require_cdr_for_documents,
        intune_policy.block_composite_hid_storage,
        intune_policy.enforcement_mode
    );

    // 2. Apply Fail-Closed Mount, AutoPlay, RemovableStorageDeny, DeviceInstall, and Stale Mount Cleanup Policies (Phase 0.1 & Phase 3.1)
    if let Err(e) = sentinel_sys::set_automount_disabled(true) {
        warn!("Startup set_automount_disabled(true) failed: {}", e);
    }
    if let Err(e) = sentinel_sys::apply_autoplay_suppression_policy() {
        warn!("Startup apply_autoplay_suppression_policy failed: {}", e);
    }
    if let Err(e) =
        sentinel_sys::apply_usb_storage_and_install_policies(&intune_policy.allowed_hardware_ids)
    {
        warn!(
            "Startup apply_usb_storage_and_install_policies failed: {}",
            e
        );
    }
    if let Err(e) = sentinel_sys::purge_stale_mounted_devices() {
        warn!("Startup purge_stale_mounted_devices failed: {}", e);
    }
    if let Ok(disabled_ids) =
        sentinel_sys::cleanup_unapproved_usb_devices(&intune_policy.allowed_hardware_ids)
    {
        if !disabled_ids.is_empty() {
            warn!(
                "Disabled {} unapproved/composite USB device(s) at startup: {:?}",
                disabled_ids.len(),
                disabled_ids
            );
        }
    }

    // 3. Verify OS Zero-Trust Endpoint Posture and record in Tamper-Evident Audit Ledger (Row 23)
    let posture = sentinel_sys::verify_system_posture();
    info!(
        "Endpoint Posture Check: Compliant={}, AutoMountDisabled={}, RemovableOffline={:?}, UserDenyPolicy={}, InstallRestricted={}, WriteProtect={}, AutoPlaySuppressed={}",
        posture.is_compliant(),
        posture.automount_disabled,
        posture.removable_volumes_offline,
        posture.user_deny_policy_present,
        posture.install_restrictions_active,
        posture.write_protect_active,
        posture.autoplay_suppressed
    );

    append_system_ledger(
        &shared_ledger,
        "AGENT_STARTUP",
        &format!(
            "Node {} initialized with policy {}",
            config.node_id, intune_policy.policy_id
        ),
    );
    append_system_ledger(
        &shared_ledger,
        "STARTUP_POSTURE_CHECK",
        &format!(
            "compliant={} automount_disabled={} user_deny={} install_restricted={} write_protect={} autoplay_suppressed={} volumes_offline={:?}",
            posture.is_compliant(),
            posture.automount_disabled,
            posture.user_deny_policy_present,
            posture.install_restrictions_active,
            posture.write_protect_active,
            posture.autoplay_suppressed,
            posture.removable_volumes_offline
        ),
    );

    // 4. Initialize VFS Provider (ProjFS on Windows with Read-Once Encrypted Shadow Cache)
    let vfs_provider = resolve_best_vfs_provider_with_ledger(Some(shared_ledger.clone()));
    info!("Active VFS Provider: {}", vfs_provider.provider_name());
    info!(
        "SafeDrive Virtual Mount Path: {}",
        config.safe_drive_mount_path.display()
    );

    // 5. Initialize Tier 1 CDR Client (Sandboxed Pipe Worker default), Quarantine Vault, Confirmation Manager, Metrics, and Falcon SIEM Bridge
    let cdr_client = Arc::new(Tier1CdrClient::new(Default::default()));
    info!(
        "Tier-1 CDR Client initialized for endpoint: {}",
        cdr_client.ipc_endpoint()
    );
    let quarantine_vault = Arc::new(
        QuarantineVault::open(config.quarantine_vault_path.clone())?
            .with_shared_ledger(shared_ledger.clone()),
    );
    if let Some(deg) = quarantine_vault.degradation_event() {
        append_system_ledger(&shared_ledger, "DEGRADATION_EVENT", deg.event_code());
    }
    let confirmation_mgr = PendingDeviceConfirmationManager::new(
        PendingDeviceConfirmationManager::default_state_file(),
    );
    let mut falcon_builder = CrowdStrikeFalconBridge::new(&config.siem_syslog_endpoint)
        .with_shared_ledger(shared_ledger.clone());
    if !config.siem_allowed_private_cidrs.is_empty() {
        let mut parsed_cidrs = Vec::new();
        for cidr_str in &config.siem_allowed_private_cidrs {
            match sentinel_core::enterprise::falcon::AllowedCidr::parse(cidr_str) {
                Ok(cidr) => parsed_cidrs.push(cidr),
                Err(e) => warn!("Ignoring invalid SIEM CIDR '{cidr_str}': {e}"),
            }
        }
        if !parsed_cidrs.is_empty() {
            falcon_builder = falcon_builder.with_allowed_private_cidrs(parsed_cidrs);
        }
    }
    if let Some(ca_path) = &config.siem_ca_cert_path {
        match sentinel_sys::ensure_not_symlink_or_reparse_point(ca_path)
            .and_then(|()| std::fs::read(ca_path))
        {
            Ok(bytes) => falcon_builder = falcon_builder.with_custom_ca(bytes),
            Err(e) => {
                let msg = format!(
                    "Failed loading SIEM custom CA PEM '{}': {e}",
                    ca_path.display()
                );
                warn!("{msg}");
                falcon_builder = falcon_builder.with_tls_config_error(msg);
            }
        }
    }
    match (&config.siem_client_cert_path, &config.siem_client_key_path) {
        (Some(cert_path), Some(key_path)) => {
            let cert_res = sentinel_sys::ensure_not_symlink_or_reparse_point(cert_path)
                .and_then(|()| std::fs::read(cert_path));
            let key_res = sentinel_sys::ensure_not_symlink_or_reparse_point(key_path)
                .and_then(|()| std::fs::read(key_path));
            match (cert_res, key_res) {
                (Ok(cert_pem), Ok(key_pem)) => {
                    falcon_builder = falcon_builder.with_client_mtls(cert_pem, key_pem);
                }
                (Err(e), _) => {
                    let msg = format!(
                        "Failed loading SIEM mTLS client certificate PEM '{}': {e}",
                        cert_path.display()
                    );
                    warn!("{msg}");
                    falcon_builder = falcon_builder.with_tls_config_error(msg);
                }
                (_, Err(e)) => {
                    let msg = format!(
                        "Failed loading SIEM mTLS client private key PEM '{}': {e}",
                        key_path.display()
                    );
                    warn!("{msg}");
                    falcon_builder = falcon_builder.with_tls_config_error(msg);
                }
            }
        }
        (Some(cert_path), None) => {
            let msg = format!(
                "Partial SIEM mTLS config: siem_client_cert_path '{}' set without siem_client_key_path",
                cert_path.display()
            );
            warn!("{msg}");
            falcon_builder = falcon_builder
                .with_client_mtls_optional(Some(Vec::new()), None)
                .with_tls_config_error(msg);
        }
        (None, Some(key_path)) => {
            let msg = format!(
                "Partial SIEM mTLS config: siem_client_key_path '{}' set without siem_client_cert_path",
                key_path.display()
            );
            warn!("{msg}");
            falcon_builder = falcon_builder
                .with_client_mtls_optional(None, Some(Vec::new()))
                .with_tls_config_error(msg);
        }
        (None, None) => {}
    }
    let falcon_bridge = Arc::new(falcon_builder);
    info!(
        "SIEM Falcon Bridge initialized (endpoint={}, mtls_enforced={})",
        config.siem_syslog_endpoint,
        falcon_bridge.is_mtls_enforced()
    );
    // CSE-23: Drain buffered SIEM spool records immediately on agent startup
    match falcon_bridge.flush_spool() {
        Ok(flushed) if flushed > 0 => {
            info!("Flushed {flushed} buffered SIEM telemetry record(s) on agent startup");
        }
        Ok(_) => {}
        Err(e) => {
            warn!("Startup SIEM spool flush deferred: {e}");
        }
    }
    let metrics = Arc::new(SentinelMetrics::default());

    // 6. Start Universal Hardware Interceptor (retaining tx in background task - BUG-CORE-01)
    let interceptor = resolve_best_interceptor();
    let mut event_rx = interceptor.start_monitoring().await?;

    // 7. 60-Second Health Beacon & Fail-Closed Mount Posture Reconciliation Timer (Phase 0.1 & Phase 4.5)
    let mut reconcile_interval = tokio::time::interval(Duration::from_secs(60));
    reconcile_interval.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Delay);
    reconcile_interval.tick().await; // consume initial tick

    // 8. 250ms SCM Shutdown Signal Poll (ensures graceful teardown on SERVICE_CONTROL_STOP/SHUTDOWN) (`CSE-26`)
    let mut scm_shutdown_poll = tokio::time::interval(Duration::from_millis(250));
    scm_shutdown_poll.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Delay);
    scm_shutdown_poll.tick().await;

    info!("Sentinel Agent running. Zero BSOD risk: 100% userspace execution.");
    info!("Monitoring physical wire, LAN, Wi-Fi, and Bluetooth channels...");

    // Event Loop (BUG-CORE-01 + Phase 0.1/3.1/4.5 60s posture reconciliation & heartbeat beacon + CSE-26 SCM stop)
    loop {
        if shutdown_flag.load(Ordering::Acquire) {
            info!("Windows SCM shutdown signal received; tearing down Sentinel Agent cleanly.");
            break;
        }
        tokio::select! {
            _ = scm_shutdown_poll.tick() => {
                if shutdown_flag.load(Ordering::Acquire) {
                    info!("Windows SCM shutdown signal received; tearing down Sentinel Agent cleanly.");
                    break;
                }
            }
            _ = tokio::signal::ctrl_c() => {
                info!("Ctrl+C shutdown signal received; tearing down Sentinel Agent cleanly.");
                break;
            }
            maybe_event = event_rx.recv() => {
                let event = match maybe_event {
                    Some(ev) => ev,
                    None => break,
                };
                info!("Intercepted connection event: {:?}", event.vector);

                match &event.vector {
                    ConnectionVector::WiredUsb {
                        vid,
                        pid,
                        serial,
                        device_instance_id,
                        interfaces,
                    } => {
                        let has_hid = interfaces.iter().any(|i| i.interface_class == 0x03);
                        let has_storage = interfaces.iter().any(|i| i.interface_class == 0x08);
                        let policy_hw_id = format!("USB\\VID_{vid:04X}&PID_{pid:04X}\\{serial}");
                        // CSE-24 / CSE-25: Use the exact OS-attributed device node ID (Windows
                        // `USB\VID_...` instance ID or Linux canonical sysfs bus-port `1-2.3`)
                        // when disabling hardware rather than fabricating Windows IDs on Linux.
                        let os_node_id = match device_instance_id.as_deref() {
                            Some(id) if !id.trim().is_empty() => id.trim().to_string(),
                            _ => {
                                #[cfg(windows)]
                                {
                                    policy_hw_id.clone()
                                }
                                #[cfg(not(windows))]
                                {
                                    if sentinel_sys::is_valid_linux_usb_bus_port(serial.trim()) {
                                        serial.trim().to_string()
                                    } else {
                                        String::new()
                                    }
                                }
                            }
                        };

                        // 1. Hardware ID Allowlist Enforcement (Row 141, CSE-24)
                        let hw_allowed = sentinel_sys::is_hardware_id_allowed(
                            &policy_hw_id,
                            &intune_policy.allowed_hardware_ids,
                        ) || sentinel_sys::is_hardware_id_allowed(
                            &os_node_id,
                            &intune_policy.allowed_hardware_ids,
                        );
                        if !hw_allowed {
                            warn!(
                                "Unapproved USB Hardware ID {} (node={}) rejected by policy — severing data lines!",
                                policy_hw_id, os_node_id
                            );
                            metrics.sentinel_threats_total.fetch_add(1, Ordering::Relaxed);
                            if let Err(e) = interceptor.sever_data_lines(&os_node_id).await {
                                warn!("sever_data_lines failed for {}: {}", os_node_id, e);
                            }
                            append_system_ledger(
                                &shared_ledger,
                                "HARDWARE_ID_BLOCKED",
                                &format!("Blocked unapproved hardware ID {policy_hw_id} (node={os_node_id})"),
                            );
                            continue;
                        }

                        // 2. Composite HID+MassStorage BadUSB Detection & Physical User Confirmation Gate (Rows 3, 142)
                        if intune_policy.block_composite_hid_storage
                            && has_hid
                            && has_storage
                            && !confirmation_mgr.is_confirmed(&os_node_id)
                        {
                            warn!(
                                "Composite HID+MassStorage BadUSB anomaly detected on {} (node={}) — severing data lines and requiring user confirmation challenge!",
                                policy_hw_id, os_node_id
                            );
                            metrics.sentinel_threats_total.fetch_add(1, Ordering::Relaxed);
                            if let Err(e) = interceptor.sever_data_lines(&os_node_id).await {
                                warn!("sever_data_lines failed for {}: {}", os_node_id, e);
                            }
                            let challenge_info = confirmation_mgr
                                .request_user_presence_challenge_extended(&os_node_id);
                            let challenge_id = challenge_info
                                .as_ref()
                                .map(|c| c.challenge_id.as_str())
                                .unwrap_or("CHALLENGE-ERR");
                            let _ = falcon_bridge.emit_alert(&FalconTelemetryEvent {
                                severity: 10,
                                signature_id: "BADUSB-COMPOSITE-001".to_string(),
                                name: "Composite HID and Mass Storage BadUSB Blocked".to_string(),
                                device_vendor_id: format!("0x{vid:04X}"),
                                device_product_id: format!("0x{pid:04X}"),
                                serial_number: serial.clone(),
                                file_sha256: None,
                                action_taken: "SEVER_DATA_LINES_AWAITING_CONFIRMATION".to_string(),
                                details: format!(
                                    "Blocked composite device {policy_hw_id} (node={os_node_id}); challenge_id={challenge_id}; physical console authorization token required (see pending_challenge_{challenge_id}.token)"
                                ),
                            });
                            append_system_ledger(
                                &shared_ledger,
                                "BADUSB_BLOCKED",
                                &format!(
                                    "Severed data lines for composite device {policy_hw_id} (node={os_node_id}); challenge_id={challenge_id} issued"
                                ),
                            );
                        } else if let Some(raw_mount) = &event.raw_mount_point {
                            // 3. Controlled Read-Only Volume Window -> Single-Read VFS Ingestion -> Offline Return (Rows 14, 15, 138, 145)
                            // Strip any drive-letter mount points (`E:\`) associated with this USB volume while
                            // retaining the persistent `\\?\Volume{GUID}\` path for read-only online/offline transitions.
                            let raw_mount_str = raw_mount.to_string_lossy();
                            let mut volume_target = raw_mount.clone();
                            for vol in sentinel_sys::enumerate_usb_volumes() {
                                if vol.volume_guid_path.eq_ignore_ascii_case(&raw_mount_str)
                                    || vol.mount_points.iter().any(|mp| mp == raw_mount)
                                {
                                    for mp in &vol.mount_points {
                                        if let Err(e) = sentinel_sys::delete_volume_mount_point(&mp.to_string_lossy()) {
                                            warn!("delete_volume_mount_point({}) notice: {}", mp.display(), e);
                                        }
                                    }
                                    volume_target = PathBuf::from(&vol.volume_guid_path);
                                    break;
                                }
                            }
                            if raw_mount_str.len() <= 3 && raw_mount_str.ends_with('\\') {
                                if let Err(e) = sentinel_sys::delete_volume_mount_point(&raw_mount_str) {
                                    warn!("delete_volume_mount_point({}) notice: {}", raw_mount.display(), e);
                                }
                            }
                            if let Err(e) = sentinel_sys::set_volume_online_readonly(&volume_target, true) {
                                warn!("set_volume_online_readonly({}) notice: {}", volume_target.display(), e);
                            }

                            let virtual_mount = config.safe_drive_mount_path.clone();
                            let mount_res = vfs_provider
                                .mount_sanitized_volume(&volume_target, &virtual_mount)
                                .await;

                            // Quarantine any threats withheld during the single-read VFS ingestion (`Row 50, 64, 145`)
                            for threat in vfs_provider.take_withheld_threats(&virtual_mount) {
                                metrics.sentinel_threats_total.fetch_add(1, Ordering::Relaxed);
                                metrics.sentinel_vault_ops_total.fetch_add(1, Ordering::Relaxed);
                                let q_res = if let Some(stream_name) = &threat.stream_name {
                                    quarantine_vault.quarantine_ntfs_stream(
                                        &threat.file_path,
                                        stream_name,
                                        &threat.threat_name,
                                        threat.risk_score,
                                    )
                                } else {
                                    quarantine_vault.quarantine_file_with_score(
                                        &threat.file_path,
                                        &threat.threat_name,
                                        threat.risk_score,
                                    )
                                };
                                if let Err(e) = q_res {
                                    warn!("Quarantine remediation notice for {:?}: {}", threat.file_path, e);
                                }
                            }

                            // Always return raw USB volume offline immediately after single-read ingestion
                            if let Err(e) = sentinel_sys::set_volume_offline(&volume_target, true) {
                                warn!("set_volume_offline({}) notice: {}", volume_target.display(), e);
                            }

                            let fallback_lp = config
                                .quarantine_vault_path
                                .join("AuditLedger")
                                .join("sentinel_unified_audit.jsonl");
                            let raw_tok = tokenize_path_for_ledger(
                                Some(&shared_ledger),
                                &fallback_lp,
                                raw_mount,
                            )
                            .unwrap_or_else(|_| "TOKEN_ERR".to_string());
                            let virt_tok = tokenize_path_for_ledger(
                                Some(&shared_ledger),
                                &fallback_lp,
                                &virtual_mount,
                            )
                            .unwrap_or_else(|_| "TOKEN_ERR".to_string());
                            match mount_res {
                                Ok(()) => {
                                    append_system_ledger(
                                        &shared_ledger,
                                        "VOLUME_PROJECTED",
                                        &format!(
                                            "Projected raw_token={raw_tok} -> mount_token={virt_tok} via {} (raw USB volume returned offline)",
                                            vfs_provider.provider_name()
                                        ),
                                    );
                                }
                                Err(e) => {
                                    warn!("Projection aborted for {}: {}", raw_mount.display(), e);
                                    append_system_ledger(
                                        &shared_ledger,
                                        "VOLUME_PROJECTION_ABORTED",
                                        &format!("Aborted projection for raw_token={raw_tok}: {e}"),
                                    );
                                }
                            }
                        }
                    }
                    _ => {
                        append_system_ledger(
                            &shared_ledger,
                            "PERIPHERAL_OBSERVED",
                            &format!("Observed connection {:?}", event.connection_id),
                        );
                    }
                }
            }
            _ = reconcile_interval.tick() => {
                // Phase 0.1 & 4.5: Re-verify fail-closed mount posture every 60s and emit health beacon
                let current_posture = sentinel_sys::verify_system_posture();
                if !current_posture.is_compliant() {
                    metrics.sentinel_policy_drift_total.fetch_add(1, Ordering::Relaxed);
                    if let Err(e) = sentinel_sys::set_automount_disabled(true) {
                        warn!("60s reconcile set_automount_disabled failed: {e}");
                    }
                    if let Err(e) = sentinel_sys::apply_autoplay_suppression_policy() {
                        warn!("60s reconcile apply_autoplay_suppression_policy failed: {e}");
                    }
                    if let Err(e) = sentinel_sys::apply_usb_storage_and_install_policies(
                        &intune_policy.allowed_hardware_ids,
                    ) {
                        warn!("60s reconcile apply_usb_storage_and_install_policies failed: {e}");
                    }
                    if let Err(e) = sentinel_sys::purge_stale_mounted_devices() {
                        warn!("60s reconcile purge_stale_mounted_devices failed: {e}");
                    }
                    if let Err(e) = sentinel_sys::cleanup_unapproved_usb_devices(
                        &intune_policy.allowed_hardware_ids,
                    ) {
                        warn!("60s reconcile cleanup_unapproved_usb_devices failed: {e}");
                    }
                    let _ = falcon_bridge.emit_alert(&FalconTelemetryEvent {
                        severity: 8,
                        signature_id: "POSTURE-DRIFT-001".to_string(),
                        name: "Endpoint USB Fail-Closed Posture Drift Detected".to_string(),
                        device_vendor_id: "0x0000".to_string(),
                        device_product_id: "0x0000".to_string(),
                        serial_number: config.node_id.clone(),
                        file_sha256: None,
                        action_taken: "RECONCILED_MOUNT_POLICY".to_string(),
                        details: format!(
                            "AutoMountDisabled={}, AutoPlaySuppressed={}, UserDeny={}, InstallRestrict={}, WriteProtect={}",
                            current_posture.automount_disabled,
                            current_posture.autoplay_suppressed,
                            current_posture.user_deny_policy_present,
                            current_posture.install_restrictions_active,
                            current_posture.write_protect_active
                        ),
                    });
                }
                let ntp_status = sentinel_sys::query_ntp_sync_status();
                append_system_ledger(
                    &shared_ledger,
                    "HEARTBEAT_BEACON",
                    &format!(
                        "Node {} alive; posture_compliant={}; ntp_synchronized={}; clock_source={}",
                        config.node_id,
                        current_posture.is_compliant(),
                        ntp_status.ntp_synchronized,
                        ntp_status.clock_source
                    ),
                );
                if let Ok(mut guard) = shared_ledger.lock() {
                    let _ = guard.emit_worm_checkpoint();
                }
                // CSE-23: Drain undelivered SIEM spool records during 60s reconciliation tick
                match falcon_bridge.flush_spool() {
                    Ok(flushed) if flushed > 0 => {
                        info!(
                            "Flushed {flushed} buffered SIEM telemetry record(s) during 60s reconciliation"
                        );
                    }
                    Ok(_) => {}
                    Err(e) => {
                        warn!("Periodic SIEM spool flush deferred: {e}");
                    }
                }
            }
        }
    }

    // Teardown any active VFS projection and emit shutdown alert (`Row 1, 149, 190`)
    let _ = vfs_provider
        .unmount_volume(&config.safe_drive_mount_path)
        .await;
    append_system_ledger(
        &shared_ledger,
        "AGENT_SHUTDOWN",
        &format!(
            "Node {} shutting down; session cache crypto-erased",
            config.node_id
        ),
    );

    Ok(())
}
