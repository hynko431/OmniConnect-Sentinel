#![forbid(unsafe_code)]
#![deny(clippy::unwrap_used, clippy::expect_used)]

use std::path::PathBuf;
use std::sync::atomic::Ordering;
use std::sync::Arc;
use std::time::Duration;
use tracing::{info, warn};
use tracing_subscriber::{layer::SubscriberExt, util::SubscriberInitExt};

use sentinel_core::config::SentinelConfig;
use sentinel_core::enterprise::falcon::{CrowdStrikeFalconBridge, FalconTelemetryEvent};
use sentinel_core::enterprise::intune::IntunePolicyManager;
use sentinel_core::enterprise::ledger::AuditLedger;
use sentinel_core::error::SentinelMetrics;
use sentinel_core::events::ConnectionVector;
use sentinel_core::interceptor::{resolve_best_interceptor, PendingDeviceConfirmationManager};
use sentinel_core::scanner::quarantine::QuarantineVault;
use sentinel_core::scanner::tier1_cdr_client::Tier1CdrClient;
use sentinel_core::vfs::resolve_best_vfs_provider;

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    tracing_subscriber::registry()
        .with(tracing_subscriber::EnvFilter::new(
            std::env::var("RUST_LOG").unwrap_or_else(|_| "info,sentinel_core=debug".into()),
        ))
        .with(tracing_subscriber::fmt::layer())
        .init();

    info!("===========================================================");
    info!("   OmniConnect Sentinel - Universal Device Interceptor     ");
    info!("        Zero-Trust Peripheral & Connection Sentry          ");
    info!("===========================================================");

    let config = SentinelConfig::default();
    info!("Loaded Agent Node ID: {}", config.node_id);

    // 1. Synchronize Intune MDM Policies
    let mut policy_mgr = IntunePolicyManager::new();
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

    let ledger_path = config
        .quarantine_vault_path
        .parent()
        .unwrap_or(config.quarantine_vault_path.as_path())
        .join("AuditLedger")
        .join("sentinel_audit.jsonl");
    let mut audit_ledger = AuditLedger::open(ledger_path);
    let _ = audit_ledger.append_event(
        "AGENT_STARTUP",
        format!(
            "Node {} initialized with policy {}",
            config.node_id, intune_policy.policy_id
        ),
    );
    let _ = audit_ledger.append_event(
        "STARTUP_POSTURE_CHECK",
        format!(
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
    let vfs_provider = resolve_best_vfs_provider();
    info!("Active VFS Provider: {}", vfs_provider.provider_name());

    // 5. Initialize Tier 1 CDR Client (Sandboxed Pipe Worker default), Quarantine Vault, Confirmation Manager, Metrics, and Falcon SIEM Bridge
    let cdr_client = Arc::new(Tier1CdrClient::new(Default::default()));
    info!(
        "Tier-1 CDR Client initialized for endpoint: {}",
        cdr_client.ipc_endpoint()
    );
    let quarantine_vault = Arc::new(QuarantineVault::open(config.quarantine_vault_path.clone())?);
    if let Some(deg) = quarantine_vault.degradation_event() {
        let _ = audit_ledger.append_event("DEGRADATION_EVENT", deg.event_code());
    }
    let confirmation_mgr = PendingDeviceConfirmationManager::new(
        PendingDeviceConfirmationManager::default_state_file(),
    );
    let falcon_bridge = Arc::new(CrowdStrikeFalconBridge::new("127.0.0.1:514"));
    let metrics = Arc::new(SentinelMetrics::default());

    // 6. Start Universal Hardware Interceptor (retaining tx in background task - BUG-CORE-01)
    let interceptor = resolve_best_interceptor();
    let mut event_rx = interceptor.start_monitoring().await?;

    // 7. 60-Second Health Beacon & Fail-Closed Mount Posture Reconciliation Timer (Phase 0.1 & Phase 4.5)
    let mut reconcile_interval = tokio::time::interval(Duration::from_secs(60));
    reconcile_interval.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Delay);
    reconcile_interval.tick().await; // consume initial tick

    info!("Sentinel Agent running. Zero BSOD risk: 100% userspace execution.");
    info!("Monitoring physical wire, LAN, Wi-Fi, and Bluetooth channels...");

    // Event Loop (BUG-CORE-01 + Phase 0.1/3.1/4.5 60s posture reconciliation & heartbeat beacon)
    loop {
        tokio::select! {
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
                        interfaces,
                    } => {
                        let has_hid = interfaces.iter().any(|i| i.interface_class == 0x03);
                        let has_storage = interfaces.iter().any(|i| i.interface_class == 0x08);
                        let device_id = format!("USB\\VID_{vid:04X}&PID_{pid:04X}\\{serial}");

                        // 1. Hardware ID Allowlist Enforcement (Row 141)
                        if !sentinel_sys::is_hardware_id_allowed(&device_id, &intune_policy.allowed_hardware_ids) {
                            warn!(
                                "Unapproved USB Hardware ID {} rejected by policy — severing data lines!",
                                device_id
                            );
                            metrics.sentinel_threats_total.fetch_add(1, Ordering::Relaxed);
                            if let Err(e) = interceptor.sever_data_lines(&device_id).await {
                                warn!("sever_data_lines failed for {}: {}", device_id, e);
                            }
                            let _ = audit_ledger.append_event(
                                "HARDWARE_ID_BLOCKED",
                                format!("Blocked unapproved hardware ID {device_id}"),
                            );
                            continue;
                        }

                        // 2. Composite HID+MassStorage BadUSB Detection & Physical User Confirmation Gate (Rows 3, 142)
                        if intune_policy.block_composite_hid_storage
                            && has_hid
                            && has_storage
                            && !confirmation_mgr.is_confirmed(&device_id)
                        {
                            warn!(
                                "Composite HID+MassStorage BadUSB anomaly detected on {} — severing data lines and requiring user confirmation challenge!",
                                device_id
                            );
                            metrics.sentinel_threats_total.fetch_add(1, Ordering::Relaxed);
                            if let Err(e) = interceptor.sever_data_lines(&device_id).await {
                                warn!("sever_data_lines failed for {}: {}", device_id, e);
                            }
                            let challenge = confirmation_mgr
                                .request_user_presence_confirmation(&device_id)
                                .unwrap_or_else(|_| "CHALLENGE-ERR".to_string());
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
                                    "Blocked composite device {device_id}; run 'sentinel confirm-device --device-id \"{device_id}\" --challenge {challenge}' to authorize"
                                ),
                            });
                            let _ = audit_ledger.append_event(
                                "BADUSB_BLOCKED",
                                format!(
                                    "Severed data lines for composite device {device_id}; challenge={challenge} issued"
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

                            let virtual_mount = PathBuf::from(r"C:\OmniConnect\SafeDrive");
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

                            match mount_res {
                                Ok(()) => {
                                    let _ = audit_ledger.append_event(
                                        "VOLUME_PROJECTED",
                                        format!(
                                            "Projected {} -> {} via {} (raw USB volume returned offline)",
                                            raw_mount.display(),
                                            virtual_mount.display(),
                                            vfs_provider.provider_name()
                                        ),
                                    );
                                }
                                Err(e) => {
                                    warn!("Projection aborted for {}: {}", raw_mount.display(), e);
                                    let _ = audit_ledger.append_event(
                                        "VOLUME_PROJECTION_ABORTED",
                                        format!("Aborted projection for {}: {}", raw_mount.display(), e),
                                    );
                                }
                            }
                        }
                    }
                    _ => {
                        let _ = audit_ledger.append_event(
                            "PERIPHERAL_OBSERVED",
                            format!("Observed connection {:?}", event.connection_id),
                        );
                    }
                }
            }
            _ = reconcile_interval.tick() => {
                // Phase 0.1 & 4.5: Re-verify fail-closed mount posture every 60s and emit health beacon
                let current_posture = sentinel_sys::verify_system_posture();
                if !current_posture.is_compliant() {
                    metrics.sentinel_policy_drift_total.fetch_add(1, Ordering::Relaxed);
                    let _ = sentinel_sys::set_automount_disabled(true);
                    let _ = sentinel_sys::apply_autoplay_suppression_policy();
                    let _ = sentinel_sys::apply_usb_storage_and_install_policies(&intune_policy.allowed_hardware_ids);
                    let _ = sentinel_sys::purge_stale_mounted_devices();
                    let _ = sentinel_sys::cleanup_unapproved_usb_devices(&intune_policy.allowed_hardware_ids);
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
                let _ = audit_ledger.append_event(
                    "HEARTBEAT_BEACON",
                    format!("Node {} alive; posture_compliant={}", config.node_id, current_posture.is_compliant()),
                );
            }
        }
    }

    // Teardown any active VFS projection and emit shutdown alert (`Row 1, 149, 190`)
    let _ = vfs_provider
        .unmount_volume(&PathBuf::from(r"C:\OmniConnect\SafeDrive"))
        .await;
    let _ = audit_ledger.append_event(
        "AGENT_SHUTDOWN",
        format!(
            "Node {} shutting down; session cache crypto-erased",
            config.node_id
        ),
    );

    Ok(())
}
