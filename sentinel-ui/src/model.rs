//! Strongly typed application state, backend API models, and honest telemetry defaults
//! for OmniConnect Sentinel's native Rune UI.

use std::sync::mpsc::Sender;

use rune::TextEdit;
use serde::Deserialize;

/// Commands dispatched from the UI thread to the background localhost API client.
#[derive(Debug, Clone)]
pub enum BackendCmd {
    PollNow,
    ExchangeBootstrap(String),
    TriggerScan,
    TriggerKioskScan,
    TriggerShred,
}

/// Active operator persona surface.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum PersonaMode {
    #[default]
    SocHud,
    Kiosk,
}

/// Light (Framed Sheet / Sunlight Kiosk) vs. Dark (SOC Cyber Ops) appearance.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum ThemeMode {
    #[default]
    Light,
    Dark,
}

/// Active accessible modal dialog.
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub enum ModalState {
    #[default]
    None,
    Mitre(&'static str),
    CdrTelemetry,
    ShredConfirm,
    SessionAuth,
}

/// Connection health with the local `sentinel ui` backend (`127.0.0.1`).
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub enum ConnectionState {
    #[default]
    Connecting,
    Connected,
    Unauthorized,
    Disconnected {
        retry_in_secs: u64,
        reason: String,
    },
    DemoFixture,
}

/// Hardware & OS pre-mount posture checks matching `PostureReport` in `sentinel-sys`.
#[derive(Debug, Clone, Default, Deserialize)]
pub struct PostureState {
    #[serde(default)]
    pub automount_disabled: bool,
    #[serde(default)]
    pub user_deny_policy_present: bool,
    #[serde(default)]
    pub install_restrictions_active: bool,
    #[serde(default)]
    pub write_protect_active: bool,
    #[serde(default)]
    pub removable_volumes_offline: bool,
    #[serde(default)]
    pub is_compliant: bool,
}

impl PostureState {
    pub fn passed_count(&self) -> usize {
        [
            self.automount_disabled,
            self.user_deny_policy_present,
            self.install_restrictions_active,
            self.write_protect_active,
            self.removable_volumes_offline,
            self.is_compliant,
        ]
        .into_iter()
        .filter(|&b| b)
        .count()
    }
}

#[derive(Debug, Clone, Default, Deserialize)]
pub struct MdmPolicyState {
    #[serde(default)]
    pub policy_id: String,
    #[serde(default)]
    pub version: u64,
    #[serde(default)]
    pub enforce_usb_zero_trust: bool,
    #[serde(default)]
    pub block_composite_hid_storage: bool,
    #[serde(default)]
    pub require_cdr_for_documents: bool,
}

#[derive(Debug, Clone, Default, Deserialize)]
pub struct ConnectedVolume {
    #[serde(default)]
    pub mount_point: String,
    #[serde(default)]
    pub volume_name: String,
    #[serde(default)]
    pub is_removable: bool,
}

#[derive(Debug, Clone, Default, Deserialize)]
pub struct WorkerStats {
    #[serde(default)]
    pub active: u64,
    #[serde(default)]
    pub processed_total: u64,
    #[serde(default)]
    pub duration_ms_total: u64,
}

#[derive(Debug, Clone, Default, Deserialize)]
pub struct ShredReceipt {
    #[serde(default)]
    pub original_path: String,
    #[serde(default)]
    pub sanitization_level: String,
    #[serde(default)]
    pub passes_completed: u8,
    #[serde(default)]
    pub rename_cycles_completed: u8,
    #[serde(default)]
    pub flush_succeeded: bool,
    #[serde(default)]
    pub media_type: String,
}

#[derive(Debug, Clone, Default)]
pub struct StreamItem {
    pub id: String,
    pub title: String,
    pub detail: String,
    pub badge_text: String,
    pub is_alert: bool,
}

/// Raw JSON shape returned by `GET /api/v1/status`.
#[derive(Debug, Clone, Default, Deserialize)]
pub struct StatusResponse {
    #[serde(default)]
    pub status: String,
    #[serde(default)]
    pub demo_mode: bool,
    #[serde(default)]
    pub architecture: String,
    #[serde(default)]
    pub csrf_token: String,
    #[serde(default)]
    pub posture: PostureState,
    #[serde(default)]
    pub mdm_policy: MdmPolicyState,
    #[serde(default)]
    pub connected_volumes: Vec<ConnectedVolume>,
    #[serde(default)]
    pub workers: WorkerStats,
    #[serde(default)]
    pub files_cleaned: u64,
    #[serde(default)]
    pub quarantine_count: usize,
    #[serde(default)]
    pub audit_ledger_verified: bool,
    #[serde(default = "default_true")]
    pub last_scan_complete: bool,
    #[serde(default)]
    pub last_scan_errors: Vec<String>,
    #[serde(default)]
    pub recent_events: Vec<serde_json::Value>,
    #[serde(default)]
    pub last_shred_receipt: Option<ShredReceipt>,
}

fn default_true() -> bool {
    true
}

/// Raw JSON shape returned by `GET /api/v1/ws`.
#[derive(Debug, Clone, Default, Deserialize)]
pub struct WsResponse {
    #[serde(default)]
    pub events: Vec<serde_json::Value>,
}

/// MITRE ATT&CK® Ring 3 hardware defense technique metadata.
#[derive(Debug, Clone, Copy)]
pub struct MitreInfo {
    pub id: &'static str,
    pub short_name: &'static str,
    pub full_title: &'static str,
    pub status: &'static str,
    pub summary: &'static str,
    pub threat_desc: &'static str,
    pub mitigation: &'static str,
    pub compliance: &'static str,
}

pub const MITRE_TECHNIQUES: [MitreInfo; 4] = [
    MitreInfo {
        id: "T1091",
        short_name: "Replication via Removable Media",
        full_title: "Replication Through Removable Media",
        status: "Intercepted",
        summary: "AutoRun worms, LNK stomping, and hidden directory infection vectors neutralized.",
        threat_desc: "Adversaries move into systems by copying malware to removable media and abusing auto-run features, shortcut (LNK) stomping, or hidden device directories.",
        mitigation: "Ring 3 pre-mount hold (MountMgr auto-mount suppression + IOCTL_VOLUME_OFFLINE) isolates untrusted BusTypeUsb volumes before explorer.exe parses shell metadata.",
        compliance: "NIST SP 800-53 Rev. 5: MP-6, MP-7 · CIS Control 10.3",
    },
    MitreInfo {
        id: "T1052",
        short_name: "Exfiltration Over Physical Medium",
        full_title: "Exfiltration Over Physical Medium",
        status: "Enforced",
        summary: "Unauthorized outbound writes blocked by read-only VFS projection and write-protect.",
        threat_desc: "Adversaries bypass network monitoring by writing sensitive documents, database exports, or source code directly to external flash media.",
        mitigation: "Enforces default write-protection policy and read-only ProjFS / FUSE3 projection so unapproved outbound file writes fail closed.",
        compliance: "NIST SP 800-53 Rev. 5: MP-7, SC-7 · IEC 62443-3-3 SR 1.13",
    },
    MitreInfo {
        id: "T1200",
        short_name: "Hardware Additions (BadUSB)",
        full_title: "Hardware Additions (BadUSB & Rogue HID)",
        status: "Isolated",
        summary: "Challenge-response confirmation and composite HID/storage policy enforcement.",
        threat_desc: "Malicious USB microcontrollers masquerade as flash drives or composite keyboards to inject keystrokes or spoof storage blocks across reads (TOCTOU).",
        mitigation: "Read-Once ShadowCache (I2) eliminates flash double-read TOCTOU while physical confirmation challenges gate unapproved USB devices.",
        compliance: "NIST SP 800-207 Zero Trust · CIS Control 4.1",
    },
    MitreInfo {
        id: "T1025",
        short_name: "Data from Removable Media",
        full_title: "Data from Removable Media",
        status: "Sanitized",
        summary: "Inbound PDF/Office/image payloads disassembled and rebuilt inside AppContainer CDR.",
        threat_desc: "Weaponized documents, polyglot images, and active macros on USB drives trigger zero-day parser exploits or second-stage execution on open.",
        mitigation: "Ephemeral sentinel-cdr-worker runs inside Zero-Capability AppContainer / seccomp-bpf (256 MiB / 30 s cap) to mathematically rebuild clean payloads.",
        compliance: "NIST SP 800-53 SI-3 · IEC 62443-3-3 SR 3.2",
    },
];

pub fn find_mitre(id: &str) -> &'static MitreInfo {
    MITRE_TECHNIQUES
        .iter()
        .find(|m| m.id == id)
        .unwrap_or(&MITRE_TECHNIQUES[0])
}

/// Kiosk workflow stage (Mode A — Air-Gapped Walk-Up Station).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum KioskStage {
    #[default]
    InsertDrive,
    Scanning,
    VerifiedClean,
    BlockedError,
}

/// Complete UI application state owned by Rune's `Runtime<SentinelState>`.
pub struct SentinelState {
    pub port: u16,
    pub persona: PersonaMode,
    pub theme: ThemeMode,
    pub modal: ModalState,
    pub connection: ConnectionState,
    pub demo_mode: bool,

    // Hardware & Security Telemetry
    pub status_label: String,
    pub architecture_label: String,
    pub bus_hold_active: bool,
    pub posture: PostureState,
    pub mdm_policy: MdmPolicyState,
    pub connected_volumes: Vec<ConnectedVolume>,
    pub workers: WorkerStats,
    pub files_cleaned: u64,
    pub quarantine_count: usize,
    pub audit_ledger_verified: bool,
    pub last_scan_complete: bool,
    pub last_scan_errors: Vec<String>,
    pub last_shred_receipt: Option<ShredReceipt>,
    pub stream_items: Vec<StreamItem>,
    pub prometheus_metrics: String,

    // Operation / Action Feedback
    pub busy_scan: bool,
    pub busy_shred: bool,
    pub shred_status_msg: String,
    pub shred_status_is_error: bool,
    pub auth_error: Option<String>,
    pub bootstrap_input: TextEdit,

    // Kiosk State
    pub kiosk_stage: KioskStage,
    pub kiosk_summary: String,

    // Background client command channel (None in headless/test mode)
    pub cmd_tx: Option<Sender<BackendCmd>>,
}

impl Default for SentinelState {
    fn default() -> Self {
        Self::new(8088, None)
    }
}

impl SentinelState {
    /// Initializes honest zero-fabrication state (`T23`: no fake telemetry prior to backend sync).
    pub fn new(port: u16, cmd_tx: Option<Sender<BackendCmd>>) -> Self {
        Self {
            port,
            persona: PersonaMode::SocHud,
            theme: ThemeMode::Light,
            modal: ModalState::None,
            connection: ConnectionState::Connecting,
            demo_mode: false,
            status_label: "OFFLINE".into(),
            architecture_label: "Ring 3 Userspace (Zero Custom Kernel Driver)".into(),
            bus_hold_active: true,
            posture: PostureState::default(),
            mdm_policy: MdmPolicyState::default(),
            connected_volumes: Vec::new(),
            workers: WorkerStats::default(),
            files_cleaned: 0,
            quarantine_count: 0,
            audit_ledger_verified: false,
            last_scan_complete: true,
            last_scan_errors: Vec::new(),
            last_shred_receipt: None,
            stream_items: vec![StreamItem {
                id: "init-0".into(),
                title: "DISCONNECTED — NO LIVE DATA".into(),
                detail: format!(
                    "Awaiting authenticated sentinel agent on 127.0.0.1:{port} (/api/v1/status)"
                ),
                badge_text: "Connecting".into(),
                is_alert: true,
            }],
            prometheus_metrics: String::new(),
            busy_scan: false,
            busy_shred: false,
            shred_status_msg: "Ready (Idle — Awaiting Live Receipt)".into(),
            shred_status_is_error: false,
            auth_error: None,
            bootstrap_input: TextEdit::new(""),
            kiosk_stage: KioskStage::InsertDrive,
            kiosk_summary: "Awaiting operator scan trigger against local Sentinel Kiosk agent."
                .into(),
            cmd_tx,
        }
    }

    pub fn send_cmd(&self, cmd: BackendCmd) {
        if let Some(tx) = &self.cmd_tx {
            let _ = tx.send(cmd);
        }
    }

    /// Applies a live authenticated `/api/v1/status` + `/api/v1/ws` payload to state.
    pub fn apply_live_status(&mut self, data: StatusResponse, ws_events: Vec<serde_json::Value>) {
        self.demo_mode = data.demo_mode;
        if !data.status.is_empty() {
            self.status_label = data.status;
        }
        if !data.architecture.is_empty() {
            self.architecture_label = data.architecture;
        }
        self.connection = if data.demo_mode {
            ConnectionState::DemoFixture
        } else {
            ConnectionState::Connected
        };
        self.posture = data.posture;
        self.mdm_policy = data.mdm_policy;
        self.connected_volumes = data.connected_volumes;
        self.workers = data.workers;
        self.files_cleaned = data.files_cleaned;
        self.quarantine_count = data.quarantine_count;
        self.audit_ledger_verified = data.audit_ledger_verified;
        self.last_scan_complete = data.last_scan_complete;
        self.last_scan_errors = data.last_scan_errors;
        if let Some(receipt) = data.last_shred_receipt {
            self.apply_shred_receipt(receipt);
        }

        if !self.last_scan_complete {
            let detail = if self.last_scan_errors.is_empty() {
                "Walk errors or file cap reached — volume kept offline fail-closed".into()
            } else {
                self.last_scan_errors.join(" | ")
            };
            self.stream_items = vec![StreamItem {
                id: "scan-incomplete".into(),
                title: "SCAN INCOMPLETE — VOLUME HELD OFFLINE".into(),
                detail,
                badge_text: "Scan Incomplete".into(),
                is_alert: true,
            }];
            return;
        }

        let raw_events = if !ws_events.is_empty() {
            ws_events
        } else {
            data.recent_events
        };

        if raw_events.is_empty() {
            let pol = if self.mdm_policy.policy_id.is_empty() {
                "ACTIVE"
            } else {
                &self.mdm_policy.policy_id
            };
            self.stream_items = vec![StreamItem {
                id: "empty-0".into(),
                title: "Empty — 0 Pending CDR Events".into(),
                detail: format!(
                    "Policy {pol} · Vault Entries: {} · Ledger: {}",
                    self.quarantine_count,
                    if self.audit_ledger_verified {
                        "VERIFIED"
                    } else {
                        "UNVERIFIED"
                    }
                ),
                badge_text: "Empty / Clean".into(),
                is_alert: false,
            }];
        } else {
            self.stream_items = raw_events
                .iter()
                .rev()
                .enumerate()
                .map(|(idx, ev)| parse_stream_event(idx, ev, self.demo_mode, self.quarantine_count))
                .collect();
        }
    }

    pub fn apply_disconnected(&mut self, retry_in_secs: u64, reason: impl Into<String>) {
        let reason = reason.into();
        self.connection = ConnectionState::Disconnected {
            retry_in_secs,
            reason: reason.clone(),
        };
        self.files_cleaned = 0;
        self.quarantine_count = 0;
        self.connected_volumes.clear();
        self.audit_ledger_verified = false;
        self.stream_items = vec![StreamItem {
            id: "disconnected".into(),
            title: "DISCONNECTED — NO LIVE DATA".into(),
            detail: format!(
                "Agent unreachable on 127.0.0.1:{} ({reason}) · Retry in {retry_in_secs}s",
                self.port
            ),
            badge_text: "Disconnected".into(),
            is_alert: true,
        }];
    }

    pub fn apply_shred_receipt(&mut self, receipt: ShredReceipt) {
        self.shred_status_is_error = !receipt.flush_succeeded;
        self.shred_status_msg = format!(
            "{} · Passes: {} · Renames: {} · Flush: {} · Media: {}",
            if receipt.sanitization_level.is_empty() {
                "Clear (logical)"
            } else {
                &receipt.sanitization_level
            },
            receipt.passes_completed,
            receipt.rename_cycles_completed,
            if receipt.flush_succeeded { "OK" } else { "FAIL" },
            if receipt.media_type.is_empty() {
                "Flash/FTL"
            } else {
                &receipt.media_type
            }
        );
        self.last_shred_receipt = Some(receipt);
    }

    /// Populates an explicitly watermarked fixture state for `--demo` and headless visual audits.
    pub fn apply_watermarked_demo(&mut self) {
        self.demo_mode = true;
        self.connection = ConnectionState::DemoFixture;
        self.bus_hold_active = true;
        self.posture = PostureState {
            automount_disabled: true,
            user_deny_policy_present: true,
            install_restrictions_active: true,
            write_protect_active: true,
            removable_volumes_offline: true,
            is_compliant: true,
        };
        self.mdm_policy = MdmPolicyState {
            policy_id: "IEC62443-SL3-DEMO".into(),
            version: 14,
            enforce_usb_zero_trust: true,
            block_composite_hid_storage: true,
            require_cdr_for_documents: true,
        };
        self.connected_volumes = vec![ConnectedVolume {
            mount_point: r"\\?\Volume{84a9-demo}\".into(),
            volume_name: "DEMO-SCADA-VENDOR-USB".into(),
            is_removable: true,
        }];
        self.workers = WorkerStats {
            active: 1,
            processed_total: 42,
            duration_ms_total: 318,
        };
        self.files_cleaned = 42;
        self.quarantine_count = 3;
        self.audit_ledger_verified = true;
        self.last_scan_complete = true;
        self.last_scan_errors.clear();
        self.apply_shred_receipt(ShredReceipt {
            original_path: r"staging\shred_canary_a91f.bin".into(),
            sanitization_level: "NIST SP 800-88 Clear (logical)".into(),
            passes_completed: 3,
            rename_cycles_completed: 3,
            flush_succeeded: true,
            media_type: "Wear-Leveled Flash (FTL)".into(),
        });
        self.stream_items = vec![
            StreamItem {
                id: "demo-1".into(),
                title: "[DEMO] CDR Rebuilt: Turbine_Calibration_Q4.xlsx".into(),
                detail: "Stripped vbaProject.bin + external rels · 6.4 ms · AppContainer worker"
                    .into(),
                badge_text: "Sanitized".into(),
                is_alert: false,
            },
            StreamItem {
                id: "demo-2".into(),
                title: "[DEMO] Quarantined: invoice_dropper.pdf.exe".into(),
                detail: "High-entropy packed PE (7.84 b/B) · Sealed to .quar SNTLQV02 + shredded"
                    .into(),
                badge_text: "Quarantined".into(),
                is_alert: true,
            },
            StreamItem {
                id: "demo-3".into(),
                title: "[DEMO] CDR Rebuilt: Substation_Schematic_Rev9.pdf".into(),
                detail: "Purged /OpenAction & /JavaScript · Depth check passed (12/64) · 9.1 ms"
                    .into(),
                badge_text: "Sanitized".into(),
                is_alert: false,
            },
            StreamItem {
                id: "demo-4".into(),
                title: "[DEMO] Shred Receipt: Token 7f4a21c9e8b01d3a".into(),
                detail: "NIST SP 800-88 Clear (logical) · 3 passes · Read-back SHA-256 verified"
                    .into(),
                badge_text: "Clear (logical)".into(),
                is_alert: false,
            },
        ];
        self.prometheus_metrics = concat!(
            "sentinel_active_workers 1\n",
            "sentinel_cdr_processed_total{format=\"pdf\",status=\"ok\"} 19\n",
            "sentinel_cdr_processed_total{format=\"openxml\",status=\"ok\"} 23\n",
            "sentinel_threats_total{category=\"executable\",severity=\"critical\"} 3\n",
            "sentinel_posture{feature=\"is_compliant\"} 1"
        )
        .into();
        self.kiosk_stage = KioskStage::VerifiedClean;
        self.kiosk_summary = "DEMO FIXTURE · 42 payloads inspected & disarmed, 0 active threats remaining on transfer target, ECDSA P-256 audit receipt signed.".into();
    }

    /// Computes honest bus state readout strings without fabricating hardware voltage/current sensors.
    pub fn bus_telemetry_readout(&self) -> (&'static str, &'static str, &'static str, String) {
        if matches!(
            self.connection,
            ConnectionState::Disconnected { .. }
                | ConnectionState::Unauthorized
                | ConnectionState::Connecting
        ) {
            return (
                "No HW Sensor",
                "Offline",
                "Fail-Closed",
                "DISCONNECTED — NO LIVE DATA".into(),
            );
        }
        if let Some(vol) = self.connected_volumes.first() {
            let kind = if vol.is_removable { "Removable" } else { "Fixed USB" };
            let label = format!(
                "{} [{kind}] ({})",
                if vol.volume_name.is_empty() {
                    "USB Volume"
                } else {
                    &vol.volume_name
                },
                if vol.mount_point.is_empty() {
                    "Offline GUID"
                } else {
                    &vol.mount_point
                }
            );
            if self.bus_hold_active {
                ("BusTypeUsb (0x07)", "HELD OFFLINE", "No HW Sensor", label)
            } else {
                ("BusTypeUsb (0x07)", "RING 3 CDR", "No HW Sensor", label)
            }
        } else {
            let label = if self.demo_mode {
                "DEMO FIXTURE VOLUME (WATERMARKED)".into()
            } else {
                "0 Removable Volumes Mounted (Fail-Closed)".into()
            };
            ("No USB Storage", "Idle", "No HW Sensor", label)
        }
    }
}

fn parse_stream_event(
    idx: usize,
    ev: &serde_json::Value,
    is_demo: bool,
    quarantine_count: usize,
) -> StreamItem {
    let ev_type = ev
        .get("event")
        .and_then(|v| v.as_str())
        .unwrap_or("EVENT");

    match ev_type {
        "SHRED_COMPLETE" => {
            let target = ev
                .get("path_token")
                .and_then(|v| v.as_str())
                .map(|t| format!("Token {}", &t[..t.len().min(16)]))
                .or_else(|| {
                    ev.get("original_path")
                        .and_then(|v| v.as_str())
                        .map(ToOwned::to_owned)
                })
                .unwrap_or_else(|| "Target".into());
            let level = ev
                .get("sanitization_level")
                .and_then(|v| v.as_str())
                .unwrap_or("NIST SP 800-88 Clear (logical)");
            let passes = ev
                .get("passes_completed")
                .and_then(|v| v.as_u64())
                .unwrap_or(0);
            let renames = ev
                .get("rename_cycles_completed")
                .and_then(|v| v.as_u64())
                .unwrap_or(0);
            let flush = ev
                .get("flush_succeeded")
                .and_then(|v| v.as_bool())
                .unwrap_or(false);
            StreamItem {
                id: format!("ev-{idx}"),
                title: format!("Shred Receipt: {target}"),
                detail: format!("{level} · Passes: {passes} · Renames: {renames} · Flush: {flush}"),
                badge_text: "Clear (logical)".into(),
                is_alert: !flush,
            }
        }
        "SCAN_COMPLETE" => {
            let target = ev
                .get("path_token")
                .and_then(|v| v.as_str())
                .map(|t| format!("Token {}", &t[..t.len().min(16)]))
                .or_else(|| {
                    ev.get("path")
                        .and_then(|v| v.as_str())
                        .map(ToOwned::to_owned)
                })
                .unwrap_or_else(|| ".sentinel_staging".into());
            let files = ev
                .get("files_scanned")
                .and_then(|v| v.as_u64())
                .unwrap_or(0);
            let threats = ev
                .get("threats_found")
                .and_then(|v| v.as_u64())
                .unwrap_or(0);
            let errors = ev.get("errors").and_then(|v| v.as_u64()).unwrap_or(0);
            let complete = ev
                .get("complete")
                .and_then(|v| v.as_bool())
                .unwrap_or(false);
            StreamItem {
                id: format!("ev-{idx}"),
                title: format!("Directory Walk: {target}"),
                detail: format!("Files: {files} · Threats: {threats} · Errors: {errors}"),
                badge_text: if complete {
                    "Scan Complete".into()
                } else {
                    "Scan Incomplete".into()
                },
                is_alert: !complete || threats > 0,
            }
        }
        _ => {
            let detail = ev
                .get("detail")
                .and_then(|v| v.as_str())
                .map(ToOwned::to_owned)
                .unwrap_or_else(|| format!("Vault Entries: {quarantine_count}"));
            StreamItem {
                id: format!("ev-{idx}"),
                title: if is_demo {
                    format!("[DEMO FIXTURE] {ev_type}")
                } else {
                    ev_type.to_owned()
                },
                detail,
                badge_text: if is_demo {
                    "Demo Fixture".into()
                } else {
                    "Live Sync".into()
                },
                is_alert: false,
            }
        }
    }
}
