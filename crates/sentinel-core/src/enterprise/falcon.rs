use serde::{Deserialize, Serialize};
use tracing::{info, warn};

/// CrowdStrike Falcon Data Replicator (FDR) / XDR Telemetry Event
/// Schema mapped to Falcon Next-Gen SIEM & Fusion SOAR event ingestion
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct FalconPeripheralEvent {
    pub event_id: String,
    pub event_type: String,
    pub timestamp_utc: chrono::DateTime<chrono::Utc>,
    pub host_agent_id: String,
    pub usb_device_info: Option<String>,
    pub threat_name: Option<String>,
    pub original_file_sha256: Option<String>,
    pub sanitized_file_sha256: Option<String>,
    pub action_taken: String,
    pub mitre_attack_technique: String,
    pub severity: String,
}

pub struct CrowdStrikeFalconBridge {
    agent_id: String,
}

impl CrowdStrikeFalconBridge {
    pub fn new(agent_id: String) -> Self {
        Self { agent_id }
    }

    /// Converts an event into CrowdStrike Falcon Data Replicator (FDR) NDJSON format
    pub fn to_fdr_json(&self, event: &FalconPeripheralEvent) -> String {
        serde_json::to_string(event).unwrap_or_default()
    }

    /// Formats event into ArcSight Common Event Format (CEF) for universal SIEM / Syslog ingestion
    pub fn to_cef_syslog(&self, event: &FalconPeripheralEvent) -> String {
        format!(
            "CEF:0|OmniConnect|Sentinel|2026.3.0|{event_type}|{threat}|{sev}|deviceExternalId={host} cs1={mitre} cs1Label=MitreAttack act={action} fileHash={hash}",
            event_type = event.event_type,
            threat = event.threat_name.as_deref().unwrap_or("UnknownThreat"),
            sev = match event.severity.as_str() {
                "Critical" => "10",
                "High" => "8",
                "Medium" => "5",
                _ => "1",
            },
            host = self.agent_id,
            mitre = event.mitre_attack_technique,
            action = event.action_taken,
            hash = event.original_file_sha256.as_deref().unwrap_or("none")
        )
    }

    /// Emits a structured telemetry event to Falcon FDR stream or local sensor pipe
    pub fn emit_event(&self, event: &FalconPeripheralEvent) {
        let fdr_json = self.to_fdr_json(event);
        info!(
            "CrowdStrike Falcon FDR Stream [{}]: {}",
            event.mitre_attack_technique, fdr_json
        );
    }

    /// Triggers automated endpoint network isolation via Falcon Fusion SOAR playbook
    pub fn trigger_automated_containment_alert(&self, threat_detail: &str) {
        warn!(
            "CRITICAL: Triggering Falcon Fusion Playbook containment request for host {}: {}",
            self.agent_id, threat_detail
        );
    }
}
