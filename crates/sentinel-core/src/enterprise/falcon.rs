use serde::{Deserialize, Serialize};
use tracing::{info, warn};

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct FalconPeripheralEvent {
    pub event_type: String,
    pub timestamp_utc: chrono::DateTime<chrono::Utc>,
    pub host_agent_id: String,
    pub usb_device_info: Option<String>,
    pub threat_name: Option<String>,
    pub original_file_sha256: Option<String>,
    pub sanitized_file_sha256: Option<String>,
    pub action_taken: String,
    pub mitre_attack_technique: String,
}

pub struct CrowdStrikeFalconBridge {
    agent_id: String,
}

impl CrowdStrikeFalconBridge {
    pub fn new(agent_id: String) -> Self {
        Self { agent_id }
    }

    pub fn emit_event(&self, event: &FalconPeripheralEvent) {
        info!(
            "Forwarding telemetry to CrowdStrike Falcon XDR / FDR: [{}] {} (Action: {})",
            event.mitre_attack_technique, event.event_type, event.action_taken
        );
        // In production: streams to local Falcon Sensor Named Pipe or HTTPS REST Event Hub
    }

    pub fn trigger_automated_containment_alert(&self, threat_detail: &str) {
        warn!(
            "CRITICAL ALERT: Triggering Falcon Fusion Playbook containment request for host {}: {}",
            self.agent_id, threat_detail
        );
    }
}
