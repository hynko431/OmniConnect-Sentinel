use serde::{Deserialize, Serialize};
use std::path::PathBuf;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DeviceConnectedEvent {
    pub connection_id: uuid::Uuid,
    pub timestamp_utc: chrono::DateTime<chrono::Utc>,
    pub vector: ConnectionVector,
    pub raw_mount_point: Option<PathBuf>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum ConnectionVector {
    WiredUsb {
        vid: u16,
        pid: u16,
        serial: String,
        interfaces: Vec<UsbInterfaceDescriptor>,
    },
    MtpMobileDevice {
        manufacturer: String,
        model: String,
        serial: String,
    },
    LocalNetworkShare {
        protocol: String,
        server_ip: String,
        share_name: String,
    },
    BluetoothDevice {
        mac_address: String,
        device_name: String,
        profile: String,
    },
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct UsbInterfaceDescriptor {
    pub interface_number: u8,
    pub interface_class: u8,
    pub interface_subclass: u8,
    pub protocol: u8,
    pub description: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum RemediationAction {
    AllowDirectMount,
    MountVirtualSanitizedView { target_virtual_drive: String },
    SeverDataLinesRetainCharging,
    QuarantineDeviceFiles { quarantined_count: usize },
    BlockAndNotifySoc { threat_summary: String },
}
