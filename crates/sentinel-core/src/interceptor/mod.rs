pub mod windows_umdf;
pub mod linux_udev;

use crate::events::DeviceConnectedEvent;
use async_trait::async_trait;
use tokio::sync::mpsc::Receiver;

#[async_trait]
pub trait DeviceInterceptor: Send + Sync {
    async fn start_monitoring(&self) -> Result<Receiver<DeviceConnectedEvent>, Box<dyn std::error::Error>>;
    async fn sever_data_lines(&self, device_id: &str) -> Result<(), Box<dyn std::error::Error>>;
    async fn enable_charge_only_mode(&self, device_id: &str) -> Result<(), Box<dyn std::error::Error>>;
}
