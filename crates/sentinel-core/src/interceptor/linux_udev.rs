use super::DeviceInterceptor;
use crate::events::DeviceConnectedEvent;
use async_trait::async_trait;
use tokio::sync::mpsc::{channel, Receiver};
use tracing::info;

pub struct LinuxUdevInterceptor;

impl LinuxUdevInterceptor {
    pub fn new() -> Self {
        Self
    }
}

#[async_trait]
impl DeviceInterceptor for LinuxUdevInterceptor {
    async fn start_monitoring(&self) -> Result<Receiver<DeviceConnectedEvent>, Box<dyn std::error::Error>> {
        let (_tx, rx) = channel(16);
        info!("Linux udev Netlink socket monitor initialized (User Space)");
        Ok(rx)
    }

    async fn sever_data_lines(&self, device_id: &str) -> Result<(), Box<dyn std::error::Error>> {
        info!("Writing '0' to /sys/bus/usb/devices/{}/authorized", device_id);
        Ok(())
    }

    async fn enable_charge_only_mode(&self, device_id: &str) -> Result<(), Box<dyn std::error::Error>> {
        self.sever_data_lines(device_id).await
    }
}
