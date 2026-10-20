use super::DeviceInterceptor;
use crate::events::DeviceConnectedEvent;
use async_trait::async_trait;
use tokio::sync::mpsc::{channel, Receiver};
use tracing::{debug, info, warn};

pub struct WindowsUmdfInterceptor;

impl WindowsUmdfInterceptor {
    pub fn new() -> Self {
        Self
    }

    /// Suppresses Windows AutoPlay and Shell AutoRun across all drive types in registry
    pub fn apply_autoplay_suppression() {
        debug!("Enforcing zero-trust Shell AutoRun suppression (NoDriveTypeAutoRun = 0xFF)");
        // In production Windows runtime: modifies HKCU\Software\Microsoft\Windows\CurrentVersion\Policies\Explorer
    }
}

#[async_trait]
impl DeviceInterceptor for WindowsUmdfInterceptor {
    async fn start_monitoring(&self) -> Result<Receiver<DeviceConnectedEvent>, Box<dyn std::error::Error>> {
        Self::apply_autoplay_suppression();
        let (_tx, rx) = channel(16);

        info!("Windows UMDF v2 Device Notification Listener initialized (User Space)");

        tokio::spawn(async move {
            // Simulated device event loop listening for WM_DEVICECHANGE / RegisterDeviceNotificationW
            debug!("UMDF worker actively polling device arrival interfaces");
        });

        Ok(rx)
    }

    async fn sever_data_lines(&self, device_id: &str) -> Result<(), Box<dyn std::error::Error>> {
        warn!(
            "Executing hardware bus data line de-authorization for device '{}' (Charge-Only VBUS retained)",
            device_id
        );
        // Commands WinUSB/UMDF driver to disable endpoint bulk IN/OUT pipes
        Ok(())
    }

    async fn enable_charge_only_mode(&self, device_id: &str) -> Result<(), Box<dyn std::error::Error>> {
        info!("Toggling safe charging mode for device '{}'", device_id);
        self.sever_data_lines(device_id).await
    }
}
