pub mod windows_umdf;
pub mod linux_udev;
pub mod drive_watcher;

use crate::events::DeviceConnectedEvent;
use async_trait::async_trait;
use tokio::sync::mpsc::Receiver;

#[async_trait]
pub trait DeviceInterceptor: Send + Sync {
    async fn start_monitoring(&self) -> Result<Receiver<DeviceConnectedEvent>, Box<dyn std::error::Error>>;
    async fn sever_data_lines(&self, device_id: &str) -> Result<(), Box<dyn std::error::Error>>;
    async fn enable_charge_only_mode(&self, device_id: &str) -> Result<(), Box<dyn std::error::Error>>;
}

/// Dynamically resolves the native userspace hardware interceptor based on host OS
pub fn resolve_best_interceptor() -> Box<dyn DeviceInterceptor> {
    #[cfg(target_os = "windows")]
    {
        Box::new(windows_umdf::WindowsUmdfInterceptor::new())
    }

    #[cfg(target_os = "linux")]
    {
        Box::new(linux_udev::LinuxUdevInterceptor::new())
    }

    #[cfg(not(any(target_os = "windows", target_os = "linux")))]
    {
        Box::new(windows_umdf::WindowsUmdfInterceptor::new())
    }
}
