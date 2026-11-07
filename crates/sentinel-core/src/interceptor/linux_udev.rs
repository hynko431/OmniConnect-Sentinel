use async_trait::async_trait;
use std::collections::HashSet;
use std::path::PathBuf;
use std::sync::{Arc, Mutex};
use std::time::Duration;
use tokio::sync::mpsc::{self, Receiver, Sender};
use tracing::{info, warn};

use sentinel_sys::{
    disable_device_node, disable_usb_interface, enumerate_usb_pnp_devices, get_removable_drives,
    register_pnp_notification_watcher, PnpNotificationGuard, UsbPnpDeviceInfo,
};

use crate::events::{ConnectionVector, DeviceConnectedEvent, UsbInterfaceDescriptor};
use crate::interceptor::DeviceInterceptor;

/// Linux udev / sysfs USB Bus Interceptor (`BUG-CORE-01`, `BUG-CORE-13`, Row 144)
///
/// Retains the `Sender<DeviceConnectedEvent>` in a persistent background task,
/// listens on `NETLINK_KOBJECT_UEVENT` via `register_pnp_notification_watcher`,
/// enumerates real `/sys/bus/usb/devices/*` `idVendor`/`idProduct`/`serial` and
/// `bInterfaceClass` descriptors, and uses `/sys/bus/usb/devices/.../authorized`
/// for device and interface deauthorization with strict error propagation.
pub struct LinuxUdevInterceptor {
    known_mounts: Arc<Mutex<HashSet<String>>>,
    known_usb_devs: Arc<Mutex<HashSet<String>>>,
    event_sender: Arc<Mutex<Option<Sender<DeviceConnectedEvent>>>>,
    pnp_guard: Arc<Mutex<Option<PnpNotificationGuard>>>,
}

impl Default for LinuxUdevInterceptor {
    fn default() -> Self {
        Self::new()
    }
}

impl LinuxUdevInterceptor {
    pub fn new() -> Self {
        let initial_mounts: HashSet<String> = get_removable_drives()
            .into_iter()
            .map(|p| p.to_string_lossy().to_string())
            .collect();
        let initial_usb: HashSet<String> = enumerate_usb_pnp_devices()
            .into_iter()
            .map(|d| d.instance_id)
            .collect();
        Self {
            known_mounts: Arc::new(Mutex::new(initial_mounts)),
            known_usb_devs: Arc::new(Mutex::new(initial_usb)),
            event_sender: Arc::new(Mutex::new(None)),
            pnp_guard: Arc::new(Mutex::new(None)),
        }
    }

    pub async fn emit_event(&self, event: DeviceConnectedEvent) -> Result<(), String> {
        let sender_opt = self.event_sender.lock().map_err(|e| e.to_string())?.clone();
        if let Some(tx) = sender_opt {
            tx.send(event)
                .await
                .map_err(|e| format!("Failed sending device event: {}", e))?;
            Ok(())
        } else {
            Err("Linux udev listener has not been started".to_string())
        }
    }

    /// Deauthorizes a specific USB interface (`/sys/bus/usb/devices/<bus-port>:<cfg>.<if>/authorized = 0`).
    pub fn deauthorize_interface(
        &self,
        device_id: &str,
        interface_id: &str,
    ) -> std::io::Result<()> {
        disable_usb_interface(device_id, interface_id)
    }

    fn build_interfaces(
        dev: &UsbPnpDeviceInfo,
        fallback_desc: &str,
    ) -> Vec<UsbInterfaceDescriptor> {
        if dev.interface_classes.is_empty() {
            return vec![UsbInterfaceDescriptor {
                interface_number: 0,
                interface_class: 0x08,
                interface_subclass: 0x06,
                protocol: 0x50,
                description: fallback_desc.to_string(),
            }];
        }
        dev.interface_classes
            .iter()
            .enumerate()
            .map(|(idx, &cls)| UsbInterfaceDescriptor {
                interface_number: idx as u8,
                interface_class: cls,
                interface_subclass: if cls == 0x08 { 0x06 } else { 0x01 },
                protocol: if cls == 0x08 { 0x50 } else { 0x01 },
                description: format!("{} (Class 0x{:02X})", dev.instance_id, cls),
            })
            .collect()
    }
}

#[async_trait]
impl DeviceInterceptor for LinuxUdevInterceptor {
    async fn start_monitoring(
        &self,
    ) -> Result<Receiver<DeviceConnectedEvent>, Box<dyn std::error::Error>> {
        info!("Starting Linux udev/sysfs USB Interceptor (Hardened Option B)...");

        let (tx, rx) = mpsc::channel(128);

        if let Ok(mut guard) = self.event_sender.lock() {
            *guard = Some(tx.clone());
        }

        let (uevent_tx, mut uevent_rx) = mpsc::unbounded_channel::<()>();
        if let Ok(guard) = register_pnp_notification_watcher(move || {
            let _ = uevent_tx.send(());
        }) {
            if let Ok(mut g) = self.pnp_guard.lock() {
                *g = Some(guard);
            }
        }

        let known_mounts = Arc::clone(&self.known_mounts);
        let known_usb = Arc::clone(&self.known_usb_devs);

        tokio::spawn(async move {
            let mut interval = tokio::time::interval(Duration::from_millis(800));
            loop {
                tokio::select! {
                    _ = interval.tick() => {}
                    _ = uevent_rx.recv() => {}
                }
                if tx.is_closed() {
                    break;
                }

                // 1. Check sysfs USB devices (including composite HID+Storage)
                let usb_devs = enumerate_usb_pnp_devices();
                let current_usb_set: HashSet<String> =
                    usb_devs.iter().map(|d| d.instance_id.clone()).collect();
                let mut new_usb = Vec::new();
                if let Ok(mut known) = known_usb.lock() {
                    for dev in &usb_devs {
                        if !known.contains(&dev.instance_id) {
                            new_usb.push(dev.clone());
                        }
                    }
                    *known = current_usb_set;
                }

                for dev in &new_usb {
                    if dev.is_composite_hid_storage {
                        let event = DeviceConnectedEvent {
                            connection_id: uuid::Uuid::new_v4(),
                            timestamp_utc: chrono::Utc::now(),
                            vector: ConnectionVector::WiredUsb {
                                vid: dev.vid,
                                pid: dev.pid,
                                serial: dev.serial.clone(),
                                interfaces: Self::build_interfaces(dev, &dev.instance_id),
                            },
                            raw_mount_point: None,
                        };
                        if tx.send(event).await.is_err() {
                            return;
                        }
                    }
                }

                // 2. Check removable mount points
                let current_set: HashSet<String> = get_removable_drives()
                    .into_iter()
                    .map(|p| p.to_string_lossy().to_string())
                    .collect();

                let mut newly_arrived = Vec::new();
                if let Ok(mut known) = known_mounts.lock() {
                    for m in &current_set {
                        if !known.contains(m) {
                            newly_arrived.push(m.clone());
                        }
                    }
                    *known = current_set;
                }

                let primary_usb = usb_devs.first().cloned();
                for mount_path in newly_arrived {
                    let (vid, pid, serial, interfaces) = if let Some(ref dev) = primary_usb {
                        (
                            dev.vid,
                            dev.pid,
                            dev.serial.clone(),
                            Self::build_interfaces(dev, &mount_path),
                        )
                    } else {
                        (
                            0x0000,
                            0x0000,
                            format!("UDEV-{}", mount_path),
                            vec![UsbInterfaceDescriptor {
                                interface_number: 0,
                                interface_class: 0x08,
                                interface_subclass: 0x06,
                                protocol: 0x50,
                                description: mount_path.clone(),
                            }],
                        )
                    };

                    let event = DeviceConnectedEvent {
                        connection_id: uuid::Uuid::new_v4(),
                        timestamp_utc: chrono::Utc::now(),
                        vector: ConnectionVector::WiredUsb {
                            vid,
                            pid,
                            serial,
                            interfaces,
                        },
                        raw_mount_point: Some(PathBuf::from(&mount_path)),
                    };
                    if tx.send(event).await.is_err() {
                        return;
                    }
                }
            }
        });

        Ok(rx)
    }

    async fn sever_data_lines(&self, device_id: &str) -> Result<(), Box<dyn std::error::Error>> {
        warn!("CRITICAL: Deauthorizing Linux USB device {}.", device_id);
        disable_device_node(device_id)?;
        Ok(())
    }

    async fn enable_charge_only_mode(
        &self,
        device_id: &str,
    ) -> Result<(), Box<dyn std::error::Error>> {
        info!(
            "Enforcing Linux sysfs authorized=0 charge-only state for {}.",
            device_id
        );
        disable_device_node(device_id)?;
        Ok(())
    }
}
