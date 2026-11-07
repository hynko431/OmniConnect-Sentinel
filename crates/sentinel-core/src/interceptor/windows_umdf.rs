use async_trait::async_trait;
use std::collections::HashSet;
use std::path::PathBuf;
use std::sync::{Arc, Mutex};
use std::time::Duration;
use tokio::sync::mpsc::{self, Receiver, Sender};
use tracing::{info, warn};

use sentinel_sys::{
    apply_autoplay_suppression_policy, delete_volume_mount_point, disable_device_node,
    enumerate_usb_pnp_devices, enumerate_usb_volumes, register_pnp_notification_watcher,
    set_automount_disabled, PnpNotificationGuard, UsbPnpDeviceInfo,
};

use crate::events::{ConnectionVector, DeviceConnectedEvent, UsbInterfaceDescriptor};
use crate::interceptor::DeviceInterceptor;

/// Windows User-Mode USB & Volume Interceptor (`BUG-CORE-01`, `BUG-CORE-13`, Phase 3.1)
///
/// Retains the event channel `Sender<DeviceConnectedEvent>` inside a persistent
/// background monitoring task (fixing `BUG-CORE-01`), registers native `CM_Register_Notification`
/// PnP arrival callbacks, enumerates `\\?\Volume{GUID}\` USB volumes via `FindFirstVolumeW` +
/// `IOCTL_STORAGE_QUERY_PROPERTY` (`BusTypeUsb`), enumerates real PnP `VID`/`PID`/composite interfaces
/// via `CM_Get_Device_ID_ListW`, and propagates errors on `CM_Disable_DevNode`.
pub struct WindowsUmdfInterceptor {
    known_volumes: Arc<Mutex<HashSet<String>>>,
    known_pnp_devices: Arc<Mutex<HashSet<String>>>,
    event_sender: Arc<Mutex<Option<Sender<DeviceConnectedEvent>>>>,
    pnp_guard: Arc<Mutex<Option<PnpNotificationGuard>>>,
}

impl Default for WindowsUmdfInterceptor {
    fn default() -> Self {
        Self::new()
    }
}

impl WindowsUmdfInterceptor {
    pub fn new() -> Self {
        let initial_volumes: HashSet<String> = enumerate_usb_volumes()
            .into_iter()
            .map(|v| v.volume_guid_path)
            .collect();
        let initial_pnp: HashSet<String> = enumerate_usb_pnp_devices()
            .into_iter()
            .map(|d| d.instance_id)
            .collect();
        Self {
            known_volumes: Arc::new(Mutex::new(initial_volumes)),
            known_pnp_devices: Arc::new(Mutex::new(initial_pnp)),
            event_sender: Arc::new(Mutex::new(None)),
            pnp_guard: Arc::new(Mutex::new(None)),
        }
    }

    /// Allows tests or external PnP hooks to dispatch a `DeviceConnectedEvent` through the retained channel.
    pub async fn emit_event(&self, event: DeviceConnectedEvent) -> Result<(), String> {
        let sender_opt = self.event_sender.lock().map_err(|e| e.to_string())?.clone();
        if let Some(tx) = sender_opt {
            tx.send(event)
                .await
                .map_err(|e| format!("Failed sending device event: {}", e))?;
            Ok(())
        } else {
            Err("Interceptor listener has not been started".to_string())
        }
    }

    fn build_interfaces_for_pnp(
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
impl DeviceInterceptor for WindowsUmdfInterceptor {
    async fn start_monitoring(
        &self,
    ) -> Result<Receiver<DeviceConnectedEvent>, Box<dyn std::error::Error>> {
        info!("Starting Windows User-Mode USB & Volume Interceptor (Hardened Option B)...");

        let (tx, rx) = mpsc::channel(128);

        // Retain `tx` inside the interceptor and move a clone into the background task
        // so `rx.recv().await` in `sentinel-agent` stays alive (`BUG-CORE-01`).
        if let Ok(mut guard) = self.event_sender.lock() {
            *guard = Some(tx.clone());
        }

        // Enforce fail-closed automount & AutoPlay suppression at startup, logging any permission error
        if let Err(e) = set_automount_disabled(true) {
            warn!(
                "MountMgr set_automount_disabled(true) returned error: {}",
                e
            );
        }
        if let Err(e) = apply_autoplay_suppression_policy() {
            warn!("apply_autoplay_suppression_policy returned error: {}", e);
        }

        // Register native CfgMgr32 PnP notification watcher (`CM_Register_Notification`)
        let (pnp_notify_tx, mut pnp_notify_rx) = mpsc::unbounded_channel::<()>();
        if let Ok(guard) = register_pnp_notification_watcher(move || {
            let _ = pnp_notify_tx.send(());
        }) {
            if let Ok(mut g) = self.pnp_guard.lock() {
                *g = Some(guard);
            }
        }

        let known_volumes = Arc::clone(&self.known_volumes);
        let known_pnp = Arc::clone(&self.known_pnp_devices);

        tokio::spawn(async move {
            let mut interval = tokio::time::interval(Duration::from_millis(800));
            loop {
                tokio::select! {
                    _ = interval.tick() => {}
                    maybe_id = pnp_notify_rx.recv() => {
                        if maybe_id.is_none() {
                            // Continue polling if PnP notification channel closes
                        }
                    }
                }
                if tx.is_closed() {
                    break;
                }

                // 1. Check newly arrived USB PnP devices (including composite HID+Storage BadUSB)
                let pnp_devices = enumerate_usb_pnp_devices();
                let current_pnp_ids: HashSet<String> =
                    pnp_devices.iter().map(|d| d.instance_id.clone()).collect();
                let mut new_pnp = Vec::new();
                if let Ok(mut known) = known_pnp.lock() {
                    for dev in &pnp_devices {
                        if !known.contains(&dev.instance_id) {
                            new_pnp.push(dev.clone());
                        }
                    }
                    *known = current_pnp_ids;
                }

                // 2. Check newly arrived USB Volume GUIDs (`\\?\Volume{GUID}\` with `BusTypeUsb`)
                let usb_volumes = enumerate_usb_volumes();
                let current_vol_ids: HashSet<String> = usb_volumes
                    .iter()
                    .map(|v| v.volume_guid_path.clone())
                    .collect();
                let mut new_vols = Vec::new();
                if let Ok(mut known) = known_volumes.lock() {
                    for vol in &usb_volumes {
                        if !known.contains(&vol.volume_guid_path) {
                            new_vols.push(vol.clone());
                        }
                    }
                    *known = current_vol_ids;
                }

                // Dispatch events for composite or standalone USB PnP arrivals
                for dev in &new_pnp {
                    if dev.is_composite_hid_storage {
                        let event = DeviceConnectedEvent {
                            connection_id: uuid::Uuid::new_v4(),
                            timestamp_utc: chrono::Utc::now(),
                            vector: ConnectionVector::WiredUsb {
                                vid: dev.vid,
                                pid: dev.pid,
                                serial: dev.serial.clone(),
                                interfaces: Self::build_interfaces_for_pnp(dev, &dev.instance_id),
                            },
                            raw_mount_point: None,
                        };
                        if tx.send(event).await.is_err() {
                            return;
                        }
                    }
                }

                // Dispatch events for newly arrived USB volumes (both DRIVE_REMOVABLE & USB DRIVE_FIXED)
                let primary_pnp = pnp_devices.first().cloned();
                for vol in new_vols {
                    let (vid, pid, serial, interfaces) = if let Some(ref dev) = primary_pnp {
                        (
                            dev.vid,
                            dev.pid,
                            dev.serial.clone(),
                            Self::build_interfaces_for_pnp(dev, &vol.volume_guid_path),
                        )
                    } else {
                        (
                            0x0000,
                            0x0000,
                            format!("VOL-{}", vol.volume_guid_path.trim_end_matches('\\')),
                            vec![UsbInterfaceDescriptor {
                                interface_number: 0,
                                interface_class: 0x08,
                                interface_subclass: 0x06,
                                protocol: 0x50,
                                description: format!("USB Volume ({})", vol.volume_guid_path),
                            }],
                        )
                    };

                    // Strip any drive-letter mount points (`E:\`) immediately and pass the persistent
                    // `\\?\Volume{GUID}\` path as `raw_mount_point` so drive-letter removal never
                    // invalidates the volume handle used for read-only ingestion (`Row 14, 15, 138`).
                    for mp in &vol.mount_points {
                        let _ = delete_volume_mount_point(&mp.to_string_lossy());
                    }
                    let mount_path = PathBuf::from(&vol.volume_guid_path);

                    let event = DeviceConnectedEvent {
                        connection_id: uuid::Uuid::new_v4(),
                        timestamp_utc: chrono::Utc::now(),
                        vector: ConnectionVector::WiredUsb {
                            vid,
                            pid,
                            serial,
                            interfaces,
                        },
                        raw_mount_point: Some(mount_path),
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
        warn!(
            "CRITICAL: Disabling USB device node {}. Severing data lines via CfgMgr32.",
            device_id
        );
        disable_device_node(device_id)?;
        Ok(())
    }

    async fn enable_charge_only_mode(
        &self,
        device_id: &str,
    ) -> Result<(), Box<dyn std::error::Error>> {
        info!(
            "Enforcing Charge-Only mode for {}: disabling USB data endpoints while retaining VBUS.",
            device_id
        );
        disable_device_node(device_id)?;
        apply_autoplay_suppression_policy()?;
        Ok(())
    }
}
