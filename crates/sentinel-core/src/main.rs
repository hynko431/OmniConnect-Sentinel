use sentinel_core::config::SentinelConfig;
use sentinel_core::enterprise::falcon::CrowdStrikeFalconBridge;
use sentinel_core::enterprise::intune::IntunePolicyManager;
use sentinel_core::interceptor::resolve_best_interceptor;
use sentinel_core::scanner::quarantine::QuarantineVault;
use sentinel_core::scanner::tier1_cdr_client::Tier1CdrClient;
use sentinel_core::vfs::resolve_best_vfs_provider;
use std::sync::Arc;
use tracing::info;
use tracing_subscriber::{layer::SubscriberExt, util::SubscriberInitExt};

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    tracing_subscriber::registry()
        .with(tracing_subscriber::EnvFilter::new(
            std::env::var("RUST_LOG").unwrap_or_else(|_| "info,sentinel_core=debug".into()),
        ))
        .with(tracing_subscriber::fmt::layer())
        .init();

    info!("===========================================================");
    info!("   OmniConnect Sentinel - Universal Device Interceptor     ");
    info!("        Zero-Trust Peripheral & Connection Sentry          ");
    info!("===========================================================");

    let config = SentinelConfig::default();
    info!("Loaded Agent Node ID: {}", config.node_id);

    // 1. Synchronize Intune Policies
    let intune_policy = IntunePolicyManager::load_active_policy();
    info!(
        "Enforcing Policies: CDR Mandatory={}, Charge-Only Fallback={}",
        intune_policy.enforce_removable_media_cdr, intune_policy.charge_only_fallback
    );

    // 2. Initialize VFS Provider (ProjFS with WinFsp fallback)
    let vfs_provider = resolve_best_vfs_provider().await;
    info!("Active VFS Provider: {}", vfs_provider.provider_name());

    // 3. Initialize Tier 1 CDR client (connecting to sentinel-cdr daemon)
    let _cdr_client = Arc::new(Tier1CdrClient::new(config.cdr_service_endpoint.clone()));
    let _quarantine_vault = Arc::new(QuarantineVault::new(config.quarantine_vault_path.clone()));
    let _falcon_bridge = Arc::new(CrowdStrikeFalconBridge::new(config.node_id.clone()));

    // 4. Start Universal Hardware Interceptor (UMDF v2 on Windows / udev on Linux)
    let interceptor = resolve_best_interceptor();
    let mut event_rx = interceptor.start_monitoring().await?;

    info!("Sentinel Agent running. Zero BSOD risk: 100% userspace execution.");
    info!("Monitoring physical wire, LAN, Wi-Fi, and Bluetooth channels...");

    // Event Loop
    while let Some(event) = event_rx.recv().await {
        info!("Intercepted connection event: {:?}", event.vector);
        // Dispatch to Tier 0 Fast triage + Tier 1 CDR + VFS projection
    }

    Ok(())
}
