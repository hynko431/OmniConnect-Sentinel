use sentinel_cdr::policy::SanitizationPolicy;
use sentinel_cdr::service::CdrGrpcService;
use sentinel_proto::content_disarm_service_server::ContentDisarmServiceServer;
use std::net::SocketAddr;
use tonic::transport::Server;
use tracing::info;
use tracing_subscriber::{layer::SubscriberExt, util::SubscriberInitExt};

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    tracing_subscriber::registry()
        .with(tracing_subscriber::EnvFilter::new(
            std::env::var("RUST_LOG").unwrap_or_else(|_| "info,sentinel_cdr=debug".into()),
        ))
        .with(tracing_subscriber::fmt::layer())
        .init();

    let addr: SocketAddr = std::env::var("SENTINEL_CDR_ADDR")
        .unwrap_or_else(|_| "127.0.0.1:50051".to_string())
        .parse()?;

    info!("Initializing OmniConnect Sentinel CDR Microservice Daemon...");
    let policy = SanitizationPolicy::default();
    let cdr_service = CdrGrpcService::new(policy);

    info!("Sentinel CDR listening on gRPC endpoint: {}", addr);

    Server::builder()
        .add_service(ContentDisarmServiceServer::new(cdr_service))
        .serve(addr)
        .await?;

    Ok(())
}
