use std::net::SocketAddr;
use std::sync::Arc;

use axum::Router;
use axum::http::Method;
use dotenvy::dotenv;
use tower_http::cors;
use x402_facilitator::config::Config;
use x402_facilitator_local::util::SigDown;
use x402_facilitator_local::{FacilitatorLocal, handlers};
use x402_types::chain::ChainRegistry;
use x402_types::chain::FromConfig;
use x402_types::scheme::{SchemeBlueprints, SchemeRegistry};

#[cfg(feature = "chain-aptos")]
use x402_chain_aptos::V2AptosExact;
#[cfg(feature = "chain-eip155")]
use x402_chain_eip155::{V1Eip155Exact, V2Eip155BatchSettlement, V2Eip155Exact, V2Eip155Upto};
#[cfg(feature = "chain-solana")]
use x402_chain_solana::{V1SolanaExact, V2SolanaExact};
#[cfg(feature = "telemetry")]
use x402_facilitator_local::util::Telemetry;

use crate::prometheus::{PrometheusFacilitatorLocal, PrometheusMetrics, metrics_router};

pub async fn run() -> Result<(), Box<dyn std::error::Error>> {
    rustls::crypto::CryptoProvider::install_default(rustls::crypto::ring::default_provider())
        .expect("Failed to initialize rustls crypto provider");

    dotenv().ok();

    #[cfg(feature = "telemetry")]
    let telemetry_providers = Telemetry::new()
        .with_name(env!("CARGO_PKG_NAME"))
        .with_version(env!("CARGO_PKG_VERSION"))
        .register();
    #[cfg(feature = "telemetry")]
    let telemetry_layer = telemetry_providers.http_tracing();

    let config = Config::load()?;

    let chain_registry = ChainRegistry::from_config(config.chains()).await?;
    let scheme_blueprints = {
        #[allow(unused_mut)]
        let mut scheme_blueprints = SchemeBlueprints::new();
        #[cfg(feature = "chain-eip155")]
        {
            scheme_blueprints.register(V1Eip155Exact);
            scheme_blueprints.register(V2Eip155Exact);
            scheme_blueprints.register(V2Eip155Upto);
            scheme_blueprints.register(V2Eip155BatchSettlement);
        }
        #[cfg(feature = "chain-solana")]
        {
            scheme_blueprints.register(V1SolanaExact);
            scheme_blueprints.register(V2SolanaExact);
        }
        #[cfg(feature = "chain-aptos")]
        {
            scheme_blueprints.register(V2AptosExact);
        }
        scheme_blueprints
    };
    let scheme_registry =
        SchemeRegistry::build(chain_registry, scheme_blueprints, config.schemes());

    let metrics = PrometheusMetrics::new();
    let facilitator =
        PrometheusFacilitatorLocal::new(FacilitatorLocal::new(scheme_registry), metrics.clone());
    let axum_state = Arc::new(facilitator);

    let http_endpoints = Router::new()
        .merge(handlers::routes().with_state(axum_state))
        .merge(metrics_router(metrics));
    #[cfg(feature = "telemetry")]
    let http_endpoints = http_endpoints.layer(telemetry_layer);
    let http_endpoints = http_endpoints.layer(
        cors::CorsLayer::new()
            .allow_origin(cors::Any)
            .allow_methods([Method::GET, Method::POST])
            .allow_headers(cors::Any),
    );

    let addr = SocketAddr::new(config.host(), config.port());
    #[cfg(feature = "telemetry")]
    tracing::info!("Starting server at http://{}", addr);

    let listener = tokio::net::TcpListener::bind(addr).await;
    #[cfg(feature = "telemetry")]
    let listener = listener.inspect_err(|e| tracing::error!("Failed to bind to {}: {}", addr, e));
    let listener = listener?;

    let sig_down = SigDown::try_new()?;
    let axum_cancellation_token = sig_down.cancellation_token();
    let axum_graceful_shutdown = async move { axum_cancellation_token.cancelled().await };
    axum::serve(listener, http_endpoints)
        .with_graceful_shutdown(axum_graceful_shutdown)
        .await?;

    Ok(())
}
