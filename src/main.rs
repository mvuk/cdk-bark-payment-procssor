mod ark_backend;
mod payjoin_receiver;
mod payjoin_state;
mod por;
mod settings;
mod telemetry;

use crate::ark_backend::ArkBackend;
use anyhow::Result;
use std::sync::Arc;
use tokio::signal;
use tracing_subscriber::EnvFilter;

#[tokio::main]
async fn main() -> Result<()> {
    // Logging
    tracing_subscriber::fmt()
        .with_env_filter(EnvFilter::from_default_env().add_directive("info".parse().unwrap()))
        .init();

    // Load configuration from environment
    let cfg = settings::Config::from_env();

    // Initialize the Ark backend
    tracing::info!("Initializing Ark payment processor");
    let backend = Arc::new(ArkBackend::new(&cfg.backend).await?);

    // One-shot recycler-primitive validation (env-gated). Moves a SMALL amount of the mint's own
    // Ark reserve to a fresh on-chain address to prove the offboard path (and reveal confirmation
    // timing) before the unattended recycler loop is wired. Spawned so it never blocks startup.
    if let Ok(v) = std::env::var("RECYCLER_TEST_OFFBOARD_SAT") {
        if let Ok(amt) = v.parse::<u64>() {
            let b = backend.clone();
            tokio::spawn(async move {
                tracing::warn!("RECYCLER_TEST_OFFBOARD_SAT={amt}: performing ONE test offboard");
                match b.recycle_test_offboard(amt).await {
                    Ok(txid) => tracing::warn!("recycle test offboard OK: txid {txid}"),
                    Err(e) => tracing::error!("recycle test offboard FAILED: {e:#}"),
                }
            });
        }
    }

    // One-shot reserve splitter (env-gated). Splits the on-chain reserve into many small randomized
    // 5-20k UTXOs so Tier-2 boards lend a small random amount per board. `RECYCLER_SPLIT_NOW=1`.
    // Range overridable via MINT_LEND_MIN_SAT / MINT_LEND_MAX_SAT (default 5000 / 20000).
    if std::env::var("RECYCLER_SPLIT_NOW").map(|v| v == "1" || v == "true").unwrap_or(false) {
        let b = backend.clone();
        let min_sat = std::env::var("MINT_LEND_MIN_SAT").ok().and_then(|v| v.parse().ok()).unwrap_or(5000u64);
        let max_sat = std::env::var("MINT_LEND_MAX_SAT").ok().and_then(|v| v.parse().ok()).unwrap_or(20000u64);
        tokio::spawn(async move {
            tracing::warn!("RECYCLER_SPLIT_NOW set: splitting reserve into {min_sat}-{max_sat} sat UTXOs");
            match b.split_reserve(min_sat, max_sat).await {
                Ok(txid) => tracing::warn!("split_reserve OK: txid {txid}"),
                Err(e) => tracing::error!("split_reserve FAILED: {e:#}"),
            }
        });
    }

    let bind_addr = "0.0.0.0";
    let server_addr = format!("{}:{}", bind_addr, cfg.server_port);
    tracing::info!("Starting CDK Payment Processor server on {}", server_addr);

    // Spawn the on-ramp payjoin poll loop. It drives all active payjoin sessions forward
    // (poll directory -> walk typestate -> cosign+store board -> post proposal -> monitor) and
    // reconciles confirmed boards for crediting. Errors are logged inside `poll_onramp`.
    {
        let onramp_backend = backend.clone();
        tokio::spawn(async move {
            let mut interval = tokio::time::interval(std::time::Duration::from_secs(5));
            loop {
                interval.tick().await;
                onramp_backend.poll_onramp().await;
            }
        });
    }

    // Spawn the VTXO maintenance loop. Custody VTXOs (the funds backing issued ecash) expire
    // after `vtxo_lifetime` blocks; missing the refresh window forces an expensive unilateral
    // exit. The cadence must sit well inside bark's refresh threshold — 12 blocks (~6 min) on
    // Mutinynet's 30s blocks — so we run every 5 minutes. Delegated mode only schedules the
    // refresh with the server (cheap, usually a no-op) and never blocks on round completion.
    {
        let maintenance_backend = backend.clone();
        tokio::spawn(async move {
            let mut interval = tokio::time::interval(std::time::Duration::from_secs(300));
            loop {
                interval.tick().await;
                if let Err(e) = maintenance_backend.run_maintenance().await {
                    tracing::warn!("VTXO maintenance error: {e:#}");
                }
            }
        });
    }

    // Proof-of-Reserves hooks — ALL ENV-GATED OFF by default (no behavior change to
    // boards/melts unless explicitly enabled). HONEST FRAMING: proof of reserves (a
    // lower bound on assets), never solvency.
    //
    //   POR_ATTEST_ONCE=1   build one attestation on startup (writes the bundle file);
    //                       publishes over Nostr only if POR_PUBLISH=1.
    //   POR_ENABLE=1        run the attestation on a timer (every POR_INTERVAL_SECS,
    //                       default ~6000s ≈ 10 mainnet blocks); POR_PUBLISH gates Nostr.
    //
    // The attest key is loaded from env POR_ATTEST_SECKEY (hex) or ~/secrets/por-attest.seckey.
    // If absent, the gated features no-op and log (binding attest pubkey <-> cdk
    // MintInfo is a documented fast-follow).
    {
        let want_once = std::env::var("POR_ATTEST_ONCE").map(|v| v == "1" || v == "true").unwrap_or(false);
        let want_timer = std::env::var("POR_ENABLE").map(|v| v == "1" || v == "true").unwrap_or(false);
        if want_once || want_timer {
            match por::load_attest_key() {
                Ok(Some(attest_key)) => {
                    let publish = std::env::var("POR_PUBLISH").map(|v| v == "1" || v == "true").unwrap_or(false);
                    tracing::warn!(
                        "PoR ENABLED (once={want_once} timer={want_timer} publish={publish}); attest pubkey {}",
                        por::attest_pubkey_xonly_hex(&attest_key)
                    );
                    if want_once {
                        let b = backend.clone();
                        let key = attest_key;
                        let timer = want_timer;
                        tokio::spawn(async move {
                            if let Err(e) = b.run_por_attestation(&key, publish).await {
                                tracing::error!("PoR one-shot attestation FAILED: {e:#}");
                            }
                            if timer {
                                por_timer_loop(b, key, publish).await;
                            }
                        });
                    } else {
                        // timer only
                        let b = backend.clone();
                        tokio::spawn(async move { por_timer_loop(b, attest_key, publish).await });
                    }
                }
                Ok(None) => tracing::warn!(
                    "PoR requested (POR_ATTEST_ONCE/POR_ENABLE) but no attest key found \
                     (set POR_ATTEST_SECKEY hex or ~/secrets/por-attest.seckey); PoR no-op"
                ),
                Err(e) => tracing::error!("PoR attest key load failed: {e:#}; PoR no-op"),
            }
        }
    }

    let mut server =
        cdk_payment_processor::PaymentProcessorServer::new(backend, bind_addr, cfg.server_port)?;

    server.start(None).await?;

    // Wait for shutdown signal
    match shutdown_signal().await {
        Ok(_) => tracing::info!("Shutdown signal received, stopping server..."),
        Err(e) => tracing::error!("Error waiting for shutdown signal: {}", e),
    }

    server.stop().await?;
    tracing::info!("Server stopped gracefully");
    Ok(())
}

/// PoR timer loop: rebuild + (optionally) publish an attestation every
/// `POR_INTERVAL_SECS` (default ~6000s ≈ 10 mainnet blocks). Env-gated by the caller.
async fn por_timer_loop(backend: Arc<ArkBackend>, attest_key: por::AttestKey, publish: bool) {
    let secs = std::env::var("POR_INTERVAL_SECS")
        .ok()
        .and_then(|v| v.parse::<u64>().ok())
        .filter(|n| *n > 0)
        .unwrap_or(6000);
    let mut interval = tokio::time::interval(std::time::Duration::from_secs(secs));
    interval.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Skip);
    // first tick fires immediately; skip it so we don't double-attest right after a once-run.
    interval.tick().await;
    loop {
        interval.tick().await;
        if let Err(e) = backend.run_por_attestation(&attest_key, publish).await {
            tracing::error!("PoR timer attestation FAILED: {e:#}");
        }
    }
}

/// Wait for shutdown signal (SIGTERM or SIGINT)
async fn shutdown_signal() -> Result<()> {
    let ctrl_c = async {
        signal::ctrl_c()
            .await
            .expect("failed to install Ctrl+C handler");
    };

    #[cfg(unix)]
    let terminate = async {
        signal::unix::signal(signal::unix::SignalKind::terminate())
            .expect("failed to install signal handler")
            .recv()
            .await;
    };

    #[cfg(not(unix))]
    let terminate = std::future::pending::<()>();

    tokio::select! {
        _ = ctrl_c => {},
        _ = terminate => {},
    }

    Ok(())
}
