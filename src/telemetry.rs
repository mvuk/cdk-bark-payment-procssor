//! Real-events-only telemetry for the on-ramp dashboard.
//!
//! Each REAL transition fires a fire-and-forget POST to
//! `${control_url}/onramp/event` with a JSON body:
//!
//! ```json
//! {
//!   "run_id":   "<quote_id>",
//!   "quote_id": "<quote_id>",
//!   "stage":    "quote_created" | "payjoin_received" | "proposal_sent"
//!              | "board_broadcast" | "board_confirmed" | "ecash_issued",
//!   "data": { "board_address"?, "board_txid"?, "vtxo_amount_sat"?, "ecash_amount_sat"? }
//! }
//! ```
//!
//! POST failures NEVER break the payment flow: they are logged and dropped. Events are emitted
//! ONLY when the corresponding thing genuinely happens.

use serde::Serialize;
use tracing::{debug, warn};

#[derive(Debug, Clone, Copy, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum OnRampStage {
    QuoteCreated,
    PayjoinReceived,
    ProposalSent,
    BoardBroadcast,
    BoardConfirmed,
    EcashIssued,
}

#[derive(Debug, Clone, Default, Serialize)]
pub struct OnRampEventData {
    #[serde(skip_serializing_if = "Option::is_none")]
    pub board_address: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub board_txid: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub vtxo_amount_sat: Option<u64>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub ecash_amount_sat: Option<u64>,
    #[serde(skip_serializing_if = "Vec::is_empty")]
    pub vtxo_ids: Vec<String>,
}

#[derive(Debug, Clone, Serialize)]
pub struct OnRampEvent {
    pub run_id: String,
    pub quote_id: String,
    pub stage: OnRampStage,
    pub data: OnRampEventData,
}

impl OnRampEvent {
    pub fn new(quote_id: &str, stage: OnRampStage) -> Self {
        Self {
            run_id: quote_id.to_string(),
            quote_id: quote_id.to_string(),
            stage,
            data: OnRampEventData::default(),
        }
    }

    pub fn with_board_address(mut self, address: &str) -> Self {
        self.data.board_address = Some(address.to_string());
        self
    }

    pub fn with_board_txid(mut self, txid: &str) -> Self {
        self.data.board_txid = Some(txid.to_string());
        self
    }

    /// Attach the boarded amount (mint reserve growth) — required on `board_confirmed`.
    pub fn with_vtxo_amount_sat(mut self, sat: u64) -> Self {
        self.data.vtxo_amount_sat = Some(sat);
        self
    }

    /// Attach the credited amount (user ecash growth) — required on `ecash_issued`.
    pub fn with_ecash_amount_sat(mut self, sat: u64) -> Self {
        self.data.ecash_amount_sat = Some(sat);
        self
    }

    /// Attach the discrete boarded VTXO ids (outpoints) — listed in the dashboard panel.
    pub fn with_vtxo_ids(mut self, ids: Vec<String>) -> Self {
        self.data.vtxo_ids = ids;
        self
    }
}

/// Fire-and-forget telemetry client. Cloning is cheap.
#[derive(Clone)]
pub struct TelemetryClient {
    control_url: String,
    http: reqwest::Client,
}

impl TelemetryClient {
    pub fn new(control_url: String) -> Self {
        Self {
            control_url,
            http: reqwest::Client::new(),
        }
    }

    /// Emit an event. Spawns a detached task; never blocks or fails the caller.
    pub fn emit(&self, event: OnRampEvent) {
        let url = format!("{}/onramp/event", self.control_url.trim_end_matches('/'));
        let http = self.http.clone();
        tokio::spawn(async move {
            match http.post(&url).json(&event).send().await {
                Ok(resp) => {
                    if !resp.status().is_success() {
                        debug!(
                            "telemetry POST {url} returned {} (continuing)",
                            resp.status()
                        );
                    }
                }
                Err(e) => warn!("telemetry POST {url} failed (continuing): {e}"),
            }
        });
    }
}
