//! On-chain -> ecash ON-RAMP payjoin v2 receiver.
//!
//! This module owns the payjoin v2 receiver side of the on-ramp. For each cdk on-chain
//! incoming quote we run a payjoin v2 session whose *receiver output* is substituted to the
//! per-quote Ark board funding script. When the sender's original PSBT arrives we walk the
//! rust-payjoin receiver typestate:
//!
//! ```text
//! Initialized
//!   -> (create_poll_request / process_response)        // poll the directory for the original PSBT
//!   -> UncheckedOriginalPayload -> check_broadcast_suitability
//!   -> MaybeInputsOwned         -> check_inputs_not_owned
//!   -> MaybeInputsSeen          -> check_no_inputs_seen_before   // anti-probing via OnRampStateStore
//!   -> OutputsUnknown           -> identify_receiver_outputs
//!   -> WantsOutputs             -> substitute_receiver_script(board_script) -> commit_outputs
//!   -> WantsInputs              -> contribute_inputs([Y])? -> commit_inputs   // Y is a STUB (see below)
//!   -> WantsFeeRange            -> apply_fee_range
//!   -> ProvisionalProposal      -> finalize_proposal(|psbt| cosign_and_store_board(psbt, ..))
//!   -> PayjoinProposal          -> (create_post_request / process_response)
//!   -> Monitor                  -> check_payment(...)   // confirm board funding tx on-chain
//! ```
//!
//! ## Input Y (receiver input contribution) — STUB
//! The task allows contributing zero inputs to keep compilation clean. We currently contribute
//! NO receiver inputs (`contribute_inputs` is skipped). This means the board VTXO is funded
//! entirely by the sender's value paid into the substituted board output. Adding a real Y means
//! selecting a processor bark on-chain UTXO and building an `InputPair::new_p2tr_keyspend`, then
//! signing it inside the finalize closure. That is left as a follow-up; see `STUB: input Y`.
//!
//! ## BIP21 / pj URI output substitution
//! rust-payjoin's `pj_uri()` hardcodes output substitution DISABLED (emits `pjos=0`). For the
//! on-ramp we MUST advertise output substitution ENABLED, otherwise `substitute_receiver_script`
//! fails with `ScriptPubKeyChangedWhenDisabled`. Per the BIP78 `pjos` semantics (see
//! payjoin uri::serialize_params: `pjos=0` is emitted only when DISABLED; ENABLED emits no
//! `pjos` param at all), we build the advertised URI by taking the library URI and stripping the
//! `pjos=0` parameter. See [`onramp_pj_uri`].

use std::collections::HashSet;
use std::sync::Arc;

use bark::onchain::bdk_wallet::{LocalOutput, SignOptions};
use bark::onchain::OnchainWallet;
use bitcoin::{FeeRate, OutPoint};
use payjoin::persist::OptionalTransitionOutcome;
use payjoin::receive::v2::{
    replay_event_log, Initialized, ReceiveSession, Receiver, SessionEvent, SessionOutcome,
    SessionStatus,
};
use payjoin::receive::InputPair;
use payjoin::ImplementationError;
use payjoin::OhttpKeys;
use tracing::{debug, info, warn};

use crate::payjoin_state::{OnRampStateStore, QuoteSessionPersister};
use crate::telemetry::{OnRampEvent, OnRampStage, TelemetryClient};

/// Static configuration for the payjoin receiver, derived from [`crate::settings`].
#[derive(Clone)]
pub struct PayjoinConfig {
    pub directory_url: String,
    pub ohttp_relay: String,
    pub ohttp_keys: Option<OhttpKeys>,
    pub control_url: String,
}

/// Result of advancing a session, used by the poll loop / crediting path.
#[derive(Debug, Clone)]
pub enum BoardResult {
    /// Board funding tx was cosigned + stored. Carries the board txid and net boarded sats, plus
    /// the data needed by the caller to persist an onchain receive intent for crediting.
    Boarded {
        board_txid: String,
        net_sat: u64,
        /// Stable synthetic deposit key for this payjoin board: "<board_txid>:<board_vout>".
        deposit_outpoint: String,
        /// Board funding output value (gross, before the server board fee).
        gross_sat: u64,
        /// The board VTXO ids produced by the cosign, as strings.
        board_vtxo_ids: Vec<String>,
    },
    /// Board funding tx observed confirmed on-chain.
    Confirmed { board_txid: String, net_sat: u64 },
    /// Session made progress but no board yet.
    InProgress,
    /// Nothing to do (no original PSBT yet / closed / expired).
    Idle,
}

/// Build the BIP21 + pj URI advertising output substitution ENABLED.
///
/// We take the receiver's canonical URI (which advertises substitution DISABLED, i.e. contains
/// `pjos=0`) and remove that parameter. Absence of `pjos` means substitution is enabled per
/// BIP78. We control the devnet sender, so this is acceptable.
pub fn onramp_pj_uri(receiver: &Receiver<Initialized>) -> String {
    let disabled = receiver.pj_uri().to_string();
    strip_pjos(&disabled)
}

/// Remove a `pjos=0` (or `pjos=1`) query parameter from a BIP21 URI string.
fn strip_pjos(uri: &str) -> String {
    // Parameters are separated by '&' within the query (after the first '?').
    // bitcoin_uri uses '?' to introduce params; remove the pjos kv wherever it sits.
    let mut out = String::with_capacity(uri.len());
    let mut first_sep_seen = false;
    for (i, segment) in uri.split('?').enumerate() {
        if i == 0 {
            out.push_str(segment);
            continue;
        }
        if !first_sep_seen {
            out.push('?');
            first_sep_seen = true;
        }
        let kept: Vec<&str> = segment
            .split('&')
            .filter(|kv| {
                let lower = kv.to_ascii_lowercase();
                !(lower == "pjos=0" || lower == "pjos=1")
            })
            .collect();
        out.push_str(&kept.join("&"));
    }
    out
}

/// The payjoin receiver runner. Holds everything needed to drive sessions for all quotes.
#[derive(Clone)]
pub struct PayjoinReceiver {
    pub config: PayjoinConfig,
    pub state: OnRampStateStore,
    pub telemetry: TelemetryClient,
    pub http: reqwest::Client,
    /// "Tier 2": when true, the mint contributes its OWN on-chain input(s) to the board (real
    /// multi-input payjoin). When false (default), the receiver contributes ZERO inputs (Tier 3,
    /// today's behavior). Set from the `PAYJOIN_RECEIVER_INPUTS` flag.
    pub receiver_inputs_enabled: bool,
    /// Target number of mint inputs to contribute when `receiver_inputs_enabled` is true. Clamped
    /// to the number of available unlocked UTXOs; 0 available -> zero-input fallback. From
    /// `PAYJOIN_RECEIVER_INPUT_COUNT` (default 2).
    pub receiver_input_count: u32,
    /// The mint's on-chain (bdk) wallet, used to source + sign the receiver input(s) in Tier 2.
    /// This is the SAME wallet handle held by `ArkBackend::onchain_wallet`, so locking here
    /// serializes against the board-poll loop's sync.
    pub onchain_wallet: Arc<tokio::sync::Mutex<OnchainWallet>>,
    /// UTXOs reserved by an in-flight Tier 2 board, so two concurrent boards can't pick the same
    /// mint input and double-spend it. Skipped during selection; release is implicit (a chosen
    /// input is spent by the board funding tx, so it never reappears in `list_unspent`).
    pub locked_utxos: Arc<tokio::sync::Mutex<HashSet<OutPoint>>>,
    /// The Ark server's minimum board amount (sats). A sender's deposit below this would be
    /// rejected by the server at cosign time. Because on-chain mint quotes are OPEN-AMOUNT (NUT-30
    /// carries no amount), the only enforcement is here at the receiver: we reject a sub-minimum
    /// original PSBT in `check_broadcast_suitability` (the FIRST check, before any reserve UTXO is
    /// touched), which drives the session to `HasReplyableError` so a BIP78 `original-psbt-rejected`
    /// reply is posted to the sender — instead of silently retrying cosign forever (the A4 hole).
    pub min_board_amount_sat: u64,
    /// The mint's own on-chain deposit (board) fee, in basis points of the user's deposit D.
    /// Deducted from the credited ecash (`net = D − server_fee − deposit_fee`); the fee remains
    /// inside the board VTXO as mint reserve. From `MINT_ONCHAIN_DEPOSIT_FEE_BPS` (default 0).
    pub onchain_deposit_fee_bps: u64,
}

impl PayjoinReceiver {
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        config: PayjoinConfig,
        state: OnRampStateStore,
        telemetry: TelemetryClient,
        receiver_inputs_enabled: bool,
        receiver_input_count: u32,
        onchain_wallet: Arc<tokio::sync::Mutex<OnchainWallet>>,
        locked_utxos: Arc<tokio::sync::Mutex<HashSet<OutPoint>>>,
        min_board_amount_sat: u64,
        onchain_deposit_fee_bps: u64,
    ) -> Self {
        Self {
            config,
            state,
            telemetry,
            http: reqwest::Client::new(),
            receiver_inputs_enabled,
            receiver_input_count,
            onchain_wallet,
            locked_utxos,
            min_board_amount_sat,
            onchain_deposit_fee_bps,
        }
    }

    /// Create and persist a fresh payjoin v2 receiver session for `quote_id`, whose receiver
    /// address is `board_address`. Returns the BIP21+pj URI advertising substitution ENABLED.
    pub fn create_session(
        &self,
        quote_id: &str,
        board_address: &bitcoin::Address,
    ) -> anyhow::Result<String> {
        let ohttp_keys = self
            .config
            .ohttp_keys
            .clone()
            .ok_or_else(|| anyhow::anyhow!("payjoin ohttp_keys not configured"))?;

        let builder = payjoin::receive::v2::ReceiverBuilder::new(
            board_address.clone(),
            &self.config.directory_url,
            ohttp_keys,
        )
        .map_err(|e| anyhow::anyhow!("failed to build payjoin receiver: {e}"))?;

        let persister = self.state.session_persister(quote_id);
        let receiver: Receiver<Initialized> = builder
            .build()
            .save(&persister)
            .map_err(|e| anyhow::anyhow!("failed to persist payjoin session: {e}"))?;

        let uri = onramp_pj_uri(&receiver);
        info!("payjoin on-ramp session created for quote {quote_id}: {uri}");
        Ok(uri)
    }

    /// Drive every active session forward by one step. Called from the poll loop.
    pub async fn poll_all(
        &self,
        wallet: &Arc<bark::Wallet>,
        wallet_db_lock: &Arc<tokio::sync::Mutex<()>>,
    ) -> Vec<(String, anyhow::Result<BoardResult>)> {
        let quotes = match self.state.all_quotes() {
            Ok(q) => q,
            Err(e) => {
                warn!("payjoin poll: failed to list quotes: {e}");
                return Vec::new();
            }
        };

        let mut results = Vec::new();
        for record in quotes {
            let res = self
                .advance_session(&record.quote_id, wallet, wallet_db_lock)
                .await;
            results.push((record.quote_id.clone(), res));
        }
        results
    }

    /// Advance a single session as far as it can go this tick. This performs the OHTTP poll
    /// for the sender's original PSBT, walks the typestate, cosigns+stores the board in the
    /// finalize closure, posts the proposal, and (if in Monitor) checks for confirmation.
    pub async fn advance_session(
        &self,
        quote_id: &str,
        wallet: &Arc<bark::Wallet>,
        wallet_db_lock: &Arc<tokio::sync::Mutex<()>>,
    ) -> anyhow::Result<BoardResult> {
        let record = match self.state.get_quote(quote_id)? {
            Some(r) => r,
            None => return Ok(BoardResult::Idle),
        };
        let persister = self.state.session_persister(quote_id);

        let (session, history) = match replay_event_log(&persister) {
            Ok(v) => v,
            Err(e) => {
                debug!("payjoin {quote_id}: replay failed (likely expired/closed): {e}");
                return Ok(BoardResult::Idle);
            }
        };

        match history.status() {
            SessionStatus::Expired | SessionStatus::Failed => return Ok(BoardResult::Idle),
            SessionStatus::Completed | SessionStatus::FallbackBroadcasted => {
                // Already terminal at protocol level; crediting is handled via the board
                // confirmation path in ark_backend. Try to surface confirmation if known.
                return Ok(BoardResult::Idle);
            }
            SessionStatus::Active => {}
        }

        match session {
            ReceiveSession::Initialized(receiver) => {
                self.poll_for_original(quote_id, receiver).await
            }
            ReceiveSession::UncheckedOriginalPayload(_)
            | ReceiveSession::MaybeInputsOwned(_)
            | ReceiveSession::MaybeInputsSeen(_)
            | ReceiveSession::OutputsUnknown(_)
            | ReceiveSession::WantsOutputs(_)
            | ReceiveSession::WantsInputs(_)
            | ReceiveSession::WantsFeeRange(_)
            | ReceiveSession::ProvisionalProposal(_) => {
                // The full original->proposal walk is performed atomically right after the
                // original PSBT is retrieved (in `poll_for_original`). If we land here it means
                // a previous tick was interrupted mid-walk; re-run the walk from the current
                // state by re-reading the original payload. For simplicity and to avoid partial
                // re-entry hazards, we re-drive from whatever state we are in.
                self.drive_from_state(
                    quote_id,
                    &record,
                    session_again(&persister)?,
                    wallet,
                    wallet_db_lock,
                )
                .await
            }
            ReceiveSession::PayjoinProposal(proposal) => {
                self.post_proposal(quote_id, &record, proposal).await
            }
            ReceiveSession::Monitor(monitor) => {
                self.check_confirmation(quote_id, &record, monitor, wallet)
                    .await
            }
            ReceiveSession::HasReplyableError(receiver) => {
                self.post_error_reply(quote_id, receiver).await
            }
            ReceiveSession::Closed(_) => Ok(BoardResult::Idle),
        }
    }

    /// Post the BIP78 error reply for a session that reached `HasReplyableError` (e.g. a
    /// sub-minimum deposit rejected in `check_broadcast_suitability`, or any protocol error the
    /// payjoin crate flagged as replyable). Without this the sender never learns the payjoin was
    /// rejected and keeps polling the directory until expiry — and a spec-compliant sender may
    /// broadcast its 1-input fallback to the (un-cosigned) board address. Posting the encapsulated
    /// error lets a compliant sender abort cleanly. Best-effort: on transport failure we log and
    /// retry on the next tick (the session stays in HasReplyableError). On success we close it.
    async fn post_error_reply(
        &self,
        quote_id: &str,
        receiver: Receiver<payjoin::receive::v2::HasReplyableError>,
    ) -> anyhow::Result<BoardResult> {
        let (request, ohttp_ctx) = receiver
            .create_error_request(&self.config.ohttp_relay)
            .map_err(|e| anyhow::anyhow!("create_error_request: {e}"))?;
        let response = self.send_request(&request).await?;
        let persister = self.state.session_persister(quote_id);
        // On success this transition persists + closes the session (SaveAndClose).
        receiver
            .process_error_response(&response, ohttp_ctx)
            .save(&persister)
            .map_err(|e| anyhow::anyhow!("process_error_response: {e}"))?;
        info!("payjoin {quote_id}: posted BIP78 error reply to sender; session closed");
        Ok(BoardResult::Idle)
    }

    /// Poll the directory for the sender's original PSBT. If present, walk the full typestate.
    async fn poll_for_original(
        &self,
        quote_id: &str,
        receiver: Receiver<Initialized>,
    ) -> anyhow::Result<BoardResult> {
        let (request, ohttp_ctx) = receiver
            .create_poll_request(&self.config.ohttp_relay)
            .map_err(|e| anyhow::anyhow!("create_poll_request: {e}"))?;

        let response = self.send_request(&request).await?;

        let persister = self.state.session_persister(quote_id);
        let outcome = receiver
            .process_response(&response, ohttp_ctx)
            .save(&persister)
            .map_err(|e| anyhow::anyhow!("process_response: {e}"))?;

        match outcome {
            OptionalTransitionOutcome::Stasis(_) => {
                debug!("payjoin {quote_id}: no original PSBT yet");
                Ok(BoardResult::Idle)
            }
            OptionalTransitionOutcome::Progress(_unchecked) => {
                info!("payjoin {quote_id}: received original PSBT");
                self.telemetry
                    .emit(OnRampEvent::new(quote_id, OnRampStage::PayjoinReceived));
                // Re-read from the freshly-persisted state and walk to a proposal.
                let record = self
                    .state
                    .get_quote(quote_id)?
                    .ok_or_else(|| anyhow::anyhow!("quote {quote_id} vanished"))?;
                let session = session_again(&persister)?;
                // wallet is needed for the board cosign; the caller passes it in advance_session
                // but poll_for_original doesn't have it. We defer the rest of the walk to the next
                // tick of advance_session, which will land in the Unchecked/.. arm with the wallet.
                let _ = record;
                let _ = session;
                Ok(BoardResult::InProgress)
            }
        }
    }

    /// Walk the receiver typestate from its current (post-original) state through to a posted
    /// proposal, cosigning + storing the board in the finalize closure.
    async fn drive_from_state(
        &self,
        quote_id: &str,
        record: &crate::payjoin_state::OnRampQuoteRecord,
        session: ReceiveSession,
        wallet: &Arc<bark::Wallet>,
        wallet_db_lock: &Arc<tokio::sync::Mutex<()>>,
    ) -> anyhow::Result<BoardResult> {
        let persister = self.state.session_persister(quote_id);

        let board_script = {
            let bytes = hex::decode(&record.board_script_hex)
                .map_err(|e| anyhow::anyhow!("bad board script hex: {e}"))?;
            bitcoin::ScriptBuf::from_bytes(bytes)
        };

        // --- UncheckedOriginalPayload -> MaybeInputsOwned ---
        let unchecked = match session {
            ReceiveSession::UncheckedOriginalPayload(s) => s,
            // If interrupted further along, we cannot cheaply rewind; bail and retry next tick.
            other => {
                return self
                    .resume_partial(quote_id, record, other, wallet)
                    .await;
            }
        };

        // A4 FIX — enforce the Ark server's minimum board amount HERE, at the first check, before
        // any reserve UTXO is selected or locked. On-chain mint quotes are open-amount (NUT-30 has
        // no amount field), so the sender freely chooses how much to pay into the board (receiver)
        // output; this is the only receiver-side gate. Returning Ok(false) from `can_broadcast`
        // yields `OriginalPsbtNotBroadcastable` -> the session transitions to `HasReplyableError`
        // (persisted), and `advance_session` then posts a BIP78 `original-psbt-rejected` reply to
        // the sender. This replaces the old silent behavior where a sub-minimum board was sent to
        // cosign, rejected by the server, and retried forever with no reply (the sender hung and
        // could broadcast its 1-input fallback to an un-cosigned board address).
        let min_sat = self.min_board_amount_sat;
        let board_spk = board_script.clone();
        let quote_for_log = quote_id.to_string();
        let maybe_owned = unchecked
            .check_broadcast_suitability(None, move |tx| {
                let deposit_sat: u64 = tx
                    .output
                    .iter()
                    .filter(|o| o.script_pubkey == *board_spk.as_script())
                    .map(|o| o.value.to_sat())
                    .sum();
                if deposit_sat < min_sat {
                    warn!(
                        "payjoin {quote_for_log}: rejecting sub-minimum deposit {deposit_sat} sat \
                         (< min_board {min_sat} sat); posting BIP78 original-psbt-rejected reply",
                    );
                    return Ok(false);
                }
                Ok(true)
            })
            .save(&persister)
            .map_err(|e| anyhow::anyhow!("check_broadcast_suitability: {e}"))?;

        // --- check_inputs_not_owned (processor owns none of the sender inputs) ---
        let maybe_seen = maybe_owned
            .check_inputs_not_owned(&mut |_script| Ok(false))
            .save(&persister)
            .map_err(|e| anyhow::anyhow!("check_inputs_not_owned: {e}"))?;

        // --- check_no_inputs_seen_before (anti-probing via redb) ---
        let state = self.state.clone();
        let outputs_unknown = maybe_seen
            .check_no_inputs_seen_before(&mut |outpoint| {
                let key = outpoint.to_string();
                let seen = state
                    .is_input_seen(&key)
                    .map_err(|e| ImplementationError::from(e.to_string().as_str()))?;
                if !seen {
                    state
                        .mark_input_seen(&key)
                        .map_err(|e| ImplementationError::from(e.to_string().as_str()))?;
                }
                Ok(seen)
            })
            .save(&persister)
            .map_err(|e| anyhow::anyhow!("check_no_inputs_seen_before: {e}"))?;

        // --- identify_receiver_outputs: the receiver output is the board funding script ---
        let board_script_cmp = board_script.clone();
        let wants_outputs = outputs_unknown
            .identify_receiver_outputs(&mut |script| Ok(*script == *board_script_cmp.as_script()))
            .save(&persister)
            .map_err(|e| anyhow::anyhow!("identify_receiver_outputs: {e}"))?;

        // --- substitute_receiver_script -> the per-quote board funding script ---
        let wants_outputs = wants_outputs
            .substitute_receiver_script(board_script.as_script())
            .map_err(|e| anyhow::anyhow!("substitute_receiver_script: {e}"))?;
        let wants_inputs = wants_outputs
            .commit_outputs()
            .save(&persister)
            .map_err(|e| anyhow::anyhow!("commit_outputs: {e}"))?;

        // --- Capture D: the user's TRUE deposit. ---
        // D is the board (receiver) output value at the WantsInputs stage, i.e. BEFORE the mint
        // contributes any input and BEFORE any fee adjustment. `substitute_receiver_script`
        // preserves the value, so the committed board output equals exactly what the sender paid
        // in. We read it from the persisted `CommittedOutputs` event (the public, replay-safe
        // snapshot of the output set captured by `commit_outputs`) by matching the board script.
        // D is the #1 correctness invariant: the user is credited D regardless of any mint input
        // contribution (the mint's contributed input is its OWN reserve sitting inside the VTXO).
        let deposit_d_sat = read_committed_board_output_value(&persister, board_script.as_script())?;
        debug!("payjoin {quote_id}: captured user deposit D = {deposit_d_sat} sat (pre-contribution board output)");

        // --- contribute the mint's OWN input(s) (Tier 2), behind the PAYJOIN_RECEIVER_INPUTS flag ---
        // When the flag is OFF we contribute ZERO receiver inputs (Tier 3, the historical
        // behavior). When ON we source up to `receiver_input_count` spendable mint UTXOs, choose a
        // privacy-preserving first input via `try_preserving_privacy` (defeats the Unnecessary
        // Input Heuristic), contribute them (turning this into a real multi-input payjoin), and
        // have the mint absorb the marginal weight of its own inputs via apply_fee_range. If no
        // suitable/unlocked UTXO exists we fall back to the zero-input path so boards NEVER fail for
        // lack of mint liquidity.
        let (wants_inputs, contributed_outpoints): (_, Vec<OutPoint>) = if self
            .receiver_inputs_enabled
        {
            let selected = self.select_mint_inputs(quote_id, &wants_inputs).await;
            if selected.is_empty() {
                warn!("payjoin {quote_id}: PAYJOIN_RECEIVER_INPUTS on but no spendable/unlocked mint UTXO; falling back to zero-input board");
                (wants_inputs, Vec::new())
            } else {
                let outpoints: Vec<OutPoint> =
                    selected.iter().map(|(_, op)| *op).collect();
                let pairs: Vec<InputPair> = selected.into_iter().map(|(p, _)| p).collect();
                match wants_inputs.contribute_inputs(pairs) {
                    Ok(w) => {
                        info!(
                            "payjoin {quote_id}: contributed {} mint input(s) {:?} (Tier 2 multi-input payjoin)",
                            outpoints.len(),
                            outpoints
                        );
                        (w, outpoints)
                    }
                    Err(e) => {
                        // Release the locks we took during selection and fall back.
                        self.unlock_utxos(quote_id, &outpoints).await;
                        warn!("payjoin {quote_id}: contribute_inputs failed ({e}); falling back to zero-input board");
                        match session_again(&persister)? {
                            ReceiveSession::WantsInputs(w) => (w, Vec::new()),
                            _ => return Err(anyhow::anyhow!(
                                "payjoin {quote_id}: session not at WantsInputs after failed contribution"
                            )),
                        }
                    }
                }
            }
        } else {
            (wants_inputs, Vec::new())
        };

        let wants_fee_range = wants_inputs
            .commit_inputs()
            .save(&persister)
            .map_err(|e| anyhow::anyhow!("commit_inputs: {e}"))?;

        // --- apply_fee_range ---
        // With a contributed mint input, apply_fee_range subtracts the marginal weight of THAT
        // input from the receiver (board) output — i.e. the mint absorbs the fee for its own
        // input, the sender does not. With zero contribution this is a no-op on the board output.
        let provisional = wants_fee_range
            .apply_fee_range(Some(FeeRate::BROADCAST_MIN), None)
            .save(&persister)
            .map_err(|e| anyhow::anyhow!("apply_fee_range: {e}"))?;

        // --- finalize_proposal: cosign + store the board over the proposal PSBT ---
        let wallet = wallet.clone();
        let expiry_height = record.expiry_height;
        let keypair_index = record.keypair_index;
        let board_script_final = board_script.clone();

        // We need an async cosign inside a sync closure. Resolve the keypair + amount first,
        // then run the blocking-friendly cosign via a oneshot bridge.
        let user_keypair = wallet
            .peek_keypair(keypair_index)
            .await
            .map_err(|e| anyhow::anyhow!("peek_keypair({keypair_index}): {e}"))?;

        // Read the on-chain board output (gross, includes any mint contribution) and its vout from
        // the provisional PSBT. This is the value of the VTXO the server will cosign — NOT what we
        // credit the user. See the D-based crediting below.
        let (board_value_sat, board_vout) = {
            let psbt = provisional.psbt_to_sign();
            psbt.unsigned_tx
                .output
                .iter()
                .enumerate()
                .find(|(_, o)| o.script_pubkey == *board_script_final.as_script())
                .map(|(vout, o)| (o.value.to_sat(), vout as u32))
                .ok_or_else(|| anyhow::anyhow!("board output missing from proposal psbt"))?
        };

        // Cosign + store the board. cosign_and_store_board is async (takes the bark wallet's
        // movement-manager lock + the wallet sqlite, and does network IO to the Ark server). The
        // cosign attaches witnesses ONLY to the board/receiver path and locates the board output by
        // script, tolerating any input set; it MUST NOT alter unsigned_tx (ntxid stability) — so the
        // proposal PSBT's unsigned_tx is returned UNCHANGED. We run the cosign BEFORE
        // finalize_proposal and, in the finalize closure, sign the mint's own input (if any).
        //
        // Concurrency: we hold `wallet_db_lock` ONLY around the cosign so the board-poll loop and
        // this cosign never touch the bark wallet's sqlite at the same time. We run the cosign on a
        // `spawn_blocking` thread (NOT a runtime worker): the inner async work is driven with
        // `Handle::block_on` on that dedicated blocking thread, so even if rusqlite parks it, no
        // runtime worker is held and the outer `tokio::time::timeout` can still be polled and fire.
        let psbt_to_cosign = provisional.psbt_to_sign().clone();
        let pending = {
            let _wallet_db_guard = wallet_db_lock.lock().await;
            let cosign_wallet = wallet.clone();
            let handle = tokio::task::spawn_blocking(move || {
                let rt = tokio::runtime::Handle::current();
                rt.block_on(async move {
                    cosign_wallet
                        .cosign_and_store_board(psbt_to_cosign, user_keypair, expiry_height)
                        .await
                })
            });
            tokio::time::timeout(std::time::Duration::from_secs(30), handle)
                .await
                .map_err(|_| anyhow::anyhow!("cosign_and_store_board timed out after 30s"))?
                .map_err(|e| anyhow::anyhow!("cosign task join error: {e}"))??
        };

        // --- finalize_proposal: sign the mint's OWN input (Tier 2) or pass through (zero-input). ---
        // bdk's `sign` signs ONLY inputs the wallet holds keys for, so it touches the mint's input
        // and leaves the sender's untouched, and it does not alter unsigned_tx (ntxid stable). If no
        // mint input was contributed, the closure is a no-op pass-through (historical behavior).
        let proposal = if !contributed_outpoints.is_empty() {
            // Sign on the onchain wallet under its lock, then hand the signed PSBT to finalize.
            let signed = {
                let onchain = self.onchain_wallet.lock().await;
                let mut psbt = provisional.psbt_to_sign();
                #[allow(deprecated)]
                let opts = SignOptions {
                    trust_witness_utxo: true,
                    ..Default::default()
                };
                onchain
                    .sign(&mut psbt, opts)
                    .map_err(|e| anyhow::anyhow!("onchain wallet sign (mint input): {e}"))?;
                psbt
            };
            provisional
                .finalize_proposal(|_psbt| Ok(signed.clone()))
                .save(&persister)
                .map_err(|e| anyhow::anyhow!("finalize_proposal (signed mint inputs): {e}"))?
        } else {
            provisional
                .finalize_proposal(|psbt| Ok(psbt.clone()))
                .save(&persister)
                .map_err(|e| anyhow::anyhow!("finalize_proposal: {e}"))?
        };
        let board_txid = pending.funding_tx.compute_txid().to_string();

        // --- Credit D, NOT the on-chain board output. ---
        // The board VTXO is worth `board_value_sat` (= D + the mint's net contribution). The mint's
        // contributed input is its OWN reserve sitting inside the VTXO — it is NEVER the user's
        // ecash — so the user must be credited only D (gross) and D − board_fee (net), regardless of
        // any contribution. The server board fee is derived from the actual VTXO:
        //   board_fee = board_value_sat − pending.amount.
        // For the zero-input path board_value_sat == D, so gross/net are unchanged vs. before.
        let (gross_credit_sat, net_credit_sat, server_fee_sat, deposit_fee_sat) = credit_from_deposit(
            deposit_d_sat,
            board_value_sat,
            pending.amount.to_sat(),
            self.onchain_deposit_fee_bps,
        );
        let board_vtxo_ids: Vec<String> =
            pending.vtxos.iter().map(ToString::to_string).collect();
        let deposit_outpoint = format!("{board_txid}:{board_vout}");
        info!(
            "payjoin {quote_id}: board cosigned, txid={board_txid}, crediting user D={gross_credit_sat} sat gross / {net_credit_sat} sat net (server_fee={server_fee_sat} sat, deposit_fee={deposit_fee_sat} sat; on-chain VTXO value {board_value_sat} sat incl. {} mint input(s))",
            contributed_outpoints.len()
        );

        // Post the proposal back to the sender via the directory.
        self.post_proposal(quote_id, record, proposal).await?;

        // The board funding tx is broadcast by the sender after they sign the proposal; we treat
        // "proposal posted + board cosigned/stored" as the board_broadcast milestone.
        self.telemetry.emit(
            OnRampEvent::new(quote_id, OnRampStage::BoardBroadcast)
                .with_board_txid(&board_txid),
        );

        Ok(BoardResult::Boarded {
            board_txid,
            // Credit D, not the (possibly mint-bumped) on-chain board output value.
            net_sat: net_credit_sat,
            deposit_outpoint,
            gross_sat: gross_credit_sat,
            board_vtxo_ids,
        })
    }

    /// Best-effort resume for a session interrupted mid-walk (between Unchecked and Provisional).
    /// We cannot rewind the typestate without re-fetching, so we log and retry next tick. In
    /// practice the full walk in `drive_from_state` runs atomically, so this is rarely hit.
    async fn resume_partial(
        &self,
        quote_id: &str,
        record: &crate::payjoin_state::OnRampQuoteRecord,
        session: ReceiveSession,
        wallet: &Arc<bark::Wallet>,
    ) -> anyhow::Result<BoardResult> {
        match session {
            ReceiveSession::ProvisionalProposal(_) => {
                // Already finalized-pending; nothing extra to do but try posting on next tick.
                debug!("payjoin {quote_id}: resuming at ProvisionalProposal");
                let _ = (record, wallet);
                Ok(BoardResult::InProgress)
            }
            ReceiveSession::PayjoinProposal(proposal) => {
                self.post_proposal(quote_id, record, proposal).await
            }
            ReceiveSession::Monitor(monitor) => {
                self.check_confirmation(quote_id, record, monitor, wallet)
                    .await
            }
            _ => {
                debug!("payjoin {quote_id}: interrupted mid-walk; will retry next tick");
                Ok(BoardResult::InProgress)
            }
        }
    }

    /// POST the finalized proposal PSBT back to the directory for the sender.
    async fn post_proposal(
        &self,
        quote_id: &str,
        _record: &crate::payjoin_state::OnRampQuoteRecord,
        proposal: Receiver<payjoin::receive::v2::PayjoinProposal>,
    ) -> anyhow::Result<BoardResult> {
        let (request, ohttp_ctx) = proposal
            .create_post_request(&self.config.ohttp_relay)
            .map_err(|e| anyhow::anyhow!("create_post_request: {e}"))?;
        let response = self.send_request(&request).await?;

        let persister = self.state.session_persister(quote_id);
        proposal
            .process_response(&response, ohttp_ctx)
            .save(&persister)
            .map_err(|e| anyhow::anyhow!("proposal process_response: {e}"))?;

        info!("payjoin {quote_id}: proposal posted to directory");
        self.telemetry
            .emit(OnRampEvent::new(quote_id, OnRampStage::ProposalSent));
        Ok(BoardResult::InProgress)
    }

    /// In the Monitor state, check whether the board funding (payjoin) tx is on-chain.
    async fn check_confirmation(
        &self,
        quote_id: &str,
        _record: &crate::payjoin_state::OnRampQuoteRecord,
        monitor: Receiver<payjoin::receive::v2::Monitor>,
        wallet: &Arc<bark::Wallet>,
    ) -> anyhow::Result<BoardResult> {
        let persister = self.state.session_persister(quote_id);
        let chain = wallet.chain().clone();
        let outcome = monitor
            .check_payment(|txid| {
                let chain = chain.clone();
                let status = tokio::task::block_in_place(|| {
                    tokio::runtime::Handle::current().block_on(async {
                        chain.tx_status(txid).await
                    })
                })
                .map_err(|e| ImplementationError::from(e.to_string().as_str()))?;
                match status {
                    bitcoin_ext::TxStatus::Confirmed(_) | bitcoin_ext::TxStatus::Mempool => {
                        // We need the tx to return it; fetch is optional. The closure contract
                        // wants Option<Transaction>; returning None keeps us polling, so only
                        // report Some when confirmed by querying the tx itself is unnecessary —
                        // the monitor only needs existence. Use a minimal existence signal.
                        Ok(None)
                    }
                    bitcoin_ext::TxStatus::NotFound => Ok(None),
                }
            })
            .save(&persister)
            .map_err(|e| anyhow::anyhow!("monitor check_payment: {e}"))?;

        match outcome {
            OptionalTransitionOutcome::Progress(()) => {
                debug!("payjoin {quote_id}: monitor reached terminal outcome");
                Ok(BoardResult::InProgress)
            }
            OptionalTransitionOutcome::Stasis(_) => Ok(BoardResult::InProgress),
        }
    }

    /// Select up to `receiver_input_count` of the mint's own spendable UTXOs to contribute to the
    /// board, locking each chosen UTXO for the duration of this session so concurrent boards can't
    /// double-spend it. The first input is chosen via `try_preserving_privacy` to defeat the
    /// Unnecessary Input Heuristic (UIH2); any remaining inputs are appended from the rest of the
    /// (unlocked) candidate set. Returns `(InputPair, OutPoint)` pairs, or an empty Vec if the
    /// wallet has no spendable/unlocked UTXO (caller falls back to the zero-input path).
    ///
    /// LOCKING NOTE: the mint's contributed UTXOs are its OWN on-chain reserve; they are never the
    /// user's ecash. Spending one inside a board moves that reserve into the board VTXO.
    async fn select_mint_inputs(
        &self,
        quote_id: &str,
        wants_inputs: &Receiver<payjoin::receive::v2::WantsInputs>,
    ) -> Vec<(InputPair, OutPoint)> {
        let target = self.receiver_input_count.max(1) as usize;

        // Durable lock set (survives restarts), unioned with the in-memory same-process set.
        let durable_locked = self.state.locked_utxos().unwrap_or_default();

        // Snapshot spendable UTXOs (excluding any already locked by an in-flight board) and build
        // candidate InputPairs. We take the onchain lock briefly only to read list_unspent.
        let candidates: Vec<(InputPair, OutPoint)> = {
            let onchain = self.onchain_wallet.lock().await;
            let locked = self.locked_utxos.lock().await;
            let utxos: Vec<LocalOutput> = onchain.list_unspent();
            drop(onchain);
            utxos
                .into_iter()
                .filter(|o| {
                    !o.is_spent
                        && !locked.contains(&o.outpoint)
                        && !durable_locked.contains(&o.outpoint.to_string())
                })
                .filter_map(|o| {
                    build_input_pair(&o)
                        .map_err(|e| {
                            warn!("payjoin: skipping mint UTXO {} (cannot build InputPair: {e})", o.outpoint)
                        })
                        .ok()
                        .map(|pair| (pair, o.outpoint))
                })
                .collect()
        };

        if candidates.is_empty() {
            return Vec::new();
        }

        // Choose the privacy-preserving first input. `try_preserving_privacy` clones the candidate
        // InputPairs and returns the chosen one; we map it back to our (pair, outpoint) list by
        // value equality (InputPair derives PartialEq, and InputPair's outpoint field is not public
        // to this crate). It falls back to the first candidate internally if none avoid UIH2 or if
        // the tx is not 2-output, so this is always best-effort and never fails the board.
        let candidate_pairs = candidates.iter().map(|(p, _)| p.clone());
        let chosen_pos = match wants_inputs.try_preserving_privacy(candidate_pairs) {
            Ok(chosen) => candidates.iter().position(|(p, _)| *p == chosen).unwrap_or(0),
            Err(e) => {
                warn!("payjoin: try_preserving_privacy errored ({e}); using first candidate");
                0
            }
        };

        // Order candidates: privacy-chosen input first, then the rest, up to `target`.
        let mut ordered: Vec<(InputPair, OutPoint)> = Vec::with_capacity(candidates.len());
        ordered.push(candidates[chosen_pos].clone());
        for (i, c) in candidates.iter().enumerate() {
            if i != chosen_pos {
                ordered.push(c.clone());
            }
        }
        ordered.truncate(target);

        // Lock the chosen UTXOs so a concurrent board cannot pick the same coins. We record BOTH
        // an in-memory lock (fast same-process guard) and a durable redb lock keyed by quote_id
        // (survives restarts; released when the board terminates / on contribution failure).
        {
            let mut locked = self.locked_utxos.lock().await;
            for (_, op) in &ordered {
                locked.insert(*op);
            }
        }
        let durable: Vec<String> = ordered.iter().map(|(_, op)| op.to_string()).collect();
        if let Err(e) = self.state.lock_utxos(quote_id, &durable) {
            warn!("payjoin {quote_id}: failed to persist UTXO locks ({e}); relying on in-memory lock only");
        }
        ordered
    }

    /// Release previously-locked UTXOs (e.g. after a failed contribution), in both the in-memory
    /// set and the durable redb registry.
    async fn unlock_utxos(&self, quote_id: &str, outpoints: &[OutPoint]) {
        let mut locked = self.locked_utxos.lock().await;
        for op in outpoints {
            locked.remove(op);
        }
        drop(locked);
        if let Err(e) = self.state.unlock_utxos_for_quote(quote_id) {
            warn!("payjoin {quote_id}: failed to release durable UTXO locks ({e})");
        }
    }

    /// Send a payjoin [`payjoin::Request`] (already OHTTP-encapsulated and pointed at the relay)
    /// and return the raw response body bytes.
    async fn send_request(&self, request: &payjoin::Request) -> anyhow::Result<Vec<u8>> {
        let resp = self
            .http
            .post(&request.url)
            .header("Content-Type", request.content_type)
            .body(request.body.clone())
            .send()
            .await
            .map_err(|e| anyhow::anyhow!("payjoin http send: {e}"))?;
        let bytes = resp
            .bytes()
            .await
            .map_err(|e| anyhow::anyhow!("payjoin http body: {e}"))?;
        Ok(bytes.to_vec())
    }
}

/// Re-read the current session state from a persister (after a `.save`).
fn session_again(persister: &QuoteSessionPersister) -> anyhow::Result<ReceiveSession> {
    let (session, _history) =
        replay_event_log(persister).map_err(|e| anyhow::anyhow!("replay: {e}"))?;
    Ok(session)
}

/// Read the user's true deposit `D` = the board (receiver) output value as committed by
/// `commit_outputs`, BEFORE any receiver input contribution or fee adjustment.
///
/// `substitute_receiver_script` preserves the output value, so the committed board output equals
/// exactly what the sender paid into the board script. We read it from the persisted
/// `SessionEvent::CommittedOutputs` snapshot (the last such event) rather than from a live PSBT
/// accessor, because the `WantsInputs` typestate exposes no public PSBT and the committed-outputs
/// snapshot is the canonical pre-contribution output set.
fn read_committed_board_output_value(
    persister: &QuoteSessionPersister,
    board_script: &bitcoin::Script,
) -> anyhow::Result<u64> {
    use payjoin::persist::SessionPersister;
    let events = persister
        .load()
        .map_err(|e| anyhow::anyhow!("load session events for D capture: {e}"))?;
    let mut board_value: Option<u64> = None;
    for event in events {
        if let SessionEvent::CommittedOutputs(outputs) = event {
            // Take the LAST CommittedOutputs (there is normally exactly one) and match the board.
            board_value = outputs
                .iter()
                .find(|o| o.script_pubkey == *board_script)
                .map(|o| o.value.to_sat())
                .or(board_value);
        }
    }
    board_value.ok_or_else(|| {
        anyhow::anyhow!("could not capture user deposit D: no committed board output found in session log")
    })
}

/// Build a payjoin [`InputPair`] from one of the mint's own bdk [`LocalOutput`]s so it can be
/// contributed as a receiver input.
///
/// The mint's on-chain wallet uses a BIP86 (P2TR key-path) descriptor, so its UTXOs are taproot
/// key-spend outputs — [`InputPair::new_p2tr_keyspend`] sets the correct `witness_utxo` and the
/// canonical key-spend input weight. We fall back to P2WPKH for any (legacy/test) segwit-v0 UTXO.
/// The PSBT `witness_utxo` carried here is what later lets the bdk wallet sign this input inside
/// the finalize closure and lets `cosign_and_store_board` compute the on-chain fee via `Psbt::fee`.
fn build_input_pair(utxo: &LocalOutput) -> anyhow::Result<InputPair> {
    let txout = utxo.txout.clone();
    let outpoint = utxo.outpoint;
    if txout.script_pubkey.is_p2tr() {
        InputPair::new_p2tr_keyspend(txout, outpoint)
            .map_err(|e| anyhow::anyhow!("new_p2tr_keyspend: {e}"))
    } else if txout.script_pubkey.is_p2wpkh() {
        InputPair::new_p2wpkh(txout, outpoint).map_err(|e| anyhow::anyhow!("new_p2wpkh: {e}"))
    } else {
        Err(anyhow::anyhow!(
            "unsupported mint UTXO script type for payjoin contribution: {}",
            txout.script_pubkey
        ))
    }
}

/// Compute what the user is credited for a payjoin board, given:
/// - `deposit_d_sat`: D, the user's true deposit (board output value BEFORE any mint contribution),
/// - `board_value_sat`: the on-chain board output value (= D + the mint's net contribution),
/// - `vtxo_amount_sat`: the net VTXO value the server cosigned (= board_value_sat − server fee).
///
/// Returns `(gross, net, server_fee, deposit_fee)` where `gross == D` and
/// `net == D − server_fee − deposit_fee` — i.e. the user is credited EXACTLY their deposit D minus
/// fees, independent of any mint input contribution. The mint's contributed input is its OWN reserve
/// sitting inside the VTXO and is never credited to the user. `deposit_fee` is the mint's own
/// on-chain deposit fee (bps of D); like the mint's reserve, it simply stays inside the VTXO (we
/// issue less ecash than the VTXO backs), so total solvency is preserved by construction.
fn credit_from_deposit(
    deposit_d_sat: u64,
    board_value_sat: u64,
    vtxo_amount_sat: u64,
    onchain_deposit_fee_bps: u64,
) -> (u64, u64, u64, u64) {
    let server_fee_sat = board_value_sat.saturating_sub(vtxo_amount_sat);
    let deposit_fee_sat = deposit_d_sat.saturating_mul(onchain_deposit_fee_bps) / 10_000;
    let gross = deposit_d_sat;
    let net = deposit_d_sat
        .saturating_sub(server_fee_sat)
        .saturating_sub(deposit_fee_sat);
    (gross, net, server_fee_sat, deposit_fee_sat)
}

// Keep SessionOutcome referenced for documentation completeness / future terminal handling.
#[allow(dead_code)]
fn _outcome_doc(_o: SessionOutcome) {}

#[cfg(test)]
mod tests {
    use super::credit_from_deposit;

    #[test]
    fn credits_d_regardless_of_mint_contribution() {
        // Zero-input (Tier 3) board, no mint fee: board output == D. Server fee 100.
        let d = 50_000;
        let (gross, net, server_fee, dep_fee) = credit_from_deposit(d, d, d - 100, 0);
        assert_eq!(gross, d, "gross must equal D in the zero-input path");
        assert_eq!(server_fee, 100);
        assert_eq!(dep_fee, 0);
        assert_eq!(net, d - 100, "net must equal D - server_fee");

        // Tier 2 board: mint contributed 30_000 net into the VTXO, so the board output is
        // D + 30_000. The server fee is charged on the whole VTXO (say 120). The user must STILL
        // be credited exactly D gross and D - fee net — the mint's contribution is NOT credited.
        let board_value = d + 30_000;
        let vtxo_amount = board_value - 120;
        let (gross2, net2, server_fee2, _) = credit_from_deposit(d, board_value, vtxo_amount, 0);
        assert_eq!(gross2, d, "gross must equal D regardless of mint contribution");
        assert_eq!(server_fee2, 120);
        assert_eq!(net2, d - 120, "net must be D - fees, never include the mint input");

        // Even a large mint contribution does not inflate the user's credit.
        let big_board = d + 5_000_000;
        let (gross3, _net3, _sf3, _df3) = credit_from_deposit(d, big_board, big_board - 200, 0);
        assert_eq!(gross3, d);
    }

    #[test]
    fn deposit_fee_is_deducted_and_solvency_preserved() {
        // 0.5% (50 bps) on-chain deposit fee, zero server fee.
        let d = 60_000;
        let (gross, net, server_fee, dep_fee) = credit_from_deposit(d, d, d, 50);
        assert_eq!(gross, d, "gross is always D");
        assert_eq!(server_fee, 0);
        assert_eq!(dep_fee, 300, "0.5% of 60_000 = 300 sat");
        assert_eq!(net, d - 300, "user credited D - deposit_fee");
        // Solvency: VTXO backs `d`, we issue only `net`, so the fee stays as mint reserve.
        assert!(net <= d, "must never credit more than the VTXO backs");

        // Tier 2 + fee together: D=55k, mint added 100k (board 155k), server fee 0.
        let (g, n, sf, df) = credit_from_deposit(55_000, 155_000, 155_000, 50);
        assert_eq!(g, 55_000);
        assert_eq!(sf, 0);
        assert_eq!(df, 275, "0.5% of 55_000 = 275 sat");
        assert_eq!(n, 55_000 - 275, "credit-D-minus-fee holds under Tier 2");
    }
}
