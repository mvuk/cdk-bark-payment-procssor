use std::collections::HashMap;
use std::path::PathBuf;
use std::pin::Pin;
use std::str::FromStr;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use ark::lightning::PaymentHash;
use ark::VtxoId;
use async_trait::async_trait;
use bark::onchain::bdk_wallet::TxOrdering;
use bark::onchain::{ChainSync, GetAddress, GetWalletTx, OnchainWallet, PreparePsbt, SignPsbt};
use bark::persist::sqlite::SqliteClient;
use bark::persist::BarkPersister;
use bitcoin::{Address, FeeRate, OutPoint, Psbt, Transaction, Txid};
use cdk_common::amount::Amount;
use cdk_common::nuts::nut_onchain::MeltQuoteOnchainFeeOption;
use cdk_common::nuts::CurrencyUnit;
use cdk_common::payment::{
    Bolt11Settings, CreateIncomingPaymentResponse, Event, IncomingPaymentOptions,
    MakePaymentResponse, MintPayment, OnchainSettings, OutgoingPaymentOptions, PaymentIdentifier,
    PaymentQuoteResponse, SettingsResponse, WaitPaymentResponse,
};
use cdk_common::{MeltQuoteState, QuoteId};
use futures::stream::{self, Stream, StreamExt};
use redb::{Database, ReadableDatabase, ReadableTable, TableDefinition};
use serde::{Deserialize, Serialize};
use tracing::{debug, info, warn};

use crate::payjoin_receiver::{BoardResult, PayjoinConfig, PayjoinReceiver};
use crate::payjoin_state::{OnRampQuoteRecord, OnRampStateStore};
use crate::settings::BackendConfig;
use crate::telemetry::{OnRampEvent, OnRampStage, TelemetryClient};

const ONCHAIN_CONFIRMATIONS: u32 = 1;
const ONCHAIN_FEE_INDEX: u32 = 0;
const ONCHAIN_ESTIMATED_BLOCKS: u32 = 6;

/// Ark payment processor backend using the Bark wallet library
#[derive(Clone)]
pub struct ArkBackend {
    wallet: Arc<bark::Wallet>,
    onchain_wallet: Arc<tokio::sync::Mutex<OnchainWallet>>,
    onchain_send_lock: Arc<tokio::sync::Mutex<()>>,
    lightning_send_lock: Arc<tokio::sync::Mutex<()>>,
    /// Serializes all access to the bark wallet's sqlite between the board-poll loop
    /// (`process_onchain_receive_boards`) and the payjoin board cosign
    /// (`cosign_and_store_board`). Without this the 5s poll loop (esp. on long chains like
    /// Mutinynet) can hold sqlite long enough to starve a cosign parked in a blocking rusqlite
    /// call, defeating the cosign's 30s timeout. Hold ONLY around wallet/sqlite ops.
    wallet_db_lock: Arc<tokio::sync::Mutex<()>>,
    state_store: Arc<ArkStateStore>,
    network: bitcoin::Network,
    /// The Ark server's minimum board amount (sats), cached at startup from the server's
    /// `ArkInfo`. A board (and therefore an on-chain/payjoin mint quote) below this amount will be
    /// rejected by the server at cosign time, so we surface it to the CDK mint via
    /// `OnchainSettings::min_receive_amount_sat`. The mint then refuses sub-minimum NUT-04 onchain
    /// mint quotes at CREATION time (before any payjoin session/URI is issued), instead of taking
    /// the payment and failing silently later in `cosign_and_store_board`.
    min_board_amount_sat: u64,
    wait_invoice_active: Arc<AtomicBool>,
    /// On-ramp payjoin receiver runner (on-chain -> ecash via board).
    payjoin: PayjoinReceiver,
    /// Real-events-only telemetry client.
    telemetry: TelemetryClient,
    /// UTXOs reserved by in-flight Tier 2 payjoin boards (mint input contribution). Shared with
    /// the `PayjoinReceiver` so concurrent boards can't pick the same mint coin. Empty / unused
    /// when `PAYJOIN_RECEIVER_INPUTS` is off.
    #[allow(dead_code)]
    payjoin_locked_utxos: Arc<tokio::sync::Mutex<std::collections::HashSet<OutPoint>>>,
}

const RECEIVE_ADDRESSES_TABLE: TableDefinition<&str, &str> =
    TableDefinition::new("receive_addresses");
const RECEIVE_INTENTS_TABLE: TableDefinition<&str, &str> = TableDefinition::new("receive_intents");
const REPORTED_RECEIVES_TABLE: TableDefinition<&str, &str> =
    TableDefinition::new("reported_receives");
const LIGHTNING_RECEIVE_QUOTES_TABLE: TableDefinition<&str, &str> =
    TableDefinition::new("lightning_receive_quotes");
const REPORTED_LIGHTNING_RECEIVES_TABLE: TableDefinition<&str, &str> =
    TableDefinition::new("reported_lightning_receives");
const SEND_INTENTS_TABLE: TableDefinition<&str, &str> = TableDefinition::new("send_intents");
const COMPLETED_SENDS_TABLE: TableDefinition<&str, &str> = TableDefinition::new("completed_sends");
const LIGHTNING_SEND_INTENTS_TABLE: TableDefinition<&str, &str> =
    TableDefinition::new("lightning_send_intents");
const COMPLETED_LIGHTNING_SENDS_TABLE: TableDefinition<&str, &str> =
    TableDefinition::new("completed_lightning_sends");

const RETRY_BACKOFF_SECS: u64 = 30;
const SEND_ATTEMPT_REVIEW_SECS: u64 = 60;

#[derive(Clone, Debug, Deserialize, Serialize)]
struct OnchainReceiveIntentRecord {
    quote_id: String,
    deposit_outpoint: String,
    gross_sat: u64,
    state: OnchainReceiveIntentState,
}

#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(tag = "state", rename_all = "snake_case")]
enum OnchainReceiveIntentState {
    Detected {
        detected_at: u64,
    },
    BoardPreparing {
        attempt: u32,
        attempt_id: String,
        started_at: u64,
    },
    Boarding {
        attempt: u32,
        board_txid: String,
        board_vtxo_ids: Vec<String>,
        fee_sat: u64,
        amount_sat: u64,
        started_at: u64,
    },
    RetryableFailed {
        attempt: u32,
        reason: String,
        failed_at: u64,
        retry_after: u64,
    },
    NeedsReview {
        reason: String,
        failed_at: u64,
    },
    Finalized {
        board_txid: String,
        board_vtxo_ids: Vec<String>,
        fee_sat: u64,
        amount_sat: u64,
        finalized_at: u64,
    },
}

#[derive(Clone, Debug, Deserialize, Serialize)]
struct OnchainSendIntentRecord {
    quote_id: String,
    address: String,
    amount_sat: u64,
    state: OnchainSendIntentState,
}

#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(tag = "state", rename_all = "snake_case")]
enum OnchainSendIntentState {
    Attempting {
        attempt: u32,
        attempt_id: String,
        fee_sat: u64,
        started_at: u64,
    },
    Broadcast {
        txid: String,
        fee_sat: u64,
        broadcast_at: u64,
    },
    NeedsReview {
        reason: String,
        fee_sat: Option<u64>,
        failed_at: u64,
    },
    Confirmed {
        txid: String,
        fee_sat: u64,
        confirmed_at: u64,
    },
}

#[derive(Clone, Debug, Deserialize, Serialize)]
struct LightningSendIntentRecord {
    quote_id: String,
    payment_hash: String,
    invoice: String,
    amount_sat: u64,
    estimated_fee_sat: u64,
    state: LightningSendIntentState,
}

#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(tag = "state", rename_all = "snake_case")]
enum LightningSendIntentState {
    Attempting {
        attempt: u32,
        attempt_id: String,
        started_at: u64,
    },
    Pending {
        fee_sat: u64,
        started_at: u64,
    },
    Paid {
        fee_sat: u64,
        preimage: String,
        paid_at: u64,
    },
    Failed {
        reason: String,
        fee_sat: Option<u64>,
        failed_at: u64,
    },
    NeedsReview {
        reason: String,
        failed_at: u64,
    },
}

struct ArkStateStore {
    db: Database,
}

impl ArkStateStore {
    fn open(path: PathBuf) -> anyhow::Result<Self> {
        let db = Database::create(path)?;
        let store = Self { db };
        store.init()?;
        Ok(store)
    }

    fn init(&self) -> anyhow::Result<()> {
        let tx = self.db.begin_write()?;
        {
            tx.open_table(RECEIVE_ADDRESSES_TABLE)?;
            tx.open_table(RECEIVE_INTENTS_TABLE)?;
            tx.open_table(REPORTED_RECEIVES_TABLE)?;
            tx.open_table(LIGHTNING_RECEIVE_QUOTES_TABLE)?;
            tx.open_table(REPORTED_LIGHTNING_RECEIVES_TABLE)?;
            tx.open_table(SEND_INTENTS_TABLE)?;
            tx.open_table(COMPLETED_SENDS_TABLE)?;
            tx.open_table(LIGHTNING_SEND_INTENTS_TABLE)?;
            tx.open_table(COMPLETED_LIGHTNING_SENDS_TABLE)?;
        }
        tx.commit()?;
        Ok(())
    }

    fn store_error(e: impl std::fmt::Display) -> cdk_common::payment::Error {
        cdk_common::payment::Error::Custom(format!("Onchain state store error: {}", e))
    }

    fn put_receive_address(
        &self,
        quote_id: &str,
        address: &str,
    ) -> Result<(), cdk_common::payment::Error> {
        let tx = self.db.begin_write().map_err(Self::store_error)?;
        {
            let mut table = tx
                .open_table(RECEIVE_ADDRESSES_TABLE)
                .map_err(Self::store_error)?;
            table.insert(quote_id, address).map_err(Self::store_error)?;
        }
        tx.commit().map_err(Self::store_error)
    }

    fn receive_addresses(&self) -> Result<HashMap<String, String>, cdk_common::payment::Error> {
        let tx = self.db.begin_read().map_err(Self::store_error)?;
        let table = tx
            .open_table(RECEIVE_ADDRESSES_TABLE)
            .map_err(Self::store_error)?;
        let mut addresses = HashMap::new();
        for entry in table.iter().map_err(Self::store_error)? {
            let (key, value) = entry.map_err(Self::store_error)?;
            addresses.insert(key.value().to_string(), value.value().to_string());
        }
        Ok(addresses)
    }

    fn get_receive_intent(
        &self,
        outpoint: &str,
    ) -> Result<Option<OnchainReceiveIntentRecord>, cdk_common::payment::Error> {
        let tx = self.db.begin_read().map_err(Self::store_error)?;
        let table = tx
            .open_table(RECEIVE_INTENTS_TABLE)
            .map_err(Self::store_error)?;
        table
            .get(outpoint)
            .map_err(Self::store_error)?
            .map(|value| serde_json::from_str(value.value()).map_err(Self::store_error))
            .transpose()
    }

    fn put_receive_intent(
        &self,
        intent: &OnchainReceiveIntentRecord,
    ) -> Result<(), cdk_common::payment::Error> {
        let tx = self.db.begin_write().map_err(Self::store_error)?;
        {
            let mut table = tx
                .open_table(RECEIVE_INTENTS_TABLE)
                .map_err(Self::store_error)?;
            let value = serde_json::to_string(intent).map_err(Self::store_error)?;
            table
                .insert(intent.deposit_outpoint.as_str(), value.as_str())
                .map_err(Self::store_error)?;
        }
        tx.commit().map_err(Self::store_error)
    }

    fn receive_intents(
        &self,
    ) -> Result<Vec<OnchainReceiveIntentRecord>, cdk_common::payment::Error> {
        let tx = self.db.begin_read().map_err(Self::store_error)?;
        let table = tx
            .open_table(RECEIVE_INTENTS_TABLE)
            .map_err(Self::store_error)?;
        let mut intents = Vec::new();
        for entry in table.iter().map_err(Self::store_error)? {
            let (_, value) = entry.map_err(Self::store_error)?;
            intents.push(serde_json::from_str(value.value()).map_err(Self::store_error)?);
        }
        Ok(intents)
    }

    fn finalized_receives_for_quote(
        &self,
        quote_id: &str,
    ) -> Result<Vec<OnchainReceiveIntentRecord>, cdk_common::payment::Error> {
        Ok(self
            .receive_intents()?
            .into_iter()
            .filter(|intent| {
                intent.quote_id == quote_id
                    && matches!(intent.state, OnchainReceiveIntentState::Finalized { .. })
            })
            .collect())
    }

    fn next_unreported_finalized_receive(
        &self,
    ) -> Result<Option<OnchainReceiveIntentRecord>, cdk_common::payment::Error> {
        for intent in self.receive_intents()? {
            if matches!(intent.state, OnchainReceiveIntentState::Finalized { .. })
                && !self.is_receive_reported(&intent.deposit_outpoint)?
            {
                return Ok(Some(intent));
            }
        }
        Ok(None)
    }

    fn mark_receive_reported(&self, outpoint: &str) -> Result<(), cdk_common::payment::Error> {
        let tx = self.db.begin_write().map_err(Self::store_error)?;
        {
            let mut table = tx
                .open_table(REPORTED_RECEIVES_TABLE)
                .map_err(Self::store_error)?;
            table.insert(outpoint, "1").map_err(Self::store_error)?;
        }
        tx.commit().map_err(Self::store_error)
    }

    fn is_receive_reported(&self, outpoint: &str) -> Result<bool, cdk_common::payment::Error> {
        let tx = self.db.begin_read().map_err(Self::store_error)?;
        let table = tx
            .open_table(REPORTED_RECEIVES_TABLE)
            .map_err(Self::store_error)?;
        Ok(table.get(outpoint).map_err(Self::store_error)?.is_some())
    }

    fn put_lightning_receive_quote(
        &self,
        quote_id: &str,
        payment_hash: &str,
    ) -> Result<(), cdk_common::payment::Error> {
        let tx = self.db.begin_write().map_err(Self::store_error)?;
        {
            let mut table = tx
                .open_table(LIGHTNING_RECEIVE_QUOTES_TABLE)
                .map_err(Self::store_error)?;
            table
                .insert(quote_id, payment_hash)
                .map_err(Self::store_error)?;
        }
        tx.commit().map_err(Self::store_error)
    }

    fn get_lightning_receive_hash(
        &self,
        quote_id: &str,
    ) -> Result<Option<String>, cdk_common::payment::Error> {
        let tx = self.db.begin_read().map_err(Self::store_error)?;
        let table = tx
            .open_table(LIGHTNING_RECEIVE_QUOTES_TABLE)
            .map_err(Self::store_error)?;
        Ok(table
            .get(quote_id)
            .map_err(Self::store_error)?
            .map(|value| value.value().to_string()))
    }

    fn lightning_receive_quote_for_hash(
        &self,
        payment_hash: &str,
    ) -> Result<Option<String>, cdk_common::payment::Error> {
        let tx = self.db.begin_read().map_err(Self::store_error)?;
        let table = tx
            .open_table(LIGHTNING_RECEIVE_QUOTES_TABLE)
            .map_err(Self::store_error)?;
        for entry in table.iter().map_err(Self::store_error)? {
            let (quote_id, stored_hash) = entry.map_err(Self::store_error)?;
            if stored_hash.value() == payment_hash {
                return Ok(Some(quote_id.value().to_string()));
            }
        }
        Ok(None)
    }

    fn mark_lightning_receive_reported(
        &self,
        request_lookup_id: &str,
    ) -> Result<(), cdk_common::payment::Error> {
        let tx = self.db.begin_write().map_err(Self::store_error)?;
        {
            let mut table = tx
                .open_table(REPORTED_LIGHTNING_RECEIVES_TABLE)
                .map_err(Self::store_error)?;
            table
                .insert(request_lookup_id, "1")
                .map_err(Self::store_error)?;
        }
        tx.commit().map_err(Self::store_error)
    }

    fn is_lightning_receive_reported(
        &self,
        request_lookup_id: &str,
    ) -> Result<bool, cdk_common::payment::Error> {
        let tx = self.db.begin_read().map_err(Self::store_error)?;
        let table = tx
            .open_table(REPORTED_LIGHTNING_RECEIVES_TABLE)
            .map_err(Self::store_error)?;
        Ok(table
            .get(request_lookup_id)
            .map_err(Self::store_error)?
            .is_some())
    }

    fn put_send(
        &self,
        quote_id: &str,
        send: &OnchainSendIntentRecord,
    ) -> Result<(), cdk_common::payment::Error> {
        let tx = self.db.begin_write().map_err(Self::store_error)?;
        {
            let mut table = tx
                .open_table(SEND_INTENTS_TABLE)
                .map_err(Self::store_error)?;
            let value = serde_json::to_string(send).map_err(Self::store_error)?;
            table
                .insert(quote_id, value.as_str())
                .map_err(Self::store_error)?;
        }
        tx.commit().map_err(Self::store_error)
    }

    fn get_send(
        &self,
        quote_id: &str,
    ) -> Result<Option<OnchainSendIntentRecord>, cdk_common::payment::Error> {
        let tx = self.db.begin_read().map_err(Self::store_error)?;
        let table = tx
            .open_table(SEND_INTENTS_TABLE)
            .map_err(Self::store_error)?;
        table
            .get(quote_id)
            .map_err(Self::store_error)?
            .map(|value| serde_json::from_str(value.value()).map_err(Self::store_error))
            .transpose()
    }

    fn sends(&self) -> Result<Vec<(String, OnchainSendIntentRecord)>, cdk_common::payment::Error> {
        let tx = self.db.begin_read().map_err(Self::store_error)?;
        let table = tx
            .open_table(SEND_INTENTS_TABLE)
            .map_err(Self::store_error)?;
        let mut sends = Vec::new();
        for entry in table.iter().map_err(Self::store_error)? {
            let (key, value) = entry.map_err(Self::store_error)?;
            sends.push((
                key.value().to_string(),
                serde_json::from_str(value.value()).map_err(Self::store_error)?,
            ));
        }
        Ok(sends)
    }

    fn mark_send_completed(&self, quote_id: &str) -> Result<(), cdk_common::payment::Error> {
        let tx = self.db.begin_write().map_err(Self::store_error)?;
        {
            let mut table = tx
                .open_table(COMPLETED_SENDS_TABLE)
                .map_err(Self::store_error)?;
            table.insert(quote_id, "1").map_err(Self::store_error)?;
        }
        tx.commit().map_err(Self::store_error)
    }

    fn is_send_completed(&self, quote_id: &str) -> Result<bool, cdk_common::payment::Error> {
        let tx = self.db.begin_read().map_err(Self::store_error)?;
        let table = tx
            .open_table(COMPLETED_SENDS_TABLE)
            .map_err(Self::store_error)?;
        Ok(table.get(quote_id).map_err(Self::store_error)?.is_some())
    }

    fn put_lightning_send(
        &self,
        payment_hash: &str,
        send: &LightningSendIntentRecord,
    ) -> Result<(), cdk_common::payment::Error> {
        let tx = self.db.begin_write().map_err(Self::store_error)?;
        {
            let mut table = tx
                .open_table(LIGHTNING_SEND_INTENTS_TABLE)
                .map_err(Self::store_error)?;
            let value = serde_json::to_string(send).map_err(Self::store_error)?;
            table
                .insert(payment_hash, value.as_str())
                .map_err(Self::store_error)?;
        }
        tx.commit().map_err(Self::store_error)
    }

    fn get_lightning_send(
        &self,
        payment_hash: &str,
    ) -> Result<Option<LightningSendIntentRecord>, cdk_common::payment::Error> {
        let tx = self.db.begin_read().map_err(Self::store_error)?;
        let table = tx
            .open_table(LIGHTNING_SEND_INTENTS_TABLE)
            .map_err(Self::store_error)?;
        table
            .get(payment_hash)
            .map_err(Self::store_error)?
            .map(|value| serde_json::from_str(value.value()).map_err(Self::store_error))
            .transpose()
    }

    fn lightning_sends(
        &self,
    ) -> Result<Vec<(String, LightningSendIntentRecord)>, cdk_common::payment::Error> {
        let tx = self.db.begin_read().map_err(Self::store_error)?;
        let table = tx
            .open_table(LIGHTNING_SEND_INTENTS_TABLE)
            .map_err(Self::store_error)?;
        let mut sends = Vec::new();
        for entry in table.iter().map_err(Self::store_error)? {
            let (key, value) = entry.map_err(Self::store_error)?;
            sends.push((
                key.value().to_string(),
                serde_json::from_str(value.value()).map_err(Self::store_error)?,
            ));
        }
        Ok(sends)
    }

    fn lightning_send_for_quote(
        &self,
        quote_id: &str,
    ) -> Result<Option<(String, LightningSendIntentRecord)>, cdk_common::payment::Error> {
        Ok(self
            .lightning_sends()?
            .into_iter()
            .find(|(_, send)| send.quote_id == quote_id))
    }

    fn mark_lightning_send_completed(
        &self,
        payment_hash: &str,
    ) -> Result<(), cdk_common::payment::Error> {
        let tx = self.db.begin_write().map_err(Self::store_error)?;
        {
            let mut table = tx
                .open_table(COMPLETED_LIGHTNING_SENDS_TABLE)
                .map_err(Self::store_error)?;
            table.insert(payment_hash, "1").map_err(Self::store_error)?;
        }
        tx.commit().map_err(Self::store_error)
    }

    fn is_lightning_send_completed(
        &self,
        payment_hash: &str,
    ) -> Result<bool, cdk_common::payment::Error> {
        let tx = self.db.begin_read().map_err(Self::store_error)?;
        let table = tx
            .open_table(COMPLETED_LIGHTNING_SENDS_TABLE)
            .map_err(Self::store_error)?;
        Ok(table
            .get(payment_hash)
            .map_err(Self::store_error)?
            .is_some())
    }
}

struct ScopedBoard<'a> {
    inner: &'a mut OnchainWallet,
    outpoint: OutPoint,
}

impl PreparePsbt for ScopedBoard<'_> {
    fn prepare_tx(
        &mut self,
        destinations: &[(Address, bitcoin::Amount)],
        fee_rate: FeeRate,
    ) -> anyhow::Result<Psbt> {
        let mut builder = self.inner.build_tx();
        builder.ordering(TxOrdering::Untouched);
        builder.add_utxo(self.outpoint)?;
        builder.manually_selected_only();
        for (dest, amount) in destinations {
            builder.add_recipient(dest.script_pubkey(), *amount);
        }
        builder.fee_rate(fee_rate);
        builder.finish().map_err(Into::into)
    }

    fn prepare_drain_tx(
        &mut self,
        destination: Address,
        fee_rate: FeeRate,
    ) -> anyhow::Result<Psbt> {
        let mut builder = self.inner.build_tx();
        builder.ordering(TxOrdering::Untouched);
        builder.add_utxo(self.outpoint)?;
        builder.manually_selected_only();
        builder.drain_to(destination.script_pubkey());
        builder.fee_rate(fee_rate);
        builder.finish().map_err(Into::into)
    }
}

#[async_trait]
impl SignPsbt for ScopedBoard<'_> {
    async fn finish_psbt(&mut self, psbt: Psbt) -> anyhow::Result<Psbt> {
        self.inner.finish_psbt(psbt).await
    }
}

impl GetWalletTx for ScopedBoard<'_> {
    fn get_wallet_tx(&self, txid: Txid) -> Option<Arc<Transaction>> {
        self.inner.get_wallet_tx(txid)
    }

    fn get_wallet_tx_confirmed_block(
        &self,
        txid: Txid,
    ) -> anyhow::Result<Option<bitcoin_ext::BlockRef>> {
        self.inner.get_wallet_tx_confirmed_block(txid)
    }
}

impl ArkBackend {
    /// Create a new Ark backend with initialized wallet
    pub async fn new(config: &BackendConfig) -> anyhow::Result<Self> {
        info!("Initializing Ark backend");

        // Parse the mnemonic
        let mnemonic = config
            .mnemonic
            .parse::<bip39::Mnemonic>()
            .map_err(|e| anyhow::anyhow!("Invalid mnemonic: {}", e))?;

        // Parse the network
        let network = match config.network.to_lowercase().as_str() {
            "mainnet" => bitcoin::Network::Bitcoin,
            "testnet" => bitcoin::Network::Testnet,
            "signet" => bitcoin::Network::Signet,
            "regtest" => bitcoin::Network::Regtest,
            _ => {
                warn!("Unknown network '{}', defaulting to Signet", config.network);
                bitcoin::Network::Signet
            }
        };

        // Build bark config. Chain source selection: prefer Esplora when ESPLORA_ADDRESS is set
        // (mainnet uses https://mempool.space/api with NO local bitcoind); otherwise fall
        // back to bitcoind for the local Mutinynet/regtest setup. bark (lib.rs:1051) picks Esplora
        // whenever esplora_address.is_some(), else bitcoind, else bails — so only one is set.
        let use_esplora = !config.esplora_address.trim().is_empty();
        let esplora_address = use_esplora.then(|| config.esplora_address.clone());
        let bitcoind_address = (!use_esplora).then(|| config.bitcoind_address.clone());
        let (bitcoind_user, bitcoind_pass) = if use_esplora {
            (None, None)
        } else {
            (
                Some(config.bitcoind_user.clone()),
                Some(config.bitcoind_pass.clone()),
            )
        };
        // Ark server access token: mainnet your Ark server is token-gated. When set, bark sends it
        // on the gRPC client (Config::server_access_token -> .access_token(..), lib.rs:1151).
        // Empty/unset for local Mutinynet (no token required).
        let server_access_token = {
            let t = config.server_access_token.trim();
            (!t.is_empty()).then(|| t.to_string())
        };
        if use_esplora {
            info!("Chain source: Esplora ({})", config.esplora_address);
        } else {
            info!("Chain source: bitcoind ({})", config.bitcoind_address);
        }
        let bark_config = bark::Config {
            server_address: config.server_address.clone(),
            server_access_token,
            esplora_address,
            bitcoind_address,
            bitcoind_user,
            bitcoind_pass,
            ..bark::Config::network_default(network)
        };

        // Create data directory if it doesn't exist
        let data_dir = PathBuf::from(&config.data_dir);
        std::fs::create_dir_all(&data_dir)
            .map_err(|e| anyhow::anyhow!("Failed to create data directory: {}", e))?;

        // Open SQLite database
        let db_path = data_dir.join("db.sqlite");
        let db: Arc<dyn BarkPersister> = Arc::new(
            SqliteClient::open(&db_path)
                .map_err(|e| anyhow::anyhow!("Failed to open SQLite database: {}", e))?,
        );

        // Give the bdk on-chain wallet its OWN sqlite file, separate from the bark VTXO
        // wallet's db.sqlite. The two subsystems use disjoint tables (bark VTXO/movement
        // state vs the bdk wallet changeset) and the processor passes the onchain wallet to
        // bark methods as a parameter, never via a shared db connection. Splitting the file
        // means the on-chain wallet's slow mempool sync no longer contends on a
        // database-level write lock with the payjoin cosign. A fresh onchain.sqlite is fine:
        // it's the payjoin fallback sink, starts empty, and re-syncs from tip via the
        // set_birthday call below.
        let onchain_db_path = data_dir.join("onchain.sqlite");
        let onchain_db: Arc<dyn BarkPersister> = Arc::new(
            SqliteClient::open(&onchain_db_path)
                .map_err(|e| anyhow::anyhow!("Failed to open on-chain SQLite database: {}", e))?,
        );

        let mut onchain_wallet =
            OnchainWallet::load_or_create(network, mnemonic.to_seed(""), onchain_db)
                .await
                .map_err(|e| anyhow::anyhow!("Failed to load onchain wallet: {}", e))?;

        // Try to open existing wallet first, fall back to creating new one
        let wallet = match bark::Wallet::open(
            &mnemonic,
            db.clone(),
            bark_config.clone(),
            bark::lock_manager::platform_default(&data_dir)
                .map_err(|e| anyhow::anyhow!("Failed to init lock manager: {}", e))?,
        )
        .await
        {
            Ok(wallet) => {
                info!("Opened existing Ark wallet");
                wallet
            }
            Err(e) => {
                info!("Creating new Ark wallet (open failed: {})", e);
                bark::Wallet::create(
                    &mnemonic,
                    network,
                    bark_config,
                    db,
                    bark::lock_manager::platform_default(&data_dir)
                        .map_err(|e| anyhow::anyhow!("Failed to init lock manager: {}", e))?,
                    false,
                )
                .await
                .map_err(|e| anyhow::anyhow!("Failed to create wallet: {}", e))?
            }
        };

        // For a freshly-created onchain wallet, seed a "birthday" checkpoint at
        // the current chain tip so the first sync doesn't scan from genesis.
        // On a long chain (e.g. Mutinynet) a genesis scan builds a multi-million
        // entry LocalChain that makes is_block_in_chain pathologically slow and
        // starves the board cosign loop. This is a no-op for an already-synced
        // wallet. The processor only cosigns boards and never needs history.
        onchain_wallet
            .set_birthday(&wallet.chain())
            .await
            .map_err(|e| anyhow::anyhow!("Failed to set onchain wallet birthday: {}", e))?;

        onchain_wallet
            .sync(&wallet.chain())
            .await
            .map_err(|e| anyhow::anyhow!("Failed to sync onchain wallet: {}", e))?;

        // Shared registry of UTXOs reserved by in-flight Tier 2 boards.
        let payjoin_locked_utxos: Arc<tokio::sync::Mutex<std::collections::HashSet<OutPoint>>> =
            Arc::new(tokio::sync::Mutex::new(std::collections::HashSet::new()));

        let state_store = Arc::new(
            ArkStateStore::open(data_dir.join("onchain_state.redb"))
                .map_err(|e| anyhow::anyhow!("Failed to open onchain state store: {}", e))?,
        );

        // On-ramp payjoin state store (separate redb file).
        let onramp_db = Arc::new(
            Database::create(data_dir.join("onramp_state.redb"))
                .map_err(|e| anyhow::anyhow!("Failed to open onramp state store: {}", e))?,
        );
        let onramp_store = OnRampStateStore::open(onramp_db)
            .map_err(|e| anyhow::anyhow!("Failed to init onramp state store: {}", e))?;

        // Startup prune of abandoned on-ramp sessions (comma-separated quote ids in
        // ONRAMP_PRUNE_QUOTES). Never-paid test sessions otherwise consume the sequential poll
        // budget (~5s OHTTP each), starving live boards. Safe: removes only the listed ids.
        if let Ok(prune_ids) = std::env::var("ONRAMP_PRUNE_QUOTES") {
            for id in prune_ids.split(',').map(|s| s.trim()).filter(|s| !s.is_empty()) {
                match onramp_store.remove_quote(id) {
                    Ok(()) => tracing::info!("onramp prune: removed stale quote {}", id),
                    Err(e) => tracing::warn!("onramp prune: failed to remove {}: {}", id, e),
                }
            }
        }

        // Log the mint's on-chain receive address so the wallet can be funded for Tier 2 payjoin
        // boarding (the mint contributing its OWN input). We derive via `address()`, which uses
        // bdk `reveal_next_address` (monotonic, single-use) — never `next_unused_address` — so an
        // advertised funding script is never reused. We additionally record the derived script in
        // the no-address-reuse guard, which logs a warning if a script was ever advertised before.
        match onchain_wallet.address().await {
            Ok(addr) => {
                info!("Mint on-chain wallet receive address: {}", addr);
                let script_hex = hex::encode(addr.script_pubkey().as_bytes());
                if let Err(e) =
                    onramp_store.record_advertised_script(&script_hex, "mint-onchain-receive")
                {
                    warn!("payjoin single-use guard: {e}");
                }
            }
            Err(e) => warn!("Could not derive mint on-chain receive address: {}", e),
        }

        // Wrap the onchain wallet in its shared Arc<Mutex> now so the same handle backs both the
        // backend and the payjoin receiver (Tier 2 input sourcing + signing).
        let onchain_wallet: Arc<tokio::sync::Mutex<OnchainWallet>> =
            Arc::new(tokio::sync::Mutex::new(onchain_wallet));

        // Resolve OHTTP keys: parse from config if present, else fetch from the directory
        // via the relay. A failure here is non-fatal: the on-ramp simply can't create sessions
        // until keys are available.
        let ohttp_keys = if config.payjoin_ohttp_keys.trim().is_empty() {
            match payjoin::io::fetch_ohttp_keys(
                config.payjoin_ohttp_relay.clone(),
                config.payjoin_directory_url.clone(),
            )
            .await
            {
                Ok(keys) => Some(keys),
                Err(e) => {
                    warn!("Failed to fetch payjoin OHTTP keys (on-ramp disabled until available): {e}");
                    None
                }
            }
        } else {
            // Configured keys are a hex-encoded OHTTP KeyConfig (the wire form decoded by
            // `OhttpKeys::decode`). The bech32 `OH1...` `FromStr` path is test-only upstream, so
            // we accept the hex form here for a stable, public decode path.
            match hex::decode(config.payjoin_ohttp_keys.trim())
                .map_err(|e| e.to_string())
                .and_then(|bytes| {
                    payjoin::OhttpKeys::decode(&bytes).map_err(|e| e.to_string())
                }) {
                Ok(keys) => Some(keys),
                Err(e) => {
                    warn!("Invalid configured payjoin OHTTP keys (expected hex KeyConfig; on-ramp disabled): {e}");
                    None
                }
            }
        };

        // Tier 2 payjoin boarding flag: when on, the mint contributes its OWN on-chain input(s) to
        // the board (real multi-input payjoin); when off (default) boards are zero-receiver-input
        // (Tier 3, unchanged historical behavior).
        if config.payjoin_receiver_inputs {
            info!(
                "Payjoin receiver inputs (Tier 2) ENABLED: mint will contribute up to {} of its own \
                 on-chain input(s) per board (PAYJOIN_RECEIVER_INPUTS=1)",
                config.payjoin_receiver_input_count
            );
        } else {
            info!("Payjoin receiver inputs (Tier 2) DISABLED: zero-input boards (Tier 3). Set PAYJOIN_RECEIVER_INPUTS=1 to enable");
        }

        let telemetry = TelemetryClient::new(config.control_url.clone());
        // Fetch the Ark server's minimum board amount at startup. This is the same value the
        // server enforces inside `cosign_and_store_board`; surfacing it here lets the CDK mint
        // reject sub-minimum on-chain (payjoin board) mint quotes at creation time rather than
        // issuing a payjoin URI, taking the payment, and failing silently at cosign.
        //
        // We MUST NOT default this to 1 on failure: a 1-sat floor silently admits sub-minimum
        // boards that the server later rejects at cosign, stranding the depositor's funds (the A4
        // path). Instead we gate startup on Ark reachability with a BOUNDED retry: poll
        // require_ark_info every 5s for up to ~2 min, then hard-fail (refuse to start) if the
        // server never answers. systemd's Restart=on-failure will retry — far better than coming
        // up with a wrong floor. Bounded so a hang is impossible (timeout discipline).
        let min_board_amount_sat = {
            const RETRY_INTERVAL: Duration = Duration::from_secs(5);
            const MAX_WAIT: Duration = Duration::from_secs(120);
            let deadline = std::time::Instant::now() + MAX_WAIT;
            loop {
                match wallet.require_ark_info().await {
                    Ok(ark_info) => {
                        let min = ark_info.min_board_amount.to_sat();
                        info!("Ark server minimum board amount: {} sat", min);
                        break min;
                    }
                    Err(e) => {
                        if std::time::Instant::now() >= deadline {
                            return Err(anyhow::anyhow!(
                                "Ark server unreachable: could not fetch min_board_amount after {}s \
                                 (last error: {}); refusing to start rather than defaulting the \
                                 board floor to 1 sat (would strand sub-minimum deposits)",
                                MAX_WAIT.as_secs(),
                                e
                            ));
                        }
                        warn!(
                            "Ark server min_board_amount not yet available ({}); retrying in {}s \
                             (bounded, will hard-fail at {}s total)",
                            e,
                            RETRY_INTERVAL.as_secs(),
                            MAX_WAIT.as_secs()
                        );
                        tokio::time::sleep(RETRY_INTERVAL).await;
                    }
                }
            }
        };

        let payjoin = PayjoinReceiver::new(
            PayjoinConfig {
                directory_url: config.payjoin_directory_url.clone(),
                ohttp_relay: config.payjoin_ohttp_relay.clone(),
                ohttp_keys,
                control_url: config.control_url.clone(),
            },
            onramp_store,
            telemetry.clone(),
            config.payjoin_receiver_inputs,
            config.payjoin_receiver_input_count,
            onchain_wallet.clone(),
            payjoin_locked_utxos.clone(),
            min_board_amount_sat,
            config.payjoin_onchain_deposit_fee_bps,
        );

        info!("Ark backend initialized successfully");

        Ok(Self {
            wallet: Arc::new(wallet),
            onchain_wallet,
            onchain_send_lock: Arc::new(tokio::sync::Mutex::new(())),
            lightning_send_lock: Arc::new(tokio::sync::Mutex::new(())),
            wallet_db_lock: Arc::new(tokio::sync::Mutex::new(())),
            state_store,
            network,
            min_board_amount_sat,
            wait_invoice_active: Arc::new(AtomicBool::new(false)),
            payjoin,
            telemetry,
            payjoin_locked_utxos,
        })
    }

    /// Drive all active payjoin on-ramp sessions forward one step. Intended to be called on a
    /// timer from the service startup (see `main.rs`). Errors per-session are logged and do not
    /// abort the loop.
    pub async fn poll_onramp(&self) {
        let results = self
            .payjoin
            .poll_all(&self.wallet, &self.wallet_db_lock)
            .await;
        for (quote_id, res) in results {
            match res {
                Ok(BoardResult::Boarded {
                    board_txid,
                    net_sat,
                    deposit_outpoint,
                    gross_sat,
                    board_vtxo_ids,
                }) => {
                    // The payjoin path cosigns + stores the board directly and never goes through
                    // the legacy `board_all` flow, so it never creates a `Boarding` receive intent.
                    // Persist one here so the existing finalize -> check_onchain_receive ->
                    // PaymentReceived machinery credits the quote once the board VTXOs become
                    // spendable. Idempotent: skip if an intent for this outpoint already exists.
                    if let Err(e) = self.record_payjoin_boarding_intent(
                        &quote_id,
                        deposit_outpoint,
                        board_txid,
                        gross_sat,
                        net_sat,
                        board_vtxo_ids,
                    ) {
                        warn!("payjoin {quote_id}: failed to record boarding intent: {e}");
                    }
                }
                Ok(_) => {}
                // A real cosign/board failure (e.g. the server rejecting the board as below its
                // minimum board amount) bubbles up here from `advance_session`/`drive_from_state`.
                // Log it at `warn!` (visible at default RUST_LOG=info) with the quote_id and full
                // error so the failure surfaces instead of looking like a silent hang.
                Err(e) => warn!("payjoin on-ramp board failed for quote {quote_id}: {e:#}"),
            }
        }
        // After advancing sessions, run the existing board detect/finalize machinery so confirmed
        // boards become spendable and are surfaced for crediting.
        if let Err(e) = self.process_onchain_receive_boards().await {
            debug!("on-ramp board reconcile error: {e}");
        }
    }

    /// Clone of the payjoin receiver for external poll loops.
    pub fn payjoin_receiver(&self) -> PayjoinReceiver {
        self.payjoin.clone()
    }

    /// Periodic bark wallet maintenance. VTXOs expire after `vtxo_lifetime` blocks; any custody
    /// VTXO (the funds backing issued ecash) not refreshed before expiry can only be recovered
    /// via an expensive unilateral exit. `maintenance_delegated` schedules refresh rounds with
    /// the server for VTXOs inside the refresh threshold without blocking on round completion.
    /// Intended to be called on a timer from `main.rs`; must run well inside the bark refresh
    /// threshold (12 blocks = ~6 min on Mutinynet's 30s blocks, 144 blocks = 24h on mainnet).
    pub async fn run_maintenance(&self) -> anyhow::Result<()> {
        // Same lock discipline as the other wallet/sqlite ops: hold `wallet_db_lock` only
        // around the bark wallet call so a payjoin cosign is never starved.
        let _wallet_db_guard = self.wallet_db_lock.lock().await;
        self.wallet.maintenance_delegated().await
    }

    /// One-shot manual offboard, env-gated from `main.rs` (`RECYCLER_TEST_OFFBOARD_SAT`). Offboards
    /// `amount_sat` of the mint's Ark reserve to a FRESH on-chain bdk address. This validates the
    /// recycler primitive on mainnet (and reveals offboard confirmation timing) BEFORE any
    /// unattended loop is wired. SAFE only while total VTXO value stays well above the
    /// outstanding-ecash liability — the caller picks a small amount well inside the mint's OWN
    /// reserve. Funds are not lost: they move Ark -> the mint's own on-chain wallet (the float).
    pub async fn recycle_test_offboard(&self, amount_sat: u64) -> anyhow::Result<Txid> {
        let dest = {
            let mut oc = self.onchain_wallet.lock().await;
            oc.address().await?
        };
        tracing::warn!(
            "recycle TEST offboard: moving {} sat Ark reserve -> fresh on-chain {}",
            amount_sat,
            dest
        );
        let _wallet_db_guard = self.wallet_db_lock.lock().await;
        let txid = self
            .wallet
            .send_onchain(dest, bitcoin::Amount::from_sat(amount_sat))
            .await?;
        tracing::warn!("recycle TEST offboard: send_onchain -> txid {}", txid);
        Ok(txid)
    }

    /// Split the mint's on-chain (bdk) reserve into many small **randomized** UTXOs (each in
    /// `[min_sat, max_sat]`), to FRESH addresses, in a single self-send tx. This is what turns a
    /// lump reserve into a stream of small lend denominations: with `PAYJOIN_RECEIVER_INPUT_COUNT=1`
    /// each Tier-2 board then contributes one of these small coins, so the lend per board is a
    /// random 5–20k. No funds leave the mint (mint -> its own fresh addresses); the only cost is the
    /// miner fee. Randomness is system-seeded (unpredictable to a chain observer; not crypto-grade,
    /// which is fine for amount jitter). Env-gated one-shot via `RECYCLER_SPLIT_NOW` in main.rs.
    pub async fn split_reserve(&self, min_sat: u64, max_sat: u64) -> anyhow::Result<Txid> {
        use std::hash::{BuildHasher, Hasher};
        let _wallet_db_guard = self.wallet_db_lock.lock().await;
        let mut oc = self.onchain_wallet.lock().await;
        let spendable = oc.balance().confirmed.to_sat();
        let fee_margin: u64 = 3000; // leave room for the miner fee; remainder becomes a small change UTXO
        anyhow::ensure!(
            spendable > min_sat + fee_margin,
            "reserve too small to split ({} sat)",
            spendable
        );
        let mut dests: Vec<(Address, bitcoin::Amount)> = Vec::new();
        let mut allocated: u64 = 0;
        let mut i: u64 = 0;
        loop {
            let remaining = spendable.saturating_sub(allocated);
            let hi = std::cmp::min(max_sat, remaining.saturating_sub(fee_margin));
            if hi < min_sat || dests.len() >= 60 {
                break;
            }
            // system-seeded unpredictable amount in [min_sat, hi]
            let s = std::collections::hash_map::RandomState::new();
            let mut h = s.build_hasher();
            h.write_u64(i);
            h.write_u64(allocated);
            let amt = min_sat + (h.finish() % (hi - min_sat + 1));
            let addr = oc.address().await?;
            dests.push((addr, bitcoin::Amount::from_sat(amt)));
            allocated += amt;
            i += 1;
        }
        anyhow::ensure!(!dests.is_empty(), "no split destinations generated");
        let feerate = FeeRate::from_sat_per_vb(2).unwrap_or(FeeRate::BROADCAST_MIN);
        tracing::warn!(
            "split_reserve: splitting {} sat of {} reserve into {} randomized UTXOs ({}-{} sat each)",
            allocated,
            spendable,
            dests.len(),
            min_sat,
            max_sat
        );
        let txid = oc
            .send_many(&self.wallet.chain(), &dests, feerate)
            .await?;
        tracing::warn!("split_reserve: broadcast split tx {} ({} outputs)", txid, dests.len());
        Ok(txid)
    }

    fn parse_bitcoin_address(
        &self,
        address: &str,
    ) -> Result<bitcoin::Address, cdk_common::payment::Error> {
        address
            .parse::<bitcoin::Address<_>>()
            .map_err(|e| cdk_common::payment::Error::Custom(format!("Invalid address: {}", e)))?
            .require_network(self.network)
            .map_err(|e| {
                cdk_common::payment::Error::Custom(format!("Address network mismatch: {}", e))
            })
    }

    async fn process_onchain_receive_boards(&self) -> Result<(), cdk_common::payment::Error> {
        // Sync the on-chain (bdk) wallet FIRST, WITHOUT holding `wallet_db_lock`. The on-chain
        // wallet now persists to its own onchain.sqlite (separate file from the bark VTXO
        // db.sqlite), so this slow mempool sync no longer touches the sqlite the payjoin board
        // cosign uses — holding `wallet_db_lock` across it would park the cosign behind the sync
        // for no reason. `onchain_wallet` is locked ONLY here (no other code path acquires it), so
        // taking it before `wallet_db_lock` cannot invert any lock order.
        let mut onchain = self.onchain_wallet.lock().await;
        onchain.sync(&self.wallet.chain()).await.map_err(|e| {
            cdk_common::payment::Error::Custom(format!("Failed to sync onchain wallet: {}", e))
        })?;

        // Everything below touches the bark VTXO sqlite (db.sqlite); serialize it against the
        // cosign by holding `wallet_db_lock` for these (fast) bark-db operations only.
        let _wallet_db_guard = self.wallet_db_lock.lock().await;

        if let Err(e) = self.wallet.sync_pending_boards().await {
            debug!("Failed to sync pending boards: {}", e);
        }

        let tip = self.wallet.chain().tip().await.map_err(|e| {
            cdk_common::payment::Error::Custom(format!("Failed to get chain tip: {}", e))
        })?;

        self.recover_preparing_receive_boards(&onchain).await?;
        self.finalize_spendable_receive_boards().await?;
        self.detect_confirmed_receive_deposits(&onchain, tip)
            .await?;
        self.start_ready_receive_boards(&mut onchain).await
    }

    async fn detect_confirmed_receive_deposits(
        &self,
        onchain: &OnchainWallet,
        tip: u32,
    ) -> Result<(), cdk_common::payment::Error> {
        let receive_addresses = self.state_store.receive_addresses()?;
        if receive_addresses.is_empty() {
            return Ok(());
        }
        let address_to_quote = receive_addresses
            .iter()
            .map(|(quote_id, address)| (address.clone(), quote_id.clone()))
            .collect::<HashMap<_, _>>();

        for output in onchain.list_unspent() {
            let Some(height) = output.chain_position.confirmation_height_upper_bound() else {
                continue;
            };
            let confirmations = tip.saturating_sub(height.saturating_sub(1));
            if confirmations < ONCHAIN_CONFIRMATIONS {
                continue;
            }

            let output_address =
                bitcoin::Address::from_script(output.txout.script_pubkey.as_script(), self.network)
                    .map(|addr| addr.to_string())
                    .ok();
            let Some(quote_id_str) = output_address
                .as_ref()
                .and_then(|address| address_to_quote.get(address))
            else {
                continue;
            };

            let outpoint = output.outpoint.to_string();
            if self.state_store.get_receive_intent(&outpoint)?.is_some() {
                continue;
            }

            QuoteId::from_str(quote_id_str).map_err(|e| {
                cdk_common::payment::Error::Custom(format!(
                    "Invalid stored quote id {}: {}",
                    quote_id_str, e
                ))
            })?;

            let intent = OnchainReceiveIntentRecord {
                quote_id: quote_id_str.clone(),
                deposit_outpoint: outpoint.clone(),
                gross_sat: output.txout.value.to_sat(),
                state: OnchainReceiveIntentState::Detected {
                    detected_at: Self::unix_now(),
                },
            };
            self.state_store.put_receive_intent(&intent)?;

            info!(
                "Detected confirmed onchain receive {} for quote {}: gross {} sat",
                outpoint, quote_id_str, intent.gross_sat
            );
        }

        Ok(())
    }

    async fn start_ready_receive_boards(
        &self,
        onchain: &mut OnchainWallet,
    ) -> Result<(), cdk_common::payment::Error> {
        let now = Self::unix_now();
        for intent in self.state_store.receive_intents()? {
            let (attempt, ready) = match &intent.state {
                OnchainReceiveIntentState::Detected { .. } => (1, true),
                OnchainReceiveIntentState::RetryableFailed {
                    attempt,
                    retry_after,
                    ..
                } => (attempt.saturating_add(1), *retry_after <= now),
                _ => (0, false),
            };

            if !ready {
                continue;
            }

            let outpoint = OutPoint::from_str(&intent.deposit_outpoint).map_err(|e| {
                cdk_common::payment::Error::Custom(format!(
                    "Invalid stored deposit outpoint {}: {}",
                    intent.deposit_outpoint, e
                ))
            })?;

            let attempt_id = uuid::Uuid::new_v4().to_string();
            let started_at = Self::unix_now();
            let mut preparing = intent.clone();
            preparing.state = OnchainReceiveIntentState::BoardPreparing {
                attempt,
                attempt_id,
                started_at,
            };
            self.state_store.put_receive_intent(&preparing)?;

            let board_result = {
                let mut scoped_board = ScopedBoard {
                    inner: onchain,
                    outpoint,
                };
                self.wallet.board_all(&mut scoped_board).await
            };

            match board_result {
                Ok(pending_board) => {
                    let board_intent = Self::boarding_intent_from_pending(
                        preparing,
                        pending_board,
                        attempt,
                        started_at,
                    );
                    self.state_store.put_receive_intent(&board_intent)?;
                    if let OnchainReceiveIntentState::Boarding {
                        board_txid,
                        amount_sat,
                        ..
                    } = &board_intent.state
                    {
                        info!(
                            "Started board {} for onchain receive {} quote {}: gross {} sat, net {} sat",
                            board_txid,
                            board_intent.deposit_outpoint,
                            board_intent.quote_id,
                            board_intent.gross_sat,
                            amount_sat
                        );
                    }
                }
                Err(e) => {
                    let reason = e.to_string();
                    warn!(
                        "Failed to start board for onchain receive {} quote {}: {}",
                        preparing.deposit_outpoint, preparing.quote_id, reason
                    );

                    if let Some(pending_board) =
                        self.pending_board_spending_outpoint(outpoint).await?
                    {
                        let board_intent = Self::boarding_intent_from_pending(
                            preparing,
                            pending_board,
                            attempt,
                            started_at,
                        );
                        self.state_store.put_receive_intent(&board_intent)?;
                    } else if onchain
                        .list_unspent()
                        .iter()
                        .any(|output| output.outpoint == outpoint)
                    {
                        let mut failed = preparing;
                        failed.state = OnchainReceiveIntentState::RetryableFailed {
                            attempt,
                            reason,
                            failed_at: Self::unix_now(),
                            retry_after: Self::unix_now().saturating_add(RETRY_BACKOFF_SECS),
                        };
                        self.state_store.put_receive_intent(&failed)?;
                    } else {
                        let mut needs_review = preparing;
                        needs_review.state = OnchainReceiveIntentState::NeedsReview {
                            reason: format!(
                                "Board attempt failed after target outpoint stopped being spendable: {}",
                                reason
                            ),
                            failed_at: Self::unix_now(),
                        };
                        self.state_store.put_receive_intent(&needs_review)?;
                    }
                }
            }
        }

        Ok(())
    }

    async fn recover_preparing_receive_boards(
        &self,
        onchain: &OnchainWallet,
    ) -> Result<(), cdk_common::payment::Error> {
        for intent in self.state_store.receive_intents()? {
            let OnchainReceiveIntentState::BoardPreparing {
                attempt,
                started_at,
                ..
            } = intent.state
            else {
                continue;
            };

            let outpoint = OutPoint::from_str(&intent.deposit_outpoint).map_err(|e| {
                cdk_common::payment::Error::Custom(format!(
                    "Invalid stored deposit outpoint {}: {}",
                    intent.deposit_outpoint, e
                ))
            })?;

            if let Some(pending_board) = self.pending_board_spending_outpoint(outpoint).await? {
                let recovered =
                    Self::boarding_intent_from_pending(intent, pending_board, attempt, started_at);
                self.state_store.put_receive_intent(&recovered)?;
            } else if onchain
                .list_unspent()
                .iter()
                .any(|output| output.outpoint == outpoint)
            {
                let mut retryable = intent;
                retryable.state = OnchainReceiveIntentState::RetryableFailed {
                    attempt,
                    reason: "Interrupted before board was committed".to_string(),
                    failed_at: Self::unix_now(),
                    retry_after: Self::unix_now(),
                };
                self.state_store.put_receive_intent(&retryable)?;
            } else {
                let mut needs_review = intent;
                needs_review.state = OnchainReceiveIntentState::NeedsReview {
                    reason: "Interrupted board attempt spent the target outpoint but no Bark pending board was found".to_string(),
                    failed_at: Self::unix_now(),
                };
                self.state_store.put_receive_intent(&needs_review)?;
            }
        }

        Ok(())
    }

    async fn finalize_spendable_receive_boards(&self) -> Result<(), cdk_common::payment::Error> {
        'intents: for intent in self.state_store.receive_intents()? {
            let OnchainReceiveIntentState::Boarding {
                board_txid,
                board_vtxo_ids,
                fee_sat,
                amount_sat,
                ..
            } = &intent.state
            else {
                continue;
            };

            for vtxo_id in board_vtxo_ids {
                let vtxo_id = match VtxoId::from_str(vtxo_id) {
                    Ok(vtxo_id) => vtxo_id,
                    Err(e) => {
                        warn!("Invalid stored board vtxo id {}: {}", vtxo_id, e);
                        continue 'intents;
                    }
                };
                let vtxo = match self.wallet.get_vtxo_by_id(vtxo_id).await {
                    Ok(vtxo) => vtxo,
                    Err(e) => {
                        debug!("Board vtxo {} is not available yet: {}", vtxo_id, e);
                        continue 'intents;
                    }
                };

                if !matches!(vtxo.state.kind(), bark::vtxo::VtxoStateKind::Spendable) {
                    continue 'intents;
                }
            }

            let mut finalized = intent.clone();
            finalized.state = OnchainReceiveIntentState::Finalized {
                board_txid: board_txid.clone(),
                board_vtxo_ids: board_vtxo_ids.clone(),
                fee_sat: *fee_sat,
                amount_sat: *amount_sat,
                finalized_at: Self::unix_now(),
            };
            self.state_store.put_receive_intent(&finalized)?;

            info!(
                "Finalized onchain receive {} for quote {} after board {} became spendable",
                finalized.deposit_outpoint, finalized.quote_id, board_txid
            );

            // REAL event: the board funding tx confirmed and the VTXO became spendable, growing
            // the mint reserve by the boarded amount.
            if self
                .payjoin
                .state
                .get_quote(&finalized.quote_id)
                .ok()
                .flatten()
                .is_some()
            {
                self.telemetry.emit(
                    OnRampEvent::new(&finalized.quote_id, OnRampStage::BoardConfirmed)
                        .with_board_txid(board_txid)
                        .with_vtxo_amount_sat(*amount_sat)
                        .with_vtxo_ids(board_vtxo_ids.clone()),
                );
            }
        }

        Ok(())
    }

    async fn pending_board_spending_outpoint(
        &self,
        outpoint: OutPoint,
    ) -> Result<Option<bark::persist::models::PendingBoard>, cdk_common::payment::Error> {
        let pending_boards = self.wallet.pending_boards().await.map_err(|e| {
            cdk_common::payment::Error::Custom(format!("Failed to list pending boards: {}", e))
        })?;

        Ok(pending_boards.into_iter().find(|board| {
            board
                .funding_tx
                .input
                .iter()
                .any(|input| input.previous_output == outpoint)
        }))
    }

    fn boarding_intent_from_pending(
        mut intent: OnchainReceiveIntentRecord,
        pending_board: bark::persist::models::PendingBoard,
        attempt: u32,
        started_at: u64,
    ) -> OnchainReceiveIntentRecord {
        let amount_sat = pending_board.amount.to_sat();
        let fee_sat = intent.gross_sat.saturating_sub(amount_sat);
        intent.state = OnchainReceiveIntentState::Boarding {
            attempt,
            board_txid: pending_board.funding_tx.compute_txid().to_string(),
            board_vtxo_ids: pending_board
                .vtxos
                .iter()
                .map(ToString::to_string)
                .collect(),
            fee_sat,
            amount_sat,
            started_at,
        };
        intent
    }

    /// Persist a `Boarding` onchain receive intent for a payjoin board that was cosigned + stored
    /// directly by the payjoin receiver (which bypasses the legacy `board_all` flow). This makes
    /// the existing `finalize_spendable_receive_boards` -> `check_onchain_receive` ->
    /// `Event::PaymentReceived` machinery credit the quote once the board VTXOs become spendable.
    ///
    /// Idempotent: if an intent already exists for `deposit_outpoint`, it is left untouched so we
    /// never overwrite a later state (e.g. `Finalized`) or re-credit.
    fn record_payjoin_boarding_intent(
        &self,
        quote_id: &str,
        deposit_outpoint: String,
        board_txid: String,
        gross_sat: u64,
        amount_sat: u64,
        board_vtxo_ids: Vec<String>,
    ) -> Result<(), cdk_common::payment::Error> {
        if self
            .state_store
            .get_receive_intent(&deposit_outpoint)?
            .is_some()
        {
            return Ok(());
        }

        let fee_sat = gross_sat.saturating_sub(amount_sat);
        let intent = OnchainReceiveIntentRecord {
            quote_id: quote_id.to_string(),
            deposit_outpoint,
            gross_sat,
            state: OnchainReceiveIntentState::Boarding {
                attempt: 1,
                board_txid,
                board_vtxo_ids,
                fee_sat,
                amount_sat,
                started_at: Self::unix_now(),
            },
        };
        self.state_store.put_receive_intent(&intent)?;
        info!(
            "Recorded payjoin board intent {} for quote {}: gross {} sat, net {} sat",
            intent.deposit_outpoint, intent.quote_id, intent.gross_sat, amount_sat
        );
        Ok(())
    }

    async fn check_onchain_receive(
        &self,
        quote_id: &QuoteId,
        mark_reported: bool,
    ) -> Result<Vec<WaitPaymentResponse>, cdk_common::payment::Error> {
        self.process_onchain_receive_boards().await?;

        let responses = self
            .state_store
            .finalized_receives_for_quote(&quote_id.to_string())?
            .into_iter()
            .filter_map(|receive| {
                let OnchainReceiveIntentState::Finalized {
                    board_txid,
                    amount_sat,
                    ..
                } = receive.state
                else {
                    return None;
                };
                Some((receive.deposit_outpoint, board_txid, amount_sat))
            })
            .collect::<Vec<_>>();

        if mark_reported && !responses.is_empty() {
            // This is the polling path the mint uses to credit ONCHAIN quotes (the
            // wait_payment_event stream only runs for bolt11). Emit the ecash_issued
            // telemetry here too — gated on this being an on-ramp quote — so the
            // dashboard's final stage + the user's ecash balance animate on a real credit.
            let is_onramp = self
                .payjoin
                .state
                .get_quote(&quote_id.to_string())
                .ok()
                .flatten()
                .is_some();
            for (outpoint, board_txid, amount_sat) in &responses {
                self.state_store.mark_receive_reported(outpoint)?;
                if is_onramp {
                    self.telemetry.emit(
                        OnRampEvent::new(&quote_id.to_string(), OnRampStage::EcashIssued)
                            .with_board_txid(board_txid)
                            .with_ecash_amount_sat(*amount_sat),
                    );
                }
            }
        }

        Ok(responses
            .into_iter()
            .map(|(_, board_txid, amount_sat)| WaitPaymentResponse {
                payment_identifier: PaymentIdentifier::QuoteId(quote_id.clone()),
                payment_amount: Amount::new(amount_sat, CurrencyUnit::Sat),
                payment_id: board_txid,
            })
            .collect())
    }

    async fn next_onchain_receive_event(
        &self,
    ) -> Result<Option<Event>, cdk_common::payment::Error> {
        self.process_onchain_receive_boards().await?;

        let Some(receive) = self.state_store.next_unreported_finalized_receive()? else {
            return Ok(None);
        };

        let quote_id = QuoteId::from_str(&receive.quote_id).map_err(|e| {
            cdk_common::payment::Error::Custom(format!(
                "Invalid stored quote id {}: {}",
                receive.quote_id, e
            ))
        })?;

        let OnchainReceiveIntentState::Finalized {
            board_txid,
            amount_sat,
            ..
        } = receive.state
        else {
            return Ok(None);
        };

        self.state_store
            .mark_receive_reported(&receive.deposit_outpoint)?;

        // REAL event: the mint is being credited (PaymentReceived emitted) for this on-ramp quote,
        // so the user's ecash balance grows by the net boarded amount.
        if self
            .payjoin
            .state
            .get_quote(&receive.quote_id)
            .ok()
            .flatten()
            .is_some()
        {
            self.telemetry.emit(
                OnRampEvent::new(&receive.quote_id, OnRampStage::EcashIssued)
                    .with_board_txid(&board_txid)
                    .with_ecash_amount_sat(amount_sat),
            );
        }

        Ok(Some(Event::PaymentReceived(WaitPaymentResponse {
            payment_identifier: PaymentIdentifier::QuoteId(quote_id),
            payment_amount: Amount::new(amount_sat, CurrencyUnit::Sat),
            payment_id: board_txid,
        })))
    }

    async fn next_onchain_send_event(&self) -> Result<Option<Event>, cdk_common::payment::Error> {
        self.reconcile_onchain_sends().await?;

        for (quote_id_str, send) in self.state_store.sends()? {
            if self.state_store.is_send_completed(&quote_id_str)? {
                continue;
            }

            let OnchainSendIntentState::Confirmed { txid, fee_sat, .. } = &send.state else {
                continue;
            };

            let quote_id = QuoteId::from_str(&quote_id_str).map_err(|e| {
                cdk_common::payment::Error::Custom(format!(
                    "Invalid stored quote id {}: {}",
                    quote_id_str, e
                ))
            })?;

            self.state_store.mark_send_completed(&quote_id_str)?;

            let total_spent = send.amount_sat.saturating_add(*fee_sat);
            return Ok(Some(Event::PaymentSuccessful {
                quote_id: quote_id.clone(),
                details: MakePaymentResponse {
                    payment_lookup_id: PaymentIdentifier::QuoteId(quote_id),
                    payment_proof: Some(txid.clone()),
                    status: MeltQuoteState::Paid,
                    total_spent: Amount::new(total_spent, CurrencyUnit::Sat),
                },
            }));
        }

        Ok(None)
    }

    async fn check_onchain_send(
        &self,
        quote_id: &QuoteId,
        mark_completed: bool,
    ) -> Result<Option<MakePaymentResponse>, cdk_common::payment::Error> {
        self.reconcile_onchain_sends().await?;

        let quote_id_str = quote_id.to_string();
        let send = self.state_store.get_send(&quote_id_str)?;
        let Some(send) = send else {
            return Ok(None);
        };

        Ok(Some(self.onchain_send_response(
            quote_id,
            &send,
            mark_completed,
        )?))
    }

    async fn reconcile_onchain_sends(&self) -> Result<(), cdk_common::payment::Error> {
        // Serialize bark-wallet sqlite/state access against the payjoin board cosign and the
        // board-poll loop. Held across the offboard sync and the per-send tx_status checks.
        let _wallet_db_guard = self.wallet_db_lock.lock().await;

        if let Err(e) = self.wallet.sync_pending_offboards().await {
            debug!("Failed to sync pending offboards: {}", e);
        }

        let now = Self::unix_now();
        for (quote_id_str, send) in self.state_store.sends()? {
            match &send.state {
                OnchainSendIntentState::Attempting {
                    fee_sat,
                    started_at,
                    ..
                } if started_at.saturating_add(SEND_ATTEMPT_REVIEW_SECS) <= now => {
                    let mut needs_review = send.clone();
                    needs_review.state = OnchainSendIntentState::NeedsReview {
                        reason: "Interrupted during Bark send_onchain; pending offboards are not exposed by the public Bark API for automatic recovery".to_string(),
                        fee_sat: Some(*fee_sat),
                        failed_at: now,
                    };
                    self.state_store.put_send(&quote_id_str, &needs_review)?;
                    warn!(
                        "Marked onchain send quote {} as needs_review after interrupted Bark send_onchain",
                        quote_id_str
                    );
                }
                OnchainSendIntentState::Broadcast { txid, fee_sat, .. } => {
                    let parsed_txid = Txid::from_str(txid).map_err(|e| {
                        cdk_common::payment::Error::Custom(format!(
                            "Invalid stored offboard txid {}: {}",
                            txid, e
                        ))
                    })?;

                    match self.wallet.chain().tx_status(parsed_txid).await {
                        Ok(bitcoin_ext::TxStatus::Confirmed(_)) => {
                            let mut confirmed = send.clone();
                            confirmed.state = OnchainSendIntentState::Confirmed {
                                txid: txid.clone(),
                                fee_sat: *fee_sat,
                                confirmed_at: now,
                            };
                            self.state_store.put_send(&quote_id_str, &confirmed)?;
                            info!("Confirmed onchain send {} for quote {}", txid, quote_id_str);
                        }
                        Ok(bitcoin_ext::TxStatus::Mempool)
                        | Ok(bitcoin_ext::TxStatus::NotFound) => {}
                        Err(e) => {
                            debug!("Failed to check onchain tx status for {}: {}", txid, e);
                        }
                    }
                }
                _ => {}
            }
        }

        Ok(())
    }

    fn onchain_send_response(
        &self,
        quote_id: &QuoteId,
        send: &OnchainSendIntentRecord,
        mark_completed: bool,
    ) -> Result<MakePaymentResponse, cdk_common::payment::Error> {
        let (status, payment_proof, total_spent) = match &send.state {
            OnchainSendIntentState::Confirmed { txid, fee_sat, .. } => {
                if mark_completed {
                    self.state_store
                        .mark_send_completed(&quote_id.to_string())?;
                }
                (
                    MeltQuoteState::Paid,
                    Some(txid.clone()),
                    send.amount_sat.saturating_add(*fee_sat),
                )
            }
            OnchainSendIntentState::Broadcast { txid, .. } => {
                (MeltQuoteState::Pending, Some(txid.clone()), 0)
            }
            OnchainSendIntentState::Attempting { .. }
            | OnchainSendIntentState::NeedsReview { .. } => (MeltQuoteState::Pending, None, 0),
        };

        Ok(MakePaymentResponse {
            payment_lookup_id: PaymentIdentifier::QuoteId(quote_id.clone()),
            payment_proof,
            status,
            total_spent: Amount::new(total_spent, CurrencyUnit::Sat),
        })
    }

    async fn reconcile_lightning_sends(&self) -> Result<(), cdk_common::payment::Error> {
        for (payment_hash, _) in self.state_store.lightning_sends()? {
            self.reconcile_lightning_send(&payment_hash).await?;
        }
        Ok(())
    }

    async fn reconcile_lightning_send(
        &self,
        payment_hash_hex: &str,
    ) -> Result<Option<LightningSendIntentRecord>, cdk_common::payment::Error> {
        let Some(intent) = self.state_store.get_lightning_send(payment_hash_hex)? else {
            return Ok(None);
        };

        let payment_hash = Self::parse_payment_hash_hex(payment_hash_hex)?;
        // Serialize the bark-wallet sqlite/state read against the cosign and poll loop.
        let bark_result = {
            let _wallet_db_guard = self.wallet_db_lock.lock().await;
            self.wallet
                .check_lightning_payment(PaymentHash::from(payment_hash), false)
                .await
        };
        match bark_result {
            Ok(state) => {
                let updated = Self::lightning_intent_from_bark_send(intent, &state);
                self.state_store
                    .put_lightning_send(payment_hash_hex, &updated)?;
                Ok(Some(updated))
            }
            Err(e) => {
                let now = Self::unix_now();
                let mut updated = intent.clone();
                if matches!(
                    intent.state,
                    LightningSendIntentState::Attempting { started_at, .. }
                        if started_at.saturating_add(SEND_ATTEMPT_REVIEW_SECS) <= now
                ) {
                    updated.state = LightningSendIntentState::NeedsReview {
                        reason: format!(
                            "Interrupted during Bark pay_lightning_invoice and no recoverable send state was found: {}",
                            e
                        ),
                        failed_at: now,
                    };
                    self.state_store
                        .put_lightning_send(payment_hash_hex, &updated)?;
                    warn!(
                        "Marked lightning send {} as needs_review after interrupted Bark payment",
                        payment_hash_hex
                    );
                    return Ok(Some(updated));
                }

                debug!(
                    "Failed to reconcile lightning send {}: {}",
                    payment_hash_hex, e
                );
                Ok(Some(intent))
            }
        }
    }

    async fn next_lightning_send_event(&self) -> Result<Option<Event>, cdk_common::payment::Error> {
        self.reconcile_lightning_sends().await?;

        for (payment_hash, send) in self.state_store.lightning_sends()? {
            if self
                .state_store
                .is_lightning_send_completed(&payment_hash)?
            {
                continue;
            }

            let quote_id = QuoteId::from_str(&send.quote_id).map_err(|e| {
                cdk_common::payment::Error::Custom(format!(
                    "Invalid stored quote id {}: {}",
                    send.quote_id, e
                ))
            })?;

            match &send.state {
                LightningSendIntentState::Paid { .. } => {
                    self.state_store
                        .mark_lightning_send_completed(&payment_hash)?;
                    return Ok(Some(Event::PaymentSuccessful {
                        quote_id: quote_id.clone(),
                        details: self.lightning_send_response_with_lookup(
                            &send,
                            false,
                            PaymentIdentifier::QuoteId(quote_id),
                        )?,
                    }));
                }
                LightningSendIntentState::Failed { reason, .. } => {
                    self.state_store
                        .mark_lightning_send_completed(&payment_hash)?;
                    return Ok(Some(Event::PaymentFailed {
                        quote_id,
                        reason: reason.clone(),
                    }));
                }
                _ => {}
            }
        }

        Ok(None)
    }

    fn lightning_send_response_with_lookup(
        &self,
        send: &LightningSendIntentRecord,
        mark_completed: bool,
        payment_lookup_id: PaymentIdentifier,
    ) -> Result<MakePaymentResponse, cdk_common::payment::Error> {
        let (status, payment_proof, total_spent) = match &send.state {
            LightningSendIntentState::Paid {
                fee_sat, preimage, ..
            } => {
                if mark_completed {
                    self.state_store
                        .mark_lightning_send_completed(&send.payment_hash)?;
                }
                (
                    MeltQuoteState::Paid,
                    Some(preimage.clone()),
                    send.amount_sat.saturating_add(*fee_sat),
                )
            }
            LightningSendIntentState::Failed { .. } => (MeltQuoteState::Unpaid, None, 0),
            LightningSendIntentState::Attempting { .. }
            | LightningSendIntentState::Pending { .. }
            | LightningSendIntentState::NeedsReview { .. } => (MeltQuoteState::Pending, None, 0),
        };

        Ok(MakePaymentResponse {
            payment_lookup_id,
            payment_proof,
            status,
            total_spent: Amount::new(total_spent, CurrencyUnit::Sat),
        })
    }

    fn lightning_intent_from_bark_send(
        mut intent: LightningSendIntentRecord,
        state: &bark::actions::lightning::pay::LightningSendState,
    ) -> LightningSendIntentRecord {
        use bark::actions::lightning::pay::LightningSendState;
        match state {
            LightningSendState::Paid(paid) => {
                intent.state = LightningSendIntentState::Paid {
                    fee_sat: intent.estimated_fee_sat,
                    preimage: hex::encode(paid.preimage.as_ref()),
                    paid_at: Self::unix_now(),
                };
            }
            LightningSendState::InProgress(send) => {
                intent.amount_sat = send.payment_amount.to_sat();
                intent.state = LightningSendIntentState::Pending {
                    fee_sat: send.fee.to_sat(),
                    started_at: Self::unix_now(),
                };
            }
            LightningSendState::Unknown => {}
        }
        intent
    }

    fn parse_payment_hash_hex(payment_hash: &str) -> Result<[u8; 32], cdk_common::payment::Error> {
        let bytes = hex::decode(payment_hash).map_err(|e| {
            cdk_common::payment::Error::Custom(format!(
                "Invalid stored payment hash {}: {}",
                payment_hash, e
            ))
        })?;
        bytes.try_into().map_err(|bytes: Vec<u8>| {
            cdk_common::payment::Error::Custom(format!(
                "Invalid stored payment hash length {}",
                bytes.len()
            ))
        })
    }

    fn estimated_lightning_fee_sat(amount_sat: u64) -> u64 {
        std::cmp::max(1, amount_sat / 1000)
    }

    /// Convert bitcoin::Amount to CDK Amount (instance method)
    fn btc_amount_to_cdk(&self, amount: bitcoin::Amount) -> Amount<CurrencyUnit> {
        Amount::new(amount.to_sat(), CurrencyUnit::Sat)
    }

    /// Convert bitcoin::Amount to CDK Amount (static method)
    fn btc_amount_to_cdk_static(amount: bitcoin::Amount) -> Amount<CurrencyUnit> {
        Amount::new(amount.to_sat(), CurrencyUnit::Sat)
    }

    /// Get zero CDK amount
    fn cdk_amount_zero() -> Amount<CurrencyUnit> {
        Amount::new(0, CurrencyUnit::Sat)
    }

    async fn check_lightning_receive(
        &self,
        payment_identifier: PaymentIdentifier,
        payment_hash: PaymentHash,
        mark_reported: bool,
    ) -> Result<Vec<WaitPaymentResponse>, cdk_common::payment::Error> {
        let receive = {
            // Serialize the bark-wallet sqlite/state read against the cosign and poll loop.
            let _wallet_db_guard = self.wallet_db_lock.lock().await;
            self.wallet
                .lightning_receive_status(payment_hash)
                .await
                .map_err(|e| {
                    cdk_common::payment::Error::Custom(format!(
                        "Failed to check receive status: {}",
                        e
                    ))
                })?
        };

        if let Some(receive) = receive {
            if receive.finished_at.is_some() {
                let amount = receive
                    .invoice
                    .amount_milli_satoshis()
                    .map(|msat| self.btc_amount_to_cdk(bitcoin::Amount::from_sat(msat / 1000)))
                    .unwrap_or(Self::cdk_amount_zero());

                let payment_hash_bytes: [u8; 32] = payment_hash.into();
                if mark_reported {
                    self.state_store
                        .mark_lightning_receive_reported(&payment_identifier.to_string())?;
                }
                return Ok(vec![WaitPaymentResponse {
                    payment_identifier,
                    payment_amount: amount,
                    payment_id: hex::encode(payment_hash_bytes),
                }]);
            }
        }

        Ok(vec![])
    }

    fn unix_now() -> u64 {
        SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map(|duration| duration.as_secs())
            .unwrap_or_default()
    }
}

#[async_trait]
impl MintPayment for ArkBackend {
    type Err = cdk_common::payment::Error;

    async fn get_settings(&self) -> Result<SettingsResponse, Self::Err> {
        debug!("Getting Ark wallet settings");
        Ok(SettingsResponse {
            unit: "sat".to_string(),
            bolt11: Some(Bolt11Settings {
                mpp: false,
                amountless: false,
                invoice_description: true,
            }),
            bolt12: None,
            onchain: Some(OnchainSettings {
                confirmations: ONCHAIN_CONFIRMATIONS,
                // Advertise the Ark server's minimum board amount as the minimum on-chain
                // (payjoin board) receive amount. The CDK mint clamps NUT-04 onchain mint quotes
                // to this minimum and rejects sub-minimum quotes at CREATION time with
                // `Error::AmountOutofLimitRange`, before `create_incoming_payment_request` issues a
                // payjoin URI. Without this, a sub-minimum quote would be accepted, paid, and then
                // fail silently in `cosign_and_store_board`.
                min_receive_amount_sat: self.min_board_amount_sat,
                min_send_amount_sat: 1,
            }),
            custom: Default::default(),
        })
    }

    async fn create_incoming_payment_request(
        &self,
        options: IncomingPaymentOptions,
    ) -> Result<CreateIncomingPaymentResponse, Self::Err> {
        debug!("Creating incoming payment request");

        let bolt11_options = match options {
            IncomingPaymentOptions::Bolt11(opts) => Some(opts),
            IncomingPaymentOptions::Onchain(opts) => {
                // PAYJOIN on-ramp: derive a per-quote board user keypair, get the board funding
                // P2TR address/script, start a payjoin v2 receiver session whose receiver output
                // is the board funding script, and return a BIP21+pj URI advertising output
                // substitution ENABLED. We MUST echo the mint-supplied quote_id verbatim.
                let quote_id = opts.quote_id;
                let quote_id_str = quote_id.to_string();

                // Derive + persist a fresh keypair index (re-derivable across restarts via
                // peak_keypair) and the board funding address/expiry for this quote.
                // Serialize the bark-wallet sqlite/state access (keypair derive+store and board
                // funding address derivation) against the cosign and poll loop. Released before the
                // payjoin session / network work below.
                let (user_keypair, keypair_index, board_address, expiry_height) = {
                    let _wallet_db_guard = self.wallet_db_lock.lock().await;
                    let (user_keypair, keypair_index) =
                        self.wallet.derive_store_next_keypair().await.map_err(|e| {
                            cdk_common::payment::Error::Custom(format!(
                                "Failed to derive board keypair: {}",
                                e
                            ))
                        })?;
                    let (board_address, expiry_height) = self
                        .wallet
                        .board_funding_address(&user_keypair)
                        .await
                        .map_err(|e| {
                            cdk_common::payment::Error::Custom(format!(
                                "Failed to derive board funding address: {}",
                                e
                            ))
                        })?;
                    (user_keypair, keypair_index, board_address, expiry_height)
                };
                let board_script = board_address.script_pubkey();
                let board_address_str = board_address.to_string();

                // No-address-reuse invariant (explicit, not incidental): the per-quote board
                // funding script is derived from a freshly advanced, monotonic keypair index
                // (`derive_store_next_keypair`) — never a "next unused" lookup — so it is single-use
                // by construction. We additionally record it in the advertised-scripts guard, which
                // refuses (errors) if this exact script was ever handed out before. A violation here
                // means a reuse bug, so we surface it loudly and abort the quote rather than risk
                // advertising a reused address.
                {
                    let script_hex = hex::encode(board_script.as_bytes());
                    self.payjoin
                        .state
                        .record_advertised_script(&script_hex, &format!("board:{quote_id_str}"))
                        .map_err(|e| {
                            cdk_common::payment::Error::Custom(format!(
                                "no-address-reuse guard rejected board script for quote {quote_id_str}: {e}"
                            ))
                        })?;
                }

                // Start the payjoin session and obtain the advertised URI.
                let bip21_uri = self
                    .payjoin
                    .create_session(&quote_id_str, &board_address)
                    .map_err(|e| {
                        cdk_common::payment::Error::Custom(format!(
                            "Failed to create payjoin session: {}",
                            e
                        ))
                    })?;

                let record = OnRampQuoteRecord {
                    quote_id: quote_id_str.clone(),
                    keypair_index,
                    expiry_height,
                    board_script_hex: hex::encode(board_script.as_bytes()),
                    board_address: board_address_str.clone(),
                    bip21_uri: bip21_uri.clone(),
                };
                self.payjoin
                    .state
                    .put_quote(&record)
                    .map_err(|e| cdk_common::payment::Error::Custom(e.to_string()))?;

                // Also register the board funding address in the legacy receive-address table so
                // the existing detect/finalize crediting machinery treats this board's confirmed
                // funding output as a receive for this quote.
                self.state_store
                    .put_receive_address(&quote_id_str, &board_address_str)?;

                info!(
                    "Created onchain payjoin on-ramp for quote {}: board address {}, expiry {}",
                    quote_id, board_address_str, expiry_height
                );

                // REAL event: the quote (and board address) was genuinely created.
                self.telemetry.emit(
                    OnRampEvent::new(&quote_id_str, OnRampStage::QuoteCreated)
                        .with_board_address(&board_address_str),
                );

                return Ok(CreateIncomingPaymentResponse {
                    request_lookup_id: PaymentIdentifier::QuoteId(quote_id),
                    request: bip21_uri,
                    expiry: None,
                    extra_json: Some(serde_json::json!({
                        "fee_policy": "bark_board_fee_deducted_from_received_amount",
                        "onramp": "payjoin_board",
                        "board_address": board_address_str,
                    })),
                });
            }
            _ => {
                return Err(cdk_common::payment::Error::UnsupportedPaymentOption);
            }
        };
        let bolt11_options = bolt11_options.expect("BOLT11 branch returns Some");

        // Only support sat unit
        if bolt11_options.amount.unit().to_string() != "sat" {
            return Err(cdk_common::payment::Error::UnsupportedUnit);
        }

        // Convert amount to bitcoin::Amount - use to_u64() to get raw value from Amount<()>
        let amount = bitcoin::Amount::from_sat(bolt11_options.amount.to_u64());

        // Generate BOLT11 invoice using bark wallet. Serialize the bark-wallet sqlite/state access
        // against the cosign and poll loop.
        let invoice = {
            let _wallet_db_guard = self.wallet_db_lock.lock().await;
            self.wallet
                .bolt11_invoice(amount, bolt11_options.description)
                .await
                .map_err(|e| {
                    cdk_common::payment::Error::Custom(format!("Failed to create invoice: {}", e))
                })?
        };

        // Extract payment hash from the invoice - bark returns lightning_invoice::Bolt11Invoice
        let payment_hash_bytes: [u8; 32] = *invoice.payment_hash().as_ref();
        let payment_hash_hex = hex::encode(payment_hash_bytes);
        let quote_id = QuoteId::new_uuid();
        self.state_store
            .put_lightning_receive_quote(&quote_id.to_string(), &payment_hash_hex)?;

        // Get expiry - convert Duration to seconds
        let expiry = Some(invoice.expiry_time().as_secs());

        // Convert invoice to string
        let invoice_str = invoice.to_string();

        info!(
            "Created BOLT11 invoice for {} sat, quote_id: {}, payment_hash: {}",
            amount.to_sat(),
            quote_id,
            payment_hash_hex
        );

        Ok(CreateIncomingPaymentResponse {
            request_lookup_id: PaymentIdentifier::QuoteId(quote_id),
            request: invoice_str,
            expiry,
            extra_json: None,
        })
    }

    async fn get_payment_quote(
        &self,
        unit: &CurrencyUnit,
        options: OutgoingPaymentOptions,
    ) -> Result<PaymentQuoteResponse, Self::Err> {
        debug!("Getting payment quote");

        // Only support sat unit
        if unit.to_string() != "sat" {
            return Err(cdk_common::payment::Error::UnsupportedUnit);
        }

        match options {
            OutgoingPaymentOptions::Bolt11(opts) => {
                let invoice = &opts.bolt11;

                let amount_msat = invoice.amount_milli_satoshis().ok_or_else(|| {
                    cdk_common::payment::Error::Custom("Invoice has no amount".to_string())
                })?;
                let amount_sat = amount_msat / 1000;
                let fee_sats = Self::estimated_lightning_fee_sat(amount_sat);

                debug!("Payment quote: {} sat + {} sat fee", amount_sat, fee_sats);

                Ok(PaymentQuoteResponse {
                    request_lookup_id: Some(PaymentIdentifier::QuoteId(opts.quote_id.clone())),
                    amount: Amount::new(amount_sat, CurrencyUnit::Sat),
                    fee: Amount::new(fee_sats, CurrencyUnit::Sat),
                    state: MeltQuoteState::Unpaid,
                    extra_json: None,
                    estimated_blocks: None,
                    fee_options: None,
                })
            }
            OutgoingPaymentOptions::Onchain(opts) => {
                let address = self.parse_bitcoin_address(&opts.address)?;
                let amount_sat = opts.amount.to_u64();
                let amount = bitcoin::Amount::from_sat(amount_sat);
                // Serialize the bark-wallet sqlite/state read against the cosign and poll loop.
                let estimate = {
                    let _wallet_db_guard = self.wallet_db_lock.lock().await;
                    self.wallet
                        .estimate_send_onchain(&address, amount)
                        .await
                        .map_err(|e| {
                            cdk_common::payment::Error::Custom(format!(
                                "Failed to estimate onchain payment: {}",
                                e
                            ))
                        })?
                };
                let fee_sat = estimate.fee.to_sat();
                let fee_options = vec![MeltQuoteOnchainFeeOption {
                    fee_index: ONCHAIN_FEE_INDEX,
                    fee_reserve: Amount::from(fee_sat),
                    estimated_blocks: ONCHAIN_ESTIMATED_BLOCKS,
                }];

                return Ok(PaymentQuoteResponse {
                    request_lookup_id: Some(PaymentIdentifier::QuoteId(opts.quote_id.clone())),
                    amount: Amount::new(amount_sat, CurrencyUnit::Sat),
                    fee: Amount::new(fee_sat, CurrencyUnit::Sat),
                    state: MeltQuoteState::Unpaid,
                    extra_json: None,
                    estimated_blocks: Some(ONCHAIN_ESTIMATED_BLOCKS),
                    fee_options: Some(fee_options),
                });
            }
            _ => Err(cdk_common::payment::Error::UnsupportedPaymentOption),
        }
    }

    async fn make_payment(
        &self,
        unit: &CurrencyUnit,
        options: OutgoingPaymentOptions,
    ) -> Result<MakePaymentResponse, Self::Err> {
        debug!("Making payment");

        // Only support sat unit
        if unit.to_string() != "sat" {
            return Err(cdk_common::payment::Error::UnsupportedUnit);
        }

        let bolt11_options = match options {
            OutgoingPaymentOptions::Bolt11(opts) => opts,
            OutgoingPaymentOptions::Onchain(opts) => {
                if !matches!(opts.fee_index, None | Some(ONCHAIN_FEE_INDEX)) {
                    return Err(cdk_common::payment::Error::Custom(format!(
                        "Unsupported onchain fee_index {:?}",
                        opts.fee_index
                    )));
                }

                let _send_guard = self.onchain_send_lock.lock().await;
                self.reconcile_onchain_sends().await?;

                let quote_id_str = opts.quote_id.to_string();
                if let Some(existing_send) = self.state_store.get_send(&quote_id_str)? {
                    return self.onchain_send_response(&opts.quote_id, &existing_send, false);
                }

                let address = self.parse_bitcoin_address(&opts.address)?;
                let address_str = address.to_string();
                let amount_sat = opts.amount.to_u64();
                let amount = bitcoin::Amount::from_sat(amount_sat);
                // Serialize the bark-wallet sqlite/state read against the cosign and poll loop.
                let estimate = {
                    let _wallet_db_guard = self.wallet_db_lock.lock().await;
                    self.wallet
                        .estimate_send_onchain(&address, amount)
                        .await
                        .map_err(|e| {
                            cdk_common::payment::Error::Custom(format!(
                                "Failed to estimate onchain payment: {}",
                                e
                            ))
                        })?
                };

                if let Some(max_fee) = opts.max_fee_amount.as_ref() {
                    let max_fee_sat = max_fee.clone().to_u64();
                    if estimate.fee.to_sat() > max_fee_sat {
                        return Err(cdk_common::payment::Error::Custom(format!(
                            "Estimated onchain fee {} sat exceeds max fee {} sat",
                            estimate.fee.to_sat(),
                            max_fee_sat
                        )));
                    }
                }

                let fee_sat = estimate.fee.to_sat();
                let mut send_intent = OnchainSendIntentRecord {
                    quote_id: quote_id_str.clone(),
                    address: address_str,
                    amount_sat,
                    state: OnchainSendIntentState::Attempting {
                        attempt: 1,
                        attempt_id: uuid::Uuid::new_v4().to_string(),
                        fee_sat,
                        started_at: Self::unix_now(),
                    },
                };
                self.state_store.put_send(&quote_id_str, &send_intent)?;

                // Serialize the bark-wallet send (sqlite/state mutation) against the cosign and
                // poll loop.
                let send_onchain_result = {
                    let _wallet_db_guard = self.wallet_db_lock.lock().await;
                    self.wallet.send_onchain(address, amount).await
                };
                let txid = match send_onchain_result {
                    Ok(txid) => txid,
                    Err(e) => {
                        let reason = e.to_string();
                        send_intent.state = OnchainSendIntentState::NeedsReview {
                            reason: format!(
                                "Bark send_onchain returned an error after the offboard attempt was started: {}",
                                reason
                            ),
                            fee_sat: Some(fee_sat),
                            failed_at: Self::unix_now(),
                        };
                        self.state_store.put_send(&quote_id_str, &send_intent)?;
                        return Err(cdk_common::payment::Error::Custom(format!(
                            "Failed to send onchain payment: {}",
                            reason
                        )));
                    }
                };

                send_intent.state = OnchainSendIntentState::Broadcast {
                    txid: txid.to_string(),
                    fee_sat,
                    broadcast_at: Self::unix_now(),
                };
                self.state_store.put_send(&quote_id_str, &send_intent)?;

                info!(
                    "Broadcasted onchain payment {} for quote {}",
                    txid, opts.quote_id
                );

                return Ok(MakePaymentResponse {
                    payment_lookup_id: PaymentIdentifier::QuoteId(opts.quote_id),
                    payment_proof: Some(txid.to_string()),
                    status: MeltQuoteState::Pending,
                    total_spent: Amount::new(0, CurrencyUnit::Sat),
                });
            }
            _ => {
                return Err(cdk_common::payment::Error::UnsupportedPaymentOption);
            }
        };

        // bolt11_options.bolt11 is already a parsed invoice
        let invoice = &bolt11_options.bolt11;

        // Extract payment hash
        let payment_hash: [u8; 32] = *invoice.payment_hash().as_ref();
        let payment_hash_hex = hex::encode(payment_hash);
        let payment_lookup_id = PaymentIdentifier::QuoteId(bolt11_options.quote_id.clone());
        let quote_id_str = bolt11_options.quote_id.to_string();

        // Get the amount from the invoice
        let amount_msat = invoice.amount_milli_satoshis().ok_or_else(|| {
            cdk_common::payment::Error::Custom("Invoice has no amount".to_string())
        })?;
        let amount_sat = amount_msat / 1000;
        let estimated_fee_sat = std::cmp::max(1, amount_sat / 1000);

        if let Some(max_fee) = bolt11_options.max_fee_amount.as_ref() {
            let max_fee_sat = max_fee.clone().to_u64();
            if estimated_fee_sat > max_fee_sat {
                return Err(cdk_common::payment::Error::Custom(format!(
                    "Estimated lightning fee {} sat exceeds max fee {} sat",
                    estimated_fee_sat, max_fee_sat
                )));
            }
        }

        let _lightning_send_guard = self.lightning_send_lock.lock().await;
        if let Some((existing_payment_hash, _)) =
            self.state_store.lightning_send_for_quote(&quote_id_str)?
        {
            if let Some(existing_send) = self
                .reconcile_lightning_send(&existing_payment_hash)
                .await?
            {
                return self.lightning_send_response_with_lookup(
                    &existing_send,
                    false,
                    payment_lookup_id.clone(),
                );
            }
        }
        if let Some(existing_send) = self.reconcile_lightning_send(&payment_hash_hex).await? {
            return self.lightning_send_response_with_lookup(
                &existing_send,
                false,
                payment_lookup_id.clone(),
            );
        }

        let invoice_str = invoice.to_string();
        let mut send_intent = LightningSendIntentRecord {
            quote_id: bolt11_options.quote_id.to_string(),
            payment_hash: payment_hash_hex.clone(),
            invoice: invoice_str.clone(),
            amount_sat,
            estimated_fee_sat,
            state: LightningSendIntentState::Attempting {
                attempt: 1,
                attempt_id: uuid::Uuid::new_v4().to_string(),
                started_at: Self::unix_now(),
            },
        };
        self.state_store
            .put_lightning_send(&payment_hash_hex, &send_intent)?;

        // Serialize the bark-wallet pay attempt (sqlite/state mutation) against the cosign and
        // poll loop.
        let pay_result = {
            let _wallet_db_guard = self.wallet_db_lock.lock().await;
            self.wallet
                .pay_lightning_invoice(invoice_str.as_str(), None, false)
                .await
        };
        if let Err(e) = pay_result {
            let reason = e.to_string();
            // Serialize the bark-wallet status read against the cosign and poll loop.
            let recovery_state = {
                let _wallet_db_guard = self.wallet_db_lock.lock().await;
                self.wallet
                    .check_lightning_payment(PaymentHash::from(payment_hash), false)
                    .await
            };
            match recovery_state {
                Ok(state)
                    if !matches!(
                        state,
                        bark::actions::lightning::pay::LightningSendState::Unknown
                    ) =>
                {
                    let recovered = Self::lightning_intent_from_bark_send(send_intent, &state);
                    self.state_store
                        .put_lightning_send(&payment_hash_hex, &recovered)?;
                }
                _ => {
                    send_intent.state = LightningSendIntentState::NeedsReview {
                        reason: format!(
                            "Bark pay_lightning_invoice returned an error after the payment attempt was started: {}",
                            reason
                        ),
                        failed_at: Self::unix_now(),
                    };
                    self.state_store
                        .put_lightning_send(&payment_hash_hex, &send_intent)?;
                }
            }
            return Err(cdk_common::payment::Error::Custom(format!(
                "Failed to pay invoice: {}",
                reason
            )));
        }

        // Serialize the bark-wallet status read against the cosign and poll loop.
        let state = {
            let _wallet_db_guard = self.wallet_db_lock.lock().await;
            self.wallet
                .check_lightning_payment(PaymentHash::from(payment_hash), false)
                .await
                .unwrap_or(bark::actions::lightning::pay::LightningSendState::Unknown)
        };
        let updated_send = Self::lightning_intent_from_bark_send(send_intent, &state);
        self.state_store
            .put_lightning_send(&payment_hash_hex, &updated_send)?;

        info!(
            "Started lightning payment for {} sat, payment_hash: {}",
            amount_sat, payment_hash_hex
        );

        self.lightning_send_response_with_lookup(&updated_send, false, payment_lookup_id)
    }

    async fn wait_payment_event(
        &self,
    ) -> Result<Pin<Box<dyn Stream<Item = Event> + Send>>, Self::Err> {
        debug!("Starting payment event stream");
        self.wait_invoice_active.store(true, Ordering::SeqCst);

        let backend = self.clone();
        let wallet = self.wallet.clone();
        let active = self.wait_invoice_active.clone();

        // Create a stream that polls for incoming payments
        let stream = stream::unfold(
            (backend, wallet, active, false),
            |(backend, wallet, active, _)| async move {
                // Check if we should stop
                if !active.load(Ordering::SeqCst) {
                    return None;
                }

                // Wait for the polling interval
                tokio::time::sleep(Duration::from_secs(5)).await;

                // Serialize the bark-wallet sqlite/state access (claim + pending list) against the
                // cosign and poll loop. Released before the per-receive bookkeeping and the
                // next_* event helpers below (which acquire the lock themselves).
                let pending = {
                    let _wallet_db_guard = backend.wallet_db_lock.lock().await;

                    // Try to claim all lightning receives (non-blocking)
                    if let Err(e) = wallet.try_claim_all_lightning_receives(false).await {
                        debug!("Failed to claim lightning receives: {}", e);
                    }

                    // Get pending lightning receives
                    match wallet.pending_lightning_receives().await {
                        Ok(pending) => pending,
                        Err(e) => {
                            debug!("Failed to get pending receives: {}", e);
                            Vec::new()
                        }
                    }
                };

                // Check for completed receives
                for receive in pending {
                    // If the receive has finished_at set, it's complete
                    if receive.finished_at.is_some() {
                        let payment_hash = receive.payment_hash;
                        let payment_hash_bytes: [u8; 32] = payment_hash.into();
                        let payment_hash_hex = hex::encode(payment_hash_bytes);
                        let payment_identifier = match backend
                            .state_store
                            .lightning_receive_quote_for_hash(&payment_hash_hex)
                        {
                            Ok(Some(quote_id_str)) => match QuoteId::from_str(&quote_id_str) {
                                Ok(quote_id) => PaymentIdentifier::QuoteId(quote_id),
                                Err(e) => {
                                    debug!(
                                        "Invalid stored lightning receive quote id {}: {}",
                                        quote_id_str, e
                                    );
                                    PaymentIdentifier::PaymentHash(payment_hash_bytes)
                                }
                            },
                            Ok(None) => PaymentIdentifier::PaymentHash(payment_hash_bytes),
                            Err(e) => {
                                debug!("Failed to look up lightning receive quote id: {}", e);
                                PaymentIdentifier::PaymentHash(payment_hash_bytes)
                            }
                        };
                        let request_lookup_id = payment_identifier.to_string();
                        match backend
                            .state_store
                            .is_lightning_receive_reported(&request_lookup_id)
                        {
                            Ok(true) => continue,
                            Ok(false) => {}
                            Err(e) => {
                                debug!("Failed to check lightning receive report state: {}", e);
                            }
                        }
                        let amount = receive
                            .invoice
                            .amount_milli_satoshis()
                            .map(|msat| {
                                Self::btc_amount_to_cdk_static(bitcoin::Amount::from_sat(
                                    msat / 1000,
                                ))
                            })
                            .unwrap_or(Self::cdk_amount_zero());

                        if let Err(e) = backend
                            .state_store
                            .mark_lightning_receive_reported(&request_lookup_id)
                        {
                            debug!("Failed to mark lightning receive reported: {}", e);
                        }
                        let event = Event::PaymentReceived(WaitPaymentResponse {
                            payment_identifier,
                            payment_amount: amount,
                            payment_id: payment_hash_hex,
                        });

                        return Some((Some(event), (backend, wallet, active, false)));
                    }
                }

                match backend.next_onchain_receive_event().await {
                    Ok(Some(event)) => {
                        return Some((Some(event), (backend, wallet, active, false)));
                    }
                    Ok(None) => {}
                    Err(e) => {
                        debug!("Failed to process onchain receives: {}", e);
                    }
                }

                match backend.next_lightning_send_event().await {
                    Ok(Some(event)) => {
                        return Some((Some(event), (backend, wallet, active, false)));
                    }
                    Ok(None) => {}
                    Err(e) => {
                        debug!("Failed to process lightning sends: {}", e);
                    }
                }

                match backend.next_onchain_send_event().await {
                    Ok(Some(event)) => {
                        return Some((Some(event), (backend, wallet, active, false)));
                    }
                    Ok(None) => {}
                    Err(e) => {
                        debug!("Failed to process onchain sends: {}", e);
                    }
                }

                Some((None, (backend, wallet, active, false)))
            },
        )
        .filter_map(|event| async move { event });

        Ok(Box::pin(stream))
    }

    async fn check_incoming_payment_status(
        &self,
        payment_identifier: &PaymentIdentifier,
    ) -> Result<Vec<WaitPaymentResponse>, Self::Err> {
        debug!("Checking incoming payment status");

        if let PaymentIdentifier::QuoteId(quote_id) = payment_identifier {
            if let Some(payment_hash) = self
                .state_store
                .get_lightning_receive_hash(&quote_id.to_string())?
            {
                let payment_hash = Self::parse_payment_hash_hex(&payment_hash)?;
                return self
                    .check_lightning_receive(
                        payment_identifier.clone(),
                        PaymentHash::from(payment_hash),
                        true,
                    )
                    .await;
            }
            return self.check_onchain_receive(quote_id, true).await;
        }

        // Extract payment hash from identifier
        let payment_hash = match payment_identifier {
            PaymentIdentifier::PaymentHash(hash) => PaymentHash::from(*hash),
            _ => {
                return Err(cdk_common::payment::Error::Custom(
                    "Unsupported payment identifier type".to_string(),
                ));
            }
        };

        self.check_lightning_receive(payment_identifier.clone(), payment_hash, true)
            .await
    }

    async fn check_outgoing_payment(
        &self,
        payment_identifier: &PaymentIdentifier,
    ) -> Result<MakePaymentResponse, Self::Err> {
        debug!("Checking outgoing payment");

        if let PaymentIdentifier::QuoteId(quote_id) = payment_identifier {
            if let Some(response) = self.check_onchain_send(quote_id, true).await? {
                return Ok(response);
            }

            let quote_id_str = quote_id.to_string();
            if let Some((payment_hash, _)) =
                self.state_store.lightning_send_for_quote(&quote_id_str)?
            {
                if let Some(send) = self.reconcile_lightning_send(&payment_hash).await? {
                    return self.lightning_send_response_with_lookup(
                        &send,
                        true,
                        PaymentIdentifier::QuoteId(quote_id.clone()),
                    );
                }
            }

            return Err(cdk_common::payment::Error::Custom(format!(
                "No outgoing payment found for quote {}",
                quote_id
            )));
        }

        Err(cdk_common::payment::Error::Custom(
            "Outgoing payment status must be checked by quote id".to_string(),
        ))
    }

    fn is_payment_event_stream_active(&self) -> bool {
        self.wait_invoice_active.load(Ordering::SeqCst)
    }

    fn cancel_payment_event_stream(&self) {
        self.wait_invoice_active.store(false, Ordering::SeqCst);
    }
}
