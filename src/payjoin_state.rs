//! redb-backed persistence for the on-chain -> ecash payjoin on-ramp.
//!
//! Two concerns live here:
//!
//! 1. A [`SessionPersister`] implementation (`QuoteSessionPersister`) that stores the
//!    append-only payjoin v2 [`SessionEvent`] log for a single quote, keyed by quote id.
//!    rust-payjoin drives its receiver state machine by replaying this event log, so we
//!    persist each `SessionEvent` as a JSON blob in an ordered redb table.
//!
//! 2. A `seen_inputs` table used as the anti-probing store for
//!    `check_no_inputs_seen_before` across all quotes.
//!
//! We also persist a small `OnRampQuoteRecord` per quote that links the cdk quote id to
//! the board keypair derivation index, expiry height, board script/address, and the
//! advertised BIP21 URI so the flow survives restarts.

use std::sync::Arc;

use payjoin::receive::v2::SessionEvent;
use redb::{Database, ReadableDatabase, ReadableTable, TableDefinition};
use serde::{Deserialize, Serialize};

/// quote_id -> JSON(OnRampQuoteRecord)
const ONRAMP_QUOTES_TABLE: TableDefinition<&str, &str> = TableDefinition::new("onramp_quotes");
/// "<quote_id>:<seq>" -> JSON(SessionEvent). Ordered by insertion sequence per quote.
const ONRAMP_SESSION_EVENTS_TABLE: TableDefinition<&str, &str> =
    TableDefinition::new("onramp_session_events");
/// "<quote_id>" -> "1" once the session is closed.
const ONRAMP_SESSION_CLOSED_TABLE: TableDefinition<&str, &str> =
    TableDefinition::new("onramp_session_closed");
/// outpoint string -> "1": every sender input we have ever seen (anti-probing).
const ONRAMP_SEEN_INPUTS_TABLE: TableDefinition<&str, &str> =
    TableDefinition::new("onramp_seen_inputs");
/// outpoint string -> quote_id: mint UTXOs currently LOCKED to an in-flight board session, so
/// concurrent boards never select (and double-spend) the same UTXO across the multi-input set.
const ONRAMP_LOCKED_UTXOS_TABLE: TableDefinition<&str, &str> =
    TableDefinition::new("onramp_locked_utxos");
/// script_pubkey hex -> context string: every script the mint has EVER advertised/derived (board
/// funding scripts and change scripts). Backs the hard no-address-reuse invariant — derivation
/// refuses to hand out a script already recorded here.
const ONRAMP_ADVERTISED_SCRIPTS_TABLE: TableDefinition<&str, &str> =
    TableDefinition::new("onramp_advertised_scripts");

/// Per-quote bookkeeping for the on-ramp.
#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct OnRampQuoteRecord {
    pub quote_id: String,
    /// Bark keypair derivation index used as the per-quote board user key.
    pub keypair_index: u32,
    /// VTXO expiry height passed to `cosign_and_store_board`.
    pub expiry_height: u32,
    /// The board funding P2TR script (hex).
    pub board_script_hex: String,
    /// The board funding address (string form).
    pub board_address: String,
    /// The BIP21 + pj URI advertised to the sender (output substitution ENABLED).
    pub bip21_uri: String,
}

/// State store for the on-ramp payjoin flow. Cheaply clonable (shares the redb handle).
#[derive(Clone)]
pub struct OnRampStateStore {
    db: Arc<Database>,
}

impl OnRampStateStore {
    pub fn open(db: Arc<Database>) -> anyhow::Result<Self> {
        let store = Self { db };
        store.init()?;
        Ok(store)
    }

    fn init(&self) -> anyhow::Result<()> {
        let tx = self.db.begin_write()?;
        {
            tx.open_table(ONRAMP_QUOTES_TABLE)?;
            tx.open_table(ONRAMP_SESSION_EVENTS_TABLE)?;
            tx.open_table(ONRAMP_SESSION_CLOSED_TABLE)?;
            tx.open_table(ONRAMP_SEEN_INPUTS_TABLE)?;
            tx.open_table(ONRAMP_LOCKED_UTXOS_TABLE)?;
            tx.open_table(ONRAMP_ADVERTISED_SCRIPTS_TABLE)?;
        }
        tx.commit()?;
        Ok(())
    }

    fn err(e: impl std::fmt::Display) -> StorageError {
        StorageError(format!("onramp state store error: {e}"))
    }

    pub fn put_quote(&self, record: &OnRampQuoteRecord) -> Result<(), StorageError> {
        let tx = self.db.begin_write().map_err(Self::err)?;
        {
            let mut table = tx.open_table(ONRAMP_QUOTES_TABLE).map_err(Self::err)?;
            let value = serde_json::to_string(record).map_err(Self::err)?;
            table
                .insert(record.quote_id.as_str(), value.as_str())
                .map_err(Self::err)?;
        }
        tx.commit().map_err(Self::err)
    }

    pub fn get_quote(&self, quote_id: &str) -> Result<Option<OnRampQuoteRecord>, StorageError> {
        let tx = self.db.begin_read().map_err(Self::err)?;
        let table = tx.open_table(ONRAMP_QUOTES_TABLE).map_err(Self::err)?;
        table
            .get(quote_id)
            .map_err(Self::err)?
            .map(|v| serde_json::from_str(v.value()).map_err(Self::err))
            .transpose()
    }

    pub fn all_quotes(&self) -> Result<Vec<OnRampQuoteRecord>, StorageError> {
        let tx = self.db.begin_read().map_err(Self::err)?;
        let table = tx.open_table(ONRAMP_QUOTES_TABLE).map_err(Self::err)?;
        let mut out = Vec::new();
        for entry in table.iter().map_err(Self::err)? {
            let (_, v) = entry.map_err(Self::err)?;
            out.push(serde_json::from_str(v.value()).map_err(Self::err)?);
        }
        Ok(out)
    }

    /// Remove a quote from the poll set. Prunes abandoned/never-paid on-ramp sessions so they
    /// stop consuming the sequential poll budget (~5s OHTTP each). Only touches the quotes table;
    /// the session event log is left as harmless orphan data.
    pub fn remove_quote(&self, quote_id: &str) -> Result<(), StorageError> {
        let tx = self.db.begin_write().map_err(Self::err)?;
        {
            let mut table = tx.open_table(ONRAMP_QUOTES_TABLE).map_err(Self::err)?;
            table.remove(quote_id).map_err(Self::err)?;
        }
        tx.commit().map_err(Self::err)
    }

    /// Anti-probing: record a sender input outpoint as seen.
    pub fn mark_input_seen(&self, outpoint: &str) -> Result<(), StorageError> {
        let tx = self.db.begin_write().map_err(Self::err)?;
        {
            let mut table = tx.open_table(ONRAMP_SEEN_INPUTS_TABLE).map_err(Self::err)?;
            table.insert(outpoint, "1").map_err(Self::err)?;
        }
        tx.commit().map_err(Self::err)
    }

    pub fn is_input_seen(&self, outpoint: &str) -> Result<bool, StorageError> {
        let tx = self.db.begin_read().map_err(Self::err)?;
        let table = tx.open_table(ONRAMP_SEEN_INPUTS_TABLE).map_err(Self::err)?;
        Ok(table.get(outpoint).map_err(Self::err)?.is_some())
    }

    // --- UTXO lock registry (multi-input boards) -------------------------------------------

    /// Returns the set of mint UTXO outpoints currently locked to any in-flight board session.
    pub fn locked_utxos(&self) -> Result<std::collections::HashSet<String>, StorageError> {
        let tx = self.db.begin_read().map_err(Self::err)?;
        let table = tx.open_table(ONRAMP_LOCKED_UTXOS_TABLE).map_err(Self::err)?;
        let mut out = std::collections::HashSet::new();
        for entry in table.iter().map_err(Self::err)? {
            let (k, _) = entry.map_err(Self::err)?;
            out.insert(k.value().to_string());
        }
        Ok(out)
    }

    /// Lock a set of mint UTXO outpoints to `quote_id` for the duration of a board session.
    /// Idempotent per outpoint (re-locking by the same quote is a no-op overwrite).
    pub fn lock_utxos(&self, quote_id: &str, outpoints: &[String]) -> Result<(), StorageError> {
        let tx = self.db.begin_write().map_err(Self::err)?;
        {
            let mut table = tx.open_table(ONRAMP_LOCKED_UTXOS_TABLE).map_err(Self::err)?;
            for outpoint in outpoints {
                table
                    .insert(outpoint.as_str(), quote_id)
                    .map_err(Self::err)?;
            }
        }
        tx.commit().map_err(Self::err)
    }

    /// Release every UTXO lock held by `quote_id` (e.g. once its board is cosigned/stored or the
    /// session terminates). Safe to call repeatedly.
    pub fn unlock_utxos_for_quote(&self, quote_id: &str) -> Result<(), StorageError> {
        let to_remove: Vec<String> = {
            let tx = self.db.begin_read().map_err(Self::err)?;
            let table = tx.open_table(ONRAMP_LOCKED_UTXOS_TABLE).map_err(Self::err)?;
            let mut v = Vec::new();
            for entry in table.iter().map_err(Self::err)? {
                let (k, val) = entry.map_err(Self::err)?;
                if val.value() == quote_id {
                    v.push(k.value().to_string());
                }
            }
            v
        };
        if to_remove.is_empty() {
            return Ok(());
        }
        let tx = self.db.begin_write().map_err(Self::err)?;
        {
            let mut table = tx.open_table(ONRAMP_LOCKED_UTXOS_TABLE).map_err(Self::err)?;
            for outpoint in &to_remove {
                table.remove(outpoint.as_str()).map_err(Self::err)?;
            }
        }
        tx.commit().map_err(Self::err)
    }

    // --- No-address-reuse invariant (advertised scripts guard) -----------------------------

    /// Returns true if `script_hex` was EVER advertised/derived by the mint before.
    pub fn is_script_advertised(&self, script_hex: &str) -> Result<bool, StorageError> {
        let tx = self.db.begin_read().map_err(Self::err)?;
        let table = tx
            .open_table(ONRAMP_ADVERTISED_SCRIPTS_TABLE)
            .map_err(Self::err)?;
        Ok(table.get(script_hex).map_err(Self::err)?.is_some())
    }

    /// Record `script_hex` as advertised/derived, with a free-form `context` (e.g. the quote id
    /// and role: "board:<quote>" or "change:<quote>"). Returns an error if the script was already
    /// recorded — the caller treats this as a hard no-address-reuse violation.
    pub fn record_advertised_script(
        &self,
        script_hex: &str,
        context: &str,
    ) -> Result<(), StorageError> {
        if self.is_script_advertised(script_hex)? {
            return Err(StorageError(format!(
                "no-address-reuse violation: script {script_hex} was already advertised"
            )));
        }
        let tx = self.db.begin_write().map_err(Self::err)?;
        {
            let mut table = tx
                .open_table(ONRAMP_ADVERTISED_SCRIPTS_TABLE)
                .map_err(Self::err)?;
            table.insert(script_hex, context).map_err(Self::err)?;
        }
        tx.commit().map_err(Self::err)
    }

    /// Build a [`SessionPersister`] scoped to a single quote's event log.
    pub fn session_persister(&self, quote_id: &str) -> QuoteSessionPersister {
        QuoteSessionPersister {
            db: self.db.clone(),
            quote_id: quote_id.to_string(),
        }
    }

    /// Returns true if the named session already has at least one persisted event.
    pub fn session_exists(&self, quote_id: &str) -> Result<bool, StorageError> {
        let tx = self.db.begin_read().map_err(Self::err)?;
        let table = tx
            .open_table(ONRAMP_SESSION_EVENTS_TABLE)
            .map_err(Self::err)?;
        let prefix = format!("{quote_id}:");
        for entry in table.iter().map_err(Self::err)? {
            let (k, _) = entry.map_err(Self::err)?;
            if k.value().starts_with(&prefix) {
                return Ok(true);
            }
        }
        Ok(false)
    }
}

/// Storage error type for the persister; satisfies the `SessionPersister` bound
/// (`std::error::Error + Send + Sync + 'static`).
#[derive(Debug)]
pub struct StorageError(pub String);

impl std::fmt::Display for StorageError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", self.0)
    }
}

impl std::error::Error for StorageError {}

/// A [`SessionPersister`] backed by redb, scoped to one quote's session event log.
///
/// Events are stored under keys `"<quote_id>:<zero-padded-seq>"` so that `load()` returns
/// them in insertion order (redb iterates keys in lexicographic order).
pub struct QuoteSessionPersister {
    db: Arc<Database>,
    quote_id: String,
}

impl QuoteSessionPersister {
    fn err(e: impl std::fmt::Display) -> StorageError {
        StorageError(format!("onramp session persister error: {e}"))
    }

    fn next_seq(&self) -> Result<u64, StorageError> {
        let tx = self.db.begin_read().map_err(Self::err)?;
        let table = tx
            .open_table(ONRAMP_SESSION_EVENTS_TABLE)
            .map_err(Self::err)?;
        let prefix = format!("{}:", self.quote_id);
        let mut count = 0u64;
        for entry in table.iter().map_err(Self::err)? {
            let (k, _) = entry.map_err(Self::err)?;
            if k.value().starts_with(&prefix) {
                count += 1;
            }
        }
        Ok(count)
    }
}

impl payjoin::persist::SessionPersister for QuoteSessionPersister {
    type InternalStorageError = StorageError;
    type SessionEvent = SessionEvent;

    fn save_event(&self, event: Self::SessionEvent) -> Result<(), Self::InternalStorageError> {
        let seq = self.next_seq()?;
        let key = format!("{}:{:012}", self.quote_id, seq);
        let value = serde_json::to_string(&event).map_err(Self::err)?;
        let tx = self.db.begin_write().map_err(Self::err)?;
        {
            let mut table = tx
                .open_table(ONRAMP_SESSION_EVENTS_TABLE)
                .map_err(Self::err)?;
            table
                .insert(key.as_str(), value.as_str())
                .map_err(Self::err)?;
        }
        tx.commit().map_err(Self::err)
    }

    fn load(
        &self,
    ) -> Result<Box<dyn Iterator<Item = Self::SessionEvent>>, Self::InternalStorageError> {
        let tx = self.db.begin_read().map_err(Self::err)?;
        let table = tx
            .open_table(ONRAMP_SESSION_EVENTS_TABLE)
            .map_err(Self::err)?;
        let prefix = format!("{}:", self.quote_id);
        let mut events = Vec::new();
        for entry in table.iter().map_err(Self::err)? {
            let (k, v) = entry.map_err(Self::err)?;
            if k.value().starts_with(&prefix) {
                let event: SessionEvent = serde_json::from_str(v.value()).map_err(Self::err)?;
                events.push(event);
            }
        }
        Ok(Box::new(events.into_iter()))
    }

    fn close(&self) -> Result<(), Self::InternalStorageError> {
        let tx = self.db.begin_write().map_err(Self::err)?;
        {
            let mut table = tx
                .open_table(ONRAMP_SESSION_CLOSED_TABLE)
                .map_err(Self::err)?;
            table
                .insert(self.quote_id.as_str(), "1")
                .map_err(Self::err)?;
        }
        tx.commit().map_err(Self::err)
    }
}
