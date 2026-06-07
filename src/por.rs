//! Proof-of-Reserves PROVER + Nostr publisher for the your-mint.example mint.
//!
//! HONEST FRAMING: this produces a **proof of reserves** — a cryptographic LOWER
//! BOUND on the assets the mint controls in live Ark VTXOs as of a stamped Bitcoin
//! block. It is NOT a proof of solvency (liabilities are out of scope). See
//! `bark-audit/SELF_SPEND_POR.md`.
//!
//! How it works (the arkoor self-spend, SELF_SPEND_POR.md §3): for each spendable
//! reserve VTXO we arkoor-spend it back to a STABLE, wallet-controlled attestation
//! address (a fixed key index — see [`resolve_attest_index`]). The returned finalized
//! `Vtxo<Full>` carries the server's fully-aggregated MuSig cosignature in its genesis
//! chain (NORDIC-POR-CONFIRMED-FACTS §3), so it validates standalone. We serialize that
//! VTXO, embed its on-chain anchor tx, and assemble + sign the bundle.
//!
//! KEY BINDING (the verifier's self-dest check, `verifier/src/lib.rs` ~line 262):
//! `owner == signer == pinned`. The arkoor self-spend OUTPUT is owned by the wallet's
//! attestation keypair at the fixed index; we sign the bundle's identity sig (and the
//! Nostr event) with THAT SAME keypair, and set `mint_identity_pubkey` to its x-only
//! pubkey. Because the output owner, the bundle signer, and the pinned identity are all
//! one key, the verifier's "the self-spent funds went BACK to the mint" check holds.
//! The index is STABLE (re-derivable next cycle), so the attestation address — and thus
//! the pinned identity — does not rotate.
//!
//! All of this is ENV-GATED OFF by default — building an attestation moves reserve
//! VTXOs (free, value-preserving self-spends), so nothing here runs unless explicitly
//! enabled. See `main.rs` for the flags.

use std::path::PathBuf;
use std::time::{SystemTime, UNIX_EPOCH};

use anyhow::{anyhow, bail, Context, Result};

use ark::bitcoin::hashes::{sha256, Hash};
use ark::bitcoin::secp256k1::{Keypair, Message, Secp256k1};
use ark::bitcoin::{consensus, Amount};
use ark::{ProtocolEncoding, Vtxo};

use ark_audit_shared::{
    Anchor, AsOfBlock, AttestationBundle, ReserveEntry, POR_FORMAT_V1,
};

/// Pinned mint id (the addressable Nostr `d`-tag and the bundle's `mint_id`).
pub const MINT_ID: &str = "your-mint.example";

/// Second's mainnet Ark server cosign pubkey (ArkInfo field 2, CONFIRMED —
/// NORDIC-POR-CONFIRMED-FACTS §1). Informational in the bundle; the verifier pins
/// this independently.
pub const PINNED_SECOND_PUBKEY: &str =
    "0375b2e4f6abe5b00736359de211c35d9e72b615e5fd424d8ad1e68a8b300b97b5";

/// Default Nostr relays to publish to. nordic's own relay write-allowlists publishers
/// (the mint's pubkey must be on its `pubkey_whitelist`); the public defaults are open.
pub const DEFAULT_NOSTR_RELAYS: &[&str] = &[
    "wss://relay.damus.io",
    "wss://nos.lol",
    "wss://relay.primal.net",
];

// ── stable attestation key (wallet-derived, the arkoor output owner) ──────────

/// The attest pubkey as x-only hex (32-byte / 64 hex) — what goes into
/// `bundle.mint_identity_pubkey` and what the bundle signature verifies against.
/// This is the x-only of the wallet's attestation keypair (= the arkoor output owner).
pub fn attest_pubkey_xonly_hex(keypair: &Keypair) -> String {
    let (xonly, _parity) = keypair.x_only_public_key();
    hex::encode(xonly.serialize())
}

/// File that persists the STABLE attestation key index across attestation cycles, so
/// the attestation address (and thus the pinned mint identity) never rotates. Path
/// `~/secrets/por-attest.index` (env `POR_ATTEST_INDEX` overrides the whole resolution).
fn attest_index_file() -> PathBuf {
    if let Ok(home) = std::env::var("HOME") {
        PathBuf::from(home).join("secrets").join("por-attest.index")
    } else {
        PathBuf::from("secrets/por-attest.index")
    }
}

/// Resolve the STABLE wallet key index used for the attestation address.
///
/// The arkoor self-spend OUTPUT must be owned by a key the prover can SIGN with, at a
/// FIXED index so it is re-spendable every cycle (NOT the rotating `new_address`). bark
/// only lets us *store* the `last+1` index (`derive_store_next_keypair`), and
/// `peek_address`/`peek_keypair` require the index to already be stored. So:
///   1. env `POR_ATTEST_INDEX` (decimal u32) wins — the operator pins a known index.
///   2. else the file `~/secrets/por-attest.index` (decimal u32, trimmed).
///   3. else BOOTSTRAP: call `new_address_with_index()` ONCE to derive+store a fresh
///      index, persist it to the file, and reuse it forever after.
/// In all cases the returned index's keypair is guaranteed stored in the wallet DB
/// (bootstrap stores it; for 1/2 we verify via `peek_keypair`).
///
/// Returns the index; the caller derives the keypair/address from it.
async fn resolve_attest_index(wallet: &bark::Wallet) -> Result<u32> {
    // 1. explicit env pin
    if let Ok(v) = std::env::var("POR_ATTEST_INDEX") {
        let idx: u32 = v.trim().parse().context("POR_ATTEST_INDEX must be a u32")?;
        wallet.peek_keypair(idx).await.with_context(|| {
            format!(
                "POR_ATTEST_INDEX={idx} is not a derived/stored wallet key; \
                 derive it first (omit the env var to bootstrap a fresh one)"
            )
        })?;
        return Ok(idx);
    }

    // 2. persisted file pin
    let path = attest_index_file();
    if let Ok(s) = std::fs::read_to_string(&path) {
        let s = s.trim();
        if !s.is_empty() {
            let idx: u32 = s
                .parse()
                .with_context(|| format!("{} must contain a u32", path.display()))?;
            wallet.peek_keypair(idx).await.with_context(|| {
                format!("persisted attest index {idx} not stored in wallet DB")
            })?;
            return Ok(idx);
        }
    }

    // 3. bootstrap: derive+store a fresh stable index and persist it.
    let (_addr, idx) = wallet
        .new_address_with_index()
        .await
        .context("bootstrap stable attestation index (new_address_with_index)")?;
    if let Some(dir) = path.parent() {
        std::fs::create_dir_all(dir).with_context(|| format!("mkdir -p {}", dir.display()))?;
    }
    std::fs::write(&path, idx.to_string())
        .with_context(|| format!("persist attest index to {}", path.display()))?;
    tracing::warn!(
        "PoR: bootstrapped STABLE attestation index {idx} (persisted to {}); \
         pin the verifier's mint identity to this key's x-only pubkey",
        path.display()
    );
    Ok(idx)
}

// ── BIP340 bundle signing ────────────────────────────────────────────────────

/// Sign a bundle's canonical preimage with the attest key (BIP340 Schnorr over
/// `sha256(bundle.canonical())`). Sets `bundle.signature`. Matches the verifier's
/// `verify_identity_sig` byte-for-byte (same `canonical()` from `ark_audit_shared`).
pub fn sign_bundle(bundle: &mut AttestationBundle, keypair: &Keypair) {
    let digest = sha256::Hash::hash(&bundle.canonical());
    let msg = Message::from_digest(digest.to_byte_array());
    // no_aux_rand keeps signing deterministic and avoids the rng global-context feature.
    let sig = Secp256k1::new().sign_schnorr_no_aux_rand(&msg, keypair);
    bundle.signature = Some(hex::encode(sig.serialize()));
}

// ── esplora freshness tip (independent block anchor) ─────────────────────────

/// `as_of_block` from esplora: the current tip height + its block hash. `base` is the
/// esplora API base (e.g. `https://mempool.space/api`).
pub async fn fetch_as_of_block(base: &str) -> Result<AsOfBlock> {
    let base = base.trim_end_matches('/');
    let client = reqwest::Client::builder()
        .timeout(std::time::Duration::from_secs(30))
        .build()
        .context("build esplora http client")?;

    let height: u32 = client
        .get(format!("{base}/blocks/tip/height"))
        .send()
        .await
        .context("GET tip height")?
        .error_for_status()
        .context("tip height status")?
        .text()
        .await
        .context("tip height body")?
        .trim()
        .parse()
        .context("parse tip height")?;

    let hash = client
        .get(format!("{base}/blocks/tip/hash"))
        .send()
        .await
        .context("GET tip hash")?
        .error_for_status()
        .context("tip hash status")?
        .text()
        .await
        .context("tip hash body")?
        .trim()
        .to_string();

    Ok(AsOfBlock { height, hash })
}

// ── the prover ────────────────────────────────────────────────────────────────

/// Result of building an attestation: the signed bundle + a few derived figures for
/// the ledger / Nostr summary.
pub struct AttestationResult {
    pub bundle: AttestationBundle,
    pub bundle_json: String,
    pub bundle_sha256_hex: String,
    /// The wallet attestation keypair that owns the arkoor outputs and signed the
    /// bundle. Reused to sign the Nostr events (same secp256k1 key works for both).
    pub attest_key: Keypair,
}

/// Build a signed proof-of-reserves bundle for the mint's current reserve.
///
/// For each spendable reserve VTXO: arkoor self-spend it to the STABLE wallet
/// attestation address (fixed key index — re-spendable next cycle, NOT a rotating
/// `new_address`); the returned finalized destination `Vtxo<Full>` (full aggregated
/// MuSig cosig) is what gets serialized into the bundle. We embed the on-chain anchor
/// tx so the verifier can validate without esplora (live unexited reserve VTXOs anchor
/// to unbroadcast txs — NORDIC-POR-CONFIRMED-FACTS §5).
///
/// The bundle's identity sig is signed with the SAME wallet attestation keypair that
/// OWNS those outputs, and `mint_identity_pubkey` is set to its x-only pubkey — so the
/// verifier's `owner == signer == pinned` self-dest check holds (the funds provably went
/// back to the mint). The keypair is returned in [`AttestationResult`] so the caller can
/// reuse it to sign the Nostr events.
///
/// CALLER MUST hold the wallet sqlite lock (this performs self-spend arkoors).
pub async fn build_attestation(
    wallet: &bark::Wallet,
    esplora_base: &str,
) -> Result<AttestationResult> {
    // Resolve the STABLE attestation key index + derive its keypair and address. This
    // key OWNS every arkoor output below and SIGNS the bundle — owner == signer.
    let attest_index = resolve_attest_index(wallet)
        .await
        .context("resolve stable attestation index")?;
    let attest_key = wallet
        .peek_keypair(attest_index)
        .await
        .with_context(|| format!("derive attestation keypair at index {attest_index}"))?;
    let attest_addr = wallet
        .peek_address(attest_index)
        .await
        .with_context(|| format!("derive attestation address at index {attest_index}"))?;

    let reserve = wallet
        .spendable_vtxos()
        .await
        .context("enumerate spendable reserve vtxos")?;

    tracing::info!(
        "PoR: building attestation over {} spendable reserve VTXO(s) to stable index {} (pubkey {})",
        reserve.len(),
        attest_index,
        attest_pubkey_xonly_hex(&attest_key),
    );

    let mut entries: Vec<ReserveEntry> = Vec::with_capacity(reserve.len());
    let mut total_sat: u64 = 0;

    for wv in &reserve {
        // `wv.vtxo` is a Vtxo<Bare> (no genesis) — cannot be serialized into a bundle.
        // We self-spend it to the STABLE wallet attestation address; the returned
        // finalized Vtxo<Full> (the arkoor DESTINATION output) carries the full genesis
        // chain incl. the server cosig, and is OWNED by `attest_key`. NORDIC-POR §3.
        let amount: Amount = wv.vtxo.amount();

        let created: Vec<Vtxo> = wallet
            .send_arkoor_payment(&attest_addr, amount)
            .await
            .with_context(|| {
                format!("self-spend arkoor for reserve vtxo {}", wv.vtxo.id())
            })?;

        // `created` is the DESTINATION output(s) (not change). For a self-spend of the
        // full input amount there is exactly one destination output at full value.
        let out = created
            .into_iter()
            .next()
            .ok_or_else(|| anyhow!("self-spend returned no destination vtxo"))?;

        // pin-check the embedded server pubkey (defence in depth; the verifier re-checks).
        let embedded = out.server_pubkey().to_string();
        if embedded != PINNED_SECOND_PUBKEY {
            bail!(
                "self-spend output embeds server pubkey {} != pinned Second key {} — refusing",
                embedded,
                PINNED_SECOND_PUBKEY
            );
        }

        let anchor = out.chain_anchor();
        let anchor_txid = anchor.txid;

        // Embed the raw anchor tx. Fetch it via the wallet's chain source. If the
        // anchor tx is not retrievable (truly unbroadcast), we cannot produce a
        // verifiable entry for this coin — fail loudly rather than emit an
        // unverifiable bundle.
        let anchor_tx = wallet
            .chain()
            .get_tx(&anchor_txid)
            .await
            .with_context(|| format!("fetch anchor tx {anchor_txid}"))?
            .ok_or_else(|| {
                anyhow!(
                    "anchor tx {anchor_txid} not retrievable (unbroadcast); cannot embed \
                     a verifiable anchor for vtxo {}",
                    out.id()
                )
            })?;
        let anchor_tx_hex = hex::encode(consensus::encode::serialize(&anchor_tx));

        let amount_sat = out.amount().to_sat();
        total_sat = total_sat
            .checked_add(amount_sat)
            .ok_or_else(|| anyhow!("reserve total overflow"))?;

        entries.push(ReserveEntry {
            vtxo_id: out.id().to_string(),
            amount_sat,
            anchor: Anchor {
                txid: anchor_txid.to_string(),
                vout: anchor.vout,
                block_height: 0, // informational; the verifier re-derives + confirms on-chain
            },
            vtxo_hex: out.serialize_hex(),
            anchor_tx_hex,
        });
    }

    let as_of_block = fetch_as_of_block(esplora_base)
        .await
        .context("fetch as_of_block from esplora tip")?;

    let now = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0);

    let mut bundle = AttestationBundle {
        format: POR_FORMAT_V1.to_string(),
        mint_id: MINT_ID.to_string(),
        mint_identity_pubkey: attest_pubkey_xonly_hex(&attest_key),
        ark_server_pubkey: PINNED_SECOND_PUBKEY.to_string(),
        as_of_block,
        reserve: entries,
        total_reserve_sat: total_sat,
        time: now,
        signature: None,
    };

    sign_bundle(&mut bundle, &attest_key);

    let bundle_json = serde_json::to_string(&bundle).context("serialize bundle JSON")?;
    let bundle_sha256_hex = hex::encode(sha256::Hash::hash(bundle_json.as_bytes()).to_byte_array());

    tracing::info!(
        "PoR: attestation built — {} sat across {} VTXO(s), as of block {} ({})",
        bundle.total_reserve_sat,
        bundle.reserve.len(),
        bundle.as_of_block.height,
        bundle.as_of_block.hash,
    );

    Ok(AttestationResult { bundle, bundle_json, bundle_sha256_hex, attest_key })
}

// ── outputs: file (for /audit/latest.json) + ledger jsonl ────────────────────

/// Write the bundle JSON to a file (for serving at `/audit/latest.json`). Path from
/// env `POR_BUNDLE_PATH`, default `~/mint/audit/latest.json`.
pub fn write_bundle_file(json: &str) -> Result<PathBuf> {
    let path = std::env::var("POR_BUNDLE_PATH")
        .map(PathBuf::from)
        .unwrap_or_else(|_| {
            let home = std::env::var("HOME").unwrap_or_else(|_| ".".to_string());
            PathBuf::from(home).join("mint").join("audit").join("latest.json")
        });
    if let Some(dir) = path.parent() {
        std::fs::create_dir_all(dir).with_context(|| format!("mkdir -p {}", dir.display()))?;
    }
    std::fs::write(&path, json).with_context(|| format!("write {}", path.display()))?;
    Ok(path)
}

/// Append a one-line summary to the attestations ledger jsonl. Path from env
/// `POR_LEDGER_PATH`, default `~/mint/ledger/attestations.jsonl`.
pub fn append_ledger(
    result: &AttestationResult,
    nostr_event_id: Option<&str>,
    url: Option<&str>,
) -> Result<PathBuf> {
    let path = std::env::var("POR_LEDGER_PATH")
        .map(PathBuf::from)
        .unwrap_or_else(|_| {
            let home = std::env::var("HOME").unwrap_or_else(|_| ".".to_string());
            PathBuf::from(home).join("mint").join("ledger").join("attestations.jsonl")
        });
    if let Some(dir) = path.parent() {
        std::fs::create_dir_all(dir).with_context(|| format!("mkdir -p {}", dir.display()))?;
    }
    let now = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0);
    let line = serde_json::json!({
        "time": now,
        "block": result.bundle.as_of_block.height,
        "total_reserve_sat": result.bundle.total_reserve_sat,
        "bundle_sha256": result.bundle_sha256_hex,
        "nostr_event_id": nostr_event_id,
        "url": url,
    });
    use std::io::Write;
    let mut f = std::fs::OpenOptions::new()
        .create(true)
        .append(true)
        .open(&path)
        .with_context(|| format!("open {}", path.display()))?;
    writeln!(f, "{}", serde_json::to_string(&line)?)
        .with_context(|| format!("append {}", path.display()))?;
    Ok(path)
}

// ── Nostr publish (nostr-sdk 0.44.x) ─────────────────────────────────────────

/// Publish the bundle to Nostr: a kind-30078 addressable "latest" event (d-tag =
/// mint_id; relays keep only the latest) plus a kind-78 "history" event. Both are
/// signed by the attest key (its 32-byte secret is the Nostr secret key too).
///
/// Returns the latest event id (hex) on success.
pub async fn publish_nostr(
    result: &AttestationResult,
    attest_key: &Keypair,
    relays: &[String],
) -> Result<String> {
    use nostr_sdk::prelude::*;

    let secret_bytes = attest_key.secret_bytes();
    let keys = Keys::new(
        nostr_sdk::SecretKey::from_slice(&secret_bytes).context("nostr secret key")?,
    );

    let client = Client::new(keys.clone());
    for r in relays {
        client
            .add_relay(r.clone())
            .await
            .with_context(|| format!("add relay {r}"))?;
    }
    client.connect().await;

    let content = result.bundle_json.clone();

    // latest (addressable, NIP-78 kind 30078, d-tag = mint_id) — relays keep only latest.
    let latest = EventBuilder::new(Kind::ApplicationSpecificData, content.clone())
        .tag(Tag::identifier(result.bundle.mint_id.clone()));
    let latest_out = client
        .send_event_builder(latest)
        .await
        .context("publish latest (kind 30078)")?;
    let latest_id = latest_out.id().to_hex();

    // history (regular kind 78, same d-tag) — the balance-over-time timeline.
    let history = EventBuilder::new(Kind::Custom(78), content)
        .tag(Tag::identifier(result.bundle.mint_id.clone()));
    if let Err(e) = client.send_event_builder(history).await {
        tracing::warn!("PoR: history event (kind 78) publish failed: {e:#}");
    }

    tracing::info!("PoR: published Nostr latest event {}", latest_id);
    Ok(latest_id)
}

/// Resolve the Nostr relay list from env `POR_NOSTR_RELAYS` (comma-separated) or the
/// built-in defaults.
pub fn nostr_relays_from_env() -> Vec<String> {
    match std::env::var("POR_NOSTR_RELAYS") {
        Ok(v) if !v.trim().is_empty() => v
            .split(',')
            .map(|s| s.trim().to_string())
            .filter(|s| !s.is_empty())
            .collect(),
        _ => DEFAULT_NOSTR_RELAYS.iter().map(|s| s.to_string()).collect(),
    }
}
