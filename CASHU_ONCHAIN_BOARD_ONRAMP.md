# On-chain → ecash on-ramp for Ark-backed Cashu mints (via board / payjoin board)

| | |
|---|---|
| **Status** | Draft / feasibility + design (no code written) |
| **Date** | 2026-05-30 |
| **Author** | matthew@second.tech |
| **Scope** | Fund a NUT-04 mint quote with an on-chain payment that boards into the mint's Ark reserve; credit ecash. Payjoin optional. |
| **Companion** | `bark-payjoin-board/PLAN.md`, `bark-payjoin-board/TECHNICAL_DESIGN_V2.md` (board-via-payjoin primitive, M1/M2, INV-1, funding-script trust property) |

> Every load-bearing code claim is cited `path:line`. Repos: `~/cdk` (CDK upstream),
> `~/cdk-bark-payment-procssor` (the processor; note the misspelled dir), `~/bark`
> (worktree at `bark-payjoin-board/bark`). Skeptical by design — blockers are named,
> not glossed.

---

## 1. Executive summary and viability verdict

**Verdict: FEASIBLE — and the plain (non-payjoin) on-ramp is *already ~80% built*.**

Three findings reframe the task:

1. **CDK already supports a non-Lightning on-chain mint method natively.** The mint-quote
   payment method is an open enum (`PaymentMethod::{Known(KnownMethod), Custom(String)}`,
   `cdk/crates/cashu/src/nuts/nut00/mod.rs:758`); `IncomingPaymentOptions` already has an
   `Onchain` variant (`cdk/crates/cdk-common/src/payment.rs:245`), and `MintMethodOptions`
   already has `Onchain { confirmations }` (`cdk/crates/cashu/src/nuts/nut04.rs:272`).
   **No CDK fork is required for the *method*.** (The sibling `~/cdk-onchain-fork` is, w.r.t.
   on-chain methods, cosmetic — it only adds swagger annotations.)

2. **The processor already implements an on-chain receive that boards into Ark.**
   `create_incoming_payment_request` for `Onchain` hands out a **plain BDK address**
   (`src/ark_backend.rs:1608`); a poller detects the confirmed deposit at 1 conf
   (`src/ark_backend.rs:770-833`) and calls `bark::Wallet::board_all()` on that specific
   UTXO (`src/ark_backend.rs:877`); the settlement event credits the **net** VTXO amount
   (`src/ark_backend.rs:1080-1081,1169-1171`). So "on-chain → ecash, boarded into the
   reserve" is **implemented in the processor** — as a **two-transaction** flow.
   *Caveat (open Q5):* what is verified is the *processor* logic (the cited lines); it is
   **not** yet verified that a running `cdk-mintd` stack actually exposes on-chain mint quotes
   *through* this processor end-to-end. So "implemented in the processor; end-to-end
   enablement unverified" — not "shipped." (The audit-devnet `fund` scenario invoking
   `cdk-cli --method onchain`, `scenario-control.py:206`, is strong evidence it *is* enabled,
   but confirm before quoting it as free.)

3. **The proposal's actual delta is "2 tx → 1 tx" + optional payjoin privacy** — and *that*
   delta is the only part that is hard.

**The single hardest dependency: the bark M1/M2 primitive** — cosign a board output that a
*third party* funded, on confirmation. Today `bark::Wallet::board_tx` *builds and broadcasts
its own* funding transaction and cosigns its own pre-broadcast txid (`bark/src/board.rs:188,
219,261`). It cannot board a UTXO that someone else sent to a board address. Until M1
(cosign split from broadcast) and M2 (cosign-on-confirmation watcher) land, the direct-board
and payjoin paths **cannot exist**; only the existing two-tx path does.

**The honest tension (see §9):** the existing two-tx path is not only already shipped, it is
**strictly safer** — the mint boards synchronously from a normal UTXO it fully controls, so
the funding-script trust window (no user reclaim leaf; server-sweep-after-expiry,
`bark/lib/src/tree/signed.rs:68`) never opens. The 1-tx direct-board *re-introduces* that
window on the mint's own deposits. So the payjoin board buys one fewer transaction + privacy,
at the cost of new boarding machinery and a new operational risk. Whether that trade is worth
it is a real question, not a foregone conclusion.

---

## 2. Background: mint funding today vs. the on-chain board path

### 2.1 Lightning (today, the default)

NUT-04: client requests a mint quote, the mint returns a `bolt11`, the client pays it, the
mint detects settlement and marks the quote PAID, the client redeems blinded signatures into
ecash. In the processor, the bolt11 path issues a bark Lightning invoice
(`src/ark_backend.rs:1651`) and detects settlement by polling bark's
`pending_lightning_receives()` for a `finished_at` flag (`src/ark_backend.rs:2014-2030`).

### 2.2 On-chain receive → board (today, *already implemented*, two transactions)

The `Onchain` incoming method:
- **Request:** returns a fresh **plain BDK on-chain address** (`onchain.address()`,
  `src/ark_backend.rs:1608`), stores `quote_id → address` (`:1619-1620`), and tags the
  response `extra_json` with `"fee_policy":"bark_board_fee_deducted_from_received_amount"`
  (`:1631-1633`). `request_lookup_id = PaymentIdentifier::QuoteId(quote_id)` (`:1628`).
- **Detect:** `process_onchain_receive_boards()` (`:749`) syncs, then
  `detect_confirmed_receive_deposits()` scans unspent outputs and accepts those with
  `confirmations ≥ ONCHAIN_CONFIRMATIONS` (= 1) whose address matches a stored quote
  (`:770-833`, conf check `:789`).
- **Board:** `start_ready_receive_boards()` calls `wallet.board_all(ScopedBoard{outpoint})`
  on that specific deposit (`:835-951`, board call `:877`) — i.e. it builds and broadcasts a
  **second** transaction that spends the deposit UTXO into a board funding output and cosigns
  it (today's synchronous boarding). A state machine tracks
  `Detected → BoardPreparing → Boarding → Finalized` (`:880-947`, finalize `:1004`).
- **Credit:** the `Event::PaymentReceived` carries `payment_amount = pending_board.amount`
  (the **net** VTXO value, gross minus the bark board fee; `:1080-1081, 1169-1171`).

So funding a quote with on-chain bitcoin and crediting ecash **already exists** — at the cost
of two on-chain transactions (the payer's deposit, then the mint's board tx) and two
confirmation waits, and with the deposit landing first at an ordinary mint-controlled UTXO.

### 2.3 The proposed direct-board path (the delta)

Instead of a plain address + a second board tx, the mint hands the payer a **board funding
address directly**. The payer's single transaction confirms *at the board script*, and the
mint **cosigns-on-confirmation** against that output (M1/M2) — no second transaction. Payjoin
is layered on top so the payer's wallet and the mint collaboratively build that single tx,
optionally with the mint contributing its own reserve inputs.

> Net effect: 2 tx → 1 tx, plus the option of payjoin privacy/consolidation. Everything in
> the CDK/quote/credit plumbing is unchanged from §2.2; the work is bark M1/M2 + a way to
> hand out and watch a board address (+ optional payjoin receiver).

---

## 3. Role mapping and end-to-end sequences

### 3.1 Role mapping (mint = payjoin receiver = boarder)

`TECHNICAL_DESIGN_V2.md` casts the **boarding user as the payjoin receiver**. Here that role
is the **mint**, not the end user:

| Payjoin role | Who | Notes |
|---|---|---|
| **Receiver = boarder** | the **mint** (its `barkd`/`bark::Wallet`) | derives the board address, runs the receiver typestates, contributes reserve inputs, cosigns-on-confirmation |
| **Sender** | the **payer** (an external on-chain/payjoin wallet) | builds + broadcasts; needs no Ark/Cashu awareness |
| **Depositor** | the **Cashu wallet** | requests the quote, polls, redeems ecash; never touches Ark keys |

The depositor and the payer may be the *same person's two wallets* (an ecash wallet + an
on-chain wallet), but they are distinct roles: only the on-chain wallet does payjoin; only the
ecash wallet redeems.

### 3.2 Sequence A — payjoin path

```
Cashu wallet            Payer wallet            Mint (processor + barkd)        captaind   chain
 request mint quote ───────────────────────────►
                                          create_incoming_payment_request(Onchain/board)
                                          kp; (board_addr,expiry)=board_funding_address(kp)
        ◄───── quote { request = bitcoin:board_addr?amount=X&pj=<mint_pj> } ──
                      ◄── BIP21 URI (out of band / shown to payer) ──
   (poll quote)        build original PSBT (X→board_addr); POST to mint_pj
                                          payjoin receiver typestates:
                                            identify_receiver_outputs(|s| s==board_spk)
                                            [opt] contribute_inputs(reserve utxos)  // +Y
                                            finalize_proposal(sign reserve inputs)
                      ◄──────── payjoin proposal PSBT ─────────
                      re-sign; broadcast ──────────────────────────────────────────► confirm
                                          observe confirmed board output (INV-1: located txid:vout)
                                          cosign_and_store_board(confirmed_tx) ─────►  cosign_board (blind)
                                          register VTXO in reserve  ◄────────────────  partial sig
                                          mark quote PAID, payment_amount = X (NOT X+Y)
   poll → PAID
   redeem blinded sigs ──────────────────►  issue ecash for X
```

### 3.3 Sequence B — plain on-chain degrade (no payjoin)

Identical except the payer simply pays the board address with an ordinary wallet (no `pj`
round-trip, no mint input contribution; `Y = 0`):

```
   request quote → mint returns bitcoin:board_addr?amount=X
   payer sends X to board_addr (one tx) ───────────────► confirm
   mint cosign-on-confirmation boards the output → VTXO(s); quote PAID (amount = X)
   cashu wallet redeems ecash for X
```

This is the mandatory baseline — the on-ramp must work for payers who cannot payjoin.

> **Important distinction from §2.2:** Sequence B is still **one** transaction (payer pays the
> *board* address directly), whereas §2.2 is **two** (payer pays a plain address; mint boards
> it). Sequence B therefore needs M1/M2; §2.2 does not. If M1/M2 are unavailable, §2.2 is the
> fallback-of-the-fallback — fully working today, just one extra tx.

---

## 4. Component-by-component changes

### 4.1 CDK (`~/cdk`) — **no fork required**

- `MintPayment` trait (`cdk/crates/cdk-common/src/payment.rs:420`) is a generic
  create-request / wait-for-event abstraction:
  - `create_incoming_payment_request(IncomingPaymentOptions) -> CreateIncomingPaymentResponse
    { request_lookup_id, request, expiry, extra_json }` (`:442`, response `:529`) — `request`
    is an arbitrary string, so a BIP21 board URI fits.
  - `wait_payment_event() -> Stream<Event>` emitting
    `Event::PaymentReceived(WaitPaymentResponse { payment_identifier, payment_amount,
    payment_id })` (`:464,:489,:510`) — "board confirmed + registered" maps cleanly onto
    emitting this event.
  - `check_incoming_payment_status(payment_identifier) -> Vec<WaitPaymentResponse>` (`:475`).
- The on-chain method is already first-class: `IncomingPaymentOptions::Onchain`
  (`cdk/crates/cdk-common/src/payment.rs:245`), `MintMethodOptions::Onchain{confirmations}`
  (`cdk/crates/cashu/src/nuts/nut04.rs:272`), registered via
  `MintBuilder::add_payment_processor(unit, method, …)` keyed by `(unit, PaymentMethod)`
  (`cdk/crates/cdk/src/mint/builder.rs:384-544`; dispatch `get_payment_processor`,
  `cdk/crates/cdk/src/mint/mod.rs:464-478`).
- **Caveat (a real but small one):** `IncomingPaymentOptions` is a *closed* enum
  (`Bolt11|Bolt12|Custom|Onchain`, `payment.rs:245-254`). We do **not** need a new variant —
  `Onchain` (or `Custom("ark-board")` for board-specific metadata) suffices. Adding a
  *dedicated* board variant *would* require forking `cdk-common`; the design avoids that by
  reusing `Onchain`/`Custom` + `extra_json`.

### 4.2 `cdk-bark-payment-procssor` — where the work concentrates

1. **Hand out a board address instead of a plain one.** In `create_incoming_payment_request`'s
   `Onchain` arm (`src/ark_backend.rs:1599-1635`), replace `onchain.address()` (`:1608`) with
   `bark::Wallet::board_funding_address(&kp)` and return a BIP21 URI (plus, for payjoin, a
   `pj=` endpoint) as `request`. Persist `quote_id → (board_spk, user_keypair, expiry)`
   *before responding* (extends the existing `put_receive_address`, `:1619-1620`).
2. **Watch the board script and cosign-on-confirmation.** Replace the
   `detect → board_all` machinery (`:770-951`) for this path with: detect a confirmed output
   *paying the board script*, then call the new bark `cosign_and_store_board(confirmed_tx)`
   (M1/M2) — **no second tx, no `board_all`**. Reuse the existing intent state machine and
   `wait_payment_event` emission shape.
3. **Report the correct amount.** Emit `payment_amount = X` (the depositor's contribution),
   **not** the board output value (§5). Today the code reports the net board value
   (`:1080-1081,1169-1171`) which equals the deposit only because the mint contributes nothing;
   with payjoin contribution it must subtract the mint's own `Y`.
4. **Payjoin receiver endpoint (optional layer).** An HTTP endpoint running the receiver
   typestates (`payjoin-rs/payjoin/src/core/receive/`): `identify_receiver_outputs(|s| s ==
   board_spk)` → `commit_outputs` → optional `contribute_inputs` → `finalize_proposal`. See
   §4.4 location discussion.

### 4.3 bark (`~/bark`, `payjoin-board` branch) — M1/M2 (the hard dependency)

- **M1 — split cosign from broadcast.** `cosign_and_store_board(funding_tx, kp, expiry)`:
  everything in `board_tx` (`bark/src/board.rs:188`) *except* the broadcast (`:261`), and
  **locate the board output by script** rather than assuming vout 0 (`:203,:219`) — payjoin
  shuffles outputs (INV-1, `TECHNICAL_DESIGN_V2.md §5.2`).
- **M2 — cosign-on-confirmation watcher.** Given a known `board_spk`, recognize the confirmed
  funding tx (payjoin proposal *or* fallback), derive the located outpoint, cosign once. The
  server cosigns blind (`bark/server/src/lib.rs:657`), so this is a normal board to captaind.
- **Optional:** a bark-side payjoin receiver module vs. keeping it in the processor (§4.4).

These are exactly the milestones in `TECHNICAL_DESIGN_V2.md §7.3-7.4`. This doc adds no new
bark requirements beyond them — it just casts the "boarding user" as the mint.

### 4.4 Where does the payjoin receiver live?

**Recommendation: in the processor, not bark.** The processor already owns the HTTP surface,
the quote↔address state, and the bark wallet handle; the payjoin receiver needs all three. A
bark module would force bark to grow an HTTP server and quote awareness it otherwise doesn't
need. bark should expose only the *primitives* (board address derivation, `InputPair`s from
its on-chain wallet, `cosign_and_store_board`); the processor orchestrates.

**v1 (BIP78) is sufficient.** A mint is always online with a public endpoint, so the
synchronous v1 model fits; v2/relay (BIP77) buys nothing here and adds an OHTTP relay
dependency. (v2 matters for *mobile* receivers, which a mint is not.)

### 4.5 Untouched

- **captaind / Ark server:** zero changes. Cosign is blind (`bark/server/src/lib.rs:657`);
  a payjoin board is an ordinary board for some outpoint.
- **ark-lib (`bark/lib`):** zero changes. `BoardBuilder` already accepts an arbitrary
  outpoint.

---

## 5. Accounting model (X vs Y)

Let `X` = the depositor's quote amount, `Y` = reserve inputs the mint contributes in a payjoin,
`F_board` = the Ark board fee, `C_on` = on-chain fee.

- **Board output value** `V = X + Y − C_on_if_receiver_pays`. The VTXO is worth `V − F_board`.
- **Ecash credited must be `X`**, not `V`. `Y` is the mint recycling its own reserve — it nets
  to zero on the mint's books; crediting it would mint free ecash against the mint's own money.
- **CDK credits the event-reported amount, not the quote amount.** `handle_mint_quote_payment`
  takes `WaitPaymentResponse.payment_amount` and calls `add_payment(amount, payment_id)`
  (`cdk/crates/cdk/src/mint/mod.rs:1005-1026`; `add_payment`
  `cdk/crates/cdk-common/src/mint.rs:748-796`); the quote flips to `Paid` once
  `amount_paid > amount_issued` (`compute_quote_state`, `cdk-common/src/mint.rs:788-795`).
  **Therefore the processor is solely responsible for reporting `X`.** This is a one-line
  policy in the processor (report the depositor's contribution, derived as deposit minus the
  mint's own contributed inputs), but it is a *correctness-critical* line — see threat T-double
  in §7.
- CDK *tolerates overpayment* (`amount_paid` may exceed the quote). The plain path today
  reports the **net** board value (`V − F_board`), i.e. it credits the depositor `X − F_board`
  and discloses that via the `fee_policy` extra_json (`src/ark_backend.rs:1631`). Decide
  explicitly who eats `F_board`: either (a) credit `X − F_board` (depositor pays the board
  fee, disclosed), or (b) credit `X` and have the mint absorb `F_board`. Pick one and document.
- **Mint payjoin-deposit P&L (the substance behind open Q1).** In a payjoin deposit where the
  mint contributes `Y` and pays the receiver-input weight `C_on` (the polite default), the
  mint credits the depositor `X` but its reserve nets `(X + Y) − F_board − Y = X − F_board`,
  while it spent `C_on` of its own on fees. So **per payjoin deposit the mint absorbs
  `C_on + F_board`** (minus whatever it recovers from the spread on the ecash it issued). That
  per-deposit cost — not a vague "fee policy" — is what Q1 must price: a mint will only offer
  input-contributing payjoin if the privacy/consolidation value exceeds `C_on + F_board`.

---

## 6. Trust model and auditability

### 6.1 Trust (no new *safety* assumption)

- **user → mint: custodial.** Standard Cashu IOU. Once ecash is issued, the mint owes the
  bearer; the mint could refuse to honor it. This is inherent to Cashu and unchanged here.
- **mint → captaind: standard Ark.** Liveness-not-safety + censorship risk. The mint's reserve
  is 2-of-2 with the server, server-sweepable after expiry (`bark/lib/src/tree/signed.rs:68`).
  Already true for every VTXO the mint holds.
- **No new safety assumption beyond "trust the mint,"** which Cashu already requires. The
  payer hands bitcoin to the mint's board address in exchange for the mint marking a quote
  PAID; if the mint misbehaves, the failure mode is the same custodial risk Cashu always has.

### 6.2 Auditability / `ark-audit` composition (a genuine *win* for boarding)

`ark-audit` computes proof-of-solvency by reading **captaind's Postgres VTXO table directly**
(`SELECT vtxo_id, amount, spend_state, policy FROM vtxo`, `ark-audit/server/src/main.rs:315-318`),
deriving the mint's account xpub children and matching VTXO owner pubkeys against them
(`:448-484`), and summing attributed spendable VTXOs into `reserve_sat` (`:466-479`).

Consequence:
- **A boarded deposit becomes a VTXO in captaind → it is inside the witnessed set → it counts
  toward audited reserve.** This is the core argument *for* boarding the deposit.
- **An un-boarded on-chain deposit (a plain UTXO the mint holds) is invisible to ark-audit** —
  it is reserve *outside* the witnessed set, so the audit would *understate* the mint's
  reserve (showing the mint as less solvent than it is). That is "safe" in the
  proof-of-reserves direction (never overstates) but means un-boarded deposits don't help the
  solvency proof until boarded.
- **Implication for §2.2's two-tx path:** between the deposit confirming and `board_all`
  completing, the deposit is a plain UTXO → temporarily outside the witnessed set. The
  direct-board path has the same gap (deposit confirmed, not yet cosigned/registered). In both
  cases the audited reserve lags the true reserve until registration — acceptable, but worth
  stating.

---

## 7. Threat model and edge cases (this composition)

| # | Threat | Analysis / mitigation |
|---|---|---|
| **T-credit** | **Mint marks PAID but never registers the VTXO** (or vice-versa) | Crediting must be gated on **registration**, not mere confirmation: emit `PaymentReceived` only after `cosign_and_store_board` + registration succeed. Ordering: board first, then credit (mirrors today's `Finalized`-then-emit, `src/ark_backend.rs:1004,1169`). If boarding fails, the quote stays unpaid and the deposit is recoverable by the mint (pre-expiry). |
| **T-expiry** | **Deposit confirms after the board address's `expiry_height`** | The funding script has **no user reclaim leaf**; post-expiry it is server-sweepable (`bark/lib/src/tree/signed.rs:68,35`). This is the **mint's** operational risk, not the depositor's (the depositor holds no VTXO and is owed ecash for a PAID quote regardless). Mitigations (`TECHNICAL_DESIGN_V2.md §5.5`): pick `expiry_height` at the server max lifetime; TTL the quote/URI well inside it; cosign immediately on confirmation; treat a post-expiry arrival as a failed quote and recover via server cooperation. **Do NOT mark such a quote PAID** until the VTXO actually registers. |
| **T-fallback** | **Payer broadcasts the payjoin *fallback*** (different txid) | The fallback also pays `board_spk` (the URI targets it). Cosign-on-confirmation binds to *whichever* tx confirms (`TECHNICAL_DESIGN_V2.md §5.4`); one cosign, one credit. No special handling beyond watching the script, not a specific txid. |
| **T-reorg** | **Deposit reorged out after credit** | If ecash was issued at 1 conf and the deposit is reorged away, the mint has issued ecash against vanished reserve. **In the 1-tx direct-board path the only on-chain artifact is the payer's funding tx** — registration is the *off-chain* `register_board_vtxo` against captaind, not a second on-chain spend — so the sole reorg lever is **funding-tx confirmation depth**. Mitigation: require ≥ N confs before crediting (configurable; raise N with `X`). (The "wait for the board tx to confirm" lever only exists in the 2-tx path, where the mint's board spend is itself on-chain; don't import it here.) |
| **T-double** | **Double-credit** (same deposit credited twice; or `X+Y` credited) | (a) CDK dedups payments by `payment_id` in `add_payment` (`cdk-common/src/mint.rs:748-796`) — use a stable `payment_id` (the board outpoint). (b) The processor must report `X`, not `V=X+Y` (§5) — a bug here mints free ecash against the mint's own `Y`. This is the most dangerous correctness line in the whole feature. |
| **T-reuse** | **Quote/address reuse** (payer pays a board address twice, or an old quote) | Bind one board address to one quote; on a second payment to the same address, either credit a *new* implicit deposit or reject. Quotes must expire (TTL) and addresses must not be recycled across quotes. The existing `quote_id → address` map (`src/ark_backend.rs:1619`) already enforces 1:1; preserve that. |
| **T-griefing** | **Payer abandons after getting the proposal** (payjoin) | No loss — the mint signed only its own contributed inputs in a proposal that was never broadcast; nothing is at stake until a tx confirms. Time out the payjoin session and the quote. |
| **T-probe** | **Payer probes the mint's reserve UTXOs via payjoin** | Standard payjoin receiver exposure: the mint reveals candidate inputs at proposal time. Mitigation: make mint input-contribution **opt-in** per mint policy; a mint that doesn't contribute (`Y=0`) exposes nothing and still gets the 1-tx benefit. |

---

## 8. Open questions and milestones

### 8.1 Open questions

1. **Who eats `F_board`** on the board on-ramp — depositor (credit `X − F_board`) or mint
   (credit `X`, absorb fee)? (§5).
2. **Confirmation depth** for crediting vs. `X` size (T-reorg). Fixed 1, or scaled?
3. **`Onchain` vs `Custom("ark-board")`** method identity: reuse the native `Onchain` method
   (simplest) or a distinct `Custom` method so clients can tell "this on-chain quote boards"?
   Leaning: reuse `Onchain` + `extra_json` flag.
4. **Quote ↔ address lifetime / TTL** tuned against `expiry_height` (T-expiry).
5. **Does cdk-mintd currently expose config to *enable* the on-chain method** against this
   processor end-to-end, or is only the type machinery present? (Verify in `cdk-mintd` wiring;
   the processor advertises it via `get_settings`, `src/ark_backend.rs:1572-1589`.)

### 8.2 Milestones (each independently committable)

| M | Title | Scope | Depends on |
|---|---|---|---|
| **O0** | Verify + harden the existing 2-tx path | First **resolve Q5**: confirm a running `cdk-mintd` exposes on-chain mint quotes through this processor end-to-end. If yes → document + test (near-zero code). If the mintd wiring is missing → O0 *includes adding it*. Not assumed zero-code. | — |
| **O1** | bark M1 | `cosign_and_store_board` (split cosign from broadcast; locate output by script) | bark |
| **O2** | bark M2 | cosign-on-confirmation watcher for a known board script | O1 |
| **O3** | Processor direct-board (plain) | hand out a board address; watch + cosign-on-confirm; report `X`; credit on registration | O1, O2 |
| **O4** | Processor payjoin receiver (v1) | receiver typestates; optional mint input contribution; `X`-not-`V` accounting | O3 |
| **O5** | Polish | conf policy, TTL, fee policy, `ark-audit` reconciliation, metrics | O3 |

O0 alone delivers the user-visible feature (on-chain deposit → ecash). O1-O4 are the
optimization (1 tx + privacy).

---

## 9. Why this might NOT be worth building

A deliberately skeptical accounting:

1. **The feature is essentially already implemented (O0).** The on-chain → ecash → boarded-reserve
   flow exists in the *processor* as a two-transaction path (§2.2, `src/ark_backend.rs:1599-1635,
   749-951, 1080-1081`). The one unverified link is whether a running `cdk-mintd` exposes
   on-chain mint quotes through it end-to-end (open Q5) — so O0 is "confirm/complete the mintd
   wiring (likely already present), then document + test," **not guaranteed zero-code**. Either
   way, a user who just wants to fund ecash with on-chain bitcoin is at most a small wiring
   step away. The entire M1-M4 effort buys **one fewer on-chain transaction** and **optional
   privacy** — not a new capability.

2. **The 1-tx path is less safe — but be precise about *which* risk, because it changes the
   verdict by deployment.** The real asymmetry is the cosign-refusal window: in the 2-tx flow
   the mint requests the cosign and broadcasts the board tx only *after* it has the cosign, so
   a refusal leaves funds at a plain, mint-controlled UTXO — fully recoverable. In the 1-tx
   flow the funds are already at the board script (no user reclaim leaf,
   `bark/lib/src/tree/signed.rs:68`) *before* any cosign, so a refusal leaves them where the
   mint cannot unilaterally reclaim. That asymmetry holds in **every** deployment — but it is
   only a **liveness** exposure, not automatically theft:
   - **Liveness (universal):** a cosign gap = a recoverable window. Complete the cosign once
     captaind responds; with a far `expiry_height` this resolves well inside the window.
   - **Theft (T10, conditional):** the server *sweeping at expiry* requires captaind to be an
     **adversarial, separately-operated** party that refuses forever and waits out expiry.
   - **Single-operator mints** (the mint runs or co-owns its captaind — plausible for an
     Ark-backed mint) reduce this to a captaind **outage**, not malice: recoverable.
   So the "poor standalone trade" conclusion is **fully right against a third-party captaind**
   and **weaker against a self-operated one**. State the captaind operating model when quoting
   this risk.

3. **Complexity concentrates in net-new, security-sensitive code:** bark M1/M2 (the hardest
   dependency, and shared with the broader payjoin-board effort) + a payjoin receiver HTTP
   service in the processor + the `X`-not-`V` accounting line (T-double) where a bug silently
   mints free ecash. That's a lot of surface for "one fewer tx."

4. **Payjoin's privacy value is real but *coupled to* the T-probe exposure — they are one
   knob seen from two sides.** Dismissing it as "only payer-side input clustering, not the
   depositor's threat model" is too quick. The win that matters here is **mint-deposit
   unlinkability**: with the mint contributing inputs, an on-chain observer cannot tell the tx
   is "someone funding mint X's board address" versus an ordinary payjoin — breaking the link
   between a user and *the fact that they deposited to a particular mint*. That plausibly *is*
   the depositor's threat model. **But that benefit requires `Y > 0`, which is exactly
   T-probe** (the mint reveals candidate reserve UTXOs at proposal time). So the honest
   synthesis: *payjoin privacy ⟺ mint contributes inputs ⟺ T-probe exposure + the `C_on +
   F_board` cost of §5.* With `Y = 0` you get the 1-tx benefit but little privacy. CDK itself
   adds nothing here — the credit/quote machinery is method-agnostic and already sufficient
   (§4.1); the privacy/cost trade lives entirely in the `Y` knob.

5. **Where the value *is* real:** (a) a mint that wants every on-chain deposit to be a single
   confirmed transaction (lower fees, less mempool footprint, faster audited-reserve
   inclusion); (b) payers who genuinely want payjoin privacy for an on-chain deposit; (c)
   reusing the *same* bark M1/M2 primitive the payjoin-board effort needs anyway, so the
   marginal cost here is mostly the processor glue.

**Recommendation:** ship **O0** (document/test the existing 2-tx path) now — it's the honest
"on-chain → ecash on-ramp" with zero new risk. Treat **O1-O4** as contingent on the broader
payjoin-board M1/M2 work landing for its own reasons; if it does, the direct-board/payjoin
on-ramp is a cheap add-on. Do **not** build M1/M2 *solely* to save one transaction on the
deposit path — the safety regression (point 2) makes that a poor standalone trade.

---

## 10. Reproducible environment (parallel devnet)

Goal: a third devnet instance that runs **fully in parallel** with the live cashu-warnet
(`:5173`) and the payjoin-board devnet (`18543/3635/5533`), to exercise this on-ramp. This
section documents the design; honest status of what runs is in §10.4.

### 10.1 What the existing setup actually is (so we reuse, not rebuild)

- **`~/bark-audit-devnet`** is a *data + control* directory, **not** a self-launching stack:
  it holds per-component configs (`captaind.toml`, `mintN.config.toml`, `ark-audit.toml`) and
  `scenario-control.py`, but has **no top-level launcher** for bitcoind/captaind/postgres/the
  base mints — those are brought up out of band. `scenario-control.py` only *spawns extra*
  mints/processors (`scenario-control.py:340-380`) and drives bitcoin-cli/cdk-cli/ark-audit.
- **`scenario-control.py`** is an HTTP control plane on **`127.0.0.1:9200`**
  (`scenario-control.py:416-417`); it shells out to `bitcoin-cli` (`:18443`), `cdk-cli`,
  `lightning-cli`, the processor, `cdk-mintd`, and the `ark-audit` server (`:9100`).
- **`ark-audit`** server (`:9100`) is the dashboard's single source of truth — `/topology`,
  `/audit-pubkey`, `/attestations/<id>`, `/sim/<id>`.
- **`~/cashu-warnet`** (the `:5173` dashboard) is a *pure consumer* of `/topology`
  (`App.jsx:13`) and is **already parameterized by env vars** —
  `VITE_AUDIT_URL` (default `:9100`, `App.jsx:19`), `VITE_CONTROL_URL` (default `:9200`,
  `App.jsx:24`), `VITE_EXPLORER_URL` (`App.jsx:23`). **A parallel dashboard is just those env
  vars + `--port 5174`; no dashboard code change is needed to point a second instance at a
  second stack.**
- The on-ramp's **plain path already runs here today**: the `fund` scenario invokes
  `cdk-cli -w <wallet> -u sat -n mint <mint_url> <amt> --method onchain` (`scenario-control.py:206-208`),
  sends bitcoin to the returned address, mines, and the processor boards + credits.

### 10.2 The third offset port block (finalized)

Distinct from both existing stacks. Separate datadirs, database, and captaind.

| Component | Live audit-devnet | payjoin-board | **on-ramp devnet (this)** |
|---|---|---|---|
| bitcoind RPC / P2P | 18443 / 18444 | 18543 / 18544 | **18643 / 18644** |
| captaind public / admin | 3535 / 3536 | 3635 / 3636 | **3735 / 3736** |
| postgres (db) | 5433 (`bark-server-db`) | 5533 | **5633 (`bark-onramp-db`)** |
| mints | 8081-8083 | — | **8181-8183** |
| mint mgmt-rpc | 8091-8093 | — | **8191-8193** |
| processors | 50051-50053 | — | **50151-50153** |
| ark-audit | 9100 | — | **9101** |
| scenario-control | 9200 | — | **9201** |
| dashboard (vite) | 5173 | — | **5174** |

Datadir root: a new `~/bark-onramp-devnet/` (mirrors `~/bark-audit-devnet/`'s layout) with its
own bitcoind/captaind/postgres datadirs so nothing is shared.

### 10.3 The two wallet actors (one user, two wallets)

1. **External on-chain / payjoin wallet (the payer) — OUTSIDE, not wired.** A standalone
   regtest wallet with **no control-plane link** to captaind or any mint; it interacts *only*
   by sending bitcoin to the mint's board address. Simplest honest implementation:
   - *plain path:* a named `bitcoind` wallet (`bitcoin-cli -rpcwallet=payer ... sendtoaddress`).
   - *payjoin path:* a small `rust-payjoin` **sender** harness (BIP78 v1) posting to the mint's
     `pj=` endpoint. **(TODO — does not exist yet; see §10.4.)**
   Rendered in the dashboard as a **detached/outside node**.
2. **Cashu wallet (the depositor's ecash wallet) — WIRED to a mint.** A `cdk-cli` wallet
   (`cdk-cli -w <onramp-wallet> ... mint --method onchain <mint_url> <amt>`): requests the
   quote, polls, redeems ecash. Rendered as a **wired node** with its ecash balance.

These model one person's two wallets; only the on-chain wallet pays, only the ecash wallet
redeems.

### 10.4 Honest status — what runs, what is blocked

| Scenario step | Status |
|---|---|
| Stand up the parallel stack on the offset block | **Buildable now** — must write the base-stack bring-up (unscripted upstream; reverse-engineered from configs + `scenario-control.py:340-380`). |
| Cashu wallet requests quote → on-chain address | **Runs today** (`cdk-cli --method onchain`, `scenario-control.py:206`). |
| External wallet pays **plain on-chain** → mint boards (2-tx) → ecash | **Runs today** (existing `fund` path; processor `board_all`, `ark_backend.rs:877`). |
| External wallet pays **payjoin** → mint contributes inputs → **1-tx direct board** | **BLOCKED** — needs bark **M1/M2** (`cosign_and_store_board` + cosign-on-confirmation watcher) *and* a mint-side payjoin receiver in the processor *and* the `rust-payjoin` sender. None exist. |
| ark-audit re-reads reserve → deposit shows server-witnessed | **Runs today** for the boarded value (audit reads captaind Postgres, `ark-audit/server/src/main.rs:315-318`). |

> **Therefore a faithful *running* payjoin on-ramp demo is not achievable yet.** The parallel
> devnet can demonstrate the **plain 2-tx on-ramp end-to-end today** (which is the honest
> baseline, §9), with the payjoin/direct-board step rendered as **pending M1/M2**. Building a
> launcher that *claims* to run the payjoin path would be fiction.

### 10.5 Commands (target UX, matching the payjoin-board devnet README style)

```sh
# bring up the isolated stack (bitcoind+captaind+postgres+3 mints+3 processors+ark-audit)
cd ~/bark-onramp-devnet && ./devnet.sh up        # offset ports 18643/3735/5633/8181../9101
./devnet.sh status                               # show component health
python3 scenario-control.py &                    # control plane on :9201

# parallel dashboard (no code change — just env + port)
cd ~/cashu-warnet && \
  VITE_AUDIT_URL=http://127.0.0.1:9101 \
  VITE_CONTROL_URL=http://127.0.0.1:9201 \
  npm run dev -- --port 5174                      # http://127.0.0.1:5174

# drive the on-ramp (plain path runs today; payjoin path stubbed pending M1/M2)
curl -XPOST http://127.0.0.1:9201/scenario/onramp -d '{"amount":50000,"mode":"plain"}'
curl -XPOST http://127.0.0.1:9201/scenario/onramp -d '{"amount":50000,"mode":"payjoin"}'  # logs BLOCKED

./devnet.sh down                                  # leaves :5173 and 18543/3635/5533 untouched
```

All ports are disjoint from `:5173`, `:3333/:3334`, and `18543/3635/5533`, so `devnet up`
coexists with both live stacks.

## 11. Appendix: code reference index

- **CDK extensibility:** `cdk/crates/cashu/src/nuts/nut00/mod.rs:758` (PaymentMethod open enum);
  `cdk/crates/cdk-common/src/payment.rs:420` (MintPayment trait), `:442` (create_incoming),
  `:464` (wait_payment_event), `:475` (check_incoming), `:489/:510/:529` (Event /
  WaitPaymentResponse / CreateIncomingPaymentResponse), `:245-254` (IncomingPaymentOptions);
  `cdk/crates/cashu/src/nuts/nut04.rs:272-286` (MintMethodOptions::Onchain).
- **CDK quote lifecycle:** `cdk/crates/cdk/src/mint/issue/mod.rs:202-397` (quote create →
  create_incoming), `:222` (get_payment_processor); `cdk/crates/cdk/src/mint/mod.rs:464-478`
  (processor registry/dispatch), `:1005-1026` (credit from event amount);
  `cdk/crates/cdk-common/src/mint.rs:554` (request_lookup_id), `:748-796` (add_payment),
  `:788-795` (Paid state); `cdk/crates/cdk-common/src/database/mint/mod.rs:328-331`
  (lookup by request id); `cdk/crates/cdk/src/mint/builder.rs:384-544` (add_payment_processor).
- **Processor today:** `src/ark_backend.rs:1572-1589` (get_settings advertises onchain),
  `:1599-1635` (onchain create_incoming → plain BDK address), `:1651-1684` (bolt11 path),
  `:749-768` (process_onchain_receive_boards), `:770-833` (detect, 1-conf at `:789`),
  `:835-951` (board_all at `:877`), `:1004` (finalize), `:1080-1081` (gross/net fee),
  `:1169-1171` (PaymentReceived amount = net). WISHLIST (orthogonal — arkoor mint-to-mint
  settlement, not this on-ramp): `WISHLIST.md:75-89`.
- **bark:** `bark/src/board.rs:160` (board_funding_address), `:188` (board_tx), `:219`
  (utxo = txid:0), `:261` (broadcast); `bark/server/src/lib.rs:657` (blind cosign, `:684`
  expired check); `bark/lib/src/tree/signed.rs:68` (cosign_taproot), `:35` (expiry_clause,
  server-only).
- **ark-audit:** `ark-audit/server/src/main.rs:315-318` (read captaind Postgres VTXO table),
  `:448-484` (xpub derive + match), `:466-479` (attribution → reserve_sat).
