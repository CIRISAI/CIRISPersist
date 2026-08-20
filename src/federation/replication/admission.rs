//! Admission-gate wrapper composing a [`TrustScoring`] + threshold.
//!
//! v3.4.0 (CIRISPersist#123). The four write paths
//! (`put_blob`, `put_attestation`, `put_revocation`, `put_contribution`)
//! all call [`AdmissionGate::check`] BEFORE any DB work — trust is
//! the cheapest reject AND the one that leaks the least information.
//! An unauthorized writer shouldn't learn "your bytes matched the SHA"
//! or "your FK target exists."

use std::collections::HashMap;
use std::sync::Arc;
use std::time::{Duration, Instant};

use super::trust_scoring::{TrustScoring, TrustScoringError};

/// v3.4.0 (CIRISPersist#123) — thin composition of `TrustScoring +
/// threshold` (v38.0.0/#748: the decorative `recursion_depth` is
/// retired — see the trait doc). Each write site calls
/// [`Self::check`]; on `Ok(score)` the site proceeds, on
/// `Err(TrustGateRejection)` the site rejects with its typed
/// per-surface error.
#[derive(Clone)]
pub struct AdmissionGate {
    scoring: Arc<dyn TrustScoring>,
    threshold: f64,
}

/// v3.4.0 (CIRISPersist#123) — typed outcome of an admission check
/// that fell below the configured threshold. Sites translate this into
/// their own typed error variant (`BlobError::TrustBelowThreshold`,
/// `federation::Error::TrustBelowThreshold`,
/// `cirisnode::Error::InvalidArgument`).
#[derive(Debug, Clone)]
pub struct TrustGateRejection {
    /// The attesting key the gate evaluated.
    pub key_id: String,
    /// The aggregate score returned by [`TrustScoring`].
    pub score: f64,
    /// The threshold the score fell below.
    pub threshold: f64,
}

impl AdmissionGate {
    /// Construct a new gate. `threshold` outside `[0.0, 1.0]` is
    /// clamped — keeps callers honest without a typed error here.
    pub fn new(scoring: Arc<dyn TrustScoring>, threshold: f64) -> Self {
        Self {
            scoring,
            threshold: threshold.clamp(0.0, 1.0),
        }
    }

    /// Threshold the gate evaluates against. Clamped to `[0.0, 1.0]`.
    pub fn threshold(&self) -> f64 {
        self.threshold
    }

    /// v3.5.1 (CIRISPersist#129) — extract a clone of the inner
    /// `Arc<dyn TrustScoring>` for cohabitation consumers that need
    /// the scorer directly (CIRISEdge `init_edge_runtime` short-
    /// circuit auto-derivation). Symmetric to
    /// [`BackendDispatch`-as-`BlackholeRules`](crate::engine::BackendDispatch)
    /// access for the deny-list trait — the substrate exposes its
    /// trait-keyed handles so consumers don't have to re-wire scoring
    /// from scratch.
    pub fn scoring_arc(&self) -> Arc<dyn TrustScoring> {
        self.scoring.clone()
    }

    /// Check whether `key_id` clears the gate. Returns:
    ///
    /// - `Ok(Ok(score))` — the key cleared at `score >= threshold`.
    /// - `Ok(Err(TrustGateRejection { … }))` — the key scored below
    ///   threshold.
    /// - `Err(TrustScoringError)` — the resolver failed.
    ///
    /// `TrustScoringError::KeyNotFound` is converted to a rejection
    /// at score `0.0` — an unknown key has no trust, and the site's
    /// downstream code (FK validation) will likely return a typed
    /// `InvalidArgument` if reached. Keeping the rejection here lets
    /// the trust gate stay first in the ordering without leaking
    /// "does this key exist" information.
    pub async fn check(
        &self,
        key_id: &str,
    ) -> Result<Result<f64, TrustGateRejection>, TrustScoringError> {
        // Bootstrap-permissive optimization: threshold 0.0 admits
        // everything without dispatching to the resolver.
        if self.threshold <= 0.0 {
            return Ok(Ok(0.0));
        }
        let score = match self.scoring.trust_score(key_id).await {
            Ok(s) => s,
            Err(TrustScoringError::KeyNotFound(_)) => 0.0,
            Err(other) => return Err(other),
        };
        if score >= self.threshold {
            Ok(Ok(score))
        } else {
            Ok(Err(TrustGateRejection {
                key_id: key_id.to_owned(),
                score,
                threshold: self.threshold,
            }))
        }
    }
}

impl AdmissionGate {
    /// Run the gate and translate its outcome into a
    /// [`crate::federation::BlobError`] result. The blob-write paths
    /// (`put_blob`) call this; rejection becomes
    /// [`crate::federation::BlobError::TrustBelowThreshold`].
    pub async fn check_blob(&self, key_id: &str) -> Result<(), crate::federation::BlobError> {
        let outcome = self
            .check(key_id)
            .await
            .map_err(|e| crate::federation::BlobError::Backend(format!("trust_scoring: {e}")))?;
        match outcome {
            Ok(_) => Ok(()),
            Err(rej) => Err(crate::federation::BlobError::TrustBelowThreshold {
                key_id: rej.key_id,
                score: rej.score,
                threshold: rej.threshold,
            }),
        }
    }

    /// Run the gate and translate its outcome into a
    /// [`crate::federation::Error`] result. The attestation /
    /// revocation write paths call this; rejection becomes
    /// [`crate::federation::Error::TrustBelowThreshold`].
    pub async fn check_federation(&self, key_id: &str) -> Result<(), crate::federation::Error> {
        let outcome = self
            .check(key_id)
            .await
            .map_err(|e| crate::federation::Error::Backend(format!("trust_scoring: {e}")))?;
        match outcome {
            Ok(_) => Ok(()),
            Err(rej) => Err(crate::federation::Error::TrustBelowThreshold {
                key_id: rej.key_id,
                score: rej.score,
                threshold: rej.threshold,
            }),
        }
    }
}

// ─────────────────────── QUOTA CONSTANTS — BEGIN ───────────────────────
//
// v25.1.0 (CIRISPersist#583) — everything between this marker and the END
// marker is **derivation-gated**. `tests::every_quota_constant_is_derived`
// scans this block out of the source at test time and fails if a constant
// here lacks a `**Bounds:**` line (what it bounds), a `**Derived:**` line
// (why *that* value), or an entry in the gate's relationship table. The
// relationships themselves — the identities and the inequalities the docs
// below claim — are asserted in the same test.
//
// The reason is #583's framing: *a magic constant with no derivation is a
// future incident.* Downstream WILL tune these numbers; the gate is what
// keeps a tuned number honest, because tuning one of them now fails a test
// that names the relationship it broke instead of silently un-bounding a
// control.

/// v22.0.0 (CIRISPersist#543 finding 4, AV-76) — how many attestation
/// writes ONE peer may land per [`PER_PEER_ATTESTATION_WRITE_WINDOW`]: the
/// **burst** allowance.
///
/// A **substrate constant**, deliberately not an operator knob (the
/// [`crate::witness::WITNESS_CORPUS_K`] precedent): a quota a deployer can
/// raise is a quota an attacker's deployment has already raised, and the
/// number exists to bound *substrate* amplification, not to express a
/// per-deployment policy. 600 writes / 60s = 10 writes/second sustained
/// from a single `attesting_key_id` — orders of magnitude above what any
/// honest replication peer, genesis bake, or bulk-ingest loop produces,
/// and far below what a bootstrap flooder needs to be interesting.
///
/// v24.3.0 (CIRISPersist#575) — the sentence above is still true about a
/// *minute*, and was catastrophically untrue about a *day*: unopposed, this
/// constant alone admitted 864,000 rows/day/peer, which is a runaway-loop
/// backstop and not an abuse control. The number is UNCHANGED — bursts are
/// honest — and the day is now bounded by
/// [`PER_PEER_SUSTAINED_WRITES_PER_WINDOW`], a second bucket charged by the
/// same write.
///
/// v25.1.0 (CIRISPersist#583) — and it is now explicitly the **many-small**
/// half of a two-dimensional control. A row count bounds the part of a
/// write's cost that does not vary with its payload (two signatures, the
/// hashes, the ids, the index entries); it is blind to the part that does,
/// which is what [`PER_PEER_ATTESTATION_BYTES_PER_WINDOW`] is for.
///
/// **Bounds:** rows one peer may land in one burst window — the fixed
/// per-row cost of storage, and the request rate the ingest path must serve.
/// **Derived:** 600 / 60 s = 10 writes/second sustained from a single
/// `attesting_key_id`; orders of magnitude above what any honest replication
/// peer, genesis bake, or bulk-ingest loop produces, and far below what a
/// bootstrap flooder needs to be interesting.
pub const PER_PEER_ATTESTATION_WRITES_PER_WINDOW: u32 = 600;

/// v22.0.0 (CIRISPersist#543 finding 4, AV-76) — the window
/// [`PER_PEER_ATTESTATION_WRITES_PER_WINDOW`] is measured over. Doubles as
/// the token bucket's refill period: tokens accrue continuously at
/// `WRITES_PER_WINDOW / WINDOW`, so a peer that has been idle for a full
/// window starts again with a full burst allowance.
///
/// **Bounds:** the horizon "too fast" is measured over — seconds, the
/// timescale an operator or a peer can react on by slowing down.
/// **Derived:** one minute is the shortest horizon on which a replication
/// round's shape is legible; shorter and an honest catch-up round looks like
/// a flood, longer and a flood looks like a round. Shared by BOTH metered
/// dimensions ([`QuotaDimension`]) so a burst is one thing, not two.
pub const PER_PEER_ATTESTATION_WRITE_WINDOW: Duration = Duration::from_secs(60);

/// v24.3.0 (CIRISPersist#575) — how many attestation writes ONE peer may
/// land per [`PER_PEER_SUSTAINED_WRITE_WINDOW`]: the **sustained** ceiling,
/// the half of the control that #575 found missing.
///
/// # Where the number comes from
///
/// It is *derived from the burst constant, not invented beside it.*
/// [`PER_PEER_ATTESTATION_WRITES_PER_WINDOW`] asserts that 600 writes in a
/// minute is honest — a catch-up round, a bake, a bulk-ingest loop. This
/// constant asserts the complementary thing: an honest author does not need
/// that burst **more than once an hour, forever**. So
///
/// ```text
/// 24 h/day × 600 writes/burst = 14 400 writes/day/peer
/// ```
///
/// and the bucket's refill rate is exactly one burst allowance per hour
/// (600/3600 s = 1 write / 6 s), with a capacity of one full day's worth so
/// an author that has been quiet accrues real catch-up credit rather than
/// being metered to a trickle.
///
/// That is a **60× reduction in the sustained rate** (36 000 rows/hour →
/// 600). Measured end to end against the v22 implementation, a peer walking
/// a full day spending everything on offer lands 864 600 rows before and
/// 28 800 after — 30×, not 60×, because the first day additionally spends
/// the day's capacity the bucket started full with. Both numbers are true
/// and the second is the one an operator feels;
/// `tests::one_peer_cannot_write_a_million_rows_in_a_day` asserts it.
///
/// At the ~1.5 KiB a typical federation-tier row occupies
/// ([`TYPICAL_ATTESTATION_ENVELOPE_BYTES`]) that is ≈21 MiB / day / peer at
/// steady state, which a volunteer node survives for years instead of days;
/// at the
/// [`MAX_ATTESTATION_ENVELOPE_BYTES`](crate::federation::admission::MAX_ATTESTATION_ENVELOPE_BYTES)
/// worst case it was still 14 GiB/day, which is why #575 ask (a) — a BYTE
/// dimension alongside the count — was the next thing this control needed.
/// A row count is a proxy for storage, and a poor one.
///
/// v25.1.0 (CIRISPersist#583) — **that dimension now exists**
/// ([`PER_PEER_SUSTAINED_BYTES_PER_WINDOW`]), and the 14 GiB/day worst case
/// is 211 MiB/day. This constant is unchanged and its job narrowed: it
/// bounds *rows*, and rows are the many-small attack.
///
/// # What it costs an honest peer
///
/// A backlog larger than 14 400 rows from a SINGLE author replays at
/// 600 rows/hour once the day's credit is spent. That is a real cost and
/// the reason it is acceptable is that the bucket keys on
/// `attesting_key_id` — the row's AUTHOR, not the peer that transmitted it
/// — so a bulk anti-entropy catch-up from one sender is spread across every
/// author in the mesh and meets a separate full bucket for each. A single
/// author with a six-figure history is the case this constant does throttle,
/// and the honest fix for it is #575 ask (d) (recipient-authored per-peer
/// policy), not a bigger substrate constant.
///
/// **Bounds:** rows one peer may land in a day — the fixed per-row storage
/// cost, accumulated on the horizon a disk feels.
/// **Derived:** `24 h/day × PER_PEER_ATTESTATION_WRITES_PER_WINDOW` — an
/// honest author does not need a full honest burst more than once an hour,
/// forever. Asserted as an identity by the derivation gate, so "tuning" this
/// number without restating the burst it comes from fails a test.
pub const PER_PEER_SUSTAINED_WRITES_PER_WINDOW: u32 = 14_400;

/// v24.3.0 (CIRISPersist#575) — the window
/// [`PER_PEER_SUSTAINED_WRITES_PER_WINDOW`] is measured over. One day: the
/// horizon #575 stated the gap in ("864 000 rows **per day** per peer"), and
/// the horizon on which a storage cost is felt.
///
/// **Bounds:** the horizon "too much, forever" is measured over — the one a
/// disk fills on.
/// **Derived:** one day: the horizon #575 stated the gap in ("864 000 rows
/// **per day** per peer"), and short enough that a peer that overruns it is
/// whole again tomorrow rather than banned. Shared by BOTH metered
/// dimensions ([`QuotaDimension`]).
pub const PER_PEER_SUSTAINED_WRITE_WINDOW: Duration = Duration::from_secs(86_400);

/// v25.1.0 (CIRISPersist#583) — the size of a **typical federation-tier
/// attestation envelope**, and the floor every write is charged on the byte
/// dimension.
///
/// This number is not new: it is the one
/// [`PER_PEER_SUSTAINED_WRITES_PER_WINDOW`]'s doc has cited since v24.3.0
/// ("the ~1.5 KiB a typical federation-tier row occupies") to argue that
/// 14 400 rows/day is ≈21 MiB/day. #583's point is that an argument made in
/// prose from a number that is not in the program is an argument nothing
/// checks. It is a program constant now, and the byte dimension is
/// calibrated from it.
///
/// # Why it is also a FLOOR
///
/// The byte dimension measures the envelope, because the envelope is the
/// attacker-controlled, unboundedly-variable part of a row. It is not the
/// whole cost: a row also carries two signatures (an ML-DSA-65 scrub
/// signature alone is ~4.4 KiB base64), hashes, ids and index entries, none
/// of which the envelope sees. So a write is charged
/// `max(envelope_bytes, TYPICAL_ATTESTATION_ENVELOPE_BYTES)` — no row costs
/// less than a typical row, and an empty envelope is not free storage.
///
/// **Bounds:** the smallest storage cost the byte dimension will admit a
/// write at, and the anchor the whole byte dimension is calibrated from.
/// **Derived:** 1.5 KiB, the typical federation-tier row size already stated
/// (and relied on) by the v24.3.0 sustained-rows derivation.
pub const TYPICAL_ATTESTATION_ENVELOPE_BYTES: u64 = 1_536;

/// v25.1.0 (CIRISPersist#583) — how many times a typical row's size a peer's
/// **mean** row may reach before the byte dimension binds instead of the row
/// dimension.
///
/// This is the whole trade the byte dimension makes, expressed as one
/// number. At `1` the byte ceiling would be exactly the row ceiling in
/// storage terms, and every peer whose rows are merely larger than typical
/// would be throttled by a control aimed at storage floods — a second row
/// control, and an AV-75 outage ("a control that refuses honest bulk
/// replication is an outage, not a gate"). At `∞` the byte dimension does
/// not exist, which is the #583 defect.
///
/// Ten says: a peer whose average row is up to ten typical rows is unmetered
/// by bytes and still metered by rows; past that, storage is what it is
/// spending and storage is what bounds it. The residual is stated rather
/// than hidden — a peer with a genuine six-figure backlog of 100 KiB rows
/// replays it slower than one with 1.5 KiB rows, and the honest fix for that
/// is #575 ask (d) (signed, recipient-authored per-peer policy), not a
/// bigger substrate constant.
///
/// **Bounds:** the mean row size at which the control switches from
/// "you are writing too many rows" to "you are writing too much storage".
/// **Derived:** ten typical rows — comfortably above any honest mean (the
/// stated typical is the mean), and 64× below the single-row cap
/// [`MAX_ATTESTATION_ENVELOPE_BYTES`](crate::federation::admission::MAX_ATTESTATION_ENVELOPE_BYTES),
/// so the rows this control does bind on are the *few huge* ones.
pub const QUOTA_BYTE_HEADROOM_MULTIPLE: u64 = 10;

/// v25.1.0 (CIRISPersist#583) — the row size the byte dimension is
/// calibrated against: `TYPICAL × HEADROOM` = 15 KiB.
///
/// Both byte constants below are this number times the corresponding row
/// constant, so the byte dimension is the row dimension re-priced in storage
/// and there is exactly ONE new free parameter in it
/// ([`QUOTA_BYTE_HEADROOM_MULTIPLE`]) rather than two magic sizes.
///
/// **Bounds:** the per-row storage price the byte budgets are sized at.
/// **Derived:** `TYPICAL_ATTESTATION_ENVELOPE_BYTES ×
/// QUOTA_BYTE_HEADROOM_MULTIPLE` = 1 536 × 10 = 15 360.
pub const QUOTA_CALIBRATION_ROW_BYTES: u64 = 15_360;

/// v25.1.0 (CIRISPersist#583) — how many **bytes** ONE peer may land per
/// [`PER_PEER_ATTESTATION_WRITE_WINDOW`]: the burst allowance on the second
/// metered dimension, and the *few-huge* half of the control.
///
/// # The gap this closes
///
/// #583, quoting CIRISServer: *"600 rows of 100 B and 600 rows of 10 MB cost
/// the same."* They did. `PeerBucket::spend` decremented a count and nothing
/// in the quota path read a payload size, so a peer at its full row
/// allowance could consume ~6 GB or ~60 KB and the substrate could not tell
/// the difference — **inauthentic storage was invisible to the control that
/// exists to bound it**. The single-envelope cap
/// ([`MAX_ATTESTATION_ENVELOPE_BYTES`](crate::federation::admission::MAX_ATTESTATION_ENVELOPE_BYTES),
/// CC#38 interim) bounds ONE row; nothing bounded the aggregate.
///
/// # Why a second dimension and not a smaller row count
///
/// Many-small and few-huge are different attacks. A row count bounds the
/// fixed per-row cost (signatures, hashes, index entries) and is blind to
/// the payload; a byte count bounds the payload and is blind to the fixed
/// cost — 14 400 empty envelopes cost real disk that a byte ceiling sized
/// for storage would wave through. **Each dimension bounds the part of the
/// cost the other cannot see**, which is why both are metered on the same
/// bucket and a write must clear both.
///
/// **Bounds:** bytes one peer may land in one burst window — the payload
/// half of storage, on the seconds horizon.
/// **Derived:** `PER_PEER_ATTESTATION_WRITES_PER_WINDOW ×
/// QUOTA_CALIBRATION_ROW_BYTES` = 600 × 15 360 = 9 216 000 B (8.79 MiB/min,
/// ≈150 KiB/s). Asserted as an identity by the derivation gate.
pub const PER_PEER_ATTESTATION_BYTES_PER_WINDOW: u64 = 9_216_000;

/// v25.1.0 (CIRISPersist#583) — how many **bytes** ONE peer may land per
/// [`PER_PEER_SUSTAINED_WRITE_WINDOW`]: the sustained storage ceiling.
///
/// # What it is worth
///
/// The v24.3.0 sustained-rows constant left a stated worst case of
/// **14 GiB/day/peer** (14 400 rows × the 1 MiB single-envelope cap). This
/// makes that worst case **211 MiB/day/peer** — a 68× reduction — and the
/// node-wide worst case 2.06 GiB/day
/// ([`NODE_INGEST_BUDGET_MULTIPLE`] peers' worth), which is a volunteer
/// node's disk over years rather than weeks. Honest traffic is nowhere near
/// it: at the typical 1.5 KiB row the row dimension binds first, at 21
/// MiB/day, and the byte budget is 90% unspent.
///
/// **Bounds:** bytes one peer may add to this node's disk in a day.
/// **Derived:** `PER_PEER_SUSTAINED_WRITES_PER_WINDOW ×
/// QUOTA_CALIBRATION_ROW_BYTES` = 14 400 × 15 360 = 221 184 000 B
/// (210.9 MiB/day) — equivalently `24 × PER_PEER_ATTESTATION_BYTES_PER_WINDOW`,
/// the same "one burst allowance per hour, forever" shape the sustained ROW
/// constant is derived by. Both identities are asserted by the derivation
/// gate.
pub const PER_PEER_SUSTAINED_BYTES_PER_WINDOW: u64 = 221_184_000;

/// v22.0.0 (CIRISPersist#543 finding 4, AV-76) — how many distinct peers
/// one [`PeerWriteQuota`] tracks.
///
/// The quota itself must not become the memory-amplification vector it
/// exists to close: without this cap a flooder rotating `attesting_key_id`
/// per write would grow the bucket map without bound. At the cap the map
/// evicts every bucket that has refilled to full (i.e. every peer idle for
/// a whole window — indistinguishable from one never seen), so the
/// retained set is bounded by *peers with live traffic*.
///
/// v24.3.0 (CIRISPersist#575) — this cap was **advisory, and inverted**.
/// Two defects, both closed here:
///
/// 1. *It did not bound anything.* The prune retained every bucket that had
///    not refilled to full and then inserted the new peer **unconditionally**
///    — so a flooder holding 4096 buckets at empty (exactly what a flooder
///    does) made the prune a no-op and grew the map past the cap for free,
///    paying an O(cap) scan on every rotated key. It is now a HARD bound: at
///    saturation an untracked peer is admitted against the shared tail
///    budget and no bucket is created.
/// 2. *A slot was a budget.* Every fresh `attesting_key_id` was born with a
///    full 600-write allowance, so 4096 slots were 2 457 600 free writes and
///    the cap was the multiplier — measured at 2 611 200, higher than
///    `cap × 600` precisely because defect 1 meant the cap did not bind.
///    Rotation now buys nothing: see [`UNTRACKED_TAIL_BUDGET_MULTIPLE`].
///
/// # v25.1.0 (CIRISPersist#583) — 4096 → 8192, and WHY a size is the fix
///
/// #583's second finding is the residue of that hard bound: *"once the table
/// saturates with live-spending peers, no new bucket is created and an
/// honest newcomer is demoted to the shared untracked tail the attacker is
/// saturating."* True, and reachable — an adversary holding `CAP` buckets
/// and touching all of them inside one sustained-token refill (6 s) makes
/// every bucket non-full at once, so the prune frees nothing and whoever
/// arrives next gets no individual budget.
///
/// The property to hold is #583's:
///
/// > **A peer with no history cannot degrade the service another peer
/// > already had, and the eviction rule cannot be steered by the party it is
/// > meant to bound.**
///
/// ## Why the eviction rule is NOT where the fix goes
///
/// #583 floats "evict by adversary-cost rather than by refill state". It is
/// the wrong lever, and the reason is worth writing down because it is not
/// obvious: **a fresh bucket is born FULL.** Therefore evicting a bucket
/// that still holds a deficit *hands its owner its spent budget back* — a
/// reset, which is exactly the primitive #575 closed. Evicting the emptiest
/// maximises that gift to the flooder; evicting the fullest minimises it but
/// still pays out (an identity that under-spends relative to the table
/// becomes the eviction target and recovers what it spent); evicting the
/// *oldest* is steerable by whoever writes most. The only eviction rule with
/// a payout of exactly zero is "evict buckets whose eviction is a no-op",
/// i.e. the full ones — which is what v24.3.0 already does. It is not
/// improvable; it is optimal. Seeding a fresh bucket from the tail instead
/// of full would unlock other rules, but then a rotation flood could evict
/// an honest peer's full bucket and the honest peer would return to a
/// *drained* one: a peer with no history degrading a peer that had service,
/// which is the property inverted.
///
/// ## So the fix is a size, and it is derived
///
/// If the table is larger than any schedule can hold non-full, the prune can
/// always free a slot and **the saturated branch is unreachable**. Every
/// non-full bucket cost the adversary at least one write, every write is
/// charged to the node budget, and one write keeps a bucket non-full for at
/// most its own refill time. So the worst case over all write sizes is
///
/// ```text
/// N_max = max over write costs c of
///           min over (dimension, horizon) of
///             (node_capacity + node_rate × w(c)) / c
///         where w(c) = the longest refill of ONE write of cost c
/// ```
///
/// which for the constants above peaks at **6 600** — the node burst
/// capacity (10 × 600 = 6 000) plus what refills during one sustained row
/// token's 6 s (600) — for every write cost from the typical row up to
/// [`QUOTA_CALIBRATION_ROW_BYTES`], and falls away above it because a bigger
/// payload buys a longer non-full window only by spending node BYTE budget
/// faster than it buys. (That the two dimensions meet exactly at the
/// calibration size is not a coincidence: it is what calibrating the byte
/// budget off the row budget means.) 8192 is the next power of two above the
/// peak, leaving ~24%
/// headroom, and `tests::the_tracked_table_is_larger_than_any_flood_can_hold`
/// re-derives `N_max` from the live constants by sweeping write costs, so
/// raising [`NODE_INGEST_BUDGET_MULTIPLE`] or shrinking this cap fails a
/// test that names the inequality it broke.
///
/// Memory: 8192 buckets × (a key id + 4 token pairs + an `Instant`) ≈ 1.5 MB
/// per backend instance. Doubling the cap doubles a megabyte and closes a
/// squeeze; that is the trade.
///
/// **Bounds:** the quota's own memory, AND (by being larger than any flood
/// can occupy) the reachability of the tail-squeeze — a peer with no history
/// always receives an individual budget.
/// **Derived:** the next power of two above `N_max` = 6 600, the largest
/// number of buckets the node budget can hold simultaneously non-full,
/// swept over write costs by the derivation gate.
pub const PER_PEER_QUOTA_TRACKED_PEERS_CAP: usize = 8192;

/// v24.3.0 (CIRISPersist#575) — the **untracked tail is one peer**.
///
/// Every write whose `attesting_key_id` has no bucket — genuinely new, or
/// pruned, or refused a slot because the table is saturated — is charged
/// against ONE shared budget pair sized at this multiple of a single peer's.
/// At `1`, a flooder holding one identity and a flooder holding ten million
/// have the same ceiling, because the ceiling is not per identity.
///
/// This is the structural half of the #575 amplifier fix. `attesting_key_id`
/// is attacker-chosen and, at this point in the chain, entirely
/// unauthenticated — the quota deliberately runs before the attester lookup.
/// A per-identity budget over free identities is not a budget, whatever the
/// tracking table does; the only thing that bounds it is an allowance that
/// does not multiply.
///
/// **Bounds:** what every identity this node has never seen may spend,
/// *together*, on every metered dimension.
/// **Derived:** 1 — one peer's worth. Not a judgement about generosity: any
/// value > 1 would still be a constant, and any value at all is fine as long
/// as it does not scale with the number of identities, which is the only
/// property that matters when identity is free.
pub const UNTRACKED_TAIL_BUDGET_MULTIPLE: u32 = 1;

/// v24.3.0 (CIRISPersist#575) — the node-wide federation-ingest ceiling, as
/// a multiple of one peer's budget: **ten peers writing at their individual
/// ceiling, simultaneously, forever** (6 000 writes/min and 144 000
/// writes/day across the whole `put_attestation` plane).
///
/// It exists because per-peer fairness and node capacity are different
/// questions and only the second one is about the disk. `CAP × per-peer` is
/// not a bound a node can survive (4096 × 14 400 = 59M rows/day), so a
/// bound on the *sum* is the only honest answer to "what can the federation
/// ingest plane cost this node".
///
/// Ten is a judgement, and the residual is stated rather than hidden: a mesh
/// whose federation ingest genuinely needs more than ten saturated peers has
/// outgrown a substrate constant, and the answer for it is #575 ask (d) —
/// signed, node-local, recipient-authored policy — not a larger number
/// guessed here.
///
/// # Why an aggregate ceiling is backpressure and not an outage
///
/// AV-75's lesson is that a gate which refuses honest operators is worse
/// than the hole it closes, so this one is only defensible because a refused
/// write is **not a lost row**: the quota runs before any mutation, so a
/// refused row leaves no trace, and the anti-entropy planes re-offer on the
/// next round by construction (the same property that lets a `Refused`
/// key-plane outcome be safe to re-offer). A ceiling therefore delays
/// replication; it does not drop it. What it *does* cost is round latency —
/// `put_attestation` signals this as `Err`, and an `Err` ends the caller's
/// current apply loop rather than skipping one row — so a saturated node
/// re-runs rounds instead of finishing them. That is the honest price of the
/// bound and the reason `retry_after_seconds` and the node-wide reasons are
/// carried out rather than collapsed.
///
/// The node-wide refusal reasons are deliberately
/// distinguishable on the wire ([`PeerQuotaRefusal::NodeBurst`] /
/// [`PeerQuotaRefusal::NodeSustained`]) so a peer can tell "you are too
/// fast" from "this node is full" and back off correctly; that discloses
/// aggregate saturation, which is a real if small widening of the gate's
/// information surface and is accepted for that reason.
///
/// **Bounds:** what the whole `put_attestation` federation-ingest plane may
/// cost this node — 6 000 rows/min and 144 000 rows/day, and (v25.1.0,
/// CIRISPersist#583) 87.9 MiB/min and 2.06 GiB/day of payload.
/// **Derived:** ten peers writing at their individual ceiling,
/// simultaneously, forever. A judgement, and the residual is on the record:
/// a mesh needing more than ten saturated peers has outgrown a substrate
/// constant and wants #575 ask (d). NOTE it is load-bearing twice — raising
/// it also raises how many buckets a flood can hold non-full, so
/// [`PER_PEER_QUOTA_TRACKED_PEERS_CAP`] must rise with it or the derivation
/// gate fails.
pub const NODE_INGEST_BUDGET_MULTIPLE: u32 = 10;

/// v24.3.0 (CIRISPersist#575) — the **reserved admission class** budget, as
/// a multiple of one peer's: one peer's worth, node-wide, that ordinary
/// traffic can never consume.
///
/// #575 ships a caveat with any tightening, and it is the important half:
/// *bounded caps convert a flood into a censorship primitive.* A
/// quota-compliant flood that fills the admission budget crowds out
/// everyone — including an accord kill-switch or a reverse-quorum objection
/// (#574), which are exactly the rows that must never be crowded out. So the
/// reserved class is charged against its OWN bucket pair and against nothing
/// else: not the node budget, not the peer's, not the tail's. An accord row
/// arriving into a fully saturated node still has a path.
///
/// **Residual, stated plainly:** the class is decided by
/// [`PeerWriteQuota::classify`], a pure predicate over the row's dimension,
/// and a pure predicate is forgeable — a flooder that shapes its traffic as
/// `accord:*` exhausts the reserve. Those rows are refused a few gates later
/// by the `accord:` emitter rule (which requires `accord_holder` in the
/// attester's `identity_type`), but the reserve has already been spent by
/// then, because *verifying* the class costs a directory read and this gate
/// consults no shared state by construction. Closing that is #575 ask (d).
/// What ships here is strictly better than nothing: any flood not
/// specifically shaped at the reserved class leaves objections a path.
///
/// **Bounds:** what the accord/objection family may spend, on a budget no
/// ordinary traffic can consume — so a quota-compliant flood cannot become a
/// censorship primitive against a kill-switch.
/// **Derived:** 1 — one peer's worth. It has to be *some* finite number (a
/// bypass would be a hole shaped exactly like the pure, forgeable class
/// predicate that decides it), and one peer's ceiling is the smallest
/// allowance that provably serves a real accord round.
pub const RESERVED_CLASS_BUDGET_MULTIPLE: u32 = 1;

/// v24.3.0 (CIRISPersist#575) — the dimension prefixes that put a row in the
/// [reserved admission class](RESERVED_CLASS_BUDGET_MULTIPLE). Closed, and
/// short on purpose: every prefix here is budget that ordinary traffic cannot
/// reach, so the set is a cost as well as a protection.
///
/// - `accord:*` — the accord kill-switch / halt / lifecycle family. An
///   existing closed concept, not one invented for the quota:
///   [`DimensionAdmissionPolicy`](crate::federation::admission::DimensionAdmissionPolicy)
///   already restricts it to attesters carrying
///   [`identity_type::ACCORD_HOLDER`](crate::federation::types::identity_type::ACCORD_HOLDER).
/// - `objection:*` — the #574 reverse-quorum family (`objection:raised:v1`,
///   `objection:dismissed:v1`). #575 names these rows specifically: *"#574 —
///   reverse quorum — its objections are exactly the rows that must never be
///   crowded out."* A reserve that omitted them would protect the wrong
///   half of the ask.
///
/// # A deliberate copy, with its retirement condition written down
///
/// That second entry is a **string copy of a namespace family #574 owns**,
/// and copying a vocabulary is the two-lists-that-disagree class. It is here
/// anyway because this cut is parented on `main`, where the reverse-quorum
/// module does not yet exist, so the constant cannot be *referenced* — and
/// the alternative was leaving the exact rows the issue names unprotected
/// until the planes meet.
///
/// **When #574 and #575 land in one tree, replace `"objection:"` with a
/// reference to `reverse_quorum::NAMESPACE_FAMILY`** so the prefix and the
/// dimensions that ride it cannot drift apart. One predicate, one
/// implementation; this is the exception that names its own end.
///
/// **Bounds:** which rows can reach the reserve — and therefore, since the
/// reserve is budget ordinary traffic cannot use, how much of this node's
/// admission capacity is unreachable to ordinary traffic.
/// **Derived:** the two families #575 names as the ones that must never be
/// crowded out (the accord kill-switch / lifecycle family, and #574's
/// reverse-quorum objections) and nothing else — every added prefix is a
/// cost as well as a protection.
pub const RESERVED_CLASS_DIMENSION_PREFIXES: &[&str] = &["accord:", "objection:"];

// ──────────────────────── QUOTA CONSTANTS — END ────────────────────────

/// v25.1.0 (CIRISPersist#583) — **what the quota meters.** Closed, and the
/// set is load-bearing: the implementation indexes its budgets and its
/// per-write costs BY this enum, so a variant added here is a compile error
/// everywhere a dimension must be priced, sized and refused — and
/// `tests::every_metered_dimension_has_a_witness` fails until a witness
/// drives a real refusal on it.
///
/// That mechanism is #583's actual lesson. The row dimension shipped in
/// v22.0.0 without a byte sibling *because nothing asserted the set was
/// complete*: there was no set, only a field. A taxonomy that a test can
/// enumerate is one a reviewer can find a hole in.
///
/// # The two dimensions, and why neither subsumes the other
///
/// - [`Self::Rows`] bounds the part of a write's cost that does not vary
///   with the payload: two signatures, hashes, ids, index entries, and the
///   request the ingest path has to serve. Blind to payload size — 600 rows
///   of 100 B and 600 rows of 10 MB cost it the same, which is #583.
/// - [`Self::Bytes`] bounds the payload. Blind to the fixed cost — 14 400
///   empty envelopes are free to it, and they are not free to the disk.
///
/// Many-small and few-huge are different attacks; each dimension bounds the
/// part of the cost the other cannot see. Both are metered on the SAME
/// bucket, and a write must clear both.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, serde::Serialize, serde::Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum QuotaDimension {
    /// One row, whatever it contains. The v22.0.0 dimension.
    Rows,
    /// The row's storage cost in bytes:
    /// `max(envelope_bytes, TYPICAL_ATTESTATION_ENVELOPE_BYTES)`.
    /// v25.1.0 (CIRISPersist#583).
    Bytes,
}

impl QuotaDimension {
    /// Every dimension, in declaration order. The index into a budget's
    /// per-dimension spec and a write's per-dimension cost is
    /// [`Self::index`], so this slice and those arrays cannot disagree.
    pub const ALL: &'static [Self] = &[Self::Rows, Self::Bytes];

    /// How many dimensions the quota meters. `[T; COUNT]` is how every
    /// per-dimension array is sized, so adding a variant that is not counted
    /// here does not compile.
    pub const COUNT: usize = 2;

    /// Dense index for the per-dimension arrays.
    #[must_use]
    pub const fn index(self) -> usize {
        match self {
            Self::Rows => 0,
            Self::Bytes => 1,
        }
    }

    /// The stable program token, identical to the serde token.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Rows => "rows",
            Self::Bytes => "bytes",
        }
    }
}

/// v25.1.0 (CIRISPersist#583) — **which budget** a write is charged against.
/// Closed; the four #575 shipped, named so the refusal taxonomy can be
/// generated from `budget × dimension × horizon` instead of hand-listed.
///
/// v38.0.0 (CIRISPersist#609): `Ord` + serde so the refusal counters can key
/// a canonical map on it — the enum serializes as its snake_case token, which
/// is what makes it a legal JSON map key.
#[derive(
    Debug, Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord, serde::Serialize, serde::Deserialize,
)]
#[serde(rename_all = "snake_case")]
pub enum QuotaBudget {
    /// This author's own bucket. Fairness.
    Peer,
    /// The shared budget for identities with no bucket
    /// ([`UNTRACKED_TAIL_BUDGET_MULTIPLE`]).
    UntrackedTail,
    /// The node-wide ordinary ceiling ([`NODE_INGEST_BUDGET_MULTIPLE`]).
    /// Capacity.
    Node,
    /// The reserved admission class ([`RESERVED_CLASS_BUDGET_MULTIPLE`]).
    Reserved,
}

impl QuotaBudget {
    /// Every budget, in declaration order.
    pub const ALL: &'static [Self] = &[Self::Peer, Self::UntrackedTail, Self::Node, Self::Reserved];

    /// The stable token — the same spelling serde emits.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Peer => "peer",
            Self::UntrackedTail => "untracked_tail",
            Self::Node => "node",
            Self::Reserved => "reserved",
        }
    }

    /// Index into [`Self::ALL`] — the refusal counters' array key.
    const fn idx(self) -> usize {
        match self {
            Self::Peer => 0,
            Self::UntrackedTail => 1,
            Self::Node => 2,
            Self::Reserved => 3,
        }
    }
}

/// v25.1.0 (CIRISPersist#583) — **which horizon** a refusal came from. Every
/// budget meters every dimension on both.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum QuotaHorizon {
    /// [`PER_PEER_ATTESTATION_WRITE_WINDOW`] — seconds. "Slow down."
    Burst,
    /// [`PER_PEER_SUSTAINED_WRITE_WINDOW`] — a day. "Too much, forever."
    Sustained,
}

impl QuotaHorizon {
    /// Both horizons, in refusal-precedence order (burst first: it is the
    /// one that clears soonest, so it is the more actionable retry hint).
    pub const ALL: &'static [Self] = &[Self::Burst, Self::Sustained];
}

/// v24.3.0 (CIRISPersist#575) — **WHICH budget refused** a write.
///
/// A quota that answers `RateLimited` and nothing else sends its reader into
/// the same disjunction #565 spent a day inside on the Key plane: *your
/// burst? your day? the node? the shared tail?* — four different operator
/// actions behind one token. A refusal is a verdict, and a verdict without
/// its evidence sends the reader to the wrong layer.
///
/// **Closed**, and every variant corresponds to exactly ONE condition in
/// `PeerWriteQuota::charge` — deliberately no `Other`, because a
/// catch-all reintroduces the disjunction one name deeper. Serde tokens are
/// snake_case and [`Self::as_str`] returns the SAME token, so a consumer
/// keys on a program constant and never on a message string. The token set
/// is the downstream contract and this mapping is **APPEND-ONLY**: add
/// variants, never re-spell one.
///
/// # v25.1.0 (CIRISPersist#583) — the set is now a PRODUCT
///
/// It is exactly `QuotaBudget × QuotaDimension × QuotaHorizon` (4 × 2 × 2 =
/// 16), generated by [`Self::of`] and asserted complete by
/// `tests::every_metered_dimension_has_a_witness`. The eight v24.3.0 tokens
/// are the `Rows` half and keep their spelling **unchanged** — `peer_burst`,
/// not `peer_rows_burst` — because downstream is already keying on them and
/// the contract is append-only. The eight new ones carry `_bytes_`
/// (`peer_bytes_burst`, `node_bytes_sustained`, …), which is what #583 asks
/// for and what lets an operator tell a **row flood** from a **storage
/// flood** without reading a message string.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, serde::Serialize, serde::Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum PeerQuotaRefusal {
    /// This peer's own **burst** bucket is out of ROW tokens: more than
    /// [`PER_PEER_ATTESTATION_WRITES_PER_WINDOW`] writes inside
    /// [`PER_PEER_ATTESTATION_WRITE_WINDOW`]. Slow down; the budget returns
    /// within seconds.
    PeerBurst,
    /// This peer's own **sustained** bucket is out of ROW tokens: more than
    /// [`PER_PEER_SUSTAINED_WRITES_PER_WINDOW`] writes inside
    /// [`PER_PEER_SUSTAINED_WRITE_WINDOW`]. The burst was fine; the *day*
    /// is not. This is the refusal #575 exists to make possible.
    PeerSustained,
    /// The shared **untracked tail**'s burst bucket is out of ROW tokens.
    /// The write came from an `attesting_key_id` this quota holds no bucket
    /// for, and the one-peer-sized tail budget that all such identities
    /// share is spent. Rotating to another new identity does not help —
    /// that is the point.
    UntrackedTailBurst,
    /// The shared **untracked tail**'s sustained ROW budget is spent. As
    /// [`Self::UntrackedTailBurst`], on the day horizon.
    UntrackedTailSustained,
    /// The **node-wide** federation-ingest burst ROW budget is spent
    /// ([`NODE_INGEST_BUDGET_MULTIPLE`] peers' worth). Not about this peer:
    /// the node is full. Distinguishable on purpose — a peer that cannot
    /// tell this from [`Self::PeerBurst`] cannot back off correctly.
    NodeBurst,
    /// The **node-wide** federation-ingest sustained ROW budget is spent. As
    /// [`Self::NodeBurst`], on the day horizon.
    NodeSustained,
    /// The **reserved class**'s burst ROW budget is spent. Only rows in the
    /// reserved class ([`RESERVED_CLASS_DIMENSION_PREFIXES`]) can spend it and
    /// only they can exhaust it — ordinary traffic never touches it, so this
    /// refusal means accord-class traffic itself is flooding.
    ReservedBurst,
    /// The **reserved class**'s sustained ROW budget is spent. As
    /// [`Self::ReservedBurst`], on the day horizon.
    ReservedSustained,
    /// v25.1.0 (CIRISPersist#583) — this peer's own **burst** BYTE budget is
    /// spent: more than [`PER_PEER_ATTESTATION_BYTES_PER_WINDOW`] of payload
    /// inside [`PER_PEER_ATTESTATION_WRITE_WINDOW`]. A **storage** flood,
    /// not a row flood — the peer is well inside its row allowance and is
    /// still costing too much disk. Distinguishable from
    /// [`Self::PeerBurst`] precisely so an operator does not tune the wrong
    /// number.
    PeerBytesBurst,
    /// v25.1.0 (CIRISPersist#583) — this peer's own **sustained** BYTE
    /// budget is spent ([`PER_PEER_SUSTAINED_BYTES_PER_WINDOW`] in a day).
    /// The one #583 exists to make possible: the day's *storage*, not the
    /// day's rows.
    PeerBytesSustained,
    /// v25.1.0 (CIRISPersist#583) — the shared **untracked tail**'s burst
    /// BYTE budget is spent. Identities this node has never seen have,
    /// together, sent too much payload too fast; rotating does not help.
    UntrackedTailBytesBurst,
    /// v25.1.0 (CIRISPersist#583) — the shared **untracked tail**'s
    /// sustained BYTE budget is spent. As
    /// [`Self::UntrackedTailBytesBurst`], on the day horizon.
    UntrackedTailBytesSustained,
    /// v25.1.0 (CIRISPersist#583) — the **node-wide** burst BYTE budget is
    /// spent. The node's federation-ingest write bandwidth is full; not
    /// about this peer.
    NodeBytesBurst,
    /// v25.1.0 (CIRISPersist#583) — the **node-wide** sustained BYTE budget
    /// is spent: this node has taken its day's federation-ingest storage.
    NodeBytesSustained,
    /// v25.1.0 (CIRISPersist#583) — the **reserved class**'s burst BYTE
    /// budget is spent. Only accord/objection-class rows can reach it, so
    /// this means accord-class traffic itself is a storage flood.
    ReservedBytesBurst,
    /// v25.1.0 (CIRISPersist#583) — the **reserved class**'s sustained BYTE
    /// budget is spent. As [`Self::ReservedBytesBurst`], on the day horizon.
    ReservedBytesSustained,
}

impl PeerQuotaRefusal {
    /// The **stable program token** for this reason — identical to the serde
    /// token, so a consumer that reads the wire and a consumer that holds
    /// the typed value key on the same constant.
    #[must_use]
    pub const fn as_str(&self) -> &'static str {
        match self {
            Self::PeerBurst => "peer_burst",
            Self::PeerSustained => "peer_sustained",
            Self::UntrackedTailBurst => "untracked_tail_burst",
            Self::UntrackedTailSustained => "untracked_tail_sustained",
            Self::NodeBurst => "node_burst",
            Self::NodeSustained => "node_sustained",
            Self::ReservedBurst => "reserved_burst",
            Self::ReservedSustained => "reserved_sustained",
            Self::PeerBytesBurst => "peer_bytes_burst",
            Self::PeerBytesSustained => "peer_bytes_sustained",
            Self::UntrackedTailBytesBurst => "untracked_tail_bytes_burst",
            Self::UntrackedTailBytesSustained => "untracked_tail_bytes_sustained",
            Self::NodeBytesBurst => "node_bytes_burst",
            Self::NodeBytesSustained => "node_bytes_sustained",
            Self::ReservedBytesBurst => "reserved_bytes_burst",
            Self::ReservedBytesSustained => "reserved_bytes_sustained",
        }
    }

    /// v25.1.0 (CIRISPersist#583) — **the taxonomy as a function**, not a
    /// list. The refusal for one `(budget, dimension, horizon)` triple.
    ///
    /// This is the single place the product is spelled, so the enum cannot
    /// quietly stop covering it: add a [`QuotaDimension`] and this match
    /// stops compiling until the variants exist.
    #[must_use]
    pub const fn of(budget: QuotaBudget, dimension: QuotaDimension, horizon: QuotaHorizon) -> Self {
        match (budget, dimension, horizon) {
            (QuotaBudget::Peer, QuotaDimension::Rows, QuotaHorizon::Burst) => Self::PeerBurst,
            (QuotaBudget::Peer, QuotaDimension::Rows, QuotaHorizon::Sustained) => {
                Self::PeerSustained
            }
            (QuotaBudget::Peer, QuotaDimension::Bytes, QuotaHorizon::Burst) => Self::PeerBytesBurst,
            (QuotaBudget::Peer, QuotaDimension::Bytes, QuotaHorizon::Sustained) => {
                Self::PeerBytesSustained
            }
            (QuotaBudget::UntrackedTail, QuotaDimension::Rows, QuotaHorizon::Burst) => {
                Self::UntrackedTailBurst
            }
            (QuotaBudget::UntrackedTail, QuotaDimension::Rows, QuotaHorizon::Sustained) => {
                Self::UntrackedTailSustained
            }
            (QuotaBudget::UntrackedTail, QuotaDimension::Bytes, QuotaHorizon::Burst) => {
                Self::UntrackedTailBytesBurst
            }
            (QuotaBudget::UntrackedTail, QuotaDimension::Bytes, QuotaHorizon::Sustained) => {
                Self::UntrackedTailBytesSustained
            }
            (QuotaBudget::Node, QuotaDimension::Rows, QuotaHorizon::Burst) => Self::NodeBurst,
            (QuotaBudget::Node, QuotaDimension::Rows, QuotaHorizon::Sustained) => {
                Self::NodeSustained
            }
            (QuotaBudget::Node, QuotaDimension::Bytes, QuotaHorizon::Burst) => Self::NodeBytesBurst,
            (QuotaBudget::Node, QuotaDimension::Bytes, QuotaHorizon::Sustained) => {
                Self::NodeBytesSustained
            }
            (QuotaBudget::Reserved, QuotaDimension::Rows, QuotaHorizon::Burst) => {
                Self::ReservedBurst
            }
            (QuotaBudget::Reserved, QuotaDimension::Rows, QuotaHorizon::Sustained) => {
                Self::ReservedSustained
            }
            (QuotaBudget::Reserved, QuotaDimension::Bytes, QuotaHorizon::Burst) => {
                Self::ReservedBytesBurst
            }
            (QuotaBudget::Reserved, QuotaDimension::Bytes, QuotaHorizon::Sustained) => {
                Self::ReservedBytesSustained
            }
        }
    }

    /// Which dimension this refusal came from — a **row** flood or a
    /// **storage** flood. v25.1.0 (CIRISPersist#583); the distinction is the
    /// whole reason the byte tokens are separate names.
    #[must_use]
    pub const fn dimension(&self) -> QuotaDimension {
        match self {
            Self::PeerBurst
            | Self::PeerSustained
            | Self::UntrackedTailBurst
            | Self::UntrackedTailSustained
            | Self::NodeBurst
            | Self::NodeSustained
            | Self::ReservedBurst
            | Self::ReservedSustained => QuotaDimension::Rows,
            Self::PeerBytesBurst
            | Self::PeerBytesSustained
            | Self::UntrackedTailBytesBurst
            | Self::UntrackedTailBytesSustained
            | Self::NodeBytesBurst
            | Self::NodeBytesSustained
            | Self::ReservedBytesBurst
            | Self::ReservedBytesSustained => QuotaDimension::Bytes,
        }
    }

    /// Which budget refused. v25.1.0 (CIRISPersist#583).
    #[must_use]
    pub const fn budget(&self) -> QuotaBudget {
        match self {
            Self::PeerBurst
            | Self::PeerSustained
            | Self::PeerBytesBurst
            | Self::PeerBytesSustained => QuotaBudget::Peer,
            Self::UntrackedTailBurst
            | Self::UntrackedTailSustained
            | Self::UntrackedTailBytesBurst
            | Self::UntrackedTailBytesSustained => QuotaBudget::UntrackedTail,
            Self::NodeBurst
            | Self::NodeSustained
            | Self::NodeBytesBurst
            | Self::NodeBytesSustained => QuotaBudget::Node,
            Self::ReservedBurst
            | Self::ReservedSustained
            | Self::ReservedBytesBurst
            | Self::ReservedBytesSustained => QuotaBudget::Reserved,
        }
    }

    /// Which horizon refused — seconds or a day. v25.1.0 (CIRISPersist#583).
    #[must_use]
    pub const fn horizon(&self) -> QuotaHorizon {
        match self {
            Self::PeerBurst
            | Self::UntrackedTailBurst
            | Self::NodeBurst
            | Self::ReservedBurst
            | Self::PeerBytesBurst
            | Self::UntrackedTailBytesBurst
            | Self::NodeBytesBurst
            | Self::ReservedBytesBurst => QuotaHorizon::Burst,
            Self::PeerSustained
            | Self::UntrackedTailSustained
            | Self::NodeSustained
            | Self::ReservedSustained
            | Self::PeerBytesSustained
            | Self::UntrackedTailBytesSustained
            | Self::NodeBytesSustained
            | Self::ReservedBytesSustained => QuotaHorizon::Sustained,
        }
    }

    /// Every variant, in declaration order — the closed set, for exhaustive
    /// gates and for a consumer enumerating the taxonomy it must handle.
    pub const ALL: &'static [Self] = &[
        Self::PeerBurst,
        Self::PeerSustained,
        Self::UntrackedTailBurst,
        Self::UntrackedTailSustained,
        Self::NodeBurst,
        Self::NodeSustained,
        Self::ReservedBurst,
        Self::ReservedSustained,
        Self::PeerBytesBurst,
        Self::PeerBytesSustained,
        Self::UntrackedTailBytesBurst,
        Self::UntrackedTailBytesSustained,
        Self::NodeBytesBurst,
        Self::NodeBytesSustained,
        Self::ReservedBytesBurst,
        Self::ReservedBytesSustained,
    ];
}

impl std::fmt::Display for PeerQuotaRefusal {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(self.as_str())
    }
}

/// v24.3.0 (CIRISPersist#575) — the typed refusal a quota check returns:
/// WHICH budget, and how long until one token has accrued in it.
///
/// Converts into [`crate::federation::Error::RateLimited`] via [`From`], so
/// the three backends' `put_attestation` call sites keep their bare `?`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct PeerQuotaRefused {
    /// WHICH budget refused. A closed enum, not a message string.
    pub reason: PeerQuotaRefusal,
    /// Wall-clock seconds until one token has accrued in that budget.
    /// Always ≥ 1 — a retry hint of 0 is an invitation to spin.
    pub retry_after_seconds: u64,
}

impl std::fmt::Display for PeerQuotaRefused {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(
            f,
            "{} exhausted; retry after {}s",
            self.reason, self.retry_after_seconds
        )
    }
}

impl From<PeerQuotaRefused> for crate::federation::Error {
    fn from(refused: PeerQuotaRefused) -> Self {
        crate::federation::Error::RateLimited {
            retry_after_seconds: refused.retry_after_seconds,
            // v24.3.0 (CIRISPersist#575) — the typed reason survives the
            // conversion instead of being dropped at the wire boundary.
            reason: refused.reason,
        }
    }
}

/// v24.3.0 (CIRISPersist#575) — which budget a write is charged against.
/// Closed, and decided by [`PeerWriteQuota::classify`] — a pure predicate
/// over the row, because this gate reads no shared state.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum WriteAdmissionClass {
    /// Everything. Charged against the node budget AND (this peer's bucket
    /// OR the shared untracked tail).
    Ordinary,
    /// [`RESERVED_CLASS_DIMENSION_PREFIXES`] rows — the accord kill-switch /
    /// objection family. Charged against the reserve and nothing else, so an
    /// ordinary flood can never crowd them out.
    Reserved,
    /// v31.1.0 (CIRISPersist#665 review) — a row CLAIMING a baked genesis
    /// delegation id. Charged against the node budget and the shared untracked
    /// tail, and **never given a peer bucket**.
    ///
    /// # Why this is not [`Reserved`](Self::Reserved), and not [`Ordinary`](Self::Ordinary)
    ///
    /// It was `Reserved` for one release and that was wrong. The quota runs at
    /// TIER 0, before any signature is checked, so at classification time
    /// `attesting_key_id = "A1"` is a CLAIM and a claim is free — an
    /// unauthenticated peer could spend the budget that exists to keep accord
    /// objections writable, with rows `verify_federation_tier_ingest` was about
    /// to reject. That is the same DoS this cut moved the reservation gate
    /// forward to close, re-opened one budget over: the gate authenticates
    /// nothing, it only checks that the CLAIMED key is on the roster.
    ///
    /// It cannot be `Ordinary` either, for the reason the class was introduced:
    /// `Ordinary` promotes the writer to a tracked peer bucket, and the node's
    /// own boot seed is not a peer. A fresh node reporting one observed peer
    /// lifts `node_state`'s peer-quota band out of `unknown` into `green` and
    /// destroys the distinction between "clean" and "never exercised".
    ///
    /// So it is charged where an unauthenticated stranger belongs — the node
    /// budget and the shared tail, both of which any peer can already spend, so
    /// no NEW scarcity is exposed — and is denied a bucket, which is strictly
    /// MORE restrictive for an attacker (the tail is shared and small, where a
    /// bucket would have been their own) and exactly right for the seed.
    ///
    /// The genesis rows lose the reserve's flood protection. That is the honest
    /// trade: they are written once at boot, and a node whose NODE budget is
    /// exhausted at boot fails the seed to `Absent`, which boots. Protecting
    /// them with a budget an unauthenticated claim can drain protects nothing.
    GenesisClaim,
}

/// One horizon of one dimension of one budget: a capacity and a continuous
/// refill rate.
#[derive(Debug, Clone, Copy)]
struct HorizonSpec {
    capacity: f64,
    per_second: f64,
}

impl HorizonSpec {
    fn new(capacity: f64, window: Duration) -> Self {
        Self {
            capacity,
            per_second: capacity / window.as_secs_f64(),
        }
    }
}

/// One dimension of one budget, on both horizons.
#[derive(Debug, Clone, Copy)]
struct DimensionSpec {
    burst: HorizonSpec,
    sustained: HorizonSpec,
}

impl DimensionSpec {
    fn horizon(&self, horizon: QuotaHorizon) -> &HorizonSpec {
        match horizon {
            QuotaHorizon::Burst => &self.burst,
            QuotaHorizon::Sustained => &self.sustained,
        }
    }
}

/// v24.3.0 (CIRISPersist#575) — one budget's capacity and continuous refill
/// rate on both horizons. Derived from the substrate constants by
/// [`Self::for_multiple`]; there are no free-floating numbers below this
/// line.
///
/// v25.1.0 (CIRISPersist#583) — indexed by [`QuotaDimension`]. The array is
/// `[_; QuotaDimension::COUNT]` and `for_multiple` matches exhaustively on
/// the enum, so **a dimension cannot be added without being sized**: the
/// compiler asks for its capacities before the code builds.
#[derive(Debug, Clone, Copy)]
struct BudgetSpec {
    dims: [DimensionSpec; QuotaDimension::COUNT],
}

impl BudgetSpec {
    /// `multiple` peers' worth of budget, on every dimension and horizon.
    fn for_multiple(multiple: u32) -> Self {
        let m = f64::from(multiple);
        #[allow(clippy::cast_precision_loss)]
        let per_dim = |d: QuotaDimension| match d {
            QuotaDimension::Rows => DimensionSpec {
                burst: HorizonSpec::new(
                    f64::from(PER_PEER_ATTESTATION_WRITES_PER_WINDOW) * m,
                    PER_PEER_ATTESTATION_WRITE_WINDOW,
                ),
                sustained: HorizonSpec::new(
                    f64::from(PER_PEER_SUSTAINED_WRITES_PER_WINDOW) * m,
                    PER_PEER_SUSTAINED_WRITE_WINDOW,
                ),
            },
            QuotaDimension::Bytes => DimensionSpec {
                burst: HorizonSpec::new(
                    PER_PEER_ATTESTATION_BYTES_PER_WINDOW as f64 * m,
                    PER_PEER_ATTESTATION_WRITE_WINDOW,
                ),
                sustained: HorizonSpec::new(
                    PER_PEER_SUSTAINED_BYTES_PER_WINDOW as f64 * m,
                    PER_PEER_SUSTAINED_WRITE_WINDOW,
                ),
            },
        };
        let mut dims = [per_dim(QuotaDimension::Rows); QuotaDimension::COUNT];
        for d in QuotaDimension::ALL {
            dims[d.index()] = per_dim(*d);
        }
        Self { dims }
    }

    fn dim(&self, dimension: QuotaDimension) -> &DimensionSpec {
        &self.dims[dimension.index()]
    }
}

/// v25.1.0 (CIRISPersist#583) — what ONE write costs, per metered dimension.
///
/// Also indexed by [`QuotaDimension`] and built by an exhaustive match, so a
/// new dimension must be *priced* as well as sized before anything compiles.
/// That pair — priced and sized — is what "the quota meters this dimension"
/// means mechanically, and it is what nothing asserted before #583.
#[derive(Debug, Clone, Copy)]
struct WriteCost {
    per_dimension: [f64; QuotaDimension::COUNT],
}

impl WriteCost {
    /// The cost of a write whose envelope serializes to `envelope_bytes`.
    ///
    /// Bytes are floored at [`TYPICAL_ATTESTATION_ENVELOPE_BYTES`]: the
    /// envelope is the variable part of a row's storage cost, not the whole
    /// of it (two signatures, hashes, ids and index entries ride along), so
    /// an empty envelope is not free disk.
    #[allow(clippy::cast_precision_loss)]
    fn for_envelope_bytes(envelope_bytes: u64) -> Self {
        let charged = envelope_bytes.max(TYPICAL_ATTESTATION_ENVELOPE_BYTES);
        let price = |d: QuotaDimension| match d {
            QuotaDimension::Rows => 1.0,
            QuotaDimension::Bytes => charged as f64,
        };
        let mut per_dimension = [0.0; QuotaDimension::COUNT];
        for d in QuotaDimension::ALL {
            per_dimension[d.index()] = price(*d);
        }
        Self { per_dimension }
    }

    /// The cost of a write whose size the caller does not know — one typical
    /// row. Used by the key-only [`PeerWriteQuota::check`] entry point, which
    /// has no envelope: a caller that cannot say how big its row is is
    /// charged the floor, never zero. A dimension with a free door is a
    /// dimension that is not metered.
    fn floor() -> Self {
        Self::for_envelope_bytes(0)
    }

    fn of(&self, dimension: QuotaDimension) -> f64 {
        self.per_dimension[dimension.index()]
    }
}

/// One dimension's token pair inside one bucket.
#[derive(Debug, Clone, Copy)]
struct DimensionTokens {
    burst: f64,
    sustained: f64,
}

impl DimensionTokens {
    fn horizon_mut(&mut self, horizon: QuotaHorizon) -> &mut f64 {
        match horizon {
            QuotaHorizon::Burst => &mut self.burst,
            QuotaHorizon::Sustained => &mut self.sustained,
        }
    }

    fn horizon(&self, horizon: QuotaHorizon) -> f64 {
        match horizon {
            QuotaHorizon::Burst => self.burst,
            QuotaHorizon::Sustained => self.sustained,
        }
    }
}

/// One budget's tokens. Every count is fractional so the refill is
/// continuous rather than stepped at window boundaries, and one write spends
/// from EVERY (dimension, horizon) cell — the burst horizon bounds the
/// second, the sustained horizon bounds the day, the row dimension bounds
/// the fixed cost, the byte dimension bounds the payload, and a write has to
/// clear all of them.
#[derive(Debug, Clone, Copy)]
struct PeerBucket {
    tokens: [DimensionTokens; QuotaDimension::COUNT],
    last_seen: Instant,
}

impl PeerBucket {
    /// A budget at full allowance as of `now`.
    fn full(spec: &BudgetSpec, now: Instant) -> Self {
        let mut tokens = [DimensionTokens {
            burst: 0.0,
            sustained: 0.0,
        }; QuotaDimension::COUNT];
        for d in QuotaDimension::ALL {
            let s = spec.dim(*d);
            tokens[d.index()] = DimensionTokens {
                burst: s.burst.capacity,
                sustained: s.sustained.capacity,
            };
        }
        Self {
            tokens,
            last_seen: now,
        }
    }

    /// Accrue tokens for the elapsed time, capped at capacity, on every
    /// dimension and horizon.
    fn refill(&mut self, spec: &BudgetSpec, now: Instant) {
        let elapsed = now.saturating_duration_since(self.last_seen).as_secs_f64();
        for d in QuotaDimension::ALL {
            let s = *spec.dim(*d);
            let t = &mut self.tokens[d.index()];
            for h in QuotaHorizon::ALL {
                let hs = s.horizon(*h);
                let cell = t.horizon_mut(*h);
                *cell = (*cell + elapsed * hs.per_second).min(hs.capacity);
            }
        }
        self.last_seen = now;
    }

    /// `None` if `cost` is affordable in EVERY cell; otherwise the refusal
    /// naming the first cell that cannot pay.
    ///
    /// Precedence: burst horizon before sustained (it is the one that clears
    /// soonest, so it is the more actionable retry hint when both are
    /// short), and within a horizon, dimensions in [`QuotaDimension::ALL`]
    /// order — rows before bytes, which keeps every v24.3.0 refusal token
    /// exactly where it was for row-bound traffic.
    fn refusal(
        &self,
        spec: &BudgetSpec,
        budget: QuotaBudget,
        cost: &WriteCost,
    ) -> Option<PeerQuotaRefused> {
        for h in QuotaHorizon::ALL {
            for d in QuotaDimension::ALL {
                let want = cost.of(*d);
                let have = self.tokens[d.index()].horizon(*h);
                if have < want {
                    let hs = spec.dim(*d).horizon(*h);
                    return Some(PeerQuotaRefused {
                        reason: PeerQuotaRefusal::of(budget, *d, *h),
                        retry_after_seconds: retry_after(want - have, hs.per_second),
                    });
                }
            }
        }
        None
    }

    /// Spend one write. Only ever called after every budget the write
    /// touches has already been proven admissible — see the no-partial-charge
    /// note on `PeerWriteQuota::charge`.
    fn spend(&mut self, cost: &WriteCost) {
        for d in QuotaDimension::ALL {
            let want = cost.of(*d);
            let t = &mut self.tokens[d.index()];
            for h in QuotaHorizon::ALL {
                *t.horizon_mut(*h) -= want;
            }
        }
    }

    /// A budget at full allowance on every dimension and horizon carries no
    /// information a fresh one wouldn't — the prune predicate, and the ONLY
    /// eviction predicate with a zero payout to the evicted party (see
    /// [`PER_PEER_QUOTA_TRACKED_PEERS_CAP`] on why that is not improvable).
    fn is_full(&self, spec: &BudgetSpec) -> bool {
        QuotaDimension::ALL.iter().all(|d| {
            let s = spec.dim(*d);
            let t = self.tokens[d.index()];
            QuotaHorizon::ALL
                .iter()
                .all(|h| t.horizon(*h) >= s.horizon(*h).capacity)
        })
    }
}

/// Seconds until `deficit` tokens have accrued at `per_second`, never 0.
#[allow(clippy::cast_possible_truncation, clippy::cast_sign_loss)]
fn retry_after(deficit: f64, per_second: f64) -> u64 {
    (deficit / per_second).ceil().max(1.0) as u64
}

/// v25.1.0 (CIRISPersist#583) — the byte size of an attestation envelope, as
/// the quota charges it.
///
/// Measured with a counting sink rather than by canonicalizing: the quota is
/// the FIRST gate in `put_attestation` and it runs on unauthenticated input,
/// so it must not allocate a second copy of an attacker-supplied payload —
/// the same reasoning that keeps a disk write off the head of the admission
/// chain ([`PeerWriteQuota::new`]). The caller has already paid to parse
/// these bytes into a `Value`; measuring the re-serialization is strictly
/// cheaper than the parse that produced it, and allocates nothing.
///
/// This is deliberately NOT
/// [`ceg_produce_canonicalize`](crate::verify::canonical::ceg_produce_canonicalize)
/// — the JCS bytes the producer signed, which
/// [`check_envelope_size_admission`](crate::federation::admission::check_envelope_size_admission)
/// measures a few gates later. The two agree to within JSON escaping and
/// number formatting, and a quota wants a proportional cost signal, not a
/// byte-exact accounting. The signed thing is the *sized* thing; the
/// *charged* thing is what it costs to hold.
fn envelope_charged_bytes(envelope: &serde_json::Value) -> u64 {
    struct Counting(u64);
    impl std::io::Write for Counting {
        fn write(&mut self, buf: &[u8]) -> std::io::Result<usize> {
            self.0 += buf.len() as u64;
            Ok(buf.len())
        }
        fn flush(&mut self) -> std::io::Result<()> {
            Ok(())
        }
    }
    let mut sink = Counting(0);
    // Serializing a `Value` into a sink that never errors cannot fail; if it
    // somehow did, the count so far is still a lower bound and the row is
    // charged at least the floor.
    let _ = serde_json::to_writer(&mut sink, envelope);
    sink.0
}

/// v22.0.0 (CIRISPersist#543 finding 4, AV-76) — per-peer write quota for
/// the attestation write path, keyed on `attesting_key_id`.
///
/// [`crate::federation::Error::RateLimited`] has been DECLARED since the
/// first federation cut, with a doc promising a quota — and was never
/// constructed anywhere. This is the construction site. A token bucket per
/// peer, capacity [`PER_PEER_ATTESTATION_WRITES_PER_WINDOW`], refilling
/// over [`PER_PEER_ATTESTATION_WRITE_WINDOW`].
///
/// # v24.3.0 (CIRISPersist#575) — four budgets, one control
///
/// The v22 control was one bucket per peer, and #575 is the bill for what
/// that alone can and cannot bound. It is now **four** budgets, and one
/// ordinary write is charged against exactly two of them:
///
/// ```text
///                 ┌ reserved (dimension accord:*) → RESERVE  (1 peer, node-wide)
/// write ─ classify┤
///                 └ ordinary ────────────────────→ NODE     (10 peers)
///                                                  ├ tracked → PEER (1 peer, own)
///                                                  └ untracked → TAIL (1 peer, shared)
/// ```
///
/// Each budget is a token bucket on TWO horizons — a burst minute and a
/// sustained day — and a write must clear both. The four exist because they
/// answer four different questions, and the v22 control could only answer
/// the first:
///
/// - **PEER** — is this author writing too fast? (fairness)
/// - **NODE** — can this node afford the sum of everyone? (capacity)
/// - **TAIL** — how much can identities I have never seen have, *together*?
///   (`attesting_key_id` is attacker-chosen and unauthenticated here, so a
///   per-identity budget over free identities is not a budget)
/// - **RESERVE** — what can an ordinary flood never take away? (the
///   censorship caveat: a bounded cap without one is a cheaper denial than
///   the flood it stops)
///
/// The type keeps its v22 name because it still governs the same thing —
/// peer writes on the attestation plane. What changed is what it *keys*
/// them on, and that is deliberately no longer a single axis.
///
/// # Placement
///
/// Held **per backend instance** (the
/// [`RepositoryStatsCache`](crate::ceg::aggregates::repository::RepositoryStatsCache)
/// precedent), never as a process global: the quota is node-local
/// admission state, and a process global would leak one engine's traffic
/// into another's budget (and one test's into the next's).
///
/// It runs ahead of every other gate in `put_attestation` — including the
/// trust gate — because it is the only check that consults NO shared
/// state. It answers "you are writing too fast", never "that key exists",
/// so it leaks strictly less than the trust threshold it precedes, while
/// bounding the recursive directory walk that
/// [`AdmissionGate::check_federation`] performs at any threshold > 0.
pub struct PeerWriteQuota {
    state: std::sync::Mutex<QuotaState>,
}

/// CIRISServer#356 — what [`PeerWriteQuota::observe`] can honestly say about
/// the #583 tail-squeeze tripwire, **with its volatility in the type**.
///
/// # Read the name before the numbers
///
/// [`process_local`](Self::process_local) is `true` on every value this crate
/// can produce, and it is a field rather than a doc note on purpose. The quota
/// is held per backend instance (never a process global — see
/// [`PeerWriteQuota`]), so both counters below:
///
/// - **reset when the process restarts**, and reset again when a host opens a
///   second engine over the same database;
/// - **differ between processes** serving the same node, so two replicas of one
///   service report two different numbers for one node;
/// - **are not stored anywhere.** No row backs them, no replication carries
///   them, and no peer can be shown them as evidence.
///
/// So this is a **gauge of this process**, not a fact about the node. Summing
/// it across replicas, diffing it across restarts, or putting it on a trust
/// card would each be reading it as something it is not. Making it durable
/// would be a schema change and is deliberately not one that was taken here.
///
/// # What it is genuinely good for
///
/// [`slot_denials`](Self::slot_denials) **must be 0** — the
/// [`PER_PEER_QUOTA_TRACKED_PEERS_CAP`] derivation makes the branch that
/// increments it unreachable by arithmetic over four constants. A non-zero
/// reading is therefore not "traffic is heavy", it is *"the inequality the
/// derivation gate asserts no longer holds in this build"*, which is worth
/// seeing from outside the crate's own test module — the only place it was
/// observable before this cut.
///
/// v38.0.0 (CIRISPersist#609) — the refusal counters land. Before this cut
/// the only exposed number was the tail-squeeze tripwire, which is derived
/// UNREACHABLE — so a node refusing 100% of a peer's writes read as
/// `Green`: the control fired perfectly and reported nothing. Refusals are
/// now counted per budget, plus a bounded distinct-refused-keys window so
/// one stuck producer is distinguishable from a wave. The BAND still does
/// not read them (a correct refusal is a fault report about someone ELSE,
/// while the tripwire's Red means THIS build's arithmetic broke) — the two
/// axes ship as data for the consumer's standing fold to band.
#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub struct PeerQuotaObservation {
    /// Always `true`. See the type doc — this is the field that says the two
    /// numbers below are about a process, not about a node.
    pub process_local: bool,
    /// Peers holding an individual budget in THIS engine's table right now.
    ///
    /// The tripwire's denominator: `0` means no peer write has been charged
    /// against this quota since the engine was opened, so
    /// [`slot_denials`](Self::slot_denials) being `0` is *untested*, not
    /// *clean*.
    pub tracked_peers: usize,
    /// The #583 tail-squeeze count. **Must be 0**; see the type doc.
    pub slot_denials: u64,
    /// v38.0.0 (#609) — refusals since process start, per budget. A key
    /// serializes as its snake_case token (`peer` / `untracked_tail` /
    /// `node` / `reserved`), so the JSON is a plain string-keyed object.
    pub refusals_by_budget: std::collections::BTreeMap<QuotaBudget, u64>,
    /// v38.0.0 (#609) — DISTINCT keys refused inside the burst window
    /// ([`PER_PEER_ATTESTATION_WRITE_WINDOW`]), bounded at
    /// [`REFUSED_KEYS_WINDOW_CAP`]: one stuck producer reads `1`, a rotating
    /// flood saturates to the cap and reads as *at least this many*.
    pub refused_keys_in_window: usize,
}

/// v38.0.0 (CIRISPersist#609) — hard bound on the refused-keys window map.
///
/// The key is `attesting_key_id`, which at this point in the chain is
/// attacker-chosen and UNAUTHENTICATED (the whole reason the untracked tail
/// exists) — an unbounded set would be a memory amplifier reachable by an
/// unauthenticated flooder, strictly worse than the blindness being fixed.
/// Sized as 2× the tracked-peers cap: comfortably above any honest
/// population, and once saturated the reading means *at least this many*.
pub const REFUSED_KEYS_WINDOW_CAP: usize = PER_PEER_QUOTA_TRACKED_PEERS_CAP * 2;

/// The four budgets, behind one lock. They move together on every write, so
/// splitting the lock would only buy a torn decision.
struct QuotaState {
    /// Per-peer budgets, hard-bounded at [`PER_PEER_QUOTA_TRACKED_PEERS_CAP`].
    buckets: HashMap<String, PeerBucket>,
    /// The node-wide ordinary budget ([`NODE_INGEST_BUDGET_MULTIPLE`]).
    node: PeerBucket,
    /// The shared budget for every identity without a bucket
    /// ([`UNTRACKED_TAIL_BUDGET_MULTIPLE`]).
    tail: PeerBucket,
    /// The reserved class's own budget ([`RESERVED_CLASS_BUDGET_MULTIPLE`]).
    reserved: PeerBucket,
    /// v25.1.0 (CIRISPersist#583) — how many admitted writes were denied an
    /// individual bucket because the table was saturated with non-full
    /// peers: the **tail-squeeze counter**.
    ///
    /// By the [`PER_PEER_QUOTA_TRACKED_PEERS_CAP`] derivation this must stay
    /// zero — the cap is sized above what any schedule can hold non-full, so
    /// the prune can always free a slot. It is counted rather than asserted
    /// because "unreachable by arithmetic over four constants" is a claim
    /// that survives exactly as long as the four constants do, and a
    /// deployment that has drifted should be able to SEE it rather than
    /// silently demote newcomers to a contended commons.
    slot_denials: u64,
    /// v38.0.0 (#609) — refusals since process start, indexed by
    /// [`QuotaBudget::idx`]. Counted at the ONE chokepoint (`charge`), so
    /// the counter and the refusal cannot disagree.
    refusals_by_budget: [u64; 4],
    /// v38.0.0 (#609) — last refusal instant per key, pruned to the burst
    /// window on every write and hard-bounded at
    /// [`REFUSED_KEYS_WINDOW_CAP`] (see the const for why the bound is the
    /// security-relevant part).
    refused_keys: HashMap<String, Instant>,
}

impl QuotaState {
    /// The one refusal-accounting site. Prune first so the window reading
    /// is honest even under a rotating-identity flood, then record —
    /// skipping the insert (but still counting the budget) once the cap is
    /// reached, so the map can never exceed its bound.
    fn record_refusal(&mut self, key_id: &str, budget: QuotaBudget, now: Instant) {
        self.refusals_by_budget[budget.idx()] += 1;
        self.refused_keys
            .retain(|_, at| now.duration_since(*at) <= PER_PEER_ATTESTATION_WRITE_WINDOW);
        if self.refused_keys.contains_key(key_id)
            || self.refused_keys.len() < REFUSED_KEYS_WINDOW_CAP
        {
            self.refused_keys.insert(key_id.to_owned(), now);
        }
    }
}

impl Default for PeerWriteQuota {
    fn default() -> Self {
        Self::new()
    }
}

impl PeerWriteQuota {
    /// The per-peer budget spec.
    fn peer_spec() -> BudgetSpec {
        BudgetSpec::for_multiple(1)
    }

    /// A fresh quota with every budget at full allowance.
    ///
    /// # This is also the restart-reset property, stated where a reader
    /// cannot miss it (#575 ask b)
    ///
    /// The budgets are **in-memory and per backend instance**. A process
    /// restart returns every one of them to full, so an attacker who can
    /// induce or wait for a restart buys a fresh instantaneous allowance;
    /// and a multi-process or multi-replica deployment holds N independent
    /// quotas, so its true ceiling is N times the constants above. Neither
    /// is a hard bound and neither is claimed to be.
    ///
    /// What v24.3.0 (CIRISPersist#575) changed is the *size of the prize*.
    /// A restart used to be worth `tracked-peers-cap × per-peer-burst` and
    /// measured at **2 611 200 writes admitted at a single instant**,
    /// because every fresh `attesting_key_id` was born with a full budget
    /// and identity is free at this point in the chain. It is now worth
    /// exactly one node-wide burst allowance
    /// ([`NODE_INGEST_BUDGET_MULTIPLE`] × 600 = 6 000 writes), because the
    /// node-wide budget is charged by every ordinary write no matter how
    /// many identities produce them — a 435× reduction in what a restart
    /// buys. Restart-reset survives as a **bounded, non-multipliable** leak
    /// instead of an unbounded one, and
    /// `tests::a_restart_is_worth_one_node_burst_not_a_sybil_multiple` is
    /// the standing measurement of it.
    ///
    /// Making it durable is deliberately NOT done here and the reasoning is
    /// on the record: persisting per write would put a disk write at the
    /// head of the admission chain, *before* any validation — turning a
    /// rate-limit check into a write amplifier that an unauthenticated
    /// flooder triggers on every request, which is a worse defect than the
    /// one it closes. The shape that does work is a periodic checkpoint of
    /// the bucket table (bounded loss = one checkpoint interval, cost
    /// amortized across all peers, off the hot path), and it needs a table,
    /// a migration, and a background writer in all three backends — none of
    /// which lives in this module. Filed as the durable half of #575 ask (b).
    pub fn new() -> Self {
        let now = Instant::now();
        Self {
            state: std::sync::Mutex::new(QuotaState {
                buckets: HashMap::new(),
                node: PeerBucket::full(&BudgetSpec::for_multiple(NODE_INGEST_BUDGET_MULTIPLE), now),
                tail: PeerBucket::full(
                    &BudgetSpec::for_multiple(UNTRACKED_TAIL_BUDGET_MULTIPLE),
                    now,
                ),
                reserved: PeerBucket::full(
                    &BudgetSpec::for_multiple(RESERVED_CLASS_BUDGET_MULTIPLE),
                    now,
                ),
                slot_denials: 0,
                refusals_by_budget: [0; 4],
                refused_keys: HashMap::new(),
            }),
        }
    }

    /// v24.3.0 (CIRISPersist#575) — which budget `row` is charged against.
    ///
    /// Pure: it reads the row's envelope dimension and nothing else, because
    /// this gate consults no shared state and that is the property that lets
    /// it lead the whole chain. See [`RESERVED_CLASS_BUDGET_MULTIPLE`] for
    /// what a *pure* (hence forgeable) class decision does and does not buy.
    pub fn classify(row: &crate::federation::types::Attestation) -> WriteAdmissionClass {
        // v31.1.0 (CIRISPersist#665) — **A ROW CLAIMING A BAKED GENESIS ID IS
        // ITS OWN CLASS, BECAUSE THE NODE'S OWN SEED IS NOT A PEER AND A CLAIM
        // IS NOT AN IDENTITY.**
        //
        // 31.1.0 made boot install `genesis-charter` / `genesis-grant:…` /
        // `genesis-lifecycle` through `put_attestation`, which charges this
        // quota — so a FRESH engine came up having "observed" one peer (`A1`)
        // that no peer had ever spoken as. That corrupts the signal at its
        // source: `tracked_peers` exists to separate *"nobody has talked to
        // us"* from *"peers have, and none were denied"*, and `node_state`
        // reads `tracked_peers > 0` as the thing that lifts the peer-quota band
        // out of `unknown` into `green`. Every fresh node would have reported a
        // TESTED quota on the strength of its own compiled-in artifact.
        //
        // The first fix routed these ids to `Reserved`, which does not open a
        // bucket — correct about the symptom and **wrong about the budget**.
        // This runs at TIER 0, ahead of any signature check, so the only thing
        // establishing `attesting_key_id = "A1"` is the row SAYING SO.
        // `check_genesis_attestation_reserved` runs before it and does not help:
        // it compares the CLAIMED key against the roster and authenticates
        // nothing. An unauthenticated peer could therefore drain the budget that
        // keeps accord objections writable, using rows
        // `verify_federation_tier_ingest` was about to reject — the same DoS
        // this cut moved that gate forward to close, re-opened one budget over.
        //
        // So the class is neither: charged against the node budget and the
        // shared untracked tail — what any stranger already pays, so no new
        // scarcity is exposed — and never promoted to a peer bucket. **Debit
        // only what the claim is entitled to.** See
        // `WriteAdmissionClass::GenesisClaim` for the full reasoning, including
        // why being denied a bucket is strictly more restrictive for an attacker
        // than being given one.
        if crate::federation::genesis::genesis_delegation_ids()
            .contains(&row.attestation_id.as_str())
        {
            return WriteAdmissionClass::GenesisClaim;
        }
        match crate::federation::admission::envelope_dimension(&row.attestation_envelope) {
            Some(dim)
                if RESERVED_CLASS_DIMENSION_PREFIXES
                    .iter()
                    .any(|p| dim.starts_with(p)) =>
            {
                WriteAdmissionClass::Reserved
            }
            _ => WriteAdmissionClass::Ordinary,
        }
    }

    /// Charge one attestation write. The call the three backends'
    /// `put_attestation` makes.
    ///
    /// `Ok(())` — admitted, and every dimension of every budget it touches
    /// has been charged.
    /// `Err(`[`Error::RateLimited`](crate::federation::Error::RateLimited)`)`
    /// — over quota; see [`Self::check_write_typed`] for WHICH budget and
    /// WHICH dimension.
    pub fn check_write(
        &self,
        row: &crate::federation::types::Attestation,
    ) -> Result<(), crate::federation::Error> {
        self.check_write_typed(row).map_err(Into::into)
    }

    /// [`Self::check_write`] keeping the typed [`PeerQuotaRefused`] instead
    /// of collapsing it to [`Error::RateLimited`](crate::federation::Error::RateLimited).
    ///
    /// The lossy conversion exists because `Error::RateLimited` has carried
    /// only `retry_after_seconds` since the first federation cut; a consumer
    /// that wants the branch calls this.
    pub fn check_write_typed(
        &self,
        row: &crate::federation::types::Attestation,
    ) -> Result<(), PeerQuotaRefused> {
        self.charge(
            &row.attesting_key_id,
            Self::classify(row),
            &WriteCost::for_envelope_bytes(envelope_charged_bytes(&row.attestation_envelope)),
            Instant::now(),
        )
    }

    /// Charge one ordinary-class write against `key_id`.
    ///
    /// Retained as the shape this method has had since v22.0.0 for callers
    /// that hold a key and no row. v25.1.0 (CIRISPersist#583): such a caller
    /// is charged [`WriteCost::floor`] on the byte dimension — one typical
    /// row — because a size-free entry point into a size-metered control is
    /// a door around the dimension, and the completeness gate exists to stop
    /// exactly that.
    pub fn check(&self, key_id: &str) -> Result<(), crate::federation::Error> {
        self.check_at(key_id, Instant::now())
    }

    /// Clock-injected ordinary-class [`Self::check`]. Private: the windows
    /// are substrate constants and callers do not get to pick "now" in
    /// production — only the unit tests below advance the clock.
    fn check_at(&self, key_id: &str, now: Instant) -> Result<(), crate::federation::Error> {
        self.check_at_class(key_id, WriteAdmissionClass::Ordinary, now)
            .map_err(Into::into)
    }

    /// Clock-injected, class-injected, floor-cost check. The shape the unit
    /// tests below have used since v22.0.0; the byte cost is
    /// [`WriteCost::floor`].
    fn check_at_class(
        &self,
        key_id: &str,
        class: WriteAdmissionClass,
        now: Instant,
    ) -> Result<(), PeerQuotaRefused> {
        self.charge(key_id, class, &WriteCost::floor(), now)
    }

    /// The clock-injected core. Every other entry point funnels here, so
    /// there is exactly one place where a write is charged.
    ///
    /// # No partial charge
    ///
    /// An ordinary write touches TWO budgets (node-wide, plus this peer's or
    /// the shared tail's) on EVERY metered dimension. All of it is proven
    /// admissible *before* anything is spent — a check that debited the node
    /// and then refused on the peer would leak the node's budget to refused
    /// traffic, which is precisely the amplification this control exists to
    /// close. v25.1.0 (CIRISPersist#583) extends the same rule across
    /// dimensions: a write that clears rows and fails bytes debits neither.
    ///
    /// # Refusal precedence
    ///
    /// Node before peer/tail; inside a budget, burst before sustained and
    /// rows before bytes. The node verdict leads because it is the one the
    /// caller cannot fix by slowing down, so it is the more useful thing to
    /// be told.
    fn charge(
        &self,
        key_id: &str,
        class: WriteAdmissionClass,
        cost: &WriteCost,
        now: Instant,
    ) -> Result<(), PeerQuotaRefused> {
        let mut st = self.state.lock().unwrap_or_else(|p| p.into_inner());
        let verdict = Self::charge_locked(&mut st, key_id, class, cost, now);
        // v38.0.0 (#609) — the refusal is COUNTED where it is decided, inside
        // the same lock acquisition, so the counter and the verdict cannot
        // disagree and the hot unauthenticated path takes no second lock.
        // The no-partial-charge invariant is about token SPEND, not about
        // accounting — a refusal that mutates only the refusal counters
        // spends nothing.
        if let Err(refused) = &verdict {
            st.record_refusal(key_id, refused.reason.budget(), now);
        }
        verdict
    }

    fn charge_locked(
        st: &mut QuotaState,
        key_id: &str,
        class: WriteAdmissionClass,
        cost: &WriteCost,
        now: Instant,
    ) -> Result<(), PeerQuotaRefused> {
        let peer_spec = Self::peer_spec();
        let node_spec = BudgetSpec::for_multiple(NODE_INGEST_BUDGET_MULTIPLE);
        let tail_spec = BudgetSpec::for_multiple(UNTRACKED_TAIL_BUDGET_MULTIPLE);
        let reserved_spec = BudgetSpec::for_multiple(RESERVED_CLASS_BUDGET_MULTIPLE);

        // The reserved class is charged against its own budget and NOTHING
        // else — not the node's, not the peer's, not the tail's. That is the
        // whole point: an ordinary flood, however large, cannot make an
        // accord objection unwritable (#575's must-ship caveat).
        if class == WriteAdmissionClass::Reserved {
            st.reserved.refill(&reserved_spec, now);
            if let Some(refused) = st
                .reserved
                .refusal(&reserved_spec, QuotaBudget::Reserved, cost)
            {
                return Err(refused);
            }
            st.reserved.spend(cost);
            return Ok(());
        }

        st.node.refill(&node_spec, now);
        if let Some(refused) = st.node.refusal(&node_spec, QuotaBudget::Node, cost) {
            return Err(refused);
        }

        // v31.1.0 (CIRISPersist#665 review) — a row CLAIMING a baked genesis id
        // is metered like any unauthenticated stranger (node + shared tail) and
        // is NEVER promoted to a peer bucket. See `WriteAdmissionClass::GenesisClaim`
        // for why it is neither `Reserved` (an unauthenticated claim must not be
        // able to drain the reserve) nor `Ordinary` (the node's own boot seed is
        // not a peer). Placed after the node charge and before the bucket
        // lookup, so it pays what everyone pays and skips only the promotion.
        if class == WriteAdmissionClass::GenesisClaim {
            st.tail.refill(&tail_spec, now);
            if let Some(refused) = st
                .tail
                .refusal(&tail_spec, QuotaBudget::UntrackedTail, cost)
            {
                return Err(refused);
            }
            st.tail.spend(cost);
            st.node.spend(cost);
            return Ok(());
        }

        // Tracked peer: its own budget, and it does not touch the tail.
        if let Some(bucket) = st.buckets.get_mut(key_id) {
            bucket.refill(&peer_spec, now);
            if let Some(refused) = bucket.refusal(&peer_spec, QuotaBudget::Peer, cost) {
                return Err(refused);
            }
            bucket.spend(cost);
            st.node.spend(cost);
            return Ok(());
        }

        // Untracked: the shared one-peer tail budget decides, and it decides
        // the same way for the millionth rotated identity as for the first.
        st.tail.refill(&tail_spec, now);
        if let Some(refused) = st
            .tail
            .refusal(&tail_spec, QuotaBudget::UntrackedTail, cost)
        {
            return Err(refused);
        }
        st.tail.spend(cost);
        st.node.spend(cost);

        // Admitted. Now — and only now — try to give this identity a bucket
        // of its own, so its second write is metered individually instead of
        // against everyone else's tail. A slot is a *convenience*, never a
        // budget: failing to get one costs the peer nothing this write.
        if st.buckets.len() >= PER_PEER_QUOTA_TRACKED_PEERS_CAP {
            // Drop every bucket that has refilled to full on every dimension
            // and horizon — exactly the set whose state carries no
            // information a fresh bucket wouldn't, and (see
            // `PER_PEER_QUOTA_TRACKED_PEERS_CAP`) the only evictable set
            // whose eviction pays the evicted party nothing. Any wider rule
            // is a budget reset wearing a fairness costume.
            st.buckets.retain(|_, b| {
                let mut probe = *b;
                probe.refill(&peer_spec, now);
                !probe.is_full(&peer_spec)
            });
        }
        if st.buckets.len() < PER_PEER_QUOTA_TRACKED_PEERS_CAP {
            let mut fresh = PeerBucket::full(&peer_spec, now);
            fresh.spend(cost); // this write, accounted in the peer's own budget too
            st.buckets.insert(key_id.to_owned(), fresh);
        } else {
            // Saturated with live-spending peers and nothing was prunable:
            // the #583 tail-squeeze. The write is still admitted (the tail
            // paid for it) — refusing it would make an honest newcomer's
            // FIRST contact the thing a flood breaks, which is the AV-75
            // outage, not a gate. What is not acceptable is that it happens
            // silently, so it is counted.
            //
            // By the `PER_PEER_QUOTA_TRACKED_PEERS_CAP` derivation this
            // branch is UNREACHABLE: the table is sized above the largest
            // number of buckets the node budget can hold non-full, so the
            // prune above always frees at least one slot. A non-zero
            // `slot_denials()` in a live deployment means that inequality no
            // longer holds — which is the thing the derivation gate refuses
            // to let happen in the tree.
            st.slot_denials += 1;
        }
        Ok(())
    }

    /// How many peers this quota is currently tracking. Observability for
    /// the [`PER_PEER_QUOTA_TRACKED_PEERS_CAP`] bound.
    pub fn tracked_peers(&self) -> usize {
        self.state
            .lock()
            .unwrap_or_else(|p| p.into_inner())
            .buckets
            .len()
    }

    /// v25.1.0 (CIRISPersist#583) — whether `key_id` currently has an
    /// individual budget rather than sharing the untracked tail.
    ///
    /// The observable form of #583's honest-newcomer property: a peer with
    /// no history must come out of first contact with a budget of its own,
    /// whatever a flood is doing at the time.
    pub fn tracks(&self, key_id: &str) -> bool {
        self.state
            .lock()
            .unwrap_or_else(|p| p.into_inner())
            .buckets
            .contains_key(key_id)
    }

    /// v25.1.0 (CIRISPersist#583) — how many admitted writes were denied an
    /// individual bucket because the tracked table was saturated with
    /// non-full peers.
    ///
    /// **Must be 0.** See [`PER_PEER_QUOTA_TRACKED_PEERS_CAP`]: the cap is
    /// derived to make this branch unreachable, and a deployment reading
    /// non-zero here is one whose constants have drifted out of the
    /// relationship the derivation gate asserts.
    pub fn slot_denials(&self) -> u64 {
        self.state
            .lock()
            .unwrap_or_else(|p| p.into_inner())
            .slot_denials
    }

    /// CIRISServer#356 — the tail-squeeze tripwire **and the denominator that
    /// makes it readable**, taken under one lock so the two cannot disagree.
    ///
    /// [`slot_denials`](Self::slot_denials) alone is not reportable state.
    /// Zero is both "the derivation still holds" and "this process has not
    /// exercised the branch yet", and a surface that cannot tell those apart
    /// renders a just-booted node green on evidence it does not have. Pairing
    /// the counter with [`tracked_peers`](Self::tracked_peers) separates them:
    /// an empty bucket table means no peer write has been charged here at all,
    /// so the tripwire has not been tested and the honest band is *unknown*.
    ///
    /// **Process-local and non-durable**, which is why it is named on the type
    /// rather than left in prose — see [`PeerQuotaObservation`].
    #[must_use]
    pub fn observe(&self) -> PeerQuotaObservation {
        let st = self.state.lock().unwrap_or_else(|p| p.into_inner());
        let now = Instant::now();
        PeerQuotaObservation {
            process_local: true,
            tracked_peers: st.buckets.len(),
            slot_denials: st.slot_denials,
            refusals_by_budget: QuotaBudget::ALL
                .iter()
                .filter(|b| st.refusals_by_budget[b.idx()] > 0)
                .map(|b| (*b, st.refusals_by_budget[b.idx()]))
                .collect(),
            refused_keys_in_window: st
                .refused_keys
                .values()
                .filter(|at| now.duration_since(**at) <= PER_PEER_ATTESTATION_WRITE_WINDOW)
                .count(),
        }
    }

    /// Remaining tokens in `key_id`'s own bucket for one dimension/horizon,
    /// if it has one. Test-only: the no-partial-charge invariant is not
    /// observable from outcomes alone, and an invariant that can only be
    /// argued is one that drifts.
    #[cfg(test)]
    fn peer_tokens(
        &self,
        key_id: &str,
        dimension: QuotaDimension,
        horizon: QuotaHorizon,
    ) -> Option<f64> {
        self.state
            .lock()
            .unwrap_or_else(|p| p.into_inner())
            .buckets
            .get(key_id)
            .map(|b| b.tokens[dimension.index()].horizon(horizon))
    }

    /// Remaining burst ROW tokens — the v24.3.0 spelling, kept for the tests
    /// that predate the byte dimension.
    #[cfg(test)]
    fn peer_burst_tokens(&self, key_id: &str) -> Option<f64> {
        self.peer_tokens(key_id, QuotaDimension::Rows, QuotaHorizon::Burst)
    }

    /// `key_id`'s bucket **refilled to `now`**, cell by cell. Test-only: the
    /// stored tokens are refilled lazily (only on a write that reaches the
    /// tracked path), so a raw read is not comparable across a schedule in
    /// which some writes are refused earlier in the chain. The
    /// adversary-monotonicity property differentials against this.
    #[cfg(test)]
    fn peer_tokens_at(&self, key_id: &str, now: Instant) -> Option<PeerBucket> {
        let peer_spec = Self::peer_spec();
        self.state
            .lock()
            .unwrap_or_else(|p| p.into_inner())
            .buckets
            .get(key_id)
            .map(|b| {
                let mut probe = *b;
                probe.refill(&peer_spec, now);
                probe
            })
    }
}

/// v22.0.0 (CIRISPersist#543 finding 4, AV-76) — the shared assertion
/// bodies proving the `put_attestation` gate ORDER, run identically
/// against every backend.
///
/// The order is a security property, not an implementation detail, and
/// #541 is the standing reminder of what happens when two backends'
/// write paths drift: the bodies live HERE, once, and each backend's test
/// module calls them, so a divergence is a compile-or-fail, never a
/// silent asymmetry.
#[cfg(test)]
pub mod gate_order_test_support {
    use crate::federation::types::{
        attestation_tier, Attestation, KeyRecord, SignedAttestation, SignedKeyRecord,
    };
    use crate::federation::FederationDirectory;

    /// A key with REAL deterministic hybrid pubkeys, so the tier-3 crypto
    /// gate resolves the attester and then rejects on the SIGNATURE
    /// (rather than short-circuiting on an unknown attester).
    fn key_with_real_pubkeys(key_id: &str) -> KeyRecord {
        let (ed_pk, mldsa_pk) =
            crate::federation::tier_ingest::test_support::hybrid_pubkeys(key_id);
        KeyRecord {
            key_id: key_id.into(),
            pubkey_ed25519_base64: ed_pk,
            pubkey_ml_dsa_65_base64: mldsa_pk,
            algorithm: crate::federation::types::algorithm::HYBRID.into(),
            identity_type: crate::federation::types::identity_type::PRIMITIVE.into(),
            identity_ref: key_id.into(),
            valid_from: "2026-05-01T00:00:00Z".parse().unwrap(),
            valid_until: None,
            registration_envelope: serde_json::json!({ "id": key_id }),
            original_content_hash: "deadbeef".into(),
            scrub_signature_classical: "c2lnbmF0dXJl".into(),
            scrub_signature_pqc: None,
            scrub_key_id: key_id.into(),
            scrub_timestamp: "2026-05-01T00:00:00Z".parse().unwrap(),
            pqc_completed_at: None,
            persist_row_hash: String::new(),
            capability_roles: Vec::new(),
            attestation_evidence: None,
            consent_role: None,
            additional_scrubs: Vec::new(),
        }
    }

    /// A federation-tier row whose scrub signature is garbage — it can
    /// never clear the tier-3 hybrid verify.
    fn unverifiable_row(key_id: &str, tier: &str, cohort_scope: &str) -> Attestation {
        // v31.0.0 (CIRISPersist#643/#598) — the tier-1 bindings (the #643
        // mirror and the #598 instants) are STAMPED but the row is deliberately
        // NOT re-signed: this witness needs a row that clears the pure tier-1
        // gates and dies at the tier-3 hybrid verify, so sealing it with a
        // valid signature would move what the test measures — and leaving a
        // tier-1 binding off moves it just as far in the other direction.
        let mut row = Attestation {
            attestation_id: uuid::Uuid::new_v4().to_string(),
            attesting_key_id: key_id.into(),
            attested_key_id: key_id.into(),
            attestation_type: "attestation:self_verify".into(),
            weight: Some(1.0),
            asserted_at: chrono::Utc::now(),
            expires_at: None,
            attestation_envelope: serde_json::json!({}),
            original_content_hash: "abcdef01".into(),
            scrub_signature_classical: "c2ln".into(),
            scrub_signature_pqc: None,
            scrub_key_id: key_id.into(),
            scrub_timestamp: chrono::Utc::now(),
            pqc_completed_at: None,
            persist_row_hash: String::new(),
            subject_key_ids: Vec::new(),
            withdraws_admission_rule: None,
            cohort_scope: cohort_scope.into(),
            tier: tier.into(),
            promoted_at: None,
            additional_scrubs: Vec::new(),
        };
        crate::federation::tier_ingest::test_support::stamp_mirror(&mut row);
        row
    }

    /// **The headline AV-76 assertion.** A federation-tier row that fails
    /// the crypto verify AND would fail a DB-walk authority gate must be
    /// refused on the CRYPTO, proving the walk never ran.
    ///
    /// The tripwire is `cohort_scope = "family"`: a legal closed-set value
    /// (so the pure tier-1 `check_cohort_scope` admits it) that the AV-45
    /// membership walk `check_write_cohort_scope_for` then refuses,
    /// because `put_attestation` supplies no `cohort_target_id`. That walk
    /// resolves the writer's occurrence→identity binding and lists its
    /// families and communities — three directory reads.
    ///
    /// BEFORE this cut the walk sat at position 6 of 21 and the crypto at
    /// position 20, so this row came back `federation_write_scope_refused`
    /// — the substrate had paid for three reads on a row whose signature
    /// was never going to verify. AFTER, crypto is position 11 and the
    /// walk position 12.
    pub async fn assert_crypto_verdict_precedes_the_authority_walk<F>(dir: &F, tag: &str)
    where
        F: FederationDirectory + ?Sized,
    {
        let key_id = format!("av76c{tag}");
        dir.put_public_key(SignedKeyRecord {
            record: key_with_real_pubkeys(&key_id),
        })
        .await
        .expect("register attester");

        let row = unverifiable_row(&key_id, attestation_tier::FEDERATION, "family");
        let err = dir
            .put_attestation(SignedAttestation { attestation: row })
            .await
            .expect_err("an unverifiable federation-tier row must be refused");
        assert_eq!(
            err.kind(),
            "federation_federation_tier_unverified",
            "AV-76: the crypto verdict must precede the DB-walk authority \
             gates — got {err:?}, which means an authority gate ran first \
             on a row whose signature can never verify"
        );
    }

    /// The counter-witness to the assertion above: the authority walk was
    /// REORDERED, not removed. The same row at LOCAL tier — where the
    /// crypto gate is a documented no-op (CC 5.3.2.2 deferred signature) —
    /// must still be refused by the AV-45 membership walk.
    pub async fn assert_authority_walk_still_rejects_when_crypto_is_a_noop<F>(dir: &F, tag: &str)
    where
        F: FederationDirectory + ?Sized,
    {
        let key_id = format!("av76w{tag}");
        dir.put_public_key(SignedKeyRecord {
            record: key_with_real_pubkeys(&key_id),
        })
        .await
        .expect("register attester");

        let row = unverifiable_row(&key_id, attestation_tier::LOCAL, "family");
        let err = dir
            .put_attestation(SignedAttestation { attestation: row })
            .await
            .expect_err("an unprovable family downgrade must still be refused");
        assert_eq!(
            err.kind(),
            "federation_write_scope_refused",
            "AV-76 moved the AV-45 membership walk; it must not have \
             weakened it — got {err:?}"
        );
    }

    /// The tier-1 half of AV-76: the pure envelope gates now precede the
    /// single unavoidable directory read (the attester `identity_type`
    /// lookup, D2).
    ///
    /// The row's attester is deliberately UNREGISTERED, so the directory
    /// read would return the typed `federation_invalid_argument` ("does
    /// not exist in federation_keys") — which is exactly what this row
    /// used to come back with, because `check_envelope_size_admission` ran
    /// at position 14 and the lookup at position 2. An envelope that can
    /// never be admitted must not buy a directory read.
    pub async fn assert_pure_envelope_gates_precede_the_directory_read<F>(dir: &F, tag: &str)
    where
        F: FederationDirectory + ?Sized,
    {
        // Comfortably past MAX_ATTESTATION_ENVELOPE_BYTES (1 MiB) once
        // canonicalized.
        let oversized = serde_json::json!({ "pad": "x".repeat(2 * 1024 * 1024) });
        let mut row = unverifiable_row(
            &format!("av76-unregistered-{tag}"),
            attestation_tier::FEDERATION,
            "self",
        );
        row.attestation_envelope = oversized;
        crate::federation::tier_ingest::test_support::reseal(&mut row);

        let err = dir
            .put_attestation(SignedAttestation { attestation: row })
            .await
            .expect_err("an oversized envelope must be refused");
        assert_eq!(
            err.kind(),
            "federation_envelope_too_large",
            "AV-76: the pure envelope-size gate must precede the attester \
             directory read — got {err:?}"
        );
    }

    /// The per-peer write quota, proven WIRED into `put_attestation` (the
    /// bucket arithmetic itself is unit-tested in this module's `tests`).
    ///
    /// Every write here is refused by the pure tier-1 `check_cohort_scope`
    /// (`global` is a §8.1.8 feed-name, never a wire value) — so the rows
    /// never reach the DB, and what the assertion isolates is that the
    /// quota is charged AHEAD of that, on the very first gate: a peer that
    /// floods inside one window eventually comes back
    /// `federation_rate_limited`, the typed error that this cut gave its
    /// first construction site.
    ///
    /// # Why it DRAINS rather than asserting on write N+1
    ///
    /// v31.0.0 (CIRISPersist#598) — it used to assert that the very next write
    /// after exactly `N` was rate-limited, and that was a **wall-clock
    /// assumption wearing an exact number**. The bucket refills CONTINUOUSLY at
    /// `PER_PEER_ATTESTATION_WRITES_PER_WINDOW / PER_PEER_ATTESTATION_WRITE_WINDOW`
    /// = 10 tokens/second, so "write N+1 is refused" only holds if all `N`
    /// writes complete within ~100 ms. Alone they took ~50 ms and it passed; in
    /// a full parallel run they took ~250 ms, two tokens accrued mid-flood, and
    /// write N+1 was legitimately back inside quota. A green run on an idle box
    /// and a red one on a loaded box, measuring machine speed.
    ///
    /// This is the same class as
    /// `substrate_machine::every_row_the_harness_writes_is_live_at_wall_clock`:
    /// a fixed expectation next to a gate that reads a real clock. The property
    /// was never "N+1 exactly" — it is *the bucket is FINITE and charged before
    /// the cohort gate*. So: flood until rate-limited, capped. If the quota
    /// were not charged on the first gate the cap is never reached and this
    /// fails, which is precisely the regression it exists to catch.
    pub async fn assert_per_peer_write_quota_is_wired<F>(dir: &F, tag: &str)
    where
        F: FederationDirectory + ?Sized,
    {
        let key_id = format!("av76q{tag}");
        let n = super::PER_PEER_ATTESTATION_WRITES_PER_WINDOW;
        let started = std::time::Instant::now();
        // The cap is `2n`: draining `n` empties a full bucket, and the second
        // `n` is headroom for tokens that accrue while the first `n` are in
        // flight. Reaching it means `2n` consecutive writes were all admitted
        // past the quota — that is not slowness, that is an uncharged bucket.
        let mut rate_limited = None;
        for i in 0..(2 * n) {
            let row = unverifiable_row(&key_id, attestation_tier::FEDERATION, "global");
            let err = dir
                .put_attestation(SignedAttestation { attestation: row })
                .await
                .expect_err("the `global` cohort_scope is never a wire value");
            match err.kind() {
                "federation_rate_limited" => {
                    rate_limited = Some(i);
                    break;
                }
                // Still inside quota: the write fell through to the closed-set
                // cohort_scope gate, which is the ONLY other verdict these rows
                // may draw. Anything else means a gate moved.
                k => assert_eq!(
                    k,
                    "federation_cohort_scope_rejected",
                    "write {i} of at most {cap} must be either inside quota (and so fail on \
                     the closed-set `cohort_scope`) or rate-limited — got {err:?}",
                    cap = 2 * n,
                ),
            }
        }
        let at = rate_limited.unwrap_or_else(|| {
            // v31.0.0 (CIRISPersist#658) — this message used to end "no amount
            // of slowness explains this", which is FALSE and would have been
            // read by the one person least able to argue with it. The bucket
            // refills continuously at `n / window` = 10 tokens/s, so draining
            // `2n` needs `n` tokens more than the bucket holds: at ≥ 50 ms per
            // write the refill supplies them and the cap is reached WITHOUT
            // any defect. Worse, the honest diagnosis — the `elapsed < window`
            // assertion just below — never runs, because this panic fires
            // first. So the message states the ambiguity and reports the
            // measurement that resolves it.
            let elapsed = started.elapsed();
            let per_write = elapsed / (2 * n);
            let refill = super::PER_PEER_ATTESTATION_WRITE_WINDOW / n;
            panic!(
                "AV-76: {cap} consecutive writes from one peer were ALL admitted past the \
                 per-peer quota. This drain took {elapsed:?} ({per_write:?} per write). Two \
                 readings, and the timing tells them apart:\n  \
                 - if that is at or above {refill:?} per write, the bucket refilled as fast as \
                   it drained and this run measured the machine, not the gate — the flood cap \
                   ({cap}) is too small for a box this slow;\n  \
                 - otherwise the quota is not wired into `put_attestation` at all, or it is \
                   charged AFTER the gate that refuses these rows.\n\
                 The bucket holds {n} and refills over {window:?}.",
                cap = 2 * n,
                window = super::PER_PEER_ATTESTATION_WRITE_WINDOW,
            )
        });
        // And it must have happened because the bucket EMPTIED, not because the
        // window elapsed and something else fired. A drain that takes longer
        // than the window is not measuring capacity.
        let elapsed = started.elapsed();
        assert!(
            elapsed < super::PER_PEER_ATTESTATION_WRITE_WINDOW,
            "AV-76: the drain took {elapsed:?}, which is at least one full refill window \
             ({window:?}) — this run measured the clock, not the bucket",
            window = super::PER_PEER_ATTESTATION_WRITE_WINDOW,
        );
        assert!(
            at >= n,
            "AV-76: the quota bit after only {at} writes, but the bucket's capacity is {n} — a \
             peer's first honest burst must fit, or the cap is a censorship primitive against \
             ordinary traffic rather than a flood brake"
        );

        // v24.3.0 (CIRISPersist#575) — the RESERVED ADMISSION CLASS, proven
        // wired on every backend. The same exhausted peer, sending an
        // `accord:`-dimension row, must NOT be rate-limited: the reserve is
        // charged instead, and ordinary traffic (here, the peer's own flood
        // above) can never consume it.
        //
        // This is #575's must-ship caveat as a cross-backend witness rather
        // than a unit-test claim, because the classification depends on the
        // real envelope reaching `PeerWriteQuota::classify` through the real
        // `put_attestation` — a bypass that only the unit tests exercise
        // certifies an unreachable feature (the AV-77 lesson).
        // EVERY reserved prefix, not just the first — a prefix appended to
        // the set without a path through `classify` is a reserve that
        // silently does not cover the family it names.
        for prefix in super::RESERVED_CLASS_DIMENSION_PREFIXES {
            let mut reserved = unverifiable_row(&key_id, attestation_tier::FEDERATION, "global");
            reserved.attestation_envelope = serde_json::json!({
                "dimension": format!("{prefix}reserved_probe:v1"),
            });
            // v31.0.0 (CIRISPersist#643) — swapping the envelope drops the
            // mirror; re-stamp (still unsigned, see `unverifiable_row`) so this
            // arm keeps measuring the quota class and not the binding.
            crate::federation::tier_ingest::test_support::stamp_mirror(&mut reserved);
            let err = dir
                .put_attestation(SignedAttestation {
                    attestation: reserved,
                })
                .await
                .expect_err("still an invalid cohort_scope");
            assert_eq!(
                err.kind(),
                "federation_cohort_scope_rejected",
                "#575: a `{prefix}` row must draw on the RESERVED budget, not \
                 the peer's exhausted one — a bounded cap without a reserved \
                 admission class converts a flood into a censorship primitive \
                 against exactly the rows (kill-switch, reverse-quorum \
                 objection) that must never be crowded out. Got {err:?}"
            );
        }

        // And it is PER PEER: a second peer is unaffected by the first's
        // flood (a shared counter would be a trivial cross-peer DoS).
        let other = unverifiable_row(
            &format!("av76q2{tag}"),
            attestation_tier::FEDERATION,
            "global",
        );
        let err = dir
            .put_attestation(SignedAttestation { attestation: other })
            .await
            .expect_err("still an invalid cohort_scope");
        assert_eq!(
            err.kind(),
            "federation_cohort_scope_rejected",
            "one peer's exhausted bucket must not spend another's — got {err:?}"
        );
    }

    /// v25.1.0 (CIRISPersist#583) — the **BYTE dimension**, proven wired into
    /// `put_attestation` on every backend.
    ///
    /// #583, quoting CIRISServer: *"600 rows of 100 B and 600 rows of 10 MB
    /// cost the same."* The unit tests in this module's `tests` prove the
    /// bucket arithmetic; this proves the real envelope reaches
    /// `PeerWriteQuota::check_write` through the real host API on all three
    /// backends. A dimension exercised only through a bypass certifies an
    /// unreachable feature — the AV-77 lesson, which is why this lives beside
    /// the row-quota witness rather than in the unit tests.
    ///
    /// Every row here is 900 KiB: comfortably under
    /// [`MAX_ATTESTATION_ENVELOPE_BYTES`](crate::federation::admission::MAX_ATTESTATION_ENVELOPE_BYTES)
    /// so the size gate admits it, and ~600 typical rows' worth of storage so
    /// the peer's BYTE budget binds long before its ROW budget. The refusal
    /// must name the byte dimension, because "you are writing too many rows"
    /// and "you are writing too much storage" are different operator actions.
    pub async fn assert_byte_dimension_is_wired<F>(dir: &F, tag: &str)
    where
        F: FederationDirectory + ?Sized,
    {
        let key_id = format!("av583{tag}");
        let big = serde_json::json!({ "pad": "x".repeat(900 * 1024) });

        let mut admitted = 0u32;
        let mut refusal = None;
        for _ in 0..super::PER_PEER_ATTESTATION_WRITES_PER_WINDOW {
            let mut row = unverifiable_row(&key_id, attestation_tier::FEDERATION, "global");
            row.attestation_envelope = big.clone();
            crate::federation::tier_ingest::test_support::reseal(&mut row);
            let err = dir
                .put_attestation(SignedAttestation { attestation: row })
                .await
                .expect_err("the `global` cohort_scope is never a wire value");
            match err {
                crate::federation::Error::RateLimited { reason, .. } => {
                    refusal = Some(reason);
                    break;
                }
                other => {
                    assert_eq!(
                        other.kind(),
                        "federation_cohort_scope_rejected",
                        "a 900 KiB envelope is under the single-row cap and must \
                         fail on the closed-set cohort_scope — got {other:?}"
                    );
                    admitted += 1;
                }
            }
        }

        let refusal = refusal.expect(
            "#583: 600 rows of 900 KiB (≈527 MiB) were all admitted by the \
             quota — it meters ROWS ONLY and inauthentic STORAGE is invisible \
             to the control that exists to bound it",
        );
        assert_eq!(
            refusal.dimension(),
            super::QuotaDimension::Bytes,
            "a storage flood must be refused on the BYTE dimension so an \
             operator can tell it from a row flood — got {refusal}"
        );
        assert!(
            admitted < super::PER_PEER_ATTESTATION_WRITES_PER_WINDOW / 10,
            "the byte budget bound only after {admitted} of \
             {} rows at 900 KiB — that is not a storage bound",
            super::PER_PEER_ATTESTATION_WRITES_PER_WINDOW,
        );
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use async_trait::async_trait;
    use std::sync::Mutex;

    struct FixedScores {
        scores: HashMap<String, f64>,
    }

    #[async_trait]
    impl TrustScoring for FixedScores {
        async fn trust_score(&self, key_id: &str) -> Result<f64, TrustScoringError> {
            match self.scores.get(key_id) {
                Some(s) => Ok(*s),
                None => Err(TrustScoringError::KeyNotFound(key_id.to_owned())),
            }
        }
    }

    fn fixed(pairs: &[(&str, f64)]) -> Arc<dyn TrustScoring> {
        let mut m = HashMap::new();
        for (k, v) in pairs {
            m.insert((*k).to_owned(), *v);
        }
        Arc::new(FixedScores { scores: m })
    }

    #[tokio::test]
    async fn threshold_zero_short_circuits_to_admit() {
        // Even an "unknown key" admits at threshold 0.0 — the gate
        // does not even hit the resolver.
        struct PanicResolver;
        #[async_trait]
        impl TrustScoring for PanicResolver {
            async fn trust_score(&self, _key_id: &str) -> Result<f64, TrustScoringError> {
                panic!("threshold 0.0 must short-circuit");
            }
        }
        let gate = AdmissionGate::new(Arc::new(PanicResolver), 0.0);
        let outcome = gate.check("any").await.unwrap();
        assert!(outcome.is_ok());
    }

    #[tokio::test]
    async fn admit_when_score_meets_threshold() {
        let gate = AdmissionGate::new(fixed(&[("k1", 0.8)]), 0.5);
        let outcome = gate.check("k1").await.unwrap();
        assert_eq!(outcome.expect("admitted"), 0.8);
    }

    #[tokio::test]
    async fn reject_when_score_below_threshold() {
        let gate = AdmissionGate::new(fixed(&[("k1", 0.3)]), 0.5);
        let outcome = gate.check("k1").await.unwrap();
        let rej = outcome.expect_err("rejected");
        assert_eq!(rej.key_id, "k1");
        assert_eq!(rej.score, 0.3);
        assert_eq!(rej.threshold, 0.5);
    }

    #[tokio::test]
    async fn unknown_key_becomes_zero_score_rejection() {
        let gate = AdmissionGate::new(fixed(&[]), 0.5);
        let outcome = gate.check("missing").await.unwrap();
        let rej = outcome.expect_err("rejected");
        assert_eq!(rej.score, 0.0);
    }

    #[tokio::test]
    async fn resolver_backend_error_surfaces() {
        struct Erroring;
        #[async_trait]
        impl TrustScoring for Erroring {
            async fn trust_score(&self, _key_id: &str) -> Result<f64, TrustScoringError> {
                Err(TrustScoringError::Backend("boom".into()))
            }
        }
        let gate = AdmissionGate::new(Arc::new(Erroring), 0.5);
        let err = gate.check("k1").await.expect_err("backend error");
        assert_eq!(err.kind(), "trust_scoring_backend");
    }

    #[tokio::test]
    async fn threshold_clamped_to_unit_range() {
        let gate = AdmissionGate::new(fixed(&[("k1", 1.0)]), 2.0);
        assert_eq!(gate.threshold(), 1.0);
        // Threshold below 0 is clamped to 0 → admit.
        let gate_neg = AdmissionGate::new(fixed(&[("k1", 1.0)]), -1.0);
        assert_eq!(gate_neg.threshold(), 0.0);
        let outcome = gate_neg.check("k1").await.unwrap();
        assert!(outcome.is_ok());
    }

    // Mutex import not needed elsewhere but kept to silence clippy on
    // some toolchains; no-op when unused.
    #[allow(dead_code)]
    fn _force_mutex(_m: Mutex<()>) {}

    // ── v22.0.0 (CIRISPersist#543 finding 4, AV-76) — per-peer quota ──

    /// The headline property: the N+1th write inside one window is
    /// RateLimited, and the typed error is the one that was DECLARED but
    /// never constructed before this cut.
    #[test]
    fn n_plus_first_write_in_window_is_rate_limited() {
        let quota = PeerWriteQuota::new();
        let t0 = Instant::now();
        for i in 0..PER_PEER_ATTESTATION_WRITES_PER_WINDOW {
            quota
                .check_at("peer-a", t0)
                .unwrap_or_else(|e| panic!("write {i} inside quota must admit: {e}"));
        }
        let err = quota
            .check_at("peer-a", t0)
            .expect_err("the N+1th write in the window must be refused");
        match err {
            crate::federation::Error::RateLimited {
                retry_after_seconds,
                reason,
            } => {
                assert!(
                    retry_after_seconds >= 1,
                    "retry_after must be actionable, got {retry_after_seconds}"
                );
                // v24.3.0 (CIRISPersist#575) — the wire carries WHICH budget
                // refused, not just that one did. Asserted on the program
                // constant, never the message text (the #565 contract).
                assert_eq!(
                    reason.as_str(),
                    "peer_burst",
                    "the N+1th write inside the window is a BURST refusal"
                );
            }
            other => panic!("expected RateLimited, got {other:?}"),
        }
        assert_eq!(err.kind(), "federation_rate_limited");
    }

    /// The quota is PER PEER: peer-a exhausting its bucket must not spend
    /// peer-b's. (A shared counter would be a trivial cross-peer DoS —
    /// one flooder silences the mesh.)
    #[test]
    fn quota_is_keyed_per_peer() {
        let quota = PeerWriteQuota::new();
        let t0 = Instant::now();
        for _ in 0..PER_PEER_ATTESTATION_WRITES_PER_WINDOW {
            quota.check_at("peer-a", t0).expect("peer-a fills its own");
        }
        assert!(quota.check_at("peer-a", t0).is_err());
        quota
            .check_at("peer-b", t0)
            .expect("peer-b's bucket is untouched by peer-a's flood");
    }

    /// Tokens accrue continuously, so a peer that waits the full window
    /// is whole again — the quota throttles, it does not ban.
    #[test]
    fn bucket_refills_over_the_window() {
        let quota = PeerWriteQuota::new();
        let t0 = Instant::now();
        for _ in 0..PER_PEER_ATTESTATION_WRITES_PER_WINDOW {
            quota.check_at("peer-a", t0).expect("initial burst admits");
        }
        assert!(quota.check_at("peer-a", t0).is_err());

        // Half a window back ⇒ half the allowance.
        let half = t0 + PER_PEER_ATTESTATION_WRITE_WINDOW / 2;
        for _ in 0..(PER_PEER_ATTESTATION_WRITES_PER_WINDOW / 2) {
            quota.check_at("peer-a", half).expect("half-window refill");
        }
        assert!(quota.check_at("peer-a", half).is_err());

        // A full window after that ⇒ full allowance again.
        let full = half + PER_PEER_ATTESTATION_WRITE_WINDOW;
        for _ in 0..PER_PEER_ATTESTATION_WRITES_PER_WINDOW {
            quota.check_at("peer-a", full).expect("full-window refill");
        }
        assert!(quota.check_at("peer-a", full).is_err());
    }

    // ── v24.3.0 (CIRISPersist#575) — the three gaps, each witnessed ──
    //
    // Every test below FAILS against the v22.0.0 implementation. They are
    // the reason the constants above exist, and they are written as
    // *ceilings over a schedule* rather than "the N+1th write is refused",
    // because "refuses at N+1" is the one property the old control already
    // had and the one that was never the problem.

    /// One peer's budget spec, spelled the way the implementation derives it,
    /// so a test can state an exact ceiling instead of a fudge factor.
    fn peer_budget() -> BudgetSpec {
        BudgetSpec::for_multiple(1)
    }

    fn node_budget() -> BudgetSpec {
        BudgetSpec::for_multiple(NODE_INGEST_BUDGET_MULTIPLE)
    }

    /// Ordinary-class check with the typed refusal kept, for the tests that
    /// assert WHICH budget spoke.
    fn ord(q: &PeerWriteQuota, key: &str, now: Instant) -> Result<(), PeerQuotaRefused> {
        q.check_at_class(key, WriteAdmissionClass::Ordinary, now)
    }

    /// The exact token-bucket ceiling over an interval, in WRITES of cost
    /// `cost`: a write spends from every horizon of every dimension, so the
    /// binding cell is whichever admits fewest —
    /// `min over cells of (capacity + rate × elapsed) / cost`. Rounded up by
    /// one so the assertion cannot flake on the last fractional token.
    ///
    /// v25.1.0 (CIRISPersist#583) — the minimum now ranges over dimensions
    /// as well as horizons, so a ceiling assertion cannot go stale by
    /// ignoring a dimension the control has started metering.
    fn ceiling_for(spec: &BudgetSpec, elapsed: Duration, cost: &WriteCost) -> u64 {
        let e = elapsed.as_secs_f64();
        let mut best = f64::INFINITY;
        for d in QuotaDimension::ALL {
            let want = cost.of(*d);
            if want <= 0.0 {
                continue;
            }
            for h in QuotaHorizon::ALL {
                let hs = spec.dim(*d).horizon(*h);
                best = best.min((hs.capacity + hs.per_second * e) / want);
            }
        }
        best.ceil() as u64
    }

    /// [`ceiling_for`] at the cost every clock-injected unit test charges.
    fn ceiling(spec: &BudgetSpec, elapsed: Duration) -> u64 {
        ceiling_for(spec, elapsed, &WriteCost::floor())
    }

    /// **GAP 1 — 864 000 rows/day/peer.** The v22 control was a burst
    /// bucket and nothing else, so "10 writes/second, sustained" meant
    /// *sustained*: one consented peer could add ~0.9M rows/day, for ever,
    /// entirely within quota.
    ///
    /// The witness walks a full simulated day, spending everything available
    /// at every step, and holds the total to the exact token-bucket ceiling
    /// of the sustained budget. Against v22 it lands 864 600 and fails.
    #[test]
    fn one_peer_cannot_write_a_million_rows_in_a_day() {
        let quota = PeerWriteQuota::new();
        let t0 = Instant::now();
        let day = Duration::from_secs(86_400);
        let step = Duration::from_secs(60);

        let mut admitted: u64 = 0;
        let mut elapsed = Duration::ZERO;
        while elapsed <= day {
            while quota.check_at("flooder", t0 + elapsed).is_ok() {
                admitted += 1;
                // The old control admits ~864k here; stop early so the
                // failure is a clean number rather than a slow one.
                if admitted > 1_000_000 {
                    break;
                }
            }
            elapsed += step;
        }

        let spec = peer_budget();
        let bound = ceiling(&spec, day);
        assert!(
            admitted <= bound,
            "#575 gap 1: one peer landed {admitted} rows in a simulated day; \
             the sustained budget bounds it at {bound} (capacity {} + {} \
             rows/day). A burst bucket alone permits 864 000.",
            spec.dim(QuotaDimension::Rows).sustained.capacity,
            PER_PEER_SUSTAINED_WRITES_PER_WINDOW,
        );
        // …and the ceiling is not vacuous: an honest peer's full burst still
        // clears instantly.
        let fresh = PeerWriteQuota::new();
        for i in 0..PER_PEER_ATTESTATION_WRITES_PER_WINDOW {
            fresh
                .check_at("honest", t0)
                .unwrap_or_else(|e| panic!("burst write {i} must still admit: {e}"));
        }
    }

    /// **GAP 3 — the tracked-peer cap made a Sybil an amplifier**, and
    /// **GAP 2 — the restart reset**, which are the same measurement: a
    /// fresh [`PeerWriteQuota`] IS a restarted one, and what a restart is
    /// worth is exactly what a fresh quota will admit instantaneously.
    ///
    /// Under v22 that was `tracked-peers-cap × per-peer-capacity` =
    /// 2 457 600 writes at a single instant, because every fresh
    /// `attesting_key_id` was born with a full 600-write allowance and
    /// identity is free at this point in the chain. It is now one node-wide
    /// burst allowance, no matter how many identities ask.
    /// v38.0.0 (CIRISPersist#609) — **a peer refused on every write is
    /// visible from outside the crate.** Before this cut the only exposed
    /// counter was the tail-squeeze tripwire (derived unreachable), so a
    /// node refusing 100% of one peer's writes serialized as clean. The
    /// refusal counters land at the ONE chokepoint, and the JSON carries
    /// them — asserted at the JSON layer because that is the actual
    /// consumer contract.
    #[test]
    fn a_peer_refused_on_every_write_is_visible_from_outside_609() {
        let quota = PeerWriteQuota::new();
        let t0 = Instant::now();
        // Drain until the control fires — the flood.
        let mut drained = 0_u64;
        while quota.check_at("flooder", t0).is_ok() {
            drained += 1;
            assert!(
                drained < 10_000_000,
                "quota never refused — no control at all"
            );
        }
        // The control fires (this passed before the fix too)...
        assert!(quota.check_at("flooder", t0).is_err());
        assert!(quota.check_at("flooder", t0).is_err());
        // ...and NOW it is countable (this is the arm that was missing).
        let o = quota.observe();
        let total: u64 = o.refusals_by_budget.values().sum();
        assert!(total >= 2, "refusals must count: {o:?}");
        assert_eq!(
            o.refused_keys_in_window, 1,
            "one stuck producer, not a wave: {o:?}"
        );
        let j = serde_json::to_value(&o).unwrap();
        assert!(
            j.get("refusals_by_budget")
                .is_some_and(|v| v.as_object().is_some_and(|m| !m.is_empty())),
            "a node refusing 100% of a peer's writes must not serialize as clean: {j}"
        );
        // And the band still holds its lane: refusals are the consumer's
        // axis, the band's Red stays the build tripwire.
        assert_eq!(o.slot_denials, 0);
    }

    /// v38.0.0 (#609) — the refused-keys window is HARD-BOUNDED. The key is
    /// attacker-chosen and unauthenticated, so an unbounded map would be a
    /// memory amplifier reachable by a rotating-identity flood — strictly
    /// worse than the blindness being fixed. Saturated reads mean *at least
    /// this many*.
    #[test]
    fn the_refused_keys_window_saturates_at_its_cap_609() {
        let quota = PeerWriteQuota::new();
        let t0 = Instant::now();
        while quota.check_at("seed", t0).is_ok() {}
        // A rotating-identity flood: every key distinct, every write refused.
        for i in 0..(REFUSED_KEYS_WINDOW_CAP + 50) {
            let _ = quota.check_at(&format!("rotator-{i}"), t0);
        }
        let o = quota.observe();
        assert!(
            o.refused_keys_in_window <= REFUSED_KEYS_WINDOW_CAP,
            "the window must saturate, never grow: {} > {REFUSED_KEYS_WINDOW_CAP}",
            o.refused_keys_in_window
        );
        assert!(
            o.refused_keys_in_window >= REFUSED_KEYS_WINDOW_CAP / 2,
            "the window must actually track distinct keys: {o:?}"
        );
    }

    #[test]
    fn a_restart_is_worth_one_node_burst_not_a_sybil_multiple() {
        let quota = PeerWriteQuota::new(); // ← the restart
        let t0 = Instant::now();
        let bound = node_budget()
            .dim(QuotaDimension::Rows)
            .burst
            .capacity
            .ceil() as u64;

        let mut admitted: u64 = 0;
        'flood: for i in 0..(PER_PEER_QUOTA_TRACKED_PEERS_CAP + 256) {
            let sybil = format!("sybil-{i}");
            while quota.check_at(&sybil, t0).is_ok() {
                admitted += 1;
                if admitted > bound {
                    break 'flood; // fail fast rather than count to 2.4M
                }
            }
        }

        assert!(
            admitted <= bound,
            "#575 gaps 2+3: a fresh quota admitted {admitted} writes at one \
             instant across rotated identities; the node-wide burst budget \
             bounds it at {bound}. Under v22 the bound was \
             tracked-peers-cap × per-peer-capacity = {}, i.e. the cap WAS \
             the multiplier.",
            PER_PEER_QUOTA_TRACKED_PEERS_CAP as u64
                * u64::from(PER_PEER_ATTESTATION_WRITES_PER_WINDOW),
        );
    }

    /// **GAP 3, memory half — the cap did not bound anything.** The v22
    /// prune retained every bucket that had not refilled to full and then
    /// inserted the newcomer *unconditionally*, so a flooder holding the
    /// table at non-full — which is what spending one token does — grew the
    /// map past the cap for free while paying an O(cap) scan per rotated key.
    ///
    /// One write per identity is enough to reproduce it: 5096 identities,
    /// each having spent exactly one token, none of them prunable.
    #[test]
    fn a_rotation_flood_cannot_grow_the_tracked_table_past_the_cap() {
        let quota = PeerWriteQuota::new();
        let t0 = Instant::now();
        for i in 0..(PER_PEER_QUOTA_TRACKED_PEERS_CAP + 1000) {
            let _ = quota.check_at(&format!("rotating-{i}"), t0);
        }
        assert!(
            quota.tracked_peers() <= PER_PEER_QUOTA_TRACKED_PEERS_CAP,
            "#575 gap 3: the tracked table holds {} buckets, past its cap of \
             {PER_PEER_QUOTA_TRACKED_PEERS_CAP}. `retain` may legitimately \
             free nothing (every bucket that just spent a token is non-full); \
             the insert that follows it must then be refused, not taken.",
            quota.tracked_peers(),
        );
    }

    /// **First contact is one peer's budget, shared.** The v22 amplifier was
    /// not really the eviction policy: it was that every never-seen
    /// `attesting_key_id` was *born with a full allowance*, and identity is
    /// free at this point in the chain (the quota runs deliberately ahead of
    /// the attester lookup). 10 000 identities writing once each therefore
    /// bought 10 000 writes. They now buy exactly what one peer buys,
    /// because the budget they draw on does not multiply with them.
    #[test]
    fn ten_thousand_fresh_identities_buy_one_peer_s_worth() {
        let t0 = Instant::now();

        let one = PeerWriteQuota::new();
        let mut with_one_identity = 0u64;
        while one.check_at("single", t0).is_ok() {
            with_one_identity += 1;
        }

        let many = PeerWriteQuota::new();
        let mut first_contacts = 0u64;
        for i in 0..10_000 {
            if many.check_at(&format!("rotated-{i}"), t0).is_ok() {
                first_contacts += 1;
            }
        }

        assert!(
            first_contacts <= with_one_identity,
            "#575 gap 3: 10 000 fresh identities landed {first_contacts} \
             writes where 1 identity lands {with_one_identity}. A per-identity \
             budget over free identities is not a budget."
        );
    }

    /// The must-ship caveat (#575): **a bounded cap converts a flood into a
    /// censorship primitive** unless the rows that must never be crowded out
    /// have a budget ordinary traffic cannot consume. An accord objection
    /// arriving into a node whose ordinary budgets are entirely spent must
    /// still be admitted.
    #[test]
    fn an_ordinary_flood_cannot_crowd_out_the_reserved_class() {
        let quota = PeerWriteQuota::new();
        let t0 = Instant::now();

        // Spend the node budget down to nothing with ordinary traffic: each
        // flooder gets a bucket on first contact and drains it.
        for i in 0..(NODE_INGEST_BUDGET_MULTIPLE + 4) {
            let key = format!("flood-{i}");
            while quota.check_at(&key, t0).is_ok() {}
        }
        let ordinary = ord(&quota, "any-ordinary-peer", t0)
            .expect_err("the ordinary budgets must be exhausted for this witness to mean anything");
        assert_eq!(ordinary.reason, PeerQuotaRefusal::NodeBurst);

        // The reserved class is untouched — it was never chargeable by any
        // of the traffic above.
        quota
            .check_at_class("accord-holder", WriteAdmissionClass::Reserved, t0)
            .expect(
                "#575 caveat: an accord-class row must not be crowded out by \
                 an ordinary flood — a cap without a reserved admission class \
                 hands an attacker a cheaper denial than the flood it stops",
            );
    }

    /// The reserve is a *reserve*, not a bypass: it is finite, it refuses
    /// with its own named reason, and spending it does not spend anyone
    /// else's budget.
    #[test]
    fn the_reserved_class_is_finite_and_separately_accounted() {
        let quota = PeerWriteQuota::new();
        let t0 = Instant::now();

        let mut reserved_admitted = 0u64;
        loop {
            match quota.check_at_class("accord", WriteAdmissionClass::Reserved, t0) {
                Ok(()) => reserved_admitted += 1,
                Err(refused) => {
                    assert_eq!(
                        refused.reason,
                        PeerQuotaRefusal::ReservedBurst,
                        "the reserve must refuse under its OWN name"
                    );
                    break;
                }
            }
        }
        assert_eq!(
            reserved_admitted,
            u64::from(PER_PEER_ATTESTATION_WRITES_PER_WINDOW)
                * u64::from(RESERVED_CLASS_BUDGET_MULTIPLE),
            "the reserve is exactly {RESERVED_CLASS_BUDGET_MULTIPLE} peer's burst allowance"
        );

        // …and none of that touched the ordinary side: a peer arriving now
        // still has its whole budget.
        let mut ordinary = 0u64;
        while quota.check_at("ordinary", t0).is_ok() {
            ordinary += 1;
        }
        assert_eq!(
            ordinary,
            u64::from(PER_PEER_ATTESTATION_WRITES_PER_WINDOW),
            "reserved traffic must not spend the ordinary budgets"
        );
    }

    /// **No partial charge.** An ordinary write clears two budgets before
    /// either is spent. A check that debited the node and then refused on
    /// the peer would leak the node's budget to refused traffic — the exact
    /// amplification this control exists to close.
    #[test]
    fn a_refused_write_debits_nothing() {
        let quota = PeerWriteQuota::new();
        let t0 = Instant::now();

        // Give `victim` a bucket, then exhaust the NODE budget elsewhere so
        // the refusal comes from a budget that is not victim's own.
        quota.check_at("victim", t0).expect("first write admits");
        let before = quota.peer_burst_tokens("victim").expect("tracked");

        for i in 0..(NODE_INGEST_BUDGET_MULTIPLE + 4) {
            let key = format!("noise-{i}");
            while quota.check_at(&key, t0).is_ok() {}
        }
        // Now every ordinary write is refused, victim's included — and
        // victim still has its whole allowance.
        for _ in 0..50 {
            assert_eq!(
                ord(&quota, "victim", t0)
                    .expect_err("node budget is spent")
                    .reason,
                PeerQuotaRefusal::NodeBurst
            );
        }
        assert_eq!(
            quota.peer_burst_tokens("victim").expect("tracked"),
            before,
            "a refused write must not have debited the peer's own budget"
        );
    }

    /// `classify` is the whole reserved class — a prefix in the set that
    /// `classify` does not route is budget nobody can reach, which is how a
    /// reserve quietly stops covering the family it names.
    #[test]
    fn every_reserved_prefix_classifies_as_reserved() {
        use crate::federation::types::Attestation;

        let row_with = |dimension: &str| Attestation {
            attestation_id: "r".into(),
            attesting_key_id: "k".into(),
            attested_key_id: "k".into(),
            attestation_type: "scores".into(),
            weight: None,
            asserted_at: chrono::Utc::now(),
            expires_at: None,
            attestation_envelope: serde_json::json!({ "dimension": dimension }),
            original_content_hash: String::new(),
            scrub_signature_classical: String::new(),
            scrub_signature_pqc: None,
            scrub_key_id: "k".into(),
            scrub_timestamp: chrono::Utc::now(),
            pqc_completed_at: None,
            persist_row_hash: String::new(),
            subject_key_ids: Vec::new(),
            withdraws_admission_rule: None,
            cohort_scope: "self".into(),
            tier: "federation".into(),
            promoted_at: None,
            additional_scrubs: Vec::new(),
        };

        assert!(
            !RESERVED_CLASS_DIMENSION_PREFIXES.is_empty(),
            "an empty reserved set is a cap with no reserved admission class"
        );
        for prefix in RESERVED_CLASS_DIMENSION_PREFIXES {
            assert_eq!(
                PeerWriteQuota::classify(&row_with(&format!("{prefix}anything:v1"))),
                WriteAdmissionClass::Reserved,
                "`{prefix}` is in the reserved set but does not route there"
            );
        }
        // And the class is narrow: ordinary families, a row with no
        // dimension at all, and a near-miss spelling all stay ordinary.
        for ordinary in [
            "trace:complete:v1",
            "consent:replication:v1",
            "accord",
            "objection",
            "not_accord:x:v1",
        ] {
            assert_eq!(
                PeerWriteQuota::classify(&row_with(ordinary)),
                WriteAdmissionClass::Ordinary,
                "`{ordinary}` must not reach the reserve"
            );
        }
        let mut no_dimension = row_with("x");
        no_dimension.attestation_envelope = serde_json::json!({});
        crate::federation::tier_ingest::test_support::reseal(&mut no_dimension);
        assert_eq!(
            PeerWriteQuota::classify(&no_dimension),
            WriteAdmissionClass::Ordinary
        );
    }

    /// The refusal names the branch, and the token a consumer keys on is the
    /// SAME string on the wire and in the program — the #565 discipline,
    /// applied to the quota's taxonomy.
    #[test]
    fn refusal_reason_tokens_match_serde() {
        for reason in PeerQuotaRefusal::ALL {
            let json = serde_json::to_string(reason).expect("serialize");
            let token = json.trim_matches('"');
            assert_eq!(
                token,
                reason.as_str(),
                "serde token and as_str() must not drift"
            );
            assert_eq!(reason.to_string(), reason.as_str());
            let back: PeerQuotaRefusal = serde_json::from_str(&json).expect("round-trip");
            assert_eq!(back, *reason);
        }
        // Closed set, no catch-all, no duplicate tokens.
        let mut tokens: Vec<&str> = PeerQuotaRefusal::ALL.iter().map(|r| r.as_str()).collect();
        tokens.sort_unstable();
        let before = tokens.len();
        tokens.dedup();
        assert_eq!(before, tokens.len(), "refusal tokens must be distinct");
    }

    /// Each named budget refuses under its own name, so a reader is never
    /// handed the disjunction.
    #[test]
    fn each_budget_refuses_under_its_own_name() {
        let t0 = Instant::now();

        // PeerBurst: a tracked peer spending its own burst.
        let q = PeerWriteQuota::new();
        while ord(&q, "p", t0).is_ok() {}
        assert_eq!(
            ord(&q, "p", t0).unwrap_err().reason,
            PeerQuotaRefusal::PeerBurst
        );

        // PeerSustained: the same peer a burst per window for long enough
        // that the burst bucket is full again and the DAY's budget is not.
        let q = PeerWriteQuota::new();
        let mut at = t0;
        let peer_sustained = loop {
            let ended_with = loop {
                if let Err(refused) = ord(&q, "p", at) {
                    break refused.reason;
                }
            };
            if ended_with == PeerQuotaRefusal::PeerSustained {
                break ended_with;
            }
            at += PER_PEER_ATTESTATION_WRITE_WINDOW;
            assert!(
                at.duration_since(t0) < PER_PEER_SUSTAINED_WRITE_WINDOW,
                "the day horizon must bind within a day"
            );
        };
        assert_eq!(
            peer_sustained,
            PeerQuotaRefusal::PeerSustained,
            "a peer inside its burst but past its day must be told WHICH"
        );

        // UntrackedTailBurst: rotation, once the shared tail is spent.
        let q = PeerWriteQuota::new();
        let mut i = 0;
        let tail_refusal = loop {
            match ord(&q, &format!("rot-{i}"), t0) {
                Ok(()) => i += 1,
                Err(refused) => break refused.reason,
            }
        };
        assert_eq!(tail_refusal, PeerQuotaRefusal::UntrackedTailBurst);

        // NodeBurst: many tracked peers, none of them individually over.
        let q = PeerWriteQuota::new();
        let mut at = t0;
        let mut peers = Vec::new();
        for i in 0..20 {
            let key = format!("peer-{i}");
            q.check_at(&key, at).expect("first contact admits");
            peers.push(key);
            at += Duration::from_secs(1); // let the tail refill
        }
        let node_refusal = 'outer: loop {
            for key in &peers {
                match ord(&q, key, at) {
                    Ok(()) => {}
                    Err(refused) => break 'outer refused.reason,
                }
            }
        };
        assert_eq!(
            node_refusal,
            PeerQuotaRefusal::NodeBurst,
            "'the node is full' is not 'you are too fast' — a peer that \
             cannot tell them apart cannot back off correctly"
        );

        // ReservedBurst / ReservedSustained are covered by
        // `the_reserved_class_is_finite_and_separately_accounted` and
        // `reserved_sustained_horizon_binds`.
    }

    /// The reserve has a day horizon too — it is a budget, not a bypass.
    #[test]
    fn reserved_sustained_horizon_binds() {
        let quota = PeerWriteQuota::new();
        let t0 = Instant::now();
        let mut at = t0;
        let reason = loop {
            let ended_with = loop {
                if let Err(refused) =
                    quota.check_at_class("accord", WriteAdmissionClass::Reserved, at)
                {
                    break refused.reason;
                }
            };
            if ended_with == PeerQuotaRefusal::ReservedSustained {
                break ended_with;
            }
            at += PER_PEER_ATTESTATION_WRITE_WINDOW;
            assert!(
                at.duration_since(t0) < PER_PEER_SUSTAINED_WRITE_WINDOW,
                "the reserve's day horizon must bind within a day"
            );
        };
        assert_eq!(
            reason,
            PeerQuotaRefusal::ReservedSustained,
            "the reserved class must be bounded on the day horizon too"
        );
    }

    /// **Property-style.** A single "refuses at N+1" assertion proves the
    /// least interesting thing about a rate control; what matters is that no
    /// *schedule* of peers and clock advances outruns the ceilings. This
    /// drives a deterministic pseudo-random mix of repeat peers and rotated
    /// identities across a simulated day and checks, after EVERY step, that
    /// three invariants still hold on the whole prefix:
    ///
    /// 1. the node-wide total is within `capacity + rate × elapsed`,
    /// 2. every individual peer is within its own such ceiling,
    /// 3. the tracked table never exceeds its cap.
    ///
    /// Invariant 1 fails immediately against v22 (there was no aggregate
    /// bound at all); invariant 2 fails within a simulated hour; invariant 3
    /// fails once rotation passes the cap.
    #[test]
    fn no_schedule_of_peers_and_clocks_outruns_the_ceilings() {
        let quota = PeerWriteQuota::new();
        let t0 = Instant::now();
        let peer_spec = peer_budget();
        let node_spec = node_budget();

        // Deterministic RNG — a property harness whose schedule changes run
        // to run tells you a different thing each time it is green.
        let mut rng: u64 = 0x5157_5f57_5249_5445;
        let mut next = move || {
            rng ^= rng << 13;
            rng ^= rng >> 7;
            rng ^= rng << 17;
            rng
        };

        let mut elapsed = Duration::ZERO;
        let mut admitted_total: u64 = 0;
        let mut admitted_per_peer: HashMap<String, u64> = HashMap::new();

        for step in 0..5_000u64 {
            let r = next();
            // 3 in 4 bursts come from a small set of repeat peers (the honest
            // shape); 1 in 4 invents a fresh identity (the flood shape).
            let key = if r % 4 == 0 {
                format!("rotated-{step}")
            } else {
                format!("repeat-{}", (r >> 8) % 12)
            };
            // Advance the clock 0-2s most steps, occasionally a long idle —
            // an equal-clock schedule tests refills trivially.
            elapsed += if (r >> 20) % 97 == 0 {
                Duration::from_secs((r >> 32) % 900)
            } else {
                Duration::from_millis((r >> 24) % 2_000)
            };

            // GREEDY: take everything on offer, up to a bounded attempt run.
            // A polite schedule never reaches a ceiling and so never tests one.
            for _ in 0..((r >> 40) % 200) {
                if quota.check_at(&key, t0 + elapsed).is_err() {
                    break;
                }
                admitted_total += 1;
                *admitted_per_peer.entry(key.clone()).or_default() += 1;
            }

            let node_ceiling = ceiling(&node_spec, elapsed);
            assert!(
                admitted_total <= node_ceiling,
                "step {step}: {admitted_total} writes admitted node-wide in \
                 {elapsed:?}, over the ceiling {node_ceiling}"
            );
            let peer_ceiling = ceiling(&peer_spec, elapsed);
            for (peer, n) in &admitted_per_peer {
                assert!(
                    *n <= peer_ceiling,
                    "step {step}: peer {peer} landed {n} writes in {elapsed:?}, \
                     over its ceiling {peer_ceiling}"
                );
            }
            assert!(
                quota.tracked_peers() <= PER_PEER_QUOTA_TRACKED_PEERS_CAP,
                "step {step}: tracked table at {} exceeds its cap",
                quota.tracked_peers()
            );
        }

        // The schedule has to have exercised something, or the invariants
        // above are vacuous.
        assert!(
            admitted_total > 1_000,
            "the harness admitted only {admitted_total} writes — it is not \
             exercising the control"
        );
    }

    // ── v25.1.0 (CIRISPersist#583) — the byte dimension, the tail-squeeze,
    //    and the three gates that outlive both fixes ────────────────────────

    /// A federation-tier row whose envelope is exactly `envelope`.
    fn row_with_envelope(
        key: &str,
        envelope: serde_json::Value,
    ) -> crate::federation::types::Attestation {
        crate::federation::types::Attestation {
            attestation_id: "r".into(),
            attesting_key_id: key.into(),
            attested_key_id: key.into(),
            attestation_type: "attestation:self_verify".into(),
            weight: None,
            asserted_at: chrono::Utc::now(),
            expires_at: None,
            attestation_envelope: envelope,
            original_content_hash: String::new(),
            scrub_signature_classical: String::new(),
            scrub_signature_pqc: None,
            scrub_key_id: key.into(),
            scrub_timestamp: chrono::Utc::now(),
            pqc_completed_at: None,
            persist_row_hash: String::new(),
            subject_key_ids: Vec::new(),
            withdraws_admission_rule: None,
            cohort_scope: "self".into(),
            tier: "federation".into(),
            promoted_at: None,
            additional_scrubs: Vec::new(),
        }
    }

    /// A row whose envelope serializes to approximately `bytes`.
    fn row_of_size(key: &str, bytes: usize) -> crate::federation::types::Attestation {
        // `{"pad":"…"}` — 12 bytes of framing around the padding.
        let pad = bytes.saturating_sub(12);
        row_with_envelope(key, serde_json::json!({ "pad": "x".repeat(pad) }))
    }

    /// **FIX 1, RED-FIRST WITNESS (#583).** *"600 rows of 100 B and 600 rows
    /// of 10 MB cost the same."* They did: `classify` keyed on the envelope's
    /// dimension, `spend` decremented a count, and **nothing in the quota
    /// path read a payload size** — so inauthentic *storage* was invisible to
    /// the control that exists to bound it.
    ///
    /// Against v24.3.0 this fails on its first assertion: all three row sizes
    /// admit exactly `PER_PEER_ATTESTATION_WRITES_PER_WINDOW`, including the
    /// 10 MB one, and a peer at its full row allowance lands ~6 GB.
    #[test]
    fn a_ten_megabyte_row_must_not_cost_the_same_as_a_hundred_byte_row() {
        // Capped: a rows-only quota admits 600 of ANY size, and 600 × 10 MB
        // is 6 GB of serialization in a debug build. The caps are above every
        // count a correct implementation can produce, so they change nothing
        // green and turn a slow failure into a fast one.
        let admits = |row: &crate::federation::types::Attestation, cap: u64| -> u64 {
            let quota = PeerWriteQuota::new();
            let mut n = 0u64;
            while n < cap && quota.check_write_typed(row).is_ok() {
                n += 1;
            }
            n
        };

        let small = row_of_size("byte-witness", 100);
        let large = row_of_size("byte-witness", 900 * 1024);
        let huge = row_of_size("byte-witness", 10 * 1024 * 1024);

        let small_admitted = admits(
            &small,
            4 * u64::from(PER_PEER_ATTESTATION_WRITES_PER_WINDOW),
        );
        let large_admitted = admits(&large, 32);
        let huge_admitted = admits(&huge, 4);

        assert!(
            large_admitted < 32 && large_admitted < small_admitted,
            "#583: a 900 KiB row landed {large_admitted} times and a 100 B row \
             {small_admitted} — a quota that meters ROWS ONLY cannot tell a \
             storage flood from a row flood, so 600 × 100 B and 600 × 10 MB \
             cost the same and ~6 GB is 'within quota'"
        );
        assert_eq!(
            small_admitted,
            u64::from(PER_PEER_ATTESTATION_WRITES_PER_WINDOW),
            "small rows must still be bounded by the ROW dimension — the byte \
             dimension must not become a second, tighter row control (AV-75)"
        );
        assert_eq!(
            huge_admitted, 0,
            "a single 10 MB row exceeds one peer's whole burst BYTE allowance \
             ({PER_PEER_ATTESTATION_BYTES_PER_WINDOW} B) and must be refused \
             outright"
        );

        // …and the refusal NAMES the dimension, so an operator can tell a row
        // flood from a storage flood without reading a message string (#583,
        // #565's contract).
        let quota = PeerWriteQuota::new();
        for _ in 0..32 {
            if quota.check_write_typed(&large).is_err() {
                break;
            }
        }
        let refused = quota
            .check_write_typed(&large)
            .expect_err("the byte budget is spent");
        assert_eq!(
            refused.reason.dimension(),
            QuotaDimension::Bytes,
            "a storage flood must be refused on the BYTE dimension, got {}",
            refused.reason
        );
        assert_eq!(refused.reason.as_str(), "peer_bytes_burst");
        assert!(refused.retry_after_seconds >= 1);
    }

    /// The byte dimension is charged on the row's *actual* envelope, and the
    /// floor is real: an empty envelope is not free storage, because the row
    /// it rides on is not free storage (two signatures, hashes, ids,
    /// indexes).
    #[test]
    fn the_byte_charge_is_the_envelope_floored_at_a_typical_row() {
        assert_eq!(
            envelope_charged_bytes(&serde_json::json!({})),
            2,
            "an empty envelope serializes to `{{}}`"
        );
        assert!(
            envelope_charged_bytes(&serde_json::json!({ "pad": "x".repeat(4096) })) >= 4096,
            "the charge must track the payload"
        );
        let floor = WriteCost::floor();
        for d in QuotaDimension::ALL {
            assert!(
                floor.of(*d) > 0.0,
                "no entry point may charge zero on a metered dimension — a \
                 size-free door into a size-metered control is the {} \
                 dimension not being metered",
                d.as_str()
            );
        }
        assert!(
            (WriteCost::for_envelope_bytes(2).of(QuotaDimension::Bytes)
                - TYPICAL_ATTESTATION_ENVELOPE_BYTES as f64)
                .abs()
                < f64::EPSILON,
            "a tiny envelope is charged the typical-row floor"
        );
    }

    /// **FIX 2, RED-FIRST WITNESS (#583).** The residue of the 4096-cap
    /// inversion: *"once the table saturates with live-spending peers, no new
    /// bucket is created and an honest newcomer is demoted to the shared
    /// untracked tail the attacker is saturating."*
    ///
    /// The attack, in three phases:
    ///
    /// 1. the fleet acquires every slot it can (rate-limited by the shared
    ///    tail, so this costs simulated minutes, not writes-out-of-nowhere);
    /// 2. everything refills, and then the fleet touches every identity it
    ///    holds **inside one sustained-token refill**, so no bucket is
    ///    prunable at the instant that matters;
    /// 3. an honest peer arrives.
    ///
    /// Against a 4096 cap the fleet holds all 4096 slots non-full — 4096 node
    /// burst tokens out of 6000 buys it — the prune frees nothing, and the
    /// newcomer is admitted with **no individual budget**, metered against
    /// the very tail the fleet is saturating. Against the derived 8192 cap
    /// the fleet cannot hold the table: the node budget it must spend to keep
    /// buckets non-full runs out first, the prune always frees a slot, and
    /// the newcomer's first contact still buys it a budget of its own.
    #[test]
    fn an_honest_newcomer_gets_its_own_budget_during_a_rotation_flood() {
        let quota = PeerWriteQuota::new();
        let t0 = Instant::now();
        let mut at = t0;
        let mut fleet: Vec<String> = Vec::new();

        // Phase 1 — acquire slots. Bounded by simulated time, not by hope:
        // the tail admits ~10 first contacts a second, so filling the table
        // takes a quarter-hour whatever the cap is.
        while fleet.len() < PER_PEER_QUOTA_TRACKED_PEERS_CAP
            && at.duration_since(t0) < Duration::from_secs(7_200)
        {
            for _ in 0..16 {
                if fleet.len() >= PER_PEER_QUOTA_TRACKED_PEERS_CAP {
                    break;
                }
                let id = format!("fleet-{}", fleet.len());
                if ord(&quota, &id, at).is_ok() {
                    fleet.push(id);
                } else {
                    break;
                }
            }
            at += Duration::from_secs(1);
        }
        assert!(
            fleet.len() > PER_PEER_QUOTA_TRACKED_PEERS_CAP / 2,
            "the fleet acquired only {} slots — the witness is not exercising \
             saturation",
            fleet.len()
        );

        // Phase 2 — let every budget refill, then squeeze: touch the whole
        // fleet at ONE instant, so every bucket carries a deficit and nothing
        // is prunable.
        at += PER_PEER_ATTESTATION_WRITE_WINDOW * 2;
        let mut touched = 0u64;
        for id in &fleet {
            if ord(&quota, id, at).is_ok() {
                touched += 1;
            }
        }

        // Phase 3 — the honest newcomer, one second later: long enough for
        // the node budget to have a token for it, far short of the six
        // seconds a spent bucket needs to become prunable. The squeeze is
        // still on.
        at += Duration::from_secs(1);
        ord(&quota, "honest-newcomer", at)
            .expect("the newcomer's first write must be admitted (the tail pays for it)");
        assert!(
            quota.tracks("honest-newcomer"),
            "#583 tail-squeeze: an honest peer arriving during a flood was \
             admitted but got NO individual budget — it is metered against the \
             shared untracked tail the fleet is saturating. The fleet holds \
             {} of {PER_PEER_QUOTA_TRACKED_PEERS_CAP} slots and touched \
             {touched} of them in one instant; the table must be sized so \
             that spend cannot cover it.",
            fleet.len(),
        );
        assert_eq!(
            quota.slot_denials(),
            0,
            "no write may be denied an individual budget: the tracked-table \
             cap is derived to make that branch unreachable"
        );
    }

    // ── GATE 1 — DIMENSIONAL COMPLETENESS ──────────────────────────────────

    /// The write cost that makes `dim` the binding dimension.
    ///
    /// Rows bind at the floor (a typical row is 1/10th of the calibration
    /// size, so the row budget runs out ten times sooner); bytes bind at four
    /// calibration rows (so the byte budget runs out four times sooner than
    /// the row budget). Both are derived from the constants, so a tuned
    /// calibration re-derives the witness rather than stranding it.
    fn witness_cost(dim: QuotaDimension) -> WriteCost {
        match dim {
            QuotaDimension::Rows => WriteCost::floor(),
            QuotaDimension::Bytes => WriteCost::for_envelope_bytes(QUOTA_CALIBRATION_ROW_BYTES * 4),
        }
    }

    /// Drive the quota until the `(budget, dimension, horizon)` cell refuses,
    /// and return what it said. Panics — with the cell named — if no schedule
    /// inside a simulated day gets there, which is what "this cell is metered
    /// but nothing can witness it" looks like.
    fn witness_refusal(
        budget: QuotaBudget,
        dim: QuotaDimension,
        horizon: QuotaHorizon,
    ) -> PeerQuotaRefusal {
        let cost = witness_cost(dim);
        let quota = PeerWriteQuota::new();
        let t0 = Instant::now();
        let mut at = t0;

        let class = match budget {
            QuotaBudget::Reserved => WriteAdmissionClass::Reserved,
            _ => WriteAdmissionClass::Ordinary,
        };
        // Peer: one identity spends its own. Node: enough identities that no
        // ONE of them can exhaust its own budget before the node's.
        // UntrackedTail: a fresh identity every write. Reserved: its own
        // class, which touches nothing else.
        let keys: Vec<String> = match budget {
            QuotaBudget::Peer => vec!["solo".into()],
            QuotaBudget::Reserved => vec!["accord".into()],
            QuotaBudget::Node => (0..(2 * NODE_INGEST_BUDGET_MULTIPLE))
                .map(|i| format!("node-peer-{i}"))
                .collect(),
            QuotaBudget::UntrackedTail => Vec::new(),
        };

        let mut rotation = 0u64;
        for _ in 0..256 {
            let ended = loop {
                if keys.is_empty() {
                    rotation += 1;
                    if let Err(refused) = quota.charge(&format!("rot-{rotation}"), class, &cost, at)
                    {
                        break refused.reason;
                    }
                } else {
                    let mut refusal = None;
                    for k in &keys {
                        if let Err(refused) = quota.charge(k, class, &cost, at) {
                            refusal = Some(refused.reason);
                            break;
                        }
                    }
                    if let Some(r) = refusal {
                        break r;
                    }
                }
            };
            if ended.budget() == budget && ended.dimension() == dim && ended.horizon() == horizon {
                return ended;
            }
            at += PER_PEER_ATTESTATION_WRITE_WINDOW;
        }
        panic!(
            "no schedule reached the ({budget:?}, {}, {horizon:?}) refusal in \
             256 windows — the quota meters that cell and nothing witnesses \
             it. #583: the row dimension shipped without a byte sibling \
             precisely because nothing asserted the set was complete.",
            dim.as_str()
        );
    }

    /// **GATE 1 — DIMENSIONAL COMPLETENESS (#583).**
    ///
    /// The refusal taxonomy is exactly `QuotaBudget × QuotaDimension ×
    /// QuotaHorizon`, and **every cell of that product is driven to a real
    /// refusal by a real schedule.** Three things fail here, in increasing
    /// order of subtlety:
    ///
    /// 1. adding a [`QuotaDimension`] variant does not compile until it is
    ///    sized ([`BudgetSpec::for_multiple`]), priced
    ///    ([`WriteCost::for_envelope_bytes`]) and named
    ///    ([`PeerQuotaRefusal::of`]) — the arrays are `[_;
    ///    QuotaDimension::COUNT]` and the matches are exhaustive;
    /// 2. it then fails the cardinality assertion below until the refusal
    ///    variants exist;
    /// 3. and it fails [`witness_refusal`] until a schedule can actually
    ///    drive the new cells — which is the assertion that a *metered*
    ///    dimension is a *reachable* one, the AV-77 lesson applied to a
    ///    taxonomy.
    ///
    /// Point 3 is the one #583 is about. The row dimension shipped alone in
    /// v22.0.0 not because anyone decided bytes did not matter but because
    /// there was no set to be incomplete — only a field.
    #[test]
    fn every_metered_dimension_has_a_witness() {
        assert_eq!(
            QuotaDimension::ALL.len(),
            QuotaDimension::COUNT,
            "COUNT sizes every per-dimension array; it must equal ALL"
        );
        for (i, d) in QuotaDimension::ALL.iter().enumerate() {
            assert_eq!(d.index(), i, "dimension indices must be dense and stable");
        }
        assert_eq!(
            PeerQuotaRefusal::ALL.len(),
            QuotaBudget::ALL.len() * QuotaDimension::ALL.len() * QuotaHorizon::ALL.len(),
            "the refusal taxonomy must be the FULL product of budget × \
             dimension × horizon — a metered dimension with no refusal token \
             is a budget that refuses under someone else's name"
        );

        // The product and the enum are the same set, both ways.
        let mut produced = std::collections::HashSet::new();
        for b in QuotaBudget::ALL {
            for d in QuotaDimension::ALL {
                for h in QuotaHorizon::ALL {
                    assert!(
                        produced.insert(PeerQuotaRefusal::of(*b, *d, *h)),
                        "two cells map to one refusal token"
                    );
                }
            }
        }
        for r in PeerQuotaRefusal::ALL {
            assert!(
                produced.contains(r),
                "{r} is in the taxonomy but no (budget, dimension, horizon) \
                 produces it"
            );
            assert_eq!(
                PeerQuotaRefusal::of(r.budget(), r.dimension(), r.horizon()),
                *r,
                "{r}'s accessors must round-trip through `of`"
            );
        }

        // …and every cell has a WITNESS: a schedule that really refuses there.
        for b in QuotaBudget::ALL {
            for d in QuotaDimension::ALL {
                for h in QuotaHorizon::ALL {
                    let observed = witness_refusal(*b, *d, *h);
                    assert_eq!(
                        observed,
                        PeerQuotaRefusal::of(*b, *d, *h),
                        "witness for ({b:?}, {}, {h:?}) refused as {observed}",
                        d.as_str()
                    );
                }
            }
        }
    }

    // ── GATE 2 — ADVERSARY MONOTONICITY ────────────────────────────────────

    /// **GATE 2 — ADVERSARY MONOTONICITY (#583), property-style.**
    ///
    /// > A peer with no history cannot degrade the service another peer
    /// > already had, and the eviction rule cannot be steered by the party it
    /// > is meant to bound.
    ///
    /// A single scenario proves the least interesting case, so this drives a
    /// deterministic pseudo-random adversary — rotation, deep drains,
    /// byte-heavy writes, clock jumps, and a *squeeze* that touches the whole
    /// held fleet at one instant — past the tracked-table cap so the eviction
    /// path really runs, with one honest incumbent writing alongside. Four
    /// invariants, re-checked as the run proceeds:
    ///
    /// 1. **No reset.** Every key's cumulative admitted writes stay inside
    ///    the ceiling `capacity + rate × elapsed` its OWN bucket allows. An
    ///    eviction that re-created a bucket carrying a deficit would hand
    ///    that key its spent budget back and show up here immediately — which
    ///    is why the prune may only drop buckets that are FULL.
    /// 2. **The incumbent is untouched.** Its bucket is differentialled
    ///    against a shadow driven only by its own writes and the clock. If
    ///    the adversary could evict-and-reseed it, drain it, or age it
    ///    differently, the two diverge.
    /// 3. **No slot denial.** A peer with no history always leaves first
    ///    contact with an individual budget.
    /// 4. **The table stays bounded**, which is the memory half the cap
    ///    exists for and must not be traded away for invariant 3.
    #[test]
    fn no_adversary_schedule_resets_itself_or_degrades_an_incumbent() {
        let quota = PeerWriteQuota::new();
        let peer_spec = peer_budget();
        let t0 = Instant::now();
        let mut at = t0;

        // Deterministic RNG — a property harness whose schedule changes run
        // to run tells you a different thing each time it is green.
        let mut rng: u64 = 0x5833_4144_5645_5253;
        let mut next = move || {
            rng ^= rng << 13;
            rng ^= rng >> 7;
            rng ^= rng << 17;
            rng
        };

        let honest = "honest-incumbent";
        let mut shadow = PeerBucket::full(&peer_spec, at);
        let mut shadow_live = false;
        // Cumulative cost per key, per dimension. Counting *writes* would not
        // do: the adversary mixes cheap and byte-heavy rows on one identity,
        // and the invariant is about what it SPENT, not how often.
        let mut spent: HashMap<String, [f64; QuotaDimension::COUNT]> = HashMap::new();
        let mut admitted: HashMap<String, u64> = HashMap::new();
        let mut fleet: Vec<String> = Vec::new();
        let mut squeezes = 0u64;
        let mut evictions_seen = false;
        let mut peak_tracked = 0usize;

        let charge = |key: &str,
                      cost: &WriteCost,
                      at: Instant,
                      spent: &mut HashMap<String, [f64; QuotaDimension::COUNT]>|
         -> bool {
            let ok = quota
                .charge(key, WriteAdmissionClass::Ordinary, cost, at)
                .is_ok();
            if ok {
                let elapsed = at.duration_since(t0).as_secs_f64();
                let acc = spent
                    .entry(key.to_owned())
                    .or_insert([0.0; QuotaDimension::COUNT]);
                // INVARIANT 1, checked on the key that just changed. A bucket
                // starts full, so everything this key has EVER spent must fit
                // inside `capacity + rate × elapsed` on every cell — an
                // eviction that re-created a bucket carrying a deficit would
                // hand it the difference back and break this immediately.
                for d in QuotaDimension::ALL {
                    acc[d.index()] += cost.of(*d);
                    for h in QuotaHorizon::ALL {
                        let hs = peer_spec.dim(*d).horizon(*h);
                        let bound = hs.capacity + hs.per_second * elapsed;
                        assert!(
                            acc[d.index()] <= bound * (1.0 + 1e-9) + 1e-6,
                            "#583 no-reset: {key} has spent {} on the ({}, \
                             {h:?}) cell in {elapsed:.1}s, over the {bound} its \
                             OWN bucket allows. An eviction that frees a bucket \
                             carrying a deficit hands its owner the budget back \
                             — which is why the prune may only drop FULL \
                             buckets, and why 'evict by adversary cost' is a \
                             reset primitive wearing a fairness costume.",
                            acc[d.index()],
                            d.as_str(),
                        );
                    }
                }
            }
            ok
        };

        for step in 0..6_000u64 {
            let r = next();

            // The honest incumbent writes at a modest, steady rate. Its
            // bucket is differentialled against a shadow that only ever sees
            // the incumbent's own writes.
            if r % 3 == 0 {
                shadow.refill(&peer_spec, at);
                if !shadow_live {
                    shadow = PeerBucket::full(&peer_spec, at);
                    shadow_live = true;
                }
                let cost = WriteCost::floor();
                let real = quota.charge(honest, WriteAdmissionClass::Ordinary, &cost, at);
                if real.is_ok() {
                    shadow.spend(&cost);
                    let n = admitted.entry(honest.to_owned()).or_default();
                    *n += 1;
                }
                if let Some(bucket) = quota.peer_tokens_at(honest, at) {
                    // INVARIANT 2 — cell by cell.
                    for d in QuotaDimension::ALL {
                        for h in QuotaHorizon::ALL {
                            let mine = bucket.tokens[d.index()].horizon(*h);
                            let theirs = shadow.tokens[d.index()].horizon(*h);
                            assert!(
                                (mine - theirs).abs() <= 1e-6 * theirs.abs().max(1.0),
                                "#583 step {step}: the incumbent's own \
                                 ({}, {h:?}) budget is {mine} where its own \
                                 history says {theirs} — a peer with no \
                                 history changed the service a peer already \
                                 had",
                                d.as_str(),
                            );
                        }
                    }
                } else {
                    // Pruned because it was FULL — a no-op by construction,
                    // and the only eviction this design permits. The shadow
                    // must agree that it was full.
                    let mut probe = shadow;
                    probe.refill(&peer_spec, at);
                    assert!(
                        probe.is_full(&peer_spec),
                        "#583 step {step}: the incumbent lost its bucket while \
                         it still carried a deficit — that is an eviction the \
                         adversary steered, and re-creating it full is a reset"
                    );
                    shadow_live = false;
                }
            }

            // The adversary. Four shapes, chosen deterministically. Where a
            // shape gets to pick a payload size it does, so the byte
            // dimension is under attack as well as the row dimension.
            let heavy =
                WriteCost::for_envelope_bytes(QUOTA_CALIBRATION_ROW_BYTES * ((r >> 6) % 8 + 1));
            let cost = if (r >> 4) % 3 == 0 {
                heavy
            } else {
                WriteCost::floor()
            };
            match (r >> 12) % 32 {
                // Rotate: brand-new identities, one write each — the shape
                // that fills the table. Cheap rows on purpose: acquiring
                // slots is what the flooder wants, and the cheapest row buys
                // the most of them.
                0..=15 => {
                    for _ in 0..(1 + (r >> 16) % 24) {
                        let id = format!("rot-{}", fleet.len());
                        if charge(&id, &WriteCost::floor(), at, &mut spent) {
                            fleet.push(id);
                        } else {
                            break;
                        }
                    }
                }
                // Deep-drain one held identity: the shape that keeps a bucket
                // non-full for as long as possible per token.
                16..=23 => {
                    if !fleet.is_empty() {
                        let id = fleet[((r >> 20) as usize) % fleet.len()].clone();
                        for _ in 0..(1 + (r >> 24) % 200) {
                            if !charge(&id, &cost, at, &mut spent) {
                                break;
                            }
                        }
                    }
                }
                // Squeeze: touch the whole held fleet at ONE instant, so
                // nothing is prunable when the next newcomer arrives.
                24 => {
                    squeezes += 1;
                    let ids: Vec<String> = fleet.clone();
                    for id in &ids {
                        if !charge(id, &cost, at, &mut spent) {
                            break;
                        }
                    }
                    // …and a newcomer arrives into exactly that instant.
                    let newcomer = format!("newcomer-{step}");
                    if charge(&newcomer, &cost, at, &mut spent) {
                        assert!(
                            quota.tracks(&newcomer),
                            "#583 step {step}: a newcomer admitted during a \
                             squeeze got no individual budget — it is metered \
                             against the very tail the fleet is saturating"
                        );
                        fleet.push(newcomer);
                    }
                }
                // Idle: let things refill. An equal-clock schedule tests
                // refills trivially.
                _ => {}
            }

            at += match (r >> 32) % 16 {
                0 => Duration::from_secs(1 + (r >> 36) % 900),
                1..=3 => Duration::from_secs(1 + (r >> 40) % 7),
                _ => Duration::from_millis((r >> 44) % 1_500),
            };

            // INVARIANTS 3 and 4.
            assert_eq!(
                quota.slot_denials(),
                0,
                "#583 step {step}: {} writes have been denied an individual \
                 budget. The table must be sized above what any flood can hold \
                 non-full ({} tracked, cap {PER_PEER_QUOTA_TRACKED_PEERS_CAP})",
                quota.slot_denials(),
                quota.tracked_peers(),
            );
            let tracked = quota.tracked_peers();
            assert!(
                tracked <= PER_PEER_QUOTA_TRACKED_PEERS_CAP,
                "#583 step {step}: the tracked table holds {tracked}, past its \
                 cap — invariant 3 must not be bought with unbounded memory"
            );
            if tracked < peak_tracked {
                evictions_seen = true;
            }
            peak_tracked = peak_tracked.max(tracked);
        }

        // The harness has to have exercised the machinery, or every invariant
        // above is vacuous.
        assert!(
            fleet.len() > PER_PEER_QUOTA_TRACKED_PEERS_CAP,
            "the adversary only reached {} identities — it never made the \
             tracked table choose",
            fleet.len()
        );
        assert!(
            evictions_seen,
            "the prune never ran; the no-reset invariant was never tested \
             against an actual eviction"
        );
        assert!(squeezes > 0, "the squeeze shape never fired");
        assert!(
            admitted.get(honest).copied().unwrap_or(0) > 100,
            "the incumbent barely wrote; the differential is vacuous"
        );
    }

    // ── GATE 3 — DERIVATION ────────────────────────────────────────────────

    /// The quota block of this file, so the gate below can read the source it
    /// is gating. `include_str!` resolves relative to this file.
    const QUOTA_SOURCE: &str = include_str!("admission.rs");

    /// Every `pub const` between the QUOTA CONSTANTS markers, paired with the
    /// doc block immediately above it.
    fn gated_constants() -> Vec<(String, String)> {
        let begin = QUOTA_SOURCE
            .find("QUOTA CONSTANTS — BEGIN")
            .expect("the derivation-gated block must be marked");
        let end = QUOTA_SOURCE
            .find("QUOTA CONSTANTS — END")
            .expect("the derivation-gated block must be closed");
        assert!(begin < end, "the markers must bracket the block");

        let mut out = Vec::new();
        let mut doc = String::new();
        for line in QUOTA_SOURCE[begin..end].lines() {
            let t = line.trim_start();
            if let Some(rest) = t.strip_prefix("///") {
                doc.push_str(rest);
                doc.push('\n');
            } else if let Some(rest) = t.strip_prefix("pub const ") {
                let name = rest
                    .split(|c: char| c == ':' || c.is_whitespace())
                    .next()
                    .unwrap_or_default()
                    .to_owned();
                out.push((name, std::mem::take(&mut doc)));
            } else if !t.starts_with("//") && !t.is_empty() {
                doc.clear();
            }
        }
        out
    }

    /// **GATE 3 — DERIVATION (#583).** Every quota number is traceable to a
    /// stated rationale, and the constants and their documented bounds stay
    /// in agreement.
    ///
    /// Three failure modes, all of them things a future tuner does:
    ///
    /// 1. **A new constant with no rationale.** The gate scans its own source
    ///    for `pub const` items inside the marked block and requires each to
    ///    carry a `**Bounds:**` line (what it bounds) and a `**Derived:**`
    ///    line (why that value) — and to be named in `GATED` below, so a new
    ///    number cannot arrive without someone writing down its relationship
    ///    to the others.
    /// 2. **A tuned number that breaks a stated identity.** The derived
    ///    constants are written as literals *and* asserted equal to their
    ///    derivations, so raising the byte budget without restating the
    ///    calibration it comes from fails here rather than silently
    ///    un-pricing storage.
    /// 3. **A tuned number that breaks a stated inequality** — the byte
    ///    dimension binding before the row dimension on honest traffic
    ///    (AV-75), or a legal row becoming unaffordable to a budget it must
    ///    pass through, which is a control that structurally cannot admit a
    ///    row the layer above calls legal.
    #[test]
    fn every_quota_constant_is_derived() {
        /// Every constant the relationships below account for. A constant in
        /// the block and not in this list fails the gate.
        const GATED: &[&str] = &[
            "PER_PEER_ATTESTATION_WRITES_PER_WINDOW",
            "PER_PEER_ATTESTATION_WRITE_WINDOW",
            "PER_PEER_SUSTAINED_WRITES_PER_WINDOW",
            "PER_PEER_SUSTAINED_WRITE_WINDOW",
            "TYPICAL_ATTESTATION_ENVELOPE_BYTES",
            "QUOTA_BYTE_HEADROOM_MULTIPLE",
            "QUOTA_CALIBRATION_ROW_BYTES",
            "PER_PEER_ATTESTATION_BYTES_PER_WINDOW",
            "PER_PEER_SUSTAINED_BYTES_PER_WINDOW",
            "PER_PEER_QUOTA_TRACKED_PEERS_CAP",
            "UNTRACKED_TAIL_BUDGET_MULTIPLE",
            "NODE_INGEST_BUDGET_MULTIPLE",
            "RESERVED_CLASS_BUDGET_MULTIPLE",
            "RESERVED_CLASS_DIMENSION_PREFIXES",
        ];

        let found = gated_constants();
        assert_eq!(
            found.len(),
            GATED.len(),
            "the derivation-gated block declares {} constants and the gate \
             accounts for {}: {:?}",
            found.len(),
            GATED.len(),
            found.iter().map(|(n, _)| n).collect::<Vec<_>>(),
        );
        for (name, doc) in &found {
            assert!(
                GATED.contains(&name.as_str()),
                "`{name}` is a quota constant with no entry in the derivation \
                 gate. A magic constant with no derivation is a future \
                 incident (#583): name what it bounds, and assert its \
                 relationship to the numbers it comes from."
            );
            assert!(
                doc.contains("**Bounds:**"),
                "`{name}` does not say what it BOUNDS"
            );
            assert!(
                doc.contains("**Derived:**"),
                "`{name}` does not say why THAT VALUE"
            );
        }

        // ── the identities the docs claim ──────────────────────────────────
        assert_eq!(
            PER_PEER_SUSTAINED_WRITES_PER_WINDOW,
            24 * PER_PEER_ATTESTATION_WRITES_PER_WINDOW,
            "the sustained ROW ceiling is derived as one burst allowance per \
             hour, forever — 24 × the burst"
        );
        assert_eq!(
            PER_PEER_SUSTAINED_WRITE_WINDOW,
            PER_PEER_ATTESTATION_WRITE_WINDOW * 60 * 24,
            "the day horizon is 1440 burst windows"
        );
        assert_eq!(
            QUOTA_CALIBRATION_ROW_BYTES,
            TYPICAL_ATTESTATION_ENVELOPE_BYTES * QUOTA_BYTE_HEADROOM_MULTIPLE,
            "the calibration row is TYPICAL × HEADROOM — one new free \
             parameter in the byte dimension, not two magic sizes"
        );
        assert_eq!(
            PER_PEER_ATTESTATION_BYTES_PER_WINDOW,
            u64::from(PER_PEER_ATTESTATION_WRITES_PER_WINDOW) * QUOTA_CALIBRATION_ROW_BYTES,
            "the burst BYTE ceiling is the burst ROW ceiling re-priced"
        );
        assert_eq!(
            PER_PEER_SUSTAINED_BYTES_PER_WINDOW,
            u64::from(PER_PEER_SUSTAINED_WRITES_PER_WINDOW) * QUOTA_CALIBRATION_ROW_BYTES,
            "the sustained BYTE ceiling is the sustained ROW ceiling re-priced"
        );
        assert_eq!(
            PER_PEER_SUSTAINED_BYTES_PER_WINDOW,
            24 * PER_PEER_ATTESTATION_BYTES_PER_WINDOW,
            "…and therefore also one burst allowance per hour, forever — the \
             two derivations must agree"
        );

        // ── the inequalities the docs claim ────────────────────────────────
        //
        // Read through locals so the assertions are evaluated rather than
        // const-folded away: `assert!(CONST >= 8)` is a compile-time tautology
        // clippy rightly objects to, and a gate that disappears when the
        // constant is right is not a gate on the constant being right.
        let (headroom, typical, calibration) = (
            QUOTA_BYTE_HEADROOM_MULTIPLE,
            TYPICAL_ATTESTATION_ENVELOPE_BYTES,
            QUOTA_CALIBRATION_ROW_BYTES,
        );
        let (node_mult, tail_mult, reserved_mult) = (
            NODE_INGEST_BUDGET_MULTIPLE,
            UNTRACKED_TAIL_BUDGET_MULTIPLE,
            RESERVED_CLASS_BUDGET_MULTIPLE,
        );
        assert!(
            headroom >= 8,
            "AV-75: at less than ~8× the typical row the byte dimension binds \
             on merely-larger-than-average honest traffic and becomes a second \
             row control — a control that refuses honest bulk replication is \
             an outage, not a gate"
        );
        assert!(
            typical < calibration
                && calibration
                    < crate::federation::admission::MAX_ATTESTATION_ENVELOPE_BYTES as u64,
            "the calibration row must sit strictly between the typical row \
             (so honest traffic is row-bound) and the single-row cap (so the \
             few-huge shape is byte-bound)"
        );

        // Affordability: a row the layer above calls legal must be payable by
        // EVERY budget it can be charged against, or the quota structurally
        // cannot admit it and the refusal is a lie about rate.
        let smallest = UNTRACKED_TAIL_BUDGET_MULTIPLE
            .min(RESERVED_CLASS_BUDGET_MULTIPLE)
            .min(1);
        let spec = BudgetSpec::for_multiple(smallest);
        let legal_row = WriteCost::for_envelope_bytes(
            crate::federation::admission::MAX_ATTESTATION_ENVELOPE_BYTES as u64,
        );
        for d in QuotaDimension::ALL {
            for h in QuotaHorizon::ALL {
                assert!(
                    spec.dim(*d).horizon(*h).capacity >= legal_row.of(*d),
                    "a maximum-size LEGAL row costs {} on the {} dimension and \
                     the smallest budget's {h:?} capacity is {} — the quota \
                     would refuse for ever a row the envelope-size gate calls \
                     admissible",
                    legal_row.of(*d),
                    d.as_str(),
                    spec.dim(*d).horizon(*h).capacity,
                );
            }
        }

        // The specs really read the constants (a spec that stopped would make
        // every identity above true and every behaviour wrong).
        let peer = BudgetSpec::for_multiple(1);
        assert_eq!(
            peer.dim(QuotaDimension::Rows).burst.capacity,
            f64::from(PER_PEER_ATTESTATION_WRITES_PER_WINDOW)
        );
        assert_eq!(
            peer.dim(QuotaDimension::Rows).sustained.capacity,
            f64::from(PER_PEER_SUSTAINED_WRITES_PER_WINDOW)
        );
        assert_eq!(
            peer.dim(QuotaDimension::Bytes).burst.capacity,
            PER_PEER_ATTESTATION_BYTES_PER_WINDOW as f64
        );
        assert_eq!(
            peer.dim(QuotaDimension::Bytes).sustained.capacity,
            PER_PEER_SUSTAINED_BYTES_PER_WINDOW as f64
        );

        // The remaining multiples, and the reserved vocabulary.
        assert!(
            node_mult >= 1 && tail_mult >= 1 && reserved_mult >= 1,
            "a budget multiple of zero is a budget that refuses everything"
        );
        assert!(
            reserved_mult <= node_mult,
            "the reserve is carved out of what this node can afford, not \
             added on top of it"
        );
        assert!(!RESERVED_CLASS_DIMENSION_PREFIXES.is_empty());
        for p in RESERVED_CLASS_DIMENSION_PREFIXES {
            assert!(
                p.ends_with(':'),
                "`{p}` must be a namespace-family prefix, or it matches \
                 dimensions nobody meant to reserve"
            );
        }
    }

    /// **GATE 3, the load-bearing half — the tracked-table cap is DERIVED**
    /// from the node budget, and the tail-squeeze is unreachable because of
    /// it rather than by luck (#583).
    ///
    /// Every non-full bucket cost the adversary at least one write; every
    /// write is charged to the node budget; and one write keeps a bucket
    /// non-full only for as long as its own deficit takes to refill. So the
    /// number of buckets any schedule can hold simultaneously non-full is
    ///
    /// ```text
    /// N(c) = min over (dimension, horizon) of
    ///          (node_capacity + node_rate × w(c)) / c
    ///   where w(c) = max over (dimension, horizon) of c / peer_rate
    /// ```
    ///
    /// and the cap must exceed `max over c of N(c)`. This sweeps `c` over
    /// every write shape an adversary can choose — payload sizes from a
    /// typical row to the single-row cap, and 1..64 writes per bucket — and
    /// re-derives the bound from the LIVE constants. Raising
    /// [`NODE_INGEST_BUDGET_MULTIPLE`], lowering
    /// [`PER_PEER_QUOTA_TRACKED_PEERS_CAP`], or re-pricing the byte dimension
    /// downward all fail here, naming the inequality they broke.
    #[test]
    fn the_tracked_table_is_larger_than_any_flood_can_hold() {
        let peer = BudgetSpec::for_multiple(1);
        let node = BudgetSpec::for_multiple(NODE_INGEST_BUDGET_MULTIPLE);

        let bound_for = |cost: &WriteCost| -> f64 {
            // How long ONE write of this cost keeps a bucket non-full.
            let mut w: f64 = 0.0;
            for d in QuotaDimension::ALL {
                let c = cost.of(*d);
                if c <= 0.0 {
                    continue;
                }
                for h in QuotaHorizon::ALL {
                    w = w.max(c / peer.dim(*d).horizon(*h).per_second);
                }
            }
            // How many such writes the node budget can supply inside it.
            let mut n = f64::INFINITY;
            for d in QuotaDimension::ALL {
                let c = cost.of(*d);
                if c <= 0.0 {
                    continue;
                }
                for h in QuotaHorizon::ALL {
                    let hs = node.dim(*d).horizon(*h);
                    n = n.min((hs.capacity + hs.per_second * w) / c);
                }
            }
            n
        };

        let mut worst = 0.0f64;
        let mut worst_shape = (0u64, 0u64);
        let max_envelope = crate::federation::admission::MAX_ATTESTATION_ENVELOPE_BYTES as u64;
        for k in [1u64, 2, 4, 8, 16, 32, 64] {
            let mut bytes = TYPICAL_ATTESTATION_ENVELOPE_BYTES / 4;
            while bytes <= max_envelope * 2 {
                let per_write = WriteCost::for_envelope_bytes(bytes);
                #[allow(clippy::cast_precision_loss)]
                let cost = WriteCost {
                    per_dimension: [k as f64, per_write.of(QuotaDimension::Bytes) * k as f64],
                };
                let n = bound_for(&cost);
                if n > worst {
                    worst = n;
                    worst_shape = (k, bytes);
                }
                bytes = (bytes * 3) / 2 + 1;
            }
        }

        assert!(
            worst.is_finite() && worst >= f64::from(NODE_INGEST_BUDGET_MULTIPLE),
            "the bound came out vacuous ({worst}) — the sweep is not \
             exercising anything"
        );
        assert!(
            worst < PER_PEER_QUOTA_TRACKED_PEERS_CAP as f64,
            "#583 tail-squeeze: a flood can hold {worst:.0} buckets \
             simultaneously non-full (worst shape: {} writes of {} envelope \
             bytes each) and the tracked table holds only \
             {PER_PEER_QUOTA_TRACKED_PEERS_CAP}. At saturation the prune \
             frees nothing and an honest newcomer is demoted to the shared \
             tail the flood is saturating. The cap must exceed the bound: \
             raise PER_PEER_QUOTA_TRACKED_PEERS_CAP, or lower \
             NODE_INGEST_BUDGET_MULTIPLE — they are one number in two places.",
            worst_shape.0,
            worst_shape.1,
        );
    }
}
