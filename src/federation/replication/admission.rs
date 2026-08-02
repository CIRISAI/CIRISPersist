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
/// threshold + recursion_depth`. Each write site calls
/// [`Self::check`]; on `Ok(score)` the site proceeds, on
/// `Err(TrustGateRejection)` the site rejects with its typed
/// per-surface error.
#[derive(Clone)]
pub struct AdmissionGate {
    scoring: Arc<dyn TrustScoring>,
    threshold: f64,
    recursion_depth: u8,
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
    pub fn new(scoring: Arc<dyn TrustScoring>, threshold: f64, recursion_depth: u8) -> Self {
        Self {
            scoring,
            threshold: threshold.clamp(0.0, 1.0),
            recursion_depth,
        }
    }

    /// Threshold the gate evaluates against. Clamped to `[0.0, 1.0]`.
    pub fn threshold(&self) -> f64 {
        self.threshold
    }

    /// Recursion depth resolved at construction.
    pub fn recursion_depth(&self) -> u8 {
        self.recursion_depth
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
        let score = match self.scoring.trust_score(key_id, self.recursion_depth).await {
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
pub const PER_PEER_ATTESTATION_WRITES_PER_WINDOW: u32 = 600;

/// v22.0.0 (CIRISPersist#543 finding 4, AV-76) — the window
/// [`PER_PEER_ATTESTATION_WRITES_PER_WINDOW`] is measured over. Doubles as
/// the token bucket's refill period: tokens accrue continuously at
/// `WRITES_PER_WINDOW / WINDOW`, so a peer that has been idle for a full
/// window starts again with a full burst allowance.
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
/// At the ~1.5 KiB a typical federation-tier row occupies that is ≈21 MiB /
/// day / peer at steady state, which a volunteer node survives for years
/// instead of days; at the
/// [`MAX_ATTESTATION_ENVELOPE_BYTES`](crate::federation::admission::MAX_ATTESTATION_ENVELOPE_BYTES)
/// worst case it is still 14 GiB/day, which is why #575 ask (a) — a BYTE
/// dimension alongside the count — remains open and is the next thing this
/// control needs. A row count is a proxy for storage, and a poor one.
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
pub const PER_PEER_SUSTAINED_WRITES_PER_WINDOW: u32 = 14_400;

/// v24.3.0 (CIRISPersist#575) — the window
/// [`PER_PEER_SUSTAINED_WRITES_PER_WINDOW`] is measured over. One day: the
/// horizon #575 stated the gap in ("864 000 rows **per day** per peer"), and
/// the horizon on which a storage cost is felt.
pub const PER_PEER_SUSTAINED_WRITE_WINDOW: Duration = Duration::from_secs(86_400);

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
pub const PER_PEER_QUOTA_TRACKED_PEERS_CAP: usize = 4096;

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
pub const RESERVED_CLASS_DIMENSION_PREFIXES: &[&str] = &["accord:", "objection:"];

/// v24.3.0 (CIRISPersist#575) — **WHICH budget refused** a write.
///
/// A quota that answers `RateLimited` and nothing else sends its reader into
/// the same disjunction #565 spent a day inside on the Key plane: *your
/// burst? your day? the node? the shared tail?* — four different operator
/// actions behind one token. A refusal is a verdict, and a verdict without
/// its evidence sends the reader to the wrong layer.
///
/// **Closed**, and every variant corresponds to exactly ONE condition in
/// `PeerWriteQuota::check_at_class` — deliberately no `Other`, because a
/// catch-all reintroduces the disjunction one name deeper. Serde tokens are
/// snake_case and [`Self::as_str`] returns the SAME token, so a consumer
/// keys on a program constant and never on a message string. The token set
/// is the downstream contract and this mapping is **APPEND-ONLY**: add
/// variants, never re-spell one.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, serde::Serialize, serde::Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum PeerQuotaRefusal {
    /// This peer's own **burst** bucket is empty: more than
    /// [`PER_PEER_ATTESTATION_WRITES_PER_WINDOW`] writes inside
    /// [`PER_PEER_ATTESTATION_WRITE_WINDOW`]. Slow down; the budget returns
    /// within seconds.
    PeerBurst,
    /// This peer's own **sustained** bucket is empty: more than
    /// [`PER_PEER_SUSTAINED_WRITES_PER_WINDOW`] writes inside
    /// [`PER_PEER_SUSTAINED_WRITE_WINDOW`]. The burst was fine; the *day*
    /// is not. This is the refusal #575 exists to make possible.
    PeerSustained,
    /// The shared **untracked tail**'s burst bucket is empty. The write came
    /// from an `attesting_key_id` this quota holds no bucket for, and the
    /// one-peer-sized tail budget that all such identities share is spent.
    /// Rotating to another new identity does not help — that is the point.
    UntrackedTailBurst,
    /// The shared **untracked tail**'s sustained bucket is empty. As
    /// [`Self::UntrackedTailBurst`], on the day horizon.
    UntrackedTailSustained,
    /// The **node-wide** federation-ingest burst budget is empty
    /// ([`NODE_INGEST_BUDGET_MULTIPLE`] peers' worth). Not about this peer:
    /// the node is full. Distinguishable on purpose — a peer that cannot
    /// tell this from [`Self::PeerBurst`] cannot back off correctly.
    NodeBurst,
    /// The **node-wide** federation-ingest sustained budget is empty. As
    /// [`Self::NodeBurst`], on the day horizon.
    NodeSustained,
    /// The **reserved class**'s burst budget is empty. Only rows in the
    /// reserved class ([`RESERVED_CLASS_DIMENSION_PREFIXES`]) can spend it and
    /// only they can exhaust it — ordinary traffic never touches it, so this
    /// refusal means accord-class traffic itself is flooding.
    ReservedBurst,
    /// The **reserved class**'s sustained budget is empty. As
    /// [`Self::ReservedBurst`], on the day horizon.
    ReservedSustained,
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
}

/// v24.3.0 (CIRISPersist#575) — one budget's capacity and continuous refill
/// rate on both horizons. Derived from the substrate constants by
/// [`Self::for_multiple`]; there are no free-floating numbers below this
/// line.
#[derive(Debug, Clone, Copy)]
struct BudgetSpec {
    burst_capacity: f64,
    burst_per_second: f64,
    sustained_capacity: f64,
    sustained_per_second: f64,
}

impl BudgetSpec {
    /// `multiple` peers' worth of budget on both horizons.
    fn for_multiple(multiple: u32) -> Self {
        let m = f64::from(multiple);
        let burst_capacity = f64::from(PER_PEER_ATTESTATION_WRITES_PER_WINDOW) * m;
        let sustained_capacity = f64::from(PER_PEER_SUSTAINED_WRITES_PER_WINDOW) * m;
        Self {
            burst_capacity,
            burst_per_second: burst_capacity / PER_PEER_ATTESTATION_WRITE_WINDOW.as_secs_f64(),
            sustained_capacity,
            sustained_per_second: sustained_capacity
                / PER_PEER_SUSTAINED_WRITE_WINDOW.as_secs_f64(),
        }
    }
}

/// One budget's token pair. Both are fractional so the refill is continuous
/// rather than stepped at window boundaries, and one write spends one token
/// from EACH — the burst horizon bounds the second, the sustained horizon
/// bounds the day, and a write has to clear both.
#[derive(Debug, Clone, Copy)]
struct PeerBucket {
    burst: f64,
    sustained: f64,
    last_seen: Instant,
}

impl PeerBucket {
    /// A budget at full allowance as of `now`.
    fn full(spec: &BudgetSpec, now: Instant) -> Self {
        Self {
            burst: spec.burst_capacity,
            sustained: spec.sustained_capacity,
            last_seen: now,
        }
    }

    /// Accrue tokens for the elapsed time, capped at capacity.
    fn refill(&mut self, spec: &BudgetSpec, now: Instant) {
        let elapsed = now.saturating_duration_since(self.last_seen).as_secs_f64();
        self.burst = (self.burst + elapsed * spec.burst_per_second).min(spec.burst_capacity);
        self.sustained =
            (self.sustained + elapsed * spec.sustained_per_second).min(spec.sustained_capacity);
        self.last_seen = now;
    }

    /// `None` if one token is available on BOTH horizons; otherwise the
    /// refusal, burst horizon first (it is the one that clears soonest, so
    /// it is the more actionable retry hint when both are short).
    fn refusal(
        &self,
        spec: &BudgetSpec,
        burst_reason: PeerQuotaRefusal,
        sustained_reason: PeerQuotaRefusal,
    ) -> Option<PeerQuotaRefused> {
        if self.burst < 1.0 {
            return Some(PeerQuotaRefused {
                reason: burst_reason,
                retry_after_seconds: retry_after(1.0 - self.burst, spec.burst_per_second),
            });
        }
        if self.sustained < 1.0 {
            return Some(PeerQuotaRefused {
                reason: sustained_reason,
                retry_after_seconds: retry_after(1.0 - self.sustained, spec.sustained_per_second),
            });
        }
        None
    }

    /// Spend one write. Only ever called after every budget the write
    /// touches has already been proven admissible — see the no-partial-charge
    /// note on `PeerWriteQuota::check_at_class`.
    fn spend(&mut self) {
        self.burst -= 1.0;
        self.sustained -= 1.0;
    }

    /// A budget at full allowance on both horizons carries no information a
    /// fresh one wouldn't — the prune predicate.
    fn is_full(&self, spec: &BudgetSpec) -> bool {
        self.burst >= spec.burst_capacity && self.sustained >= spec.sustained_capacity
    }
}

/// Seconds until `deficit` tokens have accrued at `per_second`, never 0.
fn retry_after(deficit: f64, per_second: f64) -> u64 {
    (deficit / per_second).ceil().max(1.0) as u64
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
    /// `Ok(())` — admitted, one token spent in every budget it touches.
    /// `Err(`[`Error::RateLimited`](crate::federation::Error::RateLimited)`)`
    /// — over quota; see [`Self::check_write_typed`] for WHICH budget.
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
        self.check_at_class(&row.attesting_key_id, Self::classify(row), Instant::now())
    }

    /// Charge one ordinary-class write against `key_id`.
    ///
    /// Retained as the shape this method has had since v22.0.0 for callers
    /// that hold a key and no row.
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

    /// The clock-injected core. Every other entry point funnels here, so
    /// there is exactly one place where a write is charged.
    ///
    /// # No partial charge
    ///
    /// An ordinary write touches TWO budgets (node-wide, plus this peer's or
    /// the shared tail's). Both are proven admissible *before* either is
    /// spent — a check that debited the node and then refused on the peer
    /// would leak the node's budget to refused traffic, which is precisely
    /// the amplification this control exists to close.
    ///
    /// # Refusal precedence
    ///
    /// Node before peer/tail, and burst before sustained inside a budget.
    /// The node verdict leads because it is the one the caller cannot fix by
    /// slowing down, so it is the more useful thing to be told.
    fn check_at_class(
        &self,
        key_id: &str,
        class: WriteAdmissionClass,
        now: Instant,
    ) -> Result<(), PeerQuotaRefused> {
        let peer_spec = Self::peer_spec();
        let node_spec = BudgetSpec::for_multiple(NODE_INGEST_BUDGET_MULTIPLE);
        let tail_spec = BudgetSpec::for_multiple(UNTRACKED_TAIL_BUDGET_MULTIPLE);
        let reserved_spec = BudgetSpec::for_multiple(RESERVED_CLASS_BUDGET_MULTIPLE);

        let mut st = self.state.lock().unwrap_or_else(|p| p.into_inner());

        // The reserved class is charged against its own budget and NOTHING
        // else — not the node's, not the peer's, not the tail's. That is the
        // whole point: an ordinary flood, however large, cannot make an
        // accord objection unwritable (#575's must-ship caveat).
        if class == WriteAdmissionClass::Reserved {
            st.reserved.refill(&reserved_spec, now);
            if let Some(refused) = st.reserved.refusal(
                &reserved_spec,
                PeerQuotaRefusal::ReservedBurst,
                PeerQuotaRefusal::ReservedSustained,
            ) {
                return Err(refused);
            }
            st.reserved.spend();
            return Ok(());
        }

        st.node.refill(&node_spec, now);
        if let Some(refused) = st.node.refusal(
            &node_spec,
            PeerQuotaRefusal::NodeBurst,
            PeerQuotaRefusal::NodeSustained,
        ) {
            return Err(refused);
        }

        // Tracked peer: its own budget, and it does not touch the tail.
        if let Some(bucket) = st.buckets.get_mut(key_id) {
            bucket.refill(&peer_spec, now);
            if let Some(refused) = bucket.refusal(
                &peer_spec,
                PeerQuotaRefusal::PeerBurst,
                PeerQuotaRefusal::PeerSustained,
            ) {
                return Err(refused);
            }
            bucket.spend();
            st.node.spend();
            return Ok(());
        }

        // Untracked: the shared one-peer tail budget decides, and it decides
        // the same way for the millionth rotated identity as for the first.
        st.tail.refill(&tail_spec, now);
        if let Some(refused) = st.tail.refusal(
            &tail_spec,
            PeerQuotaRefusal::UntrackedTailBurst,
            PeerQuotaRefusal::UntrackedTailSustained,
        ) {
            return Err(refused);
        }
        st.tail.spend();
        st.node.spend();

        // Admitted. Now — and only now — try to give this identity a bucket
        // of its own, so its second write is metered individually instead of
        // against everyone else's tail. A slot is a *convenience*, never a
        // budget: failing to get one costs the peer nothing this write.
        if st.buckets.len() >= PER_PEER_QUOTA_TRACKED_PEERS_CAP {
            // Drop every bucket that has refilled to full on both horizons —
            // exactly the set whose state carries no information a fresh
            // bucket wouldn't.
            st.buckets.retain(|_, b| {
                let mut probe = *b;
                probe.refill(&peer_spec, now);
                !probe.is_full(&peer_spec)
            });
        }
        if st.buckets.len() < PER_PEER_QUOTA_TRACKED_PEERS_CAP {
            let mut fresh = PeerBucket::full(&peer_spec, now);
            fresh.spend(); // this write, accounted in the peer's own budget too
            st.buckets.insert(key_id.to_owned(), fresh);
        }
        // else: saturated with live-spending peers and nothing was prunable.
        // The write is admitted (the tail paid for it) and NO bucket is
        // created — the table is a HARD bound, which is what #575 found it
        // was not.
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

    /// Remaining burst tokens in `key_id`'s own bucket, if it has one.
    /// Test-only: the no-partial-charge invariant is not observable from
    /// outcomes alone, and an invariant that can only be argued is one that
    /// drifts.
    #[cfg(test)]
    fn peer_burst_tokens(&self, key_id: &str) -> Option<f64> {
        self.state
            .lock()
            .unwrap_or_else(|p| p.into_inner())
            .buckets
            .get(key_id)
            .map(|b| b.burst)
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
        Attestation {
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
        }
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
    /// quota is charged AHEAD of that, on the very first gate: the
    /// N+1th write from one peer inside one window comes back
    /// `federation_rate_limited`, the typed error that this cut gave its
    /// first construction site.
    pub async fn assert_per_peer_write_quota_is_wired<F>(dir: &F, tag: &str)
    where
        F: FederationDirectory + ?Sized,
    {
        let key_id = format!("av76q{tag}");
        let n = super::PER_PEER_ATTESTATION_WRITES_PER_WINDOW;
        for i in 0..n {
            let row = unverifiable_row(&key_id, attestation_tier::FEDERATION, "global");
            let err = dir
                .put_attestation(SignedAttestation { attestation: row })
                .await
                .expect_err("the `global` cohort_scope is never a wire value");
            assert_eq!(
                err.kind(),
                "federation_cohort_scope_rejected",
                "write {i} of {n} must be inside quota and fail on the \
                 closed-set value instead — got {err:?}"
            );
        }
        let row = unverifiable_row(&key_id, attestation_tier::FEDERATION, "global");
        let err = dir
            .put_attestation(SignedAttestation { attestation: row })
            .await
            .expect_err("the N+1th write in the window must be refused");
        assert_eq!(
            err.kind(),
            "federation_rate_limited",
            "AV-76: the per-peer quota must be charged on the first gate — \
             got {err:?}"
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
        async fn trust_score(
            &self,
            key_id: &str,
            _recursion_depth: u8,
        ) -> Result<f64, TrustScoringError> {
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
            async fn trust_score(
                &self,
                _key_id: &str,
                _depth: u8,
            ) -> Result<f64, TrustScoringError> {
                panic!("threshold 0.0 must short-circuit");
            }
        }
        let gate = AdmissionGate::new(Arc::new(PanicResolver), 0.0, 0);
        let outcome = gate.check("any").await.unwrap();
        assert!(outcome.is_ok());
    }

    #[tokio::test]
    async fn admit_when_score_meets_threshold() {
        let gate = AdmissionGate::new(fixed(&[("k1", 0.8)]), 0.5, 0);
        let outcome = gate.check("k1").await.unwrap();
        assert_eq!(outcome.expect("admitted"), 0.8);
    }

    #[tokio::test]
    async fn reject_when_score_below_threshold() {
        let gate = AdmissionGate::new(fixed(&[("k1", 0.3)]), 0.5, 0);
        let outcome = gate.check("k1").await.unwrap();
        let rej = outcome.expect_err("rejected");
        assert_eq!(rej.key_id, "k1");
        assert_eq!(rej.score, 0.3);
        assert_eq!(rej.threshold, 0.5);
    }

    #[tokio::test]
    async fn unknown_key_becomes_zero_score_rejection() {
        let gate = AdmissionGate::new(fixed(&[]), 0.5, 0);
        let outcome = gate.check("missing").await.unwrap();
        let rej = outcome.expect_err("rejected");
        assert_eq!(rej.score, 0.0);
    }

    #[tokio::test]
    async fn resolver_backend_error_surfaces() {
        struct Erroring;
        #[async_trait]
        impl TrustScoring for Erroring {
            async fn trust_score(
                &self,
                _key_id: &str,
                _depth: u8,
            ) -> Result<f64, TrustScoringError> {
                Err(TrustScoringError::Backend("boom".into()))
            }
        }
        let gate = AdmissionGate::new(Arc::new(Erroring), 0.5, 0);
        let err = gate.check("k1").await.expect_err("backend error");
        assert_eq!(err.kind(), "trust_scoring_backend");
    }

    #[tokio::test]
    async fn threshold_clamped_to_unit_range() {
        let gate = AdmissionGate::new(fixed(&[("k1", 1.0)]), 2.0, 0);
        assert_eq!(gate.threshold(), 1.0);
        // Threshold below 0 is clamped to 0 → admit.
        let gate_neg = AdmissionGate::new(fixed(&[("k1", 1.0)]), -1.0, 0);
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

    /// The exact token-bucket ceiling over an interval: a write spends from
    /// BOTH horizons, so the binding one is whichever admits fewer —
    /// `min(capacity + rate × elapsed)` across the two. Rounded up by one so
    /// the assertion cannot flake on the last fractional token.
    fn ceiling(spec: &BudgetSpec, elapsed: Duration) -> u64 {
        let e = elapsed.as_secs_f64();
        let burst = spec.burst_capacity + spec.burst_per_second * e;
        let sustained = spec.sustained_capacity + spec.sustained_per_second * e;
        burst.min(sustained).ceil() as u64
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
            spec.sustained_capacity,
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
    #[test]
    fn a_restart_is_worth_one_node_burst_not_a_sybil_multiple() {
        let quota = PeerWriteQuota::new(); // ← the restart
        let t0 = Instant::now();
        let bound = node_budget().burst_capacity as u64;

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
}
