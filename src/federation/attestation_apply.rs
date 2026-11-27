//! v36.0.0 (CIRISPersist#624) — the **typed, pre-write replicated
//! ATTESTATION-plane apply**: the Key plane's #565 twin.
//!
//! # The asymmetry this closes
//!
//! The Key plane returns a typed, semantic outcome:
//! [`apply_replicated_key_record`](super::FederationDirectory::apply_replicated_key_record)
//! → [`ReplicatedKeyOutcome`](super::register::ReplicatedKeyOutcome) /
//! [`KeyRefusalReason`](super::register::KeyRefusalReason), decided BEFORE the
//! write. The Attestation plane had none:
//! [`put_attestation`](super::FederationDirectory::put_attestation) is
//! `Result<(), Error>`, so a same-id / different-bytes convergence conflict
//! was only discovered when the backend's UNIQUE index rejected the insert —
//! surfacing as `Error::Backend("insert attestation: UNIQUE constraint
//! failed: …")`, a **storage** classification for a **semantic** outcome.
//! CIRISEdge#459 measured the bill: 94 refusals in ~6 minutes on a production
//! canonical, all in one `federation_backend` bucket, indistinguishable from a
//! disk error.
//!
//! Three problems, named by #624:
//!
//! 1. **Cannot be counted** — one bucket for every storage failure.
//! 2. **Reads as a fault when it is a decision** — two producers minting the
//!    same id is the mesh working, not a node bug.
//! 3. **Reaches the DB to find out** — the verdict depended on the UNIQUE
//!    index EXISTING; a backend without it would silently accept the
//!    conflicting row.
//!
//! # Shape
//!
//! [`plan_replicated_attestation_apply`] is the **pure classification core**:
//! a function of `(existing row, incoming row)` only — no directory handle, no
//! backend, testable without either. The trait-level entry point
//! [`apply_replicated_attestation`](super::FederationDirectory::apply_replicated_attestation)
//! fetches the existing row, runs the plan, and only an incoming row the plan
//! ADMITS ever reaches `put_attestation` (whose full admission-gate stack
//! still binds — nothing is bypassed; this module adds a decision layer, not a
//! side door).
//!
//! The refusal-cause inventory below comes from the code, not from #624's
//! guess — the same discipline as #565, which expected six variants and
//! shipped nine. #624 named two causes (`ConflictingAttestation`, an
//! `AlreadyPresentIdentical` duplicate); the code yields **three refusal
//! reasons and four outcome states**, because the same-id-same-bytes re-offer
//! (#624's genesis case) is [`ReplicatedAttestationOutcome::Unchanged`] — an
//! outcome, not a refusal, exactly like the Key plane's `Unchanged` — and two
//! more states exist that no issue guessed: the store-step race
//! ([`AttestationRefusalReason::StoreConflict`], the twin of the Key plane's)
//! and the CEG §6.1 structural-composer replay
//! ([`ReplicatedAttestationOutcome::Deduplicated`]), which `put_attestation`
//! resolves as a **silent no-op `Ok`** — indistinguishable from an insert to
//! every caller until now.

use super::types::Attestation;
use super::Error;

/// v36.0.0 (CIRISPersist#624) — **WHICH policy branch refused** a replicated
/// Attestation-plane apply.
///
/// **Closed**, and every variant corresponds to exactly ONE condition in the
/// code — deliberately no `Other`/`Unspecified` catch-all (a catch-all
/// reintroduces the disjunction one name deeper — the
/// [`KeyRefusalReason`](super::register::KeyRefusalReason) discipline). Serde
/// tokens are snake_case and [`Self::as_str`] returns the SAME token, so a
/// consumer keys on a program constant and never on a message string.
///
/// **The token set is the downstream contract, and this mapping is
/// APPEND-ONLY.** CIRISEdge keys its receive-plane apply ledger on these
/// constants (the #565 adoption pattern: `attestation_outcome_to_apply` + an
/// `attestation_apply_refusals_by_reason` ledger). Add variants; never
/// re-spell one.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, serde::Serialize, serde::Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum AttestationRefusalReason {
    /// The `attestation_id` is already held by a row asserting **different
    /// signed content** (a different `original_content_hash`) or the same
    /// content under a **different producer** (`attesting_key_id` /
    /// `scrub_key_id`). Two producers minted the same id — the CIRISEdge#459
    /// live case (88 distinct content hashes colliding on the fixed genesis
    /// ids). First-seen wins; a re-offer of this row can never succeed.
    ConflictingAttestation,
    /// The `attestation_id` is held by a row asserting **exactly what was
    /// offered** — same `original_content_hash` (the SHA-256 of the signed
    /// canonical envelope, which since #643 binds all seven typed columns via
    /// the row mirror) under the same producer pair — differing only in
    /// unsigned decoration (signature bytes from a re-sign — ML-DSA-65
    /// signing is randomized — `scrub_timestamp`, `tier` / `promoted_at`,
    /// `withdraws_admission_rule`, `additional_scrubs`).
    ///
    /// This is a *duplicate*, not a rejection: the receiver already holds
    /// exactly what was offered, and reporting it as a conflict sends the
    /// reader hunting for a convergence collision that is not there. A
    /// BYTE-identical re-offer never reaches here — it resolves
    /// [`ReplicatedAttestationOutcome::Unchanged`] at the `persist_row_hash`
    /// comparison. The exact twin of the Key plane's
    /// `AlreadyAnchoredIdentical` near-miss split.
    AlreadyPresentIdentical,
    /// The store step refused a duplicate `attestation_id` the plan did not
    /// see: a lost race between plan and act, or a directory that cannot
    /// answer [`get_attestation`](super::FederationDirectory::get_attestation)
    /// ([`Error::Unsupported`] — the plan-free fallback, mirroring the Key
    /// plane's plan-free default body). Fail-closed: the existing row is
    /// untouched, and the record is safe to re-offer — the next round's plan
    /// names the conflict precisely.
    StoreConflict,
    /// v58.0.0 (CIRISPersist#991) — a key-plane row (`key:record:v1`,
    /// `key:revocation:v1`, `identity:occurrence:v1`) whose family door did not
    /// apply its object; the door's own reason is logged with the row id.
    /// APPENDED.
    KeyPlaneRefused,
    /// v59.0.0 (CIRISPersist#1064, CIRISEdge) — a roster change the
    /// self-roster door holds as an OPEN proposal (`pending`): it may land
    /// when an answer arrives or the window closes, so a re-offer later can
    /// succeed. Split out of [`Self::KeyPlaneRefused`], which keeps the
    /// terminal reasons (a refused proposal, a family door's refusal).
    /// APPENDED.
    SelfRosterPending,
    /// v61 (CIRISPersist#991) — a group-plane row (`group:roster:v1`,
    /// `membership:{widening,removal,resignation}:v1`) whose typed door did
    /// not apply its object (a conflicting record, a weakening supersede, a
    /// held object that differs); the door's own reason is logged with the
    /// row id. APPENDED.
    GroupPlaneRefused,
    /// v61 (CIRISPersist#1148) — THIS node is not in the row's audience
    /// ([`super::replication_audience::may_receive`] for this node's own key,
    /// [`super::FederationDirectory::node_key_id`]): a replicated door stores
    /// only what this node may receive, so a canonical that joins no private
    /// community holds no trace of one, whichever peer pushes it. RETRYABLE:
    /// the audience can widen (the node's owner joins, the membership plane
    /// arrives), and a re-offer then lands. APPENDED.
    ///
    /// v62.0.0 (wave GC8; CC 2.7.5 rc21, ruling 11) — a **LOCAL decline**,
    /// never an admission verdict: "A node keeps a row only when it is in the
    /// row's audience as it reads it. A row it declines is not Invalid, and it
    /// may take the row once it is." Nothing is recorded against the row
    /// ([`Self::is_local_decline`]). Only the earlier form can reach it: an
    /// edition-2 row is applied as its statement and the fold decides it.
    NotInAudience,
    /// v62.0.0 (RL-fix1, lead ruling (B); CC 5.4: a node "carries none it
    /// cannot verify") — an accord row (a halt invocation, notify, drill or
    /// lifecycle row) offered to a node that holds NO genesis bundle, so no
    /// accord root to judge it under. Not kept, the store untouched, and the
    /// sender's cursor ADVANCES (a bundle never arrives down a feed, so a
    /// wait here would hold the feed forever). A LOCAL decline: the
    /// door called with the host's feed position records a watermark
    /// (`edition2::accord_rescan`), and the host re-pulls from it once a
    /// bundle is in force. APPENDED.
    AccordRootNotHeld,
    /// v62.0.0 (HOLD-1a; CC 2.7.3 as ruled 11-23: "A node may decline to keep
    /// or serve a row by its own configuration … never a verdict on the row,
    /// and the row is not Invalid") — a row held for its writer's standing
    /// (the write scope) that only ADDS, offered past this node's own bound
    /// on such rows (per room, per writer, per removed member:
    /// `edition2::hold_bound`). Not kept; the store untouched; the sender's
    /// cursor ADVANCES; a re-offer once the writer's seating record is held
    /// lands. A LOCAL decline, RETRYABLE. APPENDED.
    NotKept,
    /// v62.0.0 (HEAD-fix8; CC 2.4.1.1; Constitution's ruling (a)) — the row
    /// exercises a standing and names no `refs.head`: this node does not keep
    /// it (`Error::NotKept` with `NotKeptWhy::NamesNoHead`). A LOCAL decline,
    /// never Invalid and nothing recorded against the sender; the cursor
    /// ADVANCES. NOT retryable: the same bytes never gain a head, so a
    /// re-offer is never kept; only a NEW row naming the head concludes.
    /// APPENDED. Token `act_names_no_head`.
    #[serde(rename = "act_names_no_head")]
    NamesNoHead,
}

impl AttestationRefusalReason {
    /// The **stable program token** for this reason — identical to the serde
    /// token, so a consumer that reads the wire and a consumer that holds the
    /// typed value key on the same constant.
    /// [`tests::refusal_reason_tokens_match_serde`] binds the two spellings
    /// together so they cannot drift. APPEND-ONLY (see the type doc).
    #[must_use]
    pub const fn as_str(&self) -> &'static str {
        match self {
            Self::ConflictingAttestation => "conflicting_attestation",
            Self::AlreadyPresentIdentical => "already_present_identical",
            Self::StoreConflict => "store_conflict",
            Self::KeyPlaneRefused => "key_plane_refused",
            Self::SelfRosterPending => "self_roster_pending",
            Self::GroupPlaneRefused => "group_plane_refused",
            Self::NotInAudience => "not_in_audience",
            Self::AccordRootNotHeld => "accord_root_not_held",
            Self::NotKept => "not_kept",
            Self::NamesNoHead => "act_names_no_head",
        }
    }

    /// v59.0.0 (CIRISPersist#1064) — may a later re-offer of the row succeed?
    /// `true` for [`Self::SelfRosterPending`] (the proposal may land) and
    /// [`Self::StoreConflict`] (a lost race: "safe to re-offer"); `false` for
    /// the terminal reasons. Beside `steward_purge::is_retryable`.
    #[must_use]
    pub const fn is_retryable(&self) -> bool {
        matches!(
            self,
            Self::SelfRosterPending
                | Self::StoreConflict
                | Self::NotInAudience
                | Self::AccordRootNotHeld
                | Self::NotKept
        )
    }

    /// v62.0.0 (wave GC8; CC 2.7.5 rc21, ruling 11) — is this a LOCAL
    /// decline (this node's own reading, e.g. of its audience) rather than a
    /// verdict on the row? A declined row is not Invalid: nothing is recorded
    /// against it, and it is taken once the local answer changes.
    #[must_use]
    pub const fn is_local_decline(&self) -> bool {
        matches!(
            self,
            Self::NotInAudience | Self::AccordRootNotHeld | Self::NotKept | Self::NamesNoHead
        )
    }

    /// The reason a self-roster door's [`Error::SelfRosterNotLanded`] maps to:
    /// [`Self::SelfRosterPending`] while the proposal is open, else the
    /// terminal [`Self::KeyPlaneRefused`].
    #[must_use]
    pub fn of_self_roster_decision(decision: &str) -> Self {
        if decision == "pending" {
            Self::SelfRosterPending
        } else {
            Self::KeyPlaneRefused
        }
    }

    /// Every variant, in declaration order — the closed set, for exhaustive
    /// gates and for a consumer enumerating the taxonomy it must handle.
    pub const ALL: &'static [Self] = &[
        Self::ConflictingAttestation,
        Self::AlreadyPresentIdentical,
        Self::StoreConflict,
        Self::KeyPlaneRefused,
        Self::SelfRosterPending,
        Self::GroupPlaneRefused,
        Self::NotInAudience,
        Self::AccordRootNotHeld,
        Self::NotKept,
        Self::NamesNoHead,
    ];
}

impl std::fmt::Display for AttestationRefusalReason {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(self.as_str())
    }
}

/// v36.0.0 (CIRISPersist#624) — outcome of an
/// [`apply_replicated_attestation`](super::FederationDirectory::apply_replicated_attestation).
///
/// Serde tokens are snake_case strings (`"inserted"` / `"unchanged"` /
/// `"deduplicated"`); `Refused` carries its reason as
/// `{"refused":{"reason":"<token>"}}` — the same wire shape as
/// [`ReplicatedKeyOutcome`](super::register::ReplicatedKeyOutcome).
///
/// A `Refused` is a *policy* outcome, not an error: the anti-entropy
/// Attestation plane receives unsolicited rows, so a row that is not admitted
/// against the current corpus resolves to `Refused` (fail-closed,
/// deterministic) rather than aborting the apply loop. Admission-gate
/// failures on a FRESH insert (bad signature, quota, trust, dimension policy,
/// …) still surface as their typed [`Error`]s — each already carries its own
/// stable `kind()` token, and re-wrapping them here would be a second copy of
/// that taxonomy (the two-lists-that-disagree class).
#[derive(Debug, Clone, Copy, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ReplicatedAttestationOutcome {
    /// New `attestation_id` — stored via `put_attestation` (exactly the
    /// direct write path, including its whole admission-gate stack).
    Inserted,
    /// The corpus already carries this exact row (`persist_row_hash`-equal
    /// re-offer) — idempotent no-op. **The genesis re-offer case**: every
    /// node ships the baked bundle, so a canonical re-offering
    /// `genesis-charter` / `genesis-grant:*` / `genesis-lifecycle` to a node
    /// that already holds them lands HERE, not in a refusal bucket.
    Unchanged,
    /// The CEG §6.1 structural-composer dedup: an equivalent
    /// `withdraws`/`recants`/`supersedes` — same `(references_attestation_id,
    /// attestation_type, attesting_key_id)` triple under a DIFFERENT id —
    /// already exists, so `put_attestation` resolved the replay as an
    /// idempotent no-op. No row was written. Before #624 this was
    /// indistinguishable from [`Self::Inserted`] (the backend returns a
    /// silent `Ok`), so an apply loop reported an insert that never
    /// happened.
    Deduplicated,
    /// v61.3.0 (CIRISPersist#1252) — this node holds the SAME ACT under
    /// another row: an assembled widening or removal carrying a different
    /// sufficient subset of its cosignatures (or other randomised ML-DSA
    /// bytes), or the same signer's other signature on a `cosign:*` row. The
    /// act is held, so nothing was written (for an assembled row, its id is
    /// recorded as an alias of the act) and no refusal is booked: a sender
    /// stops re-offering it. APPENDED (`DIRECTORY_ABI_VERSION` 13).
    HeldEquivalent,
    /// The row was NOT applied and the existing corpus is untouched.
    /// `reason` names the branch that fired — a closed enum, not a message
    /// string.
    Refused {
        /// WHICH policy branch refused.
        reason: AttestationRefusalReason,
    },
}

/// The classification half of the #624 apply — which action
/// [`apply_replicated_attestation`](super::FederationDirectory::apply_replicated_attestation)
/// takes for an incoming row given the currently-stored row.
///
/// `pub(crate)` like
/// [`ReplicatedKeyPlan`](super::register::ReplicatedKeyPlan): the plan is
/// where the policy branches actually are, so this is where each
/// [`AttestationRefusalReason`] is *produced*; the entry point carries it
/// through rather than re-deriving it (one predicate, one implementation).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum ReplicatedAttestationPlan {
    /// No row for `attestation_id` — insert via `put_attestation` (every
    /// admission gate still binds; nothing is bypassed for fresh rows).
    Insert,
    /// Byte-identical re-offer — no-op.
    Unchanged,
    /// Not admitted; leave the corpus untouched (fail-closed).
    Refused {
        /// WHICH policy branch refused.
        reason: AttestationRefusalReason,
    },
}

/// v36.0.0 (CIRISPersist#624) — the one constructor for a refused plan, so a
/// site cannot forget the reason (there is no reason-less way to build one).
const fn refused(reason: AttestationRefusalReason) -> ReplicatedAttestationPlan {
    ReplicatedAttestationPlan::Refused { reason }
}

/// v36.0.0 (CIRISPersist#624) — decide what a replicated Attestation-plane
/// apply does with `incoming`, **WITHOUT mutating anything and WITHOUT a
/// directory** — a pure function of `(existing, incoming)`, so the verdict
/// cannot depend on a storage constraint existing (problem 3 of #624) and the
/// three backends cannot hold three opinions of it.
///
/// Decision table:
///
/// - **no existing row** ⇒ [`ReplicatedAttestationPlan::Insert`] — the store
///   step is `put_attestation` itself, so every admission gate (genesis
///   reservation, quota, trust, envelope bindings, hybrid verify, the
///   directory-walk authority gates) still binds.
/// - **byte-identical re-offer** ⇒ [`ReplicatedAttestationPlan::Unchanged`].
///   Compared over [`compute_persist_row_hash`](super::types::compute_persist_row_hash)
///   of the incoming row with its envelope first canonicalized exactly as the
///   put door canonicalizes it (#647 canonical-at-rest; idempotent), so a
///   locally re-minted row and a wire re-offer of the stored row both compare
///   stably against the stored hash.
/// - **same signed assertion, same producer** (equal `original_content_hash`
///   — which covers the envelope and, via the #643 row mirror, all seven
///   typed columns — under equal `attesting_key_id` AND `scrub_key_id`),
///   differing only in unsigned decoration ⇒
///   [`AttestationRefusalReason::AlreadyPresentIdentical`].
/// - **anything else holding the id** ⇒
///   [`AttestationRefusalReason::ConflictingAttestation`] — different signed
///   content, or the same content under a different producer. First-seen
///   wins.
///
/// Malformed input that no policy can classify (an un-canonicalizable
/// envelope, a row that cannot serialize for hashing) surfaces as `Err` —
/// `Refused` is reserved for "well-formed but not admitted", exactly like the
/// Key plane's plan.
pub(crate) fn plan_replicated_attestation_apply(
    existing: Option<&Attestation>,
    incoming: &Attestation,
) -> Result<ReplicatedAttestationPlan, Error> {
    let Some(existing) = existing else {
        return Ok(ReplicatedAttestationPlan::Insert);
    };

    // Idempotent re-offer: byte-identical row. The envelope is canonicalized
    // first — the SAME normalization the put door applies before it computes
    // the stored hash (#647), and idempotent — so the comparison is between
    // like and like. `compute_persist_row_hash` drops the `persist_row_hash`
    // field itself, so a record arriving with the origin row's hash (or with
    // none) still compares stably.
    let incoming_hash = {
        let mut normalized = incoming.clone();
        super::canonical_at_rest::canonicalize_in_place(&mut normalized.attestation_envelope)?;
        super::types::compute_persist_row_hash(&normalized)?
    };
    if existing.persist_row_hash == incoming_hash {
        return Ok(ReplicatedAttestationPlan::Unchanged);
    }

    // The near-miss: the SAME signed assertion by the SAME producer, differing
    // only in unsigned decoration. `original_content_hash` is the SHA-256 of
    // the signed canonical envelope — the bytes both scrub signatures cover —
    // so equal hashes mean the CLAIM is identical; the producer pair pins WHO
    // made it. Split from the conflict because the remedies differ: a
    // duplicate needs nothing, a conflict needs a duplicity/convergence look.
    //
    // v50.0.0 (CIRISPersist#917 review) — the incoming hash is a CLAIM until
    // its envelope is hashed. Nothing upstream of the plan has verified it (a
    // settled row never reaches the write door's hybrid verify), so a peer
    // could copy the stored row's hash and producer pair onto a different
    // envelope and be booked a quiet duplicate. The stored row's hash was
    // verified against its envelope at admission; requiring the incoming
    // envelope to hash to the same value makes "same claim" a fact.
    if existing.original_content_hash == incoming.original_content_hash
        && existing.attesting_key_id == incoming.attesting_key_id
        && existing.scrub_key_id == incoming.scrub_key_id
        && envelope_content_hash(&incoming.attestation_envelope)? == incoming.original_content_hash
    {
        return Ok(refused(AttestationRefusalReason::AlreadyPresentIdentical));
    }

    Ok(refused(AttestationRefusalReason::ConflictingAttestation))
}

/// The SHA-256 (hex) of `envelope`'s CEG canonical bytes — what a row's
/// `original_content_hash` must equal, computed exactly as the federation-tier
/// verify computes it.
fn envelope_content_hash(envelope: &serde_json::Value) -> Result<String, Error> {
    use sha2::Digest as _;
    let canonical = crate::verify::canonical::ceg_produce_canonicalize(envelope)
        .map_err(|e| Error::InvalidArgument(format!("envelope canonicalize: {e}")))?;
    Ok(hex::encode(sha2::Sha256::digest(&canonical)))
}

/// v50.0.0 (CIRISPersist#917) — **the one body both typed Attestation-plane
/// doors run**: fetch the stored row, run
/// [`plan_replicated_attestation_apply`], act on the plan, and write an
/// admitted row through the stored-write door under `origin`.
///
/// [`apply_replicated_attestation`](super::FederationDirectory::apply_replicated_attestation)
/// passes [`WriteOrigin::Wire`](super::replication::admission::WriteOrigin::Wire);
/// [`put_attestation_synced`](super::FederationDirectory::put_attestation_synced)
/// passes [`WriteOrigin::Sync`](super::replication::admission::WriteOrigin::Sync)
/// naming the authenticated peer. Origin changes WHICH budget a fresh row is
/// metered against (the cohort question stays inside the write door) and
/// nothing else, so the same bytes classify to the same outcome on both
/// doors by construction — before #917 the synced door ran a binary
/// `persist_row_hash` verdict instead and booked a decoration-only
/// re-delivery as `Error::Conflict` while this body booked it as a duplicate.
/// v61 (CIRISPersist#1148) — may THIS node store a replicated `row`? `true`
/// for a key-plane row (every node verifies against the key plane), and on a
/// directory that has not declared its node key (it cannot ask); else
/// [`super::replication_audience::may_receive`] for the node's own key.
///
/// # Errors
///
/// Directory reads.
pub(crate) async fn replicated_row_in_audience<D>(dir: &D, row: &Attestation) -> Result<bool, Error>
where
    D: super::FederationDirectory + ?Sized,
{
    if super::key_plane::is_key_plane_row(row) {
        return Ok(true);
    }
    // v61 S2 (the release lead's ruling on #1148) — a `key_grant:{axis}:v1`
    // row is exempt as the key plane is. Its audience gate is the key-grant
    // door's own rule (`check_key_grant_row_admission`,
    // `recipient_not_in_audience`), which knows the occurrences a node hosts.
    // The key follows the bytes to the owner's occurrences (#848/#963). The
    // serve-side node-key comparison below would refuse every self-axis grant
    // to a person's other devices (I1519).
    if super::key_grant::is_key_grant_row(row) {
        return Ok(true);
    }
    let Some(me) = dir.node_key_id() else {
        return Ok(true);
    };
    Ok(super::replication_audience::may_receive(dir, &me, row)
        .await?
        .allowed())
}

/// v62.0.0 (wave GC8) — [`apply_planned`]'s edition-2 route: `None` for a
/// row that carries no statement (or no edition-2 row id); else the
/// replicated statement door's answer, in this plane's outcome. A statement
/// kept and HELD (concluding nothing yet) is [`ReplicatedAttestationOutcome::HeldEquivalent`]:
/// the act is held here, nothing is refused, and the sender stops re-offering.
///
/// # Errors
/// A statement whose `ceg_statement` member is not hex; the statement door's
/// errors (its door refusals: the statement's bytes, its signer's key plane).
///
/// v62.0.0 (E6-fix9; CIRISPersist#804) — `origin` is the caller's write
/// origin, carried to the statement door
/// ([`apply_replicated_statement_with_origin`](super::edition2::ingest::apply_replicated_statement_with_origin)),
/// so a cohort mate's sync keeps `WriteOrigin::Sync` and its budget.
async fn apply_as_statement<D>(
    dir: &D,
    row: &Attestation,
    origin: super::replication::admission::WriteOrigin,
) -> Result<Option<ReplicatedAttestationOutcome>, Error>
where
    D: super::FederationDirectory + ?Sized,
{
    use super::edition2::ingest::{
        apply_replicated_statement_with_origin, ReplicatedStatementOutcome, StatementOutcome,
        STATEMENT_MEMBER,
    };
    let Some(member) = row.attestation_envelope.get(STATEMENT_MEMBER) else {
        return Ok(None);
    };
    let Some(row_id) = super::edition2::voices::carried_row_id(row) else {
        return Ok(None);
    };
    let bytes = member
        .as_str()
        .and_then(|h| hex::decode(h).ok())
        .ok_or_else(|| {
            Error::malformed_row(
                super::edition2::door::PLANE,
                super::malformed_row::ENVELOPE_MEMBER_INVALID,
                format!("`{STATEMENT_MEMBER}` is not lowercase hex"),
            )
        })?;
    let kept = |o: &StatementOutcome, new: bool| match o {
        StatementOutcome::Pending { .. } => ReplicatedAttestationOutcome::HeldEquivalent,
        _ if new => ReplicatedAttestationOutcome::Inserted,
        _ => ReplicatedAttestationOutcome::Unchanged,
    };
    Ok(Some(
        match Box::pin(apply_replicated_statement_with_origin(
            dir, &bytes, &row_id.0, origin,
        ))
        .await?
        {
            ReplicatedStatementOutcome::Admitted(o) => kept(&o, true),
            ReplicatedStatementOutcome::Unchanged(o) => kept(&o, false),
            ReplicatedStatementOutcome::Refused { reason } => {
                ReplicatedAttestationOutcome::Refused { reason }
            }
        },
    ))
}

pub(crate) async fn apply_planned<D>(
    dir: &D,
    attestation: super::SignedAttestation,
    origin: super::replication::admission::WriteOrigin,
) -> Result<ReplicatedAttestationOutcome, Error>
where
    D: super::FederationDirectory + ?Sized,
{
    super::edition2::door::refuse_earlier_form_row("attestation", &attestation.attestation)?;
    // v62.0.0 (wave GC8; CC 2.7.3) — **a row that carries its edition-2
    // statement is applied as that statement**, through the replicated
    // statement door (`edition2::ingest::apply_replicated_statement`), never
    // through the plan below. The plan's verdicts read other rows (the row
    // held under the same id: first-seen wins; this node's audience; the
    // key-plane and group-plane doors' held state), so for an edition-2 row
    // each is a fold condition: the statement door keeps the statement, runs
    // the row's gates as a fold attempt, and holds what does not conclude
    // (reason `why_held`), re-folding it when its inputs change. A row id is
    // computed from the statement's bytes, so two different rows under one id
    // cannot arise here. What is left below is the earlier form, which the
    // shut doors refuse above.
    if let Some(outcome) = Box::pin(apply_as_statement(
        dir,
        &attestation.attestation,
        origin.clone(),
    ))
    .await?
    {
        return Ok(outcome);
    }
    use super::precedence;
    use ReplicatedAttestationOutcome as Outcome;
    use ReplicatedAttestationPlan as Plan;
    let incoming = &attestation.attestation;
    let attestation_id = incoming.attestation_id.clone();
    // v61 (CIRISPersist#1148) — **the put-time audience precondition.** A
    // replicated row this node may not receive is refused before any door
    // runs, by name: the same `may_receive` the serve side asks, for this
    // node's own key (a group-plane row through its membership-plane
    // audience). The key plane is exempt: a key's record, revocation and
    // occurrence are what every node verifies signatures against. A directory
    // that has not been told who it is cannot ask the question, and keeps the
    // pre-v61 behaviour (the host gates); an Engine always declares its key.
    if !Box::pin(replicated_row_in_audience(dir, incoming)).await? {
        // v61 S2 (the release blocker on 2c4cee2e) — **verification comes
        // before the audience verdict.** An audience answer over unverified
        // bytes is a verdict about attacker-chosen data, so a forged row is
        // reported as unverified, never as an audience miss. The verify is
        // asked only on this refusing branch. An in-audience row is verified
        // by the admission's own crypto tier below, exactly once, and the
        // reported outcome is the same as verifying first: a row that does
        // not verify is `federation_federation_tier_unverified` either way.
        // A group-plane row carries its object's signatures and is verified
        // by its typed door, so it is not re-verified here.
        if !super::group_plane::is_group_plane_row(incoming) {
            super::verify_federation_tier_ingest(dir, incoming).await?;
        }
        tracing::info!(
            attestation_id = %attestation_id,
            "replicated row refused: this node is not in its audience"
        );
        return Ok(Outcome::Refused {
            reason: AttestationRefusalReason::NotInAudience,
        });
    }
    // v58.0.0 (CIRISPersist#991, CC 3.1.3) — a key-plane row is applied by its
    // family's door, ahead of the generic plan: a key's newer claim is a new
    // row that replaces its older one, which the generic same-id plan would
    // read as a conflict.
    if super::key_plane::is_key_plane_row(incoming) {
        use super::key_plane::KeyPlaneApplied;
        let applied = match super::key_plane::apply_key_plane_row(dir, incoming).await {
            // v59.0.0 (CIRISPersist#1099) — a roster change held as a proposal
            // (or refused) by the self-roster door: the occurrence did not
            // land here, typed as the key-plane door's refusal.
            Err(e @ Error::SelfRosterNotLanded { decision, .. }) => {
                tracing::info!(attestation_id = %attestation_id, error = %e, "key-plane row held by the self-roster door");
                // v59.0.0 (CIRISPersist#1064) — pending (retry) apart from
                // refused (stop).
                return Ok(Outcome::Refused {
                    reason: AttestationRefusalReason::of_self_roster_decision(decision),
                });
            }
            other => other?,
        };
        return Ok(match applied {
            KeyPlaneApplied::Changed => Outcome::Inserted,
            KeyPlaneApplied::Unchanged => Outcome::Unchanged,
            KeyPlaneApplied::Refused(reason) => {
                tracing::info!(attestation_id = %attestation_id, reason, "key-plane row refused");
                Outcome::Refused {
                    reason: AttestationRefusalReason::KeyPlaneRefused,
                }
            }
        });
    }
    // v61 (CIRISPersist#991, CC 3.1.3) — a group-plane row is applied by the
    // typed door of the object it carries, ahead of the generic plan: a
    // record's newer version is a new row that replaces its older one.
    if super::group_plane::is_group_plane_row(incoming) {
        use super::group_plane::GroupPlaneApplied;
        return Ok(
            match super::group_plane::apply_group_plane_row(
                dir,
                incoming,
                super::group_plane::GroupRowDoor::Replicated,
            )
            .await?
            {
                GroupPlaneApplied::Changed => Outcome::Inserted,
                GroupPlaneApplied::Unchanged => Outcome::Unchanged,
                GroupPlaneApplied::HeldEquivalent => Outcome::HeldEquivalent,
                GroupPlaneApplied::Refused(reason) => {
                    tracing::info!(attestation_id = %attestation_id, reason, "group-plane row refused");
                    Outcome::Refused {
                        reason: AttestationRefusalReason::GroupPlaneRefused,
                    }
                }
            },
        );
    }
    // v61.3.0 (CIRISPersist#1252) — a cosign row whose id this node holds:
    // the same pending act, or the same signer's cosignature (its ML-DSA half
    // randomised). Held, never a conflict.
    if super::cosign::is_cosign_row(incoming) {
        if let Some(held) = dir.get_attestation(&attestation_id).await? {
            return Ok(
                if held.persist_row_hash == super::types::compute_persist_row_hash(incoming)? {
                    Outcome::Unchanged
                } else {
                    Outcome::HeldEquivalent
                },
            );
        }
    }
    // v50.0.0 (CIRISPersist#916) — an owner-binding is the moment a minter
    // learns a member has a device; read before the row is moved.
    let binding = super::owner_binding_of(incoming);
    // v55.0.0 (CIRISPersist#989) — a key-grant row carries its wrap: kept to
    // project once the store holds the row (inserted now, or held already —
    // a re-offer repairs a projection a crash cut off).
    let key_grant = super::key_grant::is_key_grant_row(incoming).then(|| incoming.clone());
    // The §6.1 silent-no-op door only exists for structural composers
    // that actually carry a references target — precompute the predicate
    // while `incoming` is still borrowed.
    let dedup_possible = precedence::is_structural_composer(&incoming.attestation_type)
        && precedence::references_attestation_id_from_envelope(&incoming.attestation_envelope)
            .is_some();
    let planned = match dir.get_attestation(&attestation_id).await {
        Ok(existing) => {
            // v50.0.0 (CIRISPersist#917 review) — bound the plan's own work. A
            // row the plan SETTLES (the id is held) never reaches the write
            // door, whose quota and size gate bound every other
            // canonicalization; without this a replay of a held id with a huge
            // envelope would be canonicalized for free. Only then: a fresh id
            // goes to the write door, which meters it BEFORE its own size gate,
            // and that order is the quota's to keep.
            if existing.is_some() {
                super::admission::check_envelope_size_admission(&incoming.attestation_envelope)?;
            }
            Some(plan_replicated_attestation_apply(
                existing.as_ref(),
                incoming,
            )?)
        }
        // v62.0.0 (PX-fix3) — the #603 plan-free arm is gone: a directory that
        // cannot answer (`Unsupported`) fails like every other could-not-ask,
        // which is never *absent* (I2190).
        Err(e) => return Err(e),
    };
    match planned {
        Some(Plan::Unchanged) => {
            if let Some(row) = &key_grant {
                dir.project_key_grant_row(row).await?;
            }
            return Ok(Outcome::Unchanged);
        }
        Some(Plan::Refused { reason }) => return Ok(Outcome::Refused { reason }),
        Some(Plan::Insert) | None => {}
    }
    match crate::observe::fold(
        crate::observe::Fold::AttestationAdmission,
        dir.put_attestation_with_origin(attestation, origin),
    )
    .await
    {
        Ok(stored) => {
            // §6.1: a structural-composer replay is a silent `Ok` with NO
            // row written. Ask the store what it actually did, so
            // `Inserted` keeps meaning inserted. Skipped on the plan-free
            // fallback (this directory cannot be asked).
            if dedup_possible
                && planned.is_some()
                && dir.get_attestation(&attestation_id).await?.is_none()
            {
                return Ok(Outcome::Deduplicated);
            }
            // v50.0.0 (CIRISPersist#917 review) — the store's own verdict,
            // not `Ok(_)`: `AlreadyHeld` means a byte-identical row landed
            // between the plan and the write (a lost race), or the plan-free
            // fallback re-offered one — nothing changed, so not `Inserted`.
            if let Some(row) = &key_grant {
                dir.project_key_grant_row(row).await?;
            }
            match stored {
                super::AttestationOutcome::Inserted => {
                    // v50.0.0 (CIRISPersist#916, #917) — the ONE re-wrap site
                    // for both typed doors: a row the store actually
                    // inserted, never a settled or already-held one.
                    if let Some((owner, device)) = binding {
                        super::rewrap_after_admission(dir, &owner, &device).await;
                    }
                    Ok(Outcome::Inserted)
                }
                super::AttestationOutcome::AlreadyHeld => Ok(Outcome::Unchanged),
            }
        }
        Err(e) if e.is_duplicate_key() => Ok(Outcome::Refused {
            reason: AttestationRefusalReason::StoreConflict,
        }),
        // v59.0.0 (CIRISPersist#1099) — a `withdraws` evicting a live roster
        // key, held as a proposal (or refused) by the self-roster door: the
        // key-plane door's refusal, as for an occurrence row.
        Err(e @ Error::SelfRosterNotLanded { decision, .. }) => {
            tracing::info!(attestation_id = %attestation_id, error = %e, "occurrence withdraws held by the self-roster door");
            Ok(Outcome::Refused {
                reason: AttestationRefusalReason::of_self_roster_decision(decision),
            })
        }
        Err(e) => Err(e),
    }
}

#[cfg(all(test, feature = "sqlite"))]
mod tests {
    use super::*;
    use crate::federation::edition2::fixture_switch as e2;
    use crate::federation::types::{attestation_tier, attestation_type, identity_type};
    use crate::federation::{FederationDirectory, SignedAttestation};

    /// v62.0.0 (JSON cut, E7) — a dimension Verify's family matcher registers
    /// (`coherence_standing:{cohort}`; v62.0.0 FS-sig-b: an ungated claim
    /// family, since `evidence:*` now needs `infra:attest`): an edition-2 row of an
    /// unregistered dimension (`identity_binding:v1`) is refused at the door.
    const DIMENSION: &str = "coherence_standing:cab:v1";

    // ── Pure plan + token tests (no backend, no directory) ────────────

    /// The serde token and [`AttestationRefusalReason::as_str`] must be the
    /// SAME spelling — a consumer that reads the wire and a consumer that
    /// holds the typed value key on one constant. Asserted over `ALL`, so a
    /// NEW variant is covered the moment it is added.
    #[test]
    fn refusal_reason_tokens_match_serde() {
        for reason in AttestationRefusalReason::ALL {
            let json = serde_json::to_string(reason).expect("serialize");
            assert_eq!(
                json,
                format!("\"{}\"", reason.as_str()),
                "serde token and as_str() diverged for {reason:?}"
            );
            let back: AttestationRefusalReason = serde_json::from_str(&json).expect("round-trip");
            assert_eq!(back, *reason);
            assert_eq!(reason.to_string(), reason.as_str(), "Display = token");
        }
        // The tokens are pairwise distinct (a duplicate token would make two
        // verdicts indistinguishable on the wire).
        let tokens: std::collections::BTreeSet<&str> = AttestationRefusalReason::ALL
            .iter()
            .map(|r| r.as_str())
            .collect();
        assert_eq!(tokens.len(), AttestationRefusalReason::ALL.len());
    }

    /// The outcome wire shapes CIRISEdge keys on: bare snake_case strings for
    /// the applied states, `{"refused":{"reason":"<token>"}}` for refusals —
    /// the [`ReplicatedKeyOutcome`](crate::federation::register::ReplicatedKeyOutcome)
    /// shape. Round-trips, so a consumer can also parse them back.
    #[test]
    fn outcome_wire_shape_is_stable() {
        assert_eq!(
            serde_json::to_string(&ReplicatedAttestationOutcome::Inserted).expect("inserted"),
            "\"inserted\""
        );
        assert_eq!(
            serde_json::to_string(&ReplicatedAttestationOutcome::Unchanged).expect("unchanged"),
            "\"unchanged\""
        );
        assert_eq!(
            serde_json::to_string(&ReplicatedAttestationOutcome::Deduplicated)
                .expect("deduplicated"),
            "\"deduplicated\""
        );
        for reason in AttestationRefusalReason::ALL {
            let outcome = ReplicatedAttestationOutcome::Refused { reason: *reason };
            let json = serde_json::to_string(&outcome).expect("refused");
            assert_eq!(
                json,
                format!("{{\"refused\":{{\"reason\":\"{}\"}}}}", reason.as_str())
            );
            assert_eq!(
                serde_json::from_str::<ReplicatedAttestationOutcome>(&json).expect("round-trip"),
                outcome
            );
        }
    }

    /// A minimal well-formed row for the PURE plan tests. These rows never
    /// touch a directory, so they carry no signatures — the plan classifies
    /// identity, not admissibility (admissibility stays `put_attestation`'s).
    fn bare_row(id: &str, author: &str, dimension: &str) -> Attestation {
        let now = chrono::DateTime::parse_from_rfc3339("2026-01-01T00:00:00Z")
            .expect("fixture instant")
            .with_timezone(&chrono::Utc);
        Attestation {
            attestation_id: id.to_owned(),
            attesting_key_id: author.to_owned(),
            attested_key_id: author.to_owned(),
            attestation_type: attestation_type::SCORES.to_owned(),
            weight: None,
            asserted_at: now,
            expires_at: None,
            attestation_envelope: serde_json::json!({
                "dimension": dimension,
                "score": 1.0,
                "confidence": 0.9,
            }),
            original_content_hash: {
                use sha2::Digest as _;
                let canonical =
                    crate::verify::canonical::ceg_produce_canonicalize(&serde_json::json!({
                        "dimension": dimension,
                        "score": 1.0,
                        "confidence": 0.9,
                    }))
                    .expect("canonicalize");
                hex::encode(sha2::Sha256::digest(&canonical))
            },
            scrub_signature_classical: "sig-classical".to_owned(),
            scrub_signature_pqc: None,
            scrub_key_id: author.to_owned(),
            scrub_timestamp: now,
            pqc_completed_at: None,
            persist_row_hash: String::new(),
            subject_key_ids: Vec::new(),
            withdraws_admission_rule: None,
            cohort_scope: "federation".to_owned(),
            tier: attestation_tier::FEDERATION.to_owned(),
            promoted_at: None,
            additional_scrubs: Vec::new(),
        }
    }

    /// The stored form of `row`: envelope canonicalized and
    /// `persist_row_hash` computed, exactly as the put door stores it.
    fn stored(mut row: Attestation) -> Attestation {
        crate::federation::canonical_at_rest::canonicalize_in_place(&mut row.attestation_envelope)
            .expect("canonicalize");
        row.persist_row_hash =
            crate::federation::types::compute_persist_row_hash(&row).expect("hash");
        row
    }

    #[test]
    fn plan_absent_row_is_insert() {
        let incoming = bare_row("att-1", "author-a", "identity_binding:v1");
        assert_eq!(
            plan_replicated_attestation_apply(None, &incoming).expect("plan"),
            ReplicatedAttestationPlan::Insert
        );
    }

    /// The genesis re-offer case, decided WITHOUT any storage constraint: the
    /// same row re-offered — including a NON-canonical envelope re-offer of a
    /// canonically-stored row, and a re-offer carrying the origin's
    /// `persist_row_hash` — is `Unchanged`.
    #[test]
    fn plan_identical_reoffer_is_unchanged() {
        let minted = bare_row("att-1", "author-a", "identity_binding:v1");
        let held = stored(minted.clone());
        // The wire re-offer of the stored row (carries the origin hash).
        assert_eq!(
            plan_replicated_attestation_apply(Some(&held), &held.clone()).expect("plan"),
            ReplicatedAttestationPlan::Unchanged
        );
        // The re-mint (pre-canonical envelope, empty hash) of the same row.
        assert_eq!(
            plan_replicated_attestation_apply(Some(&held), &minted).expect("plan"),
            ReplicatedAttestationPlan::Unchanged
        );
    }

    /// Same id, different signed content ⇒ `ConflictingAttestation` — the
    /// CIRISEdge#459 live case, decided pre-write.
    #[test]
    fn plan_different_content_is_conflicting() {
        let held = stored(bare_row("att-1", "author-a", "identity_binding:v1"));
        let rival = bare_row("att-1", "author-a", "capability_binding:v1");
        assert_eq!(
            plan_replicated_attestation_apply(Some(&held), &rival).expect("plan"),
            ReplicatedAttestationPlan::Refused {
                reason: AttestationRefusalReason::ConflictingAttestation
            }
        );
    }

    /// Same id, same signed content, DIFFERENT producer ⇒ still
    /// `ConflictingAttestation` — an identical claim under another identity
    /// is a duplicity question, never a duplicate.
    #[test]
    fn plan_same_content_different_producer_is_conflicting() {
        let held = stored(bare_row("att-1", "author-a", "identity_binding:v1"));
        let mut rival = bare_row("att-1", "author-a", "identity_binding:v1");
        rival.attesting_key_id = "author-b".to_owned();
        rival.scrub_key_id = "author-b".to_owned();
        assert_eq!(
            plan_replicated_attestation_apply(Some(&held), &rival).expect("plan"),
            ReplicatedAttestationPlan::Refused {
                reason: AttestationRefusalReason::ConflictingAttestation
            }
        );
    }

    /// Same id, same assertion, same producer, differing only in unsigned
    /// decoration (a re-sign's randomized ML-DSA bytes / a fresh
    /// `scrub_timestamp`) ⇒ `AlreadyPresentIdentical` — the near-miss that
    /// reads as a conflict until it is named.
    #[test]
    fn plan_decoration_only_difference_is_already_present() {
        let held = stored(bare_row("att-1", "author-a", "identity_binding:v1"));
        let mut reoffer = bare_row("att-1", "author-a", "identity_binding:v1");
        reoffer.scrub_signature_classical = "sig-classical-resigned".to_owned();
        reoffer.scrub_timestamp += chrono::Duration::seconds(7);
        assert_eq!(
            plan_replicated_attestation_apply(Some(&held), &reoffer).expect("plan"),
            ReplicatedAttestationPlan::Refused {
                reason: AttestationRefusalReason::AlreadyPresentIdentical
            }
        );
    }

    // ── Entry-point witnesses (the PUBLIC door) ───────────────────────
    //
    // One witness per outcome/reason variant through
    // `FederationDirectory::apply_replicated_attestation`. v62.0.0 (JSON cut,
    // E7): every row is an edition-2 statement (`e2::row_of`) by an author
    // whose `key:record` is live in the store (`e2::put_key`), so every row
    // clears the REAL admission stack. The row id is the node-computed one:
    // a caller never picks it, and reads it back off the row.

    /// A fully-admissible federation-tier row by `author`: an edition-2
    /// statement over `envelope`, mapped onto the typed row.
    fn sealed_row(author: &str, envelope: serde_json::Value) -> Attestation {
        let mut row = bare_row("", author, DIMENSION);
        row.attestation_envelope = envelope;
        e2::row_of(&row, author)
    }

    fn envelope(dimension: &str, extra: serde_json::Value) -> serde_json::Value {
        let mut env = serde_json::json!({
            "dimension": dimension,
            "score": 1.0,
            "confidence": 0.9,
        });
        if let (Some(obj), Some(more)) = (env.as_object_mut(), extra.as_object()) {
            for (k, v) in more {
                obj.insert(k.clone(), v.clone());
            }
        }
        env
    }

    async fn test_backend_with_author(author: &str) -> crate::store::sqlite::SqliteBackend {
        let dir = crate::store::test_backend::test_backend();
        // A `user` key covers every instant (E0.api v1.5): the fixture rows
        // are dated 2026-01-01, before a default node/agent window.
        e2::put_key(&dir, author, &[identity_type::USER]).await;
        dir
    }

    /// `Inserted` — a fresh row applies through the whole admission stack and
    /// is readable afterwards.
    #[tokio::test]
    async fn apply_fresh_row_is_inserted() {
        let author = "att-apply-ins-author";
        let dir = test_backend_with_author(author).await;
        let row = sealed_row(author, envelope(DIMENSION, serde_json::json!({})));
        let id = row.attestation_id.clone();
        let outcome = dir
            .apply_replicated_attestation(SignedAttestation { attestation: row })
            .await
            .expect("apply");
        assert_eq!(outcome, ReplicatedAttestationOutcome::Inserted);
        assert!(
            dir.get_attestation(&id).await.expect("get").is_some(),
            "an Inserted outcome must mean the row is actually readable"
        );
    }

    /// `Unchanged` — re-offering the STORED row (the wire re-offer every
    /// baked-genesis node produces) is an idempotent no-op, not a refusal and
    /// not an error.
    #[tokio::test]
    async fn apply_identical_reoffer_is_unchanged() {
        let author = "att-apply-unch-author";
        let dir = test_backend_with_author(author).await;
        let row = sealed_row(author, envelope(DIMENSION, serde_json::json!({})));
        let id = row.attestation_id.clone();
        dir.apply_replicated_attestation(SignedAttestation {
            attestation: row.clone(),
        })
        .await
        .expect("first apply");
        // Re-offer what the STORE now holds — the replication wire shape.
        let held = dir
            .get_attestation(&id)
            .await
            .expect("get")
            .expect("stored");
        let outcome = dir
            .apply_replicated_attestation(SignedAttestation { attestation: held })
            .await
            .expect("re-apply");
        assert_eq!(outcome, ReplicatedAttestationOutcome::Unchanged);
        // And the original (pre-canonicalization) mint re-offers as Unchanged
        // too — the hash comparison is canonicalization-stable.
        let outcome = dir
            .apply_replicated_attestation(SignedAttestation { attestation: row })
            .await
            .expect("re-apply mint");
        assert_eq!(outcome, ReplicatedAttestationOutcome::Unchanged);
    }

    /// `Refused { AlreadyPresentIdentical }` — the same assertion re-signed
    /// (fresh ML-DSA bytes, fresh scrub_timestamp) is a duplicate, not a
    /// conflict. This is the witness that distinguishes the two variants:
    /// collapsing them makes it red.
    #[tokio::test]
    async fn apply_resigned_same_assertion_is_already_present() {
        let author = "att-apply-dup-author";
        let dir = test_backend_with_author(author).await;
        let row = sealed_row(author, envelope(DIMENSION, serde_json::json!({})));
        dir.apply_replicated_attestation(SignedAttestation {
            attestation: row.clone(),
        })
        .await
        .expect("first apply");

        // v62.0.0 (JSON cut, E7) — re-sign the SAME payload by the SAME
        // author: a second statement (`voice_of`) over the same row. The row
        // id is over (type, family, sub, author, payload), never the
        // signature, so it is the same row; only the statement bytes differ.
        let again = e2::voice_of(
            &e2::carried_statement(&row).expect("the row carries its statement"),
            author,
        );
        let reoffer = e2::row_of_statement(&again, &row.tier);
        assert_eq!(
            reoffer.attestation_id, row.attestation_id,
            "same assertion, same row id"
        );
        let outcome = dir
            .apply_replicated_attestation(SignedAttestation {
                attestation: reoffer,
            })
            .await
            .expect("apply");
        assert_eq!(
            outcome,
            ReplicatedAttestationOutcome::Refused {
                reason: AttestationRefusalReason::AlreadyPresentIdentical
            }
        );
    }

    // v62.0.0 (PX-fix3) — `apply_without_a_plan_maps_duplicate_key_to_store_conflict`
    // is deleted with the #603 plan-free arm it witnessed: a directory that
    // cannot answer `get_attestation` now fails the apply (I2190).

    /// v36.0.0 (CIRISPersist#624 M6) — **a generic `get_attestation` failure
    /// must PROPAGATE, never degrade to the plan-free path.**
    ///
    /// This is the witness the #624 stream reported as inexpressible and
    /// named the remediation for: the fault double could inject exactly one
    /// error kind (`Unsupported`), which is the SANCTIONED degrade signal, so
    /// the mutation collapsing `Err(Unsupported) => plan-free` into
    /// `Err(_) => plan-free` survived every test. A surviving mutation is a
    /// claim about the instrument, and the instrument was the gap.
    ///
    /// `FaultInjectingDirectory::erroring` (added with this witness) injects
    /// `Error::Backend`. The distinction is load-bearing: `Unsupported` means
    /// *this directory cannot answer*, and proceeding plan-free is correct;
    /// `Backend` means *the answer was attempted and failed*, and proceeding
    /// would decide a convergence conflict on evidence the node never read.
    /// v62.0.0 (PX-fix3) — `Unsupported` no longer degrades either: it
    /// propagates like this `Backend` failure (I2190).
    #[tokio::test]
    async fn a_generic_get_failure_propagates_and_does_not_degrade_624() {
        let author = "att-apply-geterr-author";
        let dir = std::sync::Arc::new(test_backend_with_author(author).await);
        let failing = crate::federation::directory_double::FaultInjectingDirectory::new(
            dir.clone() as std::sync::Arc<dyn FederationDirectory>,
        )
        .erroring("get_attestation");
        assert!(
            failing.error_faults().contains("get_attestation"),
            "fixture must actually declare the fault it is testing"
        );

        let row = sealed_row(author, envelope(DIMENSION, serde_json::json!({})));
        let result = failing
            .apply_replicated_attestation(SignedAttestation { attestation: row })
            .await;
        assert!(
            result.is_err(),
            "a failed read must not become an outcome — got {result:?}"
        );
    }

    /// `Deduplicated` — the CEG §6.1 structural-composer replay: a second
    /// `withdraws` naming the same `(references_attestation_id, type,
    /// attester)` triple under a DIFFERENT id is resolved by the backend as a
    /// silent no-op; the apply names it rather than reporting an insert that
    /// never happened.
    #[tokio::test]
    async fn apply_composer_distinct_same_triple_row_is_stored() {
        let author = "att-apply-dedup-author";
        let dir = test_backend_with_author(author).await;

        // The target the withdraws retracts — the author's own row (rule 1:
        // the producer's own retraction).
        let target = sealed_row(author, envelope(DIMENSION, serde_json::json!({})));
        let target_id = target.attestation_id.clone();
        dir.apply_replicated_attestation(SignedAttestation {
            attestation: target,
        })
        .await
        .expect("target applies");

        // v62.0.0 (JSON cut, E7) — a composer carries its target's family
        // and names it by `refs.target` (the codec maps
        // `references_attestation_id` onto it). `note` makes two composers
        // over one triple two distinct rows (the row id is over the payload).
        let withdraws = |note: &str| {
            let mut row = bare_row("", author, DIMENSION);
            row.attestation_type = attestation_type::WITHDRAWS.to_owned();
            row.attestation_envelope = envelope(
                DIMENSION,
                serde_json::json!({
                    crate::federation::envelope::paths::REFERENCES_ATTESTATION_ID: target_id,
                    "note": note,
                }),
            );
            e2::row_of(&row, author)
        };
        let first = withdraws("first");
        assert_eq!(
            dir.apply_replicated_attestation(SignedAttestation { attestation: first })
                .await
                .expect("first withdraws"),
            ReplicatedAttestationOutcome::Inserted
        );

        // v61 (CIRISPersist#1157, CC rc14 3.1.9.4) — same triple, DIFFERENT
        // id: a distinct row, stored (the rank is read-time), never a replay.
        let second = withdraws("second");
        let second_id = second.attestation_id.clone();
        assert_eq!(
            dir.apply_replicated_attestation(SignedAttestation {
                attestation: second
            })
            .await
            .expect("second"),
            ReplicatedAttestationOutcome::Inserted
        );
        assert!(
            dir.get_attestation(&second_id)
                .await
                .expect("get")
                .is_some(),
            "a distinct same-triple composer is stored"
        );
    }
}
