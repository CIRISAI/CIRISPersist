//! Canonical federation-key registration admission gate
//! (v8.8.0, CIRISPersist#234, CEG 1.0-RC28/RC29 §5.6.8.15).
//!
//! # Why this module exists
//!
//! §5.6.8.15 (`consent:replication`) pins the **normative-honesty**
//! layering for out-of-group federation peering: the substrate gate
//! that lets peer **P**'s corpus admit granting node **G**'s
//! replicated rows is **G's key existing in P's `federation_keys`**
//! (registration), plus the §7 reserved-prefix identity rules. The
//! `consent:replication` attestation is the *governance/audit* record
//! of intent; it does **not** add a substrate admission check. So the
//! single load-bearing security check for every peering is one
//! operation: **register (and later deregister/expire) a peer's
//! federation key**, with hybrid-signature verification + §7
//! reserved-prefix identity rules applied at that gate.
//!
//! Before v8.8.0 two fabric siblings (CIRISServer `src/peer.rs`,
//! CIRISStatus `src/ceg.rs`) reached this gate from opposite sides,
//! each re-deriving "register this peer's key + enforce admission" —
//! a DRY violation on the *single most security-load-bearing* step in
//! the peering flow. [`verify_key_registration`] is the one canonical
//! implementation siblings call (via
//! [`Engine::register_federation_key`](crate::Engine::register_federation_key))
//! rather than re-derive.
//!
//! # What the gate verifies (the §5.6.8.15 reading)
//!
//! The registration is **hybrid-verified against the registering
//! key's own public keys** — proof-of-possession over the canonical
//! `registration_envelope`. This is the model
//! `docs/FEDERATION_DIRECTORY.md` §"Write authority — scrub-signature
//! is auth" pins: *"Persist accepts `federation_keys` writes from any
//! caller whose row carries a valid scrub-signature whose
//! `scrub_key_id` either chains to a steward via the FK chain or is
//! itself out-of-band-anchored. The cryptographic check is the auth
//! check."*
//!
//! The scrub signature on a [`KeyRecord`] is signed by the
//! `scrub_key_id` row:
//!
//! - **Self-attested (proof-of-possession), `scrub_key_id == key_id`**
//!   — the common peering case. The registering key demonstrates
//!   control of its own private keys over the registration envelope;
//!   the verifier reads the pubkeys directly off the submitted record.
//! - **Granting authority, `scrub_key_id != key_id`** — the signer
//!   must already exist in `federation_keys` (it chains to an anchor);
//!   the verifier resolves the signer's pubkeys from the directory.
//!   An unknown signer ⇒ rejected (fail-secure).
//!
//! Either way the cryptographic check is bound to **`scrub_key_id`'s**
//! keys — never to an unverified field of the submitted row alone.
//!
//! The canonical bytes the signature covers are
//! [`ceg_produce_canonicalize`](crate::verify::canonical::ceg_produce_canonicalize)`(registration_envelope)`
//! — the same JCS/Python-compat produce gate the rest of the fabric
//! signs through (post-#871 the whole fabric is on JCS). To prove the
//! verifier and the producer agree on the canonicalizer, the gate also
//! cross-checks `SHA-256(canonical) == original_content_hash`: a
//! producer that signed a *different* canonical form fails the hash
//! check first, with a clear error, and is **not stored**
//! (fail-secure).
//!
//! Verification runs in [`HybridPolicy::Strict`](crate::verify::HybridPolicy::Strict)
//! — both Ed25519 and ML-DSA-65 are REQUIRED. Peering is a high-stakes
//! domain; a hybrid-pending (Ed25519-only) registration is rejected.
//!
//! # §7 reserved-prefix identity rules at registration
//!
//! The reserved-*identity-type* rule that binds at registration is the
//! `accord_holder` hardware-attestation gate (§7.2 / §9.1): an
//! `accord_holder` row MUST carry valid hardware-attestation evidence.
//! That gate already lives in
//! [`FederationDirectory::put_public_key`](crate::federation::FederationDirectory::put_public_key)
//! (the `hardware_attestation_policy().check(...)` call) and the V048
//! schema CHECK; this module composes `put_public_key` and so does not
//! weaken or duplicate it. The §7 *emitter* rules (`accord:*`,
//! `system:*`, …) are dimension-scoped and bind at attestation
//! admission ([`super::admission`]), not at key registration.
//!
//! # Fail-secure
//!
//! ANY verification or rule failure ⇒ a typed [`Error`] (stable
//! `kind()` token [`Error::SignatureInvalid`] ⇒
//! `"federation_signature_invalid"`, or [`Error::InvalidArgument`])
//! and the row is **NOT stored** — no `put_public_key` call is made.
//! Unknown/unverified ⇒ not registered ⇒ that peer's replicated rows
//! are not admitted. That is the whole point of §5.6.8.15.

use sha2::{Digest, Sha256};

use super::types::{algorithm, KeyRecord};
use super::{Error, FederationDirectory};
use crate::verify::canonical::ceg_produce_canonicalize;
use crate::verify::{verify_hybrid, HybridPolicy, VerifyOutcome};

/// Outcome of an [`adopt_scrub_upgrade`](crate::engine::Engine::adopt_scrub_upgrade)
/// — the self-signed → anchor-scrubbed upgrade of a node's own key row
/// (CIRISPersist#351).
#[derive(Debug, Clone, Copy, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum AdoptScrubOutcome {
    /// The self-signed row was replaced by the anchor-scrubbed record.
    Upgraded,
    /// The row already carried this exact anchor-scrubbed record — idempotent
    /// no-op (re-applying the outbox record on a second boot).
    AlreadyAdopted,
}

/// v24.2.0 (CIRISPersist#565) — **WHICH policy branch refused** a replicated
/// Key-plane apply.
///
/// Before this existed, [`ReplicatedKeyOutcome::Refused`] was a unit variant,
/// so the most a receiver could honestly print was the whole disjunction —
/// *"pubkey swap / downgrade / re-scrub / ambiguous owner / unverifiable
/// sig"*. #565 is the bill for that: a day spent inside that disjunction on a
/// production canonical, over twenty refusals of one content hash. A refusal
/// is a verdict, and a verdict without its evidence sends the reader to the
/// wrong layer.
///
/// **Closed**, and every variant corresponds to exactly ONE condition in the
/// code — there is deliberately no `Other`/`Unspecified` catch-all, because a
/// catch-all reintroduces the disjunction one name deeper. Serde tokens are
/// snake_case and [`Self::as_str`] returns the SAME token, so a consumer keys
/// on a program constant and never on a message string (the explicit ask in
/// #565: persist owns this taxonomy, and a second copy of it downstream is the
/// two-lists-that-disagree class).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, serde::Serialize, serde::Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum KeyRefusalReason {
    /// A hybrid pubkey half (Ed25519 OR ML-DSA-65) differs from the stored
    /// row's. A different pubkey is a different identity, whatever the scrub
    /// says — replication may never swap an identity's keys.
    PubkeySwap,
    /// The stored row is **anchor-scrubbed** and the incoming record is
    /// **self-signed**: a downgrade. Monotonic — never demote an anchored row.
    Downgrade,
    /// The stored row and the incoming record are BOTH self-signed for the
    /// same identity but are not the same record: a conflicting second
    /// version. First-seen wins.
    ConflictingVersion,
    /// Both rows are anchor-scrubbed and the incoming one is not an admissible
    /// **canonical supersede** (not canonical-scoped, or its SIGNED envelope
    /// `valid_from` is not strictly newer, or the m-of-n quorum re-verify /
    /// withdrawal-wins check failed). The historical anchor-A→anchor-B
    /// re-scrub hijack guard.
    ReScrub,
    /// Both rows are anchor-scrubbed and the incoming record asserts the
    /// **anchoring this node already holds** — same `registration_envelope`,
    /// same `scrub_key_id` — differing only in unsigned decoration or
    /// signature bytes.
    ///
    /// This is a *duplicate*, not a rejection: the receiver already has
    /// exactly what was offered. It exists because every node now ships the
    /// baked genesis seed, so a canonical replicating its own record meets a
    /// receiver that already holds it; reporting that as a re-scrub hijack
    /// sends the reader hunting for an attack that is not there. A
    /// BYTE-identical re-offer never reaches here — it resolves
    /// [`ReplicatedKeyOutcome::Unchanged`] at the `persist_row_hash`
    /// comparison, which is the correct outcome and stays unchanged.
    AlreadyAnchoredIdentical,
    /// The incoming record's scrub-signature did not clear the Strict
    /// [`verify_key_registration`] gate (malformed record, canonicalizer
    /// disagreement, unregistered signer, or a bad hybrid signature).
    UnverifiableSignature,
    /// [`owner_of`](super::admission::owner_of) resolved **no** owner for the
    /// key: the row is not inside any single-owner node set, so replication
    /// may not auto-upgrade it (fail-closed).
    OwnerAbsent,
    /// [`owner_of`](super::admission::owner_of) resolved **more than one**
    /// owner ([`Error::AmbiguousNodeOwner`]): the owner scope is not
    /// well-defined, so replication may not auto-upgrade it (fail-closed).
    OwnerAmbiguous,
    /// The store step returned [`Error::Conflict`]: the row present at WRITE
    /// time is not the row the decision was made against. On a planning
    /// backend that is a lost race between plan and act; on a plan-free
    /// backend (the default [`FederationDirectory::apply_replicated_key_record`]
    /// body) it is a differing row already held. Either way: fail-closed, the
    /// existing row is untouched, and the record is safe to re-offer.
    StoreConflict,
}

impl KeyRefusalReason {
    /// The **stable program token** for this reason — identical to the serde
    /// token, so a consumer that reads the wire and a consumer that holds the
    /// typed value key on the same constant.
    ///
    /// This is the half of #565 that makes string-matching unnecessary rather
    /// than merely discouraged. [`tests::refusal_reason_tokens_match_serde`]
    /// binds the two spellings together so they cannot drift.
    ///
    /// **The token set is the downstream contract, and this mapping is
    /// APPEND-ONLY.** CIRISEdge keys its apply seam on these constants, so a
    /// rename here costs them a release — which is the whole cost #565 exists
    /// to stop paying. Add variants; never re-spell one.
    #[must_use]
    pub const fn as_str(&self) -> &'static str {
        match self {
            Self::PubkeySwap => "pubkey_swap",
            Self::Downgrade => "downgrade",
            Self::ConflictingVersion => "conflicting_version",
            Self::ReScrub => "re_scrub",
            Self::AlreadyAnchoredIdentical => "already_anchored_identical",
            Self::UnverifiableSignature => "unverifiable_signature",
            Self::OwnerAbsent => "owner_absent",
            Self::OwnerAmbiguous => "owner_ambiguous",
            Self::StoreConflict => "store_conflict",
        }
    }

    /// Every variant, in declaration order — the closed set, for exhaustive
    /// gates and for a consumer enumerating the taxonomy it must handle.
    pub const ALL: &'static [Self] = &[
        Self::PubkeySwap,
        Self::Downgrade,
        Self::ConflictingVersion,
        Self::ReScrub,
        Self::AlreadyAnchoredIdentical,
        Self::UnverifiableSignature,
        Self::OwnerAbsent,
        Self::OwnerAmbiguous,
        Self::StoreConflict,
    ];
}

impl std::fmt::Display for KeyRefusalReason {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(self.as_str())
    }
}

/// v12.7.0 (CIRISPersist#371) — outcome of an
/// [`apply_replicated_key_record`](crate::engine::Engine::apply_replicated_key_record),
/// the **upgrade-aware replicated Key-plane apply**. Serde tokens are
/// snake_case strings (`"inserted"` / `"upgraded"` / `"unchanged"` /
/// `"superseded"`), mirroring [`AdoptScrubOutcome`]'s wire shape;
/// `Refused` carries its reason as `{"refused":{"reason":"<token>"}}`, the
/// same shape the sibling route plane's
/// [`TransportDestinationApplyOutcome`](crate::federation::self_at_login::TransportDestinationApplyOutcome)
/// already uses.
///
/// A `Refused` is a *policy* outcome, not an error: the anti-entropy Key
/// plane receives unsolicited records, so every gate failure that means
/// "this record is not admitted against the current row" resolves to
/// `Refused` (fail-closed, deterministic, safe to re-offer on the next
/// anti-entropy round) rather than aborting the apply loop.
#[derive(Debug, Clone, Copy, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ReplicatedKeyOutcome {
    /// New `key_id` — stored via `put_public_key` (exactly the direct
    /// registration path, including its admission gates).
    Inserted,
    /// Existing **self-signed** row replaced by the incoming
    /// **anchor-scrubbed** record for the same identity (the #351
    /// `adopt_scrub_upgrade`, now riding replication).
    Upgraded,
    /// The row already carries this exact record — idempotent no-op.
    Unchanged,
    /// The record was NOT applied and the existing row is untouched.
    ///
    /// v24.2.0 (CIRISPersist#565): `reason` names the branch that fired. It
    /// used to be a bare variant, which forced every receiver to print the
    /// whole disjunction — see [`KeyRefusalReason`] for why that cost a day.
    Refused {
        /// WHICH policy branch refused. A closed enum, not a message string.
        reason: KeyRefusalReason,
    },
    /// v13.7.0 (CIRISPersist#405) — an existing **canonical** (anchor-scrubbed)
    /// row was replaced in place by a **strictly-newer, same-pubkey, m-of-n
    /// quorum-re-verified** record — the CEG-native runtime address move (a
    /// re-scrubbed canonical whose `valid_from` is newer supersedes the older).
    /// APPEND-ONLY (crosses the directory capsule ABI). Distinct from
    /// `Upgraded` (self→scrubbed): `Superseded` is scrubbed→newer-scrubbed.
    Superseded,
}

/// The classification half of the #371 replicated-key apply — which action
/// [`apply_replicated_key_record`](crate::engine::Engine::apply_replicated_key_record)
/// takes for an incoming record given the current directory state.
#[cfg(any(feature = "postgres", feature = "sqlite"))]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum ReplicatedKeyPlan {
    /// No row for `key_id` — insert via `put_public_key` (as today).
    Insert,
    /// Self-signed → anchor-scrubbed, all gates passed — run the backend's
    /// monotonic `adopt_scrub_upgrade`.
    Upgrade,
    /// v13.7.0 (CIRISPersist#405) — existing canonical (anchor-scrubbed) →
    /// strictly-newer, same-pubkey, m-of-n-re-verified canonical record. Run
    /// the backend's `supersede_canonical_record` (the CEG-native runtime
    /// address move).
    Supersede,
    /// Byte-identical re-apply — no-op.
    Unchanged,
    /// Not admitted; leave the row untouched (fail-closed).
    ///
    /// v24.2.0 (CIRISPersist#565) — carries the SAME [`KeyRefusalReason`] the
    /// outcome does. The plan is where the policy branches actually are, so
    /// this is where the reason is *produced*; the backends carry it through
    /// to [`ReplicatedKeyOutcome::Refused`] rather than re-deriving it (one
    /// predicate, one implementation).
    Refused {
        /// WHICH policy branch refused.
        reason: KeyRefusalReason,
    },
}

/// v12.7.0 (CIRISPersist#371) — decide what an **upgrade-aware replicated
/// Key-plane apply** does with `record`, WITHOUT mutating anything. The
/// shared (backend-agnostic) policy core behind both backends'
/// `apply_replicated_key_record`, so postgres and sqlite cannot drift.
///
/// Decision table (the #371 spec):
///
/// - **no existing row** ⇒ [`ReplicatedKeyPlan::Insert`] — the store step is
///   `put_public_key` itself, so every direct-registration admission gate
///   (32-byte Ed25519, `hybrid` algorithm, `accord_holder`
///   hardware-attestation) still binds; nothing is bypassed for fresh rows.
/// - **byte-identical re-apply** (same `persist_row_hash`, which is computed
///   over the canonical row with the hash field dropped) ⇒
///   [`ReplicatedKeyPlan::Unchanged`].
/// - **any pubkey change** — Ed25519 OR ML-DSA-65 — ⇒
///   [`ReplicatedKeyPlan::Refused`]. A replicated apply may never swap an
///   identity's keys (stricter than #351's Ed25519-only Rust pre-check: on
///   the unattended replication plane the PQC half is identity too).
/// - **existing self-signed + incoming anchor-scrubbed** ⇒ upgrade, iff ALL
///   of (fail-closed on each):
///   1. the incoming scrub verifies through the SAME
///      [`verify_key_registration`] `Strict` gate as
///      `register_federation_key` / `adopt_scrub_upgrade` — the scrubber
///      (`scrub_key_id`) is resolved from the directory, i.e. it chains to
///      the seeded HUMANITY_ACCORD anchor rows on a real node; a
///      verification failure ⇒ `Refused`, and
///   2. [`owner_of`](crate::federation::admission::owner_of)`(key_id)`
///      resolves to exactly ONE live owner — the row is inside a
///      well-defined single-owner node set (the v12.6.0 invariant that makes
///      auto-upgrade-on-replication safe: the Key-plane cohort spans exactly
///      the owner's nodes, CIRISServer#162). An unowned node (`None`) or an
///      [`Error::AmbiguousNodeOwner`] pre-gate anomaly ⇒ `Refused`.
///      (The record itself carries no owner field — verify's
///      `produce_scrubbed_key_record` envelope shape is pinned — so the
///      owner scope is resolved from the local attestation graph, the same
///      source the owner's replication cohort is built from.)
/// - **monotonic**: anchored→self (downgrade), anchor-A→anchor-B (re-scrub
///   hijack), and a conflicting second self-signed version are all
///   first-seen/duplicity ⇒ [`ReplicatedKeyPlan::Refused`].
///
/// Malformed input that no policy can classify (e.g. an un-canonicalizable
/// row) and backend failures still surface as `Err` — `Refused` is reserved
/// for "well-formed but not admitted".
#[cfg(any(feature = "postgres", feature = "sqlite"))]
pub(crate) async fn plan_replicated_key_apply(
    directory: &dyn FederationDirectory,
    record: &KeyRecord,
) -> Result<ReplicatedKeyPlan, Error> {
    let Some(existing) = directory.lookup_public_key(&record.key_id).await? else {
        return Ok(ReplicatedKeyPlan::Insert);
    };

    // Idempotent re-apply: byte-identical row. `compute_persist_row_hash`
    // drops the `persist_row_hash` field itself, so a record that arrives
    // carrying the origin row's hash still compares stably.
    let incoming_hash = super::types::compute_persist_row_hash(record)?;
    if existing.persist_row_hash == incoming_hash {
        return Ok(ReplicatedKeyPlan::Unchanged);
    }

    // Never a pubkey swap — BOTH hybrid halves must be identical. A
    // different pubkey is a different identity, whatever the scrub says.
    if existing.pubkey_ed25519_base64 != record.pubkey_ed25519_base64
        || existing.pubkey_ml_dsa_65_base64 != record.pubkey_ml_dsa_65_base64
    {
        return Ok(refused(KeyRefusalReason::PubkeySwap));
    }

    let existing_self_signed = existing.scrub_key_id == existing.key_id;
    let incoming_anchor_scrubbed = record.scrub_key_id != record.key_id;
    if !incoming_anchor_scrubbed {
        // v24.2.0 (CIRISPersist#565) — ONE site, TWO policies, and they were
        // fused behind one bare `Refused`. Split them: an incoming self-signed
        // record over an ANCHORED row is a downgrade (never demote); over
        // another SELF-SIGNED row it is a conflicting second version
        // (first-seen wins). The remedies differ, so the names must.
        return Ok(refused(if existing_self_signed {
            KeyRefusalReason::ConflictingVersion
        } else {
            KeyRefusalReason::Downgrade
        }));
    }
    if !existing_self_signed {
        // Existing is ALREADY anchor-scrubbed + incoming is anchor-scrubbed,
        // same pubkey (a pubkey swap was refused above). Historically an
        // anchor-A→anchor-B re-scrub was refused outright as a hijack. #405:
        // a re-scrubbed CANONICAL record whose `valid_from` is strictly newer
        // SUPERSEDES the stored one — the CEG-native runtime address move — but
        // ONLY through the same non-forgeable m-of-n quorum re-verify the add
        // path uses, and ONLY monotonically forward. Anything else stays the
        // fail-closed re-scrub refuse.
        return plan_canonical_supersede(directory, &existing, record).await;
    }

    // Gate 1 — the incoming scrub must verify (Strict hybrid, scrubber
    // pubkeys resolved from the directory ⇒ chains to the seeded accord
    // anchor). An unverifiable or malformed record is not admitted.
    if let Err(e) = verify_key_registration(directory, record).await {
        return match e {
            Error::SignatureInvalid(_) | Error::InvalidArgument(_) => {
                Ok(refused(KeyRefusalReason::UnverifiableSignature))
            }
            other => Err(other),
        };
    }

    // Gate 2 — the row must sit inside a single owner's node set
    // (v12.6.0 `owner_of`). Unowned or ambiguous ⇒ fail-closed.
    //
    // v24.2.0 (CIRISPersist#565) — "absent" and "ambiguous" were one line of
    // prose and two lines of code. They stay two: an unowned key needs an
    // owner-binding attestation, a doubly-owned one needs a duplicate
    // ownership claim resolved. Collapsing them would mislabel the common
    // case (unowned) as the anomaly.
    match super::admission::owner_of(directory, &record.key_id).await {
        Ok(Some(_)) => Ok(ReplicatedKeyPlan::Upgrade),
        Ok(None) => Ok(refused(KeyRefusalReason::OwnerAbsent)),
        Err(Error::AmbiguousNodeOwner { .. }) => Ok(refused(KeyRefusalReason::OwnerAmbiguous)),
        Err(e) => Err(e),
    }
}

/// v24.2.0 (CIRISPersist#565) — the one constructor for a refused plan, so a
/// site cannot forget the reason (there is no reason-less way to build one).
#[cfg(any(feature = "postgres", feature = "sqlite"))]
const fn refused(reason: KeyRefusalReason) -> ReplicatedKeyPlan {
    ReplicatedKeyPlan::Refused { reason }
}

/// v13.7.0 (CIRISPersist#405) — plan a **canonical supersede**: an existing
/// anchor-scrubbed canonical row replaced in place by a strictly-newer,
/// same-pubkey, m-of-n-re-verified re-scrubbed record (the CEG-native runtime
/// address move). Called only for `existing anchor-scrubbed + incoming
/// anchor-scrubbed + same pubkey`; every rejection is fail-closed `Refused`,
/// preserving the historical re-scrub-hijack guard for anything that doesn't
/// clear ALL of:
///
/// 1. **Canonical-scoped.** The incoming record MUST carry the `canonical`
///    role. Load-bearing: [`check_canonical_role_admission`] fast-paths a
///    NON-canonical row to `Ok(())`, so without this guard a single-anchor
///    re-scrub of a plain node would bypass the quorum entirely.
/// 2. **Monotonic over the SIGNED timestamp.** The incoming envelope's
///    `valid_from` MUST be strictly greater than the stored envelope's. This
///    reads the `valid_from` INSIDE `registration_envelope` — the field the
///    scrub signatures actually cover (`JCS(registration_envelope)`) — NOT the
///    top-level `KeyRecord::valid_from`, which is unsigned and forgeable: using
///    the top-level field would let an attacker replay an older validly-scrubbed
///    record with a bumped timestamp to DOWNGRADE the address. An unreadable /
///    absent envelope timestamp on either side ⇒ `Refused` (can't prove
///    monotonicity → fail closed).
/// 3. **m-of-n quorum re-verified from persist's OWN state.**
///    [`check_canonical_role_admission`] re-derives the strict-majority policy
///    over the LIVE accord roster (`verify_quorum_policy`) and re-checks every
///    co-scrub — never the record's claim, never a hardcoded threshold. It also
///    enforces withdrawal-wins (a tombstoned key stays refused).
#[cfg(any(feature = "postgres", feature = "sqlite"))]
async fn plan_canonical_supersede(
    directory: &dyn FederationDirectory,
    existing: &KeyRecord,
    record: &KeyRecord,
) -> Result<ReplicatedKeyPlan, Error> {
    if verify_canonical_supersede(directory, existing, record).await? {
        return Ok(ReplicatedKeyPlan::Supersede);
    }
    // v24.2.0 (CIRISPersist#565) — the verdict is already decided (refuse);
    // this only chooses its NAME, and only from state already in hand. It is
    // deliberately NOT a second admission predicate:
    // `verify_canonical_supersede` stays the single shared decision the
    // backends' mutation chokepoints also run, so there is no second validator
    // to disagree with it.
    Ok(refused(if asserts_the_same_anchoring(existing, record) {
        KeyRefusalReason::AlreadyAnchoredIdentical
    } else {
        KeyRefusalReason::ReScrub
    }))
}

/// v24.2.0 (CIRISPersist#565) — does `record` assert the **anchoring the
/// stored row already carries**?
///
/// True iff the two rows carry the SAME `registration_envelope` (the bytes the
/// scrubs actually cover — `JCS(registration_envelope)`, which is also where
/// the co-scrub set lives) under the SAME `scrub_key_id`. The caller has
/// already established same `key_id` and same hybrid pubkeys, so what remains
/// different is unsigned decoration (`valid_until`, the top-level unsigned
/// `valid_from`) or the signature bytes themselves — never the assertion.
///
/// A BYTE-identical record never reaches here: it resolves `Unchanged` at the
/// `persist_row_hash` comparison in [`plan_replicated_key_apply`]. This names
/// the near-miss — which is the case a baked-seed fleet actually produces, and
/// the one that read as an anchor-A→anchor-B hijack until #565.
#[cfg(any(feature = "postgres", feature = "sqlite"))]
fn asserts_the_same_anchoring(existing: &KeyRecord, record: &KeyRecord) -> bool {
    existing.scrub_key_id == record.scrub_key_id
        && existing.registration_envelope == record.registration_envelope
}

/// v13.7.0 (CIRISPersist#405) — the CANONICAL-SUPERSEDE policy core, shared by
/// [`plan_canonical_supersede`] (classification) and each backend's
/// `supersede_canonical_record` (mutation chokepoint, defense-in-depth). Given
/// the currently-stored `existing` row and the `record` proposing to replace
/// it, returns `Ok(true)` iff ALL of the following hold; `Ok(false)` for any
/// policy rejection (fail-closed); `Err` only for a real infrastructure/backend
/// failure (never masked as a refusal).
///
/// Caller pre-conditions (enforced before this is reached): same `key_id`
/// (looked up), same hybrid pubkey (a swap is refused earlier), and both rows
/// anchor-scrubbed. This fn adds:
///
/// 1. **Canonical-scoped** — the incoming record carries the `canonical` role.
///    Load-bearing: [`check_canonical_role_admission`] fast-paths a NON-canonical
///    row to `Ok(())`, so without this a single-anchor re-scrub of a plain node
///    would bypass the quorum.
/// 2. **Monotonic over the SIGNED timestamp** — the incoming envelope's
///    `valid_from` is strictly greater than the stored envelope's. Reads
///    `valid_from` INSIDE `registration_envelope` (the field the scrubs cover
///    via `JCS(registration_envelope)`), NOT the unsigned top-level
///    `KeyRecord::valid_from` — else a replay of an older validly-scrubbed
///    record with a bumped top-level timestamp could DOWNGRADE the address. An
///    absent/unparseable envelope timestamp on either side ⇒ `false`.
/// 3. **m-of-n quorum re-verified from persist's OWN state** —
///    [`check_canonical_role_admission`] re-derives the strict-majority policy
///    over the LIVE accord roster (`verify_quorum_policy`) and re-checks every
///    co-scrub; also enforces withdrawal-wins.
#[cfg(any(feature = "postgres", feature = "sqlite"))]
pub(crate) async fn verify_canonical_supersede(
    directory: &dyn FederationDirectory,
    existing: &KeyRecord,
    record: &KeyRecord,
) -> Result<bool, Error> {
    if !supersede_precheck(existing, record) {
        return Ok(false);
    }
    // m-of-n quorum re-verified from persist's own state (+ withdrawal-wins),
    // against the PRODUCTION genesis accord roster.
    match super::admission::check_canonical_role_admission(directory, record).await {
        Ok(()) => Ok(true),
        Err(Error::CanonicalRoleNotAccordConferred { .. })
        | Err(Error::CanonicalRoleWithdrawn { .. }) => Ok(false),
        Err(e) => Err(e),
    }
}

/// [`verify_canonical_supersede`] with an EXPLICIT accord-holder roster — the
/// testable core (tests co-scrub against a distinct test roster; the production
/// wrapper pins the genesis A1/B1/C1). Mirrors
/// [`check_canonical_role_admission_over_roster`](super::admission::check_canonical_role_admission_over_roster).
/// Test-only: the production apply path always resolves the genesis roster via
/// [`verify_canonical_supersede`].
#[cfg(all(test, any(feature = "postgres", feature = "sqlite")))]
pub(crate) async fn verify_canonical_supersede_over_roster(
    directory: &dyn FederationDirectory,
    existing: &KeyRecord,
    record: &KeyRecord,
    roster_key_ids: &[String],
) -> Result<bool, Error> {
    if !supersede_precheck(existing, record) {
        return Ok(false);
    }
    match super::admission::check_canonical_role_admission_over_roster_legacy(
        directory,
        record,
        roster_key_ids,
    )
    .await
    {
        Ok(()) => Ok(true),
        Err(Error::CanonicalRoleNotAccordConferred { .. })
        | Err(Error::CanonicalRoleWithdrawn { .. }) => Ok(false),
        Err(e) => Err(e),
    }
}

/// The quorum-independent half of the #405 supersede policy (canonical-scope +
/// strictly-newer SIGNED-envelope `valid_from`). Sync + crypto-free so the
/// monotonicity / replay-spoof / scope decisions are unit-testable in isolation
/// from the m-of-n quorum. Returns `true` iff the incoming record is canonical
/// AND its envelope `valid_from` is strictly newer than the stored one.
#[cfg(any(feature = "postgres", feature = "sqlite"))]
pub(crate) fn supersede_precheck(existing: &KeyRecord, record: &KeyRecord) -> bool {
    use super::types::identity_type;

    // (1) Canonical-scoped — a non-canonical anchor→anchor re-scrub stays the
    // fail-closed hijack refuse (check_canonical_role_admission fast-paths a
    // non-canonical row to Ok, so this guard is load-bearing).
    if !identity_type::set_contains(&record.identity_type, identity_type::CANONICAL) {
        return false;
    }

    // (2) Strictly-newer SIGNED (envelope) valid_from. Reads the field the
    // scrubs cover — JCS(registration_envelope) — NOT the unsigned top-level
    // KeyRecord::valid_from, which a replay could bump to forge recency.
    let envelope_valid_from = |rec: &KeyRecord| -> Option<chrono::DateTime<chrono::Utc>> {
        rec.registration_envelope
            .get("valid_from")
            .and_then(|v| v.as_str())
            .and_then(|s| chrono::DateTime::parse_from_rfc3339(s).ok())
            .map(|t| t.with_timezone(&chrono::Utc))
    };
    match (envelope_valid_from(record), envelope_valid_from(existing)) {
        (Some(incoming_vf), Some(existing_vf)) => incoming_vf > existing_vf,
        _ => false,
    }
}

/// v10.1.0 (CIRISPersist#275 hardening) — the **write-path admission
/// invariant** for a `federation_keys` row's classical public key: it
/// MUST base64-decode to exactly 32 bytes (a valid Ed25519 key).
///
/// This is the universal backstop the #275 saga proved was missing: a
/// row whose `pubkey_ed25519_base64` was a 65-byte P-256 point was stored
/// unchallenged and only failed (`invalid_length`) at a downstream
/// `verify_hybrid_via_directory` read. Called by **every** backend's
/// `put_public_key` (the one write chokepoint all registration paths —
/// `register_self_federation_key`, `register_federation_key`, the FFI,
/// direct callers — funnel through), so a wrong-curve / malformed key can
/// never be admitted regardless of how it was produced. Backend-agnostic:
/// the SAME check runs on Postgres and SQLite.
pub fn validate_registration_pubkey(record: &KeyRecord) -> Result<(), Error> {
    use base64::{engine::general_purpose::STANDARD as B64, Engine as _};
    /// An Ed25519 public key is exactly 32 bytes.
    const ED25519_PUBLIC_KEY_LEN: usize = 32;
    let decoded = B64.decode(&record.pubkey_ed25519_base64).map_err(|e| {
        Error::InvalidArgument(format!(
            "pubkey_ed25519_base64 is not valid base64 (key_id {}): {e}",
            record.key_id
        ))
    })?;
    if decoded.len() != ED25519_PUBLIC_KEY_LEN {
        return Err(Error::InvalidArgument(format!(
            "pubkey_ed25519_base64 must decode to a 32-byte Ed25519 key, got {} bytes (key_id {}) \
             — a non-Ed25519 key (e.g. a 65-byte P-256 point) cannot be admitted to \
             federation_keys",
            decoded.len(),
            record.key_id
        )));
    }
    Ok(())
}

/// v21.0.0 (CIRISPersist#502 E2) — does this record claim a role-gated
/// identity? Canonical / accord_holder / infra:attest / co-steward
/// registrations have their OWN admission (m-of-n co-scrub / HW), enforced
/// by `put_public_key`'s `check_*_role_admission` gates — the E2 peer-key
/// proof-of-possession gate MUST NOT pre-empt them (it would reject a
/// co-scrubbed canonical for lacking a self-PoP). E2 guards only the
/// ungated peer-key insert path — "the paths that don't verify at all".
pub fn record_is_role_gated(record: &KeyRecord) -> bool {
    use crate::federation::types::identity_type as it;
    record.claims_role(it::CANONICAL)
        || record.claims_role(it::ACCORD_HOLDER)
        || record.claims_role("infra:attest")
        || it::CO_STEWARD_ROLES.iter().any(|r| record.claims_role(r))
}

/// Verify a [`KeyRecord`] registration against the §5.6.8.15 admission
/// gate, BEFORE any store. Generic over [`FederationDirectory`] so it
/// composes against any backend (postgres, sqlite, memory) — the
/// directory is only consulted to resolve a granting-authority
/// signer's pubkeys when `scrub_key_id != key_id`.
///
/// On success returns the [`VerifyOutcome`] (always
/// [`VerifyOutcome::HybridVerified`] under the Strict policy this gate
/// uses); the caller then stores the row via `put_public_key`. On ANY
/// failure returns a typed [`Error`] and the caller MUST NOT store the
/// row.
///
/// This does **not** apply the `accord_holder` hardware-attestation
/// gate or the `algorithm == hybrid` check itself — those live in
/// `put_public_key` and the schema, and the caller
/// ([`Engine::register_federation_key`](crate::Engine::register_federation_key))
/// composes them by calling `put_public_key` only after this returns
/// `Ok`. The `algorithm` check is *additionally* asserted here as a
/// cheap fail-fast so a non-hybrid row never reaches the (expensive)
/// PQC verify.
pub async fn verify_key_registration<F>(
    directory: &F,
    record: &KeyRecord,
) -> Result<VerifyOutcome, Error>
where
    F: FederationDirectory + ?Sized,
{
    // Fail-fast: algorithm must be hybrid. put_public_key + the schema
    // CHECK enforce this too; asserting here keeps a non-hybrid row
    // from ever reaching the PQC verify, and gives the same
    // InvalidArgument shape the store path returns.
    if record.algorithm != algorithm::HYBRID {
        return Err(Error::InvalidArgument(format!(
            "algorithm must be 'hybrid' for registration (got '{}')",
            record.algorithm
        )));
    }

    if record.key_id.is_empty() {
        return Err(Error::InvalidArgument(
            "key_id must be non-empty for registration".to_string(),
        ));
    }
    if record.scrub_key_id.is_empty() {
        return Err(Error::InvalidArgument(
            "scrub_key_id must be non-empty for registration".to_string(),
        ));
    }
    // #275 hardening — the classical pubkey must be a valid 32-byte Ed25519
    // key (fail-fast before the PQC verify; `put_public_key` re-checks at the
    // store chokepoint for paths that skip this gate).
    validate_registration_pubkey(record)?;

    // Canonicalize the registration envelope through the CEG produce
    // gate — the same canonical form the producer signed. Cross-check
    // its SHA-256 against the row's declared original_content_hash so
    // a canonicalizer disagreement (producer signed a different shape)
    // is caught here, fail-secure, rather than masked as a downstream
    // signature mismatch.
    let canonical = ceg_produce_canonicalize(&record.registration_envelope)
        .map_err(|e| Error::InvalidArgument(format!("registration_envelope canonicalize: {e}")))?;
    let computed_hash = hex::encode(Sha256::digest(&canonical));
    if computed_hash != record.original_content_hash {
        return Err(Error::SignatureInvalid(format!(
            "registration original_content_hash mismatch: envelope canonicalizes to {computed_hash}, \
             record declares {}",
            record.original_content_hash
        )));
    }

    // Resolve the signer's (scrub_key_id's) public keys. Self-attested
    // proof-of-possession (scrub_key_id == key_id) reads the pubkeys
    // straight off the submitted record; a granting-authority
    // signature (scrub_key_id != key_id) resolves them from the
    // directory — an unknown signer is rejected (fail-secure).
    let (ed25519_pubkey_b64, ml_dsa_65_pubkey_b64) = if record.scrub_key_id == record.key_id {
        (
            record.pubkey_ed25519_base64.clone(),
            record.pubkey_ml_dsa_65_base64.clone(),
        )
    } else {
        let signer = directory
            .lookup_public_key(&record.scrub_key_id)
            .await?
            .ok_or_else(|| {
                Error::SignatureInvalid(format!(
                    "registration signer (scrub_key_id={}) is not registered",
                    record.scrub_key_id
                ))
            })?;
        (signer.pubkey_ed25519_base64, signer.pubkey_ml_dsa_65_base64)
    };

    // Strict hybrid verify: both Ed25519 and ML-DSA-65 REQUIRED.
    // Peering is high-stakes; a hybrid-pending (Ed25519-only)
    // registration is rejected. row_age is irrelevant under Strict.
    let outcome = verify_hybrid(
        &canonical,
        &record.scrub_signature_classical,
        record.scrub_signature_pqc.as_deref(),
        &ed25519_pubkey_b64,
        ml_dsa_65_pubkey_b64.as_deref(),
        HybridPolicy::Strict,
        None,
    )
    .map_err(|e| {
        Error::SignatureInvalid(format!("registration hybrid-verify: {e} ({})", e.kind()))
    })?;

    Ok(outcome)
}

#[cfg(all(test, any(feature = "postgres", feature = "sqlite")))]
mod tests {
    //! v8.8.0 (CIRISPersist#234) — the §5.6.8.15 admission-gate matrix,
    //! run identically against sqlite and (when `CIRIS_PERSIST_TEST_PG_URL`
    //! is set) postgres via [`run_register_matrix`]. Test (b) — bad/missing
    //! signature ⇒ REJECTED + NOT stored — is the load-bearing fail-secure
    //! guard.

    use super::*;
    use crate::engine::Engine;
    use crate::federation::types::{algorithm, identity_type};
    use crate::federation::{KeyRecord, SignedKeyRecord};
    use crate::signing::LocalSigner;
    use base64::engine::general_purpose::STANDARD as B64;
    use base64::Engine as _;
    use ciris_keyring::PqcSigner as _;
    use ed25519_dalek::{Signer as _, SigningKey};
    use std::sync::Arc;

    /// Engine scrub-signer for tests — deterministic seed; the engine's
    /// own signing identity is independent of the peer keys being
    /// registered.
    fn test_signer() -> Arc<LocalSigner> {
        let signing_key = SigningKey::from_bytes(&[0x7Au8; 32]);
        Arc::new(LocalSigner::from_parts(
            signing_key,
            "register-test-steward".to_string(),
            None,
            None,
        ))
    }

    /// Build a fully hybrid-signed (Ed25519 + ML-DSA-65) self-attested
    /// `KeyRecord` — `scrub_key_id == key_id`, proof-of-possession over
    /// the registration envelope. Returns the record; the seeds make
    /// it deterministic. `tamper` mutates the envelope AFTER signing
    /// (for the tampered-envelope test); `drop_pqc` strips the PQC
    /// signature (for the hybrid-pending rejection test); `corrupt_ed`
    /// flips the classical signature.
    async fn signed_self_record(
        key_id: &str,
        identity_type: &str,
        attestation_evidence: Option<serde_json::Value>,
        tamper: bool,
        drop_pqc: bool,
        corrupt_ed: bool,
    ) -> KeyRecord {
        // Deterministic-per-key seeds (first 8 bytes from the key_id).
        let mut seed = [0x11u8; 32];
        for (i, b) in key_id.bytes().take(32).enumerate() {
            seed[i] = b;
        }
        let ed_sk = SigningKey::from_bytes(&seed);
        let ed_pk = ed_sk.verifying_key().to_bytes();

        let mldsa = ciris_keyring::MlDsa65SoftwareSigner::from_seed_bytes(&seed, "reg-test-mldsa")
            .expect("seed length checked");
        let mldsa_pk = mldsa.public_key().await.expect("ml-dsa pk");

        let envelope = serde_json::json!({
            "key_id": key_id,
            "purpose": "federation-peering",
        });
        let canonical = ceg_produce_canonicalize(&envelope).expect("canonicalize");
        let original_content_hash = hex::encode(Sha256::digest(&canonical));

        // Ed25519 over canonical.
        let ed_sig = ed_sk.sign(&canonical).to_bytes();
        // ML-DSA-65 over the BOUND input (canonical || classical_sig).
        let mut bound = Vec::with_capacity(canonical.len() + ed_sig.len());
        bound.extend_from_slice(&canonical);
        bound.extend_from_slice(&ed_sig);
        let pqc_sig = mldsa.sign(&bound).await.expect("ml-dsa sign");

        let mut classical_b64 = B64.encode(ed_sig);
        if corrupt_ed {
            // Flip to a valid-length-but-wrong signature: sign a
            // DIFFERENT message so length is right but verify fails.
            let other = ed_sk.sign(b"not-the-registration-envelope").to_bytes();
            classical_b64 = B64.encode(other);
        }

        let now = chrono::Utc::now();
        let mut record = KeyRecord {
            key_id: key_id.to_owned(),
            pubkey_ed25519_base64: B64.encode(ed_pk),
            pubkey_ml_dsa_65_base64: Some(B64.encode(&mldsa_pk)),
            algorithm: algorithm::HYBRID.to_owned(),
            identity_type: identity_type.to_owned(),
            identity_ref: key_id.to_owned(),
            valid_from: now,
            valid_until: None,
            registration_envelope: envelope,
            original_content_hash,
            scrub_signature_classical: classical_b64,
            scrub_signature_pqc: if drop_pqc {
                None
            } else {
                Some(B64.encode(&pqc_sig))
            },
            scrub_key_id: key_id.to_owned(),
            scrub_timestamp: now,
            pqc_completed_at: if drop_pqc { None } else { Some(now) },
            persist_row_hash: String::new(),
            capability_roles: Vec::new(),
            attestation_evidence,
            consent_role: None,
            additional_scrubs: Vec::new(),
        };
        if drop_pqc {
            // A hybrid-pending row also drops the PQC pubkey.
            record.pubkey_ml_dsa_65_base64 = None;
        }
        if tamper {
            // Mutate the envelope AFTER signing — the signature now
            // covers a different envelope than the one stored. The
            // original_content_hash still matches the NEW envelope so
            // the hash-cross-check passes and the failure surfaces as
            // a signature mismatch (the stronger guard).
            record.registration_envelope = serde_json::json!({
                "key_id": key_id,
                "purpose": "TAMPERED",
            });
            let new_canonical =
                ceg_produce_canonicalize(&record.registration_envelope).expect("canonicalize");
            record.original_content_hash = hex::encode(Sha256::digest(&new_canonical));
        }
        record
    }

    /// #275 hardening — `validate_registration_pubkey` enforces the
    /// 32-byte Ed25519 invariant: accepts a real 32-byte key, rejects a
    /// 65-byte P-256 point, rejects non-base64. Backend-free unit coverage
    /// of the admission backstop (the matrix exercises it end-to-end on both
    /// backends via put_public_key).
    #[tokio::test]
    async fn validate_registration_pubkey_enforces_32_byte_ed25519() {
        let mut rec =
            signed_self_record("vrp-key", identity_type::AGENT, None, false, false, false).await;
        // Valid 32-byte Ed25519 (the builder uses a real key) — accepted.
        validate_registration_pubkey(&rec).expect("32-byte Ed25519 key must be accepted");

        // 65-byte uncompressed P-256 point — rejected, naming the invariant.
        rec.pubkey_ed25519_base64 = B64.encode([0x04u8; 65]);
        let err = validate_registration_pubkey(&rec).unwrap_err();
        assert_eq!(err.kind(), "federation_invalid_argument");
        assert!(
            format!("{err}").contains("32-byte"),
            "must name the invariant: {err}"
        );

        // Not valid base64 — rejected.
        rec.pubkey_ed25519_base64 = "!!! not base64 !!!".into();
        assert!(
            validate_registration_pubkey(&rec).is_err(),
            "non-base64 must be rejected"
        );
    }

    /// The full §5.6.8.15 admission-gate matrix, backend-agnostic.
    async fn run_register_matrix(engine: &Engine, run_tag: &str) {
        let directory = engine.federation_directory();

        // (a) valid hybrid-signed registration → ADMITTED + stored.
        let valid_id = format!("peer-valid-{run_tag}");
        let rec =
            signed_self_record(&valid_id, identity_type::AGENT, None, false, false, false).await;
        engine
            .register_federation_key(SignedKeyRecord { record: rec })
            .await
            .expect("(a) valid registration must be admitted");
        let read = directory
            .lookup_public_key(&valid_id)
            .await
            .expect("lookup");
        assert!(
            read.is_some(),
            "(a) admitted key must be readable via lookup_public_key"
        );

        // (a') #275 hardening — a row whose pubkey_ed25519_base64 is NOT a
        // 32-byte Ed25519 key (here a 65-byte P-256 point) is REJECTED at the
        // put_public_key write chokepoint, on BOTH backends, before any
        // INSERT. This is the admission backstop the #275 saga proved was
        // missing (a wrong-curve key was stored unchallenged and only failed
        // at read). Self-signed (scrub_key_id == key_id) so it reaches the
        // store path directly.
        let wrongcurve_id = format!("peer-wrongcurve-{run_tag}");
        let mut wrongcurve = signed_self_record(
            &wrongcurve_id,
            identity_type::AGENT,
            None,
            false,
            false,
            false,
        )
        .await;
        wrongcurve.pubkey_ed25519_base64 = B64.encode([0x04u8; 65]); // uncompressed P-256 point
        let err = directory
            .put_public_key(SignedKeyRecord { record: wrongcurve })
            .await
            .expect_err("(a') a non-32-byte pubkey must be rejected at put_public_key");
        assert_eq!(err.kind(), "federation_invalid_argument");
        assert!(
            format!("{err}").contains("32-byte"),
            "(a') rejection must name the 32-byte Ed25519 invariant: {err}"
        );
        assert!(
            directory
                .lookup_public_key(&wrongcurve_id)
                .await
                .expect("lookup")
                .is_none(),
            "(a') a rejected wrong-curve key must leave NO row"
        );

        // (b) bad/missing ML-DSA-65 (hybrid-pending under Strict) →
        // REJECTED, NOT stored. THE load-bearing fail-secure guard.
        let pending_id = format!("peer-pending-{run_tag}");
        let pending = signed_self_record(
            &pending_id,
            identity_type::AGENT,
            None,
            false,
            true, // drop_pqc
            false,
        )
        .await;
        let err = engine
            .register_federation_key(SignedKeyRecord { record: pending })
            .await
            .expect_err("(b) hybrid-pending registration must be rejected under Strict");
        assert_eq!(
            err.kind(),
            "federation_signature_invalid",
            "(b) rejection must be a signature/verification failure"
        );
        assert!(
            directory
                .lookup_public_key(&pending_id)
                .await
                .expect("lookup")
                .is_none(),
            "(b) rejected key must NOT be queryable (fail-secure: not stored)"
        );

        // (b') bad Ed25519 signature → REJECTED, NOT stored.
        let bad_ed_id = format!("peer-bad-ed-{run_tag}");
        let bad_ed = signed_self_record(
            &bad_ed_id,
            identity_type::AGENT,
            None,
            false,
            false,
            true, // corrupt_ed
        )
        .await;
        let err = engine
            .register_federation_key(SignedKeyRecord { record: bad_ed })
            .await
            .expect_err("(b') bad Ed25519 signature must be rejected");
        assert_eq!(err.kind(), "federation_signature_invalid");
        assert!(
            directory
                .lookup_public_key(&bad_ed_id)
                .await
                .expect("lookup")
                .is_none(),
            "(b') rejected key must NOT be queryable"
        );

        // (c) tampered registration_envelope (sig doesn't match) →
        // REJECTED.
        let tampered_id = format!("peer-tampered-{run_tag}");
        let tampered = signed_self_record(
            &tampered_id,
            identity_type::AGENT,
            None,
            true, // tamper
            false,
            false,
        )
        .await;
        let err = engine
            .register_federation_key(SignedKeyRecord { record: tampered })
            .await
            .expect_err("(c) tampered envelope must be rejected");
        assert_eq!(err.kind(), "federation_signature_invalid");
        assert!(
            directory
                .lookup_public_key(&tampered_id)
                .await
                .expect("lookup")
                .is_none(),
            "(c) tampered key must NOT be queryable"
        );

        // (d) §7 reserved-identity violation: accord_holder with NO
        // hardware attestation → REJECTED (existing accord-holder gate
        // in put_public_key is preserved — the registration is
        // hybrid-valid but the accord_holder gate refuses it).
        let accord_id = format!("peer-accord-{run_tag}");
        let accord = signed_self_record(
            &accord_id,
            identity_type::ACCORD_HOLDER,
            None, // no attestation_evidence
            false,
            false,
            false,
        )
        .await;
        engine
            .register_federation_key(SignedKeyRecord { record: accord })
            .await
            .expect_err("(d) accord_holder without hardware attestation must be rejected");
        assert!(
            directory
                .lookup_public_key(&accord_id)
                .await
                .expect("lookup")
                .is_none(),
            "(d) rejected accord_holder must NOT be queryable"
        );

        // (f) non-hybrid algorithm → REJECTED (existing check preserved;
        // caught by the registration gate's fail-fast).
        let nonhybrid_id = format!("peer-nonhybrid-{run_tag}");
        let mut nonhybrid = signed_self_record(
            &nonhybrid_id,
            identity_type::AGENT,
            None,
            false,
            false,
            false,
        )
        .await;
        nonhybrid.algorithm = "ed25519-only".to_owned();
        let err = engine
            .register_federation_key(SignedKeyRecord { record: nonhybrid })
            .await
            .expect_err("(f) non-hybrid algorithm must be rejected");
        assert_eq!(err.kind(), "federation_invalid_argument");
        assert!(
            directory
                .lookup_public_key(&nonhybrid_id)
                .await
                .expect("lookup")
                .is_none(),
            "(f) non-hybrid key must NOT be queryable"
        );

        // (e) deregister/expire → the key is no longer admit-valid. We
        // register a fresh peer then deregister it via a revocation;
        // a revocation row is then queryable for the key (the consumer
        // applies its policy on read and ceases admitting).
        let dereg_id = format!("peer-dereg-{run_tag}");
        let dereg =
            signed_self_record(&dereg_id, identity_type::AGENT, None, false, false, false).await;
        engine
            .register_federation_key(SignedKeyRecord {
                record: dereg.clone(),
            })
            .await
            .expect("(e) register the peer to be deregistered");
        // Build a self-signed revocation (revoking_key_id empty skips
        // the trust gate; scrub_key_id = the revoked key, self-revoke).
        let now = chrono::Utc::now();
        let rev_envelope = serde_json::json!({"revokes": dereg_id});
        let _rev_canonical = ceg_produce_canonicalize(&rev_envelope).expect("canonicalize");
        // v21.0.0 (#502 E1) — sign the revocation envelope with the
        // revoking key's registered hybrid key so admission verifies it.
        let (__rev_och, __rev_sc, __rev_sp) =
            crate::federation::tier_ingest::test_support::sign_envelope(&dereg_id, &rev_envelope);
        let revocation = crate::federation::Revocation {
            revocation_id: uuid::Uuid::new_v4().to_string(),
            revoked_key_id: dereg_id.clone(),
            revoking_key_id: dereg_id.clone(),
            reason: Some("consent:replication withdrawn".to_owned()),
            revoked_at: now,
            effective_at: now,
            revocation_envelope: rev_envelope.clone(),
            original_content_hash: __rev_och,
            scrub_signature_classical: __rev_sc,
            scrub_signature_pqc: __rev_sp,
            scrub_key_id: dereg_id.clone(),
            scrub_timestamp: now,
            pqc_completed_at: None,
            observed_region: crate::federation::verify_coord::region::US.to_owned(),
            persist_row_hash: String::new(),
        };
        engine
            .deregister_federation_key(crate::federation::SignedRevocation { revocation })
            .await
            .expect("(e) deregister must store the revocation");
        let revs = directory
            .revocations_for(&dereg_id)
            .await
            .expect("revocations_for");
        assert_eq!(
            revs.len(),
            1,
            "(e) deregistered key must carry a revocation the consumer honors on read"
        );
        assert_eq!(revs[0].revoked_key_id, dereg_id);
    }

    #[cfg(feature = "sqlite")]
    #[tokio::test]
    async fn register_matrix_sqlite() {
        let engine = Engine::with_signer(test_signer(), "sqlite::memory:")
            .await
            .expect("construct sqlite engine");
        run_register_matrix(&engine, "sqlite").await;
    }

    #[cfg(feature = "postgres")]
    #[tokio::test]
    async fn register_matrix_postgres() {
        let Ok(dsn) = std::env::var("CIRIS_PERSIST_TEST_PG_URL") else {
            eprintln!("skipping register_matrix_postgres: CIRIS_PERSIST_TEST_PG_URL unset");
            return;
        };
        let engine = Engine::with_signer(test_signer(), &dsn)
            .await
            .expect("construct postgres engine");
        // Run-scoped unique tag so parallel/repeat runs don't collide on
        // the federation_keys PK (key_id is TEXT; uuid-suffix it).
        let tag = format!("pg-{}", uuid::Uuid::new_v4().simple());
        run_register_matrix(&engine, &tag).await;
    }

    // ─── v12.7.0 (CIRISPersist#371) — apply_replicated_key_record ───
    //
    // The upgrade-aware replicated Key-plane apply decision table, run
    // identically against sqlite and (when CIRIS_PERSIST_TEST_PG_URL is
    // set) postgres through the Engine wrapper, mirroring
    // `run_register_matrix`. The ambiguous-owner (pre-gate anomaly) row
    // needs raw SQL and lives with the backend siblings
    // (`src/store/{sqlite,postgres}.rs`).

    /// Apply one replicated record through the Engine wrapper.
    async fn apply_one(engine: &Engine, record: KeyRecord) -> ReplicatedKeyOutcome {
        engine
            .apply_replicated_key_record(SignedKeyRecord { record })
            .await
            .expect("apply_replicated_key_record")
    }

    /// The `scrub_key_id` of `key_id`'s current directory row (the
    /// self-signed vs anchor-scrubbed discriminator the matrix asserts on).
    async fn row_scrub(engine: &Engine, key_id: &str) -> String {
        engine
            .federation_directory()
            .lookup_public_key(key_id)
            .await
            .expect("lookup")
            .expect("row exists")
            .scrub_key_id
    }

    /// The #371 decision table: fresh insert (self-signed AND
    /// anchor-scrubbed); idempotent re-apply; conflicting second version;
    /// unverifiable scrub; pubkey swap (Ed25519 AND ML-DSA-65 halves);
    /// absent owner; self→anchored upgrade happy path; anchored→self
    /// downgrade; anchor-A→anchor-B re-scrub; already-anchored-identical.
    ///
    /// v24.2.0 (CIRISPersist#565) — every refusal row now asserts the EXACT
    /// [`KeyRefusalReason`], not merely that something refused. That is the
    /// deliverable: a matrix that only checks "Refused" is precisely the
    /// instrument that let five distinct branches share one indistinguishable
    /// verdict all the way out to a production canonical.
    async fn run_apply_replicated_matrix(engine: &Engine, tag: &str) {
        use crate::federation::register::KeyRefusalReason as R;
        use crate::federation::register::ReplicatedKeyOutcome as O;
        use crate::federation::tier_ingest::test_support as ts;
        let directory = engine.federation_directory();
        let dir = directory.as_ref();

        let scrubber = format!("apply-anchor-a-{tag}");
        let scrubber_b = format!("apply-anchor-b-{tag}");
        let owner = format!("apply-owner-{tag}");
        let node = format!("apply-node-{tag}");
        // The scrubbers must exist as directory rows (the Strict gate
        // resolves a granting-authority signer's pubkeys from the
        // directory — the seeded accord-anchor shape) and the owner must
        // be a live `user`-role granter for `owner_of`.
        ts::register_hybrid_key(dir, &scrubber).await;
        ts::register_hybrid_key(dir, &scrubber_b).await;
        ts::register_identity_key(dir, &owner, identity_type::USER).await;

        // (1) fresh insert — new key_id, self-signed (the boot state).
        let self_rec = ts::replicated_key_record(&node, identity_type::NODE, &node, &node, "v1");
        assert_eq!(
            apply_one(engine, self_rec.clone()).await,
            O::Inserted,
            "(1) fresh insert"
        );

        // (2) byte-identical re-apply ⇒ Unchanged (idempotent).
        assert_eq!(
            apply_one(engine, self_rec.clone()).await,
            O::Unchanged,
            "(2) idempotent"
        );

        // (3) a conflicting second self-signed version ⇒ Refused
        // (first-seen/duplicity; put_public_key's direct path stays
        // untouched by this apply).
        let self_v2 = ts::replicated_key_record(&node, identity_type::NODE, &node, &node, "v2");
        assert_eq!(
            apply_one(engine, self_v2).await,
            O::Refused {
                reason: R::ConflictingVersion
            },
            "(3) conflicting version"
        );

        // (4) verifiable anchor-scrubbed record but NO owner-binding ⇒
        // Refused — the row is not inside any single-owner node set
        // (owner_of = None, fail-closed), so replication may not upgrade it.
        let scrubbed =
            ts::replicated_key_record(&node, identity_type::NODE, &scrubber, &scrubber, "v1");
        assert_eq!(
            apply_one(engine, scrubbed.clone()).await,
            O::Refused {
                reason: R::OwnerAbsent
            },
            "(4) absent owner"
        );
        assert_eq!(
            row_scrub(engine, &node).await,
            node,
            "(4) refused apply must leave the self-signed row untouched"
        );

        // Seed the owner-binding: delegates_to(owner → node) on the
        // ownership dimension (the v12.6.0 single-owner relation).
        directory
            .put_attestation(crate::federation::SignedAttestation {
                attestation: ts::owner_binding_attestation(
                    &uuid::Uuid::new_v4().to_string(),
                    &owner,
                    &node,
                ),
            })
            .await
            .expect("owner-binding admitted");

        // (5) unverifiable scrub — claims `scrubber`, signed by
        // `scrubber_b` ⇒ Refused (Strict gate), row untouched.
        let bad_sig =
            ts::replicated_key_record(&node, identity_type::NODE, &scrubber, &scrubber_b, "v1");
        assert_eq!(
            apply_one(engine, bad_sig).await,
            O::Refused {
                reason: R::UnverifiableSignature
            },
            "(5) unverifiable scrub"
        );
        assert_eq!(row_scrub(engine, &node).await, node, "(5) row untouched");

        // (6) pubkey swap ⇒ Refused — EITHER hybrid half. Never an
        // identity swap on the replication plane, whatever the scrub says.
        let (other_ed, other_mldsa) = ts::hybrid_pubkeys(&format!("someone-else-{tag}"));
        let mut ed_swap = scrubbed.clone();
        ed_swap.pubkey_ed25519_base64 = other_ed;
        assert_eq!(
            apply_one(engine, ed_swap).await,
            O::Refused {
                reason: R::PubkeySwap
            },
            "(6) Ed25519 swap"
        );
        let mut mldsa_swap = scrubbed.clone();
        mldsa_swap.pubkey_ml_dsa_65_base64 = other_mldsa;
        assert_eq!(
            apply_one(engine, mldsa_swap).await,
            O::Refused {
                reason: R::PubkeySwap
            },
            "(6) ML-DSA-65 swap"
        );
        assert_eq!(row_scrub(engine, &node).await, node, "(6) row untouched");

        // (7) the happy path: same key_id + same hybrid pubkeys, scrub
        // Strict-verifies against the directory-resolved scrubber, owner_of
        // resolves exactly one live owner ⇒ Upgraded (the #351 adopt path
        // riding replication).
        assert_eq!(
            apply_one(engine, scrubbed.clone()).await,
            O::Upgraded,
            "(7) upgrade"
        );
        assert_eq!(
            row_scrub(engine, &node).await,
            scrubber,
            "(7) row is now anchor-scrubbed"
        );

        // (8) re-apply of the exact anchored record ⇒ Unchanged.
        assert_eq!(
            apply_one(engine, scrubbed.clone()).await,
            O::Unchanged,
            "(8) idempotent anchored"
        );

        // (9) anchored→self downgrade ⇒ Refused (monotonic).
        assert_eq!(
            apply_one(engine, self_rec).await,
            O::Refused {
                reason: R::Downgrade
            },
            "(9) downgrade"
        );
        assert_eq!(
            row_scrub(engine, &node).await,
            scrubber,
            "(9) still anchored"
        );

        // (10) anchor-A→anchor-B re-scrub ⇒ Refused (duplicity/first-seen),
        // even though the record itself verifies.
        let rescrub =
            ts::replicated_key_record(&node, identity_type::NODE, &scrubber_b, &scrubber_b, "v1");
        assert_eq!(
            apply_one(engine, rescrub).await,
            O::Refused { reason: R::ReScrub },
            "(10) re-scrub hijack"
        );
        assert_eq!(
            row_scrub(engine, &node).await,
            scrubber,
            "(10) still anchor A"
        );

        // (11) fresh insert of an anchor-scrubbed record for an UNKNOWN
        // key_id ⇒ Inserted — new-key inserts are exactly put_public_key
        // "as today" (no owner gate on the insert path).
        let node2 = format!("apply-node2-{tag}");
        let fresh_scrubbed =
            ts::replicated_key_record(&node2, identity_type::NODE, &scrubber, &scrubber, "v1");
        assert_eq!(
            apply_one(engine, fresh_scrubbed).await,
            O::Inserted,
            "(11) fresh scrubbed insert"
        );
        assert_eq!(row_scrub(engine, &node2).await, scrubber);

        // (12) v24.2.0 (CIRISPersist#565) — the DUPLICATE, not a rejection.
        // Same anchoring the node already holds (identical
        // `registration_envelope`, identical `scrub_key_id`) but not
        // byte-identical: only the unsigned `valid_until` differs, so the
        // `persist_row_hash` fast-path misses and the record falls through to
        // the anchor→anchor arm. Before #565 this reported as a re-scrub
        // hijack — the shape a baked-seed fleet produces every time the
        // canonical replicates the record every node already ships.
        let mut same_anchoring = scrubbed.clone();
        same_anchoring.valid_until = Some("2030-01-01T00:00:00Z".parse().expect("valid_until"));
        assert_eq!(
            apply_one(engine, same_anchoring).await,
            O::Refused {
                reason: R::AlreadyAnchoredIdentical
            },
            "(12) already anchored to this exact assertion"
        );
        assert_eq!(
            row_scrub(engine, &node).await,
            scrubber,
            "(12) duplicate leaves the row untouched"
        );
    }

    /// v24.2.0 (CIRISPersist#565) — the two spellings of a reason are ONE
    /// spelling.
    ///
    /// [`KeyRefusalReason::as_str`] is the token a Rust consumer keys on; the
    /// serde token is what a consumer across the FFI capsule sees. #565's whole
    /// point is that a consumer never has to parse a message — so if these two
    /// could drift, the guarantee would be worth nothing to whichever half read
    /// the other spelling. Asserted over [`KeyRefusalReason::ALL`], so a NEW
    /// variant is covered the moment it is declared rather than the moment
    /// someone remembers to extend a list.
    #[test]
    fn refusal_reason_tokens_match_serde() {
        for reason in KeyRefusalReason::ALL {
            let json = serde_json::to_string(reason).expect("serialize reason");
            assert_eq!(
                json,
                format!("\"{}\"", reason.as_str()),
                "as_str() and the serde token must be the same program constant"
            );
            let back: KeyRefusalReason = serde_json::from_str(&json).expect("round-trip");
            assert_eq!(back, *reason);
            assert_eq!(reason.to_string(), reason.as_str(), "Display == as_str");
        }
        // The set is CLOSED and complete: a variant added without extending
        // ALL would be invisible to every gate keyed on it.
        let distinct: std::collections::BTreeSet<&str> =
            KeyRefusalReason::ALL.iter().map(|r| r.as_str()).collect();
        assert_eq!(
            distinct.len(),
            KeyRefusalReason::ALL.len(),
            "reason tokens must be distinct"
        );
    }

    /// v24.2.0 (CIRISPersist#565) — the OUTCOME's wire shape, pinned.
    ///
    /// `Refused` carries `{"refused":{"reason":"<token>"}}` — the same
    /// externally-tagged struct-variant shape the sibling route plane's
    /// `TransportDestinationApplyOutcome::Refused { reason }` already puts
    /// across the directory capsule, so a downstream deserializer meets a
    /// shape it already implements. The non-refusal variants keep their bare
    /// snake_case tokens exactly as before.
    #[test]
    fn replicated_key_outcome_wire_shape_is_pinned() {
        assert_eq!(
            serde_json::to_string(&ReplicatedKeyOutcome::Inserted).expect("inserted"),
            "\"inserted\""
        );
        assert_eq!(
            serde_json::to_string(&ReplicatedKeyOutcome::Unchanged).expect("unchanged"),
            "\"unchanged\""
        );
        assert_eq!(
            serde_json::to_string(&ReplicatedKeyOutcome::Superseded).expect("superseded"),
            "\"superseded\""
        );
        for reason in KeyRefusalReason::ALL {
            let outcome = ReplicatedKeyOutcome::Refused { reason: *reason };
            let json = serde_json::to_string(&outcome).expect("serialize outcome");
            assert_eq!(
                json,
                format!("{{\"refused\":{{\"reason\":\"{}\"}}}}", reason.as_str())
            );
            assert_eq!(
                serde_json::from_str::<ReplicatedKeyOutcome>(&json).expect("round-trip"),
                outcome
            );
        }
    }

    /// v24.2.0 (CIRISPersist#565) — **THE PRODUCTION CASE, on the REAL baked
    /// seed**: re-offering the canonical record every node already ships reads
    /// `AlreadyAnchoredIdentical`, NOT a re-scrub hijack and NOT `Unchanged`.
    ///
    /// This is the one #565 was actually filed about, and it is asserted
    /// against the vendored production `canonical_seed.json` through the real
    /// genesis boot — no fixture, because a fixture is exactly what would have
    /// let this stay wrong (the #545/#554 lesson: evidence written to pass your
    /// own gate proves nothing).
    ///
    /// **Why it is not `Unchanged`.** `lift_envelope_attested_roles` runs at
    /// write time (`put_public_key` / `adopt_scrub_upgrade`) and lifts the
    /// envelope's attested roles into the STORED row's `capability_roles`
    /// before `persist_row_hash` is computed. The pristine seed record on the
    /// wire carries them only inside the envelope. So the stored row and the
    /// record it was built from hash DIFFERENTLY, the byte-identical fast path
    /// misses, and the record falls through to the anchor→anchor arm — while
    /// `original_content_hash` (over the envelope) is unchanged, which is
    /// precisely the reported symptom: many refusals of a SINGLE content hash.
    ///
    /// The verdict is correct and unchanged (not applied, row untouched); what
    /// #565 fixes is that it used to report as duplicity. `genesis::
    /// seed_canonical_servers` walks this exact path on every boot after the
    /// first, so a fleet running the baked seed logged a hijack-shaped warning
    /// forever, benignly.
    async fn baked_seed_reoffer_reads_as_duplicate(engine: &Engine) {
        let sr = crate::federation::genesis::canonical_genesis_bundle().serve_nodes[0].clone();
        let dir = engine.federation_directory();
        let existing = dir
            .lookup_public_key(&sr.record.key_id)
            .await
            .expect("lookup")
            .expect("the baked canonical row is present after the genesis seed");

        // The precondition that makes this the interesting case rather than a
        // trivial one: the SIGNED assertion is identical, the row bytes are not.
        assert_eq!(
            existing.registration_envelope, sr.record.registration_envelope,
            "same signed envelope"
        );
        assert_eq!(existing.scrub_key_id, sr.record.scrub_key_id, "same anchor");
        assert_eq!(
            existing.original_content_hash, sr.record.original_content_hash,
            "same content hash — the very thing the refusals were reported against"
        );
        assert_ne!(
            existing.persist_row_hash,
            super::super::types::compute_persist_row_hash(&sr.record).expect("row hash"),
            "row bytes DIFFER (the write-time role lift), so `Unchanged` cannot catch this"
        );

        assert_eq!(
            engine
                .apply_replicated_key_record(sr.clone())
                .await
                .expect("apply"),
            ReplicatedKeyOutcome::Refused {
                reason: KeyRefusalReason::AlreadyAnchoredIdentical
            },
            "the canonical's own baked record must read as a DUPLICATE, not a re-scrub hijack"
        );
    }

    #[cfg(feature = "sqlite")]
    #[tokio::test]
    async fn baked_seed_reoffer_reads_as_duplicate_sqlite() {
        let engine = Engine::with_signer(test_signer(), "sqlite::memory:")
            .await
            .expect("construct sqlite engine");
        baked_seed_reoffer_reads_as_duplicate(&engine).await;
    }

    #[cfg(feature = "postgres")]
    #[tokio::test]
    async fn baked_seed_reoffer_reads_as_duplicate_postgres() {
        let Ok(dsn) = std::env::var("CIRIS_PERSIST_TEST_PG_URL") else {
            eprintln!("skipping baked_seed_reoffer_reads_as_duplicate_postgres: DSN unset");
            return;
        };
        let engine = Engine::with_signer(test_signer(), &dsn)
            .await
            .expect("construct postgres engine");
        baked_seed_reoffer_reads_as_duplicate(&engine).await;
    }

    #[cfg(feature = "sqlite")]
    #[tokio::test]
    async fn apply_replicated_matrix_sqlite() {
        let engine = Engine::with_signer(test_signer(), "sqlite::memory:")
            .await
            .expect("construct sqlite engine");
        run_apply_replicated_matrix(&engine, "sqlite").await;
    }

    #[cfg(feature = "postgres")]
    #[tokio::test]
    async fn apply_replicated_matrix_postgres() {
        let Ok(dsn) = std::env::var("CIRIS_PERSIST_TEST_PG_URL") else {
            eprintln!("skipping apply_replicated_matrix_postgres: CIRIS_PERSIST_TEST_PG_URL unset");
            return;
        };
        let engine = Engine::with_signer(test_signer(), &dsn)
            .await
            .expect("construct postgres engine");
        let tag = format!("pg-{}", uuid::Uuid::new_v4().simple());
        run_apply_replicated_matrix(&engine, &tag).await;
    }
}

/// v13.7.0 (CIRISPersist#405) — adversarial unit tests for [`supersede_precheck`],
/// the quorum-independent security half of the canonical-supersede policy
/// (canonical-scope + strictly-newer SIGNED-envelope `valid_from`). Crypto-free
/// so the monotonicity / replay-spoof / scope decisions are proven in isolation.
#[cfg(all(test, any(feature = "postgres", feature = "sqlite")))]
mod supersede_precheck_tests {
    use super::supersede_precheck;
    use crate::federation::types::{algorithm, KeyRecord};

    const T0: &str = "2026-07-10T00:00:00+00:00";
    const T1: &str = "2026-07-11T00:00:00+00:00"; // strictly newer than T0

    /// Build a KeyRecord whose only meaningful fields for the precheck are the
    /// `identity_type` and the ENVELOPE `valid_from`. `top_valid_from` sets the
    /// UNSIGNED top-level field independently (for the spoof test).
    fn mk(
        identity_type: &str,
        envelope_vf: &str,
        top_valid_from: chrono::DateTime<chrono::Utc>,
    ) -> KeyRecord {
        KeyRecord {
            key_id: "ciris-canonical-1".to_owned(),
            pubkey_ed25519_base64: "AA".to_owned(),
            pubkey_ml_dsa_65_base64: None,
            algorithm: algorithm::HYBRID.to_owned(),
            identity_type: identity_type.to_owned(),
            identity_ref: "ciris-canonical-1".to_owned(),
            valid_from: top_valid_from,
            valid_until: None,
            registration_envelope: serde_json::json!({ "valid_from": envelope_vf }),
            original_content_hash: String::new(),
            scrub_signature_classical: "AA".to_owned(),
            scrub_signature_pqc: None,
            scrub_key_id: "A1".to_owned(),
            scrub_timestamp: chrono::Utc::now(),
            pqc_completed_at: None,
            persist_row_hash: String::new(),
            capability_roles: Vec::new(),
            attestation_evidence: None,
            consent_role: None,
            additional_scrubs: Vec::new(),
        }
    }
    fn canonical(envelope_vf: &str) -> KeyRecord {
        mk("canonical,node", envelope_vf, chrono::Utc::now())
    }

    #[test]
    fn newer_canonical_envelope_passes() {
        assert!(supersede_precheck(&canonical(T0), &canonical(T1)));
    }

    #[test]
    fn equal_envelope_valid_from_refused() {
        assert!(!supersede_precheck(&canonical(T0), &canonical(T0)));
    }

    #[test]
    fn older_envelope_valid_from_refused() {
        // incoming T0 is OLDER than existing T1 — downgrade refused.
        assert!(!supersede_precheck(&canonical(T1), &canonical(T0)));
    }

    #[test]
    fn non_canonical_incoming_refused_even_if_newer() {
        // A non-canonical anchor→anchor re-scrub must NOT reach the quorum.
        let incoming = mk("node", T1, chrono::Utc::now());
        assert!(!supersede_precheck(&canonical(T0), &incoming));
    }

    #[test]
    fn missing_envelope_valid_from_refused() {
        let mut incoming = canonical(T1);
        incoming.registration_envelope = serde_json::json!({});
        assert!(!supersede_precheck(&canonical(T0), &incoming));
    }

    /// THE downgrade attack: replay the OLD record (envelope `valid_from` == the
    /// stored one) but bump the UNSIGNED top-level `valid_from` far into the
    /// future. The precheck reads the SIGNED envelope timestamp, so recency
    /// cannot be forged — refused.
    #[test]
    fn toplevel_valid_from_spoof_cannot_forge_recency() {
        let existing = canonical(T0);
        let spoof = mk(
            "canonical,node",
            T0,
            chrono::Utc::now() + chrono::Duration::days(3650),
        );
        assert!(
            !supersede_precheck(&existing, &spoof),
            "unsigned top-level valid_from must not override the signed envelope timestamp"
        );
    }
}
