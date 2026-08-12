//! v31.0.0 (CIRISPersist#650) — **the in-place v31 migration**: re-stamp the
//! FINAL FOLDED CEG state from the owner root, then purge what is provably
//! dead.
//!
//! # Why this exists
//!
//! v31.0.0 changed the shape of a signed envelope twice in one break window.
//! CIRISPersist#643 bound seven typed columns into the envelope under
//! [`paths::ROW`](super::envelope::paths::ROW); CIRISPersist#598 bound
//! `asserted_at` / `expires_at` as signed twins at the envelope root. Both
//! gates are tier-blind and neither has a legacy regime, so **every row this
//! substrate wrote before v31 is refused by its own put doors** — and by every
//! peer's. Without a migration, an upgrade is a corpus that can neither be
//! re-served nor re-admitted.
//!
//! The operator's frame: *"this will let us re-seed in place and push changes
//! by simply rolling a new persist out … should be 100% automatable inside
//! persist, consumers should never know."*
//!
//! # The asymmetry that makes it automatable
//!
//! Persist holds the keys for the rows it AUTHORED, and holds no peer key. So
//! the routine **re-stamps what it can author and discards what it merely
//! holds** — the discarded half comes back through the replication plane in
//! v31 shape, signed by the peer that owns it. No consumer coordinates
//! anything.
//!
//! # THE FINAL STATE, NEVER THE INTERIM STATES
//!
//! The CEG is a graph in which later rows supersede, withdraw and recant
//! earlier ones. **Replaying history would re-mint rows that were already
//! retracted — resurrecting withdrawn claims, which is the worst outcome this
//! routine can have.** A withdrawn `consent:replication:v1` grant coming back
//! to life is the concrete harm: it re-authorizes a peer the subject revoked.
//!
//! So the routine folds first ([`fold_retractions`], the SAME rule the
//! `LifecycleView::Live` read applies) and only then decides. Everything
//! retracted on the way to the current truth stays dead, and the TOMBSTONE
//! that killed it is retained unconditionally — because purging a tombstone is
//! the other way a retracted row comes back, one round of anti-entropy later.
//!
//! # The fail-secure direction, and it is the OPPOSITE of the usual one
//!
//! [`LoadBearing::treated_as_load_bearing`] is *"`Yes` AND `Unknown` are both
//! treated as load bearing. Only a proven `No` is not."* For a PURGE that
//! polarity is exactly right and is preserved verbatim: **do not delete what
//! you cannot prove is dead.** `Unknown` ⇒ keep. Purging on `Unknown` deletes
//! user data on an inconclusive predicate and is unrecoverable; keeping on
//! `Unknown` re-stamps something that did not need it, which is free.
//!
//! Every arm of [`classify`] states which side it falls on. If a future edit
//! puts `Unknown` on the deleting side, that arm is wrong.
//!
//! # THE OLD-KEYS QUESTION — exclusion is NOT structural
//!
//! #650 asks what excludes previously-slashed or leaked keys after
//! purge-and-refill, and whether it is structural. **It is not.** Three facts,
//! each read off the code:
//!
//! 1. A fresh trust root excludes nothing. `put_public_key` proves key CUSTODY
//!    (a self-signed hybrid proof-of-possession) and consults no revocation,
//!    quarantine or de-admission state on any backend; the trust root is
//!    consulted only for PRIVILEGED ROLE claims
//!    ([`ROOT_REQUIRING_GATES`](super::genesis::ROOT_REQUIRING_GATES)), never
//!    for a key's right to exist. Trust roots also CO-EXIST — a new ceremony
//!    ADDS one — so a re-seed re-establishes who may confer privilege, not who
//!    exists.
//! 2. `federation_revocations` has **no replication serve cursor at all**
//!    (there is no `list_signed_revocations_since`; the key-level revocation
//!    plane is explicitly out of CIRISPersist#507's scope). Purge it and
//!    anti-entropy cannot refill it — the exclusion is gone permanently.
//! 3. The exclusions that DO live in `federation_attestations` — peer
//!    de-admission ([`PEER_DEADMISSION_DIMENSION`]), quarantine markers,
//!    moderation / reconsideration / slashing / objection reports, and the
//!    `delegates_to` plane that AUTHORIZES all of them — are ordinary rows a
//!    naive purge would take with everything else. Their refill is
//!    order-dependent (a quarantine marker is re-admissible only after the
//!    `slash` delegation chain it hangs off is back), so "anti-entropy will
//!    sort it out" is not a property this substrate has.
//!
//! **Therefore preserving them is a REQUIRED step and this routine does it
//! explicitly**, by name, as [`is_exclusion_bearing`]: an exclusion-bearing row
//! is NEVER purged. If it can be re-authored it is re-stamped; if it cannot it
//! is [`Disposition::RetainInert`] — kept in v30 shape, unusable on the wire
//! but still read by the folds that enforce it (`check_peer_deadmission` and
//! [`resolve_quarantine`](super::quarantine::resolve_quarantine) read STORED
//! rows and do not re-verify the envelope binding). An exclusion that cannot be
//! refreshed still excludes; an exclusion that was deleted excludes nothing.
//!
//! This routine touches exactly ONE table, `federation_attestations`. Every
//! dedicated exclusion table — `federation_revocations`,
//! `federation_revocation_quorum_state`, `canonical_role_withdrawal`,
//! `federation_role_withdrawals`, `blackhole_rules` — is out of its reach by
//! construction, which is the property
//! [`test_support::exercise_v31_migration`] asserts rather than assumes.
//!
//! # Idempotence and interruption
//!
//! There is no global transaction and no completion marker, deliberately. The
//! disposition of a row is a function of the row's CURRENT shape and the
//! CURRENT fold, so:
//!
//! - A second run finds every re-stamped row already conformant
//!   ([`Disposition::AlreadyConformant`]) and every purged row absent. It is a
//!   no-op that reports zero work.
//! - An interruption leaves some rows migrated and some not — which is exactly
//!   the input this routine is built to consume. The next run completes it.
//! - The fold is STABLE under partial application: purging a retracted row
//!   removes a target, never a composer, so the retracted set on the next run
//!   is a subset of this one and no row's disposition flips. That property is
//!   what makes "run it again" safe, and it rests on the composer-retention
//!   invariant above.
//!
//! Each row's write is a single-row statement, so a crash mid-run cannot leave
//! a row half-sealed.
//!
//! [`PEER_DEADMISSION_DIMENSION`]: super::admission::PEER_DEADMISSION_DIMENSION

use std::collections::{BTreeMap, BTreeSet};

use serde::{Deserialize, Serialize};

use super::load_bearing::{
    is_load_bearing, load_bearing_closure, ClosureCompleteness, LoadBearing, LoadBearingClosure,
    ObjectRef, DEFAULT_CLOSURE_BUDGET,
};
use super::types::{attestation_tier, attestation_type, Attestation};
use super::{Error, FederationDirectory};

/// The page size the corpus walk uses. Bounded so a large corpus is streamed
/// rather than materialized; large enough that a normal node is one or two
/// pages.
pub const MIGRATION_PAGE_SIZE: u32 = 500;

/// A hard cap on how many rows one run will visit. A migration that would
/// exceed it reports [`MigrationOutcome::budget_exhausted`] and stops — and
/// because the routine is idempotent and resumable, the NEXT boot continues
/// from where it left off rather than starting over.
pub const MIGRATION_ROW_BUDGET: usize = 200_000;

// ─────────────────────────────────────────────────────────────────────────
// The fold — the FINAL state, never the interim states.
// ─────────────────────────────────────────────────────────────────────────

/// Which rows a live structural composer has retracted, and which rows ARE
/// those composers.
///
/// # The rule is the read plane's rule
///
/// A row is retracted iff some `supersedes` / `withdraws` / `recants` row
/// **from the SAME `attesting_key_id`** carries it in
/// `references_attestation_id`. That is verbatim what every backend's
/// `list_scores` does for [`LifecycleView::Live`](crate::read::LifecycleView),
/// expressed over the whole corpus instead of one page.
///
/// It is re-expressed here rather than delegated to `list_scores` for three
/// reasons, all of which would make the read a wrong answer at boot: that read
/// is SCOPE-GATED on a caller occurrence (a migration has no caller and must
/// see rows no consumer may), it is PAGINATED newest-first (a fold must be
/// total), and it is TIER-FILTERED by the filter's default. The RULE itself is
/// not duplicated — [`super::precedence::is_structural_composer`] and
/// [`super::precedence::references_attestation_id_from_envelope`] are the
/// shared definitions, and [`super::precedence::precedence_winner`] names the
/// authority.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct RetractionFold {
    /// `retracted attestation_id` → the `attestation_id` of the CEG §6.1
    /// precedence-winning composer that retracted it.
    retracted: BTreeMap<String, String>,
    /// Every live structural composer's `attestation_id`. **Never purged** —
    /// see [`is_exclusion_bearing`].
    composers: BTreeSet<String>,
}

impl RetractionFold {
    /// Is `attestation_id` retracted in the current folded state?
    #[must_use]
    pub fn is_retracted(&self, attestation_id: &str) -> bool {
        self.retracted.contains_key(attestation_id)
    }

    /// The composer that retracted `attestation_id`, if any.
    #[must_use]
    pub fn retracted_by(&self, attestation_id: &str) -> Option<&str> {
        self.retracted.get(attestation_id).map(String::as_str)
    }

    /// Is `attestation_id` itself a structural composer?
    #[must_use]
    pub fn is_composer(&self, attestation_id: &str) -> bool {
        self.composers.contains(attestation_id)
    }

    /// How many rows the fold retracts.
    #[must_use]
    pub fn retracted_count(&self) -> usize {
        self.retracted.len()
    }
}

/// Fold `rows` (the WHOLE corpus) to the current truth.
///
/// **This is the function the resurrection witness mutates.** Feed it the
/// interim states instead of the final one — i.e. stop treating a retracted row
/// as retracted — and a withdrawn `consent:replication:v1` grant is re-stamped
/// into a valid, freshly-signed v31 row that this node will serve and a peer
/// will accept. That is resurrection, and
/// [`test_support::exercise_v31_migration`]'s witness reds on it.
#[must_use]
pub fn fold_retractions(rows: &[Attestation]) -> RetractionFold {
    use super::precedence::{
        is_structural_composer, precedence_winner, references_attestation_id_from_envelope,
    };

    // Group composers by (attester, target). CEG §6.1 rule 4: cross-attester
    // chains are INDEPENDENT, so each group resolves its own winner.
    let mut groups: BTreeMap<(&str, &str), Vec<&Attestation>> = BTreeMap::new();
    let mut composers: BTreeSet<String> = BTreeSet::new();
    for row in rows {
        if !is_structural_composer(&row.attestation_type) {
            continue;
        }
        composers.insert(row.attestation_id.clone());
        let Some(target) = references_attestation_id_from_envelope(&row.attestation_envelope)
        else {
            // A composer with no target retracts nothing (it fails its own
            // §3.2 schema). It is still a composer and is still retained.
            continue;
        };
        groups
            .entry((row.attesting_key_id.as_str(), target))
            .or_default()
            .push(row);
    }

    let mut retracted: BTreeMap<String, String> = BTreeMap::new();
    for ((_attester, target), group) in groups {
        // All three composer kinds HIDE under `LifecycleView::Live`, so the
        // §6.1 winner does not change WHETHER the target is retracted — only
        // WHICH composer is the authority, which is what the report names.
        let Some(winner) = precedence_winner(&group) else {
            continue;
        };
        // A composer that targets a row from a DIFFERENT attester is a
        // cross-attester chain; the read plane's Live filter requires
        // same-attester, and so does this. Enforced by the grouping key: the
        // group's attester is the composer's, and we only retract a target
        // that is in fact authored by that same key. Rows not present in the
        // corpus are ignored (nothing here to retract).
        let Some(target_row) = rows.iter().find(|r| r.attestation_id == target) else {
            continue;
        };
        if target_row.attesting_key_id != winner.attesting_key_id {
            continue;
        }
        retracted.insert(target.to_owned(), winner.attestation_id.clone());
    }

    RetractionFold {
        retracted,
        composers,
    }
}

// ─────────────────────────────────────────────────────────────────────────
// Shape, authorship, exclusion.
// ─────────────────────────────────────────────────────────────────────────

/// Whether a stored row already satisfies the v31 put doors.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum RowShape {
    /// Both v31 bindings hold. Nothing to do — this is what makes a second run
    /// a no-op.
    V31Conformant,
    /// One of the two bindings is missing or divergent. `why` is the gate's own
    /// refusal message, carried so the report says which binding failed rather
    /// than "legacy".
    Legacy {
        /// The refusal text from [`check_row_column_binding`] or
        /// [`check_instant_binding`].
        ///
        /// [`check_row_column_binding`]: super::admission::check_row_column_binding
        /// [`check_instant_binding`]: super::admission::check_instant_binding
        why: String,
    },
}

impl RowShape {
    /// `true` for [`Self::V31Conformant`].
    #[must_use]
    pub const fn is_conformant(&self) -> bool {
        matches!(self, Self::V31Conformant)
    }
}

/// Classify a stored row against the two v31 binding gates.
///
/// Asks the REAL gates ([`super::admission::check_row_column_binding`] and
/// [`super::admission::check_instant_binding`]) rather than probing for the
/// envelope keys, so "conformant" here means exactly "admissible at a peer's
/// put door" and cannot drift from it. `now` is threaded so the skew arm is
/// deterministic in a witness.
#[must_use]
pub fn classify_shape(row: &Attestation, now: chrono::DateTime<chrono::Utc>) -> RowShape {
    if let Err(e) =
        super::admission::check_instant_binding(row, now, super::admission::DEFAULT_MAX_TOUCH_SKEW)
    {
        return RowShape::Legacy { why: e.to_string() };
    }
    if let Err(e) = super::admission::check_row_column_binding(row) {
        return RowShape::Legacy { why: e.to_string() };
    }
    RowShape::V31Conformant
}

/// Can THIS node produce valid v31 bytes for this row?
///
/// The whole migration turns on this question, and it is NOT "is the row ours
/// by tier" — a local-tier row can carry a signature that is not ours (a
/// subject-side revocation in TRANSIT, whose caller hybrid-signed the envelope;
/// see the transit exclusion on
/// [`RowMirror::stamp_local_row`](super::envelope::RowMirror::stamp_local_row)).
/// Re-stamping those bytes would rewrite an envelope someone else signed and
/// leave a stored hash and signature covering an envelope that no longer
/// exists — the #649 defect, one door over.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Authorship {
    /// A durable local-tier row with the DEFERRED empty-sentinel scrub
    /// envelope (`scrub_signature_classical == ""`). There is no signature to
    /// invalidate and no hash derived from the bytes, so the bytes are
    /// persist's to write — exactly the argument
    /// [`RowMirror::stamp_local_row`](super::envelope::RowMirror::stamp_local_row)
    /// makes for stamping at the local write door.
    UnsealedLocal,
    /// `attesting_key_id` is this node's own derived federation key id, so this
    /// node holds the key the row's signature must verify under.
    OwnKey,
    /// Someone else signed these bytes. Persist cannot re-sign, and does not
    /// need to: a federation-tier row's author is its source.
    Foreign {
        /// Which key signed it, for the report.
        attesting_key_id: String,
    },
}

impl Authorship {
    /// `true` when this node may rewrite the row's signed bytes.
    #[must_use]
    pub const fn can_reauthor(&self) -> bool {
        matches!(self, Self::UnsealedLocal | Self::OwnKey)
    }
}

/// Resolve [`Authorship`] for `row` given this node's derived key id.
///
/// `self_key_id = None` (a node with no resolvable identity) makes every
/// signed row [`Authorship::Foreign`], which is the fail-secure reading: a node
/// that cannot say who it is must not claim authorship of anything.
#[must_use]
pub fn classify_authorship(row: &Attestation, self_key_id: Option<&str>) -> Authorship {
    if row.tier == attestation_tier::LOCAL && row.scrub_signature_classical.is_empty() {
        return Authorship::UnsealedLocal;
    }
    if let Some(me) = self_key_id {
        if row.attesting_key_id == me {
            return Authorship::OwnKey;
        }
    }
    Authorship::Foreign {
        attesting_key_id: row.attesting_key_id.clone(),
    }
}

/// **The rows that carry an EXCLUSION — never purged, by name.**
///
/// See the module doc: exclusion of a previously slashed / leaked / de-admitted
/// key is not structural, does not come from the trust root, and for the rows
/// that live in `federation_attestations` it depends on those rows surviving.
/// Returns `Some(reason)` for the classes whose deletion would re-admit exactly
/// what a reset is meant to remove:
///
/// - **structural composers** (`withdraws` / `supersedes` / `recants`) — the
///   tombstones. Purging one resurrects everything it retracted, which is the
///   single worst outcome this routine can have.
/// - **peer de-admission** rows ([`PEER_DEADMISSION_DIMENSION`]) — AV-77's
///   whole defence, folded from rows THIS node authored.
/// - **quarantine** markers — withhold/release, folded by
///   [`resolve_quarantine`](super::quarantine::resolve_quarantine).
/// - **moderation / reconsideration / slashing / objection** reports — the
///   §11.10 duty plane.
/// - **every `delegates_to` row** — the plane that AUTHORIZES all of the above
///   (a quarantine marker is inadmissible without its `slash` chain), and the
///   plane the OWNER CLAIM itself lives on. Broad on purpose: retaining a
///   delegation that turned out not to matter costs a stored row; dropping one
///   that did costs the authority of every act hanging off it.
///
/// A retracted exclusion-bearing row stays retained too — the fold already
/// hides it from every read, so retention is inert, while deletion would be
/// irreversible on a class whose refill is order-dependent and, for
/// `federation_revocations`, impossible.
///
/// [`PEER_DEADMISSION_DIMENSION`]: super::admission::PEER_DEADMISSION_DIMENSION
#[must_use]
pub fn is_exclusion_bearing(row: &Attestation) -> Option<&'static str> {
    use super::admission::{
        MODERATION_DIMENSION_PREFIX, PEER_DEADMISSION_DIMENSION, QUARANTINE_DIMENSION_PREFIX,
        RECONSIDERATION_DIMENSION_PREFIX,
    };
    if super::precedence::is_structural_composer(&row.attestation_type) {
        return Some(
            "a structural composer is a TOMBSTONE: purging it resurrects everything it retracted",
        );
    }
    if row.attestation_type == attestation_type::DELEGATES_TO {
        return Some(
            "the delegation plane AUTHORIZES quarantine / moderation / slashing acts and carries \
             the owner claim; without it those acts are inadmissible on refill",
        );
    }
    let dimension = super::admission::envelope_dimension(&row.attestation_envelope)?;
    if dimension == PEER_DEADMISSION_DIMENSION {
        return Some("a peer de-admission row is AV-77's entire defence against a sanctioned peer");
    }
    if dimension.starts_with(QUARANTINE_DIMENSION_PREFIX) {
        return Some("a quarantine marker withholds a key's rows from serving");
    }
    if dimension.starts_with(MODERATION_DIMENSION_PREFIX)
        || dimension.starts_with(RECONSIDERATION_DIMENSION_PREFIX)
    {
        return Some("a §11.10 moderation / reconsideration report");
    }
    if dimension.starts_with("slashing:") || dimension.starts_with("objection:") {
        return Some("a slashing outcome / reverse-quorum objection");
    }
    None
}

// ─────────────────────────────────────────────────────────────────────────
// The disposition.
// ─────────────────────────────────────────────────────────────────────────

/// Why a row is being purged. Both arms are PROOFS, never inferences.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum PurgeReason {
    /// A live structural composer from the row's OWN attester retracts it. The
    /// strongest `No` there is — the author said so — and independent of the
    /// reachability walk, which is why it is not gated on closure
    /// completeness.
    Retracted {
        /// The composer that retracted it.
        by: String,
    },
    /// Legacy shape, not ours to re-author, federation tier. Unusable at every
    /// door AND — because `put_attestation` inserts on a primary key — it
    /// BLOCKS its own v31 replacement from landing. Its author is its source;
    /// the replication plane refills it.
    UnauthorableLegacy {
        /// Who signed it.
        attesting_key_id: String,
    },
    /// Ours, legacy, FEDERATION-tier, and PROVABLY inert: [`LoadBearing::No`]
    /// and outside a COMPLETE owner closure. The CIRISPersist#563 shape — a
    /// `consent:replication` grant that reduces to nothing here.
    ///
    /// Four conjuncts, deliberately: on a truncated walk, on a local-tier row
    /// (which the walk structurally cannot see), or on anything but a proven
    /// `No`, this arm is unreachable and the row is re-stamped instead. It is
    /// the ONLY licence in this routine to delete a row of ours that nobody has
    /// retracted, and it is meant to be hard to obtain.
    ProvablyInert,
}

/// What the migration will do with one row.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Disposition {
    /// Already v31-shaped. Untouched — the idempotence arm.
    AlreadyConformant,
    /// Legacy, ours, and load-bearing (or unprovably so). Re-stamped in place
    /// under its EXISTING `attestation_id`.
    Restamp,
    /// Legacy and NOT ours to re-author, but too dangerous to delete. Kept in
    /// v30 shape. Reported loudly, never silently.
    RetainInert {
        /// Why deletion was refused.
        why: String,
    },
    /// Deleted.
    Purge(PurgeReason),
}

impl Disposition {
    /// The stable program token, for reports and metrics.
    #[must_use]
    pub const fn as_str(&self) -> &'static str {
        match self {
            Self::AlreadyConformant => "already_conformant",
            Self::Restamp => "restamp",
            Self::RetainInert { .. } => "retain_inert",
            Self::Purge(PurgeReason::Retracted { .. }) => "purge_retracted",
            Self::Purge(PurgeReason::UnauthorableLegacy { .. }) => "purge_unauthorable_legacy",
            Self::Purge(PurgeReason::ProvablyInert) => "purge_provably_inert",
        }
    }

    /// `true` for any purging arm.
    #[must_use]
    pub const fn is_purge(&self) -> bool {
        matches!(self, Self::Purge(_))
    }
}

/// **The decision, as ONE pure function.** Everything above it is evidence
/// gathering; everything below it is execution. Pure so the whole matrix —
/// including the arms a live database makes awkward to reach — is exercisable
/// without a backend.
///
/// The arms, in order, each naming its fail-secure side:
///
/// 1. **Exclusion-bearing ⇒ NEVER purge.** Ahead of the retraction arm on
///    purpose: a retracted tombstone that got deleted would revive whatever it
///    retracted. `Unknown`-adjacent by nature (we cannot prove an exclusion is
///    spent), so keeping is the safe side. Re-stamped when we can author it,
///    otherwise [`Disposition::RetainInert`].
/// 2. **Retracted ⇒ purge.** The author's own later statement is the proof.
///    This is the arm that makes the migration carry the FINAL state and not
///    the interim ones. Not `Unknown` — a live composer is a decisive `No`.
/// 3. **Conformant ⇒ untouched.** Idempotence.
/// 4. **Ours ⇒ re-stamp**, unless PROVABLY inert (`LoadBearing::No` AND
///    federation-tier AND outside a COMPLETE closure). `Unknown` lands on the
///    re-stamp side, which is the fail-secure side.
/// 5. **Not ours, local tier ⇒ retain inert.** A local-tier row lives nowhere
///    else; no peer can refill it, so deletion is unrecoverable.
/// 6. **Not ours, federation tier ⇒ purge.** Its author is its source and the
///    replication plane refills it in v31 shape. This is the only arm that
///    deletes something we did not prove dead, and it is licensed by
///    RECOVERABILITY rather than by deadness — stated here so the difference is
///    on the record.
#[must_use]
pub fn classify(
    row: &Attestation,
    shape: &RowShape,
    fold: &RetractionFold,
    closure: &LoadBearingClosure,
    verdict: &LoadBearing,
    authorship: &Authorship,
) -> Disposition {
    // 1. EXCLUSION-BEARING — never purge. Leads the retraction arm.
    if let Some(why) = is_exclusion_bearing(row) {
        if shape.is_conformant() {
            return Disposition::AlreadyConformant;
        }
        if authorship.can_reauthor() {
            return Disposition::Restamp;
        }
        return Disposition::RetainInert {
            why: format!(
                "{why} — and this node cannot re-author it, so it is kept in v30 shape rather \
                 than deleted (CIRISPersist#650: exclusion is not structural and the dedicated \
                 revocation plane has no replication cursor)"
            ),
        };
    }

    // 2. RETRACTED — the author's own later statement. Proven dead.
    if let Some(by) = fold.retracted_by(&row.attestation_id) {
        return Disposition::Purge(PurgeReason::Retracted { by: by.to_owned() });
    }

    // 3. Already v31. The idempotence arm.
    if shape.is_conformant() {
        return Disposition::AlreadyConformant;
    }

    // 4. OURS. `Unknown` re-stamps — the fail-secure side.
    if authorship.can_reauthor() {
        // FOUR conjuncts, and every one of them is a refusal to guess.
        //
        // The `tier` conjunct is the one that is easy to miss and would be
        // wrong to omit: the recursive walk reaches attestations through
        // `list_attestations_by` / `list_attestations_for`, and BOTH are
        // `tier = 'federation'` reads (the E5 invariant — a local row must
        // never reach the serve wire). So the walk STRUCTURALLY cannot see a
        // local-tier row, and "not in the closure" carries no information about
        // one. Reading it as evidence of inertness would delete a draft that
        // exists nowhere else on the strength of a read that was never looking.
        //
        // What remains reachable is exactly the CIRISPersist#563 shape: a
        // federation-tier grant we authored, proven `No` by its family's own
        // declared predicate, that a COMPLETE walk from the owner claim did not
        // reach. That is a narrow arm by design — it is the only licence in
        // this routine to delete a row of ours that no one has retracted.
        let provably_inert = matches!(verdict, LoadBearing::No)
            && row.tier == attestation_tier::FEDERATION
            && !closure.contains_attestation(&row.attestation_id)
            && closure.completeness.complement_is_trustworthy();
        if provably_inert {
            return Disposition::Purge(PurgeReason::ProvablyInert);
        }
        return Disposition::Restamp;
    }

    // 5. Not ours, and nowhere else to come back from.
    if row.tier == attestation_tier::LOCAL {
        return Disposition::RetainInert {
            why:
                "a local-tier row this node did not seal exists nowhere else — no peer can refill \
                  it, so deleting it is unrecoverable (a subject-side revocation in transit is \
                  exactly this shape)"
                    .to_owned(),
        };
    }

    // 6. Not ours, federation tier: its author is its source.
    Disposition::Purge(PurgeReason::UnauthorableLegacy {
        attesting_key_id: row.attesting_key_id.clone(),
    })
}

// ─────────────────────────────────────────────────────────────────────────
// The re-seal door's gate stack — ONE definition, three backends.
// ─────────────────────────────────────────────────────────────────────────

/// The gate stack every backend's
/// [`reseal_attestation_v31`](FederationDirectory::reseal_attestation_v31) runs
/// before it mutates anything (verify-before-mutation, AV-9).
///
/// Written once and called three times rather than transcribed per backend:
/// three copies of a gate stack is how the backends drift, and this crate has a
/// recorded defect class for exactly that (#596 item 2 — three axes silently
/// ignored by one backend).
///
/// Two halves, in this order:
///
/// 1. **IMMUTABILITY.** A re-seal changes the SEAL, never the row's meaning.
///    Every field the #643 mirror binds, plus `tier`, must equal the stored
///    row's. A "re-seal" that could move a row between tiers or cohort scopes
///    would be a third placement door with none of the gates the other two run.
/// 2. **THE v31 BINDINGS**, over the row as it will be stored — so a caller
///    that hands over a row it forgot to stamp is REFUSED here rather than
///    silently writing a row no peer will take. That is CIRISPersist#649's
///    rule, applied to the door #650 adds.
pub fn check_reseal_admission(
    stored: &Attestation,
    resealed: &Attestation,
    now: chrono::DateTime<chrono::Utc>,
) -> Result<(), Error> {
    let immutable = |what: &str, a: String, b: String| {
        Error::InvalidArgument(format!(
            "reseal of attestation {}: `{what}` {a} diverges from the stored {b} — a v31 re-seal \
             changes the SEAL, never the row's meaning or its placement (CIRISPersist#650)",
            stored.attestation_id,
        ))
    };
    if resealed.attestation_id != stored.attestation_id {
        return Err(immutable(
            "attestation_id",
            format!("{:?}", resealed.attestation_id),
            format!("{:?}", stored.attestation_id),
        ));
    }
    if resealed.attesting_key_id != stored.attesting_key_id {
        return Err(immutable(
            "attesting_key_id",
            format!("{:?}", resealed.attesting_key_id),
            format!("{:?}", stored.attesting_key_id),
        ));
    }
    if resealed.attested_key_id != stored.attested_key_id {
        return Err(immutable(
            "attested_key_id",
            format!("{:?}", resealed.attested_key_id),
            format!("{:?}", stored.attested_key_id),
        ));
    }
    if resealed.attestation_type != stored.attestation_type {
        return Err(immutable(
            "attestation_type",
            format!("{:?}", resealed.attestation_type),
            format!("{:?}", stored.attestation_type),
        ));
    }
    if resealed.subject_key_ids != stored.subject_key_ids {
        return Err(immutable(
            "subject_key_ids",
            format!("{:?}", resealed.subject_key_ids),
            format!("{:?}", stored.subject_key_ids),
        ));
    }
    if resealed.cohort_scope != stored.cohort_scope {
        return Err(immutable(
            "cohort_scope",
            format!("{:?}", resealed.cohort_scope),
            format!("{:?}", stored.cohort_scope),
        ));
    }
    if resealed.tier != stored.tier {
        return Err(immutable(
            "tier",
            format!("{:?}", resealed.tier),
            format!("{:?}", stored.tier),
        ));
    }
    if resealed.weight != stored.weight {
        return Err(immutable(
            "weight",
            format!("{:?}", resealed.weight),
            format!("{:?}", stored.weight),
        ));
    }
    super::admission::check_instant_binding(
        resealed,
        now,
        super::admission::DEFAULT_MAX_TOUCH_SKEW,
    )?;
    super::admission::check_row_column_binding(resealed)?;
    Ok(())
}

// ─────────────────────────────────────────────────────────────────────────
// Roots, signer, driver.
// ─────────────────────────────────────────────────────────────────────────

/// The roots of the recursive walk — **the owner claim**.
///
/// #650: *"for us every node starts with an owner claim"*. Concretely that is
/// the live owner-binding `delegates_to(U → node)` edge
/// ([`super::admission::owner_of`]), so the anchor is the pair *(this node's
/// key record, its owner's key record)*. The walk then expands both through
/// the authorship / subject / delegation edges.
///
/// An UNOWNED node (no owner-binding, or an ambiguous one) still gets its own
/// key record as a root — the closure is smaller but the walk is not skipped,
/// and a smaller closure only makes the `ProvablyInert` arm harder to reach,
/// which is the safe direction.
pub async fn owner_roots(
    directory: &dyn FederationDirectory,
    self_key_id: &str,
) -> Result<Vec<ObjectRef>, Error> {
    let mut roots = vec![ObjectRef::KeyRecord {
        key_id: self_key_id.to_owned(),
    }];
    // An ambiguous owner is `Error::AmbiguousNodeOwner`, which is a real
    // finding but not a reason to refuse to migrate; the node's own key record
    // still anchors the walk.
    if let Ok(Some(owner)) = super::admission::owner_of(directory, self_key_id).await {
        roots.push(ObjectRef::KeyRecord { key_id: owner });
    }
    Ok(roots)
}

/// What the migration needs from a signer, and nothing more.
///
/// A trait rather than `&Engine` so the routine is testable without an Engine
/// and so `engine.rs` needs no method of its own — the impl for
/// [`crate::Engine`] lives here, at the bottom of this module.
#[async_trait::async_trait]
pub trait MigrationSigner: Send + Sync {
    /// The DERIVED federation `key_id` this signer signs as (never a keystore
    /// alias — CIRISPersist#247). `None` when the node has no resolvable
    /// identity, which makes every signed row [`Authorship::Foreign`].
    async fn signing_key_id(&self) -> Option<String>;

    /// Hybrid-sign `canonical`, returning `(ed25519_base64,
    /// ml_dsa_65_base64)`.
    async fn sign_canonical(&self, canonical: &[u8]) -> Result<(String, Option<String>), Error>;
}

/// One row's outcome, for the report.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct RowOutcome {
    /// The row.
    pub attestation_id: String,
    /// What was decided.
    pub disposition: Disposition,
    /// Whether the decision was actually applied (a `dry_run` reports
    /// decisions without applying them).
    pub applied: bool,
    /// A backend failure on this row. The run CONTINUES: one unwritable row
    /// must not block the rest of the corpus, and the next boot retries it.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub error: Option<String>,
}

/// The report. Every count is derivable from [`Self::rows`]; they are
/// precomputed because a caller logging one line at boot should not have to
/// fold.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct MigrationOutcome {
    /// Rows visited.
    pub visited: usize,
    /// Rows already in v31 shape (the idempotence signal — a second run is all
    /// of these).
    pub already_conformant: usize,
    /// Rows re-stamped.
    pub restamped: usize,
    /// Rows purged, by reason.
    pub purged_retracted: usize,
    /// Rows purged because they are legacy, foreign and refillable.
    pub purged_unauthorable: usize,
    /// Rows purged because they are ours, legacy and provably inert.
    pub purged_provably_inert: usize,
    /// Rows kept in v30 shape because deleting them was unsafe.
    pub retained_inert: usize,
    /// Per-row detail.
    pub rows: Vec<RowOutcome>,
    /// Whether the corpus walk hit [`MIGRATION_ROW_BUDGET`].
    pub budget_exhausted: bool,
    /// Whether the reachability closure was complete. When `false`, the
    /// `ProvablyInert` purge arm was disabled for the whole run.
    pub closure_complete: bool,
    /// Rows the walk could not act on. Non-empty means the next run has work.
    pub errors: usize,
}

impl MigrationOutcome {
    /// Did the run change anything? A `false` here on the SECOND run is the
    /// idempotence property, stated as a value rather than as a comment.
    #[must_use]
    pub const fn changed_anything(&self) -> bool {
        self.restamped > 0
            || self.purged_retracted > 0
            || self.purged_unauthorable > 0
            || self.purged_provably_inert > 0
    }

    fn record(&mut self, outcome: RowOutcome) {
        self.visited += 1;
        if outcome.error.is_some() {
            self.errors += 1;
        }
        if outcome.applied {
            match &outcome.disposition {
                Disposition::AlreadyConformant => self.already_conformant += 1,
                Disposition::Restamp => self.restamped += 1,
                Disposition::RetainInert { .. } => self.retained_inert += 1,
                Disposition::Purge(PurgeReason::Retracted { .. }) => self.purged_retracted += 1,
                Disposition::Purge(PurgeReason::UnauthorableLegacy { .. }) => {
                    self.purged_unauthorable += 1;
                }
                Disposition::Purge(PurgeReason::ProvablyInert) => {
                    self.purged_provably_inert += 1;
                }
            }
        }
        self.rows.push(outcome);
    }
}

/// Knobs. Defaults are the boot behaviour.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct MigrationOptions {
    /// Decide but do not write. Used by an operator preview and by the witness
    /// that asserts a decision without paying for it.
    pub dry_run: bool,
    /// The [`load_bearing_closure`] expansion budget.
    pub closure_budget: usize,
    /// The corpus-walk row budget.
    pub row_budget: usize,
}

impl Default for MigrationOptions {
    fn default() -> Self {
        Self {
            dry_run: false,
            closure_budget: DEFAULT_CLOSURE_BUDGET,
            row_budget: MIGRATION_ROW_BUDGET,
        }
    }
}

/// Read the whole corpus, every tier, in one stable keyset order.
async fn read_corpus(
    directory: &dyn FederationDirectory,
    row_budget: usize,
) -> Result<(Vec<Attestation>, bool), Error> {
    let mut out: Vec<Attestation> = Vec::new();
    let mut after: Option<String> = None;
    loop {
        let page = directory
            .list_attestations_for_migration(after.as_deref(), MIGRATION_PAGE_SIZE)
            .await?;
        if page.is_empty() {
            return Ok((out, false));
        }
        after = page.last().map(|r| r.attestation_id.clone());
        out.extend(page);
        if out.len() >= row_budget {
            out.truncate(row_budget);
            return Ok((out, true));
        }
    }
}

/// Build the v31-shaped twin of `row`: the SAME row, with the signed instants
/// and the typed-column mirror stamped and the seal recomputed over exactly
/// those bytes.
///
/// **The identity is preserved.** `attestation_id` is not re-minted — it is one
/// of the seven members #643 binds, and a re-mint under a fresh id would
/// detach the row from every composer that references it. That is the second
/// resurrection vector, closed by construction rather than by a check.
///
/// Both stamps go through the ONE placement each field has
/// ([`stamp_signed_instants`](super::envelope::stamp_signed_instants) and
/// [`RowMirror::stamp_row`](super::envelope::RowMirror::stamp_row)), so this is
/// not a third definition of either projection.
async fn build_restamped(
    row: &Attestation,
    signer: &dyn MigrationSigner,
    authorship: &Authorship,
) -> Result<Attestation, Error> {
    use sha2::{Digest, Sha256};

    let mut next = row.clone();
    super::envelope::stamp_signed_instants(&mut next)?;
    super::envelope::RowMirror::stamp_row(&mut next)?;

    match authorship {
        Authorship::UnsealedLocal => {
            // The deferred empty-sentinel seal is preserved verbatim: a local
            // row has no signature and no content hash, and inventing one here
            // would make the row look federation-sealed to the V066 trigger's
            // twin invariant.
            next.original_content_hash = String::new();
            next.scrub_signature_classical = String::new();
            next.scrub_signature_pqc = None;
        }
        Authorship::OwnKey => {
            let canonical =
                crate::verify::canonical::ceg_produce_canonicalize(&next.attestation_envelope)
                    .map_err(|e| Error::Backend(format!("v31 migration canonicalize: {e}")))?;
            let (ed, pqc) = signer.sign_canonical(&canonical).await?;
            next.original_content_hash = hex::encode(Sha256::digest(&canonical));
            next.scrub_signature_classical = ed;
            next.scrub_signature_pqc = pqc;
            next.scrub_key_id = signer.signing_key_id().await.ok_or_else(|| {
                Error::Backend(
                    "v31 migration: re-sealing a row this node authored requires a derived \
                     signing key id, and none resolved"
                        .to_owned(),
                )
            })?;
            next.scrub_timestamp =
                super::admission::truncate_to_substrate_resolution(chrono::Utc::now());
            // A re-seal is a FRESH scrub set: the co-scrubs covered the OLD
            // envelope bytes and cannot cover these. Same rule promotion
            // applies (#556/#557).
            next.additional_scrubs = Vec::new();
        }
        Authorship::Foreign { .. } => {
            return Err(Error::InvalidArgument(format!(
                "v31 migration refuses to re-stamp attestation {}: its bytes were signed by {} \
                 and rewriting them would leave a stored hash and signature covering an envelope \
                 that no longer exists (CIRISPersist#650)",
                row.attestation_id, row.attesting_key_id,
            )));
        }
    }
    Ok(next)
}

/// v31.0.0 (CIRISPersist#650) — **run the migration.**
///
/// See the module doc for the algorithm, the fail-secure polarity, and why it
/// is safe to interrupt and safe to repeat.
pub async fn run_v31_migration(
    directory: &dyn FederationDirectory,
    signer: &dyn MigrationSigner,
    options: &MigrationOptions,
) -> Result<MigrationOutcome, Error> {
    let now = chrono::Utc::now();
    let self_key_id = signer.signing_key_id().await;

    let (corpus, budget_exhausted) = read_corpus(directory, options.row_budget).await?;
    let fold = fold_retractions(&corpus);

    // The recursive walk from the owner claim. A node with no identity has no
    // owner claim to anchor on; the closure is then empty, which disables the
    // `ProvablyInert` arm (an empty closure with `Complete` completeness would
    // otherwise mark every `No` row purgeable). Guard it explicitly.
    let closure = match &self_key_id {
        Some(me) => {
            let roots = owner_roots(directory, me).await?;
            load_bearing_closure(directory, roots, options.closure_budget).await?
        }
        None => LoadBearingClosure {
            roots: Vec::new(),
            members: Vec::new(),
            attestation_ids: BTreeSet::new(),
            key_ids: BTreeSet::new(),
            revisits: 0,
            excluded_proven_not_load_bearing: 0,
            // NOT `Complete`: without an anchor the walk saw nothing, and a
            // caller must not read "nothing reachable" as "everything is
            // purgeable".
            completeness: ClosureCompleteness::Truncated {
                budget: options.closure_budget,
                frontier_remaining: 0,
            },
        },
    };

    let mut outcome = MigrationOutcome {
        budget_exhausted,
        closure_complete: closure.completeness.complement_is_trustworthy(),
        ..MigrationOutcome::default()
    };

    for row in &corpus {
        let shape = classify_shape(row, now);
        let authorship = classify_authorship(row, self_key_id.as_deref());
        // The per-row predicate is only consulted where it can change the
        // answer — the `ProvablyInert` arm. Skipping it elsewhere keeps a boot
        // sweep from doing two directory reads per row for a verdict no arm
        // reads.
        let verdict = if authorship.can_reauthor() && !shape.is_conformant() {
            is_load_bearing(
                directory,
                ObjectRef::Attestation {
                    attestation_id: row.attestation_id.clone(),
                },
            )
            .await?
        } else {
            LoadBearing::Unknown {
                family: "<not-consulted>".to_owned(),
                reason: "the predicate cannot change this row's disposition".to_owned(),
            }
        };
        let disposition = classify(row, &shape, &fold, &closure, &verdict, &authorship);

        if options.dry_run {
            outcome.record(RowOutcome {
                attestation_id: row.attestation_id.clone(),
                disposition,
                applied: false,
                error: None,
            });
            continue;
        }

        let applied = match &disposition {
            Disposition::AlreadyConformant | Disposition::RetainInert { .. } => Ok(()),
            Disposition::Restamp => match build_restamped(row, signer, &authorship).await {
                Ok(next) => directory.reseal_attestation_v31(&next).await.map(|_| ()),
                Err(e) => Err(e),
            },
            Disposition::Purge(_) => directory
                .purge_attestation_v31(&row.attestation_id)
                .await
                .map(|_| ()),
        };
        match applied {
            Ok(()) => outcome.record(RowOutcome {
                attestation_id: row.attestation_id.clone(),
                disposition,
                applied: true,
                error: None,
            }),
            // One unwritable row does not stop the sweep. The routine is
            // resumable by construction, so the honest response is to report
            // it and let the next boot retry.
            Err(e) => outcome.record(RowOutcome {
                attestation_id: row.attestation_id.clone(),
                disposition,
                applied: false,
                error: Some(e.to_string()),
            }),
        }
    }

    // A purge leaves the V111 signed wire index pointing at rows that are gone.
    // `rebuild_signed_wire_index` is the sanctioned repair for exactly this and
    // is already implemented on all three backends — reused rather than
    // hand-rolling three index deletes.
    if !options.dry_run
        && (outcome.purged_retracted + outcome.purged_unauthorable + outcome.purged_provably_inert)
            > 0
    {
        match directory.rebuild_signed_wire_index().await {
            Ok(_) | Err(Error::Unsupported { .. }) => {}
            Err(e) => return Err(e),
        }
    }

    Ok(outcome)
}

// ─────────────────────────────────────────────────────────────────────────
// The boot hook.
// ─────────────────────────────────────────────────────────────────────────

#[async_trait::async_trait]
impl MigrationSigner for crate::Engine {
    async fn signing_key_id(&self) -> Option<String> {
        self.local_derived_key_id().await.ok()
    }

    async fn sign_canonical(&self, canonical: &[u8]) -> Result<(String, Option<String>), Error> {
        use base64::{engine::general_purpose::STANDARD as B64, Engine as _};
        let sig = self
            .sign_hybrid(canonical)
            .await
            .map_err(|e| Error::Backend(format!("v31 migration sign_hybrid: {e}")))?;
        Ok((
            B64.encode(&sig.classical.signature),
            Some(B64.encode(&sig.pqc.signature)),
        ))
    }
}

/// v31.0.0 (CIRISPersist#650) — **the boot hook.** Called from every `Engine`
/// constructor that opens a real backend, immediately after the node's identity
/// is known to the backend and before the Engine is handed to the caller.
///
/// # Why here and not in `Backend::run_migrations`
///
/// `run_migrations` is where the idempotent data-repair sweeps live
/// (`backfill_trace_dedup_shard_keys` is the precedent), and structurally that
/// is the better slot. It cannot be used: **a re-stamp is a re-SIGN**, and
/// `Backend` has no signer. The Engine constructor is the first point at which
/// the backend and the signing key exist together, which is exactly what this
/// routine needs and exactly why it lives one layer up.
///
/// # Why it never fails a boot
///
/// A node that cannot migrate is still a node that must start — refusing to
/// boot would turn a partially-migratable corpus into an unreachable one, and
/// the routine is resumable, so the next boot retries. Failures are returned in
/// the [`MigrationOutcome`] and, for a hard error, swallowed with a `tracing`
/// warning. **A pre-genesis node** (no derived key id) migrates nothing: with
/// no identity there is no owner claim, no authorship, and therefore nothing it
/// may re-stamp or purge.
///
/// # The default-feature twin
///
/// Gated on `any(postgres, sqlite)` because
/// [`Engine::federation_directory`](crate::Engine::federation_directory) is —
/// with neither backend feature on, `BackendDispatch` has no variants and there
/// is no storage to migrate at all. The `not(...)` twin below keeps the CALL
/// SITE in `engine.rs` feature-blind, because a constructor that runs the
/// migration under one feature set and silently does not under another is the
/// shape a previous cut shipped a break in.
#[cfg(any(feature = "postgres", feature = "sqlite"))]
pub async fn run_v31_migration_at_boot(engine: &crate::Engine) -> Option<MigrationOutcome> {
    let directory = engine.federation_directory();
    // No identity ⇒ nothing is ours ⇒ nothing to do. Bail before paying for a
    // corpus read.
    MigrationSigner::signing_key_id(engine).await.as_ref()?;
    // Probe the enumerator once: a directory surface that cannot enumerate (the
    // FFI capsule) has no migration to run, and `Unsupported` is not an error.
    match directory.list_attestations_for_migration(None, 1).await {
        Ok(_) => {}
        Err(Error::Unsupported { .. }) => return None,
        Err(e) => {
            tracing::warn!(error = %e, "v31 migration (CIRISPersist#650) could not read the corpus; skipped");
            return None;
        }
    }
    match run_v31_migration(
        directory.as_ref(),
        engine as &dyn MigrationSigner,
        &MigrationOptions::default(),
    )
    .await
    {
        Ok(outcome) => {
            if outcome.changed_anything() || outcome.errors > 0 {
                tracing::info!(
                    visited = outcome.visited,
                    restamped = outcome.restamped,
                    purged_retracted = outcome.purged_retracted,
                    purged_unauthorable = outcome.purged_unauthorable,
                    purged_provably_inert = outcome.purged_provably_inert,
                    retained_inert = outcome.retained_inert,
                    errors = outcome.errors,
                    closure_complete = outcome.closure_complete,
                    "v31 in-place migration (CIRISPersist#650)"
                );
            }
            Some(outcome)
        }
        Err(e) => {
            tracing::warn!(error = %e, "v31 migration (CIRISPersist#650) failed; boot continues and the next boot retries");
            None
        }
    }
}

/// The no-backend build's twin of [`run_v31_migration_at_boot`]: there is no
/// storage in this configuration, so there is nothing to migrate.
#[cfg(not(any(feature = "postgres", feature = "sqlite")))]
pub async fn run_v31_migration_at_boot(engine: &crate::Engine) -> Option<MigrationOutcome> {
    let _ = engine;
    None
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::federation::types::{attestation_tier, attestation_type};

    fn env(dimension: &str, references: Option<&str>) -> serde_json::Value {
        let mut v = serde_json::json!({ "dimension": dimension });
        if let Some(r) = references {
            v["references_attestation_id"] = serde_json::json!(r);
        }
        v
    }

    fn row(id: &str, attester: &str, ty: &str, envelope: serde_json::Value) -> Attestation {
        let now = chrono::Utc::now();
        Attestation {
            attestation_id: id.to_owned(),
            attesting_key_id: attester.to_owned(),
            attested_key_id: attester.to_owned(),
            attestation_type: ty.to_owned(),
            weight: None,
            asserted_at: now,
            expires_at: None,
            attestation_envelope: envelope,
            original_content_hash: "aa".to_owned(),
            scrub_signature_classical: "sig".to_owned(),
            scrub_signature_pqc: None,
            scrub_key_id: attester.to_owned(),
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

    fn empty_closure(complete: bool) -> LoadBearingClosure {
        LoadBearingClosure {
            roots: Vec::new(),
            members: Vec::new(),
            attestation_ids: BTreeSet::new(),
            key_ids: BTreeSet::new(),
            revisits: 0,
            excluded_proven_not_load_bearing: 0,
            completeness: if complete {
                ClosureCompleteness::Complete
            } else {
                ClosureCompleteness::Truncated {
                    budget: 1,
                    frontier_remaining: 1,
                }
            },
        }
    }

    fn legacy() -> RowShape {
        RowShape::Legacy {
            why: "no signed `row` object".to_owned(),
        }
    }

    #[test]
    fn the_fold_retracts_only_same_attester_targets() {
        let target = row("t1", "alice", attestation_type::SCORES, env("x:y:v1", None));
        let mine = row(
            "w1",
            "alice",
            attestation_type::WITHDRAWS,
            env("x:y:v1", Some("t1")),
        );
        let theirs = row(
            "w2",
            "mallory",
            attestation_type::WITHDRAWS,
            env("x:y:v1", Some("t1")),
        );

        // Same attester retracts.
        let fold = fold_retractions(&[target.clone(), mine]);
        assert!(fold.is_retracted("t1"));
        assert_eq!(fold.retracted_by("t1"), Some("w1"));

        // A DIFFERENT attester's composer does not — CEG §6.1 rule 4, and the
        // same rule every backend's `LifecycleView::Live` filter applies.
        let fold = fold_retractions(&[target, theirs]);
        assert!(!fold.is_retracted("t1"));
    }

    #[test]
    fn recants_outranks_withdraws_as_the_named_authority() {
        let target = row("t1", "alice", attestation_type::SCORES, env("x:y:v1", None));
        let mut withdraw = row(
            "w1",
            "alice",
            attestation_type::WITHDRAWS,
            env("x:y:v1", Some("t1")),
        );
        withdraw.asserted_at = chrono::Utc::now() + chrono::Duration::seconds(60);
        let recant = row(
            "r1",
            "alice",
            attestation_type::RECANTS,
            env("x:y:v1", Some("t1")),
        );
        let fold = fold_retractions(&[target, withdraw, recant]);
        // §6.1: recants outranks withdraws REGARDLESS of time.
        assert_eq!(fold.retracted_by("t1"), Some("r1"));
    }

    #[test]
    fn a_withdrawn_grant_is_purged_and_its_tombstone_is_not() {
        // THE resurrection case, at the decision layer.
        let grant = row(
            "g1",
            "alice",
            attestation_type::SCORES,
            env(crate::federation::consent_peer_set::DIMENSION, None),
        );
        let tombstone = row(
            "w1",
            "alice",
            attestation_type::WITHDRAWS,
            env(crate::federation::consent_peer_set::DIMENSION, Some("g1")),
        );
        let fold = fold_retractions(&[grant.clone(), tombstone.clone()]);
        let closure = empty_closure(true);
        let ours = Authorship::OwnKey;

        assert!(matches!(
            classify(
                &grant,
                &legacy(),
                &fold,
                &closure,
                &LoadBearing::Unknown {
                    family: "consent:*".to_owned(),
                    reason: String::new()
                },
                &ours
            ),
            Disposition::Purge(PurgeReason::Retracted { .. })
        ));
        // The TOMBSTONE is re-stamped, never purged — purging it is the other
        // way the grant comes back.
        assert_eq!(
            classify(
                &tombstone,
                &legacy(),
                &fold,
                &closure,
                &LoadBearing::No,
                &ours
            ),
            Disposition::Restamp
        );
    }

    #[test]
    fn unknown_never_purges_and_no_only_purges_on_a_complete_closure() {
        let r = row("a1", "me", attestation_type::SCORES, env("x:y:v1", None));
        let fold = RetractionFold::default();
        let unknown = LoadBearing::Unknown {
            family: "x:*".to_owned(),
            reason: "undeclared".to_owned(),
        };

        // Unknown ⇒ re-stamp, on a COMPLETE closure. The fail-secure polarity.
        assert_eq!(
            classify(
                &r,
                &legacy(),
                &fold,
                &empty_closure(true),
                &unknown,
                &Authorship::OwnKey
            ),
            Disposition::Restamp
        );
        // A proven No, complete closure, outside it ⇒ the only arm that
        // deletes one of OUR rows.
        assert_eq!(
            classify(
                &r,
                &legacy(),
                &fold,
                &empty_closure(true),
                &LoadBearing::No,
                &Authorship::OwnKey
            ),
            Disposition::Purge(PurgeReason::ProvablyInert)
        );
        // The SAME No on a TRUNCATED closure must not delete.
        assert_eq!(
            classify(
                &r,
                &legacy(),
                &fold,
                &empty_closure(false),
                &LoadBearing::No,
                &Authorship::OwnKey
            ),
            Disposition::Restamp
        );
        // …and the SAME No on a LOCAL-tier row must not delete either, on a
        // COMPLETE closure. The walk reaches attestations only through
        // `tier = 'federation'` reads, so "absent from the closure" says
        // nothing about a local row — and a local row lives nowhere else.
        let mut local = r.clone();
        local.tier = attestation_tier::LOCAL.to_owned();
        assert_eq!(
            classify(
                &local,
                &legacy(),
                &fold,
                &empty_closure(true),
                &LoadBearing::No,
                &Authorship::UnsealedLocal
            ),
            Disposition::Restamp,
            "the closure walk cannot see local-tier rows, so its complement must never license \
             deleting one"
        );
    }

    #[test]
    fn every_exclusion_bearing_class_survives_a_purge() {
        let fold = RetractionFold::default();
        let closure = empty_closure(true);
        let foreign = Authorship::Foreign {
            attesting_key_id: "peer".to_owned(),
        };
        let cases: Vec<Attestation> = vec![
            row(
                "d1",
                "peer",
                attestation_type::SCORES,
                env(
                    crate::federation::admission::PEER_DEADMISSION_DIMENSION,
                    None,
                ),
            ),
            row(
                "q1",
                "peer",
                attestation_type::SCORES,
                env(crate::federation::quarantine::DIMENSION_WITHHELD, None),
            ),
            row(
                "q2",
                "peer",
                attestation_type::SCORES,
                env(crate::federation::quarantine::DIMENSION_RELEASED, None),
            ),
            row(
                "m1",
                "peer",
                attestation_type::SCORES,
                env("moderation:harassment", None),
            ),
            row(
                "rc1",
                "peer",
                attestation_type::SCORES,
                env("reconsideration:new_evidence", None),
            ),
            row(
                "s1",
                "peer",
                attestation_type::SCORES,
                env("slashing:upheld", None),
            ),
            row(
                "o1",
                "peer",
                attestation_type::SCORES,
                env(crate::federation::reverse_quorum::DIMENSION_OBJECTION, None),
            ),
            row(
                "del1",
                "peer",
                attestation_type::DELEGATES_TO,
                env("delegation:x:v1", None),
            ),
            row(
                "w1",
                "peer",
                attestation_type::WITHDRAWS,
                env("x:y:v1", Some("zzz")),
            ),
        ];
        for r in &cases {
            assert!(
                is_exclusion_bearing(r).is_some(),
                "{} must be exclusion-bearing",
                r.attestation_id
            );
            let d = classify(
                r,
                &legacy(),
                &fold,
                &closure,
                &LoadBearing::No,
                // Foreign AND `LoadBearing::No` AND federation tier — every
                // condition that would otherwise purge.
                &foreign,
            );
            assert!(
                matches!(d, Disposition::RetainInert { .. }),
                "{} was {d:?}, but an exclusion must never be purged",
                r.attestation_id
            );
        }
        // Negative control: an ordinary row under the SAME conditions IS
        // purged, so the assertion above is measuring the exclusion class and
        // not a routine that purges nothing.
        let ordinary = row(
            "p1",
            "peer",
            attestation_type::SCORES,
            env("weather:today:v1", None),
        );
        assert!(is_exclusion_bearing(&ordinary).is_none());
        assert!(matches!(
            classify(
                &ordinary,
                &legacy(),
                &fold,
                &closure,
                &LoadBearing::No,
                &foreign
            ),
            Disposition::Purge(PurgeReason::UnauthorableLegacy { .. })
        ));
    }

    #[test]
    fn a_foreign_local_row_is_never_purged() {
        // A subject-side revocation in TRANSIT: local tier, caller-signed.
        let mut r = row(
            "t1",
            "subject",
            attestation_type::WITHDRAWS,
            env("consent:state:v1", None),
        );
        r.tier = attestation_tier::LOCAL.to_owned();
        // Non-empty signature ⇒ not ours to rewrite even though it is local.
        assert!(matches!(
            classify_authorship(&r, Some("me")),
            Authorship::Foreign { .. }
        ));
        assert!(matches!(
            classify(
                &r,
                &legacy(),
                &RetractionFold::default(),
                &empty_closure(true),
                &LoadBearing::No,
                &classify_authorship(&r, Some("me"))
            ),
            Disposition::RetainInert { .. }
        ));
    }

    #[test]
    fn an_unsealed_local_row_is_ours_a_sealed_one_is_not() {
        let mut r = row(
            "l1",
            "someone-else",
            attestation_type::SCORES,
            env("x", None),
        );
        r.tier = attestation_tier::LOCAL.to_owned();
        r.scrub_signature_classical = String::new();
        assert_eq!(
            classify_authorship(&r, Some("me")),
            Authorship::UnsealedLocal
        );
        assert!(classify_authorship(&r, Some("me")).can_reauthor());

        r.scrub_signature_classical = "someone-elses-sig".to_owned();
        assert!(!classify_authorship(&r, Some("me")).can_reauthor());

        // No identity at all ⇒ nothing signed is ours. Fail-secure.
        let f = row("f1", "me", attestation_type::SCORES, env("x", None));
        assert!(matches!(
            classify_authorship(&f, None),
            Authorship::Foreign { .. }
        ));
    }

    #[test]
    fn conformant_rows_are_untouched_which_is_the_idempotence_property() {
        let r = row("a1", "me", attestation_type::SCORES, env("x:y:v1", None));
        assert_eq!(
            classify(
                &r,
                &RowShape::V31Conformant,
                &RetractionFold::default(),
                &empty_closure(true),
                &LoadBearing::Unknown {
                    family: String::new(),
                    reason: String::new()
                },
                &Authorship::OwnKey
            ),
            Disposition::AlreadyConformant
        );
    }
}

/// v31.0.0 (CIRISPersist#650) — the shared, backend-agnostic behavioural
/// witness, run by the memory / sqlite / postgres suites against
/// `&dyn FederationDirectory` so the three backends cannot silently diverge on
/// a routine that DELETES ROWS.
#[cfg(all(test, any(feature = "sqlite", feature = "postgres")))]
pub(crate) mod test_support {
    use super::*;
    use crate::federation::tier_ingest::test_support as seal;
    use crate::federation::types::attestation_type;
    use crate::federation::SignedAttestation;

    /// Install a row in **v30 shape** — the one thing no production door can
    /// do, because both v31 gates refuse it.
    ///
    /// Implemented per backend beside the storage it reaches (the memory
    /// `State` vector, the sqlite connection, the postgres pool), because that
    /// access is private to those modules. The witness body below is shared, so
    /// the three backends are measured by ONE set of assertions.
    #[async_trait::async_trait]
    pub(crate) trait LegacyRowInstaller: Send + Sync {
        /// Strip the #598 instants and the #643 mirror from the STORED
        /// envelope of `attestation_id`, leaving the row exactly as a v30
        /// writer would have left it. The row must already exist.
        async fn downgrade_to_v30(&self, attestation_id: &str);
    }

    /// Strip both v31 bindings from an envelope — the v30 shape, by removal.
    pub(crate) fn v30_envelope(envelope: &serde_json::Value) -> serde_json::Value {
        use crate::federation::envelope::paths;
        let mut out = envelope.clone();
        if let Some(obj) = out.as_object_mut() {
            obj.remove(paths::ROW);
            obj.remove(paths::ASSERTED_AT);
            obj.remove(paths::EXPIRES_AT);
        }
        out
    }

    /// A deterministic [`MigrationSigner`] over the fixture keypair for
    /// `key_id` — the same pair [`seal::hybrid_pubkeys`] registers, so a
    /// re-stamped row verifies against the stored key record.
    pub(crate) struct FixtureSigner {
        pub(crate) key_id: String,
    }

    #[async_trait::async_trait]
    impl MigrationSigner for FixtureSigner {
        async fn signing_key_id(&self) -> Option<String> {
            Some(self.key_id.clone())
        }
        async fn sign_canonical(
            &self,
            canonical: &[u8],
        ) -> Result<(String, Option<String>), Error> {
            let envelope: serde_json::Value = serde_json::from_slice(canonical)
                .map_err(|e| Error::Backend(format!("fixture signer parse: {e}")))?;
            let (_och, ed, pqc) = seal::sign_envelope(&self.key_id, &envelope);
            Ok((ed, pqc))
        }
    }

    fn row_with(
        id: &str,
        attester: &str,
        envelope: serde_json::Value,
        subjects: &[&str],
        ty: &str,
    ) -> Attestation {
        let now =
            crate::federation::admission::truncate_to_substrate_resolution(chrono::Utc::now());
        let mut row = Attestation {
            attestation_id: id.to_owned(),
            attesting_key_id: attester.to_owned(),
            attested_key_id: attester.to_owned(),
            attestation_type: ty.to_owned(),
            weight: None,
            asserted_at: now,
            expires_at: None,
            attestation_envelope: envelope,
            original_content_hash: String::new(),
            scrub_signature_classical: String::new(),
            scrub_signature_pqc: None,
            scrub_key_id: attester.to_owned(),
            scrub_timestamp: now,
            pqc_completed_at: None,
            persist_row_hash: String::new(),
            subject_key_ids: subjects.iter().map(|s| (*s).to_owned()).collect(),
            withdraws_admission_rule: None,
            cohort_scope: crate::federation::types::cohort_scope::FEDERATION.to_owned(),
            tier: attestation_tier::FEDERATION.to_owned(),
            promoted_at: None,
            additional_scrubs: Vec::new(),
        };
        seal::seal_row_in_place(attester, &mut row);
        row
    }

    /// A `scores` row on `dimension`, no subjects — the plain shape.
    fn scores_row(id: &str, attester: &str, dimension: &str) -> Attestation {
        row_with(
            id,
            attester,
            serde_json::json!({ "dimension": dimension }),
            &[],
            attestation_type::SCORES,
        )
    }

    /// The #650 witness. `dir` is the node under migration, `peer` is a SECOND
    /// directory used to prove that a re-stamped row is accepted by somebody
    /// else's put door — the CIRISPersist#649 lesson that local success is not
    /// acceptance.
    pub(crate) async fn exercise_v31_migration(
        dir: &dyn FederationDirectory,
        installer: &dyn LegacyRowInstaller,
        peer: &dyn FederationDirectory,
        suffix: &str,
    ) {
        // Invocation-unique: the postgres arm may share a long-lived database,
        // and every id below is a real UUID because `attestation_id` was
        // `uuid`-typed until V121.
        let run = uuid::Uuid::new_v4().simple().to_string();
        let me = format!("mig-node-{suffix}-{run}");
        let other = format!("mig-peer-{suffix}-{run}");
        for d in [dir, peer] {
            seal::register_hybrid_key(d, &me).await;
            seal::register_hybrid_key(d, &other).await;
        }
        let new_id = || uuid::Uuid::new_v4().to_string();
        let (grant_id, tomb_id, live_id, deadm_id, alien_id, alien_del_id) =
            (new_id(), new_id(), new_id(), new_id(), new_id(), new_id());

        // ── The corpus ──────────────────────────────────────────────────
        //
        // 1. `grant`  — a consent:replication grant WE authored, then withdrew.
        //               THE RESURRECTION CASE.
        // 2. `tomb`   — the withdraws composer that killed it.
        // 3. `live`   — an ordinary live row we authored, on a family with NO
        //               declared load-bearing predicate. Two jobs: the control
        //               (the migration must re-stamp, not merely delete) and
        //               the `Unknown`-verdict arm.
        // 4. `deadm`  — a peer de-admission row: an EXCLUSION.
        // 5. `alien`  — a live federation row a PEER authored (unauthorable).
        // 6. `alien_del` — a delegation a PEER authored. Same unauthorable
        //               shape as `alien` in EVERY respect except that it is
        //               EXCLUSION-BEARING, so it is the arm that makes the
        //               retention rule load-bearing rather than decorative:
        //               `alien` is purged, `alien_del` is not, and the only
        //               thing separating them is `is_exclusion_bearing`.
        // The `payload` is what the #510 closed grammar requires of a consent
        // grant; the prefix content is irrelevant here (the same minimal shape
        // `consent_peer_set`'s own fixture uses).
        let grant = row_with(
            &grant_id,
            &me,
            serde_json::json!({
                "dimension": crate::federation::consent_peer_set::DIMENSION,
                "payload": {"grants": "replication", "attestation_prefixes": ["mig-650:"]},
            }),
            &[&other],
            attestation_type::SCORES,
        );
        let tomb = row_with(
            &tomb_id,
            &me,
            serde_json::json!({
                "references_attestation_id": grant_id,
                "withdrawal_reason": "the subject revoked it",
            }),
            &[],
            attestation_type::WITHDRAWS,
        );
        let live = scores_row(&live_id, &me, "transparency_log:inclusion:v1");
        let deadm = scores_row(
            &deadm_id,
            &me,
            crate::federation::admission::PEER_DEADMISSION_DIMENSION,
        );
        let alien = scores_row(&alien_id, &other, "transparency_log:inclusion:v1");
        // Targets `me`, not itself: a SELF-`delegates_to` is a root charter and
        // carries the whole `check_trust_charter_admission` stack, which is a
        // different subject.
        let mut alien_del = row_with(
            &alien_del_id,
            &other,
            serde_json::json!({
                "dimension": "delegation:migration_fixture:v1",
                "scope": ["infra:serve"],
            }),
            &[],
            attestation_type::DELEGATES_TO,
        );
        alien_del.attested_key_id = me.clone();
        seal::seal_row_in_place(&other, &mut alien_del);

        let corpus = [&grant, &tomb, &live, &deadm, &alien, &alien_del];
        for row in corpus {
            dir.put_attestation(SignedAttestation {
                attestation: row.clone(),
            })
            .await
            .unwrap_or_else(|e| panic!("({suffix}) seed {}: {e}", row.attestation_id));
        }
        // Now make every one of them look like a v30 row AT REST — the one
        // thing no production door can do, because both v31 gates refuse it.
        for row in corpus {
            installer.downgrade_to_v30(&row.attestation_id).await;
        }

        // POSITIVE CONTROL: the downgraded rows really are refused, so "the
        // migration fixed them" is a measurement rather than a tautology.
        let stored_live = dir
            .get_attestation(&live_id)
            .await
            .expect("read")
            .expect("present");
        assert!(
            !classify_shape(&stored_live, chrono::Utc::now()).is_conformant(),
            "({suffix}) the installer did not actually produce a v30-shaped row"
        );
        peer.put_attestation(SignedAttestation {
            attestation: stored_live.clone(),
        })
        .await
        .expect_err(
            "({suffix}) a v30-shaped row must be REFUSED by a peer — if it is not, this whole \
             witness is measuring nothing",
        );

        let signer = FixtureSigner { key_id: me.clone() };

        // ── The DRY RUN reports the same decisions it would apply. ───────
        let preview = run_v31_migration(
            dir,
            &signer,
            &MigrationOptions {
                dry_run: true,
                ..MigrationOptions::default()
            },
        )
        .await
        .expect("({suffix}) dry run");
        let decided = |id: &str| -> Disposition {
            preview
                .rows
                .iter()
                .find(|r| r.attestation_id == id)
                .unwrap_or_else(|| panic!("({suffix}) {id} was not visited"))
                .disposition
                .clone()
        };
        // WITNESS: an `Unknown`-verdict row is KEPT, not purged. `live` sits on
        // a family with no declared load-bearing predicate, so the per-row
        // predicate returns `Unknown` — and `Unknown` is treated as
        // load-bearing, which is the direction the whole routine turns on.
        assert!(
            matches!(
                is_load_bearing(
                    dir,
                    ObjectRef::Attestation {
                        attestation_id: live_id.clone()
                    }
                )
                .await
                .expect("verdict"),
                LoadBearing::Unknown { .. }
            ),
            "({suffix}) the fixture no longer produces an Unknown verdict, so the Unknown arm \
             below is vacuous — pick a family with no declared predicate"
        );
        assert_eq!(
            decided(&live_id),
            Disposition::Restamp,
            "({suffix}) an Unknown-verdict row must be KEPT and re-stamped, never purged"
        );
        assert!(
            matches!(
                decided(&grant_id),
                Disposition::Purge(PurgeReason::Retracted { .. })
            ),
            "({suffix}) a withdrawn grant must be purged, not re-minted"
        );
        // Nothing was written by the preview.
        assert!(
            dir.get_attestation(&grant_id)
                .await
                .expect("read")
                .is_some(),
            "({suffix}) a dry run must not delete anything"
        );

        // ── Run ─────────────────────────────────────────────────────────
        let outcome = run_v31_migration(dir, &signer, &MigrationOptions::default())
            .await
            .expect("({suffix}) migration runs");
        assert_eq!(
            outcome.errors, 0,
            "({suffix}) first run errors: {outcome:?}"
        );

        // ── WITNESS 1 (THE ONE THAT MATTERS): the withdrawn row does NOT
        //    come back. ────────────────────────────────────────────────────
        assert!(
            dir.get_attestation(&grant_id)
                .await
                .expect("read")
                .is_none(),
            "({suffix}) a withdrawn consent grant survived the migration — this is the \
             resurrection case (CIRISPersist#650); outcome = {outcome:?}"
        );

        // ── WITNESS 2: the TOMBSTONE survives, in v31 shape. Purging it is
        //    the other way the grant comes back, one round of anti-entropy
        //    later. ─────────────────────────────────────────────────────────
        let tomb_after = dir
            .get_attestation(&tomb_id)
            .await
            .expect("read")
            .expect("({suffix}) the tombstone must survive — purging it resurrects the grant");
        assert!(
            classify_shape(&tomb_after, chrono::Utc::now()).is_conformant(),
            "({suffix}) the tombstone was kept but not re-stamped"
        );

        // ── WITNESS 3: previously-excluded keys are STILL excluded. ──────
        let deadm_after = dir.get_attestation(&deadm_id).await.expect("read").expect(
            "({suffix}) a peer de-admission row was purged — the reset would re-admit \
                 exactly the key it was meant to exclude (CIRISPersist#650)",
        );
        assert!(
            crate::federation::admission::envelope_dimension(&deadm_after.attestation_envelope)
                == Some(crate::federation::admission::PEER_DEADMISSION_DIMENSION),
            "({suffix}) the de-admission row's dimension was rewritten"
        );

        // ── WITNESS 4: the live row is re-stamped, and a PEER ACCEPTS IT.
        //    Local success is not acceptance (#649). ─────────────────────
        let live_after = dir
            .get_attestation(&live_id)
            .await
            .expect("read")
            .expect("({suffix}) a live row we authored must survive");
        assert!(
            classify_shape(&live_after, chrono::Utc::now()).is_conformant(),
            "({suffix}) the re-stamped row still fails this substrate's own v31 gates"
        );
        assert_eq!(
            live_after.attestation_id, live_id,
            "({suffix}) the re-stamp MUST preserve the identity — a fresh id detaches the row \
             from every composer that references it, which is the second resurrection vector"
        );
        peer.put_attestation(SignedAttestation {
            attestation: live_after.clone(),
        })
        .await
        .unwrap_or_else(|e| {
            panic!(
                "({suffix}) a peer's put_attestation REFUSED the re-stamped row. Local success \
                 is not acceptance — that is the #649 lesson, and a migration whose output no \
                 peer takes has migrated nothing. Refusal: {e}"
            )
        });

        // ── WITNESS 5: a peer-authored legacy row is purged, so its v31
        //    refill is not blocked by its own primary key… ────────────────
        assert!(
            dir.get_attestation(&alien_id)
                .await
                .expect("read")
                .is_none(),
            "({suffix}) a legacy row this node cannot re-author was retained; it blocks its own \
             v31 refill on the primary key"
        );
        // …and its EXCLUSION-BEARING twin — identical in author, tier, shape
        // and unauthorability — is NOT. This pair is what makes the retention
        // rule measurable: remove `is_exclusion_bearing`'s delegation arm and
        // this assertion is the one that reds.
        assert!(
            dir.get_attestation(&alien_del_id)
                .await
                .expect("read")
                .is_some(),
            "({suffix}) a peer-authored DELEGATION was purged. It authorizes every quarantine / \
             moderation / slashing act hanging off it, and its refill is order-dependent — so \
             deleting it re-admits exactly what the reset was meant to exclude \
             (CIRISPersist#650)"
        );

        // ── WITNESS 6: IDEMPOTENCE. A second run changes nothing. ────────
        let second = run_v31_migration(dir, &signer, &MigrationOptions::default())
            .await
            .expect("({suffix}) second run");
        assert!(
            !second.changed_anything(),
            "({suffix}) the migration is not idempotent: second run {second:?}"
        );
        assert_eq!(
            second.errors, 0,
            "({suffix}) the second run reported errors: {second:?}"
        );

        // ── WITNESS 7: INTERRUPTION. Put one row back into v30 shape — the
        //    state a crash mid-run leaves — and the next run COMPLETES it
        //    rather than corrupting it. ────────────────────────────────────
        installer.downgrade_to_v30(&live_id).await;
        let third = run_v31_migration(dir, &signer, &MigrationOptions::default())
            .await
            .expect("({suffix}) resumed run");
        assert_eq!(
            third.restamped, 1,
            "({suffix}) a half-migrated corpus must be COMPLETED by the next run: {third:?}"
        );
        assert_eq!(third.errors, 0, "({suffix}) resumed run errors: {third:?}");
        let live_again = dir
            .get_attestation(&live_id)
            .await
            .expect("read")
            .expect("({suffix}) still there");
        assert!(
            classify_shape(&live_again, chrono::Utc::now()).is_conformant(),
            "({suffix}) the resumed run did not finish the job"
        );
        // And the tombstone did not get taken along for the ride.
        assert!(
            dir.get_attestation(&tomb_id).await.expect("read").is_some(),
            "({suffix}) the resumed run purged the tombstone"
        );

        // ── WITNESS 8: the routine's REACH is one table. The dedicated
        //    revocation plane has NO replication cursor, so its survival is
        //    the whole of the old-keys answer. ────────────────────────────
        assert!(
            dir.revocations_for(&other).await.is_ok(),
            "({suffix}) the revocation plane must still be readable after a migration"
        );
    }

    /// The MUTATION witness: a fold that keeps the INTERIM states (nothing is
    /// treated as retracted) resurrects the withdrawn grant.
    ///
    /// House doctrine — a witness that passes before and after the fix is not a
    /// witness. This drives the SAME decision function with the SAME corpus and
    /// only the fold mutated, and asserts the disposition flips from `Purge` to
    /// `Restamp`: i.e. the withdrawn grant would be re-minted as a valid,
    /// freshly-signed, peer-admissible v31 row.
    pub(crate) fn assert_the_fold_is_load_bearing() {
        let dimension = crate::federation::consent_peer_set::DIMENSION;
        let grant = scores_row("g1", "alice", dimension);
        let tomb = row_with(
            "w1",
            "alice",
            serde_json::json!({ "references_attestation_id": "g1" }),
            &[],
            attestation_type::WITHDRAWS,
        );
        let corpus = vec![grant.clone(), tomb];
        let shape = RowShape::Legacy {
            why: "v30".to_owned(),
        };
        let closure = LoadBearingClosure {
            roots: Vec::new(),
            members: Vec::new(),
            attestation_ids: BTreeSet::new(),
            key_ids: BTreeSet::new(),
            revisits: 0,
            excluded_proven_not_load_bearing: 0,
            completeness: ClosureCompleteness::Truncated {
                budget: 0,
                frontier_remaining: 0,
            },
        };
        let verdict = LoadBearing::Unknown {
            family: "consent:*".to_owned(),
            reason: String::new(),
        };

        // The REAL fold: the grant is retracted, so it is purged.
        let real = fold_retractions(&corpus);
        assert!(matches!(
            classify(
                &grant,
                &shape,
                &real,
                &closure,
                &verdict,
                &Authorship::OwnKey
            ),
            Disposition::Purge(PurgeReason::Retracted { .. })
        ));

        // The MUTATED fold — "replay the interim states": nothing retracts.
        let mutated = RetractionFold::default();
        assert_eq!(
            classify(
                &grant,
                &shape,
                &mutated,
                &closure,
                &verdict,
                &Authorship::OwnKey
            ),
            Disposition::Restamp,
            "with the fold disabled the withdrawn grant is RE-MINTED as a valid v31 row — that \
             is the resurrection this witness exists to detect"
        );
    }
}
