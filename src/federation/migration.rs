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
//! 2. `federation_revocations` had **no replication serve cursor at all** —
//!    purge it and anti-entropy could not refill it, so the exclusion was gone
//!    permanently. v31.1.0 (CIRISPersist#655) added
//!    `list_signed_revocations_since`, which changes the blast radius but NOT
//!    this conclusion: a refill needs some peer to still hold the row, so the
//!    cursor helps a single node that lost state and does nothing for a purge
//!    that ran everywhere or for a plane no peer retained. The same is now true
//!    of `federation_role_withdrawals`, whose rebuild path (CIRISPersist#662)
//!    is a LOCAL re-derivation from replicated accord evidence — it needs the
//!    evidence to have survived somewhere too. "Recoverable in principle" is
//!    not "safe to delete".
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

use super::load_bearing::ObjectRef;
use super::types::{attestation_tier, attestation_type, Attestation};
use super::{Error, FederationDirectory};

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
    let composers: Vec<Attestation> = rows
        .iter()
        .filter(|r| super::precedence::is_structural_composer(&r.attestation_type))
        .cloned()
        .collect();
    let authors: BTreeMap<String, RetractionTarget> = rows
        .iter()
        .map(|r| (r.attestation_id.clone(), RetractionTarget::of(r)))
        .collect();
    fold_retractions_from(&composers, &authors)
}

/// v61.1.0 (61.1 review M1) — what [`fold_retractions_from`] keeps of a
/// target while it streams the corpus: its author (the same-attester arm) and
/// its [`StampPolicy`](super::precedence::StampPolicy) (the stamped arm).
#[derive(Debug, Clone)]
pub struct RetractionTarget {
    /// The target's `attesting_key_id`.
    pub author: String,
    /// Which stamps entitle a non-producer retraction of it.
    pub policy: super::precedence::StampPolicy,
}

impl RetractionTarget {
    /// The target summary of `row`.
    #[must_use]
    pub fn of(row: &Attestation) -> Self {
        Self {
            author: row.attesting_key_id.clone(),
            policy: super::precedence::stamp_policy(row),
        }
    }
}

/// [`fold_retractions`] over the two things it actually needs: every structural
/// composer, and an `attestation_id → attesting_key_id` map for the WHOLE
/// corpus.
///
/// Split out so the boot scan can stream the corpus and keep only these two —
/// the composers are a small fraction of any real corpus, and the author map is
/// two short strings a row — instead of materializing every envelope in memory
/// to answer a question about a handful of them.
#[must_use]
pub fn fold_retractions_from(
    composers: &[Attestation],
    authors: &BTreeMap<String, RetractionTarget>,
) -> RetractionFold {
    use super::precedence::{precedence_winner, references_attestation_id_from_envelope};

    // Group composers by (attester, target). CEG §6.1 rule 4: cross-attester
    // chains are INDEPENDENT, so each group resolves its own winner.
    let mut groups: BTreeMap<(&str, &str), Vec<&Attestation>> = BTreeMap::new();
    let mut composer_ids: BTreeSet<String> = BTreeSet::new();
    for row in composers {
        debug_assert!(super::precedence::is_structural_composer(
            &row.attestation_type
        ));
        composer_ids.insert(row.attestation_id.clone());
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
        // cross-attester chain: it retracts only when the write door ADMITTED
        // it (a `withdraws` carrying its admission rule — a subject's, an
        // owner's, a delegate's). That is the rule the read plane's Live
        // filter applies (v51.2.0, CIRISPersist#945), and this fold mirrors
        // it. A target absent from the corpus is ignored — there is nothing
        // here to retract.
        let Some(target_author) = authors.get(target) else {
            continue;
        };
        // v61.1.0 (61.1 review M1) — the non-producer arm asks the same
        // policy `precedence::retraction_entitled` asks, so this fold and the
        // read fold cannot disagree on a legacy stamp.
        if target_author.author != winner.attesting_key_id
            && !super::precedence::stamp_entitles(winner, target_author.policy)
        {
            continue;
        }
        retracted.insert(target.to_owned(), winner.attestation_id.clone());
    }

    RetractionFold {
        retracted,
        composers: composer_ids,
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

/// Classify a stored row against the v31 gates — both bindings AND the #647
/// at-rest invariant.
///
/// Asks the REAL gates ([`super::admission::check_row_column_binding`] and
/// [`super::admission::check_instant_binding`]) rather than probing for the
/// envelope keys, so "conformant" here means exactly "admissible at a peer's
/// put door" and cannot drift from it. `now` is threaded so the skew arm is
/// deterministic in a witness.
#[must_use]
pub fn classify_shape(row: &Attestation, now: chrono::DateTime<chrono::Utc>) -> RowShape {
    // v31.0.0 (CIRISPersist#650) — **EVALUATED AT THE ROW'S OWN INSTANT, NOT
    // AT THE WALL CLOCK.**
    //
    // `check_instant_binding` has four arms, and only three are about SHAPE
    // (the signed twins are present, they parse, they equal their columns, they
    // are at substrate resolution). The fourth is a FRESHNESS bound: reject
    // `asserted_at > now + max_skew`. Mapping that arm to `Legacy` made this
    // routine read a CLOCK PROBLEM as a shape problem — and the disposition of
    // a legacy peer row is `purge_unauthorable_legacy`.
    //
    // So on a node whose clock is an hour behind (a VM snapshot restore, a
    // container booting before NTP), a correctly-sealed peer corpus classified
    // as legacy and was DELETED, at boot, silently. Our own rows survived by
    // accident: the reseal door re-checks skew against the real clock and
    // errors out, which is recorded as a per-row error rather than a purge.
    //
    // Passing the row's own `asserted_at` as `now` makes the skew term
    // identically zero, so what remains is exactly the binding. Freshness is a
    // real property and is still enforced where it belongs — at the put doors,
    // at promotion, and in `check_reseal_admission`, all against the true
    // clock. It is not evidence about an envelope's shape.
    if let Err(e) = super::admission::check_instant_binding(
        row,
        row.asserted_at,
        super::admission::DEFAULT_MAX_TOUCH_SKEW,
    ) {
        return RowShape::Legacy { why: e.to_string() };
    }
    let _ = now;
    if let Err(e) = super::admission::check_row_column_binding(row) {
        return RowShape::Legacy { why: e.to_string() };
    }
    // v31.0.0 (CIRISPersist#647) — the at-rest form is part of "v31-shaped".
    // A row whose stored column does not sha256 to its `original_content_hash`
    // is one the substrate's own audit predicate rejects, so calling it
    // conformant would let the idempotence arm skip a row that still needs
    // work. It also makes the short-circuit in `run_v31_migration` honest: a
    // corpus it calls finished is one every at-rest check passes.
    if let Err(e) = super::canonical_at_rest::check_canonical_at_rest(&row.attestation_envelope) {
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

/// v31.0.0 (CIRISPersist#650) — the CLOSED set of never-purge classes.
///
/// # Why an enum and a table rather than an `if`-chain
///
/// The first cut of [`is_exclusion_bearing`] was a hand-maintained chain of
/// prefix tests. It shipped three defects of one kind, and an audit found all
/// three: `revocation:peer_admission:v1` was matched with `==` while every
/// other class used `starts_with`, so `revocation:partner:fraud` (declared
/// NON-ROLLBACKABLE in the manifest) and even a future `:v2` of the same class
/// fell through and were purged; an unreadable `dimension` fell through the
/// `?` and was treated as "not exclusion-bearing", i.e. an unreadable input
/// answered PROVEN-SAFE-TO-DELETE; and a class added later would simply not be
/// on the list, with nothing to notice.
///
/// All three are the same defect: **a never-purge list that relies on someone
/// remembering.** The file next door states the opposite discipline in its own
/// doc — *"adding an arm without declaring its predicate is a compile
/// failure … exhaustive by construction rather than by anyone remembering"* —
/// and this was the one place across the two that did not follow it.
///
/// So: a closed enum, an [`ExclusionClass::ALL`] array whose length the
/// compiler checks, and two `match`es with no wildcard arm. Adding a variant
/// without declaring its rationale and its matcher is a **compile failure**;
/// adding one without listing it in `ALL` is a **test failure**
/// ([`tests::every_exclusion_class_is_reachable_and_declared`]).
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ExclusionClass {
    /// A `supersedes` / `withdraws` / `recants` row — the TOMBSTONES.
    StructuralComposer,
    /// Any `delegates_to` row — the plane that AUTHORIZES the acts below, and
    /// the plane the owner claim itself lives on.
    Delegation,
    /// `revocation:*` — peer de-admission (AV-77) and every other revocation
    /// leaf. Prefix-matched, deliberately: the `==` on one leaf is the defect
    /// that produced this type.
    Revocation,
    /// `quarantine:*` — withhold / release markers.
    Quarantine,
    /// `moderation:*` — §11.10 reports.
    Moderation,
    /// `reconsideration:*` — §11.10 review reports.
    Reconsideration,
    /// `slashing:*` — slashing outcomes.
    Slashing,
    /// `objection:*` — reverse-quorum objections, dismissals and ballots.
    Objection,
    /// v54.1.0 (CIRISPersist#1054) — the accountability record
    /// ([`ACCOUNTABILITY_RECORD_PREFIXES`]) that no prefix class above
    /// reaches: `key:revocation` and `moderation_track_record:*`. Matched by
    /// [`accountability_record_family`], the list the steward purge reads too,
    /// so the two doors cannot drift; its own `revocation:`, `moderation:` and
    /// `slashing:` entries resolve to the narrower classes above first.
    AccountabilityRecord,
    /// **The dimension could not be read** — absent, or not a string.
    ///
    /// FAIL-SECURE, and the polarity is the whole point: this predicate asks
    /// *"is this too dangerous to delete?"*, so an unreadable input must answer
    /// YES. Treating it as "not exclusion-bearing" is the substrate's own
    /// [`LoadBearing`](super::load_bearing::LoadBearing) rule inverted — an
    /// unproven `No` read as a proven one.
    UnreadableDimension,
}

impl ExclusionClass {
    /// Every class, in declaration order. The gate iterates this; its LENGTH is
    /// compiler-checked against the variant set by
    /// [`tests::every_exclusion_class_is_reachable_and_declared`].
    pub const ALL: [ExclusionClass; 10] = [
        ExclusionClass::StructuralComposer,
        ExclusionClass::Delegation,
        ExclusionClass::Revocation,
        ExclusionClass::Quarantine,
        ExclusionClass::Moderation,
        ExclusionClass::Reconsideration,
        ExclusionClass::Slashing,
        ExclusionClass::Objection,
        ExclusionClass::AccountabilityRecord,
        ExclusionClass::UnreadableDimension,
    ];

    /// The dimension PREFIX that identifies this class, or `None` for the
    /// classes identified structurally (by `attestation_type`) or by the
    /// absence of a readable dimension. Exhaustive — no wildcard arm.
    #[must_use]
    pub const fn dimension_prefix(self) -> Option<&'static str> {
        match self {
            // AccountabilityRecord is the shared list's predicate, not one prefix.
            Self::StructuralComposer
            | Self::Delegation
            | Self::UnreadableDimension
            | Self::AccountabilityRecord => None,
            // The #650 audit's finding: PREFIX, never `==`. A versioned leaf
            // (`:v2`) and a sibling leaf (`revocation:partner:fraud`) are the
            // same class and must inherit the same protection.
            Self::Revocation => Some("revocation:"),
            Self::Quarantine => Some(super::admission::QUARANTINE_DIMENSION_PREFIX),
            Self::Moderation => Some(super::admission::MODERATION_DIMENSION_PREFIX),
            Self::Reconsideration => Some(super::admission::RECONSIDERATION_DIMENSION_PREFIX),
            Self::Slashing => Some("slashing:"),
            Self::Objection => Some("objection:"),
        }
    }

    /// Why deleting a row of this class would be unsafe. Exhaustive.
    #[must_use]
    pub const fn why(self) -> &'static str {
        match self {
            Self::StructuralComposer => {
                "a structural composer is a TOMBSTONE: purging it resurrects everything it \
                 retracted"
            }
            Self::Delegation => {
                "the delegation plane AUTHORIZES quarantine / moderation / slashing acts and \
                 carries the owner claim; without it those acts are inadmissible on refill"
            }
            Self::Revocation => {
                "a revocation row — peer de-admission is AV-77's entire defence against a \
                 sanctioned peer, and the manifest declares other leaves of this family \
                 NON-ROLLBACKABLE"
            }
            Self::Quarantine => "a quarantine marker withholds a key's rows from serving",
            Self::Moderation => "a §11.10 moderation report",
            Self::Reconsideration => "a §11.10 reconsideration / review report",
            Self::Slashing => "a slashing outcome",
            Self::Objection => "a reverse-quorum objection, dismissal or ballot",
            Self::AccountabilityRecord => {
                "the accountability record (`key:revocation`, `moderation_track_record:*`), \
                 never purgeable by the root or anyone (CLM-accountability-record-unpurgeable)"
            }
            Self::UnreadableDimension => {
                "the row's `dimension` is absent or not a string, so this predicate cannot tell \
                 what it is. It asks whether the row is too dangerous to delete, and an \
                 unreadable input answers YES — an unproven `No` is not a proven one"
            }
        }
    }
}

/// CLM-accountability-record-unpurgeable (CIRISConstitution rc8@8c8f536) —
/// the dimension families the text names EXACTLY as the accountability record
/// no purge may reach, "by the root or anyone". ONE list, read by both purge
/// doors (CIRISPersist#1054): the reset door through [`is_exclusion_bearing`]
/// ([`ExclusionClass::AccountabilityRecord`]) and the steward purge
/// (`steward_purge`'s retraction check). Two lists drifted once: the steward
/// purge refused `key:revocation` and `moderation_track_record:*` while this
/// door, matching [`ExclusionClass`] prefixes only, deleted them.
///
/// v57.0.0 (CIRISPersist#988 item 2) — `hard_case:` joins the list. A
/// `hard_case:{kind}` row is the node's own accountability record (CC 3.1.9.4;
/// CIRISConstitution#170 asks the steward to add it to CC 2.4.1.1's set, in
/// the protective direction). It inherits the refusal from this table, on
/// both purge doors and on the serve read, rather than from a special case in
/// any door.
///
/// Replaced by the family model's `accountability_record` column when
/// CIRISConstitution adds it (after v62.0).
pub const ACCOUNTABILITY_RECORD_PREFIXES: &[&str] = &[
    "revocation:",
    "key:revocation",
    "moderation:",
    "moderation_track_record:",
    "slashing:",
    "hard_case:",
];

/// The accountability family `dimension` belongs to, if any
/// ([`ACCOUNTABILITY_RECORD_PREFIXES`]).
#[must_use]
pub fn accountability_record_family(dimension: &str) -> Option<&'static str> {
    ACCOUNTABILITY_RECORD_PREFIXES
        .iter()
        .copied()
        .find(|p| dimension.starts_with(p))
}

/// v54.1.0 (Codex on PR #1057) — [`accountability_record_family`] as a SQL
/// predicate over the text column `column` (the generated `dimension` column
/// of `federation_attestations`), rendered FROM
/// [`ACCOUNTABILITY_RECORD_PREFIXES`] so the serve read and the purge delete
/// door ask the one list, never a second spelling of it. `substr` is a prefix
/// test with no pattern syntax to escape (a LIKE would read the `_` in
/// `moderation_track_record:` as a wildcard), the same in SQLite and Postgres;
/// a NULL column is not an accountability record (`COALESCE` to false, as the
/// Rust predicate answers `None` for a row with no dimension).
#[must_use]
pub fn accountability_record_sql(column: &str) -> String {
    let arms: Vec<String> = ACCOUNTABILITY_RECORD_PREFIXES
        .iter()
        .map(|p| {
            format!(
                "substr({column}, 1, {}) = '{}'",
                p.chars().count(),
                p.replace('\'', "''")
            )
        })
        .collect();
    format!("COALESCE(({}), FALSE)", arms.join(" OR "))
}

/// **The rows that carry an EXCLUSION — never purged.**
///
/// See the module doc: exclusion of a previously slashed / leaked / de-admitted
/// key is not structural, does not come from the trust root, and for the rows
/// that live in `federation_attestations` it depends on those rows surviving.
/// Returns the [`ExclusionClass`] whose deletion would re-admit exactly what a
/// reset is meant to remove.
///
/// A retracted exclusion-bearing row stays retained too — the fold already
/// hides it from every read, so retention is inert, while deletion would be
/// irreversible on a class whose refill is order-dependent and, for
/// `federation_revocations`, impossible.
#[must_use]
pub fn is_exclusion_bearing(row: &Attestation) -> Option<ExclusionClass> {
    // Structural first: these are identified by `attestation_type` and must not
    // depend on a readable dimension.
    if super::precedence::is_structural_composer(&row.attestation_type) {
        return Some(ExclusionClass::StructuralComposer);
    }
    if row.attestation_type == attestation_type::DELEGATES_TO {
        return Some(ExclusionClass::Delegation);
    }
    // FAIL-SECURE on an unreadable dimension. `envelope_dimension` returns
    // `None` for an absent key AND for a non-string one; the earlier `?` here
    // turned both into "safe to delete".
    let Some(dimension) = super::admission::envelope_dimension(&row.attestation_envelope) else {
        return Some(ExclusionClass::UnreadableDimension);
    };
    ExclusionClass::ALL
        .into_iter()
        .find(|c| {
            c.dimension_prefix()
                .is_some_and(|p| dimension.starts_with(p))
        })
        .or_else(|| {
            accountability_record_family(dimension).map(|_| ExclusionClass::AccountabilityRecord)
        })
}

/// v31.0.0 (CIRISPersist#650) — **the purge door's own gate.**
///
/// [`classify`] is where the decision is made, and it is careful. That is not
/// enough: a delete door whose safety lives entirely in its caller is the shape
/// CIRISPersist#652 had (a write door bypassing the gates its siblings ran), and
/// the failure mode here is worse because it is unrecoverable. So the door
/// re-asks the one question whose wrong answer cannot be undone — **is this row
/// exclusion-bearing?** — and refuses if so, whatever the caller believes.
///
/// Deliberately NOT a re-run of the whole matrix. The door cannot see the fold
/// or the corpus, so it cannot re-derive "retracted" or "foreign"; re-asking
/// only what it can answer from the row alone is what keeps this a real check
/// rather than a second, weaker copy of `classify` that could drift from it.
///
/// # Errors
///
/// [`Error::InvalidArgument`] naming the class, if the row is exclusion-bearing.
pub fn check_purge_admission(row: &Attestation) -> Result<(), Error> {
    if let Some(class) = is_exclusion_bearing(row) {
        return Err(Error::InvalidArgument(format!(
            "refusing to purge attestation {}: {} (CIRISPersist#650). Deleting it would \
             re-admit exactly what the reset excludes, and this substrate cannot refill it — \
             the dedicated revocation plane has no replication cursor at all",
            row.attestation_id,
            class.why(),
        )));
    }
    Ok(())
}

/// **Does this row carry co-signatures this node cannot reconstruct?**
///
/// A row with a non-empty `additional_scrubs` set is an m-of-n statement: the
/// base `scrub_key_id`/`scrub_signature_*` is signature #1 and every entry here
/// is another party's, all over the SAME canonical envelope bytes
/// ([`Attestation::scrubs`](super::types::Attestation::scrubs)). Persist holds
/// exactly one of those keys.
///
/// So a re-stamp — which necessarily changes the bytes — can re-sign OUR part
/// and nobody else's. The row would survive, still validly signed, **by one
/// key**: an m-of-n silently degraded to a 1-of-1, with no attacker involved
/// and no error at the site that did it. That is worse than a purge. A purge is
/// visible and the row is gone; this leaves a row that LOOKS valid and has
/// quietly lost the evidence its authority rests on.
///
/// # Which rows, and what breaks
///
/// The field is authority-bearing on attestation rows in four places, and every
/// one of them counts DISTINCT VERIFIED co-signatures through the single shared
/// body [`count_distinct_roster_scrubs`](super::reverse_quorum):
///
/// - [`trust_root::family_quorum_over`](super::trust_root) — the FAMILY CHARTER
///   quorum. Losing co-scrubs here means the charter no longer reaches its
///   threshold and the node's constitutional trust root stops validating.
/// - [`reverse_quorum`](super::reverse_quorum) — the m-of-n UNDO half of the
///   reverse quorum (`objection:dismissed:v1`). A dismissal below threshold is
///   not counted, so the objection stands.
/// - [`ownership_reclaim`](super::ownership_reclaim) — the WA finding that
///   authorizes a CC 3.2 reclaim, and the node's own co-signature on the fresh
///   post-reclaim owner-binding.
///
/// **The direction is uniformly fail-CLOSED**, which is the one piece of good
/// news: a thinned scrub set makes a quorum read as NOT MET, never as met. The
/// 1-of-N *protect* side of the reverse quorum does not read this field at all,
/// so no exclusion is ever weakened by losing it. But fail-closed here means an
/// authority that WAS conferred silently reads as never conferred, and only a
/// re-run of the original ceremony can restore it — which a boot-time migration
/// has no way to perform.
///
/// # Why promotion's precedent does NOT transfer
///
/// `promote_attestation` clears `additional_scrubs`, and this routine originally
/// cited that as precedent. It is the opposite case, and the promotion code says
/// so in its own words: *"A local-tier row defers its signature, so any
/// `additional_scrubs` it carried were STORED WITHOUT EVER BEING VERIFIED …
/// Co-signatures are earned at the ceremony that mints a federation-tier row,
/// never inherited by a promotion."* Promotion discards co-scrubs that were
/// **never verified**, on its way INTO the plane that verifies them. This
/// routine would discard co-scrubs that **were** verified — every one of them
/// checked at ingest by
/// [`verify_federation_tier_ingest`](super::tier_ingest) — and there is no
/// ceremony after a migration to earn them back.
///
/// So a co-scrubbed row is treated exactly like one this node did not author:
/// retained, reported, and left for an operator. We can re-sign our own part;
/// we cannot reconstruct anyone else's, and degrading authority we cannot
/// restore is not a migration's decision to make.
#[must_use]
pub fn is_co_scrubbed(row: &Attestation) -> bool {
    !row.additional_scrubs.is_empty()
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
    /// BLOCKS its own v31 replacement from landing.
    ///
    /// # This is licensed by an OPERATOR DECISION, not by a proof
    ///
    /// Stated plainly because the distinction is what separates this arm from
    /// the `ProvablyInert` arm that was removed. The operator's instruction is
    /// that *"the rest can be dumped and re-popped when valid via replication
    /// plane"*, and the asymmetry that makes it defensible is that these rows
    /// are PEER-SOURCED: a federation-tier row this node cannot re-author
    /// arrived from somewhere, so a copy demonstrably existed elsewhere at
    /// least once.
    ///
    /// **That is still not "they kept it."** `AntiEntropy`'s own doc demolishes
    /// the stronger reading — *"a pull surface does not learn who pulled, nor
    /// whether they kept it"* — and `anti_entropy_satisfied` is structurally
    /// `Unverifiable` on this substrate. So `tier == federation` is standing in
    /// for a residence proof this substrate cannot produce. What can go wrong,
    /// concretely: the origin peer is gone, has been de-admitted, or dropped the
    /// row itself, and then nothing refills it.
    ///
    /// Two things make it survivable, and both must stay:
    /// [`is_exclusion_bearing`] carves out every class whose loss would
    /// re-admit a key the mesh excluded, and the count is reported in
    /// [`MigrationOutcome::purged_unauthorable`] so an operator can see how much
    /// was dumped on the assumption.
    UnauthorableLegacy {
        /// Who signed it.
        attesting_key_id: String,
    },
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
/// 1. **Conformant ⇒ untouched, whatever else is true of it.** This routine is
///    a SHAPE transition, not a garbage collector. It leads because putting it
///    anywhere else made the migration delete rows that were never a v31
///    problem — see the note below, which is a defect this arm order fixes.
/// 2. **Co-scrubbed ⇒ retain, never re-stamp.** We hold one key of an m-of-n.
///    Re-signing drops everyone else's signature and degrades authority we
///    cannot restore — see [`is_co_scrubbed`]. Ahead of the exclusion arm
///    because the rows that carry co-scrubs are largely the same rows.
/// 3. **Exclusion-bearing ⇒ NEVER purge.** Ahead of the retraction arm on
///    purpose: a retracted tombstone that got deleted would revive whatever it
///    retracted. `Unknown`-adjacent by nature (we cannot prove an exclusion is
///    spent), so keeping is the safe side. Re-stamped when we can author it,
///    otherwise [`Disposition::RetainInert`].
/// 4. **Retracted AND legacy ⇒ purge.** The author's own later statement is the
///    proof. This is the arm that makes the migration carry the FINAL state and
///    not the interim ones. Not `Unknown` — a live composer is a decisive `No`.
/// 5. **Ours ⇒ re-stamp.** Unconditionally: this routine has NO arm that
///    deletes a row of ours that nobody retracted. See the note below.
/// 6. **Not ours, local tier ⇒ retain inert.** A local-tier row lives nowhere
///    else; no peer can refill it, so deletion is unrecoverable.
/// 7. **Not ours, federation tier, and NOT positively load-bearing ⇒ purge.**
///    A [`LoadBearing::Yes`](super::load_bearing::LoadBearing) retains: the
///    operator's licence covers rows we merely hold, not rows this node can see
///    something depends on. The ONLY arm that deletes
///    something nobody retracted, and it is licensed by an OPERATOR DECISION
///    ("dumped and re-popped via the replication plane"), not by a proof of
///    deadness or of residence — see [`PurgeReason::UnauthorableLegacy`], which
///    names what can go wrong.
///
/// # Why there is no "provably inert" purge, and why the closure is not consulted
///
/// An earlier cut had a fifth disposition: ours, legacy, federation-tier,
/// [`LoadBearing::No`] and absent from a COMPLETE
/// [`load_bearing_closure`](super::load_bearing::load_bearing_closure) ⇒ purge.
/// It was documented as four independent conjuncts. **Three of them were one
/// fact wearing three hats**, and a reviewer's probe found it by running the
/// real routine:
///
/// 1. `retained_replication` returns `No` for a `consent:replication:v1` grant
///    whose named peer holds no rows here yet;
/// 2. the closure walk reaches that row and **prunes it BECAUSE the verdict is
///    `No`** (a dead branch does not keep its children alive);
/// 3. the arm then read "absent from the closure" as INDEPENDENT evidence.
///
/// So the guard reduced to `verdict == No`, and the row it deleted was a grant
/// naming a **newly-added peer** — the normal state of a peer you have added
/// and not yet synced with. Deleting it makes that peer's rows inadmissible, so
/// it can never bootstrap: self-fulfilling, silent, and permanent, with the
/// operator seeing a successful migration.
///
/// The arm should never have existed, and the reason is written in
/// [`super::load_bearing`]'s own module doc: *"a `No` from this module is NOT a
/// licence to drop anything, because dropping a copy that has nowhere else to
/// live is data loss wearing a GC costume."* Release is
/// [`may_release_copy`](super::load_bearing::may_release_copy) —
/// `is_load_bearing == No` **∧** `anti_entropy_satisfied` — and the second
/// conjunct is structurally unsatisfiable on this substrate (no peer transport,
/// no acknowledgment plane), so `MayRelease::Yes` is unreachable BY DESIGN and
/// there is a test pinning that. This routine had built precisely the thing
/// that module warns about: *"a helper that returned only the first half would
/// be worse than nothing, because it would look complete."*
///
/// Hence the standing rule, enforced by this function's SIGNATURE rather than
/// by its body: **`classify` cannot see the closure at all.** Closure
/// membership is reachability evidence, and reachability evidence may only ever
/// RETAIN. Nothing here can be talked into deleting on it, because nothing here
/// is given it. `load_bearing_closure` remains what CIRISPersist#650 asked for
/// and is separately witnessed; the re-stamp set this routine produces is a
/// SUPERSET of the closure, which satisfies "re-stamp that closure" without
/// letting the walk license a deletion.
///
/// # Why arm 1 leads — a migration is not a garbage collector
///
/// With the retraction arm ahead of the conformance arm, a v31-shaped row that
/// some live composer had retracted was purged — **on every boot, forever.**
/// That is fine for the v30 rows this routine exists to clear, and wrong for
/// everything after: ordinary CEG history (a withdrawn grant, both rows minted
/// under v31) would be deleted by a routine whose remit is the envelope shape.
/// The retraction arm now applies only to rows that are also LEGACY, so the
/// migration converges: once a corpus is v31 it is a no-op, and retracted
/// history stays exactly as retracted history is meant to — at rest, hidden by
/// the fold, not collected.
#[must_use]
pub fn classify(
    row: &Attestation,
    shape: &RowShape,
    fold: &RetractionFold,
    authorship: &Authorship,
    positively_load_bearing: bool,
) -> Disposition {
    // 1. ALREADY v31 — nothing to do, whatever else is true of it. The
    //    idempotence arm, and the arm that keeps this routine from turning into
    //    a collector of retracted history.
    if shape.is_conformant() {
        return Disposition::AlreadyConformant;
    }

    // 2. CO-SCRUBBED — an m-of-n we hold ONE key of. Ahead of every arm that
    //    could re-stamp, including the exclusion arm: a dismissal, a charter
    //    and an owner-binding are all exclusion-bearing AND co-scrubbed, so
    //    checking this second is the difference between retaining the evidence
    //    and silently re-minting the row as a 1-of-1.
    if is_co_scrubbed(row) {
        return Disposition::RetainInert {
            why: format!(
                "the row carries {} co-scrub(s) over the OLD envelope bytes and this node holds \
                 only its own key. Re-stamping would re-sign our part and drop everyone else's, \
                 turning an m-of-n into a 1-of-1 with no error at the site that did it — worse \
                 than a purge, because the result LOOKS valid. Retained for operator review \
                 (CIRISPersist#650)",
                row.additional_scrubs.len(),
            ),
        };
    }

    // 3. EXCLUSION-BEARING — never purge. Leads the retraction arm.
    if let Some(class) = is_exclusion_bearing(row) {
        if authorship.can_reauthor() {
            return Disposition::Restamp;
        }
        return Disposition::RetainInert {
            why: format!(
                "{} — and this node cannot re-author it, so it is kept in v30 shape rather \
                 than deleted (CIRISPersist#650: exclusion is not structural and the dedicated \
                 revocation plane has no replication cursor)",
                class.why(),
            ),
        };
    }

    // 4. RETRACTED, and legacy. The author's own later statement is the proof.
    if let Some(by) = fold.retracted_by(&row.attestation_id) {
        return Disposition::Purge(PurgeReason::Retracted { by: by.to_owned() });
    }

    // 5. OURS. Unconditional: there is no arm here that deletes a row of ours
    //    that nobody retracted, and the closure is not consulted at all — see
    //    the note on this function.
    if authorship.can_reauthor() {
        return Disposition::Restamp;
    }

    // 6. Not ours, and nowhere else to come back from.
    if row.tier == attestation_tier::LOCAL {
        return Disposition::RetainInert {
            why:
                "a local-tier row this node did not seal exists nowhere else — no peer can refill \
                  it, so deleting it is unrecoverable (a subject-side revocation in transit is \
                  exactly this shape)"
                    .to_owned(),
        };
    }

    // 7. Not ours, federation tier: its author is its source.
    //
    // …UNLESS the substrate POSITIVELY asserts the row is load bearing.
    // `trust:*` is manifest-declared *"can never be inferred inert"*, and
    // deleting a row this node's own predicate says something depends on —
    // while betting on a refill it cannot verify — is indefensible whatever
    // the operator's recoverability licence says.
    //
    // The polarity is deliberately ASYMMETRIC and this is the only place in the
    // routine where that is true: a `Yes` RETAINS, and a `No`/`Unknown` does
    // NOT license the delete — the operator's decision does. Reachability
    // evidence may only ever retain (see the note on this function), so reading
    // `Unknown` as permission would be the removed arm's mistake again.
    if positively_load_bearing {
        return Disposition::RetainInert {
            why: "this node's own reachability predicate returns `Yes` — something held here \
                  depends on this row. The operator's \"dump and re-pop via replication\" \
                  licence covers rows we merely hold, not rows we can see are load bearing \
                  (CIRISPersist#650)"
                .to_owned(),
        };
    }

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
/// 3. **THE #647 AT-REST INVARIANT.** This is the fourth writer of
///    `attestation_envelope`; the other three canonicalize on the way in. A row
///    whose stored column does not `sha256sum` to its `original_content_hash`
///    is one the substrate's own audit predicate rejects, so it is refused here
///    rather than written.
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
    // v31.0.0 (CIRISPersist#647) — THE AT-REST INVARIANT, at the door.
    //
    // #647's promise is that `sha256sum` over the stored `attestation_envelope`
    // column equals `original_content_hash`, so the artifact is decipherable by
    // hand. The three ingest doors keep it by canonicalizing on the way in;
    // this door is a FOURTH writer of that column, so it has to ask. Gating
    // rather than silently canonicalizing here is deliberate: the caller
    // computed a hash and a signature over some bytes, and a door that quietly
    // rewrote those bytes afterwards would recreate the #649 defect — the
    // stored envelope and the signature covering it drifting apart.
    super::canonical_at_rest::check_canonical_at_rest(&resealed.attestation_envelope)?;
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
    if let Ok(Some(owner)) = super::admission::owner_of_unmarked(directory, self_key_id).await {
        roots.push(ObjectRef::KeyRecord { key_id: owner });
    }
    Ok(roots)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::federation::types::{attestation_tier, attestation_type};

    /// v31.0.0 (CIRISPersist#650) — THE MUTATION. Pure: disable the fold
    /// (replay the interim states) and the withdrawn grant flips from `Purge`
    /// to `Restamp` — i.e. it is re-minted as a valid, freshly-signed,
    /// peer-admissible v31 row.
    #[cfg(any(feature = "sqlite", feature = "postgres"))]
    #[test]
    fn the_v31_fold_is_load_bearing_650() {
        super::test_support::assert_the_fold_is_load_bearing();
    }

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

        // A DIFFERENT attester's UNADMITTED composer does not — CEG §6.1 rule
        // 4, and the same rule every backend's `LifecycleView::Live` filter
        // applies …
        let fold = fold_retractions(&[target.clone(), theirs.clone()]);
        assert!(!fold.is_retracted("t1"));
        // … but one the write door admitted (v51.2.0, #945: a subject's
        // rule-2 revocation, an owner's rule 1) retracts, as the Live filter
        // now hides it.
        let mut admitted = theirs;
        admitted.withdraws_admission_rule = Some(2);
        let fold = fold_retractions(&[target, admitted]);
        assert!(fold.is_retracted("t1"));
        assert_eq!(fold.retracted_by("t1"), Some("w2"));
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
        let ours = Authorship::OwnKey;

        assert!(matches!(
            classify(&grant, &legacy(), &fold, &ours, false,),
            Disposition::Purge(PurgeReason::Retracted { .. })
        ));
        // The TOMBSTONE is re-stamped, never purged — purging it is the other
        // way the grant comes back.
        assert_eq!(
            classify(&tombstone, &legacy(), &fold, &ours, false,),
            Disposition::Restamp
        );
    }

    /// v31.0.0 (CIRISPersist#650) — **THE RULING: there is no purge-on-inert
    /// arm, and a proven `No` on a row of OURS is not a licence to delete it.**
    ///
    /// The removed arm was `LoadBearing::No AND federation tier AND outside a
    /// COMPLETE owner closure`, documented as four independent conjuncts. Three
    /// of them were one fact: the closure walk PRUNES a row precisely because
    /// its verdict is `No`, so "outside the closure" was the verdict counted
    /// twice, and `tier == federation` was standing in for a residence proof
    /// `anti_entropy_satisfied` refuses to make.
    ///
    /// This pins the outcome rather than the reasoning: for a row we authored,
    /// EVERY verdict lands on the re-stamp side. The function no longer takes a
    /// verdict or a closure at all, so the property is enforced by the
    /// signature; this test is the behavioural statement of it.
    #[test]
    fn a_proven_no_on_our_own_row_is_re_stamped_never_purged() {
        let mut r = row("a1", "me", attestation_type::SCORES, env("x:y:v1", None));
        let fold = RetractionFold::default();
        for tier in [attestation_tier::FEDERATION, attestation_tier::LOCAL] {
            r.tier = tier.to_owned();
            assert_eq!(
                classify(&r, &legacy(), &fold, &Authorship::OwnKey, false),
                Disposition::Restamp,
                "a row we authored is never deleted on a reachability verdict — release is \
                 `may_release_copy`, whose anti-entropy conjunct this substrate cannot satisfy"
            );
        }
    }

    #[test]
    fn every_exclusion_bearing_class_survives_a_purge() {
        let fold = RetractionFold::default();
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
                // Foreign AND federation tier — every condition that would
                // otherwise purge.
                &foreign,
                false,
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
            classify(&ordinary, &legacy(), &fold, &foreign, false,),
            Disposition::Purge(PurgeReason::UnauthorableLegacy { .. })
        ));
    }

    /// v31.0.0 (CIRISPersist#650) — **THE EXHAUSTIVENESS GATE.**
    ///
    /// The never-purge list used to be a hand-maintained `if`-chain, and it
    /// shipped three defects of one kind: a leaf matched with `==` instead of a
    /// prefix, an unreadable dimension falling through as "safe to delete", and
    /// no way to notice a class that was never added. This is the mechanism that
    /// replaces remembering — the `ALL` array's LENGTH is compiler-checked
    /// against the variant set, both `match`es are wildcard-free, and every
    /// declared class is exercised here from its OWN declaration rather than
    /// from a second hand-written list that could drift.
    #[test]
    fn every_exclusion_class_is_reachable_and_declared() {
        use crate::federation::types::ScrubSig;
        let mut seen = std::collections::BTreeSet::new();
        for class in ExclusionClass::ALL {
            assert!(
                !class.why().is_empty(),
                "{class:?} must declare why deleting it is unsafe"
            );
            // Build a probe row FROM the class's own declaration, so a new
            // class cannot be "covered" by a fixture nobody updated.
            let probe = match class {
                ExclusionClass::StructuralComposer => row(
                    "p",
                    "k",
                    attestation_type::WITHDRAWS,
                    env("anything:at:all:v1", Some("t")),
                ),
                ExclusionClass::Delegation => row(
                    "p",
                    "k",
                    attestation_type::DELEGATES_TO,
                    env("d:x:v1", None),
                ),
                ExclusionClass::UnreadableDimension => {
                    // Dimension present but NOT a string — the exact shape
                    // `envelope_dimension`'s `as_str()` returns `None` for.
                    let mut r = row("p", "k", attestation_type::SCORES, env("x:y:v1", None));
                    r.attestation_envelope["dimension"] = serde_json::json!(42);
                    r
                }
                // INDEPENDENT examples, hardcoded — never derived from
                // `dimension_prefix()`. Building the probe from the
                // declaration under test makes the test self-referential: it
                // followed the prefix wherever it moved, so narrowing
                // `revocation:` back to the single `peer_admission:v1` leaf
                // left it green. These are real dimensions from the manifest
                // and from the audit, and they only match if the PREFIX is
                // right.
                ExclusionClass::Revocation => row(
                    "p",
                    "k",
                    attestation_type::SCORES,
                    // Manifest-declared NON-ROLLBACKABLE, and a sibling leaf of
                    // the one the `==` match protected.
                    env("revocation:partner:fraud", None),
                ),
                ExclusionClass::Quarantine => row(
                    "p",
                    "k",
                    attestation_type::SCORES,
                    env("quarantine:withheld:v1", None),
                ),
                ExclusionClass::Moderation => row(
                    "p",
                    "k",
                    attestation_type::SCORES,
                    env("moderation:harassment:v1", None),
                ),
                ExclusionClass::Reconsideration => row(
                    "p",
                    "k",
                    attestation_type::SCORES,
                    env("reconsideration:new_evidence:v1", None),
                ),
                ExclusionClass::Slashing => row(
                    "p",
                    "k",
                    attestation_type::SCORES,
                    env("slashing:upheld:v1", None),
                ),
                ExclusionClass::Objection => row(
                    "p",
                    "k",
                    attestation_type::SCORES,
                    env("objection:dismissed:v1", None),
                ),
                ExclusionClass::AccountabilityRecord => row(
                    "p",
                    "k",
                    attestation_type::SCORES,
                    env("moderation_track_record:ciris-canonical:v1", None),
                ),
            };
            let got = is_exclusion_bearing(&probe).unwrap_or_else(|| {
                panic!("{class:?} is declared but NOT reachable through is_exclusion_bearing")
            });
            assert_eq!(got, class, "{class:?} resolved to the wrong class");
            seen.insert(class);
        }
        assert_eq!(
            seen.len(),
            ExclusionClass::ALL.len(),
            "ALL contains duplicates"
        );

        // THE `==`-vs-`starts_with` CASE, pinned by name. A future `:v2` of the
        // one leaf the original chain protected, and a SIBLING leaf of it, must
        // both resolve — that is the whole defect the partition replaced.
        for dimension in [
            "revocation:peer_admission:v1",
            "revocation:peer_admission:v2",
            "revocation:partner:fraud",
            "revocation:agent:compromise",
        ] {
            assert_eq!(
                is_exclusion_bearing(&row(
                    "p",
                    "k",
                    attestation_type::SCORES,
                    env(dimension, None)
                )),
                Some(ExclusionClass::Revocation),
                "{dimension} must be protected — the family is prefix-matched, never one leaf \
                 by equality"
            );
        }

        // NEGATIVE CONTROL: an ordinary row is NOT exclusion-bearing, so the
        // gate above is measuring the partition and not a predicate that says
        // yes to everything.
        assert!(is_exclusion_bearing(&row(
            "p",
            "k",
            attestation_type::SCORES,
            env("weather:today:v1", None)
        ))
        .is_none());

        // And the door refuses every declared class, so the invariant is not
        // only in `classify`.
        let mut tomb = row(
            "p",
            "k",
            attestation_type::WITHDRAWS,
            env("x:y:v1", Some("t")),
        );
        tomb.additional_scrubs = vec![ScrubSig {
            cosigned_at: None,
            scrub_key_id: "a".into(),
            scrub_signature_classical: "s".into(),
            scrub_signature_pqc: None,
        }];
        assert!(check_purge_admission(&tomb).is_err());
        assert!(check_purge_admission(&row(
            "p",
            "k",
            attestation_type::SCORES,
            env("weather:today:v1", None)
        ))
        .is_ok());
    }

    /// v31.0.0 (CIRISPersist#650) — **a CLOCK is not a SHAPE.**
    ///
    /// `check_instant_binding`'s fourth arm is a wall-clock skew bound. Mapping
    /// it to `Legacy` made a node whose clock ran behind classify a correctly
    /// sealed PEER corpus as legacy — whose disposition is `purge`. A VM
    /// snapshot restore or a pre-NTP container boot was sufficient to delete it.
    #[test]
    fn a_clock_running_behind_does_not_make_a_row_legacy() {
        let mut r = row("a1", "peer", attestation_type::SCORES, env("x:y:v1", None));
        r.asserted_at =
            crate::federation::admission::truncate_to_substrate_resolution(chrono::Utc::now());
        // Seal it properly, so the only thing that could make it non-conformant
        // is the clock.
        crate::federation::envelope::stamp_signed_instants(&mut r).expect("instants");
        crate::federation::envelope::RowMirror::stamp_row(&mut r).expect("mirror");
        crate::federation::canonical_at_rest::canonicalize_in_place(&mut r.attestation_envelope)
            .expect("canonical");
        assert!(
            classify_shape(&r, chrono::Utc::now()).is_conformant(),
            "precondition: the fixture is a correctly sealed v31 row"
        );

        // THE FINDING: the same row, judged by a node an hour behind.
        let behind = chrono::Utc::now() - chrono::Duration::hours(1);
        assert!(
            classify_shape(&r, behind).is_conformant(),
            "a node whose clock runs behind must NOT read a correctly sealed row as legacy — \
             the disposition of a legacy peer row is PURGE, so this turns a clock problem into \
             silent peer data loss at boot (CIRISPersist#650)"
        );
        // And a peer row IS the population at risk: confirm the disposition it
        // would have received.
        let mut legacy_peer = r.clone();
        legacy_peer.attestation_envelope["row"] = serde_json::json!(null);
        assert!(matches!(
            classify(
                &legacy_peer,
                &classify_shape(&legacy_peer, chrono::Utc::now()),
                &RetractionFold::default(),
                &Authorship::Foreign {
                    attesting_key_id: "peer".into()
                },
                false,
            ),
            Disposition::Purge(PurgeReason::UnauthorableLegacy { .. })
        ));
    }

    /// v31.0.0 (CIRISPersist#650) — arm 7 does not delete what this node's own
    /// predicate positively asserts is load bearing.
    #[test]
    fn a_positively_load_bearing_foreign_row_is_retained() {
        let r = row(
            "a1",
            "peer",
            attestation_type::SCORES,
            env("trust:accepts:v1", None),
        );
        let foreign = Authorship::Foreign {
            attesting_key_id: "peer".into(),
        };
        assert!(matches!(
            classify(&r, &legacy(), &RetractionFold::default(), &foreign, true),
            Disposition::RetainInert { .. }
        ));
        // Negative control: the same row with a non-`Yes` verdict is purged, so
        // the retention above is the predicate's doing.
        assert!(matches!(
            classify(&r, &legacy(), &RetractionFold::default(), &foreign, false),
            Disposition::Purge(PurgeReason::UnauthorableLegacy { .. })
        ));
    }

    #[test]
    fn a_co_scrubbed_row_is_never_re_stamped() {
        // THE m-of-n CASE. This row is ours, exclusion-bearing (an
        // `objection:dismissed:v1` is the reverse quorum's m-of-n UNDO), and
        // legacy — every condition that routes to `Restamp`. The co-scrubs must
        // override all of them.
        let mut r = row(
            "d1",
            "me",
            attestation_type::SCORES,
            env(
                crate::federation::reverse_quorum::DIMENSION_DISMISSAL,
                Some("obj-1"),
            ),
        );
        r.additional_scrubs = vec![
            crate::federation::types::ScrubSig {
                cosigned_at: None,
                scrub_key_id: "holder-b".into(),
                scrub_signature_classical: "sig-b".into(),
                scrub_signature_pqc: None,
            },
            crate::federation::types::ScrubSig {
                cosigned_at: None,
                scrub_key_id: "holder-c".into(),
                scrub_signature_classical: "sig-c".into(),
                scrub_signature_pqc: None,
            },
        ];
        assert!(is_co_scrubbed(&r));
        // Precondition: every OTHER signal points at Restamp.
        assert!(is_exclusion_bearing(&r).is_some());
        assert!(Authorship::OwnKey.can_reauthor());

        let d = classify(
            &r,
            &legacy(),
            &RetractionFold::default(),
            &Authorship::OwnKey,
            false,
        );
        assert!(
            matches!(d, Disposition::RetainInert { .. }),
            "a co-scrubbed row must be RETAINED, not re-stamped — re-signing drops the other \
             holders' signatures and turns an m-of-n into a 1-of-1. Got {d:?}"
        );

        // NEGATIVE CONTROL: the SAME row without co-scrubs IS re-stamped, so
        // the assertion above measures the co-scrub arm and not a routine that
        // retains everything.
        r.additional_scrubs.clear();
        assert_eq!(
            classify(
                &r,
                &legacy(),
                &RetractionFold::default(),
                &Authorship::OwnKey,
                false,
            ),
            Disposition::Restamp
        );
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
                &classify_authorship(&r, Some("me")),
                false,
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
                &Authorship::OwnKey,
                false,
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
    ///
    /// Carries `weight = 1.0`, and that is load-bearing rather than incidental:
    /// `serde_json` writes an integral f64 as `1.0` while JCS writes `1`, so a
    /// row with this weight is one whose STORED bytes and CANONICAL bytes
    /// differ. That is the ordinary case — half this repo's fixtures use
    /// `weight: Some(1.0)` — and it is what makes the #647 at-rest assertions
    /// below able to fail. Without it, `sha256(column) == original_content_hash`
    /// holds by coincidence and the witness measures nothing.
    fn scores_row(id: &str, attester: &str, dimension: &str) -> Attestation {
        let mut r = row_with(
            id,
            attester,
            serde_json::json!({ "dimension": dimension }),
            &[],
            attestation_type::SCORES,
        );
        r.weight = Some(1.0);
        seal::seal_row_in_place(attester, &mut r);
        r
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
        // The REAL fold: the grant is retracted, so it is purged.
        let real = fold_retractions(&corpus);
        assert!(matches!(
            classify(&grant, &shape, &real, &Authorship::OwnKey, false),
            Disposition::Purge(PurgeReason::Retracted { .. })
        ));

        // The MUTATED fold — "replay the interim states": nothing retracts.
        let mutated = RetractionFold::default();
        assert_eq!(
            classify(&grant, &shape, &mutated, &Authorship::OwnKey, false),
            Disposition::Restamp,
            "with the fold disabled the withdrawn grant is RE-MINTED as a valid v31 row — that \
             is the resurrection this witness exists to detect"
        );
    }
}
