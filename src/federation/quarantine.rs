//! v25.1.0 (CIRISPersist#570 ask 5) — **quarantine: withhold from serving.**
//!
//! Tier 2 of the graded response set in CIRISServer's
//! `FSD/ADMIN_OPS_TAXONOMY.md` — the fediverse's *silence*, Tor's flag. A key
//! is doing something a cohort's authority will not relay, but nothing about
//! that judgement justifies destroying the record of it. So:
//!
//! - **rows are RETAINED locally** — persist deletes nothing, tombstones
//!   nothing, rewrites nothing;
//! - **serving is withheld** — this node stops handing the quarantined key's
//!   rows and blobs to peers;
//! - **it is REVERSIBLE** — a [`DIMENSION_RELEASED`] marker supersedes a
//!   [`DIMENSION_WITHHELD`] one and the withholding stops, with both acts
//!   surviving in the corpus.
//!
//! Between "file a report nobody must read" and the node-wide kill switch
//! there was nothing. This is the rung in between, and it is the rung a
//! response ladder actually spends most of its time on.
//!
//! # A MARKER, not a command (the #570 design wall)
//!
//! Usenet shipped `cancel` — a *command*: a message whose arrival deleted
//! another message on every server that honoured it. The cancel wars followed,
//! and NoCeM replaced it with a signed *notice* that each server folded under
//! its own policy. Every durable system re-derives this, and #574's objection
//! plane derived it here two releases ago.
//!
//! So a quarantine is a **`scores` attestation**, exactly like an objection —
//! never a `withdraws`, never an RPC, never a mutation-on-arrival:
//!
//! - nothing is changed by the marker's arrival. `put_attestation` stores one
//!   row and touches nothing else;
//! - the effect is entirely a **read-time fold** ([`fold_quarantine`]) that a
//!   reader may honour. This node honours it on its own serve paths; a peer
//!   that folds differently is not lied to, it simply does not receive the
//!   rows from *us*;
//! - it travels on the ordinary attestation plane because it *is* an ordinary
//!   attestation, so a node that was partitioned when the marker was raised
//!   converges the moment the row arrives.
//!
//! # Evidence, not verdict
//!
//! [`resolve_quarantine`] returns a [`QuarantineFold`]: the state, which
//! marker produced it, who authored that marker, the `delegation_id` it was
//! taken under, and the grounds. Persist never says the quarantined key did
//! anything wrong. It says *this authority withheld it, under this delegation,
//! at this instant, and here is the row.* The `hard_case`-evidence /
//! never-slashing-verdict split v22 shipped, on a third plane.
//!
//! # Authority is re-derived from this node's own verified state (#377)
//!
//! A marker is admitted only if its author holds a live
//! [`slash`](super::admission::DELEGATION_SCOPE_SLASH) duty — as a
//! steward-bound named moderator of the community the marker names, or via a
//! `slash`-bearing `delegates_to` chain rooted at one. That gate is
//! [`check_delegated_duty_scores_admission`](super::admission::check_delegated_duty_scores_admission),
//! wired on the [`QUARANTINE_DIMENSION_PREFIX`](super::admission::QUARANTINE_DIMENSION_PREFIX)
//! arm, and it runs inside **every** `put_attestation` on all three backends —
//! the local door and the replication apply alike.
//!
//! That is what makes the serve-side fold cheap and honest: **held implies
//! authorized**, because an unauthorized marker was never stored. The fold does
//! not re-walk the delegation graph per page, and it is not trusting the row —
//! it is trusting the admission gate that let the row exist here.
//!
//! # Which serve paths consult it
//!
//! Two, both host-reachable today:
//!
//! 1. [`Engine::serve_blob_to_peer`](crate::Engine::serve_blob_to_peer) — the
//!    blob-to-peer chokepoint. If ANY local holder of the blob is withheld,
//!    the serve is refused with
//!    [`BlobError::QuarantineWithheld`](super::BlobError::QuarantineWithheld).
//!    ANY, not ALL: withholding is the restrictive direction, and a graded
//!    response that fails open is not a response.
//! 2. `FederationDirectory::list_attestation_log` on all three backends — the
//!    relay/replication row read (`#455`), filtered through
//!    [`filter_withheld_rows`].
//!
//! What it does **not** yet consult, stated rather than implied: the
//! per-plane `list_signed_*_since` cursors each serve their own plane's rows
//! (keys, families, occurrences, route table) and are untouched here — a
//! quarantine is about an actor's ATTESTATIONS and BLOBS, which is what the
//! taxonomy's tier 2 names. Widening it to the identity planes would make a
//! quarantined key unresolvable and therefore make its own marker
//! unverifiable, which is the fail-open direction wearing a fail-secure hat.
//!
//! # The convergence carve-out
//!
//! [`filter_withheld_rows`] never withholds a row that is ITSELF on a
//! quarantine dimension. A marker that stops replicating is a marker the rest
//! of the mesh cannot fold — and worse, a *release* that stops replicating
//! makes a quarantine permanent by accident. The marker plane must travel even
//! when its subject does not.

use chrono::{DateTime, Utc};

use super::types::Attestation;
use super::{Error, FederationDirectory};

/// The `scores` dimension a **withhold** marker carries: *"I, an authority
/// bearing [`slash`](super::admission::DELEGATION_SCOPE_SLASH) for this
/// cohort, withhold this key's rows from serving."*
///
/// A **new namespace family** — see [`NAMESPACE_FAMILY`]. Versioned `:v1` per
/// the house style for persist-minted dimensions (`consent:replication:v1`,
/// `objection:raised:v1`, `trace:complete:v1`).
pub const DIMENSION_WITHHELD: &str = "quarantine:withheld:v1";

/// The `scores` dimension a **release** marker carries: *"stop withholding."*
/// The reversibility half — tier 2 is only tier 2 because it can be undone
/// without reconstructing anything.
pub const DIMENSION_RELEASED: &str = "quarantine:released:v1";

/// The CC 3.1 namespace family both dimensions live under. **Registered**
/// (CIRISPersist#590): CC 1.0-rc3 catalogues it at CC 3.1.9.2, owning component
/// `node`, alongside `moderation:{allegation_type}`, `slashing:{outcome}`,
/// `reconsideration:{grounds}` and #574's `objection:{state}`. It is on the
/// CC 3.1.7 R2(a) mint gate
/// ([`super::admission::MINTED_NAMESPACE_FAMILIES`]): a family persist mints
/// without landing its registry row now fails persist's own build.
///
/// **The row registers the family, NOT the emitter rule.** CC's row says
/// *"slash-duty-holder-only emitter"* in its `description` — human prose that
/// nothing parses — while its machine-readable `reserved_rule` is **absent**.
/// On the vendored rc3 cut this row is the **only** one of 109 whose
/// description asserts an emitter rule its `reserved_rule` omits, which makes
/// it the sharpest available example for the CC ask: the rule is decided, and
/// it is one field away from being enforceable by anyone but us.
/// `registry::RawFamily` deserializes `reserved_rule` and ignores everything
/// else, so
/// [`authority_for`](super::namespace::registry::authority_for)`("quarantine:…")`
/// returns `ProducerSteward` / `reserved: None`.
///
/// So the slash-duty-holder gate at
/// [`check_delegated_duty_scores_admission`](super::admission::check_delegated_duty_scores_admission)'s
/// [`QUARANTINE_DIMENSION_PREFIX`](super::admission::QUARANTINE_DIMENSION_PREFIX)
/// arm is the **only** enforcement. Nothing on this plane reads `.reserved`, and
/// nothing should start until the rule is on the row — a prose rule read as a
/// registered one is how two validators come to share a predicate that exists in
/// neither of their sources. Tracked in
/// [`MINTED_FAMILY_RULES_NOT_ON_THE_ROW`](super::admission::MINTED_FAMILY_RULES_NOT_ON_THE_ROW);
/// getting it onto the row rides CIRISConstitution#76.
pub const NAMESPACE_FAMILY: &str = "quarantine:{state}";

/// Envelope field names shared by the producer side and persist's fold, so the
/// two cannot disagree about where a reference lives.
pub mod field {
    /// The `federation_keys.key_id` being withheld / released. Also the
    /// marker's `attested_key_id`, so one existing read
    /// ([`list_attestations_for`](crate::federation::FederationDirectory::list_attestations_for))
    /// finds every marker about a key.
    pub const QUARANTINES: &str = "quarantines_key_id";
    /// The community whose named moderators are the `slash` duty-holder roots.
    /// Read by
    /// [`check_delegated_duty_scores_admission`](crate::federation::admission::check_delegated_duty_scores_admission)
    /// — the SAME field the `moderation:*` / `reconsideration:*` arms read, so
    /// the three duties resolve authority through one path.
    pub const COMMUNITY_ID: &str = "community_id";
    /// The `delegates_to` attestation id the author acted UNDER. Mirrors
    /// [`admin_field::DELEGATION_ID`](crate::federation::hard_case::admin_field::DELEGATION_ID)
    /// — #570 ask 3's requirement, applied to the marker itself so the
    /// attribution travels WITH the act rather than only in this node's local
    /// `hard_case` log.
    pub const DELEGATION_ID: &str = "delegation_id";
    /// Which withhold marker a release supersedes (a `DIMENSION_RELEASED`
    /// envelope only).
    pub const RELEASES: &str = "releases_marker_id";
    /// Free text: WHY. Recorded, never interpreted.
    pub const GROUNDS: &str = "grounds";
}

// ─────────────────────────────────────────────────────────────────────────
//  Typed refusals (#565 style)
// ─────────────────────────────────────────────────────────────────────────

/// **WHICH branch refused** a quarantine or release marker.
///
/// Closed, snake_case serde tokens, [`Self::as_str`] returning the SAME token,
/// no `Other`/`Unspecified` catch-all — the
/// [`KeyRefusalReason`](super::register::KeyRefusalReason) discipline #565
/// shipped. **The token set is the downstream contract and this mapping is
/// APPEND-ONLY.** Add variants; never re-spell one.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, serde::Serialize, serde::Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum QuarantineRefusalReason {
    /// The row's envelope `dimension` is neither [`DIMENSION_WITHHELD`] nor
    /// [`DIMENSION_RELEASED`]. Wrong door.
    DimensionMismatch,
    /// The envelope is missing a field the fold needs —
    /// [`field::QUARANTINES`] or [`field::COMMUNITY_ID`] on either form, or
    /// [`field::RELEASES`] on a release.
    MalformedEnvelope,
    /// The envelope carries no [`field::DELEGATION_ID`]. An act that does not
    /// carry its own authority is indistinguishable from an unauthorized one
    /// once the actor is gone (#570 ask 3) — and a marker outlives the session
    /// that raised it by construction, so this is the plane where it matters
    /// most.
    Unattributed,
    /// The row's `attested_key_id` is not the key named by
    /// [`field::QUARANTINES`]. The fold finds markers by
    /// `list_attestations_for(quarantined_key)`, so a marker filed elsewhere
    /// would be stored, durable, and permanently inert — the preserve set must
    /// equal the verified set, and a marker nobody can find is not a marker.
    NotFiledAgainstSubject,
    /// The key named by [`field::QUARANTINES`] is not registered on this node.
    /// Nothing can be withheld that this node cannot name, and admitting the
    /// marker would create a rule about a key whose rows can never arrive
    /// (they would be FK-refused).
    SubjectKeyUnknown,
    /// The author's own scrub signature did not verify against pubkeys
    /// resolved from THIS node's directory.
    UnverifiableSignature,
    /// The author holds no live [`slash`](super::admission::DELEGATION_SCOPE_SLASH)
    /// duty for the named community — not a steward-bound named moderator, and
    /// not reachable from one by a `slash`-bearing `delegates_to` chain. The
    /// gate that makes "held implies authorized" true on the serve path.
    SlashUnauthorized,
    /// A release's [`field::RELEASES`] does not resolve to a
    /// [`DIMENSION_WITHHELD`] row this node holds against the SAME key. Tested
    /// here exactly as [`fold_quarantine`] tests it, so a release cannot be
    /// admitted under one rule and re-priced under another.
    MarkerUnknown,
}

impl QuarantineRefusalReason {
    /// The **stable program token** — identical to the serde token, so a
    /// consumer reading the wire and a consumer holding the typed value key on
    /// the same constant.
    #[must_use]
    pub const fn as_str(&self) -> &'static str {
        match self {
            Self::DimensionMismatch => "dimension_mismatch",
            Self::MalformedEnvelope => "malformed_envelope",
            Self::Unattributed => "unattributed",
            Self::NotFiledAgainstSubject => "not_filed_against_subject",
            Self::SubjectKeyUnknown => "subject_key_unknown",
            Self::UnverifiableSignature => "unverifiable_signature",
            Self::SlashUnauthorized => "slash_unauthorized",
            Self::MarkerUnknown => "marker_unknown",
        }
    }

    /// Every variant, in declaration order — the closed set.
    pub const ALL: &'static [Self] = &[
        Self::DimensionMismatch,
        Self::MalformedEnvelope,
        Self::Unattributed,
        Self::NotFiledAgainstSubject,
        Self::SubjectKeyUnknown,
        Self::UnverifiableSignature,
        Self::SlashUnauthorized,
        Self::MarkerUnknown,
    ];
}

impl std::fmt::Display for QuarantineRefusalReason {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(self.as_str())
    }
}

/// Outcome of a marker admission attempt. `Refused` is a **policy** outcome,
/// not an error: a marker arrives unsolicited on a replication plane, so every
/// gate failure resolves deterministically and safe-to-re-offer rather than
/// aborting a loop. Backend/IO failures still surface as `Err`.
#[derive(Debug, Clone, Copy, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum QuarantineOutcome {
    /// Admitted and stored.
    Admitted,
    /// Not admitted; nothing was written.
    Refused {
        /// WHICH policy branch refused.
        reason: QuarantineRefusalReason,
    },
}

impl QuarantineOutcome {
    /// The refusal reason, if this is a refusal.
    #[must_use]
    pub const fn refusal(&self) -> Option<QuarantineRefusalReason> {
        match self {
            Self::Admitted => None,
            Self::Refused { reason } => Some(*reason),
        }
    }
}

// ─────────────────────────────────────────────────────────────────────────
//  The fold
// ─────────────────────────────────────────────────────────────────────────

/// What this node's held markers say about one key, right now.
///
/// A derived STATE, not a sentence — a pure function of held rows, recomputed
/// at read time, converging on every node without coordination once the rows
/// have travelled. Exactly the sense in which
/// [`ConsentState::Revoked`](super::hard_case::ConsentState::Revoked) and
/// [`ReverseQuorumStanding::Reversed`](super::reverse_quorum::ReverseQuorumStanding::Reversed)
/// are derived.
#[derive(Debug, Clone, Copy, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum QuarantineState {
    /// No marker about this key has taken effect here.
    NotQuarantined,
    /// The governing marker is a [`DIMENSION_WITHHELD`] — the serve paths
    /// withhold.
    Withheld,
    /// The governing marker is a [`DIMENSION_RELEASED`] — a quarantine was
    /// raised and lifted. Distinct from [`Self::NotQuarantined`] on purpose:
    /// "never withheld" and "withheld and released" are different facts, and
    /// an operator reviewing a key deserves to see the second one.
    Released,
}

impl QuarantineState {
    /// Does this state withhold from serving? The ONE predicate every serve
    /// path asks, so the two consult sites cannot drift on what the fold means.
    #[must_use]
    pub const fn withholds(&self) -> bool {
        matches!(self, Self::Withheld)
    }

    /// The stable program token — identical to the serde token.
    #[must_use]
    pub const fn as_str(&self) -> &'static str {
        match self {
            Self::NotQuarantined => "not_quarantined",
            Self::Withheld => "withheld",
            Self::Released => "released",
        }
    }
}

/// The read-time answer, with the evidence that produced it. The fold names
/// its marker — a state without its row sends the reader to the wrong layer.
#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub struct QuarantineFold {
    /// The key the fold is about.
    pub key_id: String,
    /// The derived state.
    pub state: QuarantineState,
    /// The governing marker's `attestation_id`, or `None` when
    /// [`QuarantineState::NotQuarantined`].
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub marker_id: Option<String>,
    /// The governing marker's author — WHO withheld (or released).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub decided_by: Option<String>,
    /// The `delegates_to` id the author acted under (#570 ask 3's attribution,
    /// carried on the marker so it survives replication).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub delegation_id: Option<String>,
    /// The governing marker's `asserted_at` — when the state took effect.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub effective_at: Option<DateTime<Utc>>,
    /// The grounds the author recorded. Never interpreted by persist.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub grounds: Option<String>,
    /// Every marker about this key that has taken effect, sorted — the fold
    /// names its whole evidence set, not only the winner. This is the
    /// enumeration a compromised-authority review reads.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub marker_ids: Vec<String>,
}

impl QuarantineFold {
    /// Does this fold withhold from serving?
    #[must_use]
    pub const fn withholds(&self) -> bool {
        self.state.withholds()
    }

    /// The empty answer for a key no marker names.
    #[must_use]
    fn none_for(key_id: &str) -> Self {
        Self {
            key_id: key_id.to_owned(),
            state: QuarantineState::NotQuarantined,
            marker_id: None,
            decided_by: None,
            delegation_id: None,
            effective_at: None,
            grounds: None,
            marker_ids: Vec::new(),
        }
    }
}

/// Is `dimension` one of the two quarantine marker dimensions?
#[must_use]
pub fn is_marker_dimension(dimension: &str) -> bool {
    dimension == DIMENSION_WITHHELD || dimension == DIMENSION_RELEASED
}

/// Read a string field off a row's envelope.
fn envelope_str<'a>(row: &'a Attestation, key: &str) -> Option<&'a str> {
    row.attestation_envelope.get(key)?.as_str()
}

/// Read a NON-EMPTY string field off a row's envelope.
fn envelope_nonempty<'a>(row: &'a Attestation, key: &str) -> Option<&'a str> {
    envelope_str(row, key).filter(|s| !s.is_empty())
}

/// The **pure fold**: a function of `(key_id, markers, now)` and nothing else.
///
/// # Counting rules
///
/// A marker governs iff ALL of: it carries [`DIMENSION_WITHHELD`] or
/// [`DIMENSION_RELEASED`]; its [`field::QUARANTINES`] names `key_id`; and its
/// `asserted_at <= now`.
///
/// **Newest-wins**, ordered by `(asserted_at, withhold-beats-release,
/// attestation_id)`. The last two components are not decoration:
///
/// - **`asserted_at` alone is not a total order.** Two markers can share an
///   instant, and that is exactly what a hostile author constructs — raise and
///   release at the same timestamp and let each node pick its own answer.
/// - **At a tie, WITHHOLD wins.** This is the fail-secure direction, and the
///   only one available: the alternative resolves a deliberate collision toward
///   *release*, which hands the escape to whoever can pick their own
///   `attestation_id`. Withholding is recoverable by a later release; a
///   wrongly-lifted quarantine is not recoverable by anything.
/// - **`attestation_id` breaks the remaining tie** between two markers of the
///   same kind at the same instant, so the fold is a pure function of the row
///   set and never of the order they arrived in.
///
/// A future-dated marker does not govern **in either direction**. Same reading:
/// a future-dated *withhold* has not started, and a future-dated *release* has
/// not lifted anything. Nobody pre-schedules their own release out of a
/// quarantine that has not been raised yet.
#[must_use]
pub fn fold_quarantine(
    key_id: &str,
    markers: &[Attestation],
    now: DateTime<Utc>,
) -> QuarantineFold {
    let mut effective: Vec<&Attestation> = markers
        .iter()
        .filter(|m| {
            envelope_str(m, "dimension").is_some_and(is_marker_dimension)
                && envelope_str(m, field::QUARANTINES) == Some(key_id)
                && m.asserted_at <= now
        })
        .collect();
    if effective.is_empty() {
        return QuarantineFold::none_for(key_id);
    }
    // Sorts ASCENDING; the last element governs. `withhold_rank` is therefore
    // 1 for a withhold and 0 for a release — restriction sorts LAST, i.e. wins.
    let withhold_rank =
        |m: &Attestation| u8::from(envelope_str(m, "dimension") == Some(DIMENSION_WITHHELD));
    effective.sort_by(|a, b| {
        a.asserted_at
            .cmp(&b.asserted_at)
            .then_with(|| withhold_rank(a).cmp(&withhold_rank(b)))
            .then_with(|| a.attestation_id.cmp(&b.attestation_id))
    });
    let mut marker_ids: Vec<String> = effective.iter().map(|m| m.attestation_id.clone()).collect();
    marker_ids.sort();

    let governing = effective[effective.len() - 1];
    let state = match envelope_str(governing, "dimension") {
        Some(DIMENSION_WITHHELD) => QuarantineState::Withheld,
        _ => QuarantineState::Released,
    };
    QuarantineFold {
        key_id: key_id.to_owned(),
        state,
        marker_id: Some(governing.attestation_id.clone()),
        decided_by: Some(governing.attesting_key_id.clone()),
        delegation_id: envelope_nonempty(governing, field::DELEGATION_ID).map(str::to_owned),
        effective_at: Some(governing.asserted_at),
        grounds: envelope_nonempty(governing, field::GROUNDS).map(str::to_owned),
        marker_ids,
    }
}

// ─────────────────────────────────────────────────────────────────────────
//  Envelope builders — one shape, producer side and persist side
// ─────────────────────────────────────────────────────────────────────────

/// Build the canonical envelope of a **withhold** marker. Defined here so a
/// producer and this node's fold agree byte-for-byte about where the
/// references live.
#[must_use]
pub fn withhold_envelope(
    quarantined_key_id: &str,
    community_id: &str,
    delegation_id: &str,
    grounds: &str,
) -> serde_json::Value {
    serde_json::json!({
        "dimension": DIMENSION_WITHHELD,
        field::QUARANTINES: quarantined_key_id,
        field::COMMUNITY_ID: community_id,
        field::DELEGATION_ID: delegation_id,
        field::GROUNDS: grounds,
    })
}

/// Build the canonical envelope of a **release** marker — the reversal.
#[must_use]
pub fn release_envelope(
    quarantined_key_id: &str,
    community_id: &str,
    releases_marker_id: &str,
    delegation_id: &str,
    grounds: &str,
) -> serde_json::Value {
    serde_json::json!({
        "dimension": DIMENSION_RELEASED,
        field::QUARANTINES: quarantined_key_id,
        field::COMMUNITY_ID: community_id,
        field::RELEASES: releases_marker_id,
        field::DELEGATION_ID: delegation_id,
        field::GROUNDS: grounds,
    })
}

// ─────────────────────────────────────────────────────────────────────────
//  The admission door
// ─────────────────────────────────────────────────────────────────────────

/// **The marker door.** Admit and store one quarantine / release marker.
///
/// Verify-before-mutation (AV-9): every gate below runs BEFORE any row is
/// written, and a refusal writes nothing.
///
/// The `slash` authority check is
/// [`check_delegated_duty_scores_admission`](super::admission::check_delegated_duty_scores_admission)
/// — the same gate `put_attestation` runs on all three backends. It is called
/// HERE too, deliberately, so this door can name the branch
/// ([`QuarantineRefusalReason::SlashUnauthorized`]) instead of surfacing a
/// generic error; the duplicate is not a second implementation of the rule but
/// a second call of the one implementation, which is the only kind of
/// duplication rule #9 permits.
///
/// A marker that clears every gate here is stored through the ordinary
/// `put_attestation` path, which re-runs the same gate. A marker that arrives
/// on the replication plane instead of through this door still meets that
/// gate, so `slash` authority is never bypassable — this door adds the
/// SHAPE checks (attribution, filing, subject resolution) on top.
pub async fn record_quarantine_marker(
    directory: &dyn FederationDirectory,
    marker: &Attestation,
) -> Result<QuarantineOutcome, Error> {
    let refused = |reason: QuarantineRefusalReason| Ok(QuarantineOutcome::Refused { reason });

    let Some(dimension) = envelope_str(marker, "dimension") else {
        return refused(QuarantineRefusalReason::DimensionMismatch);
    };
    if !is_marker_dimension(dimension) {
        return refused(QuarantineRefusalReason::DimensionMismatch);
    }
    let is_release = dimension == DIMENSION_RELEASED;

    let Some(subject) = envelope_nonempty(marker, field::QUARANTINES).map(str::to_owned) else {
        return refused(QuarantineRefusalReason::MalformedEnvelope);
    };
    if envelope_nonempty(marker, field::COMMUNITY_ID).is_none() {
        return refused(QuarantineRefusalReason::MalformedEnvelope);
    }
    let releases = envelope_nonempty(marker, field::RELEASES).map(str::to_owned);
    if is_release && releases.is_none() {
        return refused(QuarantineRefusalReason::MalformedEnvelope);
    }

    // #570 ask 3 on the wire: the act carries its own authority, or it is not
    // an act this node will hold.
    if envelope_nonempty(marker, field::DELEGATION_ID).is_none() {
        return refused(QuarantineRefusalReason::Unattributed);
    }

    // Filed where the fold looks, or it is stored and never counted.
    if marker.attested_key_id != subject {
        return refused(QuarantineRefusalReason::NotFiledAgainstSubject);
    }

    // The subject must be a key this node can name.
    if directory.lookup_public_key(&subject).await?.is_none() {
        return refused(QuarantineRefusalReason::SubjectKeyUnknown);
    }

    // The author's own signature, re-verified against pubkeys resolved from
    // this node's directory (#377 — never pubkeys carried on the row).
    if super::verify_envelope_hybrid_signature(
        directory,
        &marker.attesting_key_id,
        &marker.attestation_envelope,
        &marker.scrub_signature_classical,
        marker.scrub_signature_pqc.as_deref(),
    )
    .await
    .is_err()
    {
        return refused(QuarantineRefusalReason::UnverifiableSignature);
    }

    // A release must name a withhold marker this node holds against the SAME
    // key — the same test `fold_quarantine` applies, so a release cannot be
    // admitted under one rule and re-priced under another.
    if let Some(marker_id) = &releases {
        let named = directory.get_attestation(marker_id).await?;
        let resolves = named.is_some_and(|row| {
            envelope_str(&row, "dimension") == Some(DIMENSION_WITHHELD)
                && envelope_str(&row, field::QUARANTINES) == Some(subject.as_str())
        });
        if !resolves {
            return refused(QuarantineRefusalReason::MarkerUnknown);
        }
    }

    // ── THE `slash` GATE, re-derived from this node's own verified state.
    match super::admission::check_delegated_duty_scores_admission(directory, marker).await {
        Ok(()) => {}
        Err(Error::DelegatedScopeUnauthorized { .. }) => {
            return refused(QuarantineRefusalReason::SlashUnauthorized)
        }
        Err(e) => return Err(e),
    }

    directory
        .put_attestation(super::SignedAttestation {
            attestation: marker.clone(),
        })
        .await?;
    Ok(QuarantineOutcome::Admitted)
}

// ─────────────────────────────────────────────────────────────────────────
//  The read-time answer + the serve-path consult
// ─────────────────────────────────────────────────────────────────────────

/// Every quarantine marker this node holds about `key_id`. Markers carry
/// `attested_key_id = quarantined key`, so ONE existing read serves the fold.
async fn markers_about<F>(directory: &F, key_id: &str) -> Result<Vec<Attestation>, Error>
where
    F: FederationDirectory + ?Sized,
{
    let rows = match directory.list_attestations_for(key_id).await {
        Ok(rows) => rows,
        Err(Error::Unsupported { .. }) => Vec::new(),
        Err(e) => return Err(e),
    };
    Ok(rows
        .into_iter()
        .filter(|r| envelope_str(r, "dimension").is_some_and(is_marker_dimension))
        .collect())
}

/// **The read-time answer** — what this node's held markers say about `key_id`
/// as of `now`. Persist mutates nothing here.
pub async fn resolve_quarantine<F>(
    directory: &F,
    key_id: &str,
    now: DateTime<Utc>,
) -> Result<QuarantineFold, Error>
where
    F: FederationDirectory + ?Sized,
{
    let markers = markers_about(directory, key_id).await?;
    Ok(fold_quarantine(key_id, &markers, now))
}

/// Is `key_id` withheld from serving right now? The single question the serve
/// paths ask.
pub async fn is_withheld<F>(directory: &F, key_id: &str, now: DateTime<Utc>) -> Result<bool, Error>
where
    F: FederationDirectory + ?Sized,
{
    Ok(resolve_quarantine(directory, key_id, now)
        .await?
        .withholds())
}

/// **The serve filter.** Drop rows authored by a withheld key from a page
/// about to be handed to a peer.
///
/// Applied by every backend's `list_attestation_log` — the `#455` relay read.
///
/// # Two properties that are not obvious
///
/// - **The marker plane is never withheld.** A row on a quarantine dimension
///   passes unconditionally, even when its author is themselves withheld. A
///   marker that stops replicating cannot be folded by the rest of the mesh,
///   and a *release* that stops replicating makes a quarantine permanent by
///   accident — a reversible control that is not reversible under its own
///   effect is not reversible.
/// - **The page may come back SHORT.** Filtering is post-SQL, so a page of
///   `limit` rows can return fewer while `next_cursor` still advances
///   correctly (the cursor is derived from the SQL page's trailing row, before
///   the filter). Callers already tolerate short pages; a filter that
///   back-filled would leak the withheld set by timing.
///
/// One directory read per DISTINCT author in the page, memoized within the
/// call — pages are author-sparse in practice, and the alternative (a
/// quarantine index) is a schema commitment this plane has not earned yet.
pub async fn filter_withheld_rows<F>(
    directory: &F,
    rows: Vec<Attestation>,
    now: DateTime<Utc>,
) -> Result<Vec<Attestation>, Error>
where
    F: FederationDirectory + ?Sized,
{
    // Fast path: nothing to do on an empty page, and no directory read on a
    // page that is entirely marker rows.
    if rows.is_empty() {
        return Ok(rows);
    }
    let mut decided: std::collections::HashMap<String, bool> = std::collections::HashMap::new();
    let mut kept: Vec<Attestation> = Vec::with_capacity(rows.len());
    for row in rows {
        // The convergence carve-out — see the doc above.
        if envelope_str(&row, "dimension").is_some_and(is_marker_dimension) {
            kept.push(row);
            continue;
        }
        let withheld = match decided.get(&row.attesting_key_id) {
            Some(v) => *v,
            None => {
                let v = is_withheld(directory, &row.attesting_key_id, now).await?;
                decided.insert(row.attesting_key_id.clone(), v);
                v
            }
        };
        if !withheld {
            kept.push(row);
        }
    }
    Ok(kept)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::federation::admission::QUARANTINE_DIMENSION_PREFIX;
    use crate::federation::types::{attestation_tier, attestation_type};

    fn ts(s: &str) -> DateTime<Utc> {
        s.parse().expect("rfc3339")
    }

    fn marker(id: &str, author: &str, subject: &str, dim: &str, at: &str) -> Attestation {
        let envelope = if dim == DIMENSION_WITHHELD {
            withhold_envelope(subject, "comm-1", "att-deleg", "spam")
        } else {
            release_envelope(subject, "comm-1", "m-w", "att-deleg", "appealed")
        };
        row(id, author, subject, envelope, at)
    }

    fn row(
        id: &str,
        author: &str,
        subject: &str,
        envelope: serde_json::Value,
        at: &str,
    ) -> Attestation {
        Attestation {
            attestation_id: id.to_owned(),
            attesting_key_id: author.to_owned(),
            attested_key_id: subject.to_owned(),
            attestation_type: attestation_type::SCORES.to_owned(),
            weight: None,
            asserted_at: ts(at),
            expires_at: None,
            attestation_envelope: envelope,
            original_content_hash: "00".to_owned(),
            scrub_signature_classical: "c2ln".to_owned(),
            scrub_signature_pqc: None,
            scrub_key_id: author.to_owned(),
            scrub_timestamp: ts(at),
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

    #[test]
    fn refusal_tokens_match_serde_and_are_unique() {
        let mut tokens: Vec<&str> = QuarantineRefusalReason::ALL
            .iter()
            .map(|r| r.as_str())
            .collect();
        for reason in QuarantineRefusalReason::ALL {
            let json = serde_json::to_string(reason).expect("serialize");
            assert_eq!(json, format!("\"{}\"", reason.as_str()));
            let back: QuarantineRefusalReason = serde_json::from_str(&json).expect("round-trip");
            assert_eq!(&back, reason);
        }
        let n = tokens.len();
        tokens.sort_unstable();
        tokens.dedup();
        assert_eq!(tokens.len(), n, "tokens must be distinct");
    }

    #[test]
    fn both_dimensions_sit_under_the_gated_prefix() {
        // The load-bearing coupling: if a dimension escaped the prefix, the
        // `slash` gate in `check_delegated_duty_scores_admission` would not
        // fire on it and the marker plane would be ungoverned.
        for d in [DIMENSION_WITHHELD, DIMENSION_RELEASED] {
            assert!(
                d.starts_with(QUARANTINE_DIMENSION_PREFIX),
                "{d} must be routed to the slash duty by its prefix"
            );
            assert!(is_marker_dimension(d));
        }
        assert!(!is_marker_dimension("quarantine:something_else:v1"));
        assert!(NAMESPACE_FAMILY.starts_with(QUARANTINE_DIMENSION_PREFIX));
    }

    #[test]
    fn no_markers_is_not_quarantined() {
        let f = fold_quarantine("k-a", &[], ts("2026-08-02T10:00:00Z"));
        assert_eq!(f.state, QuarantineState::NotQuarantined);
        assert!(!f.withholds());
        assert!(f.marker_id.is_none());
    }

    #[test]
    fn a_withhold_marker_withholds_and_names_its_evidence() {
        let m = marker(
            "m-w",
            "k-mod",
            "k-bad",
            DIMENSION_WITHHELD,
            "2026-08-02T10:00:00Z",
        );
        let f = fold_quarantine("k-bad", &[m], ts("2026-08-02T11:00:00Z"));
        assert_eq!(f.state, QuarantineState::Withheld);
        assert!(f.withholds());
        assert_eq!(f.marker_id.as_deref(), Some("m-w"));
        assert_eq!(f.decided_by.as_deref(), Some("k-mod"));
        assert_eq!(f.delegation_id.as_deref(), Some("att-deleg"));
        assert_eq!(f.grounds.as_deref(), Some("spam"));
        assert_eq!(f.effective_at, Some(ts("2026-08-02T10:00:00Z")));
    }

    #[test]
    fn a_release_reverses_it_and_both_acts_survive() {
        let w = marker(
            "m-w",
            "k-mod",
            "k-bad",
            DIMENSION_WITHHELD,
            "2026-08-02T10:00:00Z",
        );
        let r = marker(
            "m-r",
            "k-mod",
            "k-bad",
            DIMENSION_RELEASED,
            "2026-08-02T12:00:00Z",
        );
        let f = fold_quarantine("k-bad", &[w, r], ts("2026-08-02T13:00:00Z"));
        assert_eq!(f.state, QuarantineState::Released);
        assert!(!f.withholds());
        assert_eq!(f.marker_id.as_deref(), Some("m-r"));
        // Reversible does not mean erased — the corpus still names both.
        assert_eq!(f.marker_ids, vec!["m-r".to_owned(), "m-w".to_owned()]);
        // …and `Released` is deliberately distinguishable from never-withheld.
        assert_ne!(f.state, QuarantineState::NotQuarantined);
    }

    #[test]
    fn a_re_quarantine_after_a_release_withholds_again() {
        let rows = vec![
            marker(
                "m-w1",
                "k-mod",
                "k-bad",
                DIMENSION_WITHHELD,
                "2026-08-02T10:00:00Z",
            ),
            marker(
                "m-r1",
                "k-mod",
                "k-bad",
                DIMENSION_RELEASED,
                "2026-08-02T11:00:00Z",
            ),
            marker(
                "m-w2",
                "k-mod",
                "k-bad",
                DIMENSION_WITHHELD,
                "2026-08-02T12:00:00Z",
            ),
        ];
        let f = fold_quarantine("k-bad", &rows, ts("2026-08-02T13:00:00Z"));
        assert_eq!(f.state, QuarantineState::Withheld);
        assert_eq!(f.marker_id.as_deref(), Some("m-w2"));
    }

    #[test]
    fn a_future_dated_marker_does_not_govern_in_either_direction() {
        let w = marker(
            "m-w",
            "k-mod",
            "k-bad",
            DIMENSION_WITHHELD,
            "2026-08-02T10:00:00Z",
        );
        let future_release = marker(
            "m-r",
            "k-mod",
            "k-bad",
            DIMENSION_RELEASED,
            "2026-09-01T00:00:00Z",
        );
        // The withhold governs; the pre-scheduled release has not arrived.
        let f = fold_quarantine(
            "k-bad",
            &[w.clone(), future_release],
            ts("2026-08-02T11:00:00Z"),
        );
        assert_eq!(
            f.state,
            QuarantineState::Withheld,
            "nobody pre-schedules their own release"
        );
        // A future-dated WITHHOLD has not started either.
        let future_withhold = marker(
            "m-w2",
            "k-mod",
            "k-other",
            DIMENSION_WITHHELD,
            "2026-09-01T00:00:00Z",
        );
        let f2 = fold_quarantine("k-other", &[future_withhold], ts("2026-08-02T11:00:00Z"));
        assert_eq!(f2.state, QuarantineState::NotQuarantined);
    }

    #[test]
    fn same_instant_markers_fold_deterministically_and_fail_secure() {
        // The case a hostile author constructs: raise and release at the same
        // timestamp and let each node pick its own answer.
        //
        // TWO properties, and the second is the one that matters. Determinism
        // alone is satisfiable by "highest attestation_id wins" — which hands
        // the escape to whoever can choose their own id. At a tie the
        // RESTRICTION must win: a withhold is recoverable by a later release,
        // a wrongly-lifted quarantine is recoverable by nothing.
        let at = "2026-08-02T10:00:00Z";
        for (w_id, r_id) in [("m-aaa", "m-zzz"), ("m-zzz", "m-aaa")] {
            let w = marker(w_id, "k-mod", "k-bad", DIMENSION_WITHHELD, at);
            let r = marker(r_id, "k-mod", "k-bad", DIMENSION_RELEASED, at);
            let one = fold_quarantine("k-bad", &[w.clone(), r.clone()], ts("2026-08-02T11:00:00Z"));
            let other = fold_quarantine("k-bad", &[r, w], ts("2026-08-02T11:00:00Z"));
            assert_eq!(one, other, "row order must not change the answer");
            assert_eq!(
                one.state,
                QuarantineState::Withheld,
                "at a tie the restriction wins, WHICHEVER id the release picked"
            );
            assert_eq!(one.marker_id.as_deref(), Some(w_id));
        }
        // A genuinely later release still lifts it — the tie-break is a
        // tie-break, not a ratchet.
        let w = marker("m-w", "k-mod", "k-bad", DIMENSION_WITHHELD, at);
        let r = marker(
            "m-r",
            "k-mod",
            "k-bad",
            DIMENSION_RELEASED,
            "2026-08-02T10:00:01Z",
        );
        assert_eq!(
            fold_quarantine("k-bad", &[w, r], ts("2026-08-02T11:00:00Z")).state,
            QuarantineState::Released
        );
    }

    #[test]
    fn two_same_kind_markers_at_one_instant_still_fold_deterministically() {
        // The remaining tie: two withholds at the same second. The
        // attestation_id break keeps the fold a pure function of the row SET.
        let at = "2026-08-02T10:00:00Z";
        let a = marker("m-aaa", "k-mod", "k-bad", DIMENSION_WITHHELD, at);
        let b = marker("m-bbb", "k-other-mod", "k-bad", DIMENSION_WITHHELD, at);
        let one = fold_quarantine("k-bad", &[a.clone(), b.clone()], ts("2026-08-02T11:00:00Z"));
        let other = fold_quarantine("k-bad", &[b, a], ts("2026-08-02T11:00:00Z"));
        assert_eq!(one, other);
        assert_eq!(one.marker_id.as_deref(), Some("m-bbb"));
        assert_eq!(one.marker_ids.len(), 2, "the fold names its whole evidence");
    }

    #[test]
    fn a_marker_about_another_key_does_not_govern_this_one() {
        let m = marker(
            "m-w",
            "k-mod",
            "k-bad",
            DIMENSION_WITHHELD,
            "2026-08-02T10:00:00Z",
        );
        let f = fold_quarantine("k-innocent", &[m], ts("2026-08-02T11:00:00Z"));
        assert_eq!(f.state, QuarantineState::NotQuarantined);
    }

    #[test]
    fn a_non_marker_row_is_ignored_by_the_fold() {
        let ordinary = row(
            "a-1",
            "k-mod",
            "k-bad",
            serde_json::json!({"dimension": "testimonial_witness:x:v1"}),
            "2026-08-02T10:00:00Z",
        );
        let f = fold_quarantine("k-bad", &[ordinary], ts("2026-08-02T11:00:00Z"));
        assert_eq!(f.state, QuarantineState::NotQuarantined);
    }

    #[test]
    fn state_tokens_are_stable_and_only_withheld_withholds() {
        assert_eq!(QuarantineState::NotQuarantined.as_str(), "not_quarantined");
        assert_eq!(QuarantineState::Withheld.as_str(), "withheld");
        assert_eq!(QuarantineState::Released.as_str(), "released");
        assert!(QuarantineState::Withheld.withholds());
        assert!(!QuarantineState::Released.withholds());
        assert!(!QuarantineState::NotQuarantined.withholds());
        for s in [
            QuarantineState::NotQuarantined,
            QuarantineState::Withheld,
            QuarantineState::Released,
        ] {
            let json = serde_json::to_string(&s).expect("serialize");
            assert_eq!(json, format!("\"{}\"", s.as_str()));
        }
    }
}

/// The #570 asks-2/3/5 behavioural witness, run by the sqlite / postgres /
/// memory suites against `&dyn FederationDirectory` so the three backends
/// cannot silently diverge on the quarantine plane (the same discipline
/// [`super::reverse_quorum`]'s witness runs). `suffix` scopes every fixture
/// key so a run against a shared postgres test DB does not collide with a
/// prior one.
#[cfg(all(test, any(feature = "sqlite", feature = "postgres")))]
pub(crate) mod test_support {
    use super::*;
    use crate::federation::admission::{DELEGATION_SCOPE_MODERATE, DELEGATION_SCOPE_SLASH};
    use crate::federation::hard_case::{
        admin_action_event, admin_action_kind, admin_field, admin_op, AdminActionRefusal,
        HardCaseFilter,
    };
    use crate::federation::tier_ingest::test_support::{hybrid_pubkeys, sign_envelope};
    use crate::federation::types::{
        attestation_tier, attestation_type, Community, CommunityMember,
    };
    use crate::federation::{SignedAttestation, SignedKeyRecord};

    /// Register `key_id` as a **`user`**-role identity carrying its real
    /// deterministic hybrid pubkeys.
    ///
    /// `user` rather than `agent` for the same load-bearing reason #574's
    /// witness uses it: a community's roster members must be steward-bound
    /// (CC 3.2) and the community must have a live named moderator (§11.11)
    /// before a federation-tier row keyed on it admits. A `user`-role key
    /// satisfies both structurally, so the witness exercises the `slash` gate
    /// rather than fighting the community gates that guard it.
    async fn register_user_key(dir: &dyn FederationDirectory, key_id: &str) {
        register_key(dir, key_id, crate::federation::types::identity_type::USER).await;
    }

    /// Register `key_id` as an **`agent`**-role identity.
    ///
    /// The delegation RECIPIENTS are agents, not users, and that is a
    /// substrate rule rather than a fixture preference: a `delegates_to`
    /// whose target is a `user` key trips the CC 3.4.11 age-assurance gate
    /// (`UserTargetStewardBindingForbidden`). Only the delegation ROOT has to
    /// be steward-bound for `check_moderation_admission`, so the deputies are
    /// agents and the property under test is untouched.
    async fn register_agent_key(dir: &dyn FederationDirectory, key_id: &str) {
        register_key(dir, key_id, crate::federation::types::identity_type::AGENT).await;
    }

    async fn register_key(dir: &dyn FederationDirectory, key_id: &str, identity_type: &str) {
        let (ed_pk, mldsa_pk) = hybrid_pubkeys(key_id);
        let now = Utc::now();
        dir.put_public_key(SignedKeyRecord {
            record: crate::federation::KeyRecord {
                key_id: key_id.to_owned(),
                pubkey_ed25519_base64: ed_pk,
                pubkey_ml_dsa_65_base64: mldsa_pk,
                algorithm: crate::federation::types::algorithm::HYBRID.to_owned(),
                identity_type: identity_type.to_owned(),
                identity_ref: key_id.to_owned(),
                valid_from: now,
                valid_until: None,
                registration_envelope: serde_json::json!({ "id": key_id }),
                original_content_hash: "deadbeef".to_owned(),
                scrub_signature_classical: "c2lnbmF0dXJl".to_owned(),
                scrub_signature_pqc: None,
                scrub_key_id: key_id.to_owned(),
                scrub_timestamp: now,
                pqc_completed_at: None,
                persist_row_hash: String::new(),
                capability_roles: Vec::new(),
                attestation_evidence: None,
                consent_role: None,
                additional_scrubs: Vec::new(),
            },
        })
        .await
        .expect("register user key");
    }

    /// A federation-tier `scores` row carrying `envelope`, authored + scrubbed
    /// by `author`, about `subject`.
    fn signed_row(
        id: &str,
        author: &str,
        subject: &str,
        envelope: serde_json::Value,
        asserted_at: DateTime<Utc>,
    ) -> Attestation {
        let (och, ed_sig, pqc_sig) = sign_envelope(author, &envelope);
        Attestation {
            attestation_id: id.to_owned(),
            attesting_key_id: author.to_owned(),
            attested_key_id: subject.to_owned(),
            attestation_type: attestation_type::SCORES.to_owned(),
            weight: None,
            asserted_at,
            expires_at: None,
            attestation_envelope: envelope,
            original_content_hash: och,
            scrub_signature_classical: ed_sig,
            scrub_signature_pqc: pqc_sig,
            scrub_key_id: author.to_owned(),
            scrub_timestamp: asserted_at,
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

    /// A `delegates_to` edge `granter → grantee` bearing `scopes`.
    fn delegation_row(
        id: &str,
        granter: &str,
        grantee: &str,
        scopes: &[&str],
        at: DateTime<Utc>,
    ) -> Attestation {
        let envelope = serde_json::json!({
            "dimension": "delegation:duty:v1",
            "scope": scopes,
        });
        let (och, ed_sig, pqc_sig) = sign_envelope(granter, &envelope);
        Attestation {
            attestation_id: id.to_owned(),
            attesting_key_id: granter.to_owned(),
            attested_key_id: grantee.to_owned(),
            attestation_type: attestation_type::DELEGATES_TO.to_owned(),
            weight: None,
            asserted_at: at,
            expires_at: None,
            attestation_envelope: envelope,
            original_content_hash: och,
            scrub_signature_classical: ed_sig,
            scrub_signature_pqc: pqc_sig,
            scrub_key_id: granter.to_owned(),
            scrub_timestamp: at,
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

    /// Is `id` present in the relay page `list_attestation_log` serves?
    async fn served(dir: &dyn FederationDirectory, id: &str) -> bool {
        dir.list_attestation_log(None, None, 10_000)
            .await
            .expect("list_attestation_log")
            .items
            .iter()
            .any(|r| r.attestation_id == id)
    }

    /// **The #570 asks-2/3/5 witness:**
    ///
    /// 1. an unattributed marker is REFUSED naming `unattributed` (ask 3's
    ///    requirement, applied to the marker itself);
    /// 2. a marker filed against the wrong key is REFUSED — a marker nobody
    ///    can find is not a marker;
    /// 3. a marker about an unregistered key is REFUSED;
    /// 4. a NON-`slash`-holder's marker is REFUSED naming `slash_unauthorized`
    ///    (ask 2 — the scope is a real gate, not a stored label);
    /// 5. a `slash`-duty holder's marker is ADMITTED, and the actor's rows
    ///    STOP being served while remaining held locally (ask 5);
    /// 6. the MARKER itself keeps being served — the convergence carve-out;
    /// 7. a RELEASE marker restores serving, with both acts still in the
    ///    corpus (reversible, non-destructive);
    /// 8. a `moderate`-only delegate cannot quarantine and a `slash`-bearing
    ///    delegate can — scope isolation, on the removal duty;
    /// 9. an `admin_action` hard_case is REFUSED without its attribution and
    ///    ADMITTED with it (ask 3, at the `record_hard_case` door).
    pub(crate) async fn exercise_admin_ops(dir: &dyn FederationDirectory, suffix: &str) {
        let founder = format!("qa-founder-{suffix}");
        let member = format!("qa-member-{suffix}");
        let stranger = format!("qa-stranger-{suffix}");
        let deputy_slash = format!("qa-dep-slash-{suffix}");
        let deputy_mod = format!("qa-dep-mod-{suffix}");
        let actor = format!("qa-actor-{suffix}");
        let community = format!("qa-commons-{suffix}");
        let now = Utc::now();

        for k in [&founder, &member, &stranger, &actor, &community] {
            register_user_key(dir, k).await;
        }
        for k in [&deputy_slash, &deputy_mod] {
            register_agent_key(dir, k).await;
        }

        // A community whose authority set is {founder, member}. `actor` and
        // `stranger` are deliberately NOT members.
        dir.put_community(
            crate::federation::tier_ingest::test_support::sign_community(
                &founder,
                Community {
                    community_key_id: community.clone(),
                    community_name: format!("commons {community}"),
                    members: vec![
                        CommunityMember {
                            key_id: founder.clone(),
                            joined_at: now,
                            role: Some("founder".to_owned()),
                        },
                        CommunityMember {
                            key_id: member.clone(),
                            joined_at: now,
                            role: Some("member".to_owned()),
                        },
                    ],
                    founded_at: now,
                    consensus_protocol: "majority".to_owned(),
                    policy_blob: None,
                    persist_row_hash: String::new(),
                },
            ),
        )
        .await
        .expect("put_community");

        // An ordinary federation-tier row by the actor — the thing serving
        // will (and then will not) hand to peers.
        let actor_row_id = uuid::Uuid::new_v4().to_string();
        let actor_row = signed_row(
            &actor_row_id,
            &actor,
            &actor,
            serde_json::json!({
                "dimension": "testimonial_witness:commons_act:v1",
                "payload": {"action": "an ordinary row"},
            }),
            now,
        );
        dir.put_attestation(SignedAttestation {
            attestation: actor_row,
        })
        .await
        .expect("the actor's row lands normally");
        assert!(
            served(dir, &actor_row_id).await,
            "({suffix}) before any marker the row is served"
        );

        let mk = |id: &str, author: &str, subject: &str, env: serde_json::Value| {
            signed_row(id, author, subject, env, Utc::now())
        };

        // ── (1) UNATTRIBUTED: no delegation_id ⇒ refused.
        let bare = mk(
            &uuid::Uuid::new_v4().to_string(),
            &founder,
            &actor,
            withhold_envelope(&actor, &community, "", "spam"),
        );
        assert_eq!(
            record_quarantine_marker(dir, &bare)
                .await
                .expect("policy outcome")
                .refusal(),
            Some(QuarantineRefusalReason::Unattributed),
            "({suffix}) an act that does not carry its own authority is \
             indistinguishable from an unauthorized one once the actor is gone"
        );

        // ── (2) FILED AGAINST THE WRONG KEY ⇒ refused (it would be inert).
        let misfiled = mk(
            &uuid::Uuid::new_v4().to_string(),
            &founder,
            &stranger, // attested_key_id ≠ quarantines_key_id
            withhold_envelope(&actor, &community, "att-deleg", "spam"),
        );
        assert_eq!(
            record_quarantine_marker(dir, &misfiled)
                .await
                .expect("policy outcome")
                .refusal(),
            Some(QuarantineRefusalReason::NotFiledAgainstSubject),
            "({suffix}) the preserve set must equal the verified set"
        );

        // ── (3) SUBJECT THIS NODE CANNOT NAME ⇒ refused.
        let ghost = format!("qa-ghost-{suffix}");
        let unknown = mk(
            &uuid::Uuid::new_v4().to_string(),
            &founder,
            &ghost,
            withhold_envelope(&ghost, &community, "att-deleg", "spam"),
        );
        assert_eq!(
            record_quarantine_marker(dir, &unknown)
                .await
                .expect("policy outcome")
                .refusal(),
            Some(QuarantineRefusalReason::SubjectKeyUnknown),
            "({suffix})"
        );

        // ── (4) A NON-HOLDER'S MARKER ⇒ refused naming the scope.
        let usurper = mk(
            &uuid::Uuid::new_v4().to_string(),
            &stranger,
            &actor,
            withhold_envelope(&actor, &community, "att-deleg", "spam"),
        );
        assert_eq!(
            record_quarantine_marker(dir, &usurper)
                .await
                .expect("policy outcome")
                .refusal(),
            Some(QuarantineRefusalReason::SlashUnauthorized),
            "({suffix}) `slash` is a gate, not a stored label — the #333 lesson"
        );
        assert!(
            !resolve_quarantine(dir, &actor, Utc::now())
                .await
                .expect("resolve")
                .withholds(),
            "({suffix}) four refusals wrote nothing"
        );
        assert!(served(dir, &actor_row_id).await, "({suffix}) still served");

        // ── (5) THE HOLDER'S MARKER LANDS, and serving stops.
        let withhold_id = uuid::Uuid::new_v4().to_string();
        let withhold = mk(
            &withhold_id,
            &founder,
            &actor,
            withhold_envelope(&actor, &community, "att-deleg-1", "sustained spam"),
        );
        assert_eq!(
            record_quarantine_marker(dir, &withhold)
                .await
                .expect("policy outcome"),
            QuarantineOutcome::Admitted,
            "({suffix}) a steward-bound community authority holds `slash` as-self"
        );
        let fold = resolve_quarantine(dir, &actor, Utc::now())
            .await
            .expect("resolve");
        assert_eq!(fold.state, QuarantineState::Withheld, "({suffix})");
        assert_eq!(fold.marker_id.as_deref(), Some(withhold_id.as_str()));
        assert_eq!(fold.decided_by.as_deref(), Some(founder.as_str()));
        assert_eq!(
            fold.delegation_id.as_deref(),
            Some("att-deleg-1"),
            "({suffix}) the attribution travels WITH the act"
        );
        assert!(
            !served(dir, &actor_row_id).await,
            "({suffix}) THE SERVE CONSULT: the actor's row is withheld"
        );
        // …and RETAINED. Withheld from serving is not deleted.
        assert!(
            dir.get_attestation(&actor_row_id)
                .await
                .expect("get")
                .is_some(),
            "({suffix}) rows are retained locally — persist deletes nothing"
        );

        // ── (6) THE CONVERGENCE CARVE-OUT: the marker itself keeps flowing.
        assert!(
            served(dir, &withhold_id).await,
            "({suffix}) a marker that stops replicating cannot be folded by \
             the rest of the mesh"
        );

        // ── (7) REVERSIBLE: a release restores serving, both acts survive.
        let release_id = uuid::Uuid::new_v4().to_string();
        let release = mk(
            &release_id,
            &founder,
            &actor,
            release_envelope(
                &actor,
                &community,
                &withhold_id,
                "att-deleg-1",
                "appeal upheld",
            ),
        );
        assert_eq!(
            record_quarantine_marker(dir, &release)
                .await
                .expect("policy outcome"),
            QuarantineOutcome::Admitted,
            "({suffix})"
        );
        let fold = resolve_quarantine(dir, &actor, Utc::now())
            .await
            .expect("resolve");
        assert_eq!(fold.state, QuarantineState::Released, "({suffix})");
        assert!(
            fold.marker_ids.contains(&withhold_id) && fold.marker_ids.contains(&release_id),
            "({suffix}) reversible does not mean erased — the corpus names both"
        );
        assert!(
            served(dir, &actor_row_id).await,
            "({suffix}) serving resumes with no reconstruction"
        );
        // A release naming a marker this node does not hold is refused.
        let dangling = mk(
            &uuid::Uuid::new_v4().to_string(),
            &founder,
            &actor,
            release_envelope(&actor, &community, "no-such-marker", "att-deleg-1", "nope"),
        );
        assert_eq!(
            record_quarantine_marker(dir, &dangling)
                .await
                .expect("policy outcome")
                .refusal(),
            Some(QuarantineRefusalReason::MarkerUnknown),
            "({suffix})"
        );

        // ── (8) SCOPE ISOLATION on the removal duty. A `moderate`-only
        //        delegate may file reports; it may NOT take things away.
        for (deputy, scope) in [
            (&deputy_mod, DELEGATION_SCOPE_MODERATE),
            (&deputy_slash, DELEGATION_SCOPE_SLASH),
        ] {
            dir.put_attestation(SignedAttestation {
                attestation: delegation_row(
                    &uuid::Uuid::new_v4().to_string(),
                    &founder,
                    deputy,
                    &[scope],
                    Utc::now(),
                ),
            })
            .await
            .expect("delegates_to lands");
        }
        let by_mod_deputy = mk(
            &uuid::Uuid::new_v4().to_string(),
            &deputy_mod,
            &actor,
            withhold_envelope(&actor, &community, "att-deleg-2", "reported"),
        );
        assert_eq!(
            record_quarantine_marker(dir, &by_mod_deputy)
                .await
                .expect("policy outcome")
                .refusal(),
            Some(QuarantineRefusalReason::SlashUnauthorized),
            "({suffix}) a `moderate` chain must not confer removal — an \
             authority to write a note is not an authority to take away"
        );
        let by_slash_deputy = mk(
            &uuid::Uuid::new_v4().to_string(),
            &deputy_slash,
            &actor,
            withhold_envelope(&actor, &community, "att-deleg-3", "delegated"),
        );
        assert_eq!(
            record_quarantine_marker(dir, &by_slash_deputy)
                .await
                .expect("policy outcome"),
            QuarantineOutcome::Admitted,
            "({suffix}) a `slash`-bearing chain from a steward-bound root DOES"
        );
        assert!(
            !served(dir, &actor_row_id).await,
            "({suffix}) the delegate's marker withholds exactly as the root's did"
        );

        // ── (9) ASK 3 at its own door: `record_hard_case`.
        let quarantine_kind = admin_action_kind(admin_op::QUARANTINE);
        let mut unattributed = admin_action_event(
            admin_op::QUARANTINE,
            &actor,
            Some(&founder),
            "att-deleg-1",
            "sustained spam",
            Utc::now(),
        );
        unattributed
            .detail
            .as_object_mut()
            .expect("object")
            .remove(admin_field::REASON);
        let before = dir
            .list_hard_case_events(HardCaseFilter {
                kind: Some(quarantine_kind.clone()),
                since: None,
            })
            .await
            .expect("list")
            .len();
        let err = dir
            .record_hard_case(unattributed)
            .await
            .expect_err("an unattributed admin action is refused");
        assert_eq!(
            err.kind(),
            "federation_admin_action_unattributed",
            "({suffix})"
        );
        assert!(
            matches!(
                err,
                Error::AdminActionUnattributed {
                    reason: AdminActionRefusal::ReasonAbsent
                }
            ),
            "({suffix}) the refusal names WHICH half is missing"
        );
        let attributed = admin_action_event(
            admin_op::QUARANTINE,
            &actor,
            Some(&founder),
            "att-deleg-1",
            "sustained spam",
            Utc::now(),
        );
        dir.record_hard_case(attributed.clone())
            .await
            .expect("a fully attributed admin action records");
        let rows = dir
            .list_hard_case_events(HardCaseFilter {
                kind: Some(quarantine_kind),
                since: None,
            })
            .await
            .expect("list");
        assert_eq!(
            rows.len(),
            before + 1,
            "({suffix}) verify-before-mutation: the refused record wrote nothing"
        );
        let stored = rows
            .iter()
            .find(|r| r.event_id == attributed.event_id)
            .expect("the attributed row is enumerable");
        assert_eq!(
            stored.detail[admin_field::DELEGATION_ID].as_str(),
            Some("att-deleg-1"),
            "({suffix}) enumerating what a compromised authority did is the \
             whole reason the attribution is required"
        );
    }
}
