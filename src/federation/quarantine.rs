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

use super::attestation_query::{AttestationQuery, FOLD_PAGE};
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
///
/// **This was "the only one of 109"; on the 114-family rc3 cut it is one of
/// FOUR, and the shape of the gap changed with the count.** The others are
/// `regime:{artifact}:{version}` (CIRISPersist#571), `mesh_config:{key}` and
/// `content_rating:{scheme}:{rating}` (v62.0.0, CC rc20: THREE — the
/// `content_rating:` row no longer states an emitter; CC 3.3.12 leaves it
/// open vocabulary). All of them sit in **CC 3.1.9.2** — as do
/// all 12 of that section's families, **none** of which carries a
/// `reserved_rule`. So this is not four unlucky rows: CC's generator sources
/// reserved rules from CC 3.4 plus a `Reserved?` table column, and 3.1.9.2's
/// table is `| Prefix | Description | Polarity |` — it has neither. **The
/// governance-steering tier is structurally unable to carry an enforceable
/// emitter rule**, which is a better-aimed CC ask than four row-by-row ones.
///
/// A count in a doc comment is exactly the claim that rots silently, so it is
/// measured rather than asserted:
/// [`registry::tests::the_prose_only_emitter_rules_are_still_confined_to_cc_3_1_9_2`](super::namespace::registry)
/// recomputes both numbers from the vendored bytes and fails when either moves.
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
/// [`RULES_NOT_ON_THE_ROW`](super::family_rules::RULES_NOT_ON_THE_ROW);
/// getting it onto the row rides CIRISConstitution#76.
pub const NAMESPACE_FAMILY: &str = "quarantine:{state}";

/// Envelope field names shared by the producer side and persist's fold, so the
/// two cannot disagree about where a reference lives.
pub mod field {
    /// The `federation_keys.key_id` being withheld / released. Also the
    /// marker's `attested_key_id`, so one existing read
    /// ([`list_attestations_for`](crate::federation::attestation_query::AttestationQuery::to))
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

/// v62.0.0 (K2-fix9) — **the `quarantine:{state}` cells of CC rc21's family
/// model** that CIRISVerify 23.3.1 does not vendor yet. Each cell is applied
/// by persist here; **drop each when Verify vendors it (23.3.3)** and read
/// Verify's answer instead.
///
/// - **authorship** — "group=affiliations & seats=one => counted ;
///   authored" (CC 4.4.3.12): authored by the slash-duty holder; counted
///   (`affiliation_member_action@subject_group`) only in an affiliation's
///   one-voice seat. Verify 23.3.1 ALREADY vendors this cell
///   (`family_authorship.json`), so persist's family model reads it from
///   Verify; [`crate::federation::edition2::occurrence::PersistCells`] pins
///   it with the empty second-signer list below.
/// - **second_signers** — none ([`SECOND_SIGNERS`]).
/// - **signer_rule** — `seat_role(slash)` via `delegates_to(slash)` (CC
///   3.1.9.2, CC 4.5.5) ([`SIGNER_RULE`]): applied by
///   [`check_delegated_duty_scores_admission`](super::admission::check_delegated_duty_scores_admission)
///   on the quarantine arm. An unauthorized signer is refused
///   `federation_delegated_scope_unauthorized` (`put_attestation`), and at
///   the statement door the row is held with the GC1 reason
///   `delegated_scope_unauthorized` (CC 2.7.3: the seat is other rows).
/// - **signer_kind** — `attest` / `withdraw` / `supersede`: any-of(`agent`,
///   person), rule `actor_content` (CC 3.4.7.3 C and E) ([`SIGNER_KINDS`],
///   [`SIGNER_KIND_RULE`]). A node key never signs it:
///   [`check_signer_kind`], a refusal on the signer's own key record (a door
///   input, CC 2.7.3).
/// - **marker-plane precedence** (CC 3.1.9.2, part_3 l.646): the marker
///   plane never withholds itself ([`filter_withheld_rows`]), and a withhold
///   outranks a release whatever their instants ([`fold_quarantine`]).
pub mod cells {
    /// DROP AT 23.3.3. The family's model second signers: none.
    pub const SECOND_SIGNERS: &[&str] = &[];
    /// DROP AT 23.3.3. The signer rule (CC 3.1.9.2, CC 4.5.5).
    pub const SIGNER_RULE: &str = "seat_role(slash) via delegates_to(slash)";
    /// DROP AT 23.3.3. The signer kinds for `attest` / `withdraw` /
    /// `supersede` (CC 3.4.7.3 C and E): an agent or a person (`user` /
    /// `accord_holder`).
    pub const SIGNER_KINDS: &[&str] = &["agent", "user", "accord_holder"];
    /// DROP AT 23.3.3. The signer-kind rule's name in CC's model.
    pub const SIGNER_KIND_RULE: &str = "actor_content";
    /// The refusal token of [`super::check_signer_kind`]: a quarantine
    /// marker signed by a key that is neither an agent nor a person.
    /// `Error::InvalidArgument` (Python `ValueError`), terminal.
    pub const SIGNER_KIND_REFUSED: &str = "quarantine_signer_kind_refused";
}

/// v62.0.0 (K2-fix9; CC 3.4.7.3 C and E, the `quarantine:{state}`
/// signer_kind cell, DROP AT 23.3.3) — **a quarantine marker is signed by an
/// agent or a person, never by a node key.** Read from the SIGNER's own key
/// record (`lookup_public_key(attesting_key_id)`): a door input, so the
/// refusal is terminal, not a hold. A signer whose record is not held here
/// is left to the key gates (it waits there). A no-op for any row that is
/// not a quarantine marker.
///
/// # Errors
/// [`Error::InvalidArgument`] prefixed [`cells::SIGNER_KIND_REFUSED`];
/// directory reads.
pub async fn check_signer_kind<F>(directory: &F, row: &Attestation) -> Result<(), Error>
where
    F: FederationDirectory + ?Sized,
{
    use super::types::identity_type::set_contains;
    let Some(dimension) = envelope_str(row, "dimension") else {
        return Ok(());
    };
    if !dimension.starts_with(super::admission::QUARANTINE_DIMENSION_PREFIX) {
        return Ok(());
    }
    let Some(rec) = directory.lookup_public_key(&row.attesting_key_id).await? else {
        return Ok(());
    };
    if cells::SIGNER_KINDS
        .iter()
        .any(|k| set_contains(&rec.identity_type, k))
    {
        return Ok(());
    }
    Err(Error::InvalidArgument(format!(
        "{}: {} is signed by {} ({}), but a quarantine marker is signed by an agent or a \
         person, never a node key (CC 3.4.7.3 C and E, rule {})",
        cells::SIGNER_KIND_REFUSED,
        row.attestation_id,
        row.attesting_key_id,
        rec.identity_type,
        cells::SIGNER_KIND_RULE
    )))
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
/// v62.0.0 (K2-fix9; CC 3.1.9.2, part_3 l.646 at rc21: "a withhold outranks
/// a release whatever their instants. The withhold holds until a release
/// names the withhold it lifts. Between one holder's own markers the CC
/// 3.5.1 default applies.") — the precedence, in two layers:
///
/// 1. **One holder's own markers** (the same `attesting_key_id`): the CC
///    3.5.1 default, newest-wins, ordered by `(asserted_at,
///    withhold-beats-release, attestation_id)`. That gives the holder's
///    governing marker; a holder's own later release lifts their own
///    withhold.
/// 2. **Across holders:** a holder's governing WITHHOLD stays live unless a
///    release (by anyone) NAMES it ([`field::RELEASES`]). A release that
///    names no live withhold lifts nothing, however late its instant, so no
///    second holder can lift a quarantine by out-dating it.
///
/// The state is `Withheld` while any live withhold remains (the governing
/// marker is the newest live withhold), else `Released` (the newest release
/// governs). Within layer 1 the tie rules below are unchanged:
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
    let order = |a: &&Attestation, b: &&Attestation| {
        a.asserted_at
            .cmp(&b.asserted_at)
            .then_with(|| withhold_rank(a).cmp(&withhold_rank(b)))
            .then_with(|| a.attestation_id.cmp(&b.attestation_id))
    };
    effective.sort_by(&order);
    let mut marker_ids: Vec<String> = effective.iter().map(|m| m.attestation_id.clone()).collect();
    marker_ids.sort();

    // Layer 1 (CC 3.5.1): each holder's own governing marker.
    let mut per_holder: std::collections::BTreeMap<&str, &Attestation> =
        std::collections::BTreeMap::new();
    for m in &effective {
        // `effective` is sorted ascending: the last write per holder wins.
        per_holder.insert(m.attesting_key_id.as_str(), m);
    }
    // Layer 2: a withhold is lifted across holders only by a release that
    // NAMES it.
    let named: std::collections::BTreeSet<&str> = effective
        .iter()
        .filter(|m| envelope_str(m, "dimension") == Some(DIMENSION_RELEASED))
        .filter_map(|m| envelope_nonempty(m, field::RELEASES))
        .collect();
    let mut live: Vec<&Attestation> = per_holder
        .values()
        .copied()
        .filter(|m| {
            envelope_str(m, "dimension") == Some(DIMENSION_WITHHELD)
                && !named.contains(m.attestation_id.as_str())
        })
        .collect();
    live.sort_by(&order);
    let governing = match live.last() {
        Some(w) => *w,
        None => effective
            .iter()
            .rev()
            .find(|m| envelope_str(m, "dimension") == Some(DIMENSION_RELEASED))
            .copied()
            .unwrap_or(effective[effective.len() - 1]),
    };
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

    // v62.0.0 (wave GC8; CC 2.7.3) — the three legs below that read OTHER
    // rows (the SUBJECT's key record, the withhold marker a release names,
    // the duty-holder's seats and chains) are fold conditions: each marks
    // the running fold attempt with its token, so a marker reached under an
    // attempt is HELD and re-folds when the subject's key, the named marker
    // or a seat / delegation lands. Outside an attempt (this earlier-form
    // door) the outcome is the refusal it was. The marker's own fields and
    // its author's signature stay door refusals.
    use super::edition2::fold as e2fold;
    e2fold::reads(e2fold::Dep::key(&subject));
    e2fold::reads(e2fold::Dep::key(&marker.attesting_key_id));
    // The subject must be a key this node can name.
    if directory.lookup_public_key(&subject).await?.is_none() {
        e2fold::note(e2fold::reason::gc8::SUBJECT_KEY_UNKNOWN);
        return refused(QuarantineRefusalReason::SubjectKeyUnknown);
    }

    // The author's own signature, re-verified against this node's directory
    // (#377 — never pubkeys carried on the row).
    //
    // v62.0.0 (F0-cp9; the one verify path, as `mesh_config`'s E6-fix8) — the
    // ROW's verify: a v62 marker is the projection of the edition-2 statement
    // it carries, proven by that statement's composite under the author's
    // live key (`tier_ingest::verify_row_hybrid_signature` →
    // `ingest::verify_carried`). cp8's envelope-only `vouched_envelope` could
    // never pass one; a row carrying no statement meets the earlier-form
    // arms, which refuse it by name.
    if super::tier_ingest::verify_row_hybrid_signature(directory, marker)
        .await
        .is_err()
    {
        return refused(QuarantineRefusalReason::UnverifiableSignature);
    }

    // A release must name a withhold marker this node holds against the SAME
    // key — the same test `fold_quarantine` applies, so a release cannot be
    // admitted under one rule and re-priced under another.
    if let Some(marker_id) = &releases {
        if let Some(named_row) = hex::decode(marker_id)
            .ok()
            .and_then(|b| <[u8; 32]>::try_from(b.as_slice()).ok())
        {
            e2fold::reads(e2fold::Dep::Row(super::edition2::names::RowId(named_row)));
        }
        let named = directory.get_attestation(marker_id).await?;
        let resolves = named.is_some_and(|row| {
            envelope_str(&row, "dimension") == Some(DIMENSION_WITHHELD)
                && envelope_str(&row, field::QUARANTINES) == Some(subject.as_str())
        });
        if !resolves {
            e2fold::note(e2fold::reason::gc8::MARKER_UNKNOWN);
            return refused(QuarantineRefusalReason::MarkerUnknown);
        }
    }

    // ── THE `slash` GATE, re-derived from this node's own verified state.
    match super::admission::check_delegated_duty_scores_admission(directory, marker).await {
        Ok(()) => {}
        Err(Error::DelegatedScopeUnauthorized { .. }) => {
            e2fold::note(e2fold::reason::gc8::SLASH_UNAUTHORIZED);
            return refused(QuarantineRefusalReason::SlashUnauthorized);
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
    // Both marker dimensions share the `quarantine:` family: the prefix seek
    // carries them, the exact match below picks them.
    let mut rows = Vec::new();
    let mut pages = AttestationQuery::to(key_id, FOLD_PAGE)
        .dimension_prefix("quarantine:")
        .pages();
    let read: Result<(), Error> = async {
        while let Some(page) = pages.next(directory).await? {
            rows.extend(page);
        }
        Ok(())
    }
    .await;
    match read {
        Ok(()) => {}
        Err(Error::Unsupported { .. }) => rows.clear(),
        Err(e) => return Err(e),
    }
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

    /// v62.0.0 (K2-fix9; CC 3.1.9.2, part_3 l.646) — **I2854 (pure)**: a
    /// withhold outranks a release whatever their instants. Another holder's
    /// NEWER release that names no live withhold lifts nothing; a release
    /// naming the withhold lifts it, whatever its instant; between one
    /// holder's own markers the CC 3.5.1 default (newest-wins) still applies.
    #[test]
    fn i2854_a_withhold_outranks_a_release_whatever_their_instants() {
        let names = |mut r: Attestation, target: &str| {
            r.attestation_envelope[field::RELEASES] = serde_json::json!(target);
            r
        };
        let w = marker(
            "m-w",
            "k-mod-a",
            "k-bad",
            DIMENSION_WITHHELD,
            "2026-08-02T10:00:00Z",
        );
        let r_other = names(
            marker(
                "m-r",
                "k-mod-b",
                "k-bad",
                DIMENSION_RELEASED,
                "2026-08-02T12:00:00Z",
            ),
            "m-something-else",
        );
        let f = fold_quarantine(
            "k-bad",
            &[w.clone(), r_other.clone()],
            ts("2026-08-02T13:00:00Z"),
        );
        assert_eq!(
            (f.state, f.marker_id.as_deref()),
            (QuarantineState::Withheld, Some("m-w")),
            "I2854: a newer release by another holder that names no live withhold lifts nothing"
        );
        // An OLDER release naming the withhold lifts it: instants do not order
        // them, the name does.
        let r_named = names(
            marker(
                "m-r2",
                "k-mod-b",
                "k-bad",
                DIMENSION_RELEASED,
                "2026-08-02T09:00:00Z",
            ),
            "m-w",
        );
        let f = fold_quarantine("k-bad", &[w.clone(), r_named], ts("2026-08-02T13:00:00Z"));
        assert_eq!(
            f.state,
            QuarantineState::Released,
            "I2854: the named withhold is lifted"
        );
        // Between one holder's own markers: CC 3.5.1, newest-wins.
        let own = names(
            marker(
                "m-r3",
                "k-mod-a",
                "k-bad",
                DIMENSION_RELEASED,
                "2026-08-02T11:00:00Z",
            ),
            "m-none",
        );
        let f = fold_quarantine("k-bad", &[w, own], ts("2026-08-02T13:00:00Z"));
        assert_eq!(
            f.state,
            QuarantineState::Released,
            "I2854: a holder's own later release lifts its own withhold"
        );
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
    use crate::federation::edition2::fixture_switch as e2;
    use crate::federation::hard_case::{
        admin_action_event, admin_action_kind, admin_field, admin_op, AdminActionRefusal,
        HardCaseFilter,
    };
    use crate::federation::types::{attestation_tier, attestation_type};

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

    /// v62 (E3): the key is live through its edition-2 `key:record`
    /// (`e2::put_key`); `key_id` is the SEED, the stored id is `e2::kid(key_id)`.
    async fn register_key(dir: &dyn FederationDirectory, key_id: &str, identity_type: &str) {
        e2::put_key(dir, key_id, &[identity_type]).await;
    }

    /// A federation-tier `scores` row carrying `envelope`, authored + scrubbed
    /// by `author`, about `subject`.
    fn signed_row(
        author: &str,
        subject: &str,
        envelope: serde_json::Value,
        asserted_at: DateTime<Utc>,
    ) -> Attestation {
        // v62 (E3): an edition-2 statement by `author` (a seed); the row id is
        // node-computed, so callers read `attestation_id` off the result.
        e2::row_of(
            &unsigned_row(
                author,
                subject,
                attestation_type::SCORES,
                envelope,
                asserted_at,
            ),
            author,
        )
    }

    /// The unsigned, earlier-form-shaped row the codec signs.
    fn unsigned_row(
        author: &str,
        subject: &str,
        attestation_type: &str,
        envelope: serde_json::Value,
        asserted_at: DateTime<Utc>,
    ) -> Attestation {
        Attestation {
            attestation_id: String::new(),
            attesting_key_id: e2::kid(author),
            attested_key_id: subject.to_owned(),
            attestation_type: attestation_type.to_owned(),
            weight: None,
            asserted_at,
            expires_at: None,
            attestation_envelope: envelope,
            original_content_hash: String::new(),
            scrub_signature_classical: String::new(),
            scrub_signature_pqc: None,
            scrub_key_id: e2::kid(author),
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
        granter: &str,
        grantee: &str,
        scopes: &[&str],
        at: DateTime<Utc>,
    ) -> Attestation {
        // K2-fix13: no `dimension` (`delegation:duty:v1` is no registered
        // dimension of `self:delegates_to`: `dimension_unregistered`).
        let mut envelope = serde_json::json!({
            "scope": scopes,
        });
        // v60.0.0 (#1048) — a duty edge carries a term (CC 2.4).
        crate::federation::admission::with_test_term(&mut envelope, at);
        // v62 (E3): a duty edge is a `self:delegates_to` row (RULINGS).
        let a = unsigned_row(
            granter,
            grantee,
            attestation_type::DELEGATES_TO,
            envelope,
            at,
        );
        e2::row_of_statement(
            &e2::statement_of_family(&a, granter, "self:delegates_to"),
            attestation_tier::FEDERATION,
        )
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

    /// v62.0.0 (K2-fix11, K2-fix13) — the shared minor/adult fixture: a
    /// `witness` key conferred `infra:attest_assurance` by W1b's ROOTED
    /// edition-2 trust root (`fixture_trust_root::rooted_trust_root`: an
    /// `infrastructure` community founded by the bundle's holders, its
    /// charter, and THIS node's acceptance naming the held head), through
    /// the root's `trust:confers:v1` grant and the witness's own second voice
    /// (CC 2.6.1.9). Returns the witness seed.
    ///
    /// K2-fix13: the earlier fixture (`confer_scope_from_trusted_root_at`: a
    /// bare key chartering itself) stands up no rooted trust root, so since
    /// the pinned bundle's deletion (C5-fix1) its grant roots nowhere, the
    /// age row is held `reserved_prefix_emitter_mismatch`, and no band
    /// resolves. The grant is dated as W1b dates its own
    /// (`put_conferral`): the bundle in force's newest tip + 90 s.
    ///
    /// # Panics
    /// The node is not `node_seed`, a refusal, or the grant does not root at
    /// the root through this node (`capability_roots_to_trusted_root`).
    async fn confer_age_witness(
        dir: &dyn FederationDirectory,
        node_seed: &str,
        tag: &str,
    ) -> String {
        confer_age_witnesses(dir, node_seed, &[tag])
            .await
            .pop()
            .expect("one witness")
    }

    /// v62.0.0 (K2-fix15) — [`confer_age_witness`] for several witnesses
    /// under ONE rooted trust root (`rooted_trust_root` is stood up once per
    /// directory): witness `i` is `"{tags[i]}-witness"`, its grant dated
    /// `i` seconds after the first.
    async fn confer_age_witnesses(
        dir: &dyn FederationDirectory,
        node_seed: &str,
        tags: &[&str],
    ) -> Vec<String> {
        use crate::federation::edition2::fixture_genesis::HOLDER_SEEDS;
        use crate::federation::edition2::fixture_trust_root::confers_statement;
        use crate::federation::types::delegation_scope::INFRA_ATTEST_ASSURANCE;
        let node = e2::kid(node_seed);
        assert_eq!(
            dir.node_key_id().as_deref(),
            Some(node.as_str()),
            "confer_age_witness: the runner gives the backend `node_seed`'s identity"
        );
        let r = e2::rooted_trust_root(dir, &HOLDER_SEEDS, "quorum:2/3").await;
        let first = crate::federation::edition2::genesis::genesis_in_force(dir)
            .await
            .expect("the bundle in force")
            .tips()
            .iter()
            .map(|t| t.asserted_at)
            .max()
            .expect("a bundle tip")
            + 90_000;
        let mut out = Vec::new();
        for (i, tag) in (0u64..).zip(tags.iter()) {
            let witness = format!("{tag}-witness");
            register_key(
                dir,
                &witness,
                crate::federation::types::identity_type::WITNESS,
            )
            .await;
            let grant = confers_statement(
                &r,
                &e2::kid(&witness),
                &[INFRA_ATTEST_ASSURANCE],
                first + i * 1_000,
            );
            e2::put_statement(dir, &grant)
                .await
                .unwrap_or_else(|e| panic!("confer_age_witness: the root's grant: {e}"));
            e2::put_statement(dir, &e2::voice_of(&grant, &witness))
                .await
                .unwrap_or_else(|e| panic!("confer_age_witness: the witness's voice: {e}"));
            let rooted = crate::federation::trust_root::capability_roots_to_trusted_root(
                dir,
                &node,
                &e2::kid(&witness),
                INFRA_ATTEST_ASSURANCE,
            )
            .await
            .expect("capability_roots_to_trusted_root");
            assert!(
                rooted.as_ref().is_some_and(|g| g.root_key_id == r.root),
                "confer_age_witness: the witness's {INFRA_ATTEST_ASSURANCE} roots at {} through \
                 this node: {rooted:?}",
                r.root
            );
            out.push(witness);
        }
        out
    }

    /// An age row by `by` about `about` (`age_assurance:*` by a witness, or
    /// `age_self_declared:*` by the subject), dated `at`, through the door.
    async fn put_age_row(
        dir: &dyn FederationDirectory,
        by: &str,
        about: &str,
        token: &str,
        at: DateTime<Utc>,
    ) -> Attestation {
        put_age_row_until(dir, by, about, token, at, None).await
    }

    /// v62.0.0 (K2-fix14) — [`put_age_row`] with an `expires_at`, stamped
    /// BEFORE the seal (`expires_at` is a common payload member, so the
    /// statement carries it).
    async fn put_age_row_until(
        dir: &dyn FederationDirectory,
        by: &str,
        about: &str,
        token: &str,
        at: DateTime<Utc>,
        expires_at: Option<DateTime<Utc>>,
    ) -> Attestation {
        use crate::federation::tier_ingest::test_support as ts;
        let id = uuid::Uuid::new_v4().to_string();
        let mut a = ts::bare_attestation(&id, by, about, &serde_json::json!({ "id": id }));
        a.attestation_type = token.to_owned();
        a.asserted_at = at;
        a.scrub_timestamp = at;
        a.expires_at = expires_at;
        ts::seal_row_in_place(by, &mut a);
        e2::put_signed(dir, &a)
            .await
            .unwrap_or_else(|e| panic!("the age row {token} about {about}: {e}"));
        a
    }

    /// v62.0.0 (K2-fix14) — `by` withdraws the held age row `row` (an
    /// edition-2 `withdraws` composer naming it, `e2::composer_of`). The
    /// subject withdraws its own declaration; a witness its own verdict.
    ///
    /// # Panics
    /// The composer does not land as a row.
    async fn withdraw_age_row(dir: &dyn FederationDirectory, row: &Attestation, by: &str) {
        use crate::federation::edition2::ingest::StatementOutcome;
        let w = e2::composer_of(attestation_type::WITHDRAWS, row, by);
        let out = e2::put_signed(dir, &w)
            .await
            .unwrap_or_else(|e| panic!("{by} withdraws its age row: {e}"));
        assert!(
            matches!(out, StatementOutcome::Row { .. }),
            "{by} withdraws its age row: {out:?}"
        );
    }

    /// The founder's duty edge `delegates_to(slash, community_id: C)` onto
    /// `grantee`, or (`duty = false`) a pure guardianship (custody purpose,
    /// `infra:serve`, no duty scope), dated `at`.
    fn founder_edge(
        founder: &str,
        community_k: &str,
        grantee: &str,
        duty: bool,
        at: DateTime<Utc>,
    ) -> Attestation {
        if duty {
            return founder_scoped_edge(founder, community_k, grantee, DELEGATION_SCOPE_SLASH, at);
        }
        let mut envelope = serde_json::json!({
            "delegation_purpose": crate::federation::types::owner_binding::CC_DELEGATION_PURPOSE,
            "scope": [crate::federation::types::delegation_scope::INFRA_SERVE],
        });
        crate::federation::admission::with_test_term(&mut envelope, at);
        let a = unsigned_row(
            founder,
            &e2::kid(grantee),
            attestation_type::DELEGATES_TO,
            envelope,
            at,
        );
        e2::row_of_statement(
            &e2::statement_of_family(&a, founder, "self:delegates_to"),
            attestation_tier::FEDERATION,
        )
    }

    /// `founder`'s duty edge `delegates_to(founder → grantee, scope:
    /// [scope], community_id: community_k)` at `at`, as an edition-2 row.
    fn founder_scoped_edge(
        founder: &str,
        community_k: &str,
        grantee: &str,
        scope: &str,
        at: DateTime<Utc>,
    ) -> Attestation {
        // K2-fix13: no `dimension` (a `delegates_to` duty edge names its
        // duty by `scope`; an invented dimension is `dimension_unregistered`).
        let mut envelope = serde_json::json!({
            "scope": [scope],
            "community_id": community_k,
        });
        crate::federation::admission::with_test_term(&mut envelope, at);
        let a = unsigned_row(
            founder,
            &e2::kid(grantee),
            attestation_type::DELEGATES_TO,
            envelope,
            at,
        );
        e2::row_of_statement(
            &e2::statement_of_family(&a, founder, "self:delegates_to"),
            attestation_tier::FEDERATION,
        )
    }

    /// The duty the I2030 guild's record declares (CC 4.5.4: not a core
    /// duty).
    const DECLARED_DUTY: &str = "curate";

    /// A community founded by `founder` (with `member`) at `at`, through
    /// T1's roster voices.
    async fn found_commons(
        dir: &dyn FederationDirectory,
        founder: &str,
        member: &str,
        community: &str,
        at: DateTime<Utc>,
    ) {
        found_commons_with(dir, founder, member, community, at, None).await;
    }

    /// [`found_commons`] with the record's `policy` map (`policy_blob`).
    async fn found_commons_with(
        dir: &dyn FederationDirectory,
        founder: &str,
        member: &str,
        community: &str,
        at: DateTime<Utc>,
        policy_blob: Option<serde_json::Value>,
    ) {
        let community_row = crate::federation::tier_ingest::test_support::sign_community(
            founder,
            crate::federation::types::Community {
                prev_head_digest: String::new(),
                charter_digest: String::new(),
                community_key_id: community.to_owned(),
                community_name: format!("commons {community}"),
                members: vec![
                    crate::federation::types::CommunityMember {
                        key_id: founder.to_owned(),
                        joined_at: at,
                        role: Some("founder".to_owned()),
                    },
                    crate::federation::types::CommunityMember {
                        key_id: member.to_owned(),
                        joined_at: at,
                        role: Some("member".to_owned()),
                    },
                ],
                founded_at: at,
                consensus_protocol: "majority".to_owned(),
                policy_blob,
                persist_row_hash: String::new(),
            },
        );
        e2::put_voices(
            dir,
            &e2::community_voices(&community_row, 1, None, e2::ms(at)),
        )
        .await
        .expect("the community roster lands");
    }

    /// v62.0.0 (K2-fix11; CC rc21 4.5.4: the duty set is OPEN) — **I2030**,
    /// on every backend. A duty the community's record declares
    /// (`policy.duties = ["curate"]`, `admission::duty_set_in_force`) is a
    /// duty, so an appointment to it onto a minor is void exactly like a core
    /// one: `Pending`, `why_held == minor_appointment_void`, and
    /// `is_named_moderator(minor, guild, curate)` is false. Controls: the
    /// same edge onto an assured adult SEATS (the declared duty is a real
    /// seat), and `curate` in a community that does NOT declare it is never
    /// judged `minor_appointment_void`.
    ///
    /// Dates: the founder key's window start + `OWNER_BINDING_OFFSET_DAYS`
    /// (`late`) plus minutes / hours.
    pub(crate) async fn exercise_declared_duty(
        engine: &crate::Engine,
        node_seed: &str,
        suffix: &str,
    ) {
        use crate::federation::admission::is_named_moderator;
        use crate::federation::age::{age_band, AgeBand};
        use crate::federation::edition2::fold::{reason::gc1::MINOR_APPOINTMENT_VOID, why_held};
        use crate::federation::edition2::ingest::StatementOutcome;
        use crate::federation::edition2::names::RowId;
        let directory = engine.federation_directory();
        let dir: &dyn FederationDirectory = directory.as_ref();
        let k = |n: &str| format!("q13-{n}-{suffix}");
        let (founder, member, community) = (k("founder"), k("member"), k("commons"));
        let (cm, ca, cn) = (k("cm"), k("ca"), k("cn"));
        for x in [&founder, &member, &community, &cm, &ca, &cn] {
            register_user_key(dir, x).await;
        }
        let base = DateTime::<Utc>::from_timestamp_millis(
            i64::try_from(e2::key_window_start_ms(&founder)).expect("a window start fits i64"),
        )
        .expect("an instant");
        let late = base
            + chrono::Duration::days(
                crate::federation::tier_ingest::test_support::OWNER_BINDING_OFFSET_DAYS,
            );
        let min = chrono::Duration::minutes(1);
        let hour = chrono::Duration::hours(1);
        let witness = confer_age_witness(dir, node_seed, &k("age")).await;
        put_age_row(
            dir,
            &witness,
            &founder,
            "age_assurance:provider:adult:v1",
            late + min,
        )
        .await;
        assert_eq!(
            age_band(dir, &e2::kid(&founder)).await.expect("band"),
            AgeBand::Adult,
            "({suffix}) I2030: precondition, the founder is an assured adult"
        );
        found_commons(dir, &founder, &member, &community, base).await;
        let community_k = e2::kid(&community);
        let land = |e: Attestation, by: String| async move {
            e2::land_with_voices(dir, &e, &[by.as_str()]).await
        };
        let void_held = |e: Attestation| async move {
            let why = why_held(dir, &RowId(e2::rid_digest(&e)))
                .await
                .expect("read the hold");
            why.is_some_and(|w| w.reason == MINOR_APPOINTMENT_VOID)
        };
        let (cm, ca, cn) = (&cm, &ca, &cn);
        let guild = k("guild");
        register_user_key(dir, &guild).await;
        found_commons_with(
            dir,
            &founder,
            &member,
            &guild,
            base,
            Some(serde_json::Value::Object(
                std::iter::once((
                    crate::federation::admission::COMMUNITY_DECLARED_DUTIES_MEMBER.to_owned(),
                    serde_json::json!([DECLARED_DUTY]),
                ))
                .collect(),
            )),
        )
        .await;
        let guild_k = e2::kid(&guild);
        assert!(
            crate::federation::admission::duty_set_in_force(dir, &guild_k)
                .await
                .expect("the duty set")
                .contains(DECLARED_DUTY),
            "({suffix}) I2030: the guild's record declares `{DECLARED_DUTY}`"
        );
        let named_curate = |who: &str| {
            let who = e2::kid(who);
            let guild_k = guild_k.clone();
            async move {
                is_named_moderator(dir, &who, &guild_k, DECLARED_DUTY)
                    .await
                    .expect("is_named_moderator")
            }
        };
        put_age_row(
            dir,
            cm,
            cm,
            "age_self_declared:band:minor:v1",
            late + min * 2,
        )
        .await;
        put_age_row(
            dir,
            &witness,
            ca,
            "age_assurance:provider:adult:v1",
            late + min * 2,
        )
        .await;
        put_age_row(
            dir,
            cn,
            cn,
            "age_self_declared:band:minor:v1",
            late + min * 2,
        )
        .await;
        let d = founder_scoped_edge(&founder, &guild_k, cm, DECLARED_DUTY, late + hour);
        let out = land(d.clone(), cm.clone())
            .await
            .unwrap_or_else(|e| panic!("({suffix}) I2030 declared: kept, not refused: {e}"));
        assert!(
            matches!(out, StatementOutcome::Pending { .. }) && void_held(d.clone()).await,
            "({suffix}) I2030: a community-declared duty onto the minor is held \
             minor_appointment_void: {out:?}"
        );
        assert!(
            !named_curate(cm).await,
            "({suffix}) I2030: no minor holds the declared duty"
        );
        let d = founder_scoped_edge(&founder, &guild_k, ca, DECLARED_DUTY, late + hour);
        let out = land(d, ca.clone())
            .await
            .expect("I2030: the adult's declared duty");
        assert!(
            matches!(out, StatementOutcome::Row { .. }) && named_curate(ca).await,
            "({suffix}) I2030 control: the declared duty seats an assured adult: {out:?}"
        );
        let d = founder_scoped_edge(&founder, &community_k, cn, DECLARED_DUTY, late + hour);
        let _ = land(d.clone(), cn.clone()).await;
        assert!(
            !void_held(d).await,
            "({suffix}) I2030 control: `{DECLARED_DUTY}` is no duty where the record does \
             not declare it, so it is never judged minor_appointment_void"
        );
    }

    /// v62.0.0 (K2-fix11; Eric's ruling: **an appointment made to a minor is
    /// VOID**) — **I2863–I2869**, on every backend. One predicate,
    /// `age::duty_edge_void_for_minor`: a duty edge D onto T is void iff a
    /// minor-band age row about T is held and D does not post-date T's
    /// earliest ASSURED-adult row (`age_assurance:*`; a self-declared adult
    /// never counts). Held at the door with the GC1 fold reason
    /// `minor_appointment_void`; the duty walk never counts it.
    ///
    /// - **I2863** (witness 9) — a self-declared minor and an assured minor:
    ///   D, landing AFTER the minor row, is held `minor_appointment_void`;
    ///   `is_named_moderator` is false; the minor's marker is not admitted.
    /// - **I2864** (witness 9, the other arrival order) — D lands first and
    ///   SEATS (no age row yet); the minor row lands; the held row re-folds
    ///   (`why_held(D) == minor_appointment_void`), `is_named_moderator` is
    ///   false, and the marker is not admitted.
    /// - **I2865** (witness 9) — D, then an assured-adult proof: still void
    ///   (D predates every adult proof); a re-appointment D' after the proof
    ///   is not void but suspended while T's own minor declaration lowers the
    ///   band (K2-fix14); T withdraws it and D' counts, while D stays void.
    /// - **I2866** (witness 9) — a BACKDATED D (dated before the adult proof,
    ///   put after it) is void.
    /// - **I2867** (clarification (a)) — D after a self-declared ADULT row,
    ///   with an earlier self-declared minor row and no assurance: void.
    /// - **I2868** (K2-fix14 reverses clarification (b)) — an assured-adult
    ///   row before D and a self-declared minor row asserted AFTER D: D is
    ///   not void but SUSPENDED (not counted); once the subject withdraws the
    ///   row D counts again, with no re-appointment.
    /// - **I2869** (witness 9) — a pure guardianship (no duty scope) from an
    ///   assured-adult founder onto a minor still lands.
    ///
    /// Dates: every instant is the founder key's window start +
    /// `OWNER_BINDING_OFFSET_DAYS` (`late`) plus minutes / hours; the witness
    /// conferral is dated `late` (`confer_scope_from_trusted_root_at`).
    pub(crate) async fn exercise_minor_duty(engine: &crate::Engine, node_seed: &str, suffix: &str) {
        use crate::federation::admission::is_named_moderator;
        use crate::federation::age::{age_band, AgeBand};
        use crate::federation::edition2::emit::draft_from_envelope;
        use crate::federation::edition2::fold::{reason::gc1::MINOR_APPOINTMENT_VOID, why_held};
        use crate::federation::edition2::ingest::StatementOutcome;
        use crate::federation::edition2::names::RowId;
        let directory = engine.federation_directory();
        let dir: &dyn FederationDirectory = directory.as_ref();
        let k = |n: &str| format!("q12-{n}-{suffix}");
        let (founder, member, actor, community) =
            (k("founder"), k("member"), k("actor"), k("commons"));
        let people: Vec<String> = ["p1", "p2", "p3", "p4", "p5", "ward", "sm", "am"]
            .iter()
            .map(|n| k(n))
            .collect();
        for x in [&founder, &member, &actor, &community]
            .into_iter()
            .chain(people.iter())
        {
            register_user_key(dir, x).await;
        }
        let base = DateTime::<Utc>::from_timestamp_millis(
            i64::try_from(e2::key_window_start_ms(&founder)).expect("a window start fits i64"),
        )
        .expect("an instant");
        let late = base
            + chrono::Duration::days(
                crate::federation::tier_ingest::test_support::OWNER_BINDING_OFFSET_DAYS,
            );
        let min = chrono::Duration::minutes(1);
        let hour = chrono::Duration::hours(1);
        let witness = confer_age_witness(dir, node_seed, &k("age")).await;
        put_age_row(
            dir,
            &witness,
            &founder,
            "age_assurance:provider:adult:v1",
            late + min,
        )
        .await;
        assert_eq!(
            age_band(dir, &e2::kid(&founder)).await.expect("band"),
            AgeBand::Adult,
            "({suffix}) precondition: the founder is an assured adult"
        );
        found_commons(dir, &founder, &member, &community, base).await;
        let (actor_k, community_k) = (e2::kid(&actor), e2::kid(&community));
        let named = |who: &str| {
            let who = e2::kid(who);
            let community_k = community_k.clone();
            async move {
                is_named_moderator(dir, &who, &community_k, DELEGATION_SCOPE_SLASH)
                    .await
                    .expect("is_named_moderator")
            }
        };
        let land = |e: Attestation, by: String| async move {
            e2::land_with_voices(dir, &e, &[by.as_str()]).await
        };
        let void_held = |e: Attestation| async move {
            let why = why_held(dir, &RowId(e2::rid_digest(&e)))
                .await
                .expect("read the hold");
            why.is_some_and(|w| w.reason == MINOR_APPOINTMENT_VOID)
        };
        let marker_admitted = |seed: String, delegation_id: String, at: DateTime<Utc>| {
            let actor_k = actor_k.clone();
            let community_k = community_k.clone();
            async move {
                let draft = draft_from_envelope(
                    &e2::kid_digest(&seed),
                    &e2::kid(&seed),
                    &actor_k,
                    attestation_type::SCORES,
                    &withhold_envelope(&actor_k, &community_k, &delegation_id, "spam"),
                    e2::ms(at),
                    None,
                )
                .expect("the marker drafts");
                let sig = e2::signing_key(&seed)
                    .sign(&draft.sig_structure)
                    .expect("the key signs");
                matches!(
                    engine
                        .put_edition2_statement(&draft.assemble(sig), None)
                        .await,
                    Ok(StatementOutcome::Row { .. })
                )
            }
        };
        let edge = |grantee: &str, duty: bool, at: DateTime<Utc>| {
            founder_edge(&founder, &community_k, grantee, duty, at)
        };
        let (p1, p2, p3, p4, p5, ward, sm, am) = (
            &people[0], &people[1], &people[2], &people[3], &people[4], &people[5], &people[6],
            &people[7],
        );

        // ── I2863: the minor row first, then D.
        put_age_row(
            dir,
            sm,
            sm,
            "age_self_declared:band:minor:v1",
            late + min * 2,
        )
        .await;
        put_age_row(
            dir,
            &witness,
            am,
            "age_assurance:provider:minor:v1",
            late + min * 2,
        )
        .await;
        for (n, minor) in [(0i32, sm), (1, am)] {
            let d = edge(minor, true, late + hour * (1 + n));
            let out = land(d.clone(), minor.clone())
                .await
                .unwrap_or_else(|e| panic!("({suffix}) I2863: kept, not refused: {e}"));
            assert!(
                matches!(out, StatementOutcome::Pending { .. }) && void_held(d.clone()).await,
                "({suffix}) I2863: D onto the minor {minor} is held minor_appointment_void: {out:?}"
            );
            assert!(!named(minor).await, "({suffix}) I2863: no minor moderator");
            assert!(
                !marker_admitted(
                    minor.clone(),
                    d.attestation_id.clone(),
                    late + hour * (3 + n)
                )
                .await,
                "({suffix}) I2863: the minor's marker is not admitted"
            );
        }

        // ── I2864: D first (seats), then the minor row: void after re-fold.
        let d = edge(p1, true, late + hour * 5);
        let out = land(d.clone(), p1.clone()).await.expect("I2864: seated");
        assert!(
            matches!(out, StatementOutcome::Row { .. }),
            "({suffix}) I2864: {out:?}"
        );
        assert!(
            named(p1).await,
            "({suffix}) I2864: seated while no age row is held"
        );
        put_age_row(
            dir,
            p1,
            p1,
            "age_self_declared:band:minor:v1",
            late + hour * 6,
        )
        .await;
        assert!(
            void_held(d.clone()).await,
            "({suffix}) I2864: the seated appointment re-folds to minor_appointment_void"
        );
        assert!(!named(p1).await, "({suffix}) I2864: unseated");
        assert!(
            !marker_admitted(p1.clone(), d.attestation_id.clone(), late + hour * 7).await,
            "({suffix}) I2864: the unseated minor's marker is not admitted"
        );

        // ── I2865: D, then an assured-adult proof: still void; D' after it
        // seats once p2's own minor declaration no longer lowers the band.
        let p2_minor = put_age_row(
            dir,
            p2,
            p2,
            "age_self_declared:band:minor:v1",
            late + min * 2,
        )
        .await;
        let d = edge(p2, true, late + hour * 8);
        let _ = land(d.clone(), p2.clone()).await;
        put_age_row(
            dir,
            &witness,
            p2,
            "age_assurance:provider:adult:v1",
            late + hour * 9,
        )
        .await;
        assert!(
            void_held(d.clone()).await && !named(p2).await,
            "({suffix}) I2865: an appointment made during minority stays void after the \
             adult proof"
        );
        let d2 = edge(p2, true, late + hour * 10);
        let out = land(d2.clone(), p2.clone())
            .await
            .expect("I2865: re-appointed");
        assert!(
            matches!(out, StatementOutcome::Row { .. }) && !void_held(d2.clone()).await,
            "({suffix}) I2865: the re-appointment after the adult proof is not void: {out:?}"
        );
        // K2-fix14 (CC 3.4.11: a self-declared minor band lowers the reading)
        // — p2's own minor declaration still stands, so D' is SUSPENDED.
        assert!(
            !named(p2).await,
            "({suffix}) I2865: D' is suspended while p2's own minor declaration stands"
        );
        withdraw_age_row(dir, &p2_minor, p2).await;
        assert!(
            named(p2).await && !void_held(d2).await,
            "({suffix}) I2865: p2 withdraws it: D' counts, with no re-appointment"
        );
        assert!(
            void_held(d.clone()).await,
            "({suffix}) I2865: the void D is never revived, not even by the withdrawal"
        );

        // ── I2866: a backdated D is void.
        put_age_row(
            dir,
            p3,
            p3,
            "age_self_declared:band:minor:v1",
            late + min * 2,
        )
        .await;
        put_age_row(
            dir,
            &witness,
            p3,
            "age_assurance:provider:adult:v1",
            late + hour * 11,
        )
        .await;
        let d = edge(p3, true, late + hour * 10);
        let _ = land(d.clone(), p3.clone()).await;
        assert!(
            void_held(d).await && !named(p3).await,
            "({suffix}) I2866: dated before the adult proof, put after it: void"
        );

        // ── I2867: a self-declared ADULT never counts.
        put_age_row(
            dir,
            p4,
            p4,
            "age_self_declared:band:minor:v1",
            late + min * 2,
        )
        .await;
        put_age_row(
            dir,
            p4,
            p4,
            "age_self_declared:band:adult:v1",
            late + hour * 12,
        )
        .await;
        let d = edge(p4, true, late + hour * 13);
        let _ = land(d.clone(), p4.clone()).await;
        assert!(
            void_held(d).await && !named(p4).await,
            "({suffix}) I2867: after a self-declared adult row, with no assurance: void"
        );

        // ── I2868: an assured adult before D, a later minor row: D stays seated.
        put_age_row(
            dir,
            &witness,
            p5,
            "age_assurance:provider:adult:v1",
            late + min * 2,
        )
        .await;
        let d = edge(p5, true, late + hour * 14);
        let out = land(d.clone(), p5.clone()).await.expect("I2868: seated");
        assert!(
            matches!(out, StatementOutcome::Row { .. }),
            "({suffix}) I2868: {out:?}"
        );
        let p5_minor = put_age_row(
            dir,
            p5,
            p5,
            "age_self_declared:band:minor:v1",
            late + hour * 15,
        )
        .await;
        // K2-fix14 (reverses K2-fix11's I2868; CC 3.4.11 + CC 4.5.4 as ruled
        // for rc22): not void, but SUSPENDED while the band resolves minor.
        assert!(
            !void_held(d.clone()).await && !named(p5).await,
            "({suffix}) I2868: a later minor row suspends D (not void, not counted)"
        );
        withdraw_age_row(dir, &p5_minor, p5).await;
        assert!(
            !void_held(d).await && named(p5).await,
            "({suffix}) I2868: withdrawn, D counts again with no re-appointment"
        );

        // ── I2869: a pure guardianship onto a minor still lands.
        put_age_row(
            dir,
            ward,
            ward,
            "age_self_declared:band:minor:v1",
            late + min * 2,
        )
        .await;
        let g = edge(ward, false, late + hour * 16);
        let out = land(g, ward.clone())
            .await
            .expect("I2869: the guardianship");
        assert!(
            matches!(out, StatementOutcome::Row { .. }),
            "({suffix}) I2869: guardianship without a duty scope is unchanged: {out:?}"
        );
    }

    /// v62.0.0 (K2-fix14; CC 3.2 rc21, CC 3.4.11, CC 4.5.4 as ruled for rc22)
    /// — **I2032–I2037: VOID and SUSPENDED are two states, and neither reads
    /// the wall clock.** On every backend. Every instant is `late` (the
    /// founder key's window start + `OWNER_BINDING_OFFSET_DAYS`, about 30
    /// days before the run) plus minutes / hours, so every `expires_at` below
    /// is PAST when the witness reads: the reader's clock disagrees with the
    /// instant each rule must use.
    ///
    /// - **I2032** (clock, void side) — an assured minor that lapsed before
    ///   an assured-adult proof; the proof is dated before D and lapses AFTER
    ///   D (and before the run). D is not void and counts; read today, after
    ///   the proof lapsed, it STILL counts. Before K2-fix14 the void predicate
    ///   read `expires_at > now` and voided D here.
    /// - **I2033** (clock, void side) — a self-declared minor; an
    ///   assured-adult proof that lapsed BEFORE D's `asserted_at`: it lifts
    ///   nothing; D is held `minor_appointment_void`.
    /// - **I2034** (suspension by the subject's own row) — an assured adult,
    ///   D (counted), a later SELF-declared minor: the band lowers to minor
    ///   (CC 3.4.11), D is SUSPENDED (no hold, not counted); the subject
    ///   withdraws it and D counts again, with no re-appointment.
    /// - **I2035** (suspension by a witness row; lifted by a newer one) — one
    ///   witness: a provider adult, D (counted), its later provider minor
    ///   (K2-fix15: its newer row stands), so D is suspended (and absent from
    ///   `moderators_of`); its later government adult stands and D counts
    ///   again, with no re-appointment. (The two-witness tie is I2042.)
    /// - **I2036** (no record) — T has no age row at all: D counts and the
    ///   band is `unknown`, never the CC 3.4.11 `under_13` default.
    /// - **I2039** (the steward-binding gate) — a guardianship from a granter
    ///   whose adult proof lapsed after the binding lands: the gate reads the
    ///   held rows, not the clock.
    /// - **I2040–I2043** (K2-fix15, `AGE_OWN_SERIES_NEWEST_WINS`) — one
    ///   signer's newest row stands: the subject's newer self-declaration
    ///   lifts its older minor one (I2040); a witness's newer adult lifts its
    ///   own earlier minor (I2041); two DIFFERENT witnesses at an equal level
    ///   still tie to minor, so D is suspended (I2042); a void D stays void
    ///   after the subject's newer declaration (I2043).
    /// - **I2044** (permanent supersession) — a witness's newest row EXPIRED
    ///   leaves that witness no current row: neither its superseded adult nor
    ///   its superseded minor returns.
    /// - **I2045** (retraction) — the witness withdraws its newest row: the
    ///   previous one stands.
    /// - **I2037** (void is never revived) — a self-declared minor, D (void),
    ///   an assured adult, then the subject withdraws the minor row: the band
    ///   is adult now, but D stays void and is not counted.
    pub(crate) async fn exercise_minor_void_instants(
        engine: &crate::Engine,
        node_seed: &str,
        suffix: &str,
    ) {
        use crate::federation::admission::{is_named_moderator, moderators_of};
        use crate::federation::age::{age_band, age_band_as_of, AgeBand};
        use crate::federation::edition2::fold::{reason::gc1::MINOR_APPOINTMENT_VOID, why_held};
        use crate::federation::edition2::ingest::StatementOutcome;
        use crate::federation::edition2::names::RowId;
        let directory = engine.federation_directory();
        let dir: &dyn FederationDirectory = directory.as_ref();
        let k = |n: &str| format!("q14-{n}-{suffix}");
        let (founder, member, community) = (k("founder"), k("member"), k("commons"));
        let people: Vec<String> = [
            "t1", "t2", "t3", "t4", "t5", "t6", "g7", "w7", "u1", "u2", "u3", "u4", "v1", "v2",
            "v3",
        ]
        .iter()
        .map(|n| k(n))
        .collect();
        for x in [&founder, &member, &community]
            .into_iter()
            .chain(people.iter())
        {
            register_user_key(dir, x).await;
        }
        let base = DateTime::<Utc>::from_timestamp_millis(
            i64::try_from(e2::key_window_start_ms(&founder)).expect("a window start fits i64"),
        )
        .expect("an instant");
        let late = base
            + chrono::Duration::days(
                crate::federation::tier_ingest::test_support::OWNER_BINDING_OFFSET_DAYS,
            );
        let min = chrono::Duration::minutes(1);
        let hour = chrono::Duration::hours(1);
        assert!(
            late + hour * 24 < crate::host::clock::now(),
            "({suffix}) precondition: every instant of this witness is before the run"
        );
        // K2-fix15: two witnesses under one root (I2042 needs a second).
        let (tag1, tag2) = (k("age"), k("age2"));
        let ws = confer_age_witnesses(dir, node_seed, &[tag1.as_str(), tag2.as_str()]).await;
        let (witness, witness2) = (ws[0].clone(), ws[1].clone());
        put_age_row(
            dir,
            &witness,
            &founder,
            "age_assurance:provider:adult:v1",
            late + min,
        )
        .await;
        assert_eq!(
            age_band(dir, &e2::kid(&founder)).await.expect("band"),
            AgeBand::Adult,
            "({suffix}) precondition: the founder is an assured adult"
        );
        found_commons(dir, &founder, &member, &community, base).await;
        let community_k = e2::kid(&community);
        let named = |who: &str| {
            let who = e2::kid(who);
            let community_k = community_k.clone();
            async move {
                is_named_moderator(dir, &who, &community_k, DELEGATION_SCOPE_SLASH)
                    .await
                    .expect("is_named_moderator")
            }
        };
        let listed = |who: &str| {
            let who = e2::kid(who);
            let community_k = community_k.clone();
            async move {
                moderators_of(dir, &community_k, DELEGATION_SCOPE_SLASH)
                    .await
                    .expect("moderators_of")
                    .contains(&who)
            }
        };
        let band_timeless = |who: &str| {
            let who = e2::kid(who);
            async move {
                age_band_as_of(dir, &who, None)
                    .await
                    .expect("age_band_as_of")
            }
        };
        let land = |e: Attestation, by: String| async move {
            e2::land_with_voices(dir, &e, &[by.as_str()]).await
        };
        let held_why = |e: Attestation| async move {
            why_held(dir, &RowId(e2::rid_digest(&e)))
                .await
                .expect("read the hold")
                .map(|w| w.reason)
        };
        let edge = |grantee: &str, at: DateTime<Utc>| {
            founder_scoped_edge(&founder, &community_k, grantee, DELEGATION_SCOPE_SLASH, at)
        };
        let (t1, t2, t3, t4, t5, t6, g7, w7) = (
            &people[0], &people[1], &people[2], &people[3], &people[4], &people[5], &people[6],
            &people[7],
        );
        let (u1, u2, u3, u4) = (&people[8], &people[9], &people[10], &people[11]);
        let (v1, v2, v3) = (&people[12], &people[13], &people[14]);

        // ── I2032: the proof lapses AFTER D; read today, D still counts.
        put_age_row_until(
            dir,
            &witness,
            t1,
            "age_assurance:provider:minor:v1",
            late + min * 2,
            Some(late + min * 30),
        )
        .await;
        put_age_row_until(
            dir,
            &witness,
            t1,
            "age_assurance:provider:adult:v1",
            late + hour,
            Some(late + hour * 3),
        )
        .await;
        assert_eq!(
            age_band(dir, &e2::kid(t1)).await.expect("band"),
            AgeBand::Unknown,
            "({suffix}) I2032 precondition: by the reader's clock both rows lapsed"
        );
        assert_eq!(
            age_band_as_of(dir, &e2::kid(t1), Some(late + hour * 2))
                .await
                .expect("band at D"),
            AgeBand::Adult,
            "({suffix}) I2032 precondition: at D the minor row had lapsed and the proof was live"
        );
        let d = edge(t1, late + hour * 2);
        let out = land(d.clone(), t1.clone())
            .await
            .unwrap_or_else(|e| panic!("({suffix}) I2032: kept, not refused: {e}"));
        assert!(
            matches!(out, StatementOutcome::Row { .. }),
            "({suffix}) I2032: D, made while the proof was live, lands: {out:?}"
        );
        assert_eq!(
            held_why(d).await,
            None,
            "({suffix}) I2032: no hold, though the proof lapsed before this read"
        );
        assert_eq!(
            band_timeless(t1).await,
            AgeBand::Adult,
            "({suffix}) I2032: as of the newest held evidence the proof is live"
        );
        assert!(
            named(t1).await,
            "({suffix}) I2032: still counted after the proof's lapse: the reader's clock does \
             not unseat"
        );

        // ── I2033: the proof had lapsed at D: it lifts nothing.
        put_age_row(
            dir,
            t2,
            t2,
            "age_self_declared:band:minor:v1",
            late + min * 2,
        )
        .await;
        put_age_row_until(
            dir,
            &witness,
            t2,
            "age_assurance:provider:adult:v1",
            late + hour * 4,
            Some(late + hour * 5),
        )
        .await;
        let d = edge(t2, late + hour * 6);
        let out = land(d.clone(), t2.clone())
            .await
            .unwrap_or_else(|e| panic!("({suffix}) I2033: kept, not refused: {e}"));
        assert!(
            matches!(out, StatementOutcome::Pending { .. }),
            "({suffix}) I2033: held: {out:?}"
        );
        assert_eq!(
            held_why(d).await.as_deref(),
            Some(MINOR_APPOINTMENT_VOID),
            "({suffix}) I2033: a proof expired at D's asserted_at lifts nothing"
        );
        assert!(!named(t2).await, "({suffix}) I2033: no minor moderator");

        // ── I2034: counted → SUSPENDED (own declaration) → counted (withdrawn).
        put_age_row(
            dir,
            &witness,
            t3,
            "age_assurance:provider:adult:v1",
            late + min * 2,
        )
        .await;
        let d = edge(t3, late + hour * 7);
        let out = land(d.clone(), t3.clone())
            .await
            .unwrap_or_else(|e| panic!("({suffix}) I2034: kept, not refused: {e}"));
        assert!(
            matches!(out, StatementOutcome::Row { .. }) && named(t3).await,
            "({suffix}) I2034: counted before the minor row: {out:?}"
        );
        let t3_minor = put_age_row(
            dir,
            t3,
            t3,
            "age_self_declared:band:minor:v1",
            late + hour * 8,
        )
        .await;
        assert_eq!(
            band_timeless(t3).await,
            AgeBand::Minor,
            "({suffix}) I2034: a self-declared minor band lowers the reading (CC 3.4.11)"
        );
        assert_eq!(
            held_why(d.clone()).await,
            None,
            "({suffix}) I2034: suspended is not void: no hold"
        );
        assert!(
            !named(t3).await && !listed(t3).await,
            "({suffix}) I2034: SUSPENDED: not counted while the band resolves minor"
        );
        withdraw_age_row(dir, &t3_minor, t3).await;
        assert_eq!(
            band_timeless(t3).await,
            AgeBand::Adult,
            "({suffix}) I2034: withdrawn, the witness reading stands"
        );
        assert!(
            held_why(d).await.is_none() && named(t3).await && listed(t3).await,
            "({suffix}) I2034: counted again, the same D, no re-appointment"
        );

        // ── I2035: counted → SUSPENDED (the witness's newer minor) → counted
        // (its newer government adult).
        put_age_row(
            dir,
            &witness,
            t4,
            "age_assurance:provider:adult:v1",
            late + min * 2,
        )
        .await;
        let d = edge(t4, late + hour * 9);
        let out = land(d.clone(), t4.clone())
            .await
            .unwrap_or_else(|e| panic!("({suffix}) I2035: kept, not refused: {e}"));
        assert!(
            matches!(out, StatementOutcome::Row { .. }) && named(t4).await,
            "({suffix}) I2035: counted before the minor row: {out:?}"
        );
        put_age_row(
            dir,
            &witness,
            t4,
            "age_assurance:provider:minor:v1",
            late + hour * 10,
        )
        .await;
        assert_eq!(
            band_timeless(t4).await,
            AgeBand::Minor,
            "({suffix}) I2035: the witness's newer minor row replaces its own adult one"
        );
        assert_ne!(
            held_why(d.clone()).await.as_deref(),
            Some(MINOR_APPOINTMENT_VOID),
            "({suffix}) I2035: D post-dates a live adult proof: not void"
        );
        assert!(
            !named(t4).await && !listed(t4).await,
            "({suffix}) I2035: SUSPENDED: CC 4.5.4, no K is a user with the minor band"
        );
        put_age_row(
            dir,
            &witness,
            t4,
            "age_assurance:government:adult:v1",
            late + hour * 11,
        )
        .await;
        assert_eq!(
            band_timeless(t4).await,
            AgeBand::Adult,
            "({suffix}) I2035: the witness's newer government adult stands"
        );
        assert!(
            named(t4).await && listed(t4).await,
            "({suffix}) I2035: counted again, the same D, no re-appointment"
        );
        assert_ne!(
            held_why(d).await.as_deref(),
            Some(MINOR_APPOINTMENT_VOID),
            "({suffix}) I2035: never void"
        );

        // ── I2036: no age row at all: counted; the band is unknown.
        let d = edge(t5, late + hour * 12);
        let out = land(d.clone(), t5.clone())
            .await
            .unwrap_or_else(|e| panic!("({suffix}) I2036: kept, not refused: {e}"));
        assert!(
            matches!(out, StatementOutcome::Row { .. }),
            "({suffix}) I2036: {out:?}"
        );
        assert_eq!(
            band_timeless(t5).await,
            AgeBand::Unknown,
            "({suffix}) I2036: absence resolves no band here, not under_13"
        );
        assert!(
            held_why(d).await.is_none() && named(t5).await && listed(t5).await,
            "({suffix}) I2036: a person with no age row stays appointable and counted"
        );

        // ── I2037: VOID is never revived, not by a proof, not by a withdrawal.
        let t6_minor = put_age_row(
            dir,
            t6,
            t6,
            "age_self_declared:band:minor:v1",
            late + min * 2,
        )
        .await;
        let d = edge(t6, late + hour * 13);
        let _ = land(d.clone(), t6.clone()).await;
        put_age_row(
            dir,
            &witness,
            t6,
            "age_assurance:provider:adult:v1",
            late + hour * 14,
        )
        .await;
        withdraw_age_row(dir, &t6_minor, t6).await;
        assert_eq!(
            band_timeless(t6).await,
            AgeBand::Adult,
            "({suffix}) I2037 precondition: the band is adult now"
        );
        assert_eq!(
            held_why(d).await.as_deref(),
            Some(MINOR_APPOINTMENT_VOID),
            "({suffix}) I2037: D stays void (a retracted minor row still counts for void)"
        );
        assert!(
            !named(t6).await,
            "({suffix}) I2037: a void appointment is never revived"
        );

        // ── I2039: the steward-binding GATE reads no clock. A guardianship
        // (no duty) from g7, whose adult proof lapsed after the binding and
        // before this run, onto a self-declared minor: the gate judges the
        // granter's band from the held rows (as of the newest held evidence),
        // so it lands; before K2-fix14 the gate's `age_band` read the clock,
        // found no live proof and held it `granter_not_adult_user`.
        put_age_row_until(
            dir,
            &witness,
            g7,
            "age_assurance:provider:adult:v1",
            late + hour * 15,
            Some(late + hour * 18),
        )
        .await;
        put_age_row(
            dir,
            w7,
            w7,
            "age_self_declared:band:minor:v1",
            late + hour * 15,
        )
        .await;
        assert_eq!(
            age_band(dir, &e2::kid(g7)).await.expect("band"),
            AgeBand::Unknown,
            "({suffix}) I2039 precondition: by the reader's clock g7's proof lapsed"
        );
        let g = founder_edge(g7, &community_k, w7, false, late + hour * 16);
        let out = land(g.clone(), w7.clone())
            .await
            .unwrap_or_else(|e| panic!("({suffix}) I2039: kept, not refused: {e}"));
        assert!(
            matches!(out, StatementOutcome::Row { .. }) && held_why(g).await.is_none(),
            "({suffix}) I2039: the gate's outcome does not depend on when it runs: {out:?}"
        );

        // ── K2-fix15 (AGE_OWN_SERIES_NEWEST_WINS; CC 3.4.11 / 3.5.1): within
        // ONE signer's series the newest row stands.
        // I2040: a self-minor "at 15", then the SAME subject's later
        // self-declaration plus a provider adult: adult, no withdrawal.
        put_age_row(
            dir,
            u1,
            u1,
            "age_self_declared:band:minor:v1",
            late + hour * 20,
        )
        .await;
        put_age_row(
            dir,
            u1,
            u1,
            "age_self_declared:band:adult:v1",
            late + hour * 21,
        )
        .await;
        put_age_row(
            dir,
            &witness,
            u1,
            "age_assurance:provider:adult:v1",
            late + hour * 21,
        )
        .await;
        assert_eq!(
            band_timeless(u1).await,
            AgeBand::Adult,
            "({suffix}) I2040: the subject's newer declaration replaces its older minor one"
        );
        let d = edge(u1, late + hour * 22);
        let out = land(d.clone(), u1.clone())
            .await
            .unwrap_or_else(|e| panic!("({suffix}) I2040: kept, not refused: {e}"));
        assert!(
            matches!(out, StatementOutcome::Row { .. })
                && held_why(d).await.is_none()
                && named(u1).await,
            "({suffix}) I2040: counted, with no withdrawal: {out:?}"
        );

        // I2041: the SAME witness's minor, then its later adult: adult.
        put_age_row(
            dir,
            &witness,
            u2,
            "age_assurance:provider:minor:v1",
            late + hour * 20,
        )
        .await;
        put_age_row(
            dir,
            &witness,
            u2,
            "age_assurance:provider:adult:v1",
            late + hour * 21,
        )
        .await;
        assert_eq!(
            band_timeless(u2).await,
            AgeBand::Adult,
            "({suffix}) I2041: a witness's newer assurance replaces its own earlier one"
        );
        let d = edge(u2, late + hour * 22);
        let out = land(d.clone(), u2.clone())
            .await
            .unwrap_or_else(|e| panic!("({suffix}) I2041: kept, not refused: {e}"));
        assert!(
            matches!(out, StatementOutcome::Row { .. })
                && held_why(d).await.is_none()
                && named(u2).await,
            "({suffix}) I2041: counted: {out:?}"
        );

        // I2042: witness A's minor, then witness B's adult, equal level:
        // still minor (two signers: tie to minor). D is not void (an adult
        // proof precedes it) but SUSPENDED.
        put_age_row(
            dir,
            &witness,
            u3,
            "age_assurance:provider:minor:v1",
            late + hour * 20,
        )
        .await;
        put_age_row(
            dir,
            &witness2,
            u3,
            "age_assurance:provider:adult:v1",
            late + hour * 21,
        )
        .await;
        assert_eq!(
            band_timeless(u3).await,
            AgeBand::Minor,
            "({suffix}) I2042: two witnesses at an equal level disagree: minor"
        );
        let d = edge(u3, late + hour * 22);
        let out = land(d.clone(), u3.clone())
            .await
            .unwrap_or_else(|e| panic!("({suffix}) I2042: kept, not refused: {e}"));
        assert!(
            matches!(out, StatementOutcome::Row { .. }) && held_why(d).await.is_none(),
            "({suffix}) I2042: not void: {out:?}"
        );
        assert!(
            !named(u3).await && !listed(u3).await,
            "({suffix}) I2042: SUSPENDED: not counted"
        );

        // I2043: a void D stays void after the subject's newer declaration.
        put_age_row(
            dir,
            u4,
            u4,
            "age_self_declared:band:minor:v1",
            late + hour * 20,
        )
        .await;
        let d = edge(u4, late + hour * 21);
        let _ = land(d.clone(), u4.clone()).await;
        put_age_row(
            dir,
            u4,
            u4,
            "age_self_declared:band:adult:v1",
            late + hour * 22,
        )
        .await;
        put_age_row(
            dir,
            &witness,
            u4,
            "age_assurance:provider:adult:v1",
            late + hour * 23,
        )
        .await;
        assert_eq!(
            band_timeless(u4).await,
            AgeBand::Adult,
            "({suffix}) I2043 precondition: the current band is adult"
        );
        assert_eq!(
            held_why(d).await.as_deref(),
            Some(MINOR_APPOINTMENT_VOID),
            "({suffix}) I2043: the void rule reads the history, not the current row"
        );
        assert!(!named(u4).await, "({suffix}) I2043: never revived");

        // ── I2044: supersession is permanent. One witness's newest row is
        // its current row; once that row EXPIRES the witness has NO current
        // row, and the older row it superseded never comes back.
        // v1: the witness's adult, then its newer minor (lapsing by +3h).
        put_age_row(
            dir,
            &witness,
            v1,
            "age_assurance:provider:adult:v1",
            late + hour * 30,
        )
        .await;
        put_age_row_until(
            dir,
            &witness,
            v1,
            "age_assurance:provider:minor:v1",
            late + hour * 31,
            Some(late + hour * 32),
        )
        .await;
        let v1k = e2::kid(v1);
        assert_eq!(
            age_band_as_of(dir, &v1k, Some(late + hour * 31 + min))
                .await
                .expect("band"),
            AgeBand::Minor,
            "({suffix}) I2044: while live, the newer minor is the witness's current row"
        );
        assert_eq!(
            age_band_as_of(dir, &v1k, Some(late + hour * 33))
                .await
                .expect("band"),
            AgeBand::Unknown,
            "({suffix}) I2044: expired, it leaves no current row: the adult does not return"
        );
        assert_eq!(
            age_band(dir, &v1k).await.expect("band"),
            AgeBand::Unknown,
            "({suffix}) I2044: the present-tense read agrees"
        );
        // v2: the witness's minor, then its newer adult proof (lapsing).
        put_age_row(
            dir,
            &witness,
            v2,
            "age_assurance:provider:minor:v1",
            late + hour * 30,
        )
        .await;
        put_age_row_until(
            dir,
            &witness,
            v2,
            "age_assurance:provider:adult:v1",
            late + hour * 31,
            Some(late + hour * 32),
        )
        .await;
        assert_eq!(
            age_band_as_of(dir, &e2::kid(v2), Some(late + hour * 33))
                .await
                .expect("band"),
            AgeBand::Unknown,
            "({suffix}) I2044: an expired adult proof does not re-minor the person"
        );

        // ── I2045: a RETRACTED newest row is un-said: the previous stands.
        put_age_row(
            dir,
            &witness,
            v3,
            "age_assurance:provider:adult:v1",
            late + hour * 30,
        )
        .await;
        let v3_minor = put_age_row(
            dir,
            &witness,
            v3,
            "age_assurance:provider:minor:v1",
            late + hour * 31,
        )
        .await;
        assert_eq!(
            band_timeless(v3).await,
            AgeBand::Minor,
            "({suffix}) I2045 precondition: the newer minor is current"
        );
        withdraw_age_row(dir, &v3_minor, &witness).await;
        assert_eq!(
            band_timeless(v3).await,
            AgeBand::Adult,
            "({suffix}) I2045: the witness withdraws it: its previous adult row stands"
        );
        assert_eq!(
            age_band(dir, &e2::kid(v3)).await.expect("band"),
            AgeBand::Adult,
            "({suffix}) I2045: the present-tense read agrees"
        );
    }

    /// v62.0.0 (K2-fix11) — **I2860–I2862: a PERSON as a named moderator.**
    /// CC 4.5.4 (part_4 l.1762): `is_named_moderator(K, C, duty)` is a live
    /// `delegates_to` chain `root →* K` with `scope ⊇ {duty}`, `community_id ==
    /// C`, the root in C's authority set: K is any key, a person's included.
    /// The user-target rule (part_3 l.1072) governs only a CUSTODY claim
    /// (`delegation_purpose == owner_binding` / `legitimacy_source`,
    /// `admission::is_custody_claim_envelope`); an ordinary `delegates_to`
    /// onto a person who can accept for itself passes it
    /// (`check_user_target_steward_binding_admission`). The one other
    /// condition on such an edge is CC 2.6.1.9's: it seats with the
    /// delegate's own statement (the `delegate` role, K2-fix6); a person sub
    /// names no `delegate_owner`.
    ///
    /// - **I2860** — the founder's `delegates_to(slash, community_id: C)`
    ///   onto a person with NO age record, voiced by the person: `Row`, and
    ///   `is_named_moderator(person, C, slash)` is true.
    /// - **I2861** — that person's externally signed marker (the two-step
    ///   flow): `Row`, and `resolve_quarantine` reads `Withheld`, governed by
    ///   the person's marker.
    /// - **I2862** — the same delegation carrying `delegation_purpose:
    ///   owner_binding` (a CUSTODY claim) onto a person: it does not land
    ///   (the user-target custody leg: an unproven-age target is held
    ///   `steward_unproven`), and that person is NOT a named moderator. The
    ///   adult arm, on every backend: onto an ASSURED adult (the witness
    ///   fixture I2865/I2868 use), the edge is `Pending`, held
    ///   `steward_unproven` with detail `target_is_self_sovereign`, and the
    ///   adult is NOT a named moderator.
    ///
    /// Dates: the founder key's window start plus
    /// `OWNER_BINDING_OFFSET_DAYS`, so the edges' 180-day test terms cover
    /// today.
    pub(crate) async fn exercise_person_moderator(
        engine: &crate::Engine,
        node_seed: &str,
        suffix: &str,
    ) {
        use crate::federation::admission::is_named_moderator;
        use crate::federation::edition2::emit::draft_from_envelope;
        use crate::federation::edition2::ingest::StatementOutcome;
        use crate::federation::edition2::names::RowId;
        let directory = engine.federation_directory();
        let dir: &dyn FederationDirectory = directory.as_ref();
        let founder = format!("q11-founder-{suffix}");
        let member = format!("q11-member-{suffix}");
        let person = format!("q11-person-{suffix}");
        let custodied = format!("q11-custodied-{suffix}");
        let actor = format!("q11-actor-{suffix}");
        let community = format!("q11-commons-{suffix}");
        for k in [&founder, &member, &person, &custodied, &actor, &community] {
            register_user_key(dir, k).await;
        }
        let base_ms = e2::key_window_start_ms(&founder);
        let base = DateTime::<Utc>::from_timestamp_millis(
            i64::try_from(base_ms).expect("a window start fits i64"),
        )
        .expect("an instant");
        let offset_days = crate::federation::tier_ingest::test_support::OWNER_BINDING_OFFSET_DAYS;
        let late = base + chrono::Duration::days(offset_days);
        let late_ms = e2::ms(late);
        let hour_ms: u64 = 3_600_000;
        let (actor_k, community_k) = (e2::kid(&actor), e2::kid(&community));
        let community_row = crate::federation::tier_ingest::test_support::sign_community(
            &founder,
            crate::federation::types::Community {
                prev_head_digest: String::new(),
                charter_digest: String::new(),
                community_key_id: community.clone(),
                community_name: format!("commons {community}"),
                members: vec![
                    crate::federation::types::CommunityMember {
                        key_id: founder.clone(),
                        joined_at: base,
                        role: Some("founder".to_owned()),
                    },
                    crate::federation::types::CommunityMember {
                        key_id: member.clone(),
                        joined_at: base,
                        role: Some("member".to_owned()),
                    },
                ],
                founded_at: base,
                consensus_protocol: "majority".to_owned(),
                policy_blob: None,
                persist_row_hash: String::new(),
            },
        );
        e2::put_voices(
            dir,
            &e2::community_voices(&community_row, 1, None, e2::ms(base)),
        )
        .await
        .expect("I2860: the community roster lands");

        // The founder's duty edge onto `grantee`, naming C; `custody` adds
        // the owner-binding purpose (a custody claim).
        let edge = |grantee: &str, custody: bool, at: DateTime<Utc>| {
            // K2-fix13: no `dimension` (`dimension_unregistered`).
            let mut envelope = serde_json::json!({
                "scope": [DELEGATION_SCOPE_SLASH],
                "community_id": community_k,
            });
            if custody {
                envelope["delegation_purpose"] = serde_json::json!(
                    crate::federation::types::owner_binding::CC_DELEGATION_PURPOSE
                );
            }
            crate::federation::admission::with_test_term(&mut envelope, at);
            let a = unsigned_row(
                &founder,
                &e2::kid(grantee),
                attestation_type::DELEGATES_TO,
                envelope,
                at,
            );
            e2::row_of_statement(
                &e2::statement_of_family(&a, &founder, "self:delegates_to"),
                attestation_tier::FEDERATION,
            )
        };

        // ── I2860: seated, and a named moderator.
        let seat = edge(&person, false, late + chrono::Duration::hours(1));
        let out = e2::land_with_voices(dir, &seat, &[person.as_str()])
            .await
            .expect("I2860: the edge onto a person is admitted");
        assert!(
            matches!(out, StatementOutcome::Row { .. }),
            "({suffix}) I2860: the founder's delegates_to(slash) onto a person (no age \
             record) seats with the person's voice: {out:?}"
        );
        assert!(
            is_named_moderator(dir, &e2::kid(&person), &community_k, DELEGATION_SCOPE_SLASH)
                .await
                .expect("I2860"),
            "({suffix}) I2860: the person is a named moderator of C for slash (CC 4.5.4)"
        );

        // ── I2861: the person's externally signed marker.
        let draft = draft_from_envelope(
            &e2::kid_digest(&person),
            &e2::kid(&person),
            &actor_k,
            attestation_type::SCORES,
            &withhold_envelope(&actor_k, &community_k, &seat.attestation_id, "spam"),
            late_ms + 2 * hour_ms,
            None,
        )
        .expect("I2861: the marker drafts");
        let sig = e2::signing_key(&person)
            .sign(&draft.sig_structure)
            .expect("I2861: the person's own key signs");
        let stmt = draft.assemble(sig);
        let marker_rid = RowId::of_statement(&stmt).expect("a row statement");
        let out = engine
            .put_edition2_statement(&stmt, None)
            .await
            .expect("I2861: admitted");
        assert!(
            matches!(out, StatementOutcome::Row { .. }),
            "({suffix}) I2861: a named-moderator person's marker lands: {out:?}"
        );
        let fold = resolve_quarantine(dir, &actor_k, Utc::now())
            .await
            .expect("resolve");
        assert_eq!(
            (fold.state, fold.marker_id.as_deref()),
            (QuarantineState::Withheld, Some(marker_rid.hex().as_str())),
            "({suffix}) I2861: Withheld, governed by the person's marker"
        );

        // ── I2862: the custody-claim form does not seat a moderator.
        let custody = edge(&custodied, true, late + chrono::Duration::hours(3));
        if let Ok(StatementOutcome::Row { .. }) =
            e2::land_with_voices(dir, &custody, &[custodied.as_str()]).await
        {
            panic!(
                "({suffix}) I2862: an owner-binding-purpose delegates_to onto a person must not \
             land"
            )
        }
        assert!(
            !is_named_moderator(
                dir,
                &e2::kid(&custodied),
                &community_k,
                DELEGATION_SCOPE_SLASH
            )
            .await
            .expect("I2862"),
            "({suffix}) I2862: a custody claim is not a moderator appointment"
        );
        // ── I2862 (proven adult): the same custody-claim edge onto an ASSURED
        // adult (the CC 3.4.12 adult-incapacity aperture is the only custody
        // of an adult; none is attested here, so `target_is_self_sovereign`).
        let adult = format!("q11-adult-{suffix}");
        register_user_key(dir, &adult).await;
        let witness = confer_age_witness(dir, node_seed, &format!("q11-age-{suffix}")).await;
        put_age_row(
            dir,
            &witness,
            &adult,
            "age_assurance:provider:adult:v1",
            late + chrono::Duration::minutes(1),
        )
        .await;
        assert_eq!(
            crate::federation::age::age_band(dir, &e2::kid(&adult))
                .await
                .expect("band"),
            crate::federation::age::AgeBand::Adult,
            "({suffix}) I2862: precondition, an assured adult"
        );
        let custody = edge(&adult, true, late + chrono::Duration::hours(4));
        let out = e2::land_with_voices(dir, &custody, &[adult.as_str()])
            .await
            .unwrap_or_else(|e| panic!("({suffix}) I2862: held, not refused: {e}"));
        assert!(
            matches!(out, StatementOutcome::Pending { .. }),
            "({suffix}) I2862: an owner-binding-purpose delegates_to onto a proven adult must \
             not land: {out:?}"
        );
        let held = crate::federation::edition2::fold::why_held(
            dir,
            &crate::federation::edition2::names::RowId(e2::rid_digest(&custody)),
        )
        .await
        .expect("read the hold")
        .unwrap_or_else(|| panic!("({suffix}) I2862: the adult custody claim is held"));
        assert!(
            held.reason == crate::federation::edition2::fold::reason::STEWARD_UNPROVEN
                && held.detail.contains("target_is_self_sovereign"),
            "({suffix}) I2862: held steward_unproven for target_is_self_sovereign (the \
             presumption of capacity): {held:?}"
        );
        assert!(
            !is_named_moderator(dir, &e2::kid(&adult), &community_k, DELEGATION_SCOPE_SLASH)
                .await
                .expect("I2862"),
            "({suffix}) I2862: a custody claim onto a proven adult seats no moderator"
        );
    }

    /// v62.0.0 (K2-fix10) — **I2855–I2857: a quarantine marker signed
    /// OUTSIDE the engine** (the two-step path CIRISServer uses for a
    /// hardware-custodied owner): `emit::draft_from_envelope(kid, iss, ..)`,
    /// the draft's `sig_structure` signed by the person's own composite key
    /// (a seeded fixture signer, never the engine's LocalSigner),
    /// `draft.assemble(sig)`, then `Engine::put_edition2_statement`.
    ///
    /// The slash seat: a PERSON holds it as the founder (a root of the
    /// community's authority set) OR as a named moderator, a person seated by
    /// the founder's `delegates_to(slash)` (CC 4.5.4; I2860). An ordinary
    /// delegation onto a person is not a custody claim, so the user-target
    /// rule does not govern it (K2-fix11). The holder here is the founder;
    /// the named-moderator person is I2860–I2861.
    ///
    /// - **I2855** — the person (a slash-seat holder: founder or named
    ///   moderator) signs: admitted (`Row`);
    ///   `resolve_quarantine` reads `Withheld`.
    /// - **I2856** — the same flow under a NODE key: refused
    ///   [`cells::SIGNER_KIND_REFUSED`].
    /// - **I2857** — a person without the slash seat: HELD (`Pending`, GC1
    ///   `delegated_scope_unauthorized`), no typed row, not admitted.
    /// - **I2858** — an AGENT holding a seated `delegates_to(slash)` from the
    ///   founder root signs externally: `Row`, and the fold is `Withheld`,
    ///   governed by the agent's marker.
    /// - **I2859** — an agent (owned) WITHOUT that delegation: held, not
    ///   admitted.
    ///
    /// Every instant is the holder key's window start plus a fixed offset.
    pub(crate) async fn exercise_external_signer_quarantine(engine: &crate::Engine, suffix: &str) {
        use crate::federation::edition2::emit::draft_from_envelope;
        use crate::federation::edition2::ingest::StatementOutcome;
        use crate::federation::edition2::names::RowId;
        let directory = engine.federation_directory();
        let dir: &dyn FederationDirectory = directory.as_ref();
        let holder = format!("q10-holder-{suffix}");
        let member = format!("q10-member-{suffix}");
        let outsider = format!("q10-outsider-{suffix}");
        let actor = format!("q10-actor-{suffix}");
        let community = format!("q10-commons-{suffix}");
        let node = format!("q10-node-{suffix}");
        for k in [&holder, &member, &outsider, &actor, &community] {
            register_user_key(dir, k).await;
        }
        register_key(dir, &node, crate::federation::types::identity_type::NODE).await;
        let base_ms = e2::key_window_start_ms(&holder);
        let base = DateTime::<Utc>::from_timestamp_millis(
            i64::try_from(base_ms).expect("a window start fits i64"),
        )
        .expect("an instant");
        let hour_ms: u64 = 3_600_000;
        let (actor_k, community_k) = (e2::kid(&actor), e2::kid(&community));
        let community_row = crate::federation::tier_ingest::test_support::sign_community(
            &holder,
            crate::federation::types::Community {
                prev_head_digest: String::new(),
                charter_digest: String::new(),
                community_key_id: community.clone(),
                community_name: format!("commons {community}"),
                members: vec![
                    crate::federation::types::CommunityMember {
                        key_id: holder.clone(),
                        joined_at: base,
                        role: Some("founder".to_owned()),
                    },
                    crate::federation::types::CommunityMember {
                        key_id: member.clone(),
                        joined_at: base,
                        role: Some("member".to_owned()),
                    },
                ],
                founded_at: base,
                consensus_protocol: "majority".to_owned(),
                policy_blob: None,
                persist_row_hash: String::new(),
            },
        );
        e2::put_voices(
            dir,
            &e2::community_voices(&community_row, 1, None, e2::ms(base)),
        )
        .await
        .expect("I2855: the community roster lands");

        // The two-step path: draft for `seed`'s key, sign OUTSIDE the engine.
        let external = |seed: &str, delegation_id: &str, at_ms: u64| {
            let draft = draft_from_envelope(
                &e2::kid_digest(seed),
                &e2::kid(seed),
                &actor_k,
                crate::federation::types::attestation_type::SCORES,
                &withhold_envelope(&actor_k, &community_k, delegation_id, "spam"),
                at_ms,
                None,
            )
            .expect("the marker drafts");
            let sig = e2::signing_key(seed)
                .sign(&draft.sig_structure)
                .expect("the person's own key signs the draft");
            draft.assemble(sig)
        };

        // ── I2855: the slash-seat holder.
        let stmt = external(&holder, "q10-deleg-h", base_ms + hour_ms);
        let out = engine
            .put_edition2_statement(&stmt, None)
            .await
            .expect("I2855: admitted");
        assert!(
            matches!(out, StatementOutcome::Row { .. }),
            "({suffix}) I2855: an externally signed holder's marker lands: {out:?}"
        );
        assert_eq!(
            resolve_quarantine(dir, &actor_k, Utc::now())
                .await
                .expect("resolve")
                .state,
            QuarantineState::Withheld,
            "({suffix}) I2855: and withholds"
        );

        // ── I2856: the same flow under a node key.
        let by_node = external(&node, "q10-deleg-n", base_ms + 2 * hour_ms);
        match engine.put_edition2_statement(&by_node, None).await {
            Err(Error::InvalidArgument(m)) if m.starts_with(cells::SIGNER_KIND_REFUSED) => {}
            other => panic!("({suffix}) I2856: a node key's marker is refused: {other:?}"),
        }

        // ── I2857: a person without the slash seat.
        let by_outsider = external(&outsider, "q10-deleg-o", base_ms + 3 * hour_ms);
        let rid = RowId::of_statement(&by_outsider).expect("a row statement");
        let out = engine
            .put_edition2_statement(&by_outsider, None)
            .await
            .expect("I2857: kept, not refused");
        assert!(
            matches!(out, StatementOutcome::Pending { .. }),
            "({suffix}) I2857: held, not admitted: {out:?}"
        );
        assert!(
            dir.get_attestation(&rid.hex())
                .await
                .expect("read")
                .is_none(),
            "({suffix}) I2857: no typed row"
        );
        let why = crate::federation::edition2::fold::why_held(dir, &rid)
            .await
            .expect("I2857: read the hold")
            .expect("I2857: held");
        assert_eq!(
            why.reason,
            crate::federation::edition2::fold::reason::gc1::DELEGATED_SCOPE_UNAUTHORIZED,
            "({suffix}) I2857: {why:?}"
        );

        // ── I2858: an AGENT holding `delegates_to(slash)` from the founder
        // root signs externally through the same flow. The edge is SEATED
        // first: the holder owns the agent (its agent owner binding, the
        // agent's own voice), and the edge lands with the delegate's voice
        // (`delegate`); the holder's own statement fills `delegate_owner`
        // (CC 2.6.1.9, authorship_text.tsv:43–44).
        // The deputy's acts sit OWNER_BINDING_OFFSET_DAYS into the window, so
        // the edge's 180-day test term (`with_test_term`) covers today too.
        let late_ms = base_ms
            + u64::try_from(
                crate::federation::tier_ingest::test_support::OWNER_BINDING_OFFSET_DAYS,
            )
            .expect("a positive offset")
                * 24
                * hour_ms;
        let late = base
            + chrono::Duration::days(
                crate::federation::tier_ingest::test_support::OWNER_BINDING_OFFSET_DAYS,
            );
        let deputy = format!("q10-deputy-{suffix}");
        let bare_agent = format!("q10-bare-agent-{suffix}");
        for k in [&deputy, &bare_agent] {
            register_agent_key(dir, k).await;
            e2::put_agent_owner_binding(dir, &holder, k, late_ms + hour_ms).await;
        }
        let edge = delegation_row(
            &holder,
            &e2::kid(&deputy),
            &[DELEGATION_SCOPE_SLASH],
            late + chrono::Duration::hours(2),
        );
        let seated = e2::land_with_voices(dir, &edge, &[deputy.as_str()])
            .await
            .expect("I2858: the slash edge");
        assert!(
            matches!(seated, StatementOutcome::Row { .. }),
            "({suffix}) I2858: the delegates_to(slash) edge is SEATED: {seated:?}"
        );
        let by_deputy = external(&deputy, "q10-deleg-d", late_ms + 3 * hour_ms);
        let deputy_rid = RowId::of_statement(&by_deputy).expect("a row statement");
        let out = engine
            .put_edition2_statement(&by_deputy, None)
            .await
            .expect("I2858: admitted");
        assert!(
            matches!(out, StatementOutcome::Row { .. }),
            "({suffix}) I2858: the delegate's externally signed marker lands: {out:?}"
        );
        let fold = resolve_quarantine(dir, &actor_k, Utc::now())
            .await
            .expect("resolve");
        assert_eq!(
            (
                fold.state,
                fold.marker_id.as_deref(),
                fold.decided_by.as_deref()
            ),
            (
                QuarantineState::Withheld,
                Some(deputy_rid.hex().as_str()),
                Some(e2::kid(&deputy).as_str())
            ),
            "({suffix}) I2858: Withheld, governed by the delegate's marker"
        );

        // ── I2859: an agent WITHOUT the delegation (owned, but no slash
        // edge): held, not admitted.
        let by_bare = external(&bare_agent, "q10-deleg-b", late_ms + 4 * hour_ms);
        let bare_rid = RowId::of_statement(&by_bare).expect("a row statement");
        let out = engine
            .put_edition2_statement(&by_bare, None)
            .await
            .expect("I2859: kept, not refused");
        assert!(
            matches!(out, StatementOutcome::Pending { .. }),
            "({suffix}) I2859: an agent with no slash edge is held: {out:?}"
        );
        assert!(
            dir.get_attestation(&bare_rid.hex())
                .await
                .expect("read")
                .is_none(),
            "({suffix}) I2859: no typed row"
        );
        let why = crate::federation::edition2::fold::why_held(dir, &bare_rid)
            .await
            .expect("I2859: read the hold")
            .expect("I2859: held");
        assert_eq!(
            why.reason,
            crate::federation::edition2::fold::reason::gc1::DELEGATED_SCOPE_UNAUTHORIZED,
            "({suffix}) I2859: {why:?}"
        );
    }

    /// v62.0.0 (K2-fix9) — **I2850–I2853: the `quarantine:{state}` cells**
    /// (`quarantine::cells`; CC rc21's family model, DROP AT 23.3.3), on every
    /// backend. Every instant is anchored to the founder's key window
    /// (`e2::key_window_start_ms`), never to the wall clock; the roster and
    /// the markers sit at fixed offsets after it.
    ///
    /// - **I2850** — a slash-seat holder's withhold lands (`Admitted`) and
    ///   withholds.
    /// - **I2851** — a NODE key's marker is refused
    ///   [`cells::SIGNER_KIND_REFUSED`] (CC 3.4.7.3 C and E, terminal: the
    ///   signer's own key record).
    /// - **I2852** — a non-holder's marker is refused
    ///   `federation_delegated_scope_unauthorized` at `put_attestation`, and
    ///   at the statement door it is held with the GC1 reason
    ///   `delegated_scope_unauthorized` (CC 2.7.3).
    /// - **I2853** — a withhold outranks a release whatever their instants
    ///   (CC 3.1.9.2, part_3 l.646): a second holder's newer release that
    ///   names only its OWN withhold leaves the first holder's withhold
    ///   standing; the release naming it lifts it.
    pub(crate) async fn exercise_quarantine_cells(dir: &dyn FederationDirectory, suffix: &str) {
        let founder = format!("q9-founder-{suffix}");
        let member = format!("q9-member-{suffix}");
        let stranger = format!("q9-stranger-{suffix}");
        let actor = format!("q9-actor-{suffix}");
        let community = format!("q9-commons-{suffix}");
        let node = format!("q9-node-{suffix}");
        for k in [&founder, &member, &stranger, &actor, &community] {
            register_user_key(dir, k).await;
        }
        register_key(dir, &node, crate::federation::types::identity_type::NODE).await;
        let base = DateTime::<Utc>::from_timestamp_millis(
            i64::try_from(e2::key_window_start_ms(&founder)).expect("a window start fits i64"),
        )
        .expect("an instant");
        let at = |hours: i64| base + chrono::Duration::hours(hours);
        let (actor_k, community_k) = (e2::kid(&actor), e2::kid(&community));

        // The community whose authority set is {founder, member}, founded at
        // the anchor.
        let community_row = crate::federation::tier_ingest::test_support::sign_community(
            &founder,
            crate::federation::types::Community {
                prev_head_digest: String::new(),
                charter_digest: String::new(),
                community_key_id: community.clone(),
                community_name: format!("commons {community}"),
                members: vec![
                    crate::federation::types::CommunityMember {
                        key_id: founder.clone(),
                        joined_at: base,
                        role: Some("founder".to_owned()),
                    },
                    crate::federation::types::CommunityMember {
                        key_id: member.clone(),
                        joined_at: base,
                        role: Some("member".to_owned()),
                    },
                ],
                founded_at: base,
                consensus_protocol: "majority".to_owned(),
                policy_blob: None,
                persist_row_hash: String::new(),
            },
        );
        e2::put_voices(
            dir,
            &e2::community_voices(&community_row, 1, None, e2::ms(base)),
        )
        .await
        .expect("I2850: the community roster lands");

        // ── I2850: the slash-seat holder's withhold lands.
        let w1 = signed_row(
            &founder,
            &actor_k,
            withhold_envelope(&actor_k, &community_k, "q9-deleg-f", "spam"),
            at(1),
        );
        let w1_id = w1.attestation_id.clone();
        assert_eq!(
            record_quarantine_marker(dir, &w1).await.expect("I2850"),
            QuarantineOutcome::Admitted,
            "({suffix}) I2850: a slash-seat holder's quarantine lands"
        );
        assert!(
            resolve_quarantine(dir, &actor_k, Utc::now())
                .await
                .expect("resolve")
                .withholds(),
            "({suffix}) I2850: and withholds"
        );

        // ── I2851: a node key never signs it.
        let by_node = signed_row(
            &node,
            &actor_k,
            withhold_envelope(&actor_k, &community_k, "q9-deleg-n", "spam"),
            at(2),
        );
        match dir
            .put_attestation(crate::federation::SignedAttestation {
                attestation: by_node,
            })
            .await
        {
            Err(Error::InvalidArgument(m)) if m.starts_with(cells::SIGNER_KIND_REFUSED) => {}
            other => panic!("({suffix}) I2851: a node key's quarantine is refused: {other:?}"),
        }

        // ── I2852: a non-holder is refused / held, by the slash seat.
        let usurp = signed_row(
            &stranger,
            &actor_k,
            withhold_envelope(&actor_k, &community_k, "q9-deleg-s", "spam"),
            at(3),
        );
        match dir
            .put_attestation(crate::federation::SignedAttestation { attestation: usurp })
            .await
        {
            Err(e) if e.kind() == "federation_delegated_scope_unauthorized" => {}
            other => panic!(
                "({suffix}) I2852: a non-holder is refused \
                 federation_delegated_scope_unauthorized: {other:?}"
            ),
        }
        let usurp_door = signed_row(
            &stranger,
            &actor_k,
            withhold_envelope(&actor_k, &community_k, "q9-deleg-s2", "spam"),
            at(3) + chrono::Duration::minutes(30),
        );
        let usurp_id = crate::federation::edition2::names::RowId(e2::rid_digest(&usurp_door));
        let out = e2::put_signed(dir, &usurp_door)
            .await
            .expect("I2852: the door keeps it");
        assert!(
            matches!(
                out,
                crate::federation::edition2::ingest::StatementOutcome::Pending { .. }
            ),
            "({suffix}) I2852: held at the statement door: {out:?}"
        );
        let why = crate::federation::edition2::fold::why_held(dir, &usurp_id)
            .await
            .expect("I2852: read the hold")
            .expect("I2852: held");
        assert_eq!(
            why.reason,
            crate::federation::edition2::fold::reason::gc1::DELEGATED_SCOPE_UNAUTHORIZED,
            "({suffix}) I2852: {why:?}"
        );

        // ── I2853: a withhold outranks a release whatever their instants.
        let wm = signed_row(
            &member,
            &actor_k,
            withhold_envelope(&actor_k, &community_k, "q9-deleg-m", "spam"),
            at(4),
        );
        let wm_id = wm.attestation_id.clone();
        assert_eq!(
            record_quarantine_marker(dir, &wm).await.expect("I2853"),
            QuarantineOutcome::Admitted,
            "({suffix}) I2853: the second holder's withhold"
        );
        let rm = signed_row(
            &member,
            &actor_k,
            release_envelope(&actor_k, &community_k, &wm_id, "q9-deleg-m", "own"),
            at(5),
        );
        assert_eq!(
            record_quarantine_marker(dir, &rm).await.expect("I2853"),
            QuarantineOutcome::Admitted,
            "({suffix}) I2853: the second holder releases ITS withhold"
        );
        let fold = resolve_quarantine(dir, &actor_k, Utc::now())
            .await
            .expect("resolve");
        assert_eq!(
            (fold.state, fold.marker_id.as_deref()),
            (QuarantineState::Withheld, Some(w1_id.as_str())),
            "({suffix}) I2853: the newest marker is a release, but it names only its own \
             withhold; the first holder's withhold still governs"
        );
        let rf = signed_row(
            &founder,
            &actor_k,
            release_envelope(&actor_k, &community_k, &w1_id, "q9-deleg-f", "lifted"),
            at(6),
        );
        assert_eq!(
            record_quarantine_marker(dir, &rf).await.expect("I2853"),
            QuarantineOutcome::Admitted,
            "({suffix}) I2853"
        );
        assert_eq!(
            resolve_quarantine(dir, &actor_k, Utc::now())
                .await
                .expect("resolve")
                .state,
            QuarantineState::Released,
            "({suffix}) I2853: the release naming the withhold lifts it"
        );
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

        for k in [&founder, &member, &stranger, &actor, &community] {
            register_user_key(dir, k).await;
        }
        for k in [&deputy_slash, &deputy_mod] {
            register_agent_key(dir, k).await;
        }
        // v62.0.0 (E0 fix 10) — every fixture instant is anchored to the
        // signing keys' WINDOW, never the wall clock: the deputies (agent keys)
        // and the node signing the hard_case rows are default-window keys, so
        // they share one start (`e2::key_window_start_ms`). The fixture sits at
        // K2's fixed offset into it (`OWNER_BINDING_OFFSET_DAYS`), and each act
        // takes the next second (`tick`), so the withhold precedes its release
        // as written.
        let now = {
            let start = e2::key_window_start_ms(&deputy_slash);
            DateTime::<Utc>::from_timestamp_millis(
                i64::try_from(start).expect("a window start in range"),
            )
            .expect("a window start in range")
                + chrono::Duration::days(
                    crate::federation::tier_ingest::test_support::OWNER_BINDING_OFFSET_DAYS,
                )
        };
        let step = std::cell::Cell::new(0_i64);
        let tick = || {
            step.set(step.get() + 1);
            now + chrono::Duration::seconds(step.get())
        };
        // v62 (E3): the seeds sign; the stored, compared ids are identity-refs.
        let (founder_k, stranger_k, actor_k, community_k) = (
            e2::kid(&founder),
            e2::kid(&stranger),
            e2::kid(&actor),
            e2::kid(&community),
        );

        // A community whose authority set is {founder, member}. `actor` and
        // `stranger` are deliberately NOT members. v62 (E3): the typed builder
        // through T1's `group:roster` voices (the founder and each listed
        // member), keyed by identity-refs.
        let community_row = crate::federation::tier_ingest::test_support::sign_community(
            &founder,
            crate::federation::types::Community {
                prev_head_digest: String::new(),
                charter_digest: String::new(),
                community_key_id: community.clone(),
                community_name: format!("commons {community}"),
                members: vec![
                    crate::federation::types::CommunityMember {
                        key_id: founder.clone(),
                        joined_at: now,
                        role: Some("founder".to_owned()),
                    },
                    crate::federation::types::CommunityMember {
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
        );
        e2::put_voices(
            dir,
            &e2::community_voices(&community_row, 1, None, e2::ms(now)),
        )
        .await
        .expect("the community roster lands");

        // An ordinary federation-tier row by the actor — the thing serving
        // will (and then will not) hand to peers.
        let actor_row = signed_row(
            &actor,
            &actor_k,
            serde_json::json!({
                "dimension": "testimonial_witness:commons_act:v1",
                "payload": {"action": "an ordinary row"},
            }),
            now,
        );
        let actor_row_id = actor_row.attestation_id.clone();
        e2::put_signed(dir, &actor_row)
            .await
            .expect("the actor's row lands normally");
        assert!(
            served(dir, &actor_row_id).await,
            "({suffix}) before any marker the row is served"
        );

        let mk = |author: &str, subject: &str, env: serde_json::Value| {
            signed_row(author, subject, env, tick())
        };

        // ── (1) UNATTRIBUTED: no delegation_id ⇒ refused.
        let bare = mk(
            &founder,
            &actor_k,
            withhold_envelope(&actor_k, &community_k, "", "spam"),
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
            &founder,
            &stranger_k, // attested_key_id ≠ quarantines_key_id
            withhold_envelope(&actor_k, &community_k, "att-deleg", "spam"),
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
        let ghost = e2::kid(&format!("qa-ghost-{suffix}"));
        let unknown = mk(
            &founder,
            &ghost,
            withhold_envelope(&ghost, &community_k, "att-deleg", "spam"),
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
            &stranger,
            &actor_k,
            withhold_envelope(&actor_k, &community_k, "att-deleg", "spam"),
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
            !resolve_quarantine(dir, &actor_k, Utc::now())
                .await
                .expect("resolve")
                .withholds(),
            "({suffix}) four refusals wrote nothing"
        );
        assert!(served(dir, &actor_row_id).await, "({suffix}) still served");

        // ── (5) THE HOLDER'S MARKER LANDS, and serving stops.
        let withhold = mk(
            &founder,
            &actor_k,
            withhold_envelope(&actor_k, &community_k, "att-deleg-1", "sustained spam"),
        );
        let withhold_id = withhold.attestation_id.clone();
        assert_eq!(
            record_quarantine_marker(dir, &withhold)
                .await
                .expect("policy outcome"),
            QuarantineOutcome::Admitted,
            "({suffix}) a steward-bound community authority holds `slash` as-self"
        );
        let fold = resolve_quarantine(dir, &actor_k, Utc::now())
            .await
            .expect("resolve");
        assert_eq!(fold.state, QuarantineState::Withheld, "({suffix})");
        assert_eq!(fold.marker_id.as_deref(), Some(withhold_id.as_str()));
        assert_eq!(fold.decided_by.as_deref(), Some(founder_k.as_str()));
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
        let release = mk(
            &founder,
            &actor_k,
            release_envelope(
                &actor_k,
                &community_k,
                &withhold_id,
                "att-deleg-1",
                "appeal upheld",
            ),
        );
        let release_id = release.attestation_id.clone();
        assert_eq!(
            record_quarantine_marker(dir, &release)
                .await
                .expect("policy outcome"),
            QuarantineOutcome::Admitted,
            "({suffix})"
        );
        let fold = resolve_quarantine(dir, &actor_k, Utc::now())
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
            &founder,
            &actor_k,
            release_envelope(
                &actor_k,
                &community_k,
                "no-such-marker",
                "att-deleg-1",
                "nope",
            ),
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
        // v62.0.0 (E0 fix 10; CC 2.6.1.9, CC ruled quarantine:{state} is a row
        // authored by the community's slash-duty holder) — each deputy is
        // SEATED: an own-act `self:delegates_to` waits for the delegate's voice
        // and, a deputy being an agent (a machine key), its owner's
        // (`delegate_owner`). The founder owns both deputies (an agent's owner
        // binding, `e2::put_agent_owner_binding`), and the delegation lands
        // through `e2::land_delegation` with exactly the roles K2's resolved
        // reader names, asserted SEATED (a held edge would make arm 8 a check
        // that cannot fail).
        for (deputy, scope) in [
            (&deputy_mod, DELEGATION_SCOPE_MODERATE),
            (&deputy_slash, DELEGATION_SCOPE_SLASH),
        ] {
            e2::put_agent_owner_binding(dir, &founder, deputy, e2::ms(tick())).await;
            let edge = delegation_row(&founder, &e2::kid(deputy), &[scope], tick());
            let (out, unvoiced) = e2::land_delegation(dir, &edge)
                .await
                .expect("the delegation is admitted");
            assert!(
                matches!(
                    out,
                    crate::federation::edition2::ingest::StatementOutcome::Row { .. }
                ),
                "({suffix}) the {scope} deputy is seated: {out:?}, unvoiced {unvoiced:?}"
            );
        }
        let by_mod_deputy = mk(
            &deputy_mod,
            &actor_k,
            withhold_envelope(&actor_k, &community_k, "att-deleg-2", "reported"),
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
            &deputy_slash,
            &actor_k,
            withhold_envelope(&actor_k, &community_k, "att-deleg-3", "delegated"),
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
            &actor_k,
            Some(&founder_k),
            "att-deleg-1",
            "sustained spam",
            tick(),
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
                emitter_key_id: None,
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
            &actor_k,
            Some(&founder_k),
            "att-deleg-1",
            "sustained spam",
            tick(),
        );
        dir.record_hard_case(attributed.clone())
            .await
            .expect("a fully attributed admin action records");
        let rows = dir
            .list_hard_case_events(HardCaseFilter {
                kind: Some(quarantine_kind),
                since: None,
                emitter_key_id: None,
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

/// v62.0.0 (K2-fix9) — the `quarantine:{state}` cells, sqlite and postgres.
#[cfg(all(test, any(feature = "sqlite", feature = "postgres")))]
mod cells_runners {
    fn suffix() -> String {
        uuid::Uuid::new_v4().simple().to_string()[..12].to_owned()
    }

    #[cfg(feature = "sqlite")]
    #[tokio::test]
    async fn i2850_i2853_quarantine_cells_sqlite() {
        use crate::store::Backend as _;
        let b = crate::store::sqlite::SqliteBackend::open_in_memory()
            .await
            .unwrap();
        b.run_migrations().await.unwrap();
        Box::pin(super::test_support::exercise_quarantine_cells(
            &b,
            &suffix(),
        ))
        .await;
    }

    #[cfg(feature = "sqlite")]
    #[tokio::test]
    async fn i2855_i2857_external_signer_quarantine_sqlite() {
        let s = suffix();
        let engine = crate::Engine::with_signer(
            crate::federation::tier_ingest::test_support::local_signer(&format!("q10-engine-{s}")),
            "sqlite::memory:",
        )
        .await
        .expect("engine");
        Box::pin(super::test_support::exercise_external_signer_quarantine(
            &engine, &s,
        ))
        .await;
    }

    #[cfg(feature = "postgres")]
    #[tokio::test]
    async fn i2855_i2857_external_signer_quarantine_postgres() {
        let Some(dsn) = crate::test_pg::isolated_dsn() else {
            eprintln!("skipping: CIRIS_PERSIST_TEST_PG_URL unset");
            return;
        };
        let s = suffix();
        let engine = crate::Engine::with_signer(
            crate::federation::tier_ingest::test_support::local_signer(&format!("q10-engine-{s}")),
            &dsn,
        )
        .await
        .expect("pg engine");
        Box::pin(super::test_support::exercise_external_signer_quarantine(
            &engine, &s,
        ))
        .await;
    }

    #[cfg(feature = "sqlite")]
    #[tokio::test]
    async fn i2860_i2862_person_moderator_sqlite() {
        let s = suffix();
        let engine = crate::Engine::with_signer(
            crate::federation::tier_ingest::test_support::local_signer(&format!("q11-engine-{s}")),
            "sqlite::memory:",
        )
        .await
        .expect("engine");
        let node = format!("q11-node-{s}");
        engine
            .sqlite_backend()
            .expect("sqlite")
            .set_node_key_id(crate::federation::edition2::fixture_switch::kid(&node));
        Box::pin(super::test_support::exercise_person_moderator(
            &engine, &node, &s,
        ))
        .await;
    }

    #[cfg(feature = "postgres")]
    #[tokio::test]
    async fn i2860_i2862_person_moderator_postgres() {
        let Some(dsn) = crate::test_pg::isolated_dsn() else {
            eprintln!("skipping: CIRIS_PERSIST_TEST_PG_URL unset");
            return;
        };
        let s = suffix();
        let engine = crate::Engine::with_signer(
            crate::federation::tier_ingest::test_support::local_signer(&format!("q11-engine-{s}")),
            &dsn,
        )
        .await
        .expect("pg engine");
        let node = format!("q11-node-{s}");
        engine
            .postgres_backend()
            .expect("postgres")
            .set_node_key_id(crate::federation::edition2::fixture_switch::kid(&node));
        Box::pin(super::test_support::exercise_person_moderator(
            &engine, &node, &s,
        ))
        .await;
    }

    #[cfg(feature = "sqlite")]
    #[tokio::test]
    async fn i2863_i2869_minor_appointment_void_sqlite() {
        let s = suffix();
        let seed = format!("q12-engine-{s}");
        let engine = crate::Engine::with_signer(
            crate::federation::tier_ingest::test_support::local_signer(&seed),
            "sqlite::memory:",
        )
        .await
        .expect("engine");
        let node = format!("q12-node-{s}");
        engine
            .sqlite_backend()
            .expect("sqlite")
            .set_node_key_id(crate::federation::edition2::fixture_switch::kid(&node));
        Box::pin(super::test_support::exercise_minor_duty(&engine, &node, &s)).await;
    }

    #[cfg(feature = "postgres")]
    #[tokio::test]
    async fn i2863_i2869_minor_appointment_void_postgres() {
        let Some(dsn) = crate::test_pg::isolated_dsn() else {
            eprintln!("skipping: CIRIS_PERSIST_TEST_PG_URL unset");
            return;
        };
        let s = suffix();
        let seed = format!("q12-engine-{s}");
        let engine = crate::Engine::with_signer(
            crate::federation::tier_ingest::test_support::local_signer(&seed),
            &dsn,
        )
        .await
        .expect("pg engine");
        let node = format!("q12-node-{s}");
        engine
            .postgres_backend()
            .expect("postgres")
            .set_node_key_id(crate::federation::edition2::fixture_switch::kid(&node));
        Box::pin(super::test_support::exercise_minor_duty(&engine, &node, &s)).await;
    }

    #[cfg(feature = "sqlite")]
    #[tokio::test]
    async fn i2030_declared_duty_minor_appointment_void_sqlite() {
        let s = suffix();
        let seed = format!("q13-engine-{s}");
        let engine = crate::Engine::with_signer(
            crate::federation::tier_ingest::test_support::local_signer(&seed),
            "sqlite::memory:",
        )
        .await
        .expect("engine");
        let node = format!("q13-node-{s}");
        engine
            .sqlite_backend()
            .expect("sqlite")
            .set_node_key_id(crate::federation::edition2::fixture_switch::kid(&node));
        Box::pin(super::test_support::exercise_declared_duty(
            &engine, &node, &s,
        ))
        .await;
    }

    #[cfg(feature = "postgres")]
    #[tokio::test]
    async fn i2030_declared_duty_minor_appointment_void_postgres() {
        let Some(dsn) = crate::test_pg::isolated_dsn() else {
            eprintln!("skipping: CIRIS_PERSIST_TEST_PG_URL unset");
            return;
        };
        let s = suffix();
        let seed = format!("q13-engine-{s}");
        let engine = crate::Engine::with_signer(
            crate::federation::tier_ingest::test_support::local_signer(&seed),
            &dsn,
        )
        .await
        .expect("pg engine");
        let node = format!("q13-node-{s}");
        engine
            .postgres_backend()
            .expect("postgres")
            .set_node_key_id(crate::federation::edition2::fixture_switch::kid(&node));
        Box::pin(super::test_support::exercise_declared_duty(
            &engine, &node, &s,
        ))
        .await;
    }

    /// v62.0.0 (K2-fix14, K2-fix15) — I2032–I2043 on sqlite
    /// (`test_support::exercise_minor_void_instants`).
    #[cfg(feature = "sqlite")]
    #[tokio::test]
    async fn i2032_i2037_minor_void_and_suspension_sqlite() {
        let s = suffix();
        let seed = format!("q14-engine-{s}");
        let engine = crate::Engine::with_signer(
            crate::federation::tier_ingest::test_support::local_signer(&seed),
            "sqlite::memory:",
        )
        .await
        .expect("engine");
        let node = format!("q14-node-{s}");
        engine
            .sqlite_backend()
            .expect("sqlite")
            .set_node_key_id(crate::federation::edition2::fixture_switch::kid(&node));
        Box::pin(super::test_support::exercise_minor_void_instants(
            &engine, &node, &s,
        ))
        .await;
    }

    /// v62.0.0 (K2-fix14, K2-fix15) — I2032–I2043 on postgres.
    #[cfg(feature = "postgres")]
    #[tokio::test]
    async fn i2032_i2037_minor_void_and_suspension_postgres() {
        let Some(dsn) = crate::test_pg::isolated_dsn() else {
            eprintln!("skipping: CIRIS_PERSIST_TEST_PG_URL unset");
            return;
        };
        let s = suffix();
        let seed = format!("q14-engine-{s}");
        let engine = crate::Engine::with_signer(
            crate::federation::tier_ingest::test_support::local_signer(&seed),
            &dsn,
        )
        .await
        .expect("pg engine");
        let node = format!("q14-node-{s}");
        engine
            .postgres_backend()
            .expect("postgres")
            .set_node_key_id(crate::federation::edition2::fixture_switch::kid(&node));
        Box::pin(super::test_support::exercise_minor_void_instants(
            &engine, &node, &s,
        ))
        .await;
    }

    #[cfg(feature = "postgres")]
    #[tokio::test]
    async fn i2850_i2853_quarantine_cells_postgres() {
        use crate::store::Backend as _;
        let Some(dsn) = crate::test_pg::isolated_dsn() else {
            eprintln!("skipping: CIRIS_PERSIST_TEST_PG_URL unset");
            return;
        };
        let b = crate::store::postgres::PostgresBackend::connect(&dsn)
            .await
            .unwrap();
        b.run_migrations().await.unwrap();
        Box::pin(super::test_support::exercise_quarantine_cells(
            &b,
            &suffix(),
        ))
        .await;
    }
}
