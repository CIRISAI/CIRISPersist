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
        let mut envelope = serde_json::json!({
            "dimension": "delegation:duty:v1",
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
