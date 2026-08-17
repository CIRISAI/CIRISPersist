//! v13.0.0 (CIRISPersist#365, CC 3.4.7.2 `consent-counter`) — the
//! **Counter-RII `consent_role`** resolver.
//!
//! `federation_keys.consent_role` is the role token (see the
//! [`consent_role`](super::types::consent_role) vocabulary — `temporary`
//! / `partnered` / `anonymous` / `authorized_review` / `peer`, with
//! `unregistered` as the stored no-role default) that gates Counter-RII
//! probe detection (RATCHET `FSD/COUNTER_RII_DETECTION.md`; Lean
//! `ConsentGate.lean`). Per CC 3.4.7.2 it is a **`federation_keys`
//! identity field** — a sibling to `identity_type`, NOT an envelope
//! primitive — and the clause states implementations MAY now build the
//! substrate (no longer a reserved slot). The COLUMN itself already
//! shipped in V020 (v1.3.0, the CIRISAgent#760 §RC "consent role lock"
//! that CC 3.4.7.2 ratifies — `TEXT NOT NULL DEFAULT 'unregistered'`);
//! v13.0.0 puts it on the wire ([`KeyRecord::consent_role`](super::KeyRecord),
//! `None` ⇔ the stored `'unregistered'`) and exposes this resolver.
//!
//! **What persist owns (and does NOT own).** The three ratified
//! semantics split by responsibility:
//!
//! - **OQ-1 (non-recursive revocation — SUBSTRATE):** a subsequent
//!   revocation OVERWRITES the prior value; the field is flat, bounded,
//!   and carries NO embedded chain. Persist implements this as the
//!   natural UPDATE/overwrite of the single mutable V020 column via
//!   [`super::FederationDirectory::set_consent_role`] (revoke = set
//!   `None` = reset to `'unregistered'`). The field is excluded from
//!   `compute_persist_row_hash` so the overwrite never disturbs the
//!   signed-registration hash.
//! - **OQ-2 (`peer` blanket suppression — CONSUMER):** a `peer`
//!   `consent_role` escapes Counter-RII detection at any `trust_mode`.
//!   Persist STORES + EXPOSES the role; edge's `ProbePatternObserver`
//!   reads it (via [`consent_role_of`]) and suppresses the
//!   advisory-only `ratchet:flag:counter_rii:*` signal. Persist houses
//!   no detector, so it applies no suppression itself.
//! - **OQ-3 (`authorized_review` strict post-window — CONSUMER):** an
//!   `authorized_review` role is signal-eligible immediately at
//!   `t > window_end`. Same split — persist carries the role; the
//!   consumer enforces the window.
//!
//! So this module is the STORE + EXPOSE + OQ-1 half; OQ-2 / OQ-3 are
//! consumer-applied signals on the field persist now carries.

/// v20.0.0 (CIRISPersist#495 C3) — the consent-state dimension PREFIX
/// constants, single-sourced. Server-side consts (infohazard.rs / peer.rs)
/// and every persist SQL literal must speak THESE strings; drift meant
/// `list_consent_revocations` silently empty → revoked consent treated as
/// active → replication kept flowing to a peer that revoked. Versioned
/// dimensions extend the prefix (`consent:state:revoked:v1`).
pub mod consent_dimension {
    /// v31.0.0 (CIRISPersist#598) — the prefix of EVERY consent-STATE
    /// dimension, i.e. the exact axis both consent folds and the #598
    /// instant-binding gate key on. It was spelled as a bare `"consent:state:"`
    /// literal in three places (both folds and the gate that had to agree with
    /// them); a fold that saw a wider set than the gate is precisely how a
    /// row reaches the ordering without passing the binding.
    pub const STATE_PREFIX: &str = "consent:state:";
    /// Prefix of every granted-state dimension.
    pub const STATE_GRANTED_PREFIX: &str = "consent:state:granted";
    /// Prefix of every revoked-state dimension.
    pub const STATE_REVOKED_PREFIX: &str = "consent:state:revoked";
    /// Prefix of every expired-state dimension.
    pub const STATE_EXPIRED_PREFIX: &str = "consent:state:expired";
}

use super::{Error, FederationDirectory};

/// v13.0.0 (CIRISPersist#365, CC 3.4.7.2) — resolve the Counter-RII
/// `consent_role` of `key_id`.
///
/// Returns `Ok(Some(role))` when the key exists and carries an assigned
/// role; `Ok(None)` when the key exists with no assigned role (the
/// stored `'unregistered'` default — including after an OQ-1
/// revoke-overwrite) **or** when `key_id` is absent. The resolver is
/// deliberately total: an absent key and a role-less key are both "no
/// assigned Counter-RII role", which a consumer treats identically
/// (detection applies normally, no suppression). The returned token is
/// one of the assigned [`consent_role`](super::types::consent_role)
/// tokens; the consumer interprets it — persist does not gate on the
/// value here.
pub async fn consent_role_of(
    dir: &dyn FederationDirectory,
    key_id: &str,
) -> Result<Option<String>, Error> {
    Ok(dir
        .lookup_public_key(key_id)
        .await?
        .and_then(|record| record.consent_role))
}

/// v16.1.0 (CIRISPersist#389) — the envelope's `dimension` string (the same
/// axis admission keys on), read straight off the stored
/// `attestation_envelope`. Shared by the consent folds
/// ([`resolve_consent_state`](super::FederationDirectory::resolve_consent_state)
/// / [`resolve_scoped_consent`](super::FederationDirectory::resolve_scoped_consent)).
pub fn envelope_dimension(a: &super::Attestation) -> Option<&str> {
    a.attestation_envelope
        .get("dimension")
        .and_then(|v| v.as_str())
}

/// v16.1.0 (CIRISPersist#389) — THE `consent:state:*` dimension → stance
/// classifier, the single mapping both consent folds share (so the closed-set
/// rule cannot drift). A `consent:state:*` value outside the closed set — or
/// no candidate at all — is `Unspecified` (forward-compat: an unknown stance
/// value never silently reads as granted).
pub fn consent_state_of(dimension: Option<&str>) -> super::hard_case::ConsentState {
    use super::hard_case::ConsentState;
    match dimension {
        Some(d) if d.starts_with(consent_dimension::STATE_GRANTED_PREFIX) => ConsentState::Granted,
        Some(d) if d.starts_with(consent_dimension::STATE_REVOKED_PREFIX) => ConsentState::Revoked,
        Some(d) if d.starts_with(consent_dimension::STATE_EXPIRED_PREFIX) => ConsentState::Expired,
        _ => ConsentState::Unspecified,
    }
}

/// v31.0.0 (CIRISPersist#598) — the **restriction rank** of a consent
/// stance: how much a stance CLOSES, ordered so that a larger number is a
/// more restrictive reading.
///
/// `Granted` is the sole fail-OPEN stance and therefore ranks lowest.
/// `Unspecified` (an unknown `consent:state:*` value — forward-compat) ranks
/// above it, because "we do not recognise this stance" must never resolve as
/// a grant. `Expired` and `Revoked` are explicit closures.
#[must_use]
pub fn restriction_rank(state: super::hard_case::ConsentState) -> u8 {
    use super::hard_case::ConsentState;
    match state {
        ConsentState::Granted => 0,
        ConsentState::Unspecified => 1,
        ConsentState::Expired => 2,
        ConsentState::Revoked => 3,
    }
}

/// v31.0.0 (CIRISPersist#598) — **THE consent-fold ordering key**, shared by
/// [`resolve_consent_state`](super::FederationDirectory::resolve_consent_state)
/// and [`resolve_scoped_consent`](super::FederationDirectory::resolve_scoped_consent)
/// so the two folds cannot disagree about which claim wins.
///
/// # The primary component is still the ROW COLUMN, on purpose
///
/// `#598`'s tempting fix is to re-key the fold to the envelope's signed
/// instant. **That is wrong**, and it is wrong in a way that reads as a fix:
/// a row that carries no envelope instant yields `None` for it, and both
/// dispositions of `None` lose.
///
/// - `None`-sorts-LOW: every instant-less row sinks below every instant-
///   bearing one, so a re-minted STALE grant carrying an instant beats a
///   RECENT revoke that does not — the exact flip #598 reports, now caused by
///   the fix.
/// - `None`-falls-back-to-the-column: the attacker simply omits the envelope
///   key and picks their own ordering key, which is the status quo with a
///   longer code path.
///
/// So the ordering stays on the column and the SECURITY comes from the gate:
/// [`crate::federation::admission::check_instant_binding`]
/// refuses a `consent:state:*` row at every write door unless the column and
/// the signed envelope carry the SAME instant. Once every stored row is
/// bound, ordering on the column IS ordering on the signed instant — and the
/// unbound rows the naive re-key had to reason about do not exist, because
/// they were never admitted.
///
/// # The two tie-break components
///
/// `max_by_key` on a bare instant has NO tie-break: a grant and a revoke at
/// the same instant resolved to whichever the backend's row order happened to
/// present last, and the backends do not agree on that. The added components
/// make it deterministic, in the RESTRICTION-WINS direction the rest of the
/// substrate already uses ([`crate::federation::quarantine`],
/// [`crate::federation::mesh_config`], [`crate::federation::precedence`]):
///
/// 1. [`restriction_rank`] — at one instant, the MOST restrictive stance wins.
///    A grant can never out-rank a revoke it ties with.
/// 2. `attestation_id` — total order for the remaining case (same instant,
///    same stance), where the fold's ANSWER is identical either way, so this
///    buys determinism without buying the attacker anything: an id chosen to
///    sort high still cannot beat rank 1.
#[must_use]
pub fn fold_ordering_key(a: &super::Attestation) -> (chrono::DateTime<chrono::Utc>, u8, String) {
    (
        a.asserted_at,
        restriction_rank(consent_state_of(envelope_dimension(a))),
        a.attestation_id.clone(),
    )
}

/// v36.0.0 (CIRISPersist#642) — **THE CONSENT-CAUSAL EDGE**: the prior consent
/// statement that this one SUPERSEDES.
///
/// # Why an edge and not a smaller skew window
///
/// [`fold_ordering_key`] orders on a wall clock the PRODUCER chooses. #598
/// bound that instant to the signed envelope, so it can no longer be FORGED —
/// but the producer still picks it, and
/// [`crate::federation::admission::DEFAULT_MAX_TOUCH_SKEW`] (300s) is the width
/// of the remaining race: a grant minted up to five minutes ahead out-sorts a
/// revocation issued inside that window.
///
/// **300s is a defensible FRESHNESS window and a wrong ORDERING window.**
/// Kerberos, JWT `leeway`, SigV4 all use ~300s to ask *"is this credential
/// recent enough to accept?"* — a question whose refusal is fail-closed and
/// whose worst case is a retried request. This fold asks a different question:
/// *"which of two signed statements is later?"* That is last-writer-wins
/// conflict resolution on a producer-chosen key, and the distributed-systems
/// answer there is the opposite of a tuned tolerance — hybrid logical clocks
/// and dotted version vectors exist precisely because physical timestamps
/// cannot resolve conflicts safely (the canonical failure being the device an
/// hour ahead that wins every merge). So 300s → 60s would buy a smaller race
/// and cost real-world robustness: **the wrong axis, tightened.**
///
/// The right axis is causality, and this repo already ships it **on a
/// neighbouring CONSENT plane**: [`crate::federation::consent_peer_set`]
/// (v21.0.0, #502 E7) folds `consent:replication:v1` by exactly this rule — a
/// structural composer naming a grant through `references_attestation_id`
/// deletes what that grant authorized, with no clock anywhere in the fold. So
/// this is not a new mechanism, it is the `consent:state:*` plane adopting the
/// one its sibling has used since v21.0.0.
///
/// `supersedes` / `withdraws` / `recants` are first-class edge types
/// ([`crate::federation::types::attestation_type`]) that name their upstream
/// through the CEG §3.2 pointer
/// [`references_attestation_id`](crate::federation::envelope::paths::REFERENCES_ATTESTATION_ID)
/// — and until v36.0.0 the `consent:state:*` plane used none of them. **A revocation
/// that NAMES the grant it revokes is ordered causally: no clock, no race, no
/// window**, and it cannot be minted ahead of the fact, because naming a row
/// requires the row to exist first.
///
/// # The wire shape — a SEPARATE key, and why
///
/// A `consent:state:*` row carries the name in its envelope's
/// [`consent_supersedes`](crate::federation::envelope::paths::CONSENT_SUPERSEDES).
/// The row keeps its `scores` type and its `consent:state:*` dimension;
/// nothing else about it moves.
///
/// The first implementation reused the composer pointer
/// `references_attestation_id` — same meaning, no envelope cost — and **a gate
/// refused it.** CC 4.5.1.1 (rc3) admits that pointer's polysemy only as an OP
/// SPLIT enumerated per emitting operation, and the table holds exactly three
/// operations (`withdraws` / `recants` / `supersedes`). A consent statement is
/// a `scores` row, so reading the pointer there is a FOURTH reading — and the
/// ruling attaches a falsifier to exactly that case, with the remedy named:
/// *"the remedy is the field split, envelope cost accepted."*
/// `namespace::supersets::tests::every_pointer_read_is_discriminator_guarded`
/// is that falsifier made mechanical, and it fired.
///
/// So the constitution chose this wire shape, not convenience: the consent
/// plane takes its own slot and the composer pointer keeps its three admitted
/// readings. The cost is one envelope key and one
/// `ENVELOPE_VOCABULARY_SHA256` re-pin; the alternative was persist
/// unilaterally minting a fourth reading of a field a ruling exists to keep
/// unambiguous.
///
/// The key lives ONLY in the signed envelope and has **no row-column twin**,
/// which is why — unlike `asserted_at` (#598) — it needs no binding gate and
/// no migration: a relay cannot add, remove or repoint it without breaking the
/// signature it rides inside.
///
/// # Read on NON-GRANTS only
///
/// `granted` is the sole fail-OPEN stance (the same asymmetry
/// [`matches_scoped_query`] already applies to scope naming), so a grant's
/// pointer is not read here at all. It could only ever eliminate a restriction,
/// and [`fold_stance`]'s ratchet would discard that result anyway — so reading
/// it would be work that cannot change an answer. A subject re-opens consent
/// with an affirmative later GRANT that wins on its own signed instant, never
/// by pointing at the refusal it wants gone.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ConsentCausalEdge<'a> {
    /// The envelope names no upstream (or the row is a grant, whose pointer
    /// this plane does not read). Clock ordering applies, unchanged.
    Absent,
    /// A usable name: the `attestation_id` of the consent statement this row
    /// supersedes.
    Names(&'a str),
    /// A non-grant carries a pointer this substrate cannot use: a non-string,
    /// the empty string, or the row's OWN id. **Not** treated as `Absent`:
    /// silently degrading a producer's causal claim back to clock ordering is
    /// exactly the fail-open #642 forbids, so an unusable edge is fail-closed
    /// through [`causal_rank`] like an unresolvable one.
    Unusable,
}

/// v36.0.0 (CIRISPersist#642) — read the [`ConsentCausalEdge`] off a consent
/// row. See that type for the whole design.
///
/// **The discriminator is checked HERE, not at the caller.** The lesson of
/// CC 4.5.1.1 — the ruling that made this a separate wire field — is that a
/// polysemous key read without its emitting discriminator is how a processor
/// ends up applying the wrong meaning. So this function refuses to read the key
/// at all unless the row states the operation that gives it meaning: a
/// `consent:state:*` dimension, and a non-`granted` one. `fold_stance` filters
/// to exactly that set already; the check is repeated here so a FUTURE caller
/// cannot resolve the key on a row that never claimed the operation.
#[must_use]
pub fn causal_edge(a: &super::Attestation) -> ConsentCausalEdge<'_> {
    use super::hard_case::ConsentState;
    // THE DISCRIMINATOR: this key is read only on a consent statement…
    let Some(dimension) = envelope_dimension(a) else {
        return ConsentCausalEdge::Absent;
    };
    if !dimension.starts_with(consent_dimension::STATE_PREFIX) {
        return ConsentCausalEdge::Absent;
    }
    // …and grants do not carry causal authority on this plane — see the type
    // doc.
    if consent_state_of(Some(dimension)) == ConsentState::Granted {
        return ConsentCausalEdge::Absent;
    }
    let Some(member) = a
        .attestation_envelope
        .get(crate::federation::envelope::paths::CONSENT_SUPERSEDES)
    else {
        return ConsentCausalEdge::Absent;
    };
    // An absent key and an explicit `null` both say "I make no causal claim"
    // — the same pairing `check_instant_binding` gives `expires_at`.
    if member.is_null() {
        return ConsentCausalEdge::Absent;
    }
    match member.as_str() {
        // A self-reference names no PRIOR statement, and left usable it would
        // eliminate the very row that carries it.
        Some(target) if !target.is_empty() && target != a.attestation_id => {
            ConsentCausalEdge::Names(target)
        }
        _ => ConsentCausalEdge::Unusable,
    }
}

/// v36.0.0 (CIRISPersist#642) — the CAUSAL component of the consent-fold
/// ordering key: **1 iff this row's edge is UNRESOLVED**, 0 otherwise. Larger
/// wins, and it is the PRIMARY component, ahead of the clock.
///
/// `known` is the id set of the subject's own consent statements about this
/// target (see [`fold_stance`]). It is what an edge resolves against — a
/// pointer at someone else's row, at a row about a different target, or at a
/// row this node has not replicated yet, resolves to nothing.
///
/// Rows whose statement is causally DEAD do not appear here at all: elimination
/// is a filter in [`fold_stance`], not a rank. A retracted statement is not a
/// statement, so it is removed rather than out-sorted — otherwise the last
/// remaining candidate would still win by default, and a `withdraws` against
/// the only live grant would buy nothing.
///
/// # Why the unresolved arm exists (the fail-closed rule)
///
/// #642 requires that *"an edge naming an unknown/absent grant must NOT
/// silently degrade to clock ordering in a way that favours the grant."* Rank 0
/// would do exactly that: the revocation would fall back to the clock and lose
/// to the grant minted ahead of it — the defect, reached through the fix.
///
/// So an unresolved edge is read as what it is: **evidence that this node's
/// view of the subject's consent history is INCOMPLETE**, and the substrate's
/// negative default (an unrecognised stance never reads as a grant —
/// [`restriction_rank`]) applies. The restriction holds until the named row
/// arrives, at which point the edge resolves, the rank drops to 0 and ordinary
/// ordering resumes. Two consequences, both deliberate:
///
/// - a node with a PARTIAL view answers no less restrictively than a node with
///   the complete view — divergence, when it happens, is monotone in what the
///   node knows and always toward the safe side;
/// - the escape is chronological again once the view is complete: a later grant
///   re-opens consent by winning on its own signed instant among rank-0 rows,
///   which it does as soon as the named grant replicates.
///
/// Rank 1 is reachable only for non-grants ([`causal_edge`] returns `Absent`
/// for a grant), so no unresolvable pointer can ever LIFT a grant.
#[must_use]
pub fn causal_rank(a: &super::Attestation, known: &std::collections::HashSet<&str>) -> u8 {
    match causal_edge(a) {
        ConsentCausalEdge::Absent => 0,
        ConsentCausalEdge::Names(target) if known.contains(target) => 0,
        ConsentCausalEdge::Names(_) | ConsentCausalEdge::Unusable => 1,
    }
}

/// v36.0.0 (CIRISPersist#642) — **THE CAUSAL consent-fold ordering key**:
/// [`causal_rank`] first, then the three v31.0.0 clock components verbatim
/// ([`fold_ordering_key`]). Largest wins under `max_by_key`.
///
/// The clock is not removed, it is DEMOTED — it decides only among rows
/// causality does not order, which is what "wall clock only as the fallback for
/// rows carrying no edge" means operationally.
#[must_use]
pub fn causal_fold_ordering_key(
    a: &super::Attestation,
    known: &std::collections::HashSet<&str>,
) -> (u8, chrono::DateTime<chrono::Utc>, u8, String) {
    let (at, rank, id) = fold_ordering_key(a);
    (causal_rank(a, known), at, rank, id)
}

/// v16.1.0 (CIRISPersist#389) — the scopes an envelope GENUINELY names: the
/// non-empty strings from a bare-string `"scope": "view"` or an array
/// `"scope": ["view", …]`. Junk shapes (`null`, `[]`, `""`, numbers, nested
/// objects) name NOTHING — which [`matches_scoped_query`] then resolves per
/// stance (a junk-scoped revoke leans BLANKET, a junk-scoped grant matches
/// nothing: both fail closed).
pub fn named_scopes(a: &super::Attestation) -> Vec<&str> {
    match a.attestation_envelope.get("scope") {
        Some(serde_json::Value::String(s)) if !s.is_empty() => vec![s.as_str()],
        Some(serde_json::Value::Array(items)) => items
            .iter()
            .filter_map(|v| v.as_str())
            .filter(|s| !s.is_empty())
            .collect(),
        _ => Vec::new(),
    }
}

/// v16.1.0 (CIRISPersist#389) — does the attestation's envelope genuinely name
/// `scope`? See [`named_scopes`] for the accepted shapes.
pub fn envelope_names_scope(a: &super::Attestation, scope: &str) -> bool {
    named_scopes(a).contains(&scope)
}

/// v16.1.1 (CIRISPersist#389 / CIRISServer#243) — does the attestation enter a
/// scoped consent fold for `(scope, qualifier)`? **Asymmetric on the fail
/// direction:**
///
/// - a row NAMING the scope ([`named_scopes`]) matches iff the
///   `content_class` also matches the qualifier (when given);
/// - a **NON-grant naming no genuine scope** (`revoked` / `expired` / unknown
///   stance with an absent — or junk: `null`/`[]`/`""` — scope member) is a
///   **blanket** stance: wholesale withdrawal matches EVERY scoped query (the
///   CC 4.5.13 fail-closed reading — a malformed revocation must never fail
///   toward leaving a gate open);
/// - a **grant naming no genuine scope** matches NOTHING — `granted` is the
///   sole fail-open stance and must name its scope exactly (a bare or
///   junk-scoped `consent:state:granted` never backs a scoped gate).
///
/// A row naming only DIFFERENT scope(s) matches nothing here (unrelated). The
/// qualifier check applies only to scope-naming rows: a blanket revoke has no
/// `content_class` to match and closes all classes by construction.
pub fn matches_scoped_query(a: &super::Attestation, scope: &str, qualifier: Option<&str>) -> bool {
    let named = named_scopes(a);
    if named.contains(&scope) {
        return match qualifier {
            Some(q) => a
                .attestation_envelope
                .get("content_class")
                .and_then(|v| v.as_str())
                .is_some_and(|c| c == q),
            None => true,
        };
    }
    if !named.is_empty() {
        // Genuinely names OTHER scope(s) → unrelated, never blanket.
        return false;
    }
    // Names no genuine scope: BLANKET for every non-grant stance; a grant
    // matches nothing (the only stance that fails open must be exact).
    !envelope_dimension(a).is_some_and(|d| d.starts_with("consent:state:granted"))
}

/// v36.0.0 (CIRISPersist#642) — **THE consent fold**, single-sourced.
///
/// Both trait entry points run this one body:
/// [`resolve_consent_state`](super::FederationDirectory::resolve_consent_state)
/// passes `scoped = None`, and
/// [`resolve_scoped_consent`](super::FederationDirectory::resolve_scoped_consent)
/// passes `Some((scope, qualifier))`. They used to carry two copies of the
/// filter chain and one shared ordering key; a causal plane bolted onto two
/// copies is the #663 class (one invariant, two implementations), so the copies
/// are gone.
///
/// `rows` is everything the directory holds ABOUT the target
/// ([`list_attestations_for`](super::FederationDirectory::list_attestations_for)
/// — federation tier). Four stages:
///
/// 1. **The universe.** The subject's own `consent:state:*` statements about
///    this target, *before* expiry and scope filtering. This is what a causal
///    edge resolves against — deliberately wider than the candidate set, so a
///    scoped query does not report an edge as unresolvable merely because the
///    row it names answers a different scope.
/// 2. **The candidates.** The universe, non-expired, and (scoped fold only)
///    matching [`matches_scoped_query`].
/// 3. **Two folds.** The v31.0.0 CLOCK fold ([`fold_ordering_key`]) verbatim,
///    and the CAUSAL fold ([`causal_fold_ordering_key`]) over the same
///    candidates minus the causally dead — a statement another candidate's edge
///    NAMES, or one the §6.1 retraction fold retired.
/// 4. **The ratchet** (below).
///
/// # THE CONSENT RATCHET — the causal plane may only TIGHTEN
///
/// The answer is the MORE RESTRICTIVE of the two folds ([`restriction_rank`]).
/// The causal plane can turn a `Granted` into a `Revoked`; it can never turn a
/// `Revoked` into a `Granted`. **Consent is re-opened by an affirmative later
/// grant that wins on its own signed instant — never by deleting a refusal.**
///
/// This is not belt-and-braces; it is what makes the new plane unable to open a
/// door the old one kept shut, and three distinct shapes need it:
///
/// - **a non-grant naming a non-grant.** `R(t=5)` names `R'(t=20)`, with a
///   grant at `t=10` also present: eliminating `R'` would hand the fold to the
///   grant. The ratchet keeps `Revoked`.
/// - **cycles.** `R1` names `R2` and `R2` names `R1` eliminates both; whatever
///   the survivors say, the answer cannot loosen.
/// - **a retraction of a REVOCATION.** [`crate::federation::precedence::retired_ids`]
///   admits a `withdraws` under rules 3/4 — authority a delegation walk
///   derived, not the subject's own hand. Retiring a grant closes consent;
///   retiring the subject's revocation must not re-open it.
///
/// # What is REUSED rather than rebuilt
///
/// Retraction is [`crate::federation::precedence::retired_ids`] — the
/// consolidated v36.0.0 fold (entitlement gate + CEG §6.1 precedence), called
/// here as a third delegate alongside `trust_root::tombstoned_ids` and
/// `admission::retracted_edge_ids`. Consent grows no second spelling of
/// "retracted". It reaches this fold only for composers filed against the SAME
/// target (`attested_key_id`), which is where the consent statement they retract
/// lives; a composer filed elsewhere is not in `rows` and is not applied — the
/// #686 rule, same direction (*a retraction I cannot resolve is a retraction I
/// do not apply*).
#[must_use]
pub fn fold_stance(
    rows: &[super::Attestation],
    subject_key_id: &str,
    now: chrono::DateTime<chrono::Utc>,
    scoped: Option<(&str, Option<&str>)>,
) -> super::hard_case::ConsentState {
    use std::collections::HashSet;

    // (1) the universe — the subject's own consent statements about this
    // target, pre-expiry and pre-scope (see the doc: an edge resolves here).
    let universe: Vec<&super::Attestation> = rows
        .iter()
        .filter(|a| a.attesting_key_id == subject_key_id)
        .filter(|a| {
            envelope_dimension(a).is_some_and(|d| d.starts_with(consent_dimension::STATE_PREFIX))
        })
        .collect();
    let known: HashSet<&str> = universe.iter().map(|a| a.attestation_id.as_str()).collect();

    // (2) the candidates this query folds over.
    let candidates: Vec<&super::Attestation> = universe
        .iter()
        .copied()
        .filter(|a| a.expires_at.is_none_or(|exp| exp > now))
        .filter(|a| match scoped {
            Some((scope, qualifier)) => matches_scoped_query(a, scope, qualifier),
            None => true,
        })
        .collect();

    let stance = |w: Option<&super::Attestation>| consent_state_of(w.and_then(envelope_dimension));

    // (3a) THE CLOCK FOLD — v31.0.0 verbatim, and the floor the causal plane
    // may only tighten.
    let by_clock = stance(
        candidates
            .iter()
            .copied()
            .max_by_key(|a| fold_ordering_key(a)),
    );

    // (3b) THE CAUSAL FOLD. `eliminated` is the union of the two ways a
    // statement can be causally dead: named by another candidate's consent
    // edge, or retired by the §6.1 retraction fold. Dead statements are
    // REMOVED, not out-sorted — see [`causal_rank`].
    let refs: Vec<&super::Attestation> = rows.iter().collect();
    let retired = crate::federation::precedence::retired_ids(&refs);
    let mut eliminated: HashSet<&str> = retired.iter().map(String::as_str).collect();
    for a in &candidates {
        if let ConsentCausalEdge::Names(target) = causal_edge(a) {
            eliminated.insert(target);
        }
    }
    let by_causality = stance(
        candidates
            .iter()
            .copied()
            .filter(|a| !eliminated.contains(a.attestation_id.as_str()))
            .max_by_key(|a| causal_fold_ordering_key(a, &known)),
    );

    // (4) THE RATCHET.
    if restriction_rank(by_causality) > restriction_rank(by_clock) {
        by_causality
    } else {
        by_clock
    }
}

/// v36.0.0 (CIRISPersist#642) — the PURE half of the causal-ordering witness:
/// the fold's decisions, driven directly on hand-built row sets so every arm is
/// reachable without a backend. The BACKEND half (real write path, all three
/// stores) is `bootstrap_admission::test_support::exercise_consent_causal_supersedes`.
///
/// Every expectation below is a hand-written literal. None is computed from
/// [`fold_stance`], [`causal_rank`] or [`fold_ordering_key`] — a witness that
/// derives its expectation from the code under test asserts only that the code
/// equals itself.
#[cfg(test)]
mod causal_fold_tests {
    use super::{causal_edge, fold_stance, ConsentCausalEdge};
    use crate::federation::hard_case::ConsentState;
    use crate::federation::Attestation;

    const GRANT: &str = "consent:state:granted:v1";
    const REVOKE: &str = "consent:state:revoked:v1";
    const EXPIRE: &str = "consent:state:expired:v1";
    /// The subject every fixture row is attested BY (the fold keys on it).
    const S: &str = "subject-642";

    fn at(secs: i64) -> chrono::DateTime<chrono::Utc> {
        "2026-06-01T00:00:00Z"
            .parse::<chrono::DateTime<chrono::Utc>>()
            .unwrap()
            + chrono::Duration::seconds(secs)
    }

    /// A `consent:state:*` row by `S` at `t(secs)`, with `extras` merged into
    /// the envelope (this is where `references_attestation_id` rides).
    fn row(id: &str, dim: &str, secs: i64, extras: serde_json::Value) -> Attestation {
        let mut env = serde_json::json!({ "dimension": dim });
        if let (Some(obj), Some(extra)) = (env.as_object_mut(), extras.as_object()) {
            for (k, v) in extra {
                obj.insert(k.clone(), v.clone());
            }
        }
        typed_row(id, "scores", env, secs)
    }

    /// A row of any structural type carrying `env` verbatim — the `withdraws`
    /// composers the §6.1 retraction arm needs.
    fn typed_row(id: &str, ty: &str, env: serde_json::Value, secs: i64) -> Attestation {
        serde_json::from_value(serde_json::json!({
            "attestation_id": id,
            "attesting_key_id": S,
            "attested_key_id": "target-642",
            "attestation_type": ty,
            "asserted_at": at(secs).to_rfc3339(),
            "attestation_envelope": env,
            "original_content_hash": "00",
            "scrub_signature_classical": "AA",
            "scrub_key_id": S,
            "scrub_timestamp": at(secs).to_rfc3339(),
            "persist_row_hash": "",
            "cohort_scope": "federation",
        }))
        .expect("fixture attestation deserializes")
    }

    fn names(target: &str) -> serde_json::Value {
        serde_json::json!({ "consent_supersedes": target })
    }

    /// A §6.1 structural composer. It names its target through the COMPOSER
    /// pointer (`references_attestation_id`), not through `consent_supersedes`
    /// — the two fields are the field split #642 landed, and a fixture that
    /// blurred them would witness nothing about either.
    fn withdraws(id: &str, target: &str, secs: i64) -> Attestation {
        typed_row(
            id,
            "withdraws",
            serde_json::json!({
                "references_attestation_id": target,
                "withdrawal_reason": "test",
            }),
            secs,
        )
    }

    /// `now` far past every fixture instant — nothing expires under it.
    fn now() -> chrono::DateTime<chrono::Utc> {
        at(1_000_000)
    }

    fn fold(rows: &[Attestation]) -> ConsentState {
        fold_stance(rows, S, now(), None)
    }

    /// The edge is read on NON-GRANTS only, and a pointer that is present but
    /// unusable is NOT the same as no pointer.
    #[test]
    fn causal_edge_is_asymmetric_and_never_degrades_silently() {
        // A grant's pointer is not read at all.
        assert_eq!(
            causal_edge(&row("g", GRANT, 0, names("x"))),
            ConsentCausalEdge::Absent
        );
        // Non-grants name their upstream.
        for dim in [REVOKE, EXPIRE, "consent:state:frozen:v9"] {
            assert_eq!(
                causal_edge(&row("r", dim, 0, names("x"))),
                ConsentCausalEdge::Names("x"),
                "{dim} must read its causal edge"
            );
        }
        // THE DISCRIMINATOR: a row that does not state the consent operation
        // has its key left unread, whatever it holds.
        assert_eq!(
            causal_edge(&row("r", "trust:demo:v1", 0, names("x"))),
            ConsentCausalEdge::Absent,
            "a non-consent dimension does not license this key's reading"
        );
        assert_eq!(
            causal_edge(&typed_row(
                "w",
                "withdraws",
                serde_json::json!({ "consent_supersedes": "x" }),
                0
            )),
            ConsentCausalEdge::Absent,
            "…nor does a row with no dimension at all"
        );
        // Absent / null → Absent (clock ordering, unchanged).
        assert_eq!(
            causal_edge(&row("r", REVOKE, 0, serde_json::json!({}))),
            ConsentCausalEdge::Absent
        );
        assert_eq!(
            causal_edge(&row(
                "r",
                REVOKE,
                0,
                serde_json::json!({ "consent_supersedes": serde_json::Value::Null })
            )),
            ConsentCausalEdge::Absent
        );
        // Present but unusable → Unusable, never Absent: a junk pointer must
        // not read as "this producer made no causal claim".
        for junk in [
            serde_json::json!({ "consent_supersedes": 42 }),
            serde_json::json!({ "consent_supersedes": "" }),
            serde_json::json!({ "consent_supersedes": ["x"] }),
            // A self-reference names no PRIOR statement.
            serde_json::json!({ "consent_supersedes": "r" }),
        ] {
            assert_eq!(
                causal_edge(&row("r", REVOKE, 0, junk.clone())),
                ConsentCausalEdge::Unusable,
                "unusable pointer must not degrade to Absent: {junk}"
            );
        }
    }

    /// **THE #642 WITNESS, pure form.** The clock says the grant wins; the edge
    /// says it was revoked; the clock-ordered fold LOSES.
    ///
    /// The control is the same two rows with the pointer removed — it must read
    /// `Granted`, or the leg above proves nothing about the edge.
    #[test]
    fn the_edge_beats_the_clock() {
        // The grant is minted 120s AHEAD of the revocation (inside the 300s
        // skew window `check_instant_binding` tolerates), so latest-wins picks
        // it. The revocation names it.
        let grant = row("grant-1", GRANT, 120, serde_json::json!({}));
        let revoke = row("revoke-1", REVOKE, 0, names("grant-1"));
        assert_eq!(
            fold(&[grant.clone(), revoke.clone()]),
            ConsentState::Revoked,
            "the revocation NAMES the grant it revokes — causality decides, not the clock"
        );
        // CONTROL: identical rows, no pointer → the clock genuinely favours the
        // grant, which is what makes the assertion above meaningful.
        let edgeless = row("revoke-1", REVOKE, 0, serde_json::json!({}));
        assert_eq!(
            fold(&[grant, edgeless]),
            ConsentState::Granted,
            "without the edge this is the #642 defect: a grant minted ahead out-sorts the \
             revocation that revoked it"
        );
    }

    /// The fail-closed rule: an edge naming a row this node cannot resolve does
    /// NOT degrade to clock ordering in the direction that favours the grant —
    /// and the same unresolvable pointer on a GRANT lifts nothing.
    #[test]
    fn an_unresolved_edge_fails_closed_and_only_for_non_grants() {
        let ahead = row("grant-2", GRANT, 120, serde_json::json!({}));
        // (a) the named grant is absent from this node's view.
        assert_eq!(
            fold(&[
                ahead.clone(),
                row("revoke-2", REVOKE, 0, names("never-replicated"))
            ]),
            ConsentState::Revoked,
            "an unresolvable causal claim is an INCOMPLETE view, and an incomplete view never \
             reads as a grant"
        );
        // (b) the pointer is junk — same treatment, same reason.
        assert_eq!(
            fold(&[
                ahead.clone(),
                row(
                    "revoke-2",
                    REVOKE,
                    0,
                    serde_json::json!({ "consent_supersedes": 42 })
                )
            ]),
            ConsentState::Revoked
        );
        // (c) THE ASYMMETRY: a GRANT pointing at a row nobody can resolve wins
        //     nothing. Were the lift symmetric, a bogus pointer would be a
        //     one-line consent bypass.
        //
        //     Recorded honestly: this ARM's outcome is defended twice — the
        //     ratchet reaches the same answer independently — so it does not on
        //     its own pin the asymmetry. `causal_edge_is_asymmetric_and_never_
        //     degrades_silently` does, on the function's own contract (the
        //     mutation that makes grants read their pointer reds THAT test and
        //     no fold-level leg).
        assert_eq!(
            fold(&[
                row("grant-3", GRANT, 0, names("never-replicated")),
                row("revoke-3", REVOKE, 120, serde_json::json!({})),
            ]),
            ConsentState::Revoked,
            "a grant may not lift itself above a later revocation by naming a phantom"
        );
    }

    /// THE RATCHET — the causal plane may only tighten. Three shapes that would
    /// otherwise re-open consent.
    #[test]
    fn the_causal_plane_can_never_loosen_the_answer() {
        // (a) a non-grant eliminating a non-grant. Without the ratchet the
        //     surviving pair is {grant@60, revoke@0} and the grant wins.
        assert_eq!(
            fold(&[
                row("grant-4", GRANT, 60, serde_json::json!({})),
                row("revoke-4", REVOKE, 120, serde_json::json!({})),
                row("revoke-5", REVOKE, 0, names("revoke-4")),
            ]),
            ConsentState::Revoked,
            "a back-dated revocation naming the real revocation must not hand the fold to the \
             grant underneath it"
        );
        // (b) a cycle eliminates both members; the answer still cannot loosen.
        assert_eq!(
            fold(&[
                row("grant-5", GRANT, 60, serde_json::json!({})),
                row("revoke-6", REVOKE, 120, names("revoke-7")),
                row("revoke-7", REVOKE, 130, names("revoke-6")),
            ]),
            ConsentState::Revoked
        );
        // (c) a §6.1 retraction of the REVOCATION. `withdraws` rules 3/4 derive
        //     authority from a delegation walk, not the subject's own hand —
        //     retiring a grant may close consent, retiring a refusal may not
        //     re-open it.
        assert_eq!(
            fold(&[
                row("grant-6", GRANT, 0, serde_json::json!({})),
                row("revoke-8", REVOKE, 60, serde_json::json!({})),
                withdraws("w-1", "revoke-8", 120),
            ]),
            ConsentState::Revoked,
            "consent is re-opened by an affirmative later grant, never by deleting a refusal"
        );
    }

    /// The §6.1 retraction fold REACHES the consent plane (it did not before
    /// #642): the subject's `withdraws` against its only grant leaves no live
    /// statement, and a retracted statement is not a statement.
    #[test]
    fn a_retraction_of_the_only_grant_leaves_no_statement() {
        assert_eq!(
            fold(&[
                row("grant-7", GRANT, 0, serde_json::json!({})),
                withdraws("w-2", "grant-7", 60),
            ]),
            ConsentState::Unspecified,
            "the grant was retracted through the substrate's own retraction primitive — the fold \
             must not keep answering Granted from it"
        );
    }

    /// The gate is a DOOR, not a wall: an affirmative later grant re-opens
    /// consent, exactly as it did before the causal plane existed.
    #[test]
    fn a_later_grant_still_re_opens_consent() {
        assert_eq!(
            fold(&[
                row("grant-8", GRANT, 0, serde_json::json!({})),
                row("revoke-9", REVOKE, 60, names("grant-8")),
                row("grant-9", GRANT, 120, serde_json::json!({})),
            ]),
            ConsentState::Granted
        );
    }

    /// An edge resolves against the subject's WHOLE consent history for the
    /// target, not against the scoped slice — otherwise a blanket revocation
    /// naming a grant that answers a different scope would read as an
    /// incomplete view on every scoped query and freeze the subject out of
    /// scopes it never revoked.
    #[test]
    fn the_resolution_universe_is_wider_than_the_scoped_slice() {
        let rows = [
            row(
                "grant-export",
                GRANT,
                0,
                serde_json::json!({ "scope": ["export"] }),
            ),
            // Blanket (scope-less) revocation naming the EXPORT grant.
            row("revoke-blanket", REVOKE, 60, names("grant-export")),
            row(
                "grant-view",
                GRANT,
                120,
                serde_json::json!({ "scope": ["view"] }),
            ),
        ];
        assert_eq!(
            fold_stance(&rows, S, now(), Some(("view", None))),
            ConsentState::Granted,
            "the blanket revocation's edge RESOLVES (the export grant is in the subject's \
             history), so the later view grant wins on the clock as it always did"
        );
        // …and on the export scope the revocation still closes the gate.
        assert_eq!(
            fold_stance(&rows, S, now(), Some(("export", None))),
            ConsentState::Revoked
        );
    }

    /// The fold is keyed on the SUBJECT: another key's consent rows about the
    /// same target neither vote nor resolve edges.
    #[test]
    fn another_subjects_rows_do_not_enter_the_fold() {
        let mut foreign = row("grant-foreign", GRANT, 120, serde_json::json!({}));
        foreign.attesting_key_id = "someone-else".into();
        assert_eq!(
            fold(&[foreign, row("revoke-10", REVOKE, 0, serde_json::json!({}))]),
            ConsentState::Revoked
        );
    }
}

#[cfg(test)]
mod scoped_query_tests {
    use super::{matches_scoped_query, named_scopes};

    /// A minimal attestation whose envelope carries `dimension` + optional
    /// scope/content_class JSON — the only members the predicate reads.
    /// Built via serde (no `Default` on the substrate type by design).
    fn att(dim: &str, envelope_extras: serde_json::Value) -> crate::federation::Attestation {
        let mut env = serde_json::json!({ "id": "t", "dimension": dim });
        if let (Some(obj), Some(extra)) = (env.as_object_mut(), envelope_extras.as_object()) {
            for (k, v) in extra {
                obj.insert(k.clone(), v.clone());
            }
        }
        serde_json::from_value(serde_json::json!({
            "attestation_id": "a-1",
            "attesting_key_id": "s",
            "attested_key_id": "t",
            "attestation_type": "scores",
            "asserted_at": "2026-06-01T00:00:00Z",
            "attestation_envelope": env,
            "original_content_hash": "00",
            "scrub_signature_classical": "AA",
            "scrub_key_id": "s",
            "scrub_timestamp": "2026-06-01T00:00:00Z",
            "persist_row_hash": "",
            "cohort_scope": "self",
        }))
        .expect("minimal test attestation deserializes")
    }
    const GRANT: &str = "consent:state:granted:v1";
    const REVOKE: &str = "consent:state:revoked:v1";
    const EXPIRE: &str = "consent:state:expired:v1";

    /// The five cases that DEFINE the asymmetry (CIRISServer#243).
    #[test]
    fn the_five_defining_cases() {
        // (1) scope-naming GRANT — matches on qualifier (and fails a mismatch).
        let g = att(
            GRANT,
            serde_json::json!({"scope": "view", "content_class": "medical"}),
        );
        assert!(matches_scoped_query(&g, "view", Some("medical")));
        assert!(matches_scoped_query(&g, "view", None));
        assert!(
            !matches_scoped_query(&g, "view", Some("legal")),
            "qualifier mismatch"
        );

        // (2) scope-naming REVOKE — matches.
        let r = att(
            REVOKE,
            serde_json::json!({"scope": "view", "content_class": "medical"}),
        );
        assert!(matches_scoped_query(&r, "view", Some("medical")));

        // (3) scope-less REVOKE — BLANKET: matches every scope + qualifier.
        let blanket = att(REVOKE, serde_json::json!({}));
        assert!(matches_scoped_query(&blanket, "view", Some("medical")));
        assert!(matches_scoped_query(&blanket, "export", None));

        // (4) scope-less GRANT — matches NOTHING (the sole fail-open stance
        //     must name its scope exactly).
        let bare_grant = att(GRANT, serde_json::json!({}));
        assert!(!matches_scoped_query(&bare_grant, "view", Some("medical")));
        assert!(!matches_scoped_query(&bare_grant, "view", None));

        // (5) different-scope REVOKE — unrelated: does NOT match (and is NOT
        //     blanket).
        let other = att(REVOKE, serde_json::json!({"scope": "replicate"}));
        assert!(!matches_scoped_query(&other, "view", None));
        assert!(!matches_scoped_query(&other, "view", Some("medical")));
    }

    /// The fail-closed edges AROUND the five: junk scope shapes lean blanket
    /// for non-grants and match-nothing for grants; expired/unknown stances
    /// take the non-grant (blanket) side; array shapes unify with bare.
    #[test]
    fn fail_closed_edges() {
        // Junk scope shapes on a REVOKE → still blanket (a malformed
        // revocation must never fail toward leaving the gate open).
        for junk in [
            serde_json::json!({ "scope": serde_json::Value::Null }),
            serde_json::json!({ "scope": [] }),
            serde_json::json!({ "scope": "" }),
            serde_json::json!({ "scope": 7 }),
            serde_json::json!({ "scope": [""] }),
        ] {
            let r = att(REVOKE, junk.clone());
            assert!(
                matches_scoped_query(&r, "view", Some("medical")),
                "junk-scoped revoke must be BLANKET: {junk}"
            );
            // …and the same junk on a GRANT matches nothing.
            let g = att(GRANT, junk.clone());
            assert!(
                !matches_scoped_query(&g, "view", Some("medical")),
                "junk-scoped grant must match NOTHING: {junk}"
            );
        }

        // Scope-less EXPIRED + unknown stances are non-grants → blanket.
        assert!(matches_scoped_query(
            &att(EXPIRE, serde_json::json!({})),
            "view",
            None
        ));
        assert!(matches_scoped_query(
            &att("consent:state:frozen:v9", serde_json::json!({})),
            "view",
            None
        ));

        // Array scope shape unifies with bare-string for both stances.
        let g_arr = att(GRANT, serde_json::json!({"scope": ["export", "view"]}));
        assert!(matches_scoped_query(&g_arr, "view", None));
        assert!(!matches_scoped_query(&g_arr, "delete", None));
        // An array naming only other scopes on a revoke stays unrelated.
        let r_arr = att(
            REVOKE,
            serde_json::json!({"scope": ["export", "replicate"]}),
        );
        assert!(!matches_scoped_query(&r_arr, "view", None));

        // named_scopes: junk items are dropped, genuine ones survive.
        let mixed = att(REVOKE, serde_json::json!({"scope": ["", "view", 3]}));
        assert_eq!(named_scopes(&mixed), vec!["view"]);
    }
}
