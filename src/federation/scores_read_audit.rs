//! v36.0.0 (CIRISPersist#552) — **the scores-plane READ LOG, and the
//! marginal-pinning feasibility program that keeps a future redaction honest.**
//!
//! # This module is what is left of #552 after the floor ruled
//!
//! #552 proposed a **read gate**: refuse `caller == subject` on the scores
//! plane when the caller is agent-class, so that an autonomous system could
//! not fetch its own scoreboard (CIRISOntology axiomology §6, *"a system is
//! never shown its own score"*).
//!
//! CIRISConstitution ratified **CC 3.4.5** and **refused that gate**, with four
//! independently sufficient findings recorded in-clause:
//!
//! 1. **The categories are not disjoint.** CC requires composed outputs to be
//!    filed as rows (`capacity:composite` is a normative `capacity:*`
//!    emission), so "rows yes, compositions no" has no referent.
//! 2. **The permitted read contains the withheld quantity.** `score` and
//!    `confidence` are REQUIRED envelope members and
//!    [`AttestationFilter::confidence_floor`](crate::read::AttestationFilter::confidence_floor)
//!    filters on the withheld field itself — a bounded binary search (~30
//!    queries) recovers the weight exactly.
//! 3. **Redaction and verifiability are exclusive.** A score-redacted row is
//!    unverifiable under the CC 2.6 JCS contract, and a subject that cannot
//!    verify what is filed about it is *structurally* less able to contest it.
//! 4. **The gate has no enforceable operand.** `identity_type` is self-asserted
//!    and optional, and CC 3.2 makes a steward-binding MANDATORY for every
//!    scored agent — so a class-keyed rule would not withhold the band, **it
//!    would relocate it to the agent's owner.**
//!
//! What is ratified instead is the **composition-context rule**: the
//! anti-Goodhart property binds at the **inference loop**, not the read
//! surface. Enforcement is *trace audit with provenance tagging, never
//! refusal*, and CC states explicitly that **no substrate read gate may be
//! claimed as the enforcement point**. The shipped persist read surface is
//! conformant as-is.
//!
//! So: **nothing here refuses anything.** If you are reading this module
//! looking for the place to add the caller-versus-subject check, the answer is
//! that it was tried, adjudicated, and killed four ways; the mechanism lives
//! at CIRISAgent#983, where the loop actually closes.
//!
//! # What persist owes instead, and what this module is
//!
//! Two things.
//!
//! **1. A read log at all six sites** — `list_scores` and `resolve_scores` on
//! each of memory / sqlite / postgres. [`log_scores_read`] records the caller
//! key id (or the literal [`UNAUTHENTICATED_CALLER`]), the subject filter, the
//! dimension filter, whether a `confidence_floor` was supplied, and the
//! timestamp. It is what makes trace audit *possible* at the substrate: the
//! composition-context rule is enforced by auditing traces, and a read that
//! left no trace cannot be audited.
//!
//! **2. The marginal-pinning feasibility program** ([`feasible_bands`]) as a
//! LIVE CI test rather than a one-time analysis — the AV-77 lesson kept. See
//! [`FEDERATION_READ_PREDICATE_REDACTED`] and the module's `tests` for what it
//! proves, which turned out to be sharper than the ask.
//!
//! # The log is a LOG. It is not a gate, and it must never become one
//!
//! [`log_scores_read`] returns `()`. It cannot refuse, it cannot fail, and it
//! takes no decision. That is deliberate to the point of being the design:
//! a fallible read log is a read gate wearing a different noun, and CC 3.4.5
//! forbids the substrate from being the enforcement point. If a future change
//! gives this function a `Result`, that change is re-opening a question the
//! floor has already closed.
//!
//! It also means the log **cannot be the reason a read fails**, which is the
//! property that lets it sit as the first statement in every door — ahead of
//! the argument validation, ahead of the scope resolution — so that a REFUSED
//! read is logged exactly like an admitted one. A log that only sees successful
//! reads is blind to precisely the reads an auditor most wants to see.
//!
//! # Why `tracing`, and not a table
//!
//! This is the one judgement call the ruling left open, so it is recorded here
//! rather than in a commit message. The read log is **emitted to `tracing`**,
//! not persisted to a migration-backed table. Five reasons, in descending
//! order of how much they would have hurt:
//!
//! 1. **CC's own word is "trace audit."** The ratified enforcement mechanism is
//!    *"trace audit with provenance tagging"*. A trace sink is the named
//!    artifact; a table is a different one that would then need its own
//!    argument.
//! 2. **A durable read log is a new surveillance corpus, and a worse one than
//!    the gate that was refused.** A `(caller, subject, dimension, when)` table
//!    is a permanent, queryable record of *who asked about whom* — a
//!    higher-sensitivity corpus than the scores it audits, and one that would
//!    itself fall under CC's read rules, consent, and revocation. #552 was
//!    refused for adding read-side machinery; answering it by adding
//!    strictly more invasive read-side machinery would miss the ruling.
//! 3. **It would turn every read into a write.** `list_scores` is a
//!    consumer-tier read handle. Persisting from it means a read-only replica,
//!    a read-only transaction, or a quiesced store can no longer serve one —
//!    converting an availability property into a durability requirement for a
//!    row nobody has asked to query.
//! 4. **Doctrine would make it a scored row.** Everything persist saves is a
//!    CEG-native envelope; a persisted read event is therefore an attestation
//!    about the caller. That is a scoreboard about who reads scoreboards, and
//!    reading *it* is a scores-plane read, which the log must then log.
//! 5. **Nothing in the contract reads it back.** The acceptance criteria name
//!    an entry's existence and its content. They name no read surface, no
//!    cursor, no retention policy, and no operator query — and a durable table
//!    with no reader is an unbounded write amplification on a hot path in
//!    exchange for nothing.
//!
//! The cost of this choice, stated plainly so it is not discovered later: a
//! deployment that does not configure a `tracing` subscriber retains nothing.
//! That is the correct place for the decision — retention of an audit trace is
//! an operator's policy, and persist's obligation is to *emit at every site,
//! without exception*, which is what the parity witnesses hold it to.

use chrono::{DateTime, Utc};

use crate::read::{AttestationFilter, ConfidenceBand};

/// The `tracing` target every scores-plane read log entry carries.
///
/// A dedicated target (rather than the module path) so an operator can route
/// the audit plane to its own sink with one filter directive —
/// `ciris_persist_scores_read=info` — without turning on persist's general
/// logging, and so a subscriber can *assert* it is receiving the audit plane
/// rather than inferring it from a module path that refactoring can move.
pub const SCORES_READ_LOG_TARGET: &str = "ciris_persist_scores_read";

/// **The literal recorded as the caller when there is no caller.**
///
/// The scores read surface takes `caller_occurrence_key_id: Option<String>` at
/// the FFI seam, which the wrapper flattens to `&str` with `unwrap_or_default`
/// — so an absent caller and an empty caller arrive identically, and both mean
/// *unauthenticated*: [`caller_scope_from_directory`](crate::scope::caller_scope_from_directory)
/// resolves them to the broad-tier-only scope.
///
/// **That path is SANCTIONED, not a defect.** An anonymous broad-tier read is a
/// legitimate use of the surface. What would be a defect is an anonymous read
/// that the log does not see — a read nobody can attribute is exactly the read
/// an audit exists to find — so the `None` path is logged *as*
/// `unauthenticated` rather than skipped, and
/// `tests::the_none_caller_path_is_logged_as_unauthenticated` is the witness
/// pinning that specific behaviour.
pub const UNAUTHENTICATED_CALLER: &str = "unauthenticated";

/// **RESERVED, AND UNUSED BY DEFAULT** (CIRISPersist#552, CC 3.4.5) — the
/// predicate token a deployment opting into local band redaction would declare.
///
/// # What "reserved" means here, exactly
///
/// The constant exists so the token has one spelling and one definition. **No
/// code path consults it, no read surface changes when it is present, and
/// nothing in persist emits it.** CC 3.4.5 declined to require redaction
/// (finding 3: a score-redacted row is unverifiable under the CC 2.6 JCS
/// contract, and a subject that cannot verify what is filed about it is
/// structurally less able to contest it), so wiring a redaction path here
/// would be shipping the thing the floor refused. `tests::the_redaction_token_is_reserved_and_unwired`
/// holds it to that: the token may appear in this module and nowhere else.
///
/// # What the feasibility program says about anyone who does wire it
///
/// The reservation is not neutral. Before a deployment redacts the band it must
/// answer the question CC finding 2 raised in general and
/// [`feasible_bands`] answers concretely: **do the fields that remain visible
/// jointly determine the field that was withheld?** The program's answer, over
/// the vendored CC namespace registry, is that for some families **they do**,
/// and no choice of retained fields can fix it — see [`PINNING_FAMILIES`].
/// For those families this token cannot be honoured at all, because the
/// *dimension the caller named in the filter* is already enough to pin the
/// band.
pub const FEDERATION_READ_PREDICATE_REDACTED: &str = "federation_read_predicate_redacted";

/// Which of the two scores-plane read doors emitted a log entry.
///
/// A closed enum rather than a `&str` parameter, so a seventh site cannot be
/// added with a misspelled name, and so the parity witnesses can compare a
/// value rather than a string a caller chose.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ScoresReadSite {
    /// [`FederationDirectory::list_scores`](crate::federation::FederationDirectory::list_scores)
    /// — the ordered subject+dimension timeline seek.
    ListScores,
    /// [`FederationDirectory::resolve_scores`](crate::federation::FederationDirectory::resolve_scores)
    /// — the composed verdict.
    ResolveScores,
}

impl ScoresReadSite {
    /// The token recorded in the log entry's `site` field.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            ScoresReadSite::ListScores => "list_scores",
            ScoresReadSite::ResolveScores => "resolve_scores",
        }
    }
}

/// One scores-plane read log entry, as a value.
///
/// Built by [`ScoresReadLogRecord::new`] and emitted by [`log_scores_read`].
/// It exists as a named struct rather than an inline `tracing::info!` argument
/// list for one reason: the three backends must emit **the same entry for the
/// same read**, and the only way to hold six call sites to that is for all six
/// to construct the entry through one constructor whose output a differential
/// witness can compare field by field.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ScoresReadLogRecord {
    /// Which door — [`ScoresReadSite::as_str`].
    pub site: &'static str,
    /// The caller's occurrence key id, or [`UNAUTHENTICATED_CALLER`] when the
    /// caller is absent or empty.
    pub caller_key_id: String,
    /// The filter's subject axes, canonically rendered — see
    /// [`ScoresReadLogRecord::render_subject_filter`].
    pub subject_filter: String,
    /// The filter's dimension axes, canonically rendered — see
    /// [`ScoresReadLogRecord::render_dimension_filter`].
    pub dimension_filter: String,
    /// Whether the caller supplied a
    /// [`confidence_floor`](crate::read::AttestationFilter::confidence_floor).
    ///
    /// **The flag, never the value.** CC 3.4.5 finding 2 is that
    /// `confidence_floor` is a ~30-query binary-search oracle over the withheld
    /// weight; recording the successive *values* would reproduce that oracle
    /// inside the audit log, which is a strictly worse place for it to live
    /// than the read surface (the log outlives the query). Recording the flag
    /// is what an auditor actually needs — a binary search is visible as a run
    /// of floor-bearing reads from one caller against one subject, and that
    /// pattern is exactly what these five fields make legible.
    pub confidence_floor_supplied: bool,
    /// When the read was served.
    pub at: DateTime<Utc>,
}

impl ScoresReadLogRecord {
    /// Build the entry for one read.
    ///
    /// `caller_occurrence_key_id` is the raw value the door received; empty
    /// becomes [`UNAUTHENTICATED_CALLER`] here, once, so no site can spell that
    /// substitution differently.
    #[must_use]
    pub fn new(
        site: ScoresReadSite,
        caller_occurrence_key_id: &str,
        filter: &AttestationFilter,
        at: DateTime<Utc>,
    ) -> Self {
        let caller = if caller_occurrence_key_id.trim().is_empty() {
            UNAUTHENTICATED_CALLER.to_owned()
        } else {
            caller_occurrence_key_id.to_owned()
        };
        ScoresReadLogRecord {
            site: site.as_str(),
            caller_key_id: caller,
            subject_filter: Self::render_subject_filter(filter),
            dimension_filter: Self::render_dimension_filter(filter),
            confidence_floor_supplied: filter.confidence_floor.is_some(),
            at,
        }
    }

    /// **The subject filter, canonically.**
    ///
    /// The scores plane has two subject axes and an auditor needs both:
    /// `subject_key_id` is the V106 `attestation_subjects` projection axis (the
    /// key a row is *about*), and `attested_key_id` / `attested_key_ids` is the
    /// key that was attested. `mem_scores_row_matches` and its SQL twins apply
    /// them independently, so recording only one would leave a whole shape of
    /// self-read invisible to the audit.
    ///
    /// Rendered as `subject=<id|->;attested=<id,id|->` with the attested set
    /// **sorted and deduplicated**, so that two callers issuing the same query
    /// with the ids in different orders produce byte-identical entries — which
    /// is what lets the three-backend differential witness compare literals,
    /// and what lets an auditor group a binary-search run by its subject.
    #[must_use]
    pub fn render_subject_filter(filter: &AttestationFilter) -> String {
        let subject = filter.subject_key_id.as_deref().unwrap_or("-");
        let mut attested: Vec<&str> = filter
            .attested_key_id
            .as_deref()
            .into_iter()
            .chain(filter.attested_key_ids.iter().map(String::as_str))
            .collect();
        attested.sort_unstable();
        attested.dedup();
        let attested = if attested.is_empty() {
            "-".to_owned()
        } else {
            attested.join(",")
        };
        format!("subject={subject};attested={attested}")
    }

    /// **The dimension filter, canonically.**
    ///
    /// Rendered as `exact=<dim|->;prefixes=<p,p|->`, prefixes sorted and
    /// deduplicated for the same reason [`Self::render_subject_filter`] sorts.
    ///
    /// The dimension is the axis that makes a read log worth keeping rather
    /// than a formality: [`feasible_bands`] shows that for a single-polarity
    /// family the *named dimension alone* determines the band, so "which
    /// dimension did this caller ask about" is, for those families, the same
    /// question as "what did this caller learn".
    #[must_use]
    pub fn render_dimension_filter(filter: &AttestationFilter) -> String {
        let exact = filter.dimension_exact.as_deref().unwrap_or("-");
        let mut prefixes: Vec<&str> = filter
            .dimension_prefixes
            .iter()
            .map(String::as_str)
            .collect();
        prefixes.sort_unstable();
        prefixes.dedup();
        let prefixes = if prefixes.is_empty() {
            "-".to_owned()
        } else {
            prefixes.join(",")
        };
        format!("exact={exact};prefixes={prefixes}")
    }
}

/// **Emit one scores-plane read log entry.** The call every one of the six
/// doors makes, as its first statement.
///
/// Returns `()` and cannot fail — see the module docs on why a fallible read
/// log would be a read gate under another name, which CC 3.4.5 forbids the
/// substrate from being.
///
/// Placed **first** in each door, ahead of argument validation and ahead of
/// [`caller_scope_from_directory`](crate::scope::caller_scope_from_directory),
/// so that a read refused for a bad `limit`, an unsupported cursor version, or
/// an unresolvable caller is logged exactly like one that succeeds. The three
/// backends validate in slightly different orders; making this the first
/// statement everywhere means the log's position is identical regardless, which
/// is what the differential witness pins.
pub fn log_scores_read(
    site: ScoresReadSite,
    caller_occurrence_key_id: &str,
    filter: &AttestationFilter,
) {
    let record = ScoresReadLogRecord::new(site, caller_occurrence_key_id, filter, Utc::now());
    tracing::info!(
        target: SCORES_READ_LOG_TARGET,
        site = record.site,
        caller_key_id = %record.caller_key_id,
        subject_filter = %record.subject_filter,
        dimension_filter = %record.dimension_filter,
        confidence_floor_supplied = record.confidence_floor_supplied,
        at = %record.at.to_rfc3339(),
        "scores-plane read",
    );
}

// ─────────────────────────────────────────────────────────────────────────
//  The marginal-pinning feasibility program (CC 3.4.5 acceptance criterion 3)
// ─────────────────────────────────────────────────────────────────────────

/// **The declared value range of one dimension family's `score`**, derived from
/// the `polarity` column CC 3.1 publishes for it.
///
/// This is the *declared* range, and the distinction is load-bearing: persist
/// does **not** enforce it. There is no score-range refusal at admission — see
/// the note on [`PINNING_FAMILIES`] — so this table says what CC says a leaf
/// may carry, not what persist would refuse. For the feasibility program that
/// is the correct premise (the program asks what a *conforming* corpus can
/// look like), and it is also the program's sharpest limitation, reported as
/// such rather than buried.
#[derive(Debug, Clone, Copy, PartialEq)]
pub struct DeclaredRange {
    /// Inclusive lower bound on `score`.
    pub lo: f64,
    /// Inclusive upper bound on `score`.
    pub hi: f64,
    /// When true the lower bound is **open** — `score > lo`, not `>=`. Used by
    /// `positive-only`, whose whole content is that zero is not a value.
    pub lo_open: bool,
}

/// **The CC polarity vocabulary, as a total map to declared ranges.**
///
/// Every distinct `polarity` string in the vendored
/// `namespace/namespace_registry.json` must appear here, and
/// `tests::every_declared_polarity_in_the_vendored_registry_is_classified`
/// fails naming the label on anything that does not. **There is no fallback
/// arm.** That absence is the mechanism CC 3.4.5 asked for when it said a
/// future single-polarity leaf must *fail the build, not review*: a CC release
/// that introduces a new polarity word stops persist's build until a human maps
/// it, and mapping it is exactly the moment to notice that the new leaf pins.
///
/// The ranges are read off the label text, which is self-describing, and are
/// hand-written literals — never derived from the classifier they are used to
/// test.
///
/// The four non-numeric labels are mapped to the **widest** range rather than
/// skipped. Widening is the sound direction: a larger feasible score set can
/// only make the feasible *band* set larger, so an over-wide range can never
/// manufacture a false "not pinned" claim about a family whose real range is
/// narrower — it can only fail to notice one. A skip, by contrast, would make
/// the family invisible, which is the AV-77 shape this program exists to avoid.
pub const POLARITY_RANGES: &[(&str, DeclaredRange)] = &[
    // The CC 4.4.2 default: score spans both signs.
    (
        "signed",
        DeclaredRange {
            lo: -1.0,
            hi: 1.0,
            lo_open: false,
        },
    ),
    // All-must-hold AND semantics; folded by MIN.
    (
        "boolean-via-score",
        DeclaredRange {
            lo: 0.0,
            hi: 1.0,
            lo_open: false,
        },
    ),
    // SINGLE POLARITY — zero is not a value ("positive-only").
    (
        "positive-only",
        DeclaredRange {
            lo: 0.0,
            hi: 1.0,
            lo_open: true,
        },
    ),
    // SINGLE POLARITY, single point.
    (
        "-1 only",
        DeclaredRange {
            lo: -1.0,
            hi: -1.0,
            lo_open: false,
        },
    ),
    // SINGLE POLARITY, two points; the interval between them is a sound
    // widening of the two-point set.
    (
        "-1 / -0.5 only",
        DeclaredRange {
            lo: -1.0,
            hi: -0.5,
            lo_open: false,
        },
    ),
    // ── labels that declare no numeric range: widened to `signed` ──
    // `accord:*` defers to a CC clause rather than stating a range.
    (
        "see CC 3.4.1",
        DeclaredRange {
            lo: -1.0,
            hi: 1.0,
            lo_open: false,
        },
    ),
    // A restricted boolean; widened past its own restriction, deliberately.
    (
        "boolean-via-score; Indeterminate allowed → RESTRICTED",
        DeclaredRange {
            lo: -1.0,
            hi: 1.0,
            lo_open: false,
        },
    ),
    // `consent:{kind}` — the range is per-leaf, so no family-level bound holds.
    (
        "per-leaf (CC 3.3.1)",
        DeclaredRange {
            lo: -1.0,
            hi: 1.0,
            lo_open: false,
        },
    ),
    // `locality:decision:{scale}`, `partner_role:{role}` — a label set, not a
    // scale; every numeric encoding of it fits inside the widest range.
    (
        "enumerated",
        DeclaredRange {
            lo: -1.0,
            hi: 1.0,
            lo_open: false,
        },
    ),
];

/// **The families for which the reserved redaction token cannot be honoured**
/// — the feasibility program's headline result, as a hand-written literal.
///
/// For each of these, [`feasible_bands`] returns a set of **cardinality 1** in
/// at least one reachable cell: the band is *fully determined* by fields the
/// caller already has, so withholding it withholds nothing. The kappa-edge
/// condition, on persist's own wire.
///
/// **What determines it is the dimension the caller named.** These three
/// families declare a single-signed range (`-1 only`, `-1 / -0.5 only`), so
/// every conforming corpus folds to a negative aggregate, so the band is
/// `Refuted` before a single row is read. No choice of retained fields repairs
/// that — the caller supplied the pinning input themselves, in the filter. This
/// is CC 3.4.5 finding 2 ("the permitted read contains the withheld quantity")
/// arriving by a second, independent route the clause did not name.
///
/// # The one thing standing between the `signed` fold and the same result, and
/// why it is thinner than it looks
///
/// Under the `signed` fold these families pin **only if confidence is bounded
/// away from zero**; persist permits `confidence = 0`, which drags the product
/// `score × confidence` to exactly `0.0` and admits `Weak` as a second feasible
/// band. That is not a designed protection. It is an unenforced gap — persist
/// declares no range for `score` or `confidence` anywhere and refuses neither.
/// Under the `boolean-via-score` fold, which does not multiply by confidence at
/// all, these families pin **today**.
///
/// **And the signed fold's exemption is measure-zero.** `confidence = 0.0`
/// EXACTLY is the only value that unpins it: a 200k-sample sweep drawing
/// confidences from `uniform(0, 1)` returns `{Refuted}` alone in every cell,
/// because the escape depends on hitting a single point of a continuum. So the
/// honest reading of the census is that these three families are pinned under
/// the boolean fold outright and pinned under the signed fold for every corpus
/// an operator will actually see — and the exemption that keeps them formally
/// unpinned is a zero-confidence row, which is to say a row asserting nothing.
///
/// `tests::the_signed_fold_escape_hatch_is_a_zero_confidence_row` pins that
/// dependency so it cannot be closed by accident: the obvious hardening
/// (refuse `confidence <= 0` at admission) would move these families to pinned
/// under both folds, and that test is what makes the consequence visible at the
/// moment someone writes the check rather than afterwards.
pub const PINNING_FAMILIES: &[&str] = &[
    "prohibited:{category}",
    "revocation:{entity_type}:{reason}",
    "rollback_detected:{revision_field}",
];

/// Which fold a feasibility question is asked under.
///
/// Not derived from the family: [`resolve_scores`](crate::federation::FederationDirectory::resolve_scores)
/// takes the composition `policy` from the **caller**, and
/// `federation::scores::resolve_policy` maps everything except an explicit
/// boolean-min id to the signed mean. So a caller may ask for either fold over
/// any family, and the program must answer for both — which is why
/// `boolean-via-score` families appear under [`Fold::SignedMean`] below and
/// `signed` families appear under [`Fold::BooleanMin`].
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Fold {
    /// `mean(score × confidence)` — CC 4.4.2 default.
    SignedMean,
    /// `min(score)` — boolean-via-score.
    BooleanMin,
}

/// The retained (permitted) marginals a redacted view would still expose — one
/// cell of the feasibility program's domain.
///
/// These are exactly [`ComposedVerdict`](crate::read::ComposedVerdict)'s
/// members other than `band`, restricted to the ones that enter
/// `federation::scores::classify`. `age_of_head` and `policy_applied` are
/// retained too but do not reach the classifier, so they cannot narrow the
/// feasible set and are omitted rather than carried as decoration.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub struct RetainedCell {
    /// `ComposedVerdict::contributor_count`.
    pub contributor_count: u32,
    /// `ComposedVerdict::open_contradictions` — `None` when the field is
    /// **withheld** rather than retained, in which case every value of it is
    /// feasible and the feasible band set is the union over all of them.
    ///
    /// # This field being withheld is the program's first result
    ///
    /// It is not a modelling convenience. Run the program with
    /// `open_contradictions` RETAINED and 99 of the registry's 114 families
    /// pin: under the `boolean-via-score` fold, a contradiction is only
    /// possible when the heads disagree in sign, which forces `min(score)`
    /// below the `>= 1.0` threshold, so **`open_contradictions > 0` alone
    /// determines `band == Contested`** — for any family, at any contributor
    /// count, with or without diversity.
    ///
    /// So a redacted view that withheld the band and kept the contradiction
    /// count would be withholding nothing at all, for almost the whole
    /// namespace. Withholding it too is the minimum that makes redaction mean
    /// anything, and that is what [`FEDERATION_READ_PREDICATE_REDACTED`]
    /// documents as the retained set. `tests::retaining_the_contradiction_count_pins_almost_the_whole_registry`
    /// keeps this paragraph honest by measuring both ways.
    pub open_contradictions: Option<u32>,
    /// Whether `ComposedVerdict::witness_diversity` is present and positive.
    pub diversity_established: bool,
}

/// **The feasibility program**: which [`ConfidenceBand`]s remain possible once
/// the retained marginals are fixed and the withheld quantities are free.
///
/// # The formulation, and which half of it is CC's
///
/// CC 3.4.5's acceptance criterion is *"feasible band set cardinality ≥ 2 over
/// retained-field marginals under declared polarity/range"*. That fixes the
/// **question** — is the withheld band determined by what is retained? — and
/// the **pass condition** — at least two bands must remain possible. It does
/// not fix the numeric range each CC polarity label implies, and the vendored
/// registry carries the labels but no bounds column. [`POLARITY_RANGES`] is
/// therefore persist's reading of CC's label vocabulary, marked as such.
///
/// # It is a feasibility enumeration, not a simplex call
///
/// The decision variables are the withheld per-head values; the constraints are
/// the declared range and the retained marginals. Because
/// `federation::scores::classify` is a **step function** whose only breakpoints
/// are `{0, 0.33, 0.66, 1.0}` and `open_contradictions ∈ {0, ≥1}`, the feasible
/// region's images under it are reached at a finite lattice of head vectors, so
/// the program is solved by enumerating that lattice against the **real**
/// classifier rather than a re-implementation of it.
///
/// **The soundness direction matters and runs the safe way.** Every band this
/// function returns is *certified reachable* — it exhibits a concrete head
/// vector producing it. So `len() >= 2` is a **constructive proof** of
/// non-pinning: two witnesses, two bands, nothing withheld is determined.
/// A returned `len() == 1` is a *candidate* pinning rather than a proof, since
/// a coarse lattice can only under-count. Under-counting reds the census; it
/// cannot green it. A check whose error mode is a false alarm is the right one
/// to put in CI.
#[must_use]
pub fn feasible_bands(
    fold: Fold,
    range: DeclaredRange,
    cell: RetainedCell,
) -> std::collections::BTreeSet<&'static str> {
    use std::collections::BTreeSet;
    let mut out: BTreeSet<&'static str> = BTreeSet::new();
    if cell.contributor_count == 0 {
        // No withheld quantity exists to be pinned: an empty fold is
        // `InsufficientWitnesses` by construction, and saying so reveals
        // nothing about rows there are none of. Excluded from the domain
        // rather than reported as a pin.
        return out;
    }
    let n = cell.contributor_count as usize;
    // The breakpoint lattice: `classify`'s thresholds, the range endpoints, and
    // the sign-change point. Hand-written; not derived from the classifier.
    let candidates: Vec<f64> = {
        let mut v = vec![
            -1.0, -0.5, -0.33, 0.0, 0.33, 0.5, 0.66, 0.9, 1.0, range.lo, range.hi,
        ];
        v.retain(|s| {
            *s >= range.lo
                && *s <= range.hi
                && !(range.lo_open && (*s - range.lo).abs() < f64::EPSILON)
        });
        v.sort_by(|a, b| a.partial_cmp(b).expect("finite lattice"));
        v.dedup_by(|a, b| (*a - *b).abs() < f64::EPSILON);
        v
    };
    // Confidence lattice — `0.0` is included because persist admits it (see
    // `PINNING_FAMILIES`); it is the whole of the signed fold's escape hatch.
    let confidences: [f64; 3] = [0.0, 0.5, 1.0];
    let diversity = if cell.diversity_established {
        Some(1.0_f64)
    } else {
        None
    };

    // Enumerate head vectors over the lattice. `n` is capped at 3 because
    // `classify`'s only contributor-count breakpoint is `>= 3`, so every larger
    // count is behaviourally identical to 3.
    let n = n.min(3);
    let mut idx = vec![0_usize; n];
    loop {
        let scores: Vec<f64> = idx.iter().map(|i| candidates[*i]).collect();
        match fold {
            Fold::SignedMean => {
                let mut cidx = vec![0_usize; n];
                loop {
                    let values: Vec<f64> = scores
                        .iter()
                        .zip(cidx.iter())
                        .map(|(s, c)| s * confidences[*c])
                        .collect();
                    let aggregate = values.iter().sum::<f64>() / values.len() as f64;
                    let believed_positive = aggregate >= 0.0;
                    let k = values
                        .iter()
                        .filter(|v| ((**v < 0.0) == believed_positive) && **v != 0.0)
                        .count() as u32;
                    if cell.open_contradictions.is_none_or(|want| want == k) {
                        out.insert(band_token(crate::federation::scores::classify_for_audit(
                            true,
                            cell.contributor_count,
                            aggregate,
                            k,
                            diversity,
                        )));
                    }
                    if !odometer(&mut cidx, confidences.len()) {
                        break;
                    }
                }
            }
            Fold::BooleanMin => {
                let aggregate = scores.iter().cloned().fold(f64::INFINITY, f64::min);
                // The global head is the latest-asserted head, which the caller
                // does not constrain — so every head is a possible global head.
                for head in &scores {
                    let believed_positive = *head > 0.0;
                    let k = scores
                        .iter()
                        .filter(|v| (**v > 0.0) != believed_positive)
                        .count() as u32;
                    if cell.open_contradictions.is_none_or(|want| want == k) {
                        out.insert(band_token(crate::federation::scores::classify_for_audit(
                            false,
                            cell.contributor_count,
                            aggregate,
                            k,
                            diversity,
                        )));
                    }
                }
            }
        }
        if !odometer(&mut idx, candidates.len()) {
            break;
        }
    }
    out
}

/// Advance a mixed-radix counter; `false` when it wraps.
fn odometer(idx: &mut [usize], radix: usize) -> bool {
    for slot in idx.iter_mut() {
        *slot += 1;
        if *slot < radix {
            return true;
        }
        *slot = 0;
    }
    false
}

/// The declared range for a family's polarity label, or `None` when the label
/// is not in [`POLARITY_RANGES`] — which is a build failure, not a fallback.
#[must_use]
pub fn range_for_polarity(label: &str) -> Option<DeclaredRange> {
    POLARITY_RANGES
        .iter()
        .find(|(l, _)| *l == label)
        .map(|(_, r)| *r)
}

/// Every `(prefix, polarity)` pair in the vendored CC namespace registry.
///
/// Parsed here rather than through
/// [`namespace::registry`](crate::federation::namespace::registry) because that
/// module's `RawFamily` deliberately deserializes `reserved_rule` and ignores
/// every other column — the polarity axis is this module's concern, and adding
/// it to a shared type to serve one caller is the second-spelling shape persist
/// spent v31 removing.
#[must_use]
pub fn vendored_family_polarities() -> Vec<(String, String)> {
    #[derive(serde::Deserialize)]
    struct Manifest {
        families: Vec<Family>,
    }
    #[derive(serde::Deserialize)]
    struct Family {
        prefix: String,
        #[serde(default)]
        polarity: Option<String>,
    }
    const REGISTRY_JSON: &str = include_str!("namespace/namespace_registry.json");
    let m: Manifest =
        serde_json::from_str(REGISTRY_JSON).expect("vendored namespace_registry.json parses");
    m.families
        .into_iter()
        .filter_map(|f| f.polarity.map(|p| (f.prefix, p)))
        .collect()
}

/// Bands, as the stable audit tokens the census literals are written in.
///
/// **Matched exhaustively, with no wildcard arm, on purpose.**
/// [`ConfidenceBand`] is `#[non_exhaustive]`, which binds downstream crates but
/// not this one — so a seventh band added to the enum is a compile error *here*
/// rather than a silent `"UNKNOWN_BAND"` flowing into the pinning census, where
/// it would read as a distinct feasible band and could turn a genuine pin
/// (cardinality 1) into a false all-clear (cardinality 2). Failing the build is
/// the direction this census must fail in.
#[must_use]
pub const fn band_token(band: ConfidenceBand) -> &'static str {
    match band {
        ConfidenceBand::Refuted => "Refuted",
        ConfidenceBand::Contested => "Contested",
        ConfidenceBand::Weak => "Weak",
        ConfidenceBand::Supported => "Supported",
        ConfidenceBand::WellEstablished => "WellEstablished",
        ConfidenceBand::InsufficientWitnesses => "InsufficientWitnesses",
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::federation::FederationDirectory;
    use std::collections::{BTreeMap, BTreeSet};
    use std::sync::{Arc, Mutex};

    // ─────────────────────────────────────────────────────────────────
    //  The tracing capture harness
    //
    //  This repo had no test that observes a `tracing` event before
    //  #552 — `tracing-subscriber` sat in `[dev-dependencies]` imported
    //  by nothing. The obvious alternative was a test-only sink inside
    //  `log_scores_read` that tests drain directly, and it is exactly
    //  the shape this repo keeps paying for: a double that observes the
    //  RECORD while the real emit goes unobserved, so deleting the
    //  `tracing::info!` and keeping the sink append stays green. So the
    //  witness subscribes to the real dispatcher and reads the real
    //  event. `the_witness_observes_the_tracing_emit_itself` proves the
    //  harness can see an event of the same shape, which is what makes a
    //  silent capture failure distinguishable from a genuinely absent
    //  log entry.
    // ─────────────────────────────────────────────────────────────────

    /// One captured event, as `field -> rendered value`.
    type Captured = BTreeMap<String, String>;

    #[derive(Default)]
    struct FieldVisitor(Captured);

    impl tracing::field::Visit for FieldVisitor {
        fn record_debug(&mut self, field: &tracing::field::Field, value: &dyn std::fmt::Debug) {
            self.0.insert(field.name().to_owned(), format!("{value:?}"));
        }
        // `record_str` and `record_bool` MUST be implemented rather than left
        // to their defaults: the default forwards to `record_debug`, which
        // renders a `&str` WITH surrounding quotes, and the witness literals
        // below are the unquoted values an operator's sink would see.
        fn record_str(&mut self, field: &tracing::field::Field, value: &str) {
            self.0.insert(field.name().to_owned(), value.to_owned());
        }
        fn record_bool(&mut self, field: &tracing::field::Field, value: bool) {
            self.0.insert(field.name().to_owned(), value.to_string());
        }
    }

    struct CaptureSubscriber {
        events: Arc<Mutex<Vec<Captured>>>,
    }

    impl tracing::Subscriber for CaptureSubscriber {
        fn enabled(&self, meta: &tracing::Metadata<'_>) -> bool {
            meta.target() == SCORES_READ_LOG_TARGET
        }
        fn new_span(&self, _: &tracing::span::Attributes<'_>) -> tracing::span::Id {
            tracing::span::Id::from_u64(1)
        }
        fn record(&self, _: &tracing::span::Id, _: &tracing::span::Record<'_>) {}
        fn record_follows_from(&self, _: &tracing::span::Id, _: &tracing::span::Id) {}
        fn event(&self, event: &tracing::Event<'_>) {
            if event.metadata().target() != SCORES_READ_LOG_TARGET {
                return;
            }
            let mut v = FieldVisitor::default();
            event.record(&mut v);
            self.events.lock().expect("capture lock").push(v.0);
        }
        fn enter(&self, _: &tracing::span::Id) {}
        fn exit(&self, _: &tracing::span::Id) {}
    }

    /// Run `f` with the capture subscriber installed on THIS thread and return
    /// the scores-plane events it emitted, with the non-deterministic `at`
    /// field lifted out (returned separately so it can still be checked).
    fn capture<F: FnOnce()>(f: F) -> (Vec<Captured>, Vec<String>) {
        let events: Arc<Mutex<Vec<Captured>>> = Arc::new(Mutex::new(Vec::new()));
        let sub = CaptureSubscriber {
            events: Arc::clone(&events),
        };
        tracing::subscriber::with_default(sub, f);
        let raw = events.lock().expect("capture lock").clone();
        let mut stamps = Vec::new();
        let stripped = raw
            .into_iter()
            .map(|mut e| {
                stamps.push(e.remove("at").unwrap_or_default());
                e
            })
            .collect();
        (stripped, stamps)
    }

    /// A current-thread runtime, built INSIDE the capture closure so every
    /// `.await` in the exercised door runs on the thread holding the
    /// subscriber's thread-local dispatcher. The three doors are careful to
    /// emit before any `spawn_blocking` (sqlite) or pool checkout (postgres)
    /// precisely because the log is the first statement.
    fn block_on<F: std::future::Future>(fut: F) -> F::Output {
        tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()
            .expect("current-thread runtime")
            .block_on(fut)
    }

    // ─────────────────────────────────────────────────────────────────
    //  The probe, and the hand-written witness literals
    // ─────────────────────────────────────────────────────────────────

    /// The `list_scores` probe filter. Deliberately exercises BOTH subject
    /// axes, BOTH dimension axes, duplicate ids across the singular and set
    /// forms, and an unsorted prefix list — so the canonical rendering is
    /// actually under test rather than incidentally correct.
    fn probe_filter() -> AttestationFilter {
        AttestationFilter {
            subject_key_id: Some("subject_key_552".to_owned()),
            attested_key_id: Some("alpha_key".to_owned()),
            attested_key_ids: vec![
                "zeta_key".to_owned(),
                "alpha_key".to_owned(),
                "zeta_key".to_owned(),
            ],
            dimension_exact: Some("capacity:composite:v1".to_owned()),
            dimension_prefixes: vec!["trust:".to_owned(), "capacity:".to_owned()],
            confidence_floor: Some(0.25),
            ..AttestationFilter::default()
        }
    }

    /// HAND-WRITTEN. Never derived from `ScoresReadLogRecord`.
    fn expected_list_event() -> Captured {
        [
            ("message", "scores-plane read"),
            ("site", "list_scores"),
            ("caller_key_id", "caller_key_552"),
            (
                "subject_filter",
                "subject=subject_key_552;attested=alpha_key,zeta_key",
            ),
            (
                "dimension_filter",
                "exact=capacity:composite:v1;prefixes=capacity:,trust:",
            ),
            ("confidence_floor_supplied", "true"),
        ]
        .into_iter()
        .map(|(k, v)| (k.to_owned(), v.to_owned()))
        .collect()
    }

    /// HAND-WRITTEN. The `None`-caller (unauthenticated) `resolve_scores`
    /// entry, over a bare filter.
    fn expected_resolve_unauthenticated_event() -> Captured {
        [
            ("message", "scores-plane read"),
            ("site", "resolve_scores"),
            ("caller_key_id", "unauthenticated"),
            ("subject_filter", "subject=-;attested=-"),
            ("dimension_filter", "exact=-;prefixes=-"),
            ("confidence_floor_supplied", "false"),
        ]
        .into_iter()
        .map(|(k, v)| (k.to_owned(), v.to_owned()))
        .collect()
    }

    /// Drive both scores-plane doors on one backend. Results are discarded on
    /// purpose: what the read RETURNS is another surface's contract, and the
    /// log must be emitted whether the read succeeds, finds nothing, or is
    /// refused.
    async fn exercise(dir: &dyn FederationDirectory) {
        let _ = dir
            .list_scores("caller_key_552", probe_filter(), None, 10)
            .await;
        let _ = dir
            .resolve_scores(
                "",
                AttestationFilter::default(),
                "cc-4.4.2-signed-mean".to_owned(),
                false,
            )
            .await;
    }

    /// The per-backend assertion: two entries, in door order, byte-equal to
    /// the literals — and both timestamps parse as RFC-3339.
    fn assert_backend_entries(tag: &str, events: &[Captured], stamps: &[String]) {
        assert_eq!(
            events.len(),
            2,
            "({tag}) the scores plane must emit exactly one log entry per read \
             at each of its two doors; got {events:#?}"
        );
        assert_eq!(
            events[0],
            expected_list_event(),
            "({tag}) list_scores entry"
        );
        assert_eq!(
            events[1],
            expected_resolve_unauthenticated_event(),
            "({tag}) resolve_scores entry"
        );
        for s in stamps {
            chrono::DateTime::parse_from_rfc3339(s)
                .unwrap_or_else(|e| panic!("({tag}) log timestamp {s:?} is not RFC-3339: {e}"));
        }
    }

    // ── the three-backend differential parity witnesses ──────────────

    #[test]
    fn scores_read_log_parity_memory() {
        let (events, stamps) = capture(|| {
            let dir = crate::store::MemoryBackend::new();
            block_on(exercise(&dir));
        });
        assert_backend_entries("mem", &events, &stamps);
    }

    #[cfg(feature = "sqlite")]
    #[test]
    fn scores_read_log_parity_sqlite() {
        let (events, stamps) = capture(|| {
            block_on(async {
                use crate::store::Backend as _;
                let dir = crate::store::SqliteBackend::open_in_memory()
                    .await
                    .expect("open sqlite");
                dir.run_migrations().await.expect("migrations");
                exercise(&dir).await;
            });
        });
        assert_backend_entries("sq", &events, &stamps);
    }

    #[cfg(feature = "postgres")]
    #[test]
    #[serial_test::serial(postgres)]
    fn scores_read_log_parity_postgres() {
        // Resolved OUTSIDE the capture closure: `test_pg::dsn()` drives its own
        // runtime, and nesting one inside `block_on` would panic.
        let Some(dsn) = crate::test_pg::dsn() else {
            eprintln!("scores_read_log_parity_postgres skipped: CIRIS_PERSIST_TEST_PG_URL unset");
            return;
        };
        let (events, stamps) = capture(|| {
            block_on(async {
                use crate::store::Backend as _;
                let dir = crate::store::PostgresBackend::connect(&dsn)
                    .await
                    .expect("connect postgres");
                dir.run_migrations().await.expect("migrations");
                exercise(&dir).await;
            });
        });
        assert_backend_entries("pg", &events, &stamps);
    }

    /// **The differential itself**, in one process: the same two reads against
    /// memory and sqlite must produce byte-identical log entries.
    ///
    /// The three per-backend witnesses above each compare against the same
    /// literal, which already forces agreement; this one fails with a diff
    /// naming the two backends rather than three separate mismatches against a
    /// constant, which is the message an operator can act on.
    #[cfg(feature = "sqlite")]
    #[test]
    fn scores_read_log_is_identical_across_backends() {
        let (mem, _) = capture(|| {
            let dir = crate::store::MemoryBackend::new();
            block_on(exercise(&dir));
        });
        let (sq, _) = capture(|| {
            block_on(async {
                use crate::store::Backend as _;
                let dir = crate::store::SqliteBackend::open_in_memory()
                    .await
                    .expect("open sqlite");
                dir.run_migrations().await.expect("migrations");
                exercise(&dir).await;
            });
        });
        assert_eq!(
            mem, sq,
            "memory and sqlite disagree about what a scores-plane read logs"
        );
    }

    /// **Acceptance criterion 3: the `None`-caller path is logged AS
    /// unauthenticated, not skipped.**
    ///
    /// Separated from the parity witnesses because it is the specific
    /// obligation the ruling named, and because it is the one a well-meaning
    /// future change is most likely to break — "there is no caller, so there
    /// is nothing to log" is a plausible-sounding sentence and it is wrong.
    /// A read nobody can attribute is exactly the read an audit exists to find.
    #[test]
    fn the_none_caller_path_is_logged_as_unauthenticated() {
        let (events, _) = capture(|| {
            let dir = crate::store::MemoryBackend::new();
            block_on(async {
                // The FFI wrapper's `caller_occurrence_key_id: Option<String>`
                // reaches the door as `unwrap_or_default()` — the empty string.
                let _ = dir
                    .list_scores("", AttestationFilter::default(), None, 10)
                    .await;
                // Whitespace is the same absence wearing a disguise.
                let _ = dir
                    .resolve_scores(
                        "   ",
                        AttestationFilter::default(),
                        "cc-4.4.2-signed-mean".to_owned(),
                        false,
                    )
                    .await;
            });
        });
        assert_eq!(events.len(), 2, "both anonymous reads must be logged");
        for (i, e) in events.iter().enumerate() {
            assert_eq!(
                e.get("caller_key_id").map(String::as_str),
                Some("unauthenticated"),
                "anonymous read {i} must be logged AS `unauthenticated`, not skipped \
                 and not logged with an empty caller: {e:#?}"
            );
        }
    }

    /// The harness can see an event of exactly the shape the doors emit, so a
    /// zero-event result from any witness above means "no entry was logged"
    /// and never "the capture silently failed".
    #[test]
    fn the_witness_observes_the_tracing_emit_itself() {
        let (events, stamps) = capture(|| {
            log_scores_read(
                ScoresReadSite::ListScores,
                "caller_key_552",
                &probe_filter(),
            );
        });
        assert_eq!(events.len(), 1);
        assert_eq!(events[0], expected_list_event());
        assert_eq!(stamps.len(), 1);
        // And it does NOT capture the rest of persist's logging.
        let (other, _) = capture(|| {
            tracing::info!(target: "some_other_plane", "not the scores plane");
        });
        assert!(
            other.is_empty(),
            "the capture must be confined to {SCORES_READ_LOG_TARGET}"
        );
    }

    // ── the pure record rendering ────────────────────────────────────

    #[test]
    fn the_canonical_renderings_are_order_and_duplicate_stable() {
        let a = ScoresReadLogRecord::render_subject_filter(&probe_filter());
        let reordered = AttestationFilter {
            attested_key_ids: vec![
                "alpha_key".to_owned(),
                "zeta_key".to_owned(),
                "alpha_key".to_owned(),
            ],
            ..probe_filter()
        };
        assert_eq!(a, ScoresReadLogRecord::render_subject_filter(&reordered));
        assert_eq!(a, "subject=subject_key_552;attested=alpha_key,zeta_key");

        let d = ScoresReadLogRecord::render_dimension_filter(&probe_filter());
        assert_eq!(d, "exact=capacity:composite:v1;prefixes=capacity:,trust:");
        assert_eq!(
            ScoresReadLogRecord::render_dimension_filter(&AttestationFilter::default()),
            "exact=-;prefixes=-"
        );
    }

    #[test]
    fn the_confidence_floor_is_recorded_as_a_flag_never_a_value() {
        let with = ScoresReadLogRecord::new(
            ScoresReadSite::ListScores,
            "k",
            &AttestationFilter {
                confidence_floor: Some(0.7301),
                ..AttestationFilter::default()
            },
            chrono::Utc::now(),
        );
        assert!(with.confidence_floor_supplied);
        // CC 3.4.5 finding 2: the floor is a binary-search oracle over the
        // withheld weight. Recording successive VALUES would rebuild that
        // oracle inside the audit trail, where it outlives the query.
        let rendered = format!("{with:?}");
        assert!(
            !rendered.contains("0.7301"),
            "the log record must not carry the floor VALUE: {rendered}"
        );
    }

    // ─────────────────────────────────────────────────────────────────
    //  The six-site census, read FROM DISK
    //
    //  Mirrors `store::parity`, the `check_capacity_consent_admission`
    //  discipline: read the three backend sources as text so the postgres
    //  arm is scanned under `--features sqlite` and under no features at
    //  all. The runtime witnesses above cannot do that — the postgres one
    //  needs a live database and the sqlite one a feature — so a site
    //  could lose its log call and stay green everywhere CI actually
    //  looks. This scan closes that, and the runtime witnesses keep this
    //  scan from being the only evidence, since a from-disk gate reads
    //  whatever is on disk WHILE IT RUNS and so fails toward a pass.
    // ─────────────────────────────────────────────────────────────────

    const SITES: [(&str, &str); 3] = [
        ("memory", "src/store/memory.rs"),
        ("sqlite", "src/store/sqlite.rs"),
        ("postgres", "src/store/postgres.rs"),
    ];

    /// Blank the CONTENT of comments and string literals, preserving byte
    /// length and line structure, so a commented-out call cannot read as live
    /// and a call name inside a SQL string cannot read as a call.
    fn strip(text: &str) -> String {
        #[derive(PartialEq)]
        enum S {
            Code,
            Line,
            Block(usize),
            Str,
            Chr,
        }
        let b = text.as_bytes();
        let mut out = vec![b' '; b.len()];
        let mut i = 0usize;
        let mut s = S::Code;
        while i < b.len() {
            if b[i] == b'\n' {
                out[i] = b'\n';
                if s == S::Line {
                    s = S::Code;
                }
                i += 1;
                continue;
            }
            match s {
                S::Code => {
                    if b[i] == b'/' && i + 1 < b.len() && b[i + 1] == b'/' {
                        s = S::Line;
                        i += 2;
                    } else if b[i] == b'/' && i + 1 < b.len() && b[i + 1] == b'*' {
                        s = S::Block(1);
                        i += 2;
                    } else if b[i] == b'"' {
                        s = S::Str;
                        i += 1;
                    } else if b[i] == b'\'' {
                        // A lifetime (`'a`, `'static`) is not a char literal.
                        let is_lifetime = i + 1 < b.len()
                            && (b[i + 1].is_ascii_alphabetic() || b[i + 1] == b'_')
                            && (i + 2 >= b.len() || b[i + 2] != b'\'');
                        if is_lifetime {
                            out[i] = b[i];
                            i += 1;
                        } else {
                            s = S::Chr;
                            i += 1;
                        }
                    } else {
                        out[i] = b[i];
                        i += 1;
                    }
                }
                S::Line => i += 1,
                S::Block(d) => {
                    if b[i] == b'/' && i + 1 < b.len() && b[i + 1] == b'*' {
                        s = S::Block(d + 1);
                        i += 2;
                    } else if b[i] == b'*' && i + 1 < b.len() && b[i + 1] == b'/' {
                        s = if d == 1 { S::Code } else { S::Block(d - 1) };
                        i += 2;
                    } else {
                        i += 1;
                    }
                }
                S::Str => {
                    if b[i] == b'\\' {
                        i += 2;
                    } else if b[i] == b'"' {
                        s = S::Code;
                        i += 1;
                    } else {
                        i += 1;
                    }
                }
                S::Chr => {
                    if b[i] == b'\\' {
                        i += 2;
                    } else if b[i] == b'\'' {
                        s = S::Code;
                        i += 1;
                    } else {
                        i += 1;
                    }
                }
            }
        }
        String::from_utf8_lossy(&out).into_owned()
    }

    /// The body of the single `async fn <name>(` in `stripped`, braces included.
    fn method_body(stripped: &str, name: &str, tag: &str) -> String {
        let needle = format!("async fn {name}(");
        let hits: Vec<usize> = stripped.match_indices(&needle).map(|(i, _)| i).collect();
        assert_eq!(
            hits.len(),
            1,
            "({tag}) expected exactly one `{needle}`; found {}",
            hits.len()
        );
        let b = stripped.as_bytes();
        let mut i = hits[0];
        while b[i] != b'{' {
            i += 1;
        }
        let (mut depth, mut j) = (0usize, i);
        loop {
            match b[j] {
                b'{' => depth += 1,
                b'}' => {
                    depth -= 1;
                    if depth == 0 {
                        break;
                    }
                }
                _ => {}
            }
            j += 1;
        }
        stripped[i..=j].to_owned()
    }

    /// **Every one of the six sites emits the read log, before its gate.**
    #[test]
    fn all_six_scores_read_sites_log() {
        let mut checked = 0usize;
        for (backend, rel) in SITES {
            let path = std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join(rel);
            let text = std::fs::read_to_string(&path)
                .unwrap_or_else(|e| panic!("read {}: {e}", path.display()));
            let stripped = strip(&text);
            for (method, variant) in [
                ("list_scores", "ScoresReadSite::ListScores"),
                ("resolve_scores", "ScoresReadSite::ResolveScores"),
            ] {
                let tag = format!("{backend}::{method}");
                let body = method_body(&stripped, method, &tag);
                assert!(
                    body.len() > 400,
                    "({tag}) body is {} bytes — the extractor collapsed and this \
                     gate would pass vacuously",
                    body.len()
                );
                assert_eq!(
                    body.matches("log_scores_read(").count(),
                    1,
                    "({tag}) must call `log_scores_read` exactly once"
                );
                assert_eq!(
                    body.matches(variant).count(),
                    1,
                    "({tag}) must name the `{variant}` site exactly once — a site \
                     logging under its sibling's name is worse than not logging"
                );
                // Position: the log precedes the caller-visibility gate, so a
                // read REFUSED by the gate is logged like one that is served.
                let log_at = body.find("log_scores_read(").expect("checked above");
                let gate_at = body.find("caller_scope_from_directory").unwrap_or_else(|| {
                    panic!("({tag}) no caller gate found — has the door moved?")
                });
                assert!(
                    log_at < gate_at,
                    "({tag}) the read log must be emitted BEFORE \
                     `caller_scope_from_directory`, or a refused read goes unlogged"
                );
                checked += 1;
            }
        }
        assert_eq!(checked, 6, "the scan must cover all six sites");
    }

    #[test]
    fn a_commented_out_log_call_does_not_read_as_live() {
        let src = "fn f() {\n    // log_scores_read(x);\n    /* log_scores_read(y); */\n    let s = \"log_scores_read(z)\";\n}\n";
        let stripped = strip(src);
        assert_eq!(
            stripped.matches("log_scores_read(").count(),
            0,
            "the stripper let a commented-out or quoted call read as live: {stripped}"
        );
        // ...but a real one still does.
        assert_eq!(
            strip("fn f() {\n    log_scores_read(a);\n}\n")
                .matches("log_scores_read(")
                .count(),
            1
        );
    }

    /// **The redaction token is RESERVED: declared, documented, and reached by
    /// nothing.** CC 3.4.5 declined to require redaction, so a wired redaction
    /// path would be shipping the thing the floor refused.
    #[test]
    fn the_redaction_token_is_reserved_and_unwired() {
        fn walk(dir: &std::path::Path, out: &mut Vec<(String, String)>) {
            let Ok(rd) = std::fs::read_dir(dir) else {
                return;
            };
            for e in rd.flatten() {
                let p = e.path();
                if p.is_dir() {
                    walk(&p, out);
                } else if p.extension().is_some_and(|x| x == "rs") {
                    if let Ok(t) = std::fs::read_to_string(&p) {
                        out.push((p.display().to_string(), t));
                    }
                }
            }
        }
        let mut sources = Vec::new();
        walk(
            &std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("src"),
            &mut sources,
        );
        assert!(
            sources.len() > 20,
            "the source walk collapsed ({} files) — this gate would pass vacuously",
            sources.len()
        );
        let hits: Vec<&String> = sources
            .iter()
            .filter(|(p, t)| {
                !p.ends_with("scores_read_audit.rs")
                    && (t.contains("FEDERATION_READ_PREDICATE_REDACTED")
                        || t.contains("federation_read_predicate_redacted"))
            })
            .map(|(p, _)| p)
            .collect();
        assert!(
            hits.is_empty(),
            "the redaction token is RESERVED and must stay unwired; CC 3.4.5 \
             refused the redaction it would switch on. Reached from: {hits:?}"
        );
    }

    // ─────────────────────────────────────────────────────────────────
    //  The marginal-pinning feasibility program
    // ─────────────────────────────────────────────────────────────────

    /// Every reachable retained cell for a contributor count, with the
    /// contradiction count WITHHELD (see `RetainedCell::open_contradictions`).
    fn redacted_cells() -> Vec<RetainedCell> {
        let mut v = Vec::new();
        for n in 1..=3u32 {
            for diversity_established in [false, true] {
                v.push(RetainedCell {
                    contributor_count: n,
                    open_contradictions: None,
                    diversity_established,
                });
            }
        }
        v
    }

    /// The families whose band is PINNED — feasible set of cardinality 1 — in
    /// at least one reachable cell, under either fold.
    fn pinned_families(retain_contradictions: bool) -> BTreeSet<String> {
        let mut pinned = BTreeSet::new();
        for (prefix, polarity) in vendored_family_polarities() {
            let Some(range) = range_for_polarity(&polarity) else {
                continue; // the partition test below is what reds on this
            };
            let cells: Vec<RetainedCell> = if retain_contradictions {
                let mut v = Vec::new();
                for n in 1..=3u32 {
                    for k in 0..=n {
                        for diversity_established in [false, true] {
                            v.push(RetainedCell {
                                contributor_count: n,
                                open_contradictions: Some(k),
                                diversity_established,
                            });
                        }
                    }
                }
                v
            } else {
                redacted_cells()
            };
            for cell in cells {
                for fold in [Fold::SignedMean, Fold::BooleanMin] {
                    // An EMPTY set means the cell is unreachable for this
                    // family (no head vector realizes it), which withholds
                    // nothing. Only a set of exactly one is a pin.
                    if feasible_bands(fold, range, cell).len() == 1 {
                        pinned.insert(prefix.clone());
                    }
                }
            }
        }
        pinned
    }

    /// **The partition, and the mechanism CC 3.4.5 asked for.**
    ///
    /// A CC release introducing a new `polarity` word stops persist's build
    /// until a human maps it to a range — which is the moment to notice that
    /// the new leaf pins. "Fails the build, not review", literally.
    #[test]
    fn every_declared_polarity_in_the_vendored_registry_is_classified() {
        let families = vendored_family_polarities();
        assert!(
            families.len() > 100,
            "the vendored registry yielded {} families with a declared polarity \
             — the parse collapsed and this gate would pass vacuously",
            families.len()
        );
        let unknown: BTreeSet<String> = families
            .iter()
            .filter(|(_, p)| range_for_polarity(p).is_none())
            .map(|(prefix, p)| format!("{prefix} -> {p:?}"))
            .collect();
        assert!(
            unknown.is_empty(),
            "CC declares a polarity persist has never mapped to a value range. \
             Map it in POLARITY_RANGES and re-read the pinning census — a \
             single-polarity leaf is exactly what the census is for. \
             Unmapped: {unknown:#?}"
        );
    }

    /// The partition runs both ways: an entry the corpus no longer contains is
    /// as much a defect as a label the table lacks.
    #[test]
    fn no_polarity_range_entry_is_stale() {
        let live: BTreeSet<String> = vendored_family_polarities()
            .into_iter()
            .map(|(_, p)| p)
            .collect();
        let stale: Vec<&str> = POLARITY_RANGES
            .iter()
            .map(|(l, _)| *l)
            .filter(|l| !live.contains(*l))
            .collect();
        assert!(
            stale.is_empty(),
            "POLARITY_RANGES carries labels the vendored registry no longer \
             declares: {stale:?}"
        );
    }

    /// **The census, as a hand-written literal.**
    ///
    /// A new single-polarity family in a future CC release lands outside this
    /// literal and reds the build; adding it is then a deliberate human act
    /// that records "this family cannot be served under the redaction token".
    #[test]
    fn the_pinning_census_is_exactly_the_single_polarity_leaves() {
        let found = pinned_families(false);
        let expected: BTreeSet<String> = PINNING_FAMILIES.iter().map(|s| (*s).to_owned()).collect();
        assert_eq!(
            found, expected,
            "the marginal-pinning census moved. Families whose ConfidenceBand is \
             FULLY DETERMINED by the fields a redacted view would retain — for \
             these, withholding the band withholds nothing, because the caller \
             named the pinning input in the filter."
        );
        // The literal is not empty, so the census is a finding and not a
        // formality — and it is not everything, so it discriminates.
        assert_eq!(PINNING_FAMILIES.len(), 3);
    }

    /// **CC 3.4.5's acceptance criterion, stated as it was written**: feasible
    /// band-set cardinality >= 2, for every family the census does not exclude,
    /// in every reachable cell. Each pass is a constructive proof — two
    /// exhibited head vectors, two different bands.
    #[test]
    fn every_non_pinning_family_admits_at_least_two_feasible_bands() {
        let excluded: BTreeSet<&str> = PINNING_FAMILIES.iter().copied().collect();
        let mut checked = 0usize;
        for (prefix, polarity) in vendored_family_polarities() {
            if excluded.contains(prefix.as_str()) {
                continue;
            }
            let range = range_for_polarity(&polarity)
                .unwrap_or_else(|| panic!("{prefix}: unmapped polarity {polarity:?}"));
            for cell in redacted_cells() {
                for fold in [Fold::SignedMean, Fold::BooleanMin] {
                    let bands = feasible_bands(fold, range, cell);
                    assert!(
                        bands.len() >= 2,
                        "{prefix} ({polarity:?}) under {fold:?} at {cell:?}: only \
                         {bands:?} is feasible — the withheld band is pinned by the \
                         retained marginals, so redaction there is a courtesy and \
                         not a gate"
                    );
                    checked += 1;
                }
            }
        }
        assert!(
            checked > 400,
            "only {checked} family/cell/fold combinations were checked — the \
             corpus collapsed and this gate would pass vacuously"
        );
    }

    /// **The measurement behind `RetainedCell::open_contradictions`'s doc.**
    ///
    /// Retaining the contradiction count pins 107 of the registry's 114
    /// families; withholding it pins 3. That two-number contrast is the whole
    /// argument for what the reserved token's retained set must be, and a
    /// paragraph asserting it would rot — so it is measured.
    #[test]
    fn retaining_the_contradiction_count_pins_almost_the_whole_registry() {
        let retained = pinned_families(true).len();
        let withheld = pinned_families(false).len();
        assert_eq!(
            (retained, withheld),
            (107, 3),
            "the contradiction-count contrast moved (retained={retained}, \
             withheld={withheld})"
        );
        assert_eq!(vendored_family_polarities().len(), 114);
    }

    /// **The signed fold's escape hatch is a zero-confidence row — and that is
    /// an unenforced gap, not a protection.**
    ///
    /// The single-polarity families pin under `boolean-via-score` today. Under
    /// the signed fold they do NOT, for one reason: `score × confidence` with
    /// `confidence = 0` reaches exactly `0.0`, admitting `Weak` beside
    /// `Refuted`. Persist declares no range for `score` or `confidence` and
    /// refuses neither, so anyone who adds the obvious `confidence > 0`
    /// admission check closes this hatch and pins these families under BOTH
    /// folds. This test exists so that change cannot be made silently.
    #[test]
    fn the_signed_fold_escape_hatch_is_a_zero_confidence_row() {
        let range = range_for_polarity("-1 only").expect("mapped");
        let cell = RetainedCell {
            contributor_count: 2,
            open_contradictions: None,
            diversity_established: false,
        };
        assert_eq!(
            feasible_bands(Fold::BooleanMin, range, cell),
            ["Refuted"].into_iter().collect::<BTreeSet<_>>(),
            "a `-1 only` family is PINNED under the boolean-via-score fold"
        );
        assert_eq!(
            feasible_bands(Fold::SignedMean, range, cell),
            ["Refuted", "Weak"].into_iter().collect::<BTreeSet<_>>(),
            "under the signed fold the ONLY thing unpinning a `-1 only` family is \
             that persist admits confidence = 0, which drags score x confidence to \
             exactly 0.0. If this assertion fails because `Weak` vanished, a \
             confidence-range refusal was added and these families now pin under \
             both folds — update PINNING_FAMILIES and say so."
        );
    }

    /// An empty fold has no withheld quantity, so it is excluded from the
    /// program's domain rather than reported as a pin.
    #[test]
    fn an_empty_fold_is_not_a_pin() {
        let range = range_for_polarity("signed").expect("mapped");
        assert!(feasible_bands(
            Fold::SignedMean,
            range,
            RetainedCell {
                contributor_count: 0,
                open_contradictions: None,
                diversity_established: false,
            }
        )
        .is_empty());
    }
}
