//! v2.10.0 (CIRISPersist#114) — typed `Goal` primitive with M-1
//! alignment as a structural construction-time invariant.
//!
//! # Why M-1 is structural, not optional
//!
//! CIRISLensCore#23 / #24 / #26 (the F-3 detector family) operate on
//! **goals pursued by groups** — and the entire detection family is
//! predicated on the declarer having claimed M-1 alignment. If
//! [`MetaGoalAlignment`] were optional in the type, a malicious or
//! sloppy declarer routes around the framework by simply not setting
//! it. The framework's whole anti-attractor-capture posture
//! (MISSION.md §1) needs M-1 to be where any goal-declaring actor
//! must engage. Type-system enforcement makes it impossible to route
//! around.
//!
//! Construction is the only place [`Goal`] becomes a value, and
//! [`Goal::new`] takes [`MetaGoalAlignment`] **by value, not
//! `Option`**. There is no `Default` impl. The shape mirrors
//! `NonZeroU32`: you cannot get an instance into existence without
//! honoring the invariant.
//!
//! ```rust
//! use ciris_persist::federation::goal::{
//!     Goal, GoalScope, M1Dimension, MetaGoalAlignment,
//! };
//!
//! // To construct a Goal you MUST provide a MetaGoalAlignment —
//! // there is no other path. The signature is the type-system
//! // enforcement.
//! let alignment = MetaGoalAlignment::new(
//!     M1Dimension::Plurality,
//!     "preserves cohort heterogeneity".into(),
//!     None,
//! );
//! let goal = Goal::new(
//!     uuid::Uuid::new_v4(),
//!     "lens-steward".into(),
//!     chrono::Utc::now(),
//!     "publish quarterly federation health report".into(),
//!     GoalScope::SingleDeclarer,
//!     alignment,
//! );
//! assert!(matches!(
//!     goal.meta_goal_alignment.dimension,
//!     M1Dimension::Plurality
//! ));
//! ```
//!
//! # Storage shape
//!
//! V050 lands `goals` (PG: `cirislens.goals`; SQLite: `goals`).
//! Every column the struct carries has a column in the schema;
//! cross-column CHECK constraints enforce the scope-discriminant
//! rule (`scope_cohort_id IS NOT NULL ⇔ scope_kind = 'cohort'`) as
//! defense-in-depth behind the Rust constructor.

use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use uuid::Uuid;

/// A typed goal, federation-visible. Every Goal carries an
/// [`MetaGoalAlignment`] — by construction.
///
/// **Construction discipline.** There is **no** `Default` impl and
/// **no** constructor that accepts `Option<MetaGoalAlignment>`. The
/// type system rules out a Goal-without-M-1 at compile time. See
/// the module-level documentation for rationale.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct Goal {
    /// Content-addressable identifier — UUIDv7 is recommended
    /// (creation-ordered) but persist stores any valid UUID.
    pub goal_id: Uuid,

    /// `federation_keys.key_id` of the party declaring the goal.
    /// Persisted column is FK-constrained.
    pub declared_by_key_id: String,

    /// Wall-clock at declaration. Sealed into the signed envelope.
    pub declared_at: DateTime<Utc>,

    /// What the goal is, in natural language. Sealed into the
    /// signed envelope verbatim; persist also stores a canonical
    /// form for byte-stable comparison (see
    /// [`canonicalize_goal_text`]).
    pub goal_text: String,

    /// Scope of the goal — single declarer, a named cohort, the
    /// whole federation. Used by lens-core's F-3 aggregation
    /// (#26) to bound the population the goal pertains to.
    pub scope: GoalScope,

    /// **M-1 alignment payload — REQUIRED.** How does this goal
    /// promote sustainable adaptive coherence? Concretely names
    /// which dimension of the Accord's M-1 the goal serves +
    /// the declarer's rationale.
    ///
    /// This field is `pub` for ergonomic read access, but [`Goal`]
    /// has no `Default` impl and no constructor that accepts
    /// `Option<MetaGoalAlignment>` — a Goal cannot be constructed
    /// without it. Same construction-time enforcement the type
    /// system gives `NonZeroU32`.
    pub meta_goal_alignment: MetaGoalAlignment,

    /// Retirement marker — `None` while live; `Some(ts)` when the
    /// declarer (or quorum, per scope) retired the goal.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub retired_at: Option<DateTime<Utc>>,
}

impl Goal {
    /// The ONLY constructor. [`MetaGoalAlignment`] is taken by value
    /// — there is no overload that lets the caller leave it out.
    ///
    /// This is the type-system enforcement of M-1: the caller can't
    /// land a Goal-shaped value without naming a [`M1Dimension`] and
    /// a rationale. See the module-level documentation for why.
    pub fn new(
        goal_id: Uuid,
        declared_by_key_id: String,
        declared_at: DateTime<Utc>,
        goal_text: String,
        scope: GoalScope,
        meta_goal_alignment: MetaGoalAlignment,
    ) -> Self {
        Self {
            goal_id,
            declared_by_key_id,
            declared_at,
            goal_text,
            scope,
            meta_goal_alignment,
            retired_at: None,
        }
    }
}

/// Why a [`Goal`] qualifies as M-1-aligned. Required on every
/// `Goal`.
///
/// > M-1 (CIRIS Accord v1.2-Beta): *"Promote sustainable adaptive
/// > coherence — the living conditions under which diverse sentient
/// > beings may pursue their own flourishing in justice and wonder."*
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct MetaGoalAlignment {
    /// Which M-1 dimension this goal serves. Closed enum — open
    /// extension is a substrate-level operation (semver-minor
    /// adds a variant), not a free-text field. Forces the declarer
    /// to think.
    pub dimension: M1Dimension,

    /// Declarer's rationale — how this goal, *in their judgment*,
    /// promotes sustainable adaptive coherence along the chosen
    /// dimension. Free text; canonicalized into the signed bytes
    /// so it's federation-auditable.
    pub rationale: String,

    /// Optional pointer to the deliberation artifact (PDMA log,
    /// discussion thread, WBD entry) where the alignment was
    /// established. `None` is legal but federation-visible —
    /// goals with no provenance trail are noisier signal for
    /// F-3 aggregate-deception detection.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub deliberation_ref: Option<DeliberationRef>,
}

impl MetaGoalAlignment {
    /// Construct a [`MetaGoalAlignment`]. The constructor is the
    /// declarative one-call sibling of [`Goal::new`] — it exists
    /// so the type's construction surface stays uniform with the
    /// rest of the federation primitives.
    pub fn new(
        dimension: M1Dimension,
        rationale: String,
        deliberation_ref: Option<DeliberationRef>,
    ) -> Self {
        Self {
            dimension,
            rationale,
            deliberation_ref,
        }
    }
}

/// The Accord M-1 dimensions, one variant per phrase of the M-1
/// statement.
///
/// **`#[non_exhaustive]`** is deliberate: the substrate retains the
/// right to add variants as the Accord evolves (semver-minor); all
/// `match` arms over [`M1Dimension`] **must** include a `_` arm.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[non_exhaustive]
#[serde(rename_all = "snake_case")]
pub enum M1Dimension {
    /// "Sustainable" — long-term viability of the conditions.
    Sustainability,
    /// "Adaptive" — capacity for course-correction.
    Adaptivity,
    /// "Coherence" — the conditions themselves (epistemic /
    /// institutional / informational).
    Coherence,
    /// "Diverse sentient beings" — preserves heterogeneity.
    Plurality,
    /// "Flourishing" — supports positive capability.
    Flourishing,
    /// "Justice" — preserves rights of those outside the
    /// declarer's circle.
    Justice,
    /// "Wonder" — preserves epistemic openness.
    Wonder,
}

impl M1Dimension {
    /// Wire-shape token, matching the schema's `meta_dimension`
    /// CHECK vocabulary. Lex-sorted across the seven variants so the
    /// CHECK clause is stable to read at the migration site.
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Adaptivity => "adaptivity",
            Self::Coherence => "coherence",
            Self::Flourishing => "flourishing",
            Self::Justice => "justice",
            Self::Plurality => "plurality",
            Self::Sustainability => "sustainability",
            Self::Wonder => "wonder",
        }
    }

    /// Parse from the wire-shape token. Returns `None` on
    /// vocabulary mismatch — caller decides whether that is a
    /// hard reject or a "future variant we don't know yet" downgrade
    /// path.
    pub fn from_wire_str(s: &str) -> Option<Self> {
        Some(match s {
            "adaptivity" => Self::Adaptivity,
            "coherence" => Self::Coherence,
            "flourishing" => Self::Flourishing,
            "justice" => Self::Justice,
            "plurality" => Self::Plurality,
            "sustainability" => Self::Sustainability,
            "wonder" => Self::Wonder,
            _ => return None,
        })
    }
}

/// Scope of a [`Goal`] — how big the population is that the
/// declarer claims the goal pertains to. F-3 detection uses scope
/// to bound aggregation.
#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "snake_case")]
pub enum GoalScope {
    /// Single declarer's own goal — no claim about others.
    SingleDeclarer,
    /// Goal pursued by a named cohort (per the cohort taxonomy).
    /// `cohort_id` is opaque to persist — consumers parse if they
    /// care.
    Cohort {
        /// Opaque cohort identifier; the cohort taxonomy lives in
        /// FSD-002.
        cohort_id: String,
    },
    /// Goal claimed for the whole federation — highest scrutiny
    /// (per FSD-002 §1.10's relational-anthropology commitment).
    Federation,
}

impl GoalScope {
    /// Wire-shape `scope_kind` token, matching the schema's CHECK
    /// vocabulary. Lex-sorted in the CHECK clause for readability.
    pub fn scope_kind_str(&self) -> &'static str {
        match self {
            Self::SingleDeclarer => "single_declarer",
            Self::Cohort { .. } => "cohort",
            Self::Federation => "federation",
        }
    }

    /// The `cohort_id` payload iff `self` is the `Cohort` variant.
    /// The persisted `scope_cohort_id` column is non-NULL iff this
    /// returns `Some(...)`, enforced by a CHECK constraint at the
    /// schema layer as defense-in-depth.
    pub fn cohort_id(&self) -> Option<&str> {
        match self {
            Self::Cohort { cohort_id } => Some(cohort_id.as_str()),
            _ => None,
        }
    }
}

/// Pointer to the deliberation artifact (PDMA log, discussion
/// thread, WBD entry) where a [`Goal`]'s M-1 alignment was
/// established.
///
/// **Shape rationale (v2.10.0).** The issue body for
/// CIRISPersist#114 references but does not pin a definition. We
/// pick the minimal conservative shape: an `artifact_type`
/// vocabulary token (`"pdma"`, `"wbd"`, `"thread"`, etc., opaque to
/// persist) and an `artifact_id` payload the upstream artifact
/// store resolves. This stays compatible with whatever the agent /
/// lens-core canonicalizes around once the WBD adjudication wire
/// shape lands.
#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct DeliberationRef {
    /// Vocabulary token for the artifact type. Persist stores
    /// opaque — consumers parse if they care.
    pub artifact_type: String,
    /// Identifier the upstream artifact store resolves. Persist
    /// stores opaque.
    pub artifact_id: String,
}

/// Filter for [`super::FederationDirectory::list_goals`]. All
/// fields AND-composed; every field optional except
/// `include_retired`, which defaults to `false` (the F-3 hot path
/// skips retired).
#[derive(Debug, Clone, Default)]
pub struct GoalsFilter {
    /// Narrow to goals declared by this `federation_keys.key_id`.
    pub declared_by_key_id: Option<String>,
    /// Narrow to goals serving this M-1 dimension.
    pub m1_dimension: Option<M1Dimension>,
    /// Narrow to goals with this scope kind. Wire-shape token
    /// (`"single_declarer"`, `"cohort"`, `"federation"`).
    pub scope_kind: Option<String>,
    /// Narrow to goals with this cohort id. Only meaningful with
    /// `scope_kind = Some("cohort")`.
    pub cohort_id: Option<String>,
    /// If `false` (default), retired rows are filtered server-side
    /// via `WHERE retired_at IS NULL`. The F-3 hot path skips
    /// retired by default; observability paths set this to `true`.
    pub include_retired: bool,
}

/// Canonicalize `goal_text` for byte-stable comparison. The
/// persisted `goal_text_canonical` column carries the output;
/// consumers may NOT canonicalize differently and expect persist's
/// equality semantics.
///
/// **Implementation (v2.10.0).** Trim leading + trailing ASCII
/// whitespace, collapse internal runs of ASCII whitespace to a
/// single space. The lossy form is suitable only for equality
/// comparison — the unchanged `goal_text` field remains the
/// authoritative human-readable form (and is what's sealed into
/// the signed envelope).
pub fn canonicalize_goal_text(text: &str) -> String {
    let mut out = String::with_capacity(text.len());
    let mut last_was_space = true; // strip leading whitespace
    for ch in text.chars() {
        if ch.is_ascii_whitespace() {
            if !last_was_space {
                out.push(' ');
                last_was_space = true;
            }
        } else {
            out.push(ch);
            last_was_space = false;
        }
    }
    if out.ends_with(' ') {
        out.pop();
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;
    use chrono::TimeZone;

    fn fixture_alignment() -> MetaGoalAlignment {
        MetaGoalAlignment::new(
            M1Dimension::Plurality,
            "preserves cohort heterogeneity".into(),
            None,
        )
    }

    #[test]
    fn constructor_requires_meta_goal_alignment() {
        // Type-system enforcement: `Goal::new` takes `MetaGoalAlignment`
        // by value. There is no path to a `Goal` value without one.
        // (Compile-fail isn't testable in stable Rust; the signature
        // IS the proof.)
        let goal = Goal::new(
            Uuid::nil(),
            "k".into(),
            Utc.with_ymd_and_hms(2026, 5, 28, 0, 0, 0).unwrap(),
            "do the thing".into(),
            GoalScope::SingleDeclarer,
            fixture_alignment(),
        );
        assert!(goal.retired_at.is_none());
        assert_eq!(goal.meta_goal_alignment.dimension, M1Dimension::Plurality);
    }

    #[test]
    fn scope_round_trips_through_json() {
        let single = GoalScope::SingleDeclarer;
        let cohort = GoalScope::Cohort {
            cohort_id: "stewards".into(),
        };
        let federation = GoalScope::Federation;
        for scope in [single, cohort.clone(), federation] {
            let json = serde_json::to_string(&scope).unwrap();
            let deser: GoalScope = serde_json::from_str(&json).unwrap();
            assert_eq!(scope, deser);
        }
        assert_eq!(cohort.cohort_id(), Some("stewards"));
    }

    #[test]
    fn m1_dimension_wire_round_trip() {
        for variant in [
            M1Dimension::Sustainability,
            M1Dimension::Adaptivity,
            M1Dimension::Coherence,
            M1Dimension::Plurality,
            M1Dimension::Flourishing,
            M1Dimension::Justice,
            M1Dimension::Wonder,
        ] {
            let wire = variant.as_str();
            let parsed = M1Dimension::from_wire_str(wire).expect("round trip");
            assert_eq!(parsed, variant);
        }
        assert!(M1Dimension::from_wire_str("totally-bogus").is_none());
    }

    #[test]
    fn goal_serde_round_trip() {
        let goal = Goal::new(
            Uuid::nil(),
            "lens-steward".into(),
            Utc.with_ymd_and_hms(2026, 5, 28, 12, 0, 0).unwrap(),
            "publish quarterly federation health report".into(),
            GoalScope::Cohort {
                cohort_id: "stewards".into(),
            },
            MetaGoalAlignment::new(
                M1Dimension::Coherence,
                "epistemic transparency".into(),
                Some(DeliberationRef {
                    artifact_type: "pdma".into(),
                    artifact_id: "pdma-2026-05".into(),
                }),
            ),
        );
        let json = serde_json::to_string(&goal).unwrap();
        let deser: Goal = serde_json::from_str(&json).unwrap();
        assert_eq!(goal, deser);
    }

    #[test]
    fn canonicalize_collapses_whitespace_and_trims() {
        assert_eq!(canonicalize_goal_text("  hello   world  "), "hello world");
        assert_eq!(canonicalize_goal_text(""), "");
        assert_eq!(canonicalize_goal_text("only"), "only");
        assert_eq!(
            canonicalize_goal_text("multi\nline\t  text"),
            "multi line text"
        );
    }
}
