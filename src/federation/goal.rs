//! v60.0.0 (CIRISPersist#988 item 4; CC 3.1.9.7) — **a Goal is a signed
//! `goal:{scale}:v1` `scores` row.**
//!
//! Signed attestations are the only state. Until v60 a Goal was a typed value
//! (`Goal::new`) written straight into the `goals` table by `put_goal`, never
//! signed by its declarer and never replicated by persist. From v60:
//!
//! | act | row | who |
//! |---|---|---|
//! | declare | `scores` on `goal:{scale}:v1`, the body in the envelope | the declarer |
//! | amend | `supersedes` naming the goal's current head, carrying the whole new body | the declarer |
//! | retire | `withdraws` naming the declaration | the declarer |
//! | "never mine" | `recants` naming the declaration | the declarer |
//!
//! `goal_id` is the declaration row's `attestation_id`. The `goals` table is
//! the PROJECTION of the goal rows this node holds
//! ([`super::goal_projection`]): one row per declaration, carrying the body of
//! the head of its amendment chain, retired at the instant of the winning
//! `withdraws`, absent once recanted. It is byte-equal to its from-rows
//! rebuild (CLM-silo-projection-rebuildable).
//!
//! # The scale
//!
//! `{scale}` is CC 3.1.9.7's open vocabulary (registered values: `self`).
//! The v59 `GoalScope` maps onto it: `single_declarer` → `self`, `cohort` →
//! `cohort` with the cohort id as the envelope member `cohort_id`,
//! `federation` → `federation`. Any other lowercase vocabulary token is
//! admitted as the registry admits it; `cohort_id` is carried iff the scale is
//! `cohort`.
//!
//! # M-1 is an admission gate
//!
//! The F-3 detector family is predicated on every declarer having claimed an
//! M-1 alignment, so a Goal without one must not exist. v2.10.0 enforced that
//! in the type system (a constructor that took `MetaGoalAlignment` by value);
//! a row has no constructor, so the same rule is now the family's admission
//! gate, [`check_goal_row_admission`], run by the attestation plane's put door
//! for local and replicated rows alike. A `goal:*` row (a declaration or an
//! amendment) whose envelope lacks a well-formed `meta_goal_alignment` — a
//! dimension in the seven, a non-empty rationale, an optional well-formed
//! deliberation pointer, nothing else — is refused as
//! [`Error::MalformedRow`](super::Error::MalformedRow) with the reason
//! [`malformed_row::GOAL_META_ALIGNMENT`](super::malformed_row::GOAL_META_ALIGNMENT);
//! any other malformed body is
//! [`malformed_row::GOAL_BODY`](super::malformed_row::GOAL_BODY). Both are
//! terminal for the bytes: no row this node could receive later makes them
//! admissible.
//!
//! # A negative score
//!
//! The family's polarity is `signed`. The score is the declarer's STANCE on
//! the goal text: its sign says whether the declarer pursues the stated state
//! of affairs (positive) or declares it a state it works against (negative:
//! an avoidance goal), its magnitude the commitment. A negative row is still a
//! declaration: it carries M-1, is amended by `supersedes`, retired by
//! `withdraws` and disowned by `recants`. A negative score never retires or
//! disowns anything; those are the structural verbs.

use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};

use super::types::{attestation_type, cohort_scope, Attestation};
use super::{EmitAttestationInput, Error};

/// The `goal:` family stem (CC 3.1.9.7). A leaf is `goal:{scale}:v1`.
pub const GOAL_DIMENSION_PREFIX: &str = "goal:";
/// The registry family a goal leaf resolves to.
pub const GOAL_FAMILY: &str = "goal:{scale}";
/// The scale of a goal about its declarer alone (v59 `single_declarer`).
pub const SCALE_SELF: &str = "self";
/// The scale of a goal pursued by a named cohort.
pub const SCALE_COHORT: &str = "cohort";
/// The scale of a goal claimed for the whole federation.
pub const SCALE_FEDERATION: &str = "federation";
/// The envelope member carrying the goal statement.
pub const GOAL_TEXT_MEMBER: &str = "goal_text";
/// The envelope member carrying the cohort id (scale `cohort` only).
pub const COHORT_ID_MEMBER: &str = "cohort_id";
/// The envelope member carrying the M-1 alignment.
pub const META_ALIGNMENT_MEMBER: &str = "meta_goal_alignment";

/// The plane name a goal refusal carries.
pub const PLANE: &str = "goal";

/// The members a v59 typed `Goal` carried and a goal body never does: its
/// id, declarer and instant are the row's, and `scope` is now `scale` +
/// `cohort_id`.
const RETIRED_TYPED_MEMBERS: &[&str] = &[
    "goal_id",
    "declared_by_key_id",
    "declared_at",
    "scope",
    "retired_at",
];

// ─── the vocabulary ─────────────────────────────────────────────────

/// The Accord M-1 dimensions, one variant per phrase of the M-1 statement.
///
/// > M-1 (CIRIS Accord v1.2-Beta): *"Promote sustainable adaptive
/// > coherence — the living conditions under which diverse sentient
/// > beings may pursue their own flourishing in justice and wonder."*
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[non_exhaustive]
#[serde(rename_all = "snake_case")]
pub enum M1Dimension {
    /// "Sustainable" — long-term viability of the conditions.
    Sustainability,
    /// "Adaptive" — capacity for course-correction.
    Adaptivity,
    /// "Coherence" — the conditions themselves.
    Coherence,
    /// "Diverse sentient beings" — preserves heterogeneity.
    Plurality,
    /// "Flourishing" — supports positive capability.
    Flourishing,
    /// "Justice" — preserves rights of those outside the declarer's circle.
    Justice,
    /// "Wonder" — preserves epistemic openness.
    Wonder,
}

impl M1Dimension {
    /// The wire token (the `goals.meta_dimension` CHECK vocabulary).
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

    /// Parse the wire token; `None` outside the seven.
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

/// Pointer to the deliberation artifact (PDMA log, discussion thread, WBD
/// entry) where a goal's M-1 alignment was established. Both members are
/// opaque to persist and non-empty.
#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct DeliberationRef {
    /// Vocabulary token for the artifact type.
    pub artifact_type: String,
    /// Identifier the upstream artifact store resolves.
    pub artifact_id: String,
}

/// Why a goal qualifies as M-1-aligned: the `meta_goal_alignment` member
/// every goal row carries.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct MetaGoalAlignment {
    /// Which M-1 dimension the goal serves.
    pub dimension: M1Dimension,
    /// The declarer's rationale. Non-empty.
    pub rationale: String,
    /// Optional pointer to the deliberation artifact.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub deliberation_ref: Option<DeliberationRef>,
}

impl MetaGoalAlignment {
    /// Construct one (its well-formedness is the admission gate's).
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

/// A goal's scale and, for `cohort`, its cohort: the `{scale}` segment and
/// the `cohort_id` member. Only [`GoalScope::new`] makes one, so a held
/// `GoalScope` is well-formed.
#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(try_from = "GoalScopeWire")]
pub struct GoalScope {
    scale: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    cohort_id: Option<String>,
}

#[derive(Deserialize)]
struct GoalScopeWire {
    scale: String,
    #[serde(default)]
    cohort_id: Option<String>,
}

impl TryFrom<GoalScopeWire> for GoalScope {
    type Error = String;
    fn try_from(w: GoalScopeWire) -> Result<Self, String> {
        GoalScope::new(&w.scale, w.cohort_id.as_deref())
    }
}

impl GoalScope {
    /// **The scope rule.** `scale` is a lowercase CC vocabulary token;
    /// `cohort_id` is present (and non-empty) iff the scale is `cohort`.
    ///
    /// # Errors
    ///
    /// The rule broken, as text.
    pub fn new(scale: &str, cohort_id: Option<&str>) -> Result<Self, String> {
        if !super::namespace::matcher::is_vocab_token(scale) {
            return Err(format!(
                "scale {scale:?} is not a lowercase vocabulary token (CC 3.1.7 R3)"
            ));
        }
        match (scale == SCALE_COHORT, cohort_id) {
            (true, Some(c)) if !c.trim().is_empty() => {}
            (true, _) => return Err("a `cohort` goal names its cohort_id".into()),
            (false, None) => {}
            (false, Some(_)) => {
                return Err(format!(
                    "cohort_id belongs to a `cohort` goal, not `{scale}`"
                ))
            }
        }
        Ok(Self {
            scale: scale.to_owned(),
            cohort_id: cohort_id.map(str::to_owned),
        })
    }

    /// The `{scale}` segment.
    #[must_use]
    pub fn scale(&self) -> &str {
        &self.scale
    }

    /// The cohort id (scale `cohort` only).
    #[must_use]
    pub fn cohort_id(&self) -> Option<&str> {
        self.cohort_id.as_deref()
    }
}

// ─── the body ───────────────────────────────────────────────────────

/// A goal's body: what the declare and amend doors take. v60.0.0 — no id,
/// declarer or instant (the row's), `scale` + `cohort_id` in place of the v59
/// `scope`, and the declarer's `score` (default `+1`).
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct GoalInput {
    /// The goal statement, verbatim. Non-empty.
    pub goal_text: String,
    /// The `{scale}` segment (`self`, `cohort`, `federation`, …).
    pub scale: String,
    /// The cohort (scale `cohort` only).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub cohort_id: Option<String>,
    /// The M-1 alignment.
    pub meta_goal_alignment: MetaGoalAlignment,
    /// The declarer's stance, `[-1, 1]` (module doc "A negative score").
    #[serde(default = "default_score")]
    pub score: f64,
}

fn default_score() -> f64 {
    1.0
}

/// A goal body as read from a row: what the projection writes.
#[derive(Debug, Clone, PartialEq)]
pub struct GoalBody {
    /// The scale and cohort.
    pub scope: GoalScope,
    /// The goal statement.
    pub goal_text: String,
    /// The M-1 alignment.
    pub meta_goal_alignment: MetaGoalAlignment,
    /// The row's score.
    pub score: f64,
}

/// Read and check a goal body from a row's `dimension` and envelope. The one
/// parser the admission gate, the planners and the projection share.
///
/// # Errors
///
/// `(reason, detail)`: [`super::malformed_row::GOAL_META_ALIGNMENT`] for a
/// missing or ill-formed `meta_goal_alignment`;
/// [`super::malformed_row::GOAL_BODY`] for every other defect.
pub fn parse_goal_body(
    dimension: &str,
    envelope: &serde_json::Value,
) -> Result<GoalBody, (&'static str, String)> {
    use super::malformed_row::{GOAL_BODY, GOAL_META_ALIGNMENT};
    let m = super::namespace::matcher::match_family(dimension);
    let scale = match (m.family, m.refusal, m.binds.get("scale")) {
        (Some(GOAL_FAMILY), None, Some(s)) => s.clone(),
        _ => {
            return Err((
                GOAL_BODY,
                format!("dimension {dimension:?} is not a well-formed goal:{{scale}}:v1 leaf"),
            ))
        }
    };
    let cohort_id = match envelope.get(COHORT_ID_MEMBER) {
        None | Some(serde_json::Value::Null) => None,
        Some(serde_json::Value::String(c)) => Some(c.as_str()),
        Some(_) => return Err((GOAL_BODY, "cohort_id is not a string".into())),
    };
    let scope = GoalScope::new(&scale, cohort_id).map_err(|e| (GOAL_BODY, e))?;
    let goal_text = envelope
        .get(GOAL_TEXT_MEMBER)
        .and_then(serde_json::Value::as_str)
        .filter(|t| !t.trim().is_empty())
        .ok_or((GOAL_BODY, "goal_text is missing or empty".to_owned()))?
        .to_owned();
    let score = envelope
        .get("score")
        .and_then(serde_json::Value::as_f64)
        .filter(|s| (-1.0..=1.0).contains(s))
        .ok_or((GOAL_BODY, "score is missing or outside [-1, 1]".to_owned()))?;
    let alignment = envelope.get(META_ALIGNMENT_MEMBER).ok_or((
        GOAL_META_ALIGNMENT,
        "meta_goal_alignment is missing: every goal names the M-1 dimension it serves and why"
            .to_owned(),
    ))?;
    let meta_goal_alignment: MetaGoalAlignment = serde_json::from_value(alignment.clone())
        .map_err(|e| (GOAL_META_ALIGNMENT, format!("meta_goal_alignment: {e}")))?;
    if meta_goal_alignment.rationale.trim().is_empty() {
        return Err((
            GOAL_META_ALIGNMENT,
            "meta_goal_alignment.rationale is empty".into(),
        ));
    }
    if let Some(d) = &meta_goal_alignment.deliberation_ref {
        if d.artifact_type.trim().is_empty() || d.artifact_id.trim().is_empty() {
            return Err((
                GOAL_META_ALIGNMENT,
                "meta_goal_alignment.deliberation_ref names an empty artifact".into(),
            ));
        }
    }
    Ok(GoalBody {
        scope,
        goal_text,
        meta_goal_alignment,
        score,
    })
}

/// Does `dimension` name the goal family (by stem)?
#[must_use]
pub fn is_goal_dimension(dimension: &str) -> bool {
    dimension.starts_with(GOAL_DIMENSION_PREFIX)
}

/// The row's goal body, when it is a `scores` or `supersedes` row on the goal
/// family carrying a well-formed one.
#[must_use]
pub fn goal_body_of(row: &Attestation) -> Option<GoalBody> {
    if row.attestation_type != attestation_type::SCORES
        && row.attestation_type != attestation_type::SUPERSEDES
    {
        return None;
    }
    let d = super::admission::envelope_dimension(&row.attestation_envelope)?;
    if !is_goal_dimension(d) {
        return None;
    }
    parse_goal_body(d, &row.attestation_envelope).ok()
}

// ─── the admission gate ─────────────────────────────────────────────

/// **The goal family's admission gate** (CC 3.1.9.7; the v2.10.0 M-1
/// invariant as a row rule). Run by the attestation plane's put door for
/// every row, local or replicated; a no-op for rows that are neither on the
/// goal family nor a `supersedes` of a held goal row.
///
/// 1. A `scores` or `supersedes` row on `goal:*` carries a well-formed body
///    ([`parse_goal_body`]); otherwise [`Error::MalformedRow`] naming the
///    reason (terminal for the bytes).
/// 2. A `supersedes` naming a HELD goal row is an amendment: it carries a
///    goal body, and it is the declarer's (the named row's own attester).
///    Otherwise [`Error::InvalidArgument`]: a foreign or body-less supersedes
///    would occupy the declarer's §6.1 replay slot on that row and never
///    amend it. A target not held yet is admitted; the projection folds it
///    when the target lands.
///
/// `withdraws` / `recants` need no goal rule: the plane's entitlement rule
/// (`precedence::retraction_entitled`) already confines them to the
/// declarer.
///
/// # Errors
///
/// As above; a directory read.
pub async fn check_goal_row_admission(
    dir: &dyn super::FederationDirectory,
    row: &Attestation,
) -> Result<(), Error> {
    let is_scores = row.attestation_type == attestation_type::SCORES;
    let is_supersedes = row.attestation_type == attestation_type::SUPERSEDES;
    if !is_scores && !is_supersedes {
        return Ok(());
    }
    let dimension = super::admission::envelope_dimension(&row.attestation_envelope);
    let carries_goal = dimension.is_some_and(is_goal_dimension);
    if carries_goal {
        let d = dimension.unwrap_or_default();
        parse_goal_body(d, &row.attestation_envelope).map_err(|(reason, detail)| {
            Error::malformed_row(
                PLANE,
                reason,
                format!(
                    "federation_malformed_row: {PLANE}: {reason}: row {} on {d}: {detail}",
                    row.attestation_id
                ),
            )
        })?;
    }
    if !is_supersedes {
        return Ok(());
    }
    let Some(target_id) =
        super::precedence::references_attestation_id_from_envelope(&row.attestation_envelope)
    else {
        return Ok(());
    };
    let Some(target) = dir.get_attestation(target_id).await? else {
        return Ok(());
    };
    if goal_body_of(&target).is_none() {
        return Ok(());
    }
    if !carries_goal || target.attesting_key_id != row.attesting_key_id {
        return Err(Error::InvalidArgument(format!(
            "supersedes {} names goal row {target_id} but is not its declarer's amendment \
             (attester {}, declarer {}; a goal amendment carries the whole goal body on \
             goal:{{scale}}:v1)",
            row.attestation_id, row.attesting_key_id, target.attesting_key_id
        )));
    }
    Ok(())
}

// ─── the planners ───────────────────────────────────────────────────

fn goal_envelope(input: &GoalInput) -> Result<serde_json::Value, Error> {
    let dimension = format!("{GOAL_DIMENSION_PREFIX}{}:v1", input.scale);
    let mut env = serde_json::json!({
        "dimension": dimension,
        "score": input.score,
        "confidence": 1.0,
        GOAL_TEXT_MEMBER: input.goal_text,
        META_ALIGNMENT_MEMBER: input.meta_goal_alignment,
    });
    if let Some(c) = &input.cohort_id {
        env[COHORT_ID_MEMBER] = serde_json::json!(c);
    }
    // The gate's own parser: a body the planner mints is a body the door
    // admits, and a refusal here carries the door's token.
    parse_goal_body(&dimension, &env).map_err(|(reason, detail)| {
        Error::malformed_row(
            PLANE,
            reason,
            format!("federation_malformed_row: {PLANE}: {reason}: {detail}"),
        )
    })?;
    Ok(env)
}

fn row_input(
    attestation_type: &str,
    env: serde_json::Value,
) -> Result<EmitAttestationInput, Error> {
    let core = super::envelope::EnvelopeCore::from_value(env)?;
    Ok(EmitAttestationInput::with_envelope(
        attestation_type,
        core,
        cohort_scope::FEDERATION,
    ))
}

/// **A declaration** (CC 3.1.9.7): `scores` on `goal:{scale}:v1`, the body
/// in the envelope, attested to the signer. Its id is the goal's id.
///
/// # Errors
///
/// [`Error::MalformedRow`] with the gate's reason for a body the gate would
/// refuse.
pub fn plan_goal_row(input: &GoalInput) -> Result<EmitAttestationInput, Error> {
    row_input(attestation_type::SCORES, goal_envelope(input)?)
}

/// **An amendment**: `supersedes` naming `head_id` (the goal's current head:
/// the declaration, or its latest amendment) and carrying the whole new body.
///
/// # Errors
///
/// As [`plan_goal_row`].
pub fn plan_goal_amendment_row(
    head_id: &str,
    head_type: &str,
    input: &GoalInput,
) -> Result<EmitAttestationInput, Error> {
    let mut env = goal_envelope(input)?;
    env["references_attestation_id"] = serde_json::json!(head_id);
    env["references_attestation_type"] = serde_json::json!(head_type);
    row_input(attestation_type::SUPERSEDES, env)
}

/// **A retirement** (`withdraws`) or **a disowning** (`recants`) of the
/// declaration `goal_id`: the structural row, no body.
///
/// # Errors
///
/// [`Error::InvalidArgument`] for any other `verb`.
pub fn plan_goal_retraction_row(verb: &str, goal_id: &str) -> Result<EmitAttestationInput, Error> {
    if verb != attestation_type::WITHDRAWS && verb != attestation_type::RECANTS {
        return Err(Error::InvalidArgument(format!(
            "a goal is retired by `withdraws` or disowned by `recants`, not `{verb}`"
        )));
    }
    row_input(
        verb,
        serde_json::json!({
            "kind": verb,
            "references_attestation_id": goal_id,
            "references_attestation_type": attestation_type::SCORES,
        }),
    )
}

/// Decode a goal door's JSON body, refusing the retired v59 typed `Goal` BY
/// NAME before the shape check.
///
/// # Errors
///
/// [`Error::MalformedRow`] ([`super::malformed_row::GOAL_TYPED_OBJECT_RETIRED`])
/// naming the member; [`Error::InvalidArgument`] for any other shape error.
pub fn decode_goal_input(json: &str) -> Result<GoalInput, Error> {
    let v: serde_json::Value = serde_json::from_str(json)
        .map_err(|e| Error::InvalidArgument(format!("goal JSON decode: {e}")))?;
    if let Some(member) = RETIRED_TYPED_MEMBERS.iter().find(|m| v.get(**m).is_some()) {
        let reason = super::malformed_row::GOAL_TYPED_OBJECT_RETIRED;
        return Err(Error::malformed_row(
            PLANE,
            reason,
            format!(
                "federation_malformed_row: {PLANE}: {reason}: the body carries `{member}`: the v59 \
                 typed Goal is retired (v60.0.0, CIRISPersist#988 item 4). A goal is a signed \
                 goal:{{scale}}:v1 row now; send {{goal_text, scale, cohort_id?, \
                 meta_goal_alignment, score?}} and the engine signs it"
            ),
        ));
    }
    serde_json::from_value(v).map_err(|e| Error::InvalidArgument(format!("goal body: {e}")))
}

// ─── the read type ──────────────────────────────────────────────────

/// A goal as the `goals` projection holds it.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct Goal {
    /// The declaration row's `attestation_id`.
    pub goal_id: String,
    /// The declarer (the declaration's attester).
    pub declared_by_key_id: String,
    /// The declaration's signed instant.
    pub declared_at: DateTime<Utc>,
    /// The goal statement (the head's).
    pub goal_text: String,
    /// The scale and cohort (the head's).
    #[serde(flatten)]
    pub scope: GoalScope,
    /// The M-1 alignment (the head's).
    pub meta_goal_alignment: MetaGoalAlignment,
    /// The head's score.
    pub score: f64,
    /// The winning `withdraws`' signed instant; `None` while live.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub retired_at: Option<DateTime<Utc>>,
    /// The head row: the declaration, or the latest amendment.
    pub attestation_id: String,
}

/// Filter for [`super::FederationDirectory::list_goals`]. All fields
/// AND-composed.
#[derive(Debug, Clone, Default)]
pub struct GoalsFilter {
    /// Only this declarer's goals.
    pub declared_by_key_id: Option<String>,
    /// Only goals serving this M-1 dimension.
    pub m1_dimension: Option<M1Dimension>,
    /// Only goals at this scale (`self`, `cohort`, `federation`, …).
    pub scale: Option<String>,
    /// Only goals of this cohort.
    pub cohort_id: Option<String>,
    /// Include retired goals (default: live only).
    pub include_retired: bool,
}

/// A pre-V204 `goals` row: a typed goal no row backs (`attestation_id` NULL).
#[derive(Debug, Clone, PartialEq)]
pub struct LegacyGoal {
    /// Its v59 id.
    pub goal_id: String,
    /// Its declarer.
    pub declared_by_key_id: String,
    /// Its statement.
    pub goal_text: String,
    /// Its scale (V204 mapped `single_declarer` to `self`).
    pub scale: String,
    /// Its cohort.
    pub cohort_id: Option<String>,
    /// `meta_dimension`.
    pub meta_dimension: String,
    /// `meta_rationale`.
    pub meta_rationale: String,
    /// `meta_deliberation`, as stored.
    pub meta_deliberation: Option<serde_json::Value>,
    /// Was it retired?
    pub retired: bool,
}

impl LegacyGoal {
    /// The body a rehome re-signs, or `None` when the legacy goal cannot be a
    /// row (its M-1 or scope would be refused by the gate).
    #[must_use]
    pub fn rehome_input(&self) -> Option<GoalInput> {
        let deliberation_ref = match &self.meta_deliberation {
            None | Some(serde_json::Value::Null) => None,
            Some(v) => Some(serde_json::from_value(v.clone()).ok()?),
        };
        let input = GoalInput {
            goal_text: self.goal_text.clone(),
            scale: self.scale.clone(),
            cohort_id: self.cohort_id.clone(),
            meta_goal_alignment: MetaGoalAlignment::new(
                M1Dimension::from_wire_str(&self.meta_dimension)?,
                self.meta_rationale.clone(),
                deliberation_ref,
            ),
            score: 1.0,
        };
        goal_envelope(&input).ok()?;
        Some(input)
    }
}

/// What a rehome did.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct GoalRehome {
    /// This node's legacy goals re-signed as rows (and the legacy row
    /// removed).
    pub rehomed: usize,
    /// Legacy goals removed without a row: another declarer's (persist
    /// cannot sign for it; the typed row carried no signature of theirs), or
    /// one the gate would refuse.
    pub dropped: usize,
}

/// Canonicalize `goal_text` for byte-stable comparison (the
/// `goal_text_canonical` column): trim, collapse ASCII whitespace runs.
pub fn canonicalize_goal_text(text: &str) -> String {
    let mut out = String::with_capacity(text.len());
    let mut last_was_space = true;
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

// ─── the Engine doors ───────────────────────────────────────────────

#[cfg(any(feature = "postgres", feature = "sqlite"))]
impl crate::Engine {
    /// v60.0.0 — **declare a goal**: this engine's `goal:{scale}:v1` row.
    /// Returns its `attestation_id`, the goal's id. Rehomes any pre-V204
    /// goal first.
    ///
    /// # Errors
    ///
    /// The gate's refusals; the plane's.
    pub async fn put_goal(&self, input: &GoalInput) -> Result<String, Error> {
        self.rehome_legacy_goals().await?;
        self.emit_attestation_self(plan_goal_row(input)?).await
    }

    /// The held goal `goal_id`, declared by this engine.
    async fn own_goal(&self, goal_id: &str) -> Result<Goal, Error> {
        let me = self
            .local_derived_key_id()
            .await
            .map_err(|e| Error::Backend(format!("goal signer: {e}")))?;
        let goal = self
            .federation_directory()
            .get_goal(goal_id)
            .await?
            .ok_or_else(|| Error::InvalidArgument(format!("goal {goal_id} is not held here")))?;
        if goal.declared_by_key_id != me {
            return Err(Error::InvalidArgument(format!(
                "goal {goal_id} was declared by {}, not this node ({me}): only its declarer \
                 amends, retires or recants it",
                goal.declared_by_key_id
            )));
        }
        Ok(goal)
    }

    /// v60.0.0 — **amend a goal**: a `supersedes` naming its current head,
    /// carrying the whole new body. Returns the amendment's id (the goal's id
    /// is unchanged).
    ///
    /// # Errors
    ///
    /// The goal not held or not this node's; the gate's; the plane's.
    pub async fn amend_goal(&self, goal_id: &str, input: &GoalInput) -> Result<String, Error> {
        let goal = self.own_goal(goal_id).await?;
        let head_type = if goal.attestation_id == goal.goal_id {
            attestation_type::SCORES
        } else {
            attestation_type::SUPERSEDES
        };
        self.emit_attestation_self(plan_goal_amendment_row(
            &goal.attestation_id,
            head_type,
            input,
        )?)
        .await
    }

    /// v60.0.0 — **retire a goal**: this declarer's `withdraws` of the
    /// declaration; the projection's `retired_at` is its signed instant. A
    /// second retirement is the §6.1 replay no-op. Returns the row's id.
    ///
    /// # Errors
    ///
    /// The goal not held or not this node's; the plane's.
    pub async fn retire_goal(&self, goal_id: &str) -> Result<String, Error> {
        self.own_goal(goal_id).await?;
        self.emit_attestation_self(plan_goal_retraction_row(
            attestation_type::WITHDRAWS,
            goal_id,
        )?)
        .await
    }

    /// v60.0.0 — **disown a goal** ("never mine"): this declarer's `recants`
    /// of the declaration; the goal leaves the projection. Returns the row's
    /// id.
    ///
    /// # Errors
    ///
    /// The goal not held or not this node's; the plane's.
    pub async fn recant_goal(&self, goal_id: &str) -> Result<String, Error> {
        self.own_goal(goal_id).await?;
        self.emit_attestation_self(plan_goal_retraction_row(
            attestation_type::RECANTS,
            goal_id,
        )?)
        .await
    }

    /// v60.0.0 — **move every pre-V204 goal off the table** (the ledger
    /// rehome precedent). A legacy goal carries no `attestation_id`, so the
    /// projection rebuild is red while one remains. This node's own goal is
    /// re-signed as a row (and withdrawn again when it was retired) and its
    /// legacy row removed; any other declarer's is removed: persist cannot
    /// sign for another key, and the typed row never carried that key's
    /// signature. A legacy goal the gate would refuse is removed too. A no-op
    /// when none remain.
    ///
    /// # Errors
    ///
    /// A table read or delete; a refused emit (the legacy row stays).
    pub async fn rehome_legacy_goals(&self) -> Result<GoalRehome, Error> {
        let dir = self.federation_directory();
        let legacy = dir.legacy_goals().await?;
        let mut out = GoalRehome::default();
        if legacy.is_empty() {
            return Ok(out);
        }
        let me = self
            .local_derived_key_id()
            .await
            .map_err(|e| Error::Backend(format!("goal signer: {e}")))?;
        for g in legacy {
            match g.rehome_input().filter(|_| g.declared_by_key_id == me) {
                Some(input) => {
                    let id = self.emit_attestation_self(plan_goal_row(&input)?).await?;
                    if g.retired {
                        self.emit_attestation_self(plan_goal_retraction_row(
                            attestation_type::WITHDRAWS,
                            &id,
                        )?)
                        .await?;
                    }
                    out.rehomed += 1;
                }
                None => out.dropped += 1,
            }
            dir.delete_legacy_goal(&g.goal_id).await?;
        }
        Ok(out)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn alignment() -> serde_json::Value {
        serde_json::json!({"dimension": "plurality", "rationale": "keeps the cohort heterogeneous"})
    }

    fn env(scale: &str, extra: serde_json::Value) -> (String, serde_json::Value) {
        let mut e = serde_json::json!({
            "score": 1.0,
            "goal_text": "publish the quarterly health report",
            "meta_goal_alignment": alignment(),
        });
        for (k, v) in extra.as_object().unwrap() {
            e[k] = v.clone();
        }
        (format!("goal:{scale}:v1"), e)
    }

    /// I1174 (unit) — the three v59 scopes are three scales of the open
    /// vocabulary; `cohort` names its cohort and no other scale does; an
    /// empty or non-vocabulary scale is refused.
    #[test]
    fn i1174_the_scales_admit_and_a_bad_scale_refuses() {
        use crate::federation::malformed_row::GOAL_BODY;
        for (scale, extra) in [
            (SCALE_SELF, serde_json::json!({})),
            (SCALE_FEDERATION, serde_json::json!({})),
            (SCALE_COHORT, serde_json::json!({"cohort_id": "stewards"})),
            ("community", serde_json::json!({})),
        ] {
            let (d, e) = env(scale, extra);
            let body = parse_goal_body(&d, &e).unwrap_or_else(|x| panic!("{scale}: {x:?}"));
            assert_eq!(body.scope.scale(), scale);
        }
        let (d, e) = env(SCALE_COHORT, serde_json::json!({"cohort_id": "stewards"}));
        assert_eq!(
            parse_goal_body(&d, &e).unwrap().scope.cohort_id(),
            Some("stewards")
        );
        for (d, extra) in [
            ("goal::v1", serde_json::json!({})),
            ("goal:v1", serde_json::json!({})),
            ("goal:Self:v1", serde_json::json!({})),
            ("goal:self", serde_json::json!({})),
            ("goal:cohort:v1", serde_json::json!({})),
            ("goal:cohort:v1", serde_json::json!({"cohort_id": " "})),
            ("goal:cohort:v1", serde_json::json!({"cohort_id": 7})),
            ("goal:self:v1", serde_json::json!({"cohort_id": "stewards"})),
        ] {
            let (_, e) = env("self", extra.clone());
            let (reason, _) = parse_goal_body(d, &e).expect_err(d);
            assert_eq!(reason, GOAL_BODY, "{d} {extra}");
        }
        assert!(GoalScope::new("", None).is_err());
        assert!(GoalScope::new("self", None).is_ok());
    }

    /// I1175 (unit) — M-1 is required and well-formed: missing, an unknown
    /// dimension, an empty rationale, an unknown member, an empty
    /// deliberation pointer each refuse with the M-1 token; the body's other
    /// defects with the body token.
    #[test]
    fn i1175_m1_is_required_and_well_formed() {
        use crate::federation::malformed_row::{GOAL_BODY, GOAL_META_ALIGNMENT};
        let (d, ok) = env(SCALE_SELF, serde_json::json!({}));
        parse_goal_body(&d, &ok).expect("a well-formed body");
        let mut with_ref = ok.clone();
        with_ref["meta_goal_alignment"]["deliberation_ref"] =
            serde_json::json!({"artifact_type": "pdma", "artifact_id": "p-1"});
        assert_eq!(
            parse_goal_body(&d, &with_ref)
                .unwrap()
                .meta_goal_alignment
                .deliberation_ref
                .unwrap()
                .artifact_id,
            "p-1"
        );
        let mut missing = ok.clone();
        missing
            .as_object_mut()
            .unwrap()
            .remove("meta_goal_alignment");
        let bad_align = [
            serde_json::json!({"dimension": "greed", "rationale": "r"}),
            serde_json::json!({"dimension": "justice", "rationale": "  "}),
            serde_json::json!({"dimension": "justice"}),
            serde_json::json!({"dimension": "justice", "rationale": "r", "extra": 1}),
            serde_json::json!({"dimension": "justice", "rationale": "r",
                "deliberation_ref": {"artifact_type": "", "artifact_id": "x"}}),
            serde_json::json!({"dimension": "justice", "rationale": "r",
                "deliberation_ref": {"artifact_type": "pdma", "artifact_id": " "}}),
            serde_json::json!("plurality"),
        ];
        let mut cases = vec![missing];
        for a in bad_align {
            let mut e = ok.clone();
            e["meta_goal_alignment"] = a;
            cases.push(e);
        }
        for e in cases {
            let (reason, detail) = parse_goal_body(&d, &e).expect_err("refused");
            assert_eq!(reason, GOAL_META_ALIGNMENT, "{e}: {detail}");
        }
        for (k, v) in [
            ("goal_text", serde_json::json!("   ")),
            ("goal_text", serde_json::json!(5)),
            ("score", serde_json::json!(1.5)),
            ("score", serde_json::json!(-1.01)),
            ("score", serde_json::json!("1")),
        ] {
            let mut e = ok.clone();
            e[k] = v.clone();
            assert_eq!(parse_goal_body(&d, &e).unwrap_err().0, GOAL_BODY, "{k}={v}");
        }
        let mut no_text = ok.clone();
        no_text.as_object_mut().unwrap().remove("goal_text");
        assert_eq!(parse_goal_body(&d, &no_text).unwrap_err().0, GOAL_BODY);
        // The signed polarity: a negative stance is a declaration.
        for s in [-1.0, -0.5, 0.0, 1.0] {
            let mut e = ok.clone();
            e["score"] = serde_json::json!(s);
            assert_eq!(parse_goal_body(&d, &e).unwrap().score, s);
        }
    }

    fn input() -> GoalInput {
        GoalInput {
            goal_text: "publish the quarterly health report".into(),
            scale: SCALE_COHORT.into(),
            cohort_id: Some("stewards".into()),
            meta_goal_alignment: MetaGoalAlignment::new(
                M1Dimension::Coherence,
                "epistemic transparency".into(),
                None,
            ),
            score: -0.5,
        }
    }

    /// I1176 (unit) — the planners mint the four verbs: a declaration on
    /// `goal:{scale}:v1`, an amendment naming its head, a retirement and a
    /// disowning naming the declaration; a planner refuses with the gate's
    /// token; the v59 typed Goal is refused by name.
    #[test]
    fn i1176_the_planners_mint_the_four_verbs() {
        let row = plan_goal_row(&input()).unwrap();
        assert_eq!(row.attestation_type, "scores");
        assert_eq!(row.cohort_scope, "federation");
        let v = row.attestation_envelope.to_value();
        assert_eq!(v["dimension"], "goal:cohort:v1");
        assert_eq!(v["cohort_id"], "stewards");
        assert_eq!(v["score"], serde_json::json!(-0.5));
        assert_eq!(v["meta_goal_alignment"]["dimension"], "coherence");
        let a = plan_goal_amendment_row("head-1", "scores", &input()).unwrap();
        assert_eq!(a.attestation_type, "supersedes");
        let v = a.attestation_envelope.to_value();
        assert_eq!(v["references_attestation_id"], "head-1");
        assert_eq!(v["references_attestation_type"], "scores");
        assert_eq!(v["dimension"], "goal:cohort:v1");
        for verb in ["withdraws", "recants"] {
            let r = plan_goal_retraction_row(verb, "g-1").unwrap();
            assert_eq!(r.attestation_type, verb);
            assert_eq!(
                r.attestation_envelope.to_value()["references_attestation_id"],
                "g-1"
            );
        }
        assert!(plan_goal_retraction_row("supersedes", "g-1").is_err());
        assert!(plan_goal_retraction_row("scores", "g-1").is_err());
        let mut bad = input();
        bad.meta_goal_alignment.rationale = String::new();
        let e = plan_goal_row(&bad).unwrap_err();
        assert!(
            matches!(&e, Error::MalformedRow { reason, .. }
                if *reason == crate::federation::malformed_row::GOAL_META_ALIGNMENT),
            "{e}"
        );
        let mut bad = input();
        bad.cohort_id = None;
        assert!(plan_goal_amendment_row("h", "scores", &bad).is_err());
        // The v59 typed Goal, refused by name.
        for member in RETIRED_TYPED_MEMBERS {
            let mut j = serde_json::to_value(input()).unwrap();
            j[*member] = serde_json::json!("x");
            let e = decode_goal_input(&j.to_string()).unwrap_err();
            assert!(
                matches!(&e, Error::MalformedRow { reason, .. }
                    if *reason == crate::federation::malformed_row::GOAL_TYPED_OBJECT_RETIRED),
                "{member}: {e}"
            );
        }
        let ok = serde_json::json!({
            "goal_text": "t", "scale": "self",
            "meta_goal_alignment": {"dimension": "wonder", "rationale": "r"},
        });
        let decoded = decode_goal_input(&ok.to_string()).expect("a body decodes");
        assert_eq!(decoded.score, 1.0, "the default stance is +1");
        assert!(matches!(
            decode_goal_input("{\"goal_text\": 1}").unwrap_err(),
            Error::InvalidArgument(_)
        ));
        assert!(matches!(
            decode_goal_input("not json").unwrap_err(),
            Error::InvalidArgument(_)
        ));
    }

    /// I1176 (unit) — a legacy goal rehomes iff the gate would admit its
    /// body.
    #[test]
    fn i1176_a_legacy_goal_rehomes_iff_its_body_is_admissible() {
        let g = LegacyGoal {
            goal_id: "l-1".into(),
            declared_by_key_id: "k".into(),
            goal_text: "t".into(),
            scale: "cohort".into(),
            cohort_id: Some("c".into()),
            meta_dimension: "justice".into(),
            meta_rationale: "r".into(),
            meta_deliberation: Some(
                serde_json::json!({"artifact_type": "pdma", "artifact_id": "p"}),
            ),
            retired: true,
        };
        let i = g.rehome_input().expect("admissible");
        assert_eq!(i.scale, "cohort");
        assert_eq!(
            i.meta_goal_alignment
                .deliberation_ref
                .unwrap()
                .artifact_type,
            "pdma"
        );
        for bad in [
            LegacyGoal {
                meta_rationale: String::new(),
                ..g.clone()
            },
            LegacyGoal {
                meta_dimension: "greed".into(),
                ..g.clone()
            },
            LegacyGoal {
                meta_deliberation: Some(serde_json::json!(3)),
                ..g.clone()
            },
            LegacyGoal {
                cohort_id: None,
                ..g.clone()
            },
        ] {
            assert!(bad.rehome_input().is_none(), "{bad:?}");
        }
        let none = LegacyGoal {
            meta_deliberation: Some(serde_json::Value::Null),
            ..g
        };
        assert!(none
            .rehome_input()
            .unwrap()
            .meta_goal_alignment
            .deliberation_ref
            .is_none());
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
            let parsed = M1Dimension::from_wire_str(variant.as_str()).expect("round trip");
            assert_eq!(parsed, variant);
            assert_eq!(
                serde_json::to_value(variant).unwrap(),
                serde_json::json!(variant.as_str())
            );
        }
        assert!(M1Dimension::from_wire_str("totally-bogus").is_none());
    }

    #[test]
    fn goal_serde_round_trip() {
        let goal = Goal {
            goal_id: "g".into(),
            declared_by_key_id: "k".into(),
            declared_at: chrono::DateTime::UNIX_EPOCH,
            goal_text: "t".into(),
            scope: GoalScope::new("cohort", Some("c")).unwrap(),
            meta_goal_alignment: MetaGoalAlignment::new(M1Dimension::Wonder, "r".into(), None),
            score: 0.25,
            retired_at: None,
            attestation_id: "h".into(),
        };
        let v = serde_json::to_value(&goal).unwrap();
        assert_eq!(v["scale"], "cohort");
        assert_eq!(v["cohort_id"], "c");
        let back: Goal = serde_json::from_value(v).unwrap();
        assert_eq!(back, goal);
        let mut bad = serde_json::to_value(&goal).unwrap();
        bad.as_object_mut().unwrap().remove("cohort_id");
        assert!(serde_json::from_value::<Goal>(bad).is_err());
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
