//! v53.0.0 (CIRISPersist#975, **CC 2.4** "The row-type slot is closed") — the
//! `attestation_type` allowlist.
//!
//! `attestation_type` was free text: V004 has no CHECK, `attestation_type::ALL`
//! was read only by a test, and [`DimensionAdmissionPolicy::check`] returned
//! `Ok` for every non-`scores` type. The absence of a check is not a gate.
//!
//! CC 2.4 closes the slot: a row's type is one of the five structural types
//! (`scores`, `delegates_to`, `supersedes`, `withdraws`, `recants`) or a
//! whole-string, byte-exact match for a registered **carrier**
//! (`holds_bytes:sha256:{prefix}`, `key_grant:{axis}:v1`); anything else is
//! refused `attestation_type_unregistered`. The set is read from the vendored
//! registry's `_meta.row_types` ([`registry::row_types`],
//! [`registry::carrier_row_type`]) and from nothing in this tree.
//!
//! # What v53 enforces, and what it reports
//!
//! - **Carrier shape — ENFORCED.** A carrier row is a self-attestation whose
//!   envelope `kind` is the carrier's and which carries no claim member
//!   (`dimension`, `score`, `confidence`, `weight`, `subject_key_ids`). Every
//!   emitter of a carrier (persist's blob doors and key-grant sets) already
//!   writes that shape, and no other repo emits a carrier.
//! - **The allowlist — REPORTED** ([`ROW_TYPE_ENFORCEMENT`] = `Report`). An
//!   unregistered type is admitted, counted per stem
//!   (`persist_attestation_type_unregistered_total{type_stem}`), and logged.
//!   Production holds 1,060 `consent`-typed rows from 578 authors
//!   (CIRISServer#713); a node re-authors its own as `scores` on its first boot
//!   of server 0.5.219+, and CC asks that no release a server consumes refuse
//!   them before that has rolled out. Server 0.5.220 consumes v53.
//! - **The dimension gate on the four composers (CC 2.4 ask 3) — REPORTED**
//!   under the same switch ([`DimensionAdmissionPolicy::check`]).
//! - **Held rows of an unregistered type** are reported by
//!   [`row_type_report`]; never deleted. Under `Enforce` the two serve reads
//!   (`list_attestations_since`, `list_attestation_log`) leave them out
//!   ([`serve_filter_sql`]).
//!
//! A later release flips [`ROW_TYPE_ENFORCEMENT`] to `Enforce` — one constant,
//! fleet-wide, never a per-node setting (two nodes disagreeing about which rows
//! exist is a partition) — once the report door reads zero admissions under
//! the switch across the fleet.
//!
//! [`DimensionAdmissionPolicy::check`]: super::admission::DimensionAdmissionPolicy::check

use super::namespace::registry::{self, CarrierRowType};
use super::{Attestation, Error, FederationDirectory};
use std::collections::BTreeMap;
use std::sync::Mutex;

/// Whether an unregistered row type is refused or only reported.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RowTypeEnforcement {
    /// Admitted, counted per stem, logged. v53's setting.
    Report,
    /// Refused `attestation_type_unregistered`; held rows left out of the
    /// serve reads.
    Enforce,
}

impl RowTypeEnforcement {
    /// The stable token (`report` / `enforce`).
    #[must_use]
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Report => "report",
            Self::Enforce => "enforce",
        }
    }
}

/// The fleet's setting. See the module doc for why v53 ships `Report`, and
/// for what a later release reads before flipping it.
pub const ROW_TYPE_ENFORCEMENT: RowTypeEnforcement = RowTypeEnforcement::Report;

#[cfg(test)]
tokio::task_local! {
    static ENFORCEMENT_OVERRIDE: RowTypeEnforcement;
}

/// The enforcement in force for the current task: [`ROW_TYPE_ENFORCEMENT`],
/// or (tests only) the mode a witness scoped with [`with_enforcement`].
#[must_use]
pub fn enforcement() -> RowTypeEnforcement {
    #[cfg(test)]
    if let Ok(mode) = ENFORCEMENT_OVERRIDE.try_with(|m| *m) {
        return mode;
    }
    ROW_TYPE_ENFORCEMENT
}

/// Run `fut` with `mode` in force — how a witness measures the refusing
/// branch the shipped constant does not take. Task-scoped, so concurrent
/// tests in one process do not see each other's mode.
#[cfg(test)]
pub async fn with_enforcement<F: std::future::Future>(
    mode: RowTypeEnforcement,
    fut: F,
) -> F::Output {
    ENFORCEMENT_OVERRIDE.scope(mode, fut).await
}

/// What the closed slot makes of a row type.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RowTypeClass {
    /// One of the five.
    Structural,
    /// A registered carrier.
    Carrier(&'static CarrierRowType),
    /// Neither.
    Unregistered,
}

fn row_types() -> &'static registry::RowTypes {
    registry::row_types().expect(
        "the vendored registry carries `_meta.row_types` (CC 2.4, rc6) — a re-vendor that drops \
         it removes the row-type gate's only source",
    )
}

/// Classify `attestation_type` against the vendored `_meta.row_types`:
/// byte-exact, whole-string.
#[must_use]
pub fn classify(attestation_type: &str) -> RowTypeClass {
    if row_types().structural.iter().any(|s| s == attestation_type) {
        return RowTypeClass::Structural;
    }
    match registry::carrier_row_type(attestation_type) {
        Some(c) => RowTypeClass::Carrier(c),
        None => RowTypeClass::Unregistered,
    }
}

/// Is `attestation_type` in the closed set?
#[must_use]
pub fn is_registered(attestation_type: &str) -> bool {
    classify(attestation_type) != RowTypeClass::Unregistered
}

/// The part of the carrier shape a row broke.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CarrierShapeViolation {
    /// `attesting_key_id != attested_key_id`.
    NotSelfAttested,
    /// The envelope `kind` is absent or is not the carrier's.
    KindDisagrees,
    /// The envelope carries a `dimension`.
    CarriesDimension,
    /// The envelope carries a `score`.
    CarriesScore,
    /// The envelope carries a `confidence`.
    CarriesConfidence,
    /// The row carries a `weight`.
    CarriesWeight,
    /// `subject_key_ids` is not empty.
    CarriesSubjects,
}

impl CarrierShapeViolation {
    /// The stable reason token.
    #[must_use]
    pub fn as_str(self) -> &'static str {
        match self {
            Self::NotSelfAttested => "carrier_not_self_attested",
            Self::KindDisagrees => "carrier_kind_disagrees",
            Self::CarriesDimension => "carrier_carries_dimension",
            Self::CarriesScore => "carrier_carries_score",
            Self::CarriesConfidence => "carrier_carries_confidence",
            Self::CarriesWeight => "carrier_carries_weight",
            Self::CarriesSubjects => "carrier_carries_subjects",
        }
    }
}

/// The carrier shape (CC 2.4): which part, if any, `row` breaks.
#[must_use]
pub fn carrier_shape_violation(
    row: &Attestation,
    carrier: &CarrierRowType,
) -> Option<CarrierShapeViolation> {
    use crate::federation::envelope::paths;
    let env = &row.attestation_envelope;
    if row.attesting_key_id != row.attested_key_id {
        return Some(CarrierShapeViolation::NotSelfAttested);
    }
    if env.get("kind").and_then(|k| k.as_str()) != Some(carrier.kind.as_str()) {
        return Some(CarrierShapeViolation::KindDisagrees);
    }
    if env.get(paths::DIMENSION).is_some() {
        return Some(CarrierShapeViolation::CarriesDimension);
    }
    if env.get("score").is_some() {
        return Some(CarrierShapeViolation::CarriesScore);
    }
    if env.get("confidence").is_some() {
        return Some(CarrierShapeViolation::CarriesConfidence);
    }
    if row.weight.is_some() {
        return Some(CarrierShapeViolation::CarriesWeight);
    }
    if !row.subject_key_ids.is_empty() {
        return Some(CarrierShapeViolation::CarriesSubjects);
    }
    None
}

fn unregistered(attestation_type: &str) -> Error {
    Error::AttestationTypeUnregistered {
        attestation_type: attestation_type.to_owned(),
        reason: ATTESTATION_TYPE_UNREGISTERED,
    }
}

/// CC's refusal token. Pinned against `_meta.row_types.refusal` by a witness.
pub const ATTESTATION_TYPE_UNREGISTERED: &str = "attestation_type_unregistered";

/// The row-type gate as a pure function of `row` — no counter, no log. For a
/// door that re-asks a row another door already admitted and counted (the
/// promotion door, the emit mint).
///
/// # Errors
///
/// [`Error::CarrierRowMalformed`] for a carrier of the wrong shape (always);
/// [`Error::AttestationTypeUnregistered`] for an unregistered type under
/// [`RowTypeEnforcement::Enforce`].
pub fn check_row_type(row: &Attestation) -> Result<RowTypeClass, Error> {
    let class = classify(&row.attestation_type);
    match class {
        RowTypeClass::Structural => {}
        RowTypeClass::Carrier(c) => {
            if let Some(v) = carrier_shape_violation(row, c) {
                return Err(Error::CarrierRowMalformed {
                    attestation_type: row.attestation_type.clone(),
                    reason: v.as_str(),
                });
            }
        }
        RowTypeClass::Unregistered => {
            if enforcement() == RowTypeEnforcement::Enforce {
                return Err(unregistered(&row.attestation_type));
            }
        }
    }
    Ok(class)
}

/// The row-type gate at a door that ADMITS a row (the three
/// `put_attestation`s): [`check_row_type`], and an unregistered type admitted
/// under `Report` is counted and logged.
///
/// # Errors
///
/// As [`check_row_type`].
pub fn admit_row_type(row: &Attestation) -> Result<(), Error> {
    if check_row_type(row)? == RowTypeClass::Unregistered {
        record_unregistered_admission(&row.attestation_type, &row.attestation_id);
    }
    Ok(())
}

/// The row-type gate at the local-tier write doors, which hold a type and not
/// yet a row. The carrier shape is asked of the row at the promotion door, the
/// only way a local row reaches the federation plane.
///
/// # Errors
///
/// [`Error::AttestationTypeUnregistered`] under `Enforce`.
pub fn admit_local_row_type(attestation_type: &str) -> Result<(), Error> {
    if classify(attestation_type) == RowTypeClass::Unregistered {
        if enforcement() == RowTypeEnforcement::Enforce {
            return Err(unregistered(attestation_type));
        }
        record_unregistered_admission(attestation_type, "(local)");
    }
    Ok(())
}

/// The metric label for `attestation_type`: its family stem (through the first
/// `:`), at most [`STEM_LABEL_MAX`] characters, control characters replaced.
/// A label is never the raw type: a peer chooses it.
#[must_use]
pub fn type_stem(attestation_type: &str) -> String {
    registry::family_stem(attestation_type)
        .chars()
        .take(STEM_LABEL_MAX)
        .map(|c| if c.is_control() { '?' } else { c })
        .collect()
}

/// Longest metric label kept.
pub const STEM_LABEL_MAX: usize = 64;
/// Most distinct stems counted; the rest share [`OVERFLOW_STEM`]. A peer
/// chooses the type, so the label set must be bounded.
pub const MAX_COUNTED_STEMS: usize = 64;
/// The label beyond [`MAX_COUNTED_STEMS`].
pub const OVERFLOW_STEM: &str = "_other";

static UNREGISTERED_ADMITTED: Mutex<BTreeMap<String, u64>> = Mutex::new(BTreeMap::new());

fn bump(map: &Mutex<BTreeMap<String, u64>>, label: String) {
    let mut m = map
        .lock()
        .unwrap_or_else(std::sync::PoisonError::into_inner);
    let key = if m.contains_key(&label) || m.len() < MAX_COUNTED_STEMS {
        label
    } else {
        OVERFLOW_STEM.to_owned()
    };
    *m.entry(key).or_insert(0) += 1;
}

fn record_unregistered_admission(attestation_type: &str, attestation_id: &str) {
    let stem = type_stem(attestation_type);
    bump(&UNREGISTERED_ADMITTED, stem.clone());
    tracing::warn!(
        metric = "persist_attestation_type_unregistered_total",
        type_stem = %stem,
        attestation_type = ?attestation_type,
        attestation_id = %attestation_id,
        enforcement = ROW_TYPE_ENFORCEMENT.as_str(),
        "admitted a row of an unregistered attestation_type (CC 2.4 closes the slot; \
         CIRISPersist#975 reports it in this release and refuses it once enforcement flips)"
    );
}

/// `persist_attestation_type_unregistered_total{type_stem}` since process
/// start.
#[must_use]
pub fn unregistered_admitted_total() -> Vec<(String, u64)> {
    UNREGISTERED_ADMITTED
        .lock()
        .unwrap_or_else(std::sync::PoisonError::into_inner)
        .iter()
        .map(|(k, v)| (k.clone(), *v))
        .collect()
}

static COMPOSER_DIMENSION_WOULD_REFUSE: Mutex<BTreeMap<String, u64>> = Mutex::new(BTreeMap::new());

/// CC 2.4 ask 3 under `Report`: a composer row (`delegates_to`, `supersedes`,
/// `withdraws`, `recants`) whose `dimension` the scores-row dimension gate
/// refuses was admitted. Counted by `{attestation_type}:{refusal kind}` (both
/// closed sets, so the label set is bounded) and logged.
pub(crate) fn record_composer_dimension_would_refuse(
    attestation_type: &str,
    dimension: &str,
    refusal: &Error,
) {
    let label = format!("{}:{}", type_stem(attestation_type), refusal.kind());
    bump(&COMPOSER_DIMENSION_WOULD_REFUSE, label.clone());
    tracing::warn!(
        metric = "persist_composer_dimension_would_refuse_total",
        label = %label,
        dimension = ?dimension,
        error = %refusal,
        "admitted a composer row whose dimension the scores dimension gate refuses (CC 2.4 ask 3; \
         CIRISPersist#975 reports it in this release and refuses it once enforcement flips)"
    );
}

/// `persist_composer_dimension_would_refuse_total{label}` since process start.
#[must_use]
pub fn composer_dimension_would_refuse_total() -> Vec<(String, u64)> {
    COMPOSER_DIMENSION_WOULD_REFUSE
        .lock()
        .unwrap_or_else(std::sync::PoisonError::into_inner)
        .iter()
        .map(|(k, v)| (k.clone(), *v))
        .collect()
}

/// The claim token a row carries for the readers that predate CC 2.4 — age
/// and capacity assurance: the envelope `dimension` of a `scores` row (CC's
/// shape), else the `attestation_type` itself (the type-slot shape rows
/// already held were written in). Both shapes resolve identically, so an
/// emitter can move to `scores` without its subject's band changing.
#[must_use]
pub fn claim_token(row: &Attestation) -> Option<&str> {
    if row.attestation_type == crate::federation::types::attestation_type::SCORES {
        super::admission::envelope_dimension(&row.attestation_envelope)
    } else {
        Some(row.attestation_type.as_str())
    }
}

// ── the serve filter ─────────────────────────────────────────────────

/// The SQL dialect a predicate is rendered for.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SqlDialect {
    /// SQLite: carriers as `GLOB` (case-sensitive, whole-string).
    Sqlite,
    /// PostgreSQL: carriers as an anchored `~` regular expression.
    Postgres,
}

fn sql_quote(s: &str) -> String {
    format!("'{}'", s.replace('\'', "''"))
}

/// A carrier pattern body rendered as the GLOB patterns that match exactly
/// the same strings. Understands the grammar CC's carrier patterns use —
/// literal `[a-z0-9_:]`, a bracket class with an optional `{n}`, and an
/// alternation group of literals — and panics on anything else, so a
/// re-vendor that widens the grammar fails the parity witness instead of
/// filtering wrongly.
fn carrier_globs(pattern: &str) -> Vec<String> {
    let body = pattern.trim_start_matches('^').trim_end_matches('$');
    let b = body.as_bytes();
    let mut out = vec![String::new()];
    let mut i = 0;
    while i < b.len() {
        match b[i] {
            b'[' => {
                let end = body[i..].find(']').expect("a closed bracket class") + i;
                let class = &body[i..=end];
                i = end + 1;
                let mut n = 1;
                if i < b.len() && b[i] == b'{' {
                    let close = body[i..].find('}').expect("a closed repeat") + i;
                    n = body[i + 1..close].parse().expect("an exact repeat count");
                    i = close + 1;
                }
                for s in &mut out {
                    for _ in 0..n {
                        s.push_str(class);
                    }
                }
            }
            b'(' => {
                let close = body[i..].find(')').expect("a closed group") + i;
                let alts: Vec<&str> = body[i + 1..close].split('|').collect();
                for a in &alts {
                    assert!(
                        a.bytes()
                            .all(|c| c.is_ascii_lowercase() || c.is_ascii_digit() || c == b'_'),
                        "carrier alternation {a:?} is not a literal"
                    );
                }
                out = out
                    .iter()
                    .flat_map(|s| alts.iter().map(move |a| format!("{s}{a}")))
                    .collect();
                i = close + 1;
            }
            c if c.is_ascii_lowercase() || c.is_ascii_digit() || c == b'_' || c == b':' => {
                for s in &mut out {
                    s.push(c as char);
                }
                i += 1;
            }
            c => panic!(
                "carrier pattern {pattern:?}: {:?} is outside the grammar the serve filter renders",
                c as char
            ),
        }
    }
    out
}

/// `column` is a registered row type, as a SQL boolean expression generated
/// from the vendored registry (the five as literals, each carrier as its
/// dialect's whole-string match).
#[must_use]
pub fn registered_row_type_sql(column: &str, dialect: SqlDialect) -> String {
    let rt = row_types();
    let mut arms = vec![format!(
        "{column} IN ({})",
        rt.structural
            .iter()
            .map(|s| sql_quote(s))
            .collect::<Vec<_>>()
            .join(", ")
    )];
    for c in &rt.carriers {
        match dialect {
            SqlDialect::Sqlite => {
                for g in carrier_globs(&c.pattern) {
                    arms.push(format!("{column} GLOB {}", sql_quote(&g)));
                }
            }
            SqlDialect::Postgres => {
                let body = c.pattern.trim_start_matches('^').trim_end_matches('$');
                arms.push(format!(
                    "{column} ~ {}",
                    sql_quote(&format!("^(?:{body})$"))
                ));
            }
        }
    }
    format!("({})", arms.join(" OR "))
}

/// The serve-read filter: `Some(predicate)` under `Enforce` (held rows of an
/// unregistered type are neither served nor replicated), `None` under
/// `Report`. Read once per query, on the calling task.
#[must_use]
pub fn serve_filter_sql(column: &str, dialect: SqlDialect) -> Option<String> {
    (enforcement() == RowTypeEnforcement::Enforce).then(|| registered_row_type_sql(column, dialect))
}

/// The memory backend's serve filter: does `row` survive it?
#[must_use]
pub fn served_under_enforcement(row: &Attestation) -> bool {
    enforcement() == RowTypeEnforcement::Report || is_registered(&row.attestation_type)
}

// ── the report door ──────────────────────────────────────────────────

/// One stored `attestation_type` and how many rows carry it.
#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub struct AttestationTypeCount {
    /// The type, verbatim.
    pub attestation_type: String,
    /// Rows of that type, every tier.
    pub count: u64,
    /// Earliest `asserted_at`.
    pub oldest: chrono::DateTime<chrono::Utc>,
    /// Latest `asserted_at`.
    pub newest: chrono::DateTime<chrono::Utc>,
}

/// One held type the closed slot does not register.
#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize)]
pub struct UnregisteredRowType {
    /// The type, verbatim.
    pub attestation_type: String,
    /// Its family stem ([`type_stem`]).
    pub type_stem: String,
    /// Rows held, every tier.
    pub count: u64,
    /// Earliest `asserted_at`.
    pub oldest: chrono::DateTime<chrono::Utc>,
    /// Latest `asserted_at`.
    pub newest: chrono::DateTime<chrono::Utc>,
}

/// A counter, as the report door returns it.
#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize)]
pub struct LabelCount {
    /// The label.
    pub label: String,
    /// Count since process start.
    pub count: u64,
}

/// What the row-type gate sees on this node — CC 2.4 ask 4's inventory, from
/// the node itself.
#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize)]
pub struct RowTypeReport {
    /// `report` or `enforce`.
    pub enforcement: &'static str,
    /// Held rows of an unregistered type, by exact type. Never deleted.
    pub held_unregistered: Vec<UnregisteredRowType>,
    /// `persist_attestation_type_unregistered_total{type_stem}`.
    pub admitted_unregistered: Vec<LabelCount>,
    /// `persist_composer_dimension_would_refuse_total{label}`.
    pub composer_dimension_would_refuse: Vec<LabelCount>,
}

/// Build the [`RowTypeReport`] from `dir`'s census and this process's
/// counters.
///
/// # Errors
///
/// The census read's.
pub async fn row_type_report(dir: &dyn FederationDirectory) -> Result<RowTypeReport, Error> {
    let held_unregistered = dir
        .attestation_type_census()
        .await?
        .into_iter()
        .filter(|c| !is_registered(&c.attestation_type))
        .map(|c| UnregisteredRowType {
            type_stem: type_stem(&c.attestation_type),
            attestation_type: c.attestation_type,
            count: c.count,
            oldest: c.oldest,
            newest: c.newest,
        })
        .collect();
    let counts = |v: Vec<(String, u64)>| {
        v.into_iter()
            .map(|(label, count)| LabelCount { label, count })
            .collect()
    };
    Ok(RowTypeReport {
        enforcement: enforcement().as_str(),
        held_unregistered,
        admitted_unregistered: counts(unregistered_admitted_total()),
        composer_dimension_would_refuse: counts(composer_dimension_would_refuse_total()),
    })
}
