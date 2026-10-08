//! v53.1.8 (CIRISPersist#1014, CIRISServer#746 §3.3) — **persist's telemetry
//! name registry**, in the style of leviculum's `EVENT_CATALOG`: every
//! metric persist emits, with its kind, unit, label keys and each key's
//! bounded value set. The host merges the four repos' catalogues into its
//! `/metrics` HELP text; the completeness gate (`observe::tests`) fails when
//! code emits a door or fold this table does not list, or the table lists one
//! nothing emits.
//!
//! Names follow the OpenTelemetry conventions (`ciris.persist.read.rows`,
//! unit `{row}`), which render to Prometheus mechanically
//! (`ciris_persist_read_rows_total`). The label value lists are written out
//! here by hand on purpose: a door added to [`super::Door`] is not catalogued
//! until someone adds it below.

/// What a metric is.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum MetricKind {
    /// Monotone; only ever increases.
    Counter,
}

/// A label key and the only values it may carry.
#[derive(Debug, Clone, Copy)]
pub struct LabelSpec {
    /// The label key.
    pub key: &'static str,
    /// Its bounded value set.
    pub values: &'static [&'static str],
}

/// One catalogued metric.
#[derive(Debug, Clone, Copy)]
pub struct CatalogEntry {
    /// The OTel-style metric name.
    pub name: &'static str,
    /// Its kind.
    pub kind: MetricKind,
    /// Its UCUM unit (`{read}`, `{row}`, `By`, ...).
    pub unit: &'static str,
    /// Its labels.
    pub labels: &'static [LabelSpec],
    /// What it counts.
    pub description: &'static str,
}

impl CatalogEntry {
    /// The [`metrics::Unit`] [`super::emit_metrics`] describes this entry with:
    /// `By` is [`metrics::Unit::Bytes`], and a UCUM annotation (`{row}`,
    /// `{read}`, `{call}`) is a dimensionless count, [`metrics::Unit::Count`].
    /// `None` for a unit this map does not know; I553 fails on any catalogued
    /// entry that maps to `None`, so a new unit is mapped before it ships.
    pub(crate) fn metrics_unit(&self) -> Option<metrics::Unit> {
        match self.unit {
            "By" => Some(metrics::Unit::Bytes),
            u if u.len() > 2 && u.starts_with('{') && u.ends_with('}') => {
                Some(metrics::Unit::Count)
            }
            _ => None,
        }
    }
}

/// The `backend` label key.
pub const LABEL_BACKEND: &str = "backend";
/// The `door` label key.
pub const LABEL_DOOR: &str = "door";
/// The `fold` label key.
pub const LABEL_FOLD: &str = "fold";

/// Door reads served.
pub const READ_CALLS: &str = "ciris.persist.read.calls";
/// Rows door reads returned.
pub const READ_ROWS: &str = "ciris.persist.read.rows";
/// Envelope bytes door reads decoded.
pub const READ_BYTES: &str = "ciris.persist.read.bytes";
/// Entries into a fold.
pub const FOLD_CALLS: &str = "ciris.persist.fold.calls";
/// Door reads made inside a fold.
pub const FOLD_READS: &str = "ciris.persist.fold.reads";
/// Rows the reads inside a fold returned.
pub const FOLD_ROWS: &str = "ciris.persist.fold.rows";
/// Envelope bytes the reads inside a fold decoded.
pub const FOLD_BYTES: &str = "ciris.persist.fold.bytes";

/// Every `backend` label value.
pub const BACKEND_VALUES: &[&str] = &["memory", "sqlite", "postgres"];

/// Every `door` label value.
pub const DOOR_VALUES: &[&str] = &[
    "list_attestations",
    "list_attestations_by",
    "list_attestations_by_dimension_citing",
    "list_attestations_by_dimension_prefix",
    "list_attestations_by_type",
    "list_attestations_by_types",
    "list_attestations_for",
    "list_attestations_for_dimension_prefix",
    "list_attestations_for_type",
    "list_attestations_for_types",
    "list_attestations_referencing",
    "list_composers_referencing_any",
    "list_targeted_by_dimension_prefix",
    "list_live_consent_grants_by",
    "list_live_consent_grants_for",
    "list_local_tier_attestations",
    "list_widening_candidates",
    "list_attestations_for_migration",
    "attestations_binding_content",
    "get_attestation",
    "list_attestations_since",
    "list_attestation_log",
];

/// Every `fold` label value.
pub const FOLD_VALUES: &[&str] = &[
    "resolve_scoped_stance_by_principals",
    "resolve_scoped_stance",
    "trusted_roots_of",
    "trust_root_valid",
    "resolve_serve_tier",
    "owner_granted_scope",
    "owner_allow_list",
    "is_public_group",
    "owner_audience",
    "attestation_admission",
];

const DOOR_LABELS: &[LabelSpec] = &[
    LabelSpec {
        key: LABEL_BACKEND,
        values: BACKEND_VALUES,
    },
    LabelSpec {
        key: LABEL_DOOR,
        values: DOOR_VALUES,
    },
];

const FOLD_LABELS: &[LabelSpec] = &[LabelSpec {
    key: LABEL_FOLD,
    values: FOLD_VALUES,
}];

/// The registry.
pub const TELEMETRY_CATALOG: &[CatalogEntry] = &[
    CatalogEntry {
        name: READ_CALLS,
        kind: MetricKind::Counter,
        unit: "{read}",
        labels: DOOR_LABELS,
        description: "Attestation-returning door reads served, by backend and door.",
    },
    CatalogEntry {
        name: READ_ROWS,
        kind: MetricKind::Counter,
        unit: "{row}",
        labels: DOOR_LABELS,
        description: "Rows the door reads returned, by backend and door.",
    },
    CatalogEntry {
        name: READ_BYTES,
        kind: MetricKind::Counter,
        unit: "By",
        labels: DOOR_LABELS,
        description: "Stored attestation_envelope bytes the door reads decoded, by backend and \
                      door (sqlite/postgres: the TEXT column's length; memory: 0).",
    },
    CatalogEntry {
        name: FOLD_CALLS,
        kind: MetricKind::Counter,
        unit: "{call}",
        labels: FOLD_LABELS,
        description: "Entries into a fold (consent, trust-root walk, audience, serve tier, \
                      attestation admission).",
    },
    CatalogEntry {
        name: FOLD_READS,
        kind: MetricKind::Counter,
        unit: "{read}",
        labels: FOLD_LABELS,
        description: "Door reads made while the fold ran, inclusive of nested folds.",
    },
    CatalogEntry {
        name: FOLD_ROWS,
        kind: MetricKind::Counter,
        unit: "{row}",
        labels: FOLD_LABELS,
        description: "Rows returned to the door reads made while the fold ran, inclusive of \
                      nested folds.",
    },
    CatalogEntry {
        name: FOLD_BYTES,
        kind: MetricKind::Counter,
        unit: "By",
        labels: FOLD_LABELS,
        description: "Envelope bytes decoded by the door reads made while the fold ran, \
                      inclusive of nested folds.",
    },
];
