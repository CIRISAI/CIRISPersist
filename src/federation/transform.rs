//! v21.6.0 (CIRISPersist#519 item 2a-ii) — the **total (terminating) transform
//! algebra**: a closed, named-opcode vocabulary for "what a placement field
//! BECOMES on an egress path", vendored from `namespace_supersets.json`'s
//! `field_transforms` section (see [`super::namespace::supersets::field_transforms`]).
//!
//! # The non-negotiable invariant
//!
//! **STRICTLY TOTAL.** Named opcodes, fixed arity, NO loops, NO recursion, NO
//! user-defined functions. Composition is a finite DAG ([`TransformPipeline`]
//! is literally a `Vec`), so a registry row — or a compiled pipeline — is its
//! own termination witness: there is no way to write one that doesn't halt,
//! because the algebra has no construct capable of not halting.
//!
//! This sits in the admission/serve path. A non-terminating transform would
//! wedge that gate; a Turing-complete dialect could express the very
//! selective-disclosure/consent flows this architecture is built to make
//! *unrepresentable* (an attacker-authored "transform" that loops forever, or
//! one that smuggles logic the CI rubric never reviewed, is not a bug to
//! patch — it is a category the type system refuses to construct). Precedent
//! for this posture: Bitcoin Script (no loops, by design); the EVM (only
//! quasi-Turing-complete, gas-metered); FHIRPath ("entirely declarative, no
//! imperative aspects"); Confluent data contracts (non-Turing-complete
//! CEL/JSONata rule dialects).
//!
//! # What this is deliberately NOT
//!
//! - **NOT version-migration rules.** Confluent's own schema-registry design
//!   keeps data-transform rules and schema-migration rules in separate
//!   registries; fusing them produces an unauditable one where "does this
//!   field change SHAPE" and "does this field change MEANING across a schema
//!   bump" can no longer be told apart by inspection.
//! - **NOT heavy computation.** The trace PII scrubber (NER+regex), the
//!   `trace_summary` feature-vector extractor, and the RATCHET
//!   detectors/scorers are NOT opcodes — they stay pinned by their own
//!   contract hash ([`super::rooting`]/`TRACE_SUMMARY_EXTRACTION_SHA256`-style
//!   constants elsewhere in the crate), never expressed in this algebra. An
//!   unbounded ML pass has no place in a total-by-construction dispatch.
//! - **NOT access control.** A transform changes what a field *becomes* on an
//!   egress path; it never decides *whether* the row is served at all — that
//!   remains `cohort_scope` / consent / capability territory
//!   ([`super::consent_grammar`], [`super::replication_policy`]).
//!
//! # Live vs. declared-only opcodes
//!
//! Every opcode in [`OPCODES`] is validated as a KNOWN member of the closed
//! set (arity/shape-checked by [`validate_family_transform_rows`]) — that's
//! what makes the algebra *complete*: a family may reference any of them.
//! Only some are *wired* ([`apply`] actually computes a result):
//!
//! | status | opcodes | why |
//! |---|---|---|
//! | **live** | `truncate`, `prefix`, `suffix`, `bucket`, `round`, `concat`, `redact`, `strip_field`, `salted_hash`, `gte`, `lt`, `in_range` | pure + total with std/existing crypto deps already in this crate (`sha2`, `chrono`, `serde_json`) — no new primitive needed. |
//! | **declared-only** | `commit`, `nullifier`, `bbs_derive` | need a primitive this cut does not wire: `commit`'s Pedersen form and `nullifier` (Semaphore) want a curve/field this crate doesn't carry yet (a plain-sha256 `commit` form IS live-able, but is deliberately left declared-only alongside its Semaphore sibling rather than half-wiring the family — see `trace_manifest:*`'s `family_transform_rows` entry, itself flagged `asymmetry_kind: logical_defect`); `bbs_derive` (BBS+ signatures) needs a pairing-friendly-curve library this crate does not depend on. [`apply`] returns [`TransformError::NotYetImplemented`] for these — a typed, closed refusal, not a panic or a missing match arm. |
//!
//! Declared-only is a **runtime** refusal, never a **validation** refusal:
//! [`validate_family_transform_rows`] accepts a family row naming `commit` (the
//! `trace_manifest:*` row does exactly this today) because the algebra is
//! complete over the opcode *name* — wiring is a separate, trackable axis
//! ([`OpcodeMeta::status`]).
//!
//! # Scope discipline — NOT this cut (follow-ups, not built here)
//!
//! - **Wiring the full op set into the promotion/serve path.** Only
//!   `strip_field` is actually applied today, at promotion
//!   ([`Engine::promote_attestation_with_strips`](crate::Engine) via
//!   [`super::consent_grammar::strip_field`], CIRISPersist#510). Generalizing
//!   promotion/serve to run an arbitrary [`TransformPipeline`] over a
//!   family's declared rows is a follow-up.
//! - **The crypto opcodes' full implementations** (`bbs_derive`'s actual
//!   derived-proof math, `commit`'s Pedersen form, `nullifier`'s Semaphore
//!   construction) — declared in the closed enum so the algebra is complete
//!   and a family can reference them, not built here.
//!
//! # The manifest-hash discipline
//!
//! [`TRANSFORM_ALGEBRA_HASH`] is the third manifest-hash pin in this style
//! (mirrors [`super::replication_policy::REPLICATION_POLICY_HASH`] and
//! [`super::consent_grammar::CONSENT_GRAMMAR_HASH`] exactly): sha256 over JCS
//! of [`algebra_manifest`], gated by the
//! `tests::transform_algebra_hash_is_pinned` witness. A silent opcode change —
//! a new variant, a changed arity, a flipped live/declared status — moves the
//! hash and fails the build until deliberately re-pinned.

use serde::{Deserialize, Serialize};
use serde_json::Value;

// ─────────────────────────── the closed opcode metadata ─────────────────

/// Wiring status of an [`OpcodeMeta`] entry — see the module doc's
/// "live vs. declared-only" table.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum OpcodeStatus {
    /// [`apply`] computes a real result for this opcode today.
    Live,
    /// [`apply`] returns [`TransformError::NotYetImplemented`] for this
    /// opcode — declared (validated as a known opcode name, referenceable by
    /// a family row) but not yet wired.
    DeclaredOnly,
}

impl OpcodeStatus {
    /// The wire/manifest string for this status (used by [`algebra_manifest`]).
    #[must_use]
    pub fn as_str(self) -> &'static str {
        match self {
            OpcodeStatus::Live => "live",
            OpcodeStatus::DeclaredOnly => "declared_only",
        }
    }
}

/// One opcode's metadata, mirroring a `field_transforms.opcodes` entry from
/// the vendored manifest (`opcode`/`arity`/`input_type`/`output_type`) plus
/// this crate's own live-vs-declared annotation. [`OPCODES`] is the single
/// source [`algebra_manifest`], [`is_total`]'s witness, and
/// [`validate_family_transform_rows`]'s known-opcode set all read from.
#[derive(Debug, Clone, Copy)]
pub struct OpcodeMeta {
    /// The wire opcode name (`op` tag / manifest `opcode` field).
    pub name: &'static str,
    /// Fixed arity, per the manifest (op-level constant data — e.g.
    /// `bucket`'s `edges` or `gte`'s threshold — counts as an argument
    /// alongside the runtime `input`, matching the manifest's own count).
    pub arity: u8,
    /// The manifest's `input_type` string (informational — not
    /// mechanically enforced beyond what [`apply`]'s match does).
    pub input_type: &'static str,
    /// The manifest's `output_type` string.
    pub output_type: &'static str,
    /// Live vs. declared-only — see the module doc.
    pub status: OpcodeStatus,
}

/// The complete, closed opcode set — one entry per [`TransformOp`] variant,
/// in the same order as `namespace_supersets.json`'s `field_transforms.opcodes`
/// (checked by `tests::rust_opcode_metadata_matches_vendored_manifest`).
pub const OPCODES: &[OpcodeMeta] = &[
    OpcodeMeta {
        name: "truncate",
        arity: 1,
        input_type: "string|bytes",
        output_type: "string|bytes",
        status: OpcodeStatus::Live,
    },
    OpcodeMeta {
        name: "prefix",
        arity: 1,
        input_type: "string",
        output_type: "string",
        status: OpcodeStatus::Live,
    },
    OpcodeMeta {
        name: "suffix",
        arity: 1,
        input_type: "string",
        output_type: "string",
        status: OpcodeStatus::Live,
    },
    OpcodeMeta {
        name: "bucket",
        arity: 1,
        input_type: "number|timestamp",
        output_type: "enum",
        status: OpcodeStatus::Live,
    },
    OpcodeMeta {
        name: "round",
        arity: 1,
        input_type: "number|timestamp",
        output_type: "number|timestamp",
        status: OpcodeStatus::Live,
    },
    OpcodeMeta {
        name: "concat",
        arity: 2,
        input_type: "string,string",
        output_type: "string",
        status: OpcodeStatus::Live,
    },
    OpcodeMeta {
        name: "redact",
        arity: 1,
        input_type: "any",
        output_type: "null|placeholder",
        status: OpcodeStatus::Live,
    },
    OpcodeMeta {
        name: "strip_field",
        arity: 1,
        input_type: "json-pointer",
        output_type: "object",
        status: OpcodeStatus::Live,
    },
    OpcodeMeta {
        name: "salted_hash",
        arity: 2,
        input_type: "bytes,salt",
        output_type: "digest",
        status: OpcodeStatus::Live,
    },
    OpcodeMeta {
        name: "commit",
        arity: 1,
        input_type: "bytes",
        output_type: "commitment",
        status: OpcodeStatus::DeclaredOnly,
    },
    OpcodeMeta {
        name: "nullifier",
        arity: 2,
        input_type: "epoch,scope",
        output_type: "digest",
        status: OpcodeStatus::DeclaredOnly,
    },
    OpcodeMeta {
        name: "bbs_derive",
        arity: 1,
        input_type: "signed-credential",
        output_type: "derived-proof",
        status: OpcodeStatus::DeclaredOnly,
    },
    OpcodeMeta {
        name: "gte",
        arity: 2,
        input_type: "number|timestamp,threshold",
        output_type: "bool",
        status: OpcodeStatus::Live,
    },
    OpcodeMeta {
        name: "lt",
        arity: 2,
        input_type: "number|timestamp,threshold",
        output_type: "bool",
        status: OpcodeStatus::Live,
    },
    OpcodeMeta {
        name: "in_range",
        arity: 3,
        input_type: "number,lo,hi",
        output_type: "bool",
        status: OpcodeStatus::Live,
    },
];

// ─────────────────────────── the closed op enum ──────────────────────────

/// One transform operation — a closed, internally-tagged enum
/// (`#[serde(tag = "op", deny_unknown_fields)]`, mirroring
/// [`super::consent_grammar::RestrictionOp`]'s discipline exactly): an
/// unrecognized `op` tag, or an unknown field on a recognized one, is a
/// serde deserialize ERROR — never a silently-skipped/ignored variant.
///
/// Every variant here is a member of [`OPCODES`] (name, arity, shape) — the
/// enum IS the algebra; [`OPCODES`] is that same algebra's metadata mirror
/// (kept honest by `tests::rust_opcode_metadata_matches_vendored_manifest`).
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(tag = "op", deny_unknown_fields)]
pub enum TransformOp {
    /// Keep at most the first `n` length-units: `char`s for a
    /// [`Value::String`], elements for a [`Value::Array`] (the "bytes"
    /// case — an opaque byte payload riding as a JSON array). Polymorphic
    /// over `string|bytes`, unlike [`TransformOp::Prefix`] (string-only) —
    /// that's why the manifest keeps them as two named opcodes even though
    /// they coincide on a string input.
    #[serde(rename = "truncate")]
    Truncate {
        /// Maximum length to keep.
        n: usize,
    },
    /// The string-only k-anonymity generalization primitive (e.g. an IP
    /// prefix, a ZIP+4 → ZIP-5 truncation): keep the first `n` `char`s.
    /// Behaviorally identical to [`TransformOp::Truncate`] on a string
    /// input today; kept distinct because the manifest's CI-rubric review
    /// treats "bytes-safety" and "string generalization" as different
    /// primitives (a future revision may diverge them, e.g. `truncate`
    /// marking elision with a suffix marker while `prefix` never does).
    #[serde(rename = "prefix")]
    Prefix {
        /// Number of leading `char`s to keep.
        n: usize,
    },
    /// Keep the last `n` `char`s of a string.
    #[serde(rename = "suffix")]
    Suffix {
        /// Number of trailing `char`s to keep.
        n: usize,
    },
    /// k-anonymity-style generalization: given a fixed, ascending
    /// `edges` cut-point list (registry DATA, not code), map a
    /// number or RFC3339 timestamp to the index of the bucket it falls
    /// in (`0` = below every edge, `edges.len()` = at-or-above the last
    /// edge).
    #[serde(rename = "bucket")]
    Bucket {
        /// Ascending cut points. Not re-sorted by [`apply`] — an
        /// out-of-order list is the registry curator's error, not a
        /// termination hazard (the count-based index is well-defined for
        /// any finite list regardless of ordering).
        edges: Vec<f64>,
    },
    /// Differential-privacy-style coarsening: round a number to
    /// `precision` decimal places (negative `precision` rounds to a power
    /// of ten — e.g. `-2` → nearest 100), or coarsen an RFC3339 timestamp
    /// to the nearest `10.pow(max(precision, 0))`-second bucket. This is
    /// ALSO the coalescing primitive [`super::admission`]'s `fresh_as_of`
    /// floor composes with (a signed freshness bound is only meaningful at
    /// a coarsened granularity, never wall-clock-exact).
    #[serde(rename = "round")]
    Round {
        /// Decimal places (number) / order-of-magnitude-seconds
        /// (timestamp, clamped to `0..=18` to stay within `i64`).
        precision: i32,
    },
    /// Join two scalars with a separator. Conceptually arity-2 (two
    /// operands), kept total under the one-`input`/`apply` shape by
    /// requiring `input` to already be the 2-element bundle: a
    /// [`Value::Array`] of exactly two scalars (string/number/bool/null —
    /// resolving two *named* envelope fields into that array is the
    /// caller's job, e.g. a pipeline stage upstream of this one).
    #[serde(rename = "concat")]
    Concat {
        /// The separator inserted between the two operands.
        sep: String,
    },
    /// Replace any input with `null` (no `placeholder`) or a fixed
    /// placeholder string — the "any → null|placeholder" opcode. Ignores
    /// `input` entirely (total over every shape by construction: there is
    /// no input this can fail to redact).
    #[serde(rename = "redact")]
    Redact {
        /// `Some(text)` replaces with that literal string;
        /// `None` (the default) replaces with `Value::Null`.
        #[serde(default)]
        placeholder: Option<String>,
    },
    /// Strip a JSON-pointer-with-wildcard `path` from `input` (which must
    /// be the envelope object). CIRISPersist#519 item 2a-ii moved the
    /// canonical implementation here from
    /// [`super::consent_grammar::strip_field`] (now a thin wrapper over
    /// `apply(&TransformOp::StripField{path}, ..)` — ONE strip
    /// implementation). See [`strip_field_impl`] for the exact semantics
    /// (wildcard fan-out, missing-path no-op, protected-root-member
    /// refusal).
    #[serde(rename = "strip_field")]
    StripField {
        /// The `/`-separated JSON pointer to strip, e.g.
        /// `"/trace/llm_calls/*/prompt"`.
        path: String,
    },
    /// SD-JWT's selective-disclosure primitive: `sha256(salt_ref ‖ 0x00 ‖
    /// value)` over a string `input`. `salt_ref` carries the literal salt
    /// value inline today (a base64 or plain-UTF-8 string) — a
    /// salt-vault indirection (resolving a `salt_ref` *identifier* to
    /// out-of-band salt material) is out of scope for this cut; the NUL
    /// delimiter between salt and value avoids the
    /// `salt_ref="ab",value="c"` / `salt_ref="a",value="bc"` collision a
    /// bare concatenation would allow.
    #[serde(rename = "salted_hash")]
    SaltedHash {
        /// The salt (see field doc for today's "inline literal" caveat).
        salt_ref: String,
    },
    /// Pedersen (or sha256-form) commitment over `input` bytes —
    /// integrity-only, NOT an availability guarantee (a commitment proves
    /// "this is the same value", never "the value is retrievable"; see
    /// the `trace_manifest:*` `family_transform_rows` entry). **Declared,
    /// not wired** — see the module doc's live/declared table.
    #[serde(rename = "commit")]
    Commit,
    /// Semaphore-style nullifier: one identity yields one digest per
    /// `(epoch, scope)`, enabling double-emit detection without
    /// revealing identity. **Declared, not wired.**
    #[serde(rename = "nullifier")]
    Nullifier {
        /// The epoch the nullifier is scoped to.
        epoch: String,
        /// The scope the nullifier is scoped to.
        scope: String,
    },
    /// BBS+ selective-disclosure derivation over a signed credential set.
    /// **Declared, not wired** — needs a pairing-friendly-curve dependency
    /// this crate does not carry.
    #[serde(rename = "bbs_derive")]
    BbsDerive,
    /// Predicate: discloses only whether `input >= v` — never `input`
    /// itself (age-over-18-style gates).
    #[serde(rename = "gte")]
    Gte {
        /// The threshold.
        v: f64,
    },
    /// Predicate: discloses only whether `input < v`.
    #[serde(rename = "lt")]
    Lt {
        /// The threshold.
        v: f64,
    },
    /// Predicate: discloses only whether `lo <= input <= hi`.
    #[serde(rename = "in_range")]
    InRange {
        /// Inclusive lower bound.
        lo: f64,
        /// Inclusive upper bound.
        hi: f64,
    },
}

/// The failure surface for [`apply`]. Never a panic, never non-termination —
/// every arm of [`apply`]'s match returns (that IS the totality claim); this
/// type covers the "the op is fine but the input/op-data don't line up" and
/// "the op is a real member of the closed set but not yet wired" cases.
#[derive(Debug, Clone, PartialEq, thiserror::Error)]
pub enum TransformError {
    /// `input` (or an op-data field) was the wrong JSON shape for this
    /// opcode.
    #[error("transform input type mismatch: expected {expected}, got {got}")]
    TypeMismatch {
        /// What the opcode needed.
        expected: &'static str,
        /// What it got (a [`Value`] type name).
        got: &'static str,
    },
    /// `input` was the right JSON type but malformed in a way that
    /// prevents computing a result (e.g. a string that doesn't parse as
    /// RFC3339 where a timestamp was expected).
    #[error("transform input malformed: {0}")]
    Malformed(String),
    /// A real, closed-enum, arity-checked opcode — just not wired yet
    /// (see the module doc's live/declared table). A typed, deliberate
    /// refusal, not a missing match arm.
    #[error(
        "transform opcode {op:?} is declared in the closed algebra (validated, arity-checked) \
         but not yet wired to a live implementation — runtime-refused by design"
    )]
    NotYetImplemented {
        /// The declared-only opcode name.
        op: &'static str,
    },
}

// ─────────────────────────── total dispatch ──────────────────────────────

/// Apply one [`TransformOp`] to `input`. **Total dispatch**: the match is
/// exhaustive over every [`TransformOp`] variant — a new opcode added to the
/// enum without an arm here is a **compile error**, the same
/// KindPolicy/Registry-of-Record discipline
/// [`super::replication_policy::policy_for`] and
/// [`super::consent_grammar::consent_transferability`] use for their own
/// exhaustive matches.
///
/// "Total" here means *terminating* (every arm returns; there is no loop,
/// no recursion beyond [`strip_field_impl`]'s bounded descent through
/// `input`'s own finite JSON structure, no user-defined function to diverge
/// in) — NOT that every input succeeds. A wrong-shaped `input` is a
/// [`TransformError`], never a panic or a hang.
pub fn apply(op: &TransformOp, input: &Value) -> Result<Value, TransformError> {
    match op {
        TransformOp::Truncate { n } => truncate_value(input, *n),
        TransformOp::Prefix { n } => prefix_value(input, *n),
        TransformOp::Suffix { n } => suffix_value(input, *n),
        TransformOp::Bucket { edges } => bucket_value(input, edges),
        TransformOp::Round { precision } => round_value(input, *precision),
        TransformOp::Concat { sep } => concat_value(input, sep),
        TransformOp::Redact { placeholder } => Ok(redact_value(placeholder)),
        TransformOp::StripField { path } => {
            let mut out = input.clone();
            strip_field_impl(&mut out, path);
            Ok(out)
        }
        TransformOp::SaltedHash { salt_ref } => salted_hash_value(input, salt_ref),
        TransformOp::Commit => Err(TransformError::NotYetImplemented { op: "commit" }),
        TransformOp::Nullifier { .. } => Err(TransformError::NotYetImplemented { op: "nullifier" }),
        TransformOp::BbsDerive => Err(TransformError::NotYetImplemented { op: "bbs_derive" }),
        TransformOp::Gte { v } => gte_value(input, *v),
        TransformOp::Lt { v } => lt_value(input, *v),
        TransformOp::InRange { lo, hi } => in_range_value(input, *lo, *hi),
    }
}

/// The machine-checkable "this algebra is total" claim: every
/// [`TransformOp`] variant returns `true`, by construction — the match is
/// exhaustive (a new variant without an arm here is a compile error,
/// exactly like [`apply`]'s dispatch), so this function's mere existence
/// (plus `tests::every_opcode_is_total` iterating a sample of every
/// variant) IS the witness, not a runtime property being measured.
#[must_use]
pub fn is_total(op: &TransformOp) -> bool {
    match op {
        TransformOp::Truncate { .. }
        | TransformOp::Prefix { .. }
        | TransformOp::Suffix { .. }
        | TransformOp::Bucket { .. }
        | TransformOp::Round { .. }
        | TransformOp::Concat { .. }
        | TransformOp::Redact { .. }
        | TransformOp::StripField { .. }
        | TransformOp::SaltedHash { .. }
        | TransformOp::Commit
        | TransformOp::Nullifier { .. }
        | TransformOp::BbsDerive
        | TransformOp::Gte { .. }
        | TransformOp::Lt { .. }
        | TransformOp::InRange { .. } => true,
    }
}

/// A finite, ordered composition of [`TransformOp`]s — the algebra's DAG
/// primitive. [`TransformPipeline::apply_all`] folds left-to-right; a
/// pipeline's `Vec` length IS its own termination bound (finite at
/// construction time, decremented by exactly one per fold step, no element
/// visited twice) — the same "the registry row is its own termination
/// witness" property the module doc claims for a single opcode extends
/// unchanged to a whole pipeline.
#[derive(Debug, Clone, Default, PartialEq, Serialize, Deserialize)]
pub struct TransformPipeline(pub Vec<TransformOp>);

impl TransformPipeline {
    /// Number of stages.
    #[must_use]
    pub fn len(&self) -> usize {
        self.0.len()
    }

    /// True iff this pipeline has no stages (folding it is the identity).
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.0.is_empty()
    }

    /// Fold [`apply`] over every stage, left-to-right, threading each
    /// stage's output into the next stage's input. Stops at the first
    /// [`TransformError`] (fail-closed — a mid-pipeline failure never
    /// silently yields a partially-transformed value).
    pub fn apply_all(&self, input: &Value) -> Result<Value, TransformError> {
        let mut current = input.clone();
        for op in &self.0 {
            current = apply(op, &current)?;
        }
        Ok(current)
    }
}

// ─────────────────────────── opcode implementations ──────────────────────

fn json_type_name(v: &Value) -> &'static str {
    match v {
        Value::Null => "null",
        Value::Bool(_) => "bool",
        Value::Number(_) => "number",
        Value::String(_) => "string",
        Value::Array(_) => "array",
        Value::Object(_) => "object",
    }
}

fn truncate_value(input: &Value, n: usize) -> Result<Value, TransformError> {
    match input {
        Value::String(s) => Ok(Value::String(s.chars().take(n).collect())),
        Value::Array(a) => Ok(Value::Array(a.iter().take(n).cloned().collect())),
        other => Err(TransformError::TypeMismatch {
            expected: "string|bytes(array)",
            got: json_type_name(other),
        }),
    }
}

fn prefix_value(input: &Value, n: usize) -> Result<Value, TransformError> {
    match input {
        Value::String(s) => Ok(Value::String(s.chars().take(n).collect())),
        other => Err(TransformError::TypeMismatch {
            expected: "string",
            got: json_type_name(other),
        }),
    }
}

fn suffix_value(input: &Value, n: usize) -> Result<Value, TransformError> {
    match input {
        Value::String(s) => {
            let total = s.chars().count();
            let skip = total.saturating_sub(n);
            Ok(Value::String(s.chars().skip(skip).collect()))
        }
        other => Err(TransformError::TypeMismatch {
            expected: "string",
            got: json_type_name(other),
        }),
    }
}

/// Shared number-or-RFC3339-timestamp axis reader for [`bucket_value`] /
/// [`gte_value`] / [`lt_value`] / [`in_range_value`] — every one of these
/// only needs `input` reduced to a comparable `f64`, never the original
/// type back.
fn numeric_axis(input: &Value) -> Result<f64, TransformError> {
    match input {
        Value::Number(n) => n.as_f64().ok_or_else(|| {
            TransformError::Malformed("number is not representable as f64".to_string())
        }),
        Value::String(s) => chrono::DateTime::parse_from_rfc3339(s)
            .map(|dt| dt.timestamp() as f64 + f64::from(dt.timestamp_subsec_nanos()) / 1e9)
            .map_err(|_| TransformError::TypeMismatch {
                expected: "number|timestamp(rfc3339)",
                got: "unparseable string",
            }),
        other => Err(TransformError::TypeMismatch {
            expected: "number|timestamp",
            got: json_type_name(other),
        }),
    }
}

fn bucket_value(input: &Value, edges: &[f64]) -> Result<Value, TransformError> {
    let x = numeric_axis(input)?;
    let idx = edges.iter().filter(|&&e| x >= e).count();
    Ok(Value::Number(serde_json::Number::from(idx as u64)))
}

fn round_number(x: f64, precision: i32) -> Result<Value, TransformError> {
    let factor = 10f64.powi(precision);
    let rounded = (x * factor).round() / factor;
    serde_json::Number::from_f64(rounded)
        .map(Value::Number)
        .ok_or_else(|| {
            TransformError::Malformed(format!(
                "round: {x} at precision {precision} produced a non-finite number"
            ))
        })
}

fn round_timestamp(s: &str, precision: i32) -> Result<Value, TransformError> {
    let dt = chrono::DateTime::parse_from_rfc3339(s)
        .map_err(|e| {
            TransformError::Malformed(format!(
                "round: {s:?} is not a valid RFC3339 timestamp: {e}"
            ))
        })?
        .with_timezone(&chrono::Utc);
    // Clamp to keep `10i64.pow` inside `i64` range unconditionally — no
    // adversarial `precision` value can panic this (termination requires
    // no panic, not just no loop).
    let p = precision.clamp(0, 18);
    let bucket_secs = 10i64.pow(p as u32);
    let secs = dt.timestamp();
    let rounded_secs = (secs as f64 / bucket_secs as f64).round() as i64 * bucket_secs;
    let rounded =
        chrono::DateTime::<chrono::Utc>::from_timestamp(rounded_secs, 0).ok_or_else(|| {
            TransformError::Malformed(format!(
                "round: {rounded_secs} seconds is out of chrono's representable range"
            ))
        })?;
    Ok(Value::String(
        rounded.to_rfc3339_opts(chrono::SecondsFormat::Secs, true),
    ))
}

fn round_value(input: &Value, precision: i32) -> Result<Value, TransformError> {
    match input {
        Value::Number(n) => {
            let x = n.as_f64().ok_or_else(|| {
                TransformError::Malformed("number is not representable as f64".to_string())
            })?;
            round_number(x, precision)
        }
        Value::String(s) => round_timestamp(s, precision),
        other => Err(TransformError::TypeMismatch {
            expected: "number|timestamp",
            got: json_type_name(other),
        }),
    }
}

fn scalar_to_string(v: &Value) -> Result<String, TransformError> {
    match v {
        Value::String(s) => Ok(s.clone()),
        Value::Number(n) => Ok(n.to_string()),
        Value::Bool(b) => Ok(b.to_string()),
        Value::Null => Ok(String::new()),
        other => Err(TransformError::TypeMismatch {
            expected: "scalar (string|number|bool|null)",
            got: json_type_name(other),
        }),
    }
}

fn concat_value(input: &Value, sep: &str) -> Result<Value, TransformError> {
    let arr = input
        .as_array()
        .ok_or_else(|| TransformError::TypeMismatch {
            expected: "array of exactly 2 scalars",
            got: json_type_name(input),
        })?;
    if arr.len() != 2 {
        return Err(TransformError::Malformed(format!(
            "concat requires an array of exactly 2 elements, got {}",
            arr.len()
        )));
    }
    let left = scalar_to_string(&arr[0])?;
    let right = scalar_to_string(&arr[1])?;
    Ok(Value::String(format!("{left}{sep}{right}")))
}

fn redact_value(placeholder: &Option<String>) -> Value {
    match placeholder {
        Some(p) => Value::String(p.clone()),
        None => Value::Null,
    }
}

fn salted_hash_value(input: &Value, salt_ref: &str) -> Result<Value, TransformError> {
    use sha2::Digest as _;
    let s = input.as_str().ok_or_else(|| TransformError::TypeMismatch {
        expected: "string",
        got: json_type_name(input),
    })?;
    let mut hasher = sha2::Sha256::new();
    hasher.update(salt_ref.as_bytes());
    // Length-implicit delimiter: without this, salt_ref="ab"/value="c" and
    // salt_ref="a"/value="bc" would hash identically.
    hasher.update([0u8]);
    hasher.update(s.as_bytes());
    Ok(Value::String(hex::encode(hasher.finalize())))
}

fn gte_value(input: &Value, v: f64) -> Result<Value, TransformError> {
    numeric_axis(input).map(|x| Value::Bool(x >= v))
}

fn lt_value(input: &Value, v: f64) -> Result<Value, TransformError> {
    numeric_axis(input).map(|x| Value::Bool(x < v))
}

fn in_range_value(input: &Value, lo: f64, hi: f64) -> Result<Value, TransformError> {
    numeric_axis(input).map(|x| Value::Bool(x >= lo && x <= hi))
}

// ───────────── strip_field (moved from consent_grammar, #519 2a-ii) ──────

/// Root-level envelope members [`TransformOp::StripField`] must never
/// remove — stripping either would destroy the discriminator (`dimension`)
/// or the cross-reference key (`trace_id`) a downstream reader needs even
/// to recognize what's left. Moved here verbatim from
/// `consent_grammar::PROTECTED_ROOT_MEMBERS` (CIRISPersist#519 item 2a-ii —
/// ONE strip implementation).
const PROTECTED_ROOT_MEMBERS: &[&str] = &["dimension", "trace_id"];

/// Apply one `strip_field` `path` to `envelope` IN PLACE. `path` is a
/// `/`-separated JSON pointer (a leading `/` is optional and stripped); a
/// `*` segment matches EVERY array index / object key at that level (a
/// wildcard fan-out), and the terminal segment names the member removed
/// wherever the path resolves. Moved verbatim from
/// `consent_grammar::strip_field` (CIRISPersist#519 item 2a-ii) —
/// [`super::consent_grammar::strip_field`] is now a thin wrapper over
/// `apply(&TransformOp::StripField{path}, ..)` calling this same function.
///
/// - Nested paths descend through objects (`get_mut(key)`) and arrays
///   (parsed as a numeric index).
/// - A MISSING path (any segment fails to resolve) is a silent no-op —
///   never an error; a grant naming a path this envelope shape doesn't
///   carry is not a grammar violation.
/// - Root-safety: a path that resolves to exactly one segment naming a
///   [`PROTECTED_ROOT_MEMBERS`] entry (`"dimension"` or `"trace_id"`) is
///   REFUSED (`tracing::warn!`), never silently honored.
fn strip_field_impl(envelope: &mut Value, path: &str) {
    let segments: Vec<&str> = path
        .trim_start_matches('/')
        .split('/')
        .filter(|s| !s.is_empty())
        .collect();
    if segments.is_empty() {
        // Resolves to the envelope root itself — refuse (never wipe the
        // whole envelope via an empty/root path).
        return;
    }
    if segments.len() == 1 && PROTECTED_ROOT_MEMBERS.contains(&segments[0]) {
        tracing::warn!(
            path = %path,
            member = %segments[0],
            "transform::strip_field: refusing to strip a protected root member"
        );
        return;
    }
    strip_field_recursive(envelope, &segments);
}

/// The recursive descent behind [`strip_field_impl`]. `segments` is always
/// non-empty on entry (the caller handles the empty-path case). Bounded by
/// `path`'s own finite segment count — the same "the input's own finite
/// structure is the termination bound" property the module doc claims.
fn strip_field_recursive(value: &mut Value, segments: &[&str]) {
    let head = segments[0];
    let rest = &segments[1..];

    if rest.is_empty() {
        // `head` is the terminal segment — remove it here.
        match value {
            Value::Object(map) => {
                if head == "*" {
                    map.clear();
                } else {
                    map.remove(head);
                }
            }
            Value::Array(arr) => {
                if head == "*" {
                    arr.clear();
                } else if let Ok(idx) = head.parse::<usize>() {
                    if idx < arr.len() {
                        arr.remove(idx);
                    }
                }
                // Non-numeric, non-`*` segment against an array: no
                // resolution → no-op.
            }
            // Scalar / null: nothing to remove into → no-op.
            _ => {}
        }
        return;
    }

    // Not the terminal segment — descend, fanning out on `*`.
    match value {
        Value::Object(map) => {
            if head == "*" {
                for v in map.values_mut() {
                    strip_field_recursive(v, rest);
                }
            } else if let Some(next) = map.get_mut(head) {
                strip_field_recursive(next, rest);
            }
            // Missing key → no-op (missing path).
        }
        Value::Array(arr) => {
            if head == "*" {
                for v in arr.iter_mut() {
                    strip_field_recursive(v, rest);
                }
            } else if let Ok(idx) = head.parse::<usize>() {
                if let Some(next) = arr.get_mut(idx) {
                    strip_field_recursive(next, rest);
                }
            }
            // Missing index → no-op (missing path).
        }
        // Scalar / null at a non-terminal segment: nothing to descend
        // into → no-op (missing path).
        _ => {}
    }
}

// ─────────────────────────── manifest + pinned hash ──────────────────────

/// The full algebra as canonical JSON — the hashed representation + the
/// public API shape a cross-repo consumer pins against. Mirrors
/// [`super::replication_policy::replication_policy_manifest`] /
/// [`super::consent_grammar::consent_grammar_manifest`]'s shape/role
/// exactly: every opcode's name, arity, input/output type, AND live-vs-
/// declared status, derived from [`OPCODES`] (the one source both this and
/// [`validate_family_transform_rows`] read from).
#[must_use]
pub fn algebra_manifest() -> Value {
    serde_json::json!({
        "contract": "transform_algebra",
        "version": 1,
        "principle": "STRICTLY TOTAL: named opcodes, fixed arity, no loops, no recursion, no user-defined functions",
        "opcodes": OPCODES.iter().map(|o| serde_json::json!({
            "op": o.name,
            "arity": o.arity,
            "input_type": o.input_type,
            "output_type": o.output_type,
            "status": o.status.as_str(),
        })).collect::<Vec<_>>(),
    })
}

/// sha256 (lowercase hex) over JCS of [`algebra_manifest`] — the same
/// canonicalizer [`super::replication_policy::replication_policy_sha256`]
/// / [`super::consent_grammar::consent_grammar_sha256`] use.
#[must_use]
pub fn transform_algebra_sha256() -> String {
    use sha2::Digest as _;
    let canonical = crate::verify::canonical::ceg_produce_canonicalize(&algebra_manifest())
        .expect("transform algebra manifest canonicalizes");
    hex::encode(sha2::Sha256::digest(&canonical))
}

/// The PINNED algebra hash. The `transform_algebra_hash_is_pinned` witness
/// asserts computed == pinned — any opcode change (a new variant, a changed
/// arity, a flipped live/declared status) is a deliberate re-pin, visible
/// to every consumer, exactly the [`super::replication_policy::REPLICATION_POLICY_HASH`]
/// / [`super::consent_grammar::CONSENT_GRAMMAR_HASH`] discipline.
pub const TRANSFORM_ALGEBRA_HASH: &str =
    "b7bd779468f4ad1ab551a5fd2dc0392df01e6f2e0ed393f924a806ed49686b4b";

// ───────────── validating the manifest's per-family transform rows ───────

/// True iff `transform` (a `field_transforms.family_transform_rows[].transform`
/// prose string) declares that NO opcode applies to this row — the
/// manifest's own "NONE - NOT AN OPCODE" / "NONE - AND DO NOT ADD ONE" /
/// bare "NONE" / "n/a" markers (see e.g. the `trust:*` / `config:*` /
/// `scores:*` rows). These rows are vacuously valid: there is nothing to
/// validate against the closed opcode set.
fn declares_no_transform(transform: &str) -> bool {
    let t = transform.trim();
    t.to_ascii_uppercase().starts_with("NONE") || t.eq_ignore_ascii_case("n/a")
}

/// Parse `namespace_supersets.json`'s `field_transforms.family_transform_rows`
/// (via [`super::namespace::supersets::field_transforms`]) and assert every
/// row that DOES declare a transform (i.e. is not [`declares_no_transform`])
/// names at least one [`OPCODES`] member somewhere in its `transform` prose.
///
/// The `transform` field is human prose (`"strip_field(json_pointer)"`,
/// `"gte / in_range predicate - disclose the ANSWER ..."`,
/// `"commit(sha256) + byte_len + component_count"`), not a machine grammar,
/// so this is a **referential** check — it tokenizes on non-alphanumeric/
/// underscore boundaries and requires at least one token to equal a known
/// opcode name — not a full parse of call syntax or an arity count over
/// prose. That is enough to catch the failure mode that matters: a row
/// naming an opcode that was renamed, removed, or never existed (a typo, a
/// stale reference after an algebra change) is a HARD ERROR, fail-closed,
/// the same posture [`super::consent_grammar::parse_grant_payload`]'s
/// unknown-`op`-tag rejection uses.
pub fn validate_family_transform_rows() -> Result<(), Vec<String>> {
    let known: std::collections::HashSet<&str> = OPCODES.iter().map(|o| o.name).collect();
    let rows = super::namespace::supersets::field_transforms()
        .get("family_transform_rows")
        .and_then(Value::as_array)
        .cloned()
        .unwrap_or_default();

    let mut errors = Vec::new();
    for row in &rows {
        let family = row
            .get("family")
            .and_then(Value::as_str)
            .unwrap_or("<row missing \"family\">");
        let transform_text = row.get("transform").and_then(Value::as_str).unwrap_or("");

        if declares_no_transform(transform_text) {
            continue;
        }

        let has_known_opcode = transform_text
            .split(|c: char| !(c.is_ascii_alphanumeric() || c == '_'))
            .filter(|tok| !tok.is_empty())
            .any(|tok| known.contains(tok.to_ascii_lowercase().as_str()));

        if !has_known_opcode {
            errors.push(format!(
                "family {family:?}: transform {transform_text:?} references no known total-algebra \
                 opcode (known: {known:?})"
            ));
        }
    }

    if errors.is_empty() {
        Ok(())
    } else {
        Err(errors)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    // ───────────────────── manifest + hash pin ───────────────────────

    #[test]
    fn transform_algebra_hash_is_pinned() {
        assert_eq!(
            transform_algebra_sha256(),
            TRANSFORM_ALGEBRA_HASH,
            "transform algebra changed: re-pin TRANSFORM_ALGEBRA_HASH deliberately"
        );
    }

    #[test]
    fn rust_opcode_metadata_matches_vendored_manifest() {
        let field_transforms = super::super::namespace::supersets::field_transforms();
        let vendored_opcodes = field_transforms
            .get("opcodes")
            .and_then(Value::as_array)
            .expect("field_transforms.opcodes is an array");
        assert_eq!(
            vendored_opcodes.len(),
            OPCODES.len(),
            "OPCODES drifted from the vendored manifest's opcode count"
        );
        for entry in vendored_opcodes {
            let name = entry
                .get("opcode")
                .and_then(Value::as_str)
                .expect("vendored opcode entry has an \"opcode\" name");
            let arity = entry
                .get("arity")
                .and_then(Value::as_u64)
                .expect("vendored opcode entry has an \"arity\"");
            let input_type = entry
                .get("input_type")
                .and_then(Value::as_str)
                .unwrap_or("");
            let output_type = entry
                .get("output_type")
                .and_then(Value::as_str)
                .unwrap_or("");
            let meta = OPCODES
                .iter()
                .find(|o| o.name == name)
                .unwrap_or_else(|| panic!("vendored opcode {name:?} has no OPCODES entry"));
            assert_eq!(
                u64::from(meta.arity),
                arity,
                "opcode {name:?} arity drifted"
            );
            assert_eq!(
                meta.input_type, input_type,
                "opcode {name:?} input_type drifted"
            );
            assert_eq!(
                meta.output_type, output_type,
                "opcode {name:?} output_type drifted"
            );
        }
    }

    #[test]
    fn every_declared_family_transform_is_a_known_total_opcode() {
        validate_family_transform_rows()
            .expect("every declared family_transform_rows entry names a known opcode");
    }

    // ───────────────────── totality witness ──────────────────────────

    /// One representative instance per [`TransformOp`] variant — used by
    /// both [`is_total`]'s witness and the opcode-name cross-check below.
    /// If a variant is added without adding a sample here, the length
    /// assertion (against [`OPCODES`]) catches the omission.
    fn sample_ops() -> Vec<(&'static str, TransformOp)> {
        vec![
            ("truncate", TransformOp::Truncate { n: 3 }),
            ("prefix", TransformOp::Prefix { n: 3 }),
            ("suffix", TransformOp::Suffix { n: 3 }),
            (
                "bucket",
                TransformOp::Bucket {
                    edges: vec![1.0, 2.0],
                },
            ),
            ("round", TransformOp::Round { precision: 2 }),
            (
                "concat",
                TransformOp::Concat {
                    sep: "-".to_string(),
                },
            ),
            ("redact", TransformOp::Redact { placeholder: None }),
            (
                "strip_field",
                TransformOp::StripField {
                    path: "/x".to_string(),
                },
            ),
            (
                "salted_hash",
                TransformOp::SaltedHash {
                    salt_ref: "s".to_string(),
                },
            ),
            ("commit", TransformOp::Commit),
            (
                "nullifier",
                TransformOp::Nullifier {
                    epoch: "e1".to_string(),
                    scope: "s1".to_string(),
                },
            ),
            ("bbs_derive", TransformOp::BbsDerive),
            ("gte", TransformOp::Gte { v: 1.0 }),
            ("lt", TransformOp::Lt { v: 1.0 }),
            ("in_range", TransformOp::InRange { lo: 0.0, hi: 1.0 }),
        ]
    }

    #[test]
    fn every_opcode_is_total() {
        let samples = sample_ops();
        assert_eq!(
            samples.len(),
            OPCODES.len(),
            "sample_ops() and OPCODES have diverged in count — a variant was added to one \
             without the other"
        );
        let known: std::collections::HashSet<&str> = OPCODES.iter().map(|o| o.name).collect();
        for (name, op) in &samples {
            assert!(is_total(op), "opcode {name} must be total");
            assert!(
                known.contains(name),
                "sample opcode name {name:?} is not in OPCODES"
            );
        }
    }

    // ───────────────────── live opcode behavior ───────────────────────

    #[test]
    fn truncate_shortens_strings_and_arrays() {
        assert_eq!(
            apply(
                &TransformOp::Truncate { n: 3 },
                &Value::String("hello".into())
            )
            .unwrap(),
            Value::String("hel".into())
        );
        assert_eq!(
            apply(
                &TransformOp::Truncate { n: 2 },
                &serde_json::json!([1, 2, 3])
            )
            .unwrap(),
            serde_json::json!([1, 2])
        );
        // Shorter than n: unchanged.
        assert_eq!(
            apply(
                &TransformOp::Truncate { n: 10 },
                &Value::String("hi".into())
            )
            .unwrap(),
            Value::String("hi".into())
        );
    }

    #[test]
    fn truncate_rejects_non_string_non_array() {
        let err = apply(&TransformOp::Truncate { n: 1 }, &serde_json::json!(42)).unwrap_err();
        assert!(matches!(err, TransformError::TypeMismatch { .. }));
    }

    #[test]
    fn prefix_and_suffix_take_leading_and_trailing_chars() {
        assert_eq!(
            apply(
                &TransformOp::Prefix { n: 3 },
                &Value::String("hello".into())
            )
            .unwrap(),
            Value::String("hel".into())
        );
        assert_eq!(
            apply(
                &TransformOp::Suffix { n: 3 },
                &Value::String("hello".into())
            )
            .unwrap(),
            Value::String("llo".into())
        );
        // n larger than the string: unchanged.
        assert_eq!(
            apply(&TransformOp::Suffix { n: 30 }, &Value::String("hi".into())).unwrap(),
            Value::String("hi".into())
        );
    }

    #[test]
    fn prefix_rejects_non_string() {
        let err = apply(&TransformOp::Prefix { n: 1 }, &serde_json::json!(1)).unwrap_err();
        assert!(matches!(err, TransformError::TypeMismatch { .. }));
    }

    #[test]
    fn bucket_maps_numbers_to_edge_indices() {
        let op = TransformOp::Bucket {
            edges: vec![10.0, 20.0, 30.0],
        };
        assert_eq!(
            apply(&op, &serde_json::json!(5)).unwrap(),
            serde_json::json!(0)
        );
        assert_eq!(
            apply(&op, &serde_json::json!(10)).unwrap(),
            serde_json::json!(1)
        );
        assert_eq!(
            apply(&op, &serde_json::json!(25)).unwrap(),
            serde_json::json!(2)
        );
        assert_eq!(
            apply(&op, &serde_json::json!(1000)).unwrap(),
            serde_json::json!(3)
        );
    }

    #[test]
    fn bucket_accepts_rfc3339_timestamps() {
        let op = TransformOp::Bucket {
            edges: vec![1_700_000_000.0],
        };
        let before = apply(&op, &serde_json::json!("2020-01-01T00:00:00Z")).unwrap();
        let after = apply(&op, &serde_json::json!("2025-01-01T00:00:00Z")).unwrap();
        assert_eq!(before, serde_json::json!(0));
        assert_eq!(after, serde_json::json!(1));
    }

    #[test]
    fn round_number_rounds_to_decimal_precision() {
        let op = TransformOp::Round { precision: 2 };
        let out = apply(&op, &serde_json::json!(1.23456)).unwrap();
        assert_eq!(out, serde_json::json!(1.23));

        let coarse = TransformOp::Round { precision: -2 };
        let out2 = apply(&coarse, &serde_json::json!(1234.0)).unwrap();
        assert_eq!(out2, serde_json::json!(1200.0));
    }

    #[test]
    fn round_timestamp_coarsens_to_a_second_bucket() {
        let op = TransformOp::Round { precision: 1 }; // nearest 10s
        let out = apply(&op, &serde_json::json!("2024-01-01T00:00:07Z")).unwrap();
        assert_eq!(out, serde_json::json!("2024-01-01T00:00:10Z"));
    }

    #[test]
    fn round_rejects_non_number_non_string() {
        let err = apply(
            &TransformOp::Round { precision: 1 },
            &serde_json::json!(true),
        )
        .unwrap_err();
        assert!(matches!(err, TransformError::TypeMismatch { .. }));
    }

    #[test]
    fn round_rejects_unparseable_timestamp_string() {
        let err = apply(
            &TransformOp::Round { precision: 1 },
            &serde_json::json!("not-a-timestamp"),
        )
        .unwrap_err();
        assert!(matches!(err, TransformError::Malformed(_)));
    }

    #[test]
    fn concat_joins_a_two_element_array() {
        let op = TransformOp::Concat {
            sep: "-".to_string(),
        };
        let out = apply(&op, &serde_json::json!(["a", "b"])).unwrap();
        assert_eq!(out, serde_json::json!("a-b"));

        // Non-string scalars coerce.
        let out2 = apply(&op, &serde_json::json!([1, true])).unwrap();
        assert_eq!(out2, serde_json::json!("1-true"));
    }

    #[test]
    fn concat_rejects_wrong_arity_or_shape() {
        let op = TransformOp::Concat {
            sep: "-".to_string(),
        };
        assert!(matches!(
            apply(&op, &serde_json::json!(["a"])).unwrap_err(),
            TransformError::Malformed(_)
        ));
        assert!(matches!(
            apply(&op, &serde_json::json!("not-an-array")).unwrap_err(),
            TransformError::TypeMismatch { .. }
        ));
        assert!(matches!(
            apply(&op, &serde_json::json!([{"a": 1}, "b"])).unwrap_err(),
            TransformError::TypeMismatch { .. }
        ));
    }

    #[test]
    fn redact_ignores_input_shape_and_defaults_to_null() {
        let op = TransformOp::Redact { placeholder: None };
        assert_eq!(
            apply(&op, &serde_json::json!({"a": 1})).unwrap(),
            Value::Null
        );
        assert_eq!(
            apply(&op, &serde_json::json!([1, 2, 3])).unwrap(),
            Value::Null
        );

        let with_placeholder = TransformOp::Redact {
            placeholder: Some("***".to_string()),
        };
        assert_eq!(
            apply(&with_placeholder, &serde_json::json!(42)).unwrap(),
            serde_json::json!("***")
        );
    }

    #[test]
    fn strip_field_removes_a_nested_member_via_apply() {
        let env = serde_json::json!({
            "dimension": "trace:complete:v1",
            "trace_id": "t-1",
            "trace": {"prompt": "secret", "response": "ok"},
        });
        let out = apply(
            &TransformOp::StripField {
                path: "/trace/prompt".to_string(),
            },
            &env,
        )
        .unwrap();
        assert_eq!(
            out,
            serde_json::json!({
                "dimension": "trace:complete:v1",
                "trace_id": "t-1",
                "trace": {"response": "ok"},
            })
        );
    }

    #[test]
    fn strip_field_refuses_protected_root_members_via_apply() {
        let env = serde_json::json!({"dimension": "x", "trace_id": "t"});
        let out = apply(
            &TransformOp::StripField {
                path: "/dimension".to_string(),
            },
            &env,
        )
        .unwrap();
        assert_eq!(out, env, "\"dimension\" at root is protected");
    }

    #[test]
    fn salted_hash_is_deterministic_and_salt_sensitive() {
        let a = apply(
            &TransformOp::SaltedHash {
                salt_ref: "salt1".to_string(),
            },
            &serde_json::json!("value"),
        )
        .unwrap();
        let a2 = apply(
            &TransformOp::SaltedHash {
                salt_ref: "salt1".to_string(),
            },
            &serde_json::json!("value"),
        )
        .unwrap();
        assert_eq!(a, a2, "salted_hash is pure/deterministic for fixed inputs");

        let b = apply(
            &TransformOp::SaltedHash {
                salt_ref: "salt2".to_string(),
            },
            &serde_json::json!("value"),
        )
        .unwrap();
        assert_ne!(a, b, "a different salt must yield a different digest");

        // Different (salt, value) split shouldn't collide via bare
        // concatenation (the NUL delimiter guards this).
        let c = apply(
            &TransformOp::SaltedHash {
                salt_ref: "sa".to_string(),
            },
            &serde_json::json!("ltvalue"),
        )
        .unwrap();
        assert_ne!(a, c);
    }

    #[test]
    fn salted_hash_rejects_non_string_input() {
        let err = apply(
            &TransformOp::SaltedHash {
                salt_ref: "s".to_string(),
            },
            &serde_json::json!(42),
        )
        .unwrap_err();
        assert!(matches!(err, TransformError::TypeMismatch { .. }));
    }

    #[test]
    fn predicates_disclose_only_the_boolean_answer() {
        assert_eq!(
            apply(&TransformOp::Gte { v: 18.0 }, &serde_json::json!(21)).unwrap(),
            serde_json::json!(true)
        );
        assert_eq!(
            apply(&TransformOp::Gte { v: 18.0 }, &serde_json::json!(15)).unwrap(),
            serde_json::json!(false)
        );
        assert_eq!(
            apply(&TransformOp::Lt { v: 18.0 }, &serde_json::json!(15)).unwrap(),
            serde_json::json!(true)
        );
        assert_eq!(
            apply(
                &TransformOp::InRange { lo: 10.0, hi: 20.0 },
                &serde_json::json!(15)
            )
            .unwrap(),
            serde_json::json!(true)
        );
        assert_eq!(
            apply(
                &TransformOp::InRange { lo: 10.0, hi: 20.0 },
                &serde_json::json!(25)
            )
            .unwrap(),
            serde_json::json!(false)
        );
    }

    #[test]
    fn predicates_reject_non_numeric_non_timestamp_input() {
        let err = apply(&TransformOp::Gte { v: 1.0 }, &serde_json::json!(null)).unwrap_err();
        assert!(matches!(err, TransformError::TypeMismatch { .. }));
    }

    // ───────────────────── declared-only opcodes ──────────────────────

    #[test]
    fn declared_only_opcodes_refuse_at_runtime() {
        let commit_err = apply(&TransformOp::Commit, &serde_json::json!("x")).unwrap_err();
        assert!(matches!(
            commit_err,
            TransformError::NotYetImplemented { op: "commit" }
        ));

        let nullifier_err = apply(
            &TransformOp::Nullifier {
                epoch: "e".to_string(),
                scope: "s".to_string(),
            },
            &serde_json::json!("x"),
        )
        .unwrap_err();
        assert!(matches!(
            nullifier_err,
            TransformError::NotYetImplemented { op: "nullifier" }
        ));

        let bbs_err = apply(&TransformOp::BbsDerive, &serde_json::json!("x")).unwrap_err();
        assert!(matches!(
            bbs_err,
            TransformError::NotYetImplemented { op: "bbs_derive" }
        ));
    }

    // ───────────────────── closed-enum deny_unknown_fields ────────────

    #[test]
    fn unknown_opcode_tag_is_rejected() {
        let raw = serde_json::json!({"op": "quantum_redaction", "n": 1});
        let result: Result<TransformOp, _> = serde_json::from_value(raw);
        assert!(
            result.is_err(),
            "an unknown op tag must fail to deserialize"
        );
    }

    #[test]
    fn unknown_field_on_a_known_op_is_rejected() {
        let raw = serde_json::json!({"op": "truncate", "n": 1, "unexpected": true});
        let result: Result<TransformOp, _> = serde_json::from_value(raw);
        assert!(result.is_err(), "an unknown field must fail to deserialize");
    }

    #[test]
    fn transform_op_round_trips() {
        let op = TransformOp::Truncate { n: 5 };
        let value = serde_json::to_value(&op).unwrap();
        assert_eq!(value, serde_json::json!({"op": "truncate", "n": 5}));
        let back: TransformOp = serde_json::from_value(value).unwrap();
        assert_eq!(back, op);
    }

    // ───────────────────── pipeline ────────────────────────────────

    #[test]
    fn pipeline_folds_left_to_right() {
        let pipeline = TransformPipeline(vec![
            TransformOp::Truncate { n: 5 },
            TransformOp::Suffix { n: 3 },
        ]);
        assert_eq!(pipeline.len(), 2);
        assert!(!pipeline.is_empty());
        let out = pipeline
            .apply_all(&serde_json::json!("hello world"))
            .unwrap();
        // truncate to 5 -> "hello"; suffix 3 -> "llo"
        assert_eq!(out, serde_json::json!("llo"));
    }

    #[test]
    fn empty_pipeline_is_the_identity() {
        let pipeline = TransformPipeline::default();
        assert!(pipeline.is_empty());
        let input = serde_json::json!({"a": 1});
        assert_eq!(pipeline.apply_all(&input).unwrap(), input);
    }

    #[test]
    fn pipeline_stops_at_the_first_error() {
        let pipeline = TransformPipeline(vec![
            TransformOp::Gte { v: 1.0 }, // "hi" -> TypeMismatch (not numeric/timestamp)
            TransformOp::Truncate { n: 1 },
        ]);
        let err = pipeline.apply_all(&serde_json::json!("hi")).unwrap_err();
        assert!(matches!(err, TransformError::TypeMismatch { .. }));
    }
}

/// v21.6.0 (CIRISPersist#519 item 2a-ii) — **the opcode table drives the
/// fuzzer.** The manifest declares the algebra STRICTLY TOTAL (named opcodes,
/// fixed arity, no loops/recursion); these property tests VERIFY totality as
/// law rather than on a sample per variant: over arbitrary JSON input and
/// arbitrary op arguments, [`apply`] always RETURNS (`Ok` or a typed `Err`) and
/// never panics, [`apply`] is deterministic, and an arbitrary bounded
/// [`TransformPipeline`] always terminates. A non-terminating or panicking
/// opcode — the exact failure the totality invariant exists to forbid, because
/// a transform sits in the admission/serve gate — is caught here by
/// construction.
#[cfg(test)]
mod proptests {
    use super::*;
    use proptest::prelude::*;
    use serde_json::Value;

    /// A bounded arbitrary JSON value — depth- and size-limited so the
    /// STRATEGY itself terminates (an unbounded generator would be its own
    /// totality violation). Covers every leaf kind + shallow arrays/objects.
    fn arb_json() -> impl Strategy<Value = Value> {
        let leaf = prop_oneof![
            Just(Value::Null),
            any::<bool>().prop_map(Value::from),
            any::<i64>().prop_map(Value::from),
            any::<f64>()
                .prop_filter("finite", |f| f.is_finite())
                .prop_map(|f| serde_json::json!(f)),
            ".{0,32}".prop_map(Value::from),
        ];
        leaf.prop_recursive(3, 24, 5, |inner| {
            prop_oneof![
                prop::collection::vec(inner.clone(), 0..5).prop_map(Value::from),
                prop::collection::vec(("[a-z]{1,6}", inner), 0..5)
                    .prop_map(|kvs| { Value::Object(kvs.into_iter().collect()) }),
            ]
        })
    }

    /// An arbitrary op — one representative per closed [`TransformOp`] variant,
    /// with fuzzed arguments. Covers live AND declared-only opcodes (the
    /// declared-only ones must still be TOTAL: return a typed `Err`, not panic).
    fn arb_op() -> impl Strategy<Value = TransformOp> {
        prop_oneof![
            (0usize..64).prop_map(|n| TransformOp::Truncate { n }),
            (0usize..64).prop_map(|n| TransformOp::Prefix { n }),
            (0usize..64).prop_map(|n| TransformOp::Suffix { n }),
            prop::collection::vec(any::<f64>().prop_filter("finite", |f| f.is_finite()), 0..6)
                .prop_map(|edges| TransformOp::Bucket { edges }),
            (1i32..1_000_000).prop_map(|precision| TransformOp::Round { precision }),
            ".{0,8}".prop_map(|sep| TransformOp::Concat { sep }),
            proptest::option::of(".{0,8}")
                .prop_map(|placeholder| TransformOp::Redact { placeholder }),
            "(/[a-z*]{1,6}){0,4}".prop_map(|path| TransformOp::StripField { path }),
            "[a-z0-9]{0,16}".prop_map(|salt_ref| TransformOp::SaltedHash { salt_ref }),
            any::<f64>()
                .prop_filter("finite", |f| f.is_finite())
                .prop_map(|v| TransformOp::Gte { v }),
            any::<f64>()
                .prop_filter("finite", |f| f.is_finite())
                .prop_map(|v| TransformOp::Lt { v }),
            (
                any::<f64>().prop_filter("finite", |f| f.is_finite()),
                any::<f64>().prop_filter("finite", |f| f.is_finite())
            )
                .prop_map(|(lo, hi)| TransformOp::InRange { lo, hi }),
            ("[a-z0-9]{0,8}", "[a-z]{0,8}")
                .prop_map(|(epoch, scope)| TransformOp::Nullifier { epoch, scope }),
        ]
    }

    proptest! {
        /// TOTALITY: apply never panics and always returns, for every op over
        /// arbitrary input. (A panic fails the case; a hang times out CI — both
        /// are totality violations the invariant forbids.)
        #[test]
        fn apply_is_total(op in arb_op(), input in arb_json()) {
            let _ = apply(&op, &input); // must simply RETURN
        }

        /// DETERMINISM: same op, same input → same result (a pure function).
        #[test]
        fn apply_is_deterministic(op in arb_op(), input in arb_json()) {
            prop_assert_eq!(apply(&op, &input), apply(&op, &input));
        }

        /// PIPELINE TERMINATION: an arbitrary bounded pipeline is a finite DAG —
        /// `apply_all` always returns, its length its own termination bound.
        #[test]
        fn pipeline_terminates(
            ops in prop::collection::vec(arb_op(), 0..12),
            input in arb_json(),
        ) {
            let _ = TransformPipeline(ops).apply_all(&input);
        }
    }

    /// The MANIFEST-DRIVEN totality claim: every opcode NAME in the vendored
    /// [`OPCODES`] table (itself 1:1-checked against
    /// `namespace_supersets.json`) is exercised by [`arb_op`] above — so the
    /// fuzzer covers the declared universe, not an arbitrary hand-picked
    /// subset. A new opcode added to the table without a matching `arb_op` arm
    /// fails this test (keeping the fuzz honest as the algebra grows).
    #[test]
    fn every_declared_opcode_is_fuzzed() {
        use std::collections::BTreeSet;
        // The op names arb_op() can produce (kept in lockstep with the strategy).
        let fuzzed: BTreeSet<&str> = [
            "truncate",
            "prefix",
            "suffix",
            "bucket",
            "round",
            "concat",
            "redact",
            "strip_field",
            "salted_hash",
            "gte",
            "lt",
            "in_range",
            "nullifier",
        ]
        .into_iter()
        .collect();
        // Declared-only opcodes with no runtime args worth fuzzing beyond
        // "returns NotYetImplemented" are exempted explicitly, not silently.
        let fuzz_exempt: BTreeSet<&str> = ["commit", "bbs_derive"].into_iter().collect();
        for meta in OPCODES {
            assert!(
                fuzzed.contains(meta.name) || fuzz_exempt.contains(meta.name),
                "opcode {:?} is in the manifest table but neither fuzzed by arb_op nor \
                 explicitly fuzz-exempt — add a strategy arm so totality stays covered",
                meta.name
            );
        }
    }
}
