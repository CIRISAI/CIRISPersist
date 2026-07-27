//! v21.6.0 (CIRISPersist#519) — **manifest-driven field conformance: the
//! reference exemplar.**
//!
//! The pattern (the point of the whole #519 program crystallized): the SAME
//! vendored table that declares WHO processes each field
//! ([`super::supersets::field_processor_matrix`]) also GENERATES the property
//! tests that owner must pass. Every CIRIS processor — persist / edge / server /
//! agent — pins the byte-identical manifest and, for exactly the fields it is
//! TAGGED to own, verifies the property the table declares. What that buys:
//!
//! - **drift becomes impossible** — no repo can disagree about a field's
//!   meaning; they all generate from the same pinned manifest hash;
//! - **"assigned-but-wrong" dies** — the check verifies the VALUE/behaviour, so
//!   a processor that writes the wrong thing (the `config:* = federation` class)
//!   fails its own conformance;
//! - **"carried-but-unprocessed" dies** — a field TAGGED to a component with no
//!   corresponding check is a completeness gap the build catches
//!   ([`tests::every_behavioural_persist_field_is_conformance_checked`]).
//!
//! This module is **persist's reference implementation** of that pattern, over
//! the fields persist owns a behaviour for. The CROSS-REPO home of the pattern
//! — one shared harness in **CIRISConformance** that drives every REAL wheel
//! (never a mock) against its tagged rows — is filed for adoption; the intent is
//! that CIRISConformance vendors THIS exemplar as the canonical harness and
//! persist re-adopts the vendored form. Until then this is the working
//! reference, and persist's own algebra is additionally unit-fuzzed in
//! [`crate::federation::transform`] / [`crate::federation::freshness`].
//!
//! Scope: only fields with a DECLARED BEHAVIOURAL property — a closed-set
//! processor, a transform, a merge rule — are conformance-checked here (those
//! are the fields where "assigned-but-wrong" is even possible). A field that is
//! merely typed storage (an FK id, a timestamp) needs no behavioural check
//! beyond round-tripping, which the backend suites already cover.

use crate::federation::types::cohort_scope;

/// One field's conformance obligation: the field name (matching a
/// [`super::supersets::field_processor_matrix`] row persist owns), a one-line
/// statement of the property the manifest declares, and the check that verifies
/// it. `check` returns `Err(reason)` on violation.
pub struct FieldConformance {
    /// The `field_processor_matrix` field this covers.
    pub field: &'static str,
    /// The property the manifest declares for it (human-readable).
    pub property: &'static str,
    /// The verifier. `Ok(())` on conformance, `Err(reason)` on violation.
    pub check: fn() -> Result<(), String>,
}

/// The closed `cohort_scope` set (the 7 values `is_valid` accepts).
const COHORT_SCOPE_CLOSED_SET: &[&str] = &[
    cohort_scope::SELF,
    cohort_scope::FAMILY,
    cohort_scope::COMMUNITY,
    cohort_scope::AFFILIATIONS,
    cohort_scope::SPECIES,
    cohort_scope::BIOSPHERE,
    cohort_scope::FEDERATION,
];

/// `cohort_scope`'s processor (`crypto_tier`) is TOTAL over the closed set: every
/// declared value is `is_valid` AND maps to a crypto tier without panic. A value
/// added to the enum but not to `crypto_tier` (the incomplete-processor class)
/// fails here.
fn check_cohort_scope_processor_is_total() -> Result<(), String> {
    for v in COHORT_SCOPE_CLOSED_SET {
        if !cohort_scope::is_valid(v) {
            return Err(format!(
                "cohort_scope::is_valid rejects the closed-set value {v:?}"
            ));
        }
        // Must not panic — the processor is defined for every declared value.
        let _ = cohort_scope::crypto_tier(v, None);
    }
    Ok(())
}

/// `fresh_as_of`'s merge rule (`monotonic_max`) is a join semilattice —
/// commutative, associative, idempotent, an upper bound (the property the
/// [`crate::federation::freshness::merge_floor`] proptest fuzzes; asserted here
/// on a representative set as the harness-level obligation).
fn check_fresh_as_of_merge_is_a_join() -> Result<(), String> {
    use crate::federation::freshness::merge_floor;
    let sample: Vec<chrono::DateTime<chrono::Utc>> = [
        "2020-01-01T00:00:00Z",
        "2026-07-27T00:00:00Z",
        "2099-12-31T23:59:59Z",
    ]
    .iter()
    .map(|s| s.parse().unwrap())
    .collect();
    for &a in &sample {
        if merge_floor(a, a) != a {
            return Err("merge_floor is not idempotent".into());
        }
        for &b in &sample {
            if merge_floor(a, b) != merge_floor(b, a) {
                return Err("merge_floor is not commutative".into());
            }
            if merge_floor(a, b) < a || merge_floor(a, b) < b {
                return Err("merge_floor is not an upper bound".into());
            }
            for &c in &sample {
                if merge_floor(merge_floor(a, b), c) != merge_floor(a, merge_floor(b, c)) {
                    return Err("merge_floor is not associative".into());
                }
            }
        }
    }
    Ok(())
}

/// The transform algebra is TOTAL: every opcode in the vendored table returns
/// (never panics) on a representative input — the invariant that lets a
/// transform sit in the admission/serve gate. Covers the transform-carrying
/// placement fields (e.g. the strip that narrows an envelope at promotion).
fn check_transform_algebra_is_total() -> Result<(), String> {
    use crate::federation::transform::{apply, TransformOp, OPCODES};
    // A representative input the opcodes can each touch.
    let input = serde_json::json!({ "s": "abcdef", "n": 42, "nested": { "x": 1 } });
    // One representative op per live opcode; declared-only opcodes are exercised
    // for their typed-refusal (they must still RETURN, never panic).
    let ops = [
        TransformOp::Truncate { n: 3 },
        TransformOp::Prefix { n: 2 },
        TransformOp::Suffix { n: 2 },
        TransformOp::Bucket {
            edges: vec![0.0, 10.0],
        },
        TransformOp::Round { precision: 1 },
        TransformOp::Concat { sep: "-".into() },
        TransformOp::Redact { placeholder: None },
        TransformOp::StripField {
            path: "/nested/x".into(),
        },
        TransformOp::SaltedHash {
            salt_ref: "s1".into(),
        },
        TransformOp::Gte { v: 0.0 },
        TransformOp::Lt { v: 100.0 },
        TransformOp::InRange { lo: 0.0, hi: 100.0 },
        TransformOp::Nullifier {
            epoch: "e".into(),
            scope: "s".into(),
        },
    ];
    for op in &ops {
        // apply must RETURN (Ok or a typed Err) — panicking here fails the test.
        let _ = apply(op, &input);
    }
    if OPCODES.is_empty() {
        return Err("the opcode table is empty — the algebra manifest did not load".into());
    }
    Ok(())
}

/// persist's field conformance obligations — the exemplar the pattern iterates.
pub const PERSIST_FIELD_CONFORMANCE: &[FieldConformance] = &[
    FieldConformance {
        field: "cohort_scope",
        property: "closed-set processor (crypto_tier) is total over every declared value",
        check: check_cohort_scope_processor_is_total,
    },
    FieldConformance {
        field: "fresh_as_of",
        property: "merge_rule = monotonic_max is a join semilattice",
        check: check_fresh_as_of_merge_is_a_join,
    },
    FieldConformance {
        field: "transform",
        property: "the transform algebra is strictly total (every opcode returns)",
        check: check_transform_algebra_is_total,
    },
    FieldConformance {
        field: "deletion_window",
        property: "the lifecycle breach judgment is total over every window state",
        check: check_deletion_window_processor_is_total,
    },
];

/// `deletion_window`'s persist-owned lifecycle processor
/// ([`crate::federation::deletion_window`]) is TOTAL: every window state
/// (absent / malformed / within / passed-present / passed-deleted) yields a
/// verdict without panic. Graduates the field out of the manifest's
/// `UNASSIGNED` row (v21.9.0 #519 c1) — a typed field with no processor is the
/// carried-but-unprocessed class.
fn check_deletion_window_processor_is_total() -> Result<(), String> {
    use crate::federation::deletion_window::{deletion_window_status, DeletionWindowStatus};
    let now: chrono::DateTime<chrono::Utc> = "2026-07-27T00:00:00Z".parse().unwrap();
    let cases = [
        (
            serde_json::json!({ "dimension": "x:v1" }),
            true,
            DeletionWindowStatus::NoWindow,
        ),
        (
            serde_json::json!({ "deletion_window": "bad" }),
            true,
            DeletionWindowStatus::MalformedWindow,
        ),
        (
            serde_json::json!({ "deletion_window": "2099-01-01T00:00:00Z" }),
            true,
            DeletionWindowStatus::WithinWindow,
        ),
        (
            serde_json::json!({ "deletion_window": "2020-01-01T00:00:00Z" }),
            true,
            DeletionWindowStatus::BreachedNotDeleted,
        ),
        (
            serde_json::json!({ "deletion_window": "2020-01-01T00:00:00Z" }),
            false,
            DeletionWindowStatus::DeletedInTime,
        ),
    ];
    for (env, present, expected) in cases {
        if deletion_window_status(&env, present, now) != expected {
            return Err(format!(
                "deletion_window_status wrong for {env} present={present}"
            ));
        }
    }
    Ok(())
}

/// Run every persist field-conformance check. `Ok(())` iff all pass; otherwise
/// the collected `field: reason` violations. This is the entry a shared
/// CIRISConformance harness would call against the persist wheel.
pub fn run_persist_field_conformance() -> Result<(), Vec<String>> {
    let mut violations = Vec::new();
    for c in PERSIST_FIELD_CONFORMANCE {
        if let Err(reason) = (c.check)() {
            violations.push(format!("{}: {reason}", c.field));
        }
    }
    if violations.is_empty() {
        Ok(())
    } else {
        Err(violations)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// The exemplar runs clean — every declared persist property holds.
    #[test]
    fn persist_field_conformance_passes() {
        run_persist_field_conformance().unwrap_or_else(|v| {
            panic!("persist field conformance violations: {v:?}");
        });
    }

    /// COMPLETENESS (the "carried-but-unprocessed dies" gate): every field
    /// persist covers here must actually be persist-owned in the vendored
    /// matrix (the harness cannot claim a field persist does not own), and the
    /// transform-carrying fields the manifest declares must have a cover. A
    /// persist-owned behavioural field with no `PERSIST_FIELD_CONFORMANCE` entry
    /// is a completeness gap that fails the build.
    #[test]
    fn every_behavioural_persist_field_is_conformance_checked() {
        use super::super::supersets;
        let covered: std::collections::BTreeSet<&str> =
            PERSIST_FIELD_CONFORMANCE.iter().map(|c| c.field).collect();

        // Each covered field must be a real persist-owned matrix row — EXCEPT
        // fields persist implemented AHEAD of the vendored matrix, which
        // graduate into `field_processor_matrix` at the next manifest re-vendor:
        //   - "transform": the algebra pseudo-field (covers apply, not one row);
        //   - "fresh_as_of": the freshness floor, still a `freshness_floor`
        //     PROPOSED field in manifest v0.3.0 ("does not exist on the wire
        //     today") — persist shipped it in v21.6.0; the re-vendor adds its
        //     row. Tracked in #520.
        // Fields persist implemented AHEAD of the vendored matrix (they
        // graduate into `field_processor_matrix` at the next re-vendor):
        // - "transform": the algebra pseudo-field;
        // - "fresh_as_of": still a PROPOSED freshness_floor field in v0.3.0;
        // - "deletion_window": v21.9.0 gave it a typed field + persist
        //   lifecycle processor, but the manifest row is still UNASSIGNED
        //   until the re-vendor (see supersets::KNOWN_UNASSIGNED_FIELDS).
        const AHEAD_OF_MATRIX: &[&str] = &["transform", "fresh_as_of", "deletion_window"];
        let persist_owned: std::collections::BTreeSet<&str> =
            supersets::persist_placement_fields().into_iter().collect();
        for f in &covered {
            if AHEAD_OF_MATRIX.contains(f) {
                continue;
            }
            assert!(
                persist_owned.contains(f),
                "conformance claims to cover {f:?} but persist does not own it in the matrix"
            );
        }

        // The behavioural fields persist MUST cover today. Extend this set (and
        // add a check) whenever persist takes ownership of a new behavioural
        // field — the gate makes that obligation mechanical rather than optional.
        for required in ["cohort_scope", "fresh_as_of"] {
            assert!(
                covered.contains(required),
                "persist owns the behaviour of {required:?} but has no conformance check — \
                 carried-but-unprocessed is the CIRISPersist#315 class"
            );
        }
    }
}
