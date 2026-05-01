//! BuildManifest extras for the persist primitive.
//!
//! # Mission alignment (MISSION.md §2 — `verify/`; PoB §1 federation
//! primitive completeness)
//!
//! v0.1.9 — when CIRISVerify ships v1.8.0's generic `BuildManifest`
//! validator (one canonical core + per-primitive typed extras), persist
//! becomes a first-class manifest primitive (`BuildPrimitive::Persist`).
//! Any peer can independently verify "is this build authentic" using
//! the same validation math that verifies CIRISAgent or CIRISVerify
//! itself — the federation primitive's *recursive golden rule*
//! (Accord Book IV Ch. 3) operationalized at the build layer.
//!
//! Three fields go in the extras, all deterministic at build time:
//!
//! - `supported_schema_versions`: the wire-format schema versions
//!   this build's parser accepts. Lets a peer verify "yes, this
//!   persist build can talk to my agent's wire format" without
//!   running the binary.
//! - `migration_set_sha256`: sha256 of the canonicalized
//!   concatenation of `migrations/postgres/lens/V*.sql` files.
//!   Lets a peer verify "yes, this build will install the schema
//!   I expect" before running migrations against shared
//!   infrastructure (THREAT_MODEL.md AV-26 cousin).
//! - `dep_tree_sha256`: sha256 of `cargo tree` output normalised
//!   to remove timestamp / order non-determinism. Lets a peer
//!   verify the dependency closure matches a known-audited set.
//!
//! These are persist-specific; agent / lens / registry / verify
//! manifests carry their own typed extras shapes. The generic
//! `BuildManifest.canonical_bytes()` covers both halves: the
//! universal core (build_id, target, binary_hash, …) and the
//! primitive-specific extras (this struct, serialised through
//! `serde_json`).

use ciris_verify_core::error::VerifyError;
use ciris_verify_core::security::build_manifest::{BuildPrimitive, ExtrasValidator};
use serde::{Deserialize, Serialize};

/// Typed extras for `BuildPrimitive::Persist` (CIRISVerify v1.8.0+).
///
/// Wire format: JSON object with the field names below. Field order
/// in the canonical bytes is determined by serde's struct-field order;
/// we pin it here so re-serialisation is byte-equal across compilers.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct PersistExtras {
    /// Wire-format schema versions this build's parser accepts
    /// (TRACE_WIRE_FORMAT.md §1). Sorted ascending for canonical
    /// representation.
    pub supported_schema_versions: Vec<String>,

    /// SHA-256 of the canonicalised migration set (V001 + V003 + …
    /// concatenated in lexicographic-order, with line endings
    /// normalised to LF). Hex-encoded with `"sha256:"` prefix to
    /// match `BuildManifest.binary_hash` shape.
    pub migration_set_sha256: String,

    /// SHA-256 of the build's dependency closure (`cargo tree`
    /// output normalised to remove non-determinism). Hex-encoded
    /// with `"sha256:"` prefix.
    pub dep_tree_sha256: String,
}

/// Validator for `BuildPrimitive::Persist`.
///
/// Parses the JSON into [`PersistExtras`] and rejects any malformed
/// input. Semantic validity (does the migration set actually
/// produce that hash; does this build link those exact deps) is the
/// build-time tooling's responsibility — the validator only enforces
/// the structural shape so consumers don't choke on corrupted
/// extras.
pub struct PersistExtrasValidator;

impl ExtrasValidator for PersistExtrasValidator {
    fn primitive(&self) -> BuildPrimitive {
        BuildPrimitive::Persist
    }

    fn validate(&self, extras: &serde_json::Value) -> Result<(), VerifyError> {
        let parsed: PersistExtras =
            serde_json::from_value(extras.clone()).map_err(|e| VerifyError::IntegrityError {
                message: format!("PersistExtras parse failed: {e}"),
            })?;
        // Structural invariants: every hex prefix is "sha256:"; the
        // hex tail is 64 chars. The hash itself isn't recomputed
        // here (validator runs at verify time; we don't have the
        // source files at hand). A peer can do that check
        // out-of-band against the artifacts in the build.
        if !parsed.migration_set_sha256.starts_with("sha256:")
            || parsed.migration_set_sha256.len() != 7 + 64
        {
            return Err(VerifyError::IntegrityError {
                message: format!(
                    "PersistExtras.migration_set_sha256 malformed: {}",
                    parsed.migration_set_sha256
                ),
            });
        }
        if !parsed.dep_tree_sha256.starts_with("sha256:") || parsed.dep_tree_sha256.len() != 7 + 64
        {
            return Err(VerifyError::IntegrityError {
                message: format!(
                    "PersistExtras.dep_tree_sha256 malformed: {}",
                    parsed.dep_tree_sha256
                ),
            });
        }
        if parsed.supported_schema_versions.is_empty() {
            return Err(VerifyError::IntegrityError {
                message: "PersistExtras.supported_schema_versions empty".into(),
            });
        }
        Ok(())
    }
}

/// Register the persist primitive's extras validator with
/// CIRISVerify's global registry.
///
/// Call once at startup if your code path will invoke
/// `ciris_verify_core::security::build_manifest::verify_build_manifest`
/// on a persist-shaped manifest. Idempotent — repeated calls
/// replace the existing registration with the same validator,
/// which is a no-op observable behaviour.
///
/// Consumers who only consume the persist library (FFI, ingest,
/// tests) don't need to call this; the registration is only
/// required when verifying *manifests*, not when running persist.
pub fn register() {
    ciris_verify_core::security::build_manifest::register_extras_validator(Box::new(
        PersistExtrasValidator,
    ));
}

#[cfg(test)]
mod tests {
    use super::*;

    fn valid_extras_json() -> serde_json::Value {
        serde_json::json!({
            "supported_schema_versions": ["2.7.0"],
            "migration_set_sha256": format!("sha256:{}", "a".repeat(64)),
            "dep_tree_sha256": format!("sha256:{}", "b".repeat(64)),
        })
    }

    #[test]
    fn validates_well_formed_extras() {
        PersistExtrasValidator
            .validate(&valid_extras_json())
            .expect("happy path");
    }

    #[test]
    fn rejects_missing_sha256_prefix() {
        let mut bad = valid_extras_json();
        bad["migration_set_sha256"] = serde_json::Value::String("a".repeat(64));
        assert!(PersistExtrasValidator.validate(&bad).is_err());
    }

    #[test]
    fn rejects_wrong_hex_length() {
        let mut bad = valid_extras_json();
        bad["dep_tree_sha256"] = serde_json::Value::String("sha256:abcd".into());
        assert!(PersistExtrasValidator.validate(&bad).is_err());
    }

    #[test]
    fn rejects_empty_schema_versions() {
        let mut bad = valid_extras_json();
        bad["supported_schema_versions"] = serde_json::json!([]);
        assert!(PersistExtrasValidator.validate(&bad).is_err());
    }

    #[test]
    fn rejects_extra_unknown_field_loosely() {
        // serde_json::from_value on PersistExtras *ignores* unknown
        // fields by default — that's fine; the canonical_bytes hash
        // covers the on-the-wire form, and accepting forward-compat
        // additions (extra fields) is the right shape for a
        // primitive that may evolve.
        let mut more = valid_extras_json();
        more["future_field"] = serde_json::json!("value");
        PersistExtrasValidator
            .validate(&more)
            .expect("forward-compat extras tolerated");
    }

    #[test]
    fn primitive_is_persist() {
        assert_eq!(PersistExtrasValidator.primitive(), BuildPrimitive::Persist);
    }
}
