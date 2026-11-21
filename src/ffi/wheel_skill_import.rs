//! v3.8.0 — PyO3 surface for CIRISVerify's `SkillImportManifest`
//! verification; v62.0.0 (BH-fix2) — **it refuses.**
//!
//! Verify's `SkillImportManifest` is the earlier bound-pair form (a separate
//! Ed25519 + ML-DSA-65 signature over its JSON, checked against a steward key
//! pair the caller passes in), and it has no composite successor (Verify's
//! ruling): in edition 2 a skill import is a ROW, family
//! `provenance:skill_import:{source}`, one composite `COSE_Sign1` statement
//! through the statement door. The verb stays so the Agent gets a named error,
//! never an `AttributeError`: it refuses every input by name
//! ([`skill_import_manifest_refusal`](crate::federation::edition2::door::skill_import_manifest_refusal),
//! `earlier_form_object`). RULINGS: "Composite signatures only".

use pyo3::exceptions::PyRuntimeError;
use pyo3::prelude::*;

/// v62.0.0 (BH-fix2) — refuses every manifest, by name. The Python type is
/// the one the earlier verify failure raised (`RuntimeError`, prefix
/// `skill_import verify failed:`), now naming the plane and the token:
/// `skill_import verify failed: skill_import: earlier_form_object: …`.
///
/// # Errors
/// Always.
pub fn verify_skill_import_manifest_json(
    manifest_bytes_b64: &str,
    steward_ed25519_pub_b64: &str,
    steward_ml_dsa_65_pub_b64: &str,
) -> PyResult<String> {
    let _ = (
        manifest_bytes_b64,
        steward_ed25519_pub_b64,
        steward_ml_dsa_65_pub_b64,
    );
    Err(PyRuntimeError::new_err(refusal_text()))
}

/// The refusal's text: `skill_import verify failed: <plane>: <token>: <why>`.
fn refusal_text() -> String {
    match crate::federation::edition2::door::skill_import_manifest_refusal() {
        crate::federation::Error::MalformedRow {
            plane,
            reason,
            message,
        } => format!("skill_import verify failed: {plane}: {reason}: {message}"),
        other => format!("skill_import verify failed: {other}"),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// v62.0.0 (BH-fix2, I2123) — the verb refuses, naming the token.
    #[test]
    fn i2123_the_manifest_verb_refuses_by_name() {
        let t = refusal_text();
        assert!(
            t.starts_with("skill_import verify failed: skill_import: earlier_form_object: "),
            "{t}"
        );
        assert!(t.contains("provenance:skill_import:{source}"), "{t}");
        let _err = verify_skill_import_manifest_json("AAAA", "AAAA", "AAAA").unwrap_err();
    }
}
