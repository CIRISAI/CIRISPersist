//! v56.0.0 (CIRISPersist#1089, CIRISAgent#1255; CC 3.1.5) — the
//! `trace_format` admission gate.
//!
//! A trace identifies its FORMAT by the signed member
//! `deployment_profile.trace_format_version`, distinct from
//! `trace_schema_version`, which stays the canonicalization epoch (major ≥ 3
//! selects JCS; the v2.8.0 agent stamps `"3.0.0"`). The gate keys on the
//! format member:
//!
//! - **absent** (and no `deployment_profile.run_kind`): a v2.7.x trace,
//!   admitted exactly as before;
//! - **a vendored format** ([`VENDORED_TRACE_FORMATS`]): the whole trace
//!   validates against that format's pinned schema, or is refused
//!   (`schema_trace_format_violation`) — never truncated to fit;
//! - **any other value**: refused BY NAME (`schema_unsupported_trace_format`,
//!   the offending string in `detail`), the batch whole, nothing stored.
//!
//! `deployment_profile.run_kind` without a format member is refused
//! (`schema_missing_field`, `deployment_profile.trace_format_version`): the
//! v2.8.0 schema says `run_kind` exists only where the format is declared, and
//! at 2.7.0 the profile is NOT in the signed bytes, so an unsigned `run_kind`
//! must never reach a run-kind gate.
//!
//! **The vendored schema.** `trace_format_v2_8_0.json` is copied byte-exact
//! from CIRISAgent ([`TRACE_FORMAT_V2_8_0_SOURCE`]) and pinned by its file
//! SHA-256 ([`TRACE_FORMAT_V2_8_0_SHA256`], the hash CIRISAgent publishes in
//! `schemas/SCHEMA_SHA256` and on CIRISPersist#1089). The bytes and the pin
//! move together; re-vendoring a new cut adds a new format here, it never
//! edits this one.

use std::sync::OnceLock;

use super::trace::{CompleteTrace, RUN_KINDS};
use super::Error;

/// The `trace_format` v2.8.0 identifier (`deployment_profile.trace_format_version`).
pub const TRACE_FORMAT_V2_8_0: &str = "2.8.0";

/// Every `trace_format_version` this build has vendored a schema for. A value
/// outside this set is refused by name.
pub const VENDORED_TRACE_FORMATS: &[&str] = &[TRACE_FORMAT_V2_8_0];

/// The vendored v2.8.0 schema, byte-exact.
pub const TRACE_FORMAT_V2_8_0_SCHEMA: &str = include_str!("trace_format_v2_8_0.json");

/// SHA-256 of the vendored `trace_format_v2_8_0.json` FILE bytes
/// (CIRISPersist#1089; CIRISAgent `schemas/SCHEMA_SHA256`).
pub const TRACE_FORMAT_V2_8_0_SHA256: &str =
    "8c51028c8983741f0e14c89c32988df6aacc0981db5a173814e31d9f461c9f81";

/// Where the vendored bytes were copied from: the CIRISAgent commit (the head
/// of CIRISAgent#1255, `feat/trace-format-v2-8-0`) and path.
pub const TRACE_FORMAT_V2_8_0_SOURCE: &str =
    "CIRISAI/CIRISAgent@e7d9115180e8910999901f4805c31b617b34e8d5:\
     ciris_adapters/ciris_accord_metrics/schemas/trace_format_v2_8_0.json";

/// The compiled validator for a vendored format, built once.
fn validator_for(format: &str) -> Option<(&'static str, &'static jsonschema::Validator)> {
    static V2_8_0: OnceLock<jsonschema::Validator> = OnceLock::new();
    match format {
        TRACE_FORMAT_V2_8_0 => Some((
            TRACE_FORMAT_V2_8_0,
            V2_8_0.get_or_init(|| {
                let schema: serde_json::Value = serde_json::from_str(TRACE_FORMAT_V2_8_0_SCHEMA)
                    .expect("the vendored trace_format v2.8.0 schema is JSON (pinned test)");
                jsonschema::validator_for(&schema)
                    .expect("the vendored trace_format v2.8.0 schema compiles (pinned test)")
            }),
        )),
        _ => None,
    }
}

/// The longest `detail` a format violation carries (paths only, never
/// payload values: THREAT_MODEL.md AV-15).
const VIOLATION_DETAIL_MAX: usize = 256;

/// The format gate over one parsed trace (see the module doc). Pure.
///
/// # Errors
///
/// - [`Error::MissingField`] — `deployment_profile.run_kind` without
///   `deployment_profile.trace_format_version`;
/// - [`Error::UnsupportedTraceFormat`] — a format this node has not vendored;
/// - [`Error::TraceFormatViolation`] — the trace does not validate against
///   its vendored format's schema;
/// - [`Error::UnknownRunKind`] — a profile `run_kind` outside [`RUN_KINDS`];
/// - [`Error::RunKindConflict`] — the top-level and profile `run_kind`
///   disagree.
pub fn check_trace_format(trace: &CompleteTrace) -> Result<(), Error> {
    let Some(profile) = trace.deployment_profile.as_ref() else {
        return Ok(());
    };
    let Some(declared) = profile.trace_format_version.as_deref() else {
        if profile.run_kind.is_some() {
            return Err(Error::MissingField(
                "deployment_profile.trace_format_version",
            ));
        }
        return Ok(());
    };
    let Some((format, validator)) = validator_for(declared) else {
        return Err(Error::UnsupportedTraceFormat {
            got: declared.to_owned(),
            vendored: VENDORED_TRACE_FORMATS,
        });
    };
    if let Some(kind) = profile.run_kind.as_deref() {
        if !RUN_KINDS.contains(&kind) {
            return Err(Error::UnknownRunKind(kind.to_owned()));
        }
        if let Some(top) = trace.run_kind.as_deref() {
            if top != kind {
                return Err(Error::RunKindConflict {
                    top_level: top.to_owned(),
                    profile: kind.to_owned(),
                });
            }
        }
    }
    let instance = serde_json::to_value(trace)?;
    if let Some(e) = validator.iter_errors(&instance).next() {
        let mut at = format!("{} ({})", e.instance_path(), e.schema_path());
        if at.len() > VIOLATION_DETAIL_MAX {
            let mut cut = VIOLATION_DETAIL_MAX;
            while !at.is_char_boundary(cut) {
                cut -= 1;
            }
            at.truncate(cut);
        }
        return Err(Error::TraceFormatViolation { format, at });
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    /// I1035 — the vendored v2.8.0 schema's file bytes hash to the pin, and
    /// the schema compiles. The bytes and the pin move together.
    #[test]
    fn i1035_vendored_trace_format_v2_8_0_sha256_is_pinned() {
        use sha2::{Digest, Sha256};
        assert_eq!(
            hex::encode(Sha256::digest(TRACE_FORMAT_V2_8_0_SCHEMA.as_bytes())),
            TRACE_FORMAT_V2_8_0_SHA256,
            "I1035: trace_format_v2_8_0.json bytes moved without TRACE_FORMAT_V2_8_0_SHA256"
        );
        assert_eq!(
            TRACE_FORMAT_V2_8_0_SHA256,
            "8c51028c8983741f0e14c89c32988df6aacc0981db5a173814e31d9f461c9f81",
            "I1035: the pin is the hash CIRISAgent published on CIRISPersist#1089"
        );
        let schema: serde_json::Value = serde_json::from_str(TRACE_FORMAT_V2_8_0_SCHEMA).unwrap();
        assert_eq!(
            schema["$id"], "https://ciris.ai/schemas/trace_format_v2.8.0.json",
            "I1035: the vendored file is the v2.8.0 contract"
        );
        assert_eq!(
            schema["definitions"]["DeploymentProfile"]["properties"]["trace_format_version"]
                ["const"],
            TRACE_FORMAT_V2_8_0,
            "I1035: the schema keys on the member the gate reads"
        );
        let enum_: Vec<&str> = schema["definitions"]["RunKind"]["enum"]
            .as_array()
            .unwrap()
            .iter()
            .map(|v| v.as_str().unwrap())
            .collect();
        assert_eq!(
            enum_, RUN_KINDS,
            "I1035: the vendored RunKind enum is persist's closed run_kind vocabulary"
        );
        assert!(validator_for(TRACE_FORMAT_V2_8_0).is_some());
        assert!(validator_for("2.9.0").is_none());
        assert_eq!(VENDORED_TRACE_FORMATS, &[TRACE_FORMAT_V2_8_0]);
        let commit = TRACE_FORMAT_V2_8_0_SOURCE.split(['@', ':']).nth(1).unwrap();
        assert!(
            commit.len() == 40 && commit.bytes().all(|b| b.is_ascii_hexdigit()),
            "I1035: the source names a full commit id, never a branch"
        );
    }
}
