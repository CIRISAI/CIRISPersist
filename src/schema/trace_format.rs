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
//! from CIRISAgent and pinned by ONE constant, [`TRACE_FORMAT_V2_8_0_PIN`]:
//! the file name, its SHA-256 (the hash CIRISAgent publishes in
//! `schemas/SCHEMA_SHA256` and on CIRISPersist#1089), the source commit, and
//! the bytes (`include_str!` of that same file name). The bytes and the pin
//! move together. **Re-vendoring the v2.8.0 re-cut** (the operator's
//! `prod-personal` / `prod-managed` amendment on #1089) is: replace the file,
//! and swap the hash and source in that one constant. I1035 then checks the
//! new bytes against the new hash, and I1037 flips from "refused" to
//! "admitted".

use std::sync::OnceLock;

use super::trace::{CompleteTrace, RUN_KINDS};
use super::Error;

/// The `trace_format` v2.8.0 identifier (`deployment_profile.trace_format_version`).
pub const TRACE_FORMAT_V2_8_0: &str = "2.8.0";

/// Every `trace_format_version` this build has vendored a schema for. A value
/// outside this set is refused by name.
pub const VENDORED_TRACE_FORMATS: &[&str] = &[TRACE_FORMAT_V2_8_0];

/// One vendored trace-format schema: everything that moves on a re-vendor.
#[derive(Debug, Clone, Copy)]
pub struct VendoredTraceFormat {
    /// The `deployment_profile.trace_format_version` it validates.
    pub format: &'static str,
    /// The vendored file's name, beside this module.
    pub file: &'static str,
    /// SHA-256 of the file's bytes (lowercase hex).
    pub sha256: &'static str,
    /// Where the bytes were copied from: `owner/repo@commit:path`.
    pub source: &'static str,
    /// The file's bytes (`include_str!` of [`file`](Self::file)).
    pub schema: &'static str,
}

/// Builds a [`VendoredTraceFormat`] whose bytes are read from the SAME file
/// name it records, so the name is written once.
macro_rules! vendored_trace_format {
    ($format:expr, $file:literal, $sha256:literal, $source:literal) => {
        VendoredTraceFormat {
            format: $format,
            file: $file,
            sha256: $sha256,
            source: $source,
            schema: include_str!($file),
        }
    };
}

/// THE v2.8.0 pin (CIRISPersist#1089). The source commit is the head of
/// CIRISAgent#1255 (`feat/trace-format-v2-8-0`), cut before the operator's
/// run_kind amendment. A re-vendor swaps this one constant and the file.
pub const TRACE_FORMAT_V2_8_0_PIN: VendoredTraceFormat = vendored_trace_format!(
    TRACE_FORMAT_V2_8_0,
    "trace_format_v2_8_0.json",
    "8c51028c8983741f0e14c89c32988df6aacc0981db5a173814e31d9f461c9f81",
    "CIRISAI/CIRISAgent@e7d9115180e8910999901f4805c31b617b34e8d5:ciris_adapters/ciris_accord_metrics/schemas/trace_format_v2_8_0.json"
);

/// The compiled validator for a vendored format, built once.
fn validator_for(format: &str) -> Option<(&'static str, &'static jsonschema::Validator)> {
    static V2_8_0: OnceLock<jsonschema::Validator> = OnceLock::new();
    match format {
        TRACE_FORMAT_V2_8_0 => Some((
            TRACE_FORMAT_V2_8_0,
            V2_8_0.get_or_init(|| {
                let schema: serde_json::Value =
                    serde_json::from_str(TRACE_FORMAT_V2_8_0_PIN.schema)
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

    /// I1035 — the vendored v2.8.0 schema's file bytes hash to the ONE pin,
    /// the schema compiles, and it keys on the member the gate reads. The
    /// bytes and the pin move together.
    #[test]
    fn i1035_vendored_trace_format_v2_8_0_sha256_is_pinned() {
        use sha2::{Digest, Sha256};
        let pin = TRACE_FORMAT_V2_8_0_PIN;
        assert_eq!(
            hex::encode(Sha256::digest(pin.schema.as_bytes())),
            pin.sha256,
            "I1035: {} bytes moved without TRACE_FORMAT_V2_8_0_PIN.sha256",
            pin.file
        );
        assert_eq!(pin.format, TRACE_FORMAT_V2_8_0);
        assert!(
            pin.source.ends_with(&format!("/{}", pin.file)),
            "I1035: the source path names the vendored file"
        );
        let commit = pin.source.split(['@', ':']).nth(1).unwrap();
        assert!(
            commit.len() == 40 && commit.bytes().all(|b| b.is_ascii_hexdigit()),
            "I1035: the source names a full commit id, never a branch"
        );
        let schema: serde_json::Value = serde_json::from_str(pin.schema).unwrap();
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
        // Every run_kind the vendored schema admits is in persist's
        // vocabulary: the schema may lag the vocabulary, never lead it.
        for v in schema["definitions"]["RunKind"]["enum"].as_array().unwrap() {
            assert!(
                RUN_KINDS.contains(&v.as_str().unwrap()),
                "I1035: the vendored schema admits {v}, outside RUN_KINDS"
            );
        }
        assert!(validator_for(TRACE_FORMAT_V2_8_0).is_some());
        assert!(validator_for("2.9.0").is_none());
        assert_eq!(VENDORED_TRACE_FORMATS, &[TRACE_FORMAT_V2_8_0]);
    }

    /// A one-trace batch body: `trace_schema_version` `epoch`, with `run_kind`
    /// at the top level and/or in a `deployment_profile` that declares
    /// `format`. Unsigned: these legs stop at the parse-time gates.
    fn batch(
        epoch: &str,
        top: Option<&str>,
        profile: Option<(Option<&str>, Option<&str>)>,
    ) -> Vec<u8> {
        let mut t = serde_json::json!({
            "trace_id": "trace-pure",
            "thought_id": "th-1",
            "task_id": "task-1",
            "agent_id_hash": "deadbeef",
            "started_at": "2026-10-14T00:15:53.123456Z",
            "completed_at": "2026-10-14T00:16:12.789012Z",
            "trace_level": "generic",
            "trace_schema_version": epoch,
            "components": [{
                "component_type": "observation",
                "event_type": "THOUGHT_START",
                "timestamp": "2026-10-14T00:15:53.123Z",
                "agent_id_hash": "deadbeef",
                "data": {"round_number": 0},
            }],
            "signature": "",
            "signature_key_id": "agent",
        });
        if let Some(k) = top {
            t["run_kind"] = serde_json::json!(k);
        }
        if let Some((kind, format)) = profile {
            let mut p = serde_json::json!({
                "agent_role": "ally",
                "agent_template": "ally-v3-default",
                "deployment_domain": "general",
                "deployment_type": "personal",
                "deployment_region": null,
                "deployment_trust_mode": "federated_peer",
            });
            if let Some(k) = kind {
                p["run_kind"] = serde_json::json!(k);
            }
            if let Some(f) = format {
                p["trace_format_version"] = serde_json::json!(f);
            }
            t["deployment_profile"] = p;
        }
        serde_json::json!({
            "events": [{"event_type": "complete_trace", "trace_level": "generic", "trace": t}],
            "batch_timestamp": "2026-10-14T15:00:00+00:00",
            "consent_timestamp": "2025-01-01T00:00:00Z",
            "trace_level": "generic",
            "trace_schema_version": epoch,
        })
        .to_string()
        .into_bytes()
    }

    fn parsed_run_kind(bytes: &[u8]) -> Result<Option<String>, Error> {
        let env = crate::schema::BatchEnvelope::from_json(bytes)?;
        let crate::schema::BatchEvent::CompleteTrace { trace, .. } = &env.events[0];
        Ok(trace.signed_run_kind().map(str::to_owned))
    }

    /// I1036 (CIRISPersist#1089, operator amendment) — the run_kind gate
    /// alone: `prod-personal` and `prod-managed` are in the closed vocabulary
    /// and admit exactly as `production` does, at the parse gate and at the
    /// `trace:*` attestation shape gate; none of them is the mock kind the
    /// ingest and federation gates refuse. Only an unknown value is refused.
    #[test]
    fn i1036_the_run_kind_gate_admits_the_production_family() {
        use crate::federation::steward_purge::RUN_KIND_MOCK;
        for kind in [
            "production",
            "prod-personal",
            "prod-managed",
            "qa",
            "battery",
        ] {
            let got = parsed_run_kind(&batch("2.7.0", Some(kind), None))
                .unwrap_or_else(|e| panic!("I1036: a 2.7.0 run_kind {kind} parses: {e}"));
            assert_eq!(got.as_deref(), Some(kind), "I1036");
            assert_ne!(
                got.as_deref(),
                Some(RUN_KIND_MOCK),
                "I1036: not the mock kind"
            );
            for (form, trace) in [
                ("top", serde_json::json!({"run_kind": kind})),
                (
                    "profile",
                    serde_json::json!({"deployment_profile": {"run_kind": kind}}),
                ),
            ] {
                let env = serde_json::json!({
                    "dimension": crate::ingest::TRACE_ATTESTATION_DIMENSION,
                    "trace_id": "trace-pure",
                    "agent_id_hash": "deadbeef",
                    "trace": trace,
                });
                crate::federation::admission::check_trace_dimension_admission(
                    Some(crate::ingest::TRACE_ATTESTATION_DIMENSION),
                    "agent",
                    &["agent".to_owned()],
                    &env,
                )
                .unwrap_or_else(|e| panic!("I1036: trace:* {form} run_kind {kind}: {e}"));
            }
        }
        // `mock` is in the vocabulary (it parses) and IS the refused kind.
        let got = parsed_run_kind(&batch("2.7.0", Some("mock"), None)).unwrap();
        assert_eq!(got.as_deref(), Some(RUN_KIND_MOCK), "I1036");
        // Outside the vocabulary: refused.
        let e = parsed_run_kind(&batch("2.7.0", Some("prod-other"), None)).unwrap_err();
        assert_eq!(e.kind(), "schema_unknown_run_kind", "I1036: {e}");
    }

    /// The hash of the v2.8.0 cut vendored at v56.0.0, which predates the
    /// operator's run_kind amendment on #1089 (its RunKind enum has four
    /// values). Not a pin: the identity of the cut I1037 describes.
    const PRE_AMENDMENT_V2_8_0_SHA256: &str =
        "8c51028c8983741f0e14c89c32988df6aacc0981db5a173814e31d9f461c9f81";

    /// I1037 (CIRISPersist#1089) — the schema-level fact, stated honestly.
    /// Under the pre-amendment v2.8.0 cut, a v2.8.0 trace carrying
    /// `prod-personal` or `prod-managed` passes the run_kind gate but is
    /// refused BY SCHEMA VALIDATION, by name (`schema_trace_format_violation`
    /// at `/deployment_profile/run_kind`), never truncated or relabelled.
    /// This leg FLIPS when the re-cut schema is vendored: under any other pin
    /// both values must admit.
    #[test]
    fn i1037_the_vendored_v28_cut_refuses_the_new_prod_values_until_re_vendored() {
        let schema: serde_json::Value =
            serde_json::from_str(TRACE_FORMAT_V2_8_0_PIN.schema).unwrap();
        let schema_kinds: Vec<&str> = schema["definitions"]["RunKind"]["enum"]
            .as_array()
            .unwrap()
            .iter()
            .map(|v| v.as_str().unwrap())
            .collect();
        // The same trace with `production` admits under every cut.
        parsed_run_kind(&batch(
            "3.0.0",
            None,
            Some((Some("production"), Some(TRACE_FORMAT_V2_8_0))),
        ))
        .expect("I1037: a v2.8.0 production trace parses");
        for kind in ["prod-personal", "prod-managed"] {
            let got = parsed_run_kind(&batch(
                "3.0.0",
                None,
                Some((Some(kind), Some(TRACE_FORMAT_V2_8_0))),
            ));
            if TRACE_FORMAT_V2_8_0_PIN.sha256 == PRE_AMENDMENT_V2_8_0_SHA256 {
                assert!(
                    !schema_kinds.contains(&kind),
                    "I1037: the pre-amendment cut does not list {kind}"
                );
                let e = got.expect_err("I1037: refused by the vendored schema");
                assert_eq!(
                    e.kind(),
                    "schema_trace_format_violation",
                    "I1037 {kind}: {e}"
                );
                let detail = e.detail().unwrap();
                assert!(
                    detail.starts_with("2.8.0:/deployment_profile/run_kind"),
                    "I1037 {kind}: refused at the member, by name: {detail}"
                );
            } else {
                assert!(
                    schema_kinds.contains(&kind),
                    "I1037: the re-vendored cut lists {kind}"
                );
                assert_eq!(
                    got.unwrap_or_else(|e| panic!("I1037: re-vendored, {kind} admits: {e}"))
                        .as_deref(),
                    Some(kind)
                );
            }
        }
    }
}
