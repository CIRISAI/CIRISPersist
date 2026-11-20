//! v62.0.0 (P7-fix9; agreed with Server + Agent, FREEZE.md
//! `trace_schema_version 3.1.0`) — **`"3.1.0"` is a JCS-epoch label, and an
//! `LLM_CALL` component's `context_manifest` rides the trace untouched**, on
//! every backend (sqlite, and postgres when a test DSN is set).
//!
//! - **I3471** (pure) `"3.1.0"` is in `SUPPORTED_VERSIONS`; it selects the
//!   JCS canonicalizer (major 3); `BatchEnvelope::from_json` takes the
//!   3.0.0 path (no `deployment_profile` demanded); the canonical payload
//!   dispatch is 3.0.0's, byte for byte save the signed version string; and
//!   the typed `llm_call` projection of a component is the same with and
//!   without its `context_manifest` (and an unknown member).
//! - **I3470** (sqlite, pg) a batch at `"3.0.0"` and one at `"3.1.0"`, each a
//!   trace ROW (the agent's `trace:complete:v1` statement under its agent
//!   key, dated from that key's own window) whose `LLM_CALL` data carries a
//!   realistic `context_manifest` (13 / 20 nested segments, guard
//!   violations, 6–12 KB, 6 levels) and an unknown member, plus an unknown
//!   trace-level member:
//!   - it lands, and its statement verified (`signatures_verified == 1`);
//!   - the blob plane holds the trace's bytes exactly, and the stored
//!     `trace_events` data reads back member for member, the manifest's JCS
//!     bytes identical to the sent ones;
//!   - the statement covers the member: the same row over a blob whose
//!     manifest changed by one segment is refused
//!     `trace_statement_content_mismatch`;
//!   - the stored `llm_call` row is the projection of the trace WITHOUT the
//!     manifest and the unknown member (they are ignored, never refused).
//!
//!   CIRISAgent#1370: every component's data also carries a signed
//!   `run_kind`, and the LLM_CALL carries `egress_alterations` (one entry
//!   with `sha256`, one without; the THOUGHT_START none). Every component's
//!   data reads back whole (JCS-identical), and the projection is unchanged.
//! - **I3470 (mock leg; sqlite, pg)** a trace whose ONLY `mock` is one
//!   component's signed `data.run_kind` (the lead's ruling, mock-dominant
//!   `manifest.run_kind`): refused `trace_run_kind_mock` at the batch door on
//!   any node and replicated onto the canonical; an older encoder's row (no
//!   `manifest.run_kind`) refused by the member pin and, replicated with its
//!   blob, by the projection-time check; a component `qa` lands.
//! - **I3471 (pure, effective kind)** a component-only mock seals as
//!   `manifest.run_kind == "mock"`; a non-mock manifest is unchanged.
//! - **I3471 (pure, mock)** `CompleteTrace::signs_mock_run` and
//!   `steward_purge::trace_signs_mock` agree on a table of signed places.

use super::*;
use crate::federation::edition2::fixture_switch as e2;
use crate::federation::{BlobBody, BlobStorage, FederationDirectory};
use crate::verify::PythonJsonDumpsCanonicalizer;

const DAY_MS: u64 = 86_400_000;

fn unique(tag: &str) -> String {
    format!(
        "p7-310-{tag}-{}",
        &uuid::Uuid::new_v4().simple().to_string()[..12]
    )
}

/// RFC 3339, milliseconds, `Z`, of `ms` since the epoch.
fn instant(ms: u64) -> String {
    chrono::DateTime::<chrono::Utc>::from_timestamp_millis(i64::try_from(ms).expect("ms"))
        .expect("an instant")
        .to_rfc3339_opts(chrono::SecondsFormat::Millis, true)
}

/// The instant `seed`'s traces are dated at: its key's own window start plus
/// K2's fixed offset (`OWNER_BINDING_OFFSET_DAYS`). Never the wall clock.
fn dated_ms(seed: &str) -> u64 {
    let offset =
        u64::try_from(crate::federation::tier_ingest::test_support::OWNER_BINDING_OFFSET_DAYS)
            .expect("a positive day count");
    e2::key_window_start_ms(seed) + offset * DAY_MS
}

const KINDS: [&str; 5] = [
    "system",
    "memory",
    "tool_result",
    "conversation",
    "guidance",
];

/// A realistic `context_manifest`, deterministic in `segments`: each segment
/// a few strings and numbers, a non-ASCII summary, and a nested provenance
/// (`manifest → segments → segment → provenance → window → bounds`: 6
/// levels); two guard violations with a nested detail.
fn context_manifest(segments: usize) -> serde_json::Value {
    let segs: Vec<serde_json::Value> = (0..segments)
        .map(|i| {
            let kind = KINDS[i % KINDS.len()];
            let summary: String = format!(
                "Context segment {i} carries the agent's working memory for this \
                 thought: retrieved notes, tool output and prior turns, trimmed to \
                 budget. Résumé de contexte; "
            )
            .repeat(2)
            .chars()
            .take(230)
            .collect();
            serde_json::json!({
                "segment_id": format!("seg-{i:03}"),
                "kind": kind,
                "source": format!("source://{kind}/{i}"),
                "token_count": 40 + 7 * i,
                "byte_len": 160 + 29 * i,
                "weight": f64::from(u8::try_from(i % 4).expect("small")) * 0.25 + 0.25,
                "summary": summary,
                "provenance": {
                    "origin": "agent_memory",
                    "content_hash": format!("sha256:{}", format!("{:02x}", i % 256).repeat(32)),
                    "window": {
                        "start": 100 * i,
                        "end": 100 * i + 80,
                        "bounds": [100 * i, 100 * i + 80],
                    },
                },
            })
        })
        .collect();
    let total: usize = (0..segments).map(|i| 40 + 7 * i).sum();
    serde_json::json!({
        "schema": "context_manifest:v1",
        "segment_count": segments,
        "total_tokens": total,
        "segments": segs,
        "guard_violations": [
            {"guard": "pii_redaction", "severity": "low", "segment_id": "seg-002",
             "detail": {"rule": "email", "matched": 1}},
            {"guard": "budget", "severity": "info",
             "segment_id": format!("seg-{:03}", segments - 1),
             "detail": {"rule": "token_budget", "matched": 0}},
        ],
        "assembled_by": {"component": "context_builder", "version": "3.1.0"},
    })
}

/// The `LLM_CALL` component's typed members (what `trace_llm_calls` holds).
fn llm_data() -> serde_json::Map<String, serde_json::Value> {
    let serde_json::Value::Object(m) = serde_json::json!({
        "attempt_index": 0,
        "handler_name": "dsdma",
        "service_name": "llm",
        "duration_ms": 812.5,
        "status": "ok",
        "model": "ciris-test-model",
        "prompt_tokens": 2048,
        "completion_tokens": 256,
        "cost_usd": 0.25,
        "parent_event_type": "THOUGHT_START",
        "parent_attempt_index": 0,
    }) else {
        unreachable!("an object literal")
    };
    m
}

/// The `egress_alterations` an agent records on a component (CIRISAgent
/// #1370): one entry with a `sha256`, one without.
fn egress_alterations() -> serde_json::Value {
    serde_json::json!([
        {"path": "data.response_text", "kind": "redacted", "original_length": 1840,
         "sha256": format!("sha256:{}", "5a".repeat(32))},
        {"path": "data.prompt", "kind": "truncated", "original_length": 96_000},
    ])
}

/// A trace at `version` ending at `at_ms`: a THOUGHT_START and an LLM_CALL
/// whose data is [`llm_data`], plus:
/// - with `manifest`: the LLM_CALL's `context_manifest` and an unknown member
///   (and an unknown trace-level member);
/// - with `run_kinds` (CIRISAgent#1370): each component's signed
///   `data.run_kind` (`[thought_start, llm_call]`), and the LLM_CALL's
///   `egress_alterations` (the THOUGHT_START has none).
///
/// No signature members: the row is its signature.
fn trace_at(
    version: &str,
    trace_id: &str,
    at_ms: u64,
    manifest: Option<&serde_json::Value>,
    run_kinds: Option<[&str; 2]>,
) -> serde_json::Value {
    let mut first = serde_json::Map::new();
    first.insert("attempt_index".into(), serde_json::json!(0));
    let mut data = llm_data();
    if let Some(m) = manifest {
        data.insert("context_manifest".into(), m.clone());
        data.insert(
            "x_future_member".into(),
            serde_json::json!({"note": "a member this build has never seen", "n": 3}),
        );
    }
    if let Some([k0, k1]) = run_kinds {
        first.insert("run_kind".into(), serde_json::json!(k0));
        data.insert("run_kind".into(), serde_json::json!(k1));
        data.insert("egress_alterations".into(), egress_alterations());
    }
    let mut t = serde_json::json!({
        "trace_id": trace_id,
        "thought_id": format!("{trace_id}-th"),
        "task_id": "task-310",
        "agent_id_hash": "agent-hash-310",
        "started_at": instant(at_ms - 2000),
        "completed_at": instant(at_ms),
        "trace_level": "generic",
        "trace_schema_version": version,
        "cohort_scope": "federation",
        "components": [
            {
                "component_type": "observation",
                "event_type": "THOUGHT_START",
                "timestamp": instant(at_ms - 2000),
                "data": first,
            },
            {
                "component_type": "llm_call",
                "event_type": "LLM_CALL",
                "timestamp": instant(at_ms - 1000),
                "data": data,
            },
        ],
    });
    if manifest.is_some() {
        t["x_future_trace_member"] = serde_json::json!("ignored, not refused");
    }
    t
}

/// The agent `seed` signs the row over `blob`.
fn row_of(seed: &str, blob: &[u8]) -> Vec<u8> {
    let iss = e2::kid(seed);
    let parsed: CompleteTrace = serde_json::from_slice(blob).expect("a CompleteTrace");
    let payload = trace_row_payload(&parsed, blob, &iss).expect("the row payload");
    ciris_verify_core::edition2::sign_row_statement(
        &e2::signing_key(seed),
        &iss,
        &iss,
        TRACE_ROW_TYPE,
        TRACE_FAMILY_ID,
        &payload,
        vec![],
    )
    .expect("sign the trace row")
}

/// A one-event row-form batch at `version`.
fn batch_of(version: &str, statement: &[u8], blob: &[u8]) -> Vec<u8> {
    use base64::Engine as _;
    let b64 = base64::engine::general_purpose::STANDARD;
    serde_json::json!({
        "events": [{
            "event_type": "complete_trace",
            "trace_level": "generic",
            "statement": b64.encode(statement),
            "trace_blob": b64.encode(blob),
        }],
        "batch_timestamp": "2026-05-01T00:00:00Z",
        "consent_timestamp": "2025-01-01T00:00:00Z",
        "trace_level": "generic",
        "trace_schema_version": version,
    })
    .to_string()
    .into_bytes()
}

async fn ingest<D>(d: &D, body: &[u8]) -> Result<BatchSummary, IngestError>
where
    D: Backend + FederationDirectory + ?Sized,
{
    let signer_key_id = "p7-310-scrub-key".to_owned();
    let mut sw = ciris_keyring::Ed25519SoftwareSigner::new(&signer_key_id);
    sw.import_key(&[0x31u8; 32]).expect("import_key");
    let signer: Box<dyn HardwareSigner> = Box::new(sw);
    let pipeline = IngestPipeline {
        backend: d,
        canonicalizer: &PythonJsonDumpsCanonicalizer,
        scrubber: &crate::scrub::NullScrubber,
        signer: &*signer,
        signer_key_id: &signer_key_id,
    };
    pipeline.receive_and_persist(body).await
}

fn jcs(v: &serde_json::Value) -> Vec<u8> {
    crate::verify::ceg_produce_canonicalize(v).expect("JCS")
}

/// The typed `llm_call` rows of `trace`, as decompose builds them.
fn llm_rows(trace: &serde_json::Value) -> Vec<crate::store::types::TraceLlmCallRow> {
    let t: CompleteTrace = serde_json::from_value(trace.clone()).expect("a CompleteTrace");
    crate::store::decompose(&t).expect("decomposes").llm_calls
}

// ── I3471 (pure) ────────────────────────────────────────────────────────

/// **I3471** — `"3.1.0"` is a supported JCS-epoch label on 3.0.0's path.
#[test]
fn i3471_3_1_0_is_a_jcs_epoch_label_on_the_3_0_0_path() {
    use crate::verify::canonical::CanonVersion;
    use crate::verify::ed25519::{canon_version_for_trace_schema, canonical_bytes_for_trace};
    assert!(
        crate::schema::SUPPORTED_VERSIONS.contains(&"3.1.0"),
        "I3471"
    );
    assert_eq!(
        crate::schema::SchemaVersion::parse("3.1.0")
            .unwrap()
            .as_str(),
        "3.1.0"
    );
    assert_eq!(canon_version_for_trace_schema("3.1.0"), CanonVersion::V2Jcs);

    // from_json: the 3.0.0 path (no deployment_profile demanded, unlike
    // 2.7.9), at both versions, with the manifest and the unknown members.
    let manifest = context_manifest(13);
    for v in ["3.0.0", "3.1.0"] {
        let mut trace = trace_at(
            v,
            "i3471",
            1_800_000_000_000,
            Some(&manifest),
            Some(["production", "qa"]),
        );
        trace["signature"] = serde_json::json!("");
        trace["signature_key_id"] = serde_json::json!("k");
        let body = serde_json::json!({
            "events": [{"event_type": "complete_trace", "trace_level": "generic", "trace": trace}],
            "batch_timestamp": "2026-05-01T00:00:00Z",
            "consent_timestamp": "2025-01-01T00:00:00Z",
            "trace_level": "generic",
            "trace_schema_version": v,
        });
        crate::schema::BatchEnvelope::from_json(body.to_string().as_bytes())
            .unwrap_or_else(|e| panic!("I3471 {v}: from_json takes it: {e}"));
    }

    // The canonical payload dispatch: 3.1.0's bytes are 3.0.0's, the signed
    // version string aside.
    let at = |v: &str| -> CompleteTrace {
        let mut t = trace_at(
            v,
            "i3471",
            1_800_000_000_000,
            Some(&manifest),
            Some(["production", "qa"]),
        );
        t["signature"] = serde_json::json!("");
        t["signature_key_id"] = serde_json::json!("k");
        serde_json::from_value(t).expect("a CompleteTrace")
    };
    let c = crate::verify::canonical::canonicalizer_for(CanonVersion::V2Jcs);
    let b300 = canonical_bytes_for_trace(&at("3.0.0"), c).expect("3.0.0 dispatches");
    let b310 = canonical_bytes_for_trace(&at("3.1.0"), c).expect("3.1.0 dispatches");
    let mut v300: serde_json::Value = serde_json::from_slice(&b300).unwrap();
    let v310: serde_json::Value = serde_json::from_slice(&b310).unwrap();
    v300["trace_schema_version"] = serde_json::json!("3.1.0");
    assert_eq!(v300, v310, "I3471: the 3.0.0 canonical layout");

    // The typed llm_call projection ignores the manifest and the unknown
    // member, at both versions.
    for v in ["3.0.0", "3.1.0"] {
        let with = llm_rows(&trace_at(
            v,
            "i3471",
            1_800_000_000_000,
            Some(&manifest),
            Some(["production", "qa"]),
        ));
        let without = llm_rows(&trace_at(v, "i3471", 1_800_000_000_000, None, None));
        assert_eq!(with.len(), 1, "I3471 {v}: one llm_call");
        assert_eq!(with, without, "I3471 {v}: the projection is unaffected");
    }
}

// ── I3470 (sqlite, pg) ──────────────────────────────────────────────────

async fn exercise_context_manifest<D>(d: &D, version: &str, segments: usize, run_kinds: [&str; 2])
where
    D: Backend + FederationDirectory + BlobStorage + crate::ceg::ReadEngine,
{
    let agent = unique("agent");
    let kid = e2::put_key(d, &agent, &["agent"]).await;
    let at = dated_ms(&agent);
    let manifest = context_manifest(segments);
    let size = jcs(&manifest).len();
    assert!(
        (6_000..=12_288).contains(&size),
        "I3470 {version}: a realistic manifest is 6–12 KB, got {size}"
    );

    let trace_id = unique("trace");
    let trace = trace_at(version, &trace_id, at, Some(&manifest), Some(run_kinds));
    let blob = canonical_trace_blob(&trace).expect("a trace object");
    let statement = row_of(&agent, &blob);

    // The statement covers the member: one segment changed in the blob.
    let mut altered = manifest.clone();
    altered["segments"][0]["token_count"] = serde_json::json!(41);
    let altered_blob = canonical_trace_blob(&trace_at(
        version,
        &trace_id,
        at,
        Some(&altered),
        Some(run_kinds),
    ))
    .unwrap();
    let refused = ingest(d, &batch_of(version, &statement, &altered_blob)).await;
    match &refused {
        Err(e) => assert_eq!(
            e.kind(),
            TRACE_STATEMENT_CONTENT_MISMATCH,
            "I3470 {version}: the row binds the member"
        ),
        Ok(_) => panic!("I3470 {version}: an altered manifest is refused"),
    }

    // It lands; the statement verified.
    let summary = ingest(d, &batch_of(version, &statement, &blob))
        .await
        .unwrap_or_else(|e| panic!("I3470 {version}: lands: {} ({e})", e.kind()));
    // The signature verify, on its own (not the tamper check above): the door
    // counted ONE verified statement, and the row it admitted is held under
    // the id Verify computes from those signed bytes, attested by the agent.
    assert_eq!(summary.signatures_verified, 1, "I3470 {version}: verified");
    let row_id = crate::federation::edition2::names::RowId::of_statement(&statement)
        .expect("a row statement")
        .hex();
    let held = d
        .get_attestation(&row_id)
        .await
        .expect("get_attestation")
        .unwrap_or_else(|| panic!("I3470 {version}: the verified row is held"));
    assert_eq!(
        held.attesting_key_id, kid,
        "I3470 {version}: the signature is the agent key's"
    );

    // The blob plane holds the trace's bytes exactly.
    let sha: [u8; 32] = sha2::Sha256::digest(&blob).into();
    match d.get_blob(&sha).await.expect("get_blob") {
        Some(BlobBody::Inline(bytes)) => assert_eq!(
            bytes, blob,
            "I3470 {version}: the blob is held byte for byte"
        ),
        other => panic!("I3470 {version}: the blob is held inline, got {other:?}"),
    }

    // The stored data reads back, member included.
    let rows: Vec<_> = d
        .fetch_trace_events_page(-1, i64::MAX, None)
        .await
        .expect("fetch_trace_events_page")
        .into_iter()
        .map(|(_, r)| r)
        .filter(|r| r.trace_id == trace_id)
        .collect();
    assert_eq!(rows.len(), 2, "I3470 {version}: both components land");
    let llm = rows
        .iter()
        .find(|r| r.event_type == crate::schema::ReasoningEventType::LlmCall)
        .expect("the LLM_CALL row");
    assert_eq!(llm.signing_key_id, kid, "I3470 {version}: the agent's row");
    let stored_manifest = llm
        .payload
        .get("context_manifest")
        .expect("I3470: the manifest is stored");
    assert_eq!(
        jcs(stored_manifest),
        jcs(&manifest),
        "I3470 {version}: the manifest reads back byte for byte (JCS)"
    );
    // Every component's data reads back whole: the LLM_CALL's (the unknown
    // member, `run_kind`, both `egress_alterations` entries — with and
    // without `sha256` — included) and the THOUGHT_START's (`run_kind`, no
    // `egress_alterations`).
    for (i, event_type) in [
        (0, crate::schema::ReasoningEventType::ThoughtStart),
        (1, crate::schema::ReasoningEventType::LlmCall),
    ] {
        let row = rows
            .iter()
            .find(|r| r.event_type == event_type)
            .expect("the component's row");
        let sent = trace["components"][i]["data"]
            .as_object()
            .expect("the data object");
        assert_eq!(
            &row.payload, sent,
            "I3470 {version}: component {i}'s data reads back whole"
        );
        assert_eq!(
            jcs(&serde_json::Value::Object(row.payload.clone())),
            jcs(&serde_json::Value::Object(sent.clone())),
            "I3470 {version}: component {i}'s data, byte for byte (JCS)"
        );
    }
    assert_eq!(
        llm.payload.get("egress_alterations"),
        Some(&egress_alterations()),
        "I3470 {version}: egress_alterations reads back"
    );
    assert!(
        rows.iter()
            .find(|r| r.event_type == crate::schema::ReasoningEventType::ThoughtStart)
            .is_some_and(|r| !r.payload.contains_key("egress_alterations")),
        "I3470 {version}: a component that carried none has none"
    );

    // The typed llm_call row is the projection WITHOUT the manifest.
    let page = d
        .list_llm_calls(
            crate::ceg::LlmCallFilter {
                trace_id: Some(trace_id.clone()),
                ..Default::default()
            },
            None,
            10,
            crate::scope::CallerScope::Unauthenticated,
        )
        .await
        .expect("list_llm_calls");
    assert_eq!(page.items.len(), 1, "I3470 {version}: one llm_call row");
    let mut stored = page.items[0].clone();
    stored.parent_event_id = None;
    let want = llm_rows(&trace_at(version, &trace_id, at, None, None));
    assert_eq!(
        vec![stored],
        want,
        "I3470 {version}: the typed projection is unaffected"
    );
}

/// **I3471 (pure, CIRISAgent#1370)** — the signed-mock rule, typed and over
/// JSON, agree: any signed place that says `mock` (top level,
/// `deployment_profile`, any component's `data.run_kind`) is a mock run.
#[test]
fn i3471_a_mock_in_any_signed_place_is_a_mock_run() {
    type Case<'a> = (Option<&'a str>, Option<[&'a str; 2]>, bool);
    let cases: &[Case<'_>] = &[
        (None, None, false),
        (None, Some(["production", "qa"]), false),
        (None, Some(["production", "mock"]), true),
        (None, Some(["mock", "production"]), true),
        (Some("mock"), Some(["production", "qa"]), true),
        (Some("production"), Some(["qa", "mock"]), true),
        (Some("qa"), None, false),
    ];
    for (top, kinds, mock) in cases {
        let mut t = trace_at("3.1.0", "i3471-mock", 1_800_000_000_000, None, *kinds);
        if let Some(k) = top {
            t["run_kind"] = serde_json::json!(k);
        }
        assert_eq!(
            crate::federation::steward_purge::trace_signs_mock(&t),
            *mock,
            "I3471 json: {top:?} {kinds:?}"
        );
        t["signature"] = serde_json::json!("");
        t["signature_key_id"] = serde_json::json!("k");
        let typed: CompleteTrace = serde_json::from_value(t).expect("a CompleteTrace");
        assert_eq!(
            typed.signs_mock_run(),
            *mock,
            "I3471 typed: {top:?} {kinds:?}"
        );
    }
}

/// How many `trace_events` rows `trace_id` has on `d`.
async fn events_count<D: Backend>(d: &D, trace_id: &str) -> usize {
    d.fetch_trace_events_page(-1, i64::MAX, None)
        .await
        .expect("fetch_trace_events_page")
        .into_iter()
        .filter(|(_, r)| r.trace_id == trace_id)
        .count()
}

/// The trace row payload's `manifest` members, by name.
fn manifest_members(payload: &ciris_verify_core::cde::Value) -> Vec<String> {
    use ciris_verify_core::cde::Value;
    match payload.get_text("manifest") {
        Some(Value::Map(m)) => m
            .iter()
            .filter_map(|(k, _)| k.as_text().map(str::to_owned))
            .collect(),
        _ => Vec::new(),
    }
}

/// The trace row payload's `manifest.run_kind`, if any.
fn manifest_run_kind(payload: &ciris_verify_core::cde::Value) -> Option<String> {
    payload
        .get_text("manifest")
        .and_then(|m| m.get_text("run_kind"))
        .and_then(ciris_verify_core::cde::Value::as_text)
        .map(str::to_owned)
}

/// **I3471 (pure; the lead's ruling, mock-dominant)** — the row's manifest
/// carries the EFFECTIVE run kind: a component-only mock seals as
/// `manifest.run_kind == "mock"`; a non-mock trace's manifest is exactly what
/// it was (a component `qa` with no trace-level kind: NO `run_kind` member,
/// the four members the earlier encoder wrote; a trace-level kind: that kind).
/// I3478 pins a non-mock row's bytes against the published encoding, so the
/// ruling leaves it unchanged.
#[test]
fn i3471_the_manifest_carries_the_effective_run_kind() {
    let payload_of = |t: &serde_json::Value| {
        let blob = canonical_trace_blob(t).expect("a trace object");
        let parsed: CompleteTrace = serde_json::from_slice(&blob).unwrap();
        trace_row_payload(&parsed, &blob, &e2::kid("i3471-effective")).expect("payload")
    };
    let at = 1_800_000_000_000;
    let mock = payload_of(&trace_at(
        "3.1.0",
        "i3471-m",
        at,
        None,
        Some(["production", "mock"]),
    ));
    assert_eq!(
        manifest_run_kind(&mock).as_deref(),
        Some("mock"),
        "I3471: mock-dominant"
    );

    let qa = payload_of(&trace_at(
        "3.1.0",
        "i3471-q",
        at,
        None,
        Some(["production", "qa"]),
    ));
    assert_eq!(manifest_run_kind(&qa), None, "I3471: absent stays absent");
    let mut members = manifest_members(&qa);
    members.sort();
    assert_eq!(
        members,
        ["byte_len", "component_count", "content_hash", "schema"],
        "I3471: the earlier encoder's manifest, member for member"
    );

    let mut top = trace_at("3.1.0", "i3471-t", at, None, Some(["qa", "qa"]));
    top["run_kind"] = serde_json::json!("production");
    assert_eq!(
        manifest_run_kind(&payload_of(&top)).as_deref(),
        Some("production"),
        "I3471: a signed kind is copied exactly"
    );
}

/// **I3470 (mock leg; CIRISAgent#1370, the lead's ruling; sqlite, pg)** — a
/// component-only mock (the Agent signs NO trace-level `run_kind`):
/// - sealed into a row, its manifest says `mock`, so the federation-tier gate
///   refuses it `trace_run_kind_mock` at the batch door on ANY node (as a
///   trace-level mock always was: the row form writes the federation tier);
/// - replicated onto the canonical, it is refused `trace_run_kind_mock`;
/// - an OLDER encoder's row (no `manifest.run_kind`, the same component mock)
///   is refused: at the batch door by the member pin, and replicated with its
///   blob held, `trace_run_kind_mock` by the projection-time check;
/// - a component `qa` with no other mock lands on the canonical.
async fn exercise_component_mock<D>(d: &D, set_node: impl Fn(&str))
where
    D: Backend + FederationDirectory + BlobStorage,
{
    let agent = unique("agent-mock");
    let kid = e2::put_key(d, &agent, &["agent"]).await;
    let at = dated_ms(&agent);
    let blob_of = |trace_id: &str, kinds: [&str; 2]| {
        canonical_trace_blob(&trace_at("3.1.0", trace_id, at, None, Some(kinds)))
            .expect("a trace object")
    };
    let id_of = |statement: &[u8]| -> [u8; 32] {
        crate::federation::edition2::names::RowId::of_statement(statement)
            .expect("a row statement")
            .0
    };
    // An older encoder's row: the manifest without `run_kind`.
    let older_row = |blob: &[u8]| {
        use ciris_verify_core::cde::Value;
        let parsed: CompleteTrace = serde_json::from_slice(blob).unwrap();
        let Value::Map(mut members) = trace_row_payload(&parsed, blob, &kid).unwrap() else {
            unreachable!("a payload map")
        };
        for (k, v) in &mut members {
            if k.as_text() == Some("manifest") {
                if let Value::Map(m) = v {
                    m.retain(|(mk, _)| mk.as_text() != Some("run_kind"));
                }
            }
        }
        ciris_verify_core::edition2::sign_row_statement(
            &e2::signing_key(&agent),
            &kid,
            &kid,
            TRACE_ROW_TYPE,
            TRACE_FAMILY_ID,
            &Value::Map(members),
            vec![],
        )
        .expect("sign")
    };

    // Not canonical: the federation-tier gate refuses the sealed mock row.
    let t1 = unique("mock-noncanonical");
    let blob = blob_of(&t1, ["production", "mock"]);
    let e = ingest(d, &batch_of("3.1.0", &row_of(&agent, &blob), &blob))
        .await
        .expect_err("I3470 mock: a mock row never reaches the federation tier");
    assert_eq!(
        e.kind(),
        crate::federation::steward_purge::TRACE_RUN_KIND_MOCK,
        "I3470 mock: by name, off the canonical too"
    );
    assert_eq!(events_count(d, &t1).await, 0, "I3470 mock: nothing lands");

    // An older encoder's row at the batch door: the member pin refuses it.
    let t2 = unique("mock-older-batch");
    let blob = blob_of(&t2, ["production", "mock"]);
    let e = ingest(d, &batch_of("3.1.0", &older_row(&blob), &blob))
        .await
        .expect_err("I3470 mock: an older encoder's mock row");
    assert_eq!(
        e.kind(),
        TRACE_STATEMENT_CONTENT_MISMATCH,
        "I3470 mock: manifest.run_kind pinned to the effective kind"
    );

    // The canonical: a genesis serve seat, as the standing is read.
    crate::federation::edition2::fixture_genesis::install_v2(d)
        .await
        .expect("the bundle/2 test ceremony installs");
    let g = crate::federation::edition2::fixture_genesis::bundle_v2()
        .serve_node_identity_ref(0)
        .to_owned();
    assert!(
        crate::federation::is_canonical_effective(d.as_dyn_directory(), &g)
            .await
            .unwrap(),
        "fixture: the seat is canonical"
    );
    set_node(&g);

    // Replicated onto the canonical: refused by the manifest gate.
    let t3 = unique("mock-replicated");
    let blob = blob_of(&t3, ["production", "mock"]);
    let st = row_of(&agent, &blob);
    let e = Box::pin(
        crate::federation::edition2::ingest::apply_replicated_statement(d, &st, &id_of(&st)),
    )
    .await
    .expect_err("I3470 mock: a replicated mock row");
    assert_eq!(
        e.kind(),
        crate::federation::steward_purge::TRACE_RUN_KIND_MOCK,
        "I3470 mock: replicated, by name"
    );

    // An older encoder's row replicated with its blob held: the projection
    // reads the signed bytes and refuses it, the same token.
    let t4 = unique("mock-older-replicated");
    let blob = blob_of(&t4, ["production", "mock"]);
    let st = older_row(&blob);
    let sha: [u8; 32] = sha2::Sha256::digest(&blob).into();
    d.store_trace_blob(&sha, blob.clone(), "federation", None, &kid)
        .await
        .expect("the blob is held");
    let e = Box::pin(
        crate::federation::edition2::ingest::apply_replicated_statement(d, &st, &id_of(&st)),
    )
    .await
    .expect_err("I3470 mock: an older encoder's replicated mock row");
    assert_eq!(
        e.kind(),
        crate::federation::steward_purge::TRACE_RUN_KIND_MOCK,
        "I3470 mock: the projection-time check, by name"
    );
    assert_eq!(
        events_count(d, &t4).await,
        0,
        "I3470 mock: nothing projected"
    );

    // A component `qa`, no other mock: lands on the canonical.
    let t5 = unique("qa-canonical");
    let blob = blob_of(&t5, ["production", "qa"]);
    ingest(d, &batch_of("3.1.0", &row_of(&agent, &blob), &blob))
        .await
        .unwrap_or_else(|e| panic!("I3470 mock: a qa run lands: {} ({e})", e.kind()));
    assert_eq!(
        events_count(d, &t5).await,
        2,
        "I3470 mock: the qa trace lands"
    );
}

#[cfg(feature = "sqlite")]
mod sqlite {
    use super::*;

    async fn backend() -> crate::store::sqlite::SqliteBackend {
        let b = crate::store::sqlite::SqliteBackend::open_in_memory()
            .await
            .unwrap();
        b.run_migrations().await.unwrap();
        b
    }

    #[tokio::test]
    async fn i3470_context_manifest_3_0_0_sqlite() {
        let b = backend().await;
        Box::pin(exercise_context_manifest(
            &b,
            "3.0.0",
            13,
            ["production", "prod-personal"],
        ))
        .await;
    }

    #[tokio::test]
    async fn i3470_component_mock_sqlite() {
        let b = backend().await;
        Box::pin(exercise_component_mock(&b, |k| b.set_node_key_id(k))).await;
    }

    #[tokio::test]
    async fn i3470_context_manifest_3_1_0_sqlite() {
        let b = backend().await;
        Box::pin(exercise_context_manifest(
            &b,
            "3.1.0",
            20,
            ["prod-managed", "battery"],
        ))
        .await;
    }
}

#[cfg(feature = "postgres")]
mod postgres {
    use super::*;

    async fn backend() -> Option<crate::store::postgres::PostgresBackend> {
        let dsn = crate::test_pg::empty_dsn()?;
        let b = crate::store::postgres::PostgresBackend::connect(&dsn)
            .await
            .unwrap();
        b.run_migrations().await.unwrap();
        Some(b)
    }

    #[tokio::test]
    async fn i3470_context_manifest_3_0_0_postgres() {
        let Some(b) = backend().await else { return };
        Box::pin(exercise_context_manifest(
            &b,
            "3.0.0",
            13,
            ["production", "prod-personal"],
        ))
        .await;
    }

    #[tokio::test]
    async fn i3470_component_mock_postgres() {
        let Some(b) = backend().await else { return };
        Box::pin(exercise_component_mock(&b, |k| b.set_node_key_id(k))).await;
    }

    #[tokio::test]
    async fn i3470_context_manifest_3_1_0_postgres() {
        let Some(b) = backend().await else { return };
        Box::pin(exercise_context_manifest(
            &b,
            "3.1.0",
            20,
            ["prod-managed", "battery"],
        ))
        .await;
    }
}
