//! v62.0.0 (wave P7; CC 2.6.1, 3.1.5; the rulings "a replicating trace is a
//! forward-form row", "the manifest form is the only form: the trace is a
//! BLOB named by digest", and "unsigned ⇒ local, never served") — **a trace's
//! `trace:complete:v1` row and its blob, through the edition-2 statement
//! door, on every backend** (sqlite, and postgres when a test DSN is set).
//!
//! - **I3472** a trace arriving as its row (signed by the agent's own key) and
//!   its blob is admitted by `receive_and_persist`, with the earlier-form
//!   doors open AND shut: one signature verified (`signatures_verified`
//!   counts an admitted statement), its `trace_events` land, the row is held
//!   under the id Verify computes with `attesting_key_id` = the agent, the
//!   blob is on the blob plane under the digest the row names, byte for byte,
//!   and no local trace attestation is minted beside it.
//! - **I3473** a trace with no row (the bound-hybrid form) is refused
//!   `earlier_form_object` once the doors are shut.
//! - **I3474** a row whose signing key is not a key of its `iss` is refused
//!   `kid_not_of_iss` (the key-of-issuer check, step 8).
//! - **I3475** a blob that is not the one the row names (a member altered
//!   after sealing) is refused `trace_statement_content_mismatch`, and nothing
//!   is written (no row, no blob).
//! - **I3476** a row emitted by one key about another's trace (`subject_key_ids`
//!   without the signer) is refused `federation_trace_dimension_invalid`
//!   (CC 3.4.5, self-emission).
//! - **I3477** a `statement` that is not base64, not a trace row, or comes
//!   without its `trace_blob` (or beside an inline `trace`) is refused
//!   `trace_statement_invalid`.
//! - **I3478** (pure) the worked example published in P7.md ("Server/lens-core
//!   adoption") is what persist's own encoder produces: the blob bytes and
//!   digest, the payload, the protected header and the row id, byte for byte.
//! - **I3479** (pure) the binding accepts exactly what `trace_row_payload`
//!   builds, and refuses each member changed on either side.
//! - **I3480** a trace blob that carries a signature member of its own is
//!   refused `trace_blob_carries_signature`, at the batch door and at the
//!   producer.
//! - **I3481** a reader never re-canonicalises: a blob in a non-canonical
//!   encoding (pretty-printed JSON) is admitted, and the blob plane holds its
//!   exact bytes.
//! - **I3482** unsigned ⇒ local, never served: an unsigned trace ingested
//!   `TrustPreVerified` lands, no federation-tier row of it exists, and the
//!   crossing gate (`crossing::plan_enter_mesh` asks it first) refuses a local
//!   `trace:*` row with no statement `trace_unsigned_local_only`, while a row
//!   carrying its statement, and any other row, pass. Strengthened: the
//!   trace's own attestation EXISTS, is local-tier and is absent from
//!   `list_attestations_since` (the serve feed); with the doors shut the
//!   unsigned trace is still accepted in this mode and still not served,
//!   while Full mode refuses the same shape `earlier_form_object`.
//! - **I3483** seal scrubs: `prepare_trace_row` (the body of
//!   `seal_trace_row`) runs persist's scrubber at the given level, so a
//!   pre-scrub field (an e-mail address in `task_description`) never appears
//!   in the hashed bytes, nor in the blob the node holds after admitting the
//!   row (sqlite, pg); a level the trace does not state is refused.

use super::*;
use crate::federation::edition2::door::with_earlier_form_doors_shut;
use crate::federation::edition2::fixture_switch as e2;
use crate::federation::{BlobBody, BlobStorage, FederationDirectory};
use crate::verify::PythonJsonDumpsCanonicalizer;
use chrono::{DateTime, Duration, SecondsFormat, Utc};
use ciris_verify_core::cde::{self, Value};

fn unique(tag: &str) -> String {
    format!(
        "p7-{tag}-{}",
        &uuid::Uuid::new_v4().simple().to_string()[..12]
    )
}

fn instant(at: DateTime<Utc>) -> String {
    at.to_rfc3339_opts(SecondsFormat::Millis, true)
}

/// A post-scrub 2.7.0 trace as a JSON object with no signature members, a
/// float and a null in it (they ride in the blob, never in the CBOR payload).
fn raw_trace(completed: DateTime<Utc>) -> serde_json::Value {
    let started = completed - Duration::seconds(20);
    serde_json::json!({
        "trace_id": unique("trace"),
        "thought_id": "th-p7",
        "task_id": null,
        "agent_id_hash": "deadbeef",
        "started_at": instant(started),
        "completed_at": instant(completed),
        "trace_level": "generic",
        "trace_schema_version": "2.7.0",
        "run_kind": "production",
        "components": [
            {
                "component_type": "observation",
                "event_type": "THOUGHT_START",
                "timestamp": instant(started),
                "data": { "attempt_index": 0 }
            },
            {
                "component_type": "action",
                "event_type": "ACTION_RESULT",
                "timestamp": instant(completed),
                "data": {
                    "attempt_index": 0,
                    "audit_sequence_number": 42,
                    "audit_entry_hash": "abcd",
                    "audit_signature": "BBBB",
                    "llm_calls": 0,
                    "tokens_total": 100,
                    "cost_cents": 0.1
                }
            }
        ]
    })
}

/// The producer's choice of blob bytes: JCS of the object.
fn blob_of(raw: &serde_json::Value) -> Vec<u8> {
    canonical_trace_blob(raw).expect("a trace object")
}

fn parsed(blob: &[u8]) -> CompleteTrace {
    serde_json::from_slice(blob).expect("the fixture is a CompleteTrace")
}

/// `seed`'s key signs the row of `blob` as `iss`, with the payload edited by
/// `edit` first.
fn statement_with(
    blob: &[u8],
    seed: &str,
    iss: &str,
    edit: impl FnOnce(&mut Vec<(Value, Value)>),
) -> Vec<u8> {
    let Value::Map(mut members) =
        trace_row_payload(&parsed(blob), blob, iss).expect("trace row payload")
    else {
        panic!("trace_row_payload builds a map")
    };
    edit(&mut members);
    ciris_verify_core::edition2::sign_row_statement(
        &e2::signing_key(seed),
        iss,
        iss,
        TRACE_ROW_TYPE,
        TRACE_FAMILY_ID,
        &Value::Map(members),
        vec![],
    )
    .expect("sign the trace row")
}

fn statement(blob: &[u8], seed: &str) -> Vec<u8> {
    statement_with(blob, seed, &e2::kid(seed), |_| {})
}

/// The row id Verify computes for `blob`'s row signed as `iss`.
fn row_id_hex(blob: &[u8], iss: &str) -> String {
    let payload = trace_row_payload(&parsed(blob), blob, iss).unwrap();
    hex::encode(ciris_verify_core::edition2::row_id(
        TRACE_ROW_TYPE,
        TRACE_FAMILY_ID,
        iss,
        Some(iss),
        &cde::encode(&payload),
    ))
}

fn digest_of(blob: &[u8]) -> [u8; 32] {
    Sha256::digest(blob).into()
}

fn wrap(event: serde_json::Value) -> Vec<u8> {
    wrap_at(event, "generic")
}

fn wrap_at(event: serde_json::Value, level: &str) -> Vec<u8> {
    serde_json::json!({
        "events": [event],
        "batch_timestamp": crate::host::clock::now().to_rfc3339(),
        "consent_timestamp": "2025-01-01T00:00:00Z",
        "trace_level": level,
        "trace_schema_version": "2.7.0",
    })
    .to_string()
    .into_bytes()
}

/// Every attestation id the node serves to a peer (the federation-tier feed,
/// `list_attestations_since`, the E5 serve rule).
async fn served_ids<D>(d: &D) -> Vec<String>
where
    D: FederationDirectory,
{
    let mut out = Vec::new();
    let mut since = None;
    loop {
        let page = d.list_attestations_since(since.clone(), 100).await.unwrap();
        if page.is_empty() {
            return out;
        }
        since = page
            .last()
            .map(|s| (s.admitted_at, s.attestation.attestation_id.clone()));
        out.extend(page.into_iter().map(|s| s.attestation.attestation_id));
    }
}

/// The v62 batch event: the statement and the blob's exact bytes, no `trace`.
fn row_batch(blob: &[u8], statement: &[u8]) -> Vec<u8> {
    wrap(serde_json::json!({
        "event_type": "complete_trace",
        "trace_level": "generic",
        "statement": BASE64.encode(statement),
        "trace_blob": BASE64.encode(blob),
    }))
}

/// An earlier-form / local event: the trace inline, no statement.
fn inline_batch(raw: &serde_json::Value) -> Vec<u8> {
    wrap(serde_json::json!({
        "event_type": "complete_trace",
        "trace_level": "generic",
        "trace": raw,
    }))
}

async fn ingest_with<D>(d: &D, body: &[u8], mode: VerifyMode) -> Result<BatchSummary, IngestError>
where
    D: Backend + FederationDirectory + ?Sized,
{
    let signer_key_id = "p7-scrub-key-v1".to_owned();
    let mut sw = ciris_keyring::Ed25519SoftwareSigner::new(&signer_key_id);
    sw.import_key(&[0xA7u8; 32]).expect("import_key");
    let signer: Box<dyn HardwareSigner> = Box::new(sw);
    let pipeline = IngestPipeline {
        backend: d,
        canonicalizer: &PythonJsonDumpsCanonicalizer,
        scrubber: &crate::scrub::NullScrubber,
        signer: &*signer,
        signer_key_id: &signer_key_id,
    };
    pipeline.receive_and_persist_with(body, mode).await
}

async fn ingest<D>(d: &D, body: &[u8]) -> Result<BatchSummary, IngestError>
where
    D: Backend + FederationDirectory + ?Sized,
{
    ingest_with(d, body, VerifyMode::Full).await
}

fn kind_of(r: &Result<BatchSummary, IngestError>) -> &'static str {
    match r {
        Ok(_) => "admitted",
        Err(e) => e.kind(),
    }
}

/// Now, less an hour: inside a default `agent` key window (E0 v1.11).
fn recently() -> DateTime<Utc> {
    crate::host::clock::now() - Duration::hours(1)
}

async fn held_blob<D>(d: &D, blob: &[u8]) -> Option<Vec<u8>>
where
    D: BlobStorage,
{
    match d.get_blob(&digest_of(blob)).await.expect("get_blob") {
        Some(BlobBody::Inline(bytes)) => Some(bytes),
        Some(_) => panic!("a trace blob is stored inline"),
        None => None,
    }
}

/// I3472 + I3473 + I3481 on one backend.
async fn exercise_admit_and_earlier_form<D>(d: &D)
where
    D: Backend + FederationDirectory + BlobStorage,
{
    let a = unique("agent");
    let kid_a = e2::put_key(d, &a, &["agent"]).await;

    let blob = blob_of(&raw_trace(recently()));
    let st = statement(&blob, &a);
    let got = ingest(d, &row_batch(&blob, &st)).await;
    let summary = got.unwrap_or_else(|e| panic!("I3472: admitted, got {} ({e})", e.kind()));
    assert_eq!(
        summary.signatures_verified, 1,
        "I3472: an admitted statement counts"
    );
    assert!(summary.trace_events_inserted > 0, "I3472: its rows land");
    assert_eq!(
        summary.trace_attestations_minted, 0,
        "I3472: the row is the trace's home; nothing minted beside it"
    );
    let held = d
        .get_attestation(&row_id_hex(&blob, &kid_a))
        .await
        .unwrap()
        .expect("I3472: the row is held under Verify's row id");
    assert_eq!(held.attesting_key_id, kid_a, "I3472: signed by the agent");
    assert_eq!(held.attestation_type, TRACE_ROW_TYPE);
    assert_eq!(
        held_blob(d, &blob).await.as_deref(),
        Some(blob.as_slice()),
        "I3472: the blob is held under the digest the row names, byte for byte"
    );

    let blob2 = blob_of(&raw_trace(recently()));
    let st2 = statement(&blob2, &a);
    let shut = with_earlier_form_doors_shut(ingest(d, &row_batch(&blob2, &st2))).await;
    assert_eq!(
        kind_of(&shut),
        "admitted",
        "I3472: the switch shuts the earlier form only"
    );

    // I3481 — a non-canonical blob: the exact bytes are what is hashed and held.
    let pretty = serde_json::to_vec_pretty(&raw_trace(recently())).unwrap();
    assert_ne!(pretty, blob_of(&serde_json::from_slice(&pretty).unwrap()));
    let st3 = statement(&pretty, &a);
    assert_eq!(
        kind_of(&ingest(d, &row_batch(&pretty, &st3)).await),
        "admitted",
        "I3481: a pretty-printed blob is admitted as sent"
    );
    assert_eq!(
        held_blob(d, &pretty).await.as_deref(),
        Some(pretty.as_slice()),
        "I3481: the blob plane holds the bytes received, not a re-canonicalisation"
    );

    // I3473 — no row: the bound-hybrid form.
    let mut hybrid = raw_trace(recently());
    hybrid["signature"] = serde_json::json!(BASE64.encode([1u8; 64]));
    hybrid["signature_key_id"] = serde_json::json!("ciris-agent-key:p7-hybrid");
    hybrid["signature_ml_dsa_65"] = serde_json::json!(BASE64.encode([2u8; 3309]));
    hybrid["pqc_key_id"] = serde_json::json!("p7-mldsa");
    let refused = with_earlier_form_doors_shut(ingest(d, &inline_batch(&hybrid))).await;
    assert_eq!(
        kind_of(&refused),
        crate::federation::edition2::token::EARLIER_FORM_OBJECT,
        "I3473: refused by name"
    );
}

/// I3474 + I3475 + I3476 + I3477 + I3480 on one backend.
async fn exercise_refusals<D>(d: &D)
where
    D: Backend + FederationDirectory + BlobStorage,
{
    let a = unique("agent-a");
    let b = unique("agent-b");
    let kid_a = e2::put_key(d, &a, &["agent"]).await;
    let kid_b = e2::put_key(d, &b, &["agent"]).await;

    // I3474 — B's key signs a row whose iss is A.
    let blob = blob_of(&raw_trace(recently()));
    let forged = statement_with(&blob, &b, &kid_a, |_| {});
    assert_eq!(
        kind_of(&ingest(d, &row_batch(&blob, &forged)).await),
        crate::federation::malformed_row::KID_NOT_OF_ISS,
        "I3474: a key not of its iss"
    );

    // I3475 — the blob altered after sealing.
    let raw = raw_trace(recently());
    let blob = blob_of(&raw);
    let st = statement(&blob, &a);
    let mut altered = raw.clone();
    altered["thought_id"] = serde_json::json!("th-p7-altered");
    let altered = blob_of(&altered);
    assert_eq!(
        kind_of(&ingest(d, &row_batch(&altered, &st)).await),
        TRACE_STATEMENT_CONTENT_MISMATCH,
        "I3475: the row does not name this blob"
    );
    assert!(
        d.get_attestation(&row_id_hex(&blob, &kid_a))
            .await
            .unwrap()
            .is_none(),
        "I3475: no row written"
    );
    assert!(
        held_blob(d, &altered).await.is_none(),
        "I3475: no blob written"
    );

    // I3476 — B emits a trace row naming A as its subject.
    let blob = blob_of(&raw_trace(recently()));
    let third_party = statement_with(&blob, &b, &kid_b, |m| {
        for (k, v) in m.iter_mut() {
            if k.as_text() == Some("subject_key_ids") {
                *v = Value::Array(vec![Value::Text(kid_a.clone())]);
            }
        }
    });
    assert_eq!(
        kind_of(&ingest(d, &row_batch(&blob, &third_party)).await),
        "federation_trace_dimension_invalid",
        "I3476: a trace is self-emitted"
    );

    // I3477 — not base64; not a trace row; no blob; blob beside an inline trace.
    let raw = raw_trace(recently());
    let blob = blob_of(&raw);
    let st = statement(&blob, &a);
    let event = |members: serde_json::Value| {
        let mut e = serde_json::json!({ "event_type": "complete_trace", "trace_level": "generic" });
        for (k, v) in members.as_object().unwrap() {
            e[k.as_str()] = v.clone();
        }
        wrap(e)
    };
    for (what, body) in [
        (
            "statement not base64",
            event(serde_json::json!({
                "statement": "!!not base64!!",
                "trace_blob": BASE64.encode(&blob),
            })),
        ),
        (
            "a statement with no trace_blob",
            event(serde_json::json!({ "statement": BASE64.encode(&st), "trace": raw })),
        ),
        (
            "a trace_blob beside an inline trace",
            event(serde_json::json!({
                "statement": BASE64.encode(&st),
                "trace_blob": BASE64.encode(&blob),
                "trace": raw,
            })),
        ),
    ] {
        assert_eq!(
            kind_of(&ingest(d, &body).await),
            TRACE_STATEMENT_INVALID,
            "I3477: {what}"
        );
    }
    let not_trace = ciris_verify_core::edition2::sign_row_statement(
        &e2::signing_key(&a),
        &kid_a,
        &kid_a,
        "scores",
        "evidence:.suite:.kind:.cell:.prefix",
        &Value::Map(vec![(
            Value::Text("asserted_at".into()),
            Value::Uint(u64::try_from(recently().timestamp_millis()).unwrap()),
        )]),
        vec![],
    )
    .unwrap();
    assert_eq!(
        kind_of(&ingest(d, &row_batch(&blob, &not_trace)).await),
        TRACE_STATEMENT_INVALID,
        "I3477: not a trace row"
    );

    // I3480 — a blob carrying a signature member of its own.
    let mut signed = raw_trace(recently());
    signed["signature_key_id"] = serde_json::json!(kid_a.clone());
    let signed_blob = serde_json::to_vec(&signed).unwrap();
    let st = statement_with(&blob, &a, &kid_a, |_| {});
    assert_eq!(
        kind_of(&ingest(d, &row_batch(&signed_blob, &st)).await),
        TRACE_BLOB_CARRIES_SIGNATURE,
        "I3480: refused at the batch door"
    );
}

/// I3482 on one backend: an unsigned trace stays local. Accepted under
/// `TrustPreVerified` with the earlier-form doors open AND shut (the
/// earlier-form refusal is the verifying path's only), its own attestation is
/// local-tier, nothing of it is served to a peer, and it never crosses.
async fn exercise_unsigned_stays_local<D>(d: &D)
where
    D: Backend + FederationDirectory + BlobStorage,
{
    let a = unique("agent-local");
    let kid_a = e2::put_key(d, &a, &["agent"]).await;
    let mut raw = raw_trace(recently());
    raw["signature_key_id"] = serde_json::json!(kid_a.clone());
    let trace_id = raw["trace_id"].as_str().unwrap().to_owned();
    let got = ingest_with(d, &inline_batch(&raw), VerifyMode::TrustPreVerified).await;
    let summary = got.unwrap_or_else(|e| panic!("I3482: an unsigned local trace lands: {e}"));
    assert!(summary.trace_events_inserted > 0, "I3482: its rows land");
    assert_eq!(
        summary.signatures_verified, 0,
        "I3482: nothing was verified"
    );
    let local = d
        .get_attestation(&trace_attestation_id(&trace_id))
        .await
        .unwrap()
        .expect("I3482: the trace's own (local) attestation");
    assert_eq!(
        local.tier,
        crate::federation::types::attestation_tier::LOCAL,
        "I3482: an unsigned trace is local-tier"
    );
    assert!(
        !served_ids(d).await.contains(&local.attestation_id),
        "I3482: an unsigned trace is not served to a peer"
    );
    let e = refuse_unsigned_trace_crossing(&local).unwrap_err();
    assert!(
        matches!(
            e,
            crate::federation::Error::MalformedRow {
                reason: TRACE_UNSIGNED_LOCAL_ONLY,
                ..
            }
        ),
        "I3482: it never crosses: {e:?}"
    );

    // The doors shut: still accepted in this mode, still not served.
    let mut raw2 = raw_trace(recently());
    raw2["signature_key_id"] = serde_json::json!(kid_a.clone());
    let trace_id2 = raw2["trace_id"].as_str().unwrap().to_owned();
    let shut = with_earlier_form_doors_shut(ingest_with(
        d,
        &inline_batch(&raw2),
        VerifyMode::TrustPreVerified,
    ))
    .await;
    assert_eq!(
        kind_of(&shut),
        "admitted",
        "I3482: the earlier-form refusal does not reach TrustPreVerified"
    );
    let served = served_ids(d).await;
    assert!(
        !served.contains(&trace_attestation_id(&trace_id2)),
        "I3482: not served with the doors shut either"
    );
    // The verifying path, by contrast, refuses the same shape by name.
    let mut raw3 = raw_trace(recently());
    raw3["signature_key_id"] = serde_json::json!(kid_a);
    let verifying = with_earlier_form_doors_shut(ingest(d, &inline_batch(&raw3))).await;
    assert_eq!(
        kind_of(&verifying),
        crate::federation::edition2::token::EARLIER_FORM_OBJECT,
        "I3482: Full mode refuses it once the doors are shut"
    );
}

/// I3483 on one backend: seal scrubs. A pre-scrub field given to the
/// producer never appears in the bytes it hashes, signs and returns, nor in
/// the blob the node then holds.
#[cfg(feature = "scrub")]
async fn exercise_seal_scrubs<D>(d: &D)
where
    D: Backend + FederationDirectory + BlobStorage,
{
    const SECRET: &str = "alice.p7@example.com";
    let a = unique("agent-seal");
    let kid_a = e2::put_key(d, &a, &["agent"]).await;
    let mut raw = raw_trace(recently());
    raw["trace_level"] = serde_json::json!("detailed");
    raw["components"][0]["data"]["task_description"] =
        serde_json::json!(format!("write to {SECRET} today"));
    raw["signature"] = serde_json::json!("AAAA");
    let (blob, payload) =
        prepare_trace_row(&raw, TraceLevel::Detailed, &kid_a).expect("I3483: sealable");
    let text = String::from_utf8(blob.clone()).unwrap();
    assert!(
        !text.contains(SECRET),
        "I3483: the pre-scrub field is not in the hashed bytes"
    );
    assert!(text.contains("[EMAIL]"), "I3483: the scrubber ran: {text}");
    assert!(
        !text.contains("\"signature\""),
        "I3483: no signature member"
    );
    let st = ciris_verify_core::edition2::sign_row_statement(
        &e2::signing_key(&a),
        &kid_a,
        &kid_a,
        TRACE_ROW_TYPE,
        TRACE_FAMILY_ID,
        &payload,
        vec![],
    )
    .unwrap();
    let body = wrap_at(
        serde_json::json!({
            "event_type": "complete_trace",
            "trace_level": "detailed",
            "statement": BASE64.encode(&st),
            "trace_blob": BASE64.encode(&blob),
        }),
        "detailed",
    );
    let got = ingest(d, &body).await;
    assert_eq!(
        kind_of(&got),
        "admitted",
        "I3483: the sealed row is admitted: {got:?}"
    );
    let held = held_blob(d, &blob).await.expect("I3483: the blob is held");
    assert!(
        !String::from_utf8(held).unwrap().contains(SECRET),
        "I3483: the held blob carries no pre-scrub content"
    );
}

/// I3483 (pure) — a trace cannot be sealed under a lighter scrub than its
/// own label.
#[cfg(feature = "scrub")]
#[test]
fn i3483_seal_refuses_a_level_the_trace_does_not_state() {
    let mut raw = raw_trace(Utc::now());
    raw["trace_level"] = serde_json::json!("detailed");
    match scrubbed_trace_blob(&raw, TraceLevel::Generic) {
        Err(IngestError::TraceRefused { kind, .. }) => {
            assert_eq!(kind, TRACE_STATEMENT_INVALID, "I3483");
        }
        other => panic!("I3483: expected the refusal, got {other:?}"),
    }
}

/// I3482 (pure) — the crossing gate itself.
#[test]
fn i3482_the_crossing_gate() {
    let row = |envelope: serde_json::Value| -> crate::federation::types::Attestation {
        serde_json::from_value(serde_json::json!({
            "attestation_id": "p7-local",
            "attesting_key_id": "k",
            "attested_key_id": "k",
            "attestation_type": "scores",
            "asserted_at": "2026-11-18T12:00:00Z",
            "attestation_envelope": envelope,
            "original_content_hash": "",
            "scrub_signature_classical": "",
            "scrub_key_id": "k",
            "scrub_timestamp": "2026-11-18T12:00:00Z",
            "persist_row_hash": "",
            "tier": "local",
        }))
        .expect("an attestation")
    };
    let unsigned = row(serde_json::json!({
        "dimension": "trace:complete:v1",
        "trace_id": "t",
        "agent_id_hash": "h",
        "trace": {},
    }));
    match refuse_unsigned_trace_crossing(&unsigned) {
        Err(crate::federation::Error::MalformedRow { reason, .. }) => {
            assert_eq!(reason, TRACE_UNSIGNED_LOCAL_ONLY, "I3482");
        }
        other => panic!("I3482: an unsigned local trace never crosses, got {other:?}"),
    }
    let summary = row(serde_json::json!({ "dimension": "trace_summary:digest:v1" }));
    assert!(
        refuse_unsigned_trace_crossing(&summary).is_err(),
        "I3482: trace_summary too"
    );
    let mut envelope = serde_json::json!({ "dimension": "trace:complete:v1" });
    envelope[crate::federation::edition2::ingest::STATEMENT_MEMBER] = serde_json::json!("d2");
    let with_statement = row(envelope);
    assert!(
        refuse_unsigned_trace_crossing(&with_statement).is_ok(),
        "I3482: a row carrying its statement is not this gate's"
    );
    let other = row(serde_json::json!({ "dimension": "evidence:safety_battery:capture:a:b:v1" }));
    assert!(
        refuse_unsigned_trace_crossing(&other).is_ok(),
        "I3482: other rows pass"
    );
}

/// I3478 — the P7.md worked example, byte for byte.
#[test]
fn i3478_the_published_example_is_persists_encoding() {
    const PROTECTED: &str = "a7013a000111d303781e6170706c69636174696f6e2f766e642e63697269732e726f772b63626f7204582011111111111111111111111111111111111111111111111111111111111111110fa401784d75726e3a696574663a706172616d733a6f617574683a636b743a7368612d3235363a4552455245524552455245524552455245524552455245524552455245524552455245524552455245524502784d75726e3a696574663a706172616d733a6f617574683a636b743a7368612d3235363a45524552455245524552455245524552455245524552455245524552455245524552455245524552455245061a6afd93543a000111720210696365672d726f772f323a000111706673636f7265733a000111717474726163653a2e666f726d3a2e76657273696f6e";
    const PAYLOAD: &str = "a866617574686f72784d75726e3a696574663a706172616d733a6f617574683a636b743a7368612d3235363a45524552455245524552455245524552455245524552455245524552455245524552455245524552455245686d616e6966657374a566736368656d617174726163655f6d616e69666573743a763168627974655f6c656e18f56872756e5f6b696e646a70726f64756374696f6e6c636f6e74656e745f6861736878477368613235363a333061316235393062333437386236336263333133643731633334316137313863306632313537366136633665633238343431636366333362623132333035336f636f6d706f6e656e745f636f756e74006874726163655f69646a74726163652d65782d316964696d656e73696f6e7174726163653a636f6d706c6574653a76316b61737365727465645f61741b000001a1ee87809b6d6167656e745f69645f686173686864656164626565666d65766964656e63655f7265667381822f582030a1b590b3478b63bc313d71c341a718c0f21576a6c6ec28441ccf33bb1230536f7375626a6563745f6b65795f69647381784d75726e3a696574663a706172616d733a6f617574683a636b743a7368612d3235363a45524552455245524552455245524552455245524552455245524552455245524552455245524552455245";
    let raw = serde_json::json!({
        "trace_id": "trace-ex-1",
        "thought_id": "th-1",
        "agent_id_hash": "deadbeef",
        "started_at": "2026-11-18T12:00:00Z",
        "completed_at": "2026-11-18T12:00:20.123Z",
        "trace_level": "generic",
        "trace_schema_version": "2.7.0",
        "components": [],
        "run_kind": "production",
    });
    let blob = canonical_trace_blob(&raw).unwrap();
    assert_eq!(
        String::from_utf8(blob.clone()).unwrap(),
        "{\"agent_id_hash\":\"deadbeef\",\"completed_at\":\"2026-11-18T12:00:20.123Z\",\
         \"components\":[],\"run_kind\":\"production\",\"started_at\":\"2026-11-18T12:00:00Z\",\
         \"thought_id\":\"th-1\",\"trace_id\":\"trace-ex-1\",\"trace_level\":\"generic\",\
         \"trace_schema_version\":\"2.7.0\"}"
    );
    assert_eq!(
        hex::encode(digest_of(&blob)),
        "30a1b590b3478b63bc313d71c341a718c0f21576a6c6ec28441ccf33bb123053"
    );
    let kid = [0x11u8; 32];
    let iss = ciris_verify_core::edition2::identity_ref(&kid);
    assert_eq!(
        iss,
        "urn:ietf:params:oauth:ckt:sha-256:ERERERERERERERERERERERERERERERERERERERERERE"
    );
    let payload = trace_row_payload(&parsed(&blob), &blob, &iss).unwrap();
    let payload_bytes = cde::encode(&payload);
    assert_eq!(hex::encode(&payload_bytes), PAYLOAD, "I3478: the payload");
    // persist's producer (scrub, then seal) gives the same bytes for this
    // generic trace: generic carries no text, so the scrub is the identity.
    #[cfg(feature = "scrub")]
    {
        let (sealed_blob, sealed_payload) =
            prepare_trace_row(&raw, TraceLevel::Generic, &iss).unwrap();
        assert_eq!(sealed_blob, blob, "I3478: the producer seals the same blob");
        assert_eq!(
            cde::encode(&sealed_payload),
            payload_bytes,
            "I3478: and the same payload"
        );
    }
    let protected = crate::federation::edition2::produce::row_protected(
        &kid,
        &iss,
        &iss,
        TRACE_ROW_TYPE,
        TRACE_FAMILY_ID,
        &payload,
    )
    .unwrap();
    assert_eq!(
        hex::encode(&protected),
        PROTECTED,
        "I3478: the protected header"
    );
    assert_eq!(
        hex::encode(ciris_verify_core::edition2::row_id(
            TRACE_ROW_TYPE,
            TRACE_FAMILY_ID,
            &iss,
            Some(iss.as_str()),
            &payload_bytes,
        )),
        "97fa6da7405878429528171c3d1f1f08fcf39e9d49ae3c1fc15f517881000e33",
        "I3478: the row id"
    );
}

/// I3479 — the binding is exact: what the builder builds passes, and each
/// member changed on either side is refused by name. I3480 at the producer.
#[test]
fn i3479_the_binding_is_exact() {
    let seed = "p7-binding";
    let iss = e2::kid(seed);
    let raw = raw_trace(Utc::now());
    let blob = blob_of(&raw);
    let trace = parsed(&blob);
    let st = statement(&blob, seed);
    assert_eq!(
        check_trace_statement_binding(&st, &trace, &blob).unwrap(),
        iss,
        "I3479: the builder's row binds its blob; the binding returns the iss"
    );
    let refused = |r: Result<String, IngestError>| match r {
        Err(IngestError::TraceRefused { kind, .. }) => kind,
        other => panic!("expected a trace refusal, got {other:?}"),
    };
    // The trace side: each change breaks the binding.
    let changes: [(&str, serde_json::Value); 4] = [
        ("trace_id", serde_json::json!("other")),
        ("run_kind", serde_json::json!("qa")),
        (
            "completed_at",
            serde_json::json!(instant(Utc::now() + Duration::seconds(5))),
        ),
        ("cohort_scope", serde_json::json!("self")),
    ];
    for (member, value) in changes {
        let mut r = raw.clone();
        r[member] = value;
        let b = blob_of(&r);
        assert_eq!(
            refused(check_trace_statement_binding(&st, &parsed(&b), &b)),
            TRACE_STATEMENT_CONTENT_MISMATCH,
            "I3479: {member} changed"
        );
    }
    // One byte of whitespace: the same trace, other bytes.
    let mut spaced = blob.clone();
    spaced.push(b' ');
    assert_eq!(
        refused(check_trace_statement_binding(&st, &trace, &spaced)),
        TRACE_STATEMENT_CONTENT_MISMATCH,
        "I3479: the digest is over the bytes, not the parse"
    );
    // The row side: a payload member changed.
    let wrong_evidence = statement_with(&blob, seed, &iss, |m| {
        for (k, v) in m.iter_mut() {
            if k.as_text() == Some("evidence_refs") {
                *v = Value::Array(vec![ciris_verify_core::edition2::hash_digest_value(
                    &[0u8; 32],
                )]);
            }
        }
    });
    assert_eq!(
        refused(check_trace_statement_binding(
            &wrong_evidence,
            &trace,
            &blob
        )),
        TRACE_STATEMENT_CONTENT_MISMATCH,
        "I3479: evidence_refs does not name the blob"
    );
    // I3480 — the blob parser refuses a signature member.
    let mut signed = raw.clone();
    signed["signature"] = serde_json::json!("AAAA");
    match parse_trace_blob(&serde_json::to_vec(&signed).unwrap()) {
        Err(IngestError::TraceRefused { kind, .. }) => {
            assert_eq!(kind, TRACE_BLOB_CARRIES_SIGNATURE, "I3480");
        }
        other => panic!("I3480: expected the refusal, got {other:?}"),
    }
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
    async fn i3472_trace_row_admitted_sqlite() {
        let b = backend().await;
        Box::pin(exercise_admit_and_earlier_form(&b)).await;
    }

    #[tokio::test]
    async fn i3474_trace_row_refusals_sqlite() {
        let b = backend().await;
        Box::pin(exercise_refusals(&b)).await;
    }

    #[tokio::test]
    async fn i3482_unsigned_trace_stays_local_sqlite() {
        let b = backend().await;
        Box::pin(exercise_unsigned_stays_local(&b)).await;
    }

    #[cfg(feature = "scrub")]
    #[tokio::test]
    async fn i3483_seal_scrubs_sqlite() {
        let b = backend().await;
        Box::pin(exercise_seal_scrubs(&b)).await;
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
    async fn i3472_trace_row_admitted_postgres() {
        let Some(b) = backend().await else { return };
        Box::pin(exercise_admit_and_earlier_form(&b)).await;
    }

    #[tokio::test]
    async fn i3474_trace_row_refusals_postgres() {
        let Some(b) = backend().await else { return };
        Box::pin(exercise_refusals(&b)).await;
    }

    #[tokio::test]
    async fn i3482_unsigned_trace_stays_local_postgres() {
        let Some(b) = backend().await else { return };
        Box::pin(exercise_unsigned_stays_local(&b)).await;
    }

    #[cfg(feature = "scrub")]
    #[tokio::test]
    async fn i3483_seal_scrubs_postgres() {
        let Some(b) = backend().await else { return };
        Box::pin(exercise_seal_scrubs(&b)).await;
    }
}
