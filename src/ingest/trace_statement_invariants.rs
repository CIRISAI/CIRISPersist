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
//! - **I3486** two nodes: a row ingested on A, replicated to B by
//!   `apply_replicated_statement`, its blob delivered by `put_blob`:
//!   B projects the same `trace_events` row-first (on the blob's arrival) and
//!   blob-first (in the row's own write).
//! - **I3487** the sign call, end to end: `Engine::seal_trace` signs with the
//!   Engine's composite LocalSigner and the same Engine ingests the row
//!   (sqlite, pg). P7-fix6: the signer is SELECTED BY REGISTERED KIND, the
//!   agent's key: an Engine whose own key is a `node` key and which carries
//!   an `agent` key (`with_trace_signer`) seals a trace signed by the AGENT
//!   key, which lands; the same Engine without it, or naming its node key
//!   (`seal_trace_as`), is refused `trace_agent_signer_not_held` (sqlite,
//!   pg).
//! - **I3488** a sealed `self` trace (option A), two engines: B holds the
//!   envelope and the row but no DEK, so the row is HELD `trace_dek_not_held`
//!   (G0's fold) and projects nothing; A's key grant reaches B and the row
//!   concludes BY ITSELF, with A's `trace_events` (sqlite, pg).
//! - **I3489** (P7-fix6; CC ruling (a): CC 3.1.5, `signer_kind.tsv`
//!   `trace:{form}:{version}` = agent, key_roles R4) the trace door's signer
//!   kind: (pure) [`trace_signer_is_agent`] over a table of identity sets;
//!   (sqlite, pg) an agent-signed trace row lands, while a `node`-signed and a
//!   `user`-signed one are each refused `trace_signer_not_agent` with nothing
//!   written (no row, no blob: the pre-check runs before the blob plane).
//! - **I3483** seal scrubs: `prepare_trace_row` (the body of
//!   `seal_trace_row`) runs persist's scrubber at the given level, so a
//!   pre-scrub field (an e-mail address in `task_description`) never appears
//!   in the hashed bytes, nor in the blob the node holds after admitting the
//!   row (sqlite, pg); a level the trace does not state is refused.

use super::*;
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
    let trace_id_1 = parsed(&blob).trace_id;
    assert!(
        events_of(d, &trace_id_1).await > 0,
        "I3472: its rows land, projected in the row's own write"
    );
    assert_eq!(
        summary.trace_events_inserted, 0,
        "I3472: not projected a second time from the batch"
    );
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
    let shut = ingest(d, &row_batch(&blob2, &st2)).await;
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
    let refused = ingest(d, &inline_batch(&hybrid)).await;
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
    let shut = ingest_with(d, &inline_batch(&raw2), VerifyMode::TrustPreVerified).await;
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
    let verifying = ingest(d, &inline_batch(&raw3)).await;
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

/// The `trace_events` rows this node holds for `trace_id`.
async fn events_of<D>(d: &D, trace_id: &str) -> usize
where
    D: Backend,
{
    d.fetch_trace_events_page(-1, i64::MAX, None)
        .await
        .expect("fetch_trace_events_page")
        .into_iter()
        .filter(|(_, r)| r.trace_id == trace_id)
        .count()
}

/// Deliver `blob` to `d` on the blob plane as a peer's replication does:
/// T2's `put_blob` under a holder's `custody:ack:v1` claim.
async fn deliver_blob<D>(d: &D, holder: &str, blob: &[u8])
where
    D: BlobStorage,
{
    let sha = digest_of(blob);
    let claim = crate::federation::edition2::typed_fixtures::custody_statement(
        holder,
        &sha,
        Some(u64::try_from(blob.len()).unwrap()),
        "federation",
        None,
        u64::try_from(recently().timestamp_millis()).unwrap(),
    );
    d.put_blob(
        &sha,
        BlobBody::Inline(blob.to_vec()),
        Some(TRACE_BLOB_MEDIA_TYPE),
        &claim,
    )
    .await
    .expect("the blob lands");
}

/// I3486 — **two nodes**: a trace row ingested on A reaches B by
/// replication (`apply_replicated_statement`) and its blob by the blob
/// plane (`put_blob`); B projects the trace's `trace_events` in
/// EITHER order: row first (on the blob's arrival) and blob first (in the
/// row's own write).
async fn exercise_replicated_projection<D>(a_node: &D, b_node: &D)
where
    D: Backend + FederationDirectory + BlobStorage,
{
    let agent = unique("agent-repl");
    let holder = unique("holder");
    let kid = e2::put_key(a_node, &agent, &["agent"]).await;
    e2::put_key(b_node, &agent, &["agent"]).await;
    e2::put_key(b_node, &holder, &["user"]).await;

    for blob_first in [false, true] {
        let raw = raw_trace(recently());
        let trace_id = raw["trace_id"].as_str().unwrap().to_owned();
        let blob = blob_of(&raw);
        let st = statement(&blob, &agent);
        let got = ingest(a_node, &row_batch(&blob, &st)).await;
        assert_eq!(kind_of(&got), "admitted", "I3486: A ingests: {got:?}");
        assert!(events_of(a_node, &trace_id).await > 0, "I3486: A projects");
        assert_eq!(
            events_of(b_node, &trace_id).await,
            0,
            "I3486: B holds nothing yet"
        );

        let row_id: [u8; 32] = hex::decode(row_id_hex(&blob, &kid))
            .unwrap()
            .try_into()
            .unwrap();
        if blob_first {
            deliver_blob(b_node, &holder, &blob).await;
            assert_eq!(
                events_of(b_node, &trace_id).await,
                0,
                "I3486: a blob alone projects nothing (no row names it yet)"
            );
        }
        let applied = Box::pin(
            crate::federation::edition2::ingest::apply_replicated_statement(b_node, &st, &row_id),
        )
        .await
        .unwrap_or_else(|e| panic!("I3486: B admits the replicated row: {e}"));
        assert!(applied.advances_cursor());
        if blob_first {
            assert!(
                events_of(b_node, &trace_id).await > 0,
                "I3486 (blob first): the row's own write projects from the held blob"
            );
        } else {
            assert_eq!(
                events_of(b_node, &trace_id).await,
                0,
                "I3486 (row first): no blob yet, nothing projected"
            );
            deliver_blob(b_node, &holder, &blob).await;
            assert!(
                events_of(b_node, &trace_id).await > 0,
                "I3486 (row first): the blob's arrival projects the held row"
            );
        }
        assert_eq!(
            events_of(b_node, &trace_id).await,
            events_of(a_node, &trace_id).await,
            "I3486: B holds the same trace_events A projected"
        );
    }
}

/// The row id of a trace row statement signed as `iss` (its raw payload).
/// Only the `scrub`-gated engine witnesses read it.
#[cfg(feature = "scrub")]
fn row_id_of_statement(statement: &[u8], iss: &str) -> [u8; 32] {
    let payload = crate::federation::edition2::door::raw_payload(statement).expect("a payload");
    ciris_verify_core::edition2::row_id(TRACE_ROW_TYPE, TRACE_FAMILY_ID, iss, Some(iss), &payload)
}

/// The Engine-level witnesses: `Engine::seal_trace` (the producer, the sign
/// call included) and the sealed `self` path (option A), on two engines.
#[cfg(feature = "scrub")]
pub(crate) mod engine_level {
    use super::*;
    use crate::federation::key_grant_invariants::two_node::{introduce_as, Node};
    use crate::federation::self_collective_invariants::bodies::bind;
    use crate::federation::tier_ingest::test_support as ts;
    use crate::federation::{AdoptDisposition, BlobProvenance, EncryptionPubkeys};
    use crate::Engine;
    use std::sync::Arc;

    pub(crate) type Pick<B> = fn(&Engine) -> Arc<B>;

    /// P7-fix6 — registered as an `agent`: `seal_trace` signs the trace row
    /// with the Engine's agent-kind key, and a trace is authored by its agent
    /// (CC 3.1.5, key_roles R4).
    async fn node_engine(alias: &str, dsn: &str) -> Engine {
        let e = Engine::with_signer_pre_genesis(ts::local_signer(alias), dsn)
            .await
            .unwrap();
        e.register_self_federation_key(crate::federation::types::identity_type::AGENT, None, None)
            .await
            .unwrap();
        e
    }

    /// **I3487 — the sign call, end to end.** `Engine::seal_trace` scrubs,
    /// builds and SIGNS the row with the Engine's composite LocalSigner
    /// (`produce::sign_row`); the same Engine's `receive_and_persist` admits
    /// it through the statement door and projects its `trace_events`.
    pub(crate) async fn i3487_seal_then_ingest<B>(dsn: &str, run: &str, pick: Pick<B>)
    where
        B: Backend + FederationDirectory + BlobStorage + Sync,
    {
        let alias = format!("p7-seal-{run}");
        let engine = node_engine(&alias, dsn).await;
        let iss = engine.local_derived_key_id().await.unwrap();
        let raw = raw_trace(recently());
        let trace_id = raw["trace_id"].as_str().unwrap().to_owned();
        let sealed = engine
            .seal_trace(&raw, TraceLevel::Generic)
            .await
            .unwrap_or_else(|e| panic!("I3487: seal_trace signs: {} ({e})", e.kind()));
        let (signed_as, _) = check_trace_row_shape(&sealed.statement, &sealed.trace_blob)
            .expect("I3487: the sealed row names its blob");
        assert_eq!(signed_as, iss, "I3487: signed by the Engine's own key");
        assert!(
            !is_sealed_trace_blob(&sealed.trace_blob),
            "I3487: a commons trace is plaintext"
        );
        let got = engine
            .receive_and_persist_with(
                &row_batch(&sealed.trace_blob, &sealed.statement),
                &crate::scrub::NullScrubber,
                VerifyMode::Full,
            )
            .await;
        let summary =
            got.unwrap_or_else(|e| panic!("I3487: the sealed row ingests: {} ({e})", e.kind()));
        assert_eq!(summary.signatures_verified, 1, "I3487");
        let b = pick(&engine);
        assert!(
            events_of(b.as_ref(), &trace_id).await > 0,
            "I3487: projected"
        );
        assert_eq!(
            held_blob(b.as_ref(), &sealed.trace_blob).await.as_deref(),
            Some(sealed.trace_blob.as_slice()),
            "I3487: the blob is held as sealed"
        );
    }

    /// **I3487 (P7-fix6) — the trace's signer is selected by REGISTERED
    /// kind.** An Engine whose own key is registered `node`:
    /// - holding no agent key, `seal_trace` is refused
    ///   `trace_agent_signer_not_held` (no silent fallback to the node key);
    /// - carrying an `agent` key (`with_trace_signer`), it seals a trace
    ///   signed by the AGENT key, which the same Engine ingests and projects;
    /// - naming its node key (`seal_trace_as`) is refused by the same token.
    pub(crate) async fn i3487_agent_signer_selected_by_kind<B>(dsn: &str, run: &str, pick: Pick<B>)
    where
        B: Backend + FederationDirectory + BlobStorage + Sync,
    {
        let node_alias = format!("p7-kind-node-{run}");
        let engine = Engine::with_signer_pre_genesis(ts::local_signer(&node_alias), dsn)
            .await
            .unwrap();
        let node_iss = engine
            .register_self_federation_key(crate::federation::types::identity_type::NODE, None, None)
            .await
            .unwrap();
        let raw = raw_trace(recently());
        let only_node = engine.seal_trace(&raw, TraceLevel::Generic).await;
        match &only_node {
            Err(IngestError::TraceRefused { kind, .. }) => {
                assert_eq!(*kind, TRACE_AGENT_SIGNER_NOT_HELD, "I3487: node key only");
            }
            other => panic!("I3487: a node-only Engine is refused by name, got {other:?}"),
        }

        let agent = ts::local_signer(&format!("p7-kind-agent-{run}"));
        let agent_iss =
            e2::put_key_for_signer(engine.federation_directory().as_ref(), &agent, &["agent"])
                .await;
        let both = engine.clone().with_trace_signer(agent);
        let trace_id = raw["trace_id"].as_str().unwrap().to_owned();
        let sealed = both
            .seal_trace(&raw, TraceLevel::Generic)
            .await
            .unwrap_or_else(|e| panic!("I3487: node + agent seals: {} ({e})", e.kind()));
        let (signed_as, _) = check_trace_row_shape(&sealed.statement, &sealed.trace_blob)
            .expect("I3487: the sealed row names its blob");
        assert_eq!(signed_as, agent_iss, "I3487: signed by the AGENT key");
        assert_ne!(signed_as, node_iss, "I3487: never by the node key");
        let summary = both
            .receive_and_persist_with(
                &row_batch(&sealed.trace_blob, &sealed.statement),
                &crate::scrub::NullScrubber,
                VerifyMode::Full,
            )
            .await
            .unwrap_or_else(|e| panic!("I3487: the agent-signed row lands: {} ({e})", e.kind()));
        assert_eq!(summary.signatures_verified, 1, "I3487");
        assert!(
            events_of(pick(&both).as_ref(), &trace_id).await > 0,
            "I3487: projected"
        );

        let named_node = both
            .seal_trace_as(
                &raw_trace(recently()),
                TraceLevel::Generic,
                Some(node_iss.as_str()),
            )
            .await;
        match &named_node {
            Err(IngestError::TraceRefused { kind, .. }) => {
                assert_eq!(*kind, TRACE_AGENT_SIGNER_NOT_HELD, "I3487: named node key");
            }
            other => panic!("I3487: naming the node key is refused, got {other:?}"),
        }
    }

    /// **I3488 — a sealed `self` trace (option A), two nodes.** A seals
    /// through `Engine::seal_trace`: the blob is the at-rest envelope (its
    /// digest is what the row names) wrapped only to A. B adopts the envelope
    /// verbatim and receives the row: B cannot open it, so the row is HELD
    /// `trace_dek_not_held` and projects nothing. A re-keys the owner's new
    /// occurrence B and its key grant reaches B: the grant lands
    /// (`put_at_rest_grants`), the held row re-folds by itself, opens,
    /// binds, and B holds the trace's `trace_events`.
    pub(crate) async fn i3488_sealed_self_trace_waits_for_its_dek<B>(
        dsn_a: &str,
        dsn_b: &str,
        run: &str,
        pick: Pick<B>,
    ) where
        B: Backend + FederationDirectory + BlobStorage + Sync,
    {
        use crate::federation::types::cohort_scope::{self, CryptoTier};
        let (alias_a, alias_b) = (format!("p7-sa-{run}"), format!("p7-sb-{run}"));
        let engine_a = node_engine(&alias_a, dsn_a).await;
        let engine_b = node_engine(&alias_b, dsn_b).await;
        let (sa, sb) = (pick(&engine_a), pick(&engine_b));
        let kem =
            |id: crate::federation::identity_aggregate::ContentKemIdentity| EncryptionPubkeys {
                x25519_base64: id.x25519_pubkey_b64,
                ml_kem_768_base64: id.ml_kem_768_pubkey_b64,
            };
        let a = Node {
            backend: sa.as_ref(),
            signer: ts::local_signer(&alias_a),
            key: engine_a.local_derived_key_id().await.unwrap(),
            kem: kem(sa.load_or_init_content_kem_identity().await.unwrap()),
        };
        let b = Node {
            backend: sb.as_ref(),
            signer: ts::local_signer(&alias_b),
            key: engine_b.local_derived_key_id().await.unwrap(),
            kem: kem(sb.load_or_init_content_kem_identity().await.unwrap()),
        };
        introduce_as(
            &[&a, &b],
            &[&alias_a, &alias_b],
            crate::federation::types::identity_type::AGENT,
        )
        .await;
        // The trace's owner is A's own identity; A is its only occurrence.
        for n in [&a, &b] {
            bind(n.backend, &a.key, &a.key, Some(a.kem.clone())).await;
        }
        let mut raw = raw_trace(recently());
        raw["cohort_scope"] = serde_json::json!(cohort_scope::SELF);
        let trace_id = raw["trace_id"].as_str().unwrap().to_owned();
        let sealed = engine_a
            .seal_trace(&raw, TraceLevel::Generic)
            .await
            .unwrap_or_else(|e| panic!("I3488: A seals its self trace: {} ({e})", e.kind()));
        assert!(
            is_sealed_trace_blob(&sealed.trace_blob),
            "I3488: a self trace's blob is the at-rest envelope"
        );
        let (iss, _) = check_trace_row_shape(&sealed.statement, &sealed.trace_blob)
            .expect("I3488: the row names the envelope's digest");
        assert_eq!(iss, a.key);
        // A ingests its own sealed trace: it holds the DEK, so it projects.
        let mine = engine_a
            .receive_and_persist_with(
                &row_batch(&sealed.trace_blob, &sealed.statement),
                &crate::scrub::NullScrubber,
                VerifyMode::Full,
            )
            .await;
        assert_eq!(kind_of(&mine), "admitted", "I3488: A ingests: {mine:?}");
        assert!(
            events_of(sa.as_ref(), &trace_id).await > 0,
            "I3488: A projects"
        );

        // B becomes an occurrence of the owner AFTER the seal (no wrap yet).
        for n in [&a, &b] {
            bind(n.backend, &a.key, &b.key, Some(b.kem.clone())).await;
        }
        engine_b
            .adopt_sealed_blob(
                &sealed.trace_blob,
                BlobProvenance {
                    author_key_id: a.key.clone(),
                    cohort_scope: cohort_scope::SELF.to_owned(),
                    community_key_id: None,
                    epoch: None,
                    tier: CryptoTier::InvisibleEncrypted,
                    minter_key_id: Some(a.key.clone()),
                },
                None,
                AdoptDisposition::LocalOnly,
            )
            .await
            .expect("I3488: B adopts the envelope verbatim");
        let row_id = row_id_of_statement(&sealed.statement, &iss);
        let applied = Box::pin(
            crate::federation::edition2::ingest::apply_replicated_statement(
                sb.as_ref(),
                &sealed.statement,
                &row_id,
            ),
        )
        .await
        .unwrap_or_else(|e| panic!("I3488: B keeps the replicated row: {e}"));
        assert!(applied.advances_cursor());
        let held = crate::federation::edition2::fold::why_held(
            sb.as_ref(),
            &crate::federation::edition2::names::RowId(row_id),
        )
        .await
        .unwrap()
        .expect("I3488: no DEK: the row is HELD, not admitted with a warning");
        assert_eq!(
            held.reason, TRACE_DEK_NOT_HELD,
            "I3488: held by name: {held:?}"
        );
        assert_eq!(
            events_of(sb.as_ref(), &trace_id).await,
            0,
            "I3488: nothing projected"
        );

        // The DEK arrives: A re-keys B in, and its key grant reaches B.
        let rk = engine_a
            .rekey_self_occurrence_add(&a.key, std::slice::from_ref(&b.key))
            .await
            .expect("I3488: A re-keys the owner's new occurrence");
        assert!(
            rk.granted.iter().any(|(r, n)| r == &b.key && *n >= 1),
            "I3488: a wrap for B: {rk:?}"
        );
        engine_a.emit_pending_key_grants().await.unwrap();
        let sets = crate::federation::key_grant_invariants::two_node::key_grant_rows_for(
            sa.as_ref(),
            &a.key,
            &b.key,
        )
        .await;
        assert!(!sets.is_empty(), "I3488: A emitted B's content grant");
        for set in sets {
            engine_b
                .apply_replicated_key_grant(set)
                .await
                .expect("I3488: B admits A's grant");
        }
        assert!(
            crate::federation::edition2::fold::why_held(
                sb.as_ref(),
                &crate::federation::edition2::names::RowId(row_id),
            )
            .await
            .unwrap()
            .is_none(),
            "I3488: the grant concluded the held row by itself (G0's re-fold)"
        );
        assert_eq!(
            events_of(sb.as_ref(), &trace_id).await,
            events_of(sa.as_ref(), &trace_id).await,
            "I3488: B projects the same trace_events A did"
        );
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

/// **I3489 (pure)** — the signer-kind predicate (CC ruling (a)).
#[test]
fn i3489_trace_signer_kind() {
    // (identity_type, admitted)
    let table: &[(&str, bool)] = &[
        ("agent", true),
        (" agent ", true),
        ("node,agent", true),
        ("user", false),
        ("agent,user", false),
        ("node", false),
        ("primitive", false),
        ("steward", false),
        ("", false),
        ("agents", false),
    ];
    for (ty, admitted) in table {
        assert_eq!(trace_signer_is_agent(ty), *admitted, "I3489: {ty:?}");
    }
    // A row of another dimension is never this rule's.
    assert!(check_trace_signer_kind(Some("capacity:x:v1"), "k", "node").is_ok());
    assert!(check_trace_signer_kind(None, "k", "node").is_ok());
    // The trace families, in either form: `trace:*` and `trace_summary:*`.
    assert!(check_trace_signer_kind(Some("trace_summary:digest:v1"), "k", "node").is_err());
    assert!(check_trace_signer_kind(Some("trace_summary:digest:v1"), "k", "agent").is_ok());
    assert!(check_trace_signer_kind(Some("trace:demo:v1"), "k", "primitive").is_err());
    let refused = check_trace_signer_kind(Some(TRACE_COMPLETE_DIMENSION), "k", "user")
        .expect_err("I3489: a person-signed trace row");
    assert!(
        matches!(
            &refused,
            crate::federation::Error::MalformedRow { reason, .. } if *reason == TRACE_SIGNER_NOT_AGENT
        ),
        "I3489: refused by name: {refused:?}"
    );
}

/// **I3489** on one backend: an agent-signed trace row lands; a node-signed
/// and a person-signed one are refused by name with nothing written.
async fn exercise_signer_kind<D>(d: &D)
where
    D: Backend + FederationDirectory + BlobStorage,
{
    let agent = unique("kind-agent");
    let kid_agent = e2::put_key(d, &agent, &["agent"]).await;
    let blob = blob_of(&raw_trace(recently()));
    let st = statement(&blob, &agent);
    assert_eq!(
        kind_of(&ingest(d, &row_batch(&blob, &st)).await),
        "admitted",
        "I3489: an agent-signed trace row lands"
    );
    assert!(
        d.get_attestation(&row_id_hex(&blob, &kid_agent))
            .await
            .unwrap()
            .is_some(),
        "I3489: the agent's row is held"
    );

    let node = unique("kind-node");
    let kid_node = e2::put_key(d, &node, &["node"]).await;
    let blob = blob_of(&raw_trace(recently()));
    let st = statement(&blob, &node);
    assert_eq!(
        kind_of(&ingest(d, &row_batch(&blob, &st)).await),
        TRACE_SIGNER_NOT_AGENT,
        "I3489: a node-signed trace row is refused by name"
    );
    assert!(
        d.get_attestation(&row_id_hex(&blob, &kid_node))
            .await
            .unwrap()
            .is_none(),
        "I3489: no row written"
    );
    assert!(
        held_blob(d, &blob).await.is_none(),
        "I3489: no blob written (the pre-check runs before the blob plane)"
    );

    let person = unique("kind-person");
    let kid_person = e2::put_key(d, &person, &["user"]).await;
    let blob = blob_of(&raw_trace(recently()));
    let st = statement(&blob, &person);
    assert_eq!(
        kind_of(&ingest(d, &row_batch(&blob, &st)).await),
        TRACE_SIGNER_NOT_AGENT,
        "I3489: a person-signed trace row is refused by name"
    );
    assert!(
        d.get_attestation(&row_id_hex(&blob, &kid_person))
            .await
            .unwrap()
            .is_none(),
        "I3489: no row written"
    );
    assert!(
        held_blob(d, &blob).await.is_none(),
        "I3489: no blob written"
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

    #[tokio::test]
    async fn i3486_replicated_row_projects_sqlite() {
        let a = backend().await;
        let b = backend().await;
        Box::pin(exercise_replicated_projection(&a, &b)).await;
    }

    #[tokio::test]
    async fn i3489_trace_signer_kind_sqlite() {
        let b = backend().await;
        Box::pin(exercise_signer_kind(&b)).await;
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

    #[tokio::test]
    async fn i3486_replicated_row_projects_postgres() {
        let Some(a) = backend().await else { return };
        let Some(b) = backend().await else { return };
        Box::pin(exercise_replicated_projection(&a, &b)).await;
    }

    #[tokio::test]
    async fn i3489_trace_signer_kind_postgres() {
        let Some(b) = backend().await else { return };
        Box::pin(exercise_signer_kind(&b)).await;
    }

    #[cfg(feature = "scrub")]
    #[tokio::test]
    async fn i3483_seal_scrubs_postgres() {
        let Some(b) = backend().await else { return };
        Box::pin(exercise_seal_scrubs(&b)).await;
    }
}

#[cfg(feature = "scrub")]
mod engine_runs {
    use super::engine_level;

    fn suffix() -> String {
        uuid::Uuid::new_v4().simple().to_string()[..12].to_owned()
    }

    #[cfg(feature = "sqlite")]
    mod sqlite {
        use super::{engine_level, suffix};
        fn pick(e: &crate::Engine) -> std::sync::Arc<crate::store::sqlite::SqliteBackend> {
            e.sqlite_backend().expect("sqlite").clone()
        }
        #[tokio::test]
        async fn i3487_seal_then_ingest_sqlite() {
            Box::pin(engine_level::i3487_seal_then_ingest(
                "sqlite::memory:",
                &suffix(),
                pick,
            ))
            .await;
        }
        #[tokio::test]
        async fn i3487_agent_signer_selected_by_kind_sqlite() {
            Box::pin(engine_level::i3487_agent_signer_selected_by_kind(
                "sqlite::memory:",
                &suffix(),
                pick,
            ))
            .await;
        }
        #[tokio::test]
        async fn i3488_sealed_self_trace_sqlite() {
            Box::pin(engine_level::i3488_sealed_self_trace_waits_for_its_dek(
                "sqlite::memory:",
                "sqlite::memory:",
                &suffix(),
                pick,
            ))
            .await;
        }
    }

    #[cfg(feature = "postgres")]
    mod postgres {
        use super::{engine_level, suffix};
        fn pick(e: &crate::Engine) -> std::sync::Arc<crate::store::postgres::PostgresBackend> {
            e.postgres_backend().expect("postgres").clone()
        }
        #[tokio::test]
        async fn i3487_seal_then_ingest_postgres() {
            let Some(dsn) = crate::test_pg::empty_dsn() else {
                return;
            };
            Box::pin(engine_level::i3487_seal_then_ingest(&dsn, &suffix(), pick)).await;
        }
        #[tokio::test]
        async fn i3487_agent_signer_selected_by_kind_postgres() {
            let Some(dsn) = crate::test_pg::empty_dsn() else {
                return;
            };
            Box::pin(engine_level::i3487_agent_signer_selected_by_kind(
                &dsn,
                &suffix(),
                pick,
            ))
            .await;
        }
        #[tokio::test]
        async fn i3488_sealed_self_trace_postgres() {
            let (Some(a), Some(b)) = (crate::test_pg::empty_dsn(), crate::test_pg::empty_dsn())
            else {
                return;
            };
            Box::pin(engine_level::i3488_sealed_self_trace_waits_for_its_dek(
                &a,
                &b,
                &suffix(),
                pick,
            ))
            .await;
        }
    }
}
