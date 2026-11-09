//! v61.1.0 (CIRISPersist#1233, CC 5.3.2.4.3.1) — **the Python verify doors
//! accept only `"strict"`**, and the audit-chain proof does not serve a
//! refused head as no head.
//!
//! - **I1560** `Engine.verify_hybrid` (caller-supplied pubkeys): a genuine
//!   hybrid signature verifies under `"strict"`; the SAME signature under
//!   every other policy string is refused `verify_policy_violation`; garbage
//!   base64 under a non-strict policy is refused with the policy token, not
//!   `verify_hybrid_base64` (the refusal runs before any decode or crypto),
//!   while under `"strict"` it reaches the decoder.
//! - **I1561** `Engine.verify_hybrid_via_directory`: the same over a
//!   registered hybrid key, plus an UNKNOWN key under a non-strict policy is
//!   refused with the policy token, not `verify_unknown_key` (before the
//!   lookup); and `verify_signed_key_record` / `verify_signed_attestation` /
//!   `verify_signed_revocation` refuse a non-strict policy before decoding
//!   the envelope.
//! - **I1567** `audit_chain_proof`: a genuine stored head is served; a stored head without its ML-DSA-65 half
//!   (written around the store gate, as an earlier build left it) is SERVED
//!   as itself (CC 2.6.1.8) and `verify_audit_sth` REFUSES the head the proof
//!   carries with `audit_sth_not_hybrid`; a stored head that does not decode
//!   is an error, not the chain with `head_signature: None` (only a real
//!   error is refused, and it is never folded to absence).
//!
//! Each runs on sqlite and postgres. The capsule leg is
//! `ffi::directory_capsule`'s I1562; the wheel leg is
//! `tests/python/test_hybrid_policy_1233_surface.py` (I1563); the store,
//! serve and verify legs of the head are `audit::hybrid_head_1233_invariants`
//! (I1564–I1566).

use super::{BackendDispatch, PyEngine};
use crate::federation::tier_ingest::test_support as ts;
use crate::verify::hybrid::VERIFY_POLICY_VIOLATION;
use pyo3::prelude::*;
use pyo3::types::PyDict;

/// Every policy string that is not exactly `"strict"`.
const NOT_STRICT: [&str; 6] = [
    "ed25519_fallback",
    "soft_freshness",
    "STRICT",
    "strict ",
    "",
    "hybrid",
];

fn runtime() -> tokio::runtime::Runtime {
    tokio::runtime::Builder::new_multi_thread()
        .enable_all()
        .build()
        .unwrap()
}

/// Open `dsn` through the Python constructor, as every host does.
fn open_from_python(dsn: &str, alias: &str, dir: &std::path::Path) -> PyEngine {
    let seed = ts::seed_for(alias);
    let ed = dir.join("ed.seed");
    let pqc = dir.join("pqc.seed");
    std::fs::write(&ed, seed).unwrap();
    std::fs::write(&pqc, seed).unwrap();
    Python::initialize();
    Python::attach(|py| {
        PyEngine::new(
            py,
            dsn,
            alias,
            None,
            Some(alias.to_owned()),
            Some(ed.display().to_string()),
            Some(alias.to_owned()),
            Some(pqc.display().to_string()),
            None,
            None,
            false,
            false,
            false,
            None,
            None,
            None,
            None,
        )
    })
    .expect("I1560: the Python open")
}

/// Register `key` with its real deterministic hybrid pubkeys on the
/// engine's own backend.
fn register(rt: &tokio::runtime::Runtime, engine: &PyEngine, key: &str) {
    match &engine.backend {
        #[cfg(feature = "sqlite")]
        BackendDispatch::Sqlite(sq) => {
            let sq = sq.clone();
            rt.block_on(ts::register_hybrid_key(sq.as_ref(), key));
        }
        #[cfg(feature = "postgres")]
        BackendDispatch::Postgres(pg) => {
            let pg = pg.clone();
            rt.block_on(ts::register_hybrid_key(pg.as_ref(), key));
        }
    }
}

/// `Ok(outcome)` or `Err(the ValueError's message)`.
fn verdict(py: Python<'_>, r: PyResult<Bound<'_, PyDict>>) -> Result<String, String> {
    match r {
        Ok(d) => Ok(d
            .get_item("outcome")
            .expect("get_item")
            .expect("an outcome")
            .extract::<String>()
            .expect("outcome is a str")),
        Err(e) => {
            assert!(
                e.is_instance_of::<pyo3::exceptions::PyValueError>(py),
                "a verify refusal is a ValueError: {e}"
            );
            Err(e.value(py).to_string())
        }
    }
}

fn policy_refused(got: Result<String, String>, what: &str) {
    assert_eq!(
        got,
        Err(VERIFY_POLICY_VIOLATION.to_owned()),
        "{what}: refused with the policy token"
    );
}

fn i1560_verify_hybrid_accepts_only_strict(engine: &PyEngine, who: &str) {
    let key = "i1560-verify-hybrid-signer";
    let msg = b"CIRISPersist#1233 I1560".as_slice();
    let sig = ts::threshold_sign(key, msg);
    let (ed_pk, pqc_pk) = ts::hybrid_pubkeys(key);
    let pqc_sig = sig.mldsa65_signature_base64.clone();
    Python::attach(|py| {
        let call = |ed_sig: &str, pqc_sig: Option<&str>, policy: &str| {
            verdict(
                py,
                engine.verify_hybrid(
                    py,
                    msg,
                    ed_sig,
                    pqc_sig,
                    &ed_pk,
                    pqc_pk.as_deref(),
                    policy,
                    Some(3_600.0),
                    Some(1.0),
                ),
            )
        };
        assert_eq!(
            call(&sig.ed25519_signature_base64, pqc_sig.as_deref(), "strict"),
            Ok("hybrid_verified".to_owned()),
            "I1560 {who}: a genuine hybrid signature verifies under strict"
        );
        for policy in NOT_STRICT {
            policy_refused(
                call(&sig.ed25519_signature_base64, pqc_sig.as_deref(), policy),
                &format!("I1560 {who}: {policy:?} over a VALID signature"),
            );
            policy_refused(
                call("!!!not-base64!!!", Some("!!!"), policy),
                &format!("I1560 {who}: {policy:?} before any decode"),
            );
        }
        assert_eq!(
            call("!!!not-base64!!!", Some("!!!"), "strict"),
            Err("verify_hybrid_base64".to_owned()),
            "I1560 {who}: under strict the same garbage reaches the decoder"
        );
    });
}

fn i1561_via_directory_accepts_only_strict(
    rt: &tokio::runtime::Runtime,
    engine: &PyEngine,
    who: &str,
) {
    let key = format!(
        "i1561-signer-{}",
        &uuid::Uuid::new_v4().simple().to_string()[..8]
    );
    register(rt, engine, &key);
    let msg = b"CIRISPersist#1233 I1561".as_slice();
    let sig = ts::threshold_sign(&key, msg);
    let pqc_sig = sig.mldsa65_signature_base64.clone();
    Python::attach(|py| {
        let call = |key_id: &str, policy: &str| {
            verdict(
                py,
                engine.verify_hybrid_via_directory(
                    py,
                    msg,
                    key_id,
                    &sig.ed25519_signature_base64,
                    pqc_sig.as_deref(),
                    policy,
                    Some(3_600.0),
                    Some(1.0),
                ),
            )
        };
        assert_eq!(
            call(&key, "strict"),
            Ok("hybrid_verified".to_owned()),
            "I1561 {who}: a genuine hybrid signature from a registered key verifies"
        );
        assert_eq!(
            call("i1561-no-such-key", "strict"),
            Err("verify_unknown_key".to_owned()),
            "I1561 {who}: under strict an unknown key reaches the lookup"
        );
        for policy in NOT_STRICT {
            policy_refused(
                call(&key, policy),
                &format!("I1561 {who}: {policy:?} over a VALID signature"),
            );
            policy_refused(
                call("i1561-no-such-key", policy),
                &format!("I1561 {who}: {policy:?} before the lookup"),
            );
        }

        // The three envelope verifies route through the same door, and
        // refuse the policy before they decode the envelope.
        for name in [
            "verify_signed_key_record",
            "verify_signed_attestation",
            "verify_signed_revocation",
        ] {
            let f = |policy: &str| {
                let r = match name {
                    "verify_signed_key_record" => {
                        engine.verify_signed_key_record(py, "{", policy, None, None)
                    }
                    "verify_signed_attestation" => {
                        engine.verify_signed_attestation(py, "{", policy, None, None)
                    }
                    _ => engine.verify_signed_revocation(py, "{", policy, None, None),
                };
                verdict(py, r)
            };
            let strict = f("strict");
            assert!(
                matches!(&strict, Err(m) if m.contains("JSON decode")),
                "I1561 {who}: {name} under strict reaches the decoder: {strict:?}"
            );
            for policy in NOT_STRICT {
                policy_refused(
                    f(policy),
                    &format!("I1561 {who}: {name} {policy:?} before decoding"),
                );
            }
        }
    });
}

#[cfg(feature = "sqlite")]
#[test]
fn i1560_i1561_python_verify_doors_accept_only_strict_sqlite() {
    let rt = runtime();
    let dir = tempfile::tempdir().unwrap();
    let dsn = format!("sqlite:///{}", dir.path().join("node.db").display());
    let alias = format!("hp{}", &uuid::Uuid::new_v4().simple().to_string()[..8]);
    let engine = open_from_python(&dsn, &alias, dir.path());
    i1560_verify_hybrid_accepts_only_strict(&engine, "sqlite");
    i1561_via_directory_accepts_only_strict(&rt, &engine, "sqlite");
}

#[cfg(feature = "postgres")]
#[test]
fn i1560_i1561_python_verify_doors_accept_only_strict_postgres() {
    let Some(dsn) = crate::test_pg::isolated_dsn() else {
        eprintln!("skipping: CIRIS_PERSIST_TEST_PG_URL unset");
        return;
    };
    let rt = runtime();
    let dir = tempfile::tempdir().unwrap();
    let alias = format!("hp{}", &uuid::Uuid::new_v4().simple().to_string()[..8]);
    let engine = open_from_python(&dsn, &alias, dir.path());
    i1560_verify_hybrid_accepts_only_strict(&engine, "postgres");
    i1561_via_directory_accepts_only_strict(&rt, &engine, "postgres");
    eprintln!("i1560_i1561 postgres: RAN");
}

// ── I1567 — audit_chain_proof serves a stored head as itself, and does not
// serve an unreadable head as no head ──

#[cfg(feature = "cirisaudit")]
fn genesis_entry(tenant: &str, trace_id: &str) -> crate::audit::AuditEntry {
    use base64::engine::general_purpose::STANDARD as B64;
    use base64::Engine as _;
    use ed25519_dalek::Signer as _;
    let key = ed25519_dalek::SigningKey::from_bytes(&[0xC7; 32]);
    let mut e = crate::audit::AuditEntry {
        entry_id: uuid::Uuid::new_v4().to_string(),
        sequence_number: 1,
        tenant_id: tenant.to_owned(),
        actor_id: B64.encode(key.verifying_key().to_bytes()),
        action_type: "system_event".into(),
        subject_kind: "task".into(),
        subject_id: trace_id.to_owned(),
        payload: serde_json::json!({ "i1567": true }),
        prev_hash: crate::audit::GENESIS_PREV_HASH.to_vec(),
        entry_hash: vec![],
        recorded_at: crate::audit::verify::truncate_to_micros(chrono::Utc::now()),
        signature: String::new(),
    };
    e.entry_hash = crate::audit::verify::compute_entry_hash(&e)
        .unwrap()
        .to_vec();
    let canon = crate::audit::verify::canonical_bytes_for_entry(&e).unwrap();
    e.signature = B64.encode(key.sign(&canon).to_bytes());
    e
}

/// The head a proof carries, decoded back from its JSON.
#[cfg(feature = "cirisaudit")]
fn proof_head(
    proof: &crate::federation::AuditChainProof,
    who: &str,
) -> ciris_verify_core::transparency::SignedTreeHead {
    let json = proof
        .head_signature
        .as_deref()
        .unwrap_or_else(|| panic!("I1567 {who}: the stored head rides the proof"));
    serde_json::from_str(json).expect("I1567: head_signature is a SignedTreeHead")
}

/// The stored heads `i1567_assert` injects around the store gate.
#[cfg(feature = "cirisaudit")]
struct I1567Heads<G, E, R> {
    genuine: G,
    emptied: E,
    removed: R,
}

/// After the genuine head (size 1) is stored, the proof serves it. After a head with its ML-DSA-65 half emptied
/// (size 2) is stored around the door, the proof serves THAT head as itself,
/// and `verify_audit_sth` refuses it with the token. After a head whose blob
/// does not decode (size 3, the `pqc` member removed), the proof is an error,
/// not the chain without a head.
#[cfg(feature = "cirisaudit")]
async fn i1567_assert<G, E, R>(
    dispatch: &BackendDispatch,
    trace_id: &str,
    heads: I1567Heads<G, E, R>,
    pins: (&str, &str),
    who: &str,
) where
    G: std::future::Future<Output = ()>,
    E: std::future::Future<Output = ()>,
    R: std::future::Future<Output = ()>,
{
    use crate::audit::merkle_store::{verify_audit_sth, AUDIT_STH_NOT_HYBRID};
    let (ed_pk, pqc_pk) = pins;

    heads.genuine.await;
    let proof = super::build_audit_chain_proof(dispatch, trace_id)
        .await
        .unwrap_or_else(|e| panic!("I1567 {who}: the genuine head is served: {e}"));
    assert_eq!(proof.entries.len(), 1, "I1567 {who}: the chain");
    // The genuine row is injected without its `signed_at`, so its served
    // instant is the column default and it is not verified here; I1565
    // verifies a genuine head stored through the door.
    let head = proof_head(&proof, who);
    assert_eq!(head.tree_size, 1, "I1567 {who}: the genuine head");
    assert!(
        !head.signature.pqc.signature.is_empty(),
        "I1567 {who}: the genuine head carries its ML-DSA-65 half"
    );

    heads.emptied.await;
    let proof = super::build_audit_chain_proof(dispatch, trace_id)
        .await
        .unwrap_or_else(|e| {
            panic!("I1567 {who}: a stored head without its half is served as itself: {e}")
        });
    assert_eq!(proof.entries.len(), 1, "I1567 {who}: the chain");
    let head = proof_head(&proof, who);
    assert_eq!(
        head.tree_size, 2,
        "I1567 {who}: the newest stored head is served, not the genuine one below it"
    );
    assert!(
        head.signature.pqc.signature.is_empty(),
        "I1567 {who}: served as itself, its half still empty"
    );
    match verify_audit_sth(&head, ed_pk, pqc_pk) {
        Err(e) => assert!(
            e.to_string().contains(AUDIT_STH_NOT_HYBRID),
            "I1567 {who}: verify refuses the served head with the token: {e}"
        ),
        Ok(()) => panic!("I1567 {who}: a head without its ML-DSA-65 half must not verify"),
    }

    heads.removed.await;
    match super::build_audit_chain_proof(dispatch, trace_id).await {
        Err(e) => assert!(
            e.contains("sth signature deserialize"),
            "I1567 {who}: the unreadable head is the error: {e}"
        ),
        Ok(p) => panic!(
            "I1567 {who}: a head that does not decode must not be served as \
             head_signature={:?} over {} entries",
            p.head_signature,
            p.entries.len()
        ),
    }
}

#[cfg(all(feature = "cirisaudit", feature = "sqlite"))]
#[tokio::test(flavor = "multi_thread")]
async fn i1567_audit_chain_proof_serves_a_stored_head_as_itself_sqlite() {
    use crate::audit::hybrid_head_1233_invariants::bodies as hb;
    use crate::audit::AuditService as _;
    use crate::store::Backend as _;
    let backend = std::sync::Arc::new(
        crate::store::sqlite::SqliteBackend::open_in_memory()
            .await
            .unwrap(),
    );
    backend.run_migrations().await.unwrap();
    let tenant = format!("i1567s-{}", uuid::Uuid::new_v4().simple());
    let trace_id = format!("i1567s-trace-{}", uuid::Uuid::new_v4().simple());
    crate::audit::sqlite::SqliteAuditBackend::new(backend.conn_handle())
        .record_entry(genesis_entry(&tenant, &trace_id))
        .await
        .expect("I1567: the genesis entry records");
    let log_id = crate::audit::merkle_store::log_id_for_tenant(&tenant);
    let (genuine, ed_pk, pqc_pk) = hb::genuine_head(&log_id, 1).await;
    let conn = backend.conn_handle();
    let genuine_blob = serde_json::to_vec(&genuine.signature).unwrap();
    let emptied_blob = hb::blob_with_the_pqc_half_emptied(&genuine);
    let removed_blob = hb::blob_with_the_pqc_half_removed(&genuine);
    let dispatch = BackendDispatch::Sqlite(backend);
    i1567_assert(
        &dispatch,
        &trace_id,
        I1567Heads {
            genuine: async { hb::inject_sth_row_sqlite(&conn, &tenant, 1, &genuine_blob) },
            emptied: async { hb::inject_sth_row_sqlite(&conn, &tenant, 2, &emptied_blob) },
            removed: async { hb::inject_sth_row_sqlite(&conn, &tenant, 3, &removed_blob) },
        },
        (ed_pk.as_str(), pqc_pk.as_str()),
        "sqlite",
    )
    .await;
}

#[cfg(all(feature = "cirisaudit", feature = "postgres"))]
#[tokio::test(flavor = "multi_thread")]
async fn i1567_audit_chain_proof_serves_a_stored_head_as_itself_postgres() {
    use crate::audit::hybrid_head_1233_invariants::bodies as hb;
    use crate::audit::AuditService as _;
    use crate::store::Backend as _;
    let Some(dsn) = crate::test_pg::dsn() else {
        eprintln!("skipping: CIRIS_PERSIST_TEST_PG_URL unset");
        return;
    };
    let backend = std::sync::Arc::new(
        crate::store::postgres::PostgresBackend::connect(&dsn)
            .await
            .unwrap(),
    );
    backend.run_migrations().await.unwrap();
    let tenant = format!("i1567p-{}", uuid::Uuid::new_v4().simple());
    let trace_id = format!("i1567p-trace-{}", uuid::Uuid::new_v4().simple());
    backend
        .record_entry(genesis_entry(&tenant, &trace_id))
        .await
        .expect("I1567: the genesis entry records");
    let log_id = crate::audit::merkle_store::log_id_for_tenant(&tenant);
    let (genuine, ed_pk, pqc_pk) = hb::genuine_head(&log_id, 1).await;
    let genuine_blob = serde_json::to_vec(&genuine.signature).unwrap();
    let emptied_blob = hb::blob_with_the_pqc_half_emptied(&genuine);
    let removed_blob = hb::blob_with_the_pqc_half_removed(&genuine);
    let dispatch = BackendDispatch::Postgres(backend.clone());
    i1567_assert(
        &dispatch,
        &trace_id,
        I1567Heads {
            genuine: hb::inject_sth_row_pg(&backend, &tenant, 1, &genuine_blob),
            emptied: hb::inject_sth_row_pg(&backend, &tenant, 2, &emptied_blob),
            removed: hb::inject_sth_row_pg(&backend, &tenant, 3, &removed_blob),
        },
        (ed_pk.as_str(), pqc_pk.as_str()),
        "postgres",
    )
    .await;
    eprintln!("i1567 postgres: RAN");
}
