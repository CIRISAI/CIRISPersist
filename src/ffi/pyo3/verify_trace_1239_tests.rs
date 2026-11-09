//! v61.1.0 (CIRISPersist#1239, CC 5.3.2.4.3.1) — **`Engine.verify_trace`, the
//! dry-run, gives ingest's verdict.**
//!
//! - **I1569** One corpus of traces, three verdicts per trace: the dry-run
//!   (`Engine.verify_trace`), ingest's verify step
//!   ([`crate::ingest::verify_trace_for_admission`], mapped to Python through
//!   the one FFI mapping), and the full ingest door
//!   (`Engine.receive_and_persist`, `pre_verified=False`). For every trace the
//!   dry-run and ingest's verify agree on the exception type and the stable
//!   token, and both match the token pinned for that cause. For every refused
//!   trace `receive_and_persist` raises the same type and token (verify is
//!   step 2, before any write, so its refusal is the door's refusal). For
//!   every admitted trace `receive_and_persist` does not refuse it on a
//!   `verify_*` ground.
//!
//!   The corpus: a genuine hybrid trace at 2.7.0 (Python-compat canon) and at
//!   3.0.0 (JCS); a trace with no PQC half (`verify_hybrid_required`, the #225
//!   hard cut); a corrupted ML-DSA-65 signature and a corrupted Ed25519
//!   signature (`verify_hybrid_failed`); a signer the directory does not know
//!   (`verify_unknown_key`).
//!
//!   And the defect, stated as a fact: the trace with no PQC half carries a
//!   VALID Ed25519 signature from a key the directory holds, so v61.0.5's
//!   dry-run (`verify_trace_via_directory`: look up the Ed25519 key, check the
//!   classical half) accepted it. That check still passes here; the dry-run
//!   now refuses the trace.
//!
//! Runs on sqlite and postgres, through the Python constructor.
//!
//! Mutation for the lead: point `PyEngine::verify_trace` back at
//! `verify_trace_via_directory` (classical only). The no-PQC and
//! corrupted-PQC traces then verify through the dry-run and are refused by
//! ingest, and I1569 reds on both backends.

use super::{BackendDispatch, PyEngine};
use crate::federation::tier_ingest::test_support as ts;
use crate::schema::{
    CompleteTrace, ComponentType, ReasoningEventType, SchemaVersion, TraceComponent, TraceLevel,
};
use crate::verify::PythonJsonDumpsCanonicalizer;
use base64::engine::general_purpose::STANDARD as B64;
use base64::Engine as _;
use pyo3::exceptions::{PyRuntimeError, PyValueError};
use pyo3::prelude::*;
use pyo3::types::PyBytes;

/// `Ok(())` for an admitted trace, or `Err((python type, args[0]))`.
type Verdict = Result<(), (&'static str, String)>;

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
    .expect("I1569: the Python open")
}

/// Register `key` with its real deterministic hybrid pubkeys on the engine's
/// own backend: the Ed25519 half `Backend::lookup_public_key` resolves and
/// the ML-DSA-65 half the federation directory resolves by `pqc_key_id`.
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

/// Classify a `PyErr` the way a Python caller sees it: its type and
/// `args[0]`, the stable token.
fn classify(py: Python<'_>, e: &PyErr, what: &str) -> (&'static str, String) {
    let ty = if e.is_instance_of::<PyValueError>(py) {
        "ValueError"
    } else if e.is_instance_of::<PyRuntimeError>(py) {
        "RuntimeError"
    } else {
        panic!("I1569 {what}: a refusal is a ValueError or a RuntimeError: {e}")
    };
    let token = e
        .value(py)
        .getattr("args")
        .and_then(|args| args.get_item(0))
        .and_then(|t| t.extract::<String>())
        .unwrap_or_else(|err| panic!("I1569 {what}: args[0] is the token: {e} ({err})"));
    (ty, token)
}

/// A one-component trace, unsigned, at `schema`.
fn unsigned_trace(schema: &str, trace_id: &str, signer: &str) -> CompleteTrace {
    let mut data = serde_json::Map::new();
    data.insert("attempt_index".into(), 0.into());
    data.insert("rationale".into(), "CIRISPersist#1239 I1569".into());
    CompleteTrace {
        trace_id: trace_id.to_owned(),
        thought_id: "th-i1569".into(),
        task_id: None,
        agent_id_hash: "deadbeef".into(),
        started_at: "2026-04-30T00:15:53.123456Z".parse().unwrap(),
        completed_at: "2026-04-30T00:16:12.789012Z".parse().unwrap(),
        trace_level: TraceLevel::Generic,
        trace_schema_version: SchemaVersion::parse(schema).expect("supported schema"),
        components: vec![TraceComponent {
            component_type: ComponentType::Observation,
            event_type: ReasoningEventType::ThoughtStart,
            timestamp: "2026-04-30T00:15:53.123Z".parse().unwrap(),
            data,
            agent_id_hash: None,
        }],
        deployment_profile: None,
        cohort_scope: "federation".into(),
        cohort_target_id: None,
        signature: String::new(),
        signature_key_id: signer.to_owned(),
        signature_ml_dsa_65: None,
        pubkey_ml_dsa_65: None,
        pqc_key_id: None,
        run_kind: None,
    }
}

/// The canonical bytes the producer signs, under the canonicalizer ingest
/// selects for the trace's signed schema epoch.
fn canonical(trace: &CompleteTrace) -> Vec<u8> {
    crate::verify::ed25519::canonical_bytes_for_trace(
        trace,
        crate::ingest::trace_canonicalizer(trace.trace_schema_version.as_str()),
    )
    .expect("I1569: the trace canonicalizes")
}

/// Hybrid-sign as a producer does: Ed25519 over the canonical bytes, ML-DSA-65
/// over `canonical || ed25519_sig`, both from `signer`'s deterministic keys,
/// with `pqc_key_id` naming the directory row that holds the PQC pubkey.
fn hybrid_signed(schema: &str, trace_id: &str, signer: &str) -> CompleteTrace {
    let mut trace = unsigned_trace(schema, trace_id, signer);
    trace.pqc_key_id = Some(signer.to_owned());
    trace.pubkey_ml_dsa_65 = ts::hybrid_pubkeys(signer).1;
    let sig = ts::threshold_sign(signer, &canonical(&trace));
    trace.signature = sig.ed25519_signature_base64;
    trace.signature_ml_dsa_65 = sig.mldsa65_signature_base64;
    assert!(
        trace.signature_ml_dsa_65.is_some(),
        "I1569: the fixture carries a PQC half"
    );
    trace
}

/// Flip one bit of a base64 signature, keeping its length (so the refusal
/// is the cryptographic check, not a length or decode check).
fn flip(sig_b64: &str) -> String {
    let mut raw = B64
        .decode(sig_b64)
        .expect("I1569: fixture signature decodes");
    raw[0] ^= 0x01;
    B64.encode(raw)
}

/// One corpus entry: what it is, the trace, and the verdict ingest gives.
struct Case {
    name: &'static str,
    trace: CompleteTrace,
    expected: Verdict,
}

fn corpus(tag: &str, signer: &str, stranger: &str) -> Vec<Case> {
    let id = |what: &str| format!("i1569-{tag}-{what}");
    let refused = |token: &str| -> Verdict { Err(("ValueError", token.to_owned())) };

    let genuine_270 = hybrid_signed("2.7.0", &id("genuine-270"), signer);
    let genuine_300 = hybrid_signed("3.0.0", &id("genuine-300"), signer);

    // No PQC half: a valid Ed25519 signature from a registered key, and
    // nothing else.
    let mut no_pqc = hybrid_signed("2.7.0", &id("no-pqc"), signer);
    no_pqc.signature_ml_dsa_65 = None;
    no_pqc.pubkey_ml_dsa_65 = None;
    no_pqc.pqc_key_id = None;

    let mut bad_pqc = hybrid_signed("2.7.0", &id("bad-pqc"), signer);
    bad_pqc.signature_ml_dsa_65 = bad_pqc.signature_ml_dsa_65.as_deref().map(flip);

    let mut bad_classical = hybrid_signed("2.7.0", &id("bad-classical"), signer);
    bad_classical.signature = flip(&bad_classical.signature);

    // Genuinely hybrid-signed by a key the directory does not hold.
    let unknown = hybrid_signed("2.7.0", &id("unknown-key"), stranger);

    vec![
        Case {
            name: "a genuine hybrid trace (2.7.0, Python-compat)",
            trace: genuine_270,
            expected: Ok(()),
        },
        Case {
            name: "a genuine hybrid trace (3.0.0, JCS)",
            trace: genuine_300,
            expected: Ok(()),
        },
        Case {
            name: "a trace with no PQC half",
            trace: no_pqc,
            expected: refused("verify_hybrid_required"),
        },
        Case {
            name: "a trace with a corrupted ML-DSA-65 signature",
            trace: bad_pqc,
            expected: refused("verify_hybrid_failed"),
        },
        Case {
            name: "a trace with a corrupted Ed25519 signature",
            trace: bad_classical,
            expected: refused("verify_hybrid_failed"),
        },
        Case {
            name: "a trace from a signer the directory does not know",
            trace: unknown,
            expected: refused("verify_unknown_key"),
        },
    ]
}

/// The dry-run's verdict, through the pymethod.
fn dry_run(engine: &PyEngine, trace: &CompleteTrace, what: &str) -> Verdict {
    let json = serde_json::to_string(trace).unwrap();
    Python::attach(|py| match engine.verify_trace(py, &json) {
        Ok(d) => {
            let verified: bool = d
                .get_item("verified")
                .expect("get_item")
                .expect("a verified key")
                .extract()
                .expect("verified is a bool");
            assert!(verified, "I1569 {what}: success says verified=True");
            let schema: String = d
                .get_item("schema_version")
                .expect("get_item")
                .expect("a schema_version key")
                .extract()
                .expect("schema_version is a str");
            assert_eq!(
                schema,
                trace.trace_schema_version.as_str(),
                "I1569 {what}: the dry-run reports the trace's schema"
            );
            Ok(())
        }
        Err(e) => Err(classify(py, &e, what)),
    })
}

/// Ingest's verify step on the engine's own backend, mapped to Python by the
/// FFI's one ingest mapping.
fn ingest_verify(
    rt: &tokio::runtime::Runtime,
    engine: &PyEngine,
    trace: &CompleteTrace,
    what: &str,
) -> Verdict {
    let r = match &engine.backend {
        #[cfg(feature = "sqlite")]
        BackendDispatch::Sqlite(sq) => {
            let sq = sq.clone();
            rt.block_on(crate::ingest::verify_trace_for_admission(
                sq.as_ref(),
                trace,
                "i1569",
                &PythonJsonDumpsCanonicalizer,
            ))
        }
        #[cfg(feature = "postgres")]
        BackendDispatch::Postgres(pg) => {
            let pg = pg.clone();
            rt.block_on(crate::ingest::verify_trace_for_admission(
                pg.as_ref(),
                trace,
                "i1569",
                &PythonJsonDumpsCanonicalizer,
            ))
        }
    };
    r.map_err(|e| Python::attach(|py| classify(py, &super::ingest_err_to_py(e, "i1569"), what)))
}

/// The full ingest door's verdict on a one-trace batch.
fn receive_and_persist(engine: &PyEngine, trace: &CompleteTrace, what: &str) -> Verdict {
    let envelope = serde_json::json!({
        "events": [{
            "event_type": "complete_trace",
            "trace_level": "generic",
            "trace": serde_json::to_value(trace).unwrap(),
        }],
        "batch_timestamp": "2026-04-30T15:00:00+00:00",
        "consent_timestamp": "2025-01-01T00:00:00Z",
        "trace_level": "generic",
        "trace_schema_version": trace.trace_schema_version.as_str(),
    });
    let bytes = envelope.to_string().into_bytes();
    Python::attach(|py| {
        let body = PyBytes::new(py, &bytes);
        match engine.receive_and_persist(py, &body, false) {
            Ok(_) => Ok(()),
            Err(e) => Err(classify(py, &e, what)),
        }
    })
}

/// The classical check v61.0.5's dry-run ran: resolve the Ed25519 key by
/// `signature_key_id` from the engine's backend, verify the Ed25519 half.
fn classical_only_check(
    rt: &tokio::runtime::Runtime,
    engine: &PyEngine,
    trace: &CompleteTrace,
) -> Result<(), String> {
    use crate::store::Backend;
    let key_id = trace.signature_key_id.as_str();
    let key = match &engine.backend {
        #[cfg(feature = "sqlite")]
        BackendDispatch::Sqlite(sq) => rt.block_on(Backend::lookup_public_key(sq.as_ref(), key_id)),
        #[cfg(feature = "postgres")]
        BackendDispatch::Postgres(pg) => {
            rt.block_on(Backend::lookup_public_key(pg.as_ref(), key_id))
        }
    }
    .map_err(|e| e.to_string())?
    .ok_or_else(|| "the signer is not in the directory".to_owned())?;
    crate::verify::verify_trace(
        trace,
        crate::ingest::trace_canonicalizer(trace.trace_schema_version.as_str()),
        &key,
    )
    .map_err(|e| e.kind().to_owned())
}

fn i1569_assert(rt: &tokio::runtime::Runtime, engine: &PyEngine, who: &str) {
    let tag = uuid::Uuid::new_v4().simple().to_string()[..8].to_owned();
    // The distinguishing part FIRST: the test signer seeds from the first 32
    // bytes of a key id.
    let signer = format!("{tag}-i1569-signer");
    let stranger = format!("{tag}-i1569-stranger");
    assert_ne!(
        ts::hybrid_pubkeys(&signer).0,
        ts::hybrid_pubkeys(&stranger).0,
        "I1569: the stranger is a different key"
    );
    register(rt, engine, &signer);

    let cases = corpus(&tag, &signer, &stranger);
    assert!(
        cases.iter().any(|c| c.expected.is_ok()) && cases.iter().any(|c| c.expected.is_err()),
        "I1569: the corpus admits and refuses, or agreement proves nothing"
    );
    for case in &cases {
        let what = format!("{who}: {}", case.name);
        let dry = dry_run(engine, &case.trace, &what);
        let ingest = ingest_verify(rt, engine, &case.trace, &what);
        assert_eq!(
            dry, ingest,
            "I1569 {what}: Engine.verify_trace and ingest's verify give one verdict"
        );
        assert_eq!(
            ingest, case.expected,
            "I1569 {what}: ingest's verdict for this cause"
        );
        let door = receive_and_persist(engine, &case.trace, &what);
        match &case.expected {
            Err(_) => assert_eq!(
                door, case.expected,
                "I1569 {what}: receive_and_persist refuses with the same type and token"
            ),
            Ok(()) => {
                if let Err((_, token)) = &door {
                    assert!(
                        !token.starts_with("verify_"),
                        "I1569 {what}: receive_and_persist must not refuse an \
                         admitted trace on a verify ground, got {token}"
                    );
                }
            }
        }
    }

    // The defect, stated as a fact: v61.0.5's dry-run ran the classical
    // check, and the trace with no PQC half passes it. The dry-run now
    // refuses that same trace.
    let no_pqc = &cases
        .iter()
        .find(|c| c.trace.signature_ml_dsa_65.is_none())
        .expect("I1569: the corpus has a trace with no PQC half")
        .trace;
    assert_eq!(
        classical_only_check(rt, engine, no_pqc),
        Ok(()),
        "I1569 {who}: the trace with no PQC half carries a valid Ed25519 signature \
         from a registered key, so v61.0.5's classical-only dry-run accepted it"
    );
    assert_eq!(
        dry_run(engine, no_pqc, who),
        Err(("ValueError", "verify_hybrid_required".to_owned())),
        "I1569 {who}: the dry-run now refuses the trace with no PQC half"
    );
}

#[cfg(feature = "sqlite")]
#[test]
fn i1569_verify_trace_gives_ingests_verdict_sqlite() {
    let rt = runtime();
    let dir = tempfile::tempdir().unwrap();
    let dsn = format!("sqlite:///{}", dir.path().join("node.db").display());
    let alias = format!("vt{}", &uuid::Uuid::new_v4().simple().to_string()[..8]);
    let engine = open_from_python(&dsn, &alias, dir.path());
    i1569_assert(&rt, &engine, "sqlite");
}

#[cfg(feature = "postgres")]
#[test]
fn i1569_verify_trace_gives_ingests_verdict_postgres() {
    let Some(dsn) = crate::test_pg::isolated_dsn() else {
        eprintln!("skipping: CIRIS_PERSIST_TEST_PG_URL unset");
        return;
    };
    let rt = runtime();
    let dir = tempfile::tempdir().unwrap();
    let alias = format!("vt{}", &uuid::Uuid::new_v4().simple().to_string()[..8]);
    let engine = open_from_python(&dsn, &alias, dir.path());
    i1569_assert(&rt, &engine, "postgres");
    eprintln!("i1569 postgres: RAN");
}
