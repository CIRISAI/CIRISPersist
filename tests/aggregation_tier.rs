//! v8.3.0 (CEG 1.0-RC12 §19.7 / CIRISPersist#230) — the §19.7 inter-object
//! aggregation storage slice (forever-memory pyramid), proven on BOTH
//! durable backends (Postgres + SQLite).
//!
//! §19.7 operator 2: N source items → 1 composite, recursed into a mipmap
//! pyramid → O(log T) forever-memory. persist is CODEC-FREE — the N→1
//! resampling is edge-side; persist stores the composite (a
//! FountainContentV1 via the EXISTING #225 hybrid admit gate) + records the
//! aggregation provenance with the §19.7 wire payload kept OPAQUE
//! (`aggregation_meta` — persist never parses it; the wire-churn firewall).
//!
//! Project rule (NO pg/sqlite asymmetry): the V086 schema + the admit
//! reuse + the navigation reads are identical on both backends; only the
//! SQL dialect differs. Each backend runs the SAME shared body.
//!
//! - Postgres is gated on `CIRIS_PERSIST_TEST_PG_URL` (plain
//!   `postgres:16`), self-isolating via uuid-suffixed content_ids.
//! - SQLite uses an in-memory database.

#![cfg(all(feature = "postgres", feature = "sqlite"))]

use base64::engine::general_purpose::STANDARD as BASE64;
use base64::Engine as _;
use ciris_keyring::{MlDsa65SoftwareSigner, PqcSigner};
use ed25519_dalek::{Signer as _, SigningKey};

use ciris_persist::fountain::{
    aggregate_corpus_kind, symbol_sha256_hex, AggregationMetaV1, FountainContent,
    FountainManifestV1, FountainSymbolV1, MANIFEST_VERSION_V1,
};
use ciris_persist::store::{Backend, Error as StoreError};
use ciris_persist::verify::PythonJsonDumpsCanonicalizer;

/// Deterministic producer Ed25519 + ML-DSA-65 keys.
fn producer_pubkeys() -> (SigningKey, String, MlDsa65SoftwareSigner) {
    let ed_sk = SigningKey::from_bytes(&[0x33; 32]);
    let ed_pk_b64 = BASE64.encode(ed_sk.verifying_key().to_bytes());
    let mldsa = MlDsa65SoftwareSigner::from_seed_bytes(&[0x44; 32], "agg-mldsa").unwrap();
    (ed_sk, ed_pk_b64, mldsa)
}

/// Build N+K synthetic symbols + their SHA-256 hashes.
fn synth_symbols(
    content_id: &str,
    n_source: u32,
    k_repair: u32,
    symbol_size: u32,
) -> (Vec<FountainSymbolV1>, Vec<String>) {
    let total = n_source + k_repair;
    let mut symbols = Vec::with_capacity(total as usize);
    let mut hashes = Vec::with_capacity(total as usize);
    for symbol_id in 0..total {
        let bytes: Vec<u8> = (0..symbol_size)
            .map(|b| (symbol_id as u8).wrapping_mul(17).wrapping_add(b as u8))
            .collect();
        hashes.push(symbol_sha256_hex(&bytes));
        let retention_priority = if symbol_id < n_source {
            symbol_id as u8
        } else {
            (n_source as u8).saturating_add((symbol_id - n_source) as u8)
        };
        symbols.push(FountainSymbolV1 {
            content_id: content_id.to_owned(),
            symbol_id,
            retention_priority,
            symbol_bytes: bytes,
        });
    }
    (symbols, hashes)
}

/// Build + hybrid-sign a manifest. `corpus_kind` lets callers build either
/// a source content (`"trace"`) or a composite (`"aggregate:trace"`).
/// `pqc=false` ⇒ classical-only (the hard-cut reject case).
async fn build_manifest_and_symbols(
    content_id: &str,
    corpus_kind: &str,
    n_source: u32,
    k_repair: u32,
    symbol_size: u32,
    pqc: bool,
) -> (FountainManifestV1, Vec<FountainSymbolV1>) {
    let (ed_sk, ed_pk_b64, mldsa) = producer_pubkeys();
    let (symbols, symbol_hashes) = synth_symbols(content_id, n_source, k_repair, symbol_size);
    let pqc_pk = mldsa.public_key().await.unwrap();

    let envelope = serde_json::json!({
        "content_id": content_id,
        "pubkey_ed25519": ed_pk_b64,
        "pubkey_ml_dsa_65": BASE64.encode(&pqc_pk),
    });

    let mut manifest = FountainManifestV1 {
        content_id: content_id.to_owned(),
        corpus_kind: corpus_kind.to_owned(),
        manifest_version: MANIFEST_VERSION_V1,
        n_source,
        k_repair,
        symbol_size,
        original_content_length: u64::from(n_source) * u64::from(symbol_size) - 2,
        min_viable_symbols: 2,
        symbol_hashes,
        envelope,
        signature: String::new(),
        signature_ml_dsa_65: String::new(),
        pqc_key_id: "agg-mldsa".to_owned(),
    };

    let canonical = manifest
        .canonical_bytes(&PythonJsonDumpsCanonicalizer)
        .unwrap();
    let ed_sig = ed_sk.sign(&canonical).to_bytes();
    manifest.signature = BASE64.encode(ed_sig);
    if pqc {
        let mut bound = Vec::with_capacity(canonical.len() + ed_sig.len());
        bound.extend_from_slice(&canonical);
        bound.extend_from_slice(&ed_sig);
        let pqc_sig = mldsa.sign(&bound).await.unwrap();
        manifest.signature_ml_dsa_65 = BASE64.encode(&pqc_sig);
    }
    (manifest, symbols)
}

/// The shared body: assertions (a)–(e) against a migrated backend.
async fn run_aggregation_assertions<B: Backend>(backend: &B, suffix: &str) {
    let n_source = 6u32;
    let k_repair = 3u32;
    let symbol_size = 12u32;
    let total = n_source + k_repair;
    let source_corpus = "trace";
    let composite_corpus = aggregate_corpus_kind(source_corpus); // "aggregate:trace"

    // ── (a) admit an aggregate composite (hybrid-signed manifest +
    //        symbols + opaque meta) → stored; the content_aggregation row +
    //        opaque aggregation_meta round-trip byte-for-byte.
    let agg_cid = format!("agg-1-{suffix}");
    let (manifest, symbols) = build_manifest_and_symbols(
        &agg_cid,
        &composite_corpus,
        n_source,
        k_repair,
        symbol_size,
        true,
    )
    .await;
    // Opaque §19.7 wire payload — arbitrary bytes persist never parses.
    let opaque_meta = vec![0x01u8, 0x02, 0x03, 0xAA, 0xBB];
    let agg = AggregationMetaV1 {
        aggregate_content_id: agg_cid.clone(),
        source_corpus_kind: source_corpus.to_owned(),
        aggregation_level: 1,
        fan_in: 3,
        member_commitment: "feedface".to_owned(),
        aggregation_meta: opaque_meta.clone(),
    };
    backend
        .put_aggregated_tier(&manifest, &symbols, &agg, 1_000)
        .await
        .expect("(a) valid composite + aggregation MUST be admitted");

    // The composite is a FountainContentV1 — readable as Full.
    let composite = backend
        .get_fountain_content(&agg_cid, &composite_corpus)
        .await
        .expect("(a) read composite")
        .expect("(a) composite manifest present");
    assert!(
        matches!(composite, FountainContent::Full { .. }),
        "(a) composite reads Full"
    );

    // The aggregation record round-trips, opaque meta byte-for-byte.
    let rec = backend
        .get_aggregation(&agg_cid)
        .await
        .expect("(a) get_aggregation")
        .expect("(a) aggregation record present");
    assert_eq!(rec.aggregate_content_id, agg_cid);
    assert_eq!(rec.source_corpus_kind, source_corpus);
    assert_eq!(rec.aggregation_level, 1);
    assert_eq!(rec.fan_in, 3);
    assert_eq!(rec.member_commitment, "feedface");
    assert_eq!(rec.aggregated_at_unix_ms, 1_000);
    assert_eq!(
        rec.aggregation_meta, opaque_meta,
        "(a) opaque aggregation_meta round-trips byte-for-byte"
    );

    // ── (b) classical-only composite manifest → REJECTED (the composite
    //        still goes through the #225 hard cut), zero rows written.
    let bad_cid = format!("agg-classical-{suffix}");
    let (m_bad, s_bad) = build_manifest_and_symbols(
        &bad_cid,
        &composite_corpus,
        n_source,
        k_repair,
        symbol_size,
        false, // classical-only
    )
    .await;
    let agg_bad = AggregationMetaV1 {
        aggregate_content_id: bad_cid.clone(),
        source_corpus_kind: source_corpus.to_owned(),
        aggregation_level: 1,
        fan_in: 3,
        member_commitment: "00".to_owned(),
        aggregation_meta: vec![0xFF],
    };
    let err = backend
        .put_aggregated_tier(&m_bad, &s_bad, &agg_bad, 2_000)
        .await
        .expect_err("(b) classical-only composite MUST be rejected (#225 hard cut)");
    assert!(
        matches!(err, StoreError::FountainAdmit(_)),
        "(b) reject is a FountainAdmit error, got {err:?}"
    );
    assert_eq!(
        err.kind(),
        "fountain_admit_hybrid_required",
        "(b) hard-cut token"
    );
    // verify-before-mutation: NOTHING written — neither composite nor row.
    assert!(
        backend
            .get_fountain_content(&bad_cid, &composite_corpus)
            .await
            .unwrap()
            .is_none(),
        "(b) rejected composite wrote ZERO content_manifest rows"
    );
    assert!(
        backend.get_aggregation(&bad_cid).await.unwrap().is_none(),
        "(b) rejected composite wrote ZERO content_aggregation rows"
    );

    // ── (c) descend_aggregated_sources: fold 3 sources → descend them to
    //        the floor (hard_delete) → each reads EnvelopeOnly; the
    //        AGGREGATE is untouched (blur persists).
    let mut source_ids = Vec::new();
    for i in 0..3 {
        let scid = format!("src-{i}-{suffix}");
        let (sm, ss) =
            build_manifest_and_symbols(&scid, source_corpus, n_source, k_repair, symbol_size, true)
                .await;
        backend
            .put_fountain_content(&sm, &ss)
            .await
            .expect("(c) admit source");
        source_ids.push((scid, source_corpus.to_owned()));
    }
    // Descend to the FLOOR (None ⇒ hard-delete each source).
    let verdict = ciris_persist::fountain::EjectionVerdict::for_target_tier(None);
    assert_eq!(
        verdict,
        ciris_persist::fountain::EjectionVerdict::EjectHardDelete,
        "(c) None target maps to the floor verdict"
    );
    let mut total_evicted = 0u64;
    for (cid, corpus) in &source_ids {
        total_evicted += backend
            .evict_fountain_content_hard_delete(cid, corpus)
            .await
            .expect("(c) descend source to floor");
    }
    assert_eq!(
        total_evicted,
        u64::from(total) * 3,
        "(c) all source symbols descended below the floor"
    );
    for (cid, corpus) in &source_ids {
        let read = backend
            .get_fountain_content(cid, corpus)
            .await
            .unwrap()
            .unwrap();
        assert!(
            matches!(read, FountainContent::EnvelopeOnly { .. }),
            "(c) source survives as EnvelopeOnly (existed; folded into the aggregate)"
        );
    }
    // The aggregate (collective blur) is NEVER touched — descent never
    // terminates at zero.
    let blur = backend
        .get_fountain_content(&agg_cid, &composite_corpus)
        .await
        .unwrap()
        .unwrap();
    assert!(
        matches!(blur, FountainContent::Full { .. }),
        "(c) the composite blur persists Full — descent never terminates at zero"
    );
    assert!(
        backend.get_aggregation(&agg_cid).await.unwrap().is_some(),
        "(c) the aggregation record persists"
    );

    // ── (d) pyramid navigation: list_aggregations_at_level returns the
    //        level's records ordered (by aggregated_at_unix_ms ASC).
    let l2_a = format!("agg-l2-a-{suffix}");
    let l2_b = format!("agg-l2-b-{suffix}");
    for (cid, ts) in [(&l2_a, 5_000i64), (&l2_b, 4_000i64)] {
        let (m, s) = build_manifest_and_symbols(
            cid,
            &composite_corpus,
            n_source,
            k_repair,
            symbol_size,
            true,
        )
        .await;
        let a = AggregationMetaV1 {
            aggregate_content_id: cid.clone(),
            source_corpus_kind: source_corpus.to_owned(),
            aggregation_level: 2,
            fan_in: 4,
            member_commitment: "abcd".to_owned(),
            aggregation_meta: vec![0x10],
        };
        backend
            .put_aggregated_tier(&m, &s, &a, ts)
            .await
            .expect("(d) admit level-2 aggregate");
    }
    let level2 = backend
        .list_aggregations_at_level(2, 10_000)
        .await
        .expect("(d) list level 2");
    // `list_aggregations_at_level` is level-filtered, not run-filtered, and
    // the PG corpus is shared across test runs — so scope the exact-order
    // assertion to THIS run's suffix (and use a generous limit so prior
    // runs' level-2 rows can't push ours past the cap). Self-isolating.
    let ids_l2: Vec<&str> = level2
        .iter()
        .map(|r| r.aggregate_content_id.as_str())
        .filter(|id| id.ends_with(suffix))
        .collect();
    assert_eq!(
        ids_l2,
        vec![l2_b.as_str(), l2_a.as_str()],
        "(d) level-2 records ordered by aggregated_at_unix_ms ASC (4000 before 5000)"
    );
    assert!(
        level2.iter().all(|r| r.aggregation_level == 2),
        "(d) only level-2 records returned"
    );
    // The level-1 aggregate (a) is NOT in the level-2 listing.
    let level1 = backend
        .list_aggregations_at_level(1, 100)
        .await
        .expect("(d) list level 1");
    assert!(
        level1.iter().any(|r| r.aggregate_content_id == agg_cid),
        "(d) the level-1 aggregate is in the level-1 listing"
    );

    // ── (e) opaque-meta is never parsed — store arbitrary NON-JSON,
    //        non-UTF-8 bytes and confirm they round-trip unchanged.
    let raw_cid = format!("agg-raw-{suffix}");
    let (rm, rs) = build_manifest_and_symbols(
        &raw_cid,
        &composite_corpus,
        n_source,
        k_repair,
        symbol_size,
        true,
    )
    .await;
    let raw_meta: Vec<u8> = vec![0x00, 0xFF, 0x80, 0x7F, 0xFE, 0x01, 0x00, 0xC0, 0x80];
    let raw_agg = AggregationMetaV1 {
        aggregate_content_id: raw_cid.clone(),
        source_corpus_kind: source_corpus.to_owned(),
        aggregation_level: 3,
        fan_in: 9,
        member_commitment: "ff00".to_owned(),
        aggregation_meta: raw_meta.clone(),
    };
    backend
        .put_aggregated_tier(&rm, &rs, &raw_agg, 9_000)
        .await
        .expect("(e) admit composite with raw opaque meta");
    let back = backend.get_aggregation(&raw_cid).await.unwrap().unwrap();
    assert_eq!(
        back.aggregation_meta, raw_meta,
        "(e) arbitrary non-UTF-8 opaque bytes round-trip unchanged (never parsed)"
    );
}

#[tokio::test]
async fn sqlite_aggregation_tier() {
    let backend = ciris_persist::store::SqliteBackend::open_in_memory()
        .await
        .expect("open sqlite");
    backend
        .run_migrations()
        .await
        .expect("sqlite migrations (incl. V086)");
    run_aggregation_assertions(&backend, "sqlite").await;
}

#[tokio::test]
async fn postgres_aggregation_tier() {
    let Some(dsn) = std::env::var("CIRIS_PERSIST_TEST_PG_URL").ok() else {
        eprintln!("postgres_aggregation_tier skipped: CIRIS_PERSIST_TEST_PG_URL unset");
        return;
    };
    let backend = ciris_persist::store::PostgresBackend::connect(&dsn)
        .await
        .expect("connect postgres");
    backend
        .run_migrations()
        .await
        .expect("pg migrations (incl. V086)");
    let suffix = uuid::Uuid::new_v4().simple().to_string();
    run_aggregation_assertions(&backend, &suffix).await;
}
