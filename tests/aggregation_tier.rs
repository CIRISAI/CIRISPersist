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
    aggregate_corpus_kind, member_commitment, symbol_sha256_hex, AggregationMetaV1,
    AggregationMetaVerifyInputsV1, FountainContent, FountainManifestV1, FountainSymbolV1,
    MANIFEST_VERSION_V1,
};
use ciris_persist::store::{Backend, Error as StoreError};
use ciris_persist::verify::PythonJsonDumpsCanonicalizer;
use ciris_verify_core::holonomic::{ConsentState, EjectionVerdict};

/// Build the §19.7.1 verification inputs (the wire fields + a valid
/// bound-hybrid signature) for an aggregation tier. The aggregator IS the
/// composite's producer, so it signs with the SAME deterministic keys
/// [`producer_pubkeys`] puts on the composite envelope. `member_ids` derive the
/// member_commitment via the verify-core construction; returns the inputs and
/// the member-commitment hex (so the stored navigation column matches).
async fn signed_verify_inputs(
    member_ids: &[String],
    tamper: bool,
    drop_pqc: bool,
) -> (AggregationMetaVerifyInputsV1, String) {
    let (ed_sk, _ed_pk_b64, mldsa) = producer_pubkeys();
    let commitment = member_commitment(member_ids);
    let commitment_hex = hex_lower(&commitment);
    let meta = ciris_verify_core::holonomic::AggregationMetaV1 {
        version: 1,
        content_id: "content-root-agg".to_owned(),
        corpus_kind: "trace".to_owned(),
        tier: 2,
        aggregation_algorithm_id: "raptorq-pyramid-v1".to_owned(),
        source_count: member_ids.len() as u32,
        member_commitment: commitment,
        noise_floor_descriptor: "mean+stddev".to_owned(),
    };
    let preimage = meta.signing_preimage();
    let ed_sig = ed_sk.sign(&preimage).to_bytes();
    let mut bound = preimage.clone();
    bound.extend_from_slice(&ed_sig);
    let pqc_sig = mldsa.sign(&bound).await.unwrap();

    // tamper: claim a different tier than what was signed → preimage diverges.
    let signed_tier = if tamper { 99 } else { meta.tier };
    let inputs = AggregationMetaVerifyInputsV1 {
        version: meta.version,
        content_id: meta.content_id.clone(),
        corpus_kind: meta.corpus_kind.clone(),
        tier: signed_tier,
        aggregation_algorithm_id: meta.aggregation_algorithm_id.clone(),
        source_count: meta.source_count,
        member_commitment_hex: commitment_hex.clone(),
        noise_floor_descriptor: meta.noise_floor_descriptor.clone(),
        sig_ed25519_b64: BASE64.encode(ed_sig),
        sig_ml_dsa_65_b64: if drop_pqc {
            String::new()
        } else {
            BASE64.encode(&pqc_sig)
        },
    };
    (inputs, commitment_hex)
}

/// Lowercase hex of raw bytes (test-local; no extra dep).
fn hex_lower(bytes: &[u8]) -> String {
    let mut s = String::with_capacity(bytes.len() * 2);
    for b in bytes {
        s.push_str(&format!("{b:02x}"));
    }
    s
}

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
    // §19.7.1 verification inputs with a VALID bound-hybrid signature; the
    // stored navigation member_commitment MUST equal the signed §19.7.1 one.
    let member_ids: Vec<String> = (0..3).map(|i| format!("member-{i}")).collect();
    let (verif, commitment_hex) = signed_verify_inputs(&member_ids, false, false).await;
    let agg = AggregationMetaV1 {
        aggregate_content_id: agg_cid.clone(),
        source_corpus_kind: source_corpus.to_owned(),
        aggregation_level: 1,
        fan_in: 3,
        member_commitment: commitment_hex.clone(),
        aggregation_meta: opaque_meta.clone(),
        verification: verif,
    };
    backend
        .put_aggregated_tier(&manifest, &symbols, &agg, 1_000)
        .await
        .expect("(a) valid composite + valid §19.7.1 meta MUST be admitted");

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
    assert_eq!(rec.member_commitment, commitment_hex);
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
    let (verif_b, commitment_b) = signed_verify_inputs(&member_ids, false, false).await;
    let agg_bad = AggregationMetaV1 {
        aggregate_content_id: bad_cid.clone(),
        source_corpus_kind: source_corpus.to_owned(),
        aggregation_level: 1,
        fan_in: 3,
        member_commitment: commitment_b,
        aggregation_meta: vec![0xFF],
        verification: verif_b,
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

    // ── (b2) §19.7.1 store-path gate: a valid composite manifest but a
    //         PQC-MISSING aggregation_meta → REJECTED at admission
    //         (aggregation_meta_hybrid_required), ZERO rows. The PQC-mandatory
    //         §10.1.5.1.1 gate — never store-then-quarantine.
    let pqcmiss_cid = format!("agg-pqcmiss-{suffix}");
    let (m_ok, s_ok) = build_manifest_and_symbols(
        &pqcmiss_cid,
        &composite_corpus,
        n_source,
        k_repair,
        symbol_size,
        true, // composite manifest is fully hybrid — only the META lacks PQC
    )
    .await;
    let (verif_nopqc, commitment_nopqc) = signed_verify_inputs(&member_ids, false, true).await;
    let agg_nopqc = AggregationMetaV1 {
        aggregate_content_id: pqcmiss_cid.clone(),
        source_corpus_kind: source_corpus.to_owned(),
        aggregation_level: 1,
        fan_in: 3,
        member_commitment: commitment_nopqc,
        aggregation_meta: vec![0xAB],
        verification: verif_nopqc,
    };
    let err = backend
        .put_aggregated_tier(&m_ok, &s_ok, &agg_nopqc, 2_500)
        .await
        .expect_err("(b2) PQC-missing aggregation_meta MUST be rejected (store-path gate)");
    assert_eq!(
        err.kind(),
        "aggregation_meta_hybrid_required",
        "(b2) PQC-mandatory store-path token"
    );
    assert!(
        backend
            .get_fountain_content(&pqcmiss_cid, &composite_corpus)
            .await
            .unwrap()
            .is_none(),
        "(b2) PQC-missing meta wrote ZERO content_manifest rows (verify-before-mutation)"
    );
    assert!(
        backend
            .get_aggregation(&pqcmiss_cid)
            .await
            .unwrap()
            .is_none(),
        "(b2) PQC-missing meta wrote ZERO content_aggregation rows"
    );

    // ── (b3) §19.7.1 store-path gate: TAMPERED meta — the signed preimage
    //         claims a different tier than the verification inputs assert, so
    //         the bound-hybrid signature does not match → REJECTED, ZERO rows.
    let tamper_cid = format!("agg-tamper-{suffix}");
    let (m_t, s_t) = build_manifest_and_symbols(
        &tamper_cid,
        &composite_corpus,
        n_source,
        k_repair,
        symbol_size,
        true,
    )
    .await;
    let (verif_t, commitment_t) = signed_verify_inputs(&member_ids, true, false).await;
    let agg_t = AggregationMetaV1 {
        aggregate_content_id: tamper_cid.clone(),
        source_corpus_kind: source_corpus.to_owned(),
        aggregation_level: 1,
        fan_in: 3,
        member_commitment: commitment_t,
        aggregation_meta: vec![0xCD],
        verification: verif_t,
    };
    let err = backend
        .put_aggregated_tier(&m_t, &s_t, &agg_t, 2_700)
        .await
        .expect_err("(b3) tampered aggregation_meta MUST be rejected (sig != preimage)");
    assert_eq!(
        err.kind(),
        "aggregation_meta_hybrid_required",
        "(b3) tampered meta token"
    );
    assert!(
        backend
            .get_aggregation(&tamper_cid)
            .await
            .unwrap()
            .is_none(),
        "(b3) tampered meta wrote ZERO content_aggregation rows"
    );

    // ── (c) descent integrity (§19.7.1.1) + verdict (§19.7.3): fold 3 sources
    //        into a composite whose member_commitment is over the source ids.
    //        A FORGED source set is REJECTED; the MATCHING set descends to the
    //        floor (Withdrawn → hard-delete) → each reads EnvelopeOnly; the
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
    // The fold's composite commits to EXACTLY these source content_ids.
    let fold_cid = format!("agg-fold-{suffix}");
    let fold_member_ids: Vec<String> = source_ids.iter().map(|(id, _)| id.clone()).collect();
    let (fold_verif, fold_commitment) = signed_verify_inputs(&fold_member_ids, false, false).await;
    let (fm, fs) = build_manifest_and_symbols(
        &fold_cid,
        &composite_corpus,
        n_source,
        k_repair,
        symbol_size,
        true,
    )
    .await;
    let fold_agg = AggregationMetaV1 {
        aggregate_content_id: fold_cid.clone(),
        source_corpus_kind: source_corpus.to_owned(),
        aggregation_level: 1,
        fan_in: 3,
        member_commitment: fold_commitment,
        aggregation_meta: vec![0x42],
        verification: fold_verif,
    };
    backend
        .put_aggregated_tier(&fm, &fs, &fold_agg, 1_500)
        .await
        .expect("(c) admit fold composite");

    // (c-forged) a source set NOT matching the commitment is REJECTED — a
    // forged member set can't drive eviction (§19.7.1.1).
    let forged: Vec<(String, String)> = vec![(format!("EVIL-{suffix}"), source_corpus.to_owned())];
    let forged_err = ciris_persist::fountain::descend_aggregated_sources_on_backend(
        backend,
        &fold_cid,
        &forged,
        ConsentState::Withdrawn,
        false,
        None,
    )
    .await
    .expect_err("(c) a forged member set MUST be rejected (descent integrity)");
    assert_eq!(
        forged_err.kind(),
        "aggregation_meta_member_commitment",
        "(c) forged-set descent token"
    );
    // The sources are untouched by the rejected descent.
    for (cid, corpus) in &source_ids {
        let read = backend
            .get_fountain_content(cid, corpus)
            .await
            .unwrap()
            .unwrap();
        assert!(
            matches!(read, FountainContent::Full { .. }),
            "(c) forged-set rejection leaves sources Full (verify-before-mutation)"
        );
    }

    // (c-matching) the MATCHING source set descends. Withdrawn → hard-delete
    // (the §19.7.3 N5 verdict — never tier-shed).
    let total_evicted = ciris_persist::fountain::descend_aggregated_sources_on_backend(
        backend,
        &fold_cid,
        &source_ids,
        ConsentState::Withdrawn,
        false,
        None,
    )
    .await
    .expect("(c) matching source set descends");
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
        let (v, c) = signed_verify_inputs(&member_ids, false, false).await;
        let a = AggregationMetaV1 {
            aggregate_content_id: cid.clone(),
            source_corpus_kind: source_corpus.to_owned(),
            aggregation_level: 2,
            fan_in: 4,
            member_commitment: c,
            aggregation_meta: vec![0x10],
            verification: v,
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
    let (raw_v, raw_c) = signed_verify_inputs(&member_ids, false, false).await;
    let raw_agg = AggregationMetaV1 {
        aggregate_content_id: raw_cid.clone(),
        source_corpus_kind: source_corpus.to_owned(),
        aggregation_level: 3,
        fan_in: 9,
        member_commitment: raw_c,
        aggregation_meta: raw_meta.clone(),
        verification: raw_v,
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

    // ── (f) §19.7.3 EjectionVerdict alignment (verify-core's verdict drives
    //        the persist action): Withdrawn → hard-delete regardless of
    //        pressure; capacity pressure on a live item → tier-shed; else Keep.
    use ciris_persist::fountain::{ejection_verdict, EjectionAction, FountainTier};
    assert_eq!(
        ejection_verdict(ConsentState::Withdrawn, false),
        EjectionVerdict::EjectHardDelete,
        "(f) revoked → hard delete (N5)"
    );
    assert_eq!(
        ejection_verdict(ConsentState::Withdrawn, true),
        EjectionVerdict::EjectHardDelete,
        "(f) revoked under pressure → still hard delete (never tier-shed)"
    );
    assert_eq!(
        EjectionAction::from_verdict(
            ejection_verdict(ConsentState::Active, true),
            Some(FountainTier::T3)
        ),
        EjectionAction::EjectToTier(FountainTier::T3),
        "(f) live + pressure → tier-shed to the persist target"
    );
    assert_eq!(
        EjectionAction::from_verdict(ejection_verdict(ConsentState::Active, false), None),
        EjectionAction::Keep,
        "(f) live + no pressure → keep"
    );

    // ── (g) §19.7.3 tier-granular stratum-shed (v8.6.0, verify v5.11.0):
    //        build a 3-level pyramid (tiers 0/1/2 content_aggregation
    //        composites, each with its OWN symbols). evict_aggregated_tier(.., 1)
    //        sheds EXACTLY the tier-1 composite's symbols (reads EnvelopeOnly)
    //        while tier-0 AND tier-2 composites stay intact (read Full); the
    //        tier-1 manifest survives.
    let mut pyramid_cids: Vec<(u32, String)> = Vec::with_capacity(3);
    for level in 0u32..=2 {
        let cid = format!("pyramid-t{level}-{suffix}");
        let (m, s) = build_manifest_and_symbols(
            &cid,
            &composite_corpus,
            n_source,
            k_repair,
            symbol_size,
            true,
        )
        .await;
        // Each stratum has its own member set + valid §19.7.1 meta.
        let members: Vec<String> = (0..3)
            .map(|i| format!("g-t{level}-m{i}-{suffix}"))
            .collect();
        let (gverif, gcommit) = signed_verify_inputs(&members, false, false).await;
        let a = AggregationMetaV1 {
            aggregate_content_id: cid.clone(),
            source_corpus_kind: source_corpus.to_owned(),
            aggregation_level: u64::from(level),
            fan_in: 3,
            member_commitment: gcommit,
            aggregation_meta: vec![0x10 + level as u8],
            verification: gverif,
        };
        backend
            .put_aggregated_tier(&m, &s, &a, 20_000 + i64::from(level))
            .await
            .expect("(g) pyramid stratum admitted");
        pyramid_cids.push((level, cid));
    }
    // Pre-condition: all three strata read Full.
    for (level, cid) in &pyramid_cids {
        let read = backend
            .get_fountain_content(cid, &composite_corpus)
            .await
            .unwrap()
            .unwrap();
        assert!(
            matches!(read, FountainContent::Full { .. }),
            "(g) tier-{level} composite starts Full"
        );
    }
    let tier1_cid = pyramid_cids[1].1.clone();

    use ciris_persist::fountain::evict_aggregated_tier_on_backend;

    // Stratum-guard: a wrong-level request sheds NOTHING (no-op).
    let wrong = evict_aggregated_tier_on_backend(backend, &tier1_cid, 2)
        .await
        .expect("(g) wrong-level request runs");
    assert_eq!(wrong, 0, "(g) wrong tier (2 vs stored 1) sheds nothing");
    assert!(
        matches!(
            backend
                .get_fountain_content(&tier1_cid, &composite_corpus)
                .await
                .unwrap()
                .unwrap(),
            FountainContent::Full { .. }
        ),
        "(g) wrong-level no-op left tier-1 Full"
    );

    // Shed EXACTLY the tier-1 stratum.
    let shed = evict_aggregated_tier_on_backend(backend, &tier1_cid, 1)
        .await
        .expect("(g) tier-1 stratum-shed runs");
    assert!(shed > 0, "(g) tier-1 stratum-shed dropped its symbols");

    // tier-1 composite now reads EnvelopeOnly; its manifest survives.
    let t1_read = backend
        .get_fountain_content(&tier1_cid, &composite_corpus)
        .await
        .unwrap()
        .unwrap();
    assert!(
        matches!(t1_read, FountainContent::EnvelopeOnly { .. }),
        "(g) shed tier-1 composite reads EnvelopeOnly (symbols gone, manifest survives)"
    );
    assert!(
        backend.get_aggregation(&tier1_cid).await.unwrap().is_some(),
        "(g) tier-1 aggregation manifest/record survives the stratum-shed"
    );

    // tier-0 (finer) AND tier-2 (coarser) composites stay intact.
    for (level, cid) in &pyramid_cids {
        if *level == 1 {
            continue;
        }
        let read = backend
            .get_fountain_content(cid, &composite_corpus)
            .await
            .unwrap()
            .unwrap();
        assert!(
            matches!(read, FountainContent::Full { .. }),
            "(g) tier-{level} composite intact after shedding tier-1 (finer+coarser untouched)"
        );
    }

    // Composes with hard-delete: re-shedding the already-erased stratum is a
    // no-op (never resurrects erased content); unknown composite → 0.
    let reshed = evict_aggregated_tier_on_backend(backend, &tier1_cid, 1)
        .await
        .unwrap();
    assert_eq!(reshed, 0, "(g) re-shed already-erased stratum is a no-op");
    let unknown = evict_aggregated_tier_on_backend(backend, &format!("nope-{suffix}"), 1)
        .await
        .unwrap();
    assert_eq!(
        unknown, 0,
        "(g) unknown composite → no-op (no resurrection)"
    );

    // ── (h) §19.7.3 verdict mapping for the new variant: verify-core's
    //        EjectAggregatedTierOnly { tier } → EjectionAction::
    //        EjectAggregatedTierOnly(tier), carrying the right tier; target_tier
    //        is irrelevant (it's a stratum index, not a fidelity tier).
    assert_eq!(
        EjectionAction::from_verdict(EjectionVerdict::EjectAggregatedTierOnly { tier: 1 }, None,),
        EjectionAction::EjectAggregatedTierOnly(1),
        "(h) variant maps tier-for-tier with target_tier=None"
    );
    assert_eq!(
        EjectionAction::from_verdict(
            EjectionVerdict::EjectAggregatedTierOnly { tier: 7 },
            Some(FountainTier::T3),
        ),
        EjectionAction::EjectAggregatedTierOnly(7),
        "(h) stratum index is preserved, target_tier ignored"
    );
    assert_eq!(
        EjectionAction::EjectAggregatedTierOnly(1).label(),
        "eject_aggregated_tier_only",
        "(h) stable telemetry label"
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
