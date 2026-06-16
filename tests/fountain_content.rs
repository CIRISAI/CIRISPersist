//! v8.0.0 (CIRISPersist#227) — the fountain content primitive
//! (store-and-evict half), proven on BOTH durable backends (Postgres +
//! SQLite).
//!
//! The `FountainContentV1` contract (RATIFIED + LOCKED on
//! CIRISPersist#227 / CIRISEdge#133): persist stores a small, signed,
//! always-retained manifest + N+K opaque fountain symbols, evicts by
//! tier × `retention_priority`, and returns a typed degraded read
//! (`Full` / `Partial` / `EnvelopeOnly`). persist is store-and-evict
//! ONLY — zero codec crates; the symbols here are SYNTHETIC random bytes
//! with a real hybrid-signed manifest.
//!
//! Project rule (NO pg/sqlite asymmetry): the V084 schema + the admit
//! gate + the eviction policy + the read contract are identical on both
//! backends; only the SQL dialect differs. Each backend runs the SAME
//! shared body.
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
    symbol_sha256_hex, FountainContent, FountainManifestV1, FountainSymbolV1, FountainTier,
    MANIFEST_VERSION_V1,
};
use ciris_persist::store::{Backend, Error as StoreError};
use ciris_persist::verify::PythonJsonDumpsCanonicalizer;

/// Deterministic producer Ed25519 + ML-DSA-65 keys (b64 pubkeys).
fn producer_pubkeys() -> (SigningKey, String, MlDsa65SoftwareSigner) {
    let ed_sk = SigningKey::from_bytes(&[0x11; 32]);
    let ed_pk_b64 = BASE64.encode(ed_sk.verifying_key().to_bytes());
    let mldsa = MlDsa65SoftwareSigner::from_seed_bytes(&[0x22; 32], "fountain-mldsa").unwrap();
    (ed_sk, ed_pk_b64, mldsa)
}

/// Build N+K synthetic symbols (deterministic-but-distinct random bytes)
/// and their SHA-256 hashes, with a per-symbol retention_priority that
/// makes repair symbols (high symbol_id) evict first.
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
        // Distinct deterministic bytes per symbol.
        let bytes: Vec<u8> = (0..symbol_size)
            .map(|b| (symbol_id as u8).wrapping_mul(31).wrapping_add(b as u8))
            .collect();
        hashes.push(symbol_sha256_hex(&bytes));
        // Source symbols keep-longest (low priority); repair evicts
        // first (high priority). symbol_id within each band gives a
        // strict order so the priority-DESC eviction is deterministic.
        let retention_priority = if symbol_id < n_source {
            symbol_id as u8 // 0..n_source: source, lower = keep longest
        } else {
            // repair: strictly above every source priority
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

/// Build + hybrid-sign a manifest. `pqc` toggles the ML-DSA-65 half:
/// `false` ⇒ classical-only (the hard-cut reject case). `corrupt_first`
/// flips a byte in symbol 0's stored bytes AFTER hashing (the AV-9 hash
/// mismatch case).
async fn build_manifest_and_symbols(
    content_id: &str,
    n_source: u32,
    k_repair: u32,
    symbol_size: u32,
    pqc: bool,
) -> (FountainManifestV1, Vec<FountainSymbolV1>) {
    let (ed_sk, ed_pk_b64, mldsa) = producer_pubkeys();
    let (symbols, symbol_hashes) = synth_symbols(content_id, n_source, k_repair, symbol_size);
    let pqc_pk = mldsa.public_key().await.unwrap();

    // The corpus envelope carries the producer pubkeys (bound by the
    // hybrid signature; the admit gate reads them off the envelope).
    let envelope = serde_json::json!({
        "content_id": content_id,
        "pubkey_ed25519": ed_pk_b64,
        "pubkey_ml_dsa_65": BASE64.encode(&pqc_pk),
    });

    let mut manifest = FountainManifestV1 {
        content_id: content_id.to_owned(),
        corpus_kind: "trace".to_owned(),
        manifest_version: MANIFEST_VERSION_V1,
        n_source,
        k_repair,
        symbol_size,
        original_content_length: u64::from(n_source) * u64::from(symbol_size) - 3,
        min_viable_symbols: 2,
        symbol_hashes,
        envelope,
        signature: String::new(),
        signature_ml_dsa_65: String::new(),
        pqc_key_id: "fountain-mldsa".to_owned(),
    };

    // Sign over the LOCKED canonical bytes (excludes the signature
    // fields). Ed25519 over canonical; ML-DSA-65 over (canonical || ed).
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
    // classical-only: leave signature_ml_dsa_65 empty (the hard cut).

    (manifest, symbols)
}

/// The shared body: assertions (a)–(g) against a migrated backend.
/// `suffix` keeps PG content_ids self-isolating across concurrent runs.
async fn run_fountain_assertions<B: Backend>(backend: &B, suffix: &str) {
    let n_source = 8u32;
    let k_repair = 4u32;
    let symbol_size = 16u32;
    let total = n_source + k_repair;
    let corpus = "trace";

    // (a) valid hybrid-signed manifest + N+K symbols → admitted, all
    //     stored.
    let cid = format!("c-valid-{suffix}");
    let (manifest, symbols) =
        build_manifest_and_symbols(&cid, n_source, k_repair, symbol_size, true).await;
    backend
        .put_fountain_content(&manifest, &symbols)
        .await
        .expect("(a) valid hybrid manifest MUST be admitted");

    // (d) read full → Full, all symbols, each hash re-verified on read.
    let content = backend
        .get_fountain_content(&cid, corpus)
        .await
        .expect("(d) read")
        .expect("(d) manifest present");
    match &content {
        FountainContent::Full { symbols, .. } => {
            assert_eq!(symbols.len() as u32, total, "(d) all N+K symbols present");
        }
        other => panic!("(d) expected Full, got {other:?}"),
    }
    assert_eq!(content.present(), total);

    // (b) classical-only manifest (no ML-DSA-65) → REJECTED, zero rows.
    let cid_classical = format!("c-classical-{suffix}");
    let (m_classical, s_classical) =
        build_manifest_and_symbols(&cid_classical, n_source, k_repair, symbol_size, false).await;
    let err = backend
        .put_fountain_content(&m_classical, &s_classical)
        .await
        .expect_err("(b) classical-only MUST be rejected (the #225 hard cut)");
    assert!(
        matches!(err, StoreError::FountainAdmit(_)),
        "(b) reject is a FountainAdmit error, got {err:?}"
    );
    assert_eq!(
        err.kind(),
        "fountain_admit_hybrid_required",
        "(b) the hard-cut token"
    );
    assert!(
        backend
            .get_fountain_content(&cid_classical, corpus)
            .await
            .unwrap()
            .is_none(),
        "(b) rejected classical-only manifest wrote ZERO rows"
    );

    // (c) a symbol whose bytes don't match symbol_hashes → REJECTED,
    //     zero rows (AV-9 verify-before-mutation).
    let cid_corrupt = format!("c-corrupt-{suffix}");
    let (m_corrupt, mut s_corrupt) =
        build_manifest_and_symbols(&cid_corrupt, n_source, k_repair, symbol_size, true).await;
    // Flip a byte in symbol 0 AFTER its hash was committed to the
    // manifest → its SHA-256 no longer matches symbol_hashes[0].
    s_corrupt[0].symbol_bytes[0] ^= 0xFF;
    let err = backend
        .put_fountain_content(&m_corrupt, &s_corrupt)
        .await
        .expect_err("(c) symbol-hash mismatch MUST be rejected (AV-9)");
    assert_eq!(
        err.kind(),
        "fountain_admit_symbol_hash",
        "(c) the per-symbol hash-mismatch token"
    );
    assert!(
        backend
            .get_fountain_content(&cid_corrupt, corpus)
            .await
            .unwrap()
            .is_none(),
        "(c) rejected admission wrote ZERO rows"
    );

    // (e) evict to T2 (keep n_source, drop repair) → read → still Full
    //     (lossless), repair symbols gone, evicted by priority DESC.
    let evicted = backend
        .evict_fountain_content_to_tier(&cid, corpus, FountainTier::T2)
        .await
        .expect("(e) evict T2");
    assert_eq!(evicted, u64::from(k_repair), "(e) T2 drops the K repair");
    let content = backend
        .get_fountain_content(&cid, corpus)
        .await
        .unwrap()
        .unwrap();
    match &content {
        FountainContent::Full { symbols, .. } => {
            assert_eq!(symbols.len() as u32, n_source, "(e) keeps n_source");
            // Repair symbols (symbol_id >= n_source) are the highest
            // retention_priority → evicted first.
            assert!(
                symbols.iter().all(|s| s.symbol_id < n_source),
                "(e) all surviving symbols are SOURCE (repair evicted by priority DESC)"
            );
        }
        other => panic!("(e) T2 must still read Full (lossless), got {other:?}"),
    }

    // (f) evict to T3 (keep between min_viable and n_source) → Partial.
    let _ = backend
        .evict_fountain_content_to_tier(&cid, corpus, FountainTier::T3)
        .await
        .expect("(f) evict T3");
    let content = backend
        .get_fountain_content(&cid, corpus)
        .await
        .unwrap()
        .unwrap();
    match &content {
        FountainContent::Partial {
            present, symbols, ..
        } => {
            assert!(
                *present >= manifest.min_viable_symbols && *present < n_source,
                "(f) Partial present {present} in [min_viable, n_source)"
            );
            assert_eq!(symbols.len() as u32, *present);
        }
        other => panic!("(f) expected Partial, got {other:?}"),
    }

    // (g) evict to T5 → EnvelopeOnly, manifest intact, zero symbols.
    let _ = backend
        .evict_fountain_content_to_tier(&cid, corpus, FountainTier::T5)
        .await
        .expect("(g) evict T5");
    let content = backend
        .get_fountain_content(&cid, corpus)
        .await
        .unwrap()
        .unwrap();
    match &content {
        FountainContent::EnvelopeOnly { manifest } => {
            assert_eq!(manifest.content_id, cid, "(g) manifest intact");
            assert_eq!(manifest.n_source, n_source);
        }
        other => panic!("(g) expected EnvelopeOnly, got {other:?}"),
    }
    assert_eq!(content.present(), 0, "(g) zero symbols survive at T5");
    // The manifest is NEVER evicted — read still resolves.
    assert!(backend
        .get_fountain_content(&cid, corpus)
        .await
        .unwrap()
        .is_some());
}

#[tokio::test]
async fn sqlite_fountain_content() {
    let backend = ciris_persist::store::SqliteBackend::open_in_memory()
        .await
        .expect("open sqlite");
    backend
        .run_migrations()
        .await
        .expect("sqlite migrations (incl. V084)");
    run_fountain_assertions(&backend, "sqlite").await;
}

#[tokio::test]
async fn postgres_fountain_content() {
    let Some(dsn) = std::env::var("CIRIS_PERSIST_TEST_PG_URL").ok() else {
        eprintln!("postgres_fountain_content skipped: CIRIS_PERSIST_TEST_PG_URL unset");
        return;
    };
    let backend = ciris_persist::store::PostgresBackend::connect(&dsn)
        .await
        .expect("connect postgres");
    backend
        .run_migrations()
        .await
        .expect("pg migrations (incl. V084)");
    let suffix = uuid::Uuid::new_v4().simple().to_string();
    run_fountain_assertions(&backend, &suffix).await;
}

/// (h) DiskPressure tier → keep-count mapping (unit test, no backend).
#[tokio::test]
async fn disk_pressure_tier_maps_to_keep_count() {
    use ciris_persist::federation::replication::disk_pressure::PressureTier;
    let (manifest, _symbols) = build_manifest_and_symbols("c-map", 8, 4, 16, true).await;

    // Normal → Full → keep N+K.
    assert_eq!(
        FountainTier::from_pressure(PressureTier::Normal).keep_count(&manifest),
        12
    );
    // Warn → T2 → keep n_source.
    assert_eq!(
        FountainTier::from_pressure(PressureTier::Warn).keep_count(&manifest),
        8
    );
    // Crit → T3 → a partial in [min_viable, n_source).
    let t3 = FountainTier::from_pressure(PressureTier::Crit).keep_count(&manifest);
    assert!((u64::from(manifest.min_viable_symbols)..8).contains(&t3));
    // Stop → T4 → keep min_viable.
    assert_eq!(
        FountainTier::from_pressure(PressureTier::Stop).keep_count(&manifest),
        u64::from(manifest.min_viable_symbols)
    );
    // HostAtRisk → T5 → keep nothing.
    assert_eq!(
        FountainTier::from_pressure(PressureTier::HostAtRisk).keep_count(&manifest),
        0
    );
}
