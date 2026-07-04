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

use ciris_persist::fountain::storage_contention::{
    assemble_storage_budget_wire, storage_budget_preimage, verify_storage_budget_wire,
    InstalledStorageBudget,
};
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

/// §Q B6/N5 (CIRISPersist#359): build + VERIFY a signed `StorageBudgetV1`
/// bound to `node_id` whose `pinned_class` covers `corpus_kind` with a
/// non-zero `pin_reserve_bytes`. Returns the verified wire JSON. This proves
/// a *valid, aggregator-signed* pin advertisement covering the subject_kind
/// exists — the exact state B6 says must NOT shield content from revocation.
/// (#370: section (k) additionally INSTALLS one as durable pin state.)
async fn build_and_verify_trace_pin(corpus_kind: &str, node_id: &str) -> String {
    let (ed_sk, ed_pk_b64, mldsa) = producer_pubkeys();
    let mldsa_pk_b64 = BASE64.encode(mldsa.public_key().await.unwrap());

    // A budget that PINS `corpus_kind` (in pinned_class) with a real byte
    // reserve — i.e. the strongest pin the §Q surface can express.
    let payload = format!(
        r#"{{"node_id":"{node_id}","epoch_id":"e1","revision":1,
            "scopes":[{{"cohort_scope":"community","budget_bytes":100000,"pin_reserve_bytes":50000}}],
            "pinned_class":["{corpus_kind}"]}}"#
    );

    // Bound-hybrid sign: Ed25519 over the preimage, ML-DSA-65 over
    // (preimage || ed_sig) — the same shape the engine's signer emits.
    let preimage = storage_budget_preimage(&payload).expect("valid pin payload");
    let ed_sig = ed_sk.sign(&preimage).to_bytes();
    let mut bound = preimage.clone();
    bound.extend_from_slice(&ed_sig);
    let pqc_sig = mldsa.sign(&bound).await.unwrap();
    let wire =
        assemble_storage_budget_wire(&payload, BASE64.encode(ed_sig), BASE64.encode(&pqc_sig))
            .expect("assemble signed budget");

    // The pin is genuinely valid (PQC-mandatory bound-hybrid verifies).
    verify_storage_budget_wire(&wire, &ed_pk_b64, &mldsa_pk_b64)
        .expect("(j) the pin advertisement is a valid, verified StorageBudgetV1");
    wire
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

    // (i) N5 (CEG 1.0-RC11 §19 / #228): revocation HardDelete overrides
    //     rarity. A FRESH content whose source symbols carry the
    //     keep-longest retention_priority (exactly what a high rarity
    //     score would set to protect content) is still fully dropped by
    //     the revocation path — `evict_fountain_content_hard_delete` never
    //     consults retention_priority, so no rarity reweight can resurrect
    //     a revoked content. The §8.1.11.3 deletion-SLA always wins.
    let rcid = format!("c-revoke-{suffix}");
    let (rman, rsyms) =
        build_manifest_and_symbols(&rcid, n_source, k_repair, symbol_size, true).await;
    backend
        .put_fountain_content(&rman, &rsyms)
        .await
        .expect("(i) admit revocable content");
    assert!(
        matches!(
            backend.get_fountain_content(&rcid, corpus).await.unwrap(),
            Some(FountainContent::Full { .. })
        ),
        "(i) full before revoke"
    );
    let dropped = backend
        .evict_fountain_content_hard_delete(&rcid, corpus)
        .await
        .expect("(i) hard delete");
    assert_eq!(
        dropped,
        u64::from(total),
        "(i) HardDelete drops ALL symbols regardless of retention_priority"
    );
    let revoked = backend
        .get_fountain_content(&rcid, corpus)
        .await
        .unwrap()
        .unwrap();
    assert!(
        matches!(revoked, FountainContent::EnvelopeOnly { .. }),
        "(i) revoked content → EnvelopeOnly regardless of priority/rarity, got {revoked:?}"
    );
    assert_eq!(
        revoked.present(),
        0,
        "(i) zero symbols survive revocation HardDelete"
    );

    // (j) §Q B6/N5 (CIRISPersist#359): PINNING NEVER DEFEATS REVOCATION.
    //     A *verified*, aggregator-signed StorageBudgetV1 whose pinned_class
    //     covers `corpus` ("trace") with pin_reserve_bytes > 0 does NOT shield
    //     that content from hard-delete. Here the pin is a verified-at-ingest
    //     ADVERTISEMENT only (never installed — the #359 thin form); as of
    //     #370 durable pin STATE exists too, and section (k) below proves the
    //     INSTALLED form is equally powerless against revocation. Either way,
    //     evict_fountain_content_hard_delete has no §Q pin parameter and
    //     reads no pin state, so a pin structurally cannot reach the deletion
    //     path. B6: a pin holds content above the floor against CAPACITY
    //     pressure only, never against revocation.
    let pin_wire = build_and_verify_trace_pin(corpus, "n-pin").await;
    assert!(
        pin_wire.contains(corpus),
        "(j) the verified pin advertisement covers the subject_kind being revoked"
    );
    let pcid = format!("c-pinned-revoke-{suffix}");
    let (pman, psyms) =
        build_manifest_and_symbols(&pcid, n_source, k_repair, symbol_size, true).await;
    backend
        .put_fountain_content(&pman, &psyms)
        .await
        .expect("(j) admit pinned-class content");
    assert!(
        matches!(
            backend.get_fountain_content(&pcid, corpus).await.unwrap(),
            Some(FountainContent::Full { .. })
        ),
        "(j) full before revoke, despite the pin"
    );
    // Revocation runs unconditionally — the pin over `corpus` is never
    // consulted (the delete takes only content_id + corpus_kind).
    let pdropped = backend
        .evict_fountain_content_hard_delete(&pcid, corpus)
        .await
        .expect("(j) hard delete over pinned class");
    assert_eq!(
        pdropped,
        u64::from(total),
        "(j) HardDelete drops ALL symbols even when a valid pin covers the class"
    );
    let pin_revoked = backend
        .get_fountain_content(&pcid, corpus)
        .await
        .unwrap()
        .unwrap();
    assert_eq!(
        pin_revoked.present(),
        0,
        "(j) pinning never defeats revocation — zero symbols survive (§Q B6)"
    );
    assert!(
        matches!(pin_revoked, FountainContent::EnvelopeOnly { .. }),
        "(j) pinned content → EnvelopeOnly after revocation, got {pin_revoked:?}"
    );

    // (k) §Q B6 with INSTALLED pin state (CIRISPersist#370): the pin-install
    //     surface persists REAL pin state now (V092 storage_budget_installed
    //     — the state the B5 capacity sweep honors), and revocation STILL
    //     runs unconditionally: `evict_fountain_content_hard_delete` takes
    //     only (content_id, corpus_kind) and reads no §Q state, so even an
    //     installed, reserve-backed pin covering the class cannot shield it.
    //     This is the staging the conformance B6 test wants: install a pin,
    //     then prove revocation defeats it.
    let pin_node = format!("n-pin-{suffix}");
    let installed_wire = build_and_verify_trace_pin(corpus, &pin_node).await;
    let installed = InstalledStorageBudget::from_wire_json(&installed_wire, chrono::Utc::now())
        .expect("(k) verified wire denormalizes");
    assert!(
        backend
            .put_installed_storage_budget(&installed)
            .await
            .expect("(k) install pin state"),
        "(k) a fresh node_id installs"
    );
    // Read-back: the installed row is live pin state covering `corpus`.
    let got = backend
        .get_installed_storage_budget(&pin_node)
        .await
        .expect("(k) getter")
        .expect("(k) installed row present");
    assert_eq!(got.revision, 1);
    assert!(
        got.pinned_class.iter().any(|c| c == corpus),
        "(k) the installed pin covers the subject_kind being revoked"
    );
    assert!(got.pin_reserve_total() > 0, "(k) a real byte reserve");
    // §Q B3 anti-rollback at the row: an equal revision is refused.
    assert!(
        !backend
            .put_installed_storage_budget(&installed)
            .await
            .expect("(k) re-put"),
        "(k) equal revision refused (B3 anti-rollback)"
    );
    // Admit content of the PINNED class, then revoke — the INSTALLED pin
    // must not shield it.
    let kcid = format!("c-installed-pin-revoke-{suffix}");
    let (kman, ksyms) =
        build_manifest_and_symbols(&kcid, n_source, k_repair, symbol_size, true).await;
    backend
        .put_fountain_content(&kman, &ksyms)
        .await
        .expect("(k) admit installed-pinned-class content");
    let kdropped = backend
        .evict_fountain_content_hard_delete(&kcid, corpus)
        .await
        .expect("(k) hard delete over INSTALLED pinned class");
    assert_eq!(
        kdropped,
        u64::from(total),
        "(k) HardDelete drops ALL symbols even under an INSTALLED pin (§Q B6)"
    );
    assert_eq!(
        backend
            .get_fountain_content(&kcid, corpus)
            .await
            .unwrap()
            .expect("(k) manifest survives as EnvelopeOnly")
            .present(),
        0,
        "(k) installed pinning never defeats revocation — zero symbols survive"
    );
    // The pin state itself is untouched by the revocation (the two paths
    // never meet): the row is still installed.
    assert!(
        backend
            .get_installed_storage_budget(&pin_node)
            .await
            .unwrap()
            .is_some(),
        "(k) revocation neither consulted nor mutated the installed pin"
    );

    // (#227 publisher view) list_held_fountain_content — the publisher sees
    // their held content + its degradation state without fetching symbols.
    let hcid = format!("c-held-{suffix}");
    let (hmanifest, hsymbols) =
        build_manifest_and_symbols(&hcid, n_source, k_repair, symbol_size, true).await;
    backend
        .put_fountain_content(&hmanifest, &hsymbols)
        .await
        .expect("admit held-list content");
    // Full: all N+K symbols held, recoverable (held >= min_viable_symbols=2).
    let held = backend
        .list_held_fountain_content("fountain-mldsa")
        .await
        .expect("list_held_fountain_content");
    assert!(
        held.iter().all(|m| m.pqc_key_id == "fountain-mldsa"),
        "filtered to the publisher"
    );
    let mine = held
        .iter()
        .find(|m| m.content_id == hcid)
        .expect("admitted content is listed for its publisher");
    assert_eq!(mine.held_symbols, total, "all symbols held when full");
    assert_eq!(mine.min_viable_symbols, 2);
    assert!(mine.recoverable, "full content is recoverable");
    assert_eq!(
        mine.recoverable,
        mine.held_symbols >= mine.min_viable_symbols,
        "recoverable == held >= min_viable"
    );
    // Degrade: evict to the lowest tier — the publisher SEES the fade (#227).
    backend
        .evict_fountain_content_to_tier(&hcid, corpus, FountainTier::T5)
        .await
        .expect("evict to T5");
    let after = backend
        .list_held_fountain_content("fountain-mldsa")
        .await
        .expect("list after evict");
    let faded = after
        .iter()
        .find(|m| m.content_id == hcid)
        .expect("still listed after eviction (manifest intact)");
    assert!(
        faded.held_symbols < total,
        "held_symbols dropped after eviction — the fade is visible to the publisher"
    );
    assert_eq!(
        faded.recoverable,
        faded.held_symbols >= faded.min_viable_symbols,
        "recoverable tracks the post-eviction symbol count"
    );
    // A publisher who holds nothing → empty.
    assert!(
        backend
            .list_held_fountain_content("no-such-publisher")
            .await
            .unwrap()
            .is_empty(),
        "unknown publisher holds nothing"
    );
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

// ───────────────────────────────────────────────────────────────────
// #227 (residual) — consent-decay clock, proven on BOTH durable backends.
// ───────────────────────────────────────────────────────────────────

/// Build + hybrid-sign a manifest whose signed envelope carries an extra
/// object (e.g. the consent-decay class) merged over the producer pubkeys.
async fn build_manifest_with_envelope(
    content_id: &str,
    n_source: u32,
    k_repair: u32,
    symbol_size: u32,
    extra: serde_json::Value,
) -> (FountainManifestV1, Vec<FountainSymbolV1>) {
    let (ed_sk, ed_pk_b64, mldsa) = producer_pubkeys();
    let (symbols, symbol_hashes) = synth_symbols(content_id, n_source, k_repair, symbol_size);
    let pqc_pk = mldsa.public_key().await.unwrap();

    let mut envelope = serde_json::json!({
        "content_id": content_id,
        "pubkey_ed25519": ed_pk_b64,
        "pubkey_ml_dsa_65": BASE64.encode(&pqc_pk),
    });
    if let (Some(base), Some(add)) = (envelope.as_object_mut(), extra.as_object()) {
        for (k, v) in add {
            base.insert(k.clone(), v.clone());
        }
    }

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
    let canonical = manifest
        .canonical_bytes(&PythonJsonDumpsCanonicalizer)
        .unwrap();
    let ed_sig = ed_sk.sign(&canonical).to_bytes();
    manifest.signature = BASE64.encode(ed_sig);
    let mut bound = Vec::with_capacity(canonical.len() + ed_sig.len());
    bound.extend_from_slice(&canonical);
    bound.extend_from_slice(&ed_sig);
    let pqc_sig = mldsa.sign(&bound).await.unwrap();
    manifest.signature_ml_dsa_65 = BASE64.encode(&pqc_sig);
    (manifest, symbols)
}

/// Shared body: the consent-decay clock decisions the
/// `sweep_consent_decay_once` loop makes, per candidate, exercised on a
/// migrated backend and scoped to `suffix`ed content_ids (so it is
/// self-isolating on the shared PG twin). Mirrors the Engine sweep:
/// enumerate → read decay class + admitted_at → `consent_decay_target_tier`
/// → reuse `evict_fountain_content_to_tier`.
async fn run_consent_decay_assertions<B: Backend>(backend: &B, suffix: &str) {
    use ciris_persist::fountain::{consent_decay_target_tier, FountainReadClass};
    let (n, k, size) = (8u32, 4u32, 16u32);
    let total = u64::from(n + k);

    let cid_temp = format!("c-decay-temp-{suffix}");
    let cid_pat = format!("c-decay-pat-{suffix}");
    let cid_none = format!("c-decay-none-{suffix}");

    let (m_temp, s_temp) = build_manifest_with_envelope(
        &cid_temp,
        n,
        k,
        size,
        serde_json::json!({ "consent_decay_class": "temporary" }),
    )
    .await;
    let (m_pat, s_pat) = build_manifest_with_envelope(
        &cid_pat,
        n,
        k,
        size,
        serde_json::json!({ "decay_protocol": "ciris-agent-90day" }),
    )
    .await;
    // No decay class declared ⇒ the clock never touches it (fail-safe).
    let (m_none, s_none) =
        build_manifest_with_envelope(&cid_none, n, k, size, serde_json::json!({})).await;

    for (m, s) in [(&m_temp, &s_temp), (&m_pat, &s_pat), (&m_none, &s_none)] {
        backend.put_fountain_content(m, s).await.expect("admit");
    }

    // The enumerate method returns our three units with their admitted_at
    // + the signed decay-class envelope (both backends, identical shape).
    let candidates = backend
        .list_fountain_decay_candidates()
        .await
        .expect("enumerate decay candidates");
    let mine: std::collections::HashMap<String, _> = candidates
        .into_iter()
        .filter(|c| c.content_id.ends_with(suffix))
        .map(|c| (c.content_id.clone(), c))
        .collect();
    assert!(mine.contains_key(&cid_temp), "temp enumerated");
    assert!(mine.contains_key(&cid_pat), "pattern enumerated");
    assert!(mine.contains_key(&cid_none), "unclassed enumerated");
    // The unclassed unit resolves to no target tier ⇒ never decayed.
    let none_cand = &mine[&cid_none];
    assert_eq!(
        consent_decay_target_tier(
            &none_cand.envelope,
            none_cand.admitted_at,
            none_cand.admitted_at + chrono::Duration::days(365)
        ),
        None,
        "no decay class ⇒ clock opts out"
    );

    let temp_admitted = mine[&cid_temp].admitted_at;
    let pat_admitted = mine[&cid_pat].admitted_at;
    let temp_env = mine[&cid_temp].envelope.clone();
    let pat_env = mine[&cid_pat].envelope.clone();

    // A single per-candidate step, exactly as the sweep does it: resolve
    // the target tier at `now`; evict via the shared mechanism unless the
    // clock is still at `Full`. Returns symbols evicted this step.
    async fn decay_step<B: Backend>(
        backend: &B,
        cid: &str,
        env: &serde_json::Value,
        admitted: chrono::DateTime<chrono::Utc>,
        now: chrono::DateTime<chrono::Utc>,
    ) -> u64 {
        match consent_decay_target_tier(env, admitted, now) {
            None => 0,
            Some(FountainTier::Full) => 0,
            Some(tier) => backend
                .evict_fountain_content_to_tier(cid, "trace", tier)
                .await
                .expect("evict to decay tier"),
        }
    }
    async fn read_class<B: Backend>(backend: &B, cid: &str, n: u32) -> FountainReadClass {
        FountainContent::classify(
            backend
                .get_fountain_content(cid, "trace")
                .await
                .unwrap()
                .unwrap()
                .present(),
            n,
            2,
        )
    }

    // (1) BELOW THRESHOLD stays: at +1d neither the 14d nor the 90d clock
    //     has reached its first breakpoint ⇒ nothing evicted, both Full.
    let now1 = temp_admitted + chrono::Duration::days(1);
    assert_eq!(
        decay_step(backend, &cid_temp, &temp_env, temp_admitted, now1).await,
        0
    );
    assert_eq!(
        decay_step(backend, &cid_pat, &pat_env, pat_admitted, now1).await,
        0
    );
    assert_eq!(
        read_class(backend, &cid_temp, n).await,
        FountainReadClass::Full
    );
    assert_eq!(
        read_class(backend, &cid_pat, n).await,
        FountainReadClass::Full
    );

    // (2) TEMPORARY past 14d decays: at +20d the 14d clock is >= 1.0 ⇒ T5
    //     (EnvelopeOnly). The 90d pattern at +20d is still < 0.25 ⇒ Full
    //     (pattern-below-threshold stays).
    let now2 = temp_admitted + chrono::Duration::days(20);
    let temp_evicted = decay_step(backend, &cid_temp, &temp_env, temp_admitted, now2).await;
    assert_eq!(
        temp_evicted, total,
        "TEMPORARY past 14d evicts every symbol (T5)"
    );
    assert_eq!(
        decay_step(backend, &cid_pat, &pat_env, pat_admitted, now2).await,
        0
    );
    assert_eq!(
        read_class(backend, &cid_temp, n).await,
        FountainReadClass::EnvelopeOnly,
        "TEMPORARY decayed to EnvelopeOnly"
    );
    assert_eq!(
        read_class(backend, &cid_pat, n).await,
        FountainReadClass::Full
    );

    // (3) IDEMPOTENT: re-running the temporary step at the same `now`
    //     evicts nothing further (already at/below the keep-count).
    assert_eq!(
        decay_step(backend, &cid_temp, &temp_env, temp_admitted, now2).await,
        0,
        "decay is idempotent at a fixed now"
    );

    // (4) PATTERN past 90d decays: at +100d the 90d clock is >= 1.0 ⇒ T5.
    let now3 = pat_admitted + chrono::Duration::days(100);
    let pat_evicted = decay_step(backend, &cid_pat, &pat_env, pat_admitted, now3).await;
    assert_eq!(
        pat_evicted, total,
        "pattern past 90d evicts every symbol (T5)"
    );
    assert_eq!(
        read_class(backend, &cid_pat, n).await,
        FountainReadClass::EnvelopeOnly,
        "pattern decayed to EnvelopeOnly"
    );
    // Idempotent again.
    assert_eq!(
        decay_step(backend, &cid_pat, &pat_env, pat_admitted, now3).await,
        0
    );

    // The unclassed unit was NEVER touched by any step ⇒ still Full.
    assert_eq!(
        read_class(backend, &cid_none, n).await,
        FountainReadClass::Full
    );
    let _ = s_none;
}

#[tokio::test]
async fn sqlite_consent_decay() {
    let backend = ciris_persist::store::SqliteBackend::open_in_memory()
        .await
        .expect("open sqlite");
    backend
        .run_migrations()
        .await
        .expect("sqlite migrations (incl. V084)");
    run_consent_decay_assertions(&backend, "sqlite").await;
}

#[tokio::test]
async fn postgres_consent_decay() {
    let Some(dsn) = std::env::var("CIRIS_PERSIST_TEST_PG_URL").ok() else {
        eprintln!("postgres_consent_decay skipped: CIRIS_PERSIST_TEST_PG_URL unset");
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
    run_consent_decay_assertions(&backend, &suffix).await;
}

/// The full `Engine::sweep_consent_decay_once` entry, end-to-end on an
/// isolated in-memory SQLite engine (the sweep enumerates ALL manifests,
/// so it is proven on the isolated backend; the per-candidate decisions +
/// pg/sqlite parity are covered by `{sqlite,postgres}_consent_decay`).
#[cfg(feature = "sqlite")]
#[tokio::test]
async fn engine_sweep_consent_decay_once_sqlite() {
    use ciris_persist::fountain::FountainReadClass;
    use ciris_persist::signing::LocalSigner;
    use std::sync::Arc;

    // A minimal plaintext signer — the engine signer plays no part in
    // fountain admission (the manifest is producer-signed) or in the decay
    // sweep (which emits nothing).
    let signer = Arc::new(LocalSigner::from_parts(
        SigningKey::from_bytes(&[0x5Au8; 32]),
        "decay-test-engine".to_string(),
        None,
        None,
    ));
    let engine = ciris_persist::Engine::with_signer(signer, "sqlite::memory:")
        .await
        .expect("engine");

    let (n, k, size) = (8u32, 4u32, 16u32);
    let (m_temp, s_temp) = build_manifest_with_envelope(
        "c-eng-temp",
        n,
        k,
        size,
        serde_json::json!({ "consent_decay_class": "temporary" }),
    )
    .await;
    let (m_none, s_none) =
        build_manifest_with_envelope("c-eng-none", n, k, size, serde_json::json!({})).await;
    let t0 = chrono::Utc::now();
    engine
        .put_fountain_content(&m_temp, &s_temp)
        .await
        .expect("put temp");
    engine
        .put_fountain_content(&m_none, &s_none)
        .await
        .expect("put none");

    // Below threshold: +1d ⇒ nothing decays.
    let r = engine
        .sweep_consent_decay_once(t0 + chrono::Duration::days(1))
        .await
        .expect("sweep +1d");
    assert_eq!(r.symbols_evicted, 0, "below-threshold sweep evicts nothing");
    assert_eq!(
        r.content_with_decay_class, 1,
        "only the temporary unit has a class"
    );

    // Past 14d: +20d ⇒ the temporary unit decays to EnvelopeOnly.
    let r = engine
        .sweep_consent_decay_once(t0 + chrono::Duration::days(20))
        .await
        .expect("sweep +20d");
    assert_eq!(
        r.symbols_evicted,
        u64::from(n + k),
        "TEMPORARY drops all symbols"
    );
    assert_eq!(r.content_decayed, 1);
    let temp = engine
        .get_fountain_content("c-eng-temp", "trace")
        .await
        .unwrap()
        .unwrap();
    assert_eq!(
        FountainContent::classify(temp.present(), n, 2),
        FountainReadClass::EnvelopeOnly
    );

    // Idempotent: an identical re-sweep evicts nothing further.
    let r = engine
        .sweep_consent_decay_once(t0 + chrono::Duration::days(20))
        .await
        .expect("sweep +20d again");
    assert_eq!(r.symbols_evicted, 0, "decay sweep is idempotent");

    // The unclassed unit is untouched (still Full).
    let none = engine
        .get_fountain_content("c-eng-none", "trace")
        .await
        .unwrap()
        .unwrap();
    assert_eq!(none.present(), n + k, "unclassed unit never decays");
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
