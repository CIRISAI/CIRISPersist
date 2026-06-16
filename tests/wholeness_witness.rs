//! v8.2.0 (CEG 1.0-RC11 §19.1 / CIRISPersist#228 items 1–2 / #229 item 1)
//! — the WholenessWitness corpus + verify-before-persist gate + WW→§10.1.6
//! quorum-merge subordination + anti-rollback, proven on BOTH durable
//! backends (Postgres + SQLite) plus the memory backend for the
//! verdict-routing assertions.
//!
//! persist is the §19 store + the WW-2 leaf-walk owner + the
//! divergence→merge router. The holonomic verifiers themselves (Merkle,
//! the PQC bound-hybrid gate, the equivocation classifier) are frozen +
//! cross-impl-proven in `ciris_verify_core::holonomic` (CIRISVerify
//! v5.9.0); persist CALLS them and never re-rolls the crypto.
//!
//! Project rule (NO pg/sqlite asymmetry): the V085 schema + the admit
//! gate + the corpus/prune contract are identical on both backends; only
//! the SQL dialect differs. The stateful corpus assertions run against
//! each durable backend; the pure verdict-routing + anti-rollback +
//! quorum-merge-subordination assertions run once.

#![cfg(all(feature = "postgres", feature = "sqlite"))]

use base64::engine::general_purpose::STANDARD as BASE64;
use base64::Engine as _;
use ciris_keyring::{MlDsa65SoftwareSigner, PqcSigner};
use ed25519_dalek::{Signer as _, SigningKey};

use ciris_persist::federation::FederationDirectory;
use ciris_persist::store::Backend;
use ciris_persist::witness::{
    accept_if_monotonic, build_local_witness, classify, WitnessLeaf, WitnessReconcileAction,
    QUORUM_MERGE_SUBJECT_KINDS, WITNESS_EQUIVOCATION,
};
use ciris_verify_core::holonomic::WholenessWitness;

/// Producer identity (Ed25519 + ML-DSA-65) with b64 pubkeys.
struct Producer {
    ed: SigningKey,
    ed_pub_b64: String,
    mldsa: MlDsa65SoftwareSigner,
}

impl Producer {
    fn new(seed: u8) -> Self {
        let ed = SigningKey::from_bytes(&[seed; 32]);
        let ed_pub_b64 = BASE64.encode(ed.verifying_key().to_bytes());
        let mldsa =
            MlDsa65SoftwareSigner::from_seed_bytes(&[seed ^ 0x55; 32], "witness-mldsa").unwrap();
        Self {
            ed,
            ed_pub_b64,
            mldsa,
        }
    }

    async fn mldsa_pub_b64(&self) -> String {
        BASE64.encode(self.mldsa.public_key().await.unwrap())
    }

    /// Bound-hybrid sign a witness's §19.1 canonical preimage:
    /// Ed25519 over preimage, ML-DSA-65 over (preimage ‖ ed_sig).
    /// Returns (ed_sig_b64, pqc_sig_b64).
    async fn sign(&self, witness: &WholenessWitness) -> (String, String) {
        let preimage = witness.canonical_preimage();
        let ed_sig = self.ed.sign(&preimage).to_bytes();
        let mut bound = preimage.clone();
        bound.extend_from_slice(&ed_sig);
        let pqc_sig = self.mldsa.sign(&bound).await.unwrap();
        (BASE64.encode(ed_sig), BASE64.encode(&pqc_sig))
    }
}

/// Stateful corpus assertions (a)–(c), (f) against a migrated backend.
/// `suffix` keeps PG peer_ids self-isolating across concurrent runs.
async fn run_corpus_assertions<B: FederationDirectory + Sync>(backend: &B, suffix: &str) {
    let producer = Producer::new(0x11);
    let pqc_pub = producer.mldsa_pub_b64().await;
    let now = chrono::Utc::now();

    // ── (a) a valid hybrid-signed witness → admitted + stored. ──
    let peer = format!("peer-valid-{suffix}");
    let leaves = vec![
        WitnessLeaf {
            claim_namespace: "scores:medical".into(),
            cohort_scope: "community".into(),
            anonymous_tier: false,
            leaf_bytes: b"leaf-1".to_vec(),
        },
        WitnessLeaf {
            claim_namespace: "scores:safety".into(),
            cohort_scope: "family".into(),
            anonymous_tier: false,
            leaf_bytes: b"leaf-2".to_vec(),
        },
    ];
    let witness = build_local_witness(&peer, 1, 1000, &leaves);
    let (ed_sig, pqc_sig) = producer.sign(&witness).await;
    backend
        .put_wholeness_witness(
            &witness,
            &ed_sig,
            Some(&pqc_sig),
            "witness-mldsa",
            &producer.ed_pub_b64,
            Some(&pqc_pub),
            None,
        )
        .await
        .expect("(a) valid hybrid witness MUST be admitted");
    let stored = backend
        .list_wholeness_witnesses_for_peer(&peer)
        .await
        .expect("(a) list");
    assert_eq!(stored.len(), 1, "(a) one witness stored");
    assert_eq!(stored[0].peer_id, peer);
    assert_eq!(stored[0].leaf_count, 2);
    // No anonymous/self in the namespaces (WW-2).
    assert!(stored[0]
        .claim_namespaces
        .iter()
        .all(|n| !n.contains("self") && !n.contains("anonymous")));

    // ── (b) classical-only witness (no ML-DSA-65) → REJECTED, ZERO rows. ──
    let peer_classical = format!("peer-classical-{suffix}");
    let w2 = build_local_witness(&peer_classical, 1, 1000, &leaves);
    let (ed_sig2, _pqc2) = producer.sign(&w2).await;
    let err = backend
        .put_wholeness_witness(
            &w2,
            &ed_sig2,
            None, // classical-only → §19.0 hard cut
            "witness-mldsa",
            &producer.ed_pub_b64,
            Some(&pqc_pub),
            None,
        )
        .await
        .expect_err("(b) classical-only MUST be rejected (§19.0 hard cut)");
    assert_eq!(
        err.kind(),
        "witness_admit_hybrid_required",
        "(b) the hard-cut token"
    );
    assert!(
        backend
            .list_wholeness_witnesses_for_peer(&peer_classical)
            .await
            .unwrap()
            .is_empty(),
        "(b) rejected classical-only witness wrote ZERO rows (verify-before-mutation)"
    );

    // ── (c) WW-2: a build over a leaf set containing anonymous-tier +
    //        cohort_scope:self rows → those leaves filtered out BEFORE the
    //        root, claim_namespaces excludes anonymous/self. ──
    let peer_ww2 = format!("peer-ww2-{suffix}");
    let mixed = vec![
        WitnessLeaf {
            claim_namespace: "scores:medical".into(),
            cohort_scope: "community".into(),
            anonymous_tier: false,
            leaf_bytes: b"keep".to_vec(),
        },
        WitnessLeaf {
            claim_namespace: "notes:private".into(),
            cohort_scope: "self".into(), // deniable → dropped
            anonymous_tier: false,
            leaf_bytes: b"drop-self".to_vec(),
        },
        WitnessLeaf {
            claim_namespace: "blob:x".into(),
            cohort_scope: "community".into(),
            anonymous_tier: true, // anonymous → dropped
            leaf_bytes: b"drop-anon".to_vec(),
        },
    ];
    let w_ww2 = build_local_witness(&peer_ww2, 1, 1000, &mixed);
    // Root is over exactly the one survivor.
    let expected_root = ciris_verify_core::holonomic::compute_merkle_root(&[b"keep".to_vec()]);
    assert_eq!(
        w_ww2.merkle_root, expected_root,
        "(c) root over survivors only"
    );
    assert_eq!(w_ww2.leaf_count, 1, "(c) self+anon leaves filtered out");
    assert_eq!(
        w_ww2.claim_namespaces,
        vec!["scores:medical".to_string()],
        "(c) namespaces exclude self/anonymous"
    );
    // And it admits + stores (the disclosed-leaves recompute path).
    let (ed3, pqc3) = producer.sign(&w_ww2).await;
    backend
        .put_wholeness_witness(
            &w_ww2,
            &ed3,
            Some(&pqc3),
            "witness-mldsa",
            &producer.ed_pub_b64,
            Some(&pqc_pub),
            Some(&[b"keep".to_vec()]), // disclosed leaves → root recompute checked
        )
        .await
        .expect("(c) WW-2-filtered witness admits with leaf disclosure");

    // ── (f) anti-rollback: a stale per-peer epoch is rejected. ──
    let peer_ar = format!("peer-ar-{suffix}");
    // Accept epoch 5.
    let w5 = build_local_witness(&peer_ar, 5, 5000, &leaves);
    let (e5, p5) = producer.sign(&w5).await;
    backend
        .put_wholeness_witness(
            &w5,
            &e5,
            Some(&p5),
            "witness-mldsa",
            &producer.ed_pub_b64,
            Some(&pqc_pub),
            None,
        )
        .await
        .expect("(f) accept epoch 5");
    let last = backend
        .last_witness_epoch_for_peer(&peer_ar)
        .await
        .expect("(f) last epoch");
    assert_eq!(last, Some(5));
    // A replayed epoch 5 and a stale epoch 4 are both rejected by the
    // guard (the eclipse defense lives in persist; the corpus would store
    // the row idempotently, but the caller must NOT act on it as newer).
    assert!(!accept_if_monotonic(last, 5), "(f) replay rejected");
    assert!(!accept_if_monotonic(last, 4), "(f) rollback rejected");
    assert!(accept_if_monotonic(last, 6), "(f) advance accepted");

    let _ = now;
}

/// (d) compare_witnesses Equivocation → hard_case emitted, both witnesses
/// retained (not reconciled). Memory backend (the verdict-routing path).
#[tokio::test]
async fn equivocation_emits_hard_case_and_retains_both() {
    let backend = ciris_persist::store::MemoryBackend::default();
    let producer = Producer::new(0x22);
    let pqc_pub = producer.mldsa_pub_b64().await;
    let now = chrono::Utc::now();
    let peer = "equiv-peer";

    // Two validly-signed witnesses, SAME (peer, epoch, namespace set),
    // DIFFERENT roots → non-repudiable equivocation.
    let leaves_a = vec![WitnessLeaf {
        claim_namespace: "scores:medical".into(),
        cohort_scope: "community".into(),
        anonymous_tier: false,
        leaf_bytes: b"root-a".to_vec(),
    }];
    let leaves_b = vec![WitnessLeaf {
        claim_namespace: "scores:medical".into(),
        cohort_scope: "community".into(),
        anonymous_tier: false,
        leaf_bytes: b"root-b".to_vec(),
    }];
    let wa = build_local_witness(peer, 7, 7000, &leaves_a);
    let wb = build_local_witness(peer, 7, 7001, &leaves_b);
    assert_ne!(wa.merkle_root, wb.merkle_root);

    for w in [&wa, &wb] {
        let (ed, pqc) = producer.sign(w).await;
        backend
            .put_wholeness_witness(
                w,
                &ed,
                Some(&pqc),
                "witness-mldsa",
                &producer.ed_pub_b64,
                Some(&pqc_pub),
                None,
            )
            .await
            .expect("admit equivocating witness");
    }

    // reconcile → Equivocation, hard_case emitted, both rows retained.
    let action = backend
        .reconcile_peer_witnesses(peer, now)
        .await
        .expect("reconcile");
    match action {
        WitnessReconcileAction::Equivocation(proofs) => {
            assert!(!proofs.is_empty(), "(d) equivocation detected");
            assert_eq!(proofs[0].peer_id, peer);
        }
        other => panic!("(d) expected Equivocation, got {other:?}"),
    }
    // Both witnesses RETAINED (never reconciled/deleted).
    let stored = backend
        .list_wholeness_witnesses_for_peer(peer)
        .await
        .unwrap();
    assert_eq!(stored.len(), 2, "(d) both equivocating witnesses retained");
    // A hard_case:witness_equivocation was emitted.
    let cases = backend
        .list_hard_case_events(ciris_persist::federation::HardCaseFilter {
            kind: Some(WITNESS_EQUIVOCATION.to_owned()),
            since: None,
        })
        .await
        .unwrap();
    assert!(
        !cases.is_empty(),
        "(d) hard_case:witness_equivocation emitted"
    );
    assert_eq!(cases[0].target_key_id.as_deref(), Some(peer));

    // Idempotent: a re-scan emits no duplicate.
    let _ = backend.reconcile_peer_witnesses(peer, now).await.unwrap();
    let cases2 = backend
        .list_hard_case_events(ciris_persist::federation::HardCaseFilter {
            kind: Some(WITNESS_EQUIVOCATION.to_owned()),
            since: None,
        })
        .await
        .unwrap();
    assert_eq!(cases.len(), cases2.len(), "(d) re-scan is idempotent");
}

/// (e) compare_witnesses Divergent on `revocation` → triggers the V058
/// quorum-merge; the merge (monotonic_quorum/revision) decides — NOT a
/// fragment-pick — and a previously-revoked record is NOT resurrected.
///
/// This proves the SUBORDINATION: the witness yields ONLY a
/// `TriggerQuorumMerge` directive (no winner, no root); the actual
/// resolution runs through the EXISTING `resolve_monotonic_quorum`, which
/// keeps the revoked record because a stale `active` can never overwrite a
/// revoke at the same revision.
#[tokio::test]
async fn divergent_triggers_quorum_merge_revoked_not_resurrected() {
    use ciris_persist::federation::operational::{resolve_monotonic_quorum, PartnerRecord};

    // Two divergent witnesses across distinct peers (different roots).
    let wa = WholenessWitness {
        peer_id: "peer-a".into(),
        epoch_id: 1,
        claim_namespaces: vec!["revocation".into()],
        merkle_root: ciris_verify_core::holonomic::compute_merkle_root(&[b"state-a".to_vec()]),
        leaf_count: 1,
        observed_at_unix_ms: 1,
        witness_version: 1,
    };
    let wb = WholenessWitness {
        peer_id: "peer-b".into(),
        epoch_id: 1,
        claim_namespaces: vec!["revocation".into()],
        merkle_root: ciris_verify_core::holonomic::compute_merkle_root(&[b"state-b".to_vec()]),
        leaf_count: 1,
        observed_at_unix_ms: 1,
        witness_version: 1,
    };

    // The witness verdict is a TRIGGER ONLY — it carries no winner.
    let action = classify(&[wa, wb]);
    assert_eq!(
        action,
        WitnessReconcileAction::TriggerQuorumMerge,
        "(e) Divergent → TriggerQuorumMerge (the witness does NOT decide)"
    );
    // The trigger names the rollback-sensitive subject_kinds.
    assert!(QUORUM_MERGE_SUBJECT_KINDS.contains(&"revocation"));

    // Fulfilling the directive: re-run the EXISTING §10.1.6 merge over the
    // stored rows. The fragment that says "active" must NOT win over the
    // "revoked" fragment at the same revision — proving the witness root
    // never bypassed the merge to "reconstitute from any fragment".
    let now = chrono::Utc::now();
    let revoked = PartnerRecord {
        attestation_id: "a".into(),
        license_id: "lic-1".into(),
        partner_id: "p".into(),
        org_id: "o".into(),
        license_type: "community".into(),
        max_autonomy_tier: "A0".into(),
        requires_supervisor: false,
        deployment_limit: 1,
        offline_grace_hours: 0,
        status: "revoked".into(),
        revision: 5,
        issued_at: now,
        expires_at: now,
        asserted_at: now,
        signed_envelope: serde_json::json!({}),
        withdrawn_at: None,
        persist_row_hash: String::new(),
    };
    let stale_active = PartnerRecord {
        attestation_id: "b".into(),
        status: "active".into(),
        ..revoked.clone()
    };
    // Both fragments present; the merge resolver decides — not a pick of
    // whichever fragment a witness root happened to commit.
    let merge_set = [stale_active, revoked.clone()];
    let winner = resolve_monotonic_quorum(&merge_set).unwrap();
    assert_eq!(
        winner.status, "revoked",
        "(e) the quorum-merge keeps the REVOKED record — a revoked key is NOT resurrected"
    );
    assert_eq!(
        winner.attestation_id, "a",
        "(e) the merge (status rank), not a fragment-pick, chose the winner"
    );
}

#[tokio::test]
async fn sqlite_witness_corpus() {
    let backend = ciris_persist::store::SqliteBackend::open_in_memory()
        .await
        .expect("open sqlite");
    backend
        .run_migrations()
        .await
        .expect("sqlite migrations (incl. V085)");
    run_corpus_assertions(&backend, "sqlite").await;
}

#[tokio::test]
async fn postgres_witness_corpus() {
    let Some(dsn) = std::env::var("CIRIS_PERSIST_TEST_PG_URL").ok() else {
        eprintln!("postgres_witness_corpus skipped: CIRIS_PERSIST_TEST_PG_URL unset");
        return;
    };
    let backend = ciris_persist::store::PostgresBackend::connect(&dsn)
        .await
        .expect("connect postgres");
    backend
        .run_migrations()
        .await
        .expect("pg migrations (incl. V085)");
    let suffix = uuid::Uuid::new_v4().simple().to_string();
    run_corpus_assertions(&backend, &suffix).await;
}

/// (g) retention_decision: Withdrawn content → EvictEligible → hard_delete
/// drops all symbols (revocation overrides rarity); N6: an unverified
/// holding claim does not count toward rarity. Pure verdict + the engine
/// wiring direction. The full hard-delete-drops-all path is already proven
/// by the fountain_content.rs (i) assertion on both backends; here we
/// prove the verify-core verdict ROUTING that drives it.
#[tokio::test]
async fn retention_decision_revoked_routes_to_hard_delete_and_n6_gate() {
    use ciris_persist::federation::hard_case::ConsentState;
    use ciris_persist::fountain::{
        holding_claim_counts, resolve_retention_action, RetentionAction,
    };

    // N5: a revoked content is HardDelete even when "rare" — revocation
    // overrides rarity. The HardDelete action is exactly what routes the
    // engine to evict_fountain_content_hard_delete (drops all symbols).
    assert_eq!(
        resolve_retention_action(ConsentState::Revoked, true),
        RetentionAction::HardDelete,
        "(g) revoked+rare → HardDelete (revocation overrides rarity)"
    );
    assert!(resolve_retention_action(ConsentState::Revoked, false).is_hard_delete());
    // Granted+rare stays retain-rare (no eviction here).
    assert_eq!(
        resolve_retention_action(ConsentState::Granted, true),
        RetentionAction::RetainRare
    );
    // Unknown (expired/unspecified) never earns rare-retention.
    assert_eq!(
        resolve_retention_action(ConsentState::Expired, true),
        RetentionAction::RetainNonRare
    );

    // N6: an unverified holding claim MUST NOT count toward rarity.
    assert!(
        !holding_claim_counts(false),
        "(g/N6) unverified claim ignored"
    );
    assert!(holding_claim_counts(true), "(g/N6) proven claim counts");
}
