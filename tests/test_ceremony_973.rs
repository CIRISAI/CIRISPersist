//! CIRISPersist#973 — **I350–I355: the software ceremony minter, the outputs
//! verifier, and the boot path against a ceremony's artifacts.** Its own
//! process: every test arms the test-anchor override through the environment
//! (the #738 rule — never from a lib unit test).

#![cfg(all(feature = "test-anchor", feature = "sqlite"))]

use ciris_persist::federation::canonical_community::resolve_community;
use ciris_persist::federation::genesis::*;
use ciris_persist::federation::FederationDirectory;
use ciris_persist::store::backend::Backend as _;
use ciris_persist::store::memory::MemoryBackend;
use ciris_persist::store::sqlite::SqliteBackend;

const SEEDS: [[u8; 32]; 3] = [[0x31; 32], [0x32; 32], [0x33; 32]];
const NODE_SEED: [u8; 32] = [0x4E; 32];
const CANON: &str = "ciris-canonical";

/// Arms the override with a minted block; disarms and clears the installed
/// ceremony on every exit path.
struct Armed;

impl Armed {
    fn with(block: &TestAnchorBlock) -> Self {
        for (k, v) in block.env_pairs() {
            std::env::set_var(k, v);
        }
        for k in ["ENVIRONMENT", "CIRIS_ENV", "CIRIS_ENVIRONMENT"] {
            std::env::remove_var(k);
        }
        Self
    }
}

impl Drop for Armed {
    fn drop(&mut self) {
        clear_test_ceremony_outputs();
        for k in TEST_ANCHOR_ENV_VARS {
            std::env::remove_var(k);
        }
    }
}

fn at(offset_secs: i64) -> chrono::DateTime<chrono::Utc> {
    chrono::Utc::now() + chrono::Duration::seconds(offset_secs)
}

fn mint(offset_secs: i64) -> TestCeremonyOutputs {
    mint_test_ceremony(&SEEDS, &NODE_SEED, at(offset_secs)).expect("mint")
}

async fn sqlite() -> SqliteBackend {
    let b = SqliteBackend::open_in_memory().await.unwrap();
    b.run_migrations().await.unwrap();
    b.seed_genesis_accord_holders(&effective_accord_holder_records())
        .await
        .expect("seed holders");
    b
}

async fn memory() -> MemoryBackend {
    let b = MemoryBackend::new();
    b.seed_genesis_accord_holders(&effective_accord_holder_records())
        .await
        .expect("seed holders");
    b
}

async fn stored_instant(d: &dyn FederationDirectory, id: &str) -> chrono::DateTime<chrono::Utc> {
    d.get_attestation(id)
        .await
        .unwrap()
        .unwrap_or_else(|| panic!("{id} stored"))
        .asserted_at
}

/// The boot body shared by the backends: a fresh node booted against an
/// installed ceremony seeds every leg and reports Entrenched, community leg
/// included.
async fn boots_fully_seeded(d: &dyn FederationDirectory, c: &TestCeremonyOutputs, tag: &str) {
    install_test_ceremony_outputs(c.bundle.clone(), Some(c.community.clone()));
    seed_family_and_canonical(d)
        .await
        .unwrap_or_else(|e| panic!("{tag} I351: the boot seed against the ceremony: {e:?}"));
    verify_canonical_seeded(d).await.expect("canonical leg");
    verify_delegation_plane_seeded(d)
        .await
        .expect("delegation leg");
    verify_canonical_community_seeded(d)
        .await
        .expect("community leg");
    let posture = genesis_posture(d).await;
    assert!(
        matches!(posture, GenesisPosture::Entrenched),
        "{tag} I351: every leg seeded, community included: {posture:?}"
    );
    assert!(
        d.lookup_public_key(TEST_CEREMONY_NODE_KEY_ID)
            .await
            .unwrap()
            .is_some(),
        "{tag} I351: the serve node is anchored"
    );
    for id in test_ceremony_delegation_ids() {
        assert!(
            d.get_attestation(&id).await.unwrap().is_some(),
            "{tag} I351: {id} installed"
        );
    }
    let r = resolve_community(d, CANON)
        .await
        .unwrap()
        .unwrap_or_else(|| panic!("{tag} I351: the community resolves"));
    assert!(r.live, "{tag} I351: live at birth: {r:?}");
    assert_eq!(
        r.founders.len(),
        3,
        "{tag} I351: three holder-founders: {r:?}"
    );
    assert!(
        r.members.iter().any(|m| m == TEST_CEREMONY_NODE_KEY_ID),
        "{tag} I351: the node is seated without signing: {r:?}"
    );
}

/// **I350 — the minted outputs verify offline**, and the minter leaves the
/// anchor block exactly as `mint_test_anchor_block` mints it.
#[serial_test::serial(test_anchor_env)]
#[tokio::test]
async fn i350_minted_outputs_verify_offline() {
    let c = mint(-5);
    assert_eq!(
        c.block,
        mint_test_anchor_block(&SEEDS).unwrap(),
        "I350: the block is the #805 block, untouched"
    );
    let _armed = Armed::with(&c.block);
    let v = verify_ceremony_outputs(&c.bundle_json().unwrap(), &c.community_json().unwrap())
        .await
        .unwrap_or_else(|e| panic!("I350: the minted outputs verify: {e}"));
    assert_eq!(v.quorum_verified, 3, "I350: all three holders authorize");
    assert_eq!(v.serve_nodes, vec![TEST_CEREMONY_NODE_KEY_ID.to_owned()]);
    assert_eq!(v.attestations, test_ceremony_delegation_ids().to_vec());
    assert_eq!((v.community_key_id.as_str(), v.founders), (CANON, 3));
    // The charter declares witnessed mode off.
    let charter = &c.bundle.attestations[0].attestation;
    assert_eq!(charter.attestation_envelope["witness_quorum"], 0);
    // The node never signs the birth.
    assert!(
        c.community.authority_key_id != TEST_CEREMONY_NODE_KEY_ID
            && c.community
                .cosignatures
                .iter()
                .all(|s| s.authority_key_id != TEST_CEREMONY_NODE_KEY_ID),
        "I350: the node signs nothing"
    );
    // Not three seeds: refused.
    assert!(mint_test_ceremony(&SEEDS[..2], &NODE_SEED, at(0)).is_err());
}

/// **I351 — a fresh node boots fully seeded from the ceremony's artifacts**
/// through `seed_delegation_plane` and the community boot leg (sqlite).
#[serial_test::serial(test_anchor_env)]
#[tokio::test]
async fn i351_boot_from_ceremony_sqlite() {
    let c = mint(-5);
    let _armed = Armed::with(&c.block);
    let b = sqlite().await;
    // Control: with NO ceremony installed the override skips every leg past
    // the family, and nothing of the ceremony is there.
    seed_family_and_canonical(&b).await.unwrap();
    assert!(b.lookup_community(CANON).await.unwrap().is_none());
    assert!(b
        .get_attestation("genesis-charter")
        .await
        .unwrap()
        .is_none());
    boots_fully_seeded(&b, &c, "sqlite").await;
}

/// I351 on the memory backend.
#[serial_test::serial(test_anchor_env)]
#[tokio::test]
async fn i351_boot_from_ceremony_memory() {
    let c = mint(-5);
    let _armed = Armed::with(&c.block);
    let b = memory().await;
    boots_fully_seeded(&b, &c, "memory").await;
}

/// I351 on postgres, when a test database is provided
/// (`scripts/pg_test_db.sh -- …`).
#[cfg(feature = "postgres")]
#[serial_test::serial(test_anchor_env)]
#[tokio::test]
async fn i351_boot_from_ceremony_postgres() {
    let Ok(dsn) = std::env::var("CIRIS_PERSIST_TEST_PG_URL") else {
        eprintln!("skipping: CIRIS_PERSIST_TEST_PG_URL unset");
        return;
    };
    let c = mint(-5);
    let _armed = Armed::with(&c.block);
    let b = ciris_persist::store::postgres::PostgresBackend::connect(&dsn)
        .await
        .unwrap();
    b.run_migrations().await.unwrap();
    b.seed_genesis_accord_holders(&effective_accord_holder_records())
        .await
        .expect("seed holders");
    boots_fully_seeded(&b, &c, "postgres").await;
}

/// **I352 — the upgrade path, end to end**: a node seeded from an OLD
/// ceremony boots against a re-mint with strictly newer instants — the three
/// rows keep their ids and are superseded, and the node is fully seeded.
#[serial_test::serial(test_anchor_env)]
#[tokio::test]
async fn i352_remint_supersedes_on_upgrade() {
    let old = mint(-3600);
    let _armed = Armed::with(&old.block);
    for (tag, d) in [
        (
            "sqlite",
            Box::new(sqlite().await) as Box<dyn FederationDirectory>,
        ),
        (
            "memory",
            Box::new(memory().await) as Box<dyn FederationDirectory>,
        ),
    ] {
        let d = d.as_ref();
        boots_fully_seeded(d, &old, tag).await;
        let before = stored_instant(d, "genesis-charter").await;
        let new = mint(-5);
        install_test_ceremony_outputs(new.bundle.clone(), Some(new.community.clone()));
        seed_family_and_canonical(d)
            .await
            .unwrap_or_else(|e| panic!("{tag} I352: boot against the re-mint: {e:?}"));
        for (id, row) in test_ceremony_delegation_ids()
            .iter()
            .zip(&new.bundle.attestations)
        {
            assert_eq!(
                stored_instant(d, id).await,
                row.attestation.asserted_at,
                "{tag} I352: {id} is the re-minted row"
            );
        }
        assert!(stored_instant(d, "genesis-charter").await > before);
        assert!(
            matches!(genesis_posture(d).await, GenesisPosture::Entrenched),
            "{tag} I352: seeded on the re-mint"
        );
        // The held community is the OLD birth: left in place, never a fault.
        assert_eq!(
            seed_canonical_community(d).await.unwrap(),
            CommunityLegOutcome::HeldDiffers,
            "{tag} I352: a held community is never overwritten by the asset"
        );
    }
}

/// **I353 — a re-mint stamped more than 300 s ahead is refused and the node
/// still boots**: the old rows stay, the fault is Absent, never Divergent.
#[serial_test::serial(test_anchor_env)]
#[tokio::test]
async fn i353_future_dated_remint_is_absent_never_divergent() {
    let old = mint(-3600);
    let _armed = Armed::with(&old.block);
    let b = sqlite().await;
    boots_fully_seeded(&b, &old, "sqlite").await;
    let before = stored_instant(&b, "genesis-charter").await;
    let future = mint(900);
    install_test_ceremony_outputs(future.bundle.clone(), Some(future.community.clone()));
    match seed_family_and_canonical(&b).await {
        Err(GenesisFault::Absent { leg, detail, .. }) => {
            assert_eq!(leg, GenesisLeg::Delegation, "I353: {detail}");
            assert!(
                detail.contains("ahead of now") && detail.contains("nothing deleted"),
                "I353: refused for the clock, before anything is removed: {detail}"
            );
        }
        other => panic!(
            "I353: a future-dated re-mint is refused as Absent (the node boots), got {other:?}"
        ),
    }
    assert_eq!(
        stored_instant(&b, "genesis-charter").await,
        before,
        "I353: the stored row is not replaced by a future-dated one"
    );
    assert!(
        !matches!(genesis_posture(&b).await, GenesisPosture::Divergent { .. }),
        "I353: never divergent"
    );
}

/// **I354 — the verifier refuses by name.**
#[serial_test::serial(test_anchor_env)]
#[tokio::test]
async fn i354_verifier_refuses_by_name() {
    use CeremonyOutputsRefusal as R;
    let c = mint(-5);
    let _armed = Armed::with(&c.block);
    let (bj, cj) = (c.bundle_json().unwrap(), c.community_json().unwrap());
    let reason =
        |r: Result<CeremonyOutputsVerified, CeremonyOutputsRefused>| r.expect_err("must refuse");

    // malformed
    assert_eq!(
        reason(verify_ceremony_outputs("{", &cj).await).reason,
        R::Malformed
    );
    assert_eq!(
        reason(verify_ceremony_outputs(&bj, "null").await).reason,
        R::Malformed
    );

    // one authorization: below the quorum
    let mut b1 = c.bundle.clone();
    b1.authorizations.truncate(1);
    let e = reason(verify_ceremony_outputs(&serde_json::to_string(&b1).unwrap(), &cj).await);
    assert_eq!(e.reason, R::BundleQuorum, "{e}");

    // a carried holder that is not this build's roster
    let mut b2 = c.bundle.clone();
    b2.holders[0].record.key_id = "someone-else".into();
    let e = reason(verify_ceremony_outputs(&serde_json::to_string(&b2).unwrap(), &cj).await);
    assert_eq!(e.reason, R::HolderRosterMismatch, "{e}");

    // a founder who did not sign the birth
    let mut c1 = c.community.clone();
    c1.cosignatures.pop();
    let e = reason(verify_ceremony_outputs(&bj, &serde_json::to_string(&c1).unwrap()).await);
    assert_eq!(e.reason, R::CommunityBirth, "{e}");

    // a node member the bundle does not anchor (no accord-scrubbed record)
    let mut c2 = c.community.clone();
    for m in &mut c2.community.members {
        if m.key_id == TEST_CEREMONY_NODE_KEY_ID {
            m.key_id = "unanchored-node".into();
        }
    }
    let e = reason(verify_ceremony_outputs(&bj, &serde_json::to_string(&c2).unwrap()).await);
    assert_eq!(e.reason, R::CommunityBirth, "{e}");

    // a tampered birth (a signed member changed after signing)
    let mut c3 = c.community.clone();
    c3.community.community_name = "Somebody Else's Services".into();
    let e = reason(verify_ceremony_outputs(&bj, &serde_json::to_string(&c3).unwrap()).await);
    assert_eq!(e.reason, R::CommunityBirth, "{e}");

    // a delegation row or a serve node altered after the holders authorized
    // the bundle: the authorization digest binds both, so the quorum fails
    let mut b3 = c.bundle.clone();
    b3.attestations[1].attestation.attestation_envelope["scope"] =
        serde_json::json!(["infra:serve"]);
    let e = reason(verify_ceremony_outputs(&serde_json::to_string(&b3).unwrap(), &cj).await);
    assert_eq!(e.reason, R::BundleQuorum, "{e}");
    let mut b4 = c.bundle.clone();
    b4.serve_nodes[0].record.identity_type = "canonical,node,steward".into();
    let e = reason(verify_ceremony_outputs(&serde_json::to_string(&b4).unwrap(), &cj).await);
    assert_eq!(e.reason, R::BundleQuorum, "{e}");

    // a correctly authorized bundle whose rows the write door refuses (stamped
    // 15 minutes ahead): caught at the bake stage, by the door's own rule
    let f = mint(900);
    let e = reason(
        verify_ceremony_outputs(&f.bundle_json().unwrap(), &f.community_json().unwrap()).await,
    );
    assert_eq!(e.reason, R::DelegationRow, "{e}");
    assert!(e.detail.contains("ahead of now"), "{e}");
}

/// **I355b — the seam is honoured only while the override is live.** With a
/// ceremony installed and the anchor disarmed, every reader sees the compiled
/// artifacts again.
#[serial_test::serial(test_anchor_env)]
#[tokio::test]
async fn i355b_seam_is_inert_without_the_override() {
    let c = mint(-5);
    let baked_holder = accord_holder_genesis_records()[0].record.key_id.clone();
    {
        let _armed = Armed::with(&c.block);
        install_test_ceremony_outputs(c.bundle.clone(), Some(c.community.clone()));
        assert_eq!(
            canonical_genesis_bundle().holders[0].record.key_id,
            "test-accord-holder-0"
        );
        assert!(canonical_community_asset().is_some());
        // Disarm WITHOUT clearing the installed ceremony.
        for k in TEST_ANCHOR_ENV_VARS {
            std::env::remove_var(k);
        }
        assert_eq!(
            canonical_genesis_bundle().holders[0].record.key_id,
            baked_holder,
            "I355b: disarmed, the compiled bundle is what every reader sees"
        );
        assert!(
            canonical_community_asset().is_none(),
            "I355b: disarmed, the compiled (unbaked) community asset"
        );
    }
}

/// **I355 — a tampered community asset never stops the boot**: the leg is
/// Absent, the rest is seeded.
#[serial_test::serial(test_anchor_env)]
#[tokio::test]
async fn i355_refused_community_asset_boots_absent() {
    let c = mint(-5);
    let _armed = Armed::with(&c.block);
    let b = sqlite().await;
    let mut bad = c.community.clone();
    bad.cosignatures.clear();
    install_test_ceremony_outputs(c.bundle.clone(), Some(bad));
    match seed_family_and_canonical(&b).await {
        Err(GenesisFault::Absent { leg, .. }) => assert_eq!(leg, GenesisLeg::Community),
        other => panic!("I355: expected Absent(community), got {other:?}"),
    }
    assert!(b.lookup_community(CANON).await.unwrap().is_none());
    verify_delegation_plane_seeded(&b)
        .await
        .expect("the rest is seeded");
    assert!(matches!(
        genesis_posture(&b).await,
        GenesisPosture::PreGenesis {
            leg: GenesisLeg::Community,
            ..
        }
    ));
}
