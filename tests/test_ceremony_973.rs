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

/// The bundle with its carried `ciris-canonical` birth changed by `f`.
fn with_birth(
    bundle: &GenesisBundle,
    f: impl FnOnce(&mut ciris_persist::federation::SignedCommunity),
) -> GenesisBundle {
    let mut b = bundle.clone();
    for r in &mut b.roster_records {
        if let GenesisRosterRecord::Community(c) = r {
            f(c);
            return b;
        }
    }
    panic!("the bundle carries a birth");
}

/// The bundle with its carried accord family record changed by `f`.
fn with_family(
    bundle: &GenesisBundle,
    f: impl FnOnce(&mut ciris_persist::federation::SignedFamily),
) -> GenesisBundle {
    let mut b = bundle.clone();
    for r in &mut b.roster_records {
        if let GenesisRosterRecord::Family(x) = r {
            f(x);
            return b;
        }
    }
    panic!("the bundle carries a family record");
}

fn json(b: &GenesisBundle) -> String {
    serde_json::to_string(b).unwrap()
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
    install_test_ceremony_outputs(c.bundle.clone());
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
    let v = verify_ceremony_outputs(&c.bundle_json().unwrap())
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
    let Ok(base) = std::env::var("CIRIS_PERSIST_TEST_PG_URL") else {
        eprintln!("skipping: CIRIS_PERSIST_TEST_PG_URL unset");
        return;
    };
    // A database of this test's own: the integration binaries share ONE
    // database, and a second ceremony seeded into it (other seeds, the same
    // holder ids) reads as anchor squatting to whichever test runs next.
    let cut = base.rfind('/').expect("dsn has a database");
    let name = format!(
        "ciris_t_{}_{}",
        std::process::id(),
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_nanos()
    );
    {
        let (admin, conn) = tokio_postgres::connect(&base, tokio_postgres::NoTls)
            .await
            .expect("connect to the base test database");
        tokio::spawn(conn);
        admin
            .batch_execute(&format!("CREATE DATABASE \"{name}\""))
            .await
            .expect("create this test's database");
    }
    let dsn = format!("{}/{name}", &base[..cut]);
    let c = mint(-5);
    let _armed = Armed::with(&c.block);
    {
        let b = ciris_persist::store::postgres::PostgresBackend::connect(&dsn)
            .await
            .unwrap();
        b.run_migrations().await.unwrap();
        b.seed_genesis_accord_holders(&effective_accord_holder_records())
            .await
            .expect("seed holders");
        boots_fully_seeded(&b, &c, "postgres").await;
    }
    // Best effort: the harness reaps `ciris_t_<pid>_*` of dead processes too.
    if let Ok((admin, conn)) = tokio_postgres::connect(&base, tokio_postgres::NoTls).await {
        tokio::spawn(conn);
        let _ = admin
            .batch_execute(&format!("DROP DATABASE IF EXISTS \"{name}\" WITH (FORCE)"))
            .await;
    }
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
        install_test_ceremony_outputs(new.bundle.clone());
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
    install_test_ceremony_outputs(future.bundle.clone());
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

/// **I354 — the verifier refuses by name.** v53.0.0: the bundle is the one
/// artifact, so the birth and the family record are tampered INSIDE it. A
/// change to a record's signed content moves the authorization digest and is
/// refused at the quorum; a change to its signatures alone is refused by the
/// record's own stage.
#[serial_test::serial(test_anchor_env)]
#[tokio::test]
async fn i354_verifier_refuses_by_name() {
    use CeremonyOutputsRefusal as R;
    let c = mint(-5);
    let _armed = Armed::with(&c.block);
    let reason =
        |r: Result<CeremonyOutputsVerified, CeremonyOutputsRefused>| r.expect_err("must refuse");

    // malformed
    assert_eq!(
        reason(verify_ceremony_outputs("{").await).reason,
        R::Malformed
    );
    // one spelling: a delegation row after a roster record
    let mut v = serde_json::to_value(&c.bundle).unwrap();
    let list = v["attestations"].as_array_mut().unwrap();
    let row = list.remove(0);
    list.push(row);
    let e = reason(verify_ceremony_outputs(&v.to_string()).await);
    assert_eq!(e.reason, R::Malformed, "{e}");

    // one authorization: below the quorum
    let mut b1 = c.bundle.clone();
    b1.authorizations.truncate(1);
    let e = reason(verify_ceremony_outputs(&json(&b1)).await);
    assert_eq!(e.reason, R::BundleQuorum, "{e}");

    // a carried holder that is not this build's roster
    let mut b2 = c.bundle.clone();
    b2.holders[0].record.key_id = "someone-else".into();
    let e = reason(verify_ceremony_outputs(&json(&b2)).await);
    assert_eq!(e.reason, R::HolderRosterMismatch, "{e}");

    // no birth in the bundle
    let mut b0 = c.bundle.clone();
    b0.roster_records
        .retain(|r| !matches!(r, GenesisRosterRecord::Community(_)));
    let e = reason(verify_ceremony_outputs(&json(&b0)).await);
    assert_eq!(e.reason, R::CommunityBirth, "{e}");

    // a founder who did not sign the birth (signatures are not content)
    let e = reason(
        verify_ceremony_outputs(&json(&with_birth(&c.bundle, |b| {
            b.cosignatures.pop();
        })))
        .await,
    );
    assert_eq!(e.reason, R::CommunityBirth, "{e}");

    // the birth's content changed after the holders authorized the bundle:
    // a node member the bundle does not anchor, or a renamed community
    for tampered in [
        with_birth(&c.bundle, |b| {
            for m in &mut b.community.members {
                if m.key_id == TEST_CEREMONY_NODE_KEY_ID {
                    m.key_id = "unanchored-node".into();
                }
            }
        }),
        with_birth(&c.bundle, |b| {
            b.community.community_name = "Somebody Else's Services".into();
        }),
    ] {
        let e = reason(verify_ceremony_outputs(&json(&tampered)).await);
        assert_eq!(e.reason, R::BundleQuorum, "{e}");
    }

    // the accord family record: a holder's signature missing, or absent
    let e = reason(
        verify_ceremony_outputs(&json(&with_family(&c.bundle, |f| {
            f.cosignatures.pop();
        })))
        .await,
    );
    assert_eq!(e.reason, R::FamilyRecord, "{e}");
    let mut bf = c.bundle.clone();
    bf.roster_records
        .retain(|r| !matches!(r, GenesisRosterRecord::Family(_)));
    let e = reason(verify_ceremony_outputs(&json(&bf)).await);
    assert_eq!(e.reason, R::FamilyRecord, "{e}");

    // a delegation row or a serve node altered after the holders authorized
    // the bundle: the authorization digest binds both, so the quorum fails
    let mut b3 = c.bundle.clone();
    b3.attestations[1].attestation.attestation_envelope["scope"] =
        serde_json::json!(["infra:serve"]);
    let e = reason(verify_ceremony_outputs(&json(&b3)).await);
    assert_eq!(e.reason, R::BundleQuorum, "{e}");
    let mut b4 = c.bundle.clone();
    b4.serve_nodes[0].record.identity_type = "canonical,node,steward".into();
    let e = reason(verify_ceremony_outputs(&json(&b4)).await);
    assert_eq!(e.reason, R::BundleQuorum, "{e}");

    // a correctly authorized bundle whose rows the write door refuses (stamped
    // 15 minutes ahead): caught at the bake stage, by the door's own rule
    let f = mint(900);
    let e = reason(verify_ceremony_outputs(&f.bundle_json().unwrap()).await);
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
        install_test_ceremony_outputs(c.bundle.clone());
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
            "I355b: disarmed, the compiled bundle (version 2) carries no birth"
        );
    }
}

/// **I355 — a refused birth never stops the boot**: the leg is Absent, the
/// rest is seeded. (The birth's signatures are stripped inside the bundle:
/// evidence, not content, so the bundle's own quorum still verifies.)
#[serial_test::serial(test_anchor_env)]
#[tokio::test]
async fn i355_refused_community_asset_boots_absent() {
    let c = mint(-5);
    let _armed = Armed::with(&c.block);
    let b = sqlite().await;
    install_test_ceremony_outputs(with_birth(&c.bundle, |b| b.cosignatures.clear()));
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

// ── v53.0.0 — the production assembler (genesis::ceremony), I420–I427 ──

use ciris_persist::federation::genesis::ceremony::{
    CeremonyError, CeremonyState, Partial, AUTHZ_ITEM_ID,
};

/// A planned ceremony over the software holders, and the holders to sign with.
fn planned(
    produced_at: chrono::DateTime<chrono::Utc>,
) -> (
    CeremonyState,
    Vec<ciris_persist::federation::accord_test_support::Identity>,
) {
    let (_, holders, inputs) =
        test_ceremony_inputs(&SEEDS, &NODE_SEED, produced_at, None).expect("inputs");
    (CeremonyState::plan(inputs).expect("plan"), holders)
}

fn partial(
    h: &ciris_persist::federation::accord_test_support::Identity,
    item: &str,
    bytes: &[u8],
) -> Partial {
    let (classical, pqc) = h.sign_bytes(bytes);
    Partial {
        item: item.to_owned(),
        holder_key_id: h.key_id.clone(),
        signature_classical: classical,
        signature_pqc: pqc,
    }
}

/// **I420 — the plan refuses inputs that cannot form a ceremony, and a state
/// survives serialization with the same items, byte for byte.**
#[test]
fn i420_plan_refuses_and_state_round_trips() {
    let at = at(-5);
    let (_, _, inputs) = test_ceremony_inputs(&SEEDS, &NODE_SEED, at, None).unwrap();
    let refused =
        |mutate: &dyn Fn(&mut ciris_persist::federation::genesis::ceremony::CeremonyInputs)| {
            let mut i = inputs.clone();
            mutate(&mut i);
            match CeremonyState::plan(i) {
                Err(CeremonyError::InvalidInputs(d)) => d,
                other => panic!("I420: expected InvalidInputs, got {other:?}"),
            }
        };
    // a holder without a recovery key (CC 4.2.6)
    let d = refused(&|i| {
        i.recovery_keys.pop_first();
    });
    assert!(d.contains("recovery key"), "{d}");
    // a recovery key that is a holder signing key
    let d = refused(&|i| {
        let h = i.holders[1].record.key_id.clone();
        let first = i.recovery_keys.keys().next().unwrap().clone();
        i.recovery_keys.get_mut(&first).unwrap().key_id = h;
    });
    assert!(d.contains("held apart"), "{d}");
    // one recovery key shared by two holders
    let d = refused(&|i| {
        let mut keys = i.recovery_keys.values().cloned();
        let shared = keys.next().unwrap();
        for v in i.recovery_keys.values_mut() {
            *v = shared.clone();
        }
    });
    assert!(d.contains("shared"), "{d}");
    // a holder listed twice, no serve node, no successors
    assert!(refused(&|i| {
        let dup = i.holders[0].clone();
        i.holders.push(dup);
    })
    .contains("twice"));
    assert!(refused(&|i| i.serve_nodes.clear()).contains("serve node"));
    assert!(refused(&|i| i.successor_keys.clear()).contains("successor"));
    // a holder record without its ML-DSA half cannot be committed to
    assert!(refused(&|i| i.holders[2].record.pubkey_ml_dsa_65_base64 = None).contains("ML-DSA"));

    let (state, _) = planned(at);
    let back = CeremonyState::from_json(&state.to_json().unwrap()).unwrap();
    assert_eq!(back, state, "I420: the state round-trips");
    assert_eq!(
        back.items().unwrap(),
        state.items().unwrap(),
        "I420: same bytes"
    );
    let mut v: serde_json::Value = serde_json::from_str(&state.to_json().unwrap()).unwrap();
    v["version"] = serde_json::json!(99);
    assert!(matches!(
        CeremonyState::from_json(&v.to_string()),
        Err(CeremonyError::StateVersion(99))
    ));
    // every item, every holder owed, in item order, authorization last
    let ids: Vec<String> = state.items().unwrap().into_iter().map(|i| i.id).collect();
    assert_eq!(
        ids,
        vec![
            format!("record:{TEST_CEREMONY_NODE_KEY_ID}"),
            "row:genesis-charter".to_owned(),
            format!("row:genesis-grant:{TEST_CEREMONY_NODE_KEY_ID}"),
            "row:genesis-lifecycle".to_owned(),
            "family:humanity-accord".to_owned(),
            format!("community:{CANON}"),
            AUTHZ_ITEM_ID.to_owned(),
        ],
        "I420: the items"
    );
}

/// **I421 — partials arriving in any order, across serialized states, form
/// the bundle the minter forms, byte for byte.**
#[test]
fn i421_any_order_across_requests_is_byte_identical() {
    let at = at(-5);
    let minted = mint_test_ceremony(&SEEDS, &NODE_SEED, at).unwrap();
    let (mut state, holders) = planned(at);
    // round by round: last holder first, last item first, a serialize/parse
    // between every partial
    loop {
        let items = state.next_items().unwrap();
        if items.is_empty() {
            break;
        }
        for h in holders.iter().rev() {
            for item in items.iter().rev() {
                let json = state.to_json().unwrap();
                state = CeremonyState::from_json(&json).unwrap();
                state
                    .add_partial(partial(h, &item.id, &item.bytes))
                    .expect("I421: a good partial");
            }
        }
    }
    let bundle = state.assemble().expect("I421: complete");
    assert_eq!(
        serde_json::to_value(&bundle).unwrap(),
        serde_json::to_value(&minted.bundle).unwrap(),
        "I421: the assembled bundle is the minted one"
    );
    // and it parses back to the same bytes (one spelling)
    let reparsed = parse_genesis_bundle(&serde_json::to_string(&bundle).unwrap()).unwrap();
    assert_eq!(
        serde_json::to_string(&reparsed).unwrap(),
        serde_json::to_string(&bundle).unwrap()
    );
}

/// **I422 — a partial is verified when it arrives and refused by name.**
#[test]
fn i422_add_partial_refuses_by_name() {
    let (mut state, holders) = planned(at(-5));
    let items = state.items().unwrap();
    let charter = items
        .iter()
        .find(|i| i.id == "row:genesis-charter")
        .unwrap();
    let family = items
        .iter()
        .find(|i| i.id == "row:genesis-lifecycle")
        .unwrap();
    // an item that waits on the charter is not signable yet
    let heads = items.iter().find(|i| i.id.starts_with("family:")).unwrap();
    assert!(heads.bytes.is_empty() && heads.waits_on == vec![charter.id.clone()]);
    let e = state
        .add_partial(partial(&holders[0], &heads.id, &charter.bytes))
        .unwrap_err();
    assert_eq!(e.as_str(), "ceremony_item_not_ready", "{e}");
    // unknown item
    let mut p = partial(&holders[0], &charter.id, &charter.bytes);
    p.item = "row:nonesuch".into();
    let e = state.add_partial(p).unwrap_err();
    assert_eq!(e.as_str(), "ceremony_item_unknown", "{e}");
    // a signer that is not a holder
    let stranger = ciris_persist::federation::accord_test_support::Identity::new("stranger");
    let e = state
        .add_partial(partial(&stranger, &charter.id, &charter.bytes))
        .unwrap_err();
    assert_eq!(e.as_str(), "ceremony_signer_not_a_holder", "{e}");
    // signed over another item's bytes: the classical half fails
    let e = state
        .add_partial(partial(&holders[0], &charter.id, &family.bytes))
        .unwrap_err();
    assert_eq!(e.as_str(), "ceremony_signature_invalid", "{e}");
    // a good classical half with the PQC half of another item
    let good = partial(&holders[0], &charter.id, &charter.bytes);
    let mut half = good.clone();
    half.signature_pqc = partial(&holders[0], &family.id, &family.bytes).signature_pqc;
    let e = state.add_partial(half).unwrap_err();
    assert_eq!(e.as_str(), "ceremony_signature_invalid", "{e}");
    // another holder's signature under this holder's name
    let mut borrowed = partial(&holders[1], &charter.id, &charter.bytes);
    borrowed.holder_key_id = holders[0].key_id.clone();
    let e = state.add_partial(borrowed).unwrap_err();
    assert_eq!(e.as_str(), "ceremony_signature_invalid", "{e}");
    // nothing refused was recorded
    assert!(state.partials.is_empty(), "I422: refusals record nothing");
    // the good one; again is a no-op; a different one conflicts
    state.add_partial(good.clone()).unwrap();
    state.add_partial(good.clone()).unwrap();
    let mut other = good;
    other.signature_classical = partial(&holders[0], &family.id, &family.bytes).signature_classical;
    let e = state.add_partial(other).unwrap_err();
    // (the classical half no longer verifies, so it is refused before the conflict)
    assert_eq!(e.as_str(), "ceremony_signature_invalid", "{e}");
}

/// **I423 — nothing assembles while a signature is owed; every holder signs
/// every item (the founding rule: no 2-of-3 at the mint).**
#[test]
fn i423_incomplete_names_what_is_owed() {
    let (mut state, holders) = planned(at(-5));
    // two of three on every item signable now
    for item in state.next_items().unwrap() {
        for h in &holders[..2] {
            state
                .add_partial(partial(h, &item.id, &item.bytes))
                .unwrap();
        }
    }
    match state.assemble() {
        Err(CeremonyError::Incomplete(owed)) => {
            assert_eq!(owed.len(), 7, "I423: every item still owes: {owed:?}");
            // the four signable items owe the third holder; the heads and the
            // authorization, still waiting on the charter, owe all three
            let third = vec![holders[2].key_id.clone()];
            assert_eq!(owed.values().filter(|o| **o == third).count(), 4);
            assert_eq!(owed.values().filter(|o| o.len() == 3).count(), 3);
        }
        other => panic!("I423: expected Incomplete, got {other:?}"),
    }
    assert_eq!(
        state.next_items().unwrap().len(),
        4,
        "I423: the waiting three are not offered"
    );
    // the third holder signs the charter: the heads and the authorization open
    let charter = state
        .items()
        .unwrap()
        .into_iter()
        .find(|i| i.id == "row:genesis-charter")
        .unwrap();
    state
        .add_partial(partial(&holders[2], &charter.id, &charter.bytes))
        .unwrap();
    let next: Vec<String> = state
        .next_items()
        .unwrap()
        .into_iter()
        .map(|i| i.id)
        .collect();
    assert_eq!(next.len(), 6, "I423: {next:?}");
    assert!(next.contains(&AUTHZ_ITEM_ID.to_owned()));
    assert!(state.items().unwrap().iter().all(|i| i.waits_on.is_empty()));
}

/// **I424 — `finish` ends in the ordinary doors and passes**; the outputs boot
/// a node (I351 boots the same path on memory, sqlite and postgres).
#[serial_test::serial(test_anchor_env)]
#[tokio::test]
async fn i424_finish_runs_the_doors() {
    let c = mint(-5);
    let _armed = Armed::with(&c.block);
    let (mut state, holders) = planned(at(-5));
    // incomplete: finish refuses before any door
    assert_eq!(
        state.finish().await.unwrap_err().as_str(),
        "ceremony_incomplete"
    );
    sign_every_item(&mut state, &holders).unwrap();
    let done = state.finish().await.expect("I424: the doors admit it");
    assert_eq!(done.verified.quorum_verified, 3);
    assert_eq!(
        (
            done.verified.community_key_id.as_str(),
            done.verified.founders
        ),
        (CANON, 3)
    );
    assert_eq!(
        parse_genesis_bundle(&done.bundle_json)
            .unwrap()
            .roster_records
            .len(),
        2
    );
}

/// **I425 — the authorization digest binds the roster records' signed
/// content and nothing about their signatures; a bundle with no records is
/// digested exactly as before (the baked version-2 seed still verifies).**
#[test]
fn i425_digest_binds_record_content_not_signatures() {
    use ciris_persist::federation::genesis::bundle::authorization_digest;
    let c = mint(-5);
    let base = authorization_digest(&c.bundle).unwrap();
    let mut signatures_only = c.bundle.clone();
    for r in &mut signatures_only.roster_records {
        match r {
            GenesisRosterRecord::Family(f) => f.cosignatures.clear(),
            GenesisRosterRecord::Community(x) => x.scrub_signature_classical = "x".into(),
        }
    }
    assert_eq!(authorization_digest(&signatures_only).unwrap(), base);
    for k in 0..2 {
        let mut content = c.bundle.clone();
        match &mut content.roster_records[k] {
            GenesisRosterRecord::Family(f) => f.family.members.pop().map(|_| ()).unwrap(),
            GenesisRosterRecord::Community(x) => x.community.community_name.push('!'),
        }
        assert_ne!(
            authorization_digest(&content).unwrap(),
            base,
            "I425: record {k}"
        );
    }
    let mut dropped = c.bundle.clone();
    dropped.roster_records.pop();
    assert_ne!(authorization_digest(&dropped).unwrap(), base);
    // The baked version-2 seed carries no records and still verifies (its
    // authorizations were taken over the pre-v53 preimage).
    let baked = parse_genesis_bundle(include_str!(
        "../src/federation/genesis/canonical_seed.json"
    ))
    .unwrap();
    assert_eq!((baked.version, baked.roster_records.len()), (2, 0));
}

/// **I426 — the wire: the records are members of `attestations`, after every
/// row, each recognised by its one key; any other spelling is refused.**
#[test]
fn i426_records_are_members_of_attestations() {
    let c = mint(-5);
    let v = serde_json::to_value(&c.bundle).unwrap();
    let list = v["attestations"].as_array().unwrap();
    assert!(
        v.get("roster_records").is_none(),
        "I426: no field beside attestations"
    );
    assert_eq!(list.len(), 5);
    assert!(list[..3].iter().all(|e| e.get("attestation").is_some()));
    assert!(list[3].get("family").is_some() && list[4].get("community").is_some());
    let refused = |v: serde_json::Value| parse_genesis_bundle(&v.to_string()).unwrap_err();
    let mut two_keys = v.clone();
    two_keys["attestations"][4]["family"] = list[3]["family"].clone();
    assert!(refused(two_keys).to_string().contains("exactly one"));
    let mut neither = v.clone();
    neither["attestations"][0] = serde_json::json!({"row": 1});
    assert!(refused(neither).to_string().contains("exactly one"));
    let mut late_row = v.clone();
    let row = late_row["attestations"].as_array_mut().unwrap().remove(0);
    late_row["attestations"].as_array_mut().unwrap().push(row);
    assert!(refused(late_row)
        .to_string()
        .contains("follows a roster record"));
}

/// **I427 — the assembler reads no clock: every instant derives from the one
/// `produced_at` the caller stamped, truncated to the microsecond.**
#[test]
fn i427_every_instant_is_the_stamp() {
    let stamp: chrono::DateTime<chrono::Utc> = "2026-10-02T12:00:00.123456789Z".parse().unwrap();
    let micro: chrono::DateTime<chrono::Utc> = "2026-10-02T12:00:00.123456Z".parse().unwrap();
    let (state, holders) = planned(stamp);
    assert_eq!(state.inputs.produced_at, micro, "I427: truncated at plan");
    let first = state.items().unwrap();
    std::thread::sleep(std::time::Duration::from_millis(20));
    assert_eq!(
        state.items().unwrap(),
        first,
        "I427: the bytes do not move with the clock"
    );
    let mut state = state;
    sign_every_item(&mut state, &holders).unwrap();
    let b = state.assemble().unwrap();
    assert_eq!(b.produced_at, micro.to_rfc3339());
    assert_eq!(b.serve_nodes[0].record.valid_from, micro);
    // a row's signed instant is stamped at millisecond precision
    // (`stamp_signed_instants`), the rows 1 ms apart from the stamp
    for (k, row) in b.attestations.iter().enumerate() {
        assert_eq!(
            row.attestation.asserted_at.timestamp_millis(),
            micro.timestamp_millis() + i64::try_from(k).unwrap()
        );
    }
    assert_eq!(
        b.community_record(CANON).unwrap().community.founded_at,
        micro
    );
}

/// The upgrade body shared by the backends: a node that ran v52 holds the
/// accord row v52 seeded — no charter named, no predecessor — so under v53 the
/// accord has no charter in force. Booting against the final bundle replaces
/// it with the bundle's genesis record itself.
async fn upgrades_from_v52(d: &dyn FederationDirectory, c: &TestCeremonyOutputs, tag: &str) {
    use ciris_persist::federation::canonical_community::{charter_in_force, HeadCharter};
    use ciris_persist::federation::types::compute_persist_row_hash;
    let accord = ciris_verify_core::accord_genesis::HUMANITY_ACCORD_FAMILY_KEY_ID;
    let roster: Vec<String> = effective_accord_holder_records()
        .iter()
        .map(|r| r.record.key_id.clone())
        .collect();
    let v52 = accord_family_genesis_record_for(
        accord,
        ciris_verify_core::accord_genesis::ACCORD_CONSENSUS_PROTOCOL,
        roster.iter().map(String::as_str),
        "",
    );
    d.put_family_local(v52).await.expect("the v52 accord row");
    let held_v52 = d.lookup_family(accord).await.unwrap().unwrap();
    assert_eq!(
        charter_in_force(d, accord).await.unwrap(),
        (accord.to_owned(), HeadCharter::Unnamed),
        "{tag} I428: control — the v52 row names no charter"
    );

    install_test_ceremony_outputs(c.bundle.clone());
    seed_family_and_canonical(d)
        .await
        .unwrap_or_else(|e| panic!("{tag} I428: the upgraded boot: {e:?}"));

    let carried = c
        .bundle
        .family_record(accord)
        .expect("the bundle's accord record");
    let digest = bundle_family_charter_digest(&c.bundle);
    assert!(!digest.is_empty());
    let held = d.lookup_family(accord).await.unwrap().unwrap();
    assert_eq!(
        (held.charter_digest.as_str(), held.prev_head_digest.as_str()),
        (digest.as_str(), ""),
        "{tag} I428: the head is the genesis record (CC T6: empty prev at genesis)"
    );
    assert_eq!(
        held.persist_row_hash,
        compute_persist_row_hash(&carried.family).unwrap(),
        "{tag} I428: the same head digest a fresh node holds"
    );
    let versions = d
        .list_group_versions(ciris_persist::federation::cohort::Cohort::Family, accord)
        .await
        .unwrap();
    assert_eq!(versions.len(), 2, "{tag} I428: {versions:?}");
    assert_eq!(
        versions[0].authorization.as_ref().unwrap()["accord_birth_replaces_unrooted"],
        serde_json::json!(held_v52.persist_row_hash),
        "{tag} I428: the v52 row is the superseded prior, labelled"
    );
    assert_eq!(
        charter_in_force(d, accord).await.unwrap(),
        (accord.to_owned(), HeadCharter::Named(digest)),
        "{tag} I428: the bundle's charter is in force"
    );
    // The accord root is valid for a node that accepts it.
    let user = format!("i428-user-{tag}");
    ciris_persist::federation::accord_test_support::register_typed_key(
        d,
        &user,
        ciris_persist::federation::types::identity_type::USER,
    )
    .await
    .unwrap();
    ciris_persist::federation::accord_test_support::emit_trust_edge(d, &user, accord, None)
        .await
        .unwrap();
    let verdict = ciris_persist::federation::trust_root::trust_root_valid(d, &user, accord)
        .await
        .unwrap();
    assert!(
        verdict.valid && verdict.root_self_declares,
        "{tag} I428: the accord root is valid with its charter in force: {verdict:?}"
    );
    assert!(
        matches!(genesis_posture(d).await, GenesisPosture::Entrenched),
        "{tag} I428: entrenched"
    );
    // A second boot changes nothing: the held head names a charter now.
    seed_family_and_canonical(d).await.unwrap();
    assert_eq!(
        d.lookup_family(accord)
            .await
            .unwrap()
            .unwrap()
            .persist_row_hash,
        held.persist_row_hash
    );
}

/// **I428 — a node upgrading from v52 takes the bundle's accord genesis
/// record** over the chartless row v52 seeded, and the accord root is valid
/// with the bundle's charter in force (sqlite, memory).
#[serial_test::serial(test_anchor_env)]
#[tokio::test]
async fn i428_v52_accord_row_takes_the_genesis_head() {
    let c = mint(-5);
    let _armed = Armed::with(&c.block);
    upgrades_from_v52(&sqlite().await, &c, "sqlite").await;
    upgrades_from_v52(&memory().await, &c, "memory").await;
}

/// **I428b — only a chartless row of this build's accord is replaced**: a held
/// accord of other seats is left standing (#648), and so is one that already
/// names a charter (a version chain).
#[serial_test::serial(test_anchor_env)]
#[tokio::test]
async fn i428b_other_accord_rows_are_left_standing() {
    let c = mint(-5);
    let _armed = Armed::with(&c.block);
    let accord = ciris_verify_core::accord_genesis::HUMANITY_ACCORD_FAMILY_KEY_ID;
    let roster: Vec<String> = effective_accord_holder_records()
        .iter()
        .map(|r| r.record.key_id.clone())
        .collect();
    for (tag, row) in [
        (
            "other seats",
            accord_family_genesis_record_for(
                accord,
                ciris_verify_core::accord_genesis::ACCORD_CONSENSUS_PROTOCOL,
                roster[..2].iter().map(String::as_str),
                "",
            ),
        ),
        (
            "names a charter",
            accord_family_genesis_record_for(
                accord,
                ciris_verify_core::accord_genesis::ACCORD_CONSENSUS_PROTOCOL,
                roster.iter().map(String::as_str),
                &"ab".repeat(32),
            ),
        ),
    ] {
        let d = memory().await;
        d.put_family_local(row).await.unwrap();
        let before = d.lookup_family(accord).await.unwrap().unwrap();
        install_test_ceremony_outputs(c.bundle.clone());
        let _ = seed_family_and_canonical(&d).await;
        assert_eq!(
            d.lookup_family(accord).await.unwrap().unwrap(),
            before,
            "I428b ({tag}): left standing"
        );
    }
}

/// I428 on postgres, when a test database is provided.
#[cfg(feature = "postgres")]
#[serial_test::serial(test_anchor_env)]
#[tokio::test]
async fn i428_v52_accord_row_takes_the_genesis_head_postgres() {
    let Ok(base) = std::env::var("CIRIS_PERSIST_TEST_PG_URL") else {
        eprintln!("skipping: CIRIS_PERSIST_TEST_PG_URL unset");
        return;
    };
    let cut = base.rfind('/').expect("dsn has a database");
    let name = format!(
        "ciris_t_{}_{}",
        std::process::id(),
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_nanos()
    );
    {
        let (admin, conn) = tokio_postgres::connect(&base, tokio_postgres::NoTls)
            .await
            .expect("connect to the base test database");
        tokio::spawn(conn);
        admin
            .batch_execute(&format!("CREATE DATABASE \"{name}\""))
            .await
            .expect("create this test's database");
    }
    let dsn = format!("{}/{name}", &base[..cut]);
    let c = mint(-5);
    let _armed = Armed::with(&c.block);
    {
        let b = ciris_persist::store::postgres::PostgresBackend::connect(&dsn)
            .await
            .unwrap();
        b.run_migrations().await.unwrap();
        b.seed_genesis_accord_holders(&effective_accord_holder_records())
            .await
            .expect("seed holders");
        upgrades_from_v52(&b, &c, "postgres").await;
    }
    if let Ok((admin, conn)) = tokio_postgres::connect(&base, tokio_postgres::NoTls).await {
        tokio::spawn(conn);
        let _ = admin
            .batch_execute(&format!("DROP DATABASE IF EXISTS \"{name}\" WITH (FORCE)"))
            .await;
    }
}

// ── v53.0.0 — an accord holder's recovery (CC 4.2.6), I429 ──

use ciris_persist::federation::accord_recovery::{
    draft_accord_recovery, recover_accord_holder, recovery_commitment_in_force,
    AccordRecoveryRequest,
};
use ciris_persist::federation::accord_test_support::Identity;

/// A software key registered under its own id.
async fn register(d: &dyn FederationDirectory, who: &Identity) {
    d.put_public_key(ciris_persist::federation::SignedKeyRecord {
        record: who.steward_key_record(),
    })
    .await
    .unwrap_or_else(|e| panic!("register {}: {e}", who.key_id));
}

/// Holder `k`'s committed recovery key as a signer.
fn recovery_identity(k: usize) -> Identity {
    let seed = test_ceremony_recovery_seed(&SEEDS[k]);
    Identity::from_seeds(
        &format!("test-accord-holder-{k}-recovery"),
        &seed,
        &test_anchor_mldsa_seed(&seed),
    )
    .unwrap()
}

fn refusal(e: ciris_persist::federation::Error) -> String {
    e.to_string()
}

/// One rotation: `old` → `new` under `recovery`, naming `next` (a key id whose
/// test pair becomes the new key's committed recovery key).
async fn rotate(
    d: &dyn FederationDirectory,
    old: &str,
    new: &Identity,
    recovery: &Identity,
    next: &str,
) -> Result<u32, ciris_persist::federation::Error> {
    let accord = ciris_verify_core::accord_genesis::HUMANITY_ACCORD_FAMILY_KEY_ID;
    let next_commitment = ciris_persist::federation::trust_root::recovery_commitment(
        &ciris_persist::federation::trust_root::test_committed_key(next),
    )
    .unwrap();
    let draft = draft_accord_recovery(
        d,
        &AccordRecoveryRequest {
            family_key_id: accord.to_owned(),
            old_holder_key_id: old.to_owned(),
            new_holder_key_id: new.key_id.clone(),
            recovery_key_id: recovery.key_id.clone(),
            next_recovery_commitment: next_commitment,
            joined_at: "2026-10-02T12:00:00Z".parse().unwrap(),
        },
    )
    .await?;
    let r = recovery.sign_bytes(&draft.statement_bytes);
    let n = new.sign_bytes(&draft.record_bytes);
    recover_accord_holder(d, draft, r, n).await
}

async fn accord_head(d: &dyn FederationDirectory) -> ciris_persist::federation::types::Family {
    d.lookup_family(ciris_verify_core::accord_genesis::HUMANITY_ACCORD_FAMILY_KEY_ID)
        .await
        .unwrap()
        .unwrap()
}

/// The recovery body shared by the backends.
async fn recovers(d: &dyn FederationDirectory, c: &TestCeremonyOutputs, tag: &str) {
    boots_fully_seeded(d, c, tag).await;
    let accord = ciris_verify_core::accord_genesis::HUMANITY_ACCORD_FAMILY_KEY_ID;
    let before = accord_head(d).await;

    // A squatter registers holder 1's committed recovery id with its own keys.
    let mut posing = Identity::new("i429-squatter");
    posing.key_id = recovery_identity(1).key_id.clone();
    register(d, &posing).await;
    let n1 = Identity::new(&format!("i429-new-1-{tag}"));
    register(d, &n1).await;
    let e = rotate(d, "test-accord-holder-1", &n1, &posing, "i429-next-x")
        .await
        .unwrap_err();
    assert!(
        e.to_string().contains("accord_recovery_key_mismatch"),
        "{tag} I429: a squatted recovery id is refused: {e}"
    );
    assert_eq!(accord_head(d).await, before, "{tag} I429: nothing written");

    // The real recovery of holder 0: no quorum, one seat swapped.
    let r0 = recovery_identity(0);
    register(d, &r0).await;
    let n0 = Identity::new(&format!("i429-new-0-{tag}"));
    register(d, &n0).await;
    // the record signed by a key other than the one taking the seat: refused
    let wrong = Identity::new("i429-wrong");
    {
        let accord_req = AccordRecoveryRequest {
            family_key_id: accord.to_owned(),
            old_holder_key_id: "test-accord-holder-0".into(),
            new_holder_key_id: n0.key_id.clone(),
            recovery_key_id: r0.key_id.clone(),
            next_recovery_commitment: ciris_persist::federation::trust_root::recovery_commitment(
                &ciris_persist::federation::trust_root::test_committed_key("i429-next-0"),
            )
            .unwrap(),
            joined_at: "2026-10-02T12:00:00Z".parse().unwrap(),
        };
        let draft = draft_accord_recovery(d, &accord_req).await.unwrap();
        let r = r0.sign_bytes(&draft.statement_bytes);
        let n = wrong.sign_bytes(&draft.record_bytes);
        assert!(recover_accord_holder(d, draft.clone(), r.clone(), n)
            .await
            .is_err());
        // a statement signed by the new key instead of the recovery key: refused
        let n_ok = n0.sign_bytes(&draft.record_bytes);
        let not_r = n0.sign_bytes(&draft.statement_bytes);
        let e = recover_accord_holder(d, draft, not_r, n_ok)
            .await
            .unwrap_err();
        assert!(refusal(e).contains("accord_recovery_signature"), "{tag}");
        assert_eq!(accord_head(d).await, before, "{tag} I429: nothing written");
    }
    rotate(d, "test-accord-holder-0", &n0, &r0, "i429-next-0")
        .await
        .unwrap_or_else(|e| panic!("{tag} I429: the holder's own recovery: {e}"));
    let after = accord_head(d).await;
    let seats: Vec<&str> = after.members.iter().map(|m| m.key_id.as_str()).collect();
    assert!(
        seats.contains(&n0.key_id.as_str()) && !seats.contains(&"test-accord-holder-0"),
        "{tag} I429: the seat moved: {seats:?}"
    );
    assert_eq!(after.members.len(), before.members.len());
    assert_eq!(
        after.prev_head_digest, before.persist_row_hash,
        "{tag} I429: a new version"
    );
    assert_eq!(
        after.charter_digest, before.charter_digest,
        "{tag} I429: the charter stays"
    );
    assert_eq!(
        (after.consensus_protocol.as_str(), after.founded_at),
        (before.consensus_protocol.as_str(), before.founded_at)
    );
    let next0 = ciris_persist::federation::trust_root::recovery_commitment(
        &ciris_persist::federation::trust_root::test_committed_key("i429-next-0"),
    )
    .unwrap();
    assert_eq!(
        recovery_commitment_in_force(d, accord, &n0.key_id)
            .await
            .unwrap(),
        Some(next0),
        "{tag} I429: the new key's own recovery commitment is in force"
    );

    // The new holder recovers in turn under "i429-next-0", naming holder 0's
    // spent key as its successor's recovery key; that successor's recovery
    // under the spent key is refused.
    let r_next0 = Identity::new("i429-next-0");
    register(d, &r_next0).await;
    let m = Identity::new(&format!("i429-m-{tag}"));
    register(d, &m).await;
    let r0_as_id = r0.key_id.clone();
    // the next commitment names r0's own material
    let r0_commitment = ciris_persist::federation::trust_root::recovery_commitment(
        &ciris_persist::federation::trust_root::CommittedKey::from_record(
            &d.lookup_public_key(&r0_as_id).await.unwrap().unwrap(),
        )
        .unwrap(),
    )
    .unwrap();
    let draft = draft_accord_recovery(
        d,
        &AccordRecoveryRequest {
            family_key_id: accord.to_owned(),
            old_holder_key_id: n0.key_id.clone(),
            new_holder_key_id: m.key_id.clone(),
            recovery_key_id: "i429-next-0".into(),
            next_recovery_commitment: r0_commitment,
            joined_at: "2026-10-02T13:00:00Z".parse().unwrap(),
        },
    )
    .await
    .unwrap();
    let (r, n) = (
        r_next0.sign_bytes(&draft.statement_bytes),
        m.sign_bytes(&draft.record_bytes),
    );
    recover_accord_holder(d, draft, r, n)
        .await
        .unwrap_or_else(|e| panic!("{tag} I429: the second recovery: {e}"));
    let x = Identity::new(&format!("i429-x-{tag}"));
    register(d, &x).await;
    let e = rotate(d, &m.key_id, &x, &r0, "i429-next-x")
        .await
        .unwrap_err();
    assert!(
        e.to_string().contains("accord_recovery_key_spent"),
        "{tag} I429: a recovery key rotates one seat once: {e}"
    );
}

/// **I429 — a holder rotates their own seat under their pre-committed
/// recovery key (CC 4.2.6)**: no quorum, one seat, a new version naming the
/// held head; a squatted recovery id, a statement not signed by the recovery
/// key and a record not signed by the new key are refused; a recovery key is
/// spent after one rotation (sqlite, memory).
#[serial_test::serial(test_anchor_env)]
#[tokio::test]
async fn i429_recovery_rotates_one_seat_without_quorum() {
    let c = mint(-5);
    let _armed = Armed::with(&c.block);
    recovers(&sqlite().await, &c, "sqlite").await;
    recovers(&memory().await, &c, "memory").await;
}

/// I429 on postgres, when a test database is provided.
#[cfg(feature = "postgres")]
#[serial_test::serial(test_anchor_env)]
#[tokio::test]
async fn i429_recovery_rotates_one_seat_without_quorum_postgres() {
    let Ok(base) = std::env::var("CIRIS_PERSIST_TEST_PG_URL") else {
        eprintln!("skipping: CIRIS_PERSIST_TEST_PG_URL unset");
        return;
    };
    let cut = base.rfind('/').expect("dsn has a database");
    let name = format!(
        "ciris_t_{}_{}",
        std::process::id(),
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_nanos()
    );
    {
        let (admin, conn) = tokio_postgres::connect(&base, tokio_postgres::NoTls)
            .await
            .expect("connect to the base test database");
        tokio::spawn(conn);
        admin
            .batch_execute(&format!("CREATE DATABASE \"{name}\""))
            .await
            .expect("create this test's database");
    }
    let dsn = format!("{}/{name}", &base[..cut]);
    let c = mint(-5);
    let _armed = Armed::with(&c.block);
    {
        let b = ciris_persist::store::postgres::PostgresBackend::connect(&dsn)
            .await
            .unwrap();
        b.run_migrations().await.unwrap();
        b.seed_genesis_accord_holders(&effective_accord_holder_records())
            .await
            .expect("seed holders");
        recovers(&b, &c, "postgres").await;
    }
    if let Ok((admin, conn)) = tokio_postgres::connect(&base, tokio_postgres::NoTls).await {
        tokio::spawn(conn);
        let _ = admin
            .batch_execute(&format!("DROP DATABASE IF EXISTS \"{name}\" WITH (FORCE)"))
            .await;
    }
}
