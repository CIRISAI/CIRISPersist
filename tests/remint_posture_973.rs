//! CIRISPersist#973 — **I360–I365: what the delegation leg reports for each
//! relation between the STORED plane and the BAKED one.** The production
//! upgrade path for a trust-root re-mint: a node must never brick on it, and
//! an operator must be able to see that a baked root was not adopted. Its own
//! process: every test arms the test-anchor override through the environment.

#![cfg(all(feature = "test-anchor", feature = "sqlite"))]

use ciris_persist::federation::genesis::*;
use ciris_persist::federation::FederationDirectory;
use ciris_persist::store::backend::Backend as _;
use ciris_persist::store::memory::MemoryBackend;
use ciris_persist::store::sqlite::SqliteBackend;

const SEEDS: [[u8; 32]; 3] = [[0x61; 32], [0x62; 32], [0x63; 32]];
const NODE_SEED: [u8; 32] = [0x6E; 32];
const CHARTER: &str = "genesis-charter";

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

fn mint_at(t: chrono::DateTime<chrono::Utc>, extra: Option<&str>) -> TestCeremonyOutputs {
    mint_test_ceremony_scoped(&SEEDS, &NODE_SEED, t, extra).expect("mint")
}

fn install(c: &TestCeremonyOutputs) {
    install_test_ceremony_outputs(c.bundle.clone());
}

async fn backends() -> Vec<(&'static str, Box<dyn FederationDirectory>)> {
    let s = SqliteBackend::open_in_memory().await.unwrap();
    s.run_migrations().await.unwrap();
    s.seed_genesis_accord_holders(&effective_accord_holder_records())
        .await
        .expect("seed holders");
    let m = MemoryBackend::new();
    m.seed_genesis_accord_holders(&effective_accord_holder_records())
        .await
        .expect("seed holders");
    vec![("sqlite", Box::new(s)), ("memory", Box::new(m))]
}

async fn stored(d: &dyn FederationDirectory, id: &str) -> ciris_persist::federation::Attestation {
    d.get_attestation(id)
        .await
        .unwrap()
        .unwrap_or_else(|| panic!("{id} stored"))
}

/// Boot a node against `c` and require it fully seeded.
async fn boot_seeded(d: &dyn FederationDirectory, c: &TestCeremonyOutputs, tag: &str) {
    install(c);
    seed_family_and_canonical(d)
        .await
        .unwrap_or_else(|e| panic!("{tag}: the boot seed: {e:?}"));
    assert!(
        matches!(genesis_posture(d).await, GenesisPosture::Entrenched),
        "{tag}: seeded"
    );
}

fn pre_genesis_delegation(p: &GenesisPosture) -> Option<&str> {
    match p {
        GenesisPosture::PreGenesis {
            leg: GenesisLeg::Delegation,
            detail,
            ..
        } => Some(detail.as_str()),
        _ => None,
    }
}

/// **I360 — stored IDENTICAL to the bake**: a second boot changes nothing and
/// the posture is Entrenched.
#[serial_test::serial(test_anchor_env)]
#[tokio::test]
async fn i360_identical_is_entrenched_and_untouched() {
    let c = mint_at(at(-600), None);
    let _armed = Armed::with(&c.block);
    for (tag, d) in backends().await {
        let d = d.as_ref();
        boot_seeded(d, &c, tag).await;
        let before = stored(d, CHARTER).await.persist_row_hash;
        seed_family_and_canonical(d)
            .await
            .unwrap_or_else(|e| panic!("{tag} I360: a reboot: {e:?}"));
        assert_eq!(
            stored(d, CHARTER).await.persist_row_hash,
            before,
            "{tag} I360"
        );
        verify_delegation_plane_seeded(d)
            .await
            .unwrap_or_else(|e| panic!("{tag} I360: {e:?}"));
        assert!(matches!(
            genesis_posture(d).await,
            GenesisPosture::Entrenched
        ));
    }
}

/// **I361 — bake STRICTLY NEWER, admitted**: the stored rows are superseded
/// (ids kept) and the posture is Entrenched on the new root.
#[serial_test::serial(test_anchor_env)]
#[tokio::test]
async fn i361_newer_bake_supersedes_and_is_entrenched() {
    let old = mint_at(at(-3600), None);
    let _armed = Armed::with(&old.block);
    for (tag, d) in backends().await {
        let d = d.as_ref();
        boot_seeded(d, &old, tag).await;
        let new = mint_at(at(-5), None);
        install(&new);
        seed_family_and_canonical(d)
            .await
            .unwrap_or_else(|e| panic!("{tag} I361: {e:?}"));
        assert_eq!(
            stored(d, CHARTER).await.asserted_at,
            new.bundle.attestations[0].attestation.asserted_at,
            "{tag} I361: the re-minted row is stored"
        );
        assert!(
            matches!(genesis_posture(d).await, GenesisPosture::Entrenched),
            "{tag} I361"
        );
    }
}

/// **I362 — bake strictly newer but REFUSED at the door** (stamped more than
/// 300 s ahead): the boot seed reports Absent and deletes nothing, and the
/// LIVE posture reports the same — pre-genesis on the delegation leg, naming
/// that the baked root was not adopted — never Entrenched on the old root and
/// never Divergent. When the instant comes into range the next boot adopts it.
#[serial_test::serial(test_anchor_env)]
#[tokio::test]
async fn i362_refused_newer_bake_is_visibly_not_adopted() {
    let old = mint_at(at(-3600), None);
    let _armed = Armed::with(&old.block);
    for (tag, d) in backends().await {
        let d = d.as_ref();
        boot_seeded(d, &old, tag).await;
        let before = stored(d, CHARTER).await;
        let future = mint_at(at(900), None);
        install(&future);
        match seed_family_and_canonical(d).await {
            Err(GenesisFault::Absent {
                leg,
                detail,
                reason,
            }) => {
                assert_eq!(leg, GenesisLeg::Delegation, "{tag} I362: {detail}");
                assert!(detail.contains("nothing deleted"), "{tag} I362: {detail}");
                // The typed cause: REFUSED at the door, carrying the door's
                // token, with the previous root still standing.
                assert_eq!(
                    reason,
                    AbsentReason::BakeNotAdopted {
                        why: BakeNotAdoptedReason::Refused {
                            refusal: "federation_invalid_argument".to_owned(),
                        },
                        held_root_in_force: true,
                    },
                    "{tag} I362: the seed names the refusal and the standing root"
                );
            }
            other => panic!("{tag} I362: the boot seed must report Absent, got {other:?}"),
        }
        assert_eq!(
            stored(d, CHARTER).await.persist_row_hash,
            before.persist_row_hash,
            "{tag} I362: the stored row is untouched"
        );
        let posture = genesis_posture(d).await;
        let detail = pre_genesis_delegation(&posture).unwrap_or_else(|| {
            panic!(
                "{tag} I362: the live posture must be pre-genesis on the delegation leg (the \
                 baked root was not adopted), got {posture:?}"
            )
        });
        assert!(
            detail.contains("not adopted"),
            "{tag} I362: the operator can see WHY: {detail}"
        );
        // The typed signal a host reads instead of the sentence: the stored
        // root is OLDER than the bake, the bake is not installed, and the
        // previous root is in force.
        let stored_older = AbsentReason::BakeNotAdopted {
            why: BakeNotAdoptedReason::StoredOlder,
            held_root_in_force: true,
        };
        assert_eq!(posture.absent_reason(), Some(&stored_older), "{tag} I362");
        assert!(posture.held_root_in_force(), "{tag} I362: {posture:?}");
        assert!(
            posture
                .banner()
                .is_some_and(|b| b.starts_with("ROOT NOT ADOPTED")),
            "{tag} I362: the banner must not claim the node holds no root: {:?}",
            posture.banner()
        );
        let json = serde_json::to_value(&posture).unwrap();
        assert_eq!(
            json["reason"],
            serde_json::json!({
                "kind": "bake_not_adopted",
                "why": { "cause": "stored_older" },
                "held_root_in_force": true,
            }),
            "{tag} I362: the wire shape a host reads: {json}"
        );
        assert_eq!(json["state"], "pre_genesis", "{tag} I362: {json}");
        match verify_delegation_plane_seeded(d).await {
            Err(f @ GenesisFault::Absent { .. }) => {
                assert_eq!(f.absent_reason(), Some(&stored_older), "{tag} I362: {f:?}");
            }
            other => panic!("{tag} I362: the leg itself is Absent, got {other:?}"),
        }
    }
}

/// **I363 — bake of EQUAL vintage with DIFFERENT content**: neither statement
/// supersedes the other. The seed leaves the stored row; the node boots; the
/// posture is NOT Entrenched (pre-genesis on the delegation leg), and not
/// Divergent — the stored row is a verified holder statement, not a
/// substitution.
#[serial_test::serial(test_anchor_env)]
#[tokio::test]
async fn i363_equal_vintage_different_content_is_not_entrenched() {
    let t = at(-600);
    let held = mint_at(t, None);
    let _armed = Armed::with(&held.block);
    for (tag, d) in backends().await {
        let d = d.as_ref();
        boot_seeded(d, &held, tag).await;
        let before = stored(d, CHARTER).await;
        let twin = mint_at(t, Some("infra:twin"));
        assert_eq!(
            twin.bundle.attestations[0].attestation.asserted_at, before.asserted_at,
            "{tag} I363 fixture: the same instant"
        );
        assert_ne!(
            twin.bundle.attestations[0]
                .attestation
                .original_content_hash,
            before.original_content_hash,
            "{tag} I363 fixture: different signed content"
        );
        install(&twin);
        let boot = seed_family_and_canonical(d).await;
        assert!(
            !matches!(boot, Err(GenesisFault::Divergent { .. })),
            "{tag} I363: the boot is never refused over a verified holder statement: {boot:?}"
        );
        assert_eq!(
            stored(d, CHARTER).await.persist_row_hash,
            before.persist_row_hash,
            "{tag} I363: a tie replaces nothing"
        );
        let posture = genesis_posture(d).await;
        assert!(
            pre_genesis_delegation(&posture).is_some(),
            "{tag} I363: a tie is not Entrenched and not Divergent: {posture:?}"
        );
        assert_eq!(
            posture.absent_reason(),
            Some(&AbsentReason::BakeNotAdopted {
                why: BakeNotAdoptedReason::EqualVintage,
                held_root_in_force: true,
            }),
            "{tag} I363: a tie is named as a tie, with the held root in force"
        );
        assert!(posture.held_root_in_force(), "{tag} I363");
    }
}

/// **I364 — bake OLDER than stored** (an old binary on a newer database): the
/// stored rows are not downgraded, the node boots, and the posture is
/// Entrenched on the newer verified root.
#[serial_test::serial(test_anchor_env)]
#[tokio::test]
async fn i364_older_bake_never_downgrades_and_is_entrenched() {
    let new = mint_at(at(-5), None);
    let _armed = Armed::with(&new.block);
    for (tag, d) in backends().await {
        let d = d.as_ref();
        boot_seeded(d, &new, tag).await;
        let before = stored(d, CHARTER).await;
        let old = mint_at(at(-3600), None);
        install(&old);
        seed_family_and_canonical(d)
            .await
            .unwrap_or_else(|e| panic!("{tag} I364: an old binary must boot: {e:?}"));
        assert_eq!(
            stored(d, CHARTER).await.persist_row_hash,
            before.persist_row_hash,
            "{tag} I364: never downgraded"
        );
        assert!(
            matches!(genesis_posture(d).await, GenesisPosture::Entrenched),
            "{tag} I364: the mesh's root is ahead of this binary, which is allowed"
        );
    }
}

/// **I365 — stored ABSENT**: an admissible bake installs and is Entrenched; a
/// refused one (future-dated) leaves the plane empty, the node boots, and the
/// posture is pre-genesis on the delegation leg.
#[serial_test::serial(test_anchor_env)]
#[tokio::test]
async fn i365_absent_installs_or_stays_absent() {
    let good = mint_at(at(-600), None);
    let _armed = Armed::with(&good.block);
    for (tag, d) in backends().await {
        boot_seeded(d.as_ref(), &good, tag).await;
    }
    for (tag, d) in backends().await {
        let d = d.as_ref();
        let future = mint_at(at(900), None);
        install(&future);
        match seed_family_and_canonical(d).await {
            Err(GenesisFault::Absent {
                leg: GenesisLeg::Delegation,
                reason,
                ..
            }) => {
                // Refused with NOTHING held: no root is in force.
                assert_eq!(
                    reason,
                    AbsentReason::BakeNotAdopted {
                        why: BakeNotAdoptedReason::Refused {
                            refusal: "federation_invalid_argument".to_owned(),
                        },
                        held_root_in_force: false,
                    },
                    "{tag} I365"
                );
            }
            other => panic!("{tag} I365: Absent on the delegation leg, got {other:?}"),
        }
        assert!(
            d.get_attestation(CHARTER).await.unwrap().is_none(),
            "{tag} I365: nothing installed"
        );
        let posture = genesis_posture(d).await;
        assert!(
            pre_genesis_delegation(&posture).is_some(),
            "{tag} I365: {posture:?}"
        );
        // The live posture of an empty plane is the plain pre-ceremony one.
        assert_eq!(
            posture.absent_reason(),
            Some(&AbsentReason::NotSeeded),
            "{tag} I365: {posture:?}"
        );
        assert!(!posture.held_root_in_force(), "{tag} I365");
        assert!(
            posture
                .banner()
                .is_some_and(|b| b.starts_with("PRE-GENESIS")),
            "{tag} I365: {:?}",
            posture.banner()
        );
    }
}

/// **I366 — the typed reason on the wire.** `reason` is additive: a posture
/// serialized before the field existed reads as `not_seeded`, the `state`
/// tokens are unchanged, and each reason round-trips.
#[test]
fn i366_absent_reason_wire_shape_is_additive() {
    let legacy = serde_json::json!({
        "state": "pre_genesis",
        "leg": "delegation",
        "detail": "delegation row genesis-charter is not installed",
    });
    let p: GenesisPosture = serde_json::from_value(legacy).expect("a pre-#973 posture parses");
    assert_eq!(p.absent_reason(), Some(&AbsentReason::NotSeeded));
    assert!(!p.held_root_in_force());
    assert_eq!(
        serde_json::to_value(&p).unwrap()["reason"],
        serde_json::json!({ "kind": "not_seeded" })
    );
    for (reason, json) in [
        (
            AbsentReason::BakeNotAdopted {
                why: BakeNotAdoptedReason::Refused {
                    refusal: "federation_invalid_argument".to_owned(),
                },
                held_root_in_force: true,
            },
            serde_json::json!({
                "kind": "bake_not_adopted",
                "why": { "cause": "refused", "refusal": "federation_invalid_argument" },
                "held_root_in_force": true,
            }),
        ),
        (
            AbsentReason::BakeNotAdopted {
                why: BakeNotAdoptedReason::EqualVintage,
                held_root_in_force: true,
            },
            serde_json::json!({
                "kind": "bake_not_adopted",
                "why": { "cause": "equal_vintage" },
                "held_root_in_force": true,
            }),
        ),
    ] {
        assert_eq!(serde_json::to_value(&reason).unwrap(), json);
        assert_eq!(
            serde_json::from_value::<AbsentReason>(json).unwrap(),
            reason
        );
    }
    assert_eq!(GenesisPosture::Entrenched.absent_reason(), None);
    assert!(!GenesisPosture::Entrenched.held_root_in_force());
}

/// A database of this test's own, in the cluster `CIRIS_PERSIST_TEST_PG_URL`
/// points at. The integration binaries all receive ONE database from
/// `scripts/pg_test_db.sh`; a second ceremony seeded into it (other seeds,
/// the same holder ids) reads as anchor squatting to whichever test runs
/// next. Named `ciris_t_<pid>_<nanos>`, the prefix the harness reaps by PID.
#[cfg(feature = "postgres")]
async fn own_pg_database(base: &str) -> (String, String, String) {
    let cut = base.rfind('/').expect("dsn has a database");
    let name = format!(
        "ciris_t_{}_{}",
        std::process::id(),
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_nanos()
    );
    let (admin, conn) = tokio_postgres::connect(base, tokio_postgres::NoTls)
        .await
        .expect("connect to the base test database");
    tokio::spawn(conn);
    admin
        .batch_execute(&format!("CREATE DATABASE \"{name}\""))
        .await
        .expect("create this test's database");
    (format!("{}/{name}", &base[..cut]), base.to_owned(), name)
}

/// I362 on postgres, when a test database is provided
/// (`scripts/pg_test_db.sh -- …`).
#[cfg(feature = "postgres")]
#[serial_test::serial(test_anchor_env)]
#[tokio::test]
async fn i362_refused_newer_bake_postgres() {
    let Ok(base) = std::env::var("CIRIS_PERSIST_TEST_PG_URL") else {
        eprintln!("skipping: CIRIS_PERSIST_TEST_PG_URL unset");
        return;
    };
    let (dsn, base, name) = own_pg_database(&base).await;
    let old = mint_at(at(-3600), None);
    let _armed = Armed::with(&old.block);
    {
        let b = ciris_persist::store::postgres::PostgresBackend::connect(&dsn)
            .await
            .unwrap();
        b.run_migrations().await.unwrap();
        b.seed_genesis_accord_holders(&effective_accord_holder_records())
            .await
            .expect("seed holders");
        boot_seeded(&b, &old, "postgres").await;
        let future = mint_at(at(900), None);
        install(&future);
        assert!(matches!(
            seed_family_and_canonical(&b).await,
            Err(GenesisFault::Absent { .. })
        ));
        let posture = genesis_posture(&b).await;
        assert!(
            pre_genesis_delegation(&posture).is_some(),
            "postgres I362: {posture:?}"
        );
    }
    // Best effort: the harness reaps `ciris_t_<pid>_*` of dead processes too.
    if let Ok((admin, conn)) = tokio_postgres::connect(&base, tokio_postgres::NoTls).await {
        tokio::spawn(conn);
        let _ = admin
            .batch_execute(&format!("DROP DATABASE IF EXISTS \"{name}\" WITH (FORCE)"))
            .await;
    }
}
