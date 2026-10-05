//! v53.1.0 — **I490–I499: a verified genesis bundle installed on a live node
//! (the import door), and the genesis successor rule the boot seed shares.**
//! Its own process: every test arms the test-anchor override through the
//! environment (the #738 rule).
//!
//! Two ceremonies of the SAME holders (two vintages, `produced_at` apart)
//! stand in for "the bundle this node was seeded from" and "a later one"; a
//! ceremony of OTHER holders stands in for another accord.

#![cfg(all(feature = "test-anchor", feature = "sqlite"))]

use ciris_persist::federation::canonical_community::{
    attach_head_for, charter_in_force, HeadCharter,
};
use ciris_persist::federation::genesis::*;
use ciris_persist::federation::types::compute_persist_row_hash;
use ciris_persist::federation::{Error, FederationDirectory};
use ciris_persist::store::backend::Backend as _;
use ciris_persist::store::memory::MemoryBackend;
use ciris_persist::store::sqlite::SqliteBackend;

const SEEDS: [[u8; 32]; 3] = [[0x31; 32], [0x32; 32], [0x33; 32]];
const OTHER_SEEDS: [[u8; 32]; 3] = [[0x61; 32], [0x62; 32], [0x63; 32]];
const NODE_SEED: [u8; 32] = [0x4E; 32];
const ACCORD: &str = ciris_verify_core::accord_genesis::HUMANITY_ACCORD_FAMILY_KEY_ID;
const CANON: &str = "ciris-canonical";

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

/// Two vintages of the same accord's ceremony, older first.
fn vintages() -> (TestCeremonyOutputs, TestCeremonyOutputs) {
    (
        mint_test_ceremony(&SEEDS, &NODE_SEED, at(-600)).expect("mint v1"),
        mint_test_ceremony(&SEEDS, &NODE_SEED, at(-5)).expect("mint v2"),
    )
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

/// A fresh postgres backend on its own database, when a DSN is provided.
#[cfg(feature = "postgres")]
async fn postgres() -> Option<(
    ciris_persist::store::postgres::PostgresBackend,
    String,
    String,
)> {
    let base = std::env::var("CIRIS_PERSIST_TEST_PG_URL").ok()?;
    let cut = base.rfind('/').expect("dsn has a database");
    let name = format!(
        "ciris_t_{}_{}",
        std::process::id(),
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_nanos()
    );
    let (admin, conn) = tokio_postgres::connect(&base, tokio_postgres::NoTls)
        .await
        .expect("connect to the base test database");
    tokio::spawn(conn);
    admin
        .batch_execute(&format!("CREATE DATABASE \"{name}\""))
        .await
        .expect("create this test's database");
    let dsn = format!("{}/{name}", &base[..cut]);
    let b = ciris_persist::store::postgres::PostgresBackend::connect(&dsn)
        .await
        .unwrap();
    b.run_migrations().await.unwrap();
    b.seed_genesis_accord_holders(&effective_accord_holder_records())
        .await
        .expect("seed holders");
    Some((b, base, name))
}

#[cfg(feature = "postgres")]
async fn drop_db(base: &str, name: &str) {
    if let Ok((admin, conn)) = tokio_postgres::connect(base, tokio_postgres::NoTls).await {
        tokio::spawn(conn);
        let _ = admin
            .batch_execute(&format!("DROP DATABASE IF EXISTS \"{name}\" WITH (FORCE)"))
            .await;
    }
}

/// Boot a node against `c` (the bundle compiled in, as far as this process
/// is concerned).
async fn boot(d: &dyn FederationDirectory, c: &TestCeremonyOutputs) {
    install_test_ceremony_outputs(c.bundle.clone());
    seed_family_and_canonical(d)
        .await
        .unwrap_or_else(|e| panic!("boot: {e:?}"));
}

fn genesis_head_hash(c: &TestCeremonyOutputs) -> String {
    compute_persist_row_hash(&bundle_accord_genesis(&c.bundle).family).unwrap()
}

/// Everything the door could write, as row hashes.
async fn snapshot(d: &dyn FederationDirectory) -> Vec<String> {
    let mut out = vec![
        d.lookup_family(ACCORD)
            .await
            .unwrap()
            .map(|f| f.persist_row_hash)
            .unwrap_or_default(),
        d.lookup_community(CANON)
            .await
            .unwrap()
            .map(|c| c.persist_row_hash)
            .unwrap_or_default(),
        d.lookup_public_key(TEST_CEREMONY_NODE_KEY_ID)
            .await
            .unwrap()
            .map(|k| k.persist_row_hash)
            .unwrap_or_default(),
    ];
    for id in test_ceremony_delegation_ids() {
        out.push(
            d.get_attestation(&id)
                .await
                .unwrap()
                .map(|a| a.persist_row_hash)
                .unwrap_or_default(),
        );
    }
    out
}

/// A user who accepts the accord through a labelled `trust:accepts` edge
/// naming the head this node holds; the verdict.
async fn accepts_accord(d: &dyn FederationDirectory, user: &str) -> bool {
    ciris_persist::federation::accord_test_support::register_typed_key(
        d,
        user,
        ciris_persist::federation::types::identity_type::USER,
    )
    .await
    .unwrap();
    ciris_persist::federation::accord_test_support::emit_trust_edge(d, user, ACCORD, None)
        .await
        .unwrap_or_else(|e| panic!("{user}: the accepts edge: {e}"));
    ciris_persist::federation::trust_root::trust_root_valid(d, user, ACCORD)
        .await
        .unwrap()
        .valid
}

fn outcome<'a>(r: &'a RosterInstall, kind: &str) -> &'a RosterRecordOutcome {
    &r.records
        .iter()
        .find(|x| x.kind == kind)
        .unwrap_or_else(|| panic!("a {kind} record: {r:?}"))
        .outcome
}

fn refused_with(o: &RosterRecordOutcome, token: &str) -> bool {
    matches!(o, RosterRecordOutcome::Refused { reason } if reason.starts_with(token))
}

// ── the bodies ──

/// I490 + I491 — a node seeded from ceremony v1 imports v2: the accord head
/// becomes v2's genesis head, a labelled `trust:accepts` edge naming it
/// attaches, and this node's own posture is what it was.
async fn imports_a_later_ceremony(
    d: &dyn FederationDirectory,
    v1: &TestCeremonyOutputs,
    v2: &TestCeremonyOutputs,
    tag: &str,
) {
    boot(d, v1).await;
    let posture_before = format!("{:?}", genesis_posture(d).await);
    let r = install_genesis_bundle_roster(d, &v2.bundle)
        .await
        .unwrap_or_else(|e| panic!("{tag} I490: import v2: {e}"));
    assert_eq!(
        outcome(&r, "family"),
        &RosterRecordOutcome::Successor,
        "{tag} I490: {r:?}"
    );
    assert!(
        refused_with(outcome(&r, "community"), "community_held_differs"),
        "{tag} I490: a held birth is never replaced here: {r:?}"
    );
    let head = genesis_head_hash(v2);
    assert_eq!(
        attach_head_for(d, ACCORD, chrono::Utc::now())
            .await
            .unwrap(),
        Some(head.clone()),
        "{tag} I490: the head a new accepts edge names is v2's genesis head"
    );
    assert_eq!(
        charter_in_force(d, ACCORD).await.unwrap().1,
        HeadCharter::Named(bundle_family_charter_digest(&v2.bundle)),
        "{tag} I490: v2's charter is in force"
    );
    assert!(
        accepts_accord(d, &format!("i490-user-{tag}")).await,
        "{tag} I490: the edge naming the imported head attaches and the root is valid"
    );
    assert_eq!(
        format!("{:?}", genesis_posture(d).await),
        posture_before,
        "{tag} I491: the import does not move this node's own posture"
    );
    assert_eq!(
        canonical_genesis_bundle().produced_at,
        v1.bundle.produced_at,
        "{tag} I491: the bundle this node treats as its own is still the one it was seeded from"
    );
}

/// I492 — a tampered bundle (a holder's signature over the family record
/// broken) installs nothing.
async fn tampered_installs_nothing(
    d: &dyn FederationDirectory,
    v1: &TestCeremonyOutputs,
    v2: &TestCeremonyOutputs,
    tag: &str,
) {
    boot(d, v1).await;
    let before = snapshot(d).await;
    let mut bad = v2.bundle.clone();
    for r in &mut bad.roster_records {
        if let GenesisRosterRecord::Family(f) = r {
            f.family.family_name = "NOT_THE_ACCORD".to_owned();
        }
    }
    let err = install_genesis_bundle_roster(d, &bad).await.unwrap_err();
    assert!(
        matches!(&err, Error::GenesisBundleInvalid { detail } if detail.starts_with("ceremony_family_record")),
        "{tag} I492: refused at verification, by stage: {err}"
    );
    assert_eq!(snapshot(d).await, before, "{tag} I492: nothing written");
}

/// I493 — a ceremony of OTHER holders (another accord) is refused at
/// verification and installs nothing.
async fn another_accord_is_refused(
    d: &dyn FederationDirectory,
    v1: &TestCeremonyOutputs,
    other: &TestCeremonyOutputs,
    tag: &str,
) {
    boot(d, v1).await;
    let before = snapshot(d).await;
    let err = install_genesis_bundle_roster(d, &other.bundle)
        .await
        .unwrap_err();
    assert!(
        matches!(&err, Error::GenesisBundleInvalid { detail } if detail.starts_with("ceremony_holder_roster_mismatch")),
        "{tag} I493: {err}"
    );
    assert_eq!(snapshot(d).await, before, "{tag} I493: nothing written");
}

/// I494 — re-importing the same bundle writes nothing.
async fn reimport_is_a_noop(
    d: &dyn FederationDirectory,
    v1: &TestCeremonyOutputs,
    v2: &TestCeremonyOutputs,
    tag: &str,
) {
    boot(d, v1).await;
    install_genesis_bundle_roster(d, &v2.bundle).await.unwrap();
    let before = snapshot(d).await;
    let versions = d
        .list_group_versions(ciris_persist::federation::cohort::Cohort::Family, ACCORD)
        .await
        .unwrap()
        .len();
    let r = install_genesis_bundle_roster(d, &v2.bundle).await.unwrap();
    assert_eq!(
        outcome(&r, "family"),
        &RosterRecordOutcome::AlreadyHeld,
        "{tag} I494"
    );
    for (id, o) in r.bake.serve_nodes.iter().chain(r.bake.attestations.iter()) {
        assert!(
            matches!(o, BakeItemOutcome::AlreadyPresent),
            "{tag} I494: {id}: {o:?}"
        );
    }
    assert_eq!(snapshot(d).await, before, "{tag} I494: nothing written");
    assert_eq!(
        d.list_group_versions(ciris_persist::federation::cohort::Cohort::Family, ACCORD)
            .await
            .unwrap()
            .len(),
        versions,
        "{tag} I494: no version added"
    );
}

/// I495 — a held accord row of other seats under the reserved id is refused
/// by name and survives.
async fn unrelated_held_row_survives(
    d: &dyn FederationDirectory,
    v2: &TestCeremonyOutputs,
    tag: &str,
) {
    let roster: Vec<String> = effective_accord_holder_records()
        .iter()
        .map(|r| r.record.key_id.clone())
        .collect();
    let other = accord_family_genesis_record_for(
        ACCORD,
        ciris_verify_core::accord_genesis::ACCORD_CONSENSUS_PROTOCOL,
        roster[..2].iter().map(String::as_str),
        "",
    );
    d.put_family_local(other).await.unwrap();
    let held = d.lookup_family(ACCORD).await.unwrap().unwrap();
    let r = install_genesis_bundle_roster(d, &v2.bundle)
        .await
        .unwrap_or_else(|e| panic!("{tag} I495: {e}"));
    assert!(
        refused_with(outcome(&r, "family"), "accord_head_held_differs"),
        "{tag} I495: {r:?}"
    );
    assert_eq!(
        d.lookup_family(ACCORD).await.unwrap().unwrap(),
        held,
        "{tag} I495: the held row survives"
    );
}

/// I496 — the import's successor case on the v52 shape: a chartless accord
/// row of this accord takes the bundle's genesis head.
async fn chartless_row_takes_the_head(
    d: &dyn FederationDirectory,
    v2: &TestCeremonyOutputs,
    tag: &str,
) {
    let roster: Vec<String> = effective_accord_holder_records()
        .iter()
        .map(|r| r.record.key_id.clone())
        .collect();
    d.put_family_local(accord_family_genesis_record_for(
        ACCORD,
        ciris_verify_core::accord_genesis::ACCORD_CONSENSUS_PROTOCOL,
        roster.iter().map(String::as_str),
        "",
    ))
    .await
    .unwrap();
    let r = install_genesis_bundle_roster(d, &v2.bundle)
        .await
        .unwrap_or_else(|e| panic!("{tag} I496: {e}"));
    assert_eq!(
        outcome(&r, "family"),
        &RosterRecordOutcome::Successor,
        "{tag} I496: {r:?}"
    );
    assert_eq!(
        d.lookup_family(ACCORD)
            .await
            .unwrap()
            .unwrap()
            .persist_row_hash,
        genesis_head_hash(v2),
        "{tag} I496"
    );
}

/// I497 — THE BOOT PATH: a node seeded from v1 re-boots with v2 compiled in.
/// Before v53.1.0 it kept v1's head, whose charter the re-bake superseded, and
/// the accord root read invalid while the posture said Entrenched.
async fn reboot_takes_the_later_genesis(
    d: &dyn FederationDirectory,
    v1: &TestCeremonyOutputs,
    v2: &TestCeremonyOutputs,
    tag: &str,
) {
    boot(d, v1).await;
    assert_eq!(
        d.lookup_family(ACCORD)
            .await
            .unwrap()
            .unwrap()
            .persist_row_hash,
        genesis_head_hash(v1),
        "{tag} I497: control — v1's head after the first boot"
    );
    boot(d, v2).await;
    assert_eq!(
        d.lookup_family(ACCORD)
            .await
            .unwrap()
            .unwrap()
            .persist_row_hash,
        genesis_head_hash(v2),
        "{tag} I497: the re-boot holds v2's genesis head — the one a fresh node holds"
    );
    assert_eq!(
        charter_in_force(d, ACCORD).await.unwrap().1,
        HeadCharter::Named(bundle_family_charter_digest(&v2.bundle)),
        "{tag} I497"
    );
    assert!(
        accepts_accord(d, &format!("i497-user-{tag}")).await,
        "{tag} I497: the accord root is valid after the re-genesis"
    );
    assert!(
        matches!(genesis_posture(d).await, GenesisPosture::Entrenched),
        "{tag} I497"
    );
    // A third boot changes nothing.
    boot(d, v2).await;
    assert_eq!(
        d.lookup_family(ACCORD)
            .await
            .unwrap()
            .unwrap()
            .persist_row_hash,
        genesis_head_hash(v2),
        "{tag} I497: idempotent"
    );
}

/// I498 — an OLDER ceremony imported onto a node seeded from a newer one is
/// refused by the bake's anti-rollback rule and writes nothing.
async fn older_ceremony_is_refused(
    d: &dyn FederationDirectory,
    v1: &TestCeremonyOutputs,
    v2: &TestCeremonyOutputs,
    tag: &str,
) {
    boot(d, v2).await;
    let before = snapshot(d).await;
    let err = install_genesis_bundle_roster(d, &v1.bundle)
        .await
        .unwrap_err();
    assert!(
        matches!(&err, Error::GenesisBundleInvalid { detail } if detail.contains("rollback refused")),
        "{tag} I498: {err}"
    );
    assert_eq!(snapshot(d).await, before, "{tag} I498: nothing written");
}

/// I499 — a held genesis head naming a charter that is not a live row is
/// replaced only once the bundle's own charter is live: before the
/// delegation plane holds it the head is left standing (it cannot be told
/// from a working root), after it the head is replaced.
async fn replaced_only_once_the_bundle_charter_is_live(
    d: &dyn FederationDirectory,
    v2: &TestCeremonyOutputs,
    tag: &str,
) {
    let roster: Vec<String> = effective_accord_holder_records()
        .iter()
        .map(|r| r.record.key_id.clone())
        .collect();
    d.put_family_local(accord_family_genesis_record_for(
        ACCORD,
        ciris_verify_core::accord_genesis::ACCORD_CONSENSUS_PROTOCOL,
        roster.iter().map(String::as_str),
        &"ab".repeat(32),
    ))
    .await
    .unwrap();
    let held = d.lookup_family(ACCORD).await.unwrap().unwrap();
    let first = install_accord_genesis_head(d, &v2.bundle).await.unwrap();
    assert!(
        refused_with(&first, "accord_head_held_differs"),
        "{tag} I499: the bundle's charter is not live yet: {first:?}"
    );
    assert_eq!(d.lookup_family(ACCORD).await.unwrap().unwrap(), held);
    bake_assembled_genesis(d, &serde_json::to_string(&v2.bundle).unwrap())
        .await
        .unwrap();
    assert_eq!(
        install_accord_genesis_head(d, &v2.bundle).await.unwrap(),
        RosterRecordOutcome::Successor,
        "{tag} I499: with the bundle's charter live, the dangling head is replaced"
    );
}

// ── the runners ──

#[serial_test::serial(test_anchor_env)]
#[tokio::test]
async fn i490_i491_import_a_later_ceremony() {
    let (v1, v2) = vintages();
    let _armed = Armed::with(&v1.block);
    imports_a_later_ceremony(&memory().await, &v1, &v2, "memory").await;
    imports_a_later_ceremony(&sqlite().await, &v1, &v2, "sqlite").await;
}

#[serial_test::serial(test_anchor_env)]
#[tokio::test]
async fn i492_tampered_bundle_installs_nothing() {
    let (v1, v2) = vintages();
    let _armed = Armed::with(&v1.block);
    tampered_installs_nothing(&memory().await, &v1, &v2, "memory").await;
    tampered_installs_nothing(&sqlite().await, &v1, &v2, "sqlite").await;
}

#[serial_test::serial(test_anchor_env)]
#[tokio::test]
async fn i493_another_accord_is_refused() {
    let (v1, _) = vintages();
    let other = mint_test_ceremony(&OTHER_SEEDS, &NODE_SEED, at(-5)).expect("mint other");
    let _armed = Armed::with(&v1.block);
    another_accord_is_refused(&memory().await, &v1, &other, "memory").await;
    another_accord_is_refused(&sqlite().await, &v1, &other, "sqlite").await;
}

#[serial_test::serial(test_anchor_env)]
#[tokio::test]
async fn i494_reimport_is_a_noop() {
    let (v1, v2) = vintages();
    let _armed = Armed::with(&v1.block);
    reimport_is_a_noop(&memory().await, &v1, &v2, "memory").await;
    reimport_is_a_noop(&sqlite().await, &v1, &v2, "sqlite").await;
}

#[serial_test::serial(test_anchor_env)]
#[tokio::test]
async fn i495_unrelated_held_row_survives() {
    let (v1, v2) = vintages();
    let _armed = Armed::with(&v1.block);
    unrelated_held_row_survives(&memory().await, &v2, "memory").await;
    unrelated_held_row_survives(&sqlite().await, &v2, "sqlite").await;
}

#[serial_test::serial(test_anchor_env)]
#[tokio::test]
async fn i496_chartless_row_takes_the_head() {
    let (v1, v2) = vintages();
    let _armed = Armed::with(&v1.block);
    chartless_row_takes_the_head(&memory().await, &v2, "memory").await;
    chartless_row_takes_the_head(&sqlite().await, &v2, "sqlite").await;
}

#[serial_test::serial(test_anchor_env)]
#[tokio::test]
async fn i497_reboot_takes_the_later_genesis() {
    let (v1, v2) = vintages();
    let _armed = Armed::with(&v1.block);
    reboot_takes_the_later_genesis(&memory().await, &v1, &v2, "memory").await;
    reboot_takes_the_later_genesis(&sqlite().await, &v1, &v2, "sqlite").await;
}

async fn held_hash(d: &dyn FederationDirectory) -> String {
    d.lookup_community(CANON)
        .await
        .unwrap()
        .unwrap()
        .persist_row_hash
}

fn birth_hash(c: &TestCeremonyOutputs) -> String {
    compute_persist_row_hash(&c.bundle.community_record(CANON).unwrap().community).unwrap()
}

/// I501 — **the BAKE replaces a held prior-genesis `ciris-canonical` birth**
/// (operator ruling 2026-10-04 on the final genesis: "It should replace right?
/// This is a new seed even if it is the same settings"). The held row is kept
/// as the superseded prior; a re-boot is idempotent; an IMPORT of a later
/// ceremony never replaces a held birth; a row that has moved past its birth
/// (a version chain) is never rolled back by a bake.
async fn bake_replaces_the_prior_birth(
    d: &dyn FederationDirectory,
    v1: &TestCeremonyOutputs,
    v2: &TestCeremonyOutputs,
    v3: &TestCeremonyOutputs,
    tag: &str,
) {
    use ciris_persist::federation::cohort::Cohort;
    boot(d, v1).await;
    assert_eq!(
        held_hash(d).await,
        birth_hash(v1),
        "{tag} I501: control — v1's birth"
    );
    let versions_before = d
        .list_group_versions(Cohort::Community, CANON)
        .await
        .unwrap()
        .len();

    // The bake of a later ceremony by the same holders replaces the birth.
    boot(d, v2).await;
    assert_eq!(
        held_hash(d).await,
        birth_hash(v2),
        "{tag} I501: the re-boot holds v2's birth — the one a fresh node holds"
    );
    assert_eq!(
        d.list_group_versions(Cohort::Community, CANON)
            .await
            .unwrap()
            .len(),
        versions_before + 1,
        "{tag} I501: the held birth is kept as the superseded prior"
    );
    boot(d, v2).await;
    assert_eq!(held_hash(d).await, birth_hash(v2), "{tag} I501: idempotent");

    // An IMPORT of a later ceremony never replaces a held birth.
    let r = install_genesis_bundle_roster(d, &v3.bundle)
        .await
        .unwrap_or_else(|e| panic!("{tag} I501: {e}"));
    assert!(
        refused_with(outcome(&r, "community"), "community_held_differs"),
        "{tag} I501: {r:?}"
    );
    assert_eq!(
        held_hash(d).await,
        birth_hash(v2),
        "{tag} I501: import never replaces a birth"
    );

    // A row that moved past its birth (a version chain) is never rolled back:
    // supersede the held birth with a chained version, then bake v3.
    let mut chained = v2.bundle.community_record(CANON).unwrap().clone();
    chained.community.prev_head_digest = birth_hash(v2);
    chained.community.persist_row_hash = String::new();
    d.supersede_group_row(
        Cohort::Community,
        serde_json::to_value(&chained).unwrap(),
        None,
    )
    .await
    .unwrap_or_else(|e| panic!("{tag} I501: chain: {e}"));
    let chained_hash = held_hash(d).await;
    assert_ne!(
        chained_hash,
        birth_hash(v2),
        "{tag} I501: the chain moved the head"
    );
    boot(d, v3).await;
    assert_eq!(
        held_hash(d).await,
        chained_hash,
        "{tag} I501: a version chain is never rolled back by a bake"
    );
}

/// I502 — **the bake replaces only a birth whose charter is no longer live**
/// (Codex on #983): the community follows the family head's rule. A node
/// holds a LATER ceremony's birth (its charter is a live row); offered an
/// OLDER compiled birth whose charter is not held, the bake arm reports
/// HeldDiffers and writes nothing. (Booting an older binary re-seeds the
/// delegation plane from its compiled bundle first, which moves every head
/// the same way; that boot-level downgrade is tracked on #984.)
async fn older_bake_keeps_the_newer_birth(
    d: &dyn FederationDirectory,
    v2: &TestCeremonyOutputs,
    v3: &TestCeremonyOutputs,
    tag: &str,
) {
    install_test_ceremony_outputs(v3.bundle.clone());
    let r = install_genesis_bundle_roster(d, &v3.bundle)
        .await
        .unwrap_or_else(|e| panic!("{tag} I502: import v3: {e}"));
    assert_eq!(
        outcome(&r, "community"),
        &RosterRecordOutcome::Installed,
        "{tag} I502: {r:?}"
    );
    assert_eq!(
        held_hash(d).await,
        birth_hash(v3),
        "{tag} I502: control — v3's birth"
    );
    // v2 is now the compiled asset; its charter is NOT a held row while v3's
    // is live: the older birth must not replace the newer one.
    install_test_ceremony_outputs(v2.bundle.clone());
    let out = seed_canonical_community_from(
        d,
        Some(v2.bundle.community_record(CANON).unwrap()),
        RosterSource::Bake,
    )
    .await
    .unwrap_or_else(|e| panic!("{tag} I502: {e:?}"));
    assert_eq!(out, CommunityLegOutcome::HeldDiffers, "{tag} I502");
    assert_eq!(
        held_hash(d).await,
        birth_hash(v3),
        "{tag} I502: a birth whose charter stands is never replaced by an older bake"
    );
}

/// I503 — **only the compiled-in asset's birth replaces** (Codex on #983):
/// a caller-supplied row handed to the public seeding function under `Bake`
/// is never written through the raw supersede door.
async fn a_forged_birth_never_replaces(
    d: &dyn FederationDirectory,
    v1: &TestCeremonyOutputs,
    v2: &TestCeremonyOutputs,
    tag: &str,
) {
    boot(d, v1).await;
    let before = held_hash(d).await;
    let mut forged = v2.bundle.community_record(CANON).unwrap().clone();
    forged.community.community_name = "forged".to_owned();
    forged.community.persist_row_hash = String::new();
    // v2 is NOT the compiled asset (v1 is installed), so the bake arm must
    // report HeldDiffers and write nothing.
    let out = seed_canonical_community_from(d, Some(&forged), RosterSource::Bake)
        .await
        .unwrap_or_else(|e| panic!("{tag} I503: {e:?}"));
    assert_eq!(out, CommunityLegOutcome::HeldDiffers, "{tag} I503");
    assert_eq!(held_hash(d).await, before, "{tag} I503: nothing replaced");
}

#[serial_test::serial(test_anchor_env)]
#[tokio::test]
async fn i502_older_bake_keeps_the_newer_birth() {
    let (_v1, v2) = vintages();
    let v3 = mint_test_ceremony(&SEEDS, &NODE_SEED, at(-1)).expect("mint v3");
    let _armed = Armed::with(&v2.block);
    older_bake_keeps_the_newer_birth(&memory().await, &v2, &v3, "memory").await;
    older_bake_keeps_the_newer_birth(&sqlite().await, &v2, &v3, "sqlite").await;
}

#[serial_test::serial(test_anchor_env)]
#[tokio::test]
async fn i503_a_forged_birth_never_replaces() {
    let (v1, v2) = vintages();
    let _armed = Armed::with(&v1.block);
    a_forged_birth_never_replaces(&memory().await, &v1, &v2, "memory").await;
    a_forged_birth_never_replaces(&sqlite().await, &v1, &v2, "sqlite").await;
}

#[serial_test::serial(test_anchor_env)]
#[tokio::test]
async fn i501_bake_replaces_the_prior_birth() {
    let (v1, v2) = vintages();
    let v3 = mint_test_ceremony(&SEEDS, &NODE_SEED, at(-1)).expect("mint v3");
    let _armed = Armed::with(&v1.block);
    bake_replaces_the_prior_birth(&memory().await, &v1, &v2, &v3, "memory").await;
    bake_replaces_the_prior_birth(&sqlite().await, &v1, &v2, &v3, "sqlite").await;
}

#[serial_test::serial(test_anchor_env)]
#[tokio::test]
async fn i498_older_ceremony_is_refused() {
    let (v1, v2) = vintages();
    let _armed = Armed::with(&v1.block);
    older_ceremony_is_refused(&memory().await, &v1, &v2, "memory").await;
    older_ceremony_is_refused(&sqlite().await, &v1, &v2, "sqlite").await;
}

#[serial_test::serial(test_anchor_env)]
#[tokio::test]
async fn i499_replaced_only_once_the_bundle_charter_is_live() {
    let (v1, v2) = vintages();
    let _armed = Armed::with(&v1.block);
    replaced_only_once_the_bundle_charter_is_live(&memory().await, &v2, "memory").await;
    replaced_only_once_the_bundle_charter_is_live(&sqlite().await, &v2, "sqlite").await;
}

/// I490–I499 on postgres, when a test database is provided.
#[cfg(feature = "postgres")]
#[serial_test::serial(test_anchor_env)]
#[tokio::test]
async fn i490_i499_postgres() {
    if std::env::var("CIRIS_PERSIST_TEST_PG_URL").is_err() {
        eprintln!("skipping: CIRIS_PERSIST_TEST_PG_URL unset");
        return;
    }
    let (v1, v2) = vintages();
    let other = mint_test_ceremony(&OTHER_SEEDS, &NODE_SEED, at(-5)).expect("mint other");
    let v3 = mint_test_ceremony(&SEEDS, &NODE_SEED, at(-1)).expect("mint v3");
    let _armed = Armed::with(&v1.block);
    macro_rules! on_pg {
        ($b:ident => $e:expr) => {{
            let (pgb, base, name) = postgres().await.unwrap();
            {
                let $b: &dyn FederationDirectory = &pgb;
                $e.await;
            }
            drop(pgb);
            drop_db(&base, &name).await;
        }};
    }
    on_pg!(b => imports_a_later_ceremony(b, &v1, &v2, "postgres"));
    on_pg!(b => tampered_installs_nothing(b, &v1, &v2, "postgres"));
    on_pg!(b => another_accord_is_refused(b, &v1, &other, "postgres"));
    on_pg!(b => reimport_is_a_noop(b, &v1, &v2, "postgres"));
    on_pg!(b => unrelated_held_row_survives(b, &v2, "postgres"));
    on_pg!(b => chartless_row_takes_the_head(b, &v2, "postgres"));
    on_pg!(b => reboot_takes_the_later_genesis(b, &v1, &v2, "postgres"));
    on_pg!(b => older_ceremony_is_refused(b, &v1, &v2, "postgres"));
    on_pg!(b => replaced_only_once_the_bundle_charter_is_live(b, &v2, "postgres"));
    on_pg!(b => bake_replaces_the_prior_birth(b, &v1, &v2, &v3, "postgres"));
    on_pg!(b => older_bake_keeps_the_newer_birth(b, &v2, &v3, "postgres"));
    on_pg!(b => a_forged_birth_never_replaces(b, &v1, &v2, "postgres"));
}
