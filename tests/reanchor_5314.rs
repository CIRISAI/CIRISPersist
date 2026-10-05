//! v53.1.4 — **I528e / I529: the equal-instant authority repair, at the
//! replicated-apply door and at boot.** CIRISServer's dry-run of 0.5.221 on a
//! copy of the canonical's production data: an UPGRADED node holds the July
//! serve record for the canonical — same key, same pubkeys, the same SIGNED
//! envelope `valid_from` as the final bundle's record — anchor-scrubbed by one
//! holder (the admit-node era), never by the accord quorum. The boot's
//! canonical leg refused the final record (not strictly newer) and skipped;
//! the community leg then could not seat the node (its held row carries no
//! accord scrub): `membership_founding_member_unsigned`, posture pre-genesis,
//! trace plane dark. Fresh nodes passed.
//!
//! Its own process: every test arms the test-anchor override through the
//! environment (the #738 rule — never from a lib unit test).

#![cfg(all(feature = "test-anchor", feature = "sqlite"))]

use ciris_persist::federation::admission::has_accord_conferred_role_over_roster;
use ciris_persist::federation::canonical_community::resolve_community;
use ciris_persist::federation::genesis::ceremony::CeremonyState;
use ciris_persist::federation::genesis::*;
use ciris_persist::federation::register::ReplicatedKeyOutcome;
use ciris_persist::federation::types::identity_type;
use ciris_persist::federation::{FederationDirectory, SignedKeyRecord};
use ciris_persist::store::backend::Backend as _;
use ciris_persist::store::sqlite::SqliteBackend;

const SEEDS: [[u8; 32]; 3] = [[0x31; 32], [0x32; 32], [0x33; 32]];
const NODE_SEED: [u8; 32] = [0x4E; 32];
const CANON: &str = "ciris-canonical";

/// Arm the override with `block` (re-armable within one process: the
/// override is parsed from the environment on every read).
fn arm(block: &TestAnchorBlock) {
    for (k, v) in block.env_pairs() {
        std::env::set_var(k, v);
    }
    for k in ["ENVIRONMENT", "CIRIS_ENV", "CIRIS_ENVIRONMENT"] {
        std::env::remove_var(k);
    }
}

/// Disarms and clears the installed ceremony on every exit path.
struct Armed;

impl Drop for Armed {
    fn drop(&mut self) {
        clear_test_ceremony_outputs();
        for k in TEST_ANCHOR_ENV_VARS {
            std::env::remove_var(k);
        }
    }
}

/// A ceremony whose serve record carries `valid_from` INSIDE its signed
/// envelope — the production shape (`canonical_seed.json`'s record does; the
/// supersede rule reads the SIGNED instant, never the unsigned column).
fn mint_with_signed_instant(
    produced_at: chrono::DateTime<chrono::Utc>,
) -> (TestAnchorBlock, GenesisBundle) {
    let (block, holders, mut inputs) =
        test_ceremony_inputs(&SEEDS, &NODE_SEED, produced_at, None).expect("inputs");
    for n in &mut inputs.serve_nodes {
        n.registration_envelope["valid_from"] = serde_json::json!(produced_at.to_rfc3339());
    }
    let mut state = CeremonyState::plan(inputs).expect("plan");
    sign_every_item(&mut state, &holders).expect("sign");
    (block, state.assemble().expect("assemble"))
}

/// The July shape: the final bundle's serve record with every co-scrub but
/// the primary holder's stripped — same key, same pubkeys, the same signed
/// envelope (`valid_from` included), anchored by ONE holder.
fn july_shape(bundle: &GenesisBundle) -> SignedKeyRecord {
    let mut r = bundle.serve_nodes[0].clone();
    r.record.additional_scrubs.clear();
    r
}

fn roster() -> Vec<String> {
    effective_accord_holder_records()
        .iter()
        .map(|r| r.record.key_id.clone())
        .collect()
}

/// Does the node's HELD key record carry the live accord roster's co-scrub
/// (the question the community leg asks before seating it)?
async fn carries_quorum<D: FederationDirectory + ?Sized>(d: &D) -> bool {
    has_accord_conferred_role_over_roster(
        d,
        TEST_CEREMONY_NODE_KEY_ID,
        identity_type::CANONICAL,
        &roster(),
    )
    .await
    .expect("roster read")
}

async fn held<D: FederationDirectory + ?Sized>(
    d: &D,
) -> ciris_persist::federation::types::KeyRecord {
    d.lookup_public_key(TEST_CEREMONY_NODE_KEY_ID)
        .await
        .unwrap()
        .expect("the serve record is held")
}

/// The holder seed each backend exposes as an inherent method.
trait Seeds: FederationDirectory {
    async fn seed_holders(&self);
}

impl Seeds for SqliteBackend {
    async fn seed_holders(&self) {
        self.seed_genesis_accord_holders(&effective_accord_holder_records())
            .await
            .expect("seed holders");
    }
}

#[cfg(feature = "postgres")]
impl Seeds for ciris_persist::store::postgres::PostgresBackend {
    async fn seed_holders(&self) {
        self.seed_genesis_accord_holders(&effective_accord_holder_records())
            .await
            .expect("seed holders");
    }
}

/// **The upgraded node**: seeded in the admit-node era, when a ONE-holder
/// roster admitted the one-scrub canonical through the ordinary gate; then
/// the final roster (three holders, the same first holder) is armed and
/// seeded. Returns with the July-shape row held and the quorum NOT carried.
async fn upgraded_node_from_july<D: Seeds + ?Sized>(
    d: &D,
    block: &TestAnchorBlock,
    bundle: &GenesisBundle,
    tag: &str,
) {
    let one = mint_test_anchor_block(&SEEDS[..1]).expect("one-holder block");
    arm(&one);
    d.seed_holders().await;
    d.put_public_key(july_shape(bundle))
        .await
        .unwrap_or_else(|e| {
            panic!("{tag}: the admit-node era admits the one-scrub canonical: {e}")
        });
    arm(block);
    d.seed_holders().await;
    let row = held(d).await;
    assert_eq!(
        (row.additional_scrubs.len(), &row.registration_envelope),
        (0, &bundle.serve_nodes[0].record.registration_envelope),
        "{tag} precondition: the held row is the final record's signed envelope, anchored by \
         one holder"
    );
    assert_eq!(
        row.registration_envelope["valid_from"],
        bundle.serve_nodes[0].record.registration_envelope["valid_from"],
        "{tag} precondition: the same SIGNED instant"
    );
    assert!(
        !carries_quorum(d).await,
        "{tag} precondition: the held row carries no accord co-scrub"
    );
}

/// **I528e — the replicated-apply door takes the quorum-signed record at the
/// same signed instant**, and the held row carries the quorum afterwards. The
/// July shape re-offered over the repaired row is refused; the repaired
/// record re-offered is `Unchanged`.
async fn i528e_the_door_repairs<D: Seeds + ?Sized>(
    d: &D,
    block: &TestAnchorBlock,
    bundle: &GenesisBundle,
    tag: &str,
) {
    upgraded_node_from_july(d, block, bundle, tag).await;
    let o = d
        .apply_replicated_key_record(bundle.serve_nodes[0].clone())
        .await
        .expect("the door answers");
    assert_eq!(
        o,
        ReplicatedKeyOutcome::Superseded,
        "{tag} I528e EXPECT the quorum-signed record at the same signed instant SUPERSEDES the \
         one-holder row — OBSERVED {o:?}"
    );
    assert!(
        carries_quorum(d).await,
        "{tag} I528e: the held row now carries the accord co-scrub"
    );
    assert_eq!(held(d).await.additional_scrubs.len(), 2);
    // Controls on the repaired row.
    assert_eq!(
        d.apply_replicated_key_record(bundle.serve_nodes[0].clone())
            .await
            .unwrap(),
        ReplicatedKeyOutcome::Unchanged,
        "{tag} I528e: the repaired record re-offered is a no-op"
    );
    let back = d
        .apply_replicated_key_record(july_shape(bundle))
        .await
        .unwrap();
    assert!(
        matches!(back, ReplicatedKeyOutcome::Refused { .. }),
        "{tag} I528e: the one-holder shape never replaces a quorum-signed row: {back:?}"
    );
    assert_eq!(held(d).await.additional_scrubs.len(), 2);
}

/// **I529 — the production shape, at boot**: the upgraded node boots against
/// the final bundle; the canonical leg takes the quorum-signed record, the
/// `ciris-canonical` birth is held, the serve node is seated, the posture is
/// Entrenched.
async fn i529_the_upgraded_node_boots<D: Seeds + ?Sized>(
    d: &D,
    block: &TestAnchorBlock,
    bundle: &GenesisBundle,
    tag: &str,
) {
    upgraded_node_from_july(d, block, bundle, tag).await;
    install_test_ceremony_outputs(bundle.clone());
    seed_family_and_canonical(d).await.unwrap_or_else(|e| {
        panic!(
            "{tag} I529 EXPECT the upgraded node boots fully seeded against the final bundle — \
             OBSERVED {e:?}"
        )
    });
    assert!(
        carries_quorum(d).await,
        "{tag} I529: the canonical leg replaced the one-holder row with the quorum-signed record"
    );
    assert_eq!(held(d).await.additional_scrubs.len(), 2);
    verify_canonical_seeded(d).await.expect("canonical leg");
    verify_canonical_community_seeded(d)
        .await
        .expect("community leg");
    let posture = genesis_posture(d).await;
    assert!(
        matches!(posture, GenesisPosture::Entrenched),
        "{tag} I529: every leg seeded, community included: {posture:?}"
    );
    let r = resolve_community(d, CANON)
        .await
        .unwrap()
        .unwrap_or_else(|| panic!("{tag} I529: the community resolves"));
    assert!(r.live, "{tag} I529: live: {r:?}");
    assert!(
        r.members.iter().any(|m| m == TEST_CEREMONY_NODE_KEY_ID),
        "{tag} I529: the serve node is seated: {r:?}"
    );
    // A second boot is idempotent.
    seed_family_and_canonical(d)
        .await
        .unwrap_or_else(|e| panic!("{tag} I529: the re-boot: {e:?}"));
    assert_eq!(held(d).await.additional_scrubs.len(), 2);
}

async fn sqlite() -> SqliteBackend {
    let b = SqliteBackend::open_in_memory().await.unwrap();
    b.run_migrations().await.unwrap();
    b
}

#[serial_test::serial(test_anchor_env)]
#[tokio::test]
async fn i528e_the_door_repairs_sqlite() {
    let (block, bundle) =
        mint_with_signed_instant(chrono::Utc::now() - chrono::Duration::seconds(5));
    let _armed = Armed;
    let b = sqlite().await;
    i528e_the_door_repairs(&b, &block, &bundle, "sqlite").await;
}

#[serial_test::serial(test_anchor_env)]
#[tokio::test]
async fn i529_the_upgraded_node_boots_sqlite() {
    let (block, bundle) =
        mint_with_signed_instant(chrono::Utc::now() - chrono::Duration::seconds(5));
    let _armed = Armed;
    let b = sqlite().await;
    i529_the_upgraded_node_boots(&b, &block, &bundle, "sqlite").await;
}

/// A database of this test's own (the integration binaries share one; a
/// second ceremony seeded into it reads as anchor squatting to the next test).
#[cfg(feature = "postgres")]
async fn own_pg_database() -> Option<(String, String, String)> {
    let Ok(base) = std::env::var("CIRIS_PERSIST_TEST_PG_URL") else {
        eprintln!("skipping: CIRIS_PERSIST_TEST_PG_URL unset");
        return None;
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
    let (admin, conn) = tokio_postgres::connect(&base, tokio_postgres::NoTls)
        .await
        .expect("connect to the base test database");
    tokio::spawn(conn);
    admin
        .batch_execute(&format!("CREATE DATABASE \"{name}\""))
        .await
        .expect("create this test's database");
    let dsn = format!("{}/{name}", &base[..cut]);
    Some((base, name, dsn))
}

#[cfg(feature = "postgres")]
async fn drop_pg_database(base: &str, name: &str) {
    if let Ok((admin, conn)) = tokio_postgres::connect(base, tokio_postgres::NoTls).await {
        tokio::spawn(conn);
        let _ = admin
            .batch_execute(&format!("DROP DATABASE IF EXISTS \"{name}\" WITH (FORCE)"))
            .await;
    }
}

#[cfg(feature = "postgres")]
#[serial_test::serial(test_anchor_env)]
#[tokio::test]
async fn i528e_the_door_repairs_postgres() {
    let Some((base, name, dsn)) = own_pg_database().await else {
        return;
    };
    let (block, bundle) =
        mint_with_signed_instant(chrono::Utc::now() - chrono::Duration::seconds(5));
    let _armed = Armed;
    {
        let b = ciris_persist::store::postgres::PostgresBackend::connect(&dsn)
            .await
            .unwrap();
        b.run_migrations().await.unwrap();
        i528e_the_door_repairs(&b, &block, &bundle, "postgres").await;
    }
    drop_pg_database(&base, &name).await;
}

#[cfg(feature = "postgres")]
#[serial_test::serial(test_anchor_env)]
#[tokio::test]
async fn i529_the_upgraded_node_boots_postgres() {
    let Some((base, name, dsn)) = own_pg_database().await else {
        return;
    };
    let (block, bundle) =
        mint_with_signed_instant(chrono::Utc::now() - chrono::Duration::seconds(5));
    let _armed = Armed;
    {
        let b = ciris_persist::store::postgres::PostgresBackend::connect(&dsn)
            .await
            .unwrap();
        b.run_migrations().await.unwrap();
        i529_the_upgraded_node_boots(&b, &block, &bundle, "postgres").await;
    }
    drop_pg_database(&base, &name).await;
}
