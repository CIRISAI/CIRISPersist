//! v53.1.4 — **I528e / I529 / I530: the equal-instant authority repair and the
//! scrub-set carry, at the replicated-apply door, at boot and at the import
//! door.** CIRISServer's dry-run of 0.5.221 on a copy of the canonical's
//! production data: the canonical's own node holds its July serve record —
//! `scrub_key_id = A1`, `additional_scrubs = []`, `identity_type =
//! "canonical,node"`, top-level `valid_from` == envelope `valid_from` ==
//! `2026-07-31T13:58:22.147317128Z`, a bound envelope carrying
//! `transport_hints` — plus a held owner binding `delegates_to` (owner →
//! canonical-1, cohort `self`) and the July `genesis-grant` by A1 with one
//! additional scrub; no community rows at all. The boot's canonical leg
//! refused the final record (same signed instant, not strictly newer) and
//! skipped; the community leg then could not seat the node (its held row
//! carries no accord scrub): `membership_founding_member_unsigned`, posture
//! pre-genesis, trace plane dark. An ORDINARY node upgraded from the same
//! release boots Entrenched: its July row went in by INSERT with both July
//! scrubs (A1+B1, a quorum), while the canonical's own self-signed row went
//! through `adopt_scrub_upgrade`, which dropped every scrub but the first.
//!
//! Its own process: every test arms the test-anchor override through the
//! environment (the #738 rule — never from a lib unit test).

#![cfg(all(feature = "test-anchor", feature = "sqlite"))]

use ciris_persist::federation::admission::has_accord_conferred_role_over_roster;
use ciris_persist::federation::canonical_community::resolve_community;
use ciris_persist::federation::genesis::ceremony::CeremonyState;
use ciris_persist::federation::genesis::*;
use ciris_persist::federation::register::ReplicatedKeyOutcome;
use ciris_persist::federation::tier_ingest::test_support as ts;
use ciris_persist::federation::types::identity_type;
use ciris_persist::federation::{FederationDirectory, SignedAttestation, SignedKeyRecord};
use ciris_persist::store::backend::Backend as _;
use ciris_persist::store::sqlite::SqliteBackend;

const SEEDS: [[u8; 32]; 3] = [[0x31; 32], [0x32; 32], [0x33; 32]];
const NODE_SEED: [u8; 32] = [0x4E; 32];
const CANON: &str = "ciris-canonical";
/// The live canonical's signed envelope instant, nanoseconds and all.
const JULY_NS: &str = "2026-07-31T13:58:22.147317128+00:00";
/// The live canonical's owner (the person whose `delegates_to` binds it).
const OWNER: &str = "eric-moore-v2-portable-f34de31d8c21-6e2b4kpvxk";
const OWNER_BOUND_AT: &str = "2026-07-02T20:18:27.267524243Z";

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

fn july() -> chrono::DateTime<chrono::Utc> {
    JULY_NS.parse().expect("the July instant")
}

/// A ceremony whose serve record carries the live canonical's envelope: the
/// July `valid_from` INSIDE the signed envelope (the supersede rule reads the
/// SIGNED instant, never the unsigned column) and `transport_hints`. The
/// bundle itself is produced NOW, as the final bake was in October over the
/// July envelope.
fn mint_final() -> (TestAnchorBlock, GenesisBundle) {
    let produced_at = chrono::Utc::now() - chrono::Duration::seconds(5);
    let (block, holders, mut inputs) =
        test_ceremony_inputs(&SEEDS, &NODE_SEED, produced_at, None).expect("inputs");
    for n in &mut inputs.serve_nodes {
        n.registration_envelope["valid_from"] = serde_json::json!(JULY_NS);
        n.registration_envelope["transport_hints"] =
            serde_json::json!([{ "kind": "ip", "destination": "108.61.242.236:4242" }]);
    }
    let mut state = CeremonyState::plan(inputs).expect("plan");
    sign_every_item(&mut state, &holders).expect("sign");
    (block, state.assemble().expect("assemble"))
}

/// The canonical's LIVE row: the final record's signed envelope, anchored by
/// A1 alone, every column instant the July one.
fn live_row(bundle: &GenesisBundle) -> SignedKeyRecord {
    let mut r = bundle.serve_nodes[0].clone();
    r.record.additional_scrubs.clear();
    r.record.valid_from = july();
    r.record.scrub_timestamp = july();
    r.record.pqc_completed_at = Some(july());
    r
}

/// An ORDINARY node's July row: inserted whole, both July scrubs (A1 + B1).
fn ordinary_july_row(bundle: &GenesisBundle) -> SignedKeyRecord {
    let mut r = live_row(bundle);
    r.record.additional_scrubs = bundle.serve_nodes[0].record.additional_scrubs[..1].to_vec();
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

/// What each backend exposes as inherent methods.
trait Node: FederationDirectory {
    async fn seed_holders(&self);
    fn be_the_node(&self);
    /// v54.0.0 (#995 row 2) — the pre-v53.1.4 UPDATE doors' drop.
    async fn drop_scrubs(&self, key_id: &str);
    async fn apply_key(&self, r: SignedKeyRecord) -> ReplicatedKeyOutcome;
}

impl Node for ciris_persist::store::memory::MemoryBackend {
    async fn seed_holders(&self) {
        self.seed_genesis_accord_holders(&effective_accord_holder_records())
            .await
            .expect("seed holders");
    }
    fn be_the_node(&self) {
        self.set_node_key_id(TEST_CEREMONY_NODE_KEY_ID);
    }
    async fn drop_scrubs(&self, key_id: &str) {
        self.test_seam_drop_key_additional_scrubs(key_id)
            .await
            .unwrap();
    }
    async fn apply_key(&self, r: SignedKeyRecord) -> ReplicatedKeyOutcome {
        self.apply_replicated_key_record(r).await.unwrap()
    }
}

impl Node for SqliteBackend {
    async fn seed_holders(&self) {
        self.seed_genesis_accord_holders(&effective_accord_holder_records())
            .await
            .expect("seed holders");
    }
    fn be_the_node(&self) {
        self.set_node_key_id(TEST_CEREMONY_NODE_KEY_ID);
    }
    async fn drop_scrubs(&self, key_id: &str) {
        self.test_seam_drop_key_additional_scrubs(key_id)
            .await
            .unwrap();
    }
    async fn apply_key(&self, r: SignedKeyRecord) -> ReplicatedKeyOutcome {
        self.apply_replicated_key_record(r).await.unwrap()
    }
}

#[cfg(feature = "postgres")]
impl Node for ciris_persist::store::postgres::PostgresBackend {
    async fn seed_holders(&self) {
        self.seed_genesis_accord_holders(&effective_accord_holder_records())
            .await
            .expect("seed holders");
    }
    fn be_the_node(&self) {
        self.set_node_key_id(TEST_CEREMONY_NODE_KEY_ID);
    }
    async fn drop_scrubs(&self, key_id: &str) {
        self.test_seam_drop_key_additional_scrubs(key_id)
            .await
            .unwrap();
    }
    async fn apply_key(&self, r: SignedKeyRecord) -> ReplicatedKeyOutcome {
        self.apply_replicated_key_record(r).await.unwrap()
    }
}

/// The ingredients of the canonical's live state, each switchable so a run
/// on the unfixed code can say which one matters.
#[derive(Clone, Copy)]
struct Live {
    /// The held row is the ordinary node's two-scrub July row instead of the
    /// canonical's A1-only one.
    two_scrubs: bool,
    /// This backend IS canonical-1.
    node_key: bool,
    /// The held owner binding `delegates_to` (owner → canonical-1).
    binding: bool,
    /// The held July `genesis-grant` by A1 with one additional scrub.
    grant: bool,
}

const CANONICAL: Live = Live {
    two_scrubs: false,
    node_key: true,
    binding: true,
    grant: true,
};

/// **The canonical's state**, admitted the way it was: the July row in the
/// admit-node era (a ONE-holder roster admits the one-scrub canonical through
/// the ordinary gate — the two-scrub ordinary row needs no such era), then the
/// final roster armed and seeded, the node key, the binding, the grant.
async fn canonical_state<D: Node + ?Sized>(
    d: &D,
    block: &TestAnchorBlock,
    bundle: &GenesisBundle,
    live: Live,
    tag: &str,
) {
    if live.two_scrubs {
        arm(block);
        d.seed_holders().await;
        d.put_public_key(ordinary_july_row(bundle))
            .await
            .unwrap_or_else(|e| panic!("{tag}: the two-scrub July row is admitted: {e}"));
    } else {
        let one = mint_test_anchor_block(&SEEDS[..1]).expect("one-holder block");
        arm(&one);
        d.seed_holders().await;
        d.put_public_key(live_row(bundle))
            .await
            .unwrap_or_else(|e| {
                panic!("{tag}: the admit-node era admits the one-scrub canonical: {e}")
            });
        arm(block);
        d.seed_holders().await;
    }
    if live.node_key {
        d.be_the_node();
    }
    if live.binding {
        ts::register_identity_key(d, OWNER, identity_type::USER).await;
        let mut a = ts::owner_binding_attestation(
            &format!("owner-binding-{tag}"),
            OWNER,
            TEST_CEREMONY_NODE_KEY_ID,
        );
        a.cohort_scope = "self".to_owned();
        a.asserted_at = OWNER_BOUND_AT.parse().unwrap();
        a.scrub_timestamp = a.asserted_at;
        ts::seal_row_in_place(OWNER, &mut a);
        d.put_attestation(SignedAttestation { attestation: a })
            .await
            .unwrap_or_else(|e| panic!("{tag}: the owner binding is held: {e}"));
    }
    if live.grant {
        let old = mint_test_ceremony(
            &SEEDS,
            &NODE_SEED,
            chrono::Utc::now() - chrono::Duration::hours(1),
        )
        .expect("the July ceremony");
        let id = format!("genesis-grant:{TEST_CEREMONY_NODE_KEY_ID}");
        let mut g = old
            .bundle
            .attestations
            .iter()
            .find(|a| a.attestation.attestation_id == id)
            .expect("the grant")
            .clone();
        g.attestation.additional_scrubs.truncate(1);
        d.put_attestation(g)
            .await
            .unwrap_or_else(|e| panic!("{tag}: the July grant is held: {e}"));
    }
    let row = held(d).await;
    assert_eq!(
        (
            row.scrub_key_id.as_str(),
            row.additional_scrubs.len(),
            row.identity_type.as_str(),
            // The UNSIGNED column is microsecond-precise on postgres; the
            // SIGNED envelope string below keeps the nanoseconds.
            row.valid_from.timestamp_micros(),
            row.registration_envelope["valid_from"].as_str(),
        ),
        (
            block.holders[0].key_id.as_str(),
            usize::from(live.two_scrubs),
            "canonical,node",
            july().timestamp_micros(),
            Some(JULY_NS),
        ),
        "{tag} precondition: the live row shape: {row:?}"
    );
    assert!(
        JULY_NS.contains("147317128"),
        "the fixture instant carries a 9-digit fraction"
    );
    assert_eq!(
        row.registration_envelope, bundle.serve_nodes[0].record.registration_envelope,
        "{tag} precondition: the same signed envelope as the final record (transport_hints, \
         the nanosecond instant)"
    );
    assert_eq!(
        carries_quorum(d).await,
        live.two_scrubs,
        "{tag} precondition: only the two-scrub row carries the accord co-scrub"
    );
}

async fn boot<D: FederationDirectory + ?Sized>(
    d: &D,
    bundle: &GenesisBundle,
) -> Result<(), GenesisFault> {
    install_test_ceremony_outputs(bundle.clone());
    seed_family_and_canonical(d).await
}

async fn assert_entrenched_and_seated<D: FederationDirectory + ?Sized>(
    d: &D,
    additional_scrubs: usize,
    tag: &str,
) {
    assert!(
        carries_quorum(d).await,
        "{tag}: the held row carries the accord co-scrub"
    );
    assert_eq!(
        held(d).await.additional_scrubs.len(),
        additional_scrubs,
        "{tag}: the scrub set the row is meant to hold"
    );
    verify_canonical_seeded(d).await.expect("canonical leg");
    verify_canonical_community_seeded(d)
        .await
        .expect("community leg");
    let posture = genesis_posture(d).await;
    assert!(
        matches!(posture, GenesisPosture::Entrenched),
        "{tag}: every leg seeded, community included: {posture:?}"
    );
    let r = resolve_community(d, CANON)
        .await
        .unwrap()
        .unwrap_or_else(|| panic!("{tag}: the community resolves"));
    assert!(
        r.live && r.members.iter().any(|m| m == TEST_CEREMONY_NODE_KEY_ID),
        "{tag}: the serve node is seated: {r:?}"
    );
}

/// **I529 — the canonical's own state, at boot**: the upgraded canonical
/// boots against the final bundle; the canonical leg takes the quorum-signed
/// record at the same signed instant, the `ciris-canonical` birth is held,
/// canonical-1 is seated, the posture is Entrenched; a re-boot is idempotent.
/// **I529b** (`two_scrubs`): an ORDINARY upgraded node holds the two-scrub
/// July row, which IS quorum-signed — it boots Entrenched, the supersede is
/// refused by name, and the row keeps its two scrubs (never "repaired").
async fn i529_the_canonical_boots<D: Node + ?Sized>(
    d: &D,
    block: &TestAnchorBlock,
    bundle: &GenesisBundle,
    live: Live,
    tag: &str,
) {
    canonical_state(d, block, bundle, live, tag).await;
    boot(d, bundle).await.unwrap_or_else(|e| {
        panic!("{tag} I529 EXPECT the canonical boots fully seeded against the final bundle — OBSERVED {e:?}")
    });
    let expected = if live.two_scrubs { 1 } else { 2 };
    assert_entrenched_and_seated(d, expected, &format!("{tag} I529")).await;
    boot(d, bundle)
        .await
        .unwrap_or_else(|e| panic!("{tag} I529: the re-boot: {e:?}"));
    assert_eq!(held(d).await.additional_scrubs.len(), expected);
}

/// **I529c — the import door** (`bake_assembled_genesis`, the #490 re-anchor):
/// the canonical's live row is re-anchored under bundle-quorum authority (its
/// own anti-rollback is over the UNSIGNED top-level instant, which the final
/// bake moved to October) and the row carries every scrub afterwards.
async fn i529c_the_import_door_reanchors<D: Node + ?Sized>(
    d: &D,
    block: &TestAnchorBlock,
    bundle: &GenesisBundle,
    tag: &str,
) {
    canonical_state(d, block, bundle, CANONICAL, tag).await;
    let report = bake_assembled_genesis(d, &serde_json::to_string(bundle).unwrap())
        .await
        .unwrap_or_else(|e| panic!("{tag} I529c: the import door bakes: {e}"));
    assert_eq!(
        report.serve_nodes,
        vec![(
            TEST_CEREMONY_NODE_KEY_ID.to_owned(),
            BakeItemOutcome::ReAnchored
        )],
        "{tag} I529c: re-anchored under bundle quorum"
    );
    assert!(
        carries_quorum(d).await,
        "{tag} I529c EXPECT the re-anchored row carries the accord co-scrub — OBSERVED scrub_key_id \
         {} with additional_scrubs {:?}",
        held(d).await.scrub_key_id,
        held(d).await.additional_scrubs
    );
    assert_eq!(held(d).await.additional_scrubs.len(), 2);
}

/// **I528e — the replicated-apply door takes the quorum-signed record at the
/// same signed instant**, and the held row carries the quorum afterwards. The
/// live shape re-offered over the repaired row is refused; the repaired
/// record re-offered is `Unchanged`.
async fn i528e_the_door_repairs<D: Node + ?Sized>(
    d: &D,
    block: &TestAnchorBlock,
    bundle: &GenesisBundle,
    tag: &str,
) {
    canonical_state(d, block, bundle, CANONICAL, tag).await;
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
    assert_eq!(
        d.apply_replicated_key_record(bundle.serve_nodes[0].clone())
            .await
            .unwrap(),
        ReplicatedKeyOutcome::Unchanged,
        "{tag} I528e: the repaired record re-offered is a no-op"
    );
    let back = d
        .apply_replicated_key_record(live_row(bundle))
        .await
        .unwrap();
    assert!(
        matches!(back, ReplicatedKeyOutcome::Refused { .. }),
        "{tag} I528e: the one-holder shape never replaces a quorum-signed row: {back:?}"
    );
    assert_eq!(held(d).await.additional_scrubs.len(), 2);
}

/// **I530 — the adopt door keeps the co-scrub set.** The canonical node's OWN
/// self-signed `node` row is upgraded to the final record at boot (#394's
/// `adopt_scrub_upgrade` arm of `seed_canonical_servers`) — the door that
/// produced the live A1-only row in the first place.
async fn i530_the_adopt_door_keeps_the_quorum<D: Node + ?Sized>(
    d: &D,
    block: &TestAnchorBlock,
    bundle: &GenesisBundle,
    tag: &str,
) {
    use ciris_persist::federation::operational::test_support::{signed_canonical_record, Identity};
    arm(block);
    d.seed_holders().await;
    d.be_the_node();
    let me = Identity::from_seeds(
        TEST_CEREMONY_NODE_KEY_ID,
        &NODE_SEED,
        &test_anchor_mldsa_seed(&NODE_SEED),
    )
    .expect("node identity");
    let baked = &bundle.serve_nodes[0].record;
    let own = signed_canonical_record(
        TEST_CEREMONY_NODE_KEY_ID,
        identity_type::NODE,
        &baked.pubkey_ed25519_base64,
        baked.pubkey_ml_dsa_65_base64.as_deref(),
        serde_json::json!({ "purpose": "federation-peering" }),
        &[&me],
    );
    assert_eq!(own.scrub_key_id, own.key_id, "self-signed");
    d.put_public_key(SignedKeyRecord { record: own })
        .await
        .unwrap_or_else(|e| panic!("{tag} I530: the node registers its own row: {e}"));
    assert!(!carries_quorum(d).await, "{tag} I530 precondition");
    boot(d, bundle).await.unwrap_or_else(|e| {
        panic!("{tag} I530 EXPECT the canonical node boots fully seeded — OBSERVED {e:?}")
    });
    let row = held(d).await;
    assert_eq!(
        (row.scrub_key_id.as_str(), row.additional_scrubs.len()),
        (baked.scrub_key_id.as_str(), 2),
        "{tag} I530: the adopted row carries every scrub: {row:?}"
    );
    assert_entrenched_and_seated(d, 2, &format!("{tag} I530")).await;
}

/// **I572 (#995 row 2) — a row a pre-v53.1.4 UPDATE door stranded is
/// re-hydrated, not read as `Unchanged`.** The node holds the final record,
/// inserted whole; the seam then reproduces the old doors' drop (the
/// `additional_scrubs` column emptied, `persist_row_hash` still over the full
/// record). The re-offered record hashes EQUAL to the stored hash, so through
/// v53 the plan answered `Unchanged` and the row stayed a one-holder record.
/// It is now `ScrubsRehydrated`, the row carries the quorum again, and a second
/// re-offer is the no-op.
async fn i572_a_stranded_row_is_rehydrated<D: Node + ?Sized>(
    d: &D,
    block: &TestAnchorBlock,
    bundle: &GenesisBundle,
    tag: &str,
) {
    arm(block);
    d.seed_holders().await;
    let full = bundle.serve_nodes[0].clone();
    d.put_public_key(full.clone())
        .await
        .unwrap_or_else(|e| panic!("{tag} I572: the final record inserts whole: {e}"));
    assert_eq!(held(d).await.additional_scrubs.len(), 2);
    assert!(
        carries_quorum(d).await,
        "{tag} I572 precondition: inserted whole"
    );
    d.drop_scrubs(TEST_CEREMONY_NODE_KEY_ID).await;
    assert!(
        !carries_quorum(d).await,
        "{tag} I572 precondition: the stranded row carries one holder"
    );
    let o = d.apply_key(full.clone()).await;
    assert_eq!(
        o,
        ReplicatedKeyOutcome::ScrubsRehydrated,
        "{tag} I572 EXPECT the stranded row is re-hydrated — OBSERVED {o:?}"
    );
    assert_eq!(held(d).await.additional_scrubs.len(), 2);
    assert!(
        carries_quorum(d).await,
        "{tag} I572: the re-hydrated row carries the accord co-scrub"
    );
    assert_eq!(
        d.apply_key(full).await,
        ReplicatedKeyOutcome::Unchanged,
        "{tag} I572: a second re-offer is the no-op"
    );
}

async fn sqlite() -> SqliteBackend {
    let b = SqliteBackend::open_in_memory().await.unwrap();
    b.run_migrations().await.unwrap();
    b
}

macro_rules! sqlite_case {
    ($name:ident, $body:expr) => {
        #[serial_test::serial(test_anchor_env)]
        #[tokio::test]
        async fn $name() {
            let (block, bundle) = mint_final();
            let _armed = Armed;
            let b = sqlite().await;
            ($body)(&b, &block, &bundle, "sqlite").await;
        }
    };
}

sqlite_case!(i529_the_canonical_boots_sqlite, |d, k, b, t| {
    i529_the_canonical_boots(d, k, b, CANONICAL, t)
});
sqlite_case!(i529_without_the_owner_binding_sqlite, |d, k, b, t| {
    i529_the_canonical_boots(
        d,
        k,
        b,
        Live {
            binding: false,
            ..CANONICAL
        },
        t,
    )
});
sqlite_case!(i529_without_the_node_key_or_grant_sqlite, |d, k, b, t| {
    i529_the_canonical_boots(
        d,
        k,
        b,
        Live {
            node_key: false,
            grant: false,
            ..CANONICAL
        },
        t,
    )
});
sqlite_case!(
    i529b_an_ordinary_node_with_the_two_scrub_row_sqlite,
    |d, k, b, t| i529_the_canonical_boots(
        d,
        k,
        b,
        Live {
            two_scrubs: true,
            node_key: false,
            ..CANONICAL
        },
        t
    )
);
sqlite_case!(
    i529c_the_import_door_reanchors_sqlite,
    i529c_the_import_door_reanchors
);
sqlite_case!(i528e_the_door_repairs_sqlite, i528e_the_door_repairs);
sqlite_case!(
    i572_a_stranded_row_is_rehydrated_sqlite,
    i572_a_stranded_row_is_rehydrated
);

#[serial_test::serial(test_anchor_env)]
#[tokio::test]
async fn i572_a_stranded_row_is_rehydrated_memory() {
    let (block, bundle) = mint_final();
    let _armed = Armed;
    let b = ciris_persist::store::memory::MemoryBackend::new();
    i572_a_stranded_row_is_rehydrated(&b, &block, &bundle, "memory").await;
}
sqlite_case!(
    i530_the_adopt_door_keeps_the_quorum_sqlite,
    i530_the_adopt_door_keeps_the_quorum
);

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
macro_rules! postgres_case {
    ($name:ident, $body:expr) => {
        #[serial_test::serial(test_anchor_env)]
        #[tokio::test]
        async fn $name() {
            let Some((base, name, dsn)) = own_pg_database().await else {
                return;
            };
            let (block, bundle) = mint_final();
            let _armed = Armed;
            {
                let b = ciris_persist::store::postgres::PostgresBackend::connect(&dsn)
                    .await
                    .unwrap();
                b.run_migrations().await.unwrap();
                ($body)(&b, &block, &bundle, "postgres").await;
            }
            drop_pg_database(&base, &name).await;
        }
    };
}

#[cfg(feature = "postgres")]
postgres_case!(i529_the_canonical_boots_postgres, |d, k, b, t| {
    i529_the_canonical_boots(d, k, b, CANONICAL, t)
});
#[cfg(feature = "postgres")]
postgres_case!(i529_without_the_owner_binding_postgres, |d, k, b, t| {
    i529_the_canonical_boots(
        d,
        k,
        b,
        Live {
            binding: false,
            ..CANONICAL
        },
        t,
    )
});
#[cfg(feature = "postgres")]
postgres_case!(i529_without_the_node_key_or_grant_postgres, |d, k, b, t| {
    i529_the_canonical_boots(
        d,
        k,
        b,
        Live {
            node_key: false,
            grant: false,
            ..CANONICAL
        },
        t,
    )
});
#[cfg(feature = "postgres")]
postgres_case!(
    i529b_an_ordinary_node_with_the_two_scrub_row_postgres,
    |d, k, b, t| i529_the_canonical_boots(
        d,
        k,
        b,
        Live {
            two_scrubs: true,
            node_key: false,
            ..CANONICAL
        },
        t
    )
);
#[cfg(feature = "postgres")]
postgres_case!(
    i529c_the_import_door_reanchors_postgres,
    i529c_the_import_door_reanchors
);
#[cfg(feature = "postgres")]
postgres_case!(i528e_the_door_repairs_postgres, i528e_the_door_repairs);
#[cfg(feature = "postgres")]
postgres_case!(
    i572_a_stranded_row_is_rehydrated_postgres,
    i572_a_stranded_row_is_rehydrated
);
#[cfg(feature = "postgres")]
postgres_case!(
    i530_the_adopt_door_keeps_the_quorum_postgres,
    i530_the_adopt_door_keeps_the_quorum
);
