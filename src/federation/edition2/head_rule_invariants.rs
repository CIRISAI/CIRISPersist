//! v62.0.0 (HEAD-2; CC 2.4.1.1, "A row that exercises a standing and names
//! no head concludes nothing, `act_names_no_head`") — **the head rule at the
//! statement door**, on sqlite and postgres, through the real door
//! (`ingest::put_statement`).
//!
//! - I6105: a person's row placed in a room that names no roster version is
//!   refused `act_names_no_head`; the same row at `self` is not refused by
//!   the head rule (a person's own row names none).
//! - I6106: judged from the row alone: an UNOWNED node's self-report with no
//!   head is refused wherever it is placed; its key record lands (HEAD-4.rev2;
//!   Constitution, head cases (3), (5)).
//! - I6123: an UNOWNED node's key record and self-pair `identity:occurrence`
//!   land with no head and no wait (it is findable; it signs no report).
//! - I6118: an OWNED node with no root: its report naming its owner binding
//!   lands, the same with no head is refused.
//! - I6119: `lifts` on one voice's end, a `supersedes` carrying `lifts`, and
//!   a root-grant act naming no bundle are refused at the door.
//!
//! The pairs make each "not refused" a check that can fail: the refused twin
//! differs only in its `cohort_scope`, so the door reached the head rule for
//! that family and signer.

use ciris_verify_core::cde::Value;
use ciris_verify_core::edition2::sign_row_statement;
use ciris_verify_core::namespace_match::family_id;

use super::door_invariants::fixture::{iref, key, key_record, map};
use super::fixture_switch as e2;
use super::ingest::{put_statement, INGEST_TIER};
use super::names::RowId;
use crate::federation::{malformed_row, Error, FederationDirectory};

fn reason(e: &Error) -> &'static str {
    match e {
        Error::MalformedRow { reason, .. } => reason,
        // v62.0.0 (HEAD-fix8) — a row that names no head is not kept.
        Error::NotKept { why, .. } => why.token(),
        other => other.kind(),
    }
}

/// A row of `family` (dimension `dimension`) authored by key `n`, placed at
/// `scope` (with `community_id` = key `room`'s identity-ref at `community`).
fn act(n: u8, family: &str, dimension: &str, scope: &str, room: u8) -> Vec<u8> {
    let k = key(n);
    let mut m = vec![
        ("asserted_at", Value::Uint(2_000)),
        ("author", Value::Text(iref(&k))),
        ("dimension", Value::Text(dimension.into())),
        ("cohort_scope", Value::Text(scope.into())),
    ];
    if scope == "community" {
        m.push(("community_id", Value::Text(iref(&key(room)))));
    }
    sign_row_statement(
        &k,
        &iref(&k),
        &iref(&k),
        "scores",
        &family_id(family),
        &map(m),
        vec![],
    )
    .expect("I6105: the act signs")
}

/// The head rule did not refuse `r` (any other outcome may follow).
fn not_head_refused(r: &Result<super::ingest::StatementOutcome, Error>, what: &str) {
    if let Err(e) = r {
        assert_ne!(
            reason(e),
            crate::federation::not_kept::ACT_NAMES_NO_HEAD,
            "{what}: the head rule refused a row that names no standing: {e:?}"
        );
    }
}

async fn head_refused(d: &dyn FederationDirectory, st: &[u8], what: &str) {
    let e = put_statement(d, st, None, INGEST_TIER)
        .await
        .expect_err(what);
    assert_eq!(
        reason(&e),
        crate::federation::not_kept::ACT_NAMES_NO_HEAD,
        "{what}: refused act_names_no_head: {e:?}"
    );
}

/// I6105 — a person's room act names its roster version.
pub(crate) async fn i6105_body(d: &dyn FederationDirectory, tag: &str) {
    let person = 61;
    put_statement(
        d,
        &key_record(&key(person), &["user"], 1_000, None),
        None,
        INGEST_TIER,
    )
    .await
    .unwrap_or_else(|e| panic!("[{tag}] I6105: the person's key record: {e:?}"));
    head_refused(
        d,
        &act(person, "chat:*", "chat:message:v1", "community", 62),
        &format!("[{tag}] I6105: a room-placed chat row naming no head"),
    )
    .await;
    let own = put_statement(
        d,
        &act(person, "chat:*", "chat:message:v1", "self", 62),
        None,
        INGEST_TIER,
    )
    .await;
    not_head_refused(&own, &format!("[{tag}] I6105: the same row at self"));
}

/// I6106 — judged from the row alone (HEAD-4.rev2; Constitution, head
/// cases (3) and (5)): an UNOWNED node's self-report names its owner
/// binding like any node's, so with no head it is refused whoever the node
/// is; its possession row (the key record) names none and lands.
pub(crate) async fn i6106_body(d: &dyn FederationDirectory, tag: &str) {
    let node = 63;
    put_statement(
        d,
        &key_record(&key(node), &["node"], 1_000, Some(80_000_000)),
        None,
        INGEST_TIER,
    )
    .await
    .unwrap_or_else(|e| panic!("[{tag}] I6106: an unowned node's key record lands: {e:?}"));
    for scope in ["self", "federation", "community"] {
        head_refused(
            d,
            &act(node, "chat:*", "chat:message:v1", scope, 64),
            &format!("[{tag}] I6106: an unowned node's row at {scope} naming no head"),
        )
        .await;
    }
}

/// I6123 (HEAD-8; Constitution, "CONSTITUTION RETRACTED THE NODE WAIT") —
/// **an unowned node is findable**: its key record AND its self-pair
/// `identity:occurrence` (its transport destination binding, signed by the
/// node alone, naming no owner) land with no head from the head rule, and no
/// wait for an owner binding. (The occurrence names its own self-roster head,
/// its key record's row, by its family's own rule; the head rule asks it for
/// none.)
pub(crate) async fn i6123_body(d: &dyn FederationDirectory, tag: &str) {
    use super::fixture_occurrence::{occurrence_bind_voices, BindOptions};
    let seed = format!("i6123-node-{tag}");
    let k = e2::put_key(d, &seed, &["node"]).await;
    assert!(
        super::head_rule::owner_binding_row(d, &k, false, 0)
            .await
            .expect("I6123: the owner read")
            .is_none(),
        "[{tag}] I6123: the node is unowned"
    );
    let (head, _) = super::occurrence::current_roster_heads(d, &k)
        .await
        .expect("I6123: the roster read")
        .expect("I6123: the node's key heads its own roster");
    let opts = BindOptions {
        extra: vec![
            (
                "transport_destination",
                super::rootless_mesh_invariants::transport(0x63, 0x64),
            ),
            ("transit_xwing_pubkey", Value::Bytes(vec![0x65; 1216])),
        ],
        head: Some(head),
        ..BindOptions::default()
    };
    let mut last = None;
    for st in occurrence_bind_voices(&seed, &seed, &seed, "server", &opts) {
        last = Some(
            put_statement(d, &st, None, INGEST_TIER)
                .await
                .unwrap_or_else(|e| panic!("[{tag}] I6123: the self pair lands: {e:?}")),
        );
    }
    assert!(
        matches!(last, Some(super::ingest::StatementOutcome::Row { .. })),
        "[{tag}] I6123: an unowned node's self-pair occurrence lands, no wait: {last:?}"
    );
}

/// A node row of `seed` at `scope` (self), stated at `at`, naming `head`.
fn node_act(seed: &str, at: u64, head: Option<&RowId>) -> Vec<u8> {
    let iss = e2::kid(seed);
    let mut m = vec![
        ("asserted_at", Value::Uint(at)),
        ("author", Value::Text(iss.clone())),
        ("dimension", Value::Text("chat:message:v1".into())),
        ("cohort_scope", Value::Text("self".into())),
    ];
    if let Some(h) = head {
        m.push((
            "refs",
            map(vec![("head", ciris_verify_core::edition2::row_ref(&h.0))]),
        ));
    }
    sign_row_statement(
        &e2::signing_key(seed),
        &iss,
        &iss,
        "scores",
        &family_id("chat:*"),
        &map(m),
        vec![],
    )
    .expect("I6118: the node's row signs")
}

/// I6118 — an OWNED node with no root: its self-report naming its owner
/// binding lands; the same report with no head is refused
/// `act_names_no_head`.
pub(crate) async fn i6118_body(d: &dyn FederationDirectory, tag: &str) {
    use crate::federation::tier_ingest::test_support as ts;
    let owner = format!("i6118-owner-{tag}");
    let node_seed = format!("i6118-node-{tag}");
    e2::put_key(d, &owner, &["user"]).await;
    let node = e2::put_key(d, &node_seed, &["node"]).await;
    let binding = ts::owner_binding_attestation(&format!("i6118-{tag}"), &owner, &node);
    e2::land_owner_binding(d, &binding, &node_seed)
        .await
        .unwrap_or_else(|e| panic!("[{tag}] I6118: the owner binding lands: {e:?}"));
    let head = super::head_rule::owner_binding_row(d, &node, false, 0)
        .await
        .expect("I6118: the binding read")
        .unwrap_or_else(|| panic!("[{tag}] I6118: the node is owned"));
    let at = u64::try_from(binding.asserted_at.timestamp_millis()).expect("ms") + 1_000;
    head_refused(
        d,
        &node_act(&node_seed, at, None),
        &format!("[{tag}] I6118: an owned node's report naming no head"),
    )
    .await;
    put_statement(d, &node_act(&node_seed, at, Some(&head)), None, INGEST_TIER)
        .await
        .unwrap_or_else(|e| panic!("[{tag}] I6118: the report naming its binding lands: {e:?}"));
}

/// I6119 — at the statement door: `lifts` on one signer's own end is
/// refused `lifts_on_own_end`; a `supersedes` carrying `lifts` is refused;
/// a person's act under a root grant (a reserved prefix whose rule names a
/// delegation scope) that names no bundle is refused `act_names_no_head`.
pub(crate) async fn i6119_body(d: &dyn FederationDirectory, tag: &str) {
    let person = 65;
    let k = key(person);
    put_statement(
        d,
        &key_record(&k, &["user"], 1_000, None),
        None,
        INGEST_TIER,
    )
    .await
    .unwrap_or_else(|e| panic!("[{tag}] I6119: the key record: {e:?}"));
    let target = map(vec![(
        "target",
        ciris_verify_core::edition2::row_ref(&[0x61; 32]),
    )]);
    let end = |row_type: &str, family: &str, extra: Vec<(&str, Value)>| {
        let mut m = vec![
            ("asserted_at", Value::Uint(2_000)),
            ("author", Value::Text(iref(&k))),
            ("lifts", Value::Bool(true)),
            ("refs", target.clone()),
        ];
        m.extend(extra);
        sign_row_statement(
            &k,
            &iref(&k),
            &iref(&k),
            row_type,
            &family_id(family),
            &map(m),
            vec![],
        )
        .expect("I6119: signs")
    };
    let e = put_statement(d, &end("withdraws", "chat:*", vec![]), None, INGEST_TIER)
        .await
        .expect_err("I6119: lifts on an own end");
    assert_eq!(
        reason(&e),
        malformed_row::LIFTS_ON_OWN_END,
        "[{tag}] I6119: lifts on one voice's end: {e:?}"
    );
    let e = put_statement(
        d,
        &end(
            "supersedes",
            "chat:*",
            vec![("dimension", Value::Text("chat:message:v1".into()))],
        ),
        None,
        INGEST_TIER,
    )
    .await
    .expect_err("I6119: a supersedes carrying lifts");
    assert_eq!(
        reason(&e),
        malformed_row::EDITION2_PAYLOAD_INVALID,
        "[{tag}] I6119: a supersedes carries no lifts: {e:?}"
    );
    head_refused(
        d,
        &act(
            person,
            "transparency_log:cosigned:{tree_size}",
            "transparency_log:cosigned:7:v1",
            "federation",
            0,
        ),
        &format!("[{tag}] I6119: a root-grant act naming no bundle"),
    )
    .await;
}

/// This node's custody reports about `sha`.
async fn acks_of<B>(
    b: &B,
    key: &str,
    sha: &[u8; 32],
) -> Vec<crate::federation::custody_ack::CustodyAck>
where
    B: FederationDirectory + Sync,
{
    crate::federation::custody_ack::custody_acks_of(b, key, &hex::encode(sha))
        .await
        .expect("I6120: the custody read")
}

/// I6120 (HEAD-6; Constitution, head cases (3)) — **the claims of an
/// unowned node's blobs resume when its owner binding lands**: a blob stored
/// while the node is unowned gets no claim and no error; the owner binds the
/// node through the real door; one pass of the host-called re-ack sweep
/// (`holding_claim::reack_own_claims`, `Engine::reack_holding_claims_once`)
/// claims it, naming the binding as its head; a second pass claims nothing.
pub(crate) async fn i6120_body<B>(b: &B, tag: &str)
where
    B: crate::federation::BlobStorage + FederationDirectory + Sync,
{
    use crate::federation::holding_claim::reack_own_claims;
    use crate::federation::key_grant_invariants::two_node::{node_as, own};
    use crate::federation::types::{cohort_scope as cs, identity_type::NODE};
    let alias = format!("i6120-node-{tag}");
    let n = node_as(b, &alias, NODE).await;
    let bytes = format!("i6120 bytes {tag}").into_bytes();
    let sha: [u8; 32] = {
        use sha2::Digest as _;
        sha2::Sha256::digest(&bytes).into()
    };
    let now = chrono::Utc::now();
    b.put_blob_signing_scoped(
        cs::FEDERATION,
        None,
        &sha,
        crate::federation::BlobBody::Inline(bytes),
        None,
        &n.key,
        &n.signer,
        now,
        uuid::Uuid::new_v4(),
    )
    .await
    .unwrap_or_else(|e| panic!("[{tag}] I6120: an unowned node stores the blob: {e:?}"));
    assert!(
        acks_of(b, &n.key, &sha).await.is_empty(),
        "[{tag}] I6120: unowned: no claim"
    );
    let r = reack_own_claims(b, &n.signer, now)
        .await
        .expect("I6120: a pass");
    assert_eq!(
        r.claimed, 0,
        "[{tag}] I6120: unowned: the pass claims nothing: {r:?}"
    );
    own(&n, &alias, &format!("i6120-owner-{tag}")).await;
    let binding = super::head_rule::owner_binding_row(b, &n.key, false, 0)
        .await
        .expect("I6120: the binding read")
        .unwrap_or_else(|| panic!("[{tag}] I6120: owned"));
    let r = reack_own_claims(b, &n.signer, now)
        .await
        .expect("I6120: a pass");
    assert_eq!(
        r.claimed, 1,
        "[{tag}] I6120: owned: one pass claims it: {r:?}"
    );
    let got = acks_of(b, &n.key, &sha).await;
    assert_eq!(got.len(), 1, "[{tag}] I6120: one claim");
    let id = hex::decode(&got[0].row_hash)
        .ok()
        .and_then(|v| <[u8; 32]>::try_from(v.as_slice()).ok())
        .map(RowId)
        .expect("I6120: the claim's row id");
    let st = super::head_rule::held_statement(b, &id)
        .await
        .expect("I6120: read")
        .expect("I6120: the claim's statement is held");
    let head =
        super::names::of_statement_names(&st).and_then(|(_, n)| super::names::single(&n, "head"));
    assert_eq!(
        head,
        Some(binding),
        "[{tag}] I6120: the claim names the binding"
    );
    let r = reack_own_claims(b, &n.signer, now)
        .await
        .expect("I6120: a pass");
    assert_eq!(r.claimed, 0, "[{tag}] I6120: never claimed twice: {r:?}");
    assert_eq!(
        acks_of(b, &n.key, &sha).await.len(),
        1,
        "[{tag}] I6120: still one claim"
    );
}

/// I6133 (HEAD-fix1; Constitution's two-standings ruling, Kernel branch
/// two-standings section J) — **a row signed in exercise of a root grant
/// names the bundle in force, whoever signs it**: a node's, an agent's or a
/// person's row of a reserved family whose rule names a delegation scope is
/// a root grantee's act (`head_rule::capacity_of`), and its head is the
/// bundle (`head_rule::head_kind`), counted or authored. Before HEAD-fix1 a
/// node's or an agent's such row was read as its owner's act and named the
/// owner binding. The control: the same node on an open family acts for its
/// owner.
#[test]
fn i6133_a_root_grant_act_names_the_bundle_whoever_signs() {
    use super::head_rule::{capacity_of, head_kind, HeadKind, Placement, SignerCapacity};
    let family = family_id("transparency_log:cosigned:{tree_size}");
    let dimension = "transparency_log:cosigned:7:v1";
    let payload = map(vec![
        ("asserted_at", Value::Uint(2_000)),
        ("dimension", Value::Text(dimension.into())),
        ("cohort_scope", Value::Text("federation".into())),
    ]);
    let leaf = super::payloads::leaf_of(&family, &payload);
    for t in ["node", "agent", "user"] {
        let types = vec![t.to_owned()];
        for counted in [false, true] {
            let capacity = capacity_of(&types, &family, Some(dimension), counted);
            assert_eq!(
                capacity,
                SignerCapacity::RootGrantee,
                "I6133: a {t} key signing under a root grant (counted: {counted})"
            );
            assert_eq!(
                head_kind(&family, leaf, Placement::of_payload(&payload), capacity),
                HeadKind::Bundle,
                "I6133: a {t} key's root-grant act names the bundle in force"
            );
        }
    }
    assert_eq!(
        capacity_of(
            &["node".to_owned()],
            &family_id("chat:*"),
            Some("chat:message:v1"),
            false
        ),
        SignerCapacity::Node,
        "I6133 control: a node's act on an open family is its owner's"
    );
}

/// I6137 (pure; HEAD-fix4; CC 3.1.2.1, Constitution v1.0-rc22-pre4
/// `names_head` = `standing` for `provenance:build_manifest:{target}`) — a
/// pipeline's build-manifest row, signed by a node or an agent key, is a
/// root grantee's act and names the bundle in force. (The door's
/// `stands_on` rule and the standing reading are witnessed in I4326, sqlite
/// and postgres.)
#[test]
fn i6137_a_build_manifest_row_names_the_bundle() {
    use super::head_rule::{capacity_of, head_kind, HeadKind, Placement, SignerCapacity};
    let family = family_id(super::build_row::BUILD_MANIFEST_FAMILY_PREFIX);
    let dimension = "provenance:build_manifest:ciris-agent-x86_64:v1";
    let payload = map(vec![
        ("asserted_at", Value::Uint(2_000)),
        ("dimension", Value::Text(dimension.into())),
        ("cohort_scope", Value::Text("federation".into())),
    ]);
    let leaf = super::payloads::leaf_of(&family, &payload);
    for t in ["node", "agent"] {
        let capacity = capacity_of(&[t.to_owned()], &family, Some(dimension), false);
        assert_eq!(
            capacity,
            SignerCapacity::RootGrantee,
            "I6137: a {t} pipeline signs its build row under its root grant"
        );
        assert_eq!(
            head_kind(&family, leaf, Placement::of_payload(&payload), capacity),
            HeadKind::Bundle,
            "I6137: a {t} pipeline's build row names the bundle in force"
        );
    }
    assert!(super::build_row::is_build_row_dimension(dimension));
    assert!(!super::build_row::is_build_row_dimension(
        "provenance:build_manifest:ciris-agent-x86_64:locale:en:v1"
    ));
}

/// I7101 (HEAD-fix8; Constitution's ruling (a): "not kept: names no head",
/// never Invalid) — a person's room act that names no roster version is NOT
/// KEPT on every plane, typed as this node's decline:
/// - the local door answers `Error::NotKept` with `NotKeptWhy::NamesNoHead`
///   (kind `federation_not_kept`, not a wait, never `federation_malformed_row`);
/// - the replicated door answers `Refused { NamesNoHead }` (nothing raised;
///   the sender's cursor advances): a LOCAL decline, NOT retryable;
/// - nothing of the row is kept either way.
pub(crate) async fn i7101_body(d: &dyn FederationDirectory, tag: &str) {
    use crate::federation::attestation_apply::AttestationRefusalReason;
    use crate::federation::NotKeptWhy;
    let person = 71;
    put_statement(
        d,
        &key_record(&key(person), &["user"], 1_000, None),
        None,
        INGEST_TIER,
    )
    .await
    .unwrap_or_else(|e| panic!("[{tag}] I7101: the person's key record: {e:?}"));
    let st = act(person, "chat:*", "chat:message:v1", "community", 72);
    let e = put_statement(d, &st, None, INGEST_TIER)
        .await
        .expect_err("I7101: a room act naming no head");
    assert!(
        matches!(
            &e,
            Error::NotKept {
                why: NotKeptWhy::NamesNoHead,
                ..
            }
        ),
        "[{tag}] I7101: not kept, names no head: {e:?}"
    );
    assert_eq!(e.kind(), "federation_not_kept", "[{tag}] I7101: its kind");
    assert!(!e.is_wait(), "[{tag}] I7101: not a wait");
    let id = RowId::of_statement(&st).expect("a row id");
    let out = super::ingest::apply_replicated_statement(d, &st, &id.0)
        .await
        .unwrap_or_else(|e| panic!("[{tag}] I7101: the replicated door raises nothing: {e:?}"));
    assert_eq!(
        out,
        super::ingest::ReplicatedStatementOutcome::Refused {
            reason: AttestationRefusalReason::NamesNoHead
        },
        "[{tag}] I7101: the replicated door declines it"
    );
    assert!(
        AttestationRefusalReason::NamesNoHead.is_local_decline()
            && !AttestationRefusalReason::NamesNoHead.is_retryable(),
        "[{tag}] I7101: a local decline, never re-offered"
    );
    assert_eq!(
        AttestationRefusalReason::NamesNoHead.as_str(),
        crate::federation::not_kept::ACT_NAMES_NO_HEAD,
        "[{tag}] I7101: the token"
    );
    assert!(
        d.get_attestation(&id.hex()).await.unwrap().is_none(),
        "[{tag}] I7101: nothing of the row is kept"
    );
}

#[cfg(feature = "sqlite")]
mod sqlite {
    use super::*;
    use crate::store::sqlite::SqliteBackend;
    use crate::store::Backend as _;

    async fn fresh() -> SqliteBackend {
        let b = SqliteBackend::open_in_memory().await.unwrap();
        b.run_migrations().await.unwrap();
        b
    }

    #[tokio::test]
    async fn i7101_a_headless_row_is_not_kept_sqlite() {
        let b = fresh().await;
        Box::pin(i7101_body(&b, "sqlite")).await;
    }

    #[tokio::test]
    async fn i6105_a_room_act_names_its_roster_sqlite() {
        let b = fresh().await;
        Box::pin(i6105_body(&b, "sqlite")).await;
    }

    #[tokio::test]
    async fn i6106_an_unowned_node_names_no_head_sqlite() {
        let b = fresh().await;
        Box::pin(i6106_body(&b, "sqlite")).await;
    }

    #[tokio::test]
    async fn i6120_claims_resume_when_the_binding_lands_sqlite() {
        let b = fresh().await;
        Box::pin(i6120_body(&b, "sqlite")).await;
    }

    #[tokio::test]
    async fn i6123_an_unowned_node_is_findable_sqlite() {
        let b = fresh().await;
        Box::pin(i6123_body(&b, "sqlite")).await;
    }

    #[tokio::test]
    async fn i6118_an_owned_node_names_its_binding_sqlite() {
        let b = fresh().await;
        Box::pin(i6118_body(&b, "sqlite")).await;
    }

    #[tokio::test]
    async fn i6119_lifts_and_root_grant_acts_at_the_door_sqlite() {
        let b = fresh().await;
        Box::pin(i6119_body(&b, "sqlite")).await;
    }
}

#[cfg(feature = "postgres")]
mod postgres {
    use super::*;
    use crate::store::postgres::PostgresBackend;
    use crate::store::Backend as _;

    async fn fresh() -> Option<PostgresBackend> {
        let dsn = crate::test_pg::empty_dsn()?;
        let b = PostgresBackend::connect(&dsn).await.unwrap();
        b.run_migrations().await.unwrap();
        Some(b)
    }

    #[tokio::test]
    async fn i7101_a_headless_row_is_not_kept_postgres() {
        let Some(b) = fresh().await else {
            eprintln!("skipping: CIRIS_PERSIST_TEST_PG_URL unset");
            return;
        };
        Box::pin(i7101_body(&b, "postgres")).await;
    }

    #[tokio::test]
    async fn i6105_a_room_act_names_its_roster_postgres() {
        let Some(b) = fresh().await else {
            eprintln!("skipping: CIRIS_PERSIST_TEST_PG_URL unset");
            return;
        };
        Box::pin(i6105_body(&b, "postgres")).await;
    }

    #[tokio::test]
    async fn i6106_an_unowned_node_names_no_head_postgres() {
        let Some(b) = fresh().await else {
            eprintln!("skipping: CIRIS_PERSIST_TEST_PG_URL unset");
            return;
        };
        Box::pin(i6106_body(&b, "postgres")).await;
    }

    #[tokio::test]
    async fn i6120_claims_resume_when_the_binding_lands_postgres() {
        let Some(b) = fresh().await else {
            eprintln!("skipping: CIRIS_PERSIST_TEST_PG_URL unset");
            return;
        };
        Box::pin(i6120_body(&b, "postgres")).await;
    }

    #[tokio::test]
    async fn i6123_an_unowned_node_is_findable_postgres() {
        let Some(b) = fresh().await else {
            eprintln!("skipping: CIRIS_PERSIST_TEST_PG_URL unset");
            return;
        };
        Box::pin(i6123_body(&b, "postgres")).await;
    }

    #[tokio::test]
    async fn i6118_an_owned_node_names_its_binding_postgres() {
        let Some(b) = fresh().await else {
            eprintln!("skipping: CIRIS_PERSIST_TEST_PG_URL unset");
            return;
        };
        Box::pin(i6118_body(&b, "postgres")).await;
    }

    #[tokio::test]
    async fn i6119_lifts_and_root_grant_acts_at_the_door_postgres() {
        let Some(b) = fresh().await else {
            eprintln!("skipping: CIRIS_PERSIST_TEST_PG_URL unset");
            return;
        };
        Box::pin(i6119_body(&b, "postgres")).await;
    }
}
