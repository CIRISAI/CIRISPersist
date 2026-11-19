//! v62.0.0 (wave T2, on W1's rooted edition-2 trust root) — **a steward
//! purge executed on one node from its founders' voices, served, and
//! applied on a second node**, on sqlite and postgres. Needs W1's
//! `edition2::fixture_trust_root` (`W1.api.md` v1): drop this module if
//! W1b is not in the synthesis.
//!
//! - **I3182** node A: the founders' `takedown_notice:steward_purge` voices
//!   are `Pending` one by one; `purge_rows_edition2` with 2 of 3 founders
//!   (`quorum:2/3`) executes the selection: the report's cosigners are the
//!   two voices and the header is A's own (`origin = local`).
//! - **I3183** A serves the execution as a bundle whose notice envelope
//!   carries the statements (`edition2_statements`), never a cosignature.
//! - **I3184** node B RECEIVES A's root (the bundle; A's
//!   key records, founding voices and charter, all A's own statements,
//!   through its replicated door) and adds its
//!   OWN acceptance edge, so both nodes hold one root and one head:
//!   a bundle carrying ONE founder's voice is refused `quorum_not_met`;
//!   the bundle A served is admitted and counted HERE, and B records the
//!   header (`origin = replicated`) and the tombstone.

use super::fixture_switch as e2;
use super::fixture_trust_root::{rooted_trust_root, RootedTrustRoot};
use super::ingest::StatementOutcome;
use super::names::RowId;
use super::typed::{takedown_payload, NoticeText, TAKEDOWN_PREFIX};
use crate::federation::steward_purge::{
    self as sp, unauthorised_reason as why, PurgeBundle, PurgeSelection, StewardPurgeNotice,
};
use crate::federation::{Error, FederationDirectory};

const PROTOCOL: &str = "quorum:2/3";

/// Node A's and node B's E0 seeds (their node keys).
const A_NODE: &str = "t2-node-a";
const B_NODE: &str = "t2-node-b";

fn rid(st: &[u8]) -> RowId {
    RowId::of_statement(st).unwrap()
}

fn reason_of(e: Error) -> String {
    match e {
        Error::PurgeRefused { body, .. } => body["reason"].as_str().unwrap_or_default().to_owned(),
        other => other.kind().to_owned(),
    }
}

/// Founder `i`'s voice over the notice for `digest` (the selection digest).
fn voice(r: &RootedTrustRoot, i: usize, digest: &[u8; 32], at_ms: u64) -> Vec<u8> {
    let notice = NoticeText {
        claim_text: "t2 rooted purge".into(),
        good_faith_statement: "the selection never belonged".into(),
        jurisdiction: "ZZ".into(),
    };
    let p = takedown_payload(
        "steward_purge",
        &r.root,
        digest,
        &[],
        &notice,
        at_ms + 7 * 24 * 3_600_000,
        at_ms,
    )
    .unwrap();
    ciris_verify_core::edition2::sign_row_statement(
        &r.founder_key(i),
        &r.founders[i],
        &r.root,
        "scores",
        &ciris_verify_core::namespace_match::family_id(TAKEDOWN_PREFIX),
        &p,
        vec![],
    )
    .unwrap()
}

fn bundle_of(statements: &[Vec<u8>], record_ids: Vec<String>) -> PurgeBundle {
    PurgeBundle {
        notice: StewardPurgeNotice {
            envelope: sp::edition2_notice_envelope(statements),
            cosignatures: vec![],
        },
        derived_from: vec![String::new(); record_ids.len()],
        record_ids,
        admitted_at: chrono::Utc::now(),
    }
}

/// A row to purge on A: an agent device's custody report (no human subject).
async fn victim<D: FederationDirectory + ?Sized>(a: &D) -> PurgeSelection {
    e2::put_key(a, "t2-purge-device", &["agent"]).await;
    let st = e2::custody_statement(
        "t2-purge-device",
        &[0x5d; 32],
        Some(10),
        "federation",
        None,
        e2::ms(chrono::Utc::now()),
    );
    e2::put_statement(a, &st).await.expect("the row to purge");
    PurgeSelection::ByIds {
        ids: vec![format!("attestation:{}", rid(&st).hex())],
    }
}

/// Node B RECEIVES A's root (one root identity, one head): the genesis
/// bundle in force (the founders' placed keys), A's own `key:record`
/// statements for the root (and any founder B lacks), A's
/// founding `group:roster` voices and the root's charter self-edge, each
/// through B's replicated statement door; then B's OWN `trust:accepts:v1`
/// edge to that root (W1's `put_acceptance`, naming B's held head), signed
/// by B's node key (its E0 seed, `B_NODE`).
async fn receive_root<D: FederationDirectory + ?Sized>(a: &D, b: &D, r: &RootedTrustRoot) {
    super::fixture_genesis::install_v2(b)
        .await
        .expect("B holds the genesis bundle in force");
    // The root's key, and any founder's key B does not hold yet: A's own
    // `key:record` statements, replayed (never re-minted on B).
    let keys = std::iter::once(&r.root).chain(r.founders.iter());
    for k in keys {
        if b.lookup_public_key(k).await.unwrap().is_some() {
            continue;
        }
        let kid = super::ingest::kid_of_identity_ref(k).expect("an identity-ref");
        let held = super::ingest::held_keys_for_kid(a, &kid).await.unwrap();
        let records = held
            .valid_records(&kid)
            .unwrap_or_else(|_| panic!("A holds a valid record of {k}"));
        assert!(!records.is_empty(), "A holds a record of {k}");
        for rec in records {
            super::ingest::apply_replicated_statement(b, &rec.statement, &rec.row_id)
                .await
                .expect("B admits A's key record");
        }
    }
    for row in [&r.birth, &r.charter] {
        let voices = a.edition2_voices(row).await.unwrap();
        assert!(!voices.is_empty(), "A holds the root's rows");
        for st in voices {
            super::ingest::apply_replicated_statement(b, &st, &row.0)
                .await
                .expect("B admits A's root rows");
        }
    }
    // B's OWN acceptance edge, through W1's helper: its
    // `attached_head_digest` is the held head's row hash as bytes, stated
    // after the root's rows. (T2-fix2: the hand-built JSON edge named the
    // head as text from `attach_head_for`, so B never read the root as
    // rooted.)
    super::fixture_trust_root::put_acceptance(b, r, &e2::signing_key(B_NODE), &e2::kid(B_NODE))
        .await
        .expect("B's own acceptance edge");
    // T2-fix5 — the verdict is printed: `NotRooted` names which half of the
    // read failed (the chain, B's own acceptance edge, or the charter).
    let standing = crate::federation::canonical_community::stored_standing(b, &r.root)
        .await
        .unwrap();
    assert!(
        matches!(
            standing,
            crate::federation::canonical_community::StoredStanding::Rooted(_)
        ),
        "B reads A's root as rooted: {standing:?}"
    );
}

async fn body<D: FederationDirectory + ?Sized>(a: &D, b: &D) {
    let ra = rooted_trust_root(a, &[1, 2, 3], PROTOCOL).await;
    receive_root(a, b, &ra).await;
    let sel = victim(a).await;
    let dry = sp::purge_dry_run(a, &sel).await.expect("the dry run");
    let digest: [u8; 32] = hex::decode(&dry.selection_digest)
        .unwrap()
        .try_into()
        .unwrap();
    let t = e2::ms(chrono::Utc::now()) - 60_000;
    let (v0, v1) = (voice(&ra, 0, &digest, t), voice(&ra, 1, &digest, t));

    // I3182 — on A: each voice kept; two of three execute the purge.
    for v in [&v0, &v1] {
        let out = e2::put_statement(a, v)
            .await
            .expect("I3182 a founder's voice");
        assert!(
            matches!(out, StatementOutcome::Pending { .. }),
            "I3182 {out:?}"
        );
    }
    let report = sp::purge_rows_edition2(a, &sel, &rid(&v0), "t2-node-a")
        .await
        .expect("I3182 two founders of three meet quorum:2/3");
    assert_eq!(
        report.notice_id,
        rid(&v0).hex(),
        "I3182 the notice id is the row id"
    );
    assert_eq!(report.record_count, 1, "I3182");
    let mut cosigners = report.cosigners.clone();
    cosigners.sort();
    let mut want = vec![ra.founders[0].clone(), ra.founders[1].clone()];
    want.sort();
    assert_eq!(cosigners, want, "I3182 the counted voices");
    let header = a
        .purge_execution(&report.notice_id)
        .await
        .unwrap()
        .expect("I3182 A's header");
    assert_eq!(header.origin, sp::origin::LOCAL, "I3182");

    // I3183 — served as statements.
    let served = sp::list_purge_bundles_since(a, None, 10).await.unwrap();
    let bundle = served
        .into_iter()
        .find(|bu| {
            bu.notice
                .envelope
                .get(sp::EDITION2_STATEMENTS_MEMBER)
                .is_some()
        })
        .expect("I3183 the execution is served");
    assert!(
        bundle.notice.cosignatures.is_empty(),
        "I3183 no cosignature"
    );
    assert_eq!(
        bundle.notice.envelope[sp::EDITION2_STATEMENTS_MEMBER]
            .as_array()
            .map(Vec::len),
        Some(2),
        "I3183 both voices ride"
    );

    // I3184 — on B: one voice is short; the served bundle is counted here.
    let e = sp::apply_replicated_purge(
        b,
        &bundle_of(std::slice::from_ref(&v0), bundle.record_ids.clone()),
        "t2-node-b",
    )
    .await
    .unwrap_err();
    assert_eq!(
        reason_of(e),
        why::QUORUM_NOT_MET,
        "I3184 one voice of three"
    );
    let out = sp::apply_replicated_purge(b, &bundle, "t2-node-b")
        .await
        .expect("I3184 the served bundle applies on B");
    assert_eq!(out.notice_id, rid(&v0).hex(), "I3184");
    assert_eq!(out.tombstoned, 1, "I3184 the tombstone");
    let header = b
        .purge_execution(&out.notice_id)
        .await
        .unwrap()
        .expect("I3184 B's header");
    assert_eq!(header.origin, sp::origin::REPLICATED, "I3184");
}

#[cfg(feature = "sqlite")]
async fn sqlite_node(name: &str) -> crate::store::sqlite::SqliteBackend {
    use crate::store::Backend as _;
    let b = crate::store::sqlite::SqliteBackend::open_in_memory()
        .await
        .unwrap();
    b.run_migrations().await.unwrap();
    let node = e2::put_key(&b, name, &["node"]).await;
    b.set_node_key_id(node);
    b
}

#[cfg(feature = "postgres")]
async fn postgres_node(name: &str) -> Option<crate::store::postgres::PostgresBackend> {
    use crate::store::Backend as _;
    let dsn = crate::test_pg::empty_dsn()?;
    let b = crate::store::postgres::PostgresBackend::connect(&dsn)
        .await
        .unwrap();
    b.run_migrations().await.unwrap();
    let node = e2::put_key(&b, name, &["node"]).await;
    b.set_node_key_id(node);
    Some(b)
}

#[cfg(feature = "sqlite")]
#[tokio::test]
async fn i3182_i3184_rooted_purge_replicates_sqlite() {
    let (a, b) = (
        sqlite_node("t2-node-a").await,
        sqlite_node("t2-node-b").await,
    );
    Box::pin(body(&a, &b)).await;
}

#[cfg(feature = "postgres")]
#[tokio::test]
async fn i3182_i3184_rooted_purge_replicates_postgres() {
    let (Some(a), Some(b)) = (postgres_node(A_NODE).await, postgres_node(B_NODE).await) else {
        return;
    };
    Box::pin(body(&a, &b)).await;
}
