//! v62.0.0 (CONTENT-A2; the Constitution's room-content rule R1–R12, names
//! of 2026-11-22) — witnesses of **the room-content door**: the refs
//! grammar's two additions, that nothing waits on a predecessor or a tip,
//! and the `membership:keeps` gate. Every store-facing body runs on sqlite
//! and postgres.
//!
//! - **I6703** (pure) — persist's copy of `check_refs` (deleted at the
//!   Verify 23.5.1 pin, where Verify's reader carries the same rules):
//!   - `refs.further_prev` is a row-ref-set allowed only beside `refs.prev`,
//!     so one without `prev` is `malformed:further_prev`;
//!   - an unsorted set is `set_order:further_prev`;
//!   - `refs.trusted_through` admits 64 tips, and 65 are
//!     `trusted_through_too_many`.
//! - **I6704** — a content row naming an UNHELD `refs.prev`, and a row naming
//!   an UNHELD `refs.trusted_through`, land concluded at the statement door.
//!   No gate reads either role (R4: nothing waits on them).
//! - **I6705** — `admission::check_membership_keeps_counted` on a keeps row of
//!   a community whose member `x` was removed by count. It is called on the
//!   keeps row directly, because the vendored registry closes
//!   `membership:{stage}` without `keeps` until CC's pre4 re-vendor, so the
//!   statement door refuses the dimension before this gate. The cases:
//!   - citing an unheld row waits (`federation_withdraws_target_unheld`
//!     outside a fold attempt);
//!   - citing the roster head, another member's end, no row or two rows is
//!     `keeps_cites_no_end`;
//!   - **I6733** (v62.0.0, CONTENT-A2b): as a fold attempt, the first two
//!     (a HELD cited row that is no end: read from another row) are HELD
//!     under `keeps_cites_no_end`, concluding nothing; the last two (the row
//!     alone shows it) leave no hold mark;
//!   - citing `x`'s removal, counted, on one member's voice is short
//!     (`membership_keeps_short`);
//!   - an AUTHORED keeps row is admitted, untouched (the fold never reads it,
//!     R7).
//!
//! **Owed at the pins** (not writable on this tree):
//! - The door-level keeps witnesses (a keeps row through the statement door:
//!   held short, then landed on the count) pass at the pre4 registry
//!   re-vendor.
//! - `further_prev` through the door (Verify 23.5.0 refuses it as
//!   `unexpected:refs`) and the cap at the door pass at the Verify 23.5.1
//!   pin, as new `produce_invariants::refs_cases` rows.

use ciris_verify_core::cde::{self, Value};

use super::fixture_switch as e2;
use super::group::{MembershipRecord, MEMBERSHIP_PREFIX};
use super::group_fixtures::{held_head, membership_voices, put_voices, row_id_of};
use super::ingest::{put_statement, StatementOutcome, INGEST_TIER, STATEMENT_MEMBER};
use super::names::RowId;
use super::produce::{check_refs, TRUSTED_THROUGH_MAX, TRUSTED_THROUGH_TOO_MANY};
use crate::federation::types::{identity_type, Attestation, CommunityMembershipRevocation};
use crate::federation::{malformed_row, Error, FederationDirectory};

fn t(s: &str) -> Value {
    Value::Text(s.into())
}

fn det_map(mut m: Vec<(&str, Value)>) -> Value {
    m.sort_by_key(|(k, _)| cde::encode(&t(k)));
    Value::Map(m.into_iter().map(|(k, v)| (t(k), v)).collect())
}

fn rref(d: &[u8; 32]) -> Value {
    ciris_verify_core::edition2::row_ref(d)
}

/// A sorted, duplicate-free row-ref-set of `ds`.
fn set(ds: &[[u8; 32]]) -> Value {
    let mut a: Vec<Value> = ds.iter().map(rref).collect();
    a.sort_by_key(cde::encode);
    a.dedup();
    Value::Array(a)
}

fn instant_of(ms: u64) -> chrono::DateTime<chrono::Utc> {
    use chrono::TimeZone as _;
    chrono::Utc
        .timestamp_millis_opt(i64::try_from(ms).unwrap())
        .single()
        .unwrap()
}

fn now_ms() -> u64 {
    e2::ms(crate::host::clock::now())
}

/// **I6703 (v62.0.0, CONTENT-A2; pure)** — the copy's two additions.
#[test]
fn i6703_check_refs_carries_further_prev_and_the_tip_cap() {
    let p = rref(&[0x11; 32]);
    let ok = det_map(vec![
        ("prev", p.clone()),
        ("further_prev", set(&[[0x12; 32], [0x13; 32]])),
    ]);
    check_refs(&ok).expect("I6703 prev with further_prev");
    let alone = det_map(vec![("further_prev", set(&[[0x12; 32]]))]);
    assert_eq!(
        check_refs(&alone),
        Err("malformed:further_prev"),
        "I6703 further_prev without prev"
    );
    let mut unsorted: Vec<Value> = vec![rref(&[0x12; 32]), rref(&[0x13; 32])];
    unsorted.sort_by_key(cde::encode);
    unsorted.reverse();
    let bad_order = det_map(vec![
        ("prev", p.clone()),
        ("further_prev", Value::Array(unsorted)),
    ]);
    assert_eq!(
        check_refs(&bad_order),
        Err("set_order:further_prev"),
        "I6703 an unsorted further_prev"
    );
    let empty = det_map(vec![("prev", p), ("further_prev", Value::Array(vec![]))]);
    assert_eq!(
        check_refs(&empty),
        Err("malformed:further_prev"),
        "I6703 an empty further_prev"
    );
    let tips = |n: usize| -> Vec<[u8; 32]> {
        (0..n)
            .map(|i| {
                let mut d = [0u8; 32];
                d[..8].copy_from_slice(&(i as u64).to_be_bytes());
                d
            })
            .collect()
    };
    check_refs(&det_map(vec![(
        "trusted_through",
        set(&tips(TRUSTED_THROUGH_MAX)),
    )]))
    .expect("I6703 64 tips");
    assert_eq!(
        check_refs(&det_map(vec![(
            "trusted_through",
            set(&tips(TRUSTED_THROUGH_MAX + 1)),
        )])),
        Err(TRUSTED_THROUGH_TOO_MANY),
        "I6703 65 tips"
    );
    assert_eq!(TRUSTED_THROUGH_TOO_MANY, "trusted_through_too_many");
}

/// `seed`'s own `chat:message` row at its `self` scope, naming `refs`.
fn chat_at_self(seed: &str, refs: Value, at: u64) -> Vec<u8> {
    let p = det_map(vec![
        ("asserted_at", Value::Uint(at)),
        ("author", t(&e2::kid(seed))),
        ("dimension", t("chat:message:v1")),
        ("cohort_scope", t("self")),
        ("refs", refs),
    ]);
    ciris_verify_core::edition2::sign_row_statement(
        &e2::signing_key(seed),
        &e2::kid(seed),
        &e2::kid(seed),
        "scores",
        &ciris_verify_core::namespace_match::family_id("chat:*"),
        &p,
        vec![],
    )
    .expect("I6704: sign a chat row")
}

/// I6704: no wait on `refs.prev` or `refs.trusted_through`.
pub(crate) async fn no_wait_body(d: &dyn FederationDirectory) {
    let a = "k2-nowait-a";
    e2::put_key(d, a, &[identity_type::USER]).await;
    let at = now_ms() - 60_000;
    for (what, refs) in [
        ("an unheld prev", det_map(vec![("prev", rref(&[0x61; 32]))])),
        (
            "an unheld tip",
            det_map(vec![("trusted_through", set(&[[0x62; 32]]))]),
        ),
        (
            "both",
            det_map(vec![
                ("prev", rref(&[0x63; 32])),
                ("trusted_through", set(&[[0x64; 32], [0x65; 32]])),
            ]),
        ),
    ] {
        let st = chat_at_self(a, refs, at);
        let id = RowId::of_statement(&st).expect("I6704 a row");
        let o = put_statement(d, &st, None, INGEST_TIER)
            .await
            .unwrap_or_else(|e| panic!("I6704 {what}: refused: {e:?}"));
        assert!(
            matches!(o, StatementOutcome::Row { .. }),
            "I6704 {what}: lands, never waits: {o:?}"
        );
        assert!(
            super::fold::why_held(d, &id).await.unwrap().is_none(),
            "I6704 {what}: not held"
        );
        assert!(
            d.get_attestation(&id.hex()).await.unwrap().is_some(),
            "I6704 {what}: concluded"
        );
    }
}

/// The keeps row `statement` signed by `signer`, as the attestation plane
/// sees it at its door (it carries its statement).
fn keeps_row(statement: &[u8], signer: &str, member: &str, at: u64) -> Attestation {
    let id = RowId::of_statement(statement).expect("I6705 a row").hex();
    let instant = instant_of(at).to_rfc3339_opts(chrono::SecondsFormat::Millis, true);
    serde_json::from_value(serde_json::json!({
        "attestation_id": id,
        "attesting_key_id": e2::kid(signer),
        "attested_key_id": member,
        "attestation_type": "scores",
        "asserted_at": instant,
        "attestation_envelope": { STATEMENT_MEMBER: hex::encode(statement) },
        "original_content_hash": "",
        "scrub_signature_classical": "",
        "scrub_key_id": e2::kid(signer),
        "scrub_timestamp": instant,
        "persist_row_hash": id,
        "cohort_scope": "federation",
    }))
    .expect("I6705: a row")
}

/// A `membership:keeps` payload for `member` of `group`, citing `cites`,
/// over `head`, adding `tip`; `author` for an authored one.
fn keeps_payload(
    group: &str,
    member: &str,
    head: &RowId,
    cites: &[[u8; 32]],
    tip: [u8; 32],
    author: Option<&str>,
    at: u64,
) -> Value {
    let mut refs = vec![("head", rref(&head.0)), ("trusted_through", set(&[tip]))];
    if !cites.is_empty() {
        refs.push(("also", det_map(vec![("cites", set(cites))])));
    }
    let mut m = vec![
        ("asserted_at", Value::Uint(at)),
        ("dimension", t("membership:keeps:v1")),
        ("group_kind", t("community")),
        ("group", t(group)),
        ("member", t(member)),
        ("refs", det_map(refs)),
    ];
    if let Some(a) = author {
        m.push(("author", t(a)));
    }
    det_map(m)
}

fn sign_keeps(seed: &str, member: &str, p: &Value) -> Vec<u8> {
    ciris_verify_core::edition2::sign_row_statement(
        &e2::signing_key(seed),
        &e2::kid(seed),
        member,
        "scores",
        &ciris_verify_core::namespace_match::family_id(MEMBERSHIP_PREFIX),
        p,
        vec![],
    )
    .expect("I6705: sign a keeps row")
}

fn keeps_reason(e: &Error) -> Option<&'static str> {
    match e {
        Error::MalformedRow { reason, .. } => Some(*reason),
        _ => None,
    }
}

/// I6705: the keeps gate, called on the row.
pub(crate) async fn keeps_gate_body(d: &dyn FederationDirectory) {
    use crate::federation::admission::{check_membership_keeps_counted, MEMBERSHIP_KEEPS_SHORT};
    let (m1, m2, m3, x) = ("k2-keeps-m1", "k2-keeps-m2", "k2-keeps-m3", "k2-keeps-x");
    for s in [m1, m2, m3, x] {
        e2::put_key(d, s, &[identity_type::USER]).await;
    }
    let c = super::voices_invariants::found_community(
        d,
        "k2-keeps-g",
        &[m1, m2, m3, x],
        "majority",
        None,
    )
    .await;
    let gid = c.community_key_id.clone();
    let (head, _) = held_head(d, &gid)
        .await
        .expect("I6705: the community's roster head is held");
    let at = now_ms() - 60_000;
    let instant = instant_of(at);
    let removal = MembershipRecord::CommunityRemoval(CommunityMembershipRevocation {
        community_key_id: gid.clone(),
        removed_identity_key_id: e2::kid(x),
        removed_at: instant,
        effective_at: instant,
        reason: None,
        witness_set: Vec::new(),
        persist_row_hash: String::new(),
        leaf: crate::federation::types::RevocationLeaf::Removal,
    });
    let keys: Vec<_> = [m1, m2, m3].iter().map(|s| e2::signing_key(s)).collect();
    let signers: Vec<&_> = keys.iter().collect();
    let voices = membership_voices(&removal, Some(&head), &signers);
    let o = put_voices(d, &voices)
        .await
        .expect("I6705: the removal's voices");
    assert!(
        matches!(o, StatementOutcome::Row { .. }),
        "I6705: x's removal lands on three of four: {o:?}"
    );
    let end = row_id_of(&voices[0]);
    let member = e2::kid(x);
    let tip = [0x70; 32];
    let gate = |p: Value, signer: &'static str, who: String| {
        Box::pin(async move {
            let st = sign_keeps(signer, &who, &p);
            let row = keeps_row(&st, signer, &who, at);
            check_membership_keeps_counted(d, &row).await
        })
    };

    // An unheld cited row: the keeps row waits.
    let e = gate(
        keeps_payload(&gid, &member, &head, &[[0x71; 32]], tip, None, at),
        m1,
        member.clone(),
    )
    .await
    .expect_err("I6705 an unheld end");
    assert!(
        matches!(e, Error::WithdrawsTargetUnheld { .. }),
        "I6705 an unheld end waits: {e:?}"
    );

    // Not an end of x's seat in this group: keeps_cites_no_end. v62.0.0
    // (CONTENT-A2b) — I6733: run as a fold attempt, a HELD cited row that is
    // no end marks the attempt held under the token (it concludes nothing:
    // read from another row, CC 2.7.3); citing no row or two shows it on the
    // row alone and leaves no hold mark (refused by name, not kept).
    for (what, p, who, held) in [
        (
            "the roster head",
            keeps_payload(&gid, &member, &head, &[head.0], tip, None, at),
            member.clone(),
            true,
        ),
        (
            "x's removal, for another member",
            keeps_payload(&gid, &e2::kid(m2), &head, &[end.0], tip, None, at),
            e2::kid(m2),
            true,
        ),
        (
            "no row",
            keeps_payload(&gid, &member, &head, &[], tip, None, at),
            member.clone(),
            false,
        ),
        (
            "two rows",
            keeps_payload(&gid, &member, &head, &[end.0, head.0], tip, None, at),
            member.clone(),
            false,
        ),
    ] {
        let e = gate(p.clone(), m1, who.clone())
            .await
            .expect_err("I6705 a keeps row citing no end");
        assert_eq!(
            keeps_reason(&e),
            Some(malformed_row::KEEPS_CITES_NO_END),
            "I6705 {what}: {e:?}"
        );
        let (e, att) = super::fold::attempt(RowId([0x7a; 32]), None, gate(p, m1, who)).await;
        assert!(e.is_err(), "I6733 {what}: it concludes nothing: {e:?}");
        assert_eq!(
            att.held.as_ref().map(|(r, _)| r.as_str()),
            held.then_some(malformed_row::KEEPS_CITES_NO_END),
            "I6733 {what}: held under the token iff the cited row is held and no end: {:?}",
            att.held
        );
    }

    // x's removal, counted, on one member's voice: short.
    let e = gate(
        keeps_payload(&gid, &member, &head, &[end.0], tip, None, at),
        m1,
        member.clone(),
    )
    .await
    .expect_err("I6705 one voice of four");
    assert!(
        matches!(&e, Error::InvalidArgument(m) if m.starts_with(MEMBERSHIP_KEEPS_SHORT)),
        "I6705 one voice is short: {e:?}"
    );

    // An authored keeps row (the member's own word) is admitted untouched.
    gate(
        keeps_payload(&gid, &member, &head, &[end.0], tip, Some(&member), at),
        x,
        member.clone(),
    )
    .await
    .expect("I6705 an authored keeps row is not this gate's to count");
}

#[cfg(feature = "sqlite")]
async fn sqlite() -> crate::store::sqlite::SqliteBackend {
    use crate::store::Backend as _;
    let b = crate::store::sqlite::SqliteBackend::open_in_memory()
        .await
        .unwrap();
    b.run_migrations().await.unwrap();
    b
}

#[cfg(feature = "postgres")]
async fn postgres() -> Option<crate::store::postgres::PostgresBackend> {
    use crate::store::Backend as _;
    let dsn = crate::test_pg::empty_dsn()?;
    let b = crate::store::postgres::PostgresBackend::connect(&dsn)
        .await
        .unwrap();
    b.run_migrations().await.unwrap();
    Some(b)
}

#[cfg(feature = "sqlite")]
#[tokio::test]
async fn i6704_nothing_waits_on_prev_or_tips_sqlite() {
    Box::pin(no_wait_body(&sqlite().await)).await;
}

#[cfg(feature = "postgres")]
#[tokio::test]
async fn i6704_nothing_waits_on_prev_or_tips_postgres() {
    let Some(b) = postgres().await else {
        return;
    };
    Box::pin(no_wait_body(&b)).await;
}

#[cfg(feature = "sqlite")]
#[tokio::test]
async fn i6705_the_keeps_gate_sqlite() {
    Box::pin(keeps_gate_body(&sqlite().await)).await;
}

#[cfg(feature = "postgres")]
#[tokio::test]
async fn i6705_the_keeps_gate_postgres() {
    let Some(b) = postgres().await else {
        return;
    };
    Box::pin(keeps_gate_body(&b)).await;
}
