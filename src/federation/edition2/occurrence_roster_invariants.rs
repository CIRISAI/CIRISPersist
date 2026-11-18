//! **I3045–I3047** (wave O1, S1; CC 3.3.6.4): the self-roster door's two
//! paths for an EDITION-2 addition (an `identity:occurrence` bind of a
//! user-role key under a user self of two or more roster keys), on sqlite
//! and postgres.
//!
//! - I3045 (the quorum path): with two roster keys, the self's genesis
//!   key's author statement alone is a held proposal (`Voice`; this node's
//!   receipt in `ceg_roster_proposals`; the key not active); a second roster
//!   key signing the same payload as the self lands it (`Row`), and the
//!   receipt is settled.
//! - I3046 (the lone path): an unanswered proposal does not land before
//!   `W_self`, and lands after it on `self_roster::execute_for`.
//! - I3048–I3049 (S1b, `eviction_body`): an edition-2 eviction through the
//!   two paths; a proposer's own withdrawal; the deterministic proposer.
//! - I3047 (objection): a strict majority of the OTHER roster keys objecting
//!   (`objection:raised` statements naming the bind's row id) keeps the lone
//!   path shut after the window.

use ciris_crypto::composite::CompositeSigningKey;
use ciris_verify_core::cde::Value;
use ciris_verify_core::edition2::sign_row_statement;

use super::door_invariants::fixture::{iref, key, key_record, map};
use super::ingest::{put_statement, StatementOutcome, INGEST_TIER};
use super::names::RowId;
use super::occurrence::OCCURRENCE_FAMILY;
use crate::federation::self_roster as sr;
use crate::federation::{Error, FederationDirectory};

fn now_ms() -> u64 {
    u64::try_from(crate::host::clock::now().timestamp_millis()).unwrap()
}

fn advance(secs: i64) {
    crate::federation::steward_purge::test_clock::set(Some(
        chrono::Utc::now() + chrono::Duration::seconds(secs),
    ));
}

fn reset_clock() {
    crate::federation::steward_purge::test_clock::set(None);
}

/// One statement over a bind of `occurrence` under `identity` (authored by
/// the identity) standing on the roster row `head`, `signer` signing as
/// `iss`.
fn bind_at(
    signer: &CompositeSigningKey,
    iss: &str,
    identity: &str,
    occurrence: &str,
    asserted_at: u64,
    head: &RowId,
) -> Vec<u8> {
    let m = vec![
        ("asserted_at", Value::Uint(asserted_at)),
        ("author", Value::Text(identity.to_owned())),
        ("identity_key_id", Value::Text(identity.to_owned())),
        ("occurrence_key_id", Value::Text(occurrence.to_owned())),
        ("device_class", Value::Text("laptop".to_owned())),
        (
            "refs",
            map(vec![(
                "head",
                ciris_verify_core::edition2::row_ref(&head.0),
            )]),
        ),
    ];
    sign_row_statement(
        signer,
        iss,
        occurrence,
        "scores",
        OCCURRENCE_FAMILY,
        &map(m),
        vec![],
    )
    .unwrap()
}

/// The identity's current roster head (`occurrence::current_roster_head`).
async fn head(d: &dyn FederationDirectory, identity: &str) -> RowId {
    super::occurrence::current_roster_head(d, identity)
        .await
        .unwrap()
        .expect("the identity's key record is held")
}

/// [`bind_at`] on the identity's current roster head.
async fn bind(
    d: &dyn FederationDirectory,
    signer: &CompositeSigningKey,
    iss: &str,
    identity: &str,
    occurrence: &str,
    asserted_at: u64,
) -> Vec<u8> {
    let h = head(d, identity).await;
    bind_at(signer, iss, identity, occurrence, asserted_at, &h)
}

/// A voice of an `identity:occurrence_revocation` (an eviction, CC
/// 3.3.6.4), the self's (`iss` = `author` = the identity), signed by the
/// E0 seed `seed`, on the identity's current roster head.
async fn revocation_voice(
    d: &dyn FederationDirectory,
    seed: &str,
    rev: &crate::federation::types::IdentityOccurrenceRevocation,
    asserted_at: u64,
) -> Vec<u8> {
    let ms = |t: chrono::DateTime<chrono::Utc>| u64::try_from(t.timestamp_millis()).unwrap();
    let h = head(d, &rev.identity_key_id).await;
    let payload = map(vec![
        ("asserted_at", Value::Uint(asserted_at)),
        ("author", Value::Text(rev.identity_key_id.clone())),
        ("identity_key_id", Value::Text(rev.identity_key_id.clone())),
        (
            "occurrence_key_id",
            Value::Text(rev.occurrence_key_id.clone()),
        ),
        ("revoked_at", Value::Uint(ms(rev.revoked_at))),
        ("effective_at", Value::Uint(ms(rev.effective_at))),
        (
            "refs",
            map(vec![("head", ciris_verify_core::edition2::row_ref(&h.0))]),
        ),
    ]);
    sign_row_statement(
        &super::fixture_switch::signing_key(seed),
        &rev.identity_key_id,
        &rev.occurrence_key_id,
        "scores",
        super::occurrence::OCCURRENCE_REVOCATION_FAMILY,
        &payload,
        vec![],
    )
    .unwrap()
}

async fn put(d: &dyn FederationDirectory, st: &[u8]) -> Result<StatementOutcome, Error> {
    Box::pin(put_statement(d, st, None, INGEST_TIER)).await
}

/// `device`'s own statement, then `author`'s as the self `u`: the outcome
/// of the author's, and the bind's row id.
async fn propose(
    d: &dyn FederationDirectory,
    u: &str,
    author: &CompositeSigningKey,
    device: &CompositeSigningKey,
    at: u64,
) -> (StatementOutcome, RowId) {
    let k = iref(device);
    let own = bind(d, device, &k, u, &k, at).await;
    let row = RowId::of_statement(&own).unwrap();
    assert!(
        matches!(put(d, &own).await, Ok(StatementOutcome::Voice { .. })),
        "the device's own statement is held"
    );
    let out = put(d, &bind(d, author, u, u, &k, at).await).await.unwrap();
    (out, row)
}

async fn active(d: &dyn FederationDirectory, u: &str, k: &str) -> bool {
    d.list_identity_occurrences_active(u)
        .await
        .unwrap()
        .iter()
        .any(|o| o.occurrence_key_id == k)
}

async fn open(d: &dyn FederationDirectory, u: &str) -> Vec<String> {
    d.list_open_edition2_roster_proposals(Some(u))
        .await
        .unwrap()
        .into_iter()
        .map(|r| r.proposal_id)
        .collect()
}

/// `voter`'s objection to the proposal `row` of the self `u`: an
/// `objection:raised:v1` statement (CC 3.1.9.2), its `vote_envelope` members.
fn objection(voter: &CompositeSigningKey, u: &str, row: &RowId, at: u64) -> Vec<u8> {
    let v = iref(voter);
    let payload = map(vec![
        ("asserted_at", Value::Uint(at)),
        ("author", Value::Text(v.clone())),
        ("dimension", Value::Text(sr::DIMENSION_OBJECTION.to_owned())),
        // -1 and 1 at the fixed scale (CC 2.6.1.5).
        ("score", Value::Nint(999_999)),
        ("confidence", Value::Uint(1_000_000)),
        ("cohort", Value::Text("self".to_owned())),
        ("cohort_key_id", Value::Text(u.to_owned())),
        ("objects_to_attestation_id", Value::Text(row.hex())),
        ("grounds", Value::Text(String::new())),
    ]);
    sign_row_statement(
        voter,
        &v,
        u,
        "scores",
        &ciris_verify_core::namespace_match::family_id("objection:{state}"),
        &payload,
        vec![],
    )
    .unwrap()
}

pub(crate) async fn body(d: &dyn FederationDirectory) {
    let (user, d1, d2, d3, d4) = (key(130), key(131), key(132), key(133), key(134));
    for k in [&user, &d1, &d2, &d3, &d4] {
        put(d, &key_record(k, &["user"], 0, None)).await.unwrap();
    }
    let u = iref(&user);
    let t = now_ms() - 3_600_000;
    // One roster key: d1 lands on the user's statement alone.
    let (out, _) = propose(d, &u, &user, &d1, t).await;
    assert!(
        matches!(out, StatementOutcome::Row { .. }),
        "one key: lands"
    );

    // I3045: two keys. The user's statement alone is held.
    let (out, row) = propose(d, &u, &user, &d2, t + 1).await;
    assert!(
        matches!(out, StatementOutcome::Voice { .. }),
        "I3045: at two keys the add is a proposal: {out:?}"
    );
    assert!(
        !active(d, &u, &iref(&d2)).await,
        "I3045: not yet a roster key"
    );
    assert_eq!(
        open(d, &u).await,
        vec![row.hex()],
        "I3045: this node's receipt"
    );
    // d1 signs the same payload as the self: the quorum.
    let out = put(d, &bind(d, &d1, &u, &u, &iref(&d2), t + 1).await)
        .await
        .unwrap();
    assert!(
        matches!(out, StatementOutcome::Row { .. }),
        "I3045: a second roster key's statement lands it: {out:?}"
    );
    assert!(active(d, &u, &iref(&d2)).await, "I3045: d2 is a roster key");
    assert!(
        open(d, &u).await.is_empty(),
        "I3045: the receipt is settled"
    );

    // I3046: three keys; the user's proposal of d3 waits out the window.
    let (out, row3) = propose(d, &u, &user, &d3, t + 2).await;
    assert!(matches!(out, StatementOutcome::Voice { .. }), "I3046: held");
    advance(sr::W_SELF_SECS - 60);
    sr::execute_for(d, &u).await.unwrap();
    assert!(
        !active(d, &u, &iref(&d3)).await,
        "I3046: not a minute early"
    );
    advance(sr::W_SELF_SECS + 1);
    sr::execute_for(d, &u).await.unwrap();
    reset_clock();
    assert!(
        active(d, &u, &iref(&d3)).await,
        "I3046: unanswered, the addition landed by the lone path"
    );
    assert!(
        !open(d, &u).await.contains(&row3.hex()),
        "I3046: the receipt is settled"
    );

    // I3047: four keys; d1 and d2 (two of the three others) object to d4.
    let (out, row4) = propose(d, &u, &user, &d4, t + 3).await;
    assert!(matches!(out, StatementOutcome::Voice { .. }), "I3047: held");
    for voter in [&d1, &d2] {
        put(d, &objection(voter, &u, &row4, now_ms()))
            .await
            .unwrap_or_else(|e| panic!("I3047: an objection is admitted: {e}"));
    }
    advance(10 * sr::W_SELF_SECS);
    sr::execute_for(d, &u).await.unwrap();
    reset_clock();
    assert!(
        !active(d, &u, &iref(&d4)).await,
        "I3047: a majority of the others objecting shuts the lone path"
    );
}

#[cfg(feature = "sqlite")]
#[tokio::test]
async fn i3045_to_i3047_sqlite() {
    use crate::store::Backend as _;
    let b = crate::store::sqlite::SqliteBackend::open_in_memory()
        .await
        .unwrap();
    b.run_migrations().await.unwrap();
    Box::pin(body(&b)).await;
}

#[cfg(feature = "postgres")]
#[tokio::test]
async fn i3045_to_i3047_postgres() {
    use crate::store::Backend as _;
    let Some(dsn) = crate::test_pg::empty_dsn() else {
        return;
    };
    let b = crate::store::postgres::PostgresBackend::connect(&dsn)
        .await
        .unwrap();
    b.run_migrations().await.unwrap();
    Box::pin(body(&b)).await;
}

/// **I3048–I3049** (S1b) on one backend, with E0's seeds and O1's / T2's
/// fixtures:
/// - I3048: an edition-2 eviction (`identity:occurrence_revocation`, the
///   self's voice) of a roster key at two keys is a held proposal, and lands
///   by the lone path after `W_self` (the target silent).
/// - I3049: the proposer's own `withdraws` naming a pending addition's row
///   id closes its receipt; after the window it never lands.
/// - I3049 (b): with two author statements held over one bind, the proposer is
///   the key of the one with the lower statement id.
pub(crate) async fn eviction_body(d: &dyn FederationDirectory) {
    use super::fixture_occurrence::{occurrence_bind_voices, put_bind, BindOptions};
    use super::fixture_switch as e2;
    use super::occurrence::carried_of_bind;
    use crate::federation::types::IdentityOccurrenceRevocation;
    let (u, d1, d2, d3, d4) = ("s1b-u", "s1b-d1", "s1b-d2", "s1b-d3", "s1b-d4");
    for s in [u, d1, d2, d3, d4] {
        e2::put_key(d, s, &["user"]).await;
    }
    let uk = e2::kid(u);
    let opts = BindOptions {
        asserted_at_ms: now_ms() - 3_600_000,
        ..BindOptions::default()
    };
    assert!(matches!(
        put_bind(d, u, u, d1, "laptop", &opts).await,
        Ok(StatementOutcome::Row { .. })
    ));

    // I3048: u proposes d1's eviction at two keys.
    let now = crate::host::clock::now();
    let rev = IdentityOccurrenceRevocation {
        identity_key_id: uk.clone(),
        occurrence_key_id: e2::kid(d1),
        revoked_at: now,
        effective_at: now,
        reason: None,
        witness_set: Vec::new(),
        persist_row_hash: String::new(),
    };
    let voice = revocation_voice(d, u, &rev, now_ms()).await;
    let keys = super::ingest::held_keys_for(d, &voice).await.unwrap();
    let admitted = super::door::admit_row(
        &voice,
        &keys,
        None,
        ciris_verify_core::edition2::family::SelectContext::default(),
    )
    .unwrap();
    d.put_edition2_statement(&admitted).await.unwrap();
    let carried = carried_of_bind(d, &admitted.row_id.hex())
        .await
        .unwrap()
        .expect("I3048: the eviction is a proposal");
    assert!(
        matches!(carried, sr::Carried::Edition2Eviction { .. }),
        "I3048: {carried:?}"
    );
    assert!(
        !sr::gate_edition2(d, carried).await.unwrap(),
        "I3048: one voice of two keys: held"
    );
    assert!(active(d, &uk, &e2::kid(d1)).await, "I3048: not yet evicted");
    advance(sr::W_SELF_SECS + 1);
    sr::execute_for(d, &uk).await.unwrap();
    reset_clock();
    assert!(
        !active(d, &uk, &e2::kid(d1)).await,
        "I3048: the eviction landed by the lone path"
    );

    // I3049: roster {u, d2}; u proposes d3, then withdraws it.
    assert!(matches!(
        put_bind(d, u, u, d2, "laptop", &opts).await,
        Ok(StatementOutcome::Row { .. })
    ));
    let late = BindOptions {
        asserted_at_ms: now_ms() - 1_000,
        head: Some(head(d, &uk).await),
        ..BindOptions::default()
    };
    let voices = occurrence_bind_voices(u, u, d3, "laptop", &late);
    let row3 = RowId::of_statement(&voices[0]).unwrap();
    assert!(matches!(
        put_bind(d, u, u, d3, "laptop", &late).await,
        Ok(StatementOutcome::Voice { .. })
    ));
    assert!(open(d, &uk).await.contains(&row3.hex()), "I3049: held");
    let withdraws = sign_row_statement(
        &e2::signing_key(u),
        &uk,
        &e2::kid(d3),
        "withdraws",
        OCCURRENCE_FAMILY,
        &map(vec![
            ("asserted_at", Value::Uint(now_ms())),
            ("author", Value::Text(uk.clone())),
            (
                "refs",
                map(vec![(
                    "target",
                    ciris_verify_core::edition2::row_ref(&row3.0),
                )]),
            ),
        ]),
        vec![],
    )
    .unwrap();
    assert!(matches!(
        put(d, &withdraws).await,
        Ok(StatementOutcome::Row { .. })
    ));
    assert!(
        !open(d, &uk).await.contains(&row3.hex()),
        "I3049: the proposer's withdraws closes the receipt"
    );
    advance(sr::W_SELF_SECS + 1);
    sr::execute_for(d, &uk).await.unwrap();
    reset_clock();
    assert!(
        !active(d, &uk, &e2::kid(d3)).await,
        "I3049: a withdrawn proposal never lands"
    );

    // I3049 (b): two author statements over d4's bind (u's, and d2's as u).
    // d4's bind stands on the head as it is now (d3's withdrawn proposal
    // landed nothing).
    let late4 = BindOptions {
        head: Some(head(d, &uk).await),
        ..late.clone()
    };
    let v4 = occurrence_bind_voices(u, u, d4, "laptop", &late4);
    let (_, payload) = super::liveness::statement_parts(&v4[1]).unwrap();
    let by_d2 = sign_row_statement(
        &e2::signing_key(d2),
        &uk,
        &e2::kid(d4),
        "scores",
        OCCURRENCE_FAMILY,
        &payload,
        vec![],
    )
    .unwrap();
    let mut ids = Vec::new();
    for st in [&v4[0], &by_d2, &v4[1]] {
        let keys = super::ingest::held_keys_for(d, st).await.unwrap();
        let a = super::door::admit_row(
            st,
            &keys,
            None,
            ciris_verify_core::edition2::family::SelectContext::default(),
        )
        .unwrap();
        d.put_edition2_statement(&a).await.unwrap();
        if a.iss == uk {
            ids.push((
                a.statement_id,
                ciris_verify_core::edition2::identity_ref(&a.kid),
            ));
        }
    }
    let want = ids.iter().min_by_key(|(id, _)| *id).unwrap().1.clone();
    let row4 = RowId::of_statement(&v4[0]).unwrap();
    let carried = carried_of_bind(d, &row4.hex()).await.unwrap().unwrap();
    assert_eq!(
        carried.proposer(),
        want,
        "I3049 (b): the proposer is the lowest statement id's key"
    );
}

#[cfg(feature = "sqlite")]
#[tokio::test]
async fn i3048_i3049_sqlite() {
    use crate::store::Backend as _;
    let b = crate::store::sqlite::SqliteBackend::open_in_memory()
        .await
        .unwrap();
    b.run_migrations().await.unwrap();
    Box::pin(eviction_body(&b)).await;
}

#[cfg(feature = "postgres")]
#[tokio::test]
async fn i3048_i3049_postgres() {
    use crate::store::Backend as _;
    let Some(dsn) = crate::test_pg::empty_dsn() else {
        return;
    };
    let b = crate::store::postgres::PostgresBackend::connect(&dsn)
        .await
        .unwrap();
    b.run_migrations().await.unwrap();
    Box::pin(eviction_body(&b)).await;
}

/// Store `voice` as the door would (admitted, held), then ask the
/// self-roster gate about the proposal its row is.
async fn hold_and_gate(d: &dyn FederationDirectory, voice: &[u8]) -> (RowId, bool) {
    let keys = super::ingest::held_keys_for(d, voice).await.unwrap();
    let a = super::door::admit_row(
        voice,
        &keys,
        None,
        ciris_verify_core::edition2::family::SelectContext::default(),
    )
    .unwrap();
    d.put_edition2_statement(&a).await.unwrap();
    let carried = super::occurrence::carried_of_bind(d, &a.row_id.hex())
        .await
        .unwrap()
        .expect("a held proposal");
    (a.row_id, sr::gate_edition2(d, carried).await.unwrap())
}

/// **I3640–I3641** (wave O1, the second block; CC 3.3.6.4) on one backend:
/// - I3640: `genesis_evicted_at` reads an EDITION-2 eviction of the genesis
///   key: an `identity:occurrence_revocation` of the pair `(f, f)` voiced by
///   two other roster keys of three lands by quorum, and from then the
///   genesis key is evicted (and no longer acts for `f`); before the second
///   voice it is not.
/// - I3641: the genesis key revoking its own pair evicts nothing.
pub(crate) async fn genesis_body(d: &dyn FederationDirectory) {
    use super::fixture_occurrence::{occurrence_bind_voices, put_bind, BindOptions};
    use super::fixture_switch as e2;
    use crate::federation::types::IdentityOccurrenceRevocation;
    let (f, d1, d2, g) = ("ge-f", "ge-d1", "ge-d2", "ge-g");
    for s in [f, d1, d2, g] {
        e2::put_key(d, s, &["user"]).await;
    }
    let fk = e2::kid(f);
    let opts = BindOptions {
        asserted_at_ms: now_ms() - 3_600_000,
        ..BindOptions::default()
    };
    assert!(matches!(
        put_bind(d, f, f, d1, "laptop", &opts).await,
        Ok(StatementOutcome::Row { .. })
    ));
    // d2 at two keys: f's statement, then d1's as f (the quorum).
    let opts2 = BindOptions {
        head: Some(head(d, &fk).await),
        ..opts.clone()
    };
    let v2 = occurrence_bind_voices(f, f, d2, "laptop", &opts2);
    for v in &v2 {
        put(d, v).await.unwrap();
    }
    let (_, payload) = super::liveness::statement_parts(&v2[1]).unwrap();
    let by_d1 = sign_row_statement(
        &e2::signing_key(d1),
        &fk,
        &e2::kid(d2),
        "scores",
        OCCURRENCE_FAMILY,
        &payload,
        vec![],
    )
    .unwrap();
    assert!(matches!(
        put(d, &by_d1).await,
        Ok(StatementOutcome::Row { .. })
    ));
    let roster = sr::roster_now(d, &fk).await.unwrap();
    assert_eq!(roster.len(), 3, "the fixture: f, d1, d2");

    // I3640: d1 and d2 evict f's genesis key.
    let now = crate::host::clock::now();
    let at = now_ms();
    let rev = IdentityOccurrenceRevocation {
        identity_key_id: fk.clone(),
        occurrence_key_id: fk.clone(),
        revoked_at: now,
        effective_at: now,
        reason: None,
        witness_set: Vec::new(),
        persist_row_hash: String::new(),
    };
    let v_d1 = revocation_voice(d, d1, &rev, at).await;
    let v_d2 = revocation_voice(d, d2, &rev, at).await;
    let (row, lands) = hold_and_gate(d, &v_d1).await;
    assert!(!lands, "I3640: one voice of three: held");
    assert!(
        !sr::genesis_evicted_at(d, &fk, crate::host::clock::now())
            .await
            .unwrap(),
        "I3640: not evicted before it lands"
    );
    let (row2, lands) = hold_and_gate(d, &v_d2).await;
    assert_eq!(row, row2, "I3640: one payload, one row");
    assert!(lands, "I3640: two of three: the quorum");
    super::occurrence::land_held_eviction(d, &row)
        .await
        .unwrap();
    assert!(
        sr::genesis_evicted_at(d, &fk, crate::host::clock::now())
            .await
            .unwrap(),
        "I3640: the genesis key is evicted"
    );
    let e = crate::federation::admission::check_signer_acts_for(d, &fk, &fk, "i3640")
        .await
        .unwrap_err();
    assert!(
        matches!(e, Error::SignerDoesNotActFor { .. }),
        "I3640: the evicted genesis key no longer acts for its self: {e:?}"
    );

    // I3641: g's genesis key revoking its own pair evicts nothing.
    let gk = e2::kid(g);
    let own = IdentityOccurrenceRevocation {
        identity_key_id: gk.clone(),
        occurrence_key_id: gk.clone(),
        ..rev.clone()
    };
    let (_, lands) = hold_and_gate(d, &revocation_voice(d, g, &own, at).await).await;
    assert!(lands, "I3641: not a roster change");
    assert!(
        !sr::genesis_evicted_at(d, &gk, crate::host::clock::now())
            .await
            .unwrap(),
        "I3641: the genesis key's own revocation of its pair evicts nothing"
    );
}

#[cfg(feature = "sqlite")]
#[tokio::test]
async fn i3640_i3641_sqlite() {
    use crate::store::Backend as _;
    let b = crate::store::sqlite::SqliteBackend::open_in_memory()
        .await
        .unwrap();
    b.run_migrations().await.unwrap();
    Box::pin(genesis_body(&b)).await;
}

#[cfg(feature = "postgres")]
#[tokio::test]
async fn i3640_i3641_postgres() {
    use crate::store::Backend as _;
    let Some(dsn) = crate::test_pg::empty_dsn() else {
        return;
    };
    let b = crate::store::postgres::PostgresBackend::connect(&dsn)
        .await
        .unwrap();
    b.run_migrations().await.unwrap();
    Box::pin(genesis_body(&b)).await;
}

/// **I3642–I3644** (wave O1, the second block; CC 3.3.6.4, the CC 2.7
/// ruling: a self-roster row counts over the roster AT THE HEAD IT NAMES)
/// on one backend:
/// - I3642: `self_roster::roster_at_head` folds the chain: at the genesis
///   key's own record it is `{f}`; at d1's bind `{f, d1}`; at d2's bind
///   `{f, d1, d2}`.
/// - I3643: the count is over the named head, not the roster now: d2 (on
///   the roster at d2's bind, not at d1's) proposing d3 on d1's bind is
///   refused for good (its proposer is not on the roster it names); on d2's
///   bind the same proposal is held.
/// - I3644: a bind naming a head this node does not hold waits (the
///   retryable unknown signer naming `row:<hex>`), and binds nothing.
pub(crate) async fn head_body(d: &dyn FederationDirectory) {
    let (f, d1, d2, d3) = (key(140), key(141), key(142), key(143));
    for k in [&f, &d1, &d2, &d3] {
        put(d, &key_record(k, &["user"], 0, None)).await.unwrap();
    }
    let fk = iref(&f);
    let t = now_ms() - 3_600_000;
    let g0 = head(d, &fk).await;
    let (out, _) = propose(d, &fk, &f, &d1, t).await;
    assert!(matches!(out, StatementOutcome::Row { .. }), "d1 lands");
    let h1 = head(d, &fk).await;
    assert_ne!(h1, g0, "I3642: d1's bind is the head now");
    let (out, _) = propose(d, &fk, &f, &d2, t + 1).await;
    assert!(matches!(out, StatementOutcome::Voice { .. }), "d2 waits");
    assert!(matches!(
        put(d, &bind_at(&d1, &fk, &fk, &iref(&d2), t + 1, &h1)).await,
        Ok(StatementOutcome::Row { .. })
    ));
    let h2 = head(d, &fk).await;

    // I3642: the fold.
    for (h, want, what) in [
        (g0, vec![fk.clone()], "I3642: at the genesis record"),
        (h1, vec![fk.clone(), iref(&d1)], "I3642: at d1's bind"),
        (
            h2,
            vec![fk.clone(), iref(&d1), iref(&d2)],
            "I3642: at d2's bind",
        ),
    ] {
        let got = sr::roster_at_head(d, &fk, &h).await.unwrap();
        let want: std::collections::BTreeSet<String> = want.into_iter().collect();
        assert_eq!(got, want, "{what}");
    }

    // I3643: d2 proposes d3 on the stale head h1, then on h2.
    let k3 = iref(&d3);
    put(d, &bind_at(&d3, &k3, &fk, &k3, t + 2, &h1))
        .await
        .unwrap();
    let e = put(d, &bind_at(&d2, &fk, &fk, &k3, t + 2, &h1))
        .await
        .unwrap_err();
    assert!(
        matches!(e, Error::SelfRosterNotLanded { .. }),
        "I3643: over h1 the proposer d2 is not on the roster: {e:?}"
    );
    put(d, &bind_at(&d3, &k3, &fk, &k3, t + 3, &h2))
        .await
        .unwrap();
    assert!(
        matches!(
            put(d, &bind_at(&d2, &fk, &fk, &k3, t + 3, &h2)).await,
            Ok(StatementOutcome::Voice { .. })
        ),
        "I3643: over h2 the same proposal is held (one voice of three)"
    );
    assert!(!active(d, &fk, &k3).await, "I3643: d3 not a roster key");

    // I3644: a head this node does not hold.
    let unheld = RowId([0x77; 32]);
    put(d, &bind_at(&d3, &k3, &fk, &k3, t + 4, &unheld))
        .await
        .unwrap();
    let e = put(d, &bind_at(&f, &fk, &fk, &k3, t + 4, &unheld))
        .await
        .unwrap_err();
    assert_eq!(
        e.kind(),
        "federation_attester_key_unknown",
        "I3644: the row waits on its head: {e}"
    );
    assert!(
        e.to_string().contains(&unheld.hex()),
        "I3644: names it: {e}"
    );
    assert!(!active(d, &fk, &k3).await, "I3644: nothing bound");
}

#[cfg(feature = "sqlite")]
#[tokio::test]
async fn i3642_to_i3644_sqlite() {
    use crate::store::Backend as _;
    let b = crate::store::sqlite::SqliteBackend::open_in_memory()
        .await
        .unwrap();
    b.run_migrations().await.unwrap();
    Box::pin(head_body(&b)).await;
}

#[cfg(feature = "postgres")]
#[tokio::test]
async fn i3642_to_i3644_postgres() {
    use crate::store::Backend as _;
    let Some(dsn) = crate::test_pg::empty_dsn() else {
        return;
    };
    let b = crate::store::postgres::PostgresBackend::connect(&dsn)
        .await
        .unwrap();
    b.run_migrations().await.unwrap();
    Box::pin(head_body(&b)).await;
}
