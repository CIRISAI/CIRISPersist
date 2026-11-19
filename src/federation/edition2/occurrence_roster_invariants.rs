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
/// 3.3.6.4), the self's (`iss` = the identity; COUNTED, so no `author`), signed by the
/// E0 seed `seed`, on the identity's current roster head.
async fn revocation_voice(
    d: &dyn FederationDirectory,
    seed: &str,
    rev: &crate::federation::types::IdentityOccurrenceRevocation,
    asserted_at: u64,
) -> Vec<u8> {
    let ms = |t: chrono::DateTime<chrono::Utc>| u64::try_from(t.timestamp_millis()).unwrap();
    let h = head(d, &rev.identity_key_id).await;
    let cites = eviction_cites_at(d, &rev.identity_key_id, &h).await;
    let payload = map(vec![
        ("asserted_at", Value::Uint(asserted_at)),
        ("identity_key_id", Value::Text(rev.identity_key_id.clone())),
        (
            "occurrence_key_id",
            Value::Text(rev.occurrence_key_id.clone()),
        ),
        ("revoked_at", Value::Uint(ms(rev.revoked_at))),
        ("effective_at", Value::Uint(ms(rev.effective_at))),
        ("refs", revocation_refs(&h, &cites)),
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

/// rc21 7f94be1 (T2-fix4) — what an eviction cites (`refs.also.cites`): the
/// latest `key:record` of every key on the roster at `head`, and each
/// non-genesis key's binding under the identity (`typed::eviction_cites`).
/// Every roster key may voice it, so every voice states the same payload.
async fn eviction_cites_at(
    d: &dyn FederationDirectory,
    identity: &str,
    head: &RowId,
) -> Vec<RowId> {
    let keys: Vec<String> = sr::roster_at_head(d, identity, head)
        .await
        .unwrap()
        .into_iter()
        .collect();
    super::typed::eviction_cites(d, identity, &keys)
        .await
        .unwrap()
}

/// An eviction's `refs`: `head`, and `also.cites` as a set.
fn revocation_refs(head: &RowId, cites: &[RowId]) -> Value {
    let mut set: Vec<Value> = cites
        .iter()
        .map(|r| ciris_verify_core::edition2::row_ref(&r.0))
        .collect();
    set.sort_by_key(ciris_verify_core::cde::encode);
    set.dedup();
    map(vec![
        ("head", ciris_verify_core::edition2::row_ref(&head.0)),
        ("also", map(vec![("cites", Value::Array(set))])),
    ])
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
        matches!(out, StatementOutcome::Pending { .. }),
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
    assert!(
        matches!(out, StatementOutcome::Pending { .. }),
        "I3046: held"
    );
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
    assert!(
        matches!(out, StatementOutcome::Pending { .. }),
        "I3047: held"
    );
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
        super::typed::family_context(d, &voice).await.unwrap(),
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
        Ok(StatementOutcome::Pending { .. })
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
            super::typed::family_context(d, st).await.unwrap(),
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
        super::typed::family_context(d, voice).await.unwrap(),
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
/// - I3643 (CC 2.7.8): d2 proposing d3 on d1's bind, whose successor (d2's
///   bind) this node acknowledged, is a VOID sibling: `Pending`, kept,
///   settled `void_superseded`, never refused; on d2's bind the same
///   proposal is held short of its count.
/// - I3644: a bind naming a head this node does not hold yet WAITS
///   (`Pending`, its receipt open), never refused; once the head is
///   delivered and lands, the bind lands with no manual step.
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
    assert!(matches!(out, StatementOutcome::Pending { .. }), "d2 waits");
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
    // CC 2.7.8: h1's successor h2 is acknowledged here, so a row on h1 is a
    // VOID sibling for this reader: held (kept), concluding nothing, never
    // refused.
    let stale = bind_at(&d2, &fk, &fk, &k3, t + 2, &h1);
    let stale_row = RowId::of_statement(&stale).unwrap();
    let out = put(d, &stale).await;
    assert!(
        matches!(out, Ok(StatementOutcome::Pending { .. })),
        "I3643: a row on the superseded head h1 is held, not refused: {out:?}"
    );
    assert_eq!(
        d.edition2_roster_proposal(&stale_row.hex())
            .await
            .unwrap()
            .and_then(|r| r.outcome)
            .as_deref(),
        Some(sr::VOID_OUTCOME),
        "I3643: void for this reader"
    );
    assert!(
        !d.edition2_voices(&stale_row).await.unwrap().is_empty(),
        "I3643: its statements are kept"
    );
    put(d, &bind_at(&d3, &k3, &fk, &k3, t + 3, &h2))
        .await
        .unwrap();
    assert!(
        matches!(
            put(d, &bind_at(&d2, &fk, &fk, &k3, t + 3, &h2)).await,
            Ok(StatementOutcome::Pending { .. })
        ),
        "I3643: over h2 the same proposal is held (one voice of three)"
    );
    assert!(!active(d, &fk, &k3).await, "I3643: d3 not a roster key");

    // I3644: a head this node does not hold yet: the row WAITS (CC 2.7.3),
    // held and concluding nothing, never refused; when the head is
    // delivered, the row lands with no manual step (G0's re-fold re-runs
    // its door: the gate declared `row:<head>`).
    let (k5, k6) = (key(144), key(145));
    for k in [&k5, &k6] {
        put(d, &key_record(k, &["primitive"], 0, None))
            .await
            .unwrap();
    }
    let (r5, r6) = (iref(&k5), iref(&k6));
    // X: k5's bind on h2 (not a roster change), NOT delivered yet.
    let x = [
        bind_at(&k5, &r5, &fk, &r5, t + 4, &h2),
        bind_at(&f, &fk, &fk, &r5, t + 4, &h2),
    ];
    let hx = RowId::of_statement(&x[0]).unwrap();
    // W: k6's bind on X.
    put(d, &bind_at(&k6, &r6, &fk, &r6, t + 5, &hx))
        .await
        .unwrap();
    let w = bind_at(&f, &fk, &fk, &r6, t + 5, &hx);
    let out = put(d, &w).await;
    assert!(
        matches!(out, Ok(StatementOutcome::Pending { .. })),
        "I3644: the row waits on its head: {out:?}"
    );
    assert!(
        open(d, &fk)
            .await
            .contains(&RowId::of_statement(&w).unwrap().hex()),
        "I3644: its receipt is open"
    );
    assert!(!active(d, &fk, &r6).await, "I3644: nothing bound yet");
    // Deliver X: it lands, and W lands with it, unprompted.
    for v in &x {
        put(d, v).await.unwrap();
    }
    assert!(active(d, &fk, &r5).await, "I3644: the head X landed");
    assert!(
        active(d, &fk, &r6).await,
        "I3644: the waiting row landed once its head arrived, no execute_for"
    );
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

/// Bind `occurrence` under `identity` (E0 seeds) on exactly `heads`
/// (`refs.head`, then `refs.further_heads`): the occurrence key's own
/// voice and the identity's author voice, NOT put.
fn bind_on(
    identity: &str,
    occurrence: &str,
    class: &str,
    heads: &[RowId],
    at: u64,
) -> Vec<Vec<u8>> {
    use super::fixture_occurrence::{occurrence_bind_voices, BindOptions};
    let opts = BindOptions {
        asserted_at_ms: at,
        head: heads.first().copied(),
        further_heads: heads.iter().skip(1).copied().collect(),
        ..BindOptions::default()
    };
    occurrence_bind_voices(identity, identity, occurrence, class, &opts)
}

/// `signer`'s author voice as `identity` (E0 seeds) over the payload of
/// the held author statement `author_st`: a further roster key's assent.
fn as_identity(signer: &str, identity: &str, author_st: &[u8]) -> Vec<u8> {
    use super::fixture_switch as e2;
    let (_, payload) = super::liveness::statement_parts(author_st).unwrap();
    let sub = payload
        .get_text("occurrence_key_id")
        .and_then(Value::as_text)
        .unwrap()
        .to_owned();
    sign_row_statement(
        &e2::signing_key(signer),
        &e2::kid(identity),
        &sub,
        "scores",
        OCCURRENCE_FAMILY,
        &payload,
        vec![],
    )
    .unwrap()
}

/// **I3645–I3648** (wave O1, the second block; CC 3.3.6.4, the CC 2.7
/// ruling, CC 2.7.8, CC rc21's `refs.further_heads`) on one backend, E0
/// seeds:
/// - I3645: a proposal waiting on a head it names lands, WITHOUT any
///   `execute_for`, once that head lands (the fold re-plans it: the gate
///   declared `row:<head>`).
/// - I3646: a sibling (A) of a head whose successor (B) this node
///   acknowledged is VOID here: kept, settled `void_superseded`, and B is
///   the one tip; a merge naming B and A lands and is the one tip after.
/// - I3647: merging never revives: A evicts e2, B (on the head before)
///   still holds e2; the roster at B holds e2, at {B, A} and at the merge
///   row it does not (e1 stays).
/// - I3648: a genesis thief's sibling naming the genesis record, after this
///   node acknowledged the honest successor, is VOID, and binds nothing.
pub(crate) async fn fork_body(d: &dyn FederationDirectory) {
    use super::fixture_occurrence::{put_bind, BindOptions};
    use super::fixture_switch as e2;
    use super::occurrence::current_roster_heads;
    let seeds = [
        "fk-h", "fk-x1", "fk-x2", "fk-t", "fk-g", "fk-e1", "fk-e2", "fk-p1", "fk-p2", "fk-q",
    ];
    for s in seeds {
        let types: &[&str] = if s.contains("-p") || s.contains("-q") {
            &["primitive"]
        } else {
            &["user"]
        };
        e2::put_key(d, s, types).await;
    }
    let at = now_ms() - 3_600_000;
    let opts = BindOptions {
        asserted_at_ms: at,
        ..BindOptions::default()
    };

    // I3645: h's roster {h, x1}; a proposal of x2 names X (q's bind), which
    // is not held yet.
    let hk = e2::kid("fk-h");
    let g0 = head(d, &hk).await;
    assert!(matches!(
        put_bind(d, "fk-h", "fk-h", "fk-x1", "laptop", &opts).await,
        Ok(StatementOutcome::Row { .. })
    ));
    let h1 = head(d, &hk).await;
    let x = bind_on("fk-h", "fk-q", "service", &[h1], at + 1);
    let rx = RowId::of_statement(&x[0]).unwrap();
    let p = bind_on("fk-h", "fk-x2", "laptop", &[rx], at + 2);
    assert!(matches!(
        put(d, &p[0]).await,
        Ok(StatementOutcome::Voice { .. })
    ));
    for v in [p[1].clone(), as_identity("fk-x1", "fk-h", &p[1])] {
        assert!(
            matches!(put(d, &v).await, Ok(StatementOutcome::Pending { .. })),
            "I3645: waits on X"
        );
    }
    assert!(!active(d, &hk, &e2::kid("fk-x2")).await, "I3645: not yet");
    for v in &x {
        put(d, v).await.unwrap();
    }
    assert!(
        active(d, &hk, &e2::kid("fk-x2")).await,
        "I3645: X landed, and the waiting proposal landed on the fold's re-plan (h and x1 \
         are 2 of 2 over X)"
    );

    // I3646 / I3647: g's roster {g, e1, e2} at H2.
    let gk = e2::kid("fk-g");
    assert!(matches!(
        put_bind(d, "fk-g", "fk-g", "fk-e1", "laptop", &opts).await,
        Ok(StatementOutcome::Row { .. })
    ));
    let g1 = head(d, &gk).await;
    let b2 = bind_on("fk-g", "fk-e2", "laptop", &[g1], at + 3);
    put(d, &b2[0]).await.unwrap();
    put(d, &b2[1]).await.unwrap();
    assert!(matches!(
        put(d, &as_identity("fk-e1", "fk-g", &b2[1])).await,
        Ok(StatementOutcome::Row { .. })
    ));
    let g2 = head(d, &gk).await;
    // Branch B: p1's bind on H2 (not a roster change: lands at once; this
    // node acknowledges it).
    let bb = bind_on("fk-g", "fk-p1", "service", &[g2], at + 4);
    for v in &bb {
        put(d, v).await.unwrap();
    }
    let rb = RowId::of_statement(&bb[0]).unwrap();
    // Branch A: e2's eviction on H2, by g and e1 (2 of 3), arriving after B:
    // a sibling of the acknowledged B, so VOID here (CC 2.7.8), kept.
    let now = crate::host::clock::now();
    let rev = crate::federation::types::IdentityOccurrenceRevocation {
        identity_key_id: gk.clone(),
        occurrence_key_id: e2::kid("fk-e2"),
        revoked_at: now,
        effective_at: now,
        reason: None,
        witness_set: Vec::new(),
        persist_row_hash: String::new(),
    };
    let cites_a = eviction_cites_at(d, &gk, &g2).await;
    let ev = |seed: &str| {
        let ms = |t: chrono::DateTime<chrono::Utc>| u64::try_from(t.timestamp_millis()).unwrap();
        sign_row_statement(
            &e2::signing_key(seed),
            &gk,
            &rev.occurrence_key_id,
            "scores",
            super::occurrence::OCCURRENCE_REVOCATION_FAMILY,
            &map(vec![
                ("asserted_at", Value::Uint(at + 5)),
                ("identity_key_id", Value::Text(gk.clone())),
                (
                    "occurrence_key_id",
                    Value::Text(rev.occurrence_key_id.clone()),
                ),
                ("revoked_at", Value::Uint(ms(rev.revoked_at))),
                ("effective_at", Value::Uint(ms(rev.effective_at))),
                ("refs", revocation_refs(&g2, &cites_a)),
            ]),
            vec![],
        )
        .unwrap()
    };
    let (ra, lands) = hold_and_gate(d, &ev("fk-g")).await;
    assert!(!lands, "I3646: A is void here");
    let (_, lands) = hold_and_gate(d, &ev("fk-e1")).await;
    assert!(!lands, "I3646: A stays void at two of three");
    let outcome = |r: RowId| async move {
        d.edition2_roster_proposal(&r.hex())
            .await
            .unwrap()
            .and_then(|r| r.outcome)
    };
    assert_eq!(
        outcome(ra).await.as_deref(),
        Some(sr::VOID_OUTCOME),
        "I3646: A settled void for this reader"
    );
    assert_eq!(
        current_roster_heads(d, &gk).await.unwrap(),
        Some((rb, Vec::new())),
        "I3646: one acknowledged tip, B"
    );

    // I3647: at B the roster still holds e2 (A never landed here); a merge
    // naming B and A counts without e2 (an eviction on any merged branch
    // stands, the void sibling's included), and e1 stays.
    let e2k = e2::kid("fk-e2");
    let r = sr::roster_at_head(d, &gk, &rb).await.unwrap();
    assert!(r.contains(&e2k), "I3647: at B, e2 is a member: {r:?}");
    let r = sr::roster_at_heads(d, &gk, &[rb, ra]).await.unwrap();
    assert!(!r.contains(&e2k), "I3647: at {{B, A}}: {r:?}");
    assert!(r.contains(&e2::kid("fk-e1")), "I3647: e1 stays");

    // I3646: the merge row (p2's bind naming B and A) lands and is the one tip.
    let m = bind_on("fk-g", "fk-p2", "service", &[rb, ra], at + 6);
    for v in &m {
        put(d, v).await.unwrap();
    }
    let rm = RowId::of_statement(&m[0]).unwrap();
    assert_eq!(
        current_roster_heads(d, &gk).await.unwrap(),
        Some((rm, Vec::new())),
        "I3646: the merge is the one tip"
    );
    let r = sr::roster_at_head(d, &gk, &rm).await.unwrap();
    assert!(!r.contains(&e2k), "I3647: at the merge: {r:?}");

    // I3648 (CC 2.7.8): a genesis thief's sibling. h's genesis key binds t on
    // the genesis record g0, whose successor (x1's bind) this node
    // acknowledged: VOID here, though over g0 alone ({h}) it would land.
    let t = bind_on("fk-h", "fk-t", "laptop", &[g0], at + 8);
    put(d, &t[0]).await.unwrap();
    let out = put(d, &t[1]).await;
    assert!(
        matches!(out, Ok(StatementOutcome::Pending { .. })),
        "I3648: held, not landed: {out:?}"
    );
    assert_eq!(
        outcome(RowId::of_statement(&t[0]).unwrap())
            .await
            .as_deref(),
        Some(sr::VOID_OUTCOME),
        "I3648: void for this reader"
    );
    assert!(
        !active(d, &hk, &e2::kid("fk-t")).await,
        "I3648: t not bound"
    );
}

#[cfg(feature = "sqlite")]
#[tokio::test]
async fn i3645_to_i3648_sqlite() {
    use crate::store::Backend as _;
    let b = crate::store::sqlite::SqliteBackend::open_in_memory()
        .await
        .unwrap();
    b.run_migrations().await.unwrap();
    Box::pin(fork_body(&b)).await;
}

#[cfg(feature = "postgres")]
#[tokio::test]
async fn i3645_to_i3648_postgres() {
    use crate::store::Backend as _;
    let Some(dsn) = crate::test_pg::empty_dsn() else {
        return;
    };
    let b = crate::store::postgres::PostgresBackend::connect(&dsn)
        .await
        .unwrap();
    b.run_migrations().await.unwrap();
    Box::pin(fork_body(&b)).await;
}

/// **I3649** (wave O1, the second block; CC 3.3.6.4, ENACT = more than 1/2
/// of the live roster at the named head, the proposer counted) on one
/// backend, E0 seeds. At a two-key roster `{a, b}`:
/// - b's lone statement as `a` adding c is ONE of TWO: held (`Pending`),
///   c is not bound, the receipt stays open;
/// - c's own statement is never a roster vote (it is the occurrence key's
///   voice, not the self's): still held;
/// - a's statement over the same payload is TWO of TWO: it lands (`Row`),
///   c is bound.
pub(crate) async fn majority_body(d: &dyn FederationDirectory) {
    use super::fixture_occurrence::{put_bind, BindOptions};
    use super::fixture_switch as e2;
    for s in ["mj-a", "mj-b", "mj-c"] {
        e2::put_key(d, s, &["user"]).await;
    }
    let ak = e2::kid("mj-a");
    let at = now_ms() - 3_600_000;
    let opts = BindOptions {
        asserted_at_ms: at,
        ..BindOptions::default()
    };
    assert!(matches!(
        put_bind(d, "mj-a", "mj-a", "mj-b", "laptop", &opts).await,
        Ok(StatementOutcome::Row { .. })
    ));
    let h = head(d, &ak).await;
    let c = bind_on("mj-a", "mj-c", "laptop", &[h], at + 1);
    let row = RowId::of_statement(&c[0]).unwrap();
    assert!(matches!(
        put(d, &c[0]).await,
        Ok(StatementOutcome::Voice { .. })
    ));
    let one = put(d, &as_identity("mj-b", "mj-a", &c[1])).await;
    assert!(
        matches!(one, Ok(StatementOutcome::Pending { .. })),
        "I3649: one of two is no strict majority: {one:?}"
    );
    assert!(
        !active(d, &ak, &e2::kid("mj-c")).await,
        "I3649: c is not bound on one of two"
    );
    assert!(
        open(d, &ak).await.contains(&row.hex()),
        "I3649: the receipt stays open"
    );
    // c's own statement offered again: not a vote.
    let _ = put(d, &c[0]).await;
    assert!(
        !active(d, &ak, &e2::kid("mj-c")).await,
        "I3649: the candidate's own voice is not counted"
    );
    let two = put(d, &c[1]).await;
    assert!(
        matches!(two, Ok(StatementOutcome::Row { .. })),
        "I3649: two of two lands: {two:?}"
    );
    assert!(active(d, &ak, &e2::kid("mj-c")).await, "I3649: c is bound");
}

#[cfg(feature = "sqlite")]
#[tokio::test]
async fn i3649_strict_majority_sqlite() {
    use crate::store::Backend as _;
    let b = crate::store::sqlite::SqliteBackend::open_in_memory()
        .await
        .unwrap();
    b.run_migrations().await.unwrap();
    Box::pin(majority_body(&b)).await;
}

#[cfg(feature = "postgres")]
#[tokio::test]
async fn i3649_strict_majority_postgres() {
    use crate::store::Backend as _;
    let Some(dsn) = crate::test_pg::empty_dsn() else {
        return;
    };
    let b = crate::store::postgres::PostgresBackend::connect(&dsn)
        .await
        .unwrap();
    b.run_migrations().await.unwrap();
    Box::pin(majority_body(&b)).await;
}

/// Put `voices` in order; every one is admitted (a voice or a landing).
async fn put_all(d: &dyn FederationDirectory, voices: &[Vec<u8>]) {
    for v in voices {
        put(d, v).await.expect("a tied bind is admitted");
    }
}

/// The `edition2_row_id` of the bind `identity`'s pair with `occurrence`
/// holds (the signed listing's envelope).
async fn holding_row(d: &dyn FederationDirectory, identity: &str, occurrence: &str) -> String {
    d.list_signed_identity_occurrences_for(identity)
        .await
        .unwrap()
        .into_iter()
        .find(|s| s.identity_occurrence.occurrence_key_id == occurrence)
        .and_then(|s| {
            s.signed_envelope
                .get("edition2_row_id")
                .and_then(serde_json::Value::as_str)
                .map(str::to_owned)
        })
        .expect("the pair is held with its row id")
}

/// **I3650** (wave O1, the second block; CC 3.5.1, CC 2.7.2; E8's I3330) on
/// one backend, two fresh directories `d1`, `d2`: two binds of ONE pair at
/// the SAME signed instant (a node self-pair, `server` vs `embedded`) are
/// delivered in OPPOSITE orders. Both directories hold the bind with the
/// LOWER row id: a same-instant tie is broken by the row id, never by
/// arrival.
pub(crate) async fn tie_body(d1: &dyn FederationDirectory, d2: &dyn FederationDirectory) {
    use super::fixture_occurrence::{occurrence_bind_voices, BindOptions};
    use super::fixture_switch as e2;
    let seed = "tie-node";
    for d in [d1, d2] {
        e2::put_key(d, seed, &["node"]).await;
    }
    let nk = e2::kid(seed);
    let h = head(d1, &nk).await;
    assert_eq!(h, head(d2, &nk).await, "I3650: one genesis record row");
    let at = now_ms() - 60_000;
    let opts = BindOptions {
        asserted_at_ms: at,
        head: Some(h),
        ..BindOptions::default()
    };
    let x = occurrence_bind_voices(seed, seed, seed, "server", &opts);
    let y = occurrence_bind_voices(seed, seed, seed, "embedded", &opts);
    let (rx, ry) = (
        RowId::of_statement(&x[0]).unwrap(),
        RowId::of_statement(&y[0]).unwrap(),
    );
    assert_ne!(rx, ry, "I3650: two rows of one pair");
    let lower = std::cmp::min(rx, ry).hex();
    put_all(d1, &x).await;
    put_all(d1, &y).await;
    put_all(d2, &y).await;
    put_all(d2, &x).await;
    assert_eq!(
        holding_row(d1, &nk, &nk).await,
        lower,
        "I3650: in order x, y the lower row id holds"
    );
    assert_eq!(
        holding_row(d2, &nk, &nk).await,
        lower,
        "I3650: in order y, x the lower row id holds"
    );
}

#[cfg(feature = "sqlite")]
#[tokio::test]
async fn i3650_same_instant_tie_sqlite() {
    use crate::store::Backend as _;
    let a = crate::store::sqlite::SqliteBackend::open_in_memory()
        .await
        .unwrap();
    a.run_migrations().await.unwrap();
    let b = crate::store::sqlite::SqliteBackend::open_in_memory()
        .await
        .unwrap();
    b.run_migrations().await.unwrap();
    Box::pin(tie_body(&a, &b)).await;
}

#[cfg(feature = "postgres")]
#[tokio::test]
async fn i3650_same_instant_tie_postgres() {
    use crate::store::Backend as _;
    let (Some(da), Some(db)) = (crate::test_pg::empty_dsn(), crate::test_pg::empty_dsn()) else {
        return;
    };
    let a = crate::store::postgres::PostgresBackend::connect(&da)
        .await
        .unwrap();
    a.run_migrations().await.unwrap();
    let b = crate::store::postgres::PostgresBackend::connect(&db)
        .await
        .unwrap();
    b.run_migrations().await.unwrap();
    Box::pin(tie_body(&a, &b)).await;
}
