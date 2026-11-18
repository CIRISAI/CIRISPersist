//! **I1905**: key liveness comes only from an edition-2 `key:record`, and
//! only the three revokers end a key (CC 2.4.1.1, CC 2.6.1.7).
//!
//! - With no record held, a statement waits (retryable). A record makes the
//!   key live over `[asserted_at, valid_until]`. Before `asserted_at` and
//!   after `valid_until` the statement is retryable, not final. A renewal
//!   extends the key to the greatest end, and a renewal signed after the end
//!   revives it.
//! - The end rule at the door:
//!   - a `node` or `agent` record without `valid_until`, or with one more
//!     than 31,536,000 s after `asserted_at`, is `key_record_out_of_window`;
//!   - a `user` or `accord_holder` record with `valid_until` is
//!     `key_record_out_of_window`;
//!   - a person-and-machine set is the typed
//!     `IdentitySetMixesPersonAndMachine`;
//!   - an unsorted `identity_type` array is `edition2_statement_invalid`;
//!   - a record that breaks the rule gives no liveness.
//! - Revocation:
//!   - the key's own revocation ends it from `revoked_after`, so statements
//!     before the bound stand; with no bound it revokes all;
//!   - a revocation by a stranger revokes nothing;
//!   - the owner / roster answer ([`RevokerStanding`]) admits a named
//!     revoker;
//!   - a revoked key is final (Invalid), never retryable.
//! - An earlier-form record is never read: a JSON key record offered to the
//!   directory files nothing, and its key stays not held.

use std::sync::Arc;

use ciris_verify_core::edition2::family::SelectContext;
use ciris_verify_core::edition2::KeyDirectory;

use super::door::admit_row;
use super::door_invariants::fixture::*;
use super::liveness::{HeldKeys, Liveness, RevokerStanding};
use crate::federation::{malformed_row, Error};

const YEAR_MS: u64 = 31_536_000 * 1000;

fn statement_at(k: &ciris_crypto::composite::CompositeSigningKey, at: u64) -> Vec<u8> {
    row_with_refs(k, at, map(vec![("target", ref2(&[0xaa; 32]))]))
}

fn verdict(held: &HeldKeys, st: &[u8]) -> &'static str {
    match admit_row(st, held, None, SelectContext::default()) {
        Ok(_) => "valid",
        Err(Error::AttesterKeyUnknown { .. }) => "waiting",
        Err(Error::MalformedRow { reason, .. })
            if reason == malformed_row::EDITION2_STATEMENT_INVALID =>
        {
            "invalid"
        }
        Err(e) => panic!("{e:?}"),
    }
}

#[test]
fn i1905_only_an_edition2_record_makes_a_key_live() {
    let k = key(20);
    let mut held = HeldKeys::new();
    assert_eq!(
        verdict(&held, &statement_at(&k, 5_000)),
        "waiting",
        "I1905 no record"
    );
    // An earlier-form (JSON) key record files nothing.
    assert!(held
        .insert_record(br#"{"key_id":"k","identity_type":"node"}"#.to_vec())
        .is_none());
    assert_eq!(
        verdict(&held, &statement_at(&k, 5_000)),
        "waiting",
        "I1905 json"
    );
    held.insert_record(key_record(&k, &["node"], 1_000, Some(10_000)))
        .unwrap();
    assert_eq!(
        verdict(&held, &statement_at(&k, 5_000)),
        "valid",
        "I1905 covered"
    );
    assert_eq!(
        verdict(&held, &statement_at(&k, 1_000)),
        "valid",
        "I1905 at start"
    );
    assert_eq!(
        verdict(&held, &statement_at(&k, 10_000)),
        "valid",
        "I1905 at end"
    );
    assert_eq!(
        verdict(&held, &statement_at(&k, 999)),
        "waiting",
        "I1905 before"
    );
    assert_eq!(
        verdict(&held, &statement_at(&k, 10_001)),
        "waiting",
        "I1905 after"
    );
    // A renewal signed after the end revives it, to the greatest end.
    held.insert_record(key_record(&k, &["node"], 20_000, Some(40_000)))
        .unwrap();
    assert_eq!(
        verdict(&held, &statement_at(&k, 30_000)),
        "valid",
        "I1905 renewed"
    );
    assert_eq!(
        verdict(&held, &statement_at(&k, 15_000)),
        "waiting",
        "I1905 gap"
    );
    assert!(matches!(
        held.liveness(&kid(&k), 39_999),
        Liveness::Live(r) if r.valid_until == Some(40_000)
    ));
}

/// **I2106** (v62.0.0, JSON-cut slice A; CC 2.4.1.1): the identity-set
/// exclusion at the edition-2 key door, as the earlier doors keep it.
/// `node` with `agent` (which Verify's end rule admits) is
/// `federation_node_identity_not_exclusive`, and such a record makes no key
/// live; `accord_holder` with `agent` is the typed person-with-machine
/// refusal; other co-locations stand.
#[test]
fn i2106_node_never_cohabits_with_agent() {
    let k = key(23);
    let held = holding(&[&k]);
    let kind = |st: Vec<u8>| match admit_row(&st, &held, None, SelectContext::default()) {
        Ok(_) => "ok".to_owned(),
        Err(e) => e.kind().to_owned(),
    };
    assert_eq!(
        kind(key_record(&k, &["agent", "node"], 0, Some(YEAR_MS))),
        "federation_node_identity_not_exclusive",
        "I2106 node + agent"
    );
    assert_eq!(
        kind(key_record(&k, &["accord_holder", "agent"], 0, None)),
        "federation_identity_set_mixes_person_and_machine",
        "I2106 holder + agent"
    );
    assert_eq!(
        kind(key_record(&k, &["canonical", "node"], 0, Some(YEAR_MS))),
        "ok",
        "I2106 other co-locations stand"
    );
    let j = key(24);
    let mut h = HeldKeys::new();
    h.insert_record(key_record(&j, &["agent", "node"], 0, Some(YEAR_MS)))
        .unwrap();
    assert!(
        !matches!(h.liveness(&kid(&j), 10), Liveness::Live(_)),
        "I2106 no liveness"
    );
}

#[test]
fn i1905_the_end_rule_at_the_door() {
    let k = key(21);
    let held = holding(&[&k]);
    let refusal = |st: Vec<u8>| match admit_row(&st, &held, None, SelectContext::default()) {
        Ok(_) => "ok".to_owned(),
        Err(Error::MalformedRow { reason, .. }) => reason.to_owned(),
        Err(Error::IdentitySetMixesPersonAndMachine { .. }) => "mixed".to_owned(),
        Err(e) => e.kind().to_owned(),
    };
    assert_eq!(
        refusal(key_record(&k, &["node"], 0, Some(YEAR_MS))),
        "ok",
        "I1905 bound"
    );
    assert_eq!(
        refusal(key_record(&k, &["node"], 0, None)),
        malformed_row::KEY_RECORD_OUT_OF_WINDOW,
        "I1905 node without end"
    );
    assert_eq!(
        refusal(key_record(&k, &["agent"], 0, Some(YEAR_MS + 1))),
        malformed_row::KEY_RECORD_OUT_OF_WINDOW,
        "I1905 agent over the bound"
    );
    assert_eq!(
        refusal(key_record(&k, &["user"], 0, Some(1))),
        malformed_row::KEY_RECORD_OUT_OF_WINDOW,
        "I1905 user with end"
    );
    assert_eq!(
        refusal(key_record(&k, &["accord_holder"], 0, Some(1))),
        malformed_row::KEY_RECORD_OUT_OF_WINDOW,
        "I1905 accord_holder with end"
    );
    assert_eq!(
        refusal(key_record(&k, &["accord_holder"], 0, None)),
        "ok",
        "I1905 holder"
    );
    // v62.0.0 (slice A, I2106): the earlier doors' token for `node` with
    // `user` (CC 2.4.1.1), before Verify's mixed-roles reading.
    assert_eq!(
        refusal(key_record(&k, &["node", "user"], 0, Some(1))),
        "federation_node_identity_not_exclusive",
        "I1905 mixed"
    );
    assert_eq!(
        refusal(key_record(&k, &["agent", "user"], 0, None)),
        "mixed",
        "I1905 person with machine"
    );
    // A record that breaks the rule gives no liveness.
    let j = key(22);
    let mut h = HeldKeys::new();
    h.insert_record(key_record(&j, &["node"], 0, None)).unwrap();
    assert!(
        matches!(h.liveness(&kid(&j), 10), Liveness::Invalid),
        "I1905"
    );
}

#[test]
fn i1905_an_unsorted_identity_set_is_refused() {
    use ciris_verify_core::cde::Value;
    use ciris_verify_core::edition2::{cose_key, sign_row_statement};
    let k = key(23);
    let unsorted = Value::Array(vec![
        Value::Text("steward".into()),
        Value::Text("node".into()),
    ]);
    let payload = map(vec![
        ("key", cose_key(k.public_key())),
        ("identity_type", unsorted),
        ("asserted_at", Value::Uint(0)),
        ("valid_until", Value::Uint(5)),
        ("author", Value::Text(iref(&k))),
    ]);
    let st = sign_row_statement(
        &k,
        &iref(&k),
        &iref(&k),
        "scores",
        "key:record",
        &payload,
        vec![],
    )
    .unwrap();
    let e = admit_row(&st, &holding(&[&k]), None, SelectContext::default()).unwrap_err();
    assert!(
        matches!(&e, Error::MalformedRow { reason, message, .. }
            if *reason == malformed_row::EDITION2_STATEMENT_INVALID && message.contains("BadIdentityType")),
        "I1905: {e:?}"
    );
}

struct Owner(String);
impl RevokerStanding for Owner {
    fn may_revoke(&self, revoker: &str, _subject: &str) -> bool {
        revoker == self.0
    }
}

#[test]
fn i1905_only_the_three_revokers_end_a_key() {
    let k = key(24);
    let stranger = key(25);
    let owner = key(26);
    let base = || {
        let mut h = HeldKeys::new();
        h.insert_record(key_record(&k, &["user"], 0, None)).unwrap();
        h.insert_record(key_record(&stranger, &["user"], 0, None))
            .unwrap();
        h.insert_record(key_record(&owner, &["user"], 0, None))
            .unwrap();
        h
    };
    // A stranger revokes nothing.
    let mut h = base();
    h.insert_revocation(revocation(&stranger, &k, 100, None));
    assert_eq!(
        verdict(&h, &statement_at(&k, 500)),
        "valid",
        "I1905 stranger"
    );
    // The key itself, with a bound: before stands, after is final.
    let mut h = base();
    h.insert_revocation(revocation(&k, &k, 100, Some(400)));
    assert_eq!(
        verdict(&h, &statement_at(&k, 399)),
        "valid",
        "I1905 before bound"
    );
    assert_eq!(
        verdict(&h, &statement_at(&k, 400)),
        "invalid",
        "I1905 at bound"
    );
    assert!(matches!(h.liveness(&kid(&k), 900), Liveness::Revoked));
    // No bound: revoke-all.
    let mut h = base();
    h.insert_revocation(revocation(&k, &k, 100, None));
    assert_eq!(
        verdict(&h, &statement_at(&k, 1)),
        "invalid",
        "I1905 revoke-all"
    );
    // The owner, through the standing answer.
    let mut h = base().with_standing(Arc::new(Owner(iref(&owner))));
    h.insert_revocation(revocation(&owner, &k, 100, None));
    assert_eq!(
        verdict(&h, &statement_at(&k, 500)),
        "invalid",
        "I1905 owner"
    );
    // ... and the same revocation without the standing answer is nothing.
    let mut h = base();
    h.insert_revocation(revocation(&owner, &k, 100, None));
    assert_eq!(
        verdict(&h, &statement_at(&k, 500)),
        "valid",
        "I1905 owner unheld"
    );
    // The lookup trait agrees.
    let mut h = base();
    h.insert_revocation(revocation(&k, &k, 1, None));
    assert!(matches!(
        h.lookup(&kid(&k), 5),
        ciris_verify_core::edition2::KeyLookup::Invalid
    ));
}
