//! **I2103** (the halt door) and **I2104** (the invocation dedup), v62.0.0
//! JSON-cut slice A; CC 4.2.1.1. Re-pinned at CIRISVerify 23.3.0 (slice C3,
//! **I2361**–**I2364**) against `accord_halt_v2.json` (vendored at
//! `tests/vectors/verify_v23/accord_halt/`, SHA-256 pinned in
//! `federation::verify_v23_vectors`). v1 is no longer replayed: Verify
//! 23.3.0 reads v1's unplaced-key and other-bundle cases as Waiting.
//!
//! - I2361: every invocation case, read by Verify's reader
//!   ([`verify_invocation_row`], re-exported by `edition2::halt`) under the
//!   roster it names, gives the vector's token; a valid one its row id, and a
//!   waiting one the keys it waits on.
//! - I2362: every lifecycle case gives the vector's token under Verify's
//!   counted reader, the reader persist's lifecycle door
//!   (`halt::put_lifecycle`, C2-fix) calls; the door's witnesses are
//!   I2342–I2346 (`halt_lifecycle_invariants`).
//! - I2363: no `not_a_holder` token survives in persist's source: a key the
//!   roster does not place waits, never a refusal (CC 4.2.1.1).
//! - I2103 / I2364, at the store door (sqlite + postgres):
//!   - with no bundle in force held, an invocation waits on the bundle;
//!   - ONE holder's constitutional halt latches the accord's active halt, no
//!     count; a re-put is idempotent;
//!   - `iss_not_holder` is refused by name; a key the roster does not place
//!     waits (retryable); a member fault is `accord_invocation_invalid`;
//!   - (I2364) a holder re-seated at a new key by a later bundle: its halt
//!     waits under the earlier roster and is valid under the later one
//!     (v62.0.0 C2-fix: kept, but with A1's first halt in force it changes
//!     nothing, Verify's latch: a second halt does not reset the fuse).
//! - I2104, both backends: an invocation repeating a held invocation's
//!   `invocation_id`, or its `nonce`, within that one's `valid_until` is
//!   `accord_invocation_replayed`; past it, it is admitted.

use std::collections::BTreeMap;

use ciris_crypto::composite::CompositeSigningKey;
use ciris_verify_core::cde::Value;
use ciris_verify_core::edition2::accord_halt::verify_lifecycle_row;
use ciris_verify_core::edition2::{sign_row_statement, thumbprint};
use serde_json::Value as J;

use super::door_invariants::fixture::{iref, key, map};
use super::halt::{
    verify_invocation_row, HaltReading, HaltRoster, InvocationRow, RosterHolder,
    FAMILY_CONSTITUTIONAL,
};

const FILE: &str =
    include_str!("../../../tests/vectors/verify_v23/accord_halt/accord_halt_v2.json");
const ACCORD: &str = "humanity-accord";

fn vectors() -> J {
    serde_json::from_str(FILE).unwrap()
}

fn seed(j: &J) -> u8 {
    u8::try_from(j["key_seed"].as_u64().unwrap()).unwrap()
}

fn hex32(j: &J) -> [u8; 32] {
    hex::decode(j.as_str().unwrap())
        .unwrap()
        .try_into()
        .unwrap()
}

/// The vector's rosters by name (`genesis`, `rotated`).
fn rosters(v: &J) -> BTreeMap<String, HaltRoster> {
    v["rosters"]
        .as_object()
        .unwrap()
        .iter()
        .map(|(name, r)| {
            let holders: Vec<RosterHolder> = r["holders"]
                .as_array()
                .unwrap()
                .iter()
                .map(|h| {
                    let k = key(seed(h));
                    assert_eq!(
                        hex::encode(thumbprint(k.public_key())),
                        h["kid_hex"].as_str().unwrap(),
                        "the vector's key seed"
                    );
                    RosterHolder {
                        identity_ref: h["iss"].as_str().unwrap().to_owned(),
                        key: k.public_key().clone(),
                    }
                })
                .collect();
            let roster = HaltRoster::new(
                r["accord_root"].as_str().unwrap(),
                hex32(&r["bundle_object_id_hex"]),
                holders,
                r["halt_fuse_secs"]
                    .as_u64()
                    .map(|s| u32::try_from(s).unwrap()),
            );
            (name.clone(), roster)
        })
        .collect()
}

fn statement(c: &J) -> Vec<u8> {
    hex::decode(c["statement"]["statement_hex"].as_str().unwrap()).unwrap()
}

fn case<'a>(v: &'a J, set: &str, id: &str) -> &'a J {
    v[set]
        .as_array()
        .unwrap()
        .iter()
        .find(|c| c["id"] == id)
        .unwrap_or_else(|| panic!("{set}/{id} is in the vector"))
}

/// The hex digests a waiting case names (`kids_hex` / `bundles_hex`).
fn hexes(j: &J) -> Vec<String> {
    j.as_array().map_or_else(Vec::new, |a| {
        a.iter().map(|x| x.as_str().unwrap().to_owned()).collect()
    })
}

/// A non-valid reading against the case's `expect` and `waiting`.
fn assert_reading<T>(c: &J, got: &HaltReading<T>, what: &str) {
    let id = c["id"].as_str().unwrap();
    assert_eq!(got.token(), c["expect"].as_str().unwrap(), "{what} {id}");
    if let HaltReading::Waiting(w) = got {
        let kids: Vec<String> = w.kids.iter().map(hex::encode).collect();
        let bundles: Vec<String> = w.bundles.iter().map(hex::encode).collect();
        assert_eq!(kids, hexes(&c["waiting"]["kids_hex"]), "{what} {id} kids");
        assert_eq!(
            bundles,
            hexes(&c["waiting"]["bundles_hex"]),
            "{what} {id} bundles"
        );
    }
}

/// Every invocation case under its roster; the valid ones by id.
fn invocations(v: &J, rs: &BTreeMap<String, HaltRoster>) -> BTreeMap<String, InvocationRow> {
    let mut valid = BTreeMap::new();
    for c in v["invocations"].as_array().unwrap() {
        let id = c["id"].as_str().unwrap();
        let roster = &rs[c["roster"].as_str().unwrap()];
        match verify_invocation_row(&statement(c), roster) {
            HaltReading::Valid(inv) => {
                assert_eq!(c["expect"], "valid", "I2361 {id}");
                assert_eq!(
                    hex::encode(inv.row_id()),
                    c["row_id_hex"].as_str().unwrap(),
                    "I2361 {id} row id"
                );
                valid.insert(id.to_owned(), inv);
            }
            other => assert_reading(c, &other, "I2361"),
        }
    }
    valid
}

#[test]
fn i2361_invocations_replay_under_the_roster_they_name() {
    let v = vectors();
    let rs = rosters(&v);
    let cases = v["invocations"].as_array().unwrap();
    assert_eq!(cases.len(), 21, "I2361: every invocation case is replayed");
    let valid = invocations(&v, &rs);
    assert_eq!(valid.len(), 5, "I2361: the five valid invocations");
    // The two waits on a key: an outsider, and a holder's new key under the
    // roster that does not seat it yet. Neither is refused.
    for id in ["outsider_halt", "halt_rotated_a1_unseated"] {
        assert_eq!(
            case(&v, "invocations", id)["expect"],
            "waiting:kid",
            "I2361 {id}"
        );
    }
}

#[test]
fn i2362_lifecycles_replay_under_the_roster_they_name() {
    let v = vectors();
    let rs = rosters(&v);
    let halts = invocations(&v, &rs);
    let cases = v["lifecycles"].as_array().unwrap();
    assert_eq!(cases.len(), 22, "I2362: every lifecycle case is replayed");
    for c in cases {
        let id = c["id"].as_str().unwrap();
        let roster = &rs[c["roster"].as_str().unwrap()];
        let halt = &halts[c["halt"].as_str().unwrap()];
        let statements: Vec<Vec<u8>> = c["statements"]
            .as_array()
            .unwrap()
            .iter()
            .map(|s| hex::decode(s["statement_hex"].as_str().unwrap()).unwrap())
            .collect();
        match verify_lifecycle_row(&statements, roster, halt) {
            HaltReading::Valid(row) => {
                assert_eq!(c["expect"], "valid", "I2362 {id}");
                assert_eq!(
                    hex::encode(row.row_id()),
                    c["row_id_hex"].as_str().unwrap(),
                    "I2362 {id} row id"
                );
            }
            other => assert_reading(c, &other, "I2362"),
        }
    }
}

/// I2363 — the removed refusal token is spelled nowhere in persist's
/// source (built here from parts, so this file does not spell it either).
#[test]
fn i2363_no_source_spells_the_removed_halt_token() {
    let needle = concat!("\"not_a", "_holder\"");
    let mut hits = Vec::new();
    let mut files = 0usize;
    let mut stack = vec![std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("src")];
    while let Some(dir) = stack.pop() {
        for e in std::fs::read_dir(&dir).unwrap().flatten() {
            let p = e.path();
            if p.is_dir() {
                stack.push(p);
            } else if p.extension().is_some_and(|x| x == "rs") {
                files += 1;
                let text = std::fs::read_to_string(&p).unwrap();
                if text.contains(needle) {
                    hits.push(p.display().to_string());
                }
            }
        }
    }
    assert!(
        files > 20,
        "I2363: the source walk collapsed ({files} files)"
    );
    assert!(
        hits.is_empty(),
        "I2363: {hits:?} spell the halt refusal Verify 23.3.0 removed; a key the roster does not \
         place waits (CC 4.2.1.1)"
    );
}

/// A constitutional halt by `k` (a holder of the vector's genesis roster).
fn halt(k: &CompositeSigningKey, id: &str, nonce: u8, at: u64, until: u64) -> Vec<u8> {
    let m = map(vec![
        ("accord_root", Value::Text(ACCORD.into())),
        ("asserted_at", Value::Uint(at)),
        ("author", Value::Text(iref(k))),
        ("invocation_id", Value::Text(id.into())),
        ("nonce", Value::Bytes(vec![nonce; 32])),
        ("valid_until", Value::Uint(until)),
    ]);
    sign_row_statement(
        k,
        &iref(k),
        ACCORD,
        "scores",
        FAMILY_CONSTITUTIONAL,
        &m,
        vec![],
    )
    .unwrap()
}

#[cfg(any(feature = "sqlite", feature = "postgres"))]
pub(crate) async fn body(d: &dyn crate::federation::FederationDirectory) {
    use super::halt::put_invocation;
    use super::ingest::{put_statement, INGEST_TIER};
    use crate::federation::{malformed_row, Error};
    let reason = |e: &Error| match e {
        Error::MalformedRow { reason, .. } => (*reason).to_owned(),
        other => other.kind().to_owned(),
    };
    let v = vectors();
    let rs = rosters(&v);
    let genesis = &rs["genesis"];
    let rotated = &rs["rotated"];
    let by_id = |id: &str| statement(case(&v, "invocations", id));
    let a1 = by_id("halt_constitutional_a1");
    // No roster in force is held at the store door: it waits on the bundle.
    let e = put_statement(d, &a1, None, INGEST_TIER).await.unwrap_err();
    assert_eq!(
        e.kind(),
        "federation_attester_key_unknown",
        "I2103 waits on the bundle"
    );
    let e = put_invocation(d, &a1, None).await.unwrap_err();
    assert_eq!(e.kind(), "federation_attester_key_unknown", "I2103");
    // One holder's statement latches.
    let out = put_invocation(d, &a1, Some(genesis)).await.unwrap();
    assert!(out.new && out.latched, "I2103 latches");
    let active = d
        .get_active_halt(ACCORD)
        .await
        .unwrap()
        .expect("I2103 active halt");
    assert_eq!(
        active.active_halt_id,
        hex::encode(out.invocation.row_id()),
        "I2103"
    );
    let again = put_invocation(d, &a1, Some(genesis)).await.unwrap();
    assert!(!again.new, "I2103 idempotent");
    // iss_not_holder, by name; a key the roster does not place waits.
    let e = put_invocation(d, &by_id("iss_of_another_holder"), Some(genesis))
        .await
        .unwrap_err();
    assert_eq!(reason(&e), malformed_row::ISS_NOT_HOLDER, "I2103");
    let e = put_invocation(d, &by_id("outsider_halt"), Some(genesis))
        .await
        .unwrap_err();
    assert_eq!(
        e.kind(),
        "federation_attester_key_unknown",
        "I2103 unknown kid waits"
    );
    let e = put_invocation(d, &by_id("nonce_31_bytes"), Some(genesis))
        .await
        .unwrap_err();
    assert_eq!(
        reason(&e),
        malformed_row::ACCORD_INVOCATION_INVALID,
        "I2103"
    );

    // I2364: A1 re-seated at a new key by the later bundle. Under the
    // genesis roster its halt waits on the key; under the rotated roster it
    // latches.
    let unseated = by_id("halt_rotated_a1_unseated");
    let e = put_invocation(d, &unseated, Some(genesis))
        .await
        .unwrap_err();
    assert_eq!(
        e.kind(),
        "federation_attester_key_unknown",
        "I2364 waits under the earlier roster"
    );
    let seated = by_id("halt_rotated_a1_seated");
    let first = d.get_active_halt(ACCORD).await.unwrap().expect("I2364");
    let out = put_invocation(d, &seated, Some(rotated))
        .await
        .expect("I2364 is valid under the later roster");
    // v62.0.0 (C2-fix, CC 4.2.1.1; Verify's `HaltLatch`) — valid, kept, and
    // it changes nothing: A1's first halt is still in force, and a second
    // halt neither replaces it nor resets its fuse.
    assert!(out.new && !out.latched && !out.held, "I2364: {out:?}");
    let active = d.get_active_halt(ACCORD).await.unwrap().expect("I2364");
    assert_eq!(
        (active.active_halt_id, active.set_at),
        (first.active_halt_id, first.set_at),
        "I2364: the halt in force and its fuse are unchanged"
    );
    // The first key, under the later roster that no longer seats it, waits.
    let e = put_invocation(d, &by_id("halt_a1_first_key_under_rotated"), Some(rotated))
        .await
        .unwrap_err();
    assert_eq!(e.kind(), "federation_attester_key_unknown", "I2364");

    // I2104: the dedup.
    let b1 = key(2);
    let held = halt(&b1, "halt-dedup", 0x21, 2_000_000, 3_000_000);
    put_invocation(d, &held, Some(genesis))
        .await
        .expect("I2104 first");
    for (why, st) in [
        (
            "same invocation_id",
            halt(&b1, "halt-dedup", 0x22, 2_500_000, 3_500_000),
        ),
        (
            "same nonce",
            halt(&b1, "halt-other", 0x21, 2_500_000, 3_500_000),
        ),
        (
            "same id, another holder",
            halt(&key(3), "halt-dedup", 0x23, 2_500_000, 3_500_000),
        ),
    ] {
        // v62.0.0 (wave GC4; CC 2.7.2, 2.7.3) — a replay is KEPT and
        // concludes nothing (held `accord_invocation_replayed`), never
        // refused; it does not latch.
        let out = put_invocation(d, &st, Some(genesis))
            .await
            .unwrap_or_else(|e| panic!("I2104 {why}: held, not refused: {e:?}"));
        assert!(out.held && !out.latched, "I2104 {why}: held, no latch");
        assert_eq!(
            super::fold::why_held(d, &super::names::RowId(*out.invocation.row_id()))
                .await
                .unwrap()
                .map(|h| h.reason)
                .as_deref(),
            Some(malformed_row::ACCORD_INVOCATION_REPLAYED),
            "I2104 {why}"
        );
    }
    // Past the held one's valid_until, the id may be used again.
    put_invocation(
        d,
        &halt(&b1, "halt-dedup", 0x24, 3_000_001, 4_000_000),
        Some(genesis),
    )
    .await
    .expect("I2104 after valid_until");
}

/// **I3790 / I3791 (wave GC4; CC 2.7.2 "one set, one answer", CC 2.7.3)** —
/// the invocation replay is a FOLD, not a refusal, and its answer does not
/// depend on arrival order. Two constitutional halts of one accord share a
/// `nonce`; `early` is asserted first and `late` within `early`'s
/// `valid_until`.
///
/// - I3790, `early` then `late`: `late` is HELD (kept, no latch, reason
///   `accord_invocation_replayed`); `early` is counted and is the active halt.
/// - I3791, `late` then `early` (another nonce): `late` is counted and
///   latches first; `early`'s arrival UN-concludes it (held, reason
///   `accord_invocation_replayed`, its latch cleared) and `early` is the
///   active halt — the same standing as I3790.
///
/// Mutation targets: the rank comparison in `replay_fold`, the
/// `clear_active_halt` of a row that becomes a replay.
#[cfg(any(feature = "sqlite", feature = "postgres"))]
pub(crate) async fn replay_order_body(d: &dyn crate::federation::FederationDirectory) {
    use super::fold::{reason, why_held};
    use super::halt::put_invocation;
    use super::names::RowId;
    let v = vectors();
    let rs = rosters(&v);
    let genesis = &rs["genesis"];
    let b1 = key(2);
    let c1 = key(3);
    let held_reason =
        |row: RowId| async move { why_held(d, &row).await.unwrap().map(|h| h.reason) };
    let active = || async {
        d.get_active_halt(ACCORD)
            .await
            .unwrap()
            .map(|h| h.active_halt_id)
    };

    // I3790: early, then late.
    let early = halt(&b1, "gc4-early-1", 0x31, 5_000_000, 6_000_000);
    let late = halt(&c1, "gc4-late-1", 0x31, 5_500_000, 6_500_000);
    let e = put_invocation(d, &early, Some(genesis))
        .await
        .expect("I3790 early");
    assert!(!e.held && e.latched, "I3790: early counts and latches");
    let l = put_invocation(d, &late, Some(genesis))
        .await
        .expect("I3790: a replay is held, never refused");
    assert!(l.new && l.held && !l.latched, "I3790: late is held: {l:?}");
    let (e_id, l_id) = (RowId(*e.invocation.row_id()), RowId(*l.invocation.row_id()));
    assert_eq!(
        held_reason(l_id).await.as_deref(),
        Some(reason::ACCORD_INVOCATION_REPLAYED),
        "I3790"
    );
    assert_eq!(held_reason(e_id).await, None, "I3790: early concludes");
    assert_eq!(
        active().await,
        Some(e_id.hex()),
        "I3790: early is the active halt"
    );

    // I3791: late, then early.
    let early = halt(&b1, "gc4-early-2", 0x41, 7_000_000, 8_000_000);
    let late = halt(&c1, "gc4-late-2", 0x41, 7_500_000, 8_500_000);
    let l = put_invocation(d, &late, Some(genesis))
        .await
        .expect("I3791 late");
    assert!(
        !l.held && l.latched,
        "I3791: alone, late counts and latches"
    );
    let l_id = RowId(*l.invocation.row_id());
    assert_eq!(active().await, Some(l_id.hex()), "I3791: late latched");
    let e = put_invocation(d, &early, Some(genesis))
        .await
        .expect("I3791 early");
    let e_id = RowId(*e.invocation.row_id());
    assert!(!e.held && e.latched, "I3791: early counts and latches");
    assert_eq!(
        held_reason(l_id).await.as_deref(),
        Some(reason::ACCORD_INVOCATION_REPLAYED),
        "I3791: late is UN-concluded by early's arrival"
    );
    assert_eq!(held_reason(e_id).await, None, "I3791: early concludes");
    assert_eq!(
        active().await,
        Some(e_id.hex()),
        "I3791: the same active halt as I3790's order"
    );
    // A re-offer of the replay changes nothing.
    let again = put_invocation(d, &late, Some(genesis))
        .await
        .expect("I3791 re-offer");
    assert!(!again.new && again.held, "I3791: still held");
}

#[cfg(feature = "sqlite")]
#[tokio::test]
async fn i3790_i3791_replay_order_sqlite() {
    use crate::store::Backend as _;
    let b = crate::store::sqlite::SqliteBackend::open_in_memory()
        .await
        .unwrap();
    b.run_migrations().await.unwrap();
    Box::pin(replay_order_body(&b)).await;
}

#[cfg(feature = "postgres")]
#[tokio::test]
async fn i3790_i3791_replay_order_postgres() {
    use crate::store::Backend as _;
    let Some(dsn) = crate::test_pg::empty_dsn() else {
        return;
    };
    let b = crate::store::postgres::PostgresBackend::connect(&dsn)
        .await
        .unwrap();
    b.run_migrations().await.unwrap();
    Box::pin(replay_order_body(&b)).await;
}

#[cfg(feature = "sqlite")]
#[tokio::test]
async fn i2103_i2104_i2364_sqlite() {
    use crate::store::Backend as _;
    let b = crate::store::sqlite::SqliteBackend::open_in_memory()
        .await
        .unwrap();
    b.run_migrations().await.unwrap();
    Box::pin(body(&b)).await;
}

#[cfg(feature = "postgres")]
#[tokio::test]
async fn i2103_i2104_i2364_postgres() {
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
