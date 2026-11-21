//! The accord halt's lifecycle and fuse at the store door (v62.0.0 C2-fix,
//! ceremony gap 8; CC 4.2.1.1, CC 4.2.1.3), on sqlite and postgres, over the
//! test ceremony's bundle (`fixture_genesis::bundle_v2`, three holders).
//!
//! - **I2342** — fire, confirm, resume: one holder's constitutional halt
//!   latches; one `confirmed` voice is kept and held `count_short`; the
//!   second voice counts it (a strict majority of three) and confirms the
//!   halt, which then never lapses; two `active` voices end it. The first
//!   voice of each row arrives through `put_statement` (the routing). A
//!   re-put of the ended halt is not a new receipt: nothing latches.
//! - **I2343** — the fuse: a lone halt is in force until `received_at +
//!   halt_fuse_secs` (the charter's 86400) and not from then on; a second
//!   halt within the fuse changes nothing and keeps the first halt's fuse; a
//!   confirmation counted after the fuse confirms nothing and clears the
//!   lapsed halt; a fresh halt then latches anew.
//! - **I2344** — refusals: a lifecycle statement under a holder's key whose
//!   `iss` names another identity is refused `iss_not_holder`; one with a
//!   dimension that is no lifecycle kind is `accord_invocation_invalid`.
//!   Neither keeps anything. A key no bundle seats WAITS (retryable): a
//!   stranger cannot be told from a holder re-seated by a bundle this node
//!   lacks (CC 4.2.1.1).
//! - **I2345** — waits are held for re-offer, never refused: a lifecycle row
//!   naming a bundle this node does not hold waits on that bundle; naming a
//!   halt it does not hold, it waits on that row; nothing of it is kept, and
//!   the same statements count once the bundle and the halt are held.
//! - **I2346** (readiness item 7) — the pre-signed, sealed halt: signed with
//!   a holder's COMPOSITE key and asserted before the genesis, it waits
//!   while no bundle is held (nothing kept) and latches once the genesis is
//!   installed. Either half of the composite signature alone is refused
//!   `accord_invocation_invalid` (`statement_invalid`).
//! - **I2308** (HL-fix1, SECURITY; CC 4.2.1.3 "against the bundle in
//!   force") — after a later bundle removes holder H, a `confirmed` voice
//!   naming the OLD (superseded) head is refused by name
//!   (`accord_lifecycle_head_not_in_force`, under `accord_invocation_invalid`)
//!   and kept nowhere, at the lifecycle door and at the statement door;
//!   H's voice plus a remaining holder's over the old head
//!   count nothing (the halt stays unconfirmed). The same `confirmed` row
//!   over the head IN FORCE, voiced by two of its holders, counts and
//!   confirms. (Before HL-fix1 the old head's roster counted H: the first
//!   assertion below would read `Ok(Pending)`.)

use chrono::{DateTime, Duration, Utc};
use ciris_crypto::composite::{CompositeSigningKey, MLDSA65_SIG_LEN};
use ciris_verify_core::cde::{self, Value};
use ciris_verify_core::edition2::{row_ref, sign_row_statement, Digest32};

use super::door_invariants::fixture::map;
use super::fixture_genesis::{bundle_v2, identity_ref_of, install_v2, test_key, FAMILY_KEY_ID};
use super::genesis::genesis_in_force;
use super::halt::{
    halt_in_force, put_invocation_at, put_lifecycle_at, HaltRoster, LifecycleKind,
    LifecycleOutcome, FAMILY_CONSTITUTIONAL, FAMILY_LIFECYCLE,
};
use super::ingest::{put_statement, StatementOutcome, INGEST_TIER};
use super::names::RowId;
use crate::federation::{malformed_row, Error, FederationDirectory};

const ACCORD: &str = FAMILY_KEY_ID;
const HOUR_MS: u64 = 3_600_000;
const FUSE_SECS: i64 = 86_400;

fn now_ms() -> u64 {
    u64::try_from(crate::host::clock::now().timestamp_millis()).unwrap()
}

fn reason(e: &Error) -> &'static str {
    match e {
        Error::MalformedRow { reason, .. } => reason,
        other => other.kind(),
    }
}

fn waits(e: &Error) -> bool {
    matches!(e, Error::AttesterKeyUnknown { .. })
}

/// A constitutional halt by `k` under the identity `iss`.
fn halt(k: &CompositeSigningKey, iss: &str, id: &str, nonce: u8, at: u64, until: u64) -> Vec<u8> {
    let m = map(vec![
        ("accord_root", Value::Text(ACCORD.into())),
        ("asserted_at", Value::Uint(at)),
        ("author", Value::Text(iss.into())),
        ("invocation_id", Value::Text(id.into())),
        ("nonce", Value::Bytes(vec![nonce; 32])),
        ("valid_until", Value::Uint(until)),
    ]);
    sign_row_statement(k, iss, ACCORD, "scores", FAMILY_CONSTITUTIONAL, &m, vec![]).unwrap()
}

/// Holder `i`'s constitutional halt (its current key, its identity).
fn holder_halt(i: usize, id: &str, nonce: u8, at: u64, until: u64) -> Vec<u8> {
    let s = bundle_v2();
    halt(
        &s.holder_key(i),
        s.holder_identity_ref(i),
        id,
        nonce,
        at,
        until,
    )
}

/// One voice of a lifecycle row: `leaf` (`confirmed` / `active`) of the halt
/// `target`, counted over the bundle `head`.
#[allow(clippy::too_many_arguments)]
fn lifecycle(
    k: &CompositeSigningKey,
    iss: &str,
    leaf: &str,
    target: &Digest32,
    head: &Digest32,
    id: &str,
    nonce: u8,
    at: u64,
) -> Vec<u8> {
    let m = map(vec![
        (
            "refs",
            map(vec![("head", row_ref(head)), ("target", row_ref(target))]),
        ),
        (
            "dimension",
            Value::Text(format!("accord:lifecycle:{leaf}:v1")),
        ),
        ("accord_root", Value::Text(ACCORD.into())),
        ("invocation_id", Value::Text(id.into())),
        ("nonce", Value::Bytes(vec![nonce; 32])),
        ("asserted_at", Value::Uint(at)),
        ("valid_until", Value::Uint(at + HOUR_MS)),
    ]);
    sign_row_statement(k, iss, ACCORD, "scores", FAMILY_LIFECYCLE, &m, vec![]).unwrap()
}

/// Holder `i`'s voice of the lifecycle row `leaf` of `target`, over the
/// ceremony's bundle.
fn voice(i: usize, leaf: &str, target: &Digest32, id: &str, nonce: u8, at: u64) -> Vec<u8> {
    let s = bundle_v2();
    lifecycle(
        &s.holder_key(i),
        s.holder_identity_ref(i),
        leaf,
        target,
        &s.object_id,
        id,
        nonce,
        at,
    )
}

fn row_of(statement: &[u8]) -> RowId {
    RowId::of_statement(statement).expect("a row id")
}

async fn roster(d: &dyn FederationDirectory) -> HaltRoster {
    genesis_in_force(d)
        .await
        .unwrap()
        .halt_roster(ACCORD)
        .expect("the ceremony's roster is in force")
}

async fn received_at(d: &dyn FederationDirectory) -> DateTime<Utc> {
    d.get_active_halt(ACCORD)
        .await
        .unwrap()
        .expect("a halt is latched")
        .set_at
}

/// I2342.
pub(crate) async fn fire_confirm_resume(d: &dyn FederationDirectory) {
    install_v2(d).await.unwrap();
    let at = now_ms();
    let h = holder_halt(0, "c2-halt-1", 0x51, at, at + HOUR_MS);
    let hid = row_of(&h);
    let out = put_statement(d, &h, None, INGEST_TIER).await.unwrap();
    assert!(
        matches!(out, StatementOutcome::Row { new: true, .. }),
        "I2342 fire: {out:?}"
    );
    let now = crate::host::clock::now();
    let f = halt_in_force(d, ACCORD, now)
        .await
        .unwrap()
        .expect("I2342: latched");
    assert_eq!(f.halt_row, Some(hid), "I2342");
    assert!(!f.confirmed, "I2342: lone");
    assert_eq!(
        f.lapses_at,
        Some(f.received_at + Duration::seconds(FUSE_SECS)),
        "I2342: the charter's fuse from receipt"
    );

    // Confirm: one voice is kept and held; the second counts.
    let c0 = voice(0, "confirmed", &hid.0, "c2-confirm-1", 0x52, at + 1);
    let out = put_statement(d, &c0, None, INGEST_TIER).await.unwrap();
    assert!(
        matches!(out, StatementOutcome::Pending { new: true, .. }),
        "I2342: one voice is short: {out:?}"
    );
    assert_eq!(
        super::fold::why_held(d, &row_of(&c0))
            .await
            .unwrap()
            .map(|h| h.reason)
            .as_deref(),
        Some(super::fold::reason::COUNT_SHORT),
        "I2342"
    );
    assert!(
        !halt_in_force(d, ACCORD, now)
            .await
            .unwrap()
            .unwrap()
            .confirmed,
        "I2342: not yet confirmed"
    );
    let c1 = voice(1, "confirmed", &hid.0, "c2-confirm-1", 0x52, at + 1);
    assert_eq!(row_of(&c1), row_of(&c0), "I2342: one row, two voices");
    let out = put_lifecycle_at(d, &c1, now).await.unwrap();
    assert_eq!(
        out,
        LifecycleOutcome::Applied {
            row_id: row_of(&c0),
            new: true,
            kind: LifecycleKind::Confirmed
        },
        "I2342 confirm"
    );
    let f = halt_in_force(d, ACCORD, now).await.unwrap().unwrap();
    assert!(f.confirmed && f.lapses_at.is_none(), "I2342: confirmed");
    let long_after = now + Duration::seconds(FUSE_SECS * 3);
    assert!(
        halt_in_force(d, ACCORD, long_after)
            .await
            .unwrap()
            .is_some(),
        "I2342: a confirmed halt never lapses"
    );

    // Resume: a strict majority of `active` ends it.
    let a1 = voice(1, "active", &hid.0, "c2-resume-1", 0x53, at + 2);
    let out = put_statement(d, &a1, None, INGEST_TIER).await.unwrap();
    assert!(
        matches!(out, StatementOutcome::Pending { .. }),
        "I2342: {out:?}"
    );
    assert!(
        halt_in_force(d, ACCORD, now).await.unwrap().is_some(),
        "I2342: one resumption voice ends nothing"
    );
    let a2 = voice(2, "active", &hid.0, "c2-resume-1", 0x53, at + 2);
    let out = put_lifecycle_at(d, &a2, now).await.unwrap();
    assert!(
        matches!(
            out,
            LifecycleOutcome::Applied {
                kind: LifecycleKind::Active,
                ..
            }
        ),
        "I2342 resume: {out:?}"
    );
    assert!(
        halt_in_force(d, ACCORD, now).await.unwrap().is_none(),
        "I2342: resumed"
    );
    assert!(
        d.get_active_halt(ACCORD).await.unwrap().is_none(),
        "I2342: the latch is clear"
    );
    // A re-put of the ended halt is not a new receipt.
    let r = roster(d).await;
    let again = put_invocation_at(d, &h, Some(&r), now).await.unwrap();
    assert!(!again.new && !again.latched, "I2342 re-put: {again:?}");
    assert!(halt_in_force(d, ACCORD, now).await.unwrap().is_none());
}

/// I2343.
pub(crate) async fn the_fuse(d: &dyn FederationDirectory) {
    install_v2(d).await.unwrap();
    let r = roster(d).await;
    let at = now_ms();
    let h = holder_halt(0, "c2-fuse-1", 0x61, at, at + 48 * HOUR_MS);
    let hid = row_of(&h);
    let now = crate::host::clock::now();
    let out = put_invocation_at(d, &h, Some(&r), now).await.unwrap();
    assert!(out.latched, "I2343: latched");
    let t0 = received_at(d).await;
    let lapse = t0 + Duration::seconds(FUSE_SECS);
    // A second halt within the fuse changes nothing and keeps the fuse.
    let second = holder_halt(1, "c2-fuse-2", 0x62, at + 1, at + 48 * HOUR_MS);
    let out = put_invocation_at(d, &second, Some(&r), t0 + Duration::seconds(10))
        .await
        .unwrap();
    assert!(
        out.new && !out.latched && !out.held,
        "I2343 second: {out:?}"
    );
    assert_eq!(received_at(d).await, t0, "I2343: the fuse is not reset");
    let f = halt_in_force(d, ACCORD, lapse - Duration::seconds(1))
        .await
        .unwrap()
        .expect("I2343: in force before the fuse runs");
    assert_eq!(f.halt_row, Some(hid), "I2343");
    assert!(
        halt_in_force(d, ACCORD, lapse).await.unwrap().is_none(),
        "I2343: lapsed at receipt + halt_fuse_secs"
    );
    // A confirmation counted after the fuse confirms nothing.
    let after = lapse + Duration::seconds(1);
    let c0 = voice(0, "confirmed", &hid.0, "c2-late-confirm", 0x63, at + 2);
    let c1 = voice(1, "confirmed", &hid.0, "c2-late-confirm", 0x63, at + 2);
    assert!(matches!(
        put_lifecycle_at(d, &c0, after).await.unwrap(),
        LifecycleOutcome::Pending { .. }
    ));
    assert_eq!(
        put_lifecycle_at(d, &c1, after).await.unwrap(),
        LifecycleOutcome::Unchanged {
            row_id: row_of(&c0),
            new: true
        },
        "I2343: a confirmation after the fuse confirms nothing"
    );
    assert!(
        d.get_active_halt(ACCORD).await.unwrap().is_none(),
        "I2343: the lapsed halt is cleared"
    );
    assert!(
        halt_in_force(d, ACCORD, t0 + Duration::seconds(5))
            .await
            .unwrap()
            .is_none(),
        "I2343: the late confirmation never confirms it"
    );
    // A fresh halt latches anew.
    let fresh = holder_halt(2, "c2-fuse-3", 0x64, at + 3, at + 48 * HOUR_MS);
    let out = put_invocation_at(d, &fresh, Some(&r), after + Duration::seconds(1))
        .await
        .unwrap();
    assert!(out.latched, "I2343: a fresh halt after the lapse latches");
    assert_eq!(
        d.get_active_halt(ACCORD)
            .await
            .unwrap()
            .unwrap()
            .active_halt_id,
        row_of(&fresh).hex(),
        "I2343"
    );
}

/// I2344.
pub(crate) async fn refusals(d: &dyn FederationDirectory) {
    install_v2(d).await.unwrap();
    let s = bundle_v2();
    let at = now_ms();
    let h = holder_halt(0, "c2-refuse-halt", 0x71, at, at + HOUR_MS);
    put_statement(d, &h, None, INGEST_TIER).await.unwrap();
    let hid = row_of(&h);
    let now = crate::host::clock::now();
    // A holder's key, an iss that is not that holder.
    let stranger = identity_ref_of(9);
    let forged_iss = lifecycle(
        &s.holder_key(0),
        &stranger,
        "confirmed",
        &hid.0,
        &s.object_id,
        "c2-refuse-1",
        0x72,
        at + 1,
    );
    let e = put_lifecycle_at(d, &forged_iss, now).await.unwrap_err();
    assert_eq!(reason(&e), malformed_row::ISS_NOT_HOLDER, "I2344: {e:?}");
    // A dimension that is no lifecycle kind.
    let paused = voice(1, "paused", &hid.0, "c2-refuse-2", 0x73, at + 1);
    let e = put_statement(d, &paused, None, INGEST_TIER)
        .await
        .unwrap_err();
    assert!(!waits(&e), "I2344: refused, not waited on: {e:?}");
    // A key no bundle seats waits, never refused.
    let k9 = test_key(9);
    let outsider = lifecycle(
        &k9,
        &stranger,
        "confirmed",
        &hid.0,
        &s.object_id,
        "c2-refuse-3",
        0x74,
        at + 1,
    );
    let e = put_lifecycle_at(d, &outsider, now).await.unwrap_err();
    assert!(waits(&e), "I2344: a key the roster lacks waits: {e:?}");
    for (what, st) in [
        ("iss_not_holder", &forged_iss),
        ("paused", &paused),
        ("outsider", &outsider),
    ] {
        assert!(
            d.edition2_voices(&row_of(st)).await.unwrap().is_empty(),
            "I2344 {what}: nothing kept"
        );
    }
    assert!(
        !halt_in_force(d, ACCORD, now)
            .await
            .unwrap()
            .unwrap()
            .confirmed,
        "I2344: nothing confirmed"
    );
}

/// I2345.
pub(crate) async fn waits_are_held_for_reoffer(d: &dyn FederationDirectory) {
    let s = bundle_v2();
    let at = now_ms();
    let h = holder_halt(0, "c2-wait-halt", 0x81, at, at + HOUR_MS);
    let hid = row_of(&h);
    let c0 = voice(0, "confirmed", &hid.0, "c2-wait-confirm", 0x82, at + 1);
    let c1 = voice(1, "confirmed", &hid.0, "c2-wait-confirm", 0x82, at + 1);
    let now = crate::host::clock::now();
    // No bundle held: it waits on the bundle its head names.
    let e = put_statement(d, &c0, None, INGEST_TIER).await.unwrap_err();
    assert!(waits(&e), "I2345: waits on the bundle: {e:?}");
    assert!(
        format!("{e:?}").contains(&hex::encode(s.object_id)),
        "I2345: it names the bundle: {e:?}"
    );
    install_v2(d).await.unwrap();
    // The bundle held, the halt not: it waits on the halt.
    let e = put_lifecycle_at(d, &c0, now).await.unwrap_err();
    assert!(waits(&e), "I2345: waits on the halt: {e:?}");
    assert!(
        format!("{e:?}").contains(&hid.hex()),
        "I2345: it names the halt: {e:?}"
    );
    assert!(
        d.edition2_voices(&row_of(&c0)).await.unwrap().is_empty(),
        "I2345: nothing of a waiting row is kept"
    );
    // Held both: the same statements, re-offered, count.
    put_statement(d, &h, None, INGEST_TIER).await.unwrap();
    assert!(matches!(
        put_lifecycle_at(d, &c0, now).await.unwrap(),
        LifecycleOutcome::Pending { .. }
    ));
    assert!(matches!(
        put_lifecycle_at(d, &c1, now).await.unwrap(),
        LifecycleOutcome::Applied {
            kind: LifecycleKind::Confirmed,
            ..
        }
    ));
}

/// `statement` with its composite signature's ML-DSA-65 half (`ml`) or
/// Ed25519 half zeroed.
fn one_half_only(statement: &[u8], keep_ed: bool) -> Vec<u8> {
    let Value::Tag(18, inner) = cde::decode(statement).unwrap() else {
        panic!("a COSE_Sign1");
    };
    let mut parts = inner.as_array().unwrap().to_vec();
    let mut sig = parts[3].as_bytes().unwrap().to_vec();
    if keep_ed {
        sig[..MLDSA65_SIG_LEN].fill(0);
    } else {
        sig[MLDSA65_SIG_LEN..].fill(0);
    }
    parts[3] = Value::Bytes(sig);
    cde::encode(&Value::Tag(18, Box::new(Value::Array(parts))))
}

/// I2346.
pub(crate) async fn the_pre_signed_halt(d: &dyn FederationDirectory) {
    let s = bundle_v2();
    let signed_at = s.asserted_at_ms - 6 * HOUR_MS;
    let sealed = holder_halt(1, "c2-sealed", 0x91, signed_at, now_ms() + 24 * HOUR_MS);
    // Before the genesis: it waits, and nothing is kept.
    let e = put_statement(d, &sealed, None, INGEST_TIER)
        .await
        .unwrap_err();
    assert!(waits(&e), "I2346: waits before the genesis: {e:?}");
    assert!(
        d.edition2_voices(&row_of(&sealed))
            .await
            .unwrap()
            .is_empty(),
        "I2346: not kept"
    );
    install_v2(d).await.unwrap();
    // Either half of the composite alone is refused.
    for (what, keep_ed) in [("Ed25519 alone", true), ("ML-DSA-65 alone", false)] {
        let e = put_statement(d, &one_half_only(&sealed, keep_ed), None, INGEST_TIER)
            .await
            .unwrap_err();
        assert_eq!(
            reason(&e),
            malformed_row::ACCORD_INVOCATION_INVALID,
            "I2346 {what}: {e:?}"
        );
        assert!(
            format!("{e:?}").contains("statement_invalid"),
            "I2346 {what}: {e:?}"
        );
    }
    // The composite, published after the genesis: it latches.
    let out = put_statement(d, &sealed, None, INGEST_TIER).await.unwrap();
    assert!(
        matches!(out, StatementOutcome::Row { new: true, .. }),
        "I2346: {out:?}"
    );
    let f = halt_in_force(d, ACCORD, crate::host::clock::now())
        .await
        .unwrap()
        .expect("I2346: the sealed halt latches");
    assert_eq!(f.halt_row, Some(row_of(&sealed)), "I2346");
}

/// I2308.
pub(crate) async fn superseded_head_counts_nothing(d: &dyn FederationDirectory) {
    use super::fixture_genesis::{install_ceremony_v2, later_v2};
    let first = bundle_v2();
    install_v2(d).await.unwrap();
    let at = now_ms();
    let now = crate::host::clock::now();
    // Holder 0 fires under the first bundle.
    let h = holder_halt(0, "hl-fix1-halt", 0xa1, at, at + HOUR_MS);
    let hid = row_of(&h);
    put_statement(d, &h, None, INGEST_TIER).await.unwrap();
    // A later bundle removes holder seed 3 (index 2) and seats seed 4.
    let later = later_v2(first, &[1, 2, 4], &[11, 12], &[1, 2, 4]);
    install_ceremony_v2(d, &later)
        .await
        .expect("I2308: the later bundle is in force");
    assert_eq!(
        genesis_in_force(d).await.unwrap().head.map(|p| p.object_id),
        Some(later.object_id),
        "I2308: the later bundle is the head"
    );
    let removed = first.holder_identity_ref(2).to_owned();
    assert!(
        !later.holder_identity_refs().contains(&removed),
        "I2308: H is no holder of the bundle in force"
    );
    // H's and holder 0's `confirmed` voices over the OLD head.
    let old_h = lifecycle(
        &first.holder_key(2),
        &removed,
        "confirmed",
        &hid.0,
        &first.object_id,
        "hl-fix1-confirm-old",
        0xa2,
        at + 1,
    );
    let old_0 = voice(0, "confirmed", &hid.0, "hl-fix1-confirm-old", 0xa2, at + 1);
    for (who, st) in [("H", &old_h), ("holder 0", &old_0)] {
        let e = put_lifecycle_at(d, st, now)
            .await
            .expect_err("I2308: a voice over a superseded head is not counted");
        assert_eq!(
            reason(&e),
            malformed_row::ACCORD_INVOCATION_INVALID,
            "I2308 {who}: {e:?}"
        );
        assert!(
            format!("{e:?}").contains("accord_lifecycle_head_not_in_force"),
            "I2308 {who}: refused by name: {e:?}"
        );
        assert!(
            d.edition2_voices(&row_of(st)).await.unwrap().is_empty(),
            "I2308 {who}: nothing kept"
        );
    }
    // Through the statement door too: refused, nothing kept (no hold).
    let e = put_statement(d, &old_h, None, INGEST_TIER)
        .await
        .expect_err("I2308: the statement door refuses it too");
    assert!(
        format!("{e:?}").contains("accord_lifecycle_head_not_in_force"),
        "I2308: {e:?}"
    );
    assert!(
        d.edition2_voices(&row_of(&old_h)).await.unwrap().is_empty(),
        "I2308: the statement door kept nothing"
    );
    assert!(
        !halt_in_force(d, ACCORD, now)
            .await
            .unwrap()
            .expect("I2308: the halt is in force")
            .confirmed,
        "I2308: the old head confirmed nothing"
    );
    // The same row over the head IN FORCE, by two of its holders, counts.
    let new_0 = lifecycle(
        &later.holder_key(0),
        later.holder_identity_ref(0),
        "confirmed",
        &hid.0,
        &later.object_id,
        "hl-fix1-confirm-new",
        0xa3,
        at + 2,
    );
    let new_1 = lifecycle(
        &later.holder_key(1),
        later.holder_identity_ref(1),
        "confirmed",
        &hid.0,
        &later.object_id,
        "hl-fix1-confirm-new",
        0xa3,
        at + 2,
    );
    assert!(matches!(
        put_lifecycle_at(d, &new_0, now).await.unwrap(),
        LifecycleOutcome::Pending { .. }
    ));
    assert!(
        matches!(
            put_lifecycle_at(d, &new_1, now).await.unwrap(),
            LifecycleOutcome::Applied {
                kind: LifecycleKind::Confirmed,
                ..
            }
        ),
        "I2308: counted over the head in force"
    );
    assert!(
        halt_in_force(d, ACCORD, now)
            .await
            .unwrap()
            .unwrap()
            .confirmed,
        "I2308: confirmed"
    );
}

#[cfg(feature = "sqlite")]
mod sqlite {
    use crate::store::Backend as _;

    async fn store() -> crate::store::sqlite::SqliteBackend {
        let b = crate::store::sqlite::SqliteBackend::open_in_memory()
            .await
            .unwrap();
        b.run_migrations().await.unwrap();
        b
    }

    #[tokio::test]
    async fn i2342_fire_confirm_resume_sqlite() {
        Box::pin(super::fire_confirm_resume(&store().await)).await;
    }

    #[tokio::test]
    async fn i2343_the_fuse_sqlite() {
        Box::pin(super::the_fuse(&store().await)).await;
    }

    #[tokio::test]
    async fn i2344_refusals_sqlite() {
        Box::pin(super::refusals(&store().await)).await;
    }

    #[tokio::test]
    async fn i2345_waits_sqlite() {
        Box::pin(super::waits_are_held_for_reoffer(&store().await)).await;
    }

    #[tokio::test]
    async fn i2346_pre_signed_halt_sqlite() {
        Box::pin(super::the_pre_signed_halt(&store().await)).await;
    }

    #[tokio::test]
    async fn i2308_superseded_head_counts_nothing_sqlite() {
        Box::pin(super::superseded_head_counts_nothing(&store().await)).await;
    }
}

#[cfg(feature = "postgres")]
mod postgres {
    use crate::store::Backend as _;

    async fn store() -> Option<crate::store::postgres::PostgresBackend> {
        let dsn = crate::test_pg::isolated_dsn()?;
        let b = crate::store::postgres::PostgresBackend::connect(&dsn)
            .await
            .unwrap();
        b.run_migrations().await.unwrap();
        Some(b)
    }

    #[tokio::test]
    async fn i2342_fire_confirm_resume_postgres() {
        let Some(b) = store().await else { return };
        Box::pin(super::fire_confirm_resume(&b)).await;
    }

    #[tokio::test]
    async fn i2343_the_fuse_postgres() {
        let Some(b) = store().await else { return };
        Box::pin(super::the_fuse(&b)).await;
    }

    #[tokio::test]
    async fn i2344_refusals_postgres() {
        let Some(b) = store().await else { return };
        Box::pin(super::refusals(&b)).await;
    }

    #[tokio::test]
    async fn i2345_waits_postgres() {
        let Some(b) = store().await else { return };
        Box::pin(super::waits_are_held_for_reoffer(&b)).await;
    }

    #[tokio::test]
    async fn i2346_pre_signed_halt_postgres() {
        let Some(b) = store().await else { return };
        Box::pin(super::the_pre_signed_halt(&b)).await;
    }

    #[tokio::test]
    async fn i2308_superseded_head_counts_nothing_postgres() {
        let Some(b) = store().await else { return };
        Box::pin(super::superseded_head_counts_nothing(&b)).await;
    }
}
