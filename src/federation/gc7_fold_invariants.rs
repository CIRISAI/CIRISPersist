//! **I3911–I3915** (wave GC7; CC 2.7.3): the gates GC7 converted from
//! "refuse" to "hold" mark a running fold attempt with their reason token
//! and declare the inputs they read, and outside an attempt are the refusals
//! they were. Store-free (the gates are pure over the rows handed to them);
//! the store-facing order witness is I3910 (`edition2::occurrence_invariants`,
//! sqlite and postgres) and I3916 is the chunk slot (`blob_admit`).
//!
//! - I3911: `family_dissolution::refuse_if_dissolved` holds
//!   `group_dissolved`, reading `key:<family>`; an undissolved family marks
//!   nothing.
//! - I3912: `check_dissolve_is_terminal_only` holds
//!   `dissolution_not_terminal_only`; a dissolution that changes only
//!   `dissolved_at` passes.
//! - I3913: `RosterAuthority::into_result` holds a shortfall `count_short`;
//!   `Admitted` marks nothing.
//! - I3914: `hold_by_own_rule` holds a typed roster / acceptance refusal
//!   under its own rule token, a dissolution under `group_dissolved`, and
//!   leaves any other error (a storage failure) unmarked.
//! - I3915: `Dep::row_hex(..).unwrap_or(Dep::key(..))` reads an edition-2 row id as `row:<hex>` and
//!   anything else as `key:<id>`; `fold::hold_detail` marks; every GC7
//!   token is registered once, in `reason::gc7`.

use super::edition2::fold::{self, reason, Dep};
use super::edition2::names::RowId;
use super::family_dissolution;
use super::types::Family;
use super::{Error, RosterAuthority};

fn family(dissolved: bool, name: &str) -> Family {
    serde_json::from_value(serde_json::json!({
        "family_key_id": "fam-gc7",
        "family_name": name,
        "members": [],
        "founded_at": "2026-01-01T00:00:00Z",
        "consensus_protocol": "founder_only",
        "dissolved_at": if dissolved { serde_json::json!("2026-06-01T00:00:00Z") } else { serde_json::Value::Null },
        "persist_row_hash": "",
    }))
    .expect("a family record")
}

/// Run `f` as a fold attempt; return its output, the held reason, and the
/// reads.
async fn in_attempt<T>(
    f: impl FnOnce() -> T,
) -> (T, Option<String>, std::collections::BTreeSet<String>) {
    let (out, att) = fold::attempt(RowId([0x7a; 32]), None, async { f() }).await;
    (out, att.held.map(|(r, _)| r), att.reads)
}

#[tokio::test]
async fn i3911_a_dissolved_family_holds_and_reads_the_family() {
    let (out, held, reads) =
        in_attempt(|| family_dissolution::refuse_if_dissolved(&family(true, "f"))).await;
    assert!(
        matches!(out, Err(Error::GroupDissolved { .. })),
        "I3911: {out:?}"
    );
    assert_eq!(held.as_deref(), Some(reason::GROUP_DISSOLVED), "I3911");
    assert!(
        reads.contains(&Dep::key("fam-gc7").read_key()),
        "I3911: the family is a declared input: {reads:?}"
    );
    let (out, held, _) =
        in_attempt(|| family_dissolution::refuse_if_dissolved(&family(false, "f"))).await;
    assert!(out.is_ok() && held.is_none(), "I3911: live family, no mark");
    assert!(!fold::in_attempt());
    assert!(
        matches!(
            family_dissolution::refuse_if_dissolved(&family(true, "f")),
            Err(Error::GroupDissolved { .. })
        ),
        "I3911: outside an attempt, the refusal it was"
    );
}

#[tokio::test]
async fn i3912_a_dissolution_that_changes_more_holds() {
    let stored = family(false, "f");
    let (out, held, _) = in_attempt(|| {
        family_dissolution::check_dissolve_is_terminal_only(&stored, &family(true, "renamed"))
    })
    .await;
    assert!(out.is_err(), "I3912");
    assert_eq!(
        held.as_deref(),
        Some(reason::DISSOLUTION_NOT_TERMINAL_ONLY),
        "I3912"
    );
    let (out, held, _) = in_attempt(|| {
        family_dissolution::check_dissolve_is_terminal_only(&stored, &family(true, "f"))
    })
    .await;
    assert!(out.is_ok() && held.is_none(), "I3912: terminal-only passes");
}

fn roster_refusal(rule: &'static str) -> Error {
    Error::RosterAuthorityUnauthorized {
        group_key_id: "g".into(),
        offered_authority_key_id: "k".into(),
        rule,
        shortfall: None,
    }
}

#[tokio::test]
async fn i3913_a_roster_shortfall_holds_count_short() {
    let (out, held, _) = in_attempt(|| {
        RosterAuthority::ConsensusShort(roster_refusal(super::ROSTER_CONSENSUS_INSUFFICIENT))
            .into_result()
    })
    .await;
    assert!(out.is_err(), "I3913");
    assert_eq!(held.as_deref(), Some(reason::COUNT_SHORT), "I3913");
    let (out, held, _) = in_attempt(|| RosterAuthority::Admitted.into_result()).await;
    assert!(out.is_ok() && held.is_none(), "I3913: admitted, no mark");
}

#[tokio::test]
async fn i3914_typed_refusals_hold_under_their_own_rule() {
    for rule in [
        super::ROSTER_LAST_FOUNDER,
        super::ROSTER_CONSENSUS_UNEVALUABLE,
        super::ROSTER_AUTHORITY_RULE_NOT_ESTABLISHED,
    ] {
        let (_, held, _) = in_attempt(|| super::hold_by_own_rule(roster_refusal(rule))).await;
        assert_eq!(held.as_deref(), Some(rule), "I3914: {rule}");
        assert!(reason::is_registered(rule), "I3914: {rule} is registered");
    }
    let (_, held, _) = in_attempt(|| {
        super::hold_by_own_rule(Error::GroupDissolved {
            group_key_id: "g".into(),
            dissolved_at: chrono::Utc::now(),
        })
    })
    .await;
    assert_eq!(held.as_deref(), Some(reason::GROUP_DISSOLVED), "I3914");
    let (_, held, _) = in_attempt(|| super::hold_by_own_rule(Error::Backend("disk".into()))).await;
    assert_eq!(
        held, None,
        "I3914: a storage failure is not a fold condition"
    );
}

#[tokio::test]
async fn i3915_named_reads_and_the_token_registry() {
    let hex64 = "ab".repeat(32);
    let named = |id: &str| Dep::row_hex(id).unwrap_or_else(|| Dep::key(id));
    assert_eq!(named(&hex64).read_key(), format!("row:{hex64}"), "I3915");
    assert_eq!(
        named("legacy-attestation-1").read_key(),
        "key:legacy-attestation-1",
        "I3915"
    );
    let (_, held, _) = in_attempt(|| fold::hold_detail(reason::BLOB_NOT_HELD, "not held")).await;
    assert_eq!(held.as_deref(), Some(reason::BLOB_NOT_HELD), "I3915");
    // GC7's slice repeats no token, and none shadows a core token.
    let mut seen = std::collections::BTreeSet::new();
    for t in reason::gc7::ALL {
        assert!(seen.insert(*t), "I3915: {t} registered twice in gc7");
        assert!(
            !reason::ALL.contains(t),
            "I3915: {t} duplicates a core token"
        );
    }
    for t in [
        reason::GOAL_AMENDMENT_NOT_DECLARERS,
        reason::AGENT_OCCURRENCE_UNOWNED,
        reason::LINK_UNHELD,
        reason::WRITE_SCOPE_REFUSED,
        reason::BACK_TO_BACK_RENEWAL,
        reason::KEY_RECORD_RIVAL,
        reason::AMENDMENT_ENTRENCHED,
        reason::SUBJECT_ERASURE_UNAUTHORISED,
        reason::WIDENING_NOT_OF_PRIOR,
    ] {
        assert!(reason::is_registered(t), "I3915: {t} registered");
    }
}

/// **I3919** (wave GC7; CC rc21 items 17/18): a rival `key:record` for a held
/// `key_id` is HELD under a fold attempt (reason `key_record_rival`, the key
/// declared as an input), so both are kept and the rival is never the key's
/// (G0 v4: `held_keys_for_kid` skips a held-back statement); a byte-identical
/// record settles with no mark; outside an attempt the rival is the refusal
/// it was.
#[tokio::test]
async fn i3919_a_rival_key_record_is_held_not_refused() {
    use super::key_plane::{OnHeld, PlannedKeyRecord};
    let record = crate::federation::tier_ingest::test_support::replicated_key_record(
        "gc7-rival",
        "agent",
        "gc7-rival",
        "gc7-rival",
        "gc7",
    );
    let key_id = record.key_id.clone();
    let same = record.persist_row_hash.clone();
    let plan = PlannedKeyRecord::Insert {
        record,
        on_held: OnHeld::Conflict,
    };
    let (out, held, reads) = in_attempt(|| plan.insert_held(Some("a-different-record"))).await;
    assert!(out.is_err(), "I3919: still an Err inside the attempt");
    assert_eq!(held.as_deref(), Some(reason::KEY_RECORD_RIVAL), "I3919");
    assert!(
        reads.contains(&Dep::key(&key_id).read_key()),
        "I3919: the key is a declared input: {reads:?}"
    );
    let (out, held, _) = in_attempt(|| plan.insert_held(Some(same.as_str()))).await;
    assert!(
        out.is_ok() && held.is_none(),
        "I3919: an identical record settles"
    );
    assert!(
        plan.insert_held(Some("a-different-record")).is_err(),
        "I3919: outside an attempt, the refusal it was"
    );
}
