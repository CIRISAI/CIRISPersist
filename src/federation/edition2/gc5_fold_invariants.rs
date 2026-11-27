//! v62.0.0 (wave GC5; CC 2.7.3) — **the group planes' and the genesis
//! bundle's fold conditions hold, never refuse**, on sqlite and postgres.
//! Every statement goes through the one entry (`ingest::put_statement`, or
//! `genesis::put_genesis_bundle` for a bundle); every typed row is read back
//! through the directory's own readers.
//!
//! - **I3830** the reason tokens GC5 appended sit after G0's seven, in
//!   append order.
//! - **I3831** a later roster version that arrives BEFORE the version its
//!   `refs.head` names is held (`link_unheld`), its
//!   voices kept and nothing concluded; when the named version lands, the
//!   re-fold concludes it. The other arrival order (the head first) ends in
//!   the same concluded set: the same head, the same history.
//! - **I3832** a genesis bundle whose holders' voices arrive one at a time:
//!   the first voice is held (`genesis_bundle_count_unmet`), kept, and not
//!   in force; the voice that meets the count concludes it, and it is the
//!   head. Either voice first gives the same head and the same held voices.
//!
//! - **I3833** (CC27 item 4) a GEOGRAPHIC community's founding version
//!   names each member's `location_proof` under `refs.also.cites`: offered
//!   before the proofs it WAITS (held, `link_unheld`)
//!   and concludes when they land; proofs first, it lands at once (the same
//!   concluded record). A cited proof outside the constraint cell holds it
//!   `geographic_member_unlocated`, never refused.
//!   EXPECTED RED until the Verify 23.3.1 re-pin (lead's ruling): a
//!   `location_proof:v1` row is not admitted at the edition-2 door before it.
//! - **I3834** (CC27 item 3) a `cosign:signature` over a group event from a
//!   key that is no member is KEPT (a voice), never refused, and changes
//!   nothing the group holds.
//!
//! - **I3835** DELETED (LINEAGE charter arm): at pre4 no row carries a
//!   charter. **I6932** replaces it: a geographic version's
//!   `refs.also.cites` holds location proofs AND (on a counted version) the
//!   resignations it names; each reader takes only its own family.
//!
//! No withdrawal leg: G0 v4 makes the group, re-bind and own-store planes
//! FINAL ("a count once met is final", CC 2.7.5), and a genesis bundle is
//! recorded on the final plane too; each gate here reads only the row's
//! NAMED past, so arrival order is the only axis to witness.

use chrono::{TimeZone, Utc};
use ciris_crypto::composite::CompositeSigningKey;

use super::door_invariants::fixture::{iref, key, key_record, map};
use super::fixture_genesis::{
    ceremony_v2, install_ceremony_v2, later_v2, CeremonySpec, HOLDER_SEEDS, SERVE_NODE_SEEDS,
};
use super::fold::{self, reason};
use super::genesis::{genesis_in_force, put_genesis_bundle, GENESIS_BUNDLE_TYP};
use super::group::{
    record_of_roster, roster_payload, roster_payload_citing, roster_view, GroupRecord,
    GROUP_ROSTER_PREFIX,
};
use super::ingest::{put_statement, StatementOutcome, INGEST_TIER};
use super::names::RowId;
use crate::federation::cohort::Cohort;
use crate::federation::types::{Community, CommunityMember, Family, FamilyMember};
use crate::federation::{malformed_row, FederationDirectory};
use ciris_verify_core::cde::Value;

type K = CompositeSigningKey;

/// The genesis fixtures' instant (the same as `fixture_genesis_invariants`).
const T: u64 = 1_780_272_000_000;

/// I3830: GC5's tokens are its own slice (`reason::gc5`, G0 v4.1), in this
/// order, each registered, none a core token; a named row not held waits
/// under the core `link_unheld`.
#[test]
fn i3830_gc5_reason_tokens_are_its_slice() {
    let gc5 = [
        reason::NAMES_ANOTHER_GROUP,
        reason::GROUP_OCCUPIED,
        reason::STALE_SUPERSEDE_PROOF,
        reason::LINEAGE_PREV_HEAD_MISMATCH,
        reason::FAMILY_ENTRENCHED,
        reason::LINEAGE_VERSION_DISAGREES_WITH_FOLD,
        reason::AFFILIATION_COHORT_MISMATCH,
        reason::AFFILIATION_COUNTERSIGN_MISSING,
        reason::COSIGN_SIGNER_NOT_MEMBER,
        reason::COSIGN_OPEN_PENDING_EXISTS,
        reason::COSIGN_SIGNATURE_IRREVOCABLE,
        reason::LOCATION_PROOF_WITHDRAW_MISMATCH,
        reason::LOCATION_PROOF_WITHDRAW_NOT_THE_ATTESTER,
        reason::GEOGRAPHIC_MEMBER_UNLOCATED,
        reason::GENESIS_BUNDLE_COUNT_UNMET,
        reason::GENESIS_BUNDLE_PREV_NOT_VALID,
        reason::GENESIS_BUNDLE_ROW_UNPLACED,
        reason::GENESIS_BUNDLE_ROW_INVALID,
        reason::REBIND_HEAD_NOT_IN_FORCE,
        reason::VERSION_DOES_NOT_FOLLOW,
    ];
    assert_eq!(reason::gc5::ALL, &gc5[..], "I3830: GC5's slice, in order");
    for r in gc5 {
        assert!(reason::is_registered(r), "I3830: {r} is registered");
        assert!(!reason::ALL.contains(&r), "I3830: {r} is not a core token");
    }
    assert!(
        reason::ALL.contains(&reason::LINK_UNHELD),
        "I3830: waiting on a named row is the core's `link_unheld`"
    );
    // The genesis reasons are the door's own tokens (the refusal they
    // replace), spelled once.
    assert_eq!(
        reason::GENESIS_BUNDLE_COUNT_UNMET,
        malformed_row::GENESIS_BUNDLE_COUNT_UNMET,
        "I3830"
    );
    assert_eq!(
        reason::GENESIS_BUNDLE_ROW_INVALID,
        malformed_row::GENESIS_BUNDLE_ROW_INVALID,
        "I3830"
    );
}

// ─────────────────────────────────────────────────────────────────────────
//  I3831 — the group door
// ─────────────────────────────────────────────────────────────────────────

fn at(ms: i64) -> chrono::DateTime<Utc> {
    Utc.timestamp_millis_opt(ms).single().unwrap()
}

fn roster(rec: &GroupRecord, version: u64, head: Option<&RowId>, at_ms: u64, k: &K) -> Vec<u8> {
    use crate::federation::edition2::group_fixtures::{fixture_founding, fixture_record};
    // GID-fixtures-sites — a first version is founded under its DERIVED id
    // (the record's id is the room's NAME); a later one names that id.
    let (group, p) = if version == 1 && head.is_none() {
        fixture_founding(rec, at_ms)
    } else {
        let rec = &fixture_record(rec);
        let group = match rec {
            GroupRecord::Family(f) => f.family_key_id.clone(),
            GroupRecord::Community(c) => c.community_key_id.clone(),
        };
        (group, roster_payload(rec, version, head, at_ms).unwrap())
    };
    ciris_verify_core::edition2::sign_row_statement(
        k,
        &iref(k),
        &group,
        "scores",
        &ciris_verify_core::namespace_match::family_id(GROUP_ROSTER_PREFIX),
        &p,
        vec![],
    )
    .unwrap()
}

fn family(g: &K, name: &str, members: &[&K]) -> GroupRecord {
    GroupRecord::Family(Family {
        family_key_id: iref(g),
        family_name: name.into(),
        members: members
            .iter()
            .map(|k| FamilyMember {
                key_id: iref(k),
                joined_at: at(1_000),
                role: None,
            })
            .collect(),
        founded_at: at(1_000),
        consensus_protocol: "majority".into(),
        consensus_protocol_entrenched: false,
        dissolved_at: None,
        prev_head_digest: String::new(),
        charter_digest: String::new(),
        persist_row_hash: String::new(),
    })
}

async fn why(d: &dyn FederationDirectory, id: &RowId) -> Option<String> {
    fold::why_held(d, id).await.unwrap().map(|h| h.reason)
}

/// One arrival order of a family's version 1 (three voices) and version 2
/// (two of three, a majority). Answers the concluded set: the head's name
/// and the number of versions held.
async fn group_order_body(d: &dyn FederationDirectory, v2_first: bool) -> (String, usize) {
    let (a, b, c, g) = (key(181), key(182), key(183), key(184));
    for k in [&a, &b, &c] {
        put_statement(d, &key_record(k, &["user"], 0, None), None, INGEST_TIER)
            .await
            .unwrap();
    }
    let v1 = family(&g, "fam one", &[&a, &b, &c]);
    // GID-fixtures-sites — the room's DERIVED id, predicted from its first
    // version (the founding below derives exactly it).
    let gid = crate::federation::edition2::group_fixtures::fixture_group_id(&v1);
    let v1_voices: Vec<Vec<u8>> = [&a, &b, &c]
        .iter()
        .map(|k| roster(&v1, 1, None, 2_000, k))
        .collect();
    let v1_id = RowId::of_statement(&v1_voices[0]).unwrap();
    let v2 = family(&g, "fam two", &[&a, &b, &c]);
    let v2_voices: Vec<Vec<u8>> = [&a, &b]
        .iter()
        .map(|k| roster(&v2, 2, Some(&v1_id), 3_000, k))
        .collect();
    let v2_id = RowId::of_statement(&v2_voices[0]).unwrap();

    if v2_first {
        for st in &v2_voices {
            let o = put_statement(d, st, None, INGEST_TIER).await.unwrap();
            assert!(
                matches!(o, StatementOutcome::Pending { .. }),
                "I3831: a version before its head is held, never refused: {o:?}"
            );
        }
        assert_eq!(
            why(d, &v2_id).await.as_deref(),
            Some(reason::LINK_UNHELD),
            "I3831: it waits on the version it names"
        );
        assert_eq!(
            d.edition2_voices(&v2_id).await.unwrap().len(),
            2,
            "I3831: both voices kept"
        );
        assert!(
            d.lookup_family(&gid).await.unwrap().is_none(),
            "I3831: nothing concluded"
        );
        for st in &v1_voices {
            put_statement(d, st, None, INGEST_TIER).await.unwrap();
        }
    } else {
        for st in v1_voices.iter().chain(&v2_voices) {
            put_statement(d, st, None, INGEST_TIER).await.unwrap();
        }
    }
    let head = d
        .lookup_family(&gid)
        .await
        .unwrap()
        .expect("I3831: the family concluded");
    assert_eq!(why(d, &v2_id).await, None, "I3831: version 2 concluded");
    assert_eq!(why(d, &v1_id).await, None, "I3831: version 1 concluded");
    let versions = d.list_group_versions(Cohort::Family, &gid).await.unwrap();
    (head.family_name, versions.len())
}

async fn group_both_orders(early: &dyn FederationDirectory, late: &dyn FederationDirectory) {
    let held_first = Box::pin(group_order_body(early, true)).await;
    let head_first = Box::pin(group_order_body(late, false)).await;
    assert_eq!(
        held_first,
        ("fam two".to_owned(), 2),
        "I3831: held first, it concludes on arrival"
    );
    assert_eq!(
        held_first, head_first,
        "I3831: the concluded set does not depend on arrival order"
    );
}

// ─────────────────────────────────────────────────────────────────────────
//  I3832 — the genesis bundle's count
// ─────────────────────────────────────────────────────────────────────────

/// One arrival order of a later bundle's two voices (a strict majority of
/// three holders). Answers the head and the held voice count.
async fn genesis_order_body(
    d: &dyn FederationDirectory,
    reverse: bool,
) -> (Option<[u8; 32]>, usize) {
    let first = ceremony_v2(&CeremonySpec::at(T));
    install_ceremony_v2(d, &first).await.unwrap();
    let later = later_v2(&first, &HOLDER_SEEDS, &SERVE_NODE_SEEDS, &HOLDER_SEEDS[..2]);
    assert_eq!(later.voices.len(), 2, "I3832: two voices");
    let rows: Vec<Vec<u8>> = later
        .rows_in_put_order()
        .into_iter()
        .map(|r| r.statement.clone())
        .collect();
    let offer = |i: usize| {
        let mut s = rows.clone();
        s.push(later.voices[i].clone());
        s
    };
    let (one, two) = if reverse { (1, 0) } else { (0, 1) };
    let before = d.edition2_objects(GENESIS_BUNDLE_TYP).await.unwrap().len();

    let out = put_genesis_bundle(d, &offer(one), None).await.unwrap();
    assert!(out.placed.is_empty(), "I3832: one voice concludes nothing");
    assert_eq!(
        out.not_placed.first().map(|n| n.token),
        Some(malformed_row::GENESIS_BUNDLE_COUNT_UNMET),
        "I3832: {out:?}"
    );
    assert_eq!(
        why(d, &RowId(later.object_id)).await.as_deref(),
        Some(reason::GENESIS_BUNDLE_COUNT_UNMET),
        "I3832: held, its reason the count"
    );
    assert_eq!(
        d.edition2_objects(GENESIS_BUNDLE_TYP).await.unwrap().len(),
        before + 1,
        "I3832: the voice is kept"
    );
    assert_eq!(
        genesis_in_force(d).await.unwrap().head.map(|h| h.object_id),
        Some(first.object_id),
        "I3832: a held bundle is not in force"
    );

    let out = put_genesis_bundle(d, &offer(two), None).await.unwrap();
    assert_eq!(
        out.placed.iter().map(|p| p.object_id).collect::<Vec<_>>(),
        vec![later.object_id],
        "I3832: the voice that meets the count concludes it"
    );
    assert_eq!(
        why(d, &RowId(later.object_id)).await,
        None,
        "I3832: no longer held"
    );
    (
        genesis_in_force(d).await.unwrap().head.map(|h| h.object_id),
        d.edition2_objects(GENESIS_BUNDLE_TYP).await.unwrap().len(),
    )
}

async fn genesis_both_orders(early: &dyn FederationDirectory, late: &dyn FederationDirectory) {
    let forward = Box::pin(genesis_order_body(early, false)).await;
    let reverse = Box::pin(genesis_order_body(late, true)).await;
    assert_eq!(
        forward, reverse,
        "I3832: the same head and the same held voices, whichever voice came first"
    );
}

// ─────────────────────────────────────────────────────────────────────────
//  I3833 — a geographic version names its members' location proofs
// ─────────────────────────────────────────────────────────────────────────

/// A res-7 cell, its res-1 ancestor (the constraint), and a res-7 cell far
/// outside it.
fn cells() -> (String, String, String) {
    let inside = h3o::LatLng::new(37.0, -122.0)
        .unwrap()
        .to_cell(h3o::Resolution::Seven);
    let constraint = inside.parent(h3o::Resolution::One).unwrap();
    let outside = h3o::LatLng::new(-33.0, 151.0)
        .unwrap()
        .to_cell(h3o::Resolution::Seven);
    (
        inside.to_string(),
        constraint.to_string(),
        outside.to_string(),
    )
}

/// A `location_proof:v1` row: the member's own word on its cell (BELIEVED
/// payload shape; P1 owns the family's table).
fn proof(k: &K, cell: &str, at_ms: u64) -> Vec<u8> {
    let p = map(vec![
        ("asserted_at", Value::Uint(at_ms)),
        ("author", Value::Text(iref(k))),
        ("cell_id", Value::Text(cell.to_owned())),
        ("cell_resolution", Value::Uint(7)),
        ("dimension", Value::Text("location_proof:v1".into())),
    ]);
    ciris_verify_core::edition2::sign_row_statement(
        k,
        &iref(k),
        &iref(k),
        "scores",
        &ciris_verify_core::namespace_match::family_id("location_proof:{version}"),
        &p,
        vec![],
    )
    .unwrap()
}

fn geographic_room(g: &K, constraint: &str, members: &[&K]) -> GroupRecord {
    GroupRecord::Community(Community {
        community_key_id: iref(g),
        community_name: "geo room".into(),
        members: members
            .iter()
            .map(|k| CommunityMember {
                key_id: iref(k),
                joined_at: at(1_000),
                role: None,
            })
            .collect(),
        founded_at: at(1_000),
        consensus_protocol: "majority".into(),
        policy_blob: Some(serde_json::json!({
            "cohort_subkind": "geographic",
            "geographic_constraint": { "cell_id": constraint, "cell_resolution": 1 },
        })),
        prev_head_digest: String::new(),
        charter_digest: String::new(),
        persist_row_hash: String::new(),
    })
}

fn citing(rec: &GroupRecord, proofs: &[RowId], k: &K) -> Vec<u8> {
    let GroupRecord::Community(_) = rec else {
        unreachable!("a community")
    };
    // GID-fixtures-sites — a first version citing its proofs, founded under
    // its DERIVED id.
    let (gid, p) =
        crate::federation::edition2::group_fixtures::fixture_founding_citing(rec, proofs, 2_000);
    ciris_verify_core::edition2::sign_row_statement(
        k,
        &iref(k),
        &gid,
        "scores",
        &ciris_verify_core::namespace_match::family_id(GROUP_ROSTER_PREFIX),
        &p,
        vec![],
    )
    .unwrap()
}

/// One arrival order: the founding's two voices before (`proofs_first =
/// false`) or after the two proofs. Answers the concluded record's hash.
async fn geographic_order_body(d: &dyn FederationDirectory, proofs_first: bool) -> String {
    let (a, b, g) = (key(191), key(192), key(193));
    for k in [&a, &b] {
        put_statement(d, &key_record(k, &["user"], 0, None), None, INGEST_TIER)
            .await
            .unwrap();
    }
    let (inside, constraint, _) = cells();
    let proofs = [proof(&a, &inside, 1_500), proof(&b, &inside, 1_500)];
    let ids: Vec<RowId> = proofs
        .iter()
        .map(|p| RowId::of_statement(p).unwrap())
        .collect();
    let room = geographic_room(&g, &constraint, &[&a, &b]);
    let voices = [citing(&room, &ids, &a), citing(&room, &ids, &b)];
    let room_id = RowId::of_statement(&voices[0]).unwrap();
    let gid = crate::federation::edition2::fixture_switch::room_id(&iref(&g)); // GID-fixtures-sites: founded above
    if proofs_first {
        for p in &proofs {
            put_statement(d, p, None, INGEST_TIER).await.unwrap();
        }
        for v in &voices {
            put_statement(d, v, None, INGEST_TIER).await.unwrap();
        }
    } else {
        for v in &voices {
            let o = put_statement(d, v, None, INGEST_TIER).await.unwrap();
            assert!(
                matches!(o, StatementOutcome::Pending { .. }),
                "I3833: before its proofs the version waits: {o:?}"
            );
        }
        assert_eq!(
            why(d, &room_id).await.as_deref(),
            Some(reason::LINK_UNHELD),
            "I3833: it waits on a named proof"
        );
        assert!(
            d.lookup_community(&gid).await.unwrap().is_none(),
            "I3833: nothing concluded"
        );
        for p in &proofs {
            put_statement(d, p, None, INGEST_TIER).await.unwrap();
        }
    }
    assert_eq!(why(d, &room_id).await, None, "I3833: concluded");
    d.lookup_community(&gid)
        .await
        .unwrap()
        .expect("I3833: the room concluded")
        .persist_row_hash
}

/// A cited proof outside the constraint holds the version.
async fn geographic_outside_body(d: &dyn FederationDirectory) {
    let (a, b, g) = (key(194), key(195), key(196));
    for k in [&a, &b] {
        put_statement(d, &key_record(k, &["user"], 0, None), None, INGEST_TIER)
            .await
            .unwrap();
    }
    let (inside, constraint, outside) = cells();
    let proofs = [proof(&a, &inside, 1_500), proof(&b, &outside, 1_500)];
    for p in &proofs {
        put_statement(d, p, None, INGEST_TIER).await.unwrap();
    }
    let ids: Vec<RowId> = proofs
        .iter()
        .map(|p| RowId::of_statement(p).unwrap())
        .collect();
    let room = geographic_room(&g, &constraint, &[&a, &b]);
    let mut last = None;
    for k in [&a, &b] {
        let v = citing(&room, &ids, k);
        let o = put_statement(d, &v, None, INGEST_TIER).await.unwrap();
        assert!(
            matches!(o, StatementOutcome::Pending { .. }),
            "I3833: held, never refused: {o:?}"
        );
        last = Some(RowId::of_statement(&v).unwrap());
    }
    assert_eq!(
        why(d, &last.unwrap()).await.as_deref(),
        Some(reason::GEOGRAPHIC_MEMBER_UNLOCATED),
        "I3833: a member outside the constraint"
    );
    assert!(
        // GID-fixtures-sites — asked under the DERIVED id (the raw name
        // would answer `None` whatever concluded).
        d.lookup_community(&crate::federation::edition2::fixture_switch::room_id(
            &iref(&g)
        ))
        .await
        .unwrap()
        .is_none(),
        "I3833: concludes nothing"
    );
}

async fn geographic_both_orders(early: &dyn FederationDirectory, late: &dyn FederationDirectory) {
    let waited = Box::pin(geographic_order_body(early, false)).await;
    let direct = Box::pin(geographic_order_body(late, true)).await;
    assert_eq!(
        waited, direct,
        "I3833: the same concluded record, whichever arrived first"
    );
    Box::pin(geographic_outside_body(late)).await;
}

/// **I6932, the pure half (LINEAGE charter arm; CC 3.3.4, pre4 part 3
/// "each new member's location_proof stands in the version's refs.also
/// under cites").** A geographic founding citing two proofs and one other
/// row (a resignation's id) of three members: the payload door's
/// "cited >= listed" counts every cited row, so the extra row SATISFIES it
/// (it can never break it: more cites only raise the count); the fold then
/// reads each cited row by family and finds a member unlocated (I3833's
/// rule). The record reads no charter from the cites.
#[test]
fn i6932_cites_hold_proofs_and_resignations_pure() {
    let (a, b, c, g) = (key(221), key(222), key(223), key(224));
    let (_, constraint, _) = cells();
    let proofs = [RowId([0x61; 32]), RowId([0x62; 32])];
    let end = RowId([0xe1; 32]);
    let room = geographic_room(&g, &constraint, &[&a, &b, &c]);
    let p = super::head_rule::with_cites(
        roster_payload_citing(&room, 1, None, &proofs, 2_000).unwrap(),
        &[end],
    )
    .unwrap();
    let view = roster_view(&iref(&g), &p).unwrap();
    let cited = view.names.iter().filter(|n| n.role == "also:cites").count();
    assert_eq!(cited, 3, "I6932: two proofs and one resignation, one set");
    assert!(
        super::payloads::check(
            &ciris_verify_core::namespace_match::family_id(GROUP_ROSTER_PREFIX),
            &p
        )
        .is_ok(),
        "I6932: cited (3) >= listed (3): satisfied by the extra row, never broken by it"
    );
    let digest = match record_of_roster(&view, String::new()).unwrap() {
        GroupRecord::Community(c) => c.charter_digest,
        GroupRecord::Family(f) => f.charter_digest,
    };
    assert_eq!(digest, "", "I6932: no cited row reads as a charter");
}

/// **I6932, the door half.** A `unanimous` geographic room of a, b, c,
/// founded citing their three proofs; c RESIGNS. Version 2 lists a and b and
/// cites a's and b's proofs AND c's resignation: the proof rule reads only
/// the proofs (no new member: nothing to locate) and the count reads only the
/// end (less c): a's and b's voices LAND it. The same version without the
/// resignation is counted over a, b, c: short. Inherits I3833's expected red
/// until a `location_proof:v1` row is admitted at the door (the Verify pin).
async fn cites_hold_proofs_and_resignations_body(d: &dyn FederationDirectory) {
    use crate::federation::edition2::group::{resignation_draft, MembershipRecord};
    use crate::federation::types::{CommunityMembershipRevocation, RevocationLeaf};
    let (a, b, c, g) = (key(231), key(232), key(233), key(234));
    for k in [&a, &b, &c] {
        put_statement(d, &key_record(k, &["user"], 0, None), None, INGEST_TIER)
            .await
            .unwrap();
    }
    let (inside, constraint, _) = cells();
    let proofs = [
        proof(&a, &inside, 1_500),
        proof(&b, &inside, 1_500),
        proof(&c, &inside, 1_500),
    ];
    let ids: Vec<RowId> = proofs
        .iter()
        .map(|p| RowId::of_statement(p).unwrap())
        .collect();
    for p in &proofs {
        put_statement(d, p, None, INGEST_TIER).await.unwrap();
    }
    let mut room = geographic_room(&g, &constraint, &[&a, &b, &c]);
    if let GroupRecord::Community(r) = &mut room {
        r.consensus_protocol = "unanimous".into();
    }
    let founding = [
        citing(&room, &ids, &a),
        citing(&room, &ids, &b),
        citing(&room, &ids, &c),
    ];
    let v1 = RowId::of_statement(&founding[0]).unwrap();
    for v in &founding {
        put_statement(d, v, None, INGEST_TIER).await.unwrap();
    }
    let gid = crate::federation::edition2::fixture_switch::room_id(&iref(&g));
    assert!(
        d.lookup_community(&gid).await.unwrap().is_some(),
        "I6932 premise: the room concluded"
    );
    let now_ms = u64::try_from(Utc::now().timestamp_millis()).unwrap();
    let resign = MembershipRecord::CommunityRemoval(CommunityMembershipRevocation {
        community_key_id: gid.clone(),
        removed_identity_key_id: iref(&c),
        removed_at: at(i64::try_from(now_ms).unwrap() - 60_000),
        effective_at: at(i64::try_from(now_ms).unwrap() - 60_000),
        reason: None,
        witness_set: vec![],
        persist_row_hash: String::new(),
        leaf: RevocationLeaf::Resignation,
    });
    let draft = resignation_draft(
        &resign,
        &v1,
        &[],
        &iref(&c),
        &ciris_verify_core::edition2::thumbprint(c.public_key()),
    )
    .unwrap();
    let st = draft.assemble(c.sign(&draft.sig_structure).unwrap());
    let end = RowId::of_statement(&st).unwrap();
    let o = put_statement(d, &st, None, INGEST_TIER).await.unwrap();
    assert!(
        matches!(o, StatementOutcome::Row { .. }),
        "I6932 premise: c resigns: {o:?}"
    );
    let mut v2_rec = crate::federation::edition2::group_fixtures::fixture_record(&room);
    if let GroupRecord::Community(r) = &mut v2_rec {
        r.members.retain(|m| m.key_id != iref(&c));
    }
    let version = |cite_end: bool, at_ms: u64| {
        let p = roster_payload_citing(&v2_rec, 2, Some(&v1), &ids[..2], at_ms).unwrap();
        let p = if cite_end {
            super::head_rule::with_cites(p, &[end]).unwrap()
        } else {
            p
        };
        [&a, &b]
            .iter()
            .map(|k| {
                ciris_verify_core::edition2::sign_row_statement(
                    k,
                    &iref(k),
                    &gid,
                    "scores",
                    &ciris_verify_core::namespace_match::family_id(GROUP_ROSTER_PREFIX),
                    &p,
                    vec![],
                )
                .unwrap()
            })
            .collect::<Vec<_>>()
    };
    let mut last = None;
    for v in version(false, now_ms - 30_000) {
        last = Some(put_statement(d, &v, None, INGEST_TIER).await.unwrap());
    }
    assert!(
        matches!(last, Some(StatementOutcome::Pending { .. })),
        "I6932: not citing the resignation, c is counted under unanimous: short: {last:?}"
    );
    let mut last = None;
    for v in version(true, now_ms - 20_000) {
        last = Some(put_statement(d, &v, None, INGEST_TIER).await.unwrap());
    }
    assert!(
        matches!(last, Some(StatementOutcome::Row { .. })),
        "I6932: citing two proofs and the resignation, a and b are every counted member: {last:?}"
    );
}

// v62.0.0 (LINEAGE charter arm) — I3835 (a geographic charter told apart
// at the chain head) is DELETED: it witnessed the earlier model, where a
// roster version cited its charter (pre4: "charter_digest names nothing in
// this form: no row carries a charter"). What covers the property now: a
// cited row is read by its FAMILY on each side (location proofs by
// `check_named_location_proofs`, resignations by the lineage), I6932.

// ─────────────────────────────────────────────────────────────────────────
//  I3834 — a non-member's cosign is kept
// ─────────────────────────────────────────────────────────────────────────

async fn cosign_non_member_body(d: &dyn FederationDirectory) {
    let (a, b, c, x, g) = (key(201), key(202), key(203), key(204), key(205));
    for k in [&a, &b, &c, &x] {
        put_statement(d, &key_record(k, &["user"], 0, None), None, INGEST_TIER)
            .await
            .unwrap();
    }
    let v1 = family(&g, "fam", &[&a, &b, &c]);
    let mut event = None;
    // GID-fixtures-sites — the room's DERIVED id, predicted from its first
    // version (the founding below derives exactly it).
    let gid = crate::federation::edition2::group_fixtures::fixture_group_id(&v1);
    for k in [&a, &b, &c] {
        let st = roster(&v1, 1, None, 2_000, k);
        put_statement(d, &st, None, INGEST_TIER).await.unwrap();
        event = RowId::of_statement(&st);
    }
    let event = event.unwrap();
    let before = d
        .lookup_family(&gid)
        .await
        .unwrap()
        .expect("I3834: founded");
    let p = super::typed::cosign_payload(&iref(&x), "signature", &event, 3_000);
    let st = ciris_verify_core::edition2::sign_row_statement(
        &x,
        &iref(&x),
        &gid,
        "scores",
        &ciris_verify_core::namespace_match::family_id(super::typed::COSIGN_PREFIX),
        &p,
        vec![],
    )
    .unwrap();
    let o = put_statement(d, &st, None, INGEST_TIER)
        .await
        .expect("I3834: a non-member's cosign is never refused");
    assert!(
        matches!(
            o,
            StatementOutcome::Voice { new: true, .. } | StatementOutcome::Pending { new: true, .. }
        ),
        "I3834: kept: {o:?}"
    );
    assert!(
        !d.edition2_voices(&RowId::of_statement(&st).unwrap())
            .await
            .unwrap()
            .is_empty(),
        "I3834: in ceg_statements"
    );
    assert_eq!(
        d.lookup_family(&gid)
            .await
            .unwrap()
            .unwrap()
            .persist_row_hash,
        before.persist_row_hash,
        "I3834: it changes nothing the group holds"
    );
}

// ─────────────────────────────────────────────────────────────────────────
//  Runners
// ─────────────────────────────────────────────────────────────────────────

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
    let dsn = crate::test_pg::isolated_dsn()?;
    let b = crate::store::postgres::PostgresBackend::connect(&dsn)
        .await
        .unwrap();
    b.run_migrations().await.unwrap();
    Some(b)
}

#[cfg(feature = "sqlite")]
#[tokio::test]
async fn i3831_group_version_held_then_concluded_sqlite() {
    let (early, late) = (sqlite().await, sqlite().await);
    Box::pin(group_both_orders(&early, &late)).await;
}

#[cfg(feature = "postgres")]
#[tokio::test]
async fn i3831_group_version_held_then_concluded_postgres() {
    let (Some(early), Some(late)) = (postgres().await, postgres().await) else {
        return;
    };
    Box::pin(group_both_orders(&early, &late)).await;
}

#[cfg(feature = "sqlite")]
#[tokio::test]
async fn i3832_genesis_count_held_then_concluded_sqlite() {
    let (early, late) = (sqlite().await, sqlite().await);
    Box::pin(genesis_both_orders(&early, &late)).await;
}

#[cfg(feature = "postgres")]
#[tokio::test]
async fn i3832_genesis_count_held_then_concluded_postgres() {
    let (Some(early), Some(late)) = (postgres().await, postgres().await) else {
        return;
    };
    Box::pin(genesis_both_orders(&early, &late)).await;
}

#[cfg(feature = "sqlite")]
#[tokio::test]
async fn i6932_cites_hold_proofs_and_resignations_sqlite() {
    Box::pin(cites_hold_proofs_and_resignations_body(&sqlite().await)).await;
}

#[cfg(feature = "postgres")]
#[tokio::test]
async fn i6932_cites_hold_proofs_and_resignations_postgres() {
    let Some(d) = postgres().await else { return };
    Box::pin(cites_hold_proofs_and_resignations_body(&d)).await;
}

#[cfg(feature = "sqlite")]
#[tokio::test]
async fn i3833_geographic_version_names_its_proofs_sqlite() {
    let (early, late) = (sqlite().await, sqlite().await);
    Box::pin(geographic_both_orders(&early, &late)).await;
}

#[cfg(feature = "postgres")]
#[tokio::test]
async fn i3833_geographic_version_names_its_proofs_postgres() {
    let (Some(early), Some(late)) = (postgres().await, postgres().await) else {
        return;
    };
    Box::pin(geographic_both_orders(&early, &late)).await;
}

#[cfg(feature = "sqlite")]
#[tokio::test]
async fn i3834_non_member_cosign_kept_sqlite() {
    Box::pin(cosign_non_member_body(&sqlite().await)).await;
}

#[cfg(feature = "postgres")]
#[tokio::test]
async fn i3834_non_member_cosign_kept_postgres() {
    let Some(b) = postgres().await else {
        return;
    };
    Box::pin(cosign_non_member_body(&b)).await;
}

/// **I2187 (v62.0.0, PX-fix1) — a genesis bundle held SHORT of its count is
/// not read as concluded THROUGH the capsule proxy.** I3832's first leg,
/// written on the backend and read through the proxy (backend ← capsule
/// dispatch ← `OpsDirectory`): one holder's voice over a later bundle is held
/// `genesis_bundle_count_unmet`, the proxy reads it held, and
/// `genesis_in_force` over the proxy keeps the FIRST bundle as head — the same
/// reading as over the backend. Before PX-fix1, routing `edition2_objects`
/// alone (with `fold_held` still the `None` default) would have read the
/// short voice as concluded. The voice that meets the count moves the head
/// through the proxy too.
async fn held_short_through_proxy_body(dir: std::sync::Arc<dyn FederationDirectory>) {
    let proxy = crate::ffi::directory_capsule::test_proxy(dir.clone());
    let (d, p) = (dir.as_ref(), proxy.as_ref());
    let first = ceremony_v2(&CeremonySpec::at(T));
    install_ceremony_v2(d, &first).await.unwrap();
    let later = later_v2(&first, &HOLDER_SEEDS, &SERVE_NODE_SEEDS, &HOLDER_SEEDS[..2]);
    assert_eq!(later.voices.len(), 2, "I2187: two voices");
    let rows: Vec<Vec<u8>> = later
        .rows_in_put_order()
        .into_iter()
        .map(|r| r.statement.clone())
        .collect();
    let offer = |i: usize| {
        let mut s = rows.clone();
        s.push(later.voices[i].clone());
        s
    };

    let out = put_genesis_bundle(d, &offer(0), None).await.unwrap();
    assert!(out.placed.is_empty(), "I2187: one voice concludes nothing");
    let held = p
        .fold_held(&RowId(later.object_id))
        .await
        .unwrap()
        .map(|h| h.reason);
    assert_eq!(
        held.as_deref(),
        Some(reason::GENESIS_BUNDLE_COUNT_UNMET),
        "I2187: the proxy reads the short bundle held"
    );
    let direct = genesis_in_force(d).await.unwrap();
    let via = genesis_in_force(p).await.unwrap();
    assert_eq!(
        via.head.as_ref().map(|h| h.object_id),
        Some(first.object_id),
        "I2187: through the proxy the held-short bundle is NOT in force"
    );
    assert!(
        !via.valid.iter().any(|v| v.object_id == later.object_id),
        "I2187: nor among the valid bundles through the proxy"
    );
    assert_eq!(
        format!("{:?}", via.valid),
        format!("{:?}", direct.valid),
        "I2187: the proxy reads the backend's lineage"
    );
    assert_eq!(via.statements, direct.statements, "I2187: served lineage");

    let out = put_genesis_bundle(d, &offer(1), None).await.unwrap();
    assert_eq!(
        out.placed.iter().map(|x| x.object_id).collect::<Vec<_>>(),
        vec![later.object_id],
        "I2187: the voice that meets the count concludes it"
    );
    assert_eq!(
        genesis_in_force(p).await.unwrap().head.map(|h| h.object_id),
        Some(later.object_id),
        "I2187: concluded, it is the head through the proxy"
    );
}

#[cfg(feature = "sqlite")]
#[tokio::test]
async fn i2187_held_short_bundle_not_in_force_through_the_proxy_sqlite() {
    Box::pin(held_short_through_proxy_body(std::sync::Arc::new(
        sqlite().await,
    )))
    .await;
}

#[cfg(feature = "postgres")]
#[tokio::test]
async fn i2187_held_short_bundle_not_in_force_through_the_proxy_postgres() {
    let Some(b) = postgres().await else {
        return;
    };
    Box::pin(held_short_through_proxy_body(std::sync::Arc::new(b))).await;
}
