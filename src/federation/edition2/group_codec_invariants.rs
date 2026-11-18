//! v62.0.0 (wave T1) — the group planes' codec, without a store.
//!
//! - **I2990**: a typed group record (family, community with a policy blob)
//!   written as its `group:roster` payload and signed reads back as the same
//!   record (`roster_payload` ∘ `record_of_roster` is the identity, the
//!   charter included), and every voice of the version shares one row id.
//! - **I2991**: each typed membership record (family / community × removal /
//!   widening) written as its counted `membership:{stage}` payload reads back
//!   as itself, naming the roster version by `refs.head`.
//! - **I2992**: `group_plane_of` names the plane of `group:roster` and of the
//!   two counted membership leaves only: an authored membership stage and a
//!   composer of a roster are not a group plane.

use chrono::{TimeZone, Utc};
use ciris_verify_core::cde::Value;

use super::door_invariants::fixture::*;
use super::group::{
    group_plane_of, membership_of, membership_payload, record_of_roster, roster_payload,
    roster_view_of_statement, GroupPlane, GroupRecord, MembershipRecord, GROUP_ROSTER_PREFIX,
    MEMBERSHIP_PREFIX,
};
use super::liveness::statement_parts;
use super::names::RowId;
use crate::federation::types::{
    Community, CommunityMember, CommunityMembershipRevocation, CommunityMembershipWidening, Family,
    FamilyMember, FamilyMembershipRevocation, FamilyMembershipWidening,
};

fn at(ms: i64) -> chrono::DateTime<Utc> {
    Utc.timestamp_millis_opt(ms).single().unwrap()
}

fn sign(
    k: &ciris_crypto::composite::CompositeSigningKey,
    sub: &str,
    prefix: &str,
    p: &Value,
) -> Vec<u8> {
    ciris_verify_core::edition2::sign_row_statement(
        k,
        &iref(k),
        sub,
        "scores",
        &ciris_verify_core::namespace_match::family_id(prefix),
        p,
        vec![],
    )
    .unwrap()
}

fn family() -> Family {
    Family {
        family_key_id: iref(&key(90)),
        family_name: "codec family".into(),
        members: vec![
            FamilyMember {
                key_id: iref(&key(91)),
                joined_at: at(1_000),
                role: Some("founder".into()),
            },
            FamilyMember {
                key_id: iref(&key(92)),
                joined_at: at(1_500),
                role: None,
            },
        ],
        founded_at: at(1_000),
        consensus_protocol: "majority".into(),
        consensus_protocol_entrenched: true,
        dissolved_at: None,
        prev_head_digest: String::new(),
        charter_digest: hex::encode([0x42; 32]),
        persist_row_hash: String::new(),
    }
}

fn community() -> Community {
    Community {
        community_key_id: iref(&key(93)),
        community_name: "codec community".into(),
        members: vec![CommunityMember {
            key_id: iref(&key(91)),
            joined_at: at(2_000),
            role: Some("founder".into()),
        }],
        founded_at: at(2_000),
        consensus_protocol: "quorum:1/1".into(),
        policy_blob: Some(serde_json::json!({"cohort_scope": "community", "max": 12})),
        prev_head_digest: String::new(),
        charter_digest: String::new(),
        persist_row_hash: String::new(),
    }
}

/// I2990 — a roster round trip, for both kinds, with and without a head.
#[test]
fn i2990_roster_payload_reads_back_as_its_record() {
    let head = RowId([0x31; 32]);
    for (record, version, head) in [
        (GroupRecord::Family(family()), 1, None),
        (GroupRecord::Family(family()), 2, Some(&head)),
        (GroupRecord::Community(community()), 1, None),
    ] {
        let p = roster_payload(&record, version, head, 9_000).unwrap();
        let group = match &record {
            GroupRecord::Family(f) => f.family_key_id.clone(),
            GroupRecord::Community(c) => c.community_key_id.clone(),
        };
        let st = sign(&key(91), &group, GROUP_ROSTER_PREFIX, &p);
        let view = roster_view_of_statement(&st).unwrap();
        assert_eq!(view.version, version, "I2990 version");
        assert_eq!(view.head, head.copied(), "I2990 refs.head");
        let back = record_of_roster(&view, String::new()).unwrap();
        // A roster's members are a set, in each element's encoding order: a
        // member without a role (a 2-entry map) before one with a role (3
        // entries), then by `key` (identity-refs are of one length, so their
        // encodings sort as the text does).
        let mut expected = record.clone();
        match &mut expected {
            GroupRecord::Family(f) => f
                .members
                .sort_by(|a, b| (a.role.is_some(), &a.key_id).cmp(&(b.role.is_some(), &b.key_id))),
            GroupRecord::Community(c) => c
                .members
                .sort_by(|a, b| (a.role.is_some(), &a.key_id).cmp(&(b.role.is_some(), &b.key_id))),
        }
        assert_eq!(back, expected, "I2990 the record reads back");
        // Every voice of the version is a voice of ONE row.
        let other = sign(&key(92), &group, GROUP_ROSTER_PREFIX, &p);
        assert_eq!(
            RowId::of_statement(&st),
            RowId::of_statement(&other),
            "I2990 one row id per version"
        );
        assert_ne!(st, other, "I2990 two voices");
        let (_, payload) = statement_parts(&st).unwrap();
        assert_eq!(
            group_plane_of(
                "scores",
                &ciris_verify_core::namespace_match::family_id(GROUP_ROSTER_PREFIX),
                &payload
            ),
            Some(GroupPlane::Roster),
            "I2990 plane"
        );
    }
}

/// I2991 — each counted membership record round-trips.
#[test]
fn i2991_membership_payload_reads_back_as_its_record() {
    let head = RowId([0x32; 32]);
    let g = iref(&key(90));
    let m = iref(&key(92));
    let records = [
        MembershipRecord::FamilyRemoval(FamilyMembershipRevocation {
            family_key_id: g.clone(),
            removed_identity_key_id: m.clone(),
            removed_at: at(5_000),
            effective_at: at(5_000),
            reason: Some("3".into()),
            witness_set: vec![iref(&key(91))],
            persist_row_hash: String::new(),
        }),
        MembershipRecord::CommunityRemoval(CommunityMembershipRevocation {
            community_key_id: g.clone(),
            removed_identity_key_id: m.clone(),
            removed_at: at(5_000),
            effective_at: at(6_000),
            reason: None,
            witness_set: vec![],
            persist_row_hash: String::new(),
        }),
        MembershipRecord::FamilyWidening(FamilyMembershipWidening {
            family_key_id: g.clone(),
            member_key_id: m.clone(),
            joined_at: at(7_000),
            effective_at: at(7_000),
            role: Some("member".into()),
            persist_row_hash: String::new(),
        }),
        MembershipRecord::CommunityWidening(CommunityMembershipWidening {
            community_key_id: g.clone(),
            member_key_id: m.clone(),
            joined_at: at(7_000),
            effective_at: at(8_000),
            role: None,
            persist_row_hash: String::new(),
        }),
    ];
    for record in records {
        let plane = match record {
            MembershipRecord::FamilyRemoval(_) | MembershipRecord::CommunityRemoval(_) => {
                GroupPlane::Removal
            }
            _ => GroupPlane::Widening,
        };
        let p = membership_payload(&record, Some(&head)).unwrap();
        let st = sign(&key(91), &m, MEMBERSHIP_PREFIX, &p);
        let (_, payload) = statement_parts(&st).unwrap();
        assert_eq!(
            group_plane_of(
                "scores",
                &ciris_verify_core::namespace_match::family_id(MEMBERSHIP_PREFIX),
                &payload
            ),
            Some(plane),
            "I2991 plane"
        );
        let (view, back) = membership_of(plane, &m, &payload).unwrap();
        assert_eq!(back, record, "I2991 the record reads back");
        assert_eq!(view.head, Some(head), "I2991 refs.head");
        assert_eq!(view.group, g, "I2991 group");
    }
}

/// I2992 — only the roster and the two counted leaves are group planes.
#[test]
fn i2992_only_the_counted_planes_are_group_planes() {
    let membership = ciris_verify_core::namespace_match::family_id(MEMBERSHIP_PREFIX);
    let roster = ciris_verify_core::namespace_match::family_id(GROUP_ROSTER_PREFIX);
    let dim = |d: &str| map(vec![("dimension", Value::Text(d.into()))]);
    assert_eq!(
        group_plane_of("scores", &membership, &dim("membership:proposal:v1")),
        None,
        "I2992 an authored stage is the attestation plane's"
    );
    assert_eq!(
        group_plane_of("scores", &membership, &map(vec![])),
        None,
        "I2992 no dimension binds no leaf"
    );
    for composer in ["withdraws", "recants", "supersedes"] {
        assert_eq!(
            group_plane_of(composer, &roster, &map(vec![])),
            None,
            "I2992 a composer of a roster is not the roster's plane"
        );
    }
    assert_eq!(
        group_plane_of("scores", "key:record", &map(vec![])),
        None,
        "I2992 another family"
    );
}
