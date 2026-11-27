//! v62.0.0 (ROOMKEY-1c; CC 3.2, CC 3.1.3.2) — **`cohort_subkind` and
//! `cohort_subkind_payload` are top-level members of the roster**, as
//! `membership` is (ROOMKEY-1). Before this slice the writer put both under
//! `policy`, where only persist's merging reader found them.
//!
//! - **I7012** (pure):
//!   - a founding of each subkind (`public`, `infrastructure` with its
//!     payload, `geographic`) states the members at the TOP LEVEL;
//!   - `policy` keeps only the rest, and is absent when nothing is left;
//!   - the held record reads back the blob the host gave.
//! - **I7013** (pure) — the door and the fold read one row ONE way: a
//!   geographic founding persist writes with no member's location proof cited
//!   is now refused by the payload door's top-level rule. Before, its subkind
//!   was under `policy` and the door read it as no subkind.
//! - **I7014** (pure) — a version in the EARLIER form (the subkind under
//!   `policy`, as persist wrote it before this slice) still reads its subkind.

#[cfg(test)]
mod pure {
    use chrono::{TimeZone, Utc};
    use ciris_verify_core::cde::Value;

    use super::super::door_invariants::fixture::{iref, key};
    use super::super::group::{
        founding_payload, record_of_roster, roster_view_of_statement, GroupRecord,
        GROUP_ROSTER_PREFIX,
    };
    use super::super::payloads::check;
    use crate::federation::community_subkind;
    use crate::federation::types::{Community, CommunityMember};

    const ROSTER: &str = "group:roster";

    fn at(ms: i64) -> chrono::DateTime<Utc> {
        Utc.timestamp_millis_opt(ms).single().unwrap()
    }

    fn community(policy_blob: serde_json::Value) -> Community {
        Community {
            community_key_id: String::new(),
            community_name: "subkind".into(),
            members: vec![CommunityMember {
                key_id: iref(&key(81)),
                joined_at: at(3_000),
                role: Some("founder".into()),
            }],
            founded_at: at(3_000),
            consensus_protocol: "majority".into(),
            policy_blob: Some(policy_blob),
            prev_head_digest: String::new(),
            charter_digest: String::new(),
            persist_row_hash: String::new(),
        }
    }

    fn sign(sub: &str, p: &Value) -> Vec<u8> {
        let k = key(81);
        ciris_verify_core::edition2::sign_row_statement(
            &k,
            &iref(&k),
            sub,
            "scores",
            &ciris_verify_core::namespace_match::family_id(GROUP_ROSTER_PREFIX),
            p,
            vec![],
        )
        .unwrap()
    }

    fn read_back(gid: &str, p: &Value) -> Community {
        let view = roster_view_of_statement(&sign(gid, p)).expect("a roster view");
        match record_of_roster(&view, String::new()).expect("a record") {
            GroupRecord::Community(c) => c,
            GroupRecord::Family(_) => panic!("a community"),
        }
    }

    fn found(blob: serde_json::Value, nonce: u8) -> (String, Value) {
        let mut rec = GroupRecord::Community(community(blob));
        founding_payload(&mut rec, &[nonce; 32], 9_000).expect("a founding payload")
    }

    /// I7012 — each subkind at the top level; the record reads back.
    #[test]
    fn i7012_the_subkind_members_are_top_level() {
        let infra_payload = serde_json::json!({
            "infrastructure_constraint": { "admission_quorum_basis": "founders" }
        });
        for (n, blob, subkind, rest) in [
            (
                1u8,
                serde_json::json!({"cohort_subkind": "public"}),
                "public",
                false,
            ),
            (
                2,
                serde_json::json!({
                    "cohort_subkind": "infrastructure",
                    "cohort_subkind_payload": infra_payload.clone(),
                }),
                "infrastructure",
                false,
            ),
            (
                3,
                serde_json::json!({
                    "cohort_subkind": "geographic",
                    "geographic_constraint": {"cell_id": "8a2a1072b59ffff", "cell_resolution": 1},
                }),
                "geographic",
                true,
            ),
        ] {
            let (gid, p) = found(blob.clone(), 0x70 + n);
            assert_eq!(
                p.get_text("cohort_subkind").and_then(Value::as_text),
                Some(subkind),
                "I7012 `cohort_subkind` is the top-level member ({subkind})"
            );
            match p.get_text("policy") {
                None => assert!(
                    !rest,
                    "I7012 a policy with more than the subkind is kept ({subkind})"
                ),
                Some(policy) => {
                    assert!(
                        rest,
                        "I7012 no `policy` is written when nothing else is left ({subkind})"
                    );
                    assert!(
                        policy.get_text("cohort_subkind").is_none()
                            && policy.get_text("cohort_subkind_payload").is_none(),
                        "I7012 the subkind members are never members of `policy` ({subkind})"
                    );
                }
            }
            if subkind == "infrastructure" {
                assert!(
                    p.get_text("cohort_subkind_payload")
                        .and_then(Value::as_map)
                        .is_some(),
                    "I7012 `cohort_subkind_payload` is the top-level map"
                );
            }
            let back = read_back(&gid, &p);
            assert_eq!(
                back.policy_blob,
                Some(blob),
                "I7012 the held record reads back the blob the host gave ({subkind})"
            );
            assert_eq!(community_subkind(&back), Some(subkind));
        }
    }

    /// I7013 — the payload door now sees a geographic founding persist wrote.
    #[test]
    fn i7013_the_door_reads_a_geographic_founding_as_the_fold_does() {
        let (_, p) = found(
            serde_json::json!({
                "cohort_subkind": "geographic",
                "geographic_constraint": {"cell_id": "8a2a1072b59ffff", "cell_resolution": 1},
            }),
            0x7a,
        );
        let refused = check(ROSTER, &p)
            .expect_err("I7013 a geographic founding citing no member's proof is refused")
            .to_string();
        assert!(
            refused.contains("location_proof"),
            "I7013 refused by the geographic founding rule, not another: {refused}"
        );
        let (_, plain) = found(serde_json::json!({"cohort_subkind": "public"}), 0x7b);
        assert!(
            check(ROSTER, &plain).is_ok(),
            "I7013 control: a public founding passes"
        );
    }

    /// I7014 — the earlier form (the subkind under `policy`) still reads.
    #[test]
    fn i7014_the_earlier_form_still_reads_its_subkind() {
        let (gid, p) = found(
            serde_json::json!({"cohort_subkind": "infrastructure"}),
            0x7c,
        );
        let Value::Map(mut m) = p else {
            panic!("a map")
        };
        m.retain(|(k, _)| k.as_text() != Some("cohort_subkind"));
        m.push((
            Value::Text("policy".into()),
            Value::Map(vec![(
                Value::Text("cohort_subkind".into()),
                Value::Text("infrastructure".into()),
            )]),
        ));
        m.sort_by_key(|(k, _)| ciris_verify_core::cde::encode(k));
        let earlier = Value::Map(m);
        assert_eq!(
            community_subkind(&read_back(&gid, &earlier)),
            Some("infrastructure"),
            "I7014 a version with the subkind under `policy` reads it"
        );
    }
}
