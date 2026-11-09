//! v61.1.0 (CIRISPersist#1188) — **I1621, I1622: the pure survivors of the
//! v61.0.0 mutation run.** Each kills a named survivor of #1188; the door
//! witnesses for the rest live beside the helpers they share (I1620
//! `group_plane_invariants`, I1623 `affiliation_floor_invariants`, I1624
//! `open_admission_invariants`, I1625 `put_audience_invariants`, I1626
//! `transport_routes_invariants`). Pure: no backend.
//!
//! - **I1621** (CC 4.4.3.4.2, CIRISPersist#1123) — the `consensus_protocol`
//!   vocabulary, by truth table. `founders_hold_authority` is true for
//!   `founder_only` and `open:self_admit` and false for every other form;
//!   `is_canonical_form` refuses `quorum:0/0` (n > 0), `quorum:3/2` (m <= n
//!   and n > 0 both hold), an empty `custom:` or `weighted:` tail, an
//!   unprefixed name and the empty string, and admits each canonical form.
//! - **I1622** (CC 3.2 T6, CIRISPersist#910.5) — the supersede's verdict
//!   against the held head (`group_supersede_admit::held_head_verdict`)
//!   reads the offered head's proof and names the group it refuses: a proof
//!   naming another prior is a stale proof even when `prev_head_digest`
//!   names the held head; an unheld group, a stale proof and a lineage
//!   mismatch each name the group's key; a head naming the held version (by
//!   proof and by `prev_head_digest`) passes.

#[cfg(test)]
mod pure {
    use crate::federation::group_supersede_admit::{
        held_head_verdict, PlannedHead, PlannedSupersede,
    };
    use crate::federation::types::consensus_protocol as cp;
    use crate::federation::types::{
        Community, Family, GroupSupersedeProof, SignedCommunity, SignedFamily,
    };

    /// I1621 — who holds a group's authority, by protocol.
    #[test]
    fn i1621_founders_hold_authority_by_protocol() {
        for p in [cp::FOUNDER_ONLY, cp::OPEN_SELF_ADMIT] {
            assert!(
                cp::founders_hold_authority(p),
                "I1621: under {p} the founders alone hold the group's authority"
            );
        }
        for p in [
            cp::UNANIMOUS,
            cp::MAJORITY,
            "quorum:2/3",
            "reverse_quorum:2/3:86400",
            "weighted:uniform_half",
            "custom:board",
            "",
        ] {
            assert!(
                !cp::founders_hold_authority(p),
                "I1621: under {p:?} authority is the protocol's, not the founders'"
            );
        }
    }

    /// I1621 — the canonical forms, and the near-misses each clause refuses.
    #[test]
    fn i1621_is_canonical_form_by_truth_table() {
        for good in [
            cp::FOUNDER_ONLY,
            cp::UNANIMOUS,
            cp::MAJORITY,
            cp::OPEN_SELF_ADMIT,
            "quorum:0/1",
            "quorum:2/3",
            "quorum:3/3",
            "weighted:uniform_half",
            "custom:board",
            "reverse_quorum:2/3:86400",
        ] {
            assert!(cp::is_canonical_form(good), "I1621: {good:?} is canonical");
        }
        for (bad, why) in [
            ("quorum:0/0", "n > 0: a 0-of-0 quorum is meaningless"),
            ("quorum:3/2", "m <= n"),
            ("quorum:4/0", "n > 0 and m <= n"),
            ("quorum:2", "the tail is {m}/{n}"),
            ("quorum:a/3", "m parses"),
            ("custom:", "a custom form names its id"),
            ("weighted:", "a weighted form names its rubric"),
            ("board", "an unprefixed name not in the bare set"),
            ("", "the empty string"),
        ] {
            assert!(
                !cp::is_canonical_form(bad),
                "I1621: {bad:?} is not canonical ({why})"
            );
        }
    }

    fn at() -> chrono::DateTime<chrono::Utc> {
        "2026-01-01T00:00:00Z".parse().expect("rfc3339")
    }

    fn proof(prior: &str) -> GroupSupersedeProof {
        GroupSupersedeProof {
            prior_persist_row_hash: prior.to_owned(),
            change_envelope: serde_json::json!({}),
            quorum_signatures: Vec::new(),
        }
    }

    /// A community head under `key`, naming `prev`, carrying `proof`.
    fn community(key: &str, prev: &str, proof: Option<GroupSupersedeProof>) -> PlannedSupersede {
        PlannedSupersede {
            cohort_str: "community",
            head: PlannedHead::Community(SignedCommunity {
                community: Community {
                    prev_head_digest: prev.to_owned(),
                    charter_digest: String::new(),
                    community_key_id: key.to_owned(),
                    community_name: "I1622".into(),
                    members: Vec::new(),
                    founded_at: at(),
                    consensus_protocol: cp::MAJORITY.to_owned(),
                    policy_blob: None,
                    persist_row_hash: String::new(),
                },
                authority_key_id: String::new(),
                scrub_signature_classical: String::new(),
                scrub_signature_pqc: None,
                supersede_proof: proof,
                cosignatures: Vec::new(),
                lineage: Vec::new(),
            }),
            authorization: None,
        }
    }

    /// A family head under `key`, naming `prev`, carrying `proof`.
    fn family(key: &str, prev: &str, proof: Option<GroupSupersedeProof>) -> PlannedSupersede {
        PlannedSupersede {
            cohort_str: "family",
            head: PlannedHead::Family(SignedFamily {
                family: Family {
                    prev_head_digest: prev.to_owned(),
                    charter_digest: String::new(),
                    family_key_id: key.to_owned(),
                    family_name: "I1622".into(),
                    members: Vec::new(),
                    founded_at: at(),
                    consensus_protocol: cp::MAJORITY.to_owned(),
                    consensus_protocol_entrenched: false,
                    dissolved_at: None,
                    persist_row_hash: String::new(),
                },
                authority_key_id: String::new(),
                scrub_signature_classical: String::new(),
                scrub_signature_pqc: None,
                supersede_proof: proof,
                cosignatures: Vec::new(),
            }),
            authorization: None,
        }
    }

    fn is_conflict(e: &crate::federation::Error, token: &str) -> bool {
        matches!(e, crate::federation::Error::Conflict(m) if m.contains(token))
    }

    /// I1622 — the held-head verdict reads the proof and names the group.
    #[test]
    fn i1622_the_held_head_verdict_reads_the_proof_and_names_the_group() {
        const HELD: &str = "i1622-held-row-hash";
        type Head = fn(&str, &str, Option<GroupSupersedeProof>) -> PlannedSupersede;
        for (kind, head) in [("community", community as Head), ("family", family as Head)] {
            let key = format!("i1622-{kind}-group-key");
            let names = |e: &crate::federation::Error, what: &str| {
                let m = e.to_string();
                assert!(
                    m.contains(&key),
                    "I1622 {kind}: the {what} refusal names the group {key:?}: {m}"
                );
            };
            // The successor: by proof and by prev_head_digest.
            held_head_verdict(&head(&key, HELD, Some(proof(HELD))), Some(HELD))
                .unwrap_or_else(|e| panic!("I1622 {kind}: the successor passes: {e}"));
            held_head_verdict(&head(&key, HELD, None), Some(HELD))
                .unwrap_or_else(|e| panic!("I1622 {kind}: no proof, prev names the head: {e}"));
            // Nothing held: nothing to supersede.
            let e = held_head_verdict(&head(&key, HELD, None), None)
                .expect_err("I1622: an unheld group has nothing to supersede");
            assert!(
                matches!(e, crate::federation::Error::InvalidArgument(_)),
                "I1622 {kind}: {e}"
            );
            names(&e, "unheld");
            // A stale proof is refused although prev_head_digest names the
            // held head: the proof is read, not only the chain link.
            let e = held_head_verdict(
                &head(&key, HELD, Some(proof("i1622-an-older-row-hash"))),
                Some(HELD),
            )
            .expect_err("I1622: a proof naming another prior is stale");
            assert!(
                is_conflict(&e, "stale supersede_proof"),
                "I1622 {kind}: {e}"
            );
            names(&e, "stale-proof");
            // A version that names another predecessor.
            let e = held_head_verdict(&head(&key, "i1622-another-head", None), Some(HELD))
                .expect_err("I1622: a version names the head it succeeds");
            assert!(
                is_conflict(&e, "lineage_prev_head_mismatch"),
                "I1622 {kind}: {e}"
            );
            names(&e, "lineage");
        }
    }
}
