//! v62.0.0 (kernel pass 2, K1) — **I2811–I2816: forks held as tips, the
//! answer's read set, and a key's end through the kernel.**
//!
//! - **I2811 / I2812** — v62.0.0 (slice F): DELETED. Both drove the
//!   earlier-form family doors (`put_family` / `supersede_family`), which
//!   refuse by name now. Their edition-2 witnesses are T1's
//!   `group_invariants` I2995, I3001, I3005 (a fork is a tip) and I2996 (an
//!   unheld head).
//! - **I2813** (pure) — the held-head verdict, by truth table: a successor
//!   extends; a sibling, a second founding version and a version naming an
//!   unheld one are tips; a proof naming the version's own prior rides with
//!   it; a proof naming another prior than the version's is refused (the
//!   stale proof when the version names the head,
//!   `supersede_proof_contradicts_prev_head` when it names another); an
//!   unheld group is refused.
//! - **I2810** (pure, in `kernel::head`) — the head answer carries its read
//!   set; **I2814–I2816** (pure, in `kernel::key_end`) — a key's end.

#[cfg(all(test, any(feature = "sqlite", feature = "postgres")))]
mod pure {
    use crate::federation::group_supersede_admit::{
        held_head_verdict, HeadVerdict, PlannedHead, PlannedSupersede,
    };
    use crate::federation::types::consensus_protocol as cp;
    use crate::federation::types::{Family, GroupSupersedeProof, SignedFamily};

    fn proof(prior: &str) -> GroupSupersedeProof {
        GroupSupersedeProof {
            prior_persist_row_hash: prior.to_owned(),
            change_envelope: serde_json::json!({}),
            quorum_signatures: Vec::new(),
        }
    }

    fn family(prev: &str, proof: Option<GroupSupersedeProof>) -> PlannedSupersede {
        PlannedSupersede {
            cohort_str: "family",
            head: PlannedHead::Family(SignedFamily {
                family: Family {
                    prev_head_digest: prev.to_owned(),
                    charter_digest: String::new(),
                    family_key_id: "i2813-family".to_owned(),
                    family_name: "I2813".into(),
                    members: Vec::new(),
                    founded_at: "2026-01-01T00:00:00Z".parse().expect("instant"),
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

    fn conflict(r: Result<HeadVerdict, crate::federation::Error>, token: &str) -> bool {
        matches!(r, Err(crate::federation::Error::Conflict(m)) if m.contains(token))
    }

    /// **I2813** — see the module doc.
    #[test]
    fn i2813_the_held_head_verdict_by_truth_table() {
        const HELD: &str = "i2813-held";
        const OTHER: &str = "i2813-other";
        const THIRD: &str = "i2813-third";
        let v = |prev: &str, p: Option<&str>| {
            held_head_verdict(&family(prev, p.map(proof)), Some(HELD))
        };
        assert_eq!(
            v(HELD, None).unwrap(),
            HeadVerdict::Extends,
            "I2813: a successor"
        );
        assert_eq!(v(HELD, Some(HELD)).unwrap(), HeadVerdict::Extends, "I2813");
        assert_eq!(
            v(OTHER, None).unwrap(),
            HeadVerdict::Tip,
            "I2813: a sibling"
        );
        assert_eq!(
            v("", None).unwrap(),
            HeadVerdict::Tip,
            "I2813: a second founding"
        );
        assert_eq!(
            v(OTHER, Some(OTHER)).unwrap(),
            HeadVerdict::Tip,
            "I2813: a proof naming the version's own prior rides with it"
        );
        assert!(
            conflict(v(HELD, Some(OTHER)), "stale supersede_proof"),
            "I2813: the version names the head, its proof another"
        );
        assert!(
            conflict(
                v(OTHER, Some(THIRD)),
                "supersede_proof_contradicts_prev_head"
            ),
            "I2813: a proof naming a third prior contradicts its version"
        );
        // v62.0.0 (CC 2.7) — nothing held yet is the wait, not a refusal.
        assert!(
            matches!(
                held_head_verdict(&family(HELD, None), None),
                Err(ref e @ crate::federation::Error::LinkNotHeld { .. }) if e.is_wait()
            ),
            "I2813: an unheld group has nothing to supersede yet: a wait"
        );
    }
}
