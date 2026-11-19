//! CIRISPersist#873 — witnesses for `FSD/OCCURRENCE_PRINCIPAL.md` §4.
//!
//! v62.0.0 (P1-fix4, round 3): I121–I124 and I141 are DELETED. Each stood
//! up the earlier "login anchor": a person's identity bound over a `node`
//! key as an `identity:occurrence` (`bind(human, node, server)`), and
//! asserted what that binding resolves. CC rc21 3.3.6 forbids that binding
//! ("An occurrence that places a `node` or `agent` key under a `user` or
//! `accord_holder` identity, or the reverse, concludes nothing"; CC 3.4.7.1:
//! a key is a person's or a machine's, never both), and the door refuses it
//! (`occurrence_binds_machine_to_person`). A node's human is its OWNER
//! binding (`admission::owner_of` / `nodes_owned_by`; v62 P5c's
//! `replication_audience`), witnessed there. I124 (one node shared by two
//! humans) has no rc21 counterpart: an owner binding is single-valued
//! (CC 3.2). I125, a from-disk check of the resolver's ordering, stays.

#[cfg(test)]
pub(crate) mod bodies {
    /// **I125 — from disk: no `LIMIT 1` without an order at this site; the
    /// audience walk asks the plural.**
    #[test]
    fn i125_no_unordered_limit_one() {
        for (name, text) in [
            ("sqlite.rs", include_str!("../store/sqlite.rs")),
            ("postgres.rs", include_str!("../store/postgres.rs")),
        ] {
            let body = text
                .split("async fn lookup_identity_for_occurrence(")
                .nth(1)
                .unwrap_or_else(|| panic!("I125: {name} has lookup_identity_for_occurrence"));
            let body = &body[..body.find("\n    }\n").expect("end")];
            assert!(
                body.contains("ORDER BY"),
                "I125: {name} lookup_identity_for_occurrence orders its LIMIT 1"
            );
            let order = &body[body.find("ORDER BY").unwrap()..];
            assert!(
                order.contains("asserted_at DESC"),
                "I125: {name} orders newest binding first"
            );
        }
        let hold = include_str!("replication/hold.rs");
        let body = hold
            .split("pub async fn audience_memberships<")
            .nth(1)
            .expect("I125: audience_memberships");
        let body = &body[..body.find("\n}\n").expect("end")];
        // E5-fix1 (round 3) — v62 P5c moved the plural read into the ONE
        // principal resolver (`self_collective::principals_of`: every active
        // identity plus the owner); the walk asks it, and it asks the plural.
        assert!(
            body.contains("principals_of("),
            "I125: the audience walk unions every principal"
        );
        let sc = include_str!("self_collective.rs");
        let resolver = sc
            .split("pub async fn principals_of<")
            .nth(1)
            .expect("I125: principals_of");
        let resolver = &resolver[..resolver.find("\n}\n").expect("end")];
        assert!(
            resolver.contains("active_identities_for_occurrence("),
            "I125: the principal resolver unions every active identity"
        );
        assert!(
            !body.contains("active_identity_for_occurrence("),
            "I125: and no longer asks the single-valued resolver"
        );
    }
}
