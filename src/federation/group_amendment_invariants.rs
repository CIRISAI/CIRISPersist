//! v49.0.0 (CIRISPersist#910 item 5; `FSD/ROOM_ROSTER_AUTHORITY.md` §10) —
//! **a group amendment replicates.**
//!
//! I178 — two directories hold the same group (a family, and a community). A
//! amends the record (name + `consensus_protocol`; a community's
//! `policy_blob` too) with a quorum that meets the group's protocol. B
//! applies A's version and holds it (name, protocol, version, a history
//! row). A version short of the protocol and a stale one (a later amendment
//! offered before the one it extends) do not move B's record.
//!
//! v62 (E3b) — on edition 2. A version is its own `group:roster` row naming
//! the version it extends (`refs.head`); every signer of the prior roster is
//! one voice over the same payload, and the door counts them at the held
//! head's protocol (T1 §6): short of it the voice is kept `Pending`, and the
//! completing voice lands the version. B takes A's statements through the
//! filtered serve path (`edition2::serve::statements_served_to`) into its
//! replicated statement door (`edition2::ingest::apply_replicated_statement`).
//! Deleted with the earlier proof object: the proof/record mismatch (2b) and
//! the proof-less differing record (3) — the door builds the change envelope
//! from held state, so neither can be expressed — and the wire-index
//! point-read of the JSON group row (no such row is minted).

/// The backend-agnostic witness bodies; `run` instantiates them per backend.
#[cfg(test)]
pub mod bodies {
    use crate::federation::cohort::Cohort;
    use crate::federation::edition2::fixture_switch as e2;
    use crate::federation::edition2::group::GroupRecord;
    use crate::federation::edition2::ingest::{
        apply_replicated_statement, ReplicatedStatementOutcome, StatementOutcome,
    };
    use crate::federation::family_roster_invariants::bodies::{deliver, requester_of, served_rows};
    use crate::federation::types::{
        consensus_protocol, Community, CommunityMember, Family, FamilyMember,
    };
    use crate::federation::FederationDirectory;

    fn at(s: &str) -> chrono::DateTime<chrono::Utc> {
        s.parse().expect("rfc3339")
    }

    /// Now − `mins`, as a statement's asserted instant.
    fn ms_ago(mins: i64) -> u64 {
        e2::ms(chrono::Utc::now() - chrono::Duration::minutes(mins))
    }

    /// One group kind, seen through the few operations the witness needs, so
    /// both kinds run the SAME body.
    #[derive(Clone, Copy, Debug)]
    enum Kind {
        Family,
        Community,
    }

    /// The fields an amendment changes (a community's `policy_blob` follows
    /// its name).
    struct Content<'a> {
        name: &'a str,
        protocol: &'a str,
    }

    impl Kind {
        fn cohort(self) -> Cohort {
            match self {
                Kind::Family => Cohort::Family,
                Kind::Community => Cohort::Community,
            }
        }

        /// The record of `members` (seeds), every key id its identity-ref.
        fn record(self, id: &str, members: &[String], c: &Content<'_>) -> GroupRecord {
            let joined = at("2026-01-01T00:00:00Z");
            match self {
                Kind::Family => GroupRecord::Family(e2::family_with_kids(&Family {
                    prev_head_digest: String::new(),
                    charter_digest: String::new(),
                    family_key_id: id.to_owned(),
                    family_name: c.name.to_owned(),
                    members: members
                        .iter()
                        .map(|k| FamilyMember {
                            key_id: k.clone(),
                            joined_at: joined,
                            role: None,
                        })
                        .collect(),
                    founded_at: joined,
                    consensus_protocol: c.protocol.to_owned(),
                    consensus_protocol_entrenched: false,
                    dissolved_at: None,
                    persist_row_hash: String::new(),
                })),
                Kind::Community => GroupRecord::Community(e2::community_with_kids(&Community {
                    prev_head_digest: String::new(),
                    charter_digest: String::new(),
                    community_key_id: id.to_owned(),
                    community_name: c.name.to_owned(),
                    members: members
                        .iter()
                        .map(|k| CommunityMember {
                            key_id: k.clone(),
                            joined_at: joined,
                            role: None,
                        })
                        .collect(),
                    founded_at: joined,
                    consensus_protocol: c.protocol.to_owned(),
                    // The community's own policy moves with its name.
                    policy_blob: Some(serde_json::json!({ "charter": c.name })),
                    persist_row_hash: String::new(),
                })),
            }
        }

        /// `(name, protocol, persist_row_hash, policy_blob)` as `d` stores it.
        async fn stored(
            self,
            d: &dyn FederationDirectory,
            id: &str,
        ) -> (String, String, String, Option<serde_json::Value>) {
            match self {
                Kind::Family => {
                    let f = d.lookup_family(id).await.unwrap().expect("family");
                    (
                        f.family_name,
                        f.consensus_protocol,
                        f.persist_row_hash,
                        None,
                    )
                }
                Kind::Community => {
                    let c = d.lookup_community(id).await.unwrap().expect("community");
                    (
                        c.community_name,
                        c.consensus_protocol,
                        c.persist_row_hash,
                        c.policy_blob,
                    )
                }
            }
        }

        async fn current_version(self, d: &dyn FederationDirectory, id: &str) -> u32 {
            d.list_group_versions(self.cohort(), id)
                .await
                .unwrap()
                .into_iter()
                .find(|v| v.is_current)
                .expect("a live version")
                .version
        }
    }

    /// **I178 — a group amendment reaches a peer; a short or stale one does
    /// not.** Runs for a family and for a community.
    pub async fn i178_a_group_amendment_replicates(
        a: &dyn FederationDirectory,
        b: &dyn FederationDirectory,
        tag: &str,
    ) {
        for kind in [Kind::Family, Kind::Community] {
            // FX-fix1 — the kind goes FIRST: a test key seeds from the first 32
            // bytes of its seed name, and `alice-i178-<32 hex>-family` /
            // `-community` were one key (`guard_seed_collision`).
            one_kind(a, b, kind, &format!("{kind:?}-{tag}").to_lowercase()).await;
        }
    }

    async fn one_kind(
        a: &dyn FederationDirectory,
        b: &dyn FederationDirectory,
        kind: Kind,
        tag: &str,
    ) {
        let keys: Vec<String> = ["alice", "bob", "carol"]
            .iter()
            .map(|n| format!("{n}-{tag}"))
            .collect();
        for d in [a, b] {
            for k in &keys {
                e2::put_key(d, k, &["user"]).await;
            }
        }
        let signing: Vec<_> = keys.iter().map(|k| e2::signing_key(k)).collect();
        let all: Vec<&_> = signing.iter().collect();
        let id = format!("group-{tag}");
        let gid = e2::kid(&id);
        let to_b = requester_of(b, &e2::kid(&keys[1]));
        let to_a = requester_of(a, &e2::kid(&keys[0]));

        // The founding version: every member's voice, on A; B takes it.
        let v1 = Content {
            name: "household",
            protocol: consensus_protocol::MAJORITY,
        };
        let founding = e2::roster_voices(&kind.record(&id, &keys, &v1), 1, None, ms_ago(30), &all);
        // GID-fixtures-sites — the room's DERIVED id, once founded (`room_id`
        // panics if it was not).
        let id = crate::federation::edition2::fixture_switch::room_id(&id);
        let r = e2::put_voices(a, &founding).await;
        assert!(
            matches!(r, Ok(StatementOutcome::Row { .. })),
            "{tag}: founding: {r:?}"
        );
        let v1_row = e2::row_id_of(&founding[0]);
        deliver(b, &served_rows(a, &to_b, &[v1_row]).await).await;
        let (_, _, v1_hash, _) = kind.stored(b, &gid).await;
        assert_eq!(kind.stored(a, &gid).await.2, v1_hash, "{tag}: one record");
        assert_eq!(kind.current_version(b, &gid).await, 1, "{tag}");

        // (1) A amends name + protocol: majority → unanimous, voiced by two
        //     of three (the MAJORITY the group's own protocol asks for). The
        //     first voice is short and kept `Pending`; the second lands it.
        let v2 = Content {
            name: "household, renamed",
            protocol: consensus_protocol::UNANIMOUS,
        };
        let v2_voices = e2::roster_voices(
            &kind.record(&id, &keys, &v2),
            2,
            Some(&v1_row),
            ms_ago(20),
            &all[..2],
        );
        let first = e2::put_voices(a, &v2_voices[..1]).await;
        assert!(
            matches!(first, Ok(StatementOutcome::Pending { .. })),
            "{tag} I178: one voice of three is short of a majority: {first:?}"
        );
        assert_eq!(kind.current_version(a, &gid).await, 1, "{tag} I178");
        let second = e2::put_voices(a, &v2_voices[1..]).await;
        assert!(
            matches!(second, Ok(StatementOutcome::Row { .. })),
            "{tag} I178: A's quorum amendment: {second:?}"
        );
        assert_eq!(
            kind.current_version(a, &gid).await,
            2,
            "{tag} I178: A is at version 2"
        );
        let v2_row = e2::row_id_of(&v2_voices[0]);
        let a_v2 = kind.stored(a, &gid).await;
        assert_eq!(a_v2.0, v2.name, "{tag} I178: renamed");
        assert_eq!(a_v2.1, v2.protocol, "{tag} I178: the new protocol");
        let served_v2 = served_rows(a, &to_b, &[v2_row]).await;
        assert_eq!(
            served_v2.len(),
            2,
            "{tag} I178: A serves both voices of version 2"
        );

        // (2) A short voice set — one voice, below the protocol — does not
        //     move B: the voice is kept `Pending`, and B keeps its record.
        let out = deliver(b, &served_v2[..1]).await;
        assert!(
            matches!(
                out[0],
                ReplicatedStatementOutcome::Admitted(StatementOutcome::Pending { .. })
            ),
            "{tag} I178: a voice below the protocol is held, not applied: {:?}",
            out[0]
        );
        assert_eq!(
            kind.stored(b, &gid).await.2,
            v1_hash,
            "{tag} I178: B keeps its record"
        );
        assert_eq!(kind.current_version(b, &gid).await, 1, "{tag} I178");

        // (4) A amends again (unanimous now: all three voice) before B holds
        //     the first amendment. Offered first, the second is STALE: its
        //     `refs.head` names a version B does not hold. v62.0.0 (E3b round
        //     3; CC 2.7, ruling 5): the dependency is genuinely missing, so
        //     the voices WAIT (kept `Pending`, concluding nothing) — or are
        //     refused retryable; either way B's record does not move.
        let v3 = Content {
            name: "household, renamed twice",
            protocol: consensus_protocol::MAJORITY,
        };
        let v3_voices = e2::roster_voices(
            &kind.record(&id, &keys, &v3),
            3,
            Some(&v2_row),
            ms_ago(10),
            &all,
        );
        let r = e2::put_voices(a, &v3_voices).await;
        assert!(
            matches!(r, Ok(StatementOutcome::Row { .. })),
            "{tag} I178: A's second amendment: {r:?}"
        );
        assert_eq!(
            kind.current_version(a, &gid).await,
            3,
            "{tag} I178: A is at version 3"
        );
        let v3_row = e2::row_id_of(&v3_voices[0]);
        let served_v3 = served_rows(a, &to_b, &[v3_row]).await;
        assert_eq!(served_v3.len(), 3, "{tag} I178: three voices of v3");
        // v62 (E3, round 6): B holds v2's voices from (3) (kept `Pending`),
        // so v3's `refs.head` names a version B HOLDS but has not settled.
        // The door may keep v3 (`Pending`), refuse it, or keep it as a K1 tip
        // (`Row`): the property is that B's settled record does not move.
        for (bytes, row) in &served_v3 {
            let _ = apply_replicated_statement(b, bytes, &row.0).await;
        }
        assert_eq!(
            kind.stored(b, &gid).await.2,
            v1_hash,
            "{tag} I178: B keeps its record"
        );
        assert_eq!(
            kind.current_version(b, &gid).await,
            1,
            "{tag} I178: a version over an unsettled head does not move B's head"
        );

        // (5) The genuine first amendment applies on B: alice's voice is
        //     already held, bob's completes it. B holds A's version 2 — name,
        //     protocol, policy, hash — with a history row the door built.
        let out = deliver(b, &served_v2).await;
        assert!(
            matches!(out[0], ReplicatedStatementOutcome::Unchanged(_)),
            "{tag} I178: the held voice is unchanged: {:?}",
            out[0]
        );
        assert!(
            matches!(
                out[1],
                ReplicatedStatementOutcome::Admitted(StatementOutcome::Row { .. })
            ),
            "{tag} I178: B applies A's amendment: {:?}",
            out[1]
        );
        // v62.0.0 (E3b round 3): v2's arrival re-folds the v3 voices that
        // waited on it (CC 2.7), so B may already stand at version 3.
        let vb = kind.current_version(b, &gid).await;
        assert!(vb == 2 || vb == 3, "{tag} I178: B moved past v1: {vb}");
        if vb == 2 {
            assert_eq!(
                kind.stored(b, &gid).await,
                a_v2,
                "{tag} I178: B holds A's version 2"
            );
        }
        let history = b.list_group_versions(kind.cohort(), &gid).await.unwrap();
        assert!(
            history.iter().any(|v| v.version == 1 && !v.is_current),
            "{tag} I178: the superseded version 1 is in B's history: {history:?}"
        );
        assert!(
            history.iter().any(|v| v
                .authorization
                .as_ref()
                .and_then(|x| x.get("change_envelope"))
                .is_some()),
            "{tag} I178: the history records the door-built change: {history:?}"
        );
        // B serves the version on, so the next peer can apply it.
        let onward = served_rows(b, &to_a, &[v2_row]).await;
        let mut theirs: Vec<&Vec<u8>> = onward.iter().map(|(s, _)| s).collect();
        let mut ours: Vec<&Vec<u8>> = served_v2.iter().map(|(s, _)| s).collect();
        theirs.sort();
        ours.sort();
        assert_eq!(theirs, ours, "{tag} I178: B serves A's voices on");
        // The same statements again are the idempotent no-op.
        for o in deliver(b, &served_v2).await {
            assert!(
                matches!(o, ReplicatedStatementOutcome::Unchanged(_)),
                "{tag} I178: the identical re-delivery: {o:?}"
            );
        }
        assert!(
            kind.current_version(b, &gid).await >= 2,
            "{tag} I178: the re-delivery changes nothing"
        );

        // (6) …and now the second applies too: B converges on version 3,
        //     judged against B's own version 2 (unanimous — all three voice).
        deliver(b, &served_v3).await;
        assert_eq!(
            kind.stored(b, &gid).await,
            kind.stored(a, &gid).await,
            "{tag} I178: B converged on A's version 3"
        );
        assert_eq!(kind.current_version(b, &gid).await, 3, "{tag} I178");
    }
}

#[cfg(all(test, any(feature = "sqlite", feature = "postgres")))]
mod run {
    fn suffix() -> String {
        uuid::Uuid::new_v4().simple().to_string()
    }

    macro_rules! dyn_runners {
        ($modname:ident, $fresh:expr) => {
            mod $modname {
                use crate::federation::FederationDirectory;
                #[tokio::test]
                async fn i178() {
                    let (Some(a), Some(b)) = ($fresh.await, $fresh.await) else {
                        return;
                    };
                    super::super::bodies::i178_a_group_amendment_replicates(
                        &a as &dyn FederationDirectory,
                        &b as &dyn FederationDirectory,
                        &format!("i178-{}", super::suffix()),
                    )
                    .await
                }
            }
        };
    }

    #[cfg(feature = "sqlite")]
    dyn_runners!(sqlite_dyn, async {
        use crate::store::Backend as _;
        let b = crate::store::sqlite::SqliteBackend::open_in_memory()
            .await
            .unwrap();
        b.run_migrations().await.unwrap();
        Some(b)
    });

    #[cfg(feature = "postgres")]
    dyn_runners!(postgres_dyn, async {
        use crate::store::Backend as _;
        let dsn = crate::test_pg::empty_dsn()?;
        let b = crate::store::postgres::PostgresBackend::connect(&dsn)
            .await
            .unwrap();
        b.run_migrations().await.unwrap();
        Some(b)
    });
}
