//! v49.0.0 (CIRISPersist#910 item 5; `FSD/ROOM_ROSTER_AUTHORITY.md` §10) —
//! **a group amendment replicates.**
//!
//! I178 — two directories hold the same group (a family, and a community). A
//! amends the record (name + `consensus_protocol`; a community's
//! `policy_blob` too) through `supersede_*_with_quorum` with a quorum that
//! meets the group's protocol. B applies A's record from the signed
//! since-read and holds the amended version (name, protocol, version, a
//! history row). A forged proof (signatures below the protocol), a stale proof
//! (a later amendment offered before the one it replaces) and a proof-less
//! differing record are each refused, and B keeps its record.

/// The backend-agnostic witness bodies; `run` instantiates them per backend.
#[cfg(test)]
pub mod bodies {
    use crate::federation::cohort::Cohort;
    use crate::federation::tier_ingest::test_support as ts;
    use crate::federation::types::{
        consensus_protocol, identity_type, Community, CommunityMember, Family, FamilyMember,
    };
    use crate::federation::{Error, FederationDirectory, GroupSupersedeProof};

    fn at(s: &str) -> chrono::DateTime<chrono::Utc> {
        s.parse().expect("rfc3339")
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

    /// A signed group record of either kind.
    #[derive(Clone)]
    enum Signed {
        Family(crate::federation::SignedFamily),
        Community(crate::federation::SignedCommunity),
    }

    impl Signed {
        fn proof(&self) -> Option<&GroupSupersedeProof> {
            match self {
                Signed::Family(f) => f.supersede_proof.as_ref(),
                Signed::Community(c) => c.supersede_proof.as_ref(),
            }
        }
        fn proof_mut(&mut self) -> &mut Option<GroupSupersedeProof> {
            match self {
                Signed::Family(f) => &mut f.supersede_proof,
                Signed::Community(c) => &mut c.supersede_proof,
            }
        }
    }

    impl Kind {
        fn cohort(self) -> Cohort {
            match self {
                Kind::Family => Cohort::Family,
                Kind::Community => Cohort::Community,
            }
        }

        /// The record of `members`, signed by the first.
        fn record(self, id: &str, members: &[String], c: &Content<'_>) -> Signed {
            let joined = at("2026-01-01T00:00:00Z");
            match self {
                Kind::Family => Signed::Family(ts::sign_family(
                    &members[0],
                    Family {
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
                        persist_row_hash: String::new(),
                    },
                )),
                Kind::Community => Signed::Community(ts::sign_community(
                    &members[0],
                    Community {
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
                    },
                )),
            }
        }

        async fn put(self, d: &dyn FederationDirectory, s: Signed) -> Result<(), Error> {
            match s {
                Signed::Family(f) => d.put_family(f).await,
                Signed::Community(c) => d.put_community(c).await,
            }
        }

        async fn supersede_with_quorum(
            self,
            d: &dyn FederationDirectory,
            s: Signed,
            change: serde_json::Value,
            sigs: Vec<ciris_verify_core::threshold::ThresholdSignature>,
        ) -> Result<u32, Error> {
            match s {
                Signed::Family(f) => d.supersede_family_with_quorum(f, change, sigs).await,
                Signed::Community(c) => d.supersede_community_with_quorum(c, change, sigs).await,
            }
        }

        /// What `d` serves for `id` on the signed since-read.
        async fn served(self, d: &dyn FederationDirectory, id: &str) -> Signed {
            match self {
                Kind::Family => Signed::Family(
                    d.list_signed_families_since(None, u32::MAX)
                        .await
                        .unwrap()
                        .into_iter()
                        .find(|r| r.family.family.family_key_id == id)
                        .expect("served family")
                        .family,
                ),
                Kind::Community => Signed::Community(
                    d.list_signed_communities_since(None, u32::MAX)
                        .await
                        .unwrap()
                        .into_iter()
                        .find(|r| r.community.community.community_key_id == id)
                        .expect("served community")
                        .community,
                ),
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

        /// Build the protocol-only change on `a` (the roster stays `members`)
        /// and have `signers` sign it.
        async fn change_signed_by(
            self,
            a: &dyn FederationDirectory,
            id: &str,
            members: &[String],
            protocol: &str,
            signers: &[&String],
        ) -> (
            serde_json::Value,
            Vec<ciris_verify_core::threshold::ThresholdSignature>,
        ) {
            let change = a
                .build_membership_change_envelope(self.cohort(), id, members, false, Some(protocol))
                .await
                .unwrap_or_else(|e| panic!("build change: {e}"));
            let bytes = ciris_verify_core::jcs::canonicalize(&change).unwrap();
            let sigs = signers
                .iter()
                .map(|k| ts::threshold_sign(k, &bytes))
                .collect();
            (change, sigs)
        }
    }

    fn is_conflict_containing(e: &Error, needle: &str) -> bool {
        matches!(e, Error::Conflict(m) if m.contains(needle))
    }

    /// **I178 — a group amendment reaches a peer; a forged, stale or
    /// proof-less one does not.** Runs for a family and for a community.
    pub async fn i178_a_group_amendment_replicates(
        a: &dyn FederationDirectory,
        b: &dyn FederationDirectory,
        tag: &str,
    ) {
        for kind in [Kind::Family, Kind::Community] {
            one_kind(a, b, kind, &format!("{tag}-{kind:?}").to_lowercase()).await;
        }
    }

    async fn one_kind(
        a: &dyn FederationDirectory,
        b: &dyn FederationDirectory,
        kind: Kind,
        tag: &str,
    ) {
        // The distinguishing part of a key id LEADS: the test signer seeds
        // from its first 32 bytes.
        let keys: Vec<String> = ["alice", "bob", "carol"]
            .iter()
            .map(|n| format!("{n}-{tag}"))
            .collect();
        let (alice, bob, carol) = (&keys[0], &keys[1], &keys[2]);
        for d in [a, b] {
            for k in &keys {
                ts::register_hybrid_key_as(d, k, k, identity_type::USER).await;
            }
        }
        let id = format!("{tag}-group");
        let v1 = Content {
            name: "household",
            protocol: consensus_protocol::MAJORITY,
        };
        let founding = kind.record(&id, &keys, &v1);
        for d in [a, b] {
            kind.put(d, founding.clone())
                .await
                .unwrap_or_else(|e| panic!("{tag}: founding record: {e}"));
        }
        let (_, _, v1_hash, _) = kind.stored(b, &id).await;
        assert_eq!(kind.stored(a, &id).await.2, v1_hash, "{tag}: one record");
        assert!(
            kind.served(a, &id).await.proof().is_none(),
            "{tag} I178: a founding record carries no proof"
        );

        // (1) A amends name + protocol: majority → unanimous, signed by two of
        //     three (the MAJORITY the group's own protocol asks for).
        let v2 = Content {
            name: "household, renamed",
            protocol: consensus_protocol::UNANIMOUS,
        };
        let (change, sigs) = kind
            .change_signed_by(a, &id, &keys, v2.protocol, &[alice, bob])
            .await;
        assert_eq!(
            kind.supersede_with_quorum(a, kind.record(&id, &keys, &v2), change, sigs)
                .await
                .unwrap_or_else(|e| panic!("{tag} I178: A's quorum amendment: {e}")),
            2,
            "{tag} I178: A is at version 2"
        );
        let served_v2 = kind.served(a, &id).await;
        let proof = served_v2
            .proof()
            .unwrap_or_else(|| panic!("{tag} I178: the amended record is served with its proof"));
        assert_eq!(
            proof.prior_persist_row_hash, v1_hash,
            "{tag} I178: the proof names the version it replaced"
        );
        let a_v2 = kind.stored(a, &id).await;

        // (2) A forged proof — one signature, below the protocol — is refused,
        //     and B keeps its record.
        let mut forged = served_v2.clone();
        forged
            .proof_mut()
            .as_mut()
            .expect("proof")
            .quorum_signatures
            .truncate(1);
        let e = kind
            .put(b, forged)
            .await
            .expect_err("a proof below the protocol must be refused");
        assert!(
            e.to_string().contains("not authorized"),
            "{tag} I178: refused by verify_membership_quorum: {e}"
        );
        assert_eq!(
            kind.stored(b, &id).await.2,
            v1_hash,
            "{tag} I178: B keeps its record"
        );

        // (3) The same record without a proof is refused (#758 unchanged for
        //     a community; the same refusal for a family).
        let mut bare = served_v2.clone();
        *bare.proof_mut() = None;
        let e = kind
            .put(b, bare)
            .await
            .expect_err("a differing record without a proof must be refused");
        assert!(
            is_conflict_containing(&e, "DIFFERENT content")
                && is_conflict_containing(&e, "CIRISPersist#758"),
            "{tag} I178: the #758 refusal: {e}"
        );
        assert_eq!(kind.stored(b, &id).await.2, v1_hash, "{tag} I178");

        // (4) A amends again (unanimous now: all three sign) before B has the
        //     first amendment. Offered first, the second is STALE.
        let v3 = Content {
            name: "household, renamed twice",
            protocol: consensus_protocol::MAJORITY,
        };
        let (change, sigs) = kind
            .change_signed_by(a, &id, &keys, v3.protocol, &[alice, bob, carol])
            .await;
        assert_eq!(
            kind.supersede_with_quorum(a, kind.record(&id, &keys, &v3), change, sigs)
                .await
                .unwrap_or_else(|e| panic!("{tag} I178: A's second amendment: {e}")),
            3,
            "{tag} I178: A is at version 3"
        );
        let served_v3 = kind.served(a, &id).await;
        let e = kind
            .put(b, served_v3.clone())
            .await
            .expect_err("a proof naming a version B does not hold must be refused");
        assert!(
            is_conflict_containing(&e, "stale supersede_proof")
                && is_conflict_containing(&e, "retryable"),
            "{tag} I178: the stale refusal says so: {e}"
        );
        assert_eq!(
            kind.stored(b, &id).await.2,
            v1_hash,
            "{tag} I178: B keeps its record"
        );

        // (5) The genuine first amendment applies on B: B holds A's version 2
        //     — name, protocol, policy, hash — with a history row carrying the
        //     quorum that authorized it.
        kind.put(b, served_v2.clone())
            .await
            .unwrap_or_else(|e| panic!("{tag} I178: B applies A's amendment: {e}"));
        assert_eq!(
            kind.stored(b, &id).await,
            a_v2,
            "{tag} I178: B holds A's version 2"
        );
        assert_eq!(a_v2.0, v2.name, "{tag} I178: renamed");
        assert_eq!(a_v2.1, v2.protocol, "{tag} I178: the new protocol");
        assert_eq!(kind.current_version(b, &id).await, 2, "{tag} I178");
        let history = b.list_group_versions(kind.cohort(), &id).await.unwrap();
        let prior = history
            .iter()
            .find(|v| v.version == 1)
            .expect("the superseded version 1 is in B's history");
        assert!(
            prior
                .authorization
                .as_ref()
                .and_then(|a| a.get("quorum_signatures"))
                .is_some(),
            "{tag} I178: the history row records the quorum: {:?}",
            prior.authorization
        );
        assert_eq!(
            kind.served(b, &id).await.proof(),
            served_v2.proof(),
            "{tag} I178: B serves the proof on, so the next peer can apply it"
        );
        // The same record again is the idempotent no-op.
        kind.put(b, served_v2)
            .await
            .unwrap_or_else(|e| panic!("{tag} I178: the identical re-put is Ok: {e}"));
        assert_eq!(kind.current_version(b, &id).await, 2, "{tag} I178");

        // (6) …and now the second applies too: B converges on version 3,
        //     judged against B's own version 2 (unanimous — all three signed).
        kind.put(b, served_v3)
            .await
            .unwrap_or_else(|e| panic!("{tag} I178: B applies the second amendment: {e}"));
        assert_eq!(
            kind.stored(b, &id).await,
            kind.stored(a, &id).await,
            "{tag} I178: B converged on A's version 3"
        );
        assert_eq!(kind.current_version(b, &id).await, 3, "{tag} I178");
    }
}

#[cfg(test)]
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

    dyn_runners!(memory_dyn, async {
        Some(crate::store::memory::MemoryBackend::new())
    });

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
