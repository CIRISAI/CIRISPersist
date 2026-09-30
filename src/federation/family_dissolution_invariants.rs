//! v52.0.0 (CIRISPersist#956) — **a quorum family's leave and dissolve
//! replicate as amendments.** Two directories hold one `majority` family of
//! three; B learns every record only from A's signed since-read (the plane).
//!
//! - **I280** — a quorum dissolution on A (two of three sign) replicates: B
//!   applies it, both hold `dissolved_at`, the family has no active members.
//! - **I281** — a dissolution is only a quorum-verified TERMINAL amendment: one
//!   signature, the plain door, a founding record, a dissolution that also
//!   renames, and a record whose `dissolved_at` the quorum did not sign are
//!   each refused, and the family stays live.
//! - **I282** — after dissolution every write naming the family is refused
//!   `federation_group_dissolved` (a further amendment on A and on B's apply,
//!   a membership revocation, a row placed at it); the identical dissolved
//!   record re-offered is the idempotent no-op.
//! - **I283** — a self-leave: carol's amendment removing only herself,
//!   signed by carol alone, is admitted on A and applied on B.
//! - **I284** — the self-leave arm admits nothing else: removing someone
//!   else, leaving while renaming, leaving while re-roling a seat, a record
//!   the leaver did not sign — each falls to the quorum, which one signature
//!   does not meet.
//! - **I285** — a live family's record never carries `dissolved_at`, so every
//!   record written before v52.0.0 keeps its bytes and signing envelope.

/// The backend-agnostic bodies.
#[cfg(test)]
pub mod bodies {
    use crate::federation::cohort::Cohort;
    use crate::federation::tier_ingest::test_support as ts;
    use crate::federation::types::{consensus_protocol, identity_type, Family, FamilyMember};
    use crate::federation::{Error, FederationDirectory, SignedFamily};

    fn at(s: &str) -> chrono::DateTime<chrono::Utc> {
        s.parse().expect("rfc3339")
    }

    struct World {
        id: String,
        keys: Vec<String>,
    }

    fn family(w: &World, members: &[&String], name: &str) -> Family {
        let joined = at("2026-01-01T00:00:00Z");
        Family {
            family_key_id: w.id.clone(),
            family_name: name.to_owned(),
            members: members
                .iter()
                .map(|k| FamilyMember {
                    key_id: (*k).clone(),
                    joined_at: joined,
                    role: None,
                })
                .collect(),
            founded_at: joined,
            consensus_protocol: consensus_protocol::MAJORITY.to_owned(),
            consensus_protocol_entrenched: false,
            dissolved_at: None,
            persist_row_hash: String::new(),
        }
    }

    async fn world(a: &dyn FederationDirectory, b: &dyn FederationDirectory, tag: &str) -> World {
        let keys: Vec<String> = ["alice", "bob", "carol"]
            .iter()
            .map(|n| format!("{n}-{tag}"))
            .collect();
        for d in [a, b] {
            for k in &keys {
                ts::register_hybrid_key_as(d, k, k, identity_type::USER).await;
            }
        }
        let w = World {
            id: format!("{tag}-fam"),
            keys,
        };
        let all: Vec<&String> = w.keys.iter().collect();
        let founding = ts::sign_family(&w.keys[0], family(&w, &all, "household"));
        for d in [a, b] {
            d.put_family(founding.clone())
                .await
                .unwrap_or_else(|e| panic!("{tag}: founding: {e}"));
        }
        w
    }

    /// The change envelope for `members` (protocol unchanged), with an
    /// optional `dissolved_at`, signed by `signers`.
    async fn change(
        a: &dyn FederationDirectory,
        w: &World,
        members: &[&String],
        dissolved_at: Option<chrono::DateTime<chrono::Utc>>,
        signers: &[&String],
    ) -> (
        serde_json::Value,
        Vec<ciris_verify_core::threshold::ThresholdSignature>,
    ) {
        let ids: Vec<String> = members.iter().map(|k| (*k).clone()).collect();
        let mut env = a
            .build_membership_change_envelope(
                Cohort::Family,
                &w.id,
                &ids,
                false,
                Some(consensus_protocol::MAJORITY),
            )
            .await
            .expect("build change");
        if let Some(t) = dissolved_at {
            env.as_object_mut()
                .unwrap()
                .insert("dissolved_at".into(), t.to_rfc3339().into());
        }
        let bytes = ciris_verify_core::jcs::canonicalize(&env).unwrap();
        let sigs = signers
            .iter()
            .map(|k| ts::threshold_sign(k, &bytes))
            .collect();
        (env, sigs)
    }

    async fn served(d: &dyn FederationDirectory, id: &str) -> SignedFamily {
        d.list_signed_families_since(None, u32::MAX)
            .await
            .unwrap()
            .into_iter()
            .find(|r| r.family.family.family_key_id == id)
            .expect("served family")
            .family
    }

    async fn held(d: &dyn FederationDirectory, id: &str) -> Family {
        d.lookup_family(id).await.unwrap().expect("family")
    }

    fn is_dissolved_refusal(e: &Error) -> bool {
        matches!(e, Error::GroupDissolved { .. }) && e.kind() == "federation_group_dissolved"
    }

    const DISSOLVED: &str = "2026-09-30T12:00:00Z";

    /// Dissolve `w` on `a` with alice + bob (a majority of three).
    async fn dissolve_on_a(a: &dyn FederationDirectory, w: &World, tag: &str) -> SignedFamily {
        let (alice, bob) = (&w.keys[0], &w.keys[1]);
        let all: Vec<&String> = w.keys.iter().collect();
        let t = at(DISSOLVED);
        let (env, sigs) = change(a, w, &all, Some(t), &[alice, bob]).await;
        let mut rec = family(w, &all, "household");
        rec.dissolved_at = Some(t);
        a.supersede_family_with_quorum(ts::sign_family(alice, rec), env, sigs)
            .await
            .unwrap_or_else(|e| panic!("{tag}: A's quorum dissolution: {e}"));
        served(a, &w.id).await
    }

    /// **I280** — a quorum dissolution replicates.
    pub async fn i280_a_quorum_dissolution_replicates(
        a: &dyn FederationDirectory,
        b: &dyn FederationDirectory,
        tag: &str,
    ) {
        let w = world(a, b, tag).await;
        assert_eq!(a.active_family_members(&w.id).await.unwrap().len(), 3);
        let dissolved = dissolve_on_a(a, &w, tag).await;
        assert!(
            dissolved.supersede_proof.is_some(),
            "{tag} I280: served with its proof"
        );
        b.put_family(dissolved)
            .await
            .unwrap_or_else(|e| panic!("{tag} I280: B applies the dissolution: {e}"));
        for (d, who) in [(a, "A"), (b, "B")] {
            assert_eq!(
                held(d, &w.id).await.dissolved_at,
                Some(at(DISSOLVED)),
                "{tag} I280: {who} holds the dissolution the quorum signed"
            );
            assert!(
                d.active_family_members(&w.id).await.unwrap().is_empty(),
                "{tag} I280: a dissolved family has no active members on {who}"
            );
        }
        assert_eq!(
            held(a, &w.id).await.persist_row_hash,
            held(b, &w.id).await.persist_row_hash,
            "{tag} I280: one record"
        );
    }

    /// **I281** — only a quorum-verified terminal amendment dissolves.
    pub async fn i281_only_a_quorum_terminal_amendment_dissolves(
        a: &dyn FederationDirectory,
        b: &dyn FederationDirectory,
        tag: &str,
    ) {
        let w = world(a, b, tag).await;
        let alice = &w.keys[0];
        let bob = &w.keys[1];
        let all: Vec<&String> = w.keys.iter().collect();
        let t = at(DISSOLVED);
        let mut rec = family(&w, &all, "household");
        rec.dissolved_at = Some(t);
        // One signature: below the family's majority.
        let (env, sigs) = change(a, &w, &all, Some(t), &[alice]).await;
        let e = a
            .supersede_family_with_quorum(ts::sign_family(alice, rec.clone()), env, sigs)
            .await
            .expect_err("one signature does not dissolve a majority family");
        assert!(e.to_string().contains("not authorized"), "{tag} I281: {e}");
        // The plain door: no quorum at all.
        let e = a
            .supersede_family(
                ts::sign_family(alice, rec.clone()),
                Some(serde_json::json!({ "quorum_signatures": "trust me" })),
            )
            .await
            .expect_err("the plain supersede door never dissolves");
        assert!(
            e.to_string().contains("only a quorum-verified amendment"),
            "{tag} I281: a caller-supplied authorization is no quorum: {e}"
        );
        // A founding record that arrives dissolved.
        let fresh = World {
            id: format!("{tag}-born-dissolved"),
            keys: w.keys.clone(),
        };
        let mut born = family(&fresh, &all, "household");
        born.dissolved_at = Some(t);
        let e = a
            .put_family(ts::sign_family(alice, born))
            .await
            .expect_err("a family is never founded dissolved");
        assert!(
            e.to_string().contains("cannot be dissolved"),
            "{tag} I281: {e}"
        );
        // A dissolution that also renames: not terminal-only.
        let mut renamed = rec.clone();
        renamed.family_name = "renamed on the way out".into();
        let (env, sigs) = change(a, &w, &all, Some(t), &[alice, bob]).await;
        let e = a
            .supersede_family_with_quorum(ts::sign_family(alice, renamed), env, sigs)
            .await
            .expect_err("a dissolution changes nothing but dissolved_at");
        assert!(
            e.to_string().contains("changes nothing but dissolved_at"),
            "{tag} I281: {e}"
        );
        // A dissolved record whose envelope the quorum signed WITHOUT a
        // dissolution (verify-A-store-B), on A and on B's apply.
        let (env, sigs) = change(a, &w, &all, None, &[alice, bob]).await;
        let e = a
            .supersede_family_with_quorum(ts::sign_family(alice, rec.clone()), env, sigs)
            .await
            .expect_err("the stored dissolution is the one the quorum signed");
        assert!(e.to_string().contains("dissolved_at"), "{tag} I281: {e}");
        let genuine = change(a, &w, &all, Some(t), &[alice, bob]).await;
        let mut forged = ts::sign_family(alice, {
            let mut r = rec.clone();
            r.dissolved_at = Some(at("2026-10-01T00:00:00Z"));
            r
        });
        forged.supersede_proof = Some(crate::federation::GroupSupersedeProof {
            prior_persist_row_hash: held(b, &w.id).await.persist_row_hash,
            change_envelope: genuine.0,
            quorum_signatures: genuine.1,
        });
        let e = b
            .put_family(forged)
            .await
            .expect_err("B refuses a dissolution instant the quorum did not sign");
        assert!(e.to_string().contains("dissolved_at"), "{tag} I281: {e}");
        for (d, who) in [(a, "A"), (b, "B")] {
            assert!(
                held(d, &w.id).await.dissolved_at.is_none(),
                "{tag} I281: the family stays live on {who}"
            );
            assert_eq!(d.active_family_members(&w.id).await.unwrap().len(), 3);
        }
    }

    /// **I282** — a dissolved family admits no further write.
    pub async fn i282_a_dissolved_family_admits_nothing(
        a: &dyn FederationDirectory,
        b: &dyn FederationDirectory,
        tag: &str,
    ) {
        let w = world(a, b, tag).await;
        let (alice, bob, carol) = (&w.keys[0], &w.keys[1], &w.keys[2]);
        let all: Vec<&String> = w.keys.iter().collect();
        // B applies the dissolution, then is offered a later amendment that
        // every member signed.
        // Before: a member may place a row at the family.
        a.check_write_cohort_scope_for(alice, "i282", "family", Some(&w.id))
            .await
            .unwrap_or_else(|e| panic!("{tag} I282: a member places a row at a live family: {e}"));
        let dissolved = dissolve_on_a(a, &w, tag).await;
        b.put_family(dissolved.clone()).await.unwrap();
        // After: no row is placed at it, whoever writes it — by name.
        let e = a
            .check_write_cohort_scope_for(alice, "i282", "family", Some(&w.id))
            .await
            .expect_err("no row is placed at a dissolved family");
        assert!(is_dissolved_refusal(&e), "{tag} I282: {e:?}");
        // The identical dissolved record again: the idempotent no-op.
        b.put_family(dissolved)
            .await
            .unwrap_or_else(|e| panic!("{tag} I282: the identical re-offer is Ok: {e}"));
        // A further amendment on A, signed by everyone: refused by name.
        let (env, sigs) = change(a, &w, &all, None, &[alice, bob, carol]).await;
        let e = a
            .supersede_family_with_quorum(
                ts::sign_family(alice, family(&w, &all, "revived")),
                env.clone(),
                sigs.clone(),
            )
            .await
            .expect_err("a dissolved family admits no amendment");
        assert!(is_dissolved_refusal(&e), "{tag} I282: {e:?}");
        // …and on B's apply, the same.
        let mut revived = ts::sign_family(alice, family(&w, &all, "revived"));
        revived.supersede_proof = Some(crate::federation::GroupSupersedeProof {
            prior_persist_row_hash: held(b, &w.id).await.persist_row_hash,
            change_envelope: env,
            quorum_signatures: sigs,
        });
        let e = b
            .put_family(revived)
            .await
            .expect_err("B refuses an amendment of a dissolved family");
        assert!(is_dissolved_refusal(&e), "{tag} I282: {e:?}");
        // A membership revocation naming the dissolved family.
        let now = chrono::Utc::now();
        let rev = ts::sign_family_membership_revocation(
            carol,
            crate::federation::types::FamilyMembershipRevocation {
                family_key_id: w.id.clone(),
                removed_identity_key_id: carol.clone(),
                removed_at: now,
                effective_at: now,
                reason: Some("I282".into()),
                witness_set: vec![],
                persist_row_hash: String::new(),
            },
        );
        let e = a
            .put_family_membership_revocation(rev)
            .await
            .expect_err("no roster row names a dissolved family");
        assert!(is_dissolved_refusal(&e), "{tag} I282: {e:?}");
        assert_eq!(held(a, &w.id).await.dissolved_at, Some(at(DISSOLVED)));
    }

    /// Carol's own amendment removing only herself.
    async fn carol_leaves(
        a: &dyn FederationDirectory,
        w: &World,
    ) -> (
        Family,
        serde_json::Value,
        Vec<ciris_verify_core::threshold::ThresholdSignature>,
    ) {
        let (alice, bob, carol) = (&w.keys[0], &w.keys[1], &w.keys[2]);
        let (env, sigs) = change(a, w, &[alice, bob], None, &[carol]).await;
        (family(w, &[alice, bob], "household"), env, sigs)
    }

    /// **I283** — a self-leave is admitted on the leaver's signature alone.
    pub async fn i283_a_self_leave_needs_only_the_leaver(
        a: &dyn FederationDirectory,
        b: &dyn FederationDirectory,
        tag: &str,
    ) {
        let w = world(a, b, tag).await;
        let carol = &w.keys[2];
        let (rec, env, sigs) = carol_leaves(a, &w).await;
        a.supersede_family_with_quorum(ts::sign_family(carol, rec), env, sigs)
            .await
            .unwrap_or_else(|e| panic!("{tag} I283: carol leaves on her own signature: {e}"));
        let left = served(a, &w.id).await;
        b.put_family(left)
            .await
            .unwrap_or_else(|e| panic!("{tag} I283: B applies carol's leave: {e}"));
        for (d, who) in [(a, "A"), (b, "B")] {
            let members: Vec<String> = held(d, &w.id)
                .await
                .members
                .into_iter()
                .map(|m| m.key_id)
                .collect();
            assert_eq!(
                members,
                vec![w.keys[0].clone(), w.keys[1].clone()],
                "{tag} I283: {who} holds the roster without carol"
            );
            assert!(
                !d.active_family_members(&w.id)
                    .await
                    .unwrap()
                    .iter()
                    .any(|m| &m.key_id == carol),
                "{tag} I283: carol is not active on {who}"
            );
        }
    }

    /// **I284** — the self-leave arm admits nothing but a self-leave.
    pub async fn i284_the_leave_arm_admits_only_a_leave(
        a: &dyn FederationDirectory,
        b: &dyn FederationDirectory,
        tag: &str,
    ) {
        let w = world(a, b, tag).await;
        let (alice, bob, carol) = (&w.keys[0], &w.keys[1], &w.keys[2]);
        let refused = |e: &Error| {
            let m = e.to_string();
            m.contains("not authorized") || m.contains("self-leave")
        };
        // Carol removes BOB, on her own signature.
        let (env, sigs) = change(a, &w, &[alice, carol], None, &[carol]).await;
        let e = a
            .supersede_family_with_quorum(
                ts::sign_family(carol, family(&w, &[alice, carol], "household")),
                env,
                sigs,
            )
            .await
            .expect_err("one member cannot remove another");
        assert!(refused(&e), "{tag} I284 (removes bob): {e}");
        // Carol leaves AND renames the family.
        let (env, sigs) = change(a, &w, &[alice, bob], None, &[carol]).await;
        let e = a
            .supersede_family_with_quorum(
                ts::sign_family(carol, family(&w, &[alice, bob], "carol's rename")),
                env,
                sigs,
            )
            .await
            .expect_err("a leave changes nothing but the leaver's seat");
        assert!(refused(&e), "{tag} I284 (renames): {e}");
        // Carol leaves AND re-roles alice.
        let mut reroled = family(&w, &[alice, bob], "household");
        reroled.members[0].role = Some("founder".into());
        let (env, sigs) = change(a, &w, &[alice, bob], None, &[carol]).await;
        let e = a
            .supersede_family_with_quorum(ts::sign_family(carol, reroled), env, sigs)
            .await
            .expect_err("a leave touches no other seat");
        assert!(refused(&e), "{tag} I284 (re-roles): {e}");
        // Carol's leave signed by BOB (not the leaver).
        let (env, sigs) = change(a, &w, &[alice, bob], None, &[bob]).await;
        let e = a
            .supersede_family_with_quorum(
                ts::sign_family(bob, family(&w, &[alice, bob], "household")),
                env,
                sigs,
            )
            .await
            .expect_err("only the leaver authorizes a leave");
        assert!(refused(&e), "{tag} I284 (not the leaver): {e}");
        // On B's apply: a leave record whose signature is bob's under carol's
        // member id.
        let (rec, env, _) = carol_leaves(a, &w).await;
        let bytes = ciris_verify_core::jcs::canonicalize(&env).unwrap();
        let mut forged_sig = ts::threshold_sign(bob, &bytes);
        forged_sig.member_id = carol.clone();
        let mut offered = ts::sign_family(carol, rec);
        offered.supersede_proof = Some(crate::federation::GroupSupersedeProof {
            prior_persist_row_hash: held(b, &w.id).await.persist_row_hash,
            change_envelope: env,
            quorum_signatures: vec![forged_sig],
        });
        let e = b
            .put_family(offered)
            .await
            .expect_err("B verifies the leaver's own key");
        assert!(refused(&e), "{tag} I284 (forged leaver sig): {e}");
        for d in [a, b] {
            assert_eq!(
                held(d, &w.id).await.members.len(),
                3,
                "{tag} I284: nothing changed"
            );
        }
    }

    /// **I285** — a live record carries no `dissolved_at`.
    #[test]
    fn i285_a_live_record_keeps_its_bytes() {
        let w = World {
            id: "i285-fam".into(),
            keys: vec!["i285-a".into()],
        };
        let all: Vec<&String> = w.keys.iter().collect();
        let live = family(&w, &all, "household");
        let v = serde_json::to_value(&live).unwrap();
        assert!(v.get("dissolved_at").is_none(), "{v}");
        assert!(live.signing_envelope().get("dissolved_at").is_none());
        let mut dead = live.clone();
        dead.dissolved_at = Some(at(DISSOLVED));
        assert!(dead.signing_envelope().get("dissolved_at").is_some());
        assert_ne!(
            crate::federation::types::compute_persist_row_hash(&live).unwrap(),
            crate::federation::types::compute_persist_row_hash(&dead).unwrap(),
            "the dissolution is part of the record's content"
        );
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
                macro_rules! case {
                    ($name:ident, $body:path, $tag:literal) => {
                        #[tokio::test]
                        async fn $name() {
                            let (Some(a), Some(b)) = ($fresh.await, $fresh.await) else {
                                return;
                            };
                            $body(
                                &a as &dyn FederationDirectory,
                                &b as &dyn FederationDirectory,
                                &format!("{}-{}", $tag, super::suffix()),
                            )
                            .await
                        }
                    };
                }
                case!(
                    i280,
                    super::super::bodies::i280_a_quorum_dissolution_replicates,
                    "i280"
                );
                case!(
                    i281,
                    super::super::bodies::i281_only_a_quorum_terminal_amendment_dissolves,
                    "i281"
                );
                case!(
                    i282,
                    super::super::bodies::i282_a_dissolved_family_admits_nothing,
                    "i282"
                );
                case!(
                    i283,
                    super::super::bodies::i283_a_self_leave_needs_only_the_leaver,
                    "i283"
                );
                case!(
                    i284,
                    super::super::bodies::i284_the_leave_arm_admits_only_a_leave,
                    "i284"
                );
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
