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
///
/// v62.0.0 (JSON-cut slice E4, flip wave 3; T1.api.md §6) — every version is
/// its own `group:roster` row: it names the version it extends by
/// `refs.head`, and each quorum signer is one voice over the same payload.
/// The door builds the change envelope itself (plus `dissolved_at`) and
/// counts the voices at the held head's protocol. A version short of the
/// protocol is KEPT as voices with no new head (`StatementOutcome::Pending`).
/// B learns a version by receiving the same statements (one entry, local or
/// replicated). Legs that only an earlier-form proof object could express
/// (a caller-supplied "quorum", a stored `dissolved_at` the quorum did not
/// sign, a forged threshold signature under another member id) cannot be
/// built and are gone (T1 §6 table).
#[cfg(test)]
pub mod bodies {
    #[cfg(any(feature = "sqlite", feature = "postgres"))]
    use crate::federation::edition2::fixture_switch as e2;
    #[cfg(any(feature = "sqlite", feature = "postgres"))]
    use crate::federation::edition2::ingest::StatementOutcome;
    #[cfg(any(feature = "sqlite", feature = "postgres"))]
    use crate::federation::tier_ingest::test_support as ts;
    #[cfg(any(feature = "sqlite", feature = "postgres"))]
    use crate::federation::types::identity_type;
    use crate::federation::types::{consensus_protocol, Family, FamilyMember};
    #[cfg(any(feature = "sqlite", feature = "postgres"))]
    use crate::federation::{Error, FederationDirectory};

    fn at(s: &str) -> chrono::DateTime<chrono::Utc> {
        s.parse().expect("rfc3339")
    }

    #[cfg(any(feature = "sqlite", feature = "postgres"))]
    fn ms(t: chrono::DateTime<chrono::Utc>) -> u64 {
        u64::try_from(t.timestamp_millis()).expect("after the epoch")
    }

    struct World {
        /// The family id: an identity-ref (`e2::kid`), as the typed row is
        /// keyed.
        id: String,
        /// The members: identity-refs (every seed-taking fixture accepts
        /// them back).
        keys: Vec<String>,
        /// v53.0.0 (CC 3.2 T6) — the founding version's hash.
        founding_hash: String,
    }

    fn family(w: &World, members: &[&String], name: &str) -> Family {
        let joined = at("2026-01-01T00:00:00Z");
        Family {
            prev_head_digest: w.founding_hash.clone(),
            charter_digest: String::new(),
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

    /// The `user` keys (no record end: the fixed 2026 instants stay live)
    /// and the founding version, on both directories.
    #[cfg(any(feature = "sqlite", feature = "postgres"))]
    async fn world(a: &dyn FederationDirectory, b: &dyn FederationDirectory, tag: &str) -> World {
        let keys: Vec<String> = ["alice", "bob", "carol"]
            .iter()
            .map(|n| e2::kid(&format!("{n}-{tag}")))
            .collect();
        for d in [a, b] {
            for k in &keys {
                e2::put_key(d, k, &[identity_type::USER]).await;
            }
        }
        let mut w = World {
            id: e2::kid(&format!("fam-{tag}")),
            keys,
            founding_hash: String::new(),
        };
        let all: Vec<&String> = w.keys.iter().collect();
        let founding = e2::family_voices(
            &ts::sign_family(&w.keys[0], family(&w, &all, "household")),
            1,
            None,
            ms(at("2026-01-01T00:00:00Z")),
        );
        for d in [a, b] {
            e2::put_voices(d, &founding)
                .await
                .unwrap_or_else(|e| panic!("{tag}: founding: {e}"));
        }
        w.founding_hash = held(a, &w.id).await.persist_row_hash;
        w
    }

    /// The next version of `w` as held on `d`: `rec`, one voice per signer,
    /// naming the held head (T1 §6).
    #[cfg(any(feature = "sqlite", feature = "postgres"))]
    async fn version(
        d: &dyn FederationDirectory,
        w: &World,
        rec: &Family,
        signers: &[&String],
        asserted: chrono::DateTime<chrono::Utc>,
    ) -> Vec<Vec<u8>> {
        use crate::federation::edition2::group::GroupRecord;
        let (head, v) = e2::held_head(d, &w.id).await.expect("a held head");
        let keys: Vec<_> = signers.iter().map(|k| e2::signing_key(k)).collect();
        let refs: Vec<&_> = keys.iter().collect();
        e2::roster_voices(
            &GroupRecord::Family(e2::family_with_kids(rec)),
            v + 1,
            Some(&head),
            ms(asserted),
            &refs,
        )
    }

    #[cfg(any(feature = "sqlite", feature = "postgres"))]
    async fn held(d: &dyn FederationDirectory, id: &str) -> Family {
        d.lookup_family(id).await.unwrap().expect("family")
    }

    #[cfg(any(feature = "sqlite", feature = "postgres"))]
    fn is_dissolved_refusal(e: &Error) -> bool {
        matches!(e, Error::GroupDissolved { .. }) && e.kind() == "federation_group_dissolved"
    }

    /// A version that did NOT move the head: kept short of the protocol
    /// (`Pending`), or refused by the self-leave arm.
    #[cfg(any(feature = "sqlite", feature = "postgres"))]
    fn not_landed(r: Result<StatementOutcome, Error>, what: &str) {
        match r {
            Ok(StatementOutcome::Pending { .. }) => {}
            Ok(other) => panic!("{what}: landed ({other:?})"),
            Err(e) => {
                let m = e.to_string();
                assert!(
                    m.contains("not authorized") || m.contains("self-leave"),
                    "{what}: {e}"
                );
            }
        }
    }

    const DISSOLVED: &str = "2026-09-30T12:00:00Z";

    /// The dissolution version of `w` (alice + bob, a majority of three),
    /// landed on `a`; returns its statements for B.
    #[cfg(any(feature = "sqlite", feature = "postgres"))]
    async fn dissolve_on_a(a: &dyn FederationDirectory, w: &World, tag: &str) -> Vec<Vec<u8>> {
        let (alice, bob) = (&w.keys[0], &w.keys[1]);
        let all: Vec<&String> = w.keys.iter().collect();
        let mut rec = family(w, &all, "household");
        rec.dissolved_at = Some(at(DISSOLVED));
        let voices = version(a, w, &rec, &[alice, bob], at(DISSOLVED)).await;
        let out = e2::put_voices(a, &voices)
            .await
            .unwrap_or_else(|e| panic!("{tag}: A's quorum dissolution: {e}"));
        assert!(
            matches!(out, StatementOutcome::Row { .. }),
            "{tag}: A's dissolution lands: {out:?}"
        );
        voices
    }

    /// **I280** — a quorum dissolution replicates.
    #[cfg(any(feature = "sqlite", feature = "postgres"))]
    pub async fn i280_a_quorum_dissolution_replicates(
        a: &dyn FederationDirectory,
        b: &dyn FederationDirectory,
        tag: &str,
    ) {
        let w = world(a, b, tag).await;
        assert_eq!(a.active_family_members(&w.id).await.unwrap().len(), 3);
        let dissolved = dissolve_on_a(a, &w, tag).await;
        e2::put_voices(b, &dissolved)
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
    #[cfg(any(feature = "sqlite", feature = "postgres"))]
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
        // One voice: below the family's majority — kept, no new head.
        let out = e2::put_voices(a, &version(a, &w, &rec, &[alice], t).await)
            .await
            .unwrap_or_else(|e| panic!("{tag} I281: a lone voice is kept: {e}"));
        assert!(
            matches!(out, StatementOutcome::Pending { .. }),
            "{tag} I281: one voice does not dissolve a majority family: {out:?}"
        );
        // A founding record that arrives dissolved.
        let fresh = World {
            id: e2::kid(&format!("born-dissolved-{tag}")),
            keys: w.keys.clone(),
            founding_hash: String::new(),
        };
        let mut born = family(&fresh, &all, "household");
        born.dissolved_at = Some(t);
        // v62 (E4 round 3; T1's founding rule): every founder voices the
        // birth, so the count is met and the record's own shape is judged.
        let founders: Vec<_> = all.iter().map(|k| e2::signing_key(k)).collect();
        let founder_refs: Vec<&_> = founders.iter().collect();
        let e = e2::put_voices(
            a,
            &e2::roster_voices(
                &crate::federation::edition2::group::GroupRecord::Family(e2::family_with_kids(
                    &born,
                )),
                1,
                None,
                ms(t),
                &founder_refs,
            ),
        )
        .await
        .expect_err("a family is never founded dissolved");
        assert!(
            e.to_string().contains("cannot be dissolved"),
            "{tag} I281: {e}"
        );
        // A dissolution that also renames: not terminal-only.
        let mut renamed = rec.clone();
        renamed.family_name = "renamed on the way out".into();
        let e = e2::put_voices(a, &version(a, &w, &renamed, &[alice, bob], t).await)
            .await
            .expect_err("a dissolution changes nothing but dissolved_at");
        assert!(
            e.to_string().contains("changes nothing but dissolved_at"),
            "{tag} I281: {e}"
        );
        for (d, who) in [(a, "A"), (b, "B")] {
            assert!(
                held(d, &w.id).await.dissolved_at.is_none(),
                "{tag} I281: the family stays live on {who}"
            );
            assert_eq!(d.active_family_members(&w.id).await.unwrap().len(), 3);
        }
    }

    /// **I282** — a dissolved family admits no further write.
    #[cfg(any(feature = "sqlite", feature = "postgres"))]
    pub async fn i282_a_dissolved_family_admits_nothing(
        a: &dyn FederationDirectory,
        b: &dyn FederationDirectory,
        tag: &str,
    ) {
        let w = world(a, b, tag).await;
        let (alice, bob, carol) = (&w.keys[0], &w.keys[1], &w.keys[2]);
        let all: Vec<&String> = w.keys.iter().collect();
        // Before: a member may place a row at the family.
        a.check_write_cohort_scope_for(alice, "i282", "family", Some(&w.id))
            .await
            .unwrap_or_else(|e| panic!("{tag} I282: a member places a row at a live family: {e}"));
        let dissolved = dissolve_on_a(a, &w, tag).await;
        e2::put_voices(b, &dissolved).await.unwrap();
        // After: no row is placed at it, whoever writes it — by name.
        let e = a
            .check_write_cohort_scope_for(alice, "i282", "family", Some(&w.id))
            .await
            .expect_err("no row is placed at a dissolved family");
        assert!(is_dissolved_refusal(&e), "{tag} I282: {e:?}");
        // The identical dissolution again: the idempotent no-op.
        e2::put_voices(b, &dissolved)
            .await
            .unwrap_or_else(|e| panic!("{tag} I282: the identical re-offer is Ok: {e}"));
        // A further version, voiced by everyone: refused by name, on A and B.
        let now = chrono::Utc::now();
        for (d, who) in [(a, "A"), (b, "B")] {
            let r = e2::put_voices(
                d,
                &version(
                    d,
                    &w,
                    &family(&w, &all, "revived"),
                    &[alice, bob, carol],
                    now,
                )
                .await,
            )
            .await;
            // v62 (E4 round 3; CC 2.7.3): read against the held (dissolved)
            // head, the amendment is held or refused by name; either way it
            // concludes nothing.
            match &r {
                Ok(StatementOutcome::Pending { .. }) => {}
                Err(e) => assert!(is_dissolved_refusal(e), "{tag} I282 on {who}: {e:?}"),
                Ok(other) => {
                    panic!("{tag} I282 on {who}: a dissolved family admits no amendment: {other:?}")
                }
            }
            assert!(
                held(d, &w.id).await.dissolved_at.is_some(),
                "{tag} I282 on {who}: still dissolved"
            );
        }
        // A membership revocation naming the dissolved family.
        let (head, _) = e2::held_head(a, &w.id).await.expect("held");
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
        // v62 (E4-fix6; CC 2.7.3): read against the held (dissolved) head,
        // the revocation is held or refused by name; it concludes nothing.
        match e2::put_voices(a, &e2::family_revocation_voices(&rev, Some(&head))).await {
            Ok(StatementOutcome::Pending { .. }) => {}
            Err(e) => assert!(is_dissolved_refusal(&e), "{tag} I282: {e:?}"),
            Ok(other) => panic!("{tag} I282: no roster row names a dissolved family: {other:?}"),
        }
        assert_eq!(held(a, &w.id).await.dissolved_at, Some(at(DISSOLVED)));
    }

    /// **I283** — a self-leave is admitted on the leaver's voice alone.
    #[cfg(any(feature = "sqlite", feature = "postgres"))]
    pub async fn i283_a_self_leave_needs_only_the_leaver(
        a: &dyn FederationDirectory,
        b: &dyn FederationDirectory,
        tag: &str,
    ) {
        let w = world(a, b, tag).await;
        let (alice, bob, carol) = (&w.keys[0], &w.keys[1], &w.keys[2]);
        let leave = version(
            a,
            &w,
            &family(&w, &[alice, bob], "household"),
            &[carol],
            chrono::Utc::now(),
        )
        .await;
        let out = e2::put_voices(a, &leave)
            .await
            .unwrap_or_else(|e| panic!("{tag} I283: carol leaves on her own voice: {e}"));
        assert!(
            matches!(out, StatementOutcome::Row { .. }),
            "{tag} I283: the leave lands: {out:?}"
        );
        e2::put_voices(b, &leave)
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
                vec![alice.clone(), bob.clone()],
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

    /// **I284** — the self-leave arm admits nothing but a self-leave: each
    /// version below is kept short of the protocol or refused, and the head
    /// does not move.
    #[cfg(any(feature = "sqlite", feature = "postgres"))]
    pub async fn i284_the_leave_arm_admits_only_a_leave(
        a: &dyn FederationDirectory,
        b: &dyn FederationDirectory,
        tag: &str,
    ) {
        let w = world(a, b, tag).await;
        let (alice, bob, carol) = (&w.keys[0], &w.keys[1], &w.keys[2]);
        let now = chrono::Utc::now();
        // Carol removes BOB, on her own voice.
        not_landed(
            e2::put_voices(
                a,
                &version(
                    a,
                    &w,
                    &family(&w, &[alice, carol], "household"),
                    &[carol],
                    now,
                )
                .await,
            )
            .await,
            &format!("{tag} I284 (removes bob)"),
        );
        // Carol leaves AND renames the family.
        not_landed(
            e2::put_voices(
                a,
                &version(
                    a,
                    &w,
                    &family(&w, &[alice, bob], "carol's rename"),
                    &[carol],
                    now,
                )
                .await,
            )
            .await,
            &format!("{tag} I284 (renames)"),
        );
        // Carol leaves AND re-roles alice.
        let mut reroled = family(&w, &[alice, bob], "household");
        reroled.members[0].role = Some("founder".into());
        not_landed(
            e2::put_voices(a, &version(a, &w, &reroled, &[carol], now).await).await,
            &format!("{tag} I284 (re-roles)"),
        );
        // Carol's leave voiced by BOB (not the leaver), on B.
        not_landed(
            e2::put_voices(
                b,
                &version(b, &w, &family(&w, &[alice, bob], "household"), &[bob], now).await,
            )
            .await,
            &format!("{tag} I284 (not the leaver)"),
        );
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
            founding_hash: String::new(),
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

#[cfg(all(test, any(feature = "sqlite", feature = "postgres")))]
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
