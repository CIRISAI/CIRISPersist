//! v49.0.0 (CIRISPersist#912; `FSD/ROOM_ROSTER_AUTHORITY.md` §11) — **a
//! listing is the member's own, and only the listed are enumerable.**
//!
//! I183 — in a `founder_only` room (founder alice, members bob and carol):
//! a member lists themself and appears in `listed_members`, nobody else does;
//! the founder cannot list anyone (`envelope_listed_not_self_asserted`, no row
//! stored); a value other than `public` is refused (`envelope_listed_bad_value`);
//! a later clear un-lists and both rows stay stored; a listing belongs to the
//! membership span it was made in (operator ruling 2026-09-25) — a non-member's
//! listing is stored and stays inert after they are widened in until they list
//! again, a removed member's listing stops appearing, a removed-then-re-added
//! member is unlisted until they list again, and a role change is not a new
//! span; a family id is `envelope_listed_scope_invalid`; two directories
//! converge through the signed since-read.

/// The backend-agnostic witness bodies; `run` instantiates them per backend.
#[cfg(test)]
pub mod bodies {
    use crate::federation::listing::{
        LISTED_PUBLIC, LISTED_RULE_BAD_VALUE, LISTED_RULE_NOT_SELF_ASSERTED,
        LISTED_RULE_SCOPE_INVALID,
    };
    use crate::federation::room_roster_authority_invariants::bodies::make_group;
    use crate::federation::tier_ingest::test_support as ts;
    use crate::federation::types::{
        consensus_protocol, identity_type, CommunityMembershipListing,
        CommunityMembershipRevocation, CommunityMembershipWidening,
    };
    use crate::federation::{Error, FederationDirectory};

    fn at(s: &str) -> chrono::DateTime<chrono::Utc> {
        s.parse().expect("rfc3339")
    }

    fn listing(
        room: &str,
        member: &str,
        effective_at: &str,
        listed: Option<&str>,
    ) -> CommunityMembershipListing {
        CommunityMembershipListing {
            community_key_id: room.to_owned(),
            member_key_id: member.to_owned(),
            effective_at: at(effective_at),
            listed: listed.map(str::to_owned),
            persist_row_hash: String::new(),
        }
    }

    async fn list_as(
        d: &dyn FederationDirectory,
        signer: &str,
        l: CommunityMembershipListing,
    ) -> Result<(), Error> {
        d.put_community_membership_listing(ts::sign_community_membership_listing(signer, l))
            .await
    }

    async fn widen(
        d: &dyn FederationDirectory,
        signer: &str,
        room: &str,
        member: &str,
        t: &str,
        role: Option<&str>,
    ) {
        d.put_community_membership_widening(ts::sign_community_membership_widening(
            signer,
            CommunityMembershipWidening {
                community_key_id: room.to_owned(),
                member_key_id: member.to_owned(),
                joined_at: at(t),
                effective_at: at(t),
                role: role.map(str::to_owned),
                persist_row_hash: String::new(),
            },
        ))
        .await
        .unwrap_or_else(|e| panic!("widen {member}: {e}"));
    }

    async fn revoke(d: &dyn FederationDirectory, signer: &str, room: &str, member: &str, t: &str) {
        d.put_community_membership_revocation(ts::sign_community_membership_revocation(
            signer,
            CommunityMembershipRevocation {
                community_key_id: room.to_owned(),
                removed_identity_key_id: member.to_owned(),
                removed_at: at(t),
                effective_at: at(t),
                reason: None,
                witness_set: vec![],
                persist_row_hash: String::new(),
            },
        ))
        .await
        .unwrap_or_else(|e| panic!("revoke {member}: {e}"));
    }

    async fn listed(d: &dyn FederationDirectory, room: &str) -> Vec<String> {
        d.listed_members(room)
            .await
            .unwrap()
            .into_iter()
            .map(|m| m.key_id)
            .collect()
    }

    async fn rows_of(d: &dyn FederationDirectory, room: &str, member: &str) -> usize {
        d.list_community_membership_listings_for(room)
            .await
            .unwrap()
            .iter()
            .filter(|l| l.member_key_id == member)
            .count()
    }

    fn rule_of(e: &Error) -> &'static str {
        match e {
            Error::MembershipListingRefused { rule, .. } => rule,
            other => panic!("expected MembershipListingRefused, got {other}"),
        }
    }

    /// The room: founder alice, members bob and carol, `founder_only` — so
    /// alice's single signature widens and removes (CC 4.4.3.4.2), and a
    /// founder is the strongest party that could try to list someone.
    async fn room_of(d: &dyn FederationDirectory, tag: &str) -> (String, [String; 3]) {
        let (room, k) = make_group(
            d,
            tag,
            consensus_protocol::FOUNDER_ONLY,
            &["alice", "bob", "carol"],
            1,
            None,
            None,
        )
        .await;
        (room, [k[0].clone(), k[1].clone(), k[2].clone()])
    }

    /// **I183 — a listing is the member's own, and only the listed are
    /// enumerable.**
    #[allow(clippy::too_many_lines)]
    pub async fn i183_the_listing_is_the_members_own(d: &dyn FederationDirectory, tag: &str) {
        let (room, [alice, bob, carol]) = room_of(d, tag).await;
        assert!(
            listed(d, &room).await.is_empty(),
            "{tag} I183: absent is the default — a private roster"
        );

        // ── bob lists himself ─────────────────────────────────────────
        list_as(
            d,
            &bob,
            listing(&room, &bob, "2026-03-01T00:00:00Z", Some(LISTED_PUBLIC)),
        )
        .await
        .unwrap_or_else(|e| panic!("{tag} I183: bob lists himself: {e}"));
        assert_eq!(
            listed(d, &room).await,
            vec![bob.clone()],
            "{tag} I183: bob chose it; carol did not"
        );

        // ── the founder cannot list anyone ────────────────────────────
        for target in [&carol, &bob] {
            let e = list_as(
                d,
                &alice,
                listing(&room, target, "2026-03-02T00:00:00Z", Some(LISTED_PUBLIC)),
            )
            .await
            .expect_err("I183: a founder listing a member");
            assert_eq!(
                rule_of(&e),
                LISTED_RULE_NOT_SELF_ASSERTED,
                "{tag} I183: the substrate does not solicit (CC 2)"
            );
            assert_eq!(e.kind(), "federation_membership_listing_refused");
        }
        // A founder clearing someone else's listing is the same refusal: the
        // choice is the member's in both directions.
        let e = list_as(
            d,
            &alice,
            listing(&room, &bob, "2026-03-02T00:00:00Z", None),
        )
        .await
        .expect_err("I183: a founder clearing a member's listing");
        assert_eq!(rule_of(&e), LISTED_RULE_NOT_SELF_ASSERTED);
        assert_eq!(rows_of(d, &room, &carol).await, 0, "{tag} I183: no row");
        assert_eq!(rows_of(d, &room, &bob).await, 1, "{tag} I183: no row");
        assert_eq!(listed(d, &room).await, vec![bob.clone()]);

        // ── one value ─────────────────────────────────────────────────
        let e = list_as(
            d,
            &carol,
            listing(&room, &carol, "2026-03-03T00:00:00Z", Some("private")),
        )
        .await
        .expect_err("I183: listed = private");
        assert_eq!(rule_of(&e), LISTED_RULE_BAD_VALUE, "{tag} I183");
        assert_eq!(rows_of(d, &room, &carol).await, 0, "{tag} I183: no row");

        // ── no future-dating; an unknown room; a family is no roster ──
        let future = (chrono::Utc::now() + chrono::Duration::days(1)).to_rfc3339();
        let e = list_as(
            d,
            &carol,
            listing(&room, &carol, &future, Some(LISTED_PUBLIC)),
        )
        .await
        .expect_err("I183: future-dated");
        assert!(matches!(e, Error::InvalidArgument(_)), "{tag} I183: {e}");
        let e = list_as(
            d,
            &carol,
            listing(
                &format!("{tag}-nowhere"),
                &carol,
                "2026-03-03T00:00:00Z",
                Some(LISTED_PUBLIC),
            ),
        )
        .await
        .expect_err("I183: unknown room");
        assert!(matches!(e, Error::InvalidArgument(_)), "{tag} I183: {e}");
        let (family, fk) = crate::federation::family_roster_invariants::bodies::make_family(
            d,
            tag,
            "fam",
            consensus_protocol::FOUNDER_ONLY,
            &["fa", "fb"],
            1,
        )
        .await;
        let e = list_as(
            d,
            &fk[1],
            listing(&family, &fk[1], "2026-03-03T00:00:00Z", Some(LISTED_PUBLIC)),
        )
        .await
        .expect_err("I183: a family id");
        assert_eq!(
            rule_of(&e),
            LISTED_RULE_SCOPE_INVALID,
            "{tag} I183: family membership is structurally invisible (CC 5.2)"
        );

        // ── an exact retry is a no-op ─────────────────────────────────
        let bob_row = ts::sign_community_membership_listing(
            &bob,
            listing(&room, &bob, "2026-03-01T00:00:00Z", Some(LISTED_PUBLIC)),
        );
        d.put_community_membership_listing(bob_row.clone())
            .await
            .unwrap_or_else(|e| panic!("{tag} I183: identical re-put: {e}"));
        assert_eq!(rows_of(d, &room, &bob).await, 1, "{tag} I183: idempotent");

        // ── bob clears it later; both rows stay ───────────────────────
        list_as(d, &bob, listing(&room, &bob, "2026-03-05T00:00:00Z", None))
            .await
            .unwrap_or_else(|e| panic!("{tag} I183: bob clears: {e}"));
        assert!(
            listed(d, &room).await.is_empty(),
            "{tag} I183: the later clear decides"
        );
        assert_eq!(
            rows_of(d, &room, &bob).await,
            2,
            "{tag} I183: forward-only — the set row is not rewritten"
        );
        let at_the_time = crate::federation::listing::listed_community_members_at(
            d,
            &room,
            at("2026-03-04T00:00:00Z"),
        )
        .await
        .unwrap();
        assert_eq!(
            at_the_time.iter().map(|m| &m.key_id).collect::<Vec<_>>(),
            vec![&bob],
            "{tag} I183: read at an earlier instant, bob was listed"
        );

        // ── a pre-join listing is stored and stays inert ──────────────
        // (operator ruling 2026-09-25: a listing belongs to the membership it
        // was made in; consent outranks listing before joining)
        let dave = format!("{tag}-dave");
        ts::register_hybrid_key_as(d, &dave, &dave, identity_type::USER).await;
        list_as(
            d,
            &dave,
            listing(&room, &dave, "2026-03-06T00:00:00Z", Some(LISTED_PUBLIC)),
        )
        .await
        .unwrap_or_else(|e| panic!("{tag} I183: a non-member's listing is stored: {e}"));
        assert_eq!(rows_of(d, &room, &dave).await, 1);
        assert!(
            listed(d, &room).await.is_empty(),
            "{tag} I183: a non-member is never listed"
        );
        widen(d, &alice, &room, &dave, "2026-03-07T00:00:00Z", None).await;
        assert!(
            listed(d, &room).await.is_empty(),
            "{tag} I183: dave's pre-join listing does NOT carry into his membership"
        );
        list_as(
            d,
            &dave,
            listing(&room, &dave, "2026-03-07T12:00:00Z", Some(LISTED_PUBLIC)),
        )
        .await
        .unwrap_or_else(|e| panic!("{tag} I183: dave lists as a member: {e}"));
        assert_eq!(
            listed(d, &room).await,
            vec![dave.clone()],
            "{tag} I183: dave is listed once he chooses it as a member"
        );

        // ── a removed member drops out; their row stays ───────────────
        list_as(
            d,
            &carol,
            listing(&room, &carol, "2026-03-08T00:00:00Z", Some(LISTED_PUBLIC)),
        )
        .await
        .unwrap_or_else(|e| panic!("{tag} I183: carol lists herself: {e}"));
        assert_eq!(listed(d, &room).await, vec![carol.clone(), dave.clone()]);
        revoke(d, &alice, &room, &carol, "2026-03-09T00:00:00Z").await;
        assert_eq!(
            listed(d, &room).await,
            vec![dave.clone()],
            "{tag} I183: a removed member's listing no longer appears"
        );
        assert_eq!(rows_of(d, &room, &carol).await, 1);

        // ── a removal ends the listing: re-added, unlisted until chosen ─
        list_as(
            d,
            &bob,
            listing(&room, &bob, "2026-03-10T00:00:00Z", Some(LISTED_PUBLIC)),
        )
        .await
        .unwrap_or_else(|e| panic!("{tag} I183: bob lists again: {e}"));
        assert_eq!(listed(d, &room).await, vec![bob.clone(), dave.clone()]);
        revoke(d, &alice, &room, &bob, "2026-03-11T00:00:00Z").await;
        widen(d, &alice, &room, &bob, "2026-03-12T00:00:00Z", None).await;
        assert_eq!(
            listed(d, &room).await,
            vec![dave.clone()],
            "{tag} I183: a re-added member is unlisted until they list again"
        );
        list_as(
            d,
            &bob,
            listing(&room, &bob, "2026-03-13T00:00:00Z", Some(LISTED_PUBLIC)),
        )
        .await
        .unwrap_or_else(|e| panic!("{tag} I183: bob lists in his new membership: {e}"));
        assert_eq!(listed(d, &room).await, vec![bob.clone(), dave.clone()]);

        // ── a role change is not a new membership ─────────────────────
        widen(
            d,
            &alice,
            &room,
            &dave,
            "2026-03-14T00:00:00Z",
            Some("editor"),
        )
        .await;
        let roles: Vec<_> = d
            .listed_members(&room)
            .await
            .unwrap()
            .into_iter()
            .map(|m| (m.key_id, m.role))
            .collect();
        assert_eq!(
            roles,
            vec![
                (bob.clone(), None),
                (dave.clone(), Some("editor".to_owned()))
            ],
            "{tag} I183: a listed member whose role changes stays listed"
        );

        // ── the served row is the signed row, byte-exact ──────────────
        let served: Vec<_> = d
            .list_signed_community_membership_listings_since(None, u32::MAX)
            .await
            .unwrap()
            .into_iter()
            .filter(|l| l.listing.community_membership_listing.community_key_id == room)
            .collect();
        assert_eq!(served.len(), 7, "{tag} I183: bob ×4, dave ×2, carol");
        let first = served
            .iter()
            .find(|l| {
                l.listing.community_membership_listing.effective_at == at("2026-03-01T00:00:00Z")
            })
            .expect("bob's listing is served");
        let mut expect = bob_row;
        expect.community_membership_listing.persist_row_hash = first
            .listing
            .community_membership_listing
            .persist_row_hash
            .clone();
        assert_eq!(
            serde_json::to_vec(&first.listing).unwrap(),
            serde_json::to_vec(&expect).unwrap(),
            "{tag} I183: served byte-exact"
        );
        crate::federation::listing::check_community_membership_listing(d, &first.listing)
            .await
            .unwrap_or_else(|e| panic!("{tag} I183: the served row re-admits: {e}"));
    }

    /// **I183 (convergence)** — B holds the same room and roster history; A's
    /// listings reach B only through the signed since-read, paged by the pair
    /// cursor, and the two directories agree on `listed_members` and on the
    /// stored rows.
    pub async fn i183_two_directories_converge(
        a: &dyn FederationDirectory,
        b: &dyn FederationDirectory,
        tag: &str,
    ) {
        let (room, [alice, bob, carol]) = room_of(a, tag).await;
        let (room_b, _) = room_of(b, tag).await;
        assert_eq!(room, room_b);
        let dave = format!("{tag}-dave");
        for d in [a, b] {
            ts::register_hybrid_key_as(d, &dave, &dave, identity_type::USER).await;
        }
        list_as(
            a,
            &bob,
            listing(&room, &bob, "2026-03-01T00:00:00Z", Some(LISTED_PUBLIC)),
        )
        .await
        .unwrap();
        list_as(
            a,
            &carol,
            listing(&room, &carol, "2026-03-02T00:00:00Z", Some(LISTED_PUBLIC)),
        )
        .await
        .unwrap();
        list_as(a, &bob, listing(&room, &bob, "2026-03-03T00:00:00Z", None))
            .await
            .unwrap();
        list_as(
            a,
            &dave,
            listing(&room, &dave, "2026-03-04T00:00:00Z", Some(LISTED_PUBLIC)),
        )
        .await
        .unwrap();
        for d in [a, b] {
            widen(d, &alice, &room, &dave, "2026-03-05T00:00:00Z", None).await;
        }
        // dave's 03-04 row predates his membership (inert); this one counts.
        list_as(
            a,
            &dave,
            listing(&room, &dave, "2026-03-06T00:00:00Z", Some(LISTED_PUBLIC)),
        )
        .await
        .unwrap();
        assert!(listed(b, &room).await.is_empty(), "{tag} I183: control");

        let mut cursor = None;
        let mut applied = 0;
        loop {
            let page = a
                .list_signed_community_membership_listings_since(cursor.clone(), 2)
                .await
                .unwrap();
            let Some(last) = page.last() else { break };
            cursor = Some(last.resume_pair());
            for row in page {
                b.put_community_membership_listing(row.listing)
                    .await
                    .unwrap_or_else(|e| panic!("{tag} I183: B applies A's row: {e}"));
                applied += 1;
            }
        }
        assert_eq!(applied, 5, "{tag} I183: every row crossed, once");
        let (la, lb) = (listed(a, &room).await, listed(b, &room).await);
        assert_eq!(la, vec![carol.clone(), dave.clone()], "{tag} I183: A");
        assert_eq!(la, lb, "{tag} I183: A and B agree on the listed members");
        assert_eq!(
            a.list_community_membership_listings_for(&room)
                .await
                .unwrap(),
            b.list_community_membership_listings_for(&room)
                .await
                .unwrap(),
            "{tag} I183: the same rows, the same row hashes"
        );
    }
}

#[cfg(test)]
mod run {
    /// A SHORT tag: the test signer seeds from a key id's first 32 bytes, so a
    /// 32-hex uuid tag in front of every member name would give the whole room
    /// one keypair.
    fn suffix() -> String {
        uuid::Uuid::new_v4().simple().to_string()[..8].to_owned()
    }

    macro_rules! dyn_runners {
        ($modname:ident, $fresh:expr) => {
            mod $modname {
                use crate::federation::FederationDirectory;
                #[tokio::test]
                async fn i183() {
                    let Some(d) = $fresh.await else { return };
                    super::super::bodies::i183_the_listing_is_the_members_own(
                        &d as &dyn FederationDirectory,
                        &format!("i183-{}", super::suffix()),
                    )
                    .await
                }
                #[tokio::test]
                async fn i183_converge() {
                    let (Some(a), Some(b)) = ($fresh.await, $fresh.await) else {
                        return;
                    };
                    super::super::bodies::i183_two_directories_converge(
                        &a as &dyn FederationDirectory,
                        &b as &dyn FederationDirectory,
                        &format!("i183c-{}", super::suffix()),
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
