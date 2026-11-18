//! v62.0.0 (v62 P5; the v62 security ruling "A serve-seat node needs an
//! announced owner … Agents are never exempt"; CC rc20 5.4.6, 3.2) —
//! **I3110–I3113: a seat serves only with an announced owner, an agent is
//! never exempt, and an unowned seat's own accountability rows still flow.**
//! sqlite and postgres.
//!
//! CC 5.4.6: "A node that holds a `serve` seat in an `infrastructure`
//! community MUST have an announced owner … While the node holds the seat, a
//! live owner-binding for it MUST exist at `cohort_scope: federation` … While
//! no such binding exists the node does not serve under the seat, refused
//! `serve_seat_owner_unannounced`; nothing in the genesis bundle or the
//! holders' ceremony carries or seeds the binding." Under ruling C a seat is
//! membership in `serve_nodes` of the genesis bundle in force, so every seat
//! a bundle places starts unowned.
//!
//! - **I3110** — an unowned bundle seat is SEATED (`is_canonical`) but does
//!   not serve: `serves_under_seat` / `seat_serve_standing` are false, its
//!   serve tier is not `Canonical`, and it is no trust root (its corpus gets
//!   `ProducerSteward` reach).
//! - **I3111** — once its owner announces it (a live owner binding at
//!   `federation`, the node's voice on it), the same seat serves: `Canonical`
//!   tier, trust-root reach. The owner withdrawing the binding takes the
//!   standing away at once (the test is live, CC 2.7.5).
//! - **I3112** — an agent is never exempt: a trust-root room (the door's
//!   verdict is "authorized infrastructure") listing an unstewarded `agent`
//!   member is refused `UnstewardedCommunityMember` and nothing is stored;
//!   the same room with only its unstewarded `node` member admits.
//! - **I3113** — an unowned seat's own `hard_case:*` statement is admitted
//!   and held: the rule withholds serve standing, never the node's
//!   accountability records.
//!
//! Mutations: drop `serve_seat_owner_announced` from `serves_under_seat` and
//! I3110 reds; make `seat_serve_standing` ignore the identity-ref branch and
//! I3111's announced legs red; restore `if !trust_root` around the
//! steward-binding gate in `community_admit::plan_put_community` and I3112
//! reds (the agent is admitted).

/// The backend-agnostic witness bodies; `run` instantiates them per backend.
#[cfg(all(test, any(feature = "sqlite", feature = "postgres")))]
pub(crate) mod bodies {
    use crate::federation::admission::{
        is_canonical, seat_serve_standing, serve_seat_owner_announced, serves_under_seat,
    };
    use crate::federation::canonical_community_invariants::bodies as cci;
    use crate::federation::edition2::fixture_genesis as fg;
    use crate::federation::edition2::fixture_switch as e2;
    use crate::federation::hard_case::{self, HardCaseEvent};
    use crate::federation::namespace::{holdings_authority, is_trust_root, AuthorityClass};
    use crate::federation::tier_ingest::test_support as ts;
    use crate::federation::trust_root::{resolve_serve_tier, ServeTier};
    use crate::federation::types::{attestation_type, identity_type, Attestation};
    use crate::federation::{Error, FederationDirectory};
    use ciris_verify_core::cde::Value;

    /// Now, at the millisecond the edition-2 wire carries, a minute back so a
    /// row never lands in its signer's future.
    fn now_ms() -> chrono::DateTime<chrono::Utc> {
        chrono::DateTime::<chrono::Utc>::from_timestamp_millis(
            chrono::Utc::now().timestamp_millis() - 60_000,
        )
        .expect("ms")
    }

    /// `statement` re-signed by bundle seat `i` (a further voice, or the
    /// seat's own row): the same row type, family, subject and payload, `iss`
    /// the seat. Synchronous, so the multi-KiB composite key never crosses an
    /// `.await` (the 2 MiB test-thread stack).
    fn seat_signed(statement: &[u8], i: usize) -> Vec<u8> {
        let c = fg::bundle_v2();
        let key = Box::new(c.serve_node_key(i));
        let iss = c.serve_node_identity_ref(i).to_owned();
        let (protected, payload) =
            crate::federation::edition2::liveness::statement_parts(statement)
                .expect("a row statement");
        let header = |label: i64| -> String {
            protected
                .get_int(label)
                .and_then(Value::as_text)
                .map(str::to_owned)
                .expect("a row statement names its row type and family")
        };
        let sub = protected
            .get_int(15)
            .and_then(|claims| claims.get_int(2))
            .and_then(Value::as_text)
            .map(str::to_owned)
            .expect("a row statement names its subject");
        ciris_verify_core::edition2::sign_row_statement(
            &key,
            &iss,
            &sub,
            &header(-70001),
            &header(-70002),
            &payload,
            vec![],
        )
        .expect("the seat signs")
    }

    /// The standard bundle/2 test ceremony, through the real import door.
    async fn install(d: &dyn FederationDirectory) {
        fg::install_v2(d)
            .await
            .expect("the bundle/2 test ceremony installs");
    }

    /// **The seat's owner announces it**: `owner_seed` (a `user` key) binds
    /// bundle seat `i` with a live owner binding at `cohort_scope:
    /// federation`, and the seat adds its voice (C557: an owner binding counts
    /// with the node's own statement). Returns the stored binding.
    ///
    /// `pub(crate)` for fixtures that need a SERVING seat (one with trust-root
    /// reach or the `Canonical` serve tier), e.g. `namespace`'s
    /// `holdings_authority_tests::seeded_canonical`.
    pub(crate) async fn announce_seat(
        d: &dyn FederationDirectory,
        i: usize,
        owner_seed: &str,
    ) -> Attestation {
        let seat = fg::bundle_v2().serve_node_identity_ref(i).to_owned();
        let _owner = e2::put_key(d, owner_seed, &[identity_type::USER]).await;
        let mut binding =
            ts::owner_binding_attestation(&uuid::Uuid::new_v4().to_string(), owner_seed, &seat);
        // The builder's fixed instant predates the seat's own record (the
        // bundle's t0): the node's voice there would be refused.
        let at = now_ms();
        binding.asserted_at = at;
        binding.scrub_timestamp = at;
        ts::reseal(&mut binding);
        assert_eq!(
            binding.cohort_scope,
            crate::federation::types::cohort_scope::FEDERATION,
            "fixture: the announced form"
        );
        e2::put_signed(d, &binding)
            .await
            .expect("the owner's binding is admitted");
        let st = e2::carried_statement(&binding).expect("a flipped binding carries its statement");
        let voice = seat_signed(&st, i);
        e2::put_statement(d, &voice)
            .await
            .expect("the seat's voice on its owner binding is admitted");
        binding
    }

    /// Every reading of serve standing for `seat`, as `(serves_under_seat,
    /// seat_serve_standing, Canonical tier, is_trust_root, AccordCoScrub)`.
    async fn standing(d: &dyn FederationDirectory, seat: &str) -> [bool; 5] {
        [
            serves_under_seat(d, seat).await.expect("serves_under_seat"),
            seat_serve_standing(d, seat)
                .await
                .expect("seat_serve_standing"),
            resolve_serve_tier(d, seat, seat).await.expect("serve tier") == ServeTier::Canonical,
            is_trust_root(d, seat).await.expect("is_trust_root"),
            holdings_authority(d, seat)
                .await
                .expect("holdings_authority")
                == AuthorityClass::AccordCoScrub,
        ]
    }

    /// **I3110** — an unowned bundle seat is seated and does not serve.
    pub async fn i3110_an_unowned_seat_does_not_serve(d: &dyn FederationDirectory) {
        install(d).await;
        let seat = fg::bundle_v2().serve_node_identity_ref(0).to_owned();
        assert!(
            is_canonical(d, &seat).await.unwrap(),
            "I3110: the bundle seats it (ruling C)"
        );
        assert!(
            !serve_seat_owner_announced(d, &seat).await.unwrap(),
            "I3110: nothing in the bundle seeds an owner binding (CC 5.4.6)"
        );
        assert_eq!(
            standing(d, &seat).await,
            [false; 5],
            "I3110: a seat with no announced owner does not serve under it \
             (serves_under_seat, seat_serve_standing, Canonical tier, trust root, \
             AccordCoScrub reach)"
        );
        assert_ne!(
            resolve_serve_tier(d, &seat, &seat).await.unwrap(),
            ServeTier::MeshServer,
            "I3110: and no lower serve rung stands in for it"
        );
    }

    /// **I3111** — the announced seat serves; the withdrawn announcement
    /// takes it back.
    pub async fn i3111_an_announced_seat_serves_until_withdrawn(d: &dyn FederationDirectory) {
        install(d).await;
        let c = fg::bundle_v2();
        let (unowned, owned) = (
            c.serve_node_identity_ref(0).to_owned(),
            c.serve_node_identity_ref(1).to_owned(),
        );
        let owner = "i3111-owner";
        let binding = announce_seat(d, 1, owner).await;
        assert!(
            serve_seat_owner_announced(d, &owned).await.unwrap(),
            "I3111: fixture: the owner is announced"
        );
        assert_eq!(
            standing(d, &owned).await,
            [true; 5],
            "I3111: a seat with an announced owner serves (every reading)"
        );
        assert_eq!(
            standing(d, &unowned).await,
            [false; 5],
            "I3111: the other seat is unaffected by this owner"
        );

        let withdrawal = e2::composer_of(attestation_type::WITHDRAWS, &binding, owner);
        e2::put_signed(d, &withdrawal)
            .await
            .expect("the owner withdraws the binding");
        assert!(
            !serve_seat_owner_announced(d, &owned).await.unwrap(),
            "I3111: fixture: the withdrawal is live"
        );
        assert_eq!(
            standing(d, &owned).await,
            [false; 5],
            "I3111: judged live, a withdrawn announcement no longer satisfies it"
        );
        assert!(
            is_canonical(d, &owned).await.unwrap(),
            "I3111: the seat itself stands; only its serving is withheld"
        );
    }

    /// The trust-root room `id` (the CC 3.2 worked example, co-scrubbed 2-of-3
    /// by the accord), its unstewarded serve node seated as a member, plus
    /// `extra` as a member.
    fn trust_root_room(id: &str, extra: Option<&str>) -> crate::federation::SignedCommunity {
        let mut row = cci::canonical_row(&cci::FOUNDERS);
        row.community_key_id = id.to_owned();
        row.community_name = format!("infrastructure {id}");
        if let Some(k) = extra {
            row.members.push(crate::federation::types::CommunityMember {
                key_id: k.to_owned(),
                joined_at: row.founded_at,
                role: Some("member".to_owned()),
            });
        }
        cci::signed(row, &["A1", "B1"])
    }

    /// **I3112** — the trust-root door exempts the node member and never the
    /// agent.
    pub async fn i3112_an_agent_is_never_exempt_at_the_trust_root_door(
        d: &dyn FederationDirectory,
    ) {
        e2::with_earlier_form_async(async move {
            cci::stand_up(d).await;
            let agent = "i3112-agent";
            ts::register_hybrid_key_as(d, agent, agent, identity_type::AGENT).await;

            let room_a = "i3112-room-a";
            match d.put_community(trust_root_room(room_a, Some(agent))).await {
                Err(Error::UnstewardedCommunityMember {
                    community_key_id,
                    member_key_id,
                    member_role,
                }) => {
                    assert_eq!(community_key_id, room_a, "I3112");
                    assert_eq!(member_key_id, agent, "I3112: the agent is named");
                    assert_eq!(member_role, identity_type::AGENT, "I3112");
                }
                other => panic!(
                    "I3112: an unstewarded agent on a trust-root room's roster must be refused, \
                     got {other:?}"
                ),
            }
            assert!(
                d.lookup_community(room_a).await.unwrap().is_none(),
                "I3112: verify-before-mutation: nothing stored"
            );

            let room_b = "i3112-room-b";
            d.put_community(trust_root_room(room_b, None))
                .await
                .expect("I3112 control: the unstewarded NODE member is exempt");
            assert!(d.lookup_community(room_b).await.unwrap().is_some());
        })
        .await
    }

    /// **I3113** — an unowned seat states a `hard_case:*` about itself at
    /// `federation` scope; the statement is admitted and held, and the seat
    /// still has no serve standing.
    pub async fn i3113_an_unowned_seats_hard_case_still_admits(d: &dyn FederationDirectory) {
        install(d).await;
        let seat = fg::bundle_v2().serve_node_identity_ref(0).to_owned();
        let at = now_ms();
        let ev = HardCaseEvent {
            event_id: "i3113-ev".to_owned(),
            kind: hard_case::kind::LINEAGE_EQUIVOCATION.to_owned(),
            target_key_id: None,
            subject_key_id: None,
            detail: serde_json::json!({ "heads": 2 }),
            emitted_at: at,
            emitter_key_id: String::new(),
        };
        let statement = {
            let mut envelope = hard_case::hard_case_envelope(&ev).expect("envelope");
            // The seat is the author `hard_case:*` commits to (an authored
            // family): the statement is the seat's own.
            envelope["author"] = serde_json::Value::String(seat.clone());
            let mut literal = e2::with_earlier_form(|| {
                ts::bare_attestation("unused", "i3113-scribe", &seat, &envelope)
            });
            literal.attestation_type = attestation_type::SCORES.to_owned();
            literal.asserted_at = at;
            literal.scrub_timestamp = at;
            seat_signed(&e2::statement_of(&literal, "i3113-scribe"), 0)
        };
        e2::put_statement(d, &statement)
            .await
            .expect("I3113: an unowned seat's own hard_case statement is admitted");
        let id = crate::federation::edition2::names::RowId::of_statement(&statement)
            .expect("a row id")
            .hex();
        let held = d
            .get_attestation(&id)
            .await
            .unwrap()
            .expect("I3113: the statement is held");
        assert_eq!(held.attesting_key_id, seat, "I3113: signed by the seat");
        assert!(
            !serves_under_seat(d, &seat).await.unwrap(),
            "I3113: and the seat still does not serve: standing is withheld, rows are not"
        );
    }
}

#[cfg(all(test, any(feature = "sqlite", feature = "postgres")))]
mod run {
    macro_rules! runners {
        ($modname:ident, $fresh:expr) => {
            mod $modname {
                use super::super::bodies;
                use crate::federation::FederationDirectory;
                #[tokio::test]
                async fn i3110() {
                    let Some(d) = $fresh.await else { return };
                    bodies::i3110_an_unowned_seat_does_not_serve(&d as &dyn FederationDirectory)
                        .await
                }
                #[tokio::test]
                async fn i3111() {
                    let Some(d) = $fresh.await else { return };
                    bodies::i3111_an_announced_seat_serves_until_withdrawn(
                        &d as &dyn FederationDirectory,
                    )
                    .await
                }
                #[tokio::test]
                async fn i3112() {
                    let Some(d) = $fresh.await else { return };
                    bodies::i3112_an_agent_is_never_exempt_at_the_trust_root_door(
                        &d as &dyn FederationDirectory,
                    )
                    .await
                }
                #[tokio::test]
                async fn i3113() {
                    let Some(d) = $fresh.await else { return };
                    bodies::i3113_an_unowned_seats_hard_case_still_admits(
                        &d as &dyn FederationDirectory,
                    )
                    .await
                }
            }
        };
    }
    #[cfg(feature = "sqlite")]
    runners!(sqlite, async {
        use crate::store::Backend as _;
        let b = crate::store::sqlite::SqliteBackend::open_in_memory()
            .await
            .unwrap();
        b.run_migrations().await.unwrap();
        Some(b)
    });
    #[cfg(feature = "postgres")]
    runners!(postgres, async {
        use crate::store::Backend as _;
        let dsn = crate::test_pg::empty_dsn()?;
        let b = crate::store::postgres::PostgresBackend::connect(&dsn)
            .await
            .unwrap();
        b.run_migrations().await.unwrap();
        Some(b)
    });
}
