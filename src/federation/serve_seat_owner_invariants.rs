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
//! - **I3112** — an agent is never exempt: an edition-2 trust-root room (an
//!   `infrastructure` community founded by the bundle's holders through
//!   `group:roster` voices; the trust-root door's verdict) listing an
//!   unstewarded `agent` member is HELD `unstewarded_community_member`
//!   (the door's `UnstewardedCommunityMember`, a fold condition) and nothing
//!   is stored; the same room with only its unstewarded `node` member lands.
//! - **I3113** — an unowned seat's own `hard_case:*` names no head and is
//!   not kept (`act_names_no_head`, Constitution's ruling (a)); once its
//!   owner's binding lands, a NEW row naming the binding as its head
//!   concludes.
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
    use crate::federation::edition2::fixture_genesis as fg;
    use crate::federation::edition2::fixture_switch as e2;
    use crate::federation::hard_case::{self, HardCaseEvent};
    use crate::federation::namespace::{holdings_authority, is_trust_root, AuthorityClass};
    use crate::federation::tier_ingest::test_support as ts;
    use crate::federation::trust_root::{resolve_serve_tier, ServeTier};
    use crate::federation::types::{attestation_type, identity_type, Attestation};
    use crate::federation::FederationDirectory;
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
        seat_signed_naming(statement, i, None)
    }

    /// [`seat_signed`], with `head` joined into the payload's `refs`
    /// (`head_rule::with_head`) when given (HEAD-fix3b, I3113).
    fn seat_signed_naming(
        statement: &[u8],
        i: usize,
        head: Option<&crate::federation::edition2::names::RowId>,
    ) -> Vec<u8> {
        let c = fg::bundle_v2();
        let key = Box::new(c.serve_node_key(i));
        let iss = c.serve_node_identity_ref(i).to_owned();
        let (protected, payload) =
            crate::federation::edition2::liveness::statement_parts(statement)
                .expect("a row statement");
        let payload = match head {
            Some(h) => crate::federation::edition2::head_rule::with_head(payload, h)
                .expect("the payload's refs join a head"),
            None => payload,
        };
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

    /// v62 (W1-fix3, CP2 rewrite) — an edition-2 trust-root room at
    /// `e2::kid(seed)`: an `infrastructure` community founded by the holders
    /// of the bundle in force (each a FOUNDER, `quorum:2/3`, the birth
    /// counted over the bundle's holders, W1's trust-root door), plus `extra`
    /// as a plain member. Its founding voices, one per holder, in order.
    fn trust_root_room(seed: &str, extra: Option<&str>) -> Vec<Vec<u8>> {
        use crate::federation::edition2::group::GroupRecord;
        use crate::federation::types::{Community, CommunityMember};
        let founded = now_ms();
        let mut members: Vec<CommunityMember> = fg::HOLDER_SEEDS
            .iter()
            .map(|h| CommunityMember {
                key_id: fg::identity_ref_of(*h),
                joined_at: founded,
                role: Some(crate::federation::admission::MEMBER_ROLE_FOUNDER.to_owned()),
            })
            .collect();
        if let Some(k) = extra {
            members.push(CommunityMember {
                key_id: k.to_owned(),
                joined_at: founded,
                role: Some("member".to_owned()),
            });
        }
        let room = GroupRecord::Community(Community {
            community_key_id: e2::kid(seed),
            community_name: format!("infrastructure {seed}"),
            members,
            founded_at: founded,
            consensus_protocol: "quorum:2/3".to_owned(),
            policy_blob: Some(serde_json::json!({
                "cohort_subkind": crate::federation::canonical_community::COHORT_SUBKIND_INFRASTRUCTURE,
                "cohort_subkind_payload": {
                    "infrastructure_constraint": {
                        "admission_quorum_basis":
                            crate::federation::canonical_community::ADMISSION_QUORUM_BASIS_FOUNDERS,
                    },
                },
                "consensus_protocol_entrenched": true,
            })),
            prev_head_digest: String::new(),
            charter_digest: String::new(),
            persist_row_hash: String::new(),
        });
        let at = u64::try_from(founded.timestamp_millis()).expect("ms") + 1_000;
        let keys: Vec<_> = fg::HOLDER_SEEDS.iter().map(|h| fg::test_key(*h)).collect();
        let refs: Vec<_> = keys.iter().collect();
        crate::federation::edition2::group_fixtures::roster_voices(&room, 1, None, at, &refs)
    }

    /// **I3112** — the trust-root door exempts the node member and never the
    /// agent. v62 (W1-fix3): the rooms are edition-2 `group:roster` foundings
    /// by the bundle's holders; the agent's room is HELD
    /// `unstewarded_community_member` by the steward gate's fold condition
    /// (CC 2.7.3: the member's binding is another row) and nothing is stored.
    pub async fn i3112_an_agent_is_never_exempt_at_the_trust_root_door(
        d: &dyn FederationDirectory,
    ) {
        use crate::federation::edition2::fold;
        use crate::federation::edition2::group_fixtures::row_id_of;
        use crate::federation::edition2::ingest::StatementOutcome;
        install(d).await;
        let agent = e2::put_key(d, "i3112-agent", &[identity_type::AGENT]).await;
        let node = e2::put_key(d, "i3112-node", &[identity_type::NODE]).await;

        let voices = trust_root_room("i3112-room-a", Some(&agent));
        let mut last = None;
        // v62 P5-fix2 — the listed member signs the founding too (the
        // founding rule, `check_community_founding_signers`: a listed member's
        // voice is its consent; an edition-2 node key record carries no
        // accord scrub, so no node is seated without it). Its voice first,
        // then the holders', so the last voice completes the row and the only
        // thing missing is the agent's steward binding.
        e2::put_statement(d, &e2::voice_of(&voices[0], "i3112-agent"))
            .await
            .expect("I3112: the agent's own voice over the founding is kept");
        for v in &voices {
            last = Some(
                e2::put_statement(d, v)
                    .await
                    .expect("I3112: a holder's founding voice is kept"),
            );
        }
        assert!(
            matches!(last, Some(StatementOutcome::Pending { .. })),
            "I3112: an unstewarded agent on a trust-root room's roster concludes nothing: \
             {last:?}"
        );
        let held = fold::why_held(d, &row_id_of(&voices[0]))
            .await
            .unwrap()
            .expect("I3112: the founding is held");
        assert_eq!(
            held.reason,
            fold::reason::gc1::UNSTEWARDED_COMMUNITY_MEMBER,
            "I3112: held by the steward gate: {held:?}"
        );
        // The agent, structurally (never the refusal's display text): the
        // held founding's declared reads name the agent's key, so it re-folds
        // when the agent's steward binding lands (`fold_dependents`).
        assert!(
            d.fold_dependents(&[fold::Dep::key(&agent).read_key()])
                .await
                .unwrap()
                .contains(&row_id_of(&voices[0])),
            "I3112: the hold waits on the agent's key: {held:?}"
        );
        assert!(
            d.lookup_community(&e2::kid("i3112-room-a"))
                .await
                .unwrap()
                .is_none(),
            "I3112: verify-before-mutation: nothing stored"
        );

        // The control: the same room with its unstewarded NODE member lands
        // (the node's own voice over the founding first, as above).
        let room_b = trust_root_room("i3112-room-b", Some(&node));
        e2::put_statement(d, &e2::voice_of(&room_b[0], "i3112-node"))
            .await
            .expect("I3112 control: the node's own voice over the founding is kept");
        let mut last = None;
        for v in &room_b {
            last = Some(
                e2::put_statement(d, v)
                    .await
                    .expect("I3112 control: a holder's founding voice"),
            );
        }
        assert!(
            matches!(last, Some(StatementOutcome::Row { .. })),
            "I3112 control: the unstewarded NODE member is exempt: {last:?}"
        );
        assert!(d
            .lookup_community(&e2::kid("i3112-room-b"))
            .await
            .unwrap()
            .is_some());
    }

    /// **I3113** (v62.0.0, rewritten by HEAD-fix3b; Constitution's ruling
    /// (a), "AN UNOWNED SERVE SEAT'S OWN REPORT"; CC 4.2: a node holds
    /// `infra:attest` for its own reports FROM ITS OWNER, and "a canonical
    /// seat is no exception") — an UNOWNED seat's own `hard_case:*` at
    /// `federation` names no head and is NOT KEPT (`act_names_no_head`): it
    /// counts for nobody, and the seat still does not serve. Once its owner's
    /// binding lands, the seat signs a NEW row naming that binding as its
    /// head, and that row concludes. (The earlier body, "an unowned seat's
    /// own hard_case is admitted and held", witnessed the model before the
    /// head rule.)
    pub async fn i3113_an_unowned_seats_hard_case_concludes_nothing(d: &dyn FederationDirectory) {
        use crate::federation::edition2::names::RowId;
        install(d).await;
        let seat = fg::bundle_v2().serve_node_identity_ref(0).to_owned();
        let at = now_ms();
        // The seat's own hard case, as its producer signs it; `head` joined
        // into `refs` when given.
        let report = |event_id: &str, head: Option<&RowId>| -> Vec<u8> {
            let ev = HardCaseEvent {
                event_id: event_id.to_owned(),
                kind: hard_case::kind::LINEAGE_EQUIVOCATION.to_owned(),
                target_key_id: None,
                subject_key_id: None,
                detail: serde_json::json!({ "heads": 2 }),
                emitted_at: at,
                emitter_key_id: String::new(),
            };
            let mut envelope = hard_case::hard_case_envelope(&ev).expect("envelope");
            // The seat is the author `hard_case:*` commits to (an authored
            // family): the statement is the seat's own.
            envelope["author"] = serde_json::Value::String(seat.clone());
            let mut literal = ts::bare_attestation("unused", "i3113-scribe", &seat, &envelope);
            literal.attestation_type = attestation_type::SCORES.to_owned();
            literal.asserted_at = at;
            literal.scrub_timestamp = at;
            seat_signed_naming(&e2::statement_of(&literal, "i3113-scribe"), 0, head)
        };

        // Unowned: not kept, counts for nobody.
        let unowned = report("i3113-ev", None);
        let e = e2::put_statement(d, &unowned)
            .await
            .expect_err("I3113: an unowned seat's hard case names no head");
        assert!(
            matches!(
                &e,
                crate::federation::Error::MalformedRow { reason, .. }
                    if *reason == crate::federation::malformed_row::ACT_NAMES_NO_HEAD
            ),
            "I3113: not kept, act_names_no_head: {e:?}"
        );
        let id = RowId::of_statement(&unowned).expect("a row id");
        assert!(
            d.get_attestation(&id.hex()).await.unwrap().is_none(),
            "I3113: nothing of the row is kept"
        );
        assert!(
            !serves_under_seat(d, &seat).await.unwrap(),
            "I3113: and the unowned seat does not serve"
        );

        // Owned: a NEW row naming the owner binding concludes.
        announce_seat(d, 0, "i3113-owner").await;
        let head = crate::federation::edition2::head_rule::owner_binding_row(d, &seat, false, 0)
            .await
            .expect("I3113: the owner read")
            .expect("I3113: the seat is owned once announced");
        let owned = report("i3113-ev-owned", Some(&head));
        e2::put_statement(d, &owned)
            .await
            .expect("I3113: the owned seat's hard case naming its binding is admitted");
        let held = d
            .get_attestation(&RowId::of_statement(&owned).expect("a row id").hex())
            .await
            .unwrap()
            .expect("I3113: the new row concludes");
        assert_eq!(held.attesting_key_id, seat, "I3113: signed by the seat");
        assert!(
            d.get_attestation(&id.hex()).await.unwrap().is_none(),
            "I3113: the headless row is still not kept: only the new row counts"
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
                    bodies::i3113_an_unowned_seats_hard_case_concludes_nothing(
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
