//! v50.0.0 (CIRISPersist#926, ruling (b); FSD `SECOND_DEVICE.md` §9) — **I190:
//! the `ciris-canonical` community row is admitted under the accord's quorum
//! and served beside the bundle.**
//!
//! (a) the fixture row, co-scrubbed 2-of-3 by the accord holders, admits and
//! resolves to a non-empty founder set, `infrastructure`, entrenched — and its
//! co-signatures are served back; (b) 1-of-3 is refused, and a founder's
//! signature does not count toward the ACCORD's quorum; (c) a `node`-bearing
//! founder is refused (#925's rule), so is a founder the accord did not confer,
//! so is each CC 3.2 shape clause; (d) `trust:accepts:v1` on `ciris-canonical`
//! is the one-row un-trust (CC 3.2 T3) and leaves the row standing; (e) the
//! CC 5.3.4 response carries the row beside the bundle and a fresh consumer
//! pins from that one response; (f) #809 — a bundle whose holder quorum is
//! short is REFUSED, not reported; (g) a supersede cannot lift the
//! entrenchment, drop the constraint, or change without the founders' quorum.
//!
//! v62.0.0 (W1-fix4, after C5-fix1): the earlier-form fixtures (the accord
//! roster under test keys, accord-conferred stewards, the co-scrubbed
//! canonical row) are deleted with C5's baked genesis; what stays is the
//! edition-2 rooted infrastructure room (`bodies`).

/// v62.0.0 (JSON cut, wave 3, E5) — **every I190 / I330–I334 witness is
/// deleted** (lead's ruling 1: canonical is the bundle in force's
/// `serve_nodes`; the accord's family, roster and quorum are genesis bundle/2).
/// Covered by C1/C2's bundle witnesses: the canonical row admitted / short /
/// served beside the bundle (a, b, e, f) → I2314 (seats canonical), I2312 /
/// I2315 (unanchored / count unmet), I2317 (statements replayed on a fresh
/// node); founders, supersede, resignations, rebirth, squats, key rotation
/// (c, g, h, i, j, k, k2, l, m, n, o*, p, q, r, t, u–z) → I2316 / I2333 (a later
/// bundle at the holders' majority), I2318 (forks), I2320 / I2304 (re-seat);
/// I330–I334 (holders found and live, departed, node-bearing, non-roster) →
/// I2330, I2333, I2334, I2335/I2336. What stays is the edition-2 fixture
/// other files' witnesses stand on: `rooted_infrastructure_room_e2`.
#[cfg(all(test, any(feature = "sqlite", feature = "postgres")))]
pub(crate) mod bodies {
    use crate::federation::tier_ingest::test_support as ts;
    use crate::federation::types::{identity_type, Community, CommunityMember};
    use crate::federation::FederationDirectory;

    /// v62.0.0 (JSON cut, critical path, E5) — a backend whose node key a
    /// fixture can set (the sqlite / postgres inherent `set_node_key_id`; not
    /// on `FederationDirectory`).
    pub(crate) trait SetNodeKey {
        fn set_node_key(&self, key_id: String);
    }
    #[cfg(feature = "sqlite")]
    impl SetNodeKey for crate::store::sqlite::SqliteBackend {
        fn set_node_key(&self, key_id: String) {
            self.set_node_key_id(key_id);
        }
    }
    #[cfg(feature = "postgres")]
    impl SetNodeKey for crate::store::postgres::PostgresBackend {
        fn set_node_key(&self, key_id: String) {
            self.set_node_key_id(key_id);
        }
    }

    /// **v62.0.0 (JSON cut, critical path, E5) — an infrastructure room ROOTED
    /// IN THIS NODE'S TRUST SET, on edition 2** (RULINGS: a conformant
    /// `infrastructure` record reachable by the node's trust walk; CC 5.4.6:
    /// a serve-seat node needs an announced owner). Returns the room's id,
    /// `kid(room_seed)`; several rooms per directory are fine.
    ///
    /// Follows W1's recipe (W1.api v1.2, `infrastructure_reached_here`: a room
    /// is reached when its record cites the `trust:charter:v1` of a root this
    /// node holds Rooted):
    /// 1. THIS node has a key (`{tag}-infra-node`, `node`), set as the node key
    ///    when none is set (W1's precondition).
    /// 2. ONE shared W1 root per directory (`rooted_trust_root` over the
    ///    bundle's `HOLDER_SEEDS` at `quorum:2/3`; idempotent per directory,
    ///    W1.api v1.4).
    /// 3. The room: `room_seed`'s `key:record` (`user`), founded by
    ///    `group:roster` voices (T1) as a conformant trust-root-grade
    ///    `infrastructure` record at `quorum:2/3` whose `charter_digest` cites
    ///    the shared root's charter. v62 (W1-fix4, after C5-fix1): its three
    ///    FOUNDERS are the holders of the genesis bundle in force
    ///    (`fixture_genesis::HOLDER_SEEDS`; the trust-root door's holder arm
    ///    and the birth's count over the bundle's holders), and
    ///    `{tag}-infra-p` (`user`) is seated as a plain member.
    /// 4. Each of `members` widened in (`{tag}-infra-p`'s proposal, the
    ///    member's acceptance, the widening voiced by holders 1 and 2: the
    ///    growth gate #955); a `node` member also gets a live owner binding at
    ///    `federation` from `{tag}-infra-owner-{i}` (`user`), its serve seat's
    ///    announced owner (P5).
    ///
    /// A caller that signs as a founder uses `fixture_genesis::test_key(h)` for
    /// `h` in `HOLDER_SEEDS` (identity-ref `identity_ref_of(h)`).
    ///
    /// Members must already be keys (seeds or identity-refs this process
    /// minted). A caller-set node key must be a kid E0 minted.
    pub(crate) async fn rooted_infrastructure_room_e2<B>(
        b: &B,
        room_seed: &str,
        members: &[&str],
        tag: &str,
    ) -> String
    where
        B: FederationDirectory + SetNodeKey + Sync,
    {
        use crate::federation::edition2::fixture_genesis;
        use crate::federation::edition2::fixture_switch as e2;
        use crate::federation::edition2::fixture_trust_root as w1;
        use crate::federation::edition2::group::{GroupRecord, MembershipRecord};
        use crate::federation::edition2::group_fixtures as gf;
        use crate::federation::membership_acceptance::test_support::{
            acceptance_row, proposal_row,
        };
        use crate::federation::types::cohort_scope::COMMUNITY;
        use crate::federation::types::CommunityMembershipWidening;

        // 1. THIS node's key.
        if b.node_key_id().is_none() {
            let node = e2::put_key(b, &format!("{tag}-infra-node"), &[identity_type::NODE]).await;
            b.set_node_key(node);
        }

        // 2. The one shared W1 root and its charter's row id: W1.api v1.4 —
        //    `rooted_trust_root` is idempotent per directory (a second call
        //    returns the held root and puts nothing).
        let charter = w1::rooted_trust_root(b, &fixture_genesis::HOLDER_SEEDS, "quorum:2/3")
            .await
            .charter
            .hex();

        // 3. The room, citing the shared root's charter. v62 (W1-fix4, after
        //    C5-fix1): a trust-root-grade room's FOUNDERS are holders of the
        //    genesis bundle in force (the trust-root door's holder arm; its
        //    birth is counted over the bundle's holders, W1), the same
        //    founding `rooted_trust_root` makes. An E0 person
        //    (`{tag}-infra-p`) is seated as a plain member: it voices the
        //    founding (every listed person does) and proposes the members
        //    below (a member of the room, in scope for its proposals).
        let room = e2::put_key(b, room_seed, &[identity_type::USER]).await;
        // The seed signs (E0: a signer seeds from the seed name, never from
        // `kid()`); the roster names its identity-ref.
        let proposer_seed = format!("{tag}-infra-p");
        let proposer = e2::put_key(b, &proposer_seed, &[identity_type::USER]).await;
        let holder_keys: Vec<_> = fixture_genesis::HOLDER_SEEDS
            .iter()
            .map(|h| fixture_genesis::test_key(*h))
            .collect();
        let at = e2::ms(crate::host::clock::now());
        let joined = chrono::DateTime::<chrono::Utc>::from_timestamp_millis(
            i64::try_from(at).expect("ms") - 60_000,
        )
        .expect("an instant");
        let mut seated: Vec<CommunityMember> = fixture_genesis::HOLDER_SEEDS
            .iter()
            .map(|h| CommunityMember {
                key_id: fixture_genesis::identity_ref_of(*h),
                joined_at: joined,
                role: Some(crate::federation::admission::MEMBER_ROLE_FOUNDER.to_owned()),
            })
            .collect();
        seated.push(CommunityMember {
            key_id: proposer.clone(),
            joined_at: joined,
            role: Some("member".to_owned()),
        });
        let record = Community {
            prev_head_digest: String::new(),
            charter_digest: charter,
            community_key_id: room.clone(),
            community_name: format!("infrastructure {tag}"),
            members: seated,
            founded_at: joined,
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
            persist_row_hash: String::new(),
        };
        let proposer_key = e2::signing_key(&proposer_seed);
        let mut key_refs: Vec<_> = holder_keys.iter().collect();
        key_refs.push(&proposer_key);
        let voices = gf::roster_voices(&GroupRecord::Community(record), 1, None, at, &key_refs);
        // The last voice is `Row` or a further `Voice` of the landed row;
        // the room is asserted held either way.
        let landed = gf::put_voices(b, &voices).await;
        assert!(
            b.lookup_community(&room)
                .await
                .expect("lookup the room")
                .is_some(),
            "the infrastructure room {room} did not land: {landed:?}"
        );

        // 4. The members: the proposer's proposal, the member's acceptance,
        //    then the widening voiced by two founders (holders 1 and 2: the
        //    room's `quorum:2/3` over its founders).
        for (i, m) in members.iter().enumerate() {
            let member = e2::kid(m);
            let now = crate::host::clock::now();
            let p = proposal_row(&proposer_seed, COMMUNITY, &room, &member, None, now);
            e2::put_signed(b, &p)
                .await
                .unwrap_or_else(|e| panic!("proposal of {member}: {e}"));
            e2::put_signed(b, &acceptance_row(&member, &p, now))
                .await
                .unwrap_or_else(|e| panic!("acceptance by {member}: {e}"));
            let w = MembershipRecord::CommunityWidening(CommunityMembershipWidening {
                community_key_id: room.clone(),
                member_key_id: member.clone(),
                joined_at: now,
                effective_at: now,
                role: None,
                persist_row_hash: String::new(),
            });
            let head = gf::held_head(b, &room).await.map(|(h, _)| h);
            gf::put_voices(
                b,
                &gf::membership_voices(&w, head.as_ref(), &[&holder_keys[0], &holder_keys[1]]),
            )
            .await
            .unwrap_or_else(|e| panic!("widening {member} into {room}: {e}"));
            let is_node = b
                .lookup_public_key(&member)
                .await
                .expect("lookup the member")
                .is_some_and(|r| {
                    identity_type::parse_set(&r.identity_type).contains(&identity_type::NODE)
                });
            if is_node {
                let owner =
                    e2::put_key(b, &format!("{tag}-infra-owner-{i}"), &[identity_type::USER]).await;
                ts::put_owner_binding(b as &dyn FederationDirectory, &owner, &member).await;
            }
        }
        room
    }
}
