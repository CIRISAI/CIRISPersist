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
//! The fixture is a BARE directory standing up the genesis accord roster under
//! test-held keys ([`register_genesis_accord_roster`]) — nobody holds the #268
//! ceremony's private halves, so the real row's signing is outside persist.
//!
//! [`register_genesis_accord_roster`]: crate::federation::accord_test_support::register_genesis_accord_roster

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
/// I2330, I2333, I2334, I2335/I2336. The helpers below stay ONLY because other
/// agents' (held) tests still call them; they go with those callers at F.
#[cfg(all(test, any(feature = "sqlite", feature = "postgres")))]
pub(crate) mod bodies {
    use crate::federation::accord_test_support as ops;
    use crate::federation::canonical_community::{
        self as cc, CIRIS_CANONICAL_COMMUNITY_KEY_ID as CANON,
    };
    use crate::federation::tier_ingest::test_support as ts;
    use crate::federation::types::{
        identity_type, Community, CommunityMember, KeyRecord, RosterCosignature, SignedCommunity,
        SignedKeyRecord,
    };
    use crate::federation::FederationDirectory;

    /// The three founders (human steward keys) and the one serve node. Short,
    /// distinct-first-byte ids: the test signer seeds from the first 32 bytes.
    pub(crate) const FOUNDERS: [&str; 3] = ["us-steward", "eu-steward", "ap-steward"];
    pub(crate) const SERVE_NODE: &str = "cc1-serve-node";

    pub(crate) fn at(s: &str) -> chrono::DateTime<chrono::Utc> {
        s.parse().expect("rfc3339")
    }

    /// A key record for `key_id` with its deterministic test pubkeys.
    fn key_record(key_id: &str, identity: &str) -> KeyRecord {
        let (ed, mldsa) = ts::hybrid_pubkeys(key_id);
        let now = at("2026-01-01T00:00:00Z");
        KeyRecord {
            key_id: key_id.to_owned(),
            pubkey_ed25519_base64: ed,
            pubkey_ml_dsa_65_base64: mldsa,
            algorithm: crate::federation::types::algorithm::HYBRID.to_owned(),
            identity_type: identity.to_owned(),
            identity_ref: key_id.to_owned(),
            valid_from: now,
            valid_until: None,
            registration_envelope: serde_json::json!({ "id": key_id }),
            original_content_hash: "deadbeef".to_owned(),
            scrub_signature_classical: "c2lnbmF0dXJl".to_owned(),
            scrub_signature_pqc: None,
            scrub_key_id: key_id.to_owned(),
            scrub_timestamp: now,
            pqc_completed_at: None,
            persist_row_hash: String::new(),
            capability_roles: Vec::new(),
            attestation_evidence: None,
            consent_role: None,
            additional_scrubs: Vec::new(),
        }
    }

    /// `key_id` as an accord-CONFERRED record: its registration co-scrubbed
    /// 2-of-3 by the genesis holders (the ceremony plane, CC 3.2 T2).
    pub(crate) async fn put_conferred(
        d: &dyn FederationDirectory,
        holders: &[ops::Identity],
        key_id: &str,
        identity: &str,
    ) {
        let record =
            ops::accord_conferred(key_record(key_id, identity), &[&holders[0], &holders[1]]);
        d.put_public_key(SignedKeyRecord { record })
            .await
            .unwrap_or_else(|e| panic!("conferred {key_id} admits: {e}"));
    }

    /// The trust root stood up on a bare directory: the genesis holders under
    /// test keys, the entrenched accord family, three human stewards the
    /// accord conferred, and one serve node. Returns the holders.
    pub(crate) async fn stand_up(d: &dyn FederationDirectory) -> Vec<ops::Identity> {
        let holders = ops::register_genesis_accord_roster(d)
            .await
            .expect("genesis accord roster");
        crate::federation::genesis::seed_accord_family(d)
            .await
            .expect("accord family");
        for f in FOUNDERS {
            put_conferred(d, &holders, f, "user,steward").await;
        }
        ts::register_hybrid_key_as(d, SERVE_NODE, SERVE_NODE, identity_type::NODE).await;
        holders
    }

    /// v62.0.0 (CC rc20 3.2 / 4.4.3.4, CIRISPersist#1274) — **a conformant,
    /// ROOTED infrastructure room** for fixtures that need the infrastructure
    /// carve-out (plaintext at rest, the Commons audience, node members
    /// without a steward). Until v62 a fixture got the carve-out by
    /// self-registering the room's key as `substrate_persist`; CC rc20 3.4.7.1
    /// ("`substrate_persist` is a key type that confers no authority … Nothing
    /// is admitted on its strength") closed that, and the carve-out now needs a
    /// conformant record rooted in this node's trust set. So this stands up the
    /// trust root (the genesis holders under test keys, the accord family,
    /// three accord-conferred human stewards as founders: "Infrastructure does
    /// not vote") and puts `room` as a trust-root-grade `quorum:2/3` record,
    /// co-scrubbed 2-of-3 by the accord, with `members` seated as `member`.
    /// `tag` keeps the founders' ids distinct per room (their FIRST bytes
    /// differ: the test signer seeds from the first 32 bytes of a key id).
    /// Returns the stored record.
    pub(crate) async fn rooted_infrastructure_room(
        d: &dyn FederationDirectory,
        room: &str,
        members: &[&str],
        tag: &str,
    ) -> Community {
        let holders = ops::register_genesis_accord_roster(d)
            .await
            .expect("genesis accord roster");
        // A second room in one directory finds the family already seeded.
        let _ = crate::federation::genesis::seed_accord_family(d).await;
        let founders: Vec<String> = ["us", "eu", "ap"]
            .iter()
            .map(|p| format!("{p}-{tag}"))
            .collect();
        for f in &founders {
            put_conferred(d, &holders, f, "user,steward").await;
        }
        let refs: Vec<&str> = founders.iter().map(String::as_str).collect();
        let mut row = canonical_row(&refs);
        row.community_key_id = room.to_owned();
        row.community_name = format!("infrastructure {tag}");
        let joined = row.founded_at;
        row.members.retain(|m| m.role.as_deref() == Some("founder"));
        for m in members {
            row.members.push(CommunityMember {
                key_id: (*m).to_owned(),
                joined_at: joined,
                role: Some("member".to_owned()),
            });
        }
        d.put_community(signed(row, &["A1", "B1"]))
            .await
            .unwrap_or_else(|e| panic!("the rooted infrastructure room {room}: {e}"));
        assert!(
            cc::is_rooted(d, room).await.unwrap(),
            "fixture: {room} is rooted"
        );
        d.lookup_community(room).await.unwrap().expect("held")
    }

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
    /// 3. The room: `room_seed`'s `key:record` (`user`), three person founders
    ///    (`{tag}-infra-f{0,1,2}`, `user`), founded by their `group:roster`
    ///    voices (T1) as a conformant `infrastructure` record at `quorum:2/3`
    ///    whose `charter_digest` cites the shared root's charter.
    /// 4. Each of `members` widened in (a founder's proposal, the member's
    ///    acceptance, the widening voiced by two founders: the growth gate
    ///    #955); a `node` member also gets a live owner binding at `federation`
    ///    from `{tag}-infra-owner-{i}` (`user`), its serve seat's announced
    ///    owner (P5).
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
        use crate::federation::edition2::group::GroupRecord;
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

        // 3. The room, citing the shared root's charter.
        let room = e2::put_key(b, room_seed, &[identity_type::USER]).await;
        let founders: Vec<String> = [0, 1, 2]
            .iter()
            .map(|i| format!("{tag}-infra-f{i}"))
            .collect();
        let mut founder_ids = Vec::new();
        for f in &founders {
            founder_ids.push(e2::put_key(b, f, &[identity_type::USER]).await);
        }
        let at = e2::ms(crate::host::clock::now());
        let joined = chrono::DateTime::<chrono::Utc>::from_timestamp_millis(
            i64::try_from(at).expect("ms") - 60_000,
        )
        .expect("an instant");
        let record = Community {
            prev_head_digest: String::new(),
            charter_digest: charter,
            community_key_id: room.clone(),
            community_name: format!("infrastructure {tag}"),
            members: founder_ids
                .iter()
                .map(|f| CommunityMember {
                    key_id: f.clone(),
                    joined_at: joined,
                    role: Some(crate::federation::admission::MEMBER_ROLE_FOUNDER.to_owned()),
                })
                .collect(),
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
        let keys: Vec<_> = founders.iter().map(|f| e2::signing_key(f)).collect();
        let key_refs: Vec<_> = keys.iter().collect();
        let voices = gf::roster_voices(&GroupRecord::Community(record), 1, None, at, &key_refs);
        gf::put_voices(b, &voices)
            .await
            .unwrap_or_else(|e| panic!("the infrastructure room {room}: {e}"));

        // 4. The members.
        for (i, m) in members.iter().enumerate() {
            let member = e2::kid(m);
            let now = crate::host::clock::now();
            let p = proposal_row(&founders[0], COMMUNITY, &room, &member, None, now);
            e2::put_signed(b, &p)
                .await
                .unwrap_or_else(|e| panic!("proposal of {member}: {e}"));
            e2::put_signed(b, &acceptance_row(&member, &p, now))
                .await
                .unwrap_or_else(|e| panic!("acceptance by {member}: {e}"));
            let mut w = ts::sign_community_membership_widening(
                &founders[0],
                CommunityMembershipWidening {
                    community_key_id: room.clone(),
                    member_key_id: member.clone(),
                    joined_at: now,
                    effective_at: now,
                    role: None,
                    persist_row_hash: String::new(),
                },
            );
            ts::cosign_community_membership_widening(&mut w, &founders[1]);
            let head = gf::held_head(b, &room).await.map(|(h, _)| h);
            gf::put_voices(b, &gf::community_widening_voices(&w, head.as_ref()))
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

    /// The CC 3.2 worked example as a record.
    pub(crate) fn canonical_row(founders: &[&str]) -> Community {
        let joined = at("2026-09-20T00:00:00Z");
        let mut members: Vec<CommunityMember> = founders
            .iter()
            .map(|k| CommunityMember {
                key_id: (*k).to_owned(),
                joined_at: joined,
                role: Some("founder".to_owned()),
            })
            .collect();
        members.push(CommunityMember {
            key_id: SERVE_NODE.to_owned(),
            joined_at: joined,
            role: Some("member".to_owned()),
        });
        Community {
            prev_head_digest: String::new(),
            charter_digest: String::new(),
            community_key_id: CANON.to_owned(),
            community_name: "CIRIS Canonical Services".to_owned(),
            members,
            founded_at: joined,
            consensus_protocol: "quorum:2/3".to_owned(),
            policy_blob: Some(serde_json::json!({
                "cohort_subkind": "infrastructure",
                "cohort_subkind_payload": {
                    "infrastructure_constraint": {
                        "service_class": "canonical",
                        "admission_quorum_basis": "founders",
                    }
                },
                "consensus_protocol_entrenched": true,
            })),
            persist_row_hash: String::new(),
        }
    }

    /// Sign `row` by `signers[0]` and co-sign by the rest.
    pub(crate) fn signed(row: Community, signers: &[&str]) -> SignedCommunity {
        let mut s = ts::sign_community(signers[0], row);
        // v52.0.0 (#955, Q1) — the listed founders consent by co-signing (the
        // fixture signer adds them); the named signers are added once each.
        s.cosignatures
            .retain(|c| !signers.contains(&c.authority_key_id.as_str()));
        for c in &signers[1..] {
            let (_h, classical, pqc) = ts::sign_envelope(c, &s.community.signing_envelope());
            s.cosignatures.push(RosterCosignature {
                authority_key_id: (*c).to_owned(),
                scrub_signature_classical: classical,
                scrub_signature_pqc: pqc,
            });
        }
        s
    }

    // ── #972 — a seated accord holder founds an infrastructure community ──
}
