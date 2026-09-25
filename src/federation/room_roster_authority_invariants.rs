//! v49.0.0 (CIRISPersist#907, #908; `FSD/ROOM_ROSTER_AUTHORITY.md` §6) — **a
//! roster change needs standing, and admission reads the same roster.**
//!
//! I170 — admission is the roster (widened ⇒ admitted; removed ⇒ refused;
//! re-added ⇒ admitted). I171 — a stranger cannot move the roster, and every
//! kind of standing can. I172 — two nodes that received the same rows in
//! different orders fold to the same roster. I173 — a revocation with no
//! recorded signer (the pre-V110 shape) still removes. I176 — co-signatures
//! are verified at the door and served byte-exact.

/// The backend-agnostic witness bodies; `run` instantiates them per backend.
#[cfg(test)]
pub mod bodies {
    use crate::federation::cohort::Cohort;
    use crate::federation::tier_ingest::test_support as ts;
    use crate::federation::types::{
        consensus_protocol, identity_type, Community, CommunityMember,
        CommunityMembershipRevocation, CommunityMembershipWidening,
    };
    use crate::federation::{Error, FederationDirectory};

    fn at(s: &str) -> chrono::DateTime<chrono::Utc> {
        s.parse().expect("rfc3339")
    }

    fn widening(
        room: &str,
        member: &str,
        effective_at: chrono::DateTime<chrono::Utc>,
        role: Option<&str>,
    ) -> CommunityMembershipWidening {
        CommunityMembershipWidening {
            community_key_id: room.to_owned(),
            member_key_id: member.to_owned(),
            joined_at: effective_at,
            effective_at,
            role: role.map(str::to_owned),
            persist_row_hash: String::new(),
        }
    }

    fn revocation(
        room: &str,
        member: &str,
        effective_at: chrono::DateTime<chrono::Utc>,
    ) -> CommunityMembershipRevocation {
        CommunityMembershipRevocation {
            community_key_id: room.to_owned(),
            removed_identity_key_id: member.to_owned(),
            removed_at: effective_at,
            effective_at,
            reason: None,
            witness_set: vec![],
            persist_row_hash: String::new(),
        }
    }

    async fn user(d: &dyn FederationDirectory, k: &str) {
        ts::register_hybrid_key_as(d, k, k, identity_type::USER).await;
    }

    /// A room of `names` (each `{tag}-{name}`, registered user keys), the
    /// first `founders` of them tagged `founder`, under `protocol`, signed by
    /// `record_signer` (default: the first member) and carrying `policy_blob`.
    /// The room id is no key. Returns the room id and the member key ids.
    pub async fn make_group(
        d: &dyn FederationDirectory,
        tag: &str,
        protocol: &str,
        names: &[&str],
        founders: usize,
        policy_blob: Option<serde_json::Value>,
        record_signer: Option<&str>,
    ) -> (String, Vec<String>) {
        let room = format!("{tag}-room");
        let keys: Vec<String> = names.iter().map(|n| format!("{tag}-{n}")).collect();
        for k in &keys {
            user(d, k).await;
        }
        let signer = record_signer
            .map(str::to_owned)
            .unwrap_or_else(|| keys[0].clone());
        d.put_community(ts::sign_community(
            &signer,
            Community {
                community_key_id: room.clone(),
                community_name: "authority room".into(),
                members: keys
                    .iter()
                    .enumerate()
                    .map(|(i, k)| CommunityMember {
                        key_id: k.clone(),
                        joined_at: at("2026-01-01T00:00:00Z"),
                        role: (i < founders).then(|| "founder".to_owned()),
                    })
                    .collect(),
                founded_at: at("2026-01-01T00:00:00Z"),
                consensus_protocol: protocol.to_owned(),
                policy_blob,
                persist_row_hash: String::new(),
            },
        ))
        .await
        .unwrap_or_else(|e| panic!("{tag}: room: {e}"));
        (room, keys)
    }

    /// The common case: alice (founder) and bob, under `protocol`.
    pub async fn make_room(
        d: &dyn FederationDirectory,
        tag: &str,
        protocol: &str,
    ) -> (String, String, String) {
        let (room, k) = make_group(d, tag, protocol, &["alice", "bob"], 1, None, None).await;
        (room, k[0].clone(), k[1].clone())
    }

    /// A widening signed by `signers[0]` and co-signed by the rest.
    async fn widen_by(
        d: &dyn FederationDirectory,
        signers: &[&str],
        w: CommunityMembershipWidening,
    ) -> Result<(), Error> {
        let mut s = ts::sign_community_membership_widening(signers[0], w);
        for c in &signers[1..] {
            ts::cosign_community_membership_widening(&mut s, c);
        }
        d.put_community_membership_widening(s).await
    }

    /// A revocation signed by `signers[0]` and co-signed by the rest.
    async fn revoke_by(
        d: &dyn FederationDirectory,
        signers: &[&str],
        r: CommunityMembershipRevocation,
    ) -> Result<(), Error> {
        let mut s = ts::sign_community_membership_revocation(signers[0], r);
        for c in &signers[1..] {
            ts::cosign_community_membership_revocation(&mut s, c);
        }
        d.put_community_membership_revocation(s).await
    }

    async fn widen(
        d: &dyn FederationDirectory,
        signer: &str,
        w: CommunityMembershipWidening,
    ) -> Result<(), Error> {
        d.put_community_membership_widening(ts::sign_community_membership_widening(signer, w))
            .await
    }

    async fn revoke(
        d: &dyn FederationDirectory,
        signer: &str,
        r: CommunityMembershipRevocation,
    ) -> Result<(), Error> {
        d.put_community_membership_revocation(ts::sign_community_membership_revocation(signer, r))
            .await
    }

    async fn active(d: &dyn FederationDirectory, room: &str) -> Vec<String> {
        let mut v: Vec<String> = d
            .active_community_members(room)
            .await
            .unwrap()
            .into_iter()
            .map(|m| m.key_id)
            .collect();
        v.sort();
        v
    }

    fn rule_of(e: &Error) -> &'static str {
        match e {
            Error::RosterAuthorityUnauthorized { rule, .. } => rule,
            other => panic!("expected RosterAuthorityUnauthorized, got {other}"),
        }
    }

    /// Is `member` admitted to `room` by every admission reader?
    async fn admitted(d: &dyn FederationDirectory, member: &str, room: &str) -> bool {
        let adm =
            crate::scope::admission::build_caller_admission_from_directory(d, &member.to_owned())
                .await
                .unwrap();
        let by_admission = adm.community_key_ids.contains(room);
        let by_active = d
            .list_communities_for_member_active(member)
            .await
            .unwrap()
            .iter()
            .any(|c| c.community_key_id == room);
        let by_groups = d
            .groups_of(Cohort::Community, member)
            .await
            .unwrap()
            .iter()
            .any(|g| g.group_key_id == room);
        assert_eq!(
            (by_admission, by_active),
            (by_active, by_groups),
            "every admission reader agrees about {member} in {room}"
        );
        by_admission
    }

    /// **I170 — admission is the roster.** A `founder_only` room, so the
    /// founder's single signature is the protocol (CC 4.4.3.4.2).
    pub async fn i170_admission_is_the_roster(d: &dyn FederationDirectory, tag: &str) {
        let (room, alice, _bob) = make_room(d, tag, consensus_protocol::FOUNDER_ONLY).await;
        let carol = format!("{tag}-carol");
        user(d, &carol).await;
        assert!(!admitted(d, &carol, &room).await, "{tag} I170: control");
        widen(
            d,
            &alice,
            widening(&room, &carol, at("2026-03-01T00:00:00Z"), None),
        )
        .await
        .unwrap_or_else(|e| panic!("{tag} I170: widen: {e}"));
        assert!(
            admitted(d, &carol, &room).await,
            "{tag} I170: a widened member is admitted (#907)"
        );
        revoke(
            d,
            &alice,
            revocation(&room, &carol, at("2026-03-02T00:00:00Z")),
        )
        .await
        .unwrap_or_else(|e| panic!("{tag} I170: revoke: {e}"));
        assert!(
            !admitted(d, &carol, &room).await,
            "{tag} I170: removed ⇒ refused"
        );
        widen(
            d,
            &alice,
            widening(&room, &carol, at("2026-03-03T00:00:00Z"), None),
        )
        .await
        .unwrap_or_else(|e| panic!("{tag} I170: re-add: {e}"));
        assert!(
            admitted(d, &carol, &room).await,
            "{tag} I170: a removed-then-re-added member is admitted again (#907)"
        );
        assert!(admitted(d, &alice, &room).await);
    }

    /// **I171 — standing is the room's consensus protocol** (CC 4.4.3.2.3):
    /// one arm per protocol, each refused and then admitted; a stranger is
    /// retryable-refused; the record signer alone has no standing.
    #[allow(clippy::too_many_lines)]
    pub async fn i171_standing_is_the_protocol(d: &dyn FederationDirectory, tag: &str) {
        use crate::federation::{
            ROSTER_AUTHORITY_RULE_NOT_ESTABLISHED as NOT_ESTABLISHED,
            ROSTER_CONSENSUS_INSUFFICIENT as INSUFFICIENT,
            ROSTER_CONSENSUS_UNEVALUABLE as UNEVALUABLE,
        };
        let t = |n: u32| at(&format!("2026-03-{n:02}T00:00:00Z"));
        let refused = |r: Result<(), Error>, want: &str, what: &str| {
            let e = r.expect_err(what);
            assert_eq!(rule_of(&e), want, "{tag} I171 {what}: {e}");
        };
        let newcomer = |n: &str| format!("{tag}-{n}");
        for n in ["x1", "x2", "x3", "x4", "x5", "x6", "eve"] {
            user(d, &newcomer(n)).await;
        }
        let eve = newcomer("eve");

        // founder_only: a plain member refused, a founder admitted.
        let (r, k) = make_group(
            d,
            &format!("{tag}-fo"),
            consensus_protocol::FOUNDER_ONLY,
            &["a", "b"],
            1,
            None,
            None,
        )
        .await;
        refused(
            widen_by(d, &[&k[1]], widening(&r, &newcomer("x1"), t(1), None)).await,
            INSUFFICIENT,
            "founder_only: a plain member",
        );
        widen_by(d, &[&k[0]], widening(&r, &newcomer("x1"), t(2), None))
            .await
            .unwrap_or_else(|e| panic!("{tag} founder_only admits a founder: {e}"));
        // A stranger: retryable, and no row is stored.
        refused(
            widen_by(d, &[&eve], widening(&r, &eve, t(3), None)).await,
            NOT_ESTABLISHED,
            "a stranger widens itself",
        );
        refused(
            revoke_by(d, &[&eve], revocation(&r, &k[1], t(3))).await,
            NOT_ESTABLISHED,
            "a stranger removes a member",
        );
        assert!(
            d.list_community_membership_revocations_for(&r)
                .await
                .unwrap()
                .is_empty(),
            "{tag} I171: a refused removal stores no row (and rotates nothing)"
        );

        // majority of three: one refused, two admitted.
        let (r, k) = make_group(
            d,
            &format!("{tag}-mj"),
            consensus_protocol::MAJORITY,
            &["a", "b", "c"],
            1,
            None,
            None,
        )
        .await;
        refused(
            widen_by(d, &[&k[1]], widening(&r, &newcomer("x2"), t(1), None)).await,
            INSUFFICIENT,
            "majority: 1 of 3",
        );
        widen_by(
            d,
            &[&k[1], &k[2]],
            widening(&r, &newcomer("x2"), t(2), None),
        )
        .await
        .unwrap_or_else(|e| panic!("{tag} majority: 2 of 3: {e}"));

        // unanimous of three: two refused, three admitted.
        let (r, k) = make_group(
            d,
            &format!("{tag}-un"),
            consensus_protocol::UNANIMOUS,
            &["a", "b", "c"],
            1,
            None,
            None,
        )
        .await;
        refused(
            widen_by(
                d,
                &[&k[0], &k[1]],
                widening(&r, &newcomer("x3"), t(1), None),
            )
            .await,
            INSUFFICIENT,
            "unanimous: 2 of 3",
        );
        widen_by(
            d,
            &[&k[0], &k[1], &k[2]],
            widening(&r, &newcomer("x3"), t(2), None),
        )
        .await
        .unwrap_or_else(|e| panic!("{tag} unanimous: 3 of 3: {e}"));

        // quorum:2/5 — absolute M.
        let (r, k) = make_group(
            d,
            &format!("{tag}-qu"),
            "quorum:2/5",
            &["a", "b", "c", "d", "e"],
            1,
            None,
            None,
        )
        .await;
        refused(
            widen_by(d, &[&k[3]], widening(&r, &newcomer("x4"), t(1), None)).await,
            INSUFFICIENT,
            "quorum:2/5: 1",
        );
        widen_by(
            d,
            &[&k[3], &k[4]],
            widening(&r, &newcomer("x4"), t(2), None),
        )
        .await
        .unwrap_or_else(|e| panic!("{tag} quorum:2/5: 2: {e}"));

        // custom:x undeclared — unevaluable, whoever signs.
        let (r, k) = make_group(
            d,
            &format!("{tag}-cu"),
            "custom:x",
            &["a", "b"],
            1,
            None,
            None,
        )
        .await;
        refused(
            widen_by(
                d,
                &[&k[0], &k[1]],
                widening(&r, &newcomer("x5"), t(1), None),
            )
            .await,
            UNEVALUABLE,
            "custom:x undeclared",
        );

        // The record signer alone — not a member — has no standing.
        let rec = newcomer("rec");
        user(d, &rec).await;
        let (r, _k) = make_group(
            d,
            &format!("{tag}-rs"),
            consensus_protocol::FOUNDER_ONLY,
            &["a", "b"],
            1,
            None,
            Some(&rec),
        )
        .await;
        refused(
            widen_by(d, &[&rec], widening(&r, &newcomer("x6"), t(1), None)).await,
            NOT_ESTABLISHED,
            "the record signer alone",
        );
    }

    /// **I172 — the fold judges the history, not the arrival.** A majority
    /// room of three; carol and alice remove bob at t1; bob and alice widen dan
    /// at t2. A sees the widening first (2 of 3 then); B sees the removal
    /// first and refuses the widening. After both arrive, both fold alike.
    pub async fn i172_the_fold_judges_the_history(
        a: &dyn FederationDirectory,
        b: &dyn FederationDirectory,
        tag: &str,
    ) {
        let names = ["alice", "bob", "carol"];
        let (room, k) =
            make_group(a, tag, consensus_protocol::MAJORITY, &names, 1, None, None).await;
        let (room_b, _) =
            make_group(b, tag, consensus_protocol::MAJORITY, &names, 1, None, None).await;
        assert_eq!(room, room_b);
        let (alice, bob, carol) = (&k[0], &k[1], &k[2]);
        let dan = format!("{tag}-dan");
        user(a, &dan).await;
        user(b, &dan).await;
        let mut rev = ts::sign_community_membership_revocation(
            alice,
            revocation(&room, bob, at("2026-03-01T00:00:00Z")),
        );
        ts::cosign_community_membership_revocation(&mut rev, carol);
        let mut wid = ts::sign_community_membership_widening(
            bob,
            widening(&room, &dan, at("2026-03-02T00:00:00Z"), None),
        );
        ts::cosign_community_membership_widening(&mut wid, alice);
        a.put_community_membership_widening(wid.clone())
            .await
            .unwrap_or_else(|e| panic!("{tag} I172: A admits the widening first: {e}"));
        a.put_community_membership_revocation(rev.clone())
            .await
            .unwrap();
        b.put_community_membership_revocation(rev).await.unwrap();
        let e = b
            .put_community_membership_widening(wid)
            .await
            .expect_err("B refuses: bob was out at t2");
        assert_eq!(
            rule_of(&e),
            crate::federation::ROSTER_CONSENSUS_INSUFFICIENT,
            "{tag} I172: {e}"
        );
        let want = {
            let mut v = vec![alice.clone(), carol.clone()];
            v.sort();
            v
        };
        assert_eq!(active(a, &room).await, want, "{tag} I172: A");
        assert_eq!(active(b, &room).await, want, "{tag} I172: B");
    }

    /// **I180 — the last founder, and leaving.** A member leaves on their own
    /// signature, in any protocol; the last founder may not leave, or be
    /// demoted, while others remain; a second founder frees them.
    pub async fn i180_the_last_founder(d: &dyn FederationDirectory, tag: &str) {
        let (room, k) = make_group(
            d,
            tag,
            consensus_protocol::UNANIMOUS,
            &["alice", "bob", "carol"],
            1,
            None,
            None,
        )
        .await;
        let (alice, bob, carol) = (&k[0], &k[1], &k[2]);
        revoke_by(
            d,
            &[bob],
            revocation(&room, bob, at("2026-03-01T00:00:00Z")),
        )
        .await
        .unwrap_or_else(|e| panic!("{tag} I180: bob leaves a unanimous room alone: {e}"));
        let e = revoke_by(
            d,
            &[alice],
            revocation(&room, alice, at("2026-03-02T00:00:00Z")),
        )
        .await
        .expect_err("the last founder may not leave while carol remains");
        assert_eq!(
            rule_of(&e),
            crate::federation::ROSTER_LAST_FOUNDER,
            "{tag} I180: {e}"
        );
        let e = widen_by(
            d,
            &[alice, carol],
            widening(&room, alice, at("2026-03-02T00:00:00Z"), None),
        )
        .await
        .expect_err("nor be demoted");
        assert_eq!(
            rule_of(&e),
            crate::federation::ROSTER_LAST_FOUNDER,
            "{tag} I180 demote: {e}"
        );
        widen_by(
            d,
            &[alice, carol],
            widening(&room, carol, at("2026-03-03T00:00:00Z"), Some("founder")),
        )
        .await
        .unwrap_or_else(|e| panic!("{tag} I180: carol promoted: {e}"));
        revoke_by(
            d,
            &[alice],
            revocation(&room, alice, at("2026-03-04T00:00:00Z")),
        )
        .await
        .unwrap_or_else(|e| panic!("{tag} I180: alice may leave once carol is a founder: {e}"));
        assert_eq!(active(d, &room).await, vec![carol.clone()], "{tag} I180");
    }

    /// **I182 — declared rubrics and custom protocols are evaluated.** The
    /// room record's `policy_blob` declares them; the evaluator reads them.
    pub async fn i182_declared_protocols(d: &dyn FederationDirectory, tag: &str) {
        let blob = serde_json::json!({
            "rubrics": {"votes": {"weights": {"role:founder": 3}, "default_weight": 1, "threshold": 4}},
            "custom": {"council": {"all_of": [{"founder": {}}, {"quorum": 2}]}}
        });
        let x = format!("{tag}-x");
        let y = format!("{tag}-y");
        user(d, &x).await;
        user(d, &y).await;
        let (r, k) = make_group(
            d,
            &format!("{tag}-w"),
            "weighted:votes",
            &["a", "b", "c"],
            1,
            Some(blob.clone()),
            None,
        )
        .await;
        let e = widen_by(
            d,
            &[&k[1], &k[2]],
            widening(&r, &x, at("2026-03-01T00:00:00Z"), None),
        )
        .await
        .expect_err("2 of 4 weight");
        assert_eq!(
            rule_of(&e),
            crate::federation::ROSTER_CONSENSUS_INSUFFICIENT,
            "{tag} I182 weighted: {e}"
        );
        widen_by(
            d,
            &[&k[0], &k[1]],
            widening(&r, &x, at("2026-03-02T00:00:00Z"), None),
        )
        .await
        .unwrap_or_else(|e| panic!("{tag} I182 weighted: 4 of 4: {e}"));
        let (r, k) = make_group(
            d,
            &format!("{tag}-c"),
            "custom:council",
            &["a", "b", "c"],
            1,
            Some(blob),
            None,
        )
        .await;
        let e = widen_by(
            d,
            &[&k[1], &k[2]],
            widening(&r, &y, at("2026-03-01T00:00:00Z"), None),
        )
        .await
        .expect_err("no founder");
        assert_eq!(
            rule_of(&e),
            crate::federation::ROSTER_CONSENSUS_INSUFFICIENT,
            "{tag} I182 custom: {e}"
        );
        widen_by(
            d,
            &[&k[0], &k[1]],
            widening(&r, &y, at("2026-03-02T00:00:00Z"), None),
        )
        .await
        .unwrap_or_else(|e| panic!("{tag} I182 custom: founder + 2: {e}"));
    }

    fn unverified_signer(e: &Error) -> &str {
        match e {
            Error::FederationTierUnverified {
                attesting_key_id, ..
            } => attesting_key_id,
            other => panic!("expected FederationTierUnverified, got {other}"),
        }
    }

    fn assert_invalid(e: &Error, needle: &str, what: &str) {
        assert!(
            matches!(e, Error::InvalidArgument(m) if m.contains(needle)),
            "{what}: expected InvalidArgument naming {needle:?}, got {e}"
        );
    }

    /// **I176 — co-signatures are verified.** A co-signature over a different
    /// envelope, a duplicate co-signer, and a co-signer equal to the primary
    /// are each refused, before any write; a co-signed row round-trips its
    /// co-signatures byte-exact through the signed since-read, and a
    /// byte-identical re-put is the #861 no-op. Widening and community
    /// revocation both; the family revocation's verify gate too.
    pub async fn i176_cosignatures_are_verified(d: &dyn FederationDirectory, tag: &str) {
        let (room, alice, bob) = make_room(d, tag, consensus_protocol::MAJORITY).await;
        let carol = format!("{tag}-carol");
        let dave = format!("{tag}-dave");
        user(d, &carol).await;
        user(d, &dave).await;
        let t1 = at("2026-03-01T00:00:00Z");
        let t2 = at("2026-03-02T00:00:00Z");

        // ── widening: the refusals, none of which stores a row ──────────
        let other = ts::sign_community_membership_widening(
            &alice,
            widening(&room, &dave, at("2026-02-01T00:00:00Z"), None),
        );
        let mut foreign = other.clone();
        ts::cosign_community_membership_widening(&mut foreign, &bob);
        let mut wrong_env =
            ts::sign_community_membership_widening(&alice, widening(&room, &dave, t1, None));
        wrong_env.cosignatures = foreign.cosignatures.clone();
        let e = d
            .put_community_membership_widening(wrong_env)
            .await
            .expect_err("I176: a co-signature over another envelope");
        assert_eq!(
            unverified_signer(&e),
            bob,
            "{tag} I176: names the co-signer"
        );

        let mut dup =
            ts::sign_community_membership_widening(&alice, widening(&room, &dave, t1, None));
        ts::cosign_community_membership_widening(&mut dup, &bob);
        ts::cosign_community_membership_widening(&mut dup, &bob);
        let e = d
            .put_community_membership_widening(dup)
            .await
            .expect_err("I176: a duplicate co-signer");
        assert_invalid(&e, "duplicate co-signer", "widening duplicate");

        let mut selfco =
            ts::sign_community_membership_widening(&alice, widening(&room, &dave, t1, None));
        ts::cosign_community_membership_widening(&mut selfco, &alice);
        let e = d
            .put_community_membership_widening(selfco)
            .await
            .expect_err("I176: the primary as its own co-signer");
        assert_invalid(&e, "is the primary signer", "widening self co-sign");
        assert!(
            !active(d, &room).await.contains(&dave),
            "{tag} I176: no refused widening stored a row"
        );

        // ── widening: the co-signed row round-trips byte-exact ──────────
        let mut good =
            ts::sign_community_membership_widening(&alice, widening(&room, &carol, t1, None));
        ts::cosign_community_membership_widening(&mut good, &bob);
        d.put_community_membership_widening(good.clone())
            .await
            .unwrap_or_else(|e| panic!("{tag} I176: a co-signed widening: {e}"));
        // #861 — the byte-identical re-put is a no-op, not a refusal.
        d.put_community_membership_widening(good.clone())
            .await
            .unwrap_or_else(|e| panic!("{tag} I176: an identical re-put: {e}"));
        let served: Vec<_> = d
            .list_signed_community_membership_widenings_since(None, u32::MAX)
            .await
            .unwrap()
            .into_iter()
            .filter(|w| {
                w.widening.community_membership_widening.community_key_id == room
                    && w.widening.community_membership_widening.member_key_id == carol
            })
            .collect();
        assert_eq!(served.len(), 1, "{tag} I176: one widening row");
        let mut expect = good.clone();
        expect.community_membership_widening.persist_row_hash = served[0]
            .widening
            .community_membership_widening
            .persist_row_hash
            .clone();
        assert_eq!(
            serde_json::to_vec(&served[0].widening).unwrap(),
            serde_json::to_vec(&expect).unwrap(),
            "{tag} I176: the widening serves its co-signatures byte-exact"
        );
        assert_eq!(served[0].widening.cosignatures.len(), 1);
        crate::federation::verify_community_membership_widening_admission(d, &served[0].widening)
            .await
            .unwrap_or_else(|e| panic!("{tag} I176: the served widening re-verifies: {e}"));
        let signers = d.community_roster_signers(&room).await.unwrap();
        let w = signers
            .widening_signers
            .iter()
            .find(|s| s.member_key_id == carol)
            .expect("carol's widening signer");
        assert_eq!(w.authority_key_id.as_deref(), Some(alice.as_str()));
        assert_eq!(
            w.cosigner_key_ids,
            vec![bob.clone()],
            "{tag} I176: co-signers"
        );

        // ── community revocation: the same four legs ───────────────────
        let mut foreign =
            ts::sign_community_membership_revocation(&alice, revocation(&room, &carol, t1));
        ts::cosign_community_membership_revocation(&mut foreign, &bob);
        let mut wrong_env =
            ts::sign_community_membership_revocation(&alice, revocation(&room, &carol, t2));
        wrong_env.cosignatures = foreign.cosignatures.clone();
        let e = d
            .put_community_membership_revocation(wrong_env)
            .await
            .expect_err("I176: a revocation co-signature over another envelope");
        assert_eq!(unverified_signer(&e), bob);

        let mut dup =
            ts::sign_community_membership_revocation(&alice, revocation(&room, &carol, t2));
        ts::cosign_community_membership_revocation(&mut dup, &bob);
        ts::cosign_community_membership_revocation(&mut dup, &bob);
        let e = d
            .put_community_membership_revocation(dup)
            .await
            .expect_err("I176: a duplicate revocation co-signer");
        assert_invalid(&e, "duplicate co-signer", "revocation duplicate");

        let mut selfco =
            ts::sign_community_membership_revocation(&alice, revocation(&room, &carol, t2));
        ts::cosign_community_membership_revocation(&mut selfco, &alice);
        let e = d
            .put_community_membership_revocation(selfco)
            .await
            .expect_err("I176: the primary as its own revocation co-signer");
        assert_invalid(&e, "is the primary signer", "revocation self co-sign");
        assert!(
            active(d, &room).await.contains(&carol),
            "{tag} I176: no refused revocation stored a row"
        );

        let mut good_rev =
            ts::sign_community_membership_revocation(&alice, revocation(&room, &carol, t2));
        ts::cosign_community_membership_revocation(&mut good_rev, &bob);
        d.put_community_membership_revocation(good_rev.clone())
            .await
            .unwrap_or_else(|e| panic!("{tag} I176: a co-signed revocation: {e}"));
        d.put_community_membership_revocation(good_rev.clone())
            .await
            .unwrap_or_else(|e| panic!("{tag} I176: an identical revocation re-put: {e}"));
        let served: Vec<_> = d
            .list_signed_community_membership_revocations_since(None, u32::MAX)
            .await
            .unwrap()
            .into_iter()
            .filter(|r| {
                r.revocation
                    .community_membership_revocation
                    .community_key_id
                    == room
                    && r.revocation
                        .community_membership_revocation
                        .removed_identity_key_id
                        == carol
            })
            .collect();
        assert_eq!(served.len(), 1, "{tag} I176: one revocation row");
        let mut expect = good_rev.clone();
        expect.community_membership_revocation.persist_row_hash = served[0]
            .revocation
            .community_membership_revocation
            .persist_row_hash
            .clone();
        assert_eq!(
            serde_json::to_vec(&served[0].revocation).unwrap(),
            serde_json::to_vec(&expect).unwrap(),
            "{tag} I176: the revocation serves its co-signatures byte-exact"
        );
        let signers = d.community_roster_signers(&room).await.unwrap();
        let r = signers
            .revocation_signers
            .iter()
            .find(|s| s.member_key_id == carol)
            .expect("carol's revocation signer");
        assert_eq!(r.cosigner_key_ids, vec![bob.clone()]);
        assert!(!active(d, &room).await.contains(&carol));

        // ── family revocation: the verify gate (no family needed) ──────
        let fam_rev = || crate::federation::types::FamilyMembershipRevocation {
            family_key_id: format!("{tag}-fam"),
            removed_identity_key_id: carol.clone(),
            removed_at: t2,
            effective_at: t2,
            reason: None,
            witness_set: vec![],
            persist_row_hash: String::new(),
        };
        let mut ok = ts::sign_family_membership_revocation(&alice, fam_rev());
        ts::cosign_family_membership_revocation(&mut ok, &bob);
        crate::federation::verify_family_membership_revocation_admission(d, &ok)
            .await
            .unwrap_or_else(|e| panic!("{tag} I176: a co-signed family revocation: {e}"));
        let mut dup = ok.clone();
        ts::cosign_family_membership_revocation(&mut dup, &bob);
        let e = crate::federation::verify_family_membership_revocation_admission(d, &dup)
            .await
            .expect_err("I176: a duplicate family co-signer");
        assert_invalid(&e, "duplicate co-signer", "family duplicate");
        let mut selfco = ts::sign_family_membership_revocation(&alice, fam_rev());
        ts::cosign_family_membership_revocation(&mut selfco, &alice);
        let e = crate::federation::verify_family_membership_revocation_admission(d, &selfco)
            .await
            .expect_err("I176: the family primary as its own co-signer");
        assert_invalid(&e, "is the primary signer", "family self co-sign");
        let mut wrong_env = ts::sign_family_membership_revocation(&alice, fam_rev());
        let mut moved = fam_rev();
        moved.effective_at = t1;
        let mut foreign = ts::sign_family_membership_revocation(&alice, moved);
        ts::cosign_family_membership_revocation(&mut foreign, &bob);
        wrong_env.cosignatures = foreign.cosignatures;
        let e = crate::federation::verify_family_membership_revocation_admission(d, &wrong_env)
            .await
            .expect_err("I176: a family co-signature over another envelope");
        assert_eq!(unverified_signer(&e), bob);
    }

    /// **I173 (fold half) — a revocation with no recorded signer counts.**
    pub fn i173_a_legacy_revocation_counts() {
        let t0 = at("2026-01-01T00:00:00Z");
        let t1 = at("2026-03-01T00:00:00Z");
        let record = vec![
            CommunityMember {
                key_id: "a".into(),
                joined_at: t0,
                role: Some("founder".into()),
            },
            CommunityMember {
                key_id: "b".into(),
                joined_at: t0,
                role: None,
            },
        ];
        let legacy = crate::federation::RosterEvent {
            effective_at: t1,
            is_add: false,
            member: CommunityMember {
                key_id: "b".into(),
                joined_at: t1,
                role: None,
            },
            signers: Default::default(),
            moderator_roots: Default::default(),
            reversed: false,
        };
        let rules = crate::federation::RosterRules {
            protocol: consensus_protocol::UNANIMOUS,
            subkind: None,
            policy_blob: None,
        };
        let roster = crate::federation::authorized_roster_at(&record, rules, &[legacy], t1);
        assert_eq!(
            roster.iter().map(|m| m.key_id.as_str()).collect::<Vec<_>>(),
            vec!["a"],
            "I173: a legacy (signer-less) revocation still removes"
        );
    }

    /// **I173 (store half)** — the same, with the signer nulled in storage
    /// below the door: the backend read maps it to `None` and the fold counts it.
    pub async fn i173_after_nulling(d: &dyn FederationDirectory, room: &str, bob: &str) {
        let signers = d.community_roster_signers(room).await.unwrap();
        assert!(
            signers
                .revocation_signers
                .iter()
                .any(|s| s.member_key_id == bob && s.authority_key_id.is_none()),
            "I173: the stored signer is gone"
        );
        assert!(
            !active(d, room).await.iter().any(|k| k == bob),
            "I173: the legacy removal still removes"
        );
    }

    /// The store-half setup: a room, bob removed by alice.
    pub async fn i173_setup(d: &dyn FederationDirectory, tag: &str) -> (String, String) {
        let (room, alice, bob) = make_room(d, tag, consensus_protocol::FOUNDER_ONLY).await;
        revoke(
            d,
            &alice,
            revocation(&room, &bob, at("2026-03-01T00:00:00Z")),
        )
        .await
        .unwrap();
        (room, bob)
    }
}

#[cfg(test)]
mod run {
    fn suffix() -> String {
        uuid::Uuid::new_v4().simple().to_string()
    }

    #[test]
    fn i173_fold() {
        super::bodies::i173_a_legacy_revocation_counts();
    }

    macro_rules! dyn_runners {
        ($modname:ident, $fresh:expr) => {
            mod $modname {
                use crate::federation::FederationDirectory;
                #[tokio::test]
                async fn i170() {
                    let Some(d) = $fresh.await else { return };
                    super::super::bodies::i170_admission_is_the_roster(
                        &d as &dyn FederationDirectory,
                        &format!("i170-{}", super::suffix()),
                    )
                    .await
                }
                #[tokio::test]
                async fn i171() {
                    let Some(d) = $fresh.await else { return };
                    super::super::bodies::i171_standing_is_the_protocol(
                        &d as &dyn FederationDirectory,
                        &format!("i171-{}", super::suffix()),
                    )
                    .await
                }
                #[tokio::test]
                async fn i180() {
                    let Some(d) = $fresh.await else { return };
                    super::super::bodies::i180_the_last_founder(
                        &d as &dyn FederationDirectory,
                        &format!("i180-{}", super::suffix()),
                    )
                    .await
                }
                #[tokio::test]
                async fn i182() {
                    let Some(d) = $fresh.await else { return };
                    super::super::bodies::i182_declared_protocols(
                        &d as &dyn FederationDirectory,
                        &format!("i182-{}", super::suffix()),
                    )
                    .await
                }
                #[tokio::test]
                async fn i176() {
                    let Some(d) = $fresh.await else { return };
                    super::super::bodies::i176_cosignatures_are_verified(
                        &d as &dyn FederationDirectory,
                        &format!("i176-{}", super::suffix()),
                    )
                    .await
                }
                #[tokio::test]
                async fn i172() {
                    let (Some(a), Some(b)) = ($fresh.await, $fresh.await) else {
                        return;
                    };
                    super::super::bodies::i172_the_fold_judges_the_history(
                        &a as &dyn FederationDirectory,
                        &b as &dyn FederationDirectory,
                        &format!("i172-{}", super::suffix()),
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

    #[cfg(feature = "sqlite")]
    #[tokio::test]
    async fn i173_sqlite() {
        use crate::store::Backend as _;
        let b = crate::store::sqlite::SqliteBackend::open_in_memory()
            .await
            .unwrap();
        b.run_migrations().await.unwrap();
        let (room, bob) = super::bodies::i173_setup(&b, &format!("i173-{}", suffix())).await;
        let r = room.clone();
        b.write(move |c| {
            c.execute(
                "UPDATE federation_community_membership_revocations \
                 SET authority_key_id = NULL WHERE community_key_id = ?1",
                [&r],
            )
        })
        .await
        .unwrap();
        super::bodies::i173_after_nulling(&b, &room, &bob).await;
    }

    #[cfg(feature = "postgres")]
    #[tokio::test]
    async fn i173_postgres() {
        use crate::store::Backend as _;
        let Some(dsn) = crate::test_pg::empty_dsn() else {
            return;
        };
        let b = crate::store::postgres::PostgresBackend::connect(&dsn)
            .await
            .unwrap();
        b.run_migrations().await.unwrap();
        let (room, bob) = super::bodies::i173_setup(&b, &format!("i173-{}", suffix())).await;
        b.get_client()
            .await
            .unwrap()
            .execute(
                "UPDATE cirislens.federation_community_membership_revocations \
                 SET authority_key_id = NULL WHERE community_key_id = $1",
                &[&room],
            )
            .await
            .unwrap();
        super::bodies::i173_after_nulling(&b, &room, &bob).await;
    }
}
