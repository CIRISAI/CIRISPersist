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
    use crate::federation::edition2::ingest::StatementOutcome;

    use crate::federation::tier_ingest::test_support as ts;
    use crate::federation::types::{
        consensus_protocol, identity_type, Community, CommunityMember,
        CommunityMembershipRevocation, CommunityMembershipWidening,
    };
    use crate::federation::{Error, FederationDirectory};

    /// v62 (E4, round 3): a key seed for `name` in the test tagged `tag`.
    /// A test signer seeds from the FIRST 32 BYTES of its seed, so
    /// `format!("{tag}-{name}")` with a long tag gives every name ONE key
    /// (and a room the same id as its members): `members` then repeats a key
    /// and the roster payload is refused. The tag is folded into a short
    /// digest after the distinguishing name.
    pub(crate) fn sd(name: &str, tag: &str) -> String {
        use sha2::Digest as _;
        let h = hex::encode(sha2::Sha256::digest(tag.as_bytes()));
        format!("{name}-{}", &h[..16])
    }

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

    /// v62 (E4): `k` live as an edition-2 `user` key (no start, no end, so
    /// the fixed 2026 instants below stay inside its liveness).
    async fn user(d: &dyn FederationDirectory, k: &str) {
        crate::federation::edition2::fixture_switch::put_key(d, k, &[identity_type::USER]).await;
    }

    /// A room of `names` (each `{tag}-{name}`, registered user keys), the
    /// first `founders` of them tagged `founder`, under `protocol`, signed by
    /// `record_signer` (default: the first member) and carrying `policy_blob`.
    /// The room id is no key. Returns the room id and the member key ids.
    ///
    /// v62 (E4, flip wave 2): the record is the `group:roster` statements of
    /// its signer and listed members (T1 `community_voices`), and the
    /// returned ids are the identity-refs the typed rows are keyed by
    /// (`e2::kid`); every seed-taking fixture accepts them back.
    pub async fn make_group(
        d: &dyn FederationDirectory,
        tag: &str,
        protocol: &str,
        names: &[&str],
        founders: usize,
        policy_blob: Option<serde_json::Value>,
        record_signer: Option<&str>,
    ) -> (String, Vec<String>) {
        let room = sd("room", tag);
        let keys: Vec<String> = names.iter().map(|n| sd(n, tag)).collect();
        for k in &keys {
            user(d, k).await;
        }
        let signer = record_signer
            .map(str::to_owned)
            .unwrap_or_else(|| keys[0].clone());
        let community = ts::sign_community(
            &signer,
            Community {
                prev_head_digest: String::new(),
                charter_digest: String::new(),
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
        );
        // v61 (CIRISPersist#1123) — the local door refuses `founder_only`
        // above the family. A room under it is a LEGACY room (stored before
        // v61, as the field holds one), which a peer still delivers: the
        // replicated door admits it as data, and every fold reads it as
        // before. An affiliation keeps `founder_only` on the local door.
        //
        // v62 (E4): an edition-2 statement has one entry for local and
        // replicated delivery (`ingest::put_statement`), so the legacy room
        // and the ordinary one land the same way.
        use crate::federation::edition2::fixture_switch as e2;
        let founded_ms = u64::try_from(at("2026-01-01T00:00:00Z").timestamp_millis()).expect("ms");
        e2::put_voices(d, &e2::community_voices(&community, 1, None, founded_ms))
            .await
            .unwrap_or_else(|e| panic!("{tag}: room: {e}"));
        (e2::kid(&room), keys.iter().map(|k| e2::kid(k)).collect())
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

    // v62 (E4, flip wave 2): the roster changes are `membership:{stage}`
    // statements (T1), one per signer, naming the held roster version
    // (`refs.head`). A change short of the protocol is KEPT as voices with
    // no typed row (`StatementOutcome::Pending`), the edition-2 form of the
    // JSON door's `roster_consensus_insufficient`; see [`short_or_refused`].

    /// The roster version a change names.
    pub(crate) async fn head_of(
        d: &dyn FederationDirectory,
        room: &str,
    ) -> Option<crate::federation::edition2::names::RowId> {
        use crate::federation::edition2::fixture_switch as e2;
        e2::held_head(d, &e2::kid_or_keep(room))
            .await
            .map(|(h, _)| h)
    }

    /// The member's consent, held as edition-2 rows before its widening
    /// (the #955 growth gate): `proposer`'s proposal, the member's
    /// acceptance. Best-effort, as `ConsentedWidening` writes it: a widening
    /// that must be refused for another reason is still refused by the door.
    pub(crate) async fn consent(
        d: &dyn FederationDirectory,
        proposer: &str,
        w: &CommunityMembershipWidening,
    ) {
        use crate::federation::edition2::fixture_switch as e2;
        use crate::federation::membership_acceptance::test_support::{
            acceptance_row, proposal_row,
        };
        let p = proposal_row(
            proposer,
            crate::federation::types::cohort_scope::COMMUNITY,
            &w.community_key_id,
            &w.member_key_id,
            w.role.as_deref(),
            w.effective_at,
        );
        if let Err(e) = e2::put_signed(d, &p).await {
            eprintln!("room_roster_authority: proposal not written: {e}");
            return;
        }
        if let Err(e) =
            e2::put_signed(d, &acceptance_row(&w.member_key_id, &p, w.effective_at)).await
        {
            eprintln!("room_roster_authority: acceptance not written: {e}");
        }
    }

    /// A widening signed by `signers[0]` and co-signed by the rest.
    pub(crate) async fn widen_by(
        d: &dyn FederationDirectory,
        signers: &[&str],
        w: CommunityMembershipWidening,
    ) -> Result<StatementOutcome, Error> {
        use crate::federation::edition2::fixture_switch as e2;
        consent(d, signers[0], &w).await;
        let head = head_of(d, &w.community_key_id).await;
        let mut s = ts::sign_community_membership_widening(signers[0], w);
        for c in &signers[1..] {
            ts::cosign_community_membership_widening(&mut s, c);
        }
        e2::put_voices(d, &e2::community_widening_voices(&s, head.as_ref())).await
    }

    /// A revocation signed by `signers[0]` and co-signed by the rest.
    pub(crate) async fn revoke_by(
        d: &dyn FederationDirectory,
        signers: &[&str],
        r: CommunityMembershipRevocation,
    ) -> Result<StatementOutcome, Error> {
        use crate::federation::edition2::fixture_switch as e2;
        let head = head_of(d, &r.community_key_id).await;
        let mut s = ts::sign_community_membership_revocation(signers[0], r);
        for c in &signers[1..] {
            ts::cosign_community_membership_revocation(&mut s, c);
        }
        e2::put_voices(d, &e2::community_revocation_voices(&s, head.as_ref())).await
    }

    async fn widen(
        d: &dyn FederationDirectory,
        signer: &str,
        w: CommunityMembershipWidening,
    ) -> Result<StatementOutcome, Error> {
        widen_by(d, &[signer], w).await
    }

    async fn revoke(
        d: &dyn FederationDirectory,
        signer: &str,
        r: CommunityMembershipRevocation,
    ) -> Result<StatementOutcome, Error> {
        revoke_by(d, &[signer], r).await
    }

    /// A change that must NOT land: `want` is the roster-authority rule.
    /// For `roster_consensus_insufficient` the edition-2 door keeps the
    /// short voices and lands no typed row (`Pending`), which is the same
    /// verdict; every other rule is a refusal.
    pub(crate) fn short_or_refused(r: Result<StatementOutcome, Error>, want: &str, what: &str) {
        match r {
            Ok(StatementOutcome::Pending { .. })
                if want == crate::federation::ROSTER_CONSENSUS_INSUFFICIENT => {}
            Ok(other) => panic!("{what}: landed ({other:?}); expected {want}"),
            Err(e) => assert_eq!(rule_of(&e), want, "{what}: {e}"),
        }
    }

    /// v62 (E4-fix6; CC 2.7.3) — a change that must NOT land, judged by a
    /// condition that reads the held roster (a fold condition): HELD
    /// (`Pending`, it concludes nothing) or refused by `want`. Never a row.
    pub(crate) fn held_or_refused(r: Result<StatementOutcome, Error>, want: &str, what: &str) {
        match r {
            Ok(StatementOutcome::Pending { .. }) => {}
            Ok(other) => panic!("{what}: landed ({other:?}); expected {want} or held"),
            Err(e) => assert_eq!(rule_of(&e), want, "{what}: {e}"),
        }
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
        let (room, alice, _bob) = make_room(d, tag, "quorum:1/1").await;
        // v62 (E4-fix6): registered from its seed, named by its identity-ref
        // (the id every admission reader returns).
        let carol_seed = sd("carol", tag);
        user(d, &carol_seed).await;
        let carol = crate::federation::edition2::fixture_switch::kid(&carol_seed);
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
        let refused = |r: Result<StatementOutcome, Error>, want: &str, what: &str| {
            short_or_refused(r, want, &format!("{tag} I171 {what}"));
        };
        let newcomer = |n: &str| sd(n, tag);
        for n in ["x1", "x2", "x3", "x4", "x5", "x6", "eve"] {
            user(d, &newcomer(n)).await;
        }
        let eve = newcomer("eve");

        // v62 (E4-fix6; CP2, ruling 4): the legacy `founder_only` arm is
        // DELETED. It drove a room stored under `founder_only` before v61; an
        // edition-2 room above the family is never founded under it (CC
        // 4.5.13, `founder_only_above_family`), so that room cannot be built.
        // The refusal of such a founding is the door's own witness; the
        // evaluator's `founder_only` arm stays witnessed on families and in
        // `consensus::tests`.

        // majority of three: one refused, two admitted.
        let (r, k) = make_group(
            d,
            &sd("mj", tag),
            consensus_protocol::MAJORITY,
            &["a", "b", "c"],
            1,
            None,
            None,
        )
        .await;
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
            &sd("un", tag),
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
            &sd("qu", tag),
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
        let (r, k) = make_group(d, &sd("cu", tag), "custom:x", &["a", "b"], 1, None, None).await;
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
            &sd("rs", tag),
            "quorum:1/1",
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
        let dan = sd("dan", tag);
        user(a, &dan).await;
        user(b, &dan).await;
        // v62 (E4, flip wave 2): the same statements reach both nodes in
        // opposite orders (the helpers put the member's consent first).
        let rev = || revocation(&room, bob, at("2026-03-01T00:00:00Z"));
        let wid = || widening(&room, &dan, at("2026-03-02T00:00:00Z"), None);
        widen_by(a, &[bob, alice], wid())
            .await
            .unwrap_or_else(|e| panic!("{tag} I172: A admits the widening first: {e}"));
        revoke_by(a, &[alice, carol], rev()).await.unwrap();
        revoke_by(b, &[alice, carol], rev()).await.unwrap();
        short_or_refused(
            widen_by(b, &[bob, alice], wid()).await,
            crate::federation::ROSTER_CONSENSUS_INSUFFICIENT,
            &format!("{tag} I172: B refuses, bob was out at t2"),
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
        // v62 (E4-fix6; CC 2.7.3): the last-founder rule reads the held
        // roster, a fold condition: the change is held or refused by name.
        held_or_refused(
            revoke_by(
                d,
                &[alice],
                revocation(&room, alice, at("2026-03-02T00:00:00Z")),
            )
            .await,
            crate::federation::ROSTER_LAST_FOUNDER,
            &format!("{tag} I180: the last founder may not leave while carol remains"),
        );
        held_or_refused(
            widen_by(
                d,
                &[alice, carol],
                widening(&room, alice, at("2026-03-02T00:00:00Z"), None),
            )
            .await,
            crate::federation::ROSTER_LAST_FOUNDER,
            &format!("{tag} I180 demote: nor be demoted"),
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
        let x = sd("x", tag);
        let y = sd("y", tag);
        user(d, &x).await;
        user(d, &y).await;
        let (r, k) = make_group(
            d,
            &sd("w", tag),
            "weighted:votes",
            &["a", "b", "c"],
            1,
            Some(blob.clone()),
            None,
        )
        .await;
        short_or_refused(
            widen_by(
                d,
                &[&k[1], &k[2]],
                widening(&r, &x, at("2026-03-01T00:00:00Z"), None),
            )
            .await,
            crate::federation::ROSTER_CONSENSUS_INSUFFICIENT,
            &format!("{tag} I182 weighted: 2 of 4 weight"),
        );
        {
            // One weight short: the founder alone carries 3 of 4.
            short_or_refused(
                widen_by(
                    d,
                    &[&k[0]],
                    widening(&r, &x, at("2026-03-02T00:00:00Z"), None),
                )
                .await,
                crate::federation::ROSTER_CONSENSUS_INSUFFICIENT,
                &format!("{tag} I182 weighted: 3 of 4 weight"),
            );
        }
        widen_by(
            d,
            &[&k[0], &k[1]],
            widening(&r, &x, at("2026-03-03T00:00:00Z"), None),
        )
        .await
        .unwrap_or_else(|e| panic!("{tag} I182 weighted: 4 of 4: {e}"));
        let (r, k) = make_group(
            d,
            &sd("c", tag),
            "custom:council",
            &["a", "b", "c"],
            1,
            Some(blob),
            None,
        )
        .await;
        // v62.0.0 (slice C) — CC 4.4.3.6's protocol table has six arms and no
        // `custom:`: a `custom:` group admits no change, with or without its
        // founder (was: insufficient without, admitted with). v62 (E4-fix6;
        // CC 2.7.3): judged against the held roster, it is held or refused.
        held_or_refused(
            widen_by(
                d,
                &[&k[1], &k[2]],
                widening(&r, &y, at("2026-03-01T00:00:00Z"), None),
            )
            .await,
            crate::federation::ROSTER_CONSENSUS_UNEVALUABLE,
            &format!("{tag} I182 custom: no founder"),
        );
        held_or_refused(
            widen_by(
                d,
                &[&k[0], &k[1]],
                widening(&r, &y, at("2026-03-02T00:00:00Z"), None),
            )
            .await,
            crate::federation::ROSTER_CONSENSUS_UNEVALUABLE,
            &format!("{tag} I182 custom, founder + 2: custom: is no consensus_protocol"),
        );
    }

    // v62 (E4, flip wave 2): I176 ("co-signatures are verified": a
    // co-signature over another envelope, a duplicate co-signer, the primary
    // as its own co-signer, and the byte-exact serve of `cosignatures`) is
    // DELETED: those are the earlier form's `RosterCosignature` proof shapes
    // (T1.api.md §3, "delete"). In edition 2 each signer is its own voice,
    // a statement the door verifies (`edition2_statement_invalid`).

    /// **I1524 (fold half; CIRISPersist#1200) — a held removal stands.** A
    /// removal admitted on a moderator's standing before the door refused it
    /// still applies in the fold: an admitted row is not unsaid by a later gate.
    pub fn i1524_an_admitted_moderator_removal_stands() {
        let t0 = at("2026-01-01T00:00:00Z");
        let t1 = at("2026-03-01T00:00:00Z");
        let member = |k: &str, role: Option<&str>| CommunityMember {
            key_id: k.into(),
            joined_at: t0,
            role: role.map(str::to_owned),
        };
        let held = crate::federation::RosterEvent {
            effective_at: t1,
            is_add: false,
            member: member("b", None),
            signers: ["mo".to_owned()].into_iter().collect(),
            moderator_roots: ["a".to_owned()].into_iter().collect(),
            reversed: false,
        };
        let rules = crate::federation::RosterRules {
            protocol: consensus_protocol::UNANIMOUS,
            subkind: None,
            policy_blob: None,
            node_bearing: &crate::federation::NO_NODE_BEARING_SEATS,
            persons: &crate::federation::key_person::NO_KEY_SELVES,
        };
        let record = vec![member("a", Some("founder")), member("b", None)];
        let roster = crate::federation::authorized_roster_at(&record, rules, &[held], t1);
        assert_eq!(
            roster.iter().map(|m| m.key_id.as_str()).collect::<Vec<_>>(),
            vec!["a"],
            "I1524: a held moderator removal still removes"
        );
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
            node_bearing: &crate::federation::NO_NODE_BEARING_SEATS,
            persons: &crate::federation::key_person::NO_KEY_SELVES,
        };
        let roster = crate::federation::authorized_roster_at(&record, rules, &[legacy], t1);
        assert_eq!(
            roster.iter().map(|m| m.key_id.as_str()).collect::<Vec<_>>(),
            vec!["a"],
            "I173: a legacy (signer-less) revocation still removes"
        );
    }

    /// **I1522** (CIRISPersist#1195; CC 4.5.4, 4.5.13) — moderation
    /// is an appointment at every protocol. A plain member of a room can sign
    /// for it, but holds no duty, is refused at the door and cannot root a
    /// chain. A founder and the founder's delegate hold exactly what was
    /// delegated.
    #[cfg(any(feature = "sqlite", feature = "postgres"))]
    pub async fn i1522_moderation_is_an_appointment(d: &dyn FederationDirectory, tag: &str) {
        use crate::federation::admission::steward_liveness_test_support::signed_row;
        use crate::federation::admission::{
            appointed_moderators_of, check_no_moderator_federate_admission,
            community_authority_set_for, duty_holders_for_community, is_named_moderator,
            moderators_of, DELEGATION_SCOPE_MODERATE, DELEGATION_SCOPE_REVIEW,
            DELEGATION_SCOPE_TAKEDOWN,
        };
        use crate::federation::edition2::fixture_switch as e2;
        use crate::federation::types::attestation_type;

        for (i, protocol) in ["majority", "unanimous", "quorum:3/4"].iter().enumerate() {
            let tag = format!("{tag}-{i}");
            let (room, keys) = make_group(
                d,
                &tag,
                protocol,
                &["f", "plain", "mod", "x"],
                1,
                None,
                None,
            )
            .await;
            let (founder, plain, modk, x) = (&keys[0], &keys[1], &keys[2], &keys[3]);

            // Who may sign is a different question, and it is unchanged.
            let record = d.lookup_community(&room).await.unwrap().unwrap();
            assert!(
                community_authority_set_for(d, &record)
                    .await
                    .unwrap()
                    .contains(plain),
                "I1522 {protocol}: a member is still a consensus signer"
            );
            check_no_moderator_federate_admission(d, &record)
                .await
                .unwrap_or_else(|e| panic!("I1522 {protocol}: the room federates: {e}"));

            for duty in [
                DELEGATION_SCOPE_MODERATE,
                DELEGATION_SCOPE_TAKEDOWN,
                DELEGATION_SCOPE_REVIEW,
            ] {
                assert_eq!(
                    moderators_of(d, &room, duty, crate::host::clock::now())
                        .await
                        .unwrap(),
                    vec![founder.clone()],
                    "I1522 {protocol}/{duty}: the founder alone, before any appointment"
                );
                assert_eq!(
                    appointed_moderators_of(d, &room, duty, crate::host::clock::now())
                        .await
                        .unwrap(),
                    vec![founder.clone()],
                );
                let holders = duty_holders_for_community(d, &room, duty).await.unwrap();
                assert_eq!(
                    holders.into_iter().collect::<Vec<_>>(),
                    vec![founder.clone()],
                    "I1522 {protocol}/{duty}: the door's holders"
                );
                assert!(
                    !is_named_moderator(d, plain, &room, duty, crate::host::clock::now())
                        .await
                        .unwrap()
                );
            }

            // The door itself, not only its helpers: a plain member's
            // community-scoped reconsideration is refused and not stored.
            let review = |signer: &str, id: &str| {
                signed_row(
                    signer,
                    signer,
                    attestation_type::SCORES,
                    serde_json::json!({
                        "id": id,
                        "dimension": "reconsideration:i1522:v1",
                        "score": 1.0,
                        "confidence": 0.9,
                        "community_id": room,
                    }),
                )
            };
            // v62 (E4): each row is its signer's edition-2 statement; its id
            // is the node's.
            let row = review(plain, &sd("plain", &tag));
            let id = e2::rid(&e2::row_of(&row, plain));
            // v62 (E4-fix6; CC 2.7.3): the duty is read from the room's
            // roster and delegations (other rows), a fold condition: the
            // review is HELD or refused by name, and never stored as a row.
            match e2::put_statement(d, &e2::statement_of(&row, plain)).await {
                Ok(StatementOutcome::Pending { .. }) => {}
                Ok(other) => panic!("I1522 {protocol}: a plain member's review landed: {other:?}"),
                Err(err) => assert_eq!(
                    err.kind(),
                    "federation_delegated_scope_unauthorized",
                    "I1522 {protocol}: {err}"
                ),
            }
            assert!(d.get_attestation(&id).await.unwrap().is_none());
            e2::try_put_row(d, &review(founder, &sd("founder", &tag)), founder)
                .await
                .unwrap_or_else(|e| panic!("I1522 {protocol}: the founder reviews: {e}"));

            // The founder appoints one duty; only that duty moves.
            let edge = |granter: &str, grantee: &str, id: &str| {
                signed_row(
                    granter,
                    grantee,
                    attestation_type::DELEGATES_TO,
                    // CW-fix1 fixture fix (4u) — the appointment NAMES the room.
                    serde_json::json!({
                        "id": id,
                        "scope": [DELEGATION_SCOPE_MODERATE],
                        "sub_delegation": false,
                        "community_id": room,
                    }),
                )
            };
            e2::try_put_row(d, &edge(founder, modk, &sd("appoint", &tag)), founder)
                .await
                .unwrap_or_else(|e| panic!("I1522 {protocol}: the appointment: {e}"));
            assert!(is_named_moderator(
                d,
                modk,
                &room,
                DELEGATION_SCOPE_MODERATE,
                crate::host::clock::now()
            )
            .await
            .unwrap());
            assert!(
                !is_named_moderator(
                    d,
                    modk,
                    &room,
                    DELEGATION_SCOPE_TAKEDOWN,
                    crate::host::clock::now()
                )
                .await
                .unwrap(),
                "I1522 {protocol}: moderate confers no takedown"
            );

            // A plain member's own edge roots nothing. The row may or may not
            // be stored; what it must not do is confer the duty.
            let _ =
                e2::try_put_row(d, &edge(plain, x, &format!("{tag}-self-appoint")), plain).await;
            assert!(
                !is_named_moderator(
                    d,
                    x,
                    &room,
                    DELEGATION_SCOPE_MODERATE,
                    crate::host::clock::now()
                )
                .await
                .unwrap(),
                "I1522 {protocol}: a member cannot appoint alone"
            );
        }
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
        let (room, alice, bob) = make_room(d, tag, "quorum:1/1").await;
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

#[cfg(all(test, any(feature = "sqlite", feature = "postgres")))]
mod run {
    fn suffix() -> String {
        uuid::Uuid::new_v4().simple().to_string()
    }

    #[test]
    fn i1524_fold() {
        super::bodies::i1524_an_admitted_moderator_removal_stands();
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
                async fn i1522() {
                    let Some(d) = $fresh.await else { return };
                    super::super::bodies::i1522_moderation_is_an_appointment(
                        &d as &dyn FederationDirectory,
                        &format!("i1522-{}", super::suffix()),
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
