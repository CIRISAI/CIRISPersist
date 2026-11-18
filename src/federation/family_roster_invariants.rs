//! v49.0.0 (CIRISPersist#910; `FSD/ROOM_ROSTER_AUTHORITY.md` §10) — **a
//! family's roster converges both ways, and a family change is judged by the
//! family's own protocol.**
//!
//! I177 — a family widening converges across two directories through the
//! signed since-read (B applies A's rows; B's fold = A's; B's record is the
//! original), and a removed family member is re-added and active again, then
//! removed again (#910.1). I179 — family standing is the family's protocol
//! (I171's arms on the family plane), and `verify_membership_quorum`'s prior
//! roster is the fold, not the raw record (#910.2).
//!
//! v62 (E3, E3b) — both on edition 2: every act is a voice over the held
//! roster head (T1); a voice short of the protocol is held `Pending` and the
//! completing voice lands it. I177's replication is B taking A's statements
//! through the filtered serve path (`edition2::serve::statements_served_to`,
//! the requester B's node key or a member) into its replicated statement
//! door (`edition2::ingest::apply_replicated_statement`).

/// The backend-agnostic witness bodies; `run` instantiates them per backend.
#[cfg(test)]
pub mod bodies {
    use crate::federation::cohort::Cohort;
    use crate::federation::edition2::ingest::{
        apply_replicated_statement, ReplicatedStatementOutcome, StatementOutcome,
    };
    use crate::federation::edition2::names::RowId;
    use crate::federation::tier_ingest::test_support as ts;
    use crate::federation::types::{
        consensus_protocol, identity_type, Family, FamilyMember, FamilyMembershipRevocation,
        FamilyMembershipWidening,
    };
    use crate::federation::{Error, FederationDirectory};

    fn at(s: &str) -> chrono::DateTime<chrono::Utc> {
        s.parse().expect("rfc3339")
    }

    fn widening(
        fam: &str,
        member: &str,
        effective_at: chrono::DateTime<chrono::Utc>,
        role: Option<&str>,
    ) -> FamilyMembershipWidening {
        FamilyMembershipWidening {
            family_key_id: fam.to_owned(),
            member_key_id: member.to_owned(),
            joined_at: effective_at,
            effective_at,
            role: role.map(str::to_owned),
            persist_row_hash: String::new(),
        }
    }

    fn revocation(
        fam: &str,
        member: &str,
        effective_at: chrono::DateTime<chrono::Utc>,
    ) -> FamilyMembershipRevocation {
        FamilyMembershipRevocation {
            family_key_id: fam.to_owned(),
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

    /// The signed record of a family of `keys`, the first `founders` of them
    /// tagged `founder`, under `protocol`, signed by the first member. The
    /// family id is no key (the doctrine: a family is keyless).
    fn family_record(
        fam: &str,
        keys: &[String],
        founders: usize,
        protocol: &str,
    ) -> crate::federation::SignedFamily {
        ts::sign_family(
            &keys[0],
            Family {
                prev_head_digest: String::new(),
                charter_digest: String::new(),
                family_key_id: fam.to_owned(),
                family_name: "household".into(),
                members: keys
                    .iter()
                    .enumerate()
                    .map(|(i, k)| FamilyMember {
                        key_id: k.clone(),
                        joined_at: at("2026-01-01T00:00:00Z"),
                        role: (i < founders).then(|| "founder".to_owned()),
                    })
                    .collect(),
                founded_at: at("2026-01-01T00:00:00Z"),
                consensus_protocol: protocol.to_owned(),
                consensus_protocol_entrenched: false,
                dissolved_at: None,
                persist_row_hash: String::new(),
            },
        )
    }

    /// A family `{tag}-{fam_name}` of `names` (registered user keys
    /// `{name}-{tag}` — the distinguishing part LEADS: the test signer seeds
    /// from a key id's first 32 bytes, and a uuid tag in front would give
    /// every member one keypair) on `d`. Returns the family id and the member
    /// key ids.
    pub async fn make_family(
        d: &dyn FederationDirectory,
        tag: &str,
        fam_name: &str,
        protocol: &str,
        names: &[&str],
        founders: usize,
    ) -> (String, Vec<String>) {
        let fam = format!("{tag}-{fam_name}");
        let keys: Vec<String> = names.iter().map(|n| format!("{n}-{tag}")).collect();
        for k in &keys {
            user(d, k).await;
        }
        d.put_family(family_record(&fam, &keys, founders, protocol))
            .await
            .unwrap_or_else(|e| panic!("{tag}: family {fam}: {e}"));
        (fam, keys)
    }

    async fn active(d: &dyn FederationDirectory, fam: &str) -> Vec<String> {
        let mut v: Vec<String> = d
            .active_family_members(fam)
            .await
            .unwrap()
            .into_iter()
            .map(|m| m.key_id)
            .collect();
        v.sort();
        v
    }

    async fn record_hash(d: &dyn FederationDirectory, fam: &str) -> String {
        d.lookup_family(fam)
            .await
            .unwrap()
            .expect("family")
            .persist_row_hash
    }

    /// Is `member` admitted to `fam` by every family admission reader?
    async fn admitted(d: &dyn FederationDirectory, member: &str, fam: &str) -> bool {
        let adm =
            crate::scope::admission::build_caller_admission_from_directory(d, &member.to_owned())
                .await
                .unwrap();
        let by_admission = adm.family_key_ids.contains(fam);
        let by_active = d
            .list_families_for_member_active(member)
            .await
            .unwrap()
            .iter()
            .any(|f| f.family_key_id == fam);
        let by_ids = d
            .active_family_key_ids_for(member)
            .await
            .unwrap()
            .iter()
            .any(|f| f == fam);
        let by_groups = d
            .groups_of(Cohort::Family, member)
            .await
            .unwrap()
            .iter()
            .any(|g| g.group_key_id == fam);
        assert!(
            by_admission == by_active && by_active == by_ids && by_ids == by_groups,
            "every family admission reader must agree for {member} in {fam}: \
             admission={by_admission} active={by_active} ids={by_ids} groups={by_groups}"
        );
        by_admission
    }

    /// v62 (E3b) — **what `from` serves `requester`** of the rows `rows`:
    /// every statement (each voice) of those rows on the FILTERED serve path
    /// (`edition2::serve::statements_served_to`; the store's raw since-read
    /// is never a serve surface), in `from`'s admission order. The pattern is
    /// E13's (device_readd / open_admission I1504).
    pub(crate) async fn served_rows(
        from: &dyn FederationDirectory,
        requester: &str,
        rows: &[RowId],
    ) -> Vec<(Vec<u8>, RowId)> {
        let mut out = Vec::new();
        let mut cursor = None;
        loop {
            let page = crate::federation::edition2::serve::statements_served_to(
                from,
                cursor.as_ref(),
                1000,
                Some(requester),
            )
            .await
            .expect("serve statements");
            for st in page.statements {
                if let Some(id) = RowId::of_statement(&st.bytes) {
                    if rows.contains(&id) {
                        out.push((st.bytes, id));
                    }
                }
            }
            match page.next {
                Some(next) => cursor = Some(next),
                None => break,
            }
        }
        assert!(
            !out.is_empty(),
            "{requester} is served the rows it asked for"
        );
        out
    }

    /// Each served statement through `to`'s replicated statement door
    /// (`edition2::ingest::apply_replicated_statement`), under the id it
    /// names.
    pub(crate) async fn deliver(
        to: &dyn FederationDirectory,
        statements: &[(Vec<u8>, RowId)],
    ) -> Vec<ReplicatedStatementOutcome> {
        let mut out = Vec::new();
        for (bytes, id) in statements {
            out.push(
                apply_replicated_statement(to, bytes, &id.0)
                    .await
                    .unwrap_or_else(|e| panic!("a replicated statement: {e}")),
            );
        }
        out
    }

    /// The requester a node names when it asks `from` for rows: its node key
    /// when the host set one, else `party` (a member's identity-ref; the
    /// serve path's audience test asks whether the requester is party).
    pub(crate) fn requester_of(to: &dyn FederationDirectory, party: &str) -> String {
        to.node_key_id().unwrap_or_else(|| party.to_owned())
    }

    /// The row id of a signed attestation's carried statement.
    fn row_of_signed(row: &crate::federation::Attestation) -> RowId {
        crate::federation::edition2::fixture_switch::carried_statement(row)
            .and_then(|st| RowId::of_statement(&st))
            .expect("the row carries its statement")
    }

    /// **I177 — a family widening converges, and a removed member comes
    /// back** (v62, E3b: edition 2). The family is founded by its voices on
    /// A; every act is a voice over the held head; B takes A's statements
    /// through the filtered serve path into its replicated statement door.
    pub async fn i177_a_family_widening_converges(
        a: &dyn FederationDirectory,
        b: &dyn FederationDirectory,
        tag: &str,
    ) {
        use crate::federation::edition2::fixture_switch as e2;
        let kid = |s: &str| e2::kid(s);
        let keys: Vec<String> = ["alice", "bob", "carol"]
            .iter()
            .map(|n| format!("{n}-{tag}"))
            .collect();
        let (alice, bob, carol) = (&keys[0], &keys[1], &keys[2]);
        for d in [a, b] {
            for k in &keys {
                e2::put_key(d, k, &["user"]).await;
            }
        }
        let fam = format!("fam-{tag}");
        let fid = kid(&fam);
        let mut rows: Vec<RowId> = Vec::new();

        // The founding record names alice (founder) and bob; carol is not on
        // it. A holds it through its voices; B takes them from A.
        let founding = e2::family_voices(
            &family_record(&fam, &keys[..2], 1, consensus_protocol::FOUNDER_ONLY),
            1,
            None,
            ms_ago(30),
        );
        let r = put_all(a, &founding).await;
        assert!(landed(&r), "{tag}: family {fam}: {r:?}");
        rows.push(e2::row_id_of(&founding[0]));
        let to_b = requester_of(b, &kid(bob));
        deliver(b, &served_rows(a, &to_b, &rows).await).await;
        let original_hash = record_hash(a, &fid).await;
        assert_eq!(
            record_hash(b, &fid).await,
            original_hash,
            "{tag}: one record"
        );
        assert!(
            !admitted(a, &kid(carol), &fid).await,
            "{tag} I177 control: before the widening carol is not admitted"
        );

        // (1) alice widens carol on A: carol's consent, then the founder's
        //     voice.
        rows.extend(consent_at(a, &fam, alice, carol, None, at_ago(25)).await);
        let widen1 = widening_voices(a, &[alice], widening(&fam, carol, at_ago(20), None)).await;
        let r = put_all(a, &widen1).await;
        assert!(landed(&r), "{tag} I177: the founder widens carol: {r:?}");
        rows.push(e2::row_id_of(&widen1[0]));
        // The same voice again changes nothing.
        let again = put_all(a, &widen1).await;
        assert!(
            again.is_ok(),
            "{tag} I177: the same voice again is the idempotent no-op: {again:?}"
        );
        // (I575, the unsigned exact retry, is deleted: an edition-2 voice is
        // signed or it is not a statement; there is no unsigned spec.)
        assert_eq!(
            record_hash(a, &fid).await,
            original_hash,
            "{tag} I177: the family record is never rewritten to grow"
        );
        assert_eq!(active(a, &fid).await, {
            let mut v = vec![kid(alice), kid(bob), kid(carol)];
            v.sort();
            v
        });
        assert!(
            admitted(a, &kid(carol), &fid).await,
            "{tag} I177: carol is in on A"
        );

        // (2) B applies A's served rows: admitted, and the folds agree.
        deliver(b, &served_rows(a, &to_b, &rows).await).await;
        assert_eq!(
            active(b, &fid).await,
            active(a, &fid).await,
            "{tag} I177: B's fold is A's"
        );
        assert_eq!(
            record_hash(b, &fid).await,
            original_hash,
            "{tag} I177: B's record is unchanged (no fork, no rewrite)"
        );
        assert!(
            admitted(b, &kid(carol), &fid).await,
            "{tag} I177: carol is in on B"
        );

        // (3) #910.1 — removed, re-added, removed again: every event is its
        // own row, and the fold follows the history on both nodes.
        let (t2, t3, t4) = (at_ago(15), at_ago(12), at_ago(10));
        let rm1 = revocation_voices(a, &[alice], revocation(&fam, carol, t2)).await;
        let r = put_all(a, &rm1).await;
        assert!(landed(&r), "{tag} I177: the founder removes carol: {r:?}");
        rows.push(e2::row_id_of(&rm1[0]));
        assert!(!admitted(a, &kid(carol), &fid).await, "{tag} I177: removed");
        rows.extend(consent_at(a, &fam, alice, carol, None, at_ago(14)).await);
        let widen2 = widening_voices(a, &[alice], widening(&fam, carol, t3, None)).await;
        let r = put_all(a, &widen2).await;
        assert!(
            landed(&r),
            "{tag} I177: a removed member can be re-added: {r:?}"
        );
        rows.push(e2::row_id_of(&widen2[0]));
        assert!(
            admitted(a, &kid(carol), &fid).await,
            "{tag} I177 (#910.1): the re-added member is active again"
        );
        let rm2 = revocation_voices(a, &[alice], revocation(&fam, carol, t4)).await;
        let r = put_all(a, &rm2).await;
        assert!(
            landed(&r),
            "{tag} I177: a re-added member can be removed again: {r:?}"
        );
        rows.push(e2::row_id_of(&rm2[0]));
        assert!(
            !admitted(a, &kid(carol), &fid).await,
            "{tag} I177: removed again"
        );
        assert_eq!(
            a.list_family_membership_revocations_for(&fid)
                .await
                .unwrap()
                .iter()
                .filter(|r| r.removed_identity_key_id == kid(carol))
                .count(),
            2,
            "{tag} I177 (#910.1): two removals of one member are two rows"
        );
        // The exact retry of a stored removal is still the #861 no-op.
        let r = put_all(a, &rm2).await;
        assert!(r.is_ok(), "{tag} I177: the #861 retry is Ok: {r:?}");
        assert_eq!(
            a.list_family_membership_revocations_for(&fid)
                .await
                .unwrap()
                .len(),
            2,
            "{tag} I177: the exact retry stored nothing"
        );

        // …and B converges on the whole history, at every instant.
        let history = served_rows(a, &to_b, &rows).await;
        deliver(b, &history).await;
        for (when, carol_in) in [
            (at_ago(18), true),
            (at_ago(13), false),
            (at_ago(11), true),
            (at_ago(5), false),
        ] {
            for (node, d) in [("A", a), ("B", b)] {
                let f = d.lookup_family(&fid).await.unwrap().expect("family");
                let roster = crate::federation::authorized_family_roster_at(d, &f, when)
                    .await
                    .unwrap();
                assert_eq!(
                    roster.iter().any(|m| m.key_id == kid(carol)),
                    carol_in,
                    "{tag} I177: on {node} at {when} carol is {}",
                    if carol_in { "in" } else { "out" }
                );
            }
        }
        assert_eq!(
            b.list_family_membership_revocations_for(&fid)
                .await
                .unwrap()
                .len(),
            2,
            "{tag} I177: B holds both removals"
        );
        assert_eq!(
            record_hash(b, &fid).await,
            original_hash,
            "{tag} I177: still one record"
        );
        // The same statements delivered again change nothing on B.
        for out in deliver(b, &history).await {
            assert!(
                matches!(out, ReplicatedStatementOutcome::Unchanged(_)),
                "{tag} I177: a re-delivered statement is Unchanged: {out:?}"
            );
        }
        assert_eq!(active(b, &fid).await, active(a, &fid).await, "{tag} I177");
    }

    // ── v62 (E3): the edition-2 twins I179 uses. A widening / removal is
    //    its voices over the held roster head (T1); a voice short of the
    //    protocol is held `Pending` and the completing voice lands it
    //    (`Row`). CC 2.7: refusals of these fold conditions are not pinned
    //    by token; a non-landing is asserted as "not `Row`" plus the roster.

    fn ms_ago(mins: i64) -> u64 {
        crate::federation::edition2::fixture_switch::ms(
            chrono::Utc::now() - chrono::Duration::minutes(mins),
        )
    }

    fn at_ago(mins: i64) -> chrono::DateTime<chrono::Utc> {
        crate::federation::admission::truncate_to_substrate_resolution(
            chrono::Utc::now() - chrono::Duration::minutes(mins),
        )
    }

    fn landed(r: &Result<StatementOutcome, Error>) -> bool {
        matches!(r, Ok(StatementOutcome::Row { .. }))
    }

    /// A family founded through its voices (asserted 30 minutes ago, so the
    /// later voices follow it).
    async fn make_family_e2(
        d: &dyn FederationDirectory,
        tag: &str,
        fam_name: &str,
        protocol: &str,
        names: &[&str],
        founders: usize,
    ) -> (String, Vec<String>) {
        use crate::federation::edition2::fixture_switch as e2;
        let fam = format!("{fam_name}-{tag}");
        let keys: Vec<String> = names.iter().map(|n| format!("{n}-{tag}")).collect();
        for k in &keys {
            e2::put_key(d, k, &["user"]).await;
        }
        let r = e2::put_voices(
            d,
            &e2::family_voices(
                &family_record(&fam, &keys, founders, protocol),
                1,
                None,
                ms_ago(30),
            ),
        )
        .await;
        assert!(landed(&r), "{tag}: family {fam}: {r:?}");
        (fam, keys)
    }

    /// `member`'s consent to join `fam` on `proposer`'s proposal (#955: the
    /// growth gate reads both as edition-2 rows).
    async fn consent_e2(
        d: &dyn FederationDirectory,
        fam: &str,
        proposer: &str,
        member: &str,
        role: Option<&str>,
    ) {
        consent_at(d, fam, proposer, member, role, at_ago(25)).await;
    }

    /// [`consent_e2`] at `when`; returns the two rows' ids (the proposal,
    /// then the acceptance), for a replay.
    async fn consent_at(
        d: &dyn FederationDirectory,
        fam: &str,
        proposer: &str,
        member: &str,
        role: Option<&str>,
        when: chrono::DateTime<chrono::Utc>,
    ) -> Vec<RowId> {
        use crate::federation::edition2::fixture_switch as e2;
        use crate::federation::membership_acceptance::test_support::{
            acceptance_row, proposal_row,
        };
        let p = proposal_row(
            proposer,
            crate::federation::types::cohort_scope::FAMILY,
            &e2::kid(fam),
            member,
            role,
            when,
        );
        e2::put_signed(d, &p).await.expect("the proposal");
        let acc = acceptance_row(member, &p, when);
        e2::put_signed(d, &acc).await.expect("the acceptance");
        vec![row_of_signed(&p), row_of_signed(&acc)]
    }

    /// The voices of a widening signed by `signers` (one each), over the
    /// held head.
    async fn widening_voices(
        d: &dyn FederationDirectory,
        signers: &[&str],
        w: FamilyMembershipWidening,
    ) -> Vec<Vec<u8>> {
        use crate::federation::edition2::fixture_switch as e2;
        let (head, _) = e2::held_head(d, &e2::kid(&w.family_key_id))
            .await
            .expect("the roster head is held");
        let mut s = ts::sign_family_membership_widening(signers[0], w);
        for c in &signers[1..] {
            ts::cosign_family_membership_widening(&mut s, c);
        }
        e2::family_widening_voices(&s, Some(&head))
    }

    /// The voices of a removal signed by `signers` (one each), over the
    /// held head.
    async fn revocation_voices(
        d: &dyn FederationDirectory,
        signers: &[&str],
        r: FamilyMembershipRevocation,
    ) -> Vec<Vec<u8>> {
        use crate::federation::edition2::fixture_switch as e2;
        let (head, _) = e2::held_head(d, &e2::kid(&r.family_key_id))
            .await
            .expect("the roster head is held");
        let mut s = ts::sign_family_membership_revocation(signers[0], r);
        for c in &signers[1..] {
            ts::cosign_family_membership_revocation(&mut s, c);
        }
        e2::family_revocation_voices(&s, Some(&head))
    }

    async fn put_all(
        d: &dyn FederationDirectory,
        voices: &[Vec<u8>],
    ) -> Result<StatementOutcome, Error> {
        crate::federation::edition2::fixture_switch::put_voices(d, voices).await
    }

    async fn active_e2(d: &dyn FederationDirectory, fam: &str) -> Vec<String> {
        active(d, &crate::federation::edition2::fixture_switch::kid(fam)).await
    }

    /// **I179 — a family's standing is its protocol** (v62, edition 2). Each
    /// protocol's short voice set is held `Pending` and the completing voice
    /// lands it; a stranger's or a removed member's voice never counts; the
    /// last founder cannot leave until another founder is seated.
    pub async fn i179_family_standing_is_the_protocol(d: &dyn FederationDirectory, tag: &str) {
        use crate::federation::edition2::fixture_switch as e2;
        let kid = |s: &str| e2::kid(s);
        let newbie = format!("newbie-{tag}");
        let stranger = format!("stranger-{tag}");
        for x in [&newbie, &stranger] {
            e2::put_key(d, x, &["user"]).await;
        }

        // founder_only: a plain member's voice and a stranger's do not
        // widen; the founder's does.
        let (fo, k) = make_family_e2(
            d,
            tag,
            "fo",
            consensus_protocol::FOUNDER_ONLY,
            &["fo-alice", "fo-bob"],
            1,
        )
        .await;
        consent_e2(d, &fo, &k[0], &newbie, None).await;
        let r = put_all(
            d,
            &widening_voices(d, &[&k[1]], widening(&fo, &newbie, at_ago(20), None)).await,
        )
        .await;
        assert!(
            !landed(&r),
            "{tag} I179: founder_only: a plain member cannot widen: {r:?}"
        );
        let r = put_all(
            d,
            &widening_voices(d, &[&stranger], widening(&fo, &newbie, at_ago(20), None)).await,
        )
        .await;
        assert!(!landed(&r), "{tag} I179: a stranger cannot widen: {r:?}");
        assert!(
            !active_e2(d, &fo).await.contains(&kid(&newbie)),
            "{tag} I179: nothing landed"
        );
        let r = put_all(
            d,
            &widening_voices(d, &[&k[0]], widening(&fo, &newbie, at_ago(20), None)).await,
        )
        .await;
        assert!(landed(&r), "{tag} I179: the founder widens: {r:?}");
        assert!(
            active_e2(d, &fo).await.contains(&kid(&newbie)),
            "{tag} I179"
        );

        // The last founder may not leave ...
        let r = put_all(
            d,
            &revocation_voices(d, &[&k[0]], revocation(&fo, &k[0], at_ago(19))).await,
        )
        .await;
        assert!(
            !landed(&r),
            "{tag} I179: the last founder may not leave: {r:?}"
        );
        assert!(active_e2(d, &fo).await.contains(&kid(&k[0])));
        // ... until bob is promoted to founder (a role change is a widening
        // of a seated member, #910.4) ...
        consent_e2(d, &fo, &k[0], &k[1], Some("founder")).await;
        let r = put_all(
            d,
            &widening_voices(
                d,
                &[&k[0]],
                widening(&fo, &k[1], at_ago(18), Some("founder")),
            )
            .await,
        )
        .await;
        assert!(
            landed(&r),
            "{tag} I179 (#910.4): the founder promotes bob: {r:?}"
        );
        assert_eq!(
            d.lookup_family(&kid(&fo))
                .await
                .unwrap()
                .unwrap()
                .members
                .len(),
            2,
            "{tag} I179: a role change never rewrites the record"
        );
        // ... and then she may.
        let r = put_all(
            d,
            &revocation_voices(d, &[&k[0]], revocation(&fo, &k[0], at_ago(17))).await,
        )
        .await;
        assert!(
            landed(&r),
            "{tag} I179: with bob a founder, alice may leave: {r:?}"
        );
        assert!(!active_e2(d, &fo).await.contains(&kid(&k[0])), "{tag} I179");
        let r = put_all(
            d,
            &revocation_voices(d, &[&stranger], revocation(&fo, &k[1], at_ago(16))).await,
        )
        .await;
        assert!(!landed(&r), "{tag} I179: a stranger cannot remove: {r:?}");
        assert!(active_e2(d, &fo).await.contains(&kid(&k[1])), "{tag} I179");

        // majority of three: one voice is held Pending; the second lands it.
        let (mj, m) = make_family_e2(
            d,
            tag,
            "mj",
            consensus_protocol::MAJORITY,
            &["mj-a", "mj-b", "mj-c"],
            0,
        )
        .await;
        consent_e2(d, &mj, &m[0], &newbie, None).await;
        let voices =
            widening_voices(d, &[&m[0], &m[1]], widening(&mj, &newbie, at_ago(20), None)).await;
        assert_eq!(voices.len(), 2);
        let first = put_all(d, &voices[..1]).await;
        assert!(
            matches!(first, Ok(StatementOutcome::Pending { .. })),
            "{tag} I179: majority: one of three is held Pending: {first:?}"
        );
        assert!(!active_e2(d, &mj).await.contains(&kid(&newbie)));
        let second = put_all(d, &voices[1..]).await;
        assert!(
            landed(&second),
            "{tag} I179: two of three is a majority: {second:?}"
        );
        assert!(
            active_e2(d, &mj).await.contains(&kid(&newbie)),
            "{tag} I179"
        );
        let r = put_all(
            d,
            &revocation_voices(d, &[&m[2]], revocation(&mj, &m[2], at_ago(15))).await,
        )
        .await;
        assert!(
            landed(&r),
            "{tag} I179: a member leaves on their own voice: {r:?}"
        );
        assert!(!active_e2(d, &mj).await.contains(&kid(&m[2])), "{tag} I179");

        // unanimous of three: two voices Pending; the third lands it.
        let (un, u) = make_family_e2(
            d,
            tag,
            "un",
            consensus_protocol::UNANIMOUS,
            &["un-a", "un-b", "un-c"],
            0,
        )
        .await;
        consent_e2(d, &un, &u[0], &newbie, None).await;
        let voices = widening_voices(
            d,
            &[&u[0], &u[1], &u[2]],
            widening(&un, &newbie, at_ago(20), None),
        )
        .await;
        let two = put_all(d, &voices[..2]).await;
        assert!(
            matches!(two, Ok(StatementOutcome::Pending { .. })),
            "{tag} I179: unanimous: all but one is held Pending: {two:?}"
        );
        let all = put_all(d, &voices[2..]).await;
        assert!(landed(&all), "{tag} I179: every member voiced: {all:?}");
        assert!(
            active_e2(d, &un).await.contains(&kid(&newbie)),
            "{tag} I179"
        );

        // (#910.2) a removed member no longer counts: after q3 leaves, q1 +
        // q3 is one countable voice of two (Pending); q2's voice lands it.
        let (qf, q) = make_family_e2(
            d,
            tag,
            "qf",
            consensus_protocol::MAJORITY,
            &["q1", "q2", "q3"],
            0,
        )
        .await;
        let r = put_all(
            d,
            &revocation_voices(d, &[&q[2]], revocation(&qf, &q[2], at_ago(22))).await,
        )
        .await;
        assert!(landed(&r), "{tag} I179: q3 leaves: {r:?}");
        consent_e2(d, &qf, &q[0], &newbie, None).await;
        let voices = widening_voices(
            d,
            &[&q[0], &q[2], &q[1]],
            widening(&qf, &newbie, at_ago(20), None),
        )
        .await;
        let short = put_all(d, &voices[..2]).await;
        assert!(
            matches!(short, Ok(StatementOutcome::Pending { .. })),
            "{tag} I179 (#910.2): a removed member's voice does not count: {short:?}"
        );
        assert!(!active_e2(d, &qf).await.contains(&kid(&newbie)));
        let done = put_all(d, &voices[2..]).await;
        assert!(landed(&done), "{tag} I179: two of the fold's two: {done:?}");
        assert!(
            active_e2(d, &qf).await.contains(&kid(&newbie)),
            "{tag} I179"
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
                #[tokio::test]
                async fn i177() {
                    let (Some(a), Some(b)) = ($fresh.await, $fresh.await) else {
                        return;
                    };
                    super::super::bodies::i177_a_family_widening_converges(
                        &a as &dyn FederationDirectory,
                        &b as &dyn FederationDirectory,
                        &format!("i177-{}", super::suffix()),
                    )
                    .await
                }
                #[tokio::test]
                async fn i179() {
                    let Some(d) = $fresh.await else { return };
                    super::super::bodies::i179_family_standing_is_the_protocol(
                        &d as &dyn FederationDirectory,
                        &format!("i179-{}", super::suffix()),
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
}
