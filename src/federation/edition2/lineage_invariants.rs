//! v62.0.0 (LINEAGE-L1; CC 2.7.8, CC 3.3.4) — **the lineage store and the
//! group door's write**, on sqlite and postgres.
//!
//! I6902 — the store: a node and its predecessors round-trip; a second
//! write of one node is no change; a group's nodes are its own; the heads
//! are the nodes no other node extends (one chain, two tips, a join).
//! I6903 — through the real door: a family's founding version is a Roster
//! node extending nothing; a widening HELD short of its count is no node; the
//! landed widening is a Widening node of its member, extending the version
//! it names; the heads are then the widening alone; and the trait default
//! (`lineage::derived_nodes`, what the capsule proxy answers) gives the same
//! nodes as the table.
//!
//! I6906 (LINEAGE-L2) — the head moves on a counted change: after a
//! widening the production resolver (`head_rule::roster_heads`) and the
//! fixtures' `held_head` answer the widening; a removal naming the WIDENING
//! as its head lands (the door takes any head of the group's lineage) and
//! is then the head, standing on the founding version as its base; a later
//! `group:roster` version naming the removal stands on that base (its typed
//! `prev_head_digest` is the record the typed table holds) and is version 2
//! (a version 3 there does not follow).
//!
//! I6908 (LINEAGE-L1b) — the statement purge keeps a lineage node's
//! statement: with an attestation-plane tombstone naming the founding
//! version, a landed widening and a widening held short, the purge function
//! deletes only the held-short row's statement; and each node records the
//! protocol in force at it (a change carries its base's).
//!
//! I6914 (LINEAGE-L3d) — the ends store and `resigned_at`: a resignation's
//! end round-trips with every head it names; "who resigned since" the
//! restating version behind a head is the members whose end acts from a
//! head in that head's lineage past, and no one whose end acts from a head
//! after it. Store-level (stored nodes and ends): a resignation is refused
//! at the door on this base until RESIGN-2 lands its plane.
//! I6915 (LINEAGE-L3d) — the statement purge keeps an END's statement as
//! it keeps a node's (both backends; the end is planted on a held row, a
//! state no door produces on this base).
//!
//! I6916 (LINEAGE-L4) — a reader that counts an act over the head it names
//! (`admission::admission_head_version`) reads the members SEATED there: at
//! a widening the new member is listed, at the founding version it is not;
//! the version's protocol stays the restating version's.
//!
//! I6911 (LINEAGE-L3; CC 3.3.4, CC 2.7.8) — a counted change is counted
//! over the members at the head it names, never at its instant: under
//! `unanimous`, a widening dated BEFORE the change it names is still short
//! until the member that change seated voices it; two widenings naming one
//! head are two tips; a widening naming both is the join, counted over the
//! members common to the tips (a member either tip seated is no voice it
//! needs), and is then the one head, seating everyone either tip seated.

pub mod bodies {
    use crate::federation::edition2::fixture_switch as e2;
    use crate::federation::edition2::ingest::StatementOutcome;
    use crate::federation::edition2::lineage::{self, HeadOf, LineageNode};
    use crate::federation::edition2::names::RowId;
    use crate::federation::group_plane::GroupKind;
    use crate::federation::tier_ingest::test_support as ts;
    use crate::federation::types::{
        consensus_protocol, Family, FamilyMember, FamilyMembershipWidening,
    };
    use crate::federation::{Error, FederationDirectory};
    use sha2::Digest as _;

    fn id(tag: &str, i: u8) -> RowId {
        let mut h = sha2::Sha256::new();
        h.update(tag.as_bytes());
        h.update([i]);
        RowId(h.finalize().into())
    }

    fn node(
        tag: &str,
        group: &str,
        i: u8,
        head_of: HeadOf,
        subject: Option<&str>,
        extends: &[u8],
    ) -> LineageNode {
        let mut ext: Vec<RowId> = extends.iter().map(|e| id(tag, *e)).collect();
        ext.sort();
        LineageNode {
            row_id: id(tag, i),
            group_kind: GroupKind::Community,
            group: group.to_owned(),
            head_of,
            subject: subject.map(str::to_owned),
            extends: ext,
            // A roster version stands on itself; a change here on node 1.
            base: Some(if head_of == HeadOf::Roster {
                id(tag, i)
            } else {
                id(tag, 1)
            }),
            consensus_protocol: Some(consensus_protocol::MAJORITY.to_owned()),
            policy_digest: None,
            entrenched: false,
        }
    }

    fn sorted(mut v: Vec<LineageNode>) -> Vec<LineageNode> {
        v.sort_by_key(|n| n.row_id);
        v
    }

    fn ids(mut v: Vec<RowId>) -> Vec<RowId> {
        v.sort();
        v
    }

    /// **I6902 — the lineage store.**
    pub async fn i6902_the_lineage_store(d: &dyn FederationDirectory, tag: &str) {
        let g = format!("lineage-g-{tag}");
        let other = format!("lineage-other-{tag}");
        let v1 = node(tag, &g, 1, HeadOf::Roster, None, &[]);
        let w = node(tag, &g, 2, HeadOf::Widening, Some("m"), &[1]);
        let r = node(tag, &g, 3, HeadOf::Removal, Some("n"), &[1]);
        let mut x = node(tag, &other, 9, HeadOf::Roster, None, &[]);
        // LINEAGE-L3e — the entrenched flag round-trips.
        x.entrenched = true;
        for n in [&v1, &w, &r, &x] {
            d.put_group_lineage_node(n).await.expect("I6902: the write");
        }
        // A second write of one node is no change.
        d.put_group_lineage_node(&w)
            .await
            .expect("I6902: idempotent");
        let held = d.group_lineage_nodes(&g).await.expect("I6902: the read");
        assert_eq!(
            sorted(held),
            sorted(vec![v1.clone(), w.clone(), r.clone()]),
            "{tag} I6902: the group's nodes, each once, with their predecessors"
        );
        assert_eq!(
            d.group_lineage_nodes(&other).await.unwrap(),
            vec![x],
            "{tag} I6902: another group's nodes are its own"
        );
        assert_eq!(
            lineage::heads(d, &g).await.unwrap(),
            ids(vec![w.row_id, r.row_id]),
            "{tag} I6902: two rows extending one head are two tips"
        );
        let j = node(tag, &g, 4, HeadOf::Widening, Some("o"), &[2, 3]);
        d.put_group_lineage_node(&j).await.unwrap();
        assert_eq!(
            lineage::heads(d, &g).await.unwrap(),
            vec![j.row_id],
            "{tag} I6902: a row naming both tips makes one head"
        );
        let held = d.group_lineage_nodes(&g).await.unwrap();
        let joined = held.iter().find(|n| n.row_id == j.row_id).expect("held");
        assert_eq!(
            joined.extends,
            ids(vec![w.row_id, r.row_id]),
            "{tag} I6902: a node keeps EVERY head it extends"
        );
        assert!(
            d.group_lineage_nodes(&format!("lineage-none-{tag}"))
                .await
                .unwrap()
                .is_empty(),
            "{tag} I6902: a group with no node"
        );
    }

    fn ms_ago(mins: i64) -> u64 {
        e2::ms(chrono::Utc::now() - chrono::Duration::minutes(mins))
    }

    fn at_ago(mins: i64) -> chrono::DateTime<chrono::Utc> {
        crate::federation::admission::truncate_to_substrate_resolution(
            chrono::Utc::now() - chrono::Duration::minutes(mins),
        )
    }

    fn landed(r: &Result<StatementOutcome, Error>) -> bool {
        matches!(r, Ok(StatementOutcome::Row { .. }))
    }

    /// **I6903 — the group door writes the lineage.**
    pub async fn i6903_the_door_writes_the_lineage(d: &dyn FederationDirectory, tag: &str) {
        use crate::federation::membership_acceptance::test_support::{
            acceptance_row, proposal_row,
        };
        let fam = format!("lin-{tag}");
        let keys: Vec<String> = ["alice", "bob"]
            .iter()
            .map(|n| format!("{n}-{tag}"))
            .collect();
        let newbie = format!("newbie-{tag}");
        for k in keys.iter().chain(std::iter::once(&newbie)) {
            e2::put_key(d, k, &["user"]).await;
        }
        let at = |s: &str| -> chrono::DateTime<chrono::Utc> { s.parse().expect("rfc3339") };
        let record = ts::sign_family(
            &keys[0],
            Family {
                prev_head_digest: String::new(),
                charter_digest: String::new(),
                family_key_id: fam.clone(),
                family_name: "household".into(),
                members: keys
                    .iter()
                    .enumerate()
                    .map(|(i, k)| FamilyMember {
                        key_id: k.clone(),
                        joined_at: at("2026-01-01T00:00:00Z"),
                        role: (i == 0).then(|| "founder".to_owned()),
                    })
                    .collect(),
                founded_at: at("2026-01-01T00:00:00Z"),
                consensus_protocol: consensus_protocol::FOUNDER_ONLY.to_owned(),
                consensus_protocol_entrenched: false,
                dissolved_at: None,
                persist_row_hash: String::new(),
            },
        );
        let founding = e2::family_voices(&record, 1, None, ms_ago(30));
        let v1 = e2::row_id_of(&founding[0]);
        let r = e2::put_voices(d, &founding).await;
        assert!(landed(&r), "{tag} I6903: the founding: {r:?}");
        let group = e2::kid(&fam);
        assert_eq!(
            d.group_lineage_nodes(&group).await.unwrap(),
            vec![LineageNode {
                row_id: v1,
                group_kind: GroupKind::Family,
                group: group.clone(),
                head_of: HeadOf::Roster,
                subject: None,
                extends: Vec::new(),
                base: Some(v1),
                consensus_protocol: Some(consensus_protocol::FOUNDER_ONLY.to_owned()),
                policy_digest: None,
                entrenched: false,
            }],
            "{tag} I6903: the founding version is the first node"
        );

        // The member's consent (#955: the growth gate reads both rows).
        let p = proposal_row(
            &keys[0],
            crate::federation::types::cohort_scope::FAMILY,
            &group,
            &newbie,
            None,
            at_ago(25),
        );
        e2::put_signed(d, &p).await.expect("the proposal");
        let acc = acceptance_row(&newbie, &p, at_ago(25));
        e2::put_signed(d, &acc).await.expect("the acceptance");

        let w = FamilyMembershipWidening {
            family_key_id: fam.clone(),
            member_key_id: newbie.clone(),
            joined_at: at_ago(20),
            effective_at: at_ago(20),
            role: None,
            persist_row_hash: String::new(),
        };
        // founder_only: a plain member's voice is short of the count.
        let short = e2::family_widening_voices(
            &ts::sign_family_membership_widening(&keys[1], w.clone()),
            Some(&v1),
        );
        let r = e2::put_voices(d, &short).await;
        assert!(!landed(&r), "{tag} I6903 premise: held short: {r:?}");
        assert_eq!(
            d.group_lineage_nodes(&group).await.unwrap().len(),
            1,
            "{tag} I6903: a row held short of its count is no node"
        );

        let voices = e2::family_widening_voices(
            &ts::sign_family_membership_widening(&keys[0], w),
            Some(&v1),
        );
        let wid = e2::row_id_of(&voices[0]);
        let r = e2::put_voices(d, &voices).await;
        assert!(landed(&r), "{tag} I6903: the founder widens: {r:?}");
        let nodes = sorted(d.group_lineage_nodes(&group).await.unwrap());
        let widening = nodes
            .iter()
            .find(|n| n.row_id == wid)
            .unwrap_or_else(|| panic!("{tag} I6903: the landed widening is a node: {nodes:?}"));
        assert_eq!(widening.head_of, HeadOf::Widening, "{tag} I6903");
        assert_eq!(widening.group_kind, GroupKind::Family, "{tag} I6903");
        assert_eq!(
            widening.subject.as_deref(),
            Some(e2::kid(&newbie).as_str()),
            "{tag} I6903: the widening's subject is its member"
        );
        assert_eq!(
            widening.extends,
            vec![v1],
            "{tag} I6903: it extends the version it names"
        );
        assert_eq!(
            lineage::heads(d, &group).await.unwrap(),
            vec![wid],
            "{tag} I6903: the landed widening is the head"
        );
        // The trait default (the capsule proxy's answer) agrees with the table.
        assert_eq!(
            sorted(lineage::derived_nodes(d, &group).await.unwrap()),
            nodes,
            "{tag} I6903: derived_nodes = the table"
        );
    }

    /// **I6906 — the head moves on a counted change** (LINEAGE-L2).
    pub async fn i6906_the_head_moves_on_a_counted_change(d: &dyn FederationDirectory, tag: &str) {
        use crate::federation::edition2::group::{prev_head_digest, roster_view_of_statement};
        use crate::federation::edition2::head_rule::roster_heads;
        use crate::federation::membership_acceptance::test_support::{
            acceptance_row, proposal_row,
        };
        use crate::federation::types::FamilyMembershipRevocation;
        let fam = format!("mv-{tag}");
        let keys: Vec<String> = ["alice", "bob"]
            .iter()
            .map(|n| format!("{n}-{tag}"))
            .collect();
        let newbie = format!("newbie-{tag}");
        for k in keys.iter().chain(std::iter::once(&newbie)) {
            e2::put_key(d, k, &["user"]).await;
        }
        let at = |s: &str| -> chrono::DateTime<chrono::Utc> { s.parse().expect("rfc3339") };
        let family = |members: &[&String]| Family {
            prev_head_digest: String::new(),
            charter_digest: String::new(),
            family_key_id: fam.clone(),
            family_name: "household".into(),
            members: members
                .iter()
                .enumerate()
                .map(|(i, k)| FamilyMember {
                    key_id: (*k).clone(),
                    joined_at: at("2026-01-01T00:00:00Z"),
                    role: (i == 0).then(|| "founder".to_owned()),
                })
                .collect(),
            founded_at: at("2026-01-01T00:00:00Z"),
            consensus_protocol: consensus_protocol::FOUNDER_ONLY.to_owned(),
            consensus_protocol_entrenched: false,
            dissolved_at: None,
            persist_row_hash: String::new(),
        };
        let founding = e2::family_voices(
            &ts::sign_family(&keys[0], family(&[&keys[0], &keys[1]])),
            1,
            None,
            ms_ago(30),
        );
        let v1 = e2::row_id_of(&founding[0]);
        let r = e2::put_voices(d, &founding).await;
        assert!(landed(&r), "{tag} I6906: the founding: {r:?}");
        let group = e2::kid(&fam);
        assert_eq!(
            roster_heads(d, &group).await.unwrap(),
            vec![v1],
            "{tag} I6906: the founding version is the head"
        );

        // A counted widening of newbie, over the founding version.
        let p = proposal_row(
            &keys[0],
            crate::federation::types::cohort_scope::FAMILY,
            &group,
            &newbie,
            None,
            at_ago(25),
        );
        e2::put_signed(d, &p).await.expect("the proposal");
        let acc = acceptance_row(&newbie, &p, at_ago(25));
        e2::put_signed(d, &acc).await.expect("the acceptance");
        let widening = e2::family_widening_voices(
            &ts::sign_family_membership_widening(
                &keys[0],
                FamilyMembershipWidening {
                    family_key_id: fam.clone(),
                    member_key_id: newbie.clone(),
                    joined_at: at_ago(20),
                    effective_at: at_ago(20),
                    role: None,
                    persist_row_hash: String::new(),
                },
            ),
            Some(&v1),
        );
        let w = e2::row_id_of(&widening[0]);
        let r = e2::put_voices(d, &widening).await;
        assert!(landed(&r), "{tag} I6906: the widening: {r:?}");
        assert_eq!(
            roster_heads(d, &group).await.unwrap(),
            vec![w],
            "{tag} I6906: the widening is the head (CC 3.3.4)"
        );
        assert_eq!(
            e2::held_head(d, &group).await,
            Some((w, 1)),
            "{tag} I6906: the fixtures' head is the widening, on version 1"
        );

        // A counted removal of bob naming the WIDENING as its head.
        let removal = e2::family_revocation_voices(
            &ts::sign_family_membership_revocation(
                &keys[0],
                FamilyMembershipRevocation {
                    family_key_id: fam.clone(),
                    removed_identity_key_id: keys[1].clone(),
                    removed_at: at_ago(15),
                    effective_at: at_ago(15),
                    reason: None,
                    witness_set: vec![],
                    persist_row_hash: String::new(),
                },
            ),
            Some(&w),
        );
        let rm = e2::row_id_of(&removal[0]);
        let r = e2::put_voices(d, &removal).await;
        assert!(
            landed(&r),
            "{tag} I6906: a removal naming the widening as its head lands: {r:?}"
        );
        assert_eq!(
            roster_heads(d, &group).await.unwrap(),
            vec![rm],
            "{tag} I6906: the removal is the head"
        );
        let node = d
            .group_lineage_node(&rm)
            .await
            .unwrap()
            .expect("I6906: the removal is a node");
        assert_eq!(node.head_of, HeadOf::Removal, "{tag} I6906");
        assert_eq!(
            node.extends,
            vec![w],
            "{tag} I6906: it extends the widening"
        );
        assert_eq!(
            node.base,
            Some(v1),
            "{tag} I6906: it stands on the founding version"
        );
        assert_eq!(
            lineage::nearest_versions(d, &[rm]).await.unwrap(),
            vec![v1],
            "{tag} I6906: one step to the restating version"
        );

        // A later version naming the removal: version 2, on the record held.
        let v2_record = ts::sign_family(&keys[0], family(&[&keys[0], &newbie]));
        let v2 = e2::family_voices(&v2_record, 2, Some(&rm), ms_ago(10));
        let view = roster_view_of_statement(&v2[0]).expect("I6906: v2 reads");
        let held = d
            .lookup_family(&group)
            .await
            .unwrap()
            .expect("I6906: the family is held")
            .persist_row_hash;
        assert_eq!(
            prev_head_digest(d, &view, &e2::row_id_of(&v2[0]))
                .await
                .expect("I6906: version 2 follows"),
            held,
            "{tag} I6906: a version naming the removal stands on the record held"
        );
        let v3 = e2::family_voices(&v2_record, 3, Some(&rm), ms_ago(10));
        let view = roster_view_of_statement(&v3[0]).expect("I6906: v3 reads");
        assert!(
            prev_head_digest(d, &view, &e2::row_id_of(&v3[0]))
                .await
                .is_err(),
            "{tag} I6906: a version 3 over version 1's lineage does not follow"
        );
    }

    /// **I6908 — a purge keeps the lineage** (LINEAGE-L1b).
    ///
    /// It stands at the level the guard sits: the statement purge
    /// (`purge_delete_tombstoned_statements`), on both backends. The state it
    /// reads is one NO DOOR produces today: an attestation-plane tombstone
    /// naming a group row (the steward purge selects attestation rows, and a
    /// group row has none), stored here directly through
    /// `store_purge_execution`. The mutation it kills: deleting the guard's
    /// `AND NOT EXISTS (SELECT 1 FROM ceg_group_lineage WHERE row_id = ...)`
    /// on either backend makes the two lineage statements go (the `0` and the
    /// "still held" assertions turn red), while the held-short row's goes in
    /// both (the contrast that keeps the test from passing on a purge that
    /// deletes nothing).
    pub async fn i6908_a_purge_keeps_the_lineage<D>(d: &D, tag: &str)
    where
        D: crate::federation::directory_admit::DirectoryStore + Sync,
    {
        use crate::federation::membership_acceptance::test_support::{
            acceptance_row, proposal_row,
        };
        use crate::federation::steward_purge::{PurgeExecution, PurgePlane, PurgeTombstone};
        let fam = format!("pg-{tag}");
        let keys: Vec<String> = ["alice", "bob"]
            .iter()
            .map(|n| format!("{n}-{tag}"))
            .collect();
        let (newbie, other) = (format!("newbie-{tag}"), format!("other-{tag}"));
        for k in keys.iter().chain([&newbie, &other]) {
            e2::put_key(d, k, &["user"]).await;
        }
        let at = |s: &str| -> chrono::DateTime<chrono::Utc> { s.parse().expect("rfc3339") };
        let record = ts::sign_family(
            &keys[0],
            Family {
                prev_head_digest: String::new(),
                charter_digest: String::new(),
                family_key_id: fam.clone(),
                family_name: "household".into(),
                members: keys
                    .iter()
                    .enumerate()
                    .map(|(i, k)| FamilyMember {
                        key_id: k.clone(),
                        joined_at: at("2026-01-01T00:00:00Z"),
                        role: (i == 0).then(|| "founder".to_owned()),
                    })
                    .collect(),
                founded_at: at("2026-01-01T00:00:00Z"),
                consensus_protocol: consensus_protocol::FOUNDER_ONLY.to_owned(),
                consensus_protocol_entrenched: false,
                dissolved_at: None,
                persist_row_hash: String::new(),
            },
        );
        let founding = e2::family_voices(&record, 1, None, ms_ago(30));
        let v1 = e2::row_id_of(&founding[0]);
        assert!(landed(&e2::put_voices(d, &founding).await), "{tag} I6908");
        let group = e2::kid(&fam);
        for m in [&newbie, &other] {
            let p = proposal_row(
                &keys[0],
                crate::federation::types::cohort_scope::FAMILY,
                &group,
                m,
                None,
                at_ago(25),
            );
            e2::put_signed(d, &p).await.expect("the proposal");
            let acc = acceptance_row(m, &p, at_ago(25));
            e2::put_signed(d, &acc).await.expect("the acceptance");
        }
        let widen = |m: &str, signer: &str| {
            e2::family_widening_voices(
                &ts::sign_family_membership_widening(
                    signer,
                    FamilyMembershipWidening {
                        family_key_id: fam.clone(),
                        member_key_id: m.to_owned(),
                        joined_at: at_ago(20),
                        effective_at: at_ago(20),
                        role: None,
                        persist_row_hash: String::new(),
                    },
                ),
                Some(&v1),
            )
        };
        let w_voices = widen(&newbie, &keys[0]);
        let w = e2::row_id_of(&w_voices[0]);
        assert!(landed(&e2::put_voices(d, &w_voices).await), "{tag} I6908");
        // founder_only: a plain member's voice alone is short; its voice is
        // kept and the row concludes nothing.
        let s_voices = widen(&other, &keys[1]);
        let short = e2::row_id_of(&s_voices[0]);
        let r = e2::put_voices(d, &s_voices).await;
        assert!(
            matches!(r, Ok(StatementOutcome::Pending { .. })),
            "{tag} I6908 premise: held short, its voice kept: {r:?}"
        );
        assert!(
            d.group_lineage_node(&short).await.unwrap().is_none(),
            "{tag} I6908 premise: a held row is no node"
        );
        // The protocol in force: the version's own; the widening its base's.
        let wn = d.group_lineage_node(&w).await.unwrap().expect("a node");
        assert_eq!(
            wn.consensus_protocol.as_deref(),
            Some(consensus_protocol::FOUNDER_ONLY),
            "{tag} I6908: a change carries its base's protocol"
        );
        assert_eq!(
            wn.policy_digest, None,
            "{tag} I6908: a family states no policy"
        );
        assert_eq!(
            wn.head_of,
            HeadOf::Widening,
            "{tag} I6908: no self-admission"
        );

        let digest = |s: &str| -> String {
            let mut h = sha2::Sha256::new();
            h.update(s.as_bytes());
            hex::encode(h.finalize())
        };
        let notice = digest(&format!("notice-{tag}"));
        let now = chrono::Utc::now();
        let execution = PurgeExecution {
            notice_id: notice.clone(),
            selection_digest: digest(&format!("selection-{tag}")),
            claimant_key_id: keys[0].clone(),
            legal_basis: "lineage witness".into(),
            record_count: 3,
            notice_jcs: "{}".into(),
            cosignatures_json: "[]".into(),
            executed_by: keys[0].clone(),
            origin: "local".into(),
            executed_at: now,
            admitted_at: now,
            finalized_at: None,
        };
        let tombstones: Vec<PurgeTombstone> = [v1, w, short]
            .iter()
            .enumerate()
            .map(|(i, id)| PurgeTombstone {
                notice_id: notice.clone(),
                ordinal: i as u64,
                plane: PurgePlane::Attestation,
                record_ref: id.hex(),
                derived_from: None,
            })
            .collect();
        d.store_purge_execution(&execution, &tombstones)
            .await
            .expect("I6908: the tombstones");
        for id in [v1, w] {
            assert_eq!(
                d.purge_delete_tombstoned_statements(&id.hex())
                    .await
                    .unwrap(),
                0,
                "{tag} I6908: a lineage node's statement is kept"
            );
            assert!(
                !d.edition2_voices(&id).await.unwrap().is_empty(),
                "{tag} I6908: still held"
            );
        }
        assert!(
            d.purge_delete_tombstoned_statements(&short.hex())
                .await
                .unwrap()
                > 0,
            "{tag} I6908: a tombstoned row that is no node loses its statement"
        );
        assert!(
            d.edition2_voices(&short).await.unwrap().is_empty(),
            "{tag} I6908: gone"
        );
        assert_eq!(
            lineage::heads(d, &group).await.unwrap(),
            vec![w],
            "{tag} I6908: the lineage is whole"
        );
    }

    async fn consent(d: &dyn FederationDirectory, group: &str, proposer: &str, member: &str) {
        use crate::federation::membership_acceptance::test_support::{
            acceptance_row, proposal_row,
        };
        let p = proposal_row(
            proposer,
            crate::federation::types::cohort_scope::FAMILY,
            group,
            member,
            None,
            at_ago(55),
        );
        e2::put_signed(d, &p).await.expect("the proposal");
        let acc = acceptance_row(member, &p, at_ago(55));
        e2::put_signed(d, &acc).await.expect("the acceptance");
    }

    /// A counted widening of `member` into the family `fam` (seeds), dated
    /// at `when`, naming `heads` (the lowest as `refs.head`), one voice per
    /// seed in `signers`.
    fn widening_naming(
        fam: &str,
        member: &str,
        when: chrono::DateTime<chrono::Utc>,
        heads: &[RowId],
        signers: &[&String],
    ) -> Vec<Vec<u8>> {
        use crate::federation::edition2::group::{
            membership_payload, MembershipRecord, MEMBERSHIP_PREFIX,
        };
        use crate::federation::edition2::head_rule::with_heads;
        let record = MembershipRecord::FamilyWidening(FamilyMembershipWidening {
            family_key_id: e2::kid(fam),
            member_key_id: e2::kid(member),
            joined_at: when,
            effective_at: when,
            role: None,
            persist_row_hash: String::new(),
        });
        let payload = with_heads(
            membership_payload(&record, None).expect("the payload"),
            heads,
        )
        .expect("the heads");
        signers
            .iter()
            .map(|k| {
                e2::sign_group_payload(
                    &e2::signing_key(k),
                    &e2::kid(member),
                    MEMBERSHIP_PREFIX,
                    &payload,
                )
            })
            .collect()
    }

    /// **I6911 — counted at the head, not the instant; tips and the join**
    /// (LINEAGE-L3).
    pub async fn i6911_counted_at_the_head(d: &dyn FederationDirectory, tag: &str) {
        use crate::federation::edition2::head_rule::roster_heads;
        let fam = format!("un-{tag}");
        let name = |n: &str| format!("{n}-{tag}");
        let (alice, bob) = (name("alice"), name("bob"));
        let (carol, dan, erin, frank, gina) = (
            name("carol"),
            name("dan"),
            name("erin"),
            name("frank"),
            name("gina"),
        );
        for k in [&alice, &bob, &carol, &dan, &erin, &frank, &gina] {
            e2::put_key(d, k, &["user"]).await;
        }
        let at = |s: &str| -> chrono::DateTime<chrono::Utc> { s.parse().expect("rfc3339") };
        let record = ts::sign_family(
            &alice,
            Family {
                prev_head_digest: String::new(),
                charter_digest: String::new(),
                family_key_id: fam.clone(),
                family_name: "household".into(),
                members: [&alice, &bob]
                    .iter()
                    .enumerate()
                    .map(|(i, k)| FamilyMember {
                        key_id: (*k).clone(),
                        joined_at: at("2026-01-01T00:00:00Z"),
                        role: (i == 0).then(|| "founder".to_owned()),
                    })
                    .collect(),
                founded_at: at("2026-01-01T00:00:00Z"),
                consensus_protocol: consensus_protocol::UNANIMOUS.to_owned(),
                consensus_protocol_entrenched: false,
                dissolved_at: None,
                persist_row_hash: String::new(),
            },
        );
        let founding = e2::family_voices(&record, 1, None, ms_ago(60));
        let v1 = e2::row_id_of(&founding[0]);
        assert!(landed(&e2::put_voices(d, &founding).await), "{tag} I6911");
        let group = e2::kid(&fam);
        for m in [&carol, &dan, &erin, &frank, &gina] {
            consent(d, &group, &alice, m).await;
        }

        // carol, by alice and bob: every member at v1.
        let wc = widening_naming(&fam, &carol, at_ago(30), &[v1], &[&alice, &bob]);
        let w_carol = e2::row_id_of(&wc[0]);
        assert!(landed(&e2::put_voices(d, &wc).await), "{tag} I6911: carol");

        // dan, DATED before carol's seat, naming it: at its instant only alice
        // and bob were members, at its head carol is one too.
        let t_dan = at_ago(40);
        let wd = widening_naming(&fam, &dan, t_dan, &[w_carol], &[&alice, &bob]);
        let w_dan = e2::row_id_of(&wd[0]);
        let r = e2::put_voices(d, &wd).await;
        assert!(
            matches!(r, Ok(StatementOutcome::Pending { .. })),
            "{tag} I6911: counted at the head it names, carol's voice is owed: {r:?}"
        );
        let r = e2::put_voices(
            d,
            &widening_naming(&fam, &dan, t_dan, &[w_carol], &[&carol]),
        )
        .await;
        assert!(landed(&r), "{tag} I6911: carol's voice completes it: {r:?}");
        assert_eq!(
            roster_heads(d, &group).await.unwrap(),
            vec![w_dan],
            "{tag} I6911"
        );

        // Two widenings naming dan's: two tips.
        let all4 = [&alice, &bob, &carol, &dan];
        let we = widening_naming(&fam, &erin, at_ago(20), &[w_dan], &all4);
        let w_erin = e2::row_id_of(&we[0]);
        assert!(landed(&e2::put_voices(d, &we).await), "{tag} I6911: erin");
        let wf = widening_naming(&fam, &frank, at_ago(19), &[w_dan], &all4);
        let w_frank = e2::row_id_of(&wf[0]);
        assert!(
            landed(&e2::put_voices(d, &wf).await),
            "{tag} I6911: frank, over the head it names (erin is no member there)"
        );
        let mut tips = vec![w_erin, w_frank];
        tips.sort();
        assert_eq!(
            roster_heads(d, &group).await.unwrap(),
            tips,
            "{tag} I6911: two tips"
        );
        let common = lineage::members_at(d, &tips).await.unwrap();
        assert!(
            !common.members.contains(&e2::kid(&erin)) && !common.members.contains(&e2::kid(&frank)),
            "{tag} I6911: at both tips, only the members common to them: {common:?}"
        );

        // gina's widening names both tips: the join, counted over the common
        // members (erin and frank owe no voice).
        let wg = widening_naming(&fam, &gina, at_ago(10), &tips, &all4);
        let w_gina = e2::row_id_of(&wg[0]);
        let r = e2::put_voices(d, &wg).await;
        assert!(
            landed(&r),
            "{tag} I6911: the join lands on the common members: {r:?}"
        );
        assert_eq!(
            roster_heads(d, &group).await.unwrap(),
            vec![w_gina],
            "{tag} I6911: one head again"
        );
        let at_join = lineage::members_at(d, &[w_gina]).await.unwrap();
        for k in [&alice, &bob, &carol, &dan, &erin, &frank, &gina] {
            assert!(
                at_join.members.contains(&e2::kid(k)),
                "{tag} I6911: {k} is seated at the join: {at_join:?}"
            );
        }
        let node = d
            .group_lineage_node(&w_gina)
            .await
            .unwrap()
            .expect("a node");
        assert_eq!(
            node.extends, tips,
            "{tag} I6911: the join extends both tips"
        );
    }

    /// **I6914 — the ends and who resigned since** (LINEAGE-L3d).
    pub async fn i6914_the_ends_and_who_resigned(d: &dyn FederationDirectory, tag: &str) {
        use crate::federation::edition2::lineage::LineageEnd;
        let g = format!("ends-g-{tag}");
        let v1 = node(tag, &g, 1, HeadOf::Roster, None, &[]);
        let w = node(tag, &g, 2, HeadOf::Widening, Some("m"), &[1]);
        let r = node(tag, &g, 3, HeadOf::Removal, Some("n"), &[2]);
        for n in [&v1, &w, &r] {
            d.put_group_lineage_node(n).await.expect("I6914: a node");
        }
        let end = |i: u8, member: &str, heads: &[u8]| {
            let mut h: Vec<RowId> = heads.iter().map(|x| id(tag, *x)).collect();
            h.sort();
            LineageEnd {
                row_id: id(tag, i),
                group_kind: GroupKind::Community,
                group: g.clone(),
                member: member.to_owned(),
                heads: h,
            }
        };
        let e_at_w = end(10, "p", &[2]);
        let e_at_r = end(11, "q", &[3]);
        let e_two = end(12, "s", &[2, 3]);
        for e in [&e_at_w, &e_at_r, &e_two] {
            d.put_group_lineage_end(e).await.expect("I6914: an end");
        }
        d.put_group_lineage_end(&e_at_w)
            .await
            .expect("I6914: idempotent");
        let mut held = d.group_lineage_ends(&g).await.unwrap();
        held.sort_by_key(|e| e.row_id);
        let mut want = vec![e_at_w.clone(), e_at_r.clone(), e_two.clone()];
        want.sort_by_key(|e| e.row_id);
        assert_eq!(
            held, want,
            "{tag} I6914: each end once, with every head it names"
        );
        assert!(
            d.group_lineage_node(&e_at_w.row_id)
                .await
                .unwrap()
                .is_none(),
            "{tag} I6914: an end is no node"
        );
        let set = |ks: &[&str]| -> std::collections::BTreeSet<String> {
            ks.iter().map(|k| (*k).to_owned()).collect()
        };
        assert_eq!(
            lineage::resigned_at(d, &[v1.row_id]).await.unwrap(),
            set(&[]),
            "{tag} I6914: no end acts from the version itself"
        );
        assert_eq!(
            lineage::resigned_at(d, &[w.row_id]).await.unwrap(),
            set(&["p", "s"]),
            "{tag} I6914: the ends acting from the widening"
        );
        assert_eq!(
            lineage::resigned_at(d, &[r.row_id]).await.unwrap(),
            set(&["p", "q", "s"]),
            "{tag} I6914: and from every head in the removal's past"
        );
        assert!(
            lineage::heads(d, &g).await.unwrap() == vec![r.row_id],
            "{tag} I6914: an end moves no head"
        );
    }

    /// **I6915 — a purge keeps an end** (LINEAGE-L3d).
    ///
    /// At the level the guard sits (the statement purge, both backends). The
    /// state is one NO DOOR produces on this base: an attestation-plane
    /// tombstone naming a group row, and an end recorded over a held row (a
    /// resignation is refused at the door until RESIGN-2), both stored
    /// directly. The mutation it kills: deleting the guard's
    /// `AND NOT EXISTS (SELECT 1 FROM ceg_group_lineage_ends WHERE row_id = ...)`
    /// makes the end's statement go; the other held row's goes in both.
    pub async fn i6915_a_purge_keeps_an_end<D>(d: &D, tag: &str)
    where
        D: crate::federation::directory_admit::DirectoryStore + Sync,
    {
        use crate::federation::edition2::lineage::LineageEnd;
        use crate::federation::steward_purge::{PurgeExecution, PurgePlane, PurgeTombstone};
        let fam = format!("pe-{tag}");
        let keys: Vec<String> = ["alice", "bob"]
            .iter()
            .map(|n| format!("{n}-{tag}"))
            .collect();
        let (x, y) = (format!("x-{tag}"), format!("y-{tag}"));
        for k in keys.iter().chain([&x, &y]) {
            e2::put_key(d, k, &["user"]).await;
        }
        let at = |s: &str| -> chrono::DateTime<chrono::Utc> { s.parse().expect("rfc3339") };
        let record = ts::sign_family(
            &keys[0],
            Family {
                prev_head_digest: String::new(),
                charter_digest: String::new(),
                family_key_id: fam.clone(),
                family_name: "household".into(),
                members: keys
                    .iter()
                    .enumerate()
                    .map(|(i, k)| FamilyMember {
                        key_id: k.clone(),
                        joined_at: at("2026-01-01T00:00:00Z"),
                        role: (i == 0).then(|| "founder".to_owned()),
                    })
                    .collect(),
                founded_at: at("2026-01-01T00:00:00Z"),
                consensus_protocol: consensus_protocol::FOUNDER_ONLY.to_owned(),
                consensus_protocol_entrenched: false,
                dissolved_at: None,
                persist_row_hash: String::new(),
            },
        );
        let founding = e2::family_voices(&record, 1, None, ms_ago(30));
        let v1 = e2::row_id_of(&founding[0]);
        assert!(landed(&e2::put_voices(d, &founding).await), "{tag} I6915");
        let group = e2::kid(&fam);
        for m in [&x, &y] {
            consent(d, &group, &keys[0], m).await;
        }
        // Two widenings voiced by a plain member alone: held short, their
        // voices kept.
        let mut short = Vec::new();
        for m in [&x, &y] {
            let v = widening_naming(&fam, m, at_ago(20), &[v1], &[&keys[1]]);
            let id = e2::row_id_of(&v[0]);
            let r = e2::put_voices(d, &v).await;
            assert!(
                matches!(r, Ok(StatementOutcome::Pending { .. })),
                "{tag} I6915 premise: held short: {r:?}"
            );
            short.push(id);
        }
        d.put_group_lineage_end(&LineageEnd {
            row_id: short[0],
            group_kind: GroupKind::Family,
            group: group.clone(),
            member: e2::kid(&x),
            heads: vec![v1],
        })
        .await
        .expect("I6915: the planted end");
        let digest = |s: &str| -> String {
            let mut h = sha2::Sha256::new();
            h.update(s.as_bytes());
            hex::encode(h.finalize())
        };
        let notice = digest(&format!("notice-{tag}"));
        let now = chrono::Utc::now();
        let execution = PurgeExecution {
            notice_id: notice.clone(),
            selection_digest: digest(&format!("selection-{tag}")),
            claimant_key_id: keys[0].clone(),
            legal_basis: "lineage witness".into(),
            record_count: 2,
            notice_jcs: "{}".into(),
            cosignatures_json: "[]".into(),
            executed_by: keys[0].clone(),
            origin: "local".into(),
            executed_at: now,
            admitted_at: now,
            finalized_at: None,
        };
        let tombstones: Vec<PurgeTombstone> = short
            .iter()
            .enumerate()
            .map(|(i, id)| PurgeTombstone {
                notice_id: notice.clone(),
                ordinal: i as u64,
                plane: PurgePlane::Attestation,
                record_ref: id.hex(),
                derived_from: None,
            })
            .collect();
        d.store_purge_execution(&execution, &tombstones)
            .await
            .expect("I6915: the tombstones");
        assert_eq!(
            d.purge_delete_tombstoned_statements(&short[0].hex())
                .await
                .unwrap(),
            0,
            "{tag} I6915: an end's statement is kept"
        );
        assert!(
            !d.edition2_voices(&short[0]).await.unwrap().is_empty(),
            "{tag} I6915: still held"
        );
        assert!(
            d.purge_delete_tombstoned_statements(&short[1].hex())
                .await
                .unwrap()
                > 0,
            "{tag} I6915: a row that is neither node nor end loses its statement"
        );
    }

    /// **I6916 — an act's head reads the seats there** (LINEAGE-L4).
    pub async fn i6916_an_acts_head_reads_the_seats(d: &dyn FederationDirectory, tag: &str) {
        use crate::federation::admission::admission_head_version;
        let fam = format!("hv-{tag}");
        let (alice, bob, newbie) = (
            format!("alice-{tag}"),
            format!("bob-{tag}"),
            format!("newbie-{tag}"),
        );
        for k in [&alice, &bob, &newbie] {
            e2::put_key(d, k, &["user"]).await;
        }
        let at = |s: &str| -> chrono::DateTime<chrono::Utc> { s.parse().expect("rfc3339") };
        let record = ts::sign_family(
            &alice,
            Family {
                prev_head_digest: String::new(),
                charter_digest: String::new(),
                family_key_id: fam.clone(),
                family_name: "household".into(),
                members: [&alice, &bob]
                    .iter()
                    .enumerate()
                    .map(|(i, k)| FamilyMember {
                        key_id: (*k).clone(),
                        joined_at: at("2026-01-01T00:00:00Z"),
                        role: (i == 0).then(|| "founder".to_owned()),
                    })
                    .collect(),
                founded_at: at("2026-01-01T00:00:00Z"),
                consensus_protocol: consensus_protocol::FOUNDER_ONLY.to_owned(),
                consensus_protocol_entrenched: false,
                dissolved_at: None,
                persist_row_hash: String::new(),
            },
        );
        let founding = e2::family_voices(&record, 1, None, ms_ago(30));
        let v1 = e2::row_id_of(&founding[0]);
        assert!(landed(&e2::put_voices(d, &founding).await), "{tag} I6916");
        let group = e2::kid(&fam);
        consent(d, &group, &alice, &newbie).await;
        let wv = widening_naming(&fam, &newbie, at_ago(20), &[v1], &[&alice]);
        let w = e2::row_id_of(&wv[0]);
        assert!(
            landed(&e2::put_voices(d, &wv).await),
            "{tag} I6916: the widening"
        );
        let keys = |v: &crate::federation::admission::HeadVersion| -> Vec<String> {
            let mut k: Vec<String> = v.members.iter().map(|(k, _)| k.clone()).collect();
            k.sort();
            k
        };
        let at_v1 = admission_head_version(d, &v1)
            .await
            .unwrap()
            .expect("I6916: the version resolves");
        assert!(
            !keys(&at_v1).contains(&e2::kid(&newbie)),
            "{tag} I6916: the founding version does not list newbie"
        );
        let at_w = admission_head_version(d, &w)
            .await
            .unwrap()
            .expect("I6916: the widening resolves to its version");
        assert!(
            keys(&at_w).contains(&e2::kid(&newbie)),
            "{tag} I6916: at the widening newbie is seated: {:?}",
            keys(&at_w)
        );
        assert_eq!(
            at_w.protocol,
            consensus_protocol::FOUNDER_ONLY,
            "{tag} I6916: the protocol in force is the version's"
        );
        let founders: Vec<&String> = at_w
            .members
            .iter()
            .filter(|(_, r)| crate::federation::consensus::is_founder_role(r.as_deref()))
            .map(|(k, _)| k)
            .collect();
        assert_eq!(founders, vec![&e2::kid(&alice)], "{tag} I6916: the founder");
    }
}

#[cfg(any(feature = "sqlite", feature = "postgres"))]
mod run {
    fn suffix() -> String {
        uuid::Uuid::new_v4().simple().to_string()
    }

    macro_rules! runners {
        ($modname:ident, $fresh:expr) => {
            mod $modname {
                use crate::federation::FederationDirectory;
                #[tokio::test]
                async fn i6902_the_lineage_store() {
                    let Some(d) = $fresh.await else { return };
                    super::super::bodies::i6902_the_lineage_store(
                        &d as &dyn FederationDirectory,
                        &format!("i6902-{}", super::suffix()),
                    )
                    .await
                }
                #[tokio::test]
                async fn i6906_the_head_moves_on_a_counted_change() {
                    let Some(d) = $fresh.await else { return };
                    super::super::bodies::i6906_the_head_moves_on_a_counted_change(
                        &d as &dyn FederationDirectory,
                        &format!("i6906-{}", super::suffix()),
                    )
                    .await
                }
                #[tokio::test]
                async fn i6908_a_purge_keeps_the_lineage() {
                    let Some(d) = $fresh.await else { return };
                    super::super::bodies::i6908_a_purge_keeps_the_lineage(
                        &d,
                        &format!("i6908-{}", super::suffix()),
                    )
                    .await
                }
                #[tokio::test]
                async fn i6911_counted_at_the_head() {
                    let Some(d) = $fresh.await else { return };
                    super::super::bodies::i6911_counted_at_the_head(
                        &d as &dyn FederationDirectory,
                        &format!("i6911-{}", super::suffix()),
                    )
                    .await
                }
                #[tokio::test]
                async fn i6914_the_ends_and_who_resigned() {
                    let Some(d) = $fresh.await else { return };
                    super::super::bodies::i6914_the_ends_and_who_resigned(
                        &d as &dyn FederationDirectory,
                        &format!("i6914-{}", super::suffix()),
                    )
                    .await
                }
                #[tokio::test]
                async fn i6915_a_purge_keeps_an_end() {
                    let Some(d) = $fresh.await else { return };
                    super::super::bodies::i6915_a_purge_keeps_an_end(
                        &d,
                        &format!("i6915-{}", super::suffix()),
                    )
                    .await
                }
                #[tokio::test]
                async fn i6916_an_acts_head_reads_the_seats() {
                    let Some(d) = $fresh.await else { return };
                    super::super::bodies::i6916_an_acts_head_reads_the_seats(
                        &d as &dyn FederationDirectory,
                        &format!("i6916-{}", super::suffix()),
                    )
                    .await
                }
                #[tokio::test]
                async fn i6903_the_door_writes_the_lineage() {
                    let Some(d) = $fresh.await else { return };
                    super::super::bodies::i6903_the_door_writes_the_lineage(
                        &d as &dyn FederationDirectory,
                        &format!("i6903-{}", super::suffix()),
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
