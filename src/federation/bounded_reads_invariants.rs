//! v53.1.6 — **I540–I545: five more reads bounded to what their folds use,
//! held to their verbatim pre-fix bodies.**
//!
//! CIRISEdge's heap harness (persist v53.1.4, sqlite) measured
//! `list_attestations_by(K)` at ~7 KB of heap per row — 59 MB for an
//! 8,252-row author — with peak ≈ concurrent peers × the largest author's
//! copy; skipping these persist reads took churn from 2.6 TB to 2.1 GB. The
//! pre-fix bodies are kept here VERBATIM as the oracles; equivalence on
//! memory, sqlite, postgres; boundedness through
//! [`crate::federation::read_probe`] on every run.
//!
//! - **I540** `send_set_for` / `owner_nodes_receiving`: one read of an
//!   owner's allow lists per owner per call ([`OwnerAudience`]), every node
//!   decided against it.
//! - **I541** `live_invitees_of`: the GROUP's live proposals (V150's
//!   `cohort_target` seek) and the invitees' `membership:*` replies, never
//!   every member's and occurrence's history. (sqlite, postgres: the
//!   membership fixtures live there.)
//! - **I542** `live_delegation_granters`: the subject's incoming
//!   `delegates_to` rows and the composers naming them (V178), the subject's
//!   `withdraws` / `recants` once for the per-granter check.
//! - **I543** the `config:*` renewal check (#997): the attester's rows about
//!   the subject under the dimension and their composers.
//! - **I544** `custody_acks_of(device, blob)`: the device's reports citing
//!   that blob (V180) and the device's composers naming them.
//! - **I545** `nodes_stewarded_by` / `nodes_owned_by` (= `nodes_of`, which
//!   `send_set_for` asks per principal on every Edge memo refresh): the
//!   steward's `delegates_to` edges (V107's `(attester, type)` prefix), never
//!   its whole history; each candidate's verdict is unchanged.
//! - **I546** (v53.1.7) `live_conferrals`: each conferral's composers through
//!   `list_attestations_referencing`, now V181's `(reference, type)` seek
//!   (CIRISEdge PR #818: a full table scan per conferral row); equivalence
//!   here, the plan in `store::sqlite`'s I546.
//! - **I547** (v53.1.7) the trust-root walks and `live_charter_rows`: each
//!   key's trust edges, conferrals, charters and drills (typed, job-filtered,
//!   with their composers), never the user's, root's, subject's or family's
//!   whole slice (CIRISServer's OOM probe: empty-kind anti-entropy rounds,
//!   410 → 2,084 MB in 16 s).
//!
//! [`OwnerAudience`]: crate::federation::replication_audience::OwnerAudience

#[cfg(all(test, any(feature = "sqlite", feature = "postgres")))]
pub(crate) mod bodies {
    use std::collections::{BTreeSet, HashSet};

    use crate::federation::audience_scan_invariants::bodies::owner_allow_list_reference;
    use crate::federation::edition2::fixture_switch as e2;
    use crate::federation::read_probe;
    use crate::federation::replication_audience as ra;
    use crate::federation::replication_audience_invariants::bodies as rab;
    use crate::federation::tier_ingest::test_support as ts;
    use crate::federation::types::attestation_type;
    use crate::federation::types::cohort_scope as cs;
    use crate::federation::types::identity_type::{AGENT, NODE, USER};
    use crate::federation::{
        admission, Attestation, Error, FederationDirectory, SignedAttestation,
    };

    /// Rows returned by reads of `method` keyed on `key`, summed.
    fn rows_of(log: &[read_probe::Read], method: &str, key: &str) -> usize {
        log.iter()
            .filter(|r| r.is(method, key))
            .map(|r| r.rows)
            .sum()
    }

    /// Calls of `method` keyed on `key`. A typed query's continuation pages
    /// (a cursor set) are the same call, walked.
    fn calls_of(log: &[read_probe::Read], method: &str, key: &str) -> usize {
        log.iter()
            .filter(|r| r.is(method, key) && r.is_first_page())
            .count()
    }

    /// v62.0.0 (JSON cut, E7) — a flipped row through the one entry
    /// (`e2::put_signed`); a delegation through `e2::land_delegation`.
    async fn put(d: &dyn FederationDirectory, a: Attestation) -> Result<(), Error> {
        // A held (earlier-form) body's row carries no statement: the JSON door.
        if e2::carried_statement(&a).is_none() {
            return d
                .put_attestation(SignedAttestation { attestation: a })
                .await
                .map(|_| ());
        }
        // v62.0.0 (round 6, E7) — a delegation lands with every voice its
        // family's model names (E0's `land_delegation`: an owner binding's
        // bound key, a conferral's delegate; CC 2.6.1.9 / 2.7.3). Short of
        // one, the row is held and concludes nothing.
        if a.attestation_type == attestation_type::DELEGATES_TO {
            e2::land_delegation(d, &a).await?;
            return Ok(());
        }
        e2::put_signed(d, &a).await?;
        Ok(())
    }

    /// v62.0.0 (JSON cut, E7) — `owner` binds `node`, NOW-relative: the
    /// builder stamps a fixed instant, and the node's voice is a node-key row
    /// (CC 2.4.1.1), so the binding is re-dated to an hour ago and re-sealed.
    fn owner_binding(owner: &str, node: &str) -> Attestation {
        let at = admission::truncate_to_substrate_resolution(
            chrono::Utc::now() - chrono::Duration::hours(1),
        );
        let mut ob = ts::owner_binding_attestation("", owner, node);
        ob.asserted_at = at;
        ob.scrub_timestamp = at;
        ob.attestation_envelope[crate::federation::envelope::paths::ASSERTED_AT] =
            serde_json::Value::String(admission::render_signed_instant(at));
        ts::reseal(&mut ob);
        ob
    }

    /// v62.0.0 (JSON cut, E7; P5c, CC ruling) — `machine`'s own
    /// SELF-occurrence (identity = occurrence = the machine, signed by it:
    /// O1's self pair): WHAT KIND of device it is. The owner binding says only
    /// WHO its human is.
    async fn self_occurrence(d: &dyn FederationDirectory, machine: &str, class: &str) {
        e2::put_bind(
            d,
            machine,
            machine,
            machine,
            class,
            &e2::BindOptions::default(),
        )
        .await
        .expect("the machine's own self-occurrence is admitted");
    }

    /// A structural composer of `kind` by `author`, attested to `attested`,
    /// naming `target`.
    ///
    /// v62.0.0 (round 6, E7) — E0's `composer_of`: `refs.target` names the
    /// TARGET's row id and the row carries the target's family (CC 2.4.1.1),
    /// about the target's subject. The earlier literal (an `id` member and a
    /// bare `references_attestation_id`) is not a composer payload, so the
    /// door could not determine its authorship. The subject is the target's
    /// subject as `composer_of` takes it; `_attested` is the earlier call
    /// shape's subject, unused (kept so the call sites read as before).
    fn composer(author: &str, _attested: &str, kind: &str, target: &Attestation) -> Attestation {
        e2::composer_of(kind, target, author)
    }

    // ── I540 ─────────────────────────────────────────────────────────────

    /// `owner_node_receives` as v53.1.5 shipped it (over the v53.1.4
    /// `owner_allow_list` oracle — the whole-slice read).
    async fn owner_node_receives_reference(
        dir: &dyn FederationDirectory,
        owner: &str,
        node: &str,
        cohort: ra::OwnerCohort<'_>,
    ) -> Result<bool, Error> {
        // v62.0.0 (JSON cut, E7; P5c) — a node is a person's device by the
        // person's OWNER BINDING (no machine sits under a person's key: WHO),
        // and its class is its own live self-occurrence's (none: server; an
        // owned agent is OwnedAgent, P5c update 4: WHAT KIND).
        // The oracle is otherwise the v53.1.5 body.
        if owner == node {
            return Ok(false);
        }
        match admission::owner_of(dir, node).await {
            Ok(Some(o)) if o == owner => {}
            Ok(_) | Err(Error::AmbiguousNodeOwner { .. }) => return Ok(false),
            Err(e) => return Err(e),
        }
        // An owned agent is OwnedAgent; an unnamed or unknown class is server.
        let is_agent = dir.lookup_public_key(node).await?.is_some_and(|r| {
            crate::federation::types::identity_type::set_contains(
                &r.identity_type,
                crate::federation::types::identity_type::AGENT,
            )
        });
        // P5c update 1 — the class is the node's own live self-occurrence's.
        let now = chrono::Utc::now();
        let stated = dir
            .list_identity_occurrences_active(node)
            .await?
            .into_iter()
            .filter(|o| o.identity_key_id == node && o.occurrence_key_id == node)
            .filter(|o| o.valid_until.is_none_or(|vu| vu > now))
            .max_by_key(|o| o.asserted_at)
            .and_then(|o| ra::NodeClass::of_device_class(&o.device_class));
        // P5c update 4 — an agent the owner OWNS (`owner_of` checked above) is
        // `OwnedAgent` whatever its self-occurrence says.
        let class = if is_agent {
            Some(ra::NodeClass::OwnedAgent)
        } else {
            stated.or_else(|| ra::NodeClass::of_device_class("server"))
        };
        let Some(class) = class else {
            return Ok(false);
        };
        let list = owner_allow_list_reference(dir, owner, node).await?;
        Ok(ra::class_allows(class, list.as_ref(), cohort))
    }

    /// `owner_nodes_receiving`, its oracle (v62.0.0, P5c: over the nodes the
    /// owner OWNS).
    pub async fn owner_nodes_receiving_reference(
        dir: &dyn FederationDirectory,
        owner: &str,
        cohort: ra::OwnerCohort<'_>,
    ) -> Result<Vec<String>, Error> {
        let nodes: BTreeSet<String> = nodes_owned_by_reference(dir, owner)
            .await?
            .into_iter()
            .collect();
        let mut out = Vec::new();
        for n in nodes {
            if owner_node_receives_reference(dir, owner, &n, cohort).await? {
                out.push(n);
            }
        }
        Ok(out)
    }

    /// `self_collective::send_set_for` as v53.1.5 shipped it.
    pub async fn send_set_for_reference(
        dir: &dyn FederationDirectory,
        k: &str,
        cohort_scope: &str,
    ) -> Result<Vec<String>, Error> {
        use crate::federation::self_collective::{nodes_of, principals_of};
        let mut set: BTreeSet<String> =
            crate::federation::consent_by_humans::consent_peers_by_principals(dir, k)
                .await?
                .into_iter()
                .collect();
        if cohort_scope == cs::SELF {
            for p in &principals_of(dir, k).await? {
                for n in nodes_of(dir, p).await? {
                    if owner_node_receives_reference(dir, p, &n, ra::OwnerCohort::SelfContent)
                        .await?
                    {
                        set.insert(n);
                    }
                }
            }
        } else if cohort_scope == cs::FAMILY {
            for p in &principals_of(dir, k).await? {
                for fam in dir.list_families_for_member_active(p).await? {
                    let cohort = ra::OwnerCohort::Group {
                        scope: cs::FAMILY,
                        target: &fam.family_key_id,
                    };
                    for m in dir.active_family_members(&fam.family_key_id).await? {
                        for n in nodes_of(dir, &m.key_id).await? {
                            if owner_node_receives_reference(dir, &m.key_id, &n, cohort).await? {
                                set.insert(n);
                            }
                        }
                    }
                }
            }
        }
        set.remove(k);
        Ok(set.into_iter().collect())
    }

    /// **I540** — the send set and the receiving nodes equal their v53.1.5
    /// bodies over two owners with several claimed nodes, lists on some, a
    /// withdrawn list, a family; and one owner's lists are read ONCE per
    /// call, never per node.
    pub async fn i540_send_set_reads_each_owners_lists_once(d: &dyn FederationDirectory, s: &str) {
        // v62.0.0 (JSON cut, E7; P5c) — keys by identity-ref; each node is its
        // owner's device by an owner binding with the node's own voice (no
        // node sits under a person's key, O1), and states its class by its
        // own self-occurrence.
        let (o1, o2) = (
            e2::kid(&format!("i540-o1-{s}")),
            e2::kid(&format!("i540-o2-{s}")),
        );
        let nodes: Vec<String> = (1..=4)
            .map(|i| e2::kid(&format!("i540-n{i}-{s}")))
            .collect();
        let fid = e2::kid(&format!("i540-fam-{s}"));
        rab::users(d, &[&o1, &o2]).await;
        rab::nodes(d, &nodes.iter().map(String::as_str).collect::<Vec<_>>()).await;
        for (owner, node, class) in [
            (&o1, &nodes[0], "laptop"),
            (&o1, &nodes[1], "server"),
            (&o1, &nodes[2], "phone"),
            (&o2, &nodes[3], "laptop"),
        ] {
            put(d, owner_binding(owner, node))
                .await
                .expect("the owner binds its device");
            self_occurrence(d, node, class).await;
        }
        rab::family(d, &fid, &[&o1, &o2]).await;
        // o1: a list on the laptop (family only), a list on the server (one
        // room), nothing on the phone; a second list on the laptop, withdrawn.
        rab::put(
            d,
            &rab::grant(
                &o1,
                Some(&nodes[0]),
                Some(rab::entries(&[("family", &fid)])),
            ),
        )
        .await
        .unwrap();
        rab::put(
            d,
            &rab::grant(
                &o1,
                Some(&nodes[1]),
                Some(rab::entries(&[("community", "r1")])),
            ),
        )
        .await
        .unwrap();
        let withdrawn = rab::grant(&o1, Some(&nodes[0]), Some(rab::entries(&[])));
        rab::put(d, &withdrawn).await.unwrap();
        put(
            d,
            composer(&o1, &o1, attestation_type::WITHDRAWS, &withdrawn),
        )
        .await
        .expect("o1 withdraws its list");
        // o2: a list naming nothing of the family's.
        rab::put(
            d,
            &rab::grant(
                &o2,
                Some(&nodes[3]),
                Some(rab::entries(&[("community", "r2")])),
            ),
        )
        .await
        .unwrap();

        let _ = read_probe::take();
        for k in [&o1, &o2, &nodes[0]] {
            for scope in [cs::SELF, cs::FAMILY, cs::COMMUNITY] {
                let got = crate::federation::self_collective::send_set_for(d, k, scope)
                    .await
                    .unwrap();
                let log = read_probe::take();
                let want = send_set_for_reference(d, k, scope).await.unwrap();
                let _ = read_probe::take();
                assert_eq!(got, want, "I540 send_set_for({k}, {scope})");
                if scope != cs::COMMUNITY {
                    assert!(
                        calls_of(&log, "list_attestations_by_dimension_prefix", &o1) <= 1,
                        "I540 send_set_for({k}, {scope}): o1's lists read more than once: {log:?}"
                    );
                }
            }
        }
        let family = ra::OwnerCohort::Group {
            scope: cs::FAMILY,
            target: &fid,
        };
        for cohort in [
            ra::OwnerCohort::SelfContent,
            family,
            ra::OwnerCohort::Group {
                scope: cs::COMMUNITY,
                target: "r1",
            },
        ] {
            for o in [&o1, &o2] {
                let got = ra::owner_nodes_receiving(d, o, cohort).await.unwrap();
                let log = read_probe::take();
                let want = owner_nodes_receiving_reference(d, o, cohort).await.unwrap();
                let _ = read_probe::take();
                assert_eq!(got, want, "I540 owner_nodes_receiving({o}, {cohort:?})");
                assert_eq!(
                    calls_of(&log, "list_attestations_by_dimension_prefix", o),
                    1,
                    "I540: the owner's lists are read once for all nodes: {log:?}"
                );
                assert_eq!(
                    rows_of(&log, "list_attestations_by", o),
                    0,
                    "I540: no whole-slice read of the owner: {log:?}"
                );
            }
        }
        // Literals: the laptop gets the family, the server does not; the
        // phone (no list) gets everything; r1 reaches the server only.
        // (Kids sort by hash, not by index: the set is compared sorted.)
        let sorted = |mut v: Vec<String>| {
            v.sort();
            v
        };
        assert_eq!(
            ra::owner_nodes_receiving(d, &o1, family).await.unwrap(),
            sorted(vec![nodes[0].clone(), nodes[2].clone()])
        );
        assert_eq!(
            ra::owner_nodes_receiving(
                d,
                &o1,
                ra::OwnerCohort::Group {
                    scope: cs::COMMUNITY,
                    target: "r1"
                }
            )
            .await
            .unwrap(),
            sorted(vec![nodes[1].clone(), nodes[2].clone()])
        );
    }

    // ── I541 ─────────────────────────────────────────────────────────────

    /// `membership_acceptance::live_invitees_of` as v53.1.5 shipped it.
    #[cfg(any(feature = "sqlite", feature = "postgres"))]
    pub async fn live_invitees_of_reference(
        dir: &dyn FederationDirectory,
        scope: &str,
        group: &str,
        members: &[String],
    ) -> Result<Vec<String>, Error> {
        use crate::federation::attestation_query::test_support::AllAttestations as _;
        use crate::federation::membership_acceptance as ma;
        use crate::federation::types::attestation_tier;
        let now = chrono::Utc::now();
        let mut signers: BTreeSet<String> = members.iter().cloned().collect();
        for m in members {
            for o in dir.list_identity_occurrences_active(m).await? {
                signers.insert(o.occurrence_key_id);
            }
        }
        let mut out = BTreeSet::new();
        for s in &signers {
            for row in dir.all_attestations_by(s).await? {
                if row.tier != attestation_tier::FEDERATION {
                    continue;
                }
                let Some(p) = ma::as_proposal(row) else {
                    continue;
                };
                if !ma::same_membership_plane(&p.row.cohort_scope, scope)
                    || p.group != group
                    || p.expires_at <= now
                {
                    continue;
                }
                // v55.0.0 (CIRISPersist#1053) — a standing proposal names no
                // invitee; the live invitees are the named ones.
                let Some(invitee) = p.invitee.clone() else {
                    continue;
                };
                if ma::proposal_withdrawn(dir, &p).await? {
                    continue;
                }
                let replies = dir
                    .all_attestations_for(&invitee)
                    .await?
                    .into_iter()
                    .filter(|r| {
                        r.tier == attestation_tier::FEDERATION
                            && matches!(
                                ma::membership_row(r),
                                Some(ma::MembershipRow::Acceptance | ma::MembershipRow::Decline)
                            )
                    })
                    .collect::<Vec<_>>();
                let declined = ma::replies_to(&replies, &p.row.attestation_id)
                    .iter()
                    .any(|r| ma::membership_row(r) == Some(ma::MembershipRow::Decline));
                if !declined {
                    out.insert(invitee);
                }
            }
        }
        Ok(out.into_iter().collect())
    }

    /// **I541** — the live invitees of a room and of a family equal the
    /// v53.1.5 body: a live proposal, a declined one, an accepted one, a
    /// withdrawn one, a proposal into another room; and no member's or
    /// occurrence's whole history is read — the group's proposals are one
    /// targeted read.
    #[cfg(any(feature = "sqlite", feature = "postgres"))]
    pub async fn i541_live_invitees_read_the_groups_proposals(
        d: &dyn FederationDirectory,
        s: &str,
    ) {
        use crate::federation::membership_acceptance::live_invitees_of;
        use crate::federation::membership_acceptance_invariants::bodies as mab;
        let (a, b) = (
            e2::kid(&format!("i541-a-{s}")),
            e2::kid(&format!("i541-b-{s}")),
        );
        let (x, y, z, w) = (
            e2::kid(&format!("i541-x-{s}")),
            e2::kid(&format!("i541-y-{s}")),
            e2::kid(&format!("i541-z-{s}")),
            e2::kid(&format!("i541-w-{s}")),
        );
        let (room, other, fam) = (
            e2::kid(&format!("i541-room-{s}")),
            e2::kid(&format!("i541-other-{s}")),
            e2::kid(&format!("i541-fam-{s}")),
        );
        mab::reg(d, &[&a, &b, &x, &y, &z, &w]).await;
        mab::found_community(d, &room, "quorum:1/1", &[&a, &b], &[])
            .await
            .expect("room");
        mab::found_community(d, &other, "quorum:1/1", &[&a], &[])
            .await
            .expect("other room");
        mab::found_family(d, &fam, "founder_only", &[&a, &b], &[])
            .await
            .expect("family");
        let now = chrono::Utc::now();
        let ttl = Some(chrono::Duration::days(7));
        // Live: a invites x into the room.
        mab::put(
            d,
            &mab::proposal(&a, cs::COMMUNITY, &room, &x, None, now, ttl),
        )
        .await
        .expect("a → x");
        // Declined: b invites y, y declines.
        let py = mab::proposal(&b, cs::COMMUNITY, &room, &y, None, now, ttl);
        mab::put(d, &py).await.expect("b → y");
        mab::put(d, &mab::reply(&y, &y, &py, false, now))
            .await
            .expect("y declines");
        // Accepted (still a live invitee until the roster grows): a invites z.
        let pz = mab::proposal(&a, cs::COMMUNITY, &room, &z, None, now, ttl);
        mab::put(d, &pz).await.expect("a → z");
        mab::put(d, &mab::reply(&z, &z, &pz, true, now))
            .await
            .expect("z accepts");
        // Withdrawn: a invites w, then withdraws the proposal.
        let pw = mab::proposal(&a, cs::COMMUNITY, &room, &w, None, now, ttl);
        mab::put(d, &pw).await.expect("a → w");
        put(d, composer(&a, &a, attestation_type::WITHDRAWS, &pw))
            .await
            .expect("a withdraws");
        // Another room's proposal by the same inviter, and a family one.
        mab::put(
            d,
            &mab::proposal(&a, cs::COMMUNITY, &other, &w, None, now, ttl),
        )
        .await
        .expect("a → w (other)");
        mab::put(d, &mab::proposal(&b, cs::FAMILY, &fam, &x, None, now, ttl))
            .await
            .expect("b → x (family)");
        let members = vec![a.clone(), b.clone()];

        let _ = read_probe::take();
        for (scope, group) in [
            (cs::COMMUNITY, &room),
            (cs::AFFILIATIONS, &room),
            (cs::COMMUNITY, &other),
            (cs::FAMILY, &fam),
            (cs::SELF, &room),
        ] {
            let got = live_invitees_of(d, scope, group, &members).await.unwrap();
            let log = read_probe::take();
            let want = live_invitees_of_reference(d, scope, group, &members)
                .await
                .unwrap();
            let _ = read_probe::take();
            assert_eq!(got, want, "I541 live_invitees_of({scope}, {group})");
            for m in &members {
                assert_eq!(
                    rows_of(&log, "list_attestations_by", m),
                    0,
                    "I541: no member's whole history is read: {log:?}"
                );
            }
            assert!(
                calls_of(&log, "list_targeted_by_dimension_prefix", group) <= 1,
                "I541: the group's proposals are one targeted read: {log:?}"
            );
        }
        assert_eq!(
            live_invitees_of(d, cs::COMMUNITY, &room, &members)
                .await
                .unwrap(),
            {
                let mut v = vec![x.clone(), z.clone()];
                v.sort();
                v
            },
            "I541: x (live) and z (accepted); y declined, w withdrawn"
        );
    }

    // ── I542 ─────────────────────────────────────────────────────────────

    /// `admission::live_delegation_granters` as v53.1.5 shipped it.
    pub async fn live_delegation_granters_reference(
        directory: &dyn FederationDirectory,
        subject: &str,
        filter: admission::DelegationEdgeFilter,
    ) -> Result<BTreeSet<String>, Error> {
        use crate::federation::attestation_query::test_support::AllAttestations as _;
        use crate::federation::types::identity_type;
        let mut out: BTreeSet<String> = BTreeSet::new();
        let mut granter_live: std::collections::HashMap<String, bool> =
            std::collections::HashMap::new();
        let now = chrono::Utc::now();
        let rows = directory.all_attestations_for(subject).await?;
        let withdrawn = admission::retracted_edge_ids(&rows);
        for r in rows {
            if r.attestation_type != attestation_type::DELEGATES_TO {
                continue;
            }
            if filter == admission::DelegationEdgeFilter::OwnerBindingOnly
                && !admission::is_owner_binding_envelope(&r.attestation_envelope)
            {
                continue;
            }
            if withdrawn.contains(r.attestation_id.as_str()) {
                continue;
            }
            if let Some(exp) = r.expires_at {
                if exp <= now {
                    continue;
                }
            }
            if admission::delegation_valid_until_lapsed(&r.attestation_envelope, now) {
                continue;
            }
            if out.contains(&r.attesting_key_id) {
                continue;
            }
            if let Some(live) = granter_live.get(r.attesting_key_id.as_str()) {
                if *live {
                    out.insert(r.attesting_key_id);
                }
                continue;
            }
            let is_user = directory
                .lookup_public_key(&r.attesting_key_id)
                .await?
                .is_some_and(|g| {
                    identity_type::set_contains(&g.identity_type, identity_type::USER)
                });
            let granter_retracted = is_user
                && directory
                    .all_attestations_by(&r.attesting_key_id)
                    .await?
                    .into_iter()
                    .any(|g| {
                        (g.attestation_type == attestation_type::WITHDRAWS
                            || g.attestation_type == attestation_type::RECANTS)
                            && g.attested_key_id == subject
                    });
            let live = is_user && !granter_retracted;
            granter_live.insert(r.attesting_key_id.clone(), live);
            if live {
                out.insert(r.attesting_key_id);
            }
        }
        Ok(out)
    }

    /// A plain conferral `delegates_to(user → agent)`.
    fn conferral(user: &str, agent: &str) -> Attestation {
        let id = uuid::Uuid::new_v4().to_string();
        let env = serde_json::json!({
            "id": id, "kind": "delegates_to", "delegate_key_id": agent,
            "scope": ["act_on_behalf", "message_io"], "sub_delegation": false,
        });
        let mut r = ts::bare_attestation(&id, user, agent, &env);
        r.attestation_type = attestation_type::DELEGATES_TO.to_owned();
        ts::seal_row_in_place(user, &mut r);
        r
    }

    /// **I542** — the live granters of an agent and of a node equal the
    /// v53.1.5 body across live, withdrawn-by-the-granter, recanted and
    /// non-user edges, under both filters; and neither the subject's whole
    /// slice nor any granter's whole history is read.
    pub async fn i542_live_granters_read_the_subjects_edges(d: &dyn FederationDirectory, s: &str) {
        use admission::DelegationEdgeFilter::{AnyDelegation, OwnerBindingOnly};
        let (u1, u2, u3) = (
            e2::kid(&format!("i542-u1-{s}")),
            e2::kid(&format!("i542-u2-{s}")),
            e2::kid(&format!("i542-u3-{s}")),
        );
        let (agent, node, node2, peer) = (
            e2::kid(&format!("i542-agent-{s}")),
            e2::kid(&format!("i542-node-{s}")),
            e2::kid(&format!("i542-node2-{s}")),
            e2::kid(&format!("i542-peer-{s}")),
        );
        for (k, t) in [
            (&u1, USER),
            (&u2, USER),
            (&u3, USER),
            (&agent, AGENT),
            (&node, NODE),
            (&node2, NODE),
            (&peer, NODE),
        ] {
            ts::register_hybrid_key_as(d, k, k, t).await;
        }
        // u1 confers to the agent (live); u2 confers, then withdraws its
        // edge; u3 confers, then recants; the peer node confers (not a user).
        put(d, conferral(&u1, &agent)).await.expect("u1 → agent");
        let e2 = conferral(&u2, &agent);
        put(d, e2.clone()).await.expect("u2 → agent");
        put(d, composer(&u2, &agent, attestation_type::WITHDRAWS, &e2))
            .await
            .expect("u2 withdraws");
        let e3 = conferral(&u3, &agent);
        put(d, e3.clone()).await.expect("u3 → agent");
        put(d, composer(&u3, &agent, attestation_type::RECANTS, &e3))
            .await
            .expect("u3 recants");
        put(d, conferral(&peer, &agent))
            .await
            .expect("peer → agent");
        // u4 confers naming the agent as the edge's subject; the AGENT
        // withdraws it (CC 4.5.1.1 rule 2: a subject may withdraw a row
        // naming it). Only the composers-attested-to-the-subject read sees
        // this retraction — the per-granter check does not, because u4
        // retracted nothing — which is what makes that read load-bearing.
        let u4 = e2::kid(&format!("i542-u4-{s}"));
        ts::register_hybrid_key_as(d, &u4, &u4, USER).await;
        let mut e4 = conferral(&u4, &agent);
        e4.subject_key_ids = vec![agent.clone()];
        ts::reseal(&mut e4);
        put(d, e4.clone())
            .await
            .expect("u4 → agent, naming the agent");
        put(
            d,
            composer(&agent, &agent, attestation_type::WITHDRAWS, &e4),
        )
        .await
        .expect("the agent withdraws u4's edge");
        // u1 owns the node; u2 owns a second node, then withdraws that
        // binding (a node has exactly one owner, so two bindings on one node
        // are refused at the door).
        put(d, owner_binding(&u1, &node))
            .await
            .expect("u1 owns the node");
        let ob2 = owner_binding(&u2, &node2);
        put(d, ob2.clone()).await.expect("u2 owns node2");
        put(d, composer(&u2, &node2, attestation_type::WITHDRAWS, &ob2))
            .await
            .expect("u2 withdraws its binding");
        // Noise about the agent: its own self-reports.
        for i in 0..5 {
            let env = serde_json::json!({ "dimension": format!("config:i542-{i}:v1"), "n": i });
            let id = uuid::Uuid::new_v4().to_string();
            let mut r = ts::bare_attestation(&id, &agent, &agent, &env);
            r.attestation_type = attestation_type::SCORES.into();
            r.weight = None;
            ts::seal_row_in_place(&agent, &mut r);
            put(d, r).await.expect("self-report");
        }

        let _ = read_probe::take();
        for subject in [&agent, &node, &node2, &u1, &peer] {
            for filter in [AnyDelegation, OwnerBindingOnly] {
                let got = admission::live_delegation_granters(d, subject, filter)
                    .await
                    .unwrap();
                let log = read_probe::take();
                let want = live_delegation_granters_reference(d, subject, filter)
                    .await
                    .unwrap();
                let _ = read_probe::take();
                assert_eq!(
                    got, want,
                    "I542 live_delegation_granters({subject}, {filter:?})"
                );
                assert_eq!(
                    rows_of(&log, "list_attestations_for", subject),
                    0,
                    "I542: the subject's whole slice is not read: {log:?}"
                );
                for g in [&u1, &u2, &u3, &u4, &peer] {
                    assert_eq!(
                        rows_of(&log, "list_attestations_by", g),
                        0,
                        "I542: no granter's whole history is read: {log:?}"
                    );
                }
            }
        }
        assert_eq!(
            admission::live_delegation_granters(d, &agent, AnyDelegation)
                .await
                .unwrap(),
            BTreeSet::from([u1.clone()]),
            "I542: u1 stands; u2 withdrew, u3 recanted, the peer is no user, the agent \
             withdrew u4's"
        );
        assert_eq!(
            admission::live_delegation_granters(d, &node, OwnerBindingOnly)
                .await
                .unwrap(),
            BTreeSet::from([u1.clone()])
        );
        assert!(
            admission::live_delegation_granters(d, &node2, OwnerBindingOnly)
                .await
                .unwrap()
                .is_empty(),
            "I542: u2 withdrew its binding"
        );
    }

    // ── I543 ─────────────────────────────────────────────────────────────

    /// `admission::check_config_renewal_supersedes` as v53.1.5 shipped it.
    pub async fn check_config_renewal_supersedes_reference(
        directory: &dyn FederationDirectory,
        row: &Attestation,
    ) -> Result<(), Error> {
        use crate::federation::attestation_query::test_support::AllAttestations as _;
        let Some(dimension) = admission::envelope_dimension(&row.attestation_envelope) else {
            return Ok(());
        };
        if !dimension.starts_with(admission::CONFIG_DIMENSION_PREFIX) {
            return Ok(());
        }
        if crate::federation::precedence::is_structural_composer(&row.attestation_type) {
            if row.attestation_type != attestation_type::SUPERSEDES {
                return Ok(());
            }
            // (The supersedes arm resolves its target through `get_attestation`
            // and is unchanged by v53.1.6; this oracle covers the renewal arm.)
            return admission::check_config_renewal_supersedes(directory, row).await;
        }
        let existing = directory.all_attestations_for(&row.attested_key_id).await?;
        let refs: Vec<&Attestation> = existing.iter().collect();
        let retired = crate::federation::precedence::retired_ids(&refs);
        for prior in &existing {
            if prior.attestation_id == row.attestation_id {
                continue;
            }
            if retired.contains(&prior.attestation_id) {
                continue;
            }
            if prior.attesting_key_id != row.attesting_key_id {
                continue;
            }
            if prior.cohort_scope != row.cohort_scope {
                continue;
            }
            if admission::envelope_dimension(&prior.attestation_envelope) != Some(dimension) {
                continue;
            }
            return Err(Error::InvalidArgument(format!(
                "{dimension} from {:?} at cohort_scope {:?} already has a live row \
                 ({}, itself at cohort_scope {:?}). A renewal MUST carry a `supersedes` naming \
                 the row it replaces (CC 3.4.5.1): two live rows for one (subject, scope, leaf) \
                 make a composer that weights by live count read one node as two, so a node \
                 that renews correctly would halve its own signal against one that does not.",
                row.attesting_key_id, row.cohort_scope, prior.attestation_id, prior.cohort_scope
            )));
        }
        Ok(())
    }

    fn self_report(k: &str, leaf: &str) -> Attestation {
        let id = uuid::Uuid::new_v4().to_string();
        let env = serde_json::json!({ "dimension": format!("config:{leaf}:v1"), "id": id });
        let mut r = ts::bare_attestation(&id, k, k, &env);
        r.attestation_type = attestation_type::SCORES.into();
        r.weight = None;
        ts::seal_row_in_place(k, &mut r);
        r
    }

    /// **I543** — the renewal check answers as the v53.1.5 body for a leaf
    /// with a live row, a recanted row, a withdrawn row, a fresh leaf, a
    /// different attester, a `withdraws` of the leaf; and the subject's
    /// whole slice is not read.
    pub async fn i543_the_config_renewal_check_reads_the_leaf(
        d: &dyn FederationDirectory,
        s: &str,
    ) {
        let (t, other) = (
            e2::kid(&format!("i543-t-{s}")),
            e2::kid(&format!("i543-other-{s}")),
        );
        ts::register_hybrid_key_as(d, &t, &t, NODE).await;
        ts::register_hybrid_key_as(d, &other, &other, NODE).await;
        put(d, self_report(&t, "live")).await.expect("live");
        let recanted = self_report(&t, "recanted");
        put(d, recanted.clone()).await.expect("recanted");
        put(d, composer(&t, &t, attestation_type::RECANTS, &recanted))
            .await
            .expect("t recants");
        let withdrawn = self_report(&t, "withdrawn");
        put(d, withdrawn.clone()).await.expect("withdrawn");
        put(d, composer(&t, &t, attestation_type::WITHDRAWS, &withdrawn))
            .await
            .expect("t withdraws");
        // Noise: consent rows and community-unrelated rows about t by others
        // are not needed — the leaf read excludes them by construction.
        let mut candidates = vec![
            ("same leaf, live", self_report(&t, "live"), true),
            ("recanted leaf", self_report(&t, "recanted"), false),
            ("withdrawn leaf", self_report(&t, "withdrawn"), false),
            ("fresh leaf", self_report(&t, "fresh"), false),
        ];
        let mut foreign = self_report(&other, "live");
        foreign.attested_key_id = t.clone();
        ts::reseal(&mut foreign);
        candidates.push(("another attester, same leaf", foreign, false));
        // v62.0.0 (JSON cut, E7) — an edition-2 composer names a HELD row.
        let w = composer(&t, &t, attestation_type::WITHDRAWS, &withdrawn);
        candidates.push(("a withdraws is exempt", w, false));

        let _ = read_probe::take();
        for (label, row, refused) in &candidates {
            let got = admission::check_config_renewal_supersedes(d, row).await;
            let log = read_probe::take();
            let want = check_config_renewal_supersedes_reference(d, row).await;
            let _ = read_probe::take();
            assert_eq!(
                got.as_ref().map_err(ToString::to_string),
                want.as_ref().map_err(ToString::to_string),
                "I543 {label}"
            );
            assert_eq!(got.is_err(), *refused, "I543 {label}");
            assert_eq!(
                rows_of(&log, "list_attestations_for", &t),
                0,
                "I543 {label}: the subject's whole slice is not read: {log:?}"
            );
        }
    }

    // ── I544 ─────────────────────────────────────────────────────────────

    /// `custody_ack::custody_acks_of` as v53.1.5 shipped it.
    pub async fn custody_acks_of_reference(
        directory: &dyn FederationDirectory,
        device_key_id: &str,
        blob_sha256_hex: &str,
    ) -> Result<Vec<crate::federation::custody_ack::CustodyAck>, Error> {
        use crate::federation::attestation_query::test_support::AllAttestations as _;
        use crate::federation::custody_ack::parse_custody_ack;
        let rows = directory.all_attestations_by(device_key_id).await?;
        let refs: Vec<&Attestation> = rows.iter().collect();
        let retired = crate::federation::precedence::retired_ids(&refs);
        Ok(rows
            .iter()
            .filter(|r| !retired.contains(&r.attestation_id))
            .filter_map(|r| match parse_custody_ack(r) {
                Ok(Some(a)) => Some(a),
                Ok(None) => None,
                Err(_) => None,
            })
            .filter(|a| a.device_key_id == device_key_id && a.blob_sha256_hex == blob_sha256_hex)
            .collect())
    }

    fn sha(tag: &str) -> [u8; 32] {
        use sha2::Digest as _;
        sha2::Sha256::digest(tag.as_bytes()).into()
    }

    /// **I544** — a device's custody of each blob equals the v53.1.5 body:
    /// several blobs, repeated reports, a `none` report, a recanted report,
    /// another device's report of the same blob; and the device's whole
    /// history is never read.
    pub async fn i544_custody_acks_read_the_devices_reports_of_the_blob(
        d: &dyn FederationDirectory,
        s: &str,
    ) {
        use crate::federation::custody_ack::CustodyState;
        use crate::federation::custody_ack_invariants::bodies as cab;
        // (`device_as` derives the key from the alias's first 32 bytes, so
        // the tag must be long enough to carry them.)
        let dev = cab::device(d, &format!("i544-device-alpha-{s}-{s}")).await;
        let other = cab::device(d, &format!("i544-device-bravo-{s}-{s}")).await;
        let blobs: Vec<[u8; 32]> = (0..4).map(|i| sha(&format!("i544-blob-{i}-{s}"))).collect();
        let base = cab::base();
        let minute = |m: i64| base + chrono::Duration::minutes(m);
        // dev: b0 here twice, b1 none, b2 here then recanted, b3 by other only.
        cab::report(d, &dev, &blobs[0], CustodyState::Here, minute(1)).await;
        cab::report(d, &dev, &blobs[0], CustodyState::Here, minute(2)).await;
        cab::report(d, &dev, &blobs[1], CustodyState::None, minute(3)).await;
        let r2 = cab::report(d, &dev, &blobs[2], CustodyState::Here, minute(4)).await;
        let r2_row = d
            .get_attestation(&r2)
            .await
            .unwrap()
            .expect("dev's report is held");
        put(d, composer(&dev, &dev, attestation_type::RECANTS, &r2_row))
            .await
            .expect("dev recants");
        cab::report(d, &other, &blobs[3], CustodyState::Here, minute(5)).await;
        cab::report(d, &other, &blobs[0], CustodyState::Here, minute(6)).await;
        // Noise under dev's key: self-reports.
        for i in 0..5 {
            put(d, self_report(&dev, &format!("i544-{i}")))
                .await
                .expect("noise");
        }

        let _ = read_probe::take();
        for device in [&dev, &other] {
            for b in &blobs {
                let hex = hex::encode(b);
                let got = crate::federation::custody_ack::custody_acks_of(d, device, &hex)
                    .await
                    .unwrap();
                let log = read_probe::take();
                let want = custody_acks_of_reference(d, device, &hex).await.unwrap();
                let _ = read_probe::take();
                assert_eq!(got, want, "I544 custody_acks_of({device}, blob {hex})");
                assert_eq!(
                    rows_of(&log, "list_attestations_by", device),
                    0,
                    "I544: the device's whole history is not read: {log:?}"
                );
                let cited = rows_of(&log, "list_attestations_by_dimension_citing", device);
                assert!(
                    cited <= 2,
                    "I544: the citation seek returns the blob's reports only: {log:?}"
                );
            }
        }
        let b0 = hex::encode(blobs[0]);
        assert_eq!(
            crate::federation::custody_ack::custody_acks_of(d, &dev, &b0)
                .await
                .unwrap()
                .len(),
            2,
            "I544: both of dev's b0 reports"
        );
        assert!(
            crate::federation::custody_ack::custody_acks_of(d, &dev, &hex::encode(blobs[2]))
                .await
                .unwrap()
                .is_empty(),
            "I544: the recanted report is retired"
        );
        let _ = HashSet::<String>::new();
    }

    // ── I545 ─────────────────────────────────────────────────────────────

    /// `admission::nodes_stewarded_by` as v53.1.5 shipped it.
    pub async fn nodes_stewarded_by_reference(
        directory: &dyn FederationDirectory,
        steward_user_key_id: &str,
    ) -> Result<Vec<String>, Error> {
        use crate::federation::attestation_query::test_support::AllAttestations as _;
        let mut candidates: std::collections::HashSet<String> = std::collections::HashSet::new();
        for r in directory.all_attestations_by(steward_user_key_id).await? {
            if r.attestation_type == attestation_type::DELEGATES_TO {
                candidates.insert(r.attested_key_id);
            }
        }
        for occ in directory
            .list_identity_occurrences_for(steward_user_key_id)
            .await?
        {
            candidates.insert(occ.occurrence_key_id);
        }
        candidates.insert(steward_user_key_id.to_owned());
        let mut out: Vec<String> = Vec::new();
        for cand in candidates {
            if admission::steward_bindings_of(directory, &cand)
                .await?
                .iter()
                .any(|anchor| anchor == steward_user_key_id)
            {
                out.push(cand);
            }
        }
        out.sort();
        Ok(out)
    }

    /// `admission::nodes_owned_by` (= `self_collective::nodes_of`) as v53.1.5
    /// shipped it.
    pub async fn nodes_owned_by_reference(
        directory: &dyn FederationDirectory,
        person: &str,
    ) -> Result<Vec<String>, Error> {
        use crate::federation::attestation_query::test_support::AllAttestations as _;
        let mut candidates = std::collections::BTreeSet::new();
        for row in directory.all_attestations_by(person).await? {
            if row.attestation_type == attestation_type::DELEGATES_TO
                && admission::is_owner_binding_envelope(&row.attestation_envelope)
                && !row.attested_key_id.is_empty()
            {
                candidates.insert(row.attested_key_id);
            }
        }
        let mut out = Vec::new();
        for node in candidates {
            match admission::owner_of(directory, &node).await {
                Ok(Some(owner)) if owner == person => out.push(node),
                Ok(_) => {}
                Err(Error::AmbiguousNodeOwner { .. }) => {}
                Err(e) => return Err(e),
            }
        }
        Ok(out)
    }

    /// A plain (unmarked) delegation `delegates_to(user → node)`.
    fn plain_delegation(user: &str, node: &str) -> Attestation {
        let id = uuid::Uuid::new_v4().to_string();
        let env = serde_json::json!({
            "id": id, "kind": "delegates_to", "delegate_key_id": node,
            "scope": [crate::federation::types::delegation_scope::INFRA_SERVE],
            "sub_delegation": false,
        });
        let mut r = ts::bare_attestation(&id, user, node, &env);
        r.attestation_type = attestation_type::DELEGATES_TO.to_owned();
        ts::seal_row_in_place(user, &mut r);
        r
    }

    /// **I545** — `nodes_stewarded_by` and `nodes_owned_by` / `nodes_of`
    /// equal their v53.1.5 bodies over a steward with many unrelated rows
    /// (self-reports, consent grants), claimed nodes, bindings withdrawn by
    /// the steward, recanted, superseded and withdrawn by the node they name,
    /// a plain delegation to a node, a conferral to an agent, and a second
    /// steward; and the steward's whole history is never read — only its
    /// `delegates_to` edges — while the v53.1.5 bodies read it every call.
    pub async fn i545_nodes_of_reads_the_stewards_delegations(
        d: &dyn FederationDirectory,
        s: &str,
    ) {
        use crate::federation::replication_audience_invariants::bodies as rab;
        let (u1, u2, u3) = (
            e2::kid(&format!("i545-u1-{s}")),
            e2::kid(&format!("i545-u2-{s}")),
            e2::kid(&format!("i545-u3-{s}")),
        );
        let n: Vec<String> = (1..=8)
            .map(|i| e2::kid(&format!("i545-n{i}-{s}")))
            .collect();
        let agent = e2::kid(&format!("i545-agent-{s}"));
        rab::users(d, &[&u1, &u2, &u3]).await;
        rab::nodes(d, &n.iter().map(String::as_str).collect::<Vec<_>>()).await;
        ts::register_hybrid_key_as(d, &agent, &agent, AGENT).await;
        // u1 claims n1 and n2 (occurrence + owner binding each).
        rab::claim(d, &u1, &n[0], "laptop").await;
        rab::claim(d, &u1, &n[1], "server").await;
        // u1 binds n3, then recants it.
        let b3 = owner_binding(&u1, &n[2]);
        put(d, b3.clone()).await.expect("u1 → n3");
        put(d, composer(&u1, &n[2], attestation_type::RECANTS, &b3))
            .await
            .expect("u1 recants n3");
        // u1's plain delegation to n4 naming n4; n4 withdraws it (a subject
        // may withdraw a row naming it — u1 retracted nothing). Plain, because
        // a node withdrawing its OWNER binding is a reclaim, refused at the
        // door without a deployment policy.
        let mut b4 = plain_delegation(&u1, &n[3]);
        b4.subject_key_ids = vec![n[3].clone()];
        ts::reseal(&mut b4);
        put(d, b4.clone()).await.expect("u1 → n4, naming n4");
        put(d, composer(&n[3], &n[3], attestation_type::WITHDRAWS, &b4))
            .await
            .expect("n4 withdraws u1's binding");
        // u1 binds n5, then withdraws it.
        let b5 = owner_binding(&u1, &n[4]);
        put(d, b5.clone()).await.expect("u1 → n5");
        put(d, composer(&u1, &n[4], attestation_type::WITHDRAWS, &b5))
            .await
            .expect("u1 withdraws n5");
        // u1 binds n6, then supersedes that binding (whatever the fold makes
        // of a superseded edge, both bodies must make the same of it).
        let b6 = owner_binding(&u1, &n[5]);
        put(d, b6.clone()).await.expect("u1 → n6");
        put(d, composer(&u1, &n[5], attestation_type::SUPERSEDES, &b6))
            .await
            .expect("u1 supersedes n6's binding");
        // u1's plain (unmarked) delegation to n7: a node has no agency, so it
        // is a steward binding but not an ownership.
        put(d, plain_delegation(&u1, &n[6]))
            .await
            .expect("u1 → n7 (plain)");
        // u1 confers to an agent (unmarked: a conferral, not custody).
        put(d, conferral(&u1, &agent)).await.expect("u1 → agent");
        // u2 claims n8.
        rab::claim(d, &u2, &n[7], "phone").await;
        // u1's unrelated history: self-reports and consent grants.
        for i in 0..12 {
            put(d, self_report(&u1, &format!("i545-{i}")))
                .await
                .expect("u1 self-report");
            rab::put(d, &rab::grant(&u1, Some(&n[0]), None))
                .await
                .expect("u1 grant");
        }
        // u3 owns nothing and has only noise.
        for i in 0..4 {
            put(d, self_report(&u3, &format!("i545-u3-{i}")))
                .await
                .expect("u3 self-report");
        }
        // u1's `delegates_to` edges: two claims, n3..n7, the agent.
        let u1_edges = 2 + 5 + 1;

        let _ = read_probe::take();
        for k in [&u1, &u2, &u3, &n[0], &agent] {
            let got = admission::nodes_stewarded_by(d, k).await.unwrap();
            let log = read_probe::take();
            let want = nodes_stewarded_by_reference(d, k).await.unwrap();
            let ref_log = read_probe::take();
            assert_eq!(got, want, "I545 nodes_stewarded_by({k})");
            assert_eq!(
                calls_of(&log, "list_attestations_by", k),
                0,
                "I545 nodes_stewarded_by({k}): the steward's history is not read: {log:?}"
            );
            assert_eq!(
                calls_of(&ref_log, "list_attestations_by", k),
                1,
                "I545: the v53.1.5 body reads the steward's history (the red): {ref_log:?}"
            );

            let got = crate::federation::self_collective::nodes_of(d, k)
                .await
                .unwrap();
            let log = read_probe::take();
            let want = nodes_owned_by_reference(d, k).await.unwrap();
            let ref_log = read_probe::take();
            assert_eq!(got, want, "I545 nodes_of({k})");
            assert_eq!(
                calls_of(&log, "list_attestations_by", k),
                0,
                "I545 nodes_of({k}): the person's history is not read: {log:?}"
            );
            assert_eq!(
                calls_of(&ref_log, "list_attestations_by", k),
                1,
                "I545: the v53.1.5 body reads the person's history (the red): {ref_log:?}"
            );
            if *k == u1 {
                assert_eq!(
                    rows_of(&log, "list_attestations_by_type", k),
                    u1_edges,
                    "I545: the type seek returns u1's delegates_to edges only: {log:?}"
                );
                assert!(
                    rows_of(&ref_log, "list_attestations_by", k) > 3 * u1_edges,
                    "I545: u1's history dwarfs its edges: {ref_log:?}"
                );
            }
        }
        // Literals: u1 owns n1, n2 (and n6 unless the fold retires a
        // superseded binding — pinned by the reference above, not here);
        // u1 stewards itself, its owned nodes and the plain-delegation n7.
        let owned = crate::federation::self_collective::nodes_of(d, &u1)
            .await
            .unwrap();
        for live in [&n[0], &n[1]] {
            assert!(owned.contains(live), "I545: u1 owns {live}: {owned:?}");
        }
        for dead in [&n[2], &n[3], &n[4], &n[6], &n[7]] {
            assert!(
                !owned.contains(dead),
                "I545: u1 does not own {dead}: {owned:?}"
            );
        }
        let stewarded = admission::nodes_stewarded_by(d, &u1).await.unwrap();
        for live in [&u1, &n[0], &n[1], &n[6]] {
            assert!(
                stewarded.contains(live),
                "I545: u1 stewards {live}: {stewarded:?}"
            );
        }
        for dead in [&n[2], &n[3], &n[4], &n[7], &agent] {
            assert!(
                !stewarded.contains(dead),
                "I545: u1 does not steward {dead}: {stewarded:?}"
            );
        }
        assert_eq!(
            crate::federation::self_collective::nodes_of(d, &u2)
                .await
                .unwrap(),
            vec![n[7].clone()]
        );
    }
    // ── I546 ─────────────────────────────────────────────────────────────

    /// `trust_root::live_conferrals` as v53.1.6 shipped it.
    pub async fn live_conferrals_reference<'a>(
        directory: &dyn FederationDirectory,
        shaped: Vec<&'a Attestation>,
    ) -> Result<Vec<&'a Attestation>, Error> {
        let mut live = Vec::with_capacity(shaped.len());
        for row in shaped {
            if row.attestation_type == attestation_type::SUPERSEDES
                && !crate::federation::trust_root::rotates_own_grant(directory, row).await?
            {
                continue;
            }
            let superseded = directory
                .list_attestations_referencing(&row.attestation_id)
                .await?
                .iter()
                .any(|r| {
                    r.attestation_type == attestation_type::SUPERSEDES
                        && r.attesting_key_id == row.attesting_key_id
                        && r.attestation_id != row.attestation_id
                });
            if !superseded {
                live.push(row);
            }
        }
        Ok(live)
    }

    /// **I546** — `live_conferrals` (the Rooted floor's per-conferral
    /// `list_attestations_referencing`, CIRISEdge PR #818) equals its v53.1.6
    /// body over a root's grant rotated twice, a foreign `supersedes`, a
    /// second grant withdrawn, and a table full of unrelated rows and
    /// composers naming OTHER rows; and each referencing read returns exactly
    /// the composers naming that row — the seek, never a slice. (The scan
    /// itself is invisible to a row probe; I546's sqlite plan check pins it.)
    pub async fn i546_live_conferrals_read_each_rows_composers(
        d: &dyn FederationDirectory,
        s: &str,
    ) {
        use crate::federation::attestation_query::test_support::AllAttestations as _;
        use crate::federation::grant_supersede_invariants::bodies as gs;
        use crate::federation::trust_root::{
            capability_roots_to_trusted_root, live_conferrals, INFRA_ATTEST_SCOPE,
            INFRA_SERVE_SCOPE,
        };
        // v62.0.0 (JSON cut, E7; E4) — `gs::fixture` is E9's edition-2 root:
        // the user is THIS node, the root and subject identity-refs, the grant
        // a rid; `supersede` / `withdraw` return the composer's rid.
        let fx = gs::fixture(d, &format!("i546-{s}")).await;
        let succ = gs::supersede(
            d,
            &format!("i546-succ-{s}"),
            &fx.root,
            &fx.subject,
            &fx.grant,
            INFRA_SERVE_SCOPE,
        )
        .await
        .expect("the root rotates its grant");
        let succ2 = gs::supersede(
            d,
            &format!("i546-succ2-{s}"),
            &fx.root,
            &fx.subject,
            &succ,
            INFRA_SERVE_SCOPE,
        )
        .await
        .expect("the root rotates it again");
        let foreign = format!("i546-foreign-{s}");
        ts::register_hybrid_key_as(d, &foreign, &foreign, NODE).await;
        // The door may or may not admit it; either way both bodies must agree.
        let _ = gs::supersede(
            d,
            &format!("i546-fsucc-{s}"),
            &foreign,
            &fx.subject,
            &fx.grant,
            INFRA_ATTEST_SCOPE,
        )
        .await;
        let fx2 = gs::fixture(d, &format!("i546b-{s}")).await;
        let _ = gs::withdraw(
            d,
            &format!("i546-w-{s}"),
            &fx2.root,
            &fx2.subject,
            &fx2.grant,
        )
        .await;
        // Unrelated rows: self-reports by the root, the subject and a bystander,
        // and the bystander's composers over its own reports.
        let bystander = format!("i546-bystander-{s}");
        ts::register_hybrid_key_as(d, &bystander, &bystander, NODE).await;
        for k in [&fx.root, &fx.subject, &bystander] {
            for i in 0..8 {
                put(d, self_report(k, &format!("i546-{i}")))
                    .await
                    .expect("noise");
            }
        }
        for i in 0..6 {
            let r = self_report(&bystander, &format!("i546-retired-{i}"));
            put(d, r.clone()).await.expect("bystander report");
            put(
                d,
                composer(&bystander, &bystander, attestation_type::RECANTS, &r),
            )
            .await
            .expect("bystander recants");
        }

        for f in [&fx, &fx2] {
            let rows = d.all_attestations_for(&f.subject).await.unwrap();
            let shaped: Vec<&Attestation> = rows
                .iter()
                .filter(|r| {
                    r.attestation_type == attestation_type::DELEGATES_TO
                        || r.attestation_type == attestation_type::SUPERSEDES
                })
                .collect();
            assert!(!shaped.is_empty(), "I546: conferral-shaped rows exist");
            let _ = read_probe::take();
            let got: Vec<String> = live_conferrals(d, shaped.clone())
                .await
                .unwrap()
                .iter()
                .map(|r| r.attestation_id.clone())
                .collect();
            let log = read_probe::take();
            let want: Vec<String> = live_conferrals_reference(d, shaped.clone())
                .await
                .unwrap()
                .iter()
                .map(|r| r.attestation_id.clone())
                .collect();
            let _ = read_probe::take();
            assert_eq!(got, want, "I546 live_conferrals for {}", f.subject);
            // Each referencing read returns exactly the composers naming its
            // row (every composer here is attested to the subject, so the
            // subject's slice holds them all); no read is keyed wider.
            for r in &shaped {
                if calls_of(&log, "list_attestations_referencing", &r.attestation_id) == 0 {
                    continue;
                }
                let naming = rows
                    .iter()
                    .filter(|c| {
                        crate::federation::precedence::is_structural_composer(&c.attestation_type)
                            && crate::federation::precedence::references_attestation_id_from_envelope(
                                &c.attestation_envelope,
                            ) == Some(r.attestation_id.as_str())
                    })
                    .count();
                assert_eq!(
                    rows_of(&log, "list_attestations_referencing", &r.attestation_id),
                    naming,
                    "I546: the referencing read of {} returns the composers naming it: {log:?}",
                    r.attestation_id
                );
            }
            for m in [
                "list_attestations_for",
                "list_attestations_by",
                "list_attestations",
            ] {
                assert!(
                    !log.iter().any(|r| r.door() == m),
                    "I546: live_conferrals reads no slice ({m}): {log:?}"
                );
            }
        }
        assert_eq!(
            capability_roots_to_trusted_root(
                d,
                &fx.user,
                &fx.subject,
                INFRA_SERVE_SCOPE,
                crate::host::clock::now()
            )
            .await
            .unwrap()
            .map(|g| g.grant_attestation_id),
            Some(succ2.clone()),
            "I546: the head of the rotation confers"
        );
        assert_eq!(
            capability_roots_to_trusted_root(
                d,
                &fx2.user,
                &fx2.subject,
                INFRA_SERVE_SCOPE,
                crate::host::clock::now()
            )
            .await
            .unwrap(),
            None,
            "I546: the withdrawn grant confers nothing"
        );
    }
    // ── I547 ─────────────────────────────────────────────────────────────

    /// Calls of either whole-slice read, any key.
    fn slice_reads(log: &[read_probe::Read]) -> usize {
        log.iter()
            .filter(|r| r.is_slice_read() && r.is_first_page())
            .count()
    }

    /// **I547** — the trust-root walks (`trusted_roots_of`, `trust_root_valid`,
    /// `capability_roots_to_trusted_root_over_roster`, `transit_eligibility_walk`,
    /// `owner_granted_scope`) and `canonical_community::live_charter_rows`
    /// equal their verbatim v53.1.6 bodies over a family (accord) root with a
    /// transit pair and ten bystanders' trust edges naming it, a key root
    /// whose grant is rotated twice, a key root whose grant is withdrawn, a key
    /// root that withdraws its own charter, a user's trust edges live,
    /// withdrawn, recanted and expired, and unrelated self-reports under every
    /// key; and no walk reads any key's whole slice (`list_attestations_by` /
    /// `_for`), while the v53.1.6 bodies do.
    pub async fn i547_trust_root_walks_read_what_they_select(d: &dyn FederationDirectory, s: &str) {
        use crate::federation::canonical_community::{
            live_charter_rows, v53_1_6_reference::live_charter_rows_reference,
        };
        use crate::federation::edition2::fixture_switch as e2;
        use crate::federation::operational::test_support as ot;
        use crate::federation::trust_root::{
            self as tr, v53_1_6_reference as r, INFRA_ATTEST_SCOPE, INFRA_SERVE_SCOPE,
        };
        // v62.0.0 (JSON cut, E7) — the roots are edition 2: E9's twins
        // (`seed_chartered_e2_root`: founded by the bundle's holders, chartered,
        // accepted by a granter; `confer_e2`; `accept_e2_root`; `withdraw_e2`).
        // Users and subjects are `user` keys named by identity-refs. The
        // earlier corpus (the accord families with co-scrubbed charters, the
        // heartbeat drill, `grant_supersede_invariants::fixture`'s rotations)
        // does not come back; the property is unchanged: every bounded walk
        // equals its v53.1.6 body, and none reads a whole slice.
        let key = |n: &str| format!("i547-{n}-{s}");
        let (u1, u2, u3) = (
            e2::put_key(d, &key("u1"), &[USER]).await,
            e2::put_key(d, &key("u2"), &[USER]).await,
            e2::put_key(d, &key("u3"), &[USER]).await,
        );
        let (s1_seed, s2_seed) = (key("s1"), key("s2"));
        let s1 = e2::put_key(d, &s1_seed, &[USER]).await;
        let s2 = e2::put_key(d, &s2_seed, &[USER]).await;
        // ra: chartered, accepted by u1, its grant to s1 live.
        let ra = ot::seed_chartered_e2_root(d, &key("ra"), &u1)
            .await
            .expect("root a");
        let g1 = ot::confer_e2(d, &ra.seed, &s1_seed, &[INFRA_SERVE_SCOPE])
            .await
            .expect("ra confers on s1");
        // rb: chartered, accepted by u2 (and u1), its grant to s2 withdrawn.
        let rb = ot::seed_chartered_e2_root(d, &key("rb"), &u2)
            .await
            .expect("root b");
        ot::accept_e2_root(d, &u1, &rb.root)
            .await
            .expect("u1 accepts rb");
        let g2 = ot::confer_e2(d, &rb.seed, &s2_seed, &[INFRA_SERVE_SCOPE])
            .await
            .expect("rb confers on s2");
        ot::withdraw_e2(d, &rb.seed, &s2, &g2)
            .await
            .expect("rb withdraws its grant");
        // rc: chartered, accepted by u3, then its root withdraws its charter.
        let rc = ot::seed_chartered_e2_root(d, &key("rc"), &u3)
            .await
            .expect("root c");
        ot::withdraw_e2(d, &rc.seed, &rc.root, &rc.charter)
            .await
            .expect("rc withdraws its charter");
        // u1's own edges: to rc, accepted then withdrawn.
        let e_w = ot::accept_e2_root(d, &u1, &rc.root)
            .await
            .expect("u1 accepts rc");
        ot::withdraw_e2(d, &u1, &rc.root, &e_w)
            .await
            .expect("u1 withdraws it");
        // Ten bystanders accept ra and rb: rows ABOUT a root no charter read
        // needs.
        for i in 0..10 {
            let b = e2::put_key(d, &key(&format!("by{i}")), &[USER]).await;
            for root in [&ra.root, &rb.root] {
                ot::accept_e2_root(d, &b, root)
                    .await
                    .expect("a bystander's acceptance");
            }
        }
        // Unrelated history under every key.
        for k in [&u1, &u2, &s1, &ra.root] {
            for i in 0..6 {
                put(d, self_report(k, &format!("i547-{i}")))
                    .await
                    .expect("noise");
            }
        }
        let (fx_user, fx_subject) = (&u1, &s1);
        let users = [&u1, &u2, &u3, &s1];
        let roots = [&ra.root, &rb.root, &rc.root, &u1];
        let roster = admission::accord_holder_roster(d).await.expect("roster");
        let now = chrono::Utc::now();
        let _ = read_probe::take();
        macro_rules! same {
            ($label:expr, $got:expr, $want:expr) => {{
                let got = $got;
                let log = read_probe::take();
                let want = $want;
                let ref_log = read_probe::take();
                assert_eq!(got, want, "I547 {}", $label);
                assert_eq!(
                    slice_reads(&log),
                    0,
                    "I547 {}: no whole-slice read: {log:?}",
                    $label
                );
                ref_log
            }};
        }
        let mut reference_slice_reads = 0;
        for k in users.into_iter().chain([&s2]) {
            let l = same!(
                format!("trusted_roots_of({k})"),
                tr::trusted_roots_of(d, k, now).await.unwrap(),
                r::trusted_roots_of_reference(d, k, now).await.unwrap()
            );
            reference_slice_reads += slice_reads(&l);
        }
        for u in users {
            for root in roots {
                let l = same!(
                    format!("trust_root_valid({u}, {root})"),
                    tr::trust_root_valid(d, u, root, crate::host::clock::now())
                        .await
                        .unwrap(),
                    r::trust_root_valid_reference(d, u, root).await.unwrap()
                );
                reference_slice_reads += slice_reads(&l);
            }
        }
        for (u, subj) in [(&u1, &s1), (&u2, &s2), (&u3, &s1), (&u1, &s2)] {
            for scope in [INFRA_SERVE_SCOPE, INFRA_ATTEST_SCOPE] {
                let l = same!(
                    format!("capability_roots({u}, {subj}, {scope})"),
                    tr::capability_roots_to_trusted_root_over_roster(
                        d,
                        u,
                        subj,
                        scope,
                        &roster,
                        crate::host::clock::now()
                    )
                    .await
                    .unwrap(),
                    r::capability_roots_to_trusted_root_over_roster_reference(
                        d, u, subj, scope, &roster
                    )
                    .await
                    .unwrap()
                );
                reference_slice_reads += slice_reads(&l);
            }
        }
        for (u, p) in [(&u1, &u2), (&u2, &u1), (&u1, &s1), (&u3, &u1)] {
            let l = same!(
                format!("transit_eligibility_walk({u}, {p})"),
                tr::transit_eligibility_walk(d, u, p).await.unwrap(),
                r::transit_eligibility_walk_reference(d, u, p)
                    .await
                    .unwrap()
            );
            reference_slice_reads += slice_reads(&l);
        }
        for (subj, granter) in [
            (&s1, &ra.root),
            (&s2, &rb.root),
            (&s1, &rb.root),
            (&u2, &u1),
        ] {
            for scope in [INFRA_SERVE_SCOPE, INFRA_ATTEST_SCOPE] {
                let l = same!(
                    format!("owner_granted_scope({subj}, {granter}, {scope})"),
                    tr::owner_granted_scope(d, subj, granter, scope)
                        .await
                        .unwrap(),
                    r::owner_granted_scope_reference(d, subj, granter, scope)
                        .await
                        .unwrap()
                );
                reference_slice_reads += slice_reads(&l);
            }
        }
        for fam in [&ra.root, &rb.root, &rc.root] {
            let ids =
                |v: Vec<Attestation>| v.into_iter().map(|a| a.attestation_id).collect::<Vec<_>>();
            let l = same!(
                format!("live_charter_rows({fam})"),
                ids(live_charter_rows(d, fam).await.unwrap()),
                ids(live_charter_rows_reference(d, fam).await.unwrap())
            );
            reference_slice_reads += slice_reads(&l);
        }
        assert!(
            reference_slice_reads > 0,
            "I547: the v53.1.6 bodies read whole slices (the red)"
        );
        // The root's about-read returns its charters, never the bystanders'
        // acceptance edges naming it.
        for fam in [&ra.root, &rb.root] {
            let _ = tr::trust_root_valid(d, &u1, fam, crate::host::clock::now())
                .await
                .unwrap();
            let log = read_probe::take();
            // v62.0.0 (round 6, E7) — the charter legs are read by the
            // root's OWN rows (`AttestationQuery::by(root)` excluding every
            // job but `trust:charter:v1`, door `list_attestations_by_types`),
            // and only a family arm also reads its about-slice
            // (`list_attestations_for_types`, the same exclusion). Either
            // way only charters come back: never a bystander's acceptance.
            let typed = rows_of(&log, "list_attestations_for_types", fam)
                + rows_of(&log, "list_attestations_by_types", fam);
            assert!(
                (1..=2).contains(&typed),
                "I547: {fam}'s typed read returns its charters only ({typed} rows): {log:?}"
            );
        }
        // Literals: ra's grant confers; rb's withdrawn grant and rc's withdrawn
        // charter confer nothing; u1 holds ra.
        assert_eq!(
            tr::capability_roots_to_trusted_root_over_roster(
                d,
                fx_user,
                fx_subject,
                INFRA_SERVE_SCOPE,
                &roster,
                crate::host::clock::now()
            )
            .await
            .unwrap()
            .map(|g| g.grant_attestation_id),
            Some(g1.hex())
        );
        assert!(tr::capability_roots_to_trusted_root_over_roster(
            d,
            &u2,
            &s2,
            INFRA_SERVE_SCOPE,
            &roster,
            crate::host::clock::now()
        )
        .await
        .unwrap()
        .is_none());
        assert!(
            tr::trust_root_valid(d, &u1, &ra.root, crate::host::clock::now())
                .await
                .unwrap()
                .valid
        );
        assert!(
            !tr::trust_root_valid(d, &u3, &rc.root, crate::host::clock::now())
                .await
                .unwrap()
                .valid
        );
        assert!(
            live_charter_rows(d, &rc.root).await.unwrap().is_empty(),
            "I547: rc's withdrawn charter is no live charter"
        );
    }
}

#[cfg(all(test, any(feature = "sqlite", feature = "postgres")))]
mod runners {
    fn suffix() -> String {
        uuid::Uuid::new_v4().simple().to_string()[..12].to_owned()
    }

    macro_rules! runners {
        ($modname:ident, $fresh:expr, [$($sql_only:ident => $sql_body:ident),*]) => {
            mod $modname {
                use super::suffix;
                use crate::federation::FederationDirectory;
                // v62.0.0 (JSON cut, E7) — FLIPPED bodies: no earlier-form wrap.
                macro_rules! flipped {
                    ($name:ident, $body:ident) => {
                        #[tokio::test]
                        async fn $name() {
                            let Some(d) = $fresh.await else { return };
                            let s = suffix();
                            // v62.0.0 (JSON cut, E7) — this node's key, set
                            // first (the edition-2 trust-root fixtures read it).
                            let node = crate::federation::edition2::fixture_switch::put_key(
                                &d,
                                &format!("br-node-{s}"),
                                &[crate::federation::types::identity_type::NODE],
                            )
                            .await;
                            d.set_node_key_id(node);
                            super::super::bodies::$body(&d as &dyn FederationDirectory, &s).await
                        }
                    };
                }
                flipped!(i540, i540_send_set_reads_each_owners_lists_once);
                flipped!(i542, i542_live_granters_read_the_subjects_edges);
                flipped!(i543, i543_the_config_renewal_check_reads_the_leaf);
                flipped!(i544, i544_custody_acks_read_the_devices_reports_of_the_blob);
                flipped!(i545, i545_nodes_of_reads_the_stewards_delegations);
                flipped!(i546, i546_live_conferrals_read_each_rows_composers);
                flipped!(i547, i547_trust_root_walks_read_what_they_select);
                $(flipped!($sql_only, $sql_body);)*
            }
        };
    }

    #[cfg(feature = "sqlite")]
    runners!(
        sqlite,
        async {
            use crate::store::Backend as _;
            let b = crate::store::sqlite::SqliteBackend::open_in_memory()
                .await
                .unwrap();
            b.run_migrations().await.unwrap();
            Some(b)
        },
        [i541 => i541_live_invitees_read_the_groups_proposals]
    );

    #[cfg(feature = "postgres")]
    runners!(
        postgres,
        async {
            use crate::store::Backend as _;
            let dsn = crate::test_pg::empty_dsn()?;
            let b = crate::store::postgres::PostgresBackend::connect(&dsn)
                .await
                .unwrap();
            b.run_migrations().await.unwrap();
            Some(b)
        },
        [i541 => i541_live_invitees_read_the_groups_proposals]
    );
}
