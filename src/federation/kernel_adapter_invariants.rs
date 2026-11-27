//! v62.0.0 (slice C, the kernel adapter) — **I1840–I1843: the switched doors,
//! and the fork the next slice switches, on every backend.** Each body runs on sqlite and on postgres.
//!
//! - **I1840** — `owner_of` answers through the kernel's owner seat. CC 3.2,
//!   *The first binding (MUST)*: "an owner-binding counts toward ownership
//!   only when the node's own key cosigned it". A binding whose node
//!   co-scrub is stripped (the co-scrubs ride outside the preimage, so the
//!   owner's base scrub still verifies) is held and names no owner; the same
//!   binding with the node's co-scrub names its owner; the owner's own
//!   `withdraws` ends the seat.
//! - **I1841** — the delegation cycle gate refuses nothing (CC 4.4.3.34:
//!   "Cycles are visited once"): `a → b`, `b → a`
//!   both land, and the walk reads the cycle once (`build_delegation_graph`
//!   expands each granter once).
//! - **I1842** — `trust_root_valid`'s edge leg is the kernel's one-hop walk:
//!   the user's acceptance edge makes `edge_exists`, and the user's own
//!   `withdraws` of it (the CC 3.5.1 fold default: one signer's chain) ends
//!   it.
//! - **I1845** — a member's leaving in the counted row's past is not counted
//!   (a `unanimous` widening after a removal needs only those remaining).
//! - **I1846** — a reference cycle (two rows naming each other's peer-chosen
//!   id) never hangs the trust walk and gives no edge.
//! - **I1843** — a fork of a held head (two versions naming one head): the
//!   kernel holds it as a tip (CC 2.7.8). v62.0.0 (kernel pass 2, K1):
//!   switched — persist holds it too, and the head does not move.

#[cfg(all(test, any(feature = "sqlite", feature = "postgres")))]
pub(crate) mod bodies {
    use crate::federation::admission::owner_of;
    use crate::federation::edition2::fixture_switch as e2;
    use crate::federation::edition2::ingest::StatementOutcome;
    use crate::federation::tier_ingest::test_support as ts;
    use crate::federation::types::{attestation_type, identity_type};
    use crate::federation::FederationDirectory;

    /// v62 (E4): `seed`'s `withdraws` of the held row `target_id`, as its
    /// edition-2 composer (`refs.target`, the target's family).
    async fn withdraw(d: &dyn FederationDirectory, seed: &str, target_id: &str) {
        let target = d
            .get_attestation(target_id)
            .await
            .unwrap()
            .unwrap_or_else(|| panic!("the target {target_id} is held"));
        e2::put_signed(
            d,
            &e2::composer_of(attestation_type::WITHDRAWS, &target, seed),
        )
        .await
        .unwrap_or_else(|e| panic!("{seed} withdraws {target_id}: {e}"));
    }

    /// **I1840** — see the module doc.
    pub(crate) async fn i1840_an_owner_binding_counts_with_the_nodes_cosignature(
        d: &dyn FederationDirectory,
        s: &str,
    ) {
        let (owner_s, bare_s, cosigned_s) = (
            format!("i1840-owner-{s}"),
            format!("i1840-bare-{s}"),
            format!("i1840-cosigned-{s}"),
        );
        // v62 (E4): edition-2 keys, named by identity-ref.
        let owner = e2::put_key(d, &owner_s, &[identity_type::USER]).await;
        let bare = e2::put_key(d, &bare_s, &[identity_type::NODE]).await;
        let cosigned = e2::put_key(d, &cosigned_s, &[identity_type::NODE]).await;
        // The node never cosigned: the owner's statement alone (the node's
        // cosignature is a second voice of the same row, CC 3.2 / RULINGS
        // "owner binding ... with the node's own statement as the second
        // voice"; here it is never offered).
        let row =
            ts::owner_binding_attestation(&uuid::Uuid::new_v4().to_string(), &owner_s, &bare_s);
        e2::put_signed(d, &row)
            .await
            .expect("I1840: an uncosigned owner binding is a well-formed, held row");
        assert_eq!(
            owner_of(d, &bare).await.expect("owner_of"),
            None,
            "I1840: CC 3.2 — a binding the node never cosigned names no owner"
        );
        // The node cosigned: its voice over the same statement, after the row.
        let row =
            ts::owner_binding_attestation(&uuid::Uuid::new_v4().to_string(), &owner_s, &cosigned_s);
        let id = e2::rid(&row);
        // v62 (E4 round 3; K2, C557): the binding is counted: the owner's
        // statement waits, and the node's voice completes it (`Row`).
        let out = e2::land_owner_binding(d, &row, &cosigned_s)
            .await
            .expect("I1840: the node's voice lands");
        assert!(
            matches!(out, StatementOutcome::Row { .. }),
            "I1840: the node's cosignature completes the held binding: {out:?}"
        );
        assert!(
            d.get_attestation(&id).await.unwrap().is_some(),
            "I1840: held"
        );
        assert_eq!(
            owner_of(d, &cosigned).await.expect("owner_of"),
            Some(owner.clone()),
            "I1840: the cosigned binding names its owner"
        );
        // The owner's own withdraws ends the seat.
        withdraw(d, &owner_s, &id).await;
        assert_eq!(
            owner_of(d, &cosigned).await.expect("owner_of"),
            None,
            "I1840: the owner's withdrawal ends the seat"
        );
    }

    /// **I1841** — see the module doc.
    pub(crate) async fn i1841_no_edge_is_refused_for_closing_a_cycle(
        d: &dyn FederationDirectory,
        s: &str,
    ) {
        let (a, b) = (format!("i1841-a-{s}"), format!("i1841-b-{s}"));
        for k in [&a, &b] {
            e2::put_key(d, k, &[identity_type::AGENT]).await;
        }
        ts::put_delegates_to(d, &a, &b, None)
            .await
            .expect("I1841: a → b");
        ts::put_delegates_to(d, &b, &a, None)
            .await
            .expect("I1841: b → a closes a cycle and is admitted (v62)");
        let g = crate::federation::build_delegation_graph(d, &e2::kid(&a), Some(8))
            .await
            .expect("I1841: the walk");
        assert_eq!(g.edges.len(), 2, "I1841: both edges, each read once");
    }

    /// **I1842** — see the module doc.
    pub(crate) async fn i1842_the_edge_leg_is_the_kernels_one_hop_walk(
        d: &dyn FederationDirectory,
        s: &str,
    ) {
        use crate::federation::accord_test_support as ops;
        use crate::federation::trust_root::trust_root_valid;
        let user = format!("i1842-user-{s}");
        e2::put_key(d, &user, &[identity_type::NODE]).await;
        // RT-fix1 — PORTED to an edition-2 trust root (E9's twins, as E5 ported
        // `trust_root_walk_and_tombstone_481`). The earlier-form
        // `establish_trust_root` puts JSON key records and a hand-chartered
        // KEY root: its door is shut (`earlier_form_object`), and a key-arm
        // root is never valid under edition 2 (its holder's custody evidence,
        // CC 4.2.2.1). The root is founded by the bundle's holders and
        // chartered (`stand_up_e2_root`); the user's own `trust:accepts` edge
        // is the edge leg this witness reads. The subject and its conferral
        // were never read here.
        // v62.0.0 (R2-fixture; CC 3.2 T5) — the root is the bundle's LINEAGE
        // (the bundle in force, its `charter`); the user's edge is its
        // acceptance of the lineage.
        ops::ensure_e2_genesis(d)
            .await
            .expect("I1842: the bundle in force");
        ops::accept_lineage_e2(d, &user)
            .await
            .expect("I1842: the user's acceptance edge");
        // v62 (E4): the store names each key by its identity-ref.
        let (user_s, user, root) = (
            user.clone(),
            e2::kid(&user),
            crate::federation::edition2::fixture_genesis::FAMILY_KEY_ID.to_owned(),
        );
        let v = trust_root_valid(d, &user, &root, crate::host::clock::now())
            .await
            .expect("verdict");
        assert!(v.edge_exists, "I1842: the user's acceptance edge is live");
        assert!(v.valid, "I1842: a valid root: {v:?}");
        let edge = d
            .list_attestations_by(&user)
            .await
            .expect("by user")
            .into_iter()
            .find(|r| {
                r.attestation_type == attestation_type::DELEGATES_TO && r.attested_key_id == root
            })
            .expect("I1842: the user's edge to the root");
        withdraw(d, &user_s, &edge.attestation_id).await;
        let v = trust_root_valid(d, &user, &root, crate::host::clock::now())
            .await
            .expect("verdict");
        assert!(
            !v.edge_exists,
            "I1842: the user's own withdraws ends the edge"
        );
        assert!(!v.valid, "I1842: no edge, no valid root");
    }

    /// **I1843** — a FORK of a held head: two versions naming one head. The
    /// family's v1 is held; v2 naming v1 is admitted (the head moves); a
    /// sibling v2' naming v1 too is the fork. v62 (E4, flip wave 2): the
    /// versions are `group:roster` statements (T1), and the door holds the
    /// fork as a K1 tip (CC 2.7.8: "Two versions of one head wait as tips")
    /// rather than refusing it; the kernel reads it as a tip too.
    pub(crate) async fn i1843_a_fork_of_the_held_head_is_a_tip_to_the_kernel(
        d: &dyn FederationDirectory,
        s: &str,
    ) {
        use crate::federation::edition2::ingest::StatementOutcome;
        use crate::federation::types::{Family, FamilyMember};
        use crate::kernel::head::{head_reading, HeadReading};
        let holders: Vec<String> = (0..3).map(|i| format!("i1843-h{i}-{s}")).collect();
        for h in &holders {
            e2::put_key(d, h, &[identity_type::NODE]).await;
        }
        let fam_s = format!("i1843-fam-{s}");
        let fam = e2::kid(&fam_s);
        // Node-signed rows stay now-relative (CC 2.4.1.1).
        let now =
            crate::federation::admission::truncate_to_substrate_resolution(chrono::Utc::now());
        let now_ms = u64::try_from(now.timestamp_millis()).expect("after the epoch");
        let family = |name: &str| Family {
            prev_head_digest: String::new(),
            charter_digest: String::new(),
            family_key_id: fam_s.clone(),
            family_name: name.into(),
            members: holders
                .iter()
                .enumerate()
                .map(|(i, k)| FamilyMember {
                    key_id: k.clone(),
                    joined_at: now,
                    role: (i == 0).then(|| "founder".to_owned()),
                })
                .collect(),
            founded_at: now,
            consensus_protocol: "quorum:2/3".to_owned(),
            consensus_protocol_entrenched: false,
            dissolved_at: None,
            persist_row_hash: String::new(),
        };
        e2::put_voices(
            d,
            &e2::family_voices(&ts::sign_family(&holders[0], family("v1")), 1, None, now_ms),
        )
        .await
        .expect("I1843: v1");
        // GID-fixtures-sites — the room's DERIVED id, once founded (`room_id`
        // panics if it was not).
        let fam = crate::federation::edition2::fixture_switch::room_id(&fam);
        let v1 = d.lookup_family(&fam).await.unwrap().expect("held");
        let (h1, _) = e2::held_head(d, &fam)
            .await
            .expect("I1843: v1 is the held head");
        e2::put_voices(
            d,
            &e2::family_voices(
                &ts::sign_family(&holders[0], family("v2")),
                2,
                Some(&h1),
                now_ms,
            ),
        )
        .await
        .expect("I1843: v2 names the held head");
        let held = d.lookup_family(&fam).await.unwrap().expect("held");
        let fork = e2::put_voices(
            d,
            &e2::family_voices(
                &ts::sign_family(&holders[0], family("v3")),
                2,
                Some(&h1),
                now_ms,
            ),
        )
        .await
        .expect("I1843: the fork is held as a tip, not refused");
        assert!(
            matches!(fork, StatementOutcome::Row { .. }),
            "I1843: the door holds the sibling version as a K1 tip: {fork:?}"
        );
        assert_eq!(
            head_reading(
                &fam,
                Some(&held.persist_row_hash),
                &v1.persist_row_hash,
                &e2::kid(&holders[0])
            ),
            HeadReading::Tip,
            "I1843: the kernel holds v3 as a tip beside v2 (CC 2.7.8)"
        );
    }

    /// **I1845** — the count reads the members at the change, less those whose
    /// own leaving is in its past (`seat::seat_rule`'s `left_in_past`; the
    /// kernel review's counterexample). A `unanimous` family of ann, ben and
    /// cat; cat leaves (removed by ann and ben, every other member); then a
    /// widening of dan signed by ann and ben is admitted. A count over the
    /// roster of the version before cat left would read 2 of 3 and refuse.
    /// v62 (E4, flip wave 2): the roster, the removal and the widening are
    /// edition-2 statements (T1); dan's proposal and acceptance are held as
    /// edition-2 rows first (the #955 growth gate). The fixed 2026 instants
    /// are signed by `user` keys only (no record end).
    pub(crate) async fn i1845_a_leaving_in_the_rows_past_is_not_counted(
        d: &dyn FederationDirectory,
        s: &str,
    ) {
        use crate::federation::membership_acceptance::test_support::{
            acceptance_row, proposal_row,
        };
        use crate::federation::types::{
            cohort_scope, Family, FamilyMember, FamilyMembershipRevocation,
            FamilyMembershipWidening,
        };
        let at = |t: &str| -> chrono::DateTime<chrono::Utc> { t.parse().expect("instant") };
        let ms =
            |t: chrono::DateTime<chrono::Utc>| u64::try_from(t.timestamp_millis()).expect("ms");
        let [ann, ben, cat, dan] = ["ann", "ben", "cat", "dan"].map(|n| format!("i1845-{n}-{s}"));
        for k in [&ann, &ben, &cat, &dan] {
            e2::put_key(d, k, &[identity_type::USER]).await;
        }
        let fam_s = format!("i1845-fam-{s}");
        let fam = e2::kid(&fam_s);
        let founded = at("2026-01-01T00:00:00Z");
        e2::put_voices(
            d,
            &e2::family_voices(
                &ts::sign_family(
                    &ann,
                    Family {
                        prev_head_digest: String::new(),
                        charter_digest: String::new(),
                        family_key_id: fam_s.clone(),
                        family_name: "household".into(),
                        members: [&ann, &ben, &cat]
                            .iter()
                            .enumerate()
                            .map(|(i, k)| FamilyMember {
                                key_id: (*k).clone(),
                                joined_at: founded,
                                role: (i == 0).then(|| "founder".to_owned()),
                            })
                            .collect(),
                        founded_at: founded,
                        consensus_protocol: "unanimous".to_owned(),
                        consensus_protocol_entrenched: false,
                        dissolved_at: None,
                        persist_row_hash: String::new(),
                    },
                ),
                1,
                None,
                ms(founded),
            ),
        )
        .await
        .expect("I1845: the family");
        // GID-fixtures-sites — the room's DERIVED id, once founded (`room_id`
        // panics if it was not).
        let fam_s = crate::federation::edition2::fixture_switch::room_id(&fam_s);
        let (head, _) = e2::held_head(d, &fam)
            .await
            .expect("I1845: the roster's head");
        let mut r = ts::sign_family_membership_revocation(
            &ann,
            FamilyMembershipRevocation {
                family_key_id: fam_s.clone(),
                removed_identity_key_id: cat.clone(),
                removed_at: at("2026-02-01T00:00:00Z"),
                effective_at: at("2026-02-01T00:00:00Z"),
                reason: None,
                witness_set: vec![],
                persist_row_hash: String::new(),
                leaf: crate::federation::types::RevocationLeaf::Removal,
            },
        );
        ts::cosign_family_membership_revocation(&mut r, &ben);
        e2::put_voices(d, &e2::family_revocation_voices(&r, Some(&head)))
            .await
            .expect("I1845: cat leaves (every other member signs)");
        // The #955 growth gate: dan's proposal and acceptance, held first.
        let proposal = proposal_row(
            &ann,
            cohort_scope::FAMILY,
            &fam,
            &dan,
            None,
            at("2026-03-01T00:00:00Z"),
        );
        e2::put_signed(d, &proposal)
            .await
            .expect("I1845: the proposal");
        e2::put_signed(
            d,
            &acceptance_row(&dan, &proposal, at("2026-03-01T00:00:00Z")),
        )
        .await
        .expect("I1845: dan's acceptance");
        let (head, _) = e2::held_head(d, &fam)
            .await
            .expect("I1845: the roster's head");
        let mut w = ts::sign_family_membership_widening(
            &ann,
            FamilyMembershipWidening {
                family_key_id: fam_s.clone(),
                member_key_id: dan.clone(),
                joined_at: at("2026-03-01T00:00:00Z"),
                effective_at: at("2026-03-01T00:00:00Z"),
                role: None,
                persist_row_hash: String::new(),
            },
        );
        ts::cosign_family_membership_widening(&mut w, &ben);
        e2::put_voices(d, &e2::family_widening_voices(&w, Some(&head)))
            .await
            .expect("I1845: ann and ben are every member at the change: unanimous");
        let active: Vec<String> = d
            .active_family_members(&fam)
            .await
            .expect("roster")
            .into_iter()
            .map(|m| m.key_id)
            .collect();
        assert!(
            active.contains(&e2::kid(&dan)) && !active.contains(&e2::kid(&cat)),
            "I1845: {active:?}"
        );
    }

    /// **I1846** — a reference cycle cannot arise (v62 edition-2 form; CC
    /// asked for this witness by file and line). An edition-2 row names
    /// another only by `refs.target`, the node-computed id of a row ALREADY
    /// HELD, and that id is computed over the named row's own bytes. So:
    /// (a) a row naming an id this node does not hold is not admitted and
    /// nothing is stored (it waits or is refused, per the door); a
    /// `supersedes` naming a row that is kept but has NOT concluded waits on
    /// it too (PIN-fix9d: a replacement needs a landed row); (b) the row
    /// that would "close" the loop is a different statement from the one
    /// first named, so its id is not the id the first row named; (c) with
    /// neither row held, the trust walk over held rows returns within a bound
    /// and gives no edge.
    pub(crate) async fn i1846_a_reference_cycle_never_hangs_the_trust_walk(
        d: &dyn FederationDirectory,
        s: &str,
    ) {
        use crate::federation::trust_root::{trust_root_valid, TRUST_ACCEPTS_DIMENSION};
        let (user_s, root_s) = (format!("i1846-user-{s}"), format!("i1846-root-{s}"));
        let user = e2::put_key(d, &user_s, &[identity_type::USER]).await;
        let root = e2::put_key(d, &root_s, &[identity_type::USER]).await;
        // A `supersedes` by the user toward the root naming `target` (64 hex).
        let naming = |label: &str, target: &str| {
            let mut r = {
                ts::bare_attestation(
                    label,
                    &user_s,
                    &root_s,
                    &serde_json::json!({
                        "references_attestation_id": target,
                        "dimension": TRUST_ACCEPTS_DIMENSION,
                    }),
                )
            };
            r.attestation_type = attestation_type::SUPERSEDES.to_owned();
            r
        };
        // B0 names an arbitrary id; A names B0's id; B names A's id.
        let b0 = naming("i1846-b0", &"ab".repeat(32));
        let id_b0 = e2::rid(&e2::row_of(&b0, &user_s));
        let a = naming("i1846-a", &id_b0);
        let id_a = e2::rid(&e2::row_of(&a, &user_s));
        let b = naming("i1846-b", &id_a);
        let id_b = e2::rid(&e2::row_of(&b, &user_s));
        // (b) the loop never closes: B's id is not the id A named.
        assert_ne!(
            id_b, id_b0,
            "I1846: a row's id is computed over its own bytes, so the row naming A is not the \
             row A named"
        );
        // (a) neither names a held row, so neither is admitted or stored.
        for (row, id, what) in [(&a, &id_a, "A"), (&b, &id_b, "B")] {
            // v62 (E4 round 3; CC 2.7, ruling 5): a composer whose target is
            // not held WAITS for it (`Pending`) or is refused; it is never a
            // row.
            let out = e2::put_statement(d, &e2::statement_of(row, &user_s)).await;
            assert!(
                matches!(
                    out,
                    Ok(crate::federation::edition2::ingest::StatementOutcome::Pending { .. })
                        | Err(_)
                ),
                "I1846: {what} names a row this node does not hold and is not admitted: {out:?}"
            );
            assert!(
                d.get_attestation(id).await.unwrap().is_none(),
                "I1846: {what} is not stored"
            );
            // v62.0.0 (PIN-fix9d) — B's target A IS kept (a held-back
            // statement), but has not concluded: B waits on it exactly as A
            // waits on the id nobody holds (`link_unheld`).
            if let Ok(crate::federation::edition2::ingest::StatementOutcome::Pending {
                row_id,
                ..
            }) = &out
            {
                let why = crate::federation::edition2::fold::why_held(d, row_id)
                    .await
                    .unwrap();
                assert_eq!(
                    why.as_ref().map(|h| h.reason.as_str()),
                    Some(crate::federation::edition2::fold::reason::LINK_UNHELD),
                    "I1846: {what} waits on the row it names: {why:?}"
                );
            }
        }
        // (c) the walk over held rows is bounded and gives no edge.
        let v = tokio::time::timeout(
            std::time::Duration::from_secs(30),
            trust_root_valid(d, &user, &root, crate::host::clock::now()),
        )
        .await
        .expect("I1846: the trust walk returns within a bound")
        .expect("I1846: the verdict");
        assert!(!v.edge_exists, "I1846: no held row, no edge");
    }
}

#[cfg(all(test, any(feature = "sqlite", feature = "postgres")))]
mod runners {
    fn tag(b: &str) -> String {
        format!("{b}{}", uuid::Uuid::new_v4().simple())
    }

    macro_rules! on_sqlite_and_postgres {
        ($name:ident, $body:path) => {
            mod $name {
                use super::tag;

                #[cfg(feature = "sqlite")]
                #[tokio::test]
                async fn sqlite() {
                    use crate::store::Backend as _;
                    let b = crate::store::sqlite::SqliteBackend::open_in_memory()
                        .await
                        .unwrap();
                    b.run_migrations().await.unwrap();
                    Box::pin($body(&b, &tag("s"))).await;
                }

                #[cfg(feature = "postgres")]
                #[tokio::test]
                async fn postgres() {
                    use crate::store::Backend as _;
                    let Some(dsn) = crate::test_pg::empty_dsn() else {
                        eprintln!(
                            "{} postgres: no CIRIS_PERSIST_TEST_PG base DSN — SKIPPED",
                            stringify!($name)
                        );
                        return;
                    };
                    let b = crate::store::postgres::PostgresBackend::connect(&dsn)
                        .await
                        .unwrap();
                    b.run_migrations().await.unwrap();
                    Box::pin($body(&b, &tag("p"))).await;
                    eprintln!("{} postgres: RAN", stringify!($name));
                }
            }
        };
    }

    on_sqlite_and_postgres!(
        i1840,
        crate::federation::kernel_adapter_invariants::bodies::i1840_an_owner_binding_counts_with_the_nodes_cosignature
    );
    on_sqlite_and_postgres!(i1841, crate::federation::kernel_adapter_invariants::bodies::i1841_no_edge_is_refused_for_closing_a_cycle);
    on_sqlite_and_postgres!(
        i1843,
        crate::federation::kernel_adapter_invariants::bodies::i1843_a_fork_of_the_held_head_is_a_tip_to_the_kernel
    );
    on_sqlite_and_postgres!(
        i1845,
        crate::federation::kernel_adapter_invariants::bodies::i1845_a_leaving_in_the_rows_past_is_not_counted
    );
    on_sqlite_and_postgres!(
        i1846,
        crate::federation::kernel_adapter_invariants::bodies::i1846_a_reference_cycle_never_hangs_the_trust_walk
    );
    on_sqlite_and_postgres!(
        i1842,
        crate::federation::kernel_adapter_invariants::bodies::i1842_the_edge_leg_is_the_kernels_one_hop_walk
    );
}

/// Phase timing of the owner seat's adapter (a profiling aid, ignored).
#[cfg(all(test, feature = "sqlite"))]
mod profile {
    use crate::federation::attestation_query::{AttestationQuery, FOLD_PAGE};
    use crate::federation::edition2::fixture_switch as e2;
    use crate::federation::tier_ingest::test_support as ts;
    use crate::federation::types::{attestation_type, identity_type};
    use crate::federation::FederationDirectory;
    use std::time::Instant;

    #[tokio::test]
    #[ignore = "profiling aid"]
    async fn owner_phases() {
        use crate::store::Backend as _;
        let b = crate::store::sqlite::SqliteBackend::open_in_memory()
            .await
            .unwrap();
        b.run_migrations().await.unwrap();
        let d: &dyn FederationDirectory = &b;
        e2::put_key(d, "prof-owner", &[identity_type::USER]).await;
        let node = e2::put_key(d, "prof-node", &[identity_type::NODE]).await;
        let row = ts::owner_binding_attestation("prof-b", "prof-owner", "prof-node");
        e2::put_signed(d, &row).await.unwrap();
        e2::put_statement(
            d,
            &e2::voice_of(&e2::carried_statement(&row).unwrap(), "prof-node"),
        )
        .await
        .unwrap();
        let n = 300u32;
        let t = Instant::now();
        for _ in 0..n {
            crate::federation::admission::owner_of_reference_for_profile(d, &node).await;
        }
        eprintln!("legacy owner_of: {:?}", t.elapsed() / n);
        let t = Instant::now();
        for _ in 0..n {
            crate::federation::admission::owner_of(d, &node)
                .await
                .unwrap();
        }
        eprintln!("kernel owner_of (with differential): {:?}", t.elapsed() / n);
        let t = Instant::now();
        for _ in 0..n {
            crate::federation::admission::kernel_owner_selves(
                d,
                &node,
                crate::kernel::owner::Cosign::Required,
            )
            .await
            .unwrap();
        }
        eprintln!("kernel_owner_selves: {:?}", t.elapsed() / n);
        let t = Instant::now();
        for _ in 0..n {
            crate::federation::admission::owner_of_reference_for_profile(d, &node).await;
        }
        eprintln!("legacy again: {:?}", t.elapsed() / n);
        let mut acc = [std::time::Duration::ZERO; 6];
        for _ in 0..n {
            let t0 = Instant::now();
            let mut edges = Vec::new();
            let mut pages = AttestationQuery::to(&node, FOLD_PAGE)
                .types(&[attestation_type::DELEGATES_TO])
                .pages();
            while let Some(page) = pages.next(d).await.unwrap() {
                edges.extend(page);
            }
            let t1 = Instant::now();
            let ids: Vec<String> = edges.iter().map(|e| e.attestation_id.clone()).collect();
            let mut rows = edges;
            rows.extend(
                d.list_composers_referencing_any(&ids, Some(&node), None)
                    .await
                    .unwrap(),
            );
            let t2 = Instant::now();
            let mut retr = Vec::new();
            let mut pages = AttestationQuery::to(&node, FOLD_PAGE)
                .types(&[attestation_type::WITHDRAWS, attestation_type::RECANTS])
                .pages();
            while let Some(page) = pages.next(d).await.unwrap() {
                retr.extend(page);
            }
            let t3 = Instant::now();
            let view = crate::kernel::owner::owner_rows(
                &node,
                &rows,
                &retr,
                chrono::Utc::now(),
                &|_| true,
                crate::kernel::owner::Cosign::Required,
            );
            let held = crate::kernel::owner::owner_holders(&view, &node).value;
            let t4 = Instant::now();
            for g in &held {
                d.lookup_public_key(g).await.unwrap();
            }
            let t5 = Instant::now();
            for g in &held {
                crate::federation::self_roster::self_of_at(d, g, chrono::Utc::now())
                    .await
                    .unwrap();
            }
            let t6 = Instant::now();
            for (i, (a, b)) in [(t0, t1), (t1, t2), (t2, t3), (t3, t4), (t4, t5), (t5, t6)]
                .iter()
                .enumerate()
            {
                acc[i] += *b - *a;
            }
        }
        for (name, a) in [
            "edges",
            "composers",
            "retractions",
            "kernel",
            "lookup",
            "self_of_at",
        ]
        .iter()
        .zip(acc)
        {
            eprintln!("{name}: {:?}", a / n);
        }
    }
}
