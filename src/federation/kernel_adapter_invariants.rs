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
//! - **I1843** — a fork of a held head (two versions naming one head): persist
//!   refuses it; the kernel holds it as a tip (CC 2.7.8). Witnessed, not
//!   switched.

#[cfg(all(test, any(feature = "sqlite", feature = "postgres")))]
pub(crate) mod bodies {
    use crate::federation::admission::owner_of;
    use crate::federation::tier_ingest::test_support as ts;
    use crate::federation::types::{attestation_type, identity_type};
    use crate::federation::{FederationDirectory, SignedAttestation};

    /// **I1840** — see the module doc.
    pub(crate) async fn i1840_an_owner_binding_counts_with_the_nodes_cosignature(
        d: &dyn FederationDirectory,
        s: &str,
    ) {
        let (owner, bare, cosigned) = (
            format!("i1840-owner-{s}"),
            format!("i1840-bare-{s}"),
            format!("i1840-cosigned-{s}"),
        );
        ts::register_hybrid_key_as(d, &owner, &owner, identity_type::USER).await;
        for n in [&bare, &cosigned] {
            ts::register_hybrid_key_as(d, n, n, identity_type::NODE).await;
        }
        // The node never cosigned: its co-scrub is stripped after the seal.
        let mut row =
            ts::owner_binding_attestation(&uuid::Uuid::new_v4().to_string(), &owner, &bare);
        assert!(
            row.additional_scrubs.iter().any(|c| c.scrub_key_id == bare),
            "I1840: the fixture sealer co-scrubs an owner binding by its node"
        );
        row.additional_scrubs.clear();
        d.put_attestation(SignedAttestation { attestation: row })
            .await
            .expect("I1840: an uncosigned owner binding is a well-formed, held row");
        assert_eq!(
            owner_of(d, &bare).await.expect("owner_of"),
            None,
            "I1840: CC 3.2 — a binding the node never cosigned names no owner"
        );
        // The node cosigned.
        let row =
            ts::owner_binding_attestation(&uuid::Uuid::new_v4().to_string(), &owner, &cosigned);
        let id = row.attestation_id.clone();
        d.put_attestation(SignedAttestation {
            attestation: row.clone(),
        })
        .await
        .expect("I1840: the cosigned binding lands");
        let held = d.get_attestation(&id).await.unwrap().expect("held");
        assert!(
            held.additional_scrubs
                .iter()
                .any(|c| c.scrub_key_id == cosigned),
            "I1840: the node's co-scrub is stored with the row"
        );
        assert_eq!(
            owner_of(d, &cosigned).await.expect("owner_of"),
            Some(owner.clone()),
            "I1840: the cosigned binding names its owner"
        );
        // The owner's own withdraws ends the seat.
        ts::put_retraction(d, &owner, &cosigned, &id, attestation_type::WITHDRAWS)
            .await
            .expect("I1840: the owner withdraws the binding");
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
            ts::register_hybrid_key_as(d, k, k, identity_type::AGENT).await;
        }
        ts::put_delegates_to(d, &a, &b, None)
            .await
            .expect("I1841: a → b");
        ts::put_delegates_to(d, &b, &a, None)
            .await
            .expect("I1841: b → a closes a cycle and is admitted (v62)");
        let g = crate::federation::build_delegation_graph(d, &a, Some(8))
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
        use crate::federation::trust_root::{trust_root_valid, INFRA_SERVE_SCOPE};
        let (user, root, subject) = (
            format!("i1842-user-{s}"),
            format!("i1842-root-{s}"),
            format!("i1842-subject-{s}"),
        );
        for k in [&user, &subject] {
            ops::register_typed_key(d, k, identity_type::NODE)
                .await
                .expect("register");
        }
        ops::establish_trust_root(d, &user, &root, &subject, INFRA_SERVE_SCOPE)
            .await
            .expect("I1842: establish the root");
        let v = trust_root_valid(d, &user, &root).await.expect("verdict");
        assert!(v.edge_exists, "I1842: the user's acceptance edge is live");
        assert!(v.valid, "I1842: a valid key root");
        let edge = d
            .list_attestations_by(&user)
            .await
            .expect("by user")
            .into_iter()
            .find(|r| {
                r.attestation_type == attestation_type::DELEGATES_TO && r.attested_key_id == root
            })
            .expect("I1842: the user's edge to the root");
        ts::put_retraction(
            d,
            &user,
            &root,
            &edge.attestation_id,
            attestation_type::WITHDRAWS,
        )
        .await
        .expect("I1842: the user withdraws the edge");
        let v = trust_root_valid(d, &user, &root).await.expect("verdict");
        assert!(
            !v.edge_exists,
            "I1842: the user's own withdraws ends the edge"
        );
        assert!(!v.valid, "I1842: no edge, no valid root");
    }

    /// **I1843** — a FORK of a held head: two versions naming one head. The
    /// family's v1 is held; v2 naming v1 is admitted (the head moves); v3
    /// naming v1 too — v2's sibling — is the fork. Persist refuses it
    /// `lineage_prev_head_mismatch` (`held_head_verdict`, unchanged in this
    /// slice); the kernel reads it as a tip beside v2 (CC 2.7.8: "Two
    /// versions of one head wait as tips"). The differential witness records
    /// the call as the `fork_as_tip` departure, on both backends.
    pub(crate) async fn i1843_a_fork_of_the_held_head_is_a_tip_to_the_kernel(
        d: &dyn FederationDirectory,
        s: &str,
    ) {
        use crate::federation::operational::test_support as ops;
        use crate::kernel::head::{head_reading, HeadReading};
        let holders: Vec<String> = (0..3).map(|i| format!("i1843-h{i}-{s}")).collect();
        for h in &holders {
            ops::register_typed_key(d, h, identity_type::NODE)
                .await
                .expect("register");
        }
        let fam = format!("i1843-fam-{s}");
        ops::seed_test_family(d, &fam, &holders, "quorum:2/3")
            .await
            .expect("I1843: v1");
        let v1 = d.lookup_family(&fam).await.unwrap().expect("held");
        let mut v2 = v1.clone();
        v2.prev_head_digest = v1.persist_row_hash.clone();
        v2.family_name = "v2".into();
        v2.persist_row_hash = String::new();
        d.supersede_family(ts::sign_family(&holders[0], v2), None)
            .await
            .expect("I1843: v2 names the held head");
        let held = d.lookup_family(&fam).await.unwrap().expect("held");
        let mut v3 = v1.clone();
        v3.prev_head_digest = v1.persist_row_hash.clone();
        v3.family_name = "v3".into();
        v3.persist_row_hash = String::new();
        let e = d
            .supersede_family(ts::sign_family(&holders[0], v3), None)
            .await
            .expect_err("I1843: persist refuses the fork (held_head_verdict, this slice)");
        assert!(
            matches!(&e, crate::federation::Error::Conflict(m) if m.contains("lineage_prev_head_mismatch")),
            "I1843: {e:?}"
        );
        assert_eq!(
            head_reading(
                &fam,
                Some(&held.persist_row_hash),
                &v1.persist_row_hash,
                &holders[0]
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
    pub(crate) async fn i1845_a_leaving_in_the_rows_past_is_not_counted(
        d: &dyn FederationDirectory,
        s: &str,
    ) {
        use crate::federation::membership_acceptance::test_support::ConsentedWidening as _;
        use crate::federation::types::{
            Family, FamilyMember, FamilyMembershipRevocation, FamilyMembershipWidening,
        };
        let at = |t: &str| -> chrono::DateTime<chrono::Utc> { t.parse().expect("instant") };
        let [ann, ben, cat, dan] = ["ann", "ben", "cat", "dan"].map(|n| format!("i1845-{n}-{s}"));
        for k in [&ann, &ben, &cat, &dan] {
            ts::register_hybrid_key_as(d, k, k, identity_type::USER).await;
        }
        let fam = format!("i1845-fam-{s}");
        let founded = at("2026-01-01T00:00:00Z");
        d.put_family(ts::sign_family(
            &ann,
            Family {
                prev_head_digest: String::new(),
                charter_digest: String::new(),
                family_key_id: fam.clone(),
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
        ))
        .await
        .expect("I1845: the family");
        let mut r = ts::sign_family_membership_revocation(
            &ann,
            FamilyMembershipRevocation {
                family_key_id: fam.clone(),
                removed_identity_key_id: cat.clone(),
                removed_at: at("2026-02-01T00:00:00Z"),
                effective_at: at("2026-02-01T00:00:00Z"),
                reason: None,
                witness_set: vec![],
                persist_row_hash: String::new(),
            },
        );
        ts::cosign_family_membership_revocation(&mut r, &ben);
        d.put_family_membership_revocation(r)
            .await
            .expect("I1845: cat leaves (every other member signs)");
        let mut w = ts::sign_family_membership_widening(
            &ann,
            FamilyMembershipWidening {
                family_key_id: fam.clone(),
                member_key_id: dan.clone(),
                joined_at: at("2026-03-01T00:00:00Z"),
                effective_at: at("2026-03-01T00:00:00Z"),
                role: None,
                persist_row_hash: String::new(),
            },
        );
        ts::cosign_family_membership_widening(&mut w, &ben);
        d.put_family_membership_widening_consented(w)
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
            active.contains(&dan) && !active.contains(&cat),
            "I1845: {active:?}"
        );
    }

    /// **I1846** — a reference cycle on today's wire: two `supersedes` rows of
    /// the user's, toward the root, each naming the other's attestation id (a
    /// peer-chosen string). Whatever the door admits, `trust_root_valid`
    /// returns within a bound, and the pair gives no edge (the kernel's door,
    /// `layers::kept`, never keeps a row whose names are not held first).
    pub(crate) async fn i1846_a_reference_cycle_never_hangs_the_trust_walk(
        d: &dyn FederationDirectory,
        s: &str,
    ) {
        use crate::federation::trust_root::{trust_root_valid, TRUST_ACCEPTS_DIMENSION};
        let (user, root) = (format!("i1846-user-{s}"), format!("i1846-root-{s}"));
        for k in [&user, &root] {
            ts::register_hybrid_key_as(d, k, k, identity_type::USER).await;
        }
        let (a, b) = (format!("i1846-a-{s}"), format!("i1846-b-{s}"));
        for (id, names) in [(&a, &b), (&b, &a)] {
            let mut row = ts::bare_attestation(
                id,
                &user,
                &root,
                &serde_json::json!({
                    "id": id,
                    "references_attestation_id": names,
                    "dimension": TRUST_ACCEPTS_DIMENSION,
                }),
            );
            row.attestation_type = attestation_type::SUPERSEDES.to_owned();
            ts::seal_row_in_place(&user, &mut row);
            // the door may refuse a rotation of a grant it does not hold;
            // either way the walk below must return
            let _ = d
                .put_attestation(SignedAttestation { attestation: row })
                .await;
        }
        let v = tokio::time::timeout(
            std::time::Duration::from_secs(30),
            trust_root_valid(d, &user, &root),
        )
        .await
        .expect("I1846: the trust walk returns within a bound over a reference cycle")
        .expect("I1846: the verdict");
        assert!(!v.edge_exists, "I1846: a reference cycle gives no edge");
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
    use crate::federation::tier_ingest::test_support as ts;
    use crate::federation::types::{attestation_type, identity_type};
    use crate::federation::{FederationDirectory, SignedAttestation};
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
        let (owner, node) = ("prof-owner".to_owned(), "prof-node".to_owned());
        ts::register_hybrid_key_as(d, &owner, &owner, identity_type::USER).await;
        ts::register_hybrid_key_as(d, &node, &node, identity_type::NODE).await;
        d.put_attestation(SignedAttestation {
            attestation: ts::owner_binding_attestation("prof-b", &owner, &node),
        })
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
