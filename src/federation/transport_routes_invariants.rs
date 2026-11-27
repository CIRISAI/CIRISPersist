//! v61 (CIRISPersist#1122) — witnesses for one destination, one live key,
//! and for routes at agent keys. One body, run on sqlite and postgres.

pub(crate) mod bodies {
    use crate::federation::self_at_login::{BindingProvenance, TransportDestination};
    use crate::federation::tier_ingest::test_support as ts;
    use crate::federation::transport_routes::TRANSPORT_DESTINATION_AGENT_KEY;
    use crate::federation::types::identity_type::{AGENT, NODE, USER};
    use crate::federation::FederationDirectory;

    fn route(occ: &str, dest: &str, epoch: u64, asserted: &str) -> TransportDestination {
        TransportDestination {
            occurrence_key_id: occ.into(),
            transport_kind: "reticulum".into(),
            destination: dest.into(),
            asserted_at: asserted.parse().unwrap(),
            last_seen_at: None,
            transport_ed25519_pubkey_base64: None,
            transport_x25519_pubkey_base64: None,
            binding_provenance: BindingProvenance::Rooted,
            epoch,
            retired_at: None,
        }
    }

    fn keys(rows: &[TransportDestination]) -> Vec<String> {
        let mut k: Vec<String> = rows.iter().map(|r| r.occurrence_key_id.clone()).collect();
        k.sort();
        k
    }

    /// I1122-A — **an agent announces no route.** v62.0.0 (O1 fix 10; CP2):
    /// a route is the `transport_destination` member of an edition-2
    /// `identity:occurrence` bind, projected after the bind commits
    /// (`transport_routes::project_occurrence_route`). Under one node identity,
    /// an AGENT key's bind carrying a destination lands but projects no
    /// route. The unsigned local put refuses an agent route by name. A NODE
    /// key's bind on the same destination projects it.
    pub(crate) async fn i1122_a_agent_routes_are_refused(d: &dyn FederationDirectory, tag: &str) {
        use crate::federation::edition2::fixture_switch as e2;
        use crate::federation::edition2::ingest::StatementOutcome;
        use crate::federation::self_at_login::test_support::e2bind::transport;
        let (id_s, agent_s, node_s) = (
            format!("{tag}-id"),
            format!("{tag}-agent"),
            format!("{tag}-node"),
        );
        e2::put_key(d, &id_s, &[NODE]).await;
        e2::put_key(d, &agent_s, &[AGENT]).await;
        e2::put_key(d, &node_s, &[NODE]).await;
        let (agent, node) = (e2::kid(&agent_s), e2::kid(&node_s));
        let (member, dest) = transport([0x31; 32], [0x32; 32]);
        let at = e2::ms(chrono::Utc::now()) - 60_000;
        let opts = e2::BindOptions {
            asserted_at_ms: at,
            extra: vec![("transport_destination", member)],
            ..e2::BindOptions::default()
        };
        let out = e2::put_bind(d, &id_s, &id_s, &agent_s, "agent", &opts).await;
        assert!(
            matches!(out, Ok(StatementOutcome::Row { .. })),
            "I1122-A: the agent's bind lands: {out:?}"
        );
        assert!(
            d.list_transport_destinations_for_unfolded(&agent)
                .await
                .unwrap()
                .is_empty(),
            "I1122-A: an agent's bind projects no route"
        );
        let a = route(&agent, &dest, 1, "2026-10-22T00:00:00.000Z");
        let e = d.put_transport_destination(&a).await.unwrap_err();
        assert!(
            e.to_string().contains(TRANSPORT_DESTINATION_AGENT_KEY),
            "I1122-A: the local put refuses an agent route by name: {e}"
        );
        let out = e2::put_bind(d, &id_s, &id_s, &node_s, "server", &opts).await;
        assert!(
            matches!(out, Ok(StatementOutcome::Row { .. })),
            "I1122-A: the node's bind lands: {out:?}"
        );
        assert_eq!(
            keys(
                &d.list_transport_destinations_by_destination(&dest)
                    .await
                    .unwrap()
            ),
            vec![node.clone()],
            "I1122-A: only the node's route is listed"
        );
    }

    /// I1543 (Edge, the v44 tag blocker) — **a shared destination costs one
    /// owner read per key, never one per pair.** Anyone can mint this shape, so
    /// the bound holds with no key record behind any of the routes. An ownerless
    /// row read alone costs its own read, whatever else claims the destination.
    pub(crate) async fn i1543_a_shared_destination_reads_each_owner_once(
        d: &dyn FederationDirectory,
        tag: &str,
    ) {
        const CLAIMANTS: usize = 12;
        let dest = format!("{tag}shared");
        let mut rows = Vec::new();
        for i in 0..CLAIMANTS {
            let r = route(
                &format!("{tag}-bench-{i}"),
                &dest,
                1 + i as u64,
                "2026-10-22T00:00:00.000Z",
            );
            d.put_transport_destination(&r).await.unwrap();
            rows.push(r);
        }
        let (kept, reads) =
            crate::federation::transport_routes::fold_counting_owner_reads(d, rows.clone())
                .await
                .unwrap();
        assert_eq!(kept.len(), CLAIMANTS, "I1543: ownerless keys coexist");
        assert!(
            reads <= CLAIMANTS,
            "I1543: {reads} owner reads for {CLAIMANTS} keys"
        );
        let (_, one) = crate::federation::transport_routes::fold_counting_owner_reads(
            d,
            vec![rows[0].clone()],
        )
        .await
        .unwrap();
        assert_eq!(one, 1, "I1543: an ownerless row costs its own read");

        // Tied claimants: each key's owner is read once, and the verdict holds.
        let owner = format!("{tag}-owner");
        ts::register_identity_key(d, &owner, USER).await;
        let tied_dest = format!("{tag}tied");
        let mut tied = Vec::new();
        for i in 0..CLAIMANTS {
            let node = format!("{tag}-tied-{i}");
            ts::register_identity_key(d, &node, NODE).await;
            ts::put_owner_binding(d, &owner, &node).await;
            // v62 (O1 fix 11): an edition-2 key, and its owner binding, are
            // named by its kid; the route names the same id.
            let node = crate::federation::edition2::fixture_switch::kid(&node);
            let r = route(&node, &tied_dest, 1 + i as u64, "2026-10-22T00:00:00.000Z");
            d.put_transport_destination(&r).await.unwrap();
            tied.push(r);
        }
        let (kept, reads) =
            crate::federation::transport_routes::fold_counting_owner_reads(d, tied.clone())
                .await
                .unwrap();
        assert_eq!(
            keys(&kept),
            vec![crate::federation::edition2::fixture_switch::kid(&format!(
                "{tag}-tied-{}",
                CLAIMANTS - 1
            ))],
            "I1543: the newest tied key alone stays live"
        );
        assert!(
            reads <= CLAIMANTS,
            "I1543: {reads} owner reads for {CLAIMANTS} keys"
        );
    }

    /// I1122-B — **one destination, one live key.** Two node keys with one
    /// live owner (a split home) on one destination: the newer route displaces
    /// the older on every read, and the older key lists no route. A third key
    /// with no owner tie (a spoofer) on the same destination still coexists.
    /// The stored rows keep the displaced one (the fold is read-time).
    pub(crate) async fn i1122_b_a_tied_newer_route_displaces(
        d: &dyn FederationDirectory,
        tag: &str,
    ) {
        let owner = format!("{tag}-owner");
        let old_node = format!("{tag}-oldnode");
        let new_node = format!("{tag}-newnode");
        let stranger = format!("{tag}-stranger");
        ts::register_identity_key(d, &owner, USER).await;
        for k in [&old_node, &new_node, &stranger] {
            ts::register_identity_key(d, k, NODE).await;
        }
        ts::put_owner_binding(d, &owner, &old_node).await;
        ts::put_owner_binding(d, &owner, &new_node).await;
        // v62 (O1 fix 11): edition-2 keys (and their owner bindings) are named
        // by their kids; the routes name the same ids.
        let kid = crate::federation::edition2::fixture_switch::kid;
        let (old_node, new_node, stranger) = (kid(&old_node), kid(&new_node), kid(&stranger));
        let dest = format!("{tag}split");
        let older = route(&old_node, &dest, 1, "2026-10-22T00:00:00.000Z");
        let newer = route(&new_node, &dest, 1, "2026-10-23T00:00:00.000Z");
        let spoof = route(&stranger, &dest, 1, "2026-10-24T00:00:00.000Z");
        // v62 (O1 fix 11; CP2): the signed transport apply is an earlier-form
        // door, shut. The fold under test is read-time over the stored rows,
        // so the routes are stored through the live local door.
        for r in [&older, &newer, &spoof] {
            d.put_transport_destination(r)
                .await
                .expect("I1122-B: each route is admitted");
        }
        assert_eq!(
            keys(
                &d.list_transport_destinations_by_destination(&dest)
                    .await
                    .unwrap()
            ),
            {
                let mut v = vec![new_node.clone(), stranger.clone()];
                v.sort();
                v
            },
            "I1122-B: the older tied route is displaced; the untied claimant coexists"
        );
        assert!(
            d.list_transport_destinations_for(&old_node)
                .await
                .unwrap()
                .is_empty(),
            "I1122-B: the displaced key lists no live route"
        );
        assert!(
            d.list_all_transport_destinations()
                .await
                .unwrap()
                .iter()
                .all(|r| r.occurrence_key_id != old_node),
            "I1122-B: the boot reload does not restore the displaced route"
        );
        assert_eq!(
            d.list_transport_destinations_for(&new_node)
                .await
                .unwrap()
                .len(),
            1
        );
        assert_eq!(
            keys(
                &d.list_transport_destinations_by_destination_unfolded(&dest)
                    .await
                    .unwrap()
            )
            .len(),
            3,
            "I1122-B: the stored rows are untouched; the fold is read-time"
        );
    }

    /// I1626 (CIRISPersist#1188, the three `displaces` survivors; CC 3.4.7.3)
    /// — **a route displaces only its own kind.** Two node keys with one live
    /// owner on one destination string, each announcing a different
    /// `transport_kind`, the second strictly newer: neither displaces the
    /// other, on every read, because a route is one per (destination, kind)
    /// and these are two. Red if the kind guard is lost to `&&` at any of the
    /// three `||` that join the same-key, kind, destination and retired
    /// clauses (the destination is always shared on the fold's listing and a
    /// listed route is never retired, so each of those mutants reduces the
    /// guard to the instant comparison and the owner tie). The control: the
    /// same two keys on one kind, I1122-B, where the newer displaces.
    pub(crate) async fn i1626_a_route_displaces_only_its_own_kind(
        d: &dyn FederationDirectory,
        tag: &str,
    ) {
        let owner = format!("{tag}-owner");
        let old_node = format!("{tag}-oldnode");
        let new_node = format!("{tag}-newnode");
        ts::register_identity_key(d, &owner, USER).await;
        for k in [&old_node, &new_node] {
            ts::register_identity_key(d, k, NODE).await;
        }
        ts::put_owner_binding(d, &owner, &old_node).await;
        ts::put_owner_binding(d, &owner, &new_node).await;
        // v62 (O1 fix 11): the keys by their kids, as I1122-B.
        let kid = crate::federation::edition2::fixture_switch::kid;
        let (old_node, new_node) = (kid(&old_node), kid(&new_node));
        let dest = format!("{tag}kinds");
        let older = route(&old_node, &dest, 1, "2026-10-22T00:00:00.000Z");
        let mut newer = route(&new_node, &dest, 2, "2026-10-23T00:00:00.000Z");
        newer.transport_kind = "websocket".into();
        // v62 (O1 fix 11; CP2): stored through the live local door, as I1122-B.
        for r in [&older, &newer] {
            d.put_transport_destination(r)
                .await
                .expect("I1626: each route is admitted");
        }
        let both = {
            let mut v = vec![new_node.clone(), old_node.clone()];
            v.sort();
            v
        };
        assert_eq!(
            keys(
                &d.list_transport_destinations_by_destination(&dest)
                    .await
                    .unwrap()
            ),
            both,
            "I1626: a newer route of another kind displaces nothing"
        );
        assert_eq!(
            d.list_transport_destinations_for(&old_node)
                .await
                .unwrap()
                .len(),
            1,
            "I1626: the older key keeps its route"
        );
        let mut reloaded: Vec<String> = d
            .list_all_transport_destinations()
            .await
            .unwrap()
            .into_iter()
            .filter(|r| r.destination == dest)
            .map(|r| r.occurrence_key_id)
            .collect();
        reloaded.sort();
        assert_eq!(reloaded, both, "I1626: the boot reload keeps both");
    }

    /// I1122-C — **a route an agent key published before v61 is swept.** A
    /// route admitted while its key was not held (so it could not be typed),
    /// then the key arrives as an agent: the sweep deletes it and counts one;
    /// a second sweep counts none.
    pub(crate) async fn i1122_c_the_sweep_removes_agent_routes(
        d: &dyn FederationDirectory,
        tag: &str,
    ) {
        // v62.0.0 — the key arrives as an edition-2 `key:record`, so the
        // route names it by its kid (the id the directory types it under).
        let agent_seed = format!("{tag}-lateagent");
        let agent = crate::federation::edition2::fixture_switch::kid(&agent_seed);
        let dest = format!("{tag}late");
        let r = route(&agent, &dest, 1, "2026-10-22T00:00:00.000Z");
        d.put_transport_destination(&r)
            .await
            .expect("I1122-C: an untyped key's local route is admitted");
        ts::register_identity_key(d, &agent_seed, AGENT).await;
        assert_eq!(
            crate::federation::transport_routes::sweep_agent_routes(d)
                .await
                .unwrap(),
            1
        );
        assert!(d
            .list_transport_destinations_for_unfolded(&agent)
            .await
            .unwrap()
            .is_empty());
        assert_eq!(
            crate::federation::transport_routes::sweep_agent_routes(d)
                .await
                .unwrap(),
            0,
            "I1122-C: the sweep is idempotent"
        );
    }

    /// I1122-D — **an occurrence projects its route through one step**: a
    /// node's occurrence carrying a transport binding lists its route; an
    /// agent's projects none, and its occurrence still lands.
    pub(crate) async fn i1122_d_an_agent_occurrence_projects_no_route<D>(d: &D, tag: &str)
    where
        D: FederationDirectory,
    {
        use base64::Engine as _;
        let b64 = base64::engine::general_purpose::STANDARD;
        use crate::federation::edition2::fixture_switch as e2;
        let identity_seed = format!("{tag}-occid");
        // v62.0.0 (wave O1) — a NODE identity: a node or agent key is never
        // an occurrence of a person (`occurrence_mixes_person_and_machine`,
        // every occurrence door), so the two machine occurrences bind under a
        // machine identity. Each key is an edition-2 `key:record`: the local
        // rows name it by its kid (the `federation_keys` id they reference).
        ts::register_identity_key(d, &identity_seed, NODE).await;
        let identity = e2::kid(&identity_seed);
        for (occ_seed, ty, want) in [
            (format!("{tag}-occnode"), NODE, 1usize),
            (format!("{tag}-occagent"), AGENT, 0usize),
        ] {
            ts::register_identity_key(d, &occ_seed, ty).await;
            let occ = e2::kid(&occ_seed);
            let row = crate::federation::IdentityOccurrence {
                identity_key_id: identity.clone(),
                occurrence_key_id: occ.clone(),
                device_class: crate::federation::types::device_class::AGENT.into(),
                hardware_attestation: None,
                asserted_at: chrono::Utc::now(),
                valid_until: None,
                encryption_pubkeys: None,
                transport_binding: Some(crate::federation::types::OccurrenceTransportBinding {
                    reticulum_x25519_pubkey_base64: b64.encode([0x21; 32]),
                    reticulum_ed25519_pubkey_base64: b64.encode([0x22; 32]),
                    destination_hash_base64: b64.encode([0x21; 16]),
                    app_name: "ciris.federation".into(),
                    aspects: vec!["announce".into()],
                }),
                persist_row_hash: String::new(),
            };
            crate::federation::edition2::fixture_switch::put_occurrence_signed(d, row)
                .await
                .expect("I1122-D: the occurrence lands");
            assert_eq!(
                d.list_transport_destinations_for_unfolded(&occ)
                    .await
                    .unwrap()
                    .len(),
                want,
                "I1122-D: {ty} occurrence routes"
            );
        }
    }
}

#[cfg(test)]
mod tests {
    fn tag() -> String {
        format!("tr{}", &uuid::Uuid::new_v4().simple().to_string()[..10])
    }

    macro_rules! runners {
        ($backend:ident, $make:expr) => {
            mod $backend {
                #[tokio::test]
                async fn i1122_a_agent_routes_are_refused() {
                    let Some(b) = $make.await else { return };
                    super::super::bodies::i1122_a_agent_routes_are_refused(&b, &super::tag()).await;
                }
                #[tokio::test]
                async fn i1543_a_shared_destination_reads_each_owner_once() {
                    let Some(b) = $make.await else { return };
                    super::super::bodies::i1543_a_shared_destination_reads_each_owner_once(
                        &b,
                        &super::tag(),
                    )
                    .await;
                }
                #[tokio::test]
                async fn i1122_b_a_tied_newer_route_displaces() {
                    let Some(b) = $make.await else { return };
                    super::super::bodies::i1122_b_a_tied_newer_route_displaces(&b, &super::tag())
                        .await;
                }
                #[tokio::test]
                async fn i1626_a_route_displaces_only_its_own_kind() {
                    let Some(b) = $make.await else { return };
                    super::super::bodies::i1626_a_route_displaces_only_its_own_kind(
                        &b,
                        &super::tag(),
                    )
                    .await;
                }
                #[tokio::test]
                async fn i1122_d_an_agent_occurrence_projects_no_route() {
                    let Some(b) = $make.await else { return };
                    super::super::bodies::i1122_d_an_agent_occurrence_projects_no_route(
                        &b,
                        &super::tag(),
                    )
                    .await;
                }
                #[tokio::test]
                async fn i1122_c_the_sweep_removes_agent_routes() {
                    let Some(b) = $make.await else { return };
                    super::super::bodies::i1122_c_the_sweep_removes_agent_routes(&b, &super::tag())
                        .await;
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
        let Some(dsn) = crate::test_pg::dsn() else {
            eprintln!("skipping: CIRIS_PERSIST_TEST_PG_URL unset");
            return None;
        };
        let b = crate::store::postgres::PostgresBackend::connect(&dsn)
            .await
            .unwrap();
        b.run_migrations().await.unwrap();
        Some(b)
    });
}
