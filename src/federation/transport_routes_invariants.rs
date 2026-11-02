//! v61 (CIRISPersist#1122) — witnesses for one destination, one live key,
//! and for routes at agent keys. One body, run on sqlite and postgres.

pub(crate) mod bodies {
    use crate::federation::self_at_login::{
        BindingProvenance, SignedTransportDestination, TransportDestination,
    };
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

    /// The route signed by its own key, with its instant in the CC 2.6.2 form.
    async fn signed(r: &TransportDestination) -> SignedTransportDestination {
        let mut env = serde_json::to_value(r).unwrap();
        env["asserted_at"] = serde_json::json!(
            crate::federation::admission::render_signed_instant(r.asserted_at)
        );
        let signer = ts::hybrid_identity(&r.occurrence_key_id);
        let (signed_envelope, signature) =
            ciris_verify_core::transport_binding::produce_signed_identity_occurrence(
                signer.as_ref(),
                env,
            )
            .await
            .unwrap();
        SignedTransportDestination {
            transport_destination: r.clone(),
            attesting_key_id: r.occurrence_key_id.clone(),
            signed_envelope,
            signature,
        }
    }

    fn keys(rows: &[TransportDestination]) -> Vec<String> {
        let mut k: Vec<String> = rows.iter().map(|r| r.occurrence_key_id.clone()).collect();
        k.sort();
        k
    }

    /// I1122-A — **an agent announces no route.** The signed apply and the
    /// unsigned local put both refuse a route at an `agent`-typed key, by
    /// name; a node's route on the same destination is admitted.
    pub(crate) async fn i1122_a_agent_routes_are_refused(d: &dyn FederationDirectory, tag: &str) {
        let agent = format!("{tag}-agent");
        let node = format!("{tag}-node");
        ts::register_identity_key(d, &agent, AGENT).await;
        ts::register_identity_key(d, &node, NODE).await;
        let dest = format!("{tag}dest");
        let a = route(&agent, &dest, 1, "2026-10-22T00:00:00.000Z");
        let e = d
            .put_signed_transport_destination(&signed(&a).await)
            .await
            .unwrap_err();
        assert!(
            e.to_string().contains(TRANSPORT_DESTINATION_AGENT_KEY),
            "I1122-A: the signed apply refuses an agent route by name: {e}"
        );
        let e = d.put_transport_destination(&a).await.unwrap_err();
        assert!(
            e.to_string().contains(TRANSPORT_DESTINATION_AGENT_KEY),
            "I1122-A: the local put refuses an agent route by name: {e}"
        );
        let n = route(&node, &dest, 1, "2026-10-23T00:00:00.000Z");
        d.put_signed_transport_destination(&signed(&n).await)
            .await
            .expect("I1122-A: a node's route is admitted");
        assert_eq!(
            keys(
                &d.list_transport_destinations_by_destination(&dest)
                    .await
                    .unwrap()
            ),
            vec![node.clone()]
        );
    }

    /// I1122-B — **one destination, one live key.** Two node keys with one
    /// live owner (a split home) on one destination: the newer route displaces
    /// the older on every read, and the older key lists no route. A third key
    /// with no owner tie (a spoofer) on the same destination still coexists.
    /// The signed replication read still serves the displaced row.
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
        let dest = format!("{tag}split");
        let older = route(&old_node, &dest, 1, "2026-10-22T00:00:00.000Z");
        let newer = route(&new_node, &dest, 1, "2026-10-23T00:00:00.000Z");
        let spoof = route(&stranger, &dest, 1, "2026-10-24T00:00:00.000Z");
        for r in [&older, &newer, &spoof] {
            d.put_signed_transport_destination(&signed(r).await)
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

    /// I1122-C — **a route an agent key published before v61 is swept.** A
    /// route admitted while its key was not held (so it could not be typed),
    /// then the key arrives as an agent: the sweep deletes it and counts one;
    /// a second sweep counts none.
    pub(crate) async fn i1122_c_the_sweep_removes_agent_routes(
        d: &dyn FederationDirectory,
        tag: &str,
    ) {
        let agent = format!("{tag}-lateagent");
        let dest = format!("{tag}late");
        let r = route(&agent, &dest, 1, "2026-10-22T00:00:00.000Z");
        d.put_transport_destination(&r)
            .await
            .expect("I1122-C: an untyped key's local route is admitted");
        ts::register_identity_key(d, &agent, AGENT).await;
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
        let identity = format!("{tag}-occid");
        ts::register_identity_key(d, &identity, USER).await;
        for (occ, ty, want) in [
            (format!("{tag}-occnode"), NODE, 1usize),
            (format!("{tag}-occagent"), AGENT, 0usize),
        ] {
            ts::register_identity_key(d, &occ, ty).await;
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
            d.put_identity_occurrence_local(row)
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
                async fn i1122_b_a_tied_newer_route_displaces() {
                    let Some(b) = $make.await else { return };
                    super::super::bodies::i1122_b_a_tied_newer_route_displaces(&b, &super::tag())
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
