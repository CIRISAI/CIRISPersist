//! v61 S2 (CIRISPersist#1165; Eric 2026-10-30, CIRISConstitution#196) —
//! **I1510: an owner's contact grant reaches an infrastructure relay, and
//! only there.** sqlite and postgres.
//!
//! The relay arm of `may_receive` (decided before "a node receives only its
//! own allow list"): a `consent:replication` grant FOR the owner's machine
//! whose subjects are NODES, signed by that machine's owner, reaches an
//! UNOWNED key on the `Canonical` serve rung as THIS node resolves it
//! (`infra:serve` from a root this node trusts). The rung is driven over a
//! test accord roster through `contact_grant_relay_over_roster` (the
//! production roster's halves live in the hardware ceremony); everything
//! else is real rows on the directory.
//!
//! Refused: a sibling unowned node with no serve rung; an owned server; a
//! grant whose attester is not the machine's owner; a grant whose subject is
//! not a node. Through the production `may_receive` with no node key
//! declared, the grant still goes no further than its machine (arm 4).

#[cfg(all(test, any(feature = "sqlite", feature = "postgres")))]
pub(crate) mod bodies {
    use crate::federation::operational::test_support::{
        naming_the_attach_head, register_accord_holder, register_typed_key,
        signed_canonical_record_with_roles, signed_trust_attestation, Identity,
    };
    use crate::federation::replication_audience::{contact_grant_relay_over_roster, may_receive};
    use crate::federation::tier_ingest::test_support as ts;
    use crate::federation::trust_root::INFRA_SERVE_SCOPE;
    use crate::federation::types::{attestation_type, identity_type};
    use crate::federation::{Attestation, FederationDirectory, SignedAttestation};
    use serde_json::json;

    /// A canonical relay `canonical`, accord-conferred `infra:serve` over a
    /// 2-of-3 test roster, that `me` (a node) trusts by its own edge.
    async fn seed_relay(
        d: &dyn FederationDirectory,
        tag: &str,
        me: &str,
        canonical: &str,
    ) -> Vec<String> {
        register_typed_key(d, me, identity_type::NODE)
            .await
            .unwrap();
        let holders = [
            Identity::new(&format!("{tag}-ch0")),
            Identity::new(&format!("{tag}-ch1")),
            Identity::new(&format!("{tag}-ch2")),
        ];
        for h in &holders {
            register_accord_holder(d, h).await.unwrap();
        }
        let roster: Vec<String> = holders.iter().map(|h| h.key_id.clone()).collect();
        let (ed_pk, mldsa_pk) = ts::hybrid_pubkeys(canonical);
        let record = signed_canonical_record_with_roles(
            canonical,
            identity_type::NODE,
            &ed_pk,
            mldsa_pk.as_deref(),
            vec![INFRA_SERVE_SCOPE.to_owned()],
            json!({ "key_id": canonical, "conferred_by": tag }),
            &[&holders[0], &holders[1]],
        );
        d.put_public_key(crate::federation::types::SignedKeyRecord { record })
            .await
            .unwrap();
        let charter_id = uuid::Uuid::new_v4().to_string();
        let successors = vec![format!("{canonical}-succ-a"), format!("{canonical}-succ-b")];
        let commitment =
            crate::federation::trust_root::test_pre_rotation_commitment(&successors).unwrap();
        d.put_attestation(SignedAttestation {
            attestation: signed_trust_attestation(
                &charter_id,
                canonical,
                canonical,
                attestation_type::DELEGATES_TO,
                json!({
                    "references_attestation_id": charter_id,
                    "dimension": crate::federation::trust_root::TRUST_CHARTER_DIMENSION,
                    "scope": [crate::federation::trust_root::INFRA_ATTEST_SCOPE, INFRA_SERVE_SCOPE],
                    "pre_rotation_commitment": commitment,
                }),
            ),
        })
        .await
        .unwrap();
        let la = format!("{canonical}-la");
        register_typed_key(d, &la, identity_type::ACCORD_HOLDER)
            .await
            .unwrap();
        let lc_id = uuid::Uuid::new_v4().to_string();
        d.put_attestation(SignedAttestation {
            attestation: signed_trust_attestation(
                &lc_id,
                &la,
                canonical,
                attestation_type::SCORES,
                json!({
                    "id": lc_id,
                    "dimension": crate::federation::trust_root::ACCORD_HEARTBEAT_DIMENSION,
                    "score": 1.0,
                    "confidence": 0.9,
                }),
            ),
        })
        .await
        .unwrap();
        let edge_id = uuid::Uuid::new_v4().to_string();
        d.put_attestation(SignedAttestation {
            attestation: signed_trust_attestation(
                &edge_id,
                me,
                canonical,
                attestation_type::DELEGATES_TO,
                naming_the_attach_head(
                    d,
                    canonical,
                    json!({
                        "id": edge_id,
                        "dimension": crate::federation::trust_root::TRUST_ACCEPTS_DIMENSION,
                        "scope": [INFRA_SERVE_SCOPE],
                    }),
                )
                .await,
            ),
        })
        .await
        .unwrap();
        roster
    }

    /// `owner`'s contact grant FOR `machine`, naming `subject`.
    fn contact_grant(owner: &str, machine: &str, subject: &str) -> Attestation {
        let envelope = json!({
            "dimension": crate::federation::consent_grammar::GRANT_DIMENSION,
            "for_key_id": machine,
            "subject_key_ids": [subject],
        });
        let mut r =
            ts::bare_attestation(&uuid::Uuid::new_v4().to_string(), owner, owner, &envelope);
        r.attestation_type = attestation_type::SCORES.to_owned();
        r.weight = None;
        r.subject_key_ids = vec![subject.to_owned()];
        ts::seal_row_in_place(owner, &mut r);
        r
    }

    async fn own(d: &dyn FederationDirectory, owner: &str, node: &str) {
        d.put_attestation(SignedAttestation {
            attestation: ts::owner_binding_attestation(
                &uuid::Uuid::new_v4().to_string(),
                owner,
                node,
            ),
        })
        .await
        .unwrap_or_else(|e| panic!("I1510: {owner} owns {node}: {e}"));
    }

    /// **I1510** — the contact grant at the relay.
    pub(crate) async fn i1510_a_contact_grant_reaches_the_relay_only(
        d: &dyn FederationDirectory,
        s: &str,
    ) {
        let k = |n: &str| format!("i1510-{n}-{s}");
        let (me, canonical, owner, machine, contact, sibling, owned_server, owner2, stranger) = (
            k("me"),
            k("canonical"),
            k("owner"),
            k("machine"),
            k("contact"),
            k("sibling"),
            k("owned-server"),
            k("owner2"),
            k("stranger"),
        );
        let roster = seed_relay(d, &k("r"), &me, &canonical).await;
        ts::register_hybrid_key_as(d, &owner, &owner, identity_type::USER).await;
        ts::register_hybrid_key_as(d, &owner2, &owner2, identity_type::USER).await;
        ts::register_hybrid_key_as(d, &stranger, &stranger, identity_type::USER).await;
        for n in [&machine, &contact, &sibling] {
            register_typed_key(d, n, identity_type::NODE).await.unwrap();
        }
        register_typed_key(d, &owned_server, "node,infra:serve")
            .await
            .unwrap();
        own(d, &owner, &machine).await;
        own(d, &owner2, &owned_server).await;
        let relay = |grant: Attestation, recipient: String| {
            let roster = roster.clone();
            let me = me.clone();
            let machine = machine.clone();
            async move {
                contact_grant_relay_over_roster(d, &me, &recipient, &grant, &machine, &roster)
                    .await
                    .expect("I1510: the relay predicate")
            }
        };
        let g = contact_grant(&owner, &machine, &contact);
        assert!(
            relay(g.clone(), canonical.clone()).await,
            "I1510: the canonical relay this node trusts receives the owner's contact grant"
        );
        assert!(
            !relay(g.clone(), sibling.clone()).await,
            "I1510: an unowned node with no serve rung does not"
        );
        assert!(
            !relay(g.clone(), owned_server.clone()).await,
            "I1510: an OWNED server does not"
        );
        assert!(
            !relay(
                contact_grant(&stranger, &machine, &contact),
                canonical.clone()
            )
            .await,
            "I1510: a grant the machine's owner did not sign does not reach it"
        );
        assert!(
            !relay(
                contact_grant(&owner, &machine, &stranger),
                canonical.clone()
            )
            .await,
            "I1510: a grant whose subject is not a node is not a contact grant"
        );
        // The production arm, on a directory that has not been told who it
        // is: the grant reaches its machine and goes no further.
        assert!(may_receive(d, &machine, &g).await.unwrap().allowed());
        assert!(
            !may_receive(d, &canonical, &g).await.unwrap().allowed(),
            "I1510: with no node key declared no relay rung can be resolved"
        );
        assert!(!may_receive(d, &sibling, &g).await.unwrap().allowed());
    }
}

#[cfg(all(test, any(feature = "sqlite", feature = "postgres")))]
mod runners {
    fn suffix() -> String {
        uuid::Uuid::new_v4().simple().to_string()[..12].to_owned()
    }

    #[cfg(feature = "sqlite")]
    #[tokio::test]
    async fn i1510_a_contact_grant_reaches_the_relay_only_sqlite() {
        use crate::store::Backend as _;
        let b = crate::store::sqlite::SqliteBackend::open_in_memory()
            .await
            .unwrap();
        b.run_migrations().await.unwrap();
        super::bodies::i1510_a_contact_grant_reaches_the_relay_only(&b, &suffix()).await;
    }

    #[cfg(feature = "postgres")]
    #[tokio::test]
    async fn i1510_a_contact_grant_reaches_the_relay_only_postgres() {
        use crate::store::Backend as _;
        let Some(dsn) = crate::test_pg::empty_dsn() else {
            return;
        };
        let b = crate::store::postgres::PostgresBackend::connect(&dsn)
            .await
            .unwrap();
        b.run_migrations().await.unwrap();
        super::bodies::i1510_a_contact_grant_reaches_the_relay_only(&b, &suffix()).await;
    }
}
