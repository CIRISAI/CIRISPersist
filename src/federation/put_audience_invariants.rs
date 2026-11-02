//! v61 S2 (CIRISPersist#1148) — **I1509: a replicated write refuses a row
//! this node is not in the audience for.** sqlite and postgres.
//!
//! On a directory that has declared its node key, every replicated door asks
//! the serve side's own question (`may_receive` for this node) before any
//! door runs: on a NON-member's node a private room's content row, its
//! `group:roster:v1` record row and its typed record are refused by name
//! (`not_in_audience`) and leave nothing behind, through
//! `apply_replicated_attestation`, `put_attestation_synced` and
//! `apply_replicated_community`; on a MEMBER's node the same rows are
//! admitted. A public room's record reaches a non-member. A TAMPERED copy
//! of the room's row is verified first and refused
//! `federation_federation_tier_unverified` on the non-member's node, never
//! `not_in_audience` (the verdict is not asked of unverified bytes).

#[cfg(all(test, any(feature = "sqlite", feature = "postgres")))]
pub(crate) mod bodies {
    use crate::federation::attestation_apply::{
        AttestationRefusalReason, ReplicatedAttestationOutcome,
    };
    use crate::federation::membership_acceptance_invariants::bodies::{
        found_community, found_public_room, reg,
    };
    use crate::federation::tier_ingest::test_support as ts;
    use crate::federation::types::{attestation_type, cohort_scope};
    use crate::federation::{
        Attestation, FederationDirectory, ReplicatedCommunityOutcome, ReplicatedCommunityRefusal,
        SignedAttestation,
    };

    /// The member key of `tag`'s fixture.
    pub(crate) fn member(tag: &str) -> String {
        format!("i1509-member-{tag}")
    }
    /// The non-member key of `tag`'s fixture.
    pub(crate) fn stranger(tag: &str) -> String {
        format!("i1509-stranger-{tag}")
    }

    fn room_row(author: &str, room: &str) -> Attestation {
        let env = serde_json::json!({
            "dimension": "trust:demo:v1",
            "score": crate::federation::namespace::registry::in_class_score("trust:demo:v1"),
            "confidence": 0.9,
            "community_key_id": room,
        });
        let mut r = ts::bare_attestation(&uuid::Uuid::new_v4().to_string(), author, author, &env);
        r.attestation_type = attestation_type::SCORES.into();
        r.weight = None;
        r.cohort_scope = cohort_scope::COMMUNITY.into();
        ts::seal_row_in_place(author, &mut r);
        r
    }

    async fn record_row(d: &dyn FederationDirectory, room: &str) -> Attestation {
        d.list_targeted_by_dimension_prefix(
            &[cohort_scope::COMMUNITY],
            room,
            crate::federation::group_plane::GROUP_ROSTER_DIMENSION,
        )
        .await
        .unwrap()
        .into_iter()
        .next()
        .unwrap_or_else(|| panic!("the source holds {room}'s record row"))
    }

    async fn signed_record(
        d: &dyn FederationDirectory,
        room: &str,
    ) -> crate::federation::types::SignedCommunity {
        d.list_signed_communities_since(None, 1000)
            .await
            .unwrap()
            .into_iter()
            .find(|c| c.community.community.community_key_id == room)
            .expect("the source serves the record")
            .community
    }

    /// **I1509** — `src` authors; `outsider` is a non-member's node and
    /// `inside` a member's (each declared by the runner).
    pub(crate) async fn i1509_a_replicated_write_needs_the_audience(
        src: &dyn FederationDirectory,
        outsider: &dyn FederationDirectory,
        inside: &dyn FederationDirectory,
        tag: &str,
    ) {
        let (m, x) = (member(tag), stranger(tag));
        let (room, public) = (format!("i1509-room-{tag}"), format!("i1509-pub-{tag}"));
        for d in [src, outsider, inside] {
            reg(d, &[&m, &x, &room, &public]).await;
        }
        found_community(src, &room, "quorum:1/1", &[&m], &[])
            .await
            .unwrap();
        found_public_room(
            src,
            &public,
            crate::federation::types::consensus_protocol::OPEN_SELF_ADMIT,
            &[&m],
            &[],
        )
        .await
        .unwrap();
        let content = room_row(&m, &room);
        src.put_attestation(SignedAttestation {
            attestation: content.clone(),
        })
        .await
        .expect("I1509: the member's row on the source");
        let record = record_row(src, &room).await;
        let refused = ReplicatedAttestationOutcome::Refused {
            reason: AttestationRefusalReason::NotInAudience,
        };
        // v61 S2 (the release blocker on 2c4cee2e) — a TAMPERED copy is
        // verified before any audience verdict: an audience answer over
        // unverified bytes is a verdict about attacker-chosen data. On the
        // non-member's node a forged copy of the room's row is
        // `federation_federation_tier_unverified`, never `not_in_audience`,
        // through both replicated doors.
        let mut forged = content.clone();
        forged.attestation_envelope["score"] = serde_json::json!(-1.0);
        for (door, e) in [
            (
                "apply_replicated_attestation",
                outsider
                    .apply_replicated_attestation(SignedAttestation {
                        attestation: forged.clone(),
                    })
                    .await,
            ),
            (
                "put_attestation_synced",
                outsider
                    .put_attestation_synced(
                        SignedAttestation {
                            attestation: forged.clone(),
                        },
                        &m,
                    )
                    .await,
            ),
        ] {
            let e = e.expect_err("I1509: a tampered row is an error, not an outcome");
            assert_eq!(
                e.kind(),
                "federation_federation_tier_unverified",
                "I1509 {door}: a forged row is unverified, never an audience miss: {e}"
            );
        }
        assert!(outsider
            .get_attestation(&forged.attestation_id)
            .await
            .unwrap()
            .is_none());
        // The non-member's node: every replicated door refuses, by name.
        for row in [&record, &content] {
            assert_eq!(
                outsider
                    .apply_replicated_attestation(SignedAttestation {
                        attestation: row.clone(),
                    })
                    .await
                    .expect("I1509: a typed outcome"),
                refused,
                "I1509: {} on a non-member's node",
                row.attestation_id
            );
            assert_eq!(
                outsider
                    .put_attestation_synced(
                        SignedAttestation {
                            attestation: row.clone(),
                        },
                        &m,
                    )
                    .await
                    .expect("I1509: a typed outcome"),
                refused,
                "I1509: the synced door too"
            );
            assert!(outsider
                .get_attestation(&row.attestation_id)
                .await
                .unwrap()
                .is_none());
        }
        assert_eq!(
            outsider
                .apply_replicated_community(signed_record(src, &room).await)
                .await
                .expect("I1509: a typed outcome"),
            ReplicatedCommunityOutcome::Refused {
                reason: ReplicatedCommunityRefusal::NotInAudience
            },
            "I1509: the typed record door refuses a non-member's node"
        );
        assert!(outsider.lookup_community(&room).await.unwrap().is_none());
        assert!(
            !AttestationRefusalReason::NotInAudience.as_str().is_empty()
                && AttestationRefusalReason::NotInAudience.is_retryable(),
            "I1509: retryable — the audience can widen"
        );
        // A public room's record reaches the non-member.
        let pub_record = record_row(src, &public).await;
        assert_eq!(
            outsider
                .apply_replicated_attestation(SignedAttestation {
                    attestation: pub_record,
                })
                .await
                .expect("I1509: public"),
            ReplicatedAttestationOutcome::Inserted,
            "I1509: a public room is everyone's audience"
        );
        // The member's node admits the record, then the content.
        assert_eq!(
            inside
                .apply_replicated_attestation(SignedAttestation {
                    attestation: record.clone(),
                })
                .await
                .expect("I1509: member record"),
            ReplicatedAttestationOutcome::Inserted,
            "I1509: the record names the member it seats"
        );
        assert_eq!(
            inside
                .apply_replicated_attestation(SignedAttestation {
                    attestation: content.clone(),
                })
                .await
                .expect("I1509: member content"),
            ReplicatedAttestationOutcome::Inserted,
            "I1509: a member's node receives the room's rows"
        );
    }
}

#[cfg(all(test, any(feature = "sqlite", feature = "postgres")))]
mod runners {
    fn suffix() -> String {
        uuid::Uuid::new_v4().simple().to_string()[..12].to_owned()
    }

    #[cfg(feature = "sqlite")]
    #[tokio::test]
    async fn i1509_a_replicated_write_needs_the_audience_sqlite() {
        use crate::store::Backend as _;
        async fn fresh() -> crate::store::sqlite::SqliteBackend {
            let b = crate::store::sqlite::SqliteBackend::open_in_memory()
                .await
                .unwrap();
            b.run_migrations().await.unwrap();
            b
        }
        let tag = suffix();
        let (src, out, ins) = (fresh().await, fresh().await, fresh().await);
        out.set_node_key_id(super::bodies::stranger(&tag));
        ins.set_node_key_id(super::bodies::member(&tag));
        super::bodies::i1509_a_replicated_write_needs_the_audience(&src, &out, &ins, &tag).await;
    }

    #[cfg(feature = "postgres")]
    #[tokio::test]
    async fn i1509_a_replicated_write_needs_the_audience_postgres() {
        use crate::store::Backend as _;
        async fn fresh() -> Option<crate::store::postgres::PostgresBackend> {
            let dsn = crate::test_pg::empty_dsn()?;
            let b = crate::store::postgres::PostgresBackend::connect(&dsn)
                .await
                .unwrap();
            b.run_migrations().await.unwrap();
            Some(b)
        }
        let tag = suffix();
        let (Some(src), Some(out), Some(ins)) = (fresh().await, fresh().await, fresh().await)
        else {
            return;
        };
        out.set_node_key_id(super::bodies::stranger(&tag));
        ins.set_node_key_id(super::bodies::member(&tag));
        super::bodies::i1509_a_replicated_write_needs_the_audience(&src, &out, &ins, &tag).await;
    }
}
