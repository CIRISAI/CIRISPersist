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
pub(crate) mod invitee {
    use crate::federation::attestation_apply::{
        AttestationRefusalReason, ReplicatedAttestationOutcome,
    };
    use crate::federation::group_plane::{GROUP_ROSTER_DIMENSION, MEMBERSHIP_WIDENING_DIMENSION};
    use crate::federation::membership_acceptance_invariants::bodies::{
        found_community, found_family, proposal, put, reg, reply, widen_community, widen_family,
    };
    use crate::federation::types::cohort_scope::{COMMUNITY, FAMILY};
    use crate::federation::{Attestation, FederationDirectory, SignedAttestation};
    use chrono::{Duration, Utc};

    /// The proposer's node key in `tag`'s fixture.
    pub(crate) fn proposer(tag: &str) -> String {
        format!("i1520-p-{tag}")
    }
    /// The invitee's node key in `tag`'s fixture.
    pub(crate) fn invitee(tag: &str) -> String {
        format!("i1520-q-{tag}")
    }

    async fn plane_row(
        d: &dyn FederationDirectory,
        scope: &str,
        group: &str,
        dimension: &str,
    ) -> Attestation {
        d.list_targeted_by_dimension_prefix(&[scope], group, dimension)
            .await
            .unwrap()
            .into_iter()
            .next()
            .unwrap_or_else(|| panic!("the source holds {group}'s {dimension} row"))
    }

    async fn carry(
        to: &dyn FederationDirectory,
        row: &Attestation,
    ) -> ReplicatedAttestationOutcome {
        to.apply_replicated_attestation(SignedAttestation {
            attestation: row.clone(),
        })
        .await
        .unwrap_or_else(|e| panic!("carry {}: {e}", row.attestation_id))
    }

    /// **I1520** (v61.0.1, CIRISPersist#1193) — an invitee's node receives
    /// the group's record. The record is self-certifying: its member list is
    /// verified on the door that judges it, so a live, undeclined proposal
    /// naming one of the node's principals, authored by a member the OFFERED
    /// record lists, puts the node in the record's audience before the node
    /// holds the group. `a` is P's node and `b` is Q's node.
    /// - family F founded by P alone: Q's node admits P's proposal, then F's
    ///   `group:roster:v1` row (it was `NotInAudience` on 61.0.0), then the
    ///   widening that seats Q once Q accepts;
    /// - the community twin;
    /// - a proposal authored by a NON-member of the offered record admits
    ///   nothing: that record stays `NotInAudience`.
    pub(crate) async fn i1520_an_invitee_receives_the_record(
        a: &dyn FederationDirectory,
        b: &dyn FederationDirectory,
        tag: &str,
    ) {
        let (p, q) = (proposer(tag), invitee(tag));
        let (x, fam, room, other) = (
            format!("i1520-x-{tag}"),
            format!("i1520-fam-{tag}"),
            format!("i1520-room-{tag}"),
            format!("i1520-other-{tag}"),
        );
        for d in [a, b] {
            reg(d, &[&p, &q, &x, &fam, &room, &other]).await;
        }
        // Every event in the past, so the seat is in force when it is read.
        let now = Utc::now() - Duration::minutes(10);
        found_family(a, &fam, "founder_only", &[&p], &[])
            .await
            .unwrap();
        found_community(a, &room, "quorum:1/1", &[&p], &[])
            .await
            .unwrap();
        for (scope, group) in [(FAMILY, &fam), (COMMUNITY, &room)] {
            let invite = proposal(&p, scope, group, &q, None, now, Some(Duration::days(7)));
            put(a, &invite).await.expect("I1520: P proposes Q");
            assert_eq!(
                carry(b, &invite).await,
                ReplicatedAttestationOutcome::Inserted,
                "I1520 {scope}: Q's node admits the proposal naming Q"
            );
            let record = plane_row(a, scope, group, GROUP_ROSTER_DIMENSION).await;
            assert_eq!(
                carry(b, &record).await,
                ReplicatedAttestationOutcome::Inserted,
                "I1520 {scope}: Q's node receives the record while Q's proposal is live"
            );
            let accept = reply(&q, &q, &invite, true, now + Duration::seconds(1));
            put(b, &accept).await.expect("I1520: Q accepts on Q's node");
            carry(a, &accept).await;
            if scope == FAMILY {
                widen_family(a, group, &p, &q, None, now + Duration::seconds(2))
                    .await
                    .expect("I1520: P seats Q");
            } else {
                widen_community(a, group, &[&p], &q, None, now + Duration::seconds(2))
                    .await
                    .expect("I1520: P seats Q");
            }
            let widening = plane_row(a, scope, group, MEMBERSHIP_WIDENING_DIMENSION).await;
            assert_eq!(
                carry(b, &widening).await,
                ReplicatedAttestationOutcome::Inserted,
                "I1520 {scope}: Q's node admits the widening that seats Q"
            );
        }
        assert!(
            b.active_family_members(&fam)
                .await
                .unwrap()
                .iter()
                .any(|m| m.key_id == q),
            "I1520: Q is seated in F on Q's node"
        );
        assert!(
            b.active_community_members(&room)
                .await
                .unwrap()
                .iter()
                .any(|m| m.key_id == q),
            "I1520: Q is seated in the room on Q's node"
        );
        // A proposal by X, who is not a member of the record offered.
        found_family(a, &other, "founder_only", &[&p], &[])
            .await
            .unwrap();
        let stray = proposal(&x, FAMILY, &other, &q, None, now, Some(Duration::days(7)));
        put(b, &stray)
            .await
            .expect("I1520: Q's node stores a proposal naming Q for a group it does not hold");
        let record = plane_row(a, FAMILY, &other, GROUP_ROSTER_DIMENSION).await;
        assert_eq!(
            carry(b, &record).await,
            ReplicatedAttestationOutcome::Refused {
                reason: AttestationRefusalReason::NotInAudience
            },
            "I1520: a proposal no listed member authored admits no record"
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

    #[cfg(feature = "sqlite")]
    #[tokio::test]
    async fn i1520_an_invitee_receives_the_record_sqlite() {
        use crate::store::Backend as _;
        async fn fresh() -> crate::store::sqlite::SqliteBackend {
            let b = crate::store::sqlite::SqliteBackend::open_in_memory()
                .await
                .unwrap();
            b.run_migrations().await.unwrap();
            b
        }
        let tag = suffix();
        let (a, b) = (fresh().await, fresh().await);
        a.set_node_key_id(super::invitee::proposer(&tag));
        b.set_node_key_id(super::invitee::invitee(&tag));
        super::invitee::i1520_an_invitee_receives_the_record(&a, &b, &tag).await;
    }

    #[cfg(feature = "postgres")]
    #[tokio::test]
    async fn i1520_an_invitee_receives_the_record_postgres() {
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
        let (Some(a), Some(b)) = (fresh().await, fresh().await) else {
            return;
        };
        a.set_node_key_id(super::invitee::proposer(&tag));
        b.set_node_key_id(super::invitee::invitee(&tag));
        super::invitee::i1520_an_invitee_receives_the_record(&a, &b, &tag).await;
        eprintln!("i1520 postgres: RAN");
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
