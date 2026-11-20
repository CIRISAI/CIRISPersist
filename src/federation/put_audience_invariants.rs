//! v61 S2 (CIRISPersist#1148) — **I1509: a replicated write refuses a row
//! this node is not in the audience for.** sqlite and postgres.
//!
//! On a directory that has declared its node key, every replicated door asks
//! the serve side's own question (`may_receive` for this node) before any
//! door runs: on a NON-member's node a private room's content row and its
//! record are refused and leave nothing behind; on a MEMBER's node the same
//! are admitted. A public room's record reaches a non-member. A TAMPERED copy
//! of the room's row is verified first and refused, never `not_in_audience`
//! (the verdict is not asked of unverified bytes).
//!
//! I1625 (v61.1.0, CIRISPersist#1188) — a family's record names its own
//! audience: on a node that holds nothing of the family, a node owned by a
//! member the record lists receives it; a stranger's node does not.
//!
//! v62.0.0 (wave 3, slice E6) — the planes are edition 2. Keys are
//! `key:record`s named by kid; a content row is an edition-2 row (its JSON
//! door, `apply_replicated_attestation` / `put_attestation_synced`, still
//! takes a row carrying its statement, with the audience gate in front);
//! a group's record and membership events are T1's counted voices, and they
//! travel as STATEMENTS (`edition2_statements_since` →
//! `apply_replicated_statement`, [`sync`]). **The record legs that expect a
//! refusal on a non-audience node DEPEND ON an audience gate at the
//! edition-2 replicated door**: T1.md ("`apply_replicated_community`'s
//! `not_in_audience` / degrade outcomes are not applied to statements") and
//! base `edition2/` run no `may_receive`. Those asserts are marked
//! "DEPENDS ON THE EDITION-2 AUDIENCE GATE"; they are red until it exists.

/// Deliver every statement `from` holds to `to`, in `from`'s admission
/// order, through the replicated statement door (`apply_replicated_statement`
/// under each statement's computed row id). A statement waiting on a key
/// `to` does not yet hold is retried on the next pass; a refusal is the
/// receiving door's verdict and is left as it is.
#[cfg(all(test, any(feature = "sqlite", feature = "postgres")))]
pub(crate) async fn sync(
    from: &dyn crate::federation::FederationDirectory,
    to: &dyn crate::federation::FederationDirectory,
) {
    use crate::federation::edition2::ingest::apply_replicated_statement;
    use crate::federation::edition2::names::RowId;
    let mut statements = Vec::new();
    let mut cursor = None;
    loop {
        let page = from
            .edition2_statements_since(cursor.as_ref(), 1000)
            .await
            .expect("the source serves its statements");
        let Some(last) = page.last() else { break };
        cursor = Some(last.cursor);
        statements.extend(page.into_iter().map(|s| s.bytes));
    }
    for _ in 0..3 {
        let mut waiting = Vec::new();
        for st in statements {
            let Some(id) = RowId::of_statement(&st) else {
                continue;
            };
            if let Err(e) = Box::pin(apply_replicated_statement(to, &st, &id.0)).await {
                if e.kind() == "federation_attester_key_unknown" {
                    waiting.push(st);
                }
            }
        }
        if waiting.is_empty() {
            break;
        }
        statements = waiting;
    }
}

#[cfg(all(test, any(feature = "sqlite", feature = "postgres")))]
pub(crate) mod bodies {
    use super::sync;
    use crate::federation::attestation_apply::{
        AttestationRefusalReason, ReplicatedAttestationOutcome,
    };
    use crate::federation::edition2::fixture_switch as e2;
    use crate::federation::membership_acceptance_invariants::bodies::{
        found_community, found_public_room, reg,
    };
    use crate::federation::tier_ingest::test_support as ts;
    use crate::federation::types::{attestation_type, cohort_scope};
    use crate::federation::{Attestation, FederationDirectory, SignedAttestation};

    /// The member key (seed) of `tag`'s fixture.
    pub(crate) fn member(tag: &str) -> String {
        format!("i1509-member-{tag}")
    }
    /// The non-member key (seed) of `tag`'s fixture.
    pub(crate) fn stranger(tag: &str) -> String {
        format!("i1509-stranger-{tag}")
    }

    fn room_row(author: &str, room: &str) -> Attestation {
        let env = serde_json::json!({
            "dimension": "trust:demo:v1",
            "score": crate::federation::namespace::registry::in_class_score("trust:demo:v1"),
            "confidence": 0.9,
            "community_key_id": e2::kid_or_keep(room),
        });
        let mut r =
            { ts::bare_attestation(&uuid::Uuid::new_v4().to_string(), author, author, &env) };
        r.attestation_type = attestation_type::SCORES.into();
        r.weight = None;
        r.cohort_scope = cohort_scope::COMMUNITY.into();
        e2::row_of(&r, author)
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
        let refused = ReplicatedAttestationOutcome::Refused {
            reason: AttestationRefusalReason::NotInAudience,
        };
        // A TAMPERED copy is verified before any audience verdict: an
        // audience answer over unverified bytes is a verdict about
        // attacker-chosen data. v62.0.0: the envelope no longer matches its
        // carried statement, whatever the token; it is an error, never the
        // audience refusal, and nothing is stored.
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
                        &e2::kid(&m),
                    )
                    .await,
            ),
        ] {
            assert!(
                e.is_err(),
                "I1509 {door}: a forged row is an error, never an audience outcome: {e:?}"
            );
        }
        assert!(outsider
            .get_attestation(&forged.attestation_id)
            .await
            .unwrap()
            .is_none());
        // The non-member's node: the content row's JSON doors refuse, by name.
        assert_eq!(
            outsider
                .apply_replicated_attestation(SignedAttestation {
                    attestation: content.clone(),
                })
                .await
                .expect("I1509: a typed outcome"),
            refused,
            "I1509: the content row on a non-member's node"
        );
        assert_eq!(
            outsider
                .put_attestation_synced(
                    SignedAttestation {
                        attestation: content.clone(),
                    },
                    &e2::kid(&m),
                )
                .await
                .expect("I1509: a typed outcome"),
            refused,
            "I1509: the synced door too"
        );
        assert!(outsider
            .get_attestation(&content.attestation_id)
            .await
            .unwrap()
            .is_none());
        assert!(
            !AttestationRefusalReason::NotInAudience.as_str().is_empty()
                && AttestationRefusalReason::NotInAudience.is_retryable(),
            "I1509: retryable — the audience can widen"
        );
        // The records travel as statements.
        sync(src, outsider).await;
        // DEPENDS ON THE EDITION-2 AUDIENCE GATE: the private room's record
        // never lands on a non-member's node.
        assert!(
            outsider
                .lookup_community(&e2::kid(&room))
                .await
                .unwrap()
                .is_none(),
            "I1509: the private room's record does not reach a non-member's node"
        );
        // A public room's record reaches the non-member.
        assert!(
            outsider
                .lookup_community(&e2::kid(&public))
                .await
                .unwrap()
                .is_some(),
            "I1509: a public room is everyone's audience"
        );
        // The member's node admits the record, then the content.
        sync(src, inside).await;
        assert!(
            inside
                .lookup_community(&e2::kid(&room))
                .await
                .unwrap()
                .is_some(),
            "I1509: the record names the member it seats"
        );
        assert!(
            matches!(
                inside
                    .apply_replicated_attestation(SignedAttestation {
                        attestation: content.clone(),
                    })
                    .await
                    .expect("I1509: member content"),
                ReplicatedAttestationOutcome::Inserted
            ) || inside
                .get_attestation(&content.attestation_id)
                .await
                .unwrap()
                .is_some(),
            "I1509: a member's node receives the room's rows"
        );
    }
}

#[cfg(all(test, any(feature = "sqlite", feature = "postgres")))]
pub(crate) mod invitee {
    use super::sync;
    use crate::federation::edition2::fixture_switch as e2;
    use crate::federation::membership_acceptance_invariants::bodies::{
        found_community, found_family, proposal, put, reg, reply, widen_community, widen_family,
    };
    use crate::federation::types::cohort_scope::{COMMUNITY, FAMILY};
    use crate::federation::FederationDirectory;
    use chrono::{Duration, Utc};

    /// The proposer's node key (seed) in `tag`'s fixture.
    pub(crate) fn proposer(tag: &str) -> String {
        format!("i1520-p-{tag}")
    }
    /// The invitee's node key (seed) in `tag`'s fixture.
    pub(crate) fn invitee(tag: &str) -> String {
        format!("i1520-q-{tag}")
    }

    async fn holds(d: &dyn FederationDirectory, scope: &str, group: &str) -> bool {
        let g = e2::kid(group);
        if scope == FAMILY {
            d.lookup_family(&g).await.unwrap().is_some()
        } else {
            d.lookup_community(&g).await.unwrap().is_some()
        }
    }

    /// **I1520** (v61.0.1, CIRISPersist#1193) — an invitee's node receives
    /// the group's record. A live, undeclined proposal naming one of the
    /// node's principals, authored by a member the offered record lists,
    /// puts the node in the record's audience before the node holds the
    /// group. `a` is P's node and `b` is Q's node.
    /// - family F founded by P alone: Q's node holds P's proposal, then F's
    ///   record, then the widening that seats Q once Q accepts;
    /// - the community twin;
    /// - a proposal authored by a NON-member of the offered record admits
    ///   nothing: that record does not land (DEPENDS ON THE EDITION-2
    ///   AUDIENCE GATE).
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
            sync(a, b).await;
            assert!(
                b.get_attestation(&invite.attestation_id)
                    .await
                    .unwrap()
                    .is_some(),
                "I1520 {scope}: Q's node holds the proposal naming Q"
            );
            assert!(
                holds(b, scope, group).await,
                "I1520 {scope}: Q's node receives the record while Q's proposal is live"
            );
            let accept = reply(&q, &q, &invite, true, now + Duration::seconds(1));
            put(b, &accept).await.expect("I1520: Q accepts on Q's node");
            sync(b, a).await;
            if scope == FAMILY {
                widen_family(a, group, &p, &q, None, now + Duration::seconds(2))
                    .await
                    .expect("I1520: P seats Q");
            } else {
                widen_community(a, group, &[&p], &q, None, now + Duration::seconds(2))
                    .await
                    .expect("I1520: P seats Q");
            }
            sync(a, b).await;
        }
        let qk = e2::kid(&q);
        assert!(
            b.active_family_members(&e2::kid(&fam))
                .await
                .unwrap()
                .iter()
                .any(|m| m.key_id == qk),
            "I1520: Q is seated in F on Q's node"
        );
        assert!(
            b.active_community_members(&e2::kid(&room))
                .await
                .unwrap()
                .iter()
                .any(|m| m.key_id == qk),
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
        sync(a, b).await;
        // DEPENDS ON THE EDITION-2 AUDIENCE GATE.
        assert!(
            !holds(b, FAMILY, &other).await,
            "I1520: a proposal no listed member authored admits no record"
        );
    }
}

#[cfg(all(test, any(feature = "sqlite", feature = "postgres")))]
pub(crate) mod family_events {
    use super::sync;
    use crate::federation::edition2::fixture_switch as e2;
    use crate::federation::group_plane::{
        GROUP_ROSTER_DIMENSION, MEMBERSHIP_REMOVAL_DIMENSION, MEMBERSHIP_RESIGNATION_DIMENSION,
        MEMBERSHIP_WIDENING_DIMENSION,
    };
    use crate::federation::membership_acceptance_invariants::bodies::{found_family, reg};
    use crate::federation::namespace::{projection_for, registry, Plane, Projection};
    use crate::federation::tier_ingest::test_support as ts;
    use crate::federation::types::cohort_scope::FAMILY;
    use crate::federation::types::FamilyMembershipRevocation;
    use crate::federation::FederationDirectory;
    use chrono::{Duration, Utc};

    /// The three members' node keys (seeds) in `tag`'s fixture.
    pub(crate) fn member(tag: &str, n: &str) -> String {
        format!("i1521-{n}-{tag}")
    }

    fn projection(dimension: &str) -> Projection {
        projection_for(
            Plane::Attestation { dimension },
            FAMILY,
            registry::authority_for(dimension).class,
            false,
        )
    }

    async fn seats(d: &dyn FederationDirectory, fam: &str, k: &str) -> bool {
        d.active_family_members(&e2::kid(fam))
            .await
            .unwrap()
            .iter()
            .any(|m| m.key_id == e2::kid(k))
    }

    /// **I1521** (v61.0.1, CIRISPersist#1182) — a family's record and its
    /// membership events reach every holder of the record. At `family` scope
    /// `group:roster:v1` projects `Cohort` and
    /// `membership:{widening,removal,resignation}:v1` project `Global`. Three
    /// members: P removes R on P's node; R's node holds the removal (it names
    /// R); Q's node, syncing only with R's node, receives the removal from
    /// R's node and Q's fold drops R. v62.0.0: the record and the removal are
    /// T1 voices, carried as statements ([`sync`]).
    pub(crate) async fn i1521_a_family_removal_reaches_every_holder(
        p_node: &dyn FederationDirectory,
        q_node: &dyn FederationDirectory,
        r_node: &dyn FederationDirectory,
        tag: &str,
    ) {
        assert_eq!(
            projection(GROUP_ROSTER_DIMENSION),
            Projection::Cohort,
            "I1521: a family's record is cohort-wide"
        );
        for dim in [
            MEMBERSHIP_WIDENING_DIMENSION,
            MEMBERSHIP_REMOVAL_DIMENSION,
            MEMBERSHIP_RESIGNATION_DIMENSION,
        ] {
            assert_eq!(
                projection(dim),
                Projection::Global,
                "I1521: a family's {dim} reaches every holder of the record"
            );
        }
        let (p, q, r) = (member(tag, "p"), member(tag, "q"), member(tag, "r"));
        let fam = format!("i1521-fam-{tag}");
        for d in [p_node, q_node, r_node] {
            reg(d, &[&p, &q, &r, &fam]).await;
        }
        found_family(p_node, &fam, "founder_only", &[&p, &q, &r], &[])
            .await
            .unwrap();
        for d in [q_node, r_node] {
            sync(p_node, d).await;
            assert!(
                seats(d, &fam, &r).await,
                "I1521: a listed member's node holds the record"
            );
        }
        let at = Utc::now() - Duration::minutes(5);
        let removal = ts::sign_family_membership_revocation(
            &p,
            FamilyMembershipRevocation {
                family_key_id: fam.clone(),
                removed_identity_key_id: r.clone(),
                removed_at: at,
                effective_at: at,
                reason: None,
                witness_set: vec![],
                persist_row_hash: String::new(),
            },
        );
        let (head, _) = e2::held_head(p_node, &e2::kid(&fam))
            .await
            .expect("I1521: P's node holds the family's head");
        e2::put_voices(p_node, &e2::family_revocation_voices(&removal, Some(&head)))
            .await
            .expect("I1521: P removes R");
        assert!(
            !seats(p_node, &fam, &r).await,
            "I1521: R leaves on P's node"
        );
        sync(p_node, r_node).await;
        assert!(
            !seats(r_node, &fam, &r).await,
            "I1521: R's node holds the removal that names R"
        );
        assert!(
            seats(q_node, &fam, &r).await,
            "I1521 precondition: Q's node still seats R"
        );
        // Q's node syncs only with R's node: the copy R's node holds.
        sync(r_node, q_node).await;
        assert!(!seats(q_node, &fam, &r).await, "I1521: Q's fold drops R");
    }

    /// The node key (seed) `n` of `tag`'s I1625 fixture.
    pub(crate) fn i1625_node(tag: &str, n: &str) -> String {
        format!("i1625-{n}-node-{tag}")
    }

    /// **I1625** (v61.1.0, CIRISPersist#1188; CC 6.1.5.3) — **a family's
    /// record names its own audience**. Node B holds nothing of the family
    /// and is a node owned by a member the record lists: B receives the
    /// record by the record alone. Node C is a stranger's node: it does not
    /// (DEPENDS ON THE EDITION-2 AUDIENCE GATE).
    pub(crate) async fn i1625_a_family_record_names_its_audience(
        a: &dyn FederationDirectory,
        b: &dyn FederationDirectory,
        c: &dyn FederationDirectory,
        tag: &str,
    ) {
        use crate::federation::types::identity_type::NODE;
        let k = |n: &str| format!("i1625-{n}-{tag}");
        let (p, q, x, fam) = (k("p"), k("q"), k("x"), k("fam"));
        let (q_node, x_node) = (i1625_node(tag, "q"), i1625_node(tag, "x"));
        for d in [a, b, c] {
            reg(d, &[&p, &q, &x, &fam]).await;
            for (owner, node) in [(&q, &q_node), (&x, &x_node)] {
                ts::register_identity_key(d, node, NODE).await;
                ts::put_owner_binding(d, owner, node).await;
            }
        }
        found_family(a, &fam, "founder_only", &[&p, &q], &[])
            .await
            .unwrap();
        assert!(
            b.lookup_family(&e2::kid(&fam)).await.unwrap().is_none(),
            "I1625 precondition: B holds nothing of the family"
        );
        sync(a, b).await;
        assert!(
            b.lookup_family(&e2::kid(&fam)).await.unwrap().is_some(),
            "I1625: a listed member's node receives the family record on its own audience"
        );
        sync(a, c).await;
        // DEPENDS ON THE EDITION-2 AUDIENCE GATE.
        assert!(
            c.lookup_family(&e2::kid(&fam)).await.unwrap().is_none(),
            "I1625: a stranger's node does not"
        );
    }
}

#[cfg(all(test, any(feature = "sqlite", feature = "postgres")))]
mod runners {
    use crate::federation::edition2::fixture_switch as e2;

    fn suffix() -> String {
        uuid::Uuid::new_v4().simple().to_string()[..12].to_owned()
    }

    #[cfg(feature = "sqlite")]
    async fn sqlite() -> crate::store::sqlite::SqliteBackend {
        use crate::store::Backend as _;
        let b = crate::store::sqlite::SqliteBackend::open_in_memory()
            .await
            .unwrap();
        b.run_migrations().await.unwrap();
        b
    }

    #[cfg(feature = "postgres")]
    async fn postgres() -> Option<crate::store::postgres::PostgresBackend> {
        use crate::store::Backend as _;
        let dsn = crate::test_pg::empty_dsn()?;
        let b = crate::store::postgres::PostgresBackend::connect(&dsn)
            .await
            .unwrap();
        b.run_migrations().await.unwrap();
        Some(b)
    }

    #[cfg(feature = "sqlite")]
    #[tokio::test]
    async fn i1509_a_replicated_write_needs_the_audience_sqlite() {
        let tag = suffix();
        let (src, out, ins) = (sqlite().await, sqlite().await, sqlite().await);
        out.set_node_key_id(e2::kid(&super::bodies::stranger(&tag)));
        ins.set_node_key_id(e2::kid(&super::bodies::member(&tag)));
        super::bodies::i1509_a_replicated_write_needs_the_audience(&src, &out, &ins, &tag).await;
    }

    #[cfg(feature = "postgres")]
    #[tokio::test]
    async fn i1509_a_replicated_write_needs_the_audience_postgres() {
        let tag = suffix();
        let (Some(src), Some(out), Some(ins)) =
            (postgres().await, postgres().await, postgres().await)
        else {
            return;
        };
        out.set_node_key_id(e2::kid(&super::bodies::stranger(&tag)));
        ins.set_node_key_id(e2::kid(&super::bodies::member(&tag)));
        super::bodies::i1509_a_replicated_write_needs_the_audience(&src, &out, &ins, &tag).await;
        eprintln!("i1509 postgres: RAN");
    }

    #[cfg(feature = "sqlite")]
    #[tokio::test]
    async fn i1520_an_invitee_receives_the_record_sqlite() {
        let tag = suffix();
        let (a, b) = (sqlite().await, sqlite().await);
        a.set_node_key_id(e2::kid(&super::invitee::proposer(&tag)));
        b.set_node_key_id(e2::kid(&super::invitee::invitee(&tag)));
        super::invitee::i1520_an_invitee_receives_the_record(&a, &b, &tag).await;
    }

    #[cfg(feature = "postgres")]
    #[tokio::test]
    async fn i1520_an_invitee_receives_the_record_postgres() {
        let tag = suffix();
        let (Some(a), Some(b)) = (postgres().await, postgres().await) else {
            return;
        };
        a.set_node_key_id(e2::kid(&super::invitee::proposer(&tag)));
        b.set_node_key_id(e2::kid(&super::invitee::invitee(&tag)));
        super::invitee::i1520_an_invitee_receives_the_record(&a, &b, &tag).await;
        eprintln!("i1520 postgres: RAN");
    }

    #[cfg(feature = "sqlite")]
    #[tokio::test]
    async fn i1521_a_family_removal_reaches_every_holder_sqlite() {
        use super::family_events::member;
        let tag = suffix();
        let (p, q, r) = (sqlite().await, sqlite().await, sqlite().await);
        p.set_node_key_id(e2::kid(&member(&tag, "p")));
        q.set_node_key_id(e2::kid(&member(&tag, "q")));
        r.set_node_key_id(e2::kid(&member(&tag, "r")));
        super::family_events::i1521_a_family_removal_reaches_every_holder(&p, &q, &r, &tag).await;
    }

    #[cfg(feature = "postgres")]
    #[tokio::test]
    async fn i1521_a_family_removal_reaches_every_holder_postgres() {
        use super::family_events::member;
        let tag = suffix();
        let (Some(p), Some(q), Some(r)) = (postgres().await, postgres().await, postgres().await)
        else {
            return;
        };
        p.set_node_key_id(e2::kid(&member(&tag, "p")));
        q.set_node_key_id(e2::kid(&member(&tag, "q")));
        r.set_node_key_id(e2::kid(&member(&tag, "r")));
        super::family_events::i1521_a_family_removal_reaches_every_holder(&p, &q, &r, &tag).await;
        eprintln!("i1521 postgres: RAN");
    }

    #[cfg(feature = "sqlite")]
    #[tokio::test]
    async fn i1625_a_family_record_names_its_audience_sqlite() {
        use super::family_events::i1625_node;
        let tag = suffix();
        let (a, b, c) = (sqlite().await, sqlite().await, sqlite().await);
        b.set_node_key_id(e2::kid(&i1625_node(&tag, "q")));
        c.set_node_key_id(e2::kid(&i1625_node(&tag, "x")));
        super::family_events::i1625_a_family_record_names_its_audience(&a, &b, &c, &tag).await;
    }

    #[cfg(feature = "postgres")]
    #[tokio::test]
    async fn i1625_a_family_record_names_its_audience_postgres() {
        use super::family_events::i1625_node;
        let tag = suffix();
        let (Some(a), Some(b), Some(c)) = (postgres().await, postgres().await, postgres().await)
        else {
            return;
        };
        b.set_node_key_id(e2::kid(&i1625_node(&tag, "q")));
        c.set_node_key_id(e2::kid(&i1625_node(&tag, "x")));
        super::family_events::i1625_a_family_record_names_its_audience(&a, &b, &c, &tag).await;
        eprintln!("i1625 postgres: RAN");
    }
}
