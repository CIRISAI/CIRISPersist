//! v52.0.0 (CIRISPersist#930) — **the occurrence plane keeps every
//! assertion**, so a verdict at an earlier instant never moves when a later
//! assertion lands (FSD `SECOND_DEVICE.md` §8.5).
//!
//! v62.0.0 (O1 fix 10; CP2) — restated over EDITION-2 binds (CC 3.3.6: one
//! `identity:occurrence` row carries the occurrence key's own voice and the
//! identity's, so "agreement" is the bind's own voice, at the bind's signed
//! instant) and edition-2 `identity:occurrence_revocation` rows. Each bind is
//! one entry of the V161 history (written by the edition-2 transaction
//! helper); the verdicts read that history.
//!
//! - **I270** — a renewal does not move an earlier verdict.
//! - **I271** — DELETED at v62.0.0 (red round 3, X1): "the identity
//!   re-signing the pair" is the earlier form's own act; every edition-2 bind
//!   carries the occurrence's own voice (O1, CC 3.3.6), so it cannot be stated.
//! - **I272** — DELETED at v62.0.0 (O1 fix 10): "the identity claims at t0,
//!   the occurrence agrees later at t2" is the earlier form's split of one
//!   binding into two rows. An edition-2 bind is ONE row whose two voices sign
//!   one payload (one instant); the identity's statement without the
//!   occurrence key's own binds nothing at all (O1's I3022 witnesses that).
//! - **I273** — a revocation still ends each interval (the #421
//!   re-establishment rule, per assertion).
//! - **I274** — an older bind arriving after a newer one lands in the history
//!   and counts; the current-state row is unchanged.
//! - **I275** — the V161 backfill: the migration's copy of the current rows
//!   restores the history the fold reads.
//! - **I276** — `node_bearing_at_with_next` names the next historical edge.
//! - **I278** — a trusted-local row is history, never agreement.
//!
//! I277 (the adopter-shaped roster judgement) lives in `rc5_adopts_invariants`
//! beside the infrastructure-room helpers it needs; I279 (the fail-open
//! provenance token) in `self_at_login`. Every body runs on sqlite and
//! postgres.

#[cfg(any(feature = "sqlite", feature = "postgres"))]
pub(crate) mod bodies {
    use crate::federation::edition2::fixture_switch as e2;
    use crate::federation::edition2::ingest::StatementOutcome;
    use crate::federation::types::identity_type as it;
    use crate::federation::types::IdentityOccurrenceRevocation;
    use crate::federation::{
        is_node_bearing_key_at, node_bearing_at_with_next, FederationDirectory,
    };
    use chrono::{DateTime, Duration, Utc};

    fn ago(secs: i64) -> DateTime<Utc> {
        let t = Utc::now() - Duration::seconds(secs);
        DateTime::<Utc>::from_timestamp_millis(t.timestamp_millis()).expect("ms")
    }

    /// The seeds and kids of a node identity and an install key (E0
    /// edition-2 `key:record`s; a node key's default window covers now).
    struct Keys {
        node_s: String,
        install_s: String,
        node: String,
        install: String,
    }

    async fn keys(d: &dyn FederationDirectory, tag: &str) -> Keys {
        let (node_s, install_s) = (format!("node-id-{tag}"), format!("install-{tag}"));
        e2::put_key(d, &node_s, &[it::NODE]).await;
        e2::put_key(d, &install_s, &[it::PRIMITIVE]).await;
        Keys {
            node: e2::kid(&node_s),
            install: e2::kid(&install_s),
            node_s,
            install_s,
        }
    }

    /// An edition-2 bind of the install key under the node, signed at `t`:
    /// the install key's own voice, then the node's (O1's door, CC 3.3.6).
    async fn bind(d: &dyn FederationDirectory, k: &Keys, t: DateTime<Utc>) {
        let opts = e2::BindOptions {
            asserted_at_ms: e2::ms(t),
            ..e2::BindOptions::default()
        };
        let out = e2::put_bind(d, &k.node_s, &k.node_s, &k.install_s, "server", &opts).await;
        assert!(
            matches!(out, Ok(StatementOutcome::Row { .. })),
            "bind {} under {} at {t}: {out:?}",
            k.install_s,
            k.node_s
        );
    }

    /// The node's edition-2 revocation of the install's occurrence, effective
    /// at `at` (a node identity's revocation is its own single signer's).
    async fn revoke(d: &dyn FederationDirectory, k: &Keys, at: DateTime<Utc>) {
        let rev = IdentityOccurrenceRevocation {
            identity_key_id: k.node.clone(),
            occurrence_key_id: k.install.clone(),
            revoked_at: at,
            effective_at: at,
            reason: None,
            witness_set: Vec::new(),
            persist_row_hash: String::new(),
        };
        let voice =
            e2::occurrence_revocation_voice(d, &k.node_s, true, &rev, None, &[], &[], e2::ms(at))
                .await;
        let out = e2::put_statement(d, &voice).await;
        assert!(
            matches!(out, Ok(StatementOutcome::Row { .. })),
            "revoke {} at {at}: {out:?}",
            k.install_s
        );
    }

    async fn bearing(d: &dyn FederationDirectory, k: &str, t: DateTime<Utc>) -> bool {
        is_node_bearing_key_at(d, k, t).await.expect("fold")
    }

    pub(crate) async fn i270_a_renewal_does_not_move_an_earlier_verdict(
        d: &dyn FederationDirectory,
        tag: &str,
    ) {
        let k = keys(d, tag).await;
        bind(d, &k, ago(300)).await;
        assert!(
            bearing(d, &k.install, ago(200)).await,
            "{tag} I270: bearing at t1"
        );
        // The pair is bound again later (a renewal: a newer bind).
        bind(d, &k, ago(100)).await;
        assert!(
            bearing(d, &k.install, ago(200)).await,
            "{tag} I270: a renewal at t3 moved the verdict at t1 < t3"
        );
        assert!(
            bearing(d, &k.install, ago(10)).await,
            "{tag} I270: bearing now"
        );
    }

    pub(crate) async fn i273_a_revocation_ends_each_interval(
        d: &dyn FederationDirectory,
        tag: &str,
    ) {
        let k = keys(d, tag).await;
        bind(d, &k, ago(300)).await;
        revoke(d, &k, ago(200)).await;
        bind(d, &k, ago(100)).await;
        assert!(
            bearing(d, &k.install, ago(250)).await,
            "{tag} I273: bearing before the revocation"
        );
        assert!(
            !bearing(d, &k.install, ago(150)).await,
            "{tag} I273: the revocation ends the first interval"
        );
        assert!(
            bearing(d, &k.install, ago(50)).await,
            "{tag} I273: re-established after"
        );

        // (b) A revocation effective at EXACTLY a bind's instant ends that
        // bind (`effective_at >= asserted_at`, the #421 rule): a
        // re-establishment must be strictly later than the revocation.
        let kb = keys(d, &format!("{tag}-b")).await;
        bind(d, &kb, ago(300)).await;
        let at = ago(200);
        bind(d, &kb, at).await;
        revoke(d, &kb, at).await;
        assert!(
            !bearing(d, &kb.install, ago(150)).await,
            "{tag} I273(b): a revocation at a bind's own instant ends it"
        );
    }

    pub(crate) async fn i274_an_older_assertion_arriving_late_counts(
        d: &dyn FederationDirectory,
        tag: &str,
    ) {
        let k = keys(d, tag).await;
        let older = ago(300);
        bind(d, &k, ago(100)).await;
        let current_before = d
            .list_identity_occurrences_by_occurrence_key(&k.install)
            .await
            .unwrap();
        // An OLDER bind of the same pair arrives after the newer one.
        bind(d, &k, older).await;
        assert_eq!(
            d.list_identity_occurrences_by_occurrence_key(&k.install)
                .await
                .unwrap(),
            current_before,
            "{tag} I274: the current-state row is unchanged by an older bind"
        );
        let history = d
            .list_identity_occurrence_history_by_occurrence(&k.install)
            .await
            .unwrap();
        assert_eq!(
            history
                .first()
                .map(|a| (a.asserted_at, a.attesting_key_id.clone())),
            Some((older, Some(k.node.clone()))),
            "{tag} I274: the older bind is in the history, first (its author the node): \
             {history:?}"
        );
        assert!(
            bearing(d, &k.install, ago(200)).await,
            "{tag} I274: the older bind's interval counts"
        );
    }

    pub(crate) async fn i276_the_next_edge_is_historical(d: &dyn FederationDirectory, tag: &str) {
        let k = keys(d, tag).await;
        let (t0, t2) = (ago(300), ago(100));
        bind(d, &k, t0).await;
        bind(d, &k, t2).await;
        let (b, next) = node_bearing_at_with_next(d, &k.install, ago(200))
            .await
            .unwrap();
        assert!(b, "{tag} I276: bearing at t1");
        assert_eq!(
            next,
            Some(t2),
            "{tag} I276: the next edge is the renewal's start"
        );
    }

    pub(crate) async fn i278_a_trusted_local_row_is_history_not_agreement(
        d: &dyn FederationDirectory,
        tag: &str,
    ) {
        let k = keys(d, tag).await;
        d.test_seam_put_identity_occurrence(crate::federation::IdentityOccurrence {
            identity_key_id: k.node.clone(),
            occurrence_key_id: k.install.clone(),
            device_class: crate::federation::types::device_class::SERVER.into(),
            hardware_attestation: None,
            asserted_at: ago(300),
            valid_until: None,
            encryption_pubkeys: None,
            transport_binding: None,
            persist_row_hash: String::new(),
        })
        .await
        .unwrap();
        let history = d
            .list_identity_occurrence_history_by_occurrence(&k.install)
            .await
            .unwrap();
        assert_eq!(history.len(), 1, "{tag} I278: the local row is history");
        assert_eq!(history[0].attesting_key_id, None, "{tag} I278: unsigned");
        assert!(
            !bearing(d, &k.install, ago(200)).await,
            "{tag} I278: a trusted-local row is never agreement"
        );
        bind(d, &k, ago(100)).await;
        assert!(
            !bearing(d, &k.install, ago(200)).await,
            "{tag} I278: the local interval starts no earlier than the agreement"
        );
        assert!(
            bearing(d, &k.install, ago(50)).await,
            "{tag} I278: bearing after agreement"
        );
    }
}

#[cfg(all(test, any(feature = "sqlite", feature = "postgres")))]
mod runners {
    fn suffix() -> String {
        uuid::Uuid::new_v4().simple().to_string()[..10].to_owned()
    }
    macro_rules! runners {
        ($modname:ident, $fresh:expr) => {
            mod $modname {
                use super::super::bodies;
                use crate::federation::FederationDirectory;
                macro_rules! w {
                    ($name:ident) => {
                        #[tokio::test]
                        async fn $name() {
                            let Some(d) = $fresh.await else { return };
                            bodies::$name(&d as &dyn FederationDirectory, &super::suffix()).await
                        }
                    };
                }
                w!(i270_a_renewal_does_not_move_an_earlier_verdict);
                w!(i273_a_revocation_ends_each_interval);
                w!(i274_an_older_assertion_arriving_late_counts);
                w!(i276_the_next_edge_is_historical);
                w!(i278_a_trusted_local_row_is_history_not_agreement);
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
