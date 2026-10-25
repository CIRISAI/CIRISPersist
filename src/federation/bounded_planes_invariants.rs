//! v56.0.0 (CIRISPersist#1001) — **I907–I912: each migrated plane's folds
//! read through the typed bounded query, bounded.**
//!
//! Every witness here lands NOISE on a key — third-party `scores` rows under a
//! dimension no fold reads (`i907noise:*`) — runs a migrated fold, and asks
//! the read probe two things about every read the fold made:
//!
//! 1. **Narrowed.** A fold that reads one family, type or dimension of a
//!    key's rows never reads the key's whole slice: no read keyed on the key
//!    answers as `list_attestations_for` / `_by` (see
//!    [`read_probe::Read::door`]), and the noise never comes back.
//! 2. **Paged.** Every typed read is one page: at most its limit rows, and
//!    its limit at most [`FOLD_PAGE`] (3 under `cfg(test)`). A fold that walks
//!    a whole slice walks it in pages and reads each row once.
//!
//! On memory, sqlite and postgres. The mutations recorded in the slice report
//! (dropping a fold's narrowing, ignoring the cursor) turn these red.
//!
//! [`FOLD_PAGE`]: crate::federation::attestation_query::FOLD_PAGE

#[cfg(all(test, any(feature = "sqlite", feature = "postgres")))]
pub(crate) mod bodies {
    use crate::federation::attestation_query::FOLD_PAGE;
    use crate::federation::read_probe::{self, Read};
    use crate::federation::tier_ingest::test_support as ts;
    use crate::federation::types::attestation_type;
    use crate::federation::{Attestation, FederationDirectory, SignedAttestation};

    /// Land `n` third-party `scores` rows by `author` about `subject` under
    /// dimensions no fold reads. Returns their ids.
    pub async fn noise(
        d: &dyn FederationDirectory,
        author: &str,
        subject: &str,
        n: usize,
    ) -> Vec<String> {
        let mut ids = Vec::new();
        for i in 0..n {
            let id = uuid::Uuid::new_v4().to_string();
            let env = serde_json::json!({ "dimension": format!("i907noise:n{i}:v1"), "id": id });
            let mut r = ts::bare_attestation(&id, author, subject, &env);
            r.attestation_type = attestation_type::SCORES.into();
            r.weight = None;
            r.asserted_at = chrono::Utc::now() - chrono::Duration::minutes(60 - i as i64);
            r.scrub_timestamp = r.asserted_at;
            ts::seal_row_in_place(author, &mut r);
            d.put_attestation(SignedAttestation { attestation: r })
                .await
                .expect("I907 noise row lands");
            ids.push(id);
        }
        ids
    }

    /// Two registered keys, unique per run.
    pub async fn keys(d: &dyn FederationDirectory, tag: &str) -> (String, String) {
        let s = uuid::Uuid::new_v4().simple().to_string();
        let a = format!("{tag}-a-{}", &s[..10]);
        let b = format!("{tag}-b-{}", &s[..10]);
        ts::register_hybrid_key(d, &a).await;
        ts::register_hybrid_key(d, &b).await;
        (a, b)
    }

    /// The reads keyed on `key` (as the door they answer as).
    fn on<'a>(log: &'a [Read], key: &str) -> Vec<&'a Read> {
        log.iter().filter(|r| r.door_key() == key).collect()
    }

    /// Every typed read is one page of at most its limit, and its limit at
    /// most `FOLD_PAGE`.
    pub fn assert_paged(log: &[Read], tag: &str) {
        for r in log {
            if let Some(q) = &r.query {
                assert!(
                    r.rows <= q.limit.get() as usize && q.limit <= FOLD_PAGE,
                    "{tag}: a read past its page: {r:?}"
                );
            }
        }
    }

    /// The fold read `key` narrowed: no whole-slice read of it, and none of
    /// `noise` came back.
    pub fn assert_narrowed(log: &[Read], key: &str, noise_rows: usize, tag: &str) {
        let reads = on(log, key);
        assert!(
            !reads.is_empty(),
            "{tag}: the fold read {key} at all: {log:?}"
        );
        assert!(
            !reads.iter().any(|r| r.is_slice_read()),
            "{tag}: a whole-slice read of {key}: {reads:?}"
        );
        let rows: usize = reads.iter().map(|r| r.rows).sum();
        assert!(
            rows < noise_rows,
            "{tag}: {rows} rows read over {key}, the noise is {noise_rows}: {reads:?}"
        );
        assert_paged(log, tag);
    }

    /// **I907** — the trust/ownership plane: quarantine markers, the objection
    /// fold, the post-reclaim rebinding gate and the node's trust-root signal.
    pub async fn i907_trust_and_ownership_folds_read_bounded(d: &dyn FederationDirectory) {
        let (k, other) = keys(d, "i907").await;
        let n = 7;
        noise(d, &other, &k, n).await;
        let now = chrono::Utc::now();

        // Quarantine markers about K: the `quarantine:` family only.
        let _ = read_probe::take();
        let fold = crate::federation::quarantine::resolve_quarantine(d, &k, now)
            .await
            .expect("I907 quarantine fold");
        assert!(!fold.withholds(), "I907 noise withholds nothing");
        assert_narrowed(&read_probe::take(), &k, n, "I907 quarantine");

        // Objections against an action by K: the `objection:` family only.
        let action = crate::federation::reverse_quorum::ActionRef {
            actor_key_id: &k,
            action_id: "i907-action",
            asserted_at: now - chrono::Duration::minutes(5),
        };
        let _ = read_probe::take();
        crate::federation::reverse_quorum::resolve_reverse_quorum_with(
            d,
            crate::federation::cohort::Cohort::Community,
            &other,
            vec![],
            None,
            None,
            action,
            now,
        )
        .await
        .expect("I907 reverse quorum fold");
        assert_narrowed(&read_probe::take(), &k, n, "I907 objections");

        // A fresh owner binding over K: the gate asks only K's withdrawals.
        let id = uuid::Uuid::new_v4().to_string();
        let env = serde_json::json!({
            "dimension": crate::federation::types::owner_binding::DIMENSION,
            "id": id,
        });
        let mut binding: Attestation = ts::bare_attestation(&id, &other, &k, &env);
        binding.attestation_type = attestation_type::DELEGATES_TO.into();
        let _ = read_probe::take();
        crate::federation::ownership_reclaim::check_post_reclaim_rebinding_admission(d, &binding)
            .await
            .expect("I907 no reclaim, no refusal");
        assert_narrowed(&read_probe::take(), &k, n, "I907 post-reclaim rebinding");

        // The node's trust-root signal walks ITS whole authored slice: in
        // pages, every row once, and it is readable.
        let (me, _) = keys(d, "i907me").await;
        noise(d, &me, &other, n).await;
        let _ = read_probe::take();
        let signal =
            crate::federation::node_state::resolve_trust_root_signal(d, Some(&me), None, now).await;
        let log = read_probe::take();
        assert_ne!(
            signal.standing,
            crate::federation::node_state::TrustRootStanding::Unreadable,
            "I907 the walk completes"
        );
        let walk: Vec<&Read> = on(&log, &me)
            .into_iter()
            .filter(|r| r.is_slice_read())
            .collect();
        assert_eq!(
            walk.iter().map(|r| r.rows).sum::<usize>(),
            n,
            "I907 the slice walk reads every row once: {walk:?}"
        );
        assert!(walk.len() > 1, "I907 the walk is paged: {walk:?}");
        assert_paged(&log, "I907 trust-root signal");
    }

    /// **I908** — the consent/audience plane: a node's community-trust
    /// consent, a member's membership replies, the key-grant emitter's
    /// already-held check. (The consent fold's rows, an owner's allow lists,
    /// a group's public charter and the family's charter rows are held by
    /// I535/I540/I547.)
    pub async fn i908_consent_and_audience_folds_read_bounded(d: &dyn FederationDirectory) {
        let (k, other) = keys(d, "i908").await;
        let n = 7;
        noise(d, &other, &k, n).await;
        // The node's own noise about itself, too: the community-trust read
        // pins the node as author AND subject.
        noise(d, &k, &k, n).await;

        let _ = read_probe::take();
        let consent =
            crate::federation::community_trust_consent::community_trust_consent_for(d, &k)
                .await
                .expect("I908 community trust fold");
        assert!(consent.is_none(), "I908 noise is no consent");
        assert_narrowed(&read_probe::take(), &k, n, "I908 community trust");

        let _ = read_probe::take();
        let replies = crate::federation::membership_acceptance::replies_of(d, &k)
            .await
            .expect("I908 replies fold");
        assert!(replies.is_empty(), "I908 noise is no reply");
        assert_narrowed(&read_probe::take(), &k, n, "I908 membership replies");

        let row = crate::federation::key_grant::KeyGrantRow {
            axis: crate::federation::key_grant::KeyGrantAxis::Content {
                at_rest_sha256: "00".repeat(32),
                cohort_scope: crate::federation::types::cohort_scope::SELF.to_owned(),
                owner_key_id: other.clone(),
            },
            wrap: crate::federation::blobs::GrantWrap {
                recipient_key_id: k.clone(),
                wrap_algorithm: "i908".into(),
                wrapped_dek: "i908".into(),
            },
        };
        let _ = read_probe::take();
        let held = crate::federation::key_grant::key_grant_row_held(d, &other, &row)
            .await
            .expect("I908 key grant check");
        assert!(!held, "I908 noise holds no grant");
        assert_narrowed(&read_probe::take(), &k, n, "I908 key grant held");
    }

    /// A fold that walks `key`'s whole slice: every row once, in more than one
    /// page, each page at most its limit.
    pub fn assert_walked(log: &[Read], key: &str, n: usize, tag: &str) {
        let walk: Vec<&Read> = on(log, key)
            .into_iter()
            .filter(|r| r.is_slice_read())
            .collect();
        assert_eq!(
            walk.iter().map(|r| r.rows).sum::<usize>(),
            n,
            "{tag}: the slice walk reads every row once: {walk:?}"
        );
        assert!(walk.len() > 1, "{tag}: the walk is paged: {walk:?}");
        assert_paged(log, tag);
    }

    /// **I909** — the identity-fact plane. Age, capacity and licensure read a
    /// claim token that rides either the `scores` dimension or the legacy
    /// type slot, so they walk the subject's slice — in pages, each row once.
    /// The content-class flag reads one dimension's `scores` rows. `d` must
    /// know its node key (the content-class door asks for it).
    pub async fn i909_identity_fact_folds_read_bounded(d: &dyn FederationDirectory) {
        let (k, other) = keys(d, "i909").await;
        let n = 7;
        noise(d, &other, &k, n).await;
        let now = chrono::Utc::now();

        let _ = read_probe::take();
        crate::federation::age::age_band(d, &k)
            .await
            .expect("I909 age band");
        assert_walked(&read_probe::take(), &k, n, "I909 age_band");

        let _ = read_probe::take();
        crate::federation::age::age_band_fine(d, &k)
            .await
            .expect("I909 age band fine");
        assert_walked(&read_probe::take(), &k, n, "I909 age_band_fine");

        let _ = read_probe::take();
        crate::federation::capacity::capacity_state(d, &k, "finance")
            .await
            .expect("I909 capacity state");
        assert_walked(&read_probe::take(), &k, n, "I909 capacity_state");

        let _ = read_probe::take();
        crate::federation::capacity::incapacity_facts(d, &k)
            .await
            .expect("I909 incapacity facts");
        assert_walked(&read_probe::take(), &k, n, "I909 incapacity_facts");

        let _ = read_probe::take();
        crate::federation::licensure::status_set_for(d, &k, "i909-authority", now)
            .await
            .expect("I909 licensure");
        assert_walked(&read_probe::take(), &k, n, "I909 licensure status_set_for");

        let _ = read_probe::take();
        let flag = crate::federation::content_class::resolve_content_class_flag(
            d,
            &k,
            "content_class:i909:v1",
            now,
        )
        .await
        .expect("I909 content class");
        assert!(!flag.flagged, "I909 noise flags nothing");
        assert_narrowed(&read_probe::take(), &k, n, "I909 content class");
    }

    /// **I911** — the custody/config/index plane: a holder's custody claims
    /// (`held_by`), a producer's retractions (the deletion window), a root's
    /// conferral of a mesh-config author, a member's candidate holders (the
    /// at-rest cascade) read narrowed; the subject's wire refs walk its slice
    /// in pages, each row once.
    pub async fn i911_custody_config_and_index_folds_read_bounded(d: &dyn FederationDirectory) {
        let (k, other) = keys(d, "i911").await;
        let n = 7;
        noise(d, &k, &other, n).await;
        noise(d, &other, &k, n).await;
        let now = chrono::Utc::now();

        let _ = read_probe::take();
        let held = crate::federation::holding_claim::held_by(d, &k, now, false)
            .await
            .expect("I911 held_by");
        assert!(held.is_empty(), "I911 noise is no custody claim");
        assert_narrowed(&read_probe::take(), &k, n, "I911 held_by");

        let _ = read_probe::take();
        let retracted = crate::federation::deletion_window::producer_retracted_ids(d, &k)
            .await
            .expect("I911 producer retractions");
        assert!(retracted.is_empty(), "I911 noise retracts nothing");
        assert_narrowed(&read_probe::take(), &k, n, "I911 producer_retracted_ids");

        // `other` authored n rows about `k`: the root's conferral read pins
        // both and one dimension.
        let _ = read_probe::take();
        crate::federation::mesh_config::root_authorizes_author(d, &other, &k, now)
            .await
            .expect("I911 root authorizes author");
        assert_narrowed(&read_probe::take(), &k, n, "I911 root_authorizes_author");

        let _ = read_probe::take();
        let refs = crate::federation::wire_index::wire_refs_for_subject(d, &k)
            .await
            .expect("I911 wire refs");
        assert!(
            refs.iter()
                .filter(|(kind, _, _)| *kind == "Attestation")
                .count()
                >= n,
            "I911 every row about the subject is a ref"
        );
        assert_walked(&read_probe::take(), &k, n, "I911 wire_refs_for_subject");
    }

    /// **I912** — the trait's own default bodies (no default reads wider
    /// than its query, #1001): `delegations_to` seeks the `delegates_to` rows
    /// about the key; `list_signed_records(Attestation)` — every row about the
    /// subject, by definition — walks the slice in pages, each row once.
    pub async fn i912_trait_default_bodies_read_bounded(d: &dyn FederationDirectory) {
        let (k, other) = keys(d, "i912").await;
        let n = 7;
        noise(d, &other, &k, n).await;

        let _ = read_probe::take();
        let delegations = d.delegations_to(&k).await.expect("I912 delegations_to");
        assert!(delegations.is_empty(), "I912 noise delegates nothing");
        assert_narrowed(&read_probe::take(), &k, n, "I912 delegations_to");

        let _ = read_probe::take();
        let records = d
            .list_signed_records(
                crate::federation::namespace::ReplicatedKind::Attestation,
                &k,
            )
            .await
            .expect("I912 signed records");
        assert_eq!(records.len(), n, "I912 every row about the subject");
        assert_walked(&read_probe::take(), &k, n, "I912 list_signed_records");
    }
}

#[cfg(all(test, any(feature = "sqlite", feature = "postgres")))]
mod runners {
    macro_rules! runners {
        ($modname:ident, $fresh:expr) => {
            mod $modname {
                use crate::federation::FederationDirectory;
                #[tokio::test]
                async fn i908_consent_and_audience_folds_read_bounded() {
                    let Some(d) = $fresh.await else { return };
                    super::super::bodies::i908_consent_and_audience_folds_read_bounded(
                        &d as &dyn FederationDirectory,
                    )
                    .await
                }
                #[tokio::test]
                async fn i911_custody_config_and_index_folds_read_bounded() {
                    let Some(d) = $fresh.await else { return };
                    super::super::bodies::i911_custody_config_and_index_folds_read_bounded(
                        &d as &dyn FederationDirectory,
                    )
                    .await
                }
                #[tokio::test]
                async fn i912_trait_default_bodies_read_bounded() {
                    let Some(d) = $fresh.await else { return };
                    super::super::bodies::i912_trait_default_bodies_read_bounded(
                        &d as &dyn FederationDirectory,
                    )
                    .await
                }
                #[tokio::test]
                async fn i907_trust_and_ownership_folds_read_bounded() {
                    let Some(d) = $fresh.await else { return };
                    super::super::bodies::i907_trust_and_ownership_folds_read_bounded(
                        &d as &dyn FederationDirectory,
                    )
                    .await
                }
            }
        };
    }

    #[cfg(feature = "sqlite")]
    #[tokio::test]
    async fn i909_sqlite() {
        use crate::store::Backend as _;
        let d = crate::store::sqlite::SqliteBackend::open_in_memory()
            .await
            .unwrap();
        d.run_migrations().await.unwrap();
        d.set_node_key_id("i909-node");
        super::bodies::i909_identity_fact_folds_read_bounded(&d).await;
    }

    #[cfg(feature = "postgres")]
    #[tokio::test]
    async fn i909_postgres() {
        use crate::store::Backend as _;
        let Some(dsn) = crate::test_pg::empty_dsn() else {
            return;
        };
        let d = crate::store::postgres::PostgresBackend::connect(&dsn)
            .await
            .unwrap();
        d.run_migrations().await.unwrap();
        d.set_node_key_id("i909-node");
        super::bodies::i909_identity_fact_folds_read_bounded(&d).await;
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
