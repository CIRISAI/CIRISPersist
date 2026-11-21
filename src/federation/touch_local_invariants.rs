//! v62.0.0 (v62 P5b; RULINGS "a touch claim is node-local";
//! CC_FAMILYMAP_ANSWER: the freshness floor is a NODE-LOCAL fold, and the
//! `witness_touch` / `n_of_m` forms are gone) — **I3114–I3117: the node's
//! own, unsigned touch write keeps the floor's rules.** sqlite and postgres.
//!
//! - **I3114** — monotonic max: the first touch advances, an older or equal
//!   one is `NotFresher` and changes nothing, a newer one advances.
//! - **I3115** — the future-skew guard: a `fresh_as_of` beyond
//!   `DEFAULT_MAX_TOUCH_SKEW` ahead of the door's clock is refused
//!   `InvalidArgument` and writes nothing; one inside the tolerance admits.
//! - **I3116** — the mandatory `cohort_scope`: a value outside the closed
//!   set is refused `CohortScopeRejected` and writes nothing; every closed
//!   value is stored and read back.
//! - **I3117** — the node-local row is the floor (`freshness_floor` reads
//!   it, with no signer), the earlier form's signed read
//!   (`lookup_freshness_floor`) does not present it as a signed claim, and an
//!   empty target is refused.
//!
//! Mutations: flip the SQL guard's `>` to `>=` or drop it and I3114 reds;
//! drop `check_touch_fresh_as_of_skew` from the plan and I3115 reds; drop
//! `check_cohort_scope` and I3116 reds; drop the `signer_form <>
//! 'node_local'` filter from the signed read and I3117 reds (the row's empty
//! signature fails to decode).

/// The backend-agnostic witness bodies; `run` instantiates them per backend.
#[cfg(all(test, any(feature = "sqlite", feature = "postgres")))]
pub(crate) mod bodies {
    use crate::federation::admission::DEFAULT_MAX_TOUCH_SKEW;
    use crate::federation::types::{cohort_scope, FreshnessFloor};
    use crate::federation::{Error, FederationDirectory, TouchApplyOutcome};

    const KIND: &str = "ownership_binding";

    /// Now, whole seconds, so every backend stores and returns it exactly
    /// (sqlite's RFC 3339 text and postgres' microsecond `timestamptz`).
    fn now_s() -> chrono::DateTime<chrono::Utc> {
        chrono::DateTime::<chrono::Utc>::from_timestamp(chrono::Utc::now().timestamp(), 0)
            .expect("seconds")
    }

    async fn floor(d: &dyn FederationDirectory, target: &str) -> Option<FreshnessFloor> {
        d.freshness_floor(target, KIND)
            .await
            .expect("freshness_floor")
    }

    async fn touch(
        d: &dyn FederationDirectory,
        target: &str,
        at: chrono::DateTime<chrono::Utc>,
    ) -> Result<TouchApplyOutcome, Error> {
        d.put_touch_claim_local(target, KIND, at, cohort_scope::SELF)
            .await
    }

    /// **I3114** — the floor only ever advances.
    pub async fn i3114_monotonic_max(d: &dyn FederationDirectory) {
        let target = "i3114-target";
        let t1 = now_s() - chrono::Duration::hours(1);
        assert_eq!(floor(d, target).await, None, "I3114: never touched");
        assert_eq!(
            touch(d, target, t1).await.unwrap(),
            TouchApplyOutcome::Advanced,
            "I3114: the first touch advances"
        );
        assert_eq!(floor(d, target).await.unwrap().fresh_as_of, t1);
        assert_eq!(
            touch(d, target, t1 - chrono::Duration::minutes(10))
                .await
                .unwrap(),
            TouchApplyOutcome::NotFresher,
            "I3114: an older touch is a no-op"
        );
        assert_eq!(
            touch(d, target, t1).await.unwrap(),
            TouchApplyOutcome::NotFresher,
            "I3114: an equal touch is a no-op (strict >)"
        );
        assert_eq!(
            floor(d, target).await.unwrap().fresh_as_of,
            t1,
            "I3114: never rolled back"
        );
        let t2 = t1 + chrono::Duration::minutes(30);
        assert_eq!(
            touch(d, target, t2).await.unwrap(),
            TouchApplyOutcome::Advanced,
            "I3114: a newer touch advances"
        );
        assert_eq!(floor(d, target).await.unwrap().fresh_as_of, t2);
    }

    /// **I3115** — a lying clock cannot jump the floor into the future.
    pub async fn i3115_future_skew_is_refused(d: &dyn FederationDirectory) {
        let target = "i3115-target";
        let far = now_s() + DEFAULT_MAX_TOUCH_SKEW + chrono::Duration::minutes(5);
        match touch(d, target, far).await {
            Err(Error::InvalidArgument(m)) => {
                assert!(m.contains("ahead of now"), "I3115: {m}");
            }
            other => panic!("I3115: a touch beyond the skew tolerance is refused, got {other:?}"),
        }
        assert_eq!(
            floor(d, target).await,
            None,
            "I3115: verify-before-mutation: nothing written"
        );
        let near = now_s() + chrono::Duration::minutes(1);
        assert_eq!(
            touch(d, target, near).await.unwrap(),
            TouchApplyOutcome::Advanced,
            "I3115: inside the tolerance admits"
        );
        assert_eq!(floor(d, target).await.unwrap().fresh_as_of, near);
    }

    /// **I3116** — the privacy row is mandatory and closed.
    pub async fn i3116_cohort_scope_is_the_closed_set(d: &dyn FederationDirectory) {
        let at = now_s() - chrono::Duration::hours(2);
        for bad in ["", "public", "everyone", "SELF"] {
            let target = format!("i3116-bad-{bad}");
            match d.put_touch_claim_local(&target, KIND, at, bad).await {
                Err(Error::CohortScopeRejected { cohort_scope }) => {
                    assert_eq!(cohort_scope, bad, "I3116");
                }
                other => panic!("I3116: {bad:?} is refused CohortScopeRejected, got {other:?}"),
            }
            assert_eq!(floor(d, &target).await, None, "I3116: nothing written");
        }
        for (i, scope) in [
            cohort_scope::SELF,
            cohort_scope::FAMILY,
            cohort_scope::COMMUNITY,
            cohort_scope::AFFILIATIONS,
            cohort_scope::SPECIES,
            cohort_scope::BIOSPHERE,
            cohort_scope::FEDERATION,
        ]
        .into_iter()
        .enumerate()
        {
            let target = format!("i3116-ok-{i}");
            assert_eq!(
                d.put_touch_claim_local(&target, KIND, at, scope)
                    .await
                    .unwrap(),
                TouchApplyOutcome::Advanced,
                "I3116: {scope}"
            );
            assert_eq!(
                floor(d, &target).await,
                Some(FreshnessFloor {
                    target_key_id: target.clone(),
                    target_kind: KIND.to_owned(),
                    fresh_as_of: at,
                    cohort_scope: scope.to_owned(),
                }),
                "I3116: stored with its scope"
            );
        }
    }

    /// **I3117** — the node-local row is the floor, and never a signed claim.
    pub async fn i3117_the_local_row_is_the_floor_not_a_signed_claim(d: &dyn FederationDirectory) {
        let target = "i3117-target";
        let at = now_s() - chrono::Duration::minutes(3);
        touch(d, target, at).await.unwrap();
        assert_eq!(
            floor(d, target).await.map(|f| f.fresh_as_of),
            Some(at),
            "I3117: the floor"
        );
        assert_eq!(
            d.lookup_freshness_floor(target, KIND)
                .await
                .expect("I3117: the signed read skips the row, it does not fail on it"),
            None,
            "I3117: a node-local floor is not presented as a signed claim"
        );
        for (t, k) in [("", KIND), (target, "")] {
            assert!(
                matches!(
                    d.put_touch_claim_local(t, k, at, cohort_scope::SELF).await,
                    Err(Error::InvalidArgument(_))
                ),
                "I3117: an empty target ({t:?}, {k:?}) is refused"
            );
        }
    }
}

#[cfg(all(test, any(feature = "sqlite", feature = "postgres")))]
mod run {
    macro_rules! runners {
        ($modname:ident, $fresh:expr) => {
            mod $modname {
                use super::super::bodies;
                use crate::federation::FederationDirectory;
                #[tokio::test]
                async fn i3114() {
                    let Some(d) = $fresh.await else { return };
                    bodies::i3114_monotonic_max(&d as &dyn FederationDirectory).await
                }
                #[tokio::test]
                async fn i3115() {
                    let Some(d) = $fresh.await else { return };
                    bodies::i3115_future_skew_is_refused(&d as &dyn FederationDirectory).await
                }
                #[tokio::test]
                async fn i3116() {
                    let Some(d) = $fresh.await else { return };
                    bodies::i3116_cohort_scope_is_the_closed_set(&d as &dyn FederationDirectory)
                        .await
                }
                #[tokio::test]
                async fn i3117() {
                    let Some(d) = $fresh.await else { return };
                    bodies::i3117_the_local_row_is_the_floor_not_a_signed_claim(
                        &d as &dyn FederationDirectory,
                    )
                    .await
                }
                /// **I2188 (v62.0.0, PX-fix1)** — the node-local touch (the
                /// replacement for the retired signed `put_touch_claim` a host
                /// called) crosses the capsule: I3114 runs THROUGH the proxy
                /// (backend ← capsule dispatch ← `OpsDirectory`), and the
                /// floor it leaves is the backend's own.
                #[tokio::test]
                async fn i2188_the_local_touch_crosses_the_proxy() {
                    let Some(d) = $fresh.await else { return };
                    let backend: std::sync::Arc<dyn FederationDirectory> = std::sync::Arc::new(d);
                    let proxy = crate::ffi::directory_capsule::test_proxy(backend.clone());
                    bodies::i3114_monotonic_max(proxy.as_ref()).await;
                    let direct = backend
                        .freshness_floor("i3114-target", "ownership_binding")
                        .await
                        .expect("I2188: the backend's floor");
                    assert!(direct.is_some(), "I2188: the touch landed on the backend");
                    assert_eq!(
                        proxy
                            .freshness_floor("i3114-target", "ownership_binding")
                            .await
                            .expect("I2188: the floor through the proxy"),
                        direct,
                        "I2188: the proxy reads the backend's floor"
                    );
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
        let dsn = crate::test_pg::empty_dsn()?;
        let b = crate::store::postgres::PostgresBackend::connect(&dsn)
            .await
            .unwrap();
        b.run_migrations().await.unwrap();
        Some(b)
    });
}
