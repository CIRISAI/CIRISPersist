//! CIRISPersist#973 (CC 3.2 T4a, steward ruling 2026-10-01, "bundle only") —
//! **a `delegates_to` with no `trust:{job}` label is no charter and gives no
//! acceptance.**
//!
//! "A new row with no `trust:{job}` label gives no acceptance and is no
//! charter … One exception stands, as a stop-gap until the re-mint: an
//! unlabelled row that is a member of the pinned GenesisBundle … Unlabelled
//! rows a node already holds keep their reading under T4."
//!
//! - **I366** (memory, sqlite, postgres) — a new unlabelled SELF-DIRECTED
//!   charter is no charter; the labelled one is.
//! - **I367** — a new unlabelled node → root edge, and one carrying the legacy
//!   `self:delegates_to:v1`, give no acceptance and name no subscribed root;
//!   the labelled edge does both.
//! - **I368** — a new unlabelled holder → family row, quorum co-scrubbed, is
//!   no charter; the labelled one is.
//! - **I369** — unlabelled rows the node HELD when the rule arrived keep their
//!   reading: memory by its seam, sqlite and postgres through the real V167
//!   upgrade (rows stored at V166, then migrated).
//! - **I370** (sqlite) — the shipped bundle's unlabelled rows still seed and
//!   charter the accord on a fresh node: pinned-bundle members, held by nobody.
//!
//! v62.0.0 (JSON cut, E5) — **I368 and I370 are deleted**: I368's row is a
//! quorum co-scrubbed JSON charter (a co-scrub set over the JCS image), and
//! I370 reads the baked bundle/1's `genesis-charter` row; bundle/2 names only
//! key records and bindings (C2), and nothing of the earlier form carries.
//! I366 and I367 are edition-2 rows: the keys are `key:record`s named by
//! identity-ref, the rows are named by their computed ids.

#[cfg(any(feature = "sqlite", feature = "postgres"))]
pub(crate) mod bodies {
    use crate::federation::edition2::fixture_switch as e2;
    use crate::federation::operational::test_support as ops;
    use crate::federation::trust_root::{
        test_pre_rotation_commitment, trust_root_valid, trusted_roots_of, INFRA_ATTEST_SCOPE,
        INFRA_SERVE_SCOPE, TRUST_ACCEPTS_DIMENSION, TRUST_CHARTER_DIMENSION,
    };
    use crate::federation::types::{attestation_type, identity_type};
    use crate::federation::FederationDirectory;

    pub(crate) fn suffix() -> String {
        uuid::Uuid::new_v4().simple().to_string()[..10].to_owned()
    }

    /// v62.0.0 (E5) — the earlier form echoed the row's own chosen id as
    /// `references_attestation_id`; an edition-2 row cannot name its own
    /// computed id, so the label rides as the `id` member.
    fn charter_envelope(id: &str, root: &str, label: Option<&str>) -> serde_json::Value {
        let commitment =
            test_pre_rotation_commitment(&[format!("{root}-succ-a"), format!("{root}-succ-b")])
                .expect("commitment");
        let mut env = serde_json::json!({
            "id": id,
            "scope": [INFRA_ATTEST_SCOPE, INFRA_SERVE_SCOPE],
            "pre_rotation_commitment": commitment,
        });
        if let Some(l) = label {
            env["dimension"] = serde_json::Value::String(l.to_owned());
        }
        env
    }

    /// Register `root` as a key root and put its self-directed charter with
    /// `label`. Returns the charter's id.
    ///
    /// v62.0.0 (E5) — the root is an edition-2 `key:record` (`node`; the
    /// fixture's hardware evidence is not carried), named by its
    /// identity-ref; the id returned is the charter's computed row id.
    pub(crate) async fn key_root(
        d: &dyn FederationDirectory,
        root: &str,
        label: Option<&str>,
    ) -> String {
        e2::put_key(d, root, &[identity_type::NODE]).await;
        let id = uuid::Uuid::new_v4().to_string();
        let charter = ops::signed_trust_attestation(
            &id,
            root,
            root,
            attestation_type::DELEGATES_TO,
            charter_envelope(&id, root, label),
        );
        e2::put_signed(d, &charter)
            .await
            .expect("a self-directed delegates_to is stored whatever its label");
        e2::rid(&charter)
    }

    /// Put `delegates_to(user → root)` with `label`. Returns its id.
    pub(crate) async fn edge(
        d: &dyn FederationDirectory,
        user: &str,
        root: &str,
        label: Option<&str>,
    ) -> String {
        ops::register_typed_key(d, user, identity_type::USER)
            .await
            .expect("register the user");
        let id = uuid::Uuid::new_v4().to_string();
        // v62.0.0 (E5) — no self-reference (see `charter_envelope`).
        let mut env = serde_json::json!({
            "id": id,
            "scope": [INFRA_ATTEST_SCOPE, INFRA_SERVE_SCOPE],
        });
        if let Some(l) = label {
            env["dimension"] = serde_json::Value::String(l.to_owned());
        }
        let row =
            ops::signed_trust_attestation(&id, user, root, attestation_type::DELEGATES_TO, env);
        e2::put_signed(d, &row)
            .await
            .expect("a delegates_to toward a key root is stored whatever its label");
        e2::rid(&row)
    }

    pub async fn i366_an_unlabelled_self_charter_is_no_charter(d: &dyn FederationDirectory) {
        let s = suffix();
        let (bare, named) = (format!("i366-bare-{s}"), format!("i366-named-{s}"));
        key_root(d, &bare, None).await;
        let v = trust_root_valid(d, "i366-probe", &e2::kid(&bare), crate::host::clock::now())
            .await
            .unwrap();
        assert!(
            !v.root_self_declares && !v.charter_has_recovery,
            "I366: a new unlabelled self-directed row is no charter: {v:?}"
        );
        key_root(d, &named, Some(TRUST_CHARTER_DIMENSION)).await;
        let v = trust_root_valid(d, "i366-probe", &e2::kid(&named), crate::host::clock::now())
            .await
            .unwrap();
        assert!(
            v.root_self_declares && v.charter_has_recovery,
            "I366 control: the labelled charter is one: {v:?}"
        );
    }

    pub async fn i367_an_unlabelled_edge_gives_no_acceptance(d: &dyn FederationDirectory) {
        let s = suffix();
        let root = format!("i367-root-{s}");
        key_root(d, &root, Some(TRUST_CHARTER_DIMENSION)).await;
        // v62.0.0 (E5) — keys are named by identity-ref from here on.
        let root = e2::kid(&root);
        let now = chrono::Utc::now();
        for (user, label) in [
            (format!("i367-bare-{s}"), None),
            (
                format!("i367-legacy-{s}"),
                Some(crate::federation::self_at_login::DIMENSION_DELEGATES_TO),
            ),
        ] {
            edge(d, &user, &root, label).await;
            let user = e2::kid(&user);
            let v = trust_root_valid(d, &user, &root, crate::host::clock::now())
                .await
                .unwrap();
            assert!(
                !v.edge_exists && !v.valid && v.root_self_declares,
                "I367: a new edge labelled {label:?} gives no acceptance: {v:?}"
            );
            assert!(
                trusted_roots_of(d, &user, now).await.unwrap().is_empty(),
                "I367: and names no subscribed root ({label:?})"
            );
        }
        let user = format!("i367-named-{s}");
        edge(d, &user, &root, Some(TRUST_ACCEPTS_DIMENSION)).await;
        let user = e2::kid(&user);
        let v = trust_root_valid(d, &user, &root, crate::host::clock::now())
            .await
            .unwrap();
        assert!(
            v.edge_exists && v.valid,
            "I367 control: the labelled edge accepts: {v:?}"
        );
        assert_eq!(
            trusted_roots_of(d, &user, now).await.unwrap(),
            vec![root.clone()],
            "I367 control"
        );
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
                async fn i366() {
                    let Some(d) = $fresh.await else { return };
                    bodies::i366_an_unlabelled_self_charter_is_no_charter(
                        &d as &dyn FederationDirectory,
                    )
                    .await
                }
                #[tokio::test]
                async fn i367() {
                    let Some(d) = $fresh.await else { return };
                    bodies::i367_an_unlabelled_edge_gives_no_acceptance(
                        &d as &dyn FederationDirectory,
                    )
                    .await
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
