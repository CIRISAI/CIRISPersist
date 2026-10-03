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

pub(crate) mod bodies {
    use crate::federation::operational::test_support as ops;
    use crate::federation::trust_root::{
        test_pre_rotation_commitment, trust_root_valid, trusted_roots_of, INFRA_ATTEST_SCOPE,
        INFRA_SERVE_SCOPE, TRUST_ACCEPTS_DIMENSION, TRUST_CHARTER_DIMENSION,
    };
    use crate::federation::types::{attestation_type, identity_type};
    use crate::federation::{FederationDirectory, SignedAttestation};

    pub(crate) fn suffix() -> String {
        uuid::Uuid::new_v4().simple().to_string()[..10].to_owned()
    }

    fn charter_envelope(id: &str, root: &str, label: Option<&str>) -> serde_json::Value {
        let commitment =
            test_pre_rotation_commitment(&[format!("{root}-succ-a"), format!("{root}-succ-b")])
                .expect("commitment");
        let mut env = serde_json::json!({
            "references_attestation_id": id,
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
    pub(crate) async fn key_root(
        d: &dyn FederationDirectory,
        root: &str,
        label: Option<&str>,
    ) -> String {
        ops::register_typed_key_with_evidence(
            d,
            root,
            identity_type::NODE,
            Some(ops::strongbox_evidence(chrono::Utc::now())),
        )
        .await
        .expect("register the root");
        let id = uuid::Uuid::new_v4().to_string();
        let charter = ops::signed_trust_attestation(
            &id,
            root,
            root,
            attestation_type::DELEGATES_TO,
            charter_envelope(&id, root, label),
        );
        d.put_attestation(SignedAttestation {
            attestation: charter,
        })
        .await
        .expect("a self-directed delegates_to is stored whatever its label");
        id
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
        let mut env = serde_json::json!({
            "references_attestation_id": id,
            "scope": [INFRA_ATTEST_SCOPE, INFRA_SERVE_SCOPE],
        });
        if let Some(l) = label {
            env["dimension"] = serde_json::Value::String(l.to_owned());
        }
        let row =
            ops::signed_trust_attestation(&id, user, root, attestation_type::DELEGATES_TO, env);
        d.put_attestation(SignedAttestation { attestation: row })
            .await
            .expect("a delegates_to toward a key root is stored whatever its label");
        id
    }

    pub async fn i366_an_unlabelled_self_charter_is_no_charter(d: &dyn FederationDirectory) {
        let s = suffix();
        let (bare, named) = (format!("i366-bare-{s}"), format!("i366-named-{s}"));
        key_root(d, &bare, None).await;
        let v = trust_root_valid(d, "i366-probe", &bare).await.unwrap();
        assert!(
            !v.root_self_declares && !v.charter_has_recovery,
            "I366: a new unlabelled self-directed row is no charter: {v:?}"
        );
        key_root(d, &named, Some(TRUST_CHARTER_DIMENSION)).await;
        let v = trust_root_valid(d, "i366-probe", &named).await.unwrap();
        assert!(
            v.root_self_declares && v.charter_has_recovery,
            "I366 control: the labelled charter is one: {v:?}"
        );
    }

    pub async fn i367_an_unlabelled_edge_gives_no_acceptance(d: &dyn FederationDirectory) {
        let s = suffix();
        let root = format!("i367-root-{s}");
        key_root(d, &root, Some(TRUST_CHARTER_DIMENSION)).await;
        let now = chrono::Utc::now();
        for (user, label) in [
            (format!("i367-bare-{s}"), None),
            (
                format!("i367-legacy-{s}"),
                Some(crate::federation::self_at_login::DIMENSION_DELEGATES_TO),
            ),
        ] {
            edge(d, &user, &root, label).await;
            let v = trust_root_valid(d, &user, &root).await.unwrap();
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
        let v = trust_root_valid(d, &user, &root).await.unwrap();
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

    pub async fn i368_an_unlabelled_holder_to_family_row_is_no_charter(
        d: &dyn FederationDirectory,
    ) {
        let s = suffix();
        let holders = |fam: &str| -> Vec<String> {
            ["h1", "h2", "h3"]
                .iter()
                .map(|h| format!("{fam}-{h}"))
                .collect()
        };
        // Control first: the labelled family charter is one.
        let named = format!("i368-named-{s}");
        let hs = holders(&named);
        for h in &hs {
            ops::register_typed_key(d, h, identity_type::ACCORD_HOLDER)
                .await
                .unwrap();
        }
        ops::seed_chartered_family_root_with_scrubs(d, &named, &hs, "i368-nobody", &[])
            .await
            .expect("the labelled family root");
        let v = trust_root_valid(d, "i368-probe", &named).await.unwrap();
        assert!(v.root_self_declares, "I368 control: {v:?}");

        // The same row with no label, every seat scrubbing it.
        let bare = format!("i368-bare-{s}");
        let hs = holders(&bare);
        for h in &hs {
            ops::register_typed_key(d, h, identity_type::ACCORD_HOLDER)
                .await
                .unwrap();
        }
        ops::seed_test_family(d, &bare, &hs, "quorum:2/3")
            .await
            .expect("the family");
        let id = uuid::Uuid::new_v4().to_string();
        let cosigners: Vec<&str> = hs[1..].iter().map(String::as_str).collect();
        let charter = ops::co_signed_trust_attestation(
            &id,
            &hs[0],
            &bare,
            attestation_type::DELEGATES_TO,
            charter_envelope(&id, &bare, None),
            &cosigners,
        );
        d.put_attestation(SignedAttestation {
            attestation: charter,
        })
        .await
        .expect("I368: stored as a delegation");
        let v = trust_root_valid(d, "i368-probe", &bare).await.unwrap();
        assert!(
            !v.root_self_declares,
            "I368: a new unlabelled holder → family row is no charter, quorum or not: {v:?}"
        );
        assert!(
            crate::federation::canonical_community::charter_members_for(d, &bare)
                .await
                .unwrap()
                .is_none(),
            "I368: and carries no charter members"
        );
    }

    /// The rows I369 judges before and after they are held: an unlabelled
    /// self-directed charter and an unlabelled acceptance edge.
    pub(crate) struct Held {
        pub root: String,
        pub user: String,
        pub ids: Vec<String>,
    }

    pub(crate) async fn i369_put_unlabelled(d: &dyn FederationDirectory) -> Held {
        let s = suffix();
        let (root, user) = (format!("i369-root-{s}"), format!("i369-user-{s}"));
        let charter = key_root(d, &root, None).await;
        let e = edge(d, &user, &root, None).await;
        Held {
            root,
            user,
            ids: vec![charter, e],
        }
    }

    pub(crate) async fn i369_assert(d: &dyn FederationDirectory, h: &Held, held: bool) {
        let v = trust_root_valid(d, &h.user, &h.root).await.unwrap();
        assert_eq!(
            (v.root_self_declares, v.edge_exists, v.valid),
            (held, held, held),
            "I369: held={held}: {v:?}"
        );
        let roots = trusted_roots_of(d, &h.user, chrono::Utc::now())
            .await
            .unwrap();
        assert_eq!(roots.contains(&h.root), held, "I369: held={held}");
        let mut got = d.trust_direction_held_among(&h.ids).await.unwrap();
        got.sort();
        let mut want = if held { h.ids.clone() } else { Vec::new() };
        want.sort();
        assert_eq!(got, want, "I369: the directory's own answer");
    }
}

#[cfg(test)]
mod run {
    use super::bodies;
    use crate::federation::FederationDirectory;

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
                #[tokio::test]
                async fn i368() {
                    let Some(d) = $fresh.await else { return };
                    bodies::i368_an_unlabelled_holder_to_family_row_is_no_charter(
                        &d as &dyn FederationDirectory,
                    )
                    .await
                }
            }
        };
    }
    runners!(memory, async {
        Some(crate::store::memory::MemoryBackend::new())
    });
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

    #[tokio::test]
    async fn i369_held_rows_keep_their_reading_memory() {
        let b = crate::store::memory::MemoryBackend::new();
        let h = bodies::i369_put_unlabelled(&b as &dyn FederationDirectory).await;
        bodies::i369_assert(&b, &h, false).await;
        for id in &h.ids {
            b.mark_trust_direction_held(id);
        }
        bodies::i369_assert(&b, &h, true).await;
    }

    /// The real upgrade: the rows are stored on a V166 schema (before the
    /// rule), V167 runs, and they keep their reading; rows put after it do not.
    #[cfg(feature = "sqlite")]
    #[tokio::test]
    async fn i369_held_rows_keep_their_reading_through_the_upgrade_sqlite() {
        use crate::store::Backend as _;
        let b = crate::store::sqlite::SqliteBackend::open_in_memory()
            .await
            .unwrap();
        b.run_migrations_through(166).await.unwrap();
        // v53.0.0 — this build reads V174's lineage-head columns on every
        // family/community lookup, so the pre-V167 write needs them; they are
        // added for the write and dropped before the upgrade, which then adds
        // them as a node upgrading from v52 would. The rows under test are
        // attestations, untouched by either step.
        b.write(|conn| conn.execute_batch(V174_TEMP_ADD_SQLITE))
            .await
            .unwrap();
        let h = bodies::i369_put_unlabelled(&b as &dyn FederationDirectory).await;
        b.write(|conn| conn.execute_batch(V174_TEMP_DROP_SQLITE))
            .await
            .unwrap();
        b.run_migrations().await.unwrap();
        bodies::i369_assert(&b, &h, true).await;
        let late = bodies::i369_put_unlabelled(&b as &dyn FederationDirectory).await;
        bodies::i369_assert(&b, &late, false).await;
    }

    #[cfg(feature = "sqlite")]
    const V174_TEMP_ADD_SQLITE: &str = "\
        ALTER TABLE federation_families ADD COLUMN prev_head_digest TEXT NOT NULL DEFAULT '';\
        ALTER TABLE federation_families ADD COLUMN charter_digest TEXT NOT NULL DEFAULT '';\
        ALTER TABLE federation_communities ADD COLUMN prev_head_digest TEXT NOT NULL DEFAULT '';\
        ALTER TABLE federation_communities ADD COLUMN charter_digest TEXT NOT NULL DEFAULT '';";
    #[cfg(feature = "sqlite")]
    const V174_TEMP_DROP_SQLITE: &str = "\
        ALTER TABLE federation_families DROP COLUMN prev_head_digest;\
        ALTER TABLE federation_families DROP COLUMN charter_digest;\
        ALTER TABLE federation_communities DROP COLUMN prev_head_digest;\
        ALTER TABLE federation_communities DROP COLUMN charter_digest;";

    #[cfg(feature = "postgres")]
    #[tokio::test]
    async fn i369_held_rows_keep_their_reading_through_the_upgrade_postgres() {
        use crate::store::Backend as _;
        let Some(dsn) = crate::test_pg::empty_dsn() else {
            return;
        };
        let b = crate::store::postgres::PostgresBackend::connect(&dsn)
            .await
            .unwrap();
        b.run_migrations_through(166).await.unwrap();
        // v53.0.0 — see the sqlite leg: V174's columns for the write only.
        let pg = |sql: &'static str| {
            let b = &b;
            async move {
                b.get_client()
                    .await
                    .unwrap()
                    .batch_execute(sql)
                    .await
                    .unwrap()
            }
        };
        pg("ALTER TABLE cirislens.federation_families \
                ADD COLUMN prev_head_digest TEXT NOT NULL DEFAULT '', \
                ADD COLUMN charter_digest TEXT NOT NULL DEFAULT ''; \
            ALTER TABLE cirislens.federation_communities \
                ADD COLUMN prev_head_digest TEXT NOT NULL DEFAULT '', \
                ADD COLUMN charter_digest TEXT NOT NULL DEFAULT '';")
        .await;
        let h = bodies::i369_put_unlabelled(&b as &dyn FederationDirectory).await;
        pg("ALTER TABLE cirislens.federation_families \
                DROP COLUMN prev_head_digest, DROP COLUMN charter_digest; \
            ALTER TABLE cirislens.federation_communities \
                DROP COLUMN prev_head_digest, DROP COLUMN charter_digest;")
        .await;
        b.run_migrations().await.unwrap();
        bodies::i369_assert(&b, &h, true).await;
        let late = bodies::i369_put_unlabelled(&b as &dyn FederationDirectory).await;
        bodies::i369_assert(&b, &late, false).await;
    }

    /// **I370** — the shipped bundle on a fresh node. Its `genesis-charter`
    /// (A1 → humanity-accord) carries no job label and this node never held
    /// it before the rule: it is read as the accord's charter because it is a
    /// member of the pinned bundle, and only for that reason.
    #[cfg(feature = "sqlite")]
    #[tokio::test]
    async fn i370_the_shipped_bundle_still_charters_the_accord_sqlite() {
        use crate::federation::genesis;
        use crate::store::Backend as _;
        if genesis::test_anchor_override_active() {
            return; // a software anchor stands in for the shipped bundle
        }
        let b = crate::store::sqlite::SqliteBackend::open_in_memory()
            .await
            .unwrap();
        b.run_migrations().await.unwrap();
        b.seed_genesis_accord_holders(&genesis::effective_accord_holder_records())
            .await
            .expect("holders");
        genesis::seed_family_and_canonical(&b)
            .await
            .expect("the shipped plane seeds on a fresh node");
        let family = crate::federation::canonical_community::accord_family_key_id();
        let about = b.list_attestations_for(family).await.unwrap();
        let charter = about
            .iter()
            .find(|a| a.attestation_id == "genesis-charter")
            .expect("the baked charter is stored");
        assert!(
            crate::federation::trust_root::names_no_trust_job(&charter.attestation_envelope),
            "I370 precondition: the shipped charter is unlabelled"
        );
        assert!(
            genesis::is_pinned_bundle_row(charter),
            "I370: it is a pinned-bundle member"
        );
        assert!(
            b.trust_direction_held_among(&["genesis-charter".to_owned()])
                .await
                .unwrap()
                .is_empty(),
            "I370: and not a row this node held before the rule"
        );
        let v = crate::federation::trust_root::trust_root_valid(&b, "i370-probe", family)
            .await
            .unwrap();
        assert!(
            v.root_self_declares && v.charter_has_recovery,
            "I370: the accord is chartered: {v:?}"
        );
        // The same statement under another id is not a member.
        let mut copy = charter.clone();
        copy.attestation_id = "genesis-charter-copy".to_owned();
        assert!(!genesis::is_pinned_bundle_row(&copy), "I370: id binds");
        let mut moved = charter.clone();
        moved.attested_key_id = "some-other-root".to_owned();
        assert!(
            !genesis::is_pinned_bundle_row(&moved),
            "I370: subject binds"
        );
        let mut altered = charter.clone();
        altered.attestation_envelope["scope"] = serde_json::json!(["infra:serve"]);
        assert!(
            !genesis::is_pinned_bundle_row(&altered),
            "I370: content binds"
        );
    }
}
