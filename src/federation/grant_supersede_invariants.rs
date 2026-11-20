//! v53.0.0 — **standing over time: rotation is a `supersedes`, compromise is a
//! `withdraws`** (CC 3.2 T2, steward ruling 2026-10-01, CIRISConstitution
//! v1.0-rc6):
//!
//! > A grant that is **superseded** — the root issues the successor grant, to
//! > a rotated key or with a changed scope, as a `supersedes` on the old one —
//! > keeps its lineage: a claim made under the superseded grant, with
//! > `asserted_at` before the successor's, keeps the standing it had, and a
//! > reader walks the `supersedes` chain to find it. A grant that is
//! > **withdrawn** or tombstoned has no successor and no lineage to walk:
//! > standing under it is gone at once, for every claim ever made under it.
//!
//! What `capability_roots_to_trusted_root_over_roster` did before this cut: a
//! `supersedes` is a structural composer but never a retraction, so the
//! superseded grant stayed a LIVE candidate (a narrowed scope never narrowed),
//! and the successor — a `supersedes` row, not a `delegates_to` — conferred
//! nothing. The walk answers "does the subject hold this scope NOW", so it
//! takes the successor and drops the superseded grant.
//!
//! - **I383** — the successor confers; the walk names it, not the grant it
//!   replaced.
//! - **I384** — a successor that changes the scope narrows it: the superseded
//!   grant's scope is not a live candidate any more.
//! - **I385** — a `withdraws` on the successor kills standing at once, and the
//!   superseded grant is not revived; a `withdraws` on a never-superseded
//!   grant still kills at once.
//! - **I386** — a `supersedes` by anyone but the grant's own root neither
//!   retires the grant nor confers.

#[cfg(all(test, any(feature = "sqlite", feature = "postgres")))]
pub(crate) mod bodies {
    use crate::federation::edition2::fixture_switch as e2;
    use crate::federation::operational::test_support::{
        accept_e2_root, confer_e2, signed_trust_attestation, stand_up_e2_root,
    };
    use crate::federation::tier_ingest::test_support as ts;
    use crate::federation::trust_root::{
        capability_roots_to_trusted_root, INFRA_ATTEST_SCOPE, INFRA_SERVE_SCOPE,
        TRUST_CONFERS_DIMENSION,
    };
    use crate::federation::types::{attestation_type, identity_type as it};
    use crate::federation::FederationDirectory;

    /// v62 (E4, wave 7): every id is an identity-ref or a row id. `user` is
    /// THIS node (the runner sets the backend's node key: the asking party
    /// of a trust walk is the node), `root` is the edition-2 root
    /// community's identity-ref (E9's `establish_e2_trust_root`: founded by
    /// the bundle's holders, chartered, accepted by the node, conferring on
    /// `subject`), and `grant` is the conferral's node-computed row id.
    pub(crate) struct Fx {
        pub(crate) user: String,
        pub(crate) root: String,
        pub(crate) subject: String,
        pub(crate) grant: String,
    }

    pub(crate) async fn fixture(d: &dyn FederationDirectory, tag: &str) -> Fx {
        use crate::federation::attestation_query::test_support::AllAttestations as _;
        let user = d
            .node_key_id()
            .expect("the runner sets the node key (set_node_key_id(e2::put_key(..)))");
        let subject_seed = format!("gs-subject-{tag}");
        let subject = e2::put_key(d, &subject_seed, &[it::NODE]).await;
        // v62 (E4-fix6; CC 4.4.3.19): the subject is a MACHINE key, so the
        // root's conferral needs its owner's voice too
        // ([`root_conferring_on_a_node`]).
        let root =
            root_conferring_on_a_node(d, &user, &format!("gs-root-{tag}"), &subject_seed).await;
        let grant = d
            .all_attestations_for(&subject)
            .await
            .unwrap()
            .into_iter()
            .find(|a| {
                a.attestation_type == attestation_type::DELEGATES_TO && a.attesting_key_id == root
            })
            .expect("the root → subject grant")
            .attestation_id;
        let walk = capability_roots_to_trusted_root(d, &user, &subject, INFRA_SERVE_SCOPE)
            .await
            .unwrap()
            .expect("CONTROL — the grant roots before any supersede");
        assert_eq!(walk.grant_attestation_id, grant, "CONTROL — the grant");
        Fx {
            user,
            root,
            subject,
            grant,
        }
    }

    /// v62 (E4-fix6; CC 4.4.3.19) — **a root, accepted by `user`, conferring
    /// `infra:serve` on the NODE key `subject_seed`.** A machine key's owner is
    /// a required voice on a delegation to it, so the subject's owner is bound
    /// first (K2's `put_sealed_owner_binding`, the node's voice included);
    /// then the root is stood up (E9's `stand_up_e2_root`) and accepted, and
    /// its conferral is voiced by the subject (`confer_e2`) and by the
    /// subject's owner. (`establish_e2_trust_root` voices the subject only, so
    /// a node subject's grant waited and its postcondition read `None`.) The
    /// root's identity-ref.
    pub(crate) async fn root_conferring_on_a_node(
        d: &dyn FederationDirectory,
        user: &str,
        root_seed: &str,
        subject_seed: &str,
    ) -> String {
        let owner_seed = format!("gs-owner-of-{subject_seed}");
        e2::put_key(d, &owner_seed, &[it::USER]).await;
        ts::put_sealed_owner_binding(
            d,
            &ts::owner_binding_attestation(
                &uuid::Uuid::new_v4().to_string(),
                &owner_seed,
                subject_seed,
            ),
            subject_seed,
        )
        .await
        .expect("the subject's owner binding lands");
        let root = stand_up_e2_root(d, root_seed)
            .await
            .expect("the edition-2 fixture stands up the root")
            .root;
        accept_e2_root(d, user, &root)
            .await
            .expect("the node accepts the root");
        let grant_row = confer_e2(d, root_seed, subject_seed, &[INFRA_SERVE_SCOPE])
            .await
            .expect("the root confers on the subject");
        let grant_st = d
            .edition2_voices(&grant_row)
            .await
            .expect("the conferral's voices")
            .into_iter()
            .next()
            .expect("the conferral is held as a statement");
        e2::put_statement(d, &e2::voice_of(&grant_st, &owner_seed))
            .await
            .expect("the subject's owner voices the conferral");
        root
    }

    /// `by` writes a `supersedes` on `target` carrying a conferral body.
    /// Returns the successor's node-computed row id (v62: `id` is only a
    /// fixture label; an edition-2 row id is computed, `e2::rid`).
    pub(crate) async fn supersede(
        d: &dyn FederationDirectory,
        id: &str,
        by: &str,
        subject: &str,
        target: &str,
        scope: &str,
    ) -> Result<String, crate::federation::Error> {
        let row = signed_trust_attestation(
            id,
            by,
            subject,
            attestation_type::SUPERSEDES,
            serde_json::json!({
                "references_attestation_id": target,
                "dimension": TRUST_CONFERS_DIMENSION,
                "scope": [scope],
            }),
        );
        e2::put_signed(d, &row).await.map(|_| e2::rid(&row))
    }

    pub(crate) async fn withdraw(
        d: &dyn FederationDirectory,
        id: &str,
        by: &str,
        subject: &str,
        target: &str,
    ) {
        let row = signed_trust_attestation(
            id,
            by,
            subject,
            attestation_type::WITHDRAWS,
            serde_json::json!({
                "references_attestation_id": target,
                "dimension": TRUST_CONFERS_DIMENSION,
            }),
        );
        e2::put_signed(d, &row)
            .await
            .unwrap_or_else(|e| panic!("the root withdraws {target}: {e}"));
    }

    async fn walk(d: &dyn FederationDirectory, fx: &Fx, scope: &str) -> Option<String> {
        capability_roots_to_trusted_root(d, &fx.user, &fx.subject, scope)
            .await
            .unwrap()
            .map(|g| g.grant_attestation_id)
    }

    /// **I383** — the successor confers, and it is the grant the walk names.
    pub(crate) async fn i383_the_successor_confers(d: &dyn FederationDirectory, tag: &str) {
        let fx = fixture(d, tag).await;
        let succ = supersede(
            d,
            &format!("gs-succ-{tag}"),
            &fx.root,
            &fx.subject,
            &fx.grant,
            INFRA_SERVE_SCOPE,
        )
        .await
        .expect("I383 the root's successor is admitted");
        assert_eq!(
            walk(d, &fx, INFRA_SERVE_SCOPE).await.as_deref(),
            Some(succ.as_str()),
            "I383 the successor confers; the superseded grant is not the live candidate"
        );
        // A second rotation: the chain's head confers.
        let succ2 = supersede(
            d,
            &format!("gs-succ2-{tag}"),
            &fx.root,
            &fx.subject,
            &succ,
            INFRA_SERVE_SCOPE,
        )
        .await
        .expect("I383 a second rotation is admitted");
        assert_eq!(
            walk(d, &fx, INFRA_SERVE_SCOPE).await.as_deref(),
            Some(succ2.as_str()),
            "I383 the head of the supersedes chain confers"
        );
    }

    /// **I384** — a successor that changes the scope narrows it.
    pub(crate) async fn i384_a_changed_scope_narrows(d: &dyn FederationDirectory, tag: &str) {
        let fx = fixture(d, tag).await;
        let succ = supersede(
            d,
            &format!("gs-narrow-{tag}"),
            &fx.root,
            &fx.subject,
            &fx.grant,
            INFRA_ATTEST_SCOPE,
        )
        .await
        .expect("I384 the root's narrowing successor is admitted");
        assert_eq!(
            walk(d, &fx, INFRA_SERVE_SCOPE).await,
            None,
            "I384 the superseded grant's scope is not a live candidate for new claims"
        );
        assert_eq!(
            walk(d, &fx, INFRA_ATTEST_SCOPE).await.as_deref(),
            Some(succ.as_str()),
            "I384 the successor's scope confers"
        );
    }

    /// **I385** — a `withdraws` kills at once; nothing is revived.
    pub(crate) async fn i385_withdraws_kills_at_once(d: &dyn FederationDirectory, tag: &str) {
        let fx = fixture(d, tag).await;
        let succ = supersede(
            d,
            &format!("gs-wsucc-{tag}"),
            &fx.root,
            &fx.subject,
            &fx.grant,
            INFRA_SERVE_SCOPE,
        )
        .await
        .expect("I385 the successor is admitted");
        withdraw(d, &format!("gs-w-{tag}"), &fx.root, &fx.subject, &succ).await;
        assert_eq!(
            walk(d, &fx, INFRA_SERVE_SCOPE).await,
            None,
            "I385 the withdrawn successor confers nothing and the superseded grant is not revived"
        );
        // Control: a never-superseded grant, withdrawn, is gone at once.
        let fx2 = fixture(d, &format!("{tag}-b")).await;
        withdraw(
            d,
            &format!("gs-w2-{tag}"),
            &fx2.root,
            &fx2.subject,
            &fx2.grant,
        )
        .await;
        assert_eq!(
            walk(d, &fx2, INFRA_SERVE_SCOPE).await,
            None,
            "I385 a withdrawn grant confers nothing"
        );
    }

    /// **I386** — only the grant's own root rotates it.
    pub(crate) async fn i386_a_foreign_supersedes_neither_retires_nor_confers(
        d: &dyn FederationDirectory,
        tag: &str,
    ) {
        let fx = fixture(d, tag).await;
        let foreign = format!("gs-foreign-{tag}");
        e2::put_key(d, &foreign, &[it::NODE]).await;
        // The door may or may not admit it; either way the walk must ignore it.
        let _ = supersede(
            d,
            &format!("gs-fsucc-{tag}"),
            &foreign,
            &fx.subject,
            &fx.grant,
            INFRA_ATTEST_SCOPE,
        )
        .await;
        assert_eq!(
            walk(d, &fx, INFRA_SERVE_SCOPE).await.as_deref(),
            Some(fx.grant.as_str()),
            "I386 a foreign supersedes does not retire the root's grant"
        );
        assert_eq!(
            walk(d, &fx, INFRA_ATTEST_SCOPE).await,
            None,
            "I386 a foreign supersedes confers nothing"
        );
        // The same from a SECOND root the user trusts: its `supersedes` over
        // the first root's grant is not a grant of its own (only a root
        // rotates its own grants), so it confers nothing either.
        let other_subject = format!("gs-osubj-{tag}");
        e2::put_key(d, &other_subject, &[it::NODE]).await;
        let root2 =
            root_conferring_on_a_node(d, &fx.user, &format!("gs-root2-{tag}"), &other_subject)
                .await;
        let _ = supersede(
            d,
            &format!("gs-r2succ-{tag}"),
            &root2,
            &fx.subject,
            &fx.grant,
            INFRA_ATTEST_SCOPE,
        )
        .await;
        assert_eq!(
            walk(d, &fx, INFRA_ATTEST_SCOPE).await,
            None,
            "I386 another trusted root's supersedes over this root's grant is no rotation"
        );
    }
}

#[cfg(all(test, any(feature = "sqlite", feature = "postgres")))]
mod runners {
    fn suffix() -> String {
        uuid::Uuid::new_v4().simple().to_string()[..12].to_owned()
    }

    macro_rules! dyn_runners {
        ($modname:ident, $fresh:expr) => {
            mod $modname {
                use super::suffix;
                use crate::federation::FederationDirectory;
                macro_rules! case {
                    ($name:ident) => {
                        #[tokio::test]
                        async fn $name() {
                            let Some(d) = $fresh.await else { return };
                            super::super::bodies::$name(
                                &d as &dyn FederationDirectory,
                                &format!("{}-{}", stringify!($name), suffix()),
                            )
                            .await
                        }
                    };
                }
                case!(i383_the_successor_confers);
                case!(i384_a_changed_scope_narrows);
                case!(i385_withdraws_kills_at_once);
                case!(i386_a_foreign_supersedes_neither_retires_nor_confers);
            }
        };
    }

    #[cfg(feature = "sqlite")]
    dyn_runners!(sqlite, async {
        use crate::store::Backend as _;
        let b = crate::store::sqlite::SqliteBackend::open_in_memory()
            .await
            .unwrap();
        b.run_migrations().await.unwrap();
        // v62 (E4): the asking party of the trust walk is THIS node.
        b.set_node_key_id(
            crate::federation::edition2::fixture_switch::put_key(
                &b,
                "gs-node",
                &[crate::federation::types::identity_type::NODE],
            )
            .await,
        );
        Some(b)
    });

    #[cfg(feature = "postgres")]
    dyn_runners!(postgres, async {
        use crate::store::Backend as _;
        let dsn = crate::test_pg::empty_dsn()?;
        let b = crate::store::postgres::PostgresBackend::connect(&dsn)
            .await
            .unwrap();
        b.run_migrations().await.unwrap();
        // v62 (E4): the asking party of the trust walk is THIS node.
        b.set_node_key_id(
            crate::federation::edition2::fixture_switch::put_key(
                &b,
                "gs-node",
                &[crate::federation::types::identity_type::NODE],
            )
            .await,
        );
        Some(b)
    });
}
