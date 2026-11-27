//! v53.0.0 — **the rc7 accord cut** (CIRISConstitution rc7 `fe459cf` /
//! `5e89627`, CIRISConstitution#139): commitments bind key material, the
//! accord's charter commits a recovery key per holder, and acceptance edges
//! rotate the way grants do.
//!
//! - **I430** — the commitment bytes are CC's spelling: JCS of
//!   `{key_id, pubkey_ed25519_base64, pubkey_ml_dsa_65_base64}` elements sorted
//!   by `key_id`, lowercase-hex SHA-256; one key twice, or an empty set, is
//!   refused; a record with no ML-DSA-65 key forms no element.
//! - **I431** — the T3 recovery door recomputes each successor's element from
//!   the key record this node stores: a record under a committed id with other
//!   keys does not satisfy the commitment (the squat).
//! - **I432** — the accord's charter must carry `recovery_commitments`, one per
//!   standing holder.
//! - **I433** — a commitment for a key that is not a standing holder is
//!   refused (stray).
//! - **I434** — a recovery key that is a holder's signing key, or one recovery
//!   key shared by two holders, is refused (not apart).
//! - **I435** — a non-accord family's charter carries no such requirement.
//! - **I436** — an accord decision carries no steward signatures, and stores
//!   and reads back on every backend without them.
//! - **I437** — `trust_root_valid`'s edge leg reads a superseded acceptance
//!   edge the way the capability walk reads a superseded grant: the successor
//!   is the live edge and the edge it replaced is not.
//! - **I438** — `trusted_roots_of` agrees with I437.
//! - **I439** — a keyless family confers only as it charters (CC 3.4.7): a
//!   grant one holder signs confers nothing as the family; the same grant
//!   scrubbed to the family's quorum does.
//!
//! v62.0.0 (JSON cut, wave 3, E5) — **I430–I436 are deleted** (lead's ruling 1:
//! the accord's charter, recovery commitments and decisions are genesis
//! bundle/2). Covered by C2's I2339 (a recovery counts on its one statement),
//! I2340 (a spent commitment never returns), I2341 (a recovery key is refused
//! as a signing key) and I2333 (a later bundle at the holders' majority).
//! I437–I439 (trust-root edges, a KEYED root's own conferral) survive.
//!
//! v62.0.0 (E9) — **I437–I439 re-pointed at edition 2** (W1b's rooted trust
//! root; DEPENDS ON W1's `trust_root_valid` edition-2 arm, W1b update 5):
//! - I437/I438: the asking party is THIS node. Its acceptance edge to r1 (the
//!   W1b root, `trust:accepts:v1`) is rotated by its own `supersedes`
//!   composer (`refs.target` = the edge, same `trust:{job}:{version}` family)
//!   naming r2, a second root founded by the bundle's holders.
//! - I439 (renamed by KR-fix2: it never tested a keyless conferral): the
//!   grant that confers is signed by the root's OWN KEY
//!   (`fixture_trust_root::confers_statement`, author = the root), so this
//!   witnesses a KEYED root. The root of the federation is the genesis bundle
//!   (CC 3.2 as ruled 2026-11-21); its counted grant, over the bundle's
//!   holders, is `edition2::root_grant_invariants` (I4200–I4204).
//!   The keyless family is gone (a root is an identity-ref community
//!   founded by the bundle's holders, CC 3.2). "Confers only as it charters"
//!   keeps its intent: a grant ONE founder signs confers nothing; the
//!   root's own `trust:confers:v1` grant (with the delegate's second voice)
//!   does, plane `Delegation`.
//!
//! v62.0.0 (R2-fixture; CC 3.2 T5) — **I437 / I438 are deleted** (a second
//! root to rotate an acceptance to is a keyed root); the note at their site
//! names the gap. I439 stays.

#[cfg(all(test, any(feature = "sqlite", feature = "postgres")))]
pub(crate) mod bodies {
    use crate::federation::edition2::fixture_genesis::HOLDER_SEEDS;
    use crate::federation::edition2::fixture_switch as e2;
    use crate::federation::operational::test_support as ops;
    use crate::federation::trust_root::{
        capability_roots_to_trusted_root, trust_root_valid, ConferralPlane, INFRA_SERVE_SCOPE,
    };
    use crate::federation::FederationDirectory;

    // ── I437 / I438 ─────────────────────────────────────────────────────
    //
    // v62.0.0 (R2-fixture; CC 3.2 T5) — I437 / I438 DELETED: they rotated THIS
    // node's acceptance from one root to a SECOND root (`stand_up_e2_root`, a
    // keyed root). A node accepts one root, the bundle's lineage; a second
    // lineage is a fork, unreachable in v62. The acceptance's own end is its
    // `withdraws` (peer_rooting I2223, `exercise_ceremony_plane_capability_walk`'s
    // lever). GAP: an acceptance superseded by its own successor (same lineage)
    // has no witness.

    // ── I439 ────────────────────────────────────────────────────────────

    /// **I439** — CC 3.4.7: a threshold root confers only as itself; one
    /// founder's grant is no grant by the root.
    pub(crate) async fn i439_a_keyed_root_confers_by_its_own_key_not_by_one_founder(
        d: &dyn FederationDirectory,
        tag: &str,
    ) {
        let node = ops::e2_node(d, tag);
        let r = e2::rooted_trust_root(d, &HOLDER_SEEDS, "quorum:2/3").await;
        assert!(
            trust_root_valid(d, &node, &r.lineage, crate::host::clock::now())
                .await
                .unwrap()
                .valid,
            "I439 CONTROL: the root is valid for this node (depends on W1)"
        );
        let subject_seed = format!("i439-subject-{tag}");
        let subject = e2::put_key(d, &subject_seed, &["user"]).await;
        let lone = ops::e2_trust_edge_by_key(
            &r.founder_key(0),
            &r.founders[0],
            &subject,
            &[INFRA_SERVE_SCOPE],
        );
        e2::put_statement(d, &lone)
            .await
            .expect("a founder's own grant is held");
        e2::put_statement(d, &e2::voice_of(&lone, &subject_seed))
            .await
            .expect("the delegate's voice");
        assert_eq!(
            capability_roots_to_trusted_root(
                d,
                &node,
                &subject,
                INFRA_SERVE_SCOPE,
                crate::host::clock::now()
            )
            .await
            .unwrap()
            .map(|g| g.root_key_id),
            None,
            "I439: one founder's grant is no grant by the root"
        );
        let grant = crate::federation::edition2::fixture_trust_root::put_conferral(
            d,
            &r,
            &subject_seed,
            &[INFRA_SERVE_SCOPE],
        )
        .await
        .expect("I439: the root's grant admits");
        let g = capability_roots_to_trusted_root(
            d,
            &node,
            &subject,
            INFRA_SERVE_SCOPE,
            crate::host::clock::now(),
        )
        .await
        .unwrap()
        .expect("I439: the root's own grant confers");
        assert_eq!(
            g.root_key_id, r.lineage,
            "I439: the threshold root is the root"
        );
        assert_eq!(
            g.grant_attestation_id,
            grant.hex(),
            "I439: the root's grant"
        );
        assert_eq!(
            g.conferral_plane,
            ConferralPlane::Delegation,
            "I439: the plane"
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
                macro_rules! tagged {
                    ($name:ident) => {
                        #[tokio::test]
                        async fn $name() {
                            // v62.0.0 (E9) — flipped: edition 2, the node key set by
                            // the backend constructor below.
                            let Some(d) = $fresh.await else { return };
                            super::super::bodies::$name(
                                &d as &dyn FederationDirectory,
                                &format!("{}-{}", stringify!($name), suffix()),
                            )
                            .await
                        }
                    };
                }
                tagged!(i439_a_keyed_root_confers_by_its_own_key_not_by_one_founder);
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
        b.set_node_key_id(
            crate::federation::edition2::fixture_switch::put_key(&b, "rc7-node", &["node"]).await,
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
        b.set_node_key_id(
            crate::federation::edition2::fixture_switch::put_key(&b, "rc7-node", &["node"]).await,
        );
        Some(b)
    });
}
