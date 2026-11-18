//! CIRISPersist#972 (CC 3.1.3.2, "a node gives no acceptance") — **I339:
//! a node is seated nowhere by others' signatures alone.** sqlite, postgres.
//!
//! v62.0.0 (wave 3, slice E6) — **I335–I338 and I1101 are deleted.** They
//! witnessed the earlier canonical `infrastructure` community: a node seated
//! there by the founders' quorum and the accord's co-scrub on its key record
//! (I335/I336), refused without it (I337), a person still accepting (I338),
//! and the serve seat's announced-owner predicate at that community's
//! widening (I1101). Canonical standing is now membership in `serve_nodes`
//! of the genesis bundle/2 in force; the covering witnesses are C1's I2314
//! (placed: seats canonical, holders not; `is_canonical_by_bundle` and
//! `admission::is_canonical_effective`), I2316 (a later bundle's seats) and
//! C2's I2330 / I2335–I2336 (the test ceremony's seats canonical, a fresh
//! node nothing).
//!
//! **I339**, rewritten on the edition-2 planes: an owned node (an edition-2
//! `node` key with an announced owner binding) is not seated in an ordinary
//! community or a family by others' signatures. A founding roster listing it
//! unsigned does not land (`Pending`: its voice is missing); a widening
//! naming it is refused `acceptance_unresolved`; a family widening seats it
//! nowhere.

#[cfg(all(test, any(feature = "sqlite", feature = "postgres")))]
pub(crate) mod bodies {
    use crate::federation::edition2::fixture_switch as e2;
    use crate::federation::membership_acceptance::RULE_ACCEPTANCE_UNRESOLVED;
    use crate::federation::membership_acceptance_invariants::bodies as m;
    use crate::federation::tier_ingest::test_support as ts;
    use crate::federation::types::identity_type;
    use crate::federation::FederationDirectory;

    async fn seated(d: &dyn FederationDirectory, group: &str, key: &str) -> bool {
        d.active_community_members(group)
            .await
            .unwrap()
            .iter()
            .any(|x| x.key_id == key)
    }

    /// **I339** — a node elsewhere is not seated by others' signatures.
    pub async fn i339_a_node_elsewhere_is_refused(d: &dyn FederationDirectory) {
        let s = m::suffix();
        let (cid, xid, fid, founder, owner, node_s) = (
            format!("i339-c-{s}"),
            format!("i339-x-{s}"),
            format!("i339-f-{s}"),
            format!("i339-u-{s}"),
            format!("i339-o-{s}"),
            format!("i339-n-{s}"),
        );
        m::reg(d, &[&cid, &xid, &fid, &founder, &owner]).await;
        let node = e2::put_key(d, &node_s, &[identity_type::NODE]).await;
        // The node is CLAIMED, by someone who is not a signer here: the
        // owner's binding (with the node's own voice, `ownership:*`'s second
        // signer), so the "no unstewarded node" rule passes and the consent
        // gate is what is reached.
        let ob = ts::owner_binding_attestation(&format!("i339-bind-{s}"), &owner, &node_s);
        let ob_st = e2::carried_statement(&ob).expect("an edition-2 owner binding");
        e2::put_signed(d, &ob)
            .await
            .expect("I339: the owner claims the node");
        e2::put_statement(d, &e2::voice_of(&ob_st, &node_s))
            .await
            .expect("I339: the node's voice on its owner binding");

        // A founding roster listing the node unsigned does not land.
        m::found_community(d, &xid, "quorum:1/1", &[&founder], &[&node_s])
            .await
            .expect("I339: the founding voices are kept (Pending)");
        assert!(
            d.lookup_community(&e2::kid(&xid)).await.unwrap().is_none(),
            "I339: a roster listing an unsigned node is not in force"
        );

        let now = chrono::Utc::now();
        m::found_community(d, &cid, "quorum:1/1", &[&founder], &[])
            .await
            .unwrap();
        let e = m::widen_community(d, &cid, &[&founder], &node_s, None, now)
            .await
            .expect_err("I339: a node in an ordinary community");
        assert_eq!(m::rule_of(&e), RULE_ACCEPTANCE_UNRESOLVED, "I339: {e}");
        assert!(
            !seated(d, &e2::kid(&cid), &node).await,
            "I339: not seated in the community"
        );
        m::found_family(d, &fid, "founder_only", &[&founder], &[])
            .await
            .unwrap();
        let _ = m::widen_family(d, &fid, &founder, &node_s, None, now).await;
        assert!(
            !d.active_family_members(&e2::kid(&fid))
                .await
                .unwrap()
                .iter()
                .any(|x| x.key_id == node),
            "I339: not seated in the family"
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
                async fn i339() {
                    let Some(d) = $fresh.await else { return };
                    bodies::i339_a_node_elsewhere_is_refused(&d as &dyn FederationDirectory).await
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
