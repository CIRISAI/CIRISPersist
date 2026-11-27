//! v62.0.0 (RELAY-1; CC Part 5 "the accord's rows and tombstones": "A node
//! carries an accord row only when its signature verifies as a seated
//! holder's of the roster the row names, and carries none it cannot
//! verify"; CC 4.2.1.1) — **the accord relay verb judges the ROW against
//! the bundle it names.**
//!
//! Every witness runs on sqlite AND postgres, across stores: the row is
//! signed by a holder's key and judged on relaying nodes that never put it.
//!
//! - **I6850** — a holder's invocation (`accord:invoke:drill`, no head) is
//!   relayed by a rooted node (bundle in force, this node's acceptance of
//!   the lineage), on TWO rooted stores.
//! - **I6851** — a non-holder's invocation is not relayed (a key no bundle
//!   places: cannot judge); a holder's key under ANOTHER holder's `iss` is
//!   judged and not seated (`iss_not_holder`).
//! - **I6852** — a head-naming row (`accord:human_dignity`) by a holder,
//!   naming the bundle in force, is relayed. After a SUCCESSOR bundle of the
//!   lineage is installed, the same holder's row naming the SUPERSEDED first
//!   bundle is still relayed (the text's bound is the roster the row NAMES),
//!   while a holder seated only by the successor, naming the first bundle,
//!   is not seated there; a head that is no bundle cannot be judged.
//! - **I6853** — an unrooted node: with the bundle held but no acceptance
//!   of the lineage, the holder's invocation is judged seated and NOT
//!   relayed (no edge); with nothing held it cannot be judged.

#[cfg(all(test, any(feature = "sqlite", feature = "postgres")))]
pub(crate) mod bodies {
    use crate::federation::edition2::fixture_genesis as fg;
    use crate::federation::edition2::fixture_switch as e2;
    use crate::federation::edition2::halt::{invocation_draft, InvocationTerms, InvokeKind};
    use crate::federation::edition2::names::RowId;
    use crate::federation::trust_root::{may_relay_accord_statement, RelayVerdict};
    use crate::federation::FederationDirectory;
    use ciris_crypto::composite::CompositeSigningKey;
    use ciris_verify_core::cde::Value;

    fn t(s: &str) -> Value {
        Value::Text(s.to_owned())
    }

    fn now_ms() -> u64 {
        e2::ms(chrono::Utc::now())
    }

    fn kid_of(key: &CompositeSigningKey) -> [u8; 32] {
        ciris_verify_core::edition2::thumbprint(key.public_key())
    }

    /// A drill invocation by `key`, stating `holder` as `iss` / `author`.
    fn drill(key: &CompositeSigningKey, holder: &str, lineage: &str, id: &str) -> Vec<u8> {
        let at = now_ms();
        let d = invocation_draft(
            &InvocationTerms {
                kind: InvokeKind::Drill,
                holder: holder.to_owned(),
                accord_root: lineage.to_owned(),
                invocation_id: id.to_owned(),
                nonce: {
                    let mut n = [0u8; 32];
                    n[..id.len().min(32)].copy_from_slice(&id.as_bytes()[..id.len().min(32)]);
                    n
                },
                asserted_at_ms: at,
                valid_until_ms: at + 3_600_000,
                payload_digest: None,
            },
            &kid_of(key),
        )
        .expect("a drill drafts");
        d.assemble(key.sign(&d.sig_structure).expect("the key signs"))
    }

    /// An `accord:human_dignity` row by `key` as `holder`, naming `head`.
    fn dignity(key: &CompositeSigningKey, holder: &str, lineage: &str, head: &RowId) -> Vec<u8> {
        let p = crate::federation::edition2::emit::sorted_map(vec![
            (t("asserted_at"), Value::Uint(now_ms())),
            (t("author"), t(holder)),
            (t("accord_root"), t(lineage)),
            (t("dimension"), t("accord:human_dignity:v1")),
            (
                t("refs"),
                crate::federation::edition2::emit::sorted_map(vec![(
                    t("head"),
                    ciris_verify_core::edition2::row_ref(&head.0),
                )]),
            ),
        ]);
        ciris_verify_core::edition2::sign_row_statement(
            key,
            holder,
            lineage,
            "scores",
            "accord:human_dignity",
            &p,
            vec![],
        )
        .expect("a dignity row signs")
    }

    async fn verdict(d: &dyn FederationDirectory, node: &str, st: &[u8]) -> RelayVerdict {
        may_relay_accord_statement(d, node, st)
            .await
            .expect("the relay verb reads")
    }

    /// The rooted fixture on `d`: lineage, the bundle in force, holder 0's
    /// identity-ref and key.
    async fn rooted(d: &dyn FederationDirectory) -> (String, RowId, String, CompositeSigningKey) {
        let r = e2::rooted_trust_root(d, &fg::HOLDER_SEEDS, "quorum:2/3").await;
        (
            r.lineage.clone(),
            RowId(r.head),
            r.founders[0].clone(),
            r.founder_key(0),
        )
    }

    /// **I6850** — a holder's invocation is relayed, on two rooted stores.
    pub(crate) async fn i6850_a_holders_invocation_relays(
        a: &dyn FederationDirectory,
        node_a: &str,
        b: &dyn FederationDirectory,
        node_b: &str,
    ) {
        let (lineage, _, h0, k0) = rooted(a).await;
        let _ = rooted(b).await;
        let st = drill(&k0, &h0, &lineage, "i6850");
        for (d, node, store) in [(a, node_a, "store A"), (b, node_b, "store B")] {
            let v = verdict(d, node, &st).await;
            assert!(
                v.may_relay(),
                "I6850 {store}: a holder's invocation is relayed: {v:?}"
            );
        }
    }

    /// **I6851** — a non-holder's invocation is not relayed.
    pub(crate) async fn i6851_a_non_holders_invocation(d: &dyn FederationDirectory, node: &str) {
        let (lineage, _, _, k0) = rooted(d).await;
        let z = "i6851-z";
        e2::put_key(d, z, &[crate::federation::types::identity_type::USER]).await;
        let kz = e2::signing_key(z);
        let iz = ciris_verify_core::edition2::identity_ref(&kid_of(&kz));
        let v = verdict(d, node, &drill(&kz, &iz, &lineage, "i6851-z")).await;
        assert!(
            !v.may_relay() && !v.signer_seated,
            "I6851: a key no bundle places is not carried: {v:?}"
        );
        let h1 = fg::identity_ref_of(fg::HOLDER_SEEDS[1]);
        let v = verdict(d, node, &drill(&k0, &h1, &lineage, "i6851-swap")).await;
        assert!(
            !v.may_relay() && !v.signer_seated,
            "I6851: a holder's key under another holder's iss is not carried: {v:?}"
        );
    }

    /// **I6852** — a head-naming row against the bundle it names, before and
    /// after a successor bundle.
    pub(crate) async fn i6852_a_head_naming_row(d: &dyn FederationDirectory, node: &str) {
        let (lineage, first, h0, k0) = rooted(d).await;
        let v = verdict(d, node, &dignity(&k0, &h0, &lineage, &first)).await;
        assert!(
            v.may_relay(),
            "I6852: a holder's row naming the bundle in force is relayed: {v:?}"
        );
        // A successor bundle seats a fourth holder.
        let later = fg::later_v2(
            fg::bundle_v2_wide(),
            &[1, 2, 3, 4],
            &fg::SERVE_NODE_SEEDS,
            &[1, 2, 3, 4],
        );
        fg::install_ceremony_v2(d, &later)
            .await
            .unwrap_or_else(|e| panic!("I6852 premise: the successor installs: {e}"));
        let v = verdict(d, node, &dignity(&k0, &h0, &lineage, &first)).await;
        assert!(
            v.may_relay(),
            "I6852: a holder of the SUPERSEDED bundle it names is still carried (the roster the \
             row names): {v:?}"
        );
        let k4 = fg::test_key(4);
        let h4 = fg::identity_ref_of(4);
        let v = verdict(d, node, &dignity(&k4, &h4, &lineage, &first)).await;
        assert!(
            v.roster_resolvable && !v.signer_seated,
            "I6852: a holder of the successor only is no holder of the first bundle: {v:?}"
        );
        let v = verdict(d, node, &dignity(&k0, &h0, &lineage, &RowId([0xee; 32]))).await;
        assert!(
            !v.roster_resolvable,
            "I6852: a head that is no bundle cannot be judged: {v:?}"
        );
    }

    /// **I6853** — an unrooted node.
    pub(crate) async fn i6853_an_unrooted_node(
        held: &dyn FederationDirectory,
        node_held: &str,
        empty: &dyn FederationDirectory,
        node_empty: &str,
    ) {
        fg::install_ceremony_v2(held, fg::bundle_v2_wide())
            .await
            .unwrap_or_else(|e| panic!("I6853 premise: the bundle installs: {e}"));
        let lineage = fg::bundle_v2_wide().spec.family_key_id.clone();
        let h0 = fg::identity_ref_of(fg::HOLDER_SEEDS[0]);
        let st = drill(&fg::test_key(fg::HOLDER_SEEDS[0]), &h0, &lineage, "i6853");
        let v = verdict(held, node_held, &st).await;
        assert!(
            v.roster_resolvable && v.signer_seated && !v.edge_exists && !v.may_relay(),
            "I6853: bundle held, lineage not accepted: seated, not relayed: {v:?}"
        );
        let v = verdict(empty, node_empty, &st).await;
        assert!(
            !v.roster_resolvable && !v.may_relay(),
            "I6853: nothing held: cannot judge: {v:?}"
        );
    }
}

#[cfg(all(test, any(feature = "sqlite", feature = "postgres")))]
mod runners {
    macro_rules! runners {
        ($modname:ident, $fresh:expr) => {
            mod $modname {
                use crate::federation::FederationDirectory;
                #[tokio::test]
                async fn i6850_a_holders_invocation_relays() {
                    let Some((a, na)) = ($fresh)("i6850-a").await else {
                        return;
                    };
                    let Some((b, nb)) = ($fresh)("i6850-b").await else {
                        return;
                    };
                    super::super::bodies::i6850_a_holders_invocation_relays(
                        &a as &dyn FederationDirectory,
                        &na,
                        &b as &dyn FederationDirectory,
                        &nb,
                    )
                    .await
                }
                #[tokio::test]
                async fn i6851_a_non_holders_invocation() {
                    let Some((d, n)) = ($fresh)("i6851").await else {
                        return;
                    };
                    super::super::bodies::i6851_a_non_holders_invocation(
                        &d as &dyn FederationDirectory,
                        &n,
                    )
                    .await
                }
                #[tokio::test]
                async fn i6852_a_head_naming_row() {
                    let Some((d, n)) = ($fresh)("i6852").await else {
                        return;
                    };
                    super::super::bodies::i6852_a_head_naming_row(
                        &d as &dyn FederationDirectory,
                        &n,
                    )
                    .await
                }
                #[tokio::test]
                async fn i6853_an_unrooted_node() {
                    let Some((h, nh)) = ($fresh)("i6853-h").await else {
                        return;
                    };
                    let Some((e, ne)) = ($fresh)("i6853-e").await else {
                        return;
                    };
                    super::super::bodies::i6853_an_unrooted_node(
                        &h as &dyn FederationDirectory,
                        &nh,
                        &e as &dyn FederationDirectory,
                        &ne,
                    )
                    .await
                }
            }
        };
    }

    #[cfg(feature = "sqlite")]
    runners!(sqlite, |tag: &'static str| async move {
        use crate::store::Backend as _;
        let b = crate::store::sqlite::SqliteBackend::open_in_memory()
            .await
            .unwrap();
        b.run_migrations().await.unwrap();
        let node = crate::federation::edition2::fixture_switch::put_key(
            &b,
            &format!("{tag}-node"),
            &[crate::federation::types::identity_type::NODE],
        )
        .await;
        b.set_node_key_id(&node);
        Some((b, node))
    });

    #[cfg(feature = "postgres")]
    runners!(postgres, |tag: &'static str| async move {
        use crate::store::Backend as _;
        let dsn = crate::test_pg::empty_dsn()?;
        let b = crate::store::postgres::PostgresBackend::connect(&dsn)
            .await
            .unwrap();
        b.run_migrations().await.unwrap();
        let node = crate::federation::edition2::fixture_switch::put_key(
            &b,
            &format!("{tag}-node"),
            &[crate::federation::types::identity_type::NODE],
        )
        .await;
        b.set_node_key_id(&node);
        Some((b, node))
    });
}
