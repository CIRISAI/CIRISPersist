//! v54.0.0 (CIRISPersist#1031, CC 4.1.1) — **the cycle-closing `delegates_to`
//! is refused at admission.**
//!
//! CC 4.1.1's anti-pattern table, row "Cycles (A → B → A)": *"Substrate MUST
//! detect cycles on the `delegates_to` graph and reject the cycle-closing
//! emission."* The walks were visited-guarded, so a cycle was tolerated at
//! read time; nothing refused the closing edge.
//!
//! I560 — one body, run on memory, sqlite and postgres:
//!
//! - (1) a chain `a → b → c` admits; `c → a` is refused
//!   `federation_delegation_cycle` (hops 2) and is not stored;
//! - (2) a self-edge `a → a` is the one-hop cycle (hops 0);
//! - (3) gate (a): after the granter's bare retraction of `b → c`, the same
//!   `c → a` admits — a retracted edge connects nothing;
//! - (4) gate (b): a retraction NAMING an edge kills it the same way;
//! - (5) an edge already expired connects nothing;
//! - (6) the ceiling: on a 17-hop chain `k0 → … → k17`, `k16 → k0` (a 16-hop
//!   path) is refused and `k17 → k0` (17 hops, past the ceiling every walk
//!   clamps to) admits;
//! - (7) a LOCAL edge that would close a cycle stages (the walks read the
//!   federation tier only), and is refused at the crossing — the row stays
//!   local.

/// The backend-agnostic witness body; `run` instantiates it per backend.
#[cfg(test)]
pub mod bodies {
    use crate::federation::tier_ingest::test_support as ts;
    use crate::federation::types::{
        attestation_tier, attestation_type, cohort_scope, identity_type,
    };
    use crate::federation::{Error, FederationDirectory};

    async fn agent(d: &dyn FederationDirectory, k: &str) {
        ts::register_hybrid_key_as(d, k, k, identity_type::AGENT).await;
    }

    /// Unwrap a `DelegationCycle`, or panic naming what came back instead —
    /// a neighbouring refusal is not this gate.
    fn expect_cycle(r: Result<String, Error>, from: &str, to: &str, hops: usize, what: &str) {
        match r {
            Err(Error::DelegationCycle {
                attesting_key_id,
                attested_key_id,
                hops: got,
            }) => {
                assert_eq!(
                    (attesting_key_id.as_str(), attested_key_id.as_str(), got),
                    (from, to, hops),
                    "{what}: the refusal names the edge and the path it closes"
                );
            }
            Err(e) => panic!(
                "{what}: expected federation_delegation_cycle, got {} ({e})",
                e.kind()
            ),
            Ok(id) => panic!("{what}: the cycle-closing edge {id} was ADMITTED"),
        }
    }

    /// No `delegates_to` from `from` to `to` is stored.
    async fn assert_no_edge(d: &dyn FederationDirectory, from: &str, to: &str, what: &str) {
        let stored = d.list_attestations_by(from).await.unwrap();
        assert!(
            !stored
                .iter()
                .any(|r| r.attestation_type == attestation_type::DELEGATES_TO
                    && r.attested_key_id == to),
            "{what}: a refused edge must not be stored"
        );
    }

    /// A `withdraws` by `granter` against `grantee` naming NO attestation —
    /// the granter's bare edge retraction (gate (a) of the walks).
    async fn bare_retraction(d: &dyn FederationDirectory, granter: &str, grantee: &str) {
        let id = uuid::Uuid::new_v4().to_string();
        let mut row = ts::bare_attestation(&id, granter, grantee, &serde_json::json!({ "id": id }));
        row.attestation_type = attestation_type::WITHDRAWS.to_owned();
        ts::seal_row_in_place(granter, &mut row);
        d.put_attestation(crate::federation::SignedAttestation { attestation: row })
            .await
            .expect("a granter's bare retraction admits");
    }

    /// A `delegates_to(granter → grantee)` shaped like
    /// [`ts::put_delegates_to`]'s, with `shape` applied before the seal.
    async fn put_edge(
        d: &dyn FederationDirectory,
        granter: &str,
        grantee: &str,
        shape: impl FnOnce(&mut crate::federation::Attestation),
    ) -> Result<String, Error> {
        let id = uuid::Uuid::new_v4().to_string();
        let mut row = ts::bare_attestation(
            &id,
            granter,
            grantee,
            &serde_json::json!({ "references_attestation_id": id, "scope": ["act_on_behalf"] }),
        );
        row.attestation_type = attestation_type::DELEGATES_TO.to_owned();
        shape(&mut row);
        ts::seal_row_in_place(granter, &mut row);
        d.put_attestation(crate::federation::SignedAttestation { attestation: row })
            .await?;
        Ok(id)
    }

    /// I560 — see the module doc.
    pub async fn i560_the_cycle_closing_edge_is_refused(d: &dyn FederationDirectory, tag: &str) {
        let k = |n: &str| format!("{tag}-{n}");
        for n in ["a", "b", "c", "d", "e", "f", "g", "h", "x", "y"] {
            agent(d, &k(n)).await;
        }
        let (a, b, c) = (k("a"), k("b"), k("c"));

        // (1) the chain admits; the closing edge is refused and not stored.
        ts::put_delegates_to(d, &a, &b, None)
            .await
            .expect("(1) a → b");
        let bc = ts::put_delegates_to(d, &b, &c, None)
            .await
            .expect("(1) b → c");
        expect_cycle(
            ts::put_delegates_to(d, &c, &a, None).await,
            &c,
            &a,
            2,
            "(1) c → a",
        );
        assert_no_edge(d, &c, &a, "(1)").await;
        // Over-refusal control: an edge that closes nothing admits beside it.
        ts::put_delegates_to(d, &a, &c, None)
            .await
            .expect("(1) a → c is a second path, not a cycle");

        // (2) the self-edge.
        expect_cycle(
            ts::put_delegates_to(d, &a, &a, None).await,
            &a,
            &a,
            0,
            "(2) a → a",
        );

        // (3) gate (a): the granter's bare retraction against the recipient.
        // `a → c` (admitted above) still reaches c; withdraw it too, so the
        // only paths from a to c are retracted ones.
        bare_retraction(d, &b, &c).await;
        bare_retraction(d, &a, &c).await;
        ts::put_delegates_to(d, &c, &a, None)
            .await
            .expect("(3) with b → c and a → c retracted by their granters, c → a closes nothing");

        // (4) gate (b), the #593 clause: a retraction NAMING the edge, by a
        // party other than its granter (so gate (a), which reads only the
        // granter's own rows, cannot see it). e → f lists f as a subject; f
        // withdraws it by name (CEG §3.2.3 rule 2); f → d then closes nothing.
        let (dk, e, f) = (k("d"), k("e"), k("f"));
        ts::put_delegates_to(d, &dk, &e, None)
            .await
            .expect("(4) d → e");
        let ef = put_edge(d, &e, &f, |r| r.subject_key_ids = vec![f.clone()])
            .await
            .expect("(4) e → f, f a subject");
        expect_cycle(
            ts::put_delegates_to(d, &f, &dk, None).await,
            &f,
            &dk,
            2,
            "(4) before",
        );
        ts::put_retraction(d, &f, &f, &ef, attestation_type::WITHDRAWS)
            .await
            .expect("(4) f withdraws e → f by name (rule 2: a subject)");
        ts::put_delegates_to(d, &f, &dk, None)
            .await
            .expect("(4) with e → f retracted by name, f → d closes nothing");
        let _ = bc;

        // (5) an expired edge connects nothing: g → h expired an hour ago.
        let (g, h) = (k("g"), k("h"));
        put_edge(d, &g, &h, |r| {
            r.asserted_at -= chrono::Duration::hours(2);
            r.scrub_timestamp = r.asserted_at;
            r.expires_at = Some(r.asserted_at + chrono::Duration::hours(1));
        })
        .await
        .expect("(5) an expired edge is still a well-formed row");
        ts::put_delegates_to(d, &h, &g, None)
            .await
            .expect("(5) g → h has expired; h → g closes nothing");

        // (6) the ceiling: a 17-hop chain.
        let chain: Vec<String> = (0..=17).map(|i| k(&format!("k{i}"))).collect();
        for c in &chain {
            agent(d, c).await;
        }
        for w in chain.windows(2) {
            ts::put_delegates_to(d, &w[0], &w[1], None)
                .await
                .expect("(6) chain hop");
        }
        expect_cycle(
            ts::put_delegates_to(d, &chain[16], &chain[0], None).await,
            &chain[16],
            &chain[0],
            16,
            "(6) a 16-hop path is within the ceiling",
        );
        ts::put_delegates_to(d, &chain[17], &chain[0], None)
            .await
            .expect("(6) a 17-hop path is past the ceiling every walk clamps to");

        // (7) the crossing: x → y in the mesh; a LOCAL y → x stages (the
        // walks read the federation tier only) and is refused when it crosses.
        let (x, y) = (k("x"), k("y"));
        ts::put_delegates_to(d, &x, &y, None)
            .await
            .expect("(7) x → y");
        let staged_id = d
            .attestation_insert_local(crate::federation::types::LocalAttestationInput {
                attestation_id: None,
                attesting_key_id: y.clone(),
                attested_key_id: Some(x.clone()),
                attestation_type: attestation_type::DELEGATES_TO.to_owned(),
                weight: Some(1.0),
                expires_at: None,
                attestation_envelope: crate::federation::envelope::EnvelopeCore::from_value(
                    serde_json::json!({
                        "dimension": crate::federation::self_at_login::DIMENSION_DELEGATES_TO,
                        "scope": ["act_on_behalf"],
                    }),
                )
                .unwrap(),
                subject_key_ids: Vec::new(),
                cohort_scope: cohort_scope::SELF.to_owned(),
                scrub_signature_classical: None,
                scrub_signature_pqc: None,
            })
            .await
            .expect("(7) the local door stages producer-authority rows");
        let staged = d.get_attestation(&staged_id).await.unwrap().unwrap();
        let ci = ts::describe_own(&staged, crate::federation::CrossingBasis::ProducerAuthority);
        match d
            .enter_mesh(&staged_id, &ci, &ts::actor_reseal(&staged))
            .await
        {
            Err(Error::DelegationCycle { hops: 1, .. }) => {}
            other => panic!("(7) crossing a cycle-closing local edge must be refused: {other:?}"),
        }
        assert_eq!(
            d.get_attestation(&staged_id).await.unwrap().unwrap().tier,
            attestation_tier::LOCAL,
            "(7) a refused crossing leaves the row local"
        );
    }
}

#[cfg(test)]
mod run {
    fn suffix() -> String {
        uuid::Uuid::new_v4().simple().to_string()
    }

    macro_rules! dyn_runners {
        ($modname:ident, $fresh:expr) => {
            mod $modname {
                use crate::federation::FederationDirectory;
                #[tokio::test(flavor = "multi_thread")]
                async fn i560() {
                    let Some(d) = $fresh.await else { return };
                    super::super::bodies::i560_the_cycle_closing_edge_is_refused(
                        &d as &dyn FederationDirectory,
                        &format!("i560-{}", super::suffix()),
                    )
                    .await
                }
            }
        };
    }

    dyn_runners!(memory_dyn, async {
        Some(crate::store::memory::MemoryBackend::new())
    });

    #[cfg(feature = "sqlite")]
    dyn_runners!(sqlite_dyn, async {
        use crate::store::Backend as _;
        let b = crate::store::sqlite::SqliteBackend::open_in_memory()
            .await
            .unwrap();
        b.run_migrations().await.unwrap();
        Some(b)
    });

    #[cfg(feature = "postgres")]
    dyn_runners!(postgres_dyn, async {
        use crate::store::Backend as _;
        let dsn = crate::test_pg::empty_dsn()?;
        let b = crate::store::postgres::PostgresBackend::connect(&dsn)
            .await
            .unwrap();
        b.run_migrations().await.unwrap();
        Some(b)
    });
}
