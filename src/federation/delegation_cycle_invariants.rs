//! v54.0.0 (CIRISPersist#1031, CC 4.1.1) — **the cycle-closing `delegates_to`
//! is refused at admission.**
//!
//! CC 4.1.1's anti-pattern table, row "Cycles (A → B → A)": *"Substrate MUST
//! detect cycles on the `delegates_to` graph and reject the cycle-closing
//! emission."* The walks were visited-guarded, so a cycle was tolerated at
//! read time; nothing refused the closing edge.
//!
//! I590 — one body, run on memory, sqlite and postgres:
//!
//! - (1) a chain `a → b → c` admits; `c → a` is refused
//!   `federation_delegation_cycle` (hops 2) and is not stored;
//! - (2) a self-edge `a → a` ADMITS: it is the root charter's
//!   self-declaration (`trust_root`), not the "A → B → A" anti-pattern;
//! - (3) gate (a): after the granter's bare retraction of `b → c`, the same
//!   `c → a` admits — a retracted edge connects nothing;
//! - (4) gate (b): a retraction NAMING an edge kills it the same way;
//! - (5) an edge already expired connects nothing;
//! - (6) the ceiling: on a 17-hop chain `k0 → … → k17`, `k16 → k0` (a 16-hop
//!   path) is refused and `k17 → k0` (17 hops, past the ceiling every walk
//!   clamps to) admits;
//! - (7) a LOCAL edge that would close a cycle stages (the walks read the
//!   federation tier only), and is refused at the crossing — the row stays
//!   local;
//! - (8) the edge's signed TERM (#1032), read through the walks' own lens: an
//!   edge whose `delegation_valid_until` (or older `valid_until`) has passed
//!   connects nothing, while an edge whose `delegation_valid_from` is still
//!   ahead DOES connect (it will be walked when its term opens), so the edge
//!   closing a cycle through it is refused now;
//! - (9) an ACCEPTANCE edge (`trust:accepts:v1`) is the subscription plane,
//!   not in the cycle graph (CC 4.2.1): a key root's grant `R → N` and the
//!   grantee's acceptance `N → R` admit in EITHER order, a CAPABILITY edge
//!   closing the same pair is still refused, and a chain that reaches the
//!   root only THROUGH an acceptance edge is not a cycle;
//! - (10) a CHARTER edge (`trust:charter:v1`) is the trust plane too: a
//!   family-shaped charter holder → root admits beside the root's capability
//!   edge back to the holder, in either order, and a capability edge closing
//!   the same pair is still refused.

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

    /// I590 — see the module doc.
    pub async fn i590_the_cycle_closing_edge_is_refused(d: &dyn FederationDirectory, tag: &str) {
        let k = |n: &str| format!("{tag}-{n}");
        for n in [
            "a", "b", "c", "d", "e", "f", "g", "h", "x", "y", "m", "n", "o", "p", "q", "r", "r1",
            "n1", "r2", "n2", "r3", "x3", "y3", "h4", "f4", "h5", "f5",
        ] {
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

        // (2) the self-edge is the root charter's shape, not a cycle.
        ts::put_delegates_to(d, &a, &a, None)
            .await
            .expect("(2) a → a is a root self-declaration, admitted");

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

        // (8) the signed term, judged by the same lens the licence and grant
        // walks use. A term that has closed connects nothing, under either
        // spelling of its upper bound; a term that has not opened yet still
        // connects, since the cycle goes live when it opens.
        let set_term = |r: &mut crate::federation::Attestation,
                        field: &str,
                        at: chrono::DateTime<chrono::Utc>| {
            r.attestation_envelope
                .as_object_mut()
                .expect("an object envelope")
                .insert(field.to_owned(), serde_json::json!(at.to_rfc3339()));
        };
        let now = chrono::Utc::now();
        let (m, n) = (k("m"), k("n"));
        put_edge(d, &m, &n, |r| {
            set_term(
                r,
                "delegation_valid_until",
                now - chrono::Duration::hours(1),
            );
        })
        .await
        .expect("(8) a term-bound edge whose term has closed is a well-formed row");
        ts::put_delegates_to(d, &n, &m, None)
            .await
            .expect("(8) m → n's delegation_valid_until has passed; n → m closes nothing");
        let (q, rk) = (k("q"), k("r"));
        put_edge(d, &q, &rk, |r| {
            set_term(r, "valid_until", now - chrono::Duration::hours(1));
        })
        .await
        .expect("(8) the older valid_until spelling");
        ts::put_delegates_to(d, &rk, &q, None)
            .await
            .expect("(8) q → r's valid_until has passed; r → q closes nothing");
        let (o, pk) = (k("o"), k("p"));
        put_edge(d, &o, &pk, |r| {
            set_term(r, "delegation_valid_from", now + chrono::Duration::hours(1));
        })
        .await
        .expect("(8) a term that opens later");
        expect_cycle(
            ts::put_delegates_to(d, &pk, &o, None).await,
            &pk,
            &o,
            1,
            "(8) o → p opens in an hour; p → o closes a cycle that goes live then",
        );

        // (9) acceptance edges are the subscription plane. Kills: the search
        // following acceptance edges (m1: 9a, 9b and 9d refuse); exempting
        // every edge into a self-chartered root instead (m2, option (c): 9c
        // admits the capability cycle).
        let accept = |r: &mut crate::federation::Attestation| {
            let env = r
                .attestation_envelope
                .as_object_mut()
                .expect("an object envelope");
            env.insert(
                "dimension".to_owned(),
                serde_json::json!(crate::federation::trust_root::TRUST_ACCEPTS_DIMENSION),
            );
            env.insert(
                "scope".to_owned(),
                serde_json::json!([
                    crate::federation::trust_root::INFRA_ATTEST_SCOPE,
                    crate::federation::trust_root::INFRA_SERVE_SCOPE
                ]),
            );
        };
        let grant = |r: &mut crate::federation::Attestation| {
            r.attestation_envelope
                .as_object_mut()
                .expect("an object envelope")
                .insert(
                    "scope".to_owned(),
                    serde_json::json!([crate::federation::trust_root::INFRA_SERVE_SCOPE]),
                );
        };
        // (9a) grant first: the key root charters itself and grants its node;
        // the node's boot then accepts the root.
        let (r1, n1) = (k("r1"), k("n1"));
        ts::put_delegates_to(d, &r1, &r1, None)
            .await
            .expect("(9a) the key root's self-charter");
        put_edge(d, &r1, &n1, grant)
            .await
            .expect("(9a) the root grants its node infra:serve");
        put_edge(d, &n1, &r1, accept).await.expect(
            "(9a) the grantee's acceptance of the root that granted it is a subscription, \
             not a cycle",
        );
        // (9b) acceptance first: the node subscribes, then the root grants it.
        let (r2, n2) = (k("r2"), k("n2"));
        ts::put_delegates_to(d, &r2, &r2, None)
            .await
            .expect("(9b) the key root's self-charter");
        put_edge(d, &n2, &r2, accept)
            .await
            .expect("(9b) the node accepts the root");
        put_edge(d, &r2, &n2, grant)
            .await
            .expect("(9b) the root's grant to a subscriber closes no cycle");
        // (9c) a CAPABILITY edge closing the same pair is still a cycle.
        expect_cycle(
            put_edge(d, &n1, &r1, |_| {}).await,
            &n1,
            &r1,
            1,
            "(9c) a capability delegates_to(node → root) beside the root's grant",
        );
        // (9d) a chain that reaches the root only THROUGH an acceptance edge:
        // x3 accepts r3, y3 delegates to x3, and r3 → y3 closes nothing.
        let (r3, x3, y3) = (k("r3"), k("x3"), k("y3"));
        ts::put_delegates_to(d, &r3, &r3, None)
            .await
            .expect("(9d) the key root's self-charter");
        put_edge(d, &x3, &r3, accept)
            .await
            .expect("(9d) x3 accepts r3");
        ts::put_delegates_to(d, &y3, &x3, None)
            .await
            .expect("(9d) y3 → x3");
        put_edge(d, &r3, &y3, grant)
            .await
            .expect("(9d) r3 → y3 reaches r3 again only through x3's acceptance: not a cycle");

        // (10) the charter is the trust plane as well. Kills: the search or the
        // gate reading only the acceptance label (10a or 10b refuses).
        let charter = |r: &mut crate::federation::Attestation| {
            r.attestation_envelope
                .as_object_mut()
                .expect("an object envelope")
                .insert(
                    "dimension".to_owned(),
                    serde_json::json!(crate::federation::trust_root::TRUST_CHARTER_DIMENSION),
                );
        };
        // (10a) the capability edge first, then the charter closing the pair.
        let (h4, f4) = (k("h4"), k("f4"));
        ts::put_delegates_to(d, &f4, &h4, None)
            .await
            .expect("(10a) f4 → h4, a capability edge");
        put_edge(d, &h4, &f4, charter)
            .await
            .expect("(10a) the charter h4 → f4 is the trust plane, not a cycle");
        // (10b) the charter first, then a capability edge the other way.
        let (h5, f5) = (k("h5"), k("f5"));
        put_edge(d, &h5, &f5, charter)
            .await
            .expect("(10b) the charter h5 → f5");
        ts::put_delegates_to(d, &f5, &h5, None)
            .await
            .expect("(10b) f5 → h5 reaches f5 again only through the charter: not a cycle");
        // (10c) a capability edge closing the same pair is still refused.
        expect_cycle(
            ts::put_delegates_to(d, &h4, &f4, None).await,
            &h4,
            &f4,
            1,
            "(10c) a capability delegates_to(h4 → f4) beside f4 → h4",
        );

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
                async fn i590() {
                    let Some(d) = $fresh.await else { return };
                    super::super::bodies::i590_the_cycle_closing_edge_is_refused(
                        &d as &dyn FederationDirectory,
                        &format!("i590-{}", super::suffix()),
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
