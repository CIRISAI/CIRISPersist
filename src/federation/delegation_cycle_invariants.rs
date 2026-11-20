//! v54.0.0 (CIRISPersist#1031, CC 4.1.1) — **the cycle-closing `delegates_to`
//! is refused at admission.**
//!
//! **v62.0.0 (slice C): no longer.** The decision answers through the kernel,
//! whose trust walk visits a cycle once (`ciris_kernel::trust::reaches`;
//! KERNEL.md 5; CC 4.4.3.34: "Cycles are visited once"; CIRISKernel `ADOPTING.md`: "no edge is refused
//! for closing a cycle"). Each witness below is kept, its refusal turned into
//! an admission: the closing edge is HELD, and the walk's reading of the
//! graph it closes (retractions, expiry, terms, the trust plane, the ceiling)
//! is still asserted through `delegation_path_hops`, the same lens the v54
//! gate read. (I597 is deleted; see below.)
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
//!
//! I608 (Codex round 3 on PR #1050) — a retraction asserted AFTER `now` (a
//! signer's clock inside the admitted future skew) has not happened yet: the
//! grant and licence walks at `now` still traverse the edge it names, so the
//! cycle gate must too. Gate (a) (the granter's bare retraction) and gate (b)
//! (a retraction naming the edge) are both read at `now`.
//!
//! I609 (Codex round 3 on PR #1050) — an edge whose row `expires_at` falls
//! before its signed term opens is never live under the lens (when the term
//! opens the row has expired), so it connects nothing; an edge whose expiry
//! falls after its term opens still connects.
//!
//! I597 (the cycle check and the insert as ONE step under the delegation
//! write lock, Codex on PR #1050) is deleted in v62.0.0's kernel pass 2 with
//! the gate, its lock and its re-ask: nothing is refused for closing a cycle,
//! so there is nothing to serialize.

//!
//! v62.0.0 (slice E6) — every edge is an edition-2 row signed by its
//! granter's `key:record` (`fixture_switch`): fixtures name keys by SEED,
//! every read (`has_fed_edge`, the walk) by KID (`kid_or_keep`). Gate (a),
//! the granter's BARE retraction (a `withdraws` naming no row), is deleted
//! from I590 (3) and I608 (a): Verify's reader requires a composer's
//! `refs.target`, so an edition-2 retraction always names its edge (gate (b)).

/// The backend-agnostic witness body; `run` instantiates it per backend.
#[cfg(all(test, any(feature = "sqlite", feature = "postgres")))]
pub mod bodies {
    use crate::federation::edition2::fixture_switch as e2;
    use crate::federation::tier_ingest::test_support as ts;
    use crate::federation::types::{
        attestation_tier, attestation_type, cohort_scope, identity_type,
    };
    use crate::federation::{Error, FederationDirectory};

    /// v62.0.0 — the key of seed `k`, an edition-2 `key:record`.
    ///
    /// v62.0.0 (E2-fix8; CC 2.7.5, K2-fix4) — an agent is a MACHINE delegate:
    /// a delegation onto it waits for its owner's voice (`delegate_owner`).
    /// So `k` is owned by a person (`owner-{k}`, role first: a test key seeds
    /// from the first 32 bytes of its name), through the edition-2 agent
    /// owner binding, before any edge names it.
    pub(crate) async fn agent(d: &dyn FederationDirectory, k: &str) {
        let _ = e2::put_key(d, k, &[identity_type::AGENT]).await;
        let owner = format!("owner-{k}");
        let _ = e2::put_key(d, &owner, &[identity_type::USER]).await;
        e2::put_agent_owner_binding(d, &owner, k, e2::ms(chrono::Utc::now())).await;
    }

    /// v62.0.0 (E2-fix8) — land an authored delegation with the voices its
    /// family's model names (`e2::land_delegation`: the delegate's, and a
    /// machine delegate's owner's). A delegation left HELD is reported as a
    /// refusal naming the unvoiced roles.
    async fn land(
        d: &dyn FederationDirectory,
        row: &crate::federation::Attestation,
    ) -> Result<(), Error> {
        use crate::federation::edition2::ingest::StatementOutcome;
        let (out, missing) = e2::land_delegation(d, row).await?;
        match out {
            StatementOutcome::Row { .. } | StatementOutcome::Voice { .. } => Ok(()),
            other => Err(Error::InvalidArgument(format!(
                "delegation {} is HELD ({other:?}); unvoiced roles: {:?}",
                row.attestation_id,
                missing.iter().map(|m| m.role.as_str()).collect::<Vec<_>>()
            ))),
        }
    }

    /// A row's envelope instant follows its column (a fixture that moves
    /// `asserted_at` before signing): `statement_of` reads the envelope's.
    fn restamp(row: &mut crate::federation::Attestation) {
        let at = crate::federation::admission::render_signed_instant(row.asserted_at);
        if let Some(env) = row.attestation_envelope.as_object_mut() {
            if env.contains_key(crate::federation::envelope::paths::ASSERTED_AT) {
                env.insert(
                    crate::federation::envelope::paths::ASSERTED_AT.to_owned(),
                    serde_json::json!(at),
                );
            }
        }
    }

    /// v62.0.0 (slice C) — the cycle-closing edge is ADMITTED: the kernel's
    /// walk visits a cycle once (`ciris_kernel::trust::reaches`; KERNEL.md 5;
    /// CC 4.4.3.34: "Cycles are visited once"), so no edge is refused for closing one. Was
    /// `expect_cycle`, which asserted the v54 refusal (CC 4.1.1's anti-pattern
    /// row). The walk's own reading of the graph is unchanged and still
    /// witnessed: the path the edge closes is the one the v54 gate reported,
    /// `hops` long, read by the same [`delegation_path_hops`] lens.
    ///
    /// [`delegation_path_hops`]: crate::federation::admission::delegation_path_hops
    async fn expect_cycle(
        d: &dyn FederationDirectory,
        r: Result<String, Error>,
        from: &str,
        to: &str,
        hops: usize,
        what: &str,
    ) {
        let id = r.unwrap_or_else(|e| {
            panic!(
                "{what}: v62 — no edge is refused for closing a cycle (the kernel's walk visits \
                 it once); got {} ({e})",
                e.kind()
            )
        });
        let seen = crate::federation::admission::delegation_path_hops(
            d,
            &e2::kid_or_keep(to),
            &e2::kid_or_keep(from),
            chrono::Utc::now(),
        )
        .await
        .expect("the walk reads");
        assert_eq!(
            seen,
            Some(hops),
            "{what}: the closing edge {id} is held, and the walk still reads the path it closes"
        );
    }

    /// v62.0.0 (slice C) — was `assert_no_edge` (a refused edge is not
    /// stored): the closing edge is held.
    async fn assert_no_edge(d: &dyn FederationDirectory, from: &str, to: &str, what: &str) {
        assert!(
            has_fed_edge(d, from, to).await,
            "{what}: v62 — the cycle-closing edge is held (the kernel refuses no edge for \
             closing a cycle)"
        );
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
        // Built in the earlier shape, shaped, then signed once (v62.0.0).
        let mut row = {
            ts::bare_attestation(
                &id,
                granter,
                grantee,
                &serde_json::json!({ "id": id, "scope": ["act_on_behalf"] }),
            )
        };
        row.attestation_type = attestation_type::DELEGATES_TO.to_owned();
        shape(&mut row);
        restamp(&mut row);
        let row = e2::row_of(&row, granter);
        let stored = row.attestation_id.clone();
        // v62.0.0 (E2-fix8): the delegation lands with its second signers.
        land(d, &row).await?;
        Ok(stored)
    }

    /// Stage a LOCAL `delegates_to(from → to)` and describe its crossing.
    pub(crate) async fn stage_local_edge(
        d: &dyn FederationDirectory,
        from: &str,
        to: &str,
    ) -> (
        String,
        crate::federation::ContextualIntegrity,
        crate::federation::TierPromotionCustody,
    ) {
        // v62.0.0 (E2-fix8; CP2, P8-fix13) — the JCS custody arms are shut
        // (`enter_mesh: earlier_form_object`): the edge is an EDITION-2 local
        // row (`from`'s statement, put at the local tier with its second
        // signers' voices) and it crosses on its own statement
        // (`TierPromotionCustody::Statement`).
        let id = uuid::Uuid::new_v4().to_string();
        let mut shape = ts::bare_attestation(
            &id,
            from,
            to,
            &serde_json::json!({ "id": id, "scope": ["act_on_behalf"] }),
        );
        shape.attestation_type = attestation_type::DELEGATES_TO.to_owned();
        shape.cohort_scope = cohort_scope::SELF.to_owned();
        shape.tier = attestation_tier::LOCAL.to_owned();
        restamp(&mut shape);
        let row = e2::row_of(&shape, from);
        land(d, &row)
            .await
            .expect("the edition-2 local edge is staged with its voices");
        let staged_id = row.attestation_id.clone();
        let staged = d.get_attestation(&staged_id).await.unwrap().unwrap();
        assert_eq!(
            staged.tier,
            attestation_tier::LOCAL,
            "the staged edge is local"
        );
        let ci = ts::describe_own(&staged, crate::federation::CrossingBasis::ProducerAuthority);
        let custody =
            crate::federation::TierPromotionCustody::of_statement(&staged, chrono::Utc::now())
                .expect("an edition-2 row crosses on its own statement");
        (staged_id, ci, custody)
    }

    /// Is a federation-tier `delegates_to(from → to)` stored?
    pub(crate) async fn has_fed_edge(d: &dyn FederationDirectory, from: &str, to: &str) -> bool {
        use crate::federation::attestation_query::test_support::AllAttestations as _;
        let (from, to) = (e2::kid_or_keep(from), e2::kid_or_keep(to));
        d.all_attestations_by(&from).await.unwrap().iter().any(|r| {
            r.attestation_type == attestation_type::DELEGATES_TO
                && r.attested_key_id == to
                && r.tier == attestation_tier::FEDERATION
        })
    }

    /// A retraction by `granter` against `grantee` naming the edge `target`,
    /// signed `ahead` in the future: inside the admitted skew, so the door
    /// stores it, and not yet in force at `now`. v62.0.0: a composer carries
    /// its target's family (`self:delegates_to`, the edge's), and names the
    /// edge by `refs.target` (`target` is its computed id).
    async fn future_retraction(
        d: &dyn FederationDirectory,
        granter: &str,
        grantee: &str,
        target: &str,
        ahead: chrono::Duration,
    ) {
        let id = uuid::Uuid::new_v4().to_string();
        let envelope = serde_json::json!({
            "id": id,
            "references_attestation_id": target,
        });
        let mut row = ts::bare_attestation(&id, granter, grantee, &envelope);
        row.attestation_type = attestation_type::WITHDRAWS.to_owned();
        row.asserted_at += ahead;
        row.scrub_timestamp = row.asserted_at;
        restamp(&mut row);
        let statement = e2::statement_of_family(&row, granter, "self:delegates_to");
        let row = e2::row_of_statement(&statement, attestation_tier::FEDERATION);
        d.put_attestation(crate::federation::SignedAttestation { attestation: row })
            .await
            .expect("a retraction inside the future skew is admitted");
    }

    /// I608 — see the module doc.
    pub async fn i608_a_future_retraction_hides_no_edge(d: &dyn FederationDirectory, tag: &str) {
        // v62.0.0 (E2-fix7): the role FIRST, the tag after it — a test key seeds
        // from the first 32 bytes of its name.
        let k = |n: &str| format!("{n}-{tag}");
        for n in ["e", "f"] {
            agent(d, &k(n)).await;
        }
        let ahead = crate::federation::operational::CLOCK_SKEW_TOLERANCE / 2;
        // v62.0.0 — gate (a) (a bare retraction, naming no edge) is deleted:
        // an edition-2 composer names its target.
        // Gate (b): e → f with f a subject; f withdraws it by name, ahead.
        let (e, f) = (k("e"), k("f"));
        let ef = put_edge(d, &e, &f, |r| r.subject_key_ids = vec![f.clone()])
            .await
            .expect("I608 (b) e → f, f a subject");
        future_retraction(d, &f, &f, &ef, ahead).await;
        expect_cycle(
            d,
            ts::put_delegates_to(d, &f, &e, None).await,
            &f,
            &e,
            1,
            "I608 (b): f's retraction naming e → f is not in force yet, so f → e closes a live \
             cycle",
        )
        .await;
        assert_no_edge(d, &f, &e, "I608 (b)").await;
    }

    /// I609 — see the module doc.
    pub async fn i609_an_edge_expiring_before_its_term_connects_nothing(
        d: &dyn FederationDirectory,
        tag: &str,
    ) {
        // v62.0.0 (E2-fix7): the role FIRST, the tag after it — a test key seeds
        // from the first 32 bytes of its name.
        let k = |n: &str| format!("{n}-{tag}");
        for n in ["o", "p", "o2", "p2"] {
            agent(d, &k(n)).await;
        }
        let now = chrono::Utc::now();
        let term = |opens: chrono::DateTime<chrono::Utc>,
                    expires: chrono::DateTime<chrono::Utc>| {
            move |r: &mut crate::federation::Attestation| {
                r.expires_at = Some(expires);
                r.attestation_envelope
                    .as_object_mut()
                    .expect("an object envelope")
                    .insert(
                        "delegation_valid_from".to_owned(),
                        serde_json::json!(crate::federation::admission::render_signed_instant(
                            opens
                        )),
                    );
            }
        };
        // o → p: the term opens in two hours, the row expires in one.
        let (o, p) = (k("o"), k("p"));
        put_edge(
            d,
            &o,
            &p,
            term(
                now + chrono::Duration::hours(2),
                now + chrono::Duration::hours(1),
            ),
        )
        .await
        .expect("I609 an edge expiring before its term opens is a stored row");
        ts::put_delegates_to(d, &p, &o, None).await.expect(
            "I609 o → p expires before its term opens, so no walk ever traverses it; p → o \
             closes nothing",
        );
        // Control: the row expires AFTER its term opens, so it is live then.
        let (o2, p2) = (k("o2"), k("p2"));
        put_edge(
            d,
            &o2,
            &p2,
            term(
                now + chrono::Duration::hours(2),
                now + chrono::Duration::hours(3),
            ),
        )
        .await
        .expect("I609 control edge");
        expect_cycle(
            d,
            ts::put_delegates_to(d, &p2, &o2, None).await,
            &p2,
            &o2,
            1,
            "I609 control: o2 → p2 is live from its term's opening until its expiry",
        )
        .await;
    }

    /// I590 — see the module doc.
    pub async fn i590_the_cycle_closing_edge_is_refused(d: &dyn FederationDirectory, tag: &str) {
        // v62.0.0 (E2-fix7): the role FIRST, the tag after it — a test key seeds
        // from the first 32 bytes of its name.
        let k = |n: &str| format!("{n}-{tag}");
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
            d,
            ts::put_delegates_to(d, &c, &a, None).await,
            &c,
            &a,
            2,
            "(1) c → a",
        )
        .await;
        assert_no_edge(d, &c, &a, "(1)").await;
        // Over-refusal control: an edge that closes nothing admits beside it.
        ts::put_delegates_to(d, &a, &c, None)
            .await
            .expect("(1) a → c is a second path, not a cycle");

        // (2) the self-edge is the root charter's shape, not a cycle.
        ts::put_delegates_to(d, &a, &a, None)
            .await
            .expect("(2) a → a is a root self-declaration, admitted");

        // (3) gate (a), the granter's BARE retraction: deleted in v62.0.0 (an
        // edition-2 composer names its target; gate (b) is (4)).

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
            d,
            ts::put_delegates_to(d, &f, &dk, None).await,
            &f,
            &dk,
            2,
            "(4) before",
        )
        .await;
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
                .insert(
                    field.to_owned(),
                    serde_json::json!(crate::federation::admission::render_signed_instant(at)),
                );
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
            d,
            ts::put_delegates_to(d, &pk, &o, None).await,
            &pk,
            &o,
            1,
            "(8) o → p opens in an hour; p → o closes a cycle that goes live then",
        )
        .await;

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
            d,
            put_edge(d, &n1, &r1, |_| {}).await,
            &n1,
            &r1,
            1,
            "(9c) a capability delegates_to(node → root) beside the root's grant",
        )
        .await;
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
            d,
            ts::put_delegates_to(d, &h4, &f4, None).await,
            &h4,
            &f4,
            1,
            "(10c) a capability delegates_to(h4 → f4) beside f4 → h4",
        )
        .await;

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
            d,
            ts::put_delegates_to(d, &chain[16], &chain[0], None).await,
            &chain[16],
            &chain[0],
            16,
            "(6) a 16-hop path is within the ceiling",
        )
        .await;
        ts::put_delegates_to(d, &chain[17], &chain[0], None)
            .await
            .expect("(6) a 17-hop path is past the ceiling every walk clamps to");

        // (7) the crossing: x → y in the mesh; a LOCAL y → x stages (the
        // walks read the federation tier only) and is refused when it crosses.
        let (x, y) = (k("x"), k("y"));
        ts::put_delegates_to(d, &x, &y, None)
            .await
            .expect("(7) x → y");
        // v62.0.0 (E2-fix8): the edition-2 local edge, crossing on its own
        // statement ([`stage_local_edge`]).
        let (staged_id, ci, custody) = stage_local_edge(d, &y, &x).await;
        d.enter_mesh(&staged_id, &ci, &custody)
            .await
            .expect("(7) the cycle-closing crossing is admitted (v62)");
        assert_eq!(
            d.get_attestation(&staged_id).await.unwrap().unwrap().tier,
            attestation_tier::FEDERATION,
            "(7) the crossed row is federation-tier"
        );
    }
}

#[cfg(all(test, any(feature = "sqlite", feature = "postgres")))]
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
                #[tokio::test(flavor = "multi_thread")]
                async fn i608() {
                    let Some(d) = $fresh.await else { return };
                    super::super::bodies::i608_a_future_retraction_hides_no_edge(
                        &d as &dyn FederationDirectory,
                        &format!("i608-{}", super::suffix()),
                    )
                    .await
                }
                #[tokio::test(flavor = "multi_thread")]
                async fn i609() {
                    let Some(d) = $fresh.await else { return };
                    super::super::bodies::i609_an_edge_expiring_before_its_term_connects_nothing(
                        &d as &dyn FederationDirectory,
                        &format!("i609-{}", super::suffix()),
                    )
                    .await
                }
            }
        };
    }

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
