//! v60.0.0 (CIRISPersist#988 item 1; CC 3.1.9.6, CC 2.4.2,
//! CLM-silo-projection-rebuildable) — **the credits and expertise ledgers are
//! the projection of this node's balance rows.**
//!
//! - **I1166** (memory, sqlite, postgres) — this node's `credits:` /
//!   `expertise:` rows project into the ledgers in the row's transaction: a
//!   newer row on a key replaces the held balance, an OLDER row arriving
//!   later does not (the fold is arrival-independent), and a peer's row on the
//!   same key is held but never projected. Both ledgers are byte-equal to
//!   their from-rows rebuild after every step.
//! - **I1169** (sqlite, postgres) — a pre-V203 ledger row (no
//!   `attestation_id`) makes `check_projection_rebuild` red, naming it; this
//!   node's row on the same key supersedes it and the rebuild is green again.
//! - **I1173** (sqlite, postgres) — V203 over an upgrading node's populated
//!   store: the six typed cirisnode tables (and V056's two watch tables) are
//!   gone; the ledgers keep their balances as legacy rows (no
//!   `attestation_id`); the scheduled takedown actions and delivery
//!   attestations keep their rows, free of the dropped foreign key; and the
//!   executed takedowns' `legal_basis` takes CC 3.3.2's spelling.

#[cfg(test)]
pub(crate) mod bodies {
    use crate::federation::attestation_admit::AttestationStore;
    use crate::federation::envelope::EnvelopeCore;
    use crate::federation::hard_case::test_support::DeclaresNode;
    use crate::federation::ledger_projection as lp;
    use crate::federation::silo_projection::{check_projection_rebuild, SiloProjection};
    use crate::federation::tier_ingest::test_support as ts;
    use crate::federation::types::{cohort_scope, identity_type};
    use crate::federation::{EmitAttestationInput, FederationDirectory};

    /// A signer and its derived, registered key id.
    pub(crate) struct Signer {
        pub(crate) signer: std::sync::Arc<crate::signing::LocalSigner>,
        pub(crate) id: String,
    }

    pub(crate) async fn signer<B>(b: &B, alias: &str, role: &str) -> Signer
    where
        B: FederationDirectory + ?Sized,
    {
        let signer = ts::local_signer(alias);
        let id = signer.derived_key_id();
        ts::register_hybrid_key_as(b, &id, alias, role).await;
        Signer { signer, id }
    }

    /// A balance row's input: `dimension`, the members, attested to
    /// `contributor`, signed at `asserted_at` when given.
    pub(crate) fn ledger_input(
        dimension: &str,
        score: f64,
        members: serde_json::Value,
        contributor: &str,
        asserted_at: Option<chrono::DateTime<chrono::Utc>>,
    ) -> EmitAttestationInput {
        let mut env = members;
        env["dimension"] = serde_json::json!(dimension);
        env["score"] = serde_json::json!(score);
        env["confidence"] = serde_json::json!(1.0);
        let mut core = EnvelopeCore::from_value(env).unwrap();
        core.asserted_at = asserted_at.map(|t| {
            crate::federation::admission::render_signed_instant(
                crate::federation::admission::truncate_to_substrate_resolution(t),
            )
        });
        let mut input =
            EmitAttestationInput::with_envelope("scores", core, cohort_scope::FEDERATION);
        input.attested_key_id = Some(contributor.to_owned());
        input
    }

    async fn emit<B>(b: &B, s: &Signer, input: EmitAttestationInput) -> String
    where
        B: FederationDirectory + Sync,
    {
        crate::federation::attestation_emit::emit_with_local_signer(b, &s.signer, input)
            .await
            .expect("the balance row is admitted")
            .attestation_id
    }

    async fn credits<B>(
        b: &B,
        s: &Signer,
        who: &str,
        balance: f64,
        at: Option<chrono::DateTime<chrono::Utc>>,
    ) -> String
    where
        B: FederationDirectory + Sync,
    {
        emit(
            b,
            s,
            ledger_input(
                "credits:health:en:arc_question:v1",
                1.0,
                serde_json::json!({lp::BALANCE_MEMBER: balance, lp::SOURCE_CONTRIBUTION_MEMBER: "c-1"}),
                who,
                at,
            ),
        )
        .await
    }

    /// The live ledger rows, rendered, after asserting the rebuild is green.
    async fn live<B>(b: &B, p: SiloProjection) -> Vec<String>
    where
        B: AttestationStore + Sync,
    {
        check_projection_rebuild(b, p)
            .await
            .unwrap_or_else(|e| panic!("I1166 {} is its rebuild: {e}", p.as_str()))
            .live
    }

    // ── I1166 ─────────────────────────────────────────────────────────────
    pub(crate) async fn i1166_the_ledgers_are_this_nodes_rows<B>(b: &B, tag: &str)
    where
        B: AttestationStore + DeclaresNode + Sync,
    {
        let node = signer(b, &format!("i1166-node-{tag}"), identity_type::NODE).await;
        b.declare_node_key_for_test(&node.id);
        let peer = signer(b, &format!("i1166-peer-{tag}"), identity_type::NODE).await;
        let alice = format!("i1166-alice-{tag}");
        ts::register_hybrid_key(b, &alice).await;

        // Explicit signed instants: two emits a microsecond apart may share
        // a truncated instant, and the fold then orders by id (a coin flip
        // this witness must not depend on).
        let t0 = chrono::Utc::now() - chrono::Duration::minutes(10);
        credits(b, &node, &alice, 12.5, Some(t0)).await;
        let rows = live(b, SiloProjection::CreditsLedger).await;
        assert_eq!(rows.len(), 1, "I1166: one key, one ledger row: {rows:?}");
        assert!(rows[0].contains("12.5"), "I1166: the balance: {rows:?}");

        // A newer row on the key replaces the balance.
        let newer = credits(
            b,
            &node,
            &alice,
            7.25,
            Some(t0 + chrono::Duration::minutes(1)),
        )
        .await;
        let rows = live(b, SiloProjection::CreditsLedger).await;
        assert_eq!(rows.len(), 1);
        assert!(
            rows[0].contains("7.25") && rows[0].contains(&newer),
            "I1166: {rows:?}"
        );

        // An OLDER row arriving later does not.
        credits(
            b,
            &node,
            &alice,
            3.5,
            Some(chrono::Utc::now() - chrono::Duration::hours(1)),
        )
        .await;
        let rows = live(b, SiloProjection::CreditsLedger).await;
        assert!(
            rows[0].contains("7.25") && !rows[0].contains("3.5"),
            "I1166: the fold keeps the greatest signed instant: {rows:?}"
        );

        // A peer's balance about the same contributor is held, not projected.
        let peers = credits(b, &peer, &alice, 99.5, None).await;
        assert!(b.get_attestation(&peers).await.unwrap().is_some());
        let rows = live(b, SiloProjection::CreditsLedger).await;
        assert!(
            rows.len() == 1 && rows[0].contains("7.25") && !rows[0].contains("99.5"),
            "I1166: a peer's row never overwrites this node's balance: {rows:?}"
        );

        // Expertise: score = the expertise, the active flag carried.
        emit(
            b,
            &node,
            ledger_input(
                "expertise:health:en:v1",
                0.75,
                serde_json::json!({
                    lp::EXPERTISE_MEMBER: 0.75,
                    lp::IS_ACTIVE_MEMBER: true,
                    lp::SOURCE_CONTRIBUTION_MEMBER: "c-1",
                }),
                &alice,
                None,
            ),
        )
        .await;
        let rows = live(b, SiloProjection::ExpertiseLedger).await;
        assert_eq!(rows.len(), 1, "I1166: {rows:?}");
        assert!(rows[0].contains("0.75"), "I1166: {rows:?}");
        // Two ledgers, two keys: the expertise row never displaces the credits
        // balance on the same contributor and cell.
        let rows = live(b, SiloProjection::CreditsLedger).await;
        assert!(
            rows.len() == 1 && rows[0].contains("7.25"),
            "I1166: the credits balance stands beside the expertise: {rows:?}"
        );
        // A malformed body is held but never projected.
        emit(
            b,
            &node,
            ledger_input(
                "expertise:health:sw:v1",
                0.5,
                serde_json::json!({lp::EXPERTISE_MEMBER: 0.5}),
                &alice,
                None,
            ),
        )
        .await;
        assert_eq!(live(b, SiloProjection::ExpertiseLedger).await.len(), 1);
    }

    // ── I1169 ─────────────────────────────────────────────────────────────
    #[cfg(any(feature = "sqlite", feature = "postgres"))]
    pub(crate) async fn i1169_a_legacy_balance_is_red_until_rehomed<B>(
        b: &B,
        tag: &str,
        insert_legacy: impl std::future::Future<Output = ()>,
    ) where
        B: AttestationStore + DeclaresNode + Sync,
    {
        let node = signer(b, &format!("i1169-node-{tag}"), identity_type::NODE).await;
        b.declare_node_key_for_test(&node.id);
        let bob = format!("i1169-bob-{tag}");
        ts::register_hybrid_key(b, &bob).await;
        insert_legacy.await;
        let e = check_projection_rebuild(b, SiloProjection::CreditsLedger)
            .await
            .expect_err("I1169: a balance with no row is not its rebuild");
        assert!(
            e.to_string().contains("credits_ledger") && e.to_string().contains(&bob),
            "I1169: the refusal names the projection and the row: {e}"
        );
        credits(b, &node, &bob, 3.0, None).await;
        check_projection_rebuild(b, SiloProjection::CreditsLedger)
            .await
            .expect("I1169: this node's row supersedes the legacy balance");
    }
}

#[cfg(test)]
mod run {
    use super::bodies as b;

    fn tag() -> String {
        uuid::Uuid::new_v4().simple().to_string()[..8].to_owned()
    }

    #[tokio::test]
    async fn i1166_memory() {
        let m = crate::store::memory::MemoryBackend::new();
        b::i1166_the_ledgers_are_this_nodes_rows(&m, &tag()).await;
    }

    #[cfg(feature = "sqlite")]
    async fn sqlite() -> crate::store::sqlite::SqliteBackend {
        use crate::store::Backend as _;
        let s = crate::store::sqlite::SqliteBackend::open_in_memory()
            .await
            .unwrap();
        s.run_migrations().await.unwrap();
        s
    }

    #[cfg(feature = "postgres")]
    async fn postgres() -> Option<crate::store::postgres::PostgresBackend> {
        use crate::store::Backend as _;
        let dsn = crate::test_pg::isolated_dsn()?;
        let p = crate::store::postgres::PostgresBackend::connect(&dsn)
            .await
            .unwrap();
        p.run_migrations().await.unwrap();
        Some(p)
    }

    #[cfg(feature = "sqlite")]
    #[tokio::test]
    async fn i1166_sqlite() {
        b::i1166_the_ledgers_are_this_nodes_rows(&sqlite().await, &tag()).await;
    }

    #[cfg(feature = "postgres")]
    #[tokio::test]
    async fn i1166_postgres() {
        let Some(p) = postgres().await else { return };
        b::i1166_the_ledgers_are_this_nodes_rows(&p, &tag()).await;
    }

    #[cfg(feature = "sqlite")]
    #[tokio::test]
    async fn i1169_sqlite() {
        let s = sqlite().await;
        let t = tag();
        let sql = format!(
            "INSERT INTO cirisnode_credits_ledger (contributor_id, domain, language, subject, \
             balance, last_updated_at, created_at) VALUES ('i1169-bob-{t}', 'health', 'en', \
             'arc_question', 2.0, '2026-01-01 00:00:00.000', '2026-01-01 00:00:00.000')"
        );
        b::i1169_a_legacy_balance_is_red_until_rehomed(&s, &t, s.test_execute(&sql)).await;
    }

    #[cfg(feature = "postgres")]
    #[tokio::test]
    async fn i1169_postgres() {
        let Some(p) = postgres().await else { return };
        let t = tag();
        let sql = format!(
            "INSERT INTO cirisnode.credits_ledger (contributor_id, domain, language, subject, \
             balance) VALUES ('i1169-bob-{t}', 'health', 'en', 'arc_question', 2.0)"
        );
        b::i1169_a_legacy_balance_is_red_until_rehomed(&p, &t, p.test_execute(&sql)).await;
    }

    // ── I1173 — V203 over an upgrading node ───────────────────────────────

    /// The seed both dialects share in shape: a Contribution, a vote on it, a
    /// moderation chain, two balances, a scheduled takedown and a delivery
    /// attestation naming the Contribution, and two executed takedowns in
    /// the old spellings.
    #[cfg(feature = "sqlite")]
    #[tokio::test]
    async fn i1173_sqlite() {
        use crate::store::Backend as _;
        let s = crate::store::sqlite::SqliteBackend::open_in_memory()
            .await
            .unwrap();
        s.run_migrations_through(202).await.unwrap();
        let cid = "11111111-1111-4111-8111-111111111111";
        for sql in [
            format!(
                "INSERT INTO cirisnode_contributions (contribution_id, contribution_type, domain, \
                 language, subject_kind, author_id, payload, submitted_at, signature, \
                 signing_key_id, persist_row_hash) VALUES ('{cid}', 'proposal', 'health', 'en', \
                 'arc_question', 'author', '{{}}', '2026-01-01T00:00:00Z', 'sig', 'author', 'h')"
            ),
            format!(
                "INSERT INTO cirisnode_votes (vote_id, contribution_id, voter_id, domain, \
                 language, payload, cast_at, signature, signing_key_id, persist_row_hash) VALUES \
                 ('22222222-2222-4222-8222-222222222222', '{cid}', 'voter', 'health', 'en', '{{}}', \
                 '2026-01-01T00:00:00Z', 'sig', 'voter', 'h')"
            ),
            format!(
                "INSERT INTO cirisnode_credits_ledger (contributor_id, domain, language, subject, \
                 balance, last_update_contribution) VALUES ('alice', 'health', 'en', \
                 'arc_question', 4.5, '{cid}')"
            ),
            format!(
                "INSERT INTO cirisnode_expertise_ledger (contributor_id, domain, language, \
                 expertise, is_active, last_update_contribution) VALUES ('alice', 'health', \
                 'en', 0.5, 1, '{cid}')"
            ),
            format!(
                "INSERT INTO cirisnode_scheduled_takedown_actions (notice_contribution_id, \
                 scheduled_eviction_at, status) VALUES ('{cid}', '2026-02-01T00:00:00Z', \
                 'pending')"
            ),
            format!(
                "INSERT INTO cirisnode_federation_delivery_attestations (announcement_id, \
                 announcement_canonical_hash, peer_key_id, peer_pubkey_ed25519_base64, \
                 received_at, transport_id, signature_classical, persist_row_hash) VALUES \
                 ('{cid}', zeroblob(32), 'peer', 'pk', '2026-01-01T00:00:00Z', 'reticulum', \
                 zeroblob(64), 'h')"
            ),
            "INSERT INTO purge_executions (notice_id, selection_digest, claimant_key_id, \
             record_count, notice_jcs, cosignatures_json, executed_by, origin, executed_at, \
             legal_basis) VALUES ('aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa', \
             'bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb', 'c', 1, '{}', \
             '[]', 'n', 'local', '2026-01-01T00:00:00.000Z', 'dmca_512')"
                .to_owned(),
        ] {
            s.test_execute(&sql).await;
        }
        s.run_migrations()
            .await
            .expect("I1173: V203 runs over a populated store");
        let one = |sql: &str| {
            let conn = s.conn_handle();
            let sql = sql.to_owned();
            move || -> String {
                conn.lock()
                    .query_row(&sql, [], |r| r.get::<_, String>(0))
                    .unwrap()
            }
        };
        for gone in [
            "cirisnode_contributions",
            "cirisnode_votes",
            "cirisnode_moderation_events",
            "cirisnode_slashing_attestations",
            "cirisnode_reconsideration_requests",
            "cirisnode_reconsideration_attestations",
            "cirisnode_consent_sla_watch",
            "cirisnode_revocation_promotion_watch",
        ] {
            let n = one(&format!(
                "SELECT CAST(COUNT(*) AS TEXT) FROM sqlite_master WHERE name = '{gone}'"
            ))();
            assert_eq!(n, "0", "I1173: {gone} is dropped");
        }
        assert_eq!(
            one(
                "SELECT CAST(balance AS TEXT) || '|' || COALESCE(attestation_id, 'NULL') || '|' \
                 || last_update_contribution FROM cirisnode_credits_ledger"
            )(),
            format!("4.5|NULL|{cid}"),
            "I1173: the balance is kept as a legacy row"
        );
        assert_eq!(
            one(
                "SELECT CAST(expertise AS TEXT) || '|' || COALESCE(attestation_id, 'NULL') \
                 FROM cirisnode_expertise_ledger"
            )(),
            "0.5|NULL"
        );
        assert_eq!(
            one("SELECT notice_contribution_id || '|' || status \
                 FROM cirisnode_scheduled_takedown_actions")(),
            format!("{cid}|pending")
        );
        assert_eq!(
            one("SELECT announcement_id FROM cirisnode_federation_delivery_attestations")(),
            cid
        );
        assert_eq!(
            one("SELECT legal_basis FROM purge_executions")(),
            "dmca512",
            "I1173: CC 3.3.2's spelling"
        );
        // No foreign key into the dropped table is left behind.
        assert_eq!(
            one("SELECT CAST(COUNT(*) AS TEXT) FROM pragma_foreign_key_check")(),
            "0"
        );
        // The kept tables take new rows (a dangling REFERENCES would refuse).
        s.test_execute(
            "INSERT INTO cirisnode_scheduled_takedown_actions (notice_contribution_id, \
             scheduled_eviction_at, status) VALUES ('x', '2026-02-01T00:00:00Z', 'pending')",
        )
        .await;
    }

    #[cfg(feature = "postgres")]
    #[tokio::test]
    async fn i1173_postgres() {
        use crate::store::Backend as _;
        let Some(dsn) = crate::test_pg::empty_dsn() else {
            return;
        };
        let p = crate::store::postgres::PostgresBackend::connect(&dsn)
            .await
            .unwrap();
        p.run_migrations_through(202).await.unwrap();
        let cid = "11111111-1111-4111-8111-111111111111";
        for sql in [
            format!(
                "INSERT INTO cirisnode.contributions (contribution_id, contribution_type, \
                 domain, language, subject_kind, author_id, payload, submitted_at, signature, \
                 signing_key_id, persist_row_hash) VALUES ('{cid}', 'proposal', 'health', 'en', \
                 'arc_question', 'author', '{{}}', '2026-01-01T00:00:00Z', 'sig', 'author', 'h')"
            ),
            format!(
                "INSERT INTO cirisnode.votes (vote_id, contribution_id, voter_id, domain, \
                 language, payload, cast_at, signature, signing_key_id, persist_row_hash) VALUES \
                 ('22222222-2222-4222-8222-222222222222', '{cid}', 'voter', 'health', 'en', '{{}}', \
                 '2026-01-01T00:00:00Z', 'sig', 'voter', 'h')"
            ),
            format!(
                "INSERT INTO cirisnode.credits_ledger (contributor_id, domain, language, subject, \
                 balance, last_update_contribution) VALUES ('alice', 'health', 'en', \
                 'arc_question', 4.5, '{cid}')"
            ),
            format!(
                "INSERT INTO cirisnode.expertise_ledger (contributor_id, domain, language, \
                 expertise, is_active, last_update_contribution) VALUES ('alice', 'health', \
                 'en', 0.5, TRUE, '{cid}')"
            ),
            format!(
                "INSERT INTO cirisnode.scheduled_takedown_actions (notice_contribution_id, \
                 scheduled_eviction_at, status) VALUES ('{cid}', '2026-02-01T00:00:00Z', \
                 'pending')"
            ),
            format!(
                "INSERT INTO cirisnode.federation_delivery_attestations (announcement_id, \
                 announcement_canonical_hash, peer_key_id, peer_pubkey_ed25519_base64, \
                 received_at, transport_id, signature_classical, persist_row_hash) VALUES \
                 ('{cid}', decode(repeat('00', 32), 'hex'), 'peer', 'pk', \
                 '2026-01-01T00:00:00Z', 'reticulum', decode(repeat('00', 64), 'hex'), 'h')"
            ),
            "INSERT INTO cirislens.purge_executions (notice_id, selection_digest, \
             claimant_key_id, record_count, notice_jcs, cosignatures_json, executed_by, origin, \
             executed_at, legal_basis) VALUES \
             ('aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa', \
             'bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb', 'c', 1, '{}', \
             '[]', 'n', 'local', '2026-01-01T00:00:00Z', 'dsa_article_16')"
                .to_owned(),
        ] {
            p.test_execute(&sql).await;
        }
        p.run_migrations()
            .await
            .expect("I1173: V203 runs over a populated store");
        let client = p.get_client().await.unwrap();
        let one = |sql: &'static str| {
            let c = &client;
            async move { c.query_one(sql, &[]).await.unwrap().get::<_, String>(0) }
        };
        assert_eq!(
            one(
                "SELECT string_agg(t, ',' ORDER BY t) FROM (SELECT table_schema || '.' || \
                 table_name AS t FROM information_schema.tables WHERE (table_schema = \
                 'cirisnode' AND table_name IN ('contributions', 'votes', 'moderation_events', \
                 'slashing_attestations', 'reconsideration_requests', \
                 'reconsideration_attestations')) OR (table_schema = 'cirislens' AND table_name \
                 IN ('cirisnode_consent_sla_watch', 'cirisnode_revocation_promotion_watch')) \
                 UNION SELECT 'none') q"
            )
            .await,
            "none",
            "I1173: the typed tables are dropped"
        );
        assert_eq!(
            one(
                "SELECT balance::text || '|' || COALESCE(attestation_id, 'NULL') || '|' || \
                 last_update_contribution FROM cirisnode.credits_ledger"
            )
            .await,
            format!("4.5|NULL|{cid}"),
        );
        assert_eq!(
            one(
                "SELECT expertise::text || '|' || COALESCE(attestation_id, 'NULL') \
                 FROM cirisnode.expertise_ledger"
            )
            .await,
            "0.5|NULL"
        );
        assert_eq!(
            one("SELECT notice_contribution_id || '|' || status \
                 FROM cirisnode.scheduled_takedown_actions")
            .await,
            format!("{cid}|pending")
        );
        assert_eq!(
            one("SELECT announcement_id FROM cirisnode.federation_delivery_attestations").await,
            cid
        );
        assert_eq!(
            one("SELECT legal_basis FROM cirislens.purge_executions").await,
            "dsa_article16"
        );
        p.test_execute(
            "INSERT INTO cirisnode.scheduled_takedown_actions (notice_contribution_id, \
             scheduled_eviction_at, status) VALUES ('x', '2026-02-01T00:00:00Z', 'pending')",
        )
        .await;
    }
}
