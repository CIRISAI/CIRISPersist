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

#[cfg(all(test, any(feature = "sqlite", feature = "postgres")))]
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
        balance: &str,
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
                // v62.0.0 (P1-fix8) — the balance as a JSON number TOKEN
                // (`arbitrary_precision`), never through `f64`.
                serde_json::json!({
                    lp::BALANCE_MEMBER: serde_json::from_str::<serde_json::Value>(balance)
                        .expect("a balance token is a JSON number"),
                    lp::SOURCE_CONTRIBUTION_MEMBER: "c-1",
                }),
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

    /// Does the projected ledger row carry `balance` as its balance? Matched
    /// as the balance COLUMN (sqlite renders the canonical decimal TEXT
    /// `…|'7.25'|…`, postgres the `numeric` as `"balance":7.25,`; v62.0.0
    /// P1-fix8), never as a bare substring: `"3.5"` is inside an instant like
    /// `…:43.572…`, which made I1166 a coin flip on the clock.
    fn balance_is(row: &str, balance: &str) -> bool {
        row.contains(&format!("|'{balance}'|")) || row.contains(&format!("\"balance\":{balance},"))
    }

    // ── I4004 (P1-fix7, P1-fix8) ──────────────────────────────────────────
    /// I4004 — a non-integral balance crosses the wire as a body number
    /// (P1-fix6) and lands in the ledger EXACTLY (P1-fix8): emits the
    /// balance TOKEN on a fresh contributor and returns the contributor's id
    /// for the backend's read of the column as text.
    pub(crate) async fn i4004_emit_balance<B>(b: &B, tag: &str, balance: &str) -> String
    where
        B: AttestationStore + DeclaresNode + Sync,
    {
        let node = signer(b, &format!("i4004-node-{tag}"), identity_type::NODE).await;
        b.declare_node_key_for_test(&node.id);
        let who = format!("i4004-who-{tag}");
        ts::register_hybrid_key(b, &who).await;
        credits(b, &node, &who, balance, None).await;
        who
    }

    /// The balances I4004 round-trips, `(token, the column's canonical
    /// text)`: a short decimal, the 0.1 + 0.2 shape (17 significant digits),
    /// 20 significant digits no `f64` holds (the canonical text drops only
    /// the trailing zero: the same value, its one spelling), a negative, and
    /// (P1-fix9, Verify 23.3.2's range) tag-4 mantissas past i64: i64::MAX + 1
    /// and -2^64, the bottom of the CBOR integer range.
    pub(crate) const I4004_BALANCES: [(&str, &str); 6] = [
        ("12.5", "12.5"),
        ("0.30000000000000004", "0.30000000000000004"),
        ("0.12345678901234567890", "0.1234567890123456789"),
        ("-3.25", "-3.25"),
        ("92233720368547758.08", "92233720368547758.08"),
        ("-184467440737095516.16", "-184467440737095516.16"),
    ];

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
        credits(b, &node, &alice, "12.5", Some(t0)).await;
        let rows = live(b, SiloProjection::CreditsLedger).await;
        assert_eq!(rows.len(), 1, "I1166: one key, one ledger row: {rows:?}");
        assert!(balance_is(&rows[0], "12.5"), "I1166: the balance: {rows:?}");

        // A newer row on the key replaces the balance.
        let newer = credits(
            b,
            &node,
            &alice,
            "7.25",
            Some(t0 + chrono::Duration::minutes(1)),
        )
        .await;
        let rows = live(b, SiloProjection::CreditsLedger).await;
        assert_eq!(rows.len(), 1);
        assert!(
            balance_is(&rows[0], "7.25") && rows[0].contains(&newer),
            "I1166: {rows:?}"
        );

        // An OLDER row arriving later does not.
        credits(
            b,
            &node,
            &alice,
            "3.5",
            Some(chrono::Utc::now() - chrono::Duration::hours(1)),
        )
        .await;
        let rows = live(b, SiloProjection::CreditsLedger).await;
        assert!(
            balance_is(&rows[0], "7.25") && !balance_is(&rows[0], "3.5"),
            "I1166: the fold keeps the greatest signed instant: {rows:?}"
        );

        // A peer's balance about the same contributor is held, not projected.
        let peers = credits(b, &peer, &alice, "99.5", None).await;
        assert!(b.get_attestation(&peers).await.unwrap().is_some());
        let rows = live(b, SiloProjection::CreditsLedger).await;
        assert!(
            rows.len() == 1 && balance_is(&rows[0], "7.25") && !balance_is(&rows[0], "99.5"),
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
            rows.len() == 1 && balance_is(&rows[0], "7.25"),
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
        credits(b, &node, &bob, "3", None).await;
        check_projection_rebuild(b, SiloProjection::CreditsLedger)
            .await
            .expect("I1169: this node's row supersedes the legacy balance");
    }
}

#[cfg(all(test, any(feature = "sqlite", feature = "postgres")))]
mod run {
    use super::bodies as b;

    fn tag() -> String {
        uuid::Uuid::new_v4().simple().to_string()[..8].to_owned()
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
             'arc_question', '2', '2026-01-01 00:00:00.000', '2026-01-01 00:00:00.000')"
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
             balance) VALUES ('i1169-bob-{t}', 'health', 'en', 'arc_question', 2)"
        );
        b::i1169_a_legacy_balance_is_red_until_rehomed(&p, &t, p.test_execute(&sql)).await;
    }

    // ── I4004 (P1-fix7, P1-fix8) — the balance round-trips exactly ────────
    // Read back as TEXT (sqlite) and `numeric::text` (postgres): the
    // canonical decimal, no float on the read either.
    #[cfg(feature = "sqlite")]
    #[tokio::test]
    async fn i4004_sqlite() {
        let s = sqlite().await;
        for (balance, text) in b::I4004_BALANCES {
            let t = tag();
            let who = b::i4004_emit_balance(&s, &t, balance).await;
            let conn = s.conn_handle();
            let got: String = conn
                .lock()
                .query_row(
                    "SELECT balance FROM cirisnode_credits_ledger WHERE contributor_id = ?1",
                    [&who],
                    |r| r.get(0),
                )
                .expect("I4004: the projected balance");
            assert_eq!(got, text, "I4004 sqlite: {balance} round-trips exactly");
        }
    }

    #[cfg(feature = "postgres")]
    #[tokio::test]
    async fn i4004_postgres() {
        let Some(p) = postgres().await else { return };
        for (balance, text) in b::I4004_BALANCES {
            let t = tag();
            let who = b::i4004_emit_balance(&p, &t, balance).await;
            let c = p.checkout().await.unwrap();
            let got: String = c
                .query_one(
                    "SELECT balance::text FROM cirisnode.credits_ledger WHERE contributor_id = $1",
                    &[&who],
                )
                .await
                .expect("I4004: the projected balance")
                .get(0);
            assert_eq!(got, text, "I4004 postgres: {balance} round-trips exactly");
        }
    }

    // ── I1173 — V203 over an upgrading node ───────────────────────────────
}
