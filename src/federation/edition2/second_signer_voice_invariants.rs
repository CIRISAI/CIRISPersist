//! v62.0.0 (v62 P8-fix4/fix5) — **I3525–I3529, I3531: a held row waits for
//! its second signers, and each finds and voices it, in any role.** sqlite and
//! postgres; every party's engine over one store.
//!
//! These witnesses need K2's second-signer gate over `self:delegates_to` and
//! owner bindings (K2-fix4..fix6: `door::resolved_second_signer_roles`) and
//! P8-fix5's fold read `Dep::key(party)` in that resolver: without the read,
//! `held_rows_for` finds nothing and I3526 reds on "D sees the delegation".
//!
//! - **I3525** — `grant_delegation` (VD-step2b: it answers the row's state) of a delegation to D answers
//!   `Waiting` (reason `count_short`, HTTP 424), not an error; no row is held.
//! - **I3526** — D finds it: `held_rows_for` (D's own key) lists it, role
//!   `delegate`, author A, with A's statement; a third key that is no party
//!   is offered nothing. D's `voice_held_row` seats it (`Seated`); A reads
//!   `Seated`; the row is held, authored by A; D's list no longer names it.
//! - **I3527** — the remote / hardware form: E is drafted its voice
//!   (`voice_draft(row, E)`), E's key signs the draft (`sign_draft`), and
//!   `submit_voice` seats the row.
//! - **I3528** — **the agent steward path, end to end.** An agent G is bound
//!   to its owner O. Steward S `steward_bind`s G: `Waiting`. Both G
//!   (role `delegate`) and O (role `delegate_owner`) find it with
//!   `held_rows_for`. G voices through a DRAFT (its pen is hardware: the
//!   draft is signed elsewhere and submitted): still `Waiting`, now only on
//!   O. O voices: `Seated`. Neither list names it any more, and G is
//!   steward-bound by S (`steward_bindings_of`).
//! - **I3529** — **another role, the same door**: an owner binding U → N
//!   authored on U's engine waits for N's voice; N finds it under role
//!   `bound_node` (and only there: the `delegate` filter lists nothing), and
//!   N's voice seats it.
//! - **I3531** — **host-reachable**: through the directory capsule's proxy
//!   (`build_persist_directory` → `build_ops_directory`, the C-ABI a host
//!   wheel uses), `held_rows_for` lists the held row, `submit_voice` of the
//!   delegate's voice answers `Seated`, and `voice_status` answers `Seated`:
//!   the ops `HeldRowsFor`, `SubmitVoice`, `VoiceStatus`.

pub(crate) mod bodies {
    use std::sync::Arc;

    use super::super::producer_invariants::bodies::{node, signer};
    use super::super::second_signer_voice::VoiceOutcome;
    use crate::federation::admission::DelegationTermBounds;
    use crate::federation::types::{delegation_scope, identity_type, owner_binding};
    use crate::federation::FederationDirectory;
    use crate::Engine;

    async fn party(dsn: &str, alias: &str, kind: &str) -> (Engine, String) {
        let e = node(dsn, alias).await;
        let id = e
            .register_self_federation_key(kind, None, None)
            .await
            .unwrap_or_else(|e| panic!("{alias} registers as {kind}: {e}"));
        (e, id)
    }

    fn waiting_row(out: &VoiceOutcome, what: &str) -> String {
        match out {
            VoiceOutcome::Waiting { row_id, reason, .. } => {
                assert_eq!(reason, "count_short", "{what}: held for a voice");
                row_id.clone()
            }
            other => panic!("{what}: no second signer has voiced it: {other:?}"),
        }
    }

    fn now_ms() -> u64 {
        u64::try_from(crate::host::clock::now().timestamp_millis()).unwrap_or(0)
    }

    /// I3525 / I3526 / I3527.
    pub(crate) async fn i3525_a_delegation_waits_for_its_delegate(dsn: &str, tag: &str) {
        let alias = |who: &str| format!("{tag}-3525-{who}");
        let (a, a_id) = party(dsn, &alias("a"), identity_type::USER).await;
        let a_signer = signer(&alias("a"), &alias("a"));
        let (d, d_id) = party(dsn, &alias("d"), identity_type::USER).await;
        let (e, e_id) = party(dsn, &alias("e"), identity_type::USER).await;
        let (x, _x_id) = party(dsn, &alias("x"), identity_type::USER).await;

        // I3525 — held, not refused.
        let out = a
            .grant_delegation(
                &a_signer,
                &d_id,
                vec!["act_on_behalf".to_owned()],
                false,
                None,
                DelegationTermBounds::default(),
            )
            .await
            .expect("I3525: a held delegation is not an error");
        let row = waiting_row(&out, "I3525");
        assert_eq!(out.http_status(), 424, "I3525");
        assert!(
            a.federation_directory()
                .get_attestation(&row)
                .await
                .unwrap()
                .is_none(),
            "I3525: no row is held yet"
        );

        // I3526 — D finds and voices it; X (no party) is offered nothing.
        let waiting = d
            .held_rows_for(None, None, None, 100)
            .await
            .expect("I3526: D's list");
        let held = waiting
            .iter()
            .find(|h| h.row_id == row)
            .unwrap_or_else(|| panic!("I3526: D sees the delegation: {waiting:?}"));
        assert_eq!(held.role, "delegate", "I3526");
        assert_eq!(held.author, a_id, "I3526: the author");
        assert_eq!(held.sub, d_id, "I3526: the delegate");
        assert!(held.parties.contains(&d_id), "I3526: D is the party");
        assert!(
            !held.statement.is_empty(),
            "I3526: what the voice signs over"
        );
        assert!(
            x.held_rows_for(None, None, None, 100)
                .await
                .unwrap()
                .iter()
                .all(|h| h.row_id != row),
            "I3526: a key that is no party is offered nothing"
        );
        let seated = d
            .voice_held_row(&row, None)
            .await
            .expect("I3526: D voices it");
        assert!(seated.is_seated(), "I3526: seated: {seated:?}");
        assert!(
            a.voice_status(&row).await.unwrap().is_seated(),
            "I3526: A reads it seated"
        );
        let landed = a
            .federation_directory()
            .get_attestation(&row)
            .await
            .unwrap()
            .expect("I3526: the row is held");
        assert_eq!(landed.attesting_key_id, a_id, "I3526: authored by A");
        assert!(
            d.held_rows_for(None, None, None, 100)
                .await
                .unwrap()
                .iter()
                .all(|h| h.row_id != row),
            "I3526: nothing left for D to voice"
        );

        // I3527 — the drafted voice of a remote / hardware delegate.
        let out = a
            .grant_delegation(
                &a_signer,
                &e_id,
                vec!["act_on_behalf".to_owned()],
                false,
                None,
                DelegationTermBounds::default(),
            )
            .await
            .expect("I3527: held");
        assert!(!out.is_seated(), "I3527: waits for E");
        let draft = a
            .voice_draft(out.row_id(), &e_id, None)
            .await
            .expect("I3527: drafted for E's pen");
        let st = e.sign_draft(&draft).await.expect("I3527: E signs");
        let seated = a
            .submit_voice(&st)
            .await
            .expect("I3527: the voice is admitted");
        assert!(seated.is_seated(), "I3527: seated: {seated:?}");
        assert_eq!(seated.row_id(), out.row_id(), "I3527: the same row");
    }

    /// I3528 — the agent steward path.
    pub(crate) async fn i3528_the_agent_steward_path(dsn: &str, tag: &str) {
        let alias = |who: &str| format!("{tag}-3528-{who}");
        let (o, o_id) = party(dsn, &alias("o"), identity_type::USER).await;
        let o_signer = signer(&alias("o"), &alias("o"));
        let (g, g_id) = party(dsn, &alias("g"), identity_type::AGENT).await;
        let g_signer = signer(&alias("g"), &alias("g"));
        let (s, s_id) = party(dsn, &alias("s"), identity_type::USER).await;
        let s_signer = signer(&alias("s"), &alias("s"));
        let dir = s.federation_directory();

        // G's owner binding (both pens in hand: O authors, G voices).
        crate::federation::edition2::occurrence::state_agent_owner_binding(
            &*dir,
            &o_signer,
            &g_signer,
            now_ms(),
        )
        .await
        .expect("I3528: G's owner binding");
        assert_eq!(
            crate::federation::admission::agent_owner_of(&*dir, &g_id, now_ms())
                .await
                .expect("I3528: G's owner reads"),
            Some(o_id.clone()),
            "I3528: O owns G (the resolver's delegate_owner party, K2-fix7)"
        );

        // S steward-binds G: held for G and for G's owner.
        let out = s
            .steward_bind(
                &s_signer,
                &g_id,
                vec![delegation_scope::INFRA_ATTEST.to_owned()],
                None,
            )
            .await
            .expect("I3528: a held steward edge is not an error");
        let row = waiting_row(&out, "I3528");

        // Both find it, each in its own role.
        let for_g = g.held_rows_for(None, None, None, 100).await.unwrap();
        let g_held = for_g
            .iter()
            .find(|h| h.row_id == row)
            .unwrap_or_else(|| panic!("I3528: G sees the steward edge: {for_g:?}"));
        assert_eq!(g_held.role, "delegate", "I3528: G's role");
        assert_eq!(g_held.author, s_id, "I3528: authored by S");
        let for_o = o.held_rows_for(None, None, None, 100).await.unwrap();
        let o_held = for_o
            .iter()
            .find(|h| h.row_id == row)
            .unwrap_or_else(|| panic!("I3528: O sees the steward edge: {for_o:?}"));
        assert_eq!(o_held.role, "delegate_owner", "I3528: O's role");
        assert_eq!(o_held.sub, g_id, "I3528: about G");

        // G's pen is hardware: the draft is signed elsewhere and submitted.
        let draft = super::super::second_signer_voice::voice_draft(&g_held.statement, &g_id, None)
            .expect("I3528: G's voice, drafted from the listed statement");
        let g_voice = g.sign_draft(&draft).await.expect("I3528: G's pen signs");
        let after_g = s
            .submit_voice(&g_voice)
            .await
            .expect("I3528: G's voice is admitted");
        assert_eq!(after_g.row_id(), row, "I3528: the same row");
        assert!(
            !after_g.is_seated(),
            "I3528: G alone does not seat it: {after_g:?}"
        );
        assert!(
            g.held_rows_for(None, None, None, 100)
                .await
                .unwrap()
                .iter()
                .all(|h| h.row_id != row),
            "I3528: nothing left for G"
        );

        // O voices: seated.
        let seated = o
            .voice_held_row(&row, None)
            .await
            .expect("I3528: O voices it");
        assert!(seated.is_seated(), "I3528: seated: {seated:?}");
        assert!(
            o.held_rows_for(None, None, None, 100)
                .await
                .unwrap()
                .iter()
                .all(|h| h.row_id != row),
            "I3528: nothing left for O"
        );

        // The edge serves: G is steward-bound by S.
        let stewards = g
            .steward_bindings_of(&g_id)
            .await
            .expect("I3528: G's stewards");
        assert!(
            stewards.contains(&s_id),
            "I3528: S stewards G: {stewards:?}"
        );
    }

    /// I3529 — an owner binding waits for its node, role `bound_node`.
    pub(crate) async fn i3529_an_owner_binding_waits_for_its_node(dsn: &str, tag: &str) {
        let alias = |who: &str| format!("{tag}-3529-{who}");
        let (u, u_id) = party(dsn, &alias("u"), identity_type::USER).await;
        let u_signer = signer(&alias("u"), &alias("u"));
        let (n, n_id) = party(dsn, &alias("n"), identity_type::NODE).await;

        let out = u
            .grant_delegation(
                &u_signer,
                &n_id,
                vec![delegation_scope::INFRA_ATTEST.to_owned()],
                false,
                Some(owner_binding::PURPOSE),
                DelegationTermBounds::default(),
            )
            .await
            .expect("I3529: a held owner binding is not an error");
        let row = waiting_row(&out, "I3529");
        let listed = n
            .held_rows_for(None, Some("bound_node"), None, 100)
            .await
            .unwrap();
        assert!(
            listed
                .iter()
                .any(|h| h.row_id == row && h.role == "bound_node"),
            "I3529: N finds it as bound_node: {listed:?}"
        );
        assert!(
            n.held_rows_for(None, Some("delegate"), None, 100)
                .await
                .unwrap()
                .iter()
                .all(|h| h.row_id != row),
            "I3529: the role filter names one role"
        );
        let seated = n
            .voice_held_row(&row, None)
            .await
            .expect("I3529: N voices it");
        assert!(seated.is_seated(), "I3529: seated: {seated:?}");
        assert_eq!(
            crate::federation::admission::owner_of(&*n.federation_directory(), &n_id)
                .await
                .unwrap()
                .as_deref(),
            Some(u_id.as_str()),
            "I3529: U owns N"
        );
    }

    /// I3531 — the list, the voice and the state through the capsule proxy.
    pub(crate) async fn i3531_through_the_capsule(
        dsn: String,
        tag: String,
        rt: Arc<tokio::runtime::Runtime>,
    ) {
        use crate::ffi::directory_capsule::{build_ops_directory, build_persist_directory};
        let alias = |who: &str| format!("{tag}-3531-{who}");
        let (a, _a_id) = party(&dsn, &alias("a"), identity_type::USER).await;
        let a_signer = signer(&alias("a"), &alias("a"));
        let (d, d_id) = party(&dsn, &alias("d"), identity_type::USER).await;

        let out = a
            .grant_delegation(
                &a_signer,
                &d_id,
                vec!["act_on_behalf".to_owned()],
                false,
                None,
                DelegationTermBounds::default(),
            )
            .await
            .expect("I3531: held");
        let row = waiting_row(&out, "I3531");
        let rid = crate::federation::edition2::names::RowId(
            <[u8; 32]>::try_from(hex::decode(&row).unwrap().as_slice()).unwrap(),
        );

        let directory = build_persist_directory(a.federation_directory());
        let executor = Arc::new(crate::ffi::executor_capsule::build_persist_executor(rt));
        let proxy: Arc<dyn FederationDirectory> =
            build_ops_directory(directory, executor).expect("I3531: abi ok");

        // HeldRowsFor
        let listed = proxy
            .held_rows_for(&d_id, None, None, 100)
            .await
            .expect("I3531: HeldRowsFor crosses");
        let held = listed
            .iter()
            .find(|h| h.row_id == row)
            .unwrap_or_else(|| panic!("I3531: the proxy lists it: {listed:?}"));
        assert_eq!(
            listed,
            a.federation_directory()
                .held_rows_for(&d_id, None, None, 100)
                .await
                .unwrap(),
            "I3531: the proxy answers what the store answers"
        );
        // VoiceStatus (waiting)
        let before = proxy
            .voice_status(&rid)
            .await
            .expect("I3531: VoiceStatus crosses");
        assert!(
            matches!(&before, VoiceOutcome::Waiting { reason, .. } if reason == "count_short"),
            "I3531: waiting, with its reason, through the proxy: {before:?}"
        );
        // SubmitVoice
        let draft = super::super::second_signer_voice::voice_draft(&held.statement, &d_id, None)
            .expect("I3531: drafted");
        let voice = d.sign_draft(&draft).await.expect("I3531: D signs");
        let seated = proxy
            .submit_voice(&voice)
            .await
            .expect("I3531: SubmitVoice crosses");
        assert!(seated.is_seated(), "I3531: seated: {seated:?}");
        // VoiceStatus (seated)
        assert!(
            proxy.voice_status(&rid).await.unwrap().is_seated(),
            "I3531: seated through the proxy"
        );
    }
}

#[cfg(test)]
mod tests {
    use super::bodies as b;

    fn tag() -> String {
        uuid::Uuid::new_v4().simple().to_string()[..8].to_owned()
    }

    #[cfg(feature = "sqlite")]
    fn sqlite_dsn(d: &tempfile::TempDir) -> String {
        format!("sqlite:///{}", d.path().join("a.db").display())
    }

    /// A runtime whose workers carry ML-DSA-65's stack (the capsule's
    /// executor spawns onto it).
    fn runtime() -> std::sync::Arc<tokio::runtime::Runtime> {
        std::sync::Arc::new(
            tokio::runtime::Builder::new_multi_thread()
                .worker_threads(2)
                .thread_stack_size(16 * 1024 * 1024)
                .enable_all()
                .build()
                .expect("build tokio runtime"),
        )
    }

    #[cfg(feature = "sqlite")]
    #[tokio::test(flavor = "multi_thread")]
    async fn i3525_sqlite() {
        let d = tempfile::tempdir().unwrap();
        Box::pin(b::i3525_a_delegation_waits_for_its_delegate(
            &sqlite_dsn(&d),
            &tag(),
        ))
        .await;
    }

    #[cfg(feature = "postgres")]
    #[tokio::test(flavor = "multi_thread")]
    async fn i3525_postgres() {
        let Some(a) = crate::test_pg::isolated_dsn() else {
            eprintln!("i3525 postgres: no CIRIS_PERSIST_TEST_PG base DSN — SKIPPED");
            return;
        };
        Box::pin(b::i3525_a_delegation_waits_for_its_delegate(&a, &tag())).await;
        eprintln!("i3525 postgres: RAN");
    }

    #[cfg(feature = "sqlite")]
    #[tokio::test(flavor = "multi_thread")]
    async fn i3528_sqlite() {
        let d = tempfile::tempdir().unwrap();
        Box::pin(b::i3528_the_agent_steward_path(&sqlite_dsn(&d), &tag())).await;
    }

    #[cfg(feature = "postgres")]
    #[tokio::test(flavor = "multi_thread")]
    async fn i3528_postgres() {
        let Some(a) = crate::test_pg::isolated_dsn() else {
            eprintln!("i3528 postgres: no CIRIS_PERSIST_TEST_PG base DSN — SKIPPED");
            return;
        };
        Box::pin(b::i3528_the_agent_steward_path(&a, &tag())).await;
        eprintln!("i3528 postgres: RAN");
    }

    #[cfg(feature = "sqlite")]
    #[tokio::test(flavor = "multi_thread")]
    async fn i3529_sqlite() {
        let d = tempfile::tempdir().unwrap();
        Box::pin(b::i3529_an_owner_binding_waits_for_its_node(
            &sqlite_dsn(&d),
            &tag(),
        ))
        .await;
    }

    #[cfg(feature = "postgres")]
    #[tokio::test(flavor = "multi_thread")]
    async fn i3529_postgres() {
        let Some(a) = crate::test_pg::isolated_dsn() else {
            eprintln!("i3529 postgres: no CIRIS_PERSIST_TEST_PG base DSN — SKIPPED");
            return;
        };
        Box::pin(b::i3529_an_owner_binding_waits_for_its_node(&a, &tag())).await;
        eprintln!("i3529 postgres: RAN");
    }

    /// The body is driven on a thread with the 16 MiB stack ML-DSA-65
    /// needs; the proxy's executor spawns each op onto the runtime's
    /// workers (the same stack), and the runtime is dropped outside any
    /// async context.
    fn run_i3531(dsn: String) {
        let t = tag();
        std::thread::Builder::new()
            .stack_size(16 * 1024 * 1024)
            .spawn(move || {
                let rt = runtime();
                rt.block_on(Box::pin(b::i3531_through_the_capsule(dsn, t, rt.clone())));
            })
            .expect("spawn the I3531 thread")
            .join()
            .expect("I3531: the body ran to completion");
    }

    #[cfg(feature = "sqlite")]
    #[test]
    fn i3531_sqlite() {
        let d = tempfile::tempdir().unwrap();
        run_i3531(sqlite_dsn(&d));
    }

    #[cfg(feature = "postgres")]
    #[test]
    fn i3531_postgres() {
        let Some(a) = crate::test_pg::isolated_dsn() else {
            eprintln!("i3531 postgres: no CIRIS_PERSIST_TEST_PG base DSN — SKIPPED");
            return;
        };
        run_i3531(a);
        eprintln!("i3531 postgres: RAN");
    }
}
