//! CIRISPersist#1041 — witnesses for the consent BASIS
//! ([`capacity_consent_stance_with_basis`](super::consent_by_humans::capacity_consent_stance_with_basis)):
//! the rows a capacity stance rests on, each with its principal and path. One
//! body per invariant over `&dyn FederationDirectory`, run by memory, sqlite
//! and postgres. Fixture shapes follow the `probe-consent-stance` witnesses
//! (W1041b/c): a node's owner-binding for the `delegates_to` path, an active
//! occurrence row for the `occurrence_of` path.
//!
//! v62.0.0 (slice E6) — every key is an edition-2 `key:record`
//! (`fixture_switch::put_key`): a fixture signs with the SEED (`*_s`), every
//! fold, envelope member and occurrence names the KID. A row's id is
//! computed, so each witness reads the id off the row it put.

#[cfg(all(test, any(feature = "sqlite", feature = "postgres")))]
pub(crate) mod bodies {
    use crate::federation::admission::ConsentGatedFamily;
    use crate::federation::consent_by_humans::{
        self as cbh, ConsentBasis, ConsentBasisRow, ConsentPrincipalPath as Path, FOR_KEY_ID,
    };
    use crate::federation::consent_scope_invariants::bodies::{put, stance};
    use crate::federation::edition2::fixture_switch as e2;
    use crate::federation::hard_case::ConsentState;
    use crate::federation::tier_ingest::test_support as ts;
    use crate::federation::types::identity_type::{AGENT, NODE, USER};
    use crate::federation::{Attestation, FederationDirectory, IdentityOccurrence};

    /// `consent:state:<state>:v1` scoped `analyze` by `author` about `target`,
    /// naming `for_key` when given.
    fn consent(
        id: &str,
        author: &str,
        target: &str,
        state: &str,
        for_key: Option<&str>,
        at: &str,
        expires: Option<&str>,
    ) -> Attestation {
        let extras = match for_key {
            Some(k) => serde_json::json!({ FOR_KEY_ID: k }),
            None => serde_json::json!({}),
        };
        stance(
            id,
            author,
            target,
            state,
            serde_json::json!("analyze"),
            extras,
            at,
            expires,
        )
    }

    async fn basis(
        d: &dyn FederationDirectory,
        x: &str,
        subj: &str,
    ) -> (ConsentState, ConsentBasis) {
        let now = chrono::Utc::now();
        let (state, basis) =
            cbh::capacity_consent_stance_with_basis(d, x, subj, ConsentGatedFamily::Capacity, now)
                .await
                .unwrap();
        // The thin wrapper and the basis-carrying fold are one fold.
        assert_eq!(
            cbh::capacity_consent_stance(d, x, subj, ConsentGatedFamily::Capacity, now)
                .await
                .unwrap(),
            state
        );
        (state, basis)
    }

    /// An instant `days` before now, as the RFC 3339 text `stance` reads.
    /// v62.0.0 — rows signed by `node`/`agent` keys are NOW-RELATIVE: under
    /// CC 2.4.1.1 such a key's rows lapse when its record ends (365 days at
    /// most), so a fixed date would rot.
    fn ago(days: i64) -> String {
        (chrono::Utc::now() - chrono::Duration::days(days))
            .to_rfc3339_opts(chrono::SecondsFormat::Millis, true)
    }

    /// Put `a`; its (computed) id.
    async fn put_id(d: &dyn FederationDirectory, a: Attestation) -> String {
        let id = a.attestation_id.clone();
        put(d, a).await.unwrap();
        id
    }

    /// The owner binding `owner_s` -> `node_s` with the node's own voice
    /// (`ownership:*` carries the node as its second signer).
    async fn put_owner_binding(d: &dyn FederationDirectory, id: &str, owner_s: &str, node_s: &str) {
        let ob = ts::owner_binding_attestation(id, owner_s, node_s);
        let st = e2::carried_statement(&ob).expect("an edition-2 owner binding");
        put(d, ob).await.unwrap();
        e2::put_statement(d, &e2::voice_of(&st, node_s))
            .await
            .expect("the node's voice on its owner binding");
    }

    fn row(principal: &str, paths: &[Path], id: &str) -> ConsentBasisRow {
        ConsentBasisRow {
            principal: principal.to_owned(),
            paths: paths.to_vec(),
            attestation_id: id.to_owned(),
        }
    }

    /// Every row a `Granted` basis names is live at `now`: held, a grant, and
    /// not past its `expires_at`. A basis naming anything else is a red.
    async fn assert_granted_basis_is_live(
        d: &dyn FederationDirectory,
        b: &ConsentBasis,
        tag: &str,
    ) {
        let now = chrono::Utc::now();
        for r in &b.rows {
            let a = d
                .get_attestation(&r.attestation_id)
                .await
                .unwrap()
                .unwrap_or_else(|| panic!("{tag}: the basis names a row not held: {r:?}"));
            assert!(
                a.expires_at.is_none_or(|e| e > now),
                "{tag}: the basis names a row not live at now: {r:?}"
            );
            assert_eq!(
                a.attestation_envelope["dimension"], "consent:state:granted:v1",
                "{tag}: a granted basis names a grant: {r:?}"
            );
        }
    }

    /// **I622 — the subject's own path.** An agent's own grant to the
    /// attester: `Granted`, the basis names exactly that grant under
    /// `subject`. With no consent anywhere: `Unspecified` and an EMPTY basis —
    /// a gate gap reads apart from a lapsed grant.
    pub async fn i622_the_subjects_own_grant(d: &dyn FederationDirectory, s: &str) {
        let (x_s, subj_s) = (format!("i622-x-{s}"), format!("i622-s-{s}"));
        let x = e2::put_key(d, &x_s, &[NODE]).await;
        let subj = e2::put_key(d, &subj_s, &[AGENT]).await;
        let (state, b) = basis(d, &x, &subj).await;
        assert_eq!(state, ConsentState::Unspecified);
        assert!(b.rows.is_empty(), "I622: unspecified has no basis: {b:?}");

        let g = put_id(
            d,
            consent(
                &format!("i622-g-{s}"),
                &subj_s,
                &x,
                "granted",
                None,
                &ago(2),
                None,
            ),
        )
        .await;
        let (state, b) = basis(d, &x, &subj).await;
        assert_eq!(state, ConsentState::Granted);
        assert_eq!(b.rows, vec![row(&subj, &[Path::Subject], &g)], "I622");
        assert_eq!(b.attestation_ids(), vec![g.as_str()]);
        assert_granted_basis_is_live(d, &b, "I622").await;
    }

    /// **I623 — the steward paths.** A node's owner (`delegates_to`) and an
    /// agent's identity anchor (`occurrence_of`), each granting with
    /// `for_key_id` = the subject: the basis names that steward's grant under
    /// its path. A steward's grant naming NO machine is not a basis (and does
    /// not grant).
    pub async fn i623_the_steward_paths(d: &dyn FederationDirectory, s: &str) {
        let x = e2::put_key(d, &format!("i623-x-{s}"), &[NODE]).await;

        // delegates_to: node N owned by human A.
        let (n_s, a_s) = (format!("i623-n-{s}"), format!("i623-a-{s}"));
        let n = e2::put_key(d, &n_s, &[NODE]).await;
        let a = e2::put_key(d, &a_s, &[USER]).await;
        put_owner_binding(d, &format!("i623-ob-{s}"), &a_s, &n_s).await;
        put(
            d,
            consent(
                &format!("i623-blanket-{s}"),
                &a_s,
                &x,
                "granted",
                None,
                &ago(2),
                None,
            ),
        )
        .await
        .unwrap();
        let (state, b) = basis(d, &x, &n).await;
        assert_eq!(
            state,
            ConsentState::Unspecified,
            "I623: a blanket grant names no machine"
        );
        assert!(b.rows.is_empty(), "I623: {b:?}");
        let ga = put_id(
            d,
            consent(
                &format!("i623-ga-{s}"),
                &a_s,
                &x,
                "granted",
                Some(&n),
                &ago(1),
                None,
            ),
        )
        .await;
        let (state, b) = basis(d, &x, &n).await;
        assert_eq!(state, ConsentState::Granted);
        assert_eq!(
            b.rows,
            vec![row(&a, &[Path::DelegatesTo], &ga)],
            "I623 delegates_to"
        );
        assert_granted_basis_is_live(d, &b, "I623").await;

        // occurrence_of: agent G, an active occurrence of human U.
        let (g, u_s) = (
            e2::put_key(d, &format!("i623-g-{s}"), &[AGENT]).await,
            format!("i623-u-{s}"),
        );
        let u = e2::put_key(d, &u_s, &[USER]).await;
        d.put_identity_occurrence_local(IdentityOccurrence {
            identity_key_id: u.clone(),
            occurrence_key_id: g.clone(),
            device_class: "agent".to_owned(),
            hardware_attestation: None,
            asserted_at: chrono::Utc::now(),
            valid_until: None,
            encryption_pubkeys: None,
            transport_binding: None,
            persist_row_hash: String::new(),
        })
        .await
        .unwrap();
        let gu = put_id(
            d,
            consent(
                &format!("i623-gu-{s}"),
                &u_s,
                &x,
                "granted",
                Some(&g),
                &ago(2),
                None,
            ),
        )
        .await;
        let (state, b) = basis(d, &x, &g).await;
        assert_eq!(state, ConsentState::Granted);
        assert_eq!(
            b.rows,
            vec![row(&u, &[Path::OccurrenceOf], &gu)],
            "I623 occurrence_of"
        );
        assert_granted_basis_is_live(d, &b, "I623").await;
    }

    /// **I624 — the basis is the rows the COMBINED state rests on.** Agent G
    /// (an occurrence of human U) grants the attester itself; U revokes for G:
    /// the stop wins (`Revoked`) and the basis names U's revocation ONLY, not
    /// G's grant. A second subject whose own grant has expired (`expires_at`
    /// past) and whose anchor grants: `Granted`, the basis names the anchor's
    /// live grant only, never the expired row.
    pub async fn i624_the_basis_follows_the_combined_state(d: &dyn FederationDirectory, s: &str) {
        let x = e2::put_key(d, &format!("i624-x-{s}"), &[NODE]).await;
        let occurrence = |u: &str, g: &str| IdentityOccurrence {
            identity_key_id: u.to_owned(),
            occurrence_key_id: g.to_owned(),
            device_class: "agent".to_owned(),
            hardware_attestation: None,
            asserted_at: chrono::Utc::now(),
            valid_until: None,
            encryption_pubkeys: None,
            transport_binding: None,
            persist_row_hash: String::new(),
        };

        let (g_s, u_s) = (format!("i624-g-{s}"), format!("i624-u-{s}"));
        let g = e2::put_key(d, &g_s, &[AGENT]).await;
        let u = e2::put_key(d, &u_s, &[USER]).await;
        d.put_identity_occurrence_local(occurrence(&u, &g))
            .await
            .unwrap();
        put(
            d,
            consent(
                &format!("i624-own-{s}"),
                &g_s,
                &x,
                "granted",
                None,
                &ago(2),
                None,
            ),
        )
        .await
        .unwrap();
        let stop = put_id(
            d,
            consent(
                &format!("i624-stop-{s}"),
                &u_s,
                &x,
                "revoked",
                Some(&g),
                &ago(1),
                None,
            ),
        )
        .await;
        let (state, b) = basis(d, &x, &g).await;
        assert_eq!(state, ConsentState::Revoked);
        assert_eq!(
            b.rows,
            vec![row(&u, &[Path::OccurrenceOf], &stop)],
            "I624: a revoked basis names the revocation, not the grant beside it"
        );

        let (h_s, v_s) = (format!("i624-h-{s}"), format!("i624-v-{s}"));
        let h = e2::put_key(d, &h_s, &[AGENT]).await;
        let v = e2::put_key(d, &v_s, &[USER]).await;
        d.put_identity_occurrence_local(occurrence(&v, &h))
            .await
            .unwrap();
        put(
            d,
            consent(
                &format!("i624-lapsed-{s}"),
                &h_s,
                &x,
                "granted",
                None,
                &ago(60),
                Some(ago(30).as_str()),
            ),
        )
        .await
        .unwrap();
        let live = put_id(
            d,
            consent(
                &format!("i624-live-{s}"),
                &v_s,
                &x,
                "granted",
                Some(&h),
                &ago(2),
                None,
            ),
        )
        .await;
        let (state, b) = basis(d, &x, &h).await;
        assert_eq!(state, ConsentState::Granted);
        assert_eq!(
            b.rows,
            vec![row(&v, &[Path::OccurrenceOf], &live)],
            "I624: the basis names the live grant, never the expired one"
        );
        assert_granted_basis_is_live(d, &b, "I624").await;
    }
}

#[cfg(all(test, any(feature = "sqlite", feature = "postgres")))]
mod run {
    fn suffix() -> String {
        uuid::Uuid::new_v4().simple().to_string()
    }
    macro_rules! runners {
        ($modname:ident, $fresh:expr) => {
            mod $modname {
                use super::super::bodies;
                #[tokio::test]
                async fn i622() {
                    let Some(b) = $fresh.await else { return };
                    bodies::i622_the_subjects_own_grant(&b, &super::suffix()).await
                }
                #[tokio::test]
                async fn i623() {
                    let Some(b) = $fresh.await else { return };
                    bodies::i623_the_steward_paths(&b, &super::suffix()).await
                }
                #[tokio::test]
                async fn i624() {
                    let Some(b) = $fresh.await else { return };
                    bodies::i624_the_basis_follows_the_combined_state(&b, &super::suffix()).await
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
