//! CIRISPersist#1041 — witnesses for the consent BASIS
//! ([`capacity_consent_stance_with_basis`](super::consent_by_humans::capacity_consent_stance_with_basis)):
//! the rows a capacity stance rests on, each with its principal and path. One
//! body per invariant over `&dyn FederationDirectory`, run by memory, sqlite
//! and postgres. Fixture shapes follow the `probe-consent-stance` witnesses
//! (W1041b/c): a node's owner-binding for the `delegates_to` path, an active
//! occurrence row for the `occurrence_of` path.

#[cfg(test)]
pub(crate) mod bodies {
    use crate::federation::admission::ConsentGatedFamily;
    use crate::federation::consent_by_humans::{
        self as cbh, ConsentBasis, ConsentBasisRow, ConsentPrincipalPath as Path, FOR_KEY_ID,
    };
    use crate::federation::consent_scope_invariants::bodies::{put, stance};
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
        let (x, subj) = (format!("i622-x-{s}"), format!("i622-s-{s}"));
        ts::register_identity_key(d, &x, NODE).await;
        ts::register_identity_key(d, &subj, AGENT).await;
        let (state, b) = basis(d, &x, &subj).await;
        assert_eq!(state, ConsentState::Unspecified);
        assert!(b.rows.is_empty(), "I622: unspecified has no basis: {b:?}");

        let g = format!("i622-g-{s}");
        put(
            d,
            consent(&g, &subj, &x, "granted", None, "2026-09-01T00:00:00Z", None),
        )
        .await
        .unwrap();
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
        let x = format!("i623-x-{s}");
        ts::register_identity_key(d, &x, NODE).await;

        // delegates_to: node N owned by human A.
        let (n, a) = (format!("i623-n-{s}"), format!("i623-a-{s}"));
        ts::register_identity_key(d, &n, NODE).await;
        ts::register_identity_key(d, &a, USER).await;
        put(
            d,
            ts::owner_binding_attestation(&format!("i623-ob-{s}"), &a, &n),
        )
        .await
        .unwrap();
        let blanket = format!("i623-blanket-{s}");
        put(
            d,
            consent(
                &blanket,
                &a,
                &x,
                "granted",
                None,
                "2026-09-01T00:00:00Z",
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
        let ga = format!("i623-ga-{s}");
        put(
            d,
            consent(
                &ga,
                &a,
                &x,
                "granted",
                Some(&n),
                "2026-09-02T00:00:00Z",
                None,
            ),
        )
        .await
        .unwrap();
        let (state, b) = basis(d, &x, &n).await;
        assert_eq!(state, ConsentState::Granted);
        assert_eq!(
            b.rows,
            vec![row(&a, &[Path::DelegatesTo], &ga)],
            "I623 delegates_to"
        );
        assert_granted_basis_is_live(d, &b, "I623").await;

        // occurrence_of: agent G, an active occurrence of human U.
        let (g, u) = (format!("i623-g-{s}"), format!("i623-u-{s}"));
        ts::register_identity_key(d, &g, AGENT).await;
        ts::register_identity_key(d, &u, USER).await;
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
        let gu = format!("i623-gu-{s}");
        put(
            d,
            consent(
                &gu,
                &u,
                &x,
                "granted",
                Some(&g),
                "2026-09-01T00:00:00Z",
                None,
            ),
        )
        .await
        .unwrap();
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
        let x = format!("i624-x-{s}");
        ts::register_identity_key(d, &x, NODE).await;
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

        let (g, u) = (format!("i624-g-{s}"), format!("i624-u-{s}"));
        ts::register_identity_key(d, &g, AGENT).await;
        ts::register_identity_key(d, &u, USER).await;
        d.put_identity_occurrence_local(occurrence(&u, &g))
            .await
            .unwrap();
        let own = format!("i624-own-{s}");
        put(
            d,
            consent(&own, &g, &x, "granted", None, "2026-09-01T00:00:00Z", None),
        )
        .await
        .unwrap();
        let stop = format!("i624-stop-{s}");
        put(
            d,
            consent(
                &stop,
                &u,
                &x,
                "revoked",
                Some(&g),
                "2026-09-02T00:00:00Z",
                None,
            ),
        )
        .await
        .unwrap();
        let (state, b) = basis(d, &x, &g).await;
        assert_eq!(state, ConsentState::Revoked);
        assert_eq!(
            b.rows,
            vec![row(&u, &[Path::OccurrenceOf], &stop)],
            "I624: a revoked basis names the revocation, not the grant beside it"
        );

        let (h, v) = (format!("i624-h-{s}"), format!("i624-v-{s}"));
        ts::register_identity_key(d, &h, AGENT).await;
        ts::register_identity_key(d, &v, USER).await;
        d.put_identity_occurrence_local(occurrence(&v, &h))
            .await
            .unwrap();
        let lapsed = format!("i624-lapsed-{s}");
        put(
            d,
            consent(
                &lapsed,
                &h,
                &x,
                "granted",
                None,
                "2026-01-01T00:00:00Z",
                Some("2026-02-01T00:00:00Z"),
            ),
        )
        .await
        .unwrap();
        let live = format!("i624-live-{s}");
        put(
            d,
            consent(
                &live,
                &v,
                &x,
                "granted",
                Some(&h),
                "2026-09-01T00:00:00Z",
                None,
            ),
        )
        .await
        .unwrap();
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

#[cfg(test)]
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
    runners!(memory, async {
        Some(crate::store::memory::MemoryBackend::new())
    });
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
