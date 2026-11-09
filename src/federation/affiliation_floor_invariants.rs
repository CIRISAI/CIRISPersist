//! v61 S2 (CIRISPersist#1143; CC rc14 4.4.3.2.8, 4.5.13) — **the
//! affiliation floor and dissolution.** sqlite and postgres.
//!
//! - **I1513** (`CLM-affiliation-one-voice-countersign`) — an affiliation
//!   with ONE deciding seat removes a member only with a countersign from a
//!   key outside the seat (its designated official): the seat alone is
//!   refused `affiliation_countersign_missing`; the seat with the official is
//!   admitted; a member's own resignation needs no one; an affiliation of two
//!   seats decides under its own protocol.
//! - **I1514** (`CLM-affiliation-dissolution`) — dissolution is the cosigned
//!   `withdraws` of the community's record under its protocol: one voice of
//!   two is refused; both are admitted, the room's seats lapse (no active
//!   members), a new seat is refused `federation_group_dissolved`, and the
//!   record stands. A family's record withdraws stays refused (a family
//!   dissolves by its own amendment).

#[cfg(all(test, any(feature = "sqlite", feature = "postgres")))]
pub(crate) mod bodies {
    use crate::federation::affiliation_config::AFFILIATION_COUNTERSIGN_MISSING;
    use crate::federation::membership_acceptance_invariants::bodies::{
        found_community, found_family, found_room_with_blob, proposal, put, reg, reply,
        widen_community,
    };
    use crate::federation::tier_ingest::test_support as ts;
    use crate::federation::types::{
        attestation_type, cohort_scope, CommunityMembershipRevocation, ScrubSig,
    };
    use crate::federation::{Attestation, Error, FederationDirectory};
    use chrono::{DateTime, Duration, Utc};

    pub(crate) fn ms(t: DateTime<Utc>) -> DateTime<Utc> {
        DateTime::<Utc>::from_timestamp_millis(t.timestamp_millis()).expect("ms instant")
    }

    pub(crate) fn rule(e: &Error) -> String {
        match e {
            Error::RosterAuthorityUnauthorized { rule, .. }
            | Error::MembershipAcceptanceRefused { rule, .. } => (*rule).to_owned(),
            other => format!("{other:?}"),
        }
    }

    pub(crate) async fn active(d: &dyn FederationDirectory, cid: &str, k: &str) -> bool {
        d.active_community_members(cid)
            .await
            .unwrap()
            .iter()
            .any(|m| m.key_id == k)
    }

    pub(crate) async fn seat(
        d: &dyn FederationDirectory,
        cid: &str,
        founder: &str,
        m: &str,
        at: DateTime<Utc>,
    ) {
        let p = proposal(
            founder,
            cohort_scope::AFFILIATIONS,
            cid,
            m,
            None,
            at,
            Some(Duration::days(7)),
        );
        put(d, &p).await.unwrap();
        put(d, &reply(m, m, &p, true, at + Duration::seconds(1)))
            .await
            .unwrap();
        widen_community(d, cid, &[founder], m, None, at + Duration::seconds(2))
            .await
            .unwrap_or_else(|e| panic!("seat {m}: {e}"));
    }

    async fn remove(
        d: &dyn FederationDirectory,
        cid: &str,
        signers: &[&str],
        m: &str,
        at: DateTime<Utc>,
    ) -> Result<(), Error> {
        let mut r = ts::sign_community_membership_revocation(
            signers[0],
            CommunityMembershipRevocation {
                community_key_id: cid.to_owned(),
                removed_identity_key_id: m.to_owned(),
                removed_at: ms(at),
                effective_at: ms(at),
                reason: None,
                witness_set: Vec::new(),
                persist_row_hash: String::new(),
            },
        );
        for c in &signers[1..] {
            ts::cosign_community_membership_revocation(&mut r, c);
        }
        d.put_community_membership_revocation(r).await
    }

    pub(crate) fn affiliation(official: Option<&str>) -> serde_json::Value {
        let mut b = serde_json::json!({
            crate::federation::affiliation_config::POLICY_COHORT_FIELD: "affiliations",
        });
        if let Some(o) = official {
            b[crate::federation::affiliation_config::POLICY_AFFILIATION_CONFIG_FIELD] = serde_json::json!({
                "designated_officials": [{ "role": "privacy_officer", "key_id": o }],
            });
        }
        b
    }

    /// **I1513** — the one-voice countersign.
    pub(crate) async fn i1513_one_voice_needs_a_countersign(d: &dyn FederationDirectory, s: &str) {
        let k = |n: &str| format!("i1513-{n}-{s}");
        let (f, g, official, m, n, solo, pair) = (
            k("f"),
            k("g"),
            k("official"),
            k("m"),
            k("n"),
            k("solo"),
            k("pair"),
        );
        reg(d, &[&f, &g, &official, &m, &n, &solo, &pair]).await;
        found_room_with_blob(
            d,
            &solo,
            "founder_only",
            &[&f],
            &[],
            Some(affiliation(Some(&official))),
        )
        .await
        .expect("I1513: a sole practitioner's affiliation");
        let at = Utc::now() - Duration::hours(1);
        seat(d, &solo, &f, &m, at).await;
        seat(d, &solo, &f, &n, at + Duration::minutes(1)).await;
        let e = remove(d, &solo, &[&f], &m, at + Duration::minutes(5))
            .await
            .expect_err("I1513: the one seat alone");
        assert_eq!(rule(&e), AFFILIATION_COUNTERSIGN_MISSING, "I1513: {e}");
        assert!(active(d, &solo, &m).await, "I1513: still a member");
        remove(d, &solo, &[&f, &official], &m, at + Duration::minutes(6))
            .await
            .expect("I1513: the seat with the designated official");
        assert!(!active(d, &solo, &m).await, "I1513: removed");
        remove(d, &solo, &[&n], &n, at + Duration::minutes(7))
            .await
            .expect("I1513: a resignation needs no countersign");
        // Two seats decide under their own protocol.
        found_room_with_blob(
            d,
            &pair,
            "founder_only",
            &[&f, &g],
            &[],
            Some(affiliation(None)),
        )
        .await
        .unwrap();
        seat(d, &pair, &f, &m, at).await;
        remove(d, &pair, &[&f], &m, at + Duration::minutes(5))
            .await
            .expect("I1513: a body of two seats");
    }

    /// The `group:roster:v1` row of `cid`.
    async fn record_row(d: &dyn FederationDirectory, cid: &str, scope: &str) -> Attestation {
        d.list_targeted_by_dimension_prefix(
            &[scope],
            cid,
            crate::federation::group_plane::GROUP_ROSTER_DIMENSION,
        )
        .await
        .unwrap()
        .into_iter()
        .next()
        .expect("the record row")
    }

    /// A `withdraws` of `target` by `signers` (base + additional scrubs).
    fn withdraw(target: &Attestation, cid: &str, scope: &str, signers: &[&str]) -> Attestation {
        let member = if scope == cohort_scope::FAMILY {
            "family_key_id"
        } else {
            "community_key_id"
        };
        let env = serde_json::json!({
            "references_attestation_id": target.attestation_id,
            member: cid,
        });
        let mut w = ts::bare_attestation(
            &uuid::Uuid::new_v4().to_string(),
            signers[0],
            signers[0],
            &env,
        );
        w.attestation_type = attestation_type::WITHDRAWS.into();
        w.weight = None;
        w.cohort_scope = scope.to_owned();
        ts::seal_row_in_place(signers[0], &mut w);
        w.additional_scrubs = signers[1..]
            .iter()
            .map(|k| {
                let (_h, c, p) = ts::sign_envelope(k, &w.attestation_envelope);
                ScrubSig {
                    cosigned_at: None,
                    scrub_key_id: (*k).to_owned(),
                    scrub_signature_classical: c,
                    scrub_signature_pqc: p,
                }
            })
            .collect();
        w
    }

    /// **I1514** — dissolution is the cosigned withdraws of the record.
    pub(crate) async fn i1514_dissolution_is_the_records_withdraws(
        d: &dyn FederationDirectory,
        s: &str,
    ) {
        let k = |n: &str| format!("i1514-{n}-{s}");
        let (a, b, j, room, fam) = (k("a"), k("b"), k("j"), k("room"), k("fam"));
        reg(d, &[&a, &b, &j, &room, &fam]).await;
        found_community(d, &room, "unanimous", &[&a, &b], &[])
            .await
            .unwrap();
        let rec = record_row(d, &room, cohort_scope::COMMUNITY).await;
        let e = put(d, &withdraw(&rec, &room, cohort_scope::COMMUNITY, &[&a]))
            .await
            .expect_err("I1514: one voice of two");
        assert!(
            matches!(e, Error::RosterAuthorityUnauthorized { .. }),
            "I1514: {e:?}"
        );
        assert!(active(d, &room, &a).await, "I1514: not dissolved");
        put(
            d,
            &withdraw(&rec, &room, cohort_scope::COMMUNITY, &[&a, &b]),
        )
        .await
        .expect("I1514: the room's protocol dissolves it");
        assert!(
            crate::federation::group_plane::community_dissolved_at(d, &room)
                .await
                .unwrap()
                .is_some(),
            "I1514: dissolved"
        );
        assert!(
            d.active_community_members(&room).await.unwrap().is_empty(),
            "I1514: the seats lapse"
        );
        assert!(
            d.lookup_community(&room).await.unwrap().is_some(),
            "I1514: the record stands"
        );
        let e = widen_community(d, &room, &[&a], &j, None, Utc::now())
            .await
            .expect_err("I1514: no new seat");
        assert_eq!(e.kind(), "federation_group_dissolved", "I1514: {e}");
        // A family's record withdraws is still refused (its own amendment).
        found_family(d, &fam, "founder_only", &[&a], &[])
            .await
            .unwrap();
        let frec = record_row(d, &fam, cohort_scope::FAMILY).await;
        put(d, &withdraw(&frec, &fam, cohort_scope::FAMILY, &[&a]))
            .await
            .expect_err("I1514: a family dissolves by its amendment");
    }
}

#[cfg(all(test, any(feature = "sqlite", feature = "postgres")))]
mod runners {
    fn suffix() -> String {
        uuid::Uuid::new_v4().simple().to_string()[..12].to_owned()
    }

    macro_rules! runners {
        ($modname:ident, $fresh:expr) => {
            mod $modname {
                use super::suffix;
                use crate::federation::FederationDirectory;
                #[tokio::test]
                async fn i1513_one_voice_needs_a_countersign() {
                    let Some(d) = $fresh.await else { return };
                    super::super::bodies::i1513_one_voice_needs_a_countersign(
                        &d as &dyn FederationDirectory,
                        &suffix(),
                    )
                    .await
                }
                #[tokio::test]
                async fn i1514_dissolution_is_the_records_withdraws() {
                    let Some(d) = $fresh.await else { return };
                    super::super::bodies::i1514_dissolution_is_the_records_withdraws(
                        &d as &dyn FederationDirectory,
                        &suffix(),
                    )
                    .await
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
