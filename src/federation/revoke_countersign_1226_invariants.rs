//! v61.1.0 (CIRISPersist#1226; CC rc14 4.4.3.2.8,
//! `CLM-affiliation-one-voice-countersign`) — **the cohort revoke door
//! carries the one-voice countersign.** sqlite and postgres.
//!
//! `FederationDirectory::revoke_member` (the `cohort_revoke_member` PyO3
//! door) builds the signed revocation from a
//! [`RevokeSpec`](crate::federation::cohort::RevokeSpec). Until #1226 the
//! spec had no co-signature list, so a one-founder affiliation could remove
//! no member through it: the seat alone is refused, and the official's
//! countersign had nowhere to ride. The spec now carries
//! [`RosterCosignature`](crate::federation::types::RosterCosignature)s (the
//! `AdmitSpec` shape), handed to the revocation door, which verifies each
//! against its signer's REGISTERED keys and counts only verified signers.
//!
//! - **I1610** — the seat with its designated official's countersign, both
//!   through the cohort door, is admitted: the member is no longer active.
//! - **I1611** — the seat alone through the cohort door is refused
//!   `affiliation_countersign_missing` (the gate is reached from this door).
//! - **I1612** — a countersign from the WRONG signer (a registered member who
//!   is not a designated official) is refused `affiliation_countersign_missing`:
//!   the gate asks who signed, not that someone did.
//! - **I1613** — a countersign that NAMES the official but was signed by
//!   another key is refused at verification and removes no one: the
//!   co-signature is verified, not just stored.
//! - **I1614** — the spec round-trips as the PyO3 door decodes it
//!   (`serde_json::from_str::<RevokeSpec>` of the JSON a host sends): the
//!   co-signatures survive, an old payload without them decodes to none, a
//!   malformed list is a refusal, and the DECODED spec drives the admitted
//!   removal.
//! - **I1615** — the family arm carries the co-signatures too: a `unanimous`
//!   family of two founders removes a member through the cohort door only
//!   with both; and a `self` removal carrying a co-signature is refused
//!   (no gate there counts it).

#[cfg(all(test, any(feature = "sqlite", feature = "postgres")))]
pub(crate) mod bodies {
    use crate::federation::affiliation_config::AFFILIATION_COUNTERSIGN_MISSING;
    use crate::federation::affiliation_floor_invariants::bodies::{
        active, affiliation, ms, rule, seat,
    };
    use crate::federation::cohort::{Cohort, RevokeSpec};
    use crate::federation::membership_acceptance_invariants::bodies::{
        found_family, found_room_with_blob, reg,
    };
    use crate::federation::tier_ingest::test_support as ts;
    use crate::federation::{Error, FederationDirectory};
    use chrono::{DateTime, Duration, Utc};

    /// A cohort-door spec for removing `m` from `group`, signed by
    /// `signers[0]` and co-signed by the rest, over the revocation
    /// `revoke_member` builds.
    fn spec(
        cohort: Cohort,
        group: &str,
        signers: &[&str],
        m: &str,
        at: DateTime<Utc>,
    ) -> RevokeSpec {
        let mut s = ts::sign_revoke_spec(cohort, signers[0], group, m, ms(at), None, vec![]);
        for c in &signers[1..] {
            ts::cosign_revoke_spec(&mut s, cohort, group, m, c);
        }
        s
    }

    /// A one-founder affiliation `solo` (founder `f`, official `official`)
    /// with members `m` and `n` seated at `at`.
    async fn sole_practice(
        d: &dyn FederationDirectory,
        solo: &str,
        f: &str,
        official: &str,
        m: &str,
        n: &str,
        at: DateTime<Utc>,
    ) {
        found_room_with_blob(
            d,
            solo,
            "founder_only",
            &[f],
            &[],
            Some(affiliation(Some(official))),
        )
        .await
        .expect("1226: a sole practitioner's affiliation");
        seat(d, solo, f, m, at).await;
        seat(d, solo, f, n, at + Duration::minutes(1)).await;
    }

    /// **I1610–I1613** — the cohort door's countersign: admitted with the
    /// official, refused alone, refused from the wrong signer, refused forged.
    pub(crate) async fn i1610_i1613_the_cohort_door_carries_the_countersign(
        d: &dyn FederationDirectory,
        s: &str,
    ) {
        let k = |x: &str| format!("i1610-{x}-{s}");
        let (f, official, m, n, solo) = (k("f"), k("official"), k("m"), k("n"), k("solo"));
        reg(d, &[&f, &official, &m, &n, &solo]).await;
        let at = Utc::now() - Duration::hours(1);
        sole_practice(d, &solo, &f, &official, &m, &n, at).await;

        // I1611 — the seat alone, through the cohort door.
        let e = d
            .revoke_member(
                Cohort::Affiliations,
                &solo,
                &m,
                spec(
                    Cohort::Affiliations,
                    &solo,
                    &[&f],
                    &m,
                    at + Duration::minutes(5),
                ),
            )
            .await
            .expect_err("I1611: the one seat alone");
        assert_eq!(rule(&e), AFFILIATION_COUNTERSIGN_MISSING, "I1611: {e}");
        assert!(active(d, &solo, &m).await, "I1611: still a member");

        // I1612 — a verified countersign from the wrong signer (a member, not
        // a designated official).
        let e = d
            .revoke_member(
                Cohort::Affiliations,
                &solo,
                &m,
                spec(
                    Cohort::Affiliations,
                    &solo,
                    &[&f, &n],
                    &m,
                    at + Duration::minutes(6),
                ),
            )
            .await
            .expect_err("I1612: a countersign from outside the officials");
        assert_eq!(rule(&e), AFFILIATION_COUNTERSIGN_MISSING, "I1612: {e}");
        assert!(active(d, &solo, &m).await, "I1612: still a member");

        // I1613 — a countersign that names the official, signed by `n`.
        let mut forged = spec(
            Cohort::Affiliations,
            &solo,
            &[&f, &n],
            &m,
            at + Duration::minutes(7),
        );
        forged.cosignatures[0].authority_key_id = official.clone();
        let e = d
            .revoke_member(Cohort::Affiliations, &solo, &m, forged)
            .await
            .expect_err("I1613: a forged countersign is verified, not stored");
        assert!(
            !matches!(e, Error::RosterAuthorityUnauthorized { .. }),
            "I1613: refused at verification, before standing: {e:?}"
        );
        assert!(active(d, &solo, &m).await, "I1613: still a member");

        // I1610 — the seat with the official, through the cohort door.
        d.revoke_member(
            Cohort::Affiliations,
            &solo,
            &m,
            spec(
                Cohort::Affiliations,
                &solo,
                &[&f, &official],
                &m,
                at + Duration::minutes(8),
            ),
        )
        .await
        .expect("I1610: the seat with the designated official");
        assert!(!active(d, &solo, &m).await, "I1610: removed");
        assert!(active(d, &solo, &n).await, "I1610: only the named member");
    }

    /// **I1614** — the spec round-trips as the PyO3 door decodes it, and the
    /// decoded spec drives the admitted removal.
    pub(crate) async fn i1614_the_python_payload_round_trips(d: &dyn FederationDirectory, s: &str) {
        let k = |x: &str| format!("i1614-{x}-{s}");
        let (f, official, m, n, solo) = (k("f"), k("official"), k("m"), k("n"), k("solo"));
        reg(d, &[&f, &official, &m, &n, &solo]).await;
        let at = Utc::now() - Duration::hours(1);
        sole_practice(d, &solo, &f, &official, &m, &n, at).await;

        let sent = spec(
            Cohort::Affiliations,
            &solo,
            &[&f, &official],
            &m,
            at + Duration::minutes(5),
        );
        // What a host sends as `revoke_spec_json`.
        let json = serde_json::to_string(&sent).expect("I1614: encode");
        let value: serde_json::Value = serde_json::from_str(&json).unwrap();
        assert_eq!(
            value["cosignatures"][0]["authority_key_id"], official,
            "I1614: the wire names the countersign: {json}"
        );
        // What `cohort_revoke_member` decodes.
        let decoded: RevokeSpec = serde_json::from_str(&json).expect("I1614: decode");
        assert_eq!(
            decoded, sent,
            "I1614: the countersign survives the round trip"
        );

        // An old payload (no `cosignatures`) decodes to none.
        let mut old = value.clone();
        old.as_object_mut().unwrap().remove("cosignatures");
        let old: RevokeSpec = serde_json::from_value(old).expect("I1614: an old payload");
        assert!(old.cosignatures.is_empty(), "I1614: absent = none");
        // A malformed list is a refusal, never read as none.
        for bad in [
            serde_json::json!([{}]),
            serde_json::json!("official"),
            serde_json::json!([{ "authority_key_id": official }]),
        ] {
            let mut v = value.clone();
            v["cosignatures"] = bad.clone();
            assert!(
                serde_json::from_value::<RevokeSpec>(v).is_err(),
                "I1614: malformed cosignatures {bad} is refused"
            );
        }

        d.revoke_member(Cohort::Affiliations, &solo, &m, decoded)
            .await
            .expect("I1614: the decoded spec removes");
        assert!(!active(d, &solo, &m).await, "I1614: removed");
    }

    async fn active_in_family(d: &dyn FederationDirectory, fid: &str, k: &str) -> bool {
        d.active_family_members(fid)
            .await
            .unwrap()
            .iter()
            .any(|m| m.key_id == k)
    }

    /// **I1615** — the family arm carries the co-signatures; `self` refuses
    /// them.
    pub(crate) async fn i1615_family_arm_and_self_refusal(d: &dyn FederationDirectory, s: &str) {
        let k = |x: &str| format!("i1615-{x}-{s}");
        let (a, b, u, fam) = (k("a"), k("b"), k("u"), k("fam"));
        reg(d, &[&a, &b, &u, &fam]).await;
        found_family(d, &fam, "unanimous", &[&a, &b], &[&u])
            .await
            .expect("I1615: a two-founder unanimous family");
        assert!(active_in_family(d, &fam, &u).await, "I1615: u is a member");
        let at = Utc::now() - Duration::minutes(30);

        d.revoke_member(
            Cohort::Family,
            &fam,
            &u,
            spec(Cohort::Family, &fam, &[&a], &u, at),
        )
        .await
        .expect_err("I1615: one of two unanimous founders");
        assert!(active_in_family(d, &fam, &u).await, "I1615: still a member");

        d.revoke_member(
            Cohort::Family,
            &fam,
            &u,
            spec(
                Cohort::Family,
                &fam,
                &[&a, &b],
                &u,
                at + Duration::minutes(1),
            ),
        )
        .await
        .expect("I1615: both founders, the second as a co-signature");
        assert!(!active_in_family(d, &fam, &u).await, "I1615: removed");

        // `self`: a co-signature has no gate to count it, so it is refused.
        let mut selfie =
            ts::sign_revoke_spec(Cohort::SelfId, &a, &a, &b, ms(Utc::now()), None, vec![]);
        selfie
            .cosignatures
            .push(crate::federation::types::RosterCosignature {
                authority_key_id: b.clone(),
                scrub_signature_classical: "AA==".into(),
                scrub_signature_pqc: None,
            });
        let e = d
            .revoke_member(Cohort::SelfId, &a, &b, selfie)
            .await
            .expect_err("I1615: a self removal carries no co-signature");
        assert!(
            matches!(e, Error::InvalidArgument(ref m) if m.contains("co-signatures")),
            "I1615: {e:?}"
        );
    }
}

#[cfg(all(test, any(feature = "sqlite", feature = "postgres")))]
mod tests {
    use super::bodies;
    use crate::federation::FederationDirectory;

    fn tag(n: &str) -> String {
        format!("{n}{}", &uuid::Uuid::new_v4().simple().to_string()[..8])
    }

    macro_rules! on_every_backend {
        ($name:ident, $body:path) => {
            mod $name {
                use super::*;

                #[cfg(feature = "sqlite")]
                #[tokio::test(flavor = "multi_thread")]
                async fn sqlite() {
                    use crate::store::Backend as _;
                    let b = crate::store::sqlite::SqliteBackend::open_in_memory()
                        .await
                        .unwrap();
                    b.run_migrations().await.unwrap();
                    $body(&b as &dyn FederationDirectory, &tag("s")).await;
                }

                #[cfg(feature = "postgres")]
                #[tokio::test(flavor = "multi_thread")]
                async fn postgres() {
                    use crate::store::Backend as _;
                    let Some(dsn) = crate::test_pg::empty_dsn() else {
                        eprintln!("1226 postgres: no CIRIS_PERSIST_TEST_PG base DSN — SKIPPED");
                        return;
                    };
                    let b = crate::store::postgres::PostgresBackend::connect(&dsn)
                        .await
                        .unwrap();
                    b.run_migrations().await.unwrap();
                    $body(&b as &dyn FederationDirectory, &tag("p")).await;
                    eprintln!("{}: RAN", stringify!($name));
                }
            }
        };
    }

    on_every_backend!(
        i1610_i1613,
        bodies::i1610_i1613_the_cohort_door_carries_the_countersign
    );
    on_every_backend!(i1614, bodies::i1614_the_python_payload_round_trips);
    on_every_backend!(i1615, bodies::i1615_family_arm_and_self_refusal);
}
