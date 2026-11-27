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
//! - **I1613** (DELETED v62.0.0: an earlier-form co-signature forgery) — a countersign that NAMES the official but was signed by
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
//!   (no gate there counts it), led by `self_removal_cosignatures_refused`.
//! - **I1616** (D15) — the countersign is a second PERSON: an official key
//!   that is a device on the seat holder's own self roster is one voice with
//!   the seat, refused `affiliation_countersign_missing`.
//! - **I1617** (L5) — the removed member's own verified co-signature makes the
//!   removal their leave: admitted without an official; a co-signature naming
//!   them but signed by another key is refused.

#[cfg(all(test, any(feature = "sqlite", feature = "postgres")))]
pub(crate) mod bodies {
    use crate::federation::affiliation_config::AFFILIATION_COUNTERSIGN_MISSING;
    use crate::federation::affiliation_floor_invariants::bodies::{
        active, affiliation, ms, rule, seat,
    };
    use crate::federation::cohort::Cohort;
    use crate::federation::edition2::fixture_switch as e2;
    use crate::federation::edition2::ingest::StatementOutcome;
    use crate::federation::membership_acceptance_invariants::bodies::{
        found_family, found_room_with_blob, id_of, proposal, put, reg, reply,
    };
    use crate::federation::tier_ingest::test_support as ts;
    use crate::federation::types::{
        cohort_scope, CommunityMembershipRevocation, FamilyMembershipRevocation,
        FamilyMembershipWidening,
    };
    use crate::federation::{Error, FederationDirectory};
    use chrono::{DateTime, Duration, Utc};

    /// v62.0.0 (JSON cut, E7; lead ruling) — a cohort removal is a
    /// `membership:removal` statement naming the held roster head; its
    /// co-signers are counted VOICES (T1 §3). `signers[0]` authors, the rest
    /// voice it. A removal short of what the group requires is held
    /// `Pending` and removes no one. Signers are SEEDS (the earlier-form
    /// signing helpers seed from the name, E0 v1.4); the group and the member
    /// may be seeds (the voices write identity-refs).
    async fn remove(
        d: &dyn FederationDirectory,
        cohort: Cohort,
        group: &str,
        signers: &[&str],
        m: &str,
        at: DateTime<Utc>,
    ) -> Result<StatementOutcome, Error> {
        let head = e2::held_head(d, &e2::kid(group)).await.map(|(h, _)| h);
        if matches!(cohort, Cohort::Family) {
            let mut s = ts::sign_family_membership_revocation(
                signers[0],
                FamilyMembershipRevocation {
                    family_key_id: group.to_owned(),
                    removed_identity_key_id: m.to_owned(),
                    removed_at: ms(at),
                    effective_at: ms(at),
                    reason: None,
                    witness_set: Vec::new(),
                    persist_row_hash: String::new(),
                    record_row_id: None,
                },
            );
            for c in &signers[1..] {
                ts::cosign_family_membership_revocation(&mut s, c);
            }
            return e2::put_voices(d, &e2::family_revocation_voices(&s, head.as_ref())).await;
        }
        let mut s = ts::sign_community_membership_revocation(
            signers[0],
            CommunityMembershipRevocation {
                community_key_id: group.to_owned(),
                removed_identity_key_id: m.to_owned(),
                removed_at: ms(at),
                effective_at: ms(at),
                reason: None,
                witness_set: Vec::new(),
                persist_row_hash: String::new(),
                record_row_id: None,
            },
        );
        for c in &signers[1..] {
            ts::cosign_community_membership_revocation(&mut s, c);
        }
        e2::put_voices(d, &e2::community_revocation_voices(&s, head.as_ref())).await
    }

    /// The removal did not land: held `Pending` (short of the group's
    /// count), or refused by the affiliation's countersign rule.
    fn not_landed(r: &Result<StatementOutcome, Error>) -> bool {
        match r {
            Ok(StatementOutcome::Pending { .. }) => true,
            Err(e) => rule(e) == AFFILIATION_COUNTERSIGN_MISSING,
            Ok(_) => false,
        }
    }

    /// The member is active in the group (keyed by identity-refs).
    async fn active_kid(d: &dyn FederationDirectory, group: &str, k: &str) -> bool {
        active(d, &e2::kid(group), &e2::kid(k)).await
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
            Some(affiliation(Some(&e2::kid(official)))),
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
        // v62.0.0 (round 3) — named as the directory keys them (E5's `id_of`,
        // as I1513 does): a seed seated nobody the roster holds.
        let (f, official, m, n, solo) = (
            id_of(&f),
            id_of(&official),
            id_of(&m),
            id_of(&n),
            id_of(&solo),
        );
        let at = Utc::now() - Duration::hours(1);
        sole_practice(d, &solo, &f, &official, &m, &n, at).await;

        // I1611 — the seat alone.
        let r = remove(
            d,
            Cohort::Affiliations,
            &solo,
            &[&f],
            &m,
            at + Duration::minutes(5),
        )
        .await;
        assert!(not_landed(&r), "I1611: the one seat alone: {r:?}");
        assert!(active_kid(d, &solo, &m).await, "I1611: still a member");

        // I1612 — a voice from the wrong signer (a member, not a designated
        // official).
        let r = remove(
            d,
            Cohort::Affiliations,
            &solo,
            &[&f, &n],
            &m,
            at + Duration::minutes(6),
        )
        .await;
        assert!(
            not_landed(&r),
            "I1612: a voice from outside the officials: {r:?}"
        );
        assert!(active_kid(d, &solo, &m).await, "I1612: still a member");

        // v62.0.0 (wave 3 rule 4; T1 "delete" row) — I1613 (a co-signature
        // naming the official but signed by another key) is deleted: it pins an
        // earlier-form `RosterCosignature` proof shape. In edition 2 a voice is a
        // statement the door verifies (`edition2_statement_invalid`).

        // I1610 — the seat with the official's voice.
        remove(
            d,
            Cohort::Affiliations,
            &solo,
            &[&f, &official],
            &m,
            at + Duration::minutes(8),
        )
        .await
        .expect("I1610: the seat with the designated official");
        assert!(!active_kid(d, &solo, &m).await, "I1610: removed");
        assert!(
            active_kid(d, &solo, &n).await,
            "I1610: only the named member"
        );
    }

    // v62.0.0 (JSON cut, E7) — I1614 (the `RevokeSpec` JSON a host sends to
    // `cohort_revoke_member`, its `cosignatures` round trip and malformed
    // lists) is deleted: an earlier-form co-signature wire shape. A removal is
    // a statement with voices (I1610).

    /// **I1616** (D15) — the countersign is a second PERSON. The affiliation's
    /// designated official is `f2`, a device on the seat holder `f`'s own self
    /// roster: `f` co-signed by `f2` is one voice, refused
    /// `affiliation_countersign_missing`. The same removal co-signed by an
    /// official who is another person is admitted (the control).
    pub(crate) async fn i1616_the_seats_own_device_is_not_a_countersign(
        d: &dyn FederationDirectory,
        s: &str,
    ) {
        let k = |x: &str| format!("i1616-{x}-{s}");
        let (f, f2, m, n, solo) = (k("f"), k("f2"), k("m"), k("n"), k("solo"));
        reg(d, &[&f, &f2, &m, &n, &solo]).await;
        // f2 joins f's self roster: f's second device, an edition-2
        // `identity:occurrence` bind (the device's own voice, then f's; O1).
        crate::federation::edition2::fixture_occurrence::put_bind(
            d,
            &f,
            &f,
            &f2,
            crate::federation::types::device_class::LAPTOP,
            &crate::federation::edition2::fixture_occurrence::BindOptions::default(),
        )
        .await
        .expect("I1616: f's second device");
        // v62.0.0 (round 3) — named as the directory keys them (E5's `id_of`,
        // as I1513 does): a seed seated nobody the roster holds.
        let (f, f2, m, n, solo) = (id_of(&f), id_of(&f2), id_of(&m), id_of(&n), id_of(&solo));
        let at = Utc::now() - Duration::hours(1);
        sole_practice(d, &solo, &f, &f2, &m, &n, at).await;
        let r = remove(d, Cohort::Affiliations, &solo, &[&f, &f2], &m, Utc::now()).await;
        assert!(
            not_landed(&r),
            "I1616: the seat's own device is not a second voice: {r:?}"
        );
        assert!(active_kid(d, &solo, &m).await, "I1616: still a member");

        // Control: an official who is another person countersigns.
        let (g, official, p, q, other) = (k("g"), k("official"), k("p"), k("q"), k("other"));
        reg(d, &[&g, &official, &p, &q, &other]).await;
        let (g, official, p, q, other) = (
            id_of(&g),
            id_of(&official),
            id_of(&p),
            id_of(&q),
            id_of(&other),
        );
        sole_practice(d, &other, &g, &official, &p, &q, at).await;
        remove(
            d,
            Cohort::Affiliations,
            &other,
            &[&g, &official],
            &p,
            Utc::now(),
        )
        .await
        .expect("I1616: another person's countersign");
        assert!(!active_kid(d, &other, &p).await, "I1616: removed");
    }

    /// **I1617** (L5) — a removal the removed member co-signed is their own
    /// leave: the seat with the member's verified co-signature removes them
    /// with no official's countersign (CC rc14 4.4.3.2.8 governs an act
    /// AGAINST a member; this is the member's act). A co-signature that names
    /// the member but was signed by another key is refused at verification
    /// and removes no one.
    pub(crate) async fn i1617_a_removed_members_own_cosignature_is_a_leave(
        d: &dyn FederationDirectory,
        s: &str,
    ) {
        let k = |x: &str| format!("i1617-{x}-{s}");
        let (f, official, m, n, solo) = (k("f"), k("official"), k("m"), k("n"), k("solo"));
        reg(d, &[&f, &official, &m, &n, &solo]).await;
        // v62.0.0 (round 3) — named as the directory keys them (E5's `id_of`,
        // as I1513 does): a seed seated nobody the roster holds.
        let (f, official, m, n, solo) = (
            id_of(&f),
            id_of(&official),
            id_of(&m),
            id_of(&n),
            id_of(&solo),
        );
        let at = Utc::now() - Duration::hours(1);
        sole_practice(d, &solo, &f, &official, &m, &n, at).await;

        // v62.0.0 (wave 3 rule 4) — the forged-co-signature arm is deleted (an
        // earlier-form `RosterCosignature` proof shape).

        // m's own verified co-signature: their leave, admitted.
        remove(
            d,
            Cohort::Affiliations,
            &solo,
            &[&f, &m],
            &m,
            at + Duration::minutes(6),
        )
        .await
        .expect("I1617: the member's own voice is a leave");
        assert!(!active_kid(d, &solo, &m).await, "I1617: m left");
        assert!(active_kid(d, &solo, &n).await, "I1617: only m");
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
        // v62.0.0 (round 3) — named as the directory keys them (E5's `id_of`,
        // as I1513 does): a seed seated nobody the roster holds.
        let (a, b, u, fam) = (id_of(&a), id_of(&b), id_of(&u), id_of(&fam));
        // Every member a founding record lists signs it (CC 3.2, the
        // founding rule), so `u` joins the two founders the way a member
        // does: by a widening both founders sign, after u's consent.
        found_family(d, &fam, "unanimous", &[&a, &b], &[])
            .await
            .expect("I1615: a two-founder unanimous family");
        // v62.0.0 (T1 v3) — u's widening lands as edition-2 rows: a founder's
        // proposal, u's acceptance, then the widening voiced by both founders
        // naming the held head.
        let t = ms(Utc::now() - Duration::hours(1));
        let p = proposal(
            &a,
            cohort_scope::FAMILY,
            &fam,
            &u,
            None,
            t,
            Some(Duration::days(7)),
        );
        put(d, &p).await.expect("I1615: the proposal");
        put(d, &reply(&u, &u, &p, true, t + Duration::seconds(1)))
            .await
            .expect("I1615: u accepts");
        let mut w = ts::sign_family_membership_widening(
            &a,
            FamilyMembershipWidening {
                family_key_id: fam.clone(),
                member_key_id: u.clone(),
                joined_at: t + Duration::seconds(2),
                effective_at: t + Duration::seconds(2),
                role: None,
                persist_row_hash: String::new(),
                record_row_id: None,
            },
        );
        ts::cosign_family_membership_widening(&mut w, &b);
        let head = e2::held_head(d, &e2::kid(&fam)).await.map(|(h, _)| h);
        e2::put_voices(d, &e2::family_widening_voices(&w, head.as_ref()))
            .await
            .expect("I1615: u joins by the founders' widening");
        assert!(
            active_in_family(d, &e2::kid(&fam), &e2::kid(&u)).await,
            "I1615: u is a member"
        );
        let at = Utc::now() - Duration::minutes(30);

        let r = remove(d, Cohort::Family, &fam, &[&a], &u, at).await;
        assert!(
            matches!(r, Ok(StatementOutcome::Pending { .. })),
            "I1615: one of two unanimous founders is short: {r:?}"
        );
        assert!(
            active_in_family(d, &e2::kid(&fam), &e2::kid(&u)).await,
            "I1615: still a member"
        );

        remove(
            d,
            Cohort::Family,
            &fam,
            &[&a, &b],
            &u,
            at + Duration::minutes(1),
        )
        .await
        .expect("I1615: both founders, the second as a voice");
        assert!(
            !active_in_family(d, &e2::kid(&fam), &e2::kid(&u)).await,
            "I1615: removed"
        );
        // v62.0.0 (JSON cut, E7) — the `self` arm (a `RevokeSpec` carrying a
        // `RosterCosignature` refused `self_removal_cosignatures_refused`) is
        // deleted: an earlier-form co-signature shape (T1 "delete" row).
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
    on_every_backend!(i1615, bodies::i1615_family_arm_and_self_refusal);
    on_every_backend!(
        i1616,
        bodies::i1616_the_seats_own_device_is_not_a_countersign
    );
    on_every_backend!(
        i1617,
        bodies::i1617_a_removed_members_own_cosignature_is_a_leave
    );
}
