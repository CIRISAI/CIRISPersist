//! v53.0.0 (CIRISPersist#963, CC 6.1.5.3) — **I410–I419: durability at every
//! tier.** Memory, sqlite, postgres.
//!
//! - **I410** `self` bytes reach the owner's other claimed personal nodes —
//!   and not a server-class node; the holdings plane is advertisable to them.
//! - **I411** `family` bytes reach the family's audience only: a member's
//!   node in, a stranger's node out.
//! - **I412** consent is supreme: a node its owner's allow list keeps a family
//!   off is in no family audience, so it is never told of a holding.
//! - **I413** an audience of 25 claimed nodes is a full-blob audience.
//! - **I414** the 26th node makes it a fountain-tuple audience.
//! - **I417** a holding claim from outside the cohort is not admitted (the
//!   claimant is not in the content's audience) — the same verb as I418.
//! - **I418** a holding is never advertised to a node outside the cohort.
//! - **I419** (from disk) the `FountainContent` arm of `projection_for` names
//!   no `SelfOwn` — the source, comments stripped.
//!
//! - **I415** the deficit is the audience without a live `here` (S2's fold):
//!   a `none` and a silent node are missing; a node outside the audience is
//!   never listed, its `here` never a copy.
//! - **I416** a lapsed `here` (72 h + 1 s) is missing; exactly 72 h is a copy;
//!   a `received` verdict is missing.
//! - **I415b** (sqlite, postgres; the engine) a node holding a DAG's manifest
//!   but missing one chunk cannot file `here`, and the deficit lists it; with
//!   every chunk held it can, and the deficit counts it.

#[cfg(test)]
pub(crate) mod bodies {
    use crate::federation::custody_ack::{CustodyState, CustodyVerdict};
    use crate::federation::custody_ack_invariants::bodies as cust;
    use crate::federation::durability::{
        content_audience, deficit_over, durability_mode, ContentAudience, DeficitAudience,
        DurabilityDeficit, DurabilityMode, DEFAULT_FEASIBILITY_FLOOR,
    };
    use crate::federation::namespace::{
        projection_for, resolve_projection_recipients, AuthorityClass, Plane, Projection,
        RecipientBasis,
    };
    use crate::federation::replication_audience_invariants::bodies::{
        claim, entries, family, grant, nodes, put, room, users,
    };
    use crate::federation::types::cohort_scope::{COMMUNITY, FAMILY, SELF};
    use crate::federation::types::device_class;
    use crate::federation::FederationDirectory;

    async fn nodes_of(
        d: &dyn FederationDirectory,
        scope: &str,
        author: Option<&str>,
        group: Option<&str>,
    ) -> std::collections::BTreeSet<String> {
        match content_audience(d, scope, author, group).await.unwrap() {
            ContentAudience::Nodes(n) => n,
            other => panic!("expected a node audience at {scope}, got {other:?}"),
        }
    }

    /// May a holding of `scope`/`group` bytes be advertised to `peer` — and,
    /// the same question, may `peer`'s holding claim be admitted?
    async fn advertisable(
        d: &dyn FederationDirectory,
        scope: &str,
        group: &str,
        peer: &str,
    ) -> (bool, bool) {
        let v = resolve_projection_recipients(
            d,
            Plane::FountainContent,
            scope,
            AuthorityClass::ProducerSteward,
            false,
            group,
            peer,
        )
        .await
        .unwrap();
        (v.set_resolvable, v.may_advertise())
    }

    /// **I410** — `self` bytes hold-and-forward among the owner's nodes.
    pub(crate) async fn i410_self_reaches_the_owners_nodes(d: &dyn FederationDirectory, s: &str) {
        let (owner, laptop, phone, server) = (
            format!("i410-o-{s}"),
            format!("i410-l-{s}"),
            format!("i410-p-{s}"),
            format!("i410-s-{s}"),
        );
        users(d, &[&owner]).await;
        nodes(d, &[&laptop, &phone, &server]).await;
        claim(d, &owner, &laptop, device_class::LAPTOP).await;
        claim(d, &owner, &phone, device_class::PHONE).await;
        claim(d, &owner, &server, device_class::SERVER).await;
        assert_eq!(
            projection_for(
                Plane::FountainContent,
                SELF,
                AuthorityClass::ProducerSteward,
                false
            ),
            Projection::Cohort,
            "I410 self bytes are Cohort (CC 6.1.5.3)"
        );
        // authored by the owner, or by one of the owner's devices: the same
        // audience (the principal behind the author)
        for author in [&owner, &laptop] {
            let a = nodes_of(d, SELF, Some(author), None).await;
            assert!(
                a.contains(&laptop) && a.contains(&phone),
                "I410 the owner's personal nodes are the audience: {a:?}"
            );
            assert!(
                !a.contains(&server),
                "I410 a server-class node holds no self content: {a:?}"
            );
        }
        let (judged, may) = advertisable(d, SELF, &owner, &phone).await;
        assert!(judged && may, "I410 a holding is advertisable to the phone");
        let (judged, may) = advertisable(d, SELF, &owner, &server).await;
        assert!(judged && !may, "I410 and judged-not to the server");
    }

    /// **I411** — `family` bytes reach the family's audience only.
    pub(crate) async fn i411_family_reaches_its_audience_only(
        d: &dyn FederationDirectory,
        s: &str,
    ) {
        let (a, b, stranger, a_laptop, b_phone, x_laptop, fam) = (
            format!("i411-a-{s}"),
            format!("i411-b-{s}"),
            format!("i411-x-{s}"),
            format!("i411-al-{s}"),
            format!("i411-bp-{s}"),
            format!("i411-xl-{s}"),
            format!("i411-f-{s}"),
        );
        users(d, &[&a, &b, &stranger]).await;
        nodes(d, &[&a_laptop, &b_phone, &x_laptop]).await;
        claim(d, &a, &a_laptop, device_class::LAPTOP).await;
        claim(d, &b, &b_phone, device_class::PHONE).await;
        claim(d, &stranger, &x_laptop, device_class::LAPTOP).await;
        family(d, &fam, &[&a, &b]).await;
        let aud = nodes_of(d, FAMILY, Some(&a), Some(&fam)).await;
        assert!(
            aud.contains(&a_laptop) && aud.contains(&b_phone),
            "I411 both members' nodes hold the family's bytes: {aud:?}"
        );
        assert!(
            !aud.contains(&x_laptop),
            "I411 a stranger's node does not: {aud:?}"
        );
        let (judged, may) = advertisable(d, FAMILY, &fam, &b_phone).await;
        assert!(
            judged && may,
            "I411 a member's node may be told of a holding"
        );
        let v = resolve_projection_recipients(
            d,
            Plane::FountainContent,
            FAMILY,
            AuthorityClass::ProducerSteward,
            false,
            &fam,
            &b_phone,
        )
        .await
        .unwrap();
        assert_eq!(
            v.basis,
            RecipientBasis::CohortRoster,
            "I411 family bytes are hold-and-forward, not publish-own"
        );
        // a family row that names no family has no audience to resolve: it
        // is never everyone, and nothing is reported as a target
        assert_eq!(
            content_audience(d, FAMILY, Some(&a), None).await.unwrap(),
            ContentAudience::Unresolvable,
            "I411 a family row with no group key is unresolvable, never everyone"
        );
    }

    /// **I412** — consent is supreme: an allow list that keeps the family off
    /// a node keeps it out of the audience and out of every advertisement.
    pub(crate) async fn i412_a_denied_node_gets_nothing(d: &dyn FederationDirectory, s: &str) {
        let (owner, work_laptop, phone, fam, work) = (
            format!("i412-o-{s}"),
            format!("i412-wl-{s}"),
            format!("i412-p-{s}"),
            format!("i412-f-{s}"),
            format!("i412-w-{s}"),
        );
        users(d, &[&owner]).await;
        nodes(d, &[&work_laptop, &phone]).await;
        claim(d, &owner, &work_laptop, device_class::LAPTOP).await;
        claim(d, &owner, &phone, device_class::PHONE).await;
        family(d, &fam, &[&owner]).await;
        room(d, &work, &[&owner]).await;
        // control: before the list, the laptop is in the family audience
        assert!(
            nodes_of(d, FAMILY, Some(&owner), Some(&fam))
                .await
                .contains(&work_laptop),
            "I412 control: a personal laptop holds the family by default"
        );
        put(
            d,
            &grant(
                &owner,
                Some(&work_laptop),
                Some(entries(&[(COMMUNITY, &work)])),
            ),
        )
        .await
        .expect("I412 the owner's allow list for the work laptop");
        let aud = nodes_of(d, FAMILY, Some(&owner), Some(&fam)).await;
        assert!(
            !aud.contains(&work_laptop),
            "I412 the denied laptop is not in the family audience: {aud:?}"
        );
        assert!(aud.contains(&phone), "I412 the phone still is: {aud:?}");
        let (judged, may) = advertisable(d, FAMILY, &fam, &work_laptop).await;
        assert!(
            judged && !may,
            "I412 the denied laptop is never told of a family holding (judged, not unknown)"
        );
        // the room it was set up to serve still reaches it
        assert!(
            nodes_of(d, COMMUNITY, Some(&owner), Some(&work))
                .await
                .contains(&work_laptop),
            "I412 the listed room reaches it"
        );
    }

    /// **I413 / I414** — the small-audience rule over a real audience.
    pub(crate) async fn i413_i414_small_audience_boundary(d: &dyn FederationDirectory, s: &str) {
        let owner = format!("i413-o-{s}");
        users(d, &[&owner]).await;
        let mut claimed = Vec::new();
        for i in 0..25 {
            let n = format!("i413-n{i}-{s}");
            nodes(d, &[&n]).await;
            claim(d, &owner, &n, device_class::LAPTOP).await;
            claimed.push(n);
        }
        let aud = nodes_of(d, SELF, Some(&owner), None).await;
        assert_eq!(aud.len(), 25, "I413 25 claimed personal nodes");
        assert_eq!(
            durability_mode(aud.len(), DEFAULT_FEASIBILITY_FLOOR),
            DurabilityMode::Full,
            "I413 below N + K every audience node holds the full blob"
        );
        let n = format!("i414-n25-{s}");
        nodes(d, &[&n]).await;
        claim(d, &owner, &n, device_class::PHONE).await;
        let aud = nodes_of(d, SELF, Some(&owner), None).await;
        assert_eq!(aud.len(), 26, "I414 the 26th node");
        assert_eq!(
            durability_mode(aud.len(), DEFAULT_FEASIBILITY_FLOOR),
            DurabilityMode::Tuple,
            "I414 at N + K the fountain tuple applies"
        );
        // a server-class node is no audience node and does not tip it
        let srv = format!("i414-srv-{s}");
        nodes(d, &[&srv]).await;
        claim(d, &owner, &srv, device_class::SERVER).await;
        assert_eq!(
            nodes_of(d, SELF, Some(&owner), None).await.len(),
            26,
            "I414 a server-class node is not counted toward the self target"
        );
    }

    /// **I417 / I418** — a holding never crosses the cohort, either way: a
    /// claim from outside is not admitted, and no outsider is told.
    pub(crate) async fn i417_i418_holdings_stay_in_the_cohort(
        d: &dyn FederationDirectory,
        s: &str,
    ) {
        let (owner, phone, stranger, x_node, fam) = (
            format!("i417-o-{s}"),
            format!("i417-p-{s}"),
            format!("i417-x-{s}"),
            format!("i417-xn-{s}"),
            format!("i417-f-{s}"),
        );
        users(d, &[&owner, &stranger]).await;
        nodes(d, &[&phone, &x_node]).await;
        claim(d, &owner, &phone, device_class::PHONE).await;
        claim(d, &stranger, &x_node, device_class::LAPTOP).await;
        family(d, &fam, &[&owner]).await;
        for (scope, group) in [(SELF, owner.as_str()), (FAMILY, fam.as_str())] {
            let (judged, may) = advertisable(d, scope, group, &x_node).await;
            assert!(
                judged && !may,
                "I417/I418 {scope}: an outsider's node neither claims nor is told"
            );
            let (judged, may) = advertisable(d, scope, group, &phone).await;
            assert!(
                judged && may,
                "I417/I418 {scope}: the cohort's own node does (the trap is reachable)"
            );
        }
        // a person key is not a node: the audience is claimed nodes
        let (judged, may) = advertisable(d, FAMILY, &fam, &owner).await;
        assert!(judged && !may, "I418 a person key is not an audience node");
    }

    /// The deficit of a `self` blob of `owner` at `now`, over S2's fold.
    async fn deficit(
        d: &dyn FederationDirectory,
        owner: &str,
        sha: &[u8; 32],
        known: &std::collections::BTreeMap<String, CustodyVerdict>,
        now: chrono::DateTime<chrono::Utc>,
    ) -> DurabilityDeficit {
        let aud = content_audience(d, SELF, Some(owner), None).await.unwrap();
        deficit_over(
            d,
            &hex::encode(sha),
            aud,
            known,
            DEFAULT_FEASIBILITY_FLOOR,
            now,
        )
        .await
        .unwrap()
    }

    fn sorted(mut v: Vec<String>) -> Vec<String> {
        v.sort();
        v
    }

    /// **I415** — the deficit lists exactly the audience nodes with no live
    /// `here`: a `none`, no report at all, and never a node outside the
    /// audience (a server-class node's live `here` is not a copy here).
    pub(crate) async fn i415_the_deficit_is_the_audience_without_a_live_here(
        d: &dyn FederationDirectory,
        s: &str,
    ) {
        use chrono::Duration;
        let owner = format!("i415-o-{s}");
        users(d, &[&owner]).await;
        let here = cust::device_as(
            d,
            &format!("i415-the-deficit-{s}--h"),
            crate::federation::types::identity_type::NODE,
        )
        .await;
        let gone = cust::device_as(
            d,
            &format!("i415-the-deficit-{s}--n"),
            crate::federation::types::identity_type::NODE,
        )
        .await;
        let silent = cust::device_as(
            d,
            &format!("i415-the-deficit-{s}--u"),
            crate::federation::types::identity_type::NODE,
        )
        .await;
        let server = cust::device_as(
            d,
            &format!("i415-the-deficit-{s}--s"),
            crate::federation::types::identity_type::NODE,
        )
        .await;
        for k in [&here, &gone, &silent] {
            claim(d, &owner, k, device_class::LAPTOP).await;
        }
        claim(d, &owner, &server, device_class::SERVER).await;
        let sha = {
            use sha2::Digest as _;
            let h: [u8; 32] = sha2::Sha256::digest(format!("i415-blob-{s}")).into();
            h
        };
        let t0 = cust::base();
        cust::report(d, &here, &sha, CustodyState::Here, t0).await;
        cust::report(d, &gone, &sha, CustodyState::None, t0).await;
        // a server-class node is not in its owner's self cohort, so it cannot
        // even place a self report: the audience and the report door agree
        let r = cust::try_report(d, &server, &sha, CustodyState::Here, t0).await;
        assert!(
            r.as_ref()
                .is_err_and(|e| e.to_string().contains("custody_ack_outside_cohort")),
            "I415 a server-class node's self report is refused: {r:?}"
        );
        let now = t0 + Duration::hours(1);
        let v = deficit(d, &owner, &sha, &Default::default(), now).await;
        assert_eq!(
            v.audience,
            DeficitAudience::Nodes(sorted(vec![here.clone(), gone.clone(), silent.clone()])),
            "I415 the audience is the owner's personal nodes only"
        );
        assert_eq!(v.live_here, vec![here.clone()], "I415 one live copy");
        assert_eq!(
            v.missing,
            sorted(vec![gone.clone(), silent.clone()]),
            "I415 a `none` and a silent node are missing; the server node is not listed"
        );
        assert_eq!(v.mode, Some(DurabilityMode::Full), "I415 3 < N + K");
    }

    /// **I416** — a lapsed `here` is missing (72 h at the reader's clock, both
    /// sides of the boundary), and so is a device whose verdict is `received`.
    pub(crate) async fn i416_an_expired_here_is_missing(d: &dyn FederationDirectory, s: &str) {
        use chrono::Duration;
        let owner = format!("i416-o-{s}");
        users(d, &[&owner]).await;
        let dev = cust::device_as(
            d,
            &format!("i416-the-deficit-{s}--h"),
            crate::federation::types::identity_type::NODE,
        )
        .await;
        claim(d, &owner, &dev, device_class::PHONE).await;
        let sha = {
            use sha2::Digest as _;
            let h: [u8; 32] = sha2::Sha256::digest(format!("i416-blob-{s}")).into();
            h
        };
        let t0 = cust::base();
        cust::report(d, &dev, &sha, CustodyState::Here, t0).await;
        let at_72h = deficit(
            d,
            &owner,
            &sha,
            &Default::default(),
            t0 + Duration::hours(72),
        )
        .await;
        assert_eq!(
            at_72h.live_here,
            vec![dev.clone()],
            "I416 exactly 72 h old is still a copy"
        );
        let after = deficit(
            d,
            &owner,
            &sha,
            &Default::default(),
            t0 + Duration::hours(72) + Duration::seconds(1),
        )
        .await;
        assert!(after.live_here.is_empty(), "I416 lapsed: {after:?}");
        assert_eq!(after.missing, vec![dev.clone()], "I416 lapsed is missing");
        // a delivery receipt the custody view folded (`received`) is not a copy
        let known = std::collections::BTreeMap::from([(dev.clone(), CustodyVerdict::Received)]);
        let rec = deficit(d, &owner, &sha, &known, t0 + Duration::hours(1)).await;
        assert_eq!(
            rec.missing,
            vec![dev.clone()],
            "I416 `received` is missing, and the view's verdict is the one used"
        );
    }
}

/// **I419** — from disk: the `FountainContent` arm of `projection_for`
/// resolves no `SelfOwn` at any scope (CC 6.1.5.3). Comments are stripped, so
/// a commented-out arm cannot satisfy or defeat the count.
#[cfg(test)]
mod from_disk {
    fn strip_comments(src: &str) -> String {
        src.lines()
            .map(|l| match l.find("//") {
                Some(i) => &l[..i],
                None => l,
            })
            .collect::<Vec<_>>()
            .join("\n")
    }

    #[test]
    fn i419_the_bytes_plane_has_no_publish_own_cell() {
        let src = std::fs::read_to_string(concat!(
            env!("CARGO_MANIFEST_DIR"),
            "/src/federation/namespace/mod.rs"
        ))
        .expect("read namespace/mod.rs");
        let code = strip_comments(&src);
        let body_start = code
            .find("pub fn projection_for(")
            .expect("I419 projection_for is in namespace/mod.rs");
        let body = &code[body_start..];
        let arm_start = body
            .find("Plane::FountainContent => match cohort_scope {")
            .expect("I419 the FountainContent arm is a match on the scope");
        let arm = &body[arm_start..];
        let arm_end = arm
            .find("Plane::HardCaseEvent")
            .expect("I419 the HardCaseEvent arm follows");
        let arm = &arm[..arm_end];
        assert_eq!(
            arm.matches("Projection::SelfOwn").count(),
            0,
            "I419 the bytes plane must not publish-own at any tier:\n{arm}"
        );
        assert!(
            arm.contains("cohort_scope::SELF") && arm.contains("cohort_scope::FAMILY"),
            "I419 self and family are named in the arm (not left to the fallback):\n{arm}"
        );
    }
}

#[cfg(test)]
mod runners {
    fn suffix() -> String {
        uuid::Uuid::new_v4().simple().to_string()[..12].to_owned()
    }

    macro_rules! dyn_runners {
        ($modname:ident, $fresh:expr) => {
            mod $modname {
                use super::suffix;
                use crate::federation::FederationDirectory;
                macro_rules! case {
                    ($name:ident) => {
                        #[tokio::test]
                        async fn $name() {
                            let Some(d) = $fresh.await else { return };
                            super::super::bodies::$name(&d as &dyn FederationDirectory, &suffix())
                                .await
                        }
                    };
                }
                case!(i410_self_reaches_the_owners_nodes);
                case!(i411_family_reaches_its_audience_only);
                case!(i412_a_denied_node_gets_nothing);
                case!(i413_i414_small_audience_boundary);
                case!(i417_i418_holdings_stay_in_the_cohort);
                case!(i415_the_deficit_is_the_audience_without_a_live_here);
                case!(i416_an_expired_here_is_missing);
            }
        };
    }

    dyn_runners!(memory, async {
        Some(crate::store::memory::MemoryBackend::new())
    });

    #[cfg(feature = "sqlite")]
    dyn_runners!(sqlite, async {
        use crate::store::Backend as _;
        let b = crate::store::sqlite::SqliteBackend::open_in_memory()
            .await
            .unwrap();
        b.run_migrations().await.unwrap();
        Some(b)
    });

    #[cfg(feature = "postgres")]
    dyn_runners!(postgres, async {
        use crate::store::Backend as _;
        let dsn = crate::test_pg::empty_dsn()?;
        let b = crate::store::postgres::PostgresBackend::connect(&dsn)
            .await
            .unwrap();
        b.run_migrations().await.unwrap();
        Some(b)
    });
}
