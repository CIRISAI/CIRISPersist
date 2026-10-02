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
//! I415 / I416 (the deficit read) sit on the custody fold and are witnessed
//! with it.

#[cfg(test)]
pub(crate) mod bodies {
    use crate::federation::durability::{
        content_audience, durability_mode, ContentAudience, DurabilityMode,
        DEFAULT_FEASIBILITY_FLOOR,
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
