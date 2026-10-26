//! v60.1.0 (docs/V61_TASK_PLAN.md §2 slice B) — **the consumer asks**, each
//! witnessed on every backend through the doors a consumer calls.
//!
//! - **I1360 (CIRISPersist#1117; CC 4.2.6 / CC 4.5.1.2)** — the accord
//!   threshold is ONE function: `accord_threshold(n) = ⌊n/2⌋ + 1`, and the
//!   threshold this node reports over its standing roster is the one its
//!   co-scrub gate counts against. Two holder signatures confer over a roster
//!   of three (the reported `m` is 2) and do not over a roster of four (the
//!   reported `m` is 3); a roster id this node holds no key for counts toward
//!   neither.

#[cfg(all(test, any(feature = "sqlite", feature = "postgres")))]
pub(crate) mod bodies {
    use crate::federation::admission::{
        accord_threshold, accord_threshold_over_roster, has_accord_conferred_role_over_roster,
        AccordThreshold,
    };
    use crate::federation::operational::test_support::{
        confer_roles, register_accord_holder, Identity,
    };
    use crate::federation::FederationDirectory;

    /// **I1360** — see the module doc.
    pub(crate) async fn i1360_accord_threshold_is_the_gates_threshold(
        d: &dyn FederationDirectory,
        tag: &str,
    ) {
        // The rule, by value: a strict majority, and an empty roster is
        // unreachable.
        for (n, m) in [
            (0, 1),
            (1, 1),
            (2, 2),
            (3, 2),
            (4, 3),
            (5, 3),
            (6, 4),
            (7, 4),
        ] {
            assert_eq!(accord_threshold(n), m, "I1360: accord_threshold({n})");
            assert!(2 * accord_threshold(n) > n, "I1360: strict majority of {n}");
        }

        // Three holders registered; a key co-scrubbed by two of them.
        let subject = format!("i1360-subject-{tag}");
        let roster = confer_roles(d, &subject, &["infra:serve"], &format!("i1360-{tag}"))
            .await
            .expect("I1360: the two-holder co-scrub stores");
        assert_eq!(roster.len(), 3);
        assert_eq!(
            accord_threshold_over_roster(d, &roster).await.unwrap(),
            AccordThreshold { m: 2, n: 3 },
            "I1360: three holders held here, two required"
        );
        assert!(
            has_accord_conferred_role_over_roster(d, &subject, "infra:serve", &roster)
                .await
                .unwrap(),
            "I1360: two of three meets the reported m = 2"
        );

        // A roster id this node holds no key for counts toward neither side.
        let mut with_unheld = roster.clone();
        with_unheld.push(format!("i1360-unheld-{tag}"));
        assert_eq!(
            accord_threshold_over_roster(d, &with_unheld).await.unwrap(),
            AccordThreshold { m: 2, n: 3 },
            "I1360: an unheld holder is not on the standing roster"
        );
        assert!(
            has_accord_conferred_role_over_roster(d, &subject, "infra:serve", &with_unheld)
                .await
                .unwrap(),
            "I1360: the gate counts the same standing roster"
        );

        // A fourth holder registered: the reported m moves to 3, and the same
        // two signatures no longer confer.
        let fourth = Identity::new(&format!("i1360-{tag}-h3"));
        register_accord_holder(d, &fourth).await.unwrap();
        let mut four = roster.clone();
        four.push(fourth.key_id.clone());
        assert_eq!(
            accord_threshold_over_roster(d, &four).await.unwrap(),
            AccordThreshold { m: 3, n: 4 },
            "I1360: four holders, three required"
        );
        assert!(
            !has_accord_conferred_role_over_roster(d, &subject, "infra:serve", &four)
                .await
                .unwrap(),
            "I1360: two of four is below the reported m = 3, and the gate agrees"
        );
    }
}

#[cfg(all(test, any(feature = "sqlite", feature = "postgres")))]
mod tests {
    use super::bodies;

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
                    $body(&b, &tag("s")).await;
                }

                #[cfg(feature = "postgres")]
                #[tokio::test(flavor = "multi_thread")]
                async fn postgres() {
                    use crate::store::Backend as _;
                    let Some(dsn) = crate::test_pg::empty_dsn() else {
                        eprintln!("v601 postgres: no CIRIS_PERSIST_TEST_PG base DSN — SKIPPED");
                        return;
                    };
                    let b = crate::store::postgres::PostgresBackend::connect(&dsn)
                        .await
                        .unwrap();
                    b.run_migrations().await.unwrap();
                    $body(&b, &tag("p")).await;
                    eprintln!("{}: RAN", stringify!($name));
                }
            }
        };
    }

    on_every_backend!(i1360, bodies::i1360_accord_threshold_is_the_gates_threshold);
}
