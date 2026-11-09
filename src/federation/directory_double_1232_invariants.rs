//! v61.1.0 (CIRISPersist#1232) — **I1650–I1651: the fault-injecting double
//! reaches the backend's `list_attestations_naming_by_dimension`**, on every
//! backend.
//!
//! 61.0.5 (#1225) added the read as a defaulted-`Unsupported` leaf that
//! every backend overrides, but left it out of `DELEGATED_DEFAULTS` in
//! `scripts/gen_directory_double.py`. A defaulted method the generator does
//! not list is silently INHERITED by the double, so
//! [`FaultInjectingDirectory`] answered `Unsupported` with no fault declared:
//! a consumer wrapping a real backend could not read the invitee's rows.
//!
//! - **I1650** with no fault declared, every page the double serves is the
//!   page the inner backend serves for the same arguments (rows, order and
//!   `next_cursor`), walking with a cursor and a small page so the subject,
//!   dimension, cursor and limit each have to reach the backend; and the
//!   backend's refusal of a bad page bound comes back as the backend's.
//! - **I1651** the double's own fault arm still runs first: `.unsupported`
//!   answers `Unsupported` naming the method, `.erroring` answers a backend
//!   failure, and neither is the page.

#[cfg(all(test, any(feature = "sqlite", feature = "postgres")))]
pub(crate) mod bodies {
    use crate::ceg::list::federation::AttestationCursor;
    use crate::federation::directory_double::FaultInjectingDirectory;
    use crate::federation::subject_read_1225_invariants::bodies as s1225;
    use crate::federation::{Error, FederationDirectory};
    use std::sync::Arc;

    const METHOD: &str = "list_attestations_naming_by_dimension";

    /// Five rows naming K under the 1225 dimension, and one under another
    /// key, so a double that dropped the subject would see a sixth.
    async fn seed(d: &dyn FederationDirectory, tag: &str) -> String {
        let (a, k) = s1225::keys(d, tag).await;
        let other = format!("i1650-other-{tag}");
        for s in [50, 40, 30, 20, 10] {
            s1225::put_naming(d, &a, &[&k], s1225::DIM, s1225::at(s), None).await;
        }
        s1225::put_naming(d, &a, &[&other], s1225::DIM, s1225::at(5), None).await;
        k
    }

    /// **I1650** — un-faulted, the double serves the backend's page.
    pub(crate) async fn i1650_double_serves_the_backends_page(
        d: Arc<dyn FederationDirectory>,
        tag: &str,
    ) {
        let k = seed(&*d, tag).await;
        let dbl = FaultInjectingDirectory::new(d.clone());
        assert!(dbl.faults().is_empty() && dbl.error_faults().is_empty());

        // Page by page, at two per page: the same cursor goes to both, so a
        // double that dropped the cursor or the limit diverges on page one
        // or two, and one that answered `Unsupported` fails the first read.
        let mut cursor: Option<AttestationCursor> = None;
        let mut pages = 0usize;
        let mut rows = 0usize;
        loop {
            let want = d
                .list_attestations_naming_by_dimension(&k, s1225::DIM, cursor.clone(), 2)
                .await
                .expect("I1650 the backend serves the read");
            let got = dbl
                .list_attestations_naming_by_dimension(&k, s1225::DIM, cursor.clone(), 2)
                .await
                .unwrap_or_else(|e| {
                    panic!("I1650 {tag}: the double reaches the backend, not {e:?}")
                });
            assert_eq!(
                got, want,
                "I1650 {tag}: page {pages} through the double is the backend's page"
            );
            assert!(
                got.items.iter().all(|r| r.subject_key_ids.contains(&k)),
                "I1650 {tag}: every row names K"
            );
            pages += 1;
            rows += got.items.len();
            match got.next_cursor {
                Some(c) => {
                    assert!(pages < 10, "I1650 {tag}: the walk does not end");
                    cursor = Some(c);
                }
                None => break,
            }
        }
        assert_eq!(
            (pages, rows),
            (3, 5),
            "I1650 {tag}: K's five rows, two per page, through the double"
        );

        // The dimension reaches the backend: K under another dimension is
        // the backend's (empty) answer, not the 1225 dimension's page.
        let elsewhere = dbl
            .list_attestations_naming_by_dimension(&k, "i1650:elsewhere:v1", None, 100)
            .await
            .expect("I1650 served");
        assert!(
            elsewhere.items.is_empty() && elsewhere.next_cursor.is_none(),
            "I1650 {tag}: another dimension is not DIM"
        );

        // The backend's own refusal of the page bound comes back through the
        // double — the backend's, so it is not `Unsupported`.
        for bad in [0, 10_001] {
            match dbl
                .list_attestations_naming_by_dimension(&k, s1225::DIM, None, bad)
                .await
            {
                Err(Error::Unsupported { method }) => {
                    panic!(
                        "I1650 {tag}: limit {bad} reached the default ({method}), not the backend"
                    )
                }
                Err(_) => {}
                Ok(p) => panic!(
                    "I1650 {tag}: limit {bad} is refused, got {} rows",
                    p.items.len()
                ),
            }
        }
    }

    /// **I1651** — a declared fault still answers first.
    pub(crate) async fn i1651_declared_faults_answer_first(
        d: Arc<dyn FederationDirectory>,
        tag: &str,
    ) {
        let k = seed(&*d, tag).await;
        let unsupported = FaultInjectingDirectory::new(d.clone()).unsupported(METHOD);
        match unsupported
            .list_attestations_naming_by_dimension(&k, s1225::DIM, None, 100)
            .await
        {
            Err(Error::Unsupported { method }) => assert_eq!(method, METHOD, "I1651 {tag}"),
            other => panic!("I1651 {tag}: a declared Unsupported answers it, got {other:?}"),
        }
        let erroring = FaultInjectingDirectory::new(d.clone()).erroring(METHOD);
        match erroring
            .list_attestations_naming_by_dimension(&k, s1225::DIM, None, 100)
            .await
        {
            Err(Error::Backend(m)) => assert!(m.contains(METHOD), "I1651 {tag}: {m}"),
            other => panic!("I1651 {tag}: a declared backend failure answers it, got {other:?}"),
        }
        // A fault on a NEIGHBOURING method does not touch this one.
        let neighbour = FaultInjectingDirectory::new(d.clone())
            .unsupported("list_attestations_citing_by_dimension");
        let page = neighbour
            .list_attestations_naming_by_dimension(&k, s1225::DIM, None, 100)
            .await
            .expect("I1651 an unrelated fault leaves the read served");
        assert_eq!(page.items.len(), 5, "I1651 {tag}");
    }
}

#[cfg(all(test, any(feature = "sqlite", feature = "postgres")))]
mod tests {
    use super::bodies;
    use crate::federation::FederationDirectory;
    use std::sync::Arc;

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
                    let d: Arc<dyn FederationDirectory> = Arc::new(b);
                    $body(d, &tag("s")).await;
                }

                #[cfg(feature = "postgres")]
                #[tokio::test(flavor = "multi_thread")]
                async fn postgres() {
                    use crate::store::Backend as _;
                    let Some(dsn) = crate::test_pg::empty_dsn() else {
                        eprintln!("1232 postgres: no CIRIS_PERSIST_TEST_PG base DSN — SKIPPED");
                        return;
                    };
                    let b = crate::store::postgres::PostgresBackend::connect(&dsn)
                        .await
                        .unwrap();
                    b.run_migrations().await.unwrap();
                    let d: Arc<dyn FederationDirectory> = Arc::new(b);
                    $body(d, &tag("p")).await;
                    eprintln!("{}: RAN", stringify!($name));
                }
            }
        };
    }

    on_every_backend!(i1650, bodies::i1650_double_serves_the_backends_page);
    on_every_backend!(i1651, bodies::i1651_declared_faults_answer_first);
}
