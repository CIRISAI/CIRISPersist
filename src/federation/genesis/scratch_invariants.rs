//! v60.0.0 (CIRISPersist#1002) — the genesis scratch, witnessed in the lib so
//! the mutation tier (which builds `--lib`) reaches it. The door-by-door
//! parity witnesses over minted ceremonies are `tests/genesis_scratch_parity.rs`
//! (I1324–I1328).
//!
//! - **I1329** — `verify_ceremony_outputs` over the compiled production bundle
//!   (no anchor armed) admits it and refuses a tampered copy on each backend's
//!   scratch; on postgres no scratch database of this process survives.
//! - **I1330** — a scratch that cannot be provisioned, or cannot be released,
//!   is refused as `ceremony_scratch_directory`, never admitted.
//! - **I1331** — the postgres scratch is dropped when released and when
//!   dropped unreleased; `dsn_with_dbname` keeps the DSN's own form.

use super::scratch::GenesisScratch;
use super::{verify_ceremony_outputs, CeremonyOutputsRefusal};
#[cfg(feature = "sqlite")]
use {
    super::scratch::ScratchDirectory,
    crate::federation::{Error, SignedKeyRecord},
};

fn canonical_json() -> &'static str {
    include_str!("canonical_seed.json")
}

/// The production bundle with one carried byte changed: its authorizations
/// no longer cover it.
fn tampered() -> String {
    let mut b = super::parse_genesis_bundle(canonical_json()).expect("the compiled bundle");
    b.produced_at = chrono::Utc::now().to_rfc3339();
    serde_json::to_string(&b).unwrap()
}

async fn admits_and_refuses(scratch: &dyn GenesisScratch, tag: &str) {
    verify_ceremony_outputs(canonical_json(), scratch)
        .await
        .unwrap_or_else(|e| panic!("{tag} I1329: the compiled bundle verifies: {e}"));
    let e = verify_ceremony_outputs(&tampered(), scratch)
        .await
        .expect_err("I1329: a tampered bundle is refused");
    assert!(
        !matches!(
            e.reason,
            CeremonyOutputsRefusal::ScratchDirectory | CeremonyOutputsRefusal::Malformed
        ),
        "{tag} I1329: refused by the replay on the scratch, not before it: {e}"
    );
}

/// A provider whose scratch fails as told.
#[cfg(feature = "sqlite")]
struct Failing {
    provision: bool,
}

#[cfg(feature = "sqlite")]
#[async_trait::async_trait]
impl GenesisScratch for Failing {
    async fn provision_genesis_scratch(
        &self,
        holders: &[SignedKeyRecord],
    ) -> Result<ScratchDirectory, Error> {
        if self.provision {
            return Err(Error::Backend("no scratch for you".into()));
        }
        let b = crate::store::test_backend::test_backend();
        b.seed_genesis_accord_holders(holders).await?;
        Ok(ScratchDirectory::new(Box::new(b), || {
            Box::pin(async { Err(Error::Backend("the scratch would not go".into())) })
        }))
    }
}

#[cfg(feature = "sqlite")]
#[tokio::test]
async fn i1329_the_compiled_bundle_on_the_sqlite_scratch() {
    admits_and_refuses(&crate::store::test_backend::test_backend(), "sqlite").await;
}

#[cfg(feature = "sqlite")]
#[tokio::test]
async fn i1330_a_scratch_that_fails_is_a_refusal() {
    for (provision, what) in [(true, "provision"), (false, "release")] {
        let e = verify_ceremony_outputs(canonical_json(), &Failing { provision })
            .await
            .expect_err("I1330: a failing scratch admits nothing");
        assert_eq!(
            e.reason,
            CeremonyOutputsRefusal::ScratchDirectory,
            "{what}: {e}"
        );
        assert_eq!(e.reason.as_str(), "ceremony_scratch_directory");
        assert!(e.detail.starts_with(what), "{what}: {e}");
    }
    // A bundle the replay refuses is that refusal, even when the release
    // then fails too.
    let e = verify_ceremony_outputs(&tampered(), &Failing { provision: false })
        .await
        .expect_err("refused");
    assert_ne!(e.reason, CeremonyOutputsRefusal::ScratchDirectory, "{e}");
}

#[cfg(feature = "postgres")]
mod postgres {
    use super::*;
    use crate::store::postgres::{dsn_with_dbname, PostgresBackend, GENESIS_SCRATCH_DB_PREFIX};

    async fn my_scratches(dsn: &str) -> i64 {
        let (admin, conn) = tokio_postgres::connect(dsn, tokio_postgres::NoTls)
            .await
            .expect("admin connect");
        tokio::spawn(conn);
        admin
            .query_one(
                "SELECT count(*) FROM pg_database WHERE datname LIKE $1",
                &[&format!(
                    "{GENESIS_SCRATCH_DB_PREFIX}{}_%",
                    std::process::id()
                )],
            )
            .await
            .unwrap()
            .get(0)
    }

    #[tokio::test(flavor = "multi_thread")]
    #[serial_test::serial(genesis_scratch)]
    async fn i1329_the_compiled_bundle_on_the_postgres_scratch() {
        let Some(dsn) = crate::test_pg::dsn() else {
            eprintln!("skipping: CIRIS_PERSIST_TEST_PG_URL unset");
            return;
        };
        let provider = PostgresBackend::connect(&dsn).await.unwrap();
        admits_and_refuses(&provider, "postgres").await;
        assert_eq!(my_scratches(&dsn).await, 0, "I1329: no scratch survives");
    }

    #[tokio::test(flavor = "multi_thread")]
    #[serial_test::serial(genesis_scratch)]
    async fn i1331_the_postgres_scratch_is_dropped_released_or_not() {
        let Some(dsn) = crate::test_pg::dsn() else {
            eprintln!("skipping: CIRIS_PERSIST_TEST_PG_URL unset");
            return;
        };
        let provider = PostgresBackend::connect(&dsn).await.unwrap();
        let holders = super::super::effective_accord_holder_records();
        let s = provider.provision_genesis_scratch(&holders).await.unwrap();
        assert_eq!(my_scratches(&dsn).await, 1, "I1331: provisioned");
        assert!(
            s.directory()
                .lookup_public_key(&holders[0].record.key_id)
                .await
                .unwrap()
                .is_some(),
            "I1331: the scratch holds the holders"
        );
        s.release().await.unwrap();
        assert_eq!(my_scratches(&dsn).await, 0, "I1331: released");
        let s = provider.provision_genesis_scratch(&holders).await.unwrap();
        assert_eq!(my_scratches(&dsn).await, 1);
        drop(s);
        assert_eq!(my_scratches(&dsn).await, 0, "I1331: dropped unreleased");
    }

    #[test]
    fn i1331_dsn_with_dbname_keeps_the_form() {
        for (dsn, want) in [
            ("postgres://u:p@h:5432/live", "postgres://u:p@h:5432/s_1"),
            (
                "postgresql://h/live?sslmode=require",
                "postgresql://h/s_1?sslmode=require",
            ),
            ("postgres://h:1", "postgres://h:1/s_1"),
            ("host=h user=u dbname=live", "host=h user=u dbname=s_1"),
            ("host=h user=u", "host=h user=u dbname=s_1"),
        ] {
            assert_eq!(dsn_with_dbname(dsn, "s_1").unwrap(), want, "{dsn}");
        }
        for bad in ["", "S1", "a-b", "a;drop", "x\"y"] {
            assert!(
                dsn_with_dbname("postgres://h/live", bad).is_err(),
                "{bad:?}"
            );
        }
        assert!(
            dsn_with_dbname("postgres:///live", "s_1").is_err(),
            "no host"
        );
    }
}
