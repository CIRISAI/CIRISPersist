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
//! - **I1332** — the reaper: provisioning drops a scratch older than
//!   `GENESIS_SCRATCH_REAP_AFTER_SECS` by its embedded instant, never a fresh
//!   one or a name it cannot read.

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
                "SELECT count(*) FROM pg_database WHERE datname ~ $1",
                &[&format!(
                    "^{GENESIS_SCRATCH_DB_PREFIX}[0-9]+_{}_[0-9a-f]+$",
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

    /// **I1332** (lib) — the reap predicate: older than the reap age by its
    /// own embedded instant, with the prefix and a tail; anything it cannot
    /// read is never stale.
    #[test]
    fn i1332_the_reap_predicate() {
        use crate::store::postgres::{stale_genesis_scratch, GENESIS_SCRATCH_REAP_AFTER_SECS};
        let p = GENESIS_SCRATCH_DB_PREFIX;
        let now = 1_000_000u64;
        let at = |secs: u64| format!("{p}{secs}_42_abcdef012345");
        assert!(stale_genesis_scratch(
            &at(now - GENESIS_SCRATCH_REAP_AFTER_SECS - 1),
            now
        ));
        assert!(!stale_genesis_scratch(
            &at(now - GENESIS_SCRATCH_REAP_AFTER_SECS),
            now
        ));
        assert!(!stale_genesis_scratch(&at(now), now));
        assert!(
            !stale_genesis_scratch(&at(now + 10), now),
            "a future instant"
        );
        for unreadable in [
            p.to_owned(),
            format!("{p}12"),
            format!("{p}12_"),
            format!("{p}_42_ab"),
            format!("{p}x12_42_ab"),
            format!("{p}1a2_42_ab"),
            "ciris_t_12_42_ab".to_owned(),
            format!("other_{p}12_42_ab"),
        ] {
            assert!(
                !stale_genesis_scratch(&unreadable, now + 1_000_000),
                "{unreadable:?}"
            );
        }
    }

    /// **I1332** (lib, postgres) — a provisioning drops the stale scratch and
    /// keeps a fresh one and an unreadable name.
    #[tokio::test(flavor = "multi_thread")]
    #[serial_test::serial(genesis_scratch)]
    async fn i1332_provisioning_reaps_only_the_stale() {
        use crate::store::postgres::GENESIS_SCRATCH_REAP_AFTER_SECS;
        let Some(dsn) = crate::test_pg::dsn() else {
            eprintln!("skipping: CIRIS_PERSIST_TEST_PG_URL unset");
            return;
        };
        let now = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_secs();
        let pid = std::process::id();
        let p = GENESIS_SCRATCH_DB_PREFIX;
        let stale = format!(
            "{p}{}_{pid}_dddddddddddd",
            now - 2 * GENESIS_SCRATCH_REAP_AFTER_SECS
        );
        let fresh = format!("{p}{now}_{pid}_eeeeeeeeeeee");
        let unreadable = format!("{p}y{pid}_ffff");
        let (admin, conn) = tokio_postgres::connect(&dsn, tokio_postgres::NoTls)
            .await
            .unwrap();
        tokio::spawn(conn);
        for n in [&stale, &fresh, &unreadable] {
            admin
                .batch_execute(&format!("CREATE DATABASE \"{n}\""))
                .await
                .unwrap();
        }
        let provider = PostgresBackend::connect(&dsn).await.unwrap();
        provider
            .provision_genesis_scratch(&super::super::effective_accord_holder_records())
            .await
            .unwrap()
            .release()
            .await
            .unwrap();
        let mut held = Vec::new();
        for n in [&stale, &fresh, &unreadable] {
            let c: i64 = admin
                .query_one("SELECT count(*) FROM pg_database WHERE datname = $1", &[n])
                .await
                .unwrap()
                .get(0);
            held.push(c == 1);
            let _ = admin
                .batch_execute(&format!("DROP DATABASE IF EXISTS \"{n}\" WITH (FORCE)"))
                .await;
        }
        assert_eq!(
            held,
            [false, true, true],
            "I1332: stale reaped; fresh and unreadable kept"
        );
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
