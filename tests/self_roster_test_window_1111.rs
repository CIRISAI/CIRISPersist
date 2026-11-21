//! v60.0.0 (CIRISPersist#1111, CIRISServer#794 T11) — **I1162: the test
//! harness's `W_self`, end to end.**
//!
//! A `test-anchor` harness binary cannot wait `W_SELF_SECS` (86 400 s) to see
//! the self roster's lone path land. With the test-anchor override LIVE,
//! `CIRIS_TEST_W_SELF_SECS` replaces the window; without the override the
//! variable is inert. Both halves run here on sqlite and postgres, on the
//! node's real clock (the purge clock's seam is `cfg(test)`-only, so an
//! integration target cannot move it, exactly like the harness).
//!
//! The override is armed by mutating the process environment, which is why
//! this is its own integration target (its own process under both runners,
//! #738) and every test in it is serial.
//!
//! v62.0.0 (BH-fix3) — ported to edition 2: the self's keys are edition-2
//! `key:record`s and each addition is an `identity:occurrence` bind through
//! the statement door (`edition2::fixture_occurrence::put_bind`). At one key
//! the bind lands (`Row`); at two it is a proposal (`Pending`), landed by the
//! lone path (`self_roster::execute_for`) once the window has passed.

#![cfg(all(feature = "test-anchor", feature = "sqlite"))]

use base64::engine::general_purpose::STANDARD as B64;
use base64::Engine as _;
use ciris_persist::federation::edition2::fixture_occurrence::{put_bind, BindOptions};
use ciris_persist::federation::edition2::fixture_switch as e2;
use ciris_persist::federation::edition2::ingest::StatementOutcome;
use ciris_persist::federation::self_roster as sr;
use ciris_persist::federation::FederationDirectory;
use ciris_persist::store::backend::Backend as _;

/// The window this target asks for, in seconds.
const SHORT: u64 = 2;

/// The override, armed for the guard's lifetime (the #738 RAII shape).
struct Armed;

impl Armed {
    fn arm() -> Self {
        let ed = ed25519_dalek::SigningKey::from_bytes(&[0x5Au8; 32]);
        std::env::set_var("CIRIS_TESTING_MODE", "true");
        std::env::set_var(
            "CIRIS_TEST_TRUST_ROOT",
            B64.encode(ed.verifying_key().to_bytes()),
        );
        std::env::remove_var("ENVIRONMENT");
        std::env::remove_var("CIRIS_ENV");
        std::env::remove_var("CIRIS_ENVIRONMENT");
        Self
    }
}

impl Drop for Armed {
    fn drop(&mut self) {
        std::env::remove_var("CIRIS_TESTING_MODE");
        std::env::remove_var("CIRIS_TEST_TRUST_ROOT");
    }
}

/// The window variable, set before any read of it (it is read once per
/// process, and both halves set the same value).
fn short_window() {
    std::env::set_var(sr::test_window::ENV, SHORT.to_string());
}

/// Is `device` an active occurrence of `f`?
async fn active(d: &dyn FederationDirectory, f: &str, device: &str) -> bool {
    d.list_identity_occurrences_active(f)
        .await
        .expect("active")
        .iter()
        .any(|o| o.occurrence_key_id == device)
}

/// A two-key self `{f, d1}` whose genesis key proposes a third key: held as
/// a proposal. Then the window passes on the node's clock with no answer,
/// and the sweep runs. Returns whether the third key landed.
async fn lone_add_after_the_short_window(d: &dyn FederationDirectory, tag: &str) -> bool {
    let (f, d1, d2) = (format!("f-{tag}"), format!("d1-{tag}"), format!("d2-{tag}"));
    for k in [&f, &d1, &d2] {
        e2::put_key(d, k, &["user"]).await;
    }
    let fk = e2::kid(&f);
    let opts = BindOptions {
        asserted_at_ms: ciris_persist::federation::edition2::composite_verify::now_ms() - 60_000,
        ..BindOptions::default()
    };
    match put_bind(d, &f, &f, &d1, "laptop", &opts).await {
        Ok(StatementOutcome::Row { .. }) => {}
        other => panic!("I1162: at one key the addition lands at once, got {other:?}"),
    }
    match put_bind(d, &f, &f, &d2, "laptop", &opts).await {
        Ok(StatementOutcome::Pending { .. }) => {}
        other => panic!("I1162: at two keys the addition is a proposal, got {other:?}"),
    }
    assert!(
        !active(d, &fk, &e2::kid(&d2)).await,
        "I1162: not before the window"
    );
    tokio::time::sleep(std::time::Duration::from_secs(SHORT + 1)).await;
    sr::execute_for(d, &fk).await.expect("execute");
    active(d, &fk, &e2::kid(&d2)).await
}

fn tag(n: &str) -> String {
    format!("{n}{}", &uuid::Uuid::new_v4().simple().to_string()[..8])
}

async fn sqlite() -> ciris_persist::store::sqlite::SqliteBackend {
    let b = ciris_persist::store::sqlite::SqliteBackend::open_in_memory()
        .await
        .unwrap();
    b.run_migrations().await.unwrap();
    b
}

/// **I1162 (armed, sqlite)** — the lone path lands after the short window.
#[serial_test::serial(test_anchor_env)]
#[tokio::test(flavor = "multi_thread")]
async fn i1162_armed_lone_path_lands_after_the_short_window_sqlite() {
    short_window();
    let _armed = Armed::arm();
    assert_eq!(sr::w_self_secs(), SHORT as i64, "I1162: the armed window");
    let b = sqlite().await;
    assert!(
        lone_add_after_the_short_window(&b, &tag("s")).await,
        "I1162: armed, the unanswered addition landed by the lone path"
    );
}

/// **I1162 (unarmed, sqlite)** — the variable alone moves nothing.
#[serial_test::serial(test_anchor_env)]
#[tokio::test(flavor = "multi_thread")]
async fn i1162_unarmed_the_env_is_inert_sqlite() {
    short_window();
    assert_eq!(sr::w_self_secs(), sr::W_SELF_SECS, "I1162: no override");
    let b = sqlite().await;
    assert!(
        !lone_add_after_the_short_window(&b, &tag("s")).await,
        "I1162: without the override the window is still W_SELF_SECS"
    );
}

#[cfg(feature = "postgres")]
async fn postgres() -> Option<ciris_persist::store::postgres::PostgresBackend> {
    let Ok(dsn) = std::env::var("CIRIS_PERSIST_TEST_PG_URL") else {
        eprintln!("I1162 postgres: CIRIS_PERSIST_TEST_PG_URL unset — SKIPPED");
        return None;
    };
    let b = ciris_persist::store::postgres::PostgresBackend::connect(&dsn)
        .await
        .unwrap();
    b.run_migrations().await.unwrap();
    Some(b)
}

/// **I1162 (armed, postgres)**.
#[cfg(feature = "postgres")]
#[serial_test::serial(test_anchor_env)]
#[tokio::test(flavor = "multi_thread")]
async fn i1162_armed_lone_path_lands_after_the_short_window_postgres() {
    short_window();
    let _armed = Armed::arm();
    let Some(b) = postgres().await else { return };
    assert!(
        lone_add_after_the_short_window(&b, &tag("p")).await,
        "I1162: armed, the unanswered addition landed by the lone path"
    );
    eprintln!("i1162 armed postgres: RAN");
}

/// **I1162 (unarmed, postgres)**.
#[cfg(feature = "postgres")]
#[serial_test::serial(test_anchor_env)]
#[tokio::test(flavor = "multi_thread")]
async fn i1162_unarmed_the_env_is_inert_postgres() {
    short_window();
    let Some(b) = postgres().await else { return };
    assert!(
        !lone_add_after_the_short_window(&b, &tag("p")).await,
        "I1162: without the override the window is still W_SELF_SECS"
    );
    eprintln!("i1162 unarmed postgres: RAN");
}
