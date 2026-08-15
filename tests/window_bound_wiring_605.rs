//! CIRISPersist#605 — **the validator is WIRED, not merely present.**
//!
//! `AttestationFilter::validate` has unit tests beside it, and they all passed
//! with the engine's `filter.validate()?` call DELETED. That is the gap this
//! file exists to close: a validator that is correct and unreachable is a
//! validator that does nothing, and its own unit tests cannot tell you which
//! one you have.
//!
//! So this drives the PUBLIC entry point — `Engine::list_attestations` — and
//! asserts the refusal comes back out of it. Deleting the call at the engine
//! makes this file red; deleting the validator makes it red; changing the
//! validator's rule without changing the engine makes it red. Nothing else in
//! the suite has that property.
//!
//! It lives in `tests/` deliberately: that compiles as a separate crate, so it
//! can only reach what a real consumer can reach.

#![cfg(feature = "sqlite")]

use std::sync::Arc;

use chrono::{DateTime, Utc};
use ciris_persist::ceg::{AttestationFilter, OPEN_ENDED_WINDOW_END};
use ciris_persist::scope::CallerScope;
use ciris_persist::signing::LocalSigner;
use ciris_persist::Engine;
use ed25519_dalek::SigningKey;

async fn engine() -> Engine {
    let signer = Arc::new(LocalSigner::from_parts(
        SigningKey::from_bytes(&[0x11; 32]),
        "test-605-wiring".into(),
        None,
        None,
    ));
    Engine::with_signer(signer, "sqlite::memory:")
        .await
        .expect("construct engine")
}

// `AttestationFilter` is `#[non_exhaustive]`, so an EXTERNAL crate — which
// this test is, deliberately — cannot use struct-expression syntax at all
// (E0639). Default-then-assign is the only shape available to a real consumer,
// which makes clippy's `field_reassign_with_default` unactionable here rather
// than merely inconvenient. Allowed with the reason, not silenced globally.
#[allow(clippy::field_reassign_with_default)]
fn filter_with_window(start: DateTime<Utc>, end: DateTime<Utc>) -> AttestationFilter {
    let mut f = AttestationFilter::default();
    f.window = Some((start, end));
    f
}

/// The whole point: `MAX_UTC` reaches the ENGINE and is refused there, instead
/// of reaching the query and silently selecting zero rows.
#[tokio::test]
async fn engine_refuses_a_max_utc_window_bound_605() {
    let eng = engine().await;
    let start: DateTime<Utc> = "2026-01-01T00:00:00Z".parse().unwrap();

    let err = eng
        .list_attestations(
            filter_with_window(start, DateTime::<Utc>::MAX_UTC),
            None,
            50,
            CallerScope::Unauthenticated,
        )
        .await
        .expect_err(
            "MAX_UTC must be REFUSED at the engine. If this returned Ok, the \
             validator is no longer wired in and an open-ended window silently \
             selects nothing — the exact failure #605 reports.",
        );

    let msg = format!("{err}");
    assert!(
        msg.contains(OPEN_ENDED_WINDOW_END),
        "the refusal must name the supported sentinel so the caller's next step \
         is in the error: {msg}"
    );
}

/// The supported sentinel goes THROUGH the engine and returns a page. Without
/// this leg, a validator that refused everything would also pass the test
/// above — "refuses the bad case" and "permits the good case" are two claims.
#[tokio::test]
async fn engine_accepts_the_supported_open_ended_sentinel_605() {
    let eng = engine().await;
    let start: DateTime<Utc> = "2026-01-01T00:00:00Z".parse().unwrap();
    let end: DateTime<Utc> = OPEN_ENDED_WINDOW_END.parse().unwrap();

    let page = eng
        .list_attestations(
            filter_with_window(start, end),
            None,
            50,
            CallerScope::Unauthenticated,
        )
        .await
        .expect("the documented open-ended sentinel must be accepted");

    // What matters is that the call was ALLOWED to reach the query at all.
    //
    // Deliberately NOT asserting the page is empty: a fresh engine carries
    // genesis-baked rows, and an earlier draft of this test asserted emptiness
    // and went red — correctly. That near-miss is worth keeping in view,
    // because "empty page" is exactly the #605 symptom, and a test that
    // DEMANDS emptiness here would have gone green on the very bug it is
    // guarding, for the wrong reason.
    let _ = page.items.len();
}
