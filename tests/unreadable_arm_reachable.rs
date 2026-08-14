//! v31.4.0 (CIRISPersist#603/#604) — **the `unreadable` arm, driven from
//! outside the crate for the first time.**
//!
//! `resolve_mesh_config` folds per-root reads and carries `unreadable_roots`, so
//! *"this backend cannot answer for root R"* stays distinct from *"root R said
//! nothing"*. Until now **no test in this repo could reach that arm**: all three
//! shipped backends implement every method, so none can return
//! `Error::Unsupported`. The only party exercising it was CIRISServer, through
//! their own directory impl — which is how the original defect was found.
//!
//! #604 recorded the shape across five workstreams in one week:
//!
//! ```text
//! Ok(value)  -> a real answer
//! Ok(empty)  -> a real answer that happens to be empty
//! Err(_)     -> WE COULD NOT ASK
//! ```
//!
//! Collapsing the third arm into the second is how a zero becomes evidence it
//! has not earned. **A zero is not evidence unless the instrument can fail.**
//! `FaultInjectingDirectory` is the instrument that can fail.
//!
//! This is an integration test on purpose — `tests/` is a separate crate, so it
//! proves the double is reachable by CIRISServer/Edge/Agent and not merely by
//! persist's own unit tests (the #664 lesson, one module over).

#![cfg(all(feature = "test-anchor", feature = "sqlite"))]

use ciris_persist::federation::directory_double::FaultInjectingDirectory;
use ciris_persist::federation::mesh_config::{resolve_mesh_config, MeshConfigBaseline};
use ciris_persist::store::{Backend as _, SqliteBackend};
use std::sync::Arc;

async fn backend() -> Arc<SqliteBackend> {
    let b = SqliteBackend::open_in_memory().await.expect("open");
    b.run_migrations().await.expect("migrations");
    Arc::new(b)
}

/// **A silent root and an unreadable root are different answers.**
///
/// The same node, the same baseline, the same instant — the only difference is
/// whether the directory can answer. A fold that reports the same thing for both
/// is the defect #603 exists to make testable.
#[tokio::test]
async fn an_unreadable_root_is_not_a_silent_root_603() {
    let inner = backend().await;
    let now = chrono::Utc::now();
    let baseline = MeshConfigBaseline::owner_defaults();

    // `resolve_mesh_config` reads per TRUSTED ROOT, so a node with no roots
    // iterates nothing and can never be unreadable — the fault would fire into
    // an empty loop and the test would pass for the wrong reason. Establish a
    // real root first, so the read the fault interrupts is a read that would
    // otherwise have happened.
    const NODE: &str = "node-603";
    const ROOT: &str = "root-603";
    // NOTE: only the NODE is pre-registered. `establish_trust_root` registers the
    // ROOT itself, and pre-registering it collides — `Conflict("key_id root-603
    // already exists with different content")`.
    ciris_persist::federation::tier_ingest::test_support::register_hybrid_key(&*inner, NODE).await;
    ciris_persist::federation::operational::test_support::establish_trust_root(
        &*inner,
        NODE,
        ROOT,
        NODE,
        "infra:serve",
    )
    .await
    .expect("establish a trust root so there is something to read");

    let roots = ciris_persist::federation::trust_root::trusted_roots_of(&*inner, NODE, now)
        .await
        .expect("roots resolve");
    assert!(
        !roots.is_empty(),
        "precondition: the node must HAVE a trusted root, or the fault fires \
         into an empty loop and this test passes for the wrong reason"
    );

    // A directory that answers normally. Nothing is unreadable.
    let readable = FaultInjectingDirectory::new(inner.clone());
    let fold_ok = resolve_mesh_config(&readable, NODE, &baseline, now)
        .await
        .expect("a readable directory resolves");
    assert!(
        fold_ok.unreadable_roots.is_empty(),
        "nothing was faulted, so nothing may be reported unreadable — got {:?}",
        fold_ok.unreadable_roots
    );

    // The SAME directory, with the per-root read declared unsupported. This is
    // the arm no shipped backend can produce.
    let unreadable =
        FaultInjectingDirectory::new(inner.clone()).unsupported("list_attestations_for");
    assert!(
        unreadable.faults().contains("list_attestations_for"),
        "the fixture must be able to assert its OWN setup, or a fault that \
         silently failed to register reads as a passing test"
    );

    let fold_bad = resolve_mesh_config(&unreadable, NODE, &baseline, now)
        .await
        .expect(
            "Unsupported is a legitimate answer from a backend that does not \
             carry this plane — the fold must SURVIVE it, not fail",
        );

    // The whole point: it did not error, and it did not pretend to have read.
    assert!(
        !fold_bad.unreadable_roots.is_empty(),
        "the root could not be read, and the fold reported nothing — this is \
         exactly the collapse of `Err(_)` into `Ok(empty)` that #604 describes"
    );
}

/// The double is inert until a fault is declared — otherwise every fixture using
/// it would be testing the double rather than the code under test.
#[tokio::test]
async fn the_double_is_behaviourally_transparent_until_faulted_603() {
    let inner = backend().await;
    let plain = FaultInjectingDirectory::new(inner.clone());
    assert!(
        plain.faults().is_empty(),
        "a fresh double declares no faults"
    );

    let key = "transparent-603";
    ciris_persist::federation::tier_ingest::test_support::register_hybrid_key(&*inner, key).await;

    // Read through the double and read through the backend: same answer.
    let via_double = ciris_persist::federation::FederationDirectory::lookup_public_key(&plain, key)
        .await
        .expect("read via double")
        .expect("present via double");
    let via_inner = ciris_persist::federation::FederationDirectory::lookup_public_key(&*inner, key)
        .await
        .expect("read via inner")
        .expect("present via inner");
    assert_eq!(
        via_double.persist_row_hash, via_inner.persist_row_hash,
        "an un-faulted double must be byte-transparent, or fixtures using it are \
         measuring the double"
    );

    // And a fault on ONE method leaves the others alone — the composability the
    // issue asks for. Faulting a write must not disturb this read.
    let narrow = FaultInjectingDirectory::new(inner.clone()).unsupported("put_public_key");
    let still_readable =
        ciris_persist::federation::FederationDirectory::lookup_public_key(&narrow, key)
            .await
            .expect("an unrelated fault must not break this read")
            .expect("still present");
    assert_eq!(still_readable.key_id, key);
}
