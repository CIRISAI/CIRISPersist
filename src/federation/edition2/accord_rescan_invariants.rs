//! v62.0.0 (RL-fix1, lead ruling (B)) — **I2246: a rootless node never
//! wedges on an accord row, and never misses a halt once it has a root**, on
//! sqlite and postgres, two nodes.
//!
//! A holds the test ceremony's bundle and latches a holder's constitutional
//! halt. B holds no bundle. A's halt, as A's serve rule hands it to B, is
//! offered to B's replicated door with B's feed position:
//!
//! - B answers `Refused { accord_root_not_held }`, which advances the cursor
//!   (CC 5.4: a node "carries none it cannot verify"), and stores nothing of
//!   the row; the feed's FIRST skipped position is the watermark (a later
//!   skip on the same feed does not move it);
//! - while B holds no bundle, `rescan_needed` is empty (a state: a re-pull
//!   would only be skipped again);
//! - B adopts the bundle (`install_v2`); `rescan_needed` names the feed and
//!   its first position; the host re-pulls from it, the halt is admitted and
//!   LATCHES on B; the ack clears the watermark.

use ciris_crypto::composite::CompositeSigningKey;
use ciris_verify_core::cde::Value;
use ciris_verify_core::edition2::sign_row_statement;

use super::accord_rescan::{ack_rescan, rescan_needed, FeedPosition};
use super::door_invariants::fixture::map;
use super::fixture_genesis::{bundle_v2, install_v2, FAMILY_KEY_ID};
use super::halt::{halt_in_force, FAMILY_CONSTITUTIONAL};
use super::ingest::{
    apply_replicated_statement_at_feed, put_statement, ReplicatedStatementOutcome,
    StatementOutcome, INGEST_TIER,
};
use super::names::RowId;
use crate::federation::attestation_apply::AttestationRefusalReason;
use crate::federation::FederationDirectory;

const ACCORD: &str = FAMILY_KEY_ID;
const HOUR_MS: u64 = 3_600_000;
const PLANE: &str = "statements";

fn now_ms() -> u64 {
    u64::try_from(crate::host::clock::now().timestamp_millis()).unwrap()
}

/// A constitutional halt by `k` under the identity `iss` (the shape
/// `halt_lifecycle_invariants` signs). A halt is valid between `at` and
/// `until`, so it is dated now: a halt is a live act, not a key window.
fn halt(k: &CompositeSigningKey, iss: &str, id: &str, nonce: u8, at: u64, until: u64) -> Vec<u8> {
    let m = map(vec![
        ("accord_root", Value::Text(ACCORD.into())),
        ("asserted_at", Value::Uint(at)),
        ("author", Value::Text(iss.into())),
        ("invocation_id", Value::Text(id.into())),
        ("nonce", Value::Bytes(vec![nonce; 32])),
        ("valid_until", Value::Uint(until)),
    ]);
    sign_row_statement(k, iss, ACCORD, "scores", FAMILY_CONSTITUTIONAL, &m, vec![]).unwrap()
}

/// I2246 on one backend pair: `a` becomes rooted here, `b` starts rootless.
pub(crate) async fn i2246_body(
    a: &dyn FederationDirectory,
    b: &dyn FederationDirectory,
    tag: &str,
) {
    // A: rooted, and a holder's halt latches.
    install_v2(a).await.unwrap();
    let s = bundle_v2();
    let at = now_ms();
    let h = halt(
        &s.holder_key(0),
        s.holder_identity_ref(0),
        &format!("rl-halt-{tag}"),
        0x61,
        at,
        at + HOUR_MS,
    );
    let hid = RowId::of_statement(&h).expect("a row id");
    let out = put_statement(a, &h, None, INGEST_TIER).await.unwrap();
    assert!(
        matches!(out, StatementOutcome::Row { new: true, .. }),
        "[{tag}] I2246: A latches the halt: {out:?}"
    );
    // What A's serve rule hands B (an accord row is a bootstrap kind).
    let page = super::serve::statements_served_to(a, None, 1_000, Some("b-node"))
        .await
        .unwrap();
    let (pos, served) = page
        .statements
        .iter()
        .enumerate()
        .find(|(_, st)| st.bytes == h)
        .map(|(i, st)| (i, st.bytes.clone()))
        .expect("A serves its halt to B");
    let feed_at = |p: usize| FeedPosition {
        plane: PLANE.into(),
        peer: "node-a".into(),
        position: format!("{p:08}"),
    };

    // B: no bundle held. Refused, the cursor advances, nothing stored.
    super::rootless_mesh_invariants::assert_rootless(b, &format!("{tag} B")).await;
    let refused = apply_replicated_statement_at_feed(b, &served, &hid.0, &feed_at(pos))
        .await
        .unwrap_or_else(|e| panic!("[{tag}] I2246: B answers, never errs or waits: {e}"));
    assert_eq!(
        refused,
        ReplicatedStatementOutcome::Refused {
            reason: AttestationRefusalReason::AccordRootNotHeld
        },
        "[{tag}] I2246: B carries none it cannot verify"
    );
    assert!(
        refused.advances_cursor(),
        "[{tag}] I2246: the feed moves on"
    );
    assert!(
        b.edition2_voices(&hid).await.unwrap().is_empty(),
        "[{tag}] I2246: nothing of the row is stored on B"
    );
    // A later skip on the same feed keeps the first position.
    let again = apply_replicated_statement_at_feed(b, &served, &hid.0, &feed_at(pos + 5))
        .await
        .unwrap();
    assert!(matches!(again, ReplicatedStatementOutcome::Refused { .. }));
    assert!(
        rescan_needed(b).await.unwrap().is_empty(),
        "[{tag}] I2246: no rescan is named while B holds no bundle (a state)"
    );
    let held = b.accord_skips().await.unwrap();
    assert_eq!(held.len(), 1, "[{tag}] I2246: one watermark per feed");
    assert_eq!(held[0].from_position, feed_at(pos).position);

    // B adopts the bundle: the rescan names the feed from its first skip.
    install_v2(b).await.unwrap();
    let todo = rescan_needed(b).await.unwrap();
    assert_eq!(todo.len(), 1, "[{tag}] I2246: one feed to re-pull");
    let r = &todo[0];
    assert_eq!(
        (r.plane.as_str(), r.peer.as_str(), r.from_position.as_str()),
        (PLANE, "node-a", feed_at(pos).position.as_str()),
        "[{tag}] I2246: the watermark names the first skipped position"
    );
    // The host re-pulls from it: the halt is admitted and latches on B.
    let readmitted = apply_replicated_statement_at_feed(b, &served, &hid.0, &feed_at(pos))
        .await
        .unwrap_or_else(|e| panic!("[{tag}] I2246: the re-offered halt: {e}"));
    assert!(
        matches!(readmitted, ReplicatedStatementOutcome::Admitted(_)),
        "[{tag}] I2246: the re-offered halt is admitted: {readmitted:?}"
    );
    assert!(
        halt_in_force(b, ACCORD, crate::host::clock::now())
            .await
            .unwrap()
            .is_some(),
        "[{tag}] I2246: the halt latches on B once it holds the root"
    );
    assert!(
        ack_rescan(b, &r.plane, &r.peer, &r.from_position)
            .await
            .unwrap(),
        "[{tag}] I2246: the ack clears the watermark"
    );
    assert!(rescan_needed(b).await.unwrap().is_empty());
}

#[cfg(feature = "sqlite")]
#[tokio::test]
async fn i2246_a_rootless_node_skips_an_accord_row_and_rescans_once_rooted_sqlite() {
    use crate::store::Backend as _;
    let open = || async {
        let b = crate::store::sqlite::SqliteBackend::open_in_memory()
            .await
            .unwrap();
        b.run_migrations().await.unwrap();
        b
    };
    let (a, b) = (open().await, open().await);
    Box::pin(i2246_body(&a, &b, "sqlite")).await;
}

#[cfg(feature = "postgres")]
#[tokio::test]
async fn i2246_a_rootless_node_skips_an_accord_row_and_rescans_once_rooted_postgres() {
    use crate::store::Backend as _;
    let (Some(da), Some(db)) = (crate::test_pg::empty_dsn(), crate::test_pg::empty_dsn()) else {
        eprintln!("skipping: CIRIS_PERSIST_TEST_PG_URL unset");
        return;
    };
    let mut nodes = Vec::new();
    for dsn in [da, db] {
        let b = crate::store::postgres::PostgresBackend::connect(&dsn)
            .await
            .unwrap();
        b.run_migrations().await.unwrap();
        nodes.push(b);
    }
    Box::pin(i2246_body(&nodes[0], &nodes[1], "postgres")).await;
}
