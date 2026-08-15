//! v31.5.0 (CIRISPersist#685) — **a quorum-WITHDRAWN trust root must stop
//! projecting Global.**
//!
//! `namespace::is_trust_root` is the load-bearing predicate in `projection_for`:
//! a public record from a trust root reaches the WHOLE FEDERATION, the same
//! scope from a plain producer relays over its cohort. It called the bare
//! `is_canonical` / `is_infra_attest`, which answer *"does the row carry this
//! role"* and say nothing about whether a quorum has since withdrawn it.
//!
//! So a withdrawn trust root kept gossiping globally. The tombstone was stored,
//! verifiable, and unread on this path — the edge existed and the reader skipped
//! it. Same shape as #659 (a co-scrub conferring `canonical` on any key_id) and
//! #608 (a sanction not covering the sanctioning dimension).
//!
//! **Why this witness withdraws TWICE.** `is_trust_root` is an OR over two
//! roles, and the baked canonical carries BOTH (`canonical` in its
//! `identity_type` set, `infra:attest` in its roles). Withdrawing one and
//! asserting `false` would be a witness that cannot distinguish *"both arms
//! consult the tombstone"* from *"one arm does and the other short-circuits"*.
//! So it withdraws them one at a time and pins the value after each.

#![cfg(all(feature = "test-anchor", feature = "sqlite"))]

use ciris_persist::federation::namespace::is_trust_root;
use ciris_persist::federation::types::{identity_type, roles};
use ciris_persist::federation::FederationDirectory;
use ciris_persist::store::{Backend as _, SqliteBackend};

const CANON: &str = "ciris-canonical-1-d7bdeu223k";

#[tokio::test]
async fn a_withdrawn_trust_root_stops_projecting_global_685() {
    let backend = SqliteBackend::open_in_memory().await.expect("open");
    backend.run_migrations().await.expect("migrations");
    backend
        .seed_genesis_accord_holders(
            ciris_persist::federation::genesis::accord_holder_genesis_records(),
        )
        .await
        .expect("holders seed");
    ciris_persist::federation::genesis::seed_family_and_canonical(&backend)
        .await
        .expect("seed the baked plane");

    // PRECONDITION, asserted rather than assumed: the canonical must actually
    // carry BOTH roles, or the two-step withdrawal below proves nothing about
    // the second arm.
    let rec = FederationDirectory::lookup_public_key(&backend, CANON)
        .await
        .expect("read")
        .expect("the baked canonical is present");
    assert!(
        rec.identity_type.contains(identity_type::CANONICAL),
        "precondition: canonical identity_type — got {:?}",
        rec.identity_type
    );
    assert!(
        rec.claims_role(roles::INFRA_ATTEST),
        "precondition: the baked canonical must carry infra:attest, or the \
         second arm below is never exercised"
    );

    // CONTROL. Without this the test could pass by refusing everything.
    assert!(
        is_trust_root(&backend, CANON).await.expect("read"),
        "a live accord-blessed canonical IS a trust root"
    );

    // Withdraw ONE role. Still a trust root via the other arm — this is the
    // assertion that makes the second step meaningful.
    // NOTE the two arms use DIFFERENT tombstone tables, which is itself worth
    // pinning: `is_canonical_effective` consults `lookup_canonical_withdrawal`
    // (the dedicated canonical table), while `is_infra_attest_effective`
    // consults the generic `lookup_role_withdrawal(role, key_id)` (V104). A
    // witness that used one writer for both would leave one arm untested.
    backend
        .record_canonical_withdrawal(CANON, None, "digest-685-canonical")
        .await
        .expect("withdraw canonical");
    assert!(
        is_trust_root(&backend, CANON).await.expect("read"),
        "one role withdrawn, the other live — `is_trust_root` is an OR, so this \
         must still be true. If it is false here, the second arm is not being \
         consulted at all and the final assertion below would pass for the \
         wrong reason."
    );

    // Withdraw the other. Now neither arm holds.
    backend
        .record_role_withdrawal(roles::INFRA_ATTEST, CANON, None, "digest-685-attest")
        .await
        .expect("withdraw infra:attest");
    assert!(
        !is_trust_root(&backend, CANON).await.expect("read"),
        "BOTH trust-root roles withdrawn by quorum and this key is still a trust \
         root — its public records would keep reaching the whole federation. The \
         tombstone is stored and this reader is not consulting it (#685)."
    );
}
