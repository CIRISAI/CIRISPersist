//! v21.6.0 (CIRISPersist#519 item 2a-iii) — the signed `fresh_as_of`
//! **freshness floor**: persist's storage + merge half of
//! `namespace_supersets.json` § `freshness_floor`.
//!
//! # The shape
//!
//! `fresh_as_of` is a **signed temporal LOWER bound**: "this object was
//! demonstrably alive no earlier than T" — the DUAL of the existing upper
//! bounds (`valid_until` / `expires_at` / `deletion_window`). The manifest
//! decomposes it into two halves that land in two very different places:
//!
//! - **merge = monotonic max** — deterministic, total, anti-rollback, and
//!   therefore a pure fold over two values. That's what lives HERE: the
//!   storage layer ([`crate::federation::FederationDirectory::put_touch_claim`]
//!   / [`crate::federation::FederationDirectory::lookup_freshness_floor`],
//!   the V112 `freshness_floor` table, and [`TouchApplyOutcome`]).
//! - **value production = a signed touch-claim** — `now()` is NOT pure, so
//!   producing the value is an ATTESTATION
//!   ([`crate::federation::types::SignedTouchClaim`]), never a transform
//!   opcode. "Reading emits a claim" is CEG-native here rather than a
//!   special case. PRODUCING a touch (deciding when to touch, which
//!   `SignerForm` to use, gathering witnesses/co-signers) is edge/agent's
//!   job — documented for adoption, not built in this crate.
//!
//! # The gap this closes
//!
//! Persist already has `last_seen_at` (e.g.
//! [`crate::federation::self_at_login::TransportDestination::last_seen_at`]),
//! but that field is advisory liveness, not signed material —
//! `fresh_as_of` is its SIGNED successor, not a duplicate. See
//! `admission.rs`'s historical note on `last_seen_at` for the exact gap
//! this cut closes.
//!
//! # Anti-rollback (deliberate, axiomatic)
//!
//! Monotonic-max is deliberately one-directional. A merge that could
//! DECREASE the floor would let a stale replica resurrect a dead liveness
//! claim — the same anti-rollback logic that makes tombstones project
//! Global. The admission-side dual — a lying clock cannot jump the floor
//! FORWARD past what any real touch could attest — is
//! [`crate::federation::admission::verify_touch_claim_admission`].
//!
//! # Privacy (MANDATORY, not optional — §4)
//!
//! Touch-claims are **cohort-scoped and consent-gated**:
//! [`crate::federation::types::SignedTouchClaim::cohort_scope`] is a
//! required field, validated
//! ([`crate::federation::admission::check_cohort_scope`]) at admission. An
//! unrestricted read-receipt trail is an access-pattern surveillance
//! surface, and for the `trace:*` family (already the one recipient-gated
//! family) it would leak exactly who is reading whose reasoning. **A
//! [`crate::federation::FederationDirectory::lookup_freshness_floor`]
//! consumer MUST apply the same cohort/consent gating persist applies to
//! any other cohort-scoped read** — this module does not, and must not,
//! expose a global "who touched what, when" surface.
//!
//! # Coalescing (a producer concern, documented here)
//!
//! The manifest names `round(precision)` as the coalescing primitive: a
//! producer SHOULD round `fresh_as_of` to a bucket boundary before
//! emitting, so repeated touches within the same bucket dedupe on the wire
//! (identical `fresh_as_of` ⇒ identical signed envelope ⇒ identical content
//! hash). The general `round` transform opcode is CIRISPersist#519 item
//! 2a-ii's (built by a sibling cut, not here); [`coalesce_touch_ts`] is a
//! small freshness-floor-specific convenience so a producer doesn't have to
//! pull in that surface just to get the rounding direction right (floor,
//! never ceiling — see its doc for why).
//!
//! # What is NOT built here
//!
//! - The producer surface (edge/agent deciding when/how to touch each
//!   family — `ownership:*`, `trust:*`, `consent:*`, ... per the
//!   manifest's `demanded_by`). Documented for adoption.
//! - Real m-of-n co-signature aggregation for
//!   [`crate::federation::types::SignerForm::NOfMCosigned`] — **implemented in
//!   v21.10.0 (#519 b2)**: the primary attester's signature (the typed
//!   [`SignedTouchClaim`] container) counts as one signer, and the co-signer
//!   set rides `extra` under [`TOUCH_COSIGNATURES_FIELD`]; admission verifies
//!   each co-signature over the same envelope against its own pinned key,
//!   requiring [`NOFM_MIN_COSIGNERS`] distinct independent co-signers beyond
//!   the primary (so a lying clock must corrupt a quorum, not one key). See
//!   [`crate::federation::admission::verify_signed_touch_claim`] step (5).
//! - Wiring `freshness_floor` into `signed_wire_index` / replication
//!   gossip — out of this cut's file scope.

use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};

/// v21.10.0 (CIRISPersist#519 b2) — the touch envelope's `extra` key carrying
/// the co-signature set for a [`crate::federation::types::SignerForm::NOfMCosigned`]
/// touch: a JCS array of
/// [`ciris_verify_core::threshold::ThresholdSignature`], each
/// over the SAME `JCS(signed_envelope)` the primary attester signed. Rides in
/// `extra` — CEG-native, not a universal envelope path — so `SelfTouch` /
/// `WitnessTouch` touches are byte-unchanged.
pub const TOUCH_COSIGNATURES_FIELD: &str = "touch_cosignatures";

/// v21.10.0 (CIRISPersist#519 b2) — the minimum DISTINCT valid signers an
/// `NOfMCosigned` touch requires (the primary attester + at least this many
/// independent co-signers): a collusion-resistant "death finding" needs more
/// than one key, so a lying clock must corrupt a quorum, not a single signer.
/// `M >= 2` total. Below this an `NOfMCosigned` touch is rejected — it would be
/// indistinguishable from a `WitnessTouch`.
pub const NOFM_MIN_COSIGNERS: usize = 1;

/// v21.6.0 (CIRISPersist#519 item 2a-iii) — outcome of a
/// [`crate::federation::FederationDirectory::put_touch_claim`] monotonic
/// apply. Deliberately a two-variant enum (unlike
/// [`crate::federation::self_at_login::TransportDestinationApplyOutcome`]'s
/// four) — the freshness floor has no tombstone/retirement concept and no
/// `Refused`-with-reason: a stale touch is simply not news.
///
/// `Ord` on `fresh_as_of` alone decides everything, so there is no
/// same-clock-fork case to distinguish (an EQUAL `fresh_as_of` is, by
/// construction, `NotFresher` — see the SQL guard's strict `>`).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum TouchApplyOutcome {
    /// No row existed, or the incoming `fresh_as_of` is strictly greater
    /// than the stored one — the floor advanced (insert or replace).
    Advanced,
    /// The incoming `fresh_as_of` is less than or equal to the stored
    /// one — a silent no-op (never an error; the anti-rollback guard,
    /// never surfaced as a `Refused`-with-reason because there is nothing
    /// exceptional about an old touch arriving late).
    NotFresher,
}

/// Round `ts` DOWN to the nearest `precision` bucket (floor, never
/// ceiling). A producer SHOULD call this on the value it is about to sign
/// as `fresh_as_of`, so repeated touches within one `precision` window
/// coalesce to an IDENTICAL signed value — the manifest's `coalescing:
/// round(precision)` primitive for this floor.
///
/// Floor, not round-to-nearest or ceiling: rounding UP could push
/// `fresh_as_of` past the real `now()` and trip
/// [`crate::federation::admission::verify_touch_claim_admission`]'s
/// future-skew guard on a legitimate, just-unlucky touch. Flooring can
/// only make the asserted lower bound MORE conservative, never less true.
///
/// `precision` of zero or negative is treated as 1 second (a no-op
/// rounding unit) rather than panicking — a misconfigured caller gets a
/// pass-through, not a crash.
pub fn coalesce_touch_ts(ts: DateTime<Utc>, precision: chrono::Duration) -> DateTime<Utc> {
    let precision_secs = precision.num_seconds().max(1);
    let epoch_secs = ts.timestamp();
    let floored_secs = epoch_secs.div_euclid(precision_secs) * precision_secs;
    DateTime::<Utc>::from_timestamp(floored_secs, 0).unwrap_or(ts)
}

/// v21.6.0 (CIRISPersist#519 item 2a-iii) — the pure freshness-floor MERGE:
/// **monotonic max**, the join of a bounded ⊔-semilattice. The manifest
/// (`freshness_floor.merge_rule = "monotonic_max"`) declares this is "a pure
/// fold, algebra-legal"; this is that fold, single-sourced. Every backend's
/// `put_touch_claim` ON-CONFLICT guard (`WHERE excluded.fresh_as_of >
/// stored.fresh_as_of`) implements exactly `merge_floor(stored, incoming)` —
/// the store keeps `merge_floor` of what it had and what arrived. Being a
/// join makes the floor **commutative, associative, and idempotent** (so
/// replicated touches converge regardless of arrival order — the property the
/// `merge_floor_is_a_join_semilattice` proptest verifies against the
/// manifest's declaration) and **anti-rollback** (`merge_floor(a, b) >= a`, so
/// the floor never retreats).
pub fn merge_floor(a: DateTime<Utc>, b: DateTime<Utc>) -> DateTime<Utc> {
    a.max(b)
}

/// v21.6.0 (CIRISPersist#519 item 2a-iii) — **the manifest declaration is the
/// proptest oracle.** `namespace_supersets.json` declares
/// `freshness_floor.merge_rule = "monotonic_max"` and calls it "a pure fold,
/// algebra-legal"; these property tests VERIFY that claim as law — that
/// [`merge_floor`] is a bounded join-⊔-semilattice (commutative + associative +
/// idempotent + an upper bound), which is exactly what makes replicated
/// touch-claims converge regardless of arrival order and the floor
/// anti-rollback. The claim in the vendored table is not asserted by hand on a
/// few samples — it is fuzzed over arbitrary instants.
#[cfg(test)]
mod proptests {
    use super::merge_floor;
    use chrono::{DateTime, Utc};
    use proptest::prelude::*;

    /// Arbitrary UTC instant over the representable range (seconds precision —
    /// the wire encoding's resolution).
    fn arb_instant() -> impl Strategy<Value = DateTime<Utc>> {
        // Bound well inside chrono's valid range so from_timestamp never fails.
        (-62_135_596_800i64..=253_402_300_799i64)
            .prop_map(|s| DateTime::<Utc>::from_timestamp(s, 0).expect("in range"))
    }

    proptest! {
        /// The manifest's `merge_rule = monotonic_max` is a join semilattice.
        #[test]
        fn merge_floor_is_a_join_semilattice(
            a in arb_instant(),
            b in arb_instant(),
            c in arb_instant(),
        ) {
            // commutative
            prop_assert_eq!(merge_floor(a, b), merge_floor(b, a));
            // associative
            prop_assert_eq!(
                merge_floor(merge_floor(a, b), c),
                merge_floor(a, merge_floor(b, c))
            );
            // idempotent
            prop_assert_eq!(merge_floor(a, a), a);
            // least upper bound: the join dominates both operands...
            prop_assert!(merge_floor(a, b) >= a);
            prop_assert!(merge_floor(a, b) >= b);
            // ...and is exactly one of them (a max, not a fabricated value).
            prop_assert!(merge_floor(a, b) == a || merge_floor(a, b) == b);
        }

        /// Anti-rollback: folding a new touch into the stored floor can only
        /// advance it — a stale (older) touch is absorbed with no effect (the
        /// property the backend `WHERE excluded.fresh_as_of > stored` guard
        /// relies on).
        #[test]
        fn merge_floor_never_retreats(stored in arb_instant(), incoming in arb_instant()) {
            let merged = merge_floor(stored, incoming);
            prop_assert!(merged >= stored);
            if incoming <= stored {
                prop_assert_eq!(merged, stored, "a stale touch must not move the floor");
            }
        }
    }
}
