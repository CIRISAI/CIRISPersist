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
//!   [`crate::federation::types::SignerForm::NOfMCosigned`] — this cut's
//!   wire shape carries a single attester (mirroring
//!   [`crate::federation::self_at_login::SignedTransportDestination`]
//!   exactly), so admission verifies it identically to `WitnessTouch`. See
//!   [`crate::federation::admission::verify_signed_touch_claim`]'s docs.
//! - Wiring `freshness_floor` into `signed_wire_index` / replication
//!   gossip — out of this cut's file scope.

use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};

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

/// v21.6.0 (CIRISPersist#519 item 2a-iii) — shared, backend-agnostic
/// conformance matrices for the freshness floor, run by the sqlite /
/// postgres / memory test suites against `&dyn FederationDirectory` so the
/// three backends cannot drift (the CIRISConformance parity rule).
/// `suffix` scopes every fixture id so runs against a shared test DB
/// (postgres) don't collide. Mirrors
/// [`crate::federation::self_at_login::test_support`]'s structure.
#[cfg(test)]
#[allow(dead_code)]
pub(crate) mod test_support {
    use super::*;
    use crate::federation::types::{cohort_scope, SignedTouchClaim, SignerForm};
    use crate::federation::{FederationDirectory, KeyRecord, SignedKeyRecord};
    use ciris_crypto::{Ed25519Signer, MlDsa65Signer};
    use ciris_verify_core::self_at_login::HybridSigningIdentity;
    use ciris_verify_core::transport_binding::produce_signed_identity_occurrence;

    fn ts(s: &str) -> DateTime<Utc> {
        s.parse().expect("test timestamp")
    }

    /// A `federation_keys` fixture with REAL hybrid pubkeys (so the
    /// touch-claim signature gate can verify envelopes signed by the
    /// matching identity). `put_public_key` does not itself hybrid-verify
    /// the registration, so the scrub fields stay placeholders — only the
    /// PUBKEYS must be real.
    fn fixture_key(key_id: &str, ed_pk: String, mldsa_pk: Option<String>) -> KeyRecord {
        KeyRecord {
            key_id: key_id.into(),
            pubkey_ed25519_base64: ed_pk,
            pubkey_ml_dsa_65_base64: mldsa_pk,
            algorithm: crate::federation::types::algorithm::HYBRID.into(),
            identity_type: crate::federation::types::identity_type::PRIMITIVE.into(),
            identity_ref: key_id.into(),
            valid_from: ts("2026-05-01T00:00:00Z"),
            valid_until: None,
            registration_envelope: serde_json::json!({ "id": key_id }),
            original_content_hash: "deadbeef".into(),
            scrub_signature_classical: "c2lnbmF0dXJl".into(),
            scrub_signature_pqc: None,
            scrub_key_id: key_id.into(),
            scrub_timestamp: ts("2026-05-01T00:00:00Z"),
            pqc_completed_at: None,
            persist_row_hash: String::new(),
            roles: Vec::new(),
            attestation_evidence: None,
            consent_role: None,
            additional_scrubs: Vec::new(),
        }
    }

    /// Build a fresh [`HybridSigningIdentity`] AND register its pubkeys
    /// under `key_id` via `put_public_key`, so a signature this identity
    /// produces verifies against the stored roster. Boxed: a multi-KiB
    /// ML-DSA-65 signer held across an `.await` inlines into the caller's
    /// future and can overflow the 2MB test stack (the established lesson
    /// — see [`crate::federation::self_at_login::test_support::run_signed_transport_route_matrix`]).
    pub(crate) async fn register_identity(
        dir: &dyn FederationDirectory,
        key_id: &str,
    ) -> Box<HybridSigningIdentity> {
        let identity = Box::new(HybridSigningIdentity::new(
            key_id,
            Ed25519Signer::random().unwrap(),
            MlDsa65Signer::new().unwrap(),
        ));
        let member = identity.directory_member().unwrap();
        dir.put_public_key(SignedKeyRecord {
            record: fixture_key(
                key_id,
                member.ed25519_public_key_base64.clone(),
                member.mldsa65_public_key_base64.clone(),
            ),
        })
        .await
        .expect("register fixture key");
        identity
    }

    /// Build + hybrid-sign a [`SignedTouchClaim`] with `identity` acting as
    /// `attesting_key_id`. Signs `SignedTouchClaim::signing_envelope()`
    /// through the REAL `produce_signed_identity_occurrence` producer —
    /// never a hand-faked signature.
    pub(crate) async fn signed_claim(
        identity: &HybridSigningIdentity,
        attesting_key_id: &str,
        target_key_id: &str,
        target_kind: &str,
        fresh_as_of: DateTime<Utc>,
        signer_form: SignerForm,
        cohort_scope: &str,
    ) -> SignedTouchClaim {
        let unsigned = SignedTouchClaim {
            target_key_id: target_key_id.to_owned(),
            target_kind: target_kind.to_owned(),
            fresh_as_of,
            signer_form,
            attesting_key_id: attesting_key_id.to_owned(),
            signed_envelope: serde_json::Value::Null,
            signature: ciris_verify_core::transport_binding::TransportBindingSignature {
                ed25519_signature_base64: String::new(),
                mldsa65_signature_base64: None,
            },
            cohort_scope: cohort_scope.to_owned(),
        };
        let (env, sig) = produce_signed_identity_occurrence(identity, unsigned.signing_envelope())
            .await
            .expect("sign touch claim envelope");
        SignedTouchClaim {
            signed_envelope: env,
            signature: sig,
            ..unsigned
        }
    }

    /// **`touch_claim_monotonic_max_only_advances`** — the anti-rollback
    /// matrix: T1 inserts (`Advanced`), T2 > T1 advances (`Advanced`), T0 <
    /// T1 is a silent no-op (`NotFresher`) that does NOT clobber the
    /// stored T2, and a byte-identical re-put of T2 is `NotFresher` (the
    /// strict `>` guard — equal is never "fresher").
    pub(crate) async fn run_monotonic_max_matrix(dir: &dyn FederationDirectory, suffix: &str) {
        // SelfTouch requires the attester to BE the touched target (or a
        // registered occurrence of it) — the simplest case is the target
        // touching itself, so `target == key_id`.
        let key_id = format!("touch-self-{suffix}");
        let target = key_id.clone();
        let identity = register_identity(dir, &key_id).await;

        let t1 = signed_claim(
            &identity,
            &key_id,
            &target,
            "occurrence",
            ts("2026-07-01T00:00:00Z"),
            SignerForm::SelfTouch,
            cohort_scope::SELF,
        )
        .await;
        assert_eq!(
            dir.put_touch_claim(&t1).await.unwrap(),
            TouchApplyOutcome::Advanced,
            "fresh insert must advance"
        );
        let stored = dir
            .lookup_freshness_floor(&target, "occurrence")
            .await
            .unwrap()
            .expect("row exists");
        assert_eq!(stored.fresh_as_of, t1.fresh_as_of);

        let t2 = signed_claim(
            &identity,
            &key_id,
            &target,
            "occurrence",
            ts("2026-07-02T00:00:00Z"),
            SignerForm::SelfTouch,
            cohort_scope::SELF,
        )
        .await;
        assert_eq!(
            dir.put_touch_claim(&t2).await.unwrap(),
            TouchApplyOutcome::Advanced,
            "strictly-greater fresh_as_of must advance"
        );
        assert_eq!(
            dir.lookup_freshness_floor(&target, "occurrence")
                .await
                .unwrap()
                .unwrap()
                .fresh_as_of,
            t2.fresh_as_of
        );

        let t0 = signed_claim(
            &identity,
            &key_id,
            &target,
            "occurrence",
            ts("2026-06-15T00:00:00Z"),
            SignerForm::SelfTouch,
            cohort_scope::SELF,
        )
        .await;
        assert_eq!(
            dir.put_touch_claim(&t0).await.unwrap(),
            TouchApplyOutcome::NotFresher,
            "an OLDER fresh_as_of must be a no-op, never an error"
        );
        assert_eq!(
            dir.lookup_freshness_floor(&target, "occurrence")
                .await
                .unwrap()
                .unwrap()
                .fresh_as_of,
            t2.fresh_as_of,
            "the older no-op must not clobber the stored, fresher T2"
        );

        assert_eq!(
            dir.put_touch_claim(&t2).await.unwrap(),
            TouchApplyOutcome::NotFresher,
            "re-putting the SAME fresh_as_of is NotFresher (strict > guard, equal never wins)"
        );
    }

    /// **`touch_claim_rejects_future_beyond_skew`** — a `fresh_as_of` more
    /// than [`crate::federation::admission::DEFAULT_MAX_TOUCH_SKEW`] ahead
    /// of wall-clock `now()` is rejected: monotonic-max stops a claim from
    /// rolling the floor BACK, this guard stops a lying clock from jumping
    /// it FORWARD past what any real touch could attest.
    pub(crate) async fn run_future_skew_rejection(dir: &dyn FederationDirectory, suffix: &str) {
        let key_id = format!("touch-future-self-{suffix}");
        let target = key_id.clone();
        let identity = register_identity(dir, &key_id).await;

        let far_future = Utc::now() + chrono::Duration::hours(1);
        let claim = signed_claim(
            &identity,
            &key_id,
            &target,
            "occurrence",
            far_future,
            SignerForm::SelfTouch,
            cohort_scope::SELF,
        )
        .await;
        let err = dir
            .put_touch_claim(&claim)
            .await
            .expect_err("fresh_as_of an hour in the future must be rejected (5m default skew)");
        assert_eq!(err.kind(), "federation_invalid_argument");
        assert!(
            dir.lookup_freshness_floor(&target, "occurrence")
                .await
                .unwrap()
                .is_none(),
            "a rejected claim must not be written"
        );
    }

    /// **`touch_claim_requires_valid_hybrid_signature`** — a forged
    /// signature is rejected; the row stays untouched. Mirrors the
    /// transport-destination forged-sig witness
    /// ([`crate::federation::self_at_login::test_support::run_signed_transport_route_matrix`]).
    pub(crate) async fn run_forged_signature_rejection(
        dir: &dyn FederationDirectory,
        suffix: &str,
    ) {
        use base64::{engine::general_purpose::STANDARD as B64, Engine as _};

        let key_id = format!("touch-forged-self-{suffix}");
        let target = key_id.clone();
        let identity = register_identity(dir, &key_id).await;

        let mut claim = signed_claim(
            &identity,
            &key_id,
            &target,
            "occurrence",
            ts("2026-07-01T00:00:00Z"),
            SignerForm::SelfTouch,
            cohort_scope::SELF,
        )
        .await;
        claim.signature.ed25519_signature_base64 = B64.encode([0u8; 64]);
        let err = dir
            .put_touch_claim(&claim)
            .await
            .expect_err("a forged signature must be rejected");
        assert_eq!(err.kind(), "federation_signature_invalid");
        assert!(
            dir.lookup_freshness_floor(&target, "occurrence")
                .await
                .unwrap()
                .is_none(),
            "a rejected claim must not be written"
        );
    }

    /// **`touch_claim_cohort_scope_validated`** — a `cohort_scope` outside
    /// the closed set (`self` / `family` / `community` / `affiliations` /
    /// `species` / `biosphere` / `federation`) is rejected — the MANDATORY
    /// privacy row (§4).
    pub(crate) async fn run_cohort_scope_validation(dir: &dyn FederationDirectory, suffix: &str) {
        let key_id = format!("touch-cohort-self-{suffix}");
        let target = key_id.clone();
        let identity = register_identity(dir, &key_id).await;

        let claim = signed_claim(
            &identity,
            &key_id,
            &target,
            "occurrence",
            ts("2026-07-01T00:00:00Z"),
            SignerForm::SelfTouch,
            "global", // not in the closed set — rejected
        )
        .await;
        let err = dir
            .put_touch_claim(&claim)
            .await
            .expect_err("an invalid cohort_scope must be rejected");
        assert_eq!(err.kind(), "federation_cohort_scope_rejected");
        assert!(dir
            .lookup_freshness_floor(&target, "occurrence")
            .await
            .unwrap()
            .is_none());
    }

    /// **Round-trip byte-exactness**: a real signed touch, once admitted,
    /// reads back via `lookup_freshness_floor` byte-identical to what was
    /// put (mirrors the #507b "the stored row IS the exact value re-served"
    /// discipline the signed-wire-index planes carry).
    pub(crate) async fn run_round_trip(dir: &dyn FederationDirectory, suffix: &str) {
        let key_id = format!("touch-roundtrip-self-{suffix}");
        let target = key_id.clone();
        let identity = register_identity(dir, &key_id).await;

        let claim = signed_claim(
            &identity,
            &key_id,
            &target,
            "canonical",
            ts("2026-07-04T12:00:00Z"),
            SignerForm::SelfTouch,
            cohort_scope::FAMILY,
        )
        .await;
        assert_eq!(
            dir.put_touch_claim(&claim).await.unwrap(),
            TouchApplyOutcome::Advanced
        );
        let stored = dir
            .lookup_freshness_floor(&target, "canonical")
            .await
            .unwrap()
            .expect("row exists");
        assert_eq!(stored, claim, "round-trip must be byte-exact");
    }

    /// A `witness_touch` from an attester independent of the target is
    /// admitted; a `witness_touch` claiming to BE the target it witnesses
    /// is rejected (the opposite bar from `self_touch`).
    pub(crate) async fn run_witness_touch_relationship(
        dir: &dyn FederationDirectory,
        suffix: &str,
    ) {
        let target_key_id = format!("touch-witnessed-{suffix}");
        let witness_key_id = format!("touch-witness-{suffix}");
        let witness = register_identity(dir, &witness_key_id).await;
        // The target itself must also be a registered key for the
        // self-vs-witness relationship check to have a subject.
        register_identity(dir, &target_key_id).await;

        let good = signed_claim(
            &witness,
            &witness_key_id,
            &target_key_id,
            "occurrence",
            ts("2026-07-01T00:00:00Z"),
            SignerForm::WitnessTouch,
            cohort_scope::SELF,
        )
        .await;
        assert_eq!(
            dir.put_touch_claim(&good).await.unwrap(),
            TouchApplyOutcome::Advanced,
            "an independent witness must be admitted"
        );

        // A "witness_touch" that claims to BE its own target is rejected —
        // a witness cannot be the thing it witnesses.
        let self_as_witness = signed_claim(
            &witness,
            &witness_key_id,
            &witness_key_id,
            "occurrence",
            ts("2026-07-01T00:00:00Z"),
            SignerForm::WitnessTouch,
            cohort_scope::SELF,
        )
        .await;
        let err = dir
            .put_touch_claim(&self_as_witness)
            .await
            .expect_err("witness_touch of one's own key must be rejected");
        assert_eq!(err.kind(), "federation_signature_invalid");
    }
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
