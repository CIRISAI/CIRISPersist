//! v31.1.0 (CIRISPersist#663) — **THE DIVERGENCE DETECTOR.**
//!
//! Two implementations of one check live in this binary:
//!
//! * `ciris_verify_core::federation_self_record::KeyRecord::check_subject_binding`
//!   — built on verify's type-agnostic `subject_binding::SubjectBinding`
//!   builder, and the projection verify's provenance walk and transport
//!   binding apply on their own planes;
//! * [`ciris_persist::federation::admission::subject_binding`] — persist's
//!   spelling, which `put_public_key`, `apply_replicated_key_record` and the
//!   accord co-scrub quorum core all go through.
//!
//! They exist separately because `ciris_verify_core`'s `KeyRecord` and
//! persist's [`ciris_persist::federation::KeyRecord`] are DISTINCT TYPES, and
//! persist's carries a declaration-order contract against CIRISRegistry's
//! vendored shape (`types.rs`: *"declaration order is the JSON key order …
//! changes here require a matching change there to preserve `persist_row_hash`
//! parity"*). That contract is real, so deduplication is not the goal here.
//! **Detectability is.**
//!
//! # Why this file exists rather than a comment
//!
//! Pinned at CIRISVerify 13.0.0, verify's projection bound FOUR members
//! (`key_id`, `identity_type`, both pubkey legs) and persist's bound THREE — it
//! omitted `identity_type`, which `is_canonical` reads off the row to decide
//! canonical standing. Same process, same release, different answers: a row
//! could pass persist's door and fail verify's check. **Both suites were fully
//! green.** The only thing that caught it was a human reading both
//! implementations side by side, and a human reading is not a build gate.
//!
//! Alignment-by-comment does not fail builds. This does.
//!
//! # How the member set is obtained WITHOUT restating it
//!
//! Verify exposes `SubjectBinding::members()`, but no verify API hands a
//! caller the `SubjectBinding` that `check_subject_binding` constructs — it is
//! built inline and consumed. Rebuilding it here with our own `.require(…)`
//! calls would mint a THIRD spelling that drifts exactly like the first two,
//! which is the defect, not the fix.
//!
//! So the set is **probed out of verify's own behaviour** instead. Verify's
//! `check` iterates its projection and reports the member that failed —
//! `Missing { member }` when the signed bytes do not carry it, `Mismatch
//! { member, claimed }` when they carry something else, where `claimed` is the
//! JSON of the value verify expected. Starting from an empty envelope and
//! feeding each reported member back in, the loop converges on **exactly the
//! members verify projects and the values it expects**, read off the shipped
//! implementation rather than copied from it. Add a fifth member in verify and
//! the probe finds it with no edit here.
//!
//! The `require_optional` disposition is probed the same way, by difference: a
//! member whose expected value is `null` is satisfied by omission (CEG §0.9),
//! so it never surfaces as `Missing`. Running the probe twice — once against a
//! record whose optional fields are all `None`, once against one where they are
//! all `Some` — makes the optional members exactly the difference between the
//! two discovered sets.
//!
//! # Sets, not order
//!
//! Both sides carry a `serde_json::Map`, which is `BTreeMap`-backed in this
//! build, so both are already lexicographic — the order JCS emits, and
//! therefore the order the co-scrubbers actually signed over. The comparisons
//! below are `BTreeMap` equality (member set AND expected value, order-free by
//! construction); nothing here asserts an insertion order, which would be a
//! false failure waiting to happen.
//!
//! # A new verify error variant is a COMPILE error here, not a fall-through
//!
//! The probes' convergence signal is *"the error stopped being a binding
//! failure"*. Spelled as a `_` wildcard, that is wrong in the worst possible
//! direction: a **new `SubjectBindingError` variant is still a binding
//! failure**, but falls through the wildcard and reads as successful
//! convergence. The probe then stops early, reports whatever subset it had
//! found, and the whole conformance test goes GREEN if that subset happens to
//! match persist's projection — the failure this file exists to prevent,
//! triggered by the exact event it exists to detect, degrading toward agreement,
//! which is the direction nobody investigates.
//!
//! Neither `SubjectBindingError` nor `ProvenanceError` is `#[non_exhaustive]`,
//! so the guard is **structural rather than defensive**: both matches carry no
//! wildcard, and a variant added in a future CIRISVerify fails to compile here.
//! Checked, not assumed — deleting one arm from each yields
//! `error[E0004]: non-exhaustive patterns … not covered`. The
//! `SubjectBindingError` match lives in exactly one function
//! ([`probe_advance`]) that both planes route through, so that is one compile
//! error to resolve rather than two.
//!
//! # MUTATION-TESTED — 9 mutations, 9 killed
//!
//! A conformance test that passes under divergence is worse than none, because
//! it certifies an agreement that does not exist. So the detector was checked
//! against the divergences it claims to catch — each applied on disk, re-read
//! back before running, and scored on nextest's `Summary [...] N tests run:`
//! line (all five tests, never a single-test filter):
//!
//! | mutation | of 5 tests |
//! | --- | --- |
//! | drop `identity_type` from `subject_binding` (the literal v31.0.0 defect) | **4 red** |
//! | bind `identity_type` off the `key_id` column (right member, wrong value) | **4 red** |
//! | bind the absent PQC leg as `""` instead of `null` (optional ⇒ required) | **4 red** |
//! | flatten §0.9 to unconditional refusal (fail-closed "simplification") | **2 red** |
//! | flatten §0.9 to unconditional tolerance (the other direction) | **2 red** |
//! | give two fixture fields one value again (hole 2) | **1 red** |
//! | inject an unmodelled binding error mid-probe (hole 3) | **1 red** |
//! | filter the fixture walk back to strings only (hole 4) | **1 red** |
//! | make the provenance plane alone require an optional leg (hole 5) | **1 red** |
//!
//! The first five mutate `src/federation/admission.rs`; the last four mutate
//! this file, because what they prove is that its own guards work. The §0.9 pair
//! legitimately leaves three green — they change absence handling, not the
//! projection.
//!
//! **Three of them are worth reading, because each measures a green-to-red
//! flip rather than asserting one:**
//!
//! * **7** injects a `NotAnObject` binding failure *after* the full member set
//!   is discovered — the faithful silent-green scenario. Shipped code: the probe
//!   panics, test reds. Against the wildcard this file originally shipped, the
//!   identical injection gave `5 tests run: 5 passed, 0 skipped` — **fully green
//!   while the binding was still failing.**
//! * **8** restores the string-only walk and reds naming `is_self_signed`, the
//!   field that really was being silently dropped.
//! * **9** makes verify's provenance plane alone require a leg the key-record
//!   plane treats as optional — codex's exact scenario. Shipped code reds on the
//!   disposition comparison. Against the pre-fix test, which compared only
//!   MATERIALIZED probes, the identical divergence gave `5 tests run: 5 passed,
//!   0 skipped`.
//!
//! Mutation 1 also proves neither probe is vacuous: the key-record one reports
//! `only ciris_verify_core binds: ["identity_type"]`, and the provenance one
//! reds on the same missing member — so both really did discover all four of
//! verify's members off verify's own behaviour, rather than off a list written
//! in this file.
//!
//! # THIS FILE IS A STOPGAP. DELETE IT WHEN CIRISVerify#254 LANDS.
//!
//! Five real holes have now been found here by review, **every one in the
//! direction of false confidence**, and none by the suite being green:
//!
//! 1. the transport plane's coverage was overstated;
//! 2. the fixture's fields were mutually indistinguishable;
//! 3. a still-failing binding read as successful convergence;
//! 4. the collision walk silently dropped every non-string leaf;
//! 5. the provenance round trip never exercised omission, so the `require` /
//!    `require_optional` split went unpinned across verify's two planes.
//!
//! Each was subtle and each is closed. But the pattern is the point, and it is
//! not carelessness: **reconstructing a foreign implementation's contract by
//! fault injection has an irreducible blind-spot problem.** The probe infers a
//! projection from error messages, and every such reconstruction has edges the
//! original does not — so the holes appear at the edges of the *reconstruction*,
//! which is exactly where nobody thinks to look, and they fail toward agreement
//! because a probe that stops early reports a subset that usually still matches.
//!
//! Expect a sixth. This detector is **well attacked**, which is a real property
//! and a weaker one than correct.
//!
//! The actual fix is not more hardening here. It is
//! [CIRISVerify#254](https://github.com/CIRISAI/CIRISVerify/issues/254) ask 2 —
//! **export the projections as data** (`KeyRecord::subject_binding() ->
//! SubjectBinding` and the provenance / transport equivalents). With that, this
//! file's two probes and every guard protecting them collapse into a direct
//! comparison of two member maps, with no inference and therefore no edges.
//!
//! **When #254 lands, delete the probes rather than porting them.** A workaround
//! documented as a workaround is fine; one that accretes authority because it
//! survived review is not.
//!
//! # Three planes, and the two this file reaches
//!
//! CIRISVerify 13.1.0 applies the same projection idea on THREE planes, not
//! one, and they are not the same projection:
//!
//! | plane | projection | covered here |
//! | --- | --- | --- |
//! | `KeyRecord::check_subject_binding` | `key_id`, `identity_type`, both pubkey legs | **yes** — probed, §1–3 below |
//! | `provenance.rs:420` (per chain link) | the same four | **yes** — probed, §4 below |
//! | `transport_binding.rs:353` | `attesting_key_id`, `transport_destination`, `encryption_pubkeys` | **NO — verify's error type makes it unreachable** |
//!
//! **Why the provenance plane is worth probing even though persist delegates
//! the walk.** #465 routed persist's chain-walk crypto through
//! `verify_provenance_chain_with_policy_and_terminus`, so there is no second
//! CHECKER to diverge. But persist is still the PRODUCER: every
//! `registration_envelope` verify's walk inspects was stamped by
//! `bind_subject_into_envelope`, off `subject_binding`. If verify widens the
//! provenance projection and persist's producer does not stamp the new member,
//! **every chain persist mints stops rooting** — a total federation outage
//! produced by a dependency bump, with nothing in either repo asserting the two
//! stay aligned. §4 asserts it, on the producer/checker seam rather than the
//! checker/checker one, and it also pins that verify's own two checker planes
//! agree with each other.
//!
//! **Why the transport plane is NOT covered — reported, not forced.**
//! `verify_transport_binding` catches the `SubjectBindingError` and returns
//! `Ok(reject(TransportBindingReason::SubjectMismatch))`, logging the detail
//! through `tracing::warn!` and dropping it. The member name and the expected
//! value never leave the function, so **the probe cannot converge**: there is
//! no way to learn which member failed, and therefore no way to enumerate
//! verify's set. Log-scraping would be a half-probe that passes without ever
//! reading verify's projection — precisely the "certifies an agreement that was
//! never checked" failure this file exists to prevent — so it is not done here.
//!
//! Persist's exposure on that plane is also structurally different, which is
//! why this is a gap and not a hole: `verify_signed_identity_occurrence`
//! **parses** `transport_destination` and `encryption_pubkeys` out of the
//! signed envelope and hands them straight to verify, rather than restating the
//! projection. There is no second spelling in persist's shipped code to
//! diverge. The residual risk is producer-side (an occurrence envelope minted
//! without `attesting_key_id` — the exact defect #659 found in six fixtures),
//! and it is unguarded. CIRISVerify#254 carries the ask.
//!
//! # If verify ever exports the list as data
//!
//! CIRISVerify#254 asks for a `KeyRecord::subject_binding() -> SubjectBinding`
//! accessor (or an equivalent member-list export). The day it lands, the probe
//! below collapses to one call and both discovery loops disappear; the
//! assertions they feed do not change. The one brittleness worth naming until
//! then: the probe depends on `SubjectBindingError::Mismatch.claimed` carrying
//! `expected.to_string()`, which today is an error-message field rather than a
//! documented contract — #254 asks for that too. If verify changes the
//! encoding, `probe_verify_projection` panics with a diagnostic rather than
//! silently discovering nothing.

use std::collections::{BTreeMap, BTreeSet};

use ciris_persist::federation::admission::{subject_binding, verify_envelope_binds_subject};
use ciris_persist::federation::KeyRecord as PersistKeyRecord;
use ciris_verify_core::federation_self_record::KeyRecord as VerifyKeyRecord;
use ciris_verify_core::provenance::{ProvenanceChain, ProvenanceError, ProvenanceLink};
use ciris_verify_core::subject_binding::SubjectBindingError;
use serde_json::{Map, Value};

// ── The one subject both implementations are asked about ────────────────────
//
// **EVERY field carries its own sentinel, and that is load-bearing.**
//
// The probe recovers verify's expected VALUE out of `Mismatch.claimed`, so the
// detector distinguishes members BY VALUE. Two fixture fields sharing a value
// are indistinguishable to it: if verify later projects `identity_ref` and
// persist binds that member off `key_id` by mistake, a fixture where both
// fields read `"conf-663-subject"` reports AGREEMENT on a wrong-column bind —
// exactly the class #663 exists to catch, silently un-caught.
//
// Caught by codex review on CIRISPersist#666: the original fixture gave
// `key_id`, `identity_ref` and `scrub_key_id` one value, and `valid_from`,
// `scrub_timestamp` and `pqc_completed_at` another. The invariant is now
// asserted rather than asserted-in-a-comment — see
// `every_fixture_field_carries_its_own_sentinel`, which derives the check from
// the serialized fixtures so a field added later cannot quietly reuse a value.

const KEY_ID: &str = "conf-663-key-id";
const IDENTITY_TYPE: &str = "conf-663-identity-type";
const IDENTITY_REF: &str = "conf-663-identity-ref";
const ALGORITHM: &str = "conf-663-algorithm";
const ED25519: &str = "conf-663-pubkey-ed25519-base64";
const MLDSA: &str = "conf-663-pubkey-ml-dsa-65-base64";
const ORIGINAL_CONTENT_HASH: &str = "conf-663-original-content-hash";
const SCRUB_KEY_ID: &str = "conf-663-scrub-key-id";
const SCRUB_SIG_CLASSICAL: &str = "conf-663-scrub-signature-classical";
const SCRUB_SIG_PQC: &str = "conf-663-scrub-signature-pqc";
const PERSIST_ROW_HASH: &str = "conf-663-persist-row-hash";
const ROLE: &str = "conf-663-role";
// Distinct INSTANTS, not one instant reused — these are the three timestamp
// fields the old fixture collapsed together.
const VALID_FROM: &str = "2026-01-01T00:00:00Z";
const VALID_UNTIL: &str = "2027-02-02T00:00:00Z";
const SCRUB_TIMESTAMP: &str = "2026-03-03T00:00:00Z";
const PQC_COMPLETED_AT: &str = "2026-04-04T00:00:00Z";

/// A value no projection can legitimately expect, used to convert a `Missing`
/// into a `Mismatch` so verify reports the value it wanted. The NUL byte keeps
/// it out of every real key-id / base64 / identity-type vocabulary — and out of
/// every sentinel above, which the distinctness witness also checks.
const PROBE_SENTINEL: &str = "\u{0}ciris-persist-663-probe-sentinel";

/// Parse one of the fixed instants above into persist's typed column.
fn instant(s: &str) -> chrono::DateTime<chrono::Utc> {
    s.parse::<chrono::DateTime<chrono::Utc>>()
        .unwrap_or_else(|e| panic!("#663: fixture instant {s:?} must be RFC-3339: {e}"))
}

/// Persist's projection for this subject, as a plain map.
fn persist_projection(pqc: Option<&str>) -> Map<String, Value> {
    subject_binding(KEY_ID, IDENTITY_TYPE, ED25519, pqc)
}

/// A verify-side `KeyRecord` for the same subject. `materialize_optionals`
/// drives EVERY `Option` field, not just the PQC pubkey — so a member verify
/// starts binding off some other optional column is caught by the same probe.
fn verify_record(materialize_optionals: bool, envelope: Value) -> VerifyKeyRecord {
    let opt = |s: &str| {
        if materialize_optionals {
            Some(s.to_string())
        } else {
            None
        }
    };
    VerifyKeyRecord {
        key_id: KEY_ID.to_string(),
        pubkey_ed25519_base64: ED25519.to_string(),
        pubkey_ml_dsa_65_base64: opt(MLDSA),
        algorithm: ALGORITHM.to_string(),
        identity_type: IDENTITY_TYPE.to_string(),
        identity_ref: IDENTITY_REF.to_string(),
        valid_from: VALID_FROM.to_string(),
        valid_until: opt(VALID_UNTIL),
        registration_envelope: envelope,
        original_content_hash: ORIGINAL_CONTENT_HASH.to_string(),
        scrub_signature_classical: SCRUB_SIG_CLASSICAL.to_string(),
        scrub_signature_pqc: opt(SCRUB_SIG_PQC),
        scrub_key_id: SCRUB_KEY_ID.to_string(),
        scrub_timestamp: SCRUB_TIMESTAMP.to_string(),
        pqc_completed_at: opt(PQC_COMPLETED_AT),
        persist_row_hash: PERSIST_ROW_HASH.to_string(),
        roles: vec![ROLE.to_string()],
        additional_scrubs: Vec::new(),
    }
}

/// A persist-side `KeyRecord` for the same subject. Only the fields the subject
/// binding reads are meaningful; the binding check is pure over the row, so no
/// signature, backend or clock is involved.
fn persist_record(pqc: Option<&str>, envelope: Value) -> PersistKeyRecord {
    PersistKeyRecord {
        key_id: KEY_ID.to_string(),
        pubkey_ed25519_base64: ED25519.to_string(),
        pubkey_ml_dsa_65_base64: pqc.map(str::to_string),
        algorithm: ALGORITHM.to_string(),
        identity_type: IDENTITY_TYPE.to_string(),
        identity_ref: IDENTITY_REF.to_string(),
        valid_from: instant(VALID_FROM),
        valid_until: Some(instant(VALID_UNTIL)),
        registration_envelope: envelope,
        original_content_hash: ORIGINAL_CONTENT_HASH.to_string(),
        scrub_signature_classical: SCRUB_SIG_CLASSICAL.to_string(),
        scrub_signature_pqc: Some(SCRUB_SIG_PQC.to_string()),
        scrub_key_id: SCRUB_KEY_ID.to_string(),
        scrub_timestamp: instant(SCRUB_TIMESTAMP),
        pqc_completed_at: Some(instant(PQC_COMPLETED_AT)),
        persist_row_hash: PERSIST_ROW_HASH.to_string(),
        capability_roles: vec![ROLE.to_string()],
        attestation_evidence: None,
        consent_role: None,
        additional_scrubs: Vec::new(),
    }
}

/// **Read verify's projection off verify's own checker.**
///
/// Returns the members `check_subject_binding` enforces and the value each one
/// expects, discovered by driving `check_subject_binding` from an empty
/// envelope and feeding back every member it names. Members whose expected
/// value is `null` are invisible to this probe BY DESIGN (§0.9 tolerates their
/// omission); [`verify_optional_members`] recovers those by difference.
fn probe_verify_projection(materialize_optionals: bool) -> BTreeMap<String, Value> {
    let mut envelope = Map::new();
    let mut discovered: BTreeMap<String, Value> = BTreeMap::new();

    // Two steps per member (Missing -> sentinel -> Mismatch -> real value), so
    // this bound tolerates a projection an order of magnitude wider than
    // today's four before it gives up.
    for _ in 0..128 {
        let record = verify_record(materialize_optionals, Value::Object(envelope.clone()));
        match record.check_subject_binding() {
            // Ok is the ONLY convergence signal on this plane: the binding
            // held, so every member has been discovered.
            Ok(()) => return discovered,
            Err(source) => {
                if let Some((member, expected)) = probe_advance(source, &mut envelope) {
                    discovered.insert(member, expected);
                }
            }
        }
    }
    panic!(
        "#663: verify's subject-binding probe did not converge in 128 steps. Either the \
         projection grew past 64 members or `check` no longer reports one failing member per \
         call — read `ciris_verify_core::subject_binding` before touching this bound."
    )
}

/// **Advance the probe by one reported binding failure — the single place this
/// file interprets a [`SubjectBindingError`].**
///
/// Returns `Some((member, expected))` when verify has just revealed what it
/// expects for a member, `None` when the step only planted a sentinel.
///
/// # This match is EXHAUSTIVE on purpose (CIRISPersist#666, third codex finding)
///
/// The provenance probe used to converge on "the error stopped being a binding
/// failure", spelled as a `_` wildcard. But a **new `SubjectBindingError`
/// variant is still a binding failure** — it would have fallen through that
/// wildcard and read as successful convergence. The probe would then stop
/// early, report whatever subset it had found, and the conformance test would
/// go GREEN if that subset happened to match persist's projection.
///
/// That is the failure this file exists to prevent, triggered by the exact
/// event it exists to detect — verify changing its projection — and it degrades
/// **in the direction of agreement**, which is the direction nobody
/// investigates.
///
/// `ciris_verify_core::subject_binding::SubjectBindingError` is **not**
/// `#[non_exhaustive]`, so the fix is structural rather than defensive: this
/// match carries no wildcard, and a variant added in a future CIRISVerify is a
/// **compile error right here** instead of a silent fall-through. Both planes
/// route through this one function, so that is one compile error to resolve,
/// not two — and resolving it forces whoever bumps the pin to decide what the
/// new variant means for the probe.
///
/// If verify ever marks the enum `#[non_exhaustive]`, this stops compiling
/// without a wildcard; the replacement is a wildcard arm that **panics**, never
/// one that converges.
fn probe_advance(
    source: SubjectBindingError,
    envelope: &mut Map<String, Value>,
) -> Option<(String, Value)> {
    match source {
        SubjectBindingError::Missing { member, .. } => {
            // Non-null expectation (a null one would have been tolerated).
            // Plant a value it cannot equal so the next pass reports WHAT it
            // wanted.
            envelope.insert(member, Value::String(PROBE_SENTINEL.to_string()));
            None
        }
        SubjectBindingError::Mismatch {
            member, claimed, ..
        } => {
            let expected: Value = serde_json::from_str(&claimed).unwrap_or_else(|e| {
                panic!(
                    "#663: verify reported the value it expects for `{member}` as {claimed:?}, \
                     which is not JSON ({e}). The probe reads verify's expectation out of this \
                     field; if its encoding changed, this file must follow."
                )
            });
            envelope.insert(member.clone(), expected.clone());
            Some((member, expected))
        }
        // The probe always feeds a JSON object, so this is unreachable for a
        // correct probe — and it is a BINDING FAILURE, so it must never be
        // mistaken for convergence. Loud, not silent.
        SubjectBindingError::NotAnObject { context } => panic!(
            "#663: verify reported NotAnObject ({context}) — the binding is still FAILING, but \
             the probe feeds a JSON object at every step, so this cannot happen unless the probe \
             itself is broken. Refusing to treat a live binding failure as convergence: doing so \
             would report whatever subset had been discovered and go green on it."
        ),
    }
}

/// The members verify projects as **optional** — expected `null` when the
/// record carries nothing, and therefore satisfiable by omission. Recovered by
/// difference: they are the members that appear only once the record's
/// `Option` fields are materialized.
fn verify_optional_members() -> BTreeSet<String> {
    let all: BTreeSet<String> = probe_verify_projection(true).into_keys().collect();
    let required: BTreeSet<String> = probe_verify_projection(false).into_keys().collect();
    assert!(
        required.is_subset(&all),
        "#663: a member enforced when the record carries NO optional fields must still be \
         enforced when it carries them. required={required:?} all={all:?}"
    );
    all.difference(&required).cloned().collect()
}

/// The members persist projects as optional — the ones whose expected value is
/// JSON `null` when the row carries nothing.
fn persist_optional_members() -> BTreeSet<String> {
    persist_projection(None)
        .into_iter()
        .filter(|(_, v)| v.is_null())
        .map(|(k, _)| k)
        .collect()
}

// ── 0. The fixture's own invariant ──────────────────────────────────────────

/// Collect **every leaf** of a serialized fixture, paired with its JSON path
/// and keyed by the leaf's SERIALIZED form.
///
/// Excludes the `registration_envelope` subtree — that is the probe's
/// workspace, not a fixture field, and it legitimately repeats the values it
/// binds.
///
/// # Why every leaf, not just the strings
///
/// Codex finding on #666, and the same blind spot as the sentinel one, one
/// type-domain over: this walk used to record `Value::String` only, silently
/// discarding nulls, booleans, numbers and empty containers. A non-string member
/// derived from the wrong field with the same serialized value stayed green —
/// and `ProvenanceLink::is_self_signed` was in fact already being dropped. The
/// under-specified thing was the WALK, not the sentinels, so it is fixed at the
/// walk.
///
/// Keyed on the serialized form rather than the Rust value so a cross-type
/// coincidence is judged correctly in both directions: the string `"1"` and the
/// number `1` serialize as `"1"` and `1`, are distinguishable in
/// `Mismatch.claimed`, and so are NOT a collision; two fields carrying the same
/// JSON value collide whatever their Rust types were.
fn leaves(value: &Value, path: &str, out: &mut Vec<(String, String)>) {
    match value {
        Value::Object(map) if !map.is_empty() => {
            for (k, v) in map {
                if path.is_empty() && k == "registration_envelope" {
                    continue;
                }
                let child = if path.is_empty() {
                    k.clone()
                } else {
                    format!("{path}.{k}")
                };
                leaves(v, &child, out);
            }
        }
        Value::Array(items) if !items.is_empty() => {
            for (i, v) in items.iter().enumerate() {
                leaves(v, &format!("{path}[{i}]"), out);
            }
        }
        // Every terminal: scalars of all types AND empty containers, which are
        // values a projection can legitimately expect.
        terminal => out.push((path.to_string(), terminal.to_string())),
    }
}

/// **The detector distinguishes members BY VALUE, so the fixture must give
/// every field its own.**
///
/// Found by codex review on CIRISPersist#666. The probe recovers verify's
/// expectation out of `Mismatch.claimed`; two fields carrying the same fixture
/// value are therefore indistinguishable to it. If verify later projects
/// `identity_ref` and persist binds that member off `key_id` by mistake, a
/// fixture where both read `"conf-663-subject"` reports agreement on a
/// wrong-column bind — the exact class this file exists to catch, silently
/// un-caught. The original fixture collapsed `key_id`/`identity_ref`/
/// `scrub_key_id` into one value and three timestamps into another.
///
/// **Derived, not listed.** The check walks the SERIALIZED fixtures, so a field
/// added to either `KeyRecord` later is covered without anyone remembering to
/// extend a table here. That matters more than the current fix: the failure
/// mode is a test that keeps passing while quietly measuring less.
#[test]
fn every_fixture_field_carries_its_own_sentinel() {
    let fixtures: [(&str, Value); 3] = [
        (
            "ciris_verify_core::KeyRecord",
            serde_json::to_value(verify_record(true, Value::Object(Map::new())))
                .expect("fixture serializes"),
        ),
        (
            "ciris_persist::KeyRecord",
            serde_json::to_value(persist_record(Some(MLDSA), Value::Object(Map::new())))
                .expect("fixture serializes"),
        ),
        (
            "ciris_verify_core::ProvenanceChain",
            serde_json::to_value(verify_provenance_chain(true, Value::Object(Map::new())))
                .expect("fixture serializes"),
        ),
    ];

    for (what, fixture) in fixtures {
        // `ProvenanceChain` nests the fields under `chain[0]`, and its own
        // `key_id` is REQUIRED to equal `chain[0].key_id` — verify refuses with
        // `QueriedKeyMismatch` otherwise. That is a structural equality the
        // fixture must honour, not a sentinel collision, so the walk starts at
        // the link. (Walking from the link's own object also keeps the
        // `registration_envelope` skip working, which is keyed on the top
        // level.)
        let root = if what.ends_with("ProvenanceChain") {
            &fixture["chain"][0]
        } else {
            &fixture
        };
        let mut found = Vec::new();
        leaves(root, "", &mut found);

        assert!(
            found.len() > 5,
            "#663: {what} yielded only {} leaves — the walk is not reaching the fixture's fields, \
             which would make this witness decorative",
            found.len()
        );

        // THE WALK MUST BE TOTAL, and this is the guard that holds it total.
        //
        // Codex finding on #666: the walk recorded `Value::String` only,
        // silently dropping nulls, booleans, numbers and empty containers —
        // `ProvenanceLink::is_self_signed` was being dropped in exactly that
        // way. A field the walk never visits is a field this witness does not
        // guard, and nothing said so.
        //
        // Every serialized field must therefore contribute at least one
        // recorded leaf. This fails under a type-filtered walk rather than
        // merely measuring less, which is the difference between a fix and a
        // fix that stays fixed.
        for key in root
            .as_object()
            .unwrap_or_else(|| panic!("#663: {what} must serialize to a JSON object"))
            .keys()
            .filter(|k| k.as_str() != "registration_envelope")
        {
            assert!(
                found.iter().any(|(path, _)| path == key
                    || path.starts_with(&format!("{key}."))
                    || path.starts_with(&format!("{key}["))),
                "#663: {what}'s field `{key}` contributed NO leaf, so this witness does not guard \
                 it. The walk is dropping a value shape (a null, boolean, number or empty \
                 container) — record every terminal, not just the strings."
            );
        }

        let mut seen: BTreeMap<&str, &str> = BTreeMap::new();
        for (path, value) in &found {
            if let Some(first) = seen.insert(value.as_str(), path.as_str()) {
                panic!(
                    "#663: {what} gives `{first}` and `{path}` the SAME value {value:?}. The probe \
                     recovers verify's expectation by VALUE, so two fields sharing one value are \
                     indistinguishable to this detector: a member persist binds off the WRONG \
                     COLUMN would report agreement. Give every field its own sentinel."
                );
            }
            assert_ne!(
                value.as_str(),
                PROBE_SENTINEL,
                "#663: {what}'s `{path}` equals PROBE_SENTINEL, which would make the probe \
                 mistake a real expectation for its own planted value and mis-converge."
            );
        }
    }
}

// ── 1. The member SET and its expected VALUES ───────────────────────────────

/// **The detector.** Persist's projection must be verify's projection —
/// member for member, value for value, and with the same optional
/// disposition.
///
/// A member added on either side alone reds this. That is the whole point:
/// #663's defect was two locally-correct implementations quietly binding
/// different field sets, and nothing in either repo could see it.
#[test]
fn verify_and_persist_project_the_same_subject_members() {
    // (a) MATERIALIZED — every optional leg present, so every member verify
    //     projects is non-null and the probe sees all of them.
    let verify_all = probe_verify_projection(true);
    let persist_all: BTreeMap<String, Value> =
        persist_projection(Some(MLDSA)).into_iter().collect();

    assert!(
        !verify_all.is_empty(),
        "#663: the probe discovered NO members, which would make every assertion here vacuous. \
         `check_subject_binding` must project at least `key_id`."
    );

    let verify_names: BTreeSet<&String> = verify_all.keys().collect();
    let persist_names: BTreeSet<&String> = persist_all.keys().collect();
    assert_eq!(
        verify_names,
        persist_names,
        "#663: THE TWO IMPLEMENTATIONS BIND DIFFERENT SUBJECT MEMBERS.\n  \
         only ciris_verify_core binds: {:?}\n  \
         only persist binds:           {:?}\n\
         This is the v31.0.0 defect recurring: verify bound four members and \
         `admission::subject_binding` bound three, so a row could pass persist's door and fail \
         verify's check inside the same process. Add the missing member to \
         `src/federation/admission.rs::subject_binding` (ONE edit — every producer goes through \
         `bind_subject_into_envelope` and the checker iterates the map), or, if verify DROPPED a \
         member, decide deliberately whether persist follows.",
        verify_names.difference(&persist_names).collect::<Vec<_>>(),
        persist_names.difference(&verify_names).collect::<Vec<_>>(),
    );

    assert_eq!(
        verify_all, persist_all,
        "#663: the two implementations agree on WHICH members name the subject but disagree on \
         WHAT they expect. The member sets match, so this is a value-derivation drift — one side \
         is reading a different column, or normalizing where the other does not. Both are \
         compared against the identical subject ({KEY_ID}, {IDENTITY_TYPE})."
    );

    // (b) DISPOSITION — `require` vs `require_optional`. A member that is
    //     optional on one side and required on the other is the same class of
    //     gap as a missing member: on one implementation its absence is
    //     tolerated, on the other it is a refusal.
    assert_eq!(
        verify_optional_members(),
        persist_optional_members(),
        "#663: the two implementations disagree on which members are OPTIONAL (expected `null`, \
         satisfiable by omission under CEG §0.9) versus REQUIRED. Verify spells this \
         `require_optional`; persist spells it a `null` in the map. A member optional on one side \
         and required on the other admits on one door and refuses on the other."
    );

    // (c) The absent-optional shape, stated: with no PQC leg the probe sees
    //     the required members only, and persist's map is those PLUS an
    //     explicit `null` per optional member. Same claim, both directions.
    let verify_required: BTreeMap<String, Value> = probe_verify_projection(false);
    let persist_non_null: BTreeMap<String, Value> = persist_projection(None)
        .into_iter()
        .filter(|(_, v)| !v.is_null())
        .collect();
    assert_eq!(
        verify_required, persist_non_null,
        "#663: with the row carrying no optional legs, the members each implementation still \
         REQUIRES must be identical."
    );
}

// ── 2. CEG §0.9, pinned ─────────────────────────────────────────────────────

/// One row of the shared conformance vector. Written as data so CIRISVerify can
/// adopt the identical cases against its own implementation (CIRISVerify#254).
struct Ceg09Case {
    /// What the case is about, quoted in every failure.
    what: &'static str,
    /// What the SIGNED envelope binds for the optional PQC leg — `None` means
    /// the member is OMITTED from the envelope entirely (not materialized as
    /// `null`, which is the distinction §0.9 is about).
    envelope_binds: Option<&'static str>,
    /// What the ROW (the carrier) claims.
    row_claims: Option<&'static str>,
    /// The pinned verdict. `true` = the binding holds.
    admit: bool,
}

/// **The CEG §0.9 omit-vs-materialize contract, as persist adopted it from
/// CIRISVerify 13.1.0.**
///
/// An expected `null` is satisfied by an OMITTED member — and ONLY then. This
/// is the sole tolerated absence anywhere in the projection, and it is
/// tolerated because a legitimate JCS producer omits rather than materializes
/// a null, so its signed bytes genuinely differ.
///
/// The three rows that make that a carve-out rather than "an omitted member is
/// never checked" are pinned here against BOTH implementations, so a future
/// "simplification" to flat fail-closed — or to flat tolerance — reds. Either
/// direction is a divergence: fail-closed refuses records verify admits, and
/// flat tolerance re-opens the skippable-by-omission hole rule 3 exists to
/// close.
#[test]
fn ceg_0_9_omit_vs_materialize_is_the_pinned_contract() {
    const OTHER_MLDSA: &str = "MLDSA65-SOMEONE-ELSE";
    let cases = [
        // The carve-out. Both sides say NOTHING, which is agreement rather
        // than tolerance.
        Ceg09Case {
            what: "envelope OMITS the PQC leg and the row claims nothing",
            envelope_binds: None,
            row_claims: None,
            admit: true,
        },
        // The envelope is silent; the carrier is not. This is the downgrade
        // direction — a PQC key the co-scrubbers never signed for, attached
        // outside the signed bytes.
        Ceg09Case {
            what: "envelope OMITS the PQC leg but the row claims a key",
            envelope_binds: None,
            row_claims: Some(MLDSA),
            admit: false,
        },
        // The envelope declares a leg the carrier drops — the asymmetric
        // direction, and how a downgrade would sneak in.
        Ceg09Case {
            what: "envelope DECLARES a PQC leg but the row claims nothing",
            envelope_binds: Some(MLDSA),
            row_claims: None,
            admit: false,
        },
        // Controls, so the table cannot pass by refusing (or admitting)
        // everything.
        Ceg09Case {
            what: "envelope and row declare the SAME PQC leg",
            envelope_binds: Some(MLDSA),
            row_claims: Some(MLDSA),
            admit: true,
        },
        Ceg09Case {
            what: "envelope and row declare DIFFERENT PQC legs",
            envelope_binds: Some(OTHER_MLDSA),
            row_claims: Some(MLDSA),
            admit: false,
        },
    ];

    for case in cases {
        let mut envelope = bound_envelope(case.row_claims);
        let obj = envelope
            .as_object_mut()
            .expect("bound_envelope is an object");
        match case.envelope_binds {
            Some(v) => {
                obj.insert(
                    "pubkey_ml_dsa_65_base64".to_string(),
                    Value::String(v.to_string()),
                );
            }
            None => {
                obj.remove("pubkey_ml_dsa_65_base64");
            }
        }

        let persist =
            verify_envelope_binds_subject(&persist_record(case.row_claims, envelope.clone()));
        let verified = verify_record(false, envelope)
            .clone_with_pqc(case.row_claims)
            .check_subject_binding();

        assert_eq!(
            persist.is_ok(),
            case.admit,
            "#663/CEG §0.9: persist must {} when {}. Verdict: {persist:?}",
            if case.admit { "ADMIT" } else { "REFUSE" },
            case.what,
        );
        assert_eq!(
            verified.is_ok(),
            case.admit,
            "#663/CEG §0.9: ciris_verify_core must {} when {}. Verdict: {verified:?}",
            if case.admit { "ADMIT" } else { "REFUSE" },
            case.what,
        );
        assert_eq!(
            persist.is_ok(),
            verified.is_ok(),
            "#663/CEG §0.9: the two implementations DISAGREE when {}. persist={persist:?} \
             verify={verified:?}",
            case.what,
        );
    }
}

// ── 3. Every member, both failure shapes, both implementations ──────────────

/// **Exhaustive by construction.** For every member the projection binds, and
/// for a row both with and without its optional legs, assert that a DIVERGING
/// value and an OMITTED member produce the same verdict on both
/// implementations — and, when refused, that persist's refusal names the same
/// member verify named.
///
/// The member list is read off `subject_binding` rather than restated, so a
/// fifth member is covered the day it is added, on both failure shapes, with
/// no edit here.
#[test]
fn every_projected_member_agrees_across_both_implementations() {
    for row_pqc in [None, Some(MLDSA)] {
        let projection = persist_projection(row_pqc);
        assert!(
            !projection.is_empty(),
            "#663: an empty projection would make this loop vacuous"
        );

        // The coherent baseline both implementations must admit.
        let baseline = bound_envelope(row_pqc);
        verify_envelope_binds_subject(&persist_record(row_pqc, baseline.clone()))
            .expect("#663: a fully bound envelope must pass persist's check");
        verify_record(false, baseline.clone())
            .clone_with_pqc(row_pqc)
            .check_subject_binding()
            .expect("#663: a fully bound envelope must pass verify's check");

        for member in projection.keys() {
            // (i) DIVERGE — the envelope binds a value naming a different
            //     subject. Refused by both, always, for every member.
            let mut diverged = baseline.clone();
            diverged
                .as_object_mut()
                .expect("object")
                .insert(member.clone(), Value::String(format!("DIVERGENT-{member}")));
            let p = verify_envelope_binds_subject(&persist_record(row_pqc, diverged.clone()));
            let v = verify_record(false, diverged)
                .clone_with_pqc(row_pqc)
                .check_subject_binding();
            let why = p.as_ref().err().cloned().unwrap_or_default();
            assert!(
                p.is_err() && v.is_err(),
                "#663: an envelope binding a DIFFERENT `{member}` names a different subject and \
                 must be refused by both. persist={p:?} verify={v:?}"
            );
            assert!(
                why.contains(member.as_str()),
                "#663: persist's refusal must NAME the member that disagreed (`{member}`), or an \
                 operator cannot tell which subject was substituted: {why}"
            );
            assert!(
                matches!(&v, Err(SubjectBindingError::Mismatch { member: m, .. }) if m == member),
                "#663: verify must refuse on the SAME member persist names (`{member}`): {v:?}"
            );

            // (ii) OMIT — the envelope does not carry the member at all. Both
            //     implementations refuse UNLESS the projection expects `null`
            //     here, which is the single CEG §0.9 carve-out and is decided
            //     by the projection itself rather than a hard-coded name.
            let mut omitted = baseline.clone();
            omitted.as_object_mut().expect("object").remove(member);
            let expects_null = projection[member].is_null();
            let p = verify_envelope_binds_subject(&persist_record(row_pqc, omitted.clone()));
            let v = verify_record(false, omitted)
                .clone_with_pqc(row_pqc)
                .check_subject_binding();
            assert_eq!(
                p.is_ok(),
                expects_null,
                "#663: persist must {} an envelope omitting `{member}` (projection expects {}). \
                 An optional check is skippable by omission, which is the whole attack — the ONE \
                 exception is an expected `null`, where both sides say nothing. Verdict: {p:?}",
                if expects_null { "ADMIT" } else { "REFUSE" },
                projection[member],
            );
            assert_eq!(
                p.is_ok(),
                v.is_ok(),
                "#663: the two implementations disagree on an envelope OMITTING `{member}`. \
                 persist={p:?} verify={v:?}"
            );
            if let Err(why) = &p {
                assert!(
                    why.contains(member.as_str()),
                    "#663: persist's refusal must name the ABSENT binding `{member}`: {why}"
                );
                assert!(
                    matches!(&v, Err(SubjectBindingError::Missing { member: m, .. }) if m == member),
                    "#663: verify must refuse the same absence on `{member}`: {v:?}"
                );
            }
        }
    }
}

// ── 4. The PROVENANCE plane — the producer/checker seam ─────────────────────

/// A single-link provenance chain for the same subject. Only the binding
/// matters: `check` runs FIRST in verify's per-link loop, before the hash, the
/// signatures and any terminus resolution (rule 4), so the probe never needs a
/// real signature.
fn verify_provenance_chain(materialize_optionals: bool, envelope: Value) -> ProvenanceChain {
    let opt = |s: &str| {
        if materialize_optionals {
            Some(s.to_string())
        } else {
            None
        }
    };
    ProvenanceChain {
        key_id: KEY_ID.to_string(),
        chain: vec![ProvenanceLink {
            key_id: KEY_ID.to_string(),
            pubkey_ed25519_base64: ED25519.to_string(),
            pubkey_ml_dsa_65_base64: opt(MLDSA),
            identity_type: IDENTITY_TYPE.to_string(),
            identity_ref: IDENTITY_REF.to_string(),
            registration_envelope: envelope,
            original_content_hash: ORIGINAL_CONTENT_HASH.to_string(),
            scrub_signature_classical: SCRUB_SIG_CLASSICAL.to_string(),
            scrub_signature_pqc: opt(SCRUB_SIG_PQC),
            // The terminus rule wants `scrub_key_id == key_id` on a
            // self-signed link. That is a REAL equality this fixture must
            // honour, so the link deliberately breaks it and declares itself
            // non-terminal — the walk then refuses on structure, AFTER the
            // binding, which is all the probe needs (rule 4).
            scrub_key_id: SCRUB_KEY_ID.to_string(),
            scrub_timestamp: SCRUB_TIMESTAMP.to_string(),
            is_self_signed: false,
        }],
        terminates_at_steward_bootstrap: false,
    }
}

/// **Read verify's PROVENANCE-link projection off verify's own walk.**
///
/// Same technique as [`probe_verify_projection`], driven through
/// `verify_provenance_chain` instead. The convergence signal differs: this walk
/// cannot return `Ok` without a real signature, so the probe stops when the
/// error stops being `SubjectBindingFailed` — at which point the binding has
/// been satisfied and some later check (hash, linkage, terminus, signature) is
/// speaking instead.
fn probe_verify_provenance_projection(materialize_optionals: bool) -> BTreeMap<String, Value> {
    let mut envelope = Map::new();
    let mut discovered: BTreeMap<String, Value> = BTreeMap::new();

    for _ in 0..128 {
        let chain = verify_provenance_chain(materialize_optionals, Value::Object(envelope.clone()));
        match provenance_binding_verdict(&chain) {
            Ok(()) => return discovered,
            Err(source) => {
                if let Some((member, expected)) = probe_advance(source, &mut envelope) {
                    discovered.insert(member, expected);
                }
            }
        }
    }
    panic!(
        "#663: verify's provenance subject-binding probe did not converge in 128 steps — read \
         `ciris_verify_core::provenance` before touching this bound."
    )
}

/// **The SUBJECT-BINDING verdict from a provenance walk**, isolated from every
/// later check.
///
/// `Err(source)` iff the walk refused on the binding; `Ok(())` for every other
/// outcome, which means the binding for link 0 PASSED and some later check
/// (hash, linkage, terminus, signature) is speaking instead. The fixture
/// deliberately cannot satisfy those — it carries no real signature — and they
/// are not this file's business.
///
/// No trusted bootstrap keys are passed: the binding is checked long before any
/// anchor resolution, which is the property verify's rule 4 exists to give.
///
/// # Exhaustive on purpose
///
/// The convergence side lists all fifteen non-binding variants rather than `_`.
/// `ProvenanceError` is not `#[non_exhaustive]`, so a variant added in a future
/// CIRISVerify is a **compile error here**, forcing whoever bumps the pin to
/// classify it as "binding failure" or "later check". A wildcard would classify
/// it silently, as convergence, which is the direction that goes green. This is
/// the ONLY place that list appears, so it is one compile error to resolve.
fn provenance_binding_verdict(chain: &ProvenanceChain) -> Result<(), SubjectBindingError> {
    match ciris_verify_core::provenance::verify_provenance_chain(chain, &[]) {
        Err(ProvenanceError::SubjectBindingFailed { source, .. }) => Err(source),
        Ok(())
        | Err(
            ProvenanceError::EmptyChain
            | ProvenanceError::OverDepth { .. }
            | ProvenanceError::QueriedKeyMismatch
            | ProvenanceError::BrokenLink { .. }
            | ProvenanceError::SelfSignedMidChain { .. }
            | ProvenanceError::TerminusNotSelfSigned
            | ProvenanceError::TerminusNotSteward { .. }
            | ProvenanceError::BadContentHash { .. }
            | ProvenanceError::ContentHashMismatch { .. }
            | ProvenanceError::BadSignatureEncoding { .. }
            | ProvenanceError::BadKeyEncoding { .. }
            | ProvenanceError::ParentMissingPqcKey { .. }
            | ProvenanceError::ScrubSignatureInvalid { .. }
            | ProvenanceError::UntrustedAnchor { .. }
            | ProvenanceError::LinkNotHybrid { .. },
        ) => Ok(()),
    }
}

/// The members verify's PROVENANCE walk treats as **optional** — recovered by
/// the same difference [`verify_optional_members`] uses on the key-record
/// plane.
fn provenance_optional_members() -> BTreeSet<String> {
    let all: BTreeSet<String> = probe_verify_provenance_projection(true)
        .into_keys()
        .collect();
    let required: BTreeSet<String> = probe_verify_provenance_projection(false)
        .into_keys()
        .collect();
    assert!(
        required.is_subset(&all),
        "#663: a member the provenance walk enforces with NO optional legs materialized must \
         still be enforced when they are. required={required:?} all={all:?}"
    );
    all.difference(&required).cloned().collect()
}

/// A persist-produced envelope with `member` **OMITTED** rather than
/// materialized as `null` — the distinction CEG §0.9 is entirely about, and the
/// one [`bound_envelope`] cannot express because persist's producer always
/// materializes.
fn envelope_omitting(pqc: Option<&str>, member: &str) -> Value {
    let mut envelope = bound_envelope(pqc);
    envelope
        .as_object_mut()
        .expect("bound_envelope is an object")
        .remove(member);
    envelope
}

/// **The provenance plane binds what persist produces.**
///
/// Persist does not re-implement this walk (#465 routed it through verify), so
/// there is no second checker here. There IS a second half: persist MINTS every
/// `registration_envelope` the walk inspects, through `bind_subject_into_envelope`
/// off `subject_binding`. If verify widens this projection and persist's
/// producer does not follow, every chain persist mints stops rooting — a
/// federation-wide outage delivered by a dependency bump.
///
/// Asserted both ways: the member set verify's walk enforces equals the set
/// persist produces, AND an envelope built by persist's producer actually
/// satisfies the walk's binding.
#[test]
fn verify_provenance_plane_binds_exactly_what_persist_produces() {
    let provenance = probe_verify_provenance_projection(true);
    let produced: BTreeMap<String, Value> = persist_projection(Some(MLDSA)).into_iter().collect();

    assert!(
        !provenance.is_empty(),
        "#663: the provenance probe discovered NO members, which would make this vacuous."
    );
    assert_eq!(
        provenance, produced,
        "#663: verify's PROVENANCE-link subject binding and persist's producer disagree. Persist \
         mints every `registration_envelope` this walk inspects (via `bind_subject_into_envelope`, \
         off `subject_binding`), so a member the walk requires and the producer does not stamp \
         means EVERY CHAIN PERSIST MINTS STOPS ROOTING — delivered by a dependency bump, with \
         nothing else in either repo asserting the two stay aligned."
    );

    // Verify's two checker planes must also agree with each other. They are
    // separate `.require(…)` chains in verify's source (`federation_self_record`
    // and `provenance.rs:420`); nothing in verify pins them together either.
    assert_eq!(
        probe_verify_projection(true),
        provenance,
        "#663: `KeyRecord::check_subject_binding` and the provenance walk project DIFFERENT \
         members. They are separate builder chains in verify's own source, so they can drift from \
         each other — and persist produces ONE envelope that must satisfy both."
    );

    // ...and they must agree on DISPOSITION, not only on the member set.
    //
    // Codex finding on #666: comparing only the MATERIALIZED probes leaves the
    // `require` / `require_optional` split unpinned across planes. If the
    // provenance chain alone spelled a leg `.require(...)`, both materialized
    // probes still converge identically and this test passes — while an
    // envelope that OMITS that member is admitted by the key-record check and
    // REFUSED by the provenance walk. That is a live divergence between
    // verify's two planes, and pinning them against each other is exactly what
    // this test claims to do.
    assert_eq!(
        probe_verify_provenance_projection(false),
        probe_verify_projection(false),
        "#663: verify's two planes REQUIRE different members once the record's optional legs are \
         absent. The materialized sets agree, so this is a `require` vs `require_optional` split \
         between `federation_self_record` and `provenance.rs` — an envelope omitting the member \
         would pass one plane and fail the other."
    );
    assert_eq!(
        provenance_optional_members(),
        persist_optional_members(),
        "#663: the provenance walk and persist's producer disagree on which members are OPTIONAL. \
         Persist materializes `null` for its optional legs, so a member the walk REQUIRES while \
         persist calls it optional is not caught by the member-set comparison above — it is \
         caught here."
    );

    // The round trip: what persist's producer actually emits satisfies the
    // walk's binding, for a row with and without its optional leg.
    for row_pqc in [None, Some(MLDSA)] {
        let chain = provenance_chain_for(row_pqc, bound_envelope(row_pqc));
        if let Err(source) = provenance_binding_verdict(&chain) {
            panic!(
                "#663: an envelope built by persist's OWN producer must satisfy verify's \
                 provenance-link binding (row_pqc={row_pqc:?}): {source}"
            );
        }
    }

    // CEG §0.9 ON THE PROVENANCE PLANE — the case `bound_envelope` structurally
    // cannot produce.
    //
    // Codex finding on #666: persist's producer ALWAYS materializes, so
    // `bound_envelope(None)` emits `pubkey_ml_dsa_65_base64: null` and the round
    // trip above never drives OMISSION. Omission is the only thing that
    // distinguishes `require_optional` from `require`, so without these legs the
    // round trip cannot tell the two apart.
    //
    // Driven off `persist_optional_members()` rather than a hard-coded name, so
    // a second optional member is covered the day it exists.
    for member in persist_optional_members() {
        // (a) envelope omits + row claims nothing ⇒ ADMIT. Both say nothing,
        //     which is agreement, and it is the ONE tolerated absence.
        let chain = provenance_chain_for(None, envelope_omitting(None, &member));
        if let Err(source) = provenance_binding_verdict(&chain) {
            panic!(
                "#663/§0.9: the provenance walk must ADMIT an envelope that OMITS `{member}` when \
                 the link claims nothing either — a legitimate JCS producer omits rather than \
                 materializes a null. Refusing here diverges from the key-record plane, which \
                 admits it: {source}"
            );
        }

        // (b) envelope omits + row claims a key ⇒ REFUSE. The downgrade
        //     direction: a leg the chain never signed for, attached outside the
        //     signed bytes.
        let chain = provenance_chain_for(Some(MLDSA), envelope_omitting(Some(MLDSA), &member));
        let source = provenance_binding_verdict(&chain).expect_err(
            "#663/§0.9: the provenance walk must REFUSE an envelope that omits a leg the link \
             CLAIMS — tolerating that is the skippable-by-omission hole",
        );
        assert!(
            matches!(&source, SubjectBindingError::Missing { member: m, .. } if *m == member),
            "#663/§0.9: the provenance refusal must name the absent member `{member}`: {source}"
        );
    }
}

/// A provenance chain whose link carries `pqc` as its ML-DSA leg and `envelope`
/// as its registration envelope — the link's own claim and the signed bytes set
/// independently, which is what every §0.9 case needs.
fn provenance_chain_for(pqc: Option<&str>, envelope: Value) -> ProvenanceChain {
    let mut chain = verify_provenance_chain(false, envelope);
    chain.chain[0].pubkey_ml_dsa_65_base64 = pqc.map(str::to_string);
    chain
}

/// An envelope that binds every projected member for this subject, built
/// through persist's PRODUCING side so the fixture cannot become a second
/// spelling of the projection.
fn bound_envelope(pqc: Option<&str>) -> Value {
    let mut envelope = Value::Object(Map::new());
    ciris_persist::federation::admission::bind_subject_into_envelope(
        &mut envelope,
        KEY_ID,
        IDENTITY_TYPE,
        ED25519,
        pqc,
    )
    .expect("#663: binding into a fresh JSON object cannot fail");
    envelope
}

/// Verify's `KeyRecord` is built with every optional field driven together (so
/// the probe can sweep them); the conformance cases need the PQC leg set
/// independently of the rest.
trait WithPqc {
    fn clone_with_pqc(self, pqc: Option<&str>) -> Self;
}

impl WithPqc for VerifyKeyRecord {
    fn clone_with_pqc(mut self, pqc: Option<&str>) -> Self {
        self.pubkey_ml_dsa_65_base64 = pqc.map(str::to_string);
        self
    }
}
