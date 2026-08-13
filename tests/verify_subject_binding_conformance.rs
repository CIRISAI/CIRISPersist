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
//! # MUTATION-TESTED — 5 mutations of the checked code, 5 killed
//!
//! A conformance test that passes under divergence is worse than none, because
//! it certifies an agreement that does not exist. So the detector was checked
//! against the divergences it claims to catch, each applied to
//! `src/federation/admission.rs` and re-read off disk before running:
//!
//! | mutation | tests red |
//! | --- | --- |
//! | drop `identity_type` from `subject_binding` (the literal v31.0.0 defect) | 3 of 3 |
//! | bind `identity_type` off the `key_id` column (right member, wrong value) | 2 of 3 |
//! | bind the absent PQC leg as `""` instead of `null` (optional ⇒ required) | 3 of 3 |
//! | flatten §0.9 to unconditional refusal (fail-closed "simplification") | 2 of 3 |
//! | flatten §0.9 to unconditional tolerance (the other direction) | 2 of 3 |
//!
//! The first mutation also proves the probe is not vacuous: it reports
//! `only ciris_verify_core binds: ["identity_type"]`, so the probe really did
//! discover all four of verify's members off verify's own behaviour.
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
use ciris_verify_core::subject_binding::SubjectBindingError;
use serde_json::{Map, Value};

// ── The one subject both implementations are asked about ────────────────────
//
// Deliberately distinguishable per field: a projection that bound the wrong
// column would still produce a set-equal map if every value were the same
// string, so the VALUE comparison needs values that cannot be confused.

const KEY_ID: &str = "conf-663-subject";
const IDENTITY_TYPE: &str = "canonical,node";
const ED25519: &str = "ED25519-LEG-conf-663";
const MLDSA: &str = "MLDSA65-LEG-conf-663";

/// A value no projection can legitimately expect, used to convert a `Missing`
/// into a `Mismatch` so verify reports the value it wanted. The NUL byte keeps
/// it out of every real key-id / base64 / identity-type vocabulary.
const PROBE_SENTINEL: &str = "\u{0}ciris-persist-663-probe-sentinel";

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
        algorithm: "hybrid-ed25519-mldsa65".to_string(),
        identity_type: IDENTITY_TYPE.to_string(),
        identity_ref: KEY_ID.to_string(),
        valid_from: "2026-01-01T00:00:00Z".to_string(),
        valid_until: opt("2027-01-01T00:00:00Z"),
        registration_envelope: envelope,
        original_content_hash: String::new(),
        scrub_signature_classical: "SCRUB-CLASSICAL".to_string(),
        scrub_signature_pqc: opt("SCRUB-PQC"),
        scrub_key_id: KEY_ID.to_string(),
        scrub_timestamp: "2026-01-01T00:00:00Z".to_string(),
        pqc_completed_at: opt("2026-01-01T00:00:00Z"),
        persist_row_hash: String::new(),
        roles: Vec::new(),
        additional_scrubs: Vec::new(),
    }
}

/// A persist-side `KeyRecord` for the same subject. Only the fields the subject
/// binding reads are meaningful; the binding check is pure over the row, so no
/// signature, backend or clock is involved.
fn persist_record(pqc: Option<&str>, envelope: Value) -> PersistKeyRecord {
    let t = "2026-01-01T00:00:00Z"
        .parse::<chrono::DateTime<chrono::Utc>>()
        .expect("fixed RFC-3339 instant");
    PersistKeyRecord {
        key_id: KEY_ID.to_string(),
        pubkey_ed25519_base64: ED25519.to_string(),
        pubkey_ml_dsa_65_base64: pqc.map(str::to_string),
        algorithm: "hybrid-ed25519-mldsa65".to_string(),
        identity_type: IDENTITY_TYPE.to_string(),
        identity_ref: KEY_ID.to_string(),
        valid_from: t,
        valid_until: None,
        registration_envelope: envelope,
        original_content_hash: String::new(),
        scrub_signature_classical: "SCRUB-CLASSICAL".to_string(),
        scrub_signature_pqc: None,
        scrub_key_id: KEY_ID.to_string(),
        scrub_timestamp: t,
        pqc_completed_at: None,
        persist_row_hash: String::new(),
        capability_roles: Vec::new(),
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
            Ok(()) => return discovered,
            Err(SubjectBindingError::Missing { member, .. }) => {
                // Non-null expectation (a null one would have been tolerated).
                // Plant a value it cannot equal so the next pass reports WHAT
                // it wanted.
                envelope.insert(member, Value::String(PROBE_SENTINEL.to_string()));
            }
            Err(SubjectBindingError::Mismatch {
                member, claimed, ..
            }) => {
                let expected: Value = serde_json::from_str(&claimed).unwrap_or_else(|e| {
                    panic!(
                        "#663: verify reported the value it expects for `{member}` as {claimed:?}, \
                         which is not JSON ({e}). The probe reads verify's expectation out of this \
                         field; if its encoding changed, this file must follow."
                    )
                });
                envelope.insert(member.clone(), expected.clone());
                discovered.insert(member, expected);
            }
            Err(other) => panic!(
                "#663: the probe feeds verify a JSON object and every member it asks for, so the \
                 only outcomes are Missing, Mismatch and Ok. Got: {other}"
            ),
        }
    }
    panic!(
        "#663: verify's subject-binding probe did not converge in 128 steps. Either the \
         projection grew past 64 members or `check` no longer reports one failing member per \
         call — read `ciris_verify_core::subject_binding` before touching this bound."
    )
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
