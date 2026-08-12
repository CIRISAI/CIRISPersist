//! v31.0.0 (CIRISPersist#612, CC 4.5.13 / CC 3.3.12 / CC 3.4.14) — the
//! **`content_class:*` flag-plane read predicate**, and the conferral that
//! makes its clearing arm safe to federate.
//!
//! # The defect this closes
//!
//! CIRISPersist#571 removed persist's CEG-0.3 emitter rule on `content_class:`
//! because CC 3.3.12 catalogues the family as **open vocabulary** and CC 3.4.14
//! R1 makes the `generated` / `generated_modified` marking universal — *every*
//! attester — so the old `substrate_persist`-only gate refused the very row the
//! Constitution makes mandatory. The v28.3.0 note that shipped with it said, in
//! as many words: *"If you relied on persist's write gate to keep these families
//! trustworthy, that enforcement is gone by design. **Discriminate on read.**"*
//!
//! CIRISServer#363 relied on it, and reported the fail-open **driven end to end
//! through the real `put_attestation` door**: an ordinary admitted `agent`-typed
//! key authored `content_class:infohazard:v1 {"withdrawn": true}` naming a
//! subject it had never flagged, persist admitted the row, and the CC 4.5.13
//! reveal gate — folding the family latest-wins with no emitter predicate —
//! returned `Allow`.
//!
//! The read door persist offered for the sibling family,
//! [`FederationDirectory::lookup_trusted_publisher_chain`](super::FederationDirectory::lookup_trusted_publisher_chain),
//! is shape-wrong for this one: it is scoped to `content_rating:*` dimensions
//! **and** keyed by a hex `content_sha256` in `evidence_refs`, while these rows
//! are `content_class:*` keyed on the **subject**. It cannot see them at all.
//! This module is the missing door.
//!
//! # The asymmetry, and why it is the whole design
//!
//! A flag on this plane means WITHHOLD. So the two directions are not
//! symmetric, and treating them as one latest-wins fold is exactly the bug:
//!
//! | motion | direction | who may |
//! |---|---|---|
//! | **raise** — a `content_class:{class}` row | withhold (fail-CLOSED) | **any** emitter |
//! | **retract own raise** — the same emitter's later `withdrawn: true` | back to status quo ante | **any** emitter |
//! | **clear ANOTHER emitter's flag** | reveal (fail-OPEN) | only a holder of [`INFRA_CLASSIFY_CONTENT`] conferred by a root **this node** trusts |
//!
//! Filtering RAISES by conferral would be the fail-open mistake in reverse: an
//! unconferred stranger's protective flag would silently vanish from the read,
//! and over-withholding is the safe error on a CC 4.5.13 child-safety gate.
//! Refusing an unconferred SELF-retraction would be the other failure — an
//! emitter that cannot take back its own statement is a permanent,
//! un-appealable withholding lever handed to anyone with a key.
//!
//! What is left is precisely the arm CIRISServer#363 could not build soundly:
//! *"a peer CIRISServer's legitimate flag and a stranger's forged one are
//! indistinguishable to us"*. It is now distinguishable, and the discriminator
//! is [`capability_roots_to_trusted_root`](super::trust_root::capability_roots_to_trusted_root)
//! — resolved at USE, per read, against a root **the asking node itself**
//! accepts.
//!
//! # Exact dimension, never the family stem
//!
//! The fold matches the caller's `dimension` **exactly**. Prefix-matching
//! `content_class:` would fuse every class into one flag — and since CC 3.4.14
//! R1 makes `content_class:generated:v1` mandatory on machine-authored
//! Contributions, a family-wide fold would read every lawful AI-disclosure
//! marking as an infohazard flag. One name, two meanings is the class this repo
//! keeps closing; here it would have been one FOLD over two vocabularies.
//!
//! # What this module does NOT do
//!
//! It does not adjudicate. CC 3.4.14 R5 puts a false or stripped marking in
//! front of a WA quorum on the `hard_case:*` evidence floor; the substrate
//! observes. Nor does it fold `withdraws`/`recants` **tombstones** on flag rows
//! — only the envelope's `withdrawn` field, which is the mechanism the flag
//! plane actually uses. Ignoring tombstones is fail-CLOSED in both directions (a
//! tombstoned raise still reads as raised, and a stranger's tombstone on someone
//! else's raise buys nothing), so the omission over-withholds rather than
//! over-reveals.

use std::collections::BTreeMap;

use super::types::{attestation_type, delegation_scope};
use super::{Attestation, Error, FederationDirectory};

/// The family stem this module folds. Every `dimension` accepted by
/// [`resolve_content_class_flag`] must begin with it.
pub const FAMILY_STEM: &str = "content_class:";

/// The envelope field that turns a `content_class:*` row from a RAISE into a
/// WITHDRAWAL. Only the JSON boolean `true` counts: absent, `false`, or any
/// non-boolean value reads as a raise, because on a withhold plane a malformed
/// retraction must not reveal.
pub const WITHDRAWN_FIELD: &str = "withdrawn";

/// v31.0.0 (CIRISPersist#612) — the folded state of one
/// `content_class:{class}` plane for one subject, as **this node** is entitled
/// to read it.
///
/// [`flagged`](Self::flagged) is the answer a CC 4.5.13 reveal gate acts on;
/// the other three fields exist so the refusal is legible rather than silent —
/// a consumer that sees `flagged == true` with a non-empty
/// [`refused_withdrawals`](Self::refused_withdrawals) is looking at an attempted
/// clear by a key with no conferred authority, which is a security event, not a
/// data condition.
#[derive(Debug, Clone, Default, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub struct ContentClassFlag {
    /// Does a live raise stand? `true` ⇒ WITHHOLD.
    pub flagged: bool,
    /// Emitters whose latest live row on this dimension is a raise that has not
    /// been cleared by an authoritative withdrawal. Sorted, deduped.
    pub raised_by: Vec<String>,
    /// The emitter whose conferred withdrawal cleared the plane (the LATEST
    /// such, when several hold the scope), if any. `Some` with `flagged == true`
    /// means a raise landed AFTER the clear — latest-wins, in the protective
    /// direction.
    pub cleared_by: Option<String>,
    /// Emitters whose withdrawal was **not** honoured as authority over other
    /// emitters' markings, for want of a conferred
    /// [`INFRA_CLASSIFY_CONTENT`](super::types::delegation_scope::INFRA_CLASSIFY_CONTENT).
    /// Such a row still cancels that emitter's OWN prior raise (per-emitter
    /// latest-wins); what it cannot do is clear anyone else's. Sorted, deduped.
    pub refused_withdrawals: Vec<String>,
}

/// The envelope `dimension` of `att`, or `None` when absent / not a string.
#[must_use]
pub fn dimension_of(att: &Attestation) -> Option<&str> {
    att.attestation_envelope
        .get("dimension")
        .and_then(serde_json::Value::as_str)
}

/// Is `att` a WITHDRAWAL on the flag plane — i.e. does its envelope carry
/// [`WITHDRAWN_FIELD`] as the JSON boolean `true`? Everything else is a RAISE;
/// see [`WITHDRAWN_FIELD`] for why the tolerance runs that way.
#[must_use]
pub fn is_withdrawal(att: &Attestation) -> bool {
    att.attestation_envelope
        .get(WITHDRAWN_FIELD)
        .and_then(serde_json::Value::as_bool)
        .unwrap_or(false)
}

/// v31.0.0 (CIRISPersist#612) — fold the `content_class` flag plane named by
/// `dimension` for `subject_key_id`, honouring a cross-emitter clear only from a
/// key holding
/// [`INFRA_CLASSIFY_CONTENT`](super::types::delegation_scope::INFRA_CLASSIFY_CONTENT)
/// from a trust root **this directory's own node** accepts.
///
/// See the [module docs](self) for the asymmetry this implements and why it is
/// asymmetric. The backing read is
/// [`list_attestations_for`](FederationDirectory::list_attestations_for)
/// (`attested_key_id = subject`), the same about-subject read the trust walk
/// itself uses, so there is one notion of "rows about this subject" rather than
/// two that can drift.
///
/// # Errors
///
/// - [`Error::InvalidArgument`] if `dimension` is not under [`FAMILY_STEM`] —
///   a caller asking this fold about `consent:state:` or a bare
///   `content_class:` stem is asking the wrong question, and answering it would
///   fuse two vocabularies.
/// - [`Error::NodeIdentityUnset`] if the directory does not know which key it
///   is. The conferral is resolved against **this node's** trust root, so
///   without an identity there is no question to answer — and a silent
///   `flagged: false` would be indistinguishable from "nothing flagged", which
///   is the exact confusion #611 rejected for the publisher chain.
/// - Any backend / walk error propagates. A caller that cannot complete the
///   fold must withhold.
pub async fn resolve_content_class_flag<F>(
    directory: &F,
    subject_key_id: &str,
    dimension: &str,
    now: chrono::DateTime<chrono::Utc>,
) -> Result<ContentClassFlag, Error>
where
    F: FederationDirectory + ?Sized,
{
    if !dimension.starts_with(FAMILY_STEM) || dimension.len() <= FAMILY_STEM.len() {
        return Err(Error::InvalidArgument(format!(
            "resolve_content_class_flag folds ONE fully-qualified {FAMILY_STEM}* dimension \
             (e.g. \"content_class:infohazard:v1\"); got {dimension:?}. Folding the family stem \
             would read CC 3.4.14 R1's mandatory `content_class:generated` marking as a flag."
        )));
    }
    // Resolved against THIS node's trust root, so the directory must know who it
    // is — the #611 decision, applied to the second read door of its class.
    let node = directory.node_key_id().ok_or(Error::NodeIdentityUnset {
        method: "resolve_content_class_flag",
        needed_for: "resolving each withdrawing emitter's infra:classify_content conferral \
                     against this node's own trust root",
    })?;

    let rows = directory.list_attestations_for(subject_key_id).await?;

    // Per-emitter latest-wins FIRST. An emitter speaks with one voice on one
    // dimension: its newest live row is its statement, and a later `withdrawn`
    // of its own is a retraction that needs no conferral (see the module docs).
    let mut latest: BTreeMap<&str, &Attestation> = BTreeMap::new();
    for att in &rows {
        if att.attestation_type != attestation_type::SCORES {
            continue;
        }
        if dimension_of(att) != Some(dimension) {
            continue;
        }
        if att.expires_at.is_some_and(|exp| exp <= now) {
            continue;
        }
        latest
            .entry(att.attesting_key_id.as_str())
            .and_modify(|cur| {
                if att.asserted_at > cur.asserted_at {
                    *cur = att;
                }
            })
            .or_insert(att);
    }

    let mut raises: Vec<(&str, chrono::DateTime<chrono::Utc>)> = Vec::new();
    let mut withdrawals: Vec<(&str, chrono::DateTime<chrono::Utc>)> = Vec::new();
    for (emitter, att) in &latest {
        if is_withdrawal(att) {
            withdrawals.push((emitter, att.asserted_at));
        } else {
            raises.push((emitter, att.asserted_at));
        }
    }

    // The ONE conferral question, asked per withdrawing emitter and never
    // cached: a conferral withdrawn between two reads must stop clearing on the
    // second one.
    let mut cleared_by: Option<String> = None;
    let mut cleared_at: Option<chrono::DateTime<chrono::Utc>> = None;
    let mut refused_withdrawals: Vec<String> = Vec::new();
    for (emitter, at) in &withdrawals {
        let conferred = super::trust_root::capability_roots_to_trusted_root(
            directory,
            &node,
            emitter,
            delegation_scope::INFRA_CLASSIFY_CONTENT,
        )
        .await?;
        if conferred.is_none() {
            refused_withdrawals.push((*emitter).to_owned());
            continue;
        }
        if cleared_at.is_none_or(|prev| *at > prev) {
            cleared_at = Some(*at);
            cleared_by = Some((*emitter).to_owned());
        }
    }

    // A raise NEWER than the authoritative clear stands again — latest-wins, in
    // the protective direction.
    let raised_by: Vec<String> = raises
        .iter()
        .filter(|(_, at)| cleared_at.is_none_or(|c| *at > c))
        .map(|(emitter, _)| (*emitter).to_owned())
        .collect();

    Ok(ContentClassFlag {
        flagged: !raised_by.is_empty(),
        raised_by,
        cleared_by,
        refused_withdrawals,
    })
}

/// v31.0.0 (CIRISPersist#612) — the ONE #612 witness body, run against every
/// backend rather than copied per backend.
///
/// The door is a default trait method composed from trait-required reads, so
/// memory / sqlite / postgres inherit one implementation — but "inherits the
/// same default" is a claim about the code, and the thing being asserted is a
/// claim about the STORE: a backend whose `list_attestations_for` orders,
/// truncates or filters differently folds differently. A fixture written three
/// slightly different ways proves the gate on one backend and silently not on
/// the others, which is this repo's recurring class
/// (`feedback_test_every_backend_not_just_memory`).
#[cfg(all(test, any(feature = "sqlite", feature = "postgres")))]
pub(crate) mod parity_test_support {
    use super::{ContentClassFlag, FederationDirectory};

    /// The dimension the CC 4.5.13 reveal gate folds — CIRISServer#363's own.
    const DIM: &str = "content_class:infohazard:v1";
    /// CC 3.4.14 R1's mandatory marking. On the SAME family, and it must never
    /// be mistaken for a flag (the exact-dimension rule).
    const GENERATED_DIM: &str = "content_class:generated:v1";

    /// Write one `content_class` row about `subject`, signed by `emitter` so it
    /// clears federation-tier ingest on every backend.
    async fn emit(
        dir: &dyn FederationDirectory,
        emitter: &str,
        subject: &str,
        dimension: &str,
        withdrawn: bool,
        at: chrono::DateTime<chrono::Utc>,
    ) {
        let id = uuid::Uuid::new_v4().to_string();
        let envelope = if withdrawn {
            serde_json::json!({
                "id": id, "dimension": dimension, "score": 1.0, "confidence": 0.9,
                super::WITHDRAWN_FIELD: true,
            })
        } else {
            serde_json::json!({
                "id": id, "dimension": dimension, "score": 1.0, "confidence": 0.9,
            })
        };
        let (och, sc, sp) =
            crate::federation::tier_ingest::test_support::sign_envelope(emitter, &envelope);
        let att = crate::federation::Attestation {
            attestation_id: id,
            attesting_key_id: emitter.to_owned(),
            attested_key_id: subject.to_owned(),
            attestation_type: crate::federation::types::attestation_type::SCORES.to_owned(),
            weight: Some(1.0),
            asserted_at: at,
            expires_at: None,
            attestation_envelope: envelope,
            original_content_hash: och,
            scrub_signature_classical: sc,
            scrub_signature_pqc: sp,
            scrub_key_id: emitter.to_owned(),
            scrub_timestamp: at,
            pqc_completed_at: Some(at),
            persist_row_hash: String::new(),
            subject_key_ids: Vec::new(),
            withdraws_admission_rule: None,
            cohort_scope: crate::federation::types::cohort_scope::FEDERATION.to_owned(),
            tier: crate::federation::types::attestation_tier::FEDERATION.to_owned(),
            promoted_at: None,
            additional_scrubs: Vec::new(),
        };
        dir.put_attestation(crate::federation::SignedAttestation { attestation: att })
            .await
            .expect("an open-vocabulary content_class row admits from any emitter (#571)");
    }

    async fn fold(
        dir: &dyn FederationDirectory,
        subject: &str,
        dimension: &str,
    ) -> ContentClassFlag {
        dir.resolve_content_class_flag(subject, dimension, chrono::Utc::now())
            .await
            .expect("fold")
    }

    /// CIRISPersist#612 — GateSpec:
    ///
    /// - **family** — `content_class:*`, frame `flag_plane`: the CC 4.5.13
    ///   reveal predicate, whose clearing arm had no emitter discriminator.
    /// - **headwaters** — `put_attestation` (the open write door #571 left
    ///   open) × `resolve_content_class_flag` (the read door this cut adds).
    /// - **references** — #612, CIRISServer#363, #611 (the same shape on
    ///   `content_rating:`), #571 (why the write gate is gone).
    /// - **dye test** — step 2 IS the dye test: it fails on a fold with no
    ///   conferral check, which is the code CIRISServer shipped and reported.
    /// - **depth** — proves the clearing arm. Says nothing about `withdraws`
    ///   tombstones, which the door deliberately does not fold.
    /// - **owner** — persist.
    pub(crate) async fn assert_content_class_flag_plane(
        dir: &dyn FederationDirectory,
        node: &str,
        tag: &str,
    ) {
        use crate::federation::tier_ingest::test_support::register_hybrid_key;

        let subject = format!("cc-subject-{tag}");
        let raiser = format!("cc-raiser-{tag}");
        let stranger = format!("cc-stranger-{tag}");
        let classifier = format!("cc-classifier-{tag}");
        for k in [&subject, &raiser, &stranger, &classifier] {
            register_hybrid_key(dir, k).await;
        }
        // Past, ascending, whole seconds — postgres stores microseconds and a
        // sub-microsecond tie would make "latest" backend-dependent (#634).
        let base = chrono::Utc::now() - chrono::Duration::seconds(600);
        let t = |n: i64| base + chrono::Duration::seconds(n);

        // (0) Nothing said → nothing flagged. The distinguished empty answer.
        let clean = fold(dir, &subject, DIM).await;
        assert!(
            !clean.flagged && clean.raised_by.is_empty() && clean.refused_withdrawals.is_empty(),
            "({tag}) an unmentioned subject is unflagged: {clean:?}"
        );

        // (1) Any emitter may RAISE. An ordinary `agent`-typed key, unconferred
        // — protective, so conferral must NOT be required here.
        emit(dir, &raiser, &subject, DIM, false, t(1)).await;
        let raised = fold(dir, &subject, DIM).await;
        assert!(
            raised.flagged && raised.raised_by == vec![raiser.clone()],
            "({tag}) an unconferred emitter's protective flag must stand: {raised:?}"
        );

        // (2) **THE WITNESS.** CIRISServer#363's exact attack: an ordinary
        // admitted `agent`-typed key withdraws a flag naming a subject it never
        // flagged. Latest-wins by `asserted_at` — so a fold without the
        // conferral check returns `flagged: false` here, which is the reported
        // `Allow`.
        emit(dir, &stranger, &subject, DIM, true, t(2)).await;
        let forged = fold(dir, &subject, DIM).await;
        assert!(
            forged.flagged,
            "({tag}) #612: a stranger's withdrawal must NOT clear a flag it did not raise \
             — this is the CIRISServer#363 fail-open: {forged:?}"
        );
        assert_eq!(
            forged.refused_withdrawals,
            vec![stranger.clone()],
            "({tag}) the refusal is legible, not silent: {forged:?}"
        );
        assert!(
            forged.cleared_by.is_none(),
            "({tag}) nothing authoritative cleared it: {forged:?}"
        );

        // (3) CC 3.4.14 R1's mandatory `generated` marking rides the SAME
        // family and must not read as an infohazard flag.
        emit(dir, &stranger, &subject, GENERATED_DIM, false, t(3)).await;
        let still = fold(dir, &subject, DIM).await;
        assert_eq!(
            still.raised_by,
            vec![raiser.clone()],
            "({tag}) exact-dimension: a `generated` marking is not a flag: {still:?}"
        );
        let generated = fold(dir, &subject, GENERATED_DIM).await;
        assert!(
            generated.flagged && generated.raised_by == vec![stranger.clone()],
            "({tag}) and the `generated` plane folds on its own: {generated:?}"
        );

        // (4) The FEDERATED arm #612 exists for: a peer holding
        // `infra:classify_content` from a root THIS node accepts clears it.
        crate::federation::admission::r2_test_support::confer_scope_from_trusted_root(
            dir,
            node,
            &format!("cc-root-{tag}"),
            &classifier,
            crate::federation::types::delegation_scope::INFRA_CLASSIFY_CONTENT,
        )
        .await;
        emit(dir, &classifier, &subject, DIM, true, t(4)).await;
        let cleared = fold(dir, &subject, DIM).await;
        assert!(
            !cleared.flagged,
            "({tag}) a conferred classifier's withdrawal clears the plane: {cleared:?}"
        );
        assert_eq!(
            cleared.cleared_by.as_deref(),
            Some(classifier.as_str()),
            "({tag}) and names who cleared it: {cleared:?}"
        );

        // (5) A raise NEWER than the authoritative clear stands again —
        // latest-wins, in the protective direction.
        emit(dir, &raiser, &subject, DIM, false, t(5)).await;
        let re_raised = fold(dir, &subject, DIM).await;
        assert!(
            re_raised.flagged && re_raised.raised_by == vec![raiser.clone()],
            "({tag}) a raise after the clear re-flags: {re_raised:?}"
        );

        // (6) Scope isolation — the conferral is for THIS token. A classifier
        // holding `infra:detect` instead could clear a child-safety flag, which
        // is exactly the reuse #612 declined.
        let detector = format!("cc-detector-{tag}");
        register_hybrid_key(dir, &detector).await;
        crate::federation::admission::r2_test_support::confer_scope_from_trusted_root(
            dir,
            node,
            &format!("cc-root-{tag}"),
            &detector,
            crate::federation::types::delegation_scope::INFRA_DETECT,
        )
        .await;
        emit(dir, &detector, &subject, DIM, true, t(6)).await;
        let detect_try = fold(dir, &subject, DIM).await;
        assert!(
            detect_try.flagged,
            "({tag}) `infra:detect` is not classification authority: {detect_try:?}"
        );
        assert!(
            detect_try.refused_withdrawals.contains(&detector),
            "({tag}) and the refusal is recorded: {detect_try:?}"
        );

        // (7) The family stem itself is refused — folding it would read CC
        // 3.4.14 R1's mandatory marking as a flag.
        let err = dir
            .resolve_content_class_flag(&subject, super::FAMILY_STEM, chrono::Utc::now())
            .await
            .expect_err("the bare family stem is not a fold-able dimension");
        assert_eq!(err.kind(), "federation_invalid_argument", "({tag}) {err}");
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn att(envelope: serde_json::Value) -> Attestation {
        Attestation {
            attestation_id: "a".into(),
            attesting_key_id: "e".into(),
            attested_key_id: "s".into(),
            attestation_type: attestation_type::SCORES.into(),
            weight: None,
            asserted_at: chrono::Utc::now(),
            expires_at: None,
            attestation_envelope: envelope,
            original_content_hash: String::new(),
            scrub_signature_classical: String::new(),
            scrub_signature_pqc: None,
            scrub_key_id: "e".into(),
            scrub_timestamp: chrono::Utc::now(),
            pqc_completed_at: None,
            persist_row_hash: String::new(),
            subject_key_ids: Vec::new(),
            withdraws_admission_rule: None,
            cohort_scope: "federation".into(),
            tier: "federation".into(),
            promoted_at: None,
            additional_scrubs: Vec::new(),
        }
    }

    /// Only the JSON boolean `true` retracts. Everything else is a RAISE,
    /// because on a withhold plane a malformed retraction must not reveal.
    #[test]
    fn only_boolean_true_withdraws() {
        assert!(is_withdrawal(&att(serde_json::json!({"withdrawn": true}))));
        for benign in [
            serde_json::json!({}),
            serde_json::json!({"withdrawn": false}),
            serde_json::json!({"withdrawn": "true"}),
            serde_json::json!({"withdrawn": 1}),
            serde_json::json!({"withdrawn": null}),
        ] {
            assert!(
                !is_withdrawal(&att(benign.clone())),
                "a malformed retraction must read as a raise: {benign}"
            );
        }
    }

    /// The scope this module gates is on the CAPABILITY axis, and the
    /// classification gate (`types::tests::every_delegation_scope_const_is_classified`)
    /// only asserts that it is classified SOMEWHERE. This asserts WHICH axis —
    /// a later edit that moves it onto the moderation ladder has to come here
    /// and read why it is not one.
    #[test]
    fn classify_content_is_a_capability_scope_not_a_moderation_rung() {
        assert!(
            delegation_scope::INFRA.contains(&delegation_scope::INFRA_CLASSIFY_CONTENT),
            "content classification is capability of the holder"
        );
        assert!(
            !delegation_scope::MODERATION.contains(&delegation_scope::INFRA_CLASSIFY_CONTENT),
            "a content-class marking is an epistemic statement, not a moderation act — \
             see INFRA_CLASSIFY_CONTENT's axis test"
        );
        assert_eq!(
            delegation_scope::MODERATION.len(),
            5,
            "the ladder is still the five §11.10 rungs; #612 added a CAPABILITY scope"
        );
        assert!(
            delegation_scope::INFRA_CLASSIFY_CONTENT.starts_with(delegation_scope::INFRA_PREFIX),
            "the intended holder is a NODE, and a node key may carry only infra:*"
        );
        assert!(
            crate::federation::admission::scopes_are_infra_only(
                &std::iter::once(delegation_scope::INFRA_CLASSIFY_CONTENT.to_owned()).collect()
            ),
            "CC 1.13.5 / CC 4.4.3.4.3 — a pure node delegate can actually hold it"
        );
    }

    /// The dimension `resolve_content_class_flag` folds is exactly one class.
    #[test]
    fn family_stem_is_the_prefix_of_the_dimension_the_issue_names() {
        assert!("content_class:infohazard:v1".starts_with(FAMILY_STEM));
        assert!("content_class:generated:v1".starts_with(FAMILY_STEM));
        assert_ne!("content_class:infohazard:v1", "content_class:generated:v1");
    }
}
