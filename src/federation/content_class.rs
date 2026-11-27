//! v31.0.0 (CIRISPersist#612, CC 4.5.13 / CC 3.3.12 / CC 3.4.14) — the
//! **`content_class:*` flag-plane read predicate**.
//!
//! v62.0.0 (KR-fix46; Constitution's ruling on F2, 11-24) — `content_class:*`
//! is an unreserved open-vocabulary family with NO duty at its door: there is
//! no `infra:classify_content` duty. The conferral arm described below
//! (a withdrawal clearing another emitter's flag only from a key holding
//! `infra:classify_content` from a root this node trusts) is DELETED. A flag
//! is withdrawn by the rules every row is withdrawn by (CC 2.4.1.1: rule 1 its
//! author, rule 2 a subject it names, rule 0 the same count where it was a
//! room's counted act), judged at the door when the `withdraws` / `recants`
//! arrives and read here through the one consolidated retraction fold
//! (`precedence::retired_ids`). The history below is kept as it was written.
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
//! | **clear ANOTHER emitter's flag** | reveal (fail-OPEN) | v31: only a holder of `infra:classify_content` conferred by a root **this node** trusts; v62.0.0 (KR-fix46): nobody by a `withdrawn` marking: an admitted `withdraws` / `recants` under the generic rules (rule 1 / 2 / 0) |
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
//! observes. v62.0.0 (KR-fix46): it now DOES fold `withdraws` / `recants` on
//! flag rows, through `precedence::retired_ids` (the door admitted each under
//! rule 1 / 2 / 0; the fold's own entitlement check drops one that is not).

use std::collections::BTreeMap;

use super::attestation_query::{AttestationQuery, FOLD_PAGE};
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
    /// v62.0.0 (KR-fix46; replaces `cleared_by`, a clean break) — the row ids
    /// of RAISES retired by an admitted `withdraws` / `recants` (rule 1 its
    /// author, rule 2 a subject it names, rule 0 the same count), through the
    /// consolidated retraction fold. Sorted, deduped.
    pub retired_raises: Vec<String>,
    /// Emitters whose latest row is a `withdrawn` marking while another
    /// emitter's raise stands: it cancels that emitter's OWN prior raise
    /// (per-emitter latest-wins) and clears nobody else's. v62.0.0 (KR-fix46):
    /// no key holds a duty over another's flag. Sorted.
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
/// `dimension` for `subject_key_id`. v62.0.0 (KR-fix46): a raise stands until
/// its emitter's own later `withdrawn` row, or until an admitted `withdraws` /
/// `recants` retires it under the rules every row is withdrawn by; no
/// conferral is asked (the `infra:classify_content` arm is deleted).
///
/// See the [module docs](self) for the asymmetry this implements and why it is
/// asymmetric. The backing read is
/// [`list_attestations_for`](crate::federation::attestation_query::AttestationQuery::to)
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
    // The subject's `scores` rows on exactly this dimension: the only rows
    // the latest-wins fold below keeps.
    let mut rows = Vec::new();
    let mut pages = AttestationQuery::to(subject_key_id, FOLD_PAGE)
        .types(&[attestation_type::SCORES])
        .dimension(dimension)
        .pages();
    while let Some(page) = pages.next(directory).await? {
        rows.extend(page);
    }

    // v62.0.0 (KR-fix46; Constitution's ruling on F2: there is no
    // `infra:classify_content` duty) — a flag is WITHDRAWN by the rules every
    // row is withdrawn by: rule 1 (its author), rule 2 (a subject it names),
    // rule 0 (the same count where it was the room's counted act). The door
    // judges each `withdraws` / `recants` under those rules when it arrives;
    // this read retires a row only through the ONE consolidated retraction
    // fold every other plane reads (`precedence::retired_ids`, its
    // entitlement check included). A retired raise is not live.
    let ids: Vec<String> = rows.iter().map(|r| r.attestation_id.clone()).collect();
    let composers = if ids.is_empty() {
        Vec::new()
    } else {
        directory
            .list_composers_referencing_any(&ids, None, None)
            .await?
    };
    let retired = {
        let refs: Vec<&Attestation> = rows.iter().chain(composers.iter()).collect();
        super::precedence::retired_ids(&refs)
    };

    // Per-emitter latest-wins over the live rows. An emitter speaks with one
    // voice on one dimension: its newest live row is its statement, and a
    // later `withdrawn` of its own is its own retraction (rule 1's reading).
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
        if retired.contains(&att.attestation_id) {
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

    let mut raised_by: Vec<String> = Vec::new();
    let mut refused_withdrawals: Vec<String> = Vec::new();
    let any_raise = latest.values().any(|att| !is_withdrawal(att));
    for (emitter, att) in &latest {
        if is_withdrawal(att) {
            // A `withdrawn` row by an emitter whose own raise it is not
            // clears nothing of anyone else's: no key holds a duty over
            // another's flag (KR-fix46). Recorded when a raise stands.
            if any_raise {
                refused_withdrawals.push((*emitter).to_owned());
            }
        } else {
            raised_by.push((*emitter).to_owned());
        }
    }
    let mut retired_raises: Vec<String> = rows
        .iter()
        .filter(|r| retired.contains(&r.attestation_id) && !is_withdrawal(r))
        .map(|r| r.attestation_id.clone())
        .collect();
    retired_raises.sort();
    retired_raises.dedup();

    Ok(ContentClassFlag {
        flagged: !raised_by.is_empty(),
        raised_by,
        retired_raises,
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
    ) -> crate::federation::Attestation {
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
        let att = crate::federation::tier_ingest::test_support::seal_row(
            emitter,
            crate::federation::Attestation {
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
            },
        );
        // v62.0.0 — the sealed row is an edition-2 statement (E0's flip):
        // it enters through the statement door.
        crate::federation::edition2::fixture_switch::put_signed(dir, &att)
            .await
            .expect("an open-vocabulary content_class row admits from any emitter (#571)");
        att
    }

    async fn fold(
        dir: &dyn FederationDirectory,
        subject: &str,
        dimension: &str,
    ) -> ContentClassFlag {
        // v62.0.0 — the rows name the subject by its kid.
        let subject = crate::federation::edition2::fixture_switch::kid_or_keep(subject);
        dir.resolve_content_class_flag(&subject, dimension, chrono::Utc::now())
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
        use crate::federation::edition2::fixture_switch::kid;
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
        let first_raise = emit(dir, &raiser, &subject, DIM, false, t(1)).await;
        let raised = fold(dir, &subject, DIM).await;
        assert!(
            raised.flagged && raised.raised_by == vec![kid(&raiser)],
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
            vec![kid(&stranger)],
            "({tag}) the refusal is legible, not silent: {forged:?}"
        );
        assert!(
            forged.retired_raises.is_empty(),
            "({tag}) nothing retired the raise: {forged:?}"
        );

        // (3) CC 3.4.14 R1's mandatory `generated` marking rides the SAME
        // family and must not read as an infohazard flag.
        emit(dir, &stranger, &subject, GENERATED_DIM, false, t(3)).await;
        let still = fold(dir, &subject, DIM).await;
        assert_eq!(
            still.raised_by,
            vec![kid(&raiser)],
            "({tag}) exact-dimension: a `generated` marking is not a flag: {still:?}"
        );
        let generated = fold(dir, &subject, GENERATED_DIM).await;
        assert!(
            generated.flagged && generated.raised_by == vec![kid(&stranger)],
            "({tag}) and the `generated` plane folds on its own: {generated:?}"
        );

        // (4) v62.0.0 (KR-fix46) — no duty clears another's flag: the deleted
        // arm let a key holding `infra:classify_content` from a root this node
        // trusts clear it with a `withdrawn` marking. Now a classifier holding
        // that very conferral clears nothing that way.
        crate::federation::admission::r2_test_support::confer_scope_from_trusted_root(
            dir,
            node,
            &format!("cc-root-{tag}"),
            &kid(&classifier),
            crate::federation::types::delegation_scope::INFRA_CLASSIFY_CONTENT,
        )
        .await;
        emit(dir, &classifier, &subject, DIM, true, t(4)).await;
        let conferred_try = fold(dir, &subject, DIM).await;
        assert!(
            conferred_try.flagged
                && conferred_try
                    .refused_withdrawals
                    .contains(&kid(&classifier)),
            "({tag}) KR-fix46: a conferred classifier's `withdrawn` marking clears nothing of \
             another's flag: {conferred_try:?}"
        );

        // (5) Rule 2: the SUBJECT the flag names withdraws it (`withdraws`,
        // admitted under the generic rules); the raise is retired and the
        // plane is clear.
        let w = crate::federation::edition2::fixture_switch::composer_of(
            crate::federation::types::attestation_type::WITHDRAWS,
            &first_raise,
            &subject,
        );
        crate::federation::edition2::fixture_switch::put_signed(dir, &w)
            .await
            .unwrap_or_else(|e| panic!("({tag}) rule 2: the subject's withdraws is admitted: {e}"));
        let cleared = fold(dir, &subject, DIM).await;
        assert!(
            !cleared.flagged && cleared.retired_raises == vec![first_raise.attestation_id.clone()],
            "({tag}) rule 2: the subject's withdraws retires the raise: {cleared:?}"
        );

        // (6) A new raise stands again, and rule 1: its AUTHOR's own
        // `withdraws` retires it. A stranger's `withdraws` of a third raise
        // retires nothing (refused or held at the door; the fold's own
        // entitlement check drops it either way).
        let second = emit(dir, &raiser, &subject, DIM, false, t(5)).await;
        let re_raised = fold(dir, &subject, DIM).await;
        assert!(
            re_raised.flagged && re_raised.raised_by == vec![kid(&raiser)],
            "({tag}) a new raise re-flags: {re_raised:?}"
        );
        let own = crate::federation::edition2::fixture_switch::composer_of(
            crate::federation::types::attestation_type::WITHDRAWS,
            &second,
            &raiser,
        );
        crate::federation::edition2::fixture_switch::put_signed(dir, &own)
            .await
            .unwrap_or_else(|e| panic!("({tag}) rule 1: the author's withdraws is admitted: {e}"));
        assert!(
            !fold(dir, &subject, DIM).await.flagged,
            "({tag}) rule 1: the author's withdraws retires its raise"
        );
        let third = emit(dir, &raiser, &subject, DIM, false, t(6)).await;
        let foreign = crate::federation::edition2::fixture_switch::composer_of(
            crate::federation::types::attestation_type::WITHDRAWS,
            &third,
            &stranger,
        );
        let _ = crate::federation::edition2::fixture_switch::put_signed(dir, &foreign).await;
        let stands = fold(dir, &subject, DIM).await;
        assert!(
            stands.flagged && !stands.retired_raises.contains(&third.attestation_id),
            "({tag}) a stranger's withdraws retires nobody's flag: {stands:?}"
        );

        // (7) The family stem itself is refused — folding it would read CC
        // 3.4.14 R1's mandatory marking as a flag.
        let err = dir
            .resolve_content_class_flag(&kid(&subject), super::FAMILY_STEM, chrono::Utc::now())
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
            7,
            "the ladder is the §11.10 rungs plus the v42.0.0 issuance axis (license, grant — \
             CIRISPersist#814 part 4); #612 added a CAPABILITY scope, which is a different \
             axis and still must NOT appear here"
        );
        assert!(
            delegation_scope::INFRA_CLASSIFY_CONTENT.starts_with(delegation_scope::INFRA_PREFIX),
            "the intended holder is a NODE, and a node key may carry only infra:*"
        );
        assert!(
            crate::federation::admission::scopes_are_infra_only(
                &std::iter::once(delegation_scope::INFRA_CLASSIFY_CONTENT.to_owned()).collect()
            ),
            "CC 3.4.7.3 / CC 4.4.3.4.3 — a pure node delegate can actually hold it"
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
