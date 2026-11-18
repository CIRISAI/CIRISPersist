//! v62.0.0 (slice C) — **the owner seat**: who owns a node, as the kernel's
//! seat over the node's key (`ciris_kernel::seat::Seats::holders`, scope
//! `owner`, object `Obj::Key(node)`).
//!
//! CC 3.2, *The first binding (MUST)*: "an owner-binding counts toward
//! ownership only when the node's own key cosigned it, or the node's genesis
//! record carries it"; CC 2.7.5: a seat is two consents. An owner binding
//! `delegates_to(O → N)` is presented as the OFFER of the seat by its
//! conferrer, the object's own key `N` (`Conf::Own`), with `O`'s signature as
//! the acceptance carried on the same row. The kernel reads the conferrer as
//! the row's `signer()` and the acceptance from `cosigners()`, so a binding
//! whose verified signatures include `N` is presented with `N` as its signer
//! and `O` among its cosigners; one `N` never signed keeps `O` as its signer
//! and the seat rule refuses it (`O` is no own key of `N`) — the ruled
//! departure (C557, I1834).
//!
//! What stays persist's here, as the reader's present and the key plane: a
//! binding's expiry and a lapsed `valid_until` (the caller's clock), whether
//! the granter is a `user` key, and the envelope's owner-binding marker
//! (a row's own shape). Retractions are the kernel's: each binding's
//! composers are folded by the CC 3.5.1 default (`derived::fold_default`, one
//! signer's chain at a time), and a winning `withdraws` / `recants` is a
//! withdrawal the seat rule concludes only when its signer signed the binding
//! or is the key it seats. A granter's own retraction about the node (a
//! `withdraws` naming the node, not the row) withdraws every binding of that
//! granter's to the node.
//!
//! **The genesis-record path** (v62.0.0, kernel pass 2, K1, I2818): a
//! binding the node's genesis record carries counts as the node's consent,
//! as its cosignature does ([`owner_rows_with_genesis`]: presented with the
//! node as the conferrer). The caller hands the carried bindings' row ids
//! in; no persist reader produces them yet — the genesis payload rule (which
//! member of the node's genesis record carries its first binding) is CC's
//! and has not landed (`edition2::genesis` module docs) — so the doors call
//! [`owner_rows`], which carries none (K1 notes).

use super::law::{seat_law, SEAT_OWNER};
use super::view::{micros, KRow, NoCut, RowId, SeatFields};
use super::Answer;
use crate::federation::types::{attestation_type, Attestation};
use ciris_kernel::derived::fold_default;
use ciris_kernel::graph::Graph;
use ciris_kernel::layers::{self, Concluded};
use ciris_kernel::seat::{seat_rule, Conf, Obj, SeatKind, Seats};
use std::collections::{BTreeMap, BTreeSet};

/// The verified signatures on a row: its signer (scrub #1) and every
/// additional scrub. The caller has verified them at ingest
/// (`verify_row_hybrid_signature` re-verifies the full set).
fn verified_voices(a: &Attestation) -> BTreeSet<String> {
    let mut v: BTreeSet<String> = a
        .additional_scrubs
        .iter()
        .map(|s| s.scrub_key_id.clone())
        .collect();
    v.insert(a.attesting_key_id.clone());
    v.insert(a.scrub_key_id.clone());
    v
}

/// The CC 3.5.1 order of the three structural composers.
fn rank(k: &str) -> u8 {
    match k {
        attestation_type::RECANTS => 3,
        attestation_type::WITHDRAWS => 2,
        attestation_type::SUPERSEDES => 1,
        _ => 0,
    }
}

/// The `withdraws_admission_rule` of an admitted ownerless-lock reclaim
/// (`federation::ownership_reclaim`, CC 3.2).
const RECLAIM_RULE: u8 = 5;

/// Whether the node's cosignature is read from the row or assumed.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Cosign {
    /// The rule (CC 3.2, the first binding): the node's key must be among
    /// the binding's verified signatures.
    Required,
    /// Every binding presented as if the node had cosigned it — the
    /// differential's counterfactual, isolating the C557 departure from
    /// every other reading (test builds only).
    Assumed,
}

/// The rows the owner seat of `node` is read from: one offer per binding the
/// reader's present admits, one withdrawal per winning retraction. No
/// binding is carried by the node's genesis record
/// ([`owner_rows_with_genesis`]).
#[must_use]
pub fn owner_rows(
    node: &str,
    rows: &[Attestation],
    retractions_about_node: &[Attestation],
    now: chrono::DateTime<chrono::Utc>,
    is_user: &dyn Fn(&str) -> bool,
    cosign: Cosign,
) -> Vec<KRow> {
    owner_rows_with_genesis(
        node,
        rows,
        retractions_about_node,
        now,
        is_user,
        cosign,
        &BTreeSet::new(),
    )
}

/// v62.0.0 (kernel pass 2, K1, I2818) — [`owner_rows`], where
/// `genesis_carried` holds the row ids of the owner bindings the node's
/// genesis record carries. CC 3.2, *The first binding (MUST)*: "an
/// owner-binding counts toward ownership only when the node's own key
/// cosigned it, or the node's genesis record carries it": a carried binding
/// is presented as conferred by the node (its signer the node, the owner's
/// signature the acceptance), whether or not the node cosigned it.
#[must_use]
pub fn owner_rows_with_genesis(
    node: &str,
    rows: &[Attestation],
    retractions_about_node: &[Attestation],
    now: chrono::DateTime<chrono::Utc>,
    is_user: &dyn Fn(&str) -> bool,
    cosign: Cosign,
    genesis_carried: &BTreeSet<RowId>,
) -> Vec<KRow> {
    owner_rows_with_voices(
        node,
        rows,
        retractions_about_node,
        now,
        is_user,
        cosign,
        genesis_carried,
        &BTreeMap::new(),
    )
}

/// v62.0.0 (wave V1, I3283) — [`owner_rows_with_genesis`], where
/// `held_voices` maps a binding's `attestation_id` to the signers (`iss`) of
/// its edition-2 VOICES (`edition2::voices::row_voice_issuers`). In edition 2
/// the node's cosignature on an owner binding is its own statement over the
/// binding's payload (RULINGS: "with the node's own statement as the second
/// voice"), held in `ceg_statements`, not an `additional_scrubs` entry: each
/// held voice joins the binding's verified signatures. Every held voice was
/// verified at its door.
#[allow(clippy::too_many_arguments)]
#[must_use]
pub fn owner_rows_with_voices(
    node: &str,
    rows: &[Attestation],
    retractions_about_node: &[Attestation],
    now: chrono::DateTime<chrono::Utc>,
    is_user: &dyn Fn(&str) -> bool,
    cosign: Cosign,
    genesis_carried: &BTreeSet<RowId>,
    held_voices: &BTreeMap<String, BTreeSet<String>>,
) -> Vec<KRow> {
    // CC 3.2, the ownerless-lock reclaim: a third-party `withdraws` the door
    // admitted only on a verified m-of-n reclaim quorum (rule 5) ends the
    // binding. The kernel has no cell for that count; the quorum is
    // signature verification, persist's, so a reclaimed binding is not
    // presented (KERNEL_SEAMS §8; reported to the CC session).
    let reclaimed: std::collections::BTreeSet<&str> = rows
        .iter()
        .filter(|r| {
            r.attestation_type == attestation_type::WITHDRAWS
                && r.withdraws_admission_rule == Some(RECLAIM_RULE)
        })
        .filter_map(|r| {
            crate::federation::precedence::references_attestation_id_from_envelope(
                &r.attestation_envelope,
            )
        })
        .collect();
    let bindings: Vec<&Attestation> = rows
        .iter()
        .filter(|r| !reclaimed.contains(r.attestation_id.as_str()))
        .filter(|r| {
            r.attestation_type == attestation_type::DELEGATES_TO
                && r.attested_key_id == node
                && crate::federation::admission::is_owner_binding_envelope(&r.attestation_envelope)
                && r.expires_at.is_none_or(|exp| exp > now)
                && !crate::federation::admission::delegation_valid_until_lapsed(
                    &r.attestation_envelope,
                    now,
                )
                && is_user(&r.attesting_key_id)
        })
        .collect();
    let id_of: BTreeMap<&str, RowId> = bindings
        .iter()
        .map(|b| (b.attestation_id.as_str(), super::view::row_id(b)))
        .collect();
    let mut out: Vec<KRow> = Vec::with_capacity(bindings.len());
    for b in &bindings {
        let mut voices = verified_voices(b);
        if let Some(held) = held_voices.get(b.attestation_id.as_str()) {
            voices.extend(held.iter().cloned());
        }
        let id = id_of[b.attestation_id.as_str()];
        let node_cosigned =
            cosign == Cosign::Assumed || voices.contains(node) || genesis_carried.contains(&id);
        let signer = if node_cosigned {
            node.to_owned()
        } else {
            b.attesting_key_id.clone()
        };
        let cosigners: Vec<String> = voices.into_iter().filter(|k| *k != signer).collect();
        out.push(
            KRow::new(id, Vec::new(), signer)
                .at(micros(b.asserted_at))
                .with_seat(SeatFields {
                    to: vec![b.attesting_key_id.clone()],
                    scope: Some(SEAT_OWNER.into()),
                    obj: Some(Obj::Key(node.to_owned())),
                    conf: Some(Conf::Own),
                    cosigners,
                    ..SeatFields::of(SeatKind::Offer)
                }),
        );
    }
    // the composers naming a binding, folded one signer's chain at a time
    let composers: Vec<KRow> = rows
        .iter()
        .filter(|r| crate::federation::precedence::is_structural_composer(&r.attestation_type))
        // CC 3.2: a node cannot outrun its owner — the node's own retraction
        // of its owner binding is no withdrawal of the seat (a node has no
        // agency; the ownerless-lock reclaim is the ceremony that ends it)
        .filter(|r| r.attesting_key_id != node)
        .filter_map(|r| {
            let t = crate::federation::precedence::references_attestation_id_from_envelope(
                &r.attestation_envelope,
            )?;
            let target = *id_of.get(t)?;
            let mut k = KRow::new(
                super::view::row_id(r),
                vec![target],
                r.attesting_key_id.clone(),
            )
            .at(micros(r.asserted_at));
            k.seat.target = Some(target);
            k.seat.policy = Some(r.attestation_type.clone());
            Some(k)
        })
        .collect();
    let cg = Concluded::with(Graph::new(composers.iter()), None);
    let all: Vec<usize> = (0..cg.g.len()).collect();
    let winners = fold_default(
        &cg,
        &all,
        |r: &KRow| r.seat.target,
        |r: &KRow| rank(r.seat.policy.as_deref().unwrap_or("")),
        |r: &KRow| r.at,
    );
    for (_, i) in winners {
        let w = cg.g.row(i);
        if rank(w.seat.policy.as_deref().unwrap_or("")) >= 2 {
            let mut wd = w.clone();
            wd.seat.kind = SeatKind::Withdraw;
            out.push(wd);
        }
    }
    // a granter's own retraction about the node withdraws its bindings
    for g in retractions_about_node {
        if (g.attestation_type == attestation_type::WITHDRAWS
            || g.attestation_type == attestation_type::RECANTS)
            && g.attested_key_id == node
        {
            for b in bindings
                .iter()
                .filter(|b| b.attesting_key_id == g.attesting_key_id)
            {
                let target = id_of[b.attestation_id.as_str()];
                let id = RowId::of_label(&[
                    "granter-retraction",
                    &g.persist_row_hash,
                    &b.persist_row_hash,
                ]);
                let mut wd = KRow::new(id, vec![target], g.attesting_key_id.clone())
                    .at(micros(g.asserted_at));
                wd.seat.kind = SeatKind::Withdraw;
                wd.seat.target = Some(target);
                out.push(wd);
            }
        }
    }
    out
}

/// **The kernel's owner seat**: the keys holding `owner` over `node`'s key,
/// read from [`owner_rows`]. Two keys of one person are the caller's to
/// collapse (KERNEL.md 7b: the adapter presents a seat as its person); the
/// seat is single-valued over persons.
#[must_use]
pub fn owner_holders(rows: &[KRow], node: &str) -> Answer<BTreeSet<String>> {
    let law = seat_law();
    // the door first (`layers::kept`): a row is read only once every row it
    // names is held, so no name cycle ever reaches the graph (I1846)
    let kept = layers::kept(rows, |_| true);
    let c = layers::conclude(kept, |p| seat_rule(p, law, &NoCut, &|_| false), None);
    let seats = Seats::new(&c, law, &NoCut, None);
    let obj = Obj::Key(node.to_owned());
    let value = seats.holders(SEAT_OWNER, &obj, None);
    let read: Vec<RowId> = seats
        .recs()
        .iter()
        .filter(|r| r.obj == obj)
        .map(|r| r.offer)
        .collect();
    // v62.0.0 (kernel pass 2, I2810) — the read set: the node's standing
    // (the seats over its key) and every presented row's citers (a
    // retraction naming a binding ends it)
    let reads = std::iter::once(super::DepKey::Standing(node.to_owned()))
        .chain(rows.iter().map(|r| super::DepKey::Refs(r.id)))
        .collect();
    Answer::reading(value, read, reads, "seat::Seats::holders/owner")
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::federation::types::ScrubSig;

    fn row(id: &str, ty: &str, by: &str, to: &str, envelope: serde_json::Value) -> Attestation {
        let mut a: Attestation = serde_json::from_value(serde_json::json!({
            "attestation_id": id, "attesting_key_id": by, "attested_key_id": to,
            "attestation_type": ty, "asserted_at": "2026-01-01T00:00:00Z",
            "attestation_envelope": envelope, "original_content_hash": "h",
            "scrub_signature_classical": "s", "scrub_key_id": by,
            "scrub_timestamp": "2026-01-01T00:00:00Z", "persist_row_hash": format!("prh-{id}"),
        }))
        .expect("a fixture row");
        a.tier = crate::federation::types::attestation_tier::FEDERATION.into();
        a
    }

    fn binding(id: &str, owner: &str, node: &str, node_cosigns: bool) -> Attestation {
        let env =
            serde_json::json!({"dimension": "ownership", "delegation_purpose": "owner_binding"});
        let mut b = row(id, attestation_type::DELEGATES_TO, owner, node, env);
        if node_cosigns {
            b.additional_scrubs.push(ScrubSig {
                scrub_key_id: node.into(),
                scrub_signature_classical: "c".into(),
                scrub_signature_pqc: None,
                cosigned_at: None,
            });
        }
        b
    }

    fn holders(rows: &[Attestation], retr: &[Attestation], cosign: Cosign) -> BTreeSet<String> {
        let now = chrono::Utc::now();
        owner_holders(&owner_rows("N", rows, retr, now, &|_| true, cosign), "N").value
    }

    /// CC 3.2, the first binding: a binding counts only with the node's cosignature (I1834).
    #[test]
    fn i1834_an_owner_binding_counts_only_with_the_nodes_cosignature() {
        let one = |k: &str| -> BTreeSet<String> { std::iter::once(k.to_owned()).collect() };
        assert!(crate::federation::admission::is_owner_binding_envelope(
            &binding("b", "O", "N", false).attestation_envelope
        ));
        assert_eq!(
            holders(&[binding("b", "O", "N", true)], &[], Cosign::Required),
            one("O")
        );
        // the answer names the rows it rests on: the binding that seats O
        let view = owner_rows(
            "N",
            &[binding("b", "O", "N", true)],
            &[],
            chrono::Utc::now(),
            &|_| true,
            Cosign::Required,
        );
        assert_eq!(
            owner_holders(&view, "N").rows,
            vec![RowId::of_hash("prh-b")],
            "I1834: the rows read are the seat's offer"
        );
        assert!(holders(&[binding("b", "O", "N", false)], &[], Cosign::Required).is_empty());
        assert_eq!(
            holders(&[binding("b", "O", "N", false)], &[], Cosign::Assumed),
            one("O")
        );
        // a cosignature by another key is no consent of the node's
        let mut other = binding("b", "O", "N", false);
        other.additional_scrubs.push(ScrubSig {
            scrub_key_id: "X".into(),
            scrub_signature_classical: "c".into(),
            scrub_signature_pqc: None,
            cosigned_at: None,
        });
        assert!(holders(&[other], &[], Cosign::Required).is_empty());
        // two cosigned bindings of two owners: two holders
        let two = holders(
            &[binding("b1", "O", "N", true), binding("b2", "P", "N", true)],
            &[],
            Cosign::Required,
        );
        assert_eq!(two.len(), 2);
    }

    #[test]
    fn i1835_a_withdrawal_ends_the_seat_only_from_a_key_of_the_seat() {
        let b = binding("b", "O", "N", true);
        let wd = |id: &str, by: &str| {
            row(
                id,
                attestation_type::WITHDRAWS,
                by,
                "N",
                serde_json::json!({"references_attestation_id": "b"}),
            )
        };
        assert!(holders(&[b.clone(), wd("w", "O")], &[], Cosign::Required).is_empty());
        // CC 3.2: a node cannot outrun its owner — its own retraction is no
        // withdrawal of the seat (the ownerless-lock reclaim is the ceremony)
        assert_eq!(
            holders(&[b.clone(), wd("w", "N")], &[], Cosign::Required).len(),
            1
        );
        assert_eq!(
            holders(&[b.clone(), wd("w", "T")], &[], Cosign::Required).len(),
            1
        );
        // the granter's own retraction about the node
        let about = row(
            "g",
            attestation_type::WITHDRAWS,
            "O",
            "N",
            serde_json::json!({}),
        );
        assert!(holders(std::slice::from_ref(&b), &[about], Cosign::Required).is_empty());
        // the granter's `recants` about the node ends its bindings too
        let recants = row(
            "g",
            attestation_type::RECANTS,
            "O",
            "N",
            serde_json::json!({}),
        );
        assert!(
            holders(std::slice::from_ref(&b), &[recants], Cosign::Required).is_empty(),
            "a granter's recants about the node withdraws its bindings"
        );
        // a row about the node that is no retraction withdraws nothing
        let scores = row("g", "scores", "O", "N", serde_json::json!({}));
        assert_eq!(
            holders(std::slice::from_ref(&b), &[scores], Cosign::Required).len(),
            1,
            "only a withdraws / recants is a granter's retraction"
        );
        // an expired binding is not presented
        let mut late = b.clone();
        late.expires_at = Some(chrono::Utc::now() - chrono::Duration::seconds(1));
        assert!(holders(&[late], &[], Cosign::Required).is_empty());
        // a binding expiring at the reading instant has lapsed (`exp > now`)
        let now = chrono::Utc::now();
        let mut at_now = b;
        at_now.expires_at = Some(now);
        let view = owner_rows("N", &[at_now], &[], now, &|_| true, Cosign::Required);
        assert!(
            owner_holders(&view, "N").value.is_empty(),
            "a binding is live only strictly before its expiry"
        );
    }

    /// **I2818** — CC 3.2, *The first binding*: a binding the node's genesis
    /// record carries seats its owner without the node's cosignature; one it
    /// does not carry still needs it.
    #[test]
    fn i2818_a_binding_the_genesis_record_carries_counts() {
        let now = chrono::Utc::now();
        let b = binding("b", "O", "N", false);
        let other = binding("c", "P", "N", false);
        let carried: BTreeSet<RowId> =
            std::iter::once(RowId::of_hash(&b.persist_row_hash)).collect();
        let view = owner_rows_with_genesis(
            "N",
            &[b.clone(), other.clone()],
            &[],
            now,
            &|_| true,
            Cosign::Required,
            &carried,
        );
        let held = owner_holders(&view, "N");
        assert_eq!(
            held.value,
            std::iter::once("O".to_owned()).collect::<BTreeSet<_>>(),
            "I2818: the carried binding seats O; P's uncosigned one seats nobody"
        );
        assert!(
            held.rows.contains(&RowId::of_hash(&b.persist_row_hash)),
            "I2818: the answer rests on the carried binding"
        );
        // without the genesis record, neither counts
        let bare = owner_rows("N", &[b, other], &[], now, &|_| true, Cosign::Required);
        assert!(owner_holders(&bare, "N").value.is_empty(), "I2818");
    }

    /// CANARY for the adapter's own-withdrawal filter in [`owner_rows`]
    /// (`.filter(|r| r.attesting_key_id != node)`, CC 3.2: a node cannot
    /// outrun its owner). The kernel's `Conf::Own` seat ends on the
    /// conferrer's own withdrawal, and the node is the presented signer of
    /// a cosigned binding, so without the filter the node's own `withdraws`
    /// ends the seat. This test hands the kernel that withdrawal DIRECTLY,
    /// bypassing the filter, and asserts the kernel STILL ends the seat.
    ///
    /// When this FAILS, the kernel has fixed it (kernel friction item 2,
    /// expected in v0.3): delete the filter in `owner_rows` and this canary,
    /// and keep `i1835`'s node-retraction assertion as the witness.
    #[test]
    fn kernel_still_needs_own_withdrawal_filter() {
        let now = chrono::Utc::now();
        let b = binding("b", "O", "N", true);
        let mut view = owner_rows(
            "N",
            std::slice::from_ref(&b),
            &[],
            now,
            &|_| true,
            Cosign::Required,
        );
        // control: the binding alone seats O
        assert_eq!(owner_holders(&view, "N").value.len(), 1);
        // control: through the adapter, the node's own withdrawal is filtered
        let own = row(
            "w",
            attestation_type::WITHDRAWS,
            "N",
            "N",
            serde_json::json!({"references_attestation_id": "b"}),
        );
        assert_eq!(
            holders(&[b.clone(), own.clone()], &[], Cosign::Required).len(),
            1,
            "the adapter filter keeps the seat"
        );
        // the row the filter drops, built as the composer path builds it
        let target = RowId::of_hash(&b.persist_row_hash);
        let mut wd = KRow::new(RowId::of_hash(&own.persist_row_hash), vec![target], "N")
            .at(micros(own.asserted_at));
        wd.seat.kind = SeatKind::Withdraw;
        wd.seat.target = Some(target);
        wd.seat.policy = Some(attestation_type::WITHDRAWS.into());
        view.push(wd);
        assert!(
            owner_holders(&view, "N").value.is_empty(),
            "CANARY: the kernel no longer ends a Conf::Own seat on the node's own \
             withdrawal — remove the own-withdrawal filter in owner_rows and this test"
        );
    }
}
