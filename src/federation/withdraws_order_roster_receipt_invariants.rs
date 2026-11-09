//! v61.1.0 (CIRISPersist#1218, CIRISPersist#1220) — **I1600–I1604: who a
//! retraction speaks for, whatever order it arrived in, and a roster
//! proposal is never held without its window.**
//!
//! The #1218 ruling: a held row is never rewritten (FSD 5.8), so a
//! `withdraws` admitted before its target keeps no rule; the door ignores an
//! offered rule; and an UNSTAMPED `withdraws` is entitled only through arm 1
//! (its signer is the target's producer). The stamp is the only non-producer
//! authority, and only this node's door writes one, at admission, with the
//! target held. So an honest non-producer `withdraws` that arrived first
//! retires nothing on that node, while an in-order node retires. That order
//! dependence is named and owned by v62 (its fold derives entitlement); these
//! witnesses assert it as it is, not as it will be.
//!
//! - **I1600** (pure: the fold) — against each of the eight adverse classes
//!   of CC 2.4.1.1 and a cosigned act, a subject's `withdraws` retires
//!   nothing, whether it arrived first (no rule), was refused at the door
//!   (absent), or carries a subject rule 2-4 an earlier door stamped. The
//!   producer's own `withdraws` retires in both orders, and so does a rule the
//!   door stamps that is not a subject rule (1, the producer's principal; 5,
//!   the recovery ceremony). On a plain row the subject's stamped rule 2
//!   retires and its unstamped early row does not; the same for a stranger's
//!   unstamped row, and for a node named as the subject of its own
//!   owner-binding (H1). Controls: a node's tier-crossing co-scrub
//!   (`cosigned_at` stamped) does not make a row cosigned; a cosigned
//!   group-plane row keeps its own plane's quorum rule (4); a type-slot
//!   `capacity:*` row is carved out as its `scores` twin is (D12). The
//!   retired set is the same for every permutation of the rows.
//! - **I1601** (sqlite, postgres) — through the real door, in both arrival
//!   orders: a room member's `withdraws` of a `moderation:*` act naming them,
//!   and of a cosigned act naming them, retires neither, and four readers
//!   agree: the consolidated fold over the held rows
//!   (`precedence::retired_ids`), the Live listing's rule
//!   (`migration::fold_retractions`), the read-time re-derivation
//!   (`blob_tombstone::retiring_composer`) and the SQL Live listing
//!   (`list_scores`, `LifecycleView::Live`). The act's signer's `withdraws`
//!   retires it in both orders for all four. The member's `withdraws` of a
//!   peer's plain row is stamped rule 2 in order and retires for all four;
//!   withdraws first it is held with no rule, and the three readers of the
//!   stored rule keep the row live, while the bytes plane's re-derivation
//!   (which asks the door again at read time, I150) retires it.
//! - **I1602** (sqlite, postgres) — a self-roster proposal's receipt (V199) is
//!   written in the row's transaction: with the receipt's INSERT made to fail,
//!   the proposal row is refused by `put_attestation`, by
//!   `apply_replicated_attestation` and by the local roster gate
//!   (`put_identity_occurrence`), and neither the row nor a receipt is held.
//!   A re-offer lands both, and a later re-offer moves nothing.
//! - **I1603** (sqlite, postgres) — the stamp is the door's, never the
//!   offered row's: a `withdraws` offered with a forged rule 1 or 5, through
//!   `put_attestation` or `apply_replicated_attestation`, in either arrival
//!   order, against a moderation act, a cosigned act, or (from a stranger) a
//!   plain row, is refused in order and held unstamped when early; it stays
//!   unstamped once its target lands; every reader keeps the target live.
//! - **I1604** (sqlite, postgres; H1) — a node named as the subject of its
//!   own owner-binding cannot shed its owner by sending its `withdraws` ahead
//!   of the binding. In order the door sends it to the CC 3.2 ceremony and
//!   refuses it; withdraws first it is held unstamped, and once the binding
//!   lands the fold, the Live listing's rule, the owner-binding walk and
//!   `owner_of` all keep the owner. The owner's own `withdraws` ends the
//!   binding in either order (the control).

/// I1600 — the fold, pure.
#[cfg(test)]
mod fold {
    use crate::federation::precedence::{retired_ids, subject_withdraws_carved_out};
    use crate::federation::tier_ingest::test_support as ts;
    use crate::federation::types::{attestation_type, Attestation, ScrubSig};
    use std::collections::HashSet;

    const PRODUCER: &str = "i1600-producer";
    const SUBJECT: &str = "i1600-subject";
    const COSIGNER: &str = "i1600-cosigner";
    const STRANGER: &str = "i1600-stranger";
    /// The node [`PRODUCER`]'s owner-binding binds, named as its subject.
    const NODE: &str = "i1600-node";

    /// The eight adverse classes, spelled here and not read from the
    /// constant, so a class dropped from it reds this witness.
    const ADVERSE: [&str; 8] = [
        "capacity:",
        "detection:",
        "licensure:",
        "revocation:",
        "moderation:",
        "hard_case:",
        "slashing:",
        "takedown_notice:",
    ];

    /// A `scores` row by [`PRODUCER`] under `dimension`, naming [`SUBJECT`].
    fn target(id: &str, dimension: &str) -> Attestation {
        let env = serde_json::json!({ "dimension": dimension, "score": 0.5 });
        let mut r = ts::bare_attestation(id, PRODUCER, SUBJECT, &env);
        r.attestation_type = attestation_type::SCORES.into();
        r.weight = None;
        r.subject_key_ids = vec![SUBJECT.to_owned()];
        r
    }

    /// [`PRODUCER`]'s owner-binding over [`NODE`], naming the node in
    /// `subject_key_ids` (the rc3-conformant shape, CC 3.2).
    fn owner_binding(id: &str) -> Attestation {
        let env = serde_json::json!({
            "kind": "delegates_to",
            "dimension": crate::federation::types::owner_binding::DIMENSION,
            "delegation_purpose": crate::federation::types::owner_binding::PURPOSE,
        });
        let mut r = ts::bare_attestation(id, PRODUCER, NODE, &env);
        r.attestation_type = attestation_type::DELEGATES_TO.into();
        r.subject_key_ids = vec![NODE.to_owned()];
        r
    }

    fn cosigned_by(mut r: Attestation, key: &str, cosigned_at: Option<&str>) -> Attestation {
        r.additional_scrubs.push(ScrubSig {
            scrub_key_id: key.to_owned(),
            scrub_signature_classical: String::new(),
            scrub_signature_pqc: None,
            cosigned_at: cosigned_at.map(str::to_owned),
        });
        r
    }

    /// `by`'s `withdraws` of `target`, carrying `rule` as the door stamped it
    /// (`None`: admitted before its target, the deferred shape).
    fn withdraws(id: &str, by: &str, target: &Attestation, rule: Option<u8>) -> Attestation {
        let env = serde_json::json!({ "references_attestation_id": target.attestation_id });
        let mut w = ts::bare_attestation(id, by, by, &env);
        w.attestation_type = attestation_type::WITHDRAWS.into();
        w.weight = None;
        w.withdraws_admission_rule = rule;
        w
    }

    fn retired(rows: &[Attestation]) -> HashSet<String> {
        let refs: Vec<&Attestation> = rows.iter().collect();
        retired_ids(&refs)
    }

    /// Every permutation of `rows` (Heap's algorithm; a case is at most four
    /// rows).
    fn permutations(rows: &[Attestation]) -> Vec<Vec<Attestation>> {
        fn heap(k: usize, a: &mut [Attestation], out: &mut Vec<Vec<Attestation>>) {
            if k <= 1 {
                out.push(a.to_vec());
                return;
            }
            for i in 0..k {
                heap(k - 1, a, out);
                if k % 2 == 0 {
                    a.swap(i, k - 1);
                } else {
                    a.swap(0, k - 1);
                }
            }
        }
        let mut a = rows.to_vec();
        let mut out = Vec::new();
        heap(a.len(), &mut a, &mut out);
        out
    }

    /// The retired set of `rows`, asserted equal over every permutation.
    fn retired_in_every_order(rows: &[Attestation], what: &str) -> HashSet<String> {
        let first = retired(rows);
        for p in permutations(rows) {
            assert_eq!(
                retired(&p),
                first,
                "I1600 {what}: the slice's order moved the verdict"
            );
        }
        first
    }

    /// One target under both arrival orders: in order, the door's verdict on
    /// the `withdraws` (`in_order`: the rule it stamps, or `None` = refused,
    /// not held); withdraws first, the deferred row (no rule). Returns whether
    /// the target is retired in each.
    fn both_orders(t: &Attestation, by: &str, in_order: Option<u8>, what: &str) -> (bool, bool) {
        let in_order_rows = match in_order {
            Some(rule) => vec![t.clone(), withdraws("w-in", by, t, Some(rule))],
            None => vec![t.clone()],
        };
        let early = vec![withdraws("w-early", by, t, None), t.clone()];
        (
            retired_in_every_order(&in_order_rows, what).contains(&t.attestation_id),
            retired_in_every_order(&early, what).contains(&t.attestation_id),
        )
    }

    #[test]
    fn i1600_only_the_producer_or_a_stamp_retires() {
        assert_eq!(
            ADVERSE,
            crate::federation::admission::SUBJECT_WITHDRAWS_CARVE_OUT,
            "I1600: the adverse classes"
        );
        let mut carved: Vec<(String, Attestation)> = ADVERSE
            .iter()
            .map(|p| {
                let dim = format!("{p}i1600:v1");
                (dim.clone(), target(&format!("t-{p}"), &dim))
            })
            .collect();
        carved.push((
            "a cosigned act".into(),
            cosigned_by(target("t-cosigned", "expertise:i1600:v1"), COSIGNER, None),
        ));

        for (what, t) in &carved {
            assert!(subject_withdraws_carved_out(t), "I1600 {what}: carved out");
            // The subject: refused in order, deferred when early. Neither
            // retires.
            assert_eq!(
                both_orders(t, SUBJECT, None, what),
                (false, false),
                "I1600 {what}: the subject's withdraws retires nothing in either order"
            );
            // A subject rule an earlier door stamped (or a forged one) does
            // not reopen the carve-out.
            for rule in [2, 3, 4] {
                let rows = vec![t.clone(), withdraws("w-stamped", SUBJECT, t, Some(rule))];
                assert!(
                    !retired_in_every_order(&rows, what).contains(&t.attestation_id),
                    "I1600 {what}: a stamped subject rule {rule} retires nothing"
                );
            }
            // The producer: rule 1 in order, the attester's own when early.
            assert_eq!(
                both_orders(t, PRODUCER, Some(1), what),
                (true, true),
                "I1600 {what}: the producer's withdraws retires in both orders"
            );
            // The rules the door stamps against such a target that are not a
            // subject's: the producer's principal (1), the ceremony (5).
            for rule in [1, 5] {
                let rows = vec![t.clone(), withdraws("w-door", STRANGER, t, Some(rule))];
                assert!(
                    retired_in_every_order(&rows, what).contains(&t.attestation_id),
                    "I1600 {what}: a door-stamped rule {rule} retires"
                );
            }
        }

        // A plain row: the subject's rule 2, stamped in order, retires it;
        // the same `withdraws` arrived first is unstamped and retires nothing
        // on this node (#1218 H1: past the producer, only the stamp entitles).
        // v62's fold owns the order dependence; this pins it as it is.
        let plain = target("t-plain", "expertise:i1600:v1");
        assert!(!subject_withdraws_carved_out(&plain), "I1600 control");
        assert_eq!(
            both_orders(&plain, SUBJECT, Some(2), "plain"),
            (true, false),
            "I1600: a subject's stamped withdraws retires a plain row; its unstamped one does not"
        );
        // A stranger's unstamped `withdraws` retires nothing either.
        let early = vec![
            withdraws("w-stranger", STRANGER, &plain, None),
            plain.clone(),
        ];
        assert!(
            !retired_in_every_order(&early, "stranger").contains(&plain.attestation_id),
            "I1600: a stranger's unstamped withdraws retires nothing"
        );
        // A node's tier-crossing co-scrub is custody, not a voice: the row is
        // not carved out, so the subject's stamped rule 2 retires it.
        let custody = cosigned_by(
            target("t-custody", "expertise:i1600:v1"),
            COSIGNER,
            Some("2026-11-08T00:00:00.000Z"),
        );
        assert!(!subject_withdraws_carved_out(&custody), "I1600 custody");
        assert_eq!(
            both_orders(&custody, SUBJECT, Some(2), "co-scrubbed"),
            (true, false),
            "I1600: a co-scrub does not make a row cosigned"
        );
        // H1 — a node named as the subject of its own owner-binding. In order
        // the door sends its `withdraws` to the CC 3.2 ceremony and refuses it
        // (not held); arrived first it is unstamped. Neither retires the
        // binding; the owner's own `withdraws` does, in both orders.
        let binding = owner_binding("t-owner-binding");
        assert_eq!(
            both_orders(&binding, NODE, None, "owner-binding"),
            (false, false),
            "I1600 H1: a node's withdraws of its own owner-binding retires nothing"
        );
        assert_eq!(
            both_orders(&binding, PRODUCER, Some(1), "owner-binding"),
            (true, true),
            "I1600 H1: the owner withdraws its binding in both orders"
        );
        // The ceremony's rule (5), stamped by the door, retires it.
        let rows = vec![
            binding.clone(),
            withdraws("w-ceremony", NODE, &binding, Some(5)),
        ];
        assert!(
            retired_in_every_order(&rows, "owner-binding").contains(&binding.attestation_id),
            "I1600 H1: a ceremony-admitted withdraws retires the binding"
        );
        // D12 — a type-slot `capacity:*` row is carved out as its `scores`
        // twin is: the family is the claim token, not the envelope dimension.
        let mut type_slot = target("t-type-slot", "expertise:i1600:v1");
        type_slot.attestation_type = "capacity:i1600:v1".into();
        assert!(
            subject_withdraws_carved_out(&type_slot),
            "I1600 D12: a type-slot capacity row is carved out"
        );
        let rows = vec![
            type_slot.clone(),
            withdraws("w-type-slot", SUBJECT, &type_slot, Some(2)),
        ];
        assert!(
            !retired_in_every_order(&rows, "type slot").contains(&type_slot.attestation_id),
            "I1600 D12: a stamped subject rule does not retire a type-slot capacity row"
        );
        // ...and a `scores` row whose envelope dimension is plain is not
        // carved out by a non-`scores` reading of the envelope.
        let mut plain_type = target("t-plain-type", "capacity:i1600:v1");
        plain_type.attestation_type = "expertise:i1600:v1".into();
        assert!(
            !subject_withdraws_carved_out(&plain_type),
            "I1600 D12: a non-scores row's family is its type, not its envelope dimension"
        );
        // Control: a group-plane row is cosigned by construction and is
        // retracted under its group's protocol (rule 4), not the carve-out.
        let mut group = cosigned_by(
            target(
                "t-group",
                crate::federation::group_plane::GROUP_ROSTER_DIMENSION,
            ),
            COSIGNER,
            None,
        );
        group.subject_key_ids.clear();
        assert!(crate::federation::group_plane::is_group_plane_row(&group));
        let rows = vec![
            group.clone(),
            withdraws("w-quorum", STRANGER, &group, Some(4)),
        ];
        assert!(
            retired_in_every_order(&rows, "group plane").contains(&group.attestation_id),
            "I1600: a group-plane row keeps its own plane's rule"
        );

        // All of it at once: one slice, every case, the same set.
        let mut all: Vec<Attestation> = Vec::new();
        for (_, t) in &carved {
            all.push(t.clone());
            all.push(withdraws(
                &format!("w-s-{}", t.attestation_id),
                SUBJECT,
                t,
                None,
            ));
        }
        all.push(plain.clone());
        all.push(withdraws("w-s-plain", SUBJECT, &plain, None));
        let stamped = target("t-plain-stamped", "expertise:i1600:v1");
        all.push(stamped.clone());
        all.push(withdraws("w-s-stamped", SUBJECT, &stamped, Some(2)));
        let forward = retired(&all);
        all.reverse();
        assert_eq!(retired(&all), forward, "I1600: the whole slice, reversed");
        assert_eq!(
            forward,
            HashSet::from([stamped.attestation_id.clone()]),
            "I1600: only the plain row whose subject's withdraws the door stamped is retired"
        );
    }
}

#[cfg(all(test, any(feature = "sqlite", feature = "postgres")))]
pub(crate) mod bodies {
    use crate::federation::membership_acceptance_invariants::bodies::{found_community, reg};
    use crate::federation::self_roster as sr;
    use crate::federation::tier_ingest::test_support as ts;
    use crate::federation::types::{attestation_type, cohort_scope, identity_type};
    use crate::federation::{Attestation, Error, FederationDirectory, SignedAttestation};

    /// A `scores` row by `by` at the room's `community` scope naming
    /// `subject`, optionally cosigned by `cosigner` (an actor's scrub over the
    /// same envelope, not a tier-crossing co-scrub). I1516's shape.
    fn about(
        by: &str,
        dimension: &str,
        subject: &str,
        room: &str,
        cosigner: Option<&str>,
    ) -> Attestation {
        let env = serde_json::json!({
            "dimension": dimension,
            "score": crate::federation::namespace::registry::in_class_score(dimension),
            "confidence": 0.9,
            "community_id": room,
            "community_key_id": room,
        });
        let mut r = ts::bare_attestation(&uuid::Uuid::new_v4().to_string(), by, by, &env);
        r.attestation_type = attestation_type::SCORES.into();
        r.weight = None;
        r.cohort_scope = cohort_scope::COMMUNITY.into();
        r.subject_key_ids = vec![subject.to_owned()];
        ts::seal_row_in_place(by, &mut r);
        if let Some(c) = cosigner {
            let (_h, classical, pqc) = ts::sign_envelope(c, &r.attestation_envelope);
            r.additional_scrubs
                .push(crate::federation::types::ScrubSig {
                    scrub_key_id: c.to_owned(),
                    scrub_signature_classical: classical,
                    scrub_signature_pqc: pqc,
                    cosigned_at: None,
                });
        }
        r
    }

    /// `issuer`'s `withdraws` of `target`.
    fn withdraws(issuer: &str, target: &Attestation) -> Attestation {
        let env = serde_json::json!({
            "references_attestation_id": target.attestation_id,
            "withdrawal_reason": "I1601",
        });
        let mut w = ts::bare_attestation(&uuid::Uuid::new_v4().to_string(), issuer, issuer, &env);
        w.attestation_type = attestation_type::WITHDRAWS.into();
        w.weight = None;
        ts::seal_row_in_place(issuer, &mut w);
        w
    }

    async fn put(d: &dyn FederationDirectory, r: &Attestation) -> Result<(), Error> {
        d.put_attestation(SignedAttestation {
            attestation: r.clone(),
        })
        .await
        .map(|_| ())
    }

    #[derive(Debug, Clone, Copy)]
    enum Order {
        TargetFirst,
        WithdrawsFirst,
    }

    /// Deliver `target` and `w` in `order`. The target always lands; returns
    /// the door's verdict on `w`. Withdraws first, the door has no target to
    /// ask and admits it deferred.
    async fn arrive(
        d: &dyn FederationDirectory,
        order: Order,
        target: &Attestation,
        w: &Attestation,
    ) -> Result<(), Error> {
        match order {
            Order::TargetFirst => {
                put(d, target).await.expect("I1601: the target lands");
                put(d, w).await
            }
            Order::WithdrawsFirst => {
                put(d, w)
                    .await
                    .expect("I1601: a withdraws whose target is not held is admitted deferred");
                let held = d.get_attestation(&w.attestation_id).await.unwrap().unwrap();
                assert_eq!(
                    held.withdraws_admission_rule, None,
                    "I1601: deferred, no rule"
                );
                put(d, target).await.expect("I1601: the target lands");
                Ok(())
            }
        }
    }

    /// What four readers say of `target` (true = retired): the consolidated
    /// fold over the held rows, the Live listing's rule
    /// (`migration::fold_retractions`), the read-time re-derivation, and the
    /// SQL Live listing itself (`list_scores` under `LifecycleView::Live`,
    /// read as `caller`, who must see the row under `IncludeWithdrawn`).
    async fn readers(
        d: &dyn FederationDirectory,
        caller: &str,
        target: &str,
        w: &str,
    ) -> [bool; 4] {
        let mut rows = Vec::new();
        for id in [target, w] {
            if let Some(r) = d.get_attestation(id).await.expect("read") {
                rows.push(r);
            }
        }
        let refs: Vec<&Attestation> = rows.iter().collect();
        let fold = crate::federation::precedence::retired_ids(&refs).contains(target);
        let live_rule = crate::federation::migration::fold_retractions(&rows).is_retracted(target);
        let held = d
            .get_attestation(target)
            .await
            .expect("read")
            .expect("the target is held");
        let rederived = crate::federation::blob_tombstone::retiring_composer(d, &held)
            .await
            .expect("re-derived")
            .is_some();
        let listed = |lifecycle: crate::read::LifecycleView| {
            let attester = held.attesting_key_id.clone();
            async move {
                d.list_scores(
                    caller,
                    crate::read::AttestationFilter {
                        attesting_key_id: Some(attester),
                        lifecycle,
                        ..crate::read::AttestationFilter::default()
                    },
                    None,
                    1_000,
                )
                .await
                .expect("list_scores")
                .items
                .iter()
                .any(|a| a.attestation_id == target)
            }
        };
        assert!(
            listed(crate::read::LifecycleView::IncludeWithdrawn).await,
            "the caller sees {target} at all (else Live proves nothing)"
        );
        let sql_retired = !listed(crate::read::LifecycleView::Live).await;
        [fold, live_rule, rederived, sql_retired]
    }

    /// The room I1601 and I1603 share: a moderator, the author the acts name
    /// and a member, all founders of a `quorum:1/1` room.
    async fn room(d: &dyn FederationDirectory, inv: &str, s: &str) -> [String; 4] {
        let k = |n: &str| format!("{inv}-{n}-{s}");
        let (moderator, author, member, room) = (k("mod"), k("author"), k("member"), k("room"));
        for u in [&moderator, &author, &member] {
            ts::register_hybrid_key_as(d, u, u, identity_type::USER).await;
        }
        reg(d, &[&room]).await;
        found_community(d, &room, "quorum:1/1", &[&moderator, &author, &member], &[])
            .await
            .unwrap();
        [moderator, author, member, room]
    }

    const PLAIN: &str = "expertise:cardiology:en:v1";

    /// **I1601** — both arrival orders, the real door, four readers.
    pub(crate) async fn i1601_both_arrival_orders_agree(d: &dyn FederationDirectory, s: &str) {
        let [moderator, author, member, room] = room(d, "i1601", s).await;

        for order in [Order::TargetFirst, Order::WithdrawsFirst] {
            let what = format!("{order:?}");
            // The subject's withdraws of a moderation act naming them.
            let mod_act = about(&moderator, "moderation:rogue_vote:v1", &author, &room, None);
            let w = withdraws(&author, &mod_act);
            let verdict = arrive(d, order, &mod_act, &w).await;
            if let Order::TargetFirst = order {
                let e = verdict.expect_err("I1601: the door refuses it in order");
                assert_eq!(e.kind(), "federation_withdraws_not_admitted", "I1601: {e}");
            }
            assert_eq!(
                readers(d, &author, &mod_act.attestation_id, &w.attestation_id).await,
                [false; 4],
                "I1601 {what}: a moderation act stays live for every reader"
            );

            // The subject's withdraws of a cosigned act naming them.
            let cosigned = about(&member, PLAIN, &author, &room, Some(&moderator));
            let w = withdraws(&author, &cosigned);
            let verdict = arrive(d, order, &cosigned, &w).await;
            if let Order::TargetFirst = order {
                let e = verdict.expect_err("I1601: the door refuses it in order");
                assert_eq!(e.kind(), "federation_withdraws_not_admitted", "I1601: {e}");
            }
            assert_eq!(
                readers(d, &author, &cosigned.attestation_id, &w.attestation_id).await,
                [false; 4],
                "I1601 {what}: a cosigned act stays live for every reader"
            );

            // The act's own signer retires it, in either order.
            let mod_act = about(&moderator, "moderation:rogue_vote:v1", &author, &room, None);
            let w = withdraws(&moderator, &mod_act);
            arrive(d, order, &mod_act, &w)
                .await
                .expect("I1601: the producer withdraws its act");
            assert_eq!(
                readers(d, &author, &mod_act.attestation_id, &w.attestation_id).await,
                [true; 4],
                "I1601 {what}: the producer's withdraws retires for every reader"
            );

            // The subject withdraws a peer's plain row about them. In order
            // the door stamps rule 2 and every reader retires it. Withdraws
            // first, the held row is never re-stamped (FSD 5.8): it keeps no
            // rule, so the three readers of the stored rule keep the row live
            // on this node (#1218 H1: past the producer, only a stamp
            // entitles), while the bytes plane, which asks the door again at
            // read time (I150), retires it. The order dependence is v62's to
            // close; this asserts it as it is.
            let peer_row = about(&member, PLAIN, &author, &room, None);
            let w = withdraws(&author, &peer_row);
            arrive(d, order, &peer_row, &w)
                .await
                .expect("I1601: the subject withdraws a plain row");
            let (rule, readers_say) = match order {
                Order::TargetFirst => (Some(2), [true; 4]),
                Order::WithdrawsFirst => (None, [false, false, true, false]),
            };
            assert_eq!(
                d.get_attestation(&w.attestation_id)
                    .await
                    .unwrap()
                    .expect("held")
                    .withdraws_admission_rule,
                rule,
                "I1601 {what}: stamped only when the door saw the target"
            );
            assert_eq!(
                readers(d, &author, &peer_row.attestation_id, &w.attestation_id).await,
                readers_say,
                "I1601 {what}: a plain row's subject withdraws it on the in-order node only \
                 ([fold, Live rule, bytes-plane re-derivation, SQL Live])"
            );
        }
    }

    /// How a row reaches the node: its own door, or the replication apply.
    #[derive(Debug, Clone, Copy)]
    enum Via {
        Put,
        Replicated,
    }

    async fn deliver(d: &dyn FederationDirectory, via: Via, r: &Attestation) -> Result<(), Error> {
        let a = SignedAttestation {
            attestation: r.clone(),
        };
        match via {
            Via::Put => d.put_attestation(a).await.map(|_| ()),
            Via::Replicated => match d.apply_replicated_attestation(a).await? {
                crate::federation::attestation_apply::ReplicatedAttestationOutcome::Refused {
                    reason,
                } => Err(Error::Conflict(format!("refused: {reason:?}"))),
                _ => Ok(()),
            },
        }
    }

    /// **I1603** — a peer cannot supply the stamp. A subject's `withdraws` of
    /// a carved-out act, offered with a forged rule 1 or 5, through either
    /// door and in either arrival order: in order the door refuses it
    /// (the stamp is the door's, not the row's); withdraws first it is held
    /// with NO rule and stays so once its target lands, and every reader keeps
    /// the act live. A forged rule on a plain row's early `withdraws` by a
    /// stranger is cleared the same way (a stranger is entitled to nothing).
    pub(crate) async fn i1603_a_forged_stamp_is_never_kept(d: &dyn FederationDirectory, s: &str) {
        let [moderator, author, member, room] = room(d, "i1603", s).await;
        let stranger = format!("i1603-stranger-{s}");
        ts::register_hybrid_key_as(d, &stranger, &stranger, identity_type::USER).await;
        for via in [Via::Put, Via::Replicated] {
            for order in [Order::TargetFirst, Order::WithdrawsFirst] {
                for forged in [1_u8, 5] {
                    let what = format!("{via:?} {order:?} forged {forged}");
                    let forge = |mut w: Attestation| {
                        w.withdraws_admission_rule = Some(forged);
                        ts::reseal(&mut w);
                        w
                    };
                    for (target, issuer) in [
                        (
                            about(&moderator, "moderation:rogue_vote:v1", &author, &room, None),
                            &author,
                        ),
                        (
                            about(&member, PLAIN, &author, &room, Some(&moderator)),
                            &author,
                        ),
                        (about(&member, PLAIN, &author, &room, None), &stranger),
                    ] {
                        let w = forge(withdraws(issuer, &target));
                        match order {
                            Order::TargetFirst => {
                                deliver(d, via, &target).await.expect("I1603: the target");
                                deliver(d, via, &w)
                                    .await
                                    .expect_err("I1603: the door refuses it, stamp or none");
                            }
                            Order::WithdrawsFirst => {
                                deliver(d, via, &w).await.expect("I1603: admitted deferred");
                                assert_eq!(
                                    d.get_attestation(&w.attestation_id)
                                        .await
                                        .unwrap()
                                        .expect("held")
                                        .withdraws_admission_rule,
                                    None,
                                    "I1603 {what}: the offered stamp is not kept"
                                );
                                deliver(d, via, &target).await.expect("I1603: the target");
                                assert_eq!(
                                    d.get_attestation(&w.attestation_id)
                                        .await
                                        .unwrap()
                                        .expect("held")
                                        .withdraws_admission_rule,
                                    None,
                                    "I1603 {what}: the held row is never re-stamped"
                                );
                            }
                        }
                        assert_eq!(
                            readers(d, &author, &target.attestation_id, &w.attestation_id).await,
                            [false; 4],
                            "I1603 {what}: {} stays live for every reader",
                            target.attestation_id
                        );
                    }
                }
            }
        }
    }

    /// **I1604** (H1) — a node cannot shed its owner by sending its
    /// `withdraws` of its own owner-binding ahead of the binding. The binding
    /// names the node in `subject_key_ids` (the rc3-conformant shape), so the
    /// pre-ruling fold's subject arm retired it once both were held.
    pub(crate) async fn i1604_a_node_cannot_outrun_its_owner(d: &dyn FederationDirectory, s: &str) {
        use crate::federation::admission::{owner_of, DelegationEdgeFilter};
        for order in [Order::TargetFirst, Order::WithdrawsFirst] {
            // Key ids are canonical lowercase (CC 2.3.2.1): the order's
            // `Debug` name is folded before it reaches one.
            let tag = format!("{s}-{order:?}").to_ascii_lowercase();
            let (owner, node) = (format!("i1604-owner-{tag}"), format!("i1604-node-{tag}"));
            ts::register_hybrid_key_as(d, &owner, &owner, identity_type::USER).await;
            ts::register_hybrid_key_as(d, &node, &node, identity_type::NODE).await;
            let mut binding =
                ts::owner_binding_attestation(&uuid::Uuid::new_v4().to_string(), &owner, &node);
            binding.subject_key_ids = vec![node.clone()];
            ts::reseal(&mut binding);
            let w = withdraws(&node, &binding);
            match order {
                Order::TargetFirst => {
                    put(d, &binding).await.expect("I1604: the binding lands");
                    let e = put(d, &w)
                        .await
                        .expect_err("I1604: in order the door refuses it (CC 3.2 ceremony)");
                    assert!(
                        matches!(e, Error::OwnershipReclaimRefused { .. }),
                        "I1604: refused by the recovery gate: {e:?}"
                    );
                }
                Order::WithdrawsFirst => {
                    put(d, &w)
                        .await
                        .expect("I1604: a withdraws whose target is not held is admitted");
                    put(d, &binding).await.expect("I1604: the binding lands");
                    assert_eq!(
                        d.get_attestation(&w.attestation_id)
                            .await
                            .unwrap()
                            .expect("held")
                            .withdraws_admission_rule,
                        None,
                        "I1604: held unstamped"
                    );
                }
            }
            let what = format!("{order:?}");
            let mut rows = vec![d
                .get_attestation(&binding.attestation_id)
                .await
                .unwrap()
                .expect("the binding is held")];
            rows.extend(d.get_attestation(&w.attestation_id).await.unwrap());
            let refs: Vec<&Attestation> = rows.iter().collect();
            assert!(
                !crate::federation::precedence::retired_ids(&refs)
                    .contains(&binding.attestation_id),
                "I1604 {what}: the fold keeps the binding"
            );
            assert!(
                !crate::federation::migration::fold_retractions(&rows)
                    .is_retracted(&binding.attestation_id),
                "I1604 {what}: the Live listing's rule keeps the binding"
            );
            assert!(
                crate::federation::admission::live_delegation_granters(
                    d,
                    &node,
                    DelegationEdgeFilter::OwnerBindingOnly,
                )
                .await
                .expect("granters")
                .contains(&owner),
                "I1604 {what}: the owner-binding walk keeps the owner"
            );
            assert_eq!(
                owner_of(d, &node).await.expect("owner_of"),
                Some(owner.clone()),
                "I1604 {what}: the node is still owned"
            );

            // Control: the owner's own `withdraws` ends the binding.
            put(d, &withdraws(&owner, &binding))
                .await
                .expect("I1604: the owner withdraws its binding");
            assert_eq!(
                owner_of(d, &node).await.expect("owner_of"),
                None,
                "I1604 {what}: the owner's withdraws ends the binding"
            );
        }
    }

    /// A self `f` holding its first key `d1`, and a third user key `d2`.
    async fn one_key_self(d: &dyn FederationDirectory, tag: &str) -> [String; 3] {
        let (f, d1, d2) = (
            format!("i1602-f-{tag}"),
            format!("i1602-d1-{tag}"),
            format!("i1602-d2-{tag}"),
        );
        for k in [&f, &d1, &d2] {
            ts::register_hybrid_key_as(d, k, k, identity_type::USER).await;
        }
        d.put_identity_occurrence(ts::signed_content_only_occurrence(&f, &f, &d1, ms_now()).await)
            .await
            .expect("I1602: at one key the addition lands");
        [f, d1, d2]
    }

    fn ms_now() -> chrono::DateTime<chrono::Utc> {
        chrono::DateTime::<chrono::Utc>::from_timestamp_millis(
            chrono::Utc::now().timestamp_millis(),
        )
        .expect("ms")
    }

    async fn receipt(
        d: &dyn FederationDirectory,
        f: &str,
        id: &str,
    ) -> Option<crate::federation::self_roster::SelfRosterReceipt> {
        d.list_open_self_roster_proposals(Some(f))
            .await
            .expect("receipts")
            .into_iter()
            .find(|r| r.proposal_id == id)
    }

    async fn held(d: &dyn FederationDirectory, id: &str) -> bool {
        d.get_attestation(id).await.expect("read").is_some()
    }

    /// **I1602** — no proposal row without its receipt. `broken` makes the
    /// receipt's INSERT fail (reads of the ledger still work, so nothing
    /// before the row's transaction can fail first); `mended` restores it.
    /// Three doors: a peer's proposal row through `put_attestation` and
    /// through `apply_replicated_attestation`, and the local roster gate
    /// (`put_identity_occurrence` → `self_roster::gate`), which reads the
    /// ledger first and then puts the row.
    pub(crate) async fn i1602_a_failed_receipt_fails_the_proposal<B, M>(
        d: &dyn FederationDirectory,
        tag: &str,
        broken: B,
        mended: M,
    ) where
        B: std::future::Future<Output = ()>,
        M: std::future::Future<Output = ()>,
    {
        // A peer's proposal: d1 proposes d2 to self f.
        let [f, d1, d2] = one_key_self(d, &format!("{tag}r")).await;
        let signed = ts::signed_content_only_occurrence(&d1, &f, &d2, ms_now()).await;
        let row = sr::proposal_row(&sr::Carried::Occurrence(signed)).expect("proposal row");
        assert!(sr::is_proposal_row(&row), "I1602: fixture");
        let id = row.attestation_id.clone();
        // A local proposal: e1 proposes e2 to self g, at the gate.
        let [g, e1, e2] = one_key_self(d, &format!("{tag}g")).await;
        let local = ts::signed_content_only_occurrence(&e1, &g, &e2, ms_now()).await;
        let local_id = sr::proposal_row(&sr::Carried::Occurrence(local.clone()))
            .expect("proposal row")
            .attestation_id;

        broken.await;
        d.put_attestation(SignedAttestation {
            attestation: row.clone(),
        })
        .await
        .expect_err("I1602: the door surfaces a failed receipt");
        assert!(
            !held(d, &id).await,
            "I1602: no proposal without its receipt"
        );
        d.apply_replicated_attestation(SignedAttestation {
            attestation: row.clone(),
        })
        .await
        .expect_err("I1602: the replicated path surfaces it too");
        assert!(!held(d, &id).await, "I1602: replicated, no row either");
        let gated = d.put_identity_occurrence(local.clone()).await;
        assert!(
            !matches!(gated, Ok(()) | Err(Error::SelfRosterNotLanded { .. })),
            "I1602: the gate surfaces a failed receipt, not a held proposal: {gated:?}"
        );
        assert!(
            !held(d, &local_id).await,
            "I1602: the gate holds no proposal without its receipt"
        );
        mended.await;
        assert!(
            receipt(d, &f, &id).await.is_none(),
            "I1602: nothing was noted"
        );
        assert!(
            receipt(d, &g, &local_id).await.is_none(),
            "I1602: nor at the gate"
        );

        // A re-offer lands both.
        let before = sr::roster_clock() - chrono::Duration::seconds(1);
        let outcome = d
            .apply_replicated_attestation(SignedAttestation {
                attestation: row.clone(),
            })
            .await
            .expect("I1602: the re-offer lands");
        assert_eq!(
            outcome,
            crate::federation::attestation_apply::ReplicatedAttestationOutcome::Inserted,
            "I1602"
        );
        assert!(held(d, &id).await, "I1602: the row is held");
        let first = receipt(d, &f, &id)
            .await
            .expect("I1602: the row brought its receipt");
        assert_eq!(
            first.identity_key_id, f,
            "I1602: the receipt names the self"
        );
        assert!(first.received_at >= before, "I1602: {}", first.received_at);
        match d.put_identity_occurrence(local).await {
            Err(Error::SelfRosterNotLanded {
                decision: "pending",
                proposal_id,
                ..
            }) => assert_eq!(proposal_id, local_id, "I1602: the gate's proposal"),
            other => panic!("I1602: the gate's re-offer holds a pending proposal: {other:?}"),
        }
        assert!(
            receipt(d, &g, &local_id).await.is_some(),
            "I1602: the gate's row brought its receipt"
        );

        // A later offer moves nothing: first seen wins.
        d.put_attestation(SignedAttestation { attestation: row })
            .await
            .expect("I1602: an idempotent re-put");
        assert_eq!(
            receipt(d, &f, &id).await.map(|r| r.received_at),
            Some(first.received_at),
            "I1602: the first instant stands"
        );
    }
}

#[cfg(all(test, any(feature = "sqlite", feature = "postgres")))]
mod runners {
    use super::bodies;

    fn tag(n: &str) -> String {
        format!("{n}{}", &uuid::Uuid::new_v4().simple().to_string()[..8])
    }

    macro_rules! on_sqlite_and_postgres {
        ($name:ident, $body:path) => {
            mod $name {
                use super::*;

                #[cfg(feature = "sqlite")]
                #[tokio::test]
                async fn sqlite() {
                    use crate::store::Backend as _;
                    let b = crate::store::sqlite::SqliteBackend::open_in_memory()
                        .await
                        .unwrap();
                    b.run_migrations().await.unwrap();
                    Box::pin($body(&b, &tag("s"))).await;
                }

                #[cfg(feature = "postgres")]
                #[tokio::test]
                async fn postgres() {
                    use crate::store::Backend as _;
                    let Some(dsn) = crate::test_pg::empty_dsn() else {
                        eprintln!(
                            "{} postgres: no CIRIS_PERSIST_TEST_PG base DSN — SKIPPED",
                            stringify!($name)
                        );
                        return;
                    };
                    let b = crate::store::postgres::PostgresBackend::connect(&dsn)
                        .await
                        .unwrap();
                    b.run_migrations().await.unwrap();
                    Box::pin($body(&b, &tag("p"))).await;
                    eprintln!("{} postgres: RAN", stringify!($name));
                }
            }
        };
    }

    on_sqlite_and_postgres!(i1601, bodies::i1601_both_arrival_orders_agree);
    on_sqlite_and_postgres!(i1603, bodies::i1603_a_forged_stamp_is_never_kept);
    on_sqlite_and_postgres!(i1604, bodies::i1604_a_node_cannot_outrun_its_owner);

    /// The receipt's INSERT is made to fail by a trigger, so every read of
    /// the ledger (the self-roster plan's) still works.
    const BREAK_SQLITE: &str = "CREATE TRIGGER i1602_receipt_fails \
        BEFORE INSERT ON federation_self_roster_proposals \
        BEGIN SELECT RAISE(ABORT, 'I1602 injected receipt failure'); END;";
    const MEND_SQLITE: &str = "DROP TRIGGER i1602_receipt_fails;";
    const BREAK_PG: &str = "CREATE FUNCTION cirislens.i1602_receipt_fails() RETURNS trigger \
        LANGUAGE plpgsql AS $$ BEGIN RAISE EXCEPTION 'I1602 injected receipt failure'; END $$; \
        CREATE TRIGGER i1602_receipt_fails \
        BEFORE INSERT ON cirislens.federation_self_roster_proposals \
        FOR EACH ROW EXECUTE FUNCTION cirislens.i1602_receipt_fails();";
    const MEND_PG: &str = "DROP TRIGGER i1602_receipt_fails \
        ON cirislens.federation_self_roster_proposals; \
        DROP FUNCTION cirislens.i1602_receipt_fails();";

    #[cfg(feature = "sqlite")]
    async fn sql_sqlite(b: &crate::store::sqlite::SqliteBackend, sql: &str) {
        b.conn_handle().lock().execute_batch(sql).unwrap();
    }

    #[cfg(feature = "postgres")]
    async fn sql_pg(b: &crate::store::postgres::PostgresBackend, sql: &str) {
        b.get_client()
            .await
            .unwrap()
            .batch_execute(sql)
            .await
            .unwrap();
    }

    #[cfg(feature = "sqlite")]
    #[tokio::test]
    async fn i1602_sqlite() {
        use crate::store::Backend as _;
        let b = crate::store::sqlite::SqliteBackend::open_in_memory()
            .await
            .unwrap();
        b.run_migrations().await.unwrap();
        Box::pin(bodies::i1602_a_failed_receipt_fails_the_proposal(
            &b,
            &tag("s"),
            sql_sqlite(&b, BREAK_SQLITE),
            sql_sqlite(&b, MEND_SQLITE),
        ))
        .await;
    }

    #[cfg(feature = "postgres")]
    #[tokio::test]
    async fn i1602_postgres() {
        use crate::store::Backend as _;
        let Some(dsn) = crate::test_pg::empty_dsn() else {
            eprintln!("i1602 postgres: no CIRIS_PERSIST_TEST_PG base DSN — SKIPPED");
            return;
        };
        let b = crate::store::postgres::PostgresBackend::connect(&dsn)
            .await
            .unwrap();
        b.run_migrations().await.unwrap();
        Box::pin(bodies::i1602_a_failed_receipt_fails_the_proposal(
            &b,
            &tag("p"),
            sql_pg(&b, BREAK_PG),
            sql_pg(&b, MEND_PG),
        ))
        .await;
        eprintln!("i1602 postgres: RAN");
    }
}
