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
//! dependence is named and owned by v62. v62 (E3): an early composer WAITS for
//! its target (cut A), so it is judged when the target lands and both arrival
//! orders now give the in-order verdict; the witnesses below assert that.
//!
//! - **I1600** (pure: the fold) — against each of the eleven adverse classes
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
//! - **I5709** (v62.0.0, FS-mtr; sqlite, postgres; CIRISConstitution's
//!   ruling of 2026-11-22 on CC 2.4.1.1) — through the real door, in both
//!   arrival orders: the subject's `withdraws` of a
//!   `moderation_track_record:{community_key_id}` row naming them is refused
//!   `federation_withdraws_not_admitted` and the row stays live for all four
//!   readers (the SQL Live listing among them: the carve-out's SQL twin); its
//!   attester's `withdraws` retires it for all four.
//! - **I5710** (v62.0.0, FS-mtr.rev2; sqlite, postgres; CC 2.4.1.1's kept
//!   list names "a `quarantine:*` marker") — the same two legs for a
//!   `quarantine:withheld:v1` marker a room's `slash` holder (a founder)
//!   files about a member.
//! - **I5712** (v62.0.0, FS-kept; CIRISConstitution's answer of 2026-11-22:
//!   "an agent's own `trace:*`") — a person named in an agent's own
//!   `trace:complete:v1` row (inline form, self-emitted) withdraws it:
//!   refused `federation_withdraws_not_admitted`, live for all four readers;
//!   the agent's own `withdraws` (rule 1) retires it.
//! - **I5713** (v62.0.0, FS-kept, FS-kept.fix1.rev3; "An affiliation
//!   withdraws no statement about itself, whatever the statement") — an
//!   affiliation founded under an id that is no key's: a peer's plain row
//!   naming it is not withdrawn by one of its seats (refused, live for all
//!   four readers); the row's signer (rule 1) retires it; a row naming a
//!   MEMBER is withdrawn by that member (rule 2). FORM FIRST (GID-prod.rev2,
//!   superseding fix1.rev3's key-record-first leg): the affiliation's id is
//!   its derived group-ref, a person's key id never is one, so a person's
//!   key withdraws a peer's row about it under rule 2, for all four readers.
//! - **I5714** (v62.0.0, FS-kept.fix1, .rev3; never admitted on absence) —
//!   a person-subject `withdraws` lands at once (its key record resolves
//!   it); a stranger's `withdraws` of a row naming a subject id with NO
//!   record of either kind is refused at once, never held (the subject alone
//!   would not admit it). The wait itself has no path through the door
//!   today (an id with no key signs nothing and is no chain's grantee).
//! - **I5716** (v62.0.0, FS-class; CC 2.4.1.1 "an act of a body under a
//!   declared legal-weight class", the narrow fail-safe form for v62.0) — a
//!   peer's plain row (no `licensure:` / `revocation:` family) carrying a
//!   `class` member: its subject's `withdraws` is HELD
//!   `withdraws_class_unread`, the row live for all four readers; the
//!   signer's own `withdraws` (rule 1) retires it; the same row without
//!   `class` is withdrawn by its subject (rule 2) as before.
//! - **I5715** (v62.0.0, FS-kept.fix1; CC 3.1.5 "Who erases a trace", as
//!   ruled 2026-11-22) — a node's own trace, the node OWNED by a person:
//!   the OWNER's `withdraws` (once rule 1 lifted to the producer's
//!   principal) is refused, the trace live for all four readers; a named
//!   person's is refused; the node's own key withdraws it (rule 1): it
//!   retires for all four readers and its content descends.
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
//! - **I1602** (deleted in v62, E3: the self-roster proposal row and its
//!   V199 receipt are the earlier door's ledger; O1's `identity:occurrence`
//!   counts voices with no proposal row or receipt, witnessed by O1 I3020.)
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
    const ADVERSE: [&str; 11] = [
        "capacity:",
        "detection:",
        "licensure:",
        "revocation:",
        "moderation:",
        "hard_case:",
        "slashing:",
        "takedown_notice:",
        "moderation_track_record:",
        "quarantine:",
        "trace:",
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
                if k.is_multiple_of(2) {
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
    use crate::federation::edition2::fixture_switch as e2;
    use crate::federation::membership_acceptance_invariants::bodies::{found_community, reg};
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
            // v62 (E3b r3): the room is held under its identity-ref (the
            // founding roster is keyed by `kid`), so the cohort target names
            // it by `e2::kid`; a seed resolves to no room
            // (`MembershipUnresolved`).
            "community_id": e2::kid(room),
            "community_key_id": e2::kid(room),
        });
        let mut r = ts::bare_attestation(&uuid::Uuid::new_v4().to_string(), by, by, &env);
        r.attestation_type = attestation_type::SCORES.into();
        r.weight = None;
        r.cohort_scope = cohort_scope::COMMUNITY.into();
        r.subject_key_ids = vec![subject.to_owned()];
        ts::seal_row_in_place(by, &mut r);
        if let Some(c) = cosigner {
            // v62 (E3): a cosignature is a further edition-2 voice over the
            // same statement, put after the row (`put`).
            add_voice(&r, c);
        }
        r
    }

    /// The further voices `put` delivers after a row, by row id.
    fn voices() -> &'static std::sync::Mutex<std::collections::HashMap<String, Vec<Vec<u8>>>> {
        static V: std::sync::OnceLock<
            std::sync::Mutex<std::collections::HashMap<String, Vec<Vec<u8>>>>,
        > = std::sync::OnceLock::new();
        V.get_or_init(Default::default)
    }

    /// `signer`'s voice over `row`'s statement, delivered with the row.
    fn add_voice(row: &Attestation, signer: &str) {
        let st = e2::carried_statement(row).expect("an edition-2 row carries its statement");
        voices()
            .lock()
            .expect("voices")
            .entry(row.attestation_id.clone())
            .or_default()
            .push(e2::voice_of(&st, signer));
    }

    /// `issuer`'s `withdraws` of `target`: v62 (E3) an edition-2 composer
    /// carrying the target's family, `refs.target` = the target's row id.
    fn withdraws(issuer: &str, target: &Attestation) -> Attestation {
        e2::composer_of("withdraws", target, issuer)
    }

    async fn put(d: &dyn FederationDirectory, r: &Attestation) -> Result<(), Error> {
        let pending = voices()
            .lock()
            .expect("voices")
            .get(&r.attestation_id)
            .cloned()
            .unwrap_or_default();
        if pending.is_empty() {
            d.put_attestation(SignedAttestation {
                attestation: r.clone(),
            })
            .await
            .map(|_| ())?;
            return Ok(());
        }
        // v62 (E3b r3): a COUNTED row (an owner binding, a cosigned row)
        // goes through the edition-2 statement door, which keeps its first
        // voice `Pending` until the rest are held (CC 3.2, C557); the JSON
        // door answers the same shortfall as a terminal
        // `owner_binding_counted_short`.
        e2::put_signed(d, r).await.map(|_| ())?;
        for v in pending {
            e2::put_statement(d, &v).await?;
        }
        Ok(())
    }

    #[derive(Debug, Clone, Copy)]
    enum Order {
        TargetFirst,
        WithdrawsFirst,
    }

    /// Deliver `target` and `w` in `order`. The target always lands; returns
    /// the door's verdict on `w`. v62 (E3): withdraws first, a composer whose
    /// target is not held WAITS (cut A): nothing is kept, and the re-offer
    /// after the target lands is judged exactly as in order.
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
                let early = put(d, w).await;
                assert!(
                    d.get_attestation(&w.attestation_id)
                        .await
                        .unwrap()
                        .is_none(),
                    "I1601: a withdraws whose target is not held waits, kept nowhere: {early:?}"
                );
                put(d, target).await.expect("I1601: the target lands");
                put(d, w).await
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
                    &e2::kid(caller),
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
            let e = verdict.expect_err("I1601: the door refuses it, in either order");
            assert_eq!(e.kind(), "federation_withdraws_not_admitted", "I1601: {e}");
            assert_eq!(
                readers(d, &author, &mod_act.attestation_id, &w.attestation_id).await,
                [false; 4],
                "I1601 {what}: a moderation act stays live for every reader"
            );

            // The subject's withdraws of a cosigned act naming them.
            let cosigned = about(&member, PLAIN, &author, &room, Some(&moderator));
            let w = withdraws(&author, &cosigned);
            let verdict = arrive(d, order, &cosigned, &w).await;
            let e = verdict.expect_err("I1601: the door refuses it, in either order");
            assert_eq!(e.kind(), "federation_withdraws_not_admitted", "I1601: {e}");
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

            // The subject withdraws a peer's plain row about them: the door
            // stamps rule 2 and every reader retires it. v62 (E3): in either
            // order, since an early composer waits for its target and is
            // judged when it lands (the order dependence #1218 named is closed).
            let peer_row = about(&member, PLAIN, &author, &room, None);
            let w = withdraws(&author, &peer_row);
            arrive(d, order, &peer_row, &w)
                .await
                .expect("I1601: the subject withdraws a plain row");
            assert_eq!(
                d.get_attestation(&w.attestation_id)
                    .await
                    .unwrap()
                    .expect("held")
                    .withdraws_admission_rule,
                Some(2),
                "I1601 {what}: stamped by the door that saw the target"
            );
            // v62.0.0 (WD-fix5; CC 6.1.5 N5, the lead's ruling) — a plain row
            // is a CLAIM: its admitted rule-2 withdrawal descends it at the
            // door, in either order. Gone for every reader, its id a
            // tombstone naming the withdrawal, a later copy refused.
            assert!(
                d.get_attestation(&peer_row.attestation_id)
                    .await
                    .unwrap()
                    .is_none(),
                "I1601 {what}: the plain row descended in either order"
            );
            match crate::federation::withdrawn_content::held_row_state(d, &peer_row.attestation_id)
                .await
                .unwrap()
            {
                crate::federation::withdrawn_content::HeldRowState::Withdrawn {
                    withdraws_attestation_id,
                    ..
                } => assert_eq!(withdraws_attestation_id, w.attestation_id, "I1601 {what}"),
                other => panic!("I1601 {what}: Withdrawn, not {other:?}"),
            }
            let late = d
                .put_attestation(SignedAttestation {
                    attestation: peer_row.clone(),
                })
                .await
                .expect_err("I1601: a later copy is refused");
            assert!(
                late.to_string()
                    .contains(crate::federation::steward_purge::token::TOMBSTONED),
                "I1601 {what}: by the tombstone: {late}"
            );
        }
    }

    /// **I5709** — see the module header.
    pub(crate) async fn i5709_a_track_record_is_not_the_subjects_to_withdraw(
        d: &dyn FederationDirectory,
        s: &str,
    ) {
        let [_moderator, author, member, room] = room(d, "i5709", s).await;
        let dimension = format!("moderation_track_record:{}:v1", e2::kid_thumb(&room));
        for order in [Order::TargetFirst, Order::WithdrawsFirst] {
            let what = format!("{order:?}");
            // The subject's withdraws of a track record about them.
            let record = about(&member, &dimension, &author, &room, None);
            let w = withdraws(&author, &record);
            let e = arrive(d, order, &record, &w)
                .await
                .expect_err("I5709: the door refuses it, in either order");
            assert_eq!(e.kind(), "federation_withdraws_not_admitted", "I5709: {e}");
            assert_eq!(
                readers(d, &author, &record.attestation_id, &w.attestation_id).await,
                [false; 4],
                "I5709 {what}: a track record stays live for every reader"
            );
            // Its attester withdraws it (rule 1), in either order.
            let record = about(&member, &dimension, &author, &room, None);
            let w = withdraws(&member, &record);
            arrive(d, order, &record, &w)
                .await
                .expect("I5709: the attester withdraws its track record");
            assert_eq!(
                readers(d, &author, &record.attestation_id, &w.attestation_id).await,
                [true; 4],
                "I5709 {what}: the attester's withdraws retires it for every reader"
            );
        }
    }

    /// **I5710** — see the module header.
    pub(crate) async fn i5710_a_quarantine_marker_is_not_the_subjects_to_withdraw(
        d: &dyn FederationDirectory,
        s: &str,
    ) {
        let [moderator, author, _member, room] = room(d, "i5710", s).await;
        for order in [Order::TargetFirst, Order::WithdrawsFirst] {
            let what = format!("{order:?}");
            // The subject's withdraws of a marker about them.
            let marker = about(&moderator, "quarantine:withheld:v1", &author, &room, None);
            let w = withdraws(&author, &marker);
            let e = arrive(d, order, &marker, &w)
                .await
                .expect_err("I5710: the door refuses it, in either order");
            assert_eq!(e.kind(), "federation_withdraws_not_admitted", "I5710: {e}");
            assert_eq!(
                readers(d, &author, &marker.attestation_id, &w.attestation_id).await,
                [false; 4],
                "I5710 {what}: a quarantine marker stays live for every reader"
            );
            // Its attester withdraws it (rule 1), in either order.
            let marker = about(&moderator, "quarantine:withheld:v1", &author, &room, None);
            let w = withdraws(&moderator, &marker);
            arrive(d, order, &marker, &w)
                .await
                .expect("I5710: the attester withdraws its marker");
            assert_eq!(
                readers(d, &author, &marker.attestation_id, &w.attestation_id).await,
                [true; 4],
                "I5710 {what}: the attester's withdraws retires it for every reader"
            );
        }
    }

    /// `agent`'s own `trace:complete:v1` row (the inline form), naming
    /// `person` among its subjects beside the agent itself (a trace is
    /// self-emitted).
    fn own_trace(agent: &str, person: &str) -> Attestation {
        let id = uuid::Uuid::new_v4().to_string();
        let env = serde_json::json!({
            "dimension": crate::ingest::TRACE_ATTESTATION_DIMENSION,
            "trace_id": format!("trace-{id}"),
            "agent_id_hash": "deadbeef",
            "trace": { "trace_id": format!("trace-{id}"), "components": [] },
        });
        let mut r = ts::bare_attestation(&id, agent, agent, &env);
        r.attestation_type = attestation_type::SCORES.into();
        r.weight = None;
        r.cohort_scope = cohort_scope::FEDERATION.into();
        r.subject_key_ids = vec![agent.to_owned(), person.to_owned()];
        ts::seal_row_in_place(agent, &mut r);
        r
    }

    /// **I5712** — see the module header.
    pub(crate) async fn i5712_an_agents_own_trace_is_not_a_named_persons_to_withdraw(
        d: &dyn FederationDirectory,
        s: &str,
    ) {
        let agent = format!("i5712-agent-{s}");
        let person = format!("i5712-person-{s}");
        ts::register_hybrid_key_as(d, &agent, &agent, identity_type::AGENT).await;
        ts::register_hybrid_key_as(d, &person, &person, identity_type::USER).await;
        for order in [Order::TargetFirst, Order::WithdrawsFirst] {
            let what = format!("{order:?}");
            let trace = own_trace(&agent, &person);
            let w = withdraws(&person, &trace);
            let e = arrive(d, order, &trace, &w)
                .await
                .expect_err("I5712: the door refuses it, in either order");
            assert_eq!(e.kind(), "federation_withdraws_not_admitted", "I5712: {e}");
            assert_eq!(
                readers(d, &person, &trace.attestation_id, &w.attestation_id).await,
                [false; 4],
                "I5712 {what}: the agent's trace stays live for every reader"
            );
            let trace = own_trace(&agent, &person);
            let w = withdraws(&agent, &trace);
            arrive(d, order, &trace, &w)
                .await
                .expect("I5712: the agent withdraws its own trace");
            assert_eq!(
                readers(d, &person, &trace.attestation_id, &w.attestation_id).await,
                [true; 4],
                "I5712 {what}: the agent's withdraws retires it for every reader"
            );
        }
    }

    /// A federation-scope plain row by `by` naming `subject`.
    fn plain_about(by: &str, subject: &str) -> Attestation {
        let id = uuid::Uuid::new_v4().to_string();
        let env = serde_json::json!({
            "id": id,
            "dimension": PLAIN,
            "score": crate::federation::namespace::registry::in_class_score(PLAIN),
            "confidence": 0.9,
        });
        let mut r = ts::bare_attestation(&id, by, by, &env);
        r.attestation_type = attestation_type::SCORES.into();
        r.weight = None;
        r.cohort_scope = cohort_scope::FEDERATION.into();
        r.subject_key_ids = vec![subject.to_owned()];
        ts::seal_row_in_place(by, &mut r);
        r
    }

    /// A federation-scope plain row by `by` naming `subject`, carrying a
    /// `class` member when `class` is given.
    fn plain_classed(by: &str, subject: &str, class: Option<&str>) -> Attestation {
        let id = uuid::Uuid::new_v4().to_string();
        let mut env = serde_json::json!({
            "id": id,
            "dimension": PLAIN,
            "score": crate::federation::namespace::registry::in_class_score(PLAIN),
            "confidence": 0.9,
        });
        if let Some(c) = class {
            env["class"] = serde_json::json!(c);
        }
        let mut r = ts::bare_attestation(&id, by, by, &env);
        r.attestation_type = attestation_type::SCORES.into();
        r.weight = None;
        r.cohort_scope = cohort_scope::FEDERATION.into();
        r.subject_key_ids = vec![subject.to_owned()];
        ts::seal_row_in_place(by, &mut r);
        r
    }

    /// **I5716** — see the module header.
    pub(crate) async fn i5716_a_classed_act_is_kept_from_its_subject(
        d: &dyn FederationDirectory,
        s: &str,
    ) {
        use crate::federation::edition2::fold;
        use crate::federation::edition2::voices::carried_row_id;
        let k = |n: &str| format!("i5716-{n}-{s}");
        let (body, person) = (k("body"), k("person"));
        for u in [&body, &person] {
            ts::register_hybrid_key_as(d, u, u, identity_type::USER).await;
        }
        for order in [Order::TargetFirst, Order::WithdrawsFirst] {
            let what = format!("{order:?}");
            // The subject's withdrawal of a classed act: held, never admitted.
            let act = plain_classed(&body, &person, Some("conviction"));
            let w = withdraws(&person, &act);
            let _ = arrive(d, order, &act, &w).await;
            assert!(
                d.get_attestation(&w.attestation_id)
                    .await
                    .unwrap()
                    .is_none(),
                "I5716 {what}: the subject's withdrawal is not admitted"
            );
            let rid = carried_row_id(&w).expect("an edition-2 row");
            assert_eq!(
                fold::why_held(d, &rid)
                    .await
                    .unwrap()
                    .map(|h| h.reason)
                    .as_deref(),
                Some(fold::reason::WITHDRAWS_CLASS_UNREAD),
                "I5716 {what}: held by name"
            );
            assert_eq!(
                readers(d, &person, &act.attestation_id, &w.attestation_id).await,
                [false; 4],
                "I5716 {what}: the classed act stays live for every reader"
            );
            // Its signer takes back its own words (rule 1).
            let act = plain_classed(&body, &person, Some("conviction"));
            let w = withdraws(&body, &act);
            arrive(d, order, &act, &w)
                .await
                .expect("I5716: the signer withdraws its own act");
            assert_eq!(
                readers(d, &person, &act.attestation_id, &w.attestation_id).await,
                [true; 4],
                "I5716 {what}: the signer's withdrawal retires it for every reader"
            );
            // No `class`: an ordinary row, its subject withdraws it (rule 2).
            let plain = plain_classed(&body, &person, None);
            let w = withdraws(&person, &plain);
            arrive(d, order, &plain, &w)
                .await
                .expect("I5716: the subject withdraws an unclassed row");
            assert_eq!(
                readers(d, &person, &plain.attestation_id, &w.attestation_id).await,
                [true; 4],
                "I5716 {what}: an unclassed row retires for every reader"
            );
        }
    }

    /// **I5713** — see the module header.
    pub(crate) async fn i5713_an_affiliation_withdraws_no_statement_about_itself(
        d: &dyn FederationDirectory,
        s: &str,
    ) {
        use crate::federation::membership_acceptance_invariants::bodies::found_affiliation;
        let k = |n: &str| format!("i5713-{n}-{s}");
        let (seat, member, peer, aff, both) =
            (k("seat"), k("member"), k("peer"), k("aff"), k("both"));
        for u in [&seat, &member, &peer] {
            ts::register_hybrid_key_as(d, u, u, identity_type::USER).await;
        }
        // GID-prod.rev2 — `aff` is founded under its DERIVED id (a
        // group-ref); `both` is a person's key and nothing else: under the
        // derived id no affiliation can be founded under a key's id, so the
        // state the earlier key-record-first order decided cannot be built,
        // and the FORM decides.
        ts::register_hybrid_key_as(d, &both, &both, identity_type::USER).await;
        let aff_id = found_affiliation(d, &aff, "quorum:1/1", &[&seat, &member], &[])
            .await
            .unwrap();
        assert_eq!(
            aff_id,
            e2::room_id(&aff),
            "I5713 premise: founded under its derived id"
        );
        assert!(
            crate::federation::edition2::group_id::is_group_ref(&aff_id)
                && !crate::federation::edition2::group_id::is_group_ref(&e2::kid(&both)),
            "I5713 premise: the body's id is a group-ref and the person's key id is not"
        );
        assert!(
            d.lookup_community(&aff_id)
                .await
                .unwrap()
                .is_some_and(|c| matches!(
                    crate::federation::affiliation_config::declared_cohort(&c),
                    Ok(crate::federation::cohort::Cohort::Affiliations)
                )),
            "I5713 premise: the record declares `affiliations`"
        );
        for order in [Order::TargetFirst, Order::WithdrawsFirst] {
            let what = format!("{order:?}");
            // A seat does not withdraw a statement about the body.
            let about_body = plain_about(&peer, &aff);
            let w = withdraws(&seat, &about_body);
            let e = arrive(d, order, &about_body, &w)
                .await
                .expect_err("I5713: the door refuses it, in either order");
            assert_eq!(e.kind(), "federation_withdraws_not_admitted", "I5713: {e}");
            assert_eq!(
                readers(d, &seat, &about_body.attestation_id, &w.attestation_id).await,
                [false; 4],
                "I5713 {what}: a statement about the affiliation stays live for every reader"
            );
            // The row's signer takes back its own words (rule 1).
            let about_body = plain_about(&peer, &aff);
            let w = withdraws(&peer, &about_body);
            arrive(d, order, &about_body, &w)
                .await
                .expect("I5713: the signer withdraws its own row");
            assert_eq!(
                readers(d, &peer, &about_body.attestation_id, &w.attestation_id).await,
                [true; 4],
                "I5713 {what}: the signer's withdraws retires it for every reader"
            );
            // A statement about a MEMBER: the member's standing is untouched.
            let about_member = plain_about(&peer, &member);
            let w = withdraws(&member, &about_member);
            arrive(d, order, &about_member, &w)
                .await
                .expect("I5713: a member withdraws a peer's row about them");
            assert_eq!(
                readers(d, &member, &about_member.attestation_id, &w.attestation_id).await,
                [true; 4],
                "I5713 {what}: a member-subject row retires for every reader"
            );
            // FORM first: an id that is not a group-ref is no body's.
            let about_key = plain_about(&peer, &both);
            let w = withdraws(&both, &about_key);
            arrive(d, order, &about_key, &w)
                .await
                .expect("I5713: the key's person withdraws a peer's row about them");
            assert_eq!(
                readers(d, &both, &about_key.attestation_id, &w.attestation_id).await,
                [true; 4],
                "I5713 {what}: form first: the row retires for every reader"
            );
        }
    }

    /// **I5715** — see the module header.
    pub(crate) async fn i5715_only_the_signers_own_key_erases_a_trace(
        d: &dyn FederationDirectory,
        s: &str,
    ) {
        let k = |n: &str| format!("i5715-{n}-{s}");
        let (node, owner, person) = (k("node"), k("owner"), k("person"));
        ts::register_hybrid_key_as(d, &owner, &owner, identity_type::USER).await;
        ts::register_hybrid_key_as(d, &person, &person, identity_type::USER).await;
        e2::put_key(d, &node, &["node"]).await;
        crate::federation::admission::steward_liveness_test_support::bind_machine_owner(
            d, &owner, &node,
        )
        .await;
        assert_eq!(
            crate::federation::admission::owner_of(d, &e2::kid(&node))
                .await
                .expect("owner_of")
                .as_deref(),
            Some(e2::kid(&owner).as_str()),
            "I5715 premise: the node is the owner's"
        );
        for order in [Order::TargetFirst, Order::WithdrawsFirst] {
            let what = format!("{order:?}");
            let trace = own_trace(&node, &person);
            for (by, who) in [(&owner, "the owner"), (&person, "a named person")] {
                let w = withdraws(by, &trace);
                let e = arrive(d, order, &trace, &w)
                    .await
                    .expect_err("I5715: refused, in either order");
                assert_eq!(
                    e.kind(),
                    "federation_withdraws_not_admitted",
                    "I5715 {who}: {e}"
                );
                assert_eq!(
                    readers(d, &owner, &trace.attestation_id, &w.attestation_id).await,
                    [false; 4],
                    "I5715 {what}: {who} does not erase the trace"
                );
            }
            let w = withdraws(&node, &trace);
            arrive(d, Order::TargetFirst, &trace, &w)
                .await
                .expect("I5715: the signer's own key withdraws its trace");
            assert_eq!(
                readers(d, &owner, &trace.attestation_id, &w.attestation_id).await,
                [true; 4],
                "I5715 {what}: the signer's withdraws retires it for every reader"
            );
            let held_w = d
                .get_attestation(&w.attestation_id)
                .await
                .unwrap()
                .expect("I5715: the withdrawal is held");
            let descent = crate::federation::withdrawn_content::descend(
                d,
                &held_w,
                "i5715",
                None,
                crate::federation::withdrawn_content::KeepPolicy::default(),
            )
            .await
            .expect("I5715: the descent reads");
            assert!(
                matches!(
                    descent,
                    crate::federation::withdrawn_content::Descent::Descended { .. }
                        | crate::federation::withdrawn_content::Descent::AlreadyDescended
                ),
                "I5715 {what}: the trace's content descends: {descent:?}"
            );
        }
    }

    /// **I5714** — see the module header.
    pub(crate) async fn i5714_an_unresolved_subject_waits_never_admits(
        d: &dyn FederationDirectory,
        s: &str,
    ) {
        use crate::federation::edition2::fold;
        use crate::federation::edition2::voices::carried_row_id;
        let k = |n: &str| format!("i5714-{n}-{s}");
        let (peer, person, stranger) = (k("peer"), k("person"), k("stranger"));
        for u in [&peer, &person, &stranger] {
            ts::register_hybrid_key_as(d, u, u, identity_type::USER).await;
        }
        // A person subject resolves by its key record: nothing to wait for.
        let about_person = plain_about(&peer, &person);
        let w = withdraws(&person, &about_person);
        arrive(d, Order::TargetFirst, &about_person, &w)
            .await
            .expect("I5714: a person withdraws a peer's row about them at once");
        assert_eq!(
            readers(d, &person, &about_person.attestation_id, &w.attestation_id).await,
            [true; 4],
            "I5714: a person-subject withdrawal retires for every reader"
        );
        // A subject id with no record of either kind: a stranger is refused at
        // once, not held (it would not admit even with the subject counted).
        let nobody = e2::kid(&k("nobody"));
        let about_nobody = plain_about(&peer, &nobody);
        let w = withdraws(&stranger, &about_nobody);
        let e = arrive(d, Order::TargetFirst, &about_nobody, &w)
            .await
            .expect_err("I5714: a stranger is refused");
        assert_eq!(e.kind(), "federation_withdraws_not_admitted", "I5714: {e}");
        let rid = carried_row_id(&w).expect("an edition-2 row");
        assert!(
            fold::why_held(d, &rid).await.unwrap().is_none(),
            "I5714: refused at once, never held on the unresolved subject"
        );
        assert_eq!(
            readers(
                d,
                &stranger,
                &about_nobody.attestation_id,
                &w.attestation_id
            )
            .await,
            [false; 4],
            "I5714: live for every reader"
        );
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
                        // v62 (E3): the rule is a column, not a member of the
                        // statement, so the offered bytes are unchanged.
                        w.withdraws_admission_rule = Some(forged);
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
                                // v62 (E3): the early composer waits; nothing,
                                // and so no offered stamp, is kept.
                                let early = deliver(d, via, &w).await;
                                assert!(
                                    d.get_attestation(&w.attestation_id)
                                        .await
                                        .unwrap()
                                        .is_none(),
                                    "I1603 {what}: an early withdraws is kept nowhere: {early:?}"
                                );
                                deliver(d, via, &target).await.expect("I1603: the target");
                                deliver(d, via, &w)
                                    .await
                                    .expect_err("I1603: re-offered, the door refuses it");
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
            // v62 (E3b r3): now-relative — the node's voice is over the same
            // payload, and the builder's fixed instant lies outside a node
            // key's default record window (CC 2.4.1.1).
            binding.asserted_at = chrono::DateTime::<chrono::Utc>::from_timestamp_millis(
                (chrono::Utc::now() - chrono::Duration::minutes(5)).timestamp_millis(),
            )
            .expect("an instant");
            binding.scrub_timestamp = binding.asserted_at;
            // v62 (E3): re-sealed by its signer's SEED (`reseal` would sign as
            // the stored identity-ref).
            ts::seal_row_in_place(&owner, &mut binding);
            // v62 (E3b r3, K2.api): the binding lands through the shared
            // `put_sealed_owner_binding` (owner's statement, then the node's
            // voice, C557); the composer still goes through `put`.
            let w = withdraws(&node, &binding);
            match order {
                Order::TargetFirst => {
                    ts::put_sealed_owner_binding(d, &binding, &node)
                        .await
                        .expect("I1604: the binding lands");
                    let e = put(d, &w)
                        .await
                        .expect_err("I1604: in order the door refuses it (CC 3.2 ceremony)");
                    assert!(
                        matches!(e, Error::OwnershipReclaimRefused { .. }),
                        "I1604: refused by the recovery gate: {e:?}"
                    );
                }
                Order::WithdrawsFirst => {
                    // v62 (E3): the early composer waits for its target; the
                    // re-offer meets the same ceremony refusal as in order.
                    let early = put(d, &w).await;
                    assert!(
                        d.get_attestation(&w.attestation_id)
                            .await
                            .unwrap()
                            .is_none(),
                        "I1604: an early withdraws is kept nowhere: {early:?}"
                    );
                    ts::put_sealed_owner_binding(d, &binding, &node)
                        .await
                        .expect("I1604: the binding lands");
                    let e = put(d, &w)
                        .await
                        .expect_err("I1604: re-offered, the door refuses it");
                    assert!(
                        matches!(e, Error::OwnershipReclaimRefused { .. }),
                        "I1604: refused by the recovery gate: {e:?}"
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
                    &e2::kid(&node),
                    DelegationEdgeFilter::OwnerBindingOnly,
                )
                .await
                .expect("granters")
                .contains(&e2::kid(&owner)),
                "I1604 {what}: the owner-binding walk keeps the owner"
            );
            assert_eq!(
                owner_of(d, &e2::kid(&node)).await.expect("owner_of"),
                Some(e2::kid(&owner)),
                "I1604 {what}: the node is still owned"
            );

            // Control: the owner's own `withdraws` ends the binding. It is
            // attested to the node, as a binding's retraction is: the
            // owner-binding walk reads the retractions about its subject.
            let mut by_owner = withdraws(&owner, &binding);
            by_owner.attested_key_id = e2::kid(&node);
            ts::seal_row_in_place(&owner, &mut by_owner);
            put(d, &by_owner)
                .await
                .expect("I1604: the owner withdraws its binding");
            assert_eq!(
                owner_of(d, &e2::kid(&node)).await.expect("owner_of"),
                None,
                "I1604 {what}: the owner's withdraws ends the binding"
            );
        }
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
    on_sqlite_and_postgres!(
        i5709,
        bodies::i5709_a_track_record_is_not_the_subjects_to_withdraw
    );
    on_sqlite_and_postgres!(
        i5710,
        bodies::i5710_a_quarantine_marker_is_not_the_subjects_to_withdraw
    );
    on_sqlite_and_postgres!(
        i5712,
        bodies::i5712_an_agents_own_trace_is_not_a_named_persons_to_withdraw
    );
    on_sqlite_and_postgres!(
        i5713,
        bodies::i5713_an_affiliation_withdraws_no_statement_about_itself
    );
    on_sqlite_and_postgres!(
        i5714,
        bodies::i5714_an_unresolved_subject_waits_never_admits
    );
    on_sqlite_and_postgres!(i5715, bodies::i5715_only_the_signers_own_key_erases_a_trace);
    on_sqlite_and_postgres!(i5716, bodies::i5716_a_classed_act_is_kept_from_its_subject);
    on_sqlite_and_postgres!(i1603, bodies::i1603_a_forged_stamp_is_never_kept);
    on_sqlite_and_postgres!(i1604, bodies::i1604_a_node_cannot_outrun_its_owner);
}
