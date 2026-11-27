//! v62.0.0 (ACK-1, ACK-1b, ACK-2; CC v1.0-rc22-pre4 Part 3 l.208, Part 2
//! l.991–998, CC 2.4.1.1, CC 2.7.3; the Constitution's receipt rulings of
//! 2026-11-24 and their correction) — **the `act:ack` receipt at the door,
//! and its draft.**
//!
//! - **I6820** (pure) — the shape: 1 and 256 acts check; 257 is refused
//!   `ack_names_too_many` (the door's `check_shape` and the interim
//!   `produce::check_refs` alike); no act, or a `refs.head`, is refused
//!   `edition2_payload_invalid`. `act_ack_payload` states the acts as a
//!   sorted set with no duplicate and the placement it is given, read back by
//!   `placement_of`; a membership row with no `cohort_scope` is placed at its
//!   group; `is_receipt_of` holds per act (equal placement only).
//! - **I6821** (sqlite + postgres) — a member's drafted receipt of a held
//!   room act LANDS at the room's scope (it names no head: the corrected head
//!   cell; before, a room-placed receipt was refused `act_names_no_head`).
//! - **I6822** (sqlite + postgres) — the receipt is never withdrawn: its
//!   author's `withdraws` of it is not admitted, nothing of it is kept, and
//!   the receipt stays held.
//! - **I6823** (sqlite + postgres) — a node's receipt LANDS (ACK-1b: never
//!   refused for what its key record says; it keeps nothing).
//! - **I6824** (sqlite + postgres) — a receipt drafted for a member's SECOND
//!   DEVICE (`act_ack_draft` naming the device key), signed by it, lands.
//! - **I6825** (sqlite + postgres) — a receipt naming an act not held here
//!   WAITS (`Pending`, held `link_unheld`) and concludes once the act lands
//!   (Q1).
//! - **I6826** (sqlite + postgres) — a receipt by the signer of an act it
//!   names LANDS (ACK-1b; it keeps nothing).
//! - **I6827** (sqlite + postgres) — a receipt placed off its act's scope (at
//!   `federation`, of a room act) is KEPT (lands) and is no receipt of that
//!   act (`is_receipt_of` false); the draft refuses acts at two scopes.
//! - **I6828** (sqlite + postgres) — a receipt by a key with no role in the
//!   act (a registered stranger) LANDS: the door reads no role (Q2; what it
//!   keeps in force is the conferral read's, ACK-3).
//! - **I6829 / I6830** (pure, `kernel::receipts`; ACK-3) — one wire receipt
//!   is one conferral row per act at its own scope, carrying the wire id;
//!   through `ciris_kernel::conferral::answers` it keeps both acts in force
//!   (E8), a node's receipt or one with the end in its past keeps nothing.
//! - **I6831** (sqlite + postgres; ACK-3) — `receipts_of` over the store:
//!   one wire receipt of two acts presented as each act's own row, the
//!   off-scope receipt as nothing.
//! - **I6832** (sqlite + postgres; ACK-4) — a body's COUNTED receipt is a
//!   receipt of the act only where its voices meet the count at the head the
//!   act names: one voice of three presents nothing; two present the room's
//!   receipt.

#[cfg(test)]
mod pure {
    use crate::federation::edition2::act_ack::{
        acked_acts, act_ack_payload, check_shape, is_receipt_of, placement_of, ACT_ACK_DIMENSION,
    };
    use crate::federation::edition2::emit::sorted_map;
    use crate::federation::edition2::names::{names_of, RowId};
    use crate::federation::edition2::produce::{check_refs, ACK_NAMES_TOO_MANY};
    use crate::federation::{malformed_row, Error};
    use ciris_verify_core::cde::Value;

    fn t(s: &str) -> Value {
        Value::Text(s.to_owned())
    }

    fn ack_set(n: usize) -> Value {
        let mut acks: Vec<Value> = (0..n)
            .map(|i| {
                let mut d = [0u8; 32];
                d[..8].copy_from_slice(&(i as u64).to_be_bytes());
                ciris_verify_core::edition2::row_ref(&d)
            })
            .collect();
        acks.sort_by_key(ciris_verify_core::cde::encode);
        Value::Array(acks)
    }

    fn receipt(n: usize, head: bool) -> Value {
        let mut refs = Vec::new();
        if n > 0 {
            refs.push((t("also"), sorted_map(vec![(t("ack"), ack_set(n))])));
        }
        if head {
            refs.push((t("head"), ciris_verify_core::edition2::row_ref(&[9u8; 32])));
        }
        let mut m = vec![
            (t("asserted_at"), Value::Uint(1_700_000_000_000)),
            (t("dimension"), t(ACT_ACK_DIMENSION)),
        ];
        if !refs.is_empty() {
            m.push((t("refs"), sorted_map(refs)));
        }
        sorted_map(m)
    }

    fn reason(e: &Error) -> &'static str {
        match e {
            Error::MalformedRow { reason, .. } => reason,
            other => other.kind(),
        }
    }

    #[test]
    fn i6820_the_receipt_shape() {
        check_shape(&receipt(1, false)).expect("I6820: one act");
        check_shape(&receipt(256, false)).expect("I6820: 256 acts");
        assert_eq!(
            reason(&check_shape(&receipt(257, false)).unwrap_err()),
            malformed_row::ACK_NAMES_TOO_MANY,
            "I6820: 257 acts"
        );
        assert_eq!(
            reason(&check_shape(&receipt(0, false)).unwrap_err()),
            malformed_row::EDITION2_PAYLOAD_INVALID,
            "I6820: no act"
        );
        assert_eq!(
            reason(&check_shape(&receipt(2, true)).unwrap_err()),
            malformed_row::EDITION2_PAYLOAD_INVALID,
            "I6820: a receipt names no head"
        );
        // The interim refs reader carries the same cap (deleted at the
        // Verify 23.6.0 pin).
        let refs = |n| sorted_map(vec![(t("also"), sorted_map(vec![(t("ack"), ack_set(n))]))]);
        check_refs(&refs(256)).expect("I6820: check_refs admits 256");
        assert_eq!(
            check_refs(&refs(257)),
            Err(ACK_NAMES_TOO_MANY),
            "I6820: check_refs refuses 257"
        );
        // The payload: a sorted set, no duplicate, the placement given.
        let iss = ciris_verify_core::edition2::identity_ref(&[5u8; 32]);
        let acts = [RowId([3u8; 32]), RowId([2u8; 32]), RowId([3u8; 32])];
        let at_room = ("community".to_owned(), Some("room-x".to_owned()));
        let p = act_ack_payload(&acts, &iss, Some(&at_room), 1_700_000_000_000)
            .expect("I6820: the payload");
        let names = names_of(&p).expect("I6820: refs");
        assert_eq!(
            acked_acts(&names),
            vec![RowId([2u8; 32]), RowId([3u8; 32])],
            "I6820: a sorted set"
        );
        assert_eq!(placement_of(&p), at_room, "I6820: the placement reads back");
        let at_family = ("family".to_owned(), Some("fam-y".to_owned()));
        let p = act_ack_payload(&acts, &iss, Some(&at_family), 1).expect("I6820: at a family");
        assert_eq!(
            p.get_text("family_id").and_then(Value::as_text),
            Some("fam-y"),
            "I6820: a family placement names family_id"
        );
        let p = act_ack_payload(&acts, &iss, None, 1).expect("I6820: unplaced");
        assert_eq!(
            placement_of(&p),
            ("federation".to_owned(), None),
            "I6820: no cohort_scope reads federation"
        );
        // A membership row names its group by `group_kind` + `group`.
        let membership = sorted_map(vec![
            (t("group_kind"), t("community")),
            (t("group"), t("room-x")),
        ]);
        assert_eq!(
            placement_of(&membership),
            at_room,
            "I6820: a membership row is placed at its group"
        );
        // Per act: a receipt at the room is a receipt of the room's act, and
        // of no act elsewhere.
        let at_room_receipt =
            act_ack_payload(&acts, &iss, Some(&at_room), 1).expect("I6820: at the room");
        assert!(
            is_receipt_of(&at_room_receipt, &membership),
            "I6820: a receipt of the act at its own scope"
        );
        assert!(
            !is_receipt_of(&p, &membership),
            "I6820: an unplaced (federation) receipt is no receipt of a room act"
        );
        let many: Vec<RowId> = (0..257u32)
            .map(|i| {
                let mut d = [0u8; 32];
                d[..4].copy_from_slice(&i.to_be_bytes());
                RowId(d)
            })
            .collect();
        assert_eq!(
            reason(&act_ack_payload(&many, &iss, None, 1).unwrap_err()),
            malformed_row::ACK_NAMES_TOO_MANY,
            "I6820: the payload refuses 257"
        );
    }
}

/// The backend witnesses (I6821–I6828), sqlite and postgres.
#[cfg(all(test, any(feature = "sqlite", feature = "postgres")))]
pub(crate) mod bodies {
    use crate::federation::edition2::act_ack::{
        act_ack_draft, act_ack_payload, is_receipt_of, placement_of,
    };
    use crate::federation::edition2::fixture_switch as e2;
    use crate::federation::edition2::ingest::StatementOutcome;
    use crate::federation::edition2::names::RowId;
    use crate::federation::edition2::verdict::{row_state, RowState};
    use crate::federation::membership_acceptance_invariants::bodies::{id_of, reg};
    use crate::federation::resign_invariants::bodies::{room_end_voices, room_of_three};
    use crate::federation::types::RevocationLeaf;
    use crate::federation::FederationDirectory;
    use chrono::{Duration, Utc};

    type Placement = (String, Option<String>);

    /// A signer's identity-ref and kid, from its fixture key.
    fn iss_kid(seed: &str) -> (String, [u8; 32]) {
        let kid = ciris_verify_core::edition2::thumbprint(e2::signing_key(seed).public_key());
        (ciris_verify_core::edition2::identity_ref(&kid), kid)
    }

    /// A room of three (`majority`) `a`, `b`, `c`, and the voices of one act
    /// in it (`a`'s own resignation), NOT yet put; its row id.
    async fn room_and_act_voices(
        d: &dyn FederationDirectory,
        tag: &str,
    ) -> (String, String, Vec<Vec<u8>>, RowId) {
        let (room, a, b, _c) = room_of_three(d, tag, "majority").await;
        let v = room_end_voices(
            d,
            &room,
            &a,
            &[&a],
            Utc::now() - Duration::hours(1),
            RevocationLeaf::Resignation,
        )
        .await;
        let act = crate::federation::edition2::group_fixtures::row_id_of(&v[0]);
        (room, b, v, act)
    }

    /// [`room_and_act_voices`], with the act put (it lands); and the act's
    /// placement (the room).
    async fn room_and_act(
        d: &dyn FederationDirectory,
        tag: &str,
    ) -> (String, String, RowId, Placement) {
        let (room, b, v, act) = room_and_act_voices(d, tag).await;
        assert!(
            matches!(
                e2::put_voices(d, &v).await,
                Ok(StatementOutcome::Row { .. })
            ),
            "{tag}: the act lands"
        );
        (room, b, act, placement_of_voice(&v[0]))
    }

    /// A receipt by `signer` (its own key) naming `acts`, placed at
    /// `placement`, at `at_ms`: signed by hand (no draft, so no held act is
    /// needed).
    fn receipt_by(signer: &str, acts: &[RowId], placement: &Placement, at_ms: u64) -> Vec<u8> {
        let key = e2::signing_key(signer);
        let (iss, _) = iss_kid(signer);
        let p = act_ack_payload(acts, &iss, Some(placement), at_ms).expect("a receipt payload");
        ciris_verify_core::edition2::sign_row_statement(
            &key,
            &iss,
            &iss,
            "scores",
            "act:ack",
            &p,
            vec![],
        )
        .expect("a receipt signs")
    }

    /// Put `statement`; it must land. Its row id.
    async fn lands(d: &dyn FederationDirectory, statement: Vec<u8>, what: &str) -> RowId {
        let id = RowId::of_statement(&statement).expect("a row id");
        let out = e2::put_voices(d, &[statement]).await;
        assert!(
            matches!(out, Ok(StatementOutcome::Row { .. })),
            "{what}: lands: {out:?}"
        );
        id
    }

    /// The placement of the act whose voice is `voice`.
    fn placement_of_voice(voice: &[u8]) -> Placement {
        crate::federation::edition2::liveness::statement_parts(voice)
            .map(|(_, p)| placement_of(&p))
            .expect("the act's payload")
    }

    /// **I6821** — a member's drafted receipt lands at the room's scope.
    pub(crate) async fn i6821_a_members_receipt_lands(d: &dyn FederationDirectory, s: &str) {
        let (room, b, act, at) = room_and_act(d, &format!("i6821-{s}")).await;
        assert_eq!(
            at.1.as_deref(),
            Some(room.as_str()),
            "I6821: the act is placed at the room"
        );
        let (iss, kid) = iss_kid(&b);
        let draft = act_ack_draft(d, &[act], &iss, &kid, e2::ms(Utc::now()))
            .await
            .expect("I6821: the draft");
        let p = ciris_verify_core::cde::decode(&draft.payload).expect("I6821: the payload");
        assert_eq!(
            placement_of(&p),
            at,
            "I6821: the draft places the receipt at its act's scope"
        );
        let st = draft.assemble(
            e2::signing_key(&b)
                .sign(&draft.sig_structure)
                .expect("b signs"),
        );
        lands(d, st, "I6821: a receipt at the room names no head and").await;
    }

    /// **I6822** — a receipt is never withdrawn.
    pub(crate) async fn i6822_a_receipt_is_never_withdrawn(d: &dyn FederationDirectory, s: &str) {
        let (_room, b, act, at) = room_and_act(d, &format!("i6822-{s}")).await;
        let rid = lands(
            d,
            receipt_by(&b, &[act], &at, e2::ms(Utc::now())),
            "I6822: b's receipt",
        )
        .await;
        let held = d
            .get_attestation(&rid.hex())
            .await
            .unwrap()
            .expect("I6822: the receipt is held");
        let (iss, _) = iss_kid(&b);
        let draft = crate::federation::subject_erasure::withdraws_draft(
            &held,
            &iss,
            e2::ms(Utc::now()) + 1,
        )
        .expect("I6822: a withdraws drafts");
        let sig = e2::signing_key(&b)
            .sign(&draft.sig_structure)
            .expect("b signs");
        let w = draft.assemble(sig);
        let wid = RowId::of_statement(&w).expect("the withdraws' row id");
        let out = e2::put_voices(d, &[w]).await;
        assert!(
            !matches!(out, Ok(StatementOutcome::Row { .. })),
            "I6822: the author's withdraws of a receipt is not admitted: {out:?}"
        );
        assert!(
            d.get_attestation(&wid.hex()).await.unwrap().is_none(),
            "I6822: no withdraws row is kept"
        );
        assert!(
            d.get_attestation(&rid.hex()).await.unwrap().is_some(),
            "I6822: the receipt stays"
        );
    }

    /// **I6823** — a node's receipt (placed where a node may write, the
    /// commons) LANDS: never refused for what its key record says (ACK-1b).
    pub(crate) async fn i6823_a_nodes_receipt(d: &dyn FederationDirectory, s: &str) {
        let (_room, _b, act, _at) = room_and_act(d, &format!("i6823-{s}")).await;
        let node = format!("i6823-{s}-node");
        e2::put_key(d, &node, &[crate::federation::types::identity_type::NODE]).await;
        let st = receipt_by(
            &node,
            &[act],
            &("federation".to_owned(), None),
            e2::ms(Utc::now()),
        );
        lands(d, st, "I6823: a node's receipt").await;
    }

    /// **I6824** — a receipt drafted for a member's second device lands.
    pub(crate) async fn i6824_a_second_devices_drafted_receipt_lands(
        d: &dyn FederationDirectory,
        s: &str,
    ) {
        let (_room, b, act, _at) = room_and_act(d, &format!("i6824-{s}")).await;
        let device = format!("i6824-{s}-phone");
        e2::put_key(d, &device, &[crate::federation::types::identity_type::USER]).await;
        crate::federation::occurrence_consent_invariants::bodies::put_bind(
            d,
            &b,
            &device,
            crate::federation::types::device_class::PHONE,
            e2::ms(Utc::now() - Duration::hours(2)),
        )
        .await;
        let (iss, _) = iss_kid(&b);
        let key = e2::signing_key(&device);
        let kid = ciris_verify_core::edition2::thumbprint(key.public_key());
        let draft = act_ack_draft(d, &[act], &iss, &kid, e2::ms(Utc::now()))
            .await
            .expect("I6824: the draft");
        assert_eq!(
            crate::federation::edition2::ingest::statement_kid(&draft.assemble(Vec::new())),
            Some(kid),
            "I6824: the draft names the device's key"
        );
        let st = draft.assemble(key.sign(&draft.sig_structure).expect("the device signs"));
        lands(d, st, "I6824: b's receipt from the second device").await;
    }

    /// **I6825** — a receipt waits for the act it names.
    pub(crate) async fn i6825_a_receipt_waits_for_its_act(d: &dyn FederationDirectory, s: &str) {
        let (_room, b, v, act) = room_and_act_voices(d, &format!("i6825-{s}")).await;
        let st = receipt_by(&b, &[act], &placement_of_voice(&v[0]), e2::ms(Utc::now()));
        let rid = RowId::of_statement(&st).expect("the receipt's row id");
        let out = e2::put_voices(d, &[st]).await.unwrap_or_else(|e| {
            panic!("I6825: a receipt of an unheld act waits, never refused: {e}")
        });
        assert!(
            matches!(out, StatementOutcome::Pending { .. }),
            "I6825: it waits: {out:?}"
        );
        assert_eq!(
            crate::federation::edition2::fold::why_held(d, &rid)
                .await
                .expect("the fold state reads")
                .map(|h| h.reason)
                .as_deref(),
            Some(crate::federation::edition2::fold::reason::LINK_UNHELD),
            "I6825: held link_unheld on the act"
        );
        assert!(
            matches!(
                e2::put_voices(d, &v).await,
                Ok(StatementOutcome::Row { .. })
            ),
            "I6825: the act lands"
        );
        assert_eq!(
            row_state(d, &rid).await.expect("the verdict reads"),
            RowState::Concluded,
            "I6825: the receipt concludes once its act is held"
        );
    }

    /// **I6826** — a receipt by the signer of the act it names (b receipts
    /// its own receipt; b stays seated) LANDS (ACK-1b).
    pub(crate) async fn i6826_a_receipt_of_ones_own_act(d: &dyn FederationDirectory, s: &str) {
        let (_room, b, act, at) = room_and_act(d, &format!("i6826-{s}")).await;
        let own = lands(
            d,
            receipt_by(&b, &[act], &at, e2::ms(Utc::now())),
            "I6826: b's receipt",
        )
        .await;
        let st = receipt_by(&b, &[own], &at, e2::ms(Utc::now()) + 1);
        lands(d, st, "I6826: a receipt of one's own act").await;
    }

    /// **I6827** — a receipt placed off its act's scope is KEPT and is no
    /// receipt of that act; the draft refuses acts at two scopes. **I6828** —
    /// a stranger's receipt (no role in the act) of a federation-placed
    /// receipt lands.
    pub(crate) async fn i6827_i6828_placement_and_role(d: &dyn FederationDirectory, s: &str) {
        let (_room, b, act, _at) = room_and_act(d, &format!("i6827-{s}")).await;
        // I6827 — b's receipt at federation of a room act.
        let federation: Placement = ("federation".to_owned(), None);
        let off = receipt_by(&b, &[act], &federation, e2::ms(Utc::now()));
        let off_id = RowId::of_statement(&off).expect("the receipt's row id");
        let payload_of = |st: &[u8]| {
            crate::federation::edition2::liveness::statement_parts(st)
                .map(|(_, p)| p)
                .expect("a payload")
        };
        let act_statement = crate::federation::edition2::head_rule::held_statement(d, &act)
            .await
            .expect("the act reads")
            .expect("the act is held");
        assert!(
            !is_receipt_of(&payload_of(&off), &payload_of(&act_statement)),
            "I6827: no receipt of the room act"
        );
        lands(d, off, "I6827: a receipt off its act's scope is kept: it").await;
        // The draft refuses acts at two scopes: the room act and b's
        // federation receipt.
        let (iss, kid) = iss_kid(&b);
        assert!(
            act_ack_draft(d, &[act, off_id], &iss, &kid, e2::ms(Utc::now()))
                .await
                .is_err(),
            "I6827: one receipt cannot be placed at two scopes"
        );
        // I6828 — z, a registered key with no part in either act, receipts
        // b's federation receipt at its scope: the door reads no role.
        let z = format!("i6828-{s}-z");
        reg(d, &[&z]).await;
        let z = id_of(&z);
        let st = receipt_by(&z, &[off_id], &federation, e2::ms(Utc::now()) + 1);
        lands(d, st, "I6828: a receipt from a key with no role").await;
    }

    /// **I6831** (ACK-3) — `kernel::receipts::receipts_of` over the store:
    /// in a room of a, b, c where a and c resign, b's ONE wire receipt
    /// naming both ends at the room is presented as a receipt of EACH (the
    /// wire id on both, signer b); b's federation receipt of a's end is
    /// presented as nothing (per act, off its scope); an act with no
    /// receipt has none.
    pub(crate) async fn i6831_receipts_of_over_the_store(d: &dyn FederationDirectory, s: &str) {
        use crate::kernel::receipts::{receipts_of, CRow};
        let (room, a, b, c) = room_of_three(d, &format!("i6831-{s}"), "majority").await;
        let mut acts = Vec::new();
        for (i, m) in [&a, &c].into_iter().enumerate() {
            let v = room_end_voices(
                d,
                &room,
                m,
                &[m],
                Utc::now() - Duration::minutes(60 - i64::try_from(i).expect("small")),
                RevocationLeaf::Resignation,
            )
            .await;
            let act = crate::federation::edition2::group_fixtures::row_id_of(&v[0]);
            assert!(
                matches!(
                    e2::put_voices(d, &v).await,
                    Ok(StatementOutcome::Row { .. })
                ),
                "I6831: {m}'s end lands"
            );
            acts.push((act, placement_of_voice(&v[0])));
        }
        let (xa, at) = acts[0].clone();
        let (xc, _) = acts[1].clone();
        assert!(
            receipts_of(d, &xa).await.unwrap().is_empty(),
            "I6831: no receipt yet"
        );
        let both = lands(
            d,
            receipt_by(&b, &[xa, xc], &at, e2::ms(Utc::now())),
            "I6831: b's receipt of both",
        )
        .await;
        let federation: Placement = ("federation".to_owned(), None);
        lands(
            d,
            receipt_by(&b, &[xa], &federation, e2::ms(Utc::now()) + 1),
            "I6831: b's federation receipt",
        )
        .await;
        let (iss, _) = iss_kid(&b);
        assert_eq!(
            receipts_of(d, &xa).await.unwrap(),
            vec![CRow::receipt(both, &iss, xa)],
            "I6831: a's end has b's room receipt, and not the federation one"
        );
        assert_eq!(
            receipts_of(d, &xc).await.unwrap(),
            vec![CRow::receipt(both, &iss, xc)],
            "I6831: c's end has the same wire receipt, as its own row"
        );
    }

    /// **I6832** (ACK-4) — a body's COUNTED receipt is counted per act, at
    /// the head that act names: in a `majority` room of a, b, c, c's end
    /// (acting from h0, where a, b, c are the members) is receipted by the
    /// room's count. One member's voice (1 of 3) presents nothing; a second
    /// voice meets the count, and the receipt is presented as the ROOM's,
    /// with the wire id.
    pub(crate) async fn i6832_a_counted_receipt(d: &dyn FederationDirectory, s: &str) {
        use crate::federation::edition2::act_ack::act_ack_counted_payload;
        use crate::kernel::receipts::{receipts_of, CRow};
        let (room, a, b, c) = room_of_three(d, &format!("i6832-{s}"), "majority").await;
        let v = room_end_voices(
            d,
            &room,
            &c,
            &[&c],
            Utc::now() - Duration::hours(1),
            RevocationLeaf::Resignation,
        )
        .await;
        let act = crate::federation::edition2::group_fixtures::row_id_of(&v[0]);
        assert!(
            matches!(
                e2::put_voices(d, &v).await,
                Ok(StatementOutcome::Row { .. })
            ),
            "I6832: c's end lands"
        );
        let at = placement_of_voice(&v[0]);
        let p = act_ack_counted_payload(&[act], Some(&at), e2::ms(Utc::now()))
            .expect("I6832: the counted payload");
        let voice = |seed: &str| {
            let key = e2::signing_key(seed);
            let (iss, _) = iss_kid(seed);
            ciris_verify_core::edition2::sign_row_statement(
                &key,
                &iss,
                &room,
                "scores",
                "act:ack",
                &p,
                vec![],
            )
            .expect("a voice signs")
        };
        let va = voice(&a);
        let k = RowId::of_statement(&va).expect("the receipt's row id");
        let out = e2::put_voices(d, &[va]).await;
        assert!(
            matches!(out, Ok(StatementOutcome::Row { .. })),
            "I6832: the counted receipt is kept on its first voice: {out:?}"
        );
        assert!(
            receipts_of(d, &act).await.unwrap().is_empty(),
            "I6832: one voice of three is short of the room's count: no receipt of the act"
        );
        let out = e2::put_voices(d, &[voice(&b)]).await;
        assert!(
            matches!(out, Ok(StatementOutcome::Voice { .. })),
            "I6832: b's voice joins it: {out:?}"
        );
        assert_eq!(
            receipts_of(d, &act).await.unwrap(),
            vec![CRow::receipt(k, &room, act)],
            "I6832: two of three meet the count: the ROOM's receipt of the act"
        );
    }
}

#[cfg(all(test, any(feature = "sqlite", feature = "postgres")))]
mod runners {
    fn suffix() -> String {
        uuid::Uuid::new_v4().simple().to_string()[..12].to_owned()
    }

    macro_rules! runners {
        ($modname:ident, $fresh:expr) => {
            mod $modname {
                use super::suffix;
                use crate::federation::FederationDirectory;
                #[tokio::test]
                async fn i6821_a_members_receipt_lands() {
                    let Some(d) = $fresh.await else { return };
                    super::super::bodies::i6821_a_members_receipt_lands(
                        &d as &dyn FederationDirectory,
                        &suffix(),
                    )
                    .await
                }
                #[tokio::test]
                async fn i6822_a_receipt_is_never_withdrawn() {
                    let Some(d) = $fresh.await else { return };
                    super::super::bodies::i6822_a_receipt_is_never_withdrawn(
                        &d as &dyn FederationDirectory,
                        &suffix(),
                    )
                    .await
                }
                #[tokio::test]
                async fn i6823_a_nodes_receipt() {
                    let Some(d) = $fresh.await else { return };
                    super::super::bodies::i6823_a_nodes_receipt(
                        &d as &dyn FederationDirectory,
                        &suffix(),
                    )
                    .await
                }
                #[tokio::test]
                async fn i6824_a_second_devices_drafted_receipt_lands() {
                    let Some(d) = $fresh.await else { return };
                    super::super::bodies::i6824_a_second_devices_drafted_receipt_lands(
                        &d as &dyn FederationDirectory,
                        &suffix(),
                    )
                    .await
                }
                #[tokio::test]
                async fn i6825_a_receipt_waits_for_its_act() {
                    let Some(d) = $fresh.await else { return };
                    super::super::bodies::i6825_a_receipt_waits_for_its_act(
                        &d as &dyn FederationDirectory,
                        &suffix(),
                    )
                    .await
                }
                #[tokio::test]
                async fn i6826_a_receipt_of_ones_own_act() {
                    let Some(d) = $fresh.await else { return };
                    super::super::bodies::i6826_a_receipt_of_ones_own_act(
                        &d as &dyn FederationDirectory,
                        &suffix(),
                    )
                    .await
                }
                #[tokio::test]
                async fn i6827_i6828_placement_and_role() {
                    let Some(d) = $fresh.await else { return };
                    super::super::bodies::i6827_i6828_placement_and_role(
                        &d as &dyn FederationDirectory,
                        &suffix(),
                    )
                    .await
                }
                #[tokio::test]
                async fn i6831_receipts_of_over_the_store() {
                    let Some(d) = $fresh.await else { return };
                    super::super::bodies::i6831_receipts_of_over_the_store(
                        &d as &dyn FederationDirectory,
                        &suffix(),
                    )
                    .await
                }
                #[tokio::test]
                async fn i6832_a_counted_receipt() {
                    let Some(d) = $fresh.await else { return };
                    super::super::bodies::i6832_a_counted_receipt(
                        &d as &dyn FederationDirectory,
                        &suffix(),
                    )
                    .await
                }
            }
        };
    }

    #[cfg(feature = "sqlite")]
    runners!(sqlite, async {
        use crate::store::Backend as _;
        let b = crate::store::sqlite::SqliteBackend::open_in_memory()
            .await
            .unwrap();
        b.run_migrations().await.unwrap();
        Some(b)
    });

    #[cfg(feature = "postgres")]
    runners!(postgres, async {
        use crate::store::Backend as _;
        let dsn = crate::test_pg::empty_dsn()?;
        let b = crate::store::postgres::PostgresBackend::connect(&dsn)
            .await
            .unwrap();
        b.run_migrations().await.unwrap();
        Some(b)
    });
}
