//! v62.0.0 (ACK-3; Kernel 11-24 on receipts; the Constitution's receipt
//! rulings of 2026-11-24 and their correction) — **an `act:ack` receipt
//! presented to `ciris_kernel::conferral`.**
//!
//! What the crate reads of a receipt (Kernel, 11-24): its `kind`
//! ([`Kind::Receipt`]) and `of` (the ONE act it acknowledges); its signer's
//! role, through the caller's `Standing::role`; and four causal-past
//! questions (the end in the receipt's past ⇒ it keeps nothing; a receipt
//! and an end concurrent and by the same signer, the "one say"; the receipt
//! in the past of a REMOVAL of its signer's key; the receipter's own end in
//! the receipt's past). So:
//!
//! - **One wire receipt naming n acts is n [`ConferralRow`]s**, one per act
//!   (`of`), each carrying the WIRE row's own id. The crate keys answers by
//!   the ACT's id and asks the past by the receipt's id, which is the same
//!   for each of the n (read from the crate's code, `conferral.rs`
//!   `receipts` / `kept` / `say`; no fixture case covers it: Kernel is told).
//! - **Per act** (the Constitution's placement ruling): a receipt is a
//!   receipt only of each act whose scope equals its own placement
//!   (`act_ack::is_receipt_of`); for any other act it is presented as
//!   nothing.
//! - **The signer** is the receipt's `iss`, the PERSON across keys (Kernel:
//!   "own is by member"), in the same key space the caller's role function
//!   reads.
//! - **Never un-fed**: a receipt is never withdrawn (ACK-1), so the set of
//!   receipts of an act only grows.
//!
//! A receipt from a node's key, from an act's own signer, or from anyone
//! with no role in the standing is presented like any other; the crate's
//! role read (`Role::Other` / `Role::Grantee`) gives it nothing to keep.

use ciris_kernel::conferral::{ConferralRow, Kind};
use ciris_verify_core::cde::Value;

use crate::federation::edition2::act_ack;
use crate::federation::edition2::names::{names_of, RowId};
use crate::federation::{Error, FederationDirectory};

/// One row as `ciris_kernel::conferral` reads it, persist's presentation:
/// the row's id, what it is to the standing, its signer (an identity-ref),
/// and the members the crate asks of a row of that kind.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct CRow {
    /// The row's id (for a receipt: the WIRE row's id, the same for each act
    /// it acknowledges).
    pub id: RowId,
    /// What the row is to the standing.
    pub kind: Kind,
    /// Its signer: the identity-ref (`iss`), the person across keys.
    pub signer: String,
    /// The head an act or an end names.
    pub head: Option<RowId>,
    /// The act a receipt acknowledges.
    pub of: Option<RowId>,
    /// The key a removal removes.
    pub target: Option<String>,
    /// The deputy edge a deputy's act is under.
    pub via: Option<RowId>,
    /// A count end that lifts the receipts of single co-holders.
    pub lifts: bool,
}

impl CRow {
    /// A receipt row: the wire receipt `id`, signed by `signer`, of `act`.
    #[must_use]
    pub fn receipt(id: RowId, signer: &str, act: RowId) -> Self {
        Self {
            id,
            kind: Kind::Receipt,
            signer: signer.to_owned(),
            head: None,
            of: Some(act),
            target: None,
            via: None,
            lifts: false,
        }
    }
}

impl ConferralRow for CRow {
    type Id = RowId;
    type Key = String;
    fn id(&self) -> &RowId {
        &self.id
    }
    fn kind(&self) -> Kind {
        self.kind
    }
    fn signer(&self) -> &String {
        &self.signer
    }
    fn head(&self) -> Option<&RowId> {
        self.head.as_ref()
    }
    fn of(&self) -> Option<&RowId> {
        self.of.as_ref()
    }
    fn target(&self) -> Option<&String> {
        self.target.as_ref()
    }
    fn via(&self) -> Option<&RowId> {
        self.via.as_ref()
    }
    fn lifts(&self) -> bool {
        self.lifts
    }
}

/// The receipt's `iss`, row id and payload, when `statement` is an
/// `act:ack` receipt (not a retraction).
fn receipt_parts(statement: &[u8]) -> Option<(RowId, String, Value)> {
    let (family, row_type) = crate::federation::edition2::emit::family_of_statement(statement)?;
    if family != act_ack::ACT_ACK_FAMILY
        || crate::federation::edition2::emit::carries_no_dimension(&row_type)
    {
        return None;
    }
    let id = RowId::of_statement(statement)?;
    let iss = crate::federation::edition2::occurrence::statement_iss(statement)?;
    let (_, payload) = crate::federation::edition2::liveness::statement_parts(statement)?;
    Some((id, iss, payload))
}

/// **The rows one held `act:ack` statement presents** to the conferral read:
/// one [`Kind::Receipt`] per act it names under `refs.also.ack` that is in
/// `acts` (the held acts: id and payload) and whose scope equals the
/// receipt's placement (`act_ack::is_receipt_of`), each carrying the wire
/// row's id. Empty for a statement that is no receipt.
#[must_use]
pub fn receipt_rows(statement: &[u8], acts: &[(RowId, Value)]) -> Vec<CRow> {
    let Some((id, iss, payload)) = receipt_parts(statement) else {
        return Vec::new();
    };
    // v62.0.0 (ACK-4) — a body's COUNTED receipt is a receipt of an act only
    // where its voices meet the count at that act's head
    // ([`counted_meets`], a directory read): never presented from its
    // statement alone.
    if act_ack::is_counted(&payload) {
        return Vec::new();
    }
    let Ok(names) = names_of(&payload) else {
        return Vec::new();
    };
    act_ack::acked_acts(&names)
        .into_iter()
        .filter_map(|of| {
            acts.iter()
                .find(|(a, _)| *a == of)
                .filter(|(_, act)| act_ack::is_receipt_of(&payload, act))
                .map(|_| CRow::receipt(id, &iss, of))
        })
        .collect()
}

/// v62.0.0 (ACK-4; the Constitution's Q3, 2026-11-24: "a body's counted
/// receipt is counted over the members at the head THE ACT IT NAMES names
/// (per act, at each act's own head)") — **do the voices of the counted
/// receipt `receipt` meet the count of the act `act_statement`'s body?**
/// The base is the members at the heads the ACT names, less the resignations
/// it cites (`lineage::count_base`, the COUNT reading); the protocol is the
/// one in force at that head (its lineage node's `consensus_protocol`); the
/// voices are the persons (`iss`) whose statements over the receipt are held
/// (`edition2_voices`), counted by `consensus::evaluate` as every ballot is.
/// `false` for an act that names no head (no body's count is defined), for
/// one naming SEVERAL heads (not judged until the tips fold is pinned,
/// kernel-v0.3.0), or for a head no node of which is held here. Every row
/// read is declared to the running fold attempt.
///
/// # Errors
/// Directory reads.
pub async fn counted_meets<F>(dir: &F, receipt: &RowId, act_statement: &[u8]) -> Result<bool, Error>
where
    F: FederationDirectory + ?Sized,
{
    use crate::federation::consensus::{evaluate, Ballot, Direction, Seat};
    use crate::federation::edition2::fold::{reads, Dep};
    let Some((_, act)) = crate::federation::edition2::liveness::statement_parts(act_statement)
    else {
        return Ok(false);
    };
    let Ok(names) = names_of(&act) else {
        return Ok(false);
    };
    let heads: Vec<RowId> = names
        .iter()
        .filter(|n| n.role == "head" || n.role == "further_heads")
        .map(|n| n.row)
        .collect();
    let [head] = heads.as_slice() else {
        return Ok(false);
    };
    let cites: Vec<RowId> = names
        .iter()
        .filter(|n| n.role == "also:cites")
        .map(|n| n.row)
        .collect();
    reads(Dep::Row(*head));
    // The head is a CONCLUDED row (the one verdict), never a kept statement.
    if !crate::federation::edition2::verdict::row_state(dir, head)
        .await?
        .is_concluded()
    {
        return Ok(false);
    }
    let Some(node) = dir.group_lineage_node(head).await? else {
        return Ok(false);
    };
    let Some(protocol) = node.consensus_protocol.clone() else {
        return Ok(false);
    };
    // The members at the act's head with their role tags, through the ONE
    // reader of a count's seats (`lineage::members_with_roles_at`: the
    // count base less the resignations the act cites; at a roster version
    // with nothing cited, the version's own list).
    let listed = crate::federation::edition2::head_rule::held_statement(dir, head)
        .await?
        .and_then(|st| crate::federation::edition2::liveness::statement_parts(&st))
        .map(|(_, p)| crate::federation::edition2::lineage::listed_members(&p))
        .unwrap_or_default();
    let members = Box::pin(crate::federation::edition2::lineage::members_with_roles_at(
        dir, head, listed, &cites,
    ))
    .await?;
    reads(Dep::key(&node.group));
    let community = dir.lookup_community(&node.group).await?;
    let t = act
        .get_text("asserted_at")
        .and_then(Value::as_u64)
        .and_then(|ms| i64::try_from(ms).ok())
        .and_then(chrono::DateTime::<chrono::Utc>::from_timestamp_millis)
        .unwrap_or_default();
    let mut seats = Vec::with_capacity(members.len());
    for (key_id, role) in members {
        seats.push(Seat {
            node_bearing: crate::federation::is_node_bearing_key_at(dir, &key_id, t).await?,
            key_id,
            role,
        });
    }
    reads(Dep::Row(*receipt));
    let signers: std::collections::BTreeSet<String> = dir
        .edition2_voices(receipt)
        .await?
        .iter()
        .filter(|v| RowId::of_statement(v) == Some(*receipt))
        .filter_map(|v| crate::federation::edition2::occurrence::statement_iss(v))
        .collect();
    if signers.is_empty() {
        return Ok(false);
    }
    Ok(evaluate(&Ballot {
        protocol: &protocol,
        subkind: community
            .as_ref()
            .and_then(crate::federation::community_subkind),
        policy_blob: community.as_ref().and_then(|c| c.policy_blob.as_ref()),
        roster: &seats,
        signers: &signers,
        // A receipt keeps an act in force: it confers, as an issuance does.
        direction: Direction::Add,
        subject: None,
        persons: crate::federation::key_person::PersonsAt::each_key(),
        high_water: None,
    })
    .admits())
}

/// **The receipts this node holds of `act`**, presented: every CONCLUDED
/// `act:ack` statement naming `act` under `refs.also.ack`
/// (`ceg_row_names`) whose placement equals the act's scope. An authored
/// receipt is presented as its signer's ([`receipt_rows`]); a body's
/// COUNTED receipt as the BODY's (signer = the group it is placed at), and
/// only where its voices meet the count at the act's head
/// ([`counted_meets`]; ACK-4). Empty when the act is not held. Every row
/// read is declared to the running fold attempt.
///
/// # Errors
/// Directory reads.
pub async fn receipts_of<F>(dir: &F, act: &RowId) -> Result<Vec<CRow>, Error>
where
    F: FederationDirectory + ?Sized,
{
    use crate::federation::edition2::fold::{reads, Dep};
    use crate::federation::edition2::head_rule::held_statement;
    reads(Dep::Row(*act));
    let Some(act_statement) = held_statement(dir, act).await? else {
        return Ok(Vec::new());
    };
    let Some((_, act_payload)) =
        crate::federation::edition2::liveness::statement_parts(&act_statement)
    else {
        return Ok(Vec::new());
    };
    let acts = [(*act, act_payload)];
    let mut out = Vec::new();
    for r in dir.edition2_rows_naming(act, act_ack::ACK_ROLE).await? {
        reads(Dep::Row(r));
        if !crate::federation::edition2::verdict::row_state(dir, &r)
            .await?
            .is_concluded()
        {
            continue;
        }
        let Some(st) = held_statement(dir, &r).await? else {
            continue;
        };
        match receipt_parts(&st) {
            Some((id, _, payload)) if act_ack::is_counted(&payload) => {
                let body = act_ack::placement_of(&payload).1;
                if let Some(body) = body {
                    if act_ack::is_receipt_of(&payload, &acts[0].1)
                        && Box::pin(counted_meets(dir, &id, &act_statement)).await?
                    {
                        out.push(CRow::receipt(id, &body, *act));
                    }
                }
            }
            _ => out.extend(receipt_rows(&st, &acts)),
        }
    }
    Ok(out)
}

#[cfg(test)]
mod tests {
    use super::{receipt_rows, CRow};
    use crate::federation::edition2::act_ack::act_ack_payload;
    use crate::federation::edition2::emit::sorted_map;
    use crate::federation::edition2::fixture_switch as e2;
    use crate::federation::edition2::names::RowId;
    use ciris_kernel::conferral::{answers, Answer, Judged, Kind, Role, Rule, Standing, Who};
    use ciris_verify_core::cde::Value;
    use std::collections::BTreeSet;

    fn t(s: &str) -> Value {
        Value::Text(s.to_owned())
    }

    fn rid(b: u8) -> RowId {
        RowId([b; 32])
    }

    /// An act's payload placed at `scope` (and a group).
    fn act_at(scope: &str, group: Option<&str>) -> Value {
        let mut m = vec![
            (t("asserted_at"), Value::Uint(1)),
            (t("cohort_scope"), t(scope)),
        ];
        if let Some(g) = group {
            m.push((t("community_id"), t(g)));
        }
        sorted_map(m)
    }

    /// **I6829** (pure) — one wire receipt naming three acts, two at its
    /// room and one at federation, presents TWO receipt rows: the wire
    /// row's id on both, `of` each room act, the signer its `iss`; none for
    /// the federation act (per act), none for an act not given.
    #[test]
    fn i6829_one_wire_receipt_is_one_row_per_act_at_its_scope() {
        let key = e2::signing_key("i6829-b");
        let iss = ciris_verify_core::edition2::identity_ref(
            &ciris_verify_core::edition2::thumbprint(key.public_key()),
        );
        let room = ("community".to_owned(), Some("room-x".to_owned()));
        let (x, y, z, w) = (rid(1), rid(2), rid(3), rid(4));
        let p = act_ack_payload(&[x, y, z, w], &iss, Some(&room), 1).expect("the payload");
        let st = ciris_verify_core::edition2::sign_row_statement(
            &key,
            &iss,
            &iss,
            "scores",
            "act:ack",
            &p,
            vec![],
        )
        .expect("it signs");
        let id = RowId::of_statement(&st).expect("a row id");
        let acts = vec![
            (x, act_at("community", Some("room-x"))),
            (y, act_at("community", Some("room-x"))),
            (z, act_at("federation", None)),
        ];
        let rows = receipt_rows(&st, &acts);
        assert_eq!(
            rows,
            vec![CRow::receipt(id, &iss, x), CRow::receipt(id, &iss, y)],
            "I6829: one receipt row per act at its own scope, each carrying the wire id"
        );
        assert!(
            rows.iter()
                .all(|r| r.kind == Kind::Receipt && r.head.is_none()),
            "I6829: a receipt names no head"
        );
    }

    fn act(id: RowId, head: RowId, signer: &str) -> CRow {
        CRow {
            id,
            kind: Kind::Act,
            signer: signer.to_owned(),
            head: Some(head),
            of: None,
            target: None,
            via: None,
            lifts: false,
        }
    }

    fn end(id: RowId, head: RowId, signer: &str) -> CRow {
        CRow {
            kind: Kind::End,
            ..act(id, head, signer)
        }
    }

    fn head(id: RowId) -> CRow {
        CRow {
            id,
            kind: Kind::Head,
            signer: String::new(),
            head: None,
            of: None,
            target: None,
            via: None,
            lifts: false,
        }
    }

    /// **I6830** (pure) — the presentation through `conferral::answers`. A
    /// standing (conferrer `cf`, grantee `g`, a node `n`) with its head `h`;
    /// two acts `x`, `y` of `g` at `h`; the end `e` by `cf` at `h`, which no
    /// act has in its past:
    ///
    /// - no receipt: each act counted, NOT in force (E2.forward);
    /// - ONE wire receipt by `cf` naming both (two rows, one id), concurrent
    ///   with the end: both in force (E8.receipt);
    /// - the same receipt by the node `n` (role Other): nothing kept;
    /// - `cf`'s receipt that has the end in its past: nothing kept.
    #[test]
    fn i6830_the_presentation_through_the_crate() {
        let (h, x, y, e, q) = (rid(10), rid(11), rid(12), rid(13), rid(14));
        let role = |k: &String| match k.as_str() {
            "cf" => Role::Conferrer,
            "g" => Role::Grantee,
            _ => Role::Other,
        };
        let st = Standing {
            role: &role,
            other_standing: false,
            who: Who::All,
            reader_acks: &[],
        };
        let base = vec![head(h), act(x, h, "g"), act(y, h, "g"), end(e, h, "cf")];
        // h is in the past of every other row; `end_in_q` puts e in q's past.
        let past = |end_in_q: bool| {
            move |a: &RowId, b: &RowId| -> Result<bool, RowId> {
                Ok((*a == h && *b != h) || (end_in_q && *a == e && *b == q))
            }
        };
        let judge = |rows: &[CRow], end_in_q: bool| {
            let refs: Vec<&CRow> = rows.iter().collect();
            let out = answers(&refs, &st, &past(end_in_q)).expect("one end");
            [x, y].map(|a| match out.get(&a) {
                Some(Answer::Judged(j)) => *j,
                other => panic!("I6830: {a:?} judged, got {other:?}"),
            })
        };
        let forward = Judged {
            counted: true,
            in_force: false,
            rule: Rule::Forward,
        };
        let kept = Judged {
            counted: true,
            in_force: true,
            rule: Rule::Receipt,
        };
        assert_eq!(judge(&base, false), [forward, forward], "I6830: no receipt");
        let with = |signer: &str| {
            let mut rows = base.clone();
            rows.push(CRow::receipt(q, signer, x));
            rows.push(CRow::receipt(q, signer, y));
            rows
        };
        assert_eq!(
            judge(&with("cf"), false),
            [kept, kept],
            "I6830: one wire receipt by the conferrer keeps BOTH acts in force"
        );
        assert_eq!(
            judge(&with("n"), false),
            [forward, forward],
            "I6830: a node's receipt keeps nothing"
        );
        assert_eq!(
            judge(&with("cf"), true),
            [forward, forward],
            "I6830: a receipt with the end in its past keeps nothing"
        );
        let ids: BTreeSet<RowId> = with("cf").iter().map(|r| r.id).collect();
        assert_eq!(ids.len(), 5, "I6830: the two receipt rows share one id");
    }
}
