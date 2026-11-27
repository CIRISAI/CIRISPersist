//! v62.0.0 (HEAD-R5a; CC 2.4.1.1 "What stays in force", CC 2.7.5, CC 3.1.3;
//! Kernel's `ConferralEnd` receipt shape, `conferral_end.py` @026e580) —
//! **the receipt of a standing's acts (`act:ack:v1`), at the door.**
//!
//! The row's shape is Kernel's:
//!
//! - **It names the acts it receipts**, each under `refs.also.ack`: one
//!   receipt entry per act. A bulk receipt names every act. Nothing is
//!   covered by the past (Kernel dropped cover-by-past: it let the target
//!   void its own end).
//! - **It names NO head** (`ack_names_a_head`). An ack has no place in
//!   the standing's lineage. What it keeps is decided by the reader
//!   (`standing_end::answers`, E8 / E3 one-say) from the rows it names and
//!   the roles of its signer.
//! - **It is capped**: at most [`ACK_MAX_ACTS`] acts (`ack_names_too_many_acts`).
//!   The `refs` grammar bounds no set, and an unbounded set the host supplies
//!   would be a resource door.
//! - **A node never signs one** (`ack_signed_by_node`). The signer is the
//!   conferrer (counted where the conferrer is a count), a co-holder of the
//!   body, or a receipter the grant names. Whether this signer holds one of
//!   those roles, and whether it signed an act it names, is read from other
//!   rows, so it is the READER's rule (an ineligible receipt keeps nothing),
//!   never a refusal here.
//!
//! The door reads the row alone, plus the signer's own key record (the
//! same read as the head rule's, `ingest::machine_kind_at`). Until the
//! pinned Verify registers the family, Verify's statement reader refuses
//! every `act:ack` statement as `unregistered_family`, before this check
//! (I6131 pins that, and flips at the pin).

use ciris_verify_core::cde::Value;

use super::names::{names_of, Name, RowId};
use crate::federation::{malformed_row, Error, FederationDirectory};

/// The family's prefix (one segment-free family).
pub const ACK_FAMILY: &str = "act:ack";

/// The `refs` role an ack names each act under.
pub const ACK_ROLE: &str = "also:ack";

/// The most acts one ack names.
pub const ACK_MAX_ACTS: usize = 256;

/// The family id of [`ACK_FAMILY`].
#[must_use]
pub fn family_id() -> String {
    ciris_verify_core::namespace_match::family_id(ACK_FAMILY)
}

fn refuse(reason: &'static str, message: String) -> Error {
    Error::malformed_row(super::door::PLANE, reason, message)
}

/// The acts an ack names (`refs.also.ack`), in the order its payload
/// states them.
///
/// # Errors
/// `edition2_payload_invalid` for `refs` that do not read.
pub fn acked(payload: &Value) -> Result<Vec<RowId>, Error> {
    let names: Vec<Name> = names_of(payload).map_err(|e| {
        refuse(
            malformed_row::EDITION2_PAYLOAD_INVALID,
            format!("{ACK_FAMILY}: refs: {e:?}"),
        )
    })?;
    Ok(names
        .into_iter()
        .filter(|n| n.role == ACK_ROLE)
        .map(|n| n.row)
        .collect())
}

/// **The ack's payload rule**, pure (the row alone): it names at least one
/// act and at most [`ACK_MAX_ACTS`] under `refs.also.ack`, and no
/// `refs.head`. Run for every non-composer statement of the family
/// (`payloads::check_by_id`); the envelope's common members are judged
/// after it, as on every family with no member list.
///
/// # Errors
/// `edition2_payload_invalid` (no act named); `ack_names_too_many_acts`;
/// `ack_names_a_head`.
pub fn check_act_ack(payload: &Value) -> Result<(), Error> {
    let acts = acked(payload)?;
    if acts.is_empty() {
        return Err(refuse(
            malformed_row::EDITION2_PAYLOAD_INVALID,
            format!("{ACK_FAMILY}: refs.also.ack names no act: an ack names each act it receipts"),
        ));
    }
    if acts.len() > ACK_MAX_ACTS {
        return Err(refuse(
            malformed_row::ACK_NAMES_TOO_MANY_ACTS,
            format!(
                "{ACK_FAMILY}: refs.also.ack names {} acts; at most {ACK_MAX_ACTS}",
                acts.len()
            ),
        ));
    }
    if super::head_rule::names_a_head(payload) {
        return Err(refuse(
            malformed_row::ACK_NAMES_A_HEAD,
            format!(
                "{ACK_FAMILY}: an ack names no refs.head: it names the acts it receipts, and the \
                 reader places them (CC 2.4.1.1)"
            ),
        ));
    }
    Ok(())
}

/// Does this key record make its key a node's?
#[must_use]
pub fn is_node_key(roles: &super::ingest::KeyRoles) -> bool {
    roles.holds(crate::federation::types::identity_type::NODE)
}

/// **A node never signs an ack** (the funnel, on a row's first arrival):
/// the signer's live key record at the row's instant is read
/// (`ingest::machine_kind_at`). A key with no live record is not judged
/// here: the door verified the statement against a live key, so a missing
/// record is the key plane's answer, never a reason to refuse.
///
/// # Errors
/// `ack_signed_by_node`; directory reads.
pub async fn require_ack_signer<F>(dir: &F, row: &super::door::AdmittedRow) -> Result<(), Error>
where
    F: FederationDirectory + ?Sized,
{
    if row.family != family_id() || !super::head_rule::row_type_acts(&row.row_type) {
        return Ok(());
    }
    let roles = super::ingest::machine_kind_at(dir, &row.kid, Some(row.asserted_at_ms)).await?;
    if roles.as_ref().is_some_and(is_node_key) {
        return Err(refuse(
            malformed_row::ACK_SIGNED_BY_NODE,
            format!(
                "{ACK_FAMILY} {} by {}: a node never signs an ack: a receipt is the \
                 conferrer's, a co-holder's of the body, or a named receipter's (CC 2.4.1.1)",
                row.row_id.hex(),
                row.iss
            ),
        ));
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use ciris_verify_core::edition2::row_ref;

    fn text(s: &str) -> Value {
        Value::Text(s.into())
    }

    fn set(ids: &[[u8; 32]]) -> Value {
        let mut v: Vec<Value> = ids.iter().map(row_ref).collect();
        v.sort_by_key(ciris_verify_core::cde::encode);
        Value::Array(v)
    }

    fn ack(acts: &[[u8; 32]], head: Option<[u8; 32]>) -> Value {
        let mut refs = vec![(text("also"), Value::Map(vec![(text("ack"), set(acts))]))];
        if let Some(h) = head {
            refs.push((text("head"), row_ref(&h)));
        }
        refs.sort_by_key(|(k, _)| ciris_verify_core::cde::encode(k));
        Value::Map(vec![
            (text("asserted_at"), Value::Uint(1_000)),
            (text("dimension"), text("act:ack:v1")),
            (text("refs"), Value::Map(refs)),
        ])
    }

    fn act(n: u16) -> [u8; 32] {
        let mut b = [0u8; 32];
        b[..2].copy_from_slice(&n.to_be_bytes());
        b[31] = 0xac;
        b
    }

    fn reason(e: &Error) -> &'static str {
        match e {
            Error::MalformedRow { reason, .. } => *reason,
            other => panic!("not a refusal: {other:?}"),
        }
    }

    /// I6130 (HEAD-R5a; CC 2.4.1.1, Kernel's receipt shape) — **an ack's
    /// payload rule, from the row alone**: it names each act it receipts (one
    /// to [`ACK_MAX_ACTS`]) and no head. One act, and the cap exactly, pass;
    /// none is `edition2_payload_invalid`; one past the cap is
    /// `ack_names_too_many_acts`; a head is `ack_names_a_head`. The acts
    /// read back as named.
    #[test]
    fn i6130_an_ack_names_its_acts_and_no_head() {
        check_act_ack(&ack(&[act(1)], None)).expect("I6130: one act");
        let cap: Vec<[u8; 32]> = (0..u16::try_from(ACK_MAX_ACTS).unwrap()).map(act).collect();
        check_act_ack(&ack(&cap, None)).expect("I6130: the cap");
        let mut read = acked(&ack(&[act(2), act(1)], None)).unwrap();
        read.sort();
        assert_eq!(
            read,
            vec![RowId(act(1)), RowId(act(2))],
            "I6130: the acts read back"
        );
        let over: Vec<[u8; 32]> = (0..=u16::try_from(ACK_MAX_ACTS).unwrap())
            .map(act)
            .collect();
        assert_eq!(
            reason(&check_act_ack(&ack(&over, None)).unwrap_err()),
            malformed_row::ACK_NAMES_TOO_MANY_ACTS
        );
        assert_eq!(
            reason(&check_act_ack(&ack(&[act(1)], Some(act(9)))).unwrap_err()),
            malformed_row::ACK_NAMES_A_HEAD
        );
        let none = Value::Map(vec![
            (text("asserted_at"), Value::Uint(1_000)),
            (text("dimension"), text("act:ack:v1")),
        ]);
        assert_eq!(
            reason(&check_act_ack(&none).unwrap_err()),
            malformed_row::EDITION2_PAYLOAD_INVALID
        );
    }

    /// I6132 (HEAD-R5a) — **a node's key never signs an ack**, an agent
    /// member's may (the reader judges its role): the predicate over the key
    /// record's roles.
    #[test]
    fn i6132_a_node_key_is_not_an_ack_signer() {
        use super::super::ingest::KeyRoles;
        use crate::federation::types::identity_type;
        assert!(is_node_key(&KeyRoles(vec![identity_type::NODE.to_owned()])));
        assert!(!is_node_key(&KeyRoles(vec![
            identity_type::AGENT.to_owned()
        ])));
        assert!(!is_node_key(&KeyRoles(
            vec![identity_type::USER.to_owned()]
        )));
    }
}
