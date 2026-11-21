//! v62.0.0 (slice D, CIRISVerify v23) — **the generic group membership
//! change, owned by persist.**
//!
//! Through v22, `ciris_verify_core::accord_genesis` carried a role-agnostic,
//! entrenchment-optional membership change (CIRISVerify#104):
//! `build_membership_change(prior_envelope, new_member_key_ids, role,
//! entrenched, consensus_protocol)` and
//! `validate_membership_change_structure(prior, new, directory)`. Persist's
//! family and community supersede doors
//! ([`FederationDirectory`](super::FederationDirectory)'s
//! `build_group_membership_change` / `verify_membership_quorum`) are built on
//! that shape.
//!
//! Verify 23.0.0 replaced those two functions with the ACCORD's roster change
//! (CC 4.2.6: `build_membership_change(standing, changes, charter_digest,
//! joined_at) -> RosterChangeDraft`, decision-bound, lineage by
//! `persist_row_hash`), which persist already enforces in its own door
//! (`accord_roster::verify_accord_roster_change`). The generic group change is
//! not the accord's and Verify no longer offers it, so it lives here, byte for
//! byte CIRISVerify 22.2's envelope and the same fail-closed checks, with the same
//! [`AccordGenesisError`] values (their `Display` text is unchanged, so every
//! refusal persist renders reads as it did).

use ciris_verify_core::accord_genesis::{accord_consensus_protocol, AccordGenesisError};
use ciris_verify_core::threshold::{Role, ThresholdMember};
use serde_json::{json, Value};

use super::edition2::fold as e2fold;

/// v62.0.0 (SM-fix1) — a string member a prior envelope must carry. Absent
/// or ill-typed is a REFUSAL (malformed is a refusal, not absence): v22
/// defaulted a missing `family_key_id` to the humanity accord's and a missing
/// `consensus_protocol` to a literal `quorum:2/3`, which named a group and a
/// rule nobody signed. On v62 every prior envelope comes from
/// `FederationDirectory::group_prior_envelope`, which reads both from a
/// stored record whose fields are non-optional `String`s, so no stored row
/// reaches this refusal; it holds the public builder to the same shape.
fn required_str<'a>(envelope: &'a Value, member: &str) -> Result<&'a str, AccordGenesisError> {
    envelope.get(member).and_then(Value::as_str).ok_or_else(|| {
        AccordGenesisError::MalformedEnvelope {
            detail: format!("prior envelope: missing or non-string `{member}`"),
        }
    })
}

fn parse_quorum_protocol(s: &str) -> Option<(usize, usize)> {
    let (m, n) = s.strip_prefix("quorum:")?.split_once('/')?;
    Some((m.parse().ok()?, n.parse().ok()?))
}

/// The envelope's member `key_id`s, in order.
///
/// # Errors
/// [`AccordGenesisError::MalformedEnvelope`] when `members` is missing, not an
/// array, or a member has no string `key_id`.
pub fn envelope_member_key_ids(envelope: &Value) -> Result<Vec<String>, AccordGenesisError> {
    let members = envelope.get("members").and_then(Value::as_array).ok_or(
        AccordGenesisError::MalformedEnvelope {
            detail: "missing or non-array `members`".to_string(),
        },
    )?;
    members
        .iter()
        .map(|m| {
            m.get("key_id")
                .and_then(Value::as_str)
                .map(str::to_string)
                .ok_or(AccordGenesisError::MalformedEnvelope {
                    detail: "a member has no string `key_id`".to_string(),
                })
        })
        .collect()
}

/// The strict-majority threshold `M` of an envelope's `quorum:M/N`: `N` must
/// equal the member count and `2·M > N`.
fn quorum_threshold_from_envelope(envelope: &Value) -> Result<usize, AccordGenesisError> {
    let n_members = envelope_member_key_ids(envelope)?.len();
    let cp = envelope
        .get("consensus_protocol")
        .and_then(Value::as_str)
        .ok_or(AccordGenesisError::MalformedEnvelope {
            detail: "missing `consensus_protocol`".to_string(),
        })?;
    let (m, n) = parse_quorum_protocol(cp).ok_or(AccordGenesisError::MalformedEnvelope {
        detail: format!("consensus_protocol {cp:?} is not quorum:M/N"),
    })?;
    if n != n_members {
        return Err(AccordGenesisError::MalformedEnvelope {
            detail: format!("consensus_protocol N={n} != member count {n_members}"),
        });
    }
    if m == 0 || m.checked_mul(2).is_none_or(|two_m| two_m <= n) {
        return Err(AccordGenesisError::WeakQuorum { m, n });
    }
    Ok(m)
}

/// One key, one seat: no two members share an Ed25519 or ML-DSA-65 key.
fn reject_duplicate_member_keys(members: &[ThresholdMember]) -> Result<(), AccordGenesisError> {
    let mut seen_ed = std::collections::HashSet::new();
    let mut seen_pqc = std::collections::HashSet::new();
    for m in members {
        if !seen_ed.insert(m.ed25519_public_key_base64.as_str()) {
            return Err(AccordGenesisError::DuplicateFounderKey {
                member_id: m.member_id.clone(),
            });
        }
        if let Some(pqc) = m.mldsa65_public_key_base64.as_deref() {
            if !seen_pqc.insert(pqc) {
                return Err(AccordGenesisError::DuplicateFounderKey {
                    member_id: m.member_id.clone(),
                });
            }
        }
    }
    Ok(())
}

/// Resolve member `key_id`s to their pinned entries, in order; a missing one
/// is [`AccordGenesisError::MemberNotInDirectory`].
///
/// v62.0.0 (wave GC8; CC 2.7.3) — a member is not the signer: its key
/// record is another row. Each member is declared read, and a missing one
/// marks the running fold attempt `member_not_in_directory` (the row is
/// held and re-folds when the record lands); outside an attempt it is the
/// refusal it was.
fn resolve_members(
    member_ids: &[String],
    directory: &[ThresholdMember],
) -> Result<Vec<ThresholdMember>, AccordGenesisError> {
    member_ids
        .iter()
        .map(|key_id| {
            e2fold::reads(e2fold::Dep::key(key_id));
            directory
                .iter()
                .find(|m| &m.member_id == key_id)
                .cloned()
                .ok_or_else(|| {
                    e2fold::note(e2fold::reason::gc8::MEMBER_NOT_IN_DIRECTORY);
                    AccordGenesisError::MemberNotInDirectory {
                        key_id: key_id.clone(),
                    }
                })
        })
        .collect()
}

/// Build a general membership-change envelope: the prior group's id and name,
/// the new members stamped with `role`, `consensus_protocol` (`None` ⇒ the
/// strict-majority `quorum:M/N` for the new count), the entrenchment flag, and
/// a `supersedes` block binding the change to the exact prior roster and
/// protocol. The prior roster co-signs it.
///
/// # Errors
/// v62.0.0 (SM-fix1) — [`AccordGenesisError::MalformedEnvelope`] when the
/// prior envelope lacks a string `family_key_id`, `family_name` or
/// `consensus_protocol`, or its `members` do not parse: never a default.
pub fn build_membership_change(
    prior_envelope: &Value,
    new_member_key_ids: &[String],
    role: Role,
    entrenched: bool,
    consensus_protocol: Option<&str>,
) -> Result<Value, AccordGenesisError> {
    let group_key_id = required_str(prior_envelope, "family_key_id")?;
    let group_name = required_str(prior_envelope, "family_name")?;
    let prior_members = envelope_member_key_ids(prior_envelope)?;
    let prior_cp = required_str(prior_envelope, "consensus_protocol")?;
    let role_str = match role {
        Role::Founder => "founder",
        Role::Member => "member",
    };
    let members: Vec<Value> = new_member_key_ids
        .iter()
        .map(|k| json!({ "key_id": k, "role": role_str }))
        .collect();
    let cp = consensus_protocol
        .map(str::to_string)
        .unwrap_or_else(|| accord_consensus_protocol(new_member_key_ids.len()));
    Ok(json!({
        "family_key_id": group_key_id,
        "family_name": group_name,
        "members": members,
        "consensus_protocol": cp,
        "consensus_protocol_entrenched": entrenched,
        "supersedes": {
            "prior_member_key_ids": prior_members,
            "prior_consensus_protocol": prior_cp,
        },
    }))
}

/// The structural invariants of a membership change (everything but who
/// signed): distinct members at a strict-majority `quorum:M/N`, distinct keys
/// in `directory`, the same `family_key_id`, no lifted entrenchment, and
/// `supersedes.prior_member_key_ids` equal to the prior roster (anti-replay).
///
/// # Errors
/// [`AccordGenesisError`] naming the first failing invariant.
pub fn validate_membership_change_structure(
    prior_envelope: &Value,
    new_envelope: &Value,
    directory: &[ThresholdMember],
) -> Result<(), AccordGenesisError> {
    let new_ids = envelope_member_key_ids(new_envelope)?;
    {
        let mut seen = std::collections::HashSet::new();
        for k in &new_ids {
            if !seen.insert(k.as_str()) {
                return Err(AccordGenesisError::DuplicateMemberKeyId { key_id: k.clone() });
            }
        }
    }
    let _new_threshold = quorum_threshold_from_envelope(new_envelope)?;

    let new_roster = resolve_members(&new_ids, directory)?;
    // v62.0.0 (wave GC8) — two members sharing a key is read from their HELD
    // key records: a fold condition.
    reject_duplicate_member_keys(&new_roster).inspect_err(|_| {
        e2fold::note(e2fold::reason::gc8::DUPLICATE_FOUNDER_KEY);
    })?;

    // v62.0.0 (wave GC8; CC 2.7.3) — the three checks below compare with the
    // PRIOR envelope, the held head: each is a fold condition
    // (`prior_roster_mismatch`), re-folded when the group's head changes.
    if let Some(g) = prior_envelope.get("family_key_id").and_then(Value::as_str) {
        e2fold::reads(e2fold::Dep::key(g));
    }
    if new_envelope.get("family_key_id") != prior_envelope.get("family_key_id") {
        e2fold::note(e2fold::reason::gc8::PRIOR_ROSTER_MISMATCH);
        return Err(AccordGenesisError::MalformedEnvelope {
            detail: "membership change must keep the same family_key_id".to_string(),
        });
    }
    let prior_entrenched =
        prior_envelope.get("consensus_protocol_entrenched") == Some(&Value::Bool(true));
    let new_entrenched =
        new_envelope.get("consensus_protocol_entrenched") == Some(&Value::Bool(true));
    if prior_entrenched && !new_entrenched {
        e2fold::note(e2fold::reason::gc8::PRIOR_ROSTER_MISMATCH);
        return Err(AccordGenesisError::MalformedEnvelope {
            detail: "membership change must not lift consensus_protocol_entrenched".to_string(),
        });
    }
    let supersedes =
        new_envelope
            .get("supersedes")
            .ok_or(AccordGenesisError::MalformedEnvelope {
                detail: "membership change missing `supersedes`".to_string(),
            })?;
    let claimed_prior: Vec<String> = supersedes
        .get("prior_member_key_ids")
        .and_then(Value::as_array)
        .map(|a| {
            a.iter()
                .filter_map(|v| v.as_str().map(str::to_string))
                .collect()
        })
        .unwrap_or_default();
    if claimed_prior != envelope_member_key_ids(prior_envelope)? {
        e2fold::note(e2fold::reason::gc8::PRIOR_ROSTER_MISMATCH);
        return Err(AccordGenesisError::MalformedEnvelope {
            detail: "supersedes.prior_member_key_ids does not match the prior group".to_string(),
        });
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn member(id: &str, ed: &str) -> ThresholdMember {
        ThresholdMember {
            member_id: id.into(),
            ed25519_public_key_base64: ed.into(),
            mldsa65_public_key_base64: None,
            role: None,
        }
    }

    fn prior() -> Value {
        json!({
            "family_key_id": "fam-1",
            "family_name": "F",
            "members": [{"key_id": "a", "role": "member"}],
            "consensus_protocol": "quorum:1/1",
            "consensus_protocol_entrenched": false,
        })
    }

    #[test]
    fn a_built_change_validates_and_binds_the_prior_roster() {
        let dir = [member("a", "KA"), member("b", "KB")];
        let change = build_membership_change(
            &prior(),
            &["a".to_string(), "b".to_string()],
            Role::Member,
            false,
            Some("quorum:2/2"),
        )
        .expect("a well-formed prior");
        assert_eq!(change["supersedes"]["prior_member_key_ids"], json!(["a"]));
        validate_membership_change_structure(&prior(), &change, &dir).unwrap();

        // Replayed against a different prior roster: refused.
        let mut other = prior();
        other["members"] = json!([{"key_id": "b", "role": "member"}]);
        assert!(matches!(
            validate_membership_change_structure(&other, &change, &dir),
            Err(AccordGenesisError::MalformedEnvelope { .. })
        ));
    }

    /// **I2192 (v62.0.0, SM-fix1)** — a prior envelope missing its
    /// `family_key_id`, `family_name` or `consensus_protocol` (or with
    /// unparseable `members`) is REFUSED by name, never defaulted (v22 read a
    /// missing protocol as `quorum:2/3` and a missing id as the humanity
    /// accord's).
    #[test]
    fn i2192_a_prior_envelope_missing_a_member_is_refused_not_defaulted() {
        for (member, missing) in [
            ("family_key_id", "`family_key_id`"),
            ("family_name", "`family_name`"),
            ("consensus_protocol", "`consensus_protocol`"),
            ("members", "`members`"),
        ] {
            let mut p = prior();
            p.as_object_mut().expect("an object").remove(member);
            match build_membership_change(&p, &["a".to_string()], Role::Member, false, None) {
                Err(AccordGenesisError::MalformedEnvelope { detail }) => assert!(
                    detail.contains(missing) || detail.contains("members"),
                    "I2192 {member}: {detail}"
                ),
                other => panic!("I2192 {member}: refused, not defaulted: {other:?}"),
            }
        }
        let mut p = prior();
        p["consensus_protocol"] = json!(3);
        assert!(
            build_membership_change(&p, &["a".to_string()], Role::Member, false, None).is_err(),
            "I2192 a non-string protocol is refused"
        );
    }

    #[test]
    fn one_key_two_seats_and_a_weak_quorum_are_refused() {
        let dir = [member("a", "SAME"), member("b", "SAME")];
        let change = build_membership_change(
            &prior(),
            &["a".to_string(), "b".to_string()],
            Role::Member,
            false,
            Some("quorum:2/2"),
        )
        .expect("a well-formed prior");
        assert!(matches!(
            validate_membership_change_structure(&prior(), &change, &dir),
            Err(AccordGenesisError::DuplicateFounderKey { .. })
        ));
        let dir = [member("a", "KA"), member("b", "KB")];
        let weak = build_membership_change(
            &prior(),
            &["a".to_string(), "b".to_string()],
            Role::Member,
            false,
            Some("quorum:1/2"),
        )
        .expect("a well-formed prior");
        assert!(matches!(
            validate_membership_change_structure(&prior(), &weak, &dir),
            Err(AccordGenesisError::WeakQuorum { m: 1, n: 2 })
        ));
    }
}
