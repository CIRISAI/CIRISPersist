//! v60.1.0 (CIRISPersist#1120; CC 3.1.5, rc10 `cadd5a9`) — **the
//! `identity_amendment:v1` admission gate.**
//!
//! An agent applies a change to its own identity only when a Wise Authority
//! approved it. The approval is a `deferral:response:approved:v1` row (the
//! WA's answer to the agent's `deferral:request:v1`); the amendment is the
//! agent's `identity_amendment:v1` row citing it. CC 3.1.5 makes the rule
//! normative: the amendment (attester = the agent's occurrence key, subject =
//! its identity key; members `amendment_digest` hex64 and `authorized_by`
//! uuid; `evidence_refs[]` → the response) is admitted **only** when the
//! cited response is admitted, its outcome is approved, its subject is this
//! agent, and its attester held a Wise Authority seat at the response's
//! `asserted_at`. Otherwise it is refused **`identity_amendment_unauthorized`**.
//!
//! CIRISServer (0.5.234, `agent_deferral.rs`) enforces the rule at its own
//! authoring door, which is the only way a server node MAKES an amendment.
//! A replicated amendment from another producer reached no gate at all; this
//! is that gate, at every door a row enters by.
//!
//! # Who holds a WA seat
//!
//! The general definition needs the WA-seat primitive (the live seated set at
//! an instant, CIRISPersist#709, open). Until it lands this gate reads the
//! ruling the producer runs under (Eric, 2026-10-22, on CIRISServer): **a
//! node's owner is the seated Wise Authority for its own agent.** The
//! response's signer holds the seat iff, at the response's `asserted_at`, its
//! self ([`self_of_at`](super::self_roster::self_of_at)) is the self of the
//! owner ([`owner_of`](super::admission::owner_of)) of the amendment's
//! signing occurrence (or, when that key has no owner binding, of the agent
//! identity the amendment is about). An unowned agent has no seated WA, so
//! nothing authorises its amendment.
//!
//! # The refusal's shape
//!
//! `identity_amendment_unauthorized` rides [`Error::InvalidArgument`] with the
//! token leading its message (the `reconsideration_community_mismatch`
//! precedent; a new `Error` arm would be a break in a minor). The ill-shaped
//! members (`amendment_digest`, `authorized_by`) are
//! [`Error::MalformedRow`]: those bytes can never be an amendment.

use super::admission::envelope_dimension;
use super::types::{attestation_type, Attestation};
use super::{malformed_row, Error, FederationDirectory};

/// The family stem the gate rules on (`federation::family_rules` derives it).
pub const IDENTITY_AMENDMENT_FAMILY_STEM: &str = "identity_amendment:";
/// `identity_amendment:v1` — the agent applied a change an approved response
/// authorised.
pub const IDENTITY_AMENDMENT_DIMENSION: &str = "identity_amendment:v1";
/// `deferral:request:v1` — the agent defers one question to a Wise Authority.
pub const DEFERRAL_REQUEST_DIMENSION: &str = "deferral:request:v1";
/// `deferral:response:approved:v1` — the WA approved.
pub const DEFERRAL_APPROVED_DIMENSION: &str = "deferral:response:approved:v1";
/// `deferral:response:rejected:v1` — the WA rejected.
pub const DEFERRAL_REJECTED_DIMENSION: &str = "deferral:response:rejected:v1";

/// The amendment's digest member: lowercase hex SHA-256 of the change.
pub const AMENDMENT_DIGEST_MEMBER: &str = "amendment_digest";
/// The amendment's authority member: the `attestation_id` (a uuid) of the
/// `deferral:response:approved:v1` it rests on.
pub const AUTHORIZED_BY_MEMBER: &str = "authorized_by";
/// The member that cites the response as evidence.
pub const EVIDENCE_REFS_MEMBER: &str = "evidence_refs";

/// CC 3.1.5 (rc10) — the refusal token.
pub const IDENTITY_AMENDMENT_UNAUTHORIZED: &str = "identity_amendment_unauthorized";

/// Which CC 3.1.5 condition an unauthorized amendment failed. Carried in the
/// refusal's message after the token; persist-local.
pub mod unauthorized_reason {
    /// `evidence_refs[]` does not cite the `authorized_by` response.
    pub const EVIDENCE_DOES_NOT_CITE: &str = "evidence_does_not_cite_response";
    /// The cited response is not admitted on this node. The one ordering
    /// gap: it may still arrive, and a re-offer after it lands admits.
    pub const RESPONSE_NOT_HELD: &str = "response_not_held";
    /// The cited row is not a `deferral:response:approved:v1`.
    pub const NOT_APPROVED: &str = "response_not_approved";
    /// The response is about another agent.
    pub const ABOUT_ANOTHER_AGENT: &str = "response_about_another_agent";
    /// The amendment is not signed by an occurrence of the agent it is about.
    pub const NOT_THE_AGENTS_OCCURRENCE: &str = "attester_not_the_agents_occurrence";
    /// The response's signer held no WA seat at its `asserted_at`.
    pub const NOT_A_SEATED_WA: &str = "response_signer_not_a_seated_wa";
}

fn unauthorized(row: &Attestation, reason: &'static str, detail: String) -> Error {
    Error::InvalidArgument(format!(
        "{IDENTITY_AMENDMENT_UNAUTHORIZED}: {reason}: amendment {} — {detail} (CC 3.1.5, \
         CIRISPersist#1120)",
        row.attestation_id
    ))
}

fn malformed(reason: &'static str, detail: String) -> Error {
    Error::malformed_row(
        "attestation",
        reason,
        format!("{IDENTITY_AMENDMENT_DIMENSION}: {detail} (CIRISPersist#1120)"),
    )
}

/// Is `s` 64 lowercase hex digits?
fn is_hex64(s: &str) -> bool {
    s.len() == 64
        && s.bytes()
            .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
}

/// Is `row` an `identity_amendment:v1` row?
#[must_use]
pub fn is_identity_amendment(row: &Attestation) -> bool {
    row.attestation_type == attestation_type::SCORES
        && envelope_dimension(&row.attestation_envelope) == Some(IDENTITY_AMENDMENT_DIMENSION)
}

/// v60.1.0 (CIRISPersist#1120; CC 3.1.5) — the gate. A no-op for every row
/// that is not an `identity_amendment:v1`; see the module doc.
///
/// # Errors
///
/// [`Error::MalformedRow`] for an ill-shaped member;
/// [`Error::InvalidArgument`] led by [`IDENTITY_AMENDMENT_UNAUTHORIZED`] when
/// a CC 3.1.5 condition fails; directory reads.
pub async fn check_identity_amendment_admission(
    directory: &dyn FederationDirectory,
    row: &Attestation,
) -> Result<(), Error> {
    use unauthorized_reason as why;
    if !is_identity_amendment(row) {
        return Ok(());
    }
    let env = &row.attestation_envelope;

    // The members' shapes.
    let digest = env.get(AMENDMENT_DIGEST_MEMBER);
    match digest.map(|v| v.as_str()) {
        None => {
            return Err(malformed(
                malformed_row::ENVELOPE_MEMBER_MISSING,
                format!("`{AMENDMENT_DIGEST_MEMBER}` is required"),
            ))
        }
        Some(Some(d)) if is_hex64(d) => {}
        Some(_) => {
            return Err(malformed(
                malformed_row::ENVELOPE_MEMBER_INVALID,
                format!("`{AMENDMENT_DIGEST_MEMBER}` is not 64 lowercase hex digits"),
            ))
        }
    }
    let authorized_by = match env.get(AUTHORIZED_BY_MEMBER).map(|v| v.as_str()) {
        None => {
            return Err(malformed(
                malformed_row::ENVELOPE_MEMBER_MISSING,
                format!("`{AUTHORIZED_BY_MEMBER}` is required"),
            ))
        }
        Some(Some(id)) if uuid::Uuid::parse_str(id).is_ok() => id,
        Some(_) => {
            return Err(malformed(
                malformed_row::ENVELOPE_MEMBER_INVALID,
                format!("`{AUTHORIZED_BY_MEMBER}` is not a uuid"),
            ))
        }
    };
    let cites = env
        .get(EVIDENCE_REFS_MEMBER)
        .and_then(serde_json::Value::as_array)
        .is_some_and(|refs| refs.iter().any(|r| r.as_str() == Some(authorized_by)));
    if !cites {
        return Err(unauthorized(
            row,
            why::EVIDENCE_DOES_NOT_CITE,
            format!("`{EVIDENCE_REFS_MEMBER}` does not cite {authorized_by}"),
        ));
    }

    // Attester = an occurrence of the agent, subject = the agent.
    let agent = row.attested_key_id.as_str();
    let signer = row.attesting_key_id.as_str();
    if signer != agent
        && !directory
            .active_identities_for_occurrence(signer)
            .await?
            .iter()
            .any(|i| i == agent)
    {
        return Err(unauthorized(
            row,
            why::NOT_THE_AGENTS_OCCURRENCE,
            format!("{signer} is not an active occurrence of {agent}"),
        ));
    }

    // (1) The cited response is admitted here.
    let Some(response) = directory.get_attestation(authorized_by).await? else {
        return Err(unauthorized(
            row,
            why::RESPONSE_NOT_HELD,
            format!("no admitted row {authorized_by} on this node"),
        ));
    };
    // (2) Its outcome is approved.
    let approved = response.attestation_type == attestation_type::SCORES
        && envelope_dimension(&response.attestation_envelope) == Some(DEFERRAL_APPROVED_DIMENSION);
    if !approved {
        return Err(unauthorized(
            row,
            why::NOT_APPROVED,
            format!("{authorized_by} is not a {DEFERRAL_APPROVED_DIMENSION}"),
        ));
    }
    // (3) Its subject is this agent.
    if response.attested_key_id != agent {
        return Err(unauthorized(
            row,
            why::ABOUT_ANOTHER_AGENT,
            format!(
                "the response is about {}, the amendment about {agent}",
                response.attested_key_id
            ),
        ));
    }
    // (4) Its signer held a WA seat at its `asserted_at`: the self of the
    // owner of the agent's node (module doc).
    let at = response.asserted_at;
    let owner = match super::admission::owner_of(directory, signer).await? {
        Some(o) => Some(o),
        None => super::admission::owner_of(directory, agent).await?,
    };
    let seated = match owner {
        Some(owner) => {
            let signer_self =
                super::self_roster::self_of_at(directory, &response.attesting_key_id, at).await?;
            let owner_self = super::self_roster::self_of_at(directory, &owner, at).await?;
            signer_self == owner_self
        }
        None => false,
    };
    if !seated {
        return Err(unauthorized(
            row,
            why::NOT_A_SEATED_WA,
            format!(
                "{} held no Wise Authority seat over {agent} at {at}",
                response.attesting_key_id
            ),
        ));
    }
    Ok(())
}
