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
//! `asserted_at`. Otherwise it is **`identity_amendment_unauthorized`**.
//!
//! # Held, not refused (v62, CC 2.7)
//!
//! "A row is never refused for what another row says." Every condition the
//! CITED RESPONSE decides (held, approved, naming this text, about this
//! agent, by a seated WA) is the amendment's [`AmendmentStanding`], read by
//! [`amendment_standing`] (one row) or [`amendment_standings_for`] (an
//! agent's) at the time of the read. The amendment is ADMITTED at every door
//! and HELD: it does not count while a condition fails, and it reports the
//! token and the condition. A matching approval held later makes it count;
//! nothing is re-written. The door ([`check_identity_amendment_admission`])
//! refuses only what the amendment's own bytes and its signer decide: the
//! member shapes ([`Error::MalformedRow`]), `evidence_refs[]` citing
//! `authorized_by`, and the signer being an occurrence of the agent
//! (`identity_amendment_unauthorized`).
//!
//! # The approved text (CC 3.1.5, rc21)
//!
//! An approval authorises ONE text, not "an amendment". CIRISServer 0.5.250
//! (CIRISServer#1365/#1366, Eric's ruling) puts the `amendment_digest` of the
//! text the Wise Authority approved into the WA-signed
//! `deferral:response:approved:v1` row, and CC rc21 adds the clause: the
//! amendment's `amendment_digest` must EQUAL the cited response's. Otherwise
//! the amendment is held under **`amendment_digest_mismatch`** (its own token,
//! [`AMENDMENT_DIGEST_MISMATCH`]), one token for every case, with the case in
//! the message ([`digest_mismatch_reason`]):
//!
//! - the response carries no `amendment_digest` (an approval that names no
//!   text authorises none — the earlier server's rows, too);
//! - the response's `amendment_digest` is present but not 64 lowercase hex
//!   digits. The response row is already admitted, so this is not the
//!   amendment's malformation: the approval names no text this amendment can
//!   be;
//! - the two digests differ.
//!
//! The condition is read after the outcome (2) and before the subject and
//! seat conditions. In the edition-2 forward form the member is a hash
//! digest (`[-16, bstr .size 32]`); the edition-2 ingest hands the gates its
//! bytes as lowercase hex, so this gate compares the hex form either way.
//!
//! CIRISServer (0.5.234, `agent_deferral.rs`) enforces the rule at its own
//! authoring door, which is the only way a server node MAKES an amendment.
//! A replicated amendment from another producer reached no gate at all; this
//! module is that rule, at every door a row enters by and at every read.
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
//! identity the amendment is about). When neither has an owner binding and
//! the signing key's active identity is a person (a `user` identity the key
//! is an occurrence of: the split home of CIRISServer 0.5.189+, where the
//! owner binds the NODE and the agent key is the owner's occurrence through
//! the login anchor), that person is the owner. An unowned agent has no
//! seated WA, so nothing authorises its amendment.
//!
//! # The refusal's shape (the door's two self-contained refusals)
//!
//! `identity_amendment_unauthorized` rides [`Error::InvalidArgument`] with the
//! token leading its message (the `reconsideration_community_mismatch`
//! precedent; a new `Error` arm would be a break in a minor). The ill-shaped
//! members (`amendment_digest`, `authorized_by`) are
//! [`Error::MalformedRow`]: those bytes can never be an amendment.
//! A held amendment reports its token and case through
//! [`AmendmentStanding::Held`], never as an error.

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

/// CC 3.1.5 (rc10) — the token: a door refusal for the two self-contained
/// conditions, a held amendment's reason for the response-decided ones.
pub const IDENTITY_AMENDMENT_UNAUTHORIZED: &str = "identity_amendment_unauthorized";

/// CC 3.1.5 (rc21; CIRISServer#1365/#1366) — the held amendment's token when
/// it is not the exact text the Wise Authority approved: the cited
/// approval's `amendment_digest` is absent, ill-shaped, or another digest.
pub const AMENDMENT_DIGEST_MISMATCH: &str = "amendment_digest_mismatch";

/// Which case an [`AMENDMENT_DIGEST_MISMATCH`] standing is; persist-local.
pub mod digest_mismatch_reason {
    /// The approval carries no `amendment_digest`: it names no text.
    pub const RESPONSE_NAMES_NO_TEXT: &str = "response_carries_no_amendment_digest";
    /// The approval's `amendment_digest` is not 64 lowercase hex digits.
    pub const RESPONSE_DIGEST_ILL_SHAPED: &str = "response_amendment_digest_not_hex64";
    /// The approval names another text.
    pub const DIGESTS_DIFFER: &str = "amendment_digest_differs_from_approved";
}

/// Which CC 3.1.5 condition an unauthorized amendment failed: in a door
/// refusal's message after the token, or in a held standing; persist-local.
pub mod unauthorized_reason {
    /// `evidence_refs[]` does not cite the `authorized_by` response.
    pub const EVIDENCE_DOES_NOT_CITE: &str = "evidence_does_not_cite_response";
    /// The cited response is not held on this node. The ordering gap: it
    /// may still arrive, and the amendment counts once it does.
    pub const RESPONSE_NOT_HELD: &str = "response_not_held";
    /// The cited row is not a `deferral:response:approved:v1`.
    pub const NOT_APPROVED: &str = "response_not_approved";
    /// The response is about another agent.
    pub const ABOUT_ANOTHER_AGENT: &str = "response_about_another_agent";
    /// The amendment is not signed by an occurrence of the agent it is about.
    pub const NOT_THE_AGENTS_OCCURRENCE: &str = "attester_not_the_agents_occurrence";
    /// The response's signer held no WA seat at its `asserted_at`.
    pub const NOT_A_SEATED_WA: &str = "response_signer_not_a_seated_wa";
    /// v62 (CC 2.7) — the approval is withdrawn (or recanted) by a key
    /// entitled to retract it: it authorises nothing any more. A held
    /// standing only, never a door refusal.
    pub const RESPONSE_WITHDRAWN: &str = "response_withdrawn";
}

/// v62 (CC 2.7) — **an amendment's standing**: whether the approval it
/// cites authorises it NOW. A row is never refused for what another row says,
/// so the door admits an amendment whatever its cited response says, and
/// every reader of "the amendment in force" asks this.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum AmendmentStanding {
    /// The cited approval authorises the amendment: it counts.
    InForce,
    /// Admitted and held: it does NOT count while `token` / `reason` holds.
    /// A later matching approval (or the response arriving) makes it count;
    /// nothing is re-written, the standing is re-read.
    Held {
        /// [`IDENTITY_AMENDMENT_UNAUTHORIZED`] or [`AMENDMENT_DIGEST_MISMATCH`].
        token: &'static str,
        /// The case: an [`unauthorized_reason`] or a [`digest_mismatch_reason`].
        reason: &'static str,
        /// Human detail.
        detail: String,
    },
}

impl AmendmentStanding {
    /// Does the amendment count?
    #[must_use]
    pub fn is_in_force(&self) -> bool {
        matches!(self, Self::InForce)
    }

    /// The reason token a held amendment reports (`None` in force).
    #[must_use]
    pub fn token(&self) -> Option<&'static str> {
        match self {
            Self::InForce => None,
            Self::Held { token, .. } => Some(token),
        }
    }

    /// The case a held amendment reports (`None` in force).
    #[must_use]
    pub fn reason(&self) -> Option<&'static str> {
        match self {
            Self::InForce => None,
            Self::Held { reason, .. } => Some(reason),
        }
    }
}

fn held(token: &'static str, reason: &'static str, detail: String) -> AmendmentStanding {
    AmendmentStanding::Held {
        token,
        reason,
        detail,
    }
}

fn unauthorized(row: &Attestation, reason: &'static str, detail: String) -> Error {
    Error::InvalidArgument(format!(
        "{IDENTITY_AMENDMENT_UNAUTHORIZED}: {reason}: amendment {} — {detail} (CC 3.1.5, \
         CIRISPersist#1120)",
        row.attestation_id
    ))
}

/// CC 3.1.5 (rc21) — **the amendment is the text the WA approved.** `digest`
/// is the amendment's own (already checked hex64); `response` is the cited
/// `deferral:response:approved:v1`. A pure function of the two rows. `None`
/// when the digests are equal; otherwise the held standing, led by
/// [`AMENDMENT_DIGEST_MISMATCH`].
fn approved_digest_standing(digest: &str, response: &Attestation) -> Option<AmendmentStanding> {
    use digest_mismatch_reason as why;
    let (reason, detail) = match response.attestation_envelope.get(AMENDMENT_DIGEST_MEMBER) {
        None => (
            why::RESPONSE_NAMES_NO_TEXT,
            format!(
                "the approval {} carries no `{AMENDMENT_DIGEST_MEMBER}`, so it authorises no text",
                response.attestation_id
            ),
        ),
        Some(serde_json::Value::String(approved)) if is_hex64(approved) => {
            if approved == digest {
                return None;
            }
            (
                why::DIGESTS_DIFFER,
                format!(
                    "the approval {} names {approved}, the amendment carries {digest}",
                    response.attestation_id
                ),
            )
        }
        Some(_) => (
            why::RESPONSE_DIGEST_ILL_SHAPED,
            format!(
                "the approval {}'s `{AMENDMENT_DIGEST_MEMBER}` is not 64 lowercase hex digits, \
                 so it names no text this amendment can be",
                response.attestation_id
            ),
        ),
    };
    Some(held(AMENDMENT_DIGEST_MISMATCH, reason, detail))
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

/// v60.1.0 (CIRISPersist#1120, CIRISServer#601) — **the person `occurrence`
/// is an occurrence of**, when its active identity is a `user`: on a split
/// home the agent key is its human's occurrence (the login anchor) and the
/// owner-binding names only the node, so that person is the owner the seat
/// reads. `None` when the active identity is the key itself or not a person.
async fn person_of_occurrence(
    directory: &dyn FederationDirectory,
    occurrence: &str,
) -> Result<Option<String>, Error> {
    let identity = directory.active_identity_for_occurrence(occurrence).await?;
    if identity != occurrence && super::self_roster::is_user_key(directory, &identity).await? {
        return Ok(Some(identity));
    }
    Ok(None)
}

/// The members a well-formed amendment carries: `(amendment_digest,
/// authorized_by)`. The row's own bytes only.
///
/// # Errors
///
/// [`Error::MalformedRow`] for an absent or ill-shaped member.
fn amendment_members(row: &Attestation) -> Result<(&str, &str), Error> {
    let env = &row.attestation_envelope;
    let digest = match env.get(AMENDMENT_DIGEST_MEMBER).map(|v| v.as_str()) {
        None => {
            return Err(malformed(
                malformed_row::ENVELOPE_MEMBER_MISSING,
                format!("`{AMENDMENT_DIGEST_MEMBER}` is required"),
            ))
        }
        Some(Some(d)) if is_hex64(d) => d,
        Some(_) => {
            return Err(malformed(
                malformed_row::ENVELOPE_MEMBER_INVALID,
                format!("`{AMENDMENT_DIGEST_MEMBER}` is not 64 lowercase hex digits"),
            ))
        }
    };
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
    Ok((digest, authorized_by))
}

/// v60.1.0 (CIRISPersist#1120; CC 3.1.5) — **the door.** A no-op for every
/// row that is not an `identity_amendment:v1`.
///
/// v62 (CC 2.7, "a row is never refused for what another row says") — the
/// door refuses only what the amendment's OWN bytes and its signer decide:
/// the member shapes, `evidence_refs[]` citing `authorized_by`, and the
/// signer being an occurrence of the agent the row is about. Everything the
/// CITED RESPONSE decides (held here, approved, about this agent, by a seated
/// WA, naming this text) is the amendment's [`AmendmentStanding`], read by
/// [`amendment_standing`] whenever the amendment's force is asked: the row
/// is admitted and held, and counts once a matching approval is held.
///
/// # Errors
///
/// [`Error::MalformedRow`] for an ill-shaped member;
/// [`Error::InvalidArgument`] led by [`IDENTITY_AMENDMENT_UNAUTHORIZED`] for
/// [`unauthorized_reason::EVIDENCE_DOES_NOT_CITE`] and
/// [`unauthorized_reason::NOT_THE_AGENTS_OCCURRENCE`]; directory reads.
pub async fn check_identity_amendment_admission(
    directory: &dyn FederationDirectory,
    row: &Attestation,
) -> Result<(), Error> {
    use unauthorized_reason as why;
    if !is_identity_amendment(row) {
        return Ok(());
    }
    let (_, authorized_by) = amendment_members(row)?;
    let cites = row
        .attestation_envelope
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

    // Attester = an occurrence of the agent, subject = the agent: a question
    // about the SIGNER, not about the cited response.
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
    Ok(())
}

/// v62 (CC 2.7; CC 3.1.5 rc10 + rc21) — **the amendment's standing, read
/// now.** `None` for a row that is not an `identity_amendment:v1`. The
/// conditions, in order, each over the cited `deferral:response:*` as this
/// node holds it at the time of the read:
///
/// 1. the response is held ([`unauthorized_reason::RESPONSE_NOT_HELD`]);
/// 2. it is a `deferral:response:approved:v1`
///    ([`unauthorized_reason::NOT_APPROVED`]), not withdrawn or recanted by a
///    key entitled to retract it ([`unauthorized_reason::RESPONSE_WITHDRAWN`];
///    a `supersedes` is not followed);
/// 3. it names this amendment's text ([`AMENDMENT_DIGEST_MISMATCH`], the
///    [`digest_mismatch_reason`] cases);
/// 4. it is about this agent ([`unauthorized_reason::ABOUT_ANOTHER_AGENT`]);
/// 5. its signer held a WA seat at its `asserted_at` (module doc,
///    [`unauthorized_reason::NOT_A_SEATED_WA`]).
///
/// All hold: [`AmendmentStanding::InForce`]. A held amendment reports the
/// first failing condition. Nothing is stored: a later approval changes the
/// answer the next read gives.
///
/// # Errors
///
/// [`Error::MalformedRow`] for an ill-shaped member (an admitted row never
/// is); directory reads.
pub async fn amendment_standing(
    directory: &dyn FederationDirectory,
    row: &Attestation,
) -> Result<Option<AmendmentStanding>, Error> {
    use unauthorized_reason as why;
    if !is_identity_amendment(row) {
        return Ok(None);
    }
    let (digest, authorized_by) = amendment_members(row)?;
    let agent = row.attested_key_id.as_str();
    let signer = row.attesting_key_id.as_str();
    let unauth = |reason, detail| Ok(Some(held(IDENTITY_AMENDMENT_UNAUTHORIZED, reason, detail)));

    // (1) The cited response is held here.
    let Some(response) = directory.get_attestation(authorized_by).await? else {
        return unauth(
            why::RESPONSE_NOT_HELD,
            format!("no admitted row {authorized_by} on this node"),
        );
    };
    // (2) Its outcome is approved.
    let approved = response.attestation_type == attestation_type::SCORES
        && envelope_dimension(&response.attestation_envelope) == Some(DEFERRAL_APPROVED_DIMENSION);
    if !approved {
        return unauth(
            why::NOT_APPROVED,
            format!("{authorized_by} is not a {DEFERRAL_APPROVED_DIMENSION}"),
        );
    }
    // (2a) v62 (CC 2.7) — it is not withdrawn: a `withdraws` / `recants` of
    // it by a key entitled to retract it (the one retraction rule,
    // `precedence::retraction_entitled`) leaves the amendment held. A
    // `supersedes` is NOT followed: the amendment names this row, and a
    // different approval is answered by an amendment citing it.
    for r in directory
        .list_attestations_referencing(&response.attestation_id)
        .await?
    {
        let retracts = r.attestation_type == attestation_type::WITHDRAWS
            || r.attestation_type == attestation_type::RECANTS;
        if retracts && super::precedence::retraction_entitled(&r, &response) {
            return unauth(
                why::RESPONSE_WITHDRAWN,
                format!("{authorized_by} is retracted by {}", r.attestation_id),
            );
        }
    }
    // (3) CC 3.1.5 rc21 — it approved exactly this text.
    if let Some(mismatch) = approved_digest_standing(digest, &response) {
        return Ok(Some(mismatch));
    }
    // (4) Its subject is this agent.
    if response.attested_key_id != agent {
        return unauth(
            why::ABOUT_ANOTHER_AGENT,
            format!(
                "the response is about {}, the amendment about {agent}",
                response.attested_key_id
            ),
        );
    }
    // (5) Its signer held a WA seat at its `asserted_at`: the self of the
    // owner of the agent's node (module doc).
    let at = response.asserted_at;
    let owner = match super::admission::owner_of(directory, signer).await? {
        Some(o) => Some(o),
        None => match super::admission::owner_of(directory, agent).await? {
            Some(o) => Some(o),
            None => person_of_occurrence(directory, signer).await?,
        },
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
        return unauth(
            why::NOT_A_SEATED_WA,
            format!(
                "{} held no Wise Authority seat over {agent} at {at}",
                response.attesting_key_id
            ),
        );
    }
    Ok(Some(AmendmentStanding::InForce))
}

/// v62 (CC 2.7) — **every `identity_amendment:v1` about `agent` this node
/// holds, each with its standing read now**, oldest first. A reader of "the
/// amendments in force" keeps those whose standing
/// [`is_in_force`](AmendmentStanding::is_in_force); a held one reports its
/// token. Retraction (`withdraws` / `recants` / `supersedes`) is the
/// reader's usual fold and is not applied here.
///
/// # Errors
///
/// Directory reads; [`Error::MalformedRow`] for a held row that does not
/// parse (an admitted row never is).
pub async fn amendment_standings_for(
    directory: &dyn FederationDirectory,
    agent: &str,
) -> Result<Vec<(Attestation, AmendmentStanding)>, Error> {
    use super::attestation_query::{AttestationQuery, FOLD_PAGE};
    let mut rows = Vec::new();
    let mut pages = AttestationQuery::to(agent, FOLD_PAGE)
        .dimension_prefix(IDENTITY_AMENDMENT_FAMILY_STEM)
        .pages();
    while let Some(page) = pages.next(directory).await? {
        rows.extend(page);
    }
    let mut out = Vec::new();
    for row in rows {
        if let Some(standing) = amendment_standing(directory, &row).await? {
            out.push((row, standing));
        }
    }
    Ok(out)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::federation::tier_ingest::test_support as ts;

    fn approval(digest: Option<serde_json::Value>) -> Attestation {
        let id = uuid::Uuid::new_v4().to_string();
        let mut env = serde_json::json!({ "id": id, "dimension": DEFERRAL_APPROVED_DIMENSION });
        if let Some(d) = digest {
            env[AMENDMENT_DIGEST_MEMBER] = d;
        }
        let mut r = ts::bare_attestation(&id, "i2930-wa", "i2930-agent", &env);
        r.attestation_type = attestation_type::SCORES.to_owned();
        r
    }

    fn mismatch_with(s: Option<AmendmentStanding>, reason: &str, what: &str) {
        let s = s.unwrap_or_else(|| panic!("I2930 ({what}): expected held, got in force"));
        assert!(!s.is_in_force(), "I2930 ({what})");
        assert_eq!(s.token(), Some(AMENDMENT_DIGEST_MISMATCH), "I2930 ({what})");
        assert_eq!(s.reason(), Some(reason), "I2930 ({what})");
    }

    /// **I2930 (CC 3.1.5 rc21; CIRISServer#1365/#1366; CC 2.7)** — the
    /// approved-text condition, as a pure function of the two rows: an equal
    /// digest raises nothing; an absent, ill-shaped (uppercase, short,
    /// non-string, null) or different one HOLDS the amendment under
    /// `amendment_digest_mismatch`, each case named. Mutation targets: the
    /// equality and the absent arm.
    #[test]
    fn i2930_the_amendment_is_the_text_the_wa_approved() {
        let digest = "cd".repeat(32);
        assert_eq!(
            approved_digest_standing(&digest, &approval(Some(serde_json::json!(digest)))),
            None,
            "I2930: the approved text raises nothing"
        );
        use digest_mismatch_reason as why;
        mismatch_with(
            approved_digest_standing(&digest, &approval(None)),
            why::RESPONSE_NAMES_NO_TEXT,
            "absent",
        );
        mismatch_with(
            approved_digest_standing(&digest, &approval(Some(serde_json::json!("ef".repeat(32))))),
            why::DIGESTS_DIFFER,
            "another text",
        );
        for (bad, what) in [
            (serde_json::json!("CD".repeat(32)), "uppercase"),
            (serde_json::json!("cd".repeat(31)), "short"),
            (serde_json::json!(7), "a number"),
            (serde_json::Value::Null, "null"),
        ] {
            mismatch_with(
                approved_digest_standing(&digest, &approval(Some(bad))),
                why::RESPONSE_DIGEST_ILL_SHAPED,
                what,
            );
        }
        assert_ne!(AMENDMENT_DIGEST_MISMATCH, IDENTITY_AMENDMENT_UNAUTHORIZED);
        assert!(AmendmentStanding::InForce.is_in_force());
        assert_eq!(AmendmentStanding::InForce.token(), None);
    }
}
