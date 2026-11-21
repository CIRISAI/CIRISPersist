//! v51.0.0 (CIRISPersist#938 / #937; CC 3.2 T6 / T4a, CC 5.3.1 rc6; FSD
//! `TRUST_ROOT_RC6.md`) — **the lineage-head cosignature**: an independent
//! witness's statement that a conferring lineage's roster chain has THIS head.
//!
//! The object is `ciris.lineage_head_cosign.v1`. Its signed bytes are the JCS
//! canonical form of [`LineageHeadCosign::signing_envelope`], which carries the
//! domain label as a member — so a tree-head cosign (`ciris.sth_cosign.v1`,
//! persist's [`crate::witness`] plane) can never verify as a lineage-head cosign
//! and vice versa: the two envelopes differ in a signed member.
//!
//! The witness set is a SECOND, independent roster: `identity_type ⊇ {witness}`
//! (CC 3.4.10), never a founder of the lineage it witnesses. A lineage
//! witnessed solely by its own founders is unwitnessed for this rule.

use serde::{Deserialize, Serialize};

/// The domain label, a signed member of the envelope.
pub const LINEAGE_HEAD_COSIGN_DOMAIN: &str = "ciris.lineage_head_cosign.v1";

/// #973 (CC 3.2 T6, "Witnessed mode off") — **the quorum a charter declares,
/// with no default substituted.** A charter silent on `witness_quorum`, or
/// declaring `0`, is in witnessed mode OFF: this returns `0`, and every reader
/// asks [`witnessed_mode_on`] before it counts a cosign.
#[must_use]
pub fn declared_witness_quorum(charter_value: Option<u32>) -> u32 {
    charter_value.unwrap_or(0)
}

/// Witnessed mode is on only by an explicit non-zero charter value.
#[must_use]
pub fn witnessed_mode_on(quorum: u32) -> bool {
    quorum > 0
}

/// A witness's cosignature over one head of one lineage.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct LineageHeadCosign {
    /// The community_key_id or family_key_id whose chain this head heads.
    pub lineage_key_id: String,
    /// The head's `persist_row_hash` (SHA-256 over the JCS-canonical signed
    /// record persist already computes and stores; FSD §1.1).
    pub head_digest_sha256_hex: String,
    /// The head's signer-stamped instant (`amended_at` for a link, `founded_at`
    /// for a birth; a family record's own signed instant). RFC 3339.
    pub head_asserted_at: String,
    /// The head this witness last cosigned for this lineage; absent on its
    /// first. A cosign whose prior is not an ancestor of the head in the chain
    /// this node holds is refused; one whose prior names a DIFFERENT witnessed
    /// head is stored as equivocation evidence.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub prior_head_digest_sha256_hex: Option<String>,
    /// The witness's signer-stamped instant. RFC 3339.
    pub signed_at: String,
    /// The witness. Must be registered, `identity_type ⊇ {witness}`, not a
    /// founder of the lineage.
    pub witness_key_id: String,
    /// Ed25519 (base64) over `JCS(signing_envelope())`.
    #[serde(default)]
    pub signature_classical: String,
    /// ML-DSA-65 (base64) over `canonical ‖ ed25519_sig`; `None` ⇒ hybrid-Strict
    /// verify rejects, as everywhere.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub signature_pqc: Option<String>,
}

impl LineageHeadCosign {
    /// The signed envelope: every member but the signatures, plus the domain
    /// label. The verifier is `verify_envelope_hybrid_signature` (deleted v62.0.0, F0-cp8)
    /// over this value, exactly as every other signed persist object.
    pub fn signing_envelope(&self) -> serde_json::Value {
        let mut v = serde_json::json!({
            "domain": LINEAGE_HEAD_COSIGN_DOMAIN,
            "lineage_key_id": self.lineage_key_id,
            "head_digest_sha256_hex": self.head_digest_sha256_hex,
            "head_asserted_at": self.head_asserted_at,
            "signed_at": self.signed_at,
            "witness_key_id": self.witness_key_id,
        });
        if let Some(p) = &self.prior_head_digest_sha256_hex {
            v["prior_head_digest_sha256_hex"] = serde_json::Value::String(p.clone());
        }
        v
    }
}

/// Why a cosign was refused at [`crate::federation::FederationDirectory::put_lineage_head_cosign`]
/// (FSD §2.1, in door order). The `kind()` token rides `Error::LineageCosignRefused`.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum LineageCosignRefusal {
    /// `witness_key_id` has no registered key record here.
    WitnessNotRegistered,
    /// The witness's `identity_type` does not contain `witness`.
    WitnessNotWitnessType,
    /// The witness key was not valid at `signed_at`: before its `valid_from`,
    /// at or after its `valid_until`, or revoked effective at or before it
    /// (PR #943 review — a retired or compromised key confers nothing).
    WitnessNotValidAt,
    /// The witness is a founder of the lineage (the independence rule).
    WitnessIsFounder,
    /// Hybrid verification over the envelope failed.
    SignatureInvalid,
    /// `head_asserted_at` is not the held head's signer-stamped instant.
    HeadInstantMismatch,
    /// `prior_head_digest` is a version this node holds that is NOT an ancestor
    /// of the head (Server's `LINEAGE_HEAD_INCONSISTENT`).
    PriorNotAncestor,
    /// `signed_at` outside CC 2.6.7's skew of now, or before `head_asserted_at`.
    Skew,
    /// The object is malformed (not a hex64 digest, not RFC 3339, empty ids).
    Malformed,
    /// v53.0.0 (CC 3.2 T6, consequence (ii)) — witnessed mode is on and the
    /// cosigned head is the held head, which lags its roster at the cosign's
    /// `signed_at`: a roster row older than one cadence no version covers.
    /// Witnesses do not cosign a lagging head
    /// ([`crate::federation::roster_head::roster_lag`]).
    HeadLagsRoster,
}

impl LineageCosignRefusal {
    /// The wire token.
    pub fn as_str(self) -> &'static str {
        match self {
            Self::WitnessNotRegistered => "witness_not_registered",
            Self::WitnessNotWitnessType => "witness_not_witness_type",
            Self::WitnessNotValidAt => "witness_not_valid_at",
            Self::WitnessIsFounder => "witness_is_founder",
            Self::SignatureInvalid => "signature_invalid",
            Self::HeadInstantMismatch => "head_instant_mismatch",
            Self::PriorNotAncestor => "prior_not_ancestor",
            Self::Skew => "skew",
            Self::Malformed => "malformed",
            Self::HeadLagsRoster => crate::federation::roster_head::LINEAGE_HEAD_LAGS_ROSTER,
        }
    }
}

/// The door's typed outcome.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case", tag = "outcome")]
pub enum LineageCosignOutcome {
    /// Stored.
    Inserted,
    /// The identical cosign was already held.
    Unchanged,
    /// Stored, but this node holds no version of the lineage with that head:
    /// held as evidence, effective once the head arrives (FSD §2.1 (5)).
    HeldForUnknownHead,
    /// Refused, with the rule.
    Refused {
        /// The rule.
        reason: LineageCosignRefusal,
    },
    /// v62.0.0 (wave GC3; CC 2.7, rc21 item 15) — STORED, and it does not
    /// count toward the head's quorum: the rule it fails reads OTHER rows
    /// (the held versions, their founders, the roster), so the cosign is
    /// kept, and the witnessed-head fold ([`effective_cosigns`],
    /// [`witnesses_of`]) leaves it out by the same rule. A lagging head's
    /// cosign therefore goes stale through the T4a freshness gate.
    KeptNotCounted {
        /// The rule it fails.
        reason: LineageCosignRefusal,
    },
}

/// v62.0.0 (wave GC3; CC 2.7, rc21 item 15) — **is `lineage`'s held head
/// lagging its roster at `at`, with witnessed mode on?** The one predicate
/// the door and the witnessed-head fold share. With witnessed mode off the
/// lag is only reported, never counted against a cosign.
pub async fn head_lags_roster_at<F>(
    directory: &F,
    lineage: &str,
    at: chrono::DateTime<chrono::Utc>,
) -> Result<bool, crate::federation::Error>
where
    F: crate::federation::FederationDirectory + ?Sized,
{
    let quorum = declared_witness_quorum(
        crate::federation::canonical_community::charter_members_for(directory, lineage)
            .await?
            .and_then(|c| c.witness_quorum),
    );
    if !witnessed_mode_on(quorum) {
        return Ok(false);
    }
    Ok(
        crate::federation::roster_head::roster_lag(directory, lineage, at)
            .await?
            .is_some(),
    )
}

/// The witness's standing at an instant (PR #943 review).
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum WitnessStanding {
    /// No key record here.
    NotRegistered,
    /// A key whose `identity_type` does not contain `witness`.
    NotWitness,
    /// Outside its lifetime, or revoked effective at or before the instant.
    NotValidAt,
    /// Counts, as this person (the principal persist's fold resolves the key to).
    Counts {
        /// The witness's person.
        principal: String,
    },
}

/// A witness key's standing at `at`: registered, `identity_type ⊇ {witness}`,
/// `valid_from <= at < valid_until`, no admitted revocation effective at or
/// before `at`; and the PERSON it resolves to (occurrence axis, then
/// owner-binding axis — [`crate::federation::admission::writer_principal`]).
/// An ambiguous owner resolves to the key itself.
pub async fn witness_standing_at<F>(
    directory: &F,
    witness_key_id: &str,
    at: chrono::DateTime<chrono::Utc>,
) -> Result<WitnessStanding, crate::federation::Error>
where
    F: crate::federation::FederationDirectory + ?Sized,
{
    use crate::federation::types::identity_type;
    let Some(record) = directory.lookup_public_key(witness_key_id).await? else {
        return Ok(WitnessStanding::NotRegistered);
    };
    if !identity_type::set_contains(&record.identity_type, identity_type::WITNESS) {
        return Ok(WitnessStanding::NotWitness);
    }
    if record.valid_from > at || record.valid_until.is_some_and(|u| u <= at) {
        return Ok(WitnessStanding::NotValidAt);
    }
    if directory
        .revocations_for(witness_key_id)
        .await?
        .iter()
        .any(|r| r.effective_at <= at)
    {
        return Ok(WitnessStanding::NotValidAt);
    }
    let principal = crate::federation::admission::writer_principal(directory, witness_key_id)
        .await
        .unwrap_or_else(|_| witness_key_id.to_owned());
    Ok(WitnessStanding::Counts { principal })
}

/// Every key's person (see [`witness_standing_at`]); a key whose fold errors is
/// its own person.
pub async fn principals_of<F>(
    directory: &F,
    keys: &[String],
) -> Result<std::collections::BTreeSet<String>, crate::federation::Error>
where
    F: crate::federation::FederationDirectory + ?Sized,
{
    let mut out = std::collections::BTreeSet::new();
    for k in keys {
        out.insert(
            crate::federation::admission::writer_principal(directory, k)
                .await
                .unwrap_or_else(|_| k.clone()),
        );
    }
    Ok(out)
}

/// A stored cosign that COUNTS: its witness key was valid at its `signed_at`,
/// and — when this node holds the version it names — its `head_asserted_at` is
/// that version's instant and its `prior`, when held, is an ancestor. A cosign
/// stored for a head this node did not yet hold is re-checked here when the
/// head arrives (PR #943 review: deferred rows pass the skipped checks before
/// they count).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct EffectiveCosign {
    /// The head it names.
    pub head_digest: String,
    /// The prior it names.
    pub prior: Option<String>,
    /// The witness's person.
    pub principal: String,
    /// The witness key.
    pub witness_key_id: String,
    /// The witness's instant.
    pub signed_at: chrono::DateTime<chrono::Utc>,
}

/// Filter `cosigns` to the ones that count, against the versions this node
/// holds (`known`: digest and signer-stamped instant, oldest first).
pub async fn effective_cosigns<F>(
    directory: &F,
    cosigns: &[LineageHeadCosign],
    known: &[(String, chrono::DateTime<chrono::Utc>)],
) -> Result<Vec<EffectiveCosign>, crate::federation::Error>
where
    F: crate::federation::FederationDirectory + ?Sized,
{
    let parse = |s: &str| {
        chrono::DateTime::parse_from_rfc3339(s)
            .ok()
            .map(|t| t.with_timezone(&chrono::Utc))
    };
    let mut out = Vec::new();
    for c in cosigns {
        let (Some(signed_at), Some(head_at)) = (parse(&c.signed_at), parse(&c.head_asserted_at))
        else {
            continue;
        };
        let WitnessStanding::Counts { principal } =
            witness_standing_at(directory, &c.witness_key_id, signed_at).await?
        else {
            continue;
        };
        if let Some(pos) = known
            .iter()
            .position(|(d, _)| d == &c.head_digest_sha256_hex)
        {
            if known[pos].1 != head_at {
                continue;
            }
            if let Some(p) = &c.prior_head_digest_sha256_hex {
                if let Some(pp) = known.iter().position(|(d, _)| d == p) {
                    if pp >= pos {
                        continue;
                    }
                }
            }
            // v62.0.0 (wave GC3; CC 2.7, rc21 item 15) — a cosign on the held
            // head that lagged its roster at the witness's instant is kept and
            // does not count (the door's `HeadLagsRoster`, now a reason).
            if pos + 1 == known.len()
                && head_lags_roster_at(directory, &c.lineage_key_id, signed_at).await?
            {
                continue;
            }
        }
        out.push(EffectiveCosign {
            head_digest: c.head_digest_sha256_hex.clone(),
            prior: c.prior_head_digest_sha256_hex.clone(),
            principal,
            witness_key_id: c.witness_key_id.clone(),
            signed_at,
        });
    }
    Ok(out)
}

/// `witnessed(head)` — at least `quorum` effective cosigns for `head_digest`
/// from DISTINCT PERSONS, none of whom is a founder's person (FSD §3.2; PR
/// #943 review: one identity's several keys count once). Pure. With witnessed
/// mode off (`quorum == 0`, #973) nothing is witnessed, whatever is held.
pub fn witnessed(
    effective: &[EffectiveCosign],
    head_digest: &str,
    founder_principals: &std::collections::BTreeSet<String>,
    quorum: u32,
) -> bool {
    witnessed_mode_on(quorum)
        && witnesses_of(effective, head_digest, founder_principals).len() as u32 >= quorum
}

/// The distinct non-founder persons whose effective cosigns name `head_digest`.
pub fn witnesses_of(
    effective: &[EffectiveCosign],
    head_digest: &str,
    founder_principals: &std::collections::BTreeSet<String>,
) -> Vec<String> {
    let mut w: Vec<String> = effective
        .iter()
        .filter(|c| c.head_digest == head_digest)
        .filter(|c| !founder_principals.contains(&c.principal))
        .map(|c| c.principal.clone())
        .collect();
    w.sort();
    w.dedup();
    w
}

#[cfg(test)]
mod tests {
    use super::*;

    fn cosign(head: &str, witness: &str) -> LineageHeadCosign {
        LineageHeadCosign {
            lineage_key_id: "ciris-canonical".into(),
            head_digest_sha256_hex: head.into(),
            head_asserted_at: "2026-09-28T00:00:00Z".into(),
            prior_head_digest_sha256_hex: None,
            signed_at: "2026-09-28T00:00:01Z".into(),
            witness_key_id: witness.into(),
            signature_classical: String::new(),
            signature_pqc: None,
        }
    }

    /// The envelope carries the domain as a signed member; the STH cosign's
    /// envelope does not — the two can never verify as each other.
    #[test]
    fn the_domain_label_is_a_signed_member() {
        let v = cosign("aa", "w1").signing_envelope();
        assert_eq!(v["domain"], LINEAGE_HEAD_COSIGN_DOMAIN);
        assert!(v.get("signature_classical").is_none());
        assert!(v.get("prior_head_digest_sha256_hex").is_none());
        let mut c = cosign("aa", "w1");
        c.prior_head_digest_sha256_hex = Some("bb".into());
        assert_eq!(c.signing_envelope()["prior_head_digest_sha256_hex"], "bb");
    }

    fn eff(head: &str, principal: &str) -> EffectiveCosign {
        EffectiveCosign {
            head_digest: head.into(),
            prior: None,
            principal: principal.into(),
            witness_key_id: format!("{principal}-key"),
            signed_at: "2026-09-28T00:00:01Z".parse().unwrap(),
        }
    }

    /// Witnessed counts DISTINCT non-founder PERSONS against the quorum: one
    /// person's two keys count once; a founder's person never counts.
    #[test]
    fn witnessed_counts_distinct_independent_persons() {
        let founders: std::collections::BTreeSet<String> =
            ["f1".to_string(), "f2".to_string()].into();
        let mut two_keys_one_person = eff("h", "w1");
        two_keys_one_person.witness_key_id = "w1-second-key".into();
        let cs = vec![
            eff("h", "w1"),
            two_keys_one_person,
            eff("h", "f1"),
            eff("g", "w2"),
        ];
        assert!(witnessed(&cs, "h", &founders, 1));
        assert!(
            !witnessed(&cs, "h", &founders, 2),
            "one person with two keys is one witness"
        );
        assert!(witnessed(&cs, "g", &founders, 1), "w2 witnesses g");
        let only_founder = vec![eff("h", "f1"), eff("h", "f2")];
        assert!(
            !witnessed(&only_founder, "h", &founders, 1),
            "a lineage witnessed solely by its founders is unwitnessed"
        );
        assert!(
            !witnessed(&cs, "h", &founders, 0),
            "quorum 0 is witnessed mode off: nothing is witnessed (#973)"
        );
        assert_eq!(declared_witness_quorum(None), 0, "silence is not a default");
        assert_eq!(declared_witness_quorum(Some(0)), 0);
        assert_eq!(declared_witness_quorum(Some(2)), 2);
        assert!(!witnessed_mode_on(0) && witnessed_mode_on(2));
    }
}
