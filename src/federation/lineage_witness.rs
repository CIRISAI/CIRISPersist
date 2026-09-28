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

/// The default witness quorum when a charter declares none (`witness_quorum`):
/// ONE independent witness. Persist's choice pending CC text (FSD §1.3).
pub const DEFAULT_WITNESS_QUORUM: u32 = 1;

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
    /// label. The verifier is [`crate::federation::tier_ingest::verify_envelope_hybrid_signature`]
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
}

impl LineageCosignRefusal {
    /// The wire token.
    pub fn as_str(self) -> &'static str {
        match self {
            Self::WitnessNotRegistered => "witness_not_registered",
            Self::WitnessNotWitnessType => "witness_not_witness_type",
            Self::WitnessIsFounder => "witness_is_founder",
            Self::SignatureInvalid => "signature_invalid",
            Self::HeadInstantMismatch => "head_instant_mismatch",
            Self::PriorNotAncestor => "prior_not_ancestor",
            Self::Skew => "skew",
            Self::Malformed => "malformed",
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
}

/// **The cosign door** (FSD `TRUST_ROOT_RC6.md` §2.1) — every refusal in door
/// order, then the store. `now` is the door's one clock read (round-9
/// discipline). A cosign for a head this node does not hold is STORED and
/// reported `HeldForUnknownHead` (evidence; effective when the head arrives).
/// No cosign is ever deleted.
pub async fn admit_lineage_head_cosign<F>(
    directory: &F,
    cosign: &LineageHeadCosign,
    now: chrono::DateTime<chrono::Utc>,
) -> Result<LineageCosignOutcome, crate::federation::Error>
where
    F: crate::federation::FederationDirectory + ?Sized,
{
    use crate::federation::types::identity_type;
    let refused = |reason: LineageCosignRefusal| Ok(LineageCosignOutcome::Refused { reason });
    // 0. shape
    let hex64 = |s: &str| {
        s.len() == 64
            && s.bytes()
                .all(|b| b.is_ascii_hexdigit() && !b.is_ascii_uppercase())
    };
    if cosign.lineage_key_id.is_empty()
        || cosign.witness_key_id.is_empty()
        || !hex64(&cosign.head_digest_sha256_hex)
        || cosign
            .prior_head_digest_sha256_hex
            .as_deref()
            .is_some_and(|p| !hex64(p))
    {
        return refused(LineageCosignRefusal::Malformed);
    }
    let parse =
        |s: &str| chrono::DateTime::parse_from_rfc3339(s).map(|t| t.with_timezone(&chrono::Utc));
    let (Ok(head_at), Ok(signed_at)) = (parse(&cosign.head_asserted_at), parse(&cosign.signed_at))
    else {
        return refused(LineageCosignRefusal::Malformed);
    };
    // 1–2. the witness: registered, identity_type ⊇ {witness}
    let Some(record) = directory.lookup_public_key(&cosign.witness_key_id).await? else {
        return refused(LineageCosignRefusal::WitnessNotRegistered);
    };
    if !identity_type::set_contains(&record.identity_type, identity_type::WITNESS) {
        return refused(LineageCosignRefusal::WitnessNotWitnessType);
    }
    // 3. independence: not a founder of the lineage (at the head, or on any
    //    version of the chain this node holds) — a family's members likewise.
    let held = directory
        .lookup_signed_community(&cosign.lineage_key_id)
        .await?;
    let family = match held {
        Some(_) => None,
        None => directory.lookup_family(&cosign.lineage_key_id).await?,
    };
    let mut founders: Vec<String> = Vec::new();
    if let Some(h) = &held {
        for v in h.lineage.iter().chain(std::iter::once(h)) {
            founders.extend(
                crate::federation::canonical_community::founders(&v.community)
                    .into_iter()
                    .map(str::to_owned),
            );
        }
    }
    if let Some(f) = &family {
        founders.extend(f.members.iter().map(|m| m.key_id.clone()));
    }
    if founders.iter().any(|f| f == &cosign.witness_key_id) {
        return refused(LineageCosignRefusal::WitnessIsFounder);
    }
    // 4. the signature, hybrid-Strict over the domain-labelled envelope
    if crate::federation::tier_ingest::verify_envelope_hybrid_signature(
        directory,
        &cosign.witness_key_id,
        &cosign.signing_envelope(),
        &cosign.signature_classical,
        cosign.signature_pqc.as_deref(),
    )
    .await
    .is_err()
    {
        return refused(LineageCosignRefusal::SignatureInvalid);
    }
    // 8 (before the head checks, it needs no row): skew — the witness's instant
    //    within CC 2.6.7's bound of now, and not before the head's instant.
    if crate::federation::operational::check_skew_bound(signed_at, now).is_err()
        || signed_at < head_at
    {
        return refused(LineageCosignRefusal::Skew);
    }
    // 5–7. the head this node holds
    let held_versions: Vec<(String, chrono::DateTime<chrono::Utc>)> = match (&held, &family) {
        (Some(h), _) => h
            .lineage
            .iter()
            .chain(std::iter::once(h))
            .map(|v| {
                (
                    v.community.persist_row_hash.clone(),
                    crate::federation::canonical_community::head_instant(v),
                )
            })
            .collect(),
        (None, Some(f)) => vec![(f.persist_row_hash.clone(), f.founded_at)],
        (None, None) => Vec::new(),
    };
    let known = held_versions
        .iter()
        .find(|(digest, _)| digest == &cosign.head_digest_sha256_hex);
    let outcome = match known {
        None => LineageCosignOutcome::HeldForUnknownHead,
        Some((_, instant)) => {
            // 6. the head's signer-stamped instant, byte-exact as an instant
            if *instant != head_at {
                return refused(LineageCosignRefusal::HeadInstantMismatch);
            }
            // 7. a prior this node HOLDS must be an ancestor of the head
            if let Some(prior) = &cosign.prior_head_digest_sha256_hex {
                let head_pos = held_versions
                    .iter()
                    .position(|(d, _)| d == &cosign.head_digest_sha256_hex)
                    .unwrap_or(0);
                let prior_pos = held_versions.iter().position(|(d, _)| d == prior);
                if let Some(pp) = prior_pos {
                    if pp > head_pos {
                        return refused(LineageCosignRefusal::PriorNotAncestor);
                    }
                }
                // an unknown prior is stored: it may be the other head of an
                // equivocation this node has not seen (evidence), or a version
                // not yet received.
            }
            LineageCosignOutcome::Inserted
        }
    };
    let inserted = directory.store_lineage_head_cosign(cosign).await?;
    Ok(if inserted {
        outcome
    } else {
        LineageCosignOutcome::Unchanged
    })
}

/// `witnessed(head)` — at least `quorum` admitted cosigns for `head_digest`
/// from DISTINCT witnesses, none of which is in `founders` (FSD §3.2). Pure.
pub fn witnessed(
    cosigns: &[LineageHeadCosign],
    head_digest: &str,
    founders: &[String],
    quorum: u32,
) -> bool {
    let mut distinct: Vec<&str> = cosigns
        .iter()
        .filter(|c| c.head_digest_sha256_hex == head_digest)
        .filter(|c| !founders.iter().any(|f| f == &c.witness_key_id))
        .map(|c| c.witness_key_id.as_str())
        .collect();
    distinct.sort_unstable();
    distinct.dedup();
    distinct.len() as u32 >= quorum.max(1)
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

    /// Witnessed counts DISTINCT non-founder witnesses against the quorum.
    #[test]
    fn witnessed_counts_distinct_independent_witnesses() {
        let founders = vec!["f1".to_string(), "f2".to_string()];
        let cs = vec![
            cosign("h", "w1"),
            cosign("h", "w1"),
            cosign("h", "f1"),
            cosign("g", "w2"),
        ];
        assert!(witnessed(&cs, "h", &founders, 1));
        assert!(
            !witnessed(&cs, "h", &founders, 2),
            "one distinct independent witness"
        );
        assert!(witnessed(&cs, "g", &founders, 1), "w2 witnesses g");
        let only_founder = vec![cosign("h", "f1"), cosign("h", "f2")];
        assert!(
            !witnessed(&only_founder, "h", &founders, 1),
            "a lineage witnessed solely by its founders is unwitnessed"
        );
        assert!(witnessed(&cs, "h", &founders, 0), "quorum 0 reads as 1");
    }
}
