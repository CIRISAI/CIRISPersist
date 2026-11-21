//! #302 (FSD-004) — accord live-quorum storage substrate.
//!
//! The durable half of the constitutional kill-switch's decimation-recovery
//! live quorum. CIRISVerify ships the **stateless** machinery in
//! [`ciris_verify_core::accord_live_quorum`] (CIRISVerify#150 / #98); the
//! CIRISServer Phase-3 runtime (CIRISServer#122) drives it and writes the
//! wire objects + anti-replay state **through** persist. Persist is the
//! storage substrate, so the tables are ours (V091) — the live-quorum
//! sibling of the `federation_keys` accord-holder storage.
//!
//! Division of labour (from #302): **persist stores + dedups + verifies
//! participations + holds nonce/halt state; the SERVER runs the tally**
//! (`verify_fire_by_live_quorum` etc. re-verify every participation at tally
//! time — persist stores the inputs + the server's frozen `AccordDecision`).
//!
//! Load-bearing rule: store the verify-core canonical objects **verbatim**
//! and DERIVE the indexed columns from them via verify-core
//! ([`AccordProposal::digest`] etc.) — never trust a caller-supplied digest,
//! never re-derive the bytes by hand.
//!
//! **Recovery (`verify_recovery_supersede`, H7) is deliberately absent** —
//! it bends entrenchment for the captured-roster case and cannot go live
//! until the CIRIS Constitution sanctions it (CIRISAccord#4). This module
//! handles `fire` / `roster_change` / `resume` only.

use chrono::{DateTime, Utc};
use sha2::Digest as _;

// ─────────────────────────────────────────────────────────────────────
// v62.0.0 (VA-quorum; CIRISVerify 23.3.3 removes `accord_live_quorum`) —
// the earlier accord-quorum objects, as an upgraded store holds them and the
// retired capsule ops carry them. SERDE-IDENTICAL stand-ins for Verify's
// `accord_live_quorum::{AccordAction, Vote, AccordProposal,
// AccordParticipation, AccordDecision}` and `threshold::ThresholdSignature`
// (CIRISVerify v23.3.2 `accord_live_quorum.rs` l.118–245 and l.1737,
// `threshold.rs` l.125–136): the same field names, order, serde
// attributes and enum spellings, so every held `*_json` and every op an old
// consumer sends decodes unchanged. Pinned by `wire_tests` below. Nothing
// here verifies a signature: rc20 retired the participation verify and the
// tally with the write doors; the objects are read and relayed only.
// ─────────────────────────────────────────────────────────────────────

/// Domain prefix of [`AccordProposal::canonical_bytes`] (Verify's
/// `PROPOSAL_DOMAIN_PREFIX`).
pub const PROPOSAL_DOMAIN_PREFIX: &str = "ciris.accord_proposal.v1\n";

/// The action an accord proposal names (Verify's `AccordAction`).
#[derive(Debug, Clone, Copy, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum AccordAction {
    /// A roster change.
    RosterChange,
}

impl AccordAction {
    /// The wire spelling (`roster_change`).
    #[must_use]
    pub fn as_str(&self) -> &'static str {
        match self {
            Self::RosterChange => "roster_change",
        }
    }
}

/// A participation's vote (Verify's `Vote`).
#[derive(Debug, Clone, Copy, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum Vote {
    /// Yes.
    Yes,
    /// No.
    No,
    /// Abstain.
    Abstain,
}

/// One member's earlier-form threshold signature (Verify's
/// `threshold::ThresholdSignature`), carried verbatim and never verified.
#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub struct AccordSignature {
    /// The signing member.
    pub member_id: String,
    /// Ed25519 signature, base64 standard.
    pub ed25519_signature_base64: String,
    /// ML-DSA-65 signature, base64 standard, when present.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub mldsa65_signature_base64: Option<String>,
}

/// An earlier-form accord proposal (Verify's `AccordProposal`).
#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub struct AccordProposal {
    /// The accord family.
    pub family_key_id: String,
    /// The action.
    pub action: AccordAction,
    /// The proposal nonce.
    pub nonce: String,
    /// The voting window's end (RFC 3339).
    pub window_until: String,
    /// The prior family record's digest.
    pub prior_family_digest: String,
    /// The payload's SHA-256 (hex).
    pub payload_sha256: String,
}

impl AccordProposal {
    /// The proposal's canonical bytes, byte for byte Verify's.
    #[must_use]
    pub fn canonical_bytes(&self) -> Vec<u8> {
        format!(
            "{PROPOSAL_DOMAIN_PREFIX}family_key_id={fk}\naction={action}\nnonce={nonce}\nwindow_until={wu}\nprior_family_digest={pfd}\npayload_sha256={ph}",
            fk = self.family_key_id,
            action = self.action.as_str(),
            nonce = self.nonce,
            wu = self.window_until,
            pfd = self.prior_family_digest,
            ph = self.payload_sha256,
        )
        .into_bytes()
    }

    /// The proposal's content digest (lowercase hex SHA-256 of
    /// [`Self::canonical_bytes`]), as Verify's.
    #[must_use]
    pub fn digest(&self) -> String {
        hex::encode(sha2::Sha256::digest(self.canonical_bytes()))
    }
}

/// An earlier-form accord participation (Verify's `AccordParticipation`).
#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub struct AccordParticipation {
    /// The accord family.
    pub family_key_id: String,
    /// The proposal's digest.
    pub proposal_digest: String,
    /// The voting member.
    pub member_id: String,
    /// The vote.
    pub vote: Vote,
    /// The voting window's end.
    pub window_until: String,
    /// When the member signed (advisory).
    pub signed_at: String,
    /// The member's signature, carried verbatim.
    pub signature: AccordSignature,
}

/// An earlier-form frozen-L decision snapshot (Verify's `AccordDecision`).
#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub struct AccordDecision {
    /// The proposal decided.
    pub proposal: AccordProposal,
    /// The live set.
    pub live_set: Vec<String>,
    /// Yes votes.
    pub yes: usize,
    /// No votes.
    pub no: usize,
    /// Abstentions.
    pub abstain: usize,
    /// Whether the decision authorized the proposal.
    pub authorized: bool,
}

// v62.0.0 (JSON-cut slice F; CC rc20) — the prepared write columns, the
// participation verify and the nonce dedup are gone with the write doors:
// rc20 has no accord proposal, participation or decision object. The read
// row types below stay for what an upgraded store holds.

/// v54.1.0 (CIRISPersist#1042 follow-up C) — the stable refusal token of
/// [`crate::federation::Error::AccordProposalNonceReused`].
pub const ACCORD_PROPOSAL_NONCE_REUSED: &str = "accord_proposal_nonce_reused";

// ─────────────────────────────────────────────────────────────────────
// Read row types — what list/get return. The verbatim `*_json` round-trips
// back to the verify-core object for the server's tally.
// ─────────────────────────────────────────────────────────────────────

/// A stored `accord_proposal`: the verbatim verify-core object + the
/// server-supplied authority signature envelope.
#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct StoredProposal {
    /// The verbatim verify-core proposal (round-trips for the server tally).
    pub proposal: AccordProposal,
    /// The server-supplied authority-signature envelope, if any.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub authority_signature: Option<serde_json::Value>,
    /// Substrate row hash (canonical SHA-256 of the stored proposal).
    pub persist_row_hash: String,
    /// When persist admitted the proposal.
    pub created_at: DateTime<Utc>,
}

/// A stored `accord_participation`: the verbatim verify-core object + the
/// authoritative server-arrival instant (C2).
#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct StoredParticipation {
    /// The verbatim verify-core participation (incl. the hybrid signature).
    pub participation: AccordParticipation,
    /// The member's PINNED Ed25519 pubkey — the M6 dedup key.
    pub pinned_pubkey: String,
    /// The AUTHORITATIVE arrival instant persist stamped (C2 window clock);
    /// `participation.signed_at` is advisory only.
    pub server_arrival_at: DateTime<Utc>,
    /// Substrate row hash (canonical SHA-256 of the stored participation).
    pub persist_row_hash: String,
}

/// A stored `accord_decision`: the verbatim frozen-L snapshot.
#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct StoredDecision {
    /// The verbatim verify-core frozen-L decision snapshot (M2, immutable).
    pub decision: AccordDecision,
    /// Substrate row hash (canonical SHA-256 of the stored decision).
    pub persist_row_hash: String,
    /// When persist admitted the decision.
    pub decided_at: DateTime<Utc>,
}

/// The active CONSTITUTIONAL halt for a family (H2). `None` when no halt is
/// active (a resume cleared it).
#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub struct ActiveHalt {
    /// The accord family the halt applies to.
    pub family_key_id: String,
    /// The active CONSTITUTIONAL halt id (a resume binds `sha256(this)`).
    pub active_halt_id: String,
    /// When the halt became active.
    pub set_at: DateTime<Utc>,
}

/// v62.0.0 (VA-quorum) — the stand-ins' WIRE is Verify's: field names,
/// order, enum spellings and the optional ML-DSA half, as JSON literals
/// written from CIRISVerify v23.3.2's definitions; and the proposal digest
/// is Verify's canonical-bytes digest.
#[cfg(test)]
mod wire_tests {
    use super::*;

    fn proposal() -> AccordProposal {
        AccordProposal {
            family_key_id: "fam".into(),
            action: AccordAction::RosterChange,
            nonce: "n1".into(),
            window_until: "2026-11-20T00:00:00Z".into(),
            prior_family_digest: "aa".into(),
            payload_sha256: "bb".into(),
        }
    }

    /// I2170 (VA-quorum) — the proposal's wire and digest.
    #[test]
    fn i2170_proposal_wire_and_digest_are_verifys() {
        let p = proposal();
        let json = serde_json::to_string(&p).unwrap();
        assert_eq!(
            json,
            r#"{"family_key_id":"fam","action":"roster_change","nonce":"n1","window_until":"2026-11-20T00:00:00Z","prior_family_digest":"aa","payload_sha256":"bb"}"#,
            "I2170: the proposal's wire"
        );
        assert_eq!(serde_json::from_str::<AccordProposal>(&json).unwrap(), p);
        assert_eq!(
            p.digest(),
            PROPOSAL_DIGEST,
            "I2170: the digest over Verify's canonical bytes"
        );
    }

    /// The digest of [`proposal`]: SHA-256 over
    /// `ciris.accord_proposal.v1\nfamily_key_id=fam\naction=roster_change\nnonce=n1\n
    /// window_until=2026-11-20T00:00:00Z\nprior_family_digest=aa\npayload_sha256=bb`.
    const PROPOSAL_DIGEST: &str =
        "ac0fce92f00f01193314ae543cc154812c9ed726271750cc2616c65bbed317d1";

    /// I2171 (VA-quorum) — the participation and decision wire.
    #[test]
    fn i2171_participation_and_decision_wire_are_verifys() {
        let part = AccordParticipation {
            family_key_id: "fam".into(),
            proposal_digest: "d".into(),
            member_id: "m".into(),
            vote: Vote::Abstain,
            window_until: "w".into(),
            signed_at: "s".into(),
            signature: AccordSignature {
                member_id: "m".into(),
                ed25519_signature_base64: "e".into(),
                mldsa65_signature_base64: None,
            },
        };
        let json = serde_json::to_string(&part).unwrap();
        assert_eq!(
            json,
            r#"{"family_key_id":"fam","proposal_digest":"d","member_id":"m","vote":"abstain","window_until":"w","signed_at":"s","signature":{"member_id":"m","ed25519_signature_base64":"e"}}"#,
            "I2171: the participation's wire (no ML-DSA half: omitted)"
        );
        assert_eq!(
            serde_json::from_str::<AccordParticipation>(&json).unwrap(),
            part
        );
        let with_pq =
            r#"{"member_id":"m","ed25519_signature_base64":"e","mldsa65_signature_base64":"q"}"#;
        assert_eq!(
            serde_json::to_string(&serde_json::from_str::<AccordSignature>(with_pq).unwrap())
                .unwrap(),
            with_pq,
            "I2171: the ML-DSA half round-trips"
        );
        let d = AccordDecision {
            proposal: proposal(),
            live_set: vec!["m".into()],
            yes: 1,
            no: 0,
            abstain: 2,
            authorized: true,
        };
        let json = serde_json::to_value(&d).unwrap();
        let mut keys: Vec<String> = json.as_object().unwrap().keys().cloned().collect();
        keys.sort();
        assert_eq!(
            keys,
            vec!["abstain", "authorized", "live_set", "no", "proposal", "yes"],
            "I2171: the decision's members"
        );
        assert_eq!(serde_json::from_value::<AccordDecision>(json).unwrap(), d);
        for (v, w) in [(Vote::Yes, "\"yes\""), (Vote::No, "\"no\"")] {
            assert_eq!(
                serde_json::to_string(&v).unwrap(),
                w,
                "I2171: the vote spelling"
            );
        }
    }
}
