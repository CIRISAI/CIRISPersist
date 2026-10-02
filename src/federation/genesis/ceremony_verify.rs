//! CIRISPersist#973 — **verify a ceremony's output offline, before it is
//! baked.**
//!
//! A re-mint ceremony hands persist one file: the bundle
//! (`canonical_seed.json`'s shape). v53.0.0 (CC rc7, T5): the bundle is the
//! only genesis artifact; the accord family's genesis record and the
//! `ciris-canonical` birth are members of it, pinned by its fingerprint.
//! Baking it is a compile-in, so a file that the boot path would refuse must
//! be caught BEFORE the bake — afterwards every node of the release simply
//! reports the leg absent.
//!
//! [`verify_ceremony_outputs`] does not re-implement a single rule. It stands
//! up a throwaway in-memory directory holding only what a fresh node holds
//! (this build's accord holders and the accord family), and applies the two
//! bundle through the ORDINARY doors: [`bake_assembled_genesis`](super::bake_assembled_genesis)
//! for the bundle (holder quorum, serve-node conferral, every delegation-row
//! gate) and the signed `put_community` door for the birth it carries
//! (signature, trust-root shape, founder eligibility, accord quorum, the
//! founding rule and the node seat). The accord family's record is checked
//! against the family this build seeds and against every holder's signature.
//! A refusal is reported by the stage it came from, with the door's own words.

use super::{BakeItemOutcome, GenesisBundle};
use crate::federation::FederationDirectory as _;

/// Which stage refused. The wire token is [`Self::as_str`].
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CeremonyOutputsRefusal {
    /// A file does not parse as its shape.
    Malformed,
    /// The bundle's carried holders are not this build's accord roster.
    HolderRosterMismatch,
    /// The holders' authorizations do not reach the quorum.
    BundleQuorum,
    /// The bake door refused the bundle outright.
    BundleBake,
    /// A serve-node record was not anchored.
    ServeNode,
    /// A delegation row was not installed.
    DelegationRow,
    /// v53.0.0 — the bundle carries no accord family record, one that is not
    /// the family this build seeds, or one a holder did not sign.
    FamilyRecord,
    /// The signed community door refused the birth (signature, shape,
    /// founder eligibility, quorum, founding rule or node seat — the detail
    /// carries the door's rule).
    CommunityBirth,
    /// The birth was admitted but the community does not resolve live.
    CommunityNotLive,
}

impl CeremonyOutputsRefusal {
    /// The stable token.
    #[must_use]
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Malformed => "ceremony_outputs_malformed",
            Self::HolderRosterMismatch => "ceremony_holder_roster_mismatch",
            Self::BundleQuorum => "ceremony_bundle_quorum",
            Self::BundleBake => "ceremony_bundle_bake",
            Self::ServeNode => "ceremony_serve_node",
            Self::DelegationRow => "ceremony_delegation_row",
            Self::FamilyRecord => "ceremony_family_record",
            Self::CommunityBirth => "ceremony_community_birth",
            Self::CommunityNotLive => "ceremony_community_not_live",
        }
    }
}

/// A refusal of [`verify_ceremony_outputs`]: the stage and the door's words.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CeremonyOutputsRefused {
    /// The stage.
    pub reason: CeremonyOutputsRefusal,
    /// What the door said.
    pub detail: String,
}

impl std::fmt::Display for CeremonyOutputsRefused {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}: {}", self.reason.as_str(), self.detail)
    }
}

impl std::error::Error for CeremonyOutputsRefused {}

fn refused(
    reason: CeremonyOutputsRefusal,
    detail: impl std::fmt::Display,
) -> CeremonyOutputsRefused {
    CeremonyOutputsRefused {
        reason,
        detail: detail.to_string(),
    }
}

/// What a verified pair of outputs contains.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CeremonyOutputsVerified {
    /// Distinct holders whose authorizations verified.
    pub quorum_verified: usize,
    /// The serve nodes the bundle anchors.
    pub serve_nodes: Vec<String>,
    /// The delegation rows the bundle installs.
    pub attestations: Vec<String>,
    /// The community the birth founds.
    pub community_key_id: String,
    /// Its counted founders.
    pub founders: usize,
}

/// **Verify a ceremony's bundle** — its delegation plane, the accord family
/// record and the community birth it carries — against this build's accord
/// roster, through the ordinary doors, on a throwaway in-memory directory.
/// Nothing outside that directory is read or written.
///
/// # Errors
///
/// [`CeremonyOutputsRefused`] naming the stage; see the module doc.
pub async fn verify_ceremony_outputs(
    bundle_json: &str,
) -> Result<CeremonyOutputsVerified, CeremonyOutputsRefused> {
    use CeremonyOutputsRefusal as R;
    let bundle: GenesisBundle = super::parse_genesis_bundle(bundle_json)
        .map_err(|e| refused(R::Malformed, format!("bundle: {e}")))?;
    let community = bundle
        .community_record(crate::federation::canonical_community::CIRIS_CANONICAL_COMMUNITY_KEY_ID)
        .cloned()
        .ok_or_else(|| {
            refused(
                R::CommunityBirth,
                "the bundle carries no ciris-canonical birth record (CC rc7: the birth is a \
                 member of bundle.attestations)",
            )
        })?;

    // The carried holders must be this build's roster: same ids, same keys.
    let roster = super::effective_accord_holder_records();
    let pair = |r: &crate::federation::SignedKeyRecord| {
        (
            r.record.key_id.clone(),
            r.record.pubkey_ed25519_base64.clone(),
            r.record.pubkey_ml_dsa_65_base64.clone(),
        )
    };
    let want: std::collections::BTreeSet<_> = roster.iter().map(pair).collect();
    let got: std::collections::BTreeSet<_> = bundle.holders.iter().map(pair).collect();
    if want != got {
        return Err(refused(
            R::HolderRosterMismatch,
            format!(
                "the bundle carries holders {:?}; this build's accord roster is {:?}",
                got.iter().map(|p| &p.0).collect::<Vec<_>>(),
                want.iter().map(|p| &p.0).collect::<Vec<_>>()
            ),
        ));
    }

    check_family_record(&bundle, &roster).map_err(|d| refused(R::FamilyRecord, d))?;

    // A fresh node: the holders and the accord family, nothing else.
    let dir = crate::store::memory::MemoryBackend::new();
    dir.seed_genesis_accord_holders(&roster)
        .await
        .map_err(|e| refused(R::HolderRosterMismatch, format!("seed holders: {e}")))?;
    super::seed_accord_family(&dir).await.map_err(|e| {
        refused(
            R::HolderRosterMismatch,
            format!("seed accord family: {e:?}"),
        )
    })?;

    super::verify_bundle_quorum(&dir, &bundle)
        .await
        .map_err(|e| refused(R::BundleQuorum, e))?;
    let report = super::bake_assembled_genesis(&dir, bundle_json)
        .await
        .map_err(|e| refused(R::BundleBake, e))?;
    for (id, outcome) in &report.serve_nodes {
        if let BakeItemOutcome::Skipped(why) = outcome {
            return Err(refused(R::ServeNode, format!("{id}: {why}")));
        }
    }
    for (id, outcome) in &report.attestations {
        if let BakeItemOutcome::Skipped(why) = outcome {
            return Err(refused(R::DelegationRow, format!("{id}: {why}")));
        }
    }

    let id = community.community.community_key_id.clone();
    dir.put_community(community)
        .await
        .map_err(|e| refused(R::CommunityBirth, e))?;
    let resolved = crate::federation::canonical_community::resolve_community(&dir, &id)
        .await
        .map_err(|e| refused(R::CommunityNotLive, e))?
        .ok_or_else(|| refused(R::CommunityNotLive, format!("{id} does not resolve")))?;
    if !resolved.live {
        return Err(refused(
            R::CommunityNotLive,
            format!(
                "{id} resolves with live = false ({} founder(s) counted)",
                resolved.founders.len()
            ),
        ));
    }
    Ok(CeremonyOutputsVerified {
        quorum_verified: report.quorum_verified,
        serve_nodes: report.serve_nodes.into_iter().map(|(k, _)| k).collect(),
        attestations: report.attestations.into_iter().map(|(k, _)| k).collect(),
        community_key_id: id,
        founders: resolved.founders.len(),
    })
}

/// v53.0.0 (CC 3.2 T6) — the accord family's genesis record the bundle
/// carries is the family this build seeds ([`accord_family_genesis_record_for`](super::accord_family_genesis_record_for):
/// same founders, protocol, entrenchment and instant, naming the bundle's own
/// charter), signed over its signing
/// envelope by EVERY holder of this build's roster (the founding rule).
fn check_family_record(
    bundle: &GenesisBundle,
    roster: &[crate::federation::SignedKeyRecord],
) -> Result<(), String> {
    // The family this build seeds, naming THIS bundle's charter (never the
    // compiled bundle's: the bundle under verification is not yet baked).
    let expected = super::accord_family_genesis_record_for(
        ciris_verify_core::accord_genesis::HUMANITY_ACCORD_FAMILY_KEY_ID,
        ciris_verify_core::accord_genesis::ACCORD_CONSENSUS_PROTOCOL,
        roster.iter().map(|r| r.record.key_id.as_str()),
        &super::bundle_family_charter_digest(bundle),
    );
    let carried = bundle
        .family_record(&expected.family_key_id)
        .ok_or_else(|| {
            format!(
                "the bundle carries no {} family record (CC rc7: the family's genesis head is a \
                 member of bundle.attestations)",
                expected.family_key_id
            )
        })?;
    if carried.family.signing_envelope() != expected.signing_envelope() {
        return Err(format!(
            "the carried {} record is not the family this build seeds",
            expected.family_key_id
        ));
    }
    let bytes =
        crate::verify::canonical::ceg_produce_canonicalize(&carried.family.signing_envelope())
            .map_err(|e| format!("canonicalize the family record: {e}"))?;
    let mut signed = std::collections::BTreeSet::new();
    let sigs = std::iter::once((
        carried.authority_key_id.as_str(),
        carried.scrub_signature_classical.as_str(),
        carried.scrub_signature_pqc.as_deref(),
    ))
    .chain(carried.cosignatures.iter().map(|c| {
        (
            c.authority_key_id.as_str(),
            c.scrub_signature_classical.as_str(),
            c.scrub_signature_pqc.as_deref(),
        )
    }));
    for (who, classical, pqc) in sigs {
        let holder = roster
            .iter()
            .find(|r| r.record.key_id == who)
            .ok_or_else(|| format!("{who} signed the family record and is not a holder"))?;
        crate::verify::hybrid::verify_hybrid(
            &bytes,
            classical,
            pqc,
            &holder.record.pubkey_ed25519_base64,
            holder.record.pubkey_ml_dsa_65_base64.as_deref(),
            crate::verify::hybrid::HybridPolicy::Strict,
            None,
        )
        .map_err(|e| format!("{who}'s signature over the family record: {e}"))?;
        signed.insert(who);
    }
    let missing: Vec<&str> = roster
        .iter()
        .map(|r| r.record.key_id.as_str())
        .filter(|k| !signed.contains(k))
        .collect();
    if !missing.is_empty() {
        return Err(format!(
            "the family record lacks the founding signature of {missing:?} (every holder signs \
             the genesis head)"
        ));
    }
    Ok(())
}
