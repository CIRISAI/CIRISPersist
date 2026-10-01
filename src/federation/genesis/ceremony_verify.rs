//! CIRISPersist#973 — **verify a ceremony's two outputs offline, before they
//! are baked.**
//!
//! A re-mint ceremony hands persist two files: the bundle
//! (`canonical_seed.json`'s shape) and the community birth
//! (`canonical_community_seed.json`'s shape). Baking them is a compile-in, so
//! a file that the boot path would refuse must be caught BEFORE the bake —
//! afterwards every node of the release simply reports the leg absent.
//!
//! [`verify_ceremony_outputs`] does not re-implement a single rule. It stands
//! up a throwaway in-memory directory holding only what a fresh node holds
//! (this build's accord holders and the accord family), and applies the two
//! files through the ORDINARY doors: [`bake_assembled_genesis`](super::bake_assembled_genesis)
//! for the bundle (holder quorum, serve-node conferral, every delegation-row
//! gate) and the signed `put_community` door for the birth (signature,
//! trust-root shape, founder eligibility, accord quorum, the founding rule
//! and the node seat). A refusal is reported by the stage it came from, with
//! the door's own words.

use super::{BakeItemOutcome, GenesisBundle};
use crate::federation::{FederationDirectory as _, SignedCommunity};

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

/// **Verify a ceremony's bundle and community birth** against this build's
/// accord roster, through the ordinary doors, on a throwaway in-memory
/// directory. Nothing outside that directory is read or written.
///
/// # Errors
///
/// [`CeremonyOutputsRefused`] naming the stage; see the module doc.
pub async fn verify_ceremony_outputs(
    bundle_json: &str,
    community_json: &str,
) -> Result<CeremonyOutputsVerified, CeremonyOutputsRefused> {
    use CeremonyOutputsRefusal as R;
    let bundle: GenesisBundle = super::parse_genesis_bundle(bundle_json)
        .map_err(|e| refused(R::Malformed, format!("bundle: {e}")))?;
    let community: SignedCommunity = serde_json::from_str(community_json)
        .map_err(|e| refused(R::Malformed, format!("community: {e}")))?;

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
