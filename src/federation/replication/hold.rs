//! CIRISPersist#846 (`FSD/BLOB_REPLICATION.md` §4, §5) — **the decision to
//! hold, and the one classification of proxy content.**
//!
//! Two predicates live here and nowhere else:
//!
//! - [`is_proxy_content`] — *is this row held for others?* Read by the
//!   force-evict sweep, the serve refusal and the accept decision, so the
//!   three agree by construction (I49). It used to be three copies keyed on
//!   the `holds_bytes` ATTESTER, which for anything a node adopts is the node
//!   itself — every relayed blob classified as protected.
//! - [`would_hold`] — *WILL this node hold content it MAY hold, now?* The
//!   accept rule every consumer-reachable accept door runs (I46). Its
//!   refusals are typed, name the axis, and disclose nothing about the
//!   content.
//!
//! # Persist never stores data this node is not party to
//!
//! "Party to" means: this node is in a cohort that may access the
//! attestation granting possession and view of the blob — its own or its
//! family's content, a community it is an active member of, or the commons
//! (everyone). Every blob a node holds is therefore one it could open and
//! inspect, which is how a host avoids holding illegal or immoral content
//! unknowingly (CC 4.4.3.2.1). There is **no relay exception and no
//! serve-role exception**: a "server" is not a node that holds non-party
//! content, it is a node that holds content it *is* party to but did not
//! create and does not itself need, so other cohort members can fetch it.
//! Serve standing therefore governs the BREADTH of holding
//! ([`HoldBreadth`]), never permission to accept.
//!
//! Persist's docs claim exactly the two privacy properties CC 1.13.3 names —
//! content-holding confidentiality and cohort-scoped visibility — and no
//! more (I53).

use std::collections::HashSet;

use crate::federation::replication::disk_pressure::DiskPressureSnapshot;
use crate::federation::types::cohort_scope::{self as cs, CryptoTier};
use crate::federation::{BlobError, Error, FederationDirectory};

/// #846 (§6.1) — what a caller declares about a sealed blob it received:
/// the facts the holder plane keeps or evicts on, read off the referencing
/// attestation (never the bytes, never the sender's word).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct BlobProvenance {
    /// The `attesting_key_id` of the attestation the blob is a projection
    /// of — the AUTHOR, recorded on the row as `author_key_id` (§5).
    pub author_key_id: String,
    /// The cohort the attestation declares (§11.1 vocabulary).
    pub cohort_scope: String,
    /// The community for `community` / `affiliations`; the owner or family
    /// key for `self` / `family`; `None` for the commons.
    pub community_key_id: Option<String>,
    /// The `(community, epoch)` the bytes were sealed under, for a
    /// `CommunityDek` blob. May be past; may be an epoch this node holds
    /// no key state for (§3).
    pub epoch: Option<u64>,
    /// The tier the bytes are AT: what the row records and reads dispatch
    /// on (I2). `Plaintext` provenance is refused by the adopt doors — that
    /// is `put_blob`'s job.
    pub tier: CryptoTier,
    /// v46.0.0 (CIRISPersist#876, `FSD/EPOCH_MINTER.md`) — **the key whose
    /// cascade MINTED the epoch**: the key that signed the `key_grant` set,
    /// which is the sealing node, not necessarily the row's author. `None`
    /// means "derive it" — from the one admitted set that granted this node
    /// a wrap at `(community, epoch)`, else from `author_key_id`.
    ///
    /// Before v46 this was inferred from [`Self::author_key_id`] on the
    /// premise that the author's cascade minted the epoch; that holds only
    /// where the author IS the sealing engine, and a chat row is authored
    /// by a person and sealed by their node.
    pub minter_key_id: Option<String>,
}

/// #846 (§4) — how WIDELY this node holds within the cohorts it is party
/// to. Derived from serve standing; it refuses nothing.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum HoldBreadth {
    /// No serve standing: hold what this node itself reads.
    OnDemand,
    /// `ServeTier::MeshServer` or above: hold everything the cohort may
    /// access, so other members can fetch it from here.
    ForCohort,
}

impl HoldBreadth {
    /// Stable lower-case label.
    pub fn label(self) -> &'static str {
        match self {
            HoldBreadth::OnDemand => "on_demand",
            HoldBreadth::ForCohort => "for_cohort",
        }
    }
}

/// #846 (§5, I49) — **the one classification of proxy content.**
///
/// A row is PROXY when it is held for others: its author is neither this
/// node nor family. `None` — a pre-V144 row, or a commons chunk written by
/// the signer-less door — is *unknown*, and unknown classifies as proxy:
/// fail toward evictable, never toward protected. Non-party content is
/// never present (the accept door refuses it), so audience is not a term
/// here; it is [`would_hold`]'s.
///
/// The three sites — the force-evict sweep, `serve_blob_to_peer` and
/// [`would_hold`] — call this and nothing else; a from-disk gate holds it.
pub fn is_proxy_content(
    author_key_id: Option<&str>,
    is_local_or_family: impl Fn(&str) -> bool,
) -> bool {
    match author_key_id {
        None => true,
        Some(author) => !is_local_or_family(author),
    }
}

/// #846 (§4) — the communities `our_key_id` is party to: those its
/// ACTIVE principal identity (or the key itself) is an active member of.
/// One directory walk per decision; the sweep reuses one set per cycle.
pub async fn audience_memberships<D>(
    directory: &D,
    our_key_id: &str,
) -> Result<HashSet<String>, Error>
where
    D: FederationDirectory + ?Sized,
{
    // v45.0.1 (CIRISPersist#873, `FSD/OCCURRENCE_PRINCIPAL.md` §3) — EVERY
    // principal, plus the node's own key: a shared device is party to both
    // humans' rooms, and the node's own memberships were always its own.
    let mut keys = directory
        .active_identities_for_occurrence(our_key_id)
        .await?;
    keys.push(our_key_id.to_owned());
    let mut out = HashSet::new();
    for key in keys {
        for c in directory.list_communities_for_member_active(&key).await? {
            out.insert(c.community_key_id);
        }
    }
    Ok(out)
}

/// #846 (§4) — the pure core of [`is_audience`]: is a node whose active
/// community memberships are `member_communities` party to content at
/// `cohort_scope` / `community_key_id`?
///
/// - `self` / `family`: iff the author is local-or-family (the content is
///   ours or our family's).
/// - `community` / `affiliations`: iff this node is an active member of the
///   named community. An unnamed community is nobody's.
/// - the commons (`species` / `biosphere` / `federation`): everyone — the
///   bytes are plaintext and the holder inspects them (CC 4.4.3.2.1).
/// - anything else: no (fail closed).
pub fn is_audience_of(
    cohort_scope: &str,
    community_key_id: Option<&str>,
    author_is_local_or_family: bool,
    member_communities: &HashSet<String>,
) -> bool {
    match cohort_scope {
        cs::SELF | cs::FAMILY => author_is_local_or_family,
        cs::COMMUNITY | cs::AFFILIATIONS => {
            community_key_id.is_some_and(|c| member_communities.contains(c))
        }
        cs::SPECIES | cs::BIOSPHERE | cs::FEDERATION => true,
        _ => false,
    }
}

/// #846 (§4) — is this node PARTY TO content at `cohort_scope` authored by
/// `author_key_id`? Asked of persist's own rosters, so the sender cannot
/// assert it. See [`is_audience_of`] for the arms.
pub async fn is_audience<D>(
    directory: &D,
    cohort_scope: &str,
    community_key_id: Option<&str>,
    author_key_id: &str,
    is_local_or_family: impl Fn(&str) -> bool,
    our_key_id: &str,
) -> Result<bool, Error>
where
    D: FederationDirectory + ?Sized,
{
    let author_local = is_local_or_family(author_key_id);
    // Only the community arms need the walk; do not pay for it otherwise.
    let members = match cohort_scope {
        cs::COMMUNITY | cs::AFFILIATIONS => audience_memberships(directory, our_key_id).await?,
        _ => HashSet::new(),
    };
    Ok(is_audience_of(
        cohort_scope,
        community_key_id,
        author_local,
        &members,
    ))
}

/// #846 (§4) — what [`would_hold`] decides against: the cached pressure
/// snapshot, the local-or-family predicate, and this node's own derived key.
/// The Engine builds it; the invariant harness builds one per case.
pub struct HoldContext<'a, F: Fn(&str) -> bool> {
    /// The cached [`DiskPressureSnapshot`] (#149): no statvfs per decision.
    pub pressure: DiskPressureSnapshot,
    /// Local-or-family, against this node's DERIVED key and the operator's
    /// family predicate.
    pub is_local_or_family: F,
    /// This node's derived federation key id (I23).
    pub our_key_id: &'a str,
}

/// #846 (§4, §6.3, I46/I47/I48) — **the WILL decision.** Given content this
/// node MAY hold (Edge's `admit_blob_store` decided that before the bytes
/// moved), does it hold it *now*, on *this* node?
///
/// 1. A local or family author is held **always** — "don't block local
///    writes ever" (#149).
/// 2. Content this node is **not party to** is refused
///    [`BlobError::NotPartyTo`], whatever its serve standing: persist never
///    stores data it could not open and inspect. Checked before pressure,
///    because it is the permanent reason and pressure is the transient one.
/// 3. At `Stop` pressure and tighter, content held for others is refused
///    [`BlobError::DiskPressureProxyRefused`] `{ operation: "accept" }`.
/// 4. Otherwise: hold.
///
/// Serve standing is **not consulted** — it governs breadth
/// ([`HoldBreadth`]), never acceptance; a from-disk gate holds that this
/// function names no serve tier. Cheap: one cached snapshot, one directory
/// walk for the community arms. Writes nothing.
pub async fn would_hold<D, F>(
    directory: &D,
    ctx: &HoldContext<'_, F>,
    provenance: &BlobProvenance,
) -> Result<(), BlobError>
where
    D: FederationDirectory + ?Sized,
    F: Fn(&str) -> bool,
{
    if !is_proxy_content(Some(&provenance.author_key_id), &ctx.is_local_or_family) {
        return Ok(());
    }
    let party = is_audience(
        directory,
        &provenance.cohort_scope,
        provenance.community_key_id.as_deref(),
        &provenance.author_key_id,
        &ctx.is_local_or_family,
        ctx.our_key_id,
    )
    .await
    .map_err(|e| BlobError::Backend(format!("would_hold: audience walk: {e} ({})", e.kind())))?;
    if !party {
        return Err(BlobError::NotPartyTo {
            cohort_scope: provenance.cohort_scope.clone(),
            community_key_id: provenance.community_key_id.clone(),
        });
    }
    if ctx.pressure.refuses_proxy_writes {
        return Err(BlobError::DiskPressureProxyRefused {
            operation: "accept",
            tier: ctx.pressure.tier.label(),
        });
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn set(items: &[&str]) -> HashSet<String> {
        items.iter().map(|s| (*s).to_owned()).collect()
    }

    // ── I49: the predicate ───────────────────────────────────────────────
    #[test]
    fn a_null_author_is_proxy() {
        assert!(is_proxy_content(None, |_| true));
    }

    #[test]
    fn a_local_or_family_author_is_protected_and_anyone_else_is_proxy() {
        let local = |k: &str| k == "me" || k == "fam";
        assert!(!is_proxy_content(Some("me"), local));
        assert!(!is_proxy_content(Some("fam"), local));
        assert!(is_proxy_content(Some("stranger"), local));
    }

    // ── §4: each arm of the audience rule ────────────────────────────────
    #[test]
    fn self_and_family_are_audience_iff_the_author_is_local_or_family() {
        let none = HashSet::new();
        for scope in [cs::SELF, cs::FAMILY] {
            assert!(is_audience_of(scope, None, true, &none), "{scope}");
            assert!(!is_audience_of(scope, None, false, &none), "{scope}");
            // membership of a community is irrelevant here
            assert!(
                !is_audience_of(scope, Some("c"), false, &set(&["c"])),
                "{scope}"
            );
        }
    }

    #[test]
    fn community_and_affiliations_are_audience_iff_an_active_member() {
        let members = set(&["c1"]);
        for scope in [cs::COMMUNITY, cs::AFFILIATIONS] {
            assert!(
                is_audience_of(scope, Some("c1"), false, &members),
                "{scope}"
            );
            assert!(
                !is_audience_of(scope, Some("c2"), false, &members),
                "{scope}"
            );
            // a local author does not make a non-member party to a community
            assert!(
                !is_audience_of(scope, Some("c2"), true, &members),
                "{scope}"
            );
            // an unnamed community is nobody's
            assert!(!is_audience_of(scope, None, false, &members), "{scope}");
        }
    }

    #[test]
    fn the_commons_are_everyones() {
        let none = HashSet::new();
        for scope in [cs::SPECIES, cs::BIOSPHERE, cs::FEDERATION] {
            assert!(is_audience_of(scope, None, false, &none), "{scope}");
        }
    }

    #[test]
    fn an_unknown_scope_is_nobodys() {
        assert!(!is_audience_of("galaxy", None, true, &set(&["c"])));
    }
}
