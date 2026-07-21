//! v18.2.0 (CIRISPersist#481) — the pluggable-trust-root graph predicate.
//!
//! Substrate half of CIRISServer's `FSD/TRUST_ROOT_CAPABILITY_GATE.md`
//! (CC ratification: CIRISConstitution#40). Trust is a layered graph of
//! plain `attestation` / `delegates_to` objects — **no new object kind**:
//!
//! - **Self-root base**: `attestation(user → user)` — the immutable
//!   identity floor. Ordinary self-attestation; nothing here touches it.
//! - **Root self-declaration**: `delegates_to(root → root,
//!   scope:[infra:attest, infra:serve])` — a root roots to itself; the
//!   self-loop IS what makes it a root.
//! - **The trust edge**: `delegates_to(user → root)` — the user's chosen,
//!   consensual delegation. Un-trust is the `withdraws` composer on that
//!   edge (the CEG tombstone; the walk folds it as ABSENT).
//!
//! [`trust_root_valid`] is the **pure graph predicate** the FSD demands —
//! "never a client assertion, never a cached flag". It lives in persist so
//! server / edge / agent share ONE implementation (the single-authority
//! discipline; edge reaches it via the directory capsule op).
//!
//! # The two trust planes (do not conflate)
//!
//! `infra:attest` here is a **delegation SCOPE token inside a
//! `delegates_to` envelope** — the user's consensual choice of what a root
//! may do for them. It is NOT the accord-conferred `infra:attest` **role**
//! on a `federation_keys` row (the v15.0.0 build-manifest trust root),
//! which remains gated by the accord co-scrub at every key-admission
//! chokepoint. A self-declared root confers capability only over users who
//! signed an edge to it; it gains NO standing in the accord role plane.

use super::precedence;
use super::types::{attestation_type, Attestation};
use super::{Error, FederationDirectory};

/// The `accord:lifecycle` freshness window (days). FSD
/// `TRUST_ROOT_CAPABILITY_GATE.md` §2 item 2 pins "≤90-day refresh" per
/// CC; the exact number is CC#40-ratification-tracked — re-pin on ruling.
pub const ACCORD_LIFECYCLE_FRESHNESS_DAYS: i64 = 90;

/// Dimension a root's liveness attestation carries. Versioned per the
/// mechanism-descriptive dimension rule (the #102 four-test gate requires a
/// version segment); the exact token is CC#40-ratification-tracked.
pub const ACCORD_LIFECYCLE_DIMENSION: &str = "accord:lifecycle:v1";

/// The delegation scope tokens a root self-declaration must carry (either
/// suffices; the FSD names both on the canonical shape).
pub const INFRA_ATTEST_SCOPE: &str = "infra:attest";
/// See [`INFRA_ATTEST_SCOPE`].
pub const INFRA_SERVE_SCOPE: &str = "infra:serve";

/// The typed, per-check verdict of [`trust_root_valid`].
///
/// Open accounting, not a bare bool (the derivation-trace discipline): a
/// consumer gates on [`Self::valid`] but can SEE which leg failed and
/// surface the right remediation ("attach a root" vs "root lifecycle
/// stale" vs "halt latched").
#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub struct TrustRootVerdict {
    /// A live (non-tombstoned) `delegates_to(user → root)` edge exists
    /// with `root != user` — the FSD's "NOT the base self-root" rule.
    pub edge_exists: bool,
    /// `root` carries a live self-referential `delegates_to(root → root)`
    /// whose envelope `scope` includes `infra:attest` / `infra:serve`.
    pub root_self_declares: bool,
    /// A live `accord:lifecycle` attestation about `root` is within the
    /// freshness window ([`ACCORD_LIFECYCLE_FRESHNESS_DAYS`]).
    pub lifecycle_active: bool,
    /// The accord halt latch for `root` (keyed as the halt-table family
    /// id): `Some(true)` = a halt is latched (brake pulled); `Some(false)`
    /// = present-and-clear; `None` = this backend cannot answer
    /// (halt storage unsupported) — reported honestly, never guessed.
    pub halt_latched: Option<bool>,
    /// The gate: every leg holds and no halt is latched.
    pub valid: bool,
}

/// Does `token` appear in the envelope's `scope` field? Accepts the two
/// established wire shapes (`topology.rs` convention): a bare string or an
/// array of tokens.
fn scope_contains(envelope: &serde_json::Value, token: &str) -> bool {
    match envelope.get("scope") {
        Some(serde_json::Value::String(s)) => s == token,
        Some(serde_json::Value::Array(items)) => items.iter().any(|v| v.as_str() == Some(token)),
        _ => false,
    }
}

/// Fold the CEG tombstones over `rows`: an attestation is DEAD when a
/// `withdraws` / `recants` composer (precedence-winning, same-attester
/// authority is enforced at composer admission) references its id.
/// Returns the set of dead `attestation_id`s.
fn tombstoned_ids(rows: &[&Attestation]) -> std::collections::HashSet<String> {
    use std::collections::HashMap;
    let mut by_target: HashMap<&str, Vec<&Attestation>> = HashMap::new();
    for row in rows {
        if precedence::is_structural_composer(&row.attestation_type) {
            if let Some(target) =
                precedence::references_attestation_id_from_envelope(&row.attestation_envelope)
            {
                by_target.entry(target).or_default().push(row);
            }
        }
    }
    let mut dead = std::collections::HashSet::new();
    for (target, composers) in by_target {
        if let Some(winner) = precedence::precedence_winner(&composers) {
            if winner.attestation_type == attestation_type::WITHDRAWS
                || winner.attestation_type == attestation_type::RECANTS
            {
                dead.insert(target.to_owned());
            }
        }
    }
    dead
}

/// v18.2.0 (CIRISPersist#481) — the trust-root graph predicate.
///
/// Evaluates, purely from graph state (FSD `TRUST_ROOT_CAPABILITY_GATE.md`
/// §2):
/// 1. a live `delegates_to(user → root)` edge exists, `root != user`;
/// 2. `root` self-declares (`delegates_to(root → root)` with an
///    `infra:attest` / `infra:serve` scope), live;
/// 3. a live `accord:lifecycle` attestation about `root` is fresh
///    (≤ [`ACCORD_LIFECYCLE_FRESHNESS_DAYS`]);
/// 4. no accord halt is latched for `root`.
///
/// The rooting-chain leg (FSD §2 item 2's "chain from this node's records
/// roots to it") stays with the existing [`super::rooting`] /
/// `has_effective_role` walks — this predicate composes beside them, it
/// does not re-derive them.
pub async fn trust_root_valid<F>(
    directory: &F,
    user_key_id: &str,
    root_key_id: &str,
) -> Result<TrustRootVerdict, Error>
where
    F: FederationDirectory + ?Sized,
{
    // A self-root is the immutable BASE, never a valid EXTERNAL root (the
    // FSD's gate demands a SHARED external root).
    if user_key_id == root_key_id {
        return Ok(TrustRootVerdict {
            edge_exists: false,
            root_self_declares: false,
            lifecycle_active: false,
            halt_latched: None,
            valid: false,
        });
    }

    // One read per authority: everything the user attested (edges + their
    // tombstones — a withdraws on your own edge is attested by YOU), and
    // everything attested about/by the root (self-declaration + its
    // tombstones + lifecycle rows).
    let by_user = directory.list_attestations_by(user_key_id).await?;
    let by_root = directory.list_attestations_by(root_key_id).await?;
    let about_root = directory.list_attestations_for(root_key_id).await?;

    // 1. Edge: live delegates_to(user → root).
    let user_refs: Vec<&Attestation> = by_user.iter().collect();
    let user_dead = tombstoned_ids(&user_refs);
    let edge_exists = by_user.iter().any(|a| {
        a.attestation_type == attestation_type::DELEGATES_TO
            && a.attested_key_id == root_key_id
            && !user_dead.contains(&a.attestation_id)
    });

    // 2. Self-declaration: live delegates_to(root → root) with infra scope.
    let root_refs: Vec<&Attestation> = by_root.iter().collect();
    let root_dead = tombstoned_ids(&root_refs);
    let root_self_declares = by_root.iter().any(|a| {
        a.attestation_type == attestation_type::DELEGATES_TO
            && a.attested_key_id == root_key_id
            && !root_dead.contains(&a.attestation_id)
            && (scope_contains(&a.attestation_envelope, INFRA_ATTEST_SCOPE)
                || scope_contains(&a.attestation_envelope, INFRA_SERVE_SCOPE))
    });

    // 3. Lifecycle: newest live accord:lifecycle row about the root within
    // the freshness window. Tombstones for rows-about-root can come from
    // their own attesters; fold over the about-set (composers reference
    // the target id and carry the same attested key).
    let about_refs: Vec<&Attestation> = about_root.iter().collect();
    let about_dead = tombstoned_ids(&about_refs);
    let now = chrono::Utc::now();
    let window = chrono::Duration::days(ACCORD_LIFECYCLE_FRESHNESS_DAYS);
    let lifecycle_active = about_root.iter().any(|a| {
        a.attestation_type == attestation_type::SCORES
            && super::admission::envelope_dimension(&a.attestation_envelope)
                == Some(ACCORD_LIFECYCLE_DIMENSION)
            && !about_dead.contains(&a.attestation_id)
            && now.signed_duration_since(a.asserted_at) <= window
    });

    // 4. Halt latch (kill-switch state). Unsupported backends report None
    // — honestly unknown, never guessed.
    let halt_latched = match directory.get_active_halt(root_key_id).await {
        Ok(v) => Some(v.is_some()),
        Err(Error::Unsupported { .. }) => None,
        Err(e) => return Err(e),
    };

    let valid = edge_exists && root_self_declares && lifecycle_active && halt_latched != Some(true);

    Ok(TrustRootVerdict {
        edge_exists,
        root_self_declares,
        lifecycle_active,
        halt_latched,
        valid,
    })
}
