//! Federation directory aggregate-query types + builders (v2.7.0,
//! CIRISPersist#104).
//!
//! Three read-only aggregate queries that feed the CIRISAgent 2.10.0
//! Epistemic Commons Framework UI (CIRISAgent#800):
//!
//! 1. [`build_trust_topology`] — Trust-Topology graph (nodes + edges
//!    with `direct` / `delegated` / `adversarial` classification),
//!    derived by walking [`crate::federation::types::attestation_type`]
//!    rows on `federation_attestations` and resolving granter/grantee
//!    keys through [`crate::federation::FederationDirectory`].
//! 2. [`build_delegation_graph`] — BFS over `delegates_to:*`
//!    attestations from a root key, depth-bounded, with cycle
//!    detection and per-edge `withdraws` / `recants` annotation.
//! 3. [`AuditChainProof`] — genesis → trace-id audit-chain walk,
//!    composed at the PyO3 surface by routing through the per-backend
//!    [`crate::audit::AuditService`] (the audit walk is backend-local;
//!    the type lives here so all three #104 wire-shapes land in one
//!    module).
//!
//! # Why these don't live on the [`FederationDirectory`] trait
//!
//! The three aggregates compose on top of the trait's CRUD surface
//! ([`FederationDirectory::list_attestations_by`] /
//! [`FederationDirectory::list_attestations_for`] /
//! [`FederationDirectory::lookup_public_key`]) and the
//! [`crate::audit::AuditService`] surface. They don't add new
//! backend-level SQL; they're pure aggregations over what already
//! exists. Keeping them out of the trait surface preserves the
//! "persist exposes the edges, the consumer composes the traversal"
//! architectural invariant from
//! `docs/FEDERATION_DIRECTORY.md` §"Explicit non-goals" while still
//! giving CIRISAgent the three load-bearing wire shapes the
//! Epistemic Commons UI needs.

use std::collections::{HashMap, HashSet, VecDeque};

use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};

use super::admission::envelope_dimension;
use super::types::attestation_type;
use super::{Attestation, Error, FederationDirectory, KeyRecord};

// ─── 1. Trust topology ────────────────────────────────────────────

/// Filter for [`build_trust_topology`]. At least one of `granter_key`
/// or `grantee_key` MUST be set — the [`FederationDirectory`] trait
/// only exposes per-key attestation lookups
/// ([`FederationDirectory::list_attestations_by`] /
/// [`FederationDirectory::list_attestations_for`]), so a full
/// "enumerate everything" mode would force a schema-level scan we
/// don't want to surface on a UI hot path.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct FederationDirectoryFilter {
    /// Narrow to attestations issued by this key (the granter side
    /// of an edge — `attesting_key_id`).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub granter_key: Option<String>,
    /// Narrow to attestations targeting this key (the grantee side
    /// of an edge — `attested_key_id`).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub grantee_key: Option<String>,
    /// Narrow to attestations whose envelope `dimension` matches the
    /// given purpose (free-form string match on the envelope's
    /// `dimension` field; `None` admits any).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub purpose: Option<String>,
    /// Include edges that have been annulled by a `withdraws` /
    /// `recants` attestation. Default `false` filters them out.
    #[serde(default)]
    pub include_revoked: bool,
}

/// A trust-topology node — one `federation_keys` row resolved to its
/// public identity attributes. UI renders one of these per unique
/// granter/grantee in the topology.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TrustNode {
    /// Canonical `federation_keys.key_id`.
    pub key_id: String,
    /// `federation_keys.identity_type` (e.g. `agent`, `steward`,
    /// `accord_holder`). Empty string when the key is referenced by
    /// an attestation but not present in `federation_keys` (FK
    /// violations shouldn't happen — schema enforces them — but the
    /// projection is best-effort if a key was hard-deleted).
    pub identity_type: String,
    /// `federation_keys.identity_ref`. `None` for the same edge case
    /// (key referenced but absent).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub identity_ref: Option<String>,
}

/// A trust-topology edge — one `(granter, grantee)` direction with
/// the granter's scored attestation collapsed into a single edge.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TrustEdge {
    /// Source of the edge — the grantee (`attested_key_id`). UI
    /// renders this as the "from" end of the arrow.
    pub from_key: String,
    /// Destination of the edge — the granter (`attesting_key_id`).
    pub to_key: String,
    /// Envelope `dimension` (the closest analog persist has to a
    /// "purpose" on a `scores` attestation). Empty string when the
    /// attestation envelope has no `dimension` field.
    pub purpose: String,
    /// Scope qualifier — same as `purpose` today; reserved for the
    /// future split if FSD-002 separates dimension from sub-scope.
    pub scope: String,
    /// Sum of attestation `weight` values (defaulting `None`→`1.0`)
    /// across all matching `SCORES` rows for this `(granter, grantee,
    /// dimension)` triple. UI uses this for edge thickness.
    pub weight: f64,
    /// Edge-type classification — see [`EdgeType`].
    pub edge_type: EdgeType,
    /// `asserted_at` of the earliest matching `SCORES` row.
    pub granted_at: DateTime<Utc>,
    /// `revoked_at` from the matching `withdraws` / `recants` row, if
    /// any. Populated only when [`EdgeType::Adversarial`].
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub revoked_at: Option<DateTime<Utc>>,
}

/// Edge-type classification per CIRISPersist#104.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum EdgeType {
    /// No `delegates_to` step in the path — the granter scored the
    /// grantee directly.
    Direct,
    /// The granter received delegation (via a `delegates_to:*`
    /// attestation issued BY some third party TO the granter) before
    /// emitting this score. Surfaced as "indirect trust" in the UI.
    Delegated,
    /// A `withdraws` or `recants` row exists by the granter against
    /// the grantee — the edge is annulled. Filtered out by default;
    /// only surfaced when `include_revoked = true` on the filter.
    Adversarial,
}

/// Result of [`build_trust_topology`] — the nodes + edges the UI
/// renders. Both vectors are sorted lex-stably (`key_id` for nodes,
/// `(from_key, to_key, purpose)` for edges) so the JSON output is
/// byte-stable across calls.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TrustTopology {
    /// Unique nodes referenced by the edges, resolved through the
    /// federation directory.
    pub nodes: Vec<TrustNode>,
    /// Edges with their `edge_type` classification.
    pub edges: Vec<TrustEdge>,
}

/// Walk [`FederationDirectory`] to produce a [`TrustTopology`].
///
/// At least one of `filter.granter_key` / `filter.grantee_key` must
/// be set (see [`FederationDirectoryFilter`] doc-comment). Returns
/// [`Error::InvalidArgument`] otherwise.
///
/// # Algorithm
///
/// 1. Fetch attestations either by `granter_key` (via
///    [`FederationDirectory::list_attestations_by`]) or by
///    `grantee_key` (via [`FederationDirectory::list_attestations_for`]).
///    If both are set, the granter-side fetch is used and the
///    grantee filter is applied in-memory.
/// 2. Bucket by `(attesting_key_id, attested_key_id, dimension)`.
///    For each bucket, sum `weight` (defaulting `None`→`1.0`) and
///    take the earliest `asserted_at` as `granted_at`.
/// 3. Classify each bucket's [`EdgeType`]:
///    - Adversarial: any `withdraws` or `recants` row from
///      `attesting_key_id` targeting `attested_key_id`.
///    - Delegated: any `delegates_to` row TO `attesting_key_id` (the
///      granter received delegation from a third party).
///    - Direct: neither of the above.
/// 4. Resolve each distinct `key_id` to its [`TrustNode`] via
///    [`FederationDirectory::lookup_public_key`].
/// 5. Sort both vectors for stable JSON output.
pub async fn build_trust_topology(
    directory: &dyn FederationDirectory,
    filter: &FederationDirectoryFilter,
) -> Result<TrustTopology, Error> {
    if filter.granter_key.is_none() && filter.grantee_key.is_none() {
        return Err(Error::InvalidArgument(
            "FederationDirectoryFilter must set at least one of \
             granter_key or grantee_key"
                .into(),
        ));
    }

    // Step 1 — fetch attestations.
    let mut candidates: Vec<Attestation> = match (&filter.granter_key, &filter.grantee_key) {
        (Some(g), _) => directory.list_attestations_by(g).await?,
        (None, Some(g)) => directory.list_attestations_for(g).await?,
        // Guarded by the InvalidArgument check above.
        (None, None) => Vec::new(),
    };

    // Apply the other-side filter in-memory if both are set.
    if let (Some(_), Some(grantee)) = (&filter.granter_key, &filter.grantee_key) {
        candidates.retain(|a| &a.attested_key_id == grantee);
    }
    // Purpose filter — checks the envelope's `dimension` field.
    if let Some(p) = &filter.purpose {
        candidates.retain(|a| envelope_dimension(&a.attestation_envelope) == Some(p.as_str()));
    }

    // Split by attestation_type — we need scores for the edges,
    // withdraws/recants/delegates_to for the EdgeType derivation.
    let mut scores: Vec<Attestation> = Vec::new();
    let mut adversarial_pairs: HashSet<(String, String)> = HashSet::new();
    let mut adversarial_when: HashMap<(String, String), (DateTime<Utc>, String)> = HashMap::new();
    // Granters that have received an inbound delegates_to from any
    // third party — they emit "delegated" edges, not direct.
    let mut delegated_granters: HashSet<String> = HashSet::new();

    for a in candidates.drain(..) {
        match a.attestation_type.as_str() {
            attestation_type::SCORES => scores.push(a),
            attestation_type::WITHDRAWS | attestation_type::RECANTS => {
                let key = (a.attesting_key_id.clone(), a.attested_key_id.clone());
                adversarial_when
                    .entry(key.clone())
                    .or_insert((a.asserted_at, a.attestation_type.clone()));
                adversarial_pairs.insert(key);
            }
            attestation_type::DELEGATES_TO => {
                // A `delegates_to` row where granter == filter target
                // means the target IS the delegate (received authority).
                // The granter on this row is irrelevant to the
                // EdgeType classification — what matters is that
                // `a.attested_key_id` (the recipient) has received a
                // delegation. So when this key later emits scores, those
                // are "delegated".
                delegated_granters.insert(a.attested_key_id.clone());
            }
            _ => {}
        }
    }

    // Step 1b — also pull inbound delegates_to for each granter we
    // see in scores. The candidates set above only covers the filter
    // direction; a granter may have received delegation via an
    // attestation NOT in our filter window. We need to query each
    // unique granter once.
    let mut granters_seen: HashSet<String> = HashSet::new();
    for s in &scores {
        granters_seen.insert(s.attesting_key_id.clone());
    }
    for g in &granters_seen {
        for a in directory.list_attestations_for(g).await? {
            if a.attestation_type == attestation_type::DELEGATES_TO {
                delegated_granters.insert(a.attested_key_id.clone());
            }
        }
    }

    // Step 2 — bucket scores by (granter, grantee, dimension).
    #[derive(Default)]
    struct Bucket {
        weight_sum: f64,
        earliest_at: Option<DateTime<Utc>>,
    }
    let mut buckets: HashMap<(String, String, String), Bucket> = HashMap::new();
    for s in &scores {
        let dim = envelope_dimension(&s.attestation_envelope)
            .unwrap_or("")
            .to_owned();
        let key = (s.attesting_key_id.clone(), s.attested_key_id.clone(), dim);
        let b = buckets.entry(key).or_default();
        b.weight_sum += s.weight.unwrap_or(1.0);
        b.earliest_at = Some(match b.earliest_at {
            Some(prior) if prior <= s.asserted_at => prior,
            _ => s.asserted_at,
        });
    }

    // Step 3 — build edges with EdgeType classification.
    let mut edges: Vec<TrustEdge> = Vec::with_capacity(buckets.len());
    for ((granter, grantee, dimension), b) in buckets {
        let pair = (granter.clone(), grantee.clone());
        let is_adversarial = adversarial_pairs.contains(&pair);
        let edge_type = if is_adversarial {
            EdgeType::Adversarial
        } else if delegated_granters.contains(&granter) {
            EdgeType::Delegated
        } else {
            EdgeType::Direct
        };
        if is_adversarial && !filter.include_revoked {
            continue;
        }
        let revoked_at = adversarial_when.get(&pair).map(|(t, _)| *t);
        edges.push(TrustEdge {
            from_key: grantee,
            to_key: granter,
            purpose: dimension.clone(),
            scope: dimension,
            weight: b.weight_sum,
            edge_type,
            granted_at: b.earliest_at.unwrap_or_else(Utc::now),
            revoked_at,
        });
    }

    // Step 4 — resolve nodes via lookup_public_key.
    let mut node_ids: HashSet<String> = HashSet::new();
    for e in &edges {
        node_ids.insert(e.from_key.clone());
        node_ids.insert(e.to_key.clone());
    }
    let mut nodes: Vec<TrustNode> = Vec::with_capacity(node_ids.len());
    for kid in node_ids {
        let resolved: Option<KeyRecord> = directory.lookup_public_key(&kid).await?;
        nodes.push(match resolved {
            Some(k) => TrustNode {
                key_id: k.key_id,
                identity_type: k.identity_type,
                identity_ref: Some(k.identity_ref),
            },
            None => TrustNode {
                key_id: kid,
                identity_type: String::new(),
                identity_ref: None,
            },
        });
    }

    // Step 5 — sort for byte-stable JSON output.
    nodes.sort_by(|a, b| a.key_id.cmp(&b.key_id));
    edges.sort_by(|a, b| {
        (&a.from_key, &a.to_key, &a.purpose).cmp(&(&b.from_key, &b.to_key, &b.purpose))
    });

    Ok(TrustTopology { nodes, edges })
}

// ─── 2. Delegation graph ──────────────────────────────────────────

/// One edge in the delegation BFS — `from_key` delegates to `to_key`
/// within the given `scope`.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DelegationEdge {
    /// Granter — the key that issued the `delegates_to` attestation.
    pub from_key: String,
    /// Recipient — the key authorized to act on the granter's behalf.
    pub to_key: String,
    /// Scope of the delegation — pulled from the attestation
    /// envelope's `scope` field (falls back to `dimension`, then to
    /// the empty string).
    pub scope: String,
    /// `asserted_at` of the `delegates_to` attestation row.
    pub granted_at: DateTime<Utc>,
    /// Evidence URIs / refs the granter included in the attestation
    /// envelope (`evidence_refs` field). Empty when the envelope has
    /// no such field.
    pub evidence_refs: Vec<String>,
    /// `withdraws` / `recants` annotation if the delegation has been
    /// retracted by a later row from the same granter.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub withdrawn_by: Option<WithdrawalEntry>,
    /// BFS depth from the root key. `0` is unused (the root is not
    /// itself an edge); the root's direct delegations are depth `1`.
    pub depth: usize,
}

/// Annotation when a `delegates_to` edge has been retracted.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct WithdrawalEntry {
    /// `key_id` of the row that issued the retraction (typically the
    /// same as the original granter, but persist accepts retractions
    /// from any key — consumer policy decides whose retraction
    /// counts).
    pub key_id: String,
    /// `asserted_at` of the retraction row.
    pub withdrawn_at: DateTime<Utc>,
    /// `"withdraws"` or `"recants"` — wire-distinct per FSD-002
    /// §2.2.4 even when consumer UIs collapse the two.
    pub kind: String,
}

/// Result of [`build_delegation_graph`] — the BFS tree rooted at
/// `from_key`, sorted by `(depth, from_key, to_key)` for byte-stable
/// JSON output.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DelegationGraph {
    /// The BFS root.
    pub root_key: String,
    /// Depth bound the BFS was run with.
    pub max_depth: usize,
    /// Edges discovered in the walk.
    pub edges: Vec<DelegationEdge>,
}

/// Maximum `max_depth` value [`build_delegation_graph`] honors. Above
/// this the caller's `max_depth` is clamped — protects against UI
/// hot-path runaway BFS on a pathologically deep delegation graph.
pub const MAX_DELEGATION_DEPTH: usize = 16;

/// BFS [`crate::federation::types::attestation_type::DELEGATES_TO`]
/// out-edges from `from_key`. Cycle-safe (visited set on the granter
/// side) and depth-bounded (capped at [`MAX_DELEGATION_DEPTH`]).
///
/// # Algorithm
///
/// 1. Queue `(from_key, 0)`. Maintain a `visited` set keyed on
///    granter key.
/// 2. For each `(current, depth)` dequeued: call
///    [`FederationDirectory::list_attestations_by`]`(current)`.
/// 3. Partition into `delegates_to` (out-edges) and `withdraws` /
///    `recants` (annotations).
/// 4. For each `delegates_to` row at `depth < max_depth`: emit a
///    [`DelegationEdge`] with `depth + 1`, check for a matching
///    retraction by `(current → attested_key_id)`, and enqueue
///    `attested_key_id` if not yet visited.
/// 5. Return when the queue drains.
pub async fn build_delegation_graph(
    directory: &dyn FederationDirectory,
    from_key: &str,
    max_depth: usize,
) -> Result<DelegationGraph, Error> {
    if from_key.is_empty() {
        return Err(Error::InvalidArgument("from_key must be non-empty".into()));
    }
    let effective_depth = max_depth.min(MAX_DELEGATION_DEPTH);

    let mut edges: Vec<DelegationEdge> = Vec::new();
    let mut visited: HashSet<String> = HashSet::new();
    let mut queue: VecDeque<(String, usize)> = VecDeque::new();
    queue.push_back((from_key.to_owned(), 0));
    visited.insert(from_key.to_owned());

    while let Some((current, depth)) = queue.pop_front() {
        if depth >= effective_depth {
            continue;
        }
        let rows = directory.list_attestations_by(&current).await?;
        // Bucket retractions by recipient for fast lookup.
        let mut retractions: HashMap<String, WithdrawalEntry> = HashMap::new();
        for r in &rows {
            if r.attestation_type == attestation_type::WITHDRAWS
                || r.attestation_type == attestation_type::RECANTS
            {
                retractions
                    .entry(r.attested_key_id.clone())
                    .or_insert(WithdrawalEntry {
                        key_id: r.attesting_key_id.clone(),
                        withdrawn_at: r.asserted_at,
                        kind: r.attestation_type.clone(),
                    });
            }
        }
        for r in rows {
            if r.attestation_type != attestation_type::DELEGATES_TO {
                continue;
            }
            let scope = envelope_field_str_or_set(&r.attestation_envelope, "scope")
                .or_else(|| envelope_field_str(&r.attestation_envelope, "dimension"))
                .unwrap_or_default();
            let evidence_refs = envelope_evidence_refs(&r.attestation_envelope);
            let withdrawn_by = retractions.get(&r.attested_key_id).cloned();
            edges.push(DelegationEdge {
                from_key: r.attesting_key_id.clone(),
                to_key: r.attested_key_id.clone(),
                scope,
                granted_at: r.asserted_at,
                evidence_refs,
                withdrawn_by,
                depth: depth + 1,
            });
            if !visited.contains(&r.attested_key_id) && depth + 1 < effective_depth {
                visited.insert(r.attested_key_id.clone());
                queue.push_back((r.attested_key_id, depth + 1));
            }
        }
    }

    edges.sort_by(|a, b| (a.depth, &a.from_key, &a.to_key).cmp(&(b.depth, &b.from_key, &b.to_key)));

    Ok(DelegationGraph {
        root_key: from_key.to_owned(),
        max_depth: effective_depth,
        edges,
    })
}

fn envelope_field_str(envelope: &serde_json::Value, field: &str) -> Option<String> {
    envelope
        .get(field)
        .and_then(|v| v.as_str())
        .map(|s| s.to_owned())
}

/// v6.7.1 (CIRISPersist#219) — read a delegation envelope field that may be
/// EITHER a bare string (`"scope": "consent_revocation"`) OR a set of tokens
/// (`"scope": ["act_on_behalf", "message_io", …]`, the shape
/// [`self_at_login::delegates_to_agent_envelope`](crate::federation::self_at_login::delegates_to_agent_envelope)
/// emits per §8.1.12.7). A bare string passes through unchanged; an array is
/// comma-joined into the set-as-string form persist already uses for
/// multi-valued columns (matching the `identity_type` set encoding), so
/// `DelegationEdge::scope` is populated for both shapes and a consumer can
/// `scope.split(',')` for membership. Returns `None` for an absent field or
/// an array with no string tokens (so the `dimension` fallback still fires).
fn envelope_field_str_or_set(envelope: &serde_json::Value, field: &str) -> Option<String> {
    match envelope.get(field) {
        Some(serde_json::Value::String(s)) => Some(s.clone()),
        Some(serde_json::Value::Array(arr)) => {
            let tokens: Vec<&str> = arr.iter().filter_map(|v| v.as_str()).collect();
            (!tokens.is_empty()).then(|| tokens.join(","))
        }
        _ => None,
    }
}

fn envelope_evidence_refs(envelope: &serde_json::Value) -> Vec<String> {
    envelope
        .get("evidence_refs")
        .and_then(|v| v.as_array())
        .map(|arr| {
            arr.iter()
                .filter_map(|v| v.as_str().map(|s| s.to_owned()))
                .collect()
        })
        .unwrap_or_default()
}

// ─── 3. Audit-chain proof ─────────────────────────────────────────

/// One entry on the audit-chain walk surfaced by
/// [`AuditChainProof`]. Mirrors the user-visible columns of
/// `cirislens_audit_log` — the BYTEA hashes are hex-encoded for the
/// UI wire (matches the rest of persist's hash serialization
/// discipline).
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AuditChainEntry {
    /// `cirislens_audit_log.sequence_number`. Genesis is `1`.
    pub sequence_number: i64,
    /// `cirislens_audit_log.tenant_id` — AV-51 per-tenant scope.
    pub tenant_id: String,
    /// `cirislens_audit_log.action_type` (e.g. `trust_grant`,
    /// `contribution_received`).
    pub action_type: String,
    /// `cirislens_audit_log.recorded_at`.
    pub timestamp: DateTime<Utc>,
    /// Hex-encoded `entry_hash` — the canonical sha256 of this row.
    pub row_hash: String,
    /// Hex-encoded `prev_hash`. `None` for the genesis row (where
    /// `prev_hash` is the all-zero genesis sentinel and surfacing it
    /// as a string would mislead UIs into showing a "chain start"
    /// hash).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub prev_hash: Option<String>,
}

/// Result of an audit-chain walk — the chain from genesis up to the
/// row that references `trace_id` as its `subject_id`. The
/// `head_signature` field carries the JSON-serialized
/// [`ciris_verify_core::transparency::SignedTreeHead`] when the
/// tenant's Merkle log has signed one; `None` otherwise.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AuditChainProof {
    /// The `trace_id` the proof was built for — echoed for the UI.
    pub trace_id: String,
    /// Genesis → trace entries in `sequence_number` order. Empty
    /// when no audit_log row references the given `trace_id`.
    pub entries: Vec<AuditChainEntry>,
    /// JSON-serialized
    /// [`ciris_verify_core::transparency::SignedTreeHead`] for the
    /// tenant's Merkle log, when one has been signed. `None` when
    /// the Merkle hook is disabled (no local signer installed) or no
    /// STH has been emitted yet.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub head_signature: Option<String>,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn edge_type_serializes_snake_case() {
        assert_eq!(
            serde_json::to_string(&EdgeType::Direct).unwrap(),
            r#""direct""#
        );
        assert_eq!(
            serde_json::to_string(&EdgeType::Delegated).unwrap(),
            r#""delegated""#
        );
        assert_eq!(
            serde_json::to_string(&EdgeType::Adversarial).unwrap(),
            r#""adversarial""#
        );
    }

    // Compile-time bounds check on MAX_DELEGATION_DEPTH — UI can't
    // request runaway BFS depth (low bound) and the constant stays
    // within a sane register (high bound).
    const _: () = {
        assert!(MAX_DELEGATION_DEPTH >= 4);
        assert!(MAX_DELEGATION_DEPTH <= 64);
    };

    #[test]
    fn envelope_evidence_refs_handles_missing_and_malformed() {
        let v = serde_json::json!({"evidence_refs": ["a", "b"]});
        assert_eq!(envelope_evidence_refs(&v), vec!["a", "b"]);
        let v = serde_json::json!({});
        assert_eq!(envelope_evidence_refs(&v), Vec::<String>::new());
        let v = serde_json::json!({"evidence_refs": "not-an-array"});
        assert_eq!(envelope_evidence_refs(&v), Vec::<String>::new());
        let v = serde_json::json!({"evidence_refs": ["a", 42, "b"]});
        // Non-string entries silently dropped.
        assert_eq!(envelope_evidence_refs(&v), vec!["a", "b"]);
    }

    #[test]
    fn envelope_field_str_pulls_string_field() {
        let v = serde_json::json!({"scope": "manifest:foo"});
        assert_eq!(envelope_field_str(&v, "scope"), Some("manifest:foo".into()));
        assert_eq!(envelope_field_str(&v, "missing"), None);
        let v2 = serde_json::json!({"scope": 42});
        assert_eq!(envelope_field_str(&v2, "scope"), None);
    }

    /// v6.7.1 (CIRISPersist#219) — the scope reader must accept BOTH a bare
    /// string and an array of tokens; the self-at-login `delegates_to`
    /// envelope emits an array, which the old string-only reader dropped to
    /// empty (every self-at-login delegation edge came out scope-less).
    #[test]
    fn envelope_field_str_or_set_handles_string_and_array() {
        // Bare string passes through unchanged.
        let s = serde_json::json!({"scope": "consent_revocation"});
        assert_eq!(
            envelope_field_str_or_set(&s, "scope"),
            Some("consent_revocation".into())
        );
        // Array is comma-joined (set-as-string), preserving order.
        let a = serde_json::json!({"scope": ["act_on_behalf", "message_io"]});
        assert_eq!(
            envelope_field_str_or_set(&a, "scope"),
            Some("act_on_behalf,message_io".into())
        );
        // The canonical #219 repro: the real self-at-login envelope.
        let env = crate::federation::self_at_login::delegates_to_agent_envelope(
            "agent-occ",
            "pair-1",
            &crate::federation::self_at_login::SELF_AT_LOGIN_DELEGATION_SCOPE,
        );
        let scope = envelope_field_str_or_set(&env, "scope").expect("array scope is read");
        assert!(
            !scope.is_empty(),
            "#219: self-at-login scope must not be empty"
        );
        for tok in crate::federation::self_at_login::SELF_AT_LOGIN_DELEGATION_SCOPE {
            assert!(
                scope.split(',').any(|t| t == tok),
                "scope set must contain {tok}"
            );
        }
        // Absent / non-string-array → None, so the `dimension` fallback fires.
        assert_eq!(envelope_field_str_or_set(&s, "missing"), None);
        assert_eq!(
            envelope_field_str_or_set(&serde_json::json!({"scope": []}), "scope"),
            None
        );
        assert_eq!(
            envelope_field_str_or_set(&serde_json::json!({"scope": [1, 2]}), "scope"),
            None
        );
    }
}
