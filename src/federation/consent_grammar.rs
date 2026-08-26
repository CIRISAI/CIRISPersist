//! v21.2.0 (CIRISPersist#509 FLOOR) — the seed of the closed consent
//! grammar.
//!
//! Contextual-integrity (Nissenbaum) frames a consented information flow
//! as five parameters: sender, subject, recipient, information-type, and
//! transmission-principle. Persist's existing wire vocabulary already
//! maps onto four of them:
//!
//! - **sender** → `attesting_key_id` (who authored the grant)
//! - **subject** → `subject_key_ids` (whose flow the grant concerns — for
//!   a `consent:replication:v1` grant, the peer(s) it extends
//!   replication trust to)
//! - **recipient** → `cohort_scope` (how far the granted content may
//!   travel: `self` / `family` / `community` / … / `federation`)
//! - **information-type** → `dimension`, narrowed by
//!   [`grant_attestation_prefixes`] / [`covers`] to the namespace-prefix
//!   set a grant actually authorizes
//!
//! The fifth — **transmission-principle** — is the `consent:*` dimension
//! family itself (the norm under which the flow is authorized).
//!
//! This module implemented ONLY the one instance persist acted on at the
//! #509 floor: [`GRANT_DIMENSION`]'s `payload.attestation_prefixes`, read
//! by [`crate::Engine::promote_consented_backlog`].
//!
//! # v21.3.0 (CIRISPersist#510 P1) — the closed grammar itself
//!
//! [`ConsentTransferPolicy`] is the full typed payload shape: every field
//! is a closed enum or a validated string, [`parse_grant_payload`] is the
//! ONE strict parser (`#[serde(deny_unknown_fields)]` throughout — a
//! malformed or unrecognized shape REJECTS THE WHOLE GRANT, never
//! silently drops the offending part), and [`consent_transferability`]
//! is the exhaustive per-[`EnvelopeKind`](super::replication_policy::EnvelopeKind)
//! consent-vs-structural classification (mirrors
//! [`super::replication_policy::policy_for`]'s exhaustive-match
//! discipline — a 15th kind cannot compile without a decision).
//!
//! [`grant_attestation_prefixes`] (the #509 floor's raw-prefix reader) is
//! now a thin wrapper over [`parse_grant_payload`] — ONE parser, not two
//! diverging ones. This is a **behavior change** from the #509 floor:
//! the floor's reader tolerated a missing `grants` token and silently
//! skipped non-string / empty-string `attestation_prefixes` entries
//! (per-entry leniency); the #510 closed grammar requires `grants` and
//! rejects the WHOLE grant on any non-conforming entry (whole-grant
//! fail-closed, the same posture [`RestrictionOp`]'s unknown-tag
//! rejection uses). Both postures agree on the OUTCOME for every case
//! that matters operationally — a malformed grant still contributes zero
//! prefixes — so `grant_attestation_prefixes`'s only real callers (its
//! own unit tests) were updated to assert the new whole-grant-reject
//! shape; see the `#510 P1` comments on
//! `non_string_entries_reject_whole_grant_510` and
//! `empty_string_prefix_rejects_whole_grant_510` below.
//!
//! [`Engine::promote_consented_backlog`](crate::Engine::promote_consented_backlog)
//! itself no longer calls `grant_attestation_prefixes` at all — it parses
//! each live grant through [`parse_grant_payload`] directly (fail-closed:
//! unparseable ⇒ covers nothing) so it gets the full policy (audience,
//! restrictions, kinds, direction, expiry), not just the prefix list.

use super::consent_peer_set;
use serde::{Deserialize, Serialize};

/// The consent-replication grant dimension (`"consent:replication:v1"`).
/// Single-sourced from [`consent_peer_set::DIMENSION`] — persist has
/// exactly one wire constant for this dimension string; this alias
/// exists so callers reasoning about the consent GRAMMAR (this module)
/// don't have to reach into the E7 PROJECTION module for it.
pub const GRANT_DIMENSION: &str = consent_peer_set::DIMENSION;

// ─────────────────────────── #510 P1: the closed grammar types ──────

/// The direction of a `payload.direction` consent-transfer grant.
/// Closed two-variant enum — an unrecognized wire string fails to
/// deserialize (serde's enum-variant matching is closed by
/// construction). Default `Egress` — the only direction
/// [`Engine::promote_consented_backlog`](crate::Engine::promote_consented_backlog)
/// currently acts on (this node shipping ITS OWN local backlog out);
/// `Ingress` is grammar-legal (round-trips, appears in the manifest) but
/// actioned by no sweep yet — a deliberate P1 scope line, not an
/// oversight.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Serialize, Deserialize)]
pub enum Direction {
    /// This node is shipping content OUT to the grant's audience.
    #[default]
    #[serde(rename = "egress")]
    Egress,
    /// Reserved for a future accepted-inbound-consent flow.
    #[serde(rename = "ingress")]
    Ingress,
}

/// The Nissenbaum transmission-principle a grant declares the flow is
/// authorized under. Closed five-variant enum, lowercase wire renames.
/// Default `Share` — the status-quo #509 posture (replication IS
/// sharing) before a grant declares otherwise.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum TransmissionPrinciple {
    /// The recipient may retain a durable copy.
    Retain,
    /// The recipient may share the content onward (the default; #509's
    /// implicit posture).
    #[default]
    Share,
    /// The recipient may analyze/derive over the content but not
    /// republish it.
    Analyze,
    /// The recipient may use the content to train a model.
    Train,
    /// The recipient may publish the content.
    Publish,
}

/// One restriction a grant places on the covered flow — a closed,
/// internally-tagged enum (`#[serde(tag = "op")]`). An unrecognized `op`
/// tag is a serde deserialize ERROR (not a skipped/ignored variant),
/// which [`parse_grant_payload`] surfaces as the grant being REJECTED at
/// admission — CIRISPersist#510's "unknown restriction op ⇒ grant
/// rejected, never silently un-restricted" invariant.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(tag = "op", deny_unknown_fields)]
pub enum RestrictionOp {
    /// Strip a JSON-pointer-with-wildcard `path` from the envelope
    /// before promotion. See [`strip_field`].
    #[serde(rename = "strip_field")]
    StripField {
        /// The path to strip, e.g. `"/trace/llm_calls/*/prompt"`.
        path: String,
    },
    /// The recipient must hold `capability` to receive the flow.
    /// Recorded in the grammar/manifest; enforced at the SERVE layer
    /// (P3), not at promotion time — [`Engine::promote_consented_backlog`](crate::Engine::promote_consented_backlog)
    /// applies no transform for this op.
    #[serde(rename = "recipient_capability")]
    RecipientCapability {
        /// The capability token the recipient must hold.
        capability: String,
    },
}

/// `[Consentable]` iff a `payload.kinds` entry naming this
/// [`EnvelopeKind`](super::replication_policy::EnvelopeKind) may appear
/// in a consent-transfer grant at all; `[StructuralPlane]` kinds
/// replicate per [`super::replication_policy::KindPolicy`] membership /
/// necessity — consent is not the gate that governs them, so naming one
/// in `payload.kinds` is a grammar error, not a narrower grant.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
pub enum Transferability {
    /// This kind is consent-gated; naming it in `payload.kinds` is legal.
    Consentable,
    /// This kind replicates structurally (KindPolicy), never by consent.
    StructuralPlane,
}

/// The EXHAUSTIVE per-kind classification (CIRISPersist#510 P1). No
/// wildcard arm — adding a 16th
/// [`EnvelopeKind`](super::replication_policy::EnvelopeKind) without
/// extending this match is a **compile failure**, the same discipline
/// [`super::replication_policy::policy_for`] uses for admission policy.
/// Only [`Attestation`](super::replication_policy::EnvelopeKind::Attestation)
/// is consentable today — every other kind is a structural-plane
/// primitive (keys, revocations, roster/proof planes, operational
/// planes) that replicates by KindPolicy membership, never by an
/// end-user consent grant.
#[must_use]
pub fn consent_transferability(
    kind: crate::federation::replication_policy::EnvelopeKind,
) -> Transferability {
    use crate::federation::replication_policy::EnvelopeKind as K;
    match kind {
        K::Attestation => Transferability::Consentable,
        K::Key
        | K::Revocation
        | K::IdentityOccurrence
        | K::Family
        | K::Community
        | K::IdentityOccurrenceRevocation
        | K::FamilyMembershipRevocation
        | K::CommunityMembershipRevocation
        | K::LocationProof
        | K::Organization
        | K::OrgMembership
        | K::PartnerRecord
        | K::TransportDestination
        // v31.1.0 (CIRISPersist#662) — the accord evidence bundle is
        // constitutional machinery, not user data: naming it in a
        // `payload.kinds` grant would let an end-user consent decision
        // narrow (or purport to widen) the carriage of the quorum that
        // governs the whole mesh.
        | K::AccordQuorumEvidence => Transferability::StructuralPlane,
    }
}

fn default_kinds() -> Vec<String> {
    vec!["Attestation".to_string()]
}

fn default_audience() -> String {
    crate::federation::types::cohort_scope::FEDERATION.to_string()
}

/// The parsed, validated `payload` of a `consent:replication:v1` grant —
/// CIRISPersist#510 P1's closed consent-transfer grammar.
/// `#[serde(deny_unknown_fields)]` — fail-closed is load-bearing: an
/// unrecognized top-level payload member rejects the WHOLE grant rather
/// than being silently ignored. Constructed ONLY via
/// [`parse_grant_payload`], which layers semantic validation (the
/// `grants` token, `kinds` consentability, `audience` closed-set
/// membership, non-empty `attestation_prefixes` entries) on top of the
/// structural `serde` parse.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ConsentTransferPolicy {
    /// Must be `"transfer"` or the legacy `"replication"` (#509
    /// backward-compat — [`parse_grant_payload`] treats them
    /// identically). Any other token is rejected.
    pub grants: String,
    /// The flow direction (default [`Direction::Egress`]).
    #[serde(default)]
    pub direction: Direction,
    /// Manifest names of consentable
    /// [`EnvelopeKind`](super::replication_policy::EnvelopeKind)s this
    /// grant covers (default `["Attestation"]`). Every entry MUST name a
    /// real kind AND be [`Transferability::Consentable`]
    /// ([`consent_transferability`]) — an unknown or non-consentable
    /// kind rejects the whole grant.
    #[serde(default = "default_kinds")]
    pub kinds: Vec<String>,
    /// The namespace-prefix set this grant authorizes for promotion
    /// (e.g. `["trace:"]`). Required. Every entry must be a non-empty
    /// string — an empty-string entry would `str::starts_with`-match
    /// EVERY dimension, silently widening the grant to "everything";
    /// [`parse_grant_payload`] rejects the whole grant instead.
    pub attestation_prefixes: Vec<String>,
    /// The Nissenbaum transmission principle (default
    /// [`TransmissionPrinciple::Share`]).
    #[serde(default)]
    pub principle: TransmissionPrinciple,
    /// The recipient cohort — one of the 7 closed
    /// [`cohort_scope`](crate::federation::types::cohort_scope) values
    /// (default `"federation"`). Validated against
    /// [`crate::federation::types::cohort_scope::is_valid`].
    #[serde(default = "default_audience")]
    pub audience: String,
    /// Free-text human-readable purpose (optional, unvalidated).
    #[serde(default)]
    pub purpose: Option<String>,
    /// The grant's own expiry as declared IN THE PAYLOAD (distinct from
    /// the row's `expires_at` column, which
    /// [`Engine::promote_consented_backlog`](crate::Engine::promote_consented_backlog)
    /// also checks). `None` = no payload-declared expiry.
    #[serde(default)]
    pub valid_until: Option<chrono::DateTime<chrono::Utc>>,
    /// Restrictions applied to the covered flow (default `[]`). See
    /// [`RestrictionOp`].
    #[serde(default)]
    pub restrictions: Vec<RestrictionOp>,
}

/// The ONE strict parser for a `consent:replication:v1` grant's
/// `payload` (CIRISPersist#510 P1). `envelope["payload"]` must be a JSON
/// object; it is then `#[serde(deny_unknown_fields)]`-parsed into
/// [`ConsentTransferPolicy`] (an unrecognized field, an unrecognized
/// `restrictions[].op` tag, or a type mismatch is a hard reject), and
/// finally semantically validated:
///
/// 1. `grants` must be `"transfer"` or the legacy `"replication"`.
/// 2. Every `kinds` entry must resolve to a real
///    [`EnvelopeKind`](super::replication_policy::EnvelopeKind) that is
///    [`Transferability::Consentable`].
/// 3. `audience` must be one of the 7 closed
///    [`cohort_scope`](crate::federation::types::cohort_scope) values.
/// 4. No `attestation_prefixes` entry may be the empty string.
///
/// LEGACY COMPAT: the exact server payload
/// `{"grants":"replication","attestation_prefixes":["capacity:"]}`
/// parses successfully (every other field defaults in) — see the
/// `legacy_grant_payload_parses_510` witness.
pub fn parse_grant_payload(envelope: &serde_json::Value) -> Result<ConsentTransferPolicy, String> {
    let payload = envelope
        .get("payload")
        .ok_or_else(|| "envelope carries no \"payload\"".to_string())?;
    if !payload.is_object() {
        return Err("envelope \"payload\" is not a JSON object".to_string());
    }
    let policy: ConsentTransferPolicy = serde_json::from_value(payload.clone()).map_err(|e| {
        format!("payload does not conform to the closed consent-transfer grammar: {e}")
    })?;

    if policy.grants != "transfer" && policy.grants != "replication" {
        return Err(format!(
            "unknown \"grants\" token {:?} (must be \"transfer\" or the legacy \"replication\")",
            policy.grants
        ));
    }

    for k in &policy.kinds {
        let kind = crate::federation::replication_policy::EnvelopeKind::ALL
            .iter()
            .copied()
            .find(|ek| ek.as_str() == k.as_str())
            .ok_or_else(|| format!("unknown \"kinds\" entry {k:?}"))?;
        if consent_transferability(kind) != Transferability::Consentable {
            return Err(format!(
                "\"kinds\" entry {k:?} is not consentable (it is a structural-plane kind)"
            ));
        }
    }

    if !crate::federation::types::cohort_scope::is_valid(&policy.audience) {
        return Err(format!(
            "\"audience\" {:?} is not one of the closed cohort_scope values",
            policy.audience
        ));
    }

    if policy.attestation_prefixes.iter().any(|p| p.is_empty()) {
        return Err(
            "\"attestation_prefixes\" contains an empty-string entry (would match every \
             dimension)"
                .to_string(),
        );
    }

    Ok(policy)
}

/// The admission-chokepoint helper (CIRISPersist#510 P1): `Ok(())` iff
/// `envelope`'s payload parses through [`parse_grant_payload`], `Err`
/// (the human-readable reason) otherwise. Every backend's
/// `put_attestation` calls this — gated on
/// `envelope_dimension(envelope) == Some(GRANT_DIMENSION)` — the same
/// "one pure helper, called identically from sqlite/postgres/memory"
/// shape [`consent_peer_set`]'s projection helpers established for E7.
pub fn validate_grant_admission(envelope: &serde_json::Value) -> Result<(), String> {
    parse_grant_payload(envelope).map(|_| ())
}

/// Read `envelope["payload"]["attestation_prefixes"]` as the JCS-sorted
/// array of namespace-prefix strings a `consent:replication:v1` grant
/// authorizes for promotion (e.g. `["trace:"]`). A trailing colon is
/// significant — `covers` matches by plain `str::starts_with`, so
/// `"trace"` (no colon) would ALSO match `"trace_summary:v1"`, which
/// `"trace:"` correctly excludes.
///
/// v21.3.0 (CIRISPersist#510 P1) — a thin wrapper over
/// [`parse_grant_payload`] (ONE parser): on a successful strict parse,
/// returns the parsed `attestation_prefixes`; on ANY parse failure
/// (missing `grants`, an empty-string prefix, an unrecognized field —
/// the closed grammar's fail-closed reject), returns the empty vec. This
/// preserves the #509 floor's own fail-closed doctrine — "every
/// malformed shape resolves to this grant covers nothing" — just now at
/// WHOLE-GRANT granularity (the #510 posture) instead of per-entry
/// leniency (the #509 floor's original posture). `Engine::
/// promote_consented_backlog` no longer calls this function at all (it
/// parses through `parse_grant_payload` directly for the full policy);
/// this wrapper remains for API stability and its own unit tests.
pub fn grant_attestation_prefixes(envelope: &serde_json::Value) -> Vec<String> {
    parse_grant_payload(envelope)
        .map(|policy| policy.attestation_prefixes)
        .unwrap_or_default()
}

/// True iff any of `prefixes` is a `str::starts_with` prefix of
/// `dimension` — i.e. the grant covers `dimension`.
#[must_use]
pub fn covers(prefixes: &[String], dimension: &str) -> bool {
    prefixes.iter().any(|p| dimension.starts_with(p.as_str()))
}

// ───────────────────────── #510 P1: restriction application ─────────

/// Apply one [`RestrictionOp::StripField`] `path` to `envelope` IN
/// PLACE (CIRISPersist#510 P1).
///
/// v21.6.0 (CIRISPersist#519 item 2a-ii) — this is now a THIN WRAPPER over
/// [`crate::federation::transform::apply`]
/// (`&`[`crate::federation::transform::TransformOp::StripField`]): the
/// canonical strip implementation (wildcard fan-out, missing-path no-op,
/// protected-root-member refusal for `dimension` / `trace_id`) moved to the
/// [`crate::federation::transform`] module so there is ONE strip
/// implementation, not two diverging ones — see that module's doc for the
/// exact semantics. `apply` never errors for `StripField` (it's pure and
/// total over every input shape), so the `Err` arm below is unreachable in
/// practice and kept only as a defensive no-op rather than an `.expect(..)`.
pub fn strip_field(envelope: &mut serde_json::Value, path: &str) {
    use crate::federation::transform::{apply, TransformOp};
    if let Ok(result) = apply(
        &TransformOp::StripField {
            path: path.to_string(),
        },
        envelope,
    ) {
        *envelope = result;
    }
}

/// Map a covering grant's `restrictions` to the transform-carrying ops the
/// promotion pipeline executes (CIRISPersist#519 item 2a-ii — the
/// application half: `Engine::promote_attestation_with_transforms`
/// generalizes promotion from a bespoke strip-only loop to a full
/// [`crate::federation::transform::TransformPipeline`], built EXCLUSIVELY
/// through this function).
///
/// v21.7.0 chose the MINIMAL variant of this cut: [`RestrictionOp`] grows
/// no new variants (still exactly `StripField` + `RecipientCapability` —
/// the wire grammar and [`CONSENT_GRAMMAR_HASH`] are UNCHANGED). Instead,
/// the one restriction that already carries a promotion-time transform
/// (`StripField`) is routed through the transform algebra by name rather
/// than by a bespoke loop:
///
/// - [`RestrictionOp::StripField`] maps 1:1, order-preserving, to
///   [`crate::federation::transform::TransformOp::StripField`] — the ONLY
///   place a `strip_field` restriction becomes a pipeline stage (single-
///   sourced, mirroring [`strip_field`]'s own "one strip implementation"
///   discipline one level up: one implementation, one place it is turned
///   into an op).
/// - [`RestrictionOp::RecipientCapability`] carries no promotion-time
///   transform (serve-layer enforcement, a P3 follow-up) and is skipped —
///   the returned `Vec` may be shorter than `restrictions`.
///
/// An empty or all-`RecipientCapability` `restrictions` slice yields an
/// empty pipeline, whose [`crate::federation::transform::TransformPipeline::apply_all`]
/// is the identity — callers use emptiness as the "no transform needed,
/// take the byte-identical fast path" signal (see
/// `Engine::promote_consented_backlog`).
#[must_use]
pub fn to_transform_ops(
    restrictions: &[RestrictionOp],
) -> Vec<crate::federation::transform::TransformOp> {
    restrictions
        .iter()
        .filter_map(|r| match r {
            RestrictionOp::StripField { path } => {
                Some(crate::federation::transform::TransformOp::StripField { path: path.clone() })
            }
            RestrictionOp::RecipientCapability { .. } => None,
        })
        .collect()
}

// ───────────────────────── #510 P1: manifest + pinned hash ──────────

/// The full closed consent grammar as canonical JSON (CIRISPersist#510
/// P1) — mirrors [`super::replication_policy::replication_policy_manifest`]'s
/// shape/role exactly: the hashed representation + the public API
/// surface a cross-repo consumer pins against.
#[must_use]
pub fn consent_grammar_manifest() -> serde_json::Value {
    use crate::federation::replication_policy::EnvelopeKind;
    use crate::federation::types::cohort_scope;

    let kind_transferability: Vec<serde_json::Value> = EnvelopeKind::ALL
        .iter()
        .map(|k| {
            let t = consent_transferability(*k);
            serde_json::json!({ "kind": k.as_str(), "transferability": t })
        })
        .collect();

    serde_json::json!({
        "contract": "consent_grammar",
        "version": "consent-grammar:v1",
        "directions": ["egress", "ingress"],
        // v30.7.0 (CIRISPersist#625) — one source of truth. Same bytes, so
        // CONSENT_GRAMMAR_HASH is unchanged; the hash test below proves it.
        "principles": crate::federation::types::transmission_principle::ALL,
        "restriction_ops": [
            {"op": "strip_field", "args": ["path"]},
            {"op": "recipient_capability", "args": ["capability"]},
        ],
        "audiences": [
            cohort_scope::SELF,
            cohort_scope::FAMILY,
            cohort_scope::COMMUNITY,
            cohort_scope::AFFILIATIONS,
            cohort_scope::SPECIES,
            cohort_scope::BIOSPHERE,
            cohort_scope::FEDERATION,
        ],
        "kind_transferability": kind_transferability,
        "legacy_compat": {"replication": "transfer"},
        "defaults": {
            "direction": "egress",
            "kinds": ["Attestation"],
            "principle": "share",
            "audience": cohort_scope::FEDERATION,
        },
    })
}

/// sha256 (lowercase hex) over JCS of [`consent_grammar_manifest`] — the
/// same canonicalizer [`super::replication_policy::replication_policy_sha256`]
/// uses.
#[must_use]
pub fn consent_grammar_sha256() -> String {
    use sha2::Digest as _;
    let canonical = crate::verify::canonical::ceg_produce_canonicalize(&consent_grammar_manifest())
        .expect("consent grammar manifest canonicalizes");
    hex::encode(sha2::Sha256::digest(&canonical))
}

/// The PINNED grammar hash. The `consent_grammar_hash_is_pinned` witness
/// asserts computed == pinned — any grammar change is a deliberate
/// re-pin, visible to every consumer (cross-repo drift is a build
/// failure), exactly the [`super::replication_policy::REPLICATION_POLICY_HASH`]
/// discipline.
/// v31.1.0 (CIRISPersist#662) — re-pinned. The manifest carries
/// `kind_transferability` over
/// [`EnvelopeKind::ALL`](super::replication_policy::EnvelopeKind::ALL), so the
/// 15th kind ([`AccordQuorumEvidence`](super::replication_policy::EnvelopeKind::AccordQuorumEvidence),
/// classified `StructuralPlane`) moves this hash too. The GRAMMAR itself —
/// principles, restriction ops, audiences — is unchanged; what changed is the
/// closed set of kinds a grant may name. Previous value:
/// `2064b567c60062fe9583ea983224d977db7440c8d240d6902a2db50e3e157d05`.
pub const CONSENT_GRAMMAR_HASH: &str =
    "b66870da9639c8560538a26c566168fea9759139eaa67ad4116ff8a5f290d69f";

#[cfg(all(test, any(feature = "sqlite", feature = "postgres")))]
pub(crate) mod test_support {
    use super::GRANT_DIMENSION;
    use crate::federation::types::{attestation_tier, attestation_type};
    use crate::federation::{Attestation, FederationDirectory, SignedAttestation};

    /// Build an UNSIGNED-then-signed `consent:replication:v1` candidate
    /// row carrying an arbitrary `payload` — the #510 admission-rejection
    /// exercise's fixture. Signed exactly like
    /// `consent_peer_set::test_support::grant` (so every gate up to the
    /// #510 grammar check passes and the #510 check is the ONE that
    /// fires).
    fn bad_grant(id: &str, node: &str, payload: serde_json::Value) -> Attestation {
        let envelope = serde_json::json!({
            "dimension": GRANT_DIMENSION,
            "subject_key_ids": [format!("peer-of-{node}")],
            "payload": payload,
        });
        let (och, ed_sig, pqc_sig) =
            crate::federation::tier_ingest::test_support::sign_envelope(node, &envelope);
        let now = chrono::Utc::now();
        let mut sealed_row_ = Attestation {
            attestation_id: id.to_owned(),
            attesting_key_id: node.to_owned(),
            attested_key_id: node.to_owned(),
            attestation_type: attestation_type::SCORES.to_owned(),
            weight: None,
            asserted_at: now,
            expires_at: None,
            attestation_envelope: envelope,
            original_content_hash: och,
            scrub_signature_classical: ed_sig,
            scrub_signature_pqc: pqc_sig,
            scrub_key_id: node.to_owned(),
            scrub_timestamp: now,
            pqc_completed_at: None,
            persist_row_hash: String::new(),
            subject_key_ids: vec![format!("peer-of-{node}")],
            withdraws_admission_rule: None,
            cohort_scope: "federation".to_owned(),
            tier: attestation_tier::FEDERATION.to_owned(),
            promoted_at: None,
            additional_scrubs: Vec::new(),
        };
        crate::federation::tier_ingest::test_support::seal_row_in_place(node, &mut sealed_row_);
        crate::federation::tier_ingest::test_support::reseal(&mut sealed_row_);
        sealed_row_
    }

    fn expect_510_reject(
        result: &Result<crate::federation::AttestationOutcome, crate::federation::Error>,
        what: &str,
    ) {
        match result {
            Err(crate::federation::Error::InvalidArgument(msg)) => {
                assert!(
                    msg.contains("#510"),
                    "{what} must reject with a #510-tagged reason, got: {msg}"
                );
            }
            other => panic!("{what} must reject as InvalidArgument, got: {other:?}"),
        }
    }

    /// v21.3.0 (CIRISPersist#510 P1) — the shared, backend-agnostic
    /// admission-rejection witness, run by the sqlite / postgres / memory
    /// test suites against `&dyn FederationDirectory` (the
    /// `consent_peer_set::test_support::exercise_*` discipline): an
    /// unknown `restrictions[].op` tag, an unrecognized top-level payload
    /// field, and a non-consentable `kinds` entry each reject the WHOLE
    /// grant at `put_attestation`, on every backend identically.
    pub(crate) async fn exercise_510_admission_rejections(
        dir: &dyn FederationDirectory,
        suffix: &str,
    ) {
        let node = format!("node-510-{suffix}");
        crate::federation::tier_ingest::test_support::register_hybrid_key(dir, &node).await;

        // ── unknown restriction op ──
        let id1 = uuid::Uuid::new_v4().to_string();
        let bad1 = bad_grant(
            &id1,
            &node,
            serde_json::json!({
                "grants": "replication",
                "attestation_prefixes": ["trace:"],
                "restrictions": [{"op": "quantum_redaction"}],
            }),
        );
        let err1 = dir
            .put_attestation(SignedAttestation { attestation: bad1 })
            .await;
        expect_510_reject(&err1, "an unknown restriction op");

        // ── unknown top-level payload field ──
        let id2 = uuid::Uuid::new_v4().to_string();
        let bad2 = bad_grant(
            &id2,
            &node,
            serde_json::json!({
                "grants": "replication",
                "attestation_prefixes": ["trace:"],
                "unexpected_field_510": true,
            }),
        );
        let err2 = dir
            .put_attestation(SignedAttestation { attestation: bad2 })
            .await;
        expect_510_reject(&err2, "an unknown top-level payload field");

        // ── nonconsentable kind ──
        let id3 = uuid::Uuid::new_v4().to_string();
        let bad3 = bad_grant(
            &id3,
            &node,
            serde_json::json!({
                "grants": "replication",
                "attestation_prefixes": ["trace:"],
                "kinds": ["Key"],
            }),
        );
        let err3 = dir
            .put_attestation(SignedAttestation { attestation: bad3 })
            .await;
        expect_510_reject(&err3, "a non-consentable kind");
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn grant_dimension_is_the_consent_peer_set_dimension() {
        assert_eq!(GRANT_DIMENSION, consent_peer_set::DIMENSION);
    }

    #[test]
    fn happy_path_extracts_prefixes() {
        let envelope = serde_json::json!({
            "dimension": GRANT_DIMENSION,
            "payload": {
                "grants": "replication",
                "attestation_prefixes": ["trace:", "capacity:sustained_coherence:v1"],
            },
        });
        assert_eq!(
            grant_attestation_prefixes(&envelope),
            vec![
                "trace:".to_string(),
                "capacity:sustained_coherence:v1".to_string()
            ]
        );
    }

    #[test]
    fn missing_payload_yields_empty() {
        let envelope = serde_json::json!({"dimension": GRANT_DIMENSION});
        assert!(grant_attestation_prefixes(&envelope).is_empty());
    }

    #[test]
    fn non_array_attestation_prefixes_yields_empty() {
        let envelope = serde_json::json!({"payload": {"attestation_prefixes": "trace:"}});
        assert!(grant_attestation_prefixes(&envelope).is_empty());

        let envelope_missing_payload_object = serde_json::json!({"payload": "not-an-object"});
        assert!(grant_attestation_prefixes(&envelope_missing_payload_object).is_empty());
    }

    /// v21.3.0 (CIRISPersist#510 P1) — SUPERSEDES the #509 floor's
    /// `non_string_entries_are_skipped_not_fatal`: the floor's raw reader
    /// skipped non-string array entries and kept the rest; the closed
    /// #510 grammar types `attestation_prefixes` as `Vec<String>` (via
    /// `parse_grant_payload`), so a non-string entry is now a STRUCTURAL
    /// parse failure that rejects the WHOLE grant (fail-closed at
    /// whole-grant granularity, same outcome — zero prefixes — reached a
    /// different way). This envelope also omits the now-required
    /// `grants` token, which alone would reject it.
    #[test]
    fn non_string_entries_reject_whole_grant_510() {
        let envelope = serde_json::json!({
            "payload": {"attestation_prefixes": ["trace:", 42, null, {"x": 1}, "capacity:"]},
        });
        assert!(
            grant_attestation_prefixes(&envelope).is_empty(),
            "a non-string attestation_prefixes entry rejects the whole grant (#510), \
             yielding zero prefixes rather than the #509 floor's skip-only-that-entry list"
        );
        assert!(parse_grant_payload(&envelope).is_err());
    }

    /// v21.3.0 (CIRISPersist#510 P1) — SUPERSEDES the #509 floor's
    /// `empty_string_prefix_is_skipped_never_a_total_grant`: an
    /// empty-string prefix now rejects the WHOLE grant (semantic
    /// validation in `parse_grant_payload`) rather than being filtered
    /// out while the rest of the array survives. Still fail-closed —
    /// `grant_attestation_prefixes` still yields `[]`, never "covers
    /// everything" — just at whole-grant granularity.
    #[test]
    fn empty_string_prefix_rejects_whole_grant_510() {
        let envelope = serde_json::json!({
            "payload": {
                "grants": "replication",
                "attestation_prefixes": ["", "trace:"],
            },
        });
        assert!(
            grant_attestation_prefixes(&envelope).is_empty(),
            "an empty-string prefix rejects the whole grant (#510), not just that one entry"
        );

        // An all-empty-string array still covers nothing (fail-closed).
        let all_empty = serde_json::json!({
            "payload": {"grants": "replication", "attestation_prefixes": [""]},
        });
        let prefixes = grant_attestation_prefixes(&all_empty);
        assert!(prefixes.is_empty());
        assert!(!covers(&prefixes, "trace:complete:v1"));
    }

    #[test]
    fn covers_matches_prefix_not_arbitrary_substring() {
        let prefixes = vec!["trace:".to_string()];
        assert!(covers(&prefixes, "trace:complete:v1"));
        assert!(!covers(&prefixes, "capacity:sustained_coherence:v1"));
        // Trailing colon is significant: "trace" (no colon) is NOT one of
        // our prefixes, so a same-named-but-different dimension family
        // must not match.
        assert!(!covers(&prefixes, "trace_summary:v1"));
    }

    // ─────────────────── #510 P1: the closed grammar ────────────────

    /// The gating manifest-hash witness (mirrors
    /// `replication_policy::tests::replication_policy_hash_is_pinned`).
    #[test]
    fn consent_grammar_hash_is_pinned() {
        assert_eq!(
            consent_grammar_sha256(),
            CONSENT_GRAMMAR_HASH,
            "consent grammar changed: re-pin CONSENT_GRAMMAR_HASH deliberately"
        );
    }

    /// LEGACY COMPAT WITNESS: the exact server payload shape
    /// `{"grants":"replication","attestation_prefixes":["capacity:"]}`
    /// MUST parse through the closed #510 grammar, every other field
    /// defaulting in.
    #[test]
    fn legacy_grant_payload_parses_510() {
        let envelope = serde_json::json!({
            "dimension": GRANT_DIMENSION,
            "payload": {"grants": "replication", "attestation_prefixes": ["capacity:"]},
        });
        let policy = parse_grant_payload(&envelope).expect("legacy payload parses");
        assert_eq!(policy.grants, "replication");
        assert_eq!(policy.direction, Direction::Egress);
        assert_eq!(policy.kinds, vec!["Attestation".to_string()]);
        assert_eq!(policy.attestation_prefixes, vec!["capacity:".to_string()]);
        assert_eq!(policy.principle, TransmissionPrinciple::Share);
        assert_eq!(
            policy.audience,
            crate::federation::types::cohort_scope::FEDERATION
        );
        assert_eq!(policy.purpose, None);
        assert_eq!(policy.valid_until, None);
        assert!(policy.restrictions.is_empty());
    }

    #[test]
    fn parse_grant_payload_rejects_unknown_grants_token() {
        let envelope = serde_json::json!({
            "payload": {"grants": "borrow", "attestation_prefixes": ["trace:"]},
        });
        let err = parse_grant_payload(&envelope).expect_err("unknown grants token rejects");
        assert!(err.contains("grants"));
    }

    #[test]
    fn parse_grant_payload_accepts_transfer_token() {
        let envelope = serde_json::json!({
            "payload": {"grants": "transfer", "attestation_prefixes": ["trace:"]},
        });
        assert!(parse_grant_payload(&envelope).is_ok());
    }

    #[test]
    fn parse_grant_payload_rejects_bad_audience() {
        let envelope = serde_json::json!({
            "payload": {
                "grants": "transfer",
                "attestation_prefixes": ["trace:"],
                "audience": "global",
            },
        });
        let err = parse_grant_payload(&envelope).expect_err("bad audience rejects");
        assert!(err.contains("audience"));
    }

    #[test]
    fn parse_grant_payload_rejects_nonconsentable_kind() {
        let envelope = serde_json::json!({
            "payload": {
                "grants": "transfer",
                "attestation_prefixes": ["trace:"],
                "kinds": ["Key"],
            },
        });
        let err = parse_grant_payload(&envelope).expect_err("nonconsentable kind rejects");
        assert!(err.contains("Key"));
    }

    #[test]
    fn parse_grant_payload_rejects_unknown_kind_name() {
        let envelope = serde_json::json!({
            "payload": {
                "grants": "transfer",
                "attestation_prefixes": ["trace:"],
                "kinds": ["NotAKind"],
            },
        });
        assert!(parse_grant_payload(&envelope).is_err());
    }

    #[test]
    fn parse_grant_payload_rejects_unknown_restriction_op() {
        let envelope = serde_json::json!({
            "payload": {
                "grants": "transfer",
                "attestation_prefixes": ["trace:"],
                "restrictions": [{"op": "quantum_redaction"}],
            },
        });
        assert!(parse_grant_payload(&envelope).is_err());
    }

    #[test]
    fn parse_grant_payload_rejects_unknown_top_level_field() {
        let envelope = serde_json::json!({
            "payload": {
                "grants": "transfer",
                "attestation_prefixes": ["trace:"],
                "not_a_real_field": 1,
            },
        });
        assert!(parse_grant_payload(&envelope).is_err());
    }

    #[test]
    fn parse_grant_payload_accepts_strip_field_and_recipient_capability_restrictions() {
        let envelope = serde_json::json!({
            "payload": {
                "grants": "transfer",
                "attestation_prefixes": ["trace:"],
                "restrictions": [
                    {"op": "strip_field", "path": "/trace/prompt"},
                    {"op": "recipient_capability", "capability": "moderator"},
                ],
            },
        });
        let policy = parse_grant_payload(&envelope).expect("valid restrictions parse");
        assert_eq!(policy.restrictions.len(), 2);
        assert_eq!(
            policy.restrictions[0],
            RestrictionOp::StripField {
                path: "/trace/prompt".to_string()
            }
        );
        assert_eq!(
            policy.restrictions[1],
            RestrictionOp::RecipientCapability {
                capability: "moderator".to_string()
            }
        );
    }

    #[test]
    fn consent_transferability_is_exhaustive_and_only_attestation_is_consentable() {
        use crate::federation::replication_policy::EnvelopeKind;
        for k in EnvelopeKind::ALL {
            let t = consent_transferability(k);
            if k == EnvelopeKind::Attestation {
                assert_eq!(t, Transferability::Consentable);
            } else {
                assert_eq!(t, Transferability::StructuralPlane);
            }
        }
    }

    // ─────────────────── #510 P1: strip_field unit matrix ───────────

    #[test]
    fn strip_field_removes_a_nested_member() {
        let mut env = serde_json::json!({
            "dimension": "trace:complete:v1",
            "trace_id": "t-1",
            "trace": {"prompt": "secret", "response": "ok"},
        });
        strip_field(&mut env, "/trace/prompt");
        assert_eq!(
            env,
            serde_json::json!({
                "dimension": "trace:complete:v1",
                "trace_id": "t-1",
                "trace": {"response": "ok"},
            })
        );
    }

    #[test]
    fn strip_field_wildcard_over_array_strips_every_element() {
        let mut env = serde_json::json!({
            "dimension": "trace:complete:v1",
            "trace_id": "t-1",
            "trace": {
                "llm_calls": [
                    {"prompt": "p1", "model": "m1"},
                    {"prompt": "p2", "model": "m2"},
                ],
            },
        });
        strip_field(&mut env, "/trace/llm_calls/*/prompt");
        assert_eq!(
            env["trace"]["llm_calls"][0],
            serde_json::json!({"model": "m1"})
        );
        assert_eq!(
            env["trace"]["llm_calls"][1],
            serde_json::json!({"model": "m2"})
        );
    }

    #[test]
    fn strip_field_missing_path_is_a_silent_noop() {
        let mut env = serde_json::json!({
            "dimension": "trace:complete:v1",
            "trace_id": "t-1",
        });
        let before = env.clone();
        strip_field(&mut env, "/does/not/exist");
        assert_eq!(env, before, "a missing path is a no-op, not an error");
    }

    #[test]
    fn strip_field_refuses_to_remove_protected_root_members() {
        let mut env = serde_json::json!({
            "dimension": "trace:complete:v1",
            "trace_id": "t-1",
            "trace": {},
        });
        let before = env.clone();
        strip_field(&mut env, "/dimension");
        assert_eq!(env, before, "\"dimension\" at root is protected");
        strip_field(&mut env, "trace_id");
        assert_eq!(
            env, before,
            "\"trace_id\" at root is protected (no leading slash too)"
        );
    }

    #[test]
    fn strip_field_nested_field_named_dimension_is_not_protected() {
        // Root-safety only protects the ROOT member; a nested field that
        // happens to share the name is an ordinary strippable member.
        let mut env = serde_json::json!({
            "dimension": "trace:complete:v1",
            "trace_id": "t-1",
            "trace": {"dimension": "nested-not-protected"},
        });
        strip_field(&mut env, "/trace/dimension");
        assert_eq!(env["trace"], serde_json::json!({}));
    }

    #[test]
    fn strip_field_root_path_is_a_noop() {
        let mut env = serde_json::json!({"dimension": "x", "trace_id": "t"});
        let before = env.clone();
        strip_field(&mut env, "/");
        assert_eq!(env, before);
        strip_field(&mut env, "");
        assert_eq!(env, before);
    }

    // ── v21.7.0 (CIRISPersist#519 item 2a-ii, promotion application) —
    //    to_transform_ops: the single-sourced RestrictionOp → TransformOp
    //    mapping (minimal variant: no new RestrictionOp variants).

    #[test]
    fn to_transform_ops_maps_strip_field_1_to_1() {
        use crate::federation::transform::TransformOp;

        let restrictions = vec![RestrictionOp::StripField {
            path: "/trace/prompt".to_string(),
        }];
        assert_eq!(
            to_transform_ops(&restrictions),
            vec![TransformOp::StripField {
                path: "/trace/prompt".to_string(),
            }]
        );
    }

    #[test]
    fn to_transform_ops_skips_recipient_capability() {
        let restrictions = vec![RestrictionOp::RecipientCapability {
            capability: "moderator".to_string(),
        }];
        assert!(
            to_transform_ops(&restrictions).is_empty(),
            "recipient_capability carries no promotion-time transform"
        );
    }

    #[test]
    fn to_transform_ops_preserves_order_and_filters_mixed_restrictions() {
        use crate::federation::transform::TransformOp;

        let restrictions = vec![
            RestrictionOp::StripField {
                path: "/a".to_string(),
            },
            RestrictionOp::RecipientCapability {
                capability: "moderator".to_string(),
            },
            RestrictionOp::StripField {
                path: "/b".to_string(),
            },
        ];
        assert_eq!(
            to_transform_ops(&restrictions),
            vec![
                TransformOp::StripField {
                    path: "/a".to_string()
                },
                TransformOp::StripField {
                    path: "/b".to_string()
                },
            ],
            "recipient_capability is filtered out; the two strip_field ops keep their \
             relative order"
        );
    }

    #[test]
    fn to_transform_ops_empty_input_yields_empty_pipeline() {
        assert!(to_transform_ops(&[]).is_empty());
    }
}
