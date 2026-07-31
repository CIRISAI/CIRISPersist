//! (CIRISPersist#519) — the `ownership:*` ownerless-lock **reclaim
//! MECHANISM** (CC 3.2 "No permanent ownerless lock (MUST)").
//!
//! # The gap this closes
//!
//! Ownership is a `delegates_to(U → node)` on the owner-binding dimension
//! ([`super::types::owner_binding::DIMENSION`]).
//! [`super::admission::check_single_node_owner_admission`] enforces
//! at-most-one live owner (CC 2.4.1.1): a node already owned rejects a
//! DIFFERENT granter's binding — the incumbent must `withdraws`/`recants`
//! it, or it must lapse. Symmetrically,
//! [`super::admission::check_withdraws_admission`]'s CEG §3.2.3 4-rule gate
//! gives a THIRD PARTY no authority to withdraw a LIVE incumbent's
//! owner-binding (rule 1 requires `issuer == target.attesting_key_id`).
//! Put together: if the owner dies or loses custody, the live binding never
//! withdraws and the node is locked **forever** — no seizure / reclaim /
//! provably-dead path exists anywhere in this crate. That is CC 3.2's "no
//! permanent ownerless lock" violated by omission.
//!
//! # The mechanism
//!
//! [`check_ownership_reclaim_admission`] is the sanctioned exception to
//! rule 1: a THIRD PARTY's `withdraws` against a live owner-binding is
//! admitted IFF **both**:
//!
//! 1. **Provably-abandoned (FAIL-SAFE).** The incumbent owner's (and/or the
//!    owned node's) signed freshness floor
//!    ([`super::FederationDirectory::lookup_freshness_floor`], v21.6.0
//!    CIRISPersist#519 item 2a-iii) is **PRESENT and** older than
//!    `now - abandonment_window`. An ABSENT floor is NOT abandonment —
//!    absence of a signed floor is absence of evidence, not evidence of
//!    death. Only a floor that was demonstrably alive and then stopped
//!    advancing is proof (v21.8.0 activation fix; this is what makes
//!    activation safe before touch-claim producers exist — every node's
//!    floor is absent today, so zero nodes are reclaimable). This is the
//!    manifest's own "HIGHEST
//!    VALUE" `demanded_by` entry for `ownership:*`
//!    (`namespace_supersets.json` § `freshness_floor.demanded_by`):
//!    distinguishing "owner alive but quiet" from "owner provably dead" is
//!    exactly the missing input this reclaim needs — a stewardship
//!    covenant made mechanical ("the work belongs to whoever keeps it
//!    running").
//! 2. **A VERIFIED m-of-n quorum** over [`ReclaimPolicy::reclaim_quorum`]'s
//!    roster, real hybrid-signature-verified via
//!    [`ciris_verify_core::threshold::verify_quorum_policy`] — the SAME
//!    strict-majority (`2M > N`, no `M==1` escape) primitive
//!    [`super::admission::verify_accord_family_coscrub`] uses for the
//!    `canonical` / `infra:attest` / co-steward conferral ceremonies. Reuse,
//!    not reinvention: a capability grant (reclaiming a node's stewardship
//!    is exactly that) is m-of-n or reverse-quorum, never a caller-passed
//!    boolean or a 1-of-N escape hatch — the accord-ops invariant this
//!    codebase already enforces everywhere else a quorum is declared.
//!    Authority is re-derived from persist's OWN registered
//!    `federation_keys` rows (Registry-of-Record), never trusted from the
//!    caller.
//!
//! # Activated with a conservative default (v21.8.0)
//!
//! Rather than ship inert, persist ACTIVATES the mechanism with a
//! conservative default ([`ReclaimPolicy::humanity_accord_default`]) so the
//! CC 3.2 MUST is satisfied *by mechanism* today: reclaim authority = the
//! HUMANITY_ACCORD holder quorum (the body that already holds the
//! kill-switch — the least-arbitrary reclaim authority, roster resolved from
//! persist's OWN registered accord holders, strict-majority threshold) + a
//! **180-day** abandonment window. **CIRISConstitution#43 ratifies/refines the
//! two parameters (the window + the authority)** — persist ships a safe
//! default, CC sets the ratified values. This is safe to activate ahead of
//! ratification for two reasons: the abandonment test is fail-safe (an absent
//! floor is never abandonment, §1 above), so the pre-producer mesh has ZERO
//! reclaimable nodes; and an empty accord roster yields an unmeetable
//! threshold ⇒ every reclaim still refused. [`check_ownership_reclaim_admission`]
//! still accepts `Option<&ReclaimPolicy>` (`None` ⇒ the pre-v21.8.0 inert
//! behaviour, for a caller that wants it); the chokepoint in
//! [`super::admission::check_withdraws_admission`] passes the accord default.
//!
//! Concretely, a reclaim is refused unless a node has DEMONSTRABLY emitted a
//! signed freshness floor and then gone dark for 180 days AND a strict
//! majority of the accord holders co-signs — so ordinary owner-binding
//! admission (a live or never-touched owner) is unaffected, and the mesh's
//! behaviour is unchanged for every node that has not been touched-then-dark.
//!
//! # What is NOT built here
//!
//! - **The abandonment window / reclaim roster / threshold values** —
//!   CC#43's, not invented here (see above).
//! - **Producing** the reclaim `withdraws` attestation or the freshness
//!   touch-claims — edge/agent's job, documented for adoption (mirrors
//!   [`super::freshness`]'s own "value production is an attestation, not
//!   built here" scoping).
//! - **Real `n_of_m_cosigned` freshness escalation** — this module reads
//!   whatever freshness floor is stored (`self_touch` or otherwise); a
//!   collusion-resistant multi-signer "death finding" touch needs the wire-
//!   shape change [`super::freshness`] already documents as a follow-up.

use chrono::{DateTime, Duration, Utc};

use super::admission::is_owner_binding_envelope;
use super::envelope::EnvelopeCore;
use super::freshness::merge_floor;
use super::precedence::references_attestation_id_from_envelope;
use super::types::attestation_type;
use super::{Attestation, Error, FederationDirectory};
use crate::verify::canonical::ceg_produce_canonicalize;
use ciris_verify_core::threshold::{
    verify_quorum_policy, QuorumPolicy, Role, ThresholdMember, ThresholdSignature,
};

/// This module's own consumer convention for the freshness floor's
/// open-vocab `target_kind` ([`super::types::SignedTouchClaim::target_kind`])
/// — the freshness floor is generic across families
/// (`ownership:*`/`trust:*`/`consent:*`/...) and resolved by whoever
/// consumes it; this is the literal this module reads/expects a producer
/// to touch under for an `ownership:*` liveness signal.
pub const OWNERSHIP_FRESHNESS_TARGET_KIND: &str = "ownership_binding";

/// The reclaim `withdraws` envelope's dimension-specific key carrying the
/// embedded m-of-n co-signature set (a [`Vec<ThresholdSignature>`],
/// wire-identical to [`ThresholdSignature`]'s own serde shape). Rides in
/// [`EnvelopeCore::extra`] — CEG-native, not a universal envelope path.
pub const RECLAIM_QUORUM_SIGNATURES_FIELD: &str = "reclaim_quorum_signatures";

/// The per-row audit value [`super::admission::check_withdraws_admission`]
/// stamps when the reclaim exception (not one of the 4 ordinary rules)
/// admits a third-party withdraws — see
/// [`super::types::Attestation::withdraws_admission_rule`]'s doc for rules
/// 1-4; this is the reclaim mechanism's rule 5.
pub const RECLAIM_WITHDRAWS_ADMISSION_RULE: u8 = 5;

/// A named roster of key_ids that may co-sign a reclaim, plus the
/// threshold count required to sign off. **CC#43's to specify — no
/// default exists.** Verified through
/// [`ciris_verify_core::threshold::verify_quorum_policy`] (the SAME
/// strict-majority `2M > N` primitive every other m-of-n gate in this
/// codebase uses — see the module doc): even a misconfigured
/// (non-strict-majority) `threshold` fails CLOSED at verification time
/// rather than silently admitting on a weaker rule.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ReclaimQuorum {
    /// The `federation_keys.key_id`s eligible to co-sign a reclaim. Only
    /// entries that resolve to a REGISTERED key count toward `N` (mirrors
    /// [`super::admission::verify_accord_family_coscrub`]'s roster
    /// resolution — an unresolvable roster member silently doesn't
    /// count, it is never treated as a caller-supplied trust anchor).
    pub roster_key_ids: Vec<String>,
    /// The `M` distinct valid co-signatures required. Combined with the
    /// LIVE resolved roster size as `N`, this MUST satisfy the federation's
    /// one quorum rule (`2M > N`) or every reclaim under this policy fails
    /// closed (never silently downgrades to a weaker rule).
    pub threshold: usize,
}

/// The reclaim policy. As of v21.8.0 persist ships an ACTIVATED conservative
/// DEFAULT ([`ReclaimPolicy::humanity_accord_default`]) rather than staying
/// inert, so the CC 3.2 "no permanent ownerless lock" MUST is satisfied by
/// mechanism today; **CIRISConstitution#43 ratifies/refines the two
/// parameters** (the window and the reclaim authority). A caller wanting the
/// pre-v21.8.0 INERT behavior still passes `None` to
/// [`check_ownership_reclaim_admission`].
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ReclaimPolicy {
    /// An owner (and the node it stewards) whose signed freshness floor was
    /// PRESENT and has not advanced within this window is provably-abandoned.
    /// The default is [`Self::DEFAULT_ABANDONMENT_WINDOW`]; CC#43 refines it.
    pub abandonment_window: Duration,
    /// The m-of-n roster authorized to co-sign a reclaim. The default is the
    /// HUMANITY_ACCORD holder quorum (the body that already holds the
    /// kill-switch — the least-arbitrary reclaim authority); CC#43 refines it.
    pub reclaim_quorum: ReclaimQuorum,
}

impl ReclaimPolicy {
    /// The default abandonment window: **180 days**. A conservative
    /// pre-ratification value — an owner whose signed freshness floor has not
    /// advanced in half a year is plausibly gone. CC#43 sets the ratified value.
    pub const DEFAULT_ABANDONMENT_WINDOW: Duration = Duration::days(180);

    /// v21.8.0 (CIRISPersist#519 activation) — the shipped conservative
    /// default: reclaim authority = the HUMANITY_ACCORD holder quorum
    /// (`roster_key_ids`, resolved by the caller from persist's OWN registered
    /// accord holders — never caller-supplied), strict-majority threshold, and
    /// [`Self::DEFAULT_ABANDONMENT_WINDOW`]. Combined with the fail-safe
    /// abandonment test (an ABSENT floor is never abandonment), this is safe to
    /// activate before touch-claim producers exist: no node is reclaimable
    /// until it has demonstrably emitted freshness and then gone dark. CC#43
    /// ratifies the window + authority.
    pub fn humanity_accord_default(roster_key_ids: Vec<String>) -> Self {
        let n = roster_key_ids.len();
        Self {
            abandonment_window: Self::DEFAULT_ABANDONMENT_WINDOW,
            reclaim_quorum: ReclaimQuorum {
                threshold: n / 2 + 1, // strict majority; verify_quorum_policy re-validates 2M > N
                roster_key_ids,
            },
        }
    }
}

/// The outcome of [`check_ownership_reclaim_admission`].
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ReclaimVerdict {
    /// `reclaim_row` is not a third-party reclaim of a live owner-binding
    /// at all (wrong attestation_type, no resolvable target, target isn't
    /// an owner-binding, or the "third party" is actually the incumbent
    /// owner itself — ordinary self-revocation, rule 1's territory, never
    /// this mechanism's). A pure no-op: callers should fall through to
    /// their normal admission logic exactly as if this function did not
    /// exist.
    NotAReclaim,
    /// The reclaim is ADMITTED: the incumbent is provably-abandoned AND a
    /// verified m-of-n quorum (per `policy.reclaim_quorum`) co-signed it.
    Admit,
    /// The reclaim is refused — including, ALWAYS, when `policy` is
    /// `None` (the shipped default; see the module doc). `reason` is a
    /// human-readable diagnostic, not a stable machine token (this
    /// mechanism is inert in production today; no consumer parses it).
    Refused {
        /// Why the reclaim was refused.
        reason: String,
    },
}

/// Build the canonical bytes a reclaim's m-of-n quorum co-signs: a small,
/// independently-reconstructable "reclaim assertion" binding the target
/// owner-binding attestation, its incumbent owner, the owned node, and the
/// reclaiming issuer. Deliberately NOT the reclaim row's own
/// `attestation_envelope` bytes — embedding co-signatures inside the very
/// envelope they sign is a fixed-point problem; signing a derived object
/// reconstructed from already-known fields (mirroring how
/// [`super::types::SignedTouchClaim::signing_envelope`] separates the
/// signed form from storage) sidesteps it entirely.
fn reclaim_assertion_bytes(
    target: &Attestation,
    reclaimer_key_id: &str,
) -> Result<Vec<u8>, String> {
    let assertion = serde_json::json!({
        "kind": "ownership_reclaim:v1",
        "target_attestation_id": target.attestation_id,
        "incumbent_owner_key_id": target.attesting_key_id,
        "node_key_id": target.attested_key_id,
        "reclaimer_key_id": reclaimer_key_id,
    });
    ceg_produce_canonicalize(&assertion)
        .map_err(|e| format!("reclaim assertion canonicalize failed: {e}"))
}

/// Read the embedded m-of-n co-signature set from a reclaim row's
/// envelope (see [`RECLAIM_QUORUM_SIGNATURES_FIELD`]). Absent/malformed
/// → empty (never a hard error here — an empty/garbage set simply fails
/// the quorum check like any other insufficient submission).
fn reclaim_quorum_signatures_from_envelope(
    envelope: &serde_json::Value,
) -> Vec<ThresholdSignature> {
    envelope
        .get(RECLAIM_QUORUM_SIGNATURES_FIELD)
        .and_then(|v| serde_json::from_value::<Vec<ThresholdSignature>>(v.clone()).ok())
        .unwrap_or_default()
}

/// Build a reclaim `withdraws` envelope carrying `quorum_sigs` — the
/// producer-side counterpart [`reclaim_quorum_signatures_from_envelope`]
/// reads. Exposed so a real producer (edge/agent) or a test fixture builds
/// a wire-correct envelope without hand-rolling the JSON shape.
#[must_use]
pub fn build_reclaim_withdraws_envelope(
    target_attestation_id: &str,
    quorum_sigs: &[ThresholdSignature],
) -> serde_json::Value {
    let mut extra = serde_json::Map::new();
    extra.insert(
        RECLAIM_QUORUM_SIGNATURES_FIELD.to_owned(),
        serde_json::to_value(quorum_sigs).expect("ThresholdSignature serializes"),
    );
    EnvelopeCore {
        references_attestation_id: Some(target_attestation_id.to_owned()),
        extra,
        ..Default::default()
    }
    .to_value()
}

/// **The CC 3.2 "no permanent ownerless lock" reclaim admission gate.**
/// See the module doc for the full mechanism + why it ships inert.
///
/// `reclaim_row` is the candidate `withdraws` attestation (NOT YET
/// admitted by the ordinary CEG §3.2.3 rules — this function is the
/// EXCEPTION path a caller consults after the ordinary rules refuse it,
/// see [`super::admission::check_withdraws_admission`]). `now` is the
/// caller's wall-clock (threaded explicitly so tests are deterministic).
pub async fn check_ownership_reclaim_admission(
    directory: &dyn FederationDirectory,
    reclaim_row: &Attestation,
    policy: Option<&ReclaimPolicy>,
    now: DateTime<Utc>,
) -> Result<ReclaimVerdict, Error> {
    // (1) Shape check: is this even a candidate reclaim? A pure no-op
    // otherwise — callers fall through to their normal logic unchanged.
    if reclaim_row.attestation_type != attestation_type::WITHDRAWS {
        return Ok(ReclaimVerdict::NotAReclaim);
    }
    let Some(target_id) =
        references_attestation_id_from_envelope(&reclaim_row.attestation_envelope)
    else {
        return Ok(ReclaimVerdict::NotAReclaim);
    };
    let Some(target) = directory.get_attestation(target_id).await? else {
        return Ok(ReclaimVerdict::NotAReclaim);
    };
    if !is_owner_binding_envelope(&target.attestation_envelope) {
        return Ok(ReclaimVerdict::NotAReclaim);
    }
    // Self-withdrawal (the incumbent revoking their OWN binding) is
    // ordinary rule-1 authority — never a reclaim, regardless of policy.
    if reclaim_row.attesting_key_id == target.attesting_key_id {
        return Ok(ReclaimVerdict::NotAReclaim);
    }

    // (2) Inert-by-default: no policy, no reclaim. Fail-closed, not a
    // silent no-op — the node stays locked, correctly, until CC#43.
    let Some(policy) = policy else {
        return Ok(ReclaimVerdict::Refused {
            reason: "no ReclaimPolicy configured — the mechanism ships inert pending \
                     CIRISConstitution#43"
                .to_owned(),
        });
    };

    // (3a) Provably-abandoned: the incumbent's (and/or the node's) signed
    // freshness floor is PRESENT and older than `now - abandonment_window`.
    //
    // v21.8.0 (CIRISPersist#519, activation) — FAIL-SAFE: an ABSENT floor is
    // NOT abandonment. Absence of a signed freshness floor is absence of
    // evidence, not evidence of death — treating it as abandoned would make
    // EVERY node reclaimable before any touch-claim producer exists (no node
    // has a floor yet), i.e. a mass-seizable mesh the instant a policy is
    // injected. Only a floor that was DEMONSTRABLY alive (present) and then
    // stopped advancing past the window is proof of abandonment. Consequence
    // (documented, tracked): a node whose owner NEVER emitted a floor stays
    // unreclaimable until ownership-establishment bootstraps an initial touch
    // (a #519 follow-up); the CC 3.2 MUST is satisfied for the touched-then-
    // dark case, which is the real-world one once producers ship.
    let incumbent = target.attesting_key_id.as_str();
    let node = target.attested_key_id.as_str();
    let incumbent_floor = directory
        .lookup_freshness_floor(incumbent, OWNERSHIP_FRESHNESS_TARGET_KIND)
        .await?;
    let node_floor = directory
        .lookup_freshness_floor(node, OWNERSHIP_FRESHNESS_TARGET_KIND)
        .await?;
    let latest = match (incumbent_floor, node_floor) {
        (Some(a), Some(b)) => Some(merge_floor(a.fresh_as_of, b.fresh_as_of)),
        (Some(a), None) => Some(a.fresh_as_of),
        (None, Some(b)) => Some(b.fresh_as_of),
        (None, None) => None,
    };
    let cutoff = now - policy.abandonment_window;
    // is_some_and: absent floor ⇒ false ⇒ NOT abandoned (fail-safe).
    let abandoned = latest.is_some_and(|f| f < cutoff);
    if !abandoned {
        return Ok(ReclaimVerdict::Refused {
            reason: match latest {
                None => format!(
                    "incumbent owner {incumbent} (and node {node}) have NO signed freshness \
                     floor — absence is not proof of abandonment (fail-safe); not reclaimable"
                ),
                Some(_) => format!(
                    "incumbent owner {incumbent} (or node {node}) has a freshness floor within \
                     the {}s abandonment window — not abandoned",
                    policy.abandonment_window.num_seconds()
                ),
            },
        });
    }

    // (3b) A VERIFIED m-of-n quorum, re-derived from persist's OWN
    // registered keys (Registry-of-Record) — never a caller-passed
    // boolean.
    let bytes = match reclaim_assertion_bytes(&target, &reclaim_row.attesting_key_id) {
        Ok(b) => b,
        Err(reason) => return Ok(ReclaimVerdict::Refused { reason }),
    };
    let mut roster: Vec<ThresholdMember> =
        Vec::with_capacity(policy.reclaim_quorum.roster_key_ids.len());
    for kid in &policy.reclaim_quorum.roster_key_ids {
        if let Some(rec) = directory.lookup_public_key(kid).await? {
            roster.push(ThresholdMember {
                member_id: rec.key_id,
                ed25519_public_key_base64: rec.pubkey_ed25519_base64,
                mldsa65_public_key_base64: rec.pubkey_ml_dsa_65_base64,
                role: Some(Role::Founder),
            });
        }
    }
    let n = roster.len();
    let qp = QuorumPolicy::new(policy.reclaim_quorum.threshold, n);
    let sigs = reclaim_quorum_signatures_from_envelope(&reclaim_row.attestation_envelope);
    match verify_quorum_policy(&bytes, &roster, &sigs, qp) {
        Ok(_) => Ok(ReclaimVerdict::Admit),
        Err(e) => Ok(ReclaimVerdict::Refused {
            reason: format!("reclaim quorum not met ({}-of-{n}): {e}", qp.m),
        }),
    }
}

#[cfg(all(test, any(feature = "sqlite", feature = "postgres")))]
mod tests {
    use super::*;
    use crate::engine::Engine;
    use crate::federation::tier_ingest::test_support as ts;
    use crate::federation::types::{attestation_tier, cohort_scope, identity_type, SignerForm};
    use crate::federation::{FederationDirectory, SignedAttestation, SignedTouchClaim};
    use crate::signing::LocalSigner;
    use ed25519_dalek::SigningKey;
    use std::sync::Arc;

    fn test_signer() -> Arc<LocalSigner> {
        let signing_key = SigningKey::from_bytes(&[0x9Cu8; 32]);
        Arc::new(LocalSigner::from_parts(
            signing_key,
            "ownership-reclaim-test-steward".to_string(),
            None,
            None,
        ))
    }

    /// Build + hybrid-sign a `SignedTouchClaim` via `ts::sign_envelope`'s
    /// DETERMINISTIC per-key_id signer — the same signer
    /// [`ts::register_identity_key`] / [`ts::owner_binding_attestation`]
    /// register/sign with, so one `register_identity_key` call serves
    /// both the owner-binding AND its self-touch claim. `self_touch`
    /// requires `attesting_key_id == target_key_id`.
    fn self_touch_claim(target_key_id: &str, fresh_as_of: DateTime<Utc>) -> SignedTouchClaim {
        let unsigned = SignedTouchClaim {
            target_key_id: target_key_id.to_owned(),
            target_kind: OWNERSHIP_FRESHNESS_TARGET_KIND.to_owned(),
            fresh_as_of,
            signer_form: SignerForm::SelfTouch,
            attesting_key_id: target_key_id.to_owned(),
            signed_envelope: serde_json::Value::Null,
            signature: ciris_verify_core::transport_binding::TransportBindingSignature {
                ed25519_signature_base64: String::new(),
                mldsa65_signature_base64: None,
            },
            cohort_scope: cohort_scope::SELF.to_owned(),
        };
        let env = unsigned.signing_envelope();
        let (_hash, classical, pqc) = ts::sign_envelope(target_key_id, &env);
        SignedTouchClaim {
            signed_envelope: env,
            signature: ciris_verify_core::transport_binding::TransportBindingSignature {
                ed25519_signature_base64: classical,
                mldsa65_signature_base64: pqc,
            },
            ..unsigned
        }
    }

    /// Build a reclaim `withdraws` [`Attestation`] against `target`, issued
    /// by `reclaimer`, embedding `quorum_sigs`. Hybrid-signed by
    /// `reclaimer`'s deterministic key via `ts::sign_envelope` (the row's
    /// OWN primary signature — orthogonal to the embedded quorum, which is
    /// what [`check_ownership_reclaim_admission`] actually verifies).
    /// `attestation_id` is a fresh UUID (the postgres backend's column is
    /// `::uuid`-typed — see `reference_test_fixtures_uuid_vs_uuid_like` —
    /// so a human-readable tag string is REJECTED by that backend, sqlite's
    /// laxer TEXT column just happened not to notice).
    fn reclaim_row(
        reclaimer: &str,
        target: &Attestation,
        quorum_sigs: &[ThresholdSignature],
    ) -> Attestation {
        let envelope = build_reclaim_withdraws_envelope(&target.attestation_id, quorum_sigs);
        let (och, classical, pqc) = ts::sign_envelope(reclaimer, &envelope);
        let ts_now: DateTime<Utc> = Utc::now();
        Attestation {
            attestation_id: uuid::Uuid::new_v4().to_string(),
            attesting_key_id: reclaimer.to_owned(),
            attested_key_id: target.attested_key_id.clone(),
            attestation_type: attestation_type::WITHDRAWS.to_owned(),
            weight: None,
            asserted_at: ts_now,
            expires_at: None,
            attestation_envelope: envelope,
            original_content_hash: och,
            scrub_signature_classical: classical,
            scrub_signature_pqc: pqc,
            scrub_key_id: reclaimer.to_owned(),
            scrub_timestamp: ts_now,
            pqc_completed_at: None,
            persist_row_hash: String::new(),
            subject_key_ids: Vec::new(),
            withdraws_admission_rule: None,
            cohort_scope: "federation".to_owned(),
            tier: attestation_tier::FEDERATION.to_owned(),
            promoted_at: None,
            additional_scrubs: Vec::new(),
        }
    }

    /// Shared fixture: register an incumbent owner + node + reclaimer, and
    /// admit a LIVE owner-binding `delegates_to(owner → node)` through the
    /// REAL production gate ([`FederationDirectory::put_attestation`]).
    /// Returns the stored owner-binding row (its `attestation_id` is what a
    /// reclaim's `references_attestation_id` names).
    async fn seed_owner_binding(
        dir: &dyn FederationDirectory,
        tag: &str,
    ) -> (String, String, String, Attestation) {
        let owner = format!("recl-owner-{tag}");
        let node = format!("recl-node-{tag}");
        let reclaimer = format!("recl-reclaimer-{tag}");
        ts::register_identity_key(dir, &owner, identity_type::USER).await;
        ts::register_identity_key(dir, &node, identity_type::NODE).await;
        ts::register_identity_key(dir, &reclaimer, identity_type::USER).await;

        // A fresh UUID, not a human-readable tag: the postgres backend's
        // `attestation_id` column is `::uuid`-typed (sqlite's laxer TEXT
        // column doesn't enforce this — see
        // `reference_test_fixtures_uuid_vs_uuid_like`).
        let binding_id = uuid::Uuid::new_v4().to_string();
        dir.put_attestation(SignedAttestation {
            attestation: ts::owner_binding_attestation(&binding_id, &owner, &node),
        })
        .await
        .expect("owner-binding admitted via the real gate");
        let target = dir
            .get_attestation(&binding_id)
            .await
            .unwrap()
            .expect("owner-binding row stored");
        (owner, node, reclaimer, target)
    }

    /// A 2-of-3 [`ReclaimPolicy`] over a freshly-registered 3-member
    /// roster (all real, distinct hybrid keys).
    async fn two_of_three_policy(
        dir: &dyn FederationDirectory,
        tag: &str,
        abandonment_window: Duration,
    ) -> (ReclaimPolicy, [String; 3]) {
        let roster = [
            format!("recl-quorum-a-{tag}"),
            format!("recl-quorum-b-{tag}"),
            format!("recl-quorum-c-{tag}"),
        ];
        for r in &roster {
            ts::register_hybrid_key(dir, r).await;
        }
        let policy = ReclaimPolicy {
            abandonment_window,
            reclaim_quorum: ReclaimQuorum {
                roster_key_ids: roster.to_vec(),
                threshold: 2,
            },
        };
        (policy, roster)
    }

    // ── witness: non_reclaim_row_is_noop ────────────────────────────────

    async fn run_non_reclaim_row_is_noop(dir: &dyn FederationDirectory, tag: &str) {
        let (owner, _node, reclaimer, target) = seed_owner_binding(dir, tag).await;
        let now = Utc::now();

        // (a) not even a `withdraws` — an ordinary `scores`-shaped row.
        let mut not_withdraws = reclaim_row(&reclaimer, &target, &[]);
        not_withdraws.attestation_type = "scores".to_owned();
        assert_eq!(
            check_ownership_reclaim_admission(dir, &not_withdraws, None, now)
                .await
                .unwrap(),
            ReclaimVerdict::NotAReclaim,
            "a non-withdraws row must never be treated as a reclaim"
        );

        // (b) a withdraws targeting something that ISN'T an owner-binding —
        // an ordinary (non-owner) `delegates_to`, the act-on-behalf/
        // hierarchy shape `check_single_node_owner_admission` and
        // `is_owner_binding_envelope` both explicitly leave untouched (no
        // `dimension` / `delegation_purpose` owner-binding marker).
        let plain_id = format!("nr-b-target-{tag}");
        let plain_envelope = serde_json::json!({
            "id": plain_id,
            "kind": "delegates_to",
            "scope": ["infra:serve"],
        });
        let (och, classical, pqc) = ts::sign_envelope(&owner, &plain_envelope);
        let plain_ts = Utc::now();
        // Row id is a fresh UUID (postgres's `::uuid` column) — `plain_id`
        // above is just descriptive envelope content, not the row key.
        let non_owner_target = Attestation {
            attestation_id: uuid::Uuid::new_v4().to_string(),
            attesting_key_id: owner.clone(),
            attested_key_id: target.attested_key_id.clone(),
            attestation_type: attestation_type::DELEGATES_TO.to_owned(),
            weight: Some(1.0),
            asserted_at: plain_ts,
            expires_at: None,
            attestation_envelope: plain_envelope,
            original_content_hash: och,
            scrub_signature_classical: classical,
            scrub_signature_pqc: pqc,
            scrub_key_id: owner.clone(),
            scrub_timestamp: plain_ts,
            pqc_completed_at: None,
            persist_row_hash: String::new(),
            subject_key_ids: Vec::new(),
            withdraws_admission_rule: None,
            cohort_scope: "federation".to_owned(),
            tier: attestation_tier::FEDERATION.to_owned(),
            promoted_at: None,
            additional_scrubs: Vec::new(),
        };
        dir.put_attestation(SignedAttestation {
            attestation: non_owner_target.clone(),
        })
        .await
        .expect("plain (non-owner) delegates_to admitted");
        let withdraws_non_owner = reclaim_row(&reclaimer, &non_owner_target, &[]);
        assert_eq!(
            check_ownership_reclaim_admission(dir, &withdraws_non_owner, None, now)
                .await
                .unwrap(),
            ReclaimVerdict::NotAReclaim,
            "a withdraws against a non-owner-binding target is not this mechanism's concern"
        );

        // (c) self-withdrawal — the incumbent revoking their OWN binding.
        let self_withdraw = reclaim_row(&owner, &target, &[]);
        assert_eq!(
            check_ownership_reclaim_admission(dir, &self_withdraw, None, now)
                .await
                .unwrap(),
            ReclaimVerdict::NotAReclaim,
            "self-withdrawal is ordinary rule-1 authority, never a reclaim"
        );
    }

    #[cfg(feature = "sqlite")]
    #[tokio::test]
    async fn non_reclaim_row_is_noop() {
        let engine = Engine::with_signer(test_signer(), "sqlite::memory:")
            .await
            .expect("construct sqlite engine");
        let dir = engine.federation_directory();
        run_non_reclaim_row_is_noop(&*dir, "sq").await;
    }

    // ── witness: reclaim_inert_without_policy_refuses ───────────────────

    async fn run_reclaim_inert_without_policy_refuses(dir: &dyn FederationDirectory, tag: &str) {
        let (owner, _node, reclaimer, target) = seed_owner_binding(dir, tag).await;
        // v21.8.0 fail-safe: the control below (WITH a policy → Admit) needs a
        // genuinely-abandoned owner, i.e. a PRESENT-then-stale floor.
        let stale = self_touch_claim(&owner, Utc::now() - Duration::days(60));
        dir.put_touch_claim(&stale).await.expect("stale self-touch");
        let (policy, roster) = two_of_three_policy(dir, tag, Duration::days(30)).await;
        let bytes = reclaim_assertion_bytes(&target, &reclaimer).unwrap();
        let sigs = vec![
            ts::threshold_sign(&roster[0], &bytes),
            ts::threshold_sign(&roster[1], &bytes),
        ];
        let row = reclaim_row(&reclaimer, &target, &sigs);

        // A well-formed reclaim (satisfies quorum + provably-abandoned via the
        // stale floor above) — but policy is None ⇒ always refused.
        match check_ownership_reclaim_admission(dir, &row, None, Utc::now())
            .await
            .unwrap()
        {
            ReclaimVerdict::Refused { .. } => {}
            other => panic!("policy=None must ALWAYS refuse, got {other:?}"),
        }
        // Sanity: the SAME row, SAME quorum, WITH the policy, admits — so
        // the None-refusal above is really the policy gate, not some other
        // defect in the fixture.
        assert_eq!(
            check_ownership_reclaim_admission(dir, &row, Some(&policy), Utc::now())
                .await
                .unwrap(),
            ReclaimVerdict::Admit,
            "control: the identical well-formed reclaim admits once a policy is injected"
        );
    }

    #[cfg(feature = "sqlite")]
    #[tokio::test]
    async fn reclaim_inert_without_policy_refuses() {
        let engine = Engine::with_signer(test_signer(), "sqlite::memory:")
            .await
            .expect("construct sqlite engine");
        let dir = engine.federation_directory();
        run_reclaim_inert_without_policy_refuses(&*dir, "sq").await;
    }

    // ── witness: reclaim_admits_abandoned_owner_with_quorum ─────────────

    async fn run_reclaim_admits_abandoned_owner_with_quorum(
        dir: &dyn FederationDirectory,
        tag: &str,
    ) {
        let (owner, _node, reclaimer, target) = seed_owner_binding(dir, tag).await;
        // v21.8.0 fail-safe semantics: PROVABLE abandonment requires a floor
        // that was PRESENT and then went stale (absence is not proof — see
        // reclaim_refuses_absent_floor). Store a stale self-touch (60 days ago),
        // well outside the 30-day window.
        let stale = self_touch_claim(&owner, Utc::now() - Duration::days(60));
        dir.put_touch_claim(&stale)
            .await
            .expect("a past-dated self-touch is admitted (not future-skewed)");
        let (policy, roster) = two_of_three_policy(dir, tag, Duration::days(30)).await;
        let bytes = reclaim_assertion_bytes(&target, &reclaimer).unwrap();
        let sigs = vec![
            ts::threshold_sign(&roster[0], &bytes),
            ts::threshold_sign(&roster[2], &bytes),
        ];
        let row = reclaim_row(&reclaimer, &target, &sigs);
        assert_eq!(
            check_ownership_reclaim_admission(dir, &row, Some(&policy), Utc::now())
                .await
                .unwrap(),
            ReclaimVerdict::Admit,
            "a present-then-stale (provably-abandoned) owner + a real 2-of-3 quorum must admit"
        );
    }

    /// v21.8.0 (CIRISPersist#519 activation) — the shipped conservative
    /// default: a 180-day window + a strict-majority accord quorum. Locks the
    /// pre-ratification parameters CC#43 will confirm/refine; an empty roster
    /// yields threshold 1 over 0 members (unmeetable) — fail-closed.
    #[test]
    fn humanity_accord_default_is_conservative() {
        let p = ReclaimPolicy::humanity_accord_default(vec!["A1".into(), "B1".into(), "C1".into()]);
        assert_eq!(p.abandonment_window, Duration::days(180));
        assert_eq!(p.reclaim_quorum.threshold, 2, "strict majority of 3");
        assert_eq!(p.reclaim_quorum.roster_key_ids.len(), 3);
        // empty roster ⇒ threshold 1, roster 0 ⇒ no quorum ever meetable.
        let empty = ReclaimPolicy::humanity_accord_default(vec![]);
        assert_eq!(empty.reclaim_quorum.threshold, 1);
        assert!(empty.reclaim_quorum.roster_key_ids.is_empty());
    }

    /// v21.8.0 (CIRISPersist#519 activation) — the FAIL-SAFE: an owner with NO
    /// signed freshness floor at all is NOT reclaimable, even with a valid
    /// quorum and a policy. Absence of a floor is absence of evidence, not
    /// proof of death — this is what makes activation safe before any
    /// touch-claim producer exists (every node's floor is absent today).
    #[cfg(feature = "sqlite")]
    #[tokio::test]
    async fn reclaim_refuses_absent_floor() {
        let engine = Engine::with_signer(test_signer(), "sqlite::memory:")
            .await
            .expect("construct sqlite engine");
        let dir = engine.federation_directory();
        let (_owner, _node, reclaimer, target) = seed_owner_binding(&*dir, "absent").await;
        // No touch claim stored → floor absent.
        let (policy, roster) = two_of_three_policy(&*dir, "absent", Duration::days(30)).await;
        let bytes = reclaim_assertion_bytes(&target, &reclaimer).unwrap();
        let sigs = vec![
            ts::threshold_sign(&roster[0], &bytes),
            ts::threshold_sign(&roster[2], &bytes),
        ];
        let row = reclaim_row(&reclaimer, &target, &sigs);
        assert!(
            matches!(
                check_ownership_reclaim_admission(&*dir, &row, Some(&policy), Utc::now())
                    .await
                    .unwrap(),
                ReclaimVerdict::Refused { .. }
            ),
            "an absent freshness floor is not abandonment — reclaim must be refused (fail-safe)"
        );
    }

    #[cfg(feature = "sqlite")]
    #[tokio::test]
    async fn reclaim_admits_abandoned_owner_with_quorum() {
        let engine = Engine::with_signer(test_signer(), "sqlite::memory:")
            .await
            .expect("construct sqlite engine");
        let dir = engine.federation_directory();
        run_reclaim_admits_abandoned_owner_with_quorum(&*dir, "sq").await;
    }

    // ── witness: reclaim_refuses_live_owner ─────────────────────────────

    async fn run_reclaim_refuses_live_owner(dir: &dyn FederationDirectory, tag: &str) {
        let (owner, _node, reclaimer, target) = seed_owner_binding(dir, tag).await;
        let now = Utc::now();
        // The owner touched recently — well within the 30-day window.
        let claim = self_touch_claim(&owner, now - Duration::minutes(5));
        dir.put_touch_claim(&claim)
            .await
            .expect("fresh self-touch admitted");

        let (policy, roster) = two_of_three_policy(dir, tag, Duration::days(30)).await;
        let bytes = reclaim_assertion_bytes(&target, &reclaimer).unwrap();
        let sigs = vec![
            ts::threshold_sign(&roster[0], &bytes),
            ts::threshold_sign(&roster[1], &bytes),
        ];
        let row = reclaim_row(&reclaimer, &target, &sigs);
        match check_ownership_reclaim_admission(dir, &row, Some(&policy), now)
            .await
            .unwrap()
        {
            ReclaimVerdict::Refused { .. } => {}
            other => panic!("a live (recently-touched) owner must be Refused, got {other:?}"),
        }
    }

    #[cfg(feature = "sqlite")]
    #[tokio::test]
    async fn reclaim_refuses_live_owner() {
        let engine = Engine::with_signer(test_signer(), "sqlite::memory:")
            .await
            .expect("construct sqlite engine");
        let dir = engine.federation_directory();
        run_reclaim_refuses_live_owner(&*dir, "sq").await;
    }

    // ── witness: reclaim_refuses_insufficient_quorum ────────────────────

    async fn run_reclaim_refuses_insufficient_quorum(dir: &dyn FederationDirectory, tag: &str) {
        let (_owner, _node, reclaimer, target) = seed_owner_binding(dir, tag).await;
        let (policy, roster) = two_of_three_policy(dir, tag, Duration::days(30)).await;
        let bytes = reclaim_assertion_bytes(&target, &reclaimer).unwrap();

        // (a) sub-threshold: only 1 of the required 2 signs.
        let sigs_short = vec![ts::threshold_sign(&roster[0], &bytes)];
        let row_short = reclaim_row(&reclaimer, &target, &sigs_short);
        match check_ownership_reclaim_admission(dir, &row_short, Some(&policy), Utc::now())
            .await
            .unwrap()
        {
            ReclaimVerdict::Refused { .. } => {}
            other => panic!("sub-threshold quorum must be Refused, got {other:?}"),
        }

        // (b) forged: 2 submissions, but one signature is corrupted, so
        // only 1 counts as valid — still insufficient.
        use base64::{engine::general_purpose::STANDARD as B64, Engine as _};
        let mut forged = ts::threshold_sign(&roster[1], &bytes);
        forged.ed25519_signature_base64 = B64.encode([0u8; 64]);
        let sigs_forged = vec![ts::threshold_sign(&roster[0], &bytes), forged];
        let row_forged = reclaim_row(&reclaimer, &target, &sigs_forged);
        match check_ownership_reclaim_admission(dir, &row_forged, Some(&policy), Utc::now())
            .await
            .unwrap()
        {
            ReclaimVerdict::Refused { .. } => {}
            other => panic!("a forged co-signature must not count, got {other:?}"),
        }
    }

    #[cfg(feature = "sqlite")]
    #[tokio::test]
    async fn reclaim_refuses_insufficient_quorum() {
        let engine = Engine::with_signer(test_signer(), "sqlite::memory:")
            .await
            .expect("construct sqlite engine");
        let dir = engine.federation_directory();
        run_reclaim_refuses_insufficient_quorum(&*dir, "sq").await;
    }

    // ── the same 5 witnesses, once more, against postgres when reachable ─

    #[cfg(feature = "postgres")]
    #[tokio::test]
    async fn ownership_reclaim_matrix_postgres() {
        let Ok(dsn) = std::env::var("CIRIS_PERSIST_TEST_PG_URL") else {
            eprintln!(
                "skipping ownership_reclaim_matrix_postgres: CIRIS_PERSIST_TEST_PG_URL unset"
            );
            return;
        };
        let engine = Engine::with_signer(test_signer(), &dsn)
            .await
            .expect("construct postgres engine");
        let dir = engine.federation_directory();
        let tag = format!("pg-{}", uuid::Uuid::new_v4().simple());
        run_non_reclaim_row_is_noop(&*dir, &format!("nr-{tag}")).await;
        run_reclaim_inert_without_policy_refuses(&*dir, &format!("inert-{tag}")).await;
        run_reclaim_admits_abandoned_owner_with_quorum(&*dir, &format!("admit-{tag}")).await;
        run_reclaim_refuses_live_owner(&*dir, &format!("live-{tag}")).await;
        run_reclaim_refuses_insufficient_quorum(&*dir, &format!("short-{tag}")).await;
    }
}
