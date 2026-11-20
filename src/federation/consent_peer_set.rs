//! v21.0.0 (CIRISPersist#502 E7) — the `consent_peer_set` projection (V109):
//! the node's LIVE `consent:replication:v1` peer grants, revocation-folded.
//!
//! # The hole this closes
//!
//! `consent:replication:v1` is a directed `scores` attestation: the node
//! attests it (`attesting_key_id` = node), and the peers it consents to
//! replicate to ride `subject_key_ids`. CIRISServer's
//! `replication_peers_from_consent` (`src/peer.rs`, `CONSENT_DIMENSION =
//! "consent:replication:v1"`) read this via `list_attestations_by(node) →
//! filter dimension == CONSENT_DIMENSION → flat_map(subject_key_ids)` — but
//! never folded a subsequent `withdraws`/`recants` against the grant, so a
//! peer whose consent was revoked kept receiving replication forever
//! (`TODO(consent revocation)`).
//!
//! # The fix
//!
//! `put_attestation` maintains `consent_peer_set` IN the same write as the
//! attestation insert (mirrors the V106 `attestation_subjects` projection):
//!
//! - a grant ([`is_consent_replication_grant`]) upserts one row per
//!   `subject_key_ids[]` peer, `(node_key_id, peer_key_id)` keyed;
//! - a structural composer ([`super::precedence::is_structural_composer`])
//!   whose envelope's `references_attestation_id`
//!   ([`revocation_fold_target`]) names a grant DELETEs every row this
//!   projection sourced from that grant (`source_attestation_id`).
//!
//! So a server-side reader does a trivial already-revocation-filtered
//! SELECT instead of re-deriving the fold itself. DERIVED / rebuildable:
//! this table is a read accelerator over `federation_attestations`, not new
//! authority — it can be reconstructed at any time from a full replay of
//! the `consent:replication:v1` grants and their withdraws/recants.

/// The consent-replication grant dimension. `attesting_key_id` = the
/// granting node; `subject_key_ids` = the peers it consents to replicate
/// to. A `withdraws`/`recants` referencing a grant's `attestation_id`
/// revokes every peer that grant named (see [`revocation_fold_target`]).
pub const DIMENSION: &str = "consent:replication:v1";

/// True iff `row` is a live `consent:replication:v1` grant — the
/// projection's upsert input (one row per `row.subject_key_ids[]` peer).
#[must_use]
pub fn is_consent_replication_grant(row: &super::Attestation) -> bool {
    crate::federation::admission::envelope_dimension(&row.attestation_envelope) == Some(DIMENSION)
}

/// The upstream attestation id a structural composer's revocation fold
/// should DELETE `consent_peer_set` rows for (matched on
/// `source_attestation_id`), or `None` if `row` is not a structural
/// composer ([`super::precedence::is_structural_composer`]) or carries no
/// `references_attestation_id`.
///
/// No existence check against `consent_peer_set` is needed here: the
/// DELETE is a no-op if the referenced id never sourced a row (e.g. a
/// `withdraws` against an unrelated attestation), so this is safe to call
/// unconditionally for every structural composer.
#[must_use]
pub fn revocation_fold_target(row: &super::Attestation) -> Option<&str> {
    if !super::precedence::is_structural_composer(&row.attestation_type) {
        return None;
    }
    super::precedence::references_attestation_id_from_envelope(&row.attestation_envelope)
}

/// v21.0.0 (CIRISPersist#502 E7) — the shared, backend-agnostic
/// `consent_peer_set` revocation-fold witness, run by the sqlite / postgres
/// test suites against `&dyn FederationDirectory` so the two SQL backends
/// cannot silently diverge on the fold (the CIRISConformance parity rule;
/// see `self_at_login::test_support` for the same pattern). `suffix` scopes
/// every fixture id so a run against a shared test DB (postgres) doesn't
/// collide with a prior run.
// The shared fold-witness body is consumed only by the sqlite/postgres
// parity tests; under a no-backend build (`--features server`) those
// callers are absent, so gate the module on a backend to avoid dead_code
// under `-D warnings`.
#[cfg(all(test, any(feature = "sqlite", feature = "postgres")))]
pub(crate) mod test_support {
    use super::DIMENSION;
    use crate::federation::types::{attestation_tier, attestation_type};
    use crate::federation::{Attestation, FederationDirectory};

    pub(crate) fn grant(id: &str, node: &str, peer: &str) -> Attestation {
        // v21.3.0 (CIRISPersist#510 P1) — a `consent:replication:v1` row
        // now admits through the closed-grammar gate (`put_attestation`),
        // so this E7/#509 projection fixture needs a minimally-valid
        // `payload` (the prefix content is irrelevant to these tests —
        // they exercise the peer-set fold / list methods, not grammar
        // semantics).
        let envelope = serde_json::json!({
            "dimension": DIMENSION,
            "payload": {"grants": "replication", "attestation_prefixes": ["e7-fixture:"]},
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
            subject_key_ids: vec![peer.to_owned()],
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

    /// v62.0.0 — a `withdraws` of `target` by `issuer`: an edition-2
    /// composer naming the target by its row id (`refs.target`), in the
    /// target's family (E0's `composer_of`). The earlier form's free
    /// `references_attestation_id` / `withdrawal_reason` envelope is not a
    /// member of the composer's payload.
    fn withdraws(issuer: &str, target: &Attestation) -> Attestation {
        crate::federation::edition2::fixture_switch::composer_of("withdraws", target, issuer)
    }

    /// A grant to peer P1 makes `list_consent_peers` include P1; a
    /// `withdraws` referencing the grant's `attestation_id` REMOVES P1; an
    /// untouched second grant to P2 survives. Exercised identically against
    /// every backend that passes `dir` in — the parity assertion IS this
    /// shared body running against two different `Arc<dyn
    /// FederationDirectory>`s. `attestation_id`s are real UUIDs (not
    /// suffix-templated strings) because postgres's `federation_attestations`
    /// binds `attestation_id::uuid`; `suffix` scopes only the node/peer
    /// `key_id`s (plain TEXT) so a shared postgres test DB doesn't collide.
    pub(crate) async fn exercise_consent_peer_set_fold(
        dir: &dyn FederationDirectory,
        suffix: &str,
    ) {
        // v62.0.0 — the node's key is an edition-2 `key:record` (`kid(node)`);
        // the grants are its statements (E0's flipped `grant`), put through
        // the statement door, and every id read back is a kid.
        use crate::federation::edition2::fixture_switch as e2;
        let node = format!("node-e7-{suffix}");
        let peer1 = format!("peer-e7-1-{suffix}");
        let peer2 = format!("peer-e7-2-{suffix}");
        crate::federation::tier_ingest::test_support::register_hybrid_key(dir, &node).await;

        let grant1 = grant("-", &node, &peer1);
        let grant2 = grant("-", &node, &peer2);
        e2::put_signed(dir, &grant1).await.expect("grant 1 admits");
        e2::put_signed(dir, &grant2).await.expect("grant 2 admits");

        let mut peers = dir
            .list_consent_peers(&e2::kid(&node))
            .await
            .expect("list_consent_peers");
        peers.sort();
        let mut want = vec![e2::kid_or_keep(&peer1), e2::kid_or_keep(&peer2)];
        want.sort();
        assert_eq!(peers, want, "both live grants must be visible, sorted");

        e2::put_signed(dir, &withdraws(&node, &grant1))
            .await
            .expect("withdraws admits");

        let peers_after = dir
            .list_consent_peers(&e2::kid(&node))
            .await
            .expect("list_consent_peers after fold");
        assert_eq!(
            peers_after,
            vec![e2::kid_or_keep(&peer2)],
            "peer-1's consent was withdrawn — it must disappear; peer-2 (untouched) survives"
        );
    }

    /// v21.2.0 (CIRISPersist#509 FLOOR) — the shared, backend-agnostic
    /// parity witness for the three new #509 `FederationDirectory`
    /// methods (`list_live_consent_grants_by` /
    /// `list_local_tier_attestations` / `set_attestation_cohort_scope`),
    /// run by the sqlite / postgres test suites against `&dyn
    /// FederationDirectory` — the same discipline as
    /// [`exercise_consent_peer_set_fold`], this module's sibling witness
    /// for the E7 projection these three methods build on.
    ///
    /// `list_local_tier_attestations` is intentionally NOT scoped by
    /// attester (the sweep walks a node's ENTIRE local backlog), so on a
    /// shared postgres test database that may already carry other tests'
    /// leftover `local`-tier rows, this witness verifies the CURSOR
    /// CONTRACT (ascending order, no duplicates, eventual termination,
    /// both our rows found) rather than asserting the page's exact
    /// contents — the same robustness discipline a real multi-tenant
    /// table would demand.
    pub(crate) async fn exercise_509_backend_methods(dir: &dyn FederationDirectory, suffix: &str) {
        use crate::federation::types::cohort_scope;
        use crate::federation::types::LocalAttestationInput;

        // v62.0.0 — the node's key is an edition-2 `key:record`: every id it
        // writes and reads by is its kid.
        use crate::federation::edition2::fixture_switch as e2;
        let node_seed = format!("node-509b-{suffix}");
        let peer = format!("peer-509b-{suffix}");
        crate::federation::tier_ingest::test_support::register_hybrid_key(dir, &node_seed).await;
        let node = e2::kid(&node_seed);

        // ── list_local_tier_attestations: the cursor contract ──
        let local_input = || LocalAttestationInput {
            attestation_id: None,
            attesting_key_id: node.clone(),
            attested_key_id: None,
            attestation_type: attestation_type::SCORES.to_owned(),
            weight: None,
            expires_at: None,
            attestation_envelope: crate::federation::envelope::EnvelopeCore::from_value(
                serde_json::json!({ "dimension": "misc_509b:v1" }),
            )
            .unwrap(),
            subject_key_ids: vec![],
            cohort_scope: cohort_scope::SELF.to_owned(),
            scrub_signature_classical: None,
            scrub_signature_pqc: None,
        };
        let local1 = dir
            .attestation_insert_local(local_input())
            .await
            .expect("insert local1");
        let local2 = dir
            .attestation_insert_local(local_input())
            .await
            .expect("insert local2");

        let mut seen: Vec<String> = Vec::new();
        let mut cursor: Option<String> = None;
        for _ in 0..200 {
            let page = dir
                .list_local_tier_attestations(cursor.as_deref(), 50)
                .await
                .expect("list_local_tier_attestations page");
            if page.is_empty() {
                break;
            }
            for row in &page {
                assert_eq!(
                    row.tier,
                    attestation_tier::LOCAL,
                    "the page source must never emit a non-local row"
                );
                if let Some(last) = seen.last() {
                    assert!(
                        row.attestation_id.as_str() > last.as_str(),
                        "ascending, strictly-after-cursor order: {last} then {}",
                        row.attestation_id
                    );
                }
                seen.push(row.attestation_id.clone());
            }
            cursor = page.last().map(|r| r.attestation_id.clone());
        }
        assert!(seen.contains(&local1), "local1 must appear in the walk");
        assert!(seen.contains(&local2), "local2 must appear in the walk");
        let mut dedup = seen.clone();
        dedup.sort();
        dedup.dedup();
        assert_eq!(
            dedup.len(),
            seen.len(),
            "no attestation_id repeats across pages"
        );

        // ── set_attestation_cohort_scope: write-back + validation ──
        // v31.0.0 (CIRISPersist#649) — a re-scope is a RE-SIGN: `cohort_scope`
        // is bound into the signed envelope, so the door takes the re-stamped
        // + re-signed bundle beside the new placement.
        // (v39.0.0 — the in-place re-scope primitive is gone; a scope change is a
        // `supersedes` written through `widen_audience`; v62.0.0, a
        // restatement at the wider audience, witnessed by
        // `edition2::crossing_producer_invariants`.)

        // ── list_live_consent_grants_by: grant → live, withdraw → gone ──
        let g = grant("-", &node_seed, &peer);
        let grant_id = g.attestation_id.clone();
        e2::put_signed(dir, &g).await.expect("grant admits");

        let live = dir
            .list_live_consent_grants_by(&node)
            .await
            .expect("live grants");
        assert!(
            live.iter().any(|a| a.attestation_id == grant_id),
            "the live grant must be visible"
        );

        e2::put_signed(dir, &withdraws(&node_seed, &g))
            .await
            .expect("withdraws admits");

        let live_after = dir
            .list_live_consent_grants_by(&node)
            .await
            .expect("live grants after withdraw");
        assert!(
            !live_after.iter().any(|a| a.attestation_id == grant_id),
            "a withdrawn grant must no longer be LIVE"
        );
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::federation::types::attestation_type;
    use crate::federation::Attestation;

    fn base(attestation_type_str: &str, envelope: serde_json::Value) -> Attestation {
        Attestation {
            attestation_id: "a-1".into(),
            attesting_key_id: "node-1".into(),
            attested_key_id: "node-1".into(),
            attestation_type: attestation_type_str.into(),
            weight: None,
            asserted_at: chrono::Utc::now(),
            expires_at: None,
            attestation_envelope: envelope,
            original_content_hash: "deadbeef".into(),
            scrub_signature_classical: "c2ln".into(),
            scrub_signature_pqc: None,
            scrub_key_id: "node-1".into(),
            scrub_timestamp: chrono::Utc::now(),
            pqc_completed_at: None,
            persist_row_hash: String::new(),
            subject_key_ids: vec!["peer-1".into()],
            withdraws_admission_rule: None,
            cohort_scope: "federation".to_string(),
            tier: crate::federation::types::attestation_tier::FEDERATION.to_string(),
            promoted_at: None,
            additional_scrubs: Vec::new(),
        }
    }

    #[test]
    fn recognizes_consent_replication_grant() {
        let grant = base(
            attestation_type::SCORES,
            serde_json::json!({"dimension": DIMENSION}),
        );
        assert!(is_consent_replication_grant(&grant));
        let other = base(
            attestation_type::SCORES,
            serde_json::json!({"dimension": "identity_binding:v1"}),
        );
        assert!(!is_consent_replication_grant(&other));
    }

    #[test]
    fn revocation_fold_target_only_for_structural_composers_with_a_ref() {
        let withdraws = base(
            attestation_type::WITHDRAWS,
            serde_json::json!({"references_attestation_id": "grant-1"}),
        );
        assert_eq!(revocation_fold_target(&withdraws), Some("grant-1"));

        let recants = base(
            attestation_type::RECANTS,
            serde_json::json!({"references_attestation_id": "grant-2"}),
        );
        assert_eq!(revocation_fold_target(&recants), Some("grant-2"));

        // Not a structural composer — no fold target even with a ref field.
        let grant = base(
            attestation_type::SCORES,
            serde_json::json!({"dimension": DIMENSION, "references_attestation_id": "grant-1"}),
        );
        assert_eq!(revocation_fold_target(&grant), None);

        // Structural composer with no ref field — unresolvable, no target.
        let malformed = base(attestation_type::WITHDRAWS, serde_json::json!({}));
        assert_eq!(revocation_fold_target(&malformed), None);
    }
}
