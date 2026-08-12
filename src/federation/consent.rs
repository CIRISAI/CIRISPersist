//! v13.0.0 (CIRISPersist#365, CC 3.4.7.2 `consent-counter`) — the
//! **Counter-RII `consent_role`** resolver.
//!
//! `federation_keys.consent_role` is the role token (see the
//! [`consent_role`](super::types::consent_role) vocabulary — `temporary`
//! / `partnered` / `anonymous` / `authorized_review` / `peer`, with
//! `unregistered` as the stored no-role default) that gates Counter-RII
//! probe detection (RATCHET `FSD/COUNTER_RII_DETECTION.md`; Lean
//! `ConsentGate.lean`). Per CC 3.4.7.2 it is a **`federation_keys`
//! identity field** — a sibling to `identity_type`, NOT an envelope
//! primitive — and the clause states implementations MAY now build the
//! substrate (no longer a reserved slot). The COLUMN itself already
//! shipped in V020 (v1.3.0, the CIRISAgent#760 §RC "consent role lock"
//! that CC 3.4.7.2 ratifies — `TEXT NOT NULL DEFAULT 'unregistered'`);
//! v13.0.0 puts it on the wire ([`KeyRecord::consent_role`](super::KeyRecord),
//! `None` ⇔ the stored `'unregistered'`) and exposes this resolver.
//!
//! **What persist owns (and does NOT own).** The three ratified
//! semantics split by responsibility:
//!
//! - **OQ-1 (non-recursive revocation — SUBSTRATE):** a subsequent
//!   revocation OVERWRITES the prior value; the field is flat, bounded,
//!   and carries NO embedded chain. Persist implements this as the
//!   natural UPDATE/overwrite of the single mutable V020 column via
//!   [`super::FederationDirectory::set_consent_role`] (revoke = set
//!   `None` = reset to `'unregistered'`). The field is excluded from
//!   `compute_persist_row_hash` so the overwrite never disturbs the
//!   signed-registration hash.
//! - **OQ-2 (`peer` blanket suppression — CONSUMER):** a `peer`
//!   `consent_role` escapes Counter-RII detection at any `trust_mode`.
//!   Persist STORES + EXPOSES the role; edge's `ProbePatternObserver`
//!   reads it (via [`consent_role_of`]) and suppresses the
//!   advisory-only `ratchet:flag:counter_rii:*` signal. Persist houses
//!   no detector, so it applies no suppression itself.
//! - **OQ-3 (`authorized_review` strict post-window — CONSUMER):** an
//!   `authorized_review` role is signal-eligible immediately at
//!   `t > window_end`. Same split — persist carries the role; the
//!   consumer enforces the window.
//!
//! So this module is the STORE + EXPOSE + OQ-1 half; OQ-2 / OQ-3 are
//! consumer-applied signals on the field persist now carries.

/// v20.0.0 (CIRISPersist#495 C3) — the consent-state dimension PREFIX
/// constants, single-sourced. Server-side consts (infohazard.rs / peer.rs)
/// and every persist SQL literal must speak THESE strings; drift meant
/// `list_consent_revocations` silently empty → revoked consent treated as
/// active → replication kept flowing to a peer that revoked. Versioned
/// dimensions extend the prefix (`consent:state:revoked:v1`).
pub mod consent_dimension {
    /// Prefix of every granted-state dimension.
    pub const STATE_GRANTED_PREFIX: &str = "consent:state:granted";
    /// Prefix of every revoked-state dimension.
    pub const STATE_REVOKED_PREFIX: &str = "consent:state:revoked";
    /// Prefix of every expired-state dimension.
    pub const STATE_EXPIRED_PREFIX: &str = "consent:state:expired";
}

use super::{Error, FederationDirectory};

/// v13.0.0 (CIRISPersist#365, CC 3.4.7.2) — resolve the Counter-RII
/// `consent_role` of `key_id`.
///
/// Returns `Ok(Some(role))` when the key exists and carries an assigned
/// role; `Ok(None)` when the key exists with no assigned role (the
/// stored `'unregistered'` default — including after an OQ-1
/// revoke-overwrite) **or** when `key_id` is absent. The resolver is
/// deliberately total: an absent key and a role-less key are both "no
/// assigned Counter-RII role", which a consumer treats identically
/// (detection applies normally, no suppression). The returned token is
/// one of the assigned [`consent_role`](super::types::consent_role)
/// tokens; the consumer interprets it — persist does not gate on the
/// value here.
pub async fn consent_role_of(
    dir: &dyn FederationDirectory,
    key_id: &str,
) -> Result<Option<String>, Error> {
    Ok(dir
        .lookup_public_key(key_id)
        .await?
        .and_then(|record| record.consent_role))
}

/// v16.1.0 (CIRISPersist#389) — the envelope's `dimension` string (the same
/// axis admission keys on), read straight off the stored
/// `attestation_envelope`. Shared by the consent folds
/// ([`resolve_consent_state`](super::FederationDirectory::resolve_consent_state)
/// / [`resolve_scoped_consent`](super::FederationDirectory::resolve_scoped_consent)).
pub fn envelope_dimension(a: &super::Attestation) -> Option<&str> {
    a.attestation_envelope
        .get("dimension")
        .and_then(|v| v.as_str())
}

/// v16.1.0 (CIRISPersist#389) — THE `consent:state:*` dimension → stance
/// classifier, the single mapping both consent folds share (so the closed-set
/// rule cannot drift). A `consent:state:*` value outside the closed set — or
/// no candidate at all — is `Unspecified` (forward-compat: an unknown stance
/// value never silently reads as granted).
pub fn consent_state_of(dimension: Option<&str>) -> super::hard_case::ConsentState {
    use super::hard_case::ConsentState;
    match dimension {
        Some(d) if d.starts_with(consent_dimension::STATE_GRANTED_PREFIX) => ConsentState::Granted,
        Some(d) if d.starts_with(consent_dimension::STATE_REVOKED_PREFIX) => ConsentState::Revoked,
        Some(d) if d.starts_with(consent_dimension::STATE_EXPIRED_PREFIX) => ConsentState::Expired,
        _ => ConsentState::Unspecified,
    }
}

/// v16.1.0 (CIRISPersist#389) — the scopes an envelope GENUINELY names: the
/// non-empty strings from a bare-string `"scope": "view"` or an array
/// `"scope": ["view", …]`. Junk shapes (`null`, `[]`, `""`, numbers, nested
/// objects) name NOTHING — which [`matches_scoped_query`] then resolves per
/// stance (a junk-scoped revoke leans BLANKET, a junk-scoped grant matches
/// nothing: both fail closed).
pub fn named_scopes(a: &super::Attestation) -> Vec<&str> {
    match a.attestation_envelope.get("scope") {
        Some(serde_json::Value::String(s)) if !s.is_empty() => vec![s.as_str()],
        Some(serde_json::Value::Array(items)) => items
            .iter()
            .filter_map(|v| v.as_str())
            .filter(|s| !s.is_empty())
            .collect(),
        _ => Vec::new(),
    }
}

/// v16.1.0 (CIRISPersist#389) — does the attestation's envelope genuinely name
/// `scope`? See [`named_scopes`] for the accepted shapes.
pub fn envelope_names_scope(a: &super::Attestation, scope: &str) -> bool {
    named_scopes(a).contains(&scope)
}

/// v16.1.1 (CIRISPersist#389 / CIRISServer#243) — does the attestation enter a
/// scoped consent fold for `(scope, qualifier)`? **Asymmetric on the fail
/// direction:**
///
/// - a row NAMING the scope ([`named_scopes`]) matches iff the
///   `content_class` also matches the qualifier (when given);
/// - a **NON-grant naming no genuine scope** (`revoked` / `expired` / unknown
///   stance with an absent — or junk: `null`/`[]`/`""` — scope member) is a
///   **blanket** stance: wholesale withdrawal matches EVERY scoped query (the
///   CC 4.5.13 fail-closed reading — a malformed revocation must never fail
///   toward leaving a gate open);
/// - a **grant naming no genuine scope** matches NOTHING — `granted` is the
///   sole fail-open stance and must name its scope exactly (a bare or
///   junk-scoped `consent:state:granted` never backs a scoped gate).
///
/// A row naming only DIFFERENT scope(s) matches nothing here (unrelated). The
/// qualifier check applies only to scope-naming rows: a blanket revoke has no
/// `content_class` to match and closes all classes by construction.
pub fn matches_scoped_query(a: &super::Attestation, scope: &str, qualifier: Option<&str>) -> bool {
    let named = named_scopes(a);
    if named.contains(&scope) {
        return match qualifier {
            Some(q) => a
                .attestation_envelope
                .get("content_class")
                .and_then(|v| v.as_str())
                .is_some_and(|c| c == q),
            None => true,
        };
    }
    if !named.is_empty() {
        // Genuinely names OTHER scope(s) → unrelated, never blanket.
        return false;
    }
    // Names no genuine scope: BLANKET for every non-grant stance; a grant
    // matches nothing (the only stance that fails open must be exact).
    !envelope_dimension(a).is_some_and(|d| d.starts_with("consent:state:granted"))
}

#[cfg(test)]
mod scoped_query_tests {
    use super::{matches_scoped_query, named_scopes};

    /// A minimal attestation whose envelope carries `dimension` + optional
    /// scope/content_class JSON — the only members the predicate reads.
    /// Built via serde (no `Default` on the substrate type by design).
    fn att(dim: &str, envelope_extras: serde_json::Value) -> crate::federation::Attestation {
        let mut env = serde_json::json!({ "id": "t", "dimension": dim });
        if let (Some(obj), Some(extra)) = (env.as_object_mut(), envelope_extras.as_object()) {
            for (k, v) in extra {
                obj.insert(k.clone(), v.clone());
            }
        }
        serde_json::from_value(serde_json::json!({
            "attestation_id": "a-1",
            "attesting_key_id": "s",
            "attested_key_id": "t",
            "attestation_type": "scores",
            "asserted_at": "2026-06-01T00:00:00Z",
            "attestation_envelope": env,
            "original_content_hash": "00",
            "scrub_signature_classical": "AA",
            "scrub_key_id": "s",
            "scrub_timestamp": "2026-06-01T00:00:00Z",
            "persist_row_hash": "",
            "cohort_scope": "self",
        }))
        .expect("minimal test attestation deserializes")
    }
    const GRANT: &str = "consent:state:granted:v1";
    const REVOKE: &str = "consent:state:revoked:v1";
    const EXPIRE: &str = "consent:state:expired:v1";

    /// The five cases that DEFINE the asymmetry (CIRISServer#243).
    #[test]
    fn the_five_defining_cases() {
        // (1) scope-naming GRANT — matches on qualifier (and fails a mismatch).
        let g = att(
            GRANT,
            serde_json::json!({"scope": "view", "content_class": "medical"}),
        );
        assert!(matches_scoped_query(&g, "view", Some("medical")));
        assert!(matches_scoped_query(&g, "view", None));
        assert!(
            !matches_scoped_query(&g, "view", Some("legal")),
            "qualifier mismatch"
        );

        // (2) scope-naming REVOKE — matches.
        let r = att(
            REVOKE,
            serde_json::json!({"scope": "view", "content_class": "medical"}),
        );
        assert!(matches_scoped_query(&r, "view", Some("medical")));

        // (3) scope-less REVOKE — BLANKET: matches every scope + qualifier.
        let blanket = att(REVOKE, serde_json::json!({}));
        assert!(matches_scoped_query(&blanket, "view", Some("medical")));
        assert!(matches_scoped_query(&blanket, "export", None));

        // (4) scope-less GRANT — matches NOTHING (the sole fail-open stance
        //     must name its scope exactly).
        let bare_grant = att(GRANT, serde_json::json!({}));
        assert!(!matches_scoped_query(&bare_grant, "view", Some("medical")));
        assert!(!matches_scoped_query(&bare_grant, "view", None));

        // (5) different-scope REVOKE — unrelated: does NOT match (and is NOT
        //     blanket).
        let other = att(REVOKE, serde_json::json!({"scope": "replicate"}));
        assert!(!matches_scoped_query(&other, "view", None));
        assert!(!matches_scoped_query(&other, "view", Some("medical")));
    }

    /// The fail-closed edges AROUND the five: junk scope shapes lean blanket
    /// for non-grants and match-nothing for grants; expired/unknown stances
    /// take the non-grant (blanket) side; array shapes unify with bare.
    #[test]
    fn fail_closed_edges() {
        // Junk scope shapes on a REVOKE → still blanket (a malformed
        // revocation must never fail toward leaving the gate open).
        for junk in [
            serde_json::json!({ "scope": serde_json::Value::Null }),
            serde_json::json!({ "scope": [] }),
            serde_json::json!({ "scope": "" }),
            serde_json::json!({ "scope": 7 }),
            serde_json::json!({ "scope": [""] }),
        ] {
            let r = att(REVOKE, junk.clone());
            assert!(
                matches_scoped_query(&r, "view", Some("medical")),
                "junk-scoped revoke must be BLANKET: {junk}"
            );
            // …and the same junk on a GRANT matches nothing.
            let g = att(GRANT, junk.clone());
            assert!(
                !matches_scoped_query(&g, "view", Some("medical")),
                "junk-scoped grant must match NOTHING: {junk}"
            );
        }

        // Scope-less EXPIRED + unknown stances are non-grants → blanket.
        assert!(matches_scoped_query(
            &att(EXPIRE, serde_json::json!({})),
            "view",
            None
        ));
        assert!(matches_scoped_query(
            &att("consent:state:frozen:v9", serde_json::json!({})),
            "view",
            None
        ));

        // Array scope shape unifies with bare-string for both stances.
        let g_arr = att(GRANT, serde_json::json!({"scope": ["export", "view"]}));
        assert!(matches_scoped_query(&g_arr, "view", None));
        assert!(!matches_scoped_query(&g_arr, "delete", None));
        // An array naming only other scopes on a revoke stays unrelated.
        let r_arr = att(
            REVOKE,
            serde_json::json!({"scope": ["export", "replicate"]}),
        );
        assert!(!matches_scoped_query(&r_arr, "view", None));

        // named_scopes: junk items are dropped, genuine ones survive.
        let mixed = att(REVOKE, serde_json::json!({"scope": ["", "view", 3]}));
        assert_eq!(named_scopes(&mixed), vec!["view"]);
    }
}
