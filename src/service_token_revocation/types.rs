//! Service-token revocation substrate wire types (v1.5.23,
//! CIRISPersist#64).
//!
//! Mirrors the row shape of `cirislens.revoked_service_tokens`
//! (Postgres) / `cirislens_revoked_service_tokens` (SQLite). All
//! four columns are NOT NULL — revocations always carry context
//! (when, by whom, why) for the audit trail.

#![allow(missing_docs)]

use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};

/// One row of the `revoked_service_tokens` substrate.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct RevokedServiceToken {
    /// SHA-based digest of the service token. PK; idempotent
    /// upsert on conflict (first record wins).
    pub token_hash: String,
    /// Wall-clock revocation time.
    pub revoked_at: DateTime<Utc>,
    /// Who triggered the revocation (operator id, automation
    /// hook, etc.).
    pub revoked_by: String,
    /// Human-readable revocation reason. Free-form string.
    pub reason: String,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn revoked_service_token_round_trip_all_columns() {
        let now = Utc::now();
        let r = RevokedServiceToken {
            token_hash: "deadbeefcafe1234".into(),
            revoked_at: now,
            revoked_by: "operator-7".into(),
            reason: "key rotation".into(),
        };
        let s = serde_json::to_string(&r).unwrap();
        let back: RevokedServiceToken = serde_json::from_str(&s).unwrap();
        assert_eq!(r, back);
    }

    #[test]
    fn revoked_service_token_serde_field_names() {
        let r = RevokedServiceToken {
            token_hash: "h".into(),
            revoked_at: Utc::now(),
            revoked_by: "by".into(),
            reason: "reason".into(),
        };
        let v: serde_json::Value = serde_json::to_value(&r).unwrap();
        assert!(v.get("token_hash").is_some());
        assert!(v.get("revoked_at").is_some());
        assert!(v.get("revoked_by").is_some());
        assert!(v.get("reason").is_some());
    }
}
