//! Occurrence registry substrate wire types (v1.7.3,
//! CIRISPersist#81).
//!
//! Mirrors the row shape of `cirislens.occurrence_registry`
//! (Postgres) / `cirislens_occurrence_registry` (SQLite); see V039.

#![allow(missing_docs)]

use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};

/// One row of the `occurrence_registry` substrate — a single live
/// occurrence under a stable Ed25519 identity.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct OccurrenceRecord {
    /// Occurrence identifier. PK; re-registering refreshes the row.
    pub occurrence_id: String,
    /// The agent's Ed25519 identity. All occurrences of one agent
    /// share this (PoB §3.2 one-key model).
    pub identity: String,
    /// Wall-clock time the occurrence was (re-)registered.
    pub registered_at: DateTime<Utc>,
    /// Wall-clock time of the most recent register / heartbeat.
    pub last_heartbeat: DateTime<Utc>,
    /// TTL expiry. `expires_at > now` means the occurrence is live;
    /// a crashed occurrence ages out past this without a clean
    /// deregister.
    pub expires_at: DateTime<Utc>,
    /// Optional free-form metadata (endpoint addresses, version,
    /// etc.).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub metadata: Option<serde_json::Value>,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn occurrence_record_round_trip_all_columns() {
        let now = Utc::now();
        let r = OccurrenceRecord {
            occurrence_id: "occ-1".into(),
            identity: "ed25519-abc".into(),
            registered_at: now,
            last_heartbeat: now,
            expires_at: now,
            metadata: Some(serde_json::json!({"endpoint": "10.0.0.1:9000"})),
        };
        let s = serde_json::to_string(&r).unwrap();
        let back: OccurrenceRecord = serde_json::from_str(&s).unwrap();
        assert_eq!(r, back);
    }

    #[test]
    fn occurrence_record_serde_field_names() {
        let r = OccurrenceRecord {
            occurrence_id: "occ".into(),
            identity: "id".into(),
            registered_at: Utc::now(),
            last_heartbeat: Utc::now(),
            expires_at: Utc::now(),
            metadata: None,
        };
        let v: serde_json::Value = serde_json::to_value(&r).unwrap();
        assert!(v.get("occurrence_id").is_some());
        assert!(v.get("identity").is_some());
        assert!(v.get("registered_at").is_some());
        assert!(v.get("last_heartbeat").is_some());
        assert!(v.get("expires_at").is_some());
        // metadata omitted when None.
        assert!(v.get("metadata").is_none());
    }
}
