//! wa_cert substrate wire types (v1.5.19, CIRISPersist#59 #11, FINAL).
//!
//! Mirrors the row shape of `cirislens.wa_cert` (Postgres) /
//! `cirislens_wa_cert` (SQLite). 24 columns matching CIRISAgent
//! v2.8.13's `wa_cert` verbatim — the Wise-Authority cert directory.
//!
//! The agent's `_json` suffixed TEXT columns are renamed to drop the
//! suffix (`oauth_links`, `scopes`, `custom_permissions`,
//! `adapter_metadata`) since on PG they ride as JSONB; on SQLite they
//! ride as TEXT but the type-layer Value shape is unchanged. The agent
//! itself round-trips the JSON via Python json.loads/dumps so the
//! wire shape is `serde_json::Value`.

#![allow(missing_docs)]

use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};

/// Wise-Authority role discriminator. **lowercase on the wire and in
/// SQL.** 3-value vocabulary matching the agent's CHECK.
///
/// Wire format (JSON via serde) is `rename_all = "snake_case"` so all
/// three variants round-trip lowercase.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum WaRole {
    /// Federation root authority — the seed-of-trust WA.
    Root,
    /// Standard authority — empowered to sign / approve / deny
    /// agent-side decisions.
    Authority,
    /// Observer — read-only; cannot sign.
    Observer,
}

impl WaRole {
    /// Stable SQL CHECK value (lowercase).
    pub fn as_sql_str(self) -> &'static str {
        match self {
            WaRole::Root => "root",
            WaRole::Authority => "authority",
            WaRole::Observer => "observer",
        }
    }

    /// Inverse of [`Self::as_sql_str`]. Accepts only the lowercase
    /// SQL vocabulary.
    pub fn parse_str(s: &str) -> Option<Self> {
        match s {
            "root" => Some(Self::Root),
            "authority" => Some(Self::Authority),
            "observer" => Some(Self::Observer),
            _ => None,
        }
    }
}

/// Token-type discriminator. **lowercase + snake_case on the wire and
/// in SQL** (so `ApiKey` round-trips as `api_key`). 5-value vocabulary
/// inferred from CIRISAgent's TokenType enum; CHECK-enforced at the
/// schema layer.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Default, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum TokenType {
    /// Standard interactive WA cert.
    #[default]
    Standard,
    /// Session-scoped token.
    Session,
    /// API-key token.
    ApiKey,
    /// OAuth-issued token.
    Oauth,
    /// Service-account token (machine-to-machine).
    Service,
}

impl TokenType {
    /// Stable SQL CHECK value (lowercase + snake_case).
    pub fn as_sql_str(self) -> &'static str {
        match self {
            TokenType::Standard => "standard",
            TokenType::Session => "session",
            TokenType::ApiKey => "api_key",
            TokenType::Oauth => "oauth",
            TokenType::Service => "service",
        }
    }

    /// Inverse of [`Self::as_sql_str`]. Accepts only the lowercase
    /// SQL vocabulary.
    pub fn parse_str(s: &str) -> Option<Self> {
        match s {
            "standard" => Some(Self::Standard),
            "session" => Some(Self::Session),
            "api_key" => Some(Self::ApiKey),
            "oauth" => Some(Self::Oauth),
            "service" => Some(Self::Service),
            _ => None,
        }
    }
}

/// One row of the `wa_cert` substrate.
///
/// 24 columns matching CIRISAgent v2.8.13's `wa_cert` table.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct WaCert {
    /// Caller-supplied WA identifier. NOT NULL, PK.
    pub wa_id: String,
    /// Human-readable WA name.
    pub name: String,
    /// Role discriminator (`root | authority | observer`).
    pub role: WaRole,
    /// Long-lived pubkey — base64 or hex-encoded by the caller; persist
    /// stores the literal wire shape.
    pub pubkey: String,
    /// JWT kid (key-id) header value. UNIQUE across the directory.
    pub jwt_kid: String,
    /// Optional password hash (interactive-login certs).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub password_hash: Option<String>,
    /// Optional API-key hash (api_key-type certs).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub api_key_hash: Option<String>,
    /// Optional OAuth provider name (e.g. `"google"`, `"github"`).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub oauth_provider: Option<String>,
    /// Optional OAuth external id — the provider's stable user id.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub oauth_external_id: Option<String>,
    /// Optional OAuth links payload (e.g. user-profile-url,
    /// avatar-url, etc.). Stored as JSONB on PG / TEXT JSON on SQLite.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub oauth_links: Option<serde_json::Value>,
    /// Optional Veilid node id for federated routing.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub veilid_id: Option<String>,
    /// Whether the cert was auto-minted (vs. operator-issued).
    #[serde(default)]
    pub auto_minted: bool,
    /// Optional parent WA id — self-FK to `wa_cert(wa_id)`.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub parent_wa_id: Option<String>,
    /// Optional signature attesting the parent-child relationship.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub parent_signature: Option<String>,
    /// Capability scopes granted to this WA. NOT NULL — agent stores
    /// these as a JSON array. JSONB on PG / TEXT JSON on SQLite.
    pub scopes: serde_json::Value,
    /// Optional custom-permissions payload (free-form JSON object
    /// shape on the agent side). JSONB on PG / TEXT JSON on SQLite.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub custom_permissions: Option<serde_json::Value>,
    /// Optional adapter id this cert is bound to.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub adapter_id: Option<String>,
    /// Optional adapter name (e.g. `"discord"`, `"api"`).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub adapter_name: Option<String>,
    /// Optional adapter-specific metadata. JSONB on PG / TEXT JSON on
    /// SQLite.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub adapter_metadata: Option<serde_json::Value>,
    /// Token-type discriminator. Defaults to [`TokenType::Standard`].
    #[serde(default)]
    pub token_type: TokenType,
    /// Wall-clock time the cert was created. NOT NULL. Preserved on
    /// upsert conflict — `upsert_wa_cert` overwrites mutables but
    /// never the creation time.
    pub created: DateTime<Utc>,
    /// Optional last-login timestamp. Updated via
    /// [`super::WaCertService::update_last_login`].
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub last_login: Option<DateTime<Utc>>,
    /// Whether the cert is currently active. Defaults to `true`.
    /// Toggled via [`super::WaCertService::set_active`].
    #[serde(default = "default_active")]
    pub active: bool,
}

fn default_active() -> bool {
    true
}

#[cfg(test)]
mod tests {
    use super::*;

    fn mk_full() -> WaCert {
        WaCert {
            wa_id: "wa-abc".into(),
            name: "Alice Authority".into(),
            role: WaRole::Authority,
            pubkey: "pk-base64".into(),
            jwt_kid: "kid-1".into(),
            password_hash: Some("argon2:...".into()),
            api_key_hash: None,
            oauth_provider: Some("google".into()),
            oauth_external_id: Some("ext-123".into()),
            oauth_links: Some(serde_json::json!({"profile": "https://example/u/alice"})),
            veilid_id: Some("veilid-1".into()),
            auto_minted: false,
            parent_wa_id: Some("wa-root".into()),
            parent_signature: Some("sig-base64".into()),
            scopes: serde_json::json!(["sign", "approve"]),
            custom_permissions: Some(serde_json::json!({"can_revoke": true})),
            adapter_id: Some("adapter-discord-1".into()),
            adapter_name: Some("discord".into()),
            adapter_metadata: Some(serde_json::json!({"guild_id": "g-1"})),
            token_type: TokenType::Standard,
            created: Utc::now(),
            last_login: Some(Utc::now()),
            active: true,
        }
    }

    #[test]
    fn role_sql_round_trip() {
        for r in [WaRole::Root, WaRole::Authority, WaRole::Observer] {
            assert_eq!(WaRole::parse_str(r.as_sql_str()), Some(r));
        }
        assert_eq!(WaRole::parse_str("ROOT"), None);
        assert_eq!(WaRole::parse_str("admin"), None);
    }

    #[test]
    fn role_serde_snake_case_wire_format() {
        assert_eq!(serde_json::to_string(&WaRole::Root).unwrap(), "\"root\"");
        assert_eq!(
            serde_json::to_string(&WaRole::Authority).unwrap(),
            "\"authority\""
        );
        assert_eq!(
            serde_json::to_string(&WaRole::Observer).unwrap(),
            "\"observer\""
        );
        let r: WaRole = serde_json::from_str("\"authority\"").unwrap();
        assert_eq!(r, WaRole::Authority);
    }

    #[test]
    fn token_type_sql_round_trip() {
        for t in [
            TokenType::Standard,
            TokenType::Session,
            TokenType::ApiKey,
            TokenType::Oauth,
            TokenType::Service,
        ] {
            assert_eq!(TokenType::parse_str(t.as_sql_str()), Some(t));
        }
        assert_eq!(TokenType::parse_str("ApiKey"), None);
        assert_eq!(TokenType::parse_str("STANDARD"), None);
    }

    #[test]
    fn token_type_serde_snake_case_wire_format() {
        assert_eq!(
            serde_json::to_string(&TokenType::ApiKey).unwrap(),
            "\"api_key\""
        );
        assert_eq!(
            serde_json::to_string(&TokenType::Standard).unwrap(),
            "\"standard\""
        );
        let t: TokenType = serde_json::from_str("\"api_key\"").unwrap();
        assert_eq!(t, TokenType::ApiKey);
    }

    #[test]
    fn token_type_default_is_standard() {
        assert_eq!(TokenType::default(), TokenType::Standard);
    }

    #[test]
    fn wa_cert_serde_round_trip_all_24_columns() {
        let c = mk_full();
        let s = serde_json::to_string(&c).unwrap();
        let back: WaCert = serde_json::from_str(&s).unwrap();
        assert_eq!(c, back);
    }

    #[test]
    fn wa_cert_serde_minimal_required_columns() {
        // wa_id, name, role, pubkey, jwt_kid, scopes, created are
        // required at the type layer. Everything else is optional or
        // has a serde default.
        let now = Utc::now();
        let json = serde_json::json!({
            "wa_id": "wa-min",
            "name": "Min",
            "role": "observer",
            "pubkey": "pk",
            "jwt_kid": "kid",
            "scopes": [],
            "created": now.to_rfc3339(),
        });
        let c: WaCert = serde_json::from_value(json).unwrap();
        assert_eq!(c.role, WaRole::Observer);
        assert!(c.password_hash.is_none());
        assert!(c.oauth_links.is_none());
        assert!(c.parent_wa_id.is_none());
        assert!(c.last_login.is_none());
        assert!(!c.auto_minted);
        assert!(c.active, "default active is true");
        assert_eq!(c.token_type, TokenType::Standard);
    }
}
