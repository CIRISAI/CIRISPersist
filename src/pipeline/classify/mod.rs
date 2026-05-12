//! Content classification taxonomy + matchers (v0.6.0+, CIRISPersist#19).
//!
//! Per FSD `POST_INGEST_FILTER_PIPELINE.md` §6. The classify stage
//! produces a [`Vec<Vec<ContentClassMatch>>`] (outer per-component,
//! inner per-span-match) that downstream stages consume:
//!
//! - **scrub** reads `(class, action)` to decide redact / pseudonymize
//!   / hash / drop on each match.
//! - **encrypt-and-store** (v0.6.1) reads `(action == EncryptAndStore)`
//!   matches to capture the cleartext before scrub replaces it.
//! - **extract** reads `(class, span)` to populate the corresponding
//!   feature counts (e.g. `pii_email_count`, `prompt_injection_flag`).
//!
//! # Five orthogonal dimensions (FSD §6.1)
//!
//! - D1 `ContentClass`    — WHAT the matched span is (the noun).
//! - D2 `DetectionMethod` — HOW the match was found (the verb).
//! - D3 `Sensitivity`     — HOW dangerous a leak is (escalation axis).
//! - D4 `Action`          — WHAT the pipeline does about it.
//! - D5 `LearningState`   — effectiveness / learning metadata.
//!
//! Each is independently encoded; existing taxonomies (CIRISAgent's
//! `SecretType` / `SensitivityLevel` / `TriggerType` / `FilterPriority`,
//! CIRISLensCore's scrub regex catalog / walker / NER) project onto
//! subsets of these dimensions per FSD §6.1.

use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};

/// **D1** — What the matched span IS. The taxonomic noun.
///
/// 36 built-in variants across 4 groups + one `Custom(String)` escape
/// hatch for operator-defined classes. Wire format: adjacently-tagged
/// JSON (`{"kind": "ApiKey"}` for unit variants, `{"kind": "Custom",
/// "value": "..."}` for `Custom`).
#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(tag = "kind", content = "value")]
pub enum ContentClass {
    // ─── Secrets (S1–S12) — CIRISAgent `SecretType` projects here ──
    /// Generic API key (provider-agnostic shape).
    ApiKey,
    /// `Authorization: Bearer ...` token.
    BearerToken,
    /// Plain-text password.
    Password,
    /// URL with embedded credentials (`user:pass@host`).
    UrlWithAuth,
    /// PEM-armored private key or PKCS#8-style key material.
    PrivateKey,
    /// Credit card number (PAN).
    CreditCard,
    /// US Social Security Number.
    SocialSecurity,
    /// AWS access key id (`AKIA...`).
    AwsAccessKey,
    /// AWS secret access key.
    AwsSecretKey,
    /// GitHub personal access token / app token.
    GithubToken,
    /// Slack bot / user token (`xox[bp]-...`).
    SlackToken,
    /// Discord bot token.
    DiscordToken,

    // ─── Patterns (P1–P10) — Agent `AdaptiveFilterService` projects here ──
    /// Mention of a known agent identity.
    AgentMention,
    /// Mention of an agent by configured name.
    AgentName,
    /// Direct-message indicator (per-adapter heuristic).
    DirectMessage,
    /// Wall-of-text (> length threshold without natural breaks).
    WallOfText,
    /// Message-flood (frequency over per-channel threshold).
    MessageFlood,
    /// Emoji spam (high emoji-to-text ratio).
    EmojiSpam,
    /// CAPS abuse (high uppercase ratio over length threshold).
    CapsAbuse,
    /// Prompt-injection attempt (jailbreak token / role-override).
    PromptInjection,
    /// Malformed JSON received where a JSON value was expected.
    MalformedJson,
    /// Excessive length (> per-class hard limit).
    ExcessiveLength,

    // ─── PII (I1–I10) — CIRISLensCore NER + regex catalog projects here ──
    /// Person name.
    PersonName,
    /// Organization name.
    Organization,
    /// Place / location name.
    Location,
    /// Email address.
    EmailAddress,
    /// Phone number.
    PhoneNumber,
    /// IP address (v4 / v6).
    IpAddress,
    /// User identifier (platform-internal handle).
    UserId,
    /// Message identifier (platform-internal id).
    MessageId,
    /// Channel / room identifier.
    ChannelId,
    /// NER MISC catch-all (named entity not in I1–I9).
    MiscNamedEntity,

    // ─── Structural (F1–F4) — payload-structural classes ──
    /// Free-form text body.
    FreeFormText,
    /// Tool action arguments blob.
    ToolArgs,
    /// Observation content (the agent's input).
    ObservationContent,
    /// Thought content (the agent's reasoning).
    ThoughtContent,

    /// Operator-defined class. The string is a stable identifier
    /// chosen by the deployment (e.g. `"customer-account-number"`).
    Custom(String),
}

/// **D2** — How the match was found. The taxonomic verb.
///
/// Existing taxonomies project to subsets:
/// - CIRISAgent `TriggerType`: REGEX/LENGTH/COUNT/FREQ/CUSTOM/SEMANTIC
///   → 6 of 8 here.
/// - CIRISLensCore scrub regex catalog → `Regex`.
/// - CIRISLensCore scrub walker → `Walker`.
/// - CIRISLensCore scrub NER → `Ner`.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum DetectionMethod {
    /// Regex pattern match against a string value.
    Regex,
    /// Structural match (key matched a known field-name catalog;
    /// e.g. `payload.tool_args` ⇒ `ToolArgs`).
    Walker,
    /// Length-based threshold (e.g. > 8k chars ⇒ `ExcessiveLength`).
    Length,
    /// Count-based threshold (e.g. > N emoji ⇒ `EmojiSpam`).
    Count,
    /// Frequency-based threshold (e.g. > N msgs / window ⇒ `MessageFlood`).
    Frequency,
    /// Operator-defined matcher (registered at runtime).
    Custom,
    /// Embedding-similarity / semantic-search match.
    Semantic,
    /// Multilingual NER (XLM-R or DistilBERT) tagged span.
    Ner,
}

/// **D3** — How dangerous a leak is. The escalation axis.
///
/// Maps to CIRISAgent's `SensitivityLevel`; ordering matches:
/// `Low < Medium < High < Critical`. Default action mapping
/// (FSD §3.3): `Critical` ⇒ `EncryptAndStore` + manual recall only;
/// `High` ⇒ `["tool"]`; `Medium` ⇒ `["tool","speak"]`; `Low` ⇒
/// `["tool","speak","memorize"]`.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Ord, PartialOrd, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Sensitivity {
    /// Logged / aggregated freely.
    Low,
    /// Visible to operators + tool actions.
    Medium,
    /// Restricted to tool actions; not surfaced in speech.
    High,
    /// Manual recall only.
    Critical,
}

/// **D4** — What the pipeline does about the match.
///
/// One of 7 outcomes. Default mapping per content class is in the
/// built-in catalog ([`taxonomy`](super::classify) in the v0.6.x
/// expansion); operator config can override per-class.
#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Action {
    /// Detect and tag, payload untouched.
    AnnotateOnly,

    /// Replace span with `{SECRET:uuid:description}` BUT do NOT store
    /// the original. Used when no secrets store is wired (sovereign
    /// no-storage mode) or when sensitivity policy says "destroy".
    ScrubReplace,

    /// Replace with `{SECRET:uuid:description}` AND encrypt-and-store
    /// the original via the [`crate::secrets::SecretsService`].
    /// Recoverable for whitelisted actions via decapsulation.
    /// Default for S1–S12 when secrets feature is enabled and a
    /// `SecretsService` is bound at pipeline build time.
    EncryptAndStore,

    /// Replace with a stable hash of the original. Used for
    /// UserId-style classes where consumers want to track occurrences
    /// without exposure.
    Hash,

    /// Replace with deterministic pseudonym from a stable mapping
    /// (`MessageId → "msg_a3f9"`). Mapping table lives in
    /// `cirislens_pseudonyms` (v0.6.1 / V008 migration).
    Pseudonymize,

    /// Drop the entire component from the BatchEnvelope. Reserved
    /// for catastrophic detections.
    Drop,

    /// Reject the whole batch — abort ingest. Reserved for invariant
    /// violations (scrubber returning schema-altered envelope, etc.).
    Reject,
}

/// **D5** — Effectiveness / learning metadata for a matcher.
///
/// Updated by the adaptive-filter loop (v0.6.x+). v0.6.0 ships the
/// type but doesn't populate it from runtime feedback — it's reserved
/// for operator-managed catalogs and the federation-stable learning
/// surface in v0.6.x. Most v0.6.0 matches have `learning = None`.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct LearningState {
    /// Effectiveness ratio in [0, 1]. Maintained as a moving average
    /// over recent fires.
    pub effectiveness: f32,
    /// False-positive rate in [0, 1]. Computed from labeler feedback
    /// (operator confirms / rejects).
    pub false_positive_rate: f32,
    /// Lifetime true-positive count.
    pub true_positive_count: u64,
    /// Lifetime false-positive count.
    pub false_positive_count: u64,
    /// Last fire wall-clock. `None` until the matcher fires once.
    pub last_triggered: Option<DateTime<Utc>>,
    /// Matcher creation wall-clock.
    pub created_at: DateTime<Utc>,
    /// Origin tag: `"system"` | `"operator:<id>"` | `"learned:<source>"`.
    pub created_by: String,
    /// Off-by-default during canary / probation.
    pub enabled: bool,
}

/// One matched span within a BatchEnvelope component.
///
/// Produced by the classify stage; consumed by scrub + (v0.6.1)
/// encrypt-and-store + extract. Wire format: stored in the
/// `cirislens.trace_events.classifications` JSONB column (V007
/// migration) as `Vec<Vec<ContentClassMatch>>` — outer vec is
/// per-component, inner vec is per-match within that component.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct ContentClassMatch {
    /// What the span IS.
    pub class: ContentClass,
    /// How it was found.
    pub method: DetectionMethod,
    /// How sensitive.
    pub sensitivity: Sensitivity,
    /// What to do.
    pub action: Action,
    /// Stable matcher id (e.g. `"regex:email_v1"`, `"ner:xlm-r:PER"`).
    /// Used for differential testing + learning attribution.
    pub matcher_id: String,
    /// Which component within the BatchEnvelope this match came from.
    pub component_index: usize,
    /// JSON-pointer-like path to the matched field within the
    /// component payload. `None` for whole-component matches (e.g.
    /// `Action::Drop`).
    pub json_path: Option<String>,
    /// Byte-offset span `(start, end)` within the matched string.
    /// `None` for non-textual matches.
    pub span: Option<(usize, usize)>,
    /// Confidence in `[0.0, 1.0]`. Regex matches → 1.0; NER matches
    /// → the model's softmax probability.
    pub confidence: f32,
    /// Learning metadata for the matcher (D5 dimension). `None` for
    /// v0.6.0 built-in matchers (no adaptive learning yet).
    pub learning: Option<LearningState>,
    /// Set by the encrypt-and-store stage to the
    /// `cirislens_secrets.secrets.uuid` row reference. `None` when
    /// the action is not `EncryptAndStore` or v0.6.1's secrets stage
    /// hasn't run yet.
    pub secret_uuid: Option<String>,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn content_class_serde_unit_variant() {
        let v = ContentClass::ApiKey;
        let s = serde_json::to_string(&v).unwrap();
        assert_eq!(s, r#"{"kind":"ApiKey"}"#);
        let back: ContentClass = serde_json::from_str(&s).unwrap();
        assert_eq!(back, v);
    }

    #[test]
    fn content_class_serde_custom_variant() {
        let v = ContentClass::Custom("customer-account-number".into());
        let s = serde_json::to_string(&v).unwrap();
        assert_eq!(s, r#"{"kind":"Custom","value":"customer-account-number"}"#);
        let back: ContentClass = serde_json::from_str(&s).unwrap();
        assert_eq!(back, v);
    }

    #[test]
    fn detection_method_serde_snake_case() {
        let v = DetectionMethod::Ner;
        let s = serde_json::to_string(&v).unwrap();
        assert_eq!(s, r#""ner""#);
    }

    #[test]
    fn sensitivity_ordering() {
        assert!(Sensitivity::Low < Sensitivity::Medium);
        assert!(Sensitivity::Medium < Sensitivity::High);
        assert!(Sensitivity::High < Sensitivity::Critical);
    }

    #[test]
    fn action_serde_snake_case() {
        let v = Action::EncryptAndStore;
        let s = serde_json::to_string(&v).unwrap();
        assert_eq!(s, r#""encrypt_and_store""#);
    }

    #[test]
    fn content_class_match_round_trip() {
        let m = ContentClassMatch {
            class: ContentClass::EmailAddress,
            method: DetectionMethod::Regex,
            sensitivity: Sensitivity::Medium,
            action: Action::ScrubReplace,
            matcher_id: "regex:email_v1".into(),
            component_index: 0,
            json_path: Some("$.task_description".into()),
            span: Some((10, 32)),
            confidence: 1.0,
            learning: None,
            secret_uuid: None,
        };
        let s = serde_json::to_string(&m).unwrap();
        let back: ContentClassMatch = serde_json::from_str(&s).unwrap();
        assert_eq!(back.class, m.class);
        assert_eq!(back.method, m.method);
        assert_eq!(back.sensitivity, m.sensitivity);
        assert_eq!(back.action, m.action);
        assert_eq!(back.matcher_id, m.matcher_id);
        assert_eq!(back.json_path, m.json_path);
        assert_eq!(back.span, m.span);
    }
}
