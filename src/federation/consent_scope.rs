//! # The consent scope token — `kind[:sub…]`
//!
//! v44.8.0 (CIRISPersist#866, `FSD/CONTEXTUAL_INTEGRITY_ENVELOPE.md` §4).
//!
//! A `consent:state:*` row names what it covers in its envelope `scope`
//! member — a bare string or an array of **tokens**. CC 3.3.1 spells a token
//! as a *kind* with optional colon-separated *sub-scoping* (`retain:90d`,
//! `share:cohort:family`). Before this module the fold matched tokens by
//! exact string equality, so every sub-scoped token a producer wrote the
//! constitution's way was silently inert: it matched nothing, and nobody was
//! told. This module is the ONE place a token is parsed, the ONE covering
//! rule, and the door gate that refuses a token the fold could not match.
//!
//! ## The grammar
//!
//! ```text
//! token := kind ( ":" sub )*
//! kind  := [a-z][a-z0-9_]*          OPEN — five canonical kinds carry meaning here
//! sub   := [a-z0-9_-]+              meaning depends on the kind
//! ```
//!
//! The kind vocabulary is **open** (CC 3.3.1: "open vocab"). Server's
//! infohazard gate mints `view`; a consumer may mint others. Persist assigns
//! meaning to the five *canonical* kinds —
//! [`transmission_principle::ALL`](crate::federation::types::transmission_principle::ALL),
//! the same five the transfer grammar pins — and treats every other kind
//! generically. What the door refuses is a **malformed** token, never an
//! unknown kind: a consumer's scope is not persist's to veto.
//!
//! ## Per-kind sub-scope semantics
//!
//! | kind | sub form | what it means | kind of constraint |
//! |---|---|---|---|
//! | `share` | `cohort:<cohort_scope>` | propagate no wider than this audience | **narrowing** (the CC 4.4.3.3.1 widening order) |
//! | `analyze` | `<family>` | derive scores only in this dimension family | **narrowing** |
//! | `retain` | `<n>d` / `<n>h` | keep the bytes at most this long after the grant's `asserted_at` | **bound** — returned by the resolver, enforced by the sweeps, never a match criterion |
//! | `train`, `publish`, any other kind | free segments | the consumer's meaning | **narrowing**, generic: a bare token is the widest, a sub-scoped token covers only a longer token with the same prefix |
//!
//! ## The covering rule ([`covers`])
//!
//! A grant token `g` covers a query token `q` iff the kinds are equal and,
//! per the table, `g` is at least as wide as `q`. A bare grant is the widest
//! grant; a bare query is the widest ask (`share` means "share to the
//! federation"). A narrowed grant therefore never covers a bare ask — a
//! caller must ask at the audience it intends. The asymmetry of the fold
//! (blanket revocations, exact grants) lives in [`super::consent`], not
//! here; this module answers only "does this token cover that one".

use chrono::{DateTime, Duration, Utc};

use super::types::transmission_principle as principle;

/// The sub-scope of a token, already interpreted for its kind.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum SubScope {
    /// No `:sub` — the whole kind. The widest grant, and the widest ask.
    Whole,
    /// `share:cohort:<x>` — an audience, one of
    /// [`cohort_scope::ALL`](crate::federation::types::cohort_scope::ALL).
    Cohort(String),
    /// `retain:<n>d` / `retain:<n>h` — a window after the grant's instant.
    Window(Duration),
    /// `analyze:<family>` — a dimension family (`capacity`, `trust`, …).
    Family(String),
    /// Every other kind (and `train` / `publish`): the segments verbatim.
    Segments(Vec<String>),
}

/// One parsed scope token.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ScopeToken {
    /// The kind — the first segment, lowercase.
    pub kind: String,
    /// The interpreted sub-scope.
    pub sub: SubScope,
}

/// Why a token did not parse. Every variant names the token verbatim so a
/// refusal at the door tells the producer exactly which member to fix.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ScopeTokenError {
    /// The empty string.
    Empty,
    /// A segment outside the grammar: empty (`share::x`, `:share`), or a
    /// character that is not `[a-z0-9_-]` (uppercase, space, punctuation).
    BadSegment {
        /// The whole token.
        token: String,
        /// The offending segment (empty when it was empty).
        segment: String,
    },
    /// A canonical kind whose closed sub form did not parse.
    MalformedSub {
        /// The whole token.
        token: String,
        /// The kind.
        kind: String,
        /// What the kind expects after the colon.
        expected: &'static str,
    },
    /// `share:cohort:<x>` where `<x>` is not a cohort scope.
    CohortNotInVocabulary {
        /// The whole token.
        token: String,
        /// The unknown audience.
        cohort: String,
    },
}

impl std::fmt::Display for ScopeTokenError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Empty => write!(f, "scope token is empty"),
            Self::BadSegment { token, segment } if segment.is_empty() => {
                write!(f, "scope token `{token}` has an empty segment")
            }
            Self::BadSegment { token, segment } => write!(
                f,
                "scope token `{token}`: segment `{segment}` is outside the grammar \
                 (kind `[a-z][a-z0-9_]*`, sub-scope segments `[a-z0-9_-]+`)"
            ),
            Self::MalformedSub {
                token,
                kind,
                expected,
            } => write!(
                f,
                "scope token `{token}`: the `{kind}` kind takes {expected}"
            ),
            Self::CohortNotInVocabulary { token, cohort } => write!(
                f,
                "scope token `{token}`: `{cohort}` is not a cohort scope ({})",
                super::types::cohort_scope::ALL.join(" / ")
            ),
        }
    }
}

impl std::error::Error for ScopeTokenError {}

fn is_kind_char(i: usize, c: char) -> bool {
    if i == 0 {
        c.is_ascii_lowercase()
    } else {
        c.is_ascii_lowercase() || c.is_ascii_digit() || c == '_'
    }
}

fn is_sub_char(c: char) -> bool {
    c.is_ascii_lowercase() || c.is_ascii_digit() || c == '_' || c == '-'
}

/// Parse `<n>d` / `<n>h` into a window; `n` is a positive integer.
fn parse_window(s: &str) -> Option<Duration> {
    let (digits, unit) = s.split_at(s.len().checked_sub(1)?);
    let n: i64 = digits.parse().ok().filter(|n| *n > 0)?;
    match unit {
        "d" => Duration::try_days(n),
        "h" => Duration::try_hours(n),
        _ => None,
    }
}

/// Parse one token. See the module documentation for the grammar.
pub fn parse_scope_token(token: &str) -> Result<ScopeToken, ScopeTokenError> {
    if token.is_empty() {
        return Err(ScopeTokenError::Empty);
    }
    let bad = |segment: &str| ScopeTokenError::BadSegment {
        token: token.to_owned(),
        segment: segment.to_owned(),
    };
    let mut segments = token.split(':');
    let kind = segments.next().unwrap_or_default();
    if kind.is_empty() || !kind.chars().enumerate().all(|(i, c)| is_kind_char(i, c)) {
        return Err(bad(kind));
    }
    let subs: Vec<&str> = segments.collect();
    for s in &subs {
        if s.is_empty() || !s.chars().all(is_sub_char) {
            return Err(bad(s));
        }
    }
    let malformed = |expected: &'static str| ScopeTokenError::MalformedSub {
        token: token.to_owned(),
        kind: kind.to_owned(),
        expected,
    };
    let sub = match (kind, subs.as_slice()) {
        (_, []) => SubScope::Whole,
        (k, [head, cohort]) if k == principle::SHARE && *head == "cohort" => {
            if !super::types::cohort_scope::is_valid(cohort) {
                return Err(ScopeTokenError::CohortNotInVocabulary {
                    token: token.to_owned(),
                    cohort: (*cohort).to_owned(),
                });
            }
            SubScope::Cohort((*cohort).to_owned())
        }
        (k, _) if k == principle::SHARE => {
            return Err(malformed("`cohort:<cohort_scope>` (an audience narrowing)"))
        }
        (k, [window]) if k == principle::RETAIN => match parse_window(window) {
            Some(d) => SubScope::Window(d),
            None => return Err(malformed("`<n>d` or `<n>h` (a positive retention window)")),
        },
        (k, _) if k == principle::RETAIN => {
            return Err(malformed("`<n>d` or `<n>h` (a positive retention window)"))
        }
        (k, [family]) if k == principle::ANALYZE => SubScope::Family((*family).to_owned()),
        (k, _) if k == principle::ANALYZE => {
            return Err(malformed(
                "`<family>` (one dimension family, e.g. `capacity`)",
            ))
        }
        (_, segs) => SubScope::Segments(segs.iter().map(|s| (*s).to_owned()).collect()),
    };
    Ok(ScopeToken {
        kind: kind.to_owned(),
        sub,
    })
}

/// Position in the closed cohort widening order; `None` never happens for a
/// parsed [`SubScope::Cohort`] (the parser checked the vocabulary).
fn cohort_rank(s: &str) -> usize {
    super::types::cohort_scope::ALL
        .iter()
        .position(|v| *v == s)
        .unwrap_or(0)
}

/// Does the grant token `grant` cover the query token `query`? The covering
/// rule of the module documentation, per kind.
#[must_use]
pub fn covers(grant: &ScopeToken, query: &ScopeToken) -> bool {
    if grant.kind != query.kind {
        return false;
    }
    match (&grant.sub, &query.sub) {
        // A bare grant is the widest grant: it covers every ask of its kind.
        (SubScope::Whole, _) => true,
        // A retention window is a bound, not a match criterion.
        (SubScope::Window(_), _) => true,
        // An audience narrowing covers an ask at or below it; a bare ask
        // means the federation, so only `cohort:federation` covers it.
        (SubScope::Cohort(g), SubScope::Cohort(q)) => cohort_rank(g) >= cohort_rank(q),
        (SubScope::Cohort(g), SubScope::Whole) => g == super::types::cohort_scope::FEDERATION,
        // A family narrowing covers exactly that family; a bare ask is every
        // family.
        (SubScope::Family(g), SubScope::Family(q)) => g == q,
        (SubScope::Family(_), SubScope::Whole) => false,
        // Generic hierarchical narrowing: the grant's segments are a prefix
        // of the query's. A narrowed grant never covers a bare ask.
        (SubScope::Segments(g), SubScope::Segments(q)) => q.starts_with(g),
        (SubScope::Segments(_), SubScope::Whole) => false,
        // Kinds equal but sub forms differ in shape — unreachable for
        // canonical kinds (the parser fixes the shape per kind), and a
        // mismatch is never a cover.
        _ => false,
    }
}

/// The instant a `retain:<window>` grant stops covering, given the grant's
/// own signed instant. `None` for every other token: no bound.
#[must_use]
pub fn retain_until(grant: &ScopeToken, asserted_at: DateTime<Utc>) -> Option<DateTime<Utc>> {
    match (grant.kind.as_str(), &grant.sub) {
        (k, SubScope::Window(w)) if k == principle::RETAIN => Some(asserted_at + *w),
        _ => None,
    }
}

/// The string tokens the envelope's `scope` member names — the accepted
/// shapes of [`super::consent::named_scopes`], unparsed. Junk shapes
/// (`null`, a number, an object) name nothing and are not this module's
/// concern: the fold's asymmetry rule reads them, the door does not refuse
/// them (v16.1.0 semantics, unchanged).
fn scope_member_tokens(envelope: &serde_json::Value) -> Vec<&str> {
    match envelope.get(super::envelope::paths::SCOPE) {
        Some(serde_json::Value::String(s)) if !s.is_empty() => vec![s.as_str()],
        Some(serde_json::Value::Array(items)) => items
            .iter()
            .filter_map(|v| v.as_str())
            .filter(|s| !s.is_empty())
            .collect(),
        _ => Vec::new(),
    }
}

/// The door gate: every token a `consent:state:*` envelope names must
/// parse. Runs at both doors (local write, federation ingest) and at the
/// promotion chokepoint, on every backend — the v44.4.0 canonical-id
/// posture: never admit a token the fold cannot match. A non-consent row is
/// not this gate's business and passes untouched.
pub fn check_consent_scope_tokens(envelope: &serde_json::Value) -> Result<(), super::Error> {
    let is_consent_state = super::admission::envelope_dimension(envelope)
        .is_some_and(|d| d.starts_with(super::consent::consent_dimension::STATE_PREFIX));
    if !is_consent_state {
        return Ok(());
    }
    for token in scope_member_tokens(envelope) {
        if let Err(e) = parse_scope_token(token) {
            return Err(super::Error::ConsentScopeTokenInvalid {
                token: token.to_owned(),
                reason: e.to_string(),
            });
        }
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn the_canonical_kinds_come_from_the_vocabulary() {
        for k in principle::ALL {
            let t = parse_scope_token(k).unwrap();
            assert_eq!(t.kind, *k);
            assert_eq!(t.sub, SubScope::Whole);
        }
    }

    #[test]
    fn a_window_is_a_positive_integer_of_days_or_hours() {
        assert_eq!(
            parse_scope_token("retain:90d").unwrap().sub,
            SubScope::Window(Duration::days(90))
        );
        assert_eq!(
            parse_scope_token("retain:12h").unwrap().sub,
            SubScope::Window(Duration::hours(12))
        );
        for bad in [
            "retain:0d",
            "retain:-1d",
            "retain:90",
            "retain:d",
            "retain:1w",
            "retain:1d:x",
        ] {
            assert!(
                matches!(
                    parse_scope_token(bad),
                    Err(ScopeTokenError::MalformedSub { .. })
                ),
                "{bad}"
            );
        }
    }

    #[test]
    fn the_gate_ignores_non_consent_rows_and_junk_shapes() {
        assert!(check_consent_scope_tokens(
            &serde_json::json!({"dimension": "trace:x:v1", "scope": "Not A Token"})
        )
        .is_ok());
        assert!(check_consent_scope_tokens(
            &serde_json::json!({"dimension": "consent:state:granted:v1", "scope": 5})
        )
        .is_ok());
        assert!(check_consent_scope_tokens(
            &serde_json::json!({"dimension": "consent:state:granted:v1"})
        )
        .is_ok());
        let err = check_consent_scope_tokens(&serde_json::json!({"dimension": "consent:state:revoked:v1", "scope": ["view", "Share"]}))
            .unwrap_err();
        assert_eq!(err.kind(), "federation_consent_scope_token_invalid");
        assert!(err.to_string().contains("Share"));
    }
}
