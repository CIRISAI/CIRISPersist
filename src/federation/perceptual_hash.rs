//! Perceptual-hash admission hook for [`BlobStorage::put_blob_signing`](crate::federation::BlobStorage::put_blob_signing).
//!
//! Mirrors the v3.4.0 [`AdmissionGate`](crate::federation::AdmissionGate)
//! pattern (#123): persist exposes a pluggable trait
//! [`PerceptualHashMatcher`]; concrete in-tree adapters are NOT shipped
//! (no PDQ / PhotoDNA / Project Arachnid integration baked in). The
//! default backend impl returns `None`; backends with a matcher
//! installed call it inside `put_blob_signing` and reject inline-body
//! writes that match a known-bad database.
//!
//! # Why pluggable (not baked-in)
//!
//! CEG 0.3 §11.5.1 (Registry commit a7d95cd, closes CIRISRegistry#39)
//! ratified option (a): self-hosted PDQ against publicly-distributed
//! feeds is the default operator path. PDQ / PhotoDNA / Arachnid
//! Shield are operator-tier integrations with vendor-specific
//! licensing, deployment surface, and audit discipline. Persist
//! exposes the hook so a deployment can wire its own matcher; persist
//! itself ships [`NullPerceptualHashMatcher`] as the no-op default
//! so the trait surface is uniform across backends.
//!
//! A `PdqHashMatcher` adapter for the open PDQ algorithm + open feeds
//! is a planned follow-up — intentionally out-of-tree to keep
//! operator control over hash-DB governance per CEG §11.5.
//!
//! # External-body skip
//!
//! The matcher runs ONLY for [`BlobBody::Inline`](crate::federation::BlobBody::Inline)
//! bodies. `External` bodies' bytes do not transit persist — persist
//! has nothing to hash. The skip is by design (architect §6.5
//! rationale): perceptual-matching belongs at the byte-origin host,
//! not at the directory that records the SHA-256 reference.

use std::sync::Arc;

// ── Hook traits + ancillary types ───────────────────────────────────

/// Closed-set policy for the [`PerceptualHashMatcher::on_match_policy`]
/// hook.
///
///   - [`Self::Refuse`] — reject the write with
///     [`BlobError::HashMatchedKnownBad`](crate::federation::BlobError::HashMatchedKnownBad).
///     No report side-effect.
///   - [`Self::ReportThenRefuse`] — report to the operator-configured
///     channel (NCMEC cybertip carrier, etc.), then refuse. The
///     reporting side-effect is the matcher impl's responsibility;
///     persist sees only the refuse outcome.
///   - [`Self::AlertOnly`] — admit the write but emit a tracing
///     warning. Used for shadow-test rollouts where the matcher's
///     false-positive rate is being characterized before flipping to
///     refuse semantics.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum OnMatchPolicy {
    /// Reject the write with the typed error.
    Refuse,
    /// Report side-channel, then reject.
    ReportThenRefuse,
    /// Admit + tracing warning.
    AlertOnly,
}

/// Closed-set policy for the matcher-unreachable failure mode.
///
///   - [`Self::FailClosed`] — refuse the write. Treats the matcher's
///     verdict as MANDATORY for admission. Persist's default — for
///     the child-safety / terrorist-content classes the hook is
///     intended for, fail-open admits the very content the matcher
///     would have rejected.
///   - [`Self::FailOpen`] — admit the write. Trades availability for
///     correctness; an operator who has a 99.9%-uptime matcher SLA
///     can flip this to keep writes flowing during the 0.1%
///     unreachable window.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum MatcherUnreachablePolicy {
    /// Reject when the matcher is unreachable.
    FailClosed,
    /// Admit when the matcher is unreachable.
    FailOpen,
}

/// Identifier for a known-bad hash database (NCMEC, GIFCT-HSI,
/// Arachnid, etc.). Free-form wire-string — persist treats it as
/// opaque, the matcher impl pins the vocabulary.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct HashDatabaseId(pub String);

/// Result of a [`PerceptualHashMatcher::check`] call.
#[derive(Clone)]
pub enum HashMatchResult {
    /// No match across the matcher's configured databases.
    NoMatch,
    /// Hit one of the matcher's databases. Score / threshold semantics
    /// are matcher-defined; persist surfaces them on the typed error.
    Match {
        /// Which database matched.
        database: HashDatabaseId,
        /// Match score.
        score: f64,
        /// Threshold the matcher applied.
        threshold: f64,
    },
}

/// Matcher errors. Distinct from `Match` because the matcher's
/// unreachable-policy choice (fail-closed vs fail-open) drives admission
/// in a different way than a positive match.
#[derive(Debug, thiserror::Error)]
pub enum HashMatchError {
    /// Matcher backend is unreachable (network failure, lib panic,
    /// rate-limit). Backends consult
    /// [`PerceptualHashMatcher::matcher_unreachable_policy`] to decide
    /// whether to fail-closed or fail-open.
    #[error("matcher unreachable: {0}")]
    Unreachable(String),
    /// Bytes were malformed for the matcher (wrong codec, etc.).
    /// Persist treats this as a write-side input error — the body is
    /// rejected with a typed
    /// [`BlobError::InvalidArgument`](crate::federation::BlobError::InvalidArgument).
    #[error("input malformed for matcher: {0}")]
    InputMalformed(String),
}

/// Perceptual-hash matcher hook. Operator-config installs a concrete
/// impl on a backend via the backend's setter (mirroring
/// `set_admission_gate`).
#[async_trait::async_trait]
pub trait PerceptualHashMatcher: Send + Sync {
    /// Check whether the given content matches a known-bad entry.
    ///
    /// `sha256` is the exact SHA-256 the caller is admitting — the
    /// same value used as the row PK and the holds-bytes attestation
    /// discriminator. `body` is the inline byte payload that
    /// `put_blob_signing` is about to commit.
    async fn check(
        &self,
        sha256: &[u8; 32],
        body: &[u8],
    ) -> Result<HashMatchResult, HashMatchError>;

    /// Which databases the matcher consults. Surface-level
    /// introspection for operator UIs / telemetry; backends do NOT
    /// gate behavior on this list.
    fn databases(&self) -> &[HashDatabaseId];

    /// Policy when [`Self::check`] returns `Match { .. }`.
    fn on_match_policy(&self) -> OnMatchPolicy;

    /// Policy when [`Self::check`] returns
    /// [`HashMatchError::Unreachable`]. Default
    /// [`MatcherUnreachablePolicy::FailClosed`].
    fn matcher_unreachable_policy(&self) -> MatcherUnreachablePolicy {
        MatcherUnreachablePolicy::FailClosed
    }
}

/// Default no-op [`PerceptualHashMatcher`] — returns `NoMatch` for
/// every check and reports an empty database list. Persist ships this
/// as the default impl; operators install a real matcher via the
/// backend's `set_perceptual_hash_matcher` setter.
///
/// # Why ship this instead of `Option<...>`
///
/// The backend's setter takes
/// `Option<Arc<dyn PerceptualHashMatcher>>` so the default state is
/// `None` (no allocation, no hook invocation in `put_blob_signing`).
/// `NullPerceptualHashMatcher` is the value an operator installs when
/// they want the trait surface present (for telemetry tests, etc.) but
/// don't have a real matcher backend wired yet — distinct from
/// "matcher absent" (`None` = bypass the hook).
pub struct NullPerceptualHashMatcher;

#[async_trait::async_trait]
impl PerceptualHashMatcher for NullPerceptualHashMatcher {
    async fn check(
        &self,
        _sha256: &[u8; 32],
        _body: &[u8],
    ) -> Result<HashMatchResult, HashMatchError> {
        Ok(HashMatchResult::NoMatch)
    }

    fn databases(&self) -> &[HashDatabaseId] {
        &[]
    }

    fn on_match_policy(&self) -> OnMatchPolicy {
        OnMatchPolicy::Refuse
    }
}

/// Shared-reference helper.
pub type SharedMatcher = Arc<dyn PerceptualHashMatcher>;

impl std::fmt::Debug for HashMatchResult {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::NoMatch => f.write_str("NoMatch"),
            Self::Match {
                database,
                score,
                threshold,
            } => f
                .debug_struct("Match")
                .field("database", database)
                .field("score", score)
                .field("threshold", threshold)
                .finish(),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    struct AlwaysMatch {
        db: HashDatabaseId,
        on_match: OnMatchPolicy,
        unreachable: MatcherUnreachablePolicy,
    }

    #[async_trait::async_trait]
    impl PerceptualHashMatcher for AlwaysMatch {
        async fn check(
            &self,
            _sha256: &[u8; 32],
            _body: &[u8],
        ) -> Result<HashMatchResult, HashMatchError> {
            Ok(HashMatchResult::Match {
                database: self.db.clone(),
                score: 0.99,
                threshold: 0.5,
            })
        }
        fn databases(&self) -> &[HashDatabaseId] {
            std::slice::from_ref(&self.db)
        }
        fn on_match_policy(&self) -> OnMatchPolicy {
            self.on_match
        }
        fn matcher_unreachable_policy(&self) -> MatcherUnreachablePolicy {
            self.unreachable
        }
    }

    #[tokio::test]
    async fn null_matcher_admits_everything() {
        let m = NullPerceptualHashMatcher;
        let r = m.check(&[0u8; 32], b"anything").await.unwrap();
        assert!(matches!(r, HashMatchResult::NoMatch));
        assert!(m.databases().is_empty());
        assert_eq!(m.on_match_policy(), OnMatchPolicy::Refuse);
        assert_eq!(
            m.matcher_unreachable_policy(),
            MatcherUnreachablePolicy::FailClosed
        );
    }

    #[tokio::test]
    async fn always_match_reports_threshold_and_score() {
        let m = AlwaysMatch {
            db: HashDatabaseId("test-ncmec".into()),
            on_match: OnMatchPolicy::Refuse,
            unreachable: MatcherUnreachablePolicy::FailClosed,
        };
        let r = m.check(&[0u8; 32], b"x").await.unwrap();
        match r {
            HashMatchResult::Match {
                database,
                score,
                threshold,
            } => {
                assert_eq!(database.0, "test-ncmec");
                assert!(score > threshold);
            }
            other => panic!("expected match, got {other:?}"),
        }
    }

    #[test]
    fn fail_closed_is_default_for_unreachable() {
        let m = NullPerceptualHashMatcher;
        assert_eq!(
            m.matcher_unreachable_policy(),
            MatcherUnreachablePolicy::FailClosed
        );
    }
}
