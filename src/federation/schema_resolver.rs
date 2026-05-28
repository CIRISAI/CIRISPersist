//! Per-axis envelope-schema resolution + validation hook
//! (CIRISPersist#102 Ask 4, v2.5.0).
//!
//! # Mission alignment (FSD-002 §4.9.1)
//!
//! Every `{axis}` value emittable under `detection:correlated_action:*`
//! MUST carry an operational definition in the named calibration-package
//! version (FSD-002 §4.9.1). The definition is machine-checkable:
//! measurement procedure + threshold function + statistical floor +
//! evidence-shape requirement + polarity semantics. Persist enforces
//! the **evidence-shape requirement** by validating the incoming
//! `attestation_envelope` against the per-axis JSON Schema document at
//! admission time.
//!
//! The schemas themselves are content-addressed (`sha256:...`) and
//! referenced via `evidence_refs[]` on every attestation. Persist's
//! [`BlobStorage`](crate::federation::BlobStorage) substrate (v2.3.0,
//! CIRISPersist#103) IS where they live; the
//! [`BlobBackedSchemaResolver`] looks them up by SHA via
//! `BlobStorage::get_blob`.
//!
//! # Trait shape (`async fn` in trait, NOT `async_trait`)
//!
//! Persist uses Rust 1.75+ native `async fn in trait` (with explicit
//! `+ Send` futures) for every federation surface — matches
//! [`FederationDirectory`](crate::federation::FederationDirectory) +
//! [`BlobStorage`](crate::federation::BlobStorage). Trait is NOT
//! object-safe by that choice. To compose impls behind `Arc<dyn ...>`
//! the public trait is the object-safe shape (one `async fn` returning
//! `Pin<Box<dyn Future + Send>>`), which is what the admission hook
//! wires through. The boxing cost is one allocation per `put_attestation`
//! when a non-default resolver is installed — acceptable for the
//! infrequent path.
//!
//! # Default policy: fail-open on unknown axes
//!
//! [`SchemaResolver::resolve`] returns `Ok(None)` when no schema is
//! registered for the resolved axis. The admission hook treats that
//! as "validation skipped" — fail-open by default; deployments wire
//! stricter via configuration (e.g., by installing a resolver whose
//! `resolve` errors on unknown axes). The rationale: persist is the
//! substrate, not the calibration-package source-of-truth — the axis
//! index is operator-supplied (see [`BlobBackedSchemaResolver`]'s
//! `axis_index` field); demanding the substrate has a schema for
//! *every* axis would couple substrate readiness to calibration-package
//! readiness, which would block any new axis introduction.
//!
//! # Dimension → axis derivation
//!
//! See [`axis_from_dimension`] for the rule. Worked example from
//! FSD-002 §4.9.1: `detection:correlated_action:rights_asymmetry:v1`
//! → axis `rights_asymmetry`. The schema lives at
//! `ratchet_calibration_v{N}:axes:rights_asymmetry:sha256:f311...`
//! and is referenced via `evidence_refs[]` on every attestation.

#[cfg(any(feature = "postgres", feature = "sqlite"))]
use std::collections::HashMap;
use std::future::Future;
use std::pin::Pin;
#[cfg(any(feature = "postgres", feature = "sqlite"))]
use std::sync::{Arc, Mutex};

use serde::{Deserialize, Serialize};

#[cfg(any(feature = "postgres", feature = "sqlite"))]
use super::blobs::{BlobBody, BlobStorage};

/// v2.5.0 (CIRISPersist#102 Ask 4) — a per-axis JSON Schema resolved
/// at admission time.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct AxisSchema {
    /// 32-byte SHA-256 the schema lives under (content-addressed per
    /// FSD-002 §4.9.1).
    pub sha256: [u8; 32],
    /// The JSON Schema document body.
    pub document: serde_json::Value,
}

/// v2.5.0 (CIRISPersist#102 Ask 4) — errors from [`SchemaResolver::resolve`].
#[derive(Debug, thiserror::Error)]
pub enum SchemaResolverError {
    /// The resolver was asked to fetch a schema by its registered
    /// SHA, but the underlying [`BlobStorage`](crate::federation::BlobStorage)
    /// either had no row or returned an `External` body (which persist
    /// does not de-reference; schemas are inline-bytes by contract).
    #[error("axis schema not found in blob storage (axis={axis:?}, sha256={sha256_hex})")]
    SchemaBlobMissing {
        /// The axis name the resolver was asked to resolve.
        axis: String,
        /// Hex-encoded SHA-256 of the schema blob that should have
        /// been present.
        sha256_hex: String,
    },

    /// The resolved blob bytes do not parse as JSON. Indicates either
    /// content corruption (the SHA matched a non-JSON blob) or a
    /// caller writing a non-JSON schema by mistake.
    #[error("axis schema bytes are not valid JSON (axis={axis:?}, sha256={sha256_hex}): {detail}")]
    SchemaNotJson {
        /// The axis name.
        axis: String,
        /// Hex-encoded SHA-256 of the schema blob.
        sha256_hex: String,
        /// Parser error detail.
        detail: String,
    },

    /// Backend-level error from the blob substrate (DB connection,
    /// serialization, etc.).
    #[error("backend: {0}")]
    Backend(String),
}

impl SchemaResolverError {
    /// Stable string-token for telemetry / structured logging.
    pub fn kind(&self) -> &'static str {
        match self {
            SchemaResolverError::SchemaBlobMissing { .. } => "schema_resolver_blob_missing",
            SchemaResolverError::SchemaNotJson { .. } => "schema_resolver_not_json",
            SchemaResolverError::Backend(_) => "schema_resolver_backend",
        }
    }
}

/// v2.5.0 (CIRISPersist#102 Ask 4) — object-safe per-axis schema
/// lookup trait. Resolves the JSON Schema for a given dimension's
/// axis (FSD-002 §4.9.1) at admission time.
///
/// # Object-safety
///
/// Persist's other federation traits ([`FederationDirectory`](crate::federation::FederationDirectory),
/// [`BlobStorage`](crate::federation::BlobStorage)) use native
/// `async fn in trait`, which is NOT object-safe. The `SchemaResolver`
/// trait deliberately deviates — the admission hook stores
/// `Arc<dyn SchemaResolver>` on each backend so deployments wire a
/// resolver at construction time without needing a backend-specific
/// generic parameter. The `Pin<Box<dyn Future>>` return type is the
/// object-safe equivalent of `async fn`; the boxing cost is one
/// allocation per attestation when a non-default resolver is
/// installed — acceptable for the typically-rare write path.
///
/// # Fail-open default
///
/// `resolve` returning `Ok(None)` means "no schema registered for
/// this axis" — the admission hook treats it as "validation skipped".
/// See module-level docs §"Default policy".
pub trait SchemaResolver: Send + Sync {
    /// Resolve the per-axis JSON Schema for the given `dimension`
    /// string.
    ///
    /// Implementations derive the axis from the dimension (typically
    /// via [`axis_from_dimension`]), look up the registered schema,
    /// and return its body + content-addressed SHA. Returns
    /// `Ok(None)` when no schema is registered.
    fn resolve<'a>(
        &'a self,
        dimension: &'a str,
    ) -> Pin<Box<dyn Future<Output = Result<Option<AxisSchema>, SchemaResolverError>> + Send + 'a>>;
}

/// v2.5.0 (CIRISPersist#102 Ask 4) — the default resolver. Always
/// returns `None`.
///
/// Used as the default on every backend constructor; existing
/// `put_attestation` callers don't break — the schema-validation
/// hook is a no-op until an operator wires a different resolver via
/// `with_schema_resolver`.
#[derive(Debug, Default, Clone, Copy)]
pub struct NoOpSchemaResolver;

impl SchemaResolver for NoOpSchemaResolver {
    fn resolve<'a>(
        &'a self,
        _dimension: &'a str,
    ) -> Pin<Box<dyn Future<Output = Result<Option<AxisSchema>, SchemaResolverError>> + Send + 'a>>
    {
        Box::pin(async { Ok(None) })
    }
}

/// v2.5.0 (CIRISPersist#102 Ask 4) — resolver that fetches schemas
/// from [`BlobStorage`](crate::federation::BlobStorage) by the
/// content-addressed SHA registered for each axis.
///
/// # Construction
///
/// ```ignore
/// use std::collections::HashMap;
/// use std::sync::Arc;
/// use ciris_persist::federation::BlobBackedSchemaResolver;
/// use ciris_persist::store::SqliteBackend;
///
/// let mut axis_index = HashMap::new();
/// axis_index.insert("rights_asymmetry".to_owned(), [0xf3, 0x11, /* ... 30 more bytes */]);
/// let backend: Arc<SqliteBackend> = /* ... */;
/// let resolver = BlobBackedSchemaResolver::new(axis_index, backend);
/// ```
///
/// # Generic over backend `B`
///
/// [`BlobStorage`](crate::federation::BlobStorage) is NOT object-safe
/// (it uses native `async fn in trait`), so the resolver holds a
/// concrete `Arc<B>` rather than `Arc<dyn BlobStorage>`. Deployments
/// pick the concrete backend type at construction time; the
/// resulting `Arc<BlobBackedSchemaResolver<B>>` IS dyn-coercible to
/// `Arc<dyn SchemaResolver>` (the resolver trait is object-safe by
/// design — see [`SchemaResolver`]'s docs).
///
/// # Cache shape
///
/// Schemas resolve to the **same** JSON Schema across the lifetime
/// of an axis_index → SHA mapping (the SHA IS the schema's identity
/// — content-addressed). The resolver caches resolved bodies in an
/// `Arc<Mutex<HashMap<[u8; 32], serde_json::Value>>>`. Choice notes:
///
/// - **`Mutex<HashMap>` not `LruCache`**: schemas are bounded by the
///   axis vocabulary's size (FSD-002 §4.9 — current axes count in the
///   ~10s, even with §4.9.2 amendment churn unlikely to exceed
///   ~100s in any deployment's lifetime). An LRU's eviction shape
///   adds complexity for no win at that cardinality; a plain
///   `HashMap` is the right primitive. The cache key is the SHA
///   (32 bytes), not the axis name — a future deploy can swap the
///   axis_index mapping atomically and the cache still hits on
///   schemas that didn't change SHA.
/// - **`Mutex` not `RwLock`**: writes are cache-fill (first call per
///   SHA) and overwhelmingly outnumbered by reads, BUT the critical
///   sections are tiny (one `HashMap::get` clone, or one `insert`).
///   `Mutex` is faster on the uncontended hot path than `RwLock` and
///   matches the rest of persist's in-memory shape (see
///   `MemoryBackend`).
#[cfg(any(feature = "postgres", feature = "sqlite"))]
pub struct BlobBackedSchemaResolver<B: BlobStorage + 'static> {
    /// Deployer-supplied mapping `axis_name → schema SHA-256`. In
    /// v0.1 persist doesn't fetch this from a remote registry —
    /// operators populate the map at construction time. A future cut
    /// can add a `RemoteSchemaResolver` that fetches the index from
    /// CIRISRegistry; out of scope for v2.5.0.
    pub axis_index: HashMap<String, [u8; 32]>,
    /// The blob substrate the resolver pulls schema bytes from.
    backend: Arc<B>,
    /// Resolved-schema cache. Keyed by content SHA (not axis name)
    /// so axis_index churn doesn't invalidate cached bodies.
    cache: Arc<Mutex<HashMap<[u8; 32], serde_json::Value>>>,
}

#[cfg(any(feature = "postgres", feature = "sqlite"))]
impl<B: BlobStorage + 'static> BlobBackedSchemaResolver<B> {
    /// Construct a resolver with the given `axis_name → SHA-256` map
    /// and blob backend. Cache is empty at construction.
    pub fn new(axis_index: HashMap<String, [u8; 32]>, backend: Arc<B>) -> Self {
        Self {
            axis_index,
            backend,
            cache: Arc::new(Mutex::new(HashMap::new())),
        }
    }

    /// True iff the resolver has cached the schema body for `sha256`.
    /// Used by tests to confirm cache-hit behavior; not part of the
    /// stable public surface.
    #[doc(hidden)]
    pub fn cached(&self, sha256: &[u8; 32]) -> bool {
        let guard = self.cache.lock().expect("BlobBackedSchemaResolver cache");
        guard.contains_key(sha256)
    }
}

#[cfg(any(feature = "postgres", feature = "sqlite"))]
impl<B: BlobStorage + 'static> SchemaResolver for BlobBackedSchemaResolver<B> {
    fn resolve<'a>(
        &'a self,
        dimension: &'a str,
    ) -> Pin<Box<dyn Future<Output = Result<Option<AxisSchema>, SchemaResolverError>> + Send + 'a>>
    {
        Box::pin(async move {
            // 1. Derive the axis. None → no schema (fail-open).
            let Some(axis) = axis_from_dimension(dimension) else {
                return Ok(None);
            };
            // 2. Look up the SHA. Missing → no schema (fail-open).
            let Some(sha256) = self.axis_index.get(axis).copied() else {
                return Ok(None);
            };
            // 3. Cache hit?
            {
                let guard = self.cache.lock().expect("BlobBackedSchemaResolver cache");
                if let Some(doc) = guard.get(&sha256) {
                    return Ok(Some(AxisSchema {
                        sha256,
                        document: doc.clone(),
                    }));
                }
            }
            // 4. Fetch + parse.
            let body = self.backend.get_blob(&sha256).await.map_err(|e| {
                SchemaResolverError::Backend(format!("get_blob: {} ({})", e, e.kind()))
            })?;
            let bytes = match body {
                Some(BlobBody::Inline(b)) => b,
                Some(BlobBody::External(_)) | None => {
                    return Err(SchemaResolverError::SchemaBlobMissing {
                        axis: axis.to_string(),
                        sha256_hex: hex::encode(sha256),
                    });
                }
            };
            let document: serde_json::Value =
                serde_json::from_slice(&bytes).map_err(|e| SchemaResolverError::SchemaNotJson {
                    axis: axis.to_string(),
                    sha256_hex: hex::encode(sha256),
                    detail: e.to_string(),
                })?;
            // 5. Insert into cache.
            {
                let mut guard = self.cache.lock().expect("BlobBackedSchemaResolver cache");
                guard.insert(sha256, document.clone());
            }
            Ok(Some(AxisSchema { sha256, document }))
        })
    }
}

/// v2.5.0 (CIRISPersist#102 Ask 4, FSD-002 §4.9.1) — derive the axis
/// name from a dimension string.
///
/// # Rule
///
/// The axis is the **last segment that does NOT match `:v[0-9]+`**.
/// Segments are split by `:`. Whitespace-trimmed.
///
/// # Worked examples (per FSD-002 §4.9.1)
///
/// - `detection:correlated_action:rights_asymmetry:v1` → `rights_asymmetry`
/// - `detection:correlated_action:participation_inclusion:v2` → `participation_inclusion`
/// - `accord:human_dignity:v1` → `human_dignity`
/// - `dma:idma:k_eff` → `k_eff` (no version segment; last is the axis)
/// - `rights_asymmetry` (single segment, no version) → `rights_asymmetry`
/// - `rights_asymmetry:v1` (single non-version segment + version) → `rights_asymmetry`
///
/// # Edge cases
///
/// - Empty string → `None`.
/// - All segments are `:v[0-9]+` (e.g. `:v1:v2`) → `None`.
pub fn axis_from_dimension(dimension: &str) -> Option<&str> {
    let trimmed = dimension.trim();
    if trimmed.is_empty() {
        return None;
    }
    // Walk segments back-to-front, pick the first non-version one.
    let mut last_non_version: Option<&str> = None;
    for seg in trimmed.split(':') {
        if seg.is_empty() {
            continue;
        }
        if is_version_segment(seg) {
            continue;
        }
        last_non_version = Some(seg);
    }
    last_non_version
}

/// True iff `seg` matches `^v[0-9]+$` exactly.
fn is_version_segment(seg: &str) -> bool {
    let bytes = seg.as_bytes();
    if bytes.len() < 2 || bytes[0] != b'v' {
        return false;
    }
    bytes[1..].iter().all(|b| b.is_ascii_digit())
}

/// v2.5.0 (CIRISPersist#102 Ask 4) — validate an `attestation_envelope`
/// against a per-axis JSON Schema. Returns the human-readable
/// violations on failure.
///
/// Used by the `put_attestation` admission hook. Pulled out as a
/// standalone helper so the admission hook stays trivial — the
/// validation logic + violation formatting lives here.
#[cfg(any(feature = "postgres", feature = "sqlite"))]
pub(crate) fn validate_envelope_against_schema(
    schema: &serde_json::Value,
    envelope: &serde_json::Value,
) -> Result<(), Vec<String>> {
    // `jsonschema::validator_for` returns Err if the SCHEMA itself
    // doesn't parse as JSON Schema (compile error). Map that to a
    // single-element violation so the caller surfaces a typed error
    // pointing at the bad schema, not at the attestation.
    let validator = match jsonschema::validator_for(schema) {
        Ok(v) => v,
        Err(e) => return Err(vec![format!("schema compile error: {e}")]),
    };
    let errors: Vec<String> = validator
        .iter_errors(envelope)
        .map(|e| e.to_string())
        .collect();
    if errors.is_empty() {
        Ok(())
    } else {
        Err(errors)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    // ── axis_from_dimension worked examples ─────────────────────────

    #[test]
    fn axis_from_correlated_action_rights_asymmetry_v1() {
        // FSD-002 §4.9.1 worked example.
        assert_eq!(
            axis_from_dimension("detection:correlated_action:rights_asymmetry:v1"),
            Some("rights_asymmetry")
        );
    }

    #[test]
    fn axis_from_correlated_action_participation_v2() {
        assert_eq!(
            axis_from_dimension("detection:correlated_action:participation_inclusion:v2"),
            Some("participation_inclusion")
        );
    }

    #[test]
    fn axis_from_accord_dimension() {
        assert_eq!(
            axis_from_dimension("accord:human_dignity:v1"),
            Some("human_dignity")
        );
    }

    #[test]
    fn axis_from_versionless_dimension_returns_last_segment() {
        // Versionless dim → return the last non-version segment.
        assert_eq!(axis_from_dimension("dma:idma:k_eff"), Some("k_eff"));
    }

    #[test]
    fn axis_from_single_segment() {
        assert_eq!(
            axis_from_dimension("rights_asymmetry"),
            Some("rights_asymmetry")
        );
    }

    #[test]
    fn axis_from_single_non_version_plus_version() {
        // Edge: single non-version segment + version segment.
        assert_eq!(
            axis_from_dimension("rights_asymmetry:v1"),
            Some("rights_asymmetry")
        );
    }

    #[test]
    fn axis_from_empty_dimension_is_none() {
        assert_eq!(axis_from_dimension(""), None);
        assert_eq!(axis_from_dimension("   "), None);
    }

    #[test]
    fn axis_from_all_version_segments_is_none() {
        // Pathological: every segment is a version. No axis.
        assert_eq!(axis_from_dimension("v1:v2:v3"), None);
        assert_eq!(axis_from_dimension(":v1:"), None);
    }

    #[test]
    fn axis_segment_starting_with_v_but_not_version_is_not_skipped() {
        // `verdict` starts with `v` but isn't `v[0-9]+`. Don't skip.
        assert_eq!(
            axis_from_dimension("detection:verdict_pending:v1"),
            Some("verdict_pending")
        );
        // `version_log` — same shape.
        assert_eq!(
            axis_from_dimension("system:version_log:v3"),
            Some("version_log")
        );
    }

    #[test]
    fn axis_from_multi_digit_version() {
        // `:v123` is a version segment.
        assert_eq!(
            axis_from_dimension("detection:correlated_action:my_axis:v123"),
            Some("my_axis")
        );
    }

    // ── is_version_segment edge cases ───────────────────────────────

    #[test]
    fn version_segment_matcher() {
        assert!(is_version_segment("v0"));
        assert!(is_version_segment("v1"));
        assert!(is_version_segment("v12345"));
        // Not v[0-9]+.
        assert!(!is_version_segment("v"));
        assert!(!is_version_segment("verdict"));
        assert!(!is_version_segment("v1a"));
        assert!(!is_version_segment("V1")); // uppercase
        assert!(!is_version_segment(""));
        assert!(!is_version_segment("1"));
    }

    // ── NoOpSchemaResolver ───────────────────────────────────────────

    #[tokio::test]
    async fn noop_resolver_returns_none() {
        let r = NoOpSchemaResolver;
        let out = r
            .resolve("detection:correlated_action:rights_asymmetry:v1")
            .await
            .unwrap();
        assert!(out.is_none());
    }

    #[test]
    fn schema_resolver_error_kinds_are_stable() {
        let e = SchemaResolverError::SchemaBlobMissing {
            axis: "ra".into(),
            sha256_hex: "ab".repeat(32),
        };
        assert_eq!(e.kind(), "schema_resolver_blob_missing");
        let e = SchemaResolverError::SchemaNotJson {
            axis: "ra".into(),
            sha256_hex: "ab".repeat(32),
            detail: "x".into(),
        };
        assert_eq!(e.kind(), "schema_resolver_not_json");
        let e = SchemaResolverError::Backend("x".into());
        assert_eq!(e.kind(), "schema_resolver_backend");
    }
}
