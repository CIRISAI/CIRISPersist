//! Schema-version gate (FSD §3.4 robustness primitive #3).
//!
//! Mission (MISSION.md §7 failure mode "schema version handled
//! loosely"): bump the constant, write a migrator, never accept
//! out-of-set silently. PoB §2.4's N_eff measurement depends on the
//! corpus shape staying defined.

use serde::{Deserialize, Serialize};

/// Wire-format schema versions this build accepts.
///
/// Currently `"2.7.0"` — agent 2.7.8 ships this version
/// (TRACE_WIRE_FORMAT.md §3 / §6).
///
/// Phase 2 may add a `"2.8.0"` entry once the per-event chain
/// extension (FSD §4.5) lands; Phase 3 may add `"3.0.0"` for the
/// schema bump named in TRACE_EVENT_LOG_PERSISTENCE.md §8. Adding
/// a version is paired with writing a migrator from the old version
/// to the canonical internal shape.
pub const SUPPORTED_VERSIONS: &[&str] = &["2.7.0"];

/// Type-checked wrapper around a recognized schema version string.
///
/// Construction is gated by [`SUPPORTED_VERSIONS`]; an unrecognized
/// version is a typed error, not a silent acceptance.
#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize)]
#[serde(transparent)]
pub struct SchemaVersion(&'static str);

impl SchemaVersion {
    /// Validate `s` against [`SUPPORTED_VERSIONS`] and return the
    /// pinned `&'static str` if recognized.
    pub fn parse(s: &str) -> Result<Self, super::Error> {
        for &v in SUPPORTED_VERSIONS {
            if v == s {
                return Ok(SchemaVersion(v));
            }
        }
        Err(super::Error::UnsupportedSchemaVersion {
            got: s.to_owned(),
            supported: SUPPORTED_VERSIONS,
        })
    }

    /// Borrow as `&'static str`. Stable across builds for any given
    /// recognized version.
    #[inline]
    pub const fn as_str(&self) -> &'static str {
        self.0
    }
}

impl std::fmt::Display for SchemaVersion {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(self.0)
    }
}

impl<'de> Deserialize<'de> for SchemaVersion {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: serde::Deserializer<'de>,
    {
        // We accept any string here and validate at the next layer
        // (`BatchEnvelope::from_json`) so the error surfaces as a
        // typed `Error::UnsupportedSchemaVersion` rather than getting
        // wrapped in `serde_json::Error`. Mission constraint
        // (MISSION.md §3 anti-pattern #4): typed errors at every
        // boundary.
        let s = String::deserialize(deserializer)?;
        // Always succeed at the serde layer; the version is validated
        // after deserialization. The string is leaked into a
        // 'static via the SUPPORTED_VERSIONS list at validation time,
        // so this temporary stores a synthetic placeholder that
        // BatchEnvelope::from_json then resolves.
        Ok(SchemaVersion::parse_lenient(&s))
    }
}

impl SchemaVersion {
    /// Lenient parse used by `Deserialize`: accepts any string,
    /// caller (typically [`BatchEnvelope::from_json`]) is responsible
    /// for the typed validation pass.
    fn parse_lenient(s: &str) -> Self {
        for &v in SUPPORTED_VERSIONS {
            if v == s {
                return SchemaVersion(v);
            }
        }
        // Synthetic — unrecognized versions land here. The string
        // gets boxed and leaked once for diagnostic purposes; this
        // path is in error handling and runs at most once per
        // rejected batch.
        SchemaVersion(Box::leak(s.to_owned().into_boxed_str()))
    }

    /// True iff this `SchemaVersion` is in [`SUPPORTED_VERSIONS`].
    /// Used by [`BatchEnvelope::from_json`] for the typed gate.
    pub fn is_supported(&self) -> bool {
        SUPPORTED_VERSIONS.contains(&self.0)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parse_accepts_2_7_0() {
        let v = SchemaVersion::parse("2.7.0").expect("2.7.0 is supported");
        assert_eq!(v.as_str(), "2.7.0");
    }

    #[test]
    fn parse_rejects_old_version() {
        let err = SchemaVersion::parse("2.6.0").unwrap_err();
        match err {
            super::super::Error::UnsupportedSchemaVersion { got, supported } => {
                assert_eq!(got, "2.6.0");
                assert_eq!(supported, &["2.7.0"]);
            }
            _ => panic!("expected UnsupportedSchemaVersion, got {err:?}"),
        }
    }

    #[test]
    fn parse_rejects_future_version() {
        // Mission: PoB §2.4 corpus shape stays defined; future versions
        // require an explicit migrator (FSD §3.4 / version.rs doc), not
        // best-effort parsing.
        assert!(SchemaVersion::parse("2.8.0").is_err());
        assert!(SchemaVersion::parse("3.0.0").is_err());
    }

    #[test]
    fn parse_rejects_garbage() {
        assert!(SchemaVersion::parse("").is_err());
        assert!(SchemaVersion::parse("not-a-version").is_err());
        assert!(SchemaVersion::parse("2.7.0-alpha").is_err());
    }

    #[test]
    fn deserialize_lenient_with_typed_validation() {
        // Mission constraint: serde::Deserialize is lenient so that
        // unsupported versions surface as typed
        // `Error::UnsupportedSchemaVersion` from
        // `BatchEnvelope::from_json` rather than getting wrapped in
        // `serde_json::Error`. The lenient deserialize succeeds; the
        // `is_supported()` gate at the next layer rejects.
        let ok: SchemaVersion = serde_json::from_str("\"2.7.0\"").unwrap();
        assert_eq!(ok.as_str(), "2.7.0");
        assert!(ok.is_supported());

        let bad: SchemaVersion = serde_json::from_str("\"99.0.0\"").unwrap();
        assert_eq!(bad.as_str(), "99.0.0");
        assert!(!bad.is_supported(), "is_supported gate rejects 99.0.0");
    }

    #[test]
    fn parse_strict_still_rejects() {
        // The constructor for typed code paths (Phase 2 internal
        // signing, etc.) stays strict.
        assert!(SchemaVersion::parse("99.0.0").is_err());
    }
}
