//! v62.0.0 (PX-fix3) — **the one door by which an `Unsupported` answer may
//! read as "none".**
//!
//! On v62 there are two real backends (sqlite, postgres), which implement
//! every `FederationDirectory` method, and the capsule proxy, which routes the
//! methods a host needs and answers `Unsupported` for the rest. A match arm
//! that turns `Err(Error::Unsupported { .. })` into an empty / `None` /
//! `false` / `Ok` answer is therefore dead on both backends and, through the
//! proxy, the fail-open "an empty result set is not a settled state": a forked
//! group read as unforked, a tombstone read as absent, a roster read as the
//! head's own. Every such arm propagates now (PX-fix3).
//!
//! The exceptions are the sites where "this directory cannot answer" truly
//! IS "none" and cannot change a verdict: each calls [`unsupported_is_none`]
//! with a key listed in [`OPTIONAL_CAPABILITY_SITES`] beside its reason.
//! I2190 (from disk) holds every production `Unsupported` arm to this helper
//! and every key to one call; `P/tools/unsupported_arms.py` is its mirror.

use super::Error;

/// The sites that may read `Unsupported` as "none", each with why.
pub(crate) const OPTIONAL_CAPABILITY_SITES: &[(&str, &str)] = &[
    (
        "canonical_community::answered",
        "a CACHE-KEY read: `None` is keyed as null, never equal to an answer, so it can only \
         miss the standing cache; the verdict itself is computed by reads that propagate",
    ),
    (
        "canonical_community::lookup_signed_community",
        "a FALLBACK, not an answer: a directory without the signed-community point read is \
         paged for the same record, so the result is the same set either way",
    ),
    (
        "membership_acceptance::proposal_candidates",
        "a FALLBACK, not an answer: a directory without the targeted seek is read per signer by \
         dimension (V137), bounded, for the same set of proposal rows",
    ),
];

/// `read`'s value, or `None` when the directory answered `Unsupported`; every
/// other error propagates. `site` must be a key of
/// [`OPTIONAL_CAPABILITY_SITES`] (I2190 checks the call sites from disk).
///
/// # Errors
/// Every error of `read` but `Unsupported`.
pub(crate) fn unsupported_is_none<T>(
    read: Result<T, Error>,
    site: &'static str,
) -> Result<Option<T>, Error> {
    debug_assert!(
        OPTIONAL_CAPABILITY_SITES.iter().any(|(k, _)| *k == site),
        "unsupported_is_none: `{site}` is not an allowlisted optional-capability site"
    );
    match read {
        Ok(v) => Ok(Some(v)),
        Err(Error::Unsupported { method }) => {
            tracing::debug!(method, site, "optional capability absent on this directory");
            Ok(None)
        }
        Err(e) => Err(e),
    }
}
