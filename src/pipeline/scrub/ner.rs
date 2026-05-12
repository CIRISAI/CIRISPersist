//! NER inference path — multilingual XLM-R / DistilBERT NER.
//!
//! v0.6.0-α2: stub-only. The full NER backends (Candle, ORT, model
//! loaders) are lifted from CIRISLens `cirislens-core/src/scrubber/`
//! in v0.6.0-α4 alongside the `scrub-ner` / `scrub-ort` Cargo
//! features and a `deny.toml` ignore block for the transitive
//! `number_prefix` + `paste` unmaintained advisories that the heavy
//! ML deps pull in.
//!
//! Until α4 lands, every call returns [`ScrubError::NerNotConfigured`]
//! — same shape as lens-core's stub when `feature = "ner"` is off.
//! `full_traces`-level traces are correctly rejected without NER per
//! FSD §6 (mission rejection — no silent multilingual coverage loss).

use super::{ScrubError, ScrubStats};

/// Returns `true` only when an NER backend is fully loaded and
/// ready. v0.6.0-α2 stub: always false (α4 wires the real backend
/// selector).
pub fn is_configured() -> bool {
    false
}

/// Single-text NER scrub. v0.6.0-α2 stub: always returns
/// [`ScrubError::NerNotConfigured`].
pub fn scrub_with_ner(_text: &str, _stats: &mut ScrubStats) -> Result<String, ScrubError> {
    Err(ScrubError::NerNotConfigured)
}

/// Batched NER scrub. v0.6.0-α2 stub: always returns
/// [`ScrubError::NerNotConfigured`].
pub fn scrub_batch(_texts: &[String], _stats: &mut ScrubStats) -> Result<Vec<String>, ScrubError> {
    Err(ScrubError::NerNotConfigured)
}
