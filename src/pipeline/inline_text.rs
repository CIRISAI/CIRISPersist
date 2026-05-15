//! v1.1.0 (CIRISPersist#33): [`InlineTextEnvelope`] — single-body
//! [`WireEnvelope`] for SPEAK / LLM-prompt / WBD / DSAR flows.
//!
//! The agent's SPEAK handler (CIRISAgent#756 concern #1) constructs
//! one of these, runs the outbound pipeline (see
//! [`default_speak_pipeline`](super::default_speak_pipeline) for the
//! Classify → Scrub → EncryptAndStore stage set), and ships the
//! possibly-redacted text to the communication gateway.
//!
//! Unlike [`crate::schema::BatchEnvelope`] (multi-component, signed,
//! corpus-bound), `InlineTextEnvelope` is intentionally minimal: one
//! string body, no per-component structure, no signature material on
//! the type itself (callers pass a `canonical_seed` if they need a
//! non-empty `canonical_bytes()` projection for an upstream verifier).

use crate::pipeline::wire_envelope::{MatchAddress, WireEnvelope};

/// v1.1.0 (CIRISPersist#33): envelope wrapping a single inline-text
/// payload for SPEAK / LLM-prompt / WBD / DSAR flows.
///
/// # Direction
///
/// Typically OUTBOUND (agent emits SPEAK / LLM completion to a
/// gateway) but the type is direction-agnostic. The
/// [`default_speak_pipeline`](super::default_speak_pipeline) factory
/// wires the canonical SPEAK-outbound stage set; callers wanting a
/// scan-only pipeline (no encrypt-and-store) compose via
/// [`default_outbound_pipeline`](super::default_outbound_pipeline).
///
/// # Fields
///
/// - `text`: the in-flight inline text. ScrubStage may mutate this in
///   place; EncryptAndStoreStage may replace cleartext spans with
///   `{SECRET:uuid:description}` placeholders.
/// - `canonical_seed`: optional bytes returned from
///   [`WireEnvelope::canonical_bytes`]. Typically empty for ephemeral
///   inline use; non-empty when the caller has an upstream signature
///   that pins a canonical projection.
#[derive(Debug, Clone)]
pub struct InlineTextEnvelope {
    /// The in-flight inline text. Mutable through
    /// [`WireEnvelope::mutate_body`].
    pub text: String,
    /// Caller-supplied seed for [`WireEnvelope::canonical_bytes`].
    /// Typically empty. Reserved for cases where the outbound text
    /// is itself signed and the verifier asks for the canonical
    /// projection.
    pub canonical_seed: Vec<u8>,
}

impl InlineTextEnvelope {
    /// Construct an envelope from a single text body. `canonical_seed`
    /// is empty by default; set it via direct struct construction
    /// when the upstream signature requires a non-empty projection.
    pub fn new(text: impl Into<String>) -> Self {
        Self {
            text: text.into(),
            canonical_seed: Vec::new(),
        }
    }
}

impl WireEnvelope for InlineTextEnvelope {
    fn canonical_bytes(&self) -> Vec<u8> {
        self.canonical_seed.clone()
    }

    fn text_bodies(&self) -> Box<dyn Iterator<Item = (MatchAddress, String)> + '_> {
        Box::new(std::iter::once((
            MatchAddress::InlineText { json_path: None },
            self.text.clone(),
        )))
    }

    fn mutate_body(&mut self, addr: &MatchAddress, mutator: &mut dyn FnMut(&mut String)) {
        if matches!(addr, MatchAddress::InlineText { .. }) {
            mutator(&mut self.text);
        }
        // BatchComponent address on an InlineTextEnvelope → no-op.
    }

    fn body_count(&self) -> usize {
        1
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn inline_text_envelope_body_count_is_one() {
        let env = InlineTextEnvelope::new("hello");
        assert_eq!(env.body_count(), 1);
    }

    #[test]
    fn inline_text_envelope_text_bodies_yields_single_body() {
        let env = InlineTextEnvelope::new("hello world");
        let bodies: Vec<_> = env.text_bodies().collect();
        assert_eq!(bodies.len(), 1);
        assert_eq!(bodies[0].0, MatchAddress::InlineText { json_path: None });
        assert_eq!(bodies[0].1, "hello world");
    }

    #[test]
    fn inline_text_envelope_mutate_body_updates_text() {
        let mut env = InlineTextEnvelope::new("alpha");
        env.mutate_body(
            &MatchAddress::InlineText { json_path: None },
            &mut |s: &mut String| {
                *s = "REDACTED".into();
            },
        );
        assert_eq!(env.text, "REDACTED");
    }

    #[test]
    fn inline_text_envelope_mutate_body_ignores_batch_address() {
        let mut env = InlineTextEnvelope::new("alpha");
        env.mutate_body(
            &MatchAddress::BatchComponent {
                index: 0,
                json_path: None,
            },
            &mut |s: &mut String| {
                *s = "PWNED".into();
            },
        );
        assert_eq!(env.text, "alpha");
    }

    #[test]
    fn inline_text_envelope_canonical_bytes_returns_seed() {
        let env = InlineTextEnvelope {
            text: "hi".into(),
            canonical_seed: vec![1, 2, 3],
        };
        assert_eq!(env.canonical_bytes(), vec![1, 2, 3]);
    }
}
