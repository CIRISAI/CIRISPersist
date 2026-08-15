//! v32.0.0 (CIRISPersist#690) — **the envelope states what the scrub actually
//! did, the signature covers that statement, and the door refuses a mismatch.**
//!
//! Before this, `ScrubEnvelope` attested THAT a scrub ran and who ran it — never
//! WHAT the content received. `NullScrubber` is a pass-through and produced a
//! perfectly valid, signed envelope, so a receiver could not tell an
//! NER-scrubbed `full_traces` trace from one that was never scrubbed at all.
//!
//! That became load-bearing when scrubbing moved to the sender's egress:
//! `apply_replicated_*` applies federated rows verbatim, so the sender's scrub
//! is the only one that will ever happen, and a receiver's only defence is to
//! refuse content that did not arrive properly treated.
//!
//! Three properties, and the third is the one that stops this being another
//! stored-and-unread signal (the #685 shape):
//!
//! 1. the scrubber REPORTS its treatment honestly;
//! 2. the signature COVERS that report, so it cannot be rewritten in flight;
//! 3. a door REFUSES a `full_traces` batch that did not get a named-entity pass.

#![cfg(feature = "sqlite")]

use ciris_persist::ingest::scrub_preimage;

/// **The signature covers the treatment, not just the payload.**
///
/// The old `scrub_signature` was `sign(canonical(post_scrub_content))` — a
/// signature over the CONTENT and nothing else, leaving every statement about
/// the content as unsigned metadata beside it. That is #643 on this plane, where
/// the attestation signature covered the envelope only and left the verb an
/// unsigned column a relay could rewrite.
///
/// So: flipping any bound field must change the bytes that get signed. Asserted
/// field by field rather than in aggregate, because an aggregate check passes
/// if only ONE field is really bound.
#[test]
fn every_treatment_claim_is_inside_the_signed_preimage_690() {
    let now = chrono::Utc::now();
    let base = scrub_preimage(
        "post-sha",
        "orig-hash",
        true,
        "full_traces",
        Some("model-abc"),
        "key-1",
        now,
    );

    // ner_ran — the claim the whole issue is about.
    let flipped_ner = scrub_preimage(
        "post-sha",
        "orig-hash",
        false,
        "full_traces",
        Some("model-abc"),
        "key-1",
        now,
    );
    assert_ne!(
        base, flipped_ner,
        "ner_ran is not inside the signed bytes — a relay could flip it and the \
         signature would still verify, which is exactly the unsigned-claim \
         problem #690 exists to remove"
    );

    // trace_level — the half that is easy to under-weight. Without it, content
    // LABELLED full_traces that received Detailed treatment is expressible with
    // an honest ner_ran beside it.
    let flipped_level = scrub_preimage(
        "post-sha",
        "orig-hash",
        true,
        "detailed",
        Some("model-abc"),
        "key-1",
        now,
    );
    assert_ne!(base, flipped_level, "trace_level is not bound");

    // model digest — "an NER pass ran" versus "an NER pass I accept ran".
    let flipped_model = scrub_preimage(
        "post-sha",
        "orig-hash",
        true,
        "full_traces",
        Some("model-xyz"),
        "key-1",
        now,
    );
    assert_ne!(base, flipped_model, "scrubber_model_digest is not bound");

    // And absence must differ from presence — otherwise "no model" and "some
    // model" collapse, which is the same ambiguity as fields_modified == 0.
    let no_model = scrub_preimage(
        "post-sha",
        "orig-hash",
        true,
        "full_traces",
        None,
        "key-1",
        now,
    );
    assert_ne!(
        base, no_model,
        "None and Some(model) must not canonicalize alike"
    );

    // The pre-existing fields stay bound — this widened the preimage, it did not
    // trade one set of claims for another.
    let flipped_orig = scrub_preimage(
        "post-sha",
        "other-hash",
        true,
        "full_traces",
        Some("model-abc"),
        "key-1",
        now,
    );
    assert_ne!(base, flipped_orig, "original_content_hash is not bound");
    let flipped_key = scrub_preimage(
        "post-sha",
        "orig-hash",
        true,
        "full_traces",
        Some("model-abc"),
        "key-2",
        now,
    );
    assert_ne!(base, flipped_key, "scrub_key_id is not bound");
    let flipped_content = scrub_preimage(
        "other-sha",
        "orig-hash",
        true,
        "full_traces",
        Some("model-abc"),
        "key-1",
        now,
    );
    assert_ne!(
        base, flipped_content,
        "the post-scrub CONTENT is not bound — the property that existed before \
         #690 must survive it"
    );
}

/// **The preimage is fixed-size regardless of trace size.**
///
/// It binds a HASH of the post-scrub content rather than the content itself.
/// CIRISServer#398 is the precedent: a widened genesis preimage reached 83,060
/// bytes and PKCS#11 PureEdDSA refused to sign it, stopping a ceremony after two
/// hardware-key taps. A scrub signature runs on every ingested component, so a
/// size that grows with payload would be worse, not better.
#[test]
fn the_preimage_does_not_grow_with_the_payload_690() {
    let now = chrono::Utc::now();
    let small = scrub_preimage(
        "a".repeat(64).as_str(),
        "o",
        true,
        "full_traces",
        Some("m"),
        "k",
        now,
    );
    // A hash is a hash: the "content" is already reduced before it gets here.
    let same_shape = scrub_preimage(
        "b".repeat(64).as_str(),
        "o",
        true,
        "full_traces",
        Some("m"),
        "k",
        now,
    );
    assert_eq!(
        small.len(),
        same_shape.len(),
        "two different content hashes must produce equal-length preimages — if \
         this ever depends on payload size, a hardware signer will refuse it \
         under load (CIRISServer#398)"
    );
    assert!(
        small.len() < 512,
        "the preimage should be a few hundred bytes, got {} — something \
         payload-sized has leaked in",
        small.len()
    );
}
