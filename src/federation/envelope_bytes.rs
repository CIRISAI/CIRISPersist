//! v31.0.0 (CIRISPersist#645) — **the signature-covered envelope columns must
//! round-trip byte-exact, on every backend.**
//!
//! # What went wrong
//!
//! Eleven columns holding producer-signed envelopes were `JSONB` on Postgres
//! and `TEXT` on SQLite. `JSONB` is not a byte-preserving container: it parses
//! numbers into `numeric`, which discards exponent notation. Measured through
//! the real `put_public_key` → `lookup_public_key` path before V122 landed:
//!
//! ```text
//! submitted: {…,"exp":1e+2,…,"neg":1.5e-3,…}
//! reloaded:  {…,"exp":100,…,"neg":0.0015,…}
//! ```
//!
//! and with it, [`crate::federation::wire_index::content_hash_of`] moved from
//! `bf61b57c…` to `a6b819b3…`. That hash is deliberately
//! `sha256(serde_json::to_vec(record))` with **no** canonicalization step —
//! its whole design is that persist's hash equals CIRISEdge's by construction
//! because both sides hash the same bytes. A storage container that rewrites
//! those bytes breaks the identity: persist advertises `H`, a peer fetches by
//! `H`, and the record persist reloads no longer hashes to `H`.
//!
//! V105 had already written the rule down — "TEXT (not JSONB) for
//! signed_envelope: the envelope must round-trip BYTE-EXACT for re-publish,
//! and JSONB does not preserve the producer's serialization" — and V112
//! followed it. V122 retrofits the eleven planes that predate it.
//!
//! # v31.0.0 (CIRISPersist#647) — the claimed property moved
//!
//! The witnesses below no longer claim byte-identity with the PRODUCER. They
//! claim byte-identity with `ceg_produce_canonicalize(submitted)`, because
//! [`crate::federation::canonical_at_rest::canonicalize_in_place`] replaces
//! the envelope with its JCS form at every `put_*` chokepoint.
//!
//! Nothing here is weakened. V105's requirement was always byte-exactness
//! **through our storage**, not byte-identity **with the producer** — and it
//! is still V122's TEXT column that delivers it: `jsonb` would rewrite even
//! canonical bytes (`1e+21` renders as `1000000000000000000000` through
//! `numeric`). What the change adds is the operator-facing property #647
//! exists for, asserted here on all three backends:
//! `sha256sum(column) == original_content_hash`
//! ([`test_support::assert_column_sha256_is_original_content_hash`]).
//!
//! # Why the shared body exists
//!
//! The bug was **exactly** a backend divergence: the SQLite leg was correct all
//! along, so any witness that ran on one backend proved nothing about the
//! other. [`test_support::exercise_envelope_byte_exactness`] therefore takes a
//! `&dyn FederationDirectory` and is run identically by both SQL suites; the
//! parity assertion IS one body over two backends.

/// The envelope every witness in this module writes: awkward but entirely
/// legal JSON, chosen so each field probes one thing a container might
/// normalize.
///
/// `exp` / `neg` are the ones that actually caught the defect — Postgres
/// `jsonb` renders them `100` and `0.0015`. They are not a corner case:
/// Python's `json.dumps` emits `1e-05` for small floats and JavaScript's
/// `JSON.stringify` emits `1.5e-6`, and the producers upstream of these
/// envelopes are Python and JS. `serde_json` is built here with
/// `arbitrary_precision`, so a `Value` carries the producer's number token
/// verbatim and a TEXT column round-trips it unchanged.
///
/// The rest (`zz`/`aa` ordering, `one`/`trail` trailing zeros, an integer
/// wider than `i64`, non-ASCII, an escaped solidus) were measured NOT to
/// diverge through `jsonb`. They stay in the fixture anyway: they cost
/// nothing and they are what a future container swap would break first.
#[cfg(test)]
pub(crate) const AWKWARD_ENVELOPE_JSON: &str = concat!(
    r#"{"zz":"last","exp":1E+2,"neg":1.5e-3,"one":1.0,"trail":1.000,"#,
    r#""big":12345678901234567890123,"aa":"first","uni":"Aé","esc":"a\/b"}"#
);

/// [`AWKWARD_ENVELOPE_JSON`] parsed, with `dimension` and any caller-supplied
/// extra fields merged in so the value can be fed to admission gates that
/// require a shape.
///
/// Parsed from TEXT rather than built with `json!` on purpose: `json!` would
/// bake the numbers through Rust literals and lose the producer tokens this
/// module exists to protect.
#[cfg(test)]
#[must_use]
pub(crate) fn awkward_envelope(extra: &[(&str, serde_json::Value)]) -> serde_json::Value {
    let mut v: serde_json::Value =
        serde_json::from_str(AWKWARD_ENVELOPE_JSON).expect("the fixture is legal JSON");
    let map = v.as_object_mut().expect("the fixture is an object");
    for (k, val) in extra {
        map.insert((*k).to_string(), val.clone());
    }
    v
}

// v31.0.0 (#647) — gate widened to plain `#[cfg(test)]`. It used to be gated
// on the SQL backends because the only two callers were the sqlite and
// postgres suites, so a DEFAULT-feature `cargo check --all-targets` compiled
// dead code. #647's canonicalization hook is backend-AGNOSTIC — it runs in
// each backend's `put_*` — so the memory backend now runs the same body and
// the parity claim covers all three. The default leg therefore has a live
// caller and the dead-code hazard the old gate guarded against is gone.
#[cfg(test)]
pub(crate) mod test_support {
    use super::awkward_envelope;
    use crate::federation::FederationDirectory;

    /// Assert the reloaded envelope's bytes are the CANONICAL form of what
    /// was submitted, naming the column so a red says which plane regressed.
    ///
    /// **v31.0.0 (#647) changed the claimed property.** It used to be
    /// byte-identity with the producer; it is now byte-identity with
    /// `ceg_produce_canonicalize(submitted)`, because the ingest chokepoints
    /// replace the envelope with its canonical form
    /// ([`crate::federation::canonical_at_rest::canonicalize_in_place`]). The
    /// V122 requirement is unchanged and still satisfied — *more* robustly:
    /// what must survive storage is a byte sequence, and a `jsonb` column
    /// would still rewrite it (canonical `1e+21` renders as
    /// `1000000000000000000000` through `numeric`). TEXT stays.
    ///
    /// Compares `to_string` output rather than `Value == Value`, because
    /// `Value`'s `PartialEq` under `arbitrary_precision` compares the number
    /// TOKENS — which is what we want — but the bytes are the property being
    /// claimed, and asserting on them directly is what makes the failure
    /// message show the drift.
    pub(crate) fn assert_envelope_bytes_eq(
        column: &str,
        submitted: &serde_json::Value,
        reloaded: &serde_json::Value,
    ) {
        let expected = String::from_utf8(
            crate::federation::canonical_at_rest::canonical_bytes(submitted)
                .expect("the submitted envelope canonicalizes"),
        )
        .expect("JCS output is UTF-8");
        let got = serde_json::to_string(reloaded).expect("reloaded serializes");
        assert_eq!(
            expected, got,
            "{column} did not round-trip as CANONICAL bytes. Either the ingest \
             chokepoint stopped canonicalizing (#647) or the column stopped \
             preserving bytes — a JSONB column rewrites them (numbers are the usual \
             axis: 1e+21 -> 1000000000000000000000), which moves \
             wire_index::content_hash_of and breaks fetch-by-content-hash. The column \
             must be TEXT on BOTH backends — see V122."
        );
        // The invariant the operator actually cashes in: the bytes in the
        // column are the bytes a signature was taken over.
        crate::federation::canonical_at_rest::check_canonical_at_rest(reloaded)
            .unwrap_or_else(|e| panic!("{column} is not canonical at rest: {e}"));
    }

    /// v31.0.0 (#647) — **the operator's own check, run as a test.**
    ///
    /// `sha256sum` of the bytes sitting in the column must equal the row's
    /// `original_content_hash`. That is the whole point of canonical-at-rest:
    /// an artifact is decipherable by hand, with no JCS implementation
    /// required to check it.
    ///
    /// `reloaded` is the envelope as read back through the REAL read path, so
    /// `serde_json::to_string(reloaded)` is exactly the byte sequence the
    /// backend bound into the TEXT column (V122) — asserting here is
    /// asserting on the column.
    pub(crate) fn assert_column_sha256_is_original_content_hash(
        column: &str,
        reloaded: &serde_json::Value,
        original_content_hash: &str,
    ) {
        use sha2::{Digest as _, Sha256};
        let stored = serde_json::to_string(reloaded).expect("reloaded serializes");
        let digest = hex::encode(Sha256::digest(stored.as_bytes()));
        assert_eq!(
            digest, original_content_hash,
            "sha256sum of {column} is not the row's original_content_hash — the \
             artifact is NOT decipherable by hand at rest.\n  stored: {stored}"
        );
    }

    /// The shared witness, run against every SQL backend.
    ///
    /// Covers the three planes reachable without a multi-party ceremony:
    /// `federation_keys.registration_envelope`,
    /// `federation_attestations.attestation_envelope`, and
    /// `federation_revocations.revocation_envelope`. Each is written through
    /// its REAL put path and read back through its REAL read path — not a
    /// hand-rolled SQL probe, because the defect lived in the bind/decode pair
    /// and only the real pair exercises both halves.
    ///
    /// The remaining eight columns are covered by each backend's schema gate
    /// (`every_v122_envelope_column_is_text_*`), which asserts the stored TYPE
    /// directly and so reds for exactly the condition this body would.
    pub(crate) async fn exercise_envelope_byte_exactness(
        dir: &dyn FederationDirectory,
        suffix: &str,
    ) {
        use crate::federation::types::{attestation_tier, attestation_type};

        // ── 1. federation_keys.registration_envelope ────────────────
        let kid = format!("k-644-{suffix}");
        let envelope = awkward_envelope(&[]);
        let (ed_pk, mldsa_pk) = crate::federation::tier_ingest::test_support::hybrid_pubkeys(&kid);
        // v30.12.0 (#634) — truncate to MICROSECONDS. Postgres `TIMESTAMPTZ` is
        // microsecond precision and `Utc::now()` is nanosecond, so a
        // nanosecond-bearing fixture fails the whole-record hash comparison
        // below for a reason that has nothing to do with the envelope. Same
        // fixture trap `register_hybrid_key` documents.
        let now = {
            use chrono::Timelike as _;
            let t = chrono::Utc::now();
            t.with_nanosecond(t.nanosecond() / 1_000 * 1_000)
                .unwrap_or(t)
        };
        let key = crate::federation::KeyRecord {
            key_id: kid.clone(),
            pubkey_ed25519_base64: ed_pk,
            pubkey_ml_dsa_65_base64: mldsa_pk,
            algorithm: crate::federation::types::algorithm::HYBRID.into(),
            identity_type: crate::federation::types::identity_type::AGENT.into(),
            identity_ref: format!("primitive-644-{suffix}"),
            valid_from: now,
            valid_until: None,
            registration_envelope: envelope.clone(),
            original_content_hash: "deadbeef".into(),
            scrub_signature_classical: "c2lnbmF0dXJl".into(),
            scrub_signature_pqc: None,
            scrub_key_id: kid.clone(),
            scrub_timestamp: now,
            pqc_completed_at: None,
            persist_row_hash: String::new(),
            capability_roles: Vec::new(),
            attestation_evidence: None,
            consent_role: None,
            additional_scrubs: Vec::new(),
        };
        dir.put_public_key(crate::federation::SignedKeyRecord {
            record: key.clone(),
        })
        .await
        .expect("put_public_key admits the awkward envelope");
        let got = dir
            .lookup_public_key(&kid)
            .await
            .expect("lookup_public_key")
            .expect("the key we just wrote is there");
        assert_envelope_bytes_eq(
            "federation_keys.registration_envelope",
            &envelope,
            &got.registration_envelope,
        );
        // The wire content hash is the property that actually broke: a peer
        // fetches by exactly this value. `put_public_key` legitimately fills
        // `persist_row_hash` (empty on submission), so the comparison pins that
        // one field to what the backend assigned and leaves the ENVELOPE as the
        // only remaining variable. Before V122 this assertion failed on
        // postgres: bf61b57c… on the way in, a6b819b3… on the way out.
        let mut expected = key.clone();
        expected.persist_row_hash = got.persist_row_hash.clone();
        // v31.0.0 (#647) — the ingest chokepoint canonicalizes, so the
        // submitted-side record must be canonicalized too before its wire
        // content hash is comparable. This is NOT weakening the assertion: it
        // is the whole claim of #647, that the hash is now a function of the
        // record's LOGICAL content and not of the producer's serializer.
        crate::federation::canonical_at_rest::canonicalize_in_place(
            &mut expected.registration_envelope,
        )
        .expect("the fixture envelope canonicalizes");
        assert_eq!(
            crate::federation::wire_index::content_hash_of(&expected)
                .expect("hash the submitted key record"),
            crate::federation::wire_index::content_hash_of(&got).expect("hash the reloaded record"),
            "the KeyRecord's wire content hash did not survive storage — with \
             persist_row_hash pinned, the envelope is the only thing that can have moved it"
        );

        // ── 2. federation_attestations.attestation_envelope ─────────
        // Signed with the same deterministic hybrid identity the federation-tier
        // ingest gate re-derives, so this goes through the REAL admission path
        // rather than a local-tier shortcut.
        let node = format!("node-644-{suffix}");
        crate::federation::tier_ingest::test_support::register_hybrid_key(dir, &node).await;
        // A mechanism-descriptive, version-segmented dimension — the admission
        // vocabulary rejects anything without `:v<N>`. Fixed (not suffixed):
        // isolation on a shared postgres database comes from the UUID
        // attestation_id and the suffixed attester key, not from the dimension.
        let att_envelope = awkward_envelope(&[(
            "dimension",
            serde_json::Value::String("envelope_bytes:round_trip:v1".to_owned()),
        )]);
        let (och, ed_sig, pqc_sig) =
            crate::federation::tier_ingest::test_support::sign_envelope(&node, &att_envelope);
        let att_id = uuid::Uuid::new_v4().to_string();
        let attestation = crate::federation::Attestation {
            attestation_id: att_id.clone(),
            attesting_key_id: node.clone(),
            attested_key_id: node.clone(),
            attestation_type: attestation_type::SCORES.to_owned(),
            weight: None,
            asserted_at: now,
            expires_at: None,
            attestation_envelope: att_envelope.clone(),
            original_content_hash: och,
            scrub_signature_classical: ed_sig,
            scrub_signature_pqc: pqc_sig,
            scrub_key_id: node.clone(),
            scrub_timestamp: now,
            pqc_completed_at: None,
            persist_row_hash: String::new(),
            subject_key_ids: vec![node.clone()],
            withdraws_admission_rule: None,
            cohort_scope: "federation".to_owned(),
            tier: attestation_tier::FEDERATION.to_owned(),
            promoted_at: None,
            additional_scrubs: Vec::new(),
        };
        dir.put_attestation(crate::federation::SignedAttestation { attestation })
            .await
            .expect("put_attestation admits the awkward envelope");
        let reloaded_att = dir
            .get_attestation(&att_id)
            .await
            .expect("get_attestation")
            .expect("the attestation we just wrote is there");
        assert_envelope_bytes_eq(
            "federation_attestations.attestation_envelope",
            &att_envelope,
            &reloaded_att.attestation_envelope,
        );
        // v31.0.0 (#647) — hand-verifiability. `original_content_hash` was
        // computed by the SIGNER, before the row ever reached storage; the
        // column must sha256sum to it.
        assert_column_sha256_is_original_content_hash(
            "federation_attestations.attestation_envelope",
            &reloaded_att.attestation_envelope,
            &reloaded_att.original_content_hash,
        );

        // ── 3. federation_revocations.revocation_envelope ───────────
        // A SELF-revocation (revoking == revoked), which
        // `check_revocation_authority` admits without a slash conferral. The
        // column under test is the same one either way, and the alternative —
        // standing up a node identity and a delegation chain — would test the
        // conferral plane, not the storage container.
        let rev_kid = format!("k-644-rev-{suffix}");
        let (rev_ed_pk, rev_mldsa_pk) =
            crate::federation::tier_ingest::test_support::hybrid_pubkeys(&rev_kid);
        dir.put_public_key(crate::federation::SignedKeyRecord {
            record: crate::federation::KeyRecord {
                key_id: rev_kid.clone(),
                pubkey_ed25519_base64: rev_ed_pk,
                pubkey_ml_dsa_65_base64: rev_mldsa_pk,
                algorithm: crate::federation::types::algorithm::HYBRID.into(),
                identity_type: crate::federation::types::identity_type::AGENT.into(),
                identity_ref: format!("primitive-644-rev-{suffix}"),
                valid_from: now,
                valid_until: None,
                registration_envelope: serde_json::json!({ "key_id": rev_kid }),
                original_content_hash: "deadbeef".into(),
                scrub_signature_classical: "c2lnbmF0dXJl".into(),
                scrub_signature_pqc: None,
                scrub_key_id: rev_kid.clone(),
                scrub_timestamp: now,
                pqc_completed_at: None,
                persist_row_hash: String::new(),
                capability_roles: Vec::new(),
                attestation_evidence: None,
                consent_role: None,
                additional_scrubs: Vec::new(),
            },
        })
        .await
        .expect("register the self-revoking key");

        let rev_envelope =
            awkward_envelope(&[("revoked_key_id", serde_json::Value::String(rev_kid.clone()))]);
        let (rev_och, rev_ed, rev_pqc) =
            crate::federation::tier_ingest::test_support::sign_envelope(&rev_kid, &rev_envelope);
        let rev_id = uuid::Uuid::new_v4().to_string();
        let revocation = crate::federation::Revocation {
            revocation_id: rev_id.clone(),
            revoked_key_id: rev_kid.clone(),
            revoking_key_id: rev_kid.clone(),
            reason: Some("644 byte-exactness witness".to_owned()),
            revoked_at: now,
            effective_at: now,
            revocation_envelope: rev_envelope.clone(),
            original_content_hash: rev_och,
            scrub_signature_classical: rev_ed,
            scrub_signature_pqc: rev_pqc,
            scrub_key_id: rev_kid.clone(),
            scrub_timestamp: now,
            pqc_completed_at: None,
            observed_region: crate::federation::verify_coord::region::US.to_owned(),
            revoked_after: None,
            persist_row_hash: String::new(),
        };
        dir.put_revocation(crate::federation::SignedRevocation { revocation })
            .await
            .expect("put_revocation admits the awkward envelope");
        let revs = dir
            .revocations_for(&rev_kid)
            .await
            .expect("revocations_for");
        let reloaded_rev = revs
            .iter()
            .find(|r| r.revoked_key_id == rev_kid)
            .expect("the revocation we just wrote is there");
        assert_envelope_bytes_eq(
            "federation_revocations.revocation_envelope",
            &rev_envelope,
            &reloaded_rev.revocation_envelope,
        );
        assert_column_sha256_is_original_content_hash(
            "federation_revocations.revocation_envelope",
            &reloaded_rev.revocation_envelope,
            &reloaded_rev.original_content_hash,
        );

        // ── 4. the PRETTY-PRINTED submission ────────────────────────
        // The producer-facing half of #647: an envelope submitted with
        // whitespace, unsorted keys and exponent tokens is stored canonical,
        // and its `original_content_hash` — computed by the signer over the
        // canonical form, before storage — still verifies against the column.
        let pretty_kid = format!("k-647-pretty-{suffix}");
        crate::federation::tier_ingest::test_support::register_hybrid_key(dir, &pretty_kid).await;
        let pretty_src = "{\n  \"zz\": \"last\",\n  \"exp\": 1E+2,\n  \
                          \"dimension\": \"envelope_bytes:pretty:v1\",\n  \
                          \"aa\": \"first\"\n}";
        let pretty_envelope: serde_json::Value =
            serde_json::from_str(pretty_src).expect("the pretty fixture is legal JSON");
        let (p_och, p_ed, p_pqc) = crate::federation::tier_ingest::test_support::sign_envelope(
            &pretty_kid,
            &pretty_envelope,
        );
        let pretty_id = uuid::Uuid::new_v4().to_string();
        dir.put_attestation(crate::federation::SignedAttestation {
            attestation: crate::federation::Attestation {
                attestation_id: pretty_id.clone(),
                attesting_key_id: pretty_kid.clone(),
                attested_key_id: pretty_kid.clone(),
                attestation_type: attestation_type::SCORES.to_owned(),
                weight: None,
                asserted_at: now,
                expires_at: None,
                attestation_envelope: pretty_envelope.clone(),
                original_content_hash: p_och.clone(),
                scrub_signature_classical: p_ed,
                scrub_signature_pqc: p_pqc,
                scrub_key_id: pretty_kid.clone(),
                scrub_timestamp: now,
                pqc_completed_at: None,
                persist_row_hash: String::new(),
                subject_key_ids: vec![pretty_kid.clone()],
                withdraws_admission_rule: None,
                cohort_scope: "federation".to_owned(),
                tier: attestation_tier::FEDERATION.to_owned(),
                promoted_at: None,
                additional_scrubs: Vec::new(),
            },
        })
        .await
        .expect("a pretty-printed envelope is admitted (and its signature still verifies)");
        let reloaded_pretty = dir
            .get_attestation(&pretty_id)
            .await
            .expect("get_attestation")
            .expect("the pretty attestation is there");
        assert_eq!(
            serde_json::to_string(&reloaded_pretty.attestation_envelope).expect("serializes"),
            r#"{"aa":"first","dimension":"envelope_bytes:pretty:v1","exp":100,"zz":"last"}"#,
            "a pretty-printed submission was not stored canonical"
        );
        assert_column_sha256_is_original_content_hash(
            "federation_attestations.attestation_envelope (pretty submission)",
            &reloaded_pretty.attestation_envelope,
            &p_och,
        );
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// The fixture is only useful if it actually carries exponent-form numbers
    /// through `serde_json`'s `arbitrary_precision` `Value` — if a future
    /// feature change made `Value` normalize them, every witness in this module
    /// would go green against a JSONB column and prove nothing.
    ///
    /// This is the "a check that cannot fail is a report" guard: it asserts the
    /// PRECONDITION that makes the round-trip witnesses meaningful.
    #[test]
    fn the_fixture_preserves_producer_number_tokens() {
        let bytes = serde_json::to_string(&awkward_envelope(&[])).expect("serializes");
        assert!(
            bytes.contains("1e+2") || bytes.contains("1E+2"),
            "the fixture's exponent token was normalized by serde_json itself \
             ({bytes}) — the byte-exactness witnesses would then pass against a \
             JSONB column and be worthless"
        );
        assert!(
            bytes.contains("1.5e-3"),
            "the fixture's negative exponent was normalized by serde_json itself: {bytes}"
        );
        assert!(
            bytes.contains("12345678901234567890123"),
            "the fixture's wide integer lost precision inside serde_json: {bytes}"
        );
    }

    /// v31.0.0 (#644) — **does the JCS canonicalization the SIGNATURE is taken
    /// over absorb what JSONB does to numbers?**
    ///
    /// The audit that raised #644 believed it did, but recorded the belief as
    /// unproven. It matters: if JCS normalizes `1e+2` to `100` the same way
    /// `jsonb` does, then a JSONB round-trip damaged the CONTENT HASH only
    /// (bad, and the reason for V122) and left signature verification intact.
    /// If JCS passes the producer token through, the same round-trip would also
    /// have invalidated stored SIGNATURES — a strictly worse failure.
    ///
    /// This test records the measured answer rather than the belief.
    #[test]
    fn jcs_number_normalization_versus_jsonb() {
        let env = awkward_envelope(&[]);
        let canonical = crate::verify::canonical::ceg_produce_canonicalize(&env)
            .expect("the produce canonicalizer accepts the fixture");
        let text = String::from_utf8(canonical).expect("JCS output is UTF-8");
        // Whatever the answer is, it must be STABLE — the same Value must
        // canonicalize to the same bytes every time, or nothing above holds.
        let again = crate::verify::canonical::ceg_produce_canonicalize(&env).expect("again");
        assert_eq!(
            text.as_bytes(),
            again.as_slice(),
            "the produce canonicalizer is not deterministic"
        );
        // Record the measurement in the failure text of an assertion that
        // states the property we depend on: JCS must NOT be sensitive to the
        // exponent token in a way that differs from a jsonb round-trip of the
        // same value, because if it were, pre-V122 rows would have lost their
        // signatures too and V122's "numbers are unrecoverable" note would be
        // understating the damage.
        let jsonb_shaped: serde_json::Value =
            serde_json::from_str(r#"{"exp":100,"neg":0.0015}"#).expect("legal");
        let mut normalized = env.clone();
        {
            let m = normalized.as_object_mut().expect("object");
            m.insert("exp".into(), jsonb_shaped["exp"].clone());
            m.insert("neg".into(), jsonb_shaped["neg"].clone());
        }
        let normalized_canonical = crate::verify::canonical::ceg_produce_canonicalize(&normalized)
            .expect("canonicalize the jsonb-shaped twin");
        assert_eq!(
            text.as_bytes(),
            normalized_canonical.as_slice(),
            "JCS distinguishes the producer's exponent token from jsonb's rendering of \
             the same number. That means a pre-V122 JSONB round-trip invalidated stored \
             SIGNATURES, not just content hashes — V122's recovery note must say so, and \
             affected rows need a re-publish from the producer, not just a re-index.\n\
             producer-token JCS: {text}\n\
             jsonb-shaped  JCS: {}",
            String::from_utf8_lossy(&normalized_canonical)
        );
    }
}
