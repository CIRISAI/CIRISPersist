//! v60.0.0 (CIRISPersist#1114; CC 2.6.1.7, rc10 `99bf187`) — **I1311:
//! `subject_key_id_malformed` is its own `federation_malformed_row` reason.**
//!
//! - **I1311 (`subject_key_id_malformed`)** — a `subject_key_ids` element that
//!   is neither a canonical lowercase key_id nor the tagged canonical form is
//!   refused with the reason by the validator the attestation door runs (it
//!   was `federation_invalid_argument`).
//!
//! v62.0.0 (slice E6) — **I1309** (`content_hash_mismatch`: an
//! `original_content_hash` that is not the SHA-256 of JCS(envelope)) and
//! **I1310** (`envelope_row_member_unknown`: the signed `row` mirror's closed
//! seven) are deleted: both are checks of the earlier-form signed object. An
//! edition-2 row's proof is its carried statement; its content hash and its
//! `row` mirror are written by the projection (`ingest::attestation_of`), never
//! offered by a peer. I1311's door leg is deleted with them: an edition-2
//! subject is an identity-ref by encoding (`IdentityRefs`), so a malformed
//! text subject cannot be offered at the statement door; the validator stays.
//!
//! The tokens are rc10 tokens (CC 2.6.1.7 at `99bf187`, after the `v1.0-rc9`
//! tag persist vendors), pinned as "named by no CC text at the pin" in
//! `namespace::cc_manifests` I1308 until the next CC re-pin.

#[cfg(test)]
mod tests {
    use crate::federation::{malformed_row, Error};

    fn reason(e: Error, what: &str) -> &'static str {
        assert_eq!(e.kind(), "federation_malformed_row", "{what}: {e}");
        match e {
            Error::MalformedRow { reason, .. } => reason,
            other => panic!("{what}: expected MalformedRow, got {other:?}"),
        }
    }

    /// **I1311** — `subject_key_id_malformed`, from the validator the
    /// attestation door runs; a canonical subject passes it.
    #[test]
    fn i1311_subject_key_id_malformed() {
        for bad_id in [
            "Actor-A".to_owned(),
            "actor a".to_owned(),
            format!("canonical:sha256:{}", "A".repeat(64)),
        ] {
            let e = crate::federation::validate_subject_key_ids(std::slice::from_ref(&bad_id))
                .unwrap_err();
            assert_eq!(
                reason(e, "I1311 validator"),
                malformed_row::SUBJECT_KEY_ID_MALFORMED,
                "I1311 {bad_id:?}"
            );
        }
        crate::federation::validate_subject_key_ids(&[format!(
            "canonical:sha256:{}",
            "9f".repeat(32)
        )])
        .expect("I1311: a canonical subject passes");

        // v62.0.0 (X2 pass 2) — an edition-2 identity-ref is a canonical
        // subject WITH its base64url segment's case; the prefix is lowercase
        // and the segment one spelling per key.
        let iref = crate::federation::edition2::fixture_switch::kid("i1311-subject");
        assert!(
            iref.bytes().any(|b| b.is_ascii_uppercase()),
            "I1311 fixture: the segment carries uppercase, so the clause is exercised: {iref}"
        );
        crate::federation::validate_subject_key_ids(std::slice::from_ref(&iref))
            .expect("I1311: an identity-ref subject passes");
        for bad_id in [
            iref.replacen("urn:ietf", "URN:IETF", 1),
            format!("{iref}A"),
            format!("{}!", &iref[..iref.len() - 1]),
        ] {
            let e = crate::federation::validate_subject_key_ids(std::slice::from_ref(&bad_id))
                .unwrap_err();
            assert_eq!(
                reason(e, "I1311 identity-ref"),
                malformed_row::SUBJECT_KEY_ID_MALFORMED,
                "I1311 {bad_id:?}"
            );
        }
    }
}
