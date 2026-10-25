//! v8.0.0 (CIRISPersist#227) — the fountain read contract every backend's
//! `get_fountain_content` shares. (v60.0.0, CIRISPersist#1002: moved here from
//! the retired memory backend's file, where it had lived since #227.)

use super::Error;

/// v8.0.0 (CIRISPersist#227) — shared read assembler: re-verify each
/// present symbol's SHA-256 against the signed `symbol_hashes`, then
/// classify present-count vs the manifest thresholds into the typed
/// [`FountainContent`](crate::fountain::FountainContent). Used by every
/// backend's `get_fountain_content` so the read contract (authenticated
/// partials, Full/Partial/EnvelopeOnly boundary) is byte-identical.
pub(crate) fn assemble_fountain_content(
    manifest: crate::fountain::FountainManifestV1,
    symbols: Vec<crate::fountain::FountainSymbolV1>,
) -> Result<crate::fountain::FountainContent, Error> {
    use crate::fountain::{FountainContent, FountainReadClass};
    // Per-symbol hash re-auth on read (authenticated partials).
    for sym in &symbols {
        let idx = sym.symbol_id as usize;
        let Some(expected) = manifest.symbol_hashes.get(idx) else {
            return Err(Error::FountainIntegrity(format!(
                "symbol_id {} has no signed hash (symbol_hashes len {})",
                sym.symbol_id,
                manifest.symbol_hashes.len()
            )));
        };
        let got = crate::fountain::symbol_sha256_hex(&sym.symbol_bytes);
        if &got != expected {
            return Err(Error::FountainIntegrity(format!(
                "stored symbol {} sha256 {} != signed hash {}",
                sym.symbol_id, got, expected
            )));
        }
    }
    let present = symbols.len() as u32;
    Ok(
        match FountainContent::classify(present, manifest.n_source, manifest.min_viable_symbols) {
            FountainReadClass::Full => FountainContent::Full { manifest, symbols },
            FountainReadClass::Partial => FountainContent::Partial {
                manifest,
                symbols,
                present,
            },
            FountainReadClass::EnvelopeOnly => FountainContent::EnvelopeOnly { manifest },
        },
    )
}

#[cfg(test)]
mod tests {
    use crate::fountain::{FountainContent, FountainManifestV1, FountainSymbolV1};

    fn symbol(id: u32, bytes: &[u8]) -> FountainSymbolV1 {
        FountainSymbolV1 {
            content_id: "c".into(),
            symbol_id: id,
            retention_priority: 0,
            symbol_bytes: bytes.to_vec(),
        }
    }

    /// **I1323** — the read re-authenticates every present symbol against
    /// the signed hash at its index: a symbol whose bytes changed is
    /// `FountainIntegrity`, never served; the signed bytes are `Full`.
    #[test]
    fn i1323_a_symbol_that_is_not_its_signed_hash_is_refused() {
        let manifest = FountainManifestV1 {
            content_id: "c".into(),
            corpus_kind: "blob".into(),
            manifest_version: 1,
            n_source: 1,
            k_repair: 0,
            symbol_size: 4,
            original_content_length: 4,
            min_viable_symbols: 1,
            symbol_hashes: vec![crate::fountain::symbol_sha256_hex(b"abcd")],
            envelope: serde_json::json!({}),
            signature: String::new(),
            signature_ml_dsa_65: String::new(),
            pqc_key_id: String::new(),
        };
        assert!(matches!(
            super::assemble_fountain_content(manifest.clone(), vec![symbol(0, b"abcd")]),
            Ok(FountainContent::Full { .. })
        ));
        let err = super::assemble_fountain_content(manifest.clone(), vec![symbol(0, b"abce")])
            .expect_err("I1323: a tampered symbol is refused");
        assert!(matches!(err, super::Error::FountainIntegrity(_)), "{err:?}");
        let err = super::assemble_fountain_content(manifest, vec![symbol(1, b"abcd")])
            .expect_err("I1323: a symbol with no signed hash is refused");
        assert!(matches!(err, super::Error::FountainIntegrity(_)), "{err:?}");
    }
}
