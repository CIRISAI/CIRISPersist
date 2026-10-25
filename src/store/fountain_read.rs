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
