//! v62.0.0 (JSON-cut slice F, F0-cp5) — **the one directory-backed composite
//! verifier.** Every door that verifies a detached signature over bytes it
//! did not frame as a `COSE_Sign1` (an HTTP request, an Edge batch, a
//! CIRISNode delivery attestation, a capsule caller) asks this, and nothing
//! else: ONE composite (ML-DSA-65-Ed25519) signature, under the signer's
//! LIVE edition-2 key, named by its identity-ref.
//!
//! RULINGS ("Composite signatures only. There are no standalone component
//! signers.") — a lone Ed25519 or ML-DSA-65 half, or the earlier two-field
//! form, is refused by name ([`VERIFY_COMPONENT_SIGNATURE`]) before any key is
//! read. A signer named by anything but an identity-ref names no edition-2
//! key ([`VERIFY_NOT_IDENTITY_REF`]): it is never looked up in the earlier
//! key read model.
//!
//! Factored from `server::secrets::authenticate_request`, which now calls it.

use ciris_crypto::composite::{MLDSA65_SIG_LEN, SIGNATURE_LEN};
use ciris_verify_core::edition2::keys::KeyRecord;

use super::ingest::{held_keys_for_kid, kid_of_identity_ref};
use super::liveness::Liveness;
use crate::federation::FederationDirectory;

/// The signer is not named by an edition-2 identity-ref.
pub const VERIFY_NOT_IDENTITY_REF: &str = "verify_not_identity_ref";
/// No valid `key:record` of the signer is held here.
pub const VERIFY_UNKNOWN_KEY: &str = "verify_unknown_key";
/// The signer's key is revoked. Final.
pub const VERIFY_SIGNER_REVOKED: &str = "verify_signer_revoked";
/// Valid records are held, but none covers the instant. Retryable.
pub const VERIFY_SIGNER_NOT_COVERED: &str = "verify_signer_not_covered";
/// The signer's record waits on a key this node does not hold. Retryable.
pub const VERIFY_SIGNER_WAITING: &str = "verify_signer_waiting";
/// The composite signature does not verify under the live key.
pub const VERIFY_COMPOSITE_INVALID: &str = "verify_composite_invalid";
/// A lone component half (or the earlier two-field form), not the composite.
pub const VERIFY_COMPONENT_SIGNATURE: &str = "verify_component_signature";
/// The directory read failed. Retryable.
pub const VERIFY_DIRECTORY: &str = "verify_directory";

/// The signer a composite signature verified under.
#[derive(Clone, Debug)]
pub struct LiveSigner {
    /// The identity-ref the caller named, verbatim.
    pub identity_ref: String,
    /// The live record the signature verified under.
    pub record: Box<KeyRecord>,
}

/// A refusal of [`verify_composite_via_directory`]. Each message leads with
/// its token ([`Self::token`]).
#[derive(Debug, thiserror::Error)]
pub enum CompositeVerifyError {
    /// [`VERIFY_NOT_IDENTITY_REF`].
    #[error(
        "verify_not_identity_ref: {0:?} is not an edition-2 identity-ref \
         (urn:ietf:params:oauth:ckt:sha-256:…); v62.0.0 verifies only edition-2 keys"
    )]
    NotIdentityRef(String),
    /// [`VERIFY_UNKNOWN_KEY`].
    #[error("verify_unknown_key: this node holds no valid key:record for {0}")]
    UnknownKey(String),
    /// [`VERIFY_SIGNER_REVOKED`].
    #[error("verify_signer_revoked: {0} is revoked")]
    Revoked(String),
    /// [`VERIFY_SIGNER_NOT_COVERED`].
    #[error("verify_signer_not_covered: no record of {identity_ref} covers {at_ms} ms")]
    NotCovered {
        /// The signer.
        identity_ref: String,
        /// The instant asked about (POSIX ms).
        at_ms: u64,
    },
    /// [`VERIFY_SIGNER_WAITING`].
    #[error(
        "verify_signer_waiting: {identity_ref}'s record waits on {missing} key(s) \
         this node does not hold"
    )]
    Waiting {
        /// The signer.
        identity_ref: String,
        /// How many keys the record waits on.
        missing: usize,
    },
    /// [`VERIFY_COMPONENT_SIGNATURE`].
    #[error(
        "verify_component_signature: a {got}-byte signature is {what}, not the one \
         composite (ML-DSA-65-Ed25519, 3373 bytes); the composite rule \
         admits no standalone component signer"
    )]
    ComponentSignature {
        /// The length handed in.
        got: usize,
        /// Which half it is the length of.
        what: &'static str,
    },
    /// [`VERIFY_COMPOSITE_INVALID`].
    #[error("verify_composite_invalid: {0}")]
    Invalid(String),
    /// [`VERIFY_DIRECTORY`].
    #[error("verify_directory: {0}")]
    Directory(#[from] crate::federation::Error),
}

impl CompositeVerifyError {
    /// The stable token this refusal leads with.
    #[must_use]
    pub fn token(&self) -> &'static str {
        match self {
            Self::NotIdentityRef(_) => VERIFY_NOT_IDENTITY_REF,
            Self::UnknownKey(_) => VERIFY_UNKNOWN_KEY,
            Self::Revoked(_) => VERIFY_SIGNER_REVOKED,
            Self::NotCovered { .. } => VERIFY_SIGNER_NOT_COVERED,
            Self::Waiting { .. } => VERIFY_SIGNER_WAITING,
            Self::ComponentSignature { .. } => VERIFY_COMPONENT_SIGNATURE,
            Self::Invalid(_) => VERIFY_COMPOSITE_INVALID,
            Self::Directory(_) => VERIFY_DIRECTORY,
        }
    }

    /// May the same call succeed later, with nothing about it changed? True
    /// for a record waiting on a key, a record not yet covering the instant,
    /// and a failed directory read; every other refusal is final.
    #[must_use]
    pub fn is_retryable(&self) -> bool {
        matches!(
            self,
            Self::Waiting { .. } | Self::NotCovered { .. } | Self::Directory(_)
        )
    }
}

/// **The composite's shape, the one check every composite signature meets
/// first** — a directory-verified row signature
/// ([`verify_composite_via_directory`]) and a CC 6.1 substrate object's
/// signature over its own binary preimage (`verify::sig19::Sig19`, CC 6.1.3)
/// alike: one composite primitive, two preimage framings. A lone Ed25519
/// (64 bytes) or ML-DSA-65 (3309 bytes) half is refused by name
/// ([`VERIFY_COMPONENT_SIGNATURE`]); any other length but
/// [`SIGNATURE_LEN`] (3373) is [`VERIFY_COMPOSITE_INVALID`]. CC 6.1.3: the only
/// lone Ed25519 signature in the text is the per-chunk media trailer under a
/// StreamKeyBinding's ephemeral key (CC 5.3.3.5), which never comes here.
///
/// # Errors
/// [`CompositeVerifyError::ComponentSignature`] / [`CompositeVerifyError::Invalid`].
#[allow(clippy::result_large_err)] // X2 4d: the error type is the owner's (box it there)
pub fn require_composite_length(got: usize) -> Result<(), CompositeVerifyError> {
    match got {
        SIGNATURE_LEN => Ok(()),
        64 => Err(CompositeVerifyError::ComponentSignature {
            got: 64,
            what: "a lone Ed25519 half",
        }),
        MLDSA65_SIG_LEN => Err(CompositeVerifyError::ComponentSignature {
            got: MLDSA65_SIG_LEN,
            what: "a lone ML-DSA-65 half",
        }),
        other => Err(CompositeVerifyError::Invalid(format!(
            "a {other}-byte signature; the composite is {SIGNATURE_LEN} bytes"
        ))),
    }
}

/// **Verify ONE composite signature over `message` under the LIVE edition-2
/// key of `identity_ref` at `at_ms` (POSIX ms).**
///
/// In order, each refused by name:
/// 1. a signature of a component half's length (or of any length but the
///    composite's): [`VERIFY_COMPONENT_SIGNATURE`] / [`VERIFY_COMPOSITE_INVALID`],
///    before any key is read;
/// 2. a signer that is not an identity-ref: [`VERIFY_NOT_IDENTITY_REF`];
/// 3. the signer's held key plane ([`held_keys_for_kid`]) read at `at_ms`:
///    unknown, revoked, not covered, waiting;
/// 4. the composite verify under the live record's key.
///
/// # Errors
/// [`CompositeVerifyError`].
pub async fn verify_composite_via_directory<F>(
    dir: &F,
    message: &[u8],
    identity_ref: &str,
    composite_sig: &[u8],
    at_ms: u64,
) -> Result<LiveSigner, CompositeVerifyError>
where
    F: FederationDirectory + ?Sized,
{
    require_composite_length(composite_sig.len())?;
    let Some(kid) = kid_of_identity_ref(identity_ref) else {
        return Err(CompositeVerifyError::NotIdentityRef(
            identity_ref.to_owned(),
        ));
    };
    let held = held_keys_for_kid(dir, &kid).await?;
    let record = match held.liveness(&kid, at_ms) {
        Liveness::Live(record) => record,
        Liveness::NotHeld | Liveness::Invalid => {
            return Err(CompositeVerifyError::UnknownKey(identity_ref.to_owned()));
        }
        Liveness::Revoked => {
            return Err(CompositeVerifyError::Revoked(identity_ref.to_owned()));
        }
        Liveness::NotCovered => {
            return Err(CompositeVerifyError::NotCovered {
                identity_ref: identity_ref.to_owned(),
                at_ms,
            });
        }
        Liveness::Waiting(keys) => {
            return Err(CompositeVerifyError::Waiting {
                identity_ref: identity_ref.to_owned(),
                missing: keys.len(),
            });
        }
    };
    record.key.verify(message, composite_sig).map_err(|e| {
        CompositeVerifyError::Invalid(format!(
            "the composite signature does not verify under {identity_ref}'s live key: {e}"
        ))
    })?;
    Ok(LiveSigner {
        identity_ref: identity_ref.to_owned(),
        record,
    })
}

/// The instant `now` as POSIX ms, the `at_ms` every live caller passes.
#[must_use]
pub fn now_ms() -> u64 {
    u64::try_from(crate::host::clock::now().timestamp_millis()).unwrap_or(0)
}
