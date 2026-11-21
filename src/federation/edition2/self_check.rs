//! v62.0.0 (KR-fix14) — **the one signature self-check of an assembled
//! statement**, for a ceremony tool, before it submits anything.
//!
//! A statement drafted by the Engine and signed elsewhere (a hardware key,
//! an offline step) can come back signed by the wrong key, or with a
//! signature cut short. [`verify_statement_signature`] says so by name, from
//! the bytes alone: no store, no clock (the instant is the statement's own).
//!
//! It is the SHARED core of the per-row self-checks, which add their own
//! shape rules on top and nothing of their own for the signature:
//! - `self_at_login::verify_owner_binding_statement` (an owner binding),
//! - `trust_root::check_root_acceptance_statement` (a root's acceptance).
//!
//! It carries no per-family shape rule: those are the door's. It can be run
//! on ANY assembled row statement: a grant from the root, a holder's voice, a
//! membership reply, a re-bind.

use ciris_crypto::composite::CompositePublicKey;
use ciris_verify_core::edition2::{
    thumbprint, verify_row_statement, Digest32, KeyDirectory, KeyLookup, KeyOf, Verdict,
};

use super::liveness::statement_parts;

/// What the caller holds of the signer.
#[derive(Clone, Copy, Debug)]
pub enum SignerKey<'a> {
    /// The signer's bare composite public key. The statement's header kid
    /// must be this key's thumbprint. Nothing is known of the key's window.
    PublicKey(&'a CompositePublicKey),
    /// The signer's own `key:record` statement. The statement is judged as
    /// the door judges it against that one record (its window, its
    /// key-of-issuer rule), by `door::admit_row`.
    KeyRecord(&'a [u8]),
}

/// Why an assembled statement's signature is not good.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum StatementFault {
    /// The bytes are not a row statement.
    NotAStatement,
    /// The kid in the protected header is not the supplied key's: the draft
    /// was made for another key than the one that is meant to sign it.
    SignerKidMismatch,
    /// The signature does not verify under the supplied key (Verify's label,
    /// or the door's refusal for a key record): a wrong key signed, or the
    /// signature was cut short.
    SignatureInvalid(String),
}

impl StatementFault {
    /// The fault's stable name.
    #[must_use]
    pub fn token(&self) -> &'static str {
        match self {
            Self::NotAStatement => "statement_not_a_row_statement",
            Self::SignerKidMismatch => "statement_signer_kid_mismatch",
            Self::SignatureInvalid(_) => "statement_signature_invalid",
        }
    }
}

impl std::fmt::Display for StatementFault {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::SignatureInvalid(d) => write!(f, "{}: {d}", self.token()),
            _ => f.write_str(self.token()),
        }
    }
}

/// One key, as Verify's key directory: the supplied key answers for its own
/// kid, and nothing else is held.
struct OneKey {
    kid: Digest32,
    key: CompositePublicKey,
}

impl KeyDirectory for OneKey {
    fn lookup(&self, kid: &Digest32, _asserted_at: u64) -> KeyLookup {
        if *kid == self.kid {
            KeyLookup::Held(Box::new(self.key.clone()))
        } else {
            KeyLookup::NotHeld
        }
    }

    fn key_of(&self, kid: &Digest32, _iss: &Digest32) -> KeyOf {
        if *kid == self.kid {
            KeyOf::Yes
        } else {
            KeyOf::No
        }
    }
}

/// **Does the assembled `statement` verify under the signer's key?** Pure.
///
/// # Errors
/// The first [`StatementFault`].
pub fn verify_statement_signature(
    statement: &[u8],
    signer: SignerKey<'_>,
) -> Result<(), StatementFault> {
    let Some((protected, _)) = statement_parts(statement) else {
        return Err(StatementFault::NotAStatement);
    };
    match signer {
        SignerKey::PublicKey(key) => {
            let kid = thumbprint(key);
            let header_kid = protected
                .get_int(4)
                .and_then(ciris_verify_core::cde::Value::as_bytes)
                .and_then(|b| <[u8; 32]>::try_from(b).ok());
            if header_kid != Some(kid) {
                return Err(StatementFault::SignerKidMismatch);
            }
            match verify_row_statement(
                statement,
                &OneKey {
                    kid,
                    key: key.clone(),
                },
            ) {
                Verdict::Valid(_) => Ok(()),
                Verdict::Invalid(i) => Err(StatementFault::SignatureInvalid(
                    super::door::invalid_label(&i),
                )),
                Verdict::Waiting { .. } => Err(StatementFault::SignatureInvalid(
                    "it waits on a key other than the signer's".into(),
                )),
            }
        }
        SignerKey::KeyRecord(record) => {
            let mut keys = super::liveness::HeldKeys::new();
            keys.insert_record(record.to_vec());
            super::door::admit_row(
                statement,
                &keys,
                None,
                ciris_verify_core::edition2::family::SelectContext::default(),
            )
            .map(|_| ())
            .map_err(|e| StatementFault::SignatureInvalid(e.to_string()))
        }
    }
}
