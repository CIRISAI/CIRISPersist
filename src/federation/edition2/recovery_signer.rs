//! v62.0.0 (wave O1; CC 4.2.6, the RULINGS entry) — **a recovery key is
//! refused as a signing key, by its public key material.**
//!
//! A holder's recovery key signs one thing: a genesis bundle's recovery
//! voice, which the bundle reader (`edition2::genesis`) judges. At the row
//! door ([`super::ingest::put_statement`]) a statement whose signing key is a
//! recovery key committed or spent by any genesis bundle held is refused
//! finally ([`crate::federation::malformed_row::RECOVERY_KEY_IS_NOT_A_SIGNER`]),
//! before the key-of-issuer check and the liveness lookups, and nothing is
//! held. Without this, the key's record (filed under the HOLDER's identity,
//! the recovery bundle names it) left the statement waiting on an unknown
//! signer, a wait that would admit it on a later look.
//!
//! The statement header carries only the signing key's thumbprint. Its
//! public key is read from the key records this node holds that record that
//! thumbprint: the statement itself when it is a `key:record`, the records
//! filed under the key's own identity, and the rows the held bundles name.
//! Each candidate key is matched by its commitment
//! (`recovery_commitment([key])`, Verify's) against every bundle's
//! `lineage_commitments` and `spent_commitments`.
//!
//! **One key per commitment (CC rc20 2.6.1.11 / 4.2.6).** "Each commitment
//! is the CC 3.2 T3 commitment over the holder's one recovery key";
//! `recovery_commitments` is `{ + identity-ref => hash-digest }`, one entry
//! per holder. Verify's reader opens a commitment exactly this way
//! (`recovery_commitment(core::slice::from_ref(rk))`, genesis.rs 1466,
//! 1676, 1747). The single-key match is therefore the reader's own reading,
//! and a commitment over a set of several keys never counts a recovery.
//! The digest is opaque, so a bundle reader cannot see the set's size; the
//! one-key rule is CC's and the reader's, and nothing else opens it.

use std::collections::BTreeSet;

use ciris_crypto::composite::CompositePublicKey;
use ciris_verify_core::cde::Value;
use ciris_verify_core::edition2::keys::{check_key_record, KEY_RECORD_FAMILY};
use ciris_verify_core::edition2::recovery::recovery_commitment;
use ciris_verify_core::edition2::{identity_ref, thumbprint, Digest32};

use super::ingest::statement_kid;
use super::liveness::statement_parts;
use crate::federation::{malformed_row, Error, FederationDirectory};

/// The public key a `key:record` statement records (its payload `key`),
/// whether or not the record keeps the end rule.
fn recorded_key(statement: &[u8]) -> Option<CompositePublicKey> {
    let (protected, payload) = statement_parts(statement)?;
    if protected.get_int(-70002).and_then(Value::as_text) != Some(KEY_RECORD_FAMILY) {
        return None;
    }
    check_key_record(&payload).ok().map(|r| r.key).or_else(|| {
        let k = payload.get_text("key")?.get_int(-1)?.as_bytes()?;
        CompositePublicKey::from_bytes(k).ok()
    })
}

/// **Is `kid` a recovery key** (pure): one of `records` records a key of
/// that thumbprint whose single-key commitment is in `commitments`.
#[must_use]
pub fn is_recovery_key<'a>(
    kid: &Digest32,
    records: impl IntoIterator<Item = &'a [u8]>,
    commitments: &BTreeSet<Digest32>,
) -> bool {
    if commitments.is_empty() {
        return false;
    }
    records.into_iter().filter_map(recorded_key).any(|k| {
        thumbprint(&k) == *kid
            && commitments.contains(&recovery_commitment(std::slice::from_ref(&k)))
    })
}

/// The recovery keys of the genesis lineage in force (CC 4.2.6): every
/// commitment any Valid held bundle names or has spent, and the kids of the
/// recovery keys whose records those bundles name (each record's key hashed
/// to one of them). Read once per held bundle set ([`recovery_keys_in_force`]).
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct RecoveryKeys {
    commitments: BTreeSet<Digest32>,
    kids: BTreeSet<Digest32>,
}

impl RecoveryKeys {
    /// The recovery keys of these placements, with `statements` the rows
    /// their bundles name.
    #[must_use]
    pub fn of(placements: &[super::genesis::GenesisPlacement], statements: &[Vec<u8>]) -> Self {
        let commitments: BTreeSet<Digest32> = placements
            .iter()
            .flat_map(|p| {
                p.lineage_commitments
                    .iter()
                    .chain(p.spent_commitments.iter())
                    .copied()
            })
            .collect();
        let kids = statements
            .iter()
            .filter_map(|st| recorded_key(st))
            .filter(|k| commitments.contains(&recovery_commitment(std::slice::from_ref(k))))
            .map(|k| thumbprint(&k))
            .collect();
        RecoveryKeys { commitments, kids }
    }

    /// No commitment is held (pre-genesis): nothing to refuse.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.commitments.is_empty()
    }

    /// Is `kid` a recovery key: one the held bundles name, or one whose key
    /// one of `records` carries and hashes to a held commitment?
    #[must_use]
    pub fn holds<'a>(&self, kid: &Digest32, records: impl IntoIterator<Item = &'a [u8]>) -> bool {
        self.kids.contains(kid) || is_recovery_key(kid, records, &self.commitments)
    }
}

const CACHE_LEN: usize = 8;

/// The recovery keys by the held bundle voices they were read from (the
/// reading is a pure function of the voices and the rows they name, which
/// are content-addressed by them). Only a reading with a Valid bundle is
/// kept, so a lineage completed by a later row is re-read.
static RECOVERY_KEYS_CACHE: std::sync::Mutex<Vec<(Digest32, RecoveryKeys)>> =
    std::sync::Mutex::new(Vec::new());

fn voices_key(voices: &[Vec<u8>]) -> Digest32 {
    use sha2::Digest as _;
    let mut sorted: Vec<&Vec<u8>> = voices.iter().collect();
    sorted.sort();
    sorted.dedup();
    let mut h = sha2::Sha256::new();
    for v in sorted {
        h.update((v.len() as u64).to_be_bytes());
        h.update(v);
    }
    h.finalize().into()
}

/// **The recovery keys in force**: one directory read of the held bundle
/// voices; on a cache miss, C1's [`super::genesis::genesis_in_force`]
/// (itself cached by content) and the derivation above.
///
/// # Errors
/// Directory read failures.
pub async fn recovery_keys_in_force<F>(dir: &F) -> Result<RecoveryKeys, Error>
where
    F: FederationDirectory + ?Sized,
{
    let voices = dir
        .edition2_objects(super::genesis::GENESIS_BUNDLE_TYP)
        .await?;
    if voices.is_empty() {
        return Ok(RecoveryKeys::default());
    }
    let key = voices_key(&voices);
    let hit = RECOVERY_KEYS_CACHE
        .lock()
        .unwrap_or_else(std::sync::PoisonError::into_inner)
        .iter()
        .find(|(k, _)| *k == key)
        .map(|(_, r)| r.clone());
    if let Some(r) = hit {
        return Ok(r);
    }
    let held = super::genesis::genesis_in_force(dir).await?;
    let keys = RecoveryKeys::of(&held.valid, &held.statements);
    if !held.valid.is_empty() {
        let mut c = RECOVERY_KEYS_CACHE
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        if !c.iter().any(|(k, _)| *k == key) {
            if c.len() >= CACHE_LEN {
                c.remove(0);
            }
            c.push((key, keys.clone()));
        }
    }
    Ok(keys)
}

/// **Refuse a statement signed by a recovery key** (module docs). Called
/// after the pure statement gates and before any key lookup:
/// [`super::ingest::put_statement`] and [`super::ingest::verify_carried`].
///
/// # Errors
/// [`malformed_row::RECOVERY_KEY_IS_NOT_A_SIGNER`] (terminal); directory
/// failures.
pub async fn refuse_recovery_key_signer<F>(dir: &F, statement: &[u8]) -> Result<(), Error>
where
    F: FederationDirectory + ?Sized,
{
    let Some(kid) = statement_kid(statement) else {
        return Ok(());
    };
    let keys = recovery_keys_in_force(dir).await?;
    if keys.is_empty() {
        return Ok(());
    }
    // A committed recovery key no bundle names yet: its key is known only
    // from a record of it (the statement itself, or one filed under it).
    let own = if keys.kids.contains(&kid) {
        Vec::new()
    } else {
        dir.edition2_statements_about(KEY_RECORD_FAMILY, &identity_ref(&kid))
            .await?
    };
    let records = std::iter::once(statement).chain(own.iter().map(Vec::as_slice));
    if keys.holds(&kid, records) {
        return Err(Error::malformed_row(
            super::door::PLANE,
            malformed_row::RECOVERY_KEY_IS_NOT_A_SIGNER,
            format!(
                "the signing key {} is a recovery key a held genesis bundle commits to: a \
                 recovery key signs no row, only its bundle's recovery voice (CC 4.2.6)",
                identity_ref(&kid)
            ),
        ));
    }
    Ok(())
}
