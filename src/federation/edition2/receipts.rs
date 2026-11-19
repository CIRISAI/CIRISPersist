//! v62.0.0 (P10; CC rc21 2.7.11, CC 2.6.1.11, RFC 9942, RFC 9943) — **a host
//! runs admitted code only once it holds a SCITT receipt** from a
//! Transparency Service it trusts.
//!
//! The receipt is SCITT's own: a COSE receipt (RFC 9942) in the statement's
//! UNPROTECTED header, parameter `receipts`, label 394, as RFC 9943 carries
//! it (`signed_object_v2.cddl`: `? 394: [+ bstr .cbor ceg-receipt]`). It is
//! never signed by the statement's signer, and it is outside the row id and
//! the statement id: both hash the protected header and the payload only
//! (`edition2::row_id`, `edition2::statement_id`). So a receipt that arrives
//! later, from any holder, names the SAME statement.
//!
//! This module holds:
//!
//! - **what is held** ([`receipts_of`], [`held_bytes`]): only the members of
//!   the `receipts` parameter that are CC's `ceg-receipt` (the deterministic
//!   encoding of a tag-18 `COSE_Sign1` carrying `vdp`, label 396), at most
//!   [`MAX_RECEIPTS`]. CC's ruling (P10 fix1, point 4): a malformed, non-CDE
//!   or non-receipt item in header 394 NEVER faults the row — the header is
//!   unsigned and can be tampered with in transit. Such an item is IGNORED:
//!   it is not held, so the code waits. The store keeps the statement with
//!   its parameter reduced to what is held ([`held_bytes`]); nothing at the
//!   door refuses for it.
//! - **the merge** ([`merged`]): a held statement takes the union of the
//!   receipts it holds and the ones a later copy carries, sorted and
//!   unique; the store rewrites the held bytes with it (never replaces a
//!   receipt), so receipts from several services and several deliveries
//!   accumulate, and the serve paths hand the statement out WITH them.
//! - **the trust** ([`trusted_services`]; CC ruling, point 5): a live
//!   `trust:accepts` edge signed by the HOST OWNER (the owner its
//!   owner-binding names), at `self` scope, whose `trust_classes` lists
//!   [`TRANSPARENCY_CLASS`], naming the service. One hop. The edge carries
//!   the service's key (point 2), in one of two arms:
//!   the service's key (point 2) in its payload member
//!   [`SERVICE_KEY_MEMBER`] (`service_key`, CC 4.4.3.34), in one of two arms:
//!   - **a CEG identity**: `service_key` is the identity-ref the edge names
//!     (or is absent); the service's key is read from that identity's
//!     `key:record` on THIS node's key plane (the composite, -70100);
//!   - **a COSE_Key**: `service_key` is the deterministic encoding of a
//!     COSE_Key with its `alg` (ES256, EdDSA, ML-DSA-65 or the composite),
//!     and the edge names the key's RFC 9679 thumbprint as the BARE 43-char
//!     base64url key segment (CC's answer), so the edge cannot name one
//!     service and carry another's key. Such an edge names a subject no
//!     `key:record` holds; the attestation door admits it on that binding
//!     ([`is_self_certified_service_edge`]) — but never when a `key:record`
//!     holds the thumbprint's identity-ref (a CEG key, revoked or retired
//!     included): a COSE_Key carrying a CEG key's public key takes the
//!     normal subject rule.
//! - **the verification** ([`read_receipt`]): RFC 9942 section 5.2.1 over
//!   the RFC 9162 SHA-256 tree (`vds` 1). The inclusion proof is applied to
//!   the statement's leaf ([`leaf_of`]); the root it reconstructs is the
//!   receipt's detached payload; the receipt's signature over that payload
//!   verifies under the trusted service's key, and the receipt's protected
//!   `alg` MUST equal the key's.
//! - **the answer** ([`admission_unit_runnable`]): `Runnable` when a held
//!   receipt of a voice of the `admission:unit` row verifies under a trusted
//!   service's key; otherwise the unit waits ([`ADMISSION_RECEIPT_MISSING`],
//!   detail `none`, `unverifiable` or `untrusted_service`, in CC's
//!   precedence).
//!
//! **What the answer is NOT.** It is the receipt leg of CC 2.7.11 only. The
//! lease, the standing of the author or group at this host, a withdrawal and
//! the halt are the host's other legs; `Runnable` here means "the receipt
//! does not hold the unit back".
//!
//! **The leaf** (CC ruling, point 1): the statement with an EMPTY
//! unprotected header ([`leaf_of`]): the signed statement as its issuer
//! signed it, with no receipt and no presentation inside it, hashed as RFC
//! 9162's `SHA-256(0x00 || leaf)`.

use std::collections::{BTreeMap, BTreeSet};

use ciris_verify_core::cde::{self, Value};
use ciris_verify_core::edition2::{self, Digest32, KeyLookup};

use crate::federation::types::Attestation;
use crate::federation::{Error, FederationDirectory};

/// The COSE header label of the `receipts` parameter (RFC 9942 section 2).
pub const RECEIPTS_LABEL: i64 = 394;
/// The COSE header label of the verifiable data structure (`vds`).
pub const VDS_LABEL: i64 = 395;
/// The COSE header label of the verifiable data proofs (`vdp`).
pub const VDP_LABEL: i64 = 396;
/// The `vdp` key of the inclusion proofs (RFC 9942 section 5.2).
pub const INCLUSION_PROOF_KEY: i64 = -1;
/// `RFC9162_SHA256`, the one verifiable data structure read here.
pub const VDS_RFC9162_SHA256: i64 = 1;
/// The CBOR tag of a `COSE_Sign1`.
const TAG_COSE_SIGN1: u64 = 18;
/// The COSE `alg` label.
const H_ALG: i64 = 1;
/// The COSE `kid` label.
const H_KID: i64 = 4;
/// The COSE CWT claims label (RFC 9597).
const H_CWT: i64 = 15;
/// The CWT `iss` claim.
const C_ISS: i64 = 1;

/// COSE `alg` ES256 (ECDSA P-256 with SHA-256; RFC 9053).
pub const ALG_ES256: i64 = -7;
/// COSE `alg` EdDSA (RFC 9053), read as Ed25519 over an OKP Ed25519 key.
pub const ALG_EDDSA: i64 = -8;
/// COSE `alg` Ed25519 (RFC 9864, fully specified).
pub const ALG_ED25519: i64 = -19;
/// COSE `alg` ML-DSA-65 (RFC 9964).
pub const ALG_ML_DSA_65: i64 = -49;
/// COSE `alg` of the composite ML-DSA-65-Ed25519 (CEG's own).
pub const ALG_COMPOSITE: i64 = ciris_crypto::composite::COSE_ALG;

/// The most receipts one statement holds: a later copy that would take a
/// statement past it merges nothing, and an offer past it holds the first
/// [`MAX_RECEIPTS`] in byte order.
pub const MAX_RECEIPTS: usize = 16;
/// The longest inclusion path read: a tree of 2^64 leaves needs 64 hashes.
pub const MAX_INCLUSION_PATH: usize = 64;

/// The `trust_classes` member a `trust:accepts` edge lists when THIS host
/// trusts the key it names as a Transparency Service (CC 2.7.11, CC 4.4.3.34:
/// a class no charter declares).
pub const TRANSPARENCY_CLASS: &str = "transparency";

/// The `trust:accepts` payload member naming a Transparency Service's key
/// (CC 4.4.3.34): EITHER the deterministic encoding of its COSE_Key (a byte
/// string, `alg` included) OR the identity-ref of a CEG identity (text).
pub const SERVICE_KEY_MEMBER: &str = "service_key";

/// The answer token of a unit held back for want of a receipt (CC 2.7.11's
/// table: "the unit waits, and does not run").
pub const ADMISSION_RECEIPT_MISSING: &str = "admission_receipt_missing";
/// The answer token of a unit no live row admits (CC 2.7.11's table); here
/// only its `no_row` detail: no `admission:unit` row of this id is held.
pub const ADMISSION_NONE: &str = "admission_none";

/// Why a unit waits for its receipt: CC 2.7.11's details of
/// [`ADMISSION_RECEIPT_MISSING`].
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ReceiptMissing {
    /// No receipt is held for any voice of the row.
    None,
    /// A receipt from a trusted service is held, and none of them verifies.
    Unverifiable,
    /// Every held receipt is from a service this host does not trust.
    UntrustedService,
}

impl ReceiptMissing {
    /// The detail text CC's table names.
    #[must_use]
    pub const fn detail(self) -> &'static str {
        match self {
            Self::None => "none",
            Self::Unverifiable => "unverifiable",
            Self::UntrustedService => "untrusted_service",
        }
    }
}

/// The receipt leg of CC 2.7.11 for one `admission:unit` row.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum AdmissionReceipt {
    /// A held receipt verifies under the key of a service this host trusts.
    Runnable {
        /// The service whose receipt verified (the identity-ref its edge
        /// names).
        service: String,
        /// The voice the receipt registered.
        statement_id: Digest32,
    },
    /// The unit waits, and does not run ([`ADMISSION_RECEIPT_MISSING`]).
    Waiting(ReceiptMissing),
    /// No `admission:unit` row of this id is held ([`ADMISSION_NONE`],
    /// detail `no_row`).
    NotHeld,
}

impl AdmissionReceipt {
    /// Does the receipt leg let the unit run?
    #[must_use]
    pub const fn is_runnable(&self) -> bool {
        matches!(self, Self::Runnable { .. })
    }

    /// The answer's token: `None` when runnable.
    #[must_use]
    pub const fn token(&self) -> Option<&'static str> {
        match self {
            Self::Runnable { .. } => None,
            Self::Waiting(_) => Some(ADMISSION_RECEIPT_MISSING),
            Self::NotHeld => Some(ADMISSION_NONE),
        }
    }

    /// The answer's detail: `None` when runnable.
    #[must_use]
    pub const fn detail(&self) -> Option<&'static str> {
        match self {
            Self::Runnable { .. } => None,
            Self::Waiting(m) => Some(m.detail()),
            Self::NotHeld => Some("no_row"),
        }
    }
}

// ─── The statement's parts ──────────────────────────────────────────────────

/// A `COSE_Sign1`'s four parts, decoded from its deterministic encoding.
struct Sign1 {
    protected: Vec<u8>,
    unprotected: Vec<(Value, Value)>,
    payload: Value,
    signature: Value,
}

fn sign1(bytes: &[u8]) -> Option<Sign1> {
    let Value::Tag(TAG_COSE_SIGN1, inner) = cde::decode(bytes).ok()? else {
        return None;
    };
    let Value::Array(parts) = *inner else {
        return None;
    };
    let [protected, unprotected, payload, signature]: [Value; 4] = parts.try_into().ok()?;
    let Value::Bytes(protected) = protected else {
        return None;
    };
    let Value::Map(unprotected) = unprotected else {
        return None;
    };
    Some(Sign1 {
        protected,
        unprotected,
        payload,
        signature,
    })
}

fn encode_sign1(s: Sign1) -> Vec<u8> {
    cde::encode(&Value::Tag(
        TAG_COSE_SIGN1,
        Box::new(Value::Array(vec![
            Value::Bytes(s.protected),
            Value::Map(s.unprotected),
            s.payload,
            s.signature,
        ])),
    ))
}

fn is_receipts_key(k: &Value) -> bool {
    k.as_i64() == Some(RECEIPTS_LABEL)
}

/// The statement id of a statement (`edition2::statement_id` over its
/// protected header and payload as signed): what a receipt never changes.
/// `None` for bytes that are no `COSE_Sign1` with an attached payload.
#[must_use]
pub fn statement_id_of(statement: &[u8]) -> Option<Digest32> {
    let s = sign1(statement)?;
    let payload = s.payload.as_bytes()?;
    Some(edition2::statement_id(&s.protected, payload))
}

/// Is `bytes` CC's `ceg-receipt`: the deterministic encoding of
/// `#6.18([bstr, {396: {* int => [+ bstr]}, * int => any}, bstr / nil, bstr])`?
#[must_use]
pub fn is_ceg_receipt(bytes: &[u8]) -> bool {
    let Some(s) = sign1(bytes) else {
        return false;
    };
    let payload_ok = matches!(s.payload, Value::Bytes(_) | Value::Null);
    let signature_ok = matches!(s.signature, Value::Bytes(_));
    let vdp_ok = s
        .unprotected
        .iter()
        .find(|(k, _)| k.as_i64() == Some(VDP_LABEL))
        .and_then(|(_, v)| v.as_map())
        .is_some_and(|m| {
            m.iter().all(|(k, v)| {
                k.as_i64().is_some()
                    && v.as_array()
                        .is_some_and(|a| !a.is_empty() && a.iter().all(|p| p.as_bytes().is_some()))
            })
        });
    payload_ok && signature_ok && vdp_ok
}

/// **The receipts a statement holds**: the members of its `receipts`
/// parameter that are [`is_ceg_receipt`], sorted, unique, at most
/// [`MAX_RECEIPTS`] (the first in byte order). Every other item — not a byte
/// string, not CDE, not a receipt, a parameter that is not an array — is
/// IGNORED (CC ruling: never a fault; not held, so the code waits).
#[must_use]
pub fn receipts_of(statement: &[u8]) -> Vec<Vec<u8>> {
    let Some(s) = sign1(statement) else {
        return Vec::new();
    };
    let set: BTreeSet<Vec<u8>> = s
        .unprotected
        .iter()
        .find(|(k, _)| is_receipts_key(k))
        .and_then(|(_, v)| v.as_array())
        .map(|a| {
            a.iter()
                .filter_map(Value::as_bytes)
                .filter(|b| is_ceg_receipt(b))
                .map(<[u8]>::to_vec)
                .collect()
        })
        .unwrap_or_default();
    set.into_iter().take(MAX_RECEIPTS).collect()
}

/// The statement with its `receipts` parameter set to `receipts` (sorted
/// and unique; removed when empty), every other unprotected member and
/// every signed byte kept. `None` for bytes that are no `COSE_Sign1`.
#[must_use]
pub fn with_receipts(statement: &[u8], receipts: &[Vec<u8>]) -> Option<Vec<u8>> {
    let mut s = sign1(statement)?;
    let set: BTreeSet<Vec<u8>> = receipts.iter().cloned().collect();
    s.unprotected.retain(|(k, _)| !is_receipts_key(k));
    if !set.is_empty() {
        s.unprotected.push((
            Value::int(RECEIPTS_LABEL),
            Value::Array(set.into_iter().map(Value::Bytes).collect()),
        ));
    }
    Some(encode_sign1(s))
}

/// **The bytes the store holds for an offered statement**: as received when
/// it has no `receipts` parameter; otherwise with the parameter reduced to
/// [`receipts_of`] (removed when nothing in it is held). The row id and the
/// statement id are those of the offered bytes (the parameter is outside
/// both). Bytes that are no `COSE_Sign1` are returned as they are.
#[must_use]
pub fn held_bytes(statement: &[u8]) -> Vec<u8> {
    let has_parameter =
        sign1(statement).is_some_and(|s| s.unprotected.iter().any(|(k, _)| is_receipts_key(k)));
    if !has_parameter {
        return statement.to_vec();
    }
    with_receipts(statement, &receipts_of(statement)).unwrap_or_else(|| statement.to_vec())
}

/// **The leaf a Transparency Service registers for a statement** (CC ruling,
/// point 1): the statement with an EMPTY unprotected header, so no receipt or
/// presentation is inside it. `None` for bytes that are no `COSE_Sign1`.
#[must_use]
pub fn leaf_of(statement: &[u8]) -> Option<Vec<u8>> {
    let mut s = sign1(statement)?;
    s.unprotected.clear();
    Some(encode_sign1(s))
}

/// **The merge**: the held statement with the union of its receipts and the
/// ones `offered` (a later copy of the same statement) carries. `None` when
/// nothing changes: `offered` brings no receipt the held copy lacks, the
/// two are not the same statement, the union would pass [`MAX_RECEIPTS`] or
/// the statement would pass the door's size cap (a merge never drops a
/// held receipt to make room).
#[must_use]
pub fn merged(held: &[u8], offered: &[u8]) -> Option<Vec<u8>> {
    let incoming = receipts_of(offered);
    if incoming.is_empty() {
        return None;
    }
    let same = statement_id_of(held)?;
    if statement_id_of(offered)? != same {
        return None;
    }
    let mut set: BTreeSet<Vec<u8>> = receipts_of(held).into_iter().collect();
    let before = set.len();
    set.extend(incoming);
    if set.len() == before || set.len() > MAX_RECEIPTS {
        return None;
    }
    let all: Vec<Vec<u8>> = set.into_iter().collect();
    let out = with_receipts(held, &all)?;
    (out.len() <= super::door::MAX_STATEMENT_BYTES).then_some(out)
}

// ─── The verification (RFC 9942 section 5.2.1, RFC 9162 section 2.1.3.2) ───

/// RFC 9162 section 2.1.3.2: the root an inclusion proof reconstructs for
/// `leaf_hash` at `leaf_index` in a tree of `tree_size` leaves, or `None`
/// when the proof fails (an index not below the size, a path of the wrong
/// length). The caller compares the root (or, for a receipt, verifies the
/// signature over it).
#[must_use]
pub fn inclusion_root(
    leaf_hash: &[u8; 32],
    leaf_index: u64,
    tree_size: u64,
    path: &[[u8; 32]],
) -> Option<[u8; 32]> {
    use ciris_verify_core::transparency::hash_node;
    if leaf_index >= tree_size || path.len() > MAX_INCLUSION_PATH {
        return None;
    }
    let mut fnode = leaf_index;
    let mut snode = tree_size - 1;
    let mut r = *leaf_hash;
    for p in path {
        if snode == 0 {
            return None;
        }
        if fnode & 1 == 1 || fnode == snode {
            r = hash_node(p, &r);
            if fnode & 1 == 0 {
                while fnode & 1 == 0 && fnode != 0 {
                    fnode >>= 1;
                    snode >>= 1;
                }
            }
        } else {
            r = hash_node(&r, p);
        }
        fnode >>= 1;
        snode >>= 1;
    }
    (snode == 0).then_some(r)
}

/// One inclusion proof: `bstr .cbor [tree-size, leaf-index, [* bstr]]`.
fn inclusion_proof(bytes: &[u8]) -> Option<(u64, u64, Vec<[u8; 32]>)> {
    let v = cde::decode(bytes).ok()?;
    let [size, index, path] = v.as_array()? else {
        return None;
    };
    let path = path
        .as_array()?
        .iter()
        .map(|h| <[u8; 32]>::try_from(h.as_bytes()?).ok())
        .collect::<Option<Vec<_>>>()?;
    Some((size.as_u64()?, index.as_u64()?, path))
}

/// The key material of a third-party service's COSE_Key.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum KeyMaterial {
    /// EC2, crv P-256: the SEC1 uncompressed point `0x04 || x || y`.
    P256(Vec<u8>),
    /// OKP, crv Ed25519: the 32-byte public key.
    Ed25519([u8; 32]),
    /// AKP, alg ML-DSA-65: the encoded public key.
    MlDsa65(Vec<u8>),
    /// AKP, alg the composite: the composite public key.
    Composite(Vec<u8>),
}

/// A third-party Transparency Service's key, as its edge carries it.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct CoseKey {
    /// The key's `alg` (label 3): a receipt's protected `alg` must equal it.
    pub alg: i64,
    /// The key's `kid` (label 2), if it states one.
    pub kid: Option<Vec<u8>>,
    /// The key.
    pub material: KeyMaterial,
    /// The RFC 9679 thumbprint of the key (SHA-256 over its required
    /// members).
    pub thumbprint: Digest32,
    /// The thumbprint as the bare 43-char base64url key segment: what the
    /// edge names (CC's answer).
    pub subject: String,
}

impl CoseKey {
    /// The thumbprint's identity-ref (`urn:ietf:params:oauth:ckt:sha-256:…`):
    /// the CEG identity a key of this thumbprint would be.
    #[must_use]
    pub fn identity_ref(&self) -> String {
        edition2::identity_ref(&self.thumbprint)
    }
}

fn bytes_n<const N: usize>(v: Option<&Value>) -> Option<[u8; N]> {
    <[u8; N]>::try_from(v?.as_bytes()?).ok()
}

/// **Parse a COSE_Key** (the deterministic encoding of a map), with its
/// `alg` required and matching its key type: EC2 P-256 with ES256; OKP
/// Ed25519 with EdDSA or Ed25519; AKP with ML-DSA-65 or the composite.
/// `None` for anything else (an edge carrying it trusts nothing).
#[must_use]
pub fn parse_cose_key(bytes: &[u8]) -> Option<CoseKey> {
    let m = cde::decode(bytes).ok()?;
    m.as_map()?;
    let kty = m.get_int(1)?.as_i64()?;
    let alg = m.get_int(3)?.as_i64()?;
    let kid = m.get_int(2).and_then(Value::as_bytes).map(<[u8]>::to_vec);
    // The RFC 9679 required members of each key type.
    let (material, required): (KeyMaterial, Vec<(i64, Value)>) = match (kty, alg) {
        (2, ALG_ES256) => {
            if m.get_int(-1)?.as_i64()? != 1 {
                return None;
            }
            let x: [u8; 32] = bytes_n(m.get_int(-2))?;
            let y: [u8; 32] = bytes_n(m.get_int(-3))?;
            let mut sec1 = Vec::with_capacity(65);
            sec1.push(0x04);
            sec1.extend_from_slice(&x);
            sec1.extend_from_slice(&y);
            (
                KeyMaterial::P256(sec1),
                vec![
                    (1, Value::Uint(2)),
                    (-1, Value::Uint(1)),
                    (-2, Value::Bytes(x.to_vec())),
                    (-3, Value::Bytes(y.to_vec())),
                ],
            )
        }
        (1, ALG_EDDSA | ALG_ED25519) => {
            if m.get_int(-1)?.as_i64()? != 6 {
                return None;
            }
            let x: [u8; 32] = bytes_n(m.get_int(-2))?;
            (
                KeyMaterial::Ed25519(x),
                vec![
                    (1, Value::Uint(1)),
                    (-1, Value::Uint(6)),
                    (-2, Value::Bytes(x.to_vec())),
                ],
            )
        }
        (7, ALG_ML_DSA_65 | ALG_COMPOSITE) => {
            let public = m.get_int(-1)?.as_bytes()?.to_vec();
            let material = if alg == ALG_ML_DSA_65 {
                KeyMaterial::MlDsa65(public.clone())
            } else {
                KeyMaterial::Composite(public.clone())
            };
            (
                material,
                vec![
                    (1, Value::Uint(7)),
                    (3, Value::int(alg)),
                    (-1, Value::Bytes(public)),
                ],
            )
        }
        _ => return None,
    };
    let thumb: Digest32 = <sha2::Sha256 as sha2::Digest>::digest(cde::encode(&Value::Map(
        required
            .into_iter()
            .map(|(k, v)| (Value::int(k), v))
            .collect(),
    )))
    .into();
    let subject =
        crate::federation::namespace::key_segment::segment_of(&edition2::identity_ref(&thumb))?;
    Some(CoseKey {
        alg,
        kid,
        material,
        thumbprint: thumb,
        subject,
    })
}

/// Does `sig` verify over `tbs` under `key`, in `alg`?
fn cose_signature_verifies(key: &CoseKey, alg: i64, tbs: &[u8], sig: &[u8]) -> bool {
    use ciris_crypto::{ClassicalVerifier as _, PqcVerifier as _};
    if alg != key.alg {
        return false;
    }
    match &key.material {
        KeyMaterial::P256(sec1) => {
            matches!(
                ciris_crypto::P256Verifier::new().verify(sec1, tbs, sig),
                Ok(true)
            )
        }
        KeyMaterial::Ed25519(pk) => {
            matches!(
                ciris_crypto::Ed25519Verifier::new().verify(pk, tbs, sig),
                Ok(true)
            )
        }
        KeyMaterial::MlDsa65(pk) => {
            matches!(
                ciris_crypto::MlDsa65Verifier::new().verify(pk, tbs, sig),
                Ok(true)
            )
        }
        KeyMaterial::Composite(pk) => ciris_crypto::composite::CompositePublicKey::from_bytes(pk)
            .is_ok_and(|k| k.verify(tbs, sig).is_ok()),
    }
}

/// How a trusted service's key is found.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum ServiceKey {
    /// A CEG identity: the key is the receipt's `kid`, read from THIS node's
    /// key plane and a key of the identity the edge names (the composite).
    Ceg,
    /// A COSE_Key the edge carries.
    Cose(CoseKey),
}

/// One Transparency Service THIS host trusts, from its owner's edge.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct TrustedService {
    /// The identity-ref the edge names.
    pub service: String,
    /// Where its key is.
    pub key: ServiceKey,
}

/// What one held receipt says, read against the statement it is held on.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ReceiptReading {
    /// The service it is from: the trusted service whose key it verifies
    /// under, or that it names (its `kid` or CWT `iss`); else what it names
    /// of itself; `None` when it names nothing.
    pub service: Option<String>,
    /// Does it verify under a trusted service's key?
    pub verifies: bool,
}

/// A receipt's protected header, read before any verification.
struct ReceiptHeader {
    alg: Option<i64>,
    vds: Option<i64>,
    kid: Option<Vec<u8>>,
    iss: Option<String>,
}

fn receipt_header(protected: &Value) -> ReceiptHeader {
    ReceiptHeader {
        alg: protected.get_int(H_ALG).and_then(Value::as_i64),
        vds: protected.get_int(VDS_LABEL).and_then(Value::as_i64),
        kid: protected
            .get_int(H_KID)
            .and_then(Value::as_bytes)
            .map(<[u8]>::to_vec),
        iss: protected
            .get_int(H_CWT)
            .and_then(|c| c.get_int(C_ISS))
            .and_then(Value::as_text)
            .filter(|s| edition2::is_identity_ref(s))
            .map(str::to_owned),
    }
}

impl ReceiptHeader {
    /// The 32-byte `kid`, the thumbprint of a CEG key.
    fn kid32(&self) -> Option<Digest32> {
        self.kid
            .as_deref()
            .and_then(|k| <[u8; 32]>::try_from(k).ok())
    }

    /// What the receipt names of itself: its CWT `iss`, else its 32-byte
    /// `kid`'s identity-ref.
    fn named(&self) -> Option<String> {
        self.iss
            .clone()
            .or_else(|| self.kid32().as_ref().map(edition2::identity_ref))
    }

    /// Is the receipt (by what it names) from `svc`? A CEG service: by its
    /// CWT `iss` or its 32-byte `kid`. A COSE_Key with a `kid`: by the
    /// receipt's `kid`. A COSE_Key WITHOUT one: by the thumbprint only (a
    /// CWT `iss` naming its identity-ref); the receipt's own `kid` carries
    /// NO weight for that key (CC's answer).
    fn names(&self, svc: &TrustedService) -> bool {
        match &svc.key {
            ServiceKey::Ceg => self.named().as_deref() == Some(svc.service.as_str()),
            ServiceKey::Cose(k) => match &k.kid {
                Some(kid) => self.kid.as_ref() == Some(kid),
                None => self.iss.as_deref() == Some(k.identity_ref().as_str()),
            },
        }
    }
}

/// The roots the receipt's inclusion proofs reconstruct from `statement`'s
/// leaf (RFC 9162 SHA-256); an attached payload must BE the root.
fn roots(statement: &[u8], r: &Sign1) -> Vec<[u8; 32]> {
    let Some(leaf) = leaf_of(statement) else {
        return Vec::new();
    };
    let leaf_hash = ciris_verify_core::transparency::hash_leaf(&leaf);
    let proofs = r
        .unprotected
        .iter()
        .find(|(k, _)| k.as_i64() == Some(VDP_LABEL))
        .and_then(|(_, v)| v.get_int(INCLUSION_PROOF_KEY))
        .and_then(Value::as_array)
        .unwrap_or_default();
    proofs
        .iter()
        .filter_map(Value::as_bytes)
        .filter_map(inclusion_proof)
        .filter_map(|(size, index, path)| inclusion_root(&leaf_hash, index, size, &path))
        .filter(|root| match &r.payload {
            Value::Bytes(attached) => attached.as_slice() == root.as_slice(),
            _ => true,
        })
        .collect()
}

/// Does the receipt verify under `svc`'s key?
fn verifies_under(
    h: &ReceiptHeader,
    r: &Sign1,
    roots: &[[u8; 32]],
    svc: &TrustedService,
    keys: &dyn edition2::KeyDirectory,
    now_ms: u64,
) -> bool {
    if h.vds != Some(VDS_RFC9162_SHA256) || roots.is_empty() {
        return false;
    }
    let (Some(alg), Some(sig)) = (h.alg, r.signature.as_bytes()) else {
        return false;
    };
    let check = |verify: &dyn Fn(&[u8]) -> bool| {
        roots
            .iter()
            .any(|root| verify(&edition2::sig_structure(&r.protected, root)))
    };
    match &svc.key {
        ServiceKey::Ceg => {
            // The CEG arm: the composite key the receipt's kid names, held
            // and in force now, and a key of the identity the edge names.
            if alg != ALG_COMPOSITE {
                return false;
            }
            let Some(kid) = h.kid32() else {
                return false;
            };
            let KeyLookup::Held(pk) = keys.lookup(&kid, now_ms) else {
                return false;
            };
            if super::door::require_key_of_iss(keys, &kid, &svc.service).is_err() {
                return false;
            }
            check(&|tbs| pk.verify(tbs, sig).is_ok())
        }
        ServiceKey::Cose(key) => check(&|tbs| cose_signature_verifies(key, alg, tbs, sig)),
    }
}

/// **Read one receipt** held on `statement` against the services THIS host
/// trusts: from the first trusted service whose key it verifies under
/// (`verifies`); else from a trusted service it names (it does not verify:
/// a wrong `alg`, a wrong signature, a wrong leaf); else from what it names
/// of itself. `keys` is the key plane of its 32-byte `kid`
/// ([`super::ingest::held_keys_for_kid`]), read for the CEG arm; `now_ms`
/// the host's clock.
#[must_use]
pub fn read_receipt(
    statement: &[u8],
    receipt: &[u8],
    trusted: &[TrustedService],
    keys: &dyn edition2::KeyDirectory,
    now_ms: u64,
) -> ReceiptReading {
    let unread = ReceiptReading {
        service: None,
        verifies: false,
    };
    let Some(r) = sign1(receipt) else {
        return unread;
    };
    let Ok(protected) = cde::decode(&r.protected) else {
        return unread;
    };
    let h = receipt_header(&protected);
    let roots = roots(statement, &r);
    let mut reading = ReceiptReading {
        service: h.named(),
        verifies: false,
    };
    for svc in trusted {
        if verifies_under(&h, &r, &roots, svc, keys, now_ms) {
            return ReceiptReading {
                service: Some(svc.service.clone()),
                verifies: true,
            };
        }
        if h.names(svc) {
            reading.service = Some(svc.service.clone());
        }
    }
    reading
}

// ─── The trust (CC 2.7.11 "Who runs a Transparency Service") ───────────────

/// Does a live acceptance edge list the class `transparency`?
fn lists_transparency(edge: &Attestation) -> bool {
    edge.attestation_envelope
        .get(super::typed::TRUST_CLASSES_MEMBER)
        .and_then(serde_json::Value::as_array)
        .is_some_and(|a| a.iter().any(|c| c.as_str() == Some(TRANSPARENCY_CLASS)))
}

/// What an edge's [`SERVICE_KEY_MEMBER`] holds.
enum ServiceKeyMember {
    /// The identity-ref of a CEG identity (text).
    Identity(String),
    /// A COSE_Key that parses.
    Cose(CoseKey),
    /// Anything else: the edge trusts nothing.
    Unreadable,
}

/// The [`SERVICE_KEY_MEMBER`] of an edge's carried statement: `None` when
/// the edge carries none (or carries no statement).
fn carried_service_key(edge: &Attestation) -> Option<ServiceKeyMember> {
    let st = super::emit::carried_statement(edge)?;
    let (_, payload) = super::liveness::statement_parts(&st)?;
    let member = payload.get_text(SERVICE_KEY_MEMBER)?;
    Some(match member {
        Value::Text(t) if edition2::is_identity_ref(t) => ServiceKeyMember::Identity(t.clone()),
        Value::Bytes(b) => {
            parse_cose_key(b).map_or(ServiceKeyMember::Unreadable, ServiceKeyMember::Cose)
        }
        _ => ServiceKeyMember::Unreadable,
    })
}

/// Does THIS node hold a CEG key of `key`'s thumbprint: a `key:record` about
/// its identity-ref (whatever its liveness: revoked and retired included),
/// or an earlier-store key row under it?
async fn ceg_key_held<F>(dir: &F, key: &CoseKey) -> Result<bool, Error>
where
    F: FederationDirectory + ?Sized,
{
    let iref = key.identity_ref();
    if !dir
        .edition2_statements_about(ciris_verify_core::edition2::keys::KEY_RECORD_FAMILY, &iref)
        .await?
        .is_empty()
    {
        return Ok(true);
    }
    Ok(dir.lookup_public_key(&iref).await?.is_some())
}

/// v62.0.0 (P10 fix1; CC 2.7.11, CC 4.4.3.34) — **is `row` a `trust:accepts`
/// edge that names its own third-party Transparency Service key**: its
/// [`SERVICE_KEY_MEMBER`] is a COSE_Key that parses, the edge's subject is
/// that key's bare thumbprint segment, AND no `key:record` (nor earlier key
/// row) holds the thumbprint's identity-ref ([`ceg_key_held`]). Such a
/// subject is known by the edge itself, so the attestation door's subject
/// rule does not hold the edge for it. A thumbprint that is a CEG key's
/// (live, revoked or retired) takes the normal subject rule: a COSE_Key
/// carrying a CEG key's public key never dodges it.
///
/// A stranger's edge of this shape is admitted and confers nothing: only the
/// host owner's edges are read ([`trusted_services`]).
///
/// # Errors
/// Directory read failures.
pub async fn is_self_certified_service_edge<F>(dir: &F, row: &Attestation) -> Result<bool, Error>
where
    F: FederationDirectory + ?Sized,
{
    if row.attestation_type != crate::federation::types::attestation_type::DELEGATES_TO
        || crate::federation::admission::envelope_dimension(&row.attestation_envelope)
            != Some(crate::federation::trust_root::TRUST_ACCEPTS_DIMENSION)
    {
        return Ok(false);
    }
    let Some(ServiceKeyMember::Cose(k)) = carried_service_key(row) else {
        return Ok(false);
    };
    if k.subject != row.attested_key_id {
        return Ok(false);
    }
    Ok(!ceg_key_held(dir, &k).await?)
}

/// v62.0.0 (P10 fix1; CC 2.7.11, CC ruling point 5) — **the Transparency
/// Services THIS host trusts at `now`**: one hop, from the HOST OWNER's own
/// live `trust:accepts` edges (the owner the node's owner-binding names,
/// `admission::owner_of_unmarked`) at `self` scope, whose `trust_classes`
/// list [`TRANSPARENCY_CLASS`], not past their `valid_until`. Each names the
/// service by its [`SERVICE_KEY_MEMBER`]: a COSE_Key is the
/// [`ServiceKey::Cose`] arm, only when the edge names that key's bare
/// thumbprint and no CEG key has that thumbprint; an identity-ref equal to
/// the edge's subject, or no member with an identity-ref subject, is the
/// [`ServiceKey::Ceg`] arm; anything else trusts nothing. No node key, no owner, or an
/// ambiguous owner: none. Tier-agnostic (CC ruling point 6).
///
/// # Errors
/// Directory read failures.
pub async fn trusted_services<F>(
    dir: &F,
    now: chrono::DateTime<chrono::Utc>,
) -> Result<Vec<TrustedService>, Error>
where
    F: FederationDirectory + ?Sized,
{
    use crate::federation::attestation_query::{AttestationQuery, FOLD_PAGE};
    use crate::federation::trust_root::TRUST_ACCEPTS_DIMENSION;
    use crate::federation::types::cohort_scope;
    let Some(node) = dir.node_key_id() else {
        return Ok(Vec::new());
    };
    let owner = match crate::federation::admission::owner_of_unmarked(dir, &node).await {
        Ok(Some(o)) => o,
        Ok(None) | Err(Error::AmbiguousNodeOwner { .. }) => return Ok(Vec::new()),
        Err(e) => return Err(e),
    };
    let (live, _) = super::typed::acceptance_edges(
        dir,
        AttestationQuery::by(&owner, FOLD_PAGE).dimension(TRUST_ACCEPTS_DIMENSION),
    )
    .await?;
    let mut out: Vec<TrustedService> = Vec::new();
    for e in &live {
        if e.attesting_key_id != owner
            || e.cohort_scope != cohort_scope::SELF
            || !e.expires_at.is_none_or(|t| t > now)
            || !lists_transparency(e)
        {
            continue;
        }
        let key = match carried_service_key(e) {
            // No member, or the identity-ref the edge names: the CEG arm.
            None if edition2::is_identity_ref(&e.attested_key_id) => ServiceKey::Ceg,
            Some(ServiceKeyMember::Identity(r)) if r == e.attested_key_id => ServiceKey::Ceg,
            // A COSE_Key whose bare thumbprint the edge names, and that is
            // no CEG key's (the door's rule, read again now).
            Some(ServiceKeyMember::Cose(k)) if k.subject == e.attested_key_id => {
                if ceg_key_held(dir, &k).await? {
                    continue;
                }
                ServiceKey::Cose(k)
            }
            _ => continue,
        };
        let svc = TrustedService {
            service: e.attested_key_id.clone(),
            key,
        };
        if !out.contains(&svc) {
            out.push(svc);
        }
    }
    Ok(out)
}

// ─── The answer ─────────────────────────────────────────────────────────────

/// Is `statement` a voice of an `admission:unit` row (its header's family)?
fn is_admission_unit(statement: &[u8]) -> bool {
    super::liveness::statement_parts(statement).is_some_and(|(protected, _)| {
        protected.get_int(-70002).and_then(Value::as_text)
            == Some(super::payloads::ADMISSION_UNIT_FAMILY)
    })
}

/// CC 2.7.11's rule over the readings of every held receipt (CC's
/// `receipt_rule`): none held waits `none`; one that verifies from a trusted
/// service runs; else a trusted service's receipt waits `unverifiable`; else
/// `untrusted_service`.
#[must_use]
pub fn receipt_rule(
    readings: &[(Digest32, ReceiptReading)],
    trusted: &BTreeSet<String>,
) -> AdmissionReceipt {
    if readings.is_empty() {
        return AdmissionReceipt::Waiting(ReceiptMissing::None);
    }
    let is_trusted = |r: &ReceiptReading| r.service.as_ref().is_some_and(|s| trusted.contains(s));
    if let Some((statement_id, r)) = readings.iter().find(|(_, r)| r.verifies && is_trusted(r)) {
        return AdmissionReceipt::Runnable {
            service: r.service.clone().unwrap_or_default(),
            statement_id: *statement_id,
        };
    }
    if readings.iter().any(|(_, r)| is_trusted(r)) {
        AdmissionReceipt::Waiting(ReceiptMissing::Unverifiable)
    } else {
        AdmissionReceipt::Waiting(ReceiptMissing::UntrustedService)
    }
}

/// v62.0.0 (P10; CC rc21 2.7.11) — **may the unit an `admission:unit` row
/// admits run, as far as its receipt goes**: [`AdmissionReceipt::Runnable`]
/// when a receipt held on a voice of the row verifies ([`read_receipt`])
/// under the key of a service THIS host trusts ([`trusted_services`]);
/// `Waiting(..)` ([`ADMISSION_RECEIPT_MISSING`]) otherwise; `NotHeld` when
/// no voice of an `admission:unit` row of this id is held. Read at `now`:
/// nothing is stored, so a later receipt, a later edge or a withdrawn edge
/// changes the next answer. Only the row's own voices are read (CC ruling
/// point 3).
///
/// # Errors
/// Directory read failures.
pub async fn admission_unit_runnable<F>(
    dir: &F,
    row_id: &super::names::RowId,
    now: chrono::DateTime<chrono::Utc>,
) -> Result<AdmissionReceipt, Error>
where
    F: FederationDirectory + ?Sized,
{
    let voices: Vec<Vec<u8>> = dir
        .edition2_voices(row_id)
        .await?
        .into_iter()
        .filter(|v| is_admission_unit(v))
        .collect();
    if voices.is_empty() {
        return Ok(AdmissionReceipt::NotHeld);
    }
    let trusted = trusted_services(dir, now).await?;
    let names: BTreeSet<String> = trusted.iter().map(|s| s.service.clone()).collect();
    let now_ms = u64::try_from(now.timestamp_millis()).unwrap_or(0);
    let mut planes: BTreeMap<Digest32, super::liveness::HeldKeys> = BTreeMap::new();
    let mut readings = Vec::new();
    for voice in &voices {
        let Some(statement_id) = statement_id_of(voice) else {
            continue;
        };
        for receipt in receipts_of(voice) {
            let kid = sign1(&receipt)
                .and_then(|r| cde::decode(&r.protected).ok())
                .and_then(|p| receipt_header(&p).kid32());
            let keys = match kid {
                Some(kid) => {
                    if let Some(held) = planes.get(&kid) {
                        held.clone()
                    } else {
                        let held = super::ingest::held_keys_for_kid(dir, &kid).await?;
                        planes.insert(kid, held.clone());
                        held
                    }
                }
                None => super::liveness::HeldKeys::new(),
            };
            readings.push((
                statement_id,
                read_receipt(voice, &receipt, &trusted, &keys, now_ms),
            ));
        }
    }
    Ok(receipt_rule(&readings, &names))
}

// ─── Producer and test support ──────────────────────────────────────────────

/// Test and producer support: **mint a COSE receipt** (RFC 9942) for
/// `statement`, registered at `leaf_index` of a tree whose other leaves are
/// `others` (the statement's leaf inserted at `leaf_index`). `protected` is
/// the receipt's protected header (its `vds` is added); `sign` signs the
/// `Sig_structure` over the root.
///
/// # Panics
/// `leaf_index > others.len()`, or bytes that are no `COSE_Sign1`.
#[cfg(any(test, feature = "test-anchor"))]
#[must_use]
pub fn mint_receipt_with(
    protected: Vec<(Value, Value)>,
    sign: &dyn Fn(&[u8]) -> Vec<u8>,
    statement: &[u8],
    others: &[Vec<u8>],
    leaf_index: usize,
) -> Vec<u8> {
    use ciris_verify_core::transparency::{hash_leaf, hash_node};
    fn mth(leaves: &[[u8; 32]]) -> [u8; 32] {
        match leaves.len() {
            // A minted tree holds the statement's leaf: never empty.
            0 => [0; 32],
            1 => leaves[0],
            n => {
                let k = split(n);
                hash_node(&mth(&leaves[..k]), &mth(&leaves[k..]))
            }
        }
    }
    /// The largest power of two below `n` (n > 1).
    fn split(n: usize) -> usize {
        let mut k = 1;
        while k << 1 < n {
            k <<= 1;
        }
        k
    }
    /// RFC 9162 section 2.1.3.1 PATH(m, D[n]), leaf to root.
    fn path(m: usize, leaves: &[[u8; 32]]) -> Vec<[u8; 32]> {
        let n = leaves.len();
        if n <= 1 {
            return Vec::new();
        }
        let k = split(n);
        if m < k {
            let mut p = path(m, &leaves[..k]);
            p.push(mth(&leaves[k..]));
            p
        } else {
            let mut p = path(m - k, &leaves[k..]);
            p.push(mth(&leaves[..k]));
            p
        }
    }
    let mut leaves: Vec<[u8; 32]> = others.iter().map(|l| hash_leaf(l.as_slice())).collect();
    let leaf = leaf_of(statement).expect("mint_receipt: a COSE_Sign1 statement");
    leaves.insert(leaf_index, hash_leaf(&leaf));
    let root = mth(&leaves);
    let proof = cde::encode(&Value::Array(vec![
        Value::Uint(u64::try_from(leaves.len()).expect("mint_receipt: tree size")),
        Value::Uint(u64::try_from(leaf_index).expect("mint_receipt: leaf index")),
        Value::Array(
            path(leaf_index, &leaves)
                .into_iter()
                .map(|h| Value::Bytes(h.to_vec()))
                .collect(),
        ),
    ]));
    let mut protected = protected;
    protected.retain(|(k, _)| k.as_i64() != Some(VDS_LABEL));
    protected.push((Value::int(VDS_LABEL), Value::int(VDS_RFC9162_SHA256)));
    let protected = cde::encode(&Value::Map(protected));
    let sig = sign(&edition2::sig_structure(&protected, &root));
    encode_sign1(Sign1 {
        protected,
        unprotected: vec![(
            Value::int(VDP_LABEL),
            Value::Map(vec![(
                Value::int(INCLUSION_PROOF_KEY),
                Value::Array(vec![Value::Bytes(proof)]),
            )]),
        )],
        payload: Value::Null,
        signature: Value::Bytes(sig),
    })
}

/// Test and producer support: [`mint_receipt_with`] for a CEG service (the
/// composite algorithm, its `kid` the key's thumbprint), `iss` adding a CWT
/// `iss` claim.
///
/// # Panics
/// As [`mint_receipt_with`], or a signing failure.
#[cfg(any(test, feature = "test-anchor"))]
#[must_use]
pub fn mint_receipt(
    service: &ciris_crypto::composite::CompositeSigningKey,
    iss: Option<&str>,
    statement: &[u8],
    others: &[Vec<u8>],
    leaf_index: usize,
) -> Vec<u8> {
    let kid = edition2::thumbprint(service.public_key());
    let mut protected = vec![
        (Value::int(H_ALG), Value::int(ALG_COMPOSITE)),
        (Value::int(H_KID), Value::Bytes(kid.to_vec())),
    ];
    if let Some(iss) = iss {
        protected.push((
            Value::int(H_CWT),
            Value::Map(vec![(Value::int(C_ISS), Value::Text(iss.to_owned()))]),
        ));
    }
    mint_receipt_with(
        protected,
        &|tbs| service.sign(tbs).expect("mint_receipt: sign"),
        statement,
        others,
        leaf_index,
    )
}
