//! v62.0.0 (F0-cp8; CC 2.6.1.7, CC 6.1.3) — **the closed registry of signing
//! domains**, and the one framing a host artefact's composite signature is
//! over.
//!
//! RULINGS: composite signatures only, and no standalone component signer.
//! A host artefact that is not a `COSE_Sign1` statement (an audit entry, the
//! accord manifest, an Agent task / deferral / DSAR / external-SQL proof) is
//! signed with ONE composite over [`domain_preimage`]:
//!
//! ```text
//! b"ciris.signing_domain/v1\0"           24 bytes, the framing tag
//! u32le(len(tag)) || tag (UTF-8)          the domain (SigningDomain::tag)
//! message                                 the artefact's own bytes
//! ```
//!
//! The tag is length-framed and the registry is CLOSED ([`SigningDomain`]):
//! a signature made for one domain does not verify as another's, and an
//! unregistered tag is refused by name ([`SIGNING_DOMAIN_UNKNOWN`]) before
//! anything is signed or read. The framing tag keeps these preimages apart
//! from every other byte string a key signs: a COSE `Sig_structure` opens
//! with a CBOR array header, a signed tree head with its own fields.
//!
//! The registry is APPENDED and pinned by position (I2899): a tag is never
//! renamed or reused; a new artefact appends a variant.
//!
//! Hardware: the composite's Ed25519 half signs the composite's fixed-size
//! message representative (127 bytes, `ciris_crypto::composite::REPRESENTATIVE_LEN`),
//! never the message itself, so a single-part PKCS#11 EdDSA token signs a
//! composite over any message length.

use sha2::{Digest as _, Sha256};

use super::composite_verify::{verify_composite_via_directory, CompositeVerifyError, LiveSigner};
use crate::federation::{Error, FederationDirectory};

/// The framing tag every domain preimage opens with.
pub const DOMAIN_PREIMAGE_PREFIX: &[u8] = b"ciris.signing_domain/v1\0";

/// Refusal token: a tag the closed registry does not hold.
pub const SIGNING_DOMAIN_UNKNOWN: &str = "signing_domain_unknown";

/// Refusal token: a retired tag (it keeps its registry position).
pub const SIGNING_DOMAIN_RETIRED: &str = "signing_domain_retired";

/// Refusal token: an accord manifest signed by a key that is not a holder of
/// the genesis bundle in force.
pub const ACCORD_MANIFEST_SIGNER_NOT_HOLDER: &str = "accord_manifest_signer_not_holder";

/// **The closed set of signing domains.** Appended only; each tag is pinned.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub enum SigningDomain {
    /// An audit-chain entry (`audit::verify::entry_signing_preimage`).
    AuditEntry,
    /// The accord manifest, signed by an accord holder
    /// ([`accord_manifest_v2_message`]).
    AccordManifest,
    /// An Agent system-task signature.
    AgentSystemTask,
    /// An Agent deferral resolution.
    AgentDeferralResolution,
    /// An Agent DSAR proof.
    AgentDsarProof,
    /// An Agent external-data SQL proof.
    AgentExternalDataSql,
    /// The Agent's verification-route response.
    AgentVerificationRoute,
    /// An identity template's signature (its signer is an accord holder).
    IdentityTemplate,
    /// An emergency-shutdown command (F0-cp10; ruling: no raw-key
    /// exception): signed by a person's own composite key — the agent's
    /// owner, a Wise Authority or an accord holder (ROOT) — verified by
    /// identity-ref through the directory; the authority is the signer's
    /// standing ([`signer_standing`]), never a key list.
    EmergencyShutdown,
}

impl SigningDomain {
    /// Every domain, in registry order (pinned by position).
    pub const ALL: [Self; 9] = [
        Self::AuditEntry,
        Self::AccordManifest,
        Self::AgentSystemTask,
        Self::AgentDeferralResolution,
        Self::AgentDsarProof,
        Self::AgentExternalDataSql,
        Self::AgentVerificationRoute,
        Self::IdentityTemplate,
        Self::EmergencyShutdown,
    ];

    /// The registry's positions in order, the RETIRED ones included (`None`):
    /// a retired tag keeps its position and is never reused or re-admitted
    /// (I2060).
    pub const POSITIONS: [(&'static str, Option<Self>); 10] = [
        ("ciris.audit_entry.v1", Some(Self::AuditEntry)),
        ("ciris.accord_manifest.v2", Some(Self::AccordManifest)),
        ("ciris.agent.system_task.v1", Some(Self::AgentSystemTask)),
        (
            "ciris.agent.deferral_resolution.v1",
            Some(Self::AgentDeferralResolution),
        ),
        ("ciris.agent.dsar_proof.v1", Some(Self::AgentDsarProof)),
        (
            "ciris.agent.external_data_sql.v1",
            Some(Self::AgentExternalDataSql),
        ),
        (
            "ciris.agent.verification_route.v1",
            Some(Self::AgentVerificationRoute),
        ),
        ("ciris.identity_template.v1", Some(Self::IdentityTemplate)),
        // F0-cp10: RETIRED (the carried-key WA domain, ruled out).
        ("ciris.wa.emergency_shutdown.v1", None),
        ("ciris.emergency_shutdown.v1", Some(Self::EmergencyShutdown)),
    ];

    /// The domain's tag, the bytes framed into its preimage.
    #[must_use]
    pub const fn tag(self) -> &'static str {
        match self {
            Self::AuditEntry => "ciris.audit_entry.v1",
            Self::AccordManifest => "ciris.accord_manifest.v2",
            Self::AgentSystemTask => "ciris.agent.system_task.v1",
            Self::AgentDeferralResolution => "ciris.agent.deferral_resolution.v1",
            Self::AgentDsarProof => "ciris.agent.dsar_proof.v1",
            Self::AgentExternalDataSql => "ciris.agent.external_data_sql.v1",
            Self::AgentVerificationRoute => "ciris.agent.verification_route.v1",
            Self::IdentityTemplate => "ciris.identity_template.v1",
            Self::EmergencyShutdown => "ciris.emergency_shutdown.v1",
        }
    }

    /// The domain a tag names, exactly (one spelling).
    ///
    /// # Errors
    /// [`Error::InvalidArgument`] leading with [`SIGNING_DOMAIN_UNKNOWN`].
    pub fn from_tag(tag: &str) -> Result<Self, Error> {
        if Self::POSITIONS
            .iter()
            .any(|(t, live)| *t == tag && live.is_none())
        {
            return Err(Error::InvalidArgument(format!(
                "{SIGNING_DOMAIN_RETIRED}: {tag:?} is a retired signing domain"
            )));
        }
        Self::ALL
            .into_iter()
            .find(|d| d.tag() == tag)
            .ok_or_else(|| {
                Error::InvalidArgument(format!(
                    "{SIGNING_DOMAIN_UNKNOWN}: {tag:?} is not a registered signing domain"
                ))
            })
    }
}

/// **The bytes a domain's ONE composite is over** (see the module doc).
#[must_use]
pub fn domain_preimage(domain: SigningDomain, message: &[u8]) -> Vec<u8> {
    let tag = domain.tag().as_bytes();
    let mut buf = Vec::with_capacity(DOMAIN_PREIMAGE_PREFIX.len() + 4 + tag.len() + message.len());
    buf.extend_from_slice(DOMAIN_PREIMAGE_PREFIX);
    // A registered tag is a short literal: its length fits a u32.
    buf.extend_from_slice(&(tag.len() as u32).to_le_bytes());
    buf.extend_from_slice(tag);
    buf.extend_from_slice(message);
    buf
}

/// **Verify a domain's composite under the live edition-2 key of
/// `identity_ref`** at `at_ms`: [`verify_composite_via_directory`] over
/// [`domain_preimage`]. It asks about the signer's key only; a role the
/// artefact needs (a holder, a seat) is the caller's, or a domain verify
/// that names it ([`verify_accord_manifest_v2`]).
///
/// # Errors
/// [`CompositeVerifyError`], each by its token.
#[allow(clippy::result_large_err)] // the error type is composite_verify's
pub async fn verify_domain_composite_via_directory<F>(
    dir: &F,
    domain: SigningDomain,
    message: &[u8],
    identity_ref: &str,
    composite_sig: &[u8],
    at_ms: u64,
) -> Result<LiveSigner, CompositeVerifyError>
where
    F: FederationDirectory + ?Sized,
{
    verify_composite_via_directory(
        dir,
        &domain_preimage(domain, message),
        identity_ref,
        composite_sig,
        at_ms,
    )
    .await
}

/// v62.0.0 (CE-fix1) — **verify a domain's composite under a key in hand**:
/// ONE composite over [`domain_preimage`]`(domain, message)` under `key`.
/// Pure: no directory, no clock.
///
/// **A self-check before a bundle exists, and nothing else.** The offline
/// ceremony (`crate::ceremony`) checks a holder's manifest signature under
/// the composite key of the holder's own `key:record` before any node holds
/// it. A HOST DECISION (an emergency shutdown, a manifest the Agent boots
/// on, any authority) must resolve the signer through the directory:
/// [`verify_domain_composite_via_directory`], [`verify_accord_manifest_v2`]
/// (the holder check). A raw-key verify is not a host authority path
/// (ruling, Eric): this stays Rust-only, with no PyO3 verb and no capsule op.
///
/// # Errors
/// [`Error::SignatureInvalid`] leading with `verify_composite_invalid`.
pub fn verify_domain_composite(
    key: &ciris_crypto::composite::CompositePublicKey,
    domain: SigningDomain,
    message: &[u8],
    composite_sig: &[u8],
) -> Result<(), Error> {
    key.verify(&domain_preimage(domain, message), composite_sig)
        .map_err(|e| {
            Error::SignatureInvalid(format!(
                "{}: the composite signature does not verify under the given key in domain \
                 {}: {e}",
                super::composite_verify::VERIFY_COMPOSITE_INVALID,
                domain.tag()
            ))
        })
}

/// **The accord manifest's signed message (v2)**: the 32-byte SHA-256 of the
/// RFC 8785 (JCS) image of
/// `{"domain": "ciris.accord_manifest.v2", "manifest_sha256": <hex>,
/// "manifest_size": <bytes>, "signer_identity": <the holder's identity-ref>}`.
/// The holder signs [`domain_preimage`]`(AccordManifest, this)`: 24 + 4 + 24 +
/// 32 = 84 bytes.
///
/// # Errors
/// [`Error::InvalidArgument`] for a `manifest_sha256` that is not 64 lowercase
/// hex characters, or an empty `signer_identity`.
pub fn accord_manifest_v2_message(
    manifest_sha256_hex: &str,
    manifest_size: u64,
    signer_identity: &str,
) -> Result<[u8; 32], Error> {
    let hex_ok = manifest_sha256_hex.len() == 64
        && manifest_sha256_hex
            .bytes()
            .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b));
    if !hex_ok {
        return Err(Error::InvalidArgument(
            "accord manifest: manifest_sha256 must be 64 lowercase hex characters".into(),
        ));
    }
    if signer_identity.is_empty() {
        return Err(Error::InvalidArgument(
            "accord manifest: signer_identity is empty".into(),
        ));
    }
    let statement = serde_json::json!({
        "domain": SigningDomain::AccordManifest.tag(),
        "manifest_sha256": manifest_sha256_hex,
        "manifest_size": manifest_size,
        "signer_identity": signer_identity,
    });
    let jcs = crate::verify::canonical::ceg_produce_canonicalize(&statement)
        .map_err(|e| Error::InvalidArgument(format!("accord manifest canonicalize: {e}")))?;
    Ok(Sha256::digest(&jcs).into())
}

/// **Verify an accord manifest signature (v2)**: `signer_identity` must be a
/// holder of the genesis bundle in force
/// ([`GenesisInForce::is_holder`](super::genesis::GenesisInForce::is_holder)),
/// and `composite_sig` ONE composite over
/// [`domain_preimage`]`(AccordManifest, `[`accord_manifest_v2_message`]`)`
/// under that holder's live edition-2 key at `at_ms`. The holder check is
/// here, in the verify: the manifest's authority is the role.
///
/// # Errors
/// [`Error::InvalidArgument`] for a malformed statement;
/// [`Error::MalformedRow`] leading with [`ACCORD_MANIFEST_SIGNER_NOT_HOLDER`]
/// for a signer that is not a holder; a composite refusal as
/// [`Error::SignatureInvalid`] leading with its token; a directory failure as
/// itself.
pub async fn verify_accord_manifest_v2<F>(
    dir: &F,
    manifest_sha256_hex: &str,
    manifest_size: u64,
    signer_identity: &str,
    composite_sig: &[u8],
    at_ms: u64,
) -> Result<(), Error>
where
    F: FederationDirectory + ?Sized,
{
    let message = accord_manifest_v2_message(manifest_sha256_hex, manifest_size, signer_identity)?;
    let in_force = super::genesis::genesis_in_force(dir).await?;
    if !in_force.is_holder(signer_identity) {
        return Err(Error::malformed_row(
            "accord_manifest",
            ACCORD_MANIFEST_SIGNER_NOT_HOLDER,
            format!(
                "{signer_identity} is not an accord holder of the genesis bundle in force; \
                 the accord manifest is signed by a holder"
            ),
        ));
    }
    match verify_domain_composite_via_directory(
        dir,
        SigningDomain::AccordManifest,
        &message,
        signer_identity,
        composite_sig,
        at_ms,
    )
    .await
    {
        Ok(_) => Ok(()),
        Err(CompositeVerifyError::Directory(e)) => Err(e),
        Err(e) => Err(Error::SignatureInvalid(e.to_string())),
    }
}

/// v62.0.0 (BH-fix3) — the length of an identity template's statement
/// digest, the message its holder signs.
pub const IDENTITY_TEMPLATE_DIGEST_LEN: usize = 32;

/// v62.0.0 (BH-fix3) — **an identity template's signed message (v1)**,
/// [`accord_manifest_v2_message`]'s twin in the identity-template domain: the
/// 32-byte SHA-256 of the RFC 8785 (JCS) image of
/// `{"domain": "ciris.identity_template.v1", "manifest_sha256": <hex>,
/// "manifest_size": <bytes>, "signer_identity": <the holder's identity-ref>}`.
/// The holder signs [`domain_preimage`]`(IdentityTemplate, this)`, which is
/// 24 + 4 + 26 + 32 = 86 bytes. The Agent may compute the message itself;
/// this is the reference.
///
/// # Errors
/// [`Error::InvalidArgument`] for a `manifest_sha256` that is not 64 lowercase
/// hex characters, or an empty `signer_identity`.
pub fn identity_template_v1_message(
    manifest_sha256_hex: &str,
    manifest_size: u64,
    signer_identity: &str,
) -> Result<[u8; 32], Error> {
    let hex_ok = manifest_sha256_hex.len() == 64
        && manifest_sha256_hex
            .bytes()
            .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b));
    if !hex_ok {
        return Err(Error::InvalidArgument(
            "identity template: manifest_sha256 must be 64 lowercase hex characters".into(),
        ));
    }
    if signer_identity.is_empty() {
        return Err(Error::InvalidArgument(
            "identity template: signer_identity is empty".into(),
        ));
    }
    let statement = serde_json::json!({
        "domain": SigningDomain::IdentityTemplate.tag(),
        "manifest_sha256": manifest_sha256_hex,
        "manifest_size": manifest_size,
        "signer_identity": signer_identity,
    });
    let jcs = crate::verify::canonical::ceg_produce_canonicalize(&statement)
        .map_err(|e| Error::InvalidArgument(format!("identity template canonicalize: {e}")))?;
    Ok(Sha256::digest(&jcs).into())
}

/// v62.0.0 (BH-fix3) — **verify an identity template signature (v1)**, as
/// [`verify_accord_manifest_v2`] verifies the accord manifest: the message is
/// the caller's 32-byte statement digest ([`identity_template_v1_message`]);
/// `signer_identity` must be a holder of the genesis bundle in force
/// ([`GenesisInForce::is_holder`](super::genesis::GenesisInForce::is_holder)),
/// checked HERE, in the verify; and `composite_sig` must be ONE composite over
/// [`domain_preimage`]`(IdentityTemplate, digest)` under that holder's live
/// edition-2 key at `at_ms`, resolved by identity-ref through the directory.
/// The tokens are the accord manifest's.
///
/// # Errors
/// [`Error::InvalidArgument`] for a digest that is not
/// [`IDENTITY_TEMPLATE_DIGEST_LEN`] bytes or an empty signer;
/// [`Error::MalformedRow`] leading with [`ACCORD_MANIFEST_SIGNER_NOT_HOLDER`]
/// (plane `identity_template`) for a signer that is not a holder; a composite
/// refusal (another domain's signature, another signer's, other bytes) as
/// [`Error::SignatureInvalid`] leading with its token; a directory failure as
/// itself.
pub async fn verify_identity_template_v1<F>(
    dir: &F,
    statement_digest: &[u8],
    signer_identity: &str,
    composite_sig: &[u8],
    at_ms: u64,
) -> Result<(), Error>
where
    F: FederationDirectory + ?Sized,
{
    if statement_digest.len() != IDENTITY_TEMPLATE_DIGEST_LEN {
        return Err(Error::InvalidArgument(format!(
            "identity template: the statement digest must be {IDENTITY_TEMPLATE_DIGEST_LEN} \
             bytes, got {}",
            statement_digest.len()
        )));
    }
    if signer_identity.is_empty() {
        return Err(Error::InvalidArgument(
            "identity template: signer_identity is empty".into(),
        ));
    }
    let in_force = super::genesis::genesis_in_force(dir).await?;
    if !in_force.is_holder(signer_identity) {
        return Err(Error::malformed_row(
            "identity_template",
            ACCORD_MANIFEST_SIGNER_NOT_HOLDER,
            format!(
                "{signer_identity} is not an accord holder of the genesis bundle in force; \
                 an identity template is signed by a holder"
            ),
        ));
    }
    match verify_domain_composite_via_directory(
        dir,
        SigningDomain::IdentityTemplate,
        statement_digest,
        signer_identity,
        composite_sig,
        at_ms,
    )
    .await
    {
        Ok(_) => Ok(()),
        Err(CompositeVerifyError::Directory(e)) => Err(e),
        Err(e) => Err(Error::SignatureInvalid(e.to_string())),
    }
}

/// v62.0.0 (F0-cp10; ruling: authority from standing, not a key list) —
/// **what standing a signer has over an agent**, the check an emergency
/// shutdown needs after its composite verifies
/// ([`verify_domain_composite_via_directory`] in
/// [`SigningDomain::EmergencyShutdown`]).
#[derive(Clone, Copy, Debug, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum SignerStanding {
    /// An accord holder of the genesis bundle in force.
    Root,
    /// A Wise Authority: an ACTIVE member of the named WA body (a family,
    /// the conferred seat) whose record also carries the `wise_authority`
    /// card (CC 4.3). The card alone is self-declared at registration
    /// (`ConferralMode::DerivedFromVerifiedState`) and confers nothing.
    WiseAuthority,
    /// The agent's one counted owner.
    Owner,
    /// None of the above.
    None,
}

impl SignerStanding {
    /// The wire token.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Root => "root",
            Self::WiseAuthority => "wise_authority",
            Self::Owner => "owner",
            Self::None => "none",
        }
    }
}

/// **The signer's standing over `agent_ref`, at `at_ms`** — built on the
/// existing reads, no new rule, first match wins:
///
/// 1. [`SignerStanding::Root`] — `identity_ref` is a holder of the genesis
///    bundle in force
///    ([`genesis_in_force`](super::genesis::genesis_in_force) +
///    [`GenesisInForce::is_holder`](super::genesis::GenesisInForce::is_holder));
/// 2. [`SignerStanding::WiseAuthority`] — `wa_body` names a WA body (a family;
///    never the accord's own roster), `identity_ref` is one of its ACTIVE
///    members ([`FederationDirectory::active_family_members`], the conferred
///    seat), and its key read model carries the `wise_authority` card
///    ([`FederationDirectory::lookup_public_key`]): the same two reads
///    ownership reclaim counts a WA by (`ownership_reclaim::wa_quorum_over_body`).
///    With no `wa_body`, nobody is a Wise Authority: the card is self-declared
///    at registration and is never standing by itself;
/// 3. [`SignerStanding::Owner`] — `identity_ref` is the agent's one counted
///    owner ([`agent_owner_of`](crate::federation::admission::agent_owner_of)
///    at `at_ms`); two counted owners resolve fail-closed to no owner;
/// 4. [`SignerStanding::None`].
///
/// It reads standing only: the caller verifies the signature first.
///
/// # Errors
/// Directory reads.
pub async fn signer_standing<F>(
    dir: &F,
    identity_ref: &str,
    agent_ref: &str,
    wa_body: Option<&str>,
    at_ms: u64,
) -> Result<SignerStanding, Error>
where
    F: FederationDirectory + ?Sized,
{
    use crate::federation::types::identity_type;
    if super::genesis::genesis_in_force(dir)
        .await?
        .is_holder(identity_ref)
    {
        return Ok(SignerStanding::Root);
    }
    if let Some(body) = wa_body.filter(|b| {
        !b.trim().is_empty()
            && *b != ciris_verify_core::accord_genesis::HUMANITY_ACCORD_FAMILY_KEY_ID
    }) {
        let seated = match dir.active_family_members(body).await {
            Ok(members) => members.iter().any(|m| m.key_id == identity_ref),
            Err(e) => return Err(e),
        };
        if seated {
            if let Some(rec) = dir.lookup_public_key(identity_ref).await? {
                if identity_type::set_contains(&rec.identity_type, identity_type::WISE_AUTHORITY) {
                    return Ok(SignerStanding::WiseAuthority);
                }
            }
        }
    }
    match crate::federation::admission::agent_owner_of(dir, agent_ref, at_ms).await {
        Ok(Some(owner)) if owner == identity_ref => Ok(SignerStanding::Owner),
        Ok(_) | Err(Error::AmbiguousNodeOwner { .. }) => Ok(SignerStanding::None),
        Err(e) => Err(e),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// **I2124 (BH-fix3) — the identity template's preimage, pinned byte for
    /// byte**: the framing tag, `u32le(26)`, the tag
    /// `ciris.identity_template.v1`, then the 32-byte statement digest (86
    /// bytes); its message differs from the accord manifest's over the same
    /// members (the `domain` member), and a malformed member is refused.
    #[test]
    fn i2124_the_identity_template_preimage_is_pinned() {
        let digest = [0x11u8; 32];
        let pre = domain_preimage(SigningDomain::IdentityTemplate, &digest);
        let mut want = b"ciris.signing_domain/v1\0".to_vec();
        want.extend_from_slice(&26u32.to_le_bytes());
        want.extend_from_slice(b"ciris.identity_template.v1");
        want.extend_from_slice(&digest);
        assert_eq!(pre, want, "I2124: the framing");
        assert_eq!(pre.len(), 86, "I2124: 24 + 4 + 26 + 32");
        assert_eq!(
            SigningDomain::from_tag("ciris.identity_template.v1").unwrap(),
            SigningDomain::IdentityTemplate,
            "I2124: the registered tag"
        );
        let hex = "ab".repeat(32);
        let m = identity_template_v1_message(&hex, 10, "urn:x").unwrap();
        let mut members =
            b"{\"domain\":\"ciris.identity_template.v1\",\"manifest_sha256\":\"".to_vec();
        members.extend_from_slice(hex.as_bytes());
        members.extend_from_slice(b"\",\"manifest_size\":10,\"signer_identity\":\"urn:x\"}");
        let expect: [u8; 32] = <Sha256 as sha2::Digest>::digest(&members).into();
        assert_eq!(m, expect, "I2124: sha256 over the JCS of the four members");
        assert_ne!(
            m,
            accord_manifest_v2_message(&hex, 10, "urn:x").unwrap(),
            "I2124: the domain member separates the two messages"
        );
        assert!(identity_template_v1_message("AB", 10, "urn:x").is_err());
        assert!(identity_template_v1_message(&hex, 10, "").is_err());
    }

    /// **I2899 (the registry leg) — the closed set, pinned by position, one
    /// spelling per tag; the framing is exact.**
    #[test]
    fn i2899_the_signing_domain_registry_is_closed_and_pinned() {
        let tags: Vec<&str> = SigningDomain::ALL.iter().map(|d| d.tag()).collect();
        assert_eq!(
            tags,
            [
                "ciris.audit_entry.v1",
                "ciris.accord_manifest.v2",
                "ciris.agent.system_task.v1",
                "ciris.agent.deferral_resolution.v1",
                "ciris.agent.dsar_proof.v1",
                "ciris.agent.external_data_sql.v1",
                "ciris.agent.verification_route.v1",
                "ciris.identity_template.v1",
                "ciris.emergency_shutdown.v1",
            ],
            "I2899: appended only, pinned by position"
        );
        for d in SigningDomain::ALL {
            assert_eq!(SigningDomain::from_tag(d.tag()).unwrap(), d, "I2899");
        }
        for bad in ["", "ciris.audit_entry.V1", "ciris.audit_entry.v1 ", "x"] {
            match SigningDomain::from_tag(bad) {
                Err(Error::InvalidArgument(m)) => {
                    assert!(m.starts_with(SIGNING_DOMAIN_UNKNOWN), "I2899 {bad:?}: {m}");
                }
                other => panic!("I2899 {bad:?}: refused by name, got {other:?}"),
            }
        }
        let pre = domain_preimage(SigningDomain::AuditEntry, b"m");
        let mut want = b"ciris.signing_domain/v1\0".to_vec();
        want.extend_from_slice(&20u32.to_le_bytes());
        want.extend_from_slice(b"ciris.audit_entry.v1");
        want.extend_from_slice(b"m");
        assert_eq!(pre, want, "I2899: the framing");
        assert_ne!(
            domain_preimage(SigningDomain::AgentSystemTask, b"m"),
            domain_preimage(SigningDomain::AgentDsarProof, b"m"),
            "I2899: two domains, two preimages"
        );
        let msg = accord_manifest_v2_message(&"ab".repeat(32), 10, "urn:x").unwrap();
        assert_eq!(
            domain_preimage(SigningDomain::AccordManifest, &msg).len(),
            84,
            "I2899: the accord manifest preimage stays small"
        );
        assert!(accord_manifest_v2_message("AB", 10, "urn:x").is_err());

        // I2060 — the registry's positions, the retired one included, pinned.
        let positions: Vec<(&str, bool)> = SigningDomain::POSITIONS
            .iter()
            .map(|(t, live)| (*t, live.is_some()))
            .collect();
        assert_eq!(
            positions,
            [
                ("ciris.audit_entry.v1", true),
                ("ciris.accord_manifest.v2", true),
                ("ciris.agent.system_task.v1", true),
                ("ciris.agent.deferral_resolution.v1", true),
                ("ciris.agent.dsar_proof.v1", true),
                ("ciris.agent.external_data_sql.v1", true),
                ("ciris.agent.verification_route.v1", true),
                ("ciris.identity_template.v1", true),
                ("ciris.wa.emergency_shutdown.v1", false),
                ("ciris.emergency_shutdown.v1", true),
            ],
            "I2060: appended only, a retired position kept, never reused"
        );
        for (t, live) in SigningDomain::POSITIONS {
            if let Some(d) = live {
                assert_eq!(d.tag(), t, "I2060: the position names its tag");
            }
        }
        assert_eq!(
            SigningDomain::POSITIONS
                .iter()
                .filter(|(_, l)| l.is_some())
                .count(),
            SigningDomain::ALL.len(),
            "I2060: every live domain has one position"
        );
        match SigningDomain::from_tag("ciris.wa.emergency_shutdown.v1") {
            Err(Error::InvalidArgument(m)) => {
                assert!(m.starts_with(SIGNING_DOMAIN_RETIRED), "I2060: {m}");
            }
            other => panic!("I2060: a retired tag is refused by name: {other:?}"),
        }
    }
}
