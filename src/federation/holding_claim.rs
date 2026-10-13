//! v55.0.0 (CIRISPersist#989, CC 3.1.3.3 / 2.4 / 5.3.2.1, CIRISConstitution#141)
//! — **the ONE holding claim.**
//!
//! `custody:ack:v1` with `custody_state: here` is the holding claim of the
//! mesh at every tier. It replaces the retired `holds_bytes:sha256:{prefix}`
//! carrier, which was a second holding claim with its audience hard-coded to
//! `federation`, so community content advertised its existence to everyone
//! and the bytes-plane fold had to exclude it by type (CC 2.4).
//!
//! CC 3.1.3.3's five rules, and where each lives:
//!
//! 1. **Scope is the content's.** A claim is placed at the `cohort_scope` of
//!    the blob it is about: `federation` for Commons-tier content (plaintext,
//!    which includes `public` and `infrastructure` rooms), the bytes' own
//!    `self` / `family` / `community` / `affiliations` cohort otherwise.
//!    [`ClaimScope::of_content`] is the one derivation, and every door that
//!    emits a claim takes the scope from the content it stores, never from a
//!    caller. The admission gate refuses a claim whose scope is not its
//!    content's ([`check_holding_claim_scope`]) wherever this node holds the
//!    content.
//! 2. **Audience follows from the one rule** (CC 6.1.5.3): the claim is a row
//!    at the content's scope, so replication delivers it exactly as any row
//!    at that scope. At `federation` the `here` rows ARE the holder directory
//!    ([`live_holders`]).
//! 3. **Never a content binding.** `envelope_binds_content` excludes the
//!    `custody:` family; the bytes-plane fold reads liveness from the
//!    content's own rows only.
//! 4. **Retracted by its signer alone** — a later `none`, or the signer's own
//!    `withdraws` ([`check_custody_withdraws_signer`](super::custody_ack::check_custody_withdraws_signer)).
//! 5. **Freshness is the row's.** A claim carries `expires_at` = its signed
//!    instant + 72 h ([`CUSTODY_LIVE_SECS`]); no second TTL exists.
//!
//! # Emission
//!
//! [`emit_holding_claim`] announces a claim for a row this node ALREADY
//! stores, through [`BlobStorage::put_holding_claim`]. The write doors that
//! store and announce in one transaction (`put_blob_with_scope`,
//! `adopt_sealed_blob_at`) rebuild the same row through
//! [`prepare_holding_claim_row`]. Either way the row is
//! [`holding_claim_row`], signed by [`sign_holding_claim`], admitted through
//! the custody gate (audience at a bounded scope).
//!
//! # Legacy `holds_bytes` rows
//!
//! A `holds_bytes:sha256:{prefix}` row a node already holds is, per CC 2.4,
//! "reported to the operator, … neither served nor replicated, and … not
//! deleted": it stays stored, `row_type_report` counts it, the serve reads
//! leave it out, and no fold reads it. Its 24 h freshness lapsed with the
//! carrier; nothing re-emits it (CIRISPersist#989 item 4). A new one is
//! refused `attestation_type_unregistered` at every door, whatever the
//! row-type enforcement mode
//! ([`registry::RETIRED_CARRIER_STEMS`](super::namespace::registry::RETIRED_CARRIER_STEMS)).

use chrono::{DateTime, Utc};

use super::attestation_query::{AttestationQuery, FOLD_PAGE};
use super::custody_ack::{
    custody_ack_envelope, parse_custody_ack, CustodyState, CUSTODY_ACK_DIMENSION, CUSTODY_LIVE_SECS,
};
use super::types::cohort_scope::{self as cs, CryptoTier};
use super::{Attestation, BlobError, BlobStorage, Error, FederationDirectory, PutBlobAttestation};

/// **Where a holding claim is placed** (CC 3.1.3.3 rule 1): the content's
/// cohort, as the claim's `cohort_scope` and the cohort target its envelope
/// names (`family_key_id` for a family, `community_id` for a room, none for
/// `self` and the commons).
///
/// Constructed only from the content ([`Self::of_content`]); no door takes a
/// claim scope from a caller.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ClaimScope {
    cohort_scope: String,
    target: Option<String>,
}

impl ClaimScope {
    /// **The one derivation.** `tier` is the tier the content is stored at
    /// (the row's resolved tier), `cohort_scope` the cohort the write named,
    /// `group` the group it named (the owner for `self`, the family, the
    /// room).
    ///
    /// - [`CryptoTier::Plaintext`] — the Commons tier, which is the commons
    ///   scopes AND the plaintext rooms (`public`, `infrastructure`): the
    ///   claim is at `federation` with no target. "There is nothing to hide
    ///   at this tier" (CC 3.2).
    /// - a sealed tier — the content's own cohort, with its group as the
    ///   target. `self` names none (a self report is about the device's own
    ///   principal); `family`, `community` and `affiliations` must name it.
    ///
    /// # Errors
    ///
    /// [`BlobError::InvalidArgument`] `holding_claim_scope_unresolved` when a
    /// sealed family or room content names no group, or the cohort is not a
    /// sealed one.
    pub fn of_content(
        tier: CryptoTier,
        cohort_scope: &str,
        group: Option<&str>,
    ) -> Result<Self, BlobError> {
        if tier == CryptoTier::Plaintext {
            return Ok(Self {
                cohort_scope: cs::FEDERATION.to_owned(),
                target: None,
            });
        }
        let group = group.filter(|g| !g.is_empty());
        match (cohort_scope, group) {
            (cs::SELF, _) => Ok(Self {
                cohort_scope: cs::SELF.to_owned(),
                target: None,
            }),
            (cs::FAMILY | cs::COMMUNITY | cs::AFFILIATIONS, Some(g)) => Ok(Self {
                cohort_scope: cohort_scope.to_owned(),
                target: Some(g.to_owned()),
            }),
            (cs::FAMILY | cs::COMMUNITY | cs::AFFILIATIONS, None) => {
                Err(BlobError::InvalidArgument(format!(
                    "{HOLDING_CLAIM_SCOPE_UNRESOLVED}: {cohort_scope} content at the {tier:?} tier \
                     names no {cohort_scope}, so its holding claim has no cohort to be placed at \
                     (CC 3.1.3.3 rule 1: the claim is at the content's scope)"
                )))
            }
            _ => Err(BlobError::InvalidArgument(format!(
                "{HOLDING_CLAIM_SCOPE_UNRESOLVED}: {cohort_scope:?} content at the sealed {tier:?} \
                 tier — a sealed blob is self, family, community or affiliations content"
            ))),
        }
    }

    /// The claim's `cohort_scope`.
    #[must_use]
    pub fn cohort_scope(&self) -> &str {
        &self.cohort_scope
    }

    /// The cohort the claim's envelope names, if any.
    #[must_use]
    pub fn target(&self) -> Option<&str> {
        self.target.as_deref()
    }

    /// Is this the holder directory scope (`federation`)?
    #[must_use]
    pub fn is_directory(&self) -> bool {
        self.cohort_scope == cs::FEDERATION
    }

    /// The scope a stored claim row is placed at: its `cohort_scope` and the
    /// cohort target its envelope names.
    ///
    /// # Errors
    ///
    /// The envelope's cohort-target aliases disagree.
    pub fn of_row(row: &Attestation) -> Result<Self, Error> {
        Ok(Self {
            cohort_scope: row.cohort_scope.clone(),
            target: super::admission::envelope_cohort_target(&row.attestation_envelope)?
                .map(str::to_owned),
        })
    }
}

/// Refusal token: the content names no group for its holding claim.
pub const HOLDING_CLAIM_SCOPE_UNRESOLVED: &str = "holding_claim_scope_unresolved";

/// Refusal token (CC 3.1.3.3 rule 1): a holding claim placed at a scope that
/// is not its content's, judged where this node holds the content.
pub const CUSTODY_ACK_SCOPE_MISMATCH: &str = "custody_ack_scope_mismatch";

/// **The ONE definition of a holding-claim row**, ready to sign: a `scores`
/// row on [`CUSTODY_ACK_DIMENSION`], `custody_state: here`, attested by and
/// about `holder`, citing the blob's full digest in `evidence_refs`, carrying
/// its `size`, placed at `scope`, with `expires_at` = the truncated signed
/// instant + [`CUSTODY_LIVE_SECS`] (CC 3.1.3.3 rule 5). The scrub fields are
/// blank for whoever fills them.
///
/// A pure function of its inputs, so the door that stores the claim REBUILDS
/// these bytes and checks the caller signed them
/// ([`prepare_holding_claim_row`]) — the party that mints the bytes stamps,
/// the party that receives them checks.
///
/// # Errors
///
/// [`BlobError::InvalidArgument`] when `size` is zero (CC 5.3.2.5: every blob
/// carries its size) or `scope` cannot carry a custody report.
pub fn holding_claim_row(
    sha256: &[u8; 32],
    holder_key_id: &str,
    attestation_id: &str,
    asserted_at: DateTime<Utc>,
    size: u64,
    scope: &ClaimScope,
) -> Result<Attestation, BlobError> {
    if size == 0 {
        return Err(BlobError::InvalidArgument(
            "holding claim: size must be the positive byte length of the blob (CC 5.3.2.5: \
             every blob carries its size, checked first)"
                .into(),
        ));
    }
    let envelope = custody_ack_envelope(
        sha256,
        CustodyState::Here,
        Some(size),
        scope.cohort_scope(),
        scope.target(),
    )
    .map_err(|e| BlobError::InvalidArgument(e.to_string()))?;
    let asserted_at = super::admission::truncate_to_substrate_resolution(asserted_at);
    let mut row = Attestation {
        attestation_id: attestation_id.to_owned(),
        attesting_key_id: holder_key_id.to_owned(),
        // A holder self-report: the device the claim is about signs it.
        attested_key_id: holder_key_id.to_owned(),
        attestation_type: super::types::attestation_type::SCORES.to_owned(),
        weight: None,
        asserted_at,
        expires_at: Some(asserted_at + chrono::Duration::seconds(CUSTODY_LIVE_SECS)),
        attestation_envelope: envelope,
        original_content_hash: String::new(),
        scrub_signature_classical: String::new(),
        scrub_signature_pqc: None,
        scrub_key_id: String::new(),
        scrub_timestamp: asserted_at,
        pqc_completed_at: None,
        persist_row_hash: String::new(),
        subject_key_ids: Vec::new(),
        withdraws_admission_rule: None,
        cohort_scope: scope.cohort_scope().to_owned(),
        // Stated, never defaulted (#652): the claim rides the federation
        // plane, and its cohort_scope decides who receives it.
        tier: super::types::attestation_tier::FEDERATION.to_owned(),
        promoted_at: None,
        additional_scrubs: Vec::new(),
    };
    super::envelope::stamp_signed_instants(&mut row)
        .map_err(|e| BlobError::Backend(format!("holding claim instants: {e}")))?;
    super::envelope::RowMirror::stamp_row(&mut row)
        .map_err(|e| BlobError::Backend(format!("holding claim mirror: {e}")))?;
    Ok(row)
}

/// **Sign a holding claim** for `sha256` at `scope` as this node: the
/// [`holding_claim_row`] envelope, the produce-side canonicalizer, the
/// signer's DERIVED key id as attester and `scrub_key_id` (I23).
///
/// HYBRID/PQC ONLY (CIRISPersist#851 §20.5): a claim rides the federation
/// plane and every peer's ingest gate demands both halves, so a `local` with
/// no ML-DSA-65 key refuses here rather than producing a claim no peer will
/// admit.
///
/// # Errors
///
/// [`BlobError::AttestationEmissionFailed`] when `local` has no PQC half;
/// [`BlobError::InvalidArgument`] as [`holding_claim_row`].
pub async fn sign_holding_claim(
    local: &crate::signing::LocalSigner,
    sha256: &[u8; 32],
    attestation_id: uuid::Uuid,
    now: DateTime<Utc>,
    size: u64,
    scope: &ClaimScope,
) -> Result<PutBlobAttestation, BlobError> {
    use base64::engine::general_purpose::STANDARD as B64;
    use base64::Engine as _;
    use sha2::{Digest, Sha256};

    let holder = local.derived_key_id();
    let row = holding_claim_row(
        sha256,
        &holder,
        &attestation_id.to_string(),
        now,
        size,
        scope,
    )?;
    let canonical = crate::verify::canonical::ceg_produce_canonicalize(&row.attestation_envelope)
        .map_err(|e| {
        BlobError::InvalidArgument(format!("canonicalize holding claim envelope: {e}"))
    })?;
    let original_content_hash_hex = hex::encode(Sha256::digest(&canonical));
    let sig = local.sign_hybrid(&canonical).await.map_err(|e| {
        BlobError::AttestationEmissionFailed(match e {
            crate::signing::LocalSignerError::PqcNotConfigured => format!(
                "hybrid-only: {holder} has no ML-DSA-65 key, so it cannot sign a holding claim; \
                 a classical-only producer does not announce (CIRISPersist#851 §20.5 / CC \
                 5.3.2.4.3.1)"
            ),
            other => format!("sign_hybrid: {other}"),
        })
    })?;
    Ok(PutBlobAttestation {
        attesting_key_id: holder.clone(),
        attestation_id: attestation_id.to_string(),
        size,
        original_content_hash_hex,
        scrub_signature_classical: B64.encode(&sig.classical.signature),
        scrub_signature_pqc: Some(B64.encode(&sig.pqc.signature)),
        scrub_key_id: holder,
        scrub_timestamp: row.asserted_at,
        asserted_at: row.asserted_at,
    })
}

/// A holding-claim row a backend inserts verbatim: the admitted row plus the
/// two serialized columns both dialects store beside it.
#[derive(Debug, Clone)]
pub struct PreparedHoldingClaim {
    /// The admitted row, every column populated.
    pub row: Attestation,
    /// `attestation_envelope` as stored (JSON text).
    pub envelope_text: String,
    /// `original_content_hash` decoded from the caller's hex.
    pub original_content_hash: Vec<u8>,
}

/// **Rebuild and ADMIT the holding claim** for `sha256` at `scope` from the
/// caller's signed components: rebuild the row ([`holding_claim_row`]),
/// copy the caller's scrub in, run the door's own gates (the future-skew
/// bound, and the caller's hash covering the bytes persist rebuilt —
/// [`super::blobs::check_put_blob_admission`]), parse it back as a custody
/// report, and stamp the row hash. Refuses before anything is written.
///
/// The audience half of the custody gate needs the directory and is asked
/// by the async caller ([`check_holding_claim_audience`]).
///
/// # Errors
///
/// As [`holding_claim_row`] and `check_put_blob_admission`.
#[cfg(any(feature = "postgres", feature = "sqlite"))]
pub(crate) fn prepare_holding_claim_row(
    sha256: &[u8; 32],
    claim: &PutBlobAttestation,
    scope: &ClaimScope,
) -> Result<PreparedHoldingClaim, BlobError> {
    let original_content_hash = hex::decode(&claim.original_content_hash_hex).map_err(|e| {
        BlobError::InvalidArgument(format!("original_content_hash hex decode: {e}"))
    })?;
    let mut row = holding_claim_row(
        sha256,
        &claim.attesting_key_id,
        &claim.attestation_id,
        claim.asserted_at,
        claim.size,
        scope,
    )?;
    row.original_content_hash = claim.original_content_hash_hex.clone();
    row.scrub_signature_classical = claim.scrub_signature_classical.clone();
    row.scrub_signature_pqc = claim.scrub_signature_pqc.clone();
    row.scrub_key_id = claim.scrub_key_id.clone();
    row.scrub_timestamp = claim.scrub_timestamp;
    super::blobs::check_put_blob_admission(&row, &claim.original_content_hash_hex, Utc::now())?;
    parse_custody_ack(&row)
        .map_err(|e| BlobError::InvalidArgument(e.to_string()))?
        .ok_or_else(|| {
            BlobError::Backend("holding claim row did not parse as a custody report".into())
        })?;
    row.persist_row_hash = super::types::compute_persist_row_hash(&row)
        .map_err(|e| BlobError::Backend(format!("persist_row_hash: {e}")))?;
    let envelope_text = serde_json::to_string(&row.attestation_envelope)
        .map_err(|e| BlobError::Backend(format!("envelope serialize: {e}")))?;
    Ok(PreparedHoldingClaim {
        row,
        envelope_text,
        original_content_hash,
    })
}

/// **The pre-transaction half of `BlobStorage::put_holding_claim`**, shared by
/// both backends: the scope must be the stored content's
/// (`custody_ack_scope_mismatch`), the claim's size the stored length (AV-89),
/// the row rebuilt and admitted ([`prepare_holding_claim_row`]) and the holder
/// in the cohort ([`check_holding_claim_audience`]). Returns the prepared row
/// for the backend's transaction, which re-checks the row is still held.
///
/// # Errors
///
/// [`BlobError::NotHeld`] when nothing is held; the refusals above.
#[cfg(any(feature = "postgres", feature = "sqlite"))]
pub(crate) async fn prepare_announcement<B>(
    backend: &B,
    sha256: &[u8; 32],
    claim: &PutBlobAttestation,
    scope: &ClaimScope,
) -> Result<PreparedHoldingClaim, BlobError>
where
    B: BlobStorage + FederationDirectory + Sync,
{
    let not_held = || BlobError::NotHeld {
        sha256_hex: hex::encode(sha256),
    };
    let want = content_claim_scope(backend, sha256)
        .await?
        .ok_or_else(not_held)?;
    if &want != scope {
        return Err(BlobError::InvalidArgument(format!(
            "{CUSTODY_ACK_SCOPE_MISMATCH}: a holding claim about {} at {} {:?}, but the stored \
             content is at {} {:?} (CC 3.1.3.3 rule 1)",
            hex::encode(sha256),
            scope.cohort_scope,
            scope.target,
            want.cohort_scope,
            want.target
        )));
    }
    let size = backend
        .blob_head(sha256)
        .await?
        .ok_or_else(not_held)?
        .size_bytes;
    if claim.size != size {
        return Err(BlobError::InvalidArgument(format!(
            "holding claim declares size {} but the stored bytes are {size} (CC 5.3.2.5 / AV-89: \
             a holder announces exactly what it holds)",
            claim.size
        )));
    }
    let prepared = prepare_holding_claim_row(sha256, claim, scope)?;
    check_holding_claim_audience(backend, &prepared.row).await?;
    Ok(prepared)
}

/// **The audience half of the custody gate** for a holding claim a blob door
/// is about to write (CC 3.1.3.3 rule 2): the holder must be in the claim's
/// cohort. Trivially true at `federation`.
///
/// # Errors
///
/// `custody_ack_outside_cohort` (as the attestation door refuses it).
pub async fn check_holding_claim_audience(
    dir: &dyn FederationDirectory,
    row: &Attestation,
) -> Result<(), BlobError> {
    super::custody_ack::check_custody_ack_admission(dir, row)
        .await
        .map_err(|e| BlobError::InvalidArgument(e.to_string()))
}

/// **The claim scope of the content this node stores for `sha256`**, or
/// `None` when no row is held: the one derivation ([`ClaimScope::of_content`])
/// over the row's own columns — its resolved tier, its cohort, and its group
/// (the sealing epoch's community where a binding exists, else the group the
/// write recorded).
///
/// # Errors
///
/// Backend errors; `holding_claim_scope_unresolved` for a sealed family or
/// room row that records no group.
pub async fn content_claim_scope<B>(
    backend: &B,
    sha256: &[u8; 32],
) -> Result<Option<ClaimScope>, BlobError>
where
    B: BlobStorage + Sync + ?Sized,
{
    let Some(head) = backend.blob_head(sha256).await? else {
        return Ok(None);
    };
    if head.crypto_tier == CryptoTier::Plaintext {
        return ClaimScope::of_content(CryptoTier::Plaintext, &head.cohort_scope, None).map(Some);
    }
    let bound = match head.cohort_scope.as_str() {
        cs::COMMUNITY | cs::AFFILIATIONS => backend
            .community_dek_blob_epoch(sha256)
            .await?
            .map(|(community, _, _)| community),
        _ => None,
    };
    let group = match bound {
        Some(c) => Some(c),
        None => backend
            .blob_provenance(sha256)
            .await?
            .and_then(|p| p.group_key_id),
    };
    ClaimScope::of_content(head.crypto_tier, &head.cohort_scope, group.as_deref()).map(Some)
}

/// **CC 3.1.3.3 rule 1 at admission** — a holding claim (`custody:ack:v1`
/// `here` or `none`) about a blob this node HOLDS must be placed at that
/// blob's claim scope ([`content_claim_scope`]). A claim about a blob this
/// node does not hold is not judged here: the content's scope is not known to
/// it (a commons directory row about bytes held elsewhere is the ordinary
/// case). A no-op off the custody leaf.
///
/// # Errors
///
/// `custody_ack_scope_mismatch`.
pub async fn check_holding_claim_scope<B>(backend: &B, row: &Attestation) -> Result<(), Error>
where
    B: super::renditions::HeldBlobScope + Sync + ?Sized,
{
    let Some(ack) = parse_custody_ack(row)? else {
        return Ok(());
    };
    let Ok(sha) = <[u8; 32]>::try_from(hex::decode(&ack.blob_sha256_hex).unwrap_or_default())
    else {
        return Ok(());
    };
    // A held sealed row that records no group (pre-V177) has no derivable
    // target: the content's scope cannot be judged here, as for a blob not
    // held.
    let want = match backend.held_claim_scope(&sha).await {
        Ok(Some(w)) => w,
        Ok(None) => return Ok(()),
        Err(Error::InvalidArgument(m)) if m.contains(HOLDING_CLAIM_SCOPE_UNRESOLVED) => {
            return Ok(())
        }
        Err(e) => return Err(e),
    };
    let got = ClaimScope::of_row(row)?;
    // A self report names no target; compare the cohort alone there.
    let agrees = got.cohort_scope == want.cohort_scope
        && (want.cohort_scope == cs::SELF || got.target == want.target);
    if agrees {
        Ok(())
    } else {
        Err(Error::InvalidArgument(format!(
            "{CUSTODY_ACK_SCOPE_MISMATCH}: a holding claim about {} is placed at {} {:?}, but the \
             content is at {} {:?} — a claim is placed at its content's scope, never one its \
             emitter chooses (CC 3.1.3.3 rule 1)",
            ack.blob_sha256_hex, got.cohort_scope, got.target, want.cohort_scope, want.target
        )))
    }
}

/// What [`emit_holding_claim`] did.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum HoldingClaimOutcome {
    /// A claim was signed and stored.
    Emitted {
        /// The claim's `attestation_id`.
        attestation_id: String,
        /// Where it was placed.
        scope: ClaimScope,
    },
    /// This node is not in the content's cohort, so it cannot claim (CC
    /// 3.1.3.3 rule 2: the holder of a bounded-cohort claim is in the
    /// cohort). Decided structurally, before signing; nothing was written.
    /// Never at `federation`, where everyone is audience.
    NotInCohort {
        /// The scope the claim would have been placed at.
        scope: ClaimScope,
    },
}

impl HoldingClaimOutcome {
    /// Was a claim stored?
    #[must_use]
    pub fn emitted(&self) -> bool {
        matches!(self, Self::Emitted { .. })
    }
}

/// **Emit this node's holding claim for a blob it already stores** (CC
/// 3.1.3.3): the one shared emission every door after the bytes reaches.
///
/// The scope is the stored content's ([`content_claim_scope`]); the size is
/// the stored length. At a bounded scope the claim is emitted only when this
/// node is in the cohort ([`HoldingClaimOutcome::NotInCohort`] otherwise — an
/// unclaimed node, or a server-class occurrence holding its owner's `self`
/// content, reports nothing). Signed by `local` (hybrid only) and stored
/// through [`BlobStorage::put_holding_claim`], which checks the row is still
/// held and runs the custody gate.
///
/// A chunk DAG is claimed by its manifest; the write doors that call this
/// hold every chunk by construction. A node asking for a DAG it adopted uses
/// `put_custody_ack`, which checks completeness first.
///
/// v55.0.0 (Codex r3 on #1065) — **never about withheld bytes.** Bytes a
/// tombstone withholds (a counter-notice takedown keeps them on disk through
/// its window; `steward_purge::purge_withheld` names the notice) are refused
/// [`BlobError::Purged`] before anything is signed, so no caller — a write
/// door, the re-ack, the upgrade conversion — re-advertises them.
///
/// # Errors
///
/// [`BlobError::NotHeld`] when no row is held; [`BlobError::Purged`] when a
/// tombstone withholds the bytes; signing and admission errors.
pub async fn emit_holding_claim<B>(
    backend: &B,
    local: &crate::signing::LocalSigner,
    sha256: &[u8; 32],
    now: DateTime<Utc>,
) -> Result<HoldingClaimOutcome, BlobError>
where
    B: BlobStorage + FederationDirectory + Sync,
{
    let not_held = || BlobError::NotHeld {
        sha256_hex: hex::encode(sha256),
    };
    if let Some(notice_id) = withheld_by(backend, sha256).await? {
        return Err(BlobError::Purged {
            sha256_hex: hex::encode(sha256),
            notice_id,
        });
    }
    let scope = content_claim_scope(backend, sha256)
        .await?
        .ok_or_else(not_held)?;
    let size = backend
        .blob_head(sha256)
        .await?
        .ok_or_else(not_held)?
        .size_bytes;
    let holder = local.derived_key_id();
    if !scope.is_directory()
        && !super::custody_ack::holder_in_cohort(
            backend,
            &holder,
            scope.cohort_scope(),
            scope.target(),
        )
        .await
        .map_err(|e| BlobError::Backend(format!("holding claim audience: {e}")))?
    {
        return Ok(HoldingClaimOutcome::NotInCohort { scope });
    }
    let attestation_id = uuid::Uuid::new_v4();
    let claim = sign_holding_claim(local, sha256, attestation_id, now, size, &scope).await?;
    backend.put_holding_claim(sha256, claim, &scope).await?;
    Ok(HoldingClaimOutcome::Emitted {
        attestation_id: attestation_id.to_string(),
        scope,
    })
}

// ── the re-ack (CC 3.1.3.3 rule 5) ───────────────────────────────────

/// **How old this node's own claim may grow before the re-ack renews it**:
/// a day. The claim lives [`CUSTODY_LIVE_SECS`] (72 h) from its signed
/// instant and "devices re-acknowledge about daily" (CC 3.1.3.3), so a node
/// that misses two sweeps is still advertised.
pub const HOLDING_CLAIM_REACK_AFTER_SECS: i64 = 24 * 60 * 60;

/// How often the background re-ack sweeper ([`Engine::spawn_reack_sweeper`])
/// wakes. Each wake renews only the claims older than
/// [`HOLDING_CLAIM_REACK_AFTER_SECS`], so the cadence bounds how late a renewal
/// can be, not how often one is signed.
///
/// [`Engine::spawn_reack_sweeper`]: crate::Engine::spawn_reack_sweeper
pub const HOLDING_CLAIM_REACK_SWEEP_INTERVAL: std::time::Duration =
    std::time::Duration::from_secs(60 * 60);

/// v55.0.0 (Codex r4 on #1065; CIRISEdge) — how long after spawn the re-ack
/// sweeper's FIRST pass runs: short, so an upgraded node converts its retired
/// rc6 claims within minutes rather than an interval, and not zero, so the
/// pass does not land on the announce cold-start and replication catch-up.
pub const HOLDING_CLAIM_REACK_START_DELAY: std::time::Duration = std::time::Duration::from_secs(90);

/// v56.0.0 (CIRISPersist#1071; CIRISEdge) — **the most claims ONE re-ack pass
/// signs**, renewals and upgrade conversions together. Each is a hybrid sign
/// and a write on the shared writer, and a node back from a long downtime has
/// every claim due at once, alongside replication catch-up. The pass renews
/// the OLDEST claims first (the nearest expiry), so a claim waits at most
/// `due / cap` passes; the rest is counted in [`ReackReport::deferred`] and
/// taken by the next pass. A claim is due at
/// [`HOLDING_CLAIM_REACK_AFTER_SECS`] (24 h) and lapses at
/// [`CUSTODY_LIVE_SECS`] (72 h): 48 hourly passes between, so 256 a pass keeps
/// about 12,000 claims live at a pass a wake. 2 under `cfg(test)`, so the
/// witnesses run the deferral on a handful of claims.
pub const HOLDING_CLAIM_REACK_MAX_PER_PASS: u64 = if cfg!(test) { 2 } else { 256 };

/// What one [`reack_own_claims`] pass did.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, serde::Serialize)]
pub struct ReackReport {
    /// Blobs whose latest claim by this node is `here` (any age).
    pub scanned: u64,
    /// Claims renewed: a fresh `here` signed at `now`.
    pub renewed: u64,
    /// Claims younger than [`HOLDING_CLAIM_REACK_AFTER_SECS`], left alone.
    pub fresh: u64,
    /// Claims about bytes this node no longer holds: never renewed (a claim
    /// is a holding fact, CC 3.1.3.3 rule 3; the lapse retires it).
    pub not_held: u64,
    /// Content whose cohort no longer seats this node: not renewed.
    pub not_in_cohort: u64,
    /// Renewals that failed (logged); the next pass retries them.
    pub failed: u64,
    /// Blobs this node held under a retired rc6 claim of its OWN and had no
    /// custody claim about: claimed now, once (the upgrade conversion).
    pub converted: u64,
    /// Blobs a tombstone withholds (Codex r3 on #1065): neither renewed nor
    /// converted, and not a failure — the next pass skips them the same way.
    pub withheld: u64,
    /// v56.0.0 (#1071) — renewals and conversions that were due but past
    /// this pass's [`HOLDING_CLAIM_REACK_MAX_PER_PASS`]: the next pass takes
    /// them, oldest first.
    pub deferred: u64,
}

/// **Re-acknowledge this node's own holdings** (CC 3.1.3.3 rule 5: "freshness
/// is the row's"): every blob whose latest claim by this node is `here`, whose
/// bytes this node still holds, and whose claim is at least
/// [`HOLDING_CLAIM_REACK_AFTER_SECS`] old gets a fresh claim through
/// [`emit_holding_claim`] — the same door, the same content-derived scope.
/// Without it every claim lapses 72 h after it was signed and the holder
/// directory goes dark.
///
/// After an upgrade it also claims, once, each blob this node still holds and
/// had announced under the retired rc6 carrier with its OWN row, and has made
/// no custody report about ([`ReackReport::converted`]); a peer's retired row
/// stays inert (CC 2.4).
///
/// v56.0.0 (CIRISPersist#1071): at most [`HOLDING_CLAIM_REACK_MAX_PER_PASS`]
/// emissions a pass, the oldest claims first; what is left over is
/// [`ReackReport::deferred`] and the next pass takes it.
///
/// Idempotent: a renewed claim is fresh, so a second pass at the same `now`
/// renews nothing. It never claims a blob this node did not already claim
/// (a `LocalOnly` copy stays unannounced) and never renews a claim about bytes
/// that are gone. A failure on one blob is counted and the pass goes on.
///
/// # Errors
///
/// Directory errors on the scan.
pub async fn reack_own_claims<B>(
    backend: &B,
    local: &crate::signing::LocalSigner,
    now: DateTime<Utc>,
) -> Result<ReackReport, BlobError>
where
    B: BlobStorage + FederationDirectory + Sync,
{
    let me = local.derived_key_id();
    let mut report = ReackReport::default();
    // v56.0.0 (#1071) — every emission this pass may make.
    let mut budget = HOLDING_CLAIM_REACK_MAX_PER_PASS;
    let shas = held_by(backend, &me, now, false)
        .await
        .map_err(|e| BlobError::Backend(format!("reack: {e}")))?;
    // First the due set: each held blob whose latest `here` is a day old (or
    // absent), with that instant. Bounded by the blobs this node claims, not
    // by its history.
    let mut due: Vec<(DateTime<Utc>, [u8; 32])> = Vec::new();
    for sha in shas {
        // One row at a time, each read its own short acquisition; yield
        // between rows so a long walk never starves the writers.
        tokio::task::yield_now().await;
        report.scanned += 1;
        // Codex r2 on #1065 — a maintenance scan reads the row HEAD, never
        // `has_blob`, which counts as an access (access_count,
        // last_accessed_at): an hourly re-ack must not keep cold bytes hot.
        if backend.blob_head(&sha).await?.is_none() {
            report.not_held += 1;
            continue;
        }
        let latest = super::custody_ack::custody_acks_of(backend, &me, &hex::encode(sha))
            .await
            .map_err(|e| BlobError::Backend(format!("reack: {e}")))?
            .into_iter()
            .filter(|a| a.state == CustodyState::Here)
            .map(|a| a.instant)
            .max();
        if latest.is_some_and(|t| (now - t).num_seconds() < HOLDING_CLAIM_REACK_AFTER_SECS) {
            report.fresh += 1;
            continue;
        }
        due.push((latest.unwrap_or(DateTime::<Utc>::MIN_UTC), sha));
    }
    // Oldest first: the nearest expiry is renewed before a later one, so the
    // cap defers only claims with the most time left (#1071).
    due.sort_unstable();
    for (_, sha) in due {
        if budget == 0 {
            report.deferred += 1;
            continue;
        }
        budget -= 1;
        match emit_holding_claim(backend, local, &sha, now).await {
            Ok(HoldingClaimOutcome::Emitted { .. }) => report.renewed += 1,
            Ok(HoldingClaimOutcome::NotInCohort { .. }) => report.not_in_cohort += 1,
            Err(BlobError::Purged { .. }) => report.withheld += 1,
            Err(e) => {
                report.failed += 1;
                tracing::warn!(
                    error = %e,
                    sha256_prefix = &hex::encode(sha)[..16],
                    "holding-claim re-ack failed; the next pass retries"
                );
            }
        }
    }
    // The upgrade conversion: a blob this node still holds and announced
    // under the retired rc6 carrier (its OWN row; a peer's is inert, CC 2.4)
    // and has made no custody report about — not even `none` — is claimed
    // now, at the content's scope. Once: the claim it emits is a custody
    // report, so a later pass finds it above and only renews it.
    //
    // v56.0.0 (#1071) — the retired rows are SOUGHT (the `holds_bytes:` type
    // prefix on the attester+type index), not filtered out of every row this
    // node ever authored, and walked a page at a time: no full-history Vec.
    // The conversion shares the pass's budget, after the renewals (a
    // conversion is a new claim; a renewal is one about to lapse).
    let mut seen: std::collections::HashSet<[u8; 32]> = std::collections::HashSet::new();
    let mut pages = AttestationQuery::by(&me, FOLD_PAGE)
        .type_prefix(super::namespace::registry::RETIRED_HOLDING_CLAIM_STEM)
        .pages();
    while let Some(page) = pages
        .next(backend)
        .await
        .map_err(|e| BlobError::Backend(format!("reack: {e}")))?
    {
        for r in page {
            let Some(sha) = r
                .attestation_envelope
                .get("evidence_refs")
                .and_then(|v| v.get(0))
                .and_then(serde_json::Value::as_str)
                .and_then(|h| hex::decode(h).ok())
                .and_then(|b| <[u8; 32]>::try_from(b).ok())
            else {
                continue;
            };
            if !seen.insert(sha) {
                continue;
            }
            tokio::task::yield_now().await;
            if backend.blob_head(&sha).await?.is_none()
                || !super::custody_ack::custody_acks_of(backend, &me, &hex::encode(sha))
                    .await
                    .map_err(|e| BlobError::Backend(format!("reack: {e}")))?
                    .is_empty()
            {
                continue;
            }
            if budget == 0 {
                report.deferred += 1;
                continue;
            }
            budget -= 1;
            match emit_holding_claim(backend, local, &sha, now).await {
                Ok(HoldingClaimOutcome::Emitted { .. }) => report.converted += 1,
                Ok(HoldingClaimOutcome::NotInCohort { .. }) => report.not_in_cohort += 1,
                // Codex r3 on #1065 — a counter-notice takedown keeps the bytes
                // through its window; the conversion never re-advertises them.
                Err(BlobError::Purged { .. }) => report.withheld += 1,
                Err(e) => {
                    report.failed += 1;
                    tracing::warn!(
                        error = %e,
                        sha256_prefix = &hex::encode(sha)[..16],
                        "retired-claim conversion failed; the next pass retries"
                    );
                }
            }
        }
    }
    Ok(report)
}

// ── the holder directory ─────────────────────────────────────────────

/// One holder's latest admitted claim about one blob, folded.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct HolderClaimState {
    /// The holder (attester).
    pub holder_key_id: String,
    /// The latest non-retired report's state.
    pub state: CustodyState,
    /// Its size, for `here`.
    pub size: Option<u64>,
    /// Its signed instant.
    pub instant: DateTime<Utc>,
    /// Its `attestation_id`.
    pub attestation_id: String,
    /// Is it live at the reader's `now` (CC 3.1.3.3 rule 5)?
    pub live: bool,
}

/// **Every holder's latest claim about `sha256`**, re-derived from the rows:
/// for each attester of a `custody:ack:v1` row citing the blob, its latest
/// non-retired report (by signed instant, ties by row hash), folded exactly
/// as the custody view folds a device ([`super::custody_ack::custody_acks_of`]).
/// Sorted by holder.
///
/// # Errors
///
/// Directory errors.
pub async fn holder_claims<D>(
    dir: &D,
    sha256: &[u8; 32],
    now: DateTime<Utc>,
) -> Result<Vec<HolderClaimState>, Error>
where
    D: FederationDirectory + ?Sized,
{
    let hex_sha = hex::encode(sha256);
    let mut holders: Vec<String> = dir
        .list_attestations_citing_by_dimension(CUSTODY_ACK_DIMENSION, &hex_sha)
        .await?
        .into_iter()
        .map(|r| r.attesting_key_id)
        .collect();
    holders.sort();
    holders.dedup();
    let mut out = Vec::with_capacity(holders.len());
    for h in holders {
        let acks = super::custody_ack::custody_acks_of(dir, &h, &hex_sha).await?;
        let Some(latest) = acks
            .iter()
            .max_by(|a, b| (a.instant, &a.row_hash).cmp(&(b.instant, &b.row_hash)))
        else {
            continue;
        };
        out.push(HolderClaimState {
            holder_key_id: h,
            state: latest.state,
            size: latest.size,
            instant: latest.instant,
            attestation_id: latest.attestation_id.clone(),
            live: super::custody_ack::is_live(latest.instant, now),
        });
    }
    Ok(out)
}

/// **The holder directory read** (CC 5.3.2.1): every holder whose latest
/// claim about `sha256` is a LIVE `here`. Sorted.
///
/// # Errors
///
/// Directory errors.
pub async fn live_holders<D>(
    dir: &D,
    sha256: &[u8; 32],
    now: DateTime<Utc>,
) -> Result<Vec<String>, Error>
where
    D: FederationDirectory + ?Sized,
{
    Ok(holder_claims(dir, sha256, now)
        .await?
        .into_iter()
        .filter(|c| c.live && c.state == CustodyState::Here)
        .map(|c| c.holder_key_id)
        .collect())
}

/// **Every blob `holder` claims `here`** (the inverse read): the blobs its
/// `custody:ack:v1` rows cite whose latest non-retired report by `holder` is
/// `here`, live at `now` when `live_only`. Sorted, deduplicated.
///
/// # Errors
///
/// Directory errors.
pub async fn held_by<D>(
    dir: &D,
    holder_key_id: &str,
    now: DateTime<Utc>,
    live_only: bool,
) -> Result<Vec<[u8; 32]>, Error>
where
    D: FederationDirectory + ?Sized,
{
    // v56.0.0 (#1071) — deduped as the pages arrive: the holder's reports
    // include every daily renewal, so a Vec of every row's sha grew with
    // the claim history; the set holds one entry per blob.
    let mut shas: std::collections::BTreeSet<String> = std::collections::BTreeSet::new();
    let mut pages = AttestationQuery::by(holder_key_id, FOLD_PAGE)
        .dimension_prefix(CUSTODY_ACK_DIMENSION)
        .pages();
    while let Some(page) = pages.next(dir).await? {
        shas.extend(
            page.iter()
                .filter_map(|r| parse_custody_ack(r).ok().flatten())
                .map(|a| a.blob_sha256_hex),
        );
    }
    let mut out = Vec::with_capacity(shas.len());
    for hex_sha in shas {
        let acks = super::custody_ack::custody_acks_of(dir, holder_key_id, &hex_sha).await?;
        let Some(latest) = acks
            .iter()
            .max_by(|a, b| (a.instant, &a.row_hash).cmp(&(b.instant, &b.row_hash)))
        else {
            continue;
        };
        if latest.state != CustodyState::Here
            || (live_only && !super::custody_ack::is_live(latest.instant, now))
        {
            continue;
        }
        if let Ok(sha) = <[u8; 32]>::try_from(hex::decode(&hex_sha).unwrap_or_default()) {
            out.push(sha);
        }
    }
    Ok(out)
}

/// The `attestation_id`s of `holder`'s own non-retired `here` claims about
/// `sha256` — what an eviction retracts with the holder's own `withdraws`
/// (rule 4: the signer retracts; nobody else).
///
/// # Errors
///
/// Directory errors.
pub async fn own_here_claims<D>(
    dir: &D,
    holder_key_id: &str,
    sha256: &[u8; 32],
) -> Result<Vec<String>, Error>
where
    D: FederationDirectory + ?Sized,
{
    Ok(
        super::custody_ack::custody_acks_of(dir, holder_key_id, &hex::encode(sha256))
            .await?
            .into_iter()
            .filter(|a| a.state == CustodyState::Here)
            .map(|a| a.attestation_id)
            .collect(),
    )
}

// ── the BlobStorage holder doors, once ───────────────────────────────

/// **`BlobStorage::list_holders`, one implementation for every backend**:
/// [`live_holders`] — every holder whose latest claim about `sha256` is a live
/// `here`. When this node holds the bytes itself, freshness is not asked
/// (v3.6.4, CIRISPersist#130: the 72 h window is a backstop for peers that go
/// silent; for bytes held here the row's age says nothing), and a holder's own
/// retraction or later `none` is still honoured.
///
/// # Errors
///
/// Backend errors.
pub async fn list_holders_of<B>(backend: &B, sha256: &[u8; 32]) -> Result<Vec<String>, BlobError>
where
    B: BlobStorage + FederationDirectory + Sync,
{
    // v55.0.0 (CIRISEdge v55) — withheld bytes have no holder to fetch from
    // or fan out to: the takedown's content is never a pull or repair target.
    if is_withheld(backend, sha256).await? {
        return Ok(Vec::new());
    }
    // A directory read, not an access to the bytes (Codex r2 on #1065).
    let held_here = backend.blob_head(sha256).await?.is_some();
    let claims = holder_claims(backend, sha256, Utc::now())
        .await
        .map_err(|e| BlobError::Backend(format!("list_holders: {e}")))?;
    Ok(claims
        .into_iter()
        .filter(|c| c.state == CustodyState::Here && (held_here || c.live))
        .map(|c| c.holder_key_id)
        .collect())
}

/// **`BlobStorage::list_local_holders`, once**: empty when this node does not
/// hold the bytes; otherwise every holder whose latest claim is `here`,
/// whatever its age (the local-truth read, CIRISPersist#130).
///
/// # Errors
///
/// Backend errors.
pub async fn list_local_holders_of<B>(
    backend: &B,
    sha256: &[u8; 32],
) -> Result<Vec<String>, BlobError>
where
    B: BlobStorage + FederationDirectory + Sync,
{
    if backend.blob_head(sha256).await?.is_none() || is_withheld(backend, sha256).await? {
        return Ok(Vec::new());
    }
    Ok(holder_claims(backend, sha256, Utc::now())
        .await
        .map_err(|e| BlobError::Backend(format!("list_local_holders: {e}")))?
        .into_iter()
        .filter(|c| c.state == CustodyState::Here)
        .map(|c| c.holder_key_id)
        .collect())
}

/// **`BlobStorage::list_held_by`, once**: [`held_by`] at the 72 h freshness.
///
/// # Errors
///
/// Backend errors.
pub async fn list_held_by_of<B>(
    backend: &B,
    holder_key_id: &str,
) -> Result<Vec<[u8; 32]>, BlobError>
where
    B: BlobStorage + FederationDirectory + Sync,
{
    let mut out = Vec::new();
    for sha in held_by(backend, holder_key_id, Utc::now(), true)
        .await
        .map_err(|e| BlobError::Backend(format!("list_held_by: {e}")))?
    {
        // v55.0.0 (CIRISEdge v55) — a withheld blob is no adopt suggestion.
        if !is_withheld(backend, &sha).await? {
            out.push(sha);
        }
    }
    Ok(out)
}

/// v55.0.0 (CIRISEdge v55) — **is `sha256` withheld by a tombstone here?**
/// The ONE question every read that feeds replication or repair asks
/// ([`steward_purge::purge_withheld`](super::steward_purge::purge_withheld)):
/// the holder directory, the durability deficit, the custody view.
///
/// # Errors
///
/// Directory reads.
pub async fn is_withheld<D>(dir: &D, sha256: &[u8; 32]) -> Result<bool, BlobError>
where
    D: FederationDirectory + ?Sized,
{
    Ok(withheld_by(dir, sha256).await?.is_some())
}

/// [`is_withheld`], naming the notice that withholds the bytes.
///
/// # Errors
///
/// Directory reads.
pub async fn withheld_by<D>(dir: &D, sha256: &[u8; 32]) -> Result<Option<String>, BlobError>
where
    D: FederationDirectory + ?Sized,
{
    super::steward_purge::purge_withheld(dir, sha256)
        .await
        .map_err(|e| BlobError::Backend(format!("tombstone: {e}")))
}

/// **`BlobStorage::evict_actor`, once.** Every blob `actor` claims `here`
/// (whatever the claim's age) is deleted from this node, and `signer`'s OWN
/// `here` claims about each are retracted with its own `withdraws` (CC
/// 3.1.3.3 rule 4: the signer retracts; nobody retracts another device's
/// claim — so when `actor` is a peer, its claims stand and only this node's
/// copies and claims go). Fail-honest as before: the bytes go even when a
/// retraction fails, and the report counts both.
///
/// # Errors
///
/// Backend errors on the read or the delete.
#[cfg(any(feature = "postgres", feature = "sqlite"))]
pub async fn evict_actor_of<B>(
    backend: &B,
    actor: &str,
    signer: &crate::signing::LocalSigner,
    now: DateTime<Utc>,
) -> Result<super::EvictActorReport, BlobError>
where
    B: BlobStorage + FederationDirectory + Sync,
{
    let shas = held_by(backend, actor, now, false)
        .await
        .map_err(|e| BlobError::Backend(format!("evict_actor: {e}")))?;
    let me = signer.derived_key_id();
    let mut report = super::EvictActorReport::default();
    for sha in shas {
        let own = own_here_claims(backend, &me, &sha)
            .await
            .map_err(|e| BlobError::Backend(format!("evict_actor: {e}")))?;
        for claim_id in own {
            let Some(prior) = backend
                .get_attestation(&claim_id)
                .await
                .map_err(|e| BlobError::Backend(format!("evict_actor: {e}")))?
            else {
                continue;
            };
            match super::blobs::emit_withdraws_attestation_helper(&prior, &me, signer, backend, now)
                .await
            {
                Ok(()) => report.withdraws_emitted += 1,
                Err(e) => {
                    report.withdraws_failed += 1;
                    tracing::warn!(
                        error = %e,
                        actor = %actor,
                        sha256_prefix = &hex::encode(sha)[..16],
                        "evict_actor: holding-claim retraction failed"
                    );
                }
            }
        }
        if backend.delete_blob(&sha).await? {
            report.blobs_evicted += 1;
        }
    }
    Ok(report)
}

/// **Retract this node's own holding claims about `sha256`** (CC 3.1.3.3 rule
/// 4): every non-retired `here` claim `holder_key_id` (this node — `signer`'s
/// derived key) made about the blob gets `signer`'s own `withdraws`, placed at
/// the claim's scope. A claim already
/// retracted is not re-retracted (the fold drops it), so a retry after a
/// partial failure is safe. The first retraction that cannot be admitted
/// ABORTS with its error: the doors that delete bytes after this (epoch
/// eviction, purge eviction) leave the bytes in place for the retry rather
/// than leave a claim naming bytes that are gone. Returns how many were
/// retracted.
///
/// # Errors
///
/// [`BlobError::AttestationEmissionFailed`] naming the claim; backend errors.
#[cfg(any(feature = "postgres", feature = "sqlite"))]
pub async fn retract_own_claims(
    dir: &dyn FederationDirectory,
    holder_key_id: &str,
    signer: &crate::signing::LocalSigner,
    sha256: &[u8; 32],
    now: DateTime<Utc>,
) -> Result<usize, BlobError> {
    let me = holder_key_id;
    let ids = own_here_claims(dir, me, sha256)
        .await
        .map_err(|e| BlobError::Backend(format!("own holding claims: {e}")))?;
    let mut n = 0;
    for id in ids {
        let Some(prior) = dir
            .get_attestation(&id)
            .await
            .map_err(|e| BlobError::Backend(format!("holding claim {id}: {e}")))?
        else {
            continue;
        };
        super::blobs::emit_withdraws_attestation_helper(&prior, me, signer, dir, now)
            .await
            .map_err(|e| {
                BlobError::AttestationEmissionFailed(format!(
                    "the retraction of holding claim {id} about {} could not be admitted; bytes \
                     left in place for retry: {e}",
                    hex::encode(sha256)
                ))
            })?;
        n += 1;
    }
    Ok(n)
}
