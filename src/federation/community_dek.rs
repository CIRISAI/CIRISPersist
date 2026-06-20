//! v9.0.0 G5 (CC 4.4.3.2.1 / 4.4.3.2.2, CIRISPersist#237) — the
//! **community DEK cascade + rotation-on-removal** for the
//! [`CryptoTier::CommunityDek`] tier.
//!
//! # Relation to the self/family cascade
//!
//! This is the community analog of
//! [`at_rest_cascade`](crate::federation::at_rest_cascade), and reuses
//! its primitives verbatim — [`seal`](crate::federation::at_rest_cascade::seal),
//! [`open`](crate::federation::at_rest_cascade::open),
//! [`fresh_dek`](crate::federation::at_rest_cascade::fresh_dek),
//! [`wrap_dek_v2`](crate::federation::at_rest_cascade::wrap_dek_v2),
//! [`wrap_dek_for_persist`](crate::federation::at_rest_cascade::wrap_dek_for_persist),
//! [`unwrap_dek_for_persist`](crate::federation::at_rest_cascade::unwrap_dek_for_persist),
//! the [`AtRestEnvelope`](crate::federation::at_rest_cascade::AtRestEnvelope)
//! format, and the [`WRAP_ALGORITHM_V2`](crate::federation::at_rest_cascade::WRAP_ALGORITHM_V2)
//! string. **It reinvents no crypto.** The single structural difference is
//! the DEK lifetime:
//!
//! | tier | DEK lifetime | per-emission cost | rotation |
//! |---|---|---|---|
//! | self/family ([`InvisibleEncrypted`]) | **fresh per write** | O(members) wraps | none (forward-only via fresh DEK) |
//! | community ([`CommunityDek`]) | **one shared per `(community, epoch)`** | O(1) (DEK already wrapped at epoch creation) | **epoch bump on member removal** (CC 4.4.3.2.2) |
//!
//! CC 4.4.3.2.1: "a community is a stream its members subscribe to,
//! cryptographically" — one DEK shared across emissions, wrapped to each
//! member once on admission, re-wrapped on membership change.
//!
//! # Rotation-on-removal (CC 4.4.3.2.2 — Option-A forward secrecy)
//!
//! On member removal the substrate bumps the community DEK *epoch*
//! ([`BlobStorage::community_dek_bump_epoch`](crate::federation::blobs::BlobStorage::community_dek_bump_epoch),
//! wired into `put_community_membership_revocation`). The NEXT emission
//! mints a FRESH DEK for the new epoch and wraps it only to the remaining
//! members — the removed member's keys can never unwrap it. Blobs already
//! sealed under the OLD epoch keep their grants untouched: the removed
//! member keeps what they could already read (no PCS), and receives no NEW
//! community content. **Exposure window:** content emitted between the
//! member's effective removal and the epoch bump — which here is zero,
//! because community membership revocation is **immediate** (a future-dated
//! `effective_at` is rejected at write time — SecReview F4 /
//! [`reject_future_dated_community_revocation`]), the bump is transactionally
//! part of the revocation write, and every subsequent emission reads the
//! bumped epoch. (A removed member
//! retains read access only to pre-rotation blobs they were already a
//! grantee on, which is exactly Option-A's "once shared, always shared"
//! forward-only guarantee.)
//!
//! This is a **flat per-member re-wrap** (the same shape the self/family
//! path uses), deliberately **NOT MLS TreeKEM**. Full CC 5.1 TreeKEM —
//! multicast-vs-unicast, removal-coalescing, the binary-tree key
//! schedule — is the RET transport layer's open question; the substrate's
//! responsibility ends at the flat cascade.
//!
//! # Infrastructure opt-out (CC 4.4.3.2.1, normative)
//!
//! An **authorized** `community` with `cohort_subkind: infrastructure`
//! (`ciris-canonical` / governance roots whose own key is the
//! `substrate_persist` governance authority) opts OUT of the DEK cascade
//! entirely — Commons-tier plaintext, `holds_bytes`, NO DEK. The trust
//! root must be publicly auditable.
//! [`admission::is_authorized_infrastructure_community`](crate::federation::admission::is_authorized_infrastructure_community)
//! is the check; the cascade refuses to seal an authorized infra
//! community's content (the caller stores it plaintext via the ordinary
//! path). SecReview F2: a self-labeled `infrastructure` community whose key
//! is NOT `substrate_persist` is NOT exempted — it gets the full DEK
//! cascade, so an unauthorized label can never force content to plaintext.
//!
//! # v2-only (CC 4.4.3.4.1 / CC 5.2)
//!
//! Every wrap is `wrap_algorithm: v2`
//! (`x25519_mlkem768_aes256_gcm_hkdf_sha256`, FIPS-203 hybrid). There is
//! NO v1 path and NO plaintext fallback — a member lacking a valid
//! ML-KEM-768 is **fail-secure excluded** and surfaced as
//! `hard_case:recipient_excluded` (same mechanism + reason-set as the
//! self/family cascade, scoped to the community).
//!
//! [`CryptoTier::CommunityDek`]: crate::federation::types::cohort_scope::CryptoTier::CommunityDek
//! [`InvisibleEncrypted`]: crate::federation::types::cohort_scope::CryptoTier::InvisibleEncrypted
//! [`CommunityDek`]: crate::federation::types::cohort_scope::CryptoTier::CommunityDek

use crate::federation::types::Community;

/// SecReview F4 — the small clock-skew tolerance (60s) on a community
/// membership revocation's `effective_at`. Community removal is **immediate**
/// for forward-secrecy (the epoch bump happens at write time), so a
/// future-dated `effective_at` is rejected; this constant only absorbs
/// benign clock drift between the ceremony's clock and persist's.
pub const COMMUNITY_REVOCATION_MAX_FUTURE_SKEW_SECS: i64 = 60;

/// SecReview F4 — reject a future-dated community membership revocation.
///
/// `put_community_membership_revocation` bumps the DEK epoch at write time
/// (rotation-on-removal), but a removed member is only dropped from the wrap
/// fan-out once `effective_at <= now` ([`orchestrate`]'s
/// `resolve_community_members`). A future-dated `effective_at` would
/// therefore bump the epoch immediately yet keep wrapping the "removed"
/// member into the fresh epoch DEK until `effective_at` arrives — opening
/// the exact exposure window the "exposure window = zero" claim denies.
/// Community removal is immediate (no future-dating); a future `effective_at`
/// beyond [`COMMUNITY_REVOCATION_MAX_FUTURE_SKEW_SECS`] is
/// [`Error::InvalidArgument`](crate::federation::Error::InvalidArgument)
/// BEFORE any write, on every backend.
pub fn reject_future_dated_community_revocation(
    effective_at: chrono::DateTime<chrono::Utc>,
) -> Result<(), crate::federation::Error> {
    let now = chrono::Utc::now();
    let max_allowed = now + chrono::Duration::seconds(COMMUNITY_REVOCATION_MAX_FUTURE_SKEW_SECS);
    if effective_at > max_allowed {
        return Err(crate::federation::Error::InvalidArgument(format!(
            "community membership revocation effective_at {effective_at} is future-dated \
             (> now + {COMMUNITY_REVOCATION_MAX_FUTURE_SKEW_SECS}s); community removal is \
             immediate for forward-secrecy (SecReview F4)"
        )));
    }
    Ok(())
}

/// True iff `community` carries the `policy_blob.cohort_subkind ==
/// "infrastructure"` **label**. This is the *syntactic* check only.
///
/// SecReview F2: the label alone does NOT confer the CC 4.4.3.2.1
/// Commons-plaintext carve-out — honoring it additionally requires the
/// community's own key to be the `substrate_persist` governance authority
/// ([`admission::is_authorized_infrastructure_community`](crate::federation::admission::is_authorized_infrastructure_community),
/// the gate the cascade actually consults). This predicate is retained for
/// the label-presence test surface; production carve-out decisions go
/// through the authority-gated helper.
#[must_use]
pub fn is_infrastructure_community(community: &Community) -> bool {
    community
        .policy_blob
        .as_ref()
        .and_then(|b| b.get("cohort_subkind"))
        .and_then(|v| v.as_str())
        == Some("infrastructure")
}

/// The recipient-resolution + shared-epoch-DEK + grant-record
/// orchestration for the [`CryptoTier::CommunityDek`] tier. Generic over a
/// backend that is **both** a [`FederationDirectory`] (roster resolution)
/// and a [`BlobStorage`] (ciphertext + epoch-DEK persistence) — the
/// concrete `PostgresBackend` / `SqliteBackend`.
///
/// [`CryptoTier::CommunityDek`]: crate::federation::types::cohort_scope::CryptoTier::CommunityDek
/// [`FederationDirectory`]: crate::federation::FederationDirectory
/// [`BlobStorage`]: crate::federation::blobs::BlobStorage
pub mod orchestrate {
    use crate::federation::at_rest_cascade::{
        fresh_dek, open, seal, unwrap_dek_for_persist, wrap_dek_for_persist, wrap_dek_v2,
        AtRestEnvelope, AtRestError, DEK_LEN, WRAP_ALGORITHM_V2,
    };
    use crate::federation::blobs::{BlobBody, BlobError, BlobStorage};
    use crate::federation::types::cohort_scope::{
        crypto_tier, CryptoTier, AFFILIATIONS, COMMUNITY,
    };
    use crate::federation::types::EncryptionPubkeys;
    use crate::federation::FederationDirectory;
    use sha2::{Digest, Sha256};

    /// Outcome of a [`encrypt_and_cascade_community`] community emission.
    #[derive(Debug, Clone, PartialEq, Eq)]
    pub struct CommunityCascadeResult {
        /// The at-rest content address (SHA-256 of the stored ciphertext
        /// envelope) — the handle a later
        /// [`read_for_community_viewer`] read targets.
        pub at_rest_sha256: [u8; 32],
        /// The `(community, epoch)` the blob was sealed under.
        pub epoch: u64,
        /// Member occurrence key_ids that hold a v2 grant on this epoch's
        /// DEK (granted at epoch creation; reused across emissions).
        pub granted: Vec<String>,
        /// Member occurrence key_ids **fail-secure excluded** because they
        /// carried no valid `encryption_pubkeys` — NO grant, never a
        /// plaintext / v1 fallback. Surfaced as
        /// `hard_case:recipient_excluded` by [`emit_excluded_hard_cases`].
        pub excluded: Vec<String>,
    }

    fn map_dir_err(e: crate::federation::Error) -> BlobError {
        BlobError::Backend(format!("community DEK cascade directory: {e}"))
    }

    fn map_at_rest_err(e: AtRestError) -> BlobError {
        BlobError::Backend(format!("community DEK cascade crypto: {e}"))
    }

    /// Valid-now wrap target? A member is excluded unless its occurrence
    /// carries BOTH encryption-pubkey halves. (Identical predicate to the
    /// self/family `usable_keys`; replicated locally to keep the surfaces
    /// independent.)
    fn usable_keys(keys: &Option<EncryptionPubkeys>) -> Option<&EncryptionPubkeys> {
        keys.as_ref()
            .filter(|k| !k.x25519_base64.is_empty() && !k.ml_kem_768_base64.is_empty())
    }

    /// Resolve the **current** member-occurrence wrap targets of a
    /// community as `(occurrence_key_id, encryption_pubkeys?)` pairs.
    ///
    /// Composes [`lookup_community`](FederationDirectory::lookup_community)'s
    /// roster with the membership-revocation table (drop members removed
    /// with `effective_at <= now`, the CC 4.4.3.2.4 / §11.7.1
    /// active-membership read), then each remaining member identity's
    /// active occurrences. This is the same shape the self/family
    /// `resolve_recipients` family arm uses, keyed on the community.
    async fn resolve_community_members<B>(
        backend: &B,
        community_key_id: &str,
    ) -> Result<Vec<(String, Option<EncryptionPubkeys>)>, BlobError>
    where
        B: FederationDirectory + Sync,
    {
        let community = backend
            .lookup_community(community_key_id)
            .await
            .map_err(map_dir_err)?
            .ok_or_else(|| {
                BlobError::InvalidArgument(format!(
                    "community DEK cascade names unknown community_key_id {community_key_id:?}"
                ))
            })?;

        // CC 4.4.3.2.1 normative carve-out: an AUTHORIZED infrastructure
        // community never gets a DEK. Refuse here so a mis-dispatched infra
        // emission is a loud error, not a silent encrypt. SecReview F2: the
        // Commons-plaintext opt-out is honored ONLY when the community's own
        // key is the `substrate_persist` governance authority — a self-
        // labeled `infrastructure` community whose key is NOT substrate_persist
        // is NOT exempted (it gets the full DEK cascade, fail-secure: an
        // unauthorized infra label can never force its content to plaintext).
        if crate::federation::admission::is_authorized_infrastructure_community(backend, &community)
            .await
            .map_err(map_dir_err)?
        {
            return Err(BlobError::InvalidArgument(format!(
                "community {community_key_id:?} is an authorized cohort_subkind:infrastructure — \
                 Commons-tier plaintext (CC 4.4.3.2.1 opt-out); the DEK cascade must not run for it"
            )));
        }

        // Active membership = roster minus effective revocations (the
        // CC 4.4.3.2.2 forward-secrecy read: a removed member is dropped
        // from the wrap fan-out BEFORE we wrap). The roster-minus-effective-
        // revocations subtraction is the shared #249 Cut B
        // [`removed_key_ids_at`](crate::federation::removed_key_ids_at) fold —
        // the SAME rule the `active_*_members` group-roster readers compose,
        // so the forward-secrecy subtraction is never forked.
        let revs = backend
            .list_community_membership_revocations_for(community_key_id)
            .await
            .map_err(map_dir_err)?;
        let removed = crate::federation::removed_key_ids_at(
            revs.iter()
                .map(|r| (r.removed_identity_key_id.as_str(), r.effective_at)),
            chrono::Utc::now(),
        );

        let mut out = Vec::new();
        for member in &community.members {
            if removed.contains(member.key_id.as_str()) {
                continue;
            }
            let occ = backend
                .list_identity_occurrences_active(&member.key_id)
                .await
                .map_err(map_dir_err)?;
            for o in occ {
                out.push((o.occurrence_key_id, o.encryption_pubkeys));
            }
        }
        Ok(out)
    }

    /// Mint (or read) the shared DEK for `(community, epoch)` and ensure it
    /// is wrapped to every current member occurrence + persist's own
    /// self-retention.
    ///
    /// On the FIRST emission in an epoch (no self-retention row yet) this
    /// mints a fresh DEK, records persist's content-master self-retention
    /// wrap, and v2-wraps it to each member (fail-secure excluding the
    /// keyless). On a LATER emission in the same epoch it recovers the
    /// already-minted DEK via the self-retention row and only fills in any
    /// member who joined since (idempotent — already-granted members are
    /// skipped). Returns `(dek, granted, excluded)`.
    async fn ensure_epoch_dek<B>(
        backend: &B,
        community_key_id: &str,
        epoch: u64,
    ) -> Result<([u8; DEK_LEN], Vec<String>, Vec<String>), BlobError>
    where
        B: FederationDirectory + BlobStorage + Sync,
    {
        let members = resolve_community_members(backend, community_key_id).await?;
        let content_master = backend.load_or_init_content_master().await?;

        // Recover-or-mint the epoch DEK.
        let dek = match backend
            .community_dek_get_self_retention(community_key_id, epoch)
            .await?
        {
            Some(wrapped) => {
                unwrap_dek_for_persist(&content_master, &wrapped).map_err(map_at_rest_err)?
            }
            None => {
                let dek = fresh_dek().map_err(map_at_rest_err)?;
                let self_wrap =
                    wrap_dek_for_persist(&content_master, &dek).map_err(map_at_rest_err)?;
                // First-write-wins: a concurrent first-emitter may have
                // raced us. Re-read after the idempotent put to converge on
                // the persisted DEK rather than using our discarded one.
                backend
                    .community_dek_put_self_retention(community_key_id, epoch, &self_wrap)
                    .await?;
                let persisted = backend
                    .community_dek_get_self_retention(community_key_id, epoch)
                    .await?
                    .ok_or_else(|| {
                        BlobError::Backend(format!(
                            "community DEK self-retention vanished after put for \
                             {community_key_id:?} epoch {epoch} (corrupt cascade state)"
                        ))
                    })?;
                unwrap_dek_for_persist(&content_master, &persisted).map_err(map_at_rest_err)?
            }
        };

        // Member fan-out — wrap to each member not already granted; the put
        // is idempotent so a re-emission is a no-op. Fail-secure exclude
        // the keyless (no grant, surfaced as recipient_excluded).
        let already: std::collections::HashSet<String> = backend
            .community_dek_member_grant_recipients(community_key_id, epoch)
            .await?
            .into_iter()
            .collect();
        let mut granted = Vec::new();
        let mut excluded = Vec::new();
        for (occ_key_id, keys) in members {
            match usable_keys(&keys) {
                Some(k) => {
                    if !already.contains(&occ_key_id) {
                        let wrapped = wrap_dek_v2(&k.x25519_base64, &k.ml_kem_768_base64, &dek)
                            .map_err(map_at_rest_err)?;
                        backend
                            .community_dek_put_member_grant(
                                community_key_id,
                                epoch,
                                &occ_key_id,
                                WRAP_ALGORITHM_V2,
                                &wrapped,
                            )
                            .await?;
                    }
                    granted.push(occ_key_id);
                }
                None => excluded.push(occ_key_id),
            }
        }
        Ok((dek, granted, excluded))
    }

    /// Encrypt `plaintext` under the community's CURRENT-epoch shared DEK,
    /// store the ciphertext envelope, bind it to `(community, epoch)`, and
    /// (on first emission in the epoch) wrap the DEK to every current
    /// member — fail-secure excluding members without valid
    /// `encryption_pubkeys`.
    ///
    /// Returns the [`CommunityCascadeResult`]. Unlike the self/family
    /// cascade this does NOT suppress `holds_bytes`: community content
    /// federates with cleartext provenance (the caller emits the
    /// `holds_bytes:*` row; this owns only the at-rest crypto + grants).
    ///
    /// Precondition: the community is NOT `cohort_subkind: infrastructure`
    /// (asserted in [`resolve_community_members`] — an infra community is
    /// rejected with [`BlobError::InvalidArgument`], never sealed).
    pub async fn encrypt_and_cascade_community<B>(
        backend: &B,
        community_key_id: &str,
        plaintext: &[u8],
        media_type: Option<&str>,
    ) -> Result<CommunityCascadeResult, BlobError>
    where
        B: FederationDirectory + BlobStorage + Sync,
    {
        // Defense-in-depth: the dispatch (crypto_tier over COMMUNITY/
        // AFFILIATIONS) should already have routed here. Both scopes share
        // this path; the subkind opt-out is enforced in resolve.
        debug_assert!(matches!(
            crypto_tier(COMMUNITY, None),
            CryptoTier::CommunityDek
        ));
        debug_assert!(matches!(
            crypto_tier(AFFILIATIONS, None),
            CryptoTier::CommunityDek
        ));

        let epoch = backend
            .community_dek_current_epoch(community_key_id)
            .await?;
        let (dek, granted, excluded) = ensure_epoch_dek(backend, community_key_id, epoch).await?;

        // Seal the body under the shared epoch DEK into the self-describing
        // CRBLOB envelope (same format as self/family).
        let envelope = seal(&dek, plaintext).map_err(map_at_rest_err)?;
        let envelope_bytes = envelope.to_bytes();
        let at_rest_sha256: [u8; 32] = Sha256::digest(&envelope_bytes).into();

        backend
            .store_blob_local(
                &at_rest_sha256,
                BlobBody::Inline(envelope_bytes),
                media_type,
            )
            .await?;
        backend
            .community_dek_bind_blob_epoch(&at_rest_sha256, community_key_id, epoch)
            .await?;

        Ok(CommunityCascadeResult {
            at_rest_sha256,
            epoch,
            granted,
            excluded,
        })
    }

    /// Recover the plaintext community-content body for a member viewer.
    ///
    /// Authorization predicate: the viewer must hold a v2 grant on the
    /// blob's `(community, epoch)`
    /// ([`community_dek_has_member_grant`](BlobStorage::community_dek_has_member_grant)).
    /// A removed member who was a grantee on a PRE-rotation epoch still
    /// passes for those blobs (Option-A forward-only: they keep what they
    /// could already read); a member who only ever held grants on a
    /// later-rotated epoch cannot read a blob sealed under an epoch they
    /// were never granted on. Persist recovers the actual DEK via its
    /// per-epoch self-retention row (the V070 read discipline).
    ///
    /// - [`BlobError::NotHeld`] if the ciphertext is absent.
    /// - [`BlobError::NotGranted`] if the viewer holds no grant on the
    ///   blob's epoch.
    /// - [`BlobError::InvalidArgument`] if the blob carries no
    ///   community-DEK binding (not a community blob).
    pub async fn read_for_community_viewer<B>(
        backend: &B,
        at_rest_sha256: &[u8; 32],
        viewer_key_id: &str,
    ) -> Result<Vec<u8>, BlobError>
    where
        B: BlobStorage + Sync,
    {
        let (community_key_id, epoch) = backend
            .community_dek_blob_epoch(at_rest_sha256)
            .await?
            .ok_or_else(|| {
                BlobError::InvalidArgument(format!(
                    "at-rest blob {} carries no community-DEK binding",
                    hex::encode(at_rest_sha256)
                ))
            })?;

        // Fail-secure authorization gate.
        let authorized = backend
            .community_dek_has_member_grant(&community_key_id, epoch, viewer_key_id)
            .await?;
        if !authorized {
            return Err(BlobError::NotGranted {
                sha256_hex: hex::encode(at_rest_sha256),
                viewer_key_id: viewer_key_id.to_string(),
            });
        }

        let body = backend.get_blob(at_rest_sha256).await?;
        let envelope_bytes = match body {
            Some(BlobBody::Inline(b)) => b,
            Some(_) => {
                return Err(BlobError::InvalidArgument(
                    "community at-rest blob is not an inline ciphertext envelope".into(),
                ))
            }
            None => {
                return Err(BlobError::NotHeld {
                    sha256_hex: hex::encode(at_rest_sha256),
                })
            }
        };
        let envelope = AtRestEnvelope::from_bytes(&envelope_bytes).map_err(map_at_rest_err)?;

        // Recover the epoch DEK via persist's self-retention row.
        let self_wrap = backend
            .community_dek_get_self_retention(&community_key_id, epoch)
            .await?
            .ok_or_else(|| {
                BlobError::Backend(format!(
                    "community blob {} bound to {community_key_id:?} epoch {epoch} has no \
                     persist self-retention row (corrupt cascade state)",
                    hex::encode(at_rest_sha256)
                ))
            })?;
        let content_master = backend.load_or_init_content_master().await?;
        let dek = unwrap_dek_for_persist(&content_master, &self_wrap).map_err(map_at_rest_err)?;

        open(&dek, &envelope).map_err(map_at_rest_err)
    }

    /// Emit one `hard_case:recipient_excluded` per fail-secure-excluded
    /// member from a completed community cascade (CC 4.4.3.4.1 non-silent
    /// recipient exclusion). Reuses the exact self/family mechanism +
    /// reason-set, scoped to the community's `cohort_scope`. Idempotent on
    /// the deterministic `event_id`.
    pub async fn emit_excluded_hard_cases<B>(
        backend: &B,
        result: &CommunityCascadeResult,
        observed_at: chrono::DateTime<chrono::Utc>,
    ) -> Result<(), BlobError>
    where
        B: FederationDirectory + Sync,
    {
        use crate::federation::hard_case;
        for excluded in &result.excluded {
            backend
                .record_hard_case(hard_case::HardCaseEvent {
                    event_id: hard_case::recipient_excluded_event_id(
                        COMMUNITY,
                        excluded,
                        observed_at,
                    ),
                    kind: hard_case::kind::RECIPIENT_EXCLUDED.to_string(),
                    target_key_id: None,
                    subject_key_id: Some(excluded.clone()),
                    detail: serde_json::json!({
                        "cohort_scope": COMMUNITY,
                        "scope_key_id": excluded,
                        "reason": "no_valid_encryption_pubkeys",
                    }),
                    emitted_at: observed_at,
                })
                .await
                .map_err(|e| BlobError::Backend(format!("emit recipient_excluded: {e}")))?;
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::federation::types::{Community, CommunityMember};

    fn community(policy: Option<serde_json::Value>) -> Community {
        Community {
            community_key_id: "comm-1".into(),
            community_name: "Test Co-op".into(),
            members: vec![CommunityMember {
                key_id: "alice".into(),
                joined_at: chrono::Utc::now(),
                role: None,
            }],
            founded_at: chrono::Utc::now(),
            consensus_protocol: "founder_only".into(),
            policy_blob: policy,
            persist_row_hash: String::new(),
        }
    }

    #[test]
    fn infrastructure_community_is_detected() {
        assert!(is_infrastructure_community(&community(Some(
            serde_json::json!({"cohort_subkind": "infrastructure"})
        ))));
    }

    #[test]
    fn non_infrastructure_communities_are_not_opted_out() {
        // No policy blob.
        assert!(!is_infrastructure_community(&community(None)));
        // A geographic community is still DEK-cascaded.
        assert!(!is_infrastructure_community(&community(Some(
            serde_json::json!({"cohort_subkind": "geographic"})
        ))));
        // An empty / unrelated blob.
        assert!(!is_infrastructure_community(&community(Some(
            serde_json::json!({"some_other_field": "x"})
        ))));
    }
}
