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
    use crate::federation::blobs::{BlobBody, BlobError, BlobStorage, DekKeyState};
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

        active_member_occurrences(backend, &community).await
    }

    /// The community's ACTIVE member occurrences: roster minus effective
    /// revocations, then each remaining identity's active occurrences.
    ///
    /// Active membership = roster minus effective revocations (the
    /// CC 4.4.3.2.2 forward-secrecy read: a removed member is dropped
    /// from the wrap fan-out BEFORE we wrap). The roster-minus-effective-
    /// revocations subtraction is the shared #249 Cut B
    /// [`removed_key_ids_at`](crate::federation::removed_key_ids_at) fold —
    /// the SAME rule the `active_*_members` group-roster readers compose,
    /// so the forward-secrecy subtraction is never forked. Shared by the
    /// wrap fan-out ([`resolve_community_members`]) and the eviction
    /// disclosure predicate ([`may_learn_epoch_fate`], #833) so "who is a
    /// member" has one answer.
    async fn active_member_occurrences<B>(
        backend: &B,
        community: &crate::federation::types::Community,
    ) -> Result<Vec<(String, Option<EncryptionPubkeys>)>, BlobError>
    where
        B: FederationDirectory + Sync,
    {
        let revs = backend
            .list_community_membership_revocations_for(&community.community_key_id)
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

    /// #833 (`BLOB_ENCRYPTION_AT_REST.md` §11.5, I31) — may `viewer_key_id`
    /// be told what became of content sealed under `(community, epoch)`?
    ///
    /// Two legs, either suffices:
    /// 1. the viewer holds a member grant on that epoch — the same predicate
    ///    that authorizes reading a LIVE blob under it (a removed member
    ///    keeps pre-rotation grants by AV-70, until the epoch is destroyed);
    /// 2. the viewer is an active occurrence of a member on the community's
    ///    current roster — the set the next emission would wrap to.
    ///
    /// The second leg is load-bearing, not a convenience: the sweep destroys
    /// an epoch in the same pass that evicts it, and destroy deletes every
    /// member-grant row (I5), so by the time a member asks, the epoch's own
    /// grants are gone. A predicate with only leg 1 would refuse every
    /// member `NotGranted` after a production sweep.
    ///
    /// An unknown community (its record gone) authorizes nobody — the
    /// refusal to a non-member must not name it (I4b), so this returns
    /// `false` rather than an error that would.
    pub async fn may_learn_epoch_fate<B>(
        backend: &B,
        community_key_id: &str,
        epoch: u64,
        viewer_key_id: &str,
    ) -> Result<bool, BlobError>
    where
        B: BlobStorage + FederationDirectory + Sync,
    {
        if backend
            .community_dek_has_member_grant(community_key_id, epoch, viewer_key_id)
            .await?
        {
            return Ok(true);
        }
        let Some(community) = backend
            .lookup_community(community_key_id)
            .await
            .map_err(map_dir_err)?
        else {
            return Ok(false);
        };
        Ok(active_member_occurrences(backend, &community)
            .await?
            .iter()
            .any(|(occ, _)| occ == viewer_key_id))
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

        // v43.0.0 (§10.5) — NEVER SEAL UNDER A NON-ENABLED EPOCH.
        //
        // `disabled` means "rotated past": it still decrypts, so existing
        // content stays readable, but new content must not join it — that is
        // the whole point of rotating. `destroyed` has no key material at
        // all. An absent state is a first mint and is fine.
        //
        // Without this the state column would be decoration: rotation would
        // bump the pointer and sealing would carry on regardless.
        if let Some(state) = backend
            .community_dek_key_state(community_key_id, epoch)
            .await?
        {
            if state != DekKeyState::Enabled {
                return Err(BlobError::InvalidArgument(format!(
                    "community {community_key_id:?} epoch {epoch} is {} — refusing to seal \
                     new content under it. A rotated epoch still DECRYPTS what it sealed; \
                     it does not accept more (BLOB_ENCRYPTION_AT_REST.md §10.5)",
                    state.as_str()
                )));
            }
        }
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
        encrypt_and_cascade_community_scoped(
            backend,
            COMMUNITY,
            community_key_id,
            plaintext,
            media_type,
        )
        .await
    }

    /// [`encrypt_and_cascade_community`] recording the cohort the write
    /// NAMED (`community` or `affiliations`) on the row. Both cohorts share
    /// this cascade and the `CommunityDek` tier; the row's `cohort_scope` is
    /// provenance and must not be collapsed to `community` for an
    /// `affiliations` write (§11.1).
    pub async fn encrypt_and_cascade_community_scoped<B>(
        backend: &B,
        cohort_scope: &str,
        community_key_id: &str,
        plaintext: &[u8],
        media_type: Option<&str>,
    ) -> Result<CommunityCascadeResult, BlobError>
    where
        B: FederationDirectory + BlobStorage + Sync,
    {
        debug_assert!(
            cohort_scope == COMMUNITY || cohort_scope == AFFILIATIONS,
            "the community cascade serves community/affiliations, got {cohort_scope:?}"
        );
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

        // §11.4 / I17 — read the epoch, seal, store, BIND-IF-STILL-CURRENT. A
        // rotation that lands between the read and the bind refuses the
        // bind; the attempt cleans up its own ciphertext row and this loop
        // re-seals under the epoch that is current now. Bounded: a community
        // rotating faster than a write can land is reported, not spun on.
        const ATTEMPTS: usize = 3;
        let mut last_epoch = 0;
        for _ in 0..ATTEMPTS {
            let epoch = backend
                .community_dek_current_epoch(community_key_id)
                .await?;
            match seal_store_bind_at(
                backend,
                cohort_scope,
                community_key_id,
                epoch,
                plaintext,
                media_type,
            )
            .await?
            {
                SealOutcome::Bound(r) => return Ok(r),
                SealOutcome::EpochMoved { at_rest_sha256 } => {
                    tracing::debug!(
                        community = %community_key_id,
                        epoch,
                        sha256_prefix = &hex::encode(at_rest_sha256)[..16],
                        "community cascade: epoch moved under a write; orphan removed, re-sealing"
                    );
                    last_epoch = epoch;
                }
            }
        }
        Err(BlobError::EpochNotCurrent {
            community_key_id: community_key_id.to_owned(),
            epoch: last_epoch,
        })
    }

    /// What one [`seal_store_bind_at`] attempt did.
    #[derive(Debug)]
    pub(crate) enum SealOutcome {
        /// Sealed, stored, bound to `epoch`.
        Bound(CommunityCascadeResult),
        /// The bind was refused because `epoch` is no longer current (or not
        /// enabled). The ciphertext row this attempt stored has been removed
        /// again — **no orphan** — and `at_rest_sha256` names it so a test
        /// can prove that.
        EpochMoved {
            /// The sha of the row that was stored and then removed.
            at_rest_sha256: [u8; 32],
        },
    }

    /// ONE attempt of the community cascade at a caller-named `epoch`:
    /// ensure the DEK, seal, store the ciphertext, bind if `epoch` is still
    /// the current enabled epoch. On a refused bind the stored row is deleted
    /// before returning [`SealOutcome::EpochMoved`]; any other error also
    /// removes the row (a ciphertext row with no binding is an orphan, never
    /// a public blob). [`encrypt_and_cascade_community`] is the door and
    /// loops over this; it is crate-private so no consumer can seal at an
    /// epoch of its choosing.
    pub(crate) async fn seal_store_bind_at<B>(
        backend: &B,
        cohort_scope: &str,
        community_key_id: &str,
        epoch: u64,
        plaintext: &[u8],
        media_type: Option<&str>,
    ) -> Result<SealOutcome, BlobError>
    where
        B: FederationDirectory + BlobStorage + Sync,
    {
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
                cohort_scope,
                crate::federation::StorageFloor::resolved(CryptoTier::CommunityDek),
            )
            .await?;
        match backend
            .community_dek_bind_blob_epoch(&at_rest_sha256, community_key_id, epoch)
            .await
        {
            Ok(()) => Ok(SealOutcome::Bound(CommunityCascadeResult {
                at_rest_sha256,
                epoch,
                granted,
                excluded,
            })),
            Err(BlobError::EpochNotCurrent { .. }) => {
                backend.delete_blob(&at_rest_sha256).await?;
                Ok(SealOutcome::EpochMoved { at_rest_sha256 })
            }
            Err(e) => {
                backend.delete_blob(&at_rest_sha256).await?;
                Err(e)
            }
        }
    }

    /// v43.0.0 (`FSD/BLOB_ENCRYPTION_AT_REST.md` §10.5) — **transition a
    /// community DEK epoch's key state, refusing an unsafe DESTROY.**
    ///
    /// This is the door. [`BlobStorage::community_dek_set_key_state`] is the
    /// raw setter and enforces nothing; callers use this.
    ///
    /// # The DESTROY precondition
    ///
    /// An epoch may become [`DekKeyState::Destroyed`] only when **no object
    /// ON THIS NODE is still sealed under it**. The precondition is LOCAL and
    /// says so (§11.4): persist cannot know what peers hold, and a
    /// precondition that cannot be checked is one that gets asserted. Recall
    /// of fountained copies is the tombstone plane's job, not destroy's. Destroying a DEK whose content still
    /// exists does not erase that content — it **orphans** it, turning a
    /// confidentiality operation into unrecoverable data loss. The content
    /// must be re-sealed under a live epoch or evicted from every holder
    /// first.
    ///
    /// A destroy that cannot prove its precondition **refuses**. That is
    /// deliberate and it is the whole reason V138 adds the
    /// `(community_key_id, epoch)` reverse index: before it, the check was a
    /// full table scan, and a precondition that is expensive to verify is one
    /// that gets skipped — while the thing it guards is irreversible.
    ///
    /// # What this amends
    ///
    /// AV-70 ratifies "forward-only (old-epoch blobs keep grants)" — Option-A's
    /// *once shared, always shared*, the same posture MLS and Tink both take.
    /// `Disabled` IS that behaviour, now one state among three. `Destroyed`
    /// is the amendment, and it is a **stronger** property than either offers,
    /// which is exactly why the precondition is not optional.
    ///
    /// # Errors
    ///
    /// - [`BlobError::InvalidArgument`] — the epoch has no DEK row, or the
    ///   destroy precondition is unmet (the message names the count).
    pub async fn set_key_state<B>(
        backend: &B,
        community_key_id: &str,
        epoch: u64,
        to: DekKeyState,
    ) -> Result<(), BlobError>
    where
        B: BlobStorage + Sync,
    {
        // The epoch must exist. Setting state on a DEK that was never minted
        // would otherwise succeed-by-doing-nothing on some backends.
        let current = backend
            .community_dek_key_state(community_key_id, epoch)
            .await?
            .ok_or_else(|| {
                BlobError::InvalidArgument(format!(
                    "community {community_key_id:?} has no DEK at epoch {epoch}"
                ))
            })?;

        // Destroyed is terminal. Re-enabling a destroyed epoch would claim a
        // key that no longer exists — every read under it would fail at
        // unwrap time instead of at this door, which is a worse place to
        // learn it.
        if current == DekKeyState::Destroyed && to != DekKeyState::Destroyed {
            return Err(BlobError::InvalidArgument(format!(
                "community {community_key_id:?} epoch {epoch} is destroyed; the key material \
                 is gone and no state transition brings it back"
            )));
        }

        // §11.4 / I20 — the CURRENT epoch is the primary: it is retired by
        // rotation, never by this door. Moving it to disabled/destroyed would
        // leave the pointer naming an epoch no write can use. The backend's
        // conditional UPDATE refuses this too; here it gets a reason.
        if to != DekKeyState::Enabled {
            let current_epoch = backend
                .community_dek_current_epoch(community_key_id)
                .await?;
            if epoch == current_epoch {
                return Err(BlobError::InvalidArgument(format!(
                    "refusing to move community {community_key_id:?} epoch {epoch} to \
                     {to:?}: it is the CURRENT epoch. The pointer would keep naming it and \
                     every later write would fail — rotate first \
                     (BLOB_ENCRYPTION_AT_REST.md §11.4)"
                )));
            }
        }

        // The BACKEND's conditional UPDATE is the real guard (§11.4); this
        // early check only produces a friendlier message.
        if to == DekKeyState::Destroyed {
            let remaining = backend
                .community_dek_epoch_object_count(community_key_id, epoch)
                .await?;
            if remaining > 0 {
                return Err(BlobError::InvalidArgument(format!(
                    "refusing to destroy community {community_key_id:?} epoch {epoch}: \
                     {remaining} object(s) are still sealed under it. Destroying the DEK \
                     would ORPHAN them, not erase them — re-seal them under a live epoch or \
                     evict them from every holder first (BLOB_ENCRYPTION_AT_REST.md §10.5)"
                )));
            }
        }

        backend
            .community_dek_set_key_state(community_key_id, epoch, to)
            .await
    }

    /// v43.0.0 (`FSD/BLOB_ENCRYPTION_AT_REST.md` §10.7) — what one sweep did.
    #[derive(Debug, Default, Clone, PartialEq, Eq)]
    pub struct SweepReport {
        /// Epochs moved `enabled` → `disabled` (rotated past; no new seals).
        pub disabled: Vec<u64>,
        /// Epochs moved to `destroyed` — their content was already gone, or
        /// this sweep evicted it under the retention policy.
        pub destroyed: Vec<u64>,
        /// Local objects deleted by this sweep.
        pub evicted_objects: u64,
        /// `(epoch, remaining)` for epochs that could NOT be destroyed
        /// because content is still sealed under them and the retention
        /// policy does not authorize deleting it.
        ///
        /// **Reported, never forced.** An epoch stuck here is the sweep
        /// declining to orphan content, which is the correct outcome — but
        /// an operator watching key material accumulate deserves to see why.
        pub blocked: Vec<(u64, u64)>,
        /// `(epoch, error)` for epochs whose eviction FAILED — a `withdraws`
        /// could not be signed or admitted (§11.5, I18). Nothing was deleted
        /// for that epoch; the next sweep retries. Reported, never swallowed:
        /// the first rebuild deleted anyway and called it fail-honest.
        pub failed: Vec<(u64, String)>,
    }

    /// v43.0.0 (§10.7) — **sweep one community's rotated-past epochs.**
    ///
    /// Intended to run in the BACKGROUND. Re-sealing and eviction are
    /// O(objects at the epoch), so running this inline with a membership
    /// change would stall a community rotation on its own corpus. Callers
    /// that want it now call it directly; the scheduled path calls the same
    /// function.
    ///
    /// # What it does, per epoch below the current one
    ///
    /// 1. `enabled` → **`disabled`**. A rotated-past epoch must stop
    ///    accepting new seals; it keeps decrypting what it already sealed.
    ///    This is AV-70's ratified behaviour and is always safe.
    /// 2. If the retention policy authorizes it (`retain_past_epochs = Some(n)`
    ///    and the epoch is more than `n` behind), **evict** its local objects
    ///    and then **destroy** the epoch.
    /// 3. Otherwise, destroy only if the epoch is already empty; else record
    ///    it in [`SweepReport::blocked`].
    ///
    /// # The retention policy is opt-in, and that is deliberate
    ///
    /// `retain_past_epochs = NULL` means retain indefinitely — today's
    /// behaviour, and the default. Deletion is destructive and irreversible,
    /// so it happens only where an operator has said how much history to
    /// keep. OpenMLS ships the same knob for the same reason: a delivery
    /// service cannot guarantee epoch-N content arrives before epoch N+1
    /// begins, and eager deletion loses in-flight content.
    ///
    /// # What this does NOT do
    ///
    /// It does not recall copies already fountained to peers. **Rotation is
    /// not recall** (§10.6): the mechanism that reaches other holders is the
    /// tombstone plane, and this sweep is local. An operator who reads
    /// `evicted_objects` as "erased from the mesh" is wrong in a way that
    /// matters.
    pub async fn sweep_rotated_epochs<B>(
        backend: &B,
        community_key_id: &str,
        signer: &crate::signing::LocalSigner,
        now: chrono::DateTime<chrono::Utc>,
    ) -> Result<SweepReport, BlobError>
    where
        B: BlobStorage + Sync,
    {
        let current = backend
            .community_dek_current_epoch(community_key_id)
            .await?;
        let retain = backend
            .community_dek_retain_past_epochs(community_key_id)
            .await?;
        let mut report = SweepReport::default();

        for (epoch, state) in backend.community_dek_epochs(community_key_id).await? {
            // The current epoch is the primary. Never touched.
            if epoch >= current || state == DekKeyState::Destroyed {
                continue;
            }

            if state == DekKeyState::Enabled {
                backend
                    .community_dek_set_key_state(community_key_id, epoch, DekKeyState::Disabled)
                    .await?;
                report.disabled.push(epoch);
            }

            // Does the policy authorize deleting this epoch's content?
            // `current - epoch > n` — an epoch exactly `n` behind is still
            // retained, so `retain_past_epochs = 0` means "keep only the
            // current epoch" rather than "keep nothing".
            let deletable = retain.is_some_and(|n| current.saturating_sub(epoch) > n);

            if deletable {
                // §11.5 — retracts the local holds_bytes announcement (a
                // withdraws per row, via the signer) BEFORE deleting. A
                // failed retraction leaves the bytes in place (I18); this
                // epoch is reported and the sweep moves on.
                match backend
                    .community_dek_evict_epoch_objects(community_key_id, epoch, signer, now)
                    .await
                {
                    Ok(n) => report.evicted_objects += n,
                    Err(e) => {
                        report.failed.push((epoch, e.to_string()));
                        continue;
                    }
                }
            }

            let remaining = backend
                .community_dek_epoch_object_count(community_key_id, epoch)
                .await?;
            if remaining == 0 {
                // Goes through `set_key_state`, not the raw setter, so the
                // DESTROY precondition is re-checked at the door rather than
                // trusted from the count we just read.
                set_key_state(backend, community_key_id, epoch, DekKeyState::Destroyed).await?;
                report.destroyed.push(epoch);
            } else {
                report.blocked.push((epoch, remaining));
            }
        }
        Ok(report)
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
        // v43.0.0 (§11.3) — AUTHORIZE FIRST. The destroyed-epoch refusal
        // below names the community; a non-grantee must never reach it.
        if !backend
            .community_dek_has_member_grant(&community_key_id, epoch, viewer_key_id)
            .await?
        {
            return Err(BlobError::NotGranted {
                sha256_hex: hex::encode(at_rest_sha256),
                viewer_key_id: viewer_key_id.to_owned(),
            });
        }
        let body = backend.get_blob(at_rest_sha256).await?;
        let envelope_bytes = match body {
            Some(BlobBody::Inline(b)) => b,
            Some(_) => {
                return Err(BlobError::InvalidArgument(format!(
                    "at-rest blob {} is not an inline body",
                    hex::encode(at_rest_sha256)
                )))
            }
            None => {
                return Err(BlobError::NotHeld {
                    sha256_hex: hex::encode(at_rest_sha256),
                })
            }
        };
        let envelope = AtRestEnvelope::from_bytes(&envelope_bytes).map_err(map_at_rest_err)?;
        read_for_community_viewer_sealed(backend, at_rest_sha256, viewer_key_id, &envelope).await
    }

    /// The decrypt half of [`read_for_community_viewer`], for a caller that
    /// has ALREADY authorized the viewer and parsed the envelope. The
    /// destroyed-epoch refusal lives here — i.e. strictly after
    /// authorization — so it can name the epoch to a grantee without
    /// disclosing the binding to anyone else.
    pub async fn read_for_community_viewer_sealed<B>(
        backend: &B,
        at_rest_sha256: &[u8; 32],
        viewer_key_id: &str,
        envelope: &AtRestEnvelope,
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
        // Defense in depth: the §11.3 door authorized already; a direct
        // caller of this function is re-checked rather than trusted.
        if !backend
            .community_dek_has_member_grant(&community_key_id, epoch, viewer_key_id)
            .await?
        {
            return Err(BlobError::NotGranted {
                sha256_hex: hex::encode(at_rest_sha256),
                viewer_key_id: viewer_key_id.to_owned(),
            });
        }
        let wrapped = backend
            .community_dek_get_self_retention(&community_key_id, epoch)
            .await?
            .ok_or_else(|| {
                // NULL self-retention ⇔ destroyed (V139's CHECK): the key
                // material is gone. Said to a GRANTEE, after authorization.
                BlobError::InvalidArgument(format!(
                    "community {community_key_id:?} epoch {epoch} is destroyed — the key material \
                     is gone and this blob is permanently unreadable \
                     (BLOB_ENCRYPTION_AT_REST.md §11.4)"
                ))
            })?;
        let content_master = backend.load_or_init_content_master().await?;
        let dek = unwrap_dek_for_persist(&content_master, &wrapped).map_err(map_at_rest_err)?;
        open(&dek, envelope).map_err(map_at_rest_err)
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

/// Fixture helpers for [`lifecycle_harness`]. Generic over the backend so
/// the same setup runs on every implementation — the harness is only
/// cross-backend if its fixture is too.
#[cfg(any(test, feature = "test-anchor"))]
#[allow(dead_code)]
pub mod lifecycle_support {
    use crate::federation::{BlobStorage, FederationDirectory};

    /// Register a key, its occurrence, and give the occurrence real
    /// content-KEM pubkeys — without which the member is **excluded
    /// fail-secure** from the DEK fan-out and the harness would be asserting
    /// against an empty grant set.
    pub async fn seed_member<B>(backend: &B, identity_key_id: &str, occurrence_key_id: &str)
    where
        B: BlobStorage + FederationDirectory + Sync,
    {
        use crate::federation::tier_ingest::test_support as ts;
        use crate::federation::types::identity_type;
        use base64::{engine::general_purpose::STANDARD as B64, Engine as _};

        for k in [identity_key_id, occurrence_key_id] {
            ts::register_hybrid_key_as(backend, k, k, identity_type::USER).await;
        }
        let (_xp, x_pub, _mp, ml_pub) =
            crate::federation::identity_aggregate::mint_content_kem_keypair().expect("mint kem");
        backend
            .put_identity_occurrence_local(crate::federation::types::IdentityOccurrence {
                identity_key_id: identity_key_id.to_owned(),
                occurrence_key_id: occurrence_key_id.to_owned(),
                device_class: crate::federation::types::device_class::SERVER.into(),
                hardware_attestation: None,
                asserted_at: chrono::Utc::now(),
                valid_until: None,
                encryption_pubkeys: Some(crate::federation::EncryptionPubkeys {
                    x25519_base64: B64.encode(x_pub),
                    ml_kem_768_base64: B64.encode(&ml_pub),
                }),
                transport_binding: None,
                persist_row_hash: String::new(),
            })
            .await
            .unwrap_or_else(|e| panic!("seed occurrence {occurrence_key_id}: {e}"));
    }

    /// Create a community whose own key is the signing authority, with the
    /// given `(identity, occurrence)` members seeded and keyed.
    pub async fn seed_community<B>(backend: &B, community_key_id: &str, members: &[(&str, &str)])
    where
        B: BlobStorage + FederationDirectory + Sync,
    {
        seed_community_with(
            backend,
            community_key_id,
            members,
            crate::federation::types::identity_type::USER,
            None,
        )
        .await
    }

    /// As [`seed_community`], with control over the community key's
    /// identity type (SUBSTRATE_PERSIST makes an `infrastructure`-labeled
    /// community AUTHORIZED per SecReview F2) and its policy blob.
    pub async fn seed_community_with<B>(
        backend: &B,
        community_key_id: &str,
        members: &[(&str, &str)],
        community_identity_type: &str,
        policy_blob: Option<serde_json::Value>,
    ) where
        B: BlobStorage + FederationDirectory + Sync,
    {
        use crate::federation::tier_ingest::test_support as ts;

        ts::register_hybrid_key_as(
            backend,
            community_key_id,
            community_key_id,
            community_identity_type,
        )
        .await;
        for (ident, occ) in members {
            seed_member(backend, ident, occ).await;
        }
        let roster = members
            .iter()
            .map(|(ident, _)| crate::federation::types::CommunityMember {
                key_id: (*ident).to_owned(),
                joined_at: chrono::Utc::now(),
                role: None,
            })
            .collect();
        backend
            .put_community(ts::sign_community(
                community_key_id,
                crate::federation::types::Community {
                    community_key_id: community_key_id.to_owned(),
                    community_name: "Lifecycle Co-op".into(),
                    members: roster,
                    founded_at: chrono::Utc::now(),
                    consensus_protocol: crate::federation::types::consensus_protocol::MAJORITY
                        .to_owned(),
                    policy_blob,
                    persist_row_hash: String::new(),
                },
            ))
            .await
            .unwrap_or_else(|e| panic!("seed community {community_key_id}: {e}"));
    }

    /// Revoke a member. The community DEK epoch bump rides this write
    /// transactionally (AV-70), so this single call IS the rotation — there
    /// is no separate "rotate" API to call, and a harness that invented one
    /// would be testing something the substrate does not do.
    ///
    /// `effective_at` is NOW rather than future-dated: a future-dated
    /// community revocation is rejected at write time (SecReview F4), and
    /// `removed_key_ids_at` deliberately excludes future-dated rows from the
    /// removed set.
    pub async fn revoke_member<B>(backend: &B, community_key_id: &str, removed_identity: &str)
    where
        B: BlobStorage + FederationDirectory + Sync,
    {
        use crate::federation::tier_ingest::test_support as ts;
        let now = chrono::Utc::now();
        backend
            .put_community_membership_revocation(ts::sign_community_membership_revocation(
                community_key_id,
                crate::federation::types::CommunityMembershipRevocation {
                    community_key_id: community_key_id.to_owned(),
                    removed_identity_key_id: removed_identity.to_owned(),
                    removed_at: now,
                    effective_at: now,
                    reason: None,
                    witness_set: vec![],
                    persist_row_hash: String::new(),
                },
            ))
            .await
            .unwrap_or_else(|e| panic!("revoke {removed_identity} from {community_key_id}: {e}"));
    }
}

/// v43.0.0 (`FSD/BLOB_ENCRYPTION_AT_REST.md` §10) — **the cohort lifecycle
/// harness: create → encrypt → decrypt → rotate → key-state.**
///
/// Cross-backend by construction, in the shape the `exercise_*` witnesses
/// already use: one function, called from every backend's test module, so a
/// backend that diverges cannot pass by having its own copy of the test.
/// Generic rather than `&dyn` because [`BlobStorage`] returns `impl Future`
/// and is not object-safe.
///
/// # What it drives, and why each step is here
///
/// 1. **CREATE** — a community with two keyed members.
/// 2. **ENCRYPT** — seal a blob under epoch 0.
/// 3. **DECRYPT** — both members read it. Proves the grant fan-out reached
///    every member, not just the first.
/// 4. **ROTATE** — revoke one member. The epoch bump is transactional with
///    the revocation write (AV-70), so this is one call, not two.
/// 5. **ENCRYPT AGAIN** — seal a second blob, which lands on epoch 1.
/// 6. **FORWARD SECRECY** — the removed member CANNOT read the post-rotation
///    blob. This is the property rotation exists for.
/// 7. **FORWARD-ONLY** — the removed member CAN still read the
///    pre-rotation blob. This is AV-70's ratified "once shared, always
///    shared", and asserting it stops a future change from silently
///    strengthening the guarantee without amending the threat model.
/// 8. **KEY STATE** — disable epoch 0: it still decrypts, accepts no new
///    seals, and cannot be destroyed while its content is live.
///
/// Steps 6 and 7 are the pair that matters. Either alone is satisfiable by a
/// wrong implementation — one by revoking everything, the other by revoking
/// nothing.
#[cfg(any(test, feature = "test-anchor"))]
#[allow(dead_code)]
pub mod lifecycle_harness {
    use crate::federation::{BlobStorage, DekKeyState, FederationDirectory};

    /// Drive the full cycle against one backend. `tag` namespaces the keys so
    /// two backends can share a database without colliding.
    pub async fn exercise_cohort_lifecycle_43<B>(backend: &B, tag: &str)
    where
        B: BlobStorage + FederationDirectory + Sync,
    {
        use crate::federation::community_dek::orchestrate::{
            encrypt_and_cascade_community, read_for_community_viewer, set_key_state,
        };

        let run = uuid::Uuid::new_v4().simple().to_string();
        let comm = format!("{tag}-comm-{run}");
        let alice = format!("{tag}-alice-{run}");
        let alice_occ = format!("{tag}-alice-occ-{run}");
        let bob = format!("{tag}-bob-{run}");
        let bob_occ = format!("{tag}-bob-occ-{run}");

        // ── 1. CREATE ────────────────────────────────────────────────────
        super::lifecycle_support::seed_community(
            backend,
            &comm,
            &[(&alice, &alice_occ), (&bob, &bob_occ)],
        )
        .await;

        // ── 2. ENCRYPT (epoch 0) ─────────────────────────────────────────
        let before = encrypt_and_cascade_community(backend, &comm, b"pre-rotation minutes", None)
            .await
            .unwrap_or_else(|e| panic!("{tag}: seal at epoch 0: {e}"));
        assert_eq!(
            before.epoch, 0,
            "{tag}: a never-rotated community is epoch 0"
        );
        for occ in [&alice_occ, &bob_occ] {
            assert!(
                before.granted.contains(occ),
                "{tag}: {occ} must hold a grant; granted={:?} excluded={:?}",
                before.granted,
                before.excluded
            );
        }

        // ── 3. DECRYPT — both members ────────────────────────────────────
        for occ in [&alice_occ, &bob_occ] {
            let got = read_for_community_viewer(backend, &before.at_rest_sha256, occ)
                .await
                .unwrap_or_else(|e| panic!("{tag}: {occ} reads the pre-rotation blob: {e}"));
            assert_eq!(got, b"pre-rotation minutes", "{tag}: {occ} round trip");
        }

        // ── 4. ROTATE — revoking bob bumps the epoch transactionally ─────
        super::lifecycle_support::revoke_member(backend, &comm, &bob).await;

        // ── 5. ENCRYPT AGAIN — lands on the NEW epoch ────────────────────
        let after = encrypt_and_cascade_community(backend, &comm, b"post-rotation minutes", None)
            .await
            .unwrap_or_else(|e| panic!("{tag}: seal after rotation: {e}"));
        assert!(
            after.epoch > before.epoch,
            "{tag}: rotation must advance the epoch ({} -> {})",
            before.epoch,
            after.epoch
        );
        assert!(
            !after.granted.contains(&bob_occ),
            "{tag}: the removed member must NOT be granted on the new epoch, got {:?}",
            after.granted
        );

        // ── 6. FORWARD SECRECY — the removed member cannot read new content
        let err = read_for_community_viewer(backend, &after.at_rest_sha256, &bob_occ)
            .await
            .expect_err("a removed member must not read post-rotation content");
        assert!(
            matches!(err, crate::federation::BlobError::NotGranted { .. }),
            "{tag}: expected NotGranted for the removed member, got {err:?}"
        );

        // ...while the remaining member can.
        let got = read_for_community_viewer(backend, &after.at_rest_sha256, &alice_occ)
            .await
            .unwrap_or_else(|e| panic!("{tag}: alice reads post-rotation: {e}"));
        assert_eq!(got, b"post-rotation minutes");

        // ── 7. FORWARD-ONLY — the removed member KEEPS pre-rotation access
        //
        // AV-70, ratified: "once shared, always shared". If this ever starts
        // failing, the threat model changed and §10.5's destroy path — not an
        // incidental edit — should be the reason.
        let got = read_for_community_viewer(backend, &before.at_rest_sha256, &bob_occ)
            .await
            .unwrap_or_else(|e| {
                panic!("{tag}: AV-70 forward-only — bob keeps pre-rotation access: {e}")
            });
        assert_eq!(got, b"pre-rotation minutes");

        // ── 8. KEY STATE on the rotated-past epoch ───────────────────────
        set_key_state(backend, &comm, before.epoch, DekKeyState::Disabled)
            .await
            .unwrap_or_else(|e| panic!("{tag}: disable epoch 0: {e}"));

        // It still decrypts — the difference between disabled and destroyed.
        let got = read_for_community_viewer(backend, &before.at_rest_sha256, &alice_occ)
            .await
            .unwrap_or_else(|e| panic!("{tag}: a disabled epoch still decrypts: {e}"));
        assert_eq!(got, b"pre-rotation minutes");

        // And it cannot be destroyed while its content is live: destroying
        // would ORPHAN the blob, not erase it.
        let err = set_key_state(backend, &comm, before.epoch, DekKeyState::Destroyed)
            .await
            .expect_err("destroying an epoch with live content must be refused");
        assert!(
            err.to_string().contains("still sealed under it"),
            "{tag}: the refusal must name the precondition, got: {err}"
        );

        // ── 9. TRANSFER SHIPS CIPHERTEXT — no decrypt/re-encrypt hop ─────
        //
        // The optimization the envelope design exists for: a blob is sealed
        // ONCE under a DEK, and the DEK is WRAPPED per recipient. What
        // crosses the wire is the stored ciphertext, byte for byte.
        //
        // Pinned because it is invisible to every other test. A change that
        // decrypted on serve and re-encrypted per peer would return the same
        // plaintext to every viewer, pass every round-trip assertion above,
        // and cost O(payload) per transfer instead of O(key) per recipient —
        // silently, and worst exactly at fan-out.
        let stored = backend
            .get_blob(&after.at_rest_sha256)
            .await
            .unwrap_or_else(|e| panic!("{tag}: read the stored bytes: {e}"))
            .unwrap_or_else(|| panic!("{tag}: the sealed blob must be present"));
        let crate::federation::BlobBody::Inline(stored_bytes) = stored else {
            panic!("{tag}: a sealed blob is stored inline");
        };

        assert!(
            stored_bytes.starts_with(&crate::federation::at_rest_cascade::AT_REST_ENVELOPE_MAGIC),
            "{tag}: what is STORED must be the at-rest envelope, not plaintext"
        );
        assert_ne!(
            stored_bytes.as_slice(),
            b"post-rotation minutes",
            "{tag}: the stored bytes must not be the plaintext"
        );

        // ── 10. THE COHORT-AGNOSTIC READ ────────────────────────────────
        //
        // What a server or agent actually calls: address + viewer, no
        // knowledge of cohort, DEK, epoch or grant. It must return the SAME
        // plaintext the cohort-specific read returns, and it must refuse the
        // same non-viewer — otherwise the convenience door is a bypass.
        let via_generic = crate::federation::at_rest_cascade::orchestrate::read_any_for_viewer(
            backend,
            &after.at_rest_sha256,
            &alice_occ,
        )
        .await
        .unwrap_or_else(|e| panic!("{tag}: the cohort-agnostic read: {e}"));
        assert_eq!(
            via_generic, b"post-rotation minutes",
            "{tag}: the generic read must return the same plaintext as the specific one"
        );

        let err = crate::federation::at_rest_cascade::orchestrate::read_any_for_viewer(
            backend,
            &after.at_rest_sha256,
            &bob_occ,
        )
        .await
        .expect_err("the generic read must enforce the SAME grant check");
        assert!(
            matches!(err, crate::federation::BlobError::NotGranted { .. }),
            "{tag}: a convenience door that skips authorization is a bypass, got {err:?}"
        );

        // ── 11. THE SWEEP, ON THIS BACKEND (§11.5, §11.9 / I12) ─────────
        //
        // Rotated-past epoch 0 is `disabled`. Authorize deletion, sweep,
        // and assert the three things the sweep must do IN ORDER: retract
        // the announcement (withdraws), delete the bytes, destroy the key.
        // The first implementation's sweep had zero postgres coverage; this
        // step runs on every backend that runs the harness.
        let sweeper = crate::federation::at_rest_cascade::blob_invariants::node_signer(
            backend,
            &format!("{tag}-sweeper-{run}"),
        )
        .await;
        let sweeper_id = sweeper.derived_key_id();
        // Announce epoch 0's sealed bytes as this sweeper node, so there is
        // an announcement to retract.
        let crate::federation::BlobBody::Inline(sealed0) = backend
            .get_blob(&before.at_rest_sha256)
            .await
            .unwrap()
            .unwrap()
        else {
            panic!("{tag}: sealed blob is inline");
        };
        backend
            .put_blob_signing_at(
                crate::federation::types::cohort_scope::COMMUNITY,
                crate::federation::StorageFloor::resolved(
                    crate::federation::types::cohort_scope::CryptoTier::CommunityDek,
                ),
                &before.at_rest_sha256,
                crate::federation::BlobBody::Inline(sealed0),
                None,
                &sweeper_id,
                &crate::signing::LocalSignerHardwareAdapter::new(sweeper.clone()),
                chrono::Utc::now(),
                uuid::Uuid::new_v4(),
            )
            .await
            .unwrap_or_else(|e| panic!("{tag}: announce epoch-0 bytes: {e}"));
        assert!(
            backend
                .list_holders(&before.at_rest_sha256)
                .await
                .unwrap()
                .contains(&sweeper_id),
            "{tag}: precondition — the sweeper is a listed holder"
        );
        backend
            .community_dek_set_retain_past_epochs(&comm, Some(0))
            .await
            .unwrap();
        let report = crate::federation::community_dek::orchestrate::sweep_rotated_epochs(
            backend,
            &comm,
            &sweeper,
            chrono::Utc::now(),
        )
        .await
        .unwrap_or_else(|e| panic!("{tag}: sweep: {e}"));
        assert_eq!(
            report.evicted_objects, 1,
            "{tag}: epoch 0's one object is evicted"
        );
        assert_eq!(
            report.destroyed,
            vec![before.epoch],
            "{tag}: epoch 0 is destroyed"
        );
        assert!(
            !backend
                .list_holders(&before.at_rest_sha256)
                .await
                .unwrap()
                .contains(&sweeper_id),
            "{tag}: the announcement was RETRACTED (withdraws) before the bytes went"
        );
        assert!(
            !backend.has_blob(&before.at_rest_sha256).await.unwrap(),
            "{tag}: the bytes are gone"
        );
        assert!(
            backend
                .community_dek_get_self_retention(&comm, before.epoch)
                .await
                .unwrap()
                .is_none()
                && backend
                    .community_dek_member_grant_recipients(&comm, before.epoch)
                    .await
                    .unwrap()
                    .is_empty(),
            "{tag}: destroyed ⇒ no key material (self-retention AND member grants)"
        );
        // The CURRENT epoch is untouched.
        let got = read_for_community_viewer(backend, &after.at_rest_sha256, &alice_occ)
            .await
            .unwrap_or_else(|e| panic!("{tag}: the current epoch is never swept: {e}"));
        assert_eq!(got, b"post-rotation minutes");

        // The content address is the hash of the CIPHERTEXT, which is what
        // lets dedup and fountain coding operate on sealed bytes — and why
        // encrypt-then-fountain (§10.8) is a gate rather than a convention.
        use sha2::Digest as _;
        let recomputed: [u8; 32] = sha2::Sha256::digest(&stored_bytes).into();
        assert_eq!(
            recomputed, after.at_rest_sha256,
            "{tag}: the at-rest address must be SHA-256 OF THE CIPHERTEXT — if this \
             drifts, content addressing has moved off the sealed bytes and a peer can \
             no longer verify what it holds without the key"
        );
    }
}
