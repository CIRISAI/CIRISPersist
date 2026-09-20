//! v45.0.0 (CIRISPersist#871, `FSD/MEDIA_SOURCE.md` §4–§5) — **the rendition
//! index and the sized holder claim**, the pure half.
//!
//! CC 3.3.13: *"Renditions are separate blobs … any derived rendition is its
//! own blob with its own digest and `derived_from` naming the original."*
//! A row whose `media.derived_from` is set therefore describes TWO blobs,
//! and the question a renderer asks — *"which renditions of this digest
//! exist?"* — is a fold over every such row. V149 `blob_renditions` is that
//! fold, projected in the same write that admits the row and removed by the
//! same retraction fold that retires it (the V109 `consent_peer_set`
//! discipline). DERIVED / rebuildable: it is a read accelerator over
//! `federation_attestations`, never new authority.
//!
//! CC 5.3.2.5: *"Every blob carries its size, and size is checked first."*
//! [`HolderClaim`] is the puller's budget: the holder's key and the byte
//! length its SIGNED `holds_bytes` claim declares, so a `ContentFetch` caps
//! its read BEFORE hashing (AV-88) and refuses a holder whose number
//! disagrees with the descriptor it is fetching for (AV-89).
//!
//! Nothing here validates the struct — that is `media_source::check_media_source`,
//! the one gate at every door. [`rendition_of_row`] reads only what the
//! projection needs and answers `None` for anything else; a row the gate
//! admitted and this fold declines is a row with no `derived_from`.

use serde::{Deserialize, Serialize};

use super::{Attestation, Error};

/// One row of V149 `blob_renditions`: a blob that is a rendition of another.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Rendition {
    /// The rendition blob's own sha256 (the struct's `digest`), lowercase hex.
    pub rendition_sha256_hex: String,
    /// The original it derives from (the struct's `derived_from`), lowercase hex.
    pub original_sha256_hex: String,
    /// The rendition's RFC 6838 essence (`type/subtype`), as the struct declared it.
    pub format: String,
    /// The rendition's byte length (CC 5.3.2.5: every blob carries its size).
    pub size: u64,
    /// Layout hint, when the struct carried one.
    pub width: Option<u32>,
    /// Layout hint, when the struct carried one.
    pub height: Option<u32>,
    /// [`role_of`] the struct's `name`: one of the closed set, else `other`.
    pub role: String,
    /// The attestation row this projection was folded from; the retraction
    /// fold keys on it.
    pub source_attestation_id: String,
    /// The row's `cohort_scope` — a rendition is placed in the same crossing
    /// as its original (FSD §5, the placement rule).
    pub cohort_scope: String,
}

/// v45.0.0 (#871, FSD §4) — one live `holds_bytes` claim with the byte
/// length the holder SIGNED. The puller's budget for a `ContentFetch`.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct HolderClaim {
    /// The holder (`attesting_key_id` of the claim).
    pub key_id: String,
    /// The byte length the claim declares (`envelope.size`).
    pub size: u64,
}

/// The closed rendition roles (FSD §5). A struct `name` that is exactly one
/// of these IS that role; anything else, including no name, is `other`.
pub const ROLES: [&str; 4] = ["thumbnail", "poster", "transcode", "caption_track"];

/// The role a rendition takes from the struct's `name`: an exact match on
/// one of [`ROLES`], else `"other"`.
#[must_use]
pub fn role_of(name: Option<&str>) -> &'static str {
    match name {
        Some(n) => ROLES.iter().copied().find(|r| *r == n).unwrap_or("other"),
        None => "other",
    }
}

/// True iff `s` is exactly 64 lowercase hex characters — the spelling the
/// struct's digest members carry and the index is keyed by.
fn is_lower_hex64(s: &str) -> bool {
    s.len() == 64
        && s.bytes()
            .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
}

/// The [`Rendition`] a row projects, or `None` when the row describes no
/// rendition. **Pure and permissive by design**: it reads
/// `attestation_envelope.media` and answers `Some` only when that struct
/// has a `derived_from` of 64 lowercase hex, a `digest` of 64 hex, an
/// integer `size > 0` and a string `format`; `width` / `height` ride along
/// when they are `u32`. It does NO other validation — the door gate
/// (`check_media_source`) refused a malformed struct before this fold ever
/// sees the row, and a fold that re-validated would be a second, drifting
/// gate.
#[must_use]
pub fn rendition_of_row(row: &Attestation) -> Option<Rendition> {
    let media = row.attestation_envelope.get("media")?.as_object()?;
    let derived_from = media.get("derived_from")?.as_str()?;
    if !is_lower_hex64(derived_from) {
        return None;
    }
    let digest = media.get("digest")?.as_str()?;
    if digest.len() != 64 || !digest.bytes().all(|b| b.is_ascii_hexdigit()) {
        return None;
    }
    let size = media.get("size")?.as_u64()?;
    if size == 0 {
        return None;
    }
    let format = media.get("format")?.as_str()?;
    let dim = |k: &str| -> Option<u32> {
        media
            .get(k)
            .and_then(serde_json::Value::as_u64)
            .and_then(|v| u32::try_from(v).ok())
    };
    Some(Rendition {
        rendition_sha256_hex: digest.to_ascii_lowercase(),
        original_sha256_hex: derived_from.to_owned(),
        format: format.to_owned(),
        size,
        width: dim("width"),
        height: dim("height"),
        role: role_of(media.get("name").and_then(serde_json::Value::as_str)).to_owned(),
        source_attestation_id: row.attestation_id.clone(),
        cohort_scope: row.cohort_scope.clone(),
    })
}

/// The byte length a `holds_bytes` claim's envelope declares, or `None`
/// when the claim carries no `size`, a non-integer one, or zero. The
/// receive door refuses those from this cut on (FSD §4); a legacy row
/// without one is not a holder a puller can budget for, so the sized read
/// SKIPS it rather than failing.
#[must_use]
pub fn holder_claim_size(envelope: &serde_json::Value) -> Option<u64> {
    envelope
        .get("size")
        .and_then(serde_json::Value::as_u64)
        .filter(|s| *s > 0)
}

/// v45.0.0 (#871) — **the pure tail of `list_holders_sized`**, shared by
/// the three backends so they cannot disagree on what a sized holder is.
/// `candidates` are `(attesting_key_id, envelope)` pairs the backend has
/// already narrowed to the claim's type prefix and folded the holder's own
/// `withdraws` / `recants` out of; this keeps the ones that cite `full_hex`
/// in `evidence_refs` (the prefix-collision discriminator) and carry a
/// positive `size`, one per holder (first wins), sorted by key.
pub fn sized_holder_claims(
    full_hex: &str,
    candidates: impl IntoIterator<Item = (String, serde_json::Value)>,
) -> Vec<HolderClaim> {
    let mut out: Vec<HolderClaim> = Vec::new();
    for (key_id, env) in candidates {
        if !super::admission::envelope_binds_content(&env, full_hex) {
            continue;
        }
        let Some(size) = holder_claim_size(&env) else {
            continue;
        };
        if out.iter().any(|c| c.key_id == key_id) {
            continue;
        }
        out.push(HolderClaim { key_id, size });
    }
    out.sort_by(|a, b| a.key_id.cmp(&b.key_id));
    out
}

/// The 32-byte digest a `list_derived_hex` argument names, or
/// `InvalidArgument` when it is not 64 hex characters. Every backend decodes
/// through this so the three agree on what a malformed argument is.
pub fn decode_sha256_hex(hex64: &str) -> Result<[u8; 32], Error> {
    let bytes = hex::decode(hex64)
        .map_err(|e| Error::InvalidArgument(format!("sha256 hex `{hex64}`: {e}")))?;
    <[u8; 32]>::try_from(bytes).map_err(|b| {
        Error::InvalidArgument(format!(
            "sha256 hex `{hex64}`: {} bytes, expected 32",
            b.len()
        ))
    })
}

// ─────────────────────────────────────────────────────────────────────────
// v45.0.0 (#871, FSD §5) — the placement rule, enforced where persist can
// see it.
// ─────────────────────────────────────────────────────────────────────────

/// What the placement check asks a backend: the `cohort_scope` under which
/// THIS node holds the blob `sha256`, or `None` when it holds no such blob.
///
/// Sqlite and postgres answer from the blob row they wrote
/// ([`super::BlobStorage::blob_cohort_scope`]: the cohort the write NAMED).
/// Memory has no blob storage and answers `None` — it never holds an
/// original, so on that backend the rule is always the node's (FSD §5).
/// The trait exists so the three attestation doors run ONE gate by ONE name
/// (`store::parity` pins the sequence) rather than two backends checking
/// and one silently not.
pub trait HeldBlobScope {
    /// The stored `cohort_scope` of the blob `sha256` if this node holds it.
    fn held_blob_cohort_scope(
        &self,
        sha256: &[u8; 32],
    ) -> impl std::future::Future<Output = Result<Option<String>, Error>> + Send;
}

/// The `derived_from` digest a row's struct names, when it names one.
/// Reads only that member: a row reaching the placement check has already
/// passed `check_media_source`, so the spelling is 64 hex by then.
#[must_use]
pub fn derived_from_of(envelope: &serde_json::Value) -> Option<&str> {
    envelope
        .get("media")?
        .as_object()?
        .get("derived_from")?
        .as_str()
}

/// **The placement rule, pure.** CC 3.3.13: a rendition inherits the
/// original's `cohort_scope` and audience and is placed in the same
/// crossing. Given the scope a row names and the scope this node holds the
/// original under, refuse a mismatch by the member that made the row a
/// rendition (`derived_from`), naming both scopes.
pub fn check_placement_against(row_scope: &str, original_scope: &str) -> Result<(), Error> {
    if row_scope == original_scope {
        return Ok(());
    }
    Err(super::media_source::MediaSourceError {
        member: "derived_from".to_owned(),
        reason: format!(
            "this node holds the original at cohort_scope `{original_scope}`; a rendition is \
             placed in the same crossing as its original (CC 3.3.13, FSD/MEDIA_SOURCE.md §5), \
             not `{row_scope}`"
        ),
    }
    .into())
}

/// **The placement gate at the six attestation write doors** (three ingest
/// doors, three local writers; FSD §5–§6). A row whose struct names a
/// `derived_from` this node holds is refused unless it names the original's
/// own `cohort_scope`. A row with no `derived_from`, or whose original this
/// node does not hold, passes: the rule is then the node's, not persist's.
///
/// AV-76 TIER 4 — it reads the blob store, so it runs after the crypto and
/// beside the other state-reading gates, never ahead of them.
pub async fn check_rendition_placement<B: HeldBlobScope + ?Sized>(
    backend: &B,
    envelope: &serde_json::Value,
    cohort_scope: &str,
) -> Result<(), Error> {
    let Some(derived_from) = derived_from_of(envelope) else {
        return Ok(());
    };
    let sha = decode_sha256_hex(derived_from)?;
    let Some(held) = backend.held_blob_cohort_scope(&sha).await? else {
        return Ok(());
    };
    check_placement_against(cohort_scope, &held)
}

/// v45.0.0 (#871) — the backend-agnostic witness bodies for the two reads
/// and the retraction fold, run by memory, sqlite and postgres from
/// [`runs`] and from each backend's projection-helper test (the helper is
/// backend-specific; what it feeds is not).
#[cfg(test)]
pub(crate) mod witnesses {
    use super::{HolderClaim, Rendition};
    use crate::federation::media_source_invariants::bodies::{hex64, media_row, put, row};
    use crate::federation::tier_ingest::test_support as ts;
    use crate::federation::types::identity_type::USER;
    use crate::federation::types::{attestation_type, cohort_scope};
    use crate::federation::{holds_bytes_attestation_type, Attestation, FederationDirectory};

    fn sha_of(seed: &str) -> [u8; 32] {
        use sha2::Digest as _;
        sha2::Sha256::digest(seed.as_bytes()).into()
    }

    /// A signed, sized `holds_bytes` claim by `holder` over `cited` whose
    /// type prefix is that of `typed` (the two differ only in a
    /// prefix-collision case).
    fn claim(id: &str, holder: &str, typed: &[u8; 32], cited: &[u8; 32], size: u64) -> Attestation {
        let env = serde_json::json!({
            "kind": "holds_bytes",
            "evidence_refs": [hex::encode(cited)],
            "size": size,
        });
        let mut r = row(id, holder, holder, env, cohort_scope::FEDERATION);
        r.attestation_type = holds_bytes_attestation_type(typed);
        ts::reseal(&mut r);
        r
    }

    fn retraction(id: &str, signer: &str, kind: &str, references: &str) -> Attestation {
        let mut r = row(
            id,
            signer,
            signer,
            serde_json::json!({"references_attestation_id": references, "withdrawal_reason": "871"}),
            cohort_scope::FEDERATION,
        );
        r.attestation_type = kind.to_owned();
        ts::reseal(&mut r);
        r
    }

    /// `list_holders_sized`: one sorted entry per holder with the size the
    /// claim SIGNED; a holder's own `withdraws` or `recants` folds its claim
    /// out; a claim on a prefix-colliding digest is not this blob's; a
    /// second holder's retraction of a claim it did not make folds nothing.
    pub async fn sized_holders_fold_retractions(d: &dyn FederationDirectory, s: &str) {
        let (h1, h2, h3) = (
            format!("871-h1-{s}"),
            format!("871-h2-{s}"),
            format!("871-h3-{s}"),
        );
        for h in [&h1, &h2, &h3] {
            ts::register_identity_key(d, h, USER).await;
        }
        let sha = sha_of(&format!("871-bytes-{s}"));
        // Same 8-hex type prefix, different digest.
        let mut colliding = sha;
        colliding[31] ^= 0xff;
        assert_eq!(
            holds_bytes_attestation_type(&sha),
            holds_bytes_attestation_type(&colliding)
        );
        assert!(d.list_holders_sized(&sha).await.unwrap().is_empty());

        // h3 first so the sort is visible; h1 claims the colliding digest too.
        let c3 = format!("871-c3-{s}");
        put(d, claim(&c3, &h3, &sha, &sha, 30)).await.unwrap();
        let c1 = format!("871-c1-{s}");
        put(d, claim(&c1, &h1, &sha, &sha, 10)).await.unwrap();
        put(
            d,
            claim(&format!("871-c1x-{s}"), &h1, &colliding, &colliding, 99),
        )
        .await
        .unwrap();
        let c2 = format!("871-c2-{s}");
        put(d, claim(&c2, &h2, &sha, &sha, 20)).await.unwrap();
        assert_eq!(
            d.list_holders_sized(&sha).await.unwrap(),
            vec![
                HolderClaim {
                    key_id: h1.clone(),
                    size: 10
                },
                HolderClaim {
                    key_id: h2.clone(),
                    size: 20
                },
                HolderClaim {
                    key_id: h3.clone(),
                    size: 30
                },
            ],
            "sorted by key, one per holder, the signed size, the collision excluded"
        );
        assert_eq!(
            d.list_holders_sized(&colliding).await.unwrap(),
            vec![HolderClaim {
                key_id: h1.clone(),
                size: 99
            }]
        );

        // h2 retracts h1's claim: not h2's to retract; nothing folds.
        put(
            d,
            retraction(
                &format!("871-w-foreign-{s}"),
                &h2,
                attestation_type::WITHDRAWS,
                &c1,
            ),
        )
        .await
        .unwrap();
        assert_eq!(d.list_holders_sized(&sha).await.unwrap().len(), 3);

        // h1 withdraws its own claim; h3 recants its own claim.
        put(
            d,
            retraction(
                &format!("871-w1-{s}"),
                &h1,
                attestation_type::WITHDRAWS,
                &c1,
            ),
        )
        .await
        .unwrap();
        put(
            d,
            retraction(&format!("871-r3-{s}"), &h3, attestation_type::RECANTS, &c3),
        )
        .await
        .unwrap();
        assert_eq!(
            d.list_holders_sized(&sha).await.unwrap(),
            vec![HolderClaim {
                key_id: h2.clone(),
                size: 20
            }],
            "a withdrawn and a recanted claim are not holders a puller can budget for"
        );
        // The retraction on `sha` did not touch h1's claim on the other digest.
        assert_eq!(d.list_holders_sized(&colliding).await.unwrap().len(), 1);
    }

    /// `store_plaintext_local` (FSD §4, #863 ask 1): the bytes are kept at
    /// `federation` / plaintext and readable; NO claim is announced (neither
    /// holder read sees one); the content address is checked; a second call
    /// is idempotent.
    #[cfg(any(feature = "sqlite", feature = "postgres"))]
    pub async fn plaintext_local_keeps_verified_bytes_unannounced<B>(b: &B, s: &str)
    where
        B: crate::federation::BlobStorage + FederationDirectory + Sync,
    {
        use crate::federation::types::cohort_scope::CryptoTier;
        use crate::federation::{BlobBody, BlobError};
        let bytes = format!("871 commons bytes {s}").into_bytes();
        let sha: [u8; 32] = {
            use sha2::Digest as _;
            sha2::Sha256::digest(&bytes).into()
        };
        // Content-address checked BEFORE anything is stored.
        let err = b
            .store_plaintext_local(&sha, b"not those bytes".to_vec(), None)
            .await
            .unwrap_err();
        assert!(matches!(err, BlobError::HashMismatch { .. }), "{err}");
        assert!(b.get_blob(&sha).await.unwrap().is_none());

        b.store_plaintext_local(&sha, bytes.clone(), Some("image/png"))
            .await
            .unwrap();
        match b.get_blob(&sha).await.unwrap() {
            Some(BlobBody::Inline(got)) => assert_eq!(got, bytes),
            other => panic!("expected inline bytes, got {other:?}"),
        }
        assert_eq!(
            b.blob_cohort_scope(&sha).await.unwrap().as_deref(),
            Some(cohort_scope::FEDERATION)
        );
        assert_eq!(
            b.blob_crypto_tier(&sha).await.unwrap(),
            Some(CryptoTier::Plaintext)
        );
        assert!(
            b.list_holders(&sha).await.unwrap().is_empty()
                && b.list_holders_sized(&sha).await.unwrap().is_empty(),
            "LocalOnly: nothing is announced"
        );
        // Idempotent on the address.
        b.store_plaintext_local(&sha, bytes, None).await.unwrap();
    }

    /// Two admitted rendition rows of one original, both signed by `signer`,
    /// ready for the backend's projection helper. Returned in the order the
    /// index must NOT depend on (`r_hi` sorts after `r_lo` by digest).
    pub async fn two_rendition_rows(
        d: &dyn FederationDirectory,
        s: &str,
    ) -> (String, Attestation, Attestation) {
        let (signer, target) = (format!("871-rs-{s}"), format!("871-rt-{s}"));
        ts::register_identity_key(d, &signer, USER).await;
        ts::register_identity_key(d, &target, USER).await;
        let original = hex64(&format!("871-orig-{s}"));
        let (a, b) = (hex64(&format!("871-ra-{s}")), hex64(&format!("871-rb-{s}")));
        let (lo, hi) = if a < b { (a, b) } else { (b, a) };
        let mk = |id: &str, digest: &str, name: &str, size: u64| {
            media_row(
                id,
                &signer,
                &target,
                digest,
                serde_json::json!({"digest": digest, "size": size, "format": "image/webp",
                                   "width": 32, "height": 24, "name": name, "derived_from": original}),
                cohort_scope::FEDERATION,
            )
        };
        let r_hi = mk(&format!("871-row-hi-{s}"), &hi, "poster", 700);
        let r_lo = mk(&format!("871-row-lo-{s}"), &lo, "thumbnail", 500);
        put(d, r_hi.clone())
            .await
            .expect("a rendition row is admitted");
        put(d, r_lo.clone())
            .await
            .expect("a rendition row is admitted");
        (original, r_hi, r_lo)
    }

    /// After the backend's helper projected `r_hi` then `r_lo`: the index
    /// answers both ordered by digest with every column; re-projecting a row
    /// upserts rather than duplicates; the signer's `withdraws` of one row
    /// folds only that row's projection; `purge_attestation_projections`
    /// folds the other.
    pub async fn index_reads_and_folds<F, Fut>(
        d: &dyn FederationDirectory,
        original: &str,
        r_hi: &Attestation,
        r_lo: &Attestation,
        reproject: F,
        s: &str,
    ) where
        F: Fn(Attestation) -> Fut,
        Fut: std::future::Future<Output = ()>,
    {
        let expect = |r: &Attestation| {
            let m = &r.attestation_envelope["media"];
            Rendition {
                rendition_sha256_hex: m["digest"].as_str().unwrap().to_owned(),
                original_sha256_hex: original.to_owned(),
                format: "image/webp".into(),
                size: m["size"].as_u64().unwrap(),
                width: Some(32),
                height: Some(24),
                role: m["name"].as_str().unwrap().to_owned(),
                source_attestation_id: r.attestation_id.clone(),
                cohort_scope: cohort_scope::FEDERATION.into(),
            }
        };
        assert_eq!(
            d.list_derived_hex(original).await.unwrap(),
            vec![expect(r_lo), expect(r_hi)],
            "ordered by rendition digest, every column, regardless of projection order"
        );
        assert_eq!(
            d.list_derived_hex(&original.to_ascii_uppercase())
                .await
                .unwrap()
                .len(),
            2,
            "the argument is hex, case-insensitive"
        );
        assert!(matches!(
            d.list_derived_hex("not-hex").await,
            Err(crate::federation::Error::InvalidArgument(_))
        ));
        assert!(d
            .list_derived_hex(&hex64(&format!("871-unrelated-{s}")))
            .await
            .unwrap()
            .is_empty());

        // Upsert: the same rendition digest projected again is one row.
        reproject(r_hi.clone()).await;
        assert_eq!(d.list_derived_hex(original).await.unwrap().len(), 2);

        // The signer withdraws `r_hi`: its projection leaves; `r_lo` stays.
        put(
            d,
            retraction(
                &format!("871-w-hi-{s}"),
                &r_hi.attesting_key_id,
                attestation_type::WITHDRAWS,
                &r_hi.attestation_id,
            ),
        )
        .await
        .expect("the producer withdraws its own row");
        assert_eq!(
            d.list_derived_hex(original).await.unwrap(),
            vec![expect(r_lo)],
            "a retired row's rendition leaves the index with it"
        );
        // The reaper's projection drop folds the other.
        d.purge_attestation_projections(&r_lo.attestation_id)
            .await
            .unwrap();
        assert!(d.list_derived_hex(original).await.unwrap().is_empty());
    }
}

#[cfg(test)]
mod runs {
    fn suffix() -> String {
        uuid::Uuid::new_v4().simple().to_string()
    }
    macro_rules! runners {
        ($modname:ident, $fresh:expr) => {
            mod $modname {
                use super::super::witnesses;
                #[tokio::test]
                async fn sized_holders_fold_retractions_871() {
                    let Some(b) = $fresh.await else { return };
                    witnesses::sized_holders_fold_retractions(&b, &super::suffix()).await
                }
            }
        };
    }
    #[cfg(any(feature = "sqlite", feature = "postgres"))]
    macro_rules! blob_runners {
        ($modname:ident, $fresh:expr) => {
            mod $modname {
                use super::super::witnesses;
                #[tokio::test]
                async fn plaintext_local_keeps_verified_bytes_unannounced_871() {
                    let Some(b) = $fresh.await else { return };
                    witnesses::plaintext_local_keeps_verified_bytes_unannounced(
                        &b,
                        &super::suffix(),
                    )
                    .await
                }
            }
        };
    }
    runners!(memory, async {
        Some(crate::store::memory::MemoryBackend::new())
    });
    #[cfg(feature = "sqlite")]
    runners!(sqlite, async {
        use crate::store::Backend as _;
        let b = crate::store::sqlite::SqliteBackend::open_in_memory()
            .await
            .unwrap();
        b.run_migrations().await.unwrap();
        Some(b)
    });
    #[cfg(feature = "sqlite")]
    blob_runners!(sqlite_blob, async {
        use crate::store::Backend as _;
        let b = crate::store::sqlite::SqliteBackend::open_in_memory()
            .await
            .unwrap();
        b.run_migrations().await.unwrap();
        Some(b)
    });
    #[cfg(feature = "postgres")]
    runners!(postgres, async {
        use crate::store::Backend as _;
        let dsn = crate::test_pg::dsn()?;
        let b = crate::store::postgres::PostgresBackend::connect(&dsn)
            .await
            .unwrap();
        b.run_migrations().await.unwrap();
        Some(b)
    });
    #[cfg(feature = "postgres")]
    blob_runners!(postgres_blob, async {
        use crate::store::Backend as _;
        let dsn = crate::test_pg::dsn()?;
        let b = crate::store::postgres::PostgresBackend::connect(&dsn)
            .await
            .unwrap();
        b.run_migrations().await.unwrap();
        Some(b)
    });
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::federation::types::{attestation_tier, attestation_type};

    fn hex64(seed: &str) -> String {
        use sha2::Digest as _;
        hex::encode(sha2::Sha256::digest(seed.as_bytes()))
    }

    fn row_with(envelope: serde_json::Value) -> Attestation {
        let at = chrono::Utc::now();
        Attestation {
            attestation_id: "r-1".into(),
            attesting_key_id: "k".into(),
            attested_key_id: "k".into(),
            attestation_type: attestation_type::SCORES.to_owned(),
            weight: None,
            asserted_at: at,
            expires_at: None,
            attestation_envelope: envelope,
            original_content_hash: String::new(),
            scrub_signature_classical: String::new(),
            scrub_signature_pqc: None,
            scrub_key_id: "k".into(),
            scrub_timestamp: at,
            pqc_completed_at: None,
            persist_row_hash: String::new(),
            subject_key_ids: Vec::new(),
            withdraws_admission_rule: None,
            cohort_scope: "community".into(),
            tier: attestation_tier::FEDERATION.to_owned(),
            promoted_at: None,
            additional_scrubs: Vec::new(),
        }
    }

    #[test]
    fn role_is_an_exact_match_on_the_closed_set_else_other() {
        for r in ROLES {
            assert_eq!(role_of(Some(r)), r);
        }
        assert_eq!(role_of(None), "other");
        assert_eq!(role_of(Some("Thumbnail")), "other");
        assert_eq!(role_of(Some("thumbnail ")), "other");
        assert_eq!(role_of(Some("cat.jpg")), "other");
        assert_eq!(role_of(Some("")), "other");
    }

    #[test]
    fn a_full_struct_projects_every_column() {
        let (orig, thumb) = (hex64("orig"), hex64("thumb"));
        let row = row_with(serde_json::json!({
            "evidence_refs": [thumb],
            "media": {"digest": thumb, "size": 512, "format": "image/webp",
                      "width": 32, "height": 24, "name": "poster", "derived_from": orig},
        }));
        assert_eq!(
            rendition_of_row(&row),
            Some(Rendition {
                rendition_sha256_hex: thumb.clone(),
                original_sha256_hex: orig.clone(),
                format: "image/webp".into(),
                size: 512,
                width: Some(32),
                height: Some(24),
                role: "poster".into(),
                source_attestation_id: "r-1".into(),
                cohort_scope: "community".into(),
            })
        );
    }

    #[test]
    fn hints_and_name_are_optional_and_the_digest_is_lowercased() {
        let (orig, thumb) = (hex64("orig"), hex64("thumb"));
        let row = row_with(serde_json::json!({
            "media": {"digest": thumb.to_ascii_uppercase(), "size": 1, "format": "image/png",
                      "derived_from": orig},
        }));
        let r = rendition_of_row(&row).expect("a rendition with no hints");
        assert_eq!((r.width, r.height, r.role.as_str()), (None, None, "other"));
        assert_eq!(
            r.rendition_sha256_hex, thumb,
            "keyed by the lowercase spelling"
        );
        // A hint that is not a u32 is dropped, not refused (the gate's job).
        let row = row_with(serde_json::json!({
            "media": {"digest": thumb, "size": 1, "format": "image/png",
                      "derived_from": orig, "width": -1, "height": 4294967296u64},
        }));
        let r = rendition_of_row(&row).unwrap();
        assert_eq!((r.width, r.height), (None, None));
    }

    #[test]
    fn a_row_without_the_four_required_members_projects_nothing() {
        let (orig, thumb) = (hex64("orig"), hex64("thumb"));
        let good = serde_json::json!({"digest": thumb, "size": 5, "format": "image/png", "derived_from": orig});
        assert!(rendition_of_row(&row_with(serde_json::json!({"media": good}))).is_some());
        // no media at all / media not an object
        assert!(rendition_of_row(&row_with(serde_json::json!({}))).is_none());
        assert!(rendition_of_row(&row_with(serde_json::json!({"media": "x"}))).is_none());
        // each required member absent or the wrong shape
        for (member, bad) in [
            ("derived_from", serde_json::Value::Null),
            ("derived_from", serde_json::json!(orig.to_ascii_uppercase())),
            ("derived_from", serde_json::json!(&orig[..63])),
            ("digest", serde_json::Value::Null),
            ("digest", serde_json::json!("zz")),
            ("size", serde_json::Value::Null),
            ("size", serde_json::json!(0)),
            ("size", serde_json::json!(-4)),
            ("size", serde_json::json!("12")),
            ("format", serde_json::Value::Null),
            ("format", serde_json::json!(7)),
        ] {
            let mut m = good.clone();
            if bad.is_null() {
                m.as_object_mut().unwrap().remove(member);
            } else {
                m[member] = bad.clone();
            }
            assert!(
                rendition_of_row(&row_with(serde_json::json!({"media": m}))).is_none(),
                "{member} = {bad} must not project"
            );
        }
    }

    #[test]
    fn a_holder_claim_size_is_a_positive_integer_or_nothing() {
        assert_eq!(
            holder_claim_size(&serde_json::json!({"size": 12})),
            Some(12)
        );
        assert_eq!(holder_claim_size(&serde_json::json!({})), None);
        assert_eq!(holder_claim_size(&serde_json::json!({"size": 0})), None);
        assert_eq!(holder_claim_size(&serde_json::json!({"size": -1})), None);
        assert_eq!(holder_claim_size(&serde_json::json!({"size": "12"})), None);
        assert_eq!(holder_claim_size(&serde_json::json!({"size": 1.5})), None);
    }

    #[test]
    fn the_sized_tail_keeps_cited_sized_claims_once_per_holder_sorted() {
        let sha = hex64("bytes");
        let other = hex64("other-bytes");
        let claim = |k: &str, env: serde_json::Value| (k.to_owned(), env);
        let got = sized_holder_claims(
            &sha,
            vec![
                claim("z", serde_json::json!({"evidence_refs": [sha], "size": 9})),
                // prefix collision: a different digest is not this blob
                claim(
                    "a",
                    serde_json::json!({"evidence_refs": [other], "size": 9}),
                ),
                // legacy claim with no size: not a holder a puller can budget for
                claim("b", serde_json::json!({"evidence_refs": [sha]})),
                claim("c", serde_json::json!({"evidence_refs": [sha], "size": 0})),
                claim("m", serde_json::json!({"evidence_refs": [sha], "size": 4})),
                // a second claim by the same holder: first wins
                claim("m", serde_json::json!({"evidence_refs": [sha], "size": 5})),
            ],
        );
        assert_eq!(
            got,
            vec![
                HolderClaim {
                    key_id: "m".into(),
                    size: 4
                },
                HolderClaim {
                    key_id: "z".into(),
                    size: 9
                },
            ]
        );
    }

    #[test]
    fn the_digest_argument_decodes_or_is_an_invalid_argument() {
        let h = hex64("x");
        assert_eq!(hex::encode(decode_sha256_hex(&h).unwrap()), h);
        assert_eq!(
            hex::encode(decode_sha256_hex(&h.to_ascii_uppercase()).unwrap()),
            h,
            "hex is case-insensitive on the way in"
        );
        for bad in ["", "zz", &h[..62], &format!("{h}00")] {
            assert!(
                matches!(decode_sha256_hex(bad), Err(Error::InvalidArgument(_))),
                "{bad:?}"
            );
        }
    }
}
