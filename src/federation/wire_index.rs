//! v21.1.0 (CIRISPersist#507b) — the shared signed-wire content-hash index
//! (`signed_wire_index`, V111): ONE table, `PRIMARY KEY (kind, content_hash)`,
//! covering every kind CIRISEdge serves — the 5 primary signed planes (#507c),
//! the 5 E4 keyless-declaration planes (#504), and the operational
//! org/org_membership/partner_record trio. 13 of the 14
//! [`super::replication_policy::EnvelopeKind`]s (`Revocation`, the key-level
//! revocation plane, is out of #507's scope — see the trait doc on
//! [`super::FederationDirectory::lookup_signed_record_by_content_hash`]).
//!
//! # The lockstep fact
//!
//! The content hash of a signed record is the lowercase-hex sha256 over the
//! EXACT JSON bytes persist's read surface returns for that record —
//! `sha256(serde_json::to_vec(record))`, the same value a `list_signed_*_since`
//! / `list_attestations_since` bulk read serializes when the caller does
//! `serde_json::to_vec` on an element. CIRISEdge keys its fetch map by
//! `sha256(wire_bytes)` per `(kind, hash)`; hashing the identical bytes on
//! both ends makes persist's hash equal edge's BY CONSTRUCTION — no separate
//! canonicalization step, no cross-repo hash-function pin.
//!
//! # What lives here vs. in the backends
//!
//! This module holds the backend-agnostic half: computing the hash
//! ([`content_hash_of`]) and encoding/decoding the kind-specific `record_key`
//! JSON blob ([`record_key`] / [`record_key_field`]) a backend stores
//! alongside `(kind, content_hash)` so [`super::FederationDirectory::lookup_signed_record_by_content_hash`]
//! can reload the record without a second index. The actual
//! `INSERT ... ON CONFLICT` upsert is backend-specific (sqlite/postgres SQL
//! dialect, or the memory backend's in-process map), called from each
//! covered kind's put path right after (ideally in the same transaction as)
//! the primary write.

use super::Error;

/// Encode a kind-specific primary-key tuple as a small JSON object —
/// `record_key(&[("key_id", key_id)])` for a single-column PK,
/// `record_key(&[("identity_key_id", a), ("occurrence_key_id", b)])` for a
/// composite one. Field order is whatever the caller passes (not
/// semantically meaningful — only [`record_key_field`] ever reads it back
/// out, by name).
#[must_use]
pub fn record_key(fields: &[(&str, &str)]) -> String {
    let mut map = serde_json::Map::with_capacity(fields.len());
    for (k, v) in fields {
        map.insert(
            (*k).to_string(),
            serde_json::Value::String((*v).to_string()),
        );
    }
    serde_json::Value::Object(map).to_string()
}

/// Parse a stored `record_key` blob and pull one string field back out —
/// the inverse of [`record_key`]'s per-field encoding. Used by each
/// backend's `lookup_signed_record_by_content_hash` to reconstruct the
/// lookup call (e.g. `lookup_public_key(record_key_field(rk, "key_id")?)`).
pub fn record_key_field(record_key_json: &str, field: &str) -> Result<String, Error> {
    let value: serde_json::Value = serde_json::from_str(record_key_json)
        .map_err(|e| Error::Backend(format!("signed_wire_index record_key parse: {e}")))?;
    value
        .get(field)
        .and_then(|v| v.as_str())
        .map(str::to_owned)
        .ok_or_else(|| {
            Error::Backend(format!(
                "signed_wire_index record_key missing field '{field}'"
            ))
        })
}

/// The lockstep hash: lowercase-hex sha256 over `serde_json::to_vec(record)`
/// — the exact bytes persist's read surface returns for `record`. Any
/// serializable read-surface type works (`KeyRecord`, `Attestation`,
/// `SignedFamily`, `SignedIdentityOccurrence`, ...); the caller passes
/// whatever the corresponding `list_signed_*_since` element type is.
pub fn content_hash_of<T: serde::Serialize>(record: &T) -> Result<String, Error> {
    let bytes = serde_json::to_vec(record)
        .map_err(|e| Error::Backend(format!("signed_wire_index content hash serialize: {e}")))?;
    Ok(content_hash_of_bytes(&bytes))
}

/// The lockstep hash computed directly over already-serialized bytes — for
/// callers that already hold the exact wire bytes (e.g. re-serializing a
/// reloaded record inside `lookup_signed_record_by_content_hash`'s
/// defensive recompute) and don't want to serialize twice.
#[must_use]
pub fn content_hash_of_bytes(bytes: &[u8]) -> String {
    use sha2::Digest as _;
    hex::encode(sha2::Sha256::digest(bytes))
}

/// v24.1.0 (CIRISPersist#547) — the `("Key", content_hash) → record_key` entry
/// for one `federation_keys` row, as `(content_hash, record_key)`.
///
/// # Why this is a function and not two lines at each write site
///
/// `signed_wire_index` is a SECOND list that must agree with `federation_keys`,
/// and #547 is what happens when it does not. Three `UPDATE federation_keys`
/// paths — `adopt_scrub_upgrade`, `supersede_canonical_record`,
/// `adopt_genesis_reanchor` — mutated the row and left the index holding the
/// PRE-mutation hash. `put_public_key` was the only writer that maintained it.
/// So a node scrub-upgraded while running advertised the hash of its NEW row
/// (`list_signed_key_records_since` re-serializes the current row) while the
/// index still pointed at the old one: the peer asked for exactly the ref we
/// had just advertised and `lookup_signed_record_by_content_hash` returned
/// `None`. Measured in CIRISServer adopting v22.0.1 — advertise and reload were
/// byte-identical, so it was never a serialization drift; it was index KEY
/// COVERAGE, which is why `rebuild_signed_wire_index()` cured it.
///
/// That is the same shape as #541's preserve-set ≢ verified-set: two lists,
/// maintained separately, free to disagree. The remedy is the same — make the
/// agreement come from ONE derivation. Every `federation_keys` write that
/// changes a **serialized** column ends here, so the hash the index carries is
/// computed from the exact value the read surface re-serializes, by one
/// function, from the one row the writer is about to store.
///
/// Callers hold the pair across a `move` closure (the SQL backends compute it
/// before the row is consumed by the statement, exactly as `put_public_key`
/// already did) and upsert it with their own dialect-specific statement.
pub(crate) fn key_entry(row: &crate::federation::KeyRecord) -> Result<(String, String), Error> {
    let content_hash = content_hash_of(&crate::federation::SignedKeyRecord {
        record: row.clone(),
    })?;
    Ok((content_hash, record_key(&[("key_id", &row.key_id)])))
}

/// v21.1.0 (CIRISPersist#507b) — the shared per-kind reload dispatcher every
/// backend's `lookup_signed_record_by_content_hash` calls after its own
/// `SELECT record_key FROM signed_wire_index WHERE (kind, content_hash) = ...`
/// hit. Written once, against `&dyn FederationDirectory` — the SAME trait
/// surface every backend (and the capsule's `OpsDirectory` proxy) already
/// implements — so the reload logic is not duplicated per backend.
///
/// Parses `record_key_json` per `kind` (the field set is kind-specific — see
/// each arm), reloads via the corresponding EXISTING read method (the same
/// one the `list_signed_*_since` bulk surface uses), and re-serializes
/// EXACTLY as that read surface's element type would — the same bytes
/// [`content_hash_of`] would hash. Returns `Ok(None)` if the underlying
/// record has since vanished (never found — the record_key pointed at
/// something that's gone, e.g. a promoted/retired/superseded row that no
/// longer matches the filter the read method applies) rather than erroring;
/// the caller (the point-read) treats that identically to a hash mismatch.
///
/// `Organization`/`OrgMembership` carry their own single-signer signature
/// fields inline (same shape as `KeyRecord`/`Attestation`) — no bulk
/// signed-since surface exists (or is needed) for them, so this reloads via
/// the plain `list_organizations_since`/`list_org_memberships_since` (which
/// already return the fully-signed row) and searches by `attestation_id`.
/// `PartnerRecord`'s M-of-N steward quorum is external to the row
/// (`SignedPartnerRecord`), so that arm uses
/// `list_signed_partner_records_since` instead.
///
/// The `_since(None, u32::MAX)` full-scan arms (`Family`/`Community`/
/// `LocationProof`/`*MembershipRevocation`/`Organization`/`OrgMembership`/
/// `PartnerRecord`) are O(n) in table size — acceptable for a point-read
/// fallback/backfill path (not a per-request hot path); the 3 primary
/// planes with a natural per-parent grouping (`IdentityOccurrence`,
/// `IdentityOccurrenceRevocation`, `TransportDestination`) and the 2 with a
/// direct single-row getter (`Key`, `Attestation`) reload targeted instead.
pub async fn reload_record_bytes(
    dir: &dyn super::FederationDirectory,
    kind: &str,
    record_key_json: &str,
) -> Result<Option<Vec<u8>>, Error> {
    let to_bytes = |e: serde_json::Error, what: &str| {
        Error::Backend(format!("signed_wire_index reload {what}: {e}"))
    };
    let bytes = match kind {
        "Key" => {
            let key_id = record_key_field(record_key_json, "key_id")?;
            match dir.lookup_public_key(&key_id).await? {
                Some(record) => Some(
                    serde_json::to_vec(&super::SignedKeyRecord { record })
                        .map_err(|e| to_bytes(e, "Key"))?,
                ),
                None => None,
            }
        }
        "Attestation" => {
            let attestation_id = record_key_field(record_key_json, "attestation_id")?;
            match dir.get_attestation(&attestation_id).await? {
                Some(a) if a.tier == super::types::attestation_tier::FEDERATION => {
                    Some(serde_json::to_vec(&a).map_err(|e| to_bytes(e, "Attestation"))?)
                }
                _ => None,
            }
        }
        "IdentityOccurrence" => {
            let identity_key_id = record_key_field(record_key_json, "identity_key_id")?;
            let occurrence_key_id = record_key_field(record_key_json, "occurrence_key_id")?;
            let rows = dir
                .list_signed_identity_occurrences_for(&identity_key_id)
                .await?;
            match rows
                .into_iter()
                .find(|r| r.identity_occurrence.occurrence_key_id == occurrence_key_id)
            {
                Some(r) => {
                    Some(serde_json::to_vec(&r).map_err(|e| to_bytes(e, "IdentityOccurrence"))?)
                }
                None => None,
            }
        }
        "TransportDestination" => {
            let occurrence_key_id = record_key_field(record_key_json, "occurrence_key_id")?;
            let transport_kind = record_key_field(record_key_json, "transport_kind")?;
            let rows = dir
                .list_signed_transport_destinations_for(&occurrence_key_id)
                .await?;
            match rows
                .into_iter()
                .find(|r| r.transport_destination.transport_kind == transport_kind)
            {
                Some(r) => {
                    Some(serde_json::to_vec(&r).map_err(|e| to_bytes(e, "TransportDestination"))?)
                }
                None => None,
            }
        }
        "IdentityOccurrenceRevocation" => {
            let identity_key_id = record_key_field(record_key_json, "identity_key_id")?;
            let occurrence_key_id = record_key_field(record_key_json, "occurrence_key_id")?;
            let rows = dir
                .list_signed_identity_occurrence_revocations_for(&identity_key_id)
                .await?;
            match rows
                .into_iter()
                .find(|r| r.identity_occurrence_revocation.occurrence_key_id == occurrence_key_id)
            {
                Some(r) => Some(
                    serde_json::to_vec(&r)
                        .map_err(|e| to_bytes(e, "IdentityOccurrenceRevocation"))?,
                ),
                None => None,
            }
        }
        "Family" => {
            let family_key_id = record_key_field(record_key_json, "family_key_id")?;
            let rows = dir.list_signed_families_since(None, u32::MAX).await?;
            match rows
                .into_iter()
                .find(|r| r.family.family_key_id == family_key_id)
            {
                Some(r) => Some(serde_json::to_vec(&r).map_err(|e| to_bytes(e, "Family"))?),
                None => None,
            }
        }
        "Community" => {
            let community_key_id = record_key_field(record_key_json, "community_key_id")?;
            let rows = dir.list_signed_communities_since(None, u32::MAX).await?;
            match rows
                .into_iter()
                .find(|r| r.community.community_key_id == community_key_id)
            {
                Some(r) => Some(serde_json::to_vec(&r).map_err(|e| to_bytes(e, "Community"))?),
                None => None,
            }
        }
        "LocationProof" => {
            let subject_key_id = record_key_field(record_key_json, "subject_key_id")?;
            let asserted_at = record_key_field(record_key_json, "asserted_at")?;
            let rows = dir
                .list_signed_location_proofs_since(None, u32::MAX)
                .await?;
            match rows.into_iter().find(|r| {
                r.location_proof.subject_key_id == subject_key_id
                    && r.location_proof.asserted_at.to_rfc3339() == asserted_at
            }) {
                Some(r) => Some(serde_json::to_vec(&r).map_err(|e| to_bytes(e, "LocationProof"))?),
                None => None,
            }
        }
        "FamilyMembershipRevocation" => {
            let family_key_id = record_key_field(record_key_json, "family_key_id")?;
            let removed_identity_key_id =
                record_key_field(record_key_json, "removed_identity_key_id")?;
            let rows = dir
                .list_signed_family_membership_revocations_since(None, u32::MAX)
                .await?;
            match rows.into_iter().find(|r| {
                r.family_membership_revocation.family_key_id == family_key_id
                    && r.family_membership_revocation.removed_identity_key_id
                        == removed_identity_key_id
            }) {
                Some(r) => Some(
                    serde_json::to_vec(&r)
                        .map_err(|e| to_bytes(e, "FamilyMembershipRevocation"))?,
                ),
                None => None,
            }
        }
        "CommunityMembershipRevocation" => {
            let community_key_id = record_key_field(record_key_json, "community_key_id")?;
            let removed_identity_key_id =
                record_key_field(record_key_json, "removed_identity_key_id")?;
            let rows = dir
                .list_signed_community_membership_revocations_since(None, u32::MAX)
                .await?;
            match rows.into_iter().find(|r| {
                r.community_membership_revocation.community_key_id == community_key_id
                    && r.community_membership_revocation.removed_identity_key_id
                        == removed_identity_key_id
            }) {
                Some(r) => Some(
                    serde_json::to_vec(&r)
                        .map_err(|e| to_bytes(e, "CommunityMembershipRevocation"))?,
                ),
                None => None,
            }
        }
        "Organization" => {
            let attestation_id = record_key_field(record_key_json, "attestation_id")?;
            let rows = dir.list_organizations_since(None, u32::MAX).await?;
            match rows
                .into_iter()
                .find(|r| r.attestation_id == attestation_id)
            {
                Some(r) => Some(serde_json::to_vec(&r).map_err(|e| to_bytes(e, "Organization"))?),
                None => None,
            }
        }
        "OrgMembership" => {
            let attestation_id = record_key_field(record_key_json, "attestation_id")?;
            let rows = dir.list_org_memberships_since(None, u32::MAX).await?;
            match rows
                .into_iter()
                .find(|r| r.attestation_id == attestation_id)
            {
                Some(r) => Some(serde_json::to_vec(&r).map_err(|e| to_bytes(e, "OrgMembership"))?),
                None => None,
            }
        }
        "PartnerRecord" => {
            let attestation_id = record_key_field(record_key_json, "attestation_id")?;
            let rows = dir
                .list_signed_partner_records_since(None, u32::MAX)
                .await?;
            match rows
                .into_iter()
                .find(|r| r.partner_record.attestation_id == attestation_id)
            {
                Some(r) => Some(serde_json::to_vec(&r).map_err(|e| to_bytes(e, "PartnerRecord"))?),
                None => None,
            }
        }
        other => {
            return Err(Error::Backend(format!(
                "signed_wire_index: unknown or unsupported kind '{other}'"
            )))
        }
    };
    Ok(bytes)
}

/// v30.12.0 (CIRISPersist#634) — the **subject-scoped** wire refs: every
/// `(kind_token, content_hash, record_key)` the signed-wire index holds for
/// `subject_key_id`, computed from the same reads and the same
/// [`content_hash_of`] the index write hooks use.
///
/// # What this is for
///
/// CIRISEdge#462's subject-scoped RECEIVE-axis pull needs `EnvelopeRef`s that
/// resolve through [`FederationDirectory::lookup_signed_record_by_content_hash`](super::FederationDirectory::lookup_signed_record_by_content_hash).
/// Edge could not use `list_signed_records(kind, subject)` for this: it returns
/// `canonical_json = serde_json::to_value(row)`, and with no
/// `serde_json/preserve_order` in the workspace `to_value` SORTS object keys,
/// so `sha256(to_vec(canonical_json)) != sha256(to_vec(row))` — not the wire
/// index hash. So edge composed the per-kind subject reads and hashed the
/// STRUCTS itself, which works only while those `_for` reads serialize
/// byte-identically to what the `_since` reads hashed. That held, but it was
/// edge asserting a property about persist's serialization.
///
/// Now persist asserts it, in one place, gated.
///
/// # The kind token is `EnvelopeKind`, NOT `ReplicatedKind`
///
/// #634 proposed returning `ReplicatedKind`. It cannot: `ReplicatedKind::as_str`
/// is `"key_record"` / `"identity_occurrence"`, while `signed_wire_index.kind`
/// — and therefore the `kind` argument of
/// `lookup_signed_record_by_content_hash` — is the `EnvelopeKind` token
/// `"Key"` / `"IdentityOccurrence"`. Two vocabularies name these same planes,
/// and handing back the one that does NOT key the index would leave every
/// caller writing the same mapping, each free to get it wrong. The token
/// returned here goes straight into the fetch call.
///
/// # Cost, honestly
///
/// Four of the five planes have a subject-scoped read. The Key plane does not
/// — there is no `lookup_signed_key_record`, only the bulk
/// `list_signed_key_records_since` the index itself is built from — so that
/// plane is filtered from a full scan. #634 hoped this would be cheaper than
/// edge's compose-and-rehash; for four planes it is the same work, and for the
/// Key plane it is more. The value delivered is the byte-exactness guarantee
/// moving into persist, not a speedup. A subject-indexed signed key read would
/// fix the asymmetry and is not in this cut.
///
/// `seq` is not returned: `signed_wire_index` has no seq column and the
/// subject-scoped reads do not surface one. #634 marked it optional.
pub async fn wire_refs_for_subject(
    dir: &dyn super::FederationDirectory,
    subject_key_id: &str,
) -> Result<Vec<(&'static str, String, String)>, Error> {
    let mut out = Vec::new();

    // Key — no subject-scoped signed read; filtered from the same bulk read
    // the index is built from, which is what keeps it byte-exact.
    for r in dir.list_signed_key_records_since(None, u32::MAX).await? {
        if r.record.key_id == subject_key_id {
            let rk = record_key(&[("key_id", &r.record.key_id)]);
            out.push(("Key", content_hash_of(&r)?, rk));
        }
    }
    for a in dir.list_attestations_for(subject_key_id).await? {
        let rk = record_key(&[("attestation_id", &a.attestation_id)]);
        out.push(("Attestation", content_hash_of(&a)?, rk));
    }
    for r in dir
        .list_signed_identity_occurrences_for(subject_key_id)
        .await?
    {
        let rk = record_key(&[
            ("identity_key_id", &r.identity_occurrence.identity_key_id),
            (
                "occurrence_key_id",
                &r.identity_occurrence.occurrence_key_id,
            ),
        ]);
        out.push(("IdentityOccurrence", content_hash_of(&r)?, rk));
    }
    // Transport destinations hang off the OCCURRENCE, so the subject's
    // occurrences are the key set — a subject with no occurrence has no routes.
    for occ in dir
        .list_signed_identity_occurrences_for(subject_key_id)
        .await?
    {
        let occ_id = &occ.identity_occurrence.occurrence_key_id;
        for r in dir.list_signed_transport_destinations_for(occ_id).await? {
            let rk = record_key(&[
                (
                    "occurrence_key_id",
                    &r.transport_destination.occurrence_key_id,
                ),
                ("transport_kind", &r.transport_destination.transport_kind),
            ]);
            out.push(("TransportDestination", content_hash_of(&r)?, rk));
        }
    }
    for r in dir
        .list_signed_identity_occurrence_revocations_for(subject_key_id)
        .await?
    {
        let rk = record_key(&[
            (
                "identity_key_id",
                &r.identity_occurrence_revocation.identity_key_id,
            ),
            (
                "occurrence_key_id",
                &r.identity_occurrence_revocation.occurrence_key_id,
            ),
        ]);
        out.push(("IdentityOccurrenceRevocation", content_hash_of(&r)?, rk));
    }
    Ok(out)
}

/// v21.1.0 (CIRISPersist#507b) — the shared full-scan half of
/// `rebuild_signed_wire_index`: bulk-lists every covered kind via its
/// EXISTING `list_signed_*_since(None, u32::MAX)` / `list_*_since(None,
/// u32::MAX)` surface (the same read the wire-index write hooks index
/// incrementally), computing `(kind, content_hash, record_key)` for each
/// row. Written once against `&dyn FederationDirectory` so the "which 13
/// kinds, which record_key shape" list lives in exactly one place, shared
/// by every backend's `rebuild_signed_wire_index` (each does its own
/// backend-specific upsert loop over the result).
pub async fn all_kind_hash_keys(
    dir: &dyn super::FederationDirectory,
) -> Result<Vec<(&'static str, String, String)>, Error> {
    let mut out = Vec::new();
    for r in dir.list_signed_key_records_since(None, u32::MAX).await? {
        let rk = record_key(&[("key_id", &r.record.key_id)]);
        out.push(("Key", content_hash_of(&r)?, rk));
    }
    // Federation-tier-only by construction (the E5 invariant).
    for a in dir.list_attestations_since(None, u32::MAX).await? {
        let rk = record_key(&[("attestation_id", &a.attestation_id)]);
        out.push(("Attestation", content_hash_of(&a)?, rk));
    }
    for r in dir
        .list_signed_identity_occurrences_since(None, u32::MAX)
        .await?
    {
        let rk = record_key(&[
            ("identity_key_id", &r.identity_occurrence.identity_key_id),
            (
                "occurrence_key_id",
                &r.identity_occurrence.occurrence_key_id,
            ),
        ]);
        out.push(("IdentityOccurrence", content_hash_of(&r)?, rk));
    }
    for r in dir
        .list_signed_transport_destinations_since(None, u32::MAX)
        .await?
    {
        let rk = record_key(&[
            (
                "occurrence_key_id",
                &r.transport_destination.occurrence_key_id,
            ),
            ("transport_kind", &r.transport_destination.transport_kind),
        ]);
        out.push(("TransportDestination", content_hash_of(&r)?, rk));
    }
    for r in dir
        .list_signed_identity_occurrence_revocations_since(None, u32::MAX)
        .await?
    {
        let rk = record_key(&[
            (
                "identity_key_id",
                &r.identity_occurrence_revocation.identity_key_id,
            ),
            (
                "occurrence_key_id",
                &r.identity_occurrence_revocation.occurrence_key_id,
            ),
        ]);
        out.push(("IdentityOccurrenceRevocation", content_hash_of(&r)?, rk));
    }
    for r in dir.list_signed_families_since(None, u32::MAX).await? {
        let rk = record_key(&[("family_key_id", &r.family.family_key_id)]);
        out.push(("Family", content_hash_of(&r)?, rk));
    }
    for r in dir.list_signed_communities_since(None, u32::MAX).await? {
        let rk = record_key(&[("community_key_id", &r.community.community_key_id)]);
        out.push(("Community", content_hash_of(&r)?, rk));
    }
    for r in dir
        .list_signed_location_proofs_since(None, u32::MAX)
        .await?
    {
        let rk = record_key(&[
            ("subject_key_id", &r.location_proof.subject_key_id),
            ("asserted_at", &r.location_proof.asserted_at.to_rfc3339()),
        ]);
        out.push(("LocationProof", content_hash_of(&r)?, rk));
    }
    for r in dir
        .list_signed_family_membership_revocations_since(None, u32::MAX)
        .await?
    {
        let rk = record_key(&[
            (
                "family_key_id",
                &r.family_membership_revocation.family_key_id,
            ),
            (
                "removed_identity_key_id",
                &r.family_membership_revocation.removed_identity_key_id,
            ),
        ]);
        out.push(("FamilyMembershipRevocation", content_hash_of(&r)?, rk));
    }
    for r in dir
        .list_signed_community_membership_revocations_since(None, u32::MAX)
        .await?
    {
        let rk = record_key(&[
            (
                "community_key_id",
                &r.community_membership_revocation.community_key_id,
            ),
            (
                "removed_identity_key_id",
                &r.community_membership_revocation.removed_identity_key_id,
            ),
        ]);
        out.push(("CommunityMembershipRevocation", content_hash_of(&r)?, rk));
    }
    for r in dir.list_organizations_since(None, u32::MAX).await? {
        let rk = record_key(&[("attestation_id", &r.attestation_id)]);
        out.push(("Organization", content_hash_of(&r)?, rk));
    }
    for r in dir.list_org_memberships_since(None, u32::MAX).await? {
        let rk = record_key(&[("attestation_id", &r.attestation_id)]);
        out.push(("OrgMembership", content_hash_of(&r)?, rk));
    }
    for r in dir
        .list_signed_partner_records_since(None, u32::MAX)
        .await?
    {
        let rk = record_key(&[("attestation_id", &r.partner_record.attestation_id)]);
        out.push(("PartnerRecord", content_hash_of(&r)?, rk));
    }
    Ok(out)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn record_key_round_trips_single_field() {
        let rk = record_key(&[("key_id", "abc123")]);
        assert_eq!(record_key_field(&rk, "key_id").unwrap(), "abc123");
    }

    #[test]
    fn record_key_round_trips_composite_field() {
        let rk = record_key(&[("identity_key_id", "id1"), ("occurrence_key_id", "occ1")]);
        assert_eq!(record_key_field(&rk, "identity_key_id").unwrap(), "id1");
        assert_eq!(record_key_field(&rk, "occurrence_key_id").unwrap(), "occ1");
    }

    #[test]
    fn record_key_field_missing_errors() {
        let rk = record_key(&[("key_id", "abc123")]);
        assert!(record_key_field(&rk, "nope").is_err());
    }

    #[test]
    fn content_hash_of_matches_manual_sha256() {
        #[derive(serde::Serialize)]
        struct Foo {
            a: u32,
            b: String,
        }
        let foo = Foo {
            a: 1,
            b: "x".into(),
        };
        let bytes = serde_json::to_vec(&foo).unwrap();
        let expected = content_hash_of_bytes(&bytes);
        assert_eq!(content_hash_of(&foo).unwrap(), expected);
    }
}
