//! v46.1.0 (CIRISPersist#878) — **the typed reference a producer writes
//! instead of, or beside, an `evidence_refs[]` citation.**
//!
//! `BLOB_REPLICATION.md` §5 puts provenance on the referencing attestation.
//! A citation says WHICH BYTES the row is about; a **pointer** says that
//! and also which key plane they are under — the community, the epoch, and
//! the tier the write door RESOLVED. The two are different axes and v46.0.0
//! read the wrong one: it took the tier from the ROW's `cohort_scope`, so a
//! chat row (placed at `self`, body sealed under the room's DEK) resolved
//! to `InvisibleEncrypted` for community-DEK ciphertext.
//!
//! Persist does not own the producer's type; it reads the members it needs,
//! structurally, from any envelope member that looks like one. That is
//! deliberate: attachments and future blob-bearing members are covered by
//! construction rather than by a list of field names persist would have to
//! keep in step with its consumers.

use serde_json::Value;

use super::types::cohort_scope::CryptoTier;

/// The members persist reads off a producer's blob pointer. Everything else
/// the producer carries (content field, media type, stream id) is its own.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct BlobPointerRef {
    /// The at-rest sha256 this pointer names, lowercase hex.
    pub content_sha256: String,
    /// The community whose key plane the bytes are under. May be empty on a
    /// non-community pointer.
    pub community_key_id: String,
    /// The tier the write door RESOLVED and recorded. Absent means the
    /// pointer predates the member, which described commons content.
    pub tier: CryptoTier,
    /// The epoch the bytes were sealed under; `CommunityDek` only.
    pub epoch: Option<u64>,
}

/// Is this envelope member shaped like a blob pointer? The discriminator is
/// a `content_sha256` of 64 hex characters beside a `community_key_id`
/// member — the two every producer's pointer carries. A `media` Source
/// struct (#871) is NOT one: it spells its digest `digest`.
fn parse_member(v: &Value) -> Option<BlobPointerRef> {
    let o = v.as_object()?;
    let sha = o.get("content_sha256")?.as_str()?;
    if sha.len() != 64 || !sha.bytes().all(|b| b.is_ascii_hexdigit()) {
        return None;
    }
    let community_key_id = o
        .get("community_key_id")?
        .as_str()
        .unwrap_or_default()
        .to_owned();
    // Absent tier = a pointer written before the member existed, which
    // described commons content (the producer's own serde default).
    let tier = match o.get("tier") {
        None | Some(Value::Null) => CryptoTier::Plaintext,
        Some(t) => CryptoTier::parse_str(t.as_str()?)?,
    };
    let epoch = o.get("epoch").and_then(Value::as_u64);
    Some(BlobPointerRef {
        content_sha256: sha.to_ascii_lowercase(),
        community_key_id,
        tier,
        epoch,
    })
}

/// **The pointer in `envelope` that names `sha256_hex`, if any.** Scans
/// every top-level member (and the members of an array member, so a list of
/// attachments resolves too) and returns the first whose `content_sha256`
/// matches, in the envelope's own key order.
///
/// Matching on the sha is what makes a multi-blob row unambiguous: a row
/// with three attachments has three pointers, and the one being adopted
/// selects itself.
#[must_use]
pub fn pointer_for(envelope: &Value, sha256_hex: &str) -> Option<BlobPointerRef> {
    let want = sha256_hex.to_ascii_lowercase();
    let members = envelope.as_object()?;
    for (_k, v) in members {
        if let Some(p) = parse_member(v) {
            if p.content_sha256 == want {
                return Some(p);
            }
        }
        if let Some(arr) = v.as_array() {
            for item in arr {
                if let Some(p) = parse_member(item) {
                    if p.content_sha256 == want {
                        return Some(p);
                    }
                }
            }
        }
    }
    None
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    fn sha(c: &str) -> String {
        c.repeat(64)
    }

    #[test]
    fn a_pointer_is_found_by_its_sha_in_any_member() {
        let env = json!({
            "dimension": "chat:message:v1",
            "content": {
                "community_key_id": "room-1",
                "tier": "community_dek",
                "content_sha256": sha("a"),
                "content_field": "body",
                "epoch": 3
            }
        });
        let p = pointer_for(&env, &sha("a")).expect("found by sha");
        assert_eq!(p.community_key_id, "room-1");
        assert_eq!(p.tier, CryptoTier::CommunityDek);
        assert_eq!(p.epoch, Some(3));
        assert!(pointer_for(&env, &sha("b")).is_none(), "a different blob");
    }

    #[test]
    fn an_attachment_list_resolves_and_the_sha_selects() {
        let env = json!({
            "attachments": [
                {"community_key_id": "r", "tier": "community_dek", "content_sha256": sha("a")},
                {"community_key_id": "r", "tier": "community_dek", "content_sha256": sha("b")}
            ]
        });
        assert_eq!(
            pointer_for(&env, &sha("b")).unwrap().content_sha256,
            sha("b"),
            "the blob in hand selects its own pointer"
        );
    }

    #[test]
    fn a_media_source_struct_is_not_a_pointer() {
        // #871's struct spells its digest `digest`, so it cannot be read as
        // a pointer and claim a key plane it does not describe.
        let env = json!({"media": {"digest": sha("a"), "size": 4, "format": "image/png"}});
        assert!(pointer_for(&env, &sha("a")).is_none());
    }

    #[test]
    fn a_tierless_pointer_reads_as_commons() {
        let env = json!({"content": {"community_key_id": "", "content_sha256": sha("c")}});
        assert_eq!(
            pointer_for(&env, &sha("c")).unwrap().tier,
            CryptoTier::Plaintext
        );
    }

    #[test]
    fn an_unknown_tier_is_not_a_pointer_persist_will_read() {
        let env = json!({"content": {"community_key_id": "r", "tier": "quantum", "content_sha256": sha("d")}});
        assert!(pointer_for(&env, &sha("d")).is_none());
    }
}
