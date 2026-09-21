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

/// v46.1.0 (#878, review) — a member that is SHAPED like a pointer but
/// carries key-plane metadata persist cannot read. This is never "not a
/// pointer": a malformed reference to the blob in hand must refuse by
/// member, or the caller silently falls back to the citation path and
/// records the bytes under a tier derived from the row's scope — the exact
/// defect this module exists to close.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PointerError {
    /// The offending member (`community_key_id`, `tier`, `epoch`, or
    /// `content_sha256` for conflicting duplicates).
    pub member: String,
    /// The rule it broke, in words.
    pub reason: String,
}

impl std::fmt::Display for PointerError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}: {}", self.member, self.reason)
    }
}

fn refuse(member: &str, reason: impl Into<String>) -> PointerError {
    PointerError {
        member: member.to_owned(),
        reason: reason.into(),
    }
}

/// Is this envelope member shaped like a blob pointer, and if so what does
/// it say? The discriminator is a `content_sha256` of 64 hex characters
/// beside a `community_key_id` MEMBER (present, of any type) — the two every
/// producer's pointer carries. A `media` Source struct (#871) is NOT one: it
/// spells its digest `digest`. A member that merely mentions a sha with no
/// `community_key_id` is not one either.
///
/// `Ok(None)` = not pointer-shaped. `Err` = pointer-shaped and unreadable:
/// a non-string community, an unknown or non-string tier, a non-integer
/// epoch. The two are kept distinct on purpose (see [`PointerError`]).
fn parse_member(v: &Value) -> Result<Option<BlobPointerRef>, PointerError> {
    let Some(o) = v.as_object() else {
        return Ok(None);
    };
    let Some(sha) = o.get("content_sha256").and_then(Value::as_str) else {
        return Ok(None);
    };
    if sha.len() != 64 || !sha.bytes().all(|b| b.is_ascii_hexdigit()) {
        return Ok(None);
    }
    let Some(community) = o.get("community_key_id") else {
        return Ok(None);
    };
    let community_key_id = community
        .as_str()
        .ok_or_else(|| refuse("community_key_id", "a pointer's community is a string"))?
        .to_owned();
    // Absent tier = a pointer written before the member existed, which
    // described commons content (the producer's own serde default).
    let tier = match o.get("tier") {
        None | Some(Value::Null) => CryptoTier::Plaintext,
        Some(t) => {
            let s = t
                .as_str()
                .ok_or_else(|| refuse("tier", "a pointer's tier is a string"))?;
            CryptoTier::parse_str(s).ok_or_else(|| {
                refuse(
                    "tier",
                    format!("{s:?} is not a tier persist knows (plaintext | invisible_encrypted | community_dek)"),
                )
            })?
        }
    };
    let epoch = match o.get("epoch") {
        None | Some(Value::Null) => None,
        Some(e) => Some(
            e.as_u64()
                .ok_or_else(|| refuse("epoch", "a pointer's epoch is a non-negative integer"))?,
        ),
    };
    Ok(Some(BlobPointerRef {
        content_sha256: sha.to_ascii_lowercase(),
        community_key_id,
        tier,
        epoch,
    }))
}

/// **The pointer in `envelope` that names `sha256_hex`, if any.** Scans
/// every top-level member (and the members of an array member, so a list of
/// attachments resolves too).
///
/// Matching on the sha is what makes a multi-blob row unambiguous: a row
/// with three attachments has three pointers, and the one being adopted
/// selects itself. The same blob may legitimately be referenced twice (in
/// `content` and again in an attachment list) — identical duplicates are
/// one pointer. Two references to the same sha that DISAGREE on the key
/// plane are refused: choosing one silently would bind the bytes to the
/// wrong epoch or tier.
///
/// `Err` when a member shaped like a pointer at these bytes is unreadable
/// ([`PointerError`]) — never silently "no pointer".
pub fn pointer_for(
    envelope: &Value,
    sha256_hex: &str,
) -> Result<Option<BlobPointerRef>, PointerError> {
    let want = sha256_hex.to_ascii_lowercase();
    let Some(members) = envelope.as_object() else {
        return Ok(None);
    };
    let mut found: Option<BlobPointerRef> = None;
    let mut consider = |v: &Value| -> Result<(), PointerError> {
        if let Some(p) = parse_member(v)? {
            if p.content_sha256 != want {
                return Ok(());
            }
            match &found {
                None => found = Some(p),
                Some(prev) if *prev == p => {}
                Some(prev) => {
                    return Err(refuse(
                        "content_sha256",
                        format!(
                            "two pointers at {want} disagree on the key plane \
                             ({:?}/{:?}/{:?} vs {:?}/{:?}/{:?}); a blob is under one key",
                            prev.tier,
                            prev.community_key_id,
                            prev.epoch,
                            p.tier,
                            p.community_key_id,
                            p.epoch
                        ),
                    ))
                }
            }
        }
        Ok(())
    };
    for (_k, v) in members {
        consider(v)?;
        if let Some(arr) = v.as_array() {
            for item in arr {
                consider(item)?;
            }
        }
    }
    Ok(found)
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
        let p = pointer_for(&env, &sha("a")).unwrap().expect("found by sha");
        assert_eq!(p.community_key_id, "room-1");
        assert_eq!(p.tier, CryptoTier::CommunityDek);
        assert_eq!(p.epoch, Some(3));
        assert!(
            pointer_for(&env, &sha("b")).unwrap().is_none(),
            "a different blob"
        );
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
            pointer_for(&env, &sha("b"))
                .unwrap()
                .unwrap()
                .content_sha256,
            sha("b"),
            "the blob in hand selects its own pointer"
        );
    }

    #[test]
    fn a_media_source_struct_is_not_a_pointer() {
        // #871's struct spells its digest `digest`, so it cannot be read as
        // a pointer and claim a key plane it does not describe.
        let env = json!({"media": {"digest": sha("a"), "size": 4, "format": "image/png"}});
        assert_eq!(pointer_for(&env, &sha("a")), Ok(None));
    }

    #[test]
    fn a_sha_alone_is_not_a_pointer() {
        // The producer's type carries `community_key_id` on every pointer
        // (required, possibly empty). A member that merely mentions a sha —
        // a note, a receipt, a future reference of some other kind — must
        // not be read as a claim about the key plane.
        let env = json!({"receipt": {"content_sha256": sha("e"), "note": "seen"}});
        assert_eq!(pointer_for(&env, &sha("e")), Ok(None));
    }

    #[test]
    fn a_tierless_pointer_reads_as_commons() {
        let env = json!({"content": {"community_key_id": "", "content_sha256": sha("c")}});
        assert_eq!(
            pointer_for(&env, &sha("c")).unwrap().unwrap().tier,
            CryptoTier::Plaintext
        );
    }

    #[test]
    fn an_unknown_tier_on_a_matching_pointer_is_refused_not_ignored() {
        // Review P2: returning "no pointer" here would let the caller fall
        // back to the citation path and derive a tier from the row's scope.
        let env = json!({"content": {"community_key_id": "r", "tier": "quantum", "content_sha256": sha("d")}});
        let e = pointer_for(&env, &sha("d")).expect_err("refused");
        assert_eq!(e.member, "tier");
        let env =
            json!({"content": {"community_key_id": "r", "tier": 3, "content_sha256": sha("d")}});
        assert_eq!(pointer_for(&env, &sha("d")).unwrap_err().member, "tier");
    }

    #[test]
    fn a_non_string_community_is_refused_not_coerced() {
        // Review P2: `unwrap_or_default` would have read this as a plaintext
        // pointer with an empty community, outranking a good citation.
        let env = json!({"x": {"community_key_id": 7, "content_sha256": sha("f")}});
        assert_eq!(
            pointer_for(&env, &sha("f")).unwrap_err().member,
            "community_key_id"
        );
    }

    #[test]
    fn a_non_integer_epoch_is_refused() {
        let env = json!({"x": {"community_key_id": "r", "tier": "community_dek", "epoch": "0", "content_sha256": sha("1")}});
        assert_eq!(pointer_for(&env, &sha("1")).unwrap_err().member, "epoch");
    }

    #[test]
    fn duplicate_pointers_agree_or_are_refused() {
        // Review P2: the same blob in `content` and in `attachments` is one
        // reference; two that disagree on the key plane are none.
        let same = json!({"community_key_id": "r", "tier": "community_dek", "epoch": 1, "content_sha256": sha("2")});
        let env = json!({"content": same, "attachments": [same]});
        assert_eq!(
            pointer_for(&env, &sha("2")).unwrap().unwrap().epoch,
            Some(1)
        );
        let other = json!({"community_key_id": "r", "tier": "community_dek", "epoch": 2, "content_sha256": sha("2")});
        let env = json!({"content": same, "attachments": [other]});
        let e = pointer_for(&env, &sha("2")).expect_err("conflict");
        assert_eq!(e.member, "content_sha256");
        assert!(e.reason.contains("disagree"), "{e}");
    }
}
