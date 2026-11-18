//! The edition-2 payload members of the families persist maps onto its
//! typed tables (v62.0.0, JSON-cut slice A; CC 2.6.1, CC 3.1.3).
//!
//! **CC-READING(next-edition).** CC adopted this reading: each family's
//! edition-2 payload carries the earlier record's members one to one, in
//! the deterministic encoding (CDE), with no embedded signed object. The
//! statements are the authority. What the earlier form carried as a
//! co-signature (a co-scrub, a roster cosignature, a quorum or threshold
//! signature set) is now a further statement over the same payload: a
//! counted voice, never a payload member. This module is the source the
//! CDDL is written from; `docs/EDITION2_PAYLOADS.md` is rendered from it
//! ([`render_markdown`]) and a witness keeps the two equal.
//!
//! The members every row carries are CC 2.6.1.3's, not repeated per family:
//! `asserted_at` (uint, POSIX ms, required), `author` (identity-ref, on an
//! authored family only), `dimension` (tstr: the family instance, required
//! where the family id has a parameter, e.g. `membership:widening:v1` under
//! `membership:{stage}`) and `refs` (map of row-refs). Per-family `refs`
//! roles are listed with the members.
//!
//! The conversions, everywhere:
//! - an instant (RFC 3339 text, `DateTime`) is a uint of POSIX ms (CC 2.6.2);
//! - a key id is an identity-ref (CC 2.6.1.1);
//! - a reference to a held row (`persist_row_hash`, `attestation_id`) is an
//!   edition-2 `row-ref` under `refs`, computed by the node (CC 2.6.1.3);
//! - a SHA-256 digest carried as hex is a hash digest, `[-16, bstr .size
//!   32]`;
//! - `persist_row_hash`, `original_content_hash`, the scrub members and
//!   `pqc_completed_at` are gone: the row id and the statements replace them.

use ciris_verify_core::cde::Value;

use super::names::{names_of, Name};
use crate::federation::{malformed_row, Error};

/// The plane name the payload check's refusals carry.
pub const PLANE: &str = "edition2_payload";

/// A member's CBOR type.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Ty {
    /// uint, POSIX milliseconds.
    Ms,
    /// uint.
    Uint,
    /// bstr.
    Bstr,
    /// A hash digest, `[-16, bstr .size 32]` (SHA-256, the COSE algorithm
    /// id -16), as Verify's door reads a digest member.
    Digest,
    /// tstr.
    Tstr,
    /// tstr, an identity-ref (CC 2.6.1.1).
    IdentityRef,
    /// bool.
    Bool,
    /// map (text keys), opaque to persist.
    Map,
    /// array of identity-refs, sorted by encoding, unique.
    IdentityRefs,
    /// array of hash digests (`[-16, bstr .size 32]`), sorted by encoding,
    /// unique.
    Digests,
    /// array of roster members ([`ROSTER_MEMBER`]), sorted by `key`.
    RosterMembers,
}

impl Ty {
    /// The type as the CDDL / the payload document spells it.
    #[must_use]
    pub const fn spelling(self) -> &'static str {
        match self {
            Ty::Ms => "uint (ms)",
            Ty::Uint => "uint",
            Ty::Bstr => "bstr",
            Ty::Digest => "hash-digest [-16, bstr .size 32]",
            Ty::Tstr => "tstr",
            Ty::IdentityRef => "identity-ref",
            Ty::Bool => "bool",
            Ty::Map => "map",
            Ty::IdentityRefs => "[* identity-ref]",
            Ty::Digests => "[* hash-digest]",
            Ty::RosterMembers => "[* roster-member]",
        }
    }

    fn holds(self, v: &Value) -> bool {
        let identity = |v: &Value| {
            v.as_text()
                .is_some_and(ciris_verify_core::edition2::is_identity_ref)
        };
        let digest = |v: &Value| match v.as_array() {
            Some([alg, b]) => {
                alg.as_i64() == Some(-16) && b.as_bytes().is_some_and(|b| b.len() == 32)
            }
            _ => false,
        };
        let sorted_unique = |a: &[Value]| {
            let enc: Vec<Vec<u8>> = a.iter().map(ciris_verify_core::cde::encode).collect();
            enc.windows(2).all(|w| w[0] < w[1])
        };
        match self {
            Ty::Ms | Ty::Uint => v.as_u64().is_some(),
            Ty::Bstr => v.as_bytes().is_some(),
            Ty::Digest => digest(v),
            Ty::Tstr => v.as_text().is_some(),
            Ty::IdentityRef => identity(v),
            Ty::Bool => matches!(v, Value::Bool(_)),
            Ty::Map => v.as_map().is_some(),
            Ty::IdentityRefs => v
                .as_array()
                .is_some_and(|a| a.iter().all(identity) && sorted_unique(a)),
            Ty::Digests => v
                .as_array()
                .is_some_and(|a| a.iter().all(digest) && sorted_unique(a)),
            Ty::RosterMembers => v.as_array().is_some_and(|a| {
                let keys: Vec<Vec<u8>> = a
                    .iter()
                    .filter_map(|m| m.get_text("key"))
                    .map(ciris_verify_core::cde::encode)
                    .collect();
                keys.len() == a.len()
                    && keys.windows(2).all(|w| w[0] < w[1])
                    && a.iter().all(|m| check_members(ROSTER_MEMBER, m).is_ok())
            }),
        }
    }
}

/// Whether a member must be present.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Presence {
    /// Always present.
    Required,
    /// May be absent.
    Optional,
    /// Present exactly when the named member holds the given text.
    RequiredWhen(&'static str, &'static str),
}

impl Presence {
    const fn spelling(self) -> &'static str {
        match self {
            Presence::Required => "required",
            Presence::Optional => "optional",
            Presence::RequiredWhen(..) => "required when",
        }
    }
}

/// One payload member.
#[derive(Clone, Copy, Debug)]
pub struct Member {
    /// The CBOR map key.
    pub name: &'static str,
    /// Its type.
    pub ty: Ty,
    /// Required or optional.
    pub presence: Presence,
    /// The earlier-form field it maps from.
    pub from: &'static str,
}

/// One `refs` role a family's row carries.
#[derive(Clone, Copy, Debug)]
pub struct RefRole {
    /// The `refs` member path (`prev`, `target`, `head`, `also:charter`).
    pub role: &'static str,
    /// Required or optional.
    pub presence: Presence,
    /// The earlier-form field it maps from.
    pub from: &'static str,
}

/// One earlier-form signature member that is now a counted voice.
#[derive(Clone, Copy, Debug)]
pub struct Voice {
    /// The earlier-form member.
    pub from: &'static str,
    /// What it is under edition 2.
    pub becomes: &'static str,
}

/// One family's payload.
#[derive(Clone, Copy, Debug)]
pub struct FamilyPayload {
    /// The family id (header -70002).
    pub family: &'static str,
    /// The earlier-form record(s) it replaces.
    pub replaces: &'static str,
    /// Authored (`author` present) or counted (CC's family model).
    pub authorship: &'static str,
    /// The CWT `sub`.
    pub sub: &'static str,
    /// The payload members, beyond the common ones.
    pub members: &'static [Member],
    /// The `refs` roles.
    pub refs: &'static [RefRole],
    /// The earlier form's co-signatures, now counted voices.
    pub voices: &'static [Voice],
    /// The typed table the door lands it in.
    pub table: &'static str,
}

const fn m(name: &'static str, ty: Ty, presence: Presence, from: &'static str) -> Member {
    Member {
        name,
        ty,
        presence,
        from,
    }
}

const R: Presence = Presence::Required;
const O: Presence = Presence::Optional;

/// The members of one roster entry (`members` of `group:roster`).
pub const ROSTER_MEMBER: &[Member] = &[
    m(
        "key",
        Ty::IdentityRef,
        R,
        "FamilyMember/CommunityMember.key_id",
    ),
    m(
        "joined_at",
        Ty::Ms,
        R,
        "FamilyMember/CommunityMember.joined_at",
    ),
    m("role", Ty::Tstr, O, "FamilyMember/CommunityMember.role"),
];

/// Every family this module maps, in document order.
pub const FAMILIES: &[FamilyPayload] = &[
    FamilyPayload {
        family: "group:roster",
        replaces: "SignedFamily / Family, SignedCommunity / Community, a federation_group_versions row",
        authorship: "counted",
        sub: "the group's identity-ref (family_key_id / community_key_id)",
        members: &[
            m("group_kind", Ty::Tstr, R, "the record's kind: \"family\" | \"community\""),
            m("group", Ty::IdentityRef, R, "Family.family_key_id / Community.community_key_id (equals sub)"),
            m("name", Ty::Tstr, R, "Family.family_name / Community.community_name"),
            m("version", Ty::Uint, R, "federation_group_versions.version"),
            m("members", Ty::RosterMembers, R, "Family.members / Community.members"),
            m("founded_at", Ty::Ms, R, "founded_at"),
            m("consensus_protocol", Ty::Tstr, R, "consensus_protocol"),
            m("consensus_protocol_entrenched", Ty::Bool, O, "Family.consensus_protocol_entrenched (absent: false)"),
            m("dissolved_at", Ty::Ms, O, "Family.dissolved_at"),
            m("policy", Ty::Map, O, "Community.policy_blob (cohort_scope among its members)"),
        ],
        refs: &[
            RefRole { role: "prev", presence: O, from: "prev_head_digest (the predecessor version's persist_row_hash); absent on version 1" },
            RefRole { role: "also:charter", presence: O, from: "charter_digest (the trust:charter:v1 row in force)" },
        ],
        voices: &[
            Voice { from: "scrub_signature_classical / scrub_signature_pqc under authority_key_id", becomes: "the group key's own statement" },
            Voice { from: "cosignatures (RosterCosignature)", becomes: "one statement per listed member over the same payload" },
            Voice { from: "supersede_proof.quorum_signatures (ThresholdSignature)", becomes: "the predecessor roster's holders' statements, counted at its consensus_protocol" },
            Voice { from: "SignedCommunity.lineage", becomes: "nothing carried: each prior version is its own held row, named by refs.prev" },
        ],
        table: "federation_families / federation_communities (+ federation_group_versions)",
    },
    FamilyPayload {
        family: "membership:{stage}",
        replaces: "Signed{Family,Community}MembershipRevocation (stage `removal`), Signed{Family,Community}MembershipWidening (stage `widening`)",
        authorship: "counted (stages widening, removal)",
        sub: "the member's identity-ref",
        members: &[
            m("group_kind", Ty::Tstr, R, "\"family\" | \"community\" (which struct)"),
            m("group", Ty::IdentityRef, R, "family_key_id / community_key_id"),
            m("member", Ty::IdentityRef, R, "removal: removed_identity_key_id; widening: member_key_id (equals sub)"),
            m("removed_at", Ty::Ms, Presence::RequiredWhen("dimension", "removal"), "MembershipRevocation.removed_at"),
            m("joined_at", Ty::Ms, Presence::RequiredWhen("dimension", "widening"), "MembershipWidening.joined_at"),
            m("effective_at", Ty::Ms, R, "effective_at"),
            m("reason", Ty::Tstr, O, "MembershipRevocation.reason"),
            m("role", Ty::Tstr, O, "MembershipWidening.role"),
            m("witness_set", Ty::IdentityRefs, O, "MembershipRevocation.witness_set (vouching key ids, not signatures)"),
        ],
        refs: &[
            RefRole { role: "head", presence: O, from: "the roster version the change is counted over (earlier: the signed instant)" },
        ],
        voices: &[
            Voice { from: "scrub_signature_* under authority_key_id", becomes: "the proposer's statement" },
            Voice { from: "cosignatures (RosterCosignature)", becomes: "the roster members' statements, counted at the group's consensus_protocol" },
        ],
        table: "federation_{family,community}_membership_{revocations,widenings}",
    },
    FamilyPayload {
        family: "identity:occurrence_revocation",
        replaces: "FramedOccurrenceRevocation / IdentityOccurrenceRevocation (an identity:occurrence_revocation:v1 row)",
        authorship: "counted for a user self (identity=user), else authored",
        sub: "the occurrence's identity-ref",
        members: &[
            m("identity", Ty::IdentityRef, R, "identity_key_id"),
            m("occurrence", Ty::IdentityRef, R, "occurrence_key_id (equals sub)"),
            m("revoked_at", Ty::Ms, R, "revoked_at"),
            m("effective_at", Ty::Ms, R, "effective_at (may be later than asserted_at)"),
            m("reason", Ty::Tstr, O, "reason"),
            m("witness_set", Ty::IdentityRefs, O, "witness_set"),
        ],
        refs: &[],
        voices: &[
            Voice { from: "FramedOccurrenceRevocation.signature (TransportBindingSignature) under attesting_key_id", becomes: "the revoker's statement" },
            Voice { from: "the row's additional_scrubs (roster cosigs, user self)", becomes: "the roster members' statements, a strict majority counted" },
        ],
        table: "federation_identity_occurrence_revocations",
    },
    FamilyPayload {
        family: "cosign:{state}",
        replaces: "LineageHeadCosign (state `lineage_head`); cosign:pending:v1 / cosign:signature:v1 rows",
        authorship: "authored",
        sub: "the lineage's identity-ref (lineage_head); the group's (pending, signature)",
        members: &[
            m("lineage", Ty::IdentityRef, Presence::RequiredWhen("dimension", "lineage_head"), "LineageHeadCosign.lineage_key_id"),
            m("head_asserted_at", Ty::Ms, Presence::RequiredWhen("dimension", "lineage_head"), "LineageHeadCosign.head_asserted_at"),
            m("event_family", Ty::Tstr, Presence::RequiredWhen("dimension", "pending"), "cosign event_family"),
            m("group_kind", Ty::Tstr, Presence::RequiredWhen("dimension", "pending"), "cosign group_kind"),
        ],
        refs: &[
            RefRole { role: "head", presence: Presence::RequiredWhen("dimension", "lineage_head"), from: "head_digest_sha256_hex (the head's persist_row_hash)" },
            RefRole { role: "prev", presence: O, from: "prior_head_digest_sha256_hex" },
            RefRole { role: "target", presence: Presence::RequiredWhen("dimension", "pending"), from: "pending: the event (embedded `event`, now named); signature: quorum_key (the pending row)" },
        ],
        voices: &[
            Voice { from: "signature_classical / signature_pqc under witness_key_id", becomes: "the witness's statement (iss); signed_at is asserted_at" },
            Voice { from: "cosign:signature row's scrub + additional_scrubs", becomes: "a further statement over the event's own row (CC 2.6.1.9); the signature state carries no member of its own" },
        ],
        table: "federation_lineage_head_cosigns (lineage_head); ceg_statements only (pending, signature)",
    },
    FamilyPayload {
        family: "revocation:{entity_type}:{reason}",
        replaces: "SignedRevocation / Revocation (a key revocation is key:revocation instead)",
        authorship: "authored",
        sub: "the revoked entity's identity-ref (an entity with a key)",
        members: &[
            m("revoked_at", Ty::Ms, R, "revoked_at"),
            m("effective_at", Ty::Ms, R, "effective_at"),
            m("revoked_after", Ty::Ms, O, "revoked_after"),
            m("reason", Ty::Tstr, O, "reason (free text; the {reason} leaf is the coded one)"),
        ],
        refs: &[
            RefRole { role: "target", presence: O, from: "the revoked row, when the entity is a row (no earlier field: revoked_key_id named keys only)" },
        ],
        voices: &[
            Voice { from: "scrub_signature_* under scrub_key_id / revoking_key_id", becomes: "the revoker's statement (iss = author)" },
        ],
        table: "federation_revocations (an entity with a key); ceg_statements only otherwise",
    },
    FamilyPayload {
        family: "takedown_notice:{basis}",
        replaces: "StewardPurgeNotice (envelope members, notice_terms)",
        authorship: "counted for leaf steward_purge, else authored",
        sub: "the claimant's identity-ref",
        members: &[
            m("legal_basis", Ty::Tstr, R, "legal_basis (also the {basis} leaf)"),
            m("claimant", Ty::IdentityRef, R, "claimant_key_id"),
            m("content_sha256", Ty::Digest, R, "content_sha256 (the selection digest)"),
            m("content_holders", Ty::IdentityRefs, R, "content_holder_key_ids"),
            m("claim_text", Ty::Tstr, R, "claim_text"),
            m("good_faith_statement", Ty::Tstr, R, "good_faith_statement"),
            m("jurisdiction", Ty::Tstr, R, "jurisdiction"),
            m("evidence_refs", Ty::Digests, O, "evidence_refs (the dry-run ledger digests)"),
            m("selection_counts", Ty::Map, O, "selection_counts"),
            m("expires_at", Ty::Ms, O, "expires_at"),
        ],
        refs: &[],
        voices: &[
            Voice { from: "cosignatures (ThresholdSignature, one per founder)", becomes: "the stewards' statements, counted" },
        ],
        table: "ceg_statements (the notice; its id is the row id); purge_executions when the purge runs",
    },
    FamilyPayload {
        family: "custody:{kind}",
        replaces: "custody:ack:v1 envelope (CustodyAck)",
        authorship: "authored",
        sub: "the device's identity-ref (equals iss)",
        members: &[
            m("custody_state", Ty::Tstr, R, "custody_state: \"here\" | \"none\""),
            m("evidence_refs", Ty::Digests, R, "evidence_refs (blob sha256)"),
            m("size", Ty::Uint, Presence::RequiredWhen("custody_state", "here"), "size"),
            m("cohort", Ty::IdentityRef, R, "community_id / family_key_id"),
            m("expires_at", Ty::Ms, R, "the row's expires_at (asserted_at + 72 h)"),
        ],
        refs: &[],
        voices: &[],
        table: "federation_attestations (custody:ack) and the holding-claim fold",
    },
    FamilyPayload {
        family: "key_grant:{axis}",
        replaces: "SignedKeyGrantRow (envelope)",
        authorship: "authored",
        sub: "the recipient's identity-ref (attested_key_id / GrantWrap.recipient_key_id)",
        members: &[
            m("axis", Ty::Tstr, R, "axis: \"epoch\" | \"content\" | \"stream\" (also the {axis} leaf)"),
            m("wrap_algorithm", Ty::Tstr, R, "GrantWrap.wrap_algorithm"),
            m("wrapped_dek", Ty::Bstr, R, "GrantWrap.wrapped_dek"),
            m("community", Ty::IdentityRef, Presence::RequiredWhen("axis", "epoch"), "community_key_id"),
            m("community_id", Ty::Tstr, O, "community_id"),
            m("minter", Ty::IdentityRef, Presence::RequiredWhen("axis", "epoch"), "minter_key_id"),
            m("epoch", Ty::Uint, O, "epoch (epoch and stream axes)"),
            m("at_rest_sha256", Ty::Digest, Presence::RequiredWhen("axis", "content"), "at_rest_sha256"),
            m("owner", Ty::IdentityRef, O, "owner_key_id (content and stream axes)"),
            m("stream_id", Ty::Tstr, Presence::RequiredWhen("axis", "stream"), "stream_id"),
            m("cohort", Ty::IdentityRef, O, "the cohort target (community_id / family_key_id)"),
        ],
        refs: &[],
        voices: &[],
        table: "federation_attestations (key_grant) + federation_blob_key_grants / federation_stream_dek_grants",
    },
    FamilyPayload {
        family: "delivery_receipt:{stream_id}",
        replaces: "DeliveryReceipt",
        authorship: "authored",
        sub: "the subscriber's identity-ref (subscriber_key_id; equals iss)",
        members: &[
            m("stream_id", Ty::Tstr, R, "stream_id (also the {stream_id} leaf)"),
            m("epoch", Ty::Uint, R, "epoch"),
            m("k", Ty::Uint, R, "k (the chunk index acknowledged)"),
            m("chunk_root", Ty::Digest, R, "chunk_root"),
        ],
        refs: &[],
        voices: &[
            Voice { from: "signature (HybridSignature over the binary receipt bytes)", becomes: "the subscriber's composite statement; the receipt store's HybridSignature is filled from its two halves" },
        ],
        table: "federation_stream_delivery_receipts",
    },
];

/// The members every row carries (CC 2.6.1.3), allowed in any payload.
pub const COMMON: &[&str] = &["asserted_at", "author", "dimension", "refs"];

/// The payload of `family`, if this module maps it.
#[must_use]
pub fn family(family: &str) -> Option<&'static FamilyPayload> {
    FAMILIES.iter().find(|f| f.family == family)
}

fn refuse(message: String) -> Error {
    Error::malformed_row(PLANE, malformed_row::EDITION2_PAYLOAD_INVALID, message)
}

/// The leaf a `RequiredWhen("dimension", leaf)` reads: the payload's
/// `dimension` contains `:{leaf}` as a segment.
fn dimension_has(payload: &Value, leaf: &str) -> bool {
    payload
        .get_text("dimension")
        .and_then(Value::as_text)
        .is_some_and(|d| d.split(':').any(|s| s == leaf))
}

fn required(p: Presence, payload: &Value) -> bool {
    match p {
        Presence::Required => true,
        Presence::Optional => false,
        Presence::RequiredWhen("dimension", leaf) => dimension_has(payload, leaf),
        Presence::RequiredWhen(member, value) => {
            payload.get_text(member).and_then(Value::as_text) == Some(value)
        }
    }
}

fn check_members(members: &[Member], payload: &Value) -> Result<(), String> {
    let Some(map) = payload.as_map() else {
        return Err("the payload is not a map".into());
    };
    for mem in members {
        match payload.get_text(mem.name) {
            None if required(mem.presence, payload) => {
                return Err(format!("`{}` is required", mem.name));
            }
            None => {}
            Some(v) if !mem.ty.holds(v) => {
                return Err(format!("`{}` is not {}", mem.name, mem.ty.spelling()));
            }
            Some(_) => {}
        }
    }
    for (k, _) in map {
        let Some(k) = k.as_text() else {
            return Err("a member key is not text".into());
        };
        if !COMMON.contains(&k) && !members.iter().any(|x| x.name == k) {
            return Err(format!("`{k}` is not a member of this family's payload"));
        }
    }
    Ok(())
}

/// **Check a payload of a mapped family** against its member list: each
/// required member present, each present member of its type, no member
/// outside the list and the common ones, each required `refs` role named.
/// `Ok` for a family this module does not map (its rules are elsewhere).
///
/// # Errors
/// `edition2_payload_invalid` (`federation_malformed_row`), naming the
/// member.
pub fn check(family_id: &str, payload: &Value) -> Result<(), Error> {
    let Some(f) = family(family_id) else {
        return Ok(());
    };
    check_members(f.members, payload).map_err(|e| refuse(format!("{family_id}: {e}")))?;
    let names: Vec<Name> =
        names_of(payload).map_err(|e| refuse(format!("{family_id}: refs: {e:?}")))?;
    for r in f.refs {
        if required(r.presence, payload) && !names.iter().any(|n| n.role == r.role) {
            return Err(refuse(format!("{family_id}: refs.{} is required", r.role)));
        }
    }
    Ok(())
}

fn cell(s: &str) -> String {
    s.replace('|', "\\|")
}

fn presence_cell(p: Presence) -> String {
    match p {
        Presence::RequiredWhen(k, v) => format!("required when `{k}` is `{v}`"),
        other => other.spelling().to_owned(),
    }
}

/// The payload document's per-family tables, rendered from [`FAMILIES`].
#[must_use]
pub fn render_markdown() -> String {
    let mut out = String::new();
    for f in FAMILIES {
        out.push_str(&format!("### `{}`\n\n", f.family));
        out.push_str(&format!("- **Replaces:** {}\n", cell(f.replaces)));
        out.push_str(&format!("- **Authorship:** {}\n", f.authorship));
        out.push_str(&format!("- **`sub`:** {}\n", cell(f.sub)));
        out.push_str(&format!("- **Lands in:** {}\n\n", cell(f.table)));
        out.push_str("| member | CBOR type | presence | maps from |\n|---|---|---|---|\n");
        for mem in f.members {
            out.push_str(&format!(
                "| `{}` | `{}` | {} | {} |\n",
                mem.name,
                mem.ty.spelling(),
                presence_cell(mem.presence),
                cell(mem.from)
            ));
        }
        for r in f.refs {
            out.push_str(&format!(
                "| `refs.{}` | `row-ref` | {} | {} |\n",
                r.role,
                presence_cell(r.presence),
                cell(r.from)
            ));
        }
        out.push('\n');
        if f.voices.is_empty() {
            out.push_str(
                "Co-signatures now counted voices: none (the author's statement alone).\n\n",
            );
        } else {
            out.push_str("| earlier-form co-signature (not a payload member) | now |\n|---|---|\n");
            for v in f.voices {
                out.push_str(&format!("| {} | {} |\n", cell(v.from), cell(v.becomes)));
            }
            out.push('\n');
        }
    }
    out.push_str("### `roster-member` (an entry of `group:roster`'s `members`)\n\n");
    out.push_str("| member | CBOR type | presence | maps from |\n|---|---|---|---|\n");
    for mem in ROSTER_MEMBER {
        out.push_str(&format!(
            "| `{}` | `{}` | {} | {} |\n",
            mem.name,
            mem.ty.spelling(),
            presence_cell(mem.presence),
            cell(mem.from)
        ));
    }
    out
}
