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
//! v62.0.0 (wave P1) — CC checked the nine families against its text
//! (`manifests/family_payloads_v2.cddl`, read with `signed_object_v2.cddl`)
//! and, where the two differed, the text won: `refs.head` (not `prev`) names
//! a roster version's predecessor; the charter is cited under
//! `refs.also.cites` (the `also` roles are closed: `ack`, `cites`); a
//! `reason` is a uint code, free text riding `body.note`; the cosign states
//! are `pending` | `signature` and carry no member (the lineage-head
//! cosignature is no row, CC 3.4.10 / CC 5.3.1); a custody report carries
//! no `expires_at` and no `cohort` (its scope is the CC 2.1 members
//! `community_id` / `family_id`); `evidence_refs` is the envelope's
//! sequence `[+ hash-digest]`; a delivery receipt's inner signed preimage is
//! the earlier form's (CC 8.11.30).
//!
//! The members every row may carry are the envelope's (CC 2.6.1.3, the
//! `attestation-envelope` of `signed_object_v2.cddl`) and the CC 2.1
//! visibility / revocability / delivery members the logical-names table
//! (CC 2.6.1.4) maps to "payload members of the same names" ([`COMMON`]),
//! not repeated per family. Per-family `refs` roles are listed with the
//! members.
//!
//! The conversions, everywhere:
//! - an instant (RFC 3339 text, `DateTime`) is a uint of POSIX ms (CC 2.6.2);
//! - a key id is an identity-ref (CC 2.6.1.1);
//! - a reference to a held row (`persist_row_hash`, `attestation_id`) is an
//!   edition-2 `row-ref` under `refs`, computed by the node (CC 2.6.1.3);
//! - a SHA-256 digest carried as hex is a hash digest, `[-16, bstr .size
//!   32]` ([`HASH_DIGEST_MEMBERS`] names the ones every family may carry);
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
    /// v62.0.0 (wave P1) — the envelope's `evidence_refs` shape: a SEQUENCE
    /// of hash digests (`[+ hash-digest]`), non-empty, in the order signed
    /// (CC 2.6.1.4: "payload `evidence_refs`, a sequence"). Not a set.
    Digests,
    /// array of roster members ([`ROSTER_MEMBER`]): a set, sorted by each
    /// element's deterministic encoding, one entry per `key`.
    RosterMembers,
    /// v62.0.0 (wave P1) — any `ceg-value`: a member whose type the text
    /// leaves OPEN (`takedown_notice`'s `perceptual_hash`).
    Any,
    /// v62.0.0 (wave P1e) — a set of text (`[* tstr]`): sorted by each
    /// element's encoding, unique (`admission:unit`'s `capabilities`; its
    /// closure and non-emptiness are the family's own rule, with the
    /// verifier's token).
    Tstrs,
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
            Ty::Digests => "[+ hash-digest]",
            Ty::RosterMembers => "[* roster-member]",
            Ty::Any => "ceg-value",
            Ty::Tstrs => "[* tstr]",
        }
    }

    fn holds(self, v: &Value) -> bool {
        let identity = |v: &Value| {
            v.as_text()
                .is_some_and(ciris_verify_core::edition2::is_identity_ref)
        };
        match self {
            Ty::Ms | Ty::Uint => v.as_u64().is_some(),
            Ty::Bstr => v.as_bytes().is_some(),
            Ty::Digest => is_digest(v),
            Ty::Tstr => v.as_text().is_some(),
            Ty::IdentityRef => identity(v),
            Ty::Bool => matches!(v, Value::Bool(_)),
            Ty::Map => v.as_map().is_some(),
            Ty::IdentityRefs => v
                .as_array()
                .is_some_and(|a| a.iter().all(identity) && sorted_unique(a)),
            Ty::Digests => v
                .as_array()
                .is_some_and(|a| !a.is_empty() && a.iter().all(is_digest)),
            Ty::RosterMembers => v.as_array().is_some_and(|a| {
                let mut keys: Vec<Vec<u8>> = a
                    .iter()
                    .filter_map(|m| m.get_text("key"))
                    .map(ciris_verify_core::cde::encode)
                    .collect();
                let n = keys.len();
                keys.sort();
                keys.dedup();
                n == a.len()
                    && keys.len() == n
                    && sorted_unique(a)
                    && a.iter().all(|m| check_map(ROSTER_MEMBER, &[], m).is_ok())
            }),
            Ty::Any => true,
            Ty::Tstrs => v
                .as_array()
                .is_some_and(|a| a.iter().all(|e| e.as_text().is_some()) && sorted_unique(a)),
        }
    }
}

/// `[-16, bstr .size 32]`.
fn is_digest(v: &Value) -> bool {
    match v.as_array() {
        Some([alg, b]) => alg.as_i64() == Some(-16) && b.as_bytes().is_some_and(|b| b.len() == 32),
        _ => false,
    }
}

/// A set: sorted by each element's deterministic encoding, no duplicate.
fn sorted_unique(a: &[Value]) -> bool {
    let enc: Vec<Vec<u8>> = a.iter().map(ciris_verify_core::cde::encode).collect();
    enc.windows(2).all(|w| w[0] < w[1])
}

/// Whether a member must be present.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Presence {
    /// Always present.
    Required,
    /// May be absent.
    Optional,
    /// Required when the named member holds one of the given texts
    /// (`dimension`: when one of them is a segment of `dimension`).
    RequiredWhen(&'static str, &'static [&'static str]),
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
    /// The `refs` member path as [`names_of`] spells it (`head`, `target`,
    /// `also:cites`).
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

/// v62.0.0 (wave P1) — the takedown bases, CC 3.3.2's closed set of eleven
/// wire strings, compared byte for byte (the `{basis}` vocabulary of the
/// `takedown_notice:{basis}` registry row; a witness keeps the two equal).
pub const LEGAL_BASES: &[&str] = &[
    "dmca512",
    "dsa_article16",
    "tvec_terrorist",
    "ncmec_csam",
    "gifct_cip",
    "community_standards",
    "perceptual_hash_csam",
    "osa_illegal_content",
    "avmsd_age_inappropriate",
    "court_order",
    "steward_purge",
];

/// The wrap algorithm a key grant carries: the v2 wire string, MANDATORY
/// for every wrapped DEK (CC 3.3.2); v1 wraps none.
const WRAP_ALGORITHMS: &[&str] = &[crate::federation::at_rest_cascade::WRAP_ALGORITHM_V2];

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
            m("version", Ty::Uint, R, "federation_group_versions.version (a consistency check only)"),
            m("members", Ty::RosterMembers, R, "Family.members / Community.members (a set)"),
            m("founded_at", Ty::Ms, R, "founded_at"),
            m("consensus_protocol", Ty::Tstr, R, "consensus_protocol"),
            m("consensus_protocol_entrenched", Ty::Bool, O, "Family.consensus_protocol_entrenched (absent reads false)"),
            m("dissolved_at", Ty::Ms, O, "Family.dissolved_at"),
            m("policy", Ty::Map, O, "Community.policy_blob (an open map)"),
            m("cohort_subkind", Ty::Tstr, O, "a community's discriminator (CC 3.2; earlier: policy_blob.cohort_subkind)"),
            m("cohort_subkind_payload", Ty::Map, O, "a community's Option<SubkindPayload> (CC 3.2)"),
            m("membership", Ty::Tstr, O, "a community's founding row: \"private\" | \"public\" (CC 3.1.3.2; absent reads public)"),
        ],
        refs: &[
            RefRole { role: "head", presence: O, from: "prev_head_digest: the version this one extends (CC 3.2 T6); absent on version 1, present on every later one" },
            RefRole { role: "also:cites", presence: O, from: "charter_digest: the trust:charter row in force; and, for a geographic community (rc21, CC 3.2), each NEW member's location_proof:v1 row. A reader places each cited row by its family" },
        ],
        voices: &[
            Voice { from: "scrub_signature_classical / scrub_signature_pqc under authority_key_id", becomes: "the group key's own statement" },
            Voice { from: "cosignatures (RosterCosignature)", becomes: "one statement per listed member over the same payload" },
            Voice { from: "supersede_proof.quorum_signatures (ThresholdSignature)", becomes: "the predecessor roster's holders' statements, counted at its consensus_protocol" },
            Voice { from: "SignedCommunity.lineage", becomes: "nothing carried: each prior version is its own held row, named by refs.head" },
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
            m("removed_at", Ty::Ms, Presence::RequiredWhen("dimension", &["removal"]), "MembershipRevocation.removed_at"),
            m("joined_at", Ty::Ms, Presence::RequiredWhen("dimension", &["widening"]), "MembershipWidening.joined_at"),
            m("effective_at", Ty::Ms, R, "effective_at"),
            m("valid_until", Ty::Ms, O, "a time-boxed guest's widening (CC 3.3.4)"),
            m("reason", Ty::Uint, O, "MembershipRevocation.reason, as a code of the closed registry (free text: body.note)"),
            m("role", Ty::Tstr, O, "MembershipWidening.role"),
            m("witness_set", Ty::IdentityRefs, O, "MembershipRevocation.witness_set (vouching key ids, not signatures)"),
        ],
        refs: &[
            RefRole { role: "head", presence: R, from: "the roster version the change is counted over (CC 2.6.1.9; earlier: the signed instant)" },
            RefRole { role: "also:cites", presence: O, from: "a widening: the acceptance it spends (CC 3.1.3.2); a node's widening has none" },
        ],
        voices: &[
            Voice { from: "scrub_signature_* under authority_key_id", becomes: "the proposer's statement" },
            Voice { from: "cosignatures (RosterCosignature)", becomes: "the roster members' statements, counted at the group's consensus_protocol" },
        ],
        table: "federation_{family,community}_membership_{revocations,widenings}",
    },
    FamilyPayload {
        family: "identity:occurrence",
        replaces: "SignedIdentityOccurrence / IdentityOccurrence (an identity:occurrence:v1 row)",
        authorship: "authored (by a live roster key of the identity); the occurrence key's own statement is a second voice, role occurrence_key (party sub)",
        sub: "the occurrence key's identity-ref (occurrence_key_id)",
        members: &[
            m("identity_key_id", Ty::IdentityRef, R, "identity_key_id (equals author)"),
            m("occurrence_key_id", Ty::IdentityRef, R, "occurrence_key_id (equals sub)"),
            m("device_class", Ty::Tstr, R, "device_class: phone | laptop | server | embedded | agent | service"),
            m("hardware_attestation", Ty::Bstr, O, "hardware_attestation (base64 in the earlier form)"),
            m("transport_destination", Ty::Map, O, "transport_destination: exactly reticulum_x25519_pubkey (bstr 32), reticulum_ed25519_pubkey (bstr 32), app_name (tstr), aspects ([* tstr]), destination_hash (bstr 16, derived per CC 3.3.6.3)"),
            m("transit_xwing_pubkey", Ty::Bstr, O, "transport_destination's transit_xwing_pubkey: 1216 bytes, at the top level (CC 3.3.6.2)"),
            m("onion_hop_xwing_pubkey", Ty::Bstr, O, "transport_destination's onion_hop_xwing_pubkey: 1216 bytes, at the top level (CC 3.3.6.2)"),
            m("dial_hints", Ty::Any, O, "dial hints, most preferred first: [1*8 [type (uint, at most 255), body (bstr, 0..255 bytes, the FedCode hint body)]]; hints only, no transport identity; a genesis serve seat needs one tcp hint (shape and rule judged by Verify's reader, 23.4.0)"),
            m("onion_relay", Ty::Map, O, "exactly {\"opt_out\": true}, on a node that opts out of relaying (CC 3.3.6.2)"),
            m("encryption_pubkeys", Ty::Map, O, "encryption_pubkeys: exactly x25519 (bstr 32) and ml_kem_768 (bstr 1184)"),
            m("build_manifest_hash", Ty::Digest, O, "build_manifest_hash"),
            m("valid_until", Ty::Ms, O, "valid_until (absent: indefinite; present: later than asserted_at)"),
        ],
        refs: &[
            RefRole { role: "head", presence: R, from: "the last landed self-roster row of the identity (CC 2.7 rulings item 2); the first bind of a new identity names the genesis key's own key:record row" },
            RefRole { role: "further_heads", presence: O, from: "the other self-roster tips this row merges, as group:roster's" },
            RefRole { role: "also:cites", presence: O, from: "build_manifest_ref: the provenance:build_manifest:{target} row" },
        ],
        voices: &[
            Voice { from: "SignedIdentityOccurrence.signature (TransportBindingSignature) under attesting_key_id", becomes: "the author's statement: a live roster key of the identity (iss = identity_key_id)" },
            Voice { from: "none (the earlier form carried no proof of possession)", becomes: "the occurrence key's own statement over the same payload (iss = sub), required before the author's" },
            Voice { from: "the self-roster door's assent rows (objection:assent:v1)", becomes: "further roster keys' statements as the identity over the same payload, a strict majority of the live roster counted" },
        ],
        table: "federation_identity_occurrences (+ federation_identity_occurrence_history, transport_destinations)",
    },
    FamilyPayload {
        family: "identity:occurrence_revocation",
        replaces: "IdentityOccurrenceRevocation (an identity:occurrence_revocation:v1 row; no framed object is embedded)",
        authorship: "counted for a user self (identity=user), else authored",
        sub: "the occurrence's identity-ref",
        members: &[
            m("identity_key_id", Ty::IdentityRef, R, "identity_key_id (the occurrence record's own name, CC ruling v62)"),
            m("occurrence_key_id", Ty::IdentityRef, R, "occurrence_key_id (equals sub)"),
            m("revoked_at", Ty::Ms, R, "revoked_at"),
            m("effective_at", Ty::Ms, R, "effective_at (may be later than asserted_at)"),
            m("reason", Ty::Uint, O, "reason, as a code of the closed registry (free text: body.note)"),
            m("witness_set", Ty::IdentityRefs, O, "witness_set"),
        ],
        refs: &[
            RefRole { role: "head", presence: R, from: "the last landed self-roster row of the identity (CC 2.7 rulings item 2); the first bind of a new identity names the genesis key's own key:record row" },
            RefRole { role: "further_heads", presence: O, from: "the other self-roster tips this row merges, as group:roster's" },
            RefRole { role: "also:cites", presence: R, from: "the key:record of each voice, and that key's occurrence binding when it has one (CC rc21 7f94be1); REQUIRED: the per-voice coverage is T2's door" },
        ],
        voices: &[
            Voice { from: "FramedOccurrenceRevocation.signature (TransportBindingSignature) under attesting_key_id", becomes: "the revoker's statement (the statement's signer)" },
            Voice { from: "the row's additional_scrubs (roster cosigs, user self)", becomes: "the roster members' statements, a strict majority counted" },
        ],
        table: "federation_identity_occurrence_revocations",
    },
    FamilyPayload {
        family: "cosign:{state}",
        replaces: "cosign:pending:v1 / cosign:signature:v1 rows (the states are closed: pending | signature)",
        authorship: "authored",
        sub: "the event's sub (the group's identity-ref)",
        members: &[],
        refs: &[],
        voices: &[
            Voice { from: "cosign:pending row's embedded event and the primary's signature over its signing bytes", becomes: "the primary's statement over the event's own payload and header, named by the event's row id; no member of its own" },
            Voice { from: "cosign:signature row's scrub + additional_scrubs", becomes: "a further statement over the event's own payload (CC 2.6.1.9); no member of its own" },
            Voice { from: "LineageHeadCosign (signature_classical / signature_pqc under witness_key_id)", becomes: "no row and no state of this family: the ciris.lineage_head_cosign.v1 object (CC 3.4.10, CC 5.3.1), its edition-2 form OPEN" },
        ],
        table: "ceg_statements only",
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
        authorship: "authored, but counted for leaf steward_purge and for group=affiliations & seats=one (CC 4.4.3.12)",
        sub: "the claimant's identity-ref",
        members: &[
            m("legal_basis", Ty::Tstr, R, "legal_basis (CC 3.3.2's closed set; equals the {basis} leaf)"),
            m("claimant", Ty::IdentityRef, R, "claimant_key_id"),
            m("content_sha256", Ty::Digest, R, "content_sha256 (the selection digest)"),
            m("content_holders", Ty::IdentityRefs, R, "content_holder_key_ids"),
            m("claim_text", Ty::Tstr, R, "claim_text"),
            m("good_faith_statement", Ty::Tstr, R, "good_faith_statement"),
            m("jurisdiction", Ty::Tstr, R, "jurisdiction"),
            m("evidence_refs", Ty::Digests, O, "evidence_refs (the dry-run ledger digests; a URI reference is OPEN)"),
            m("perceptual_hash", Ty::Any, O, "perceptual_hash (CC 3.3.2; its type is OPEN)"),
            m("counter_notice_channel", Ty::Tstr, O, "counter_notice_channel (CC 3.3.2)"),
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
            m("evidence_refs", Ty::Digests, R, "evidence_refs: exactly one, the blob's address digest"),
            m("size", Ty::Uint, Presence::RequiredWhen("custody_state", &["here"]), "size"),
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
            m("wrap_algorithm", Ty::Tstr, R, "GrantWrap.wrap_algorithm (the v2 wire string only)"),
            m("wrapped_dek", Ty::Bstr, R, "GrantWrap.wrapped_dek"),
            m("community", Ty::IdentityRef, Presence::RequiredWhen("axis", &["epoch"]), "community_key_id"),
            m("minter", Ty::IdentityRef, Presence::RequiredWhen("axis", &["epoch"]), "minter_key_id"),
            m("epoch", Ty::Uint, Presence::RequiredWhen("axis", &["epoch", "stream"]), "epoch"),
            m("at_rest_sha256", Ty::Digest, Presence::RequiredWhen("axis", &["content"]), "at_rest_sha256"),
            m("owner", Ty::IdentityRef, Presence::RequiredWhen("axis", &["content", "stream"]), "owner_key_id (the axis identity, CC 3.3.2)"),
            m("stream_id", Ty::Tstr, Presence::RequiredWhen("axis", &["stream"]), "stream_id"),
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
            m("k", Ty::Uint, R, "K (the chunk index acknowledged; CBOR member names are lowercase)"),
            m("chunk_root", Ty::Digest, R, "chunk_root"),
        ],
        refs: &[],
        voices: &[
            Voice { from: "signature (HybridSignature over the length-prefixed ciris-delivery-receipt/v1 bytes)", becomes: "the subscriber's composite statement over the payload; no inner signed object (the earlier layout is CC 8.11.30); the receipt store's HybridSignature is filled from its two halves" },
        ],
        table: "federation_stream_delivery_receipts",
    },
    FamilyPayload {
        family: "admission:unit",
        replaces: "nothing: new in rc21 (CC 2.7.11, the code scope of kernel admission; wire admission:unit:v1, row type scores)",
        authorship: "counted where refs.head is present (act = group), authored otherwise; one person's (authored) row naming an effect is at cohort_scope self and admits only on a host that person owns; every signer a person (identity_type holds user or accord_holder); no delegate role",
        sub: "the unit digest as tagged text, canonical:sha256:{hex} (not an identity-ref)",
        members: &[
            m("unit", Ty::Digest, R, "SHA-256 over the unit's bytes as the host loads them (a multi-file unit: its manifest's digest)"),
            m("capabilities", Ty::Tstrs, R, "the admitted capabilities: compute, read, net_send, submit, sign, store_write, actuate"),
            m("valid_until", Ty::Ms, R, "the lease closes (asserted_at opens it)"),
        ],
        refs: &[
            RefRole { role: "head", presence: O, from: "counted only: the roster head the count is over" },
        ],
        voices: &[
            Voice { from: "none (a new family)", becomes: "counted: one statement per voice over one payload, counted over the members at refs.head by the group's cosigned_act protocol, never fewer than two persons; a shortfall is held, never refused" },
        ],
        table: "ceg_statements + federation_attestations (the mapped scores row), held count_short until a counted row's count is met; no typed plane: the host's answer (admission_unit_runnable) reads the conclusion, the lease, the withdrawal, the standing and the receipt",
    },
    FamilyPayload {
        family: "identity_amendment",
        replaces: "the identity_amendment:v1 envelope (CC 3.1.5; rc21: authorized_by under refs.also.cites, no evidence_refs)",
        authorship: "authored (the agent's occurrence key)",
        sub: "the agent identity's identity-ref",
        members: &[
            m("amendment_digest", Ty::Digest, R, "amendment_digest (earlier: hex64); on the base link (no refs.prev), the base template manifest's digest"),
        ],
        refs: &[
            RefRole { role: "prev", presence: O, from: "the identity_amendment this link follows (rc21, CC 2.7.11); absent on the base link" },
            RefRole { role: "also:cites", presence: R, from: "authorized_by (rc21): the approving deferral:response:approved row, exactly one; evidence_refs is dropped" },
        ],
        voices: &[
            Voice { from: "scrub_signature_* under the agent's occurrence key", becomes: "the agent occurrence's statement" },
        ],
        table: "federation_attestations (identity_amendment:v1, gated identity_amendment_unauthorized)",
    },
    FamilyPayload {
        family: "deferral:request",
        replaces: "the deferral:request:v1 envelope (CC 3.1.5; rc21 CC ruling)",
        authorship: "authored (the deferring agent's occurrence key)",
        sub: "the agent identity's identity-ref",
        members: &[
            m("deferral_id", Ty::Tstr, R, "deferral_id (rc21, CC ruling): the deferral, as the agent names it; its response correlates on it"),
            m("reason_digest", Ty::Digest, R, "reason_digest (rc21, CC ruling): the digest of the agent's reason text (the text stays off the row)"),
        ],
        refs: &[],
        voices: &[
            Voice { from: "scrub_signature_* under the agent's occurrence key", becomes: "the deferring agent's statement" },
        ],
        table: "federation_attestations (answered by a deferral:response; routed by community_id, the pair room: a two-person community record, CC FINAL)",
    },
    FamilyPayload {
        family: "deferral:response:{outcome}",
        replaces: "the deferral:response:{approved,rejected}:v1 envelope (CC 3.1.5; rc21: the request under refs.answers)",
        authorship: "authored (the Wise Authority)",
        sub: "the agent identity's identity-ref",
        members: &[
            m("amendment_digest", Ty::Digest, O, "approved only: the digest of the exact text approved (CIRISServer#1365)"),
            m("call_fingerprint", Ty::Digest, O, "approved only: the call approved, SHA-256(CDE([\"CEG-call/2\", verb, tool, arguments, channel])) (rc21, CC 2.7.11)"),
            m("deferral_id", Ty::Tstr, R, "deferral_id (rc21, CC ruling): the deferral answered, as the agent named it; the response correlates on it"),
        ],
        refs: &[
            RefRole { role: "answers", presence: R, from: "the deferral:request answered (rc21; earlier references_attestation_id, never refs.target). The pair room rides community_id (FINAL, CC: a two-person community record; no room member)" },
        ],
        voices: &[
            Voice { from: "scrub_signature_* under the WA's key", becomes: "the Wise Authority's statement" },
        ],
        table: "federation_attestations (read by the identity_amendment gate)",
    },
    FamilyPayload {
        family: "location_proof:{version}",
        replaces: "the location_proof subject_kind (CC 3.3.3; wire location_proof:v1, a scores row)",
        authorship: "authored by the subject alone (subject-only: iss = sub, CC 4.5.9)",
        sub: "the subject's identity-ref (earlier subject_key_id; equals iss)",
        members: &[
            m("cell_id", Ty::Tstr, R, "cell_id: the H3 cell, lowercase hex (CC 2.6.6)"),
            m("cell_resolution", Ty::Uint, R, "cell_resolution: at most 7, rough-only (CC 2.6.6.1)"),
            m("attestation_evidence", Ty::Bstr, O, "attestation_evidence (earlier base64): a hardware-attested location claim"),
        ],
        refs: &[],
        voices: &[
            Voice { from: "scrub_signature_* under the subject's key", becomes: "the subject's statement" },
        ],
        table: "federation_attestations (read by a geographic roster version that cites it, CC 3.2)",
    },
    FamilyPayload {
        family: "transport:canonical_rebind",
        replaces: "the transport:canonical_rebind:v1 scores row (its additional_scrubs, and the carried SignedTransportDestination under transport_destination)",
        authorship: "counted (the accord's holders: a strict majority of the holders of the genesis bundle in force that refs.head names, each at its placed key; refused reserved_family_unseated otherwise, CC 3.4.7)",
        sub: "the seat's identity-ref (a serve node of the genesis bundle in force)",
        members: &[
            m("transit_xwing_pubkey", Ty::Bstr, R, "the carried row's transit_xwing_pubkey: 1216 bytes, pk_M then pk_X (CC 3.3.6.2)"),
            m("onion_hop_xwing_pubkey", Ty::Bstr, O, "the carried row's onion_hop_xwing_pubkey: 1216 bytes (CC 3.3.6.2)"),
            m("transport_destination", Ty::Map, O, "the carried row's transport_destination, as identity:occurrence's"),
        ],
        refs: &[
            RefRole { role: "head", presence: R, from: "none (new): the genesis bundle in force the re-bind is counted over, by its object id" },
        ],
        voices: &[
            Voice { from: "authority scrub + additional_scrubs by accord holders over the canonical envelope", becomes: "one statement per holder over the same payload, counted at a strict majority of the holders of the bundle in force" },
        ],
        table: "ceg_statements (no typed table; the seat's live transit key is read from the counted voices)",
    },
    // v62.0.0 (wave P7; CC 3.1.5, the ruling "the manifest form is the only
    // form") — the trace row. A foreign hunk for P1's table.
    FamilyPayload {
        family: "trace:{form}:{version}",
        replaces: "the trace:complete:v1 local mint and the bound-hybrid CompleteTrace signature (signature + signature_ml_dsa_65)",
        authorship: "authored (the agent: self-emitted, CC 3.4.5)",
        sub: "the agent's identity-ref (equals iss, author and the one subject_key_ids entry)",
        members: &[
            m("trace_id", Ty::Tstr, R, "CompleteTrace.trace_id (non-empty)"),
            m("agent_id_hash", Ty::Tstr, R, "CompleteTrace.agent_id_hash (non-empty)"),
            m("manifest", Ty::Map, R, "trace_manifest:v1: schema, content_hash (sha256: + 64 lowercase hex over the trace blob's bytes as stored), byte_len, component_count, run_kind; the trace itself is a blob named by evidence_refs, never inline"),
        ],
        refs: &[],
        voices: &[
            Voice { from: "signature (Ed25519) and signature_ml_dsa_65 bound over the trace's canonical bytes", becomes: "the agent's statement over the manifest" },
        ],
        table: "federation_attestations (the row); the trace blob in federation_blobs; trace_events projected at ingest from the blob",
    },
];

/// The members any row may carry, beyond its family's: the envelope's
/// named members (`attestation-envelope`, CC 2.6.1.3) and the CC 2.1
/// visibility / revocability / delivery members CC 2.6.1.4 maps to
/// "payload members of the same names" (`cohort_scope`, `community_id`,
/// `family_id`, `subject_key_ids`, `delivery_mode`). v62.0.0 (wave P1): a
/// custody report's or key grant's cohort target is `community_id` /
/// `family_id` here, not a family member. A family's map stays closed: a
/// custody report refuses the envelope's `expires_at` ([`PROSE_RULES`]).
pub const COMMON: &[&str] = &[
    "asserted_at",
    "author",
    "body",
    "cohort_scope",
    "community_id",
    "confidence",
    "delivery_mode",
    "dimension",
    "evidence_refs",
    "expires_at",
    "family_id",
    "passed",
    "reason",
    "refs",
    "salt",
    "score",
    "seat_commitment",
    "subject_key_ids",
    "total",
    "valid_from",
    "valid_until",
    "weight",
];

/// The common members persist types (the rest are typed by Verify's door
/// or are the CC 2.1 members the earlier gates read as they are).
const COMMON_TYPED: &[Member] = &[
    m("asserted_at", Ty::Ms, R, "asserted_at"),
    m("author", Ty::IdentityRef, O, "the author's iss"),
    m("dimension", Ty::Tstr, O, "dimension"),
    m("refs", Ty::Map, O, "refs"),
    m("reason", Ty::Uint, O, "a code of the closed registry"),
    m("body", Ty::Map, O, "body"),
    m("evidence_refs", Ty::Digests, O, "evidence_refs"),
    m("seat_commitment", Ty::Digest, O, "seat_commitment"),
    m("valid_from", Ty::Ms, O, "valid_from"),
    m("valid_until", Ty::Ms, O, "valid_until"),
    m("expires_at", Ty::Ms, O, "expires_at"),
    m("salt", Ty::Bstr, O, "salt"),
];

/// The longest `body.note`, in bytes (CC 2.6.1.10; `tstr .size (0..2048)`).
pub const BODY_NOTE_MAX: usize = 2048;

/// v62.0.0 (wave P1) — the hash-digest members (`[-16, bstr .size 32]`,
/// SHA-256) any family may carry, that the earlier-form gates read as 64
/// lowercase hex: the mapping projects each back to hex (`ingest`) and a
/// producer states each as a digest (`emit`). `evidence_refs` is a sequence
/// of them, the others one. `amendment_digest` rides
/// `deferral:response:approved` and `identity_amendment` (CC 3.1.5): the
/// hex the identity-amendment gate compares.
pub const HASH_DIGEST_MEMBERS: &[&str] = &[
    "evidence_refs",
    "carried",
    "seat_commitment",
    "amendment_digest",
    "call_fingerprint",
];

/// v62.0.0 (wave P1e, E10's finding) — is `member` a hash-digest member of a
/// payload of `family_id` (the header's family id)? Every family's
/// [`HASH_DIGEST_MEMBERS`], and the family's own `Digest` / `Digests`
/// members. The mapping renders each as the 64-lowercase-hex text the
/// earlier-form readers read ([`digest_json`]).
#[must_use]
pub fn is_digest_member(family_id: &str, member: &str) -> bool {
    HASH_DIGEST_MEMBERS.contains(&member)
        || family_by_id(family_id).is_some_and(|f| {
            f.members
                .iter()
                .any(|m| m.name == member && matches!(m.ty, Ty::Digest | Ty::Digests))
        })
}

/// A hash digest `[-16, bstr .size 32]` as lowercase hex.
#[must_use]
pub fn digest_hex(v: &Value) -> Option<String> {
    match v.as_array()? {
        [alg, d] if alg.as_i64() == Some(-16) => {
            d.as_bytes().filter(|b| b.len() == 32).map(hex::encode)
        }
        _ => None,
    }
}

/// v62.0.0 (wave P1e) — a digest member's JSON projection: one digest as
/// its hex text, a sequence or set of digests as an array of hex texts (in
/// order). `None` for a value that is neither (left to the generic
/// projection, and refused at the door by the member list).
#[must_use]
pub fn digest_json(v: &Value) -> Option<serde_json::Value> {
    if let Some(h) = digest_hex(v) {
        return Some(serde_json::Value::String(h));
    }
    let hexes: Option<Vec<serde_json::Value>> = v
        .as_array()?
        .iter()
        .map(|e| digest_hex(e).map(serde_json::Value::String))
        .collect();
    hexes.map(serde_json::Value::Array)
}

/// v62.0.0 (wave P1e; CC ruling) — **a number in a free-form body, as
/// CBOR**: the EXACT decimal of the source JSON number's text (never via
/// `f64`; persist builds `serde_json` with `arbitrary_precision`, so the
/// number keeps its token).
///
/// - An integral value is a plain CBOR integer: `2.0` → `2`, `1e2` → `100`,
///   `-3` → `-3`.
/// - A non-integral value is CBOR tag 4, `[exponent, mantissa]`, normalised:
///   a negative exponent and a mantissa NOT divisible by 10. `0.5` →
///   `4([-1, 5])`, `1.25` → `4([-2, 125])`, `-0.050` → `4([-2, -5])`.
/// - A mantissa or an integral value outside the CBOR integer range
///   (`-2^64 ..= 2^64 - 1`; v62.0.0 R1-v2332 alignment: Verify 23.3.2's
///   `from_json` limit, no stricter), or an exponent that cannot be read, is
///   refused `body_number_unrepresentable`.
///
/// Fixed-scale MEMBERS (`score`, `confidence`, `weight`) are NOT this:
/// they stay fixed6 integers (CC 2.6.1.5). The reader's check is
/// [`check_body_numbers`].
///
/// # Errors
/// `body_number_unrepresentable` (`federation_malformed_row`).
pub fn body_number(n: &serde_json::Number) -> Result<Value, Error> {
    let text = n.to_string();
    let refuse = |why: &str| {
        Error::malformed_row(
            PLANE,
            crate::federation::malformed_row::BODY_NUMBER_UNREPRESENTABLE,
            format!("body number {text}: {why}"),
        )
    };
    let (negative, rest) = match text.strip_prefix('-') {
        Some(r) => (true, r),
        None => (false, text.as_str()),
    };
    let (num, exp) = match rest.find(['e', 'E']) {
        Some(i) => (&rest[..i], &rest[i + 1..]),
        None => (rest, "0"),
    };
    let exp: i64 = exp
        .strip_prefix('+')
        .unwrap_or(exp)
        .parse()
        .map_err(|_| refuse("its exponent cannot be read"))?;
    let (int_part, frac_part) = match num.split_once('.') {
        Some((i, f)) => (i, f),
        None => (num, ""),
    };
    let digits_ok = |d: &str| d.bytes().all(|b| b.is_ascii_digit());
    if int_part.is_empty() || !digits_ok(int_part) || !digits_ok(frac_part) {
        return Err(refuse("not a JSON number"));
    }
    // The decimal digits and the power of ten they scale by.
    let mut digits: String = format!("{int_part}{frac_part}")
        .trim_start_matches('0')
        .to_owned();
    let frac_len = i64::try_from(frac_part.len()).map_err(|_| refuse("too many digits"))?;
    let mut exponent = exp
        .checked_sub(frac_len)
        .ok_or_else(|| refuse("its exponent is out of range"))?;
    if digits.is_empty() {
        return Ok(Value::Uint(0));
    }
    // Normalise: no trailing zero in the mantissa.
    while digits.ends_with('0') {
        digits.pop();
        exponent = exponent
            .checked_add(1)
            .ok_or_else(|| refuse("its exponent is out of range"))?;
    }
    if digits.len() > 38 {
        return Err(refuse("its mantissa is outside the CBOR integer range"));
    }
    let magnitude: i128 = digits
        .parse()
        .map_err(|_| refuse("its mantissa is outside the CBOR integer range"))?;
    let signed = if negative { -magnitude } else { magnitude };
    if exponent >= 0 {
        // Integral: mantissa × 10^exponent, a plain CBOR integer.
        let scale = u32::try_from(exponent)
            .ok()
            .and_then(|e| 10i128.checked_pow(e))
            .ok_or_else(|| refuse("an integral value outside the CBOR integer range"))?;
        let v = signed
            .checked_mul(scale)
            .ok_or_else(|| refuse("an integral value outside the CBOR integer range"))?;
        return int_value(v)
            .ok_or_else(|| refuse("an integral value outside the CBOR integer range"));
    }
    let (Some(e), Some(m)) = (int_value(i128::from(exponent)), int_value(signed)) else {
        return Err(refuse("its mantissa is outside the CBOR integer range"));
    };
    Ok(Value::Tag(4, Box::new(Value::Array(vec![e, m]))))
}

/// v62.0.0 (wave P1e; lead's ruling) — the FREE-FORM BODY subtrees, where a
/// JSON number states through [`body_number`] (a float becomes a tag-4
/// decimal) instead of being refused: `(family, member)`, `*` for every
/// family. The CDDL's `body`, and `hard_case:{kind}`'s `hard_case` body
/// (P3). A producer whose family carries another free-form body appends it.
pub const BODY_MEMBERS: &[(&str, &str)] = &[
    ("*", "body"),
    ("hard_case:{kind}", "hard_case"),
    // v62.0.0 (P1-fix6; the lead's ruling) — a ledger's free-form numbers:
    // a credits `balance` and an `expertise` are body numbers (an integer
    // when integral, else the normalised tag-4 decimal, exact), never fixed6
    // (reserved for score / confidence / weight, CC 2.6.1.5).
    ("credits:{domain}:{language}:{subject}", "balance"),
    ("expertise:{domain}:{language}", "expertise"),
];

/// v62.0.0 (wave P1e) — is `member` a free-form body of a payload of
/// `family_id` (the header's family id)?
#[must_use]
pub fn is_body_member(family_id: &str, member: &str) -> bool {
    BODY_MEMBERS.iter().any(|(fam, m)| {
        *m == member
            && (*fam == "*" || ciris_verify_core::namespace_match::family_id(fam) == family_id)
    })
}

/// v62.0.0 (wave P1e) — **the decoder's inverse of [`body_number`]**: a
/// normalised tag-4 decimal `[exponent, mantissa]` as the EXACT JSON number
/// it states (`4([-2, 125])` → `1.25`), its text built from the digits,
/// never via `f64` (`arbitrary_precision` keeps the token). `None` for a
/// value that is not a normalised decimal.
#[must_use]
pub fn json_number_of_decimal(v: &Value) -> Option<serde_json::Number> {
    let Value::Tag(4, inner) = v else {
        return None;
    };
    let [e, m] = inner.as_array()? else {
        return None;
    };
    // v62.0.0 (R1-v2332 alignment) — the mantissa anywhere in the CBOR
    // integer range, as Verify 23.3.2 admits it (`Nint(k)` is `-1 - k`).
    let e = e.as_i64()?;
    let (negative, magnitude) = match m {
        Value::Uint(u) => (false, u128::from(*u)),
        Value::Nint(k) => (true, u128::from(*k) + 1),
        _ => return None,
    };
    if e >= 0 || magnitude == 0 || magnitude % 10 == 0 {
        return None;
    }
    let digits = magnitude.to_string();
    let places = usize::try_from(e.unsigned_abs()).ok()?;
    let text = if digits.len() > places {
        let (int, frac) = digits.split_at(digits.len() - places);
        format!("{int}.{frac}")
    } else {
        format!("0.{}{digits}", "0".repeat(places - digits.len()))
    };
    let text = if negative { format!("-{text}") } else { text };
    serde_json::from_str(&text).ok()
}

/// An integer as a CBOR integer value, if it fits (`-2^64 ..= 2^64 - 1`).
fn int_value(v: i128) -> Option<Value> {
    if v >= 0 {
        u64::try_from(v).ok().map(Value::Uint)
    } else {
        // -1 - n for a negative v.
        u64::try_from(-(v + 1)).ok().map(Value::Nint)
    }
}

/// v62.0.0 (wave P1e; CC ruling) — **the reader's check of decimal
/// numbers**: every CBOR tag 4 anywhere in `v` is `[exponent, mantissa]`
/// with a negative exponent, a mantissa not divisible by 10 (and not zero),
/// both integers. A non-normalised decimal (`4([-1, 50])`, `4([0, 3])`) is
/// refused: one value has one spelling. The door runs it at the schema step
/// (with the payload's common members, [`check_by_id`]).
///
/// # Errors
/// `edition2_payload_invalid`, naming the decimal.
pub fn check_body_numbers(v: &Value) -> Result<(), Error> {
    // v62.0.0 (R1-v2332; CC rc21 cddl 87–91, CIRISVerify 23.3.2) — a bignum
    // (tag 2 / 3) that does not fit a CBOR integer, as a member or as a
    // decimal's mantissa, is a number a body cannot carry:
    // `body_number_unrepresentable`, the token `body_number` refuses the
    // same value with on the way in. A bignum that DOES fit an integer is a
    // second encoding (Verify's reader: `malformed:ceg-value`, or a decode
    // refusal inside a decimal).
    fn big_bignum(v: &Value) -> bool {
        matches!(v, Value::Tag(2 | 3, b)
            if b.as_bytes().is_some_and(|b| b.len() > 8 && b[0] != 0))
    }
    fn unrepresentable(inner: &Value) -> Error {
        Error::malformed_row(
            PLANE,
            malformed_row::BODY_NUMBER_UNREPRESENTABLE,
            format!("a body number outside CBOR's integer range: {inner:?}"),
        )
    }
    fn walk(v: &Value) -> Result<(), Error> {
        match v {
            Value::Tag(4, inner) => {
                if let Some([Value::Nint(_), m]) = inner.as_array() {
                    if big_bignum(m) {
                        return Err(unrepresentable(inner));
                    }
                }
                // Verify's `cde::decimal_is_normal` (23.3.2), read the same
                // way: a negative exponent, and a mantissa anywhere in CBOR's
                // integer range whose magnitude is not divisible by ten (so
                // not zero).
                let ok = match inner.as_array() {
                    Some([Value::Nint(_), m]) => {
                        let mag = match m {
                            Value::Uint(n) => Some(u128::from(*n)),
                            Value::Nint(n) => Some(u128::from(*n) + 1),
                            _ => None,
                        };
                        mag.is_some_and(|m| m % 10 != 0)
                    }
                    _ => false,
                };
                if ok {
                    Ok(())
                } else {
                    Err(refuse(format!(
                        "a decimal (tag 4) that is not normalised (a negative exponent, a \
                         mantissa not divisible by 10): {inner:?}"
                    )))
                }
            }
            x if big_bignum(x) => Err(unrepresentable(x)),
            Value::Tag(_, inner) => walk(inner),
            Value::Array(a) => a.iter().try_for_each(walk),
            Value::Map(m) => m.iter().try_for_each(|(k, x)| {
                walk(k)?;
                walk(x)
            }),
            _ => Ok(()),
        }
    }
    walk(v)
}

/// The `also` roles of `refs`, a closed registry (CC 2.6.1.3, the CDDL's
/// `also-role`), as [`names_of`] spells them.
pub const ALSO_ROLES: &[&str] = &["also:ack", "also:cites"];

/// How a family's first parameter (its leaf, `dimension`'s second segment)
/// bounds this module's table.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Leaves {
    /// A closed set: a payload at any other leaf is refused.
    Closed(&'static [&'static str]),
    /// The table maps these leaves; a payload at another registered leaf
    /// is not this table's (its forward payload is OPEN) and passes.
    Mapped(&'static [&'static str]),
    /// v62.0.0 (wave P1e) — the table maps every leaf but these; a payload at
    /// one of these is not this table's and passes.
    Except(&'static [&'static str]),
}

/// v62.0.0 (wave P1) — the leaves each parameterised family's table
/// covers. The membership stages the table maps are the counted leaves,
/// `widening` and `removal` (CC 3.1.3.2); the cosign states are closed
/// (CC 3.1.3); the takedown bases are CC 3.3.2's.
pub const LEAVES: &[(&str, Leaves)] = &[
    (
        "membership:{stage}",
        Leaves::Mapped(&["widening", "removal"]),
    ),
    ("cosign:{state}", Leaves::Closed(&["pending", "signature"])),
    ("takedown_notice:{basis}", Leaves::Closed(LEGAL_BASES)),
    (
        "deferral:response:{outcome}",
        Leaves::Closed(&["approved", "rejected"]),
    ),
    // v62.0.0 (wave P1e, E3) — a peer de-admission
    // (`revocation:peer_admission:{reason}:v1`) is a `scores` denial (a
    // negative score about the peer), not an entity revocation: its payload
    // is not this table's (no `revoked_at` / `effective_at`).
    (
        "revocation:{entity_type}:{reason}",
        Leaves::Except(&["peer_admission"]),
    ),
];

/// v62.0.0 (wave P1) — members whose text is one of a closed set, compared
/// byte for byte: `(family, member, values)`.
pub const CLOSED_VALUES: &[(&str, &str, &[&str])] = &[
    ("group:roster", "membership", &["private", "public"]),
    ("takedown_notice:{basis}", "legal_basis", LEGAL_BASES),
    ("custody:{kind}", "custody_state", &["here", "none"]),
    ("key_grant:{axis}", "wrap_algorithm", WRAP_ALGORITHMS),
];

/// v62.0.0 (wave P1) — the families whose statement is over ANOTHER row's
/// payload (a cosign state: the event's own), so the payload's members are
/// the event family's and are checked under it; this table checks only the
/// state.
pub const OVER_THE_EVENT: &[&str] = &["cosign:{state}"];

/// v62.0.0 (wave P1) — the rules the member lists cannot state, each
/// checked by [`check`] (refusal `edition2_payload_invalid`): `(family,
/// rule)`; `*` is every mapped family.
pub const PROSE_RULES: &[(&str, &str)] = &[
    (
        "*",
        "every `refs.also` role is `ack` or `cites` (a closed registry, CC 2.6.1.3)",
    ),
    (
        "*",
        "`body.note`, when present, is text of at most 2048 bytes",
    ),
    (
        "*",
        "a composer (`withdraws`, `recants`, `supersedes`) carries its target's family but its own payload: the common members and `refs.target`, never the target family's list",
    ),
    (
        "group:roster",
        "`refs.head` is absent on version 1 and present on every later version",
    ),
    (
        "group:roster",
        "a `geographic` community names each new member's `location_proof:v1` row under `refs.also.cites` (CC 3.2, rc21): a founding version (every member new) cites at least as many rows as it lists members; the fold waits for the proofs and concludes nothing unless each is contained in the constraint and live at `asserted_at`",
    ),
    (
        "takedown_notice:{basis}",
        "`legal_basis` equals the `{basis}` leaf of `dimension`",
    ),
    (
        "takedown_notice:{basis}",
        "a `steward_purge` notice is counted: it carries no `author`",
    ),
    (
        "location_proof:{version}",
        "`cell_resolution` is at most 7 (rough-only, CC 2.6.6.1); `cell_id` is lowercase hex",
    ),
    (
        "custody:{kind}",
        "`evidence_refs` holds exactly one digest, the blob's address",
    ),
    (
        "deferral:response:{outcome}",
        "`amendment_digest` and `call_fingerprint` ride an `approved` response only",
    ),
    (
        "deferral:response:{outcome}",
        "the request answered stands under `refs.answers`, never `refs.target` (rc21)",
    ),
    (
        "deferral:response:{outcome}",
        "a response carries `deferral_id` (required) and never `reason_digest` (the request's own, CC ruling)",
    ),
    (
        "identity_amendment",
        "`refs.also.cites` names exactly one row, the approving response; the amendment carries no `evidence_refs` (rc21)",
    ),
    (
        "custody:{kind}",
        "`expires_at` is not a member: a report is live 72 hours from its `asserted_at` (CC 3.1.3.3)",
    ),
];

/// v62.0.0 (wave P1e; CC rc21 CC 2.7.11) — the family id of the code scope
/// of kernel admission.
pub const ADMISSION_UNIT_FAMILY: &str = "admission:unit";

/// v62.0.0 (wave P1e; CC 2.7.11) — the closed capability set of an
/// `admission:unit` row.
pub const ADMISSION_CAPABILITIES: &[&str] = &[
    "compute",
    "read",
    "net_send",
    "submit",
    "sign",
    "store_write",
    "actuate",
];

/// v62.0.0 (wave P1e; CC 2.7.11) — the effect capabilities (`compute` and
/// `read` are not effects). A row naming one is counted (never on fewer than
/// two persons), or one person's row at `cohort_scope: self` that admits only
/// on a host that person owns (AU-fix1; CC 2.7.11 P2:1682).
pub const ADMISSION_EFFECTS: &[&str] = &["net_send", "submit", "sign", "store_write", "actuate"];

/// v62.0.0 (wave P1e; CC 2.7.11, constants.tsv) — `unit_lease_max_secs`, in
/// ms: a lease closes at most this long after it opens.
pub const UNIT_LEASE_MAX_MS: u64 = 86_400 * 1_000;

/// v62.0.0 (wave P1e) — the `sub` of an `admission:unit` row: its unit's
/// digest as tagged text.
pub const ADMISSION_UNIT_SUB_PREFIX: &str = "canonical:sha256:";

/// v62.0.0 (wave P1e; CC 2.7.11) — the verifier's rules over an
/// `admission:unit` payload, each refused with its OWN token (not
/// `edition2_payload_invalid`): `(token, rule)`. The pure four are
/// [`check_admission_unit`]'s; the person rule reads the signer's key record
/// (`edition2::ingest`, after Verify's verdict).
pub const ADMISSION_UNIT_RULES: &[(&str, &str)] = &[
    (
        crate::federation::malformed_row::ADMISSION_UNIT_MALFORMED,
        "`author` and `refs.head` are not both present or both absent; `sub` is `canonical:sha256:{hex}` of `unit`",
    ),
    (
        crate::federation::malformed_row::ADMISSION_CAPABILITY_UNKNOWN,
        "`capabilities` is non-empty and within the closed set",
    ),
    (
        crate::federation::malformed_row::ADMISSION_LEASE_OUT_OF_WINDOW,
        "`asserted_at < valid_until <= asserted_at + unit_lease_max_secs * 1000` (86400 s)",
    ),
    (
        crate::federation::malformed_row::ADMISSION_OWNER_ROW_NOT_SELF,
        "one person's (authored) row that names an effect capability (`net_send`, `submit`, `sign`, `store_write`, `actuate`) is at `cohort_scope: self`",
    ),
    (
        crate::federation::malformed_row::ADMISSION_ISSUER_NOT_PERSON,
        "every signer's key record holds `user` or `accord_holder` (the statement alone is refused)",
    ),
];

/// v62.0.0 (wave P1e; AU-fix1) — **the verifier's pure rules over an
/// `admission:unit` payload** (CC 2.7.11), after its member list
/// ([`check`]) passed: authored XOR counted, `sub` is the unit's digest, the
/// capabilities closed and non-empty, the lease window, and one person's row
/// that names an effect at `cohort_scope: self` (CC 2.7.11 P2:1682: "Such a
/// row MUST be at `self` scope; at any other scope it is Invalid
/// (`admission_owner_row_not_self`)"). An authored row that names no effect
/// takes any scope, as a counted row does. Each refusal carries the
/// verifier's token. Pure; the door runs it with its other pure gates. (The
/// person rule needs the signer's key record and runs after Verify's
/// verdict; the count is a fold, `admission::check_admission_unit_counted`.)
///
/// # Errors
/// `admission_unit_malformed`, `admission_capability_unknown`,
/// `admission_lease_out_of_window`, `admission_owner_row_not_self`.
pub fn check_admission_unit(sub: &str, payload: &Value) -> Result<(), Error> {
    use crate::federation::malformed_row as mr;
    let fail = |reason: &'static str, msg: String| {
        Error::malformed_row(PLANE, reason, format!("{ADMISSION_UNIT_FAMILY}: {msg}"))
    };
    let authored = payload.get_text("author").is_some();
    let counted = names_of(payload)
        .map(|n| n.iter().any(|x| x.role == "head"))
        .unwrap_or(false);
    if authored == counted {
        return Err(fail(
            mr::ADMISSION_UNIT_MALFORMED,
            "exactly one of `author` (authored) and `refs.head` (counted) is present".into(),
        ));
    }
    let unit_hex = payload
        .get_text("unit")
        .and_then(Value::as_array)
        .and_then(|a| a.get(1))
        .and_then(Value::as_bytes)
        .map(hex::encode)
        .unwrap_or_default();
    if sub != format!("{ADMISSION_UNIT_SUB_PREFIX}{unit_hex}") {
        return Err(fail(
            mr::ADMISSION_UNIT_MALFORMED,
            format!("`sub` {sub:?} is not {ADMISSION_UNIT_SUB_PREFIX}{{hex}} of `unit`"),
        ));
    }
    let caps: Vec<&str> = payload
        .get_text("capabilities")
        .and_then(Value::as_array)
        .map(|a| a.iter().filter_map(Value::as_text).collect())
        .unwrap_or_default();
    if caps.is_empty() || caps.iter().any(|c| !ADMISSION_CAPABILITIES.contains(c)) {
        return Err(fail(
            mr::ADMISSION_CAPABILITY_UNKNOWN,
            format!("`capabilities` {caps:?} is empty or outside {ADMISSION_CAPABILITIES:?}"),
        ));
    }
    let at = payload.get_text("asserted_at").and_then(Value::as_u64);
    let until = payload.get_text("valid_until").and_then(Value::as_u64);
    match (at, until) {
        (Some(a), Some(u)) if a < u && u - a <= UNIT_LEASE_MAX_MS => {}
        _ => {
            return Err(fail(
                mr::ADMISSION_LEASE_OUT_OF_WINDOW,
                format!(
                    "the lease [{at:?}, {until:?}) is not open, or longer than {UNIT_LEASE_MAX_MS} ms"
                ),
            ));
        }
    }
    // AU-fix1 (CC 2.7.11 P2:1682) — one person's row that names an effect
    // admits only on a host that person owns, and stands at `self`. An absent
    // `cohort_scope` reads as the earlier default (`federation`), so such a
    // row states `self`. (Which host it admits on is the host's read:
    // `edition2::admission_unit::admission_unit_runnable`.)
    if authored && payload.get_text("cohort_scope").and_then(Value::as_text) != Some("self") {
        if let Some(e) = caps.iter().find(|c| ADMISSION_EFFECTS.contains(c)) {
            return Err(fail(
                mr::ADMISSION_OWNER_ROW_NOT_SELF,
                format!(
                    "one person's row names the effect capability `{e}` at a scope other than \
                     `self`: it admits only on that person's own host"
                ),
            ));
        }
    }
    Ok(())
}

/// The payload of `family`, if this module maps it.
#[must_use]
pub fn family(family: &str) -> Option<&'static FamilyPayload> {
    FAMILIES.iter().find(|f| f.family == family)
}

/// v62.0.0 (wave P1d) — the payload of the family a statement's header names
/// (label -70002, the family id: each `{name}` written `.name`, CC 2.6), if
/// this module maps it.
#[must_use]
pub fn family_by_id(family_id: &str) -> Option<&'static FamilyPayload> {
    FAMILIES
        .iter()
        .find(|f| ciris_verify_core::namespace_match::family_id(f.family) == family_id)
}

/// v62.0.0 (wave P1e; CC rc21) — how many rows a [`REF_MEMBERS`] entry's
/// earlier member holds.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum RefShape {
    /// One row id (lowercase hex text).
    One,
    /// A list of row ids (an array of lowercase hex text).
    Many,
}

/// v62.0.0 (wave P1e; CC rc21) — the earlier-form members that name a row
/// and now live under a `refs` role (CC 2.6.1.3: "a member that names a row
/// stands in `refs` and nowhere else"): `(family, role, earlier member,
/// shape)`. The mapping (`ingest::attestation_of`) projects each role back
/// to its earlier member (row id hex) for the earlier-form gates; the emit
/// side (`emit::payload_from_envelope`) states each earlier member under its
/// role. One table, both directions.
pub const REF_MEMBERS: &[(&str, &str, &str, RefShape)] = &[
    (
        "identity_amendment",
        "also:cites",
        "authorized_by",
        RefShape::One,
    ),
    (
        "identity_amendment",
        "also:cites",
        "evidence_refs",
        RefShape::Many,
    ),
    (
        "deferral:response:{outcome}",
        "answers",
        "references_attestation_id",
        RefShape::One,
    ),
    // v62.0.0 (E2-fix9; CC rc21 994b4f5 ruling (c); CC 3.2 "the recovery
    // gate", CC 8.10's `ownership:*` withdraw guard) — `wa_adjudication_ref`
    // is a LOGICAL name (signed_object_v2.tsv): on the gated `withdraws` of
    // an owner binding (a composer carrying the binding's family) the WA
    // quorum finding stands in `refs.also.cites`, EXACTLY ONE row, the
    // withdrawn binding in `refs.target`. No refs member or also role is
    // added; a `cites` of any other count projects nothing (the gate then
    // reads no finding: the withdraws concludes nothing).
    (
        "ownership:{relation}:{target_kind}:{version}",
        "also:cites",
        "wa_adjudication_ref",
        RefShape::One,
    ),
    // v62.0.0 (AU-fix2; CC 2.7.11's member table, P2:955: `head` | `"refs"`
    // | refs.head, "The roster head the count is over") — a counted
    // `admission:unit` row (and the group's counted withdrawal of one)
    // names its roster head as the logical member `head` (64-hex row id) on
    // the JSON surfaces: a host drafts it (`emit::draft_from_envelope`) and
    // the mapping projects it back.
    ("admission:unit", "head", "head", RefShape::One),
];

/// v62.0.0 (wave P1e) — the [`REF_MEMBERS`] entries of the family a
/// statement's header names (its family id).
///
/// v62.0.0 (E2-fix9) — matched by the entry's own family id, so a family
/// with no member list here (`ownership:*`, whose composers carry its family)
/// keeps its named rows too.
#[must_use]
pub fn ref_members(family_id: &str) -> Vec<(&'static str, &'static str, RefShape)> {
    REF_MEMBERS
        .iter()
        .filter(|(fam, ..)| ciris_verify_core::namespace_match::family_id(fam) == family_id)
        .map(|(_, role, member, shape)| (*role, *member, *shape))
        .collect()
}

/// v62.0.0 (wave P1e; CC rc21, CC 3.2) — the `cohort_subkind` of a
/// geographic community, whose roster versions name each new member's
/// `location_proof:v1` row under [`LOCATION_PROOF_ROLE`].
pub const GEOGRAPHIC_SUBKIND: &str = "geographic";

/// v62.0.0 (wave P1e; CC rc21, CC 3.2) — the `refs` role a geographic
/// `group:roster` version names each new member's `location_proof:v1` row
/// under: `also.cites` (the ruling names no role of its own; the `also`
/// roles are closed to `ack` and `cites`). As [`names_of`] spells it.
pub const LOCATION_PROOF_ROLE: &str = "also:cites";

/// v62.0.0 (wave P1e, O1's finding) — the composer row types (CC 2.4.1.1).
/// A composer carries its TARGET's family (header -70002,
/// `composer_family_mismatch` otherwise) but states its OWN payload, so the
/// target family's list never applies to it: [`check_composer`] does.
pub const COMPOSER_ROW_TYPES: &[&str] = &["withdraws", "recants", "supersedes"];

/// v62.0.0 (wave P1e) — **a composer's payload rule**: the common members
/// only ([`COMMON`], typed as everywhere), `refs.target` required (the row
/// it composes), the `also` roles closed. Whatever the target family's list
/// says, a composer carries none of that family's members.
///
/// # Errors
/// `edition2_payload_invalid`, naming the member.
pub fn check_composer(row_type: &str, payload: &Value) -> Result<(), Error> {
    let fail = |e: String| refuse(format!("{row_type} (a composer): {e}"));
    check_common(payload).map_err(fail)?;
    check_map(&[], COMMON, payload).map_err(fail)?;
    let names: Vec<Name> = names_of(payload).map_err(|e| fail(format!("refs: {e:?}")))?;
    if let Some(n) = names
        .iter()
        .find(|n| n.role.starts_with("also:") && !ALSO_ROLES.contains(&n.role.as_str()))
    {
        return Err(fail(format!(
            "refs `{}` is not an also role (ack | cites)",
            n.role
        )));
    }
    if !names.iter().any(|n| n.role == "target") {
        return Err(fail("refs.target is required: the row it composes".into()));
    }
    Ok(())
}

/// v62.0.0 (wave P1d) — **the door's payload check**: for a composer row
/// type, [`check_composer`] (its own shape, whatever family it carries);
/// otherwise [`check`] for the family a statement's header names (its family
/// id). A non-composer of a family this module does not map keeps only the
/// envelope's typed common members (its other members pass as before). Pure; the edition-2 door runs it with its
/// other pure gates, before any directory read
/// (`door::pure_statement_gates`).
///
/// # Errors
/// `edition2_payload_invalid`, as [`check`] / [`check_composer`].
pub fn check_by_id(family_id: &str, row_type: &str, payload: &Value) -> Result<(), Error> {
    // v62.0.0 (wave P1e; CC ruling) — every decimal in the payload is
    // normalised, on every family and every row type.
    check_body_numbers(payload)?;
    if COMPOSER_ROW_TYPES.contains(&row_type) {
        return check_composer(row_type, payload);
    }
    match family_by_id(family_id) {
        Some(f) => check(f.family, payload),
        // v62.0.0 (wave P1e, E3's finding) — a family with no list keeps the
        // envelope's typed members (CC 2.6.1.3, `attestation-envelope`):
        // a malformed common member is refused here, at the door, never read
        // as something else later. Its other members pass as before.
        None => {
            check_common(payload).map_err(|e| refuse(format!("{family_id}: {e}")))?;
            // v62.0.0 (CC rc21 397100e, CC 3.3.11) — on a family with no list
            // the `refs` roles are open (a chat reply names its message under
            // `answers`), but the `also` roles stay closed (ack | cites): CC
            // 2.6.1.3's `also-role` is a closed registry, as on every listed
            // family and every composer. A REFUSAL, not a hold: it reads the
            // statement's own bytes only (the CC27 door line). Witnessed at the
            // door, sqlite and postgres, by `payloads_invariants`
            // `i4002_a_chat_answer_passes_the_door_{sqlite,postgres}`.
            let names: Vec<Name> =
                names_of(payload).map_err(|e| refuse(format!("{family_id}: refs: {e:?}")))?;
            if let Some(n) = names
                .iter()
                .find(|n| n.role.starts_with("also:") && !ALSO_ROLES.contains(&n.role.as_str()))
            {
                return Err(refuse(format!(
                    "{family_id}: refs `{}` is not an also role (ack | cites)",
                    n.role
                )));
            }
            Ok(())
        }
    }
}

fn refuse(message: String) -> Error {
    Error::malformed_row(PLANE, malformed_row::EDITION2_PAYLOAD_INVALID, message)
}

fn text_of<'a>(payload: &'a Value, member: &str) -> Option<&'a str> {
    payload.get_text(member).and_then(Value::as_text)
}

/// Whether the payload's `dimension` contains `leaf` as a segment.
fn dimension_has(payload: &Value, leaf: &str) -> bool {
    text_of(payload, "dimension").is_some_and(|d| d.split(':').any(|s| s == leaf))
}

/// The leaf of `family_id` a payload's `dimension` names: its second
/// segment, when its first is the family's stem. `None` without a
/// `dimension`, or with one of another family (a cosign state's payload
/// is the event's).
fn leaf_of<'a>(family_id: &str, payload: &'a Value) -> Option<&'a str> {
    // v62.0.0 (triage 1) — the leaf is the dimension's segment at the
    // position of the family's FIRST parameter, after every literal segment
    // before it matches: `deferral:response:{outcome}` reads `approved` from
    // `deferral:response:approved:v1`, not `response`. (The first-segment
    // reading held only for one-literal families.)
    let pattern: Vec<&str> = family_id.split(':').collect();
    let at = pattern
        .iter()
        .position(|s| s.starts_with('{') || s.starts_with('.'))?;
    let d = text_of(payload, "dimension")?;
    let segs: Vec<&'a str> = d.split(':').collect();
    if segs.len() <= at || pattern[..at] != segs[..at] {
        return None;
    }
    Some(segs[at])
}

fn required(p: Presence, payload: &Value) -> bool {
    match p {
        Presence::Required => true,
        Presence::Optional => false,
        Presence::RequiredWhen("dimension", leaves) => {
            leaves.iter().any(|l| dimension_has(payload, l))
        }
        Presence::RequiredWhen(member, values) => {
            text_of(payload, member).is_some_and(|v| values.contains(&v))
        }
    }
}

/// Each listed member present when required and of its type; no member
/// outside `members` and `extra`.
fn check_map(members: &[Member], extra: &[&str], payload: &Value) -> Result<(), String> {
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
        if !extra.contains(&k) && !members.iter().any(|x| x.name == k) {
            return Err(format!("`{k}` is not a member of this family's payload"));
        }
    }
    Ok(())
}

/// The common members' types, and `body.note`'s bound.
fn check_common(payload: &Value) -> Result<(), String> {
    for mem in COMMON_TYPED {
        match payload.get_text(mem.name) {
            None if required(mem.presence, payload) => {
                return Err(format!("`{}` is required", mem.name));
            }
            Some(v) if !mem.ty.holds(v) => {
                return Err(format!("`{}` is not {}", mem.name, mem.ty.spelling()));
            }
            _ => {}
        }
    }
    // v62.0.0 (wave P1e, E3's finding) — the fixed-scale members are
    // integers at the scale of 10^6 (CC 2.6.1.5), the battery counts
    // unsigned: anything else is refused here, never read as a number later.
    for member in ["score", "confidence", "weight"] {
        if let Some(v) = payload.get_text(member) {
            if v.as_i64().is_none() {
                return Err(format!(
                    "`{member}` is not an integer at the fixed scale (fixed6)"
                ));
            }
        }
    }
    for member in ["passed", "total"] {
        if let Some(v) = payload.get_text(member) {
            if v.as_u64().is_none() {
                return Err(format!("`{member}` is not a uint"));
            }
        }
    }
    if let Some(note) = payload.get_text("body").and_then(|b| b.get_text("note")) {
        match note.as_text() {
            Some(t) if t.len() <= BODY_NOTE_MAX => {}
            _ => {
                return Err(format!(
                    "`body.note` is not text of at most {BODY_NOTE_MAX} bytes"
                ))
            }
        }
    }
    Ok(())
}

/// The rules of [`PROSE_RULES`] beyond the common ones.
fn check_prose(family_id: &str, payload: &Value, names: &[Name]) -> Result<(), String> {
    match family_id {
        "group:roster" => {
            let version = payload.get_text("version").and_then(Value::as_u64);
            let head = names.iter().any(|n| n.role == "head");
            match (version, head) {
                (Some(1), true) => {
                    return Err("version 1 extends no version: `refs.head` is absent".into())
                }
                (Some(v), false) if v > 1 => {
                    return Err(format!(
                        "version {v} extends its predecessor: `refs.head` names it"
                    ))
                }
                _ => {}
            }
            // v62.0.0 (wave P1e; CC rc21, CC 3.2) — a geographic version
            // NAMES each new member's `location_proof:v1` row under
            // `refs.also.cites`. A founding version's members are all new,
            // so it cites at least as many rows as it lists (its charter, if
            // cited, rides the same set: a lower bound). A later version's
            // new members are known only against its predecessor: the fold
            // (GC5) waits for each named proof and judges containment and
            // liveness; nothing here reads a held row.
            let geographic = payload.get_text("cohort_subkind").and_then(Value::as_text)
                == Some(GEOGRAPHIC_SUBKIND);
            if geographic && version == Some(1) {
                let listed = payload
                    .get_text("members")
                    .and_then(Value::as_array)
                    .map_or(0, <[Value]>::len);
                let cited = names
                    .iter()
                    .filter(|n| n.role == LOCATION_PROOF_ROLE)
                    .count();
                if cited < listed {
                    return Err(format!(
                        "a founding geographic version names each member's location_proof under \
                         refs.also.cites: {listed} members, {cited} cited rows"
                    ));
                }
            }
        }
        "takedown_notice:{basis}" => {
            let leaf = leaf_of(family_id, payload);
            if leaf.is_none() || leaf != text_of(payload, "legal_basis") {
                return Err("`legal_basis` is not the `{basis}` leaf of `dimension`".into());
            }
            if leaf == Some("steward_purge") && payload.get_text("author").is_some() {
                return Err("a steward_purge notice is counted: it carries no `author`".into());
            }
        }
        "deferral:response:{outcome}" => {
            if names.iter().any(|n| n.role == "target") {
                return Err(
                    "the request answered stands under refs.answers, never refs.target (rc21)"
                        .into(),
                );
            }
            if leaf_of(family_id, payload) != Some("approved")
                && (payload.get_text("amendment_digest").is_some()
                    || payload.get_text("call_fingerprint").is_some())
            {
                return Err(
                    "`amendment_digest` and `call_fingerprint` ride an approved response only"
                        .into(),
                );
            }
        }
        "identity_amendment" => {
            if payload.get_text("evidence_refs").is_some() {
                return Err(
                    "an amendment carries no `evidence_refs`: its approval stands under \
                     refs.also.cites (rc21)"
                        .into(),
                );
            }
            let cited = names.iter().filter(|n| n.role == "also:cites").count();
            if cited != 1 {
                return Err(format!(
                    "refs.also.cites names exactly one row, the approving response, not {cited}"
                ));
            }
        }
        "location_proof:{version}" => {
            let res = payload.get_text("cell_resolution").and_then(Value::as_u64);
            if res.is_some_and(|r| r > 7) {
                return Err(format!(
                    "cell_resolution {res:?} is finer than 7: a location proof is rough-only (CC 2.6.6.1)"
                ));
            }
            let cell = payload
                .get_text("cell_id")
                .and_then(Value::as_text)
                .unwrap_or("");
            if cell.is_empty() || !cell.bytes().all(|b| matches!(b, b'0'..=b'9' | b'a'..=b'f')) {
                return Err("cell_id is the H3 cell in lowercase hex".into());
            }
        }
        "custody:{kind}" => {
            // CC 3.1.3.3: the 72-hour window is read from the instant; the
            // envelope's common `expires_at` is not a member of this map.
            if payload.get_text("expires_at").is_some() {
                return Err(
                    "`expires_at` is not a member of this family's payload (a report \
                     is live 72 hours from its asserted_at)"
                        .into(),
                );
            }
            let n = payload
                .get_text("evidence_refs")
                .and_then(Value::as_array)
                .map_or(0, <[Value]>::len);
            if n != 1 {
                return Err(format!(
                    "`evidence_refs` holds exactly one digest, the blob's address, not {n}"
                ));
            }
        }
        _ => {}
    }
    Ok(())
}

/// **Check a payload of a mapped family** against its member list: each
/// required member present, each present member of its type, no member
/// outside the list and the common ones ([`COMMON`]), each required `refs`
/// role named, the `also` roles closed, the leaf within [`LEAVES`], each
/// closed text within [`CLOSED_VALUES`], and the family's
/// [`PROSE_RULES`]. `Ok` for a family this module does not map (its rules
/// are elsewhere) and for a `membership` stage the table does not map.
///
/// # Errors
/// `edition2_payload_invalid` (`federation_malformed_row`), naming the
/// member.
pub fn check(family_id: &str, payload: &Value) -> Result<(), Error> {
    let Some(f) = family(family_id) else {
        return Ok(());
    };
    let fail = |e: String| refuse(format!("{family_id}: {e}"));
    if let Some((_, leaves)) = LEAVES.iter().find(|(fam, _)| *fam == family_id) {
        match (leaves, leaf_of(family_id, payload)) {
            (Leaves::Closed(set), Some(l)) if !set.contains(&l) => {
                return Err(fail(format!("`{l}` is not a leaf of this family")));
            }
            (Leaves::Mapped(set), Some(l)) if !set.contains(&l) => return Ok(()),
            (Leaves::Except(set), Some(l)) if set.contains(&l) => return Ok(()),
            _ => {}
        }
    }
    let names: Vec<Name> = names_of(payload).map_err(|e| fail(format!("refs: {e:?}")))?;
    if let Some(n) = names
        .iter()
        .find(|n| n.role.starts_with("also:") && !ALSO_ROLES.contains(&n.role.as_str()))
    {
        return Err(fail(format!(
            "refs `{}` is not an also role (ack | cites)",
            n.role
        )));
    }
    if OVER_THE_EVENT.contains(&family_id) {
        // The payload is the event's own: its members are checked under the
        // event's family.
        return Ok(());
    }
    check_common(payload).map_err(fail)?;
    check_map(f.members, COMMON, payload).map_err(fail)?;
    for (fam, member, values) in CLOSED_VALUES {
        if *fam != family_id {
            continue;
        }
        if let Some(v) = text_of(payload, member) {
            if !values.contains(&v) {
                return Err(fail(format!("`{member}` {v:?} is not one of {values:?}")));
            }
        }
    }
    for r in f.refs {
        if required(r.presence, payload) && !names.iter().any(|n| n.role == r.role) {
            return Err(fail(format!("{} is required", ref_spelling(r.role))));
        }
    }
    check_prose(family_id, payload, &names).map_err(fail)
}

/// A `refs` role as the document spells it (`refs.also.cites`).
fn ref_spelling(role: &str) -> String {
    format!("refs.{}", role.replace(':', "."))
}

fn cell(s: &str) -> String {
    s.replace('|', "\\|")
}

fn presence_cell(p: Presence) -> String {
    match p {
        Presence::RequiredWhen(k, vs) => {
            let vs: Vec<String> = vs.iter().map(|v| format!("`{v}`")).collect();
            format!("required when `{k}` is {}", vs.join(" or "))
        }
        other => other.spelling().to_owned(),
    }
}

fn codes(vs: &[&str]) -> String {
    vs.iter()
        .map(|v| format!("`{v}`"))
        .collect::<Vec<_>>()
        .join(", ")
}

/// The payload document's per-family tables, rendered from [`FAMILIES`],
/// [`LEAVES`], [`CLOSED_VALUES`] and [`PROSE_RULES`].
#[must_use]
pub fn render_markdown() -> String {
    let mut out = String::new();
    for f in FAMILIES {
        out.push_str(&format!("### `{}`\n\n", f.family));
        out.push_str(&format!("- **Replaces:** {}\n", cell(f.replaces)));
        out.push_str(&format!("- **Authorship:** {}\n", f.authorship));
        out.push_str(&format!("- **`sub`:** {}\n", cell(f.sub)));
        out.push_str(&format!("- **Lands in:** {}\n", cell(f.table)));
        for (_, leaves) in LEAVES.iter().filter(|(fam, _)| *fam == f.family) {
            match leaves {
                Leaves::Closed(set) => {
                    out.push_str(&format!("- **Leaves (closed):** {}\n", codes(set)));
                }
                Leaves::Except(set) => out.push_str(&format!(
                    "- **Leaves not mapped:** {} (that leaf's payload is not this table's)\n",
                    codes(set)
                )),
                Leaves::Mapped(set) => out.push_str(&format!(
                    "- **Leaves mapped:** {} (another leaf's payload is OPEN, not this table's)\n",
                    codes(set)
                )),
            }
        }
        if OVER_THE_EVENT.contains(&f.family) {
            out.push_str(
                "- **Payload:** the event's own; its members are checked under the event's family\n",
            );
        }
        out.push('\n');
        if f.members.is_empty() && f.refs.is_empty() {
            out.push_str("Members of its own: none.\n\n");
        } else {
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
                    "| `{}` | `row-ref` | {} | {} |\n",
                    ref_spelling(r.role),
                    presence_cell(r.presence),
                    cell(r.from)
                ));
            }
            out.push('\n');
        }
        let closed: Vec<String> = CLOSED_VALUES
            .iter()
            .filter(|(fam, _, _)| *fam == f.family)
            .map(|(_, member, vs)| format!("- `{member}` is one of {}\n", codes(vs)))
            .collect();
        let prose: Vec<String> = PROSE_RULES
            .iter()
            .filter(|(fam, _)| *fam == f.family)
            .map(|(_, rule)| format!("- {rule}\n"))
            .collect();
        if f.family == ADMISSION_UNIT_FAMILY {
            out.push_str("Verifier rules (each refused with its own token):\n\n");
            for (token, rule) in ADMISSION_UNIT_RULES {
                out.push_str(&format!("- `{token}`: {rule}\n"));
            }
            out.push('\n');
        }
        if !closed.is_empty() || !prose.is_empty() {
            out.push_str("Rules beyond the list (refused `edition2_payload_invalid`):\n\n");
            for line in closed.iter().chain(prose.iter()) {
                out.push_str(line);
            }
            out.push('\n');
        }
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
    out.push_str("\n### Every mapped family\n\n");
    out.push_str(&format!(
        "- **Common members** (any family): {}\n",
        codes(COMMON)
    ));
    out.push_str(&format!(
        "- **Hash-digest members** (any family; the earlier gates read each as 64 hex): {}\n",
        codes(HASH_DIGEST_MEMBERS)
    ));
    for (_, rule) in PROSE_RULES.iter().filter(|(fam, _)| *fam == "*") {
        out.push_str(&format!("- {rule}\n"));
    }
    out
}
