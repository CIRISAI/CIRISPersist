//! **I2102** (v62.0.0, JSON-cut slice A): the payload member lists.
//!
//! - `docs/EDITION2_PAYLOADS.md` carries exactly the tables
//!   [`render_markdown`] renders from [`FAMILIES`] (the document CC writes
//!   the CDDL from cannot drift from the check persist runs). Set
//!   `CIRIS_BLESS_PAYLOADS=1` to rewrite the rendered block.
//! - [`check`] admits a payload carrying the required members, and refuses
//!   `edition2_payload_invalid` for a missing required member, a member of
//!   the wrong type, an unlisted member, an unsorted set, and a missing
//!   required `refs` role; a conditional member is required only when its
//!   condition holds; a family it does not map passes.
//!
//! v62.0.0 (wave P1) — CC's corrections to the nine families (the CC text
//! wins where it differs from persist's earlier table). Each witness admits
//! the corrected shape and refuses the earlier one `edition2_payload_invalid`:
//!
//! - **I2900** — a roster version names its predecessor by `refs.head`
//!   (absent on version 1, present on every later one); `refs.prev` alone
//!   does not.
//! - **I2901** — the charter rides `refs.also.cites`; the `also` roles are
//!   closed (`ack`, `cites`), on every mapped family.
//! - **I2902** — `consensus_protocol_entrenched` is a bool; absent reads
//!   false.
//! - **I2903** — `group:roster` carries `cohort_subkind`,
//!   `cohort_subkind_payload` and `membership` (`private` | `public`).
//! - **I2904** — a roster's `members` is a set by element encoding, one
//!   entry per key.
//! - **I2905** — the membership table maps the stages `widening` and
//!   `removal`, each counted over `refs.head` (required); another
//!   registered stage is not this table's and passes.
//! - **I2906** — `reason` is a uint code, never text, on every family;
//!   free text rides `body.note` (at most 2048 bytes).
//! - **I2907** — a time-boxed widening carries `valid_until`.
//! - **I2908** — the cosign states are `pending` | `signature`, with no
//!   member of their own (the payload is the event's); no `lineage_head`
//!   state.
//! - **I2909** — a takedown notice: `legal_basis` is CC 3.3.2's closed set
//!   and equals the leaf; a steward purge carries no `author`;
//!   `perceptual_hash` and `counter_notice_channel` ride; `evidence_refs`
//!   is a non-empty sequence.
//! - **I2910** — a custody report carries no `expires_at` (refused: the
//!   map is closed; live 72 h from its instant) and no `cohort`: its scope
//!   is `community_id` / `family_id`; exactly one evidence digest.
//! - **I2911** — a key grant: `owner` on content and stream, `epoch` on
//!   epoch and stream, `wrap_algorithm` the v2 wire string only, no
//!   `cohort`.
//! - **I2912** — a delivery receipt's chunk index is `k` (lowercase); no
//!   inner signature member.
//! - **I2918** — `identity:occurrence` (CC 3.3.6, carried for O1): the
//!   ruling's members admit; a missing `device_class` is refused (its
//!   vocabulary is `types::device_class`'s, one source); an unlisted member
//!   is refused.
//! - **I2920** (wave P1d, CC's naming ruling) — `identity:occurrence_revocation`
//!   names its two keys as the occurrence record does, `identity_key_id` and
//!   `occurrence_key_id`; the short spellings `identity` / `occurrence` are
//!   refused as unlisted members.
//! - **I2921** (wave P1e, CC rc21 CC 2.7.11) — `admission:unit`: the member
//!   list, then the verifier's pure rules with their own tokens: authored XOR
//!   counted (`admission_unit_malformed`), `sub` the unit's digest
//!   (`admission_unit_malformed`), capabilities closed and non-empty
//!   (`admission_capability_unknown`), the lease window
//!   (`admission_lease_out_of_window`); AU-fix1 (CC 2.7.11 P2:1682): one
//!   person's row naming an effect at `self` only
//!   (`admission_owner_row_not_self`), one naming no effect and a counted row
//!   at any scope.
//! - **I2922** (wave P1e) — an `admission:unit` signer is a person:
//!   `admission_issuer_not_person` for a key whose record holds neither
//!   `user` nor `accord_holder`; other families are untouched.
//! - **I2923** (wave P1e) — `identity_amendment` carries `refs.prev` (and
//!   none on the base link), `amendment_digest` a digest, never hex;
//!   `deferral:response:approved` carries `call_fingerprint` and
//!   `amendment_digest`, a `rejected` response neither.
//! - **I2926** (wave P1e, O1's finding) — a composer (`withdraws`,
//!   `recants`, `supersedes`) carries its target's family but is checked by
//!   the composer rule, never the target family's list: an edition-2
//!   `withdraws` of an `identity:occurrence` passes; a composer with an
//!   unknown member (even one the target family lists) or with no
//!   `refs.target` is refused `edition2_payload_invalid`; a COUNTED
//!   composer (no `author`, `refs.target` + `refs.head`) passes; at the door
//!   with zero reads, on sqlite and postgres.
//! - **I2929** (wave P1e, CC rc21 CC 3.2) — a geographic `group:roster`
//!   version names each new member's `location_proof:v1` under
//!   `refs.also.cites`: a founding geographic version citing as many rows as
//!   it lists members passes, one citing fewer is refused; a later version
//!   (new members known only against its predecessor) and a non-geographic
//!   version are not counted here.
//! - **I3990** (wave P1e, CC rc21 member homes) — `identity_amendment`:
//!   the approval under `refs.also.cites` (exactly one), no
//!   `authorized_by` member, no `evidence_refs`; the mapping projects the
//!   cited row back as `authorized_by` and `evidence_refs` (hex) for the
//!   earlier gate.
//! - **I3991** (FINAL, CC ruling) — `deferral:response:*`: the request
//!   under `refs.answers` (required), never `refs.target`; `deferral_id`
//!   REQUIRED, `reason_digest` refused; `deferral:request`: `deferral_id`
//!   and `reason_digest` REQUIRED; the mapping projects `refs.answers` back as
//!   `references_attestation_id` (stored, on sqlite and postgres).
//! - **I3992** — no payload map lists `id` (Server's envelope uuid is gone;
//!   the row id is computed); a mapped family's payload carrying `id` is
//!   refused.
//! - **I3993** (CC 2.7 rulings item 2) — `identity:occurrence` and
//!   `identity:occurrence_revocation` REQUIRE `refs.head` (the identity's
//!   last landed self-roster row) and take an optional
//!   `refs.further_heads`.
//! - **I3995** (CC ruling, free-form body numbers) — `body_number`: an
//!   integral value is a plain integer (`2.0` → 2, `1e2` → 100), a
//!   non-integral one tag 4 normalised (`0.5` → 4([-1,5]), `1.25` →
//!   4([-2,125])), from the exact decimal text; a mantissa or an integral
//!   value outside the CBOR integer range (Verify 23.3.2's limit; P1-fix8
//!   widened the mantissa from i64) is refused
//!   `body_number_unrepresentable`, and the decoder reads every mantissa in
//!   that range back exactly.
//! - **I3996** — the reader refuses a non-normalised tag 4 (4([-1,50]),
//!   4([0,3])) with `edition2_payload_invalid`, anywhere in a payload, at the
//!   door's schema step.
//! - **I3997** (FINAL, CC) — a deferral request and response route by
//!   `community_id` (the pair room); there is no `room` member.
//! - **I3998** — `location_proof:{version}` (CC 3.3.3): `cell_id`
//!   (lowercase hex), `cell_resolution` (at most 7), optional
//!   `attestation_evidence`; no `subject_key_id` member (the subject is the
//!   `sub`).
//! - **I3999** (lead's ruling, the entry point) — the decoder reads a
//!   normalised tag-4 decimal back as its EXACT JSON number
//!   (`json_number_of_decimal`, and `ingest::json_of` / `attestation_of`),
//!   the inverse of `body_number`; the free-form bodies are `body` on every
//!   family and `hard_case:{kind}`'s `hard_case`.
//! - **I4001** (CC rc21 7f94be1) — an `identity:occurrence_revocation`
//!   REQUIRES `refs.also.cites` (each voice's key:record, plus its
//!   occurrence binding when it has one): without it, refused
//!   `edition2_payload_invalid`; whether every voice is covered is T2's door.
//! - **I4002** (CC rc21 397100e, CC 3.3.11) — a chat REPLY and a chat
//!   REACTION (a sealed `chat:reaction`) name their message in
//!   `refs.answers`: the payload check admits it on the chat family
//!   (`chat:*`, an unmapped family whose `refs` roles are open; only the
//!   `also` roles are closed), and at the door (sqlite, postgres) such a
//!   statement passes the pure gates and reaches the directory.
//! - **I4003** (P1-fix6; the lead's ruling) — a ledger's `balance` /
//!   `expertise` are body numbers: the encoder states a non-integral one as
//!   the normalised tag-4 decimal and an integral one as an integer (never
//!   fixed6, never refused); the mapping reads it back exactly. The
//!   store-backed round trip is `ledger_projection_invariants` I1166 / I1169
//!   (12.5, 7.25, 3.5 projected, sqlite and postgres).
//! - **I2919** (wave P1d) — the list is enforced AT THE DOOR: for each mapped
//!   family, a statement whose payload breaks its list (an unknown member, a
//!   missing required one, a wrong type, a closed leaf) is refused
//!   `edition2_payload_invalid` by `put_statement` with ZERO directory reads
//!   (every directory method of the wrapping double errors), and a valid one
//!   passes the pure gates and reaches the directory; on sqlite and
//!   postgres. A family with no list passes as before.
//! - **I2913** — `amendment_digest` is a hash-digest member
//!   ([`HASH_DIGEST_MEMBERS`]); [`LEGAL_BASES`] is the registry's
//!   `{basis}` vocabulary.

use ciris_verify_core::cde::Value;
use ciris_verify_core::edition2::identity_ref;

use super::door_invariants::fixture::*;
use super::payloads::{check, render_markdown, FAMILIES, HASH_DIGEST_MEMBERS, LEGAL_BASES};
use crate::federation::{malformed_row, Error};

const BEGIN: &str = "<!-- BEGIN rendered from federation::edition2::payloads -->\n";
const END: &str = "<!-- END rendered -->";

#[test]
fn i2102_the_document_is_rendered_from_the_member_lists() {
    let path = concat!(env!("CARGO_MANIFEST_DIR"), "/docs/EDITION2_PAYLOADS.md");
    let doc = std::fs::read_to_string(path).expect("I2102: docs/EDITION2_PAYLOADS.md");
    let (head, rest) = doc.split_once(BEGIN).expect("I2102: the BEGIN marker");
    let (_, tail) = rest.split_once(END).expect("I2102: the END marker");
    let rendered = render_markdown();
    if std::env::var_os("CIRIS_BLESS_PAYLOADS").is_some() {
        std::fs::write(path, format!("{head}{BEGIN}{rendered}{END}{tail}")).unwrap();
        return;
    }
    assert_eq!(
        &rest[..rest.len() - tail.len() - END.len()],
        rendered,
        "I2102: the document drifted from FAMILIES (re-render with CIRIS_BLESS_PAYLOADS=1)"
    );
    for f in FAMILIES {
        assert!(
            doc.contains(&format!("### `{}`", f.family)),
            "I2102 {}",
            f.family
        );
    }
}

fn reason(e: &Error) -> &'static str {
    match e {
        Error::MalformedRow { reason, .. } => reason,
        other => other.kind(),
    }
}

fn ms(n: u64) -> Value {
    Value::Uint(n)
}

fn txt(s: &str) -> Value {
    Value::Text(s.into())
}

/// An identity-ref, without minting a key.
fn id(n: u8) -> String {
    identity_ref(&[n; 32])
}

/// `[-16, h'nn..']`.
fn digest(n: u8) -> Value {
    Value::Array(vec![Value::Nint(15), Value::Bytes(vec![n; 32])])
}

/// `{role: row-ref}`.
fn refs(entries: Vec<(&str, Value)>) -> Value {
    map(entries)
}

/// `{also: {role: [row-ref]}}`'s inner value: a one-element set.
fn ref_set(n: u8) -> Value {
    Value::Array(vec![ref2(&[n; 32])])
}

/// The payload with `extra` added (replacing a member of the same name)
/// and `drop` removed.
fn with(base: &Value, extra: Vec<(&str, Value)>, drop: &[&str]) -> Value {
    let Value::Map(entries) = base else {
        unreachable!()
    };
    let mut v: Vec<(&str, Value)> = entries
        .iter()
        .filter_map(|(k, v)| {
            let k = k.as_text()?;
            (!drop.contains(&k) && !extra.iter().any(|(e, _)| *e == k))
                .then(|| (leak(k), v.clone()))
        })
        .collect();
    v.extend(extra);
    map(v)
}

/// The fixtures' member names are `'static` text in this file; a payload
/// rebuilt from one is keyed by the same names.
fn leak(k: &str) -> &'static str {
    Box::leak(k.to_owned().into_boxed_str())
}

#[track_caller]
fn ok(family: &str, p: &Value, why: &str) {
    if let Err(e) = check(family, p) {
        panic!("{why}: {family} refused: {e}");
    }
}

#[track_caller]
fn bad(family: &str, p: &Value, why: &str) {
    match check(family, p) {
        Ok(()) => panic!("{why}: {family} admitted {p:?}"),
        Err(e) => assert_eq!(
            reason(&e),
            malformed_row::EDITION2_PAYLOAD_INVALID,
            "{why}: {e}"
        ),
    }
}

const MEMBERSHIP: &str = "membership:{stage}";

fn widening(extra: Vec<(&str, Value)>) -> Value {
    let mut v = vec![
        ("asserted_at", ms(1_000)),
        ("dimension", txt("membership:widening:v1")),
        ("group_kind", txt("community")),
        ("group", txt(&id(110))),
        ("member", txt(&id(111))),
        ("joined_at", ms(900)),
        ("effective_at", ms(1_000)),
        ("refs", refs(vec![("head", ref2(&[0x40; 32]))])),
    ];
    v.extend(extra);
    map(v)
}

fn removal() -> Value {
    map(vec![
        ("asserted_at", ms(1_000)),
        ("dimension", txt("membership:removal:v1")),
        ("group_kind", txt("family")),
        ("group", txt(&id(110))),
        ("member", txt(&id(111))),
        ("removed_at", ms(990)),
        ("effective_at", ms(1_000)),
        ("refs", refs(vec![("head", ref2(&[0x41; 32]))])),
    ])
}

#[test]
fn i2102_check_reads_the_member_lists() {
    let fam = MEMBERSHIP;
    check(fam, &widening(vec![])).expect("I2102 required members");
    check(fam, &widening(vec![("role", txt("moderator"))])).expect("I2102 optional member");
    let bad = |p: Value, why: &str| {
        let e = check(fam, &p).unwrap_err();
        assert_eq!(
            reason(&e),
            malformed_row::EDITION2_PAYLOAD_INVALID,
            "I2102 {why}"
        );
    };
    // Missing a required member.
    bad(
        with(&widening(vec![]), vec![], &["effective_at"]),
        "missing",
    );
    // `joined_at` is required for a widening, `removed_at` is not.
    bad(
        with(&widening(vec![]), vec![], &["joined_at"]),
        "conditional",
    );
    // Wrong types.
    bad(widening(vec![("role", ms(3))]), "tstr");
    bad(
        with(
            &widening(vec![]),
            vec![("member", txt("alias-not-an-identity-ref"))],
            &[],
        ),
        "identity-ref",
    );
    // An unlisted member.
    bad(widening(vec![("persist_row_hash", ms(1))]), "unlisted");
    // An unsorted set.
    let (a, b) = (id(112), id(113));
    let (lo, hi) = if a < b { (a, b) } else { (b, a) };
    check(
        fam,
        &widening(vec![(
            "witness_set",
            Value::Array(vec![txt(&lo), txt(&hi)]),
        )]),
    )
    .expect("I2102 sorted set");
    bad(
        widening(vec![(
            "witness_set",
            Value::Array(vec![txt(&hi), txt(&lo)]),
        )]),
        "unsorted",
    );
    // A family the module does not map passes.
    check(
        "evidence:.suite:.kind:.cell:.prefix",
        &map(vec![("x", ms(1))]),
    )
    .unwrap();
}

// ---- group:roster ------------------------------------------------------

const ROSTER: &str = "group:roster";

fn roster_member(n: u8, joined: u64) -> Value {
    map(vec![("key", txt(&id(n))), ("joined_at", ms(joined))])
}

/// A sorted set of roster entries.
fn roster_members(entries: Vec<Value>) -> Value {
    let mut e = entries;
    e.sort_by_key(ciris_verify_core::cde::encode);
    Value::Array(e)
}

fn roster(version: u64, extra: Vec<(&str, Value)>) -> Value {
    let mut v = vec![
        ("asserted_at", ms(1_000)),
        ("group_kind", txt("community")),
        ("group", txt(&id(120))),
        ("name", txt("Acme Co-op")),
        ("version", ms(version)),
        (
            "members",
            roster_members(vec![roster_member(121, 10), roster_member(122, 20)]),
        ),
        ("founded_at", ms(10)),
        ("consensus_protocol", txt("majority")),
    ];
    v.extend(extra);
    map(v)
}

/// I2900: a roster version names its predecessor by `refs.head`.
#[test]
fn i2900_a_roster_version_names_its_predecessor_by_head() {
    ok(
        ROSTER,
        &roster(1, vec![]),
        "I2900 version 1 extends nothing",
    );
    ok(
        ROSTER,
        &roster(2, vec![("refs", refs(vec![("head", ref2(&[0x50; 32]))]))]),
        "I2900 version 2 names its predecessor by refs.head",
    );
    bad(
        ROSTER,
        &roster(2, vec![("refs", refs(vec![("prev", ref2(&[0x50; 32]))]))]),
        "I2900 refs.prev is a signer's own series, not the version a roster extends",
    );
    bad(
        ROSTER,
        &roster(2, vec![]),
        "I2900 a later version names its predecessor",
    );
    bad(
        ROSTER,
        &roster(1, vec![("refs", refs(vec![("head", ref2(&[0x50; 32]))]))]),
        "I2900 version 1 extends no version",
    );
}

/// I2901: the charter rides `refs.also.cites`; the `also` roles are closed.
#[test]
fn i2901_the_charter_is_cited_and_the_also_roles_are_closed() {
    let also = |role: &str| refs(vec![("also", map(vec![(leak(role), ref_set(0x51))]))]);
    ok(
        ROSTER,
        &roster(1, vec![("refs", also("cites"))]),
        "I2901 the charter under also.cites",
    );
    bad(
        ROSTER,
        &roster(1, vec![("refs", also("charter"))]),
        "I2901 `charter` is no also role",
    );
    // The closure holds on every mapped family.
    // `widening()` already carries `refs`: REPLACE it (a second `refs` key
    // would be a duplicate map key, and the first, the base's, would be read).
    let with_also = |role: &str| {
        with(
            &widening(vec![]),
            vec![(
                "refs",
                refs(vec![
                    ("head", ref2(&[0x40; 32])),
                    ("also", map(vec![(leak(role), ref_set(0x52))])),
                ]),
            )],
            &[],
        )
    };
    ok(
        MEMBERSHIP,
        &with_also("cites"),
        "I2901 a widening cites its acceptance",
    );
    ok(MEMBERSHIP, &with_also("ack"), "I2901 ack is an also role");
    bad(
        MEMBERSHIP,
        &with_also("acceptance"),
        "I2901 an unregistered also role",
    );
}

/// I2902: `consensus_protocol_entrenched` is a bool; absent reads false.
#[test]
fn i2902_entrenched_is_a_bool() {
    ok(ROSTER, &roster(1, vec![]), "I2902 absent (reads false)");
    for b in [true, false] {
        ok(
            ROSTER,
            &roster(1, vec![("consensus_protocol_entrenched", Value::Bool(b))]),
            "I2902 a bool",
        );
    }
    bad(
        ROSTER,
        &roster(1, vec![("consensus_protocol_entrenched", ms(1))]),
        "I2902 not a uint",
    );
    bad(
        ROSTER,
        &roster(1, vec![("consensus_protocol_entrenched", txt("true"))]),
        "I2902 not text",
    );
}

/// I2903: `cohort_subkind`, `cohort_subkind_payload`, `membership`.
#[test]
fn i2903_a_roster_carries_its_subkind_and_membership() {
    let full = roster(
        1,
        vec![
            ("cohort_subkind", txt("infrastructure")),
            (
                "cohort_subkind_payload",
                map(vec![("region", txt("north"))]),
            ),
            ("membership", txt("private")),
        ],
    );
    ok(ROSTER, &full, "I2903 the community record's members");
    ok(
        ROSTER,
        &with(&full, vec![("membership", txt("public"))], &[]),
        "I2903 public",
    );
    ok(
        ROSTER,
        &with(&full, vec![], &["membership"]),
        "I2903 membership absent reads public",
    );
    bad(
        ROSTER,
        &with(&full, vec![("membership", txt("secret"))], &[]),
        "I2903 membership is private | public",
    );
    bad(
        ROSTER,
        &with(&full, vec![("cohort_subkind", ms(1))], &[]),
        "I2903 cohort_subkind is text",
    );
    bad(
        ROSTER,
        &with(&full, vec![("cohort_subkind_payload", txt("x"))], &[]),
        "I2903 cohort_subkind_payload is a map",
    );
}

/// I2904: `members` is a set by element encoding, one entry per key.
#[test]
fn i2904_roster_members_is_a_set() {
    let (a, b) = (roster_member(121, 10), roster_member(122, 20));
    let sorted = roster_members(vec![a.clone(), b.clone()]);
    let Value::Array(s) = &sorted else {
        unreachable!()
    };
    let reversed = Value::Array(vec![s[1].clone(), s[0].clone()]);
    ok(
        ROSTER,
        &with(&roster(1, vec![]), vec![("members", sorted.clone())], &[]),
        "I2904 sorted",
    );
    bad(
        ROSTER,
        &with(&roster(1, vec![]), vec![("members", reversed)], &[]),
        "I2904 unsorted",
    );
    let twice = roster_members(vec![roster_member(121, 10), roster_member(121, 11)]);
    bad(
        ROSTER,
        &with(&roster(1, vec![]), vec![("members", twice)], &[]),
        "I2904 one entry per key",
    );
    let stray = roster_members(vec![
        a,
        map(vec![
            ("key", txt(&id(122))),
            ("joined_at", ms(20)),
            ("asserted_at", ms(1)),
        ]),
    ]);
    bad(
        ROSTER,
        &with(&roster(1, vec![]), vec![("members", stray)], &[]),
        "I2904 an entry carries only key, joined_at, role",
    );
    let _ = b;
}

// ---- membership:{stage} --------------------------------------------------

/// I2905: the stages mapped are `widening` and `removal`, each counted over
/// `refs.head`; another stage is not this table's.
#[test]
fn i2905_the_mapped_stages_are_widening_and_removal() {
    ok(MEMBERSHIP, &widening(vec![]), "I2905 widening");
    ok(MEMBERSHIP, &removal(), "I2905 removal");
    bad(
        MEMBERSHIP,
        &with(&widening(vec![]), vec![], &["refs"]),
        "I2905 a widening is counted over refs.head",
    );
    bad(
        MEMBERSHIP,
        &with(&removal(), vec![], &["refs"]),
        "I2905 a removal is counted over refs.head",
    );
    bad(
        MEMBERSHIP,
        &with(&removal(), vec![], &["removed_at"]),
        "I2905 a removal states removed_at",
    );
    // A single-signer stage's forward payload is OPEN: not this table's.
    let proposal = map(vec![
        ("asserted_at", ms(1_000)),
        ("dimension", txt("membership:proposal:v1")),
        ("group_kind", txt("community")),
        ("role", txt("member")),
        ("expires_at", ms(2_000)),
    ]);
    ok(
        MEMBERSHIP,
        &proposal,
        "I2905 a proposal is not this table's",
    );
}

/// I2906: `reason` is a uint code, never text; free text rides `body.note`.
#[test]
fn i2906_reason_is_a_code() {
    ok(
        MEMBERSHIP,
        &with(&removal(), vec![("reason", ms(3))], &[]),
        "I2906 membership reason code",
    );
    bad(
        MEMBERSHIP,
        &with(&removal(), vec![("reason", txt("spam"))], &[]),
        "I2906 membership reason text",
    );
    let occ = occurrence_revocation();
    let fam = "identity:occurrence_revocation";
    ok(fam, &occ, "I2906 occurrence revocation");
    ok(
        fam,
        &with(&occ, vec![("reason", ms(1))], &[]),
        "I2906 occurrence reason code",
    );
    bad(
        fam,
        &with(&occ, vec![("reason", txt("lost device"))], &[]),
        "I2906 occurrence reason text",
    );
    let rev = map(vec![
        ("asserted_at", ms(1_000)),
        ("author", txt(&id(132))),
        ("dimension", txt("revocation:key:compromise:v1")),
        ("revoked_at", ms(1_000)),
        ("effective_at", ms(1_000)),
    ]);
    let fam = "revocation:{entity_type}:{reason}";
    ok(fam, &rev, "I2906 revocation");
    ok(
        fam,
        &with(&rev, vec![("reason", ms(2))], &[]),
        "I2906 the envelope's reason code",
    );
    bad(
        fam,
        &with(&rev, vec![("reason", txt("key leaked"))], &[]),
        "I2906 no free-text reason beside the coded leaf",
    );
    ok(
        fam,
        &with(
            &rev,
            vec![("body", map(vec![("note", txt("key leaked"))]))],
            &[],
        ),
        "I2906 free text rides body.note",
    );
    bad(
        fam,
        &with(
            &rev,
            vec![("body", map(vec![("note", txt(&"x".repeat(2049)))]))],
            &[],
        ),
        "I2906 body.note is bounded",
    );
    bad(
        fam,
        &with(&rev, vec![("body", map(vec![("note", ms(1))]))], &[]),
        "I2906 body.note is text",
    );
}

/// I2907: a time-boxed guest is a widening with `valid_until`.
#[test]
fn i2907_a_widening_carries_valid_until() {
    ok(
        MEMBERSHIP,
        &widening(vec![("valid_until", ms(5_000))]),
        "I2907 valid_until",
    );
    bad(
        MEMBERSHIP,
        &widening(vec![("valid_until", txt("2026-01-01T00:00:00Z"))]),
        "I2907 valid_until is POSIX ms",
    );
}

// ---- cosign:{state} -------------------------------------------------------

/// I2908: the cosign states are `pending` | `signature`, with no member of
/// their own; no `lineage_head` state.
#[test]
fn i2908_cosign_states_are_pending_and_signature() {
    let fam = "cosign:{state}";
    // The statement is over the event's own payload: its members are the
    // event family's, not this table's.
    ok(fam, &widening(vec![]), "I2908 the event's payload");
    for state in ["pending", "signature"] {
        ok(
            fam,
            &map(vec![
                ("asserted_at", ms(1_000)),
                ("dimension", txt(leak(&format!("cosign:{state}:v1")))),
            ]),
            "I2908 a closed state",
        );
    }
    let lineage = map(vec![
        ("asserted_at", ms(1_000)),
        ("author", txt(&id(140))),
        ("dimension", txt("cosign:lineage_head:v1")),
        ("lineage", txt(&id(140))),
        ("head_asserted_at", ms(900)),
        ("refs", refs(vec![("head", ref2(&[0x44; 32]))])),
    ]);
    bad(fam, &lineage, "I2908 no lineage_head state");
    bad(
        fam,
        &with(
            &widening(vec![]),
            vec![(
                "refs",
                refs(vec![
                    ("head", ref2(&[0x40; 32])),
                    ("also", map(vec![("event", ref_set(0x53))])),
                ]),
            )],
            &[],
        ),
        "I2908 the also roles stay closed",
    );
}

// ---- takedown_notice:{basis} ---------------------------------------------

const TAKEDOWN: &str = "takedown_notice:{basis}";

fn notice(basis: &str) -> Value {
    let (h1, h2) = (id(151), id(152));
    map(vec![
        ("asserted_at", ms(1_000)),
        ("author", txt(&id(150))),
        (
            "dimension",
            txt(leak(&format!("takedown_notice:{basis}:v1"))),
        ),
        ("legal_basis", txt(basis)),
        ("claimant", txt(&id(150))),
        ("content_sha256", digest(0x60)),
        ("content_holders", text_set(&[h1.as_str(), h2.as_str()])),
        ("claim_text", txt("the work is mine")),
        ("good_faith_statement", txt("in good faith")),
        ("jurisdiction", txt("US")),
    ])
}

/// I2909: a takedown notice's closed basis, its counted leaf, its new
/// optional members, and the evidence sequence.
#[test]
fn i2909_a_takedown_notice() {
    for basis in LEGAL_BASES.iter().filter(|b| **b != "steward_purge") {
        ok(TAKEDOWN, &notice(basis), "I2909 a closed basis");
    }
    let unknown = notice("dmca_512");
    bad(
        TAKEDOWN,
        &unknown,
        "I2909 a basis outside CC 3.3.2's eleven",
    );
    bad(
        TAKEDOWN,
        &with(
            &notice("dmca512"),
            vec![("legal_basis", txt("court_order"))],
            &[],
        ),
        "I2909 legal_basis equals the leaf",
    );
    let purge = with(&notice("steward_purge"), vec![], &["author"]);
    ok(TAKEDOWN, &purge, "I2909 a steward purge is counted");
    bad(
        TAKEDOWN,
        &notice("steward_purge"),
        "I2909 a steward purge carries no author",
    );
    ok(
        TAKEDOWN,
        &with(
            &notice("perceptual_hash_csam"),
            vec![
                ("perceptual_hash", Value::Bytes(vec![7; 8])),
                ("counter_notice_channel", txt("mailto:counter@example.org")),
            ],
            &[],
        ),
        "I2909 perceptual_hash and counter_notice_channel",
    );
    bad(
        TAKEDOWN,
        &with(
            &notice("dmca512"),
            vec![("counter_notice_channel", ms(1))],
            &[],
        ),
        "I2909 counter_notice_channel is text",
    );
    // A sequence, in the order signed: not sorted, not a set.
    let seq = Value::Array(vec![digest(0x62), digest(0x61)]);
    ok(
        TAKEDOWN,
        &with(&notice("dmca512"), vec![("evidence_refs", seq)], &[]),
        "I2909 evidence_refs is a sequence",
    );
    bad(
        TAKEDOWN,
        &with(
            &notice("dmca512"),
            vec![("evidence_refs", Value::Array(vec![]))],
            &[],
        ),
        "I2909 evidence_refs is non-empty",
    );
    bad(
        TAKEDOWN,
        &with(
            &notice("dmca512"),
            vec![("evidence_refs", Value::Array(vec![txt(&"ab".repeat(32))]))],
            &[],
        ),
        "I2909 evidence_refs holds digests, never hex",
    );
}

// ---- custody:{kind} -------------------------------------------------------

const CUSTODY: &str = "custody:{kind}";

fn custody(extra: Vec<(&str, Value)>) -> Value {
    let mut v = vec![
        ("asserted_at", ms(1_000)),
        ("author", txt(&id(160))),
        ("dimension", txt("custody:ack:v1")),
        ("custody_state", txt("here")),
        ("evidence_refs", Value::Array(vec![digest(0x70)])),
        ("size", ms(4096)),
        ("cohort_scope", txt("community")),
        ("community_id", txt(&id(161))),
    ];
    v.extend(extra);
    map(v)
}

/// I2910: a custody report carries no `expires_at` and no `cohort`;
/// exactly one evidence digest.
#[test]
fn i2910_a_custody_report() {
    ok(
        CUSTODY,
        &custody(vec![]),
        "I2910 no expires_at: live 72 h from its instant",
    );
    bad(
        CUSTODY,
        &custody(vec![("expires_at", ms(1_000 + 72 * 3_600_000))]),
        "I2910 custody has no expires_at member: the map is closed",
    );
    ok(
        CUSTODY,
        &with(
            &custody(vec![]),
            vec![
                ("cohort_scope", txt("family")),
                ("family_id", txt(&id(162))),
            ],
            &["community_id"],
        ),
        "I2910 a family-scoped report names family_id",
    );
    bad(
        CUSTODY,
        &with(
            &custody(vec![]),
            vec![("cohort", txt(&id(161)))],
            &["community_id"],
        ),
        "I2910 no `cohort` member",
    );
    bad(
        CUSTODY,
        &with(
            &custody(vec![]),
            vec![(
                "evidence_refs",
                Value::Array(vec![digest(0x70), digest(0x71)]),
            )],
            &[],
        ),
        "I2910 exactly one evidence digest",
    );
    bad(
        CUSTODY,
        &with(&custody(vec![]), vec![], &["size"]),
        "I2910 a here report states its size",
    );
    ok(
        CUSTODY,
        &with(
            &custody(vec![]),
            vec![("custody_state", txt("none"))],
            &["size"],
        ),
        "I2910 a none report",
    );
    bad(
        CUSTODY,
        &with(&custody(vec![]), vec![("custody_state", txt("gone"))], &[]),
        "I2910 custody_state is here | none",
    );
}

// ---- key_grant:{axis} -----------------------------------------------------

const GRANT: &str = "key_grant:{axis}";

fn grant(axis: &str, extra: Vec<(&str, Value)>) -> Value {
    let mut v = vec![
        ("asserted_at", ms(1_000)),
        ("author", txt(&id(170))),
        ("dimension", txt(leak(&format!("key_grant:{axis}:v1")))),
        ("axis", txt(axis)),
        (
            "wrap_algorithm",
            txt(crate::federation::at_rest_cascade::WRAP_ALGORITHM_V2),
        ),
        ("wrapped_dek", Value::Bytes(vec![9; 48])),
    ];
    v.extend(extra);
    map(v)
}

/// I2911: `owner` on content and stream, `epoch` on epoch and stream, the
/// v2 wrap only, no `cohort`.
#[test]
fn i2911_a_key_grant() {
    let epoch = grant(
        "epoch",
        vec![
            ("community", txt(&id(171))),
            ("minter", txt(&id(172))),
            ("epoch", ms(3)),
        ],
    );
    let content = grant(
        "content",
        vec![("at_rest_sha256", digest(0x72)), ("owner", txt(&id(173)))],
    );
    let stream = grant(
        "stream",
        vec![
            ("stream_id", txt("s-1")),
            ("epoch", ms(4)),
            ("owner", txt(&id(173))),
        ],
    );
    ok(GRANT, &epoch, "I2911 epoch");
    ok(GRANT, &content, "I2911 content");
    ok(GRANT, &stream, "I2911 stream");
    bad(
        GRANT,
        &with(&epoch, vec![], &["epoch"]),
        "I2911 epoch on epoch",
    );
    bad(
        GRANT,
        &with(&stream, vec![], &["epoch"]),
        "I2911 epoch on stream",
    );
    bad(
        GRANT,
        &with(&content, vec![], &["owner"]),
        "I2911 owner on content",
    );
    bad(
        GRANT,
        &with(&stream, vec![], &["owner"]),
        "I2911 owner on stream",
    );
    bad(
        GRANT,
        &with(
            &content,
            vec![(
                "wrap_algorithm",
                txt(crate::federation::key_grant::KEY_GRANT_ALGORITHM_V2_LEGACY_HYPHENATED),
            )],
            &[],
        ),
        "I2911 the v2 wire string only",
    );
    bad(
        GRANT,
        &with(&epoch, vec![("cohort", txt(&id(171)))], &[]),
        "I2911 no `cohort` member",
    );
    ok(
        GRANT,
        &with(
            &epoch,
            vec![
                ("cohort_scope", txt("community")),
                ("community_id", txt(&id(171))),
            ],
            &[],
        ),
        "I2911 the target alias is the CC 2.1 member",
    );
}

// ---- delivery_receipt:{stream_id} -----------------------------------------

/// I2912: the chunk index is `k`; no inner signature member.
#[test]
fn i2912_a_delivery_receipt() {
    let fam = "delivery_receipt:{stream_id}";
    let r = map(vec![
        ("asserted_at", ms(1_000)),
        ("author", txt(&id(180))),
        ("dimension", txt("delivery_receipt:s-1:v1")),
        ("stream_id", txt("s-1")),
        ("epoch", ms(2)),
        ("k", ms(17)),
        ("chunk_root", digest(0x80)),
    ]);
    ok(fam, &r, "I2912 the receipt payload");
    bad(
        fam,
        &with(&r, vec![("K", ms(17))], &["k"]),
        "I2912 CBOR member names are lowercase",
    );
    bad(
        fam,
        &with(&r, vec![("signature", Value::Bytes(vec![1; 64]))], &[]),
        "I2912 no inner signed object",
    );
}

// ---- the tables -----------------------------------------------------------

/// I2913: `amendment_digest` is a hash-digest member; the bases are the
/// registry's.
#[test]
fn i2913_the_member_tables() {
    for member in [
        "evidence_refs",
        "seat_commitment",
        "carried",
        "amendment_digest",
    ] {
        assert!(
            HASH_DIGEST_MEMBERS.contains(&member),
            "I2913 {member} is a hash-digest member"
        );
    }
    let path = concat!(
        env!("CARGO_MANIFEST_DIR"),
        "/src/federation/namespace/namespace_registry.json"
    );
    let reg: serde_json::Value =
        serde_json::from_str(&std::fs::read_to_string(path).expect("I2913 the registry"))
            .expect("I2913 registry json");
    let mut found = None;
    let mut stack = vec![&reg];
    while let Some(v) = stack.pop() {
        match v {
            serde_json::Value::Object(o) => {
                if o.get("prefix").and_then(serde_json::Value::as_str)
                    == Some("takedown_notice:{basis}")
                {
                    found = o.get("segments").cloned();
                }
                stack.extend(o.values());
            }
            serde_json::Value::Array(a) => stack.extend(a.iter()),
            _ => {}
        }
    }
    let segments = found.expect("I2913 the takedown_notice row");
    let values: Vec<String> = segments
        .as_array()
        .into_iter()
        .flatten()
        .filter(|s| s["segment"] == "{basis}")
        .flat_map(|s| s["values"].as_array().cloned().unwrap_or_default())
        .filter_map(|v| v.as_str().map(str::to_owned))
        .collect();
    let mut want: Vec<String> = LEGAL_BASES.iter().map(|s| (*s).to_owned()).collect();
    let mut got = values;
    want.sort();
    got.sort();
    assert_eq!(
        got, want,
        "I2913 LEGAL_BASES is the registry's {{basis}} vocabulary"
    );
}

// ---- identity:occurrence (O1) -------------------------------------------

/// I2918: the `identity:occurrence` payload.
#[test]
fn i2918_an_identity_occurrence() {
    let fam = "identity:occurrence";
    let occ = occurrence();
    ok(fam, &occ, "I2918 the required members");
    ok(
        fam,
        &with(
            &occ,
            vec![
                ("build_manifest_hash", digest(0x90)),
                ("valid_until", ms(9_000)),
                ("hardware_attestation", Value::Bytes(vec![1; 16])),
                ("onion_relay", map(vec![("opt_out", Value::Bool(true))])),
                (
                    "refs",
                    refs(vec![
                        ("head", ref2(&[0x9e; 32])),
                        ("also", map(vec![("cites", ref_set(0x91))])),
                    ]),
                ),
            ],
            &[],
        ),
        "I2918 the optional members",
    );
    bad(
        fam,
        &with(&occ, vec![], &["device_class"]),
        "I2918 device_class is required",
    );
    // The device-class vocabulary is `types::device_class` (its own token,
    // `federation_device_class_rejected`, at O1's door): one source, so the
    // list types the member and does not close it.
    ok(
        fam,
        &with(&occ, vec![("device_class", txt("toaster"))], &[]),
        "I2918 the vocabulary is device_class's own gate, not the list's",
    );
    bad(
        fam,
        &with(&occ, vec![("occurrence", txt(&id(191)))], &[]),
        "I2918 an unlisted member (the short spelling no family uses)",
    );
    bad(
        fam,
        &with(
            &occ,
            vec![("build_manifest_hash", txt(&"ab".repeat(32)))],
            &[],
        ),
        "I2918 build_manifest_hash is a digest, never hex",
    );
}

// ---- the fixtures the door witness signs (I2919) -------------------------

fn occurrence() -> Value {
    map(vec![
        ("asserted_at", ms(1_000)),
        ("author", txt(&id(190))),
        ("identity_key_id", txt(&id(190))),
        ("occurrence_key_id", txt(&id(191))),
        ("device_class", txt("phone")),
        ("refs", refs(vec![("head", ref2(&[0x9e; 32]))])),
    ])
}

fn occurrence_revocation() -> Value {
    map(vec![
        ("asserted_at", ms(1_000)),
        ("author", txt(&id(130))),
        ("identity_key_id", txt(&id(130))),
        ("occurrence_key_id", txt(&id(131))),
        ("revoked_at", ms(1_000)),
        ("effective_at", ms(1_000)),
        // CC rc21 7f94be1: the key:record of each voice (and its occurrence
        // binding, when it has one) under refs.also.cites.
        (
            "refs",
            refs(vec![
                ("head", ref2(&[0x9e; 32])),
                ("also", map(vec![("cites", voice_cites())])),
            ]),
        ),
    ])
}

/// The rows an occurrence revocation's voices are cited by: a voice's
/// key:record and its occurrence binding (a set, sorted by encoding).
fn voice_cites() -> Value {
    let mut v = vec![ref2(&[0x9c; 32]), ref2(&[0x9d; 32])];
    v.sort_by_key(ciris_verify_core::cde::encode);
    Value::Array(v)
}

fn revocation() -> Value {
    map(vec![
        ("asserted_at", ms(1_000)),
        ("author", txt(&id(132))),
        ("dimension", txt("revocation:key:compromise:v1")),
        ("revoked_at", ms(1_000)),
        ("effective_at", ms(1_000)),
    ])
}

fn receipt() -> Value {
    map(vec![
        ("asserted_at", ms(1_000)),
        ("author", txt(&id(180))),
        ("dimension", txt("delivery_receipt:s-1:v1")),
        ("stream_id", txt("s-1")),
        ("epoch", ms(2)),
        ("k", ms(17)),
        ("chunk_root", digest(0x80)),
    ])
}

fn cosign_pending() -> Value {
    map(vec![
        ("asserted_at", ms(1_000)),
        ("dimension", txt("cosign:pending:v1")),
    ])
}

/// Per mapped family: a valid payload, and one that breaks its list.
fn door_cases() -> Vec<(&'static str, Value, Value, &'static str)> {
    let content = grant(
        "content",
        vec![("at_rest_sha256", digest(0x72)), ("owner", txt(&id(173)))],
    );
    vec![
        (
            ROSTER,
            roster(1, vec![]),
            roster(1, vec![("charter_digest", txt(&"ab".repeat(32)))]),
            "an unknown member",
        ),
        (
            MEMBERSHIP,
            widening(vec![]),
            with(&widening(vec![]), vec![], &["effective_at"]),
            "a missing required member",
        ),
        (
            "identity:occurrence",
            occurrence(),
            with(&occurrence(), vec![("device_class", ms(1))], &[]),
            "a wrong type",
        ),
        (
            "identity:occurrence_revocation",
            occurrence_revocation(),
            with(&occurrence_revocation(), vec![("reason", txt("lost"))], &[]),
            "a wrong type (reason is a code)",
        ),
        (
            "cosign:{state}",
            cosign_pending(),
            with(
                &cosign_pending(),
                vec![("dimension", txt("cosign:lineage_head:v1"))],
                &[],
            ),
            "a leaf outside the closed states",
        ),
        (
            "revocation:{entity_type}:{reason}",
            revocation(),
            with(&revocation(), vec![], &["revoked_at"]),
            "a missing required member",
        ),
        (
            TAKEDOWN,
            notice("dmca512"),
            with(&notice("dmca512"), vec![("notice_terms", txt("x"))], &[]),
            "an unknown member",
        ),
        (
            CUSTODY,
            custody(vec![]),
            custody(vec![("expires_at", ms(1_000 + 72 * 3_600_000))]),
            "a member the closed custody map refuses",
        ),
        (
            GRANT,
            content.clone(),
            with(&content, vec![("wrapped_dek", txt("not bytes"))], &[]),
            "a wrong type",
        ),
        (
            "delivery_receipt:{stream_id}",
            receipt(),
            with(&receipt(), vec![("K", ms(17))], &["k"]),
            "an unknown member (and k missing)",
        ),
        (
            "admission:unit",
            admission_unit(true, &["compute", "read"]),
            with(
                &admission_unit(true, &["compute", "read"]),
                vec![],
                &["valid_until"],
            ),
            "a missing required member",
        ),
        (
            "identity_amendment",
            amendment(true),
            with(
                &amendment(true),
                vec![("amendment_digest", txt(&"cd".repeat(32)))],
                &[],
            ),
            "a wrong type (hex, not a digest)",
        ),
        (
            "deferral:response:{outcome}",
            approval(),
            with(&approval(), vec![("call_fingerprint", ms(1))], &[]),
            "a wrong type",
        ),
        (
            "location_proof:{version}",
            location_proof(),
            with(&location_proof(), vec![("cell_resolution", ms(9))], &[]),
            "finer than rough",
        ),
        (
            "deferral:request",
            deferral_request(),
            with(&deferral_request(), vec![], &["reason_digest"]),
            "a missing required member",
        ),
        // v62.0.0 (red round 3, X1) — the canonical seat's X-Wing re-bind
        // (counted by the accord's holders, `refs.head` the bundle in force).
        (
            "transport:canonical_rebind",
            canonical_rebind(),
            with(
                &canonical_rebind(),
                vec![("transit_xwing_pubkey", txt("not bytes"))],
                &[],
            ),
            "a wrong type",
        ),
        // v62.0.0 (wave P7, foreign hunk) — the trace row: the inline form is
        // gone (CC: the manifest form is the only form).
        (
            "trace:{form}:{version}",
            trace_row(),
            with(
                &trace_row(),
                vec![("trace", map(vec![("trace_id", txt("t-1"))]))],
                &[],
            ),
            "an unknown member (an inline trace)",
        ),
    ]
}

/// v62.0.0 (wave P7) — a `trace:complete:v1` payload in the manifest form.
fn trace_row() -> Value {
    map(vec![
        ("asserted_at", ms(1_000)),
        ("author", txt(&id(204))),
        ("dimension", txt("trace:complete:v1")),
        ("trace_id", txt("t-1")),
        ("agent_id_hash", txt("deadbeef")),
        ("subject_key_ids", Value::Array(vec![txt(&id(204))])),
        ("evidence_refs", Value::Array(vec![digest(0xc0)])),
        (
            "manifest",
            map(vec![
                ("schema", txt("trace_manifest:v1")),
                ("content_hash", txt(&format!("sha256:{}", "c0".repeat(32)))),
                ("byte_len", ms(10)),
                ("component_count", ms(0)),
            ]),
        ),
    ])
}

// ---- rc21 admission (I2921–I2923) ----------------------------------------

/// A sorted set of text.
fn text_set_of(xs: &[&str]) -> Value {
    let mut e: Vec<Value> = xs.iter().map(|x| txt(x)).collect();
    e.sort_by_key(ciris_verify_core::cde::encode);
    Value::Array(e)
}

/// An `admission:unit` payload: authored (an `author`) or counted (a
/// `refs.head`), with `caps`, a one-hour lease from 1_000.
fn admission_unit(authored: bool, caps: &[&str]) -> Value {
    let mut v = vec![
        ("asserted_at", ms(1_000)),
        ("dimension", txt("admission:unit:v1")),
        ("unit", digest(0xa0)),
        ("capabilities", text_set_of(caps)),
        ("valid_until", ms(1_000 + 3_600_000)),
    ];
    if authored {
        v.push(("author", txt(&id(201))));
        // CC ruling: an owner-alone row is at `self`.
        v.push(("cohort_scope", txt("self")));
    } else {
        v.push(("refs", refs(vec![("head", ref2(&[0xa1; 32]))])));
    }
    map(v)
}

/// The `sub` of [`admission_unit`]'s row.
fn unit_sub() -> String {
    format!(
        "{}{}",
        super::payloads::ADMISSION_UNIT_SUB_PREFIX,
        hex::encode([0xa0u8; 32])
    )
}

/// An `identity_amendment` payload; a later link names its `prev`.
fn amendment(base: bool) -> Value {
    let mut v = vec![
        ("asserted_at", ms(1_000)),
        ("author", txt(&id(202))),
        ("dimension", txt("identity_amendment:v1")),
        ("amendment_digest", digest(0xb0)),
    ];
    // rc21: the approving response under refs.also.cites; no evidence_refs.
    let cites = (
        "also",
        map(vec![("cites", Value::Array(vec![ref2(&[0xb1; 32])]))]),
    );
    if base {
        v.push(("refs", refs(vec![cites])));
    } else {
        v.push(("refs", refs(vec![cites, ("prev", ref2(&[0xb2; 32]))])));
    }
    map(v)
}

/// A `deferral:response:approved` payload approving a call and a text.
fn approval() -> Value {
    map(vec![
        ("asserted_at", ms(1_000)),
        ("author", txt(&id(203))),
        ("dimension", txt("deferral:response:approved:v1")),
        ("amendment_digest", digest(0xc0)),
        ("call_fingerprint", digest(0xc1)),
        ("deferral_id", txt("d-17")),
        ("refs", refs(vec![("answers", ref2(&[0xc2; 32]))])),
    ])
}

/// A `deferral:request` payload (CC ruling: `deferral_id` and
/// `reason_digest` required).
fn deferral_request() -> Value {
    map(vec![
        ("asserted_at", ms(900)),
        ("author", txt(&id(204))),
        ("dimension", txt("deferral:request:v1")),
        ("deferral_id", txt("d-17")),
        ("reason_digest", digest(0xc4)),
    ])
}

fn admission_reason(p: &Value) -> String {
    use super::payloads::{check, check_admission_unit};
    match check("admission:unit", p).and_then(|()| check_admission_unit(&unit_sub(), p)) {
        Ok(()) => "ok".into(),
        Err(e) => reason(&e).to_owned(),
    }
}

/// I2921: the `admission:unit` list and the verifier's pure rules.
#[test]
fn i2921_an_admission_unit() {
    use crate::federation::malformed_row as mr;
    assert_eq!(
        admission_reason(&admission_unit(true, &["compute", "read"])),
        "ok",
        "I2921 authored, no effect"
    );
    assert_eq!(
        admission_reason(&admission_unit(false, &["compute", "net_send", "sign"])),
        "ok",
        "I2921 a counted row may name effects"
    );
    // Authored XOR counted.
    let both = with(
        &admission_unit(true, &["read"]),
        vec![("refs", refs(vec![("head", ref2(&[0xa1; 32]))]))],
        &[],
    );
    assert_eq!(
        admission_reason(&both),
        mr::ADMISSION_UNIT_MALFORMED,
        "I2921 both"
    );
    let neither = with(&admission_unit(true, &["read"]), vec![], &["author"]);
    assert_eq!(
        admission_reason(&neither),
        mr::ADMISSION_UNIT_MALFORMED,
        "I2921 neither"
    );
    // AU-fix1 (CC 2.7.11 P2:1682): one person's row that names an effect
    // is at `self` (`admission_owner_row_not_self` elsewhere, an absent scope
    // included); one that names no effect, and a counted row, at any scope.
    for scope in [Some("federation"), Some("community"), None] {
        let at = |caps: &[&str]| match scope {
            Some(sc) => with(
                &admission_unit(true, caps),
                vec![("cohort_scope", txt(sc))],
                &[],
            ),
            None => with(&admission_unit(true, caps), vec![], &["cohort_scope"]),
        };
        assert_eq!(
            admission_reason(&at(&["compute", "net_send"])),
            mr::ADMISSION_OWNER_ROW_NOT_SELF,
            "I2921 one person's effect row at {scope:?} is not at self"
        );
        assert_eq!(
            admission_reason(&at(&["read"])),
            "ok",
            "I2921 one person's compute/read row at {scope:?}"
        );
    }
    for sc in ["self", "community", "federation"] {
        let p = with(
            &admission_unit(false, &["read", "net_send"]),
            vec![("cohort_scope", txt(sc))],
            &[],
        );
        assert_eq!(admission_reason(&p), "ok", "I2921 a counted row at {sc}");
    }
    // `sub` is the unit's digest.
    let e = super::payloads::check_admission_unit(
        "canonical:sha256:00",
        &admission_unit(true, &["read"]),
    )
    .unwrap_err();
    assert_eq!(reason(&e), mr::ADMISSION_UNIT_MALFORMED, "I2921 sub");
    // Capabilities: closed, non-empty.
    assert_eq!(
        admission_reason(&admission_unit(true, &[])),
        mr::ADMISSION_CAPABILITY_UNKNOWN,
        "I2921 empty"
    );
    assert_eq!(
        admission_reason(&admission_unit(false, &["teleport"])),
        mr::ADMISSION_CAPABILITY_UNKNOWN,
        "I2921 unknown"
    );
    // The lease window.
    for (until, why) in [
        (1_000, "closed at opening"),
        (999, "before"),
        (1_000 + 86_400_001, "too long"),
    ] {
        let p = with(
            &admission_unit(true, &["read"]),
            vec![("valid_until", ms(until))],
            &[],
        );
        assert_eq!(
            admission_reason(&p),
            mr::ADMISSION_LEASE_OUT_OF_WINDOW,
            "I2921 {why}"
        );
    }
    let edge = with(
        &admission_unit(true, &["read"]),
        vec![("valid_until", ms(1_000 + 86_400_000))],
        &[],
    );
    assert_eq!(
        admission_reason(&edge),
        "ok",
        "I2921 exactly unit_lease_max_secs"
    );
    // AU-fix1 (CC 2.7.11): one person's effect row at `self` is well
    // formed; it admits only on that person's own host (the host's read).
    assert_eq!(
        admission_reason(&admission_unit(true, &["compute", "actuate"])),
        "ok",
        "I2921 one person's effect row at self"
    );
    // Shape faults stay the list's.
    let unsorted = with(
        &admission_unit(true, &["read"]),
        vec![(
            "capabilities",
            // "read" encodes shorter than "compute", so the set's order is
            // read, compute: this is the reverse.
            Value::Array(vec![txt("compute"), txt("read")]),
        )],
        &[],
    );
    assert_eq!(
        admission_reason(&unsorted),
        malformed_row::EDITION2_PAYLOAD_INVALID,
        "I2921 capabilities is a set"
    );
}

/// I2922: an admission signer is a person.
#[test]
fn i2922_an_admission_signer_is_a_person() {
    use super::door::AdmittedRow;
    use super::door_invariants::fixture::{key, key_record, kid};
    use super::ingest::require_admission_signer_is_person;
    use super::liveness::HeldKeys;
    use crate::federation::malformed_row as mr;
    let row = |k: &ciris_crypto::composite::CompositeSigningKey, family: &str| AdmittedRow {
        row_id: super::names::RowId([0xd0; 32]),
        statement_id: [0xd1; 32],
        kid: kid(k),
        iss: iref(k),
        sub: unit_sub(),
        row_type: "scores".into(),
        family: family.into(),
        author: Some(iref(k)),
        asserted_at_ms: 5_000,
        payload: admission_unit(true, &["read"]),
        names: Vec::new(),
        role: None,
        bytes: Vec::new(),
    };
    for (n, roles, person) in [
        (210u8, &["user"][..], true),
        (211, &["accord_holder"][..], true),
        (212, &["node"][..], false),
        (213, &["agent"][..], false),
    ] {
        let k = key(n);
        let mut keys = HeldKeys::new();
        keys.insert_record(key_record(&k, roles, 0, None));
        let got = require_admission_signer_is_person(&keys, &row(&k, "admission:unit"));
        if person {
            got.unwrap_or_else(|e| panic!("I2922 {roles:?} is a person: {e}"));
        } else {
            assert_eq!(
                reason(&got.unwrap_err()),
                mr::ADMISSION_ISSUER_NOT_PERSON,
                "I2922 {roles:?}"
            );
            // Another family is not judged by the admission rule.
            require_admission_signer_is_person(&keys, &row(&k, "identity_amendment"))
                .expect("I2922 other families untouched");
        }
    }
    // A signer with no held record is no person either.
    let k = key(214);
    assert_eq!(
        reason(
            &require_admission_signer_is_person(&HeldKeys::new(), &row(&k, "admission:unit"))
                .unwrap_err()
        ),
        mr::ADMISSION_ISSUER_NOT_PERSON,
        "I2922 unheld"
    );
}

/// I2923: the profile chain's `refs.prev`, and the approval's fingerprint.
#[test]
fn i2923_the_amendment_chain_and_the_call_fingerprint() {
    let ia = "identity_amendment";
    ok(ia, &amendment(true), "I2923 the base link names no prev");
    ok(ia, &amendment(false), "I2923 a later link names its prev");
    bad(
        ia,
        &with(
            &amendment(false),
            vec![("prev", txt(&hex::encode([0xb2u8; 32])))],
            &[],
        ),
        "I2923 prev is a row-ref under refs, not a member",
    );
    bad(
        ia,
        &with(&amendment(true), vec![], &["amendment_digest"]),
        "I2923 amendment_digest is required",
    );
    let dr = "deferral:response:{outcome}";
    ok(
        dr,
        &approval(),
        "I2923 approved: call_fingerprint and amendment_digest",
    );
    ok(
        dr,
        &with(
            &approval(),
            vec![],
            &["call_fingerprint", "amendment_digest"],
        ),
        "I2923 an approval of neither",
    );
    let rejected = with(
        &approval(),
        vec![("dimension", txt("deferral:response:rejected:v1"))],
        &["call_fingerprint", "amendment_digest"],
    );
    ok(dr, &rejected, "I2923 rejected");
    bad(
        dr,
        &with(&rejected, vec![("call_fingerprint", digest(0xc1))], &[]),
        "I2923 a rejected response carries no fingerprint",
    );
    bad(
        dr,
        &with(
            &approval(),
            vec![("dimension", txt("deferral:response:maybe:v1"))],
            &[],
        ),
        "I2923 the outcomes are closed",
    );
    assert!(
        super::payloads::HASH_DIGEST_MEMBERS.contains(&"call_fingerprint"),
        "I2923 call_fingerprint reads back as hex for the earlier gates"
    );
}

/// Every mapped family has a door case.
#[test]
fn i2919_every_mapped_family_has_a_door_case() {
    let cased: Vec<&str> = door_cases().iter().map(|c| c.0).collect();
    for f in FAMILIES {
        assert!(
            cased.contains(&f.family),
            "I2919 {} has no door case",
            f.family
        );
    }
}

#[cfg(any(feature = "sqlite", feature = "postgres"))]
mod door {
    use std::sync::Arc;

    use ciris_verify_core::edition2::sign_row_statement;
    use ciris_verify_core::namespace_match::family_id;

    use super::super::door_invariants::fixture::{iref, key};
    use super::super::ingest::{put_statement, INGEST_TIER};
    use super::*;
    use crate::federation::directory_double::FaultInjectingDirectory;
    use crate::federation::FederationDirectory;

    /// The generated double, read for the names of the methods it delegates.
    const DOUBLE: &str = include_str!("../directory_double.rs");

    /// `inner` with every delegated method erroring: any directory read
    /// answers `federation_backend`.
    fn no_reads(inner: Arc<dyn FederationDirectory>) -> FaultInjectingDirectory {
        DOUBLE
            .lines()
            .filter_map(|l| l.trim_start().strip_prefix("async fn "))
            .filter_map(|rest| rest.split('(').next())
            .map(str::trim)
            .filter(|n| !n.is_empty())
            .fold(FaultInjectingDirectory::new(inner), |d, m| d.erroring(m))
    }

    fn signed(family: &str, payload: &Value) -> Vec<u8> {
        let k = key(200);
        // An admission row's `sub` is its unit's digest (CC 2.7.11).
        let sub = if family == "admission:unit" {
            unit_sub()
        } else {
            iref(&k)
        };
        sign_row_statement(
            &k,
            &iref(&k),
            &sub,
            "scores",
            &family_id(family),
            payload,
            vec![],
        )
        .unwrap()
    }

    async fn body(inner: Arc<dyn FederationDirectory>) {
        let dir = no_reads(inner);
        for (family, good, broken, what) in door_cases() {
            let e = put_statement(&dir, &signed(family, &broken), None, INGEST_TIER)
                .await
                .unwrap_err();
            assert_eq!(
                reason(&e),
                malformed_row::EDITION2_PAYLOAD_INVALID,
                "I2919 {family}: {what} is refused at the door with no read: {e:?}"
            );
            let e = put_statement(&dir, &signed(family, &good), None, INGEST_TIER)
                .await
                .unwrap_err();
            assert_eq!(
                e.kind(),
                "federation_backend",
                "I2919 {family}: a valid payload passes the pure gates and reaches the \
                 directory (the double's injected failure): {e:?}"
            );
        }
        // I2926: a composer carries its target's family, and the composer
        // rule (not the target's list) judges it, before any read.
        let k = key(200);
        let withdraws = |p: &Value| {
            sign_row_statement(
                &k,
                &iref(&k),
                &iref(&k),
                "withdraws",
                &family_id("identity:occurrence"),
                p,
                vec![],
            )
            .unwrap()
        };
        let e = put_statement(&dir, &withdraws(&composer()), None, INGEST_TIER)
            .await
            .unwrap_err();
        assert_eq!(
            e.kind(),
            "federation_backend",
            "I2926 an edition-2 withdraws of an occurrence passes the payload check: {e:?}"
        );
        let counted = map(vec![
            ("asserted_at", ms(2_000)),
            (
                "refs",
                refs(vec![
                    ("target", ref2(&[0xe0; 32])),
                    ("head", ref2(&[0xe1; 32])),
                ]),
            ),
        ]);
        let e = put_statement(&dir, &withdraws(&counted), None, INGEST_TIER)
            .await
            .unwrap_err();
        assert_eq!(
            e.kind(),
            "federation_backend",
            "I2926 a counted withdraws (target + head, no author) passes the payload check: {e:?}"
        );
        let e = put_statement(
            &dir,
            &withdraws(&with(&composer(), vec![("nonsense", ms(1))], &[])),
            None,
            INGEST_TIER,
        )
        .await
        .unwrap_err();
        assert_eq!(
            reason(&e),
            malformed_row::EDITION2_PAYLOAD_INVALID,
            "I2926 a composer with an unknown member is refused with no read: {e:?}"
        );
        // A family with no list passes the payload check as before.
        let e = put_statement(
            &dir,
            &signed(
                "evidence:.suite:.kind:.cell:.prefix",
                &map(vec![("asserted_at", ms(1_000)), ("anything", ms(1))]),
            ),
            None,
            INGEST_TIER,
        )
        .await
        .unwrap_err();
        assert_eq!(
            e.kind(),
            "federation_backend",
            "I2919 an unmapped family is not checked against a list: {e:?}"
        );
    }

    /// I3991: a response stored through the door reads its request back.
    async fn answers_body(d: Arc<dyn FederationDirectory>) {
        use super::super::door_invariants::fixture::key_record;
        // `signed` signs with key(200): its record is held, and it authors.
        let k = key(200);
        put_statement(&*d, &key_record(&k, &["user"], 0, None), None, INGEST_TIER)
            .await
            .unwrap_or_else(|e| panic!("I3991 key record: {e:?}"));
        let p = with(&approval(), vec![("author", txt(&iref(&k)))], &[]);
        let st = signed("deferral:response:{outcome}", &p);
        let out = put_statement(&*d, &st, None, INGEST_TIER)
            .await
            .unwrap_or_else(|e| panic!("I3991 a response admits: {e:?}"));
        let super::super::ingest::StatementOutcome::Row { row_id, .. } = out else {
            panic!("I3991: {out:?}");
        };
        let stored = d.get_attestation(&row_id.hex()).await.unwrap().unwrap();
        assert_eq!(
            stored.attestation_envelope["references_attestation_id"],
            serde_json::json!(hex::encode([0xc2u8; 32])),
            "I3991 stored: refs.answers read back as the request"
        );
    }

    #[cfg(feature = "sqlite")]
    #[tokio::test]
    async fn i3991_a_stored_response_reads_its_request_sqlite() {
        use crate::store::Backend as _;
        let b = crate::store::sqlite::SqliteBackend::open_in_memory()
            .await
            .unwrap();
        b.run_migrations().await.unwrap();
        Box::pin(answers_body(Arc::new(b))).await;
    }

    #[cfg(feature = "postgres")]
    #[tokio::test]
    async fn i3991_a_stored_response_reads_its_request_postgres() {
        use crate::store::Backend as _;
        let Some(dsn) = crate::test_pg::empty_dsn() else {
            return;
        };
        let b = crate::store::postgres::PostgresBackend::connect(&dsn)
            .await
            .unwrap();
        b.run_migrations().await.unwrap();
        Box::pin(answers_body(Arc::new(b))).await;
    }

    #[cfg(feature = "sqlite")]
    #[tokio::test]
    async fn i2919_the_lists_are_enforced_at_the_door_sqlite() {
        use crate::store::Backend as _;
        let b = crate::store::sqlite::SqliteBackend::open_in_memory()
            .await
            .unwrap();
        b.run_migrations().await.unwrap();
        Box::pin(body(Arc::new(b))).await;
    }

    #[cfg(feature = "postgres")]
    #[tokio::test]
    async fn i2919_the_lists_are_enforced_at_the_door_postgres() {
        use crate::store::Backend as _;
        let Some(dsn) = crate::test_pg::empty_dsn() else {
            return;
        };
        let b = crate::store::postgres::PostgresBackend::connect(&dsn)
            .await
            .unwrap();
        b.run_migrations().await.unwrap();
        Box::pin(body(Arc::new(b))).await;
    }

    /// I4002: a chat reply and a chat reaction naming their message in
    /// `refs.answers` pass the door's pure gates (no refusal before the
    /// first directory read, which the all-erroring double answers).
    async fn chat_body(inner: Arc<dyn FederationDirectory>) {
        let dir = no_reads(inner);
        for (what, p) in [("reply", chat_reply()), ("reaction", chat_reaction())] {
            let e = put_statement(&dir, &signed("chat:*", &p), None, INGEST_TIER)
                .await
                .unwrap_err();
            assert_eq!(
                e.kind(),
                "federation_backend",
                "I4002 a chat {what} with refs.answers passes the payload check: {e:?}"
            );
        }
        // Still the closed `also` roles on chat: an unregistered one is refused.
        let bad_also = with(
            &chat_reply(),
            vec![(
                "refs",
                refs(vec![
                    ("answers", ref2(&[0xa7; 32])),
                    ("also", map(vec![("thread", ref_set(0xa8))])),
                ]),
            )],
            &[],
        );
        let e = put_statement(&dir, &signed("chat:*", &bad_also), None, INGEST_TIER)
            .await
            .unwrap_err();
        assert_eq!(
            reason(&e),
            malformed_row::EDITION2_PAYLOAD_INVALID,
            "I4002 the also roles stay closed on chat: {e:?}"
        );
    }

    #[cfg(feature = "sqlite")]
    #[tokio::test]
    async fn i4002_a_chat_answer_passes_the_door_sqlite() {
        use crate::store::Backend as _;
        let b = crate::store::sqlite::SqliteBackend::open_in_memory()
            .await
            .unwrap();
        b.run_migrations().await.unwrap();
        Box::pin(chat_body(Arc::new(b))).await;
    }

    #[cfg(feature = "postgres")]
    #[tokio::test]
    async fn i4002_a_chat_answer_passes_the_door_postgres() {
        use crate::store::Backend as _;
        let Some(dsn) = crate::test_pg::empty_dsn() else {
            return;
        };
        let b = crate::store::postgres::PostgresBackend::connect(&dsn)
            .await
            .unwrap();
        b.run_migrations().await.unwrap();
        Box::pin(chat_body(Arc::new(b))).await;
    }
}

/// I2920: the occurrence revocation uses the occurrence record's own names.
#[test]
fn i2920_the_occurrence_revocation_uses_the_records_names() {
    let fam = "identity:occurrence_revocation";
    ok(
        fam,
        &occurrence_revocation(),
        "I2920 identity_key_id / occurrence_key_id",
    );
    let short = with(
        &occurrence_revocation(),
        vec![("identity", txt(&id(130))), ("occurrence", txt(&id(131)))],
        &["identity_key_id", "occurrence_key_id"],
    );
    bad(fam, &short, "I2920 the short spellings are not members");
    bad(
        fam,
        &with(&occurrence_revocation(), vec![], &["occurrence_key_id"]),
        "I2920 occurrence_key_id is required",
    );
}

// ---- composers (I2926) ---------------------------------------------------

/// A composer's payload naming its target.
fn composer() -> Value {
    map(vec![
        ("asserted_at", ms(2_000)),
        ("author", txt(&id(190))),
        ("refs", refs(vec![("target", ref2(&[0xe0; 32]))])),
    ])
}

/// I2926: the composer rule, not the target family's list.
#[test]
fn i2926_a_composer_is_checked_by_the_composer_rule() {
    use super::payloads::check_by_id;
    use ciris_verify_core::namespace_match::family_id;
    let occ = family_id("identity:occurrence");
    // v62.0.0 (PIN-fix5) — the composer rule is a retraction's
    // (`withdraws` / `recants`); a `supersedes` takes its family's check
    // (I2434).
    for kind in ["withdraws", "recants"] {
        check_by_id(&occ, kind, &composer())
            .unwrap_or_else(|e| panic!("I2926 a {kind} of an occurrence passes: {e}"));
        // The target family's own member is not a composer's.
        let e = check_by_id(
            &occ,
            kind,
            &with(&composer(), vec![("device_class", txt("phone"))], &[]),
        )
        .unwrap_err();
        assert_eq!(
            reason(&e),
            malformed_row::EDITION2_PAYLOAD_INVALID,
            "I2926 {kind}"
        );
        let e = check_by_id(
            &occ,
            kind,
            &with(&composer(), vec![("nonsense", ms(1))], &[]),
        )
        .unwrap_err();
        assert_eq!(
            reason(&e),
            malformed_row::EDITION2_PAYLOAD_INVALID,
            "I2926 {kind}"
        );
        let e = check_by_id(&occ, kind, &with(&composer(), vec![], &["refs"])).unwrap_err();
        assert_eq!(
            reason(&e),
            malformed_row::EDITION2_PAYLOAD_INVALID,
            "I2926 {kind} names its target"
        );
    }
    // A COUNTED composer (a group's withdrawal of a counted row): no
    // `author`, `refs.target` and `refs.head` (the roster head it is counted
    // over). The composer rule admits it.
    let counted = map(vec![
        ("asserted_at", ms(2_000)),
        (
            "refs",
            refs(vec![
                ("target", ref2(&[0xe0; 32])),
                ("head", ref2(&[0xe1; 32])),
            ]),
        ),
    ]);
    for fam in [
        family_id("membership:{stage}"),
        family_id("group:roster"),
        occ.clone(),
    ] {
        for kind in ["withdraws", "recants"] {
            check_by_id(&fam, kind, &counted).unwrap_or_else(|e| {
                panic!("I2926 a counted {kind} (target + head, no author) of {fam} passes: {e}")
            });
        }
    }
    // Still the composer rule: a counted composer with no target is refused.
    let e = check_by_id(
        &occ,
        "withdraws",
        &map(vec![
            ("asserted_at", ms(2_000)),
            ("refs", refs(vec![("head", ref2(&[0xe1; 32]))])),
        ]),
    )
    .unwrap_err();
    assert_eq!(
        reason(&e),
        malformed_row::EDITION2_PAYLOAD_INVALID,
        "I2926 a counted composer names its target"
    );
    // The same payload as a non-composer of the family meets the list.
    assert!(
        check_by_id(&occ, "scores", &composer()).is_err(),
        "I2926 a non-composer is the family's list"
    );
    // One list of composer types.
    assert_eq!(
        super::payloads::COMPOSER_ROW_TYPES,
        &super::ingest::COMPOSER_ROW_TYPES[..],
        "I2926 the door's composer types are ingest's"
    );
}

/// I2434 (v62.0.0, PIN-fix5; the Constitution's ruling of 2026-11-21, CC
/// 2.4.1; CIRISVerify 23.4.1) — a `supersedes` is a replacement statement:
/// its FAMILY's payload check, with `refs.target` required and the `also`
/// roles closed. A `supersedes` of an occurrence carrying the occurrence's
/// own members passes; one carrying a member the family does not define, one
/// naming no target, and one with an `also` role outside (ack | cites) are
/// refused. (A family that differs from its target's is the door's HOLD,
/// `composer_family_mismatch`, read from the target row: not this pure
/// check.)
#[test]
fn i2434_a_supersedes_is_checked_by_its_family() {
    use super::payloads::check_by_id;
    use ciris_verify_core::namespace_match::family_id;
    let occ = family_id("identity:occurrence");
    let replacement = with(
        &occurrence(),
        vec![(
            "refs",
            refs(vec![
                ("head", ref2(&[0x9e; 32])),
                ("target", ref2(&[0xe0; 32])),
            ]),
        )],
        &[],
    );
    check_by_id(&occ, "supersedes", &replacement)
        .unwrap_or_else(|e| panic!("I2434 a supersedes with its family's own members passes: {e}"));
    let e = check_by_id(
        &occ,
        "supersedes",
        &with(&replacement, vec![("nonsense", ms(1))], &[]),
    )
    .unwrap_err();
    assert_eq!(
        reason(&e),
        malformed_row::EDITION2_PAYLOAD_INVALID,
        "I2434 a member the family does not define is refused"
    );
    let e = check_by_id(&occ, "supersedes", &occurrence()).unwrap_err();
    assert_eq!(
        reason(&e),
        malformed_row::EDITION2_PAYLOAD_INVALID,
        "I2434 a supersedes names the row it replaces (refs.target)"
    );
    assert!(
        e.to_string().contains("refs.target is required"),
        "I2434 named: {e}"
    );
    let e = check_by_id(
        &occ,
        "supersedes",
        &with(
            &replacement,
            vec![(
                "refs",
                refs(vec![
                    ("head", ref2(&[0x9e; 32])),
                    ("target", ref2(&[0xe0; 32])),
                    ("also", map(vec![("thread", ref_set(0xe2))])),
                ]),
            )],
            &[],
        ),
    )
    .unwrap_err();
    assert_eq!(
        reason(&e),
        malformed_row::EDITION2_PAYLOAD_INVALID,
        "I2434 the also roles stay closed"
    );
    // The retraction rule still refuses the family's members on a withdraws.
    assert!(
        check_by_id(&occ, "withdraws", &replacement).is_err(),
        "I2434 a withdraws carries common members only"
    );
}

// ---- geographic proofs (I2929) -------------------------------------------

/// `n` distinct rows under `refs.also.cites` (a set, sorted by encoding).
fn cites(n: u8, head: bool) -> Value {
    let mut set: Vec<Value> = (0..n).map(|i| ref2(&[0xf0 + i; 32])).collect();
    set.sort_by_key(ciris_verify_core::cde::encode);
    // An `also` role is a non-empty set: no cites, no `also`.
    let mut r = if set.is_empty() {
        Vec::new()
    } else {
        vec![("also", map(vec![("cites", Value::Array(set))]))]
    };
    if head {
        r.push(("head", ref2(&[0xef; 32])));
    }
    refs(r)
}

/// I2929: a geographic founding version names its members' proofs.
#[test]
fn i2929_a_geographic_version_names_its_location_proofs() {
    assert_eq!(super::payloads::LOCATION_PROOF_ROLE, "also:cites");
    let geo = |version: u64, refs_v: Option<Value>| {
        let mut extra = vec![("cohort_subkind", txt(super::payloads::GEOGRAPHIC_SUBKIND))];
        if let Some(r) = refs_v {
            extra.push(("refs", r));
        }
        roster(version, extra)
    };
    // `roster()` lists two members.
    ok(
        ROSTER,
        &geo(1, Some(cites(2, false))),
        "I2929 two members, two proofs",
    );
    ok(
        ROSTER,
        &geo(1, Some(cites(3, false))),
        "I2929 the charter rides the same set",
    );
    bad(
        ROSTER,
        &geo(1, Some(cites(1, false))),
        "I2929 a member's proof is missing",
    );
    bad(
        ROSTER,
        &geo(1, None),
        "I2929 a founding geographic version cites nothing",
    );
    // A later version: its new members are known against its predecessor;
    // the fold waits for the proofs (GC5), the list does not count them.
    ok(
        ROSTER,
        &geo(2, Some(cites(0, true))),
        "I2929 a later version, head only",
    );
    ok(
        ROSTER,
        &geo(2, Some(cites(1, true))),
        "I2929 a later version naming a proof",
    );
    // Not geographic: nothing counted.
    ok(
        ROSTER,
        &roster(1, vec![("cohort_subkind", txt("public"))]),
        "I2929 a non-geographic founding version",
    );
}

// ---- rc21 member homes (I3990–I3993) -------------------------------------

/// An admitted row of `family` (a header family id) over `payload`, as the
/// door hands it to the mapping.
fn admitted(family: &str, payload: Value) -> super::door::AdmittedRow {
    let names = super::names::names_of(&payload).unwrap();
    super::door::AdmittedRow {
        row_id: super::names::RowId([0x61; 32]),
        statement_id: [0x62; 32],
        kid: [0x63; 32],
        iss: id(240),
        sub: id(241),
        row_type: "scores".into(),
        family: family.into(),
        author: Some(id(240)),
        asserted_at_ms: 1_000,
        payload,
        names,
        role: None,
        bytes: Vec::new(),
    }
}

/// I3990: the amendment's approval lives under refs.also.cites.
#[test]
fn i3990_the_amendments_approval_is_cited() {
    use ciris_verify_core::namespace_match::family_id;
    let ia = "identity_amendment";
    ok(
        ia,
        &amendment(true),
        "I3990 the base link cites its approval",
    );
    ok(
        ia,
        &amendment(false),
        "I3990 a later link cites its approval",
    );
    bad(
        ia,
        &with(
            &amendment(true),
            vec![("authorized_by", txt(&hex::encode([0xb1u8; 32])))],
            &[],
        ),
        "I3990 authorized_by is no member",
    );
    bad(
        ia,
        &with(
            &amendment(true),
            vec![("evidence_refs", Value::Array(vec![digest(0xb1)]))],
            &[],
        ),
        "I3990 an amendment carries no evidence_refs",
    );
    bad(
        ia,
        &with(&amendment(true), vec![], &["refs"]),
        "I3990 the approval is required",
    );
    let two = with(
        &amendment(true),
        vec![(
            "refs",
            refs(vec![(
                "also",
                map(vec![(
                    "cites",
                    Value::Array({
                        let mut v = vec![ref2(&[0xb1; 32]), ref2(&[0xb3; 32])];
                        v.sort_by_key(ciris_verify_core::cde::encode);
                        v
                    }),
                )]),
            )]),
        )],
        &[],
    );
    bad(ia, &two, "I3990 exactly one approval");
    // The mapping projects the cited row for the earlier gate.
    let a =
        super::ingest::attestation_of(&admitted(&family_id(ia), amendment(false)), "federation")
            .unwrap();
    let hex_b1 = hex::encode([0xb1u8; 32]);
    assert_eq!(
        a.attestation_envelope["authorized_by"],
        serde_json::json!(hex_b1),
        "I3990"
    );
    assert_eq!(
        a.attestation_envelope["evidence_refs"],
        serde_json::json!([hex_b1]),
        "I3990 the earlier gate's citation"
    );
}

/// I3991: the response answers its request.
#[test]
fn i3991_a_response_answers_its_request() {
    use ciris_verify_core::namespace_match::family_id;
    let dr = "deferral:response:{outcome}";
    // FINAL (CC ruling): `deferral_id` is required on the request AND the
    // response (the response correlates on it); `reason_digest` is required
    // on the request and absent from the response.
    ok(
        dr,
        &with(&approval(), vec![("community_id", txt(&id(242)))], &[]),
        "I3991 deferral_id, refs.answers, the routing room (community_id; pending CC)",
    );
    bad(
        dr,
        &with(&approval(), vec![], &["deferral_id"]),
        "I3991 a response correlates on deferral_id",
    );
    bad(
        dr,
        &with(&approval(), vec![("reason_digest", digest(0xc3))], &[]),
        "I3991 a response carries no reason_digest",
    );
    bad(
        dr,
        &with(&approval(), vec![], &["refs"]),
        "I3991 refs.answers is required",
    );
    bad(
        dr,
        &with(
            &approval(),
            vec![(
                "refs",
                refs(vec![
                    ("answers", ref2(&[0xc2; 32])),
                    ("target", ref2(&[0xc2; 32])),
                ]),
            )],
            &[],
        ),
        "I3991 never refs.target",
    );
    let rq = "deferral:request";
    ok(
        rq,
        &deferral_request(),
        "I3991 the request: deferral_id and reason_digest",
    );
    bad(
        rq,
        &with(&deferral_request(), vec![], &["deferral_id"]),
        "I3991 a request names its deferral_id",
    );
    bad(
        rq,
        &with(&deferral_request(), vec![], &["reason_digest"]),
        "I3991 a request carries its reason_digest",
    );
    bad(
        rq,
        &with(
            &deferral_request(),
            vec![("reason_digest", txt("hex"))],
            &[],
        ),
        "I3991 reason_digest is a digest",
    );
    let a =
        super::ingest::attestation_of(&admitted(&family_id(dr), approval()), "federation").unwrap();
    assert_eq!(
        a.attestation_envelope["references_attestation_id"],
        serde_json::json!(hex::encode([0xc2u8; 32])),
        "I3991 the request read back for the earlier gates"
    );
}

/// I3992: no payload map lists `id`.
#[test]
fn i3992_no_payload_map_lists_id() {
    for f in FAMILIES {
        assert!(
            f.members.iter().all(|m| m.name != "id"),
            "I3992 {} lists `id`",
            f.family
        );
    }
    assert!(
        !super::payloads::COMMON.contains(&"id"),
        "I3992 COMMON lists `id`"
    );
    bad(
        "identity_amendment",
        &with(&amendment(true), vec![("id", txt("4f0c-uuid"))], &[]),
        "I3992 Server's envelope uuid is no member",
    );
}

/// I3993: the occurrence families name the identity's self-roster head.
#[test]
fn i3993_occurrence_rows_name_their_roster_head() {
    for (fam, base) in [
        ("identity:occurrence", occurrence()),
        ("identity:occurrence_revocation", occurrence_revocation()),
    ] {
        ok(fam, &base, "I3993 refs.head");
        bad(
            fam,
            &with(&base, vec![], &["refs"]),
            "I3993 refs.head is required",
        );
        let mut tips = vec![ref2(&[0x9a; 32]), ref2(&[0x9b; 32])];
        tips.sort_by_key(ciris_verify_core::cde::encode);
        ok(
            fam,
            &with(
                &base,
                vec![(
                    "refs",
                    // `also.cites` rides too: the revocation requires it, the
                    // occurrence allows it.
                    refs(vec![
                        ("head", ref2(&[0x9e; 32])),
                        ("further_heads", Value::Array(tips)),
                        ("also", map(vec![("cites", voice_cites())])),
                    ]),
                )],
                &[],
            ),
            "I3993 refs.further_heads merges other tips",
        );
        bad(
            fam,
            &with(
                &base,
                vec![(
                    "refs",
                    refs(vec![(
                        "further_heads",
                        Value::Array(vec![ref2(&[0x9a; 32])]),
                    )]),
                )],
                &[],
            ),
            "I3993 further_heads without head",
        );
    }
}

// ---- body numbers, the pair room, location proofs (I3995–I3998) ----------

fn num(text: &str) -> serde_json::Number {
    serde_json::from_str(text).unwrap_or_else(|e| panic!("{text}: {e}"))
}

fn tag4(e: i64, m: i64) -> Value {
    let int = |v: i64| {
        if v >= 0 {
            Value::Uint(v.unsigned_abs())
        } else {
            Value::Nint(v.unsigned_abs() - 1)
        }
    };
    Value::Tag(4, Box::new(Value::Array(vec![int(e), int(m)])))
}

/// I3995: the shared body-number helper.
#[test]
fn i3995_body_numbers_are_exact_decimals() {
    use super::payloads::body_number;
    for (text, want) in [
        ("2.0", Value::Uint(2)),
        ("1e2", Value::Uint(100)),
        ("1E+2", Value::Uint(100)),
        ("-3", Value::Nint(2)),
        ("0", Value::Uint(0)),
        ("-0.0", Value::Uint(0)),
        ("0.5", tag4(-1, 5)),
        ("1.25", tag4(-2, 125)),
        ("-0.050", tag4(-2, -5)),
        ("12.50e-1", tag4(-2, 125)),
        ("0.1", tag4(-1, 1)),
        // Never via f64: 0.1 + 0.2's exact text stays exact.
        ("0.30000000000000004", tag4(-17, 30_000_000_000_000_004)),
    ] {
        assert_eq!(body_number(&num(text)).unwrap(), want, "I3995 {text}");
    }
    // v62.0.0 (P1-fix8, aligned with Verify 23.3.2 per R1-v2332) — a
    // mantissa anywhere in the CBOR integer range states, past i64 included,
    // and the decoder reads it back as the same text.
    let tag4_raw = |e: i64, m: Value| {
        Value::Tag(
            4,
            Box::new(Value::Array(vec![Value::Nint(e.unsigned_abs() - 1), m])),
        )
    };
    for (text, want) in [
        // i64::MAX + 1: past i64, inside CBOR's range.
        (
            "92233720368547758.08",
            tag4_raw(-2, Value::Uint(9_223_372_036_854_775_808)),
        ),
        // -2^64, the bottom of the CBOR integer range.
        (
            "-184467440737095516.16",
            tag4_raw(-2, Value::Nint(u64::MAX)),
        ),
        (
            "0.12345678901234567891",
            tag4_raw(-20, Value::Uint(12_345_678_901_234_567_891)),
        ),
    ] {
        let got = body_number(&num(text)).unwrap();
        assert_eq!(got, want, "I3995 {text}");
        assert_eq!(
            super::payloads::json_number_of_decimal(&got).map(|n| n.to_string()),
            Some(text.to_owned()),
            "I3995 {text} decodes exactly"
        );
    }
    for text in [
        // 2^64: one past the top of the CBOR integer range.
        "184467440737095516.16",
        "-184467440737095516.17",
        "1e40",
        "-1e40",
        "0.123456789012345678901",
    ] {
        let e = body_number(&num(text)).unwrap_err();
        assert_eq!(
            reason(&e),
            malformed_row::BODY_NUMBER_UNREPRESENTABLE,
            "I3995 {text} is refused"
        );
    }
    // The top of the CBOR integer range still states.
    assert_eq!(
        body_number(&num("18446744073709551615")).unwrap(),
        Value::Uint(u64::MAX)
    );
}

/// I3996: the reader refuses a non-normalised decimal, at the door.
#[test]
fn i3996_a_non_normalised_decimal_is_refused() {
    use super::payloads::{check_body_numbers, check_by_id};
    check_body_numbers(&tag4(-1, 5)).expect("I3996 normalised");
    check_body_numbers(&map(vec![("x", Value::Array(vec![tag4(-2, 125)]))])).expect("I3996 nested");
    for (bad_v, what) in [
        (tag4(-1, 50), "a mantissa divisible by 10"),
        (tag4(0, 3), "a zero exponent"),
        (tag4(1, 3), "a positive exponent"),
        (tag4(-1, 0), "a zero mantissa"),
        (
            Value::Tag(4, Box::new(Value::Array(vec![Value::Text("x".into())]))),
            "not [exponent, mantissa]",
        ),
    ] {
        let e = check_body_numbers(&map(vec![("deep", map(vec![("n", bad_v)]))])).unwrap_err();
        assert_eq!(
            reason(&e),
            malformed_row::EDITION2_PAYLOAD_INVALID,
            "I3996 {what}"
        );
    }
    // At the door's schema step, in a body, on any family.
    let p = map(vec![
        ("asserted_at", ms(1_000)),
        ("body", map(vec![("ratio", tag4(-1, 50))])),
    ]);
    let e = check_by_id("evidence:.suite:.kind:.cell:.prefix", "scores", &p).unwrap_err();
    assert_eq!(
        reason(&e),
        malformed_row::EDITION2_PAYLOAD_INVALID,
        "I3996 door"
    );
    let ok_p = map(vec![
        ("asserted_at", ms(1_000)),
        ("body", map(vec![("ratio", tag4(-1, 5))])),
    ]);
    check_by_id("evidence:.suite:.kind:.cell:.prefix", "scores", &ok_p).expect("I3996 ok");
}

/// I3997: the pair room is `community_id` (FINAL, CC).
#[test]
fn i3997_a_deferral_routes_by_community_id() {
    let room = id(244);
    for (fam, p) in [
        ("deferral:request", deferral_request()),
        ("deferral:response:{outcome}", approval()),
    ] {
        ok(
            fam,
            &with(&p, vec![("community_id", txt(&room))], &[]),
            "I3997 the pair room rides community_id",
        );
        bad(
            fam,
            &with(&p, vec![("room", txt(&room))], &[]),
            "I3997 there is no room member",
        );
    }
}

/// A `location_proof:v1` payload.
/// A valid `transport:canonical_rebind` payload: counted (no author), the
/// seat's new transit X-Wing key (1216 bytes), and the genesis bundle in force
/// it is counted over as `refs.head`.
fn canonical_rebind() -> Value {
    map(vec![
        ("asserted_at", ms(1_000)),
        ("transit_xwing_pubkey", Value::Bytes(vec![0x5a; 1216])),
        ("refs", refs(vec![("head", ref2(&[0x5b; 32]))])),
    ])
}

fn location_proof() -> Value {
    map(vec![
        ("asserted_at", ms(1_000)),
        ("author", txt(&id(245))),
        ("dimension", txt("location_proof:v1")),
        ("cell_id", txt("872830828ffffff")),
        ("cell_resolution", ms(7)),
        ("valid_until", ms(9_000)),
    ])
}

/// I3998: the location proof's list.
#[test]
fn i3998_a_location_proof() {
    let lp = "location_proof:{version}";
    ok(
        lp,
        &location_proof(),
        "I3998 cell_id, resolution 7, valid_until",
    );
    ok(
        lp,
        &with(
            &location_proof(),
            vec![("attestation_evidence", Value::Bytes(vec![1; 8]))],
            &[],
        ),
        "I3998 hardware evidence",
    );
    ok(
        lp,
        &with(&location_proof(), vec![], &["valid_until"]),
        "I3998 indefinite",
    );
    bad(
        lp,
        &with(&location_proof(), vec![("cell_resolution", ms(8))], &[]),
        "I3998 rough-only",
    );
    bad(
        lp,
        &with(
            &location_proof(),
            vec![("cell_id", txt("872830828FFFFFF"))],
            &[],
        ),
        "I3998 lowercase hex",
    );
    bad(
        lp,
        &with(&location_proof(), vec![], &["cell_id"]),
        "I3998 cell_id required",
    );
    bad(
        lp,
        &with(
            &location_proof(),
            vec![("subject_key_id", txt(&id(245)))],
            &[],
        ),
        "I3998 the subject is the sub, not a member",
    );
}

/// I3999: the decoder's exact inverse, and the body subtrees.
#[test]
fn i3999_a_decimal_reads_back_exactly() {
    use super::payloads::{body_number, is_body_member, json_number_of_decimal};
    use ciris_verify_core::namespace_match::family_id;
    for (text, back) in [
        ("0.5", "0.5"),
        ("1.25", "1.25"),
        ("-0.050", "-0.05"),
        ("12.50e-1", "1.25"),
        ("0.0001", "0.0001"),
        ("0.30000000000000004", "0.30000000000000004"),
    ] {
        let v = body_number(&num(text)).unwrap();
        let n = json_number_of_decimal(&v).unwrap_or_else(|| panic!("I3999 {text}"));
        assert_eq!(n.to_string(), back, "I3999 {text} reads back exactly");
        // And states again as the same decimal.
        assert_eq!(body_number(&n).unwrap(), v, "I3999 {text} round-trips");
    }
    assert!(
        json_number_of_decimal(&tag4(-1, 50)).is_none(),
        "I3999 not normalised"
    );
    assert!(
        json_number_of_decimal(&Value::Uint(2)).is_none(),
        "I3999 an integer is no decimal"
    );
    // The mapping reads a body's decimal as a JSON number.
    let a = super::ingest::attestation_of(
        &admitted(
            "evidence:.suite:.kind:.cell:.prefix",
            map(vec![
                ("asserted_at", ms(1_000)),
                ("body", map(vec![("ratio", tag4(-2, 125))])),
            ]),
        ),
        "federation",
    )
    .unwrap();
    assert_eq!(
        a.attestation_envelope["body"]["ratio"].to_string(),
        "1.25",
        "I3999 the mapping's body number"
    );
    assert!(is_body_member(
        "evidence:.suite:.kind:.cell:.prefix",
        "body"
    ));
    assert!(is_body_member(&family_id("hard_case:{kind}"), "hard_case"));
    assert!(!is_body_member(
        "evidence:.suite:.kind:.cell:.prefix",
        "hard_case"
    ));
    assert!(!is_body_member(&family_id("hard_case:{kind}"), "score"));
}

/// I4001: an eviction cites its voices' key records.
#[test]
fn i4001_an_occurrence_revocation_cites_its_voices() {
    let fam = "identity:occurrence_revocation";
    ok(
        fam,
        &occurrence_revocation(),
        "I4001 head + the voices' cites",
    );
    let uncited = with(
        &occurrence_revocation(),
        vec![("refs", refs(vec![("head", ref2(&[0x9e; 32]))]))],
        &[],
    );
    bad(fam, &uncited, "I4001 refs.also.cites is required");
    let one = with(
        &occurrence_revocation(),
        vec![(
            "refs",
            refs(vec![
                ("head", ref2(&[0x9e; 32])),
                (
                    "also",
                    map(vec![("cites", Value::Array(vec![ref2(&[0x9c; 32])]))]),
                ),
            ]),
        )],
        &[],
    );
    ok(fam, &one, "I4001 one voice, no binding: one cite");
    // The occurrence itself is unchanged: also.cites stays optional there.
    ok(
        "identity:occurrence",
        &occurrence(),
        "I4001 an occurrence needs no cites",
    );
}

// ---- chat answers (I4002) -------------------------------------------------

/// A chat reply: a message naming the message it answers in `refs.answers`.
fn chat_reply() -> Value {
    map(vec![
        ("asserted_at", ms(1_000)),
        ("author", txt(&id(250))),
        ("dimension", txt("chat:message:v1")),
        ("body", map(vec![("note", txt("agreed"))])),
        ("refs", refs(vec![("answers", ref2(&[0xa7; 32]))])),
    ])
}

/// A chat reaction (sealed, withdrawn by its author): it names its message
/// in `refs.answers`.
fn chat_reaction() -> Value {
    map(vec![
        ("asserted_at", ms(1_100)),
        ("author", txt(&id(250))),
        ("dimension", txt("chat:reaction:v1")),
        ("body", map(vec![("note", txt("+1"))])),
        ("refs", refs(vec![("answers", ref2(&[0xa7; 32]))])),
    ])
}

/// I4002: refs.answers on the chat family.
#[test]
fn i4002_a_chat_reply_and_reaction_name_their_message() {
    use super::payloads::check_by_id;
    use ciris_verify_core::namespace_match::family_id;
    let chat = family_id("chat:*");
    for (what, p) in [("reply", chat_reply()), ("reaction", chat_reaction())] {
        check_by_id(&chat, "scores", &p)
            .unwrap_or_else(|e| panic!("I4002 a chat {what} with refs.answers: {e}"));
        let names = super::names::names_of(&p).unwrap();
        assert_eq!(
            super::names::single(&names, "answers").map(|r| r.0),
            Some([0xa7; 32]),
            "I4002 the {what} names its message"
        );
    }
    // A reaction's withdrawal is a composer by its author: the composer rule.
    let withdraws = map(vec![
        ("asserted_at", ms(1_200)),
        ("author", txt(&id(250))),
        ("refs", refs(vec![("target", ref2(&[0xa9; 32]))])),
    ]);
    check_by_id(&chat, "withdraws", &withdraws).expect("I4002 the author withdraws a reaction");
}

/// I4003: a ledger balance is a body number, exact both ways.
#[test]
fn i4003_a_ledger_balance_is_an_exact_body_number() {
    use super::emit::payload_from_envelope;
    use super::payloads::is_body_member;
    use ciris_verify_core::namespace_match::family_id;
    let credits = family_id("credits:{domain}:{language}:{subject}");
    let expertise = family_id("expertise:{domain}:{language}");
    assert!(is_body_member(&credits, "balance"), "I4003 balance");
    assert!(is_body_member(&expertise, "expertise"), "I4003 expertise");
    let n = |t: &str| -> serde_json::Value { serde_json::from_str(t).unwrap() };
    for (text, want, back) in [
        ("12.5", tag4(-1, 125), "12.5"),
        ("7.25", tag4(-2, 725), "7.25"),
        ("3", Value::Uint(3), "3"),
        ("2.0", Value::Uint(2), "2"),
    ] {
        let env = serde_json::json!({
            "dimension": "credits:code:en:rust:v1",
            "score": n("0.5"),
            "balance": n(text),
        });
        let p = payload_from_envelope(&env, &credits, 7, None, &[])
            .unwrap_or_else(|e| panic!("I4003 {text}: the producer states it: {e:?}"));
        assert_eq!(
            p.get_text("balance"),
            Some(&want),
            "I4003 {text} on the wire"
        );
        assert_eq!(
            p.get_text("score"),
            Some(&Value::Uint(500_000)),
            "I4003 score stays fixed6"
        );
        let a = super::ingest::attestation_of(&admitted(&credits, p), "federation").unwrap();
        assert_eq!(
            a.attestation_envelope["balance"].to_string(),
            back,
            "I4003 {text} reads back exactly"
        );
    }
    // An expertise in [0, 1], a decimal.
    let env = serde_json::json!({ "dimension": "expertise:code:en:v1", "expertise": n("0.75") });
    let p = payload_from_envelope(&env, &expertise, 7, None, &[]).unwrap();
    assert_eq!(
        p.get_text("expertise"),
        Some(&tag4(-2, 75)),
        "I4003 expertise"
    );
    // Outside the ledger members a real is still refused.
    let env = serde_json::json!({ "dimension": "credits:code:en:rust:v1", "ratio": n("0.5") });
    assert!(
        payload_from_envelope(&env, &credits, 7, None, &[]).is_err(),
        "I4003 refused"
    );
}
