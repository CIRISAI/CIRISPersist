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

use ciris_verify_core::cde::Value;

use super::door_invariants::fixture::*;
use super::payloads::{check, render_markdown, FAMILIES};
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

fn widening(extra: Vec<(&str, Value)>) -> Value {
    let (g, mbr) = (key(110), key(111));
    let mut v = vec![
        ("asserted_at", ms(1_000)),
        ("dimension", Value::Text("membership:widening:v1".into())),
        ("group_kind", Value::Text("community".into())),
        ("group", Value::Text(iref(&g))),
        ("member", Value::Text(iref(&mbr))),
        ("joined_at", ms(900)),
        ("effective_at", ms(1_000)),
    ];
    v.extend(extra);
    map(v)
}

#[test]
fn i2102_check_reads_the_member_lists() {
    let fam = "membership:{stage}";
    check(fam, &widening(vec![])).expect("I2102 required members");
    check(
        fam,
        &widening(vec![("role", Value::Text("moderator".into()))]),
    )
    .expect("I2102 optional member");
    let bad = |p: Value, why: &str| {
        let e = check(fam, &p).unwrap_err();
        assert_eq!(
            reason(&e),
            malformed_row::EDITION2_PAYLOAD_INVALID,
            "I2102 {why}"
        );
    };
    // Missing a required member.
    let Value::Map(mut entries) = widening(vec![]) else {
        unreachable!()
    };
    entries.retain(|(k, _)| k.as_text() != Some("effective_at"));
    bad(Value::Map(entries), "missing");
    // `joined_at` is required for a widening, `removed_at` is not.
    let Value::Map(mut entries) = widening(vec![]) else {
        unreachable!()
    };
    entries.retain(|(k, _)| k.as_text() != Some("joined_at"));
    bad(Value::Map(entries), "conditional");
    // Wrong types.
    bad(widening(vec![("reason", ms(3))]), "tstr");
    let Value::Map(mut entries) = widening(vec![]) else {
        unreachable!()
    };
    for (k, v) in &mut entries {
        if k.as_text() == Some("member") {
            *v = Value::Text("alias-not-an-identity-ref".into());
        }
    }
    bad(Value::Map(entries), "identity-ref");
    // An unlisted member.
    bad(widening(vec![("persist_row_hash", ms(1))]), "unlisted");
    // An unsorted set.
    let (a, b) = (iref(&key(112)), iref(&key(113)));
    let (lo, hi) = if a < b { (a, b) } else { (b, a) };
    check(
        fam,
        &widening(vec![(
            "witness_set",
            Value::Array(vec![Value::Text(lo.clone()), Value::Text(hi.clone())]),
        )]),
    )
    .expect("I2102 sorted set");
    bad(
        widening(vec![(
            "witness_set",
            Value::Array(vec![Value::Text(hi), Value::Text(lo)]),
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

#[test]
fn i2102_a_required_refs_role_is_checked() {
    let g = key(114);
    let lineage = |refs: Option<Value>| {
        let mut v = vec![
            ("asserted_at", ms(1_000)),
            ("author", Value::Text(iref(&g))),
            ("dimension", Value::Text("cosign:lineage_head:v1".into())),
            ("lineage", Value::Text(iref(&g))),
            ("head_asserted_at", ms(900)),
        ];
        if let Some(r) = refs {
            v.push(("refs", r));
        }
        map(v)
    };
    check(
        "cosign:{state}",
        &lineage(Some(map(vec![("head", ref2(&[0x44; 32]))]))),
    )
    .expect("I2102 head named");
    let e = check("cosign:{state}", &lineage(None)).unwrap_err();
    assert_eq!(
        reason(&e),
        malformed_row::EDITION2_PAYLOAD_INVALID,
        "I2102 refs.head"
    );
}
