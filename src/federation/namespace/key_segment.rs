//! v62 (CC rc21, CC 3.1 "A shape beyond the class") — **a key written into a
//! family name is its BARE thumbprint.**
//!
//! An edition-2 key id is an identity-ref,
//! `urn:ietf:params:oauth:ckt:sha-256:<43 base64url>` (RFC 9679 §5.7; CC
//! 2.6.1.1). Payload members (`iss`, `author`, `sub`, role parties) carry the
//! full URN. Where a family name embeds a key, as `licensure:{authority_id}`
//! does, the `dimension` segment is the bare thumbprint: the 43 unpadded
//! base64url characters after the prefix, with no colon and zero trailing
//! bits. The edition-2 family label (-70002) is the TEMPLATE
//! (`licensure:.authority_id`), so the thumbprint appears only in the
//! payload's `dimension` member, where the namespace matcher reads it as a
//! verbatim, case-preserving value segment.
//!
//! This module is the ONE place that writes a key into a family name and
//! reads one back. Segment parsing stays plain `:`-splitting: a key segment
//! has no colon. CC rc21: a URN written where the key goes matches NO family
//! (the matcher's arity), so it names no key and falls through to the door's
//! normal answer for a dimension no family claims; a second spelling of a key
//! segment in a key-bearing position is malformed
//! ([`check_dimension_key_segments`]).
//!
//! The prefix is fixed, so [`segment_of`] and [`identity_ref_of`] are
//! inverse one-to-one maps.

use super::super::{malformed_row, Error};

/// `urn:ietf:params:oauth:ckt:sha-256:`.
pub use ciris_verify_core::edition2::IDENTITY_REF_PREFIX;

/// The length of a key segment: 32 bytes as unpadded base64url.
pub const KEY_SEGMENT_LEN: usize = 43;

/// The last characters a 43-char base64url string may end in when it
/// encodes exactly 32 bytes (zero trailing bits): one spelling per key.
const ZERO_TRAILING_BITS_LAST: &[u8] = b"AEIMQUYcgkosw048";

/// Is `s` a key segment: exactly 43 base64url characters (`[A-Za-z0-9_-]`)
/// with zero trailing bits?
#[must_use]
pub fn is_key_segment(s: &str) -> bool {
    let b = s.as_bytes();
    b.len() == KEY_SEGMENT_LEN
        && b.iter()
            .all(|c| c.is_ascii_alphanumeric() || *c == b'-' || *c == b'_')
        && ZERO_TRAILING_BITS_LAST.contains(&b[KEY_SEGMENT_LEN - 1])
}

/// The key segment of an identity-ref: the 43 characters after
/// [`IDENTITY_REF_PREFIX`]. `None` when `identity_ref` is not a well-formed
/// identity-ref.
#[must_use]
pub fn segment_of(identity_ref: &str) -> Option<String> {
    // v62.0.0 (GID-prod; CIRISConstitution "THE DERIVED GROUP ID") — a
    // group-ref in a key-bearing position (`moderation_track_record:
    // {community_key_id}`) carries "the 43 characters after the prefix", as a
    // key carries its 43: the same segment shape the registry pins.
    if let Some(seg) = identity_ref
        .strip_prefix(crate::federation::edition2::group_id::GROUP_REF_PREFIX)
        .filter(|s| is_key_segment(s))
    {
        return Some(seg.to_owned());
    }
    if !ciris_verify_core::edition2::is_identity_ref(identity_ref) {
        return None;
    }
    identity_ref
        .strip_prefix(IDENTITY_REF_PREFIX)
        .filter(|s| is_key_segment(s))
        .map(str::to_owned)
}

/// The identity-ref a key segment names. `None` when `segment` is not a key
/// segment.
#[must_use]
pub fn identity_ref_of(segment: &str) -> Option<String> {
    is_key_segment(segment).then(|| format!("{IDENTITY_REF_PREFIX}{segment}"))
}

/// **A key id as a family-name segment**: an identity-ref is written as its
/// bare segment; any other id (an earlier-form key id, while those doors
/// are open) is written as itself.
#[must_use]
pub fn family_param_of(key_id: &str) -> std::borrow::Cow<'_, str> {
    match segment_of(key_id) {
        Some(s) => std::borrow::Cow::Owned(s),
        None => std::borrow::Cow::Borrowed(key_id),
    }
}

/// **A family-name segment as a key id**: a key segment is read as the
/// identity-ref it names; any other segment (an earlier-form key id) is read
/// as itself. The inverse of [`family_param_of`].
#[must_use]
pub fn key_id_of_param(segment: &str) -> std::borrow::Cow<'_, str> {
    match identity_ref_of(segment) {
        Some(r) => std::borrow::Cow::Owned(r),
        None => std::borrow::Cow::Borrowed(segment),
    }
}

/// The families whose `{…}` parameter names a KEY: `(registry family,
/// the placeholder that binds the key)`. A dimension is in a key-bearing
/// position only when the namespace matcher resolves it to one of these
/// (CC rc21: a URN written where the key goes matches NO family, so it is not
/// in a key-bearing position at all).
pub const KEY_BEARING_FAMILIES: &[(&str, &str)] = &[
    ("licensure:{authority_id}", "authority_id"),
    (
        "moderation_track_record:{community_key_id}",
        "community_key_id",
    ),
];

/// The scope tokens whose parameter after the stem names a KEY (CC rc21 lists
/// `infra:attest:licensure:{authority_id}`). The bare parent
/// (`infra:attest:licensure`) carries no parameter and is not matched.
pub const KEY_BEARING_SCOPE_STEMS: &[&str] = &["infra:attest:licensure:"];

/// **The key bound by a key-bearing family**: the bound value when the
/// namespace matcher resolves `dimension` to one of
/// [`KEY_BEARING_FAMILIES`] (whatever refusal the matcher also reports, so
/// a version-less `licensure:acme` still binds `acme`); `None` otherwise,
/// including for a URN written where the key goes (no family claims it).
#[must_use]
pub fn bound_key_param(dimension: &str) -> Option<(&'static str, String)> {
    let m = super::matcher::match_family(dimension);
    let family = m.family?;
    let (_, bind) = KEY_BEARING_FAMILIES.iter().find(|(f, _)| *f == family)?;
    m.binds.get(*bind).map(|v| (family, v.clone()))
}

/// A key segment the probe below writes into a key position: 43 `A`s, zero
/// trailing bits (CC's own `SAMPLE_THUMBPRINT`, `tools/cc_namespace_match.py`
/// at v1.0-rc21-wire).
const SAMPLE_KEY_SEGMENT: &str = "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA";

/// v62.0.0 (R1c; CC v1.0-rc21-wire e6fd7c60, CC 3.1 "A shape beyond the
/// class") — **is the key position's own pattern the ONLY grammar fault
/// the matcher finds in `dimension`?**
///
/// From rc21-wire the registry pins each [`KEY_BEARING_FAMILIES`] placeholder
/// to a bare thumbprint (`segments[].pattern`
/// `^[A-Za-z0-9_-]{42}[AEIMQUYcgkosw048]$`), so the one matcher answers
/// `namespace_dimension_case_malformed` for an earlier-form key id there
/// (`licensure:acme:v1`). Whether such an id is refused is this module's
/// switch ([`check_dimension_key_segments`]: refused once the earlier-form
/// doors are shut, still a key id until then), not the case rule's. This
/// answers `true` when the dimension resolves to a key-bearing family, its
/// key parameter is not a key segment, and the same dimension with a key
/// segment written in that position earns no case or vocabulary refusal:
/// every other segment stands on its own grammar.
#[must_use]
pub fn only_the_key_pattern_refuses(dimension: &str) -> bool {
    use super::matcher::{match_family, Refusal};
    let Some((_, param)) = bound_key_param(dimension) else {
        return false;
    };
    if is_key_segment(&param) || param.contains(':') {
        return false;
    }
    let mut replaced = false;
    let probe: Vec<&str> = dimension
        .split(':')
        .enumerate()
        .map(|(i, p)| {
            if i > 0 && !replaced && p == param {
                replaced = true;
                SAMPLE_KEY_SEGMENT
            } else {
                p
            }
        })
        .collect();
    replaced
        && !matches!(
            match_family(&probe.join(":")).refusal,
            Some(Refusal::CaseMalformed | Refusal::VocabValueUnregistered)
        )
}

/// **The key-segment gate** (pure; every door). In a key-bearing position, a
/// segment that is not a key segment is refused as [`Error::MalformedRow`]
/// with [`malformed_row::ENVELOPE_MEMBER_INVALID`]:
///
/// - a segment shaped like a key segment (43 base64url characters) with
///   non-zero trailing bits, which is a second spelling of a key;
/// - once the earlier-form doors are shut
///   ([`EARLIER_FORM_DOORS_SHUT`](crate::federation::edition2::door::EARLIER_FORM_DOORS_SHUT)),
///   ANY segment that is not a key segment (a b64url of the wrong length, an
///   earlier-form key id). Until then, an earlier-form key id is still a key
///   id.
///
/// A `dimension` is in a key-bearing position only when it RESOLVES to a
/// [`KEY_BEARING_FAMILIES`] family ([`bound_key_param`]). CC rc21: an
/// identity-ref URN written where the key goes matches no family. That is
/// not this gate's refusal: the dimension falls through to the door's
/// normal answer for a dimension no family claims.
///
/// Each `scope` token of the envelope (a `delegates_to`'s scope, bare string
/// or array) is checked against [`KEY_BEARING_SCOPE_STEMS`] by stem: the
/// parameter is the segment right after the stem. There only the
/// trailing-bits spelling (a bytes check) is refused: a URN or any other
/// non-segment in a caveat's key position matches no key, so the caveat
/// grants nothing (it narrows to empty), before and after CP2 alike.
///
/// # Errors
///
/// [`Error::MalformedRow`] as above.
pub fn check_dimension_key_segments(envelope: &serde_json::Value) -> Result<(), Error> {
    if let Some(dimension) = envelope
        .get("dimension")
        .and_then(serde_json::Value::as_str)
    {
        if let Some((family, param)) = bound_key_param(dimension) {
            check_key_param(
                "dimension",
                dimension,
                family,
                &param,
                crate::federation::edition2::door::EARLIER_FORM_DOORS_SHUT,
            )?;
        }
    }
    // A `delegates_to`'s `scope`: a bare token or an array of tokens.
    let tokens: Vec<&str> = match envelope.get("scope") {
        Some(serde_json::Value::String(s)) => vec![s.as_str()],
        Some(serde_json::Value::Array(a)) => a.iter().filter_map(|v| v.as_str()).collect(),
        _ => Vec::new(),
    };
    for token in tokens {
        for stem in KEY_BEARING_SCOPE_STEMS {
            if let Some(rest) = token.strip_prefix(stem) {
                let param = rest.split(':').next().unwrap_or("");
                // A non-segment in a caveat's key position matches nothing
                // (the caveat grants nothing): never a refusal.
                check_key_param("scope", token, stem, param, false)?;
            }
        }
    }
    Ok(())
}

/// One key-bearing parameter `param` of `text` (envelope member `member`,
/// position `position`): the rules [`check_dimension_key_segments`] states.
/// `non_segment_refused`: whether a non-segment is refused (a dimension once
/// the earlier-form doors are shut; never a scope caveat).
fn check_key_param(
    member: &str,
    text: &str,
    position: &str,
    param: &str,
    non_segment_refused: bool,
) -> Result<(), Error> {
    if is_key_segment(param) {
        return Ok(());
    }
    let refuse = |detail: String| {
        Err(Error::malformed_row(
            "attestation",
            malformed_row::ENVELOPE_MEMBER_INVALID,
            format!("`{member}` {text:?}: {detail} (CC 3.1, rc21)"),
        ))
    };
    let key_shaped = param.len() == KEY_SEGMENT_LEN
        && param
            .bytes()
            .all(|c| c.is_ascii_alphanumeric() || c == b'-' || c == b'_');
    if key_shaped {
        return refuse(format!(
            "{param:?} is not a key segment: its last character carries trailing bits"
        ));
    }
    if non_segment_refused {
        return refuse(format!(
            "{param:?} in `{position}` is not a key segment (43 base64url characters, zero \
             trailing bits)"
        ));
    }
    Ok(())
}

#[cfg(test)]
pub(crate) mod tests {
    use super::*;

    /// A well-formed key segment: 42×`fill` then `A` (zero trailing bits).
    pub(crate) fn segment(fill: char) -> String {
        let mut s: String = std::iter::repeat_n(fill, KEY_SEGMENT_LEN - 1).collect();
        s.push('A');
        assert!(is_key_segment(&s), "{s}");
        s
    }

    /// The identity-ref of [`segment`]`(fill)`.
    pub(crate) fn kid(fill: char) -> String {
        identity_ref_of(&segment(fill)).expect("a key segment names an identity-ref")
    }

    /// **I2960** — `is_key_segment`: 43 base64url characters with zero
    /// trailing bits, and nothing else.
    #[test]
    fn i2960_a_key_segment_has_one_spelling() {
        assert!(is_key_segment(&segment('Q')));
        assert!(is_key_segment(&segment('-')));
        assert!(is_key_segment(&segment('_')));
        let s = segment('Q');
        assert!(!is_key_segment(&s[..42]), "42 characters");
        assert!(!is_key_segment(&format!("{s}A")), "44 characters");
        let mut bits = s.clone();
        bits.pop();
        bits.push('B');
        assert!(!is_key_segment(&bits), "non-zero trailing bits");
        let mut pad = s.clone();
        pad.pop();
        pad.push('=');
        assert!(!is_key_segment(&pad), "padding");
        let mut plus = s.clone();
        plus.replace_range(0..1, "+");
        assert!(!is_key_segment(&plus), "standard base64");
        assert!(!is_key_segment(&kid('Q')), "the URN is not a segment");
        assert!(!is_key_segment(&"ab".repeat(32)), "64 hex");
        assert!(!is_key_segment("acme"));
        assert!(!is_key_segment(""));
    }

    /// **I2961** — `segment_of` and `identity_ref_of` are inverse one-to-one
    /// maps, and agree with Verify's identity-ref grammar.
    #[test]
    fn i2961_segment_and_identity_ref_are_inverse() {
        for fill in ['Q', 'g', '-', '_', '0', 'z'] {
            let seg = segment(fill);
            let r = identity_ref_of(&seg).unwrap();
            assert!(ciris_verify_core::edition2::is_identity_ref(&r), "{r}");
            assert_eq!(segment_of(&r).as_deref(), Some(seg.as_str()));
            assert_eq!(identity_ref_of(&segment_of(&r).unwrap()), Some(r.clone()));
            assert_eq!(family_param_of(&r), seg.as_str());
            assert_eq!(key_id_of_param(&seg), r.as_str());
        }
        // A real thumbprint round-trips through Verify's own identity_ref.
        let thumb = [0x5au8; 32];
        let r = ciris_verify_core::edition2::identity_ref(&thumb);
        let seg = segment_of(&r).expect("Verify's identity-ref has a segment");
        assert!(is_key_segment(&seg));
        assert_eq!(identity_ref_of(&seg), Some(r));
        // Not identity-refs / not segments.
        assert_eq!(segment_of("acme"), None);
        assert_eq!(
            segment_of(&segment('Q')),
            None,
            "a bare segment is not a ref"
        );
        assert_eq!(identity_ref_of("acme"), None);
        assert_eq!(identity_ref_of(&kid('Q')), None, "a ref is not a segment");
        // Earlier-form ids pass through both directions unchanged.
        assert_eq!(family_param_of("acme"), "acme");
        assert_eq!(key_id_of_param("acme"), "acme");
    }

    /// **I2962** — the key-segment gate, on `dimension` and on `scope`
    /// tokens: a bare segment admits; a key-shaped segment with trailing bits
    /// in a key-bearing position is a malformed row; an earlier-form id there
    /// follows `EARLIER_FORM_DOORS_SHUT`. CC rc21: a URN written where the key
    /// goes matches NO family, binds no key, and is not this gate's refusal.
    /// In a scope caveat only trailing bits are refused; a URN or other
    /// non-segment there matches nothing, before and after CP2.
    /// Other families and rows without a dimension are untouched.
    #[test]
    fn i2962_the_key_segment_gate() {
        let dim = |d: String| serde_json::json!({ "dimension": d });
        let malformed = |r: Result<(), Error>, what: &str| match r {
            Err(Error::MalformedRow { reason, .. }) => {
                assert_eq!(reason, malformed_row::ENVELOPE_MEMBER_INVALID, "{what}");
            }
            other => panic!("{what}: expected a malformed row, got {other:?}"),
        };
        let seg = segment('Q');
        check_dimension_key_segments(&dim(format!("licensure:{seg}:v1"))).expect("bare");
        check_dimension_key_segments(&dim(format!("licensure:{seg}"))).expect("bare, no tail");
        check_dimension_key_segments(&dim(format!("moderation_track_record:{seg}:v1")))
            .expect("bare");
        // CC rc21: a URN written where the key goes matches NO family, so it
        // is in no key-bearing position: not this gate's refusal (the door's
        // normal unclaimed-dimension answer applies).
        let urn_dim = format!("licensure:{}:v1", kid('Q'));
        assert_eq!(bound_key_param(&urn_dim), None, "a URN binds no key");
        assert_eq!(
            crate::federation::namespace::matcher::match_family(&urn_dim).family,
            None,
            "a URN in the authority position matches no family"
        );
        check_dimension_key_segments(&dim(urn_dim)).expect("no family, no key position");
        check_dimension_key_segments(&dim(format!("credits:rust:en:{}:v1", kid('Q'))))
            .expect("a URN elsewhere is not this gate's business");
        assert_eq!(
            bound_key_param(&format!("licensure:{seg}:v1")),
            Some(("licensure:{authority_id}", seg.clone()))
        );
        assert_eq!(
            bound_key_param("licensure:acme"),
            Some(("licensure:{authority_id}", "acme".to_owned())),
            "a version-less dimension still binds"
        );
        let mut bits = seg.clone();
        bits.pop();
        bits.push('B');
        malformed(
            check_dimension_key_segments(&dim(format!("licensure:{bits}:v1"))),
            "trailing bits",
        );
        let earlier = check_dimension_key_segments(&dim("licensure:acme:v1".to_owned()));
        if crate::federation::edition2::door::EARLIER_FORM_DOORS_SHUT {
            malformed(earlier, "an earlier-form id once the doors are shut");
        } else {
            earlier.expect("an earlier-form id while the doors are open");
        }
        check_dimension_key_segments(&dim("credits:rust:en:alice:v1".to_owned())).unwrap();

        // Scope tokens: the key caveat names its key by the bare segment.
        let scope = |v: serde_json::Value| serde_json::json!({ "scope": v });
        check_dimension_key_segments(&scope(serde_json::json!([
            "infra:attest",
            "infra:attest:licensure",
            format!("infra:attest:licensure:{seg}"),
            format!("infra:attest:licensure:{seg}:board"),
        ])))
        .expect("bare segment caveats");
        check_dimension_key_segments(&scope(serde_json::json!(format!(
            "infra:attest:licensure:{seg}"
        ))))
        .expect("a bare-string scope");
        // A URN (or any non-segment) in a caveat's key position matches no
        // key: never a refusal, whatever the earlier-form switch says.
        check_dimension_key_segments(&scope(serde_json::json!([
            "infra:attest",
            format!("infra:attest:licensure:{}", kid('Q')),
            format!("infra:attest:licensure:{}", &seg[..20]),
            "infra:attest:licensure:acme",
        ])))
        .expect("a non-segment caveat matches nothing, never a refusal");
        malformed(
            check_dimension_key_segments(&scope(serde_json::json!(format!(
                "infra:attest:licensure:{bits}"
            )))),
            "trailing bits in a scope caveat",
        );
        check_dimension_key_segments(&serde_json::json!({ "x": 1 })).unwrap();
    }
}
