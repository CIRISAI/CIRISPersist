//! # The media Source struct — `media := { digest, size, format, … }`
//!
//! v45.0.0 (CIRISPersist#871, `FSD/MEDIA_SOURCE.md` §3–§4; CC 3.3.13 the
//! multimedia Source struct, CC 5.3.2.5 size checked first, CC 5.3.2.6 the
//! render tier is receiver policy).
//!
//! A row that describes a blob carries a typed `media` member beside the
//! `evidence_refs[]` that cites the blob. Before this module nothing bounded
//! the PULL side of a blob: a puller doing a `ContentFetch` had no declared
//! length, read to EOF, and hashed afterwards — so a lying or hostile holder
//! could stream unbounded bytes at it before the full-SHA check could refuse
//! (AV-88). And nothing said what a media descriptor WAS, so a producer could
//! write a `safe: true` bit into it and a reader could believe it. This
//! module is the ONE place the struct is parsed, the ONE list of what it may
//! carry, and the door gate that refuses a malformed struct by member name.
//!
//! ## The grammar
//!
//! ```text
//! media := {
//!   digest              hex64        REQUIRED; == an entry of evidence_refs[]
//!   size                u64 > 0      REQUIRED (CC 3.3.13 / 5.3.2.5)
//!   format              essence      REQUIRED; RFC 6838 `type/subtype`, lowercase, no parameters
//!   codec               token        REQUIRED iff format ∈ {video/mp4, audio/mp4}; RFC 6381 family
//!   width, height       u32 > 0      optional layout hints
//!   duration_ms         u64          optional
//!   placeholder         base64       optional; thumbhash, ≤ 64 decoded bytes
//!   name                string       optional; display only, RFC 6266 §4.3 sanitised
//!   content_digest      hex64        optional; the plaintext hash when digest is over ciphertext
//!   derived_from        hex64        optional; this blob is a rendition of that one (≠ digest)
//!   captions            hex64        optional; a separate text/vtt blob; == an entry of evidence_refs[]
//!   digital_source_type string       optional; the closed IPTC set
//!   init_segment        hex64        optional; live stream: the per-epoch fMP4 init segment
//! }
//! hex64   := [0-9a-f]{64}
//! essence := restricted-name "/" restricted-name       (RFC 6838 §4.2, lowercase)
//! restricted-name := [a-z0-9][a-z0-9!#$&^_.+-]{0,126}
//! token   := [a-zA-Z0-9]+ ( "." [a-zA-Z0-9]+ )*         (RFC 6381 family: avc1.42E01E, mp4a.40.2, opus)
//! ```
//!
//! The struct is **closed**: an unknown member is refused by name. The
//! constitution's MUST-NOT list — `safe`, `renderable`, `tier`, `crypto_tier`,
//! `render_tier` — is refused by name with the CC 5.3.2.6 reason, not as a
//! generic unknown: the render tier is receiver policy computed from
//! verified, sniffed bytes, never a claim in the descriptor. Persist
//! validates the GRAMMAR and nothing more — it never sniffs bytes, never
//! compares the sniffed essence to `format`, and never decides a tier. Those
//! are the node's (CIRISServer#614) and the client's (#615).
//!
//! ## Why every refusal names a member
//!
//! A door refusal is read by a producer with an envelope in hand. "invalid
//! media" tells them nothing; "media source member `size` refused: must be
//! positive" tells them what to fix. [`MediaSourceError`] therefore always carries
//! the member, and the parser is written over the raw object — member by
//! member, in declaration order — rather than through a derived
//! `Deserialize`, whose type errors do not name the field.
//! [`MediaSource`]'s `Deserialize` impl goes THROUGH [`parse_media_source`],
//! so there is exactly one parser and no shape a derive would admit that the
//! door would refuse.
//!
//! ## `size` on the holder claim
//!
//! A `holds_bytes:*` claim is a one-member descriptor: `size` is REQUIRED on
//! it too (FSD §4), checked by the same positive-integer rule
//! ([`holds_bytes_claim_size`]), refused with the same kind. The puller caps
//! its read at that number BEFORE hashing (AV-88); a holder whose claimed size
//! disagrees with the author's descriptor is refused by the puller (AV-89) —
//! [`HolderClaim`] is what the sized holder read returns so it can compare.

use serde::{Deserialize, Serialize};
use serde_json::Value;

/// The envelope member that carries the struct.
pub const MEDIA_MEMBER: &str = "media";
/// The envelope member that cites blobs — bare sha256 strings (CC 3.3.13),
/// the reading `admission::envelope_binds_content` has always used.
pub const EVIDENCE_REFS_MEMBER: &str = "evidence_refs";
/// The size member, on the struct and on the `holds_bytes` claim alike.
pub const SIZE_MEMBER: &str = "size";

/// Every member the struct may carry, in declaration order. Anything else is
/// refused by name.
pub const KNOWN_MEMBERS: [&str; 14] = [
    "digest",
    "size",
    "format",
    "codec",
    "width",
    "height",
    "duration_ms",
    "placeholder",
    "name",
    "content_digest",
    "derived_from",
    "captions",
    "digital_source_type",
    "init_segment",
];

/// CC 3.3.13's MUST-NOT list: a `safe` / `renderable` / tier bit in the
/// descriptor. Refused with the CC 5.3.2.6 reason, checked BEFORE anything
/// else so the refusal names the rule rather than "unknown member".
pub const FORBIDDEN_MEMBERS: [&str; 5] =
    ["safe", "renderable", "tier", "crypto_tier", "render_tier"];

/// The formats whose bytes cannot be interpreted without a codec string
/// (an MP4 container says nothing about what is inside it).
pub const CODEC_REQUIRED_FORMATS: [&str; 2] = ["video/mp4", "audio/mp4"];

/// The IPTC Digital Source Type vocabulary, closed.
pub const DIGITAL_SOURCE_TYPES: [&str; 8] = [
    "trainedAlgorithmicMedia",
    "compositeWithTrainedAlgorithmicMedia",
    "compositeSynthetic",
    "algorithmicallyEnhanced",
    "humanEdits",
    "digitalCapture",
    "screenCapture",
    "virtualRecording",
];

/// `placeholder` decodes to at most this many bytes (a thumbhash is ~25).
pub const PLACEHOLDER_MAX_DECODED_BYTES: usize = 64;
/// The longest standard base64 encoding of [`PLACEHOLDER_MAX_DECODED_BYTES`]
/// bytes, padding included — checked before decoding (cheapest first).
const PLACEHOLDER_MAX_ENCODED_LEN: usize = PLACEHOLDER_MAX_DECODED_BYTES.div_ceil(3) * 4;
/// `name` is at most this many bytes (RFC 6266 §4.3 display-name hygiene).
pub const NAME_MAX_BYTES: usize = 255;
/// Each side of an RFC 6838 restricted-name is at most this long.
const RESTRICTED_NAME_MAX_LEN: usize = 127;

/// The parsed struct. Construct one only through [`parse_media_source`] (or
/// the `Deserialize` impl, which is the same parser): every field here has
/// passed the grammar.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct MediaSource {
    /// The sha256 of the blob's bytes, 64 lowercase hex characters. The row
    /// must cite it in `evidence_refs[]` ([`check_media_source`]).
    pub digest: String,
    /// The blob's byte length, > 0. The puller's read cap (CC 5.3.2.5).
    pub size: u64,
    /// RFC 6838 essence, lowercase `type/subtype`, no parameters.
    pub format: String,
    /// RFC 6381-family codec token; required iff [`CODEC_REQUIRED_FORMATS`].
    #[serde(skip_serializing_if = "Option::is_none")]
    pub codec: Option<String>,
    /// Layout hint, > 0 when present.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub width: Option<u32>,
    /// Layout hint, > 0 when present.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub height: Option<u32>,
    /// Duration in milliseconds.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub duration_ms: Option<u64>,
    /// Standard base64 thumbhash, ≤ [`PLACEHOLDER_MAX_DECODED_BYTES`] decoded.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub placeholder: Option<String>,
    /// Display-only name, RFC 6266 §4.3 sanitised. Never a path.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub name: Option<String>,
    /// The plaintext hash when `digest` is over ciphertext (sealed scopes).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub content_digest: Option<String>,
    /// The original this blob is a rendition of; never equal to `digest`.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub derived_from: Option<String>,
    /// The sha256 of a separate `text/vtt` blob; the row must cite it too.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub captions: Option<String>,
    /// One of [`DIGITAL_SOURCE_TYPES`].
    #[serde(skip_serializing_if = "Option::is_none")]
    pub digital_source_type: Option<String>,
    /// Live stream (CC 3.3.13 Phase 2): the sha256 of the per-epoch fMP4
    /// init segment (`ftyp` + `moov`).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub init_segment: Option<String>,
}

impl<'de> Deserialize<'de> for MediaSource {
    /// The ONE parser: a `MediaSource` deserialized from any source has
    /// passed [`parse_media_source`], so a derive-shaped hole (`size: 0`, an
    /// unknown member, an uppercase `format`) cannot be admitted by
    /// deserializing around the door.
    fn deserialize<D: serde::Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        let value = Value::deserialize(deserializer)?;
        parse_media_source(&value).map_err(serde::de::Error::custom)
    }
}

/// Why the struct did not parse: WHICH member, and why. The member is always
/// present so a door refusal tells the producer exactly what to fix.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct MediaSourceError {
    /// The offending member — a struct member, one of [`FORBIDDEN_MEMBERS`],
    /// an unknown key verbatim, or `media` itself when the member is not an
    /// object.
    pub member: String,
    /// The rule it broke, in words.
    pub reason: String,
}

impl std::fmt::Display for MediaSourceError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "media source member `{}`: {}", self.member, self.reason)
    }
}

impl std::error::Error for MediaSourceError {}

impl From<MediaSourceError> for super::Error {
    fn from(e: MediaSourceError) -> Self {
        super::Error::MediaSourceInvalid {
            member: e.member,
            reason: e.reason,
        }
    }
}

/// One sized holder, as the sized holder read returns it: WHO claims to hold
/// the bytes and HOW MANY bytes the claim says. A puller compares `size`
/// against the author's descriptor before fetching (AV-89).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct HolderClaim {
    /// The holder's key id — the `attesting_key_id` of its `holds_bytes` row.
    pub key_id: String,
    /// The byte length the holder's signed claim declares.
    pub size: u64,
}

fn refuse(member: &str, reason: impl Into<String>) -> MediaSourceError {
    MediaSourceError {
        member: member.to_owned(),
        reason: reason.into(),
    }
}

/// A short noun for the JSON shape a member actually had, for reasons like
/// "expected a string, got a number".
fn shape_of(v: &Value) -> &'static str {
    match v {
        Value::Null => "null",
        Value::Bool(_) => "a boolean",
        Value::Number(_) => "a number",
        Value::String(_) => "a string",
        Value::Array(_) => "an array",
        Value::Object(_) => "an object",
    }
}

/// `[0-9a-f]{64}` — the one spelling of a sha256 on the wire.
fn is_hex64(s: &str) -> bool {
    s.len() == 64
        && s.bytes()
            .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
}

/// RFC 6838 §4.2 restricted-name, lowercase only:
/// `[a-z0-9][a-z0-9!#$&^_.+-]{0,126}`.
fn is_restricted_name(s: &str) -> bool {
    let mut bytes = s.bytes();
    let Some(first) = bytes.next() else {
        return false;
    };
    s.len() <= RESTRICTED_NAME_MAX_LEN
        && (first.is_ascii_lowercase() || first.is_ascii_digit())
        && bytes.all(|b| b.is_ascii_lowercase() || b.is_ascii_digit() || b"!#$&^_.+-".contains(&b))
}

/// RFC 6838 essence: exactly one `/`, a restricted-name on each side.
fn is_media_essence(s: &str) -> bool {
    match s.split_once('/') {
        Some((t, sub)) => is_restricted_name(t) && is_restricted_name(sub),
        None => false,
    }
}

/// RFC 6381-family token: `[a-zA-Z0-9]+(\.[a-zA-Z0-9]+)*`.
fn is_codec_token(s: &str) -> bool {
    !s.is_empty()
        && s.split('.')
            .all(|seg| !seg.is_empty() && seg.bytes().all(|b| b.is_ascii_alphanumeric()))
}

/// The base64 engine `placeholder` is read with: the standard alphabet,
/// padding optional on decode (a producer may or may not pad a thumbhash).
const PLACEHOLDER_B64: base64::engine::GeneralPurpose = base64::engine::GeneralPurpose::new(
    &base64::alphabet::STANDARD,
    base64::engine::GeneralPurposeConfig::new()
        .with_decode_padding_mode(base64::engine::DecodePaddingMode::Indifferent),
);

/// The positive-integer rule shared by the struct's `size` and the
/// `holds_bytes` claim's `size`: present, a JSON number, an integer, > 0.
/// `required` is the reason given when the member is absent.
fn positive_size(member: &str, v: Option<&Value>, required: &str) -> Result<u64, MediaSourceError> {
    let v = v.ok_or_else(|| refuse(member, required))?;
    let n = match v {
        Value::Number(n) => n,
        other => {
            return Err(refuse(
                member,
                format!(
                    "must be a positive integer (a JSON number), got {}",
                    shape_of(other)
                ),
            ))
        }
    };
    let size = n.as_u64().ok_or_else(|| {
        refuse(
            member,
            format!("must be a positive integer (no sign, no fraction, ≤ 2^64-1), got {n}"),
        )
    })?;
    if size == 0 {
        return Err(refuse(member, "must be > 0: a blob has bytes, got 0"));
    }
    Ok(size)
}

fn required_str<'a>(
    obj: &'a serde_json::Map<String, Value>,
    member: &str,
    required: &str,
) -> Result<&'a str, MediaSourceError> {
    match obj.get(member) {
        None => Err(refuse(member, required)),
        Some(Value::String(s)) => Ok(s.as_str()),
        Some(other) => Err(refuse(
            member,
            format!("must be a string, got {}", shape_of(other)),
        )),
    }
}

fn optional_str<'a>(
    obj: &'a serde_json::Map<String, Value>,
    member: &str,
) -> Result<Option<&'a str>, MediaSourceError> {
    match obj.get(member) {
        None => Ok(None),
        Some(Value::String(s)) => Ok(Some(s.as_str())),
        Some(other) => Err(refuse(
            member,
            format!("must be a string, got {}", shape_of(other)),
        )),
    }
}

fn optional_hex64(
    obj: &serde_json::Map<String, Value>,
    member: &str,
    what: &str,
) -> Result<Option<String>, MediaSourceError> {
    match optional_str(obj, member)? {
        None => Ok(None),
        Some(s) if is_hex64(s) => Ok(Some(s.to_owned())),
        Some(s) => Err(refuse(
            member,
            format!("must be {what}: a sha256 as 64 lowercase hex characters, got `{s}`"),
        )),
    }
}

/// An optional unsigned integer member with an inclusive upper bound and a
/// minimum (`min` is 1 for a layout hint, 0 for a duration).
fn optional_uint(
    obj: &serde_json::Map<String, Value>,
    member: &str,
    min: u64,
    max: u64,
) -> Result<Option<u64>, MediaSourceError> {
    let Some(v) = obj.get(member) else {
        return Ok(None);
    };
    let n = match v {
        Value::Number(n) => n,
        other => {
            return Err(refuse(
                member,
                format!(
                    "must be an integer (a JSON number), got {}",
                    shape_of(other)
                ),
            ))
        }
    };
    match n.as_u64() {
        Some(u) if u >= min && u <= max => Ok(Some(u)),
        _ => Err(refuse(
            member,
            format!("must be an integer in {min}..={max}, got {n}"),
        )),
    }
}

/// A layout hint: an optional `u32`, > 0 (a zero-pixel dimension describes
/// no image).
fn optional_layout_hint(
    obj: &serde_json::Map<String, Value>,
    member: &str,
) -> Result<Option<u32>, MediaSourceError> {
    optional_uint(obj, member, 1, u64::from(u32::MAX))?
        .map(|u| u32::try_from(u).map_err(|_| refuse(member, format!("must fit a u32, got {u}"))))
        .transpose()
}

/// RFC 6266 §4.3 on a display name persist will not sanitise for anyone: no
/// path separator, no control character, no leading period, non-empty, at
/// most [`NAME_MAX_BYTES`] bytes. A name that fails is refused, not repaired
/// — a signed member cannot be rewritten at the door.
fn check_display_name(name: &str) -> Result<(), MediaSourceError> {
    const M: &str = "name";
    if name.is_empty() {
        return Err(refuse(
            M,
            "must not be empty when present (a display name displays something)",
        ));
    }
    if name.len() > NAME_MAX_BYTES {
        return Err(refuse(
            M,
            format!("must be at most {NAME_MAX_BYTES} bytes, got {}", name.len()),
        ));
    }
    if name.starts_with('.') {
        return Err(refuse(
            M,
            "must not begin with `.` (RFC 6266 §4.3: `..` and a leading period are not a display name)",
        ));
    }
    if let Some(c) = name.chars().find(|c| *c == '/' || *c == '\\') {
        return Err(refuse(
            M,
            format!("must not contain the path separator `{c}` (RFC 6266 §4.3: display only, never a path)"),
        ));
    }
    if let Some(c) = name.chars().find(|c| c.is_control()) {
        return Err(refuse(
            M,
            format!(
                "must not contain a control character (found U+{:04X})",
                c as u32
            ),
        ));
    }
    Ok(())
}

fn check_placeholder(s: &str) -> Result<(), MediaSourceError> {
    use base64::Engine as _;
    const M: &str = "placeholder";
    if s.is_empty() {
        return Err(refuse(
            M,
            "must not be empty when present (a placeholder has bytes)",
        ));
    }
    // Cheapest first: the encoded length bounds the decoded length, so an
    // oversized value is refused before any decoding.
    if s.len() > PLACEHOLDER_MAX_ENCODED_LEN {
        return Err(refuse(
            M,
            format!(
                "must decode to at most {PLACEHOLDER_MAX_DECODED_BYTES} bytes \
                 ({PLACEHOLDER_MAX_ENCODED_LEN} base64 characters), got {} characters",
                s.len()
            ),
        ));
    }
    let decoded = PLACEHOLDER_B64
        .decode(s)
        .map_err(|e| refuse(M, format!("must be standard base64 (RFC 4648 §4): {e}")))?;
    if decoded.len() > PLACEHOLDER_MAX_DECODED_BYTES {
        return Err(refuse(
            M,
            format!(
                "must decode to at most {PLACEHOLDER_MAX_DECODED_BYTES} bytes, got {}",
                decoded.len()
            ),
        ));
    }
    Ok(())
}

/// Parse the struct. See the module documentation for the grammar. Members
/// are checked in this order, and the FIRST failure is the refusal: the
/// CC 3.3.13 MUST-NOT list, then unknown members, then each declared member
/// in declaration order, then the cross-member rules (`codec` iff MP4,
/// `derived_from` ≠ `digest`).
pub fn parse_media_source(value: &Value) -> Result<MediaSource, MediaSourceError> {
    let obj = match value {
        Value::Object(obj) => obj,
        other => {
            return Err(refuse(
                MEDIA_MEMBER,
                format!(
                    "must be a JSON object (the CC 3.3.13 Source struct), got {}",
                    shape_of(other)
                ),
            ))
        }
    };
    // CC 3.3.13 MUST-NOT, before anything else: the refusal names the rule.
    for forbidden in FORBIDDEN_MEMBERS {
        if obj.contains_key(forbidden) {
            return Err(refuse(
                forbidden,
                "a Source struct MUST NOT carry a safe / renderable / tier bit (CC 3.3.13): \
                 the render tier is receiver policy, computed from verified, sniffed bytes and \
                 never from a claim in the descriptor (CC 5.3.2.6)",
            ));
        }
    }
    // Closed struct: an unknown member is refused by its own name.
    if let Some(unknown) = obj.keys().find(|k| !KNOWN_MEMBERS.contains(&k.as_str())) {
        return Err(refuse(
            unknown,
            format!(
                "is not a member of the Source struct (CC 3.3.13); the struct is closed to: {}",
                KNOWN_MEMBERS.join(", ")
            ),
        ));
    }
    let digest = required_str(
        obj,
        "digest",
        "required: the sha256 of the blob's bytes as 64 lowercase hex characters, \
         and an entry of `evidence_refs[]`",
    )?;
    if !is_hex64(digest) {
        return Err(refuse(
            "digest",
            format!("must be a sha256 as 64 lowercase hex characters, got `{digest}`"),
        ));
    }
    let size = positive_size(
        SIZE_MEMBER,
        obj.get(SIZE_MEMBER),
        "required (CC 3.3.13 / 5.3.2.5): the blob's byte length as a positive integer — \
         the cheaper check that runs before the digest",
    )?;
    let format = required_str(
        obj,
        "format",
        "required: the RFC 6838 media essence, lowercase `type/subtype` with no parameters",
    )?;
    if !is_media_essence(format) {
        return Err(refuse(
            "format",
            format!(
                "must be an RFC 6838 essence — lowercase `type/subtype`, each side \
                 `[a-z0-9][a-z0-9!#$&^_.+-]{{0,126}}`, no parameters, no whitespace — got `{format}`"
            ),
        ));
    }
    let codec = optional_str(obj, "codec")?;
    if let Some(c) = codec {
        if !is_codec_token(c) {
            return Err(refuse(
                "codec",
                format!(
                    "must be an RFC 6381-family token `[a-zA-Z0-9]+(.[a-zA-Z0-9]+)*` \
                     (avc1.42E01E, mp4a.40.2, av01.0.05M.08, opus), got `{c}`"
                ),
            ));
        }
    } else if CODEC_REQUIRED_FORMATS.contains(&format) {
        return Err(refuse(
            "codec",
            format!(
                "required when format is `{format}`: the container does not say what is inside it"
            ),
        ));
    }
    let width = optional_layout_hint(obj, "width")?;
    let height = optional_layout_hint(obj, "height")?;
    let duration_ms = optional_uint(obj, "duration_ms", 0, u64::MAX)?;
    let placeholder = optional_str(obj, "placeholder")?;
    if let Some(p) = placeholder {
        check_placeholder(p)?;
    }
    let name = optional_str(obj, "name")?;
    if let Some(n) = name {
        check_display_name(n)?;
    }
    let content_digest = optional_hex64(obj, "content_digest", "the plaintext hash")?;
    let derived_from = optional_hex64(obj, "derived_from", "the original blob's digest")?;
    let captions = optional_hex64(obj, "captions", "the `text/vtt` blob's digest")?;
    let digital_source_type = optional_str(obj, "digital_source_type")?;
    if let Some(d) = digital_source_type {
        if !DIGITAL_SOURCE_TYPES.contains(&d) {
            return Err(refuse(
                "digital_source_type",
                format!(
                    "must be one of the IPTC Digital Source Type vocabulary ({}), got `{d}`",
                    DIGITAL_SOURCE_TYPES.join(" | ")
                ),
            ));
        }
    }
    let init_segment = optional_hex64(obj, "init_segment", "the fMP4 init segment's digest")?;
    if derived_from.as_deref() == Some(digest) {
        return Err(refuse(
            "derived_from",
            "must differ from `digest`: a blob is not its own rendition (CC 3.3.13)",
        ));
    }
    Ok(MediaSource {
        digest: digest.to_owned(),
        size,
        format: format.to_owned(),
        codec: codec.map(str::to_owned),
        width,
        height,
        duration_ms,
        placeholder: placeholder.map(str::to_owned),
        name: name.map(str::to_owned),
        content_digest,
        derived_from,
        captions,
        digital_source_type: digital_source_type.map(str::to_owned),
        init_segment,
    })
}

/// The string entries of the envelope's `evidence_refs[]` — the same reading
/// as `admission::envelope_binds_content`: an entry that is not a string
/// cites nothing (CC 3.3.13: `evidence_refs[]` stays bare sha256, so the
/// `[{sha, size}]` shape can never creep in as a citation).
fn cited_digests(envelope: &Value) -> Vec<&str> {
    envelope
        .get(EVIDENCE_REFS_MEMBER)
        .and_then(Value::as_array)
        .map(|arr| arr.iter().filter_map(Value::as_str).collect())
        .unwrap_or_default()
}

/// The door gate: a row that carries a `media` member carries a well-formed
/// Source struct whose `digest` (and `captions`, when present) the row cites
/// in `evidence_refs[]`. Runs at every door — three ingest, three local, the
/// promotion chokepoint (the #866 pattern) — on every backend. A row with no
/// `media` member (or `media: null`, which the typed envelope reads as
/// absent) is not this gate's business and passes untouched.
///
/// The citation rule is what makes the struct actionable: the fold that
/// finds the rows describing a blob (`attestations_binding_content`) keys on
/// `evidence_refs`, so a struct whose blob is not cited is a struct no puller
/// would ever act on — "accepted but not projected", refused at the door.
pub fn check_media_source(envelope: &Value) -> Result<(), super::Error> {
    let Some(media) = envelope.get(MEDIA_MEMBER).filter(|v| !v.is_null()) else {
        return Ok(());
    };
    let source = parse_media_source(media)?;
    let cited = cited_digests(envelope);
    if !cited.contains(&source.digest.as_str()) {
        return Err(refuse(
            "digest",
            format!(
                "`{}` is not an entry of `evidence_refs[]`: the struct describes what the row \
                 cites, and a blob the row does not cite is a blob no puller would fetch \
                 (CC 3.3.13: `evidence_refs[]` stays bare sha256)",
                source.digest
            ),
        )
        .into());
    }
    if let Some(captions) = &source.captions {
        if !cited.contains(&captions.as_str()) {
            return Err(refuse(
                "captions",
                format!(
                    "`{captions}` is not an entry of `evidence_refs[]`: the captions blob is \
                     a separate blob the row must cite (CC 3.3.13)"
                ),
            )
            .into());
        }
    }
    Ok(())
}

/// FSD §4 — the `size` a `holds_bytes` claim's envelope declares: present, a
/// JSON number, an integer, > 0; else `Error::MediaSourceInvalid { member:
/// "size", .. }` (a claim is a one-member descriptor, so it is the same
/// kind). Returns the size so the two blob doors can compare it against the
/// byte length they store (AV-89) and the sized holder read can return it.
pub fn holds_bytes_claim_size(envelope: &Value) -> Result<u64, super::Error> {
    Ok(positive_size(
        SIZE_MEMBER,
        envelope.get(SIZE_MEMBER),
        "required on a `holds_bytes` claim (CC 3.3.13 / 5.3.2.5): the byte length the holder \
         stores, the number a puller caps its read at before hashing",
    )?)
}

/// The ingest-side form of [`holds_bytes_claim_size`]: for a row whose
/// `attestation_type` is a `holds_bytes:sha256:*` claim, require the size;
/// for every other row, nothing to check.
pub fn check_holder_claim_size(
    envelope: &Value,
    attestation_type: &str,
) -> Result<(), super::Error> {
    if attestation_type.starts_with(super::blobs::HOLDS_BYTES_ATTESTATION_TYPE_PREFIX) {
        holds_bytes_claim_size(envelope)?;
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    const DIGEST: &str = "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef";
    const OTHER: &str = "fedcba9876543210fedcba9876543210fedcba9876543210fedcba9876543210";
    const VTT: &str = "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa";

    /// The I115 fixture, byte for byte.
    fn good_media() -> Value {
        json!({
            "digest": DIGEST,
            "size": 4096,
            "format": "image/jpeg",
            "width": 64,
            "height": 48,
            "name": "cat.jpg",
        })
    }

    fn member_of(v: Value) -> String {
        parse_media_source(&v)
            .expect_err(&format!("refused: {v}"))
            .member
    }

    #[test]
    fn a_well_formed_struct_parses_to_its_members() {
        let m = parse_media_source(&good_media()).unwrap();
        assert_eq!(
            m,
            MediaSource {
                digest: DIGEST.into(),
                size: 4096,
                format: "image/jpeg".into(),
                codec: None,
                width: Some(64),
                height: Some(48),
                duration_ms: None,
                placeholder: None,
                name: Some("cat.jpg".into()),
                content_digest: None,
                derived_from: None,
                captions: None,
                digital_source_type: None,
                init_segment: None,
            }
        );
        // Every optional member, well-formed.
        let full = json!({
            "digest": DIGEST, "size": 10, "format": "video/mp4", "codec": "avc1.42E01E",
            "width": 1920, "height": 1080, "duration_ms": 0, "placeholder": "AQID",
            "name": "clip.mp4", "content_digest": OTHER, "derived_from": OTHER,
            "captions": VTT, "digital_source_type": "digitalCapture", "init_segment": VTT,
        });
        let m = parse_media_source(&full).unwrap();
        assert_eq!(m.codec.as_deref(), Some("avc1.42E01E"));
        assert_eq!(m.duration_ms, Some(0));
        assert_eq!(m.derived_from.as_deref(), Some(OTHER));
        assert_eq!(m.init_segment.as_deref(), Some(VTT));
    }

    /// The I115 witness table, copied: each malformed struct is refused
    /// naming the member the witness expects.
    #[test]
    fn the_i115_fixtures_are_refused_by_name() {
        let digest = DIGEST;
        let bad: &[(&str, Value, &str)] = &[
            (
                "no-size",
                json!({"digest": digest, "format": "image/jpeg"}),
                "size",
            ),
            (
                "zero-size",
                json!({"digest": digest, "size": 0, "format": "image/jpeg"}),
                "size",
            ),
            (
                "string-size",
                json!({"digest": digest, "size": "4096", "format": "image/jpeg"}),
                "size",
            ),
            ("no-format", json!({"digest": digest, "size": 1}), "format"),
            (
                "upper-format",
                json!({"digest": digest, "size": 1, "format": "Image/JPEG"}),
                "format",
            ),
            (
                "param-format",
                json!({"digest": digest, "size": 1, "format": "image/jpeg; q=1"}),
                "format",
            ),
            (
                "mp4-no-codec",
                json!({"digest": digest, "size": 1, "format": "video/mp4"}),
                "codec",
            ),
            (
                "bad-codec",
                json!({"digest": digest, "size": 1, "format": "video/mp4", "codec": "avc1 baseline"}),
                "codec",
            ),
            (
                "slash-name",
                json!({"digest": digest, "size": 1, "format": "image/png", "name": "../etc/passwd"}),
                "name",
            ),
            (
                "ctrl-name",
                json!({"digest": digest, "size": 1, "format": "image/png", "name": "a\u{0007}b"}),
                "name",
            ),
            (
                "fat-placeholder",
                json!({"digest": digest, "size": 1, "format": "image/png", "placeholder": "A".repeat(200)}),
                "placeholder",
            ),
            (
                "bad-digest",
                json!({"digest": "abc", "size": 1, "format": "image/png"}),
                "digest",
            ),
            (
                "bad-dst",
                json!({"digest": digest, "size": 1, "format": "image/png", "digital_source_type": "aiMadeIt"}),
                "digital_source_type",
            ),
            (
                "unknown-member",
                json!({"digest": digest, "size": 1, "format": "image/png", "bitrate": 9}),
                "bitrate",
            ),
            (
                "safe",
                json!({"digest": digest, "size": 1, "format": "image/png", "safe": true}),
                "safe",
            ),
            (
                "renderable",
                json!({"digest": digest, "size": 1, "format": "image/png", "renderable": true}),
                "renderable",
            ),
            (
                "tier",
                json!({"digest": digest, "size": 1, "format": "image/png", "tier": "A"}),
                "tier",
            ),
            (
                "crypto_tier",
                json!({"digest": digest, "size": 1, "format": "image/png", "crypto_tier": "plaintext"}),
                "crypto_tier",
            ),
            (
                "render_tier",
                json!({"digest": digest, "size": 1, "format": "image/png", "render_tier": "A"}),
                "render_tier",
            ),
            (
                "self-rendition",
                json!({"digest": digest, "size": 1, "format": "image/png", "derived_from": digest}),
                "derived_from",
            ),
        ];
        for (n, media, member) in bad {
            let err = parse_media_source(media).expect_err(&format!("I115: `{n}` is refused"));
            assert_eq!(err.member, *member, "I115 `{n}`: {err}");
            assert!(
                err.to_string().contains(member),
                "I115 `{n}`: names `{member}`: {err}"
            );
            // Through the door, the same member and the same kind.
            let env = json!({"evidence_refs": [digest], "media": media});
            let door = check_media_source(&env).expect_err(n);
            assert_eq!(door.kind(), "federation_media_source_invalid", "{n}");
            assert!(door.to_string().contains(member), "{n}: {door}");
        }
        // I115's second table: the MUST-NOT refusal on an otherwise good struct
        // names the rule, not "unknown member".
        for member in ["safe", "renderable", "tier"] {
            let mut m = good_media();
            m[member] = Value::Bool(true);
            let err = parse_media_source(&m).unwrap_err();
            assert_eq!(err.member, member);
            assert!(
                err.to_string().contains("5.3.2.6") && err.to_string().contains("receiver policy"),
                "{member}: {err}"
            );
        }
    }

    #[test]
    fn the_must_not_list_wins_over_every_other_refusal() {
        // A struct that is ALSO missing everything: the MUST-NOT member is
        // still what the refusal names, so the producer reads the rule first.
        for member in FORBIDDEN_MEMBERS {
            let m = json!({member: 1, "bitrate": 2});
            let err = parse_media_source(&m).unwrap_err();
            assert_eq!(err.member, member, "{err}");
            assert!(err.reason.contains("CC 5.3.2.6"), "{err}");
        }
    }

    #[test]
    fn an_unknown_member_is_refused_by_its_own_name_and_the_struct_is_closed() {
        let mut m = good_media();
        m["Size"] = json!(1);
        let err = parse_media_source(&m).unwrap_err();
        assert_eq!(err.member, "Size");
        assert!(err.reason.contains("closed"), "{err}");
        // The `Deserialize` impl is the same parser: no derive-shaped hole.
        let e = serde_json::from_value::<MediaSource>(m).unwrap_err();
        assert!(e.to_string().contains("`Size`"), "{e}");
        let mut z = good_media();
        z["size"] = json!(0);
        let e = serde_json::from_value::<MediaSource>(z).unwrap_err();
        assert!(e.to_string().contains("`size`"), "{e}");
        // And a well-formed one round-trips through Serialize without nulls.
        let m = parse_media_source(&good_media()).unwrap();
        let back = serde_json::to_value(&m).unwrap();
        assert_eq!(back, good_media());
        assert_eq!(serde_json::from_value::<MediaSource>(back).unwrap(), m);
    }

    #[test]
    fn the_struct_must_be_an_object() {
        for v in [json!("x"), json!(1), json!([]), json!(true)] {
            let err = parse_media_source(&v).unwrap_err();
            assert_eq!(err.member, "media", "{err}");
        }
    }

    #[test]
    fn digest_is_sixty_four_lowercase_hex() {
        let with = |d: &str| json!({"digest": d, "size": 1, "format": "image/png"});
        assert!(parse_media_source(&with(DIGEST)).is_ok());
        for bad in [
            "",
            "abc",
            &DIGEST[..63],
            &format!("{DIGEST}0"),
            &DIGEST.to_uppercase(),
            &format!("g{}", &DIGEST[1..]),
            &format!(" {}", &DIGEST[1..]),
        ] {
            assert_eq!(member_of(with(bad)), "digest", "{bad:?}");
        }
        assert_eq!(
            member_of(json!({"digest": 5, "size": 1, "format": "image/png"})),
            "digest"
        );
        assert_eq!(
            member_of(json!({"size": 1, "format": "image/png"})),
            "digest"
        );
    }

    #[test]
    fn size_is_a_positive_integer() {
        let with = |s: Value| json!({"digest": DIGEST, "size": s, "format": "image/png"});
        assert_eq!(parse_media_source(&with(json!(1))).unwrap().size, 1);
        assert_eq!(
            parse_media_source(&with(json!(u64::MAX))).unwrap().size,
            u64::MAX
        );
        for (bad, why) in [
            (json!(0), "> 0"),
            (json!(-1), "positive"),
            (json!("4096"), "got a string"),
            (json!(4096.5), "positive"),
            (json!(true), "got a boolean"),
            (json!(null), "got null"),
            (json!([4096]), "got an array"),
        ] {
            let err = parse_media_source(&with(bad.clone())).unwrap_err();
            assert_eq!(err.member, "size", "{bad}: {err}");
            assert!(err.reason.contains(why), "{bad}: {err}");
        }
    }

    #[test]
    fn format_is_an_rfc6838_essence() {
        let with = |f: &str| json!({"digest": DIGEST, "size": 1, "format": f});
        for ok in [
            "image/jpeg",
            "image/svg+xml",
            "application/vnd.api+json",
            "text/vtt",
            "font/woff2",
            "audio/ogg",
            "x-custom/a!#$&^_.+-9",
            &format!("image/{}", "a".repeat(127)),
        ] {
            assert!(parse_media_source(&with(ok)).is_ok(), "{ok}");
        }
        for bad in [
            "",
            "image",
            "image/",
            "/jpeg",
            "image/jpeg/x",
            "Image/JPEG",
            "image/jpeg; q=1",
            "image/jpeg;",
            "image/ jpeg",
            "image/jpeg ",
            " image/jpeg",
            "im age/jpeg",
            "-image/jpeg",
            "image/.jpeg",
            "image/jpég",
            &format!("image/{}", "a".repeat(128)),
        ] {
            assert_eq!(member_of(with(bad)), "format", "{bad:?}");
        }
        assert_eq!(
            member_of(json!({"digest": DIGEST, "size": 1, "format": 7})),
            "format"
        );
        assert_eq!(member_of(json!({"digest": DIGEST, "size": 1})), "format");
    }

    #[test]
    fn codec_is_required_iff_mp4_and_is_a_token_when_present() {
        let with = |f: &str, c: Option<&str>| {
            let mut m = json!({"digest": DIGEST, "size": 1, "format": f});
            if let Some(c) = c {
                m["codec"] = json!(c);
            }
            m
        };
        for f in CODEC_REQUIRED_FORMATS {
            let err = parse_media_source(&with(f, None)).unwrap_err();
            assert_eq!(err.member, "codec", "{f}");
            assert!(err.reason.contains("required"), "{err}");
        }
        assert!(parse_media_source(&with("video/webm", None)).is_ok());
        // A codec on a non-MP4 format is allowed and still grammar-checked.
        assert!(parse_media_source(&with("video/webm", Some("vp09.00.10.08"))).is_ok());
        assert_eq!(member_of(with("video/webm", Some("vp9 profile0"))), "codec");
        for ok in [
            "avc1.42E01E",
            "mp4a.40.2",
            "av01.0.05M.08",
            "opus",
            "hvc1.1.6.L93.B0",
            "a",
        ] {
            assert!(
                parse_media_source(&with("video/mp4", Some(ok))).is_ok(),
                "{ok}"
            );
        }
        for bad in [
            "",
            "avc1 baseline",
            "avc1.",
            ".avc1",
            "avc1..42",
            "avc1,mp4a.40.2",
            "avc1/42",
            "avc1-42",
            "avc1_42",
        ] {
            assert_eq!(member_of(with("audio/mp4", Some(bad))), "codec", "{bad:?}");
        }
        assert_eq!(
            member_of(json!({"digest": DIGEST, "size": 1, "format": "video/mp4", "codec": 1})),
            "codec"
        );
    }

    #[test]
    fn layout_hints_and_duration_are_bounded_integers() {
        let with =
            |k: &str, v: Value| json!({"digest": DIGEST, "size": 1, "format": "image/png", k: v});
        for k in ["width", "height"] {
            assert_eq!(
                parse_media_source(&with(k, json!(1)))
                    .unwrap()
                    .width
                    .or(Some(1)),
                Some(1)
            );
            assert!(parse_media_source(&with(k, json!(u32::MAX))).is_ok());
            for bad in [
                json!(0),
                json!(-1),
                json!(u64::from(u32::MAX) + 1),
                json!("64"),
                json!(1.5),
            ] {
                assert_eq!(member_of(with(k, bad.clone())), k, "{k}={bad}");
            }
        }
        assert_eq!(
            parse_media_source(&with("duration_ms", json!(0)))
                .unwrap()
                .duration_ms,
            Some(0)
        );
        assert!(parse_media_source(&with("duration_ms", json!(u64::MAX))).is_ok());
        for bad in [json!(-1), json!("1200"), json!(1.5), json!(null)] {
            assert_eq!(
                member_of(with("duration_ms", bad.clone())),
                "duration_ms",
                "{bad}"
            );
        }
    }

    #[test]
    fn name_is_display_only() {
        let with = |n: &str| json!({"digest": DIGEST, "size": 1, "format": "image/png", "name": n});
        for ok in [
            "cat.jpg",
            "My Photo (1).jpg",
            "café-été.png",
            "thumbnail",
            "a.b..c",
            &"n".repeat(255),
        ] {
            assert!(parse_media_source(&with(ok)).is_ok(), "{ok:?}");
        }
        for (bad, why) in [
            ("", "empty"),
            ("../etc/passwd", "begin with `.`"),
            ("..", "begin with `.`"),
            (".", "begin with `.`"),
            (".hidden", "begin with `.`"),
            ("a/b", "path separator `/`"),
            ("a\\b", "path separator `\\`"),
            ("a\u{0007}b", "control character (found U+0007)"),
            ("a\u{007f}b", "control character (found U+007F)"),
            ("a\u{0085}b", "control character (found U+0085)"),
            ("a\nb", "control character"),
            ("a\0b", "control character"),
            (&"n".repeat(256), "at most 255 bytes"),
            (&"é".repeat(128), "at most 255 bytes"),
        ] {
            let err = parse_media_source(&with(bad)).unwrap_err();
            assert_eq!(err.member, "name", "{bad:?}: {err}");
            assert!(err.reason.contains(why), "{bad:?}: {err}");
        }
        assert_eq!(
            member_of(json!({"digest": DIGEST, "size": 1, "format": "image/png", "name": 1})),
            "name"
        );
    }

    #[test]
    fn placeholder_is_small_standard_base64() {
        use base64::Engine as _;
        let with =
            |p: &str| json!({"digest": DIGEST, "size": 1, "format": "image/png", "placeholder": p});
        let std = base64::engine::general_purpose::STANDARD;
        let sixty_four = std.encode([0xABu8; 64]);
        assert_eq!(sixty_four.len(), PLACEHOLDER_MAX_ENCODED_LEN);
        assert!(parse_media_source(&with(&sixty_four)).is_ok());
        assert!(parse_media_source(&with("AQID")).is_ok());
        // Padding is optional on decode.
        assert!(parse_media_source(&with("AQI=")).is_ok());
        assert!(parse_media_source(&with("AQI")).is_ok());
        // A real-shaped thumbhash (25 bytes).
        assert!(parse_media_source(&with(&std.encode([7u8; 25]))).is_ok());
        for (bad, why) in [
            (std.encode([0xABu8; 65]), "at most 64 bytes"),
            ("A".repeat(200), "at most 64 bytes"),
            ("".to_owned(), "empty"),
            ("not base64!".to_owned(), "standard base64"),
            ("AQ-_".to_owned(), "standard base64"),
            ("A".to_owned(), "standard base64"),
        ] {
            let err = parse_media_source(&with(&bad)).unwrap_err();
            assert_eq!(err.member, "placeholder", "{bad:?}: {err}");
            assert!(err.reason.contains(why), "{bad:?}: {err}");
        }
        assert_eq!(
            member_of(
                json!({"digest": DIGEST, "size": 1, "format": "image/png", "placeholder": 1})
            ),
            "placeholder"
        );
    }

    #[test]
    fn the_optional_hex_members_are_each_sixty_four_lowercase_hex() {
        for member in ["content_digest", "derived_from", "captions", "init_segment"] {
            let ok = json!({"digest": DIGEST, "size": 1, "format": "image/png", member: OTHER});
            assert!(parse_media_source(&ok).is_ok(), "{member}");
            for bad in [
                json!("abc"),
                json!(DIGEST.to_uppercase()),
                json!(""),
                json!(1),
                json!(null),
            ] {
                let m = json!({"digest": DIGEST, "size": 1, "format": "image/png", member: bad});
                assert_eq!(member_of(m), member, "{member}={bad}");
            }
        }
    }

    #[test]
    fn a_blob_is_not_its_own_rendition() {
        let m = json!({"digest": DIGEST, "size": 1, "format": "image/png", "derived_from": DIGEST});
        let err = parse_media_source(&m).unwrap_err();
        assert_eq!(err.member, "derived_from");
        assert!(err.reason.contains("its own rendition"), "{err}");
        let m = json!({"digest": DIGEST, "size": 1, "format": "image/png", "derived_from": OTHER});
        assert_eq!(
            parse_media_source(&m).unwrap().derived_from.as_deref(),
            Some(OTHER)
        );
    }

    #[test]
    fn digital_source_type_is_the_closed_iptc_set() {
        for ok in DIGITAL_SOURCE_TYPES {
            let m = json!({"digest": DIGEST, "size": 1, "format": "image/png", "digital_source_type": ok});
            assert_eq!(
                parse_media_source(&m)
                    .unwrap()
                    .digital_source_type
                    .as_deref(),
                Some(ok)
            );
        }
        for bad in ["aiMadeIt", "TrainedAlgorithmicMedia", "", "digitalCapture "] {
            let m = json!({"digest": DIGEST, "size": 1, "format": "image/png", "digital_source_type": bad});
            let err = parse_media_source(&m).unwrap_err();
            assert_eq!(err.member, "digital_source_type", "{bad:?}");
            assert!(err.reason.contains("trainedAlgorithmicMedia"), "{err}");
        }
        assert_eq!(
            member_of(
                json!({"digest": DIGEST, "size": 1, "format": "image/png", "digital_source_type": true})
            ),
            "digital_source_type"
        );
    }

    #[test]
    fn the_gate_ignores_rows_without_a_media_member() {
        assert!(check_media_source(&json!({"dimension": "trace:x:v1", "score": 1.0})).is_ok());
        assert!(check_media_source(&json!({"media": null, "evidence_refs": []})).is_ok());
        assert!(check_media_source(&json!({})).is_ok());
        assert!(check_media_source(&json!("not even an object")).is_ok());
        // A row that names `media` must carry the struct.
        let err = check_media_source(&json!({"media": "x"})).unwrap_err();
        assert_eq!(err.kind(), "federation_media_source_invalid");
        assert!(err.to_string().contains("`media`"), "{err}");
    }

    /// I116, at the gate: the struct describes what the row cites.
    #[test]
    fn the_gate_requires_the_digest_and_captions_to_be_cited() {
        let ok = json!({"evidence_refs": [DIGEST], "media": good_media()});
        assert!(check_media_source(&ok).is_ok());
        // digest not cited
        for env in [
            json!({"evidence_refs": [OTHER], "media": good_media()}),
            json!({"evidence_refs": [], "media": good_media()}),
            json!({"media": good_media()}),
            json!({"evidence_refs": DIGEST, "media": good_media()}),
            // CC 3.3.13: an object entry is not a citation (the ask-2 shape, pinned out).
            json!({"evidence_refs": [{"sha": DIGEST, "size": 4096}], "media": good_media()}),
        ] {
            let err = check_media_source(&env).expect_err(&env.to_string());
            assert_eq!(err.kind(), "federation_media_source_invalid");
            assert!(err.to_string().contains("evidence_refs"), "{err}");
            assert!(err.to_string().contains("`digest`"), "{err}");
        }
        // captions not cited
        let video = |refs: Value| {
            json!({"evidence_refs": refs, "media": {
                "digest": DIGEST, "size": 10, "format": "video/mp4", "codec": "avc1.42E01E", "captions": VTT
            }})
        };
        let err = check_media_source(&video(json!([DIGEST]))).unwrap_err();
        assert_eq!(err.kind(), "federation_media_source_invalid");
        assert!(
            err.to_string().contains("captions") && err.to_string().contains("evidence_refs"),
            "{err}"
        );
        assert!(check_media_source(&video(json!([DIGEST, VTT]))).is_ok());
        assert!(check_media_source(&video(json!([VTT, OTHER, DIGEST]))).is_ok());
        // Other members' citations are the struct's own business, not the gate's.
        let derived = json!({"evidence_refs": [DIGEST], "media": {
            "digest": DIGEST, "size": 1, "format": "image/webp", "derived_from": OTHER
        }});
        assert!(check_media_source(&derived).is_ok());
    }

    /// I117's ingest half, at the function.
    #[test]
    fn a_holds_bytes_claim_declares_a_positive_integer_size() {
        let claim = |size: Value| {
            let mut env = json!({"kind": "holds_bytes", "evidence_refs": [DIGEST]});
            if !size.is_null() {
                env["size"] = size;
            }
            env
        };
        for (n, size) in [
            ("absent", Value::Null),
            ("zero", json!(0)),
            ("string", json!("12")),
            ("negative", json!(-1)),
            ("float", json!(12.0)),
            ("object", json!({"bytes": 12})),
        ] {
            let err = holds_bytes_claim_size(&claim(size)).expect_err(n);
            assert_eq!(err.kind(), "federation_media_source_invalid", "{n}: {err}");
            assert!(err.to_string().contains("size"), "{n}: {err}");
            assert!(
                matches!(&err, super::super::Error::MediaSourceInvalid { member, .. } if member == "size"),
                "{n}: {err}"
            );
        }
        assert_eq!(holds_bytes_claim_size(&claim(json!(12))).unwrap(), 12);
        assert_eq!(
            holds_bytes_claim_size(&claim(json!(u64::MAX))).unwrap(),
            u64::MAX
        );
        let absent = holds_bytes_claim_size(&claim(Value::Null)).unwrap_err();
        assert!(absent.to_string().contains("holds_bytes"), "{absent}");
    }

    #[test]
    fn the_holder_claim_check_only_looks_at_holds_bytes_rows() {
        let without_size = json!({"kind": "holds_bytes", "evidence_refs": [DIGEST]});
        let holds = format!(
            "{}{DIGEST}",
            super::super::blobs::HOLDS_BYTES_ATTESTATION_TYPE_PREFIX
        );
        let err = check_holder_claim_size(&without_size, &holds).unwrap_err();
        assert_eq!(err.kind(), "federation_media_source_invalid");
        assert!(check_holder_claim_size(&without_size, "scores").is_ok());
        assert!(
            check_holder_claim_size(&without_size, "holds_bytes").is_ok(),
            "the type, not the kind member"
        );
        let sized = json!({"kind": "holds_bytes", "evidence_refs": [DIGEST], "size": 12});
        assert!(check_holder_claim_size(&sized, &holds).is_ok());
    }

    #[test]
    fn a_holder_claim_round_trips() {
        let c = HolderClaim {
            key_id: "node-a".into(),
            size: 12,
        };
        let v = serde_json::to_value(&c).unwrap();
        assert_eq!(v, json!({"key_id": "node-a", "size": 12}));
        assert_eq!(serde_json::from_value::<HolderClaim>(v).unwrap(), c);
    }

    #[test]
    fn the_refusal_names_the_member_in_both_displays() {
        let e = refuse("size", "must be > 0");
        assert_eq!(e.to_string(), "media source member `size`: must be > 0");
        let door: super::super::Error = e.into();
        assert_eq!(door.kind(), "federation_media_source_invalid");
        assert_eq!(
            door.to_string(),
            "media source member `size` refused: must be > 0"
        );
    }
}
