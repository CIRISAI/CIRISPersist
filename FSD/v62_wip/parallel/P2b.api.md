# P2b.api.md — `crate::federation::namespace::key_segment`

Status: implemented in P2b.patch. Final ruling from CC: the encoding is the bare base64url thumbprint.

Update: the original three signatures are unchanged. Added since first publication: `family_param_of`, `key_id_of_param`, `KEY_BEARING_STEMS`, `check_dimension_key_segments`, and the licensure changes at the end (`authority_of` now returns `Cow`, and there is a new `licensure_stem_of`).

The module is `src/federation/namespace/key_segment.rs`, declared `pub mod key_segment;` in `namespace/mod.rs`. It is the ONE place where a key is written into a family name (a `dimension` value segment) and read back out of one. Payload members (iss, author, sub, role parties) keep the full URN.

```rust
/// `urn:ietf:params:oauth:ckt:sha-256:` (re-export of Verify's constant).
pub use ciris_verify_core::edition2::IDENTITY_REF_PREFIX;

/// The bare key segment of an identity-ref: the 43 unpadded base64url
/// characters after IDENTITY_REF_PREFIX. `None` when `identity_ref` is not a
/// well-formed identity-ref (`ciris_verify_core::edition2::is_identity_ref`).
#[must_use]
pub fn segment_of(identity_ref: &str) -> Option<String>;

/// The identity-ref a key segment names: IDENTITY_REF_PREFIX + `segment`.
/// `None` when `segment` is not a key segment (`is_key_segment`).
/// One-to-one with `segment_of`.
#[must_use]
pub fn identity_ref_of(segment: &str) -> Option<String>;

/// Exactly 43 base64url characters ([A-Za-z0-9_-]) whose last character
/// carries zero trailing bits (one of `AEIMQUYcgkosw048`), i.e. a 32-byte
/// thumbprint with one spelling.
#[must_use]
pub fn is_key_segment(s: &str) -> bool;
```

Laws, each witnessed by a unit test:
- `segment_of(r).and_then(|s| identity_ref_of(&s)) == Some(r)` for every well-formed identity-ref `r`.
- `identity_ref_of(s).and_then(|r| segment_of(&r)) == Some(s)` for every `s` with `is_key_segment(s)`.
- `is_key_segment(s)` holds iff `identity_ref_of(s).is_some()`.

## Added

```rust
pub const KEY_SEGMENT_LEN: usize = 43;

/// A key id as a family-name segment: an identity-ref becomes its bare
/// segment; any other id (an earlier-form key id) is returned unchanged.
pub fn family_param_of(key_id: &str) -> std::borrow::Cow<'_, str>;

/// A family-name segment as a key id: a key segment becomes the identity-ref
/// it names; any other segment is returned unchanged. Inverse of `family_param_of`.
pub fn key_id_of_param(segment: &str) -> std::borrow::Cow<'_, str>;

/// Families whose parameter right after the stem names a key.
pub const KEY_BEARING_STEMS: &[&str] = &["licensure:", "moderation_track_record:"];
/// Scope tokens whose parameter after the stem names a key.
pub const KEY_BEARING_SCOPE_STEMS: &[&str] = &["infra:attest:licensure:"];

/// The admission gate: pure, called at the put, local and promotion doors.
/// It checks `dimension` and every `scope` token.
/// Error::MalformedRow { reason: malformed_row::ENVELOPE_MEMBER_INVALID, .. }.
pub fn check_dimension_key_segments(envelope: &serde_json::Value) -> Result<(), Error>;
```

Test helpers, under `#[cfg(test)] pub(crate) mod tests`:
- `segment(fill: char) -> String`: 42×fill followed by `A`.
- `kid(fill: char) -> String`: the identity-ref of `segment(fill)`.

## `crate::federation::licensure` (changed)

```rust
// BREAKING inside the crate: authority_of now returns Cow (was Option<&str>).
// A key segment is returned as its identity-ref.
pub fn authority_of(dimension: &str) -> Option<std::borrow::Cow<'_, str>>;

/// "licensure:" + family_param_of(authority_id)
pub fn licensure_stem_of(authority_id: &str) -> String;
```
