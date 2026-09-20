# The media Source struct, and size on every claim (CIRISPersist#871)

**Status:** v45.0.0 design. Filed from CIRISEdge's #871 (the persist half of
CIRISConstitution#104, ruled on rc5: CC 3.3.13 the multimedia Source struct,
CC 5.3.2.5 size checked first, CC 5.3.2.6 the render tier is receiver
policy). Consumers: CIRISServer#614 (the node's ingest pipeline),
CIRISServer#615 (the client blob contract), CIRISEdge's sibling issue.
Sequenced after #870 (v44.8.1): a peer can now learn a holder.

**Numbering.** MAJOR, on our own rule: the signed `holds_bytes` claim gains
a REQUIRED member and the door refuses a claim without it; the envelope
vocabulary re-pins. There are no blobs in production, so the strictness
costs nothing today and never has to be introduced later.

## 1. What the constitution says, verbatim

CC 5.3.2.5 (normative): *"Every blob carries its size, and size is checked
first. A descriptor that cites a blob from `evidence_refs[]` … carries the
blob's byte length alongside its digest. A producer always knows it at
creation time. The consumer MUST compare the received length to the declared
size before computing the digest: a mismatch is a refusal without reading
the rest … Size is not a substitute for the digest, only the cheaper check
that runs first."*

CC 3.3.13 (normative, the #104 ruling): *"`size` (bytes) is REQUIRED — on
every blob, not only media."* — *"`evidence_refs[]` stays bare sha256."* —
*"What the struct MUST NOT carry: any `safe` / `renderable` / tier bit."* —
*"Renditions are separate blobs … any derived rendition is its own blob
with its own digest and `derived_from` naming the original."*

CC 5.3.2.6 (normative): the render tier is *"computed from verified,
sniffed bytes, never from a claim in the descriptor"*; the sniffed essence
must **equal** the declared `format`; *"a mismatch is a refusal, not a
correction."* Enforcement *"belongs on the node."*

Three consequences for the substrate, all decided by the text:

1. `size` rides **beside** the digest, never inside `evidence_refs[]`. The
   `[{sha, size}]` form in #871's ask 2 contradicts CC 3.3.13 and breaks
   every reader (persist's `envelope_binds_content` and Edge's
   `evidence_refs: Vec<String>` both read strings). Not built.
2. Persist validates the **grammar** of the struct and refuses a malformed
   one by name; it never sniffs bytes and never decides a render tier.
   Those are the node's (CIRISServer#614) and the client's (#615).
3. `size` is **required** wherever a blob is described — the `holds_bytes`
   claim and the Source struct — and refused when absent. An optional size
   is a size nobody checks; requiring it is strictly stronger and, with no
   production blobs, free.

## 2. The threat model this closes

Persist bounds the WRITE side today: AV-7 (8 MiB body limit), AV-40
(`body_size_bytes ≤ 8 MiB` schema CHECK), the inline-put deployment cap in
`blobs.rs`, AV-76's cheapest-first tiering. Nothing bounds the PULL side: a
puller doing a `ContentFetch` has no declared length, reads to EOF, then
hashes — a lying or hostile holder streams unbounded bytes at it before the
full-SHA check (CC 5.3.2.5) can refuse.

| AV | threat | mitigation (this cut) |
|---|---|---|
| **AV-88** | Unbounded `ContentFetch`: the puller reads to EOF and hashes after — memory/disk exhaustion by a holder, before any refusal | `size` is a REQUIRED, signed member of every `holds_bytes` claim and every Source struct; the puller caps its read at the declared size and refuses on overrun or underrun BEFORE hashing (AV-76's discipline on the byte plane). Persist supplies the number in the signed bytes a peer already verifies; Edge enforces the cap (its half). |
| **AV-89** | Size divergence: a holder's claim says one length, the author's descriptor another — the holder is lying, or holds different bytes under the same sha (impossible) or a truncation | The author's size (Source struct / descriptor) and the holder's size (claim) must agree; `list_holders_sized` returns both parties' numbers so a puller refuses a holder whose claim disagrees with the descriptor it is fetching for. Persist refuses, at its own adopt door, to announce a claim whose size is not the byte length it just stored. |

`content_digest` (plaintext hash beside the ciphertext hash on sealed
scopes) is carried because rc5 ruled it. Named here so it is accepted, not
discovered: AAD binding stops substitution; it does **not** stop a
dictionary check — anyone holding the row can confirm a candidate plaintext
for a community blob. That is a property of the ruling, recorded.

## 3. The struct

Envelope member **`media`**, a typed member of `EnvelopeCore` (byte-preserving
`Option<serde_json::Value>`, validated by the door gate — a decode error is
a generic refusal, the gate's is a named one), listed in the envelope
vocabulary (`paths::MEDIA`; **`ENVELOPE_VOCABULARY_SHA256` re-pins**, the
v31.0.0 / v44.6.0 motion — every consumer asserting the hash re-pins in
the same window).

```
media := {
  digest              hex64        REQUIRED; == an entry of evidence_refs[]
  size                u64 > 0      REQUIRED (CC 3.3.13 / 5.3.2.5)
  format              string       REQUIRED; RFC 6838 essence: lowercase `type/subtype`,
                                   restricted-name grammar, no parameters
  codec               string       RFC 6381-family token; REQUIRED iff format ∈ {video/mp4, audio/mp4}
  width, height       u32          optional layout hints
  duration_ms         u64          optional
  placeholder         string       optional; base64 thumbhash, ≤ 64 decoded bytes
  name                string       optional; display only; RFC 6266 §4.3 sanitised:
                                   no path separators, no control characters, ≤ 255 bytes
  content_digest      hex64        optional; the plaintext hash when digest is over ciphertext
  derived_from        hex64        optional; this blob is a rendition of that one
  captions            hex64        optional; sha256 of a separate text/vtt blob; == an entry of evidence_refs[]
  digital_source_type string       optional; IPTC Digital Source Type, closed:
                                   trainedAlgorithmicMedia | compositeWithTrainedAlgorithmicMedia |
                                   compositeSynthetic | algorithmicallyEnhanced | humanEdits |
                                   digitalCapture | screenCapture | virtualRecording
  init_segment        hex64        optional; live stream (CC 3.3.13 Phase 2): the sha256 of the
                                   per-epoch fMP4 init segment (ftyp + moov)
}
```

Closed (`deny_unknown_fields`): an unknown member is refused by name. The
constitution's MUST-NOT list — `safe`, `renderable`, `tier`, `crypto_tier`,
`render_tier` — is refused by name with the CC 5.3.2.6 reason, not as a
generic unknown. A live stream in progress is the one struct with no total
`size` (CC 5.3.2.5); it is expressed as `size` on each chunk and on the
init segment, never as an absent `size` here — the struct always has one.

**The one gate** `media_source::check_media_source(envelope)` runs at every
door (three ingest, three local, the promotion chokepoint — the #866
pattern) and refuses with `Error::MediaSourceInvalid { member, reason }`
(kind `federation_media_source_invalid`). It also requires
`digest` (and `captions`, when present) to appear in the row's
`evidence_refs[]` — the struct describes what the row cites, and the fold
that finds rows for a blob (`attestations_binding_content`) keys on
`evidence_refs`, so a struct whose blob is not cited is a struct no puller
would ever act on.

Not persist's: sniffing, the sniffed-essence == `format` refusal, the
render tier, `alt_text` / transcript / license slots of the sub-kind
schemas (CIRISNodeCore FSD/MEDIA_SHARING.md §4), and the `content_class`
marking rule (CC 3.3.12 R1: a `trainedAlgorithmicMedia` row must carry
`content_class:generated` — a separate flag row, the node's duty at ingest).

## 4. `size` on the holder claim

`holds_bytes_attestation_row(sha, attester, id, asserted_at, size)` — the
ONE definition (v31.0.0, #652) gains `size: u64` in the envelope:
`{kind, evidence_refs, size, asserted_at, …}`. Persist rebuilds the
envelope at the local door and checks the signer's hash against the rebuild
(unchanged), so the signer (`sign_holds_bytes_claim`) takes the size too.
Both blob doors pass the byte length they store. **The receive side
refuses** a `holds_bytes:*` row whose envelope has no `size`, or a `size`
that is not a positive integer (`Error::MediaSourceInvalid { member:
"size", … }` — the same kind; a claim is a one-member descriptor).

`list_holders_sized(sha) -> Vec<HolderClaim { key_id, size }>` is the new
read; `list_holders(sha) -> Vec<String>` stays (Edge compiles). PyO3
`list_holders_sized_json`.

A public `store_blob_local(sha, bytes, media_type)` (#863 ask 1): the
commons/plaintext LocalOnly store — content-address checked, no claim
emitted, the sealed adopt door's `LocalOnly` semantics for plaintext.

## 5. `derived_from` — the rendition index and its placement rule

**V149 `blob_renditions`** (both dialects): `rendition_sha256` (PK),
`original_sha256`, `format`, `size`, `width`, `height`, `role`,
`source_attestation_id`, `cohort_scope`. Projected in the same write that
admits a row whose `media.derived_from` is set (every backend's
`put_attestation`, the local writer, the promotion door), removed by the
same retraction fold that retires the row. Read: `list_derived(sha) ->
Vec<Rendition>`; PyO3 `list_derived_json`.

**Placement rule (CC 3.3.13, stated once):** a rendition inherits the
original's `cohort_scope` and audience and is placed in the same crossing.
Enforced where persist can see it: when the original blob is held locally,
a rendition row whose `cohort_scope` differs from the original's is refused
(`MediaSourceInvalid { member: "derived_from", … }`); when the original is
not held, the row is admitted and the rule is the node's. `self` / `family`
renditions emit no `holds_bytes` exactly as their originals
(`suppresses_holds_bytes`, unchanged).

`role` is the struct's `name` when it parses as one of `thumbnail`,
`poster`, `transcode`, `caption_track`; else `other`. A rendition's
`digest` must differ from its `derived_from` (a blob is not its own
rendition).

## 6. Lifecycle, by door

| door | what changes |
|---|---|
| local write (3 backends) | `check_media_source`; `blob_renditions` projection |
| federation ingest (3) | `check_media_source`; the `holds_bytes` size refusal; projection |
| promotion chokepoint | `check_media_source` (a local row admitted before this cut does not cross without it) |
| `put_blob_with_scope` / `adopt_sealed_blob_at` (2 backends) | the claim carries the stored byte length; adopt refuses to announce a size ≠ the length it stored |
| `list_holders_sized`, `list_derived`, `store_blob_local` | new reads / the LocalOnly plaintext door |
| envelope vocabulary | `paths::MEDIA`; re-pin |

## 7. Invariants

- **I115** — a malformed struct is refused by name at all seven doors:
  missing `size`, `size: 0`, missing `format`, `format: "Image/JPEG"`,
  `format: "image/jpeg; q=1"`, `video/mp4` without `codec`, a `name` with
  `/` or a control character, a `placeholder` over the cap, an unknown
  member, and each of `safe` / `renderable` / `tier` / `crypto_tier` /
  `render_tier` (the CC 5.3.2.6 refusal names the rule). A well-formed
  struct is admitted on all three backends.
- **I116** — `digest` not in `evidence_refs[]` is refused; `captions` not
  in `evidence_refs[]` is refused; `evidence_refs` entries stay strings —
  a row with an object entry is refused by `envelope_binds_content`'s
  reading, unchanged (pinned, so ask 2's shape cannot creep in).
- **I117** — a `holds_bytes` claim without `size`, or with `size: 0` /
  `"12"` / `-1`, is refused at ingest on all three backends; the claims the
  two blob doors write carry the exact stored length; `list_holders_sized`
  returns it; a two-node delivery (the #870 I113c shape) carries the size
  to the peer.
- **I118** — a row with `derived_from` projects one `blob_renditions` row
  in the same write on all three backends; `list_derived(original)` returns
  it; retiring the row removes it; a rendition at a different
  `cohort_scope` than a locally held original is refused; a rendition whose
  digest equals its `derived_from` is refused.
- **I119** — from disk: every blob write door stores `size` and the
  validated `format` into `federation_blobs` (`size_bytes`, `media_type`),
  and the claim a peer receives carries `size` — the local column alone
  proves nothing to a peer (#871 ask 5); the gate call appears at all seven
  doors; the vocabulary manifest lists `paths::MEDIA`.
- **I120** — the vocabulary hash is re-pinned deliberately: the test that
  asserts `ENVELOPE_VOCABULARY_SHA256 == envelope_vocabulary_sha256()`
  stays; the CHANGELOG names the old and new hash.

## 8. Not in scope

- Sniffing, the render tier, renditions' production (the node).
- `evidence_refs[]` entries as objects (contradicts CC 3.3.13; breaks
  every reader).
- Changing `list_holders`'s signature.
- `settlement:*`, hop/TTL (#672), the community principal (#860) — next.
