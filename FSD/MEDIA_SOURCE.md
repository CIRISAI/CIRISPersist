# The media Source struct, and size on every claim (CIRISPersist#871)

**Status:** implemented. From CIRISEdge#871, the persist half of
CIRISConstitution#104: CC 3.3.13 (the multimedia Source struct), CC 5.3.2.5
(size checked first), CC 5.3.2.6 (the render tier is receiver policy).
Consumers: CIRISServer#614 (the node's ingest pipeline), CIRISServer#615 (the
client blob contract), CIRISEdge.

**The holding claim.** A node's claim to hold a blob is `custody:ack:v1` with
`custody_state: here` (`src/federation/holding_claim.rs`, CC 3.1.3.3), placed
at the CONTENT's scope (`federation` for Commons-tier content, the bytes' own
`self` / `family` / room cohort otherwise), fresh until its own `expires_at`
(72 h), retracted by its signer alone. The retired `holds_bytes:sha256:{prefix}`
carrier is refused at every door, never served, and read by no fold.

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
   `[{sha, size}]` entry form would contradict CC 3.3.13 and break every
   reader (persist's `envelope_binds_content` and Edge's
   `evidence_refs: Vec<String>` both read strings).
2. Persist validates the **grammar** of the struct and refuses a malformed
   one by name; it never sniffs bytes and never decides a render tier.
   Those are the node's (CIRISServer#614) and the client's (#615).
3. `size` is **required** wherever a blob is described — the holding claim
   and the Source struct — and refused when absent. An optional size is a
   size nobody checks.

## 2. The threat model this closes

Persist bounds the WRITE side: AV-7 (8 MiB body limit), AV-40
(`body_size_bytes ≤ 8 MiB` schema CHECK), the inline-put deployment cap in
`blobs.rs`, AV-76's cheapest-first tiering. The PULL side needs a declared
length: without one, a puller doing a `ContentFetch` reads to EOF, then
hashes — a lying or hostile holder streams unbounded bytes at it before the
full-SHA check (CC 5.3.2.5) can refuse.

| AV | threat | mitigation |
|---|---|---|
| **AV-88** | Unbounded `ContentFetch`: the puller reads to EOF and hashes after — memory/disk exhaustion by a holder, before any refusal | `size` is a REQUIRED, signed member of every holding claim and every Source struct; the puller caps its read at the declared size and refuses on overrun or underrun BEFORE hashing (AV-76's discipline on the byte plane). Persist supplies the number in the signed bytes a peer already verifies; Edge enforces the cap (its half). |
| **AV-89** | Size divergence: a holder's claim says one length, the author's descriptor another — the holder is lying, or holds different bytes under the same sha (impossible) or a truncation | The author's size (Source struct / descriptor) and the holder's size (claim) must agree; `list_holders_sized` returns both parties' numbers so a puller refuses a holder whose claim disagrees with the descriptor it is fetching for. Persist refuses, at its own adopt door, to announce a claim whose size is not the byte length it just stored. |

`content_digest` (plaintext hash beside the ciphertext hash on sealed
scopes) is carried (CC 3.3.13). AAD binding stops substitution; it does
**not** stop a dictionary check — anyone holding the row can confirm a
candidate plaintext for a community blob. That is a known property of the
field.

## 3. The struct

Envelope member **`media`**, a typed member of `EnvelopeCore` (byte-preserving
`Option<serde_json::Value>`, validated by the door gate — a decode error is
a generic refusal, the gate's is a named one), listed in the envelope
vocabulary (`paths::MEDIA`, pinned by `ENVELOPE_VOCABULARY_SHA256`).

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
door (the shared ingest plan, the shared local-write plan and the
promotion chokepoint, which both backends reach — the #866 pattern) and refuses with `Error::MediaSourceInvalid { member, reason }`
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

The holding claim carries `size: u64` in its envelope: a `here` report
carries the blob's stored length, a `none` report carries none
(`custody_ack.rs`). The ONE row builder is `holding_claim_row`, signed by
`sign_holding_claim`; both blob write doors (`put_blob_with_scope`,
`adopt_sealed_blob_at`) pass the byte length they store. **The receive side
refuses** a `here` claim whose envelope has no `size`, or a `size` that is not
a positive integer (`custody_ack_malformed` — a malformed report is refused,
never read as an absent one).

`list_holders_sized(sha) -> Vec<HolderClaim { key_id, size }>` returns each
holder's committed size (its own retractions and later `none` folded out;
withheld bytes return nothing); `list_holders(sha) -> Vec<String>` is the
key-only read. PyO3 `list_holders_sized_json`.

A public `store_blob_local(sha, bytes, media_type)` (#863): the
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
not held, the row is admitted and the rule is the node's. A rendition's holding
claim is placed at its own content's scope, exactly as its original's, so
`self` / `family` renditions stay structurally invisible
(`is_structurally_invisible`).

`role` is the struct's `name` when it parses as one of `thumbnail`,
`poster`, `transcode`, `caption_track`; else `other`. A rendition's
`digest` must differ from its `derived_from` (a blob is not its own
rendition).

## 6. Lifecycle, by door

| door | what it does |
|---|---|
| local write (both backends) | `check_media_source`; `blob_renditions` projection |
| federation ingest (both) | `check_media_source`; the holding-claim size refusal; projection |
| promotion chokepoint | `check_media_source` (a local row does not cross without passing it) |
| `put_blob_with_scope` / `adopt_sealed_blob_at` (2 backends) | the claim carries the stored byte length; adopt refuses to announce a size ≠ the length it stored |
| `list_holders_sized`, `list_derived`, `store_blob_local` | reads / the LocalOnly plaintext door |
| envelope vocabulary | `paths::MEDIA`, pinned |

## 7. Invariants

- **I115** — a malformed struct is refused by name at every door:
  missing `size`, `size: 0`, missing `format`, `format: "Image/JPEG"`,
  `format: "image/jpeg; q=1"`, `video/mp4` without `codec`, a `name` with
  `/` or a control character, a `placeholder` over the cap, an unknown
  member, and each of `safe` / `renderable` / `tier` / `crypto_tier` /
  `render_tier` (the CC 5.3.2.6 refusal names the rule). A well-formed
  struct is admitted on both backends.
- **I116** — `digest` not in `evidence_refs[]` is refused; `captions` not
  in `evidence_refs[]` is refused; `evidence_refs` entries stay strings —
  a row with an object entry is refused by `envelope_binds_content`'s
  reading (pinned, so the object shape cannot creep in).
- **I117** — a holding claim without `size`, or with `size: 0` /
  `"12"` / `-1`, is refused at ingest on both backends; the claims the
  two blob doors write carry the exact stored length; `list_holders_sized`
  returns it; a two-node delivery (the #870 I113c shape) carries the size
  to the peer.
- **I118** — a row with `derived_from` projects one `blob_renditions` row
  in the same write on both backends; `list_derived(original)` returns
  it; retiring the row removes it; a rendition at a different
  `cohort_scope` than a locally held original is refused; a rendition whose
  digest equals its `derived_from` is refused.
- **I119** — from disk: every blob write door stores `size` and the
  validated `format` into `federation_blobs` (`size_bytes`, `media_type`),
  and the claim a peer receives carries `size` — the local column alone
  proves nothing to a peer; the gate call appears at every door; the vocabulary manifest lists `paths::MEDIA`.
- **I120** — the vocabulary hash is pinned: the test asserts
  `ENVELOPE_VOCABULARY_SHA256 == envelope_vocabulary_sha256()`.

## 8. Not in scope

- Sniffing, the render tier, renditions' production (the node).
- `evidence_refs[]` entries as objects (contradicts CC 3.3.13; breaks
  every reader).
- Changing `list_holders`'s signature.
- `settlement:*` and hop/TTL (#672).

## 9. `sealed_descriptor` — the description inside the seal (CIRISPersist#922 / #923; CIRISConstitution#114)

**The rule (CC 3.3.13, CIRISConstitution#114).** In CC 3.3.13's encrypted
two-hash case, `name`, `format` (and `codec`) live INSIDE the seal; `size`,
the address digest, the room target, `content_digest` and `placeholder` stay
in clear. "May read the name" and "may open the bytes" are one fact: the
descriptor is sealed under the SAME DEK the bytes were sealed under (the
pointer's tier / community / epoch), never an edge-derived key.

### 9.1 The struct

```
media := {
  … (as §3) …
  format              string  REQUIRED iff sealed_descriptor is ABSENT
  codec               string  as §3, iff format is present in clear
  name                string  optional; FORBIDDEN beside sealed_descriptor
  sealed_descriptor   string  optional; standard base64 of an AtRestEnvelope
                              (magic ‖ nonce ‖ ciphertext‖tag) over the JCS bytes of
                              {name, format, codec?}, AES-256-GCM under the blob's DEK,
                              AAD = the persist-framed address digest (§9.3)
}
```

Exactly one description: a struct carries `format` (+ `codec`) in clear XOR
`sealed_descriptor`. `KNOWN_MEMBERS` includes `sealed_descriptor` (15). The
member belongs to `paths::MEDIA`'s object, not the envelope vocabulary: the
vocabulary lists the `media` member, not its keys, so
`ENVELOPE_VOCABULARY_SHA256` does not cover it.

### 9.2 The gate (`check_media_source`, every door)

Four shapes, one parser, refusals by member name (`Error::MediaSourceInvalid
{ member, reason }`):
1. clear `format` (+`codec`), no seal — admitted;
2. `sealed_descriptor` present, `format`/`codec`/`name` ABSENT in clear —
   admitted iff the seal decodes (base64) to an at-rest envelope of at least
   `magic + nonce + tag` bytes; persist NEVER opens it (no DEK on the row
   plane) and never sniffs (CC 5.3.2.6 runs where bytes decrypt);
3. neither — refused, member `format`;
4. both a seal and clear `format` or `codec` — refused, member
   `sealed_descriptor`, reason `one description: format/codec in clear beside
   a seal`; `name` in clear beside a seal — refused, member `name`, reason
   `the name lives inside the seal` (CC 3.3.13 two-hash case).
`size`, `digest`, the room target, `content_digest`, `placeholder` are
required/checked BEFORE any hashing (CC 5.3.2.5 / AV-88).
`MediaSource.format` is `Option<String>`; the blob
write doors store `media_type` only when it is in clear (a sealed row's
`media_type` is NULL — a reader learns it after the DEK opens; I119's
"validated format" clause reads "when present in clear").

### 9.3 The doors (#923) — `Engine::seal_descriptor_for_blob` / `open_descriptor_for_blob`

Edge never holds a DEK. Two Engine doors seal/open small caller bytes under
an EXISTING blob's DEK:

```
seal_descriptor_for_blob(at_rest_sha256, key_id, plaintext_jcs) -> Result<Vec<u8>, BlobError>
open_descriptor_for_blob(at_rest_sha256, viewer_key_id, sealed)   -> Result<Vec<u8>, BlobError>
```
- The row says what the blob is (its recorded tier, §11.1); the caller is
  authorized exactly as `read_blob_as` authorizes a viewer
  (`authorize_viewer_by_tier`, then `refuse_if_withdrawn`): a stranger is
  `NotGranted` and learns nothing; a withdrawn blob refuses; a PLAINTEXT
  row is `InvalidArgument` (nothing to seal under — the description of a
  plaintext blob is in clear by construction).
- The DEK is the blob's, recovered by the tier's own resolver
  (`recover_blob_dek_for_viewer` for the invisible tier;
  `community_dek_has_member_grant` + `recover_epoch_dek_for_viewer` for a
  community row) — one resolver per tier, shared with the bytes read, so
  "may open the descriptor" ⇔ "may open the bytes" by construction.
- AAD = `b"ciris.sealed_descriptor.v1" ‖ at_rest_sha256` (persist-framed,
  domain-separated from the bytes' own AAD, so a descriptor lifted onto
  another blob, or the blob's ciphertext presented as a descriptor, does not
  open). The seal is `seal_aad`; the open is `open_aad`; the envelope is the
  on-disk `AtRestEnvelope` byte layout, returned raw (the producer base64s it
  into the struct).
- Plaintext cap: a descriptor over 4 KiB is refused at the seal door
  (`InvalidArgument`) — it is `{name, format, codec?}`, not a payload.
- pyo3: `seal_descriptor_for_blob(sha256_hex, key_id, plaintext: bytes) -> bytes`,
  `open_descriptor_for_blob(sha256_hex, viewer_key_id, sealed: bytes) -> bytes`;
  refusals keep `read_blob_as`'s Python types.

### 9.4 Invariants

- **I121** — the four shapes of §9.2 on sqlite and postgres at the
  ingest door and the local door: (1) admitted; (2) admitted, stored
  `media_type` NULL; (3) refused `format`; (4) refused `sealed_descriptor`
  (both) and `name` (name beside seal); a seal that is not base64, or decodes
  short of the envelope header, is refused by member `sealed_descriptor`.
  `ENVELOPE_VOCABULARY_SHA256` does not cover the member (the pin test
  holds with or without it).
- **I122** — the doors: a member of the room seals `{name, format}` for a
  community-sealed blob and opens it back; a non-member is `NotGranted` on
  both doors and learns nothing; the invisible tier likewise for its owner
  vs a stranger; a plaintext row is `InvalidArgument` on both; a withdrawn
  blob refuses the open; the descriptor sealed for blob A does not open
  against blob B (AAD); the blob's own ciphertext presented as a descriptor
  does not open (domain separation); a 4 KiB + 1 plaintext is refused at the
  seal.
- **I123** — end to end through the real doors (two nodes): the producer
  seals the descriptor, writes the row with `sealed_descriptor`, the row
  replicates, the second node's member opens the descriptor and reads
  `format`; the same node's non-member sees the row (size, digest, room) and
  cannot open the descriptor.
- **I124** — from disk: the gate call is at every door; every
  blob write door's `media_type` store reads the clear `format` only.

### 9.5 Readers

A `file:v1` row whose `content` pointer carries `sealed_descriptor` has no
`media` member, so the gate never sees it. A `media` struct with no clear
`format` is admitted only by a reader that implements §9.2; a producer emits
the sealed `media` struct only once every reader it serves does
(CIRISEdge#698; CIRISNodeCore's MEDIA_SHARING schema and CIRISServer's FileRef
read the description after the DEK opens).

### 9.6 Not in scope

- Moderation / de-admission / revocation addressed by key fingerprint
  (#784): a wire-vocabulary change on three planes (`revoked_key_id` and the
  moderation subject fields would carry a second identifier form) and a
  CC §4.5.1 Standards Action. Tracked on #784.
- The disclosure store (#914): its own FSD.

### 9.7 Mutation table

| # | Mutant | Verdict | Killed by |
|---|---|---|---|
| S1 | one-description rule dropped | KILLED | media_source::tests::a_sealed_descriptor_is_one_description_and_never_opened |
| S2 | descriptor AAD dropped at the seal | KILLED | v51_invariants::descriptor::postgres::i122, v51_invariants::descriptor::sqlite::i122 |

S3 (a plaintext row sealable) is not a clean single-site mutant: the plaintext arm is one `match` arm whose only alternative is the refusal I122 asserts on both doors.
