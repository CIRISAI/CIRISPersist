# FSD: Blob Replication — the holder plane, and the decision to hold

**Status:** §1–§10 implemented in v44.2.0 (design locked 2026-09-14; the
operator's party-to correction applied before the build reached §4).
§11–§18 (key transport, #848) locked 2026-09-15 for v44.3.0.
**Author:** Eric Moore (CIRIS Team) with Claude Fable 5.1
**Created:** 2026-09-14
**Repo:** `~/CIRISPersist`
**Companion to:** CIRISServer `FSD/CEG_REPLICATION_MODEL.md` (the ATTESTATION
plane — Server-owned, implemented here as `replication_policy.rs` and pinned by
`REPLICATION_POLICY_HASH`) and `FSD/BLOB_ENCRYPTION_AT_REST.md` (what a blob
IS at rest). Neither covers what this one does: how a blob **moves**, and who
decides to **hold** it.
**Risk:** Additive doors and one behaviour change on accept — non-party
content is now refused — stated in §10. No on-disk format change to existing
rows; one new nullable column.

---

## 0. Why this exists, and what it is not

There are two replication planes and until today only one had a specification.

The **attestation plane** is specified: state changes only via a hybrid-verified
claim by a signer resolved against our own directory, admitted through one
Registry-of-Record keyed on a closed `EnvelopeKind`, with projections
maintained in the admit transaction (`CEG_REPLICATION_MODEL.md` §0, §4). That
model is implemented and hash-pinned; it is not restated here.

The **holder plane** — blobs, `holds_bytes`, the fountain swarm, disk pressure,
who relays what — was implemented across four module docs and never written
down as one model. Three consumers are now building against it at once
(CIRISEdge#601 pull-on-attestation, CIRISServer#594 N-member rooms,
CIRISPersist#843), and the audit that produced this document found the model
they would each have to reconstruct is **incomplete at the one point that
matters for the light-up**: a node has no door through which to store a sealed
blob it received from a peer (§3). Everything else here exists in some form and
is being written down; §3 and §4 are new.

This document does not re-decide the at-rest design. Every reference to a tier,
a DEK, an envelope or an invariant numbered I1–I44 means what
`BLOB_ENCRYPTION_AT_REST.md` says it means.

## 1. The model

**Attestations flow first; a blob is a projection of an admitted attestation.**
`blob_swarm/meaning.rs` on Edge says it in one line — *no blobs without CEG
envelopes signed by someone; that is an invalid state* — and persist's shape
already enforces the half it can see: `put_blob` refuses a body with no
attestation, `read_blob_as` dispatches on the row the write door resolved, and
scope is never an input a caller asserts (§11.2 of the at-rest FSD). A blob's
meaning — its author, its cohort, its community, its tier — is **read off the
attestation that references it**, then carried onto the row. It is not
re-derived from the bytes and not trusted from the sender.

**Blobs are pulled, never pushed to their audience.** The attestation is both
the authorization to fetch and the only way a node learns the bytes exist
(CIRISEdge#601). The holder plane is the discovery surface:

| primitive | what it is | normative source |
|---|---|---|
| `holds_bytes:sha256:<prefix>` | the ONE claim "I hold these bytes", a signed attestation like any other, emitted by `put_blob*` and suppressed by `store_blob_local` | CC 3.1.9.1, CC 5.2 |
| 24 h TTL from `asserted_at` | a holder claim goes stale on its own; `list_holders` filters it | CC 5.3.2.1 |
| `ContentMiss` → `withdraws` | a holder that no longer has the bytes is withdrawn by the CONSUMER that missed, `withdrawal_reason: content_miss` | CC 5.3.2.1 |
| eviction → `withdraws` | a holder that evicts announces it; eviction is never silent | `replication/mod.rs`, CC 4.4.2 item 2 |
| `FountainContent` projection | `SelfOwn` for self/family, `Cohort` for community/affiliations and non-root commons, `Global` only for trust-root commons | `namespace/mod.rs::projection_for`, #713 |
| tombstone ceiling | a retraction on this plane reaches `Cohort`, or `Global` for a trust root — the row-max, so it reaches every holder a copy could have reached and nobody beyond | `tombstone_ceiling`, #713 |

Under ~20 members most nodes will end up holding most of a community's corpus.
That is a consequence of everyone pulling what they are audience for; it is
not a push, and the model must not be implemented as one.

## 2. Contextual integrity — what the wire already says, and what persist may claim

The CIRIS treatment of privacy is Nissenbaum's: *the appropriate flow of
information*, not secrecy. The wire format carries the five parameters of a
flow as fields, and every one of them is something a holder reads **without
opening the content**:

| parameter | wire field | on the holder plane |
|---|---|---|
| sender | `attesting_key_id` | the author of the referencing attestation — the **provenance** a holder keeps or evicts on (§5) |
| data subject | `subject_key_ids` | who may revoke; a `withdraws` reaches every holder at the ceiling |
| recipient — see / revoke / receive | `cohort_scope` / `subject_key_ids` / `delivery_mode` | `cohort_scope` decides the tier and the projection; **audience** is Edge's axis 2 (§4) |
| information type | `dimension` | admitted at the attestation plane, never re-judged here |
| transmission principle | `consent:scope` | retain / share / … — the operator's consent to hold a CLASS is Edge's axis 3 (§4) |

Two bounds from the Constitution govern every sentence persist writes about
this plane:

- **CC 1.13.3** — "privacy" means exactly *content-holding confidentiality*
  and *cohort-scoped visibility*, and nothing more. Persist's docs say
  "structurally invisible" for self/family (correct: CC 5.2, no holder claim is
  ever emitted) and never "unobservable", "undiscoverable" or "metadata
  private". The audit swept `blobs.rs`, the cascades, `namespace/mod.rs`, the
  replication modules and the at-rest FSD and found no overclaim. §8 adds a
  doc gate so one cannot arrive later.
- **CC 4.4.3.2.1, the holder-inspectability principle** — *any data a host
  holds above local tier MUST support an informed keep/evict decision*: a
  Commons holder inspects the bytes; a Community holder inspects the
  **cleartext provenance** on the `holds_bytes` emission (`attesting_key_id`,
  `community_id`, reason). This is the Constitution's own statement of the
  decision §4 builds. It also says, at rc5 (2026-09-09, the correction persist
  reported as #824), that a community "is not therefore plaintext-by-default:
  its content is encrypted at rest under a per-community DEK, and what
  federates with each `holds_bytes` emission is cleartext provenance, not
  cleartext bytes."

Persist's vendored namespace is the rc5 branch head, byte for byte
(`VENDORED_CC_VERSION = "1.0-rc5"`, verified 2026-09-14). Main is at rc4; rc5 is
the latest text and is fifteen commits ahead of it.

## 3. The finding: there is no door to adopt a received sealed blob

A member of community C reads a chat row on its own node. The row carries a
`BlobPointer` to bytes sealed under C's epoch-E DEK on the author's node. The
member's node fetches those bytes from a holder — the transfer path ships the
ciphertext verbatim and never decrypts (I36). Now it must **store** them.

Every write door persist has is wrong for that:

| door | what it does with received envelope bytes |
|---|---|
| `put_blob` / `put_blob_signing` / `put_blob_chunks` | stores them as a **plaintext-tier** row with no epoch binding. The row then says `crypto_tier = plaintext`, and `read_blob_as` dispatches on the row (I2), so the bytes are served as if they were content — or refused by the floor as a self-contradicting row (I25). Either way the member never opens them. |
| `put_blob_scoped` | takes **plaintext** and seals it under THIS node's current epoch. The receiver does not have the plaintext, and if it did, re-sealing is exactly what "sealed once, wrapped per recipient, never re-encoded" (#826) forbids. |
| `store_blob_local` | commons/self only; announces nothing; same tier problem. |

This is consistent with what Edge observed from the other side: on every
non-author member the transcript is pointers to bytes the node never asked for,
reading `Body::Unopened`, and the two-party ladder "passes because it does not
look" (CIRISEdge#601). No sealed blob has ever been stored by a node that did
not seal it. The pull mechanism Edge is building has nowhere to put what it
pulls.

The door is **`adopt_sealed_blob`** (§6.1): store a received `AtRestEnvelope`
verbatim at the tier and under the `(community, epoch)` binding its
provenance declares, addressed by the SHA-256 of the ciphertext, and announce
that we hold it. It is the receiver-side twin of `serve_blob_to_peer`, and like
it, it contains no `open(` — a from-disk gate (I45) holds that.

Two rules that follow from the model and are easy to get wrong:

- **The binding is the author's fact, not ours.** I17 says a *write* must bind
  the current epoch. An *adopt* records the epoch the bytes were sealed under,
  which may be past, and may be an epoch this node holds no grant for — a
  member admitted after epoch E is party to the community and may hold E's
  bytes for the members who can open them (§4), without a grant of its own.
  Reads then behave exactly as for any row at that tier: a viewer with a grant
  opens; anyone else gets the typed refusal (`NotGranted`, or `Evicted` if it
  was swept). Adopt does not consult key state and does not require the epoch
  to be current. What it does require is that this node be **party to** the
  cohort (§4) — a node outside the community never adopts its bytes.
- **A stream chunk keeps its original owner.** I41 says a stream belongs to its
  first append. Across nodes the first append is the author's, so an adopted
  chunk's stream row records the AUTHOR's derived key as `owner_key_id`, never
  the adopter's (I50). A node that adopted a stream cannot then append to it as
  if it owned it.

## 4. The decision to hold — two halves, one question

> *We decide whether we will accept a blob that we **may** hold, based on
> backpressure and role.*

That sentence has two verbs and they are decided by two parties.

**MAY** is Edge's store gate (`admit_blob_store`, CIRISEdge#581, built in edge
v23.1.0), three axes in the operator's order — *trust first, then whether we
MAY accept, then whether we SHOULD*:

1. **provenance** — is this sender approved for this tier? (a valid signature
   is not authorization; commons is an allowlist)
2. **audience** — are we in the audience the content declares? (asked of
   persist's own rosters, so it is unforgeable by the sender)
3. **operator consent** — did this operator agree to hold this class at all?

It returns a trichotomy, because persist has two write doors that publish
different things: `StoreAndAnnounce`, `StoreLocalOnly`, or `Refuse(axis)`.
Nothing in persist re-derives any of the three; a second "may I hold this"
predicate would drift from the first, and Edge#581 says so.

**WILL** is persist's, and it is the half this document adds. Given content we
MAY hold, do we hold it *now*, on *this* node:

| input | source | rule |
|---|---|---|
| **backpressure** | the cached `DiskPressureSnapshot` (#149) | at `Stop` and tighter, non-local, non-family content is refused with `DiskPressureProxyRefused { operation: "accept" }`; local and family content is **never** refused ("don't block local writes ever") |
| **party** | `is_audience(directory, provenance)` — this node's own rosters | **a node never holds content it is not party to.** If no cohort this node belongs to may access the attestation that grants possession and view of the blob, the adopt is refused, typed `NotPartyTo`, always. There is no relay exception and no serve-role exception. Commons is party-to for everyone and plaintext, so the holder inspects the bytes. |
| **role** | `resolve_serve_tier(directory, our key, our key)` (#788) | governs the **breadth** of holding, never permission. A node with serve standing (`ServeTier >= MeshServer`) is a *server*: it holds content it is party to but did not create and does not itself need, so other members of the cohort can fetch it. A node without serve standing holds what it reads. Exposed as `hold_breadth() -> OnDemand | ForCohort` for Edge's pull scheduler; `would_hold` does not consult it. |
| **provenance class** | the author key on the meaning, against the local/family predicate | decides whether backpressure applies (§5 records it on the row) |

The order is: MAY before bytes move (it is Edge's, it precedes the fetch);
WILL at the door, after the bytes arrived and their hash verified, before the
row is written. Within WILL, **party before pressure**: a permanent refusal is
named before a transient one, so a caller never retries a `NotPartyTo` as if
the disk might clear. WILL is cheap — one cached snapshot, one directory read for the
serve tier — and its refusals are typed, name the axis, and disclose nothing
about the content (I4b's class).

**Why "party to" is the rule, and why it is stricter than the Constitution's
floor.** CC 4.4.3.2.1 permits non-member holders of community content — they
keep or evict on cleartext provenance without reading. Persist chooses not to
be one. **We never store data we are not party to**: every blob this node
holds is one it could open and inspect, because it is a member of a cohort
the granting attestation admits, or the content is commons plaintext. That is
how a node avoids storing illegal or immoral content *unknowingly* — not by a
trust score (which #737 notes defaults to zero) and not by a relay role, but by
never holding bytes it has no standing to look at. The Constitution's
provenance-only keep/evict is the floor for the federation; this is persist's
posture on it, and it is the stricter one.

"Server" does not loosen this. A server is a node that holds what it is party
to but did not create and does not need, for the cohort's benefit — breadth,
not permission.

## 5. Author is not holder

The blob row carries no author. Provenance lives on the referencing attestation
(right — that is the CEG-native place) and the `holds_bytes` row names the
HOLDER, which for anything this node stores is this node. So the one predicate
that classifies content as *proxy* — "no local `holds_bytes` attester is
local-or-family" — is true of nothing this node adopts: the holder is always
us. Every adopted blob would classify as protected, never force-evicted first,
never refused under pressure. The #149 doctrine would be intact at its site and
void at the next.

The fix is one nullable column, written by every write door and read by one
predicate:

- `federation_blobs.author_key_id` — the `attesting_key_id` of the attestation
  the blob is a projection of. Local writes record the local signer (the value
  I23 already derives); `adopt_sealed_blob` records the provenance it was given.
  Nullable only for rows that predate the column; V144 backfills what it can
  from the epoch binding's community write and from the local signer, and
  leaves the rest NULL, which the predicate treats as *unknown* → proxy
  (fail-toward-evictable, never toward protected).
- `is_proxy_content(row)` — ONE predicate: `author_key_id` is not
  local-or-family (content we are party to but hold for others; non-party
  content is never present, §4). It replaces the holder-attester scan in the force-evict sweep, the serve
  refusal and the accept decision, so all three agree by construction (I49).

## 6. The doors

### 6.1 `Engine::adopt_sealed_blob`

```rust
pub async fn adopt_sealed_blob(
    &self,
    envelope: &[u8],                 // the AtRestEnvelope, verbatim
    provenance: BlobProvenance,      // author_key_id, cohort_scope, community_key_id, epoch, tier
    aad: Option<&[u8]>,              // carried, not opened here; recorded so a later read can bind
    disposition: AdoptDisposition,   // Announce | LocalOnly — Edge's trichotomy, carried not re-derived
) -> Result<AdoptOutcome, BlobError>
```

1. `sha256(envelope)` is the address; a caller-supplied expected hash, if any,
   must match or `HashMismatch`.
2. The WILL decision (§4) runs against `provenance` and the pressure snapshot;
   a refusal is typed and nothing is written.
3. The floor stores the row with `crypto_tier` = the provenance's tier,
   `cohort_scope` as declared, `author_key_id` as declared, and — for
   `CommunityDek` — the `(community, epoch)` binding **as declared**, in the
   same transaction (no key-state precondition; §3).
4. `Announce` emits `holds_bytes` signed by THIS node with the cleartext
   provenance CC 3.2 requires; `LocalOnly` emits nothing.
5. There is no `open(` in this door or anything it calls (I45).

Idempotent on the address: a second adopt of the same ciphertext is a no-op on
the row and re-emits the holder claim (the same first-write-wins the other
doors have).

### 6.2 `Engine::adopt_sealed_chunk`

The per-chunk twin for a DAG: the same five steps per envelope, plus the
stream row written insert-if-absent with the AUTHOR as owner (I50) and each
chunk's `seq` as declared. The sealed v2 manifest is adopted as a blob like any
other; the manifest's `stream_id` and per-chunk `seq` are what a later
`read_stream_chunk_as` binds against, unchanged.

### 6.3 The WILL decision as a door of its own

`Engine::would_hold(provenance) -> HoldDecision` exposes §4's predicate without
writing, so Edge can ask *before* fetching whether the fetch is worth making
under current pressure — the same "one predicate, asked twice" shape Edge#601
asks for on its side. The adopt doors call the same function; there are not two
copies (I46).

### 6.4 What does not change

`put_blob_scoped` keeps its contract (local author, current epoch, I17). `put_blob`
stays the commons form. `serve_blob_to_peer` is untouched except that its
proxy classification now reads `is_proxy_content` (§5).

## 7. Invariants — each falsifiable through a consumer-held door

Numbering continues the at-rest series (I1–I42) and #840's (I43–I44).

| # | invariant | falsified by | gate |
|---|---|---|---|
| I45 | The adopt path never decrypts: `adopt_sealed_blob`, `adopt_sealed_chunk` and everything they call contain no `open(`, `open_aad(`, `unwrap_dek` or `read_any` (from-disk, the I36 shape). | a receiver that peeks at what it relays | `blob_surface_gates` |
| I46 | The WILL decision runs on every consumer-reachable accept door and exists in exactly one place: `adopt_sealed_blob`, `adopt_sealed_chunk` and `put_blob_signing` all call `would_hold`; no other site reads `refuses_proxy_writes` (from-disk). | a door that accepts under `Stop` | `blob_surface_gates` |
| I47 | Under `Stop` pressure a non-local, non-family adopt is refused `DiskPressureProxyRefused { operation: "accept" }` and nothing is written; a local or family adopt succeeds at every tier. | a full disk that still takes relay content; a node that refuses its own family | behavioural, both backends |
| I48 | A node never adopts content it is not party to: a non-audience adopt is refused `NotPartyTo`, typed, regardless of serve standing; an audience adopt succeeds regardless of serve standing; `would_hold` contains no `resolve_serve_tier` / `ServeTier` read (from-disk). Role reaches consumers only as `hold_breadth()`. | a relay holding a community's bytes without membership; a member refused its own community's bytes; a serve-role node admitting non-party content | behavioural + from-disk |
| I49 | `is_proxy_content` is the one classification — *party to, but the author is not local-or-family* (held for others): the force-evict sweep, `serve_blob_to_peer` and `would_hold` all call it; an adopted blob authored elsewhere classifies proxy; a `NULL` author classifies proxy. | an adopted blob that survives a force-evict; a proxy blob served under `Stop` | from-disk + behavioural |
| I50 | An adopted stream chunk's stream row records the AUTHOR's derived key as owner; a later append by the adopter is refused as a foreign writer (I41 carried across nodes). | a relay that takes over a stream it holds | behavioural |
| I51 | An adopted `CommunityDek` blob is readable by a viewer holding a grant for its declared epoch and refused `NotGranted` for one who does not, with no key state for that epoch on the adopting node required for the adopt itself. | an adopt that needs the receiver to already be a member; an adopted blob that opens for anyone | behavioural |
| I52 | `Announce` emits this node's `holds_bytes` claim (the unchanged v31 envelope — embedding provenance would move its preimage) and the row carries the cleartext provenance beside it (`author_key_id`, `community_key_id`, readable through `blob_provenance`); `LocalOnly` emits nothing; self/family provenance can never `Announce` (CC 5.2, refused before the floor). | a holder claim with no provenance a member can keep/evict on; an announced family blob | behavioural |
| I53 | No source or FSD text in the blob and replication modules claims "unobservable", "undiscoverable", "metadata privacy" or "traffic-analysis" resistance (CC 1.13.3; from-disk). | a docstring that overclaims | `blob_surface_gates` |

Each is written RED before the code that makes it green, and each load-bearing
check is mutated once to prove the witness measures it and not a neighbour.

## 8. Docstrings this cut corrects

- `FSD/BLOB_ENCRYPTION_AT_REST.md` §10.6 — "until CIRISEdge#581 lands" is
  stale: the gate is built (edge v23.1.0); arming it over the converger's push
  path is CIRISEdge#601, and until then the recall reach is still *intended,
  not enforced*. Re-pointed.
- `src/federation/replication_policy.rs` — cites `FSD CEG_REPLICATION_MODEL.md`
  without naming the repo; it is CIRISServer's. Named.
- `src/federation/replication/mod.rs` — "trust-weighted admission gate" now
  states the #737 posture (an unconfigured gate is a threshold of zero) and
  points here for the accept decision.
- `src/federation/replication/disk_pressure.rs` — the Stop tier's "refuse to
  ACCEPT new federation-proxied content" names the door it is enforced on and
  the role axis beside it.
- `Engine::put_blob_signing`, `Engine::serve_blob_to_peer` — proxy
  classification now described as author-and-audience, not holder-attester.

## 9. Cross-repo

- **CIRISEdge** (#601): after `admit_blob_store` returns `StoreAndAnnounce` or
  `StoreLocalOnly`, fetch, then call `adopt_sealed_blob` (or the chunk twin)
  with the `BlobMeaning` provenance and the disposition — carried, not
  re-derived. `would_hold` is available before the fetch; `hold_breadth`
  tells the pull scheduler whether this node pulls the cohort's corpus
  (server) or only what it reads (member). The FountainContent
  ceiling narrows to `Cohort` when the store gate is armed, as #601 gap 2 says.
- **CIRISServer** (#594): nothing new is required of Server for this cut. #843
  ships beside it.
- **CIRISConstitution**: nothing to amend. CC 4.4.3.2.1's holder-inspectability
  principle is the normative basis for §4; CC 5.3.2.1 for the holder TTL and
  `ContentMiss`; CC 5.2 for the `Announce` refusal on self/family.

## 10. Versioning

**v44.2.0**, MINOR. Additive: the three doors, `BlobProvenance`,
`HoldDecision`, `NotPartyTo`, `hold_breadth`, `federation_blobs.author_key_id`
(V144, nullable). One behaviour change, stated: a node now refuses to accept
content it is not party to — no cohort it belongs to may access the granting
attestation — on `put_blob_signing` as well as the new doors. Today that
content is accepted by anyone above a trust threshold that defaults to zero.

---

# Part II — Key transport (#848): the key follows the bytes

## 11. The fork, and the ruling: an epoch belongs to its minter

v44.2.0 gets the bytes to a member's node and not the key. The per-epoch
wraps and the per-blob grants are written only by the author node's cascade
into local tables; nothing carries them. Before carrying them, CIRISEdge's
review of this issue (verified in-tree) showed the epoch itself was not one
thing: `federation_community_dek` is keyed `(community, epoch)`,
`ensure_epoch_dek` mints from the **local** self-retention row, and
`community_dek_bump_epoch` has one production caller (the revoker). Two
members writing at the same epoch number mint two random DEKs both labelled
E; the grant table holds one. The Constitution rules this a **fork by
definition**: a ledger MUST declare its serialization discipline — a write
lease, or per-delegate sub-ledgers folded deterministically — and
concurrent unleased writes at one sequence number are a fork (ledger clause
3; part 3 composition; CC 5.3.3 for streams).

**Ruling: per-minter epochs.** The stream rule (I41) applied to the key
layer. An epoch belongs to its **minter** M — the occurrence whose cascade
minted it. Key state, self-retention and grants are keyed
`(community_key_id, minter_key_id, epoch)`; a blob's key identity is
`(community, author, epoch)`, and the author is already on the row
(`author_key_id`, §5). Each minter owns its counter: the local bump on
admitting a removal is correct by construction, the signer rule falls out
(M signs M's counter), and nothing consumes "one DEK per community epoch".
The write-lease shape was rejected: more surface for a property nothing
reads. In the Constitution's steady state, where the content DEK derives
from the MLS exporter (CC 5.4), the minter becomes the leaseholder
committer with no schema change here; the lease lives at the agreement
layer (CIRISEdge#604), which is where TreeKEM already needs one.

## 12. The carrier is the Constitution's `key_grant`, on a replicated kind

The wire object exists. CC 3 defines **`key_grant`** as a Contribution
subject_kind — `wrapped_dek` (base64url, under the recipient's encryption
pubkeys), `wrap_algorithm` (`x25519_mlkem768_aes256_gcm_hkdf_sha256`,
mandatory), a supersession lineage — and CC 5.1 names its two addressing
axes: **content-addressed** `(content_sha256, recipient)` and
**epoch-addressed** `(stream_id, epoch[, recipient])`, "the same
supersession reused on the new axis". Persist does not invent a dimension;
it gives that object a replicated kind.

**`EnvelopeKind::KeyGrant`** — the sixteenth kind, appended (the order is
hashed). One envelope carries one **set**:

| axis | identity | `wraps[]` | who signs |
|---|---|---|---|
| epoch (community / affiliations) | `(community_key_id, minter_key_id, epoch)` | every recipient occurrence M could wrap to at emission | M's occurrence key |
| content (self / family) | `(at_rest_sha256, cohort_scope, owner_or_family_key_id)` | every recipient occurrence of the self-collective / family | the blob's author |

Each `wraps[]` entry is `{ recipient_occurrence_key_id, wrap_algorithm,
wrapped_dek }`. The envelope is opaque to everyone but each recipient; a
member is party to the community, so a node stores the whole set (§13) and
a late device can be served the set by any member.

**Registry-of-Record row** (`policy_for`): signer `RegisteredSigner`,
binding `SelfOwn` (the minter signs its own counter; the author its own
blob), `PopOnInsert::NotApplicable`, `WireTier::FederationOnly`,
projections `[Projection::KeyGrants]`. **Admission** (the E-edges, CC §0):
the signer is resolved from the admitting node's own directory, never the
sender; on the epoch axis the signer's identity must be an **active member**
of the community at `asserted_at` per the replicated roster fold, and must
equal the envelope's `minter_key_id`; on the content axis the signer must
equal the blob row's `author_key_id` when the row is present, and the set
is accepted before the row arrives (the grant is opaque; order
independence, §13). Any other signer is refused at admission.

**Projection plane.** `projection_for` gains `Plane::KeyGrant { axis }`:
`SelfOwn` on the content axis (self / family), `Cohort` on the epoch axis
(community / affiliations), never `Global`. Grants are never retracted —
forward secrecy is by rotation, and CC 3 says a publisher "retains existing
key_grants (cannot retroactively un-share)" — so the tombstone ceiling is
the row max and no withdraw exists for this kind.

`REPLICATION_POLICY_HASH` moves. CIRISServer re-pins; CIRISEdge adds the
wire kind (its protocol enum mirrors the sixteen names in order).

## 13. `Projection::KeyGrants` — union, idempotent, order-independent

On admission the projection writes, in the admit transaction, every entry of
the set: epoch axis → `federation_community_dek_member_grants (community,
minter, epoch, recipient)`; content axis → `federation_blob_key_grants
(at_rest_sha256, recipient)`. **Union semantics**: a grant, once admitted
for an epoch or a blob, is never removed by a later set. A later set for the
same identity adds what it carries. This is what makes partial emission
safe (§14) and what CC 3's "cannot retroactively un-share" requires. A
recipient that appears in **no** admitted set is `NotGranted` on that node
until a set carrying it is admitted. The projection does not consult the
local keyring: it stores wraps for every recipient, and `read_blob_as`
finds the viewer's row and unwraps with the viewer's private half exactly
as today.

**Implementation note (the build, #848).** The carrier row is admitted
through the attestation plane's own door (`apply_replicated_attestation`:
the hybrid-Strict ingest gate against the receiver's directory, every
`put_attestation` gate, the plan/act convergence outcome) and the grant
rows are then written in ONE transaction of their own
(`community_dek_put_member_grants` / `put_at_rest_grants`). Two ordered
transactions, not one: the projection cannot ride inside `put_attestation`
without either duplicating the minter / member / author rules there or
projecting a `key_grant:*` row that arrived through the generic attestation
door unchecked. A crash between the two leaves a stored row and no grants,
which the next re-emission repairs — the same set re-applied projects on
`Unchanged` / `AlreadyPresentIdentical` as well as on `Inserted`. A
`key_grant:*` row that reaches a node through `apply_replicated_attestation`
instead of `apply_replicated_key_grant` is stored and projects nothing; the
member's read is `NotGranted` until the right door runs — a visible failure,
not a bypass.

**Implementation note (§15, the build).** The revocation door bumps every
counter this node owns when a removal is admitted (materialising a pointer
for a minter that has minted but never rotated), and `ensure_epoch_dek`
disables every enabled epoch of the minter that was minted before the latest
effective removal, so "the old B-epoch is disabled" holds on the door path
as well. The `removed_at > minted_at` compare on the CURRENT epoch remains as
the backstop for a removal that reached the roster without that bump; in
process it is unreachable, and is stated as BELIEVED in the cut's report.

**Implementation note (PR #850 review).** A content-axis set that arrives
before its bytes is *admitted and not projected*: the blob row is what names
the author, so until it exists the signer cannot be checked against the
author, and a recipient who knows the DEK could otherwise grant an outsider by
speaking first. The carrier row is stored (`KeyGrantAdmission.pending`), and
the adopt path — the moment the row names its author — projects every stored
content set the author signed (`project_pending_content_grants`); a set
signed by anyone else stays a stored attestation and grants nothing. Order
independence is kept by reconciliation, never by projecting an unverifiable
set (I65). The epoch-axis membership check folds occurrence revocations at
the row's `asserted_at`, as the community-removal fold does; the attestation
plane's cohort gate asks about the signer *now* and must stay there —
`asserted_at` is signer-chosen, and a revoked occurrence must not regain
admission by back-dating (I60b).

**Implementation note (PR #850 review, round two).** The pending index
(`federation_key_grant_pending`, V146) is keyed `(at_rest_sha256,
cohort_scope)`: admission records a pending set there and the adopt takes
its own rows, never scanning an author's attestations. Admission re-reads
the blob's provenance *after* the carrier row lands: an adopt that stored
the row and took the index between admission's first look and the carrier's
insert would otherwise leave the set unprojected — with the re-read, every
interleaving projects (the adopt's take sees the index row written before the
re-read, or the re-read sees the adopt's row).

## 14. Emission: the full set, every time, supersedable

- **Epoch axis.** When `ensure_epoch_dek` mints (C, M, E), and after every
  fan-out that granted a new recipient, the minter emits one `KeyGrant`
  for (C, M, E) carrying **every** grant it holds for that epoch — the full
  enumeration, not the delta — through the normal attestation store, so it
  replicates by the Cohort projection like any admitted row. A node that
  dies mid-fan-out re-emits the full set on its next write. Re-emission is
  idempotent on every receiver (§13).
- **Content axis.** After `encrypt_and_cascade` (self / family) the author
  emits one `KeyGrant` for the blob carrying every occurrence grant.

**Implementation note (PR #850 review).** A retroactive ADD
(`rekey_for_newcomers`, reached by `rekey_family_member_add`,
`rekey_self_occurrence_add` and `self_at_login`) writes new per-blob wraps for
existing self/family ciphertext; it reports each changed blob
(`RekeyResult.changed_blobs`) and the Engine door emits that blob's full
content-axis set (I68). Every Python write door — the two specialized doors
included — emits through one helper (I69).

**Implementation note (PR #850 review, round two) — the emission ledger.**
A door that dies between its cascade's commit and its emission leaves a
durable DEK and wraps and no set on the cursor, and the next write finds the
fan-out unchanged. The ledger is `key_grant_emitted_at` on the epoch's
self-retention row and on the blob row (V146): an axis is DIRTY when never
emitted or when a grant under it is newer than the last emission (the grant
tables' `created_at`, the database's own clock on both sides). `ensure_epoch_dek`
reports `changed` when dirty, so every consumer emits; `emit_key_grant`
marks on success; a skipped emission stays dirty. `Engine::emit_pending_key_grants`
sweeps at every constructor after the sentinel resolves (best effort, logged)
and on demand (I70).

**Implementation note (PR #850 review, round three) — the ledger's stamp is
the snapshot's watermark.** The emitter reads the newest grant's
`created_at` under the axis before building the set and stamps that value on
success (never the clock, never backwards); the dirty predicate is strict
(`stamp < newest grant`), so equality means "carried". The one window the
ledger cannot see — a grant landing in the same millisecond as the snapshot's
newest, after the read — is closed by that grant's own door emitting (I74).
A pending row (§13) is retired only after its projection succeeds or its
verdict is final; a failed projection leaves it for the next adopt. Both
adopt doors reconcile (I72). The retroactive-ADD walk sees only blobs this
node self-retains — a peer-authored blob adopted here is skipped, never an
abort (I65).

## 15. Rotation on admitted removal — every minter, its own counter

CIRISEdge's fact 1 is a present-day forward-secrecy hole across nodes: after
a removal only the revoker's node rotates; every other member's node keeps
sealing under E, which the removed member can still open. Under per-minter
epochs the fix is local and needs no coordination: **a minter rotates its
own counter before its next seal after admitting a removal.**
`ensure_epoch_dek` compares the replicated roster fold's latest
`removed_at` for C against the current (C, M, E)'s `minted_at`; if a removal
is newer, it disables E and mints E+1 before sealing. The revoker's explicit
bump stays as it is. Coalescing per CC 5.1 is unchanged.

**Implementation note (PR #850 review, round two).** The comparison is
against the removal's *effective* instant: a removal admitted with a
skew-window future `effective_at`, and a bump-and-seal in between, mint an
epoch newer than `removed_at` that still grants the member (correctly — the
removal is not yet in effect); at the first seal after `effective_at` that
epoch rotates too (I71).

## 16. Schema — V145, and the sentinel only the running node can resolve

Rebuild (the V136 shape, final name) with `minter_key_id`:
`federation_community_dek_epoch` → PK `(community_key_id, minter_key_id)`;
`federation_community_dek` → PK `(community_key_id, minter_key_id, epoch)`
plus `minted_at`; `federation_community_dek_member_grants` → PK
`(community_key_id, minter_key_id, epoch, member_key_id)`; the V139 key-state
table gains `minter_key_id`; `federation_community_blob_epoch` gains
`minter_key_id` (from the blob row's `author_key_id` where present).

The backfill is exact — every existing row on a node was minted by that
node — but SQL cannot know the node's key. V145 writes the sentinel
`__this_node__`; a boot-time step beside the #840 and #845 repairs resolves
the sentinel to the node's own derived key, idempotently, before any read.
A row still carrying the sentinel after that step aborts the boot.

**Implementation note (PR #850 review).** `Engine::from_shared` /
`from_shared_with_local` are synchronous and cannot resolve the sentinel at
construction (CIRISEdge constructs through them). The backend records that
`repair_minter_sentinel` completed, and every Engine door that touches the
community-DEK plane checks it first — an atomic load thereafter, the same
resolver otherwise; a survivor fails that door with the sentinel named,
never a silently unreadable binding (I66d, I66e).

**Ruling (PR #850 review, rounds three and four) — a pre-V145 binding is its
author's.** V145 binds each pre-V145 blob to the row's `author_key_id` (the
author is the minter) and NULL authors to the sentinel. A node whose signer
rotated since a write does not keep that content under its new key: the
derived key is the occurrence (one-key identity), a rotated signer is a new
occurrence, old epochs belong to the old one, and a new occurrence opening an
old one's epoch without a grant is what the gates forbid. The read refuses —
nothing is stranded silently. Binding by the local DEK instead (tried in
round three) would also mis-bind a pre-V145 adopted blob whose epoch number
collides with a local one. An adopter binding by author is therefore exact.

## 17. Reads

`community_dek_blob_epoch(sha)` returns `(community, minter, epoch)`;
`has_member_grant(community, minter, epoch, viewer)`. `read_blob_as`,
`read_blob_range_as` and `read_stream_chunk_as` keep their signatures; the
tier dispatch (I2) is unchanged; only the binding they consult is wider.

## 18. Invariants — each falsifiable through a consumer-held door, on two nodes

"Two nodes" is two backends, each with its own signer and keyring, connected
only by taking an envelope from one and handing it to the other's apply
door. No shared directory.

| # | invariant | falsified by | gate |
|---|---|---|---|
| I59 | `KeyGrant` is the sixteenth kind with a policy row; `REPLICATION_POLICY_HASH` is re-pinned and the manifest witness holds; the wire table documents it. | a kind without a policy; a moved hash nobody pinned | from-disk + witness |
| I60 | A `KeyGrant` whose signer is not the envelope's minter, or not an active member of the community at `asserted_at`, is refused at admission; the signer is resolved from the admitting node's directory. | a forged wrap set accepted | behavioural, both backends |
| I61 | **The end to end.** A seals a community blob under (C, A, E) and emits its set; B admits the set and adopts the bytes; B's member occurrence opens the blob; a non-member on B is `NotGranted`. | a member's node that holds the bytes and not the key | behavioural, two nodes |
| I62 | The projection is a union and is order-independent: re-applying a set, applying a superset, and applying the set before the bytes arrive all leave every prior grant in place and add the new ones. | a re-emission that un-grants; a grant that arrives before its blob and is lost | behavioural, two nodes |
| I63 | B admits A's revocation of X; B's next seal is under a new B-epoch; the old B-epoch is `disabled`; X is absent from B's new set. | the cross-node forward-secrecy hole | behavioural, two nodes |
| I64 | Two minters at the same epoch number coexist: B's viewer opens A's content at (C, A, 3) and C's content at (C, C, 3). | the fork | behavioural, two nodes |
| I65 | Content axis: the owner's second occurrence on B opens a self blob sealed on A once A's set is admitted on B. | a person's other device that cannot read their own content | behavioural, two nodes |
| I66 | A pre-V145 database resolves every `__this_node__` sentinel to the node's own key at boot, its existing content still opens, and a sentinel that survives aborts the boot. | a silent minter of nobody | behavioural (sqlite + postgres) |
| I67 | No production path removes a grant within an epoch; the only forward-secrecy mechanism is rotation (from-disk: no `DELETE` on the grant tables outside the epoch destroy sweep). | an un-share | from-disk |
| I60b | A set from a minter occurrence revoked after the set's `asserted_at` passes the KeyGrant fold (at `asserted_at`) and is refused by the attestation plane's cohort gate (at now); a set asserted after the revocation is refused by the fold itself. | a revoked occurrence regaining admission by back-dating; or a fold at the wall clock | behavioural, two-node, typed reasons |
| I65 (revised) | A content set admitted before its bytes is `pending` and projects nothing; a forged set from a recipient naming an outsider never projects; the adopt projects the author's set; the outsider stays `NotGranted`. | a recipient granting an outsider by speaking first | behavioural, two-node |
| I66d | An `Engine` built by `from_shared*` over a V145-migrated backend resolves the sentinel at its first DEK-plane door; a survivor fails that door with the sentinel named. | a shared-backend host with silently unreadable bindings | behavioural, sqlite file |
| I66e | Every Engine door that touches the community-DEK plane calls the resolver first (from disk, sixteen doors). | a door added without the check | from-disk |
| I68 | `rekey_self_occurrence_add` names each changed blob and emits its full content set; a second walk changes and emits nothing. | a newcomer device with local grants and no key on its remote node | behavioural, Engine door |
| I69 | Every Python write door — the two specialized ones included — calls the one emission helper (from disk). | bytes stored through Python with no set on the cursor | from-disk |
| I70 | A cascade that ran with no emission (the crash shape) leaves the epoch DIRTY; the next door emits though the fan-out is unchanged; a clean epoch emits nothing more; `emit_pending_key_grants` emits a dirty community once and then nothing. | ciphertext announced, key never carried | behavioural, Engine door + sweep |
| I71 | A removal with a future `effective_at`, a bump-and-seal in between (minted after `removed_at`, before `effective_at`, X still granted), then after `effective_at` the next seal rotates that epoch, disables it, excludes X. | an epoch minted in the skew window kept forever | behavioural, two-node |
| I72 | Both adopt doors project the pending content sets once the row names its author (from disk). | a chunk's set that arrived first, never projected | from-disk |
| I74 | The ledger's stamp is the snapshot watermark: a grant newer than the emitted snapshot keeps the axis dirty; a stamp at the newest grant cleans it; an older stamp never re-dirties. | a concurrent grant hidden behind a wall-clock stamp | behavioural, floor, both dialects' predicate |
| I66 (extended) | A pre-V145 binding authored by an old signer stays the old occurrence's and refuses under the new key; a NULL-author row resolves to the node; an adopted binding keeps its author. | a new occurrence opening an old one's epoch; silent stranding | behavioural, sqlite file |
| I65 (5) | A retroactive ADD on the adopting node skips the peer-authored blob and grants the new device nothing there. | a rekey aborting on adopted content | behavioural, two-node |

## 20. The occurrence that carries the key (#851)

CIRISEdge's mesh harness ran the plane I61 could not: I61 copies each node's
occurrence between two backends by hand, and every receiving node on the mesh
refused every set — `signer_not_active_member`. Three facts, each verified in
the tree at 713dd42:

1. **Admission asked membership about the instrument.** §12's check looked
   for the minter's *occurrence row* on the admitting node. That is the #765
   shape exactly: the roster's members are persons; a node is its owner's
   instrument, and its authority to speak lives on the live
   `delegates_to(owner → node)` owner binding — an owner-signed attestation
   the mesh already carries for every node.
2. **A node-class occurrence could not replicate.** It is written through the
   trusted-local door (`self_at_login`, Edge's `provision_engine_occurrence`,
   I61's fixture), whose rows are never advertised
   (`list_signed_identity_occurrences_since` lists signed-put rows only); the
   gated door requires a `transport_destination` in the envelope and a signer
   that is the identity or an already-active occurrence of it — a node cannot
   sign its own first occurrence, and its transport identity already lives on
   its own plane (`SignedTransportDestination`).
3. **The fan-out has the mirror gap.** The minter wraps to
   `active_member_occurrences` — occurrence rows with `encryption_pubkeys` —
   so a far member whose node-class occurrence never arrives is never in the
   set at all. Fixing admission alone would admit sets that omit every far
   member.

### 20.1 Admission asks about the principal

`admit_replicated_key_grant` (epoch axis) resolves the minter through
`admission_identity_for_writer`: an occurrence lifts to its identity, an owned
node lifts to its single live owner (`owner_of`, the #578/#584 liveness fold),
anything else stays itself. The **principal** must be an active member of the
community at `asserted_at` per the replicated roster fold. A minter with
neither an occurrence row nor a live owner binding on the admitting node is
refused `signer_not_active_member`, as today. No wire change: the binding is
already a replicated attestation.

### 20.2 The content-only signed occurrence

The gated door (`put_identity_occurrence`, HTTP and wire — one gate) admits a
second form beside #418's transport-bound one: an envelope carrying
`encryption_pubkeys` and **no** `transport_destination`. Verified exactly as
the signed revocation is: the typed projection must equal the envelope; the
hybrid signature over `JCS(envelope)` verifies at 1-of-1 against the PINNED
federation keys of `attesting_key_id`; and `signer_acts_for` — extended by
one clause: the signer may be **the occurrence key itself when a live owner
binding lifts it to `identity_key_id`** (`owner_of(occurrence) == identity`).
Authority comes from the owner-signed, replicated binding; the KEM pubkeys are
covered by the node's own signature; a consented peer holds neither key, so
#418's content-MITM stays closed. Transport-bound occurrences keep #418's rule
verbatim (`verify_transport_binding`, transport ≠ signing). The stored row is
signed-put, so the plane advertises it and the far node admits it through the
same gate.

**Implementation note (PR #852 review).** The content-only gate binds every
field the backends read back — `device_class`, `asserted_at` (the
last-signed-wins and revocation-freshness clock), `valid_until`,
`hardware_attestation` — at the producer's millisecond precision; a relay
cannot forward-date a typed row under a valid signature. The self-signed
form consults the LIVE owner binding on every admission and never the
occurrence row a prior admission left, so a withdrawn or lapsed binding
stops vouching the moment it dies (I76, legs 4 and 5).

### 20.3 The door: a node publishes its own occurrence

`Engine::publish_self_occurrence(identity_key_id, device_class)` /
`PyEngine.publish_self_occurrence` builds the content-only envelope with this
node's content-KEM identity, signs it with the composed hybrid signer, and
admits it through the gated door — so a node's occurrence is born replicable.
This is what CIRISEdge's `provision_engine_occurrence` calls in place of the
trusted-local write, once the node's owner binding exists. `self_at_login`
writes only the app and agent DEVICE occurrences and keeps the trusted-local
door for them; their replicable form is the same content-only occurrence
signed by the identity itself (§20.2 admits it — the identity is the
signer; no lift needed), which Edge can produce with the identity seed it
already holds. No further persist change.

### 20.5 The claim the plane served and every peer refused

I75's first delivery leg found the next thing I61 never carried: the
`holds_bytes` claim a write door announces is stored at federation tier but
signed classical-only (`sign_holds_bytes_claim` signs through the classical
`HardwareSigner`, which has no hybrid method), the cursor serves it, and the
federation-tier ingest gate on every peer refuses it (CC 5.3.2.4.3.1 —
classical-only producers are confined to local tier). The claim is now
hybrid-signed whenever the Engine or PyEngine has a LocalSigner (the optional
signer is threaded from the doors through `put_blob_signing_at` and
`adopt_sealed_blob` to the claim); an engine without one keeps the classical
claim, which no peer will admit — stated, not silent (I79).

### 20.4 Invariants — three planes, delivered, never copied

| # | invariant | falsified by | gate |
|---|---|---|---|
| I75 | **The end to end, delivered.** Two Engines; alice owns A, bob owns B (owner bindings as attestations); A and B each publish their own content-only occurrence; every row crosses only through a since-read and the gated door on the other side — bindings via the attestation cursor, occurrences via `list_signed_identity_occurrences_since` → `put_identity_occurrence`, the set via the cursor → `apply_replicated_key_grant`; B's node is IN A's set; B admits and opens. | the mesh's refusal (#851); a set that omits the far member | behavioural, two Engines, both backends |
| I76 | A content-only signed occurrence signed by its own key is admitted iff a live owner binding lifts that key to the identity; unbound, or bound to another identity, refused; a transport-bound occurrence is verified as before. | a peer minting a victim's occurrence | behavioural, both backends |
| I77 | A `KeyGrant` whose minter is an owned node with no occurrence row on the admitting node is admitted when the owner is an active member, refused when the owner was removed at `asserted_at` or the binding is not live. | membership asked about the instrument | behavioural, two-node |
| I78 | The occurrence plane's since-read lists the published occurrence (signed-put) and never a trusted-local row (from disk + behavioural). | an occurrence written unadvertised | both |
| I79 | A `holds_bytes` claim announced by an Engine with a LocalSigner carries a PQC signature and is admitted by a peer through the attestation cursor. | a claim the plane serves and every peer refuses | behavioural, two Engines |

## 19. What Edge and Server do

- **Edge**: add the wire kind (sixteenth, in order); on admitting a
  `KeyGrant` call `apply_replicated_key_grant`; nothing else in the
  pull-on-attestation hook changes — the grants arrive on the same
  replication path the hook already sits on. Then the #601 ladder rung "B
  opens A's body across nodes" turns green.
- **Server**: re-pin `REPLICATION_POLICY_HASH`; N-member rooms need nothing
  else.

**v44.3.0**, MINOR with the re-pin stated.

