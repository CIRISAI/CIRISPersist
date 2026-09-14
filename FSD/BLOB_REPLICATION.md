# FSD: Blob Replication — the holder plane, and the decision to hold

**Status:** Proposed (design locked on the thread that lit the mesh, 2026-09-14;
this document is the spec for v44.2.0)
**Author:** Eric Moore (CIRIS Team) with Claude Fable 5.1
**Created:** 2026-09-14
**Repo:** `~/CIRISPersist`
**Companion to:** CIRISServer `FSD/CEG_REPLICATION_MODEL.md` (the ATTESTATION
plane — Server-owned, implemented here as `replication_policy.rs` and pinned by
`REPLICATION_POLICY_HASH`) and `FSD/BLOB_ENCRYPTION_AT_REST.md` (what a blob
IS at rest). Neither covers what this one does: how a blob **moves**, and who
decides to **hold** it.
**Risk:** Additive doors and one behaviour change on relay accept, stated in
§7. No on-disk format change to existing rows; one new nullable column.

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
  which may be past, and may be an epoch this node holds no grant for at all —
  a relay holds on provenance alone (CC 4.4.3.2.1). Reads then behave exactly as
  for any row at that tier: a viewer with a grant opens; anyone else gets the
  typed refusal (`NotGranted`, or `Evicted` if it was swept). Adopt does not
  consult key state and does not require the epoch to be current.
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
| **role** | `resolve_serve_tier(directory, our key, our key)` (#788) | content we are **audience** for is held by right of audience, whatever our serve standing. Content we are **not** audience for — a pure relay hold — is accepted only by a node with serve standing (`ServeTier >= MeshServer`). A node nobody conferred `infra:serve` on does not volunteer as a relay. |
| **provenance class** | the author key on the meaning, against the local/family predicate | decides which of the two rules above applies, and is recorded on the row (§5) |

The order is: MAY before bytes move (it is Edge's, it precedes the fetch);
WILL at the door, after the bytes arrived and their hash verified, before the
row is written. WILL is cheap — one cached snapshot, one directory read for the
serve tier — and its refusals are typed, name the axis, and disclose nothing
about the content (I4b's class).

**Why role at all.** Without it, "backpressure" is the only thing standing
between a node and holding the whole federation's commons: any peer above the
trust threshold could push relay content onto any node until the disk filled,
and #737 notes the trust threshold is zero when nobody configured it. The
Constitution already keys serving of the one role-projected family (`trace:*`)
on `infra:serve`; holding what one is not audience for is the same act one hop
earlier.

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
  local-or-family **and** this node is not audience for the row's cohort. It
  replaces the holder-attester scan in the force-evict sweep, the serve
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
| I48 | A node with `ServeTier::None` refuses to adopt content it is not audience for (`RelayRequiresServeStanding`, typed); it adopts content it is audience for regardless of serve standing; a `MeshServer` node adopts both. | a nobody-node filling with commons; a member refused its own community's bytes | behavioural, both backends |
| I49 | `is_proxy_content` is the one classification: the force-evict sweep, `serve_blob_to_peer` and `would_hold` all call it; an adopted non-audience blob classifies proxy; a `NULL` author classifies proxy. | an adopted relay blob that survives a force-evict; a proxy blob served under `Stop` | from-disk + behavioural |
| I50 | An adopted stream chunk's stream row records the AUTHOR's derived key as owner; a later append by the adopter is refused as a foreign writer (I41 carried across nodes). | a relay that takes over a stream it holds | behavioural |
| I51 | An adopted `CommunityDek` blob is readable by a viewer holding a grant for its declared epoch and refused `NotGranted` for one who does not, with no key state for that epoch on the adopting node required for the adopt itself. | an adopt that needs the receiver to already be a member; an adopted blob that opens for anyone | behavioural |
| I52 | `Announce` emits `holds_bytes` carrying `author_key_id` and `community_key_id` in the clear; `LocalOnly` emits nothing; self/family provenance can never `Announce` (CC 5.2, refused before the floor). | a holder claim a relay cannot keep/evict on; an announced family blob | behavioural |
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
  re-derived. `would_hold` is available before the fetch. The FountainContent
  ceiling narrows to `Cohort` when the store gate is armed, as #601 gap 2 says.
- **CIRISServer** (#594): nothing new is required of Server for this cut. #843
  ships beside it.
- **CIRISConstitution**: nothing to amend. CC 4.4.3.2.1's holder-inspectability
  principle is the normative basis for §4; CC 5.3.2.1 for the holder TTL and
  `ContentMiss`; CC 5.2 for the `Announce` refusal on self/family.

## 10. Versioning

**v44.2.0**, MINOR. Additive: the three doors, `BlobProvenance`,
`HoldDecision`, `RelayRequiresServeStanding`, `federation_blobs.author_key_id`
(V144, nullable, backfilled). One behaviour change, stated: a node with no serve
standing now refuses to accept content it is not audience for, on
`put_blob_signing` as well as the new doors. Today that content is accepted by
anyone above a trust threshold that defaults to zero; after this cut it is
accepted by the nodes the mesh conferred that role on.
