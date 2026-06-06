# FSD: CIRISPersist — Streaming substrate (CEG 0.10 §10.5 impl)

**Status:** Proposed (on-ramp to CIRISPersist#142; ratifies #144 adopt/roll decisions)
**Author:** Eric Moore (CIRIS Team) with Claude Opus 4.8
**Created:** 2026-06-06
**Repo:** `~/CIRISPersist`
**Risk:** Substrate evolution, multi-cut. Additive at the grammar layer (CEG §3 1+4 lockdown holds) but **one bounded CHECK-constraint migration** at the `key_grant` layer (RC1-1c, §6.4). Sequenced so each cut stands alone.
**Upstream issues:** CIRISPersist#142 (substrate proposal), #144 (library survey — ratified here), #145 (swarm fetch, downstream), CIRISRegistry#34 (STH consistency-proof enforcement, accountable tier), CIRISVerify#47 (hybrid KEM, shipped).
**Spec of record (protocol):** `CIRISRegistry/FSD/CEG/10_endpoints.md` §10.5 (V1/V2/V3 locks), §7.9 (`delivery_receipt:{stream_id}`), §0.9 (JCS canonical). This FSD is the **substrate mapping** of that protocol; where the two differ, CEG §10.5 is normative and this doc is wrong.

---

## 0. TL;DR

CEG 0.10 closed the **delivery axis** (visibility + revocability + *delivery*). Its media-multicast half is "spec-now, impl substrate-pending **CIRISPersist#142**." This FSD turns #142's three primitives — `get_range`, `BlobBody::ChunkDag`, live `put_blob_chunk`/`seal_stream` — into a substrate spec **re-grounded against CEG 0.10 §10.5** (which advanced well past #142's pre-0.10 sketch). The strategic call from #144 holds: **substrate stays SHA-256** (BLAKE3/iroh would force a 7-repo wire migration not justified by keyframe-aligned seek). Most building blocks already exist in-tree (`SignedTreeHead`/`TransparencyStore`, `aes-gcm`, `hkdf`, the hybrid KEM); the net-new substrate is one table, one BlobBody variant, one range API, and one bounded CHECK migration.

**What CEG 0.10 §10.5 added beyond #142 (the re-grounding deltas):**
1. **Per-stream transparency log** — each stream is its own RFC 6962 log (`log_id = stream_id`), reusing the `SignedTreeHead` shape, NOT a `scores`-attestation `chunk_available` dimension (#142's original). Keeps media chunks out of the global provenance tree (§10.5.0).
2. **PQC wrap MANDATORY** — streaming epoch DEKs MUST wrap with `wrap_algorithm: v2 = x25519+ml-kem-768` (§10.5.3), not #142's `v1` X25519-only. Harvest-now-decrypt-later defense for indefinitely-persisted content.
3. **STREAM nonce layout** (§10.5.2 V2 lock) — exact `prefix[7] ‖ counter_be[4] ‖ last_flag[1]` construction, not #142's looser `HKDF(DEK,"chunk-iv"||idx)`.
4. **Epoch axis + RC1-1c CHECK migration** — the per-`(stream_id, epoch)` key_grant axis needs a parallel CHECK arm at the V054 constraint (§6.4); explicitly NOT pure-additive there.
5. **Delivery receipts** (§10.5.4 V3 lock) — `delivery_receipt:{stream_id}` reserved prefix; verify is a JOIN against the published root, not a sig-check.

---

## 1. Why — mission + the CEG dependency

CEG 0.10 (`CIRISRegistry/FSD/CEG/`) is at Public Working Draft; its streaming-multicast half cannot reach impl-live, and **CEG cannot progress toward 1.0**, while #142 is open. Persist is the named blocker. This is the CEG-1.0 critical path.

Mission grounding (MISSION.md):
- **§1.2 N_eff / evidence** — a live stream is signed evidence like any trace; the per-stream transparency log (§10.5.1) makes a stream's chunk sequence tamper-evident under the same RFC 6962 algorithm persist already runs for audit chains. Streams don't get a weaker integrity story.
- **§1.4 apophatic bound — substrate stays format-blind.** Persist does NOT parse fMP4/WebM/HLS/DASH. Seek intelligence lives at the consumer (every container encodes its own time→byte index). Substrate serves opaque octet ranges over content-addressed bytes. This is the same "not an analytics engine" discipline applied to media.
- **§1.5 parity** — `get_range`, `ChunkDag`, and the stream tables all ship on BOTH Postgres and SQLite. A Raspberry-Pi peer hosting a community's stream is a first-class peer.
- **§1.6 fail-honest** — a catch-up request against an evicted epoch returns `ContentMiss`, never a silent gap (§10.5.3 P4). At-rest auth happens per-chunk so a truncated/torn stream is *detected*, not coerced.
- **§3 canonical bytes** — the STREAM nonce, the STH `signing_bytes`, and the delivery-receipt `receipt_signing_bytes` are all domain-separated + length-prefixed per the CEG-locked layouts; persist re-emits byte-exact.

---

## 2. Scope

### 2.1 In scope (the substrate, across cuts)

| Primitive | CEG §10.5 anchor | Cut |
|---|---|---|
| `get_range(sha, start, end) → bytes` (byte-range read, both backends + External proxy) | — (substrate primitive; enables §10.5 chunk fetch) | A |
| `BlobBody::ChunkDag { manifest_sha }` + manifest format + `put_blob_chunks` atomic upload | §10.1.1 Merkle-over-chunks | B |
| `federation_stream_chunks (stream_id, seq) → chunk_sha` index table | §10.5.3 table | C |
| `put_blob_chunk(stream_id, seq, …)` + `seal_stream(stream_id)` live append | §10.5.0/.1 | C |
| Per-stream transparency log (reuse `SignedTreeHead`/`TransparencyStore`, `log_id = stream_id`) | §10.5.1 V1 | C |
| Per-segment AES-256-GCM + STREAM nonce sealing | §10.5.2 V2 | C |
| Epoch-DEK `key_grant` cascade w/ `wrap_algorithm: v2` (PQC) + the RC1-1c CHECK migration | §10.5.3 D2/D3 | C |
| `delivery_receipt:{stream_id}` ingest/read (reserved prefix) | §10.5.4 V3 | C |

### 2.2 Out of scope (named, not silently dropped)

- **Container parsing** — substrate is format-blind (§1.4). `symphonia`/`mp4parse`/`webm-iterable` live at edge/consumer (#144 track-don't-adopt).
- **Multi-peer swarm fetch** — CIRISPersist#145; consumes #142's `get_range`/`ChunkDag` primitives, separate cut.
- **MoQ / QUIC live transport** — lives at CIRISEdge; substrate exposes bytes (`get_range` PyO3 + optional HTTP/3 206), edge does the wire. `quinn`/`h3`/`wtransport` are edge deps (#144).
- **HTTP server surface** — persist has none today; the optional 206 HTTP tier (§4.1) is deferred behind the PyO3 path which cohabitation callers want first.
- **BLAKE3 / Bao-tree verified streaming** — refused (§3.1); substrate stays SHA-256.
- **MLS-style O(log N) rekey tree** — CEG §10.5.3 marks it "1.x, additive" (rides the opaque key_grant payload); not this cut.

---

## 3. #144 adopt/roll decisions — RATIFIED

CIRISPersist#144's decision matrix is sound and is hereby ratified into the design of record (close #144 against this). The load-bearing calls:

### 3.1 Strategic: SHA-256, not BLAKE3 (LOCKED)

CEG §10.1.1 fixes the substrate hash as SHA-256 — every `federation_key`, every `evidence_refs[]`, every Contribution lineage walk depends on it. Adopting `iroh-blobs`/Bao-tree (BLAKE3) would mean either a multi-month 7-repo BLAKE3 wire migration or a fork-every-consumer hybrid. The streaming win it buys — byte-aligned sub-chunk verified streaming — is wasted on video, whose seek granularity is **keyframe-aligned (1–5s), not byte-aligned**. Merkle-over-chunks (manifest SHA + per-chunk SHA, §10.1.1) gives the integrity property at chunk granularity using SHA-256 already in stack. **Substrate stays SHA-256.**

### 3.2 Adopt (all already in-tree or transitively present)

| Concern | Crate | Note |
|---|---|---|
| Range header parsing (if HTTP tier) | `axum-extra` `headers::Range` | only if/when §4.1 HTTP tier lands |
| BLOB-substr reads | `rusqlite` incremental `Blob` I/O; PG `substring(bytea,…)` | both backends native partial reads |
| Per-segment AEAD | `aes-gcm` (RustCrypto) | in stack via ciris-keyring |
| Per-chunk nonce/key HKDF | `hkdf` (RustCrypto) | in stack |
| Epoch-DEK hybrid wrap | `ciris-crypto` `hybrid_kex` + `ml_kem` (CIRISVerify#47) | **shipped**; this is the §10.5.3 `wrap_algorithm: v2` |
| `(stream_id, seq)` monotonicity | DB `UNIQUE` constraint | substrate primitive, not a lib |
| Manifest compression (sidecar only) | `zstd` | in stack; manifests/playlists only — NEVER video bytes |
| Per-stream RFC 6962 log | **in-tree** `SignedTreeHead`/`TransparencyStore` (CIRISVerify 2.3.0 transparency) | instantiate per `stream_id` |

### 3.3 Roll our own (small, scoped)

| Concern | ~lines | Why |
|---|---|---|
| ChunkDag manifest (flat Merkle list) | ~100 | flat one-level DAG; `rs_merkle` over-delivers; two serde structs + JCS |
| STREAM-nonce AES-GCM-HKDF framing | ~150 | tight loop over chunks; `tink-rs` incomplete/unmaintained |
| Per-backend BLOB-substr facade | ~50/backend | backend-specific SQL; no lib abstracts both |
| Manifest verify (SHA-of-manifest + per-chunk SHA) | ~50 | linear walk; `sha2` in stack |

### 3.4 Explicitly NOT adopting (with reasons, from #144)

`tink-rs` (incomplete/unmaintained), `iroh-blobs` now (BLAKE3, §3.1), zstd seekable format (v0.1.0 since 2017), IPFS UnixFS wire (CID v1 + dag-pb commitment — defer until a real IPFS consumer), `actix-web` (stack is axum/tokio). Track-don't-adopt: `moq-rs` (when IETF MoQ → RFC; forward bet), `libp2p-bitswap` (#145 design ref), `iroh-blobs` (if federation ever rides iroh gossip).

---

## 4. Substrate mapping — the three primitives

### 4.1 `get_range` (Cut A — pure additive, no CEG change)

```rust
// Backend trait + Engine + PyO3
async fn get_range(&self, content_sha256: &str, start: u64, end_inclusive: u64)
    -> Result<Bytes, BlobError>;
```

- **`BlobBody::Inline`** — server-side substring, no full-buffer load: SQLite `rusqlite` incremental `Blob` read at `(offset, len)`; Postgres `SELECT substring(bytes_inline FROM $start+1 FOR $len)`.
- **`BlobBody::External(ExternalRef)`** — proxy `Range: bytes=start-end` to the upstream object store; honor `206`/`Content-Range`.
- **`BlobBody::ChunkDag`** (Cut B) — walk the manifest prefix-sum, fetch covering chunk(s), slice at the boundaries.
- **Bounds** — reject `start > end`, `end ≥ total_size` clamped per RFC 9110 §14.4 semantics; typed `BlobError::RangeNotSatisfiable`.
- **Surface (open question resolved, §8):** **PyO3 first** (cohabitation callers — lens-core, sovereign agent — want in-process bytes). An optional HTTP/3 `206` tier (`axum` + `axum-extra` Range) is deferred to a later cut behind the same `get_range` core; remote viewers ride edge's transport meanwhile.

Cut A ships against today's `Inline | External` with zero CEG/schema change — immediate value (ranged reads for existing media) and the seam every later cut builds on.

### 4.2 `BlobBody::ChunkDag` (Cut B)

`federation_blobs.bytes_inline` stores the **manifest** (JCS-canonical JSON per CEG §0.9), `content_sha256` = SHA(manifest bytes):

```json
{ "v": 1, "total_size": <u64>, "chunks": [ {"sha":"<hex32>","size":<u32>}, … ] }
```

- Each chunk is its own `federation_blobs` row (`Inline` or `External`). One-level DAG only (UnixFS flat-leaves; no nested DAGs).
- **CEG §10.1.1 satisfaction**: consumer verifies manifest SHA (= row `content_sha256`) before consumption, then each chunk's SHA on read. Full-SHA-before-consumption holds at both levels; no prefix short-circuit.
- `put_blob_chunks(manifest, chunks…)` — atomic multi-row insert (manifest + N chunk rows in one txn).
- Adds one `storage_kind`/`BlobBody` variant; the chunk relation rides CEG open-vocab `topical_relation:has_chunk` (no grammar change).
- **Chunk size: 1 MiB** (§8 resolved) — IPFS UnixFS 2025 profile; below fMP4 2–6s segment sizes; 16-byte GCM tag overhead < 0.002%.

### 4.3 Live append + per-stream log (Cut C)

```rust
async fn put_blob_chunk(&self, stream_id: &str, seq: u64, body: Bytes, epoch: u64, …)
    -> Result<ChunkReceipt, StreamError>;
async fn seal_stream(&self, stream_id: &str) -> Result<SealedStream, StreamError>;
```

- New table `federation_stream_chunks (stream_id TEXT, seq BIGINT, chunk_sha TEXT, epoch BIGINT, …, PRIMARY KEY (stream_id, seq))` — the `UNIQUE(stream_id, seq)` is the monotonicity guarantee. Each chunk also lands as a normal `federation_blobs` row.
- **Per-stream transparency log (§10.5.1 V1)** — instantiate the in-tree `TransparencyStore`/`SignedTreeHead` with `log_id = stream_id`; chunks are leaves; the producer publishes a **producer-signed STH** (hybrid Ed25519 + ML-DSA-65, §10.3 `signing_bytes`) every **K=64 chunks OR T=2s, always at an epoch boundary + at `sealed_at`**. Witness cosign is OPTIONAL (best-effort = producer-signed only; accountable = §10.3.1 consistency proof, also gated on CIRISRegistry#34). **A live_stream MUST NOT append into the global provenance log** (§10.5.0) — separate per-stream instance.
- `seal_stream` builds the `ChunkDag` manifest from the index, computes its SHA, writes the final `federation_blobs` row + final STH with `last_flag` chunk.
- **Subscribe-while-live** rides the existing CEG attestation-subscribe path; no new `attestation_type` (1+4 lockdown).

### 4.4 The RC1-1c CHECK migration (the one non-additive piece)

CEG §10.5.3 is explicit: today's V054 cross-column CHECK requires `key_grant` rows be **content-addressed** (`media_content_sha256 IS NOT NULL`). The streaming epoch-key axis is **stream/epoch-addressed** (`(stream_id, epoch[, recipient])`, NULL `media_content_sha256`) → rejected by the current CHECK. The migration adds a **parallel CHECK arm**: `(content-addressed) OR (stream/epoch-addressed)` — a bounded constraint migration on both backends (PG `DROP/ADD CONSTRAINT`, SQLite trigger rewrite per V054/V056 discipline). This is the only place the cut is not pure-additive at the constraint layer; named here so no one claims otherwise.

---

## 5. Encryption posture (§10.5.2 / §10.5.3)

Full PQC envelope for streaming, per CEG §10.5.3:

| Layer | Algorithm | Source |
|---|---|---|
| Content (bulk) | AES-256-GCM per-chunk, **STREAM nonce** | `aes-gcm` (in stack) |
| Chunk nonce | `prefix[7]=HKDF-SHA256(epoch_dek; "ciris-stream-nonce/v1"‖stream_id‖epoch)[0..7]` ‖ `counter_be[4]` ‖ `last_flag[1]` | `hkdf` (in stack); mirrors `KEY_GRANT_V1_INFO` versioned-context pattern |
| DEK wrap (per epoch) | **`wrap_algorithm: v2 = X25519 + ML-KEM-768` (hybrid, FIPS 203) — MANDATORY** | `ciris-crypto` `hybrid_kex`/`ml_kem` (shipped) |
| Authenticity (STH, receipts) | Ed25519 + ML-DSA-65 | `ciris-crypto` (in stack) |
| Hashes | SHA-256 | `sha2` (in stack) |

Key invariants:
- **Per-segment AEAD, never whole-object** — whole-object GCM buffers the entire blob to validate one tag (AWS S3 EC v3) → incompatible with seek. Each 1 MiB chunk seals independently → random access works.
- **STREAM nonce safety** — within an epoch the 32-bit `counter_be` is strictly monotonic and MUST NOT wrap; substrate forces an epoch roll before `2³²−1` (operational cap `MAX_CHUNKS_PER_EPOCH = 2²⁴`). Across epochs the DEK changes, so a reset counter is a distinct `(key, nonce)` pair — cross-epoch reset is nonce-safe. `last_flag=0x01` on the final chunk gives truncation+append resistance.
- **Epoch triggers** — **member removal ⇒ MANDATORY rotation** (forward-only unsubscribe); member addition ⇒ no rotation + Option-A catch-up bounded by `history_on_join`; time/bytes ⇒ optional hygiene. Forward-only, NO PCS (consistent with CEG 0.7 §11.7.1 Option A).
- **Consumer MUST reject** a streaming epoch grant carrying `wrap_algorithm: v1`.
- **Catch-up bound (P4)** — `min(operator depth cap, chunk-eviction horizon)`; an evicted-epoch request returns `ContentMiss` (fail-honest). Operators MUST ship the P4 cap *with* the cascade (else 10⁶ grants/rekey worst case).

No per-segment `key_grant` rows — HKDF derives per-chunk keys from one epoch DEK (§142 anti-recommendation; §10.5.3).

---

## 6. Integration with the v4.0 cohort_scope machinery

A stream is scoped content. A `live_stream` delivered to a community rides the **same v4.0 target-membership gate**: the stream's `cohort_scope`/`cohort_target_id` names the audience (a `community_key_id`), and the epoch-DEK `key_grant` cascade is the Policy-L cascade over **that community's roster** (§10.5.3) against the rotating epoch key. The read-side §4.3 predicate and write-side §4.6 AV-58 gate apply to stream chunks exactly as to traces — no new scope machinery, the streaming cut reuses v4.0's `CallerScope`/`CallerAdmission` + `cohort_scope_sql_predicate`. Member removal triggering epoch rotation (§5) is the cryptographic enforcement of the same forward-only-unsubscribe the v4.1 revocation substrate (#161) enforces at the membership-row layer.

This is why streaming lands *after* v4.0: it composes on the cohort substrate rather than reinventing it.

---

## 7. Cut sequence

| Cut | Deliverable | CEG / gate | Non-additive? |
|---|---|---|---|
| **A** | `get_range` over `Inline`+`External` (PyO3) | none | no |
| **B** | `BlobBody::ChunkDag` + manifest + `put_blob_chunks` + `get_range` over ChunkDag | §10.1.1 | no (one BlobBody variant) |
| **C** | `federation_stream_chunks` + `put_blob_chunk`/`seal_stream` + per-stream STH + STREAM-nonce AEAD + epoch-DEK v2 cascade + `delivery_receipt:{stream_id}` | §10.5.1–.4; gated on CEG 0.10 §10.5 ratified (it is, PWD) + CIRISRegistry#34 for accountable tier | **yes — RC1-1c CHECK migration (§4.4)** |

Cuts A and B are immediately shippable (pure additive, no upstream dependency). Cut C is the CEG-1.0-unblocking cut and carries the one CHECK migration + the epoch cascade; the **accountable** witness-cosign tier additionally waits on CIRISRegistry#34, but the **best-effort** tier (producer-signed STH only) ships with Cut C.

---

## 8. Open questions — resolved

| #142 open question | Resolution |
|---|---|
| Chunk size | **1 MiB** (IPFS 2025 profile; below fMP4 segment sizes; tag overhead negligible). Per-content-class tuning deferred — operator knob, not a substrate constant. |
| Live latency target | **CMAF/LL-HLS now, MoQ forward bet.** Substrate exposes bytes; transport choice lives at edge. `moq-rs` track-don't-adopt until IETF moq-transport → RFC. |
| `get_range` surface | **PyO3 first** (cohabitation callers); HTTP/3 206 tier deferred behind the same core. |
| IPFS interop | **Defer** until a real IPFS consumer appears (CID v1 + dag-pb is a non-trivial commitment). |
| Encryption at-rest seek | **Resolved by CEG §10.5.2** — per-segment AES-256-GCM + STREAM nonce; whole-object GCM refused. |
| DEK wrap algorithm | **Resolved by CEG §10.5.3** — `wrap_algorithm: v2` hybrid PQC MANDATORY (changed from #142's v1). |

---

## 9. Cross-references

- **CEG 0.10** `CIRISRegistry/FSD/CEG/10_endpoints.md` §10.5 (.0 framing, .1 per-stream STH V1, .2 STREAM nonce V2, .3 epoch cascade D2/D3 + PQC wrap, .4 delivery receipts V3); §7.9 reserved prefix; §0.9 JCS; §10.1.1 full-SHA MUST; §10.3 SignedTreeHead reuse.
- **CIRISPersist#142** — the substrate proposal this re-grounds.
- **CIRISPersist#144** — adopt/roll survey, ratified in §3.
- **CIRISPersist#145** — multi-peer swarm fetch (consumes A/B primitives).
- **CIRISPersist#161** — revocation substrate (the membership-row layer the epoch rotation enforces cryptographically).
- **CIRISVerify#47** — hybrid X25519+ML-KEM-768 KEX (shipped; the §10.5.3 `wrap_algorithm: v2`).
- **CIRISRegistry#34** — STH consistency-proof enforcement (accountable-tier gate).
- **MISSION.md** §1.4 (format-blind), §1.5 (parity), §1.6 (fail-honest), §3 (canonical bytes).
- In-tree reuse: `ciris_verify_core::transparency` (`SignedTreeHead`/`TransparencyStore`), `ciris-crypto` (`hybrid_kex`/`ml_kem`/`aes_gcm`/`hkdf`), `federation_blobs`, V054 `key_grant` constraint.
