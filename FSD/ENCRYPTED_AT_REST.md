# FSD: Content Encryption at Rest — CIRISPersist

**Status:** Proposed (locked design — this document formalizes a settled
exploration; it is the spec, not a re-exploration)
**Author:** Eric Moore (CIRIS Team) with Claude Opus 4.7
**Created:** 2026-05-22
**Repo:** `~/CIRISPersist`
**Risk:** Architectural, on-disk format. Multi-release, phased. The
on-disk format change sits entirely behind the `Engine` API; post-2.9.0
persist is the sole DB opener, so the change is **unilateral** — no
downstream coordination, gated only on absorption completeness.

---

## 1. Why this exists

Every CIRISPersist substrate stores, at rest, the *reasoning content* of
CIRIS agents — the raw payloads of trace events, the attributes of
memory-graph nodes, the context of audit entries. Today the at-rest
confidentiality of that content is **delegated to deployment full-disk
encryption** (`docs/THREAT_MODEL.md:738` — "software-backed deployments
have no key isolation beyond OS keyring file permissions … mitigations
are deployment-level (full-disk encryption …)"). That is the right
posture for a row's *structural metadata* and the wrong posture for its
*content*: it makes confidentiality a property of how the operator
provisioned the disk, not a property persist guarantees.

A solar-LoRa Raspberry Pi, a federation relay host run by a peer you
have rated but do not control, a phone in a pocket, a leaked Postgres
backup tarball — these are the deployments the federation is *for*, and
on every one of them "we assumed the operator turned on FDE" is a hope,
not a guarantee.

This FSD specifies **content encryption at rest**: persist itself
encrypts the reasoning content of every substrate, application-layer,
**100% backend-agnostic**, while keeping a plaintext queryable
projection of each record's structural skeleton. The ciphertext is the
authoritative form; the plaintext projection is a reconcilable cache.

The capability this buys: **a federation that measures reasoning quality
without reading reasoning content.** The Coherence Ratchet and the N_eff
measurement (MISSION.md §1.2 — "N_eff is k_eff") score the *derived
signals* on the projection; they never need the content. A peer relay
can host another agent's evidence corpus, serve scoreable queries over
it, and be cryptographically unable to read what the agent reasoned
about. Evidence that is *scoreable-but-not-readable*.

### 1.1 Why this is uniquely possible for CIRIS data

Application-layer "encrypt the content, keep a queryable projection"
fails for general-purpose databases — you cannot know in advance which
columns a future query needs, so either you encrypt nothing queryable or
you encrypt nothing useful. CIRIS data escapes that trap for four
structural reasons:

**(a) The query set is closed and typed → the projection is *knowably
complete*.** The `ReadEngine` analytics surface is a fixed set of ~21
methods (`migrations/.../V042__trace_events_analytics_indexes.sql`
header: "The ReadEngine analytics query set is FIXED (~21 methods)").
V042 already *enumerated* every scalar those queries extract. When the
query set is closed, the set of columns that must stay plaintext is
finite, knowable, and auditable — not a guess about the future.

**(b) The federation scores derived signals, not content → the privacy
boundary equals the queryability boundary, by design.** The
Coherence Ratchet, capacity scoring, and manifold-conformity paths
cluster on cohort-identity labels and operate on *scored scalars*
(`csdma_plausibility_score`, `dsdma_domain_alignment`, `idma_k_eff`,
`idma_correlation_risk` — V042 Group A). They never read the prose of a
thought. So the columns a query needs *are exactly* the columns that are
non-sensitive by design. There is no tension to resolve: the line
between "queryable" and "private" is one line, drawn once.

**(c) Every record is agent-signed → the plaintext projection is
plaintext-but-unforgeable.** Every persist row carries a scrub/audit
envelope: an Ed25519 (cold-path ML-DSA-65) signature over the canonical
bytes (`src/ingest.rs::sign_scrub_envelopes`; the
`signature`/`scrub_signature*`/`original_content_hash`/`persist_row_hash`
columns on every substrate table). Confidentiality and integrity are
therefore **orthogonal layers**: the signature already makes the
projection *tamper-evident* without encrypting it. Plaintext-here is
plaintext-but-unforgeable, not plaintext-and-unprotected. Encryption
adds the one property the signature does not — confidentiality — and
adds it only where it is needed.

**(d) The scrubber already located the content/signal boundary.** The
post-ingest pipeline already cleaves content from signal: trace *levels*
(`trace_level` column) gate how much content a deployment ships at all,
and the scrub envelope's `original_content_hash`
(`src/ingest.rs::compute_pre_scrub_hashes`) is precisely the hash of
"the content, before scrub" — persist already names, hashes, and signs
the content/signal seam. Content encryption at rest does not *invent*
that boundary; it *enforces* the boundary the scrubber already drew.

The conclusion: the skeleton/content cleavage is not an imposition on
CIRIS data — it is a property CIRIS data already has, made load-bearing.

---

## 2. The boundary principle

Every persist substrate is a **signed, structured record** with two
parts. Content encryption at rest splits the record along the seam that
already exists between them.

### 2.1 Skeleton / queryable projection — stays PLAINTEXT

The structural columns the `ReadEngine` and indexes need stay plaintext:

- The cohort/identity/time axes: `agent_id_hash`, `ts`, `event_type`,
  `trace_id`, `thought_id`, `deployment_domain`, `deployment_type`,
  `agent_role`, the cost columns (`cost_usd`, `cost_llm_calls`,
  `cost_tokens`).
- The **V042-shredded scored scalars** — `csdma_plausibility_score`,
  `dsdma_domain_alignment`, `idma_k_eff`, `idma_correlation_risk` —
  promoted to real typed columns (see §5).
- The audit machinery: hash-chain fields (`sequence_number`,
  `prev_hash`, `entry_hash`), Merkle fields (`leaf_hash`, `root_hash`,
  `leaf_index`), the per-identity `next_value` sequence counter, and
  every signature/envelope column
  (`signature`, `signing_key_id`, `signature_verified`,
  `original_content_hash`, `scrub_signature_classical`,
  `scrub_signature_pqc`, `scrub_key_id`, `scrub_timestamp`,
  `pqc_completed_at`, `persist_row_hash`).

**Rationale.** (i) This is the *intended federation-transparency
surface*: the Coherence Ratchet / N_eff measurement score *on* these
columns, so they are non-sensitive by design (§1.1b). (ii) The columns
are covered by the agent's signature over the canonical bytes — plaintext
here is *plaintext-but-tamper-evident* (§1.1c), not unprotected. The
projection is a queryable cache, and a *signed* one.

### 2.2 Content — gets ENCRYPTED

The raw reasoning content gets encrypted: `trace_events.payload`,
`cirisgraph.nodes.attributes`, `cirislens.audit_log.payload`, the
free-text fields of agent runtime substrates (`thoughts.content`,
`tasks.description`, …), and the consensus-envelope payloads.

The authoritative form of a content column becomes
`AES-GCM(signed_canonical_content)`. On read, persist decrypts, then
**re-verifies the signature** against the decrypted plaintext, then
returns it. The plaintext projection (the shredded scalars, the
skeleton) is a queryable cache reconcilable against that signed
authority: if the cache and the decrypted-and-verified content disagree,
the signed content wins and the divergence is a typed error
(`docs/THREAT_MODEL.md` discipline — fail honest, MISSION.md §1.6).

---

## 3. The boundary map — per-substrate classification

This is the core deliverable. Each substrate's main table(s) is walked
column by column. `P` = projection (stays plaintext); `E` = content
(encrypted); `⚑` = **judgment call flagged for the user** — see §3.12.

Schema sources are cited per substrate; every cited path exists in
`migrations/postgres/lens/` (SQLite parity files mirror them).

### 3.1 `cirislens.trace_events` — `V001` + `V003` + `V006` + `V009`

The flagship substrate. One row per `ReasoningEvent` broadcast.

| Column | Class | Why |
|---|---|---|
| `event_id`, `ts` | P | PK; time axis — every analytics query seeks on `ts`. |
| `trace_id`, `thought_id`, `task_id` | P | Journey/dedup keys; `trace_events_dedup` / `trace_events_journey` indexes. |
| `step_point`, `event_type`, `attempt_index` | P | Closed-enum structural discriminators; V042 partials filter on `event_type`. |
| `agent_id_hash` | P | Hashed cohort identity; the federation-transparency surface (§1.1b). |
| `agent_name` | ⚑ | Hashed-vs-named — see §3.12. Plaintext today; flagged. |
| `cognitive_state`, `trace_level`, `schema_version` | P | Structural labels; `trace_level` gates content shipment (§1.1d). |
| `deployment_domain` | ⚑ | Cohort axis the Ratchet clusters on, BUT may reveal operational specifics — see §3.12. |
| `deployment_type`, `agent_role`, `agent_template`, `deployment_region`, `deployment_trust_mode` | ⚑ | Cohort axes (V006); `deployment_region` in particular can be operationally revealing — see §3.12. |
| `cost_usd`, `cost_llm_calls`, `cost_tokens` | P | Scored scalars; cost-analytics queries aggregate them. |
| **`payload`** | **E** | **The raw reasoning content.** The authoritative form becomes `AES-GCM(signed_canonical_payload)`. |
| `extracted_features`, `classifications`, `pipeline_metadata` | ⚑ | V009 pipeline side-channels. `extracted_features` is *derived signal* (projection-like); `classifications` can name detected content classes (PII categories) — see §3.12. |
| `signature`, `signing_key_id`, `signature_verified` | P | Integrity envelope (§2.1). |
| `original_content_hash`, `scrub_signature`, `scrub_key_id`, `scrub_timestamp` | P | Scrub envelope (`V003`); the integrity layer. |
| `audit_sequence_number`, `audit_entry_hash`, `audit_signature` | P | Audit-chain anchor; `trace_events_audit_seq` indexes it. |
| `pii_scrubbed` | P | Structural flag. |

**Fit:** clean. The V042-shredded scalars currently live *inside*
`payload`; §5 promotes them out so `payload` can be fully encrypted.

### 3.2 `cirislens.trace_llm_calls` — `V001`

| Column | Class | Why |
|---|---|---|
| `call_id`, `ts`, `trace_id`, `thought_id`, `task_id` | P | Keys + time axis. |
| `parent_event_id`, `parent_event_type`, `parent_attempt_index`, `attempt_index` | P | Structural linkage. |
| `duration_ms`, `prompt_tokens`, `completion_tokens`, `prompt_bytes`, `completion_bytes`, `cost_usd`, `attempt_count`, `retry_count` | P | Scored scalars. |
| `handler_name`, `service_name`, `model`, `base_url`, `response_model`, `status`, `error_class` | ⚑ | Operational labels; `base_url` can reveal a private LLM endpoint — see §3.12. |
| `prompt_hash` | P | Hash, not content. |
| **`prompt`, `response_text`** | **E** | **Raw LLM prompt and completion — the most sensitive content in the corpus.** |

**Fit:** clean. `trace_llm_calls` has no V042 indexes; no shredding
needed. Note this table carries **no per-row signature envelope** — its
integrity rides on the parent `trace_events` row. Encrypting `prompt` /
`response_text` here means the re-verify-on-read step (§4.2) must verify
against the parent event's signature, not a local one. See §8 unresolved.

### 3.3 `cirisgraph.nodes` / `cirisgraph.edges` — `V013`

| `nodes` column | Class | Why |
|---|---|---|
| `node_id`, `scope`, `node_type` | P | PK + closed-enum structural type; `nodes_type_scope` index. |
| `version`, `updated_by`, `updated_at`, `created_at` | P | Lifecycle / optimistic-concurrency. |
| **`attributes`** | **E** | **The node's content payload.** `AES-GCM(signed_canonical_attributes)`. |
| `signature`, `signing_key_id`, `signature_verified`, `original_content_hash`, `persist_row_hash` | P | Integrity envelope. |

| `edges` column | Class | Why |
|---|---|---|
| `edge_id`, `source_node_id`, `target_node_id`, `scope`, `relationship` | P | Graph topology — k-hop CTE traversal needs all of it plaintext. |
| `weight` | P | Scored scalar. |
| `attributes` | ⚑ | Per-edge attributes (timestamp windows, direction). Small, structural — but free-form. See §3.12. |
| `created_at` | P | Lifecycle. |

**Fit, with one caveat — the GIN index.** `V013` builds
`nodes_attributes_gin ... USING GIN (attributes)` for `@>` containment /
`?` key-existence predicate push-down. **A GIN index over encrypted
ciphertext extracts nothing** — this is the V042 problem (§5) again, in a
different substrate. The boundary map flags it: encrypting
`attributes` forces either (a) dropping `nodes_attributes_gin` and
accepting that attribute-predicate reads become full scans, or (b) a
`cirisgraph`-side shredding migration analogous to V042-final. Verified
against `V013`'s own header: the agent's actual graph workload is "point
lookup + time-window scan + bounded procedural k-hop" — *not*
attribute-predicate-heavy — so (a) is likely acceptable, but it is a
**flagged decision**, see §3.12.

### 3.4 `cirislens.audit_log` — `V014`

| Column | Class | Why |
|---|---|---|
| `entry_id`, `sequence_number`, `tenant_id` | P | PK + per-tenant monotonic chain key; `UNIQUE(tenant_id, sequence_number)` enforces order. |
| `actor_id`, `action_type`, `subject_kind`, `subject_id` | P | Self-signed identity + closed-token discriminators; `audit_log_subject` / `audit_log_actor` / `audit_log_action_type` indexes. |
| **`payload`** | **E** | **Free-form per-action content.** |
| `prev_hash`, `entry_hash` | P | **Hash chain — MUST stay plaintext (§2.1).** Critical: see fit note. |
| `recorded_at` | P | Time axis. |
| `signature`, `signing_key_id`, `signature_verified`, `persist_row_hash` | P | Integrity envelope. |

**Fit — the load-bearing subtlety.** `V014`'s header states the
canonical bytes used for `prev_hash`/`entry_hash` "include this payload
byte-for-byte." The hash chain therefore commits to the *plaintext*
payload. The spec mandates: **the hash chain commits to plaintext
content; the ciphertext column is a confidentiality wrapper over already
hash-chained bytes.** Encrypt-on-write encrypts `canonical(payload)`;
the chain hash is computed over that *same plaintext* `canonical(payload)`
*before* encryption. Decrypt-on-read recovers the plaintext, and chain
verification runs against it exactly as today. The encryption layer is
strictly *outside* the integrity layer. This must be a tested invariant
(§6). Same principle applies to `merkle_leaves.canonical_bytes` /
`leaf_serialized` (§3.7).

### 3.5 `cirisgraph.telemetry_metrics` — `V015`

| Column | Class | Why |
|---|---|---|
| `metric_id`, `metric_name`, `tenant_id` | P | Keys; `telemetry_window` index. |
| `value` | P | Scored scalar — the measurement itself. |
| `labels` | ⚑ | Free-form label set (4 KiB cap). Mostly structural; can carry operational specifics. See §3.12. |
| `observed_at`, `expires_at`, `created_at` | P | Time / TTL axes; `telemetry_expires` reaping index. |

**Fit — does NOT fit the cleavage cleanly; flagged as honest exception.**
`telemetry_metrics` has **no content column and no per-row signature**
(`V015` header: "Audit envelope is intentionally OMITTED on raw
metrics … they're ephemeral (24h)"). It is pure projection — there is no
"content" to encrypt. The spec's honest position: **`telemetry_metrics`
is exempt from content encryption** (no content; 24h-lived; FDE remains
the at-rest posture for it). If `labels` is judged sensitive (§3.12),
that is a *labels-only* encryption decision, not a skeleton/content
split. Rolled-up `tsdb_summary` nodes land in `cirisgraph.nodes` and are
covered by §3.3.

### 3.6 `cirislens.federation_keys` / `_attestations` / `_revocations` — `V004`

| Representative columns (`federation_keys`) | Class | Why |
|---|---|---|
| `key_id`, `identity_type`, `identity_ref`, `algorithm` | P | The directory's lookup keys; `federation_keys_identity` index. |
| `pubkey_ed25519_base64`, `pubkey_ml_dsa_65_base64` | P | **Public** keys — public by definition. |
| `valid_from`, `valid_until` | P | Validity window. |
| `registration_envelope` (`_attestations.attestation_envelope`, `_revocations.revocation_envelope`) | ⚑ | "Canonical bytes signed at registration … stored verbatim for forensic reconstruction." It is envelope/provenance, not reasoning content — leans P, but it is a JSONB blob. See §3.12. |
| `original_content_hash`, `scrub_signature_classical`, `scrub_signature_pqc`, `scrub_key_id`, `scrub_timestamp`, `pqc_completed_at`, `persist_row_hash` | P | Integrity envelope. |
| `reason` (`_revocations`) | ⚑ | Free-form revocation reason — could name a person/incident. See §3.12. |

**Fit — does NOT fit the cleavage cleanly; flagged as honest exception.**
The federation directory is, by purpose, a **transparency substrate**:
it exists so peers can walk a trust chain (`V004` header — "the
'registry DB compromise → arbitrary trust anchor' attack disappears
because consumers walk the FK chain"). It is the *least* content-bearing
substrate in persist. The spec's default: **federation directory tables
are projection-only — exempt from content encryption** — with `reason`
and the `*_envelope` blobs raised as flagged calls (§3.12). The
`AV-` entry (§5b of THREAT_MODEL, §7 here) must say this plainly: a
stolen federation directory reveals the trust graph, and that is
*intended* — it is a public ledger.

### 3.7 `cirislens.merkle_leaves` / `merkle_sth_log` — `V021`

| Column | Class | Why |
|---|---|---|
| `tenant_id`, `leaf_index`, `chain_event_id`, `tree_size` | P | Tree coordinates. |
| `leaf_hash`, `root_hash` | P | Merkle hashes — MUST stay plaintext (§2.1). |
| `canonical_bytes`, `leaf_serialized` | P | RFC 6962 hashing-form bytes — see fit note. |
| `signature_blob`, `signer_key_id`, `witness_signatures` | P | Signed-tree-head signatures. |
| `appended_at`, `signed_at` | P | Time axes. |

**Fit — projection-only by construction.** The Merkle layer is a
*transparency* layer (RFC 6962). `canonical_bytes` and `leaf_serialized`
embed a copy of the audit entry — but the audit entry's *content*
(`audit_log.payload`) is already encrypted at its source row (§3.4). The
`merkle_leaves` copy is the **hashing-form bytes**; the tree commits to
them and they must be byte-identical to what was hashed. The spec
mandates: **the Merkle layer stores the same already-content-encrypted
form** — i.e. `leaf_serialized` is built from the *encrypted* `payload`,
so the tree commits to ciphertext and the transparency proofs work
without ever exposing plaintext. This is internally consistent with
§3.4's invariant *only if* the audit leaf's canonical/hashed form is
defined over the encrypted payload; **this ordering is the single
hardest open question — see §8.**

### 3.8 `cirislens_secrets.*` — `V010`

**Fit — already encrypted; this feature does not touch it.**
`cirislens_secrets.secrets.encrypted_value` is already
`AES-256-GCM(secret)` via `src/secrets/crypto.rs`. The secrets substrate
is the *pattern* this FSD generalizes, not a target of it. `access_log`,
`master_key_meta`, `filter_config`, `cirislens_pseudonyms` are
projection/metadata and stay as-is. One genuine note: `access_log.purpose`
and `access_log.error` are free-form — but the secrets module is
out of scope for this FSD; no change.

### 3.9 `cirisnode.*` — `V011` / `V012`

Eight federation-consensus tables (`contributions`, `votes`,
`credits_ledger`, `expertise_ledger`, `moderation_events`,
`slashing_attestations`, `reconsideration_requests`,
`reconsideration_attestations`, `promotion_attestations`).

| Representative columns | Class | Why |
|---|---|---|
| `*_id`, `contribution_type`, `domain`, `language`, `subject_kind` | P | PK + closed-enum cell discriminators; `contributions_cell` etc. indexes. |
| `author_id`, `voter_id`, `accuser_id`, `adjudicator_id`, `target_contributor`, `contributor_id` | P | Self-signed identities (Ed25519 pubkeys). |
| `submitted_at` / `cast_at` / `filed_at` / `attested_at` / `requested_at` | P | Time axes. |
| `is_canonical`, `canonicalized_at` | P | Pending-vs-canonical gate. |
| `balance`, `expertise`, `is_active` | P | Derived ledger scalars (scored). |
| **`payload`** | **E** | **The consensus content** — deferral text, proposal body, accusation evidence, adjudication rationale. |
| `witness_set` | ⚑ | Witness set for high-stakes contributions — names witnessing keys; structural-ish but free-form. See §3.12. |
| `aggregate_evidence` (`V012`) | ⚑ | Evidence blob backing a promotion attestation. See §3.12. |
| `registration_envelope`-style envelopes, all `signature*`/`scrub_*`/`persist_row_hash` | P | Integrity envelope. |

**Fit:** clean for `payload`. The derived `credits_ledger` /
`expertise_ledger` are pure projection (no content column) — exempt,
like `telemetry_metrics`.

### 3.10 Agent runtime substrates — `V024`–`V035`

`tasks`, `thoughts`, `service_correlations`, `scheduled_tasks`,
`tickets`, `deferral_reports`, `creation_ceremonies`,
`continuity_awareness`, `feedback_mappings`, `wa_cert`. These are Phase 3
absorption tables (FSD `CIRIS_PERSIST.md` §2) — mutable relational state.

Representative classification (`thoughts`, `V025`):

| Column | Class | Why |
|---|---|---|
| `thought_id`, `source_task_id`, `channel_id`, `thought_type`, `status` | P | Keys + closed-enum state. |
| `created_at`, `updated_at`, `round_number`, `thought_depth`, `parent_thought_id`, `agent_occurrence_id` | P | Structural / lifecycle. |
| **`content`** | **E** | **The thought's reasoning prose.** |
| `context_json`, `ponder_notes_json`, `final_action_json` | **E** | Reasoning content — JSONB, but content, not skeleton. |

`tasks` (`V024`): `description`, `context_json`, `outcome_json`,
`updated_info_content`, `images_json` → **E**; everything else → P.
`creation_ceremonies` (`V031`): `new_agent_purpose`,
`new_agent_description`, `creation_justification`,
`ethical_considerations`, `expected_capabilities` → **E**; IDs,
timestamps, `ceremony_status` → P.
`continuity_awareness` (`V032`): `final_thoughts`,
`reactivation_instructions`, `unfinished_tasks`, `deferred_goals` → **E**;
the rest → P.

**Fit — two genuine problems, flagged.** (i) `tickets` (`V028`) carries
`email` (`NOT NULL`) and `user_identifier` — **direct PII columns that
are also lookup keys**. This is the one place the skeleton/content
cleavage genuinely fights itself: the column is both PII (wants
encryption) and a query key (wants plaintext). See §3.12 and §8.
(ii) `wa_cert` (`V034`) carries `password_hash`, `api_key_hash`,
`oauth_external_id`, `oauth_links` — credential material. `password_hash`
/ `api_key_hash` are *already hashes* (not reversible content); but
`oauth_external_id` and `oauth_links` are identifying. See §3.12.

### 3.11 Primitives with no content — `V030`, `V037`, `V038`, `V039`

`maintenance_locks` (`V030`), `revoked_service_tokens` (`V037`),
`identity_sequences` (`V038`), `occurrence_registry` (`V039`).

**Fit — projection-only by construction; exempt.** These are
coordination primitives: a lock row, a revocation tombstone, a monotonic
counter (`identity_sequences.next_value` — MUST stay plaintext, it is
the sequence authority), an occurrence heartbeat. The single nuance:
`occurrence_registry.metadata` is a free-form JSONB blob — flagged in
§3.12. Nothing else here has content; FDE remains the at-rest posture.

### 3.12 Judgment calls — flagged for the user to decide

The boundary map does **not** silently decide these. Each is a genuine
"projection convenience vs. confidentiality" trade. The user picks.

| # | Column(s) | The tension |
|---|---|---|
| **JC-1** | `trace_events.deployment_domain` (and `cirisnode` `domain`) | The *known* hard call. The Ratchet clusters cohorts on it, so plaintext makes cross-agent analytics cheap — but for some deployments the domain string ("crisis-intervention", a named customer) *is* an operational disclosure. **Options:** (a) plaintext always; (b) content-encrypted always (analytics then query a per-deployment opaque cohort token instead); (c) per-deployment policy flag — domain is plaintext where the deployment declares it non-sensitive, encrypted otherwise, with a stable hashed cohort token kept plaintext for the Ratchet either way. |
| **JC-2** | `trace_events.agent_name` vs `agent_id_hash` | `agent_id_hash` is already a hash and unambiguously projection. `agent_name` is a human-readable label and may name a real deployment/person. Recommend: encrypt `agent_name`, keep `agent_id_hash` plaintext (V042 indexes already cover `agent_name` — it would need to move to a content column, which is fine: no analytics *groups* on the name, only displays it). User confirms. |
| **JC-3** | `deployment_type`, `agent_role`, `agent_template`, `deployment_region`, `deployment_trust_mode` | Cohort axes (V006). Most are low-cardinality closed enums (safe plaintext). `deployment_region` and `agent_template` are higher-cardinality and can be operationally revealing. User: are all six plaintext, or do `region`/`template` move to content? |
| **JC-4** | `trace_events.classifications` (V009) | `extracted_features` is derived signal → projection. But `classifications` names *which content classes* (PII categories — UserId, ChannelId, …) were detected. Knowing "this trace contained 3 UserId matches" is itself a small leak. User: projection or content? |
| **JC-5** | `trace_llm_calls` `base_url`, `model`, `service_name`, `handler_name` | `base_url` can be a private/internal LLM endpoint URL. User: plaintext operational labels, or encrypt `base_url` (and possibly `model`)? |
| **JC-6** | `cirisgraph.nodes` GIN index | Encrypting `attributes` kills `nodes_attributes_gin`. User: (a) drop the GIN index and accept full-scan attribute reads (V013 says the real workload doesn't need it), or (b) commission a `cirisgraph` shredding migration analogous to V042-final. |
| **JC-7** | `cirisgraph.edges.attributes`, `telemetry_metrics.labels`, `occurrence_registry.metadata`, `cirisnode` `witness_set` / `aggregate_evidence`, `federation_keys` `registration_envelope` / `*_envelope`, `federation_revocations.reason` | Free-form JSONB/text blobs on otherwise projection-only substrates. Each *leans* projection (structural/provenance, not reasoning content) but none is a closed type. User: blanket "free-form blobs on projection-only tables stay plaintext", or encrypt case-by-case? |
| **JC-8** | `tickets.email` / `tickets.user_identifier` (V028) | The genuine conflict (§3.10): PII that is also a lookup key. **Options:** (a) plaintext (FDE-only protection for ticket PII); (b) encrypt the value, keep a separate `email_hash` plaintext column for lookup (a deterministic-hash sidecar — equality lookup works, no range/substring); (c) encrypt and accept that ticket lookup-by-email becomes a decrypt-and-scan. |
| **JC-9** | `wa_cert` `oauth_external_id`, `oauth_links` (V034) | `password_hash` / `api_key_hash` are already non-reversible hashes (leave plaintext). `oauth_external_id` / `oauth_links` are identifying. User: encrypt the OAuth identity columns? |

---

## 4. Mechanism

### 4.1 Encrypt-on-write — the ingest path

Encryption hooks into the ingest path **after verify, after scrub,
before backend insert** — i.e. between step 5 (sign scrub envelopes) and
step 6 (decompose / insert) of
`src/ingest.rs::IngestPipeline::receive_and_persist`. Ordering is
load-bearing and must not change: verify-before-persist (MISSION.md §1.6)
runs over the *agent-shipped plaintext*; scrub mutates plaintext;
encryption is the *last* transform before bytes hit the backend.

For each content column of each decomposed row:

1. Take the **canonical bytes** of the content (`canonicalize_value` —
   the same canonicalizer the signature was computed over).
2. Derive a per-row content key (§4.3).
3. `ct = crypto::encrypt(content_key, fresh_nonce, canonical_content)`
   — AES-256-GCM via the existing `src/secrets/crypto.rs` facade.
4. The row's content column is written as `ct`; the per-row
   `salt` + `nonce` + `encryption_key_ref` are written to sidecar
   columns (§4.4). The plaintext skeleton/projection columns (including
   the V042-shredded scalars, §5) are written plaintext as today.

The shredded scalars are extracted from the *plaintext* content
**before** step 3 — encryption is strictly downstream of shredding.

Substrates with their own write paths (graph upsert, audit append,
cirisnode ingest) get the identical transform at their respective
`insert_*` boundaries; the encrypt step is a shared helper, not
re-implemented per backend (mirrors how `crypto.rs` is the sole
`ciris_crypto` import site).

### 4.2 Decrypt + re-verify on read

On every read that returns a content column:

1. Read `ct` + sidecar `salt`/`nonce`/`encryption_key_ref`.
2. Derive the content key (§4.3) and
   `pt = crypto::decrypt(content_key, nonce, ct)` — GCM auth-tag
   failure is a typed `Crypto` error (corruption or master-key
   mismatch).
3. **Re-verify the row signature** against `pt` using the existing
   `src/verify/` path (`verify_trace` / the audit-chain verifier). The
   decrypted content must match what the agent signed. A signature
   failure here is *not* a soft warning — it is a typed error, and the
   read fails honest (MISSION.md §1.6: "no third state").
4. Decrypted plaintext is held in `Zeroizing<Vec<u8>>` (§4.5) and
   returned; if the read also touched the plaintext projection cache,
   persist may reconcile (§4.6).

GCM is authenticated encryption — step 2 already detects ciphertext
tampering. Step 3 is the *additional* guarantee: it proves the plaintext
is the *agent's* content, not merely *some* content that decrypts
cleanly under persist's key. Confidentiality (GCM) and authenticity
(Ed25519/ML-DSA) stay orthogonal layers end to end (§1.1c).

### 4.3 Key structure — per-row content keys under the master key

Mirror `src/secrets/` exactly. The master key is **the secrets master
key path persist already owns**: hardware-rooted, derived by
`ciris_verify_core::derive_symmetric_key` over a TPM / Android Keystore /
Secure-Enclave-sealed seed (`src/secrets/hardware.rs`), with a software
fallback that is *honest about being software*
(`SecretsError::HardwareKeyUnavailable` — MISSION.md §1.6). Content
encryption introduces **no new master-key root**; it reuses this one,
under a distinct HKDF context string (a new stable wire constant
analogous to `SECRETS_MASTER_CONTEXT`, e.g. `content-at-rest-master-v1`,
so content keys and secret-store keys are domain-separated).

Per row: a fresh 32-byte `salt` and a fresh 12-byte `nonce`, exactly as
`src/secrets/crypto.rs` (`SALT_LEN = 32`, `NONCE_LEN = 12`). The per-row
content key is `derive_secret_key(content_master, salt)` —
PBKDF2-HMAC-SHA-256, 600k iters. Each row's content is encrypted under
its own derived key with its own nonce: no nonce reuse across rows, and
a single leaked per-row key never compromises any other row.

**Open performance question (see §8):** `secrets/` uses PBKDF2 at ~100 ms
per key because secrets are low-volume. Trace ingest is high-volume.
Per-row PBKDF2 at ingest rate is almost certainly too slow; the
implementation phase must choose a per-row KDF appropriate to the volume
— most likely **HKDF-SHA-256** (microseconds, the same primitive
`hardware.rs` already uses for master derivation) keyed by
`(content_master, row-unique salt)`. This FSD records HKDF-per-row as the
*intended* mechanism and PBKDF2-per-row as explicitly rejected on
performance grounds; the implementation phase confirms.

### 4.4 Per-row sidecar columns

Each content-bearing table gains, per encrypted column (or one shared
set where a table has a single content column), the sidecar columns the
secrets schema already models (`V010` `secrets`): `salt BYTEA`,
`nonce BYTEA`, `encryption_key_ref TEXT` (FK into a content-key-meta
table mirroring `master_key_meta`, so master-key rotation has one
surface). A `content_enc_version` small-int per row records the
encryption-format version so future format changes are
detectable/migratable. These sidecar columns are themselves
projection/metadata — plaintext.

### 4.5 Zeroization

Decrypted content is sensitive material in process memory. As
`src/secrets/` already does (`hardware.rs` wraps the raw seed in
`Zeroizing`), every decrypted plaintext buffer and every derived per-row
key is held in `zeroize::Zeroizing` so it is scrubbed on drop. The
re-verify step (§4.2) operates on the `Zeroizing` buffer in place. No
decrypted content is logged, ever (the AV-15 sanitization discipline —
`SecretsError::kind()` tokens, never payload bytes — extends here).

### 4.6 Reconciliation

The plaintext projection (shredded scalars, skeleton) is a *cache* of
facts derivable from the signed authoritative content. The authoritative
form is `AES-GCM(signed_canonical_content)`. Where a read both decrypts
content and consults the projection, persist may reconcile: if a shredded
scalar in the plaintext column disagrees with the value re-extracted
from the decrypted-and-verified content, the **signed content wins** and
the divergence is surfaced as a typed error (a corruption signal —
fail-honest, MISSION.md §1.6). Routine reads trust the cache for speed;
reconciliation is the audit/repair path.

---

## 5. The V042 consequence — full shredding ("V042-final")

V042 built **expression indexes** on `payload->>'csdma_plausibility_score'`
etc. — `migrations/{postgres,sqlite}/lens/V042__trace_events_analytics_indexes.sql`.
The index key carries `(payload->>'<field>')::float8` (Postgres) /
`json_extract(payload, '$.<field>')` (SQLite) as a trailing covering
column, and the partial predicate filters `payload ? '<field>'`.

**Once `payload` is AES-GCM ciphertext, every one of those expression
indexes extracts nothing.** `payload->>'x'` over ciphertext is not a
score; it is garbage or NULL. The four V042 Group A indexes
(`trace_events_an_csdma`, `_an_dsdma`, `_an_idma_keff`, `_an_idma_corr`)
and the `payload`-derived FILTER columns of Group B (`trace_events_an_trace_summary`)
silently stop working.

Content encryption therefore **forces** completing V042's design —
promoting the shredded scalars from expression-index targets to **real,
plaintext, typed columns.** This is *part of this work*, not separate;
it is the first migration phase (§9.1). Call it **V042-final / full
shredding.** It comprises:

1. **Promote the four scalars to real columns** on `trace_events`:
   `csdma_plausibility_score`, `dsdma_domain_alignment`, `idma_k_eff`,
   `idma_correlation_risk` — typed `DOUBLE PRECISION`, NULLABLE. Either
   persist-populated columns written by the ingest decompose pass (the
   recommended shape — works identically on both backends; generated
   columns over an encrypted blob are impossible), or, if a deployment
   keeps `payload` plaintext during transition, generated columns
   bridging the gap. The locked choice: **persist-populated real
   columns**, written by decompose from the plaintext content *before*
   encryption (§4.1).
2. **Rebuild V042's indexes on the real columns.** The Group A indexes
   become plain composite/partial indexes `(deployment_domain, ts,
   agent_id_hash, <real scalar column>)` — no expression, no
   `payload ?` predicate; the partial predicate becomes
   `WHERE event_type = '<EVENT>' AND <scalar> IS NOT NULL`. Simpler and
   faster than the V042 expression indexes, and **identical on Postgres
   and SQLite** (the dialect divergence in V042 existed *only* because
   JSON-extraction syntax differs — real columns erase it).
3. **Rewrite the `ReadEngine` SQL** (`src/store/postgres.rs`,
   `src/store/sqlite.rs` — `cross_agent_divergence`,
   `list_trace_summaries`, and the rest of the ~21-method set) to query
   the real columns instead of `payload->>'…'` / `json_extract(...)`.
   The "exact-expression-match constraint" V042 documents disappears:
   no expression to match.

Net: V042-final is strictly better engineering *independent of
encryption* (real typed columns beat expression indexes), and it is the
*precondition* that makes `payload` encryptable at all. The boundary map
(§3.1) lists the four shredded scalars as projection columns precisely
because this phase makes them real.

---

## 6. Backend-agnostic guarantee

This is non-negotiable (`MEMORY`: no PG-only declarations).

- **One mechanism.** Application-layer AES-256-GCM via
  `src/secrets/crypto.rs` → `ciris_crypto::aes_gcm`. Not SQLCipher
  (SQLite-only — would make SQLite and Postgres structurally different).
  Not Postgres TDE / `pgcrypto` (Postgres-only). Not filesystem/FDE
  (deployment-managed, not persist-managed — the posture this FSD
  *replaces* for content). The ciphertext is computed in Rust, identically,
  before it reaches either backend.
- **One column type.** Encrypted content lands in `BYTEA` on Postgres
  and `BLOB` on SQLite — the *identical* logical column, the same
  `Vec<u8>` round-trip. This is the same shape `cirislens_secrets.secrets.encrypted_value`
  already uses on both backends (`V010`). No backend sees anything the
  other does not.
- **One test suite.** Every encryption test runs against *both*
  backends — encrypt-on-write, decrypt-on-read, re-verify, GCM-tamper
  rejection, master-key-mismatch rejection, the §4.6 reconciliation
  path, and the §3.4 / §3.7 "hash chain commits to plaintext / Merkle
  commits consistently" invariants. A test that passes on one backend
  and not the other is a release blocker. The V042-final indexes
  (§5) are likewise verified identical on both.

---

## 7. Threat model

**Adversary.** Anyone who obtains the database **at rest** — the DB file
or a backup of it — *without* the running persist process and its
in-memory key cache. Concretely: a stolen solar-LoRa Pi or phone; a
malicious or compromised federation relay host that stores another
agent's corpus; a leaked Postgres backup tarball; a discarded disk.

**What is defended.** The **reasoning content** — `trace_events.payload`,
`trace_llm_calls.prompt` / `response_text`, `cirisgraph.nodes.attributes`,
`audit_log.payload`, `cirisnode` `payload`, agent-runtime
`content`/`description`/`*_json` — is AES-256-GCM ciphertext under a
key the adversary does not have (the key is HKDF-derived from a
TPM/Keystore/Secure-Enclave-sealed seed; on a software-fallback host the
key derives from an OS-keyring seed the adversary would *also* need —
the same residual `docs/THREAT_MODEL.md` AV-25 already names for the
software-signer fallback). An adversary with the DB file alone cannot
read what any agent reasoned about.

**What the projection still reveals — stated honestly.** A stolen DB
file still exposes the plaintext skeleton: hashed agent IDs
(`agent_id_hash`), timestamps (`ts`), event types, trace/thought IDs,
cost scalars, the V042-final scored scalars, the cohort axes (subject to
the JC-1/JC-3 decisions), the audit hash-chain and Merkle structure, and
the federation directory's trust graph (§3.6). **This is not a leak —
it is the intended federation-transparency surface** (§1.1b, §2.1). The
Coherence Ratchet and N_eff measurement are *designed* to operate on
exactly this data; a peer is *supposed* to be able to score it. The
honest framing for operators: content encryption at rest protects *what
the agent reasoned about*, not *that the agent reasoned, when, at what
cost, and how well it scored*. The latter is public-by-design evidence.

**Residual.** (i) The running process holds derived keys and decrypted
buffers in memory — an adversary with live process memory access (root
on the running host, a debugger) is outside this threat model, exactly
as for `src/secrets/`. (ii) Software-fallback hosts inherit the
AV-25-class residual: no hardware key isolation; mitigation is
operational (prefer hardware-attested deployments). (iii) The metadata
projection is unencrypted by design — FDE remains *recommended* for
defense-in-depth over the projection, but is no longer the *only* thing
standing between an adversary and the content.

**Proposed new THREAT_MODEL.md entry — `AV-<next>`: at-rest content
confidentiality.** A new `AV-` entry stating: persist encrypts substrate
*content* at rest under the hardware-rooted secrets master key;
substrate *projection/skeleton* stays plaintext as the intended
transparency surface and is signed (tamper-evident); the federation
directory and coordination primitives are projection-only and exempt;
software-fallback hosts inherit the AV-25 residual.

**Posture change at `docs/THREAT_MODEL.md:738`.** That paragraph
currently delegates *all* at-rest confidentiality to deployment FDE. It
must be revised: at-rest confidentiality **of content** becomes
persist-managed (this feature); FDE remains *recommended* for the
plaintext projection metadata as defense-in-depth, but is downgraded
from "the mitigation" to "a complementary mitigation." The line that FDE
is the mitigation for *content* is deleted — content is now encrypted by
persist.

---

## 8. Honest assessment — what is hard or unresolved

The skeleton/content cleavage is real and most substrates fit it
cleanly. The genuinely hard parts:

1. **Audit-leaf canonical form vs. encryption ordering (§3.4 + §3.7) —
   the single hardest open question.** The audit hash chain commits to
   `canonical(payload)`; the Merkle tree commits to `AuditLeaf` hashing-
   form bytes that *embed* the payload. For the transparency proofs to
   remain verifiable by a peer, the leaf must commit to a *stable,
   reproducible* byte form. Two self-consistent designs exist and the
   FSD does **not** pick one — it must be decided before §9.4:
   (a) the chain/tree commit to **plaintext** `canonical(payload)`, and
   encryption is a pure confidentiality wrapper applied *after* hashing
   (clean integrity story; but a peer verifying a proof would need the
   plaintext, so cross-peer Merkle audit of *encrypted* corpora cannot
   verify leaf contents — only structure); or
   (b) the chain/tree commit to the **ciphertext**, so proofs verify
   against ciphertext and a peer can audit structure without plaintext
   (clean transparency-of-encrypted-corpus story; but then "the chain
   commits to what the agent signed" needs the agent's signature to also
   be over the ciphertext, which fights §1.1c's orthogonality). This is
   a real architectural fork. **Flagged for decision.**

2. **`trace_llm_calls` has no per-row signature (§3.2).** Its integrity
   rides on the parent `trace_events` row. Encrypting `prompt` /
   `response_text` means decrypt-on-read cannot re-verify against a
   *local* signature — it must verify against the parent event. The
   read path must therefore join to the parent, or the decompose pass
   must propagate a per-call integrity hash. Tractable, but it makes the
   §4.2 re-verify step non-uniform across substrates.

3. **Per-row KDF performance (§4.3).** `secrets/` uses PBKDF2 at ~100 ms
   per key. At trace-ingest volume that is fatal. The FSD records HKDF-
   per-row as the intended mechanism but the implementation phase must
   confirm the throughput and the domain-separation argument.

4. **Substrates that do not fit the cleavage** — stated plainly rather
   than forced: `telemetry_metrics` (§3.5) has *no content column* and
   no signature — exempt; the federation directory (§3.6) is a
   *transparency substrate* by purpose — projection-only, exempt; the
   coordination primitives (§3.11) have no content — exempt;
   `credits_ledger` / `expertise_ledger` (§3.9) are pure derived
   projection — exempt. "Exempt" is an honest classification, not a gap:
   these substrates have nothing confidential to encrypt.

5. **`tickets.email` (§3.10, JC-8)** is the one column where the
   cleavage genuinely self-contradicts — PII that is also a query key.
   No option is free; the user picks among plaintext / hash-sidecar /
   decrypt-and-scan.

6. **The GIN index on `cirisgraph.nodes.attributes` (§3.3, JC-6)** is a
   second, smaller V042 — encrypting `attributes` kills predicate
   push-down. V013's own header argues the real workload doesn't need
   it, so dropping the index is probably fine — but it is a decision,
   not an assumption.

---

## 9. Sequenced implementation plan

Honest, phased, multi-release. Each phase is its own release and stands
on its own. No phase ships content encryption until the one before it
has landed.

### 9.1 Phase 1 — boundary map + V042-final shredding migration

Land §3 (this document) as the committed boundary map. Resolve the
§3.12 judgment calls (JC-1..JC-9) and the §8(1) audit-leaf fork. Ship
the **V042-final** schema migration (§5): promote the four shredded
scalars to real `DOUBLE PRECISION` columns on `trace_events`,
backfill them from existing plaintext `payload`, on both backends.
*No encryption yet* — `payload` is still plaintext; this phase is pure
schema/shredding and is independently valuable.

### 9.2 Phase 2 — `ReadEngine` SQL rewrite + V042-final index rebuild

Rewrite the ~21 `ReadEngine` methods (`src/store/postgres.rs`,
`src/store/sqlite.rs`) to query the real scalar columns. Drop the V042
expression indexes; create the V042-final plain composite/partial
indexes (§5.2). Verify identical query plans and results on both
backends. Still no encryption — but the read path no longer depends on
`payload` being plaintext-JSON.

### 9.3 Phase 3 — ingest-path encrypt-on-write

Add the content-key-meta table and the per-row sidecar columns (§4.4).
Implement the shared encrypt helper (§4.1) and the per-row HKDF key
derivation under the content master (§4.3). Wire encrypt-on-write into
the ingest decompose boundary and the graph/audit/cirisnode write paths
for the substrates classified `E` in §3. New writes land encrypted; old
rows are still plaintext (read path handles both via
`content_enc_version`).

### 9.4 Phase 4 — read-path decrypt + signature re-verify + reconcile

Implement decrypt-on-read, the §4.2 signature re-verification, the
`Zeroizing` discipline (§4.5), and the §4.6 reconciliation path.
Resolve §8(1) and §8(2) here in code. This is the phase that delivers
the actual confidentiality guarantee end to end.

### 9.5 Phase 5 — transparent migration of existing plaintext data

A versioned data migration walks every pre-encryption row, encrypts its
content columns in place, and bumps `content_enc_version`. **Unilateral**
— post-2.9.0 persist is the sole DB opener, the format change is entirely
behind the `Engine` API, and no downstream consumer coordinates on it
(gated only on absorption completeness, FSD `CIRIS_PERSIST.md` §2).
Batched and lock-considerate, mirroring `secrets`'
`reencrypt_all` chunking (`REENCRYPT_CHUNK_SIZE`).

### 9.6 Phase 6 — documentation

Update `docs/THREAT_MODEL.md`: add the `AV-` entry (§7) and revise the
`:738` at-rest posture. Update `MISSION.md` §1.6 — content encryption at
rest is a *fail-honest* feature (decrypt-then-re-verify, no third state;
reconciliation surfaces divergence as a typed error) and belongs in the
"fail-honest is a mission stance" section. Update
`FSD/CIRIS_PERSIST.md` to reference this substrate property.

---

## 10. Summary

CIRISPersist can encrypt the *content* of every substrate at rest —
persist-managed, hardware-rooted, 100% backend-agnostic — while keeping
a plaintext, signed, queryable projection. This is uniquely possible for
CIRIS data because the query set is closed (the projection is knowably
complete), the federation scores derived signals rather than content
(the privacy boundary *is* the queryability boundary), every record is
agent-signed (the projection is plaintext-but-unforgeable), and the
scrubber already located the content/signal seam. The capability is a
federation that measures reasoning quality without reading reasoning
content. V042-final (real shredded columns) is the precondition. The
hard parts — audit-leaf canonical ordering, `trace_llm_calls` lacking a
local signature, per-row KDF throughput, `tickets.email` — are named,
not hidden, and the substrates that do not fit the cleavage are
classified exempt, honestly.
