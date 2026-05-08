# FSD: Post-Ingest Filter Pipeline + Federated Secrets Service

**Status:** Locked
**Author:** Eric Moore (CIRIS Team) with Claude Opus 4.7
**Created:** 2026-05-02
**Locked:** 2026-05-04
**Closes:** CIRISPersist#19 (Absorb trace scrubber + feature extractor as post-ingest filter pipeline)
**Drives:** CIRISEdge issue (forthcoming) — primary call site for the pipeline
**Adjacent:** CIRISPersist#7 (canonicalization), #14 (`verify_hybrid_via_directory`), #17 (`StewardSigner`), #18 (`detection_events` + `calibration_bundles`)
**Risk:** Architectural. Two new substrate surfaces: (1) a typed multi-stage pipeline behind the existing `Scrubber` trait slot, (2) a federated `SecretsService` that absorbs the full agent-side `SecretsServiceProtocol` surface so agents can delegate secrets CRUD to persist. Heavy ML deps and crypto deps stay opt-in behind cargo features. No agent breakage at any phase — agent's local SecretsService becomes a thin client over persist's API.

---

## 1. Why this exists

Persist already owns the **wire-to-storage boundary**: `Engine.receive_and_persist` parses, verifies, and decomposes a hybrid-signed `BatchEnvelope` into rows. The `Scrubber` trait (`src/scrub/mod.rs`) is the documented hook between verify and store; `docs/INTEGRATION_LENS.md:336` already documents `Engine(scrubber=my_scrubber)` as a constructor parameter; `docs/PUBLIC_SCHEMA_CONTRACT.md` already exposes `pii_scrubbed: bool` as a tier-stable column.

**What is missing today:**

1. **A default scrubber.** `NullScrubber` is a passthrough. Production deployments must inject a real scrubber, and the only canonical implementation lives in lens-core (lifted from `cirislens-core`).
2. **A typed feature extractor.** Lens-core's `extract/` module produces a `Features` struct that every consumer wants (RATCHET, registry, partner, sovereign), reachable today only through lens-core.
3. **A content-class taxonomy.** CIRISAgent ships `SecretsFilter` (12 secret types, AES-256-GCM, regex) and `AdaptiveFilterService` (6 trigger types, 5 priorities, learning loop). They run **inside the agent**, before traces are emitted. Persist has no visibility into what they detected and consumers downstream can't reproduce the same decisions on stored traces.
4. **A federated secrets store.** The agent's `SecretsServiceProtocol` covers full CRUD + decapsulation + key rotation + hardware-key migration + audit logging (~13 methods, see §3.1). Today every agent runs a private SQLite store. There is no canonical federated surface for: recalling a secret across agents in the same federation, key rotation across the fleet, audit-trail aggregation, hardware-key delegation to CIRISVerify across hosts.

**The claim:** these four surfaces are one substrate concern at four layers of granularity (classify → scrub → extract → encrypt-and-store). They share inputs, share output shape, share the storage column, and share the trust boundary. Persist should ship them as a single `pipeline` module + `secrets` module with a unified taxonomy. Edge invokes the pipeline on the receive boundary so persist's storage never sees cleartext PII or unencrypted secrets. **Secrets are on us.**

This FSD locks down both surfaces.

## 2. Scope

### 2.1 Pipeline module (`src/pipeline/`)

```
src/pipeline/
├── mod.rs              — Pipeline orchestration + Stage trait
├── classify/           — content-class taxonomy (the unified matrix; §6)
│   ├── mod.rs            — ContentClass + Sensitivity + Action enums
│   ├── matchers.rs       — typed matchers (regex / length / count / freq / custom / semantic / NER / walker)
│   └── taxonomy.rs       — built-in catalog: 12 secret types + 10 patterns + 10 PII + 4 structural
├── scrub/              — already partly in src/scrub/; expand per #19
│   ├── mod.rs            — Scrubber trait (existing) + DefaultScrubber (new)
│   ├── walker.rs         — depth-limited JSON walk
│   ├── regex.rs          — patterns + year-residue + probe-match invariants
│   ├── fields.rs         — SCRUB_FIELDS static
│   ├── ner.rs            — NER pipeline (cfg(feature = "scrub-ner"))
│   ├── xlm_r_loader.rs / distilbert_loader.rs / ort_loader.rs
│   └── proptests.rs
└── extract/            — typed feature extractor
    ├── features.rs       — Features struct
    ├── static_extract.rs — walk components → populate Features
    └── json_path.rs      — JSONPath utility
```

### 2.2 Secrets module (`src/secrets/`)

```
src/secrets/
├── mod.rs              — SecretsService trait + types
├── store.rs            — Backend-agnostic SecretsStore (postgres + sqlite)
├── crypto.rs           — Thin facade over ciris-crypto. NO primitive crypto in persist.
│                         AES-256-GCM, PBKDF2, HKDF, HMAC all come through
│                         ciris-crypto re-exports. See §7.6 for the boundary.
├── hardware.rs         — Thin facade over ciris-keyring (CIRISVerify TPM/Keystore)
│                         for hardware-backed master keys (cfg(feature = "secrets-hw"))
├── decapsulate.rs      — Action-context decapsulation (whitelist-checked)
├── audit.rs            — Access-log row + audit append
├── rotate.rs           — reencrypt_all + master-key rotation (calls ciris-crypto)
└── api.rs              — Wire-format types for federated SecretsService API
```

**Crypto invariant (load-bearing):** persist takes ZERO direct dependencies on AES-GCM, PBKDF2, HKDF, HMAC, or any other crypto primitive crate. Every cryptographic operation routes through `ciris-crypto` (symmetric + KDF + MAC) or `ciris-keyring` (hardware-backed keys). CIRISVerify is the federation's crypto authority; persist is a substrate consumer. If a primitive is missing, the prerequisite is to add it to `ciris-crypto` first — never to bypass.

### 2.3 Stage execution

| Stage          | Input                                  | Output                                   | Side effects                                   |
|----------------|----------------------------------------|------------------------------------------|------------------------------------------------|
| **Classify**   | typed `BatchEnvelope` (post-verify)    | `Vec<ContentClassMatch>` per component   | none                                            |
| **Scrub**      | `BatchEnvelope` + classifications       | mutated `BatchEnvelope` + `usize` modified | (per match) `ScrubReplace` / `Hash` / `Pseudonymize` / `Drop` |
| **EncryptAndStore** | `BatchEnvelope` + classifications  | mutated `BatchEnvelope` + `Vec<SecretRef>` | writes encrypted `SecretRecord` rows to `cirislens_secrets.secrets` |
| **Extract**    | scrubbed `BatchEnvelope`                | typed `Features`                          | none                                            |

Stages are **declarative**, run in `(Classify, Scrub, EncryptAndStore, Extract)` order, and each respects the `Action` field on the prior `ContentClassMatch`. Scrub and EncryptAndStore are mutually exclusive per match (a class with `Action::EncryptAndStore` does NOT also `ScrubReplace`; the placeholder `{SECRET:uuid:description}` from EncryptAndStore replaces the original span).

### 2.4 Feature gating

```toml
[features]
default = []

# Pipeline
classify         = []                                                                # light: regex + length + count + freq matchers
scrub            = ["classify"]                                                      # regex-only scrubber + walker
scrub-ner        = ["scrub", "candle-core", "candle-nn", "tokenizers", "hf-hub"]    # +500MB build
scrub-ort        = ["scrub-ner", "ort", "ndarray"]                                  # INT8 ONNX
extract          = ["scrub"]                                                        # typed Features

# Secrets — ALL crypto goes through ciris-crypto / ciris-keyring (CIRISVerify).
# Persist does NOT take direct deps on aes-gcm / pbkdf2 / hkdf / hmac /
# any other primitive crate. If a primitive is missing from ciris-crypto,
# the prerequisite is to add it there first (see §7.6).
secrets          = ["ciris-crypto/aes-gcm", "ciris-crypto/kdf", "ciris-crypto/hmac"]   # software-key crypto via ciris-crypto
secrets-hw       = ["secrets", "ciris-keyring/symmetric-derivation"]                   # CIRISVerify TPM/Keystore
secrets-server   = ["secrets", "server"]                                               # HTTP API for federated CRUD

# Bundles
default-pipeline = ["scrub-ner", "extract", "secrets"]                              # production lens / edge ingest
default-sovereign = ["scrub", "extract", "secrets"]                                 # Pi-class / sovereign mode (no ML)
```

Sovereign-mode + Pi-class deployments build with `default-sovereign` (regex-only scrubber, no ML). Production federated deployments build with `default-pipeline`. Agent-side embedded persist (umbrella FSD Phase 3) builds with `classify + scrub + secrets` — agents delegate secrets CRUD to the embedded persist; the agent's own `SecretsService` becomes a Rust-FFI client.

### 2.5 Out of scope

- Replacing CIRISAgent's `AdaptiveFilterService` (it remains at the agent's wire-receive boundary; it's adapter-context-aware in ways persist isn't).
- Federation-side **policy** about content classes (consumers may disagree on what "PII" means; this FSD specifies shape, not policy).
- The 16-CRC projection itself (lives in `cirislens-core` per CIRISLensCore#3; this FSD only covers the upstream `Features` struct).

## 3. Reference: existing CIRISAgent surfaces

### 3.1 `SecretsServiceProtocol` (the surface to absorb)

**Path:** `CIRISAgent/ciris_engine/protocols/services/runtime/secrets.py`
**Implementation:** `CIRISAgent/ciris_engine/logic/secrets/{service,filter,store,encryption}.py`

Method-by-method, this is everything persist must provide:

| # | Method                              | Returns                            | Purpose |
|---|-------------------------------------|------------------------------------|---------|
| 1 | `encrypt(plaintext)`                | base64 ciphertext                   | Direct AES-256-GCM encrypt for caller-managed transport |
| 2 | `decrypt(ciphertext)`               | plaintext                           | Direct decrypt |
| 3 | `store_secret(key, value)`          | `()`                                | Store user-keyed encrypted secret (manual entry path) |
| 4 | `retrieve_secret(key)`              | `Option<plaintext>`                 | Retrieve by key |
| 5 | `process_incoming_text(text, msg_id)` | `(filtered_text, Vec<SecretReference>)` | Detect → encrypt → replace with `{SECRET:uuid:desc}` |
| 6 | `decapsulate_secrets_in_parameters(action_type, params, ctx)` | mutated `params` | Replace `{SECRET:...}` placeholders with cleartext for whitelisted actions |
| 7 | `list_stored_secrets(limit)`        | `Vec<SecretReference>`              | Metadata-only listing (no decrypt) |
| 8 | `get_filter_config()`               | `FilterConfig`                      | Read current filter pattern catalog |
| 9 | `recall_secret(uuid, purpose, accessor, decrypt)` | `Option<SecretRecallResult>` | Audited recall by UUID with optional decryption |
| 10| `forget_secret(uuid, accessor)`     | `bool`                              | Audited delete |
| 11| `update_filter_config(updates, accessor)` | `FilterUpdateResult`           | CRUD on pattern catalog |
| 12| `get_service_stats()`               | `SecretsServiceStats`               | Total secrets / active filters / encryption status |
| 13| `is_healthy()`                      | `bool`                              | Liveness |
| 14| `reencrypt_all(new_master_key)`     | `bool`                              | Master-key rotation; re-encrypts every stored secret |

Plus the agent's `SecretsStore` exposes additionally:

| # | Method                                | Returns                  | Purpose |
|---|---------------------------------------|--------------------------|---------|
| 15| `get_access_logs(uuid?, limit)`       | `Vec<AccessLogEntry>`    | Audit trail query |
| 16| `rotate_master_key(new?)`             | `bytes`                  | Generate or apply new master key |
| 17| `test_encryption()`                   | `bool`                   | Health check on encryption path |
| 18| `migrate_to_hardware_key()`           | `bool`                   | Migrate software-stored master to CIRISVerify TPM/Keystore |

**Persist must provide all 18.** That is the meaning of "secrets are on us."

### 3.2 SecretType taxonomy (12 values)

```python
class SecretType(str, Enum):
    API_KEYS         = "api_keys"
    BEARER_TOKENS    = "bearer_tokens"
    PASSWORDS        = "passwords"
    URLS_WITH_AUTH   = "urls_with_auth"
    PRIVATE_KEYS     = "private_keys"
    CREDIT_CARDS     = "credit_cards"
    SOCIAL_SECURITY  = "social_security"
    AWS_ACCESS_KEY   = "aws_access_key"
    AWS_SECRET_KEY   = "aws_secret_key"
    GITHUB_TOKEN     = "github_token"
    SLACK_TOKEN      = "slack_token"
    DISCORD_TOKEN    = "discord_token"
```

### 3.3 SensitivityLevel (4 values)

`LOW`, `MEDIUM`, `HIGH`, `CRITICAL`. Maps to `auto_decapsulate_for_actions` defaults:

| Sensitivity | Default `auto_decapsulate_for_actions`       |
|-------------|----------------------------------------------|
| `CRITICAL`  | `[]` — manual recall only                    |
| `HIGH`      | `["tool"]`                                   |
| `MEDIUM`    | `["tool", "speak"]`                          |
| `LOW`       | `["tool", "speak", "memorize"]`              |

### 3.4 TriggerType (6) and FilterPriority (5)

```python
class TriggerType(str, Enum):
    REGEX     = "regex"
    COUNT     = "count"
    LENGTH    = "length"
    FREQUENCY = "frequency"
    CUSTOM    = "custom"
    SEMANTIC  = "semantic"

class FilterPriority(str, Enum):
    CRITICAL = "critical"
    HIGH     = "high"
    MEDIUM   = "medium"
    LOW      = "low"
    IGNORE   = "ignore"
```

### 3.5 Lens-core scrubber + extractor

Lifted code in `CIRISLensCore/src/{scrub,extract}/` — ~3,300 LOC, 47 tests passing per persist#19. Detailed module breakdown was in the v0.5.0 draft; absorbed verbatim with `crate::scrub` → `crate::pipeline::scrub` rename.

## 4. Architecture: edge as call site, persist as substrate

### 4.1 The call-site decision

The pipeline's primary call site is **CIRISEdge**, not persist. Reasoning:

- **Defense-in-depth (THREAT_MODEL.md AV-3).** If scrub runs in persist, persist's process memory briefly holds cleartext PII. If it runs in edge, persist never sees cleartext. Operator logs, peer replication, sovereign-mode cross-host gossip — all clean.
- **Encryption boundary.** Secrets must be encrypted before they touch persist's storage. If persist is the encryptor, the moment between "received cleartext" and "wrote ciphertext" is a window of exposure. Edge encrypting upstream collapses that window.
- **Edge is already content-aware.** Edge runs `verify_hybrid` which requires understanding the payload bytes. Adding scrub/extract/encrypt is a continuation of that role, not a new one.
- **Multi-consumer storage shape.** RATCHET, registry, partner, sovereign all read `cirislens.trace_events.{payload, classifications, extracted_features}`. The shape lives at persist regardless of who produced it.

### 4.2 Crate ownership vs. call site

| What                              | Owner   | Rationale |
|-----------------------------------|---------|-----------|
| `pipeline` module (types, traits) | Persist | Owns storage shape; closure pattern (CIRISPersist#7/#14/#17/#18) |
| `secrets` module (types, traits)  | Persist | Owns encrypted-row storage and federation-stable wire types |
| Default classifier catalog        | Persist | Same as schema columns — substrate-stable |
| Default scrubber implementation   | Persist | Lifted from lens-core per persist#19 |
| Default extractor implementation  | Persist | Same |
| **Pipeline runtime invocation**   | Edge    | First peer-controlled component on the receive path |
| **Secrets storage backend**       | Persist | `cirislens_secrets` schema (§7) lives in persist's database |
| **Decapsulation enforcement**     | Persist | Action-whitelist + audit must run with substrate keys |

Edge embeds `ciris-persist-pipeline` and `ciris-persist-secrets` as Rust libraries (cargo deps on `ciris-persist` with `pipeline` + `secrets` features). Edge calls the pipeline; pipeline emits a typed sidecar; edge forwards (envelope + sidecar) to persist; persist verifies the sidecar's edge signature and stores. Persist itself runs the same pipeline as a defense-in-depth no-op pass on the embedded path (sovereign / agent-embedded deployments without an edge).

### 4.3 Wire format: edge → persist sidecar

The existing wire format `BatchEnvelope` (TRACE_WIRE_FORMAT.md) flows agent → edge unchanged. Between edge and persist, a **federation-internal extension envelope** wraps the (now scrubbed) `BatchEnvelope`:

```rust
/// Wire envelope from edge to persist. Contains the scrubbed agent
/// BatchEnvelope plus the typed sidecar produced by the pipeline.
/// Edge-signed; persist verifies before storing.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PipelineEnvelope {
    /// Federation-internal schema version. Bumped when the sidecar
    /// shape changes. Persist rejects unknown versions.
    pub pipeline_schema_version: String,        // "1.0"

    /// The agent's BatchEnvelope, post-scrub. Original agent signature
    /// (Ed25519 + ML-DSA-65) is preserved on this inner envelope.
    pub envelope: BatchEnvelope,

    /// Typed pipeline outputs.
    pub sidecar: PipelineSidecar,

    /// Edge's hybrid signature over canonical(envelope || sidecar).
    /// Persist verifies via ciris-verify-core HybridVerifier.
    pub edge_signature: HybridSignatureBlock,

    /// Edge identity — looked up in federation_keys table for verify.
    pub edge_key_id: String,
    pub edge_pqc_key_id: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PipelineSidecar {
    /// Per-component classifications.
    pub classifications: Vec<Vec<ContentClassMatch>>,

    /// Typed features (None if `extract` feature off at edge build).
    pub features: Option<Features>,

    /// Encrypted secret records produced by EncryptAndStore.
    /// Edge writes these to persist via the secrets API as a
    /// transactional batch alongside the trace.
    pub encrypted_secrets: Vec<EncryptedSecretRecord>,

    /// Pipeline metadata for observability.
    pub pipeline_metadata: PipelineMetadata,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PipelineMetadata {
    /// Stages that ran (so persist can verify the pipeline did its job).
    pub stages_executed: Vec<String>,           // ["classify", "scrub", "encrypt_and_store", "extract"]

    /// Total fields modified (sum across components).
    pub fields_modified: usize,

    /// Number of secrets encrypted (length of encrypted_secrets).
    pub secrets_encrypted: usize,

    /// Wall-clock pipeline latency.
    pub pipeline_duration_ms: u32,

    /// Edge build identifier (binary version, host, etc.) for forensics.
    pub edge_build_id: String,
}
```

**Invariants persist enforces on `receive_pipeline_envelope()`:**

1. `pipeline_schema_version` is a known version (currently `"1.0"`).
2. `edge_signature` verifies via `verify_hybrid_via_directory` against `edge_key_id` in `federation_keys`. Edge keys are a new role-tagged subset (see §8.1).
3. The inner agent `BatchEnvelope` signature ALSO verifies (defense-in-depth — edge could be compromised; agent's signature is the ground truth for content authenticity).
4. `pii_scrubbed` MUST be `true` if `pipeline_metadata.stages_executed` contains `"scrub"`.
5. `classifications.len()` MUST equal the inner envelope's component count.
6. Each `EncryptedSecretRecord.secret_uuid` MUST appear at least once in the scrubbed envelope as a `{SECRET:uuid:description}` placeholder (orphan-secret detection).
7. `pipeline_metadata.fields_modified` is non-decreasing across replays of the same envelope (replay safety).

If any invariant fails, persist returns `IngestError::PipelineInvariant` and does NOT store the trace or the secrets. Edge sees a 422 and treats the envelope as poisoned.

### 4.4 Embedded mode (no edge)

For sovereign-mode + agent-embedded deployments without an edge:

- Persist's `Engine.receive_and_persist` runs the pipeline inline (`Stage` trait orchestration, same code as edge calls).
- The intermediate `PipelineEnvelope` is constructed in-process and never serialized to a wire.
- The `edge_signature` is replaced by `Engine`'s own signing identity (a self-signed sidecar marker — recorded for audit but trivially verifiable).
- All other invariants (1, 4–7) still apply.

Same code, same invariants, two call sites.

## 5. Pipeline architecture

### 5.1 Stage trait

```rust
/// A pipeline stage operates on a verified BatchEnvelope and produces
/// some side-channel output (classifications, features, encrypted secrets)
/// plus possibly mutates the envelope in place (scrub, encrypt-and-store).
#[async_trait]
pub trait Stage: Send + Sync {
    type Output;
    type Error: Into<crate::Error> + Send + Sync;

    fn name(&self) -> &'static str;
    fn dependencies(&self) -> &[&'static str] { &[] }

    async fn run(
        &self,
        env: &mut BatchEnvelope,
        prior: &mut PipelineState,
    ) -> Result<Self::Output, Self::Error>;
}

/// Accumulates typed outputs of prior stages so a later stage can
/// read e.g. classification results without re-running matchers.
pub struct PipelineState {
    pub classifications: Vec<Vec<ContentClassMatch>>,
    pub features: Option<Features>,
    pub encrypted_secrets: Vec<EncryptedSecretRecord>,
    pub fields_modified: usize,
    pub stages_executed: Vec<String>,
}
```

### 5.2 Default pipeline composition

```rust
pub fn default_pipeline(secrets: Arc<dyn SecretsService>) -> Pipeline {
    PipelineBuilder::new()
        .add_stage(ClassifyStage::with_default_catalog())
        .add_stage(ScrubStage::new(DefaultScrubber::default()))
        .add_stage(EncryptAndStoreStage::new(secrets))
        .add_stage(ExtractStage::new(StaticExtractor::default()))
        .build()
}
```

### 5.3 Engine flow with the pipeline (edge invocation)

```text
agent emits BatchEnvelope (signed)
    │
    ▼
edge receives, runs verify_hybrid
    │
    ▼
┌───────────────────────────────────────────────────────────┐
│ pipeline (in edge process)                                │
│   │                                                       │
│   ▼                                                       │
│ Stage 1: classify → Vec<Vec<ContentClassMatch>>           │
│   │                                                       │
│   ▼                                                       │
│ Stage 2: scrub → mutated env, fields_modified count       │
│   │                                                       │
│   ▼                                                       │
│ Stage 3: encrypt_and_store →                              │
│     - placeholders in env                                 │
│     - Vec<EncryptedSecretRecord> in sidecar              │
│   │                                                       │
│   ▼                                                       │
│ Stage 4: extract → Features                               │
└───────────────────────────────────────────────────────────┘
    │
    ▼
edge constructs PipelineEnvelope (envelope + sidecar)
    │
    ▼
edge signs sidecar (Ed25519 + ML-DSA-65 via StewardSigner)
    │
    ▼
edge POSTs to persist /api/v1/pipeline/ingest
    │
    ▼
persist verifies (edge_signature, agent BatchEnvelope signature, invariants)
    │
    ▼
backend.insert_batch → cirislens.trace_events.{
    payload                  -- scrubbed JSONB                 (existing)
    pii_scrubbed             -- bool                           (existing)
    extracted_features       -- Features as JSONB              (NEW v0.5.0)
    classifications          -- Vec<Vec<ContentClassMatch>>    (NEW v0.5.0)
    pipeline_metadata        -- PipelineMetadata as JSONB      (NEW v0.5.0)
}
    +
secrets_backend.batch_store_encrypted →
  cirislens_secrets.secrets (one row per encrypted_secrets[i])
```

### 5.4 Engine API additions

```rust
impl Engine {
    /// Receive a PipelineEnvelope from edge.
    pub async fn receive_pipeline_envelope(
        &self,
        env: PipelineEnvelope,
    ) -> Result<BatchSummary, IngestError>;

    /// Read typed features for one (trace, thought).
    pub async fn get_features(
        &self,
        trace_id: &str,
        thought_id: &str,
    ) -> Result<Option<Features>, Error>;

    /// Read typed classifications for one (trace, thought).
    pub async fn get_classifications(
        &self,
        trace_id: &str,
        thought_id: &str,
    ) -> Result<Vec<Vec<ContentClassMatch>>, Error>;

    /// Iterator over (cohort, features) pairs for calibration consumers.
    pub fn iter_features_by_cohort(
        &self,
        filter: FeatureFilter,
    ) -> impl Stream<Item = Result<(CohortKey, Features), Error>>;

    /// Replace the default pipeline (advanced).
    pub fn with_pipeline(self, pipeline: Pipeline) -> Self;

    /// Borrow the federated secrets service. Used by agents (via PyO3
    /// or HTTP) for CRUD on the encrypted store.
    pub fn secrets(&self) -> &dyn SecretsService;
}
```

PyO3 surface mirrors the CIRISPersist#17 wraps-Rust pattern. `PyEngine::receive_pipeline_envelope`, `PyEngine::get_features`, `PyEngine::get_classifications`, `PyEngine::secrets()` — all thin async-bridged wrappers, no Python reimplementation.

## 6. Unified content-class taxonomy — the matrix (locked)

### 6.1 Five orthogonal dimensions

| Dim | Name              | Cardinality | Description                                          |
|-----|-------------------|-------------|------------------------------------------------------|
| D1  | `ContentClass`    | open enum   | What the matched span IS. The taxonomic noun.        |
| D2  | `DetectionMethod` | 8 variants  | How the match was found. The taxonomic verb.         |
| D3  | `Sensitivity`     | 4 variants  | How dangerous a leak is. The escalation axis.        |
| D4  | `Action`          | **7 variants** | What the pipeline does about it. The response axis. |
| D5  | `LearningState`   | 5-field struct | Effectiveness/learning metadata. The adaptive axis. |

Existing taxonomies as projections:

| Existing taxonomy             | Projects to                                          |
|-------------------------------|------------------------------------------------------|
| `SecretType` (12 values)      | D1 only                                              |
| `SensitivityLevel` (4)        | D3 only                                              |
| `TriggerType` (6 values)      | D2 only (REGEX/LENGTH/COUNT/FREQ/CUSTOM/SEMANTIC)    |
| `FilterPriority` (5 values)   | (D3, D4) joint                                       |
| Lens-core scrub regex catalog | D2=Regex, D1 various PII                             |
| Lens-core scrub walker        | D2=Walker, D1 structurally-named                     |
| Lens-core scrub NER           | D2=NER, D1 NER classes (PER, ORG, LOC, MISC)         |
| Lens-core extract             | Orthogonal — quantitative projection, separate layer |
| Agent SecretsFilter encrypt   | D4=EncryptAndStore + D1 secret class                 |

### 6.2 The matrix

Rows are **content classes (D1)**. Columns are detection methods (D2). Cells show whether that method can detect that class (✓ / ◐ / —). The rightmost column shows the default `(D3, D4)` when `secrets-store` is wired in.

| #   | D1 ContentClass        | Origin           | Regex | Walker | Length | Count | Frequency | Custom | Semantic | NER     | Default `(D3, D4)`             |
|-----|------------------------|------------------|-------|--------|--------|-------|-----------|--------|----------|---------|--------------------------------|
| **Secrets — `EncryptAndStore` if store wired, else `ScrubReplace`** | | | | | | | | | | | |
| S1  | `ApiKey`               | agent secrets    | ✓     | ◐      | —      | —     | —         | ◐      | ◐        | —       | (HIGH, EncryptAndStore)        |
| S2  | `BearerToken`          | agent secrets    | ✓     | ◐      | —      | —     | —         | ◐      | ◐        | —       | (HIGH, EncryptAndStore)        |
| S3  | `Password`             | agent secrets    | ✓     | ✓      | —      | —     | —         | ◐      | ◐        | —       | (HIGH, EncryptAndStore)        |
| S4  | `UrlWithAuth`          | agent secrets    | ✓     | —      | —      | —     | —         | ◐      | —        | —       | (HIGH, EncryptAndStore)        |
| S5  | `PrivateKey`           | agent secrets    | ✓     | ✓      | ✓ (>1KB)| —    | —         | ◐      | ◐        | —       | (CRITICAL, EncryptAndStore)    |
| S6  | `CreditCard`           | agent secrets    | ✓     | —      | —      | —     | —         | ◐ (Luhn)| —       | —       | (CRITICAL, EncryptAndStore)    |
| S7  | `SocialSecurity`       | agent secrets    | ✓     | —      | —      | —     | —         | —      | —        | —       | (CRITICAL, EncryptAndStore)    |
| S8  | `AwsAccessKey`         | agent secrets    | ✓     | —      | —      | —     | —         | —      | —        | —       | (CRITICAL, EncryptAndStore)    |
| S9  | `AwsSecretKey`         | agent secrets    | ✓     | —      | —      | —     | —         | —      | —        | —       | (CRITICAL, EncryptAndStore)    |
| S10 | `GithubToken`          | agent secrets    | ✓     | —      | —      | —     | —         | —      | —        | —       | (CRITICAL, EncryptAndStore)    |
| S11 | `SlackToken`           | agent secrets    | ✓     | —      | —      | —     | —         | —      | —        | —       | (HIGH, EncryptAndStore)        |
| S12 | `DiscordToken`         | agent secrets    | ✓     | —      | —      | —     | —         | —      | —        | —       | (HIGH, EncryptAndStore)        |
| **Patterns — `AnnotateOnly` (consumer-policy decides action)** | | | | | | | | | | | |
| P1  | `AgentMention`         | agent adaptive   | ✓     | —      | —      | —     | —         | —      | —        | —       | (HIGH, AnnotateOnly)           |
| P2  | `AgentName`            | agent adaptive   | ✓     | —      | —      | —     | —         | —      | ◐        | —       | (HIGH, AnnotateOnly)           |
| P3  | `DirectMessage`        | agent adaptive   | —     | —      | —      | —     | —         | ✓      | —        | —       | (HIGH, AnnotateOnly)           |
| P4  | `WallOfText`           | agent adaptive   | —     | —      | ✓ (>1k)| —     | —         | —      | —        | —       | (MEDIUM, AnnotateOnly)         |
| P5  | `MessageFlood`         | agent adaptive   | —     | —      | —      | —     | ✓ (5:60)  | —      | —        | —       | (MEDIUM, AnnotateOnly)         |
| P6  | `EmojiSpam`            | agent adaptive   | —     | —      | —      | ✓ (>10)| —        | —      | —        | —       | (LOW, AnnotateOnly)            |
| P7  | `CapsAbuse`            | agent adaptive   | ✓     | —      | —      | —     | —         | —      | —        | —       | (LOW, AnnotateOnly)            |
| P8  | `PromptInjection`      | agent adaptive   | ✓     | —      | —      | —     | —         | —      | ◐        | —       | (CRITICAL, ScrubReplace)       |
| P9  | `MalformedJson`        | agent adaptive   | —     | —      | —      | —     | —         | ✓      | —        | —       | (MEDIUM, AnnotateOnly)         |
| P10 | `ExcessiveLength`      | agent adaptive   | —     | —      | ✓ (>50k)| —    | —         | —      | —        | —       | (MEDIUM, AnnotateOnly)         |
| **PII — `ScrubReplace` (no recall use case)** | | | | | | | | | | | |
| I1  | `PersonName`           | lens-core NER    | ◐     | ✓ (`name`) | —  | —     | —         | —      | ◐        | ✓ (PER) | (MEDIUM, ScrubReplace)         |
| I2  | `Organization`         | lens-core NER    | —     | ✓ (`org`) | —   | —     | —         | —      | ◐        | ✓ (ORG) | (LOW, ScrubReplace)            |
| I3  | `Location`             | lens-core NER    | —     | ✓ (`addr`) | —  | —     | —         | —      | ◐        | ✓ (LOC) | (MEDIUM, ScrubReplace)         |
| I4  | `EmailAddress`         | lens-core regex  | ✓     | ✓ (`email`) | — | —     | —         | —      | —        | ◐       | (MEDIUM, ScrubReplace)         |
| I5  | `PhoneNumber`          | lens-core regex  | ✓     | ✓ (`phone`) | — | —     | —         | —      | —        | —       | (MEDIUM, ScrubReplace)         |
| I6  | `IpAddress`            | lens-core regex  | ✓     | —      | —      | —     | —         | —      | —        | —       | (LOW, ScrubReplace)            |
| I7  | `UserId`               | lens-core walker | ◐     | ✓ (SCRUB_FIELDS) | — | —  | —         | —      | —        | —       | (MEDIUM, Hash)                 |
| I8  | `MessageId`            | lens-core walker | —     | ✓ (SCRUB_FIELDS) | — | —  | —         | —      | —        | —       | (LOW, Pseudonymize)            |
| I9  | `ChannelId`            | lens-core walker | —     | ✓ (SCRUB_FIELDS) | — | —  | —         | —      | —        | —       | (LOW, Pseudonymize)            |
| I10 | `MiscNamedEntity`      | lens-core NER    | —     | —      | —      | —     | —         | —      | ◐        | ✓ (MISC)| (LOW, AnnotateOnly)            |
| **Structural — pass-through to NER pass** | | | | | | | | | | | |
| F1  | `FreeFormText`         | lens-core fields | —     | ✓ (`content`/`message`/`text`/`description`) | — | — | — | —   | —        | —       | (varies)                       |
| F2  | `ToolArgs`             | lens-core fields | —     | ✓ (`tool_args`/`arguments`) | — | — | —    | —      | —        | —       | (HIGH, ScrubReplace)           |
| F3  | `ObservationContent`   | lens-core fields | —     | ✓ (`observation`/`result`) | — | — | —     | —      | —        | —       | (varies)                       |
| F4  | `ThoughtContent`       | lens-core fields | —     | ✓ (`thought`/`reasoning`) | — | — | —      | —      | —        | —       | (varies)                       |

**Total: 36 built-in classes × 8 detection methods × 4 sensitivities × 7 actions × 5 learning states.**

### 6.3 Locked Rust shapes

```rust
// src/pipeline/classify/mod.rs

#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(tag = "kind", content = "value")]
pub enum ContentClass {
    // Secrets (S1–S12)
    ApiKey, BearerToken, Password, UrlWithAuth, PrivateKey,
    CreditCard, SocialSecurity, AwsAccessKey, AwsSecretKey,
    GithubToken, SlackToken, DiscordToken,

    // Patterns (P1–P10)
    AgentMention, AgentName, DirectMessage, WallOfText, MessageFlood,
    EmojiSpam, CapsAbuse, PromptInjection, MalformedJson, ExcessiveLength,

    // PII (I1–I10)
    PersonName, Organization, Location, EmailAddress, PhoneNumber,
    IpAddress, UserId, MessageId, ChannelId, MiscNamedEntity,

    // Structural (F1–F4)
    FreeFormText, ToolArgs, ObservationContent, ThoughtContent,

    /// Operator-defined class.
    Custom(String),
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum DetectionMethod {
    Regex, Walker, Length, Count, Frequency, Custom, Semantic, Ner,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Ord, PartialOrd, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Sensitivity {
    Low, Medium, High, Critical,
}

#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Action {
    /// Detect and tag, payload untouched.
    AnnotateOnly,

    /// Replace span with `{SECRET:uuid:description}` BUT do NOT store
    /// the original. Used when no secrets store is wired (sovereign
    /// no-storage mode) or when sensitivity policy says "destroy".
    ScrubReplace,

    /// Replace with `{SECRET:uuid:description}` AND encrypt-and-store
    /// the original via the SecretsService. Recoverable for whitelisted
    /// actions via decapsulation. Default for S1–S12 when secrets feature
    /// is enabled and a SecretsService is bound at pipeline build time.
    EncryptAndStore,

    /// Replace with stable hash of the original. Used for UserId-style
    /// classes where consumers want to track occurrences without exposure.
    Hash,

    /// Replace with deterministic pseudonym from a stable mapping
    /// (MessageId → "msg_a3f9"). Mapping table lives in
    /// cirislens_pseudonyms (V008 migration).
    Pseudonymize,

    /// Drop the entire component from the BatchEnvelope. Reserved
    /// for catastrophic detections.
    Drop,

    /// Reject the whole batch — abort ingest. Reserved for invariant
    /// violations (scrubber returning schema-altered envelope, etc.).
    Reject,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct LearningState {
    pub effectiveness: f32,                        // [0, 1]
    pub false_positive_rate: f32,                  // [0, 1]
    pub true_positive_count: u64,
    pub false_positive_count: u64,
    pub last_triggered: Option<DateTime<Utc>>,
    pub created_at: DateTime<Utc>,
    pub created_by: String,                        // "system" | "operator:<id>" | "learned:<source>"
    pub enabled: bool,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ContentClassMatch {
    pub class: ContentClass,
    pub method: DetectionMethod,
    pub sensitivity: Sensitivity,
    pub action: Action,
    pub matcher_id: String,
    pub component_index: usize,
    pub json_path: Option<String>,
    pub span: Option<(usize, usize)>,
    pub confidence: f32,                           // [0, 1]
    pub learning: Option<LearningState>,
    /// Set by EncryptAndStore stage; references cirislens_secrets.secrets row.
    pub secret_uuid: Option<String>,
}
```

## 7. Secrets module — locked surface

### 7.1 Trait

```rust
// src/secrets/mod.rs

#[async_trait]
pub trait SecretsService: Send + Sync {
    // ── CRUD (matches CIRISAgent SecretsServiceProtocol §3.1 #3, #4, #7, #9, #10) ──

    /// Store a manually-keyed secret. Caller provides key; server
    /// derives per-secret encryption key, encrypts, persists.
    async fn store_secret(
        &self,
        key: String,
        value: String,
        accessor: String,
    ) -> Result<(), SecretsError>;

    /// Retrieve a secret by manual key. Decrypts and returns plaintext.
    /// Audited.
    async fn retrieve_secret(
        &self,
        key: &str,
        accessor: String,
    ) -> Result<Option<String>, SecretsError>;

    /// Recall a detected secret by UUID (the path EncryptAndStore creates).
    /// `decrypt = false` returns metadata only.
    async fn recall_secret(
        &self,
        uuid: &str,
        purpose: String,
        accessor: String,
        decrypt: bool,
    ) -> Result<Option<SecretRecallResult>, SecretsError>;

    /// Metadata-only listing.
    async fn list_stored_secrets(
        &self,
        limit: usize,
        filter: SecretsListFilter,
    ) -> Result<Vec<SecretReference>, SecretsError>;

    /// Audited delete.
    async fn forget_secret(
        &self,
        uuid: &str,
        accessor: String,
    ) -> Result<bool, SecretsError>;

    // ── Detection + decapsulation (matches §3.1 #5, #6) ──

    /// Detect → encrypt → store → return (filtered_text, refs).
    /// This is the Edge-side EncryptAndStore stage's primary entry.
    async fn process_incoming_text(
        &self,
        text: &str,
        source_message_id: &str,
        accessor: String,
    ) -> Result<(String, Vec<SecretReference>), SecretsError>;

    /// Walk action params, decapsulate `{SECRET:...}` placeholders for
    /// whitelisted actions. Audit each decapsulation.
    async fn decapsulate_secrets_in_parameters(
        &self,
        action_type: &str,
        action_params: serde_json::Value,
        ctx: DecapsulationContext,
    ) -> Result<serde_json::Value, SecretsError>;

    // ── Direct crypto (matches §3.1 #1, #2) ──

    /// Direct AES-256-GCM encrypt; returns base64(salt || nonce || ciphertext).
    /// Caller manages transport. NOT stored.
    async fn encrypt(&self, plaintext: &str) -> Result<String, SecretsError>;

    /// Direct decrypt of caller-managed ciphertext.
    async fn decrypt(&self, ciphertext: &str) -> Result<String, SecretsError>;

    // ── Filter config CRUD (matches §3.1 #8, #11) ──

    async fn get_filter_config(&self) -> Result<FilterConfig, SecretsError>;

    async fn update_filter_config(
        &self,
        updates: FilterUpdateRequest,
        accessor: String,
    ) -> Result<FilterUpdateResult, SecretsError>;

    // ── Audit + observability (matches §3.1 #12, #13 + §3.1#15) ──

    async fn get_service_stats(&self) -> Result<SecretsServiceStats, SecretsError>;

    async fn is_healthy(&self) -> Result<bool, SecretsError>;

    async fn get_access_logs(
        &self,
        secret_uuid: Option<&str>,
        limit: usize,
    ) -> Result<Vec<AccessLogEntry>, SecretsError>;

    // ── Key rotation + hardware key (matches §3.1 #14 + §3.1 #16, #17, #18) ──

    /// Re-encrypt every stored secret under a new master key. Atomic
    /// (transactional in postgres; backup-and-replace in sqlite).
    async fn reencrypt_all(
        &self,
        new_master_key_ref: MasterKeyRef,
        accessor: String,
    ) -> Result<RotationResult, SecretsError>;

    /// Rotate to a freshly generated master key (or use the supplied one).
    /// Returns the new key reference.
    async fn rotate_master_key(
        &self,
        new_master: Option<bytes::Bytes>,
        accessor: String,
    ) -> Result<MasterKeyRef, SecretsError>;

    /// Health check on the encryption path: encrypt → decrypt round-trip.
    async fn test_encryption(&self) -> Result<bool, SecretsError>;

    /// Migrate the master key from software file to CIRISVerify
    /// TPM/Keystore. Re-encrypts every secret as part of the migration.
    /// Requires the `secrets-hw` feature.
    #[cfg(feature = "secrets-hw")]
    async fn migrate_to_hardware_key(
        &self,
        accessor: String,
    ) -> Result<MasterKeyRef, SecretsError>;
}
```

### 7.2 Wire types (federation-stable)

```rust
// src/secrets/api.rs

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SecretRecord {
    pub secret_uuid: String,                // UUID v4
    pub encrypted_value: bytes::Bytes,      // AES-256-GCM ciphertext
    pub encryption_key_ref: String,         // per-secret key derivation reference
    pub salt: bytes::Bytes,                 // PBKDF2/HKDF salt (16 bytes)
    pub nonce: bytes::Bytes,                // AES-GCM nonce (12 bytes)
    pub description: String,
    pub sensitivity_level: Sensitivity,
    pub detected_pattern: String,           // matcher_id from ContentClassMatch
    pub context_hint: Option<String>,
    pub created_at: DateTime<Utc>,
    pub last_accessed: Option<DateTime<Utc>>,
    pub access_count: u64,
    pub source_message_id: Option<String>,
    pub auto_decapsulate_for_actions: Vec<String>,
    pub manual_access_only: bool,
    /// Schema version for forward-compat. v1.0 today.
    pub record_schema_version: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct EncryptedSecretRecord {
    pub record: SecretRecord,
    /// Optional: federation-internal HMAC over canonical(record) for
    /// integrity. Edge writes; persist verifies before insert.
    pub edge_hmac: Option<bytes::Bytes>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SecretReference {
    pub uuid: String,
    pub description: String,
    pub context_hint: Option<String>,
    pub sensitivity: Sensitivity,
    pub detected_pattern: String,
    pub auto_decapsulate_actions: Vec<String>,
    pub created_at: DateTime<Utc>,
    pub last_accessed: Option<DateTime<Utc>>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SecretRecallResult {
    pub found: bool,
    pub value: Option<String>,
    pub error: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DecapsulationContext {
    pub action_type: String,
    pub accessor: String,
    pub purpose: String,
    pub trace_id: Option<String>,
    pub thought_id: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AccessLogEntry {
    pub log_id: u64,                         // BIGSERIAL
    pub secret_uuid: String,
    pub accessor: String,
    pub operation: AccessOp,                  // Store / Retrieve / Recall / Forget / Encrypt / Decrypt
    pub action_type: Option<String>,
    pub purpose: Option<String>,
    pub success: bool,
    pub error: Option<String>,
    pub trace_id: Option<String>,
    pub thought_id: Option<String>,
    pub created_at: DateTime<Utc>,
}

#[derive(Debug, Clone, Copy, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum AccessOp {
    Store, Retrieve, Recall, Forget, Encrypt, Decrypt, Reencrypt, Rotate,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SecretsListFilter {
    pub sensitivity: Option<Sensitivity>,
    pub pattern: Option<String>,
    pub source_message_id: Option<String>,
    pub created_after: Option<DateTime<Utc>>,
    pub created_before: Option<DateTime<Utc>>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SecretsServiceStats {
    pub total_secrets: u64,
    pub active_filters: u64,
    pub filter_matches_today: u64,
    pub last_filter_update: Option<DateTime<Utc>>,
    pub encryption_enabled: bool,
    pub hardware_key_active: bool,
    pub last_rotation: Option<DateTime<Utc>>,
    pub rotation_count: u64,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RotationResult {
    pub success: bool,
    pub secrets_reencrypted: u64,
    pub failures: Vec<String>,                // UUIDs that failed
    pub duration_ms: u32,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum MasterKeyRef {
    /// Software-stored: opaque file path or in-memory key handle.
    Software { handle: String },
    /// Hardware-stored: CIRISVerify keystore key id.
    Hardware { key_id: String, descriptor: String },
}

#[derive(Debug, thiserror::Error)]
pub enum SecretsError {
    #[error("not found: {0}")]
    NotFound(String),
    #[error("not authorized: action={action}, accessor={accessor}")]
    NotAuthorized { action: String, accessor: String },
    #[error("encryption failed: {0}")]
    Encryption(String),
    #[error("decryption failed: {0}")]
    Decryption(String),
    #[error("rate limited: {0}")]
    RateLimited(String),
    #[error("invariant violated: {0}")]
    Invariant(String),
    #[error("backend: {0}")]
    Backend(#[source] Box<dyn std::error::Error + Send + Sync>),
    #[error("hardware key error: {0}")]
    Hardware(String),
}
```

### 7.3 PostgreSQL schema

```sql
-- migrations/postgres/lens/008_secrets.sql

CREATE SCHEMA IF NOT EXISTS cirislens_secrets;

CREATE TABLE cirislens_secrets.secrets (
    secret_uuid                   UUID PRIMARY KEY,
    encrypted_value               BYTEA NOT NULL,
    encryption_key_ref            TEXT NOT NULL,
    salt                          BYTEA NOT NULL,
    nonce                         BYTEA NOT NULL,
    description                   TEXT NOT NULL,
    sensitivity_level             TEXT NOT NULL CHECK (sensitivity_level IN ('low','medium','high','critical')),
    detected_pattern              TEXT NOT NULL,
    context_hint                  TEXT,
    created_at                    TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    last_accessed                 TIMESTAMPTZ,
    access_count                  BIGINT NOT NULL DEFAULT 0,
    source_message_id             TEXT,
    auto_decapsulate_for_actions  TEXT[] NOT NULL DEFAULT '{}',
    manual_access_only            BOOLEAN NOT NULL DEFAULT FALSE,
    record_schema_version         TEXT NOT NULL DEFAULT '1.0'
);

CREATE INDEX secrets_created_at        ON cirislens_secrets.secrets (created_at);
CREATE INDEX secrets_sensitivity       ON cirislens_secrets.secrets (sensitivity_level);
CREATE INDEX secrets_pattern           ON cirislens_secrets.secrets (detected_pattern);
CREATE INDEX secrets_source_message    ON cirislens_secrets.secrets (source_message_id) WHERE source_message_id IS NOT NULL;

CREATE TABLE cirislens_secrets.access_log (
    log_id        BIGSERIAL PRIMARY KEY,
    secret_uuid   UUID,                       -- nullable for direct encrypt/decrypt ops
    accessor      TEXT NOT NULL,
    operation     TEXT NOT NULL CHECK (operation IN ('store','retrieve','recall','forget','encrypt','decrypt','reencrypt','rotate')),
    action_type   TEXT,
    purpose       TEXT,
    success       BOOLEAN NOT NULL,
    error         TEXT,
    trace_id      TEXT,
    thought_id    TEXT,
    created_at    TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE INDEX access_log_secret_uuid    ON cirislens_secrets.access_log (secret_uuid) WHERE secret_uuid IS NOT NULL;
CREATE INDEX access_log_accessor       ON cirislens_secrets.access_log (accessor);
CREATE INDEX access_log_created_at     ON cirislens_secrets.access_log (created_at);
CREATE INDEX access_log_trace_id       ON cirislens_secrets.access_log (trace_id) WHERE trace_id IS NOT NULL;

CREATE TABLE cirislens_secrets.master_key_meta (
    key_ref       TEXT PRIMARY KEY,
    key_kind      TEXT NOT NULL CHECK (key_kind IN ('software','hardware')),
    descriptor    TEXT,                       -- e.g. CIRISVerify storage descriptor
    created_at    TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    activated_at  TIMESTAMPTZ,
    deactivated_at TIMESTAMPTZ,
    rotated_to    TEXT REFERENCES cirislens_secrets.master_key_meta(key_ref)
);

CREATE INDEX master_key_active ON cirislens_secrets.master_key_meta (activated_at)
  WHERE deactivated_at IS NULL;

CREATE TABLE cirislens_secrets.filter_config (
    config_id     TEXT PRIMARY KEY,
    config_value  JSONB NOT NULL,
    version       INTEGER NOT NULL DEFAULT 1,
    updated_at    TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    updated_by    TEXT NOT NULL
);

CREATE TABLE cirislens_pseudonyms (
    -- For Action::Pseudonymize. Stable mapping original_hash → pseudonym.
    original_hash  BYTEA PRIMARY KEY,         -- SHA-256 of original ID
    pseudonym      TEXT NOT NULL UNIQUE,      -- e.g. "msg_a3f9"
    class          TEXT NOT NULL,             -- ContentClass kind
    created_at     TIMESTAMPTZ NOT NULL DEFAULT NOW()
);
```

### 7.4 Schema evolution + observability columns

```sql
-- migrations/postgres/lens/007_pipeline_columns.sql

ALTER TABLE cirislens.trace_events
  ADD COLUMN extracted_features JSONB,
  ADD COLUMN classifications    JSONB,
  ADD COLUMN pipeline_metadata  JSONB;

CREATE INDEX trace_events_extracted_features_gin
  ON cirislens.trace_events USING GIN (extracted_features jsonb_path_ops);
CREATE INDEX trace_events_classifications_gin
  ON cirislens.trace_events USING GIN (classifications jsonb_path_ops);

COMMENT ON COLUMN cirislens.trace_events.extracted_features IS
  'Features (16 CRC + observation weights + step ts + models_used + cost/tokens). PUBLIC_SCHEMA_CONTRACT @ v0.3.3 tier=stable.';
COMMENT ON COLUMN cirislens.trace_events.classifications IS
  'Vec<Vec<ContentClassMatch>> from pipeline. PUBLIC_SCHEMA_CONTRACT @ v0.3.3 tier=stable.';
COMMENT ON COLUMN cirislens.trace_events.pipeline_metadata IS
  'PipelineMetadata: stages_executed, fields_modified, secrets_encrypted, latency, edge_build_id. tier=mutable.';
```

### 7.5a Crypto-through-ciris-crypto (no primitives in persist)

Every crypto operation in `src/secrets/` routes through `ciris-crypto`. The `src/secrets/crypto.rs` facade is the only place that imports from `ciris_crypto::*`; the rest of the secrets module imports from `crate::secrets::crypto`. This makes the boundary auditable in one file.

**Operations and their ciris-crypto entry points** (names illustrative — actual function names come from ciris-crypto's API):

| Operation in persist                              | Routes through ciris-crypto                                |
|---------------------------------------------------|------------------------------------------------------------|
| AES-256-GCM encrypt (per-secret key + nonce)      | `ciris_crypto::aes_gcm::encrypt(key, nonce, plaintext)`    |
| AES-256-GCM decrypt                               | `ciris_crypto::aes_gcm::decrypt(key, nonce, ciphertext)`   |
| Generate per-secret key from master + salt        | `ciris_crypto::kdf::pbkdf2_hmac_sha256(master, salt, iters)` |
| HKDF derivation for hardware-mode keys            | `ciris_crypto::kdf::hkdf_sha256(ikm, salt, info)`          |
| HMAC over canonical(EncryptedSecretRecord)        | `ciris_crypto::hmac::sha256(key, msg)`                     |
| Constant-time compare (for HMAC verify)           | `ciris_crypto::util::ct_eq(a, b)`                          |
| Random bytes (master key, nonces, salts)          | `ciris_crypto::random::fill(&mut buf)`                     |
| Hardware-backed master key (CIRISVerify TPM)      | `ciris_keyring::HardwareSigner::*` (existing v1.7+ API)    |

If `ciris-crypto` does not yet expose one of the above, that function is added to `ciris-crypto` first (a pre-req PR against `CIRISVerify`), the version is bumped, and persist depends on the new release. Persist does not work around the gap with a direct primitive-crate dep, ever.

The ciris-crypto features persist enables:

```toml
ciris-crypto = { version = "1", features = [
    "ed25519",            # already enabled — for signing
    "pqc-ml-dsa",         # already enabled — for hybrid sigs
    "aes-gcm",            # NEW — symmetric encryption for secrets at rest
    "kdf",                # NEW — PBKDF2 + HKDF for key derivation
    "hmac",               # NEW — for EncryptedSecretRecord integrity
    "random",             # NEW — RNG facade (so we don't depend on rand directly)
] }
```

If those features don't exist in ciris-crypto v1.9.0, the prerequisite tracking issue is filed against `CIRISVerify` before `ciris-persist v0.5.0` lands. **No persist release ships that sidesteps this.**

### 7.6 SQLite mirror

Symmetric tables in SQLite for sovereign-mode. `BYTEA` → `BLOB`; `JSONB` → `TEXT NOT NULL DEFAULT '{}'`; `TIMESTAMPTZ` → `TEXT` (RFC 3339 round-trip via the existing chrono integration); `TEXT[]` → `TEXT NOT NULL DEFAULT '[]'` (JSON array). Idiom is already established in the existing migrations.

## 8. Federation-stable HTTP API

### 8.1 New federation roles

`PUBLIC_SCHEMA_CONTRACT.md @ v0.3.3` adds two role tags to `federation_keys`:

| Role tag                    | Permits                                                      |
|-----------------------------|--------------------------------------------------------------|
| `cirislens_secrets_writer`  | POST `/api/v1/pipeline/ingest` — write encrypted secrets      |
| `cirislens_secrets_reader`  | GET  `/api/v1/secrets/*` — read metadata, recall with whitelist |
| `cirislens_secrets_admin`   | POST `/api/v1/secrets/rotate`, `/migrate-hardware`            |

Edge keys are tagged `cirislens_secrets_writer`. Agent keys can be tagged `cirislens_secrets_reader` to recall their own secrets (filter-by-source_message_id enforces tenancy). Operator-held keys hold `_admin`.

### 8.2 Endpoints

```text
POST   /api/v1/pipeline/ingest                  PipelineEnvelope                        -> BatchSummary
POST   /api/v1/secrets/store                    {key, value}                            -> ()
GET    /api/v1/secrets/{uuid}                   ?decrypt={bool}&purpose=&accessor=      -> SecretRecallResult | metadata
GET    /api/v1/secrets/by-key/{key}                                                     -> string | null
GET    /api/v1/secrets                          ?limit=&filter=*                        -> Vec<SecretReference>
DELETE /api/v1/secrets/{uuid}                                                           -> {deleted: bool}
POST   /api/v1/secrets/decapsulate              {action_type, params, ctx}              -> JSON
POST   /api/v1/secrets/encrypt                  {plaintext}                             -> {ciphertext}
POST   /api/v1/secrets/decrypt                  {ciphertext}                            -> {plaintext}
GET    /api/v1/secrets/filter-config                                                    -> FilterConfig
PATCH  /api/v1/secrets/filter-config            FilterUpdateRequest                     -> FilterUpdateResult
GET    /api/v1/secrets/stats                                                            -> SecretsServiceStats
GET    /api/v1/secrets/health                                                           -> {healthy: bool}
GET    /api/v1/secrets/access-log               ?secret_uuid=&limit=                    -> Vec<AccessLogEntry>
POST   /api/v1/secrets/reencrypt-all            {new_master_key_ref}                    -> RotationResult
POST   /api/v1/secrets/rotate-master                                                    -> {new_master_key_ref}
POST   /api/v1/secrets/test-encryption                                                  -> {ok: bool}
POST   /api/v1/secrets/migrate-hardware                                                 -> {new_master_key_ref}
```

All endpoints require federation key authentication (Ed25519 + ML-DSA-65 hybrid bound signature on the request body, verified via `verify_hybrid_via_directory`). All write operations append to `cirislens_secrets.access_log`. Rate limits per accessor follow the existing federation rate-limit config.

## 9. PyO3 surface

Wraps Rust 1:1 (CIRISPersist#17 pattern):

```python
from cirispersist import Engine, ContentClass, DetectionMethod, Sensitivity, Action

engine = Engine.builder().postgres_url(url).build()

# Pipeline outputs.
features = await engine.get_features(trace_id, thought_id)
matches  = await engine.get_classifications(trace_id, thought_id)

# Federated secrets API — same surface as agent's local SecretsService.
secrets = engine.secrets()

filtered_text, refs = await secrets.process_incoming_text(text, msg_id, accessor="agent")
recall              = await secrets.recall_secret(uuid, purpose="action", accessor="agent", decrypt=True)
metadata            = await secrets.list_stored_secrets(limit=10, filter=None)
ok                  = await secrets.forget_secret(uuid, accessor="agent")

# Direct crypto.
ct = await secrets.encrypt(plaintext)
pt = await secrets.decrypt(ct)

# Decapsulation.
new_params = await secrets.decapsulate_secrets_in_parameters(
    action_type="tool",
    action_params={"cmd": "curl -H 'Authorization: Bearer {SECRET:abc-123:my-key}'"},
    ctx=DecapsulationContext(action_type="tool", accessor="agent", purpose="exec",
                              trace_id=tid, thought_id=thid),
)

# Filter CRUD.
cfg = await secrets.get_filter_config()
res = await secrets.update_filter_config(updates, accessor="operator")

# Audit + ops.
log = await secrets.get_access_logs(secret_uuid=uuid, limit=100)
stats = await secrets.get_service_stats()
ok = await secrets.test_encryption()

# Rotation.
result = await secrets.reencrypt_all(new_master_key_ref, accessor="operator")
new_ref = await secrets.rotate_master_key(new_master=None, accessor="operator")

# Hardware migration (cfg(feature = "secrets-hw")).
new_ref = await secrets.migrate_to_hardware_key(accessor="operator")
```

## 10. Why edge, not persist, for runtime invocation

Repeated for clarity:

- **Defense-in-depth.** Edge runs scrub + encrypt before persist sees cleartext. Persist's process memory, logs, peer-replication payloads, sovereign-mode cross-host gossip are all clean.
- **Encryption boundary collapse.** Edge encrypts at the receive boundary; the cleartext window is one process, one host, one key.
- **Edge already content-aware.** `verify_hybrid` reads the payload bytes; classify/scrub/extract/encrypt are continuations of that role.
- **Substrate shape stays at persist.** The crate, the schema, the matcher catalog, the wire types, the trait surfaces — all persist-owned. Edge depends on persist as a Rust library. Closure pattern intact.

## 11. Why not absorb the agent's `AdaptiveFilterService`

Stays in agent: it is **adapter-context-aware** (Discord vs CLI vs API), **pre-emit** (runs before traces are constructed), and feeds **agent governance** (deferral, trust scoring, consent gaming). The pipeline this FSD specifies is a **substrate-layer second pass** that produces a consumer-stable annotation shape; it is not a replacement for the agent's pre-emit filtering. The two compose: agent filters at message-receive; pipeline filters at trace-receive; both are visible in `classifications`.

## 12. Migration plan

### 12.0 Prerequisite — ciris-crypto exposes AES-GCM + KDF + HMAC + RNG

Filed against `CIRISVerify`: add `aes-gcm`, `kdf`, `hmac`, `random` features to `ciris-crypto`, exposing the operations enumerated in §7.5a. Bump `ciris-crypto` (and `ciris-verify-core` / `ciris-keyring` for tag coherence) to v1.10.0. Persist v0.5.0 depends on v1.10.0. **No persist work that touches symmetric crypto starts until this prerequisite ships.**

### 12.1 v0.5.0 — pipeline + secrets land in persist

- `src/pipeline/` module (classify + scrub + extract).
- `src/secrets/` module (full SecretsService trait + postgres + sqlite impls).
- `src/secrets/crypto.rs` is the sole import site for `ciris_crypto::{aes_gcm,kdf,hmac,random}`.
- V007 migration: `extracted_features`, `classifications`, `pipeline_metadata` columns on `cirislens.trace_events`.
- V008 migration: `cirislens_secrets` schema (4 tables) + `cirislens_pseudonyms` table.
- `Engine::default_pipeline()` + `Engine::receive_pipeline_envelope()` + `Engine::secrets()`.
- 18-method `SecretsService` trait + impl.
- HTTP endpoints (§8.2) behind `secrets-server` feature.
- PyO3 wraps-Rust surface (§9).
- `PUBLIC_SCHEMA_CONTRACT.md @ v0.3.3` declares all new columns + roles tier=stable.
- Cargo features: `classify`, `scrub`, `scrub-ner`, `scrub-ort`, `extract`, `secrets`, `secrets-hw`, `secrets-server`, `default-pipeline`, `default-sovereign`.

### 12.2 v0.5.1 — edge cutover

CIRISEdge issue (filed concurrent with this FSD lock):
- Edge depends on `ciris-persist` with `default-pipeline + secrets`.
- Edge runs `pipeline.run(env)` after `verify_hybrid` and before forward.
- Edge constructs `PipelineEnvelope`, signs sidecar with `StewardSigner`, POSTs to `/api/v1/pipeline/ingest`.
- Edge's existing FSD wire format (agent → edge) stays unchanged.
- Old persist endpoint `POST /api/v1/accord/events` continues to accept un-piped envelopes for transition window; logs a warning; sovereign deployments are exempt.

### 12.3 v0.5.2 — lens-core unwinds

- Delete `CIRISLensCore/src/scrub/` + `src/extract/{features,static_extract,json_path}.rs`.
- Drop candle, ort, tokenizers, hf-hub, log, env_logger, anyhow, parking_lot, hex, uuid deps + `ner` + `ner-ort` features.
- Keep `src/cohort/`, `src/detector/`, `src/scoring/`, `src/signing/`, `src/pipeline/` (lens-side projection only), `src/extract/projection.rs` reading `Features` via `Engine.get_features`.

### 12.4 v0.5.3 — RATCHET cutover

- RATCHET reads `extracted_features` directly via `cirislens_reader` role.
- `projection_version = "crc-v1"` pins to `PUBLIC_SCHEMA_CONTRACT.md @ v0.3.3`.
- CIRISLensCore#3 calibration ask fulfilled.

### 12.5 v0.5.4 — agent cutover (optional)

- CIRISAgent's `SecretsService` becomes a thin client over persist's federated secrets API.
- Agent's local SQLite secrets store deprecated; data migrated to persist via `migrate_to_hardware_key`-shaped one-shot tool.
- Agent's `AdaptiveFilterService` keeps running; persist's pipeline is the second pass.

### 12.6 Testing strategy

- **Property tests.** Every `Vec<ContentClassMatch>` round-trips through serde JSONB without loss. `EncryptedSecretRecord` round-trips through encrypt → decrypt → original. (Already a proptest invariant in lens-core's lifted scrubber.)
- **Real-fixture tests.** Existing `tests/fixtures/2.7.0/*.json` fixtures get classification expectations.
- **Differential test vs CIRISAgent SecretsFilter.** Same input through both; check every `SecretRecord` from agent has corresponding `EncryptedSecretRecord` in persist's pipeline output.
- **Differential test vs `AdaptiveFilterService`.** Same content; check `(triggered_filters, priority)` → `(matcher_id, sensitivity)`.
- **End-to-end edge → persist.** Spin up edge with embedded persist crate, agent with mock signer, verify scrubbed payload + encrypted secrets land in postgres.
- **Replay safety.** Send the same `PipelineEnvelope` twice; second insert is idempotent (dedup_key already exists in `BatchEnvelope`).
- **Tampering detection.** Replay with mutated sidecar; persist rejects on edge_signature verify.
- **Decapsulation whitelist.** `auto_decapsulate_for_actions = ["tool"]` blocks `action_type = "speak"`.
- **Key rotation.** `reencrypt_all` is atomic — no decrypt failures during the rotation window.
- **Bench harness.** New `[[bench]] name = "pipeline"` and `[[bench]] name = "secrets_crud"`.

### 12.7 Rollback

Each phase is independently rollback-safe:

- v0.5.0 columns are nullable; pre-pipeline rows stay valid.
- v0.5.1 edge cutover: edge can revert to the pre-pipeline path; persist continues to accept un-piped envelopes through v0.5.x for the transition window.
- v0.5.2 lens-core unwind: lens-core can keep its own scrub/extract for one minor version while RATCHET migrates; persist is the source of truth either way.
- v0.5.3 RATCHET: keeps a fallback reader against the legacy lens-core projection during cutover.
- v0.5.4 agent cutover: agent can run both local + federated SecretsService side-by-side until traffic is fully on the federated path.

## 13. References

- Persist scrubber slot: `docs/INTEGRATION_LENS.md:336`
- Persist `pii_scrubbed` flag: `docs/PUBLIC_SCHEMA_CONTRACT.md`
- Existing scrub trait: `src/scrub/mod.rs`
- 16-field CRC projection: CIRISLensCore#3
- CIRISAgent SecretsFilter: `CIRISAgent/ciris_engine/logic/secrets/filter.py`
- CIRISAgent SecretsService: `CIRISAgent/ciris_engine/logic/secrets/service.py`
- CIRISAgent SecretsServiceProtocol: `CIRISAgent/ciris_engine/protocols/services/runtime/secrets.py`
- CIRISAgent SecretsStore: `CIRISAgent/ciris_engine/logic/secrets/store.py`
- CIRISAgent SecretType: `CIRISAgent/ciris_engine/schemas/secrets/core.py:SecretType`
- CIRISAgent SecretsEncryption: `CIRISAgent/ciris_engine/logic/secrets/encryption.py`
- CIRISAgent AdaptiveFilterService: `CIRISAgent/ciris_engine/logic/services/governance/adaptive_filter/service.py`
- CIRISAgent FilterTrigger schema: `CIRISAgent/ciris_engine/schemas/services/filters_core.py`
- CIRISLensCore lifted code: `CIRISLensCore/src/scrub/` + `CIRISLensCore/src/extract/{features,static_extract,json_path}.rs`
- Closure-pattern precedents: CIRISPersist#7 (canonicalization), #14 (verify_hybrid), #17 (StewardSigner), #18 (detection_events + calibration_bundles)
- Edge mission: `CIRISEdge/MISSION.md` (wire/transport, verify, ACK, dispatch, queue)
- Threat model: `THREAT_MODEL.md` AV-3 (defense-in-depth on PII), AV-18 (TLS), §6 (no unsafe)
