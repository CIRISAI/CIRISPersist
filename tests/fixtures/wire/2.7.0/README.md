# Wire format fixtures — `trace_schema_version: "2.7.0"`

Captured production traces from CIRISAgent `release/2.7.8` at `d6b740ee6`
(the commit that landed the explicit CIRISVerify block per
`context/TRACE_WIRE_FORMAT.md` §5.2.1). Used by `verify/`, `schema/`, and
`store/` integration tests.

These are **real signed traces** — Ed25519 signature, agent_id_hash,
signature_key_id, agent-side audit anchor on `ACTION_RESULT`. Treat the
file bytes as load-bearing: any whitespace / key-order change invalidates
the signature.

## Set

| File | Tier | thought_id | Components | Size |
|---|---|---|---|---|
| `generic_0afd50b2.json` | `generic` | `th_followup_th_seed__438b6432-1b1` | 12 | 7.3 KB |
| `detailed_ed713366.json` | `detailed` | `th_seed_e7747e00_130aed3b-945` | 16 | 39 KB |
| `full_traces_0afd50b2.json` | `full_traces` | `th_followup_th_seed__438b6432-1b1` | 12 | 648 KB |
| `full_traces_ed713366.json` | `full_traces` | `th_seed_e7747e00_130aed3b-945` | 16 | 3.0 MB |

**Cross-tier pairs:** the suffixes `0afd50b2` and `ed713366` each appear at
two tiers from the same thought, so tests can assert that PII-bearing
fields are progressively revealed (`generic` → `detailed` → `full_traces`)
without the underlying event count or structural shape changing.

## Component coverage (all four traces)

```
ACTION_RESULT      — seal event with audit-chain anchor (§5.9)
ASPDMA_RESULT
CONSCIENCE_RESULT
DMA_RESULTS
IDMA_RESULT
LLM_CALL           — per-LLM-call broadcast (new in 2.7.8)
SNAPSHOT_AND_CONTEXT — carries CIRISVerify block (§5.2.1)
THOUGHT_START
```

The full set covers every `@streaming_step` event class except
`VERB_SECOND_PASS_RESULT`, which fires only on the recursive-DMA path and
isn't represented in this capture. New fixture set will add it when we
have a captured run that exercises that branch.

## CIRISVerify pins

These fixtures pin the privacy contract that `tests/verify_privacy.rs`
(Phase 1) enforces. Per `context/TRACE_WIRE_FORMAT.md` §5.2.1 each tier
must contain:

| Field group | `generic` | `detailed` | `full_traces` |
|---|---|---|---|
| Per-check booleans (`binary_ok`, `env_ok`, `registry_ok`, `file_integrity_ok`, `audit_ok`, `play_integrity_ok`, `hardware_backed`) | ✓ all 7 | ✓ all 7 | ✓ all 7 |
| Attestation summary (`attestation_level`, `attestation_status`, `attestation_context`, `disclosure_severity`) | ✓ all 4 | ✓ all 4 | ✓ all 4 |
| Key identity (`ed25519_fingerprint`, `key_storage_mode`, `hardware_type`, `verify_version`) | **MUST be absent** | ✓ all 4 | ✓ all 4 |

Validated 2026-04-30 against this fixture set: all four pass.

## Captured agent identity

All four traces are from the same agent — `agent_id_hash` prefix
`8a0b70302aaeb401`, `signature_key_id: agent-8a0b70302aae`. Public key
must be registered in the `accord_public_keys` table before signature
verification can pass; see `verify/ed25519.rs` (Phase 1).

CIRISVerify block on these captures: attestation level 3, status
`partial`, severity `warning`, hardware `TpmFirmware`, verify version
`1.6.3`. The `partial` status means at least one of the seven boolean
checks failed at attestation time — useful for testing the disclosure
banner code path.

## SHA-256 (for tamper-detection on the fixture files themselves)

```
01d78b7778d9de52b7fc7ffd685ea19ebed3dbce17934ef45406c83c847d4233  detailed_ed713366.json
ea2ff3c329aac141eb9c5088347af06f11669aa7e9bd770bb1899f1c846efdf6  full_traces_0afd50b2.json
68b3b74cd3aa06b1077d79f6446180d6ccdf2ba1d6e8884b489458c49a689d24  full_traces_ed713366.json
e7d48076a4840e83662aa1378aeb3284d8243d4d9850fa05ad34c06174d4632b  generic_0afd50b2.json
```

If a CI run modifies these files (e.g. an editor stripping trailing
whitespace), the Ed25519 signature check will fail before the SHA mismatch
is even noticed — but committing the SHAs here gives a faster diagnosis
when that happens.

## Renewal

When `trace_schema_version` bumps (e.g. `2.8.0` removes `TSASPDMA_RESULT`
per `context/TRACE_WIRE_FORMAT.md` §13), capture a parallel fixture set
under `tests/fixtures/wire/<new-version>/` rather than overwriting these.
The schema-version gate (`src/schema/version.rs`) needs to handle both
during the supported-set window.
