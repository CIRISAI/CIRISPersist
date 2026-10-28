# Telemetry tag conventions

The canonical tag-key vocabulary for `crate::telemetry::Observation.labels` and
`MetricSummary.labels`. It matches the keys CIRISAgent's telemetry emitters use
(CIRISAgent#756). Consumers (CIRISLensCore dashboards, CIRISEdge metric
routers) use these keys 1:1 so cross-substrate queries do not drift on label
spelling.

## Why this exists

- `Observation.labels` and `MetricSummary.labels` are `JSONB` /
  canonical-JSON-TEXT, schema-free at the storage layer.
- Schema-free labels let cardinality and key spelling drift without bound.
- One written vocabulary, shared with the emitter, keeps dashboard queries
  stable.

## Canonical keys

| Key | Type | When emitted | Notes |
|---|---|---|---|
| `handler` | string | Auto-attached by `GraphTelemetryService.record_metric` + `ActionDispatcher` when a handler name is in context. | The agent handler that owned the call (e.g., `"speak_handler"`). |
| `action` | string | `ActionDispatcher` | The HandlerAction taxonomy value (`"speak"`, `"recall"`, `"defer"`, etc.). |
| `path_type` | string | `ActionDispatcher`, `ThoughtProcessor` | The processing path (`"agent_thought"`, `"system_event"`, ...). |
| `source_module` | string | `ActionDispatcher`, `ThoughtProcessor` | Module-of-origin for the metric. |
| `thought_id` | UUID string | `ThoughtProcessor`, `LLMBus` (optional) | Per-thought correlation. Use the same UUID across emitters in the same thought lifecycle. |
| `service` | string | `LLMBus` | LLM service name (`"openai"`, `"anthropic"`, ...). |
| `model` | string | `LLMBus` | Model identifier (`"gpt-4"`, `"claude-sonnet-4-6"`, ...). |
| `api_base` | string | `LLMBus` | Base URL of the LLM endpoint. |
| `metric_type` | string enum | Substrate-canonical when carried | `"gauge" \| "counter" \| "histogram" \| "summary"`. Promotes the agent's first-class `metric_type` column to a label. |
| `service_name` | string | Substrate-canonical when carried | Promotes the agent's first-class `service_name` column to a label. Service that emitted the metric. |
| `tenant_id` | string | Substrate-set on INSERT | NOT in the labels JSONB — first-class column on persist (`Observation.tenant_id`). Listed here for completeness; do not duplicate into labels. |

## Keys that should NOT be used

- **`source`** — a constant (`"telemetry"`) on this substrate; everyone
  reading these rows already knows they are telemetry observations.
- **`timestamp`** — redundant with persist's first-class `observed_at`
  column (TIMESTAMPTZ / RFC 3339).

## Changing the vocabulary

Additive only, in step with CIRISAgent's emitter: a new key is added here and
in the emitter source together. A key is removed only after a deprecation
comment and a migration window. Removing a key from this list is a breaking
change for consumers, whose dashboards depend on the spelling.

## Consumer expectations

- **CIRISLensCore dashboards** — query by canonical key. A key not in this
  table is a deployment-specific extension; do not surface it in default
  dashboards.
- **CIRISEdge metric routers** — preserve canonical keys when proxying
  observations between agents and the federation substrate. Do not rename,
  lowercase or strip prefixes.
- **CIRISAgent** — emits the canonical keys directly.

## See also

- `migrations/postgres/lens/V015__cirisgraph_telemetry.sql` — the
  `Observation` + `MetricSummary` table schemas.
- `src/telemetry/types.rs` — `Observation`, `MetricSummary`,
  `ConsolidationLevel`.
- CIRISAgent#756 — the emitter survey this vocabulary comes from.
