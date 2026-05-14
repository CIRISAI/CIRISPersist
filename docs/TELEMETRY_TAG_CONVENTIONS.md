# Telemetry Tag Conventions (v1.0.0)

Canonical tag-key vocabulary for `crate::telemetry::Observation.labels`
and `MetricSummary.labels`. Codified from CIRISAgent's
`GraphTelemetryService` emitter survey (CIRISAgent#756 concern #3
audit). Persist consumers (CIRISLensCore dashboards, CIRISEdge
metric routers) should adopt these keys 1:1 so cross-substrate
queries don't drift on label spelling.

## Why this exists

- Persist's `Observation.labels` and `MetricSummary.labels` are
  `JSONB` / canonical-JSON-TEXT — schema-free at the storage layer.
- Schema-free labels make cardinality + key-name drift unbounded.
- The agent team's `GraphTelemetryService` (CIRISAgent v2.x) has
  established a working set of tag keys. CIRISPersist 1.0.0 mirrors
  that set as substrate-canonical so the cutover (CIRISAgent v2.9.0)
  preserves dashboard queries.

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

The cutover audit (CIRISAgent#756) surfaced two redundant keys that
the agent team confirmed should be dropped:

- **`source`** — agent's `GraphTelemetryService` auto-attached
  `tags["source"] = "telemetry"`. Constant value on this substrate
  (everyone reading these rows knows they're telemetry-substrate
  observations). Drop on cutover.
- **`timestamp`** — agent's `GraphTelemetryService` auto-attached
  `tags["timestamp"] = iso8601_now()`. Redundant with persist's
  first-class `observed_at` TIMESTAMPTZ / RFC 3339 column. Drop on
  cutover.

## Evolution

Additive-only, in lockstep with CIRISAgent's emitter changes. New
keys land here + in the agent's emitter source simultaneously;
old keys go through a deprecation comment + a migration window
before removal. Removing a key from this canonical list is a
**major-version-bump consideration** (consumers' dashboards
depend on the spelling).

## Consumer expectations

- **CIRISLensCore dashboards** — query by canonical key. If a key
  isn't in this table, treat it as deployment-specific extension
  and don't surface in default dashboards.
- **CIRISEdge metric routers** — preserve canonical keys when
  proxying observations between agents and the federation
  substrate. Don't rename / lowercase / strip prefixes.
- **CIRISAgent v2.9.0+** — emit via the canonical keys directly;
  the dual-write phase carries both old + new spellings, the
  read-side cutover snaps to canonical keys when the wheel-side
  switchover completes.

## See also

- `migrations/postgres/lens/V015__cirisgraph_telemetry.sql` — the
  `Observation` + `MetricSummary` table schemas.
- `src/telemetry/types.rs` — `Observation`, `MetricSummary`,
  `ConsolidationLevel`.
- `CIRISAgent#756 comment 4455250673` — the original audit + diff
  that this doc codifies.
