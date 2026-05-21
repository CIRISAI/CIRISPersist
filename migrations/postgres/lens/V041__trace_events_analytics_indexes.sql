-- V041 — analytics-query indexes on trace_events (CIRISPersist#88
-- review, performance finding H1).
--
-- The ReadEngine analytics methods (cross_agent_divergence,
-- temporal_drift, hash_chain_gaps, aggregate_scoring_factors,
-- conscience_override_rates) and the count_* family all filter on
--   agent_id_hash = $1 AND ts >= $2 AND ts < $3
-- or
--   deployment_domain = $1 AND ts >= $2 AND ts < $3
--
-- No composite index covered the (column, ts) shape: the
-- `trace_events_dedup` index leads with agent_id_hash but the ts
-- column sits at position 6, so a ts range predicate could not be
-- satisfied by an index-range scan — those queries scanned every
-- row for the agent/domain. `trace_events_agent_ts` is keyed on
-- agent_NAME, not the hash. These two (col, ts) indexes turn the
-- analytics queries into index-range scans that grow with the
-- result window, not the table.

CREATE INDEX IF NOT EXISTS trace_events_agenthash_ts
    ON cirislens.trace_events (agent_id_hash, ts);

CREATE INDEX IF NOT EXISTS trace_events_domain_ts
    ON cirislens.trace_events (deployment_domain, ts);
