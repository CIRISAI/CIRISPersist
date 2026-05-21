-- V041 — analytics-query indexes on trace_events, SQLite dialect
-- (CIRISPersist#88 review, performance finding H1). Postgres parity
-- with V041 over there.
--
-- The SQLite ReadEngine analytics port (cross_agent_divergence,
-- temporal_drift, hash_chain_gaps, aggregate_scoring_factors, the
-- count_* family) filters `agent_id_hash = ?1 AND ts >= ?2 AND ts <
-- ?3` (and the same shape on deployment_domain). Without a
-- (column, ts) index SQLite scans every row for the agent/domain;
-- these two indexes make them index-range scans.

CREATE INDEX IF NOT EXISTS trace_events_agenthash_ts
    ON trace_events (agent_id_hash, ts);

CREATE INDEX IF NOT EXISTS trace_events_domain_ts
    ON trace_events (deployment_domain, ts);
