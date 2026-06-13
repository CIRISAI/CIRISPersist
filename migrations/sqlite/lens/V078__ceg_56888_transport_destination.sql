-- V078 — CEG §5.6.8.8.1 transport_destination: per-occurrence reachability
--        rows for the "self at login" substrate (CIRISPersist#183,
--        CEG §8.1.12.7). SQLite dialect. Postgres parity: postgres/lens/V078.
--        See that file for the full rationale.
--
-- One reachable address for one identity_occurrence: transport_kind +
-- destination, keyed composite so an occurrence can register several and
-- writes are idempotent. TIMESTAMPTZ → TEXT (RFC-3339 UTC — lexical order
-- == chronological for liveness sweeps). No signature / persist_row_hash:
-- reachability is mutable + disposable (drop+re-register, not revoke). The
-- FK to federation_keys(key_id) keeps an address from naming an unknown
-- occurrence key. Refinery wraps this migration in its own transaction.

CREATE TABLE transport_destinations (
    occurrence_key_id    TEXT NOT NULL REFERENCES federation_keys(key_id),
    transport_kind       TEXT NOT NULL,
    destination          TEXT NOT NULL,
    asserted_at          TEXT NOT NULL,   -- RFC-3339 UTC
    last_seen_at         TEXT,            -- RFC-3339 UTC, advisory
    PRIMARY KEY (occurrence_key_id, transport_kind, destination)
);

CREATE INDEX transport_destinations_by_occurrence
    ON transport_destinations (occurrence_key_id);
