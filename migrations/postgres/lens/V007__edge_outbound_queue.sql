-- V007 — Edge outbound queue (v0.4.0, CIRISPersist#16).
--
-- Companion to CIRISEdge OQ-09. Edge ships two outbound channels:
--
--   send()         — ephemeral; caller-owned retry; failure visible
--   send_durable() — must eventually land across edge restart;
--                    edge-owned retry; caller gets a DurableHandle
--                    to observe outcome
--
-- Delivery class lives on the message type. send() consumers
-- (AccordEventsBatch, heartbeats) recover via persist's AV-9 dedup.
-- send_durable() consumers (BuildManifestPublication, DSARRequest /
-- DSARResponse, AttestationGossip, PublicKeyRegistration) need a
-- substrate that survives edge restart, retries with backoff,
-- bounds attempts, and supports content-derived ACK matching.
--
-- This migration is that substrate.
--
-- # State machine
--
--   enqueue → pending → sending → (transport ok)
--                              ↓                ↓
--                              awaiting_ack    delivered (no ack required)
--                              ↓
--                              delivered (ack received)
--                              ↓
--                              abandoned (ack timeout → max_attempts → abandoned)
--
--   abandoned_reason ∈ {max_attempts, ttl_expired, operator_cancel}
--
-- # Per-row policy
--
-- max_attempts + ttl_seconds + ack_timeout_seconds are copied onto
-- the row at enqueue from the message-type policy. Policy changes
-- don't retroactively break in-flight rows.
--
-- # Multi-instance dispatch (CIRISEdge OQ-06)
--
-- claimed_until + claimed_by support optimistic claim via
-- SELECT FOR UPDATE SKIP LOCKED + UPDATE. Concurrent dispatcher
-- workers get disjoint batches. Expired claims (worker crashed
-- mid-flight) revert via the sweep_expired_claims primitive.
--
-- # Schema lifecycle
--
-- Experimental during v0.4.x per the same v0.4.0-stabilization
-- contract federation_keys uses. Stabilizes at v0.5.0 once edge
-- traffic shape settles.

CREATE TABLE IF NOT EXISTS cirislens.edge_outbound_queue (
    -- Server-generated row identifier. Returned to the caller as
    -- DurableHandle.queue_id; load-bearing for status queries
    -- (outbound_status), ACK matching backstop, operator surface
    -- (cancel_outbound, replay_abandoned).
    queue_id                   UUID PRIMARY KEY DEFAULT gen_random_uuid(),

    -- Sender + destination peers. Both reference federation_keys
    -- (the canonical pubkey directory at v0.4.0+; accord_public_keys
    -- fallback retired in this release per lens#8 ASK 2). FK lets
    -- operator queries cleanly join against pubkey/identity columns.
    sender_key_id              TEXT NOT NULL,
    destination_key_id         TEXT NOT NULL,

    -- Wire-format identifiers. message_type maps onto the
    -- CIRISEdge MessageType enum; edge_schema_version is the
    -- envelope's wire-format version (independent of the trace
    -- schema_version used in trace_events).
    message_type               TEXT NOT NULL,
    edge_schema_version        TEXT NOT NULL,

    -- Envelope bytes verbatim — what the dispatcher hands to the
    -- transport layer. body_sha256 is the content hash used for
    -- ACK matching (the receiver's ACK envelope echoes this hash
    -- in its in_reply_to field — content-derived, not sender-
    -- local-id-derived; both peers naturally agree).
    envelope_bytes             BYTEA NOT NULL,
    body_sha256                BYTEA NOT NULL,
    body_size_bytes            INTEGER NOT NULL,

    -- State machine + timestamps. enqueued_at is the row birth;
    -- next_attempt_after is the earliest time a dispatcher claim
    -- is allowed (initially = enqueued_at; backed off after each
    -- transport failure). last_attempt_at + transport_delivered_at
    -- + delivered_at + abandoned_at are state-transition timestamps.
    status                     TEXT NOT NULL,
    enqueued_at                TIMESTAMPTZ NOT NULL DEFAULT now(),
    next_attempt_after         TIMESTAMPTZ NOT NULL,
    last_attempt_at            TIMESTAMPTZ,
    transport_delivered_at     TIMESTAMPTZ,
    delivered_at               TIMESTAMPTZ,
    abandoned_at               TIMESTAMPTZ,
    abandoned_reason           TEXT,

    -- Per-row policy (copied from message-type at enqueue).
    -- attempt_count is the number of transport attempts that have
    -- run (incremented on each mark_transport_failed); compared
    -- against max_attempts to decide retry-vs-abandon.
    attempt_count              INTEGER NOT NULL DEFAULT 0,
    max_attempts               INTEGER NOT NULL,
    ttl_seconds                BIGINT  NOT NULL,
    last_error_class           TEXT,
    last_error_detail          TEXT,
    last_transport             TEXT,

    -- ACK contract (per message-type policy).
    -- requires_ack=false: !requires_ack → 'delivered' immediately
    -- after mark_transport_delivered.
    -- requires_ack=true: → 'awaiting_ack' until match_ack_to_outbound
    -- lands the receiver's ACK envelope; ack_timeout_seconds bounds
    -- how long we wait before sweep_ack_timeouts retries or
    -- abandons.
    requires_ack               BOOLEAN NOT NULL,
    ack_timeout_seconds        BIGINT,
    ack_envelope_bytes         BYTEA,
    ack_received_at            TIMESTAMPTZ,

    -- Optimistic claim for multi-instance dispatch (OQ-06).
    -- claim_pending_outbound writes claimed_until = now() +
    -- claim_duration_seconds + claimed_by = worker_id. Concurrent
    -- workers see this row as already-claimed via SELECT FOR
    -- UPDATE SKIP LOCKED and skip it. sweep_expired_claims reverts
    -- claimed_until < now() rows back to 'pending' so they can be
    -- re-claimed (worker crashed mid-flight without releasing).
    claimed_until              TIMESTAMPTZ,
    claimed_by                 TEXT,

    -- ─── FK + invariant constraints ──────────────────────────────
    -- AV-1 / AV-28: every row's sender + destination resolve to
    -- registered federation peers. FK to federation_keys means
    -- forging an outbound row requires also forging a
    -- federation_keys row first.
    CONSTRAINT sender_key_must_exist
        FOREIGN KEY (sender_key_id) REFERENCES cirislens.federation_keys(key_id),
    CONSTRAINT destination_key_must_exist
        FOREIGN KEY (destination_key_id) REFERENCES cirislens.federation_keys(key_id),

    CONSTRAINT status_must_be_known
        CHECK (status IN ('pending', 'sending', 'awaiting_ack', 'delivered', 'abandoned')),
    CONSTRAINT abandoned_reason_must_be_known
        CHECK (abandoned_reason IS NULL OR abandoned_reason IN ('max_attempts', 'ttl_expired', 'operator_cancel')),

    -- AV-13: outbound queue is not a body-size flood vector.
    -- 8 MiB matches the persist ingest body limit (DefaultBodyLimit).
    CONSTRAINT body_size_bounded
        CHECK (body_size_bytes BETWEEN 1 AND 8388608),
    -- SHA-256 is exactly 32 bytes. Anything else is a buffer-mix bug.
    CONSTRAINT body_sha256_correct_length
        CHECK (octet_length(body_sha256) = 32),

    CONSTRAINT max_attempts_positive   CHECK (max_attempts > 0),
    CONSTRAINT ttl_seconds_positive    CHECK (ttl_seconds > 0),
    -- ack_timeout_seconds is required when requires_ack — the
    -- whole point of awaiting_ack is bounded waiting.
    CONSTRAINT ack_timeout_required_when_requires_ack
        CHECK ((NOT requires_ack) OR (ack_timeout_seconds IS NOT NULL AND ack_timeout_seconds > 0)),

    -- Cross-column shape invariants. Each terminal status implies
    -- its corresponding timestamp/reason is set; absence is a state-
    -- machine bug.
    CONSTRAINT delivered_implies_delivered_at
        CHECK ((status = 'delivered') = (delivered_at IS NOT NULL)),
    CONSTRAINT abandoned_implies_abandoned_at
        CHECK ((status = 'abandoned') = (abandoned_at IS NOT NULL AND abandoned_reason IS NOT NULL)),

    -- ACK envelope + ack_received_at are paired; either both null
    -- or both set. ack_received_at without requires_ack is
    -- nonsensical (we wouldn't have asked for one).
    CONSTRAINT ack_envelope_implies_ack_received
        CHECK ((ack_envelope_bytes IS NOT NULL) = (ack_received_at IS NOT NULL)),
    CONSTRAINT ack_received_implies_requires_ack
        CHECK (ack_received_at IS NULL OR requires_ack = TRUE)
);

-- Dispatch index: claim_pending_outbound's hot path. WHERE-clause
-- partial index keeps it small (only pending rows; delivered/
-- abandoned rows don't churn the index).
CREATE INDEX IF NOT EXISTS edge_outbound_queue_pending_dispatch
    ON cirislens.edge_outbound_queue (next_attempt_after)
    WHERE status = 'pending';

-- ACK-timeout sweep index. Walks awaiting_ack rows in
-- transport_delivered_at order so older-pending rows surface first.
CREATE INDEX IF NOT EXISTS edge_outbound_queue_awaiting_ack_sweep
    ON cirislens.edge_outbound_queue (transport_delivered_at)
    WHERE status = 'awaiting_ack';

-- Content-derived ACK matching: receiver's ACK envelope's
-- in_reply_to field equals our body_sha256. match_ack_to_outbound
-- walks this index. Partial on awaiting_ack so completed rows
-- don't slow lookups.
CREATE INDEX IF NOT EXISTS edge_outbound_queue_body_sha256_awaiting
    ON cirislens.edge_outbound_queue (body_sha256)
    WHERE status = 'awaiting_ack';

-- Operator surface: "what's queued for peer X / what's stuck".
CREATE INDEX IF NOT EXISTS edge_outbound_queue_destination
    ON cirislens.edge_outbound_queue (destination_key_id, status);

CREATE INDEX IF NOT EXISTS edge_outbound_queue_status_enqueued
    ON cirislens.edge_outbound_queue (status, enqueued_at);

-- Expired-claim sweep: rows in 'sending' with claimed_until < now()
-- (worker crashed mid-flight). Partial index keeps the sweep query
-- against this index small.
CREATE INDEX IF NOT EXISTS edge_outbound_queue_claimed_until_sweep
    ON cirislens.edge_outbound_queue (claimed_until)
    WHERE status = 'sending';
