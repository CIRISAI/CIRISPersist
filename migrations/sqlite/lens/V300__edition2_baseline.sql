-- V300 — THE EDITION-2 BASELINE (SQLite). CIRISPersist v62.0.0, slice E2b.
--
-- CC 1.0-rc20, "nothing carries, clean mesh": a v62 node reads nothing from
-- an earlier store. Edition 1's migration history (V001..V216) is retired;
-- this one file builds the schema those 197 files built, object for object
-- (the I1950 witness compares it with the frozen edition-1 catalog in
-- tests/fixtures/edition1_schema/), and then the edition-2 additions at the
-- end of the file.
--
-- Numbering. Edition 2 starts at V300, so no edition-2 store can be read as
-- an edition-1 one: an edition-1 history holds versions 1..216 only. The
-- runner refuses to apply this file over a store with any history row below
-- 300 (store::migration_runner::EDITION_TWO_BASELINE); that store is an
-- earlier one, and store::edition_upgrade deletes it. Future migrations
-- append as V301, V302, ...
--
-- Immutability. From v62 on, this file's BYTES are its contract, as every
-- shipped migration's are (FSD/MIGRATION_IMMUTABILITY.md;
-- evidence/migration_checksums.tsv pins its checksum).
--
-- Layout: every table (in the order edition 1 created them), then every
-- index, then the triggers; each statement is the text edition 1 left in
-- sqlite_schema, so the stored DDL is byte-identical. Then the edition-2
-- additions.

-- ════ tables ════
CREATE TABLE trace_events (
    event_id        INTEGER PRIMARY KEY AUTOINCREMENT,
    trace_id        TEXT    NOT NULL,
    thought_id      TEXT    NOT NULL,
    task_id         TEXT,
    step_point      TEXT,
    event_type      TEXT    NOT NULL,
    attempt_index   INTEGER NOT NULL DEFAULT 0,
    ts              TEXT    NOT NULL,
    agent_name      TEXT,
    agent_id_hash   TEXT,
    cognitive_state TEXT,
    trace_level     TEXT    NOT NULL,
    payload         TEXT    NOT NULL,
    cost_llm_calls  INTEGER,
    cost_tokens     INTEGER,
    -- f64-shaped column (see postgres V001 note about
    -- DOUBLE PRECISION choice). REAL in SQLite.
    cost_usd        REAL,
    signature       TEXT,
    signing_key_id  TEXT,
    signature_verified INTEGER NOT NULL DEFAULT 0,
    schema_version  TEXT,
    pii_scrubbed    INTEGER NOT NULL DEFAULT 0,
    audit_sequence_number INTEGER,
    audit_entry_hash      TEXT,
    audit_signature       TEXT
, original_content_hash TEXT, scrub_signature       TEXT, scrub_key_id          TEXT, scrub_timestamp       TEXT, agent_role            TEXT, agent_template        TEXT, deployment_domain     TEXT, deployment_type       TEXT, deployment_region     TEXT, deployment_trust_mode TEXT, extracted_features  TEXT, classifications     TEXT, pipeline_metadata   TEXT, verification_source TEXT NOT NULL DEFAULT 'persist'
        CHECK (verification_source IN ('persist', 'edge')), cohort_scope TEXT NOT NULL DEFAULT 'federation', cohort_target_id TEXT, pqc_key_id          TEXT, shard_key INTEGER, scrub_ner_ran             INTEGER, scrub_applied_trace_level TEXT, scrub_model_digest        TEXT, admitted_at TEXT);
CREATE TABLE trace_llm_calls (
    call_id              INTEGER PRIMARY KEY AUTOINCREMENT,
    trace_id             TEXT    NOT NULL,
    thought_id           TEXT    NOT NULL,
    task_id              TEXT,
    parent_event_id      INTEGER,
    parent_event_type    TEXT,
    parent_attempt_index INTEGER,
    attempt_index        INTEGER NOT NULL DEFAULT 0,
    ts                   TEXT    NOT NULL,
    duration_ms          REAL,
    handler_name         TEXT,
    service_name         TEXT,
    model                TEXT,
    base_url             TEXT,
    response_model       TEXT,
    prompt_tokens        INTEGER,
    completion_tokens    INTEGER,
    prompt_bytes         INTEGER,
    completion_bytes     INTEGER,
    cost_usd             REAL,
    status               TEXT,
    error_class          TEXT,
    attempt_count        INTEGER,
    retry_count          INTEGER,
    prompt_hash          TEXT,
    prompt               TEXT,
    response_text        TEXT
);
CREATE TABLE accord_public_keys (
    key_id            TEXT    PRIMARY KEY,
    public_key_base64 TEXT    NOT NULL,
    algorithm         TEXT,
    description       TEXT,
    -- DEFAULT CURRENT_TIMESTAMP emits ISO-8601 UTC (no offset);
    -- matches the TEXT-as-TIMESTAMPTZ shape across the schema.
    created_at        TEXT    NOT NULL DEFAULT CURRENT_TIMESTAMP,
    expires_at        TEXT,
    revoked_at        TEXT,
    revoked_reason    TEXT,
    added_by          TEXT
);
CREATE TABLE edge_outbound_queue (
    queue_id                   TEXT PRIMARY KEY,

    sender_key_id              TEXT NOT NULL,
    destination_key_id         TEXT NOT NULL,

    message_type               TEXT NOT NULL,
    edge_schema_version        TEXT NOT NULL,
    envelope_bytes             BLOB NOT NULL,
    body_sha256                BLOB NOT NULL,
    body_size_bytes            INTEGER NOT NULL,

    status                     TEXT NOT NULL,
    enqueued_at                TEXT NOT NULL DEFAULT (strftime('%Y-%m-%dT%H:%M:%fZ', 'now')),
    next_attempt_after         TEXT NOT NULL,
    last_attempt_at            TEXT,
    transport_delivered_at     TEXT,
    delivered_at               TEXT,
    abandoned_at               TEXT,
    abandoned_reason           TEXT,

    attempt_count              INTEGER NOT NULL DEFAULT 0,
    max_attempts               INTEGER NOT NULL,
    ttl_seconds                INTEGER NOT NULL,
    last_error_class           TEXT,
    last_error_detail          TEXT,
    last_transport             TEXT,

    requires_ack               INTEGER NOT NULL,  -- bool: 0/1
    ack_timeout_seconds        INTEGER,
    ack_envelope_bytes         BLOB,
    ack_received_at            TEXT,

    claimed_until              TEXT,
    claimed_by                 TEXT,

    FOREIGN KEY (sender_key_id) REFERENCES federation_keys(key_id),
    FOREIGN KEY (destination_key_id) REFERENCES federation_keys(key_id),

    CHECK (status IN ('pending', 'sending', 'awaiting_ack', 'delivered', 'abandoned')),
    CHECK (abandoned_reason IS NULL OR abandoned_reason IN ('max_attempts', 'ttl_expired', 'operator_cancel')),
    CHECK (body_size_bytes BETWEEN 1 AND 8388608),
    CHECK (length(body_sha256) = 32),
    CHECK (max_attempts > 0),
    CHECK (ttl_seconds > 0),
    CHECK ((NOT requires_ack) OR (ack_timeout_seconds IS NOT NULL AND ack_timeout_seconds > 0)),
    CHECK ((status = 'delivered') = (delivered_at IS NOT NULL)),
    CHECK ((status = 'abandoned') = (abandoned_at IS NOT NULL AND abandoned_reason IS NOT NULL)),
    CHECK ((ack_envelope_bytes IS NOT NULL) = (ack_received_at IS NOT NULL)),
    CHECK (ack_received_at IS NULL OR requires_ack = 1)
);
CREATE TABLE cirislens_secrets_secrets (
    secret_uuid                   TEXT PRIMARY KEY,
    encrypted_value               BLOB NOT NULL,
    encryption_key_ref            TEXT NOT NULL,
    salt                          BLOB NOT NULL,
    nonce                         BLOB NOT NULL,
    description                   TEXT NOT NULL,
    sensitivity_level             TEXT NOT NULL
        CHECK (sensitivity_level IN ('low','medium','high','critical')),
    detected_pattern              TEXT NOT NULL,
    context_hint                  TEXT,
    created_at                    TEXT NOT NULL DEFAULT (strftime('%Y-%m-%d %H:%M:%f', 'now')),
    last_accessed                 TEXT,
    access_count                  INTEGER NOT NULL DEFAULT 0,
    source_message_id             TEXT,
    auto_decapsulate_for_actions  TEXT NOT NULL DEFAULT '[]',
    manual_access_only            INTEGER NOT NULL DEFAULT 0,
    record_schema_version         TEXT NOT NULL DEFAULT '1.0'
, content_hmac BLOB);
CREATE TABLE cirislens_secrets_access_log (
    log_id        INTEGER PRIMARY KEY AUTOINCREMENT,
    secret_uuid   TEXT,
    accessor      TEXT NOT NULL,
    operation     TEXT NOT NULL
        CHECK (operation IN (
            'store','retrieve','recall','forget',
            'encrypt','decrypt','reencrypt','rotate'
        )),
    action_type   TEXT,
    purpose       TEXT,
    success       INTEGER NOT NULL,
    error         TEXT,
    trace_id      TEXT,
    thought_id    TEXT,
    created_at    TEXT NOT NULL DEFAULT (strftime('%Y-%m-%d %H:%M:%f', 'now'))
);
CREATE TABLE cirislens_secrets_master_key_meta (
    key_ref       TEXT PRIMARY KEY,
    key_kind      TEXT NOT NULL CHECK (key_kind IN ('software','hardware')),
    descriptor    TEXT,
    created_at    TEXT NOT NULL DEFAULT (strftime('%Y-%m-%d %H:%M:%f', 'now')),
    activated_at  TEXT,
    deactivated_at TEXT,
    rotated_to    TEXT REFERENCES cirislens_secrets_master_key_meta(key_ref)
);
CREATE TABLE cirislens_secrets_filter_config (
    config_id     TEXT PRIMARY KEY,
    config_value  TEXT NOT NULL,
    version       INTEGER NOT NULL DEFAULT 1,
    updated_at    TEXT NOT NULL DEFAULT (strftime('%Y-%m-%d %H:%M:%f', 'now')),
    updated_by    TEXT NOT NULL
);
CREATE TABLE cirislens_pseudonyms (
    original_hash  BLOB PRIMARY KEY,
    pseudonym      TEXT NOT NULL UNIQUE,
    class          TEXT NOT NULL,
    created_at     TEXT NOT NULL DEFAULT (strftime('%Y-%m-%d %H:%M:%f', 'now'))
);
CREATE TABLE cirisnode_promotion_attestations (
    attestation_id                TEXT PRIMARY KEY,
    target_kind                   TEXT NOT NULL
        CHECK (target_kind IN (
            'contribution',
            'vote',
            'moderation_event',
            'slashing_attestation',
            'reconsideration_attestation'
        )),
    target_ids                    TEXT NOT NULL,
    attested_by                   TEXT NOT NULL,
    aggregate_evidence            TEXT NOT NULL,
    attested_at                   TEXT NOT NULL,
    signature                     TEXT NOT NULL,
    signing_key_id                TEXT NOT NULL,
    signature_verified            INTEGER NOT NULL DEFAULT 0,
    original_content_hash         BLOB,
    scrub_signature_classical     TEXT,
    scrub_signature_pqc           TEXT,
    scrub_key_id                  TEXT,
    scrub_timestamp               TEXT,
    pqc_completed_at              TEXT,
    persist_row_hash              TEXT NOT NULL,
    created_at                    TEXT NOT NULL DEFAULT (strftime('%Y-%m-%d %H:%M:%f', 'now'))
);
CREATE TABLE cirisgraph_nodes (
    node_id          TEXT NOT NULL,
    scope            TEXT NOT NULL
        CHECK (scope IN ('LOCAL', 'IDENTITY', 'ENVIRONMENT', 'COMMUNITY')),
    node_type        TEXT NOT NULL,
    attributes       TEXT NOT NULL,
    version          INTEGER NOT NULL DEFAULT 1
        CHECK (version >= 1),
    updated_by       TEXT NOT NULL,
    updated_at       TEXT NOT NULL DEFAULT (strftime('%Y-%m-%d %H:%M:%f', 'now')),
    created_at       TEXT NOT NULL DEFAULT (strftime('%Y-%m-%d %H:%M:%f', 'now')),

    -- Audit envelope.
    signature                 TEXT,
    signing_key_id            TEXT,
    signature_verified        INTEGER NOT NULL DEFAULT 0,
    original_content_hash     BLOB,
    persist_row_hash          TEXT, consolidation_level TEXT NOT NULL DEFAULT 'basic',

    PRIMARY KEY (node_id, scope)
);
CREATE TABLE cirisgraph_edges (
    edge_id          TEXT PRIMARY KEY,
    source_node_id   TEXT NOT NULL,
    target_node_id   TEXT NOT NULL,
    scope            TEXT NOT NULL
        CHECK (scope IN ('LOCAL', 'IDENTITY', 'ENVIRONMENT', 'COMMUNITY')),
    relationship     TEXT NOT NULL,
    weight           REAL,
    attributes       TEXT NOT NULL DEFAULT '{}',
    created_at       TEXT NOT NULL DEFAULT (strftime('%Y-%m-%d %H:%M:%f', 'now'))
);
CREATE TABLE cirislens_audit_log (
    entry_id              TEXT PRIMARY KEY,
    sequence_number       INTEGER NOT NULL CHECK (sequence_number >= 1),
    tenant_id             TEXT NOT NULL,
    actor_id              TEXT NOT NULL,
    action_type           TEXT NOT NULL,
    subject_kind          TEXT NOT NULL,
    subject_id            TEXT NOT NULL,
    payload               TEXT NOT NULL,
    prev_hash             BLOB NOT NULL,
    entry_hash            BLOB NOT NULL,
    recorded_at           TEXT NOT NULL,

    -- Audit envelope.
    signature             TEXT NOT NULL,
    signing_key_id        TEXT NOT NULL,
    signature_verified    INTEGER NOT NULL DEFAULT 0,
    persist_row_hash      TEXT NOT NULL, content_hash BLOB,

    UNIQUE (tenant_id, sequence_number)
);
CREATE TABLE cirisgraph_telemetry_metrics (
    metric_id         TEXT PRIMARY KEY,
    metric_name       TEXT NOT NULL,
    tenant_id         TEXT NOT NULL,
    value             REAL NOT NULL,
    labels            TEXT NOT NULL DEFAULT '{}',
    observed_at       TEXT NOT NULL,
    expires_at        TEXT NOT NULL,
    created_at        TEXT NOT NULL DEFAULT (strftime('%Y-%m-%d %H:%M:%f', 'now'))
);
CREATE TABLE cirisgraph_consolidation_locks (
    period_start      TEXT NOT NULL,
    period_end        TEXT NOT NULL,
    tenant_id         TEXT NOT NULL,
    locked_by         TEXT NOT NULL,
    locked_at         TEXT NOT NULL DEFAULT (strftime('%Y-%m-%d %H:%M:%f', 'now')),

    PRIMARY KEY (period_start, tenant_id),
    CHECK (period_end > period_start)
);
CREATE TABLE edge_detection_events (
    detection_id        TEXT PRIMARY KEY,  -- UUID-as-TEXT; caller generates
    tenant_id           TEXT NOT NULL,
    detector_kind       TEXT NOT NULL,
    -- FK to federation_keys.key_id — SQLite enforces with PRAGMA
    -- foreign_keys=ON which SqliteBackend boot pragmas already set.
    subject_key_id      TEXT NOT NULL REFERENCES federation_keys(key_id),
    observed_at         TEXT NOT NULL,
    evidence            TEXT NOT NULL,      -- JSONB → TEXT
    severity            TEXT NOT NULL,
    signature           TEXT NOT NULL,
    signing_key_id      TEXT NOT NULL,
    signature_verified  INTEGER NOT NULL DEFAULT 0,
    persist_row_hash    TEXT NOT NULL
);
CREATE TABLE federation_trust_grants (
    grant_id           TEXT PRIMARY KEY,    -- UUID-as-TEXT; caller generates
    grantee_key        TEXT NOT NULL REFERENCES federation_keys(key_id),
    granter_key        TEXT NOT NULL REFERENCES federation_keys(key_id),
    purpose            TEXT NOT NULL
                       CHECK (purpose IN ('technical','deferral','contribution','service')),
    scope              TEXT NOT NULL,
    granted_at         TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP,
    expires_at         TEXT,
    revoked_at         TEXT,
    revoked_by         TEXT REFERENCES federation_keys(key_id),
    chain_event_id     INTEGER NOT NULL,
    chain_event_hash   BLOB NOT NULL,
    tenant_id          TEXT NOT NULL,
    CHECK (granter_key != grantee_key),
    CHECK (revoked_at IS NULL OR revoked_by IS NOT NULL),
    UNIQUE (grantee_key, granter_key, purpose, scope)
);
CREATE TABLE merkle_leaves (
    tenant_id          TEXT NOT NULL,
    leaf_index         INTEGER NOT NULL,
    chain_event_id     INTEGER NOT NULL,
    leaf_hash          BLOB NOT NULL,
    canonical_bytes    BLOB NOT NULL,
    leaf_serialized    BLOB NOT NULL,
    appended_at        TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP,
    PRIMARY KEY (tenant_id, leaf_index),
    UNIQUE (tenant_id, chain_event_id),
    CHECK (length(leaf_hash) = 32)
);
CREATE TABLE merkle_sth_log (
    tenant_id              TEXT NOT NULL,
    tree_size              INTEGER NOT NULL,
    root_hash              BLOB NOT NULL,
    signed_at              TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP,
    signer_key_id          TEXT NOT NULL,
    signature_blob         BLOB NOT NULL,
    witness_signatures     TEXT NOT NULL DEFAULT '[]',  -- JSON-array string
    PRIMARY KEY (tenant_id, tree_size),
    CHECK (length(root_hash) = 32)
);
CREATE TABLE "cirislens_incident_records" (
    incident_id           TEXT PRIMARY KEY,
    tenant_id             TEXT NOT NULL,
    severity              TEXT NOT NULL
        CHECK (severity IN ('info', 'warning', 'error', 'critical',
                            'low', 'medium', 'high')),
    category              TEXT NOT NULL,
    title                 TEXT NOT NULL,
    description           TEXT,
    correlation_keys      TEXT NOT NULL DEFAULT '[]',
    state                 TEXT NOT NULL
        CHECK (state IN ('open', 'investigating', 'resolved', 'closed',
                         'recurring')),
    first_seen_at         TEXT NOT NULL,
    last_seen_at          TEXT NOT NULL,
    resolved_at           TEXT,
    resolution_notes      TEXT,
    occurrences           INTEGER NOT NULL DEFAULT 1
        CHECK (occurrences >= 1),

    -- Audit envelope (preserved verbatim from V016).
    signature             TEXT,
    signing_key_id        TEXT,
    signature_verified    INTEGER NOT NULL DEFAULT 0,
    persist_row_hash      TEXT NOT NULL,
    created_at            TEXT NOT NULL DEFAULT (strftime('%Y-%m-%d %H:%M:%f', 'now')),

    -- v1.5.5 forensic fields (CIRISPersist#56). All nullable.
    incident_type         TEXT,
    source_component      TEXT,
    handler_name          TEXT,
    exception_type        TEXT,
    stack_trace           TEXT,
    filename              TEXT,
    line_number           INTEGER,
    function_name         TEXT,
    impact                TEXT,
    urgency               TEXT,
    detection_method      TEXT
);
CREATE TABLE cirislens_service_correlations (
    correlation_id        TEXT PRIMARY KEY,
    service_type          TEXT NOT NULL,
    handler_name          TEXT NOT NULL,
    action_type           TEXT NOT NULL,
    request_data          TEXT,
    response_data         TEXT,
    status                TEXT NOT NULL DEFAULT 'pending'
        CHECK (status IN ('pending', 'active', 'completed',
                          'failed', 'cancelled')),
    created_at            TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP,
    updated_at            TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP,
    correlation_type      TEXT NOT NULL DEFAULT 'service_interaction'
        CHECK (correlation_type IN ('service_interaction', 'metric',
                                    'trace', 'log')),
    timestamp             TEXT,
    metric_name           TEXT,
    metric_value          REAL,
    log_level             TEXT,
    trace_id              TEXT,
    span_id               TEXT,
    parent_span_id        TEXT,
    tags                  TEXT,
    retention_policy      TEXT NOT NULL DEFAULT 'raw'
        CHECK (retention_policy IN ('raw', 'aggregated', 'summary',
                                    'retained_indefinitely')),
    agent_occurrence_id   TEXT NOT NULL DEFAULT 'default'
);
CREATE TABLE cirislens_scheduled_tasks (
    id                    TEXT PRIMARY KEY,
    name                  TEXT NOT NULL,
    goal_description      TEXT NOT NULL,
    status                TEXT NOT NULL
        CHECK (status IN ('PENDING', 'ACTIVE', 'COMPLETE', 'FAILED')),
    defer_until           TEXT,
    schedule_cron         TEXT,
    trigger_prompt        TEXT NOT NULL,
    origin_thought_id     TEXT NOT NULL,
    created_at            TEXT NOT NULL,
    last_triggered_at     TEXT,
    next_trigger_at       TEXT,
    deferral_count        INTEGER NOT NULL DEFAULT 0
        CHECK (deferral_count >= 0),
    deferral_history      TEXT,
    created_by_agent      TEXT,
    agent_occurrence_id   TEXT NOT NULL DEFAULT 'default',
    FOREIGN KEY (origin_thought_id) REFERENCES cirislens_thoughts(thought_id)
);
CREATE TABLE cirislens_deferral_reports (
    message_id        TEXT PRIMARY KEY,
    task_id           TEXT NOT NULL,
    thought_id        TEXT NOT NULL,
    package           TEXT,
    created_at        TEXT NOT NULL DEFAULT (strftime('%Y-%m-%d %H:%M:%f', 'now')),
    resolved_at       TEXT,
    resolution_notes  TEXT,
    FOREIGN KEY (task_id) REFERENCES cirislens_tasks(task_id),
    FOREIGN KEY (thought_id) REFERENCES cirislens_thoughts(thought_id)
);
CREATE TABLE cirislens_maintenance_locks (
    lock_key             TEXT PRIMARY KEY,
    locked_by            TEXT,
    locked_at            TEXT,
    lock_timeout_seconds INTEGER NOT NULL DEFAULT 300
        CHECK (lock_timeout_seconds > 0),
    metadata             TEXT
);
CREATE TABLE cirislens_creation_ceremonies (
    ceremony_id              TEXT PRIMARY KEY,
    timestamp                TEXT NOT NULL,
    creator_agent_id         TEXT NOT NULL,
    creator_human_id         TEXT NOT NULL,
    wise_authority_id        TEXT NOT NULL,
    new_agent_id             TEXT NOT NULL,
    new_agent_name           TEXT NOT NULL,
    new_agent_purpose        TEXT NOT NULL,
    new_agent_description    TEXT,
    creation_justification   TEXT NOT NULL,
    expected_capabilities    TEXT,
    ethical_considerations   TEXT NOT NULL,
    template_profile_hash    TEXT,
    ceremony_status          TEXT NOT NULL
        CHECK (ceremony_status IN (
            'pending', 'in_progress', 'completed', 'failed', 'revoked'
        ))
);
CREATE TABLE cirislens_continuity_awareness (
    id                         TEXT PRIMARY KEY,
    agent_id                   TEXT NOT NULL,
    shutdown_timestamp         TEXT NOT NULL,
    is_terminal                INTEGER NOT NULL,
    shutdown_reason            TEXT NOT NULL,
    expected_reactivation      TEXT,
    initiated_by               TEXT NOT NULL,
    final_thoughts             TEXT NOT NULL,
    unfinished_tasks           TEXT,
    reactivation_instructions  TEXT,
    deferred_goals             TEXT,
    preservation_node_id       TEXT NOT NULL,
    preservation_scope         TEXT NOT NULL DEFAULT 'IDENTITY'
        CHECK (preservation_scope IN ('LOCAL', 'IDENTITY', 'ENVIRONMENT', 'COMMUNITY')),
    reactivation_count         INTEGER NOT NULL DEFAULT 0
        CHECK (reactivation_count >= 0),
    FOREIGN KEY (preservation_node_id, preservation_scope)
        REFERENCES cirisgraph_nodes (node_id, scope)
);
CREATE TABLE cirislens_feedback_mappings (
    feedback_id        TEXT PRIMARY KEY,
    source_message_id  TEXT,
    target_thought_id  TEXT,
    feedback_type      TEXT,
    created_at         TEXT NOT NULL DEFAULT (strftime('%Y-%m-%d %H:%M:%f', 'now')),
    FOREIGN KEY (target_thought_id) REFERENCES cirislens_thoughts(thought_id)
);
CREATE TABLE cirislens_wa_cert (
    wa_id                  TEXT PRIMARY KEY,
    name                   TEXT NOT NULL,
    role                   TEXT NOT NULL
        CHECK (role IN ('root','authority','observer')),
    pubkey                 TEXT NOT NULL,
    jwt_kid                TEXT NOT NULL UNIQUE,
    password_hash          TEXT,
    api_key_hash           TEXT,
    oauth_provider         TEXT,
    oauth_external_id      TEXT,
    oauth_links            TEXT,
    veilid_id              TEXT,
    auto_minted            INTEGER NOT NULL DEFAULT 0,
    parent_wa_id           TEXT,
    parent_signature       TEXT,
    scopes                 TEXT NOT NULL,
    custom_permissions     TEXT,
    adapter_id             TEXT,
    adapter_name           TEXT,
    adapter_metadata       TEXT,
    token_type             TEXT NOT NULL DEFAULT 'standard'
        CHECK (token_type IN ('standard','session','api_key','oauth','service')),
    created                TEXT NOT NULL,
    last_login             TEXT,
    active                 INTEGER NOT NULL DEFAULT 1,
    FOREIGN KEY (parent_wa_id) REFERENCES cirislens_wa_cert(wa_id)
);
CREATE TABLE "cirislens_thoughts" (
    thought_id            TEXT PRIMARY KEY,
    source_task_id        TEXT NOT NULL,
    channel_id            TEXT,
    thought_type          TEXT NOT NULL DEFAULT 'standard',
    status                TEXT NOT NULL
        CHECK (status IN ('pending', 'processing', 'completed',
                          'failed', 'deferred')),
    created_at            TEXT NOT NULL,
    updated_at            TEXT NOT NULL,
    round_number          INTEGER NOT NULL DEFAULT 0
        CHECK (round_number >= 0),
    content               TEXT NOT NULL,
    context_json          TEXT,
    thought_depth         INTEGER NOT NULL DEFAULT 0
        CHECK (thought_depth >= 0),
    ponder_notes_json     TEXT,
    parent_thought_id     TEXT,
    final_action_json     TEXT,
    agent_occurrence_id   TEXT NOT NULL DEFAULT 'default',
    FOREIGN KEY (source_task_id) REFERENCES cirislens_tasks(task_id)
        ON DELETE CASCADE,
    FOREIGN KEY (parent_thought_id) REFERENCES cirislens_thoughts(thought_id)
);
CREATE TABLE cirislens_revoked_service_tokens (
    token_hash  TEXT PRIMARY KEY,
    revoked_at  TEXT NOT NULL,
    revoked_by  TEXT NOT NULL,
    reason      TEXT NOT NULL
);
CREATE TABLE cirislens_identity_sequences (
    identity    TEXT NOT NULL,
    stream      TEXT NOT NULL,
    next_value  INTEGER NOT NULL DEFAULT 0,
    updated_at  TEXT NOT NULL,
    PRIMARY KEY (identity, stream)
);
CREATE TABLE cirislens_occurrence_registry (
    occurrence_id   TEXT PRIMARY KEY,
    identity        TEXT NOT NULL,
    registered_at   TEXT NOT NULL,
    last_heartbeat  TEXT NOT NULL,
    expires_at      TEXT NOT NULL,
    metadata        TEXT
);
CREATE TABLE cirislens_derived_calibration_bundles (
    ratchet_calibration_version  INTEGER PRIMARY KEY,

    projection_version           TEXT NOT NULL,

    calibrated_at                TEXT NOT NULL,

    calibration_corpus_sha256    TEXT NOT NULL,
    calibration_corpus_n         INTEGER NOT NULL,

    sample_size_gate             INTEGER NOT NULL,
    manifold_threshold_global    REAL NOT NULL,

    projection_metadata          TEXT NOT NULL,
    cohort_centroids             TEXT NOT NULL,

    is_current                   INTEGER NOT NULL DEFAULT 0,

    canonical_bytes              BLOB NOT NULL,
    ed25519_sig                  BLOB NOT NULL,
    ml_dsa_65_sig                BLOB NOT NULL,
    signing_key_id               TEXT NOT NULL,

    inserted_at                  TEXT NOT NULL,

    CONSTRAINT calibration_bundles_corpus_n_positive
        CHECK (calibration_corpus_n > 0),
    CONSTRAINT calibration_bundles_sample_size_gate_positive
        CHECK (sample_size_gate > 0),
    CONSTRAINT calibration_bundles_manifold_threshold_positive
        CHECK (manifold_threshold_global > 0.0),
    CONSTRAINT calibration_bundles_ed25519_sig_correct_length
        CHECK (length(ed25519_sig) = 64),
    CONSTRAINT calibration_bundles_ml_dsa_65_sig_correct_length
        CHECK (length(ml_dsa_65_sig) = 3309),
    CONSTRAINT calibration_bundles_canonical_bytes_bounded
        CHECK (length(canonical_bytes) BETWEEN 1 AND 8388608),
    CONSTRAINT calibration_bundles_is_current_bool
        CHECK (is_current IN (0, 1))
);
CREATE TABLE cirislens_audit_archives (
    archive_id     TEXT    PRIMARY KEY,
    tenant_id      TEXT    NOT NULL,
    from_ts        TEXT    NOT NULL,
    to_ts          TEXT    NOT NULL,
    rows_archived  INTEGER NOT NULL CHECK (rows_archived >= 0),
    chain_anchor   BLOB    NOT NULL CHECK (length(chain_anchor) = 32),
    archive_bytes  BLOB    NOT NULL,
    created_at     TEXT    NOT NULL DEFAULT (strftime('%Y-%m-%dT%H:%M:%fZ', 'now')),
    CHECK (from_ts < to_ts)
);
CREATE TABLE federation_peer_metadata (
    key_id              TEXT    NOT NULL PRIMARY KEY
        REFERENCES federation_keys(key_id) ON DELETE CASCADE,
    alias               TEXT,
    trust               TEXT    NOT NULL DEFAULT 'untrusted'
        CHECK (trust IN ('untrusted', 'trusted', 'restricted', 'blocked')),
    notes               TEXT,
    policy_blob         TEXT,
    transport_identity  TEXT,
    removed_at          TEXT,
    inserted_at         TEXT    NOT NULL
        DEFAULT (strftime('%Y-%m-%dT%H:%M:%fZ', 'now')),
    updated_at          TEXT    NOT NULL
        DEFAULT (strftime('%Y-%m-%dT%H:%M:%fZ', 'now')),
    persist_row_hash    TEXT    NOT NULL
);
CREATE TABLE blackhole_rules (
    identity_hash    BLOB    NOT NULL PRIMARY KEY,
    until            TEXT,
    reason           TEXT,
    added_at         TEXT    NOT NULL
        DEFAULT (strftime('%Y-%m-%dT%H:%M:%fZ', 'now')),
    hits             INTEGER NOT NULL DEFAULT 0,
    persist_row_hash TEXT    NOT NULL
);
CREATE TABLE identity_canonical_binding (
    canonical_hash       TEXT NOT NULL PRIMARY KEY,
    federation_key_id    TEXT NOT NULL
        REFERENCES federation_keys(key_id) ON DELETE CASCADE,
    bound_at             TEXT NOT NULL,
    binding_attestation_id TEXT
        REFERENCES federation_attestations(attestation_id) ON DELETE SET NULL,
    inserted_at          TEXT NOT NULL DEFAULT (strftime('%Y-%m-%d %H:%M:%f', 'now'))
);
CREATE TABLE federation_revocation_quorum_state (
    revocation_id     TEXT PRIMARY KEY
        REFERENCES federation_revocations(revocation_id) ON DELETE CASCADE,

    -- First-observation timestamp per region (ISO-8601 TEXT;
    -- NULL = not yet observed in that region).
    us_observed_at    TEXT,
    eu_observed_at    TEXT,
    apac_observed_at  TEXT,

    -- When 2-of-3 quorum was first crossed (ISO-8601 TEXT;
    -- NULL = pre-quorum).
    quorum_reached_at TEXT,

    -- Q1 tier-1 merge input. Always 1..=3 (denormalized count of
    -- non-NULL region columns; the comparator reads this in one
    -- column-load instead of three NULL-checks).
    quorum_weight     INTEGER NOT NULL DEFAULT 1
        CHECK (quorum_weight BETWEEN 1 AND 3),

    -- Always-current timestamp the substrate sets on every write
    -- (postgres parity: `DEFAULT NOW()`; sqlite uses CURRENT_TIMESTAMP).
    updated_at        TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP
);
CREATE TABLE "federation_blobs" (
    -- SHA-256 content hash (32 bytes raw).
    sha256        BLOB PRIMARY KEY
        CHECK (length(sha256) = 32),

    -- 'inline' | 's3' | 'external_url' | 'chunk_dag'  (V061 adds chunk_dag).
    storage_kind  TEXT NOT NULL
        CHECK (storage_kind IN ('inline', 's3', 'external_url', 'chunk_dag')),

    -- Inline body OR (V061) the JCS chunk-DAG manifest. Present iff
    -- storage_kind in ('inline','chunk_dag').
    bytes_inline  BLOB,

    -- External URI/URL. Present iff storage_kind in ('s3','external_url').
    external_ref  TEXT,

    size_bytes    INTEGER NOT NULL CHECK (size_bytes >= 0),

    media_type    TEXT,

    first_seen_at TEXT NOT NULL DEFAULT (strftime('%Y-%m-%d %H:%M:%f', 'now')),

    -- JSON array string. Empty array = no region-specific tracking.
    regions_held  TEXT NOT NULL DEFAULT '[]',

    -- V053 access-tracking columns (MUST survive the rebuild).
    last_accessed_at TEXT NOT NULL
        DEFAULT '1970-01-01T00:00:00+00:00',
    access_count  INTEGER NOT NULL DEFAULT 0, cohort_scope TEXT NOT NULL DEFAULT 'federation'
        CHECK (cohort_scope IN ('self', 'family', 'community', 'affiliations',
                                'species', 'biosphere', 'federation')), crypto_tier TEXT NOT NULL DEFAULT 'plaintext'
        CHECK (crypto_tier IN ('plaintext', 'invisible_encrypted', 'community_dek')), author_key_id TEXT NULL, key_grant_emitted_at TEXT, group_key_id TEXT NULL,

    -- Cross-column rule, extended with the chunk_dag arm (manifest in
    -- bytes_inline, like inline; external_ref NULL).
    CHECK (
        (storage_kind = 'inline'
            AND bytes_inline IS NOT NULL
            AND external_ref IS NULL)
        OR
        (storage_kind = 'chunk_dag'
            AND bytes_inline IS NOT NULL
            AND external_ref IS NULL)
        OR
        (storage_kind IN ('s3', 'external_url')
            AND bytes_inline IS NULL
            AND external_ref IS NOT NULL)
    )
);
CREATE TABLE federation_stream_chunks (
    -- Opaque producer-chosen stream id (CEG §10.5 log_id).
    stream_id   TEXT NOT NULL,

    -- Monotonic per-stream sequence. Part of the PK — a re-used seq is a
    -- PK conflict (the monotonicity guarantee). u64 in Rust, bound i64.
    seq         INTEGER NOT NULL,

    -- Content address of this chunk's bytes — a federation_blobs.sha256,
    -- exactly 32 bytes.
    chunk_sha   BLOB NOT NULL
        CHECK (length(chunk_sha) = 32),

    -- Key-rotation epoch (CEG §10.5.3). Stored now; cascade is Cut C3.
    epoch       INTEGER NOT NULL DEFAULT 0,

    -- This chunk's byte length.
    size_bytes  INTEGER NOT NULL CHECK (size_bytes >= 0),

    -- Wall-clock at append time (RFC3339).
    created_at  TEXT NOT NULL DEFAULT (strftime('%Y-%m-%d %H:%M:%f', 'now')),

    -- Set on seal_stream (informational). NULL while live.
    sealed_at   TEXT NULL, plaintext_size_bytes INTEGER NOT NULL DEFAULT 0
        CHECK (plaintext_size_bytes >= 0),

    -- The monotonicity guarantee + the seq-ordered seal walk index.
    PRIMARY KEY (stream_id, seq)
);
CREATE TABLE federation_stream_sth (
    -- Parsed `<stream_id>` from the STH's `stream:<id>` log_id (CEG
    -- §10.5.1). Joins to federation_stream_chunks.
    stream_id           TEXT NOT NULL,

    -- RFC 6962 tree size (leaf/chunk count). u64 in Rust, bound i64.
    -- Part of the PK.
    tree_size           INTEGER NOT NULL,

    -- Key-rotation epoch (CEG §10.5.3). Stored now; cascade is Cut C3.
    epoch               INTEGER NOT NULL DEFAULT 0,

    -- Merkle root the STH claims. Recomputed from persist's own chunks
    -- and asserted equal BEFORE insert (anti-equivocation gate). 32 B.
    root_hash           BLOB NOT NULL
        CHECK (length(root_hash) = 32),

    -- Wall-clock the producer signed the STH (RFC3339).
    signed_at           TEXT NOT NULL,

    -- The federation_keys key that signed; the producer pubkey is
    -- resolved from federation_keys via this id for the sig gate.
    producer_key_id     TEXT NOT NULL,

    -- Serialized ciris_crypto::HybridSignature (JSON-as-bytes), mirror
    -- of merkle_store's serialize_signature (same encoding PG/SQLite).
    signature_blob      BLOB NOT NULL,

    -- Serialized witness cosignatures (CEG §10.5.1). Stored as-provided
    -- (default empty); no cosign quorum enforcement this cut.
    witness_signatures  TEXT NOT NULL DEFAULT '[]',

    -- One STH per (stream, size); append-only, monotonic tree_size.
    PRIMARY KEY (stream_id, tree_size)
);
CREATE TABLE federation_stream_delivery_receipts (
    -- The stream this receipt acknowledges. Joins to
    -- federation_stream_sth / federation_stream_chunks.
    stream_id           TEXT NOT NULL,

    -- The acknowledging subscriber's federation_keys.key_id. The
    -- subscriber pubkey is resolved from federation_keys via this id
    -- for the signature gate.
    subscriber_key_id   TEXT NOT NULL,

    -- Key-rotation epoch the chunk was sealed under (per-epoch
    -- entitlement / billing scope). u64 in Rust, bound i64.
    epoch               INTEGER NOT NULL DEFAULT 0,

    -- Chunk index acknowledged (the K in §10.5.4). u64 in Rust, bound
    -- i64. Part of the PK.
    k                   INTEGER NOT NULL,

    -- The committed STH root the subscriber saw at tree_size >= k. The
    -- put gate JOINs this against federation_stream_sth.root_hash; an
    -- unpublished root is rejected. 32 B.
    chunk_root          BLOB NOT NULL
        CHECK (length(chunk_root) = 32),

    -- Serialized ciris_crypto::HybridSignature (Ed25519 + ML-DSA-65)
    -- over receipt_signing_bytes. JSON-as-bytes, same encoding PG/SQLite
    -- (mirror of merkle_store's serialize_signature).
    signature_blob      BLOB NOT NULL,

    -- Wall-clock persist accepted the receipt (RFC3339).
    received_at         TEXT NOT NULL,

    -- One receipt per (stream, subscriber, chunk); a re-PUT of the same
    -- (root) is idempotent, a different root at the same key is a
    -- subscriber equivocation attempt → rejected by put_delivery_receipt.
    PRIMARY KEY (stream_id, subscriber_key_id, k)
);
CREATE TABLE federation_blob_key_grants (
    -- The at-rest content address: SHA-256 of the stored ciphertext
    -- envelope (NOT the plaintext sha). References the federation_blobs row.
    at_rest_sha256       BLOB NOT NULL
        CHECK (length(at_rest_sha256) = 32),

    -- Recipient federation key_id (an occurrence_key_id for self/family
    -- recipients), or the reserved '__persist_self__' sentinel for
    -- persist's own content-master self-retention row.
    recipient_key_id     TEXT NOT NULL,

    -- 'x25519_mlkem768_aes256_gcm_hkdf_sha256' (recipient v2 grant) or
    -- 'aes256_gcm_content_master' (persist self-retention).
    wrap_algorithm       TEXT NOT NULL
        CHECK (wrap_algorithm IN (
            'x25519_mlkem768_aes256_gcm_hkdf_sha256',
            'aes256_gcm_content_master'
        )),

    -- The wrapped DEK. For v2 grants: the KeyGrantWrapV2 JSON envelope
    -- (base64 fields). For the self-retention row: base64 of
    -- nonce(12) || aes256_gcm(content_master, dek).
    wrapped_dek          TEXT NOT NULL,

    -- The cohort_scope the originating write carried ('self' | 'family').
    -- Informational / audit; the grant itself is scope-agnostic at read.
    cohort_scope         TEXT NOT NULL,

    created_at           TEXT NOT NULL DEFAULT (strftime('%Y-%m-%d %H:%M:%f', 'now')),

    PRIMARY KEY (at_rest_sha256, recipient_key_id)
);
CREATE TABLE federation_content_master (
    id              INTEGER PRIMARY KEY CHECK (id = 0),
    key_kind        TEXT NOT NULL CHECK (key_kind IN ('software', 'hardware')),
    master_key_b64  TEXT,            -- present iff key_kind='software'
    descriptor      TEXT NOT NULL,   -- provenance string
    created_at      TEXT NOT NULL DEFAULT (strftime('%Y-%m-%d %H:%M:%f', 'now'))
);
CREATE TABLE federation_content_kem_identity (
    id                       INTEGER PRIMARY KEY CHECK (id = 0),

    -- Honest provenance of the SEAL ('software' iff the sealing
    -- content-master is software — the only posture wired today).
    key_kind                 TEXT NOT NULL CHECK (key_kind IN ('software', 'hardware')),

    -- The two PUBLIC halves (base64 standard). x25519 = 32 raw bytes;
    -- ML-KEM-768 = 1184 raw bytes (FIPS 203).
    content_x25519_pubkey_b64       TEXT NOT NULL,
    content_ml_kem_768_pubkey_b64   TEXT NOT NULL,

    -- The two PRIVATE halves, SEALED under the content master via
    -- wrap_dek_for_persist (base64 of nonce(12) || aes256_gcm(master, sk)).
    content_x25519_privkey_sealed_b64       TEXT NOT NULL,
    content_ml_kem_768_privkey_sealed_b64   TEXT NOT NULL,

    created_at               TEXT NOT NULL DEFAULT (strftime('%Y-%m-%d %H:%M:%f', 'now'))
);
CREATE TABLE shared_instance_leases (
    instance_name        TEXT PRIMARY KEY,
    owner_pid            INTEGER NOT NULL,
    owner_hostname       TEXT NOT NULL,
    acquired_at          TEXT NOT NULL,   -- RFC-3339 UTC
    last_heartbeat_at    TEXT NOT NULL,   -- RFC-3339 UTC
    lease_version        INTEGER NOT NULL DEFAULT 1
);
CREATE TABLE hard_case_events (
    event_id          TEXT PRIMARY KEY,   -- deterministic: dedupes re-scans
    kind              TEXT NOT NULL,      -- the `hard_case:{kind}` suffix (open vocab)
    target_key_id     TEXT,               -- the Contribution / row the case is against
    subject_key_id    TEXT,               -- the subject, where one applies
    detail            TEXT NOT NULL DEFAULT '{}',  -- JSON context (sla_days, deadline, …)
    emitted_at        TEXT NOT NULL       -- RFC-3339 UTC
, attestation_id TEXT
        REFERENCES federation_attestations(attestation_id) ON DELETE CASCADE, emitter_key_id TEXT);
CREATE TABLE retention_policies (
    table_name             TEXT PRIMARY KEY,   -- validated identifier (schema.table)
    time_column            TEXT NOT NULL DEFAULT 'ts',
    min_keep_secs          INTEGER NOT NULL,   -- sacred floor
    pressure_trigger_bytes INTEGER,            -- NULL = flat (no pressure gate)
    pressure_target_bytes  INTEGER,            -- NULL = flat
    interval_secs          INTEGER NOT NULL,   -- sweeper cadence (advisory; scheduler honours)
    updated_at             TEXT NOT NULL       -- RFC-3339 UTC
);
CREATE TABLE "cirislens_derived_detection_events" (
    detection_id                 TEXT PRIMARY KEY,

    -- V080: PII-linkage columns relaxed to NULLABLE so the Art. 17
    -- tombstone can NULL them (were NOT NULL in V040).
    trace_id                     TEXT,
    body_sha256                  BLOB,

    detector                     TEXT NOT NULL,
    severity                     TEXT NOT NULL,

    cohort_cell                  TEXT NOT NULL,
    conformity_variant           TEXT NOT NULL,
    conformity_payload           TEXT NOT NULL,

    lens_core_version            TEXT NOT NULL,
    ratchet_calibration_version  INTEGER NOT NULL,

    -- V080: relaxed to NULLABLE (tombstone NULLs it).
    canonical_bytes              BLOB,
    ed25519_sig                  BLOB NOT NULL,
    ml_dsa_65_sig                BLOB NOT NULL,
    signing_key_id               TEXT NOT NULL,

    ts                           TEXT NOT NULL,

    -- V080 (CIRISPersist#222) — Art. 17 tombstone marker.
    erased_at                    TEXT, attestation_id TEXT
        REFERENCES federation_attestations(attestation_id) ON DELETE CASCADE,

    CONSTRAINT detection_events_severity_known
        CHECK (severity IN ('info', 'warning', 'critical')),
    CONSTRAINT detection_events_conformity_variant_known
        CHECK (conformity_variant IN ('numeric', 'indeterminate', 'unavailable')),
    CONSTRAINT detection_events_body_sha256_correct_length
        CHECK (length(body_sha256) = 32),
    CONSTRAINT detection_events_ed25519_sig_correct_length
        CHECK (length(ed25519_sig) = 64),
    CONSTRAINT detection_events_ml_dsa_65_sig_correct_length
        CHECK (length(ml_dsa_65_sig) = 3309),
    CONSTRAINT detection_events_canonical_bytes_bounded
        CHECK (length(canonical_bytes) BETWEEN 1 AND 1048576)
);
CREATE TABLE trace_events_factor_rollup_1h (
    -- TEXT bucket key: strftime('%Y-%m-%dT%H:00:00Z', ts). Stored as the
    -- hour-truncated RFC3339 string so window bounds (also RFC3339 TEXT)
    -- compare lexically.
    bucket_start                       TEXT    NOT NULL,
    agent_id_hash                      TEXT,
    deployment_domain                  TEXT,
    cohort_scope                       TEXT,
    cohort_target_id                   TEXT,

    trace_count                        INTEGER NOT NULL DEFAULT 0,

    csdma_sum                          REAL    NOT NULL DEFAULT 0,
    csdma_n                            INTEGER NOT NULL DEFAULT 0,
    k_eff_sum                          REAL    NOT NULL DEFAULT 0,
    k_eff_n                            INTEGER NOT NULL DEFAULT 0,
    correlation_risk_sum               REAL    NOT NULL DEFAULT 0,
    correlation_risk_n                 INTEGER NOT NULL DEFAULT 0,

    override_trace_count               INTEGER NOT NULL DEFAULT 0,
    fragility_trace_count              INTEGER NOT NULL DEFAULT 0,
    conscience_fail_trace_count        INTEGER NOT NULL DEFAULT 0,
    entropy_fail_trace_count           INTEGER NOT NULL DEFAULT 0,
    coherence_fail_trace_count         INTEGER NOT NULL DEFAULT 0,
    optimization_veto_fail_trace_count INTEGER NOT NULL DEFAULT 0,
    epistemic_humility_fail_trace_count INTEGER NOT NULL DEFAULT 0,

    audit_seq_trace_count              INTEGER NOT NULL DEFAULT 0,
    audit_sig_trace_count              INTEGER NOT NULL DEFAULT 0
);
CREATE TABLE trace_events_factor_rollup_meta (
    id                  INTEGER PRIMARY KEY CHECK (id = 1),
    last_refreshed_ts   TEXT
);
INSERT INTO trace_events_factor_rollup_meta (id, last_refreshed_ts) VALUES (1, NULL);
CREATE TABLE content_manifest (
    content_id              TEXT     NOT NULL,
    corpus_kind             TEXT     NOT NULL,
    manifest_version        INTEGER  NOT NULL,
    n_source                INTEGER  NOT NULL,
    k_repair                INTEGER  NOT NULL,
    symbol_size             INTEGER  NOT NULL,
    original_content_length INTEGER  NOT NULL,
    min_viable_symbols      INTEGER  NOT NULL,
    symbol_hashes           TEXT     NOT NULL,  -- JSON array of hex strings
    envelope                TEXT     NOT NULL,  -- corpus's opaque signed header (JSON)
    signature               TEXT     NOT NULL,  -- Ed25519 b64 (classical)
    signature_ml_dsa_65     TEXT     NOT NULL,  -- ML-DSA-65 b64 (REQUIRED, #225 hard cut)
    pqc_key_id              TEXT     NOT NULL,
    admitted_at             TEXT     NOT NULL,  -- ISO-8601 UTC
    PRIMARY KEY (content_id, corpus_kind)
);
CREATE TABLE content_symbols (
    content_id         TEXT     NOT NULL,
    symbol_id          INTEGER  NOT NULL,
    retention_priority INTEGER  NOT NULL,  -- u8 on the wire; eviction key
    symbol_bytes       BLOB     NOT NULL,
    PRIMARY KEY (content_id, symbol_id)
);
CREATE TABLE wholeness_witness_corpus (
    peer_id             TEXT     NOT NULL,
    epoch_id            INTEGER  NOT NULL,  -- per-peer monotonic (N4)
    observed_at_unix_ms INTEGER  NOT NULL,
    claim_namespaces    TEXT     NOT NULL,  -- JSON array (WW-2-filtered)
    merkle_root         TEXT     NOT NULL,  -- lowercase hex (64 chars)
    leaf_count          INTEGER  NOT NULL,
    witness_version     INTEGER  NOT NULL,
    signature           TEXT     NOT NULL,  -- Ed25519 b64 (classical)
    signature_ml_dsa_65 TEXT     NOT NULL,  -- ML-DSA-65 b64 (REQUIRED)
    pqc_key_id          TEXT     NOT NULL,
    admitted_at         TEXT     NOT NULL,  -- ISO-8601 UTC
    PRIMARY KEY (peer_id, epoch_id, observed_at_unix_ms)
);
CREATE TABLE content_aggregation (
    aggregate_content_id  TEXT    NOT NULL,
    source_corpus_kind    TEXT    NOT NULL,
    aggregation_level     INTEGER NOT NULL,  -- BIGINT on PG
    fan_in                INTEGER NOT NULL,  -- BIGINT on PG
    member_commitment     TEXT    NOT NULL,  -- Merkle root (hex); stored, not verified this cut
    aggregation_meta      BLOB    NOT NULL,  -- OPAQUE §19.7 wire payload; never parsed (BYTEA on PG)
    aggregated_at_unix_ms INTEGER NOT NULL,  -- epoch ms
    PRIMARY KEY (aggregate_content_id)
);
CREATE TABLE federation_scope_blobs (
    -- FSD §2.4 HMAC-SHA3-256 record identifier (32 bytes).
    record_id        BLOB NOT NULL,
    -- 0..N symbol index within the record (N=20 default).
    symbol_index     INTEGER NOT NULL CHECK (symbol_index >= 0),
    -- XChaCha20-Poly1305 nonce (24 bytes, CSPRNG, caller-supplied).
    nonce            BLOB NOT NULL,
    -- Pre-encrypted symbol bytes (opaque to the substrate).
    ciphertext       BLOB NOT NULL,
    -- Poly1305 tag (16 bytes, caller-supplied).
    tag              BLOB NOT NULL,
    -- The community DEK epoch the symbol was sealed under.
    group_dek_epoch  INTEGER NOT NULL CHECK (group_dek_epoch >= 0),
    -- Write wall-clock (ISO8601; audit + secondary eviction tiebreak).
    admitted_at      TEXT NOT NULL,
    -- LRU signal (ISO8601): most-recent read wall-clock. Bumped on read.
    last_accessed_at TEXT NOT NULL,
    PRIMARY KEY (record_id, symbol_index)
);
CREATE TABLE accord_proposal (
    proposal_digest      TEXT PRIMARY KEY,
    family_key_id        TEXT NOT NULL,
    action               TEXT NOT NULL
        CHECK (action IN ('fire', 'roster_change', 'resume')),
    nonce                TEXT NOT NULL,
    window_until         TEXT NOT NULL,            -- RFC-3339
    prior_family_digest  TEXT NOT NULL,
    payload_sha256       TEXT NOT NULL,
    proposal_json        TEXT NOT NULL
        CHECK (json_valid(proposal_json)),
    authority_signature  TEXT
        CHECK (authority_signature IS NULL OR json_valid(authority_signature)),
    persist_row_hash     TEXT NOT NULL,
    created_at           TEXT NOT NULL             -- RFC-3339
);
CREATE TABLE accord_participation (
    proposal_digest      TEXT NOT NULL
        REFERENCES accord_proposal (proposal_digest),
    member_id            TEXT NOT NULL,
    pinned_pubkey        TEXT NOT NULL,
    vote                 TEXT NOT NULL
        CHECK (vote IN ('yes', 'no', 'abstain')),
    window_until         TEXT NOT NULL,            -- RFC-3339
    signed_at            TEXT NOT NULL,            -- RFC-3339 (advisory, C2)
    server_arrival_at    TEXT NOT NULL,            -- RFC-3339 (authoritative, C2)
    participation_json   TEXT NOT NULL
        CHECK (json_valid(participation_json)),
    persist_row_hash     TEXT NOT NULL,
    PRIMARY KEY (proposal_digest, pinned_pubkey)
);
CREATE TABLE accord_decision (
    proposal_digest      TEXT PRIMARY KEY
        REFERENCES accord_proposal (proposal_digest),
    family_key_id        TEXT NOT NULL,
    authorized           INTEGER NOT NULL
        CHECK (authorized IN (0, 1)),
    yes                  INTEGER NOT NULL,
    no                   INTEGER NOT NULL,
    abstain              INTEGER NOT NULL,
    live_set             TEXT NOT NULL
        CHECK (json_valid(live_set)),
    window_until         TEXT NOT NULL,            -- RFC-3339
    decision_json        TEXT NOT NULL
        CHECK (json_valid(decision_json)),
    persist_row_hash     TEXT NOT NULL,
    decided_at           TEXT NOT NULL             -- RFC-3339
);
CREATE TABLE accord_active_halt (
    family_key_id        TEXT PRIMARY KEY,
    active_halt_id       TEXT NOT NULL,
    set_at               TEXT NOT NULL             -- RFC-3339
);
CREATE TABLE storage_budget_installed (
    -- The owner node this budget binds (StorageBudgetV1.node_id).
    node_id       TEXT PRIMARY KEY,
    -- Monotonic revision; higher supersedes, lower/equal is refused
    -- (§Q B3 anti-rollback).
    revision      INTEGER NOT NULL CHECK (revision >= 0),
    -- Epoch keying (CC 5.1).
    epoch_id      TEXT NOT NULL,
    -- Denormalized per-cohort_scope allotments (JSON array; never
    -- self/family — B3 suppression, enforced at verify).
    scopes        TEXT NOT NULL CHECK (json_valid(scopes)),
    -- Denormalized corpus subject_kinds the owner elects to pin (B2-ii).
    pinned_class  TEXT NOT NULL CHECK (json_valid(pinned_class)),
    -- The signed StorageBudgetV1 wire JSON VERBATIM.
    wire          TEXT NOT NULL CHECK (json_valid(wire)),
    -- RFC-3339; caller-supplied for cross-dialect parity.
    installed_at  TEXT NOT NULL
);
CREATE TABLE canonical_role_withdrawal (
    -- The withdrawn canonical node (the `federation_keys.key_id` whose
    -- `canonical` role is tombstoned).
    key_id                    TEXT PRIMARY KEY,
    -- RFC-3339; caller-supplied for cross-dialect parity.
    withdrawn_at              TEXT NOT NULL,
    -- The authorizing accord AccordDecision proposal digest (V091 / #302).
    authority_decision_digest TEXT NOT NULL,
    -- The successor key_id for a SUPERSEDE (old→new link); NULL for a plain
    -- WITHDRAW.
    superseded_by             TEXT,
    -- Substrate row hash (canonical SHA-256 of the stored row).
    persist_row_hash          TEXT NOT NULL
);
CREATE TABLE federation_role_withdrawals (
    -- The withdrawn role token (e.g. `infra:attest` — types::roles::*).
    role                      TEXT NOT NULL,
    -- The `federation_keys.key_id` whose role is tombstoned.
    key_id                    TEXT NOT NULL,
    -- RFC-3339; caller-supplied for cross-dialect parity.
    withdrawn_at              TEXT NOT NULL,
    -- The authorizing accord AccordDecision proposal digest (V091 / #302).
    authority_decision_digest TEXT NOT NULL,
    -- The successor key_id for a SUPERSEDE (old→new link); NULL for a plain
    -- WITHDRAW.
    superseded_by             TEXT,
    -- Substrate row hash (canonical SHA-256 of the stored row).
    persist_row_hash          TEXT NOT NULL,
    PRIMARY KEY (role, key_id)
);
CREATE TABLE attestation_subjects (
    subject_key_id  TEXT NOT NULL,
    dimension       TEXT,                    -- NULL iff the envelope has no dimension
    asserted_at     TEXT NOT NULL,           -- RFC-3339 UTC, copy of parent
    attestation_id  TEXT NOT NULL
        REFERENCES federation_attestations(attestation_id) ON DELETE CASCADE,
    tier            TEXT NOT NULL,           -- 'local' | 'federation', copy of parent
    cohort_scope    TEXT NOT NULL,           -- copy of parent (the §4.3 gate axis)
    PRIMARY KEY (subject_key_id, attestation_id)
);
CREATE TABLE announced_peers (
    key_id                  TEXT PRIMARY KEY,
    pubkey_ed25519_base64   TEXT NOT NULL,
    pubkey_ml_dsa_65_base64 TEXT,             -- announce may carry the PQC half
    -- The identity_type CLAIMED by the announce. Advisory display data only —
    -- unverified, never an authority input.
    claimed_identity_type   TEXT,
    first_seen_at           TEXT NOT NULL,    -- RFC-3339 UTC
    last_seen_at            TEXT NOT NULL,    -- RFC-3339 UTC, refreshed per announce
    announce_count          INTEGER NOT NULL DEFAULT 1
);
CREATE TABLE signed_wire_index (
    kind            TEXT NOT NULL,
    content_hash    TEXT NOT NULL,
    record_key      TEXT NOT NULL,
    PRIMARY KEY (kind, content_hash)
);
CREATE TABLE freshness_floor (
    target_key_id    TEXT NOT NULL,
    target_kind      TEXT NOT NULL,
    fresh_as_of      TEXT NOT NULL,   -- RFC-3339 UTC
    signer_form      TEXT NOT NULL,
    attesting_key_id TEXT NOT NULL,
    signed_envelope  TEXT NOT NULL,   -- byte-exact JSON
    signature        TEXT NOT NULL,   -- hybrid detached sig, byte-exact JSON
    cohort_scope     TEXT NOT NULL,
    PRIMARY KEY (target_key_id, target_kind)
);
CREATE TABLE "cirislens_tickets" (
    ticket_id              TEXT PRIMARY KEY,
    sop                    TEXT NOT NULL,
    ticket_type            TEXT NOT NULL,
    -- v24.1.0 (CIRISPersist#560) — 'proposed' joins the set.
    status                 TEXT NOT NULL
        CHECK (status IN ('proposed', 'pending', 'assigned', 'in_progress',
                          'blocked', 'deferred', 'completed',
                          'cancelled', 'failed')),
    priority               INTEGER NOT NULL DEFAULT 5
        CHECK (priority BETWEEN 1 AND 10),
    email                  TEXT NOT NULL,
    user_identifier        TEXT,
    submitted_at           TEXT NOT NULL,
    deadline               TEXT,
    last_updated           TEXT NOT NULL,
    completed_at           TEXT,
    metadata               TEXT NOT NULL DEFAULT '{}',
    notes                  TEXT,
    automated              INTEGER NOT NULL DEFAULT 0
        CHECK (automated IN (0, 1)),
    correlation_id         TEXT,
    agent_occurrence_id    TEXT NOT NULL DEFAULT '__shared__',
    created_at             TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP
);
CREATE TABLE cirislens_ledger_heads (
    ledger_id           TEXT NOT NULL PRIMARY KEY,
    owner_key_id        TEXT NOT NULL,
    unit                TEXT NOT NULL,
    standard_version    TEXT NOT NULL,
    -- NULL until the first head lands: "registered, no head yet" is a real
    -- state and a sentinel value would collapse it into "head at seq 0".
    seq                 INTEGER,
    head_hash           TEXT,
    witness_anchor_ref  TEXT,
    source_envelope_ref TEXT,
    created_at          TEXT NOT NULL,
    updated_at          TEXT NOT NULL,
    CONSTRAINT ledger_heads_seq_nonneg CHECK (seq IS NULL OR seq >= 0),
    CONSTRAINT ledger_heads_head_pairs CHECK ((seq IS NULL) = (head_hash IS NULL)),
    -- L1: one ledger per (steward-bound identity, unit, standard_version).
    CONSTRAINT ledger_heads_l1_triple UNIQUE (owner_key_id, unit, standard_version)
);
CREATE TABLE cirislens_ledger_checkpoints (
    ledger_id           TEXT NOT NULL REFERENCES cirislens_ledger_heads (ledger_id),
    seq                 INTEGER NOT NULL,
    balance_minor       TEXT NOT NULL,
    witness_refs        TEXT NOT NULL,
    supersedes_ref      TEXT,
    source_envelope_ref TEXT,
    created_at          TEXT NOT NULL,
    CONSTRAINT ledger_checkpoints_seq_nonneg CHECK (seq >= 0),
    PRIMARY KEY (ledger_id, seq)
);
CREATE TABLE cirislens_ledger_entry_ranges (
    ledger_id       TEXT NOT NULL REFERENCES cirislens_ledger_heads (ledger_id),
    from_seq        INTEGER NOT NULL,
    to_seq          INTEGER NOT NULL,
    blob_ref        TEXT NOT NULL,
    head_hash_at_to TEXT NOT NULL,
    created_at      TEXT NOT NULL,
    CONSTRAINT ledger_entry_ranges_from_nonneg CHECK (from_seq >= 0),
    CONSTRAINT ledger_entry_ranges_ordered CHECK (to_seq >= from_seq),
    PRIMARY KEY (ledger_id, from_seq)
);
CREATE TABLE cirislens_ledger_fork_evidence (
    evidence_id   TEXT NOT NULL PRIMARY KEY,
    ledger_id     TEXT NOT NULL,
    seq           INTEGER NOT NULL,
    fork_kind     TEXT NOT NULL,
    evidence_json TEXT NOT NULL,
    detected_at   TEXT NOT NULL,
    CONSTRAINT ledger_fork_evidence_seq_nonneg CHECK (seq >= 0),
    CONSTRAINT ledger_fork_evidence_kind CHECK (fork_kind IN ('double_head', 'witness_contradiction'))
);
CREATE TABLE cirislens_key_escrows (
    escrow_id  TEXT NOT NULL PRIMARY KEY,
    key_id     TEXT NOT NULL,
    org_id     TEXT NOT NULL,
    escrow_type TEXT NOT NULL,
    custodian  TEXT NOT NULL,
    status     TEXT NOT NULL,
    created_at TEXT NOT NULL,
    expires_at TEXT,
    CONSTRAINT key_escrows_type CHECK (escrow_type IN ('steward', 'attorney', 'dual_custody')),
    CONSTRAINT key_escrows_status CHECK (status IN ('active', 'recovered', 'revoked', 'expired'))
);
CREATE TABLE known_wire_hashes (
    kind                TEXT NOT NULL,
    content_hash        TEXT NOT NULL,
    last_advertised_at  TEXT NOT NULL,
    advertised_by       TEXT,
    PRIMARY KEY (kind, content_hash)
);
CREATE TABLE trace_thought_signatures (
    thought_id           TEXT PRIMARY KEY,
    signature_ml_dsa_65  TEXT NOT NULL,
    pqc_key_id           TEXT
);
CREATE TABLE cirislens_tasks (
    task_id               TEXT PRIMARY KEY,
    channel_id            TEXT NOT NULL,
    description           TEXT NOT NULL,
    -- v41.2.0 (CIRISPersist#810) — 'rejected' joins the set.
    status                TEXT NOT NULL
        CHECK (status IN ('pending', 'active', 'completed',
                          'failed', 'cancelled', 'deferred',
                          'rejected')),
    priority              INTEGER NOT NULL DEFAULT 0,
    created_at            TEXT NOT NULL,
    updated_at            TEXT NOT NULL,
    parent_task_id        TEXT,
    context_json          TEXT,
    outcome_json          TEXT,
    retry_count           INTEGER NOT NULL DEFAULT 0
        CHECK (retry_count >= 0),
    signed_by             TEXT,
    signature             TEXT,
    signed_at             TEXT,
    updated_info_available INTEGER NOT NULL DEFAULT 0,
    updated_info_content  TEXT,
    agent_occurrence_id   TEXT NOT NULL DEFAULT 'default',
    images_json           TEXT,
    FOREIGN KEY (parent_task_id) REFERENCES cirislens_tasks(task_id)
);
CREATE TABLE federation_keys (
    key_id                    TEXT PRIMARY KEY,
    pubkey_ed25519_base64     TEXT NOT NULL,
    pubkey_ml_dsa_65_base64   TEXT,
    algorithm                 TEXT NOT NULL CHECK (algorithm = 'hybrid'),
    identity_type             TEXT NOT NULL,
    identity_ref              TEXT NOT NULL,
    valid_from                TEXT NOT NULL,
    valid_until               TEXT,
    registration_envelope     TEXT NOT NULL,
    original_content_hash      BLOB NOT NULL,
    scrub_signature_classical  TEXT NOT NULL,
    scrub_signature_pqc        TEXT,
    scrub_key_id               TEXT NOT NULL,
    scrub_timestamp            TEXT NOT NULL,
    pqc_completed_at           TEXT,
    persist_row_hash           TEXT NOT NULL,
    consent_role               TEXT NOT NULL DEFAULT 'unregistered',
    trust_type                 TEXT NOT NULL DEFAULT 'temporary',
    trust_relationship         TEXT NOT NULL DEFAULT 'direct',
    trust_domains              TEXT,
    trusted_at                 TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP,
    trusted_by                 TEXT,
    expires_at                 TEXT,
    roles                      TEXT,
    attestation_evidence       TEXT,
    additional_scrubs          TEXT NOT NULL DEFAULT '[]',
    -- CIRISPersist#828 — NOT NULL, as on postgres since V126.
    admitted_at                TEXT NOT NULL,
    mutated_at                 TEXT, attestation_id TEXT
        REFERENCES federation_attestations(attestation_id) ON DELETE SET NULL,
    FOREIGN KEY (scrub_key_id) REFERENCES federation_keys(key_id) DEFERRABLE INITIALLY DEFERRED
);
CREATE TABLE federation_attestations (
    attestation_id        TEXT PRIMARY KEY,
    attesting_key_id      TEXT NOT NULL REFERENCES federation_keys(key_id),
    attested_key_id       TEXT NOT NULL,
    attestation_type      TEXT NOT NULL,
    weight                REAL,
    asserted_at           TEXT NOT NULL,
    expires_at            TEXT,
    attestation_envelope  TEXT NOT NULL,
    original_content_hash      BLOB NOT NULL,
    scrub_signature_classical  TEXT NOT NULL,
    scrub_signature_pqc        TEXT,
    scrub_key_id               TEXT NOT NULL REFERENCES federation_keys(key_id),
    scrub_timestamp            TEXT NOT NULL,
    pqc_completed_at           TEXT,
    persist_row_hash           TEXT NOT NULL,
    subject_key_ids            TEXT NOT NULL DEFAULT '[]'
        CHECK (json_valid(subject_key_ids)
               AND json_type(subject_key_ids) = 'array'),
    withdraws_admission_rule   INTEGER
        CHECK (withdraws_admission_rule IS NULL
               OR withdraws_admission_rule BETWEEN 1 AND 5),
    cohort_scope               TEXT NOT NULL DEFAULT 'federation'
        CHECK (cohort_scope IN (
            'self', 'family', 'community',
            'affiliations', 'species', 'biosphere', 'federation'
        )),
    tier                       TEXT NOT NULL DEFAULT 'federation'
        CHECK (tier IN ('local', 'federation')),
    promoted_at                TEXT,
    additional_scrubs          TEXT NOT NULL DEFAULT '[]'
        CHECK (json_valid(additional_scrubs)
               AND json_type(additional_scrubs) = 'array'),
    dimension                  TEXT
        GENERATED ALWAYS AS (json_extract(attestation_envelope, '$.dimension')) VIRTUAL,
    -- CIRISPersist#828 — NOT NULL, as on postgres since V130.
    admitted_at                TEXT NOT NULL
, cohort_target TEXT
        GENERATED ALWAYS AS (
            COALESCE(
                json_extract(attestation_envelope, '$.community_id'),
                json_extract(attestation_envelope, '$.community_key_id'),
                json_extract(attestation_envelope, '$.cohort_key_id'),
                json_extract(attestation_envelope, '$.family_key_id')
            )
        ) VIRTUAL);
CREATE TABLE federation_identity_occurrences (
    identity_key_id       TEXT NOT NULL
        REFERENCES federation_keys(key_id),
    occurrence_key_id     TEXT NOT NULL
        REFERENCES federation_keys(key_id),
    device_class          TEXT NOT NULL
        CHECK (device_class IN ('phone', 'laptop', 'server', 'embedded',
                                 'agent', 'service')),
    hardware_attestation  TEXT,
    asserted_at           TEXT NOT NULL,
    valid_until           TEXT,
    persist_row_hash      TEXT NOT NULL,
    pubkey_x25519_base64      TEXT,
    pubkey_ml_kem_768_base64  TEXT,
    attesting_key_id      TEXT,
    signed_envelope       TEXT,
    signature             TEXT,
    transport_binding     TEXT,
    -- CIRISPersist#828 — NOT NULL, as on postgres since V130.
    admitted_at           TEXT NOT NULL, attestation_id TEXT
        REFERENCES federation_attestations(attestation_id) ON DELETE SET NULL,
    PRIMARY KEY (identity_key_id, occurrence_key_id)
);
CREATE TABLE federation_identity_occurrence_revocations (
    identity_key_id     TEXT NOT NULL REFERENCES federation_keys(key_id),
    occurrence_key_id   TEXT NOT NULL REFERENCES federation_keys(key_id),
    revoked_at          TEXT NOT NULL,
    effective_at        TEXT NOT NULL,
    reason              TEXT,
    witness_set         TEXT NOT NULL DEFAULT '[]'
        CHECK (json_valid(witness_set) AND json_type(witness_set) = 'array'),
    persist_row_hash    TEXT NOT NULL,
    attesting_key_id    TEXT,
    signed_envelope     TEXT,
    signature           TEXT,
    -- CIRISPersist#828 — NOT NULL, as on postgres since V130.
    admitted_at         TEXT NOT NULL, legacy_framed INTEGER NOT NULL DEFAULT 0 CHECK (legacy_framed IN (0, 1)),
    PRIMARY KEY (identity_key_id, occurrence_key_id)
);
CREATE TABLE federation_location_proofs (
    subject_key_id        TEXT NOT NULL REFERENCES federation_keys(key_id),
    cell_id               TEXT NOT NULL,
    cell_resolution       INTEGER NOT NULL
        CHECK (cell_resolution BETWEEN 0 AND 15),
    asserted_at           TEXT NOT NULL,
    valid_until           TEXT,
    attestation_evidence  BLOB,
    withdrawn_at          TEXT,
    persist_row_hash      TEXT NOT NULL,
    authority_key_id      TEXT,
    scrub_signature_classical TEXT,
    scrub_signature_pqc   TEXT,
    -- CIRISPersist#828 — NOT NULL, as on postgres since V130.
    admitted_at           TEXT NOT NULL,
    PRIMARY KEY (subject_key_id, asserted_at)
);
CREATE TABLE federation_families (
    family_key_id                   TEXT PRIMARY KEY,
    family_name                     TEXT NOT NULL,
    members                         TEXT NOT NULL DEFAULT '[]'
        CHECK (json_type(members) = 'array'),
    founded_at                      TEXT NOT NULL,
    consensus_protocol              TEXT NOT NULL,
    consensus_protocol_entrenched   INTEGER NOT NULL DEFAULT 0
        CHECK (consensus_protocol_entrenched IN (0, 1)),
    persist_row_hash                TEXT NOT NULL,
    version                         INTEGER NOT NULL DEFAULT 1,
    authority_key_id                TEXT,
    scrub_signature_classical       TEXT,
    scrub_signature_pqc             TEXT,
    -- CIRISPersist#828 — NOT NULL, as on postgres since V130.
    admitted_at                     TEXT NOT NULL
, supersede_proof TEXT, cosignatures TEXT NOT NULL DEFAULT '[]', dissolved_at TEXT NULL, prev_head_digest TEXT NOT NULL DEFAULT '', charter_digest TEXT NOT NULL DEFAULT '', attestation_id TEXT
        REFERENCES federation_attestations(attestation_id) ON DELETE SET NULL);
CREATE TABLE transport_destinations (
    occurrence_key_id               TEXT NOT NULL,
    transport_kind                  TEXT NOT NULL,
    destination                     TEXT NOT NULL,
    asserted_at                     TEXT NOT NULL,
    last_seen_at                    TEXT,
    transport_ed25519_pubkey_base64 TEXT,
    transport_x25519_pubkey_base64  TEXT,
    binding_provenance              TEXT NOT NULL DEFAULT 'rooted',
    epoch                           INTEGER NOT NULL DEFAULT 0,
    retired_at                      TEXT,
    attesting_key_id                TEXT,
    signed_envelope                 TEXT,
    signature                       TEXT,
    -- CIRISPersist#828 — NOT NULL, as on postgres since V130.
    admitted_at                     TEXT NOT NULL,
    PRIMARY KEY (occurrence_key_id, transport_kind)
);
CREATE TABLE federation_streams (
    stream_id          TEXT NOT NULL PRIMARY KEY,
    cohort_scope       TEXT NOT NULL,
    community_key_id   TEXT NULL,
    owner_key_id       TEXT NULL,
    created_at         TEXT NOT NULL DEFAULT (strftime('%Y-%m-%d %H:%M:%f', 'now'))
, abandoned_at TEXT NULL);
CREATE TABLE federation_community_dek_epoch (
    community_key_id    TEXT NOT NULL,
    minter_key_id       TEXT NOT NULL,
    epoch               INTEGER NOT NULL DEFAULT 0 CHECK (epoch >= 0),
    rotated_at          TEXT NOT NULL DEFAULT (strftime('%Y-%m-%d %H:%M:%f', 'now')),
    retain_past_epochs  INTEGER
        CHECK (retain_past_epochs IS NULL OR retain_past_epochs >= 0),
    PRIMARY KEY (community_key_id, minter_key_id)
);
CREATE TABLE federation_community_dek (
    community_key_id  TEXT NOT NULL,
    minter_key_id     TEXT NOT NULL,
    epoch             INTEGER NOT NULL CHECK (epoch >= 0),
    wrap_algorithm    TEXT NOT NULL
        CHECK (wrap_algorithm IN ('aes256_gcm_content_master')),
    -- NULL iff key_state = 'destroyed': the material is gone (V139).
    wrapped_dek       TEXT,
    created_at        TEXT NOT NULL DEFAULT (strftime('%Y-%m-%d %H:%M:%f', 'now')),
    -- §15 — when THIS minter minted the DEK. A removal admitted after this
    -- instant rotates the minter's counter before its next seal.
    minted_at         TEXT NOT NULL DEFAULT (strftime('%Y-%m-%d %H:%M:%f', 'now')),
    key_state         TEXT NOT NULL DEFAULT 'enabled'
        CHECK (key_state IN ('enabled', 'disabled', 'destroyed')), key_grant_emitted_at TEXT,
    CHECK ((key_state = 'destroyed') = (wrapped_dek IS NULL)),
    PRIMARY KEY (community_key_id, minter_key_id, epoch)
);
CREATE TABLE federation_community_dek_member_grants (
    community_key_id      TEXT NOT NULL,
    minter_key_id         TEXT NOT NULL,
    epoch                 INTEGER NOT NULL CHECK (epoch >= 0),
    member_key_id         TEXT NOT NULL,
    wrap_algorithm        TEXT NOT NULL
        CHECK (wrap_algorithm IN ('x25519_mlkem768_aes256_gcm_hkdf_sha256')),
    wrapped_dek           TEXT NOT NULL,
    created_at            TEXT NOT NULL DEFAULT (strftime('%Y-%m-%d %H:%M:%f', 'now')),
    PRIMARY KEY (community_key_id, minter_key_id, epoch, member_key_id)
);
CREATE TABLE federation_community_blob_epoch (
    at_rest_sha256    BLOB PRIMARY KEY
        CHECK (length(at_rest_sha256) = 32),
    community_key_id  TEXT NOT NULL,
    minter_key_id     TEXT NOT NULL,
    epoch             INTEGER NOT NULL CHECK (epoch >= 0),
    created_at        TEXT NOT NULL DEFAULT (strftime('%Y-%m-%d %H:%M:%f', 'now')),
    evicted_at        TEXT
);
CREATE TABLE federation_key_grant_pending (
    at_rest_sha256   BLOB NOT NULL CHECK (length(at_rest_sha256) = 32),
    cohort_scope     TEXT NOT NULL,
    attestation_id   TEXT NOT NULL,
    signer_key_id    TEXT NOT NULL,
    created_at       TEXT NOT NULL DEFAULT (strftime('%Y-%m-%d %H:%M:%f', 'now')),
    PRIMARY KEY (at_rest_sha256, cohort_scope, attestation_id)
);
CREATE TABLE consent_peer_set_for (
    author_key_id           TEXT NOT NULL,
    for_key_id              TEXT NOT NULL,
    peer_key_id             TEXT NOT NULL,
    source_attestation_id   TEXT NOT NULL,
    asserted_at             TEXT NOT NULL,   -- RFC-3339 UTC
    PRIMARY KEY (author_key_id, for_key_id, peer_key_id)
);
CREATE TABLE federation_key_registration_history (
    history_id                 INTEGER PRIMARY KEY AUTOINCREMENT,
    key_id                     TEXT NOT NULL,
    registration_envelope      TEXT NOT NULL,
    original_content_hash      BLOB NOT NULL,
    scrub_signature_classical  TEXT NOT NULL,
    scrub_signature_pqc        TEXT,
    scrub_key_id               TEXT NOT NULL,
    scrub_timestamp            TEXT NOT NULL,   -- RFC-3339 UTC, the replaced record's own
    replaced_at                TEXT NOT NULL,   -- RFC-3339 UTC, THIS node's mutation instant
    replaced_by_hash           TEXT NOT NULL    -- persist_row_hash of the record that replaced it
, replaced_row_hash TEXT, replacement_kind TEXT NOT NULL DEFAULT 'rebind'
        CHECK (replacement_kind IN ('rebind', 'invalid_replaced')));
CREATE TABLE blob_renditions (
    rendition_sha256        BLOB PRIMARY KEY,    -- the rendition blob's digest
    original_sha256         BLOB NOT NULL,       -- `media.derived_from`
    format                  TEXT NOT NULL,       -- RFC 6838 essence, as declared
    size                    INTEGER NOT NULL,    -- bytes (CC 5.3.2.5)
    width                   INTEGER,
    height                  INTEGER,
    role                    TEXT NOT NULL,       -- thumbnail|poster|transcode|caption_track|other
    source_attestation_id   TEXT NOT NULL,
    cohort_scope            TEXT NOT NULL
);
CREATE TABLE "federation_community_membership_revocations" (
    community_key_id         TEXT NOT NULL REFERENCES federation_communities(community_key_id),
    removed_identity_key_id  TEXT NOT NULL REFERENCES federation_keys(key_id),
    removed_at               TEXT NOT NULL,
    effective_at             TEXT NOT NULL,
    reason                   TEXT,
    witness_set              TEXT NOT NULL DEFAULT '[]'
        CHECK (json_valid(witness_set) AND json_type(witness_set) = 'array'),
    persist_row_hash         TEXT NOT NULL,
    authority_key_id         TEXT,
    scrub_signature_classical TEXT,
    scrub_signature_pqc      TEXT,
    admitted_at              TEXT NOT NULL, cosignatures TEXT NOT NULL DEFAULT '[]', attestation_id TEXT
        REFERENCES federation_attestations(attestation_id) ON DELETE SET NULL,
    PRIMARY KEY (community_key_id, removed_identity_key_id, effective_at)
);
CREATE TABLE federation_community_membership_widenings (
    community_key_id          TEXT NOT NULL REFERENCES federation_communities(community_key_id),
    member_key_id             TEXT NOT NULL REFERENCES federation_keys(key_id),
    joined_at                 TEXT NOT NULL,
    effective_at              TEXT NOT NULL,
    role                      TEXT,
    persist_row_hash          TEXT NOT NULL,
    authority_key_id          TEXT,
    scrub_signature_classical TEXT,
    scrub_signature_pqc       TEXT,
    admitted_at               TEXT NOT NULL, cosignatures TEXT NOT NULL DEFAULT '[]', attestation_id TEXT
        REFERENCES federation_attestations(attestation_id) ON DELETE SET NULL,
    PRIMARY KEY (community_key_id, member_key_id, effective_at)
);
CREATE TABLE "consent_peer_set" (
    node_key_id             TEXT NOT NULL,
    for_key_id              TEXT NOT NULL,
    peer_key_id             TEXT NOT NULL,
    source_attestation_id   TEXT NOT NULL,
    asserted_at             TEXT NOT NULL,
    PRIMARY KEY (node_key_id, for_key_id, peer_key_id)
);
CREATE TABLE "federation_family_membership_revocations" (
    family_key_id            TEXT NOT NULL REFERENCES federation_families(family_key_id),
    removed_identity_key_id  TEXT NOT NULL REFERENCES federation_keys(key_id),
    removed_at               TEXT NOT NULL,
    effective_at             TEXT NOT NULL,
    reason                   TEXT,
    witness_set              TEXT NOT NULL DEFAULT '[]'
        CHECK (json_valid(witness_set) AND json_type(witness_set) = 'array'),
    persist_row_hash         TEXT NOT NULL,
    authority_key_id         TEXT,
    scrub_signature_classical TEXT,
    scrub_signature_pqc      TEXT,
    admitted_at              TEXT NOT NULL,
    cosignatures             TEXT NOT NULL DEFAULT '[]', attestation_id TEXT
        REFERENCES federation_attestations(attestation_id) ON DELETE SET NULL,
    PRIMARY KEY (family_key_id, removed_identity_key_id, effective_at)
);
CREATE TABLE federation_family_membership_widenings (
    family_key_id             TEXT NOT NULL REFERENCES federation_families(family_key_id),
    member_key_id             TEXT NOT NULL REFERENCES federation_keys(key_id),
    joined_at                 TEXT NOT NULL,
    effective_at              TEXT NOT NULL,
    role                      TEXT,
    persist_row_hash          TEXT NOT NULL,
    authority_key_id          TEXT,
    scrub_signature_classical TEXT,
    scrub_signature_pqc       TEXT,
    admitted_at               TEXT NOT NULL,
    cosignatures              TEXT NOT NULL DEFAULT '[]', attestation_id TEXT
        REFERENCES federation_attestations(attestation_id) ON DELETE SET NULL,
    PRIMARY KEY (family_key_id, member_key_id, effective_at)
);
CREATE TABLE federation_withdraws_admission_depths (
    attestation_id TEXT PRIMARY KEY,
    depth          INTEGER NOT NULL CHECK (depth BETWEEN 0 AND 16)
);
CREATE TABLE federation_lineage_head_cosigns (
    lineage_key_id                TEXT NOT NULL,
    head_digest_sha256_hex        TEXT NOT NULL,
    witness_key_id                TEXT NOT NULL,
    head_asserted_at              TEXT NOT NULL,
    prior_head_digest_sha256_hex  TEXT,
    signed_at                     TEXT NOT NULL,
    signature_classical           TEXT NOT NULL,
    signature_pqc                 TEXT,
    admitted_at                   TEXT NOT NULL,
    PRIMARY KEY (lineage_key_id, head_digest_sha256_hex, witness_key_id, signed_at)
);
CREATE TABLE federation_manifest_children (
    root_sha256    BLOB NOT NULL,
    child_index    INTEGER NOT NULL CHECK (child_index >= 0),
    child_sha256   BLOB NOT NULL,
    PRIMARY KEY (root_sha256, child_index)
);
CREATE TABLE federation_identity_occurrence_history (
    identity_key_id     TEXT NOT NULL,
    occurrence_key_id   TEXT NOT NULL,
    asserted_at         TEXT NOT NULL,
    valid_until         TEXT,
    attesting_key_id    TEXT NOT NULL DEFAULT '',
    signed_envelope     TEXT,
    signature           TEXT,
    PRIMARY KEY (identity_key_id, occurrence_key_id, asserted_at, attesting_key_id)
);
CREATE TABLE federation_revocations (
    revocation_id         TEXT PRIMARY KEY,
    revoked_key_id        TEXT,
    revoking_key_id       TEXT NOT NULL REFERENCES federation_keys(key_id),
    reason                TEXT,
    revoked_at            TEXT NOT NULL,
    effective_at          TEXT NOT NULL,
    revocation_envelope   TEXT NOT NULL,
    original_content_hash      BLOB NOT NULL,
    scrub_signature_classical  TEXT NOT NULL,
    scrub_signature_pqc        TEXT,
    scrub_key_id               TEXT NOT NULL REFERENCES federation_keys(key_id),
    scrub_timestamp            TEXT NOT NULL,
    pqc_completed_at           TEXT,
    persist_row_hash           TEXT NOT NULL,
    observed_region            TEXT NOT NULL DEFAULT 'us'
        CHECK (observed_region IN ('us', 'eu', 'apac')),
    revoked_after              TEXT,
    admitted_at                TEXT NOT NULL,
    revoked_key_sha256_ed25519_raw TEXT
        CHECK (revoked_key_sha256_ed25519_raw IS NULL
               OR (length(revoked_key_sha256_ed25519_raw) = 64
                   AND revoked_key_sha256_ed25519_raw NOT GLOB '*[^0-9a-f]*'))
, attestation_id TEXT
        REFERENCES federation_attestations(attestation_id) ON DELETE SET NULL);
CREATE TABLE federation_stream_epoch_counts (
    stream_id    TEXT NOT NULL,
    epoch        INTEGER NOT NULL,
    chunk_count  INTEGER NOT NULL CHECK (chunk_count >= 0),
    PRIMARY KEY (stream_id, epoch)
);
CREATE TABLE federation_trust_direction_held (
    attestation_id TEXT PRIMARY KEY
);
CREATE TABLE federation_dag_chunks (
    manifest_sha256  BLOB NOT NULL CHECK (length(manifest_sha256) = 32),
    seq              INTEGER NOT NULL CHECK (seq >= 0),
    chunk_sha256     BLOB NOT NULL CHECK (length(chunk_sha256) = 32),
    stream_id        TEXT NOT NULL,
    PRIMARY KEY (manifest_sha256, seq)
);
CREATE TABLE federation_group_versions (
    cohort            TEXT NOT NULL
        CHECK (cohort IN ('family', 'community', 'affiliations')),
    group_key_id      TEXT NOT NULL,
    version           INTEGER NOT NULL,
    snapshot          TEXT NOT NULL
        CHECK (json_valid(snapshot)),
    change_authorization TEXT
        CHECK (change_authorization IS NULL OR json_valid(change_authorization)),
    superseded_at     TEXT NOT NULL,    -- RFC-3339
    persist_row_hash  TEXT NOT NULL,
    PRIMARY KEY (cohort, group_key_id, version)
);
CREATE TABLE federation_blob_associations (
    sha256        BLOB NOT NULL CHECK (length(sha256) = 32),
    cohort_scope  TEXT NOT NULL,
    group_key_id  TEXT NOT NULL DEFAULT '',
    PRIMARY KEY (sha256, cohort_scope, group_key_id)
);
CREATE TABLE dag_link_backfill_cursor (
    singleton     INTEGER PRIMARY KEY CHECK (singleton = 1),
    after_sha256  BLOB NULL CHECK (after_sha256 IS NULL OR length(after_sha256) = 32),
    updated_at    TEXT NOT NULL DEFAULT (strftime('%Y-%m-%dT%H:%M:%fZ', 'now'))
);
CREATE TABLE purge_executions (
    notice_id          TEXT PRIMARY KEY CHECK (length(notice_id) = 64 AND notice_id NOT GLOB '*[^0-9a-f]*'),
    selection_digest   TEXT NOT NULL CHECK (length(selection_digest) = 64 AND selection_digest NOT GLOB '*[^0-9a-f]*'),
    claimant_key_id    TEXT NOT NULL CHECK (claimant_key_id <> ''),
    record_count       INTEGER NOT NULL CHECK (record_count >= 0),
    notice_jcs         TEXT NOT NULL,
    cosignatures_json  TEXT NOT NULL,
    executed_by        TEXT NOT NULL,
    origin             TEXT NOT NULL CHECK (origin IN ('local', 'replicated')),
    executed_at        TEXT NOT NULL,
    admitted_at        TEXT NOT NULL DEFAULT (strftime('%Y-%m-%dT%H:%M:%fZ', 'now')),
    finalized_at       TEXT NULL,
    legal_basis        TEXT NOT NULL CHECK (legal_basis <> '')
);
CREATE TABLE purge_tombstones (
    notice_id     TEXT NOT NULL REFERENCES purge_executions (notice_id),
    plane         TEXT NOT NULL CHECK (plane IN ('attestation', 'trace', 'blob')),
    record_ref    TEXT NOT NULL CHECK (record_ref <> ''),
    ordinal       INTEGER NOT NULL CHECK (ordinal >= 0),
    derived_from  TEXT NULL,
    PRIMARY KEY (notice_id, plane, record_ref)
);
CREATE TABLE accord_proposal_nonce_claim (
    family_key_id    TEXT NOT NULL,
    nonce            TEXT NOT NULL,
    proposal_digest  TEXT NOT NULL,
    PRIMARY KEY (family_key_id, nonce)
);
CREATE TABLE federation_stream_deks (
    stream_id             TEXT NOT NULL,
    epoch                 INTEGER NOT NULL CHECK (epoch >= 0),
    owner_key_id          TEXT NOT NULL,
    cohort_scope          TEXT NOT NULL
        CHECK (cohort_scope IN ('self', 'family', 'community', 'affiliations')),
    group_key_id          TEXT NOT NULL,
    self_retention_wrap   TEXT NOT NULL,
    minted_at             TEXT NOT NULL DEFAULT (strftime('%Y-%m-%d %H:%M:%f', 'now')),
    closed_at             TEXT,
    terminated_at         TEXT,
    key_grant_emitted_at  TEXT,
    -- #981 — the caller supplied this epoch's DEK (persist never rolls it).
    supplied              INTEGER NOT NULL DEFAULT 0 CHECK (supplied IN (0, 1)),
    -- #977 — a room stream epoch's place in the room's retention: the
    -- writer's community epoch when the stream epoch was minted. The
    -- community retention sweep evicts the epoch's chunks under the same
    -- policy as the community epoch it names; NULL for self / family.
    room_epoch            INTEGER CHECK (room_epoch IS NULL OR room_epoch >= 0),
    -- #977 — when that sweep evicted the epoch's chunks (the row stays).
    evicted_at            TEXT,
    PRIMARY KEY (stream_id, epoch)
);
CREATE TABLE federation_stream_dek_grants (
    stream_id         TEXT NOT NULL,
    epoch             INTEGER NOT NULL CHECK (epoch >= 0),
    sealer_key_id     TEXT NOT NULL,
    recipient_key_id  TEXT NOT NULL,
    wrap_algorithm    TEXT NOT NULL
        CHECK (wrap_algorithm IN ('x25519_mlkem768_aes256_gcm_hkdf_sha256')),
    wrapped_dek       TEXT NOT NULL,
    cohort_scope      TEXT NOT NULL
        CHECK (cohort_scope IN ('self', 'family', 'community', 'affiliations')),
    created_at        TEXT NOT NULL DEFAULT (strftime('%Y-%m-%d %H:%M:%f', 'now')),
    PRIMARY KEY (stream_id, epoch, sealer_key_id, recipient_key_id)
);
CREATE TABLE federation_self_roster_proposals (
    attestation_id   TEXT PRIMARY KEY
                     REFERENCES federation_attestations(attestation_id) ON DELETE CASCADE,
    identity_key_id  TEXT NOT NULL,
    received_at      TEXT NOT NULL,
    settled_at       TEXT NULL,
    outcome          TEXT NULL,
    CHECK ((settled_at IS NULL) = (outcome IS NULL))
);
CREATE TABLE cirisnode_credits_ledger (
    contributor_id                TEXT NOT NULL,
    domain                        TEXT NOT NULL,
    language                      TEXT NOT NULL,
    subject                       TEXT NOT NULL,
    balance                       TEXT NOT NULL DEFAULT '0',
    last_update_contribution      TEXT,
    last_updated_at               TEXT NOT NULL DEFAULT (strftime('%Y-%m-%d %H:%M:%f', 'now')),
    created_at                    TEXT NOT NULL DEFAULT (strftime('%Y-%m-%d %H:%M:%f', 'now')),
    attestation_id                TEXT
        REFERENCES federation_attestations(attestation_id) ON DELETE CASCADE,
    PRIMARY KEY (contributor_id, domain, language, subject)
);
CREATE TABLE cirisnode_expertise_ledger (
    contributor_id                TEXT NOT NULL,
    domain                        TEXT NOT NULL,
    language                      TEXT NOT NULL,
    expertise                     TEXT NOT NULL DEFAULT '0'
        CHECK (expertise IN ('0', '1') OR (expertise GLOB '0.*[1-9]' AND substr(expertise, 3) NOT GLOB '*[^0-9]*')),
    is_active                     INTEGER NOT NULL DEFAULT 0,
    last_updated_at               TEXT NOT NULL DEFAULT (strftime('%Y-%m-%d %H:%M:%f', 'now')),
    last_update_contribution      TEXT,
    created_at                    TEXT NOT NULL DEFAULT (strftime('%Y-%m-%d %H:%M:%f', 'now')),
    attestation_id                TEXT
        REFERENCES federation_attestations(attestation_id) ON DELETE CASCADE,
    PRIMARY KEY (contributor_id, domain, language)
);
CREATE TABLE cirisnode_scheduled_takedown_actions (
    notice_contribution_id    TEXT NOT NULL PRIMARY KEY,
    scheduled_eviction_at     TEXT NOT NULL,
    status                    TEXT NOT NULL
        CHECK (status IN ('pending', 'evicted', 'counter_noticed', 'expired')),
    inserted_at               TEXT NOT NULL DEFAULT (strftime('%Y-%m-%d %H:%M:%f', 'now'))
);
CREATE TABLE cirisnode_federation_delivery_attestations (
    announcement_id              TEXT NOT NULL,
    announcement_canonical_hash  BLOB NOT NULL
        CHECK (length(announcement_canonical_hash) = 32),
    peer_key_id                  TEXT NOT NULL,
    received_at                  TEXT NOT NULL,
    transport_id                 TEXT NOT NULL
        CHECK (transport_id IN ('reticulum', 'tcp_tls', 'http_over_tls', 'other')),
    signature_composite          BLOB NOT NULL
        CHECK (length(signature_composite) = 3373),
    inserted_at                  TEXT NOT NULL DEFAULT (strftime('%Y-%m-%d %H:%M:%f', 'now')),
    signature_verified           INTEGER NOT NULL DEFAULT 0,
    persist_row_hash             TEXT NOT NULL,
    PRIMARY KEY (announcement_id, peer_key_id)
);
CREATE TABLE goals (
    goal_id                TEXT    PRIMARY KEY,
    declared_by_key_id     TEXT    NOT NULL
        REFERENCES federation_keys(key_id) ON DELETE RESTRICT,
    declared_at            TEXT    NOT NULL,
    goal_text              TEXT    NOT NULL,
    goal_text_canonical    TEXT    NOT NULL,
    scale                  TEXT    NOT NULL,
    scope_cohort_id        TEXT,
    meta_dimension         TEXT    NOT NULL
        CHECK (meta_dimension IN (
            'adaptivity', 'coherence', 'flourishing', 'justice',
            'plurality', 'sustainability', 'wonder'
        )),
    meta_rationale         TEXT    NOT NULL,
    meta_deliberation      TEXT,
    retired_at             TEXT,
    persist_row_hash       TEXT    NOT NULL,
    attestation_id         TEXT
        REFERENCES federation_attestations(attestation_id) ON DELETE CASCADE,
    score                  REAL,
    CONSTRAINT goals_scope_cohort_discriminant CHECK (
        (scale = 'cohort' AND scope_cohort_id IS NOT NULL)
        OR (scale <> 'cohort' AND scope_cohort_id IS NULL)
    ),
    CONSTRAINT goals_projection_row CHECK (
        (attestation_id IS NULL AND score IS NULL)
        OR (attestation_id IS NOT NULL AND score IS NOT NULL)
    )
);
CREATE TABLE federation_communities (
    community_key_id      TEXT PRIMARY KEY,
    community_name        TEXT NOT NULL,
    members               TEXT NOT NULL,
    founded_at            TEXT NOT NULL,
    consensus_protocol    TEXT NOT NULL,
    policy_blob           TEXT,
    persist_row_hash      TEXT NOT NULL,
    version               INTEGER NOT NULL DEFAULT 1,
    authority_key_id           TEXT,
    scrub_signature_classical  TEXT,
    scrub_signature_pqc        TEXT,
    -- CIRISPersist#828 — NOT NULL, as on postgres since V130.
    admitted_at                TEXT NOT NULL,
    supersede_proof            TEXT,
    cosignatures               TEXT NOT NULL DEFAULT '[]',
    lineage                    TEXT NOT NULL DEFAULT '[]',
    prev_head_digest           TEXT NOT NULL DEFAULT '',
    charter_digest             TEXT NOT NULL DEFAULT '',
    attestation_id             TEXT
        REFERENCES federation_attestations(attestation_id) ON DELETE SET NULL,
    CHECK (consensus_protocol GLOB 'founder_only'
        OR consensus_protocol GLOB 'unanimous'
        OR consensus_protocol GLOB 'majority'
        -- v61 (CIRISPersist#1123) — a public room's open admission.
        OR consensus_protocol = 'open:self_admit'
        OR consensus_protocol GLOB 'quorum:*/*'
        OR consensus_protocol GLOB 'reverse_quorum:*/*:*'
        OR consensus_protocol GLOB 'weighted:?*'
        OR consensus_protocol GLOB 'custom:?*')
);
CREATE TABLE federation_attestations_form_refused (
    attestation_id   TEXT PRIMARY KEY,
    attesting_key_id TEXT NOT NULL,
    persist_row_hash TEXT NOT NULL,
    refused_member   TEXT NOT NULL,
    refused_value    TEXT NOT NULL,
    refused_at       TEXT NOT NULL
);
CREATE TABLE federation_vote_windows (
    action_id      TEXT PRIMARY KEY,
    first_held_at  TEXT NOT NULL
);
CREATE TABLE federation_cosign_pending (
    quorum_key       TEXT PRIMARY KEY,
    group_kind       TEXT NOT NULL CHECK (group_kind IN ('family', 'community')),
    group_key_id     TEXT NOT NULL,
    proposer_key_id  TEXT NOT NULL,
    received_at      TEXT NOT NULL,
    settled_at       TEXT NULL,
    outcome          TEXT NULL,
    CHECK ((settled_at IS NULL) = (outcome IS NULL))
);
CREATE TABLE federation_cosign_signatures (
    attestation_id   TEXT PRIMARY KEY,
    quorum_key       TEXT NOT NULL,
    signer_key_id    TEXT NOT NULL,
    UNIQUE (quorum_key, signer_key_id)
);
CREATE TABLE federation_cosign_aliases (
    alias_attestation_id  TEXT PRIMARY KEY,
    quorum_key            TEXT NOT NULL,
    held_attestation_id   TEXT NOT NULL
);

-- ════ indexs ════
CREATE INDEX trace_events_journey
    ON trace_events (thought_id, ts);
CREATE INDEX trace_events_agent_ts
    ON trace_events (agent_name, ts DESC);
CREATE INDEX trace_events_type_ts
    ON trace_events (event_type, ts DESC);
CREATE INDEX trace_events_audit_seq
    ON trace_events (audit_sequence_number)
    WHERE audit_sequence_number IS NOT NULL;
CREATE INDEX trace_llm_calls_thought
    ON trace_llm_calls (thought_id, ts);
CREATE INDEX trace_llm_calls_parent
    ON trace_llm_calls (parent_event_id);
CREATE INDEX trace_llm_calls_model_ts
    ON trace_llm_calls (model, ts DESC);
CREATE INDEX trace_llm_calls_status_ts
    ON trace_llm_calls (status, ts DESC) WHERE status IS NOT 'ok';
CREATE INDEX trace_events_scrub_key
    ON trace_events (scrub_key_id, ts DESC)
    WHERE scrub_signature IS NOT NULL;
CREATE INDEX trace_events_deployment_domain
    ON trace_events (deployment_domain, ts DESC)
    WHERE deployment_domain IS NOT NULL;
CREATE INDEX trace_events_deployment_type
    ON trace_events (deployment_type, ts DESC)
    WHERE deployment_type IS NOT NULL;
CREATE INDEX trace_events_agent_role
    ON trace_events (agent_role, ts DESC)
    WHERE agent_role IS NOT NULL;
CREATE INDEX trace_events_deployment_trust_mode
    ON trace_events (deployment_trust_mode, ts DESC)
    WHERE deployment_trust_mode IS NOT NULL;
CREATE INDEX edge_outbound_queue_pending_dispatch
    ON edge_outbound_queue (next_attempt_after)
    WHERE status = 'pending';
CREATE INDEX edge_outbound_queue_awaiting_ack_sweep
    ON edge_outbound_queue (transport_delivered_at)
    WHERE status = 'awaiting_ack';
CREATE INDEX edge_outbound_queue_body_sha256_awaiting
    ON edge_outbound_queue (body_sha256)
    WHERE status = 'awaiting_ack';
CREATE INDEX edge_outbound_queue_destination
    ON edge_outbound_queue (destination_key_id, status);
CREATE INDEX edge_outbound_queue_status_enqueued
    ON edge_outbound_queue (status, enqueued_at);
CREATE INDEX edge_outbound_queue_claimed_until_sweep
    ON edge_outbound_queue (claimed_until)
    WHERE status = 'sending';
CREATE INDEX secrets_created_at
    ON cirislens_secrets_secrets (created_at);
CREATE INDEX secrets_sensitivity
    ON cirislens_secrets_secrets (sensitivity_level);
CREATE INDEX secrets_pattern
    ON cirislens_secrets_secrets (detected_pattern);
CREATE INDEX secrets_source_message
    ON cirislens_secrets_secrets (source_message_id)
    WHERE source_message_id IS NOT NULL;
CREATE INDEX access_log_secret_uuid
    ON cirislens_secrets_access_log (secret_uuid)
    WHERE secret_uuid IS NOT NULL;
CREATE INDEX access_log_accessor
    ON cirislens_secrets_access_log (accessor);
CREATE INDEX access_log_created_at
    ON cirislens_secrets_access_log (created_at);
CREATE INDEX access_log_trace_id
    ON cirislens_secrets_access_log (trace_id)
    WHERE trace_id IS NOT NULL;
CREATE INDEX master_key_active
    ON cirislens_secrets_master_key_meta (activated_at)
    WHERE deactivated_at IS NULL;
CREATE INDEX cirislens_pseudonyms_class
    ON cirislens_pseudonyms (class);
CREATE INDEX promotion_attestations_target_kind
    ON cirisnode_promotion_attestations (target_kind);
CREATE INDEX promotion_attestations_attested_by
    ON cirisnode_promotion_attestations (attested_by);
CREATE INDEX promotion_attestations_attested_at
    ON cirisnode_promotion_attestations (attested_at);
CREATE INDEX cirisgraph_nodes_type_scope
    ON cirisgraph_nodes (node_type, scope);
CREATE INDEX cirisgraph_nodes_updated_at
    ON cirisgraph_nodes (updated_at);
CREATE INDEX cirisgraph_edges_source
    ON cirisgraph_edges (source_node_id, scope);
CREATE INDEX cirisgraph_edges_target
    ON cirisgraph_edges (target_node_id, scope);
CREATE INDEX cirisgraph_edges_relationship
    ON cirisgraph_edges (relationship);
CREATE INDEX audit_log_tenant_seq
    ON cirislens_audit_log (tenant_id, sequence_number);
CREATE INDEX audit_log_subject
    ON cirislens_audit_log (subject_kind, subject_id);
CREATE INDEX audit_log_actor
    ON cirislens_audit_log (actor_id);
CREATE INDEX audit_log_recorded_at
    ON cirislens_audit_log (recorded_at);
CREATE INDEX audit_log_action_type
    ON cirislens_audit_log (action_type);
CREATE INDEX telemetry_window
    ON cirisgraph_telemetry_metrics (tenant_id, metric_name, observed_at);
CREATE INDEX telemetry_expires
    ON cirisgraph_telemetry_metrics (expires_at);
CREATE INDEX consolidation_locks_locked_at
    ON cirisgraph_consolidation_locks (locked_at);
CREATE UNIQUE INDEX secrets_content_hmac_key
    ON cirislens_secrets_secrets (content_hmac)
    WHERE content_hmac IS NOT NULL;
CREATE UNIQUE INDEX audit_log_content_hash_key
    ON cirislens_audit_log (content_hash)
    WHERE content_hash IS NOT NULL;
CREATE INDEX tsdb_summary_level_metric_period
    ON cirisgraph_nodes (
        node_type,
        consolidation_level,
        json_extract(attributes, '$.metric_name'),
        json_extract(attributes, '$.period_start')
    )
    WHERE node_type = 'tsdb_summary';
CREATE INDEX edge_detection_events_tenant_observed
    ON edge_detection_events (tenant_id, observed_at DESC);
CREATE INDEX edge_detection_events_subject
    ON edge_detection_events (subject_key_id);
CREATE INDEX edge_detection_events_kind_severity
    ON edge_detection_events (detector_kind, severity);
CREATE INDEX idx_ftg_grantee_purpose ON federation_trust_grants
    (grantee_key, purpose, scope) WHERE revoked_at IS NULL;
CREATE INDEX idx_ftg_granter ON federation_trust_grants (granter_key);
CREATE INDEX idx_ftg_chain ON federation_trust_grants (chain_event_id);
CREATE INDEX idx_ftg_tenant ON federation_trust_grants (tenant_id);
CREATE INDEX idx_merkle_leaves_chain ON merkle_leaves (chain_event_id);
CREATE INDEX idx_merkle_sth_signed_at ON merkle_sth_log (tenant_id, signed_at DESC);
CREATE INDEX incident_open_recent
    ON cirislens_incident_records (tenant_id, state, last_seen_at)
    WHERE state IN ('open', 'investigating', 'recurring');
CREATE INDEX incident_first_seen
    ON cirislens_incident_records (tenant_id, first_seen_at);
CREATE INDEX incident_records_filename_line
    ON cirislens_incident_records (filename, line_number)
    WHERE filename IS NOT NULL;
CREATE INDEX incident_records_source_component
    ON cirislens_incident_records (source_component)
    WHERE source_component IS NOT NULL;
CREATE INDEX service_correlations_service_recency
    ON cirislens_service_correlations
    (agent_occurrence_id, service_type, updated_at DESC);
CREATE INDEX service_correlations_type_time
    ON cirislens_service_correlations
    (correlation_type, timestamp DESC);
CREATE INDEX service_correlations_trace_id
    ON cirislens_service_correlations (trace_id)
    WHERE trace_id IS NOT NULL;
CREATE INDEX service_correlations_parent_span
    ON cirislens_service_correlations (parent_span_id)
    WHERE parent_span_id IS NOT NULL;
CREATE INDEX service_correlations_metric_time
    ON cirislens_service_correlations (metric_name, timestamp DESC)
    WHERE metric_name IS NOT NULL;
CREATE INDEX scheduled_tasks_due
    ON cirislens_scheduled_tasks (agent_occurrence_id, next_trigger_at)
    WHERE next_trigger_at IS NOT NULL
      AND status IN ('PENDING', 'ACTIVE');
CREATE INDEX scheduled_tasks_status_occurrence
    ON cirislens_scheduled_tasks (agent_occurrence_id, status, created_at DESC);
CREATE INDEX scheduled_tasks_origin
    ON cirislens_scheduled_tasks (origin_thought_id);
CREATE INDEX deferral_reports_task
    ON cirislens_deferral_reports (task_id);
CREATE INDEX deferral_reports_thought
    ON cirislens_deferral_reports (thought_id);
CREATE INDEX deferral_reports_active
    ON cirislens_deferral_reports (created_at DESC)
    WHERE resolved_at IS NULL;
CREATE INDEX maintenance_locks_active
    ON cirislens_maintenance_locks (locked_at DESC)
    WHERE locked_by IS NOT NULL;
CREATE INDEX creation_ceremonies_new_agent
    ON cirislens_creation_ceremonies (new_agent_id);
CREATE INDEX creation_ceremonies_creator
    ON cirislens_creation_ceremonies (creator_agent_id, timestamp DESC);
CREATE INDEX creation_ceremonies_wa
    ON cirislens_creation_ceremonies (wise_authority_id, timestamp DESC);
CREATE INDEX creation_ceremonies_timeline
    ON cirislens_creation_ceremonies (timestamp DESC);
CREATE INDEX continuity_awareness_agent_recent
    ON cirislens_continuity_awareness (agent_id, shutdown_timestamp DESC);
CREATE INDEX continuity_awareness_active_session
    ON cirislens_continuity_awareness (agent_id, shutdown_timestamp DESC)
    WHERE is_terminal = 0;
CREATE INDEX feedback_mappings_thought ON cirislens_feedback_mappings (target_thought_id)
    WHERE target_thought_id IS NOT NULL;
CREATE INDEX feedback_mappings_source_message ON cirislens_feedback_mappings (source_message_id)
    WHERE source_message_id IS NOT NULL;
CREATE INDEX feedback_mappings_type_recent ON cirislens_feedback_mappings (feedback_type, created_at DESC)
    WHERE feedback_type IS NOT NULL;
CREATE UNIQUE INDEX wa_cert_jwt_kid ON cirislens_wa_cert (jwt_kid);
CREATE INDEX wa_cert_oauth ON cirislens_wa_cert (oauth_provider, oauth_external_id)
    WHERE oauth_provider IS NOT NULL AND oauth_external_id IS NOT NULL;
CREATE INDEX wa_cert_role_active ON cirislens_wa_cert (role, active) WHERE active = 1;
CREATE INDEX wa_cert_adapter ON cirislens_wa_cert (adapter_id) WHERE adapter_id IS NOT NULL;
CREATE INDEX wa_cert_parent ON cirislens_wa_cert (parent_wa_id) WHERE parent_wa_id IS NOT NULL;
CREATE INDEX thoughts_task_recency
    ON cirislens_thoughts (source_task_id, updated_at DESC);
CREATE INDEX thoughts_status_occurrence
    ON cirislens_thoughts (agent_occurrence_id, status, updated_at DESC);
CREATE INDEX thoughts_parent
    ON cirislens_thoughts (parent_thought_id)
    WHERE parent_thought_id IS NOT NULL;
CREATE INDEX occurrence_registry_identity_live
    ON cirislens_occurrence_registry (identity, expires_at);
CREATE UNIQUE INDEX calibration_bundles_one_current
    ON cirislens_derived_calibration_bundles (is_current)
    WHERE is_current = 1;
CREATE INDEX calibration_bundles_projection_version
    ON cirislens_derived_calibration_bundles
       (projection_version, ratchet_calibration_version DESC);
CREATE INDEX trace_events_agenthash_ts
    ON trace_events (agent_id_hash, ts);
CREATE INDEX trace_events_domain_ts
    ON trace_events (deployment_domain, ts);
CREATE INDEX trace_events_an_csdma
    ON trace_events (
        deployment_domain,
        ts,
        agent_id_hash,
        agent_name,
        json_extract(payload, '$.csdma_plausibility_score')
    )
    WHERE event_type = 'DMA_RESULTS'
          AND json_extract(payload, '$.csdma_plausibility_score') IS NOT NULL;
CREATE INDEX trace_events_an_dsdma
    ON trace_events (
        deployment_domain,
        ts,
        agent_id_hash,
        agent_name,
        json_extract(payload, '$.dsdma_domain_alignment')
    )
    WHERE event_type = 'DMA_RESULTS'
          AND json_extract(payload, '$.dsdma_domain_alignment') IS NOT NULL;
CREATE INDEX trace_events_an_idma_keff
    ON trace_events (
        deployment_domain,
        ts,
        agent_id_hash,
        agent_name,
        json_extract(payload, '$.idma_k_eff')
    )
    WHERE event_type = 'IDMA_RESULT'
          AND json_extract(payload, '$.idma_k_eff') IS NOT NULL;
CREATE INDEX trace_events_an_idma_corr
    ON trace_events (
        deployment_domain,
        ts,
        agent_id_hash,
        agent_name,
        json_extract(payload, '$.idma_correlation_risk')
    )
    WHERE event_type = 'IDMA_RESULT'
          AND json_extract(payload, '$.idma_correlation_risk') IS NOT NULL;
CREATE INDEX trace_events_an_trace_summary
    ON trace_events (trace_id, ts, event_type, agent_id_hash, cost_usd);
CREATE UNIQUE INDEX master_key_one_active
    ON cirislens_secrets_master_key_meta (1)
    WHERE activated_at IS NOT NULL AND deactivated_at IS NULL;
CREATE UNIQUE INDEX federation_trust_grants_tenant_chain
    ON federation_trust_grants (tenant_id, chain_event_id);
CREATE INDEX audit_archives_tenant_range
    ON cirislens_audit_archives (tenant_id, from_ts, to_ts);
CREATE INDEX idx_fpm_trust
    ON federation_peer_metadata (trust)
    WHERE removed_at IS NULL;
CREATE INDEX idx_fpm_alias
    ON federation_peer_metadata (alias)
    WHERE alias IS NOT NULL;
CREATE INDEX idx_blackhole_until
    ON blackhole_rules (until)
    WHERE until IS NOT NULL;
CREATE INDEX idx_identity_canonical_binding_federation_key_id
    ON identity_canonical_binding (federation_key_id);
CREATE INDEX federation_peer_metadata_cohort_scope
    ON federation_peer_metadata (json_extract(policy_blob, '$.cohort_scope'))
    WHERE removed_at IS NULL AND policy_blob IS NOT NULL;
CREATE INDEX federation_revocation_quorum_state_committed
    ON federation_revocation_quorum_state (quorum_reached_at DESC)
    WHERE quorum_reached_at IS NOT NULL;
CREATE INDEX federation_revocation_quorum_state_pending
    ON federation_revocation_quorum_state (revocation_id, quorum_weight);
CREATE INDEX idx_trace_events_v060_repository_stats
ON trace_events (cohort_scope, cohort_target_id, ts, deployment_domain, trace_id);
CREATE INDEX federation_blobs_size_bytes
    ON federation_blobs (size_bytes);
CREATE INDEX federation_blobs_first_seen_at
    ON federation_blobs (first_seen_at DESC);
CREATE INDEX federation_blobs_eviction_score
    ON federation_blobs (last_accessed_at ASC, access_count ASC);
CREATE INDEX federation_stream_chunks_stream_epoch
    ON federation_stream_chunks (stream_id, epoch);
CREATE INDEX federation_stream_sth_stream_size
    ON federation_stream_sth (stream_id, tree_size DESC);
CREATE INDEX federation_stream_delivery_receipts_stream_k
    ON federation_stream_delivery_receipts (stream_id, k);
CREATE INDEX federation_blob_key_grants_by_recipient
    ON federation_blob_key_grants (recipient_key_id);
CREATE INDEX shared_instance_leases_heartbeat_idx
    ON shared_instance_leases (last_heartbeat_at);
CREATE INDEX hard_case_events_by_kind_time
    ON hard_case_events (kind, emitted_at);
CREATE INDEX hard_case_events_by_target
    ON hard_case_events (target_key_id);
CREATE INDEX federation_blob_key_grants_by_scope_recipient
    ON federation_blob_key_grants (cohort_scope, recipient_key_id);
CREATE INDEX detection_events_trace_id
    ON cirislens_derived_detection_events (trace_id);
CREATE INDEX detection_events_body_sha256
    ON cirislens_derived_detection_events (body_sha256);
CREATE INDEX detection_events_detector_ts
    ON cirislens_derived_detection_events (detector, ts DESC);
CREATE INDEX detection_events_erased_at
    ON cirislens_derived_detection_events (erased_at)
    WHERE erased_at IS NOT NULL;
CREATE UNIQUE INDEX trace_events_factor_rollup_1h_key
    ON trace_events_factor_rollup_1h (
        bucket_start,
        COALESCE(agent_id_hash, ''),
        COALESCE(deployment_domain, ''),
        COALESCE(cohort_scope, ''),
        COALESCE(cohort_target_id, '')
    );
CREATE INDEX trace_events_factor_rollup_1h_agent_bucket
    ON trace_events_factor_rollup_1h (agent_id_hash, bucket_start);
CREATE INDEX content_symbols_evict
    ON content_symbols (content_id, retention_priority);
CREATE INDEX wholeness_witness_corpus_peer_recency
    ON wholeness_witness_corpus (peer_id, observed_at_unix_ms DESC);
CREATE INDEX content_aggregation_level_recency
    ON content_aggregation (aggregation_level, aggregated_at_unix_ms);
CREATE INDEX idx_federation_scope_blobs_admitted
    ON federation_scope_blobs (admitted_at ASC);
CREATE INDEX idx_federation_scope_blobs_accessed
    ON federation_scope_blobs (last_accessed_at ASC);
CREATE INDEX accord_proposal_by_anchor
    ON accord_proposal (action, prior_family_digest);
CREATE INDEX accord_proposal_by_family
    ON accord_proposal (family_key_id);
CREATE INDEX accord_participation_by_proposal
    ON accord_participation (proposal_digest);
CREATE UNIQUE INDEX trace_events_dedup_sharded
    ON trace_events (
        shard_key, agent_id_hash, trace_id, thought_id, event_type,
        attempt_index, ts
    );
CREATE INDEX trace_events_shard_backfill
    ON trace_events (event_id)
    WHERE shard_key IS NULL;
CREATE INDEX attestation_subjects_seek
    ON attestation_subjects (subject_key_id, dimension, asserted_at DESC, attestation_id);
CREATE INDEX tickets_sop_status_recency
    ON cirislens_tickets (agent_occurrence_id, sop, status, last_updated DESC);
CREATE INDEX tickets_email_recency
    ON cirislens_tickets (email, last_updated DESC);
CREATE INDEX tickets_due_deadline
    ON cirislens_tickets (status, deadline ASC)
    WHERE status NOT IN ('completed', 'cancelled', 'failed');
CREATE INDEX tickets_correlation
    ON cirislens_tickets (correlation_id)
    WHERE correlation_id IS NOT NULL;
CREATE INDEX accord_proposal_by_payload
    ON accord_proposal (payload_sha256);
CREATE INDEX trace_events_scrub_treatment
    ON trace_events (scrub_applied_trace_level, scrub_model_digest, ts DESC)
    WHERE scrub_ner_ran IS NOT NULL;
CREATE INDEX trace_events_admitted_at
    ON trace_events (admitted_at DESC)
    WHERE admitted_at IS NOT NULL;
CREATE INDEX idx_ledger_heads_owner ON cirislens_ledger_heads (owner_key_id);
CREATE INDEX idx_ledger_entry_ranges_to ON cirislens_ledger_entry_ranges (ledger_id, to_seq);
CREATE INDEX idx_ledger_fork_evidence_ledger ON cirislens_ledger_fork_evidence (ledger_id);
CREATE INDEX idx_key_escrows_org ON cirislens_key_escrows (org_id);
CREATE INDEX idx_key_escrows_key ON cirislens_key_escrows (key_id);
CREATE INDEX known_wire_hashes_age
    ON known_wire_hashes (last_advertised_at);
CREATE INDEX trace_events_pqc_key
    ON trace_events (pqc_key_id, ts DESC);
CREATE INDEX tasks_status_occurrence
    ON cirislens_tasks (agent_occurrence_id, status, updated_at DESC);
CREATE INDEX tasks_channel
    ON cirislens_tasks (channel_id, updated_at DESC);
CREATE INDEX tasks_parent
    ON cirislens_tasks (parent_task_id)
    WHERE parent_task_id IS NOT NULL;
CREATE UNIQUE INDEX tasks_correlation_id_unique
    ON cirislens_tasks (
        agent_occurrence_id,
        json_extract(context_json, '$.correlation_id')
    )
    WHERE context_json IS NOT NULL
      AND json_extract(context_json, '$.correlation_id') IS NOT NULL;
CREATE INDEX federation_keys_identity
    ON federation_keys (identity_type, identity_ref);
CREATE INDEX federation_keys_scrub_key
    ON federation_keys (scrub_key_id);
CREATE INDEX federation_keys_trust_relationship
    ON federation_keys (trust_relationship);
CREATE INDEX federation_keys_expires_at
    ON federation_keys (expires_at);
CREATE INDEX federation_keys_accord_holder_evidence
    ON federation_keys (key_id)
    WHERE identity_type = 'accord_holder';
CREATE INDEX federation_keys_consent_role
    ON federation_keys (consent_role)
    WHERE consent_role <> 'unregistered';
CREATE INDEX federation_keys_serve_position
    ON federation_keys (
        MAX(COALESCE(admitted_at, scrub_timestamp),
            COALESCE(mutated_at, COALESCE(admitted_at, scrub_timestamp))),
        key_id
    );
CREATE INDEX federation_attestations_attested
    ON federation_attestations (attested_key_id, asserted_at DESC);
CREATE INDEX federation_attestations_attesting
    ON federation_attestations (attesting_key_id, asserted_at DESC);
CREATE INDEX federation_attestations_withdraws_admission_rule_idx
    ON federation_attestations (withdraws_admission_rule)
    WHERE withdraws_admission_rule IS NOT NULL;
CREATE INDEX federation_attestations_cohort_scope
    ON federation_attestations (cohort_scope)
    WHERE cohort_scope != 'federation';
CREATE INDEX idx_federation_attestations_v060_by_target
    ON federation_attestations (attested_key_id, cohort_scope, asserted_at DESC);
CREATE INDEX idx_federation_attestations_v060_emitter_scope
    ON federation_attestations (scrub_key_id, cohort_scope);
CREATE INDEX federation_attestations_local_tier
    ON federation_attestations (tier)
    WHERE tier = 'local';
CREATE INDEX federation_attestations_composer_ref
    ON federation_attestations (
        attesting_key_id,
        attestation_type,
        json_extract(attestation_envelope, '$.references_attestation_id')
    );
CREATE INDEX federation_attestations_admitted
    ON federation_attestations
       (COALESCE(admitted_at, promoted_at, asserted_at), attestation_id);
CREATE INDEX federation_attestations_attester_dimension
    ON federation_attestations (attesting_key_id, dimension);
CREATE INDEX federation_identity_occurrences_by_identity
    ON federation_identity_occurrences (identity_key_id);
CREATE INDEX federation_identity_occurrences_by_occurrence_live
    ON federation_identity_occurrences (occurrence_key_id)
    WHERE valid_until IS NULL;
CREATE INDEX federation_identity_occurrences_by_occurrence_all
    ON federation_identity_occurrences (occurrence_key_id);
CREATE INDEX federation_identity_occurrences_admitted
    ON federation_identity_occurrences
       (COALESCE(admitted_at, asserted_at), identity_key_id, occurrence_key_id);
CREATE INDEX federation_identity_occurrence_revocations_effective
    ON federation_identity_occurrence_revocations (effective_at);
CREATE INDEX federation_identity_occurrence_revocations_by_occurrence
    ON federation_identity_occurrence_revocations (occurrence_key_id);
CREATE INDEX federation_identity_occurrence_revocations_admitted
    ON federation_identity_occurrence_revocations
       (COALESCE(admitted_at, revoked_at), identity_key_id, occurrence_key_id);
CREATE INDEX federation_location_proofs_by_subject_live
    ON federation_location_proofs (subject_key_id)
    WHERE withdrawn_at IS NULL;
CREATE INDEX federation_location_proofs_by_cell
    ON federation_location_proofs (cell_id);
CREATE INDEX federation_location_proofs_admitted
    ON federation_location_proofs
       (COALESCE(admitted_at, asserted_at), subject_key_id, persist_row_hash);
CREATE INDEX federation_families_entrenched
    ON federation_families (family_key_id)
    WHERE consensus_protocol_entrenched = 1;
CREATE INDEX federation_families_admitted
    ON federation_families (COALESCE(admitted_at, founded_at), family_key_id);
CREATE INDEX transport_destinations_by_occurrence
    ON transport_destinations (occurrence_key_id);
CREATE INDEX transport_destinations_admitted
    ON transport_destinations
       (COALESCE(admitted_at, asserted_at), occurrence_key_id, transport_kind);
CREATE INDEX federation_community_dek_member_grants_by_member
    ON federation_community_dek_member_grants (member_key_id);
CREATE INDEX federation_community_blob_epoch_by_community_epoch
    ON federation_community_blob_epoch (community_key_id, minter_key_id, epoch);
CREATE INDEX consent_peer_set_for_by_for_key
    ON consent_peer_set_for (for_key_id);
CREATE INDEX consent_peer_set_for_by_source
    ON consent_peer_set_for (source_attestation_id);
CREATE INDEX federation_key_registration_history_by_key
    ON federation_key_registration_history (key_id, history_id);
CREATE INDEX blob_renditions_by_original
    ON blob_renditions (original_sha256, rendition_sha256);
CREATE INDEX blob_renditions_by_source
    ON blob_renditions (source_attestation_id);
CREATE INDEX federation_attestations_cohort_target
    ON federation_attestations (cohort_scope, cohort_target)
    WHERE cohort_scope IN ('community', 'affiliations', 'family');
CREATE INDEX federation_community_membership_revocations_effective
    ON federation_community_membership_revocations (effective_at);
CREATE INDEX federation_community_membership_revocations_by_member
    ON federation_community_membership_revocations (removed_identity_key_id);
CREATE INDEX federation_community_membership_revocations_admitted
    ON federation_community_membership_revocations
       (COALESCE(admitted_at, removed_at), community_key_id, removed_identity_key_id, effective_at);
CREATE INDEX federation_community_membership_widenings_effective
    ON federation_community_membership_widenings (effective_at);
CREATE INDEX federation_community_membership_widenings_by_member
    ON federation_community_membership_widenings (member_key_id);
CREATE INDEX federation_community_membership_widenings_admitted
    ON federation_community_membership_widenings
       (COALESCE(admitted_at, joined_at), community_key_id, member_key_id, effective_at);
CREATE INDEX consent_peer_set_by_source ON consent_peer_set (source_attestation_id);
CREATE INDEX federation_family_membership_revocations_effective
    ON federation_family_membership_revocations (effective_at);
CREATE INDEX federation_family_membership_revocations_by_member
    ON federation_family_membership_revocations (removed_identity_key_id);
CREATE INDEX federation_family_membership_revocations_admitted
    ON federation_family_membership_revocations
       (COALESCE(admitted_at, removed_at), family_key_id, removed_identity_key_id, effective_at);
CREATE INDEX federation_family_membership_widenings_effective
    ON federation_family_membership_widenings (effective_at);
CREATE INDEX federation_family_membership_widenings_by_member
    ON federation_family_membership_widenings (member_key_id);
CREATE INDEX federation_family_membership_widenings_admitted
    ON federation_family_membership_widenings
       (COALESCE(admitted_at, joined_at), family_key_id, member_key_id, effective_at);
CREATE INDEX idx_lineage_head_cosigns_lineage
    ON federation_lineage_head_cosigns (lineage_key_id, signed_at);
CREATE INDEX federation_manifest_children_by_child
    ON federation_manifest_children (child_sha256);
CREATE INDEX federation_identity_occurrence_history_by_occurrence
    ON federation_identity_occurrence_history (occurrence_key_id);
CREATE INDEX federation_revocations_subject
    ON federation_revocations (revoked_key_sha256_ed25519_raw, effective_at DESC);
CREATE INDEX federation_revocations_revoked
    ON federation_revocations (revoked_key_id, effective_at DESC);
CREATE INDEX federation_revocations_observed_region
    ON federation_revocations (observed_region, revoked_key_sha256_ed25519_raw, scrub_timestamp DESC)
    WHERE observed_region != 'us';
CREATE INDEX federation_revocations_admitted
    ON federation_revocations (COALESCE(admitted_at, scrub_timestamp), revocation_id);
CREATE INDEX federation_stream_chunks_chunk_sha
    ON federation_stream_chunks (chunk_sha);
CREATE INDEX federation_dag_chunks_by_chunk
    ON federation_dag_chunks (chunk_sha256);
CREATE INDEX federation_attestations_attested_dimension
    ON federation_attestations (attested_key_id, dimension);
CREATE INDEX federation_attestations_attested_composer_ref
    ON federation_attestations (
        attested_key_id,
        attestation_type,
        json_extract(attestation_envelope, '$.references_attestation_id')
    );
CREATE INDEX trace_events_trace_ts_scope
    ON trace_events (trace_id, ts, cohort_scope, cohort_target_id);
CREATE INDEX federation_attestations_attester_dimension_citation
    ON federation_attestations (
        attesting_key_id,
        dimension,
        json_extract(attestation_envelope, '$.evidence_refs[0]')
    );
CREATE INDEX federation_attestations_reference_seek
    ON federation_attestations (
        json_extract(attestation_envelope, '$.references_attestation_id'),
        attestation_type
    );
CREATE INDEX federation_group_versions_by_group
    ON federation_group_versions (cohort, group_key_id);
CREATE INDEX signed_wire_index_record_key
    ON signed_wire_index (kind, record_key);
CREATE INDEX purge_executions_serve
    ON purge_executions (admitted_at, notice_id);
CREATE INDEX purge_tombstones_record
    ON purge_tombstones (plane, record_ref);
CREATE INDEX purge_tombstones_ordinal
    ON purge_tombstones (notice_id, ordinal);
CREATE INDEX federation_attestations_dimension_citation
    ON federation_attestations (
        dimension,
        json_extract(attestation_envelope, '$.evidence_refs[0]')
    );
CREATE INDEX federation_stream_dek_grants_recipient
    ON federation_stream_dek_grants (recipient_key_id, cohort_scope);
CREATE UNIQUE INDEX hard_case_events_by_attestation
    ON hard_case_events (attestation_id);
CREATE INDEX hard_case_events_legacy
    ON hard_case_events (event_id) WHERE attestation_id IS NULL;
CREATE UNIQUE INDEX detection_events_by_attestation
    ON cirislens_derived_detection_events (attestation_id);
CREATE INDEX detection_events_legacy
    ON cirislens_derived_detection_events (detection_id) WHERE attestation_id IS NULL;
CREATE UNIQUE INDEX federation_keys_by_attestation
    ON federation_keys (attestation_id);
CREATE INDEX federation_keys_without_row
    ON federation_keys (key_id) WHERE attestation_id IS NULL;
CREATE UNIQUE INDEX federation_revocations_by_attestation
    ON federation_revocations (attestation_id);
CREATE INDEX federation_revocations_without_row
    ON federation_revocations (revocation_id) WHERE attestation_id IS NULL;
CREATE UNIQUE INDEX federation_identity_occurrences_by_attestation
    ON federation_identity_occurrences (attestation_id);
CREATE INDEX federation_identity_occurrences_without_row
    ON federation_identity_occurrences (identity_key_id, occurrence_key_id)
    WHERE attestation_id IS NULL;
CREATE INDEX federation_self_roster_proposals_open
    ON federation_self_roster_proposals (identity_key_id, received_at)
    WHERE settled_at IS NULL;
CREATE INDEX federation_self_roster_proposals_settled
    ON federation_self_roster_proposals (identity_key_id, settled_at)
    WHERE settled_at IS NOT NULL;
CREATE INDEX hard_case_events_by_emitter
    ON hard_case_events (emitter_key_id, emitted_at);
CREATE INDEX credits_contributor ON cirisnode_credits_ledger (contributor_id);
CREATE INDEX credits_cell        ON cirisnode_credits_ledger (domain, language);
CREATE INDEX expertise_contributor ON cirisnode_expertise_ledger (contributor_id);
CREATE INDEX expertise_cell        ON cirisnode_expertise_ledger (domain, language);
CREATE INDEX expertise_routable    ON cirisnode_expertise_ledger (domain, language, is_active)
    WHERE expertise <> '0' AND is_active = 1;
CREATE INDEX idx_scheduled_takedowns_pending
    ON cirisnode_scheduled_takedown_actions (scheduled_eviction_at)
    WHERE status = 'pending';
CREATE INDEX federation_delivery_attestations_peer
    ON cirisnode_federation_delivery_attestations (peer_key_id);
CREATE INDEX federation_delivery_attestations_received_at
    ON cirisnode_federation_delivery_attestations (received_at);
CREATE INDEX goals_declared_by_key_id ON goals (declared_by_key_id);
CREATE INDEX goals_meta_dimension ON goals (meta_dimension);
CREATE INDEX goals_retired_at_live ON goals (retired_at) WHERE retired_at IS NULL;
CREATE INDEX goals_scope_cohort ON goals (scale, scope_cohort_id)
    WHERE scale = 'cohort';
CREATE INDEX goals_attestation_id ON goals (attestation_id);
CREATE UNIQUE INDEX federation_families_by_attestation
    ON federation_families (attestation_id);
CREATE INDEX federation_families_without_row
    ON federation_families (family_key_id) WHERE attestation_id IS NULL;
CREATE UNIQUE INDEX federation_family_membership_revocations_by_attestation
    ON federation_family_membership_revocations (attestation_id);
CREATE INDEX federation_family_membership_revocations_without_row
    ON federation_family_membership_revocations (family_key_id, removed_identity_key_id, effective_at) WHERE attestation_id IS NULL;
CREATE UNIQUE INDEX federation_community_membership_revocations_by_attestation
    ON federation_community_membership_revocations (attestation_id);
CREATE INDEX federation_community_membership_revocations_without_row
    ON federation_community_membership_revocations (community_key_id, removed_identity_key_id, effective_at) WHERE attestation_id IS NULL;
CREATE UNIQUE INDEX federation_family_membership_widenings_by_attestation
    ON federation_family_membership_widenings (attestation_id);
CREATE INDEX federation_family_membership_widenings_without_row
    ON federation_family_membership_widenings (family_key_id, member_key_id, effective_at) WHERE attestation_id IS NULL;
CREATE UNIQUE INDEX federation_community_membership_widenings_by_attestation
    ON federation_community_membership_widenings (attestation_id);
CREATE INDEX federation_community_membership_widenings_without_row
    ON federation_community_membership_widenings (community_key_id, member_key_id, effective_at) WHERE attestation_id IS NULL;
CREATE INDEX federation_communities_admitted
    ON federation_communities (COALESCE(admitted_at, founded_at), community_key_id);
CREATE UNIQUE INDEX federation_communities_by_attestation
    ON federation_communities (attestation_id);
CREATE INDEX federation_communities_without_row
    ON federation_communities (community_key_id) WHERE attestation_id IS NULL;
CREATE INDEX federation_attestations_asserted_seek
    ON federation_attestations (asserted_at DESC, attestation_id DESC);
CREATE INDEX federation_attestations_reference_live
    ON federation_attestations (
        json_extract(attestation_envelope, '$.references_attestation_id'),
        attestation_type
    )
    WHERE json_extract(attestation_envelope, '$.references_attestation_id') IS NOT NULL;
CREATE UNIQUE INDEX federation_cosign_pending_one_open
    ON federation_cosign_pending (group_kind, group_key_id, proposer_key_id)
    WHERE settled_at IS NULL;
CREATE INDEX federation_cosign_aliases_quorum
    ON federation_cosign_aliases (quorum_key);
CREATE INDEX federation_cosign_aliases_held
    ON federation_cosign_aliases (held_attestation_id);
CREATE INDEX federation_attestations_attester_dimension_asserted
    ON federation_attestations (
        attesting_key_id,
        dimension,
        asserted_at DESC,
        attestation_id DESC
    );
CREATE INDEX federation_attestations_attested_dimension_asserted
    ON federation_attestations (
        attested_key_id,
        dimension,
        asserted_at DESC,
        attestation_id DESC
    );

-- ════ triggers ════
CREATE TRIGGER trace_events_cohort_scope_insert_check
BEFORE INSERT ON trace_events
FOR EACH ROW
WHEN NEW.cohort_scope NOT IN
    ('self','family','community','affiliations','species','biosphere','federation')
BEGIN
    SELECT RAISE(ABORT,
        'trace_events.cohort_scope must be one of self/family/community/affiliations/species/biosphere/federation');
END;
CREATE TRIGGER trace_events_cohort_scope_update_check
BEFORE UPDATE ON trace_events
FOR EACH ROW
WHEN NEW.cohort_scope NOT IN
    ('self','family','community','affiliations','species','biosphere','federation')
BEGIN
    SELECT RAISE(ABORT,
        'trace_events.cohort_scope must be one of self/family/community/affiliations/species/biosphere/federation');
END;
CREATE TRIGGER federation_keys_accord_holder_requires_attestation_insert
BEFORE INSERT ON federation_keys
FOR EACH ROW
WHEN NEW.identity_type = 'accord_holder'
    AND NEW.attestation_evidence IS NULL
BEGIN
    SELECT RAISE(ABORT,
        'federation_keys_accord_holder_requires_attestation: identity_type=accord_holder rows MUST carry attestation_evidence (v2.5.0 / CIRISPersist#102 Ask 8)'
    );
END;
CREATE TRIGGER federation_keys_accord_holder_requires_attestation_update
BEFORE UPDATE OF identity_type, attestation_evidence ON federation_keys
FOR EACH ROW
WHEN NEW.identity_type = 'accord_holder'
    AND NEW.attestation_evidence IS NULL
BEGIN
    SELECT RAISE(ABORT,
        'federation_keys_accord_holder_requires_attestation: identity_type=accord_holder rows MUST carry attestation_evidence (v2.5.0 / CIRISPersist#102 Ask 8)'
    );
END;
CREATE TRIGGER federation_attestations_federation_tier_signed_ins
    BEFORE INSERT ON federation_attestations
    FOR EACH ROW
    WHEN (NEW.tier = 'federation' AND NEW.scrub_signature_classical = '')
    BEGIN
        SELECT RAISE(ABORT, 'federation_attestations: tier=federation requires a non-empty scrub_signature_classical (federation ⟹ signed; CEG §10.1.5 AV-60). A deferred-signature row must be tier=local.');
    END;
CREATE TRIGGER federation_attestations_federation_tier_signed_upd
    BEFORE UPDATE ON federation_attestations
    FOR EACH ROW
    WHEN (NEW.tier = 'federation' AND NEW.scrub_signature_classical = '')
    BEGIN
        SELECT RAISE(ABORT, 'federation_attestations: tier=federation requires a non-empty scrub_signature_classical (federation ⟹ signed; CEG §10.1.5 AV-60). A deferred-signature row must be tier=local.');
    END;

-- ════ edition-2 additions ════
--
-- Not in edition 1. The I1950 witness subtracts exactly these objects
-- (store::edition_baseline::EDITION_TWO_ADDITIONS) before it compares, and
-- applies the federation_keys columns below to edition 1's table.

-- The edition-2 projection of a verified key:record into federation_keys
-- (slice E2a). Edition-1-shaped rows are edition 1 with the two ids NULL; an
-- edition-2 projection carries the record's row id and kid. Every FK to
-- federation_keys stays valid. Appended with ALTER so edition 1's DDL text is
-- kept and the addition is visible (store::edition_baseline::KEYS_EDITION_TWO_SQLITE).
ALTER TABLE federation_keys ADD COLUMN edition SMALLINT NOT NULL DEFAULT 1 CHECK (edition IN (1, 2));
ALTER TABLE federation_keys ADD COLUMN record_row_id BLOB CHECK (record_row_id IS NULL OR (typeof(record_row_id) = 'blob' AND length(record_row_id) = 32));
ALTER TABLE federation_keys ADD COLUMN kid BLOB CHECK (kid IS NULL OR (typeof(kid) = 'blob' AND length(kid) = 32)) CHECK (edition <> 2 OR (record_row_id IS NOT NULL AND kid IS NOT NULL));

-- The local-tier record of an earlier store's deletion (store::edition_upgrade,
-- I1955). Node-local: no door replicates it. Counts only, never content.
CREATE TABLE store_edition_deletions (
    deletion_id         INTEGER PRIMARY KEY,
    tier                TEXT    NOT NULL DEFAULT 'local' CHECK (tier = 'local'),
    deleted_at          TEXT    NOT NULL,
    earlier_edition     INTEGER NOT NULL CHECK (earlier_edition = 1),
    earlier_head        INTEGER NOT NULL,
    earlier_migrations  INTEGER NOT NULL,
    plane_counts        TEXT    NOT NULL,
    rows_deleted        INTEGER NOT NULL
);

-- Slice E2a (the edition-2 wire): one row per stored edition-2 statement.
-- A `ceg-row/2` carries its row columns; a non-row object
-- (`ceg-genesis-bundle/2`, `ceg-revocation-snapshot/2`) is keyed by its
-- object id in row_id and leaves them NULL.
CREATE TABLE ceg_statements (
    statement_id    BLOB    NOT NULL PRIMARY KEY
        CHECK (typeof(statement_id) = 'blob' AND length(statement_id) = 32),
    row_id          BLOB    NOT NULL CHECK (typeof(row_id) = 'blob' AND length(row_id) = 32),
    typ             TEXT    NOT NULL,
    row_type        TEXT,
    family          TEXT,
    kid             BLOB    NOT NULL CHECK (typeof(kid) = 'blob' AND length(kid) = 32),
    iss             TEXT    NOT NULL,
    sub             TEXT,
    author          TEXT,
    asserted_at_ms  INTEGER CHECK (asserted_at_ms IS NULL OR typeof(asserted_at_ms) = 'integer'),
    bytes           BLOB    NOT NULL,
    -- Slice J0: THIS node's admission position, POSIX microseconds, strictly
    -- after the last one handed out. The serve cursor is the pair
    -- (admitted_us, statement_id) (edition2_statements_since).
    admitted_us     INTEGER NOT NULL CHECK (typeof(admitted_us) = 'integer'),
    CHECK ((typ = 'ceg-row/2') = (row_type IS NOT NULL AND family IS NOT NULL
        AND sub IS NOT NULL AND asserted_at_ms IS NOT NULL))
);
CREATE INDEX ceg_statements_row_id ON ceg_statements (row_id);
CREATE INDEX ceg_statements_admitted ON ceg_statements (admitted_us, statement_id);

-- Slice E2a: the rows a statement names, by refs member path (`head`,
-- `further_heads`, `prev`, `target`, `trusted_through`, `also:ack`,
-- `also:cites`, or any other refs member verbatim). No FK: a named row may
-- not be held here. The key serves "names of X"; the index "rows naming X".
CREATE TABLE ceg_row_names (
    row_id          BLOB    NOT NULL CHECK (typeof(row_id) = 'blob' AND length(row_id) = 32),
    named_row_id    BLOB    NOT NULL
        CHECK (typeof(named_row_id) = 'blob' AND length(named_row_id) = 32),
    role            TEXT    NOT NULL,
    PRIMARY KEY (row_id, named_row_id, role)
);
CREATE INDEX ceg_row_names_named ON ceg_row_names (named_row_id, role, row_id);

-- Wave G0 (CC 2.7.3, the fold): every folded row, held or concluded: its
-- FIRST arrival (replicated or local, tier), its plane and projection slot
-- (the fold re-folds under exactly that arrival and un-concludes through the
-- plane), and, while it concludes nothing, why: `reason` a token
-- (edition2::fold::reason), `detail` the refusal the gate would have raised,
-- `since_us` THIS node's clock when it was first held for this reason
-- (node-local, never replicated). A concluded row has `reason` NULL.
CREATE TABLE ceg_fold_state (
    row_id          BLOB    NOT NULL PRIMARY KEY
        CHECK (typeof(row_id) = 'blob' AND length(row_id) = 32),
    family          TEXT    NOT NULL,
    tier            TEXT    NOT NULL,
    replicated      INTEGER NOT NULL CHECK (replicated IN (0, 1)),
    plane           TEXT    NOT NULL,
    slot            TEXT    NOT NULL,
    reason          TEXT,
    detail          TEXT,
    since_us        INTEGER CHECK (since_us IS NULL OR typeof(since_us) = 'integer'),
    CHECK ((reason IS NULL) = (detail IS NULL) AND (reason IS NULL) = (since_us IS NULL))
);
CREATE INDEX ceg_fold_state_slot ON ceg_fold_state (slot, row_id);
CREATE INDEX ceg_fold_state_held ON ceg_fold_state (reason, row_id);

-- Wave G0: the dependency index. Every input a row's last fold evaluation
-- read (`row:<hex>`, `key:<id>`, `family:<family>`), held or concluded; a
-- statement that touches a read key re-folds the rows that read it.
CREATE TABLE ceg_fold_reads (
    read_key        TEXT    NOT NULL,
    row_id          BLOB    NOT NULL CHECK (typeof(row_id) = 'blob' AND length(row_id) = 32),
    PRIMARY KEY (read_key, row_id)
);
CREATE INDEX ceg_fold_reads_row ON ceg_fold_reads (row_id);

-- Kernel pass 2 (v62.0.0, K1, I2812; CC 2.7.8 "Two versions of one head wait
-- as tips"): a family / community version whose prev_head_digest does not
-- name the held head is held here beside the head, never refused. The live
-- row stays the head; a held tip re-offered once the version it names is the
-- head runs the whole supersede door and leaves this table. snapshot is the
-- signed wrapper as offered.
CREATE TABLE federation_group_tips (
    cohort               TEXT NOT NULL
        CHECK (cohort IN ('family', 'community', 'affiliations')),
    group_key_id         TEXT NOT NULL,
    persist_row_hash     TEXT NOT NULL,
    prev_head_digest     TEXT NOT NULL,
    snapshot             TEXT NOT NULL CHECK (json_valid(snapshot)),
    change_authorization TEXT
        CHECK (change_authorization IS NULL OR json_valid(change_authorization)),
    held_at              TEXT NOT NULL,    -- RFC-3339
    PRIMARY KEY (cohort, group_key_id, persist_row_hash)
);

-- v62.0.0 (wave O1, S1; CC 3.3.6.4): THIS node's receipts of edition-2
-- self-roster proposals: an identity:occurrence bind awaiting the two paths.
-- The proposal is the bind's row id (lowercase hex); its statements are in
-- ceg_statements. No FK: no attestation row backs it. The lone path's window
-- starts at received_at (this node's first hold).
CREATE TABLE ceg_roster_proposals (
    row_id          TEXT    PRIMARY KEY,
    identity_key_id TEXT    NOT NULL,
    received_at     TEXT    NOT NULL,
    settled_at      TEXT,
    outcome         TEXT,
    CHECK ((settled_at IS NULL) = (outcome IS NULL))
);
CREATE INDEX ceg_roster_proposals_open
    ON ceg_roster_proposals (identity_key_id, received_at)
    WHERE settled_at IS NULL;

-- v62.0.0 (P8-fix14; CC 4.4.3.3.1 / 8.1.5, lead ruling (a)): an edition-2
-- row's restatement key (crossing::restatement_key_of_row), derived from its
-- statement on every node and written by the row writer beside the row,
-- never in the envelope (no content hash sees it). The Live read hides a row
-- that a live, same-attester row with this key and a strictly containing
-- audience restates. Appended with ALTER, so edition 1's DDL stays as it was
-- (store::edition_baseline::ATTESTATIONS_EDITION_TWO_SQLITE).
ALTER TABLE federation_attestations ADD COLUMN restatement_key TEXT;
CREATE INDEX federation_attestations_restatement ON federation_attestations (attesting_key_id, restatement_key) WHERE restatement_key IS NOT NULL;
