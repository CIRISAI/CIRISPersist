-- V300 — THE EDITION-2 BASELINE (PostgreSQL). CIRISPersist v62.0.0, slice E2b.
--
-- CC 1.0-rc20, "nothing carries, clean mesh": a v62 node reads nothing from
-- an earlier store. Edition 1's migration history (V001..V216) is retired;
-- this one file builds the schema those 205 files built, object for object
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
-- Where things live: the five schemas persist owns (cirislens,
-- cirislens_derived, cirislens_secrets, cirisnode, cirisgraph); the
-- `cirislens_pseudonyms` table, unqualified, in the connection's current
-- schema (where edition 1's V010 left it, beside the history table). The body
-- is pg_dump's schema-only form of an edition-1 store at V216, with no owner
-- and no session settings.

-- The read-only role (edition 1's V005). A role is cluster-global: the
-- guard skips the CREATE (and its CREATEROLE need) when it exists, and the
-- handler absorbs a concurrent creator in another database.
DO $$
BEGIN
    IF NOT EXISTS (SELECT 1 FROM pg_roles WHERE rolname = 'cirislens_reader') THEN
        BEGIN
            CREATE ROLE cirislens_reader NOLOGIN;
        EXCEPTION WHEN duplicate_object THEN NULL;
        END;
    END IF;
END
$$;

CREATE SCHEMA IF NOT EXISTS cirisgraph;
CREATE SCHEMA IF NOT EXISTS cirislens;
CREATE SCHEMA IF NOT EXISTS cirislens_derived;
CREATE SCHEMA IF NOT EXISTS cirislens_secrets;
CREATE SCHEMA IF NOT EXISTS cirisnode;

CREATE TABLE cirislens_pseudonyms (
    original_hash bytea NOT NULL,
    pseudonym text NOT NULL,
    class text NOT NULL,
    created_at timestamp with time zone DEFAULT now() NOT NULL
);

COMMENT ON TABLE cirislens_pseudonyms IS 'v0.6.1 (CIRISPersist#19) — stable Pseudonymize mappings for Action::Pseudonymize. Same hash → same pseudonym across federation peers.';

ALTER TABLE ONLY cirislens_pseudonyms
    ADD CONSTRAINT cirislens_pseudonyms_pkey PRIMARY KEY (original_hash);

ALTER TABLE ONLY cirislens_pseudonyms
    ADD CONSTRAINT cirislens_pseudonyms_pseudonym_key UNIQUE (pseudonym);

CREATE INDEX cirislens_pseudonyms_class ON cirislens_pseudonyms USING btree (class);

CREATE TABLE cirisgraph.consolidation_locks (
    period_start timestamp with time zone NOT NULL,
    period_end timestamp with time zone NOT NULL,
    tenant_id text NOT NULL,
    locked_by text NOT NULL,
    locked_at timestamp with time zone DEFAULT now() NOT NULL,
    CONSTRAINT consolidation_locks_check CHECK ((period_end > period_start))
);

COMMENT ON TABLE cirisgraph.consolidation_locks IS 'v0.8.2 (CIRISPersist#36) — per-(period_start, tenant_id) lock for the TSDB rollup. Acquired via INSERT…ON CONFLICT DO NOTHING; stale locks (>1h since locked_at) auto-break per AV-53.';

CREATE TABLE cirisgraph.edges (
    edge_id uuid NOT NULL,
    source_node_id text NOT NULL,
    target_node_id text NOT NULL,
    scope text NOT NULL,
    relationship text NOT NULL,
    weight double precision,
    attributes jsonb DEFAULT '{}'::jsonb NOT NULL,
    created_at timestamp with time zone DEFAULT now() NOT NULL,
    CONSTRAINT edges_scope_check CHECK ((scope = ANY (ARRAY['LOCAL'::text, 'IDENTITY'::text, 'ENVIRONMENT'::text, 'COMMUNITY'::text])))
);

COMMENT ON TABLE cirisgraph.edges IS 'v0.8.0 (CIRISPersist#34) — directed typed edges between nodes. No FK on source/target so eventual-consistency writes work; k-hop CTE tolerates dangling edges. (edge_id) is the PK (UUID); the (source, target, relationship) tuple may repeat across different windows / weights.';

CREATE TABLE cirisgraph.nodes (
    node_id text NOT NULL,
    scope text NOT NULL,
    node_type text NOT NULL,
    attributes jsonb NOT NULL,
    version integer DEFAULT 1 NOT NULL,
    updated_by text NOT NULL,
    updated_at timestamp with time zone DEFAULT now() NOT NULL,
    created_at timestamp with time zone DEFAULT now() NOT NULL,
    signature text,
    signing_key_id text,
    signature_verified boolean DEFAULT false NOT NULL,
    original_content_hash bytea,
    persist_row_hash text,
    consolidation_level text DEFAULT 'basic'::text NOT NULL,
    CONSTRAINT nodes_consolidation_level_check CHECK ((consolidation_level = ANY (ARRAY['basic'::text, 'daily'::text, 'weekly'::text, 'monthly'::text]))),
    CONSTRAINT nodes_scope_check CHECK ((scope = ANY (ARRAY['LOCAL'::text, 'IDENTITY'::text, 'ENVIRONMENT'::text, 'COMMUNITY'::text]))),
    CONSTRAINT nodes_version_check CHECK ((version >= 1))
);

COMMENT ON TABLE cirisgraph.nodes IS 'v0.8.0 (CIRISPersist#34) — typed graph nodes absorbed from CIRISAgent LocalGraphMemoryService. Schema mirrors agent column shape for parity; persist adds audit envelope (signature / signing_key_id / signature_verified / original_content_hash / persist_row_hash). PK is (node_id, scope) — same id may exist in multiple scopes without collision.';

COMMENT ON COLUMN cirisgraph.nodes.consolidation_level IS 'v1.0.0 (CIRISAgent#756 Q7) — TSDB rollup tier for node_type=tsdb_summary rows: basic (6h, raw obs), daily (basic rollup), weekly (daily rollup), monthly (weekly rollup). DEFAULT basic; CHECK-gated for typo defense.';

CREATE TABLE cirisgraph.telemetry_metrics (
    metric_id uuid NOT NULL,
    metric_name text NOT NULL,
    tenant_id text NOT NULL,
    value double precision NOT NULL,
    labels jsonb DEFAULT '{}'::jsonb NOT NULL,
    observed_at timestamp with time zone NOT NULL,
    expires_at timestamp with time zone NOT NULL,
    created_at timestamp with time zone DEFAULT now() NOT NULL
);

COMMENT ON TABLE cirisgraph.telemetry_metrics IS 'v0.8.2 (CIRISPersist#36) — raw telemetry observations (24h-lived). Rolled up every 6h into tsdb_summary nodes in cirisgraph.nodes; raw rows deleted after rollup. No per-row audit envelope (ephemeral); rolled-up summary carries the audit path.';

CREATE TABLE cirislens.accord_active_halt (
    family_key_id text NOT NULL,
    active_halt_id text NOT NULL,
    set_at timestamp with time zone NOT NULL
);

CREATE TABLE cirislens.accord_decision (
    proposal_digest text NOT NULL,
    family_key_id text NOT NULL,
    authorized boolean NOT NULL,
    yes bigint NOT NULL,
    no bigint NOT NULL,
    abstain bigint NOT NULL,
    live_set jsonb NOT NULL,
    window_until timestamp with time zone NOT NULL,
    decision_json jsonb NOT NULL,
    persist_row_hash text NOT NULL,
    decided_at timestamp with time zone NOT NULL
);

CREATE TABLE cirislens.accord_participation (
    proposal_digest text NOT NULL,
    member_id text NOT NULL,
    pinned_pubkey text NOT NULL,
    vote text NOT NULL,
    window_until timestamp with time zone NOT NULL,
    signed_at timestamp with time zone NOT NULL,
    server_arrival_at timestamp with time zone NOT NULL,
    participation_json jsonb NOT NULL,
    persist_row_hash text NOT NULL,
    CONSTRAINT accord_participation_vote_check CHECK ((vote = ANY (ARRAY['yes'::text, 'no'::text, 'abstain'::text])))
);

CREATE TABLE cirislens.accord_proposal (
    proposal_digest text NOT NULL,
    family_key_id text NOT NULL,
    action text NOT NULL,
    nonce text NOT NULL,
    window_until timestamp with time zone NOT NULL,
    prior_family_digest text NOT NULL,
    payload_sha256 text NOT NULL,
    proposal_json jsonb NOT NULL,
    authority_signature jsonb,
    persist_row_hash text NOT NULL,
    created_at timestamp with time zone NOT NULL,
    CONSTRAINT accord_proposal_action_check CHECK ((action = ANY (ARRAY['fire'::text, 'roster_change'::text, 'resume'::text])))
);

CREATE TABLE cirislens.accord_proposal_nonce_claim (
    family_key_id text NOT NULL,
    nonce text NOT NULL,
    proposal_digest text NOT NULL
);

CREATE TABLE cirislens.accord_public_keys (
    key_id text NOT NULL,
    public_key_base64 text NOT NULL,
    algorithm text,
    description text,
    created_at timestamp with time zone DEFAULT now() NOT NULL,
    expires_at timestamp with time zone,
    revoked_at timestamp with time zone,
    revoked_reason text,
    added_by text
);

CREATE TABLE cirislens.announced_peers (
    key_id text NOT NULL,
    pubkey_ed25519_base64 text NOT NULL,
    pubkey_ml_dsa_65_base64 text,
    claimed_identity_type text,
    first_seen_at timestamp with time zone NOT NULL,
    last_seen_at timestamp with time zone NOT NULL,
    announce_count bigint DEFAULT 1 NOT NULL
);

CREATE TABLE cirislens.attestation_subjects (
    subject_key_id text NOT NULL,
    dimension text,
    asserted_at timestamp with time zone NOT NULL,
    attestation_id text NOT NULL,
    tier text NOT NULL,
    cohort_scope text NOT NULL
);

CREATE TABLE cirislens.audit_archives (
    archive_id uuid NOT NULL,
    tenant_id text NOT NULL,
    from_ts timestamp with time zone NOT NULL,
    to_ts timestamp with time zone NOT NULL,
    rows_archived bigint NOT NULL,
    chain_anchor bytea NOT NULL,
    archive_bytes bytea NOT NULL,
    created_at timestamp with time zone DEFAULT now() NOT NULL,
    CONSTRAINT audit_archives_chain_anchor_check CHECK ((octet_length(chain_anchor) = 32)),
    CONSTRAINT audit_archives_check CHECK ((from_ts < to_ts)),
    CONSTRAINT audit_archives_rows_archived_check CHECK ((rows_archived >= 0))
);

COMMENT ON TABLE cirislens.audit_archives IS 'v2.7.0 (CIRISPersist#107) — chain-anchored audit-log archive blobs. Engine::archive_audit_range writes one row per archived range; the chain_anchor BYTEA holds the entry_hash of the last archived row so verifiers can walk the chain across an archive. archive_bytes carries the canonical JSON of the archived AuditEntry rows.';

CREATE TABLE cirislens.audit_log (
    entry_id uuid NOT NULL,
    sequence_number bigint NOT NULL,
    tenant_id text NOT NULL,
    actor_id text NOT NULL,
    action_type text NOT NULL,
    subject_kind text NOT NULL,
    subject_id text NOT NULL,
    payload jsonb NOT NULL,
    prev_hash bytea NOT NULL,
    entry_hash bytea NOT NULL,
    recorded_at timestamp with time zone NOT NULL,
    signature text NOT NULL,
    signing_key_id text NOT NULL,
    signature_verified boolean DEFAULT false NOT NULL,
    persist_row_hash text NOT NULL,
    content_hash bytea,
    CONSTRAINT audit_log_sequence_number_check CHECK ((sequence_number >= 1))
);

COMMENT ON TABLE cirislens.audit_log IS 'v0.8.1 (CIRISPersist#35) — hash-chained audit log. Per-tenant monotonic sequence_number + sha256 prev_hash chain. Each entry signs over canonical bytes; persist verifies on INSERT and refuses chain breaks. Self-signed identity model: actor_id IS the Ed25519 pubkey (base64).';

COMMENT ON COLUMN cirislens.audit_log.content_hash IS 'v1.0.0 — sha256(canonical_envelope_bytes) for atomic-claim dedup. NULL on rows written via the legacy record_entry path. UNIQUE; conflicts surface as ClaimResult::AlreadyClaimed.';

CREATE TABLE cirislens.blackhole_rules (
    identity_hash bytea NOT NULL,
    until timestamp with time zone,
    reason text,
    added_at timestamp with time zone DEFAULT now() NOT NULL,
    hits bigint DEFAULT 0 NOT NULL,
    persist_row_hash text NOT NULL
);

COMMENT ON TABLE cirislens.blackhole_rules IS 'v3.2.0 (CIRISPersist#120) — operator-driven per-identity deny-list keyed by 16-byte Reticulum identity_hash. Sibling to federation_keys (no FK; transport identities exist independently of cryptographic identities). until=NULL means permanent. hits is a non-transactional observation counter; record_hit is commutative.';

CREATE TABLE cirislens.blob_renditions (
    rendition_sha256 bytea NOT NULL,
    original_sha256 bytea NOT NULL,
    format text NOT NULL,
    size bigint NOT NULL,
    width integer,
    height integer,
    role text NOT NULL,
    source_attestation_id text NOT NULL,
    cohort_scope text NOT NULL
);

CREATE TABLE cirislens.canonical_role_withdrawal (
    key_id text NOT NULL,
    withdrawn_at timestamp with time zone NOT NULL,
    authority_decision_digest text NOT NULL,
    superseded_by text,
    persist_row_hash text NOT NULL
);

CREATE TABLE cirislens.consent_peer_set (
    node_key_id text NOT NULL,
    peer_key_id text NOT NULL,
    source_attestation_id text NOT NULL,
    asserted_at timestamp with time zone NOT NULL,
    for_key_id text NOT NULL
);

CREATE TABLE cirislens.consent_peer_set_for (
    author_key_id text NOT NULL,
    for_key_id text NOT NULL,
    peer_key_id text NOT NULL,
    source_attestation_id text NOT NULL,
    asserted_at timestamp with time zone NOT NULL
);

CREATE TABLE cirislens.content_aggregation (
    aggregate_content_id text NOT NULL,
    source_corpus_kind text NOT NULL,
    aggregation_level bigint NOT NULL,
    fan_in bigint NOT NULL,
    member_commitment text NOT NULL,
    aggregation_meta bytea NOT NULL,
    aggregated_at_unix_ms bigint NOT NULL
);

CREATE TABLE cirislens.content_manifest (
    content_id text NOT NULL,
    corpus_kind text NOT NULL,
    manifest_version integer NOT NULL,
    n_source bigint NOT NULL,
    k_repair bigint NOT NULL,
    symbol_size bigint NOT NULL,
    original_content_length bigint NOT NULL,
    min_viable_symbols bigint NOT NULL,
    symbol_hashes jsonb NOT NULL,
    envelope jsonb NOT NULL,
    signature text NOT NULL,
    signature_ml_dsa_65 text NOT NULL,
    pqc_key_id text NOT NULL,
    admitted_at timestamp with time zone DEFAULT now() NOT NULL
);

CREATE TABLE cirislens.content_symbols (
    content_id text NOT NULL,
    symbol_id bigint NOT NULL,
    retention_priority smallint NOT NULL,
    symbol_bytes bytea NOT NULL
);

CREATE TABLE cirislens.continuity_awareness (
    id text NOT NULL,
    agent_id text NOT NULL,
    shutdown_timestamp timestamp with time zone NOT NULL,
    is_terminal boolean NOT NULL,
    shutdown_reason text NOT NULL,
    expected_reactivation timestamp with time zone,
    initiated_by text NOT NULL,
    final_thoughts text NOT NULL,
    unfinished_tasks jsonb,
    reactivation_instructions text,
    deferred_goals jsonb,
    preservation_node_id text NOT NULL,
    preservation_scope text DEFAULT 'IDENTITY'::text NOT NULL,
    reactivation_count integer DEFAULT 0 NOT NULL,
    CONSTRAINT continuity_awareness_preservation_scope_check CHECK ((preservation_scope = ANY (ARRAY['LOCAL'::text, 'IDENTITY'::text, 'ENVIRONMENT'::text, 'COMMUNITY'::text]))),
    CONSTRAINT continuity_awareness_reactivation_count_check CHECK ((reactivation_count >= 0))
);

COMMENT ON TABLE cirislens.continuity_awareness IS 'v1.5.17 (CIRISPersist#59 #9) — continuity_awareness substrate. Absorbs CIRISAgent ciris_engine.db.continuity_awareness; per-shutdown record giving the next boot a "where did I leave off" surface. 14 columns matching the agent verbatim. First substrate with a cross-substrate FK: (preservation_node_id, preservation_scope) references cirisgraph.nodes(node_id, scope) DEFERRABLE so shutdown ceremony can land graph-node + continuity row in one tx. preservation_scope CHECK over LOCAL|IDENTITY|ENVIRONMENT|COMMUNITY (matches cirisgraph scope vocabulary). reactivation_count CHECK (>= 0).';

CREATE TABLE cirislens.creation_ceremonies (
    ceremony_id text NOT NULL,
    "timestamp" timestamp with time zone NOT NULL,
    creator_agent_id text NOT NULL,
    creator_human_id text NOT NULL,
    wise_authority_id text NOT NULL,
    new_agent_id text NOT NULL,
    new_agent_name text NOT NULL,
    new_agent_purpose text NOT NULL,
    new_agent_description text,
    creation_justification text NOT NULL,
    expected_capabilities text,
    ethical_considerations text NOT NULL,
    template_profile_hash text,
    ceremony_status text NOT NULL,
    CONSTRAINT creation_ceremonies_ceremony_status_check CHECK ((ceremony_status = ANY (ARRAY['pending'::text, 'in_progress'::text, 'completed'::text, 'failed'::text, 'revoked'::text])))
);

COMMENT ON TABLE cirislens.creation_ceremonies IS 'v1.5.16 (CIRISPersist#59 #8) — creation_ceremonies substrate. Absorbs CIRISAgent ciris_engine.db.creation_ceremonies; identity-creation history (typically write-once, occasionally revisited for "history of agent creations" queries). 14 columns matching the agent verbatim. No FKs (agent_id references are free-form pointers across substrate boundaries). ceremony_status CHECK over pending|in_progress|completed|failed|revoked.';

CREATE TABLE cirislens.dag_link_backfill_cursor (
    singleton boolean DEFAULT true NOT NULL,
    after_sha256 bytea,
    updated_at timestamp with time zone DEFAULT now() NOT NULL,
    CONSTRAINT dag_link_backfill_cursor_after_sha256_check CHECK (((after_sha256 IS NULL) OR (length(after_sha256) = 32))),
    CONSTRAINT dag_link_backfill_cursor_singleton_check CHECK (singleton)
);

CREATE TABLE cirislens.deferral_reports (
    message_id text NOT NULL,
    task_id text NOT NULL,
    thought_id text NOT NULL,
    package jsonb,
    created_at timestamp with time zone DEFAULT now() NOT NULL,
    resolved_at timestamp with time zone,
    resolution_notes text
);

COMMENT ON TABLE cirislens.deferral_reports IS 'v1.5.14 (CIRISPersist#59 #6) — deferral_reports substrate. Absorbs CIRISAgent ciris_engine.db.deferral_reports. Light 5-col agent shape + 2 persist-only nullable columns (resolved_at, resolution_notes) for the list_active hot path. FKs to cirislens.tasks + cirislens.thoughts both DEFERRABLE INITIALLY DEFERRED.';

CREATE TABLE cirislens.edge_detection_events (
    detection_id uuid NOT NULL,
    tenant_id text NOT NULL,
    detector_kind text NOT NULL,
    subject_key_id text NOT NULL,
    observed_at timestamp with time zone NOT NULL,
    evidence jsonb NOT NULL,
    severity text NOT NULL,
    signature text NOT NULL,
    signing_key_id text NOT NULL,
    signature_verified boolean DEFAULT false NOT NULL,
    persist_row_hash text NOT NULL,
    CONSTRAINT edge_detection_events_detector_kind_check CHECK ((detector_kind = ANY (ARRAY['unconsented_external_probe'::text, 'excessive_recursion'::text, 'consent_gate_leak'::text]))),
    CONSTRAINT edge_detection_events_severity_check CHECK ((severity = ANY (ARRAY['info'::text, 'warn'::text, 'block'::text])))
);

CREATE TABLE cirislens.edge_outbound_queue (
    queue_id uuid DEFAULT gen_random_uuid() NOT NULL,
    sender_key_id text NOT NULL,
    destination_key_id text NOT NULL,
    message_type text NOT NULL,
    edge_schema_version text NOT NULL,
    envelope_bytes bytea NOT NULL,
    body_sha256 bytea NOT NULL,
    body_size_bytes integer NOT NULL,
    status text NOT NULL,
    enqueued_at timestamp with time zone DEFAULT now() NOT NULL,
    next_attempt_after timestamp with time zone NOT NULL,
    last_attempt_at timestamp with time zone,
    transport_delivered_at timestamp with time zone,
    delivered_at timestamp with time zone,
    abandoned_at timestamp with time zone,
    abandoned_reason text,
    attempt_count integer DEFAULT 0 NOT NULL,
    max_attempts integer NOT NULL,
    ttl_seconds bigint NOT NULL,
    last_error_class text,
    last_error_detail text,
    last_transport text,
    requires_ack boolean NOT NULL,
    ack_timeout_seconds bigint,
    ack_envelope_bytes bytea,
    ack_received_at timestamp with time zone,
    claimed_until timestamp with time zone,
    claimed_by text,
    CONSTRAINT abandoned_implies_abandoned_at CHECK (((status = 'abandoned'::text) = ((abandoned_at IS NOT NULL) AND (abandoned_reason IS NOT NULL)))),
    CONSTRAINT abandoned_reason_must_be_known CHECK (((abandoned_reason IS NULL) OR (abandoned_reason = ANY (ARRAY['max_attempts'::text, 'ttl_expired'::text, 'operator_cancel'::text])))),
    CONSTRAINT ack_envelope_implies_ack_received CHECK (((ack_envelope_bytes IS NOT NULL) = (ack_received_at IS NOT NULL))),
    CONSTRAINT ack_received_implies_requires_ack CHECK (((ack_received_at IS NULL) OR (requires_ack = true))),
    CONSTRAINT ack_timeout_required_when_requires_ack CHECK (((NOT requires_ack) OR ((ack_timeout_seconds IS NOT NULL) AND (ack_timeout_seconds > 0)))),
    CONSTRAINT body_sha256_correct_length CHECK ((octet_length(body_sha256) = 32)),
    CONSTRAINT body_size_bounded CHECK (((body_size_bytes >= 1) AND (body_size_bytes <= 8388608))),
    CONSTRAINT delivered_implies_delivered_at CHECK (((status = 'delivered'::text) = (delivered_at IS NOT NULL))),
    CONSTRAINT max_attempts_positive CHECK ((max_attempts > 0)),
    CONSTRAINT status_must_be_known CHECK ((status = ANY (ARRAY['pending'::text, 'sending'::text, 'awaiting_ack'::text, 'delivered'::text, 'abandoned'::text]))),
    CONSTRAINT ttl_seconds_positive CHECK ((ttl_seconds > 0))
);

CREATE TABLE cirislens.federation_attestations (
    attestation_id text DEFAULT (gen_random_uuid())::text NOT NULL,
    attesting_key_id text NOT NULL,
    attested_key_id text NOT NULL,
    attestation_type text NOT NULL,
    weight numeric,
    asserted_at timestamp with time zone NOT NULL,
    expires_at timestamp with time zone,
    attestation_envelope text NOT NULL,
    original_content_hash bytea NOT NULL,
    scrub_signature_classical text NOT NULL,
    scrub_signature_pqc text,
    scrub_key_id text NOT NULL,
    scrub_timestamp timestamp with time zone NOT NULL,
    pqc_completed_at timestamp with time zone,
    persist_row_hash text NOT NULL,
    subject_key_ids jsonb DEFAULT '[]'::jsonb NOT NULL,
    withdraws_admission_rule smallint,
    cohort_scope text DEFAULT 'federation'::text NOT NULL,
    tier text DEFAULT 'federation'::text NOT NULL,
    promoted_at timestamp with time zone,
    additional_scrubs text DEFAULT '[]'::text NOT NULL,
    dimension text GENERATED ALWAYS AS (((attestation_envelope)::jsonb ->> 'dimension'::text)) STORED,
    admitted_at timestamp with time zone NOT NULL,
    cohort_target text GENERATED ALWAYS AS (COALESCE(((attestation_envelope)::jsonb ->> 'community_id'::text), ((attestation_envelope)::jsonb ->> 'community_key_id'::text), ((attestation_envelope)::jsonb ->> 'cohort_key_id'::text), ((attestation_envelope)::jsonb ->> 'family_key_id'::text))) STORED,
    CONSTRAINT federation_attestations_cohort_scope_closed_set CHECK ((cohort_scope = ANY (ARRAY['self'::text, 'family'::text, 'community'::text, 'affiliations'::text, 'species'::text, 'biosphere'::text, 'federation'::text]))),
    CONSTRAINT federation_attestations_federation_tier_signed CHECK (((tier = 'local'::text) OR (scrub_signature_classical <> ''::text))),
    CONSTRAINT federation_attestations_subject_key_ids_is_array CHECK ((jsonb_typeof(subject_key_ids) = 'array'::text)),
    CONSTRAINT federation_attestations_tier_check CHECK ((tier = ANY (ARRAY['local'::text, 'federation'::text]))),
    CONSTRAINT federation_attestations_withdraws_admission_rule_range CHECK (((withdraws_admission_rule IS NULL) OR ((withdraws_admission_rule >= 1) AND (withdraws_admission_rule <= 5))))
);

COMMENT ON COLUMN cirislens.federation_attestations.attestation_envelope IS 'v31.0.0 (CIRISPersist#645) — TEXT, not JSONB. Query sites that need to reach inside cast explicitly (attestation_envelope::jsonb->>…); the cast is immutable and the two expression indexes above are built over it. SQLite parity: TEXT since V004.';

COMMENT ON COLUMN cirislens.federation_attestations.subject_key_ids IS 'v3.7.0 (CIRISPersist#146, CEG 0.6 §4.2). OPTIONAL list of consent-holder key_ids for this attestation. Each entry MAY be a federation_keys.key_id OR a canonical-hash identifier (CEG 0.6 §4.2.2). Default [] = status quo (producer-only authority). Substrate does NOT FK-enforce that entries are federation_keys rows — canonical-hash subjects (Discord user-ids, external party identifiers) are valid per CEG 0.6 design.';

COMMENT ON COLUMN cirislens.federation_attestations.withdraws_admission_rule IS 'v3.7.0 (CIRISPersist#146, CEG 0.6 §3.2.3). Per-rule audit metadata: which of the 4 admission rules admitted this withdraws. 1 = producer self-revocation (legacy), 2 = subject self-revocation (CEG 0.6 NEW), 3 = delegates_to proxy with consent_revocation scope (CEG 0.6 NEW), 4 = delegates_to chain via any of 1-3. NULL on non-withdraws rows. Populated at admission time in v3.8.0+ once the 4-rule admission gate lands.';

COMMENT ON COLUMN cirislens.federation_attestations.cohort_scope IS 'v3.9.0 (CIRISPersist#150, CEG §4.2.4). Closed-set producer-side visibility scope. Default ''federation'' (pre-v3.9.0 backward-compat). Orthogonal to subject_key_ids[] (revocability authority). §8.1.8 feed compositions filter by this column.';

COMMENT ON COLUMN cirislens.federation_attestations.tier IS 'v4.4 (CIRISPersist#171, CEG §10.1.3/§10.1.5) — local (producer-only authority, signature deferred, visible only to the producing occurrence) | federation (hybrid-signed, federation-visible). DEFAULT federation. CHECK federation_attestations_federation_tier_signed enforces federation ⟹ non-empty classical signature (AV-60).';

COMMENT ON COLUMN cirislens.federation_attestations.promoted_at IS 'v4.4 (CIRISPersist#171) — set by attestation_promote at the local→federation transition (the federation-emit moment). NULL for natively-federation rows and un-promoted local rows. Persist-internal — NOT part of the JCS canonical signing bytes (CEG §10.1.5.3 must #2).';

COMMENT ON COLUMN cirislens.federation_attestations.additional_scrubs IS 'v24.0.0 (CIRISPersist#556) — JSON array of the 2nd..Nth ScrubSig entries over the SAME canonical attestation_envelope as the base scrub. Empty array = single-scrub row (wire-absent, persist_row_hash unchanged).';

COMMENT ON COLUMN cirislens.federation_attestations.admitted_at IS 'NOT NULL on both dialects since sqlite V141 (CIRISPersist#828); postgres has been NOT NULL since V130.';

CREATE TABLE cirislens.federation_attestations_form_refused (
    attestation_id text NOT NULL,
    attesting_key_id text NOT NULL,
    persist_row_hash text NOT NULL,
    refused_member text NOT NULL,
    refused_value text NOT NULL,
    refused_at timestamp with time zone NOT NULL
);

CREATE TABLE cirislens.federation_blob_associations (
    sha256 bytea NOT NULL,
    cohort_scope text NOT NULL,
    group_key_id text DEFAULT ''::text NOT NULL,
    CONSTRAINT federation_blob_associations_sha256_check CHECK ((length(sha256) = 32))
);

CREATE TABLE cirislens.federation_blob_key_grants (
    at_rest_sha256 bytea NOT NULL,
    recipient_key_id text NOT NULL,
    wrap_algorithm text NOT NULL,
    wrapped_dek text NOT NULL,
    cohort_scope text NOT NULL,
    created_at timestamp with time zone DEFAULT now() NOT NULL,
    CONSTRAINT federation_blob_key_grants_at_rest_sha256_check CHECK ((octet_length(at_rest_sha256) = 32)),
    CONSTRAINT federation_blob_key_grants_wrap_algorithm_check CHECK ((wrap_algorithm = ANY (ARRAY['x25519_mlkem768_aes256_gcm_hkdf_sha256'::text, 'aes256_gcm_content_master'::text])))
);

CREATE TABLE cirislens.federation_blobs (
    sha256 bytea NOT NULL,
    storage_kind text NOT NULL,
    bytes_inline bytea,
    external_ref text,
    size_bytes bigint NOT NULL,
    media_type text,
    first_seen_at timestamp with time zone DEFAULT now() NOT NULL,
    regions_held text[] DEFAULT '{}'::text[] NOT NULL,
    last_accessed_at timestamp with time zone DEFAULT now() NOT NULL,
    access_count bigint DEFAULT 0 NOT NULL,
    cohort_scope text DEFAULT 'federation'::text NOT NULL,
    crypto_tier text DEFAULT 'plaintext'::text NOT NULL,
    author_key_id text,
    key_grant_emitted_at timestamp with time zone,
    group_key_id text,
    CONSTRAINT federation_blobs_cohort_scope_check CHECK ((cohort_scope = ANY (ARRAY['self'::text, 'family'::text, 'community'::text, 'affiliations'::text, 'species'::text, 'biosphere'::text, 'federation'::text]))),
    CONSTRAINT federation_blobs_crypto_tier_check CHECK ((crypto_tier = ANY (ARRAY['plaintext'::text, 'invisible_encrypted'::text, 'community_dek'::text]))),
    CONSTRAINT federation_blobs_sha256_check CHECK ((octet_length(sha256) = 32)),
    CONSTRAINT federation_blobs_size_bytes_check CHECK ((size_bytes >= 0)),
    CONSTRAINT federation_blobs_storage_kind_check CHECK ((storage_kind = ANY (ARRAY['inline'::text, 's3'::text, 'external_url'::text, 'chunk_dag'::text]))),
    CONSTRAINT federation_blobs_storage_kind_columns_match CHECK ((((storage_kind = 'inline'::text) AND (bytes_inline IS NOT NULL) AND (external_ref IS NULL)) OR ((storage_kind = 'chunk_dag'::text) AND (bytes_inline IS NOT NULL) AND (external_ref IS NULL)) OR ((storage_kind = ANY (ARRAY['s3'::text, 'external_url'::text])) AND (bytes_inline IS NULL) AND (external_ref IS NOT NULL))))
);

COMMENT ON TABLE cirislens.federation_blobs IS 'v2.3 (CIRISPersist#103) — Content-addressable byte storage. SHA-256-keyed; storage_kind chooses inline vs s3 vs external_url. Holders are tracked via holds_bytes:sha256:<8-hex-prefix> attestations on federation_attestations (auto-emitted by put_blob). No GC in v0.1; blobs persist forever (deferred to a follow-up issue).';

COMMENT ON COLUMN cirislens.federation_blobs.sha256 IS 'SHA-256 content hash, 32 bytes raw. Primary key — put_blob is idempotent on SHA collision (first-write-wins on storage_kind).';

COMMENT ON COLUMN cirislens.federation_blobs.storage_kind IS 'How the bytes are stored: inline (bytes_inline) | s3 (external_ref) | external_url (external_ref) | chunk_dag (JCS manifest in bytes_inline; CIRISPersist#142 Cut B). First-write-wins on conflict — see put_blob doc.';

COMMENT ON COLUMN cirislens.federation_blobs.last_accessed_at IS 'v3.4.0 (CIRISPersist#123) — wall-clock of the most recent get_blob / has_blob hit. Backfilled to first_seen_at for pre-V053 rows; bumped by put-side reads via UPDATE … RETURNING in the same statement that selects the row.';

COMMENT ON COLUMN cirislens.federation_blobs.access_count IS 'v3.4.0 (CIRISPersist#123) — monotonic count of get_blob / has_blob hits since the row was inserted. Used by the EvictionSweeper to break ties when last_accessed_at matches.';

COMMENT ON COLUMN cirislens.federation_blobs.author_key_id IS '#846 (BLOB_REPLICATION.md §5) — the attesting_key_id of the attestation this blob is a projection of: the writer''s DERIVED federation key id for a local write (I23), the declared provenance for an adopted one. NULL = unknown, which is_proxy_content treats as proxy (fail toward evictable). Not backfilled: no pre-V144 row records its author.';

COMMENT ON COLUMN cirislens.federation_blobs.key_grant_emitted_at IS 'When this node last emitted the blob''s content-axis KeyGrant set; NULL or not later than the newest at-rest grant means DIRTY (CIRISPersist#848, §14).';

COMMENT ON COLUMN cirislens.federation_blobs.group_key_id IS '#984 (rows 1 and 4) — the group the write named: the owner identity (self), the family key (family) or the community key, as the scoped doors received it. NULL = unknown (pre-V177, adopted, or a write that named no group). The retroactive-ADD walk joins on it and excludes NULL (fail-secure); durability resolves a family blob''s audience from it. Not backfilled: no pre-V177 row records its group.';

CREATE TABLE cirislens.federation_communities (
    community_key_id text NOT NULL,
    community_name text NOT NULL,
    members jsonb NOT NULL,
    founded_at timestamp with time zone NOT NULL,
    consensus_protocol text NOT NULL,
    policy_blob jsonb,
    persist_row_hash text NOT NULL,
    version integer DEFAULT 1 NOT NULL,
    authority_key_id text,
    scrub_signature_classical text,
    scrub_signature_pqc text,
    admitted_at timestamp with time zone NOT NULL,
    supersede_proof jsonb,
    cosignatures jsonb DEFAULT '[]'::jsonb NOT NULL,
    lineage jsonb DEFAULT '[]'::jsonb NOT NULL,
    prev_head_digest text DEFAULT ''::text NOT NULL,
    charter_digest text DEFAULT ''::text NOT NULL,
    attestation_id text,
    CONSTRAINT federation_communities_consensus_protocol_form CHECK ((consensus_protocol ~ '^(founder_only|unanimous|majority|open:self_admit|quorum:[0-9]+/[0-9]+|reverse_quorum:[0-9]+/[0-9]+:[0-9]+([+]escalate:[0-9]+:[0-9]+)?|weighted:.+|custom:.+)$'::text))
);

COMMENT ON COLUMN cirislens.federation_communities.admitted_at IS 'NOT NULL on both dialects since sqlite V141 (CIRISPersist#828); postgres has been NOT NULL since V130.';

CREATE TABLE cirislens.federation_community_blob_epoch (
    at_rest_sha256 bytea NOT NULL,
    community_key_id text NOT NULL,
    epoch bigint NOT NULL,
    created_at timestamp with time zone DEFAULT now() NOT NULL,
    evicted_at timestamp with time zone,
    minter_key_id text NOT NULL,
    CONSTRAINT federation_community_blob_epoch_at_rest_sha256_check CHECK ((octet_length(at_rest_sha256) = 32)),
    CONSTRAINT federation_community_blob_epoch_epoch_check CHECK ((epoch >= 0))
);

CREATE TABLE cirislens.federation_community_dek (
    community_key_id text NOT NULL,
    epoch bigint NOT NULL,
    wrap_algorithm text NOT NULL,
    wrapped_dek text,
    created_at timestamp with time zone DEFAULT now() NOT NULL,
    key_state text DEFAULT 'enabled'::text NOT NULL,
    minter_key_id text NOT NULL,
    minted_at timestamp with time zone DEFAULT now() NOT NULL,
    key_grant_emitted_at timestamp with time zone,
    CONSTRAINT federation_community_dek_destroyed_has_no_key CHECK (((key_state = 'destroyed'::text) = (wrapped_dek IS NULL))),
    CONSTRAINT federation_community_dek_epoch_check CHECK ((epoch >= 0)),
    CONSTRAINT federation_community_dek_key_state_check CHECK ((key_state = ANY (ARRAY['enabled'::text, 'disabled'::text, 'destroyed'::text]))),
    CONSTRAINT federation_community_dek_wrap_algorithm_check CHECK ((wrap_algorithm = 'aes256_gcm_content_master'::text))
);

COMMENT ON COLUMN cirislens.federation_community_dek.minter_key_id IS 'The occurrence whose cascade minted this epoch (CIRISPersist#848). `__this_node__` only between V145 and the boot-time resolution; a surviving sentinel aborts the boot.';

COMMENT ON COLUMN cirislens.federation_community_dek.minted_at IS 'When this minter minted the DEK; a removal admitted after it rotates the counter before the next seal (BLOB_REPLICATION.md §15).';

COMMENT ON COLUMN cirislens.federation_community_dek.key_grant_emitted_at IS 'When this node last emitted the epoch''s KeyGrant set; NULL or not later than the newest member grant means DIRTY — the next write door or the boot sweep emits (CIRISPersist#848, BLOB_REPLICATION.md §14).';

CREATE TABLE cirislens.federation_community_dek_epoch (
    community_key_id text NOT NULL,
    epoch bigint DEFAULT 0 NOT NULL,
    rotated_at timestamp with time zone DEFAULT now() NOT NULL,
    retain_past_epochs integer,
    minter_key_id text NOT NULL,
    CONSTRAINT federation_community_dek_epoch_epoch_check CHECK ((epoch >= 0)),
    CONSTRAINT federation_community_dek_epoch_retain_past_epochs_check CHECK (((retain_past_epochs IS NULL) OR (retain_past_epochs >= 0)))
);

CREATE TABLE cirislens.federation_community_dek_member_grants (
    community_key_id text NOT NULL,
    epoch bigint NOT NULL,
    member_key_id text NOT NULL,
    wrap_algorithm text NOT NULL,
    wrapped_dek text NOT NULL,
    created_at timestamp with time zone DEFAULT now() NOT NULL,
    minter_key_id text NOT NULL,
    CONSTRAINT federation_community_dek_member_grants_epoch_check CHECK ((epoch >= 0)),
    CONSTRAINT federation_community_dek_member_grants_wrap_algorithm_check CHECK ((wrap_algorithm = 'x25519_mlkem768_aes256_gcm_hkdf_sha256'::text))
);

CREATE TABLE cirislens.federation_community_membership_revocations (
    community_key_id text NOT NULL,
    removed_identity_key_id text NOT NULL,
    removed_at timestamp with time zone NOT NULL,
    effective_at timestamp with time zone NOT NULL,
    reason text,
    witness_set jsonb DEFAULT '[]'::jsonb NOT NULL,
    persist_row_hash text NOT NULL,
    authority_key_id text,
    scrub_signature_classical text,
    scrub_signature_pqc text,
    admitted_at timestamp with time zone NOT NULL,
    cosignatures jsonb DEFAULT '[]'::jsonb NOT NULL,
    attestation_id text,
    CONSTRAINT federation_community_membership_revocations_witness_set_check CHECK ((jsonb_typeof(witness_set) = 'array'::text))
);

COMMENT ON COLUMN cirislens.federation_community_membership_revocations.admitted_at IS 'NOT NULL on both dialects since sqlite V141 (CIRISPersist#828); postgres has been NOT NULL since V130.';

CREATE TABLE cirislens.federation_community_membership_widenings (
    community_key_id text NOT NULL,
    member_key_id text NOT NULL,
    joined_at timestamp with time zone NOT NULL,
    effective_at timestamp with time zone NOT NULL,
    role text,
    persist_row_hash text NOT NULL,
    authority_key_id text,
    scrub_signature_classical text,
    scrub_signature_pqc text,
    admitted_at timestamp with time zone NOT NULL,
    cosignatures jsonb DEFAULT '[]'::jsonb NOT NULL,
    attestation_id text
);

CREATE TABLE cirislens.federation_content_kem_identity (
    id integer NOT NULL,
    key_kind text NOT NULL,
    content_x25519_pubkey_b64 text NOT NULL,
    content_ml_kem_768_pubkey_b64 text NOT NULL,
    content_x25519_privkey_sealed_b64 text NOT NULL,
    content_ml_kem_768_privkey_sealed_b64 text NOT NULL,
    created_at timestamp with time zone DEFAULT now() NOT NULL,
    CONSTRAINT federation_content_kem_identity_id_check CHECK ((id = 0)),
    CONSTRAINT federation_content_kem_identity_key_kind_check CHECK ((key_kind = ANY (ARRAY['software'::text, 'hardware'::text])))
);

CREATE TABLE cirislens.federation_content_master (
    id integer NOT NULL,
    key_kind text NOT NULL,
    master_key_b64 text,
    descriptor text NOT NULL,
    created_at timestamp with time zone DEFAULT now() NOT NULL,
    CONSTRAINT federation_content_master_id_check CHECK ((id = 0)),
    CONSTRAINT federation_content_master_key_kind_check CHECK ((key_kind = ANY (ARRAY['software'::text, 'hardware'::text])))
);

CREATE TABLE cirislens.federation_cosign_aliases (
    alias_attestation_id text NOT NULL,
    quorum_key text NOT NULL,
    held_attestation_id text NOT NULL
);

CREATE TABLE cirislens.federation_cosign_pending (
    quorum_key text NOT NULL,
    group_kind text NOT NULL,
    group_key_id text NOT NULL,
    proposer_key_id text NOT NULL,
    received_at timestamp with time zone NOT NULL,
    settled_at timestamp with time zone,
    outcome text,
    CONSTRAINT federation_cosign_pending_check CHECK (((settled_at IS NULL) = (outcome IS NULL))),
    CONSTRAINT federation_cosign_pending_group_kind_check CHECK ((group_kind = ANY (ARRAY['family'::text, 'community'::text])))
);

CREATE TABLE cirislens.federation_cosign_signatures (
    attestation_id text NOT NULL,
    quorum_key text NOT NULL,
    signer_key_id text NOT NULL
);

CREATE TABLE cirislens.federation_dag_chunks (
    manifest_sha256 bytea NOT NULL,
    seq bigint NOT NULL,
    chunk_sha256 bytea NOT NULL,
    stream_id text NOT NULL,
    CONSTRAINT federation_dag_chunks_chunk_sha256_check CHECK ((octet_length(chunk_sha256) = 32)),
    CONSTRAINT federation_dag_chunks_manifest_sha256_check CHECK ((octet_length(manifest_sha256) = 32)),
    CONSTRAINT federation_dag_chunks_seq_check CHECK ((seq >= 0))
);

CREATE TABLE cirislens.federation_families (
    family_key_id text NOT NULL,
    family_name text NOT NULL,
    members jsonb DEFAULT '[]'::jsonb NOT NULL,
    founded_at timestamp with time zone NOT NULL,
    consensus_protocol text NOT NULL,
    consensus_protocol_entrenched boolean DEFAULT false NOT NULL,
    persist_row_hash text NOT NULL,
    version integer DEFAULT 1 NOT NULL,
    authority_key_id text,
    scrub_signature_classical text,
    scrub_signature_pqc text,
    admitted_at timestamp with time zone NOT NULL,
    supersede_proof jsonb,
    cosignatures jsonb DEFAULT '[]'::jsonb NOT NULL,
    dissolved_at timestamp with time zone,
    prev_head_digest text DEFAULT ''::text NOT NULL,
    charter_digest text DEFAULT ''::text NOT NULL,
    attestation_id text,
    CONSTRAINT federation_families_members_check CHECK ((jsonb_typeof(members) = 'array'::text))
);

COMMENT ON COLUMN cirislens.federation_families.admitted_at IS 'NOT NULL on both dialects since sqlite V141 (CIRISPersist#828); postgres has been NOT NULL since V130.';

CREATE TABLE cirislens.federation_family_membership_revocations (
    family_key_id text NOT NULL,
    removed_identity_key_id text NOT NULL,
    removed_at timestamp with time zone NOT NULL,
    effective_at timestamp with time zone NOT NULL,
    reason text,
    witness_set jsonb DEFAULT '[]'::jsonb NOT NULL,
    persist_row_hash text NOT NULL,
    authority_key_id text,
    scrub_signature_classical text,
    scrub_signature_pqc text,
    admitted_at timestamp with time zone NOT NULL,
    cosignatures jsonb DEFAULT '[]'::jsonb NOT NULL,
    attestation_id text,
    CONSTRAINT federation_family_membership_revocations_witness_set_check CHECK ((jsonb_typeof(witness_set) = 'array'::text))
);

COMMENT ON COLUMN cirislens.federation_family_membership_revocations.admitted_at IS 'NOT NULL on both dialects since sqlite V141 (CIRISPersist#828); postgres has been NOT NULL since V130.';

CREATE TABLE cirislens.federation_family_membership_widenings (
    family_key_id text NOT NULL,
    member_key_id text NOT NULL,
    joined_at timestamp with time zone NOT NULL,
    effective_at timestamp with time zone NOT NULL,
    role text,
    persist_row_hash text NOT NULL,
    authority_key_id text,
    scrub_signature_classical text,
    scrub_signature_pqc text,
    admitted_at timestamp with time zone NOT NULL,
    cosignatures jsonb DEFAULT '[]'::jsonb NOT NULL,
    attestation_id text
);

CREATE TABLE cirislens.federation_group_versions (
    cohort text NOT NULL,
    group_key_id text NOT NULL,
    version integer NOT NULL,
    snapshot jsonb NOT NULL,
    change_authorization jsonb,
    superseded_at timestamp with time zone NOT NULL,
    persist_row_hash text NOT NULL,
    CONSTRAINT federation_group_versions_cohort_check CHECK ((cohort = ANY (ARRAY['family'::text, 'community'::text, 'affiliations'::text])))
);

CREATE TABLE cirislens.federation_identity_occurrence_history (
    identity_key_id text NOT NULL,
    occurrence_key_id text NOT NULL,
    asserted_at timestamp with time zone NOT NULL,
    valid_until timestamp with time zone,
    attesting_key_id text DEFAULT ''::text NOT NULL,
    signed_envelope text,
    signature text
);

CREATE TABLE cirislens.federation_identity_occurrence_revocations (
    identity_key_id text NOT NULL,
    occurrence_key_id text NOT NULL,
    revoked_at timestamp with time zone NOT NULL,
    effective_at timestamp with time zone NOT NULL,
    reason text,
    witness_set jsonb DEFAULT '[]'::jsonb NOT NULL,
    persist_row_hash text NOT NULL,
    attesting_key_id text,
    signed_envelope text,
    signature text,
    admitted_at timestamp with time zone NOT NULL,
    legacy_framed boolean DEFAULT false NOT NULL,
    CONSTRAINT federation_identity_occurrence_revocations_witness_set_check CHECK ((jsonb_typeof(witness_set) = 'array'::text))
);

COMMENT ON COLUMN cirislens.federation_identity_occurrence_revocations.admitted_at IS 'NOT NULL on both dialects since sqlite V141 (CIRISPersist#828); postgres has been NOT NULL since V130.';

CREATE TABLE cirislens.federation_identity_occurrences (
    identity_key_id text NOT NULL,
    occurrence_key_id text NOT NULL,
    device_class text NOT NULL,
    hardware_attestation text,
    asserted_at timestamp with time zone NOT NULL,
    valid_until timestamp with time zone,
    persist_row_hash text NOT NULL,
    pubkey_x25519_base64 text,
    pubkey_ml_kem_768_base64 text,
    attesting_key_id text,
    signed_envelope text,
    signature text,
    transport_binding text,
    admitted_at timestamp with time zone NOT NULL,
    attestation_id text,
    CONSTRAINT federation_identity_occurrences_device_class_check CHECK ((device_class = ANY (ARRAY['phone'::text, 'laptop'::text, 'server'::text, 'embedded'::text, 'agent'::text, 'service'::text])))
);

COMMENT ON COLUMN cirislens.federation_identity_occurrences.admitted_at IS 'NOT NULL on both dialects since sqlite V141 (CIRISPersist#828); postgres has been NOT NULL since V130.';

CREATE TABLE cirislens.federation_key_grant_pending (
    at_rest_sha256 bytea NOT NULL,
    cohort_scope text NOT NULL,
    attestation_id text NOT NULL,
    signer_key_id text NOT NULL,
    created_at timestamp with time zone DEFAULT now() NOT NULL,
    CONSTRAINT federation_key_grant_pending_at_rest_sha256_check CHECK ((octet_length(at_rest_sha256) = 32))
);

COMMENT ON TABLE cirislens.federation_key_grant_pending IS 'Content-axis KeyGrant sets admitted before their bytes; the adopt takes its rows by (sha, scope) and projects the author-signed ones (CIRISPersist#848, §13).';

CREATE TABLE cirislens.federation_key_registration_history (
    history_id bigint NOT NULL,
    key_id text NOT NULL,
    registration_envelope text NOT NULL,
    original_content_hash bytea NOT NULL,
    scrub_signature_classical text NOT NULL,
    scrub_signature_pqc text,
    scrub_key_id text NOT NULL,
    scrub_timestamp timestamp with time zone NOT NULL,
    replaced_at timestamp with time zone NOT NULL,
    replaced_by_hash text NOT NULL,
    replaced_row_hash text,
    replacement_kind text DEFAULT 'rebind'::text NOT NULL,
    CONSTRAINT federation_key_registration_history_replacement_kind_check CHECK ((replacement_kind = ANY (ARRAY['rebind'::text, 'invalid_replaced'::text])))
);

CREATE SEQUENCE cirislens.federation_key_registration_history_history_id_seq
    START WITH 1
    INCREMENT BY 1
    NO MINVALUE
    NO MAXVALUE
    CACHE 1;

ALTER SEQUENCE cirislens.federation_key_registration_history_history_id_seq OWNED BY cirislens.federation_key_registration_history.history_id;

CREATE TABLE cirislens.federation_keys (
    key_id text NOT NULL,
    pubkey_ed25519_base64 text NOT NULL,
    pubkey_ml_dsa_65_base64 text,
    algorithm text NOT NULL,
    identity_type text NOT NULL,
    identity_ref text NOT NULL,
    valid_from timestamp with time zone NOT NULL,
    valid_until timestamp with time zone,
    registration_envelope text NOT NULL,
    original_content_hash bytea NOT NULL,
    scrub_signature_classical text NOT NULL,
    scrub_signature_pqc text,
    scrub_key_id text NOT NULL,
    scrub_timestamp timestamp with time zone NOT NULL,
    pqc_completed_at timestamp with time zone,
    persist_row_hash text NOT NULL,
    consent_role text DEFAULT 'unregistered'::text NOT NULL,
    trust_type text DEFAULT 'temporary'::text NOT NULL,
    trust_relationship text DEFAULT 'direct'::text NOT NULL,
    trust_domains text[],
    trusted_at timestamp with time zone DEFAULT now() NOT NULL,
    trusted_by text,
    expires_at timestamp with time zone,
    roles text[],
    attestation_evidence jsonb,
    additional_scrubs text DEFAULT '[]'::text NOT NULL,
    admitted_at timestamp with time zone NOT NULL,
    mutated_at timestamp with time zone,
    attestation_id text,
    CONSTRAINT federation_keys_accord_holder_requires_attestation CHECK (((identity_type <> 'accord_holder'::text) OR (attestation_evidence IS NOT NULL))),
    CONSTRAINT federation_keys_algorithm_check CHECK ((algorithm = 'hybrid'::text)),
    CONSTRAINT federation_keys_consent_role_check CHECK ((consent_role = ANY (ARRAY['unregistered'::text, 'temporary'::text, 'partnered'::text, 'anonymous'::text, 'authorized_review'::text, 'peer'::text]))),
    CONSTRAINT federation_keys_trust_relationship_check CHECK ((trust_relationship = ANY (ARRAY['direct'::text, 'registry'::text]))),
    CONSTRAINT federation_keys_trust_type_check CHECK ((trust_type = ANY (ARRAY['temporary'::text, 'partnered'::text, 'anonymous'::text])))
);

COMMENT ON COLUMN cirislens.federation_keys.registration_envelope IS 'v31.0.0 (CIRISPersist#645) — TEXT, not JSONB: the exact bytes the producer signed. See V122 for the measurement and for what pre-V122 rows lost. SQLite parity: TEXT since V004.';

COMMENT ON COLUMN cirislens.federation_keys.consent_role IS 'V020 (CIRISAgent#760 §RC lock) ratified by CC 3.4.7.2 consent-counter (CIRISPersist#365, v12.7.0) — Counter-RII consent_role. Single flat role token (unregistered / temporary / partnered / anonymous / authorized_review / peer) gating Counter-RII probe detection applied by a consumer (edge ProbePatternObserver / RATCHET). Mutable, overwrite-on-revoke (OQ-1) via Engine.set_consent_role; ''unregistered'' = no assigned role (wire None). Excluded from persist_row_hash — NOT part of the signed registration content.';

COMMENT ON COLUMN cirislens.federation_keys.attestation_evidence IS 'v2.5.0 (CIRISPersist#102 Ask 8) — hardware-attestation evidence captured at key-binding time. REQUIRED for identity_type = ''accord_holder'' rows per FSD-002 §7.3. JSONB shape: {platform_attestation: <PlatformAttestation JSON>, nonce_captured_at: <RFC3339>}. The HardwareAttestationPolicy admission hook validates variant + field presence + nonce freshness; the CHECK constraint here catches direct-SQL bypass. Active cert-chain validation is deferred to CIRISVerify#32 Ask 5.';

COMMENT ON COLUMN cirislens.federation_keys.additional_scrubs IS 'V096 (CIRISPersist#383, CC 3.4.7.1 / CIRISVerify#174) — the 2nd..Nth anchor scrub signatures over the SAME canonical registration_envelope, as a JSON array of {scrub_key_id, scrub_signature_classical, scrub_signature_pqc?} (KeyRecord.additional_scrubs). Scrub #1 stays in scrub_key_id/scrub_signature_*. The `canonical` role is conferred only on a record whose scrub set has >=2 distinct anchor holders with VALID signatures (the 2-of-3 add gate); root_binding still roots via any one scrub. DEFAULT ''[]'' — an empty set serializes away so a single-scrub row''s persist_row_hash is byte-identical to pre-#383.';

COMMENT ON COLUMN cirislens.federation_keys.admitted_at IS 'NOT NULL on both dialects since sqlite V141 (CIRISPersist#828); postgres has been NOT NULL since V126.';

COMMENT ON CONSTRAINT federation_keys_accord_holder_requires_attestation ON cirislens.federation_keys IS 'v2.5.0 — defense in depth. accord_holder rows MUST carry attestation_evidence; the admission hook is the load-bearing point, the CHECK constraint is the backstop against direct-SQL writes that skip the admission path.';

CREATE TABLE cirislens.federation_lineage_head_cosigns (
    lineage_key_id text NOT NULL,
    head_digest_sha256_hex text NOT NULL,
    witness_key_id text NOT NULL,
    head_asserted_at text NOT NULL,
    prior_head_digest_sha256_hex text,
    signed_at text NOT NULL,
    signature_classical text NOT NULL,
    signature_pqc text,
    admitted_at timestamp with time zone DEFAULT now() NOT NULL
);

CREATE TABLE cirislens.federation_location_proofs (
    subject_key_id text NOT NULL,
    cell_id text NOT NULL,
    cell_resolution smallint NOT NULL,
    asserted_at timestamp with time zone NOT NULL,
    valid_until timestamp with time zone,
    attestation_evidence bytea,
    withdrawn_at timestamp with time zone,
    persist_row_hash text NOT NULL,
    authority_key_id text,
    scrub_signature_classical text,
    scrub_signature_pqc text,
    admitted_at timestamp with time zone NOT NULL,
    CONSTRAINT federation_location_proofs_cell_resolution_check CHECK (((cell_resolution >= 0) AND (cell_resolution <= 15)))
);

COMMENT ON COLUMN cirislens.federation_location_proofs.admitted_at IS 'NOT NULL on both dialects since sqlite V141 (CIRISPersist#828); postgres has been NOT NULL since V130.';

CREATE TABLE cirislens.federation_manifest_children (
    root_sha256 bytea NOT NULL,
    child_index bigint NOT NULL,
    child_sha256 bytea NOT NULL,
    CONSTRAINT federation_manifest_children_child_index_check CHECK ((child_index >= 0))
);

CREATE TABLE cirislens.federation_peer_metadata (
    key_id text NOT NULL,
    alias text,
    trust text DEFAULT 'untrusted'::text NOT NULL,
    notes text,
    policy_blob jsonb,
    transport_identity text,
    removed_at timestamp with time zone,
    inserted_at timestamp with time zone DEFAULT now() NOT NULL,
    updated_at timestamp with time zone DEFAULT now() NOT NULL,
    persist_row_hash text NOT NULL,
    CONSTRAINT federation_peer_metadata_trust_check CHECK ((trust = ANY (ARRAY['untrusted'::text, 'trusted'::text, 'restricted'::text, 'blocked'::text])))
);

COMMENT ON TABLE cirislens.federation_peer_metadata IS 'v3.1.0 (CIRISPersist#117) — operator-local per-instance peer metadata. Sibling to federation_keys (FK with ON DELETE CASCADE). Carries alias/trust/notes/policy_blob/transport_identity for the six FederationDirectory::*_peer_* mutation methods that back CIRISEdge v0.13.0 UniFFI peer-mgmt. trust is enum-typed via CHECK; rest is opaque to persist.';

CREATE TABLE cirislens.federation_revocation_quorum_state (
    revocation_id text NOT NULL,
    us_observed_at timestamp with time zone,
    eu_observed_at timestamp with time zone,
    apac_observed_at timestamp with time zone,
    quorum_reached_at timestamp with time zone,
    quorum_weight smallint DEFAULT 1 NOT NULL,
    updated_at timestamp with time zone DEFAULT now() NOT NULL,
    CONSTRAINT federation_revocation_quorum_state_quorum_weight_check CHECK (((quorum_weight >= 1) AND (quorum_weight <= 3)))
);

CREATE TABLE cirislens.federation_revocations (
    revocation_id text DEFAULT (gen_random_uuid())::text NOT NULL,
    revoked_key_id text,
    revoking_key_id text NOT NULL,
    reason text,
    revoked_at timestamp with time zone NOT NULL,
    effective_at timestamp with time zone NOT NULL,
    revocation_envelope text NOT NULL,
    original_content_hash bytea NOT NULL,
    scrub_signature_classical text NOT NULL,
    scrub_signature_pqc text,
    scrub_key_id text NOT NULL,
    scrub_timestamp timestamp with time zone NOT NULL,
    pqc_completed_at timestamp with time zone,
    persist_row_hash text NOT NULL,
    observed_region text DEFAULT 'us'::text NOT NULL,
    revoked_after timestamp with time zone,
    admitted_at timestamp with time zone NOT NULL,
    revoked_key_sha256_ed25519_raw text NOT NULL,
    attestation_id text,
    CONSTRAINT federation_revocations_observed_region_check CHECK ((observed_region = ANY (ARRAY['us'::text, 'eu'::text, 'apac'::text]))),
    CONSTRAINT federation_revocations_subject_digest_shape CHECK ((revoked_key_sha256_ed25519_raw ~ '^[0-9a-f]{64}$'::text))
);

COMMENT ON COLUMN cirislens.federation_revocations.revocation_id IS 'v31.1.0 (CIRISPersist#622) — TEXT, not UUID. `Revocation::revocation_id` is a String and nothing constrains it to UUID shape; memory and SQLite have always stored any TEXT. Same relaxation V121 applied to attestation_id.';

COMMENT ON COLUMN cirislens.federation_revocations.revocation_envelope IS 'v31.0.0 (CIRISPersist#645) — TEXT, not JSONB. V118 reads `revoked_after` out of this envelope; it is the SIGNED bound, so byte fidelity is load-bearing. SQLite parity: TEXT since V004.';

COMMENT ON COLUMN cirislens.federation_revocations.admitted_at IS 'NOT NULL on both dialects since sqlite V141 (CIRISPersist#828); postgres has been NOT NULL since V123.';

CREATE TABLE cirislens.federation_role_withdrawals (
    role text NOT NULL,
    key_id text NOT NULL,
    withdrawn_at timestamp with time zone NOT NULL,
    authority_decision_digest text NOT NULL,
    superseded_by text,
    persist_row_hash text NOT NULL
);

CREATE TABLE cirislens.federation_scope_blobs (
    record_id bytea NOT NULL,
    symbol_index integer NOT NULL,
    nonce bytea NOT NULL,
    ciphertext bytea NOT NULL,
    tag bytea NOT NULL,
    group_dek_epoch bigint NOT NULL,
    admitted_at timestamp with time zone DEFAULT now() NOT NULL,
    last_accessed_at timestamp with time zone DEFAULT now() NOT NULL,
    CONSTRAINT federation_scope_blobs_group_dek_epoch_check CHECK ((group_dek_epoch >= 0)),
    CONSTRAINT federation_scope_blobs_symbol_index_check CHECK ((symbol_index >= 0))
);

COMMENT ON TABLE cirislens.federation_scope_blobs IS 'v9.1.0 (CIRISPersist#243, CC 1.13.3 / FSD §2.4) — caller-pre-encrypted (XChaCha20-Poly1305) RaptorQ symbol store at community/family/self scope. PK (record_id, symbol_index). LRU + capacity eviction (no trust-scoring); opaque holder identity.';

CREATE TABLE cirislens.federation_self_roster_proposals (
    attestation_id text NOT NULL,
    identity_key_id text NOT NULL,
    received_at timestamp with time zone NOT NULL,
    settled_at timestamp with time zone,
    outcome text,
    CONSTRAINT federation_self_roster_proposals_check CHECK (((settled_at IS NULL) = (outcome IS NULL)))
);

CREATE TABLE cirislens.federation_stream_chunks (
    stream_id text NOT NULL,
    seq bigint NOT NULL,
    chunk_sha bytea NOT NULL,
    epoch bigint DEFAULT 0 NOT NULL,
    size_bytes bigint NOT NULL,
    created_at timestamp with time zone DEFAULT now() NOT NULL,
    sealed_at timestamp with time zone,
    plaintext_size_bytes bigint DEFAULT 0 NOT NULL,
    CONSTRAINT federation_stream_chunks_chunk_sha_check CHECK ((octet_length(chunk_sha) = 32)),
    CONSTRAINT federation_stream_chunks_plaintext_size_bytes_check CHECK ((plaintext_size_bytes >= 0)),
    CONSTRAINT federation_stream_chunks_size_bytes_check CHECK ((size_bytes >= 0))
);

COMMENT ON TABLE cirislens.federation_stream_chunks IS 'v4.1 (CIRISPersist#142, Cut C1a) — live-stream chunk index. (stream_id, seq) PK is the monotonicity guarantee; chunk_sha references a federation_blobs row. put_blob_chunk appends; seal_stream walks seq-ordered to build the chunk_dag manifest. epoch stored for the Cut C3 DEK cascade (no crypto this cut).';

COMMENT ON COLUMN cirislens.federation_stream_chunks.seq IS 'Monotonic per-stream sequence. Part of the PK — a re-used seq is rejected (append-only enforcement). u64 in Rust, bound i64.';

COMMENT ON COLUMN cirislens.federation_stream_chunks.epoch IS 'Key-rotation epoch (CEG §10.5.3). Stored now; the epoch-DEK cascade is Cut C3 (no crypto this cut).';

COMMENT ON COLUMN cirislens.federation_stream_chunks.plaintext_size_bytes IS '#832 (§12.6) — the chunk''s CONTENT length. Equals size_bytes for a plaintext chunk; size_bytes − 36 (CRBLOB envelope overhead) for a sealed one. The sealed manifest and stream_chunks report this, never the stored length.';

CREATE TABLE cirislens.federation_stream_dek_grants (
    stream_id text NOT NULL,
    epoch bigint NOT NULL,
    sealer_key_id text NOT NULL,
    recipient_key_id text NOT NULL,
    wrap_algorithm text NOT NULL,
    wrapped_dek text NOT NULL,
    cohort_scope text NOT NULL,
    created_at timestamp with time zone DEFAULT now() NOT NULL,
    CONSTRAINT federation_stream_dek_grants_cohort_scope_v193 CHECK ((cohort_scope = ANY (ARRAY['self'::text, 'family'::text, 'community'::text, 'affiliations'::text]))),
    CONSTRAINT federation_stream_dek_grants_epoch_check CHECK ((epoch >= 0)),
    CONSTRAINT federation_stream_dek_grants_wrap_algorithm_check CHECK ((wrap_algorithm = 'x25519_mlkem768_aes256_gcm_hkdf_sha256'::text))
);

CREATE TABLE cirislens.federation_stream_deks (
    stream_id text NOT NULL,
    epoch bigint NOT NULL,
    owner_key_id text NOT NULL,
    cohort_scope text NOT NULL,
    group_key_id text NOT NULL,
    self_retention_wrap text NOT NULL,
    minted_at timestamp with time zone DEFAULT now() NOT NULL,
    closed_at timestamp with time zone,
    terminated_at timestamp with time zone,
    key_grant_emitted_at timestamp with time zone,
    supplied boolean DEFAULT false NOT NULL,
    room_epoch bigint,
    evicted_at timestamp with time zone,
    CONSTRAINT federation_stream_deks_cohort_scope_v193 CHECK ((cohort_scope = ANY (ARRAY['self'::text, 'family'::text, 'community'::text, 'affiliations'::text]))),
    CONSTRAINT federation_stream_deks_epoch_check CHECK ((epoch >= 0)),
    CONSTRAINT federation_stream_deks_room_epoch_check CHECK (((room_epoch IS NULL) OR (room_epoch >= 0)))
);

CREATE TABLE cirislens.federation_stream_delivery_receipts (
    stream_id text NOT NULL,
    subscriber_key_id text NOT NULL,
    epoch bigint DEFAULT 0 NOT NULL,
    k bigint NOT NULL,
    chunk_root bytea NOT NULL,
    signature_blob bytea NOT NULL,
    received_at timestamp with time zone NOT NULL,
    CONSTRAINT federation_stream_delivery_receipts_chunk_root_check CHECK ((octet_length(chunk_root) = 32))
);

COMMENT ON TABLE cirislens.federation_stream_delivery_receipts IS 'v4.1 (CIRISPersist#142, Cut C4, CEG §10.5.4) — subscriber-signed proof-of-delivery for stream chunks. put_delivery_receipt verifies the subscriber''s hybrid signature against federation_keys, then JOINs the receipt''s chunk_root against a published federation_stream_sth row at tree_size >= k (the signature is necessary but NOT sufficient — a subscriber cannot acknowledge an unpublished root), then inserts. (stream_id, subscriber_key_id, k) PK = append-only; a same-key different-root receipt is a subscriber equivocation attempt and is rejected. Proof-of-delivery, not proof-of-consumption. Persist validates but does NOT adjudicate.';

COMMENT ON COLUMN cirislens.federation_stream_delivery_receipts.k IS 'Chunk index acknowledged (K). u64 in Rust, bound i64 (BIGINT). Part of the PK. The put gate requires a published STH at tree_size >= k.';

COMMENT ON COLUMN cirislens.federation_stream_delivery_receipts.chunk_root IS 'The STH root the subscriber acknowledges. JOINed against federation_stream_sth.root_hash (tree_size >= k) BEFORE insert; an unpublished root is rejected. 32 bytes.';

COMMENT ON COLUMN cirislens.federation_stream_delivery_receipts.signature_blob IS 'Serialized ciris_crypto::HybridSignature (JSON-as-bytes) over receipt_signing_bytes; verified against the federation_keys row named by subscriber_key_id.';

CREATE TABLE cirislens.federation_stream_epoch_counts (
    stream_id text NOT NULL,
    epoch bigint NOT NULL,
    chunk_count bigint NOT NULL,
    CONSTRAINT federation_stream_epoch_counts_chunk_count_check CHECK ((chunk_count >= 0))
);

CREATE TABLE cirislens.federation_stream_sth (
    stream_id text NOT NULL,
    tree_size bigint NOT NULL,
    epoch bigint DEFAULT 0 NOT NULL,
    root_hash bytea NOT NULL,
    signed_at timestamp with time zone NOT NULL,
    producer_key_id text NOT NULL,
    signature_blob bytea NOT NULL,
    witness_signatures jsonb DEFAULT '[]'::jsonb NOT NULL,
    CONSTRAINT federation_stream_sth_root_hash_check CHECK ((octet_length(root_hash) = 32))
);

COMMENT ON TABLE cirislens.federation_stream_sth IS 'v4.1 (CIRISPersist#142, Cut C1b, CEG §10.5.1) — per-stream transparency log: producer-signed Signed Tree Heads over a stream''s chunk hashes (leaves live in federation_stream_chunks). put_stream_sth recomputes the root from persist''s own chunks + asserts equality with the claimed root (anti-equivocation gate), then verifies the producer''s hybrid signature against federation_keys, then inserts. (stream_id, tree_size) PK = append-only/monotonic; a same-size different-root STH is an equivocation attempt and is rejected. Persist does NOT sign stream STHs.';

COMMENT ON COLUMN cirislens.federation_stream_sth.tree_size IS 'RFC 6962 tree size (leaf count). u64 in Rust, bound i64 (BIGINT). Part of the PK.';

COMMENT ON COLUMN cirislens.federation_stream_sth.root_hash IS 'Merkle root the STH claims. Recomputed from federation_stream_chunks and asserted equal BEFORE insert (anti-equivocation gate). 32 bytes.';

COMMENT ON COLUMN cirislens.federation_stream_sth.signature_blob IS 'Serialized ciris_crypto::HybridSignature (JSON-as-bytes) over the STH signing bytes; verified against the federation_keys row named by producer_key_id.';

CREATE TABLE cirislens.federation_streams (
    stream_id text NOT NULL,
    cohort_scope text NOT NULL,
    community_key_id text,
    owner_key_id text,
    created_at timestamp with time zone DEFAULT now() NOT NULL,
    abandoned_at timestamp with time zone
);

COMMENT ON TABLE cirislens.federation_streams IS '#837 (§12.9, I41) — one row per stream_id: the cohort, community and first ATTRIBUTED writer (derived key id) of its first append. Written insert-if-absent by the chunk floor in the first chunk''s transaction; every later append must match all three or is refused at that chunk. owner_key_id NULL = unclaimed (backfilled or commons-started); the first attributed append adopts it.';

COMMENT ON COLUMN cirislens.federation_streams.owner_key_id IS 'The first attributed writer''s DERIVED federation key id (never an alias, I23). NULL = unclaimed. A refusal to a non-owner never names this value.';

CREATE TABLE cirislens.federation_trust_direction_held (
    attestation_id text NOT NULL
);

CREATE TABLE cirislens.federation_trust_grants (
    grant_id uuid DEFAULT gen_random_uuid() NOT NULL,
    grantee_key text NOT NULL,
    granter_key text NOT NULL,
    purpose text NOT NULL,
    scope text NOT NULL,
    granted_at timestamp with time zone DEFAULT now() NOT NULL,
    expires_at timestamp with time zone,
    revoked_at timestamp with time zone,
    revoked_by text,
    chain_event_id bigint NOT NULL,
    chain_event_hash bytea NOT NULL,
    tenant_id text NOT NULL,
    CONSTRAINT federation_trust_grants_check CHECK ((granter_key <> grantee_key)),
    CONSTRAINT federation_trust_grants_check1 CHECK (((revoked_at IS NULL) OR (revoked_by IS NOT NULL))),
    CONSTRAINT federation_trust_grants_purpose_check CHECK ((purpose = ANY (ARRAY['technical'::text, 'deferral'::text, 'contribution'::text, 'service'::text])))
);

CREATE TABLE cirislens.federation_vote_windows (
    action_id text NOT NULL,
    first_held_at timestamp with time zone NOT NULL
);

CREATE TABLE cirislens.federation_withdraws_admission_depths (
    attestation_id text NOT NULL,
    depth integer NOT NULL,
    CONSTRAINT federation_withdraws_admission_depths_depth_check CHECK (((depth >= 0) AND (depth <= 16)))
);

CREATE TABLE cirislens.feedback_mappings (
    feedback_id text NOT NULL,
    source_message_id text,
    target_thought_id text,
    feedback_type text,
    created_at timestamp with time zone DEFAULT now() NOT NULL
);

COMMENT ON TABLE cirislens.feedback_mappings IS 'v1.5.18 (CIRISPersist#59 #10) — feedback_mappings substrate. Absorbs CIRISAgent ciris_engine.db.feedback_mappings; the link between an inbound feedback Discord-message (or analogous wire-message id) and the agent thought it resolved against. 5 columns matching the agent. target_thought_id FK to cirislens.thoughts(thought_id), DEFERRABLE INITIALLY DEFERRED, only fires for non-NULL values (PG handles null FKs natively). Designed as a dedicated substrate rather than folded into cirisgraph_edges — feedback rides on typed-substrate FKs (thoughts), not graph-node FKs.';

CREATE TABLE cirislens.freshness_floor (
    target_key_id text NOT NULL,
    target_kind text NOT NULL,
    fresh_as_of timestamp with time zone NOT NULL,
    signer_form text NOT NULL,
    attesting_key_id text NOT NULL,
    signed_envelope text NOT NULL,
    signature text NOT NULL,
    cohort_scope text NOT NULL
);

CREATE TABLE cirislens.goals (
    goal_id text NOT NULL,
    declared_by_key_id text NOT NULL,
    declared_at timestamp with time zone NOT NULL,
    goal_text text NOT NULL,
    goal_text_canonical text NOT NULL,
    scale text NOT NULL,
    scope_cohort_id text,
    meta_dimension text NOT NULL,
    meta_rationale text NOT NULL,
    meta_deliberation jsonb,
    retired_at timestamp with time zone,
    persist_row_hash text NOT NULL,
    attestation_id text,
    score double precision,
    CONSTRAINT goals_meta_dimension_check CHECK ((meta_dimension = ANY (ARRAY['adaptivity'::text, 'coherence'::text, 'flourishing'::text, 'justice'::text, 'plurality'::text, 'sustainability'::text, 'wonder'::text]))),
    CONSTRAINT goals_projection_row CHECK ((((attestation_id IS NULL) AND (score IS NULL)) OR ((attestation_id IS NOT NULL) AND (score IS NOT NULL)))),
    CONSTRAINT goals_scope_cohort_discriminant CHECK ((((scale = 'cohort'::text) AND (scope_cohort_id IS NOT NULL)) OR ((scale <> 'cohort'::text) AND (scope_cohort_id IS NULL))))
);

COMMENT ON TABLE cirislens.goals IS 'v60.0.0 (CIRISPersist#988 item 4) — the projection of the goal:{scale}:v1 rows this node holds: one row per declaration (goal_id = its attestation_id), the head of its amendment chain (attestation_id), retired at the winning withdraws, absent once recanted. Written only by the attestation plane executor; byte-equal to its from-rows rebuild. A row with NULL attestation_id is a pre-V204 typed goal awaiting the rehome.';

CREATE TABLE cirislens.hard_case_events (
    event_id text NOT NULL,
    kind text NOT NULL,
    target_key_id text,
    subject_key_id text,
    detail jsonb DEFAULT '{}'::jsonb NOT NULL,
    emitted_at timestamp with time zone NOT NULL,
    attestation_id text,
    emitter_key_id text
);

CREATE TABLE cirislens.identity_canonical_binding (
    canonical_hash text NOT NULL,
    federation_key_id text NOT NULL,
    bound_at timestamp with time zone NOT NULL,
    binding_attestation_id text,
    inserted_at timestamp with time zone DEFAULT now() NOT NULL
);

COMMENT ON TABLE cirislens.identity_canonical_binding IS 'v3.9.0 (CIRISPersist#146 Ask 6, CEG §3.2.3 rule 3 + §4.2.2). Index of canonical-hash subjects bound to federation-enrolled identities. Populated when an identity:canonical_binding attestation is admitted. Consulted at withdraws admission to admit rule-3 proxy-chain revocations.';

CREATE TABLE cirislens.identity_sequences (
    identity text NOT NULL,
    stream text NOT NULL,
    next_value bigint DEFAULT 0 NOT NULL,
    updated_at timestamp with time zone DEFAULT now() NOT NULL
);

COMMENT ON TABLE cirislens.identity_sequences IS 'v1.7.1 (CIRISPersist#83) — atomic monotonic sequence counters keyed (identity, stream). next_value is the LAST issued value; the issuing UPSERT bumps then RETURNs.';

CREATE TABLE cirislens.incident_records (
    incident_id uuid NOT NULL,
    tenant_id text NOT NULL,
    severity text NOT NULL,
    category text NOT NULL,
    title text NOT NULL,
    description text,
    correlation_keys jsonb DEFAULT '[]'::jsonb NOT NULL,
    state text NOT NULL,
    first_seen_at timestamp with time zone NOT NULL,
    last_seen_at timestamp with time zone NOT NULL,
    resolved_at timestamp with time zone,
    resolution_notes text,
    occurrences integer DEFAULT 1 NOT NULL,
    signature text,
    signing_key_id text,
    signature_verified boolean DEFAULT false NOT NULL,
    persist_row_hash text NOT NULL,
    created_at timestamp with time zone DEFAULT now() NOT NULL,
    incident_type text,
    source_component text,
    handler_name text,
    exception_type text,
    stack_trace text,
    filename text,
    line_number integer,
    function_name text,
    impact text,
    urgency text,
    detection_method text,
    CONSTRAINT incident_records_occurrences_check CHECK ((occurrences >= 1)),
    CONSTRAINT incident_records_severity_check CHECK ((severity = ANY (ARRAY['info'::text, 'warning'::text, 'error'::text, 'critical'::text, 'low'::text, 'medium'::text, 'high'::text]))),
    CONSTRAINT incident_records_state_check CHECK ((state = ANY (ARRAY['open'::text, 'investigating'::text, 'resolved'::text, 'closed'::text, 'recurring'::text])))
);

COMMENT ON TABLE cirislens.incident_records IS 'v0.8.3 (CIRISPersist#37) — incident records absorbed from CIRISAgent IncidentManagementService. Correlation-keyed dedup on record (bumps occurrences for matching open incident); open→investigating→resolved→closed state machine enforced server-side (AV-55).';

COMMENT ON COLUMN cirislens.incident_records.incident_type IS 'v1.5.5 (CIRISPersist#56) — free-form incident type for agent forensics: ERROR | WARNING | EXCEPTION.';

COMMENT ON COLUMN cirislens.incident_records.source_component IS 'v1.5.5 — component that raised the incident.';

COMMENT ON COLUMN cirislens.incident_records.handler_name IS 'v1.5.5 — handler that processed the incident.';

COMMENT ON COLUMN cirislens.incident_records.exception_type IS 'v1.5.5 — Python exception class name (EXCEPTION-type incidents).';

COMMENT ON COLUMN cirislens.incident_records.stack_trace IS 'v1.5.5 — captured stack trace for EXCEPTION-type incidents.';

COMMENT ON COLUMN cirislens.incident_records.filename IS 'v1.5.5 — source file the incident was raised from (forensics).';

COMMENT ON COLUMN cirislens.incident_records.line_number IS 'v1.5.5 — source line number.';

COMMENT ON COLUMN cirislens.incident_records.function_name IS 'v1.5.5 — source function name.';

COMMENT ON COLUMN cirislens.incident_records.impact IS 'v1.5.5 — ITIL impact dimension (free-form).';

COMMENT ON COLUMN cirislens.incident_records.urgency IS 'v1.5.5 — ITIL urgency dimension (free-form).';

COMMENT ON COLUMN cirislens.incident_records.detection_method IS 'v1.5.5 — how the incident was detected.';

CREATE TABLE cirislens.key_escrows (
    escrow_id text NOT NULL,
    key_id text NOT NULL,
    org_id text NOT NULL,
    escrow_type text NOT NULL,
    custodian text NOT NULL,
    status text NOT NULL,
    created_at timestamp with time zone NOT NULL,
    expires_at timestamp with time zone,
    CONSTRAINT key_escrows_status CHECK ((status = ANY (ARRAY['active'::text, 'recovered'::text, 'revoked'::text, 'expired'::text]))),
    CONSTRAINT key_escrows_type CHECK ((escrow_type = ANY (ARRAY['steward'::text, 'attorney'::text, 'dual_custody'::text])))
);

COMMENT ON TABLE cirislens.key_escrows IS 'CC 4.4.3.2.8 archive_custody working index (CIRISPersist#752): custody metadata, never key material, never a claims plane.';

CREATE TABLE cirislens.known_wire_hashes (
    kind text NOT NULL,
    content_hash text NOT NULL,
    last_advertised_at timestamp with time zone NOT NULL,
    advertised_by text
);

CREATE TABLE cirislens.ledger_checkpoints (
    ledger_id text NOT NULL,
    seq bigint NOT NULL,
    balance_minor text NOT NULL,
    witness_refs jsonb NOT NULL,
    supersedes_ref text,
    source_envelope_ref text,
    created_at timestamp with time zone NOT NULL,
    CONSTRAINT ledger_checkpoints_seq_nonneg CHECK ((seq >= 0))
);

COMMENT ON TABLE cirislens.ledger_checkpoints IS 'CC 3.3.10.1 L5: co-witnessed balance snapshots. Immutable once written — a witnessed fact pins, never flips.';

CREATE TABLE cirislens.ledger_entry_ranges (
    ledger_id text NOT NULL,
    from_seq bigint NOT NULL,
    to_seq bigint NOT NULL,
    blob_ref text NOT NULL,
    head_hash_at_to text NOT NULL,
    created_at timestamp with time zone NOT NULL,
    CONSTRAINT ledger_entry_ranges_from_nonneg CHECK ((from_seq >= 0)),
    CONSTRAINT ledger_entry_ranges_ordered CHECK ((to_seq >= from_seq))
);

COMMENT ON TABLE cirislens.ledger_entry_ranges IS 'CC 3.3.10.1 L2/L6: which evidence_refs blob holds entries [from_seq, to_seq] of a chain.';

CREATE TABLE cirislens.ledger_fork_evidence (
    evidence_id text NOT NULL,
    ledger_id text NOT NULL,
    seq bigint NOT NULL,
    fork_kind text NOT NULL,
    evidence_json jsonb NOT NULL,
    detected_at timestamp with time zone NOT NULL,
    CONSTRAINT ledger_fork_evidence_kind CHECK ((fork_kind = ANY (ARRAY['double_head'::text, 'witness_contradiction'::text]))),
    CONSTRAINT ledger_fork_evidence_seq_nonneg CHECK ((seq >= 0))
);

CREATE TABLE cirislens.ledger_heads (
    ledger_id text NOT NULL,
    owner_key_id text NOT NULL,
    unit text NOT NULL,
    standard_version text NOT NULL,
    seq bigint,
    head_hash text,
    witness_anchor_ref text,
    source_envelope_ref text,
    created_at timestamp with time zone NOT NULL,
    updated_at timestamp with time zone NOT NULL,
    CONSTRAINT ledger_heads_head_pairs CHECK (((seq IS NULL) = (head_hash IS NULL))),
    CONSTRAINT ledger_heads_seq_nonneg CHECK (((seq IS NULL) OR (seq >= 0)))
);

COMMENT ON TABLE cirislens.ledger_heads IS 'CC 3.3.10.1 L1/L4 working index: one row per ledger triple; head + witness anchor. NOT an envelope plane.';

CREATE TABLE cirislens.maintenance_locks (
    lock_key text NOT NULL,
    locked_by text,
    locked_at timestamp with time zone,
    lock_timeout_seconds integer DEFAULT 300 NOT NULL,
    metadata jsonb,
    CONSTRAINT maintenance_locks_lock_timeout_seconds_check CHECK ((lock_timeout_seconds > 0))
);

COMMENT ON TABLE cirislens.maintenance_locks IS 'v1.5.15 (CIRISPersist#59 #7) — maintenance_locks substrate. Absorbs CIRISAgent ciris_engine.db.consolidation_locks; generalized to a generic lock_key-keyed family per the substrate spec since the steal-the-stale-via-timeout mechanism is not consolidation-specific. 5 columns (4 agent + 1 persist-only metadata JSONB). Coexists with the per-period cirisgraph.consolidation_locks (V015).';

CREATE TABLE cirislens.merkle_leaves (
    tenant_id text NOT NULL,
    leaf_index bigint NOT NULL,
    chain_event_id bigint NOT NULL,
    leaf_hash bytea NOT NULL,
    canonical_bytes bytea NOT NULL,
    leaf_serialized bytea NOT NULL,
    appended_at timestamp with time zone DEFAULT now() NOT NULL,
    CONSTRAINT merkle_leaves_leaf_hash_check CHECK ((octet_length(leaf_hash) = 32))
);

CREATE TABLE cirislens.merkle_sth_log (
    tenant_id text NOT NULL,
    tree_size bigint NOT NULL,
    root_hash bytea NOT NULL,
    signed_at timestamp with time zone DEFAULT now() NOT NULL,
    signer_key_id text NOT NULL,
    signature_blob bytea NOT NULL,
    witness_signatures jsonb DEFAULT '[]'::jsonb NOT NULL,
    CONSTRAINT merkle_sth_log_root_hash_check CHECK ((octet_length(root_hash) = 32))
);

CREATE TABLE cirislens.occurrence_registry (
    occurrence_id text NOT NULL,
    identity text NOT NULL,
    registered_at timestamp with time zone NOT NULL,
    last_heartbeat timestamp with time zone NOT NULL,
    expires_at timestamp with time zone NOT NULL,
    metadata jsonb
);

COMMENT ON TABLE cirislens.occurrence_registry IS 'v1.7.3 (CIRISPersist#81) — occurrence liveness registry. TTL-based: expires_at > NOW() means live. Crashed occurrences age out.';

CREATE TABLE cirislens.purge_executions (
    notice_id text NOT NULL,
    selection_digest text NOT NULL,
    claimant_key_id text NOT NULL,
    record_count bigint NOT NULL,
    notice_jcs text NOT NULL,
    cosignatures_json text NOT NULL,
    executed_by text NOT NULL,
    origin text NOT NULL,
    executed_at timestamp with time zone NOT NULL,
    admitted_at timestamp with time zone DEFAULT now() NOT NULL,
    finalized_at timestamp with time zone,
    legal_basis text NOT NULL,
    CONSTRAINT purge_executions_claimant_key_id_check CHECK ((claimant_key_id <> ''::text)),
    CONSTRAINT purge_executions_legal_basis_check CHECK ((legal_basis <> ''::text)),
    CONSTRAINT purge_executions_notice_id_check CHECK ((notice_id ~ '^[0-9a-f]{64}$'::text)),
    CONSTRAINT purge_executions_origin_check CHECK ((origin = ANY (ARRAY['local'::text, 'replicated'::text]))),
    CONSTRAINT purge_executions_record_count_check CHECK ((record_count >= 0)),
    CONSTRAINT purge_executions_selection_digest_check CHECK ((selection_digest ~ '^[0-9a-f]{64}$'::text))
);

CREATE TABLE cirislens.purge_tombstones (
    notice_id text NOT NULL,
    plane text NOT NULL,
    record_ref text NOT NULL,
    ordinal bigint NOT NULL,
    derived_from text,
    CONSTRAINT purge_tombstones_ordinal_check CHECK ((ordinal >= 0)),
    CONSTRAINT purge_tombstones_plane_check CHECK ((plane = ANY (ARRAY['attestation'::text, 'trace'::text, 'blob'::text]))),
    CONSTRAINT purge_tombstones_record_ref_check CHECK ((record_ref <> ''::text))
);

CREATE TABLE cirislens.retention_policies (
    table_name text NOT NULL,
    time_column text DEFAULT 'ts'::text NOT NULL,
    min_keep_secs bigint NOT NULL,
    pressure_trigger_bytes bigint,
    pressure_target_bytes bigint,
    interval_secs bigint NOT NULL,
    updated_at timestamp with time zone NOT NULL
);

CREATE TABLE cirislens.revoked_service_tokens (
    token_hash text NOT NULL,
    revoked_at timestamp with time zone NOT NULL,
    revoked_by text NOT NULL,
    reason text NOT NULL
);

COMMENT ON TABLE cirislens.revoked_service_tokens IS 'v1.5.23 (CIRISPersist#64) — service-token revocation substrate. Absorbs agent revoked_service_tokens.db.';

CREATE TABLE cirislens.scheduled_tasks (
    id text NOT NULL,
    name text NOT NULL,
    goal_description text NOT NULL,
    status text NOT NULL,
    defer_until timestamp with time zone,
    schedule_cron text,
    trigger_prompt text NOT NULL,
    origin_thought_id text NOT NULL,
    created_at timestamp with time zone NOT NULL,
    last_triggered_at timestamp with time zone,
    next_trigger_at timestamp with time zone,
    deferral_count integer DEFAULT 0 NOT NULL,
    deferral_history jsonb,
    created_by_agent text,
    agent_occurrence_id text DEFAULT 'default'::text NOT NULL,
    CONSTRAINT scheduled_tasks_deferral_count_check CHECK ((deferral_count >= 0)),
    CONSTRAINT scheduled_tasks_status_check CHECK ((status = ANY (ARRAY['PENDING'::text, 'ACTIVE'::text, 'COMPLETE'::text, 'FAILED'::text])))
);

COMMENT ON TABLE cirislens.scheduled_tasks IS 'v1.5.12 (CIRISPersist#59 #4) — scheduled tasks substrate. Absorbs CIRISAgent ciris_engine.db.scheduled_tasks. Status vocabulary is UPPERCASE (PENDING/ACTIVE/COMPLETE/FAILED). FK to cirislens.thoughts DEFERRABLE.';

CREATE TABLE cirislens.service_correlations (
    correlation_id text NOT NULL,
    service_type text NOT NULL,
    handler_name text NOT NULL,
    action_type text NOT NULL,
    request_data jsonb,
    response_data jsonb,
    status text DEFAULT 'pending'::text NOT NULL,
    created_at timestamp with time zone DEFAULT now() NOT NULL,
    updated_at timestamp with time zone DEFAULT now() NOT NULL,
    correlation_type text DEFAULT 'service_interaction'::text NOT NULL,
    "timestamp" timestamp with time zone,
    metric_name text,
    metric_value real,
    log_level text,
    trace_id text,
    span_id text,
    parent_span_id text,
    tags jsonb,
    retention_policy text DEFAULT 'raw'::text NOT NULL,
    agent_occurrence_id text DEFAULT 'default'::text NOT NULL,
    CONSTRAINT service_correlations_correlation_type_check CHECK ((correlation_type = ANY (ARRAY['service_interaction'::text, 'metric'::text, 'trace'::text, 'log'::text]))),
    CONSTRAINT service_correlations_retention_policy_check CHECK ((retention_policy = ANY (ARRAY['raw'::text, 'aggregated'::text, 'summary'::text, 'retained_indefinitely'::text]))),
    CONSTRAINT service_correlations_status_check CHECK ((status = ANY (ARRAY['pending'::text, 'active'::text, 'completed'::text, 'failed'::text, 'cancelled'::text])))
);

COMMENT ON TABLE cirislens.service_correlations IS 'v1.5.11 (CIRISPersist#59 #3) — service correlations substrate. Absorbs CIRISAgent ciris_engine.db.service_correlations. Dual-purpose: service-interaction tracking + TSDB metrics + distributed-trace spans + logs. correlation_type column discriminates between sub-shapes.';

CREATE TABLE cirislens.shared_instance_leases (
    instance_name text NOT NULL,
    owner_pid integer NOT NULL,
    owner_hostname text NOT NULL,
    acquired_at timestamp with time zone NOT NULL,
    last_heartbeat_at timestamp with time zone NOT NULL,
    lease_version bigint DEFAULT 1 NOT NULL
);

CREATE TABLE cirislens.signed_wire_index (
    kind text NOT NULL,
    content_hash text NOT NULL,
    record_key text NOT NULL
);

CREATE TABLE cirislens.storage_budget_installed (
    node_id text NOT NULL,
    revision bigint NOT NULL,
    epoch_id text NOT NULL,
    scopes jsonb NOT NULL,
    pinned_class jsonb NOT NULL,
    wire jsonb NOT NULL,
    installed_at timestamp with time zone NOT NULL,
    CONSTRAINT storage_budget_installed_revision_check CHECK ((revision >= 0))
);

CREATE TABLE cirislens.tasks (
    task_id text NOT NULL,
    channel_id text NOT NULL,
    description text NOT NULL,
    status text NOT NULL,
    priority integer DEFAULT 0 NOT NULL,
    created_at timestamp with time zone NOT NULL,
    updated_at timestamp with time zone NOT NULL,
    parent_task_id text,
    context_json jsonb,
    outcome_json jsonb,
    retry_count integer DEFAULT 0 NOT NULL,
    signed_by text,
    signature text,
    signed_at timestamp with time zone,
    updated_info_available boolean DEFAULT false NOT NULL,
    updated_info_content text,
    agent_occurrence_id text DEFAULT 'default'::text NOT NULL,
    images_json jsonb,
    CONSTRAINT tasks_retry_count_check CHECK ((retry_count >= 0)),
    CONSTRAINT tasks_status_check CHECK ((status = ANY (ARRAY['pending'::text, 'active'::text, 'completed'::text, 'failed'::text, 'cancelled'::text, 'deferred'::text, 'rejected'::text])))
);

COMMENT ON TABLE cirislens.tasks IS 'v1.5.9 (CIRISPersist#59 #1) — agent tasks substrate. Absorbs CIRISAgent ciris_engine.db.tasks. Ends dual-libsqlite access pattern.';

COMMENT ON COLUMN cirislens.tasks.status IS 'v41.2.0 (CIRISPersist#810) — closed 7-value set. SUPERSET of CIRISAgent''s TaskStatus (pending/active/completed/failed/deferred/rejected); ''cancelled'' is persist-only. Grows with the consumer enum, never shrinks: a missing value wedges the task active forever (CIRISAgent#1077).';

CREATE TABLE cirislens.thoughts (
    thought_id text NOT NULL,
    source_task_id text NOT NULL,
    channel_id text,
    thought_type text DEFAULT 'standard'::text NOT NULL,
    status text NOT NULL,
    created_at timestamp with time zone NOT NULL,
    updated_at timestamp with time zone NOT NULL,
    round_number integer DEFAULT 0 NOT NULL,
    content text NOT NULL,
    context_json jsonb,
    thought_depth integer DEFAULT 0 NOT NULL,
    ponder_notes_json jsonb,
    parent_thought_id text,
    final_action_json jsonb,
    agent_occurrence_id text DEFAULT 'default'::text NOT NULL,
    CONSTRAINT thoughts_round_number_check CHECK ((round_number >= 0)),
    CONSTRAINT thoughts_status_check CHECK ((status = ANY (ARRAY['pending'::text, 'processing'::text, 'completed'::text, 'failed'::text, 'deferred'::text]))),
    CONSTRAINT thoughts_thought_depth_check CHECK ((thought_depth >= 0))
);

COMMENT ON TABLE cirislens.thoughts IS 'v1.5.10 (CIRISPersist#59 #2) — agent thoughts substrate. Absorbs CIRISAgent ciris_engine.db.thoughts. FKs to cirislens.tasks + self-FK both DEFERRABLE.';

CREATE TABLE cirislens.tickets (
    ticket_id text NOT NULL,
    sop text NOT NULL,
    ticket_type text NOT NULL,
    status text NOT NULL,
    priority integer DEFAULT 5 NOT NULL,
    email text NOT NULL,
    user_identifier text,
    submitted_at timestamp with time zone NOT NULL,
    deadline timestamp with time zone,
    last_updated timestamp with time zone NOT NULL,
    completed_at timestamp with time zone,
    metadata jsonb DEFAULT '{}'::jsonb NOT NULL,
    notes text,
    automated boolean DEFAULT false NOT NULL,
    correlation_id text,
    agent_occurrence_id text DEFAULT '__shared__'::text NOT NULL,
    created_at timestamp with time zone DEFAULT CURRENT_TIMESTAMP NOT NULL,
    CONSTRAINT tickets_priority_check CHECK (((priority >= 1) AND (priority <= 10))),
    CONSTRAINT tickets_status_check CHECK ((status = ANY (ARRAY['proposed'::text, 'pending'::text, 'assigned'::text, 'in_progress'::text, 'blocked'::text, 'deferred'::text, 'completed'::text, 'cancelled'::text, 'failed'::text])))
);

COMMENT ON TABLE cirislens.tickets IS 'v1.5.13 (CIRISPersist#59 #5) — tickets substrate. Absorbs CIRISAgent ciris_engine.db.tickets. Status vocabulary is LOWERCASE 8-value (pending/assigned/in_progress/blocked/deferred/completed/cancelled/failed); priority 1-10 (default 5); agent_occurrence_id default ''__shared__'' (cross-occurrence work items).';

CREATE TABLE cirislens.trace_events (
    event_id bigint NOT NULL,
    trace_id text NOT NULL,
    thought_id text NOT NULL,
    task_id text,
    step_point text,
    event_type text NOT NULL,
    attempt_index integer DEFAULT 0 NOT NULL,
    ts timestamp with time zone NOT NULL,
    agent_name text,
    agent_id_hash text,
    cognitive_state text,
    trace_level text NOT NULL,
    payload jsonb NOT NULL,
    cost_llm_calls integer,
    cost_tokens integer,
    cost_usd double precision,
    signature text,
    signing_key_id text,
    signature_verified boolean DEFAULT false NOT NULL,
    schema_version text,
    pii_scrubbed boolean DEFAULT false NOT NULL,
    audit_sequence_number bigint,
    audit_entry_hash text,
    audit_signature text,
    original_content_hash text,
    scrub_signature text,
    scrub_key_id text,
    scrub_timestamp timestamp with time zone,
    agent_role text,
    agent_template text,
    deployment_domain text,
    deployment_type text,
    deployment_region text,
    deployment_trust_mode text,
    extracted_features jsonb,
    classifications jsonb,
    pipeline_metadata jsonb,
    verification_source text DEFAULT 'persist'::text NOT NULL,
    cohort_scope text DEFAULT 'federation'::text NOT NULL,
    cohort_target_id text,
    pqc_key_id text,
    shard_key smallint,
    scrub_ner_ran boolean,
    scrub_applied_trace_level text,
    scrub_model_digest text,
    admitted_at timestamp with time zone,
    CONSTRAINT trace_events_cohort_scope_closed_set CHECK ((cohort_scope = ANY (ARRAY['self'::text, 'family'::text, 'community'::text, 'affiliations'::text, 'species'::text, 'biosphere'::text, 'federation'::text]))),
    CONSTRAINT trace_events_verification_source_check CHECK ((verification_source = ANY (ARRAY['persist'::text, 'edge'::text])))
);

COMMENT ON COLUMN cirislens.trace_events.extracted_features IS 'v0.6.0 (CIRISPersist#19) — typed Features JSONB. NULL for pre-pipeline rows.';

COMMENT ON COLUMN cirislens.trace_events.classifications IS 'v0.6.0 (CIRISPersist#19) — Vec<Vec<ContentClassMatch>> JSONB. NULL for pre-pipeline rows.';

COMMENT ON COLUMN cirislens.trace_events.pipeline_metadata IS 'v0.6.0 (CIRISPersist#19) — PipelineMetadata JSONB (stages, timings, sidecar ref). NULL for pre-pipeline rows.';

COMMENT ON COLUMN cirislens.trace_events.verification_source IS 'v2.0 (CIRISPersist#91) — who established this trace''s authenticity. ''persist'' = persist ran verify_trace (VerifyMode::Full). ''edge'' = verification delegated upstream to an Edge verifier (VerifyMode::TrustPreVerified relay skip-verify path). signature_verified stays TRUE in both cases — the signature is valid either way.';

COMMENT ON COLUMN cirislens.trace_events.cohort_scope IS 'v4.0 (CIRISPersist#160, CEG 0.4 §4.2.4 / 0.10 §10.1.4). Producer-formed visibility/routing axis. Closed-set; default ''federation'' (backward-compat). The §4.3 read-gate filters (cohort_scope, cohort_target_id) against the reader''s resolved admission.';

COMMENT ON COLUMN cirislens.trace_events.cohort_target_id IS 'v4.0 (CIRISPersist#160, FSD §4.3). Scope target: family_id / community_id the producer routed to, or — for cohort_scope=''self'' — the owner identity the substrate resolved from the verified signer at write. NULL for the broad belonging-tiers.';

CREATE SEQUENCE cirislens.trace_events_event_id_seq
    START WITH 1
    INCREMENT BY 1
    NO MINVALUE
    NO MAXVALUE
    CACHE 1;

ALTER SEQUENCE cirislens.trace_events_event_id_seq OWNED BY cirislens.trace_events.event_id;

CREATE TABLE cirislens.trace_events_factor_rollup_1h (
    bucket_start timestamp with time zone NOT NULL,
    agent_id_hash text,
    deployment_domain text,
    cohort_scope text,
    cohort_target_id text,
    trace_count bigint DEFAULT 0 NOT NULL,
    csdma_sum double precision DEFAULT 0 NOT NULL,
    csdma_n bigint DEFAULT 0 NOT NULL,
    k_eff_sum double precision DEFAULT 0 NOT NULL,
    k_eff_n bigint DEFAULT 0 NOT NULL,
    correlation_risk_sum double precision DEFAULT 0 NOT NULL,
    correlation_risk_n bigint DEFAULT 0 NOT NULL,
    override_trace_count bigint DEFAULT 0 NOT NULL,
    fragility_trace_count bigint DEFAULT 0 NOT NULL,
    conscience_fail_trace_count bigint DEFAULT 0 NOT NULL,
    entropy_fail_trace_count bigint DEFAULT 0 NOT NULL,
    coherence_fail_trace_count bigint DEFAULT 0 NOT NULL,
    optimization_veto_fail_trace_count bigint DEFAULT 0 NOT NULL,
    epistemic_humility_fail_trace_count bigint DEFAULT 0 NOT NULL,
    audit_seq_trace_count bigint DEFAULT 0 NOT NULL,
    audit_sig_trace_count bigint DEFAULT 0 NOT NULL
);

CREATE TABLE cirislens.trace_events_factor_rollup_meta (
    id boolean DEFAULT true NOT NULL,
    last_refreshed_ts timestamp with time zone,
    CONSTRAINT trace_events_factor_rollup_meta_singleton CHECK (id)
);

-- edition 1's one seeded row (V081).
INSERT INTO cirislens.trace_events_factor_rollup_meta (id, last_refreshed_ts) VALUES (true, NULL);

CREATE TABLE cirislens.trace_llm_calls (
    call_id bigint NOT NULL,
    trace_id text NOT NULL,
    thought_id text NOT NULL,
    task_id text,
    parent_event_id bigint,
    parent_event_type text,
    parent_attempt_index integer,
    attempt_index integer DEFAULT 0 NOT NULL,
    ts timestamp with time zone NOT NULL,
    duration_ms double precision,
    handler_name text,
    service_name text,
    model text,
    base_url text,
    response_model text,
    prompt_tokens integer,
    completion_tokens integer,
    prompt_bytes integer,
    completion_bytes integer,
    cost_usd double precision,
    status text,
    error_class text,
    attempt_count integer,
    retry_count integer,
    prompt_hash text,
    prompt text,
    response_text text
);

CREATE SEQUENCE cirislens.trace_llm_calls_call_id_seq
    START WITH 1
    INCREMENT BY 1
    NO MINVALUE
    NO MAXVALUE
    CACHE 1;

ALTER SEQUENCE cirislens.trace_llm_calls_call_id_seq OWNED BY cirislens.trace_llm_calls.call_id;

CREATE TABLE cirislens.trace_thought_signatures (
    thought_id text NOT NULL,
    signature_ml_dsa_65 text NOT NULL,
    pqc_key_id text
);

CREATE TABLE cirislens.transport_destinations (
    occurrence_key_id text NOT NULL,
    transport_kind text NOT NULL,
    destination text NOT NULL,
    asserted_at timestamp with time zone NOT NULL,
    last_seen_at timestamp with time zone,
    transport_ed25519_pubkey_base64 text,
    transport_x25519_pubkey_base64 text,
    binding_provenance text DEFAULT 'rooted'::text NOT NULL,
    epoch bigint DEFAULT 0 NOT NULL,
    retired_at timestamp with time zone,
    attesting_key_id text,
    signed_envelope text,
    signature text,
    admitted_at timestamp with time zone NOT NULL
);

COMMENT ON COLUMN cirislens.transport_destinations.admitted_at IS 'NOT NULL on both dialects since sqlite V141 (CIRISPersist#828); postgres has been NOT NULL since V130.';

CREATE TABLE cirislens.wa_cert (
    wa_id text NOT NULL,
    name text NOT NULL,
    role text NOT NULL,
    pubkey text NOT NULL,
    jwt_kid text NOT NULL,
    password_hash text,
    api_key_hash text,
    oauth_provider text,
    oauth_external_id text,
    oauth_links jsonb,
    veilid_id text,
    auto_minted boolean DEFAULT false NOT NULL,
    parent_wa_id text,
    parent_signature text,
    scopes jsonb NOT NULL,
    custom_permissions jsonb,
    adapter_id text,
    adapter_name text,
    adapter_metadata jsonb,
    token_type text DEFAULT 'standard'::text NOT NULL,
    created timestamp with time zone NOT NULL,
    last_login timestamp with time zone,
    active boolean DEFAULT true NOT NULL,
    CONSTRAINT wa_cert_role_check CHECK ((role = ANY (ARRAY['root'::text, 'authority'::text, 'observer'::text]))),
    CONSTRAINT wa_cert_token_type_check CHECK ((token_type = ANY (ARRAY['standard'::text, 'session'::text, 'api_key'::text, 'oauth'::text, 'service'::text])))
);

COMMENT ON TABLE cirislens.wa_cert IS 'v1.5.19 (CIRISPersist#59 #11, FINAL) — wa_cert substrate. Absorbs CIRISAgent ciris_engine.db.wa_cert; the Wise-Authority cert directory keyed on wa_id. 24 columns matching the agent (TEXT JSON columns promoted to JSONB; INTEGER 0/1 booleans promoted to BOOLEAN; TEXT timestamps promoted to TIMESTAMPTZ). Lives in the engine DB (not a separate auth.db) per the persist-is-the-only-library-opening-the-file guarantee. Self-FK on parent_wa_id is DEFERRABLE INITIALLY DEFERRED so a one-tx ceremony writing parent + child in either order is supported. JWT-verify hot path hits the unique jwt_kid index; OAuth login hits the partial oauth index; list_observers / list_authorities hits the role+active partial index.';

CREATE TABLE cirislens.wholeness_witness_corpus (
    peer_id text NOT NULL,
    epoch_id bigint NOT NULL,
    observed_at_unix_ms bigint NOT NULL,
    claim_namespaces jsonb NOT NULL,
    merkle_root text NOT NULL,
    leaf_count bigint NOT NULL,
    witness_version integer NOT NULL,
    signature text NOT NULL,
    signature_ml_dsa_65 text NOT NULL,
    pqc_key_id text NOT NULL,
    admitted_at timestamp with time zone DEFAULT now() NOT NULL
);

CREATE TABLE cirislens_derived.calibration_bundles (
    ratchet_calibration_version integer NOT NULL,
    projection_version text NOT NULL,
    calibrated_at timestamp with time zone NOT NULL,
    calibration_corpus_sha256 text NOT NULL,
    calibration_corpus_n integer NOT NULL,
    sample_size_gate integer NOT NULL,
    manifold_threshold_global real NOT NULL,
    projection_metadata jsonb NOT NULL,
    cohort_centroids jsonb NOT NULL,
    is_current boolean DEFAULT false NOT NULL,
    canonical_bytes bytea NOT NULL,
    ed25519_sig bytea NOT NULL,
    ml_dsa_65_sig bytea NOT NULL,
    signing_key_id text NOT NULL,
    inserted_at timestamp with time zone DEFAULT now() NOT NULL,
    CONSTRAINT calibration_bundles_canonical_bytes_bounded CHECK (((octet_length(canonical_bytes) >= 1) AND (octet_length(canonical_bytes) <= 8388608))),
    CONSTRAINT calibration_bundles_corpus_n_positive CHECK ((calibration_corpus_n > 0)),
    CONSTRAINT calibration_bundles_ed25519_sig_correct_length CHECK ((octet_length(ed25519_sig) = 64)),
    CONSTRAINT calibration_bundles_manifold_threshold_positive CHECK ((manifold_threshold_global > (0.0)::double precision)),
    CONSTRAINT calibration_bundles_ml_dsa_65_sig_correct_length CHECK ((octet_length(ml_dsa_65_sig) = 3309)),
    CONSTRAINT calibration_bundles_sample_size_gate_positive CHECK ((sample_size_gate > 0))
);

CREATE TABLE cirislens_derived.detection_events (
    detection_id uuid NOT NULL,
    trace_id text,
    body_sha256 bytea,
    detector text NOT NULL,
    severity text NOT NULL,
    cohort_cell jsonb NOT NULL,
    conformity_variant text NOT NULL,
    conformity_payload jsonb NOT NULL,
    lens_core_version text NOT NULL,
    ratchet_calibration_version integer NOT NULL,
    canonical_bytes bytea,
    ed25519_sig bytea NOT NULL,
    ml_dsa_65_sig bytea NOT NULL,
    signing_key_id text NOT NULL,
    ts timestamp with time zone DEFAULT now() NOT NULL,
    erased_at timestamp with time zone,
    attestation_id text,
    CONSTRAINT detection_events_body_sha256_correct_length CHECK ((octet_length(body_sha256) = 32)),
    CONSTRAINT detection_events_canonical_bytes_bounded CHECK (((octet_length(canonical_bytes) >= 1) AND (octet_length(canonical_bytes) <= 1048576))),
    CONSTRAINT detection_events_conformity_variant_known CHECK ((conformity_variant = ANY (ARRAY['numeric'::text, 'indeterminate'::text, 'unavailable'::text]))),
    CONSTRAINT detection_events_ed25519_sig_correct_length CHECK ((octet_length(ed25519_sig) = 64)),
    CONSTRAINT detection_events_ml_dsa_65_sig_correct_length CHECK ((octet_length(ml_dsa_65_sig) = 3309)),
    CONSTRAINT detection_events_severity_known CHECK ((severity = ANY (ARRAY['info'::text, 'warning'::text, 'critical'::text])))
);

COMMENT ON COLUMN cirislens_derived.detection_events.erased_at IS 'V080 (CIRISPersist#222) — Art. 17 tombstone marker. NON-NULL = the PII linkage (trace_id, body_sha256, canonical_bytes) was NULLed by delete_traces_for_agent_id_hash; the detection analytics (detector/severity/cohort_cell) are retained.';

CREATE TABLE cirislens_secrets.access_log (
    log_id bigint NOT NULL,
    secret_uuid uuid,
    accessor text NOT NULL,
    operation text NOT NULL,
    action_type text,
    purpose text,
    success boolean NOT NULL,
    error text,
    trace_id text,
    thought_id text,
    created_at timestamp with time zone DEFAULT now() NOT NULL,
    CONSTRAINT access_log_operation_check CHECK ((operation = ANY (ARRAY['store'::text, 'retrieve'::text, 'recall'::text, 'forget'::text, 'encrypt'::text, 'decrypt'::text, 'reencrypt'::text, 'rotate'::text])))
);

COMMENT ON TABLE cirislens_secrets.access_log IS 'v0.6.1 (CIRISPersist#19) — every SecretsService operation appends here. Audit trail for FSD §3.1 #15.';

CREATE SEQUENCE cirislens_secrets.access_log_log_id_seq
    START WITH 1
    INCREMENT BY 1
    NO MINVALUE
    NO MAXVALUE
    CACHE 1;

ALTER SEQUENCE cirislens_secrets.access_log_log_id_seq OWNED BY cirislens_secrets.access_log.log_id;

CREATE TABLE cirislens_secrets.filter_config (
    config_id text NOT NULL,
    config_value jsonb NOT NULL,
    version integer DEFAULT 1 NOT NULL,
    updated_at timestamp with time zone DEFAULT now() NOT NULL,
    updated_by text NOT NULL
);

COMMENT ON TABLE cirislens_secrets.filter_config IS 'v0.6.1 (CIRISPersist#19) — pattern-catalog config. CIRISAgent FilterConfig surface CRUD lives here per FSD §3.1 #11.';

CREATE TABLE cirislens_secrets.master_key_meta (
    key_ref text NOT NULL,
    key_kind text NOT NULL,
    descriptor text,
    created_at timestamp with time zone DEFAULT now() NOT NULL,
    activated_at timestamp with time zone,
    deactivated_at timestamp with time zone,
    rotated_to text,
    CONSTRAINT master_key_meta_key_kind_check CHECK ((key_kind = ANY (ARRAY['software'::text, 'hardware'::text])))
);

COMMENT ON TABLE cirislens_secrets.master_key_meta IS 'v0.6.1 (CIRISPersist#19) — master-key lifecycle. rotate_master_key INSERTS a new row; reencrypt_all activates it; old key gets deactivated_at + rotated_to set.';

CREATE TABLE cirislens_secrets.secrets (
    secret_uuid uuid NOT NULL,
    encrypted_value bytea NOT NULL,
    encryption_key_ref text NOT NULL,
    salt bytea NOT NULL,
    nonce bytea NOT NULL,
    description text NOT NULL,
    sensitivity_level text NOT NULL,
    detected_pattern text NOT NULL,
    context_hint text,
    created_at timestamp with time zone DEFAULT now() NOT NULL,
    last_accessed timestamp with time zone,
    access_count bigint DEFAULT 0 NOT NULL,
    source_message_id text,
    auto_decapsulate_for_actions text[] DEFAULT '{}'::text[] NOT NULL,
    manual_access_only boolean DEFAULT false NOT NULL,
    record_schema_version text DEFAULT '1.0'::text NOT NULL,
    content_hmac bytea,
    CONSTRAINT secrets_sensitivity_level_check CHECK ((sensitivity_level = ANY (ARRAY['low'::text, 'medium'::text, 'high'::text, 'critical'::text])))
);

COMMENT ON TABLE cirislens_secrets.secrets IS 'v0.6.1 (CIRISPersist#19) — encrypted-secrets store. AES-256-GCM via src/secrets/crypto.rs facade. Federated SecretsServiceProtocol substrate.';

COMMENT ON COLUMN cirislens_secrets.secrets.content_hmac IS 'v1.0.0 — HMAC-SHA256(active_master_key, plaintext) for atomic-claim dedup. NULL on rows written via the legacy store_secret path. UNIQUE; conflicts surface as ClaimResult::AlreadyClaimed.';

CREATE TABLE cirisnode.credits_ledger (
    contributor_id text NOT NULL,
    domain text NOT NULL,
    language text NOT NULL,
    subject text NOT NULL,
    balance double precision DEFAULT 0 NOT NULL,
    last_update_contribution text,
    last_updated_at timestamp with time zone DEFAULT now() NOT NULL,
    created_at timestamp with time zone DEFAULT now() NOT NULL,
    attestation_id text
);

COMMENT ON TABLE cirisnode.credits_ledger IS 'v0.7.0 — derived Credits balances per (contributor, cell, subject). SCHEMA.md §10.';

CREATE TABLE cirisnode.expertise_ledger (
    contributor_id text NOT NULL,
    domain text NOT NULL,
    language text NOT NULL,
    expertise double precision DEFAULT 0 NOT NULL,
    is_active boolean DEFAULT false NOT NULL,
    last_updated_at timestamp with time zone DEFAULT now() NOT NULL,
    last_update_contribution text,
    created_at timestamp with time zone DEFAULT now() NOT NULL,
    attestation_id text,
    CONSTRAINT expertise_ledger_expertise_check CHECK (((expertise >= (0)::double precision) AND (expertise <= (1)::double precision)))
);

COMMENT ON TABLE cirisnode.expertise_ledger IS 'v0.7.0 — derived Expertise balances per (contributor, cell). Routing-eligibility lookup uses the partial index for the WHERE is_active path.';

CREATE TABLE cirisnode.federation_delivery_attestations (
    announcement_id text NOT NULL,
    announcement_canonical_hash bytea NOT NULL,
    peer_key_id text NOT NULL,
    peer_pubkey_ed25519_base64 text NOT NULL,
    received_at timestamp with time zone NOT NULL,
    transport_id text NOT NULL,
    signature_classical bytea NOT NULL,
    signature_pqc bytea,
    inserted_at timestamp with time zone DEFAULT now() NOT NULL,
    signature_verified boolean DEFAULT false NOT NULL,
    persist_row_hash text NOT NULL,
    CONSTRAINT federation_delivery_attestati_announcement_canonical_hash_check CHECK ((octet_length(announcement_canonical_hash) = 32)),
    CONSTRAINT federation_delivery_attestations_signature_classical_check CHECK ((octet_length(signature_classical) = 64)),
    CONSTRAINT federation_delivery_attestations_signature_pqc_check CHECK (((signature_pqc IS NULL) OR (octet_length(signature_pqc) = 3309))),
    CONSTRAINT federation_delivery_attestations_transport_id_check CHECK ((transport_id = ANY (ARRAY['reticulum'::text, 'tcp_tls'::text, 'http_over_tls'::text, 'other'::text])))
);

COMMENT ON TABLE cirisnode.federation_delivery_attestations IS 'v2.1 (CIRISPersist#101) — per-peer Mandatory-delivery attestation paired with each federation_announcement Contribution. Wire shape locked per FSD/FEDERATION_ANNOUNCEMENT.md §3.2.1 (ratified 2026-05-27). Surface for RATCHET reach verification (FSD §3.2). Writes come from CIRISEdge through persist''s put_delivery_attestation; persist verifies the hybrid signature against federation_keys[peer_key_id] before INSERT.';

CREATE TABLE cirisnode.promotion_attestations (
    attestation_id uuid NOT NULL,
    target_kind text NOT NULL,
    target_ids uuid[] NOT NULL,
    attested_by text NOT NULL,
    aggregate_evidence jsonb NOT NULL,
    attested_at timestamp with time zone NOT NULL,
    signature text NOT NULL,
    signing_key_id text NOT NULL,
    signature_verified boolean DEFAULT false NOT NULL,
    original_content_hash bytea,
    scrub_signature_classical text,
    scrub_signature_pqc text,
    scrub_key_id text,
    scrub_timestamp timestamp with time zone,
    pqc_completed_at timestamp with time zone,
    persist_row_hash text NOT NULL,
    created_at timestamp with time zone DEFAULT now() NOT NULL,
    CONSTRAINT promotion_attestations_target_kind_check CHECK ((target_kind = ANY (ARRAY['contribution'::text, 'vote'::text, 'moderation_event'::text, 'slashing_attestation'::text, 'reconsideration_attestation'::text])))
);

COMMENT ON TABLE cirisnode.promotion_attestations IS 'v0.7.2 (CIRISPersist#32) — signed federation-consensus attestation that promotes target rows from is_canonical=FALSE to is_canonical=TRUE. Transactionally written alongside the UPDATE on the target rows; readers query the GIN index on target_ids for "what promoted this row?" audits.';

CREATE TABLE cirisnode.scheduled_takedown_actions (
    notice_contribution_id text NOT NULL,
    scheduled_eviction_at timestamp with time zone NOT NULL,
    status text NOT NULL,
    inserted_at timestamp with time zone DEFAULT now() NOT NULL,
    CONSTRAINT scheduled_takedown_actions_status_check CHECK ((status = ANY (ARRAY['pending'::text, 'evicted'::text, 'counter_noticed'::text, 'expired'::text])))
);

COMMENT ON TABLE cirisnode.scheduled_takedown_actions IS 'v3.6.0 (CIRISPersist#134) — counter-notice scheduling. EvictionSweeper consults at each cycle. Counter-notice carrier shape upstream-blocked on CIRISNodeCore#24.';

ALTER TABLE ONLY cirislens.federation_key_registration_history ALTER COLUMN history_id SET DEFAULT nextval('cirislens.federation_key_registration_history_history_id_seq'::regclass);

ALTER TABLE ONLY cirislens.trace_events ALTER COLUMN event_id SET DEFAULT nextval('cirislens.trace_events_event_id_seq'::regclass);

ALTER TABLE ONLY cirislens.trace_llm_calls ALTER COLUMN call_id SET DEFAULT nextval('cirislens.trace_llm_calls_call_id_seq'::regclass);

ALTER TABLE ONLY cirislens_secrets.access_log ALTER COLUMN log_id SET DEFAULT nextval('cirislens_secrets.access_log_log_id_seq'::regclass);

ALTER TABLE ONLY cirisgraph.consolidation_locks
    ADD CONSTRAINT consolidation_locks_pkey PRIMARY KEY (period_start, tenant_id);

ALTER TABLE ONLY cirisgraph.edges
    ADD CONSTRAINT edges_pkey PRIMARY KEY (edge_id);

ALTER TABLE ONLY cirisgraph.nodes
    ADD CONSTRAINT nodes_pkey PRIMARY KEY (node_id, scope);

ALTER TABLE ONLY cirisgraph.telemetry_metrics
    ADD CONSTRAINT telemetry_metrics_pkey PRIMARY KEY (metric_id);

ALTER TABLE ONLY cirislens.accord_active_halt
    ADD CONSTRAINT accord_active_halt_pkey PRIMARY KEY (family_key_id);

ALTER TABLE ONLY cirislens.accord_decision
    ADD CONSTRAINT accord_decision_pkey PRIMARY KEY (proposal_digest);

ALTER TABLE ONLY cirislens.accord_participation
    ADD CONSTRAINT accord_participation_pkey PRIMARY KEY (proposal_digest, pinned_pubkey);

ALTER TABLE ONLY cirislens.accord_proposal_nonce_claim
    ADD CONSTRAINT accord_proposal_nonce_claim_pkey PRIMARY KEY (family_key_id, nonce);

ALTER TABLE ONLY cirislens.accord_proposal
    ADD CONSTRAINT accord_proposal_pkey PRIMARY KEY (proposal_digest);

ALTER TABLE ONLY cirislens.accord_public_keys
    ADD CONSTRAINT accord_public_keys_pkey PRIMARY KEY (key_id);

ALTER TABLE ONLY cirislens.announced_peers
    ADD CONSTRAINT announced_peers_pkey PRIMARY KEY (key_id);

ALTER TABLE ONLY cirislens.attestation_subjects
    ADD CONSTRAINT attestation_subjects_pkey PRIMARY KEY (subject_key_id, attestation_id);

ALTER TABLE ONLY cirislens.audit_archives
    ADD CONSTRAINT audit_archives_pkey PRIMARY KEY (archive_id);

ALTER TABLE cirislens.audit_log
    ADD CONSTRAINT audit_log_action_type_check CHECK ((action_type = ANY (ARRAY['handler_action_speak'::text, 'handler_action_memorize'::text, 'handler_action_recall'::text, 'handler_action_forget'::text, 'handler_action_tool'::text, 'handler_action_defer'::text, 'handler_action_reject'::text, 'handler_action_ponder'::text, 'handler_action_observe'::text, 'handler_action_task_complete'::text, 'system_event'::text, 'security_event'::text, 'config_change'::text, 'service_lifecycle'::text, 'error_event'::text, 'wallet_funds_received'::text, 'wallet_funds_sent'::text, 'wallet_transfer_failed'::text, 'wallet_swap_completed'::text, 'wallet_swap_failed'::text, 'wallet_security_event'::text, 'trust_granted'::text, 'trust_revoked'::text, 'consent_event'::text, 'wisdom_based_deferral'::text]))) NOT VALID;

ALTER TABLE ONLY cirislens.audit_log
    ADD CONSTRAINT audit_log_content_hash_key UNIQUE (content_hash);

ALTER TABLE ONLY cirislens.audit_log
    ADD CONSTRAINT audit_log_pkey PRIMARY KEY (entry_id);

ALTER TABLE ONLY cirislens.audit_log
    ADD CONSTRAINT audit_log_tenant_id_sequence_number_key UNIQUE (tenant_id, sequence_number);

ALTER TABLE ONLY cirislens.blackhole_rules
    ADD CONSTRAINT blackhole_rules_pkey PRIMARY KEY (identity_hash);

ALTER TABLE ONLY cirislens.blob_renditions
    ADD CONSTRAINT blob_renditions_pkey PRIMARY KEY (rendition_sha256);

ALTER TABLE ONLY cirislens.canonical_role_withdrawal
    ADD CONSTRAINT canonical_role_withdrawal_pkey PRIMARY KEY (key_id);

ALTER TABLE ONLY cirislens.consent_peer_set_for
    ADD CONSTRAINT consent_peer_set_for_pkey PRIMARY KEY (author_key_id, for_key_id, peer_key_id);

ALTER TABLE ONLY cirislens.consent_peer_set
    ADD CONSTRAINT consent_peer_set_pkey PRIMARY KEY (node_key_id, for_key_id, peer_key_id);

ALTER TABLE ONLY cirislens.content_aggregation
    ADD CONSTRAINT content_aggregation_pkey PRIMARY KEY (aggregate_content_id);

ALTER TABLE ONLY cirislens.content_manifest
    ADD CONSTRAINT content_manifest_pkey PRIMARY KEY (content_id, corpus_kind);

ALTER TABLE ONLY cirislens.content_symbols
    ADD CONSTRAINT content_symbols_pkey PRIMARY KEY (content_id, symbol_id);

ALTER TABLE ONLY cirislens.continuity_awareness
    ADD CONSTRAINT continuity_awareness_pkey PRIMARY KEY (id);

ALTER TABLE ONLY cirislens.creation_ceremonies
    ADD CONSTRAINT creation_ceremonies_pkey PRIMARY KEY (ceremony_id);

ALTER TABLE ONLY cirislens.dag_link_backfill_cursor
    ADD CONSTRAINT dag_link_backfill_cursor_pkey PRIMARY KEY (singleton);

ALTER TABLE ONLY cirislens.deferral_reports
    ADD CONSTRAINT deferral_reports_pkey PRIMARY KEY (message_id);

ALTER TABLE ONLY cirislens.edge_detection_events
    ADD CONSTRAINT edge_detection_events_pkey PRIMARY KEY (detection_id);

ALTER TABLE ONLY cirislens.edge_outbound_queue
    ADD CONSTRAINT edge_outbound_queue_pkey PRIMARY KEY (queue_id);

ALTER TABLE ONLY cirislens.federation_attestations_form_refused
    ADD CONSTRAINT federation_attestations_form_refused_pkey PRIMARY KEY (attestation_id);

ALTER TABLE ONLY cirislens.federation_attestations
    ADD CONSTRAINT federation_attestations_pkey PRIMARY KEY (attestation_id);

ALTER TABLE ONLY cirislens.federation_blob_associations
    ADD CONSTRAINT federation_blob_associations_pkey PRIMARY KEY (sha256, cohort_scope, group_key_id);

ALTER TABLE ONLY cirislens.federation_blob_key_grants
    ADD CONSTRAINT federation_blob_key_grants_pkey PRIMARY KEY (at_rest_sha256, recipient_key_id);

ALTER TABLE ONLY cirislens.federation_blobs
    ADD CONSTRAINT federation_blobs_pkey PRIMARY KEY (sha256);

ALTER TABLE ONLY cirislens.federation_communities
    ADD CONSTRAINT federation_communities_pkey PRIMARY KEY (community_key_id);

ALTER TABLE ONLY cirislens.federation_community_blob_epoch
    ADD CONSTRAINT federation_community_blob_epoch_pkey PRIMARY KEY (at_rest_sha256);

ALTER TABLE ONLY cirislens.federation_community_dek_epoch
    ADD CONSTRAINT federation_community_dek_epoch_pkey PRIMARY KEY (community_key_id, minter_key_id);

ALTER TABLE ONLY cirislens.federation_community_dek_member_grants
    ADD CONSTRAINT federation_community_dek_member_grants_pkey PRIMARY KEY (community_key_id, minter_key_id, epoch, member_key_id);

ALTER TABLE ONLY cirislens.federation_community_dek
    ADD CONSTRAINT federation_community_dek_pkey PRIMARY KEY (community_key_id, minter_key_id, epoch);

ALTER TABLE ONLY cirislens.federation_community_membership_revocations
    ADD CONSTRAINT federation_community_membership_revocations_pkey PRIMARY KEY (community_key_id, removed_identity_key_id, effective_at);

ALTER TABLE ONLY cirislens.federation_community_membership_widenings
    ADD CONSTRAINT federation_community_membership_widenings_pkey PRIMARY KEY (community_key_id, member_key_id, effective_at);

ALTER TABLE ONLY cirislens.federation_content_kem_identity
    ADD CONSTRAINT federation_content_kem_identity_pkey PRIMARY KEY (id);

ALTER TABLE ONLY cirislens.federation_content_master
    ADD CONSTRAINT federation_content_master_pkey PRIMARY KEY (id);

ALTER TABLE ONLY cirislens.federation_cosign_aliases
    ADD CONSTRAINT federation_cosign_aliases_pkey PRIMARY KEY (alias_attestation_id);

ALTER TABLE ONLY cirislens.federation_cosign_pending
    ADD CONSTRAINT federation_cosign_pending_pkey PRIMARY KEY (quorum_key);

ALTER TABLE ONLY cirislens.federation_cosign_signatures
    ADD CONSTRAINT federation_cosign_signatures_pkey PRIMARY KEY (attestation_id);

ALTER TABLE ONLY cirislens.federation_cosign_signatures
    ADD CONSTRAINT federation_cosign_signatures_quorum_key_signer_key_id_key UNIQUE (quorum_key, signer_key_id);

ALTER TABLE ONLY cirislens.federation_dag_chunks
    ADD CONSTRAINT federation_dag_chunks_pkey PRIMARY KEY (manifest_sha256, seq);

ALTER TABLE ONLY cirislens.federation_families
    ADD CONSTRAINT federation_families_pkey PRIMARY KEY (family_key_id);

ALTER TABLE ONLY cirislens.federation_family_membership_revocations
    ADD CONSTRAINT federation_family_membership_revocations_pkey PRIMARY KEY (family_key_id, removed_identity_key_id, effective_at);

ALTER TABLE ONLY cirislens.federation_family_membership_widenings
    ADD CONSTRAINT federation_family_membership_widenings_pkey PRIMARY KEY (family_key_id, member_key_id, effective_at);

ALTER TABLE ONLY cirislens.federation_group_versions
    ADD CONSTRAINT federation_group_versions_pkey PRIMARY KEY (cohort, group_key_id, version);

ALTER TABLE ONLY cirislens.federation_identity_occurrence_history
    ADD CONSTRAINT federation_identity_occurrence_history_pkey PRIMARY KEY (identity_key_id, occurrence_key_id, asserted_at, attesting_key_id);

ALTER TABLE ONLY cirislens.federation_identity_occurrence_revocations
    ADD CONSTRAINT federation_identity_occurrence_revocations_pkey PRIMARY KEY (identity_key_id, occurrence_key_id);

ALTER TABLE ONLY cirislens.federation_identity_occurrences
    ADD CONSTRAINT federation_identity_occurrences_pkey PRIMARY KEY (identity_key_id, occurrence_key_id);

ALTER TABLE ONLY cirislens.federation_key_grant_pending
    ADD CONSTRAINT federation_key_grant_pending_pkey PRIMARY KEY (at_rest_sha256, cohort_scope, attestation_id);

ALTER TABLE ONLY cirislens.federation_key_registration_history
    ADD CONSTRAINT federation_key_registration_history_pkey PRIMARY KEY (history_id);

ALTER TABLE cirislens.federation_keys
    ADD CONSTRAINT federation_keys_no_self_trust CHECK (((trusted_by IS NULL) OR (trusted_by <> key_id))) NOT VALID;

ALTER TABLE ONLY cirislens.federation_keys
    ADD CONSTRAINT federation_keys_pkey PRIMARY KEY (key_id);

ALTER TABLE cirislens.federation_keys
    ADD CONSTRAINT federation_keys_registry_requires_domains CHECK (((trust_relationship <> 'registry'::text) OR ((trust_domains IS NOT NULL) AND (array_length(trust_domains, 1) > 0)))) NOT VALID;

ALTER TABLE ONLY cirislens.federation_lineage_head_cosigns
    ADD CONSTRAINT federation_lineage_head_cosigns_pkey PRIMARY KEY (lineage_key_id, head_digest_sha256_hex, witness_key_id, signed_at);

ALTER TABLE ONLY cirislens.federation_location_proofs
    ADD CONSTRAINT federation_location_proofs_pkey PRIMARY KEY (subject_key_id, asserted_at);

ALTER TABLE ONLY cirislens.federation_manifest_children
    ADD CONSTRAINT federation_manifest_children_pkey PRIMARY KEY (root_sha256, child_index);

ALTER TABLE ONLY cirislens.federation_peer_metadata
    ADD CONSTRAINT federation_peer_metadata_pkey PRIMARY KEY (key_id);

ALTER TABLE ONLY cirislens.federation_revocation_quorum_state
    ADD CONSTRAINT federation_revocation_quorum_state_pkey PRIMARY KEY (revocation_id);

ALTER TABLE ONLY cirislens.federation_revocations
    ADD CONSTRAINT federation_revocations_pkey PRIMARY KEY (revocation_id);

ALTER TABLE ONLY cirislens.federation_role_withdrawals
    ADD CONSTRAINT federation_role_withdrawals_pkey PRIMARY KEY (role, key_id);

ALTER TABLE ONLY cirislens.federation_scope_blobs
    ADD CONSTRAINT federation_scope_blobs_pkey PRIMARY KEY (record_id, symbol_index);

ALTER TABLE ONLY cirislens.federation_self_roster_proposals
    ADD CONSTRAINT federation_self_roster_proposals_pkey PRIMARY KEY (attestation_id);

ALTER TABLE ONLY cirislens.federation_stream_chunks
    ADD CONSTRAINT federation_stream_chunks_pkey PRIMARY KEY (stream_id, seq);

ALTER TABLE ONLY cirislens.federation_stream_dek_grants
    ADD CONSTRAINT federation_stream_dek_grants_pkey PRIMARY KEY (stream_id, epoch, sealer_key_id, recipient_key_id);

ALTER TABLE ONLY cirislens.federation_stream_deks
    ADD CONSTRAINT federation_stream_deks_pkey PRIMARY KEY (stream_id, epoch);

ALTER TABLE ONLY cirislens.federation_stream_delivery_receipts
    ADD CONSTRAINT federation_stream_delivery_receipts_pkey PRIMARY KEY (stream_id, subscriber_key_id, k);

ALTER TABLE ONLY cirislens.federation_stream_epoch_counts
    ADD CONSTRAINT federation_stream_epoch_counts_pkey PRIMARY KEY (stream_id, epoch);

ALTER TABLE ONLY cirislens.federation_stream_sth
    ADD CONSTRAINT federation_stream_sth_pkey PRIMARY KEY (stream_id, tree_size);

ALTER TABLE ONLY cirislens.federation_streams
    ADD CONSTRAINT federation_streams_pkey PRIMARY KEY (stream_id);

ALTER TABLE ONLY cirislens.federation_trust_direction_held
    ADD CONSTRAINT federation_trust_direction_held_pkey PRIMARY KEY (attestation_id);

ALTER TABLE ONLY cirislens.federation_trust_grants
    ADD CONSTRAINT federation_trust_grants_grantee_key_granter_key_purpose_sco_key UNIQUE (grantee_key, granter_key, purpose, scope);

ALTER TABLE ONLY cirislens.federation_trust_grants
    ADD CONSTRAINT federation_trust_grants_pkey PRIMARY KEY (grant_id);

ALTER TABLE ONLY cirislens.federation_vote_windows
    ADD CONSTRAINT federation_vote_windows_pkey PRIMARY KEY (action_id);

ALTER TABLE ONLY cirislens.federation_withdraws_admission_depths
    ADD CONSTRAINT federation_withdraws_admission_depths_pkey PRIMARY KEY (attestation_id);

ALTER TABLE ONLY cirislens.feedback_mappings
    ADD CONSTRAINT feedback_mappings_pkey PRIMARY KEY (feedback_id);

ALTER TABLE ONLY cirislens.freshness_floor
    ADD CONSTRAINT freshness_floor_pkey PRIMARY KEY (target_key_id, target_kind);

ALTER TABLE ONLY cirislens.goals
    ADD CONSTRAINT goals_pkey PRIMARY KEY (goal_id);

ALTER TABLE ONLY cirislens.hard_case_events
    ADD CONSTRAINT hard_case_events_pkey PRIMARY KEY (event_id);

ALTER TABLE ONLY cirislens.identity_canonical_binding
    ADD CONSTRAINT identity_canonical_binding_pkey PRIMARY KEY (canonical_hash);

ALTER TABLE ONLY cirislens.identity_sequences
    ADD CONSTRAINT identity_sequences_pkey PRIMARY KEY (identity, stream);

ALTER TABLE ONLY cirislens.incident_records
    ADD CONSTRAINT incident_records_pkey PRIMARY KEY (incident_id);

ALTER TABLE ONLY cirislens.key_escrows
    ADD CONSTRAINT key_escrows_pkey PRIMARY KEY (escrow_id);

ALTER TABLE ONLY cirislens.known_wire_hashes
    ADD CONSTRAINT known_wire_hashes_pkey PRIMARY KEY (kind, content_hash);

ALTER TABLE ONLY cirislens.ledger_checkpoints
    ADD CONSTRAINT ledger_checkpoints_pkey PRIMARY KEY (ledger_id, seq);

ALTER TABLE ONLY cirislens.ledger_entry_ranges
    ADD CONSTRAINT ledger_entry_ranges_pkey PRIMARY KEY (ledger_id, from_seq);

ALTER TABLE ONLY cirislens.ledger_fork_evidence
    ADD CONSTRAINT ledger_fork_evidence_pkey PRIMARY KEY (evidence_id);

ALTER TABLE ONLY cirislens.ledger_heads
    ADD CONSTRAINT ledger_heads_l1_triple UNIQUE (owner_key_id, unit, standard_version);

ALTER TABLE ONLY cirislens.ledger_heads
    ADD CONSTRAINT ledger_heads_pkey PRIMARY KEY (ledger_id);

ALTER TABLE ONLY cirislens.maintenance_locks
    ADD CONSTRAINT maintenance_locks_pkey PRIMARY KEY (lock_key);

ALTER TABLE ONLY cirislens.merkle_leaves
    ADD CONSTRAINT merkle_leaves_pkey PRIMARY KEY (tenant_id, leaf_index);

ALTER TABLE ONLY cirislens.merkle_leaves
    ADD CONSTRAINT merkle_leaves_tenant_id_chain_event_id_key UNIQUE (tenant_id, chain_event_id);

ALTER TABLE ONLY cirislens.merkle_sth_log
    ADD CONSTRAINT merkle_sth_log_pkey PRIMARY KEY (tenant_id, tree_size);

ALTER TABLE ONLY cirislens.occurrence_registry
    ADD CONSTRAINT occurrence_registry_pkey PRIMARY KEY (occurrence_id);

ALTER TABLE ONLY cirislens.purge_executions
    ADD CONSTRAINT purge_executions_pkey PRIMARY KEY (notice_id);

ALTER TABLE ONLY cirislens.purge_tombstones
    ADD CONSTRAINT purge_tombstones_pkey PRIMARY KEY (notice_id, plane, record_ref);

ALTER TABLE ONLY cirislens.retention_policies
    ADD CONSTRAINT retention_policies_pkey PRIMARY KEY (table_name);

ALTER TABLE ONLY cirislens.revoked_service_tokens
    ADD CONSTRAINT revoked_service_tokens_pkey PRIMARY KEY (token_hash);

ALTER TABLE ONLY cirislens.scheduled_tasks
    ADD CONSTRAINT scheduled_tasks_pkey PRIMARY KEY (id);

ALTER TABLE ONLY cirislens.service_correlations
    ADD CONSTRAINT service_correlations_pkey PRIMARY KEY (correlation_id);

ALTER TABLE ONLY cirislens.shared_instance_leases
    ADD CONSTRAINT shared_instance_leases_pkey PRIMARY KEY (instance_name);

ALTER TABLE ONLY cirislens.signed_wire_index
    ADD CONSTRAINT signed_wire_index_pkey PRIMARY KEY (kind, content_hash);

ALTER TABLE ONLY cirislens.storage_budget_installed
    ADD CONSTRAINT storage_budget_installed_pkey PRIMARY KEY (node_id);

ALTER TABLE ONLY cirislens.tasks
    ADD CONSTRAINT tasks_pkey PRIMARY KEY (task_id);

ALTER TABLE ONLY cirislens.thoughts
    ADD CONSTRAINT thoughts_pkey PRIMARY KEY (thought_id);

ALTER TABLE ONLY cirislens.tickets
    ADD CONSTRAINT tickets_pkey PRIMARY KEY (ticket_id);

ALTER TABLE ONLY cirislens.trace_events_factor_rollup_meta
    ADD CONSTRAINT trace_events_factor_rollup_meta_pkey PRIMARY KEY (id);

ALTER TABLE ONLY cirislens.trace_events
    ADD CONSTRAINT trace_events_pkey PRIMARY KEY (event_id, ts);

ALTER TABLE ONLY cirislens.trace_llm_calls
    ADD CONSTRAINT trace_llm_calls_pkey PRIMARY KEY (call_id, ts);

ALTER TABLE ONLY cirislens.trace_thought_signatures
    ADD CONSTRAINT trace_thought_signatures_pkey PRIMARY KEY (thought_id);

ALTER TABLE ONLY cirislens.transport_destinations
    ADD CONSTRAINT transport_destinations_pkey PRIMARY KEY (occurrence_key_id, transport_kind);

ALTER TABLE ONLY cirislens.wa_cert
    ADD CONSTRAINT wa_cert_jwt_kid_key UNIQUE (jwt_kid);

ALTER TABLE ONLY cirislens.wa_cert
    ADD CONSTRAINT wa_cert_pkey PRIMARY KEY (wa_id);

ALTER TABLE ONLY cirislens.wholeness_witness_corpus
    ADD CONSTRAINT wholeness_witness_corpus_pkey PRIMARY KEY (peer_id, epoch_id, observed_at_unix_ms);

ALTER TABLE ONLY cirislens_derived.calibration_bundles
    ADD CONSTRAINT calibration_bundles_pkey PRIMARY KEY (ratchet_calibration_version);

ALTER TABLE ONLY cirislens_derived.detection_events
    ADD CONSTRAINT detection_events_pkey PRIMARY KEY (detection_id);

ALTER TABLE ONLY cirislens_secrets.access_log
    ADD CONSTRAINT access_log_pkey PRIMARY KEY (log_id);

ALTER TABLE ONLY cirislens_secrets.filter_config
    ADD CONSTRAINT filter_config_pkey PRIMARY KEY (config_id);

ALTER TABLE ONLY cirislens_secrets.master_key_meta
    ADD CONSTRAINT master_key_meta_pkey PRIMARY KEY (key_ref);

ALTER TABLE ONLY cirislens_secrets.secrets
    ADD CONSTRAINT secrets_content_hmac_key UNIQUE (content_hmac);

ALTER TABLE ONLY cirislens_secrets.secrets
    ADD CONSTRAINT secrets_pkey PRIMARY KEY (secret_uuid);

ALTER TABLE ONLY cirisnode.credits_ledger
    ADD CONSTRAINT credits_ledger_pkey PRIMARY KEY (contributor_id, domain, language, subject);

ALTER TABLE ONLY cirisnode.expertise_ledger
    ADD CONSTRAINT expertise_ledger_pkey PRIMARY KEY (contributor_id, domain, language);

ALTER TABLE ONLY cirisnode.federation_delivery_attestations
    ADD CONSTRAINT federation_delivery_attestations_pkey PRIMARY KEY (announcement_id, peer_key_id);

ALTER TABLE ONLY cirisnode.promotion_attestations
    ADD CONSTRAINT promotion_attestations_pkey PRIMARY KEY (attestation_id);

ALTER TABLE ONLY cirisnode.scheduled_takedown_actions
    ADD CONSTRAINT scheduled_takedown_actions_pkey PRIMARY KEY (notice_contribution_id);

CREATE INDEX consolidation_locks_locked_at ON cirisgraph.consolidation_locks USING btree (locked_at);

CREATE INDEX edges_relationship ON cirisgraph.edges USING btree (relationship);

CREATE INDEX edges_source ON cirisgraph.edges USING btree (source_node_id, scope);

CREATE INDEX edges_target ON cirisgraph.edges USING btree (target_node_id, scope);

CREATE INDEX nodes_attributes_gin ON cirisgraph.nodes USING gin (attributes);

CREATE INDEX nodes_type_scope ON cirisgraph.nodes USING btree (node_type, scope);

CREATE INDEX nodes_updated_at ON cirisgraph.nodes USING btree (updated_at);

CREATE INDEX telemetry_expires ON cirisgraph.telemetry_metrics USING btree (expires_at);

CREATE INDEX telemetry_window ON cirisgraph.telemetry_metrics USING btree (tenant_id, metric_name, observed_at);

CREATE INDEX tsdb_summary_level_metric_period ON cirisgraph.nodes USING btree (node_type, consolidation_level, ((attributes ->> 'metric_name'::text)), ((attributes ->> 'period_start'::text)) DESC) WHERE (node_type = 'tsdb_summary'::text);

CREATE INDEX accord_participation_by_proposal ON cirislens.accord_participation USING btree (proposal_digest);

CREATE INDEX accord_proposal_by_anchor ON cirislens.accord_proposal USING btree (action, prior_family_digest);

CREATE INDEX accord_proposal_by_family ON cirislens.accord_proposal USING btree (family_key_id);

CREATE INDEX accord_proposal_by_payload ON cirislens.accord_proposal USING btree (payload_sha256);

CREATE INDEX attestation_subjects_seek ON cirislens.attestation_subjects USING btree (subject_key_id, dimension, asserted_at DESC, attestation_id);

CREATE INDEX audit_archives_tenant_range ON cirislens.audit_archives USING btree (tenant_id, from_ts, to_ts);

CREATE INDEX audit_log_action_type ON cirislens.audit_log USING btree (action_type);

CREATE INDEX audit_log_actor ON cirislens.audit_log USING btree (actor_id);

CREATE INDEX audit_log_recorded_at ON cirislens.audit_log USING btree (recorded_at);

CREATE INDEX audit_log_subject ON cirislens.audit_log USING btree (subject_kind, subject_id);

CREATE INDEX audit_log_tenant_seq ON cirislens.audit_log USING btree (tenant_id, sequence_number);

CREATE INDEX blob_renditions_by_original ON cirislens.blob_renditions USING btree (original_sha256, rendition_sha256);

CREATE INDEX blob_renditions_by_source ON cirislens.blob_renditions USING btree (source_attestation_id);

CREATE INDEX consent_peer_set_by_source ON cirislens.consent_peer_set USING btree (source_attestation_id);

CREATE INDEX consent_peer_set_for_by_for_key ON cirislens.consent_peer_set_for USING btree (for_key_id);

CREATE INDEX consent_peer_set_for_by_source ON cirislens.consent_peer_set_for USING btree (source_attestation_id);

CREATE INDEX content_aggregation_level_recency ON cirislens.content_aggregation USING btree (aggregation_level, aggregated_at_unix_ms);

CREATE INDEX content_symbols_evict ON cirislens.content_symbols USING btree (content_id, retention_priority);

CREATE INDEX continuity_awareness_active_session ON cirislens.continuity_awareness USING btree (agent_id, shutdown_timestamp DESC) WHERE (is_terminal = false);

CREATE INDEX continuity_awareness_agent_recent ON cirislens.continuity_awareness USING btree (agent_id, shutdown_timestamp DESC);

CREATE INDEX creation_ceremonies_creator ON cirislens.creation_ceremonies USING btree (creator_agent_id, "timestamp" DESC);

CREATE INDEX creation_ceremonies_new_agent ON cirislens.creation_ceremonies USING btree (new_agent_id);

CREATE INDEX creation_ceremonies_timeline ON cirislens.creation_ceremonies USING btree ("timestamp" DESC);

CREATE INDEX creation_ceremonies_wa ON cirislens.creation_ceremonies USING btree (wise_authority_id, "timestamp" DESC);

CREATE INDEX deferral_reports_active ON cirislens.deferral_reports USING btree (created_at DESC) WHERE (resolved_at IS NULL);

CREATE INDEX deferral_reports_task ON cirislens.deferral_reports USING btree (task_id);

CREATE INDEX deferral_reports_thought ON cirislens.deferral_reports USING btree (thought_id);

CREATE INDEX edge_detection_events_kind_severity ON cirislens.edge_detection_events USING btree (detector_kind, severity);

CREATE INDEX edge_detection_events_subject ON cirislens.edge_detection_events USING btree (subject_key_id);

CREATE INDEX edge_detection_events_tenant_observed ON cirislens.edge_detection_events USING btree (tenant_id, observed_at DESC);

CREATE INDEX edge_outbound_queue_awaiting_ack_sweep ON cirislens.edge_outbound_queue USING btree (transport_delivered_at) WHERE (status = 'awaiting_ack'::text);

CREATE INDEX edge_outbound_queue_body_sha256_awaiting ON cirislens.edge_outbound_queue USING btree (body_sha256) WHERE (status = 'awaiting_ack'::text);

CREATE INDEX edge_outbound_queue_claimed_until_sweep ON cirislens.edge_outbound_queue USING btree (claimed_until) WHERE (status = 'sending'::text);

CREATE INDEX edge_outbound_queue_destination ON cirislens.edge_outbound_queue USING btree (destination_key_id, status);

CREATE INDEX edge_outbound_queue_pending_dispatch ON cirislens.edge_outbound_queue USING btree (next_attempt_after) WHERE (status = 'pending'::text);

CREATE INDEX edge_outbound_queue_status_enqueued ON cirislens.edge_outbound_queue USING btree (status, enqueued_at);

CREATE INDEX federation_attestations_admitted ON cirislens.federation_attestations USING btree (admitted_at, attestation_id);

CREATE INDEX federation_attestations_asserted_seek ON cirislens.federation_attestations USING btree (asserted_at DESC, attestation_id DESC);

CREATE INDEX federation_attestations_attested ON cirislens.federation_attestations USING btree (attested_key_id, asserted_at DESC);

CREATE INDEX federation_attestations_attested_composer_ref ON cirislens.federation_attestations USING btree (attested_key_id, attestation_type, (((attestation_envelope)::jsonb ->> 'references_attestation_id'::text)));

CREATE INDEX federation_attestations_attested_dimension ON cirislens.federation_attestations USING btree (attested_key_id, dimension COLLATE "C");

CREATE INDEX federation_attestations_attested_dimension_asserted ON cirislens.federation_attestations USING btree (attested_key_id, dimension COLLATE "C", asserted_at DESC, attestation_id DESC);

CREATE INDEX federation_attestations_attester_dimension ON cirislens.federation_attestations USING btree (attesting_key_id, dimension COLLATE "C");

CREATE INDEX federation_attestations_attester_dimension_asserted ON cirislens.federation_attestations USING btree (attesting_key_id, dimension COLLATE "C", asserted_at DESC, attestation_id DESC);

CREATE INDEX federation_attestations_attester_dimension_citation ON cirislens.federation_attestations USING btree (attesting_key_id, dimension COLLATE "C", ((((attestation_envelope)::jsonb -> 'evidence_refs'::text) ->> 0)));

CREATE INDEX federation_attestations_attesting ON cirislens.federation_attestations USING btree (attesting_key_id, asserted_at DESC);

CREATE INDEX federation_attestations_cohort_scope ON cirislens.federation_attestations USING btree (cohort_scope) WHERE (cohort_scope <> 'federation'::text);

CREATE INDEX federation_attestations_cohort_target ON cirislens.federation_attestations USING btree (cohort_scope, cohort_target) WHERE (cohort_scope = ANY (ARRAY['community'::text, 'affiliations'::text, 'family'::text]));

CREATE INDEX federation_attestations_composer_ref ON cirislens.federation_attestations USING btree (attesting_key_id, attestation_type, (((attestation_envelope)::jsonb ->> 'references_attestation_id'::text)));

CREATE INDEX federation_attestations_dimension_citation ON cirislens.federation_attestations USING btree (dimension COLLATE "C", ((((attestation_envelope)::jsonb -> 'evidence_refs'::text) ->> 0)));

CREATE INDEX federation_attestations_evidence_refs_gin ON cirislens.federation_attestations USING gin ((((attestation_envelope)::jsonb -> 'evidence_refs'::text)));

CREATE INDEX federation_attestations_local_tier ON cirislens.federation_attestations USING btree (tier) WHERE (tier = 'local'::text);

CREATE INDEX federation_attestations_reference_live ON cirislens.federation_attestations USING btree ((((attestation_envelope)::jsonb ->> 'references_attestation_id'::text)), attestation_type) WHERE (((attestation_envelope)::jsonb ->> 'references_attestation_id'::text) IS NOT NULL);

CREATE INDEX federation_attestations_reference_seek ON cirislens.federation_attestations USING btree ((((attestation_envelope)::jsonb ->> 'references_attestation_id'::text)), attestation_type);

CREATE INDEX federation_attestations_subject_key_ids_gin ON cirislens.federation_attestations USING gin (subject_key_ids);

CREATE INDEX federation_attestations_withdraws_admission_rule_idx ON cirislens.federation_attestations USING btree (withdraws_admission_rule) WHERE (withdraws_admission_rule IS NOT NULL);

CREATE INDEX federation_blob_key_grants_by_recipient ON cirislens.federation_blob_key_grants USING btree (recipient_key_id);

CREATE INDEX federation_blob_key_grants_by_scope_recipient ON cirislens.federation_blob_key_grants USING btree (cohort_scope, recipient_key_id);

CREATE INDEX federation_blobs_eviction_score ON cirislens.federation_blobs USING btree (last_accessed_at, access_count);

CREATE INDEX federation_blobs_first_seen_at ON cirislens.federation_blobs USING btree (first_seen_at DESC);

CREATE INDEX federation_blobs_size_bytes ON cirislens.federation_blobs USING btree (size_bytes);

CREATE INDEX federation_communities_admitted ON cirislens.federation_communities USING btree (admitted_at, community_key_id);

CREATE UNIQUE INDEX federation_communities_by_attestation ON cirislens.federation_communities USING btree (attestation_id);

CREATE INDEX federation_communities_without_row ON cirislens.federation_communities USING btree (community_key_id) WHERE (attestation_id IS NULL);

CREATE INDEX federation_community_blob_epoch_by_community_epoch ON cirislens.federation_community_blob_epoch USING btree (community_key_id, minter_key_id, epoch);

CREATE INDEX federation_community_dek_member_grants_by_member ON cirislens.federation_community_dek_member_grants USING btree (member_key_id);

CREATE INDEX federation_community_membership_revocations_admitted ON cirislens.federation_community_membership_revocations USING btree (admitted_at, community_key_id, removed_identity_key_id);

CREATE UNIQUE INDEX federation_community_membership_revocations_by_attestation ON cirislens.federation_community_membership_revocations USING btree (attestation_id);

CREATE INDEX federation_community_membership_revocations_by_member ON cirislens.federation_community_membership_revocations USING btree (removed_identity_key_id);

CREATE INDEX federation_community_membership_revocations_effective ON cirislens.federation_community_membership_revocations USING btree (effective_at);

CREATE INDEX federation_community_membership_revocations_without_row ON cirislens.federation_community_membership_revocations USING btree (community_key_id, removed_identity_key_id, effective_at) WHERE (attestation_id IS NULL);

CREATE INDEX federation_community_membership_widenings_admitted ON cirislens.federation_community_membership_widenings USING btree (admitted_at, community_key_id, member_key_id, effective_at);

CREATE UNIQUE INDEX federation_community_membership_widenings_by_attestation ON cirislens.federation_community_membership_widenings USING btree (attestation_id);

CREATE INDEX federation_community_membership_widenings_by_member ON cirislens.federation_community_membership_widenings USING btree (member_key_id);

CREATE INDEX federation_community_membership_widenings_effective ON cirislens.federation_community_membership_widenings USING btree (effective_at);

CREATE INDEX federation_community_membership_widenings_without_row ON cirislens.federation_community_membership_widenings USING btree (community_key_id, member_key_id, effective_at) WHERE (attestation_id IS NULL);

CREATE INDEX federation_cosign_aliases_held ON cirislens.federation_cosign_aliases USING btree (held_attestation_id);

CREATE INDEX federation_cosign_aliases_quorum ON cirislens.federation_cosign_aliases USING btree (quorum_key);

CREATE UNIQUE INDEX federation_cosign_pending_one_open ON cirislens.federation_cosign_pending USING btree (group_kind, group_key_id, proposer_key_id) WHERE (settled_at IS NULL);

CREATE INDEX federation_dag_chunks_by_chunk ON cirislens.federation_dag_chunks USING btree (chunk_sha256);

CREATE INDEX federation_families_admitted ON cirislens.federation_families USING btree (admitted_at, family_key_id);

CREATE UNIQUE INDEX federation_families_by_attestation ON cirislens.federation_families USING btree (attestation_id);

CREATE INDEX federation_families_entrenched ON cirislens.federation_families USING btree (family_key_id) WHERE (consensus_protocol_entrenched = true);

CREATE INDEX federation_families_members_gin ON cirislens.federation_families USING gin (members jsonb_path_ops);

CREATE INDEX federation_families_without_row ON cirislens.federation_families USING btree (family_key_id) WHERE (attestation_id IS NULL);

CREATE INDEX federation_family_membership_revocations_admitted ON cirislens.federation_family_membership_revocations USING btree (admitted_at, family_key_id, removed_identity_key_id);

CREATE UNIQUE INDEX federation_family_membership_revocations_by_attestation ON cirislens.federation_family_membership_revocations USING btree (attestation_id);

CREATE INDEX federation_family_membership_revocations_by_member ON cirislens.federation_family_membership_revocations USING btree (removed_identity_key_id);

CREATE INDEX federation_family_membership_revocations_effective ON cirislens.federation_family_membership_revocations USING btree (effective_at);

CREATE INDEX federation_family_membership_revocations_without_row ON cirislens.federation_family_membership_revocations USING btree (family_key_id, removed_identity_key_id, effective_at) WHERE (attestation_id IS NULL);

CREATE INDEX federation_family_membership_widenings_admitted ON cirislens.federation_family_membership_widenings USING btree (admitted_at, family_key_id, member_key_id, effective_at);

CREATE UNIQUE INDEX federation_family_membership_widenings_by_attestation ON cirislens.federation_family_membership_widenings USING btree (attestation_id);

CREATE INDEX federation_family_membership_widenings_by_member ON cirislens.federation_family_membership_widenings USING btree (member_key_id);

CREATE INDEX federation_family_membership_widenings_effective ON cirislens.federation_family_membership_widenings USING btree (effective_at);

CREATE INDEX federation_family_membership_widenings_without_row ON cirislens.federation_family_membership_widenings USING btree (family_key_id, member_key_id, effective_at) WHERE (attestation_id IS NULL);

CREATE INDEX federation_group_versions_by_group ON cirislens.federation_group_versions USING btree (cohort, group_key_id);

CREATE INDEX federation_identity_occurrence_history_by_occurrence ON cirislens.federation_identity_occurrence_history USING btree (occurrence_key_id);

CREATE INDEX federation_identity_occurrence_revocations_admitted ON cirislens.federation_identity_occurrence_revocations USING btree (admitted_at, identity_key_id, occurrence_key_id);

CREATE INDEX federation_identity_occurrence_revocations_by_occurrence ON cirislens.federation_identity_occurrence_revocations USING btree (occurrence_key_id);

CREATE INDEX federation_identity_occurrence_revocations_effective ON cirislens.federation_identity_occurrence_revocations USING btree (effective_at);

CREATE INDEX federation_identity_occurrences_admitted ON cirislens.federation_identity_occurrences USING btree (admitted_at, identity_key_id, occurrence_key_id);

CREATE UNIQUE INDEX federation_identity_occurrences_by_attestation ON cirislens.federation_identity_occurrences USING btree (attestation_id);

CREATE INDEX federation_identity_occurrences_by_identity ON cirislens.federation_identity_occurrences USING btree (identity_key_id);

CREATE INDEX federation_identity_occurrences_by_occurrence_all ON cirislens.federation_identity_occurrences USING btree (occurrence_key_id);

CREATE INDEX federation_identity_occurrences_by_occurrence_live ON cirislens.federation_identity_occurrences USING btree (occurrence_key_id) WHERE (valid_until IS NULL);

CREATE INDEX federation_identity_occurrences_without_row ON cirislens.federation_identity_occurrences USING btree (identity_key_id, occurrence_key_id) WHERE (attestation_id IS NULL);

CREATE INDEX federation_key_registration_history_by_key ON cirislens.federation_key_registration_history USING btree (key_id, history_id);

CREATE INDEX federation_keys_accord_holder_evidence ON cirislens.federation_keys USING btree (key_id) WHERE (identity_type = 'accord_holder'::text);

CREATE UNIQUE INDEX federation_keys_by_attestation ON cirislens.federation_keys USING btree (attestation_id);

CREATE INDEX federation_keys_consent_role ON cirislens.federation_keys USING btree (consent_role) WHERE (consent_role <> 'unregistered'::text);

CREATE INDEX federation_keys_expires_at ON cirislens.federation_keys USING btree (expires_at) WHERE (expires_at IS NOT NULL);

CREATE INDEX federation_keys_identity ON cirislens.federation_keys USING btree (identity_type, identity_ref);

CREATE INDEX federation_keys_scrub_key ON cirislens.federation_keys USING btree (scrub_key_id);

CREATE INDEX federation_keys_serve_position ON cirislens.federation_keys USING btree (GREATEST(admitted_at, mutated_at), key_id);

CREATE INDEX federation_keys_trust_domains_gin ON cirislens.federation_keys USING gin (trust_domains) WHERE (trust_relationship = 'registry'::text);

CREATE INDEX federation_keys_trust_relationship ON cirislens.federation_keys USING btree (trust_relationship);

CREATE INDEX federation_keys_without_row ON cirislens.federation_keys USING btree (key_id) WHERE (attestation_id IS NULL);

CREATE INDEX federation_location_proofs_admitted ON cirislens.federation_location_proofs USING btree (admitted_at, subject_key_id, persist_row_hash);

CREATE INDEX federation_location_proofs_by_cell ON cirislens.federation_location_proofs USING btree (cell_id);

CREATE INDEX federation_location_proofs_by_subject_live ON cirislens.federation_location_proofs USING btree (subject_key_id) WHERE (withdrawn_at IS NULL);

CREATE INDEX federation_manifest_children_by_child ON cirislens.federation_manifest_children USING btree (child_sha256);

CREATE INDEX federation_peer_metadata_cohort_scope ON cirislens.federation_peer_metadata USING btree (((policy_blob ->> 'cohort_scope'::text))) WHERE ((removed_at IS NULL) AND (policy_blob IS NOT NULL));

CREATE INDEX federation_revocation_quorum_state_committed ON cirislens.federation_revocation_quorum_state USING btree (quorum_reached_at DESC) WHERE (quorum_reached_at IS NOT NULL);

CREATE INDEX federation_revocation_quorum_state_pending ON cirislens.federation_revocation_quorum_state USING btree (revocation_id, quorum_weight);

CREATE INDEX federation_revocations_admitted ON cirislens.federation_revocations USING btree (admitted_at, revocation_id);

CREATE UNIQUE INDEX federation_revocations_by_attestation ON cirislens.federation_revocations USING btree (attestation_id);

CREATE INDEX federation_revocations_observed_region ON cirislens.federation_revocations USING btree (observed_region, revoked_key_sha256_ed25519_raw, scrub_timestamp DESC) WHERE (observed_region <> 'us'::text);

CREATE INDEX federation_revocations_revoked ON cirislens.federation_revocations USING btree (revoked_key_id, effective_at DESC);

CREATE INDEX federation_revocations_subject ON cirislens.federation_revocations USING btree (revoked_key_sha256_ed25519_raw, effective_at DESC);

CREATE INDEX federation_revocations_without_row ON cirislens.federation_revocations USING btree (revocation_id) WHERE (attestation_id IS NULL);

CREATE INDEX federation_self_roster_proposals_open ON cirislens.federation_self_roster_proposals USING btree (identity_key_id, received_at) WHERE (settled_at IS NULL);

CREATE INDEX federation_self_roster_proposals_settled ON cirislens.federation_self_roster_proposals USING btree (identity_key_id, settled_at) WHERE (settled_at IS NOT NULL);

CREATE INDEX federation_stream_chunks_chunk_sha ON cirislens.federation_stream_chunks USING btree (chunk_sha);

CREATE INDEX federation_stream_chunks_stream_epoch ON cirislens.federation_stream_chunks USING btree (stream_id, epoch);

CREATE INDEX federation_stream_dek_grants_recipient ON cirislens.federation_stream_dek_grants USING btree (recipient_key_id, cohort_scope);

CREATE INDEX federation_stream_delivery_receipts_stream_k ON cirislens.federation_stream_delivery_receipts USING btree (stream_id, k);

CREATE INDEX federation_stream_sth_stream_size ON cirislens.federation_stream_sth USING btree (stream_id, tree_size DESC);

CREATE UNIQUE INDEX federation_trust_grants_tenant_chain ON cirislens.federation_trust_grants USING btree (tenant_id, chain_event_id);

COMMENT ON INDEX cirislens.federation_trust_grants_tenant_chain IS 'v2.0.x — UNIQUE(tenant_id, chain_event_id). Mirrors the per-tenant key shape audit_log uses (UNIQUE(tenant_id, sequence_number)) and merkle_leaves uses (UNIQUE(tenant_id, chain_event_id)). Makes lookup_grant_id_by_chain_event query_opt single-row contract enforceable at the schema level.';

CREATE INDEX feedback_mappings_source_message ON cirislens.feedback_mappings USING btree (source_message_id) WHERE (source_message_id IS NOT NULL);

CREATE INDEX feedback_mappings_thought ON cirislens.feedback_mappings USING btree (target_thought_id) WHERE (target_thought_id IS NOT NULL);

CREATE INDEX feedback_mappings_type_recent ON cirislens.feedback_mappings USING btree (feedback_type, created_at DESC) WHERE (feedback_type IS NOT NULL);

CREATE INDEX goals_attestation_id ON cirislens.goals USING btree (attestation_id);

CREATE INDEX goals_declared_by_key_id ON cirislens.goals USING btree (declared_by_key_id);

CREATE INDEX goals_meta_dimension ON cirislens.goals USING btree (meta_dimension);

CREATE INDEX goals_retired_at_live ON cirislens.goals USING btree (retired_at) WHERE (retired_at IS NULL);

CREATE INDEX goals_scope_cohort ON cirislens.goals USING btree (scale, scope_cohort_id) WHERE (scale = 'cohort'::text);

CREATE UNIQUE INDEX hard_case_events_by_attestation ON cirislens.hard_case_events USING btree (attestation_id);

CREATE INDEX hard_case_events_by_emitter ON cirislens.hard_case_events USING btree (emitter_key_id, emitted_at);

CREATE INDEX hard_case_events_by_kind_time ON cirislens.hard_case_events USING btree (kind, emitted_at);

CREATE INDEX hard_case_events_by_target ON cirislens.hard_case_events USING btree (target_key_id);

CREATE INDEX hard_case_events_legacy ON cirislens.hard_case_events USING btree (event_id) WHERE (attestation_id IS NULL);

CREATE INDEX idx_blackhole_until ON cirislens.blackhole_rules USING btree (until) WHERE (until IS NOT NULL);

CREATE INDEX idx_federation_attestations_v060_by_target ON cirislens.federation_attestations USING btree (attested_key_id, cohort_scope, asserted_at DESC);

CREATE INDEX idx_federation_attestations_v060_emitter_scope ON cirislens.federation_attestations USING btree (scrub_key_id, cohort_scope);

CREATE INDEX idx_federation_communities_members_gin ON cirislens.federation_communities USING gin (members);

CREATE INDEX idx_federation_scope_blobs_accessed ON cirislens.federation_scope_blobs USING btree (last_accessed_at);

CREATE INDEX idx_federation_scope_blobs_admitted ON cirislens.federation_scope_blobs USING btree (admitted_at);

CREATE INDEX idx_fpm_alias ON cirislens.federation_peer_metadata USING btree (alias) WHERE (alias IS NOT NULL);

CREATE INDEX idx_fpm_trust ON cirislens.federation_peer_metadata USING btree (trust) WHERE (removed_at IS NULL);

CREATE INDEX idx_ftg_chain ON cirislens.federation_trust_grants USING btree (chain_event_id);

CREATE INDEX idx_ftg_grantee_purpose ON cirislens.federation_trust_grants USING btree (grantee_key, purpose, scope) WHERE (revoked_at IS NULL);

CREATE INDEX idx_ftg_granter ON cirislens.federation_trust_grants USING btree (granter_key);

CREATE INDEX idx_ftg_tenant ON cirislens.federation_trust_grants USING btree (tenant_id);

CREATE INDEX idx_identity_canonical_binding_federation_key_id ON cirislens.identity_canonical_binding USING btree (federation_key_id);

CREATE INDEX idx_key_escrows_key ON cirislens.key_escrows USING btree (key_id);

CREATE INDEX idx_key_escrows_org ON cirislens.key_escrows USING btree (org_id);

CREATE INDEX idx_ledger_entry_ranges_to ON cirislens.ledger_entry_ranges USING btree (ledger_id, to_seq);

CREATE INDEX idx_ledger_fork_evidence_ledger ON cirislens.ledger_fork_evidence USING btree (ledger_id);

CREATE INDEX idx_ledger_heads_owner ON cirislens.ledger_heads USING btree (owner_key_id);

CREATE INDEX idx_lineage_head_cosigns_lineage ON cirislens.federation_lineage_head_cosigns USING btree (lineage_key_id, signed_at);

CREATE INDEX idx_merkle_leaves_chain ON cirislens.merkle_leaves USING btree (chain_event_id);

CREATE INDEX idx_merkle_sth_signed_at ON cirislens.merkle_sth_log USING btree (tenant_id, signed_at DESC);

CREATE INDEX idx_trace_events_v060_repository_stats ON cirislens.trace_events USING btree (cohort_scope, cohort_target_id, ts, deployment_domain) INCLUDE (trace_id, agent_id_hash, scrub_key_id);

CREATE INDEX incident_correlation_gin ON cirislens.incident_records USING gin (correlation_keys);

CREATE INDEX incident_first_seen ON cirislens.incident_records USING btree (tenant_id, first_seen_at);

CREATE INDEX incident_open_recent ON cirislens.incident_records USING btree (tenant_id, state, last_seen_at) WHERE (state = ANY (ARRAY['open'::text, 'investigating'::text, 'recurring'::text]));

CREATE INDEX incident_records_filename_line ON cirislens.incident_records USING btree (filename, line_number) WHERE (filename IS NOT NULL);

CREATE INDEX incident_records_source_component ON cirislens.incident_records USING btree (source_component) WHERE (source_component IS NOT NULL);

CREATE INDEX known_wire_hashes_age ON cirislens.known_wire_hashes USING btree (last_advertised_at);

CREATE INDEX maintenance_locks_active ON cirislens.maintenance_locks USING btree (locked_at DESC) WHERE (locked_by IS NOT NULL);

CREATE INDEX occurrence_registry_identity_live ON cirislens.occurrence_registry USING btree (identity, expires_at);

CREATE INDEX purge_executions_serve ON cirislens.purge_executions USING btree (admitted_at, notice_id);

CREATE INDEX purge_tombstones_ordinal ON cirislens.purge_tombstones USING btree (notice_id, ordinal);

CREATE INDEX purge_tombstones_record ON cirislens.purge_tombstones USING btree (plane, record_ref);

CREATE INDEX scheduled_tasks_due ON cirislens.scheduled_tasks USING btree (agent_occurrence_id, next_trigger_at) WHERE ((next_trigger_at IS NOT NULL) AND (status = ANY (ARRAY['PENDING'::text, 'ACTIVE'::text])));

CREATE INDEX scheduled_tasks_origin ON cirislens.scheduled_tasks USING btree (origin_thought_id);

CREATE INDEX scheduled_tasks_status_occurrence ON cirislens.scheduled_tasks USING btree (agent_occurrence_id, status, created_at DESC);

CREATE INDEX service_correlations_metric_time ON cirislens.service_correlations USING btree (metric_name, "timestamp" DESC) WHERE (metric_name IS NOT NULL);

CREATE INDEX service_correlations_parent_span ON cirislens.service_correlations USING btree (parent_span_id) WHERE (parent_span_id IS NOT NULL);

CREATE INDEX service_correlations_service_recency ON cirislens.service_correlations USING btree (agent_occurrence_id, service_type, updated_at DESC);

CREATE INDEX service_correlations_trace_id ON cirislens.service_correlations USING btree (trace_id) WHERE (trace_id IS NOT NULL);

CREATE INDEX service_correlations_type_time ON cirislens.service_correlations USING btree (correlation_type, "timestamp" DESC);

CREATE INDEX shared_instance_leases_heartbeat_idx ON cirislens.shared_instance_leases USING btree (last_heartbeat_at);

CREATE INDEX signed_wire_index_record_key ON cirislens.signed_wire_index USING btree (kind, record_key);

CREATE INDEX tasks_channel ON cirislens.tasks USING btree (channel_id, updated_at DESC);

CREATE UNIQUE INDEX tasks_correlation_id_unique ON cirislens.tasks USING btree (agent_occurrence_id, ((context_json ->> 'correlation_id'::text))) WHERE ((context_json IS NOT NULL) AND ((context_json ->> 'correlation_id'::text) IS NOT NULL));

CREATE INDEX tasks_parent ON cirislens.tasks USING btree (parent_task_id) WHERE (parent_task_id IS NOT NULL);

CREATE INDEX tasks_status_occurrence ON cirislens.tasks USING btree (agent_occurrence_id, status, updated_at DESC);

CREATE INDEX thoughts_parent ON cirislens.thoughts USING btree (parent_thought_id) WHERE (parent_thought_id IS NOT NULL);

CREATE INDEX thoughts_status_occurrence ON cirislens.thoughts USING btree (agent_occurrence_id, status, updated_at DESC);

CREATE INDEX thoughts_task_recency ON cirislens.thoughts USING btree (source_task_id, updated_at DESC);

CREATE INDEX tickets_correlation ON cirislens.tickets USING btree (correlation_id) WHERE (correlation_id IS NOT NULL);

CREATE INDEX tickets_due_deadline ON cirislens.tickets USING btree (status, deadline) WHERE (status <> ALL (ARRAY['completed'::text, 'cancelled'::text, 'failed'::text]));

CREATE INDEX tickets_email_recency ON cirislens.tickets USING btree (email, last_updated DESC);

CREATE INDEX tickets_sop_status_recency ON cirislens.tickets USING btree (agent_occurrence_id, sop, status, last_updated DESC);

CREATE INDEX trace_events_admitted_at ON cirislens.trace_events USING btree (admitted_at DESC) WHERE (admitted_at IS NOT NULL);

CREATE INDEX trace_events_agent_role ON cirislens.trace_events USING btree (agent_role, ts DESC) WHERE (agent_role IS NOT NULL);

CREATE INDEX trace_events_agent_ts ON cirislens.trace_events USING btree (agent_name, ts DESC);

CREATE INDEX trace_events_agenthash_ts ON cirislens.trace_events USING btree (agent_id_hash, ts);

CREATE INDEX trace_events_an_csdma ON cirislens.trace_events USING btree (deployment_domain, ts, agent_id_hash, agent_name, (((payload ->> 'csdma_plausibility_score'::text))::double precision)) WHERE ((event_type = 'DMA_RESULTS'::text) AND (payload ? 'csdma_plausibility_score'::text));

CREATE INDEX trace_events_an_dsdma ON cirislens.trace_events USING btree (deployment_domain, ts, agent_id_hash, agent_name, (((payload ->> 'dsdma_domain_alignment'::text))::double precision)) WHERE ((event_type = 'DMA_RESULTS'::text) AND (payload ? 'dsdma_domain_alignment'::text));

CREATE INDEX trace_events_an_idma_corr ON cirislens.trace_events USING btree (deployment_domain, ts, agent_id_hash, agent_name, (((payload ->> 'idma_correlation_risk'::text))::double precision)) WHERE ((event_type = 'IDMA_RESULT'::text) AND (payload ? 'idma_correlation_risk'::text));

CREATE INDEX trace_events_an_idma_keff ON cirislens.trace_events USING btree (deployment_domain, ts, agent_id_hash, agent_name, (((payload ->> 'idma_k_eff'::text))::double precision)) WHERE ((event_type = 'IDMA_RESULT'::text) AND (payload ? 'idma_k_eff'::text));

CREATE INDEX trace_events_an_trace_summary ON cirislens.trace_events USING btree (trace_id, ts) INCLUDE (event_type, agent_id_hash, cost_usd);

CREATE INDEX trace_events_audit_seq ON cirislens.trace_events USING btree (audit_sequence_number) WHERE (audit_sequence_number IS NOT NULL);

CREATE UNIQUE INDEX trace_events_dedup_sharded ON cirislens.trace_events USING btree (shard_key, agent_id_hash, trace_id, thought_id, event_type, attempt_index, ts);

CREATE INDEX trace_events_deployment_domain ON cirislens.trace_events USING btree (deployment_domain, ts DESC) WHERE (deployment_domain IS NOT NULL);

CREATE INDEX trace_events_deployment_trust_mode ON cirislens.trace_events USING btree (deployment_trust_mode, ts DESC) WHERE (deployment_trust_mode IS NOT NULL);

CREATE INDEX trace_events_deployment_type ON cirislens.trace_events USING btree (deployment_type, ts DESC) WHERE (deployment_type IS NOT NULL);

CREATE INDEX trace_events_domain_ts ON cirislens.trace_events USING btree (deployment_domain, ts);

CREATE INDEX trace_events_factor_rollup_1h_agent_bucket ON cirislens.trace_events_factor_rollup_1h USING btree (agent_id_hash, bucket_start);

CREATE UNIQUE INDEX trace_events_factor_rollup_1h_key ON cirislens.trace_events_factor_rollup_1h USING btree (bucket_start, COALESCE(agent_id_hash, ''::text), COALESCE(deployment_domain, ''::text), COALESCE(cohort_scope, ''::text), COALESCE(cohort_target_id, ''::text));

CREATE INDEX trace_events_journey ON cirislens.trace_events USING btree (thought_id, ts);

CREATE INDEX trace_events_pqc_key ON cirislens.trace_events USING btree (pqc_key_id, ts DESC);

CREATE INDEX trace_events_scrub_key ON cirislens.trace_events USING btree (scrub_key_id, ts DESC) WHERE (scrub_signature IS NOT NULL);

CREATE INDEX trace_events_scrub_treatment ON cirislens.trace_events USING btree (scrub_applied_trace_level, scrub_model_digest, ts DESC) WHERE (scrub_ner_ran IS NOT NULL);

CREATE INDEX trace_events_shard_backfill ON cirislens.trace_events USING btree (event_id) WHERE (shard_key IS NULL);

CREATE INDEX trace_events_trace_ts_scope ON cirislens.trace_events USING btree (trace_id, ts) INCLUDE (cohort_scope, cohort_target_id);

CREATE INDEX trace_events_type_ts ON cirislens.trace_events USING btree (event_type, ts DESC);

CREATE INDEX trace_llm_calls_model_ts ON cirislens.trace_llm_calls USING btree (model, ts DESC);

CREATE INDEX trace_llm_calls_parent ON cirislens.trace_llm_calls USING btree (parent_event_id);

CREATE INDEX trace_llm_calls_status_ts ON cirislens.trace_llm_calls USING btree (status, ts DESC) WHERE (status IS DISTINCT FROM 'ok'::text);

CREATE INDEX trace_llm_calls_thought ON cirislens.trace_llm_calls USING btree (thought_id, ts);

CREATE INDEX transport_destinations_admitted ON cirislens.transport_destinations USING btree (admitted_at, occurrence_key_id, transport_kind);

CREATE INDEX transport_destinations_by_occurrence ON cirislens.transport_destinations USING btree (occurrence_key_id);

CREATE INDEX wa_cert_adapter ON cirislens.wa_cert USING btree (adapter_id) WHERE (adapter_id IS NOT NULL);

CREATE UNIQUE INDEX wa_cert_jwt_kid ON cirislens.wa_cert USING btree (jwt_kid);

CREATE INDEX wa_cert_oauth ON cirislens.wa_cert USING btree (oauth_provider, oauth_external_id) WHERE ((oauth_provider IS NOT NULL) AND (oauth_external_id IS NOT NULL));

CREATE INDEX wa_cert_parent ON cirislens.wa_cert USING btree (parent_wa_id) WHERE (parent_wa_id IS NOT NULL);

CREATE INDEX wa_cert_role_active ON cirislens.wa_cert USING btree (role, active) WHERE (active = true);

CREATE INDEX wholeness_witness_corpus_peer_recency ON cirislens.wholeness_witness_corpus USING btree (peer_id, observed_at_unix_ms DESC);

CREATE UNIQUE INDEX calibration_bundles_one_current ON cirislens_derived.calibration_bundles USING btree (is_current) WHERE (is_current = true);

CREATE INDEX calibration_bundles_projection_version ON cirislens_derived.calibration_bundles USING btree (projection_version, ratchet_calibration_version DESC);

CREATE INDEX detection_events_body_sha256 ON cirislens_derived.detection_events USING btree (body_sha256);

CREATE UNIQUE INDEX detection_events_by_attestation ON cirislens_derived.detection_events USING btree (attestation_id);

CREATE INDEX detection_events_detector_ts ON cirislens_derived.detection_events USING btree (detector, ts DESC);

CREATE INDEX detection_events_erased_at ON cirislens_derived.detection_events USING btree (erased_at) WHERE (erased_at IS NOT NULL);

CREATE INDEX detection_events_legacy ON cirislens_derived.detection_events USING btree (detection_id) WHERE (attestation_id IS NULL);

CREATE INDEX detection_events_trace_id ON cirislens_derived.detection_events USING btree (trace_id);

CREATE INDEX access_log_accessor ON cirislens_secrets.access_log USING btree (accessor);

CREATE INDEX access_log_created_at ON cirislens_secrets.access_log USING btree (created_at);

CREATE INDEX access_log_secret_uuid ON cirislens_secrets.access_log USING btree (secret_uuid) WHERE (secret_uuid IS NOT NULL);

CREATE INDEX access_log_trace_id ON cirislens_secrets.access_log USING btree (trace_id) WHERE (trace_id IS NOT NULL);

CREATE INDEX master_key_active ON cirislens_secrets.master_key_meta USING btree (activated_at) WHERE (deactivated_at IS NULL);

CREATE UNIQUE INDEX master_key_one_active ON cirislens_secrets.master_key_meta USING btree ((true)) WHERE ((activated_at IS NOT NULL) AND (deactivated_at IS NULL));

COMMENT ON INDEX cirislens_secrets.master_key_one_active IS 'v2.0 (CIRISPersist secrets-concurrency hardening) — DB-enforced "exactly one active master key". active := activated_at IS NOT NULL AND deactivated_at IS NULL. Backstops rotate_master_key''s first-use activation against concurrent bootstrap.';

CREATE INDEX secrets_created_at ON cirislens_secrets.secrets USING btree (created_at);

CREATE INDEX secrets_pattern ON cirislens_secrets.secrets USING btree (detected_pattern);

CREATE INDEX secrets_sensitivity ON cirislens_secrets.secrets USING btree (sensitivity_level);

CREATE INDEX secrets_source_message ON cirislens_secrets.secrets USING btree (source_message_id) WHERE (source_message_id IS NOT NULL);

CREATE INDEX credits_cell ON cirisnode.credits_ledger USING btree (domain, language);

CREATE INDEX credits_contributor ON cirisnode.credits_ledger USING btree (contributor_id);

CREATE INDEX expertise_cell ON cirisnode.expertise_ledger USING btree (domain, language);

CREATE INDEX expertise_contributor ON cirisnode.expertise_ledger USING btree (contributor_id);

CREATE INDEX expertise_routable ON cirisnode.expertise_ledger USING btree (domain, language, is_active) WHERE ((expertise > (0)::double precision) AND (is_active = true));

CREATE INDEX federation_delivery_attestations_peer ON cirisnode.federation_delivery_attestations USING btree (peer_key_id);

CREATE INDEX federation_delivery_attestations_received_at ON cirisnode.federation_delivery_attestations USING btree (received_at);

CREATE INDEX idx_scheduled_takedowns_pending ON cirisnode.scheduled_takedown_actions USING btree (scheduled_eviction_at) WHERE (status = 'pending'::text);

CREATE INDEX promotion_attestations_attested_at ON cirisnode.promotion_attestations USING btree (attested_at);

CREATE INDEX promotion_attestations_attested_by ON cirisnode.promotion_attestations USING btree (attested_by);

CREATE INDEX promotion_attestations_target_ids_gin ON cirisnode.promotion_attestations USING gin (target_ids);

CREATE INDEX promotion_attestations_target_kind ON cirisnode.promotion_attestations USING btree (target_kind);

ALTER TABLE ONLY cirislens.accord_decision
    ADD CONSTRAINT accord_decision_proposal_digest_fkey FOREIGN KEY (proposal_digest) REFERENCES cirislens.accord_proposal(proposal_digest);

ALTER TABLE ONLY cirislens.accord_participation
    ADD CONSTRAINT accord_participation_proposal_digest_fkey FOREIGN KEY (proposal_digest) REFERENCES cirislens.accord_proposal(proposal_digest);

ALTER TABLE ONLY cirislens.attestation_subjects
    ADD CONSTRAINT attestation_subjects_attestation_id_fkey FOREIGN KEY (attestation_id) REFERENCES cirislens.federation_attestations(attestation_id) ON DELETE CASCADE;

ALTER TABLE ONLY cirislens.continuity_awareness
    ADD CONSTRAINT continuity_awareness_preservation_fk FOREIGN KEY (preservation_node_id, preservation_scope) REFERENCES cirisgraph.nodes(node_id, scope) DEFERRABLE INITIALLY DEFERRED;

ALTER TABLE ONLY cirislens.deferral_reports
    ADD CONSTRAINT deferral_reports_task_fk FOREIGN KEY (task_id) REFERENCES cirislens.tasks(task_id) DEFERRABLE INITIALLY DEFERRED;

ALTER TABLE ONLY cirislens.deferral_reports
    ADD CONSTRAINT deferral_reports_thought_fk FOREIGN KEY (thought_id) REFERENCES cirislens.thoughts(thought_id) DEFERRABLE INITIALLY DEFERRED;

ALTER TABLE ONLY cirislens.edge_outbound_queue
    ADD CONSTRAINT destination_key_must_exist FOREIGN KEY (destination_key_id) REFERENCES cirislens.federation_keys(key_id);

ALTER TABLE ONLY cirislens.edge_detection_events
    ADD CONSTRAINT edge_detection_events_subject_key_id_fkey FOREIGN KEY (subject_key_id) REFERENCES cirislens.federation_keys(key_id);

ALTER TABLE ONLY cirislens.federation_attestations
    ADD CONSTRAINT federation_attestations_attesting_key_id_fkey FOREIGN KEY (attesting_key_id) REFERENCES cirislens.federation_keys(key_id);

ALTER TABLE ONLY cirislens.federation_attestations
    ADD CONSTRAINT federation_attestations_scrub_key_id_fkey FOREIGN KEY (scrub_key_id) REFERENCES cirislens.federation_keys(key_id);

ALTER TABLE ONLY cirislens.federation_communities
    ADD CONSTRAINT federation_communities_attestation_id_fkey FOREIGN KEY (attestation_id) REFERENCES cirislens.federation_attestations(attestation_id) ON DELETE SET NULL;

ALTER TABLE ONLY cirislens.federation_community_membership_revocations
    ADD CONSTRAINT federation_community_membership_re_removed_identity_key_id_fkey FOREIGN KEY (removed_identity_key_id) REFERENCES cirislens.federation_keys(key_id);

ALTER TABLE ONLY cirislens.federation_community_membership_revocations
    ADD CONSTRAINT federation_community_membership_revocations_attestation_id_fkey FOREIGN KEY (attestation_id) REFERENCES cirislens.federation_attestations(attestation_id) ON DELETE SET NULL;

ALTER TABLE ONLY cirislens.federation_community_membership_revocations
    ADD CONSTRAINT federation_community_membership_revocations_community_fkey FOREIGN KEY (community_key_id) REFERENCES cirislens.federation_communities(community_key_id);

ALTER TABLE ONLY cirislens.federation_community_membership_widenings
    ADD CONSTRAINT federation_community_membership_widenings_attestation_id_fkey FOREIGN KEY (attestation_id) REFERENCES cirislens.federation_attestations(attestation_id) ON DELETE SET NULL;

ALTER TABLE ONLY cirislens.federation_community_membership_widenings
    ADD CONSTRAINT federation_community_membership_widenings_community_key_id_fkey FOREIGN KEY (community_key_id) REFERENCES cirislens.federation_communities(community_key_id);

ALTER TABLE ONLY cirislens.federation_community_membership_widenings
    ADD CONSTRAINT federation_community_membership_widenings_member_key_id_fkey FOREIGN KEY (member_key_id) REFERENCES cirislens.federation_keys(key_id);

ALTER TABLE ONLY cirislens.federation_families
    ADD CONSTRAINT federation_families_attestation_id_fkey FOREIGN KEY (attestation_id) REFERENCES cirislens.federation_attestations(attestation_id) ON DELETE SET NULL;

ALTER TABLE ONLY cirislens.federation_family_membership_revocations
    ADD CONSTRAINT federation_family_membership_revoc_removed_identity_key_id_fkey FOREIGN KEY (removed_identity_key_id) REFERENCES cirislens.federation_keys(key_id);

ALTER TABLE ONLY cirislens.federation_family_membership_revocations
    ADD CONSTRAINT federation_family_membership_revocations_attestation_id_fkey FOREIGN KEY (attestation_id) REFERENCES cirislens.federation_attestations(attestation_id) ON DELETE SET NULL;

ALTER TABLE ONLY cirislens.federation_family_membership_revocations
    ADD CONSTRAINT federation_family_membership_revocations_family_fkey FOREIGN KEY (family_key_id) REFERENCES cirislens.federation_families(family_key_id);

ALTER TABLE ONLY cirislens.federation_family_membership_widenings
    ADD CONSTRAINT federation_family_membership_widenings_attestation_id_fkey FOREIGN KEY (attestation_id) REFERENCES cirislens.federation_attestations(attestation_id) ON DELETE SET NULL;

ALTER TABLE ONLY cirislens.federation_family_membership_widenings
    ADD CONSTRAINT federation_family_membership_widenings_family_key_id_fkey FOREIGN KEY (family_key_id) REFERENCES cirislens.federation_families(family_key_id);

ALTER TABLE ONLY cirislens.federation_family_membership_widenings
    ADD CONSTRAINT federation_family_membership_widenings_member_key_id_fkey FOREIGN KEY (member_key_id) REFERENCES cirislens.federation_keys(key_id);

ALTER TABLE ONLY cirislens.federation_identity_occurrence_revocations
    ADD CONSTRAINT federation_identity_occurrence_revocatio_occurrence_key_id_fkey FOREIGN KEY (occurrence_key_id) REFERENCES cirislens.federation_keys(key_id);

ALTER TABLE ONLY cirislens.federation_identity_occurrence_revocations
    ADD CONSTRAINT federation_identity_occurrence_revocations_identity_key_id_fkey FOREIGN KEY (identity_key_id) REFERENCES cirislens.federation_keys(key_id);

ALTER TABLE ONLY cirislens.federation_identity_occurrences
    ADD CONSTRAINT federation_identity_occurrences_attestation_id_fkey FOREIGN KEY (attestation_id) REFERENCES cirislens.federation_attestations(attestation_id) ON DELETE SET NULL;

ALTER TABLE ONLY cirislens.federation_identity_occurrences
    ADD CONSTRAINT federation_identity_occurrences_identity_key_id_fkey FOREIGN KEY (identity_key_id) REFERENCES cirislens.federation_keys(key_id);

ALTER TABLE ONLY cirislens.federation_identity_occurrences
    ADD CONSTRAINT federation_identity_occurrences_occurrence_key_id_fkey FOREIGN KEY (occurrence_key_id) REFERENCES cirislens.federation_keys(key_id);

ALTER TABLE ONLY cirislens.federation_keys
    ADD CONSTRAINT federation_keys_attestation_id_fkey FOREIGN KEY (attestation_id) REFERENCES cirislens.federation_attestations(attestation_id) ON DELETE SET NULL;

ALTER TABLE ONLY cirislens.federation_location_proofs
    ADD CONSTRAINT federation_location_proofs_subject_key_id_fkey FOREIGN KEY (subject_key_id) REFERENCES cirislens.federation_keys(key_id);

ALTER TABLE ONLY cirislens.federation_peer_metadata
    ADD CONSTRAINT federation_peer_metadata_key_id_fkey FOREIGN KEY (key_id) REFERENCES cirislens.federation_keys(key_id) ON DELETE CASCADE;

ALTER TABLE ONLY cirislens.federation_revocation_quorum_state
    ADD CONSTRAINT federation_revocation_quorum_state_revocation_id_fkey FOREIGN KEY (revocation_id) REFERENCES cirislens.federation_revocations(revocation_id) ON DELETE CASCADE;

ALTER TABLE ONLY cirislens.federation_revocations
    ADD CONSTRAINT federation_revocations_attestation_id_fkey FOREIGN KEY (attestation_id) REFERENCES cirislens.federation_attestations(attestation_id) ON DELETE SET NULL;

ALTER TABLE ONLY cirislens.federation_revocations
    ADD CONSTRAINT federation_revocations_revoking_key_id_fkey FOREIGN KEY (revoking_key_id) REFERENCES cirislens.federation_keys(key_id);

ALTER TABLE ONLY cirislens.federation_revocations
    ADD CONSTRAINT federation_revocations_scrub_key_id_fkey FOREIGN KEY (scrub_key_id) REFERENCES cirislens.federation_keys(key_id);

ALTER TABLE ONLY cirislens.federation_self_roster_proposals
    ADD CONSTRAINT federation_self_roster_proposals_attestation_id_fkey FOREIGN KEY (attestation_id) REFERENCES cirislens.federation_attestations(attestation_id) ON DELETE CASCADE;

ALTER TABLE ONLY cirislens.federation_trust_grants
    ADD CONSTRAINT federation_trust_grants_grantee_key_fkey FOREIGN KEY (grantee_key) REFERENCES cirislens.federation_keys(key_id);

ALTER TABLE ONLY cirislens.federation_trust_grants
    ADD CONSTRAINT federation_trust_grants_granter_key_fkey FOREIGN KEY (granter_key) REFERENCES cirislens.federation_keys(key_id);

ALTER TABLE ONLY cirislens.federation_trust_grants
    ADD CONSTRAINT federation_trust_grants_revoked_by_fkey FOREIGN KEY (revoked_by) REFERENCES cirislens.federation_keys(key_id);

ALTER TABLE ONLY cirislens.feedback_mappings
    ADD CONSTRAINT feedback_mappings_target_thought_fk FOREIGN KEY (target_thought_id) REFERENCES cirislens.thoughts(thought_id) DEFERRABLE INITIALLY DEFERRED;

ALTER TABLE ONLY cirislens.goals
    ADD CONSTRAINT goals_attestation_id_fkey FOREIGN KEY (attestation_id) REFERENCES cirislens.federation_attestations(attestation_id) ON DELETE CASCADE;

ALTER TABLE ONLY cirislens.goals
    ADD CONSTRAINT goals_declared_by_key_id_fkey FOREIGN KEY (declared_by_key_id) REFERENCES cirislens.federation_keys(key_id) ON DELETE RESTRICT;

ALTER TABLE ONLY cirislens.hard_case_events
    ADD CONSTRAINT hard_case_events_attestation_id_fkey FOREIGN KEY (attestation_id) REFERENCES cirislens.federation_attestations(attestation_id) ON DELETE CASCADE;

ALTER TABLE ONLY cirislens.identity_canonical_binding
    ADD CONSTRAINT identity_canonical_binding_binding_attestation_id_fkey FOREIGN KEY (binding_attestation_id) REFERENCES cirislens.federation_attestations(attestation_id) ON DELETE SET NULL;

ALTER TABLE ONLY cirislens.identity_canonical_binding
    ADD CONSTRAINT identity_canonical_binding_federation_key_id_fkey FOREIGN KEY (federation_key_id) REFERENCES cirislens.federation_keys(key_id) ON DELETE CASCADE;

ALTER TABLE ONLY cirislens.ledger_checkpoints
    ADD CONSTRAINT ledger_checkpoints_ledger_id_fkey FOREIGN KEY (ledger_id) REFERENCES cirislens.ledger_heads(ledger_id);

ALTER TABLE ONLY cirislens.ledger_entry_ranges
    ADD CONSTRAINT ledger_entry_ranges_ledger_id_fkey FOREIGN KEY (ledger_id) REFERENCES cirislens.ledger_heads(ledger_id);

ALTER TABLE ONLY cirislens.purge_tombstones
    ADD CONSTRAINT purge_tombstones_notice_id_fkey FOREIGN KEY (notice_id) REFERENCES cirislens.purge_executions(notice_id);

ALTER TABLE ONLY cirislens.scheduled_tasks
    ADD CONSTRAINT scheduled_tasks_origin_thought_fk FOREIGN KEY (origin_thought_id) REFERENCES cirislens.thoughts(thought_id) DEFERRABLE INITIALLY DEFERRED;

ALTER TABLE ONLY cirislens.federation_keys
    ADD CONSTRAINT scrub_key_must_exist FOREIGN KEY (scrub_key_id) REFERENCES cirislens.federation_keys(key_id) DEFERRABLE INITIALLY DEFERRED;

ALTER TABLE ONLY cirislens.edge_outbound_queue
    ADD CONSTRAINT sender_key_must_exist FOREIGN KEY (sender_key_id) REFERENCES cirislens.federation_keys(key_id);

ALTER TABLE ONLY cirislens.tasks
    ADD CONSTRAINT tasks_parent_fk FOREIGN KEY (parent_task_id) REFERENCES cirislens.tasks(task_id) DEFERRABLE INITIALLY DEFERRED;

ALTER TABLE ONLY cirislens.thoughts
    ADD CONSTRAINT thoughts_parent_fk FOREIGN KEY (parent_thought_id) REFERENCES cirislens.thoughts(thought_id) DEFERRABLE INITIALLY DEFERRED;

ALTER TABLE ONLY cirislens.thoughts
    ADD CONSTRAINT thoughts_task_fk FOREIGN KEY (source_task_id) REFERENCES cirislens.tasks(task_id) ON DELETE CASCADE DEFERRABLE INITIALLY DEFERRED;

ALTER TABLE ONLY cirislens.wa_cert
    ADD CONSTRAINT wa_cert_parent_fk FOREIGN KEY (parent_wa_id) REFERENCES cirislens.wa_cert(wa_id) DEFERRABLE INITIALLY DEFERRED;

ALTER TABLE ONLY cirislens_derived.detection_events
    ADD CONSTRAINT detection_events_attestation_id_fkey FOREIGN KEY (attestation_id) REFERENCES cirislens.federation_attestations(attestation_id) ON DELETE CASCADE;

ALTER TABLE ONLY cirislens_secrets.master_key_meta
    ADD CONSTRAINT master_key_meta_rotated_to_fkey FOREIGN KEY (rotated_to) REFERENCES cirislens_secrets.master_key_meta(key_ref);

ALTER TABLE ONLY cirisnode.credits_ledger
    ADD CONSTRAINT credits_ledger_attestation_id_fkey FOREIGN KEY (attestation_id) REFERENCES cirislens.federation_attestations(attestation_id) ON DELETE CASCADE;

ALTER TABLE ONLY cirisnode.expertise_ledger
    ADD CONSTRAINT expertise_ledger_attestation_id_fkey FOREIGN KEY (attestation_id) REFERENCES cirislens.federation_attestations(attestation_id) ON DELETE CASCADE;

GRANT USAGE ON SCHEMA cirislens TO cirislens_reader;

GRANT SELECT ON TABLE cirislens.accord_active_halt TO cirislens_reader;

GRANT SELECT ON TABLE cirislens.accord_decision TO cirislens_reader;

GRANT SELECT ON TABLE cirislens.accord_participation TO cirislens_reader;

GRANT SELECT ON TABLE cirislens.accord_proposal TO cirislens_reader;

GRANT SELECT ON TABLE cirislens.accord_proposal_nonce_claim TO cirislens_reader;

GRANT SELECT ON TABLE cirislens.accord_public_keys TO cirislens_reader;

GRANT SELECT ON TABLE cirislens.announced_peers TO cirislens_reader;

GRANT SELECT ON TABLE cirislens.attestation_subjects TO cirislens_reader;

GRANT SELECT ON TABLE cirislens.audit_archives TO cirislens_reader;

GRANT SELECT ON TABLE cirislens.audit_log TO cirislens_reader;

GRANT SELECT ON TABLE cirislens.blackhole_rules TO cirislens_reader;

GRANT SELECT ON TABLE cirislens.blob_renditions TO cirislens_reader;

GRANT SELECT ON TABLE cirislens.canonical_role_withdrawal TO cirislens_reader;

GRANT SELECT ON TABLE cirislens.consent_peer_set TO cirislens_reader;

GRANT SELECT ON TABLE cirislens.consent_peer_set_for TO cirislens_reader;

GRANT SELECT ON TABLE cirislens.content_aggregation TO cirislens_reader;

GRANT SELECT ON TABLE cirislens.content_manifest TO cirislens_reader;

GRANT SELECT ON TABLE cirislens.content_symbols TO cirislens_reader;

GRANT SELECT ON TABLE cirislens.continuity_awareness TO cirislens_reader;

GRANT SELECT ON TABLE cirislens.creation_ceremonies TO cirislens_reader;

GRANT SELECT ON TABLE cirislens.dag_link_backfill_cursor TO cirislens_reader;

GRANT SELECT ON TABLE cirislens.deferral_reports TO cirislens_reader;

GRANT SELECT ON TABLE cirislens.edge_detection_events TO cirislens_reader;

GRANT SELECT ON TABLE cirislens.edge_outbound_queue TO cirislens_reader;

GRANT SELECT ON TABLE cirislens.federation_attestations TO cirislens_reader;

GRANT SELECT ON TABLE cirislens.federation_attestations_form_refused TO cirislens_reader;

GRANT SELECT ON TABLE cirislens.federation_blob_associations TO cirislens_reader;

GRANT SELECT ON TABLE cirislens.federation_blob_key_grants TO cirislens_reader;

GRANT SELECT ON TABLE cirislens.federation_blobs TO cirislens_reader;

GRANT SELECT ON TABLE cirislens.federation_communities TO cirislens_reader;

GRANT SELECT ON TABLE cirislens.federation_community_blob_epoch TO cirislens_reader;

GRANT SELECT ON TABLE cirislens.federation_community_dek TO cirislens_reader;

GRANT SELECT ON TABLE cirislens.federation_community_dek_epoch TO cirislens_reader;

GRANT SELECT ON TABLE cirislens.federation_community_dek_member_grants TO cirislens_reader;

GRANT SELECT ON TABLE cirislens.federation_community_membership_revocations TO cirislens_reader;

GRANT SELECT ON TABLE cirislens.federation_community_membership_widenings TO cirislens_reader;

GRANT SELECT ON TABLE cirislens.federation_content_kem_identity TO cirislens_reader;

GRANT SELECT ON TABLE cirislens.federation_content_master TO cirislens_reader;

GRANT SELECT ON TABLE cirislens.federation_cosign_aliases TO cirislens_reader;

GRANT SELECT ON TABLE cirislens.federation_cosign_pending TO cirislens_reader;

GRANT SELECT ON TABLE cirislens.federation_cosign_signatures TO cirislens_reader;

GRANT SELECT ON TABLE cirislens.federation_dag_chunks TO cirislens_reader;

GRANT SELECT ON TABLE cirislens.federation_families TO cirislens_reader;

GRANT SELECT ON TABLE cirislens.federation_family_membership_revocations TO cirislens_reader;

GRANT SELECT ON TABLE cirislens.federation_family_membership_widenings TO cirislens_reader;

GRANT SELECT ON TABLE cirislens.federation_group_versions TO cirislens_reader;

GRANT SELECT ON TABLE cirislens.federation_identity_occurrence_history TO cirislens_reader;

GRANT SELECT ON TABLE cirislens.federation_identity_occurrence_revocations TO cirislens_reader;

GRANT SELECT ON TABLE cirislens.federation_identity_occurrences TO cirislens_reader;

GRANT SELECT ON TABLE cirislens.federation_key_grant_pending TO cirislens_reader;

GRANT SELECT ON TABLE cirislens.federation_key_registration_history TO cirislens_reader;

GRANT SELECT ON TABLE cirislens.federation_keys TO cirislens_reader;

GRANT SELECT ON TABLE cirislens.federation_lineage_head_cosigns TO cirislens_reader;

GRANT SELECT ON TABLE cirislens.federation_location_proofs TO cirislens_reader;

GRANT SELECT ON TABLE cirislens.federation_manifest_children TO cirislens_reader;

GRANT SELECT ON TABLE cirislens.federation_peer_metadata TO cirislens_reader;

GRANT SELECT ON TABLE cirislens.federation_revocation_quorum_state TO cirislens_reader;

GRANT SELECT ON TABLE cirislens.federation_revocations TO cirislens_reader;

GRANT SELECT ON TABLE cirislens.federation_role_withdrawals TO cirislens_reader;

GRANT SELECT ON TABLE cirislens.federation_scope_blobs TO cirislens_reader;

GRANT SELECT ON TABLE cirislens.federation_self_roster_proposals TO cirislens_reader;

GRANT SELECT ON TABLE cirislens.federation_stream_chunks TO cirislens_reader;

GRANT SELECT ON TABLE cirislens.federation_stream_dek_grants TO cirislens_reader;

GRANT SELECT ON TABLE cirislens.federation_stream_deks TO cirislens_reader;

GRANT SELECT ON TABLE cirislens.federation_stream_delivery_receipts TO cirislens_reader;

GRANT SELECT ON TABLE cirislens.federation_stream_epoch_counts TO cirislens_reader;

GRANT SELECT ON TABLE cirislens.federation_stream_sth TO cirislens_reader;

GRANT SELECT ON TABLE cirislens.federation_streams TO cirislens_reader;

GRANT SELECT ON TABLE cirislens.federation_trust_direction_held TO cirislens_reader;

GRANT SELECT ON TABLE cirislens.federation_trust_grants TO cirislens_reader;

GRANT SELECT ON TABLE cirislens.federation_vote_windows TO cirislens_reader;

GRANT SELECT ON TABLE cirislens.federation_withdraws_admission_depths TO cirislens_reader;

GRANT SELECT ON TABLE cirislens.feedback_mappings TO cirislens_reader;

GRANT SELECT ON TABLE cirislens.freshness_floor TO cirislens_reader;

GRANT SELECT ON TABLE cirislens.goals TO cirislens_reader;

GRANT SELECT ON TABLE cirislens.hard_case_events TO cirislens_reader;

GRANT SELECT ON TABLE cirislens.identity_canonical_binding TO cirislens_reader;

GRANT SELECT ON TABLE cirislens.identity_sequences TO cirislens_reader;

GRANT SELECT ON TABLE cirislens.incident_records TO cirislens_reader;

GRANT SELECT ON TABLE cirislens.key_escrows TO cirislens_reader;

GRANT SELECT ON TABLE cirislens.known_wire_hashes TO cirislens_reader;

GRANT SELECT ON TABLE cirislens.ledger_checkpoints TO cirislens_reader;

GRANT SELECT ON TABLE cirislens.ledger_entry_ranges TO cirislens_reader;

GRANT SELECT ON TABLE cirislens.ledger_fork_evidence TO cirislens_reader;

GRANT SELECT ON TABLE cirislens.ledger_heads TO cirislens_reader;

GRANT SELECT ON TABLE cirislens.maintenance_locks TO cirislens_reader;

GRANT SELECT ON TABLE cirislens.merkle_leaves TO cirislens_reader;

GRANT SELECT ON TABLE cirislens.merkle_sth_log TO cirislens_reader;

GRANT SELECT ON TABLE cirislens.occurrence_registry TO cirislens_reader;

GRANT SELECT ON TABLE cirislens.purge_executions TO cirislens_reader;

GRANT SELECT ON TABLE cirislens.purge_tombstones TO cirislens_reader;

GRANT SELECT ON TABLE cirislens.retention_policies TO cirislens_reader;

GRANT SELECT ON TABLE cirislens.revoked_service_tokens TO cirislens_reader;

GRANT SELECT ON TABLE cirislens.scheduled_tasks TO cirislens_reader;

GRANT SELECT ON TABLE cirislens.service_correlations TO cirislens_reader;

GRANT SELECT ON TABLE cirislens.shared_instance_leases TO cirislens_reader;

GRANT SELECT ON TABLE cirislens.signed_wire_index TO cirislens_reader;

GRANT SELECT ON TABLE cirislens.storage_budget_installed TO cirislens_reader;

GRANT SELECT ON TABLE cirislens.tasks TO cirislens_reader;

GRANT SELECT ON TABLE cirislens.thoughts TO cirislens_reader;

GRANT SELECT ON TABLE cirislens.tickets TO cirislens_reader;

GRANT SELECT ON TABLE cirislens.trace_events TO cirislens_reader;

GRANT SELECT ON TABLE cirislens.trace_events_factor_rollup_1h TO cirislens_reader;

GRANT SELECT ON TABLE cirislens.trace_events_factor_rollup_meta TO cirislens_reader;

GRANT SELECT ON TABLE cirislens.trace_llm_calls TO cirislens_reader;

GRANT SELECT ON TABLE cirislens.trace_thought_signatures TO cirislens_reader;

GRANT SELECT ON TABLE cirislens.transport_destinations TO cirislens_reader;

GRANT SELECT ON TABLE cirislens.wa_cert TO cirislens_reader;

GRANT SELECT ON TABLE cirislens.wholeness_witness_corpus TO cirislens_reader;

ALTER DEFAULT PRIVILEGES IN SCHEMA cirislens GRANT SELECT ON TABLES TO cirislens_reader;

-- ════ edition-2 additions ════
--
-- Not in edition 1. The I1950 witness subtracts exactly these objects
-- (store::edition_baseline::EDITION_TWO_ADDITIONS) before it compares, and
-- applies the federation_keys columns below to edition 1's table.

-- The edition-2 projection of a verified key:record into federation_keys
-- (slice E2a). Edition-1-shaped rows are edition 1 with the two ids NULL; an
-- edition-2 projection carries the record's row id and kid. Every FK to
-- federation_keys stays valid (store::edition_baseline::KEYS_EDITION_TWO_POSTGRES).
ALTER TABLE cirislens.federation_keys
    ADD COLUMN edition smallint DEFAULT 1 NOT NULL CONSTRAINT federation_keys_edition_check CHECK (edition IN (1, 2)),
    ADD COLUMN record_row_id bytea CONSTRAINT federation_keys_record_row_id_check CHECK (octet_length(record_row_id) = 32),
    ADD COLUMN kid bytea CONSTRAINT federation_keys_kid_check CHECK (octet_length(kid) = 32),
    ADD CONSTRAINT federation_keys_edition_two_ids CHECK (edition <> 2 OR (record_row_id IS NOT NULL AND kid IS NOT NULL));

-- The local-tier record of an earlier store's deletion (store::edition_upgrade,
-- I1955). Node-local: no door replicates it. Counts only, never content.
CREATE TABLE cirislens.store_edition_deletions (
    deletion_id         bigint GENERATED ALWAYS AS IDENTITY PRIMARY KEY,
    tier                text NOT NULL DEFAULT 'local' CHECK (tier = 'local'),
    deleted_at          timestamp with time zone NOT NULL,
    earlier_edition     integer NOT NULL CHECK (earlier_edition = 1),
    earlier_head        integer NOT NULL,
    earlier_migrations  integer NOT NULL,
    plane_counts        text NOT NULL,
    rows_deleted        bigint NOT NULL
);

-- Slice E2a (the edition-2 wire): one row per stored edition-2 statement.
-- A `ceg-row/2` carries its row columns; a non-row object
-- (`ceg-genesis-bundle/2`, `ceg-revocation-snapshot/2`) is keyed by its
-- object id in row_id and leaves them NULL.
CREATE TABLE cirislens.ceg_statements (
    statement_id    bytea NOT NULL PRIMARY KEY CHECK (octet_length(statement_id) = 32),
    row_id          bytea NOT NULL CHECK (octet_length(row_id) = 32),
    typ             text NOT NULL,
    row_type        text,
    family          text,
    kid             bytea NOT NULL CHECK (octet_length(kid) = 32),
    iss             text NOT NULL,
    sub             text,
    author          text,
    asserted_at_ms  bigint,
    bytes           bytea NOT NULL,
    -- Slice J0: THIS node's admission position, POSIX microseconds, after
    -- the last one handed out. The serve cursor is the pair
    -- (admitted_us, statement_id) (edition2_statements_since).
    admitted_us     bigint NOT NULL,
    CHECK ((typ = 'ceg-row/2') = (row_type IS NOT NULL AND family IS NOT NULL
        AND sub IS NOT NULL AND asserted_at_ms IS NOT NULL))
);
CREATE INDEX ceg_statements_row_id ON cirislens.ceg_statements (row_id);
CREATE INDEX ceg_statements_admitted ON cirislens.ceg_statements (admitted_us, statement_id);

-- Slice E2a: the rows a statement names, by refs member path (`head`,
-- `further_heads`, `prev`, `target`, `trusted_through`, `also:ack`,
-- `also:cites`, or any other refs member verbatim). No FK: a named row may
-- not be held here. The key serves "names of X"; the index "rows naming X".
CREATE TABLE cirislens.ceg_row_names (
    row_id          bytea NOT NULL CHECK (octet_length(row_id) = 32),
    named_row_id    bytea NOT NULL CHECK (octet_length(named_row_id) = 32),
    role            text NOT NULL,
    PRIMARY KEY (row_id, named_row_id, role)
);
CREATE INDEX ceg_row_names_named ON cirislens.ceg_row_names (named_row_id, role, row_id);
