CREATE TABLE agents (
    agent_id TEXT PRIMARY KEY,
    status TEXT NOT NULL,
    autonomy_level TEXT NOT NULL,
    session_binding TEXT,
    rate_limit INTEGER NOT NULL,
    spend_limit NUMERIC NOT NULL,
    review_limit NUMERIC NOT NULL,
    suspended_at TIMESTAMPTZ,
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE TABLE agent_credentials (
    credential_id TEXT PRIMARY KEY,
    agent_id TEXT NOT NULL REFERENCES agents(agent_id),
    token_hash TEXT NOT NULL,
    session_id TEXT,
    expires_at TIMESTAMPTZ NOT NULL,
    revoked_at TIMESTAMPTZ,
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE TABLE agent_capabilities (
    capability_id TEXT PRIMARY KEY,
    agent_id TEXT NOT NULL REFERENCES agents(agent_id),
    status TEXT NOT NULL,
    autonomy_level TEXT NOT NULL,
    allowed_actions JSONB NOT NULL,
    allowed_assets JSONB NOT NULL,
    allowed_chains JSONB NOT NULL,
    allowed_contracts JSONB NOT NULL,
    allowed_functions JSONB NOT NULL,
    expires_at TIMESTAMPTZ,
    revoked_at TIMESTAMPTZ,
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE TABLE agent_mandates (
    mandate_id TEXT PRIMARY KEY,
    agent_id TEXT NOT NULL REFERENCES agents(agent_id),
    status TEXT NOT NULL,
    autonomy_level TEXT NOT NULL,
    policy_version TEXT NOT NULL,
    policy_hash TEXT NOT NULL,
    expires_at TIMESTAMPTZ NOT NULL,
    revoked_at TIMESTAMPTZ,
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE TABLE agent_tool_permissions (
    permission_id TEXT PRIMARY KEY,
    agent_id TEXT NOT NULL REFERENCES agents(agent_id),
    capability_id TEXT REFERENCES agent_capabilities(capability_id),
    operation_name TEXT NOT NULL,
    downstream_service TEXT NOT NULL,
    status TEXT NOT NULL,
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE TABLE agent_sessions (
    session_id TEXT PRIMARY KEY,
    agent_id TEXT NOT NULL REFERENCES agents(agent_id),
    credential_id TEXT REFERENCES agent_credentials(credential_id),
    expires_at TIMESTAMPTZ NOT NULL,
    revoked_at TIMESTAMPTZ,
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE TABLE agent_tasks (
    task_id TEXT PRIMARY KEY,
    agent_id TEXT NOT NULL REFERENCES agents(agent_id),
    session_id TEXT REFERENCES agent_sessions(session_id),
    status TEXT NOT NULL,
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE TABLE agent_actions (
    action_id TEXT PRIMARY KEY,
    intent_id TEXT NOT NULL UNIQUE,
    agent_id TEXT NOT NULL REFERENCES agents(agent_id),
    mandate_id TEXT NOT NULL REFERENCES agent_mandates(mandate_id),
    capability_id TEXT NOT NULL REFERENCES agent_capabilities(capability_id),
    status TEXT NOT NULL,
    decision TEXT NOT NULL,
    reason_code TEXT,
    idempotency_key TEXT NOT NULL,
    nonce TEXT NOT NULL,
    request_hash TEXT NOT NULL,
    amount NUMERIC NOT NULL,
    window_bucket TIMESTAMPTZ NOT NULL,
    risk_reference TEXT,
    policy_version TEXT NOT NULL,
    policy_hash TEXT NOT NULL,
    expires_at TIMESTAMPTZ NOT NULL,
    approved_at TIMESTAMPTZ,
    cancelled_at TIMESTAMPTZ,
    forwarded_at TIMESTAMPTZ,
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE TABLE audit_events (
    event_id TEXT PRIMARY KEY,
    intent_id TEXT,
    agent_id TEXT,
    mandate_id TEXT,
    decision TEXT NOT NULL,
    reason_code TEXT,
    actor TEXT NOT NULL,
    payload JSONB,
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE TABLE audit_event_hashes (
    event_id TEXT PRIMARY KEY REFERENCES audit_events(event_id),
    event_hash TEXT NOT NULL,
    prev_hash TEXT,
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE TABLE authorization_events (
    authorization_event_id TEXT PRIMARY KEY,
    intent_id TEXT NOT NULL,
    policy_reference TEXT NOT NULL,
    risk_reference TEXT NOT NULL,
    decision TEXT NOT NULL,
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE INDEX idx_agents_status ON agents(status, updated_at);
CREATE INDEX idx_agent_credentials_agent_id ON agent_credentials(agent_id, expires_at);
CREATE INDEX idx_agent_capabilities_agent_id ON agent_capabilities(agent_id, status, revoked_at);
CREATE INDEX idx_agent_mandates_agent_id ON agent_mandates(agent_id, status, revoked_at);
CREATE INDEX idx_agent_actions_agent_id ON agent_actions(agent_id, created_at);
CREATE INDEX idx_agent_actions_intent_id ON agent_actions(intent_id);
CREATE INDEX idx_agent_actions_mandate_id ON agent_actions(mandate_id, created_at);
CREATE INDEX idx_audit_events_intent_id ON audit_events(intent_id, created_at);
CREATE INDEX idx_audit_events_agent_id ON audit_events(agent_id, created_at);
