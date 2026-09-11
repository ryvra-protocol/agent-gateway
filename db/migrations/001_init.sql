CREATE TABLE IF NOT EXISTS agents (
    agent_id TEXT PRIMARY KEY,
    status TEXT NOT NULL,
    autonomy_level TEXT NOT NULL,
    session_binding TEXT,
    rate_limit INTEGER NOT NULL,
    spend_limit REAL NOT NULL,
    review_limit REAL NOT NULL,
    suspended_at TIMESTAMP,
    created_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP,
    updated_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP
);

CREATE TABLE IF NOT EXISTS agent_credentials (
    credential_id TEXT PRIMARY KEY,
    agent_id TEXT NOT NULL REFERENCES agents(agent_id),
    token_hash TEXT NOT NULL,
    session_id TEXT,
    expires_at TIMESTAMP NOT NULL,
    revoked_at TIMESTAMP,
    created_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP
);

CREATE TABLE IF NOT EXISTS agent_capabilities (
    capability_id TEXT PRIMARY KEY,
    agent_id TEXT NOT NULL REFERENCES agents(agent_id),
    status TEXT NOT NULL,
    autonomy_level TEXT NOT NULL,
    allowed_actions TEXT NOT NULL,
    allowed_assets TEXT NOT NULL,
    allowed_chains TEXT NOT NULL,
    allowed_contracts TEXT NOT NULL,
    allowed_functions TEXT NOT NULL,
    expires_at TIMESTAMP,
    revoked_at TIMESTAMP,
    created_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP
);

CREATE TABLE IF NOT EXISTS agent_mandates (
    mandate_id TEXT PRIMARY KEY,
    agent_id TEXT NOT NULL REFERENCES agents(agent_id),
    status TEXT NOT NULL,
    autonomy_level TEXT NOT NULL,
    policy_version TEXT NOT NULL,
    policy_hash TEXT NOT NULL,
    expires_at TIMESTAMP NOT NULL,
    revoked_at TIMESTAMP,
    created_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP
);

CREATE TABLE IF NOT EXISTS agent_tool_permissions (
    permission_id TEXT PRIMARY KEY,
    agent_id TEXT NOT NULL REFERENCES agents(agent_id),
    capability_id TEXT REFERENCES agent_capabilities(capability_id),
    operation_name TEXT NOT NULL,
    downstream_service TEXT NOT NULL,
    status TEXT NOT NULL,
    created_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP
);

CREATE TABLE IF NOT EXISTS agent_sessions (
    session_id TEXT PRIMARY KEY,
    agent_id TEXT NOT NULL REFERENCES agents(agent_id),
    credential_id TEXT REFERENCES agent_credentials(credential_id),
    expires_at TIMESTAMP NOT NULL,
    revoked_at TIMESTAMP,
    created_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP
);

CREATE TABLE IF NOT EXISTS agent_tasks (
    task_id TEXT PRIMARY KEY,
    agent_id TEXT NOT NULL REFERENCES agents(agent_id),
    session_id TEXT REFERENCES agent_sessions(session_id),
    status TEXT NOT NULL,
    created_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP
);

CREATE TABLE IF NOT EXISTS agent_actions (
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
    amount REAL NOT NULL,
    window_bucket TIMESTAMP NOT NULL,
    risk_reference TEXT,
    policy_version TEXT NOT NULL,
    policy_hash TEXT NOT NULL,
    expires_at TIMESTAMP NOT NULL,
    approved_at TIMESTAMP,
    cancelled_at TIMESTAMP,
    forwarded_at TIMESTAMP,
    created_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP
);

CREATE TABLE IF NOT EXISTS audit_events (
    event_id TEXT PRIMARY KEY,
    intent_id TEXT,
    agent_id TEXT,
    mandate_id TEXT,
    decision TEXT NOT NULL,
    reason_code TEXT,
    actor TEXT NOT NULL,
    payload TEXT,
    created_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP
);

CREATE TABLE IF NOT EXISTS audit_event_hashes (
    event_id TEXT PRIMARY KEY REFERENCES audit_events(event_id),
    event_hash TEXT NOT NULL,
    prev_hash TEXT,
    created_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP
);

CREATE TABLE IF NOT EXISTS authorization_events (
    authorization_event_id TEXT PRIMARY KEY,
    intent_id TEXT NOT NULL,
    policy_reference TEXT NOT NULL,
    risk_reference TEXT NOT NULL,
    decision TEXT NOT NULL,
    created_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP
);

CREATE INDEX IF NOT EXISTS idx_agents_status ON agents(status, updated_at);
CREATE INDEX IF NOT EXISTS idx_agent_credentials_agent_id ON agent_credentials(agent_id, expires_at);
CREATE INDEX IF NOT EXISTS idx_agent_capabilities_agent_id ON agent_capabilities(agent_id, status, revoked_at);
CREATE INDEX IF NOT EXISTS idx_agent_mandates_agent_id ON agent_mandates(agent_id, status, revoked_at);
CREATE INDEX IF NOT EXISTS idx_agent_actions_agent_id ON agent_actions(agent_id, created_at);
CREATE INDEX IF NOT EXISTS idx_agent_actions_intent_id ON agent_actions(intent_id);
CREATE INDEX IF NOT EXISTS idx_agent_actions_mandate_id ON agent_actions(mandate_id, created_at);
CREATE INDEX IF NOT EXISTS idx_audit_events_intent_id ON audit_events(intent_id, created_at);
CREATE INDEX IF NOT EXISTS idx_audit_events_agent_id ON audit_events(agent_id, created_at);
