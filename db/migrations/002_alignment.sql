ALTER TABLE agent_credentials ADD COLUMN last_used_at TIMESTAMP;

ALTER TABLE agent_actions ADD COLUMN updated_at TIMESTAMP;
ALTER TABLE agent_actions ADD COLUMN actor_type TEXT;
ALTER TABLE agent_actions ADD COLUMN actor_id TEXT;
ALTER TABLE agent_actions ADD COLUMN action_name TEXT;
ALTER TABLE agent_actions ADD COLUMN asset_id TEXT;
ALTER TABLE agent_actions ADD COLUMN chain_id TEXT;
ALTER TABLE agent_actions ADD COLUMN recipient TEXT;
ALTER TABLE agent_actions ADD COLUMN venue TEXT;
ALTER TABLE agent_actions ADD COLUMN purpose TEXT;
ALTER TABLE agent_actions ADD COLUMN correlation_id TEXT;
ALTER TABLE agent_actions ADD COLUMN policy_decision_id TEXT;
ALTER TABLE agent_actions ADD COLUMN risk_assessment_id TEXT;
ALTER TABLE agent_actions ADD COLUMN authorization_id TEXT;
ALTER TABLE agent_actions ADD COLUMN policy_outcome TEXT;
ALTER TABLE agent_actions ADD COLUMN replay_window_bucket TEXT;
ALTER TABLE agent_actions ADD COLUMN execution_contract TEXT;
ALTER TABLE agent_actions ADD COLUMN execution_function TEXT;
ALTER TABLE agent_actions ADD COLUMN execution_call_target TEXT;
ALTER TABLE agent_actions ADD COLUMN metadata_json TEXT;
ALTER TABLE agent_actions ADD COLUMN deprecation_warnings_json TEXT;
ALTER TABLE agent_actions ADD COLUMN downstream_reference TEXT;
-- Legacy columns retained and deprecated: amount, risk_reference, policy_hash, window_bucket.

ALTER TABLE audit_events ADD COLUMN actor_id TEXT;
ALTER TABLE audit_events ADD COLUMN policy_version TEXT;
ALTER TABLE audit_events ADD COLUMN risk_assessment_id TEXT;
ALTER TABLE audit_events ADD COLUMN authorization_id TEXT;
ALTER TABLE audit_events ADD COLUMN correlation_id TEXT;

ALTER TABLE authorization_events ADD COLUMN policy_decision_id TEXT;
ALTER TABLE authorization_events ADD COLUMN risk_assessment_id TEXT;
ALTER TABLE authorization_events ADD COLUMN authorization_id TEXT;
ALTER TABLE authorization_events ADD COLUMN policy_version TEXT;

CREATE UNIQUE INDEX IF NOT EXISTS idx_agent_actions_agent_idempotency ON agent_actions(agent_id, idempotency_key);
CREATE UNIQUE INDEX IF NOT EXISTS idx_agent_actions_agent_nonce_bucket ON agent_actions(agent_id, nonce, replay_window_bucket);
CREATE INDEX IF NOT EXISTS idx_agent_actions_intent_lookup ON agent_actions(intent_id);
CREATE INDEX IF NOT EXISTS idx_agent_actions_correlation_lookup ON agent_actions(correlation_id);
