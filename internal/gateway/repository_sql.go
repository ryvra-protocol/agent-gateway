package gateway

import (
	"database/sql"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"runtime"
	"sort"
	"strings"
	"time"

	_ "modernc.org/sqlite"
)

type SQLRepository struct {
	db *sql.DB
}

func OpenSQLRepository(dsn string) (*SQLRepository, error) {
	db, err := sql.Open("sqlite", dsn)
	if err != nil {
		return nil, err
	}
	db.SetMaxOpenConns(1)
	db.SetMaxIdleConns(1)
	if _, err := db.Exec(`PRAGMA busy_timeout = 5000;`); err != nil {
		return nil, err
	}
	if err := applyMigrations(db); err != nil {
		return nil, err
	}
	return &SQLRepository{db: db}, nil
}

func applyMigrations(db *sql.DB) error {
	_, err := db.Exec(`CREATE TABLE IF NOT EXISTS schema_migrations (name TEXT PRIMARY KEY, applied_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP)`)
	if err != nil {
		return err
	}
	_, file, _, ok := runtime.Caller(0)
	if !ok {
		return fmt.Errorf("cannot locate migrations")
	}
	dir := filepath.Clean(filepath.Join(filepath.Dir(file), "../../db/migrations"))
	entries, err := os.ReadDir(dir)
	if err != nil {
		return err
	}
	sort.Slice(entries, func(i, j int) bool { return entries[i].Name() < entries[j].Name() })
	for _, entry := range entries {
		if entry.IsDir() || !strings.HasSuffix(entry.Name(), ".sql") {
			continue
		}
		content, err := os.ReadFile(filepath.Join(dir, entry.Name()))
		if err != nil {
			return err
		}
		var applied string
		switch err := db.QueryRow(`SELECT name FROM schema_migrations WHERE name = ?`, entry.Name()).Scan(&applied); err {
		case nil:
			continue
		case sql.ErrNoRows:
		default:
			return err
		}
		if _, err := db.Exec(string(content)); err != nil {
			return fmt.Errorf("apply %s: %w", entry.Name(), err)
		}
		if _, err := db.Exec(`INSERT INTO schema_migrations(name) VALUES(?)`, entry.Name()); err != nil {
			return err
		}
	}
	return nil
}

func (r *SQLRepository) SeedAgent(agent Agent) error {
	if agent.RateLimit == 0 {
		agent.RateLimit = 1
	}
	_, err := r.db.Exec(`
		INSERT INTO agents(agent_id, status, autonomy_level, session_binding, rate_limit, spend_limit, review_limit, suspended_at, created_at, updated_at)
		VALUES(?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
		ON CONFLICT(agent_id) DO UPDATE SET
		status=excluded.status,
		autonomy_level=excluded.autonomy_level,
		session_binding=excluded.session_binding,
		rate_limit=excluded.rate_limit,
		spend_limit=excluded.spend_limit,
		review_limit=excluded.review_limit,
		suspended_at=excluded.suspended_at,
		updated_at=excluded.updated_at
	`, agent.ID, agent.Status, agent.AutonomyLevel, nullableString(agent.SessionBinding), agent.RateLimit, agent.SpendLimit, agent.ReviewLimit, timePtrValue(agent.SuspendedAt), time.Now().UTC(), time.Now().UTC())
	return err
}

func (r *SQLRepository) SeedCredential(credential AgentCredential) error {
	_, err := r.db.Exec(`
		INSERT INTO agent_credentials(credential_id, agent_id, token_hash, session_id, expires_at, revoked_at, last_used_at, created_at)
		VALUES(?, ?, ?, ?, ?, ?, ?, ?)
		ON CONFLICT(credential_id) DO UPDATE SET
		token_hash=excluded.token_hash,
		session_id=excluded.session_id,
		expires_at=excluded.expires_at,
		revoked_at=excluded.revoked_at,
		last_used_at=excluded.last_used_at
	`, credential.ID, credential.AgentID, hashString(credential.Token), nullableString(credential.SessionID), credential.ExpiresAt.UTC(), timePtrValue(credential.RevokedAt), timePtrValue(credential.LastUsedAt), time.Now().UTC())
	return err
}

func (r *SQLRepository) SeedCapability(capability AgentCapability) error {
	_, err := r.db.Exec(`
		INSERT INTO agent_capabilities(capability_id, agent_id, status, autonomy_level, allowed_actions, allowed_assets, allowed_chains, allowed_contracts, allowed_functions, expires_at, revoked_at, created_at)
		VALUES(?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
		ON CONFLICT(capability_id) DO UPDATE SET
		status=excluded.status,
		autonomy_level=excluded.autonomy_level,
		allowed_actions=excluded.allowed_actions,
		allowed_assets=excluded.allowed_assets,
		allowed_chains=excluded.allowed_chains,
		allowed_contracts=excluded.allowed_contracts,
		allowed_functions=excluded.allowed_functions,
		expires_at=excluded.expires_at,
		revoked_at=excluded.revoked_at
	`, capability.ID, capability.AgentID, capability.Status, capability.AutonomyLevel, mustJSON(capability.AllowedActions), mustJSON(capability.AllowedAssets), mustJSON(capability.AllowedChains), mustJSON(capability.AllowedContracts), mustJSON(capability.AllowedFunctions), timePtrValue(capability.ExpiresAt), timePtrValue(capability.RevokedAt), time.Now().UTC())
	return err
}

func (r *SQLRepository) SeedMandate(mandate AgentMandate) error {
	_, err := r.db.Exec(`
		INSERT INTO agent_mandates(mandate_id, agent_id, status, autonomy_level, policy_version, policy_hash, expires_at, revoked_at, created_at)
		VALUES(?, ?, ?, ?, ?, ?, ?, ?, ?)
		ON CONFLICT(mandate_id) DO UPDATE SET
		status=excluded.status,
		autonomy_level=excluded.autonomy_level,
		policy_version=excluded.policy_version,
		policy_hash=excluded.policy_hash,
		expires_at=excluded.expires_at,
		revoked_at=excluded.revoked_at
	`, mandate.ID, mandate.AgentID, mandate.Status, mandate.AutonomyLevel, mandate.PolicyVersion, mandate.PolicyHash, mandate.ExpiresAt.UTC(), timePtrValue(mandate.RevokedAt), time.Now().UTC())
	return err
}

func (r *SQLRepository) AuthenticateAgent(tokenHash, sessionID string, now time.Time) (authenticatedActor, error) {
	row := r.db.QueryRow(`
		SELECT c.credential_id, c.agent_id, c.session_id, c.revoked_at, c.expires_at, a.status, a.session_binding
		FROM agent_credentials c
		JOIN agents a ON a.agent_id = c.agent_id
		WHERE c.token_hash = ?
		LIMIT 1
	`, tokenHash)
	var credentialID, agentID string
	var credentialSession, agentSession sql.NullString
	var revokedAt sql.NullTime
	var expiresAt time.Time
	var status AgentStatus
	if err := row.Scan(&credentialID, &agentID, &credentialSession, &revokedAt, &expiresAt, &status, &agentSession); err != nil {
		if err == sql.ErrNoRows {
			return authenticatedActor{}, errUnauthorized
		}
		return authenticatedActor{}, err
	}
	if revokedAt.Valid || now.After(expiresAt) {
		return authenticatedActor{}, errUnauthorized
	}
	if status == AgentStatusSuspended {
		return authenticatedActor{}, errForbidden
	}
	if credentialSession.Valid && credentialSession.String != sessionID {
		return authenticatedActor{}, errUnauthorized
	}
	if agentSession.Valid && agentSession.String != sessionID {
		return authenticatedActor{}, errUnauthorized
	}
	_, _ = r.db.Exec(`UPDATE agent_credentials SET last_used_at = ? WHERE credential_id = ?`, now.UTC(), credentialID)
	return authenticatedActor{Actor: "agent:" + agentID, AgentID: agentID}, nil
}

func (r *SQLRepository) GetAgent(agentID string) (Agent, bool, error) {
	row := r.db.QueryRow(`SELECT agent_id, status, autonomy_level, session_binding, rate_limit, spend_limit, review_limit, suspended_at FROM agents WHERE agent_id = ?`, agentID)
	var agent Agent
	var sessionBinding sql.NullString
	var suspended sql.NullTime
	if err := row.Scan(&agent.ID, &agent.Status, &agent.AutonomyLevel, &sessionBinding, &agent.RateLimit, &agent.SpendLimit, &agent.ReviewLimit, &suspended); err != nil {
		if err == sql.ErrNoRows {
			return Agent{}, false, nil
		}
		return Agent{}, false, err
	}
	if sessionBinding.Valid {
		agent.SessionBinding = sessionBinding.String
	}
	if suspended.Valid {
		t := suspended.Time.UTC()
		agent.SuspendedAt = &t
	}
	return agent, true, nil
}

func (r *SQLRepository) GetCapability(capabilityID string) (AgentCapability, bool, error) {
	row := r.db.QueryRow(`SELECT capability_id, agent_id, status, autonomy_level, allowed_actions, allowed_assets, allowed_chains, allowed_contracts, allowed_functions, expires_at, revoked_at FROM agent_capabilities WHERE capability_id = ?`, capabilityID)
	var capability AgentCapability
	var actions, assets, chains, contracts, functions string
	var expiresAt, revokedAt sql.NullTime
	if err := row.Scan(&capability.ID, &capability.AgentID, &capability.Status, &capability.AutonomyLevel, &actions, &assets, &chains, &contracts, &functions, &expiresAt, &revokedAt); err != nil {
		if err == sql.ErrNoRows {
			return AgentCapability{}, false, nil
		}
		return AgentCapability{}, false, err
	}
	_ = json.Unmarshal([]byte(actions), &capability.AllowedActions)
	_ = json.Unmarshal([]byte(assets), &capability.AllowedAssets)
	_ = json.Unmarshal([]byte(chains), &capability.AllowedChains)
	_ = json.Unmarshal([]byte(contracts), &capability.AllowedContracts)
	_ = json.Unmarshal([]byte(functions), &capability.AllowedFunctions)
	if expiresAt.Valid {
		t := expiresAt.Time.UTC()
		capability.ExpiresAt = &t
	}
	if revokedAt.Valid {
		t := revokedAt.Time.UTC()
		capability.RevokedAt = &t
	}
	return capability, true, nil
}

func (r *SQLRepository) GetMandate(mandateID string) (AgentMandate, bool, error) {
	row := r.db.QueryRow(`SELECT mandate_id, agent_id, status, autonomy_level, policy_version, policy_hash, expires_at, revoked_at FROM agent_mandates WHERE mandate_id = ?`, mandateID)
	var mandate AgentMandate
	var revokedAt sql.NullTime
	if err := row.Scan(&mandate.ID, &mandate.AgentID, &mandate.Status, &mandate.AutonomyLevel, &mandate.PolicyVersion, &mandate.PolicyHash, &mandate.ExpiresAt, &revokedAt); err != nil {
		if err == sql.ErrNoRows {
			return AgentMandate{}, false, nil
		}
		return AgentMandate{}, false, err
	}
	if revokedAt.Valid {
		t := revokedAt.Time.UTC()
		mandate.RevokedAt = &t
	}
	mandate.ExpiresAt = mandate.ExpiresAt.UTC()
	return mandate, true, nil
}

func (r *SQLRepository) GetIntent(intentID string) (IntentRecord, bool, error) {
	rows, err := r.db.Query(intentRecordSelect+` WHERE intent_id = ?`, intentID)
	if err != nil {
		return IntentRecord{}, false, err
	}
	defer rows.Close()
	if !rows.Next() {
		return IntentRecord{}, false, nil
	}
	record, err := scanIntentRecord(rows)
	if err != nil {
		return IntentRecord{}, false, err
	}
	return record, true, nil
}

func (r *SQLRepository) ListAuditEvents(intentID string) ([]AuditEvent, error) {
	query := `
		SELECT e.event_id, e.created_at, e.intent_id, e.actor_id, e.agent_id, e.mandate_id, e.policy_version, e.risk_assessment_id, e.authorization_id, e.correlation_id, e.decision, e.reason_code, e.actor, h.event_hash, h.prev_hash
		FROM audit_events e
		JOIN audit_event_hashes h ON h.event_id = e.event_id
	`
	args := []interface{}{}
	if intentID != "" {
		query += ` WHERE e.intent_id = ?`
		args = append(args, intentID)
	}
	query += ` ORDER BY e.created_at, e.event_id`
	rows, err := r.db.Query(query, args...)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var events []AuditEvent
	for rows.Next() {
		var event AuditEvent
		var intentID, actorID, agentID, mandateID, policyVersion, riskID, authID, corrID, reason sql.NullString
		var createdAt flexibleTime
		var prevHash sql.NullString
		if err := rows.Scan(&event.EventID, &createdAt, &intentID, &actorID, &agentID, &mandateID, &policyVersion, &riskID, &authID, &corrID, &event.Decision, &reason, &event.Actor, &event.Hash, &prevHash); err != nil {
			return nil, err
		}
		event.Timestamp = createdAt.Time.UTC()
		event.IntentID = intentID.String
		event.ActorID = actorID.String
		event.AgentID = agentID.String
		event.MandateID = mandateID.String
		event.PolicyVersion = policyVersion.String
		event.RiskAssessmentID = riskID.String
		event.AuthorizationID = authID.String
		event.CorrelationID = corrID.String
		event.ReasonCode = reason.String
		event.PrevHash = prevHash.String
		events = append(events, event)
	}
	return events, rows.Err()
}

func (r *SQLRepository) VerifyAuditIntegrity() (bool, error) {
	events, err := r.ListAuditEvents("")
	if err != nil {
		return false, err
	}
	prev := ""
	for _, event := range events {
		if event.PrevHash != prev {
			return false, nil
		}
		if hashAuditEvent(event, prev) != event.Hash {
			return false, nil
		}
		prev = event.Hash
	}
	return true, nil
}

func (r *SQLRepository) KillSwitchActive() (bool, error) {
	row := r.db.QueryRow(`SELECT decision FROM audit_events WHERE decision IN ('killswitch_activated', 'killswitch_deactivated') ORDER BY created_at DESC, event_id DESC LIMIT 1`)
	var decision string
	if err := row.Scan(&decision); err != nil {
		if err == sql.ErrNoRows {
			return false, nil
		}
		return false, err
	}
	return decision == "killswitch_activated", nil
}

func (r *SQLRepository) CountRecentActions(agentID string, since time.Time) (int, error) {
	row := r.db.QueryRow(`SELECT COUNT(*) FROM agent_actions WHERE agent_id = ? AND created_at >= ?`, agentID, since.UTC())
	var count int
	return count, row.Scan(&count)
}

func (r *SQLRepository) SumRecentApprovedSpend(agentID string, since time.Time) (float64, error) {
	row := r.db.QueryRow(`SELECT COALESCE(SUM(amount), 0) FROM agent_actions WHERE agent_id = ? AND forwarded_at IS NOT NULL AND created_at >= ?`, agentID, since.UTC())
	var total float64
	return total, row.Scan(&total)
}

func (r *SQLRepository) FindActionByIdempotency(agentID, key string) (IntentRecord, bool, error) {
	rows, err := r.db.Query(intentRecordSelect+` WHERE agent_id = ? AND idempotency_key = ? ORDER BY created_at DESC LIMIT 1`, agentID, key)
	if err != nil {
		return IntentRecord{}, false, err
	}
	defer rows.Close()
	if !rows.Next() {
		return IntentRecord{}, false, nil
	}
	record, err := scanIntentRecord(rows)
	return record, err == nil, err
}

func (r *SQLRepository) FindActionByReplay(agentID, nonce, replayBucket string) (IntentRecord, bool, error) {
	rows, err := r.db.Query(intentRecordSelect+` WHERE agent_id = ? AND nonce = ? AND replay_window_bucket = ? ORDER BY created_at DESC LIMIT 1`, agentID, nonce, replayBucket)
	if err != nil {
		return IntentRecord{}, false, err
	}
	defer rows.Close()
	if !rows.Next() {
		return IntentRecord{}, false, nil
	}
	record, err := scanIntentRecord(rows)
	return record, err == nil, err
}

func (r *SQLRepository) SaveIntent(record IntentRecord) error {
	_, err := r.db.Exec(`
		INSERT INTO agent_actions(
			action_id, intent_id, agent_id, mandate_id, capability_id, status, decision, reason_code, idempotency_key, nonce, request_hash, amount, window_bucket, risk_reference, policy_version, policy_hash, expires_at, approved_at, cancelled_at, forwarded_at,
			actor_type, actor_id, action_name, asset_id, chain_id, recipient, venue, purpose, correlation_id, policy_decision_id, risk_assessment_id, authorization_id, policy_outcome, replay_window_bucket, execution_contract, execution_function, execution_call_target, metadata_json, deprecation_warnings_json, updated_at, downstream_reference
		) VALUES(?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
	`,
		newActionID(record.Intent.IntentID),
		record.Intent.IntentID,
		record.Execution.AgentID,
		record.Intent.MandateID,
		record.Execution.CapabilityID,
		record.Status,
		record.Status,
		nullableString(record.ReasonCode),
		record.Intent.IdempotencyKey,
		record.Execution.Nonce,
		record.RequestHash,
		amountValue(record.Intent.Amount),
		record.CreatedAt.UTC().Truncate(time.Minute),
		nullableString(record.Authority.RiskAssessmentID),
		record.Intent.PolicyVersion,
		"",
		record.Intent.ExpiresAt.UTC(),
		timePtrValue(record.ApprovedAt),
		timePtrValue(record.CancelledAt),
		nilIfFalse(record.Forwarded, record.CreatedAt.UTC()),
		record.Intent.ActorType,
		record.Intent.ActorID,
		record.Intent.Action,
		record.Intent.AssetID,
		nullableString(record.Intent.ChainID),
		nullableString(record.Intent.Recipient),
		nullableString(record.Intent.Venue),
		record.Intent.Purpose,
		record.Intent.CorrelationID,
		nullableString(record.Authority.PolicyDecisionID),
		nullableString(record.Authority.RiskAssessmentID),
		nullableString(record.Authority.AuthorizationID),
		nullableString(string(record.PolicyOutcome)),
		bucketFor(record.CreatedAt, 5*time.Minute),
		nullableString(record.Execution.ExecutionRef.Contract),
		nullableString(record.Execution.ExecutionRef.Function),
		nullableString(record.Execution.ExecutionRef.CallTarget),
		nullableJSON(record.Metadata),
		nullableJSON(record.DeprecationWarnings),
		record.UpdatedAt.UTC(),
		nullableString(record.DownstreamReference),
	)
	return err
}

func (r *SQLRepository) UpdateIntent(record IntentRecord) error {
	_, err := r.db.Exec(`
		UPDATE agent_actions SET status = ?, decision = ?, reason_code = ?, forwarded_at = ?, approved_at = ?, cancelled_at = ?, updated_at = CURRENT_TIMESTAMP, policy_outcome = ?, policy_decision_id = ?, risk_assessment_id = ?, authorization_id = ?, deprecation_warnings_json = ?, metadata_json = ?, execution_contract = ?, execution_function = ?, execution_call_target = ?, recipient = ?, venue = ?, chain_id = ? , downstream_reference = ?
		WHERE intent_id = ?
	`, record.Status, record.Status, nullableString(record.ReasonCode), nilIfFalse(record.Forwarded, record.UpdatedAt.UTC()), timePtrValue(record.ApprovedAt), timePtrValue(record.CancelledAt), nullableString(string(record.PolicyOutcome)), nullableString(record.Authority.PolicyDecisionID), nullableString(record.Authority.RiskAssessmentID), nullableString(record.Authority.AuthorizationID), nullableJSON(record.DeprecationWarnings), nullableJSON(record.Metadata), nullableString(record.Execution.ExecutionRef.Contract), nullableString(record.Execution.ExecutionRef.Function), nullableString(record.Execution.ExecutionRef.CallTarget), nullableString(record.Intent.Recipient), nullableString(record.Intent.Venue), nullableString(record.Intent.ChainID), nullableString(record.DownstreamReference), record.Intent.IntentID)
	return err
}

func (r *SQLRepository) RecordAuthorization(intentID string, authority AuthorityReferences, policyVersion string, now time.Time) error {
	_, err := r.db.Exec(`
		INSERT INTO authorization_events(authorization_event_id, intent_id, policy_reference, risk_reference, decision, policy_decision_id, risk_assessment_id, authorization_id, policy_version, created_at)
		VALUES(?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
	`, "authz:"+intentID, intentID, authority.PolicyDecisionID, authority.RiskAssessmentID, authority.Outcome, authority.PolicyDecisionID, authority.RiskAssessmentID, authority.AuthorizationID, policyVersion, now.UTC())
	return err
}

func (r *SQLRepository) AppendAudit(event AuditEvent, payload map[string]interface{}) error {
	prevHash := ""
	_ = r.db.QueryRow(`SELECT event_hash FROM audit_event_hashes ORDER BY created_at DESC, event_id DESC LIMIT 1`).Scan(&prevHash)
	event.PrevHash = prevHash
	event.Hash = hashAuditEvent(event, prevHash)
	_, err := r.db.Exec(`
		INSERT INTO audit_events(event_id, intent_id, agent_id, mandate_id, decision, reason_code, actor, payload, created_at, actor_id, policy_version, risk_assessment_id, authorization_id, correlation_id)
		VALUES(?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
	`, event.EventID, nullableString(event.IntentID), nullableString(event.AgentID), nullableString(event.MandateID), event.Decision, nullableString(event.ReasonCode), event.Actor, nullableJSON(payload), event.Timestamp.UTC(), nullableString(event.ActorID), nullableString(event.PolicyVersion), nullableString(event.RiskAssessmentID), nullableString(event.AuthorizationID), nullableString(event.CorrelationID))
	if err != nil {
		return err
	}
	_, err = r.db.Exec(`INSERT INTO audit_event_hashes(event_id, event_hash, prev_hash, created_at) VALUES(?, ?, ?, ?)`, event.EventID, event.Hash, nullableString(event.PrevHash), event.Timestamp.UTC())
	return err
}

func (r *SQLRepository) SuspendAgent(agentID string, now time.Time) error {
	res, err := r.db.Exec(`UPDATE agents SET status = ?, suspended_at = ?, updated_at = ? WHERE agent_id = ?`, AgentStatusSuspended, now.UTC(), now.UTC(), agentID)
	if err != nil {
		return err
	}
	if affected, _ := res.RowsAffected(); affected == 0 {
		return fmt.Errorf("agent not found")
	}
	return nil
}

func (r *SQLRepository) RevokeAgentCredentials(agentID string, now time.Time) error {
	_, err := r.db.Exec(`UPDATE agent_credentials SET revoked_at = ? WHERE agent_id = ? AND revoked_at IS NULL`, now.UTC(), agentID)
	return err
}

func (r *SQLRepository) RevokeCapability(capabilityID string, now time.Time) error {
	res, err := r.db.Exec(`UPDATE agent_capabilities SET status = ?, revoked_at = ? WHERE capability_id = ?`, RecordStatusRevoked, now.UTC(), capabilityID)
	if err != nil {
		return err
	}
	if affected, _ := res.RowsAffected(); affected == 0 {
		return fmt.Errorf("capability not found")
	}
	return nil
}

const intentRecordSelect = `
	SELECT intent_id, actor_type, actor_id, action_name, asset_id, amount, chain_id, recipient, venue, purpose, mandate_id, policy_version, correlation_id, idempotency_key, expires_at,
		agent_id, capability_id, nonce, execution_contract, execution_function, execution_call_target,
		status, reason_code, request_hash, forwarded_at, created_at, updated_at, approved_at, cancelled_at, policy_decision_id, risk_assessment_id, authorization_id, policy_outcome, metadata_json, deprecation_warnings_json, downstream_reference
	FROM agent_actions`

type scanner interface {
	Scan(dest ...interface{}) error
}

func scanIntentRecord(row scanner) (IntentRecord, error) {
	var record IntentRecord
	var chainID, recipient, venue, execContract, execFunction, execCallTarget sql.NullString
	var reasonCode sql.NullString
	var forwardedAt, approvedAt, cancelledAt flexibleTime
	var expiresAt, createdAt, updatedAt flexibleTime
	var policyDecisionID, riskAssessmentID, authorizationID, policyOutcome sql.NullString
	var metadataJSON, warningsJSON, downstreamRef sql.NullString
	if err := row.Scan(
		&record.Intent.IntentID,
		&record.Intent.ActorType,
		&record.Intent.ActorID,
		&record.Intent.Action,
		&record.Intent.AssetID,
		newAmountScanTarget(&record.Intent.Amount),
		&chainID,
		&recipient,
		&venue,
		&record.Intent.Purpose,
		&record.Intent.MandateID,
		&record.Intent.PolicyVersion,
		&record.Intent.CorrelationID,
		&record.Intent.IdempotencyKey,
		&expiresAt,
		&record.Execution.AgentID,
		&record.Execution.CapabilityID,
		&record.Execution.Nonce,
		&execContract,
		&execFunction,
		&execCallTarget,
		&record.Status,
		&reasonCode,
		&record.RequestHash,
		&forwardedAt,
		&createdAt,
		&updatedAt,
		&approvedAt,
		&cancelledAt,
		&policyDecisionID,
		&riskAssessmentID,
		&authorizationID,
		&policyOutcome,
		&metadataJSON,
		&warningsJSON,
		&downstreamRef,
	); err != nil {
		return IntentRecord{}, err
	}
	record.Intent.ExpiresAt = expiresAt.Time.UTC()
	record.CreatedAt = createdAt.Time.UTC()
	record.UpdatedAt = updatedAt.Time.UTC()
	record.Intent.ChainID = chainID.String
	record.Intent.Recipient = recipient.String
	record.Intent.Venue = venue.String
	record.Execution.ExecutionRef.Contract = execContract.String
	record.Execution.ExecutionRef.Function = execFunction.String
	record.Execution.ExecutionRef.CallTarget = execCallTarget.String
	record.ReasonCode = reasonCode.String
	record.Forwarded = forwardedAt.Valid
	record.ApprovedAt = flexibleTimePtr(approvedAt)
	record.CancelledAt = flexibleTimePtr(cancelledAt)
	record.Authority.PolicyDecisionID = policyDecisionID.String
	record.Authority.RiskAssessmentID = riskAssessmentID.String
	record.Authority.AuthorizationID = authorizationID.String
	record.Authority.Outcome = PolicyOutcome(policyOutcome.String)
	record.PolicyOutcome = PolicyOutcome(policyOutcome.String)
	record.DownstreamReference = downstreamRef.String
	if metadataJSON.Valid && metadataJSON.String != "" {
		_ = json.Unmarshal([]byte(metadataJSON.String), &record.Metadata)
	}
	if warningsJSON.Valid && warningsJSON.String != "" {
		_ = json.Unmarshal([]byte(warningsJSON.String), &record.DeprecationWarnings)
	}
	return record, nil
}

type amountTarget struct{ out **float64 }

func newAmountScanTarget(out **float64) *amountTarget { return &amountTarget{out: out} }

func (a *amountTarget) Scan(src interface{}) error {
	if src == nil {
		*a.out = nil
		return nil
	}
	switch v := src.(type) {
	case float64:
		*a.out = &v
	case int64:
		f := float64(v)
		*a.out = &f
	case []byte:
		return a.Scan(string(v))
	case string:
		var f float64
		_, err := fmt.Sscan(v, &f)
		if err != nil {
			return err
		}
		*a.out = &f
	default:
		return fmt.Errorf("unsupported amount type %T", src)
	}
	return nil
}

func mustJSON(value interface{}) string {
	b, _ := json.Marshal(value)
	return string(b)
}

func nullableJSON(value interface{}) interface{} {
	if value == nil {
		return nil
	}
	b, _ := json.Marshal(value)
	if string(b) == "null" {
		return nil
	}
	return string(b)
}

func nullableString(value string) interface{} {
	if value == "" {
		return nil
	}
	return value
}

func nilIfFalse(enabled bool, t time.Time) interface{} {
	if !enabled {
		return nil
	}
	return t
}

func timePtrValue(value *time.Time) interface{} {
	if value == nil {
		return nil
	}
	return value.UTC()
}

func nullTimePtr(value sql.NullTime) *time.Time {
	if !value.Valid {
		return nil
	}
	t := value.Time.UTC()
	return &t
}

type flexibleTime struct {
	Time  time.Time
	Valid bool
}

func (f *flexibleTime) Scan(src interface{}) error {
	if src == nil {
		f.Valid = false
		f.Time = time.Time{}
		return nil
	}
	switch v := src.(type) {
	case time.Time:
		f.Time = v.UTC()
	case string:
		t, err := parseTime(v)
		if err != nil {
			return err
		}
		f.Time = t
	case []byte:
		t, err := parseTime(string(v))
		if err != nil {
			return err
		}
		f.Time = t
	default:
		return fmt.Errorf("unsupported time type %T", src)
	}
	f.Valid = true
	return nil
}

func parseTime(value string) (time.Time, error) {
	layouts := []string{time.RFC3339Nano, "2006-01-02 15:04:05.999999999-07:00", "2006-01-02 15:04:05.999999999", "2006-01-02 15:04:05"}
	for _, layout := range layouts {
		if t, err := time.Parse(layout, value); err == nil {
			return t.UTC(), nil
		}
	}
	return time.Time{}, fmt.Errorf("cannot parse time %q", value)
}

func flexibleTimePtr(value flexibleTime) *time.Time {
	if !value.Valid {
		return nil
	}
	t := value.Time.UTC()
	return &t
}

func hashAuditEvent(event AuditEvent, prevHash string) string {
	parts := []string{event.EventID, event.Timestamp.UTC().Format(time.RFC3339Nano), event.IntentID, event.ActorID, event.AgentID, event.MandateID, event.PolicyVersion, event.RiskAssessmentID, event.AuthorizationID, event.CorrelationID, event.Decision, event.ReasonCode, event.Actor, prevHash}
	return hashString(strings.Join(parts, "|"))
}

func hashString(value string) string {
	return (&Service{}).hashString(value)
}

func newActionID(intentID string) string {
	return "action:" + intentID
}
