package gateway

import (
	"crypto/sha256"
	"database/sql"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"strings"
	"sync/atomic"
	"time"
)

var (
	errUnauthorized = errors.New("unauthorized")
	errForbidden    = errors.New("forbidden")
)

type authenticatedActor struct {
	Actor   string
	AgentID string
	Admin   bool
}

type PolicyRiskResolver interface {
	Resolve(intent FinancialIntent, authority AuthorityReferences) (AuthorityReferences, error)
}

type StaticPolicyRiskResolver struct {
	Lookups map[string]AuthorityReferences
}

func (r StaticPolicyRiskResolver) Resolve(intent FinancialIntent, authority AuthorityReferences) (AuthorityReferences, error) {
	if completeAuthority(authority) {
		if !isValidPolicyOutcome(authority.Outcome) {
			return AuthorityReferences{}, errors.New("invalid policy outcome")
		}
		authority.LookupKey = ""
		return authority, nil
	}
	if authority.LookupKey != "" {
		resolved, ok := r.Lookups[authority.LookupKey]
		if !ok || !completeAuthority(resolved) || !isValidPolicyOutcome(resolved.Outcome) {
			return AuthorityReferences{}, errors.New("unverifiable policy/risk linkage")
		}
		resolved.LookupKey = authority.LookupKey
		return resolved, nil
	}
	return AuthorityReferences{}, errors.New("missing authoritative policy/risk linkage")
}

type Repository interface {
	SeedAgent(agent Agent) error
	SeedCredential(credential AgentCredential) error
	SeedCapability(capability AgentCapability) error
	SeedMandate(mandate AgentMandate) error
	AuthenticateAgent(tokenHash, sessionID string, now time.Time) (authenticatedActor, error)
	GetAgent(agentID string) (Agent, bool, error)
	GetCapability(capabilityID string) (AgentCapability, bool, error)
	GetMandate(mandateID string) (AgentMandate, bool, error)
	GetIntent(intentID string) (IntentRecord, bool, error)
	ListAuditEvents(intentID string) ([]AuditEvent, error)
	VerifyAuditIntegrity() (bool, error)
	KillSwitchActive() (bool, error)
	CountRecentActions(agentID string, since time.Time) (int, error)
	SumRecentApprovedSpend(agentID string, since time.Time) (float64, error)
	FindActionByIdempotency(agentID, key string) (IntentRecord, bool, error)
	FindActionByReplay(agentID, nonce, replayBucket string) (IntentRecord, bool, error)
	SaveIntent(record IntentRecord) error
	UpdateIntent(record IntentRecord) error
	RecordAuthorization(intentID string, authority AuthorityReferences, policyVersion string, now time.Time) error
	AppendAudit(event AuditEvent, payload map[string]interface{}) error
	SuspendAgent(agentID string, now time.Time) error
	RevokeAgentCredentials(agentID string, now time.Time) error
	RevokeCapability(capabilityID string, now time.Time) error
}

type Service struct {
	repo      Repository
	resolver  PolicyRiskResolver
	cfg       Config
	sequence  atomic.Uint64
}

func NewService(cfg Config, repo Repository, resolver PolicyRiskResolver) *Service {
	if resolver == nil {
		resolver = StaticPolicyRiskResolver{}
	}
	return &Service{cfg: cfg, repo: repo, resolver: resolver}
}

func (s *Service) SeedAgent(agent Agent) {
	_ = s.repo.SeedAgent(agent)
}

func (s *Service) SeedCredential(credential AgentCredential) {
	_ = s.repo.SeedCredential(credential)
}

func (s *Service) SeedCapability(capability AgentCapability) {
	_ = s.repo.SeedCapability(capability)
}

func (s *Service) SeedMandate(mandate AgentMandate) {
	_ = s.repo.SeedMandate(mandate)
}

func (s *Service) AuthenticateAgent(token, sessionID string, now time.Time) (authenticatedActor, error) {
	if token == "" {
		return authenticatedActor{}, errUnauthorized
	}
	return s.repo.AuthenticateAgent(s.hashString(token), sessionID, now)
}

func (s *Service) AuthenticateAdmin(token, scope string) (authenticatedActor, error) {
	if token == "" {
		return authenticatedActor{}, errUnauthorized
	}
	allowed := s.cfg.AdminWriteToken
	if scope == "approval" && s.cfg.ApprovalToken != "" {
		allowed = s.cfg.ApprovalToken
	}
	if scope == "killswitch" && s.cfg.KillSwitchToken != "" {
		allowed = s.cfg.KillSwitchToken
	}
	if scope == "read" && s.cfg.AdminReadToken != "" {
		allowed = s.cfg.AdminReadToken
	}
	if allowed == "" || token != allowed {
		return authenticatedActor{}, errUnauthorized
	}
	return authenticatedActor{Actor: "admin", Admin: true}, nil
}

func (s *Service) ProcessIntent(req SubmitIntentRequest, actor authenticatedActor, now time.Time) (DecisionEnvelope, error) {
	intent := req.Intent
	if intent.IntentID == "" {
		intent.IntentID = s.newID("intent")
	}
	if err := s.validateRequest(intent, req.Execution); err != nil {
		return s.rejectIntent(req, now, actor.Actor, DecisionDenied, err.Error())
	}
	if intent.ActorType != ActorTypeAgent || intent.ActorID == "" || intent.ActorID != actor.AgentID || req.Execution.AgentID != actor.AgentID {
		return s.rejectIntent(req, now, actor.Actor, DecisionDenied, "ACTOR_MISMATCH")
	}
	if intent.MandateID == "" || req.Execution.CapabilityID == "" {
		return s.rejectIntent(req, now, actor.Actor, DecisionDenied, "MISSING_AUTHORITY_FIELDS")
	}
	if now.After(intent.ExpiresAt) {
		return s.rejectIntent(req, now, actor.Actor, DecisionDenied, "INTENT_EXPIRED")
	}
	if active, err := s.repo.KillSwitchActive(); err != nil {
		return DecisionEnvelope{}, err
	} else if active {
		return s.rejectIntent(req, now, actor.Actor, DecisionBlocked, "KILLSWITCH_ACTIVE")
	}

	agent, ok, err := s.repo.GetAgent(req.Execution.AgentID)
	if err != nil {
		return DecisionEnvelope{}, err
	}
	if !ok {
		return s.rejectIntent(req, now, actor.Actor, DecisionDenied, "UNKNOWN_AGENT")
	}
	if agent.Status == AgentStatusSuspended {
		return s.rejectIntent(req, now, actor.Actor, DecisionBlocked, "AGENT_SUSPENDED")
	}
	mandate, ok, err := s.repo.GetMandate(intent.MandateID)
	if err != nil {
		return DecisionEnvelope{}, err
	}
	if !ok || mandate.AgentID != req.Execution.AgentID || mandate.Status != RecordStatusActive || now.After(mandate.ExpiresAt) || mandate.RevokedAt != nil {
		return s.rejectIntent(req, now, actor.Actor, DecisionDenied, "MANDATE_REVOKED_OR_EXPIRED")
	}
	capability, ok, err := s.repo.GetCapability(req.Execution.CapabilityID)
	if err != nil {
		return DecisionEnvelope{}, err
	}
	if !ok || capability.AgentID != req.Execution.AgentID || capability.Status != RecordStatusActive || (capability.ExpiresAt != nil && now.After(*capability.ExpiresAt)) || capability.RevokedAt != nil {
		return s.rejectIntent(req, now, actor.Actor, DecisionDenied, "CAPABILITY_REVOKED_OR_EXPIRED")
	}
	if _, ok := routeDownstream(intent.Action); !ok {
		return s.rejectIntent(req, now, actor.Actor, DecisionDenied, "UNSUPPORTED_ACTION")
	}
	if reason := capabilityCompatibilityReason(capability, req); reason != "" {
		return s.rejectIntent(req, now, actor.Actor, DecisionDenied, reason)
	}
	if !s.autonomyAllowed(req.Execution.AutonomyLevel, capability.AutonomyLevel, mandate.AutonomyLevel, agent.AutonomyLevel) {
		return s.rejectIntent(req, now, actor.Actor, DecisionDenied, "AUTONOMY_VIOLATION")
	}
	authority, err := s.resolver.Resolve(intent, req.Authority)
	if err != nil {
		return s.rejectIntent(req, now, actor.Actor, DecisionDenied, "POLICY_RISK_UNVERIFIED")
	}
	requestHash := s.requestHash(intent, req.Execution)
	if existing, ok, err := s.repo.FindActionByIdempotency(req.Execution.AgentID, intent.IdempotencyKey); err != nil {
		return DecisionEnvelope{}, err
	} else if ok {
		if existing.RequestHash != requestHash {
			return s.rejectIntent(req, now, actor.Actor, DecisionBlocked, "IDEMPOTENCY_KEY_REUSED_WITH_DIFFERENT_PAYLOAD")
		}
		return s.rejectIntent(req, now, actor.Actor, DecisionBlocked, "DUPLICATE_IDEMPOTENCY_KEY")
	}
	replayBucket := bucketFor(now, s.cfg.ReplayWindow)
	if existing, ok, err := s.repo.FindActionByReplay(req.Execution.AgentID, req.Execution.Nonce, replayBucket); err != nil {
		return DecisionEnvelope{}, err
	} else if ok && now.Sub(existing.CreatedAt) <= s.cfg.ReplayWindow {
		return s.rejectIntent(req, now, actor.Actor, DecisionBlocked, "REPLAY_DETECTED")
	}
	if recent, err := s.repo.CountRecentActions(req.Execution.AgentID, now.Add(-s.cfg.RateLimitWindow)); err != nil {
		return DecisionEnvelope{}, err
	} else if agent.RateLimit > 0 && recent >= agent.RateLimit {
		return s.rejectIntent(req, now, actor.Actor, DecisionBlocked, "RATE_LIMIT_EXCEEDED")
	}
	if amountValue(intent.Amount) > 0 {
		if spent, err := s.repo.SumRecentApprovedSpend(req.Execution.AgentID, now.Add(-s.cfg.RateLimitWindow)); err != nil {
			return DecisionEnvelope{}, err
		} else if agent.SpendLimit > 0 && spent+amountValue(intent.Amount) > agent.SpendLimit {
			return s.rejectIntent(req, now, actor.Actor, DecisionBlocked, "SPEND_LIMIT_EXCEEDED")
		}
	}

	status, reason := decisionFromOutcome(authority.Outcome)
	record := IntentRecord{
		Intent:              intent,
		Execution:           req.Execution,
		Authority:           authority,
		Status:              status,
		PolicyOutcome:       authority.Outcome,
		ReasonCode:          reason,
		Forwarded:           status == DecisionApproved,
		CreatedAt:           now.UTC(),
		UpdatedAt:           now.UTC(),
		RequestHash:         requestHash,
		Metadata:            req.Metadata,
		DeprecationWarnings: req.DeprecationWarnings,
	}
	if record.Forwarded {
		record.DownstreamReference = s.forward(intent)
	}
	if err := s.repo.SaveIntent(record); err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return s.rejectIntent(req, now, actor.Actor, DecisionBlocked, "REPLAY_DETECTED")
		}
		if strings.Contains(strings.ToLower(err.Error()), "unique") {
			if _, ok, lookupErr := s.repo.FindActionByIdempotency(req.Execution.AgentID, intent.IdempotencyKey); lookupErr == nil && ok {
				return s.rejectIntent(req, now, actor.Actor, DecisionBlocked, "DUPLICATE_IDEMPOTENCY_KEY")
			}
			return s.rejectIntent(req, now, actor.Actor, DecisionBlocked, "REPLAY_DETECTED")
		}
		return DecisionEnvelope{}, err
	}
	if err := s.repo.RecordAuthorization(intent.IntentID, authority, intent.PolicyVersion, now); err != nil {
		return DecisionEnvelope{}, err
	}
	if err := s.audit(record, actor.Actor, now, strings.ToLower(string(status)), reason); err != nil {
		return DecisionEnvelope{}, err
	}
	if record.Forwarded {
		if err := s.audit(record, actor.Actor, now, "forwarded", ""); err != nil {
			return DecisionEnvelope{}, err
		}
	}
	return envelope(record), nil
}

func (s *Service) ApproveIntent(intentID string, actor authenticatedActor, now time.Time) (DecisionEnvelope, error) {
	record, ok, err := s.repo.GetIntent(intentID)
	if err != nil {
		return DecisionEnvelope{}, err
	}
	if !ok {
		return DecisionEnvelope{}, errors.New("intent not found")
	}
	if record.Status != DecisionReview && record.Status != DecisionChallenge && record.Status != DecisionDelay {
		return DecisionEnvelope{}, errors.New("intent not awaiting approval")
	}
	record.Status = DecisionApproved
	record.ReasonCode = ""
	record.Forwarded = true
	record.ApprovedAt = ptrTime(now.UTC())
	record.UpdatedAt = now.UTC()
	record.DownstreamReference = s.forward(record.Intent)
	if err := s.repo.UpdateIntent(record); err != nil {
		return DecisionEnvelope{}, err
	}
	if err := s.audit(record, actor.Actor, now, "approved", ""); err != nil {
		return DecisionEnvelope{}, err
	}
	if err := s.audit(record, actor.Actor, now, "forwarded", ""); err != nil {
		return DecisionEnvelope{}, err
	}
	return envelope(record), nil
}

func (s *Service) CancelIntent(intentID string, actor authenticatedActor, now time.Time) (DecisionEnvelope, error) {
	record, ok, err := s.repo.GetIntent(intentID)
	if err != nil {
		return DecisionEnvelope{}, err
	}
	if !ok {
		return DecisionEnvelope{}, errors.New("intent not found")
	}
	record.Status = DecisionCancelled
	record.ReasonCode = "CANCELLED"
	record.UpdatedAt = now.UTC()
	record.CancelledAt = ptrTime(now.UTC())
	if err := s.repo.UpdateIntent(record); err != nil {
		return DecisionEnvelope{}, err
	}
	if err := s.audit(record, actor.Actor, now, "cancelled", "CANCELLED"); err != nil {
		return DecisionEnvelope{}, err
	}
	return envelope(record), nil
}

func (s *Service) GetIntent(intentID string) (IntentRecord, bool) {
	record, ok, err := s.repo.GetIntent(intentID)
	if err != nil {
		return IntentRecord{}, false
	}
	return record, ok
}

func (s *Service) GetAgentStatus(agentID string) (Agent, bool) {
	agent, ok, err := s.repo.GetAgent(agentID)
	if err != nil {
		return Agent{}, false
	}
	return agent, ok
}

func (s *Service) SuspendAgent(agentID string, actor authenticatedActor, now time.Time) error {
	if err := s.repo.SuspendAgent(agentID, now.UTC()); err != nil {
		return err
	}
	return s.repo.AppendAudit(AuditEvent{
		EventID:   s.newID("evt"),
		Timestamp: now.UTC(),
		AgentID:   agentID,
		Decision:  "suspended",
		ReasonCode:"DOWNSTREAM_PREVENTION_SIGNALLED",
		Actor:     actor.Actor,
	}, map[string]interface{}{"signal": "agent:" + agentID})
}

func (s *Service) RevokeAgentCredentials(agentID string, actor authenticatedActor, now time.Time) error {
	if err := s.repo.RevokeAgentCredentials(agentID, now.UTC()); err != nil {
		return err
	}
	return s.repo.AppendAudit(AuditEvent{
		EventID:    s.newID("evt"),
		Timestamp:  now.UTC(),
		AgentID:    agentID,
		Decision:   "revoked",
		ReasonCode: "CREDENTIALS_REVOKED",
		Actor:      actor.Actor,
	}, nil)
}

func (s *Service) RevokeCapability(capabilityID string, actor authenticatedActor, now time.Time) error {
	capability, ok, err := s.repo.GetCapability(capabilityID)
	if err != nil {
		return err
	}
	if !ok {
		return errors.New("capability not found")
	}
	if err := s.repo.RevokeCapability(capabilityID, now.UTC()); err != nil {
		return err
	}
	return s.repo.AppendAudit(AuditEvent{
		EventID:    s.newID("evt"),
		Timestamp:  now.UTC(),
		AgentID:    capability.AgentID,
		Decision:   "revoked",
		ReasonCode: "CAPABILITY_REVOKED",
		Actor:      actor.Actor,
	}, nil)
}

func (s *Service) ActivateKillSwitch(actor authenticatedActor, now time.Time) error {
	return s.repo.AppendAudit(AuditEvent{
		EventID:    s.newID("evt"),
		Timestamp:  now.UTC(),
		Decision:   "killswitch_activated",
		ReasonCode: "DOWNSTREAM_PREVENTION_SIGNALLED",
		Actor:      actor.Actor,
	}, map[string]interface{}{"signal": "global"})
}

func (s *Service) DeactivateKillSwitch(actor authenticatedActor, now time.Time) error {
	return s.repo.AppendAudit(AuditEvent{
		EventID:   s.newID("evt"),
		Timestamp: now.UTC(),
		Decision:  "killswitch_deactivated",
		Actor:     actor.Actor,
	}, nil)
}

func (s *Service) AuditEvents(intentID string) []AuditEvent {
	events, err := s.repo.ListAuditEvents(intentID)
	if err != nil {
		return nil
	}
	return events
}

func (s *Service) VerifyAuditIntegrity() bool {
	ok, err := s.repo.VerifyAuditIntegrity()
	return err == nil && ok
}

func (s *Service) validateRequest(intent FinancialIntent, execution ExecutionHints) error {
	switch {
	case !isValidActorType(intent.ActorType):
		return errors.New("MALFORMED_INTENT")
	case !isValidAction(intent.Action):
		return errors.New("MALFORMED_INTENT")
	case intent.ActorID == "", intent.AssetID == "", intent.Purpose == "", intent.PolicyVersion == "", intent.CorrelationID == "", intent.IdempotencyKey == "", intent.ExpiresAt.IsZero(), execution.AgentID == "", execution.CapabilityID == "", execution.Nonce == "":
		return errors.New("MISSING_AUTHORITY_FIELDS")
	case intent.Amount != nil && *intent.Amount <= 0:
		return errors.New("MALFORMED_INTENT")
	}
	return nil
}

func (s *Service) rejectIntent(req SubmitIntentRequest, now time.Time, actor string, decision Decision, reason string) (DecisionEnvelope, error) {
	record := IntentRecord{
		Intent:              req.Intent,
		Execution:           req.Execution,
		Authority:           req.Authority,
		Status:              decision,
		ReasonCode:          reason,
		CreatedAt:           now.UTC(),
		UpdatedAt:           now.UTC(),
		RequestHash:         s.requestHash(req.Intent, req.Execution),
		Metadata:            req.Metadata,
		DeprecationWarnings: req.DeprecationWarnings,
	}
	if err := s.repo.SaveIntent(record); err == nil {
		_ = s.audit(record, actor, now, strings.ToLower(string(decision)), reason)
	}
	return envelope(record), nil
}

func (s *Service) autonomyAllowed(levels ...AutonomyLevel) bool {
	if len(levels) == 0 {
		return false
	}
	target := autonomyRank[levels[0]]
	for _, level := range levels[1:] {
		if target > autonomyRank[level] {
			return false
		}
	}
	return true
}

func (s *Service) forward(intent FinancialIntent) string {
	downstream, _ := routeDownstream(intent.Action)
	return downstream + ":" + s.hashString(intent.IntentID+intent.CorrelationID)[:12]
}

func (s *Service) audit(record IntentRecord, actor string, now time.Time, decision, reason string) error {
	payload := map[string]interface{}{
		"intent":    record.Intent,
		"execution": record.Execution,
		"authority": record.Authority,
		"status":    record.Status,
	}
	return s.repo.AppendAudit(AuditEvent{
		EventID:          s.newID("evt"),
		Timestamp:        now.UTC(),
		IntentID:         record.Intent.IntentID,
		ActorID:          record.Intent.ActorID,
		AgentID:          record.Execution.AgentID,
		MandateID:        record.Intent.MandateID,
		PolicyVersion:    record.Intent.PolicyVersion,
		RiskAssessmentID: record.Authority.RiskAssessmentID,
		AuthorizationID:  record.Authority.AuthorizationID,
		CorrelationID:    record.Intent.CorrelationID,
		Decision:         decision,
		ReasonCode:       reason,
		Actor:            actor,
	}, payload)
}

func (s *Service) newID(prefix string) string {
	return fmt.Sprintf("%s-%06d", prefix, s.sequence.Add(1))
}

func (s *Service) requestHash(intent FinancialIntent, execution ExecutionHints) string {
	intent.IntentID = ""
	intent.ExpiresAt = time.Time{}
	b, _ := json.Marshal(struct {
		Intent    FinancialIntent `json:"intent"`
		Execution ExecutionHints  `json:"execution"`
	}{Intent: intent, Execution: execution})
	return s.hashString(string(b))
}

func (s *Service) hashString(value string) string {
	sum := sha256.Sum256([]byte(value))
	return hex.EncodeToString(sum[:])
}

func envelope(record IntentRecord) DecisionEnvelope {
	return DecisionEnvelope{
		ContractVersion:     ContractVersion,
		SchemaVersion:       SchemaVersion,
		Intent:              record.Intent,
		Execution:           record.Execution,
		Authority:           record.Authority,
		Decision:            record.Status,
		Status:              record.Status,
		PolicyOutcome:       record.PolicyOutcome,
		ReasonCode:          record.ReasonCode,
		Forwarded:           record.Forwarded,
		ApprovalRequired:    record.Status == DecisionReview || record.Status == DecisionChallenge || record.Status == DecisionDelay,
		DownstreamReference: record.DownstreamReference,
		DeprecationWarnings: record.DeprecationWarnings,
	}
}

func completeAuthority(authority AuthorityReferences) bool {
	return authority.PolicyDecisionID != "" && authority.RiskAssessmentID != "" && authority.AuthorizationID != "" && authority.Outcome != ""
}

func decisionFromOutcome(outcome PolicyOutcome) (Decision, string) {
	switch outcome {
	case PolicyOutcomeAllow:
		return DecisionApproved, ""
	case PolicyOutcomeDeny:
		return DecisionDenied, "POLICY_DENIED"
	case PolicyOutcomeReview:
		return DecisionReview, "APPROVAL_REQUIRED"
	case PolicyOutcomeChallenge:
		return DecisionChallenge, "POLICY_CHALLENGE"
	case PolicyOutcomeDelay:
		return DecisionDelay, "POLICY_DELAY"
	case PolicyOutcomeQuarantine:
		return DecisionQuarantine, "POLICY_QUARANTINED"
	default:
		return DecisionDenied, "POLICY_RISK_UNVERIFIED"
	}
}

func routeDownstream(action FinancialAction) (string, bool) {
	switch action {
	case ActionPay, ActionTransfer, ActionCollect:
		return "pay", true
	case ActionSwap, ActionTrade, ActionRebalance, ActionOpenPosition, ActionClosePosition:
		return "markets", true
	default:
		return "", false
	}
}

func capabilityCompatibilityReason(capability AgentCapability, req SubmitIntentRequest) string {
	if !contains(capability.AllowedActions, string(req.Intent.Action)) {
		return "UNSUPPORTED_ACTION"
	}
	if req.Intent.AssetID != "" && len(capability.AllowedAssets) > 0 && !contains(capability.AllowedAssets, req.Intent.AssetID) {
		return "UNSUPPORTED_ASSET"
	}
	if req.Intent.ChainID != "" && len(capability.AllowedChains) > 0 && !contains(capability.AllowedChains, req.Intent.ChainID) {
		return "UNSUPPORTED_CHAIN"
	}
	if req.Execution.ExecutionRef.Contract != "" && len(capability.AllowedContracts) > 0 && !contains(capability.AllowedContracts, req.Execution.ExecutionRef.Contract) {
		return "UNSUPPORTED_CALL_TARGET"
	}
	if req.Execution.ExecutionRef.Function != "" && len(capability.AllowedFunctions) > 0 && !contains(capability.AllowedFunctions, req.Execution.ExecutionRef.Function) {
		return "UNSUPPORTED_CALL_TARGET"
	}
	return ""
}

func isValidActorType(value ActorType) bool {
	switch value {
	case ActorTypeUser, ActorTypeApplication, ActorTypeSystem, ActorTypeAgent:
		return true
	default:
		return false
	}
}

func isValidAction(value FinancialAction) bool {
	switch value {
	case ActionPay, ActionTransfer, ActionSwap, ActionTrade, ActionRebalance, ActionCollect, ActionOpenPosition, ActionClosePosition:
		return true
	default:
		return false
	}
}

func isValidPolicyOutcome(value PolicyOutcome) bool {
	switch value {
	case PolicyOutcomeAllow, PolicyOutcomeDeny, PolicyOutcomeReview, PolicyOutcomeChallenge, PolicyOutcomeDelay, PolicyOutcomeQuarantine:
		return true
	default:
		return false
	}
}

func contains(values []string, target string) bool {
	for _, value := range values {
		if strings.EqualFold(value, target) {
			return true
		}
	}
	return false
}

func bucketFor(now time.Time, window time.Duration) string {
	if window <= 0 {
		return now.UTC().Format(time.RFC3339)
	}
	return now.UTC().Truncate(window).Format(time.RFC3339)
}

func amountValue(value *float64) float64 {
	if value == nil {
		return 0
	}
	return *value
}

func ptrTime(t time.Time) *time.Time {
	return &t
}
