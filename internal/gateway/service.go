package gateway

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"strings"
	"sync"
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

type Service struct {
	mu                 sync.RWMutex
	cfg                Config
	agents             map[string]Agent
	credentialsByID    map[string]AgentCredential
	credentialsByToken map[string]string
	capabilities       map[string]AgentCapability
	mandates           map[string]AgentMandate
	intents            map[string]IntentRecord
	idempotency        map[string]string
	nonces             map[string]time.Time
	agentRequests      map[string][]time.Time
	agentSpend         map[string][]spendEntry
	auditEvents        []AuditEvent
	lastAuditHash      string
	killSwitch         bool
	preventionSignals  []string
	nextID             int
}

type spendEntry struct {
	At     time.Time
	Amount float64
}

func NewService(cfg Config) *Service {
	return &Service{
		cfg:                cfg,
		agents:             map[string]Agent{},
		credentialsByID:    map[string]AgentCredential{},
		credentialsByToken: map[string]string{},
		capabilities:       map[string]AgentCapability{},
		mandates:           map[string]AgentMandate{},
		intents:            map[string]IntentRecord{},
		idempotency:        map[string]string{},
		nonces:             map[string]time.Time{},
		agentRequests:      map[string][]time.Time{},
		agentSpend:         map[string][]spendEntry{},
	}
}

func (s *Service) SeedAgent(agent Agent) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if agent.RateLimit == 0 {
		agent.RateLimit = s.cfg.DefaultRateLimit
	}
	if agent.SpendLimit == 0 {
		agent.SpendLimit = s.cfg.DefaultSpendLimit
	}
	if agent.ReviewLimit == 0 {
		agent.ReviewLimit = s.cfg.DefaultReviewLimit
	}
	s.agents[agent.ID] = agent
}

func (s *Service) SeedCredential(credential AgentCredential) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.credentialsByID[credential.ID] = credential
	s.credentialsByToken[credential.Token] = credential.ID
}

func (s *Service) SeedCapability(capability AgentCapability) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.capabilities[capability.ID] = capability
}

func (s *Service) SeedMandate(mandate AgentMandate) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.mandates[mandate.ID] = mandate
}

func (s *Service) AuthenticateAgent(token, sessionID string, now time.Time) (authenticatedActor, error) {
	s.mu.Lock()
	defer s.mu.Unlock()

	credentialID, ok := s.credentialsByToken[token]
	if !ok {
		return authenticatedActor{}, errUnauthorized
	}
	credential := s.credentialsByID[credentialID]
	if credential.RevokedAt != nil || credential.ExpiresAt.Before(now) {
		return authenticatedActor{}, errUnauthorized
	}
	agent, ok := s.agents[credential.AgentID]
	if !ok {
		return authenticatedActor{}, errUnauthorized
	}
	if agent.Status == AgentStatusSuspended {
		return authenticatedActor{}, errForbidden
	}
	if credential.SessionID != "" && credential.SessionID != sessionID {
		return authenticatedActor{}, errUnauthorized
	}
	if agent.SessionBinding != "" && agent.SessionBinding != sessionID {
		return authenticatedActor{}, errUnauthorized
	}

	credential.LastUsedAt = ptrTime(now)
	s.credentialsByID[credential.ID] = credential
	return authenticatedActor{
		Actor:   "agent:" + agent.ID,
		AgentID: agent.ID,
	}, nil
}

func (s *Service) AuthenticateAdmin(token string) (authenticatedActor, error) {
	if token == "" || token != s.cfg.AdminToken {
		return authenticatedActor{}, errUnauthorized
	}
	return authenticatedActor{Actor: "admin", Admin: true}, nil
}

func (s *Service) ProcessIntent(intent FinancialIntent, actor authenticatedActor, now time.Time) (DecisionEnvelope, error) {
	s.mu.Lock()
	defer s.mu.Unlock()

	intentID := intent.IntentID
	if intentID == "" {
		intentID = s.newID("intent")
		intent.IntentID = intentID
	}
	s.audit(now, intentID, intent.AgentID, intent.MandateID, "received", "", actor.Actor)

	if s.killSwitch {
		return s.rejectIntent(intent, now, actor.Actor, DecisionBlocked, "KILLSWITCH_ACTIVE"), nil
	}

	if intent.ActorType != "agent" || intent.ActorID == "" || intent.ActorID != actor.AgentID || intent.AgentID != actor.AgentID {
		return s.rejectIntent(intent, now, actor.Actor, DecisionDenied, "ACTOR_MISMATCH"), nil
	}
	if intent.IdempotencyKey == "" || intent.CorrelationID == "" || intent.MandateID == "" || intent.CapabilityID == "" {
		return s.rejectIntent(intent, now, actor.Actor, DecisionDenied, "MISSING_AUTHORITY_FIELDS"), nil
	}
	if intent.PolicyBinding.Version == "" || intent.PolicyBinding.Hash == "" {
		return s.rejectIntent(intent, now, actor.Actor, DecisionDenied, "MISSING_POLICY_BINDING"), nil
	}
	if intent.Nonce == "" || intent.Action == "" || intent.Asset == "" || intent.Contract == "" || intent.Function == "" || intent.Amount <= 0 {
		return s.rejectIntent(intent, now, actor.Actor, DecisionDenied, "MALFORMED_INTENT"), nil
	}
	if intent.ExpiresAt.IsZero() || now.After(intent.ExpiresAt) {
		return s.rejectIntent(intent, now, actor.Actor, DecisionDenied, "INTENT_EXPIRED"), nil
	}

	agent, ok := s.agents[intent.AgentID]
	if !ok {
		return s.rejectIntent(intent, now, actor.Actor, DecisionDenied, "UNKNOWN_AGENT"), nil
	}
	if agent.Status == AgentStatusSuspended {
		return s.rejectIntent(intent, now, actor.Actor, DecisionBlocked, "AGENT_SUSPENDED"), nil
	}
	s.audit(now, intentID, intent.AgentID, intent.MandateID, "authenticated", "", actor.Actor)

	mandate, ok := s.mandates[intent.MandateID]
	if !ok || mandate.AgentID != intent.AgentID || mandate.Status != RecordStatusActive || now.After(mandate.ExpiresAt) || mandate.RevokedAt != nil {
		return s.rejectIntent(intent, now, actor.Actor, DecisionDenied, "MANDATE_REVOKED_OR_EXPIRED"), nil
	}
	s.audit(now, intentID, intent.AgentID, intent.MandateID, "mandate_checked", "", actor.Actor)

	capability, ok := s.capabilities[intent.CapabilityID]
	if !ok || capability.AgentID != intent.AgentID || capability.Status != RecordStatusActive || (capability.ExpiresAt != nil && now.After(*capability.ExpiresAt)) || capability.RevokedAt != nil {
		return s.rejectIntent(intent, now, actor.Actor, DecisionDenied, "CAPABILITY_REVOKED_OR_EXPIRED"), nil
	}
	if mapActionToService(intent.Action) == "blocked" {
		return s.rejectIntent(intent, now, actor.Actor, DecisionDenied, "UNSUPPORTED_ACTION"), nil
	}
	if !s.capabilityPermits(capability, intent) {
		return s.rejectIntent(intent, now, actor.Actor, DecisionDenied, "UNSUPPORTED_ACTION"), nil
	}
	if !s.autonomyAllowed(intent.AutonomyLevel, capability.AutonomyLevel, mandate.AutonomyLevel, agent.AutonomyLevel) {
		return s.rejectIntent(intent, now, actor.Actor, DecisionDenied, "AUTONOMY_VIOLATION"), nil
	}
	s.audit(now, intentID, intent.AgentID, intent.MandateID, "capability_checked", "", actor.Actor)

	requestHash := s.requestHash(intent)

	policyRef := intent.PolicyBinding.DecisionRef
	if policyRef == "" {
		policyRef = "policy:" + s.hashString(intent.PolicyBinding.Version + ":" + intent.PolicyBinding.Hash)[:12]
		intent.PolicyBinding.DecisionRef = policyRef
	}
	s.audit(now, intentID, intent.AgentID, intent.MandateID, "policy_checked", "", actor.Actor)

	if intent.RiskLinkage.Reference == "" {
		intent.RiskLinkage.Reference = "risk:" + s.hashString(intentID + ":" + intent.CorrelationID)[:12]
	}
	if intent.RiskLinkage.DecisionRef == "" {
		intent.RiskLinkage.DecisionRef = intent.RiskLinkage.Reference
	}
	s.audit(now, intentID, intent.AgentID, intent.MandateID, "risk_checked", "", actor.Actor)

	idempotencyKey := intent.AgentID + ":" + intent.IdempotencyKey
	if existingID, ok := s.idempotency[idempotencyKey]; ok {
		existing := s.intents[existingID]
		if existing.RequestHash != requestHash {
			return s.rejectIntent(intent, now, actor.Actor, DecisionBlocked, "IDEMPOTENCY_KEY_REUSED_WITH_DIFFERENT_PAYLOAD"), nil
		}
		return s.rejectIntent(intent, now, actor.Actor, DecisionBlocked, "DUPLICATE_IDEMPOTENCY_KEY"), nil
	}
	if issued, ok := s.nonces[intent.AgentID+":"+intent.Nonce]; ok && now.Sub(issued) <= s.cfg.ReplayWindow {
		return s.rejectIntent(intent, now, actor.Actor, DecisionBlocked, "NONCE_REPLAYED"), nil
	}
	if now.Sub(intent.IssuedAt) > s.cfg.ReplayWindow {
		return s.rejectIntent(intent, now, actor.Actor, DecisionBlocked, "STALE_NONCE"), nil
	}

	if s.rateLimitExceeded(intent.AgentID, now, agent.RateLimit) {
		return s.rejectIntent(intent, now, actor.Actor, DecisionBlocked, "RATE_LIMIT_EXCEEDED"), nil
	}
	if s.spendLimitExceeded(intent.AgentID, now, agent.SpendLimit, intent.Amount) {
		return s.rejectIntent(intent, now, actor.Actor, DecisionBlocked, "SPEND_LIMIT_EXCEEDED"), nil
	}

	status := DecisionApproved
	reason := ""
	if intent.ReviewRequested || intent.Amount > agent.ReviewLimit {
		status = DecisionReview
		reason = "APPROVAL_REQUIRED"
	}
	if intent.RiskLinkage.Score >= 0.95 {
		status = DecisionQuarantine
		reason = "RISK_QUARANTINED"
	} else if intent.RiskLinkage.Score >= 0.85 {
		status = DecisionChallenge
		reason = "RISK_CHALLENGED"
	} else if intent.RiskLinkage.Score >= 0.70 {
		status = DecisionDelay
		reason = "RISK_DELAYED"
	}

	record := IntentRecord{
		FinancialIntent: intent,
		Status:          status,
		ReasonCode:      reason,
		CreatedAt:       now,
		UpdatedAt:       now,
		RequestHash:     requestHash,
	}
	s.idempotency[idempotencyKey] = intentID
	s.nonces[intent.AgentID+":"+intent.Nonce] = now
	s.agentRequests[intent.AgentID] = append(s.agentRequests[intent.AgentID], now)

	if status == DecisionApproved {
		record.Forwarded = true
		record.DownstreamReference = s.forward(intent)
		s.agentSpend[intent.AgentID] = append(s.agentSpend[intent.AgentID], spendEntry{At: now, Amount: intent.Amount})
		s.audit(now, intentID, intent.AgentID, intent.MandateID, "approved", "", actor.Actor)
		s.audit(now, intentID, intent.AgentID, intent.MandateID, "forwarded", "", actor.Actor)
	} else {
		s.audit(now, intentID, intent.AgentID, intent.MandateID, strings.ToLower(string(status)), reason, actor.Actor)
	}

	s.intents[intentID] = record
	return envelope(record), nil
}

func (s *Service) ApproveIntent(intentID string, actor authenticatedActor, now time.Time) (DecisionEnvelope, error) {
	s.mu.Lock()
	defer s.mu.Unlock()

	record, ok := s.intents[intentID]
	if !ok {
		return DecisionEnvelope{}, errors.New("intent not found")
	}
	if record.Status != DecisionReview && record.Status != DecisionChallenge && record.Status != DecisionDelay {
		return DecisionEnvelope{}, errors.New("intent not awaiting approval")
	}
	record.Status = DecisionApproved
	record.ReasonCode = ""
	record.Forwarded = true
	record.ApprovedAt = ptrTime(now)
	record.UpdatedAt = now
	record.DownstreamReference = s.forward(record.FinancialIntent)
	s.agentSpend[record.AgentID] = append(s.agentSpend[record.AgentID], spendEntry{At: now, Amount: record.Amount})
	s.intents[intentID] = record
	s.audit(now, intentID, record.AgentID, record.MandateID, "approved", "", actor.Actor)
	s.audit(now, intentID, record.AgentID, record.MandateID, "forwarded", "", actor.Actor)
	return envelope(record), nil
}

func (s *Service) CancelIntent(intentID string, actor authenticatedActor, now time.Time) (DecisionEnvelope, error) {
	s.mu.Lock()
	defer s.mu.Unlock()

	record, ok := s.intents[intentID]
	if !ok {
		return DecisionEnvelope{}, errors.New("intent not found")
	}
	record.Status = DecisionCancelled
	record.ReasonCode = "CANCELLED"
	record.UpdatedAt = now
	record.CancelledAt = ptrTime(now)
	s.intents[intentID] = record
	s.audit(now, intentID, record.AgentID, record.MandateID, "cancelled", "CANCELLED", actor.Actor)
	return envelope(record), nil
}

func (s *Service) GetIntent(intentID string) (IntentRecord, bool) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	record, ok := s.intents[intentID]
	return record, ok
}

func (s *Service) GetAgentStatus(agentID string) (Agent, bool) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	agent, ok := s.agents[agentID]
	return agent, ok
}

func (s *Service) SuspendAgent(agentID string, actor authenticatedActor, now time.Time) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	agent, ok := s.agents[agentID]
	if !ok {
		return errors.New("agent not found")
	}
	agent.Status = AgentStatusSuspended
	agent.SuspendedAt = ptrTime(now)
	s.agents[agentID] = agent
	s.preventionSignals = append(s.preventionSignals, "agent:"+agentID)
	s.audit(now, "", agentID, "", "suspended", "DOWNSTREAM_PREVENTION_SIGNALLED", actor.Actor)
	return nil
}

func (s *Service) RevokeAgentCredentials(agentID string, actor authenticatedActor, now time.Time) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	for id, credential := range s.credentialsByID {
		if credential.AgentID != agentID {
			continue
		}
		credential.RevokedAt = ptrTime(now)
		s.credentialsByID[id] = credential
	}
	s.audit(now, "", agentID, "", "revoked", "CREDENTIALS_REVOKED", actor.Actor)
	return nil
}

func (s *Service) RevokeCapability(capabilityID string, actor authenticatedActor, now time.Time) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	capability, ok := s.capabilities[capabilityID]
	if !ok {
		return errors.New("capability not found")
	}
	capability.Status = RecordStatusRevoked
	capability.RevokedAt = ptrTime(now)
	s.capabilities[capabilityID] = capability
	s.audit(now, "", capability.AgentID, "", "revoked", "CAPABILITY_REVOKED", actor.Actor)
	return nil
}

func (s *Service) ActivateKillSwitch(actor authenticatedActor, now time.Time) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.killSwitch = true
	s.preventionSignals = append(s.preventionSignals, "global")
	s.audit(now, "", "", "", "killswitch_activated", "DOWNSTREAM_PREVENTION_SIGNALLED", actor.Actor)
}

func (s *Service) DeactivateKillSwitch(actor authenticatedActor, now time.Time) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.killSwitch = false
	s.audit(now, "", "", "", "killswitch_deactivated", "", actor.Actor)
}

func (s *Service) AuditEvents(intentID string) []AuditEvent {
	s.mu.RLock()
	defer s.mu.RUnlock()
	out := make([]AuditEvent, 0)
	for _, event := range s.auditEvents {
		if intentID == "" || event.IntentID == intentID {
			out = append(out, event)
		}
	}
	return out
}

func (s *Service) PreventionSignals() []string {
	s.mu.RLock()
	defer s.mu.RUnlock()
	return append([]string(nil), s.preventionSignals...)
}

func (s *Service) VerifyAuditIntegrity() bool {
	s.mu.RLock()
	defer s.mu.RUnlock()
	prev := ""
	for _, event := range s.auditEvents {
		if event.PrevHash != prev {
			return false
		}
		if event.Hash != s.auditHash(event.EventID, event.Timestamp, event.IntentID, event.AgentID, event.MandateID, event.Decision, event.ReasonCode, event.Actor, event.PrevHash) {
			return false
		}
		prev = event.Hash
	}
	return true
}

func (s *Service) rejectIntent(intent FinancialIntent, now time.Time, actor string, decision Decision, reason string) DecisionEnvelope {
	record := IntentRecord{
		FinancialIntent: intent,
		Status:          decision,
		ReasonCode:      reason,
		CreatedAt:       now,
		UpdatedAt:       now,
		RequestHash:     s.intentHash(intent),
	}
	s.intents[intent.IntentID] = record
	stage := strings.ToLower(string(decision))
	if decision == DecisionDenied {
		stage = "denied"
	}
	s.audit(now, intent.IntentID, intent.AgentID, intent.MandateID, stage, reason, actor)
	return envelope(record)
}

func (s *Service) rateLimitExceeded(agentID string, now time.Time, limit int) bool {
	windowStart := now.Add(-s.cfg.RateLimitWindow)
	timestamps := s.agentRequests[agentID][:0]
	for _, ts := range s.agentRequests[agentID] {
		if ts.After(windowStart) {
			timestamps = append(timestamps, ts)
		}
	}
	s.agentRequests[agentID] = timestamps
	return limit > 0 && len(timestamps) >= limit
}

func (s *Service) spendLimitExceeded(agentID string, now time.Time, limit, requested float64) bool {
	windowStart := now.Add(-s.cfg.RateLimitWindow)
	entries := s.agentSpend[agentID][:0]
	total := 0.0
	for _, entry := range s.agentSpend[agentID] {
		if entry.At.After(windowStart) {
			entries = append(entries, entry)
			total += entry.Amount
		}
	}
	s.agentSpend[agentID] = entries
	return limit > 0 && total+requested > limit
}

func (s *Service) capabilityPermits(capability AgentCapability, intent FinancialIntent) bool {
	if !contains(capability.AllowedActions, intent.Action) {
		return false
	}
	if !contains(capability.AllowedAssets, intent.Asset) {
		return false
	}
	if !contains(capability.AllowedChains, intent.Chain) {
		return false
	}
	if !contains(capability.AllowedContracts, intent.Contract) {
		return false
	}
	if !contains(capability.AllowedFunctions, intent.Function) {
		return false
	}
	return true
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
	return mapActionToService(intent.Action) + ":" + s.hashString(intent.IntentID + intent.CorrelationID)[:12]
}

func (s *Service) audit(now time.Time, intentID, agentID, mandateID, decision, reasonCode, actor string) {
	eventID := s.newID("evt")
	hash := s.auditHash(eventID, now, intentID, agentID, mandateID, decision, reasonCode, actor, s.lastAuditHash)
	event := AuditEvent{
		EventID:    eventID,
		Timestamp:  now.UTC(),
		IntentID:   intentID,
		AgentID:    agentID,
		MandateID:  mandateID,
		Decision:   decision,
		ReasonCode: reasonCode,
		Actor:      actor,
		Hash:       hash,
		PrevHash:   s.lastAuditHash,
	}
	s.auditEvents = append(s.auditEvents, event)
	s.lastAuditHash = hash
}

func (s *Service) newID(prefix string) string {
	s.nextID++
	return fmt.Sprintf("%s-%06d", prefix, s.nextID)
}

func (s *Service) auditHash(eventID string, ts time.Time, intentID, agentID, mandateID, decision, reasonCode, actor, prevHash string) string {
	parts := strings.Join([]string{eventID, ts.UTC().Format(time.RFC3339Nano), intentID, agentID, mandateID, decision, reasonCode, actor, prevHash}, "|")
	return s.hashString(parts)
}

func (s *Service) intentHash(intent FinancialIntent) string {
	type alias FinancialIntent
	b, _ := json.Marshal(alias(intent))
	return s.hashString(string(b))
}

func (s *Service) requestHash(intent FinancialIntent) string {
	intent.IntentID = ""
	intent.IssuedAt = time.Time{}
	intent.ExpiresAt = time.Time{}
	intent.PolicyBinding.DecisionRef = ""
	intent.RiskLinkage.Reference = ""
	intent.RiskLinkage.DecisionRef = ""
	return s.intentHash(intent)
}

func (s *Service) hashString(value string) string {
	sum := sha256.Sum256([]byte(value))
	return hex.EncodeToString(sum[:])
}

func envelope(record IntentRecord) DecisionEnvelope {
	return DecisionEnvelope{
		IntentID:            record.IntentID,
		Decision:            record.Status,
		Status:              record.Status,
		ReasonCode:          record.ReasonCode,
		Forwarded:           record.Forwarded,
		ApprovalRequired:    record.Status == DecisionReview || record.Status == DecisionChallenge || record.Status == DecisionDelay,
		DownstreamReference: record.DownstreamReference,
		PolicyDecisionRef:   record.PolicyBinding.DecisionRef,
		RiskReference:       record.RiskLinkage.Reference,
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

func mapActionToService(action string) string {
	switch strings.ToUpper(action) {
	case "TRANSFER":
		return "pay"
	case "TRADE":
		return "markets"
	case "BALANCE_CHECK":
		return "accounts"
	default:
		return "blocked"
	}
}

func ptrTime(t time.Time) *time.Time {
	return &t
}
