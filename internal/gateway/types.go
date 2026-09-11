package gateway

import "time"

const (
	ContractVersion = "RFC-0005/0007"
	SchemaVersion   = "v1"
)

type Decision string

const (
	DecisionApproved   Decision = "APPROVED"
	DecisionDenied     Decision = "DENIED"
	DecisionReview     Decision = "REVIEW"
	DecisionChallenge  Decision = "CHALLENGE"
	DecisionDelay      Decision = "DELAY"
	DecisionQuarantine Decision = "QUARANTINE"
	DecisionCancelled  Decision = "CANCELLED"
	DecisionBlocked    Decision = "BLOCKED"
)

type PolicyOutcome string

const (
	PolicyOutcomeAllow      PolicyOutcome = "ALLOW"
	PolicyOutcomeDeny       PolicyOutcome = "DENY"
	PolicyOutcomeReview     PolicyOutcome = "REVIEW"
	PolicyOutcomeChallenge  PolicyOutcome = "CHALLENGE"
	PolicyOutcomeDelay      PolicyOutcome = "DELAY"
	PolicyOutcomeQuarantine PolicyOutcome = "QUARANTINE"
)

type ActorType string

const (
	ActorTypeUser        ActorType = "USER"
	ActorTypeApplication ActorType = "APPLICATION"
	ActorTypeSystem      ActorType = "SYSTEM"
	ActorTypeAgent       ActorType = "AGENT"
)

type FinancialAction string

const (
	ActionPay           FinancialAction = "PAY"
	ActionTransfer      FinancialAction = "TRANSFER"
	ActionSwap          FinancialAction = "SWAP"
	ActionTrade         FinancialAction = "TRADE"
	ActionRebalance     FinancialAction = "REBALANCE"
	ActionCollect       FinancialAction = "COLLECT"
	ActionOpenPosition  FinancialAction = "OPEN_POSITION"
	ActionClosePosition FinancialAction = "CLOSE_POSITION"
)

type AgentStatus string

const (
	AgentStatusActive    AgentStatus = "ACTIVE"
	AgentStatusSuspended AgentStatus = "SUSPENDED"
)

type RecordStatus string

const (
	RecordStatusActive  RecordStatus = "ACTIVE"
	RecordStatusRevoked RecordStatus = "REVOKED"
)

type AutonomyLevel string

const (
	AutonomyA0 AutonomyLevel = "A0"
	AutonomyA1 AutonomyLevel = "A1"
	AutonomyA2 AutonomyLevel = "A2"
	AutonomyA3 AutonomyLevel = "A3"
)

var autonomyRank = map[AutonomyLevel]int{
	AutonomyA0: 0,
	AutonomyA1: 1,
	AutonomyA2: 2,
	AutonomyA3: 3,
}

type Agent struct {
	ID             string        `json:"agentId"`
	Status         AgentStatus   `json:"status"`
	RateLimit      int           `json:"rateLimit"`
	SpendLimit     float64       `json:"spendLimit"`
	ReviewLimit    float64       `json:"reviewLimit"`
	AutonomyLevel  AutonomyLevel `json:"autonomyLevel"`
	SessionBinding string        `json:"sessionBinding,omitempty"`
	SuspendedAt    *time.Time    `json:"suspendedAt,omitempty"`
}

type AgentCredential struct {
	ID         string     `json:"credentialId"`
	AgentID    string     `json:"agentId"`
	Token      string     `json:"-"`
	SessionID  string     `json:"sessionId,omitempty"`
	RevokedAt  *time.Time `json:"revokedAt,omitempty"`
	ExpiresAt  time.Time  `json:"expiresAt"`
	LastUsedAt *time.Time `json:"lastUsedAt,omitempty"`
}

type AgentCapability struct {
	ID               string        `json:"capabilityId"`
	AgentID          string        `json:"agentId"`
	AllowedActions   []string      `json:"allowedActions"`
	AllowedAssets    []string      `json:"allowedAssets"`
	AllowedChains    []string      `json:"allowedChains"`
	AllowedContracts []string      `json:"allowedContracts"`
	AllowedFunctions []string      `json:"allowedFunctions"`
	AutonomyLevel    AutonomyLevel `json:"autonomyLevel"`
	Status           RecordStatus  `json:"status"`
	RevokedAt        *time.Time    `json:"revokedAt,omitempty"`
	ExpiresAt        *time.Time    `json:"expiresAt,omitempty"`
}

type AgentMandate struct {
	ID            string        `json:"mandateId"`
	AgentID       string        `json:"agentId"`
	AutonomyLevel AutonomyLevel `json:"autonomyLevel"`
	PolicyVersion string        `json:"policyVersion"`
	PolicyHash    string        `json:"policyHash,omitempty"`
	Status        RecordStatus  `json:"status"`
	RevokedAt     *time.Time    `json:"revokedAt,omitempty"`
	ExpiresAt     time.Time     `json:"expiresAt"`
}

type FinancialIntent struct {
	IntentID       string          `json:"intentId,omitempty"`
	ActorType      ActorType       `json:"actorType"`
	ActorID        string          `json:"actorId"`
	Action         FinancialAction `json:"action"`
	AssetID        string          `json:"assetId"`
	Amount         *float64        `json:"amount,omitempty"`
	ChainID        string          `json:"chainId,omitempty"`
	Recipient      string          `json:"recipient,omitempty"`
	Venue          string          `json:"venue,omitempty"`
	Purpose        string          `json:"purpose"`
	MandateID      string          `json:"mandateId,omitempty"`
	PolicyVersion  string          `json:"policyVersion"`
	CorrelationID  string          `json:"correlationId"`
	IdempotencyKey string          `json:"idempotencyKey"`
	ExpiresAt      time.Time       `json:"expiresAt"`
}

type ExecutionContextRef struct {
	CallTarget string `json:"callTarget,omitempty"`
	Contract   string `json:"contract,omitempty"`
	Function   string `json:"function,omitempty"`
}

type ExecutionHints struct {
	AgentID        string              `json:"agentId"`
	CapabilityID   string              `json:"capabilityId"`
	Nonce          string              `json:"nonce"`
	AutonomyLevel  AutonomyLevel       `json:"autonomyLevel,omitempty"`
	ExecutionRef   ExecutionContextRef `json:"executionRef,omitempty"`
	DownstreamHint string              `json:"downstreamHint,omitempty"`
}

type AuthorityReferences struct {
	PolicyDecisionID string        `json:"policyDecisionId,omitempty"`
	RiskAssessmentID string        `json:"riskAssessmentId,omitempty"`
	AuthorizationID  string        `json:"authorizationId,omitempty"`
	Outcome          PolicyOutcome `json:"outcome,omitempty"`
	LookupKey        string        `json:"lookupKey,omitempty"`
}

type PolicyBinding struct {
	Version     string `json:"version"`
	Hash        string `json:"hash"`
	DecisionRef string `json:"decisionRef,omitempty"`
}

type RiskLinkage struct {
	Reference   string  `json:"reference,omitempty"`
	DecisionRef string  `json:"decisionRef,omitempty"`
	Score       float64 `json:"score,omitempty"`
}

type SubmitIntentRequest struct {
	Intent              FinancialIntent         `json:"intent"`
	Execution           ExecutionHints          `json:"execution"`
	Authority           AuthorityReferences     `json:"authority,omitempty"`
	Metadata            map[string]interface{}  `json:"metadata,omitempty"`
	DeprecationWarnings []string                `json:"deprecationWarnings,omitempty"`
}

type IntentRecord struct {
	Intent              FinancialIntent        `json:"intent"`
	Execution           ExecutionHints         `json:"execution"`
	Authority           AuthorityReferences    `json:"authority"`
	Status              Decision               `json:"status"`
	PolicyOutcome       PolicyOutcome          `json:"policyOutcome,omitempty"`
	ReasonCode          string                 `json:"reasonCode,omitempty"`
	Forwarded           bool                   `json:"forwarded"`
	CreatedAt           time.Time              `json:"createdAt"`
	UpdatedAt           time.Time              `json:"updatedAt"`
	RequestHash         string                 `json:"requestHash"`
	DownstreamReference string                 `json:"downstreamReference,omitempty"`
	ApprovedAt          *time.Time             `json:"approvedAt,omitempty"`
	CancelledAt         *time.Time             `json:"cancelledAt,omitempty"`
	Metadata            map[string]interface{} `json:"metadata,omitempty"`
	DeprecationWarnings []string               `json:"deprecationWarnings,omitempty"`
}

type DecisionEnvelope struct {
	ContractVersion     string              `json:"contractVersion"`
	SchemaVersion       string              `json:"schemaVersion"`
	Intent              FinancialIntent     `json:"intent"`
	Execution           ExecutionHints      `json:"execution"`
	Authority           AuthorityReferences `json:"authority"`
	Decision            Decision            `json:"decision"`
	Status              Decision            `json:"status"`
	PolicyOutcome       PolicyOutcome       `json:"policyOutcome,omitempty"`
	ReasonCode          string              `json:"reasonCode,omitempty"`
	Forwarded           bool                `json:"forwarded"`
	ApprovalRequired    bool                `json:"approvalRequired"`
	DownstreamReference string              `json:"downstreamReference,omitempty"`
	DeprecationWarnings []string            `json:"deprecationWarnings,omitempty"`
}

type AuditEvent struct {
	EventID           string    `json:"eventId"`
	Timestamp         time.Time `json:"timestamp"`
	IntentID          string    `json:"intentId,omitempty"`
	ActorID           string    `json:"actorId,omitempty"`
	AgentID           string    `json:"agentId,omitempty"`
	MandateID         string    `json:"mandateId,omitempty"`
	PolicyVersion     string    `json:"policyVersion,omitempty"`
	RiskAssessmentID  string    `json:"riskAssessmentId,omitempty"`
	AuthorizationID   string    `json:"authorizationId,omitempty"`
	CorrelationID     string    `json:"correlationId,omitempty"`
	Decision          string    `json:"decision"`
	ReasonCode        string    `json:"reasonCode,omitempty"`
	Actor             string    `json:"actor"`
	Hash              string    `json:"hash"`
	PrevHash          string    `json:"prevHash,omitempty"`
}

type Config struct {
	AdminReadToken    string
	AdminWriteToken   string
	KillSwitchToken   string
	ApprovalToken     string
	DatabaseURL       string
	ReplayWindow      time.Duration
	RateLimitWindow   time.Duration
	DefaultRateLimit  int
	DefaultSpendLimit float64
	DefaultReviewLimit float64
}
