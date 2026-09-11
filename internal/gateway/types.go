package gateway

import "time"

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
	Status        RecordStatus  `json:"status"`
	RevokedAt     *time.Time    `json:"revokedAt,omitempty"`
	ExpiresAt     time.Time     `json:"expiresAt"`
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

type FinancialIntent struct {
	IntentID        string                 `json:"intentId,omitempty"`
	ActorType       string                 `json:"actorType"`
	ActorID         string                 `json:"actorId"`
	AgentID         string                 `json:"agentId"`
	CapabilityID    string                 `json:"capabilityId"`
	MandateID       string                 `json:"mandateId"`
	Action          string                 `json:"action"`
	Asset           string                 `json:"asset"`
	Amount          float64                `json:"amount"`
	Chain           string                 `json:"chain"`
	Contract        string                 `json:"contract"`
	Function        string                 `json:"function"`
	Nonce           string                 `json:"nonce"`
	IssuedAt        time.Time              `json:"issuedAt"`
	ExpiresAt       time.Time              `json:"expiresAt"`
	IdempotencyKey  string                 `json:"idempotencyKey"`
	CorrelationID   string                 `json:"correlationId"`
	AutonomyLevel   AutonomyLevel          `json:"autonomyLevel"`
	PolicyBinding   PolicyBinding          `json:"policyBinding"`
	RiskLinkage     RiskLinkage            `json:"riskLinkage"`
	ReviewRequested bool                   `json:"reviewRequested,omitempty"`
	Metadata        map[string]interface{} `json:"metadata,omitempty"`
}

type IntentRecord struct {
	FinancialIntent
	Status              Decision   `json:"status"`
	ReasonCode          string     `json:"reasonCode,omitempty"`
	Forwarded           bool       `json:"forwarded"`
	CreatedAt           time.Time  `json:"createdAt"`
	UpdatedAt           time.Time  `json:"updatedAt"`
	RequestHash         string     `json:"requestHash"`
	DownstreamReference string     `json:"downstreamReference,omitempty"`
	ApprovedAt          *time.Time `json:"approvedAt,omitempty"`
	CancelledAt         *time.Time `json:"cancelledAt,omitempty"`
}

type DecisionEnvelope struct {
	IntentID            string   `json:"intentId"`
	Decision            Decision `json:"decision"`
	Status              Decision `json:"status"`
	ReasonCode          string   `json:"reasonCode,omitempty"`
	Forwarded           bool     `json:"forwarded"`
	ApprovalRequired    bool     `json:"approvalRequired"`
	DownstreamReference string   `json:"downstreamReference,omitempty"`
	PolicyDecisionRef   string   `json:"policyDecisionRef,omitempty"`
	RiskReference       string   `json:"riskReference,omitempty"`
}

type AuditEvent struct {
	EventID    string    `json:"eventId"`
	Timestamp  time.Time `json:"timestamp"`
	IntentID   string    `json:"intentId,omitempty"`
	AgentID    string    `json:"agentId,omitempty"`
	MandateID  string    `json:"mandateId,omitempty"`
	Decision   string    `json:"decision"`
	ReasonCode string    `json:"reasonCode,omitempty"`
	Actor      string    `json:"actor"`
	Hash       string    `json:"hash"`
	PrevHash   string    `json:"prevHash,omitempty"`
}

type Config struct {
	AdminToken         string
	ReplayWindow       time.Duration
	RateLimitWindow    time.Duration
	DefaultRateLimit   int
	DefaultSpendLimit  float64
	DefaultReviewLimit float64
}
