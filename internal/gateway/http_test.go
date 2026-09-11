package gateway

import (
	"bytes"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"
)

const testAgentToken = "test-agent-token"

func TestIntentLifecycleAndControls(t *testing.T) {
	svc := seededService()
	handler := NewHandler(svc, "admin-token")

	intent := validIntent()
	res := performJSON(t, handler, http.MethodPost, "/v1/intents", intent, map[string]string{
		"Authorization": "Bearer " + testAgentToken,
		"X-Session-ID":  "session-1",
	})
	if res.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d: %s", res.Code, res.Body.String())
	}

	var envelope DecisionEnvelope
	decodeBody(t, res, &envelope)
	if envelope.Decision != DecisionApproved || !envelope.Forwarded {
		t.Fatalf("expected approved+forwarded, got %+v", envelope)
	}

	getRes := performJSON(t, handler, http.MethodGet, "/v1/intents/"+envelope.IntentID, nil, nil)
	if getRes.Code != http.StatusOK {
		t.Fatalf("expected intent fetch to succeed, got %d", getRes.Code)
	}

	statusRes := performJSON(t, handler, http.MethodGet, "/v1/agents/agent-1/status", nil, nil)
	if statusRes.Code != http.StatusOK {
		t.Fatalf("expected agent status, got %d", statusRes.Code)
	}

	eventsRes := performJSON(t, handler, http.MethodGet, "/v1/audit/events?intentId="+envelope.IntentID, nil, nil)
	var events []AuditEvent
	decodeBody(t, eventsRes, &events)
	if len(events) < 6 {
		t.Fatalf("expected audit trail, got %d events", len(events))
	}
	if !svc.VerifyAuditIntegrity() {
		t.Fatal("expected audit chain to verify")
	}
}

func TestAuthFailures(t *testing.T) {
	t.Run("revoked credential fails", func(t *testing.T) {
		svc := seededService()
		now := time.Now().UTC()
		cred := svc.credentialsByID["cred-1"]
		cred.RevokedAt = &now
		svc.credentialsByID["cred-1"] = cred
		handler := NewHandler(svc, "admin-token")

		res := performJSON(t, handler, http.MethodPost, "/v1/intents", validIntent(), map[string]string{
			"Authorization": "Bearer " + testAgentToken,
			"X-Session-ID":  "session-1",
		})
		if res.Code != http.StatusUnauthorized {
			t.Fatalf("expected 401, got %d", res.Code)
		}
	})

	t.Run("expired credential fails", func(t *testing.T) {
		svc := seededService()
		cred := svc.credentialsByID["cred-1"]
		cred.ExpiresAt = time.Now().UTC().Add(-time.Minute)
		svc.credentialsByID["cred-1"] = cred
		handler := NewHandler(svc, "admin-token")

		res := performJSON(t, handler, http.MethodPost, "/v1/intents", validIntent(), map[string]string{
			"Authorization": "Bearer " + testAgentToken,
			"X-Session-ID":  "session-1",
		})
		if res.Code != http.StatusUnauthorized {
			t.Fatalf("expected 401, got %d", res.Code)
		}
	})

	t.Run("suspended agent fails", func(t *testing.T) {
		svc := seededService()
		agent := svc.agents["agent-1"]
		agent.Status = AgentStatusSuspended
		svc.agents["agent-1"] = agent
		handler := NewHandler(svc, "admin-token")

		res := performJSON(t, handler, http.MethodPost, "/v1/intents", validIntent(), map[string]string{
			"Authorization": "Bearer " + testAgentToken,
			"X-Session-ID":  "session-1",
		})
		if res.Code != http.StatusForbidden {
			t.Fatalf("expected 403, got %d", res.Code)
		}
	})

	t.Run("revoked capability fails", func(t *testing.T) {
		svc := seededService()
		capability := svc.capabilities["cap-1"]
		now := time.Now().UTC()
		capability.Status = RecordStatusRevoked
		capability.RevokedAt = &now
		svc.capabilities["cap-1"] = capability
		handler := NewHandler(svc, "admin-token")

		res := performJSON(t, handler, http.MethodPost, "/v1/intents", validIntent(), map[string]string{
			"Authorization": "Bearer " + testAgentToken,
			"X-Session-ID":  "session-1",
		})
		assertReasonCode(t, res, "CAPABILITY_REVOKED_OR_EXPIRED")
	})

	t.Run("revoked mandate fails", func(t *testing.T) {
		svc := seededService()
		mandate := svc.mandates["mandate-1"]
		now := time.Now().UTC()
		mandate.Status = RecordStatusRevoked
		mandate.RevokedAt = &now
		svc.mandates["mandate-1"] = mandate
		handler := NewHandler(svc, "admin-token")

		res := performJSON(t, handler, http.MethodPost, "/v1/intents", validIntent(), map[string]string{
			"Authorization": "Bearer " + testAgentToken,
			"X-Session-ID":  "session-1",
		})
		assertReasonCode(t, res, "MANDATE_REVOKED_OR_EXPIRED")
	})
}

func TestRequestValidationReplayAndLimits(t *testing.T) {
	t.Run("malformed schema rejected", func(t *testing.T) {
		svc := seededService()
		handler := NewHandler(svc, "admin-token")
		intent := validIntent()
		intent.Asset = ""
		res := performJSON(t, handler, http.MethodPost, "/v1/intents", intent, map[string]string{
			"Authorization": "Bearer " + testAgentToken,
			"X-Session-ID":  "session-1",
		})
		assertReasonCode(t, res, "MALFORMED_INTENT")
	})

	t.Run("missing authority fields rejected", func(t *testing.T) {
		svc := seededService()
		handler := NewHandler(svc, "admin-token")
		intent := validIntent()
		intent.CorrelationID = ""
		res := performJSON(t, handler, http.MethodPost, "/v1/intents", intent, map[string]string{
			"Authorization": "Bearer " + testAgentToken,
			"X-Session-ID":  "session-1",
		})
		assertReasonCode(t, res, "MISSING_AUTHORITY_FIELDS")
	})

	t.Run("expired intent rejected", func(t *testing.T) {
		svc := seededService()
		handler := NewHandler(svc, "admin-token")
		intent := validIntent()
		intent.ExpiresAt = time.Now().UTC().Add(-time.Minute)
		res := performJSON(t, handler, http.MethodPost, "/v1/intents", intent, map[string]string{
			"Authorization": "Bearer " + testAgentToken,
			"X-Session-ID":  "session-1",
		})
		assertReasonCode(t, res, "INTENT_EXPIRED")
	})

	t.Run("unsupported action rejected", func(t *testing.T) {
		svc := seededService()
		handler := NewHandler(svc, "admin-token")
		intent := validIntent()
		intent.Action = "SWAP"
		res := performJSON(t, handler, http.MethodPost, "/v1/intents", intent, map[string]string{
			"Authorization": "Bearer " + testAgentToken,
			"X-Session-ID":  "session-1",
		})
		assertReasonCode(t, res, "UNSUPPORTED_ACTION")
	})

	t.Run("duplicate idempotency key blocked", func(t *testing.T) {
		svc := seededService()
		handler := NewHandler(svc, "admin-token")
		headers := map[string]string{"Authorization": "Bearer " + testAgentToken, "X-Session-ID": "session-1"}
		performJSON(t, handler, http.MethodPost, "/v1/intents", validIntent(), headers)
		res := performJSON(t, handler, http.MethodPost, "/v1/intents", validIntent(), headers)
		assertReasonCode(t, res, "DUPLICATE_IDEMPOTENCY_KEY")
	})

	t.Run("stale nonce blocked", func(t *testing.T) {
		svc := seededService()
		handler := NewHandler(svc, "admin-token")
		intent := validIntent()
		intent.IssuedAt = time.Now().UTC().Add(-10 * time.Minute)
		res := performJSON(t, handler, http.MethodPost, "/v1/intents", intent, map[string]string{
			"Authorization": "Bearer " + testAgentToken,
			"X-Session-ID":  "session-1",
		})
		assertReasonCode(t, res, "STALE_NONCE")
	})

	t.Run("altered payload with same key blocked", func(t *testing.T) {
		svc := seededService()
		handler := NewHandler(svc, "admin-token")
		headers := map[string]string{"Authorization": "Bearer " + testAgentToken, "X-Session-ID": "session-1"}
		performJSON(t, handler, http.MethodPost, "/v1/intents", validIntent(), headers)
		intent := validIntent()
		intent.Amount = 99
		res := performJSON(t, handler, http.MethodPost, "/v1/intents", intent, headers)
		assertReasonCode(t, res, "IDEMPOTENCY_KEY_REUSED_WITH_DIFFERENT_PAYLOAD")
	})

	t.Run("rate limit exceeded blocked", func(t *testing.T) {
		svc := seededService()
		agent := svc.agents["agent-1"]
		agent.RateLimit = 1
		svc.agents["agent-1"] = agent
		handler := NewHandler(svc, "admin-token")
		headers := map[string]string{"Authorization": "Bearer " + testAgentToken, "X-Session-ID": "session-1"}
		intent1 := validIntent()
		intent1.IdempotencyKey = "idem-rate-1"
		intent1.Nonce = "nonce-rate-1"
		performJSON(t, handler, http.MethodPost, "/v1/intents", intent1, headers)
		intent2 := validIntent()
		intent2.IdempotencyKey = "idem-rate-2"
		intent2.Nonce = "nonce-rate-2"
		res := performJSON(t, handler, http.MethodPost, "/v1/intents", intent2, headers)
		assertReasonCode(t, res, "RATE_LIMIT_EXCEEDED")
	})

	t.Run("spend cap exceeded blocked", func(t *testing.T) {
		svc := seededService()
		agent := svc.agents["agent-1"]
		agent.SpendLimit = 10
		agent.ReviewLimit = 100
		svc.agents["agent-1"] = agent
		handler := NewHandler(svc, "admin-token")
		headers := map[string]string{"Authorization": "Bearer " + testAgentToken, "X-Session-ID": "session-1"}
		intent1 := validIntent()
		intent1.IdempotencyKey = "idem-spend-1"
		intent1.Nonce = "nonce-spend-1"
		intent1.Amount = 7
		performJSON(t, handler, http.MethodPost, "/v1/intents", intent1, headers)
		intent2 := validIntent()
		intent2.IdempotencyKey = "idem-spend-2"
		intent2.Nonce = "nonce-spend-2"
		intent2.Amount = 5
		res := performJSON(t, handler, http.MethodPost, "/v1/intents", intent2, headers)
		assertReasonCode(t, res, "SPEND_LIMIT_EXCEEDED")
	})
}

func TestApprovalAndKillSwitchFlows(t *testing.T) {
	svc := seededService()
	handler := NewHandler(svc, "admin-token")
	headers := map[string]string{"Authorization": "Bearer " + testAgentToken, "X-Session-ID": "session-1"}

	intent := validIntent()
	intent.Amount = 5000
	intent.IdempotencyKey = "idem-review"
	intent.Nonce = "nonce-review"
	res := performJSON(t, handler, http.MethodPost, "/v1/intents", intent, headers)
	var review DecisionEnvelope
	decodeBody(t, res, &review)
	if review.Decision != DecisionReview {
		t.Fatalf("expected review, got %+v", review)
	}

	approveRes := performJSON(t, handler, http.MethodPost, "/v1/intents/"+review.IntentID+"/approve", nil, map[string]string{
		"X-Admin-Token": "admin-token",
	})
	var approved DecisionEnvelope
	decodeBody(t, approveRes, &approved)
	if approved.Decision != DecisionApproved || !approved.Forwarded {
		t.Fatalf("expected approval to forward, got %+v", approved)
	}

	killRes := performJSON(t, handler, http.MethodPost, "/v1/killswitch/activate", nil, map[string]string{
		"X-Admin-Token": "admin-token",
	})
	if killRes.Code != http.StatusOK {
		t.Fatalf("expected kill switch activation, got %d", killRes.Code)
	}
	blocked := validIntent()
	blocked.IdempotencyKey = "idem-kill"
	blocked.Nonce = "nonce-kill"
	blockedRes := performJSON(t, handler, http.MethodPost, "/v1/intents", blocked, headers)
	assertReasonCode(t, blockedRes, "KILLSWITCH_ACTIVE")

	if len(svc.PreventionSignals()) == 0 {
		t.Fatal("expected downstream prevention signal")
	}

	deactivateRes := performJSON(t, handler, http.MethodPost, "/v1/killswitch/deactivate", nil, map[string]string{
		"X-Admin-Token": "admin-token",
		"X-High-Trust":  "true",
	})
	if deactivateRes.Code != http.StatusOK {
		t.Fatalf("expected killswitch deactivation, got %d", deactivateRes.Code)
	}

	suspendRes := performJSON(t, handler, http.MethodPost, "/v1/agents/agent-1/suspend", nil, map[string]string{
		"X-Admin-Token": "admin-token",
	})
	if suspendRes.Code != http.StatusOK {
		t.Fatalf("expected suspend ok, got %d", suspendRes.Code)
	}
	agentBlocked := validIntent()
	agentBlocked.IdempotencyKey = "idem-suspend"
	agentBlocked.Nonce = "nonce-suspend"
	agentBlockedRes := performJSON(t, handler, http.MethodPost, "/v1/intents", agentBlocked, headers)
	if agentBlockedRes.Code != http.StatusForbidden {
		t.Fatalf("expected suspended agent request to fail, got %d", agentBlockedRes.Code)
	}
}

func seededService() *Service {
	svc := NewService(Config{
		AdminToken:         "admin-token",
		ReplayWindow:       5 * time.Minute,
		RateLimitWindow:    time.Minute,
		DefaultRateLimit:   10,
		DefaultSpendLimit:  10000,
		DefaultReviewLimit: 500,
	})
	svc.SeedAgent(Agent{
		ID:             "agent-1",
		Status:         AgentStatusActive,
		RateLimit:      10,
		SpendLimit:     10000,
		ReviewLimit:    500,
		AutonomyLevel:  AutonomyA2,
		SessionBinding: "session-1",
	})
	svc.SeedCredential(AgentCredential{
		ID:        "cred-1",
		AgentID:   "agent-1",
		Token:     testAgentToken,
		SessionID: "session-1",
		ExpiresAt: time.Now().UTC().Add(time.Hour),
	})
	svc.SeedCapability(AgentCapability{
		ID:               "cap-1",
		AgentID:          "agent-1",
		AllowedActions:   []string{"TRANSFER", "BALANCE_CHECK"},
		AllowedAssets:    []string{"USD"},
		AllowedChains:    []string{"solana"},
		AllowedContracts: []string{"treasury-vault"},
		AllowedFunctions: []string{"transfer", "balanceOf"},
		AutonomyLevel:    AutonomyA2,
		Status:           RecordStatusActive,
	})
	svc.SeedMandate(AgentMandate{
		ID:            "mandate-1",
		AgentID:       "agent-1",
		AutonomyLevel: AutonomyA2,
		Status:        RecordStatusActive,
		ExpiresAt:     time.Now().UTC().Add(time.Hour),
	})
	return svc
}

func validIntent() FinancialIntent {
	now := time.Now().UTC()
	return FinancialIntent{
		ActorType:      "agent",
		ActorID:        "agent-1",
		AgentID:        "agent-1",
		CapabilityID:   "cap-1",
		MandateID:      "mandate-1",
		Action:         "TRANSFER",
		Asset:          "USD",
		Amount:         25,
		Chain:          "solana",
		Contract:       "treasury-vault",
		Function:       "transfer",
		Nonce:          "nonce-1",
		IssuedAt:       now,
		ExpiresAt:      now.Add(time.Minute),
		IdempotencyKey: "idem-1",
		CorrelationID:  "corr-1",
		AutonomyLevel:  AutonomyA2,
		PolicyBinding:  PolicyBinding{Version: "2026-09", Hash: "abc123"},
		RiskLinkage:    RiskLinkage{Score: 0.1},
	}
}

func performJSON(t *testing.T, handler http.Handler, method, path string, body interface{}, headers map[string]string) *httptest.ResponseRecorder {
	t.Helper()
	var buf bytes.Buffer
	if body != nil {
		if err := json.NewEncoder(&buf).Encode(body); err != nil {
			t.Fatal(err)
		}
	}
	req := httptest.NewRequest(method, path, &buf)
	for key, value := range headers {
		req.Header.Set(key, value)
	}
	if body != nil {
		req.Header.Set("Content-Type", "application/json")
	}
	res := httptest.NewRecorder()
	handler.ServeHTTP(res, req)
	return res
}

func decodeBody(t *testing.T, res *httptest.ResponseRecorder, target interface{}) {
	t.Helper()
	if err := json.Unmarshal(res.Body.Bytes(), target); err != nil {
		t.Fatalf("failed to decode body %q: %v", res.Body.String(), err)
	}
}

func assertReasonCode(t *testing.T, res *httptest.ResponseRecorder, code string) {
	t.Helper()
	var body map[string]interface{}
	decodeBody(t, res, &body)
	if body["reasonCode"] != code {
		t.Fatalf("expected reasonCode %s, got %v (status %d body %s)", code, body["reasonCode"], res.Code, res.Body.String())
	}
}
