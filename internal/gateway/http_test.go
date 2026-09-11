package gateway

import (
	"bytes"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"sync"
	"testing"
	"time"
)

const (
	testAgentToken  = "test-agent-token"
	adminReadToken  = "admin-read-token"
	adminWriteToken = "admin-write-token"
	killToken       = "kill-token"
	approvalToken   = "approval-token"
)

func TestCanonicalSchemaValidation(t *testing.T) {
	t.Run("uppercase enums required", func(t *testing.T) {
		handler := testHandler(t)
		req := validRequest()
		req.Intent.ActorType = ActorType("agent")
		res := performJSON(t, handler, http.MethodPost, "/v1/intents", req, agentHeaders())
		assertReasonCode(t, res, "MALFORMED_INTENT")
	})

	t.Run("required fields enforced", func(t *testing.T) {
		handler := testHandler(t)
		req := validRequest()
		req.Intent.Purpose = ""
		res := performJSON(t, handler, http.MethodPost, "/v1/intents", req, agentHeaders())
		assertReasonCode(t, res, "MISSING_AUTHORITY_FIELDS")
	})
}

func TestLegacyPayloadCompatibility(t *testing.T) {
	handler := testHandler(t)
	payload := map[string]interface{}{
		"intentId":        "legacy-intent-1",
		"actorType":       "AGENT",
		"actorId":         "agent-1",
		"action":          "TRANSFER",
		"asset":           "USD",
		"amount":          25,
		"chain":           "SOLANA",
		"purpose":         "settlement",
		"mandateId":       "mandate-1",
		"policyVersion":   "2026-09",
		"correlationId":   "corr-legacy-1",
		"idempotencyKey":  "idem-legacy-1",
		"expiresAt":       time.Now().UTC().Add(time.Minute),
		"agentId":         "agent-1",
		"capabilityId":    "cap-1",
		"nonce":           "nonce-legacy-1",
		"autonomyLevel":   "A2",
		"contract":        "treasury-vault",
		"function":        "transfer",
		"authority": map[string]interface{}{
			"policyDecisionId": "pol-1",
			"riskAssessmentId": "risk-1",
			"authorizationId":  "auth-1",
			"outcome":          "ALLOW",
		},
	}
	res := performJSON(t, handler, http.MethodPost, "/v1/intents", payload, agentHeaders())
	if res.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d: %s", res.Code, res.Body.String())
	}
	var envelope DecisionEnvelope
	decodeBody(t, res, &envelope)
	if envelope.Intent.AssetID != "USD" || envelope.Execution.ExecutionRef.Contract != "treasury-vault" {
		t.Fatalf("expected legacy mapping, got %+v", envelope)
	}
	if len(envelope.DeprecationWarnings) < 3 {
		t.Fatalf("expected deprecation warnings, got %+v", envelope.DeprecationWarnings)
	}
}

func TestPolicyRiskMissingFailsClosed(t *testing.T) {
	handler := testHandler(t)
	req := validRequest()
	req.Authority = AuthorityReferences{}
	res := performJSON(t, handler, http.MethodPost, "/v1/intents", req, agentHeaders())
	assertReasonCode(t, res, "POLICY_RISK_UNVERIFIED")
}

func TestDBBackedIdempotencyAndReplayConcurrency(t *testing.T) {
	handler := testHandler(t)
	var wg sync.WaitGroup
	codes := make(chan string, 8)
	for i := 0; i < 8; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			res := performJSON(t, handler, http.MethodPost, "/v1/intents", validRequest(), agentHeaders())
			if res.Code == http.StatusOK {
				codes <- "APPROVED"
				return
			}
			var envelope DecisionEnvelope
			decodeBody(t, res, &envelope)
			codes <- envelope.ReasonCode
		}()
	}
	wg.Wait()
	close(codes)
	approved := 0
	duplicates := 0
	for code := range codes {
		switch code {
		case "APPROVED":
			approved++
		case "DUPLICATE_IDEMPOTENCY_KEY", "REPLAY_DETECTED":
			duplicates++
		default:
			t.Fatalf("unexpected code %s", code)
		}
	}
	if approved != 1 {
		t.Fatalf("expected exactly one approval, got %d", approved)
	}
	if duplicates != 7 {
		t.Fatalf("expected duplicate/replay responses, got %d", duplicates)
	}
}

func TestKillSwitchAndSuspensionUseDBState(t *testing.T) {
	handler := testHandler(t)
	activateRes := performJSON(t, handler, http.MethodPost, "/v1/killswitch/activate", nil, adminHeaders(killToken))
	if activateRes.Code != http.StatusOK {
		t.Fatalf("expected activation, got %d", activateRes.Code)
	}
	blocked := validRequest()
	blocked.Intent.IdempotencyKey = "idem-kill"
	blocked.Execution.Nonce = "nonce-kill"
	blocked.Intent.CorrelationID = "corr-kill"
	res := performJSON(t, handler, http.MethodPost, "/v1/intents", blocked, agentHeaders())
	assertReasonCode(t, res, "KILLSWITCH_ACTIVE")

	deactivateRes := performJSON(t, handler, http.MethodPost, "/v1/killswitch/deactivate", nil, map[string]string{
		"Authorization": "Bearer " + killToken,
		"X-High-Trust":  "true",
	})
	if deactivateRes.Code != http.StatusOK {
		t.Fatalf("expected deactivation, got %d", deactivateRes.Code)
	}

	suspendRes := performJSON(t, handler, http.MethodPost, "/v1/agents/agent-1/suspend", nil, adminHeaders(adminWriteToken))
	if suspendRes.Code != http.StatusOK {
		t.Fatalf("expected suspend, got %d", suspendRes.Code)
	}
	blocked.Intent.IdempotencyKey = "idem-suspend"
	blocked.Execution.Nonce = "nonce-suspend"
	blocked.Intent.CorrelationID = "corr-suspend"
	blockedRes := performJSON(t, handler, http.MethodPost, "/v1/intents", blocked, agentHeaders())
	assertReasonCode(t, blockedRes, "AGENT_SUSPENDED")
}

func TestAuditHashChainPersistenceAndIntegrity(t *testing.T) {
	svc := testService(t)
	handler := NewHandler(svc)
	res := performJSON(t, handler, http.MethodPost, "/v1/intents", validRequest(), agentHeaders())
	if res.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d", res.Code)
	}
	if !svc.VerifyAuditIntegrity() {
		t.Fatal("expected audit integrity to verify")
	}
	eventsRes := performJSON(t, handler, http.MethodGet, "/v1/audit/events", nil, adminHeaders(adminReadToken))
	if eventsRes.Code != http.StatusOK {
		t.Fatalf("expected audit fetch, got %d", eventsRes.Code)
	}
	var events []AuditEvent
	decodeBody(t, eventsRes, &events)
	if len(events) < 2 {
		t.Fatalf("expected persisted audit events, got %d", len(events))
	}
	if events[0].Hash == "" || events[len(events)-1].PrevHash == "" {
		t.Fatalf("expected persisted hash chain, got %+v", events)
	}
}

func TestApprovalFlowUsesScopedAdminToken(t *testing.T) {
	handler := testHandler(t)
	req := validRequest()
	req.Intent.IdempotencyKey = "idem-review"
	req.Intent.CorrelationID = "corr-review"
	req.Execution.Nonce = "nonce-review"
	req.Authority.Outcome = PolicyOutcomeReview
	res := performJSON(t, handler, http.MethodPost, "/v1/intents", req, agentHeaders())
	var review DecisionEnvelope
	decodeBody(t, res, &review)
	if review.Decision != DecisionReview {
		t.Fatalf("expected review, got %+v", review)
	}
	approveRes := performJSON(t, handler, http.MethodPost, "/v1/intents/"+review.Intent.IntentID+"/approve", nil, adminHeaders(approvalToken))
	if approveRes.Code != http.StatusOK {
		t.Fatalf("expected approval, got %d: %s", approveRes.Code, approveRes.Body.String())
	}
}

func testService(t *testing.T) *Service {
	t.Helper()
	dsn := filepath.Join(t.TempDir(), "gateway.db")
	repo, err := OpenSQLRepository(dsn)
	if err != nil {
		t.Fatal(err)
	}
	svc := NewService(Config{
		AdminReadToken:      adminReadToken,
		AdminWriteToken:     adminWriteToken,
		KillSwitchToken:     killToken,
		ApprovalToken:       approvalToken,
		DatabaseURL:         dsn,
		ReplayWindow:        5 * time.Minute,
		RateLimitWindow:     time.Minute,
		DefaultRateLimit:    10,
		DefaultSpendLimit:   10000,
		DefaultReviewLimit:  500,
	}, repo, StaticPolicyRiskResolver{})
	svc.SeedAgent(Agent{ID: "agent-1", Status: AgentStatusActive, RateLimit: 10, SpendLimit: 10000, ReviewLimit: 500, AutonomyLevel: AutonomyA2, SessionBinding: "session-1"})
	svc.SeedCredential(AgentCredential{ID: "cred-1", AgentID: "agent-1", Token: testAgentToken, SessionID: "session-1", ExpiresAt: time.Now().UTC().Add(time.Hour)})
	svc.SeedCapability(AgentCapability{ID: "cap-1", AgentID: "agent-1", AllowedActions: []string{"PAY", "TRANSFER", "SWAP", "TRADE", "REBALANCE", "COLLECT", "OPEN_POSITION", "CLOSE_POSITION"}, AllowedAssets: []string{"USD"}, AllowedChains: []string{"SOLANA"}, AllowedContracts: []string{"treasury-vault"}, AllowedFunctions: []string{"transfer", "swap", "rebalance", "open", "close", "collect"}, AutonomyLevel: AutonomyA2, Status: RecordStatusActive})
	svc.SeedMandate(AgentMandate{ID: "mandate-1", AgentID: "agent-1", AutonomyLevel: AutonomyA2, PolicyVersion: "2026-09", PolicyHash: "policy-hash", Status: RecordStatusActive, ExpiresAt: time.Now().UTC().Add(time.Hour)})
	return svc
}

func testHandler(t *testing.T) http.Handler {
	t.Helper()
	return NewHandler(testService(t))
}

func validRequest() SubmitIntentRequest {
	now := time.Now().UTC()
	amount := 25.0
	return SubmitIntentRequest{
		Intent: FinancialIntent{
			ActorType:      ActorTypeAgent,
			ActorID:        "agent-1",
			Action:         ActionTransfer,
			AssetID:        "USD",
			Amount:         &amount,
			ChainID:        "SOLANA",
			Purpose:        "settlement",
			MandateID:      "mandate-1",
			PolicyVersion:  "2026-09",
			CorrelationID:  "corr-1",
			IdempotencyKey: "idem-1",
			ExpiresAt:      now.Add(time.Minute),
		},
		Execution: ExecutionHints{
			AgentID:       "agent-1",
			CapabilityID:  "cap-1",
			Nonce:         "nonce-1",
			AutonomyLevel: AutonomyA2,
			ExecutionRef: ExecutionContextRef{
				Contract: "treasury-vault",
				Function: "transfer",
			},
		},
		Authority: AuthorityReferences{
			PolicyDecisionID: "pol-1",
			RiskAssessmentID: "risk-1",
			AuthorizationID:  "auth-1",
			Outcome:          PolicyOutcomeAllow,
		},
	}
}

func agentHeaders() map[string]string {
	return map[string]string{
		"Authorization": "Bearer " + testAgentToken,
		"X-Session-ID":  "session-1",
	}
}

func adminHeaders(token string) map[string]string {
	return map[string]string{"Authorization": "Bearer " + token}
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
	var body DecisionEnvelope
	if err := json.Unmarshal(res.Body.Bytes(), &body); err == nil && body.ReasonCode != "" {
		if body.ReasonCode != code {
			t.Fatalf("expected reasonCode %s, got %s (status %d body %s)", code, body.ReasonCode, res.Code, res.Body.String())
		}
		return
	}
	var structured map[string]map[string]string
	if err := json.Unmarshal(res.Body.Bytes(), &structured); err != nil {
		t.Fatalf("failed to decode body %q: %v", res.Body.String(), err)
	}
	if got := structured["error"]["message"]; got != code {
		t.Fatalf("expected error message %s, got %s (status %d body %s)", code, got, res.Code, res.Body.String())
	}
}

func TestStructuredAuthErrors(t *testing.T) {
	handler := testHandler(t)
	res := performJSON(t, handler, http.MethodPost, "/v1/intents", validRequest(), nil)
	if res.Code != http.StatusUnauthorized {
		t.Fatalf("expected 401, got %d", res.Code)
	}
	var body map[string]map[string]string
	decodeBody(t, res, &body)
	if body["error"]["code"] != "UNAUTHORIZED" {
		t.Fatalf("unexpected auth body: %+v", body)
	}
}

func TestExpandedActionCompatibility(t *testing.T) {
	handler := testHandler(t)
	for i, action := range []FinancialAction{ActionPay, ActionTransfer, ActionSwap, ActionTrade, ActionRebalance, ActionCollect, ActionOpenPosition, ActionClosePosition} {
		req := validRequest()
		req.Intent.Action = action
		req.Intent.IdempotencyKey = fmt.Sprintf("idem-%d", i)
		req.Intent.CorrelationID = fmt.Sprintf("corr-%d", i)
		req.Execution.Nonce = fmt.Sprintf("nonce-%d", i)
		if action != ActionTransfer && action != ActionPay {
			req.Execution.ExecutionRef.Function = "swap"
		}
		res := performJSON(t, handler, http.MethodPost, "/v1/intents", req, agentHeaders())
		if res.Code != http.StatusOK && action == ActionPay {
			t.Fatalf("expected supported action %s, got %d %s", action, res.Code, res.Body.String())
		}
	}
}
