package gateway

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"strings"
	"time"
)

func NewHandler(service *Service) http.Handler {
	mux := http.NewServeMux()

	mux.HandleFunc("GET /healthz", func(w http.ResponseWriter, _ *http.Request) {
		writeJSON(w, http.StatusOK, map[string]string{"status": "ok"})
	})

	mux.HandleFunc("POST /v1/intents", func(w http.ResponseWriter, r *http.Request) {
		actor, err := authenticateAgentRequest(service, r)
		if err != nil {
			writeError(w, err)
			return
		}
		req, err := decodeSubmitIntentRequest(r.Body)
		if err != nil {
			writeJSON(w, http.StatusBadRequest, structuredError("INVALID_REQUEST", err.Error()))
			return
		}
		result, err := service.ProcessIntent(req, actor, time.Now().UTC())
		if err != nil {
			writeError(w, err)
			return
		}
		status := http.StatusOK
		if result.Decision == DecisionDenied || result.Decision == DecisionBlocked || result.Decision == DecisionQuarantine {
			status = http.StatusForbidden
		}
		writeJSON(w, status, result)
	})

	mux.HandleFunc("POST /v1/intents/", func(w http.ResponseWriter, r *http.Request) {
		intentID, action, ok := tailParts(strings.TrimPrefix(r.URL.Path, "/v1/intents/"))
		if !ok {
			http.NotFound(w, r)
			return
		}
		scope := "write"
		if action == "approve" {
			scope = "approval"
		}
		adminActor, err := authenticateAdminRequest(service, r, scope)
		if err != nil {
			writeError(w, err)
			return
		}
		switch action {
		case "approve":
			result, err := service.ApproveIntent(intentID, adminActor, time.Now().UTC())
			if err != nil {
				writeJSON(w, http.StatusBadRequest, structuredError("INVALID_STATE", err.Error()))
				return
			}
			writeJSON(w, http.StatusOK, result)
		case "cancel":
			result, err := service.CancelIntent(intentID, adminActor, time.Now().UTC())
			if err != nil {
				writeJSON(w, http.StatusBadRequest, structuredError("INVALID_STATE", err.Error()))
				return
			}
			writeJSON(w, http.StatusOK, result)
		default:
			http.NotFound(w, r)
		}
	})

	mux.HandleFunc("GET /v1/intents/", func(w http.ResponseWriter, r *http.Request) {
		intentID := strings.TrimPrefix(r.URL.Path, "/v1/intents/")
		record, ok := service.GetIntent(intentID)
		if !ok {
			writeJSON(w, http.StatusNotFound, structuredError("NOT_FOUND", "intent not found"))
			return
		}
		writeJSON(w, http.StatusOK, envelope(record))
	})

	mux.HandleFunc("GET /v1/agents/", func(w http.ResponseWriter, r *http.Request) {
		agentID, action, ok := tailParts(strings.TrimPrefix(r.URL.Path, "/v1/agents/"))
		if !ok || action != "status" {
			http.NotFound(w, r)
			return
		}
		if _, err := authenticateAdminRequest(service, r, "read"); err != nil {
			writeError(w, err)
			return
		}
		agent, found := service.GetAgentStatus(agentID)
		if !found {
			writeJSON(w, http.StatusNotFound, structuredError("NOT_FOUND", "agent not found"))
			return
		}
		writeJSON(w, http.StatusOK, agent)
	})

	mux.HandleFunc("POST /v1/agents/", func(w http.ResponseWriter, r *http.Request) {
		agentID, action, ok := tailParts(strings.TrimPrefix(r.URL.Path, "/v1/agents/"))
		if !ok {
			http.NotFound(w, r)
			return
		}
		adminActor, err := authenticateAdminRequest(service, r, "write")
		if err != nil {
			writeError(w, err)
			return
		}
		switch action {
		case "suspend":
			err = service.SuspendAgent(agentID, adminActor, time.Now().UTC())
		case "revoke-credentials":
			err = service.RevokeAgentCredentials(agentID, adminActor, time.Now().UTC())
		default:
			http.NotFound(w, r)
			return
		}
		if err != nil {
			writeJSON(w, http.StatusBadRequest, structuredError("INVALID_REQUEST", err.Error()))
			return
		}
		writeJSON(w, http.StatusOK, map[string]string{"status": "ok"})
	})

	mux.HandleFunc("POST /v1/capabilities/", func(w http.ResponseWriter, r *http.Request) {
		capabilityID, action, ok := tailParts(strings.TrimPrefix(r.URL.Path, "/v1/capabilities/"))
		if !ok || action != "revoke" {
			http.NotFound(w, r)
			return
		}
		adminActor, err := authenticateAdminRequest(service, r, "write")
		if err != nil {
			writeError(w, err)
			return
		}
		if err := service.RevokeCapability(capabilityID, adminActor, time.Now().UTC()); err != nil {
			writeJSON(w, http.StatusBadRequest, structuredError("INVALID_REQUEST", err.Error()))
			return
		}
		writeJSON(w, http.StatusOK, map[string]string{"status": "ok"})
	})

	mux.HandleFunc("POST /v1/killswitch/activate", func(w http.ResponseWriter, r *http.Request) {
		adminActor, err := authenticateAdminRequest(service, r, "killswitch")
		if err != nil {
			writeError(w, err)
			return
		}
		if err := service.ActivateKillSwitch(adminActor, time.Now().UTC()); err != nil {
			writeJSON(w, http.StatusBadRequest, structuredError("INVALID_REQUEST", err.Error()))
			return
		}
		writeJSON(w, http.StatusOK, map[string]string{"status": "activated"})
	})

	mux.HandleFunc("POST /v1/killswitch/deactivate", func(w http.ResponseWriter, r *http.Request) {
		adminActor, err := authenticateAdminRequest(service, r, "killswitch")
		if err != nil {
			writeError(w, err)
			return
		}
		if r.Header.Get("X-High-Trust") != "true" {
			writeJSON(w, http.StatusForbidden, structuredError("FORBIDDEN", "high trust path required"))
			return
		}
		if err := service.DeactivateKillSwitch(adminActor, time.Now().UTC()); err != nil {
			writeJSON(w, http.StatusBadRequest, structuredError("INVALID_REQUEST", err.Error()))
			return
		}
		writeJSON(w, http.StatusOK, map[string]string{"status": "deactivated"})
	})

	mux.HandleFunc("GET /v1/audit/events", func(w http.ResponseWriter, r *http.Request) {
		if _, err := authenticateAdminRequest(service, r, "read"); err != nil {
			writeError(w, err)
			return
		}
		intentID := r.URL.Query().Get("intentId")
		writeJSON(w, http.StatusOK, service.AuditEvents(intentID))
	})

	return mux
}

func authenticateAgentRequest(service *Service, r *http.Request) (authenticatedActor, error) {
	token, err := bearerToken(r.Header.Get("Authorization"))
	if err != nil {
		return authenticatedActor{}, errUnauthorized
	}
	return service.AuthenticateAgent(token, r.Header.Get("X-Session-ID"), time.Now().UTC())
}

func authenticateAdminRequest(service *Service, r *http.Request, scope string) (authenticatedActor, error) {
	token, err := bearerToken(r.Header.Get("Authorization"))
	if err != nil {
		return authenticatedActor{}, errUnauthorized
	}
	return service.AuthenticateAdmin(token, scope)
}

func bearerToken(header string) (string, error) {
	parts := strings.SplitN(header, " ", 2)
	if len(parts) != 2 || parts[0] != "Bearer" || strings.TrimSpace(parts[1]) == "" {
		return "", errUnauthorized
	}
	return strings.TrimSpace(parts[1]), nil
}

func tailParts(path string) (string, string, bool) {
	parts := strings.Split(strings.Trim(path, "/"), "/")
	if len(parts) != 2 {
		return "", "", false
	}
	return parts[0], parts[1], true
}

func writeError(w http.ResponseWriter, err error) {
	switch {
	case errors.Is(err, errUnauthorized):
		writeJSON(w, http.StatusUnauthorized, structuredError("UNAUTHORIZED", "authentication required"))
	case errors.Is(err, errForbidden):
		writeJSON(w, http.StatusForbidden, structuredError("FORBIDDEN", "request forbidden"))
	default:
		writeJSON(w, http.StatusBadRequest, structuredError("INVALID_REQUEST", err.Error()))
	}
}

func structuredError(code, message string) map[string]interface{} {
	return map[string]interface{}{
		"error": map[string]string{
			"code":    code,
			"message": message,
		},
	}
}

func writeJSON(w http.ResponseWriter, status int, value interface{}) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(value)
}

func decodeSubmitIntentRequest(body io.Reader) (SubmitIntentRequest, error) {
	payload, err := io.ReadAll(body)
	if err != nil {
		return SubmitIntentRequest{}, err
	}
	payload = bytes.TrimSpace(payload)
	if len(payload) == 0 {
		return SubmitIntentRequest{}, fmt.Errorf("request body is required")
	}
	var raw struct {
		Intent         *FinancialIntent       `json:"intent"`
		Execution      *ExecutionHints        `json:"execution"`
		Authority      *AuthorityReferences   `json:"authority"`
		Metadata       map[string]interface{} `json:"metadata"`
		IntentID       string                 `json:"intentId"`
		ActorType      ActorType              `json:"actorType"`
		ActorID        string                 `json:"actorId"`
		Action         FinancialAction        `json:"action"`
		AssetID        string                 `json:"assetId"`
		Amount         *float64               `json:"amount"`
		ChainID        string                 `json:"chainId"`
		Recipient      string                 `json:"recipient"`
		Venue          string                 `json:"venue"`
		Purpose        string                 `json:"purpose"`
		MandateID      string                 `json:"mandateId"`
		PolicyVersion  string                 `json:"policyVersion"`
		CorrelationID  string                 `json:"correlationId"`
		IdempotencyKey string                 `json:"idempotencyKey"`
		ExpiresAt      time.Time              `json:"expiresAt"`
		AgentID        string                 `json:"agentId"`
		CapabilityID   string                 `json:"capabilityId"`
		Nonce          string                 `json:"nonce"`
		AutonomyLevel  AutonomyLevel          `json:"autonomyLevel"`
		ExecutionRef   ExecutionContextRef    `json:"executionRef"`
		Asset          string                 `json:"asset"`
		Chain          string                 `json:"chain"`
		Contract       string                 `json:"contract"`
		Function       string                 `json:"function"`
		PolicyBinding  PolicyBinding          `json:"policyBinding"`
		RiskLinkage    RiskLinkage            `json:"riskLinkage"`
	}
	decoder := json.NewDecoder(bytes.NewReader(payload))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(&raw); err != nil {
		return SubmitIntentRequest{}, err
	}
	req := SubmitIntentRequest{Metadata: raw.Metadata}
	if raw.Intent != nil {
		req.Intent = *raw.Intent
	}
	if raw.Execution != nil {
		req.Execution = *raw.Execution
	}
	if raw.Authority != nil {
		req.Authority = *raw.Authority
	}
	apply := func(current *string, legacy, canonical, warning string) error {
		if canonical != "" {
			*current = canonical
		}
		if legacy == "" {
			return nil
		}
		if *current != "" && *current != legacy {
			return fmt.Errorf("legacy field conflict for %s", warning)
		}
		*current = legacy
		req.DeprecationWarnings = append(req.DeprecationWarnings, warning)
		return nil
	}
	if req.Intent.IntentID == "" {
		req.Intent.IntentID = raw.IntentID
	}
	if req.Intent.ActorType == "" {
		req.Intent.ActorType = raw.ActorType
	}
	if req.Intent.ActorID == "" {
		req.Intent.ActorID = raw.ActorID
	}
	if req.Intent.Action == "" {
		req.Intent.Action = raw.Action
	}
	if req.Intent.AssetID == "" {
		req.Intent.AssetID = raw.AssetID
	}
	if req.Intent.Amount == nil {
		req.Intent.Amount = raw.Amount
	}
	if req.Intent.ChainID == "" {
		req.Intent.ChainID = raw.ChainID
	}
	if req.Intent.Recipient == "" {
		req.Intent.Recipient = raw.Recipient
	}
	if req.Intent.Venue == "" {
		req.Intent.Venue = raw.Venue
	}
	if req.Intent.Purpose == "" {
		req.Intent.Purpose = raw.Purpose
	}
	if req.Intent.MandateID == "" {
		req.Intent.MandateID = raw.MandateID
	}
	if req.Intent.PolicyVersion == "" {
		req.Intent.PolicyVersion = raw.PolicyVersion
	}
	if req.Intent.CorrelationID == "" {
		req.Intent.CorrelationID = raw.CorrelationID
	}
	if req.Intent.IdempotencyKey == "" {
		req.Intent.IdempotencyKey = raw.IdempotencyKey
	}
	if req.Intent.ExpiresAt.IsZero() {
		req.Intent.ExpiresAt = raw.ExpiresAt
	}
	if req.Execution.AgentID == "" {
		req.Execution.AgentID = raw.AgentID
	}
	if req.Execution.CapabilityID == "" {
		req.Execution.CapabilityID = raw.CapabilityID
	}
	if req.Execution.Nonce == "" {
		req.Execution.Nonce = raw.Nonce
	}
	if req.Execution.AutonomyLevel == "" {
		req.Execution.AutonomyLevel = raw.AutonomyLevel
	}
	if req.Execution.ExecutionRef == (ExecutionContextRef{}) {
		req.Execution.ExecutionRef = raw.ExecutionRef
	}
	if err := apply(&req.Intent.AssetID, raw.Asset, req.Intent.AssetID, "legacy field 'asset' is deprecated; use intent.assetId"); err != nil {
		return SubmitIntentRequest{}, err
	}
	if err := apply(&req.Intent.ChainID, raw.Chain, req.Intent.ChainID, "legacy field 'chain' is deprecated; use intent.chainId"); err != nil {
		return SubmitIntentRequest{}, err
	}
	if err := apply(&req.Execution.ExecutionRef.Contract, raw.Contract, req.Execution.ExecutionRef.Contract, "legacy field 'contract' is deprecated; use execution.executionRef.contract"); err != nil {
		return SubmitIntentRequest{}, err
	}
	if err := apply(&req.Execution.ExecutionRef.Function, raw.Function, req.Execution.ExecutionRef.Function, "legacy field 'function' is deprecated; use execution.executionRef.function"); err != nil {
		return SubmitIntentRequest{}, err
	}
	if req.Intent.PolicyVersion == "" && raw.PolicyBinding.Version != "" {
		req.Intent.PolicyVersion = raw.PolicyBinding.Version
		req.DeprecationWarnings = append(req.DeprecationWarnings, "legacy field 'policyBinding.version' is deprecated; use intent.policyVersion")
	}
	if req.Authority.PolicyDecisionID == "" && raw.PolicyBinding.DecisionRef != "" {
		req.Authority.PolicyDecisionID = raw.PolicyBinding.DecisionRef
		req.DeprecationWarnings = append(req.DeprecationWarnings, "legacy field 'policyBinding.decisionRef' is deprecated; use authority.policyDecisionId")
	}
	if req.Authority.RiskAssessmentID == "" && raw.RiskLinkage.Reference != "" {
		req.Authority.RiskAssessmentID = raw.RiskLinkage.Reference
		req.DeprecationWarnings = append(req.DeprecationWarnings, "legacy field 'riskLinkage.reference' is deprecated; use authority.riskAssessmentId")
	}
	if raw.RiskLinkage.Score > 0 {
		req.DeprecationWarnings = append(req.DeprecationWarnings, "legacy field 'riskLinkage.score' is deprecated and ignored; authoritative policy outcomes are required")
	}
	return req, nil
}
