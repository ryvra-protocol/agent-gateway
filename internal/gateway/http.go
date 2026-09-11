package gateway

import (
	"encoding/json"
	"errors"
	"net/http"
	"strings"
	"time"
)

func NewHandler(service *Service, adminToken string) http.Handler {
	mux := http.NewServeMux()

	mux.HandleFunc("GET /healthz", func(w http.ResponseWriter, _ *http.Request) {
		writeJSON(w, http.StatusOK, map[string]string{"status": "ok"})
	})

	mux.HandleFunc("POST /v1/intents", func(w http.ResponseWriter, r *http.Request) {
		actor, err := authenticateRequest(service, r)
		if err != nil {
			writeError(w, err)
			return
		}

		var intent FinancialIntent
		if err := json.NewDecoder(r.Body).Decode(&intent); err != nil {
			writeJSON(w, http.StatusBadRequest, map[string]string{"error": "invalid JSON"})
			return
		}
		result, err := service.ProcessIntent(intent, actor, time.Now().UTC())
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
		adminActor, err := authenticateAdminRequest(service, r)
		if err != nil {
			writeError(w, err)
			return
		}
		switch action {
		case "approve":
			result, err := service.ApproveIntent(intentID, adminActor, time.Now().UTC())
			if err != nil {
				writeJSON(w, http.StatusBadRequest, map[string]string{"error": err.Error()})
				return
			}
			writeJSON(w, http.StatusOK, result)
		case "cancel":
			result, err := service.CancelIntent(intentID, adminActor, time.Now().UTC())
			if err != nil {
				writeJSON(w, http.StatusBadRequest, map[string]string{"error": err.Error()})
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
			writeJSON(w, http.StatusNotFound, map[string]string{"error": "intent not found"})
			return
		}
		writeJSON(w, http.StatusOK, record)
	})

	mux.HandleFunc("GET /v1/agents/", func(w http.ResponseWriter, r *http.Request) {
		agentID, action, ok := tailParts(strings.TrimPrefix(r.URL.Path, "/v1/agents/"))
		if !ok || action != "status" {
			http.NotFound(w, r)
			return
		}
		agent, found := service.GetAgentStatus(agentID)
		if !found {
			writeJSON(w, http.StatusNotFound, map[string]string{"error": "agent not found"})
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
		adminActor, err := authenticateAdminRequest(service, r)
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
			writeJSON(w, http.StatusBadRequest, map[string]string{"error": err.Error()})
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
		adminActor, err := authenticateAdminRequest(service, r)
		if err != nil {
			writeError(w, err)
			return
		}
		if err := service.RevokeCapability(capabilityID, adminActor, time.Now().UTC()); err != nil {
			writeJSON(w, http.StatusBadRequest, map[string]string{"error": err.Error()})
			return
		}
		writeJSON(w, http.StatusOK, map[string]string{"status": "ok"})
	})

	mux.HandleFunc("POST /v1/killswitch/activate", func(w http.ResponseWriter, r *http.Request) {
		adminActor, err := authenticateAdminRequest(service, r)
		if err != nil {
			writeError(w, err)
			return
		}
		service.ActivateKillSwitch(adminActor, time.Now().UTC())
		writeJSON(w, http.StatusOK, map[string]string{"status": "activated"})
	})

	mux.HandleFunc("POST /v1/killswitch/deactivate", func(w http.ResponseWriter, r *http.Request) {
		adminActor, err := authenticateAdminRequest(service, r)
		if err != nil {
			writeError(w, err)
			return
		}
		if r.Header.Get("X-High-Trust") != "true" {
			writeJSON(w, http.StatusForbidden, map[string]string{"error": "high trust path required"})
			return
		}
		service.DeactivateKillSwitch(adminActor, time.Now().UTC())
		writeJSON(w, http.StatusOK, map[string]string{"status": "deactivated"})
	})

	mux.HandleFunc("GET /v1/audit/events", func(w http.ResponseWriter, r *http.Request) {
		intentID := r.URL.Query().Get("intentId")
		writeJSON(w, http.StatusOK, service.AuditEvents(intentID))
	})

	return mux
}

func authenticateRequest(service *Service, r *http.Request) (authenticatedActor, error) {
	auth := strings.TrimPrefix(r.Header.Get("Authorization"), "Bearer ")
	return service.AuthenticateAgent(auth, r.Header.Get("X-Session-ID"), time.Now().UTC())
}

func authenticateAdminRequest(service *Service, r *http.Request) (authenticatedActor, error) {
	return service.AuthenticateAdmin(r.Header.Get("X-Admin-Token"))
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
		writeJSON(w, http.StatusUnauthorized, map[string]string{"error": "unauthorized"})
	case errors.Is(err, errForbidden):
		writeJSON(w, http.StatusForbidden, map[string]string{"error": "forbidden"})
	default:
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": err.Error()})
	}
}

func writeJSON(w http.ResponseWriter, status int, value interface{}) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(value)
}
