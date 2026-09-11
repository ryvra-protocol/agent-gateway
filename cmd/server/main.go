package main

import (
	"log"
	"net/http"
	"os"
	"time"

	"github.com/ryvra-protocol/agent-gateway/internal/gateway"
)

func main() {
	adminToken := os.Getenv("ADMIN_TOKEN")
	if adminToken == "" {
		adminToken = "admin-token"
	}

	svc := gateway.NewService(gateway.Config{
		AdminToken:         adminToken,
		ReplayWindow:       5 * time.Minute,
		RateLimitWindow:    time.Minute,
		DefaultRateLimit:   30,
		DefaultSpendLimit:  10000,
		DefaultReviewLimit: 1000,
	})

	svc.SeedAgent(gateway.Agent{
		ID:             "agent-demo",
		Status:         gateway.AgentStatusActive,
		RateLimit:      30,
		SpendLimit:     10000,
		ReviewLimit:    1000,
		AutonomyLevel:  gateway.AutonomyA2,
		SessionBinding: "session-demo",
	})
	svc.SeedCredential(gateway.AgentCredential{
		ID:        "cred-demo",
		AgentID:   "agent-demo",
		Token:     "agent-token",
		SessionID: "session-demo",
		ExpiresAt: time.Now().Add(time.Hour),
	})
	svc.SeedCapability(gateway.AgentCapability{
		ID:               "cap-demo",
		AgentID:          "agent-demo",
		AllowedActions:   []string{"TRANSFER", "BALANCE_CHECK"},
		AllowedAssets:    []string{"USD", "USDC"},
		AllowedChains:    []string{"solana"},
		AllowedContracts: []string{"treasury-vault"},
		AllowedFunctions: []string{"transfer", "balanceOf"},
		AutonomyLevel:    gateway.AutonomyA2,
		Status:           gateway.RecordStatusActive,
	})
	svc.SeedMandate(gateway.AgentMandate{
		ID:            "mandate-demo",
		AgentID:       "agent-demo",
		AutonomyLevel: gateway.AutonomyA2,
		Status:        gateway.RecordStatusActive,
		ExpiresAt:     time.Now().Add(24 * time.Hour),
	})

	addr := os.Getenv("ADDR")
	if addr == "" {
		addr = ":8080"
	}

	log.Printf("agent gateway listening on %s", addr)
	log.Fatal(http.ListenAndServe(addr, gateway.NewHandler(svc, adminToken)))
}
