package main

import (
	"encoding/json"
	"errors"
	"log"
	"net/http"
	"os"
	"time"

	"github.com/ryvra-protocol/agent-gateway/internal/gateway"
)

func main() {
	cfg, addr, resolver, err := loadRuntime()
	if err != nil {
		log.Fatal(err)
	}
	repo, err := gateway.OpenSQLRepository(cfg.DatabaseURL)
	if err != nil {
		log.Fatal(err)
	}
	svc := gateway.NewService(cfg, repo, resolver)
	log.Printf("agent gateway listening on %s", addr)
	log.Fatal(http.ListenAndServe(addr, gateway.NewHandler(svc)))
}

func loadRuntime() (gateway.Config, string, gateway.PolicyRiskResolver, error) {
	cfg, addr, err := loadConfigFromEnv(os.Getenv)
	if err != nil {
		return gateway.Config{}, "", nil, err
	}
	resolver, err := loadResolverFromEnv(os.Getenv)
	if err != nil {
		return gateway.Config{}, "", nil, err
	}
	return cfg, addr, resolver, nil
}

func loadConfigFromEnv(getenv func(string) string) (gateway.Config, string, error) {
	databaseURL := getenv("DATABASE_URL")
	if databaseURL == "" {
		return gateway.Config{}, "", errors.New("DATABASE_URL is required")
	}
	adminWrite := getenv("ADMIN_WRITE_TOKEN")
	if adminWrite == "" {
		adminWrite = getenv("ADMIN_TOKEN")
	}
	if adminWrite == "" {
		return gateway.Config{}, "", errors.New("ADMIN_WRITE_TOKEN or ADMIN_TOKEN is required")
	}
	adminRead := getenv("ADMIN_READ_TOKEN")
	if adminRead == "" {
		adminRead = adminWrite
	}
	cfg := gateway.Config{
		AdminReadToken:     adminRead,
		AdminWriteToken:    adminWrite,
		KillSwitchToken:    fallback(getenv("KILLSWITCH_ADMIN_TOKEN"), adminWrite),
		ApprovalToken:      fallback(getenv("APPROVAL_ADMIN_TOKEN"), adminWrite),
		DatabaseURL:        databaseURL,
		ReplayWindow:       5 * time.Minute,
		RateLimitWindow:    time.Minute,
		DefaultRateLimit:   30,
		DefaultSpendLimit:  10000,
		DefaultReviewLimit: 1000,
	}
	addr := getenv("ADDR")
	if addr == "" {
		addr = ":8080"
	}
	return cfg, addr, nil
}

func loadResolverFromEnv(getenv func(string) string) (gateway.PolicyRiskResolver, error) {
	lookupsJSON := getenv("POLICY_RISK_LOOKUPS_JSON")
	if lookupsJSON == "" {
		return gateway.StaticPolicyRiskResolver{}, nil
	}
	lookups := map[string]gateway.AuthorityReferences{}
	if err := json.Unmarshal([]byte(lookupsJSON), &lookups); err != nil {
		return nil, err
	}
	return gateway.StaticPolicyRiskResolver{Lookups: lookups}, nil
}

func fallback(value, alternative string) string {
	if value != "" {
		return value
	}
	return alternative
}
