package main

import "testing"

func TestLoadConfigFromEnvFailsWhenRequiredSecretsMissing(t *testing.T) {
	_, _, err := loadConfigFromEnv(func(string) string { return "" })
	if err == nil {
		t.Fatal("expected missing env error")
	}

	_, _, err = loadConfigFromEnv(func(key string) string {
		if key == "DATABASE_URL" {
			return "file:test.db"
		}
		return ""
	})
	if err == nil {
		t.Fatal("expected missing admin token error")
	}
}

func TestLoadConfigFromEnvUsesScopedFallbacks(t *testing.T) {
	cfg, addr, err := loadConfigFromEnv(func(key string) string {
		switch key {
		case "DATABASE_URL":
			return "file:test.db"
		case "ADMIN_TOKEN":
			return "admin-token"
		case "ADDR":
			return ":9090"
		default:
			return ""
		}
	})
	if err != nil {
		t.Fatal(err)
	}
	if cfg.AdminReadToken != "admin-token" || cfg.AdminWriteToken != "admin-token" || cfg.KillSwitchToken != "admin-token" || cfg.ApprovalToken != "admin-token" {
		t.Fatalf("unexpected config: %+v", cfg)
	}
	if addr != ":9090" {
		t.Fatalf("unexpected addr %s", addr)
	}
}
