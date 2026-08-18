package config

import (
	"strings"
	"testing"
)

func TestLoadFromEnvSemanticClassifier(t *testing.T) {
	t.Setenv("JWT_SECRET", "test-secret")

	t.Run("default is disabled with default timeout", func(t *testing.T) {
		t.Setenv("SEMANTIC_CLASSIFIER_MODE", "")
		t.Setenv("SEMANTIC_CLASSIFIER_URL", "")
		t.Setenv("SEMANTIC_CLASSIFIER_TIMEOUT_MS", "")
		cfg, err := LoadFromEnv()
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		if cfg.SemanticClassifierMode != "disabled" {
			t.Fatalf("expected mode disabled, got %q", cfg.SemanticClassifierMode)
		}
		if cfg.SemanticClassifierTimeoutMs != 2000 {
			t.Fatalf("expected default timeout 2000, got %d", cfg.SemanticClassifierTimeoutMs)
		}
	})

	t.Run("shadow mode with url accepted", func(t *testing.T) {
		t.Setenv("SEMANTIC_CLASSIFIER_MODE", "shadow")
		t.Setenv("SEMANTIC_CLASSIFIER_URL", "http://classifier:8080")
		cfg, err := LoadFromEnv()
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		if cfg.SemanticClassifierMode != "shadow" {
			t.Fatalf("expected mode shadow, got %q", cfg.SemanticClassifierMode)
		}
		if cfg.SemanticClassifierURL != "http://classifier:8080" {
			t.Fatalf("expected url to be parsed, got %q", cfg.SemanticClassifierURL)
		}
	})

	t.Run("unsupported mode rejected", func(t *testing.T) {
		t.Setenv("SEMANTIC_CLASSIFIER_MODE", "production")
		_, err := LoadFromEnv()
		if err == nil {
			t.Fatal("expected error for unsupported mode")
		}
		if !strings.Contains(err.Error(), "SEMANTIC_CLASSIFIER_MODE") {
			t.Fatalf("expected error to mention the offending variable, got %v", err)
		}
	})

	t.Run("custom timeout parsed", func(t *testing.T) {
		t.Setenv("SEMANTIC_CLASSIFIER_MODE", "disabled")
		t.Setenv("SEMANTIC_CLASSIFIER_TIMEOUT_MS", "3500")
		cfg, err := LoadFromEnv()
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		if cfg.SemanticClassifierTimeoutMs != 3500 {
			t.Fatalf("expected timeout 3500, got %d", cfg.SemanticClassifierTimeoutMs)
		}
	})
}
