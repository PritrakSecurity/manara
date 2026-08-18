package classification

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"
)

// TestSemanticProviderMapsFindings verifies a successful semantic response is
// mapped to findings with ShadowOnly forced on.
func TestSemanticProviderMapsFindings(t *testing.T) {
	finding := Finding{
		Type:             "credential",
		Detector:         "semantic",
		Confidence:       0.7,
		EvidenceStrength: EvidenceContextual,
		StartOffset:      5,
		EndOffset:        20,
	}
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/classify" {
			t.Errorf("unexpected path: %s", r.URL.Path)
		}
		var req SemanticRequest
		if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
			t.Errorf("failed to decode request: %v", err)
			return
		}
		if req.ContractVersion != "v1" {
			t.Errorf("expected contract v1, got %q", req.ContractVersion)
		}
		if !strings.Contains(req.BoundedContext, "credential") {
			t.Errorf("expected bounded context in request, got %q", req.BoundedContext)
		}
		resp := SemanticResponse{
			ContractVersion: "v1",
			RequestID:       "req-1",
			Status:          StatusClassified,
			Findings:        []Finding{finding},
		}
		json.NewEncoder(w).Encode(resp)
	}))
	defer srv.Close()

	p := NewSemanticProvider(srv.URL, srv.Client(), 5*time.Second)
	resp, err := p.Analyze(context.Background(), AnalysisRequest{
		RequestID:      "req-1",
		BoundedContext: "credential in file",
	})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if resp.Status != StatusClassified {
		t.Fatalf("expected status classified, got %q", resp.Status)
	}
	if len(resp.Findings) != 1 {
		t.Fatalf("expected 1 finding, got %d", len(resp.Findings))
	}
	f := resp.Findings[0]
	if !f.ShadowOnly {
		t.Fatalf("semantic finding must be shadow-only: %+v", f)
	}
	if f.Type != "credential" || f.Confidence != 0.7 ||
		f.EvidenceStrength != EvidenceContextual || f.StartOffset != 5 || f.EndOffset != 20 {
		t.Fatalf("finding not mapped correctly: %+v", f)
	}
}

// TestSemanticProviderTimeout verifies a provider that exceeds the configured
// timeout maps to timed_out.
func TestSemanticProviderTimeout(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		time.Sleep(300 * time.Millisecond)
	}))
	defer srv.Close()

	p := NewSemanticProvider(srv.URL, srv.Client(), 50*time.Millisecond)
	resp, err := p.Analyze(context.Background(), AnalysisRequest{BoundedContext: "hello"})
	if err == nil {
		t.Fatal("expected error for timed out provider")
	}
	if resp.Status != StatusTimedOut {
		t.Fatalf("expected status timed_out, got %q", resp.Status)
	}
	if len(resp.Findings) != 0 {
		t.Fatalf("expected no findings on timeout, got %d", len(resp.Findings))
	}
}

// TestSemanticProviderUnavailable verifies an unreachable provider maps to
// unavailable.
func TestSemanticProviderUnavailable(t *testing.T) {
	p := NewSemanticProvider("http://127.0.0.1:1", &http.Client{Timeout: 500 * time.Millisecond}, 500*time.Millisecond)
	resp, err := p.Analyze(context.Background(), AnalysisRequest{BoundedContext: "hello"})
	if err == nil {
		t.Fatal("expected error for unreachable provider")
	}
	if resp.Status != StatusUnavailable {
		t.Fatalf("expected status unavailable, got %q", resp.Status)
	}
}

// TestSemanticProviderNoRawTextInErrors verifies raw bounded context never
// leaks into returned errors, even when the server echoes it back.
func TestSemanticProviderNoRawTextInErrors(t *testing.T) {
	secret := "secret-shadow-content-24680"
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusInternalServerError)
		w.Write([]byte("provider exploded: " + secret))
	}))
	defer srv.Close()

	p := NewSemanticProvider(srv.URL, srv.Client(), time.Second)
	_, err := p.Analyze(context.Background(), AnalysisRequest{BoundedContext: secret})
	if err == nil {
		t.Fatal("expected error from failing provider")
	}
	if strings.Contains(err.Error(), secret) {
		t.Fatalf("raw content leaked into error message: %v", err)
	}
}

// TestSemanticShadowCannotDowngradeHard verifies that even when a semantic
// provider returns a shadow finding that conflicts with a hard deterministic
// finding, MergeFindings preserves the hard finding and ignores the shadow
// finding's attempt to downgrade it.
func TestSemanticShadowCannotDowngradeHard(t *testing.T) {
	hard := Finding{
		ID:               "det-ssn-1",
		Type:             "ssn",
		Detector:         "ssn_validator",
		Confidence:       1.0,
		EvidenceStrength: EvidenceHardValidated,
		HardEvidence:     true,
		Status:           StatusClassified,
	}

	shadow := Finding{
		ID:               "det-ssn-1",
		Type:             "ssn",
		Detector:         "semantic",
		Confidence:       0.2,
		EvidenceStrength: EvidenceWeakHeuristic,
		ShadowOnly:       true,
		Status:           StatusClassified,
	}

	merged := MergeFindings([]Finding{hard}, []Finding{shadow})

	if len(merged) != 1 {
		t.Fatalf("expected 1 merged finding, got %d", len(merged))
	}
	if !merged[0].HardEvidence {
		t.Fatalf("hard finding lost its HardEvidence flag: %+v", merged[0])
	}
	if merged[0].Confidence != 1.0 {
		t.Fatalf("shadow finding downgraded hard confidence to %v, want 1.0", merged[0].Confidence)
	}
	if merged[0].EvidenceStrength != EvidenceHardValidated {
		t.Fatalf("shadow finding downgraded hard evidence to %q, want %q", merged[0].EvidenceStrength, EvidenceHardValidated)
	}
}

// TestEngineShadowProviderFindings verifies end-to-end that semantic shadow
// findings are merged into the engine result with ShadowOnly set while
// deterministic findings are preserved.
func TestEngineShadowProviderFindings(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		resp := SemanticResponse{
			ContractVersion: "v1",
			Status:          StatusClassified,
			Findings: []Finding{{
				Type:             "credential",
				Detector:         "semantic",
				Confidence:       0.6,
				EvidenceStrength: EvidenceContextual,
				StartOffset:      0,
				EndOffset:        8,
			}},
		}
		json.NewEncoder(w).Encode(resp)
	}))
	defer srv.Close()

	ce := NewEngineWithProvider(NewSemanticProvider(srv.URL, srv.Client(), 5*time.Second))

	// Score 80 (mysql:// connection string) -> within the 50-90 Phase 2.5 window.
	path := writeTempFile(t, "config.txt", "mysql://root:root@prod-db.internal:3306/prod")

	result := ce.Classify(path)

	var shadowFound bool
	var deterministicFound bool
	for _, f := range result.Findings {
		if f.ShadowOnly && f.Type == "credential" {
			shadowFound = true
		}
		if f.Type == "secret" && f.Category == "db_connection_string" && !f.ShadowOnly {
			deterministicFound = true
		}
	}
	if !shadowFound {
		t.Fatalf("expected shadow finding in engine result: %+v", result.Findings)
	}
	if !deterministicFound {
		t.Fatalf("expected deterministic finding preserved: %+v", result.Findings)
	}
}
