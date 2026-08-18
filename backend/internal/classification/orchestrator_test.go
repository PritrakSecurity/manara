package classification

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"testing"
	"time"
)

func writeTempFile(t *testing.T, name, content string) string {
	t.Helper()
	path := filepath.Join(t.TempDir(), name)
	if err := os.WriteFile(path, []byte(content), 0644); err != nil {
		t.Fatalf("failed to write temp file: %v", err)
	}
	return path
}

// TestNoOpProviderAbstains verifies the default provider returns abstained
// with no findings.
func TestNoOpProviderAbstains(t *testing.T) {
	resp, err := NoOpProvider{}.Analyze(context.Background(), AnalysisRequest{RequestID: "req-1"})
	if err != nil {
		t.Fatalf("NoOpProvider returned error: %v", err)
	}
	if resp.Status != StatusAbstained {
		t.Fatalf("expected status abstained, got %q", resp.Status)
	}
	if len(resp.Findings) != 0 {
		t.Fatalf("expected no findings, got %d", len(resp.Findings))
	}
	if resp.RequestID != "req-1" {
		t.Fatalf("expected request id echoed, got %q", resp.RequestID)
	}
}

type sleepingProvider struct {
	delay time.Duration
}

func (p sleepingProvider) Analyze(ctx context.Context, req AnalysisRequest) (AnalysisResponse, error) {
	time.Sleep(p.delay)
	return AnalysisResponse{Status: StatusClassified}, nil
}

type erroringProvider struct {
	err error
}

func (p erroringProvider) Analyze(ctx context.Context, req AnalysisRequest) (AnalysisResponse, error) {
	return AnalysisResponse{}, p.err
}

// TestOrchestratorTimeout verifies a provider that exceeds the request
// deadline is mapped to timed_out.
func TestOrchestratorTimeout(t *testing.T) {
	o := NewOrchestrator(sleepingProvider{delay: 300 * time.Millisecond})

	resp, err := o.Execute(context.Background(), AnalysisRequest{Deadline: 50 * time.Millisecond})
	if err == nil {
		t.Fatal("expected error for timed out provider")
	}
	if resp.Status != StatusTimedOut {
		t.Fatalf("expected status timed_out, got %q", resp.Status)
	}
}

// TestOrchestratorUnavailable verifies a provider failure is mapped to
// unavailable.
func TestOrchestratorUnavailable(t *testing.T) {
	o := NewOrchestrator(erroringProvider{err: errors.New("connection refused")})

	resp, err := o.Execute(context.Background(), AnalysisRequest{})
	if err == nil {
		t.Fatal("expected error for unreachable provider")
	}
	if resp.Status != StatusUnavailable {
		t.Fatalf("expected status unavailable, got %q", resp.Status)
	}
	if len(resp.Findings) != 0 {
		t.Fatalf("expected no findings from failed provider, got %d", len(resp.Findings))
	}
}

type verdictProvider struct{}

func (verdictProvider) Analyze(ctx context.Context, req AnalysisRequest) (AnalysisResponse, error) {
	return AnalysisResponse{Status: StatusClassified, Metadata: map[string]interface{}{"block": true}}, nil
}

// TestValidateResponseRejectsForbiddenVerdict verifies responses carrying a
// forbidden verdict key are rejected.
func TestValidateResponseRejectsForbiddenVerdict(t *testing.T) {
	for _, key := range []string{"allow", "deny", "block", "quarantine", "enforcement_action", "policy_decision"} {
		t.Run(key, func(t *testing.T) {
			resp := AnalysisResponse{Metadata: map[string]interface{}{key: true}}
			if err := ValidateResponse(resp); err == nil {
				t.Fatalf("expected forbidden verdict key %q to be rejected", key)
			}
		})
	}

	if err := ValidateResponse(AnalysisResponse{}); err != nil {
		t.Fatalf("expected clean response to pass validation, got %v", err)
	}
	benign := AnalysisResponse{Metadata: map[string]interface{}{"confidence_bucket": "high"}}
	if err := ValidateResponse(benign); err != nil {
		t.Fatalf("expected benign metadata to pass validation, got %v", err)
	}
}

// TestOrchestratorRejectsVerdictResponse verifies the orchestrator returns
// invalid_input when the provider ships a forbidden verdict field.
func TestOrchestratorRejectsVerdictResponse(t *testing.T) {
	o := NewOrchestrator(verdictProvider{})

	resp, err := o.Execute(context.Background(), AnalysisRequest{})
	if err == nil {
		t.Fatal("expected error for verdict-bearing response")
	}
	if resp.Status != StatusInvalidInput {
		t.Fatalf("expected status invalid_input, got %q", resp.Status)
	}
}

type unavailableProvider struct{}

func (unavailableProvider) Analyze(ctx context.Context, req AnalysisRequest) (AnalysisResponse, error) {
	return AnalysisResponse{}, errors.New("provider unreachable")
}

// TestEnginePreservesHardFindingsOnProviderFailure verifies the engine keeps
// its deterministic hard findings and continues to Phase 4 when the Phase 2.5
// provider is unavailable.
func TestEnginePreservesHardFindingsOnProviderFailure(t *testing.T) {
	ce := NewClassificationEngine()
	ce.SetOrchestrator(NewOrchestrator(unavailableProvider{}))

	// Score 55 (25 SSN + 15 confidential + 15 salary) -> within the 50-90
	// Phase 2.5 window.
	path := writeTempFile(t, "test.txt", "confidential salary 123-45-6789")

	result := ce.Classify(path)

	if result.Classification != "CONFIDENTIAL" {
		t.Fatalf("expected engine to continue to Phase 4, got classification %q", result.Classification)
	}

	var found bool
	for _, f := range result.Findings {
		if f.Type == "ssn" && f.HardEvidence && f.EvidenceStrength == EvidenceHardValidated {
			found = true
		}
	}
	if !found {
		t.Fatalf("hard SSN finding was not preserved: %+v", result.Findings)
	}
}

// TestEngineDefaultProviderAbstains verifies the default NoOp-backed engine
// still preserves hard deterministic findings.
func TestEngineDefaultProviderAbstains(t *testing.T) {
	ce := NewClassificationEngine()
	path := writeTempFile(t, "test.txt", "confidential salary 123-45-6789")

	result := ce.Classify(path)

	var found bool
	for _, f := range result.Findings {
		if f.Type == "ssn" && f.HardEvidence {
			found = true
		}
	}
	if !found {
		t.Fatalf("hard SSN finding missing with default provider: %+v", result.Findings)
	}
}
