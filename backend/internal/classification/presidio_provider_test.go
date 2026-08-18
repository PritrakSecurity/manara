package classification

import (
	"context"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"
)

// TestPresidioProviderMapsFindings verifies a successful Presidio response is
// mapped to Findings with contextual evidence.
func TestPresidioProviderMapsFindings(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/analyze" {
			t.Errorf("unexpected path: %s", r.URL.Path)
		}
		w.Header().Set("Content-Type", "application/json")
		w.Write([]byte(`[
			{"entity_type":"PERSON","start":0,"end":4,"score":0.9,"text":"John"},
			{"entity_type":"CREDIT_CARD","start":10,"end":26,"score":0.85,"text":"4111111111111111"}
		]`))
	}))
	defer srv.Close()

	p := NewPresidioProvider(srv.URL, srv.Client(), 5*time.Second)
	resp, err := p.Analyze(context.Background(), AnalysisRequest{
		BoundedContext: "John pays 4111111111111111",
		LanguageHint:   "en",
	})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if resp.Status != StatusClassified {
		t.Fatalf("expected status classified, got %q", resp.Status)
	}
	if len(resp.Findings) != 2 {
		t.Fatalf("expected 2 findings, got %d", len(resp.Findings))
	}

	person := resp.Findings[0]
	if person.Type != "PERSON" || person.Confidence != 0.9 ||
		person.EvidenceStrength != EvidenceContextual || person.HardEvidence ||
		person.StartOffset != 0 || person.EndOffset != 4 || person.Status != StatusClassified {
		t.Fatalf("PERSON finding not mapped correctly: %+v", person)
	}
}

// TestPresidioProviderTimeout verifies a provider that exceeds the configured
// timeout maps to timed_out.
func TestPresidioProviderTimeout(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		time.Sleep(300 * time.Millisecond)
	}))
	defer srv.Close()

	p := NewPresidioProvider(srv.URL, srv.Client(), 50*time.Millisecond)
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

// TestPresidioProviderUnavailable verifies an unreachable provider maps to
// unavailable.
func TestPresidioProviderUnavailable(t *testing.T) {
	p := NewPresidioProvider("http://127.0.0.1:1", &http.Client{Timeout: 500 * time.Millisecond}, 500*time.Millisecond)
	resp, err := p.Analyze(context.Background(), AnalysisRequest{BoundedContext: "hello"})
	if err == nil {
		t.Fatal("expected error for unreachable provider")
	}
	if resp.Status != StatusUnavailable {
		t.Fatalf("expected status unavailable, got %q", resp.Status)
	}
}

// TestPresidioProviderNoRawTextInErrors verifies raw bounded context never
// leaks into returned errors, even when the server echoes it back.
func TestPresidioProviderNoRawTextInErrors(t *testing.T) {
	secret := "secret-bounded-content-987654"
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusInternalServerError)
		w.Write([]byte("provider exploded: " + secret))
	}))
	defer srv.Close()

	p := NewPresidioProvider(srv.URL, srv.Client(), time.Second)
	_, err := p.Analyze(context.Background(), AnalysisRequest{BoundedContext: secret})
	if err == nil {
		t.Fatal("expected error from failing provider")
	}
	if strings.Contains(err.Error(), secret) {
		t.Fatalf("raw content leaked into error message: %v", err)
	}
}

// TestPresidioProviderInvalidJSON verifies an unparseable response maps to
// unavailable with a sanitized error.
func TestPresidioProviderInvalidJSON(t *testing.T) {
	secret := "unparseable-content-112233"
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		w.Write([]byte("not json: " + secret))
	}))
	defer srv.Close()

	p := NewPresidioProvider(srv.URL, srv.Client(), time.Second)
	resp, err := p.Analyze(context.Background(), AnalysisRequest{BoundedContext: secret})
	if err == nil {
		t.Fatal("expected error for unparseable response")
	}
	if resp.Status != StatusUnavailable {
		t.Fatalf("expected status unavailable, got %q", resp.Status)
	}
	if strings.Contains(err.Error(), secret) {
		t.Fatalf("raw content leaked into error message: %v", err)
	}
}
