package license

import (
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

func TestServiceEnabled(t *testing.T) {
	svc := NewService([]string{"cloud-dspm", " ignored ", "UNKNOWN-FEATURE"})
	if !svc.Enabled(FeatureCloudDSPM) {
		t.Fatal("expected cloud-dspm to be enabled")
	}
	if svc.Enabled(Feature("not-listed")) {
		t.Fatal("expected an unlisted feature to be disabled")
	}
	if !svc.Enabled(Feature("ignored")) {
		t.Fatal("expected whitespace-trimmed name to be enabled")
	}
	if !svc.Enabled(Feature("unknown-feature")) {
		t.Fatal("expected names to be normalized to lowercase")
	}
	want := []string{"cloud-dspm", "ignored", "unknown-feature"}
	got := svc.FeatureNames()
	if len(got) != len(want) {
		t.Fatalf("unexpected feature names: %v", got)
	}
	for i := range want {
		if got[i] != want[i] {
			t.Fatalf("feature names not sorted as expected: %v", got)
		}
	}
}

func TestNilServiceIsLockedDown(t *testing.T) {
	var svc *Service
	if svc.Enabled(FeatureCloudDSPM) {
		t.Fatal("nil service must not enable any feature")
	}
}

func TestRequireFeatureAllowsEnabled(t *testing.T) {
	svc := NewService([]string{"cloud-dspm"})
	called := false
	h := RequireFeature(svc, FeatureCloudDSPM, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		called = true
		w.WriteHeader(http.StatusNoContent)
	}))

	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, httptest.NewRequest(http.MethodPost, "/", nil))

	if rec.Code != http.StatusNoContent {
		t.Fatalf("expected 204, got %d", rec.Code)
	}
	if !called {
		t.Fatal("wrapped handler was not invoked")
	}
}

func TestRequireFeatureRejectsDisabled(t *testing.T) {
	svc := NewService(nil)
	called := false
	h := RequireFeature(svc, FeatureCloudDSPM, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		called = true
	}))

	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, httptest.NewRequest(http.MethodPost, "/", nil))

	if rec.Code != http.StatusForbidden {
		t.Fatalf("expected 403, got %d", rec.Code)
	}
	if called {
		t.Fatal("wrapped handler must not be invoked for a disabled feature")
	}
	if body := rec.Body.String(); !strings.Contains(body, "feature_not_enabled") {
		t.Fatalf("unexpected body: %s", body)
	}
}

func TestRequireFeatureNilServiceRejects(t *testing.T) {
	h := RequireFeature(nil, FeatureCloudDSPM, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {}))
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, httptest.NewRequest(http.MethodPost, "/", nil))
	if rec.Code != http.StatusForbidden {
		t.Fatalf("expected 403, got %d", rec.Code)
	}
}