package api

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/aws/smithy-go"

	"manara-dlp/internal/dspm/cloud"
	"manara-dlp/internal/dspm/cloud/aws"
	"manara-dlp/internal/license"
)

// fakeCloudConnector is a deterministic cloud.Connector for handler tests.
type fakeCloudConnector struct {
	mu            sync.Mutex
	validateErr   error
	postureResult cloud.ScanResult
	contentResult cloud.ScanResult
	postureCalls  int
	contentCalls  int
}

func (f *fakeCloudConnector) ID() string                    { return "aws-s3" }
func (f *fakeCloudConnector) Kind() string                  { return cloud.ProviderAWS }
func (f *fakeCloudConnector) Validate(context.Context) error { return f.validateErr }

func (f *fakeCloudConnector) ScanPosture(_ context.Context, _ cloud.ScanRequest) cloud.ScanResult {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.postureCalls++
	return f.postureResult
}

func (f *fakeCloudConnector) ScanContent(_ context.Context, _ cloud.ScanRequest) cloud.ScanResult {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.contentCalls++
	return f.contentResult
}

func (f *fakeCloudConnector) calls() (int, int) {
	f.mu.Lock()
	defer f.mu.Unlock()
	return f.postureCalls, f.contentCalls
}

func newTestCloudHandler(licSvc *license.Service, conn *fakeCloudConnector) *CloudHandler {
	h := NewCloudHandler(licSvc)
	h.newConnector = func(cfg aws.AWSConfig) (cloud.Connector, error) {
		return conn, nil
	}
	return h
}

func authedRequest(t *testing.T, body string) *http.Request {
	t.Helper()
	r := httptest.NewRequest(http.MethodPost, "/api/v1/cloud/aws/s3/scan", strings.NewReader(body))
	ctx := context.WithValue(r.Context(), claimsContextKey{}, &Claims{UserID: "u-1", Email: "admin@example.com", Role: "admin"})
	return r.WithContext(ctx)
}

func scanResultFixture() cloud.ScanResult {
	return cloud.ScanResult{
		ScanID:      "scan-1",
		StartedAt:   time.Now().Add(-time.Second).UTC(),
		CompletedAt: time.Now().UTC(),
		Findings: []cloud.Finding{{
			ID: "abc", ConnectorID: "aws-s3", Provider: cloud.ProviderAWS,
			ResourceType: cloud.ResourceTypeBucket, ResourceID: "b",
			Category: "security_posture", RuleID: "aws-s3-bucket-encryption",
			Severity: cloud.SeverityHigh, Status: cloud.StatusCompliant,
			Title: "ok", Evidence: map[string]string{"sse": "AES256"},
			DetectedAt: time.Now().UTC(),
		}},
	}
}

func TestHandleAWSS3ScanUnauthenticated(t *testing.T) {
	h := newTestCloudHandler(license.NewService([]string{"cloud-dspm"}), &fakeCloudConnector{})
	rec := httptest.NewRecorder()
	h.HandleAWSS3Scan(rec, httptest.NewRequest(http.MethodPost, "/", strings.NewReader(`{}`)))
	if rec.Code != http.StatusUnauthorized {
		t.Fatalf("expected 401, got %d", rec.Code)
	}
}

func TestHandleAWSS3ScanInvalidJSON(t *testing.T) {
	h := newTestCloudHandler(license.NewService([]string{"cloud-dspm"}), &fakeCloudConnector{})
	rec := httptest.NewRecorder()
	h.HandleAWSS3Scan(rec, authedRequest(t, `{"role_arn": `))
	if rec.Code != http.StatusBadRequest {
		t.Fatalf("expected 400, got %d", rec.Code)
	}
}

func TestHandleAWSS3ScanRejectsUnknownFields(t *testing.T) {
	h := newTestCloudHandler(license.NewService([]string{"cloud-dspm"}), &fakeCloudConnector{})
	cases := []string{
		`{"role_arn":"arn:aws:iam::123456789012:role/x","external_id":"e","access_key_id":"AKIA..."}`,
		`{"role_arn":"arn:aws:iam::123456789012:role/x","external_id":"e","secret_access_key":"s3cret"}`,
		`{"role_arn":"arn:aws:iam::123456789012:role/x","external_id":"e","nonsense":true}`,
	}
	for _, body := range cases {
		rec := httptest.NewRecorder()
		h.HandleAWSS3Scan(rec, authedRequest(t, body))
		if rec.Code != http.StatusBadRequest {
			t.Errorf("body %q: expected 400 for unknown field, got %d", body, rec.Code)
		}
	}
}

func TestHandleAWSS3ScanRejectsExcessiveOrZeroLimits(t *testing.T) {
	h := newTestCloudHandler(license.NewService([]string{"cloud-dspm"}), &fakeCloudConnector{})
	base := `"role_arn":"arn:aws:iam::123456789012:role/x","external_id":"e"`
	cases := []string{
		`{` + base + `,"max_buckets":999999}`,
		`{` + base + `,"max_buckets":0}`,
		`{` + base + `,"max_objects_per_bucket":999999}`,
		`{` + base + `,"max_object_bytes":99999999999}`,
		`{` + base + `,"max_sample_bytes":-1}`,
	}
	for _, body := range cases {
		rec := httptest.NewRecorder()
		h.HandleAWSS3Scan(rec, authedRequest(t, body))
		if rec.Code != http.StatusBadRequest {
			t.Errorf("body %q: expected 400, got %d", body, rec.Code)
		}
	}
}

func TestHandleAWSS3ScanRejectsOversizedBody(t *testing.T) {
	h := newTestCloudHandler(license.NewService([]string{"cloud-dspm"}), &fakeCloudConnector{})
	big := `{"role_arn":"arn:aws:iam::123456789012:role/x","external_id":"e","pad":"` + strings.Repeat("a", 128*1024) + `"}`
	rec := httptest.NewRecorder()
	h.HandleAWSS3Scan(rec, authedRequest(t, big))
	if rec.Code != http.StatusRequestEntityTooLarge {
		t.Fatalf("expected 413, got %d", rec.Code)
	}
}

func TestHandleAWSS3ScanRequiresRoleAndExternalID(t *testing.T) {
	h := newTestCloudHandler(license.NewService([]string{"cloud-dspm"}), &fakeCloudConnector{})
	cases := []string{
		`{}`,
		`{"external_id":"e"}`,
		`{"role_arn":"arn:aws:iam::123456789012:role/x"}`,
	}
	for _, body := range cases {
		rec := httptest.NewRecorder()
		h.HandleAWSS3Scan(rec, authedRequest(t, body))
		if rec.Code != http.StatusBadRequest {
			t.Errorf("body %q: expected 400, got %d", body, rec.Code)
		}
	}
}

func TestHandleAWSS3ScanValidateErrorSanitized(t *testing.T) {
	conn := &fakeCloudConnector{validateErr: &smithy.GenericAPIError{Code: "AccessDenied", Message: "user arn:aws:iam::1:user/admin is not authorized"}}
	h := newTestCloudHandler(license.NewService([]string{"cloud-dspm"}), conn)
	rec := httptest.NewRecorder()
	body := `{"role_arn":"arn:aws:iam::123456789012:role/x","external_id":"e"}`
	h.HandleAWSS3Scan(rec, authedRequest(t, body))
	if rec.Code != http.StatusForbidden {
		t.Fatalf("expected 403, got %d", rec.Code)
	}
	resp := map[string]string{}
	if err := json.Unmarshal(rec.Body.Bytes(), &resp); err != nil {
		t.Fatalf("invalid error body: %v", err)
	}
	if strings.Contains(resp["message"], "not authorized") || strings.Contains(resp["message"], "arn:aws:iam") {
		t.Fatalf("error message leaked raw AWS error details: %q", resp["message"])
	}
}

func TestHandleAWSS3ScanSuccess(t *testing.T) {
	conn := &fakeCloudConnector{
		postureResult: scanResultFixture(),
		contentResult: scanResultFixture(),
	}
	h := newTestCloudHandler(license.NewService([]string{"cloud-dspm"}), conn)
	rec := httptest.NewRecorder()
	body := `{"role_arn":"arn:aws:iam::123456789012:role/x","external_id":"e","max_buckets":50}`
	h.HandleAWSS3Scan(rec, authedRequest(t, body))

	if rec.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d: %s", rec.Code, rec.Body.String())
	}
	var result cloud.ScanResult
	if err := json.Unmarshal(rec.Body.Bytes(), &result); err != nil {
		t.Fatalf("invalid result body: %v", err)
	}
	if result.ScanID == "" {
		t.Error("expected a scan id")
	}
	if len(result.Findings) != 2 {
		t.Errorf("expected merged findings, got %d", len(result.Findings))
	}
	postureCalls, contentCalls := conn.calls()
	if postureCalls != 1 || contentCalls != 1 {
		t.Errorf("expected posture and content scans to run once each, got %d/%d", postureCalls, contentCalls)
	}
}

func TestHandleAWSS3ScanDisablesScans(t *testing.T) {
	conn := &fakeCloudConnector{
		postureResult: scanResultFixture(),
		contentResult: scanResultFixture(),
	}
	h := newTestCloudHandler(license.NewService([]string{"cloud-dspm"}), conn)
	rec := httptest.NewRecorder()
	body := `{"role_arn":"arn:aws:iam::123456789012:role/x","external_id":"e","scan_posture":false,"scan_content":false}`
	h.HandleAWSS3Scan(rec, authedRequest(t, body))
	if rec.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d", rec.Code)
	}
	postureCalls, contentCalls := conn.calls()
	if postureCalls != 0 || contentCalls != 0 {
		t.Errorf("expected no scans, got %d/%d", postureCalls, contentCalls)
	}
}

func TestCloudHandlerRegisterRoutesBehindLicensing(t *testing.T) {
	t.Run("unlicensed returns 403", func(t *testing.T) {
		h := NewCloudHandler(license.NewService(nil))
		mux := http.NewServeMux()
		h.RegisterRoutes(mux)
		rec := httptest.NewRecorder()
		mux.ServeHTTP(rec, authedRequest(t, `{}`))
		if rec.Code != http.StatusForbidden {
			t.Fatalf("expected 403 for unlicensed feature, got %d", rec.Code)
		}
	})

	t.Run("licensed reaches handler", func(t *testing.T) {
		conn := &fakeCloudConnector{}
		h := newTestCloudHandler(license.NewService([]string{"cloud-dspm"}), conn)
		mux := http.NewServeMux()
		h.RegisterRoutes(mux)
		rec := httptest.NewRecorder()
		body := `{"role_arn":"arn:aws:iam::123456789012:role/x","external_id":"e"}`
		mux.ServeHTTP(rec, authedRequest(t, body))
		if rec.Code != http.StatusOK {
			t.Fatalf("expected 200, got %d: %s", rec.Code, rec.Body.String())
		}
	})
}

func TestCloudPathAuthenticationClassification(t *testing.T) {
	path := "/api/v1/cloud/aws/s3/scan"
	if isPublicPath(path) {
		t.Error("cloud scan route must not be a public path")
	}
	if !isAdminEndpoint(path) {
		t.Error("cloud scan route must be an admin endpoint (device tokens denied)")
	}
}

func TestValidateScanLimits(t *testing.T) {
	ok := awsS3ScanRequest{}
	if err := validateScanLimits(ok); err != nil {
		t.Fatalf("empty limits must pass, got %v", err)
	}
	if err := validateScanLimits(awsS3ScanRequest{MaxBuckets: intPtr(1)}); err != nil {
		t.Fatalf("small limits must pass, got %v", err)
	}
	if err := validateScanLimits(awsS3ScanRequest{MaxBuckets: intPtr(aws.MaxBucketsAllowed)}); err != nil {
		t.Fatalf("at-limit values must pass, got %v", err)
	}
	if err := validateScanLimits(awsS3ScanRequest{MaxBuckets: intPtr(aws.MaxBucketsAllowed + 1)}); err == nil {
		t.Error("over-limit values must fail")
	}
	if err := validateScanLimits(awsS3ScanRequest{MaxObjectBytes: int64Ptr(0)}); err == nil {
		t.Error("zero byte limits must fail")
	}
}

func intPtr(v int) *int       { return &v }
func int64Ptr(v int64) *int64 { return &v }