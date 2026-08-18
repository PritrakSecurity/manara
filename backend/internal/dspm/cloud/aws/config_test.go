package aws

import (
	"context"
	"testing"

	"manara-dlp/internal/dspm/cloud"
)

func TestAWSConfigValidateRequiresRoleAndExternalID(t *testing.T) {
	cases := []struct {
		name    string
		cfg     AWSConfig
		wantErr bool
	}{
		{"valid", AWSConfig{RoleARN: "arn:aws:iam::123456789012:role/scan", ExternalID: "ext-123"}, false},
		{"missing role", AWSConfig{ExternalID: "ext-123"}, true},
		{"missing external id", AWSConfig{RoleARN: "arn:aws:iam::123456789012:role/scan"}, true},
		{"malformed role", AWSConfig{RoleARN: "not-an-arn", ExternalID: "ext-123"}, true},
		{"profile allowed", AWSConfig{Profile: "local", AllowProfile: true}, false},
		{"profile allowed but role without external id", AWSConfig{Profile: "local", AllowProfile: true, RoleARN: "arn:aws:iam::123456789012:role/scan"}, true},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			err := tc.cfg.Validate()
			if tc.wantErr && err == nil {
				t.Fatal("expected error, got nil")
			}
			if !tc.wantErr && err != nil {
				t.Fatalf("expected no error, got %v", err)
			}
		})
	}
}

func TestAWSConfigValidateLimits(t *testing.T) {
	base := AWSConfig{RoleARN: "arn:aws:iam::123456789012:role/scan", ExternalID: "ext"}
	if err := (AWSConfig{
		RoleARN: base.RoleARN, ExternalID: base.ExternalID,
		MaxBuckets:          MaxBucketsAllowed + 1,
		MaxObjectsPerBucket: MaxObjectsPerBucketAllowed + 1,
		MaxObjectBytes:      MaxObjectBytesAllowed + 1,
		MaxSampleBytes:      MaxSampleBytesAllowed + 1,
	}).Validate(); err == nil {
		t.Fatal("expected oversized limits to be rejected")
	}
}

func TestNormalizeRequestClampsToServerMaximums(t *testing.T) {
	r := cloud.ScanRequest{
		ScanID:              "scan-1",
		MaxBuckets:          999999,
		MaxObjectsPerBucket: 999999,
		MaxObjectBytes:      1 << 40,
		MaxSampleBytes:      1 << 40,
	}
	n := normalizeRequest(r)
	if n.MaxBuckets != MaxBucketsAllowed {
		t.Errorf("MaxBuckets not clamped: %d", n.MaxBuckets)
	}
	if n.MaxObjectsPerBucket != MaxObjectsPerBucketAllowed {
		t.Errorf("MaxObjectsPerBucket not clamped: %d", n.MaxObjectsPerBucket)
	}
	if n.MaxObjectBytes != MaxObjectBytesAllowed {
		t.Errorf("MaxObjectBytes not clamped: %d", n.MaxObjectBytes)
	}
	if n.MaxSampleBytes != MaxSampleBytesAllowed {
		t.Errorf("MaxSampleBytes not clamped: %d", n.MaxSampleBytes)
	}
	if n.ScanID != "scan-1" {
		t.Errorf("ScanID lost: %s", n.ScanID)
	}
}

func TestNormalizeRequestDefaults(t *testing.T) {
	n := normalizeRequest(cloud.ScanRequest{ScanID: "s"})
	if n.MaxBuckets != 100 || n.MaxObjectsPerBucket != 100 {
		t.Errorf("unexpected bucket defaults: %d/%d", n.MaxBuckets, n.MaxObjectsPerBucket)
	}
	if n.MaxObjectBytes != 10*1024*1024 || n.MaxSampleBytes != 1*1024*1024 {
		t.Errorf("unexpected byte defaults: %d/%d", n.MaxObjectBytes, n.MaxSampleBytes)
	}
}

func TestAccountFromRoleARN(t *testing.T) {
	cases := []struct {
		arn  string
		want string
	}{
		{"arn:aws:iam::123456789012:role/scan", "123456789012"},
		{"arn:aws:iam::123456789012:role/service/name", "123456789012"},
		{"not-an-arn", ""},
		{"", ""},
	}
	for _, tc := range cases {
		if got := accountFromRoleARN(tc.arn); got != tc.want {
			t.Errorf("accountFromRoleARN(%q) = %q, want %q", tc.arn, got, tc.want)
		}
	}
}

func TestClassifyError(t *testing.T) {
	cases := []struct {
		name string
		err  error
		want errorKind
	}{
		{"access denied", awsErr("AccessDenied"), kindAuthz},
		{"access denied exception", awsErr("AccessDeniedException"), kindAuthz},
		{"invalid token", awsErr("InvalidClientTokenId"), kindAuth},
		{"expired token", awsErr("ExpiredToken"), kindAuth},
		{"throttling", awsErr("Throttling"), kindThrottled},
		{"slow down", awsErr("SlowDown"), kindThrottled},
		{"no such bucket", awsErr("NoSuchBucket"), kindNotFound},
		{"no such lifecycle", awsErr("NoSuchLifecycleConfiguration"), kindNotFound},
		{"unknown", awsErr("InternalError"), kindTransient},
		{"cancelled", context.Canceled, kindCancelled},
		{"deadline", context.DeadlineExceeded, kindCancelled},
		{"nil", nil, kindUnknown},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			kind, msg := classifyError(tc.err)
			if kind != tc.want {
				t.Errorf("kind = %v, want %v", kind, tc.want)
			}
			if msg == "" && tc.err != nil {
				t.Error("expected a sanitized message")
			}
		})
	}
}

func TestAuthErrorSanitized(t *testing.T) {
	e := authError("authentication", awsErr("AccessDenied"))
	if e == nil {
		t.Fatal("expected a scan error")
	}
	if e.category != "access_denied" {
		t.Errorf("unexpected category %q", e.category)
	}
	if e.message == "" || e.message == "mocked" {
		t.Errorf("message must be sanitized, got %q", e.message)
	}
	if e.retryable {
		t.Error("authorization failures are not retryable")
	}
}