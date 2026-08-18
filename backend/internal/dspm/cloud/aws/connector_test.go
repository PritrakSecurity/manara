package aws

import (
	"context"
	"errors"
	"net/http"
	"testing"

	awssdk "github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/credentials"
	"github.com/aws/aws-sdk-go-v2/service/s3"
	"github.com/aws/aws-sdk-go-v2/service/s3control"
	s3controltypes "github.com/aws/aws-sdk-go-v2/service/s3control/types"
	s3types "github.com/aws/aws-sdk-go-v2/service/s3/types"

	"manara-dlp/internal/dspm/cloud"
)

func TestConnectorValidateAuthSuccess(t *testing.T) {
	session := testSession()
	session.Config.Credentials = awsCredentialsProvider{}
	conn := newS3Connector(AWSConfig{RoleARN: "arn:aws:iam::123456789012:role/scan", ExternalID: "ext"}, &fakeAuth{session: session}, func(*Session) ClientFactory { return nil }, nil, nil, nil)
	if err := conn.Validate(context.Background()); err != nil {
		t.Fatalf("expected valid auth, got %v", err)
	}
}

// awsCredentialsProvider is a fixed credentials provider for tests only. It is
// never used in production code paths.
type awsCredentialsProvider struct{}

func (awsCredentialsProvider) Retrieve(context.Context) (awssdk.Credentials, error) {
	return credentials.NewStaticCredentialsProvider("AKIA-test", "secret", "token").Retrieve(context.Background())
}

func TestConnectorValidateAuthFailureStatus(t *testing.T) {
	cases := []struct {
		name       string
		err        error
		wantStatus int
	}{
		{"invalid external id", awsErr("InvalidClientTokenId"), http.StatusUnauthorized},
		{"expired credentials", awsErr("ExpiredToken"), http.StatusUnauthorized},
		{"access denied", awsErr("AccessDenied"), http.StatusForbidden},
		{"throttled", awsErr("Throttling"), http.StatusServiceUnavailable},
		{"cancelled", context.DeadlineExceeded, http.StatusGatewayTimeout},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			conn := newS3Connector(AWSConfig{RoleARN: "arn:aws:iam::123456789012:role/scan", ExternalID: "ext"}, &fakeAuth{err: tc.err}, nil, nil, nil, nil)
			err := conn.Validate(context.Background())
			if err == nil {
				t.Fatal("expected validation error")
			}
			if got := HTTPStatusForError(err); got != tc.wantStatus {
				t.Errorf("HTTPStatusForError = %d, want %d", got, tc.wantStatus)
			}
			if msg := SanitizeError(err); msg == "" || msg == tc.err.Error() {
				t.Errorf("sanitized message must differ from raw error, got %q", msg)
			}
		})
	}
}

func TestScanPostureAuthFailureRecorded(t *testing.T) {
	conn := newS3Connector(AWSConfig{}, &fakeAuth{err: awsErr("AccessDenied")}, func(*Session) ClientFactory { return nil }, nil, nil, nil)
	result := conn.ScanPosture(context.Background(), cloud.ScanRequest{ScanID: "s"})
	if len(result.Findings) != 0 {
		t.Fatalf("expected no findings on auth failure, got %d", len(result.Findings))
	}
	found := false
	for _, e := range result.Errors {
		if e.Category == "access_denied" {
			found = true
		}
	}
	if !found {
		t.Fatalf("expected an access_denied error, got %v", result.Errors)
	}
}

func TestScanContentAuthFailureRecorded(t *testing.T) {
	conn := newS3Connector(AWSConfig{}, &fakeAuth{err: awsErr("ExpiredToken")}, func(*Session) ClientFactory { return nil }, nil, nil, nil)
	result := conn.ScanContent(context.Background(), cloud.ScanRequest{ScanID: "s"})
	found := false
	for _, e := range result.Errors {
		if e.Category == "authentication" {
			found = true
		}
	}
	if !found {
		t.Fatalf("expected an authentication error, got %v", result.Errors)
	}
}

func TestScanPostureIntegrationDeterministic(t *testing.T) {
	client := &stubS3{
		onListBuckets: func(context.Context, *s3.ListBucketsInput) (*s3.ListBucketsOutput, error) {
			return bucketList("b-1", "b-2"), nil
		},
		onGetBucketLocation: func(context.Context, *s3.GetBucketLocationInput) (*s3.GetBucketLocationOutput, error) {
			return &s3.GetBucketLocationOutput{}, nil
		},
		onGetPublicAccessBlock: func(context.Context, *s3.GetPublicAccessBlockInput) (*s3.GetPublicAccessBlockOutput, error) {
			return &s3.GetPublicAccessBlockOutput{PublicAccessBlockConfiguration: pab(true, true, true, true)}, nil
		},
		onGetBucketPolicyStatus: func(context.Context, *s3.GetBucketPolicyStatusInput) (*s3.GetBucketPolicyStatusOutput, error) {
			return &s3.GetBucketPolicyStatusOutput{PolicyStatus: &s3types.PolicyStatus{IsPublic: awssdk.Bool(false)}}, nil
		},
		onGetBucketAcl: func(context.Context, *s3.GetBucketAclInput) (*s3.GetBucketAclOutput, error) {
			return &s3.GetBucketAclOutput{}, nil
		},
		onGetBucketOwnershipControls: func(context.Context, *s3.GetBucketOwnershipControlsInput) (*s3.GetBucketOwnershipControlsOutput, error) {
			return &s3.GetBucketOwnershipControlsOutput{OwnershipControls: &s3types.OwnershipControls{
				Rules: []s3types.OwnershipControlsRule{{ObjectOwnership: s3types.ObjectOwnershipBucketOwnerEnforced}},
			}}, nil
		},
		onGetBucketEncryption: func(context.Context, *s3.GetBucketEncryptionInput) (*s3.GetBucketEncryptionOutput, error) {
			return &s3.GetBucketEncryptionOutput{ServerSideEncryptionConfiguration: &s3types.ServerSideEncryptionConfiguration{
				Rules: []s3types.ServerSideEncryptionRule{{
					ApplyServerSideEncryptionByDefault: &s3types.ServerSideEncryptionByDefault{SSEAlgorithm: s3types.ServerSideEncryptionAwsKms, KMSMasterKeyID: awssdk.String("key")},
				}},
			}}, nil
		},
		onGetBucketVersioning: func(context.Context, *s3.GetBucketVersioningInput) (*s3.GetBucketVersioningOutput, error) {
			return &s3.GetBucketVersioningOutput{Status: s3types.BucketVersioningStatusEnabled}, nil
		},
		onGetObjectLockConfiguration: func(context.Context, *s3.GetObjectLockConfigurationInput) (*s3.GetObjectLockConfigurationOutput, error) {
			return &s3.GetObjectLockConfigurationOutput{ObjectLockConfiguration: &s3types.ObjectLockConfiguration{ObjectLockEnabled: s3types.ObjectLockEnabledEnabled}}, nil
		},
		onGetBucketLogging: func(context.Context, *s3.GetBucketLoggingInput) (*s3.GetBucketLoggingOutput, error) {
			return &s3.GetBucketLoggingOutput{LoggingEnabled: &s3types.LoggingEnabled{TargetBucket: awssdk.String("logs")}}, nil
		},
		onGetBucketLifecycleConfiguration: func(context.Context, *s3.GetBucketLifecycleConfigurationInput) (*s3.GetBucketLifecycleConfigurationOutput, error) {
			return &s3.GetBucketLifecycleConfigurationOutput{Rules: []s3types.LifecycleRule{{ID: awssdk.String("r")}}}, nil
		},
	}
	control := &stubControl{onGetPublicAccessBlock: func(context.Context, *s3control.GetPublicAccessBlockInput) (*s3control.GetPublicAccessBlockOutput, error) {
		return &s3control.GetPublicAccessBlockOutput{PublicAccessBlockConfiguration: &s3controltypes.PublicAccessBlockConfiguration{
			BlockPublicAcls: awssdk.Bool(true), IgnorePublicAcls: awssdk.Bool(true),
			BlockPublicPolicy: awssdk.Bool(true), RestrictPublicBuckets: awssdk.Bool(true),
		}}, nil
	}}
	factory := &fakeFactory{s3: map[string]*stubS3{"us-east-1": client}, control: control}
	auth := &fakeAuth{session: testSession()}
	conn := newS3Connector(AWSConfig{}, auth, func(*Session) ClientFactory { return factory }, nil, nil, nil)

	result := conn.ScanPosture(context.Background(), cloud.ScanRequest{ScanID: "s", MaxBuckets: 100})

	// Account PAB (1) + 9 bucket rules x 2 buckets = 19 findings.
	if len(result.Findings) != 19 {
		t.Fatalf("expected 19 findings, got %d", len(result.Findings))
	}
	if result.Truncated {
		t.Error("unexpected truncation")
	}
	// Deterministic ordering: resource ascending, then rule ascending.
	for i := 1; i < len(result.Findings); i++ {
		prev, cur := result.Findings[i-1], result.Findings[i]
		if prev.ResourceID > cur.ResourceID || (prev.ResourceID == cur.ResourceID && prev.RuleID > cur.RuleID) {
			t.Errorf("findings not sorted deterministically at %d: %s/%s then %s/%s", i, prev.ResourceID, prev.RuleID, cur.ResourceID, cur.RuleID)
		}
	}
	// Re-run to confirm identical output (auditable results).
	again := conn.ScanPosture(context.Background(), cloud.ScanRequest{ScanID: "s", MaxBuckets: 100})
	if len(again.Findings) != len(result.Findings) {
		t.Fatal("re-run produced a different number of findings")
	}
	for i := range result.Findings {
		if result.Findings[i].ID != again.Findings[i].ID || result.Findings[i].Status != again.Findings[i].Status {
			t.Fatalf("re-run diverged at index %d", i)
		}
	}
}

func TestHTTPStatusForErrorDefault(t *testing.T) {
	if got := HTTPStatusForError(errors.New("some non-aws error")); got != http.StatusInternalServerError {
		t.Errorf("unexpected default status %d", got)
	}
}