package aws

import (
	"context"
	"testing"

	awssdk "github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/s3"
	"github.com/aws/aws-sdk-go-v2/service/s3control"
	s3controltypes "github.com/aws/aws-sdk-go-v2/service/s3control/types"
	s3types "github.com/aws/aws-sdk-go-v2/service/s3/types"

	"manara-dlp/internal/dspm/cloud"
)

func pab(b, i, p, r bool) *s3types.PublicAccessBlockConfiguration {
	return &s3types.PublicAccessBlockConfiguration{
		BlockPublicAcls:       awssdk.Bool(b),
		IgnorePublicAcls:      awssdk.Bool(i),
		BlockPublicPolicy:     awssdk.Bool(p),
		RestrictPublicBuckets: awssdk.Bool(r),
	}
}

func TestPostureAccessDeniedIsUnknownNeverNonCompliant(t *testing.T) {
	conn := newS3Connector(AWSConfig{}, &fakeAuth{session: testSession()}, func(*Session) ClientFactory { return nil }, nil, nil, nil)
	client := &stubS3{
		onGetPublicAccessBlock: func(context.Context, *s3.GetPublicAccessBlockInput) (*s3.GetPublicAccessBlockOutput, error) {
			return nil, awsErr("AccessDenied")
		},
		onGetBucketPolicyStatus: func(context.Context, *s3.GetBucketPolicyStatusInput) (*s3.GetBucketPolicyStatusOutput, error) {
			return nil, awsErr("AccessDenied")
		},
		onGetBucketAcl: func(context.Context, *s3.GetBucketAclInput) (*s3.GetBucketAclOutput, error) {
			return nil, awsErr("AccessDenied")
		},
		onGetBucketOwnershipControls: func(context.Context, *s3.GetBucketOwnershipControlsInput) (*s3.GetBucketOwnershipControlsOutput, error) {
			return nil, awsErr("AccessDenied")
		},
		onGetBucketEncryption: func(context.Context, *s3.GetBucketEncryptionInput) (*s3.GetBucketEncryptionOutput, error) {
			return nil, awsErr("AccessDenied")
		},
		onGetBucketVersioning: func(context.Context, *s3.GetBucketVersioningInput) (*s3.GetBucketVersioningOutput, error) {
			return nil, awsErr("AccessDenied")
		},
		onGetObjectLockConfiguration: func(context.Context, *s3.GetObjectLockConfigurationInput) (*s3.GetObjectLockConfigurationOutput, error) {
			return nil, awsErr("AccessDenied")
		},
		onGetBucketLogging: func(context.Context, *s3.GetBucketLoggingInput) (*s3.GetBucketLoggingOutput, error) {
			return nil, awsErr("AccessDenied")
		},
		onGetBucketLifecycleConfiguration: func(context.Context, *s3.GetBucketLifecycleConfigurationInput) (*s3.GetBucketLifecycleConfigurationOutput, error) {
			return nil, awsErr("AccessDenied")
		},
	}

	var findings []cloud.Finding
	var errs []cloud.ScanError
	conn.assessBucketPosture(context.Background(), client, "b", &findings, &errs)

	for _, f := range findings {
		if f.Status == cloud.StatusNonCompliant {
			t.Errorf("rule %s reported noncompliant on AccessDenied", f.RuleID)
		}
		if f.Status != cloud.StatusUnknown {
			t.Errorf("rule %s expected unknown, got %s", f.RuleID, f.Status)
		}
		if reason := f.Evidence["reason"]; reason != "access_denied" {
			t.Errorf("rule %s expected reason access_denied, got %q", f.RuleID, reason)
		}
	}
	if len(errs) != 0 {
		t.Errorf("AccessDenied must not surface as a scan error, got %v", errs)
	}
}

func TestPostureAccountAndBucketPublicAccessBlock(t *testing.T) {
	conn := newS3Connector(AWSConfig{}, &fakeAuth{session: testSession()}, func(*Session) ClientFactory { return nil }, nil, nil, nil)

	// Account-level: fully blocked => compliant.
	control := &stubControl{onGetPublicAccessBlock: func(_ context.Context, params *s3control.GetPublicAccessBlockInput) (*s3control.GetPublicAccessBlockOutput, error) {
		if *params.AccountId != "123456789012" {
			t.Fatalf("unexpected account id %q", *params.AccountId)
		}
		return &s3control.GetPublicAccessBlockOutput{
			PublicAccessBlockConfiguration: &s3controltypes.PublicAccessBlockConfiguration{
				BlockPublicAcls: awssdk.Bool(true), IgnorePublicAcls: awssdk.Bool(true),
				BlockPublicPolicy: awssdk.Bool(true), RestrictPublicBuckets: awssdk.Bool(true),
			},
		}, nil
	}}
	var findings []cloud.Finding
	var errs []cloud.ScanError
	conn.assessAccountPosture(context.Background(), control, "123456789012", &findings, &errs)
	if len(findings) != 1 || findings[0].Status != cloud.StatusCompliant {
		t.Fatalf("expected compliant account PAB, got %+v", findings)
	}

	// Account-level: not configured => noncompliant, never unknown.
	control2 := &stubControl{onGetPublicAccessBlock: func(context.Context, *s3control.GetPublicAccessBlockInput) (*s3control.GetPublicAccessBlockOutput, error) {
		return nil, awsErr("NoSuchPublicAccessBlockConfiguration")
	}}
	findings = nil
	errs = nil
	conn.assessAccountPosture(context.Background(), control2, "123456789012", &findings, &errs)
	if len(findings) != 1 || findings[0].Status != cloud.StatusNonCompliant {
		t.Fatalf("expected noncompliant account PAB, got %+v", findings)
	}

	// Bucket-level: partially blocked => noncompliant.
	client := &stubS3{onGetPublicAccessBlock: func(context.Context, *s3.GetPublicAccessBlockInput) (*s3.GetPublicAccessBlockOutput, error) {
		return &s3.GetPublicAccessBlockOutput{PublicAccessBlockConfiguration: pab(true, true, false, false)}, nil
	}}
	findings = nil
	errs = nil
	conn.assessBucketPosture(context.Background(), client, "b", &findings, &errs)
	var pabFinding *cloud.Finding
	for i := range findings {
		if findings[i].RuleID == "aws-s3-bucket-public-access-block" {
			pabFinding = &findings[i]
		}
	}
	if pabFinding == nil {
		t.Fatal("missing bucket PAB finding")
	}
	if pabFinding.Status != cloud.StatusNonCompliant {
		t.Fatalf("expected noncompliant bucket PAB, got %+v", pabFinding)
	}
}

func TestPosturePublicPolicy(t *testing.T) {
	conn := newS3Connector(AWSConfig{}, nil, nil, nil, nil, nil)
	cases := []struct {
		name     string
		stub     func(context.Context, *s3.GetBucketPolicyStatusInput) (*s3.GetBucketPolicyStatusOutput, error)
		want     string
	}{
		{"public policy is noncompliant", func(context.Context, *s3.GetBucketPolicyStatusInput) (*s3.GetBucketPolicyStatusOutput, error) {
			return &s3.GetBucketPolicyStatusOutput{PolicyStatus: &s3types.PolicyStatus{IsPublic: awssdk.Bool(true)}}, nil
		}, cloud.StatusNonCompliant},
		{"private policy is compliant", func(context.Context, *s3.GetBucketPolicyStatusInput) (*s3.GetBucketPolicyStatusOutput, error) {
			return &s3.GetBucketPolicyStatusOutput{PolicyStatus: &s3types.PolicyStatus{IsPublic: awssdk.Bool(false)}}, nil
		}, cloud.StatusCompliant},
		{"no policy is compliant", func(context.Context, *s3.GetBucketPolicyStatusInput) (*s3.GetBucketPolicyStatusOutput, error) {
			return nil, awsErr("NoSuchBucketPolicy")
		}, cloud.StatusCompliant},
		{"access denied is unknown", func(context.Context, *s3.GetBucketPolicyStatusInput) (*s3.GetBucketPolicyStatusOutput, error) {
			return nil, awsErr("AccessDenied")
		}, cloud.StatusUnknown},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			o := conn.checkBucketPolicyStatus(context.Background(), &stubS3{onGetBucketPolicyStatus: tc.stub}, "b")
			if o.status != tc.want {
				t.Errorf("status = %s, want %s", o.status, tc.want)
			}
		})
	}
}

func TestPosturePublicAcl(t *testing.T) {
	conn := newS3Connector(AWSConfig{}, nil, nil, nil, nil, nil)
	allUsers := awssdk.String("http://acs.amazonaws.com/groups/global/AllUsers")
	cases := []struct {
		name string
		grants []s3types.Grant
		want string
	}{
		{"public read grant is noncompliant", []s3types.Grant{
			{Grantee: &s3types.Grantee{Type: s3types.TypeGroup, URI: allUsers}, Permission: s3types.PermissionRead},
		}, cloud.StatusNonCompliant},
		{"authenticated users grant is noncompliant", []s3types.Grant{
			{Grantee: &s3types.Grantee{Type: s3types.TypeGroup, URI: awssdk.String("http://acs.amazonaws.com/groups/global/AuthenticatedUsers")}, Permission: s3types.PermissionWrite},
		}, cloud.StatusNonCompliant},
		{"canonical user grant is compliant", []s3types.Grant{
			{Grantee: &s3types.Grantee{Type: s3types.TypeCanonicalUser, ID: awssdk.String("abc")}, Permission: s3types.PermissionFullControl},
		}, cloud.StatusCompliant},
		{"no grants is compliant", nil, cloud.StatusCompliant},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			o := conn.checkBucketAcl(context.Background(), &stubS3{onGetBucketAcl: func(context.Context, *s3.GetBucketAclInput) (*s3.GetBucketAclOutput, error) {
				return &s3.GetBucketAclOutput{Grants: tc.grants}, nil
			}}, "b")
			if o.status != tc.want {
				t.Errorf("status = %s, want %s", o.status, tc.want)
			}
		})
	}
}

func TestPostureEncryption(t *testing.T) {
	conn := newS3Connector(AWSConfig{}, nil, nil, nil, nil, nil)
	cases := []struct {
		name   string
		algo   s3types.ServerSideEncryption
		kmsKey *string
		want   string
	}{
		{"SSE-S3 is compliant at rest", s3types.ServerSideEncryptionAes256, nil, cloud.StatusCompliant},
		{"SSE-KMS is compliant at rest", s3types.ServerSideEncryptionAwsKms, awssdk.String("alias/my-key"), cloud.StatusCompliant},
		{"DSSE-KMS is compliant at rest", s3types.ServerSideEncryptionAwsKmsDsse, awssdk.String("arn:aws:kms:us-east-1:123:key/abc"), cloud.StatusCompliant},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			o := conn.checkBucketEncryption(context.Background(), &stubS3{onGetBucketEncryption: func(context.Context, *s3.GetBucketEncryptionInput) (*s3.GetBucketEncryptionOutput, error) {
				return &s3.GetBucketEncryptionOutput{ServerSideEncryptionConfiguration: &s3types.ServerSideEncryptionConfiguration{
					Rules: []s3types.ServerSideEncryptionRule{{
						ApplyServerSideEncryptionByDefault: &s3types.ServerSideEncryptionByDefault{SSEAlgorithm: tc.algo, KMSMasterKeyID: tc.kmsKey},
					}},
				}}, nil
			}}, "b")
			if o.status != tc.want {
				t.Errorf("status = %s, want %s", o.status, tc.want)
			}
			if tc.algo == s3types.ServerSideEncryptionAes256 {
				if d := o.evidence["description"]; d == "" || o.evidence["kms_key_configured"] != "false" {
					t.Errorf("SSE-S3 must be described as encrypted at rest, evidence=%v", o.evidence)
				}
			}
		})
	}

	t.Run("not configured is noncompliant", func(t *testing.T) {
		o := conn.checkBucketEncryption(context.Background(), &stubS3{onGetBucketEncryption: func(context.Context, *s3.GetBucketEncryptionInput) (*s3.GetBucketEncryptionOutput, error) {
			return nil, awsErr("ServerSideEncryptionConfigurationNotFoundError")
		}}, "b")
		if o.status != cloud.StatusNonCompliant {
			t.Errorf("status = %s, want noncompliant", o.status)
		}
	})
	t.Run("access denied is unknown", func(t *testing.T) {
		o := conn.checkBucketEncryption(context.Background(), &stubS3{onGetBucketEncryption: func(context.Context, *s3.GetBucketEncryptionInput) (*s3.GetBucketEncryptionOutput, error) {
			return nil, awsErr("AccessDenied")
		}}, "b")
		if o.status != cloud.StatusUnknown {
			t.Errorf("status = %s, want unknown", o.status)
		}
	})
}

func TestPostureVersioning(t *testing.T) {
	conn := newS3Connector(AWSConfig{}, nil, nil, nil, nil, nil)
	cases := []struct {
		name   string
		status s3types.BucketVersioningStatus
		want   string
	}{
		{"enabled is compliant", s3types.BucketVersioningStatusEnabled, cloud.StatusCompliant},
		{"suspended is noncompliant", s3types.BucketVersioningStatusSuspended, cloud.StatusNonCompliant},
		{"never configured is noncompliant", "", cloud.StatusNonCompliant},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			o := conn.checkBucketVersioning(context.Background(), &stubS3{onGetBucketVersioning: func(context.Context, *s3.GetBucketVersioningInput) (*s3.GetBucketVersioningOutput, error) {
				out := &s3.GetBucketVersioningOutput{}
				if tc.status != "" {
					out.Status = tc.status
				}
				return out, nil
			}}, "b")
			if o.status != tc.want {
				t.Errorf("status = %s, want %s", o.status, tc.want)
			}
		})
	}
}

func TestPostureObjectLock(t *testing.T) {
	conn := newS3Connector(AWSConfig{}, nil, nil, nil, nil, nil)
	enabled := conn.checkBucketObjectLock(context.Background(), &stubS3{onGetObjectLockConfiguration: func(context.Context, *s3.GetObjectLockConfigurationInput) (*s3.GetObjectLockConfigurationOutput, error) {
		return &s3.GetObjectLockConfigurationOutput{ObjectLockConfiguration: &s3types.ObjectLockConfiguration{ObjectLockEnabled: s3types.ObjectLockEnabledEnabled}}, nil
	}}, "b")
	if enabled.status != cloud.StatusCompliant {
		t.Errorf("enabled object lock = %s, want compliant", enabled.status)
	}

	absent := conn.checkBucketObjectLock(context.Background(), &stubS3{onGetObjectLockConfiguration: func(context.Context, *s3.GetObjectLockConfigurationInput) (*s3.GetObjectLockConfigurationOutput, error) {
		return nil, awsErr("ObjectLockConfigurationNotFoundError")
	}}, "b")
	if absent.status != cloud.StatusNonCompliant {
		t.Errorf("absent object lock = %s, want noncompliant", absent.status)
	}

	denied := conn.checkBucketObjectLock(context.Background(), &stubS3{onGetObjectLockConfiguration: func(context.Context, *s3.GetObjectLockConfigurationInput) (*s3.GetObjectLockConfigurationOutput, error) {
		return nil, awsErr("AccessDenied")
	}}, "b")
	if denied.status != cloud.StatusUnknown {
		t.Errorf("denied object lock = %s, want unknown", denied.status)
	}
}

func TestPostureOwnershipControls(t *testing.T) {
	conn := newS3Connector(AWSConfig{}, nil, nil, nil, nil, nil)
	cases := []struct {
		name    string
		owner   s3types.ObjectOwnership
		want    string
	}{
		{"BucketOwnerEnforced is compliant", s3types.ObjectOwnershipBucketOwnerEnforced, cloud.StatusCompliant},
		{"BucketOwnerPreferred is noncompliant", s3types.ObjectOwnershipBucketOwnerPreferred, cloud.StatusNonCompliant},
		{"ObjectWriter is noncompliant", s3types.ObjectOwnershipObjectWriter, cloud.StatusNonCompliant},
		{"absent is noncompliant", "", cloud.StatusNonCompliant},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			o := conn.checkBucketOwnershipControls(context.Background(), &stubS3{onGetBucketOwnershipControls: func(context.Context, *s3.GetBucketOwnershipControlsInput) (*s3.GetBucketOwnershipControlsOutput, error) {
				if tc.owner == "" {
					return nil, awsErr("OwnershipControlsNotFoundError")
				}
				return &s3.GetBucketOwnershipControlsOutput{OwnershipControls: &s3types.OwnershipControls{
					Rules: []s3types.OwnershipControlsRule{{ObjectOwnership: tc.owner}},
				}}, nil
			}}, "b")
			if o.status != tc.want {
				t.Errorf("status = %s, want %s", o.status, tc.want)
			}
		})
	}
}

func TestPostureLoggingAndLifecycle(t *testing.T) {
	conn := newS3Connector(AWSConfig{}, nil, nil, nil, nil, nil)

	logEnabled := conn.checkBucketLogging(context.Background(), &stubS3{onGetBucketLogging: func(context.Context, *s3.GetBucketLoggingInput) (*s3.GetBucketLoggingOutput, error) {
		return &s3.GetBucketLoggingOutput{LoggingEnabled: &s3types.LoggingEnabled{TargetBucket: awssdk.String("log-bucket")}}, nil
	}}, "b")
	if logEnabled.status != cloud.StatusCompliant {
		t.Errorf("logging enabled = %s, want compliant", logEnabled.status)
	}

	logDisabled := conn.checkBucketLogging(context.Background(), &stubS3{onGetBucketLogging: func(context.Context, *s3.GetBucketLoggingInput) (*s3.GetBucketLoggingOutput, error) {
		return &s3.GetBucketLoggingOutput{}, nil
	}}, "b")
	if logDisabled.status != cloud.StatusNonCompliant {
		t.Errorf("logging disabled = %s, want noncompliant", logDisabled.status)
	}

	lifecycle := conn.checkBucketLifecycle(context.Background(), &stubS3{onGetBucketLifecycleConfiguration: func(context.Context, *s3.GetBucketLifecycleConfigurationInput) (*s3.GetBucketLifecycleConfigurationOutput, error) {
		return &s3.GetBucketLifecycleConfigurationOutput{Rules: []s3types.LifecycleRule{{ID: awssdk.String("r1")}}}, nil
	}}, "b")
	if lifecycle.status != cloud.StatusCompliant {
		t.Errorf("lifecycle configured = %s, want compliant", lifecycle.status)
	}

	lifecycleAbsent := conn.checkBucketLifecycle(context.Background(), &stubS3{onGetBucketLifecycleConfiguration: func(context.Context, *s3.GetBucketLifecycleConfigurationInput) (*s3.GetBucketLifecycleConfigurationOutput, error) {
		return nil, awsErr("NoSuchLifecycleConfiguration")
	}}, "b")
	if lifecycleAbsent.status != cloud.StatusNonCompliant {
		t.Errorf("lifecycle absent = %s, want noncompliant", lifecycleAbsent.status)
	}
}