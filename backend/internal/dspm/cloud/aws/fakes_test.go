package aws

import (
	"context"
	"errors"
	"io"

	awssdk "github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/s3"
	"github.com/aws/aws-sdk-go-v2/service/s3control"
	"github.com/aws/aws-sdk-go-v2/service/sts"
	"github.com/aws/smithy-go"
)

// errUnimplemented is returned by stub methods that a test did not configure.
var errUnimplemented = errors.New("stub method not implemented")

// trackCloser records whether a response body was closed. It is used to verify
// that GetObject response bodies are always closed by the scanner.
type trackCloser struct {
	io.Reader
	closed bool
}

func (t *trackCloser) Close() error {
	t.closed = true
	return nil
}

// stubS3 implements S3API with per-method function fields so tests can
// configure only the operations they exercise.
type stubS3 struct {
	onListBuckets              func(ctx context.Context, params *s3.ListBucketsInput) (*s3.ListBucketsOutput, error)
	onGetBucketLocation        func(ctx context.Context, params *s3.GetBucketLocationInput) (*s3.GetBucketLocationOutput, error)
	onListObjectsV2            func(ctx context.Context, params *s3.ListObjectsV2Input) (*s3.ListObjectsV2Output, error)
	onHeadObject               func(ctx context.Context, params *s3.HeadObjectInput) (*s3.HeadObjectOutput, error)
	onGetObject                func(ctx context.Context, params *s3.GetObjectInput) (*s3.GetObjectOutput, error)
	onGetBucketAcl             func(ctx context.Context, params *s3.GetBucketAclInput) (*s3.GetBucketAclOutput, error)
	onGetBucketPolicyStatus    func(ctx context.Context, params *s3.GetBucketPolicyStatusInput) (*s3.GetBucketPolicyStatusOutput, error)
	onGetBucketOwnershipControls func(ctx context.Context, params *s3.GetBucketOwnershipControlsInput) (*s3.GetBucketOwnershipControlsOutput, error)
	onGetBucketEncryption      func(ctx context.Context, params *s3.GetBucketEncryptionInput) (*s3.GetBucketEncryptionOutput, error)
	onGetBucketVersioning      func(ctx context.Context, params *s3.GetBucketVersioningInput) (*s3.GetBucketVersioningOutput, error)
	onGetObjectLockConfiguration func(ctx context.Context, params *s3.GetObjectLockConfigurationInput) (*s3.GetObjectLockConfigurationOutput, error)
	onGetBucketLogging         func(ctx context.Context, params *s3.GetBucketLoggingInput) (*s3.GetBucketLoggingOutput, error)
	onGetBucketLifecycleConfiguration func(ctx context.Context, params *s3.GetBucketLifecycleConfigurationInput) (*s3.GetBucketLifecycleConfigurationOutput, error)
	onGetPublicAccessBlock     func(ctx context.Context, params *s3.GetPublicAccessBlockInput) (*s3.GetPublicAccessBlockOutput, error)
}

func (s *stubS3) ListBuckets(ctx context.Context, params *s3.ListBucketsInput, _ ...func(*s3.Options)) (*s3.ListBucketsOutput, error) {
	if s.onListBuckets != nil {
		return s.onListBuckets(ctx, params)
	}
	return nil, errUnimplemented
}

func (s *stubS3) GetBucketLocation(ctx context.Context, params *s3.GetBucketLocationInput, _ ...func(*s3.Options)) (*s3.GetBucketLocationOutput, error) {
	if s.onGetBucketLocation != nil {
		return s.onGetBucketLocation(ctx, params)
	}
	return nil, errUnimplemented
}

func (s *stubS3) ListObjectsV2(ctx context.Context, params *s3.ListObjectsV2Input, _ ...func(*s3.Options)) (*s3.ListObjectsV2Output, error) {
	if s.onListObjectsV2 != nil {
		return s.onListObjectsV2(ctx, params)
	}
	return nil, errUnimplemented
}

func (s *stubS3) HeadObject(ctx context.Context, params *s3.HeadObjectInput, _ ...func(*s3.Options)) (*s3.HeadObjectOutput, error) {
	if s.onHeadObject != nil {
		return s.onHeadObject(ctx, params)
	}
	return nil, errUnimplemented
}

func (s *stubS3) GetObject(ctx context.Context, params *s3.GetObjectInput, _ ...func(*s3.Options)) (*s3.GetObjectOutput, error) {
	if s.onGetObject != nil {
		return s.onGetObject(ctx, params)
	}
	return nil, errUnimplemented
}

func (s *stubS3) GetBucketAcl(ctx context.Context, params *s3.GetBucketAclInput, _ ...func(*s3.Options)) (*s3.GetBucketAclOutput, error) {
	if s.onGetBucketAcl != nil {
		return s.onGetBucketAcl(ctx, params)
	}
	return nil, errUnimplemented
}

func (s *stubS3) GetBucketPolicyStatus(ctx context.Context, params *s3.GetBucketPolicyStatusInput, _ ...func(*s3.Options)) (*s3.GetBucketPolicyStatusOutput, error) {
	if s.onGetBucketPolicyStatus != nil {
		return s.onGetBucketPolicyStatus(ctx, params)
	}
	return nil, errUnimplemented
}

func (s *stubS3) GetBucketOwnershipControls(ctx context.Context, params *s3.GetBucketOwnershipControlsInput, _ ...func(*s3.Options)) (*s3.GetBucketOwnershipControlsOutput, error) {
	if s.onGetBucketOwnershipControls != nil {
		return s.onGetBucketOwnershipControls(ctx, params)
	}
	return nil, errUnimplemented
}

func (s *stubS3) GetBucketEncryption(ctx context.Context, params *s3.GetBucketEncryptionInput, _ ...func(*s3.Options)) (*s3.GetBucketEncryptionOutput, error) {
	if s.onGetBucketEncryption != nil {
		return s.onGetBucketEncryption(ctx, params)
	}
	return nil, errUnimplemented
}

func (s *stubS3) GetBucketVersioning(ctx context.Context, params *s3.GetBucketVersioningInput, _ ...func(*s3.Options)) (*s3.GetBucketVersioningOutput, error) {
	if s.onGetBucketVersioning != nil {
		return s.onGetBucketVersioning(ctx, params)
	}
	return nil, errUnimplemented
}

func (s *stubS3) GetObjectLockConfiguration(ctx context.Context, params *s3.GetObjectLockConfigurationInput, _ ...func(*s3.Options)) (*s3.GetObjectLockConfigurationOutput, error) {
	if s.onGetObjectLockConfiguration != nil {
		return s.onGetObjectLockConfiguration(ctx, params)
	}
	return nil, errUnimplemented
}

func (s *stubS3) GetBucketLogging(ctx context.Context, params *s3.GetBucketLoggingInput, _ ...func(*s3.Options)) (*s3.GetBucketLoggingOutput, error) {
	if s.onGetBucketLogging != nil {
		return s.onGetBucketLogging(ctx, params)
	}
	return nil, errUnimplemented
}

func (s *stubS3) GetBucketLifecycleConfiguration(ctx context.Context, params *s3.GetBucketLifecycleConfigurationInput, _ ...func(*s3.Options)) (*s3.GetBucketLifecycleConfigurationOutput, error) {
	if s.onGetBucketLifecycleConfiguration != nil {
		return s.onGetBucketLifecycleConfiguration(ctx, params)
	}
	return nil, errUnimplemented
}

func (s *stubS3) GetPublicAccessBlock(ctx context.Context, params *s3.GetPublicAccessBlockInput, _ ...func(*s3.Options)) (*s3.GetPublicAccessBlockOutput, error) {
	if s.onGetPublicAccessBlock != nil {
		return s.onGetPublicAccessBlock(ctx, params)
	}
	return nil, errUnimplemented
}

// stubControl implements S3ControlAPI.
type stubControl struct {
	onGetPublicAccessBlock func(ctx context.Context, params *s3control.GetPublicAccessBlockInput) (*s3control.GetPublicAccessBlockOutput, error)
}

func (s *stubControl) GetPublicAccessBlock(ctx context.Context, params *s3control.GetPublicAccessBlockInput, _ ...func(*s3control.Options)) (*s3control.GetPublicAccessBlockOutput, error) {
	if s.onGetPublicAccessBlock != nil {
		return s.onGetPublicAccessBlock(ctx, params)
	}
	return nil, errUnimplemented
}

// fakeFactory returns the configured stub clients per region. It implements
// ClientFactory so tests never construct real SDK clients.
type fakeFactory struct {
	s3      map[string]*stubS3
	control *stubControl
}

func (f *fakeFactory) S3(region string) S3API {
	if c, ok := f.s3[region]; ok {
		return c
	}
	return &stubS3{}
}

func (f *fakeFactory) S3Control() S3ControlAPI {
	if f.control != nil {
		return f.control
	}
	return &stubControl{}
}

func (f *fakeFactory) Close() {}

// fakeAuth implements Authenticator with deterministic behavior.
type fakeAuth struct {
	session *Session
	err     error
}

func (a *fakeAuth) Authenticate(context.Context) (*Session, error) {
	if a.err != nil {
		return nil, a.err
	}
	return a.session, nil
}

func testSession() *Session {
	return &Session{Config: awssdk.Config{}, AccountID: "123456789012"}
}

// awsErr builds a smithy API error with the given AWS error code.
func awsErr(code string) error {
	return &smithy.GenericAPIError{Code: code, Message: "mocked"}
}

var _ STSAPI = (*stubSTS)(nil)

type stubSTS struct {
	onAssumeRole        func(ctx context.Context, params *sts.AssumeRoleInput) (*sts.AssumeRoleOutput, error)
	onGetCallerIdentity func(ctx context.Context, params *sts.GetCallerIdentityInput) (*sts.GetCallerIdentityOutput, error)
}

func (s *stubSTS) AssumeRole(ctx context.Context, params *sts.AssumeRoleInput, _ ...func(*sts.Options)) (*sts.AssumeRoleOutput, error) {
	if s.onAssumeRole != nil {
		return s.onAssumeRole(ctx, params)
	}
	return nil, errUnimplemented
}

func (s *stubSTS) GetCallerIdentity(ctx context.Context, params *sts.GetCallerIdentityInput, _ ...func(*sts.Options)) (*sts.GetCallerIdentityOutput, error) {
	if s.onGetCallerIdentity != nil {
		return s.onGetCallerIdentity(ctx, params)
	}
	return nil, errUnimplemented
}