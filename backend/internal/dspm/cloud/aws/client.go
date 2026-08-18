package aws

import (
	"context"
	"net/http"
	"sync"
	"time"

	awssdk "github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/s3"
	"github.com/aws/aws-sdk-go-v2/service/s3control"
	"github.com/aws/aws-sdk-go-v2/service/sts"
)

// S3API is the narrow set of read-only S3 operations used by the connector.
// Handlers and scanner logic depend on this interface instead of the concrete
// SDK client so unit tests can use deterministic fakes.
type S3API interface {
	ListBuckets(ctx context.Context, params *s3.ListBucketsInput, optFns ...func(*s3.Options)) (*s3.ListBucketsOutput, error)
	GetBucketLocation(ctx context.Context, params *s3.GetBucketLocationInput, optFns ...func(*s3.Options)) (*s3.GetBucketLocationOutput, error)
	ListObjectsV2(ctx context.Context, params *s3.ListObjectsV2Input, optFns ...func(*s3.Options)) (*s3.ListObjectsV2Output, error)
	HeadObject(ctx context.Context, params *s3.HeadObjectInput, optFns ...func(*s3.Options)) (*s3.HeadObjectOutput, error)
	GetObject(ctx context.Context, params *s3.GetObjectInput, optFns ...func(*s3.Options)) (*s3.GetObjectOutput, error)
	GetBucketAcl(ctx context.Context, params *s3.GetBucketAclInput, optFns ...func(*s3.Options)) (*s3.GetBucketAclOutput, error)
	GetBucketPolicyStatus(ctx context.Context, params *s3.GetBucketPolicyStatusInput, optFns ...func(*s3.Options)) (*s3.GetBucketPolicyStatusOutput, error)
	GetBucketOwnershipControls(ctx context.Context, params *s3.GetBucketOwnershipControlsInput, optFns ...func(*s3.Options)) (*s3.GetBucketOwnershipControlsOutput, error)
	GetBucketEncryption(ctx context.Context, params *s3.GetBucketEncryptionInput, optFns ...func(*s3.Options)) (*s3.GetBucketEncryptionOutput, error)
	GetBucketVersioning(ctx context.Context, params *s3.GetBucketVersioningInput, optFns ...func(*s3.Options)) (*s3.GetBucketVersioningOutput, error)
	GetObjectLockConfiguration(ctx context.Context, params *s3.GetObjectLockConfigurationInput, optFns ...func(*s3.Options)) (*s3.GetObjectLockConfigurationOutput, error)
	GetBucketLogging(ctx context.Context, params *s3.GetBucketLoggingInput, optFns ...func(*s3.Options)) (*s3.GetBucketLoggingOutput, error)
	GetBucketLifecycleConfiguration(ctx context.Context, params *s3.GetBucketLifecycleConfigurationInput, optFns ...func(*s3.Options)) (*s3.GetBucketLifecycleConfigurationOutput, error)
	GetPublicAccessBlock(ctx context.Context, params *s3.GetPublicAccessBlockInput, optFns ...func(*s3.Options)) (*s3.GetPublicAccessBlockOutput, error)
}

// S3ControlAPI is the narrow account-level S3 Control operation used for the
// account-wide Public Access Block assessment.
type S3ControlAPI interface {
	GetPublicAccessBlock(ctx context.Context, params *s3control.GetPublicAccessBlockInput, optFns ...func(*s3control.Options)) (*s3control.GetPublicAccessBlockOutput, error)
}

// STSAPI is the narrow STS surface used to resolve the assumed role's account
// ID for account-level assessments.
type STSAPI interface {
	AssumeRole(ctx context.Context, params *sts.AssumeRoleInput, optFns ...func(*sts.Options)) (*sts.AssumeRoleOutput, error)
	GetCallerIdentity(ctx context.Context, params *sts.GetCallerIdentityInput, optFns ...func(*sts.Options)) (*sts.GetCallerIdentityOutput, error)
}

// ClientFactory builds regional S3 clients and the S3 Control client from an
// authenticated session. Clients are created per region because buckets can
// live in different regions; the SDK clients are never recreated per object.
type ClientFactory interface {
	// S3 returns a client for the given region. Clients are cached and share a
	// single HTTP transport so connections are reused across requests.
	S3(region string) S3API
	// S3Control returns the account-level S3 Control client.
	S3Control() S3ControlAPI
}

// sdkClientFactory is the production implementation backed by the AWS SDK.
type sdkClientFactory struct {
	base      awssdk.Config
	mu        sync.Mutex
	s3        map[string]*s3.Client
	control   *s3control.Client
	transport *http.Transport
}

// newSDKClientFactoryFromSession builds a ClientFactory from an authenticated
// session. It configures a shared bounded HTTP transport, the standard retry
// mode with bounded attempts, and per-region client caching.
func newSDKClientFactoryFromSession(s *Session) ClientFactory {
	cfg := s.Config
	transport := &http.Transport{
		Proxy:               http.ProxyFromEnvironment,
		MaxIdleConns:        32,
		MaxIdleConnsPerHost: 8,
		IdleConnTimeout:     90 * time.Second,
	}
	cfg.HTTPClient = &http.Client{Transport: transport}
	cfg.RetryMode = awssdk.RetryModeStandard
	cfg.RetryMaxAttempts = 3

	return &sdkClientFactory{
		base:      cfg,
		s3:        make(map[string]*s3.Client),
		transport: transport,
	}
}

func (f *sdkClientFactory) S3(region string) S3API {
	f.mu.Lock()
	defer f.mu.Unlock()
	if c, ok := f.s3[region]; ok {
		return c
	}
	opts := []func(*s3.Options){func(o *s3.Options) { o.Region = region }}
	client := s3.NewFromConfig(f.base, opts...)
	f.s3[region] = client
	return client
}

func (f *sdkClientFactory) S3Control() S3ControlAPI {
	f.mu.Lock()
	defer f.mu.Unlock()
	if f.control != nil {
		return f.control
	}
	f.control = s3control.NewFromConfig(f.base)
	return f.control
}

// Close releases the shared transport idle connections. It is safe to call
// multiple times.
func (f *sdkClientFactory) Close() {
	if f.transport != nil {
		f.transport.CloseIdleConnections()
	}
}