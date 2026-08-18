package aws

import (
	"fmt"
	"strings"
	"time"

	"manara-dlp/internal/dspm/cloud"
)

// Server-side scan limits. The connector clamps every incoming ScanRequest to
// these bounds; clients can request smaller limits but can never raise them.
const (
	// MaxBucketsAllowed is the hard ceiling for scanned buckets per scan.
	MaxBucketsAllowed = 500
	// MaxObjectsPerBucketAllowed is the hard ceiling for objects sampled per bucket.
	MaxObjectsPerBucketAllowed = 500
	// MaxObjectBytesAllowed is the hard ceiling for a full structured-object download.
	MaxObjectBytesAllowed = 100 * 1024 * 1024
	// MaxSampleBytesAllowed is the hard ceiling for a prefix sample.
	MaxSampleBytesAllowed = 10 * 1024 * 1024
	// MaxConcurrentBuckets bounds how many buckets are processed at once.
	MaxConcurrentBuckets = 5
	// MaxConcurrentObjects bounds the total number of concurrent object downloads.
	MaxConcurrentObjects = 10
	// MaxRequestBodyBytes bounds the scan request JSON body size.
	MaxRequestBodyBytes = 64 * 1024
	// ScanTimeout is the server-side bound for a single synchronous scan.
	ScanTimeout = 5 * time.Minute
	// DefaultSessionDuration is the temporary credential lifetime for AssumeRole.
	DefaultSessionDuration = 1 * time.Hour
	// MaxSessionDuration is the longest allowed AssumeRole session.
	MaxSessionDuration = 12 * time.Hour
)

// AWSConfig configures an AWS S3 DSPM connector.
//
// Production connectors assume a customer role using temporary STS credentials
// and require a unique external ID. Profile-based credentials are accepted only
// when the server explicitly allows local development/tests (AllowProfile) and
// the operator configures a named profile.
type AWSConfig struct {
	RoleARN               string
	ExternalID            string
	Region                string
	RoleSessionNamePrefix string
	Profile               string
	AllowProfile          bool
	MaxBuckets            int
	MaxObjectsPerBucket   int
	MaxObjectBytes        int64
	MaxSampleBytes        int64
}

// ApplyDefaults fills empty optional fields with safe defaults.
func (c *AWSConfig) ApplyDefaults() {
	if c.Region == "" {
		c.Region = "us-east-1"
	}
	if c.RoleSessionNamePrefix == "" {
		c.RoleSessionNamePrefix = "dlp-cloud-scan"
	}
	if c.MaxBuckets <= 0 {
		c.MaxBuckets = 100
	}
	if c.MaxObjectsPerBucket <= 0 {
		c.MaxObjectsPerBucket = 100
	}
	if c.MaxObjectBytes <= 0 {
		c.MaxObjectBytes = 10 * 1024 * 1024
	}
	if c.MaxSampleBytes <= 0 {
		c.MaxSampleBytes = 1 * 1024 * 1024
	}
}

// Validate checks the connector configuration. It returns an error suitable
// for a 400 response when the configuration is malformed.
func (c AWSConfig) Validate() error {
	profileMode := c.AllowProfile && c.Profile != ""
	if !profileMode {
		if strings.TrimSpace(c.RoleARN) == "" {
			return fmt.Errorf("role_arn is required")
		}
		if !strings.HasPrefix(c.RoleARN, "arn:aws:iam::") {
			return fmt.Errorf("role_arn must be a valid AWS IAM role ARN")
		}
		if strings.TrimSpace(c.ExternalID) == "" {
			return fmt.Errorf("external_id is required for cross-account connectors")
		}
	} else {
		if strings.TrimSpace(c.RoleARN) != "" && strings.TrimSpace(c.ExternalID) == "" {
			return fmt.Errorf("external_id is required when assuming a role")
		}
	}
	if c.MaxBuckets < 0 || c.MaxBuckets > MaxBucketsAllowed {
		return fmt.Errorf("max_buckets must be between 1 and %d", MaxBucketsAllowed)
	}
	if c.MaxObjectsPerBucket < 0 || c.MaxObjectsPerBucket > MaxObjectsPerBucketAllowed {
		return fmt.Errorf("max_objects_per_bucket must be between 1 and %d", MaxObjectsPerBucketAllowed)
	}
	if c.MaxObjectBytes < 0 || c.MaxObjectBytes > MaxObjectBytesAllowed {
		return fmt.Errorf("max_object_bytes must be between 1 and %d", MaxObjectBytesAllowed)
	}
	if c.MaxSampleBytes < 0 || c.MaxSampleBytes > MaxSampleBytesAllowed {
		return fmt.Errorf("max_sample_bytes must be between 1 and %d", MaxSampleBytesAllowed)
	}
	return nil
}

// normalizeRequest applies server-side maximums to a caller-supplied request.
// The connector never trusts callers to raise safety limits, so out-of-range
// values are clamped to the allowed ceilings and missing values use defaults.
func normalizeRequest(r cloud.ScanRequest) cloud.ScanRequest {
	out := cloud.ScanRequest{
		ScanID:              r.ScanID,
		MaxBuckets:          r.MaxBuckets,
		MaxObjectsPerBucket: r.MaxObjectsPerBucket,
		MaxObjectBytes:      r.MaxObjectBytes,
		MaxSampleBytes:      r.MaxSampleBytes,
	}
	if out.MaxBuckets <= 0 {
		out.MaxBuckets = 100
	}
	if out.MaxObjectsPerBucket <= 0 {
		out.MaxObjectsPerBucket = 100
	}
	if out.MaxObjectBytes <= 0 {
		out.MaxObjectBytes = 10 * 1024 * 1024
	}
	if out.MaxSampleBytes <= 0 {
		out.MaxSampleBytes = 1 * 1024 * 1024
	}
	if out.MaxBuckets > MaxBucketsAllowed {
		out.MaxBuckets = MaxBucketsAllowed
	}
	if out.MaxObjectsPerBucket > MaxObjectsPerBucketAllowed {
		out.MaxObjectsPerBucket = MaxObjectsPerBucketAllowed
	}
	if out.MaxObjectBytes > MaxObjectBytesAllowed {
		out.MaxObjectBytes = MaxObjectBytesAllowed
	}
	if out.MaxSampleBytes > MaxSampleBytesAllowed {
		out.MaxSampleBytes = MaxSampleBytesAllowed
	}
	return out
}