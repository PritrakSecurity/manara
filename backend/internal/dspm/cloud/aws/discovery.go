package aws

import (
	"context"
	"sort"
	"strings"

	awssdk "github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/s3"
)

// bucket identifies a discovered bucket and the region its data APIs must
// target. Buckets can live in different regions, so a regional client is used
// per bucket.
type bucket struct {
	name   string
	region string
}

// discoverBuckets lists accessible general-purpose buckets, resolves each
// bucket's region, and returns them sorted by name. The result is truncated at
// the configured maximum with the truncation flag set. Unsupported bucket types
// (for example S3 Express directory buckets) are skipped with an explicit
// unsupported error rather than being assumed to be regular buckets.
func discoverBuckets(ctx context.Context, factory ClientFactory, maxBuckets int) ([]bucket, bool, []*scanError) {
	var errs []*scanError
	client := factory.S3("us-east-1")

	// Collect all bucket names first so the deterministic prefix (sorted) is
	// selected for scanning, regardless of the order ListBuckets returns.
	var names []string
	token := ""
	for {
		params := &s3.ListBucketsInput{}
		if token != "" {
			params.ContinuationToken = awssdk.String(token)
		}
		out, err := client.ListBuckets(ctx, params)
		if err != nil {
			errs = append(errs, awsErrorToScanError("discovery", "buckets", err))
			return nil, false, errs
		}
		for _, b := range out.Buckets {
			if b.Name == nil || *b.Name == "" {
				continue
			}
			if strings.HasSuffix(*b.Name, "--x-s3") {
				errs = append(errs, &scanError{scope: "discovery", resource: *b.Name, category: "unsupported", retryable: false, message: "S3 Express directory buckets are not supported"})
				continue
			}
			names = append(names, *b.Name)
		}
		if out.ContinuationToken == nil || *out.ContinuationToken == "" {
			break
		}
		token = *out.ContinuationToken
	}
	sort.Strings(names)

	truncated := false
	if maxBuckets > 0 && len(names) > maxBuckets {
		names = names[:maxBuckets]
		truncated = true
	}

	buckets := make([]bucket, 0, len(names))
	for _, name := range names {
		region, err := bucketRegion(ctx, client, name)
		if err != nil {
			if isUnsupportedBucketError(err) {
				errs = append(errs, &scanError{scope: "discovery", resource: name, category: "unsupported", retryable: false, message: "bucket type is unsupported"})
			} else {
				errs = append(errs, awsErrorToScanError("discovery", name, err))
			}
			continue
		}
		if region == "" {
			errs = append(errs, &scanError{scope: "discovery", resource: name, category: "unsupported", retryable: false, message: "could not resolve bucket region"})
			continue
		}
		buckets = append(buckets, bucket{name: name, region: region})
	}

	sort.Slice(buckets, func(i, j int) bool { return buckets[i].name < buckets[j].name })
	return buckets, truncated, errs
}

// bucketRegion resolves a bucket's home region using GetBucketLocation. It
// handles the historical empty result (us-east-1) and the legacy "EU" value
// (eu-west-1). GetBucketLocation succeeds for general-purpose buckets from any
// region, so a single client in the connector's default region is sufficient.
func bucketRegion(ctx context.Context, client S3API, name string) (string, error) {
	out, err := client.GetBucketLocation(ctx, &s3.GetBucketLocationInput{Bucket: awssdk.String(name)})
	if err != nil {
		return "", err
	}
	switch string(out.LocationConstraint) {
	case "":
		return "us-east-1", nil
	case "EU":
		return "eu-west-1", nil
	default:
		return string(out.LocationConstraint), nil
	}
}