package aws

import (
	"context"
	"testing"

	awssdk "github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/s3"
	"github.com/aws/aws-sdk-go-v2/service/s3/types"
)

func bucketList(buckets ...string) *s3.ListBucketsOutput {
	out := &s3.ListBucketsOutput{}
	for _, name := range buckets {
		n := name
		out.Buckets = append(out.Buckets, types.Bucket{Name: &n})
	}
	return out
}

func TestDiscoverBucketsNoBuckets(t *testing.T) {
	client := &stubS3{onListBuckets: func(context.Context, *s3.ListBucketsInput) (*s3.ListBucketsOutput, error) {
		return &s3.ListBucketsOutput{}, nil
	}}
	factory := &fakeFactory{s3: map[string]*stubS3{"us-east-1": client}}

	buckets, truncated, errs := discoverBuckets(context.Background(), factory, 100)
	if len(buckets) != 0 {
		t.Fatalf("expected no buckets, got %d", len(buckets))
	}
	if truncated {
		t.Fatal("expected no truncation")
	}
	if len(errs) != 0 {
		t.Fatalf("unexpected errors: %v", errs)
	}
}

func TestDiscoverBucketsMultipleRegionsAndLegacyLocation(t *testing.T) {
	client := &stubS3{
		onListBuckets: func(context.Context, *s3.ListBucketsInput) (*s3.ListBucketsOutput, error) {
			return bucketList("z-bucket", "a-bucket", "e-bucket"), nil
		},
		onGetBucketLocation: func(_ context.Context, params *s3.GetBucketLocationInput) (*s3.GetBucketLocationOutput, error) {
			switch *params.Bucket {
			case "a-bucket":
				return &s3.GetBucketLocationOutput{}, nil // legacy empty => us-east-1
			case "e-bucket":
				return &s3.GetBucketLocationOutput{LocationConstraint: "EU"}, nil // legacy EU => eu-west-1
			case "z-bucket":
				return &s3.GetBucketLocationOutput{LocationConstraint: "ap-southeast-2"}, nil
			}
			return &s3.GetBucketLocationOutput{}, awsErr("NoSuchBucket")
		},
	}
	factory := &fakeFactory{s3: map[string]*stubS3{"us-east-1": client}}

	buckets, _, errs := discoverBuckets(context.Background(), factory, 100)
	if len(errs) != 0 {
		t.Fatalf("unexpected errors: %v", errs)
	}
	if len(buckets) != 3 {
		t.Fatalf("expected 3 buckets, got %d", len(buckets))
	}
	// Deterministic order: sorted by name.
	want := []bucket{
		{name: "a-bucket", region: "us-east-1"},
		{name: "e-bucket", region: "eu-west-1"},
		{name: "z-bucket", region: "ap-southeast-2"},
	}
	for i, w := range want {
		if buckets[i] != w {
			t.Errorf("bucket[%d] = %+v, want %+v", i, buckets[i], w)
		}
	}
}

func TestDiscoverBucketsPagination(t *testing.T) {
	calls := 0
	client := &stubS3{
		onListBuckets: func(_ context.Context, params *s3.ListBucketsInput) (*s3.ListBucketsOutput, error) {
			calls++
			switch calls {
			case 1:
				if params.ContinuationToken != nil {
					t.Fatal("first call must not set a continuation token")
				}
				return &s3.ListBucketsOutput{
					Buckets:          []types.Bucket{{Name: awssdk.String("first-page")}},
					ContinuationToken: awssdk.String("tok-1"),
				}, nil
			case 2:
				if params.ContinuationToken == nil || *params.ContinuationToken != "tok-1" {
					t.Fatalf("expected continuation token tok-1, got %v", params.ContinuationToken)
				}
				return &s3.ListBucketsOutput{
					Buckets: []types.Bucket{{Name: awssdk.String("second-page")}},
				}, nil
			}
			return nil, awsErr("UnexpectedCall")
		},
		onGetBucketLocation: func(_ context.Context, params *s3.GetBucketLocationInput) (*s3.GetBucketLocationOutput, error) {
			return &s3.GetBucketLocationOutput{}, nil
		},
	}
	factory := &fakeFactory{s3: map[string]*stubS3{"us-east-1": client}}

	buckets, _, errs := discoverBuckets(context.Background(), factory, 100)
	if len(errs) != 0 {
		t.Fatalf("unexpected errors: %v", errs)
	}
	if len(buckets) != 2 {
		t.Fatalf("expected 2 buckets, got %d", len(buckets))
	}
	if buckets[0].name != "first-page" || buckets[1].name != "second-page" {
		t.Fatalf("unexpected bucket order: %v", buckets)
	}
}

func TestDiscoverBucketsMaximumLimit(t *testing.T) {
	client := &stubS3{
		onListBuckets: func(context.Context, *s3.ListBucketsInput) (*s3.ListBucketsOutput, error) {
			return bucketList("b3", "b1", "b2", "b4"), nil
		},
		onGetBucketLocation: func(_ context.Context, params *s3.GetBucketLocationInput) (*s3.GetBucketLocationOutput, error) {
			return &s3.GetBucketLocationOutput{}, nil
		},
	}
	factory := &fakeFactory{s3: map[string]*stubS3{"us-east-1": client}}

	buckets, truncated, _ := discoverBuckets(context.Background(), factory, 2)
	if !truncated {
		t.Fatal("expected truncation when limit is reached")
	}
	if len(buckets) != 2 {
		t.Fatalf("expected 2 buckets, got %d", len(buckets))
	}
	// Deterministic prefix selection: the two lexicographically smallest names.
	if buckets[0].name != "b1" || buckets[1].name != "b2" {
		t.Fatalf("unexpected deterministic prefix: %v", buckets)
	}
}

func TestDiscoverBucketsSkipsUnsupportedTypes(t *testing.T) {
	client := &stubS3{
		onListBuckets: func(context.Context, *s3.ListBucketsInput) (*s3.ListBucketsOutput, error) {
			return bucketList("normal-bucket", "directory-bucket--x-s3"), nil
		},
		onGetBucketLocation: func(_ context.Context, params *s3.GetBucketLocationInput) (*s3.GetBucketLocationOutput, error) {
			return &s3.GetBucketLocationOutput{}, nil
		},
	}
	factory := &fakeFactory{s3: map[string]*stubS3{"us-east-1": client}}

	buckets, _, errs := discoverBuckets(context.Background(), factory, 100)
	if len(buckets) != 1 || buckets[0].name != "normal-bucket" {
		t.Fatalf("unexpected buckets: %v", buckets)
	}
	foundUnsupported := false
	for _, e := range errs {
		if e.category == "unsupported" && e.resource == "directory-bucket--x-s3" {
			foundUnsupported = true
		}
	}
	if !foundUnsupported {
		t.Fatalf("expected an explicit unsupported error for the directory bucket, got %v", errs)
	}
}