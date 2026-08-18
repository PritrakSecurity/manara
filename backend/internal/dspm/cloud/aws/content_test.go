package aws

import (
	"archive/zip"
	"bytes"
	"context"
	"io"
	"strconv"
	"strings"
	"sync"
	"testing"
	"time"

	awssdk "github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/s3"
	s3types "github.com/aws/aws-sdk-go-v2/service/s3/types"

	"manara-dlp/internal/classification"
	"manara-dlp/internal/dspm/cloud"
)

func contentConnector(factory *fakeFactory) *S3Connector {
	auth := &fakeAuth{session: testSession()}
	scanner := classification.NewContentScanner()
	scanner.SetMaxFileSize(int64(MaxObjectBytesAllowed))
	return newS3Connector(AWSConfig{}, auth, func(*Session) ClientFactory { return factory }, classification.NewClassificationEngine(), scanner, nil)
}

func defaultScanRequest() cloud.ScanRequest {
	return cloud.ScanRequest{
		ScanID:              "test-scan",
		MaxBuckets:          100,
		MaxObjectsPerBucket: 100,
		MaxObjectBytes:      10 * 1024 * 1024,
		MaxSampleBytes:      1 * 1024 * 1024,
	}
}

func makeDocx(t *testing.T, text string) []byte {
	t.Helper()
	var buf bytes.Buffer
	w := zip.NewWriter(&buf)
	f, err := w.Create("word/document.xml")
	if err != nil {
		t.Fatalf("failed to create docx entry: %v", err)
	}
	_, err = f.Write([]byte("<w:document><w:body><w:p><w:r><w:t>" + text + "</w:t></w:r></w:p></w:body></w:document>"))
	if err != nil {
		t.Fatalf("failed to write docx: %v", err)
	}
	if err := w.Close(); err != nil {
		t.Fatalf("failed to close zip: %v", err)
	}
	return buf.Bytes()
}

func findContentFinding(t *testing.T, result cloud.ScanResult, key string) *cloud.Finding {
	t.Helper()
	for i := range result.Findings {
		if result.Findings[i].ResourceID == "b/"+key {
			return &result.Findings[i]
		}
	}
	return nil
}

func TestScanContentTextPrefixScan(t *testing.T) {
	client := &stubS3{
		onListBuckets: func(context.Context, *s3.ListBucketsInput) (*s3.ListBucketsOutput, error) {
			return bucketList("b"), nil
		},
		onGetBucketLocation: func(context.Context, *s3.GetBucketLocationInput) (*s3.GetBucketLocationOutput, error) {
			return &s3.GetBucketLocationOutput{}, nil
		},
		onListObjectsV2: func(context.Context, *s3.ListObjectsV2Input) (*s3.ListObjectsV2Output, error) {
			return &s3.ListObjectsV2Output{Contents: []s3types.Object{{Key: awssdk.String("notes.txt"), Size: awssdk.Int64(2 * 1024 * 1024)}}}, nil
		},
		onHeadObject: func(_ context.Context, params *s3.HeadObjectInput) (*s3.HeadObjectOutput, error) {
			return &s3.HeadObjectOutput{ContentLength: awssdk.Int64(2 * 1024 * 1024), ContentType: awssdk.String("text/plain"), StorageClass: s3types.StorageClassStandard}, nil
		},
		onGetObject: func(_ context.Context, params *s3.GetObjectInput) (*s3.GetObjectOutput, error) {
			if params.Range == nil {
				t.Fatal("prefix scan must request a Range")
			}
			if *params.Range != "bytes=0-1048575" {
				t.Fatalf("unexpected range %q", *params.Range)
			}
			return &s3.GetObjectOutput{Body: io.NopCloser(strings.NewReader(strings.Repeat("public data ", 10000)))}, nil
		},
	}
	conn := contentConnector(&fakeFactory{s3: map[string]*stubS3{"us-east-1": client}})

	result := conn.ScanContent(context.Background(), defaultScanRequest())
	if result.CompletedAt.Before(result.StartedAt) {
		t.Fatal("completed before started")
	}
	f := findContentFinding(t, result, "notes.txt")
	if f == nil {
		t.Fatalf("missing finding for notes.txt: %+v", result.Findings)
	}
	// Prefix-only scan of PUBLIC content cannot be claimed clean.
	if f.Status != cloud.StatusUnknown {
		t.Errorf("expected unknown status for prefix-only scan, got %s", f.Status)
	}
	if f.Evidence["coverage"] != coveragePrefix {
		t.Errorf("expected prefix coverage, got %s", f.Evidence["coverage"])
	}
	if f.Evidence["reason"] != "prefix_only" {
		t.Errorf("expected prefix_only reason, got %q", f.Evidence["reason"])
	}
}

func TestScanContentObjectSmallerThanSampleIsFull(t *testing.T) {
	body := []byte("small complete content")
	client := &stubS3{
		onListBuckets: func(context.Context, *s3.ListBucketsInput) (*s3.ListBucketsOutput, error) {
			return bucketList("b"), nil
		},
		onGetBucketLocation: func(context.Context, *s3.GetBucketLocationInput) (*s3.GetBucketLocationOutput, error) {
			return &s3.GetBucketLocationOutput{}, nil
		},
		onListObjectsV2: func(context.Context, *s3.ListObjectsV2Input) (*s3.ListObjectsV2Output, error) {
			return &s3.ListObjectsV2Output{Contents: []s3types.Object{{Key: awssdk.String("small.txt"), Size: awssdk.Int64(int64(len(body)))}}}, nil
		},
		onHeadObject: func(_ context.Context, params *s3.HeadObjectInput) (*s3.HeadObjectOutput, error) {
			return &s3.HeadObjectOutput{ContentLength: awssdk.Int64(int64(len(body))), ContentType: awssdk.String("text/plain")}, nil
		},
		onGetObject: func(_ context.Context, params *s3.GetObjectInput) (*s3.GetObjectOutput, error) {
			if *params.Range != "bytes=0-21" { // size-1
				t.Fatalf("unexpected range %q", *params.Range)
			}
			return &s3.GetObjectOutput{Body: io.NopCloser(bytes.NewReader(body))}, nil
		},
	}
	conn := contentConnector(&fakeFactory{s3: map[string]*stubS3{"us-east-1": client}})
	result := conn.ScanContent(context.Background(), defaultScanRequest())
	f := findContentFinding(t, result, "small.txt")
	if f == nil {
		t.Fatalf("missing finding: %+v", result.Findings)
	}
	if f.Evidence["coverage"] != coverageFull {
		t.Errorf("expected full coverage for an object smaller than the sample, got %s", f.Evidence["coverage"])
	}
	// Full scan of PUBLIC content is compliant.
	if f.Status != cloud.StatusCompliant {
		t.Errorf("expected compliant, got %s", f.Status)
	}
}

func TestScanContentServerIgnoresRange(t *testing.T) {
	// The server returns the entire 2 MiB object even though a 1 MiB Range was
	// requested. io.LimitReader must cap the read.
	big := bytes.Repeat([]byte("x"), 2*1024*1024)
	client := &stubS3{
		onListBuckets: func(context.Context, *s3.ListBucketsInput) (*s3.ListBucketsOutput, error) {
			return bucketList("b"), nil
		},
		onGetBucketLocation: func(context.Context, *s3.GetBucketLocationInput) (*s3.GetBucketLocationOutput, error) {
			return &s3.GetBucketLocationOutput{}, nil
		},
		onListObjectsV2: func(context.Context, *s3.ListObjectsV2Input) (*s3.ListObjectsV2Output, error) {
			return &s3.ListObjectsV2Output{Contents: []s3types.Object{{Key: awssdk.String("big.txt"), Size: awssdk.Int64(2 * 1024 * 1024)}}}, nil
		},
		onHeadObject: func(context.Context, *s3.HeadObjectInput) (*s3.HeadObjectOutput, error) {
			return &s3.HeadObjectOutput{ContentLength: awssdk.Int64(2 * 1024 * 1024), ContentType: awssdk.String("text/plain")}, nil
		},
		onGetObject: func(context.Context, *s3.GetObjectInput) (*s3.GetObjectOutput, error) {
			return &s3.GetObjectOutput{Body: io.NopCloser(bytes.NewReader(big))}, nil
		},
	}
	conn := contentConnector(&fakeFactory{s3: map[string]*stubS3{"us-east-1": client}})
	result := conn.ScanContent(context.Background(), defaultScanRequest())
	f := findContentFinding(t, result, "big.txt")
	if f == nil {
		t.Fatalf("missing finding: %+v", result.Findings)
	}
	if f.Evidence["coverage"] != coveragePrefix {
		t.Errorf("expected prefix coverage, got %s", f.Evidence["coverage"])
	}
}

func TestScanContentStructuredFullDownload(t *testing.T) {
	docx := makeDocx(t, "SSN 123-45-6789")
	client := &stubS3{
		onListBuckets: func(context.Context, *s3.ListBucketsInput) (*s3.ListBucketsOutput, error) {
			return bucketList("b"), nil
		},
		onGetBucketLocation: func(context.Context, *s3.GetBucketLocationInput) (*s3.GetBucketLocationOutput, error) {
			return &s3.GetBucketLocationOutput{}, nil
		},
		onListObjectsV2: func(context.Context, *s3.ListObjectsV2Input) (*s3.ListObjectsV2Output, error) {
			return &s3.ListObjectsV2Output{Contents: []s3types.Object{{Key: awssdk.String("report.docx"), Size: awssdk.Int64(int64(len(docx)))}}}, nil
		},
		onHeadObject: func(context.Context, *s3.HeadObjectInput) (*s3.HeadObjectOutput, error) {
			return &s3.HeadObjectOutput{ContentLength: awssdk.Int64(int64(len(docx))), ContentType: awssdk.String("application/vnd.openxmlformats-officedocument.wordprocessingml.document")}, nil
		},
		onGetObject: func(_ context.Context, params *s3.GetObjectInput) (*s3.GetObjectOutput, error) {
			if params.Range != nil {
				t.Fatal("structured full download must not set a Range")
			}
			return &s3.GetObjectOutput{Body: io.NopCloser(bytes.NewReader(docx))}, nil
		},
	}
	conn := contentConnector(&fakeFactory{s3: map[string]*stubS3{"us-east-1": client}})
	result := conn.ScanContent(context.Background(), defaultScanRequest())
	f := findContentFinding(t, result, "report.docx")
	if f == nil {
		t.Fatalf("missing finding: %+v", result.Findings)
	}
	if f.Evidence["coverage"] != coverageFull {
		t.Errorf("expected full coverage, got %s", f.Evidence["coverage"])
	}
	if f.Status != cloud.StatusNonCompliant {
		t.Errorf("SSN-bearing content must be noncompliant, got %s", f.Status)
	}
	if f.Severity != cloud.SeverityCritical {
		t.Errorf("expected critical severity, got %s", f.Severity)
	}
}

func TestScanContentOversizedStructuredSkipped(t *testing.T) {
	client := &stubS3{
		onListBuckets: func(context.Context, *s3.ListBucketsInput) (*s3.ListBucketsOutput, error) {
			return bucketList("b"), nil
		},
		onGetBucketLocation: func(context.Context, *s3.GetBucketLocationInput) (*s3.GetBucketLocationOutput, error) {
			return &s3.GetBucketLocationOutput{}, nil
		},
		onListObjectsV2: func(context.Context, *s3.ListObjectsV2Input) (*s3.ListObjectsV2Output, error) {
			return &s3.ListObjectsV2Output{Contents: []s3types.Object{{Key: awssdk.String("huge.pptx"), Size: awssdk.Int64(50 * 1024 * 1024)}}}, nil
		},
		onHeadObject: func(context.Context, *s3.HeadObjectInput) (*s3.HeadObjectOutput, error) {
			return &s3.HeadObjectOutput{ContentLength: awssdk.Int64(50 * 1024 * 1024), ContentType: awssdk.String("application/vnd.openxmlformats-officedocument.presentationml.presentation")}, nil
		},
		onGetObject: func(context.Context, *s3.GetObjectInput) (*s3.GetObjectOutput, error) {
			t.Fatal("GetObject must not be called for an oversized structured object")
			return nil, nil
		},
	}
	conn := contentConnector(&fakeFactory{s3: map[string]*stubS3{"us-east-1": client}})
	result := conn.ScanContent(context.Background(), defaultScanRequest())
	f := findContentFinding(t, result, "huge.pptx")
	if f == nil {
		t.Fatalf("missing finding: %+v", result.Findings)
	}
	if f.Status != cloud.StatusUnsupported {
		t.Errorf("expected unsupported, got %s", f.Status)
	}
	if f.Evidence["reason"] != "object_too_large_for_structured_scan" {
		t.Errorf("unexpected reason %q", f.Evidence["reason"])
	}
	if f.Evidence["coverage"] != coverageSkipped {
		t.Errorf("expected skipped coverage, got %s", f.Evidence["coverage"])
	}
}

func TestScanContentArchivedSkipped(t *testing.T) {
	client := &stubS3{
		onListBuckets: func(context.Context, *s3.ListBucketsInput) (*s3.ListBucketsOutput, error) {
			return bucketList("b"), nil
		},
		onGetBucketLocation: func(context.Context, *s3.GetBucketLocationInput) (*s3.GetBucketLocationOutput, error) {
			return &s3.GetBucketLocationOutput{}, nil
		},
		onListObjectsV2: func(context.Context, *s3.ListObjectsV2Input) (*s3.ListObjectsV2Output, error) {
			return &s3.ListObjectsV2Output{Contents: []s3types.Object{{Key: awssdk.String("old.txt"), Size: awssdk.Int64(100)}}}, nil
		},
		onHeadObject: func(context.Context, *s3.HeadObjectInput) (*s3.HeadObjectOutput, error) {
			return &s3.HeadObjectOutput{ContentLength: awssdk.Int64(100), StorageClass: s3types.StorageClassGlacier}, nil
		},
		onGetObject: func(context.Context, *s3.GetObjectInput) (*s3.GetObjectOutput, error) {
			t.Fatal("GetObject must not be called for an archived object")
			return nil, nil
		},
	}
	conn := contentConnector(&fakeFactory{s3: map[string]*stubS3{"us-east-1": client}})
	result := conn.ScanContent(context.Background(), defaultScanRequest())
	f := findContentFinding(t, result, "old.txt")
	if f == nil {
		t.Fatalf("missing finding: %+v", result.Findings)
	}
	if f.Status != cloud.StatusUnsupported {
		t.Errorf("expected unsupported, got %s", f.Status)
	}
	if f.Evidence["reason"] != "archived_storage_class" {
		t.Errorf("unexpected reason %q", f.Evidence["reason"])
	}
}

func TestScanContentPaginationAndObjectLimit(t *testing.T) {
	calls := 0
	client := &stubS3{
		onListBuckets: func(context.Context, *s3.ListBucketsInput) (*s3.ListBucketsOutput, error) {
			return bucketList("b"), nil
		},
		onGetBucketLocation: func(context.Context, *s3.GetBucketLocationInput) (*s3.GetBucketLocationOutput, error) {
			return &s3.GetBucketLocationOutput{}, nil
		},
		onListObjectsV2: func(_ context.Context, params *s3.ListObjectsV2Input) (*s3.ListObjectsV2Output, error) {
			calls++
			out := &s3.ListObjectsV2Output{Contents: []s3types.Object{
				{Key: awssdk.String("obj-1"), Size: awssdk.Int64(3)},
				{Key: awssdk.String("obj-2"), Size: awssdk.Int64(3)},
				{Key: awssdk.String("obj-3"), Size: awssdk.Int64(3)},
			}}
			if calls == 1 {
				out.NextContinuationToken = awssdk.String("tok-2")
			}
			return out, nil
		},
		onHeadObject: func(_ context.Context, params *s3.HeadObjectInput) (*s3.HeadObjectOutput, error) {
			return &s3.HeadObjectOutput{ContentLength: awssdk.Int64(3), ContentType: awssdk.String("text/plain")}, nil
		},
		onGetObject: func(context.Context, *s3.GetObjectInput) (*s3.GetObjectOutput, error) {
			return &s3.GetObjectOutput{Body: io.NopCloser(strings.NewReader("abc"))}, nil
		},
	}
	conn := contentConnector(&fakeFactory{s3: map[string]*stubS3{"us-east-1": client}})

	req := defaultScanRequest()
	req.MaxObjectsPerBucket = 2
	result := conn.ScanContent(context.Background(), req)

	if calls != 1 {
		t.Fatalf("expected pagination to stop immediately once the limit is reached, got %d calls", calls)
	}
	if !result.Truncated {
		t.Error("expected truncated=true when object limit is reached")
	}
	if len(result.Findings) != 2 {
		t.Fatalf("expected 2 object findings, got %d", len(result.Findings))
	}
}

func TestScanContentClassifierFailure(t *testing.T) {
	client := &stubS3{
		onListBuckets: func(context.Context, *s3.ListBucketsInput) (*s3.ListBucketsOutput, error) {
			return bucketList("b"), nil
		},
		onGetBucketLocation: func(context.Context, *s3.GetBucketLocationInput) (*s3.GetBucketLocationOutput, error) {
			return &s3.GetBucketLocationOutput{}, nil
		},
		onListObjectsV2: func(context.Context, *s3.ListObjectsV2Input) (*s3.ListObjectsV2Output, error) {
			return &s3.ListObjectsV2Output{Contents: []s3types.Object{{Key: awssdk.String("blob.bin"), Size: awssdk.Int64(64)}}}, nil
		},
		onHeadObject: func(context.Context, *s3.HeadObjectInput) (*s3.HeadObjectOutput, error) {
			return &s3.HeadObjectOutput{ContentLength: awssdk.Int64(64), ContentType: awssdk.String("application/octet-stream")}, nil
		},
		onGetObject: func(context.Context, *s3.GetObjectInput) (*s3.GetObjectOutput, error) {
			return &s3.GetObjectOutput{Body: io.NopCloser(bytes.NewReader([]byte{0x00, 0x01, 0x02, 0x03, 0xFF}))}, nil
		},
	}
	conn := contentConnector(&fakeFactory{s3: map[string]*stubS3{"us-east-1": client}})
	result := conn.ScanContent(context.Background(), defaultScanRequest())
	f := findContentFinding(t, result, "blob.bin")
	if f == nil {
		t.Fatalf("missing finding: %+v", result.Findings)
	}
	if f.Status != cloud.StatusUnknown {
		t.Errorf("expected unknown for unreadable content, got %s", f.Status)
	}
	if f.Evidence["reason"] != "content_unreadable" {
		t.Errorf("unexpected reason %q", f.Evidence["reason"])
	}
}

func TestScanContentFindingsAreRedacted(t *testing.T) {
	sensitive := "SSN 123-45-6789 and credit card 4532015112830366"
	client := &stubS3{
		onListBuckets: func(context.Context, *s3.ListBucketsInput) (*s3.ListBucketsOutput, error) {
			return bucketList("b"), nil
		},
		onGetBucketLocation: func(context.Context, *s3.GetBucketLocationInput) (*s3.GetBucketLocationOutput, error) {
			return &s3.GetBucketLocationOutput{}, nil
		},
		onListObjectsV2: func(context.Context, *s3.ListObjectsV2Input) (*s3.ListObjectsV2Output, error) {
			return &s3.ListObjectsV2Output{Contents: []s3types.Object{{Key: awssdk.String("pii.txt"), Size: awssdk.Int64(int64(len(sensitive)))}}}, nil
		},
		onHeadObject: func(context.Context, *s3.HeadObjectInput) (*s3.HeadObjectOutput, error) {
			return &s3.HeadObjectOutput{ContentLength: awssdk.Int64(int64(len(sensitive))), ContentType: awssdk.String("text/plain")}, nil
		},
		onGetObject: func(context.Context, *s3.GetObjectInput) (*s3.GetObjectOutput, error) {
			return &s3.GetObjectOutput{Body: io.NopCloser(strings.NewReader(sensitive))}, nil
		},
	}
	conn := contentConnector(&fakeFactory{s3: map[string]*stubS3{"us-east-1": client}})
	result := conn.ScanContent(context.Background(), defaultScanRequest())
	f := findContentFinding(t, result, "pii.txt")
	if f == nil {
		t.Fatalf("missing finding: %+v", result.Findings)
	}
	for k, v := range f.Evidence {
		if strings.Contains(k, "123-45-6789") || strings.Contains(v, "123-45-6789") ||
			strings.Contains(k, "4532015112830366") || strings.Contains(v, "4532015112830366") {
			t.Fatalf("finding evidence leaked raw PII: %s=%s", k, v)
		}
	}
	// The finding must still surface the risk, not the data.
	if f.Status != cloud.StatusNonCompliant {
		t.Errorf("PII-bearing content must be noncompliant, got %s", f.Status)
	}
}

func TestScanContentResponseBodyAlwaysClosed(t *testing.T) {
	var mu sync.Mutex
	bodies := []*trackCloser{}
	newBody := func() *trackCloser {
		b := &trackCloser{Reader: strings.NewReader("hello world public")}
		mu.Lock()
		bodies = append(bodies, b)
		mu.Unlock()
		return b
	}
	client := &stubS3{
		onListBuckets: func(context.Context, *s3.ListBucketsInput) (*s3.ListBucketsOutput, error) {
			return bucketList("b"), nil
		},
		onGetBucketLocation: func(context.Context, *s3.GetBucketLocationInput) (*s3.GetBucketLocationOutput, error) {
			return &s3.GetBucketLocationOutput{}, nil
		},
		onListObjectsV2: func(context.Context, *s3.ListObjectsV2Input) (*s3.ListObjectsV2Output, error) {
			return &s3.ListObjectsV2Output{Contents: []s3types.Object{{Key: awssdk.String("a.txt"), Size: awssdk.Int64(17)}, {Key: awssdk.String("b.txt"), Size: awssdk.Int64(17)}}}, nil
		},
		onHeadObject: func(context.Context, *s3.HeadObjectInput) (*s3.HeadObjectOutput, error) {
			return &s3.HeadObjectOutput{ContentLength: awssdk.Int64(17), ContentType: awssdk.String("text/plain")}, nil
		},
		onGetObject: func(context.Context, *s3.GetObjectInput) (*s3.GetObjectOutput, error) {
			return &s3.GetObjectOutput{Body: newBody()}, nil
		},
	}
	conn := contentConnector(&fakeFactory{s3: map[string]*stubS3{"us-east-1": client}})
	result := conn.ScanContent(context.Background(), defaultScanRequest())
	if len(result.Findings) != 2 {
		t.Fatalf("expected 2 findings, got %d", len(result.Findings))
	}
	mu.Lock()
	defer mu.Unlock()
	for i, b := range bodies {
		if !b.closed {
			t.Errorf("response body %d was not closed", i)
		}
	}
}

func TestScanContentCancellation(t *testing.T) {
	client := &stubS3{
		onListBuckets: func(context.Context, *s3.ListBucketsInput) (*s3.ListBucketsOutput, error) {
			return bucketList("b"), nil
		},
		onGetBucketLocation: func(context.Context, *s3.GetBucketLocationInput) (*s3.GetBucketLocationOutput, error) {
			return &s3.GetBucketLocationOutput{}, nil
		},
		onListObjectsV2: func(context.Context, *s3.ListObjectsV2Input) (*s3.ListObjectsV2Output, error) {
			return &s3.ListObjectsV2Output{Contents: []s3types.Object{{Key: awssdk.String("blocked.txt"), Size: awssdk.Int64(100)}}}, nil
		},
		onHeadObject: func(context.Context, *s3.HeadObjectInput) (*s3.HeadObjectOutput, error) {
			return &s3.HeadObjectOutput{ContentLength: awssdk.Int64(100), ContentType: awssdk.String("text/plain")}, nil
		},
		onGetObject: func(ctx context.Context, params *s3.GetObjectInput) (*s3.GetObjectOutput, error) {
			<-ctx.Done()
			return nil, ctx.Err()
		},
	}
	conn := contentConnector(&fakeFactory{s3: map[string]*stubS3{"us-east-1": client}})

	ctx, cancel := context.WithTimeout(context.Background(), 50*time.Millisecond)
	defer cancel()

	done := make(chan struct{})
	go func() {
		conn.ScanContent(ctx, defaultScanRequest())
		close(done)
	}()
	select {
	case <-done:
	case <-time.After(5 * time.Second):
		t.Fatal("scan did not return after context cancellation (possible goroutine leak)")
	}
}

func TestScanContentConcurrentBuckets(t *testing.T) {
	const numBuckets = 20
	const objectsPerBucket = 30
	var bucketNames []string
	for i := 0; i < numBuckets; i++ {
		bucketNames = append(bucketNames, "b-"+strings.Repeat(string(rune('a'+i%26)), 3))
	}
	client := &stubS3{
		onListBuckets: func(context.Context, *s3.ListBucketsInput) (*s3.ListBucketsOutput, error) {
			return bucketList(bucketNames...), nil
		},
		onGetBucketLocation: func(context.Context, *s3.GetBucketLocationInput) (*s3.GetBucketLocationOutput, error) {
			return &s3.GetBucketLocationOutput{}, nil
		},
		onListObjectsV2: func(_ context.Context, params *s3.ListObjectsV2Input) (*s3.ListObjectsV2Output, error) {
			var contents []s3types.Object
			for i := 0; i < objectsPerBucket; i++ {
				key := *params.Bucket + "/obj-" + strconv.Itoa(i)
				contents = append(contents, s3types.Object{Key: awssdk.String(key), Size: awssdk.Int64(4)})
			}
			return &s3.ListObjectsV2Output{Contents: contents}, nil
		},
		onHeadObject: func(context.Context, *s3.HeadObjectInput) (*s3.HeadObjectOutput, error) {
			return &s3.HeadObjectOutput{ContentLength: awssdk.Int64(4), ContentType: awssdk.String("text/plain")}, nil
		},
		onGetObject: func(context.Context, *s3.GetObjectInput) (*s3.GetObjectOutput, error) {
			return &s3.GetObjectOutput{Body: io.NopCloser(strings.NewReader("data"))}, nil
		},
	}
	conn := contentConnector(&fakeFactory{s3: map[string]*stubS3{"us-east-1": client}})

	result := conn.ScanContent(context.Background(), defaultScanRequest())
	// Every object is fully scanned and classified PUBLIC => compliant.
	want := numBuckets * objectsPerBucket
	if len(result.Findings) != want {
		t.Fatalf("expected %d findings, got %d", want, len(result.Findings))
	}
	for _, f := range result.Findings {
		if f.Status != cloud.StatusCompliant {
			t.Fatalf("unexpected status %s for %s", f.Status, f.ResourceID)
		}
	}
}

func TestScanContentBucketFailureDoesNotCancelScan(t *testing.T) {
	client := &stubS3{
		onListBuckets: func(context.Context, *s3.ListBucketsInput) (*s3.ListBucketsOutput, error) {
			return bucketList("bad-bucket", "good-bucket"), nil
		},
		onGetBucketLocation: func(context.Context, *s3.GetBucketLocationInput) (*s3.GetBucketLocationOutput, error) {
			return &s3.GetBucketLocationOutput{}, nil
		},
		onListObjectsV2: func(_ context.Context, params *s3.ListObjectsV2Input) (*s3.ListObjectsV2Output, error) {
			if *params.Bucket == "bad-bucket" {
				return nil, awsErr("AccessDenied")
			}
			return &s3.ListObjectsV2Output{Contents: []s3types.Object{{Key: awssdk.String("ok.txt"), Size: awssdk.Int64(2)}}}, nil
		},
		onHeadObject: func(context.Context, *s3.HeadObjectInput) (*s3.HeadObjectOutput, error) {
			return &s3.HeadObjectOutput{ContentLength: awssdk.Int64(2), ContentType: awssdk.String("text/plain")}, nil
		},
		onGetObject: func(context.Context, *s3.GetObjectInput) (*s3.GetObjectOutput, error) {
			return &s3.GetObjectOutput{Body: io.NopCloser(strings.NewReader("ok"))}, nil
		},
	}
	conn := contentConnector(&fakeFactory{s3: map[string]*stubS3{"us-east-1": client}})
	result := conn.ScanContent(context.Background(), defaultScanRequest())

	if len(result.Findings) != 1 {
		t.Fatalf("expected the good bucket to still be scanned, got %d findings", len(result.Findings))
	}
	// The bad bucket failure is preserved as an error entry.
	foundDenied := false
	for _, e := range result.Errors {
		if e.Resource == "bad-bucket" && e.Category == "access_denied" {
			foundDenied = true
		}
	}
	if !foundDenied {
		t.Fatalf("expected an access_denied error for bad-bucket, got %v", result.Errors)
	}
}

func TestScanContentMislabeledStructuredRedetected(t *testing.T) {
	docx := makeDocx(t, "restricted board meeting notes")
	client := &stubS3{
		onListBuckets: func(context.Context, *s3.ListBucketsInput) (*s3.ListBucketsOutput, error) {
			return bucketList("b"), nil
		},
		onGetBucketLocation: func(context.Context, *s3.GetBucketLocationInput) (*s3.GetBucketLocationOutput, error) {
			return &s3.GetBucketLocationOutput{}, nil
		},
		onListObjectsV2: func(context.Context, *s3.ListObjectsV2Input) (*s3.ListObjectsV2Output, error) {
			return &s3.ListObjectsV2Output{Contents: []s3types.Object{{Key: awssdk.String("weird-name-no-ext"), Size: awssdk.Int64(int64(len(docx)))}}}, nil
		},
		onHeadObject: func(context.Context, *s3.HeadObjectInput) (*s3.HeadObjectOutput, error) {
			return &s3.HeadObjectOutput{ContentLength: awssdk.Int64(int64(len(docx))), ContentType: awssdk.String("application/octet-stream")}, nil
		},
		onGetObject: func(_ context.Context, params *s3.GetObjectInput) (*s3.GetObjectOutput, error) {
			// First call is the prefix sample (Range set), second is the full download.
			if params.Range != nil {
				return &s3.GetObjectOutput{Body: io.NopCloser(bytes.NewReader(docx))}, nil
			}
			return &s3.GetObjectOutput{Body: io.NopCloser(bytes.NewReader(docx))}, nil
		},
	}
	conn := contentConnector(&fakeFactory{s3: map[string]*stubS3{"us-east-1": client}})
	result := conn.ScanContent(context.Background(), defaultScanRequest())
	f := findContentFinding(t, result, "weird-name-no-ext")
	if f == nil {
		t.Fatalf("missing finding: %+v", result.Findings)
	}
	if f.Evidence["coverage"] != coverageFull {
		t.Errorf("expected full coverage after magic-byte redetection, got %s", f.Evidence["coverage"])
	}
	// The container type is unknown, so the honest status is unknown, never
	// compliant. The full download ensures we did not claim clean from a prefix.
	if f.Status != cloud.StatusUnknown {
		t.Errorf("unidentified structured content must be unknown, got %s", f.Status)
	}
	if f.Evidence["reason"] != "content_unreadable" {
		t.Errorf("expected content_unreadable reason, got %q", f.Evidence["reason"])
	}
}
