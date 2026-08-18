package aws

import (
	"bytes"
	"context"
	"fmt"
	"io"
	"path"
	"sort"
	"strconv"
	"strings"
	"sync"
	"time"

	awssdk "github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/s3"
	"golang.org/x/sync/errgroup"

	"manara-dlp/internal/classification"
	"manara-dlp/internal/dspm/cloud"
)

// Content coverage states recorded on findings. A prefix-only scan can never be
// used to claim an object is clean.
const (
	coverageFull    = "full"
	coveragePrefix  = "prefix"
	coverageSkipped = "skipped"
	coverageFailed  = "failed"
)

// formatKind classifies how an object's content can be safely sampled.
type formatKind int

const (
	// formatPlain formats can be safely processed from a bounded prefix
	// (plain text and linear formats).
	formatPlain formatKind = iota
	// formatStructured formats (OOXML, PDF, ZIP and compressed containers)
	// require the complete object because required metadata or content may
	// appear after the first MiB.
	formatStructured
)

// objectInfo is the minimal metadata for a listed object.
type objectInfo struct {
	key          string
	size         int64
	storageClass string
}

// scanContentResult is the outcome of sampling a single object.
type scanContentResult struct {
	finding *cloud.Finding
	err     *scanError
}

// ScanContent performs bounded, policy-controlled content sampling and
// classification across discovered buckets. It never writes, deletes, tags,
// decrypts or rewrites objects, and it never holds more data in memory than
// the configured limits.
func (c *S3Connector) ScanContent(ctx context.Context, request cloud.ScanRequest) (result cloud.ScanResult) {
	result = cloud.ScanResult{
		ScanID:    request.ScanID,
		StartedAt: time.Now().UTC(),
		Findings:  []cloud.Finding{},
		Errors:    []cloud.ScanError{},
	}
	defer func() { result.CompletedAt = time.Now().UTC() }()

	req := normalizeRequest(request)

	session, err := c.sessionFor(ctx)
	if err != nil {
		result.Errors = append(result.Errors, toCloudError(authError("authentication", err)))
		return result
	}
	factory := c.factory(session)
	if closer, ok := factory.(interface{ Close() }); ok {
		defer closer.Close()
	}

	buckets, truncated, discErrs := discoverBuckets(ctx, factory, req.MaxBuckets)
	for _, e := range discErrs {
		result.Errors = append(result.Errors, toCloudError(e))
	}
	result.Truncated = result.Truncated || truncated
	if len(buckets) == 0 {
		return result
	}

	var mu sync.Mutex
	downloadSem := make(chan struct{}, MaxConcurrentObjects)
	g, gctx := errgroup.WithContext(ctx)
	g.SetLimit(MaxConcurrentBuckets)

	for _, b := range buckets {
		b := b
		g.Go(func() error {
			objects, objTruncated, listErrs := c.listObjects(gctx, factory, b, req.MaxObjectsPerBucket)
			mu.Lock()
			if objTruncated {
				result.Truncated = true
			}
			for _, e := range listErrs {
				result.Errors = append(result.Errors, toCloudError(e))
			}
			mu.Unlock()

			for _, o := range objects {
				if err := gctx.Err(); err != nil {
					return err
				}
				outcome := c.scanObject(gctx, factory, b, o, req, downloadSem)
				mu.Lock()
				if outcome.finding != nil {
					result.Findings = append(result.Findings, *outcome.finding)
				}
				if outcome.err != nil {
					result.Errors = append(result.Errors, toCloudError(outcome.err))
				}
				mu.Unlock()
			}
			return nil
		})
	}

	if err := g.Wait(); err != nil {
		mu.Lock()
		result.Errors = append(result.Errors, cloud.ScanError{
			Scope:    "content",
			Category: "cancelled",
			Message:  "scan cancelled or timed out",
		})
		mu.Unlock()
	}

	// Deterministic ordering: bucket (resource), then rule.
	sort.Slice(result.Findings, func(i, j int) bool {
		if result.Findings[i].ResourceID != result.Findings[j].ResourceID {
			return result.Findings[i].ResourceID < result.Findings[j].ResourceID
		}
		return result.Findings[i].RuleID < result.Findings[j].RuleID
	})
	return result
}

// listObjects lists objects in a bucket using pagination, stopping immediately
// when the configured maximum is reached.
func (c *S3Connector) listObjects(ctx context.Context, factory ClientFactory, b bucket, maxObjects int) ([]objectInfo, bool, []*scanError) {
	client := factory.S3(b.region)
	var objectsOut []objectInfo
	truncated := false
	var errs []*scanError
	token := ""

	for {
		if maxObjects > 0 && len(objectsOut) >= maxObjects {
			truncated = true
			break
		}
		params := &s3.ListObjectsV2Input{Bucket: awssdk.String(b.name)}
		if token != "" {
			params.ContinuationToken = awssdk.String(token)
		}
		out, err := client.ListObjectsV2(ctx, params)
		if err != nil {
			errs = append(errs, awsErrorToScanError("content", b.name, err))
			break
		}
		for _, obj := range out.Contents {
			if maxObjects > 0 && len(objectsOut) >= maxObjects {
				truncated = true
				break
			}
			if obj.Key == nil {
				continue
			}
			objectsOut = append(objectsOut, objectInfo{
				key:          *obj.Key,
				size:         awssdk.ToInt64(obj.Size),
				storageClass: string(obj.StorageClass),
			})
		}
		if out.NextContinuationToken == nil || *out.NextContinuationToken == "" {
			break
		}
		token = *out.NextContinuationToken
	}

	sort.Slice(objectsOut, func(i, j int) bool { return objectsOut[i].key < objectsOut[j].key })
	return objectsOut, truncated, errs
}

// scanObject samples and classifies a single object. The object is inspected
// via HeadObject before any download so delete markers, directory placeholders,
// archived objects and inaccessible objects are skipped cheaply.
func (c *S3Connector) scanObject(ctx context.Context, factory ClientFactory, b bucket, o objectInfo, req cloud.ScanRequest, sem chan struct{}) scanContentResult {
	client := factory.S3(b.region)

	head, err := client.HeadObject(ctx, &s3.HeadObjectInput{Bucket: awssdk.String(b.name), Key: awssdk.String(o.key)})
	if err != nil {
		kind, _ := classifyError(err)
		if kind == kindNotFound {
			return scanContentResult{} // object disappeared between list and head
		}
		return scanContentResult{err: awsErrorToScanError("content", b.name+"/"+o.key, err)}
	}
	if awssdk.ToBool(head.DeleteMarker) {
		return scanContentResult{} // skip delete markers
	}

	size := awssdk.ToInt64(head.ContentLength)
	if size == 0 {
		size = o.size
	}
	if size == 0 || isDirectoryPlaceholder(o.key) {
		return scanContentResult{} // skip directory placeholders and empty objects
	}

	storageClass := string(head.StorageClass)
	if storageClass == "" {
		storageClass = o.storageClass
	}
	if isArchivedStorageClass(storageClass) {
		return scanContentResult{finding: c.objectSkippedFinding(b.name, o.key, storageClass, "archived_storage_class", "object is archived and not sampled")}
	}

	contentType := ""
	if head.ContentType != nil {
		contentType = *head.ContentType
	}
	kindFormat := classifyFormat(o.key, contentType)

	data, coverage, skipped, reason, scanErr := c.downloadObject(ctx, client, b.name, o.key, size, kindFormat, req, sem)
	if skipped {
		return scanContentResult{finding: c.objectSkippedFinding(b.name, o.key, extOf(o.key), reason, "object was not sampled")}
	}
	if scanErr != nil {
		return scanContentResult{err: scanErr}
	}

	// Structured containers that were mislabeled as plain text are re-detected
	// from their magic bytes and re-sampled as structured.
	if kindFormat == formatPlain && isStructuredMagic(data) {
		if size > req.MaxObjectBytes {
			return scanContentResult{finding: c.objectSkippedFinding(b.name, o.key, extOf(o.key), "object_too_large_for_structured_scan", "object exceeds the structured scan size limit")}
		}
		data, coverage, skipped, reason, scanErr = c.downloadObject(ctx, client, b.name, o.key, size, formatStructured, req, sem)
		if skipped {
			return scanContentResult{finding: c.objectSkippedFinding(b.name, o.key, extOf(o.key), reason, "object was not sampled")}
		}
		if scanErr != nil {
			return scanContentResult{err: scanErr}
		}
	}

	text, extractErr := c.scanner.ExtractText(data, extOf(o.key))
	if extractErr != nil {
		return scanContentResult{finding: c.objectUnknownFinding(b.name, o.key, coverage, "content_unreadable", "text could not be extracted from the sampled content")}
	}

	cls := c.classifier.ClassifyWithContent(o.key, text, size)
	return scanContentResult{finding: c.classificationFinding(b.name, o.key, coverage, size, cls)}
}

// downloadObject retrieves an object under strict bounds. For prefix-safe text
// formats a Range request is used, but io.LimitReader still enforces the limit
// in case the server ignores the Range header. For structured formats the whole
// object is downloaded only when its known size fits within MaxObjectBytes.
// Response bodies are always closed.
func (c *S3Connector) downloadObject(ctx context.Context, client S3API, bucketName, key string, size int64, kindFormat formatKind, req cloud.ScanRequest, sem chan struct{}) (data []byte, coverage string, skipped bool, reason string, scanErr *scanError) {
	if kindFormat == formatStructured {
		if size > req.MaxObjectBytes {
			return nil, coverageSkipped, true, "object_too_large_for_structured_scan", nil
		}
		select {
		case sem <- struct{}{}:
		case <-ctx.Done():
			return nil, coverageSkipped, true, "cancelled", nil
		}
		defer func() { <-sem }()

		out, err := client.GetObject(ctx, &s3.GetObjectInput{Bucket: awssdk.String(bucketName), Key: awssdk.String(key)})
		if err != nil {
			kind, _ := classifyError(err)
			if kind == kindNotFound {
				return nil, "", false, "", nil
			}
			return nil, "", false, "", awsErrorToScanError("content", bucketName+"/"+key, err)
		}
		defer out.Body.Close()

		limit := req.MaxObjectBytes
		buf, rerr := io.ReadAll(io.LimitReader(out.Body, limit+1))
		if rerr != nil {
			return nil, "", false, "", awsErrorToScanError("content", bucketName+"/"+key, rerr)
		}
		if int64(len(buf)) > limit {
			return nil, coverageSkipped, true, "object_too_large_for_structured_scan", nil
		}
		return buf, coverageFull, false, "", nil
	}

	limit := req.MaxSampleBytes
	full := size <= limit
	if full {
		limit = size
	}
	if limit <= 0 {
		return nil, coverageSkipped, true, "empty_object", nil
	}

	select {
	case sem <- struct{}{}:
	case <-ctx.Done():
		return nil, coverageSkipped, true, "cancelled", nil
	}
	defer func() { <-sem }()

	rangeHeader := fmt.Sprintf("bytes=0-%d", limit-1)
	out, err := client.GetObject(ctx, &s3.GetObjectInput{
		Bucket: awssdk.String(bucketName),
		Key:    awssdk.String(key),
		Range:  awssdk.String(rangeHeader),
	})
	if err != nil {
		kind, _ := classifyError(err)
		if kind == kindNotFound {
			return nil, "", false, "", nil
		}
		return nil, "", false, "", awsErrorToScanError("content", bucketName+"/"+key, err)
	}
	defer out.Body.Close()

	// io.LimitReader enforces the bound even if the server ignores Range.
	buf, rerr := io.ReadAll(io.LimitReader(out.Body, limit+1))
	if rerr != nil {
		return nil, "", false, "", awsErrorToScanError("content", bucketName+"/"+key, rerr)
	}
	if int64(len(buf)) > limit {
		buf = buf[:limit]
	}
	if full {
		return buf, coverageFull, false, "", nil
	}
	return buf, coveragePrefix, false, "", nil
}

// classifyFormat decides how an object must be sampled. It never relies solely
// on filename extensions: content-type hints and, during sampling, magic bytes
// are used as well. Formats whose metadata may appear after the first MiB
// (OOXML, PDF, ZIP and compressed containers) require a full download.
func classifyFormat(key, contentType string) formatKind {
	switch strings.ToLower(path.Ext(key)) {
	case ".txt", ".log", ".csv", ".tsv", ".json", ".xml", ".html", ".htm",
		".md", ".yml", ".yaml", ".ini", ".cfg", ".conf", ".rtf", ".sql":
		return formatPlain
	case ".docx", ".xlsx", ".pptx", ".doc", ".xls", ".ppt", ".pdf",
		".zip", ".7z", ".gz", ".tgz", ".tar", ".rar", ".jar":
		return formatStructured
	}
	ct := strings.ToLower(contentType)
	switch {
	case strings.Contains(ct, "text/"), strings.Contains(ct, "json"),
		strings.Contains(ct, "xml"), strings.Contains(ct, "csv"), strings.Contains(ct, "yaml"):
		return formatPlain
	case strings.Contains(ct, "zip"), strings.Contains(ct, "pdf"),
		strings.Contains(ct, "officedocument"), strings.Contains(ct, "msword"),
		strings.Contains(ct, "ms-excel"), strings.Contains(ct, "ms-powerpoint"),
		strings.Contains(ct, "gzip"), strings.Contains(ct, "tar"), strings.Contains(ct, "compressed"):
		return formatStructured
	default:
		// Unknown formats are treated as plain for a bounded prefix scan; the
		// magic bytes are checked after download and mislabeled structured
		// containers are re-sampled as structured.
		return formatPlain
	}
}

// isStructuredMagic reports whether sampled bytes look like a structured
// container that needs a full download.
func isStructuredMagic(data []byte) bool {
	if len(data) >= 4 && bytes.Equal(data[:4], []byte{0x50, 0x4B, 0x03, 0x04}) {
		return true // ZIP / OOXML (DOCX, XLSX, PPTX)
	}
	if len(data) >= 5 && bytes.Equal(data[:5], []byte("%PDF-")) {
		return true
	}
	return false
}

func isDirectoryPlaceholder(key string) bool {
	return strings.HasSuffix(key, "/")
}

func isArchivedStorageClass(sc string) bool {
	switch sc {
	case "GLACIER", "DEEP_ARCHIVE", "GLACIER_IR":
		return true
	}
	return false
}

func extOf(key string) string {
	return strings.ToLower(path.Ext(key))
}

func (c *S3Connector) classificationFinding(bucketName, key, coverage string, size int64, cls classification.EngineClassificationResult) *cloud.Finding {
	status := cloud.StatusUnknown
	severity := cloud.SeverityInfo
	reason := ""
	classification := cls.Classification

	switch {
	case classification != "PUBLIC":
		status = cloud.StatusNonCompliant
		severity = severityForClassification(classification)
	case coverage == coverageFull:
		status = cloud.StatusCompliant
	case coverage == coveragePrefix:
		status = cloud.StatusUnknown
		reason = "prefix_only"
	default:
		status = cloud.StatusUnknown
		reason = "incomplete_scan"
	}

	evidence := map[string]string{
		"bucket":         bucketName,
		"key":            key,
		"size":           strconv.FormatInt(size, 10),
		"coverage":       coverage,
		"classification": classification,
	}
	if reason != "" {
		evidence["reason"] = reason
	}

	return &cloud.Finding{
		ID:           cloud.FindingID(c.id, c.Kind(), cloud.ResourceTypeObject, bucketName+"/"+key, "aws-s3-object-content"),
		ConnectorID:  c.id,
		Provider:     c.Kind(),
		ResourceType: cloud.ResourceTypeObject,
		ResourceID:   bucketName + "/" + key,
		Category:     "data_classification",
		RuleID:       "aws-s3-object-content",
		Severity:     severity,
		Status:       status,
		Title:        "Object content classification",
		Evidence:     evidence,
		DetectedAt:   time.Now().UTC(),
	}
}

func (c *S3Connector) objectSkippedFinding(bucketName, key, storageClass, reason, note string) *cloud.Finding {
	evidence := map[string]string{
		"bucket":         bucketName,
		"key":            key,
		"storage_class":  storageClass,
		"coverage":       coverageSkipped,
		"reason":         reason,
	}
	if note != "" {
		evidence["note"] = note
	}
	return &cloud.Finding{
		ID:           cloud.FindingID(c.id, c.Kind(), cloud.ResourceTypeObject, bucketName+"/"+key, "aws-s3-object-content"),
		ConnectorID:  c.id,
		Provider:     c.Kind(),
		ResourceType: cloud.ResourceTypeObject,
		ResourceID:   bucketName + "/" + key,
		Category:     "data_classification",
		RuleID:       "aws-s3-object-content",
		Severity:     cloud.SeverityInfo,
		Status:       cloud.StatusUnsupported,
		Title:        "Object content not sampled",
		Evidence:     evidence,
		DetectedAt:   time.Now().UTC(),
	}
}

func (c *S3Connector) objectUnknownFinding(bucketName, key, coverage, reason, note string) *cloud.Finding {
	evidence := map[string]string{
		"bucket":   bucketName,
		"key":      key,
		"coverage": coverage,
		"reason":   reason,
	}
	if note != "" {
		evidence["note"] = note
	}
	return &cloud.Finding{
		ID:           cloud.FindingID(c.id, c.Kind(), cloud.ResourceTypeObject, bucketName+"/"+key, "aws-s3-object-content"),
		ConnectorID:  c.id,
		Provider:     c.Kind(),
		ResourceType: cloud.ResourceTypeObject,
		ResourceID:   bucketName + "/" + key,
		Category:     "data_classification",
		RuleID:       "aws-s3-object-content",
		Severity:     cloud.SeverityInfo,
		Status:       cloud.StatusUnknown,
		Title:        "Object content could not be assessed",
		Evidence:     evidence,
		DetectedAt:   time.Now().UTC(),
	}
}

func severityForClassification(classification string) string {
	switch classification {
	case "RESTRICTED":
		return cloud.SeverityCritical
	case "CONFIDENTIAL":
		return cloud.SeverityHigh
	case "INTERNAL":
		return cloud.SeverityMedium
	case "PRIVATE":
		return cloud.SeverityLow
	default:
		return cloud.SeverityInfo
	}
}