package api

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"time"

	"github.com/google/uuid"

	"manara-dlp/internal/classification"
	"manara-dlp/internal/dspm/cloud"
	"manara-dlp/internal/dspm/cloud/aws"
	"manara-dlp/internal/license"
)

// CloudHandler exposes the Cloud DSPM APIs. It is intentionally wired behind
// the licensing gate at registration time; the handler itself never bypasses
// it.
type CloudHandler struct {
	licSvc       *license.Service
	allowProfile bool
	newConnector func(cfg aws.AWSConfig) (cloud.Connector, error)
}

// AllowAWSProfile controls whether Cloud DSPM accepts a local AWS profile for
// authentication. It is server-configured from ALLOW_AWS_PROFILE and can never
// be enabled by a client.
var AllowAWSProfile bool

// NewCloudHandler builds a CloudHandler. Profile-based authentication is
// enabled only when the server explicitly allows it.
func NewCloudHandler(licSvc *license.Service) *CloudHandler {
	return &CloudHandler{
		licSvc:       licSvc,
		allowProfile: AllowAWSProfile,
		newConnector: func(cfg aws.AWSConfig) (cloud.Connector, error) {
			engine := classification.NewEngineWithProvider(ClassificationProvider)
			return aws.NewS3ConnectorWithEngine(cfg, engine), nil
		},
	}
}

// RegisterRoutes registers the Cloud DSPM routes on the given mux. Every route
// is wrapped with the licensing middleware for the Cloud DSPM feature.
func (h *CloudHandler) RegisterRoutes(mux *http.ServeMux) {
	mux.HandleFunc("/api/v1/cloud/aws/s3/scan",
		license.RequireFeature(h.licSvc, license.FeatureCloudDSPM, h.HandleAWSS3Scan))
}

// awsS3ScanRequest is the client-facing payload for POST
// /api/v1/cloud/aws/s3/scan. Numeric limits use pointers so the handler can
// distinguish "unset" (default applied) from "explicitly zero" (rejected).
// Unknown JSON fields, including any AWS secret key fields, are rejected.
type awsS3ScanRequest struct {
	RoleARN               string `json:"role_arn"`
	ExternalID            string `json:"external_id"`
	Region                string `json:"region"`
	RoleSessionNamePrefix string `json:"role_session_name_prefix"`
	Profile               string `json:"profile"`

	MaxBuckets          *int   `json:"max_buckets"`
	MaxObjectsPerBucket *int   `json:"max_objects_per_bucket"`
	MaxObjectBytes      *int64 `json:"max_object_bytes"`
	MaxSampleBytes      *int64 `json:"max_sample_bytes"`

	ScanPosture *bool `json:"scan_posture"`
	ScanContent *bool `json:"scan_content"`
}

// HandleAWSS3Scan runs a bounded, synchronous AWS S3 DSPM scan.
//
// The scan is executed in-process with a server-side timeout. A scan is
// resource-bound by the connector's own safety limits (bucket count, objects
// per bucket, bytes per object); clients can request smaller limits but can
// never raise them.
func (h *CloudHandler) HandleAWSS3Scan(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}

	// The router's AuthMiddleware enforces authentication before this handler
	// runs. The claims are checked again here as defense in depth so a handler
	// can never be reached without a validated identity.
	if claimsFromContext(r.Context()) == nil {
		writeCloudJSONError(w, http.StatusUnauthorized, "authentication required")
		return
	}

	// Reject oversized request bodies before parsing.
	r.Body = http.MaxBytesReader(w, r.Body, aws.MaxRequestBodyBytes)
	dec := json.NewDecoder(r.Body)
	dec.DisallowUnknownFields()

	var req awsS3ScanRequest
	if err := dec.Decode(&req); err != nil {
		var maxErr *http.MaxBytesError
		if errors.As(err, &maxErr) {
			writeCloudJSONError(w, http.StatusRequestEntityTooLarge, "request body too large")
			return
		}
		writeCloudJSONError(w, http.StatusBadRequest, "invalid request body")
		return
	}
	// Reject any trailing data after the JSON document.
	if err := dec.Decode(&struct{}{}); err != io.EOF {
		writeCloudJSONError(w, http.StatusBadRequest, "request body must contain a single JSON object")
		return
	}

	cfg := aws.AWSConfig{
		RoleARN:               req.RoleARN,
		ExternalID:            req.ExternalID,
		Region:                req.Region,
		RoleSessionNamePrefix: req.RoleSessionNamePrefix,
		Profile:               req.Profile,
		AllowProfile:          h.allowProfile,
		MaxBuckets:            intValue(req.MaxBuckets, 100),
		MaxObjectsPerBucket:   intValue(req.MaxObjectsPerBucket, 100),
		MaxObjectBytes:        int64Value(req.MaxObjectBytes, 10*1024*1024),
		MaxSampleBytes:        int64Value(req.MaxSampleBytes, 1*1024*1024),
	}

	if err := validateScanLimits(req); err != nil {
		writeCloudJSONError(w, http.StatusBadRequest, err.Error())
		return
	}

	if err := cfg.Validate(); err != nil {
		writeCloudJSONError(w, http.StatusBadRequest, err.Error())
		return
	}

	connector, err := h.newConnector(cfg)
	if err != nil {
		writeCloudJSONError(w, http.StatusInternalServerError, "failed to create cloud connector")
		return
	}

	// Authenticate and validate before scanning. Errors are sanitized and
	// mapped to appropriate HTTP statuses.
	ctx, cancel := context.WithTimeout(r.Context(), aws.ScanTimeout)
	defer cancel()

	if err := connector.Validate(ctx); err != nil {
		writeCloudJSONError(w, aws.HTTPStatusForError(err), aws.SanitizeError(err))
		return
	}

	scanID := uuid.New().String()
	request := cloud.ScanRequest{
		ScanID:              scanID,
		MaxBuckets:          cfg.MaxBuckets,
		MaxObjectsPerBucket: cfg.MaxObjectsPerBucket,
		MaxObjectBytes:      cfg.MaxObjectBytes,
		MaxSampleBytes:      cfg.MaxSampleBytes,
	}

	postureOn := req.ScanPosture == nil || *req.ScanPosture
	contentOn := req.ScanContent == nil || *req.ScanContent

	var posture cloud.ScanResult
	var content cloud.ScanResult
	if postureOn {
		posture = connector.ScanPosture(ctx, request)
	}
	if contentOn {
		content = connector.ScanContent(ctx, request)
	}

	result := mergeScanResults(scanID, posture, content)
	writeCloudJSON(w, http.StatusOK, result)
}

// validateScanLimits rejects client-supplied limits that would disable a safety
// bound or exceed the server-side maximum. Zero means "no limit" to a naive
// implementation and is therefore rejected outright.
func validateScanLimits(req awsS3ScanRequest) error {
	if req.MaxBuckets != nil && (*req.MaxBuckets <= 0 || *req.MaxBuckets > aws.MaxBucketsAllowed) {
		return fmt.Errorf("max_buckets must be between 1 and %d", aws.MaxBucketsAllowed)
	}
	if req.MaxObjectsPerBucket != nil && (*req.MaxObjectsPerBucket <= 0 || *req.MaxObjectsPerBucket > aws.MaxObjectsPerBucketAllowed) {
		return fmt.Errorf("max_objects_per_bucket must be between 1 and %d", aws.MaxObjectsPerBucketAllowed)
	}
	if req.MaxObjectBytes != nil && (*req.MaxObjectBytes <= 0 || *req.MaxObjectBytes > aws.MaxObjectBytesAllowed) {
		return fmt.Errorf("max_object_bytes must be between 1 and %d", aws.MaxObjectBytesAllowed)
	}
	if req.MaxSampleBytes != nil && (*req.MaxSampleBytes <= 0 || *req.MaxSampleBytes > aws.MaxSampleBytesAllowed) {
		return fmt.Errorf("max_sample_bytes must be between 1 and %d", aws.MaxSampleBytesAllowed)
	}
	return nil
}

func intValue(p *int, def int) int {
	if p == nil {
		return def
	}
	return *p
}

// claimsFromContext returns the authenticated identity claims stored on the
// request context by AuthMiddleware, or nil when the request is unauthenticated.
func claimsFromContext(ctx context.Context) *Claims {
	if v := ctx.Value(claimsContextKey{}); v != nil {
		if c, ok := v.(*Claims); ok {
			return c
		}
	}
	return nil
}

func int64Value(p *int64, def int64) int64 {
	if p == nil {
		return def
	}
	return *p
}

// mergeScanResults combines the posture and content results of one scan into a
// single deterministic result.
func mergeScanResults(scanID string, posture, content cloud.ScanResult) cloud.ScanResult {
	result := cloud.ScanResult{
		ScanID:    scanID,
		StartedAt: posture.StartedAt,
		Findings:  make([]cloud.Finding, 0, len(posture.Findings)+len(content.Findings)),
		Errors:    make([]cloud.ScanError, 0, len(posture.Errors)+len(content.Errors)),
	}
	if content.StartedAt.Before(posture.StartedAt) {
		result.StartedAt = content.StartedAt
	}
	completed := posture.CompletedAt
	if content.CompletedAt.After(completed) {
		completed = content.CompletedAt
	}
	if result.StartedAt.IsZero() {
		result.StartedAt = time.Now().UTC()
	}
	if completed.IsZero() {
		completed = time.Now().UTC()
	}
	result.CompletedAt = completed
	result.Truncated = posture.Truncated || content.Truncated

	result.Findings = append(result.Findings, posture.Findings...)
	result.Findings = append(result.Findings, content.Findings...)
	result.Errors = append(result.Errors, posture.Errors...)
	result.Errors = append(result.Errors, content.Errors...)
	return result
}

func writeCloudJSON(w http.ResponseWriter, status int, v interface{}) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	json.NewEncoder(w).Encode(v)
}

func writeCloudJSONError(w http.ResponseWriter, status int, message string) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	json.NewEncoder(w).Encode(map[string]string{
		"error":   http.StatusText(status),
		"message": message,
	})
}
