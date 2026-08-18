// Package cloud defines provider-neutral types for the DSPM cloud connectors.
//
// Handlers and higher-level orchestration depend only on these types, never on
// provider SDK types, so additional cloud providers can be added without
// touching callers.
package cloud

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"time"
)

// Provider identifiers.
const (
	ProviderAWS = "aws"
)

// Finding statuses. A resource is either explicitly assessed (compliant /
// noncompliant) or could not be assessed (unknown), is not supported by the
// connector (unsupported), or failed during assessment (error). An unavailable
// permission (AccessDenied) must never be reported as a security
// misconfiguration; it maps to the "unknown" status.
const (
	StatusNonCompliant = "noncompliant"
	StatusCompliant    = "compliant"
	StatusUnknown      = "unknown"
	StatusUnsupported  = "unsupported"
	StatusError        = "error"
)

// Finding severities.
const (
	SeverityCritical = "critical"
	SeverityHigh     = "high"
	SeverityMedium   = "medium"
	SeverityLow      = "low"
	SeverityInfo     = "info"
)

// Resource types emitted by connectors.
const (
	ResourceTypeAccount = "aws_account"
	ResourceTypeBucket  = "aws_s3_bucket"
	ResourceTypeObject  = "aws_s3_object"
)

// Connector is the provider-neutral interface every cloud DSPM connector
// implements.
type Connector interface {
	// ID returns a stable connector identifier, e.g. "aws-s3".
	ID() string
	// Kind returns the provider kind, e.g. cloud.ProviderAWS.
	Kind() string
	// Validate validates the connector configuration and, for connectors that
	// authenticate against a live provider, proves the configuration can
	// authenticate. It must not mutate anything.
	Validate(ctx context.Context) error
	// ScanPosture evaluates the security posture of discovered resources using
	// read-only APIs. It never modifies provider resources.
	ScanPosture(ctx context.Context, request ScanRequest) ScanResult
	// ScanContent performs bounded, policy-controlled content sampling and
	// classification. It never writes, deletes, tags, decrypts or rewrites
	// provider objects.
	ScanContent(ctx context.Context, request ScanRequest) ScanResult
}

// ScanRequest carries the bounds for a single scan. Limits are enforced by the
// connector against server-side maximums; callers can never raise them beyond
// what the connector allows.
type ScanRequest struct {
	ScanID              string
	MaxBuckets          int
	MaxObjectsPerBucket int
	MaxObjectBytes      int64
	MaxSampleBytes      int64
}

// ScanResult is the deterministic, auditable output of a scan.
type ScanResult struct {
	ScanID      string      `json:"scan_id"`
	StartedAt   time.Time   `json:"started_at"`
	CompletedAt time.Time   `json:"completed_at"`
	Findings    []Finding   `json:"findings"`
	Errors      []ScanError `json:"errors"`
	Truncated   bool        `json:"truncated"`
}

// Finding is a single deterministic posture or content result for one resource
// and one rule. Finding IDs are stable across runs.
type Finding struct {
	ID           string            `json:"id"`
	ConnectorID  string            `json:"connector_id"`
	Provider     string            `json:"provider"`
	ResourceType string            `json:"resource_type"`
	ResourceID   string            `json:"resource_id"`
	Category     string            `json:"category"`
	RuleID       string            `json:"rule_id"`
	Severity     string            `json:"severity"`
	Status       string            `json:"status"`
	Title        string            `json:"title"`
	Evidence     map[string]string `json:"evidence"`
	DetectedAt   time.Time         `json:"detected_at"`
}

// ScanError records a per-resource failure. A failure on one resource never
// cancels the whole scan; partial results are always preserved.
type ScanError struct {
	Scope     string `json:"scope"`
	Resource  string `json:"resource"`
	Category  string `json:"category"`
	Retryable bool   `json:"retryable"`
	Message   string `json:"message"`
}

// FindingID derives a deterministic, stable identifier for a finding from the
// identity of the resource and rule that produced it. The same inputs always
// yield the same identifier, so results are reproducible and auditable.
func FindingID(connectorID, provider, resourceType, resourceID, ruleID string) string {
	h := sha256.New()
	h.Write([]byte(connectorID))
	h.Write([]byte{0})
	h.Write([]byte(provider))
	h.Write([]byte{0})
	h.Write([]byte(resourceType))
	h.Write([]byte{0})
	h.Write([]byte(resourceID))
	h.Write([]byte{0})
	h.Write([]byte(ruleID))
	sum := h.Sum(nil)
	return hex.EncodeToString(sum[:10]) // 20 hex characters
}