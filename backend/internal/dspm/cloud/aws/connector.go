package aws

import (
	"context"
	"fmt"
	"log"
	"net/http"
	"os"
	"sort"
	"sync"
	"time"

	"manara-dlp/internal/classification"
	"manara-dlp/internal/dspm/cloud"
)

// ConnectorID is the stable identifier for the AWS S3 connector.
const ConnectorID = "aws-s3"

// S3Connector implements cloud.Connector for AWS S3. Handlers and scanner logic
// depend on the narrow AWS interfaces defined in this package, never on
// concrete SDK clients.
type S3Connector struct {
	id         string
	cfg        AWSConfig
	auth       Authenticator
	factory    func(*Session) ClientFactory
	classifier *classification.ClassificationEngine
	scanner    *classification.ContentScanner
	logger     *log.Logger

	sessionMu sync.Mutex
	session   *Session
}

// NewS3Connector builds a production AWS S3 connector backed by the AWS SDK.
func NewS3Connector(cfg AWSConfig) *S3Connector {
	cfg.ApplyDefaults()
	scanner := classification.NewContentScanner()
	scanner.SetMaxFileSize(int64(MaxObjectBytesAllowed))
	return newS3Connector(cfg, newAuthenticator(cfg), newSDKClientFactoryFromSession, classification.NewClassificationEngine(), scanner, nil)
}

// NewS3ConnectorWithEngine builds a production AWS S3 connector backed by the
// AWS SDK using the provided classification engine (e.g. one wired to an
// optional AI analysis provider). A nil engine falls back to the default.
func NewS3ConnectorWithEngine(cfg AWSConfig, engine *classification.ClassificationEngine) *S3Connector {
	cfg.ApplyDefaults()
	scanner := classification.NewContentScanner()
	scanner.SetMaxFileSize(int64(MaxObjectBytesAllowed))
	return newS3Connector(cfg, newAuthenticator(cfg), newSDKClientFactoryFromSession, engine, scanner, nil)
}

// newS3Connector is the internal constructor used by production wiring and by
// tests that substitute deterministic fakes.
func newS3Connector(cfg AWSConfig, auth Authenticator, factory func(*Session) ClientFactory, engine *classification.ClassificationEngine, scanner *classification.ContentScanner, logger *log.Logger) *S3Connector {
	cfg.ApplyDefaults()
	if logger == nil {
		logger = log.New(os.Stderr, "[cloud-dspm] ", log.LstdFlags)
	}
	if scanner == nil {
		scanner = classification.NewContentScanner()
	}
	if engine == nil {
		engine = classification.NewClassificationEngine()
	}
	return &S3Connector{
		id:         ConnectorID,
		cfg:        cfg,
		auth:       auth,
		factory:    factory,
		classifier: engine,
		scanner:    scanner,
		logger:     logger,
	}
}

func (c *S3Connector) ID() string   { return c.id }
func (c *S3Connector) Kind() string { return cloud.ProviderAWS }

// Validate verifies the configuration and proves the configured identity can
// authenticate. It never mutates any AWS resource.
func (c *S3Connector) Validate(ctx context.Context) error {
	if err := c.cfg.Validate(); err != nil {
		return err
	}
	session, err := c.sessionFor(ctx)
	if err != nil {
		return err
	}
	if session == nil || session.Config.Credentials == nil {
		return fmt.Errorf("authentication produced no credentials")
	}
	if _, err := session.Config.Credentials.Retrieve(ctx); err != nil {
		return err
	}
	return nil
}

// sessionFor authenticates once per connector lifetime. Connectors are created
// per scan request, so the session (and its temporary credentials) never
// outlives the request that created it.
func (c *S3Connector) sessionFor(ctx context.Context) (*Session, error) {
	c.sessionMu.Lock()
	defer c.sessionMu.Unlock()
	if c.session != nil {
		return c.session, nil
	}
	session, err := c.auth.Authenticate(ctx)
	if err != nil {
		return nil, err
	}
	c.session = session
	return session, nil
}

// ScanPosture evaluates the security posture of every accessible bucket using
// read-only APIs. Account-level Public Access Block is evaluated once per scan.
func (c *S3Connector) ScanPosture(ctx context.Context, request cloud.ScanRequest) (result cloud.ScanResult) {
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

	// Account-level Public Access Block is a single account-wide check.
	if session.AccountID != "" {
		c.assessAccountPosture(ctx, factory.S3Control(), session.AccountID, &result.Findings, &result.Errors)
	}

	buckets, truncated, discErrs := discoverBuckets(ctx, factory, req.MaxBuckets)
	for _, e := range discErrs {
		result.Errors = append(result.Errors, toCloudError(e))
	}
	result.Truncated = result.Truncated || truncated

	// Bucket posture checks are sequential: they are lightweight and
	// deterministic, and there is no benefit to racing a small account.
	for _, b := range buckets {
		if err := ctx.Err(); err != nil {
			result.Errors = append(result.Errors, cloud.ScanError{
				Scope:    "posture",
				Category: "cancelled",
				Message:  "scan cancelled or timed out",
			})
			break
		}
		client := factory.S3(b.region)
		c.assessBucketPosture(ctx, client, b.name, &result.Findings, &result.Errors)
	}

	// Deterministic ordering: resource, then rule.
	sort.Slice(result.Findings, func(i, j int) bool {
		if result.Findings[i].ResourceID != result.Findings[j].ResourceID {
			return result.Findings[i].ResourceID < result.Findings[j].ResourceID
		}
		return result.Findings[i].RuleID < result.Findings[j].RuleID
	})
	return result
}

// toCloudError converts an internal scanError into the provider-neutral type.
func toCloudError(e *scanError) cloud.ScanError {
	if e == nil {
		return cloud.ScanError{Scope: "scan", Category: "transient", Message: "unknown error"}
	}
	return cloud.ScanError{
		Scope:     e.scope,
		Resource:  e.resource,
		Category:  e.category,
		Retryable: e.retryable,
		Message:   e.message,
	}
}

// HTTPStatusForError maps an error returned by Validate to an appropriate HTTP
// status code. Errors are always sanitized before they reach a client.
func HTTPStatusForError(err error) int {
	kind, _ := classifyError(err)
	switch kind {
	case kindAuth:
		return http.StatusUnauthorized
	case kindAuthz:
		return http.StatusForbidden
	case kindThrottled:
		return http.StatusServiceUnavailable
	case kindCancelled:
		return http.StatusGatewayTimeout
	case kindNotFound:
		return http.StatusBadRequest
	default:
		return http.StatusInternalServerError
	}
}

// SanitizeError returns a non-sensitive message for an error surfaced to a
// client. It never includes the raw error string.
func SanitizeError(err error) string {
	if err == nil {
		return ""
	}
	kind, _ := classifyError(err)
	return sanitize(kind)
}