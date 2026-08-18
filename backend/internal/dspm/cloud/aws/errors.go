package aws

import (
	"context"
	"errors"
	"fmt"
	"net/http"
	"strings"

	"github.com/aws/smithy-go"
)

// errorKind classifies AWS failures so callers can distinguish authentication
// failure, authorization failure, throttling, resource absence and transient
// errors. These are never confused with each other.
type errorKind int

const (
	kindUnknown errorKind = iota
	kindAuth            // invalid/expired credentials, invalid signature
	kindAuthz           // AccessDenied / authorization failure
	kindThrottled       // throttling / rate limiting
	kindNotFound        // resource does not exist
	kindTransient       // 5xx, network, SlowDown
	kindCancelled       // context cancelled or deadline exceeded
)

// classifyError maps a raw error to a kind and a sanitized, non-sensitive
// message. The raw error may contain credential or request details, so the
// returned message never echoes it verbatim.
func classifyError(err error) (errorKind, string) {
	if err == nil {
		return kindUnknown, ""
	}
	if errors.Is(err, context.Canceled) || errors.Is(err, context.DeadlineExceeded) {
		return kindCancelled, "the scan was cancelled or timed out"
	}

	var apiErr smithy.APIError
	if errors.As(err, &apiErr) {
		code := apiErr.ErrorCode()
		lower := strings.ToLower(code)
		switch {
		case isThrottleCode(lower):
			return kindThrottled, "the AWS API is throttling requests; try again later"
		case isAuthCode(lower):
			return kindAuth, "the AWS credentials could not be authenticated"
		case lower == "accessdenied" || lower == "accessdeniedexception" || strings.HasPrefix(lower, "accessdenied"):
			return kindAuthz, "permission denied by the AWS account"
		case isNotFoundCode(lower):
			return kindNotFound, "the resource was not found"
		default:
			return kindTransient, "the AWS API returned an unexpected error"
		}
	}

	var httpErr interface{ StatusCode() int }
	if errors.As(err, &httpErr) {
		switch httpErr.StatusCode() {
		case http.StatusTooManyRequests:
			return kindThrottled, "the AWS API is throttling requests; try again later"
		case http.StatusForbidden:
			return kindAuthz, "permission denied by the AWS account"
		case http.StatusUnauthorized:
			return kindAuth, "the AWS credentials could not be authenticated"
		case http.StatusNotFound:
			return kindNotFound, "the resource was not found"
		case http.StatusInternalServerError, http.StatusBadGateway, http.StatusServiceUnavailable:
			return kindTransient, "the AWS API is temporarily unavailable"
		}
	}

	return kindTransient, "the scan could not reach the AWS API"
}

func isAuthCode(lower string) bool {
	switch lower {
	case "invalidclienttokenid", "expiredtoken", "signaturedoesnotmatch",
		"invalidsignatureexception", "unrecognizedclientexception",
		"invalidaccesskeyid", "tokenrefreshrequired":
		return true
	}
	return false
}

func isThrottleCode(lower string) bool {
	switch lower {
	case "slowdown", "throttling", "throttlingexception", "requestlimitexceeded",
		"ratelimitexceeded", "provisionedthroughputexceededexception",
		"toomanyrequests", "bandwidthlimitsexceeded":
		return true
	}
	return strings.HasPrefix(lower, "throttl")
}

func isNotFoundCode(lower string) bool {
	switch lower {
	case "nosuchbucket", "nosuchbucketpolicy", "nosuchkey", "nosuchlifecycleconfiguration",
		"nosuchpublicaccessblockconfiguration", "notfound", "notfoundexception",
		"serversideencryptionconfigurationnotfounderror",
		"ownershipcontrolsnotfounderror", "objectlockconfigurationnotfounderror",
		"nosuchupload", "nosuchversion", "nosuchcorsconfiguration",
		"nosuchtagset", "replicationconfigurationnotfounderror":
		return true
	}
	return false
}

// isAccessDenied reports whether err is an AWS AccessDenied error. Bucket-level
// read APIs that return AccessDenied must be reported as unknown, never as a
// security misconfiguration.
func isAccessDenied(err error) bool {
	if err == nil {
		return false
	}
	var apiErr smithy.APIError
	if errors.As(err, &apiErr) {
		code := strings.ToLower(apiErr.ErrorCode())
		return code == "accessdenied" || code == "accessdeniedexception" || strings.HasPrefix(code, "accessdenied")
	}
	var httpErr interface{ StatusCode() int }
	if errors.As(err, &httpErr) {
		return httpErr.StatusCode() == http.StatusForbidden
	}
	return false
}

// isMissingConfiguration reports whether err is one of the "not configured"
// error codes that indicate an optional configuration is simply absent rather
// than broken.
func isMissingConfiguration(err error) bool {
	if err == nil {
		return false
	}
	var apiErr smithy.APIError
	if errors.As(err, &apiErr) {
		switch strings.ToLower(apiErr.ErrorCode()) {
		case "nosuchbucketpolicy", "nosuchpublicaccessblockconfiguration",
			"serversideencryptionconfigurationnotfounderror",
			"ownershipcontrolsnotfounderror", "objectlockconfigurationnotfounderror",
			"nosuchlifecycleconfiguration", "notfound":
			return true
		}
	}
	return false
}

// isUnsupportedBucketError reports whether err indicates the bucket type is not
// supported by the general-purpose S3 APIs (for example an S3 Express directory
// bucket).
func isUnsupportedBucketError(err error) bool {
	if err == nil {
		return false
	}
	var apiErr smithy.APIError
	if errors.As(err, &apiErr) {
		code := strings.ToLower(apiErr.ErrorCode())
		msg := strings.ToLower(apiErr.ErrorMessage())
		switch {
		case code == "invalidbucketstate" || code == "notimplemented":
			return true
		case strings.Contains(msg, "directory bucket"), strings.Contains(msg, "express"):
			return true
		}
	}
	return false
}

// sanitize returns a short, non-sensitive summary of a scan error. It never
// includes the raw error string, which may leak credentials or request data.
func sanitize(kind errorKind) string {
	switch kind {
	case kindAuth:
		return "authentication failed; check the configured credentials"
	case kindAuthz:
		return "authorization failed; the role lacks the required permissions"
	case kindThrottled:
		return "AWS is throttling requests; retry later"
	case kindNotFound:
		return "resource not found"
	case kindCancelled:
		return "scan cancelled or timed out"
	default:
		return "the scan encountered an unexpected AWS API error"
	}
}

// awsErrorToScanError converts a raw AWS error into a non-sensitive ScanError.
func awsErrorToScanError(scope, resource string, err error) *scanError {
	kind, _ := classifyError(err)
	cat := "transient"
	switch kind {
	case kindAuth:
		cat = "authentication"
	case kindAuthz:
		cat = "access_denied"
	case kindThrottled:
		cat = "throttled"
	case kindNotFound:
		cat = "not_found"
	case kindCancelled:
		cat = "cancelled"
	}
	return &scanError{scope: scope, resource: resource, category: cat, retryable: kind == kindTransient || kind == kindThrottled, message: sanitize(kind)}
}

// scanError is the internal mutable form of cloud.ScanError used while building
// results. It is converted to cloud.ScanError on output.
type scanError struct {
	scope     string
	resource  string
	category  string
	retryable bool
	message   string
}

// Error satisfies the error interface so scan errors can flow through the
// standard error paths internally. The message is always non-sensitive.
func (e *scanError) Error() string {
	return fmt.Sprintf("%s %s: %s", e.scope, e.resource, e.message)
}