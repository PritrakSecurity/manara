package aws

import (
	"context"
	"fmt"
	"strings"

	awssdk "github.com/aws/aws-sdk-go-v2/aws"
	awsconfig "github.com/aws/aws-sdk-go-v2/config"
	"github.com/aws/aws-sdk-go-v2/credentials/stscreds"
	"github.com/aws/aws-sdk-go-v2/service/sts"
	"github.com/google/uuid"
)

// Session carries the authenticated AWS configuration and the account ID the
// credentials belong to. Only temporary or explicitly configured local
// credentials are ever used; they are never persisted or logged.
type Session struct {
	Config    awssdk.Config
	AccountID string
}

// Authenticator establishes an authenticated AWS session for a scan. The
// connector and scanner logic depend on this interface so tests can substitute
// deterministic fakes.
type Authenticator interface {
	Authenticate(ctx context.Context) (*Session, error)
}

// assumeRoleAuthenticator loads the application's base AWS credentials through
// the standard SDK credential chain and assumes the configured customer role
// with a unique external ID, producing short-lived temporary credentials.
type assumeRoleAuthenticator struct {
	cfg AWSConfig
}

func newAssumeRoleAuthenticator(cfg AWSConfig) Authenticator {
	return &assumeRoleAuthenticator{cfg: cfg}
}

func (a *assumeRoleAuthenticator) Authenticate(ctx context.Context) (*Session, error) {
	// Load the application's own deployment identity using the standard SDK
	// credential chain (environment, shared config, container, instance
	// metadata). Customer credentials are never provided by the caller.
	opts := []func(*awsconfig.LoadOptions) error{
		awsconfig.WithRetryMode(awssdk.RetryModeStandard),
		awsconfig.WithRetryMaxAttempts(3),
	}
	if a.cfg.Region != "" {
		opts = append(opts, awsconfig.WithRegion(a.cfg.Region))
	}
	baseCfg, err := awsconfig.LoadDefaultConfig(ctx, opts...)
	if err != nil {
		return nil, fmt.Errorf("failed to load AWS configuration: %w", err)
	}

	stsClient := sts.NewFromConfig(baseCfg)

	sessionName := a.cfg.RoleSessionNamePrefix
	if sessionName == "" {
		sessionName = "dlp-cloud-scan"
	}

	// The customer account is derived from the role ARN so account-level
	// assessments (e.g. account Public Access Block) target the right account.
	accountID := accountFromRoleARN(a.cfg.RoleARN)

	provider := stscreds.NewAssumeRoleProvider(stsClient, a.cfg.RoleARN,
		func(o *stscreds.AssumeRoleOptions) {
			o.RoleSessionName = sessionName + "-" + uuid.New().String()[:8]
			o.ExternalID = awssdk.String(a.cfg.ExternalID)
			o.Duration = DefaultSessionDuration
		})

	cfg := baseCfg.Copy()
	cfg.Credentials = awssdk.NewCredentialsCache(provider)
	if cfg.Region == "" {
		cfg.Region = "us-east-1"
	}

	return &Session{Config: cfg, AccountID: accountID}, nil
}

// profileAuthenticator loads credentials from a named local profile. It is used
// only when the server explicitly enables local development/testing mode.
type profileAuthenticator struct {
	cfg AWSConfig
}

func (a *profileAuthenticator) Authenticate(ctx context.Context) (*Session, error) {
	opts := []func(*awsconfig.LoadOptions) error{
		awsconfig.WithSharedConfigProfile(a.cfg.Profile),
		awsconfig.WithRetryMode(awssdk.RetryModeStandard),
		awsconfig.WithRetryMaxAttempts(3),
	}
	if a.cfg.Region != "" {
		opts = append(opts, awsconfig.WithRegion(a.cfg.Region))
	}
	cfg, err := awsconfig.LoadDefaultConfig(ctx, opts...)
	if err != nil {
		return nil, fmt.Errorf("failed to load AWS profile configuration: %w", err)
	}

	// Resolve the account ID of the local identity for account-level checks.
	stsClient := sts.NewFromConfig(cfg)
	identity, err := stsClient.GetCallerIdentity(ctx, &sts.GetCallerIdentityInput{})
	if err != nil {
		return nil, fmt.Errorf("failed to resolve AWS account identity: %w", err)
	}
	accountID := ""
	if identity.Account != nil {
		accountID = *identity.Account
	}
	return &Session{Config: cfg, AccountID: accountID}, nil
}

// newAuthenticator returns the appropriate authenticator for the configuration.
func newAuthenticator(cfg AWSConfig) Authenticator {
	if cfg.AllowProfile && cfg.Profile != "" {
		return &profileAuthenticator{cfg: cfg}
	}
	return &assumeRoleAuthenticator{cfg: cfg}
}

// accountFromRoleARN extracts the account ID from an IAM role ARN of the form
// arn:aws:iam::123456789012:role/Name. It returns "" if the ARN is malformed.
func accountFromRoleARN(arn string) string {
	parts := strings.Split(arn, ":")
	if len(parts) >= 6 && parts[0] == "arn" && parts[2] == "iam" {
		if id := parts[4]; id != "" && len(id) <= 12 {
			return id
		}
	}
	return ""
}

// authError converts an authentication failure into a non-sensitive ScanError.
func authError(scope string, err error) *scanError {
	kind, _ := classifyError(err)
	switch kind {
	case kindAuth:
		return &scanError{scope: scope, category: "authentication", retryable: false, message: sanitize(kind)}
	case kindAuthz:
		return &scanError{scope: scope, category: "access_denied", retryable: false, message: sanitize(kind)}
	case kindThrottled:
		return &scanError{scope: scope, category: "throttled", retryable: true, message: sanitize(kind)}
	case kindCancelled:
		return &scanError{scope: scope, category: "cancelled", retryable: false, message: sanitize(kind)}
	default:
		return &scanError{scope: scope, category: "authentication", retryable: false, message: "authentication failed"}
	}
}