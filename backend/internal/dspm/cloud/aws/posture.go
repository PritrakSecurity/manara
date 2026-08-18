package aws

import (
	"context"
	"strconv"
	"time"

	awssdk "github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/s3"
	"github.com/aws/aws-sdk-go-v2/service/s3control"
	s3controltypes "github.com/aws/aws-sdk-go-v2/service/s3control/types"
	s3types "github.com/aws/aws-sdk-go-v2/service/s3/types"

	"manara-dlp/internal/dspm/cloud"
)

// postureOutcome is the result of a single posture rule evaluation.
type postureOutcome struct {
	ruleID   string
	severity string
	title    string
	status   string
	evidence map[string]string
}

// postureRules lists every posture rule in deterministic order.
var postureRules = []string{
	"aws-s3-account-public-access-block",
	"aws-s3-bucket-public-access-block",
	"aws-s3-bucket-public-policy",
	"aws-s3-bucket-public-acl",
	"aws-s3-bucket-ownership-controls",
	"aws-s3-bucket-encryption",
	"aws-s3-bucket-versioning",
	"aws-s3-bucket-object-lock",
	"aws-s3-bucket-logging",
	"aws-s3-bucket-lifecycle",
}

// assessAccountPosture evaluates the account-level Public Access Block once per
// scan and appends its finding.
func (c *S3Connector) assessAccountPosture(ctx context.Context, control S3ControlAPI, accountID string, findings *[]cloud.Finding, errs *[]cloud.ScanError) {
	outcome := c.checkAccountPublicAccessBlock(ctx, control, accountID)
	appendPostureFinding(c, findings, accountID, outcome)
	if outcome.status == cloud.StatusUnknown && outcome.evidence["reason"] == "error" {
		*errs = append(*errs, postureScanError(accountID, outcome))
	}
}

// assessBucketPosture evaluates every posture rule for one bucket. AccessDenied
// on an individual read API is reported as "unknown", never as a security
// misconfiguration.
func (c *S3Connector) assessBucketPosture(ctx context.Context, client S3API, name string, findings *[]cloud.Finding, errs *[]cloud.ScanError) {
	checks := []struct {
		run func() postureOutcome
	}{
		{func() postureOutcome { return c.checkBucketPublicAccessBlock(ctx, client, name) }},
		{func() postureOutcome { return c.checkBucketPolicyStatus(ctx, client, name) }},
		{func() postureOutcome { return c.checkBucketAcl(ctx, client, name) }},
		{func() postureOutcome { return c.checkBucketOwnershipControls(ctx, client, name) }},
		{func() postureOutcome { return c.checkBucketEncryption(ctx, client, name) }},
		{func() postureOutcome { return c.checkBucketVersioning(ctx, client, name) }},
		{func() postureOutcome { return c.checkBucketObjectLock(ctx, client, name) }},
		{func() postureOutcome { return c.checkBucketLogging(ctx, client, name) }},
		{func() postureOutcome { return c.checkBucketLifecycle(ctx, client, name) }},
	}
	for _, check := range checks {
		outcome := check.run()
		appendPostureFinding(c, findings, name, outcome)
		if outcome.status == cloud.StatusUnknown && outcome.evidence["reason"] == "error" {
			*errs = append(*errs, postureScanError(name, outcome))
		}
	}
}

func appendPostureFinding(c *S3Connector, findings *[]cloud.Finding, resourceID string, o postureOutcome) {
	if o.evidence == nil {
		o.evidence = map[string]string{}
	}
	*findings = append(*findings, cloud.Finding{
		ID:           cloud.FindingID(c.id, c.Kind(), cloud.ResourceTypeBucket, resourceID, o.ruleID),
		ConnectorID:  c.id,
		Provider:     c.Kind(),
		ResourceType: cloud.ResourceTypeBucket,
		ResourceID:   resourceID,
		Category:     "security_posture",
		RuleID:       o.ruleID,
		Severity:     o.severity,
		Status:       o.status,
		Title:        o.title,
		Evidence:     o.evidence,
		DetectedAt:   time.Now().UTC(),
	})
}

func postureScanError(resourceID string, o postureOutcome) cloud.ScanError {
	return cloud.ScanError{
		Scope:    "posture",
		Resource: resourceID,
		Category: o.evidence["reason"],
		Message:  "the posture check could not be completed",
	}
}

// unknownOutcome builds the "unknown" outcome used when a read-only API is
// unavailable (AccessDenied), returns an unexpected error, or is unsupported.
func unknownOutcome(ruleID, title, reason string) postureOutcome {
	return postureOutcome{
		ruleID:   ruleID,
		severity: cloud.SeverityInfo,
		title:    title,
		status:   cloud.StatusUnknown,
		evidence: map[string]string{"reason": reason},
	}
}

// checkAccountPublicAccessBlock evaluates the account-level Public Access Block.
func (c *S3Connector) checkAccountPublicAccessBlock(ctx context.Context, control S3ControlAPI, accountID string) postureOutcome {
	ruleID := "aws-s3-account-public-access-block"
	title := "Account-level S3 Public Access Block enabled"
	out, err := control.GetPublicAccessBlock(ctx, &s3control.GetPublicAccessBlockInput{AccountId: awssdk.String(accountID)})
	if err != nil {
		if isAccessDenied(err) {
			return unknownOutcome(ruleID, title, "access_denied")
		}
		if isMissingConfiguration(err) {
			return postureOutcome{ruleID: ruleID, severity: cloud.SeverityHigh, title: title, status: cloud.StatusNonCompliant,
				evidence: map[string]string{"configured": "false", "reason": "account_public_access_block_disabled"}}
		}
		return unknownOutcome(ruleID, title, "error")
	}
	cfg := out.PublicAccessBlockConfiguration
	if cfg == nil {
		return postureOutcome{ruleID: ruleID, severity: cloud.SeverityHigh, title: title, status: cloud.StatusNonCompliant,
			evidence: map[string]string{"configured": "false", "reason": "account_public_access_block_disabled"}}
	}
	return publicAccessBlockOutcome(ruleID, title, cloud.SeverityHigh, pabFromS3Control(cfg), "account")
}

// checkBucketPublicAccessBlock evaluates the bucket-level Public Access Block.
func (c *S3Connector) checkBucketPublicAccessBlock(ctx context.Context, client S3API, name string) postureOutcome {
	ruleID := "aws-s3-bucket-public-access-block"
	title := "Bucket-level S3 Public Access Block enabled"
	out, err := client.GetPublicAccessBlock(ctx, &s3.GetPublicAccessBlockInput{Bucket: awssdk.String(name)})
	if err != nil {
		if isAccessDenied(err) {
			return unknownOutcome(ruleID, title, "access_denied")
		}
		if isMissingConfiguration(err) {
			return postureOutcome{ruleID: ruleID, severity: cloud.SeverityHigh, title: title, status: cloud.StatusNonCompliant,
				evidence: map[string]string{"configured": "false", "reason": "bucket_public_access_block_disabled"}}
		}
		return unknownOutcome(ruleID, title, "error")
	}
	if out.PublicAccessBlockConfiguration == nil {
		return postureOutcome{ruleID: ruleID, severity: cloud.SeverityHigh, title: title, status: cloud.StatusNonCompliant,
			evidence: map[string]string{"configured": "false", "reason": "bucket_public_access_block_disabled"}}
	}
	return publicAccessBlockOutcome(ruleID, title, cloud.SeverityHigh, pabFromS3(out.PublicAccessBlockConfiguration), "bucket")
}

// pabSettings is the provider-neutral view of a Public Access Block
// configuration shared by the S3 and S3 Control API shapes.
type pabSettings struct {
	blockAcls, ignoreAcls, blockPolicy, restrictBuckets bool
}

func pabFromS3(c *s3types.PublicAccessBlockConfiguration) pabSettings {
	if c == nil {
		return pabSettings{}
	}
	return pabSettings{
		blockAcls:        awssdk.ToBool(c.BlockPublicAcls),
		ignoreAcls:       awssdk.ToBool(c.IgnorePublicAcls),
		blockPolicy:      awssdk.ToBool(c.BlockPublicPolicy),
		restrictBuckets:  awssdk.ToBool(c.RestrictPublicBuckets),
	}
}

func pabFromS3Control(c *s3controltypes.PublicAccessBlockConfiguration) pabSettings {
	if c == nil {
		return pabSettings{}
	}
	return pabSettings{
		blockAcls:       awssdk.ToBool(c.BlockPublicAcls),
		ignoreAcls:      awssdk.ToBool(c.IgnorePublicAcls),
		blockPolicy:     awssdk.ToBool(c.BlockPublicPolicy),
		restrictBuckets: awssdk.ToBool(c.RestrictPublicBuckets),
	}
}

func publicAccessBlockOutcome(ruleID, title, severity string, cfg pabSettings, scope string) postureOutcome {
	blockAcls := cfg.blockAcls
	ignoreAcls := cfg.ignoreAcls
	blockPolicy := cfg.blockPolicy
	restrictBuckets := cfg.restrictBuckets
	evidence := map[string]string{
		"block_public_acls":       strconv.FormatBool(blockAcls),
		"ignore_public_acls":      strconv.FormatBool(ignoreAcls),
		"block_public_policy":     strconv.FormatBool(blockPolicy),
		"restrict_public_buckets": strconv.FormatBool(restrictBuckets),
		"scope":                   scope,
	}
	if blockAcls && ignoreAcls && blockPolicy && restrictBuckets {
		return postureOutcome{ruleID: ruleID, severity: severity, title: title, status: cloud.StatusCompliant, evidence: evidence}
	}
	evidence["reason"] = "public_access_block_partially_disabled"
	return postureOutcome{ruleID: ruleID, severity: severity, title: title, status: cloud.StatusNonCompliant, evidence: evidence}
}

// checkBucketPolicyStatus evaluates whether the bucket policy is public.
func (c *S3Connector) checkBucketPolicyStatus(ctx context.Context, client S3API, name string) postureOutcome {
	ruleID := "aws-s3-bucket-public-policy"
	title := "Bucket policy does not grant public access"
	out, err := client.GetBucketPolicyStatus(ctx, &s3.GetBucketPolicyStatusInput{Bucket: awssdk.String(name)})
	if err != nil {
		if isAccessDenied(err) {
			return unknownOutcome(ruleID, title, "access_denied")
		}
		if isMissingConfiguration(err) {
			// No policy exists, so it cannot be public.
			return postureOutcome{ruleID: ruleID, severity: cloud.SeverityInfo, title: title, status: cloud.StatusCompliant,
				evidence: map[string]string{"policy": "none"}}
		}
		return unknownOutcome(ruleID, title, "error")
	}
	if out.PolicyStatus == nil || !awssdk.ToBool(out.PolicyStatus.IsPublic) {
		return postureOutcome{ruleID: ruleID, severity: cloud.SeverityInfo, title: title, status: cloud.StatusCompliant,
			evidence: map[string]string{"public": "false"}}
	}
	return postureOutcome{ruleID: ruleID, severity: cloud.SeverityCritical, title: title, status: cloud.StatusNonCompliant,
		evidence: map[string]string{"public": "true", "reason": "public_bucket_policy"}}
}

// checkBucketAcl evaluates whether the bucket ACL grants public access.
func (c *S3Connector) checkBucketAcl(ctx context.Context, client S3API, name string) postureOutcome {
	ruleID := "aws-s3-bucket-public-acl"
	title := "Bucket ACL does not grant public access"
	out, err := client.GetBucketAcl(ctx, &s3.GetBucketAclInput{Bucket: awssdk.String(name)})
	if err != nil {
		if isAccessDenied(err) {
			return unknownOutcome(ruleID, title, "access_denied")
		}
		return unknownOutcome(ruleID, title, "error")
	}
	public := 0
	perms := ""
	for _, grant := range out.Grants {
		if grant.Grantee == nil || grant.Grantee.Type != s3types.TypeGroup {
			continue
		}
		uri := ""
		if grant.Grantee.URI != nil {
			uri = *grant.Grantee.URI
		}
		if isPublicGroupURI(uri) {
			public++
			if perms != "" {
				perms += ","
			}
			perms += string(grant.Permission)
		}
	}
	if public == 0 {
		return postureOutcome{ruleID: ruleID, severity: cloud.SeverityInfo, title: title, status: cloud.StatusCompliant,
			evidence: map[string]string{"public_grants": "0"}}
	}
	return postureOutcome{ruleID: ruleID, severity: cloud.SeverityCritical, title: title, status: cloud.StatusNonCompliant,
		evidence: map[string]string{"public_grants": strconv.Itoa(public), "permissions": perms, "reason": "public_acl_grant"}}
}

func isPublicGroupURI(uri string) bool {
	return uri == "http://acs.amazonaws.com/groups/global/AllUsers" ||
		uri == "http://acs.amazonaws.com/groups/global/AuthenticatedUsers" ||
		uri == "https://acs.amazonaws.com/groups/global/AllUsers" ||
		uri == "https://acs.amazonaws.com/groups/global/AuthenticatedUsers"
}

// checkBucketOwnershipControls evaluates the bucket ownership controls rule.
func (c *S3Connector) checkBucketOwnershipControls(ctx context.Context, client S3API, name string) postureOutcome {
	ruleID := "aws-s3-bucket-ownership-controls"
	title := "Bucket ownership controls enforce object ownership"
	out, err := client.GetBucketOwnershipControls(ctx, &s3.GetBucketOwnershipControlsInput{Bucket: awssdk.String(name)})
	if err != nil {
		if isAccessDenied(err) {
			return unknownOutcome(ruleID, title, "access_denied")
		}
		if isMissingConfiguration(err) {
			return postureOutcome{ruleID: ruleID, severity: cloud.SeverityMedium, title: title, status: cloud.StatusNonCompliant,
				evidence: map[string]string{"ownership_controls": "absent", "reason": "ownership_controls_not_configured"}}
		}
		return unknownOutcome(ruleID, title, "error")
	}
	if out.OwnershipControls == nil || len(out.OwnershipControls.Rules) == 0 {
		return postureOutcome{ruleID: ruleID, severity: cloud.SeverityMedium, title: title, status: cloud.StatusNonCompliant,
			evidence: map[string]string{"ownership_controls": "absent", "reason": "ownership_controls_not_configured"}}
	}
	ownership := string(out.OwnershipControls.Rules[0].ObjectOwnership)
	if ownership == "BucketOwnerEnforced" {
		return postureOutcome{ruleID: ruleID, severity: cloud.SeverityInfo, title: title, status: cloud.StatusCompliant,
			evidence: map[string]string{"object_ownership": ownership}}
	}
	return postureOutcome{ruleID: ruleID, severity: cloud.SeverityLow, title: title, status: cloud.StatusNonCompliant,
		evidence: map[string]string{"object_ownership": ownership, "reason": "ownership_not_enforced"}}
}

// checkBucketEncryption evaluates default encryption at rest.
func (c *S3Connector) checkBucketEncryption(ctx context.Context, client S3API, name string) postureOutcome {
	ruleID := "aws-s3-bucket-encryption"
	title := "Bucket encrypts objects at rest"
	out, err := client.GetBucketEncryption(ctx, &s3.GetBucketEncryptionInput{Bucket: awssdk.String(name)})
	if err != nil {
		if isAccessDenied(err) {
			return unknownOutcome(ruleID, title, "access_denied")
		}
		if isMissingConfiguration(err) {
			return postureOutcome{ruleID: ruleID, severity: cloud.SeverityHigh, title: title, status: cloud.StatusNonCompliant,
				evidence: map[string]string{"encryption": "none", "reason": "encryption_not_configured"}}
		}
		return unknownOutcome(ruleID, title, "error")
	}
	if out.ServerSideEncryptionConfiguration == nil || len(out.ServerSideEncryptionConfiguration.Rules) == 0 ||
		out.ServerSideEncryptionConfiguration.Rules[0].ApplyServerSideEncryptionByDefault == nil {
		return postureOutcome{ruleID: ruleID, severity: cloud.SeverityHigh, title: title, status: cloud.StatusNonCompliant,
			evidence: map[string]string{"encryption": "none", "reason": "encryption_not_configured"}}
	}
	byDefault := out.ServerSideEncryptionConfiguration.Rules[0].ApplyServerSideEncryptionByDefault
	algo := string(byDefault.SSEAlgorithm)
	desc := ""
	switch algo {
	case string(s3types.ServerSideEncryptionAes256):
		desc = "encrypted at rest with S3-managed keys (SSE-S3)"
	case string(s3types.ServerSideEncryptionAwsKms):
		desc = "encrypted at rest with AWS KMS (SSE-KMS)"
	case string(s3types.ServerSideEncryptionAwsKmsDsse):
		desc = "encrypted at rest with dual-layer AWS KMS (DSSE-KMS)"
	default:
		return unknownOutcome(ruleID, title, "unsupported_algorithm")
	}
	evidence := map[string]string{
		"sse_algorithm":         algo,
		"kms_key_configured":    strconv.FormatBool(byDefault.KMSMasterKeyID != nil && *byDefault.KMSMasterKeyID != ""),
		"bucket_key_enabled":    strconv.FormatBool(awssdk.ToBool(out.ServerSideEncryptionConfiguration.Rules[0].BucketKeyEnabled)),
		"description":           desc,
	}
	return postureOutcome{ruleID: ruleID, severity: cloud.SeverityInfo, title: title, status: cloud.StatusCompliant, evidence: evidence}
}

// checkBucketVersioning evaluates bucket versioning state.
func (c *S3Connector) checkBucketVersioning(ctx context.Context, client S3API, name string) postureOutcome {
	ruleID := "aws-s3-bucket-versioning"
	title := "Bucket versioning is enabled"
	out, err := client.GetBucketVersioning(ctx, &s3.GetBucketVersioningInput{Bucket: awssdk.String(name)})
	if err != nil {
		if isAccessDenied(err) {
			return unknownOutcome(ruleID, title, "access_denied")
		}
		return unknownOutcome(ruleID, title, "error")
	}
	switch out.Status {
	case s3types.BucketVersioningStatusEnabled:
		return postureOutcome{ruleID: ruleID, severity: cloud.SeverityInfo, title: title, status: cloud.StatusCompliant,
			evidence: map[string]string{"versioning": "enabled"}}
	case s3types.BucketVersioningStatusSuspended:
		return postureOutcome{ruleID: ruleID, severity: cloud.SeverityMedium, title: title, status: cloud.StatusNonCompliant,
			evidence: map[string]string{"versioning": "suspended", "reason": "versioning_suspended"}}
	default:
		return postureOutcome{ruleID: ruleID, severity: cloud.SeverityMedium, title: title, status: cloud.StatusNonCompliant,
			evidence: map[string]string{"versioning": "not_configured", "reason": "versioning_not_configured"}}
	}
}

// checkBucketObjectLock evaluates S3 Object Lock state.
func (c *S3Connector) checkBucketObjectLock(ctx context.Context, client S3API, name string) postureOutcome {
	ruleID := "aws-s3-bucket-object-lock"
	title := "Bucket Object Lock is enabled"
	out, err := client.GetObjectLockConfiguration(ctx, &s3.GetObjectLockConfigurationInput{Bucket: awssdk.String(name)})
	if err != nil {
		if isAccessDenied(err) {
			return unknownOutcome(ruleID, title, "access_denied")
		}
		if isMissingConfiguration(err) {
			return postureOutcome{ruleID: ruleID, severity: cloud.SeverityLow, title: title, status: cloud.StatusNonCompliant,
				evidence: map[string]string{"object_lock": "absent", "reason": "object_lock_not_configured"}}
		}
		return unknownOutcome(ruleID, title, "error")
	}
	if out.ObjectLockConfiguration != nil && out.ObjectLockConfiguration.ObjectLockEnabled == s3types.ObjectLockEnabledEnabled {
		return postureOutcome{ruleID: ruleID, severity: cloud.SeverityInfo, title: title, status: cloud.StatusCompliant,
			evidence: map[string]string{"object_lock": "enabled"}}
	}
	return postureOutcome{ruleID: ruleID, severity: cloud.SeverityLow, title: title, status: cloud.StatusNonCompliant,
		evidence: map[string]string{"object_lock": "disabled", "reason": "object_lock_not_enabled"}}
}

// checkBucketLogging evaluates whether access logging is enabled.
func (c *S3Connector) checkBucketLogging(ctx context.Context, client S3API, name string) postureOutcome {
	ruleID := "aws-s3-bucket-logging"
	title := "Bucket access logging is enabled"
	out, err := client.GetBucketLogging(ctx, &s3.GetBucketLoggingInput{Bucket: awssdk.String(name)})
	if err != nil {
		if isAccessDenied(err) {
			return unknownOutcome(ruleID, title, "access_denied")
		}
		return unknownOutcome(ruleID, title, "error")
	}
	if out.LoggingEnabled != nil {
		target := ""
		if out.LoggingEnabled.TargetBucket != nil {
			target = *out.LoggingEnabled.TargetBucket
		}
		return postureOutcome{ruleID: ruleID, severity: cloud.SeverityInfo, title: title, status: cloud.StatusCompliant,
			evidence: map[string]string{"logging": "enabled", "target_bucket": target}}
	}
	return postureOutcome{ruleID: ruleID, severity: cloud.SeverityMedium, title: title, status: cloud.StatusNonCompliant,
		evidence: map[string]string{"logging": "disabled", "reason": "logging_not_enabled"}}
}

// checkBucketLifecycle evaluates whether a lifecycle policy is configured.
func (c *S3Connector) checkBucketLifecycle(ctx context.Context, client S3API, name string) postureOutcome {
	ruleID := "aws-s3-bucket-lifecycle"
	title := "Bucket lifecycle policy is configured"
	out, err := client.GetBucketLifecycleConfiguration(ctx, &s3.GetBucketLifecycleConfigurationInput{Bucket: awssdk.String(name)})
	if err != nil {
		if isAccessDenied(err) {
			return unknownOutcome(ruleID, title, "access_denied")
		}
		if isMissingConfiguration(err) {
			return postureOutcome{ruleID: ruleID, severity: cloud.SeverityLow, title: title, status: cloud.StatusNonCompliant,
				evidence: map[string]string{"lifecycle": "absent", "reason": "lifecycle_not_configured"}}
		}
		return unknownOutcome(ruleID, title, "error")
	}
	if len(out.Rules) == 0 {
		return postureOutcome{ruleID: ruleID, severity: cloud.SeverityLow, title: title, status: cloud.StatusNonCompliant,
			evidence: map[string]string{"lifecycle": "absent", "reason": "lifecycle_not_configured"}}
	}
	return postureOutcome{ruleID: ruleID, severity: cloud.SeverityInfo, title: title, status: cloud.StatusCompliant,
		evidence: map[string]string{"lifecycle": "configured", "rules": strconv.Itoa(len(out.Rules))}}
}
