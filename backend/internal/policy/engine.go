package policy

import (
	"context"
	"database/sql"
	"encoding/json"
	"fmt"
	"strings"

	"enterprise-dlp-backend/internal/approval"
	"enterprise-dlp-backend/internal/classification"
	"enterprise-dlp-backend/internal/keywords"
	"enterprise-dlp-backend/internal/ownership"
)

// FileEvent represents a file operation event for policy evaluation
type FileEvent struct {
	FileHash          string `json:"file_hash"`
	FileName          string `json:"file_name"`
	FilePath          string `json:"file_path"`
	FileSize          int64  `json:"file_size"`
	FileType          string `json:"file_type"`
	FileContent       string `json:"file_content,omitempty"` // Extracted text content

	CurrentUserSID    string `json:"current_user_sid"`
	CurrentUsername   string `json:"current_username"`
	CurrentUserEmail  string `json:"current_user_email,omitempty"`

	DeviceID          string `json:"device_id"`
	Hostname          string `json:"hostname"`
	IPAddress         string `json:"ip_address,omitempty"`

	ActionType        string `json:"action_type"` // UPLOAD, USB_TRANSFER, EMAIL_ATTACH, PRINT, COPY, CLOUD_SYNC
	DestinationType   string `json:"destination_type"` // BROWSER, REMOVABLE_MEDIA, EMAIL, NETWORK_SHARE, CLOUD
	DestinationDetail string `json:"destination_detail"` // URL, path, email address, etc.
}

// PolicyDecision represents the decision made by the policy engine
type PolicyDecision struct {
	Action            string   `json:"action"` // ALLOW, BLOCK, PENDING_APPROVAL
	Reason            string   `json:"reason"`
	PolicyID          string   `json:"policy_id,omitempty"`
	PolicyName        string   `json:"policy_name,omitempty"`
	RuleID            string   `json:"rule_id,omitempty"`
	RuleName          string   `json:"rule_name,omitempty"`
	Classification    string   `json:"classification"`
	MatchedKeywords   []string `json:"matched_keywords,omitempty"`
	HardBlocked       bool     `json:"hard_blocked"`
	AllowOverride     bool     `json:"allow_override"`
	RequiresApproval  bool     `json:"requires_approval"`
	ApproverSID       string   `json:"approver_sid,omitempty"`
	ApproverUsername  string   `json:"approver_username,omitempty"`
	ApprovalTimeout   int      `json:"approval_timeout,omitempty"` // seconds
}

// PolicyRule represents a rule within a policy
type PolicyRule struct {
	RuleID          string   `json:"rule_id"`
	Name            string   `json:"name"`
	ActionType      string   `json:"action_type"`
	DestinationType string   `json:"destination_type,omitempty"`
	Enabled         bool     `json:"enabled"`
	Priority        int      `json:"priority"`

	// Conditions
	AllowedDomains    []string `json:"allowed_domains,omitempty"`
	BlockedDomains    []string `json:"blocked_domains,omitempty"`
	AllowedFileTypes  []string `json:"allowed_file_types,omitempty"`
	BlockedFileTypes  []string `json:"blocked_file_types,omitempty"`
	MaxFileSize       int64    `json:"max_file_size,omitempty"`

	// Enforcement
	Enforcement       string `json:"enforcement"` // ALLOW, BLOCK, REQUIRE_OWNER_APPROVAL, REQUIRE_ADMIN_APPROVAL

	// Actions
	Logging           bool   `json:"logging"`
	Notification      bool   `json:"notification"`
	AlertSecurityTeam bool   `json:"alert_security_team"`
	QuarantineFile    bool   `json:"quarantine_file"`

	Description       string `json:"description,omitempty"`
}

// ClassificationPolicy maps classification levels to policies
type ClassificationPolicy struct {
	Classification string       `json:"classification"`
	PolicyID       string       `json:"policy_id"`
	PolicyName     string       `json:"policy_name"`
	Rules          []PolicyRule `json:"rules"`
	Priority       int          `json:"priority"`
}

// Engine is the policy evaluation engine
type Engine struct {
	db                *sql.DB
	policyService     *Service
	keywordService    *keywords.Service
	classifierService *classification.Classifier
	ownershipTracker  *ownership.Tracker
	approvalService   *approval.WorkflowService
}

// NewEngine creates a new policy evaluation engine
func NewEngine(
	db *sql.DB,
	policyService *Service,
	keywordService *keywords.Service,
	classifierService *classification.Classifier,
	ownershipTracker *ownership.Tracker,
	approvalService *approval.WorkflowService,
) *Engine {
	return &Engine{
		db:                db,
		policyService:     policyService,
		keywordService:    keywordService,
		classifierService: classifierService,
		ownershipTracker:  ownershipTracker,
		approvalService:   approvalService,
	}
}

// Evaluate evaluates a file event and returns a policy decision
func (e *Engine) Evaluate(ctx context.Context, event *FileEvent) (*PolicyDecision, error) {
	decision := &PolicyDecision{
		Action:         "BLOCK", // Default to fail-closed
		Reason:         "Default policy: Block all",
		Classification: "PRIVATE",
		AllowOverride:  false,
	}

	// Step 1: Check for hard block keywords first
	if event.FileContent != "" {
		isHardBlocked, hardBlockMatch := e.checkHardBlockKeywords(ctx, event.FileContent)
		if isHardBlocked {
			decision.Action = "BLOCK"
			decision.Reason = fmt.Sprintf("Hard block keyword detected: %s", hardBlockMatch.Keyword)
			decision.HardBlocked = true
			decision.AllowOverride = false
			decision.MatchedKeywords = []string{hardBlockMatch.Keyword}
			decision.Classification = "RESTRICTED"
			return decision, nil
		}
	}

	// Step 2: Get or determine file classification
	fileClass, err := e.getFileClassification(ctx, event)
	if err != nil {
		// Default to PRIVATE if classification fails
		fileClass = "PRIVATE"
	}
	decision.Classification = fileClass

	// Step 3: Get applicable policy for classification
	policy, rules := e.getPolicyForClassification(ctx, fileClass)
	if policy != nil {
		decision.PolicyID = policy.ID.String()
		decision.PolicyName = policy.Name
	}

	// Step 4: Find matching rule
	matchingRule := e.findMatchingRule(rules, event)
	if matchingRule != nil {
		decision.RuleID = matchingRule.RuleID
		decision.RuleName = matchingRule.Name
	}

	// Step 5: Apply enforcement based on classification
	e.applyEnforcement(ctx, event, matchingRule, fileClass, decision)

	return decision, nil
}

// checkHardBlockKeywords checks if content contains any hard block keywords
func (e *Engine) checkHardBlockKeywords(ctx context.Context, content string) (bool, *keywords.KeywordMatch) {
	if e.keywordService == nil {
		return false, nil
	}

	matches, err := e.keywordService.TestKeywords(ctx, content)
	if err != nil {
		return false, nil
	}

	for _, match := range matches {
		if match.HardBlock {
			return true, &match
		}
	}

	return false, nil
}

// getFileClassification gets or determines the classification for a file
func (e *Engine) getFileClassification(ctx context.Context, event *FileEvent) (string, error) {
	// First, check if file is already classified
	if e.classifierService != nil && event.FileHash != "" {
		existing, err := e.classifierService.GetClassification(ctx, event.FileHash)
		if err == nil && existing != nil {
			return existing.Classification, nil
		}
	}

	// Classify based on content
	if event.FileContent != "" && e.keywordService != nil {
		matches, err := e.keywordService.TestKeywords(ctx, event.FileContent)
		if err == nil && len(matches) > 0 {
			// Get highest classification from matches
			return e.getHighestClassification(matches), nil
		}
	}

	// Default to PRIVATE for unknown files
	return "PRIVATE", nil
}

// getHighestClassification returns the highest classification level from matches
func (e *Engine) getHighestClassification(matches []keywords.KeywordMatch) string {
	priority := map[string]int{
		"PUBLIC":       0,
		"PRIVATE":      1,
		"CONFIDENTIAL": 2,
		"RESTRICTED":   3,
	}

	highest := "PUBLIC"
	for _, match := range matches {
		if priority[match.Classification] > priority[highest] {
			highest = match.Classification
		}
	}

	return highest
}

// getPolicyForClassification returns the policy and rules for a classification
func (e *Engine) getPolicyForClassification(ctx context.Context, classification string) (*Policy, []PolicyRule) {
	// Query for policy that matches classification
	query := `
		SELECT id, name, rules FROM policies
		WHERE enabled = true AND rules::text ILIKE $1
		ORDER BY priority DESC
		LIMIT 1
	`

	var policy Policy
	var rulesJSON string

	err := e.db.QueryRowContext(ctx, query, "%"+classification+"%").Scan(
		&policy.ID,
		&policy.Name,
		&rulesJSON,
	)

	if err != nil {
		// Return default policy rules based on classification
		return nil, e.getDefaultRulesForClassification(classification)
	}

	// Parse rules
	var rulesWrapper struct {
		Rules []PolicyRule `json:"rules"`
	}
	if err := json.Unmarshal([]byte(rulesJSON), &rulesWrapper); err != nil {
		return &policy, e.getDefaultRulesForClassification(classification)
	}

	return &policy, rulesWrapper.Rules
}

// getDefaultRulesForClassification returns default rules based on classification
func (e *Engine) getDefaultRulesForClassification(classification string) []PolicyRule {
	switch classification {
	case "PUBLIC":
		return []PolicyRule{
			{RuleID: "default-public-allow", Name: "Allow Public Data", Enforcement: "ALLOW", Logging: true},
		}
	case "PRIVATE":
		return []PolicyRule{
			{RuleID: "default-private-upload", Name: "Block Private Upload", ActionType: "UPLOAD", Enforcement: "BLOCK", Logging: true},
			{RuleID: "default-private-usb", Name: "Block Private USB", ActionType: "USB_TRANSFER", Enforcement: "BLOCK", Logging: true},
			{RuleID: "default-private-email", Name: "Internal Email Only", ActionType: "EMAIL_ATTACH", Enforcement: "ALLOW", Logging: true},
		}
	case "CONFIDENTIAL":
		return []PolicyRule{
			{RuleID: "default-conf-upload", Name: "Require Approval for Upload", ActionType: "UPLOAD", Enforcement: "REQUIRE_OWNER_APPROVAL", Logging: true},
			{RuleID: "default-conf-usb", Name: "Require Approval for USB", ActionType: "USB_TRANSFER", Enforcement: "REQUIRE_OWNER_APPROVAL", Logging: true},
			{RuleID: "default-conf-email", Name: "Internal Email with Approval", ActionType: "EMAIL_ATTACH", Enforcement: "REQUIRE_OWNER_APPROVAL", Logging: true},
			{RuleID: "default-conf-print", Name: "Require Approval for Print", ActionType: "PRINT", Enforcement: "REQUIRE_OWNER_APPROVAL", Logging: true},
		}
	case "RESTRICTED":
		return []PolicyRule{
			{RuleID: "default-restricted-all", Name: "Block All Restricted", Enforcement: "BLOCK", Logging: true, AlertSecurityTeam: true},
		}
	default:
		return []PolicyRule{
			{RuleID: "default-deny", Name: "Default Deny", Enforcement: "BLOCK", Logging: true},
		}
	}
}

// findMatchingRule finds the first matching rule for an event
func (e *Engine) findMatchingRule(rules []PolicyRule, event *FileEvent) *PolicyRule {
	for _, rule := range rules {
		if !rule.Enabled && rule.RuleID != "" && !strings.HasPrefix(rule.RuleID, "default-") {
			continue
		}

		// Check action type match
		if rule.ActionType != "" && rule.ActionType != event.ActionType {
			continue
		}

		// Check destination type match
		if rule.DestinationType != "" && rule.DestinationType != event.DestinationType {
			continue
		}

		// Check file type restrictions
		if len(rule.BlockedFileTypes) > 0 {
			if containsIgnoreCase(rule.BlockedFileTypes, event.FileType) {
				return &rule
			}
		}

		// Check domain restrictions
		if len(rule.BlockedDomains) > 0 && event.DestinationDetail != "" {
			for _, domain := range rule.BlockedDomains {
				if strings.Contains(strings.ToLower(event.DestinationDetail), strings.ToLower(domain)) {
					return &rule
				}
			}
		}

		// Check file size
		if rule.MaxFileSize > 0 && event.FileSize > rule.MaxFileSize {
			return &rule
		}

		// Rule matches
		return &rule
	}

	return nil
}

// applyEnforcement applies the enforcement action based on the rule and classification
func (e *Engine) applyEnforcement(ctx context.Context, event *FileEvent, rule *PolicyRule, classification string, decision *PolicyDecision) {
	// Determine enforcement based on rule or classification defaults
	var enforcement string
	if rule != nil {
		enforcement = rule.Enforcement
	} else {
		// Default enforcement based on classification
		switch classification {
		case "PUBLIC":
			enforcement = "ALLOW"
		case "PRIVATE":
			enforcement = "BLOCK"
		case "CONFIDENTIAL":
			enforcement = "REQUIRE_OWNER_APPROVAL"
		case "RESTRICTED":
			enforcement = "BLOCK"
		default:
			enforcement = "BLOCK"
		}
	}

	switch enforcement {
	case "ALLOW":
		decision.Action = "ALLOW"
		decision.Reason = "Action allowed by policy"
		decision.AllowOverride = true

	case "BLOCK":
		decision.Action = "BLOCK"
		decision.Reason = fmt.Sprintf("Action blocked for %s classification", classification)
		decision.AllowOverride = (classification != "RESTRICTED")

	case "REQUIRE_OWNER_APPROVAL":
		// Check if user is the owner
		isOwner, err := e.checkOwnership(ctx, event.FileHash, event.CurrentUserSID)
		if err == nil && isOwner {
			decision.Action = "ALLOW"
			decision.Reason = "User is the file owner"
			decision.AllowOverride = true
		} else {
			// Check for cached approval
			if e.approvalService != nil {
				cached, _ := e.approvalService.CheckCachedApproval(ctx, event.FileHash, event.CurrentUserSID, event.ActionType, event.DestinationDetail)
				if cached {
					decision.Action = "ALLOW"
					decision.Reason = "Previously approved by owner"
					decision.AllowOverride = true
					return
				}
			}

			// Require approval
			decision.Action = "PENDING_APPROVAL"
			decision.Reason = "Requires owner approval"
			decision.RequiresApproval = true
			decision.AllowOverride = false
			decision.ApprovalTimeout = 300 // 5 minutes

			// Get owner info
			if e.ownershipTracker != nil {
				ownerSID, _ := e.ownershipTracker.GetOwnerSID(ctx, event.FileHash)
				ownerUsername, _ := e.ownershipTracker.GetOwnerUsername(ctx, event.FileHash)
				decision.ApproverSID = ownerSID
				decision.ApproverUsername = ownerUsername
			}
		}

	case "REQUIRE_ADMIN_APPROVAL":
		decision.Action = "PENDING_APPROVAL"
		decision.Reason = "Requires administrator approval"
		decision.RequiresApproval = true
		decision.AllowOverride = false
		decision.ApprovalTimeout = 300
		// Admin SID would come from configuration

	default:
		decision.Action = "BLOCK"
		decision.Reason = "Unknown enforcement action"
		decision.AllowOverride = false
	}
}

// checkOwnership checks if a user is the owner of a file
func (e *Engine) checkOwnership(ctx context.Context, fileHash, userSID string) (bool, error) {
	if e.ownershipTracker == nil {
		return false, fmt.Errorf("ownership tracker not available")
	}
	return e.ownershipTracker.IsOwner(ctx, fileHash, userSID)
}

// Helper function - uses containsIgnoreCase to avoid redeclaration
func containsIgnoreCase(slice []string, item string) bool {
	for _, s := range slice {
		if strings.EqualFold(s, item) {
			return true
		}
	}
	return false
}
