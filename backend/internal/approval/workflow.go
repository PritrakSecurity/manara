package approval

import (
	"context"
	"database/sql"
	"fmt"
	"time"

	"github.com/google/uuid"
)

// ApprovalRequest represents an owner approval request
type ApprovalRequest struct {
	RequestID          string     `json:"request_id"`
	FileHash           string     `json:"file_hash"`
	FileName           string     `json:"file_name"`
	FilePath           string     `json:"file_path"`
	FileClassification string     `json:"file_classification"`

	// Requester info
	RequesterSID      string `json:"requester_sid"`
	RequesterUsername string `json:"requester_username"`
	RequesterEmail    string `json:"requester_email"`
	RequesterDeviceID string `json:"requester_device_id"`
	RequesterHostname string `json:"requester_hostname"`

	// Owner info
	OwnerSID      string `json:"owner_sid"`
	OwnerUsername string `json:"owner_username"`
	OwnerEmail    string `json:"owner_email"`

	// Action details
	ActionType        string `json:"action_type"` // UPLOAD, USB_TRANSFER, EMAIL_ATTACH, etc.
	DestinationType   string `json:"destination_type"`
	DestinationDetail string `json:"destination_detail"`

	// Status
	Status          string  `json:"status"` // PENDING, APPROVED, DENIED, TIMEOUT, CANCELLED
	DecisionComment string  `json:"decision_comment"`
	AllowPermanent  bool    `json:"allow_permanent"` // Cache decision for future

	// Timestamps
	CreatedAt    time.Time  `json:"created_at"`
	DecidedAt    *time.Time `json:"decided_at,omitempty"`
	TimeoutAt    time.Time  `json:"timeout_at"`
	NotifiedAt   *time.Time `json:"notified_at,omitempty"`
	ReminderSent bool       `json:"reminder_sent"`

	// Policy context
	PolicyID string `json:"policy_id,omitempty"`
	RuleID   string `json:"rule_id,omitempty"`

	// Computed fields
	SecondsRemaining int `json:"seconds_remaining,omitempty"`
}

// ApprovalFilters for querying approval requests
type ApprovalFilters struct {
	OwnerSID      string
	RequesterSID  string
	Status        string
	ActionType    string
	PendingOnly   bool
	StartDate     *time.Time
	EndDate       *time.Time
	Limit         int
	Offset        int
}

// WorkflowService handles approval workflow operations
type WorkflowService struct {
	db       *sql.DB
	notifier *Notifier
	timeout  time.Duration
}

// NewWorkflowService creates a new approval workflow service
func NewWorkflowService(db *sql.DB, notifier *Notifier) *WorkflowService {
	return &WorkflowService{
		db:       db,
		notifier: notifier,
		timeout:  5 * time.Minute, // Default 5 minute timeout
	}
}

// SetTimeout sets the approval timeout duration
func (s *WorkflowService) SetTimeout(d time.Duration) {
	s.timeout = d
}

// CreateRequest creates a new approval request
func (s *WorkflowService) CreateRequest(ctx context.Context, req *ApprovalRequest) error {
	if req.RequestID == "" {
		req.RequestID = uuid.New().String()
	}
	req.CreatedAt = time.Now()
	req.TimeoutAt = req.CreatedAt.Add(s.timeout)
	req.Status = "PENDING"

	query := `
		INSERT INTO approval_requests (
			request_id, file_hash, file_name, file_path, file_classification,
			requester_sid, requester_username, requester_email, requester_device_id, requester_hostname,
			owner_sid, owner_username, owner_email,
			action_type, destination_type, destination_detail,
			status, allow_permanent,
			created_at, timeout_at,
			policy_id, rule_id
		) VALUES (
			$1, $2, $3, $4, $5, $6, $7, $8, $9, $10,
			$11, $12, $13, $14, $15, $16, $17, $18, $19, $20, $21, $22
		)
	`

	_, err := s.db.ExecContext(ctx, query,
		req.RequestID,
		req.FileHash,
		req.FileName,
		req.FilePath,
		req.FileClassification,
		req.RequesterSID,
		req.RequesterUsername,
		req.RequesterEmail,
		req.RequesterDeviceID,
		req.RequesterHostname,
		req.OwnerSID,
		req.OwnerUsername,
		req.OwnerEmail,
		req.ActionType,
		req.DestinationType,
		req.DestinationDetail,
		req.Status,
		req.AllowPermanent,
		req.CreatedAt,
		req.TimeoutAt,
		nullString(req.PolicyID),
		nullString(req.RuleID),
	)

	if err != nil {
		return fmt.Errorf("failed to create approval request: %w", err)
	}

	// Notify owner
	if s.notifier != nil {
		s.notifier.NotifyApprovalRequest(req)
	}

	return nil
}

// GetRequest retrieves an approval request by ID
func (s *WorkflowService) GetRequest(ctx context.Context, requestID string) (*ApprovalRequest, error) {
	query := `
		SELECT request_id, file_hash, file_name, file_path, file_classification,
			requester_sid, requester_username, requester_email, requester_device_id, requester_hostname,
			owner_sid, owner_username, owner_email,
			action_type, destination_type, destination_detail,
			status, decision_comment, allow_permanent,
			created_at, decided_at, timeout_at, notified_at, reminder_sent,
			policy_id, rule_id
		FROM approval_requests
		WHERE request_id = $1
	`

	req := &ApprovalRequest{}
	var decisionComment, fileName, filePath, fileClassification sql.NullString
	var requesterEmail, requesterDeviceID, requesterHostname sql.NullString
	var ownerEmail, destType, destDetail sql.NullString
	var decidedAt, notifiedAt sql.NullTime
	var policyID, ruleID sql.NullString

	err := s.db.QueryRowContext(ctx, query, requestID).Scan(
		&req.RequestID,
		&req.FileHash,
		&fileName,
		&filePath,
		&fileClassification,
		&req.RequesterSID,
		&req.RequesterUsername,
		&requesterEmail,
		&requesterDeviceID,
		&requesterHostname,
		&req.OwnerSID,
		&req.OwnerUsername,
		&ownerEmail,
		&req.ActionType,
		&destType,
		&destDetail,
		&req.Status,
		&decisionComment,
		&req.AllowPermanent,
		&req.CreatedAt,
		&decidedAt,
		&req.TimeoutAt,
		&notifiedAt,
		&req.ReminderSent,
		&policyID,
		&ruleID,
	)

	if err == sql.ErrNoRows {
		return nil, fmt.Errorf("approval request not found: %s", requestID)
	}
	if err != nil {
		return nil, fmt.Errorf("failed to get approval request: %w", err)
	}

	// Set nullable fields
	req.FileName = nullStringValue(fileName)
	req.FilePath = nullStringValue(filePath)
	req.FileClassification = nullStringValue(fileClassification)
	req.RequesterEmail = nullStringValue(requesterEmail)
	req.RequesterDeviceID = nullStringValue(requesterDeviceID)
	req.RequesterHostname = nullStringValue(requesterHostname)
	req.OwnerEmail = nullStringValue(ownerEmail)
	req.DestinationType = nullStringValue(destType)
	req.DestinationDetail = nullStringValue(destDetail)
	req.DecisionComment = nullStringValue(decisionComment)
	req.PolicyID = nullStringValue(policyID)
	req.RuleID = nullStringValue(ruleID)

	if decidedAt.Valid {
		req.DecidedAt = &decidedAt.Time
	}
	if notifiedAt.Valid {
		req.NotifiedAt = &notifiedAt.Time
	}

	// Calculate remaining time
	if req.Status == "PENDING" {
		remaining := time.Until(req.TimeoutAt)
		if remaining > 0 {
			req.SecondsRemaining = int(remaining.Seconds())
		}
	}

	return req, nil
}

// GetPendingForOwner retrieves pending approval requests for an owner
func (s *WorkflowService) GetPendingForOwner(ctx context.Context, ownerSID string) ([]*ApprovalRequest, error) {
	return s.List(ctx, ApprovalFilters{
		OwnerSID:    ownerSID,
		PendingOnly: true,
		Limit:       100,
	})
}

// List retrieves approval requests with filters
func (s *WorkflowService) List(ctx context.Context, filters ApprovalFilters) ([]*ApprovalRequest, error) {
	baseQuery := `
		SELECT request_id, file_hash, file_name, file_path, file_classification,
			requester_sid, requester_username, requester_email, requester_device_id, requester_hostname,
			owner_sid, owner_username, owner_email,
			action_type, destination_type, destination_detail,
			status, decision_comment, allow_permanent,
			created_at, decided_at, timeout_at, notified_at, reminder_sent,
			policy_id, rule_id
		FROM approval_requests
		WHERE 1=1
	`

	args := []interface{}{}
	argPos := 1

	if filters.OwnerSID != "" {
		baseQuery += fmt.Sprintf(" AND owner_sid = $%d", argPos)
		args = append(args, filters.OwnerSID)
		argPos++
	}

	if filters.RequesterSID != "" {
		baseQuery += fmt.Sprintf(" AND requester_sid = $%d", argPos)
		args = append(args, filters.RequesterSID)
		argPos++
	}

	if filters.Status != "" {
		baseQuery += fmt.Sprintf(" AND status = $%d", argPos)
		args = append(args, filters.Status)
		argPos++
	}

	if filters.ActionType != "" {
		baseQuery += fmt.Sprintf(" AND action_type = $%d", argPos)
		args = append(args, filters.ActionType)
		argPos++
	}

	if filters.PendingOnly {
		baseQuery += " AND status = 'PENDING' AND timeout_at > NOW()"
	}

	if filters.StartDate != nil {
		baseQuery += fmt.Sprintf(" AND created_at >= $%d", argPos)
		args = append(args, *filters.StartDate)
		argPos++
	}

	if filters.EndDate != nil {
		baseQuery += fmt.Sprintf(" AND created_at <= $%d", argPos)
		args = append(args, *filters.EndDate)
		argPos++
	}

	baseQuery += " ORDER BY created_at DESC"

	if filters.Limit > 0 {
		baseQuery += fmt.Sprintf(" LIMIT $%d", argPos)
		args = append(args, filters.Limit)
		argPos++
	}

	if filters.Offset > 0 {
		baseQuery += fmt.Sprintf(" OFFSET $%d", argPos)
		args = append(args, filters.Offset)
	}

	rows, err := s.db.QueryContext(ctx, baseQuery, args...)
	if err != nil {
		return nil, fmt.Errorf("failed to list approval requests: %w", err)
	}
	defer rows.Close()

	var requests []*ApprovalRequest
	for rows.Next() {
		req := &ApprovalRequest{}
		var decisionComment, fileName, filePath, fileClassification sql.NullString
		var requesterEmail, requesterDeviceID, requesterHostname sql.NullString
		var ownerEmail, destType, destDetail sql.NullString
		var decidedAt, notifiedAt sql.NullTime
		var policyID, ruleID sql.NullString

		err := rows.Scan(
			&req.RequestID,
			&req.FileHash,
			&fileName,
			&filePath,
			&fileClassification,
			&req.RequesterSID,
			&req.RequesterUsername,
			&requesterEmail,
			&requesterDeviceID,
			&requesterHostname,
			&req.OwnerSID,
			&req.OwnerUsername,
			&ownerEmail,
			&req.ActionType,
			&destType,
			&destDetail,
			&req.Status,
			&decisionComment,
			&req.AllowPermanent,
			&req.CreatedAt,
			&decidedAt,
			&req.TimeoutAt,
			&notifiedAt,
			&req.ReminderSent,
			&policyID,
			&ruleID,
		)
		if err != nil {
			continue
		}

		req.FileName = nullStringValue(fileName)
		req.FilePath = nullStringValue(filePath)
		req.FileClassification = nullStringValue(fileClassification)
		req.RequesterEmail = nullStringValue(requesterEmail)
		req.RequesterDeviceID = nullStringValue(requesterDeviceID)
		req.RequesterHostname = nullStringValue(requesterHostname)
		req.OwnerEmail = nullStringValue(ownerEmail)
		req.DestinationType = nullStringValue(destType)
		req.DestinationDetail = nullStringValue(destDetail)
		req.DecisionComment = nullStringValue(decisionComment)
		req.PolicyID = nullStringValue(policyID)
		req.RuleID = nullStringValue(ruleID)

		if decidedAt.Valid {
			req.DecidedAt = &decidedAt.Time
		}
		if notifiedAt.Valid {
			req.NotifiedAt = &notifiedAt.Time
		}

		if req.Status == "PENDING" {
			remaining := time.Until(req.TimeoutAt)
			if remaining > 0 {
				req.SecondsRemaining = int(remaining.Seconds())
			}
		}

		requests = append(requests, req)
	}

	return requests, nil
}

// Approve approves an approval request
func (s *WorkflowService) Approve(ctx context.Context, requestID, comment string, permanent bool) error {
	now := time.Now()

	query := `
		UPDATE approval_requests
		SET status = 'APPROVED', decision_comment = $2, allow_permanent = $3, decided_at = $4
		WHERE request_id = $1 AND status = 'PENDING'
	`

	result, err := s.db.ExecContext(ctx, query, requestID, comment, permanent, now)
	if err != nil {
		return fmt.Errorf("failed to approve request: %w", err)
	}

	rowsAffected, _ := result.RowsAffected()
	if rowsAffected == 0 {
		return fmt.Errorf("approval request not found or not pending: %s", requestID)
	}

	// Cache approval if permanent
	if permanent {
		if err := s.cacheApproval(ctx, requestID); err != nil {
			// Log but don't fail
			fmt.Printf("Failed to cache approval: %v\n", err)
		}
	}

	// Notify requester
	if s.notifier != nil {
		req, _ := s.GetRequest(ctx, requestID)
		if req != nil {
			s.notifier.NotifyApprovalDecision(req)
		}
	}

	return nil
}

// Deny denies an approval request
func (s *WorkflowService) Deny(ctx context.Context, requestID, comment string) error {
	now := time.Now()

	query := `
		UPDATE approval_requests
		SET status = 'DENIED', decision_comment = $2, decided_at = $3
		WHERE request_id = $1 AND status = 'PENDING'
	`

	result, err := s.db.ExecContext(ctx, query, requestID, comment, now)
	if err != nil {
		return fmt.Errorf("failed to deny request: %w", err)
	}

	rowsAffected, _ := result.RowsAffected()
	if rowsAffected == 0 {
		return fmt.Errorf("approval request not found or not pending: %s", requestID)
	}

	// Notify requester
	if s.notifier != nil {
		req, _ := s.GetRequest(ctx, requestID)
		if req != nil {
			s.notifier.NotifyApprovalDecision(req)
		}
	}

	return nil
}

// Cancel cancels an approval request
func (s *WorkflowService) Cancel(ctx context.Context, requestID string) error {
	query := `
		UPDATE approval_requests
		SET status = 'CANCELLED', decided_at = NOW()
		WHERE request_id = $1 AND status = 'PENDING'
	`

	result, err := s.db.ExecContext(ctx, query, requestID)
	if err != nil {
		return fmt.Errorf("failed to cancel request: %w", err)
	}

	rowsAffected, _ := result.RowsAffected()
	if rowsAffected == 0 {
		return fmt.Errorf("approval request not found or not pending: %s", requestID)
	}

	return nil
}

// ProcessTimeouts processes timed out approval requests
func (s *WorkflowService) ProcessTimeouts(ctx context.Context) (int, error) {
	query := `
		UPDATE approval_requests
		SET status = 'TIMEOUT', decided_at = NOW()
		WHERE status = 'PENDING' AND timeout_at <= NOW()
	`

	result, err := s.db.ExecContext(ctx, query)
	if err != nil {
		return 0, fmt.Errorf("failed to process timeouts: %w", err)
	}

	rowsAffected, _ := result.RowsAffected()
	return int(rowsAffected), nil
}

// CheckCachedApproval checks if there's a cached approval for an action
func (s *WorkflowService) CheckCachedApproval(ctx context.Context, fileHash, userSID, actionType, destination string) (bool, error) {
	query := `
		SELECT COUNT(*) FROM cached_approvals
		WHERE file_hash = $1 AND user_sid = $2 AND action_type = $3
			AND (destination_pattern IS NULL OR destination_pattern = '' OR $4 LIKE destination_pattern)
			AND (expires_at IS NULL OR expires_at > NOW())
	`

	var count int
	err := s.db.QueryRowContext(ctx, query, fileHash, userSID, actionType, destination).Scan(&count)
	if err != nil {
		return false, err
	}

	return count > 0, nil
}

// cacheApproval stores a permanent approval decision
func (s *WorkflowService) cacheApproval(ctx context.Context, requestID string) error {
	req, err := s.GetRequest(ctx, requestID)
	if err != nil {
		return err
	}

	query := `
		INSERT INTO cached_approvals (file_hash, user_sid, action_type, destination_pattern,
			approved_by_sid, approved_by_username, approval_comment)
		VALUES ($1, $2, $3, $4, $5, $6, $7)
		ON CONFLICT (file_hash, user_sid, action_type, destination_pattern) DO UPDATE SET
			approved_by_sid = EXCLUDED.approved_by_sid,
			approved_by_username = EXCLUDED.approved_by_username,
			approval_comment = EXCLUDED.approval_comment,
			created_at = NOW()
	`

	_, err = s.db.ExecContext(ctx, query,
		req.FileHash,
		req.RequesterSID,
		req.ActionType,
		req.DestinationDetail,
		req.OwnerSID,
		req.OwnerUsername,
		req.DecisionComment,
	)

	return err
}

// GetPendingCount returns count of pending approvals for an owner
func (s *WorkflowService) GetPendingCount(ctx context.Context, ownerSID string) (int, error) {
	var count int
	err := s.db.QueryRowContext(ctx,
		"SELECT COUNT(*) FROM approval_requests WHERE owner_sid = $1 AND status = 'PENDING' AND timeout_at > NOW()",
		ownerSID,
	).Scan(&count)
	return count, err
}

// Helper functions
func nullString(s string) sql.NullString {
	if s == "" {
		return sql.NullString{}
	}
	return sql.NullString{String: s, Valid: true}
}

func nullStringValue(ns sql.NullString) string {
	if ns.Valid {
		return ns.String
	}
	return ""
}
