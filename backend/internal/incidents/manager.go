package incidents

import (
	"context"
	"database/sql"
	"encoding/json"
	"fmt"
	"time"

	"github.com/google/uuid"
	"github.com/lib/pq"
)

// Incident represents a security incident
type Incident struct {
	ID          int64     `json:"id"`
	IncidentID  string    `json:"incident_id"`
	Timestamp   time.Time `json:"timestamp"`

	// Severity and category
	Severity string `json:"severity"` // LOW, MEDIUM, HIGH, CRITICAL
	Category string `json:"category"` // DATA_EXFILTRATION, POLICY_VIOLATION, etc.

	// Device info
	DeviceID  string `json:"device_id"`
	Hostname  string `json:"hostname"`
	IPAddress string `json:"ip_address"`

	// User info
	UserSID        string `json:"user_sid"`
	Username       string `json:"username"`
	UserEmail      string `json:"user_email"`
	UserDepartment string `json:"user_department"`

	// File info
	FileHash           string `json:"file_hash"`
	FileName           string `json:"file_name"`
	FilePath           string `json:"file_path"`
	FileSize           int64  `json:"file_size"`
	FileType           string `json:"file_type"`
	FileClassification string `json:"file_classification"`

	// Action details
	ActionAttempted   string `json:"action_attempted"`
	DestinationType   string `json:"destination_type"`
	DestinationDetail string `json:"destination_detail"`

	// Decision
	Decision        string   `json:"decision"` // ALLOW, BLOCK, PENDING_APPROVAL
	BlockReason     string   `json:"block_reason"`
	MatchedKeywords []string `json:"matched_keywords"`

	// Policy info
	PolicyID   string `json:"policy_id"`
	PolicyName string `json:"policy_name"`
	RuleID     string `json:"rule_id"`
	RuleName   string `json:"rule_name"`

	// Approval tracking
	ApprovalRequestID string `json:"approval_request_id"`

	// Investigation status
	Status            string     `json:"status"` // OPEN, INVESTIGATING, RESOLVED, etc.
	AssignedTo        string     `json:"assigned_to"`
	AssignedAt        *time.Time `json:"assigned_at"`
	EscalatedTo       string     `json:"escalated_to"`
	EscalatedAt       *time.Time `json:"escalated_at"`
	InvestigationNotes string    `json:"investigation_notes"`
	ResolutionNotes   string     `json:"resolution_notes"`
	ResolvedAt        *time.Time `json:"resolved_at"`
	ResolvedBy        string     `json:"resolved_by"`

	// Metadata
	Tags      []string               `json:"tags"`
	Metadata  map[string]interface{} `json:"metadata"`
	CreatedAt time.Time              `json:"created_at"`
	UpdatedAt time.Time              `json:"updated_at"`
}

// IncidentNote represents a note on an incident
type IncidentNote struct {
	ID             int64     `json:"id"`
	IncidentID     int64     `json:"incident_id"`
	AuthorUsername string    `json:"author_username"`
	NoteType       string    `json:"note_type"` // COMMENT, STATUS_CHANGE, ASSIGNMENT, etc.
	Content        string    `json:"content"`
	PreviousStatus string    `json:"previous_status"`
	NewStatus      string    `json:"new_status"`
	CreatedAt      time.Time `json:"created_at"`
}

// IncidentFilters for querying incidents
type IncidentFilters struct {
	Severity   string
	Status     string
	Decision   string
	UserSID    string
	DeviceID   string
	PolicyID   string
	AssignedTo string
	Search     string
	StartDate  *time.Time
	EndDate    *time.Time
	Limit      int
	Offset     int
}

// Manager handles incident operations
type Manager struct {
	db *sql.DB
}

// NewManager creates a new incident manager
func NewManager(db *sql.DB) *Manager {
	return &Manager{db: db}
}

// Create creates a new incident
func (m *Manager) Create(ctx context.Context, inc *Incident) error {
	if inc.IncidentID == "" {
		inc.IncidentID = "INC-" + uuid.New().String()[:8]
	}
	if inc.Timestamp.IsZero() {
		inc.Timestamp = time.Now()
	}
	if inc.Status == "" {
		inc.Status = "OPEN"
	}
	inc.CreatedAt = time.Now()
	inc.UpdatedAt = time.Now()

	metadataJSON, _ := json.Marshal(inc.Metadata)
	if inc.Metadata == nil {
		metadataJSON = []byte("{}")
	}

	query := `
		INSERT INTO incidents (
			incident_id, timestamp, severity, category,
			device_id, hostname, ip_address,
			user_sid, username, user_email, user_department,
			file_hash, file_name, file_path, file_size, file_type, file_classification,
			action_attempted, destination_type, destination_detail,
			decision, block_reason, matched_keywords,
			policy_id, policy_name, rule_id, rule_name,
			approval_request_id, status,
			tags, metadata, created_at, updated_at
		) VALUES (
			$1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12, $13, $14, $15, $16, $17,
			$18, $19, $20, $21, $22, $23, $24, $25, $26, $27, $28, $29, $30, $31, $32, $33
		) RETURNING id
	`

	err := m.db.QueryRowContext(ctx, query,
		inc.IncidentID,
		inc.Timestamp,
		inc.Severity,
		inc.Category,
		nullStr(inc.DeviceID),
		nullStr(inc.Hostname),
		nullStr(inc.IPAddress),
		nullStr(inc.UserSID),
		inc.Username,
		nullStr(inc.UserEmail),
		nullStr(inc.UserDepartment),
		nullStr(inc.FileHash),
		nullStr(inc.FileName),
		nullStr(inc.FilePath),
		inc.FileSize,
		nullStr(inc.FileType),
		nullStr(inc.FileClassification),
		inc.ActionAttempted,
		nullStr(inc.DestinationType),
		nullStr(inc.DestinationDetail),
		inc.Decision,
		nullStr(inc.BlockReason),
		pq.Array(inc.MatchedKeywords),
		nullStr(inc.PolicyID),
		nullStr(inc.PolicyName),
		nullStr(inc.RuleID),
		nullStr(inc.RuleName),
		nullStr(inc.ApprovalRequestID),
		inc.Status,
		pq.Array(inc.Tags),
		metadataJSON,
		inc.CreatedAt,
		inc.UpdatedAt,
	).Scan(&inc.ID)

	if err != nil {
		return fmt.Errorf("failed to create incident: %w", err)
	}

	return nil
}

// GetByID retrieves an incident by ID
func (m *Manager) GetByID(ctx context.Context, id int64) (*Incident, error) {
	query := `
		SELECT id, incident_id, timestamp, severity, category,
			device_id, hostname, ip_address,
			user_sid, username, user_email, user_department,
			file_hash, file_name, file_path, file_size, file_type, file_classification,
			action_attempted, destination_type, destination_detail,
			decision, block_reason, matched_keywords,
			policy_id, policy_name, rule_id, rule_name,
			approval_request_id, status, assigned_to, assigned_at,
			escalated_to, escalated_at, investigation_notes, resolution_notes,
			resolved_at, resolved_by, tags, metadata, created_at, updated_at
		FROM incidents
		WHERE id = $1
	`

	inc := &Incident{}
	if err := m.scanIncident(m.db.QueryRowContext(ctx, query, id), inc); err != nil {
		if err == sql.ErrNoRows {
			return nil, fmt.Errorf("incident not found: %d", id)
		}
		return nil, err
	}

	return inc, nil
}

// GetByIncidentID retrieves an incident by incident_id
func (m *Manager) GetByIncidentID(ctx context.Context, incidentID string) (*Incident, error) {
	query := `
		SELECT id, incident_id, timestamp, severity, category,
			device_id, hostname, ip_address,
			user_sid, username, user_email, user_department,
			file_hash, file_name, file_path, file_size, file_type, file_classification,
			action_attempted, destination_type, destination_detail,
			decision, block_reason, matched_keywords,
			policy_id, policy_name, rule_id, rule_name,
			approval_request_id, status, assigned_to, assigned_at,
			escalated_to, escalated_at, investigation_notes, resolution_notes,
			resolved_at, resolved_by, tags, metadata, created_at, updated_at
		FROM incidents
		WHERE incident_id = $1
	`

	inc := &Incident{}
	if err := m.scanIncident(m.db.QueryRowContext(ctx, query, incidentID), inc); err != nil {
		if err == sql.ErrNoRows {
			return nil, fmt.Errorf("incident not found: %s", incidentID)
		}
		return nil, err
	}

	return inc, nil
}

// List retrieves incidents with filters
func (m *Manager) List(ctx context.Context, filters IncidentFilters) ([]*Incident, int, error) {
	baseQuery := `FROM incidents WHERE 1=1`
	args := []interface{}{}
	argPos := 1

	if filters.Severity != "" {
		baseQuery += fmt.Sprintf(" AND severity = $%d", argPos)
		args = append(args, filters.Severity)
		argPos++
	}

	if filters.Status != "" {
		baseQuery += fmt.Sprintf(" AND status = $%d", argPos)
		args = append(args, filters.Status)
		argPos++
	}

	if filters.Decision != "" {
		baseQuery += fmt.Sprintf(" AND decision = $%d", argPos)
		args = append(args, filters.Decision)
		argPos++
	}

	if filters.UserSID != "" {
		baseQuery += fmt.Sprintf(" AND user_sid = $%d", argPos)
		args = append(args, filters.UserSID)
		argPos++
	}

	if filters.DeviceID != "" {
		baseQuery += fmt.Sprintf(" AND device_id = $%d", argPos)
		args = append(args, filters.DeviceID)
		argPos++
	}

	if filters.PolicyID != "" {
		baseQuery += fmt.Sprintf(" AND policy_id = $%d", argPos)
		args = append(args, filters.PolicyID)
		argPos++
	}

	if filters.AssignedTo != "" {
		baseQuery += fmt.Sprintf(" AND assigned_to = $%d", argPos)
		args = append(args, filters.AssignedTo)
		argPos++
	}

	if filters.Search != "" {
		baseQuery += fmt.Sprintf(" AND (file_name ILIKE $%d OR username ILIKE $%d OR hostname ILIKE $%d)", argPos, argPos+1, argPos+2)
		searchTerm := "%" + filters.Search + "%"
		args = append(args, searchTerm, searchTerm, searchTerm)
		argPos += 3
	}

	if filters.StartDate != nil {
		baseQuery += fmt.Sprintf(" AND timestamp >= $%d", argPos)
		args = append(args, *filters.StartDate)
		argPos++
	}

	if filters.EndDate != nil {
		baseQuery += fmt.Sprintf(" AND timestamp <= $%d", argPos)
		args = append(args, *filters.EndDate)
		argPos++
	}

	// Count total
	var total int
	countQuery := "SELECT COUNT(*) " + baseQuery
	err := m.db.QueryRowContext(ctx, countQuery, args...).Scan(&total)
	if err != nil {
		return nil, 0, fmt.Errorf("failed to count incidents: %w", err)
	}

	// Get results
	if filters.Limit == 0 {
		filters.Limit = 50
	}

	selectQuery := fmt.Sprintf(`
		SELECT id, incident_id, timestamp, severity, category,
			device_id, hostname, ip_address,
			user_sid, username, user_email, user_department,
			file_hash, file_name, file_path, file_size, file_type, file_classification,
			action_attempted, destination_type, destination_detail,
			decision, block_reason, matched_keywords,
			policy_id, policy_name, rule_id, rule_name,
			approval_request_id, status, assigned_to, assigned_at,
			escalated_to, escalated_at, investigation_notes, resolution_notes,
			resolved_at, resolved_by, tags, metadata, created_at, updated_at
		%s
		ORDER BY timestamp DESC
		LIMIT $%d OFFSET $%d
	`, baseQuery, argPos, argPos+1)

	args = append(args, filters.Limit, filters.Offset)

	rows, err := m.db.QueryContext(ctx, selectQuery, args...)
	if err != nil {
		return nil, 0, fmt.Errorf("failed to query incidents: %w", err)
	}
	defer rows.Close()

	var incidents []*Incident
	for rows.Next() {
		inc := &Incident{}
		if err := m.scanIncidentRow(rows, inc); err != nil {
			continue
		}
		incidents = append(incidents, inc)
	}

	return incidents, total, nil
}

// UpdateStatus updates the status of an incident
func (m *Manager) UpdateStatus(ctx context.Context, id int64, status, username string) error {
	// Get current status
	inc, err := m.GetByID(ctx, id)
	if err != nil {
		return err
	}

	previousStatus := inc.Status

	query := `
		UPDATE incidents
		SET status = $2, updated_at = NOW()
		WHERE id = $1
	`

	result, err := m.db.ExecContext(ctx, query, id, status)
	if err != nil {
		return fmt.Errorf("failed to update status: %w", err)
	}

	rowsAffected, _ := result.RowsAffected()
	if rowsAffected == 0 {
		return fmt.Errorf("incident not found: %d", id)
	}

	// Add status change note
	m.AddNote(ctx, id, username, "STATUS_CHANGE", fmt.Sprintf("Status changed from %s to %s", previousStatus, status), previousStatus, status)

	return nil
}

// Assign assigns an incident to an analyst
func (m *Manager) Assign(ctx context.Context, id int64, assignTo, assignedBy string) error {
	query := `
		UPDATE incidents
		SET assigned_to = $2, assigned_at = NOW(), status = CASE WHEN status = 'OPEN' THEN 'INVESTIGATING' ELSE status END, updated_at = NOW()
		WHERE id = $1
	`

	result, err := m.db.ExecContext(ctx, query, id, assignTo)
	if err != nil {
		return fmt.Errorf("failed to assign incident: %w", err)
	}

	rowsAffected, _ := result.RowsAffected()
	if rowsAffected == 0 {
		return fmt.Errorf("incident not found: %d", id)
	}

	m.AddNote(ctx, id, assignedBy, "ASSIGNMENT", fmt.Sprintf("Assigned to %s", assignTo), "", "")

	return nil
}

// Escalate escalates an incident
func (m *Manager) Escalate(ctx context.Context, id int64, escalateTo, escalatedBy string) error {
	query := `
		UPDATE incidents
		SET escalated_to = $2, escalated_at = NOW(), status = 'ESCALATED', updated_at = NOW()
		WHERE id = $1
	`

	result, err := m.db.ExecContext(ctx, query, id, escalateTo)
	if err != nil {
		return fmt.Errorf("failed to escalate incident: %w", err)
	}

	rowsAffected, _ := result.RowsAffected()
	if rowsAffected == 0 {
		return fmt.Errorf("incident not found: %d", id)
	}

	m.AddNote(ctx, id, escalatedBy, "ESCALATION", fmt.Sprintf("Escalated to %s", escalateTo), "", "ESCALATED")

	return nil
}

// Resolve resolves an incident
func (m *Manager) Resolve(ctx context.Context, id int64, resolutionNotes, resolvedBy string) error {
	query := `
		UPDATE incidents
		SET status = 'RESOLVED', resolution_notes = $2, resolved_at = NOW(), resolved_by = $3, updated_at = NOW()
		WHERE id = $1
	`

	result, err := m.db.ExecContext(ctx, query, id, resolutionNotes, resolvedBy)
	if err != nil {
		return fmt.Errorf("failed to resolve incident: %w", err)
	}

	rowsAffected, _ := result.RowsAffected()
	if rowsAffected == 0 {
		return fmt.Errorf("incident not found: %d", id)
	}

	m.AddNote(ctx, id, resolvedBy, "RESOLUTION", resolutionNotes, "", "RESOLVED")

	return nil
}

// MarkFalsePositive marks an incident as false positive
func (m *Manager) MarkFalsePositive(ctx context.Context, id int64, notes, markedBy string) error {
	query := `
		UPDATE incidents
		SET status = 'FALSE_POSITIVE', resolution_notes = $2, resolved_at = NOW(), resolved_by = $3, updated_at = NOW()
		WHERE id = $1
	`

	result, err := m.db.ExecContext(ctx, query, id, notes, markedBy)
	if err != nil {
		return fmt.Errorf("failed to mark false positive: %w", err)
	}

	rowsAffected, _ := result.RowsAffected()
	if rowsAffected == 0 {
		return fmt.Errorf("incident not found: %d", id)
	}

	m.AddNote(ctx, id, markedBy, "RESOLUTION", "Marked as false positive: "+notes, "", "FALSE_POSITIVE")

	return nil
}

// AddNote adds a note to an incident
func (m *Manager) AddNote(ctx context.Context, incidentID int64, author, noteType, content, prevStatus, newStatus string) error {
	query := `
		INSERT INTO incident_notes (incident_id, author_username, note_type, content, previous_status, new_status)
		VALUES ($1, $2, $3, $4, $5, $6)
	`

	_, err := m.db.ExecContext(ctx, query, incidentID, author, noteType, content,
		nullStr(prevStatus), nullStr(newStatus))
	return err
}

// GetNotes retrieves notes for an incident
func (m *Manager) GetNotes(ctx context.Context, incidentID int64) ([]*IncidentNote, error) {
	query := `
		SELECT id, incident_id, author_username, note_type, content, previous_status, new_status, created_at
		FROM incident_notes
		WHERE incident_id = $1
		ORDER BY created_at DESC
	`

	rows, err := m.db.QueryContext(ctx, query, incidentID)
	if err != nil {
		return nil, fmt.Errorf("failed to get notes: %w", err)
	}
	defer rows.Close()

	var notes []*IncidentNote
	for rows.Next() {
		note := &IncidentNote{}
		var prevStatus, newStatus sql.NullString

		err := rows.Scan(&note.ID, &note.IncidentID, &note.AuthorUsername, &note.NoteType,
			&note.Content, &prevStatus, &newStatus, &note.CreatedAt)
		if err != nil {
			continue
		}

		note.PreviousStatus = getStr(prevStatus)
		note.NewStatus = getStr(newStatus)
		notes = append(notes, note)
	}

	return notes, nil
}

// GetStats returns incident statistics
func (m *Manager) GetStats(ctx context.Context, days int) (map[string]interface{}, error) {
	if days == 0 {
		days = 7
	}

	stats := make(map[string]interface{})

	// Total counts by severity
	severityQuery := `
		SELECT severity, COUNT(*) FROM incidents
		WHERE timestamp >= NOW() - INTERVAL '1 day' * $1
		GROUP BY severity
	`
	rows, err := m.db.QueryContext(ctx, severityQuery, days)
	if err == nil {
		bySeverity := make(map[string]int)
		for rows.Next() {
			var severity string
			var count int
			rows.Scan(&severity, &count)
			bySeverity[severity] = count
		}
		rows.Close()
		stats["by_severity"] = bySeverity
	}

	// Total counts by status
	statusQuery := `
		SELECT status, COUNT(*) FROM incidents
		WHERE timestamp >= NOW() - INTERVAL '1 day' * $1
		GROUP BY status
	`
	rows, err = m.db.QueryContext(ctx, statusQuery, days)
	if err == nil {
		byStatus := make(map[string]int)
		for rows.Next() {
			var status string
			var count int
			rows.Scan(&status, &count)
			byStatus[status] = count
		}
		rows.Close()
		stats["by_status"] = byStatus
	}

	// Total counts by decision
	decisionQuery := `
		SELECT decision, COUNT(*) FROM incidents
		WHERE timestamp >= NOW() - INTERVAL '1 day' * $1
		GROUP BY decision
	`
	rows, err = m.db.QueryContext(ctx, decisionQuery, days)
	if err == nil {
		byDecision := make(map[string]int)
		for rows.Next() {
			var decision string
			var count int
			rows.Scan(&decision, &count)
			byDecision[decision] = count
		}
		rows.Close()
		stats["by_decision"] = byDecision
	}

	// Daily trend
	trendQuery := `
		SELECT DATE(timestamp), COUNT(*) FROM incidents
		WHERE timestamp >= NOW() - INTERVAL '1 day' * $1
		GROUP BY DATE(timestamp)
		ORDER BY DATE(timestamp)
	`
	rows, err = m.db.QueryContext(ctx, trendQuery, days)
	if err == nil {
		var trend []map[string]interface{}
		for rows.Next() {
			var date time.Time
			var count int
			rows.Scan(&date, &count)
			trend = append(trend, map[string]interface{}{
				"date":  date.Format("2006-01-02"),
				"count": count,
			})
		}
		rows.Close()
		stats["daily_trend"] = trend
	}

	// Open incidents count
	var openCount int
	m.db.QueryRowContext(ctx, "SELECT COUNT(*) FROM incidents WHERE status = 'OPEN'").Scan(&openCount)
	stats["open_count"] = openCount

	return stats, nil
}

// Helper functions

func (m *Manager) scanIncident(row *sql.Row, inc *Incident) error {
	var deviceID, hostname, ipAddress sql.NullString
	var userSID, userEmail, userDept sql.NullString
	var fileHash, fileName, filePath, fileType, fileClass sql.NullString
	var destType, destDetail, blockReason sql.NullString
	var policyID, policyName, ruleID, ruleName sql.NullString
	var approvalReqID, assignedTo, escalatedTo sql.NullString
	var investigationNotes, resolutionNotes, resolvedBy sql.NullString
	var assignedAt, escalatedAt, resolvedAt sql.NullTime
	var matchedKeywords pq.StringArray
	var tags pq.StringArray
	var metadataJSON []byte

	err := row.Scan(
		&inc.ID, &inc.IncidentID, &inc.Timestamp, &inc.Severity, &inc.Category,
		&deviceID, &hostname, &ipAddress,
		&userSID, &inc.Username, &userEmail, &userDept,
		&fileHash, &fileName, &filePath, &inc.FileSize, &fileType, &fileClass,
		&inc.ActionAttempted, &destType, &destDetail,
		&inc.Decision, &blockReason, &matchedKeywords,
		&policyID, &policyName, &ruleID, &ruleName,
		&approvalReqID, &inc.Status, &assignedTo, &assignedAt,
		&escalatedTo, &escalatedAt, &investigationNotes, &resolutionNotes,
		&resolvedAt, &resolvedBy, &tags, &metadataJSON, &inc.CreatedAt, &inc.UpdatedAt,
	)
	if err != nil {
		return err
	}

	inc.DeviceID = getStr(deviceID)
	inc.Hostname = getStr(hostname)
	inc.IPAddress = getStr(ipAddress)
	inc.UserSID = getStr(userSID)
	inc.UserEmail = getStr(userEmail)
	inc.UserDepartment = getStr(userDept)
	inc.FileHash = getStr(fileHash)
	inc.FileName = getStr(fileName)
	inc.FilePath = getStr(filePath)
	inc.FileType = getStr(fileType)
	inc.FileClassification = getStr(fileClass)
	inc.DestinationType = getStr(destType)
	inc.DestinationDetail = getStr(destDetail)
	inc.BlockReason = getStr(blockReason)
	inc.PolicyID = getStr(policyID)
	inc.PolicyName = getStr(policyName)
	inc.RuleID = getStr(ruleID)
	inc.RuleName = getStr(ruleName)
	inc.ApprovalRequestID = getStr(approvalReqID)
	inc.AssignedTo = getStr(assignedTo)
	inc.EscalatedTo = getStr(escalatedTo)
	inc.InvestigationNotes = getStr(investigationNotes)
	inc.ResolutionNotes = getStr(resolutionNotes)
	inc.ResolvedBy = getStr(resolvedBy)
	inc.MatchedKeywords = matchedKeywords
	inc.Tags = tags

	if assignedAt.Valid {
		inc.AssignedAt = &assignedAt.Time
	}
	if escalatedAt.Valid {
		inc.EscalatedAt = &escalatedAt.Time
	}
	if resolvedAt.Valid {
		inc.ResolvedAt = &resolvedAt.Time
	}

	if len(metadataJSON) > 0 {
		json.Unmarshal(metadataJSON, &inc.Metadata)
	}

	return nil
}

func (m *Manager) scanIncidentRow(rows *sql.Rows, inc *Incident) error {
	var deviceID, hostname, ipAddress sql.NullString
	var userSID, userEmail, userDept sql.NullString
	var fileHash, fileName, filePath, fileType, fileClass sql.NullString
	var destType, destDetail, blockReason sql.NullString
	var policyID, policyName, ruleID, ruleName sql.NullString
	var approvalReqID, assignedTo, escalatedTo sql.NullString
	var investigationNotes, resolutionNotes, resolvedBy sql.NullString
	var assignedAt, escalatedAt, resolvedAt sql.NullTime
	var matchedKeywords pq.StringArray
	var tags pq.StringArray
	var metadataJSON []byte

	err := rows.Scan(
		&inc.ID, &inc.IncidentID, &inc.Timestamp, &inc.Severity, &inc.Category,
		&deviceID, &hostname, &ipAddress,
		&userSID, &inc.Username, &userEmail, &userDept,
		&fileHash, &fileName, &filePath, &inc.FileSize, &fileType, &fileClass,
		&inc.ActionAttempted, &destType, &destDetail,
		&inc.Decision, &blockReason, &matchedKeywords,
		&policyID, &policyName, &ruleID, &ruleName,
		&approvalReqID, &inc.Status, &assignedTo, &assignedAt,
		&escalatedTo, &escalatedAt, &investigationNotes, &resolutionNotes,
		&resolvedAt, &resolvedBy, &tags, &metadataJSON, &inc.CreatedAt, &inc.UpdatedAt,
	)
	if err != nil {
		return err
	}

	inc.DeviceID = getStr(deviceID)
	inc.Hostname = getStr(hostname)
	inc.IPAddress = getStr(ipAddress)
	inc.UserSID = getStr(userSID)
	inc.UserEmail = getStr(userEmail)
	inc.UserDepartment = getStr(userDept)
	inc.FileHash = getStr(fileHash)
	inc.FileName = getStr(fileName)
	inc.FilePath = getStr(filePath)
	inc.FileType = getStr(fileType)
	inc.FileClassification = getStr(fileClass)
	inc.DestinationType = getStr(destType)
	inc.DestinationDetail = getStr(destDetail)
	inc.BlockReason = getStr(blockReason)
	inc.PolicyID = getStr(policyID)
	inc.PolicyName = getStr(policyName)
	inc.RuleID = getStr(ruleID)
	inc.RuleName = getStr(ruleName)
	inc.ApprovalRequestID = getStr(approvalReqID)
	inc.AssignedTo = getStr(assignedTo)
	inc.EscalatedTo = getStr(escalatedTo)
	inc.InvestigationNotes = getStr(investigationNotes)
	inc.ResolutionNotes = getStr(resolutionNotes)
	inc.ResolvedBy = getStr(resolvedBy)
	inc.MatchedKeywords = matchedKeywords
	inc.Tags = tags

	if assignedAt.Valid {
		inc.AssignedAt = &assignedAt.Time
	}
	if escalatedAt.Valid {
		inc.EscalatedAt = &escalatedAt.Time
	}
	if resolvedAt.Valid {
		inc.ResolvedAt = &resolvedAt.Time
	}

	if len(metadataJSON) > 0 {
		json.Unmarshal(metadataJSON, &inc.Metadata)
	}

	return nil
}

func nullStr(s string) sql.NullString {
	if s == "" {
		return sql.NullString{}
	}
	return sql.NullString{String: s, Valid: true}
}

func getStr(ns sql.NullString) string {
	if ns.Valid {
		return ns.String
	}
	return ""
}
