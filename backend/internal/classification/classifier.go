package classification

import (
	"context"
	"crypto/sha256"
	"database/sql"
	"encoding/hex"
	"fmt"
	"time"

	"enterprise-dlp-backend/internal/keywords"
	"github.com/lib/pq"
)

// ClassifiedFile represents a file with its classification
type ClassifiedFile struct {
	FileHash             string    `json:"file_hash"`
	FileName             string    `json:"file_name"`
	FilePath             string    `json:"file_path"`
	Classification       string    `json:"classification"`
	ClassificationReason string    `json:"classification_reason"`
	MatchedKeywords      []string  `json:"matched_keywords"`
	FirstSeen            time.Time `json:"first_seen"`
	LastAccessed         time.Time `json:"last_accessed"`
	AccessCount          int       `json:"access_count"`
	FileSize             int64     `json:"file_size"`
	FileType             string    `json:"file_type"`
	MimeType             string    `json:"mime_type"`
	OwnerSID             string    `json:"owner_sid"`
	OwnerUsername        string    `json:"owner_username"`
	Quarantined          bool      `json:"quarantined"`
	QuarantinedAt        *time.Time `json:"quarantined_at,omitempty"`
	QuarantinedBy        string    `json:"quarantined_by,omitempty"`
	CreatedAt            time.Time `json:"created_at"`
	UpdatedAt            time.Time `json:"updated_at"`
}

// ClassificationResult represents the result of classifying content
type ClassificationResult struct {
	Classification       string            `json:"classification"`
	ClassificationReason string            `json:"classification_reason"`
	MatchedKeywords      []string          `json:"matched_keywords"`
	HardBlocked          bool              `json:"hard_blocked"`
	HardBlockReason      string            `json:"hard_block_reason,omitempty"`
	Matches              []keywords.KeywordMatch `json:"matches"`
}

// FileFilters for querying classified files
type FileFilters struct {
	Classification string
	FileType       string
	OwnerSID       string
	Quarantined    *bool
	Search         string
	StartDate      *time.Time
	EndDate        *time.Time
	Limit          int
	Offset         int
}

// Classifier handles file classification
type Classifier struct {
	db              *sql.DB
	scanner         *ContentScanner
	keywordService  *keywords.Service
}

// NewClassifier creates a new file classifier
func NewClassifier(db *sql.DB, keywordService *keywords.Service) *Classifier {
	return &Classifier{
		db:             db,
		scanner:        NewContentScanner(),
		keywordService: keywordService,
	}
}

// ClassifyContent classifies content based on keywords
func (c *Classifier) ClassifyContent(ctx context.Context, content string) (*ClassificationResult, error) {
	matches, err := c.keywordService.TestKeywords(ctx, content)
	if err != nil {
		return nil, fmt.Errorf("failed to test keywords: %w", err)
	}

	result := &ClassificationResult{
		Classification:  "PUBLIC",
		MatchedKeywords: make([]string, 0),
		Matches:         matches,
	}

	if len(matches) == 0 {
		result.ClassificationReason = "No keywords matched"
		return result, nil
	}

	// Check for hard blocks first
	for _, match := range matches {
		if match.HardBlock {
			result.HardBlocked = true
			result.HardBlockReason = fmt.Sprintf("Hard block keyword detected: %s", match.Keyword)
			result.Classification = "RESTRICTED"
			result.ClassificationReason = result.HardBlockReason
			result.MatchedKeywords = append(result.MatchedKeywords, match.Keyword)
			return result, nil
		}
	}

	// Get highest classification from matches
	classificationPriority := map[string]int{
		"PUBLIC":       0,
		"PRIVATE":      1,
		"CONFIDENTIAL": 2,
		"RESTRICTED":   3,
	}

	for _, match := range matches {
		result.MatchedKeywords = append(result.MatchedKeywords, match.Keyword)
		if classificationPriority[match.Classification] > classificationPriority[result.Classification] {
			result.Classification = match.Classification
			result.ClassificationReason = fmt.Sprintf("Matched keyword: %s", match.Keyword)
		}
	}

	return result, nil
}

// ClassifyFile classifies a file and stores the result
func (c *Classifier) ClassifyFile(ctx context.Context, fileData []byte, fileName, filePath, fileType, ownerSID, ownerUsername string) (*ClassifiedFile, *ClassificationResult, error) {
	// Calculate file hash
	hash := sha256.Sum256(fileData)
	fileHash := hex.EncodeToString(hash[:])

	// Extract text content
	text, err := c.scanner.ExtractText(fileData, fileType)
	if err != nil {
		// File might be binary or unsupported format
		// Default to PRIVATE for unreadable files
		text = fileName // At least check the filename
	}

	// Classify content
	classResult, err := c.ClassifyContent(ctx, text)
	if err != nil {
		return nil, nil, err
	}

	// Create or update classified file record
	cf := &ClassifiedFile{
		FileHash:             fileHash,
		FileName:             fileName,
		FilePath:             filePath,
		Classification:       classResult.Classification,
		ClassificationReason: classResult.ClassificationReason,
		MatchedKeywords:      classResult.MatchedKeywords,
		FileSize:             int64(len(fileData)),
		FileType:             fileType,
		MimeType:             GetMimeType(fileType),
		OwnerSID:             ownerSID,
		OwnerUsername:        ownerUsername,
	}

	if err := c.upsertClassifiedFile(ctx, cf); err != nil {
		return nil, nil, err
	}

	return cf, classResult, nil
}

// GetClassification retrieves classification for a file hash
func (c *Classifier) GetClassification(ctx context.Context, fileHash string) (*ClassifiedFile, error) {
	query := `
		SELECT file_hash, file_name, file_path, classification, classification_reason,
			matched_keywords, first_seen, last_accessed, access_count, file_size,
			file_type, mime_type, owner_sid, owner_username, quarantined,
			quarantined_at, quarantined_by, created_at, updated_at
		FROM classified_files
		WHERE file_hash = $1
	`

	var cf ClassifiedFile
	var matchedKeywords pq.StringArray
	var quarantinedAt sql.NullTime
	var quarantinedBy sql.NullString

	err := c.db.QueryRowContext(ctx, query, fileHash).Scan(
		&cf.FileHash,
		&cf.FileName,
		&cf.FilePath,
		&cf.Classification,
		&cf.ClassificationReason,
		&matchedKeywords,
		&cf.FirstSeen,
		&cf.LastAccessed,
		&cf.AccessCount,
		&cf.FileSize,
		&cf.FileType,
		&cf.MimeType,
		&cf.OwnerSID,
		&cf.OwnerUsername,
		&cf.Quarantined,
		&quarantinedAt,
		&quarantinedBy,
		&cf.CreatedAt,
		&cf.UpdatedAt,
	)

	if err == sql.ErrNoRows {
		return nil, nil // Not classified yet
	}
	if err != nil {
		return nil, fmt.Errorf("failed to get classification: %w", err)
	}

	cf.MatchedKeywords = matchedKeywords
	if quarantinedAt.Valid {
		cf.QuarantinedAt = &quarantinedAt.Time
	}
	if quarantinedBy.Valid {
		cf.QuarantinedBy = quarantinedBy.String
	}

	return &cf, nil
}

// ListClassifiedFiles lists classified files with filters
func (c *Classifier) ListClassifiedFiles(ctx context.Context, filters FileFilters) ([]*ClassifiedFile, int, error) {
	baseQuery := `FROM classified_files WHERE 1=1`
	args := []interface{}{}
	argPos := 1

	if filters.Classification != "" {
		baseQuery += fmt.Sprintf(" AND classification = $%d", argPos)
		args = append(args, filters.Classification)
		argPos++
	}

	if filters.FileType != "" {
		baseQuery += fmt.Sprintf(" AND file_type = $%d", argPos)
		args = append(args, filters.FileType)
		argPos++
	}

	if filters.OwnerSID != "" {
		baseQuery += fmt.Sprintf(" AND owner_sid = $%d", argPos)
		args = append(args, filters.OwnerSID)
		argPos++
	}

	if filters.Quarantined != nil {
		baseQuery += fmt.Sprintf(" AND quarantined = $%d", argPos)
		args = append(args, *filters.Quarantined)
		argPos++
	}

	if filters.Search != "" {
		baseQuery += fmt.Sprintf(" AND (file_name ILIKE $%d OR file_path ILIKE $%d)", argPos, argPos+1)
		searchTerm := "%" + filters.Search + "%"
		args = append(args, searchTerm, searchTerm)
		argPos += 2
	}

	if filters.StartDate != nil {
		baseQuery += fmt.Sprintf(" AND first_seen >= $%d", argPos)
		args = append(args, *filters.StartDate)
		argPos++
	}

	if filters.EndDate != nil {
		baseQuery += fmt.Sprintf(" AND first_seen <= $%d", argPos)
		args = append(args, *filters.EndDate)
		argPos++
	}

	// Count total
	var total int
	countQuery := "SELECT COUNT(*) " + baseQuery
	err := c.db.QueryRowContext(ctx, countQuery, args...).Scan(&total)
	if err != nil {
		return nil, 0, fmt.Errorf("failed to count files: %w", err)
	}

	// Get results
	if filters.Limit == 0 {
		filters.Limit = 50
	}

	selectQuery := fmt.Sprintf(`
		SELECT file_hash, file_name, file_path, classification, classification_reason,
			matched_keywords, first_seen, last_accessed, access_count, file_size,
			file_type, mime_type, owner_sid, owner_username, quarantined,
			quarantined_at, quarantined_by, created_at, updated_at
		%s
		ORDER BY last_accessed DESC
		LIMIT $%d OFFSET $%d
	`, baseQuery, argPos, argPos+1)

	args = append(args, filters.Limit, filters.Offset)

	rows, err := c.db.QueryContext(ctx, selectQuery, args...)
	if err != nil {
		return nil, 0, fmt.Errorf("failed to query files: %w", err)
	}
	defer rows.Close()

	var files []*ClassifiedFile
	for rows.Next() {
		var cf ClassifiedFile
		var matchedKeywords pq.StringArray
		var quarantinedAt sql.NullTime
		var quarantinedBy sql.NullString

		err := rows.Scan(
			&cf.FileHash,
			&cf.FileName,
			&cf.FilePath,
			&cf.Classification,
			&cf.ClassificationReason,
			&matchedKeywords,
			&cf.FirstSeen,
			&cf.LastAccessed,
			&cf.AccessCount,
			&cf.FileSize,
			&cf.FileType,
			&cf.MimeType,
			&cf.OwnerSID,
			&cf.OwnerUsername,
			&cf.Quarantined,
			&quarantinedAt,
			&quarantinedBy,
			&cf.CreatedAt,
			&cf.UpdatedAt,
		)
		if err != nil {
			return nil, 0, fmt.Errorf("failed to scan file: %w", err)
		}

		cf.MatchedKeywords = matchedKeywords
		if quarantinedAt.Valid {
			cf.QuarantinedAt = &quarantinedAt.Time
		}
		if quarantinedBy.Valid {
			cf.QuarantinedBy = quarantinedBy.String
		}

		files = append(files, &cf)
	}

	return files, total, nil
}

// Reclassify reclassifies a file
func (c *Classifier) Reclassify(ctx context.Context, fileHash, newClassification, reason, changedBy string) error {
	query := `
		UPDATE classified_files
		SET classification = $2, classification_reason = $3, updated_at = NOW()
		WHERE file_hash = $1
	`

	result, err := c.db.ExecContext(ctx, query, fileHash, newClassification, reason)
	if err != nil {
		return fmt.Errorf("failed to reclassify file: %w", err)
	}

	rowsAffected, _ := result.RowsAffected()
	if rowsAffected == 0 {
		return fmt.Errorf("file not found: %s", fileHash)
	}

	return nil
}

// QuarantineFile quarantines a file
func (c *Classifier) QuarantineFile(ctx context.Context, fileHash, quarantinedBy string) error {
	query := `
		UPDATE classified_files
		SET quarantined = true, quarantined_at = NOW(), quarantined_by = $2, updated_at = NOW()
		WHERE file_hash = $1
	`

	result, err := c.db.ExecContext(ctx, query, fileHash, quarantinedBy)
	if err != nil {
		return fmt.Errorf("failed to quarantine file: %w", err)
	}

	rowsAffected, _ := result.RowsAffected()
	if rowsAffected == 0 {
		return fmt.Errorf("file not found: %s", fileHash)
	}

	return nil
}

// UnquarantineFile removes quarantine from a file
func (c *Classifier) UnquarantineFile(ctx context.Context, fileHash string) error {
	query := `
		UPDATE classified_files
		SET quarantined = false, quarantined_at = NULL, quarantined_by = NULL, updated_at = NOW()
		WHERE file_hash = $1
	`

	result, err := c.db.ExecContext(ctx, query, fileHash)
	if err != nil {
		return fmt.Errorf("failed to unquarantine file: %w", err)
	}

	rowsAffected, _ := result.RowsAffected()
	if rowsAffected == 0 {
		return fmt.Errorf("file not found: %s", fileHash)
	}

	return nil
}

// RecordAccess records a file access event
func (c *Classifier) RecordAccess(ctx context.Context, fileHash, userSID, username, deviceID, hostname, actionType, destinationType, destinationDetail, decision, policyID, ruleID string) error {
	// Insert access history
	query := `
		INSERT INTO file_access_history (file_hash, user_sid, username, device_id, hostname,
			action_type, destination_type, destination_detail, decision, policy_id, rule_id)
		VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11)
	`

	var policyUUID interface{}
	if policyID != "" {
		policyUUID = policyID
	}

	_, err := c.db.ExecContext(ctx, query,
		fileHash, userSID, username, deviceID, hostname,
		actionType, destinationType, destinationDetail, decision,
		policyUUID, ruleID,
	)
	if err != nil {
		return fmt.Errorf("failed to record access: %w", err)
	}

	// Update last accessed
	updateQuery := `
		UPDATE classified_files
		SET last_accessed = NOW(), access_count = access_count + 1
		WHERE file_hash = $1
	`
	c.db.ExecContext(ctx, updateQuery, fileHash)

	return nil
}

// GetAccessHistory retrieves access history for a file
func (c *Classifier) GetAccessHistory(ctx context.Context, fileHash string, limit, offset int) ([]map[string]interface{}, error) {
	if limit == 0 {
		limit = 50
	}

	query := `
		SELECT id, file_hash, user_sid, username, device_id, hostname,
			action_type, destination_type, destination_detail, decision,
			policy_id, rule_id, timestamp
		FROM file_access_history
		WHERE file_hash = $1
		ORDER BY timestamp DESC
		LIMIT $2 OFFSET $3
	`

	rows, err := c.db.QueryContext(ctx, query, fileHash, limit, offset)
	if err != nil {
		return nil, fmt.Errorf("failed to get access history: %w", err)
	}
	defer rows.Close()

	var history []map[string]interface{}
	for rows.Next() {
		var id int64
		var fh, userSID, username, actionType, decision string
		var deviceID, hostname, destType, destDetail, policyID, ruleID sql.NullString
		var timestamp time.Time

		err := rows.Scan(&id, &fh, &userSID, &username, &deviceID, &hostname,
			&actionType, &destType, &destDetail, &decision, &policyID, &ruleID, &timestamp)
		if err != nil {
			continue
		}

		entry := map[string]interface{}{
			"id":          id,
			"file_hash":   fh,
			"user_sid":    userSID,
			"username":    username,
			"action_type": actionType,
			"decision":    decision,
			"timestamp":   timestamp,
		}

		if deviceID.Valid {
			entry["device_id"] = deviceID.String
		}
		if hostname.Valid {
			entry["hostname"] = hostname.String
		}
		if destType.Valid {
			entry["destination_type"] = destType.String
		}
		if destDetail.Valid {
			entry["destination_detail"] = destDetail.String
		}
		if policyID.Valid {
			entry["policy_id"] = policyID.String
		}
		if ruleID.Valid {
			entry["rule_id"] = ruleID.String
		}

		history = append(history, entry)
	}

	return history, nil
}

// upsertClassifiedFile inserts or updates a classified file
func (c *Classifier) upsertClassifiedFile(ctx context.Context, cf *ClassifiedFile) error {
	query := `
		INSERT INTO classified_files (file_hash, file_name, file_path, classification,
			classification_reason, matched_keywords, file_size, file_type, mime_type,
			owner_sid, owner_username, first_seen, last_accessed, access_count)
		VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, NOW(), NOW(), 1)
		ON CONFLICT (file_hash) DO UPDATE SET
			classification = EXCLUDED.classification,
			classification_reason = EXCLUDED.classification_reason,
			matched_keywords = EXCLUDED.matched_keywords,
			last_accessed = NOW(),
			access_count = classified_files.access_count + 1,
			updated_at = NOW()
	`

	_, err := c.db.ExecContext(ctx, query,
		cf.FileHash,
		cf.FileName,
		cf.FilePath,
		cf.Classification,
		cf.ClassificationReason,
		pq.Array(cf.MatchedKeywords),
		cf.FileSize,
		cf.FileType,
		cf.MimeType,
		cf.OwnerSID,
		cf.OwnerUsername,
	)

	if err != nil {
		return fmt.Errorf("failed to upsert classified file: %w", err)
	}

	return nil
}

// CalculateFileHash calculates SHA-256 hash of file data
func CalculateFileHash(data []byte) string {
	hash := sha256.Sum256(data)
	return hex.EncodeToString(hash[:])
}
