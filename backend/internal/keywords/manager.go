package keywords

import (
	"context"
	"database/sql"
	"encoding/csv"
	"fmt"
	"strings"
	"time"

	"github.com/google/uuid"
	"github.com/lib/pq"
)

// Keyword represents a keyword rule for content inspection
type Keyword struct {
	ID            string    `json:"id"`
	Keyword       string    `json:"keyword"`
	MatchType     string    `json:"match_type"` // EXACT, PARTIAL, REGEX
	CaseSensitive bool      `json:"case_sensitive"`
	Classification string   `json:"classification"` // PUBLIC, PRIVATE, CONFIDENTIAL, RESTRICTED
	Priority      int       `json:"priority"`
	HardBlock     bool      `json:"hard_block"`
	Description   string    `json:"description"`
	Tags          []string  `json:"tags"`
	GroupID       *string   `json:"group_id,omitempty"`
	Enabled       bool      `json:"enabled"`
	CreatedAt     time.Time `json:"created_at"`
	UpdatedAt     time.Time `json:"updated_at"`
	CreatedBy     string    `json:"created_by,omitempty"`
}

// KeywordGroup represents a group of related keywords
type KeywordGroup struct {
	ID                    string    `json:"id"`
	Name                  string    `json:"name"`
	Description           string    `json:"description"`
	DefaultClassification string    `json:"default_classification"`
	Enabled               bool      `json:"enabled"`
	CreatedAt             time.Time `json:"created_at"`
	UpdatedAt             time.Time `json:"updated_at"`
}

// KeywordFilters for querying keywords
type KeywordFilters struct {
	Classification string
	MatchType      string
	HardBlock      *bool
	Enabled        *bool
	GroupID        string
	Search         string
	Limit          int
	Offset         int
}

// Service handles keyword operations
type Service struct {
	db      *sql.DB
	matcher *Matcher
}

// NewService creates a new keywords service
func NewService(db *sql.DB) *Service {
	return &Service{
		db:      db,
		matcher: NewMatcher(),
	}
}

// Create creates a new keyword
func (s *Service) Create(ctx context.Context, kw *Keyword) error {
	if kw.ID == "" {
		kw.ID = uuid.New().String()
	}
	kw.CreatedAt = time.Now()
	kw.UpdatedAt = time.Now()

	query := `
		INSERT INTO keywords (id, keyword, match_type, case_sensitive, classification,
			priority, hard_block, description, tags, group_id, enabled, created_at, updated_at, created_by)
		VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12, $13, $14)
	`

	_, err := s.db.ExecContext(ctx, query,
		kw.ID,
		kw.Keyword,
		kw.MatchType,
		kw.CaseSensitive,
		kw.Classification,
		kw.Priority,
		kw.HardBlock,
		kw.Description,
		pq.Array(kw.Tags),
		kw.GroupID,
		kw.Enabled,
		kw.CreatedAt,
		kw.UpdatedAt,
		kw.CreatedBy,
	)

	if err != nil {
		return fmt.Errorf("failed to create keyword: %w", err)
	}

	// Reload matcher cache
	s.reloadMatcher(ctx)
	return nil
}

// GetByID retrieves a keyword by ID
func (s *Service) GetByID(ctx context.Context, id string) (*Keyword, error) {
	query := `
		SELECT id, keyword, match_type, case_sensitive, classification, priority,
			hard_block, description, tags, group_id, enabled, created_at, updated_at, created_by
		FROM keywords
		WHERE id = $1
	`

	var kw Keyword
	var tags pq.StringArray
	var groupID sql.NullString
	var createdBy sql.NullString

	err := s.db.QueryRowContext(ctx, query, id).Scan(
		&kw.ID,
		&kw.Keyword,
		&kw.MatchType,
		&kw.CaseSensitive,
		&kw.Classification,
		&kw.Priority,
		&kw.HardBlock,
		&kw.Description,
		&tags,
		&groupID,
		&kw.Enabled,
		&kw.CreatedAt,
		&kw.UpdatedAt,
		&createdBy,
	)

	if err == sql.ErrNoRows {
		return nil, fmt.Errorf("keyword not found: %s", id)
	}
	if err != nil {
		return nil, fmt.Errorf("failed to get keyword: %w", err)
	}

	kw.Tags = tags
	if groupID.Valid {
		kw.GroupID = &groupID.String
	}
	if createdBy.Valid {
		kw.CreatedBy = createdBy.String
	}

	return &kw, nil
}

// List retrieves keywords with filters
func (s *Service) List(ctx context.Context, filters KeywordFilters) ([]*Keyword, int, error) {
	// Build query
	baseQuery := `FROM keywords WHERE 1=1`
	args := []interface{}{}
	argPos := 1

	if filters.Classification != "" {
		baseQuery += fmt.Sprintf(" AND classification = $%d", argPos)
		args = append(args, filters.Classification)
		argPos++
	}

	if filters.MatchType != "" {
		baseQuery += fmt.Sprintf(" AND match_type = $%d", argPos)
		args = append(args, filters.MatchType)
		argPos++
	}

	if filters.HardBlock != nil {
		baseQuery += fmt.Sprintf(" AND hard_block = $%d", argPos)
		args = append(args, *filters.HardBlock)
		argPos++
	}

	if filters.Enabled != nil {
		baseQuery += fmt.Sprintf(" AND enabled = $%d", argPos)
		args = append(args, *filters.Enabled)
		argPos++
	}

	if filters.GroupID != "" {
		baseQuery += fmt.Sprintf(" AND group_id = $%d", argPos)
		args = append(args, filters.GroupID)
		argPos++
	}

	if filters.Search != "" {
		baseQuery += fmt.Sprintf(" AND (keyword ILIKE $%d OR description ILIKE $%d)", argPos, argPos+1)
		searchTerm := "%" + filters.Search + "%"
		args = append(args, searchTerm, searchTerm)
		argPos += 2
	}

	// Count total
	var total int
	countQuery := "SELECT COUNT(*) " + baseQuery
	err := s.db.QueryRowContext(ctx, countQuery, args...).Scan(&total)
	if err != nil {
		return nil, 0, fmt.Errorf("failed to count keywords: %w", err)
	}

	// Get results
	if filters.Limit == 0 {
		filters.Limit = 100
	}

	selectQuery := fmt.Sprintf(`
		SELECT id, keyword, match_type, case_sensitive, classification, priority,
			hard_block, description, tags, group_id, enabled, created_at, updated_at, created_by
		%s
		ORDER BY priority DESC, created_at DESC
		LIMIT $%d OFFSET $%d
	`, baseQuery, argPos, argPos+1)

	args = append(args, filters.Limit, filters.Offset)

	rows, err := s.db.QueryContext(ctx, selectQuery, args...)
	if err != nil {
		return nil, 0, fmt.Errorf("failed to query keywords: %w", err)
	}
	defer rows.Close()

	var keywords []*Keyword
	for rows.Next() {
		var kw Keyword
		var tags pq.StringArray
		var groupID sql.NullString
		var createdBy sql.NullString

		err := rows.Scan(
			&kw.ID,
			&kw.Keyword,
			&kw.MatchType,
			&kw.CaseSensitive,
			&kw.Classification,
			&kw.Priority,
			&kw.HardBlock,
			&kw.Description,
			&tags,
			&groupID,
			&kw.Enabled,
			&kw.CreatedAt,
			&kw.UpdatedAt,
			&createdBy,
		)
		if err != nil {
			return nil, 0, fmt.Errorf("failed to scan keyword: %w", err)
		}

		kw.Tags = tags
		if groupID.Valid {
			kw.GroupID = &groupID.String
		}
		if createdBy.Valid {
			kw.CreatedBy = createdBy.String
		}

		keywords = append(keywords, &kw)
	}

	return keywords, total, nil
}

// Update updates an existing keyword
func (s *Service) Update(ctx context.Context, kw *Keyword) error {
	kw.UpdatedAt = time.Now()

	query := `
		UPDATE keywords
		SET keyword = $2, match_type = $3, case_sensitive = $4, classification = $5,
			priority = $6, hard_block = $7, description = $8, tags = $9, group_id = $10,
			enabled = $11, updated_at = $12
		WHERE id = $1
	`

	result, err := s.db.ExecContext(ctx, query,
		kw.ID,
		kw.Keyword,
		kw.MatchType,
		kw.CaseSensitive,
		kw.Classification,
		kw.Priority,
		kw.HardBlock,
		kw.Description,
		pq.Array(kw.Tags),
		kw.GroupID,
		kw.Enabled,
		kw.UpdatedAt,
	)

	if err != nil {
		return fmt.Errorf("failed to update keyword: %w", err)
	}

	rowsAffected, _ := result.RowsAffected()
	if rowsAffected == 0 {
		return fmt.Errorf("keyword not found: %s", kw.ID)
	}

	// Reload matcher cache
	s.reloadMatcher(ctx)
	return nil
}

// Delete deletes a keyword
func (s *Service) Delete(ctx context.Context, id string) error {
	result, err := s.db.ExecContext(ctx, "DELETE FROM keywords WHERE id = $1", id)
	if err != nil {
		return fmt.Errorf("failed to delete keyword: %w", err)
	}

	rowsAffected, _ := result.RowsAffected()
	if rowsAffected == 0 {
		return fmt.Errorf("keyword not found: %s", id)
	}

	// Reload matcher cache
	s.reloadMatcher(ctx)
	return nil
}

// GetHardBlockKeywords returns all hard block keywords
func (s *Service) GetHardBlockKeywords(ctx context.Context) ([]*Keyword, error) {
	enabled := true
	hardBlock := true
	keywords, _, err := s.List(ctx, KeywordFilters{
		Enabled:   &enabled,
		HardBlock: &hardBlock,
		Limit:     1000,
	})
	return keywords, err
}

// TestKeywords tests content against all keywords
func (s *Service) TestKeywords(ctx context.Context, content string) ([]KeywordMatch, error) {
	// Load keywords if not already loaded
	if err := s.reloadMatcher(ctx); err != nil {
		return nil, err
	}

	return s.matcher.MatchContent(content), nil
}

// ImportCSV imports keywords from CSV data
func (s *Service) ImportCSV(ctx context.Context, data []byte, createdBy string) (int, int, error) {
	reader := csv.NewReader(strings.NewReader(string(data)))
	records, err := reader.ReadAll()
	if err != nil {
		return 0, 0, fmt.Errorf("failed to parse CSV: %w", err)
	}

	if len(records) < 2 {
		return 0, 0, fmt.Errorf("CSV must have header row and at least one data row")
	}

	// Parse header
	header := records[0]
	colMap := make(map[string]int)
	for i, col := range header {
		colMap[strings.ToLower(strings.TrimSpace(col))] = i
	}

	imported := 0
	skipped := 0

	for _, row := range records[1:] {
		kw := &Keyword{
			MatchType:     "PARTIAL",
			Classification: "PRIVATE",
			Priority:      50,
			Enabled:       true,
			CreatedBy:     createdBy,
		}

		// Map columns
		if idx, ok := colMap["keyword"]; ok && idx < len(row) {
			kw.Keyword = strings.TrimSpace(row[idx])
		}
		if kw.Keyword == "" {
			skipped++
			continue
		}

		if idx, ok := colMap["match_type"]; ok && idx < len(row) {
			mt := strings.ToUpper(strings.TrimSpace(row[idx]))
			if mt == "EXACT" || mt == "PARTIAL" || mt == "REGEX" {
				kw.MatchType = mt
			}
		}

		if idx, ok := colMap["classification"]; ok && idx < len(row) {
			cls := strings.ToUpper(strings.TrimSpace(row[idx]))
			if cls == "PUBLIC" || cls == "PRIVATE" || cls == "CONFIDENTIAL" || cls == "RESTRICTED" {
				kw.Classification = cls
			}
		}

		if idx, ok := colMap["description"]; ok && idx < len(row) {
			kw.Description = strings.TrimSpace(row[idx])
		}

		if idx, ok := colMap["hard_block"]; ok && idx < len(row) {
			hb := strings.ToLower(strings.TrimSpace(row[idx]))
			kw.HardBlock = hb == "true" || hb == "yes" || hb == "1"
		}

		if err := s.Create(ctx, kw); err != nil {
			skipped++
			continue
		}
		imported++
	}

	return imported, skipped, nil
}

// ExportCSV exports all keywords as CSV
func (s *Service) ExportCSV(ctx context.Context) ([]byte, error) {
	keywords, _, err := s.List(ctx, KeywordFilters{Limit: 10000})
	if err != nil {
		return nil, err
	}

	var buf strings.Builder
	writer := csv.NewWriter(&buf)

	// Header
	writer.Write([]string{"id", "keyword", "match_type", "case_sensitive", "classification", "priority", "hard_block", "description", "enabled"})

	for _, kw := range keywords {
		writer.Write([]string{
			kw.ID,
			kw.Keyword,
			kw.MatchType,
			fmt.Sprintf("%t", kw.CaseSensitive),
			kw.Classification,
			fmt.Sprintf("%d", kw.Priority),
			fmt.Sprintf("%t", kw.HardBlock),
			kw.Description,
			fmt.Sprintf("%t", kw.Enabled),
		})
	}

	writer.Flush()
	return []byte(buf.String()), nil
}

// GetGroups returns all keyword groups
func (s *Service) GetGroups(ctx context.Context) ([]*KeywordGroup, error) {
	query := `
		SELECT id, name, description, default_classification, enabled, created_at, updated_at
		FROM keyword_groups
		ORDER BY name
	`

	rows, err := s.db.QueryContext(ctx, query)
	if err != nil {
		return nil, fmt.Errorf("failed to query keyword groups: %w", err)
	}
	defer rows.Close()

	var groups []*KeywordGroup
	for rows.Next() {
		var g KeywordGroup
		err := rows.Scan(&g.ID, &g.Name, &g.Description, &g.DefaultClassification, &g.Enabled, &g.CreatedAt, &g.UpdatedAt)
		if err != nil {
			return nil, fmt.Errorf("failed to scan keyword group: %w", err)
		}
		groups = append(groups, &g)
	}

	return groups, nil
}

// reloadMatcher reloads the keyword matcher with current keywords
func (s *Service) reloadMatcher(ctx context.Context) error {
	enabled := true
	keywords, _, err := s.List(ctx, KeywordFilters{Enabled: &enabled, Limit: 10000})
	if err != nil {
		return err
	}

	s.matcher.LoadKeywords(keywords)
	return nil
}

// GetMatcher returns the keyword matcher
func (s *Service) GetMatcher() *Matcher {
	return s.matcher
}
