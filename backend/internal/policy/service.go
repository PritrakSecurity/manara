package policy

import (
	"context"
	"database/sql"
	"encoding/json"
	"fmt"
	"time"

	"github.com/google/uuid"
	_ "github.com/lib/pq"
)

// Policy represents a DLP policy
type Policy struct {
	ID          uuid.UUID       `json:"id"`
	Name        string          `json:"name"`
	Description string          `json:"description"`
	Rules       json.RawMessage `json:"rules"` // JSONB in database
	Priority    int             `json:"priority"`
	Enabled     bool            `json:"enabled"`
	CreatedAt   time.Time       `json:"created_at"`
	UpdatedAt   time.Time       `json:"updated_at"`
	CreatedBy   string          `json:"created_by"`
}

// Service handles policy operations
type Service struct {
	db *sql.DB
}

// NewService creates a new policy service
func NewService(db *sql.DB) *Service {
	return &Service{db: db}
}

// GetPolicy retrieves the active policy for an agent
func (s *Service) GetPolicy(ctx context.Context, agentID string) (*Policy, error) {
	query := `
		SELECT id, name, description, rules, priority, enabled, created_at, updated_at, created_by
		FROM policies
		WHERE enabled = true
		ORDER BY priority DESC, created_at DESC
		LIMIT 1
	`

	var policy Policy
	var rulesJSON string

	err := s.db.QueryRowContext(ctx, query).Scan(
		&policy.ID,
		&policy.Name,
		&policy.Description,
		&rulesJSON,
		&policy.Priority,
		&policy.Enabled,
		&policy.CreatedAt,
		&policy.UpdatedAt,
		&policy.CreatedBy,
	)

	if err == sql.ErrNoRows {
		// Return default policy (block all)
		return s.getDefaultPolicy(), nil
	}

	if err != nil {
		return nil, fmt.Errorf("failed to query policy: %w", err)
	}

	// Parse JSON rules
	policy.Rules = json.RawMessage(rulesJSON)

	return &policy, nil
}

// GetPolicyByID retrieves a specific policy by ID
func (s *Service) GetPolicyByID(ctx context.Context, policyID uuid.UUID) (*Policy, error) {
	query := `
		SELECT id, name, description, rules, priority, enabled, created_at, updated_at, created_by
		FROM policies
		WHERE id = $1
	`

	var policy Policy
	var rulesJSON string

	err := s.db.QueryRowContext(ctx, query, policyID).Scan(
		&policy.ID,
		&policy.Name,
		&policy.Description,
		&rulesJSON,
		&policy.Priority,
		&policy.Enabled,
		&policy.CreatedAt,
		&policy.UpdatedAt,
		&policy.CreatedBy,
	)

	if err != nil {
		return nil, fmt.Errorf("failed to query policy: %w", err)
	}

	policy.Rules = json.RawMessage(rulesJSON)
	return &policy, nil
}

// CreatePolicy creates a new policy
func (s *Service) CreatePolicy(ctx context.Context, policy *Policy) error {
	policy.ID = uuid.New()
	policy.CreatedAt = time.Now()
	policy.UpdatedAt = time.Now()

	query := `
		INSERT INTO policies (id, name, description, rules, priority, enabled, created_at, updated_at, created_by)
		VALUES ($1, $2, $3, $4::jsonb, $5, $6, $7, $8, $9)
	`

	_, err := s.db.ExecContext(ctx, query,
		policy.ID,
		policy.Name,
		policy.Description,
		string(policy.Rules),
		policy.Priority,
		policy.Enabled,
		policy.CreatedAt,
		policy.UpdatedAt,
		policy.CreatedBy,
	)

	if err != nil {
		return fmt.Errorf("failed to create policy: %w", err)
	}

	return nil
}

// UpdatePolicy updates an existing policy
func (s *Service) UpdatePolicy(ctx context.Context, policy *Policy) error {
	policy.UpdatedAt = time.Now()

	query := `
		UPDATE policies
		SET name = $2, description = $3, rules = $4::jsonb, priority = $5, enabled = $6, updated_at = $7
		WHERE id = $1
	`

	_, err := s.db.ExecContext(ctx, query,
		policy.ID,
		policy.Name,
		policy.Description,
		string(policy.Rules),
		policy.Priority,
		policy.Enabled,
		policy.UpdatedAt,
	)

	if err != nil {
		return fmt.Errorf("failed to update policy: %w", err)
	}

	return nil
}

// ListPolicies lists all policies
func (s *Service) ListPolicies(ctx context.Context, limit, offset int) ([]*Policy, error) {
	query := `
		SELECT id, name, description, rules, priority, enabled, created_at, updated_at, created_by
		FROM policies
		ORDER BY priority DESC, created_at DESC
		LIMIT $1 OFFSET $2
	`

	rows, err := s.db.QueryContext(ctx, query, limit, offset)
	if err != nil {
		return nil, fmt.Errorf("failed to query policies: %w", err)
	}
	defer rows.Close()

	var policies []*Policy
	for rows.Next() {
		var policy Policy
		var rulesJSON string

		err := rows.Scan(
			&policy.ID,
			&policy.Name,
			&policy.Description,
			&rulesJSON,
			&policy.Priority,
			&policy.Enabled,
			&policy.CreatedAt,
			&policy.UpdatedAt,
			&policy.CreatedBy,
		)

		if err != nil {
			return nil, fmt.Errorf("failed to scan policy: %w", err)
		}

		policy.Rules = json.RawMessage(rulesJSON)
		policies = append(policies, &policy)
	}

	return policies, nil
}

// DeletePolicy deletes a policy
func (s *Service) DeletePolicy(ctx context.Context, policyID uuid.UUID) error {
	query := `DELETE FROM policies WHERE id = $1`

	_, err := s.db.ExecContext(ctx, query, policyID)
	if err != nil {
		return fmt.Errorf("failed to delete policy: %w", err)
	}

	return nil
}

// getDefaultPolicy returns a default fail-closed policy
func (s *Service) getDefaultPolicy() *Policy {
	defaultRules := json.RawMessage(`{
		"rules": [
			{
				"rule_id": "default-deny",
				"name": "Default Deny",
				"priority": 0,
				"enabled": true,
				"action": "BLOCK",
				"conditions": {},
				"description": "Default fail-closed policy - block all operations"
			}
		]
	}`)

	return &Policy{
		ID:        uuid.Nil,
		Name:       "Default Policy",
		Rules:      defaultRules,
		Priority:   0,
		Enabled:    true,
		CreatedAt: time.Now(),
		UpdatedAt: time.Now(),
	}
}
