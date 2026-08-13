package alerts

import (
	"context"
	"database/sql"
	"encoding/json"
	"fmt"
	"time"

	"github.com/google/uuid"
	_ "github.com/lib/pq"
)

// Incident represents a policy violation incident
type Incident struct {
	ID                int64     `json:"id"`
	EventID           *int64    `json:"event_id"`
	AgentID           string    `json:"agent_id"`
	PolicyID          *uuid.UUID `json:"policy_id"`
	RuleID            string    `json:"rule_id"`
	UserID            string    `json:"user_id"`
	ViolationType     string    `json:"violation_type"`
	DataClassification []string `json:"data_classification"`
	Resolved          bool      `json:"resolved"`
	ResolvedAt        *time.Time `json:"resolved_at"`
	ResolvedBy        *string   `json:"resolved_by"`
	ResolutionNotes   *string   `json:"resolution_notes"`
	CreatedAt         time.Time `json:"created_at"`
}

// Service handles alert and incident operations
type Service struct {
	db *sql.DB
}

// NewService creates a new alerts service
func NewService(db *sql.DB) *Service {
	return &Service{db: db}
}

// CheckViolation checks if an event violates policy and creates an incident if needed
func (s *Service) CheckViolation(ctx context.Context, event map[string]interface{}) error {
	// Extract event details
	actionTaken, ok := event["action_taken"].(string)
	if !ok {
		return nil
	}

	// Only create incidents for blocked operations
	if actionTaken != "BLOCK" {
		return nil
	}

	agentID, _ := event["agent_id"].(string)
	ruleID, _ := event["rule_id"].(string)
	userID, _ := event["user_id"].(string)
	violationType, _ := event["event_type"].(string)

	// Create incident
	query := `
		INSERT INTO policy_violations (agent_id, rule_id, user_id, violation_type, data_classification)
		VALUES ($1, $2, $3, $4, $5)
	`

	var dataClassification []string
	if dc, ok := event["data_classification"].([]string); ok {
		dataClassification = dc
	}

	_, err := s.db.ExecContext(ctx, query, agentID, ruleID, userID, violationType, dataClassification)
	if err != nil {
		return fmt.Errorf("failed to create incident: %w", err)
	}

	return nil
}

// GetIncidents retrieves incidents
func (s *Service) GetIncidents(ctx context.Context, limit, offset int, resolved *bool) ([]*Incident, error) {
	var query string
	var args []interface{}

	if resolved != nil {
		query = `
			SELECT id, event_id, agent_id, policy_id, rule_id, user_id, violation_type,
			       data_classification, resolved, resolved_at, resolved_by, resolution_notes, created_at
			FROM policy_violations
			WHERE resolved = $1
			ORDER BY created_at DESC
			LIMIT $2 OFFSET $3
		`
		args = []interface{}{*resolved, limit, offset}
	} else {
		query = `
			SELECT id, event_id, agent_id, policy_id, rule_id, user_id, violation_type,
			       data_classification, resolved, resolved_at, resolved_by, resolution_notes, created_at
			FROM policy_violations
			ORDER BY created_at DESC
			LIMIT $1 OFFSET $2
		`
		args = []interface{}{limit, offset}
	}

	rows, err := s.db.QueryContext(ctx, query, args...)
	if err != nil {
		return nil, fmt.Errorf("failed to query incidents: %w", err)
	}
	defer rows.Close()

	var incidents []*Incident
	for rows.Next() {
		var incident Incident
		var dataClassificationJSON []byte

		err := rows.Scan(
			&incident.ID,
			&incident.EventID,
			&incident.AgentID,
			&incident.PolicyID,
			&incident.RuleID,
			&incident.UserID,
			&incident.ViolationType,
			&dataClassificationJSON,
			&incident.Resolved,
			&incident.ResolvedAt,
			&incident.ResolvedBy,
			&incident.ResolutionNotes,
			&incident.CreatedAt,
		)

		if err != nil {
			return nil, fmt.Errorf("failed to scan incident: %w", err)
		}

		if len(dataClassificationJSON) > 0 {
			json.Unmarshal(dataClassificationJSON, &incident.DataClassification)
		}

		incidents = append(incidents, &incident)
	}

	return incidents, nil
}

// ResolveIncident marks an incident as resolved
func (s *Service) ResolveIncident(ctx context.Context, incidentID int64, resolvedBy, notes string) error {
	query := `
		UPDATE policy_violations
		SET resolved = true, resolved_at = NOW(), resolved_by = $2, resolution_notes = $3
		WHERE id = $1
	`

	_, err := s.db.ExecContext(ctx, query, incidentID, resolvedBy, notes)
	if err != nil {
		return fmt.Errorf("failed to resolve incident: %w", err)
	}

	return nil
}
