package telemetry

import (
	"context"
	"database/sql"
	"encoding/json"
	"fmt"
	"time"

	"github.com/google/uuid"
	_ "github.com/lib/pq"
)

// Event represents a telemetry event from an agent
type Event struct {
	ID            int64           `json:"id"`
	AgentID       string          `json:"agent_id"`
	EventType     string          `json:"event_type"`
	Operation     string          `json:"operation"`
	SourcePath    string          `json:"source_path"`
	Destination   string          `json:"destination"`
	Application   string          `json:"application"`
	UserID        string          `json:"user_id"`
	Data          json.RawMessage `json:"data"` // JSONB in database
	Severity      string          `json:"severity"`
	ActionTaken   string          `json:"action_taken"`
	PolicyID      *uuid.UUID      `json:"policy_id"`
	RuleID        string          `json:"rule_id"`
	Timestamp     time.Time       `json:"timestamp"`
}

// Service handles telemetry operations
type Service struct {
	db           *sql.DB
	alertService interface {
		CheckViolation(ctx context.Context, event map[string]interface{}) error
	}
}

// NewService creates a new telemetry service
func NewService(db *sql.DB, alertService interface {
	CheckViolation(ctx context.Context, event map[string]interface{}) error
}) *Service {
	return &Service{db: db, alertService: alertService}
}

// InsertEvent inserts a new telemetry event
func (s *Service) InsertEvent(ctx context.Context, event *Event) error {
	event.Timestamp = time.Now()

	query := `
		INSERT INTO telemetry_events (
			agent_id, event_type, operation, source_path, destination,
			application, user_id, data, severity, action_taken, policy_id, rule_id, timestamp
		)
		VALUES ($1, $2, $3, $4, $5, $6, $7, $8::jsonb, $9, $10, $11, $12, $13)
		RETURNING id
	`

	err := s.db.QueryRowContext(ctx, query,
		event.AgentID,
		event.EventType,
		event.Operation,
		event.SourcePath,
		event.Destination,
		event.Application,
		event.UserID,
		string(event.Data),
		event.Severity,
		event.ActionTaken,
		event.PolicyID,
		event.RuleID,
		event.Timestamp,
	).Scan(&event.ID)

	if err != nil {
		return fmt.Errorf("failed to insert event: %w", err)
	}

	return nil
}

// StreamEvents processes a stream of events from an agent
func (s *Service) StreamEvents(ctx context.Context, agentID string, events []*Event) error {
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return fmt.Errorf("failed to begin transaction: %w", err)
	}
	defer tx.Rollback()

	for _, event := range events {
		event.AgentID = agentID
		event.Timestamp = time.Now()

		query := `
			INSERT INTO telemetry_events (
				agent_id, event_type, operation, source_path, destination,
				application, user_id, data, severity, action_taken, policy_id, rule_id, timestamp
			)
			VALUES ($1, $2, $3, $4, $5, $6, $7, $8::jsonb, $9, $10, $11, $12, $13)
		`

		_, err := tx.ExecContext(ctx, query,
			event.AgentID,
			event.EventType,
			event.Operation,
			event.SourcePath,
			event.Destination,
			event.Application,
			event.UserID,
			string(event.Data),
			event.Severity,
			event.ActionTaken,
			event.PolicyID,
			event.RuleID,
			event.Timestamp,
		)

		if err != nil {
			return fmt.Errorf("failed to insert event in stream: %w", err)
		}

		// Check for violations and trigger alerts
		if event.Severity == "CRITICAL" || event.Severity == "HIGH" {
			if err := s.checkViolation(ctx, tx, event); err != nil {
				// Log error but don't fail the transaction
				fmt.Printf("Failed to check violation: %v\n", err)
			}
		}
	}

	if err := tx.Commit(); err != nil {
		return fmt.Errorf("failed to commit transaction: %w", err)
	}

	return nil
}

// GetEvents retrieves events with filtering
func (s *Service) GetEvents(ctx context.Context, filters EventFilters) ([]*Event, error) {
	query := `
		SELECT id, agent_id, event_type, operation, source_path, destination,
		       application, user_id, data, severity, action_taken, policy_id, rule_id, timestamp
		FROM telemetry_events
		WHERE 1=1
	`

	args := []interface{}{}
	argPos := 1

	if filters.AgentID != "" {
		query += fmt.Sprintf(" AND agent_id = $%d", argPos)
		args = append(args, filters.AgentID)
		argPos++
	}

	if filters.EventType != "" {
		query += fmt.Sprintf(" AND event_type = $%d", argPos)
		args = append(args, filters.EventType)
		argPos++
	}

	if filters.Severity != "" {
		query += fmt.Sprintf(" AND severity = $%d", argPos)
		args = append(args, filters.Severity)
		argPos++
	}

	if filters.StartTime != nil {
		query += fmt.Sprintf(" AND timestamp >= $%d", argPos)
		args = append(args, *filters.StartTime)
		argPos++
	}

	if filters.EndTime != nil {
		query += fmt.Sprintf(" AND timestamp <= $%d", argPos)
		args = append(args, *filters.EndTime)
		argPos++
	}

	query += " ORDER BY timestamp DESC LIMIT $%d OFFSET $%d"
	query = fmt.Sprintf(query, argPos, argPos+1)
	args = append(args, filters.Limit, filters.Offset)

	rows, err := s.db.QueryContext(ctx, query, args...)
	if err != nil {
		return nil, fmt.Errorf("failed to query events: %w", err)
	}
	defer rows.Close()

	var events []*Event
	for rows.Next() {
		var event Event
		var dataJSON string
		var policyID sql.NullString

		err := rows.Scan(
			&event.ID,
			&event.AgentID,
			&event.EventType,
			&event.Operation,
			&event.SourcePath,
			&event.Destination,
			&event.Application,
			&event.UserID,
			&dataJSON,
			&event.Severity,
			&event.ActionTaken,
			&policyID,
			&event.RuleID,
			&event.Timestamp,
		)

		if err != nil {
			return nil, fmt.Errorf("failed to scan event: %w", err)
		}

		event.Data = json.RawMessage(dataJSON)
		if policyID.Valid {
			id, _ := uuid.Parse(policyID.String)
			event.PolicyID = &id
		}

		events = append(events, &event)
	}

	return events, nil
}

// EventFilters for querying events
type EventFilters struct {
	AgentID   string
	EventType string
	Severity  string
	StartTime *time.Time
	EndTime   *time.Time
	Limit     int
	Offset    int
}

// checkViolation checks if event is a policy violation and triggers alert
func (s *Service) checkViolation(ctx context.Context, tx *sql.Tx, event *Event) error {
	// Check if this is a blocked operation (violation)
	if event.ActionTaken == "BLOCK" {
		// Insert into violations table (if exists)
		// Or send alert notification
		// For now, just log
		fmt.Printf("Policy violation detected: Agent=%s, Event=%s, User=%s\n",
			event.AgentID, event.EventType, event.UserID)
	}

	return nil
}
