package endpoints

import (
	"context"
	"database/sql"
	"fmt"
	"time"

	"github.com/google/uuid"
	_ "github.com/lib/pq"
)

// Endpoint represents a registered agent
type Endpoint struct {
	ID          uuid.UUID `json:"id"`
	AgentID     string    `json:"agent_id"`
	Hostname    string    `json:"hostname"`
	IPAddress   string    `json:"ip_address"`
	OSVersion   string    `json:"os_version"`
	AgentVersion string   `json:"agent_version"`
	LastSeen    time.Time `json:"last_seen"`
	CreatedAt   time.Time `json:"created_at"`
	Status      string    `json:"status"`
}

// Service handles endpoint operations
type Service struct {
	db *sql.DB
}

// NewService creates a new endpoint service
func NewService(db *sql.DB) *Service {
	return &Service{db: db}
}

// RegisterEndpoint registers a new endpoint or updates existing one
func (s *Service) RegisterEndpoint(ctx context.Context, agentID, hostname, ipAddress, osVersion, agentVersion string) (*Endpoint, error) {
	query := `
		INSERT INTO endpoints (agent_id, hostname, ip_address, os_version, agent_version, last_seen, status)
		VALUES ($1, $2, $3, $4, $5, NOW(), 'active')
		ON CONFLICT (agent_id) DO UPDATE SET
			hostname = EXCLUDED.hostname,
			ip_address = EXCLUDED.ip_address,
			os_version = EXCLUDED.os_version,
			agent_version = EXCLUDED.agent_version,
			last_seen = NOW(),
			status = 'active'
		RETURNING id, agent_id, hostname, ip_address, os_version, agent_version, last_seen, created_at, status
	`

	var endpoint Endpoint
	err := s.db.QueryRowContext(ctx, query, agentID, hostname, ipAddress, osVersion, agentVersion).Scan(
		&endpoint.ID,
		&endpoint.AgentID,
		&endpoint.Hostname,
		&endpoint.IPAddress,
		&endpoint.OSVersion,
		&endpoint.AgentVersion,
		&endpoint.LastSeen,
		&endpoint.CreatedAt,
		&endpoint.Status,
	)

	if err != nil {
		return nil, fmt.Errorf("failed to register endpoint: %w", err)
	}

	return &endpoint, nil
}

// GetEndpoint retrieves an endpoint by agent ID
func (s *Service) GetEndpoint(ctx context.Context, agentID string) (*Endpoint, error) {
	query := `
		SELECT id, agent_id, hostname, ip_address, os_version, agent_version, last_seen, created_at, status
		FROM endpoints
		WHERE agent_id = $1
	`

	var endpoint Endpoint
	err := s.db.QueryRowContext(ctx, query, agentID).Scan(
		&endpoint.ID,
		&endpoint.AgentID,
		&endpoint.Hostname,
		&endpoint.IPAddress,
		&endpoint.OSVersion,
		&endpoint.AgentVersion,
		&endpoint.LastSeen,
		&endpoint.CreatedAt,
		&endpoint.Status,
	)

	if err == sql.ErrNoRows {
		return nil, nil
	}

	if err != nil {
		return nil, fmt.Errorf("failed to get endpoint: %w", err)
	}

	return &endpoint, nil
}

// ListEndpoints lists all endpoints
func (s *Service) ListEndpoints(ctx context.Context, limit, offset int) ([]*Endpoint, error) {
	query := `
		SELECT id, agent_id, hostname, ip_address, os_version, agent_version, last_seen, created_at, status
		FROM endpoints
		ORDER BY last_seen DESC
		LIMIT $1 OFFSET $2
	`

	rows, err := s.db.QueryContext(ctx, query, limit, offset)
	if err != nil {
		return nil, fmt.Errorf("failed to query endpoints: %w", err)
	}
	defer rows.Close()

	var endpoints []*Endpoint
	for rows.Next() {
		var endpoint Endpoint
		err := rows.Scan(
			&endpoint.ID,
			&endpoint.AgentID,
			&endpoint.Hostname,
			&endpoint.IPAddress,
			&endpoint.OSVersion,
			&endpoint.AgentVersion,
			&endpoint.LastSeen,
			&endpoint.CreatedAt,
			&endpoint.Status,
		)

		if err != nil {
			return nil, fmt.Errorf("failed to scan endpoint: %w", err)
		}

		endpoints = append(endpoints, &endpoint)
	}

	return endpoints, nil
}

// UpdateLastSeen updates the last seen timestamp for an endpoint
func (s *Service) UpdateLastSeen(ctx context.Context, agentID string) error {
	query := `UPDATE endpoints SET last_seen = NOW(), status = 'active' WHERE agent_id = $1`
	_, err := s.db.ExecContext(ctx, query, agentID)
	if err != nil {
		return fmt.Errorf("failed to update last seen: %w", err)
	}
	return nil
}
