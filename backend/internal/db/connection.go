package db

import (
	"database/sql"
	"fmt"

	_ "github.com/lib/pq"
)

// Connection wraps database connection
type Connection struct {
	*sql.DB
}

// NewConnection creates a new database connection
func NewConnection(connString string) (*Connection, error) {
	db, err := sql.Open("postgres", connString)
	if err != nil {
		return nil, fmt.Errorf("failed to open database: %w", err)
	}

	if err := db.Ping(); err != nil {
		return nil, fmt.Errorf("failed to ping database: %w", err)
	}

	return &Connection{db}, nil
}

// Close closes the database connection
func (c *Connection) Close() error {
	return c.DB.Close()
}
