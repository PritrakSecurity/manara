package db

import (
	"errors"
	"fmt"
	"log"
	"os"
	"path/filepath"
	"sort"

	"github.com/lib/pq"
)

func RunMigrations(conn *Connection) error {
	paths := make(map[string]struct{})
	for _, pattern := range []string{
		filepath.Join("migrations", "*.sql"),
		filepath.Join("backend", "migrations", "*.sql"),
		filepath.Join("..", "..", "migrations", "*.sql"),
	} {
		matches, err := filepath.Glob(pattern)
		if err != nil {
			return fmt.Errorf("failed to find migrations: %w", err)
		}
		for _, path := range matches {
			paths[path] = struct{}{}
		}
	}

	ordered := make([]string, 0, len(paths))
	for path := range paths {
		ordered = append(ordered, path)
	}
	sort.Strings(ordered)

	if len(ordered) == 0 {
		return fmt.Errorf("no migration files found")
	}

	for _, path := range ordered {
		sqlBytes, err := os.ReadFile(path)
		if err != nil {
			return fmt.Errorf("failed to read migration %s: %w", path, err)
		}
		if _, err := conn.Exec(string(sqlBytes)); err != nil {
			var pgErr *pq.Error
			// PostgreSQL error codes 42P07 (duplicate_table), 42710
			// (duplicate_object) and 42701 (duplicate_column) are raised when a
			// migration is re-run against an already-updated schema. Ignoring them
			// keeps the runner idempotent and locale-agnostic (the message text
			// varies by locale; the code does not).
			if errors.As(err, &pgErr) && (pgErr.Code == pq.ErrorCode("42P07") ||
				pgErr.Code == pq.ErrorCode("42710") || pgErr.Code == pq.ErrorCode("42701")) {
				log.Printf("WARNING: migration %s skipped (object already exists): %v", path, pgErr.Message)
				continue
			}
			return fmt.Errorf("failed to execute migration %s: %w", path, err)
		}
	}

	return nil
}
