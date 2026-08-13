package db

import (
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strings"
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
		if _, err := conn.Exec(string(sqlBytes)); err != nil && !strings.Contains(err.Error(), "already exists") {
			return fmt.Errorf("failed to execute migration %s: %w", path, err)
		}
	}

	return nil
}
