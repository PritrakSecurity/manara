package policy

import (
	"database/sql"
	"encoding/json"
	"fmt"
	"log"
	"strings"
	"time"

	"github.com/google/uuid"
)

func contains(s, substr string) bool {
	return strings.Contains(strings.ToLower(s), strings.ToLower(substr))
}

// InitializeDefaultPolicies creates default policies on startup
func InitializeDefaultPolicies(db *sql.DB) error {
	if db == nil {
		log.Println("Database not available, skipping default policy initialization")
		return nil
	}

	// Check if USB policy already exists (handle case where is_default column might not exist yet)
	var exists bool
	err := db.QueryRow(
		"SELECT EXISTS(SELECT 1 FROM policies WHERE name = $1)",
		"USB Transfer Prevention",
	).Scan(&exists)

	if err != nil {
		// If column doesn't exist, try without is_default check
		err2 := db.QueryRow(
			"SELECT EXISTS(SELECT 1 FROM policies WHERE name = $1)",
			"USB Transfer Prevention",
		).Scan(&exists)
		if err2 != nil {
			return fmt.Errorf("failed to check for existing policy: %w", err)
		}
	}

	if exists {
		log.Println("Default USB Transfer Prevention policy already exists")
		return nil
	}

	// Create default USB prevention policy rules
	rules := []map[string]interface{}{
		{
			"id":          "rule-usb-block",
			"type":        "file-transfer-block",
			"source":      "local-machine",
			"destination": "removable-media",
			"action":      "block",
			"fileTypes": []string{
				".pdf",
				".xlsx",
				".xls",
				".txt",
				".doc",
				".docx",
				".ppt",
				".pptx",
				".csv",
				".json",
				".xml",
				".png",
				".jpg",
				".jpeg",
			},
			"logging":      true,
			"notification": true,
			"severity":     "high",
		},
	}

	rulesJSON, err := json.Marshal(rules)
	if err != nil {
		return fmt.Errorf("failed to marshal rules: %w", err)
	}

	// Insert default policy
	policyID := uuid.New().String()

	// Try with is_default column first, fallback if column doesn't exist
	query := `
		INSERT INTO policies (id, name, description, rules, priority, enabled, is_default, created_at, updated_at, created_by)
		VALUES ($1, $2, $3, $4::jsonb, $5, $6, $7, $8, $9, $10)
	`

	_, err = db.Exec(
		query,
		policyID,
		"USB Transfer Prevention",
		"Prevent copying sensitive files to USB drives",
		string(rulesJSON),
		100, // High priority
		true, // Enabled by default
		true, // Is default policy
		time.Now(),
		time.Now(),
		"system",
	)

	// If is_default column doesn't exist, try without it
	if err != nil && (err.Error() == "pq: column \"is_default\" does not exist" ||
		contains(err.Error(), "is_default")) {
		query = `
			INSERT INTO policies (id, name, description, rules, priority, enabled, created_at, updated_at, created_by)
			VALUES ($1, $2, $3, $4::jsonb, $5, $6, $7, $8, $9)
		`
		_, err = db.Exec(
			query,
			policyID,
			"USB Transfer Prevention",
			"Prevent copying sensitive files to USB drives",
			string(rulesJSON),
			100,
			true,
			time.Now(),
			time.Now(),
			"system",
		)
	}

	if err != nil {
		return fmt.Errorf("failed to create default policy: %w", err)
	}

	log.Println("Default USB Transfer Prevention policy created successfully")
	return nil
}
