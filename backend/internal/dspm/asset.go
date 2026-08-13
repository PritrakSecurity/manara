package dspm

import (
	"time"

	"github.com/google/uuid"
)

// Asset represents a discovered file asset in the inventory
type Asset struct {
	ID             uuid.UUID `json:"id" db:"id"`
	FilePath       string    `json:"file_path" db:"file_path"`
	FileHashSHA256 string    `json:"file_hash_sha256" db:"file_hash_sha256"`
	OwnerUserID    string    `json:"owner_user_id" db:"owner_user_id"`
	Classification string    `json:"classification" db:"classification"`
	FileSizeBytes  int64     `json:"file_size_bytes" db:"file_size_bytes"`
	LastAccessedAt time.Time `json:"last_accessed_at" db:"last_accessed_at"`
	FirstScannedAt time.Time `json:"first_scanned_at" db:"first_scanned_at"`
}
