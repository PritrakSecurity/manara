package ownership

import (
	"context"
	"database/sql"
	"fmt"
	"time"
)

// FileOwnership represents ownership information for a file
type FileOwnership struct {
	FileHash              string    `json:"file_hash"`
	OriginalOwnerSID      string    `json:"original_owner_sid"`
	OriginalOwnerUsername string    `json:"original_owner_username"`
	CreationTimestamp     time.Time `json:"creation_timestamp"`
	SourceType            string    `json:"source_type"` // LOCAL, DOWNLOAD, EMAIL, SHARE, CLOUD
	SourceDetail          string    `json:"source_detail"`
	LastVerified          time.Time `json:"last_verified"`
}

// Tracker handles file ownership tracking
type Tracker struct {
	db *sql.DB
}

// NewTracker creates a new ownership tracker
func NewTracker(db *sql.DB) *Tracker {
	return &Tracker{db: db}
}

// RegisterOwnership registers the original owner of a file
func (t *Tracker) RegisterOwnership(ctx context.Context, ownership *FileOwnership) error {
	if ownership.CreationTimestamp.IsZero() {
		ownership.CreationTimestamp = time.Now()
	}
	ownership.LastVerified = time.Now()

	query := `
		INSERT INTO file_ownership (file_hash, original_owner_sid, original_owner_username,
			creation_timestamp, source_type, source_detail, last_verified)
		VALUES ($1, $2, $3, $4, $5, $6, $7)
		ON CONFLICT (file_hash) DO UPDATE SET
			last_verified = EXCLUDED.last_verified
	`

	_, err := t.db.ExecContext(ctx, query,
		ownership.FileHash,
		ownership.OriginalOwnerSID,
		ownership.OriginalOwnerUsername,
		ownership.CreationTimestamp,
		ownership.SourceType,
		ownership.SourceDetail,
		ownership.LastVerified,
	)

	if err != nil {
		return fmt.Errorf("failed to register ownership: %w", err)
	}

	return nil
}

// GetOwnership retrieves ownership information for a file
func (t *Tracker) GetOwnership(ctx context.Context, fileHash string) (*FileOwnership, error) {
	query := `
		SELECT file_hash, original_owner_sid, original_owner_username,
			creation_timestamp, source_type, source_detail, last_verified
		FROM file_ownership
		WHERE file_hash = $1
	`

	var ownership FileOwnership
	var sourceType, sourceDetail sql.NullString

	err := t.db.QueryRowContext(ctx, query, fileHash).Scan(
		&ownership.FileHash,
		&ownership.OriginalOwnerSID,
		&ownership.OriginalOwnerUsername,
		&ownership.CreationTimestamp,
		&sourceType,
		&sourceDetail,
		&ownership.LastVerified,
	)

	if err == sql.ErrNoRows {
		return nil, nil // No ownership registered
	}
	if err != nil {
		return nil, fmt.Errorf("failed to get ownership: %w", err)
	}

	if sourceType.Valid {
		ownership.SourceType = sourceType.String
	}
	if sourceDetail.Valid {
		ownership.SourceDetail = sourceDetail.String
	}

	return &ownership, nil
}

// IsOwner checks if a user is the original owner of a file
func (t *Tracker) IsOwner(ctx context.Context, fileHash, userSID string) (bool, error) {
	ownership, err := t.GetOwnership(ctx, fileHash)
	if err != nil {
		return false, err
	}

	if ownership == nil {
		// No ownership registered - treat as owned by current user
		return true, nil
	}

	return ownership.OriginalOwnerSID == userSID, nil
}

// GetOwnerUsername returns the username of the file owner
func (t *Tracker) GetOwnerUsername(ctx context.Context, fileHash string) (string, error) {
	ownership, err := t.GetOwnership(ctx, fileHash)
	if err != nil {
		return "", err
	}

	if ownership == nil {
		return "", nil
	}

	return ownership.OriginalOwnerUsername, nil
}

// GetOwnerSID returns the SID of the file owner
func (t *Tracker) GetOwnerSID(ctx context.Context, fileHash string) (string, error) {
	ownership, err := t.GetOwnership(ctx, fileHash)
	if err != nil {
		return "", err
	}

	if ownership == nil {
		return "", nil
	}

	return ownership.OriginalOwnerSID, nil
}

// UpdateOwnership updates ownership information
func (t *Tracker) UpdateOwnership(ctx context.Context, fileHash, ownerSID, ownerUsername, sourceType, sourceDetail string) error {
	query := `
		UPDATE file_ownership
		SET original_owner_sid = $2, original_owner_username = $3,
			source_type = $4, source_detail = $5, last_verified = NOW()
		WHERE file_hash = $1
	`

	result, err := t.db.ExecContext(ctx, query, fileHash, ownerSID, ownerUsername, sourceType, sourceDetail)
	if err != nil {
		return fmt.Errorf("failed to update ownership: %w", err)
	}

	rowsAffected, _ := result.RowsAffected()
	if rowsAffected == 0 {
		return fmt.Errorf("ownership not found for file: %s", fileHash)
	}

	return nil
}

// DeleteOwnership removes ownership record
func (t *Tracker) DeleteOwnership(ctx context.Context, fileHash string) error {
	_, err := t.db.ExecContext(ctx, "DELETE FROM file_ownership WHERE file_hash = $1", fileHash)
	if err != nil {
		return fmt.Errorf("failed to delete ownership: %w", err)
	}
	return nil
}

// ListByOwner lists all files owned by a specific user
func (t *Tracker) ListByOwner(ctx context.Context, ownerSID string, limit, offset int) ([]*FileOwnership, error) {
	if limit == 0 {
		limit = 50
	}

	query := `
		SELECT file_hash, original_owner_sid, original_owner_username,
			creation_timestamp, source_type, source_detail, last_verified
		FROM file_ownership
		WHERE original_owner_sid = $1
		ORDER BY creation_timestamp DESC
		LIMIT $2 OFFSET $3
	`

	rows, err := t.db.QueryContext(ctx, query, ownerSID, limit, offset)
	if err != nil {
		return nil, fmt.Errorf("failed to list files by owner: %w", err)
	}
	defer rows.Close()

	var ownerships []*FileOwnership
	for rows.Next() {
		var ownership FileOwnership
		var sourceType, sourceDetail sql.NullString

		err := rows.Scan(
			&ownership.FileHash,
			&ownership.OriginalOwnerSID,
			&ownership.OriginalOwnerUsername,
			&ownership.CreationTimestamp,
			&sourceType,
			&sourceDetail,
			&ownership.LastVerified,
		)
		if err != nil {
			continue
		}

		if sourceType.Valid {
			ownership.SourceType = sourceType.String
		}
		if sourceDetail.Valid {
			ownership.SourceDetail = sourceDetail.String
		}

		ownerships = append(ownerships, &ownership)
	}

	return ownerships, nil
}

// GetFileCountByOwner returns the count of files owned by a user
func (t *Tracker) GetFileCountByOwner(ctx context.Context, ownerSID string) (int, error) {
	var count int
	err := t.db.QueryRowContext(ctx, "SELECT COUNT(*) FROM file_ownership WHERE original_owner_sid = $1", ownerSID).Scan(&count)
	if err != nil {
		return 0, fmt.Errorf("failed to count files by owner: %w", err)
	}
	return count, nil
}
