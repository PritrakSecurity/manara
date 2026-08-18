package api

import (
	"database/sql"
	"encoding/json"
	"fmt"
	"log"
	"net/http"
	"regexp"
	"strconv"
	"strings"
	"time"

	"github.com/google/uuid"

	"manara-dlp/internal/classification"
)

var (
	ssnMaskRegex  = regexp.MustCompile(`\d{3}-\d{2}-(\d{4})`)
	ccMaskRegex   = regexp.MustCompile(`\b(?:\d{4}[-\s]?){3}(\d{4})\b`)
	phoneMaskRegex = regexp.MustCompile(`(?:\+?\d[\d\s-]{7,})(\d{4})`)
)

// DSPMHandler provides the data-discovery inventory APIs backed by the
// inventory_assets table (migration 014).
type DSPMHandler struct {
	db *sql.DB
}

func NewDSPMHandler(db *sql.DB) *DSPMHandler {
	return &DSPMHandler{db: db}
}

// inventoryAsset mirrors the inventory_assets schema (migration 015).
type inventoryAsset struct {
	ID             string        `json:"id"`
	FilePath       string        `json:"file_path"`
	FileHashSha256 string        `json:"file_hash_sha256"`
	OwnerUserID    string        `json:"owner_user_id"`
	Classification string        `json:"classification"`
	FileSizeBytes  int64         `json:"file_size_bytes"`
	LastAccessedAt time.Time     `json:"last_accessed_at"`
	FirstScannedAt time.Time     `json:"first_scanned_at"`
	CreatedAt      time.Time     `json:"created_at"`
	ExposureLevel  string        `json:"exposure_level"`
	RiskScore      int           `json:"risk_score"`
	ContentSnippet string        `json:"content_snippet"`
	OwnerSID       string        `json:"owner_sid"`
	Findings       []findingView `json:"findings,omitempty"`
}

// HandleInventoryUpsert handles POST /api/v1/dspm/inventory
//
// Upserts a discovered asset using file_hash_sha256 as the identity. Schema 014
// has no unique constraint on the hash, so the update path is an explicit
// check-then-insert/update. Metadata only - no file content.
func (h *DSPMHandler) HandleInventoryUpsert(w http.ResponseWriter, r *http.Request) {
	var req struct {
		FilePath        string   `json:"file_path"`
		FileHash        string   `json:"file_hash"`
		FileSize        int64    `json:"file_size"`
		Classification  string   `json:"classification"`
		MatchedKeywords []string `json:"matched_keywords"`
		Hostname        string   `json:"hostname"`
		ExposureLevel   string   `json:"exposure_level"`
		RiskScore       int      `json:"risk_score"`
		ContentSnippet  string   `json:"content_snippet"`
		OwnerSID        string   `json:"owner_sid"`
		Findings        []classification.Finding `json:"findings"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		http.Error(w, "invalid request", http.StatusBadRequest)
		return
	}
	if req.FileHash == "" || req.FilePath == "" {
		http.Error(w, "file_hash and file_path are required", http.StatusBadRequest)
		return
	}
	if req.Classification == "" {
		req.Classification = "UNKNOWN"
	}
	if req.FileSize < 0 {
		req.FileSize = 0
	}
	if req.ExposureLevel == "" {
		req.ExposureLevel = "INTERNAL"
	}
	req.ExposureLevel = strings.ToUpper(req.ExposureLevel)
	switch req.ExposureLevel {
	case "PUBLIC", "INTERNAL", "RESTRICTED":
	default:
		http.Error(w, "invalid exposure_level", http.StatusBadRequest)
		return
	}
	if req.RiskScore < 0 || req.RiskScore > 100 {
		http.Error(w, "risk_score must be between 0 and 100", http.StatusBadRequest)
		return
	}
	owner := req.Hostname
	if owner == "" {
		owner = "unknown"
	}
	now := time.Now().UTC()

	var existing string
	err := h.db.QueryRow(
		`SELECT file_hash_sha256 FROM inventory_assets WHERE file_hash_sha256 = $1`,
		req.FileHash,
	).Scan(&existing)

	maskedSnippet := MaskSensitiveData(req.ContentSnippet)

	findingsJSON, err := marshalFindings(req.Findings)
	if err != nil {
		http.Error(w, "invalid findings", http.StatusBadRequest)
		return
	}

	if err == sql.ErrNoRows {
		_, err = h.db.Exec(`
			INSERT INTO inventory_assets
				(id, file_path, file_hash_sha256, owner_user_id, classification,
				 file_size_bytes, last_accessed_at, first_scanned_at, created_at,
				 exposure_level, risk_score, content_snippet, owner_sid, findings)
			VALUES ($1, $2, $3, $4, $5, $6, $7, $7, now(), $8, $9, $10, $11, $12)
		`, uuid.New().String(), req.FilePath, req.FileHash, owner, req.Classification,
			req.FileSize, now, req.ExposureLevel, req.RiskScore, maskedSnippet, req.OwnerSID, findingsJSON)
	} else if err == nil {
		_, err = h.db.Exec(`
			UPDATE inventory_assets
			SET file_path = $1, owner_user_id = $2, classification = $3,
			    file_size_bytes = $4, last_accessed_at = $5,
			    exposure_level = $6, risk_score = $7, content_snippet = $8, owner_sid = $9,
			    findings = $11
			WHERE file_hash_sha256 = $10
		`, req.FilePath, owner, req.Classification, req.FileSize, now,
			req.ExposureLevel, req.RiskScore, maskedSnippet, req.OwnerSID, req.FileHash, findingsJSON)
	}

	if err != nil {
		log.Printf("[DSPM] Failed to upsert inventory asset %s: %v", req.FileHash, err)
		http.Error(w, "failed to save inventory asset", http.StatusInternalServerError)
		return
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(map[string]string{"status": "ok"})
}

// HandleInventoryList handles GET /api/v1/dspm/inventory
//
// Supports pagination (limit, offset), classification filtering, and a free
// text search on file path.
func (h *DSPMHandler) HandleInventoryList(w http.ResponseWriter, r *http.Request) {
	limit := 50
	offset := 0
	if v := r.URL.Query().Get("limit"); v != "" {
		if n, err := strconv.Atoi(v); err == nil && n >= 0 && n <= 500 {
			limit = n
		}
	}
	if v := r.URL.Query().Get("offset"); v != "" {
		if n, err := strconv.Atoi(v); err == nil && n >= 0 {
			offset = n
		}
	}
	classification := r.URL.Query().Get("classification")
	search := r.URL.Query().Get("search")

	where := ` WHERE 1=1`
	args := []interface{}{}
	idx := 1
	if classification != "" {
		where += fmt.Sprintf(" AND classification = $%d", idx)
		args = append(args, classification)
		idx++
	}
	if search != "" {
		where += fmt.Sprintf(" AND file_path ILIKE $%d", idx)
		args = append(args, "%"+search+"%")
		idx++
	}

	var total int
	if err := h.db.QueryRow(`SELECT COUNT(*) FROM inventory_assets`+where, args...).Scan(&total); err != nil {
		log.Printf("[DSPM] Failed to count inventory: %v", err)
		http.Error(w, "database error", http.StatusInternalServerError)
		return
	}

	query := `
		SELECT id, file_path, file_hash_sha256, owner_user_id, classification,
		       file_size_bytes, last_accessed_at, first_scanned_at, created_at,
		       exposure_level, risk_score, content_snippet, owner_sid, findings
		FROM inventory_assets` + where +
		fmt.Sprintf(" ORDER BY risk_score DESC, last_accessed_at DESC LIMIT $%d OFFSET $%d", idx, idx+1)
	args = append(args, limit, offset)

	rows, err := h.db.Query(query, args...)
	if err != nil {
		log.Printf("[DSPM] Failed to query inventory: %v", err)
		http.Error(w, "database error", http.StatusInternalServerError)
		return
	}
	defer rows.Close()

	assets := []inventoryAsset{}
	for rows.Next() {
		var a inventoryAsset
		var findingsRaw []byte
		if err := rows.Scan(&a.ID, &a.FilePath, &a.FileHashSha256, &a.OwnerUserID,
			&a.Classification, &a.FileSizeBytes, &a.LastAccessedAt, &a.FirstScannedAt, &a.CreatedAt,
			&a.ExposureLevel, &a.RiskScore, &a.ContentSnippet, &a.OwnerSID, &findingsRaw); err != nil {
			continue
		}
		if len(findingsRaw) > 0 {
			_ = json.Unmarshal(findingsRaw, &a.Findings)
		}
		assets = append(assets, a)
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(map[string]interface{}{
		"data":   assets,
		"total":  total,
		"limit":  limit,
		"offset": offset,
	})
}

// HandleInventoryStats handles GET /api/v1/dspm/stats
//
// Returns asset counts grouped by classification, a risk distribution broken
// into critical/high/medium/low buckets, and a TOTAL count.
func (h *DSPMHandler) HandleInventoryStats(w http.ResponseWriter, r *http.Request) {
	rows, err := h.db.Query(`SELECT classification, COUNT(*) FROM inventory_assets GROUP BY classification`)
	if err != nil {
		log.Printf("[DSPM] Failed to query inventory stats: %v", err)
		http.Error(w, "database error", http.StatusInternalServerError)
		return
	}
	defer rows.Close()

	stats := map[string]interface{}{}
	total := 0
	for rows.Next() {
		var c string
		var n int
		if err := rows.Scan(&c, &n); err != nil {
			continue
		}
		stats[c] = n
		total += n
	}

	riskDist := map[string]int{
		"critical": 0,
		"high":     0,
		"medium":   0,
		"low":      0,
	}
	riskRows, err := h.db.Query(`
		SELECT
			SUM(CASE WHEN risk_score BETWEEN 76 AND 100 THEN 1 ELSE 0 END) AS critical,
			SUM(CASE WHEN risk_score BETWEEN 51 AND 75 THEN 1 ELSE 0 END) AS high,
			SUM(CASE WHEN risk_score BETWEEN 26 AND 50 THEN 1 ELSE 0 END) AS medium,
			SUM(CASE WHEN risk_score BETWEEN 0 AND 25 THEN 1 ELSE 0 END) AS low
		FROM inventory_assets`)
	if err != nil {
		log.Printf("[DSPM] Failed to query risk distribution: %v", err)
		http.Error(w, "database error", http.StatusInternalServerError)
		return
	}
	defer riskRows.Close()

	if riskRows.Next() {
		var critical, high, medium, low sql.NullInt64
		if err := riskRows.Scan(&critical, &high, &medium, &low); err == nil {
			riskDist["critical"] = int(critical.Int64)
			riskDist["high"] = int(high.Int64)
			riskDist["medium"] = int(medium.Int64)
			riskDist["low"] = int(low.Int64)
		}
	}

	stats["risk_distribution"] = riskDist
	stats["TOTAL"] = total

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(stats)
}

// MaskSensitiveData masks PII inside a snippet before it is persisted.
//
// SSNs (123-45-6789) become ***-**-6789, credit card numbers keep only the
// last four digits, and phone numbers keep only the last four digits.
func MaskSensitiveData(snippet string) string {
	if snippet == "" {
		return snippet
	}
	snippet = ssnMaskRegex.ReplaceAllString(snippet, "***-**-$1")
	snippet = ccMaskRegex.ReplaceAllString(snippet, "****-****-****-$1")
	snippet = phoneMaskRegex.ReplaceAllString(snippet, "***-***-$1")
	return snippet
}
