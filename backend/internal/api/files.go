package api

import (
	"encoding/json"
	"net/http"
	"strconv"

	"enterprise-dlp-backend/internal/classification"
)

// FilesHandler handles file classification API requests
type FilesHandler struct {
	classifier *classification.Classifier
}

// NewFilesHandler creates a new files handler
func NewFilesHandler(classifier *classification.Classifier) *FilesHandler {
	return &FilesHandler{classifier: classifier}
}

// HandleList handles GET /api/files/classified
func (h *FilesHandler) HandleList(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()

	filters := classification.FileFilters{
		Classification: r.URL.Query().Get("classification"),
		FileType:       r.URL.Query().Get("file_type"),
		OwnerSID:       r.URL.Query().Get("owner_sid"),
		Search:         r.URL.Query().Get("search"),
	}

	if limit := r.URL.Query().Get("limit"); limit != "" {
		filters.Limit, _ = strconv.Atoi(limit)
	} else {
		filters.Limit = 50
	}

	if offset := r.URL.Query().Get("offset"); offset != "" {
		filters.Offset, _ = strconv.Atoi(offset)
	}

	if quarantined := r.URL.Query().Get("quarantined"); quarantined != "" {
		q := quarantined == "true"
		filters.Quarantined = &q
	}

	files, total, err := h.classifier.ListClassifiedFiles(ctx, filters)
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}

	response := map[string]interface{}{
		"files":  files,
		"total":  total,
		"limit":  filters.Limit,
		"offset": filters.Offset,
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(response)
}

// HandleGet handles GET /api/files/:hash
func (h *FilesHandler) HandleGet(w http.ResponseWriter, r *http.Request) {
	fileHash := r.URL.Query().Get("hash")
	if fileHash == "" {
		http.Error(w, "Missing file hash", http.StatusBadRequest)
		return
	}

	file, err := h.classifier.GetClassification(r.Context(), fileHash)
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}

	if file == nil {
		http.Error(w, "File not found", http.StatusNotFound)
		return
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(file)
}

// HandleReclassify handles POST /api/files/:hash/reclassify
func (h *FilesHandler) HandleReclassify(w http.ResponseWriter, r *http.Request) {
	fileHash := r.URL.Query().Get("hash")
	if fileHash == "" {
		http.Error(w, "Missing file hash", http.StatusBadRequest)
		return
	}

	var req struct {
		Classification string `json:"classification"`
		Reason         string `json:"reason"`
		ChangedBy      string `json:"changed_by"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		http.Error(w, "Invalid request body", http.StatusBadRequest)
		return
	}

	// Validate classification
	validClassifications := map[string]bool{
		"PUBLIC": true, "PRIVATE": true, "CONFIDENTIAL": true, "RESTRICTED": true,
	}
	if !validClassifications[req.Classification] {
		http.Error(w, "Invalid classification", http.StatusBadRequest)
		return
	}

	if err := h.classifier.Reclassify(r.Context(), fileHash, req.Classification, req.Reason, req.ChangedBy); err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(map[string]interface{}{
		"message":        "File reclassified",
		"file_hash":      fileHash,
		"classification": req.Classification,
	})
}

// HandleHistory handles GET /api/files/:hash/history
func (h *FilesHandler) HandleHistory(w http.ResponseWriter, r *http.Request) {
	fileHash := r.URL.Query().Get("hash")
	if fileHash == "" {
		http.Error(w, "Missing file hash", http.StatusBadRequest)
		return
	}

	limit := 50
	offset := 0
	if l := r.URL.Query().Get("limit"); l != "" {
		limit, _ = strconv.Atoi(l)
	}
	if o := r.URL.Query().Get("offset"); o != "" {
		offset, _ = strconv.Atoi(o)
	}

	history, err := h.classifier.GetAccessHistory(r.Context(), fileHash, limit, offset)
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(map[string]interface{}{
		"file_hash": fileHash,
		"history":   history,
	})
}

// HandleQuarantine handles POST /api/files/:hash/quarantine
func (h *FilesHandler) HandleQuarantine(w http.ResponseWriter, r *http.Request) {
	fileHash := r.URL.Query().Get("hash")
	if fileHash == "" {
		http.Error(w, "Missing file hash", http.StatusBadRequest)
		return
	}

	var req struct {
		QuarantinedBy string `json:"quarantined_by"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		http.Error(w, "Invalid request body", http.StatusBadRequest)
		return
	}

	if err := h.classifier.QuarantineFile(r.Context(), fileHash, req.QuarantinedBy); err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(map[string]interface{}{
		"message":   "File quarantined",
		"file_hash": fileHash,
	})
}

// HandleUnquarantine handles POST /api/files/:hash/unquarantine
func (h *FilesHandler) HandleUnquarantine(w http.ResponseWriter, r *http.Request) {
	fileHash := r.URL.Query().Get("hash")
	if fileHash == "" {
		http.Error(w, "Missing file hash", http.StatusBadRequest)
		return
	}

	if err := h.classifier.UnquarantineFile(r.Context(), fileHash); err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(map[string]interface{}{
		"message":   "File unquarantined",
		"file_hash": fileHash,
	})
}

// HandleClassify handles POST /api/files/classify
func (h *FilesHandler) HandleClassify(w http.ResponseWriter, r *http.Request) {
	var req struct {
		Content       string `json:"content"`
		FileName      string `json:"file_name,omitempty"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		http.Error(w, "Invalid request body", http.StatusBadRequest)
		return
	}

	if req.Content == "" {
		http.Error(w, "Content is required", http.StatusBadRequest)
		return
	}

	result, err := h.classifier.ClassifyContent(r.Context(), req.Content)
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(result)
}

// HandleStats handles GET /api/files/stats
func (h *FilesHandler) HandleStats(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()

	// Get counts by classification
	stats := make(map[string]interface{})

	classifications := []string{"PUBLIC", "PRIVATE", "CONFIDENTIAL", "RESTRICTED"}
	byClassification := make(map[string]int)

	for _, c := range classifications {
		files, total, _ := h.classifier.ListClassifiedFiles(ctx, classification.FileFilters{
			Classification: c,
			Limit:          1,
		})
		_ = files
		byClassification[c] = total
	}

	stats["by_classification"] = byClassification

	// Get quarantined count
	q := true
	_, quarantinedCount, _ := h.classifier.ListClassifiedFiles(ctx, classification.FileFilters{
		Quarantined: &q,
		Limit:       1,
	})
	stats["quarantined_count"] = quarantinedCount

	// Get total count
	_, totalCount, _ := h.classifier.ListClassifiedFiles(ctx, classification.FileFilters{Limit: 1})
	stats["total_count"] = totalCount

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(stats)
}
