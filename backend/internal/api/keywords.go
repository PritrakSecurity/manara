package api

import (
	"encoding/json"
	"io"
	"net/http"
	"strconv"

	"enterprise-dlp-backend/internal/keywords"
)

// KeywordsHandler handles keyword API requests
type KeywordsHandler struct {
	service *keywords.Service
}

// NewKeywordsHandler creates a new keywords handler
func NewKeywordsHandler(service *keywords.Service) *KeywordsHandler {
	return &KeywordsHandler{service: service}
}

// HandleList handles GET /api/keywords
func (h *KeywordsHandler) HandleList(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()

	// Parse filters
	filters := keywords.KeywordFilters{
		Classification: r.URL.Query().Get("classification"),
		MatchType:      r.URL.Query().Get("match_type"),
		GroupID:        r.URL.Query().Get("group_id"),
		Search:         r.URL.Query().Get("search"),
	}

	if limit := r.URL.Query().Get("limit"); limit != "" {
		filters.Limit, _ = strconv.Atoi(limit)
	} else {
		filters.Limit = 100
	}

	if offset := r.URL.Query().Get("offset"); offset != "" {
		filters.Offset, _ = strconv.Atoi(offset)
	}

	if enabled := r.URL.Query().Get("enabled"); enabled != "" {
		e := enabled == "true"
		filters.Enabled = &e
	}

	if hardBlock := r.URL.Query().Get("hard_block"); hardBlock != "" {
		hb := hardBlock == "true"
		filters.HardBlock = &hb
	}

	kws, total, err := h.service.List(ctx, filters)
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}

	response := map[string]interface{}{
		"keywords": kws,
		"total":    total,
		"limit":    filters.Limit,
		"offset":   filters.Offset,
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(response)
}

// HandleGet handles GET /api/keywords/:id
func (h *KeywordsHandler) HandleGet(w http.ResponseWriter, r *http.Request) {
	id := r.URL.Query().Get("id")
	if id == "" {
		// Try to get from path
		// This is a simple implementation - in production use a proper router
		http.Error(w, "Missing keyword ID", http.StatusBadRequest)
		return
	}

	kw, err := h.service.GetByID(r.Context(), id)
	if err != nil {
		http.Error(w, err.Error(), http.StatusNotFound)
		return
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(kw)
}

// HandleCreate handles POST /api/keywords
func (h *KeywordsHandler) HandleCreate(w http.ResponseWriter, r *http.Request) {
	var kw keywords.Keyword
	if err := json.NewDecoder(r.Body).Decode(&kw); err != nil {
		http.Error(w, "Invalid request body", http.StatusBadRequest)
		return
	}

	// Validate required fields
	if kw.Keyword == "" {
		http.Error(w, "Keyword is required", http.StatusBadRequest)
		return
	}

	// Set defaults
	if kw.MatchType == "" {
		kw.MatchType = "PARTIAL"
	}
	if kw.Classification == "" {
		kw.Classification = "PRIVATE"
	}

	// Validate regex if REGEX type
	if kw.MatchType == "REGEX" {
		if err := keywords.ValidateRegex(kw.Keyword); err != nil {
			http.Error(w, "Invalid regex pattern: "+err.Error(), http.StatusBadRequest)
			return
		}
	}

	if err := h.service.Create(r.Context(), &kw); err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}

	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusCreated)
	json.NewEncoder(w).Encode(kw)
}

// HandleUpdate handles PUT /api/keywords/:id
func (h *KeywordsHandler) HandleUpdate(w http.ResponseWriter, r *http.Request) {
	id := r.URL.Query().Get("id")
	if id == "" {
		http.Error(w, "Missing keyword ID", http.StatusBadRequest)
		return
	}

	var kw keywords.Keyword
	if err := json.NewDecoder(r.Body).Decode(&kw); err != nil {
		http.Error(w, "Invalid request body", http.StatusBadRequest)
		return
	}

	kw.ID = id

	// Validate regex if REGEX type
	if kw.MatchType == "REGEX" {
		if err := keywords.ValidateRegex(kw.Keyword); err != nil {
			http.Error(w, "Invalid regex pattern: "+err.Error(), http.StatusBadRequest)
			return
		}
	}

	if err := h.service.Update(r.Context(), &kw); err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(kw)
}

// HandleDelete handles DELETE /api/keywords/:id
func (h *KeywordsHandler) HandleDelete(w http.ResponseWriter, r *http.Request) {
	id := r.URL.Query().Get("id")
	if id == "" {
		http.Error(w, "Missing keyword ID", http.StatusBadRequest)
		return
	}

	if err := h.service.Delete(r.Context(), id); err != nil {
		http.Error(w, err.Error(), http.StatusNotFound)
		return
	}

	w.WriteHeader(http.StatusNoContent)
}

// HandleTest handles POST /api/keywords/test
func (h *KeywordsHandler) HandleTest(w http.ResponseWriter, r *http.Request) {
	var req struct {
		Content string `json:"content"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		http.Error(w, "Invalid request body", http.StatusBadRequest)
		return
	}

	if req.Content == "" {
		http.Error(w, "Content is required", http.StatusBadRequest)
		return
	}

	matches, err := h.service.TestKeywords(r.Context(), req.Content)
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}

	// Determine highest classification
	classification := "PUBLIC"
	for _, match := range matches {
		if match.Classification == "RESTRICTED" {
			classification = "RESTRICTED"
			break
		} else if match.Classification == "CONFIDENTIAL" && classification != "RESTRICTED" {
			classification = "CONFIDENTIAL"
		} else if match.Classification == "PRIVATE" && classification == "PUBLIC" {
			classification = "PRIVATE"
		}
	}

	response := map[string]interface{}{
		"matches":        matches,
		"match_count":    len(matches),
		"classification": classification,
		"has_hard_block": false,
	}

	for _, match := range matches {
		if match.HardBlock {
			response["has_hard_block"] = true
			break
		}
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(response)
}

// HandleImport handles POST /api/keywords/import
func (h *KeywordsHandler) HandleImport(w http.ResponseWriter, r *http.Request) {
	// Parse multipart form
	if err := r.ParseMultipartForm(10 << 20); err != nil { // 10MB max
		http.Error(w, "Failed to parse form", http.StatusBadRequest)
		return
	}

	file, _, err := r.FormFile("file")
	if err != nil {
		http.Error(w, "Failed to get file", http.StatusBadRequest)
		return
	}
	defer file.Close()

	data, err := io.ReadAll(file)
	if err != nil {
		http.Error(w, "Failed to read file", http.StatusInternalServerError)
		return
	}

	// Get created_by from form or header
	createdBy := r.FormValue("created_by")
	if createdBy == "" {
		createdBy = "import"
	}

	imported, skipped, err := h.service.ImportCSV(r.Context(), data, createdBy)
	if err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}

	response := map[string]interface{}{
		"imported": imported,
		"skipped":  skipped,
		"message":  "Import completed",
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(response)
}

// HandleExport handles GET /api/keywords/export
func (h *KeywordsHandler) HandleExport(w http.ResponseWriter, r *http.Request) {
	data, err := h.service.ExportCSV(r.Context())
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}

	w.Header().Set("Content-Type", "text/csv")
	w.Header().Set("Content-Disposition", "attachment; filename=keywords.csv")
	w.Write(data)
}

// HandleGroups handles GET /api/keywords/groups
func (h *KeywordsHandler) HandleGroups(w http.ResponseWriter, r *http.Request) {
	groups, err := h.service.GetGroups(r.Context())
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(map[string]interface{}{
		"groups": groups,
	})
}

// HandleValidateRegex handles POST /api/keywords/validate-regex
func (h *KeywordsHandler) HandleValidateRegex(w http.ResponseWriter, r *http.Request) {
	var req struct {
		Pattern string `json:"pattern"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		http.Error(w, "Invalid request body", http.StatusBadRequest)
		return
	}

	if req.Pattern == "" {
		http.Error(w, "Pattern is required", http.StatusBadRequest)
		return
	}

	err := keywords.ValidateRegex(req.Pattern)
	valid := err == nil
	errMsg := ""
	if err != nil {
		errMsg = err.Error()
	}

	response := map[string]interface{}{
		"valid":   valid,
		"error":   errMsg,
		"pattern": req.Pattern,
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(response)
}
