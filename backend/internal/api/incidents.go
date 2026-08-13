package api

import (
	"encoding/json"
	"net/http"
	"strconv"

	"manara-dlp/internal/incidents"
)

// IncidentsHandler handles incident API requests
type IncidentsHandler struct {
	manager *incidents.Manager
}

// NewIncidentsHandler creates a new incidents handler
func NewIncidentsHandler(manager *incidents.Manager) *IncidentsHandler {
	return &IncidentsHandler{manager: manager}
}

// HandleList handles GET /api/incidents
func (h *IncidentsHandler) HandleList(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()

	filters := incidents.IncidentFilters{
		Severity:   r.URL.Query().Get("severity"),
		Status:     r.URL.Query().Get("status"),
		Decision:   r.URL.Query().Get("decision"),
		UserSID:    r.URL.Query().Get("user_sid"),
		DeviceID:   r.URL.Query().Get("device_id"),
		PolicyID:   r.URL.Query().Get("policy_id"),
		AssignedTo: r.URL.Query().Get("assigned_to"),
		Search:     r.URL.Query().Get("search"),
	}

	if limit := r.URL.Query().Get("limit"); limit != "" {
		filters.Limit, _ = strconv.Atoi(limit)
	} else {
		filters.Limit = 50
	}

	if offset := r.URL.Query().Get("offset"); offset != "" {
		filters.Offset, _ = strconv.Atoi(offset)
	}

	incs, total, err := h.manager.List(ctx, filters)
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}

	response := map[string]interface{}{
		"incidents": incs,
		"total":     total,
		"limit":     filters.Limit,
		"offset":    filters.Offset,
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(response)
}

// HandleGet handles GET /api/incidents/:id
func (h *IncidentsHandler) HandleGet(w http.ResponseWriter, r *http.Request) {
	idStr := r.URL.Query().Get("id")
	if idStr == "" {
		http.Error(w, "Missing incident ID", http.StatusBadRequest)
		return
	}

	id, err := strconv.ParseInt(idStr, 10, 64)
	if err != nil {
		http.Error(w, "Invalid incident ID", http.StatusBadRequest)
		return
	}

	inc, err := h.manager.GetByID(r.Context(), id)
	if err != nil {
		http.Error(w, err.Error(), http.StatusNotFound)
		return
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(inc)
}

// HandleCreate handles POST /api/incidents
func (h *IncidentsHandler) HandleCreate(w http.ResponseWriter, r *http.Request) {
	var inc incidents.Incident
	if err := json.NewDecoder(r.Body).Decode(&inc); err != nil {
		http.Error(w, "Invalid request body", http.StatusBadRequest)
		return
	}

	// Validate required fields
	if inc.Username == "" || inc.ActionAttempted == "" || inc.Decision == "" {
		http.Error(w, "Missing required fields", http.StatusBadRequest)
		return
	}

	// Set defaults
	if inc.Severity == "" {
		inc.Severity = "MEDIUM"
	}
	if inc.Status == "" {
		inc.Status = "OPEN"
	}

	if err := h.manager.Create(r.Context(), &inc); err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}

	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusCreated)
	json.NewEncoder(w).Encode(inc)
}

// HandleUpdateStatus handles PUT /api/incidents/:id/status
func (h *IncidentsHandler) HandleUpdateStatus(w http.ResponseWriter, r *http.Request) {
	idStr := r.URL.Query().Get("id")
	if idStr == "" {
		http.Error(w, "Missing incident ID", http.StatusBadRequest)
		return
	}

	id, err := strconv.ParseInt(idStr, 10, 64)
	if err != nil {
		http.Error(w, "Invalid incident ID", http.StatusBadRequest)
		return
	}

	var req struct {
		Status   string `json:"status"`
		Username string `json:"username"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		http.Error(w, "Invalid request body", http.StatusBadRequest)
		return
	}

	// Validate status
	validStatuses := map[string]bool{
		"OPEN": true, "INVESTIGATING": true, "ESCALATED": true,
		"RESOLVED": true, "FALSE_POSITIVE": true, "ACKNOWLEDGED": true,
	}
	if !validStatuses[req.Status] {
		http.Error(w, "Invalid status", http.StatusBadRequest)
		return
	}

	if err := h.manager.UpdateStatus(r.Context(), id, req.Status, req.Username); err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(map[string]interface{}{
		"message": "Status updated",
		"id":      id,
		"status":  req.Status,
	})
}

// HandleAssign handles PUT /api/incidents/:id/assign
func (h *IncidentsHandler) HandleAssign(w http.ResponseWriter, r *http.Request) {
	idStr := r.URL.Query().Get("id")
	if idStr == "" {
		http.Error(w, "Missing incident ID", http.StatusBadRequest)
		return
	}

	id, err := strconv.ParseInt(idStr, 10, 64)
	if err != nil {
		http.Error(w, "Invalid incident ID", http.StatusBadRequest)
		return
	}

	var req struct {
		AssignTo   string `json:"assign_to"`
		AssignedBy string `json:"assigned_by"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		http.Error(w, "Invalid request body", http.StatusBadRequest)
		return
	}

	if req.AssignTo == "" {
		http.Error(w, "assign_to is required", http.StatusBadRequest)
		return
	}

	if err := h.manager.Assign(r.Context(), id, req.AssignTo, req.AssignedBy); err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(map[string]interface{}{
		"message":   "Incident assigned",
		"id":        id,
		"assign_to": req.AssignTo,
	})
}

// HandleEscalate handles POST /api/incidents/:id/escalate
func (h *IncidentsHandler) HandleEscalate(w http.ResponseWriter, r *http.Request) {
	idStr := r.URL.Query().Get("id")
	if idStr == "" {
		http.Error(w, "Missing incident ID", http.StatusBadRequest)
		return
	}

	id, err := strconv.ParseInt(idStr, 10, 64)
	if err != nil {
		http.Error(w, "Invalid incident ID", http.StatusBadRequest)
		return
	}

	var req struct {
		EscalateTo  string `json:"escalate_to"`
		EscalatedBy string `json:"escalated_by"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		http.Error(w, "Invalid request body", http.StatusBadRequest)
		return
	}

	if req.EscalateTo == "" {
		http.Error(w, "escalate_to is required", http.StatusBadRequest)
		return
	}

	if err := h.manager.Escalate(r.Context(), id, req.EscalateTo, req.EscalatedBy); err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(map[string]interface{}{
		"message":     "Incident escalated",
		"id":          id,
		"escalate_to": req.EscalateTo,
	})
}

// HandleResolve handles POST /api/incidents/:id/resolve
func (h *IncidentsHandler) HandleResolve(w http.ResponseWriter, r *http.Request) {
	idStr := r.URL.Query().Get("id")
	if idStr == "" {
		http.Error(w, "Missing incident ID", http.StatusBadRequest)
		return
	}

	id, err := strconv.ParseInt(idStr, 10, 64)
	if err != nil {
		http.Error(w, "Invalid incident ID", http.StatusBadRequest)
		return
	}

	var req struct {
		ResolutionNotes string `json:"resolution_notes"`
		ResolvedBy      string `json:"resolved_by"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		http.Error(w, "Invalid request body", http.StatusBadRequest)
		return
	}

	if err := h.manager.Resolve(r.Context(), id, req.ResolutionNotes, req.ResolvedBy); err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(map[string]interface{}{
		"message": "Incident resolved",
		"id":      id,
	})
}

// HandleFalsePositive handles POST /api/incidents/:id/false-positive
func (h *IncidentsHandler) HandleFalsePositive(w http.ResponseWriter, r *http.Request) {
	idStr := r.URL.Query().Get("id")
	if idStr == "" {
		http.Error(w, "Missing incident ID", http.StatusBadRequest)
		return
	}

	id, err := strconv.ParseInt(idStr, 10, 64)
	if err != nil {
		http.Error(w, "Invalid incident ID", http.StatusBadRequest)
		return
	}

	var req struct {
		Notes    string `json:"notes"`
		MarkedBy string `json:"marked_by"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		http.Error(w, "Invalid request body", http.StatusBadRequest)
		return
	}

	if err := h.manager.MarkFalsePositive(r.Context(), id, req.Notes, req.MarkedBy); err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(map[string]interface{}{
		"message": "Marked as false positive",
		"id":      id,
	})
}

// HandleAddNote handles POST /api/incidents/:id/notes
func (h *IncidentsHandler) HandleAddNote(w http.ResponseWriter, r *http.Request) {
	idStr := r.URL.Query().Get("id")
	if idStr == "" {
		http.Error(w, "Missing incident ID", http.StatusBadRequest)
		return
	}

	id, err := strconv.ParseInt(idStr, 10, 64)
	if err != nil {
		http.Error(w, "Invalid incident ID", http.StatusBadRequest)
		return
	}

	var req struct {
		Author  string `json:"author"`
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

	if err := h.manager.AddNote(r.Context(), id, req.Author, "COMMENT", req.Content, "", ""); err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}

	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusCreated)
	json.NewEncoder(w).Encode(map[string]interface{}{
		"message": "Note added",
		"id":      id,
	})
}

// HandleGetNotes handles GET /api/incidents/:id/notes
func (h *IncidentsHandler) HandleGetNotes(w http.ResponseWriter, r *http.Request) {
	idStr := r.URL.Query().Get("id")
	if idStr == "" {
		http.Error(w, "Missing incident ID", http.StatusBadRequest)
		return
	}

	id, err := strconv.ParseInt(idStr, 10, 64)
	if err != nil {
		http.Error(w, "Invalid incident ID", http.StatusBadRequest)
		return
	}

	notes, err := h.manager.GetNotes(r.Context(), id)
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(map[string]interface{}{
		"incident_id": id,
		"notes":       notes,
	})
}

// HandleStats handles GET /api/incidents/stats
func (h *IncidentsHandler) HandleStats(w http.ResponseWriter, r *http.Request) {
	days := 7
	if d := r.URL.Query().Get("days"); d != "" {
		days, _ = strconv.Atoi(d)
	}

	stats, err := h.manager.GetStats(r.Context(), days)
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(stats)
}
