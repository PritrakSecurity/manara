package api

import (
	"encoding/json"
	"net/http"
	"strconv"

	"enterprise-dlp-backend/internal/approval"
)

// ApprovalsHandler handles approval API requests
type ApprovalsHandler struct {
	service *approval.WorkflowService
}

// NewApprovalsHandler creates a new approvals handler
func NewApprovalsHandler(service *approval.WorkflowService) *ApprovalsHandler {
	return &ApprovalsHandler{service: service}
}

// HandleList handles GET /api/approvals
func (h *ApprovalsHandler) HandleList(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()

	filters := approval.ApprovalFilters{
		OwnerSID:     r.URL.Query().Get("owner_sid"),
		RequesterSID: r.URL.Query().Get("requester_sid"),
		Status:       r.URL.Query().Get("status"),
		ActionType:   r.URL.Query().Get("action_type"),
	}

	if r.URL.Query().Get("pending_only") == "true" {
		filters.PendingOnly = true
	}

	if limit := r.URL.Query().Get("limit"); limit != "" {
		filters.Limit, _ = strconv.Atoi(limit)
	} else {
		filters.Limit = 50
	}

	if offset := r.URL.Query().Get("offset"); offset != "" {
		filters.Offset, _ = strconv.Atoi(offset)
	}

	requests, err := h.service.List(ctx, filters)
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(map[string]interface{}{
		"requests": requests,
		"total":    len(requests),
	})
}

// HandleGetPending handles GET /api/approvals/pending
func (h *ApprovalsHandler) HandleGetPending(w http.ResponseWriter, r *http.Request) {
	ownerSID := r.URL.Query().Get("owner_sid")
	if ownerSID == "" {
		http.Error(w, "Missing owner_sid parameter", http.StatusBadRequest)
		return
	}

	requests, err := h.service.GetPendingForOwner(r.Context(), ownerSID)
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(map[string]interface{}{
		"requests": requests,
		"count":    len(requests),
	})
}

// HandleGet handles GET /api/approvals/:id
func (h *ApprovalsHandler) HandleGet(w http.ResponseWriter, r *http.Request) {
	requestID := r.URL.Query().Get("id")
	if requestID == "" {
		http.Error(w, "Missing request ID", http.StatusBadRequest)
		return
	}

	request, err := h.service.GetRequest(r.Context(), requestID)
	if err != nil {
		http.Error(w, err.Error(), http.StatusNotFound)
		return
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(request)
}

// HandleCreate handles POST /api/approvals
func (h *ApprovalsHandler) HandleCreate(w http.ResponseWriter, r *http.Request) {
	var req approval.ApprovalRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		http.Error(w, "Invalid request body", http.StatusBadRequest)
		return
	}

	// Validate required fields
	if req.FileHash == "" || req.RequesterSID == "" || req.OwnerSID == "" || req.ActionType == "" {
		http.Error(w, "Missing required fields", http.StatusBadRequest)
		return
	}

	if err := h.service.CreateRequest(r.Context(), &req); err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}

	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusCreated)
	json.NewEncoder(w).Encode(req)
}

// HandleApprove handles POST /api/approvals/:id/approve
func (h *ApprovalsHandler) HandleApprove(w http.ResponseWriter, r *http.Request) {
	requestID := r.URL.Query().Get("id")
	if requestID == "" {
		http.Error(w, "Missing request ID", http.StatusBadRequest)
		return
	}

	var req struct {
		Comment   string `json:"comment"`
		Permanent bool   `json:"permanent"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		// Allow empty body
		req.Comment = ""
		req.Permanent = false
	}

	if err := h.service.Approve(r.Context(), requestID, req.Comment, req.Permanent); err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(map[string]interface{}{
		"message":    "Request approved",
		"request_id": requestID,
	})
}

// HandleDeny handles POST /api/approvals/:id/deny
func (h *ApprovalsHandler) HandleDeny(w http.ResponseWriter, r *http.Request) {
	requestID := r.URL.Query().Get("id")
	if requestID == "" {
		http.Error(w, "Missing request ID", http.StatusBadRequest)
		return
	}

	var req struct {
		Comment string `json:"comment"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		req.Comment = ""
	}

	if err := h.service.Deny(r.Context(), requestID, req.Comment); err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(map[string]interface{}{
		"message":    "Request denied",
		"request_id": requestID,
	})
}

// HandleCancel handles POST /api/approvals/:id/cancel
func (h *ApprovalsHandler) HandleCancel(w http.ResponseWriter, r *http.Request) {
	requestID := r.URL.Query().Get("id")
	if requestID == "" {
		http.Error(w, "Missing request ID", http.StatusBadRequest)
		return
	}

	if err := h.service.Cancel(r.Context(), requestID); err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(map[string]interface{}{
		"message":    "Request cancelled",
		"request_id": requestID,
	})
}

// HandleHistory handles GET /api/approvals/history
func (h *ApprovalsHandler) HandleHistory(w http.ResponseWriter, r *http.Request) {
	filters := approval.ApprovalFilters{
		OwnerSID:     r.URL.Query().Get("owner_sid"),
		RequesterSID: r.URL.Query().Get("requester_sid"),
		PendingOnly:  false,
		Limit:        100,
	}

	if limit := r.URL.Query().Get("limit"); limit != "" {
		filters.Limit, _ = strconv.Atoi(limit)
	}

	if offset := r.URL.Query().Get("offset"); offset != "" {
		filters.Offset, _ = strconv.Atoi(offset)
	}

	requests, err := h.service.List(r.Context(), filters)
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(map[string]interface{}{
		"requests": requests,
		"total":    len(requests),
	})
}

// HandlePendingCount handles GET /api/approvals/pending/count
func (h *ApprovalsHandler) HandlePendingCount(w http.ResponseWriter, r *http.Request) {
	ownerSID := r.URL.Query().Get("owner_sid")
	if ownerSID == "" {
		http.Error(w, "Missing owner_sid parameter", http.StatusBadRequest)
		return
	}

	count, err := h.service.GetPendingCount(r.Context(), ownerSID)
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(map[string]interface{}{
		"count":     count,
		"owner_sid": ownerSID,
	})
}

// HandleProcessTimeouts handles POST /api/approvals/process-timeouts
func (h *ApprovalsHandler) HandleProcessTimeouts(w http.ResponseWriter, r *http.Request) {
	count, err := h.service.ProcessTimeouts(r.Context())
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(map[string]interface{}{
		"timed_out": count,
		"message":   "Timeouts processed",
	})
}
