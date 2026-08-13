package api

import (
	"encoding/json"
	"log"
	"net/http"

	"enterprise-dlp-backend/internal/classification"
)

// ClassificationRulesHandler handles rule management APIs
type ClassificationRulesHandler struct {
	ruleEngine *classification.RuleEngine
}

// NewClassificationRulesHandler creates a new rules handler
func NewClassificationRulesHandler(ruleEngine *classification.RuleEngine) *ClassificationRulesHandler {
	return &ClassificationRulesHandler{
		ruleEngine: ruleEngine,
	}
}

// HandleGetRules returns all classification rules
func (h *ClassificationRulesHandler) HandleGetRules(w http.ResponseWriter, r *http.Request) {
	if h.ruleEngine == nil {
		http.Error(w, "Rule engine not available", http.StatusServiceUnavailable)
		return
	}

	rules := h.ruleEngine.GetAllRules()

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(map[string]interface{}{
		"rules": rules,
		"total": len(rules),
	})
}

// HandleCreateRule creates a new classification rule
func (h *ClassificationRulesHandler) HandleCreateRule(w http.ResponseWriter, r *http.Request) {
	if h.ruleEngine == nil {
		http.Error(w, "Rule engine not available", http.StatusServiceUnavailable)
		return
	}

	var rule classification.ClassificationRule
	if err := json.NewDecoder(r.Body).Decode(&rule); err != nil {
		http.Error(w, "Invalid request body", http.StatusBadRequest)
		log.Printf("[ERROR] Failed to decode rule: %v", err)
		return
	}

	if err := h.ruleEngine.AddRule(rule); err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		log.Printf("[ERROR] Failed to add rule: %v", err)
		return
	}

	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusCreated)
	json.NewEncoder(w).Encode(map[string]interface{}{
		"success": true,
		"message": "Rule created successfully",
	})
}

// HandleUpdateRule updates an existing classification rule
func (h *ClassificationRulesHandler) HandleUpdateRule(w http.ResponseWriter, r *http.Request, ruleID int) {
	if h.ruleEngine == nil {
		http.Error(w, "Rule engine not available", http.StatusServiceUnavailable)
		return
	}

	var rule classification.ClassificationRule
	if err := json.NewDecoder(r.Body).Decode(&rule); err != nil {
		http.Error(w, "Invalid request body", http.StatusBadRequest)
		return
	}

	rule.ID = ruleID

	if err := h.ruleEngine.UpdateRule(rule); err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(map[string]interface{}{
		"success": true,
		"message": "Rule updated successfully",
	})
}

// HandleDeleteRule deletes a classification rule
func (h *ClassificationRulesHandler) HandleDeleteRule(w http.ResponseWriter, r *http.Request, ruleID int) {
	if h.ruleEngine == nil {
		http.Error(w, "Rule engine not available", http.StatusServiceUnavailable)
		return
	}

	if err := h.ruleEngine.DeleteRule(ruleID); err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(map[string]interface{}{
		"success": true,
		"message": "Rule deleted successfully",
	})
}
