package api

import (
	"encoding/json"
	"fmt"
	"log"
	"net/http"
	"sync"
	"time"

	"enterprise-dlp-backend/internal/classification"
)

// InMemoryRulesStore provides in-memory storage for classification rules (when database is unavailable)
type InMemoryRulesStore struct {
	rules  map[int]classification.ClassificationRule
	mu     sync.RWMutex
	nextID int
}

// NewInMemoryRulesStore creates a new in-memory rules store
func NewInMemoryRulesStore() *InMemoryRulesStore {
	return &InMemoryRulesStore{
		rules:  make(map[int]classification.ClassificationRule),
		nextID: 1,
	}
}

// GetAllRules returns all rules
func (s *InMemoryRulesStore) GetAllRules() []classification.ClassificationRule {
	s.mu.RLock()
	defer s.mu.RUnlock()

	rules := make([]classification.ClassificationRule, 0, len(s.rules))
	for _, rule := range s.rules {
		rules = append(rules, rule)
	}
	return rules
}

// AddRule adds a new rule
func (s *InMemoryRulesStore) AddRule(rule classification.ClassificationRule) error {
	s.mu.Lock()
	defer s.mu.Unlock()

	rule.ID = s.nextID
	rule.CreatedAt = time.Now()
	rule.UpdatedAt = time.Now()
	s.rules[s.nextID] = rule
	s.nextID++

	log.Printf("[IN-MEMORY] Added rule '%s' (ID: %d)", rule.Name, rule.ID)
	return nil
}

// UpdateRule updates an existing rule
func (s *InMemoryRulesStore) UpdateRule(rule classification.ClassificationRule) error {
	s.mu.Lock()
	defer s.mu.Unlock()

	if _, exists := s.rules[rule.ID]; !exists {
		return fmt.Errorf("rule %d not found", rule.ID)
	}

	rule.UpdatedAt = time.Now()
	s.rules[rule.ID] = rule
	log.Printf("[IN-MEMORY] Updated rule '%s' (ID: %d)", rule.Name, rule.ID)
	return nil
}

// DeleteRule deletes a rule by ID
func (s *InMemoryRulesStore) DeleteRule(ruleID int) error {
	s.mu.Lock()
	defer s.mu.Unlock()

	if _, exists := s.rules[ruleID]; !exists {
		return fmt.Errorf("rule %d not found", ruleID)
	}

	delete(s.rules, ruleID)
	log.Printf("[IN-MEMORY] Deleted rule (ID: %d)", ruleID)
	return nil
}

// InMemoryRulesHandler handles rules via in-memory storage
type InMemoryRulesHandler struct {
	store      *InMemoryRulesStore
	ruleEngine *classification.RuleEngine
}

// NewInMemoryRulesHandler creates a new in-memory rules handler
func NewInMemoryRulesHandler() *InMemoryRulesHandler {
	return &InMemoryRulesHandler{
		store:      NewInMemoryRulesStore(),
		ruleEngine: classification.NewRuleEngine(nil), // nil DB = in-memory only
	}
}

// GetRuleEngine returns the rule engine (for wiring to events handler)
func (h *InMemoryRulesHandler) GetRuleEngine() *classification.RuleEngine {
	return h.ruleEngine
}

// syncRulesToEngine syncs the current rules to the rule engine
func (h *InMemoryRulesHandler) syncRulesToEngine() {
	rules := h.store.GetAllRules()
	h.ruleEngine.SetRules(rules)
}

// HandleGetRules returns all classification rules
func (h *InMemoryRulesHandler) HandleGetRules(w http.ResponseWriter, r *http.Request) {
	rules := h.store.GetAllRules()

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(map[string]interface{}{
		"rules": rules,
		"total": len(rules),
	})
}

// HandleCreateRule creates a new classification rule
func (h *InMemoryRulesHandler) HandleCreateRule(w http.ResponseWriter, r *http.Request) {
	// Accept both frontend format and backend format
	var raw map[string]interface{}
	if err := json.NewDecoder(r.Body).Decode(&raw); err != nil {
		http.Error(w, "Invalid request body", http.StatusBadRequest)
		log.Printf("[ERROR] Failed to decode rule: %v", err)
		return
	}

	// Convert frontend format to backend format
	var rule classification.ClassificationRule

	// Map name
	if name, ok := raw["name"].(string); ok {
		rule.Name = name
	}
	if desc, ok := raw["description"].(string); ok {
		rule.Description = desc
	}
	if priority, ok := raw["priority"].(float64); ok {
		rule.Priority = int(priority)
	}

	// Map isActive -> Enabled
	if isActive, ok := raw["isActive"].(bool); ok {
		rule.Enabled = isActive
	} else if enabled, ok := raw["enabled"].(bool); ok {
		rule.Enabled = enabled
	} else {
		rule.Enabled = true // Default to enabled
	}

	// Map classification -> ActionClassification
	if cls, ok := raw["classification"].(string); ok {
		rule.ActionClassification = cls
	} else if cls, ok := raw["action_classification"].(string); ok {
		rule.ActionClassification = cls
	}

	// Map conditions array -> ConditionField, ConditionOperator, ConditionValue
	if conditions, ok := raw["conditions"].([]interface{}); ok && len(conditions) > 0 {
		if cond, ok := conditions[0].(map[string]interface{}); ok {
			if condType, ok := cond["type"].(string); ok {
				rule.ConditionField = condType
			}
			if condVal, ok := cond["value"].(string); ok {
				rule.ConditionValue = condVal
			}
			// Default operator based on type
			if rule.ConditionField == "keyword" {
				rule.ConditionOperator = "contains"
			} else if op, ok := cond["operator"].(string); ok {
				rule.ConditionOperator = op
			}
		}
	} else {
		// Try backend format fields
		if cf, ok := raw["condition_field"].(string); ok {
			rule.ConditionField = cf
		}
		if co, ok := raw["condition_operator"].(string); ok {
			rule.ConditionOperator = co
		}
		if cv, ok := raw["condition_value"].(string); ok {
			rule.ConditionValue = cv
		}
	}

	// Map action type
	if at, ok := raw["action_type"].(string); ok {
		rule.ActionType = at
	} else if actions, ok := raw["actions"].([]interface{}); ok && len(actions) > 0 {
		if act, ok := actions[0].(map[string]interface{}); ok {
			if actType, ok := act["type"].(string); ok {
				rule.ActionType = actType
			}
		}
	}

	log.Printf("[IN-MEMORY] Creating rule: name=%s enabled=%v field=%s op=%s value=%s classification=%s",
		rule.Name, rule.Enabled, rule.ConditionField, rule.ConditionOperator, rule.ConditionValue, rule.ActionClassification)

	if err := h.store.AddRule(rule); err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		log.Printf("[ERROR] Failed to add rule: %v", err)
		return
	}

	// Sync rules to engine for classification
	h.syncRulesToEngine()

	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusCreated)
	json.NewEncoder(w).Encode(map[string]interface{}{
		"success": true,
		"message": "Rule created successfully",
	})
}

// HandleUpdateRule updates an existing classification rule
func (h *InMemoryRulesHandler) HandleUpdateRule(w http.ResponseWriter, r *http.Request, ruleID int) {
	var rule classification.ClassificationRule
	if err := json.NewDecoder(r.Body).Decode(&rule); err != nil {
		http.Error(w, "Invalid request body", http.StatusBadRequest)
		return
	}

	rule.ID = ruleID

	if err := h.store.UpdateRule(rule); err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}

	// Sync rules to engine for classification
	h.syncRulesToEngine()

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(map[string]interface{}{
		"success": true,
		"message": "Rule updated successfully",
	})
}

// HandleDeleteRule deletes a classification rule
func (h *InMemoryRulesHandler) HandleDeleteRule(w http.ResponseWriter, r *http.Request, ruleID int) {
	if err := h.store.DeleteRule(ruleID); err != nil {
		http.Error(w, err.Error(), http.StatusNotFound)
		return
	}

	// Sync rules to engine for classification
	h.syncRulesToEngine()

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(map[string]interface{}{
		"success": true,
		"message": "Rule deleted successfully",
	})
}
