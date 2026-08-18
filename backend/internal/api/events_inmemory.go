package api

import (
	"encoding/json"
	"log"
	"net/http"
	"strings"
	"sync"
	"time"

	"manara-dlp/internal/classification"

	"github.com/google/uuid"
)

type InMemoryEventsHandler struct {
	mu            sync.RWMutex
	events        []map[string]interface{}
	incidents     []map[string]interface{}
	rules         []map[string]interface{}
	classifier    *classification.ClassificationEngine
	ruleEngine    *classification.RuleEngine
	pendingEvents map[string]string    // filePath -> event ID for events waiting for content
	pendingExpiry map[string]time.Time // filePath -> expiry time
}

func NewInMemoryEventsHandler() *InMemoryEventsHandler {
	h := &InMemoryEventsHandler{
		classifier:    classification.NewEngineWithProvider(ClassificationProvider),
		ruleEngine:    nil,
		pendingEvents: make(map[string]string),
		pendingExpiry: make(map[string]time.Time),
	}
	// Seed a simple DLP rule
	h.rules = []map[string]interface{}{
		{"id": "rule-1", "name": "Confidential Files", "conditions": map[string]interface{}{"classification": []string{"CONFIDENTIAL", "RESTRICTED"}}, "action": "ALERT", "severity": "HIGH"},
		{"id": "rule-2", "name": "Password Leakage", "conditions": map[string]interface{}{"keywords_found": []string{"password", "credential"}}, "action": "ALERT", "severity": "CRITICAL"},
	}
	h.events = []map[string]interface{}{}
	h.incidents = []map[string]interface{}{}
	return h
}

// SetRuleEngine sets the rule engine for classification
func (h *InMemoryEventsHandler) SetRuleEngine(engine *classification.RuleEngine) {
	h.mu.Lock()
	defer h.mu.Unlock()
	h.ruleEngine = engine
	if h.classifier != nil {
		h.classifier.SetRuleEngine(engine)
	}
}

// ReceiveEventBatch accepts event batches and stores them in memory
func (h *InMemoryEventsHandler) ReceiveEventBatch(w http.ResponseWriter, r *http.Request) {
	var batch EventBatch
	if err := json.NewDecoder(r.Body).Decode(&batch); err != nil {
		http.Error(w, "invalid request format", http.StatusBadRequest)
		log.Printf("[ERROR] Invalid event batch (inmemory): %v", err)
		return
	}
	if len(batch.Events) == 0 {
		http.Error(w, "events array is empty", http.StatusBadRequest)
		return
	}

	// Extract file content from header if available
	fileContent := r.Header.Get("X-File-Content")

	h.mu.Lock()
	defer h.mu.Unlock()

	// Clean up expired pending events
	now := time.Now()
	for fp, expiry := range h.pendingExpiry {
		if now.After(expiry) {
			delete(h.pendingEvents, fp)
			delete(h.pendingExpiry, fp)
		}
	}

	processed := 0
	var incidentIDs []string

	for _, ev := range batch.Events {
		// Normalize file path for consistent lookups
		normalizedPath := strings.ToLower(ev.FilePath)

		// Check if this event has content and there's a pending event for this file
		if fileContent != "" && len(fileContent) > 0 {
			if pendingID, exists := h.pendingEvents[normalizedPath]; exists {
				// Found a pending event - update it with proper classification
				for i, storedEvent := range h.events {
					if storedEvent["id"] == pendingID {
						// Classify with the new content
						res := h.classifier.ClassifyWithContent(ev.FilePath, fileContent, int64(len(fileContent)))
						log.Printf("[INMEM-UPDATE-PENDING] file=%s pendingID=%s contentLen=%d class=%s score=%.2f risk=%s",
							ev.FilePath, pendingID, len(fileContent), res.Classification, res.Score, res.RiskLevel)

						h.events[i]["classification"] = res.Classification
						h.events[i]["risk_level"] = res.RiskLevel
						h.events[i]["classification_score"] = res.Score

						// Check if this triggers incidents
						ev.Classification = res.Classification
						ev.RiskLevel = res.RiskLevel
						ev.ClassificationScore = res.Score
						triggered := h.checkDLPRules(pendingID, batch.DeviceID, &ev)
						for _, tid := range triggered {
							incidentIDs = append(incidentIDs, tid)
						}

						// Remove from pending
						delete(h.pendingEvents, normalizedPath)
						delete(h.pendingExpiry, normalizedPath)
						break
					}
				}
				// Don't create a new event - we updated the pending one
				processed++
				continue
			}
		}

		id := uuid.New().String()

		// Classify if we have a path; fall back to PUBLIC for missing paths
		classificationValue := ev.Classification
		riskValue := ev.RiskLevel
		scoreValue := ev.ClassificationScore

		// If agent already provided a valid classification, USE IT!
		agentProvidedValidClassification := classificationValue != "" &&
			classificationValue != "PENDING" &&
			classificationValue != "UNKNOWN"

		if agentProvidedValidClassification {
			log.Printf("[INMEM-AGENT-CLASS] Using agent classification: file=%s class=%s", ev.FilePath, classificationValue)
			// Determine risk level based on classification
			if riskValue == "" {
				switch classificationValue {
				case "RESTRICTED", "SECRET":
					riskValue = "HIGH"
					scoreValue = 100
				case "CONFIDENTIAL":
					riskValue = "MEDIUM"
					scoreValue = 75
				case "INTERNAL":
					riskValue = "LOW"
					scoreValue = 50
				default:
					riskValue = "NONE"
					scoreValue = 0
				}
			}
		} else if ev.FilePath != "" {
			var res classification.EngineClassificationResult

			// Use content-based classification if content is available
			if fileContent != "" && len(fileContent) > 0 {
				// Pass content length as file size so fast filter doesn't treat as empty
				res = h.classifier.ClassifyWithContent(ev.FilePath, fileContent, int64(len(fileContent)))
				log.Printf("[INMEM-CLASSIFY-CONTENT] file=%s contentLen=%d class=%s score=%.2f risk=%s",
					ev.FilePath, len(fileContent), res.Classification, res.Score, res.RiskLevel)
			} else {
				// No content - if this is a rename/create, mark as pending
				isRenameOrCreate := ev.EventType == "file_renamed" || ev.EventType == "file_created"
				if isRenameOrCreate {
					// Store as pending - use PENDING classification temporarily
					res = classification.EngineClassificationResult{
						Classification: "PENDING",
						Score:          0,
						RiskLevel:      "NONE",
					}
					h.pendingEvents[normalizedPath] = id
					h.pendingExpiry[normalizedPath] = time.Now().Add(30 * time.Second)
					log.Printf("[INMEM-PENDING] file=%s id=%s waiting for content (expires in 30s)", ev.FilePath, id)
				} else {
					res = h.classifier.Classify(ev.FilePath)
					log.Printf("[INMEM-CLASSIFY] file=%s class=%s score=%.2f risk=%s",
						ev.FilePath, res.Classification, res.Score, res.RiskLevel)
				}
			}

			classificationValue = res.Classification
			riskValue = res.RiskLevel
			scoreValue = res.Score
			ev.Classification = classificationValue
			ev.RiskLevel = riskValue
			ev.ClassificationScore = scoreValue
		}
		if classificationValue == "" {
			classificationValue = "PUBLIC"
		}
		if riskValue == "" {
			riskValue = "NONE"
		}

		rec := map[string]interface{}{
			"id":                   id,
			"device_id":            batch.DeviceID,
			"event_type":           ev.EventType,
			"file_path":            ev.FilePath,
			"file_name":            ev.FileName,
			"classification":       classificationValue,
			"risk_level":           riskValue,
			"classification_score": scoreValue,
			"keywords_found":       ev.KeywordsFound,
			"username":             ev.Username,
			"created_at":           ev.Timestamp,
		}
		h.events = append([]map[string]interface{}{rec}, h.events...)
		processed++

		// Broadcast event to WebSocket clients for real-time updates
		if GlobalWSHub != nil {
			GlobalWSHub.BroadcastFileEvent(rec)
		}

		// check rules - but not for PENDING events
		if classificationValue != "PENDING" {
			triggered := h.checkDLPRules(id, batch.DeviceID, &ev)
			for _, tid := range triggered {
				incidentIDs = append(incidentIDs, tid)
			}
		}
	}

	resp := map[string]interface{}{"processed": processed, "incidents_triggered": len(incidentIDs), "incident_ids": incidentIDs, "message": "events logged (in-memory)"}
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(resp)
}

// ListEventLogs returns stored events with simple filters
func (h *InMemoryEventsHandler) ListEventLogs(w http.ResponseWriter, r *http.Request) {
	q := r.URL.Query()
	eventType := q.Get("event_type")
	classification := q.Get("classification")
	riskLevel := q.Get("risk_level")
	username := q.Get("username")

	h.mu.RLock()
	defer h.mu.RUnlock()
	out := []map[string]interface{}{}
	for _, ev := range h.events {
		if eventType != "" && ev["event_type"] != eventType {
			continue
		}
		if classification != "" && ev["classification"] != classification {
			continue
		}
		if riskLevel != "" && ev["risk_level"] != riskLevel {
			continue
		}
		if username != "" {
			if uname, ok := ev["username"].(string); !ok || !strings.Contains(strings.ToLower(uname), strings.ToLower(username)) {
				continue
			}
		}
		out = append(out, ev)
	}
	resp := map[string]interface{}{"events": out, "total": len(out), "limit": len(out), "offset": 0}
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(resp)
}

// ListIncidents returns incidents
func (h *InMemoryEventsHandler) ListIncidents(w http.ResponseWriter, r *http.Request) {
	status := r.URL.Query().Get("status")
	severity := r.URL.Query().Get("severity")

	h.mu.RLock()
	defer h.mu.RUnlock()
	out := []map[string]interface{}{}
	for _, inc := range h.incidents {
		if status != "" && inc["status"] != status {
			continue
		}
		if severity != "" && inc["severity"] != severity {
			continue
		}
		out = append(out, inc)
	}
	resp := map[string]interface{}{"incidents": out, "total": len(out), "limit": len(out), "offset": 0}
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(resp)
}

// ResolveIncident marks an incident resolved
func (h *InMemoryEventsHandler) ResolveIncident(w http.ResponseWriter, r *http.Request) {
	parts := splitPath(r.URL.Path)
	if len(parts) < 4 {
		http.Error(w, "invalid path", http.StatusBadRequest)
		return
	}
	id := parts[3]
	h.mu.Lock()
	defer h.mu.Unlock()
	for _, inc := range h.incidents {
		if inc["id"] == id {
			inc["status"] = "RESOLVED"
			inc["resolved_at"] = time.Now()
			w.Header().Set("Content-Type", "application/json")
			json.NewEncoder(w).Encode(map[string]string{"message": "incident resolved"})
			return
		}
	}
	http.Error(w, "incident not found", http.StatusNotFound)
}

// checkDLPRules applies simple in-memory rules and creates incidents
func (h *InMemoryEventsHandler) checkDLPRules(eventID, deviceID string, ev *FileEvent) []string {
	ids := []string{}
	for _, r := range h.rules {
		// check classification
		if cond, ok := r["conditions"].(map[string]interface{}); ok {
			match := true
			if clsAny, ok := cond["classification"]; ok {
				if cls, ok := clsAny.([]string); ok {
					found := false
					for _, v := range cls {
						if v == ev.Classification {
							found = true
							break
						}
					}
					match = match && found
				}
			}
			if kwsAny, ok := cond["keywords_found"]; ok {
				if kws, ok := kwsAny.([]string); ok {
					found := false
					for _, want := range kws {
						for _, f := range ev.KeywordsFound {
							if strings.EqualFold(want, f) {
								found = true
								break
							}
						}
					}
					match = match && found
				}
			}
			if match {
				id := uuid.New().String()
				inc := map[string]interface{}{
					"id":                    id,
					"device_id":             deviceID,
					"event_id":              eventID,
					"incident_type":         "DLP_VIOLATION",
					"severity":              r["severity"],
					"description":           "In-memory DLP rule triggered",
					"status":                "OPEN",
					"rule_name":             r["name"],
					"rule_triggered_reason": "In-memory rule",
					"file_involved":         ev.FilePath,
					"user_involved":         ev.Username,
					"action_taken":          r["action"],
					"created_at":            time.Now(),
				}
				h.incidents = append([]map[string]interface{}{inc}, h.incidents...)
				ids = append(ids, id)
			}
		}
	}
	return ids
}

// ClassifyFile classifies a file using the classification engine and rule engine
func (h *InMemoryEventsHandler) ClassifyFile(w http.ResponseWriter, r *http.Request) {
	var request struct {
		FilePath    string `json:"file_path"`
		FileContent string `json:"file_content,omitempty"`
	}

	if err := json.NewDecoder(r.Body).Decode(&request); err != nil {
		http.Error(w, "invalid request", http.StatusBadRequest)
		return
	}

	if request.FilePath == "" {
		http.Error(w, "file_path is required", http.StatusBadRequest)
		return
	}

	h.mu.RLock()
	classifier := h.classifier
	ruleEngine := h.ruleEngine
	h.mu.RUnlock()

	// If we have a classifier, use it
	if classifier != nil {
		var result classification.EngineClassificationResult

		if request.FileContent != "" {
			// Use content-based classification
			result = classifier.ClassifyWithContent(request.FilePath, request.FileContent, int64(len(request.FileContent)))
		} else {
			// Standard file path classification
			result = classifier.Classify(request.FilePath)
		}

		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(result)
		return
	}

	// Fallback: Try rule engine directly if no classifier
	if ruleEngine != nil {
		rules := ruleEngine.GetAllRules()
		log.Printf("[CLASSIFY] Checking %d rules for file: %s", len(rules), request.FilePath)

		for _, rule := range rules {
			if !rule.Enabled {
				continue
			}

			// Check filename match
			filename := strings.ToLower(request.FilePath)
			value := strings.ToLower(rule.ConditionValue)

			if rule.ConditionField == "keyword" && rule.ConditionOperator == "contains" {
				// Check if filename or content contains the keyword
				if strings.Contains(filename, value) {
					log.Printf("[CLASSIFY] Rule '%s' matched filename (keyword contains '%s')", rule.Name, value)
					w.Header().Set("Content-Type", "application/json")
					json.NewEncoder(w).Encode(map[string]interface{}{
						"classification": rule.ActionClassification,
						"score":          100,
						"confidence":     100,
						"risk_level":     "HIGH",
						"explanation":    "Rule '" + rule.Name + "' triggered",
						"rule_triggered": rule.Name,
						"elapsed_ms":     0,
					})
					return
				}

				// Check content if provided
				if request.FileContent != "" && strings.Contains(strings.ToLower(request.FileContent), value) {
					log.Printf("[CLASSIFY] Rule '%s' matched content (keyword contains '%s')", rule.Name, value)
					w.Header().Set("Content-Type", "application/json")
					json.NewEncoder(w).Encode(map[string]interface{}{
						"classification": rule.ActionClassification,
						"score":          100,
						"confidence":     100,
						"risk_level":     "HIGH",
						"explanation":    "Rule '" + rule.Name + "' triggered on content",
						"rule_triggered": rule.Name,
						"elapsed_ms":     0,
					})
					return
				}
			}
		}
	}

	// Default response if no rules match
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(map[string]interface{}{
		"classification": "INTERNAL",
		"score":          0,
		"confidence":     100,
		"risk_level":     "LOW",
		"explanation":    "No matching rules found",
		"elapsed_ms":     0,
	})
}
