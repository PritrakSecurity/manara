package api

import (
    "database/sql"
    "encoding/json"
    "fmt"
    "log"
    "net/http"
    "strings"
    "time"

    "github.com/lib/pq"
    "github.com/google/uuid"
    "manara-dlp/internal/classification"
)

type FileEvent struct {
    EventType           string    `json:"event_type"`
    FilePath            string    `json:"file_path"`
    FileName            string    `json:"file_name"`
    FileSize            int64     `json:"file_size"`
    FileExtension       string    `json:"file_extension"`
    SourceLocation      string    `json:"source_location"`
    DestinationLocation string    `json:"destination_location"`
    Classification      string    `json:"classification"`
    ClassificationScore float64   `json:"classification_score"`
    RiskLevel           string    `json:"risk_level"`
    KeywordsFound       []string  `json:"keywords_found"`
    ProcessName         string    `json:"process_name"`
    Username            string    `json:"username"`
    OperationResult     string    `json:"operation_result"`
    Timestamp           time.Time `json:"timestamp"`
    RuleTriggered       string    `json:"rule_triggered,omitempty"` // NEW FOR V3.0: Name of rule that triggered classification
}

type EventBatch struct {
    DeviceID string      `json:"device_id"`
    Events   []FileEvent `json:"events"`
}

type EventsHandler struct {
    db                   *sql.DB
    classificationEngine *classification.ClassificationEngine
}

func NewEventsHandler(db *sql.DB) *EventsHandler {
    ce := classification.NewClassificationEngine()
    return &EventsHandler{
        db:                   db,
        classificationEngine: ce,
    }
}

// SetRuleEngine allows wiring the classification rule engine (supports in-memory rules)
func (h *EventsHandler) SetRuleEngine(engine *classification.RuleEngine) {
    if h != nil && h.classificationEngine != nil {
        h.classificationEngine.SetRuleEngine(engine)
    }
}

// POST /api/v1/events/batch
func (h *EventsHandler) ReceiveEventBatch(w http.ResponseWriter, r *http.Request) {
    var batch EventBatch
    if err := json.NewDecoder(r.Body).Decode(&batch); err != nil {
        http.Error(w, "invalid request format", http.StatusBadRequest)
        log.Printf("[ERROR] Invalid event batch: %v", err)
        return
    }
    if len(batch.Events) == 0 {
        http.Error(w, "events array is empty", http.StatusBadRequest)
        return
    }

    // Verify device exists
    var deviceExists bool
    err := h.db.QueryRow("SELECT EXISTS(SELECT 1 FROM devices WHERE id = $1)", batch.DeviceID).Scan(&deviceExists)
    if err != nil || !deviceExists {
        http.Error(w, "device not found", http.StatusNotFound)
        return
    }

    processed := 0
    var incidentIDs []string

    for _, ev := range batch.Events {
        eid := uuid.New().String()

        // Classify the file if we have a file path
        classification := "INTERNAL"
        classificationScore := 0.0
        riskLevel := "LOW"

        if ev.FilePath != "" {
            result := h.classificationEngine.Classify(ev.FilePath)
            classification = result.Classification
            classificationScore = result.Score
            riskLevel = result.RiskLevel
            log.Printf("[CLASSIFICATION] File: %s | Classification: %s (%v) | Risk: %s | Elapsed: %dms", 
                ev.FilePath, classification, classificationScore, riskLevel, result.ElapsedMs)
        }

        insert := `INSERT INTO event_logs (id, device_id, event_type, file_path, file_name, file_size, file_extension, source_location, destination_location, classification, risk_level, keywords_found, process_name, username, operation_result, created_at) VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12,$13,$14,$15,$16)`

        _, err := h.db.Exec(insert,
            eid,
            batch.DeviceID,
            ev.EventType,
            ev.FilePath,
            ev.FileName,
            ev.FileSize,
            ev.FileExtension,
            ev.SourceLocation,
            ev.DestinationLocation,
            classification,
            riskLevel,
            pq.Array(ev.KeywordsFound),
            ev.ProcessName,
            ev.Username,
            ev.OperationResult,
            ev.Timestamp,
        )
        if err != nil {
            log.Printf("[ERROR] Failed to insert event: %v", err)
            continue
        }
        processed++

        // Update event with classification data for DLP rule checking
        ev.Classification = classification
        ev.ClassificationScore = classificationScore
        ev.RiskLevel = riskLevel

        triggered := h.checkDLPRules(eid, batch.DeviceID, &ev)
        incidentIDs = append(incidentIDs, triggered...)

        log.Printf("[EVENT] Logged: %s | Device: %s | User: %s | File: %s | Classification: %s | Risk: %s", 
            ev.EventType, batch.DeviceID, ev.Username, ev.FileName, classification, riskLevel)
    }

    // update device last_seen and status
    h.db.Exec("UPDATE devices SET last_seen = NOW(), status = 'online' WHERE id = $1", batch.DeviceID)

    resp := map[string]interface{}{"processed": processed, "incidents_triggered": len(incidentIDs), "incident_ids": incidentIDs, "message": "events logged successfully"}
    w.Header().Set("Content-Type", "application/json")
    json.NewEncoder(w).Encode(resp)
}

// POST /api/classify - Classify a file by path
func (h *EventsHandler) ClassifyFile(w http.ResponseWriter, r *http.Request) {
    var request struct {
        FilePath string `json:"file_path"`
    }

    if err := json.NewDecoder(r.Body).Decode(&request); err != nil {
        http.Error(w, "invalid request", http.StatusBadRequest)
        return
    }

    if request.FilePath == "" {
        http.Error(w, "file_path is required", http.StatusBadRequest)
        return
    }

    // Classify the file
    result := h.classificationEngine.Classify(request.FilePath)

    w.Header().Set("Content-Type", "application/json")
    json.NewEncoder(w).Encode(result)
}

// GET /api/v1/event-logs
func (h *EventsHandler) ListEventLogs(w http.ResponseWriter, r *http.Request) {
    limit := 100
    offset := 0
    q := r.URL.Query()
    eventType := q.Get("event_type")
    classification := q.Get("classification")
    riskLevel := q.Get("risk_level")
    username := q.Get("username")

    query := `SELECT id, device_id, event_type, file_path, file_name, file_size, file_extension, source_location, destination_location, classification, risk_level, keywords_found, process_name, username, operation_result, was_blocked, block_reason, created_at FROM event_logs WHERE 1=1`
    args := []interface{}{}
    idx := 1

    if eventType != "" {
        query += " AND event_type = $" + itoa(idx)
        args = append(args, eventType)
        idx++
    }
    if classification != "" {
        query += " AND classification = $" + itoa(idx)
        args = append(args, classification)
        idx++
    }
    if riskLevel != "" {
        query += " AND risk_level = $" + itoa(idx)
        args = append(args, riskLevel)
        idx++
    }
    if username != "" {
        query += " AND username ILIKE '%' || $" + itoa(idx) + " || '%'"
        args = append(args, username)
        idx++
    }

    query += " ORDER BY created_at DESC LIMIT $" + itoa(idx) + " OFFSET $" + itoa(idx+1)
    args = append(args, limit, offset)

    rows, err := h.db.Query(query, args...)
    if err != nil {
        http.Error(w, "database error", http.StatusInternalServerError)
        log.Printf("[ERROR] Failed to list events: %v", err)
        return
    }
    defer rows.Close()

    type EventLog struct {
        ID                  string    `json:"id"`
        DeviceID            string    `json:"device_id"`
        EventType           string    `json:"event_type"`
        FilePath            string    `json:"file_path"`
        FileName            string    `json:"file_name"`
        FileSize            int64     `json:"file_size"`
        FileExtension       string    `json:"file_extension"`
        SourceLocation      string    `json:"source_location"`
        DestinationLocation string    `json:"destination_location"`
        Classification      string    `json:"classification"`
        RiskLevel           string    `json:"risk_level"`
        KeywordsFound       []string  `json:"keywords_found"`
        ProcessName         string    `json:"process_name"`
        Username            string    `json:"username"`
        OperationResult     string    `json:"operation_result"`
        WasBlocked          bool      `json:"was_blocked"`
        BlockReason         string    `json:"block_reason"`
        CreatedAt           time.Time `json:"created_at"`
    }

    events := []EventLog{}
    for rows.Next() {
        var el EventLog
        var keywords []string
        if err := rows.Scan(&el.ID, &el.DeviceID, &el.EventType, &el.FilePath, &el.FileName, &el.FileSize, &el.FileExtension, &el.SourceLocation, &el.DestinationLocation, &el.Classification, &el.RiskLevel, pq.Array(&keywords), &el.ProcessName, &el.Username, &el.OperationResult, &el.WasBlocked, &el.BlockReason, &el.CreatedAt); err != nil {
            continue
        }
        el.KeywordsFound = keywords
        events = append(events, el)
    }

    resp := map[string]interface{}{"events": events, "total": len(events), "limit": limit, "offset": offset}
    w.Header().Set("Content-Type", "application/json")
    json.NewEncoder(w).Encode(resp)
}

// GET /api/v1/incidents
func (h *EventsHandler) ListIncidents(w http.ResponseWriter, r *http.Request) {
    status := r.URL.Query().Get("status")
    severity := r.URL.Query().Get("severity")
    limit := 50
    offset := 0

    query := `SELECT id, device_id, event_id, incident_type, severity, description, status, rule_name, rule_triggered_reason, file_involved, user_involved, action_taken, created_at, updated_at, resolved_at FROM incidents WHERE 1=1`
    args := []interface{}{}
    idx := 1
    if status != "" {
        query += " AND status = $" + itoa(idx)
        args = append(args, status)
        idx++
    }
    if severity != "" {
        query += " AND severity = $" + itoa(idx)
        args = append(args, severity)
        idx++
    }

    query += " ORDER BY created_at DESC LIMIT $" + itoa(idx) + " OFFSET $" + itoa(idx+1)
    args = append(args, limit, offset)

    rows, err := h.db.Query(query, args...)
    if err != nil {
        http.Error(w, "database error", http.StatusInternalServerError)
        return
    }
    defer rows.Close()

    type Incident struct {
        ID                  string     `json:"id"`
        DeviceID            string     `json:"device_id"`
        EventID             string     `json:"event_id"`
        IncidentType        string     `json:"incident_type"`
        Severity            string     `json:"severity"`
        Description         string     `json:"description"`
        Status              string     `json:"status"`
        RuleName            string     `json:"rule_name"`
        RuleTriggeredReason string     `json:"rule_triggered_reason"`
        FileInvolved        string     `json:"file_involved"`
        UserInvolved        string     `json:"user_involved"`
        ActionTaken         string     `json:"action_taken"`
        CreatedAt           time.Time  `json:"created_at"`
        UpdatedAt           time.Time  `json:"updated_at"`
        ResolvedAt          *time.Time `json:"resolved_at"`
    }

    incidents := []Incident{}
    for rows.Next() {
        var i Incident
        if err := rows.Scan(&i.ID, &i.DeviceID, &i.EventID, &i.IncidentType, &i.Severity, &i.Description, &i.Status, &i.RuleName, &i.RuleTriggeredReason, &i.FileInvolved, &i.UserInvolved, &i.ActionTaken, &i.CreatedAt, &i.UpdatedAt, &i.ResolvedAt); err != nil {
            continue
        }
        incidents = append(incidents, i)
    }

    resp := map[string]interface{}{"incidents": incidents, "total": len(incidents), "limit": limit, "offset": offset}
    w.Header().Set("Content-Type", "application/json")
    json.NewEncoder(w).Encode(resp)
}

// PUT /api/v1/incidents/:id/resolve
func (h *EventsHandler) ResolveIncident(w http.ResponseWriter, r *http.Request) {
    // Extract id from path: /api/v1/incidents/{id}/resolve
    parts := splitPath(r.URL.Path)
    if len(parts) < 4 {
        http.Error(w, "invalid path", http.StatusBadRequest)
        return
    }
    incidentID := parts[3]

    query := `UPDATE incidents SET status = 'RESOLVED', resolved_at = NOW(), updated_at = NOW() WHERE id = $1`
    res, err := h.db.Exec(query, incidentID)
    if err != nil {
        http.Error(w, "failed to resolve incident", http.StatusInternalServerError)
        return
    }
    ra, _ := res.RowsAffected()
    if ra == 0 {
        http.Error(w, "incident not found", http.StatusNotFound)
        return
    }
    w.Header().Set("Content-Type", "application/json")
    json.NewEncoder(w).Encode(map[string]string{"message": "incident resolved"})
}

// Helper: Check DLP Rules and create incidents
func (h *EventsHandler) checkDLPRules(eventID string, deviceID string, event *FileEvent) []string {
    ids := []string{}
    rows, err := h.db.Query(`SELECT id, name, conditions, action, severity FROM dlp_rules WHERE enabled = true`)
    if err != nil {
        log.Printf("[ERROR] Failed to query DLP rules: %v", err)
        return ids
    }
    defer rows.Close()

    for rows.Next() {
        var ruleID, ruleName, conditionsJSON, action, severity string
        if err := rows.Scan(&ruleID, &ruleName, &conditionsJSON, &action, &severity); err != nil {
            continue
        }
        if h.doesRuleMatch(conditionsJSON, event) {
            incID := h.createIncident(deviceID, eventID, ruleName, severity, event, action)
            if incID != "" {
                ids = append(ids, incID)
            }
            log.Printf("[INCIDENT] Rule triggered: %s | Severity: %s | File: %s", ruleName, severity, event.FileName)
        }
    }
    return ids
}

// Helper: simple rule matching (JSON conditions)
func (h *EventsHandler) doesRuleMatch(conditionsJSON string, event *FileEvent) bool {
    var cond map[string]interface{}
    if err := json.Unmarshal([]byte(conditionsJSON), &cond); err != nil {
        return false
    }

    // event_type
    if v, ok := cond["event_type"]; ok {
        switch vv := v.(type) {
        case string:
            if vv != event.EventType { return false }
        case []interface{}:
            match := false
            for _, el := range vv {
                if s, ok := el.(string); ok && s == event.EventType { match = true; break }
            }
            if !match { return false }
        }
    }

    if v, ok := cond["classification"]; ok {
        if arr, ok := v.([]interface{}); ok {
            match := false
            for _, el := range arr {
                if s, ok := el.(string); ok && s == event.Classification { match = true; break }
            }
            if !match { return false }
        }
    }

    if v, ok := cond["risk_level"]; ok {
        if arr, ok := v.([]interface{}); ok {
            match := false
            for _, el := range arr {
                if s, ok := el.(string); ok && s == event.RiskLevel { match = true; break }
            }
            if !match { return false }
        }
    }

    if v, ok := cond["file_extension"]; ok {
        if arr, ok := v.([]interface{}); ok {
            match := false
            for _, el := range arr {
                if s, ok := el.(string); ok && s == event.FileExtension { match = true; break }
            }
            if !match { return false }
        }
    }

    if v, ok := cond["keywords_found"]; ok {
        if arr, ok := v.([]interface{}); ok {
            for _, want := range arr {
                if ws, ok := want.(string); ok {
                    for _, found := range event.KeywordsFound {
                        if ws == found { return true }
                    }
                }
            }
            return false
        }
    }

    return true
}

// Helper: create incident record
func (h *EventsHandler) createIncident(deviceID, eventID, ruleName, severity string, event *FileEvent, action string) string {
    // incidents.id is BIGSERIAL: never insert a UUID into it. Let the database
    // assign the id and return it so incidents are actually persisted.
    insert := `INSERT INTO incidents (device_id, event_id, incident_type, severity, description, status, rule_name, rule_triggered_reason, file_involved, user_involved, action_taken, created_at, updated_at) VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12,$13) RETURNING id::text`
    desc := "DLP rule triggered: " + ruleName
    reason := "File operation matches DLP rule conditions"
    actionTaken := action
    var id string
    err := h.db.QueryRow(insert, deviceID, eventID, "DLP_VIOLATION", severity, desc, "OPEN", ruleName, reason, event.FilePath, event.Username, actionTaken, time.Now(), time.Now()).Scan(&id)
    if err != nil {
        log.Printf("[ERROR] Failed to create incident: %v", err)
        return ""
    }
    return id
}

// Small helpers
func itoa(i int) string { return fmt.Sprintf("%d", i) }
func splitPath(p string) []string {
    parts := []string{}
    for _, seg := range strings.Split(p, "/") {
        if seg != "" { parts = append(parts, seg) }
    }
    return parts
}
