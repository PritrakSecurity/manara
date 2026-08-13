package api

import (
	"database/sql"
	"encoding/json"
	"fmt"
	"net/http"
	"strconv"
	"time"
)

// DashboardHandler handles dashboard API requests
type DashboardHandler struct {
	db *sql.DB
}

// NewDashboardHandler creates a new dashboard handler
func NewDashboardHandler(db *sql.DB) *DashboardHandler {
	return &DashboardHandler{db: db}
}

// HandleStats handles GET /api/dashboard/stats
func (h *DashboardHandler) HandleStats(w http.ResponseWriter, r *http.Request) {
	stats := make(map[string]interface{})

	// Devices from device manager (in-memory, already works)
	var totalDevices, onlineDevices int
	if deviceManager != nil {
		devices := deviceManager.ListDevices()
		totalDevices = len(devices)
		for _, d := range devices {
			if d.Status == "online" {
				onlineDevices++
			}
		}
	}
	stats["endpoints"] = map[string]interface{}{
		"total":   totalDevices,
		"online":  onlineDevices,
		"offline": totalDevices - onlineDevices,
	}

	if h.db == nil {
		stats["policies"] = map[string]interface{}{"active": 0, "total": 0}
		stats["incidents"] = map[string]interface{}{"today": 0, "critical": 0, "trend": 0.0}
		stats["files_classified"] = 0
		stats["open_incidents"] = 0
		stats["pending_approvals"] = 0
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(stats)
		return
	}

	// Policies: count enabled
	var activePolicies, totalPolicies int
	h.db.QueryRow("SELECT COUNT(*) FROM policies WHERE enabled = true").Scan(&activePolicies)
	h.db.QueryRow("SELECT COUNT(*) FROM policies").Scan(&totalPolicies)
	stats["policies"] = map[string]interface{}{"active": activePolicies, "total": totalPolicies}

	// Incidents today
	var incidentsToday int
	h.db.QueryRow("SELECT COUNT(*) FROM incidents WHERE created_at >= CURRENT_DATE").Scan(&incidentsToday)

	// Critical incidents (unresolved)
	var criticalIncidents int
	h.db.QueryRow("SELECT COUNT(*) FROM incidents WHERE severity = 'CRITICAL' AND status NOT IN ('RESOLVED', 'FALSE_POSITIVE')").Scan(&criticalIncidents)

	// Open incidents
	var openIncidents int
	h.db.QueryRow("SELECT COUNT(*) FROM incidents WHERE status IN ('OPEN', 'INVESTIGATING', 'ESCALATED')").Scan(&openIncidents)

	// Incidents trend (today vs yesterday)
	var incidentsYesterday int
	h.db.QueryRow("SELECT COUNT(*) FROM incidents WHERE created_at >= CURRENT_DATE - 1 AND created_at < CURRENT_DATE").Scan(&incidentsYesterday)
	var trend float64
	if incidentsYesterday > 0 {
		trend = float64(incidentsToday-incidentsYesterday) / float64(incidentsYesterday) * 100
	}

	stats["incidents"] = map[string]interface{}{
		"today":    incidentsToday,
		"critical": criticalIncidents,
		"trend":    trend,
	}
	stats["open_incidents"] = openIncidents

	// Classified files
	var filesClassified int
	h.db.QueryRow("SELECT COUNT(*) FROM classified_files").Scan(&filesClassified)
	stats["files_classified"] = filesClassified

	// Pending approvals
	var pendingApprovals int
	h.db.QueryRow("SELECT COUNT(*) FROM approval_requests WHERE status = 'PENDING'").Scan(&pendingApprovals)
	stats["pending_approvals"] = pendingApprovals

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(stats)
}

// HandleIncidentsTrend handles GET /api/dashboard/incidents-trend
func (h *DashboardHandler) HandleIncidentsTrend(w http.ResponseWriter, r *http.Request) {
	days := 7
	if d := r.URL.Query().Get("days"); d != "" {
		if v, err := strconv.Atoi(d); err == nil && v > 0 {
			days = v
		}
	}

	w.Header().Set("Content-Type", "application/json")

	if h.db == nil {
		json.NewEncoder(w).Encode(map[string]interface{}{"trend": []map[string]interface{}{}, "days": days})
		return
	}

	rows, err := h.db.Query(`
		SELECT DATE(timestamp) as date, COUNT(*) as total,
		       SUM(CASE WHEN decision = 'BLOCK' THEN 1 ELSE 0 END) as blocked,
		       SUM(CASE WHEN decision = 'ALLOW' THEN 1 ELSE 0 END) as allowed
		FROM incidents
		WHERE timestamp >= NOW() - $1::interval
		GROUP BY DATE(timestamp)
		ORDER BY date`, fmt.Sprintf("%d days", days))
	if err != nil {
		json.NewEncoder(w).Encode(map[string]interface{}{"trend": []map[string]interface{}{}, "days": days})
		return
	}
	defer rows.Close()

	trend := []map[string]interface{}{}
	for rows.Next() {
		var date time.Time
		var total, blocked, allowed int
		if err := rows.Scan(&date, &total, &blocked, &allowed); err != nil {
			continue
		}
		trend = append(trend, map[string]interface{}{
			"date":    date.Format("2006-01-02"),
			"total":   total,
			"blocked": blocked,
			"allowed": allowed,
		})
	}

	json.NewEncoder(w).Encode(map[string]interface{}{"trend": trend, "days": days})
}

// HandleTopViolators handles GET /api/dashboard/top-violators
func (h *DashboardHandler) HandleTopViolators(w http.ResponseWriter, r *http.Request) {
	limit := 10
	if l := r.URL.Query().Get("limit"); l != "" {
		if v, err := strconv.Atoi(l); err == nil && v > 0 {
			limit = v
		}
	}

	w.Header().Set("Content-Type", "application/json")

	if h.db == nil {
		json.NewEncoder(w).Encode(map[string]interface{}{"violators": []map[string]interface{}{}})
		return
	}

	rows, err := h.db.Query(`
		SELECT username, COUNT(*) as violations,
		       SUM(CASE WHEN severity = 'CRITICAL' THEN 1 ELSE 0 END) as critical_count
		FROM incidents
		WHERE username IS NOT NULL AND username != ''
		GROUP BY username
		ORDER BY violations DESC
		LIMIT $1`, limit)
	if err != nil {
		json.NewEncoder(w).Encode(map[string]interface{}{"violators": []map[string]interface{}{}})
		return
	}
	defer rows.Close()

	violators := []map[string]interface{}{}
	for rows.Next() {
		var username string
		var violations, criticalCount int
		if err := rows.Scan(&username, &violations, &criticalCount); err != nil {
			continue
		}
		violators = append(violators, map[string]interface{}{
			"username":       username,
			"violations":     violations,
			"critical_count": criticalCount,
		})
	}

	json.NewEncoder(w).Encode(map[string]interface{}{"violators": violators})
}

// HandleTopDestinations handles GET /api/dashboard/top-destinations
func (h *DashboardHandler) HandleTopDestinations(w http.ResponseWriter, r *http.Request) {
	limit := 10
	if l := r.URL.Query().Get("limit"); l != "" {
		if v, err := strconv.Atoi(l); err == nil && v > 0 {
			limit = v
		}
	}

	w.Header().Set("Content-Type", "application/json")

	if h.db == nil {
		json.NewEncoder(w).Encode(map[string]interface{}{"destinations": []map[string]interface{}{}})
		return
	}

	rows, err := h.db.Query(`
		SELECT destination_type, COUNT(*) as count
		FROM incidents
		WHERE destination_type IS NOT NULL AND destination_type != ''
		GROUP BY destination_type
		ORDER BY count DESC
		LIMIT $1`, limit)
	if err != nil {
		json.NewEncoder(w).Encode(map[string]interface{}{"destinations": []map[string]interface{}{}})
		return
	}
	defer rows.Close()

	destinations := []map[string]interface{}{}
	for rows.Next() {
		var dest string
		var count int
		if err := rows.Scan(&dest, &count); err != nil {
			continue
		}
		destinations = append(destinations, map[string]interface{}{
			"destination": dest,
			"count":       count,
		})
	}

	json.NewEncoder(w).Encode(map[string]interface{}{"destinations": destinations})
}

// HandleClassificationDistribution handles GET /api/dashboard/classification-distribution
func (h *DashboardHandler) HandleClassificationDistribution(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json")

	if h.db == nil {
		json.NewEncoder(w).Encode(map[string]interface{}{"distribution": []map[string]interface{}{}})
		return
	}

	rows, err := h.db.Query(`
		SELECT classification, COUNT(*) as count
		FROM classified_files
		GROUP BY classification
		ORDER BY count DESC`)
	if err != nil {
		json.NewEncoder(w).Encode(map[string]interface{}{"distribution": []map[string]interface{}{}})
		return
	}
	defer rows.Close()

	distribution := []map[string]interface{}{}
	for rows.Next() {
		var classification string
		var count int
		if err := rows.Scan(&classification, &count); err != nil {
			continue
		}
		distribution = append(distribution, map[string]interface{}{
			"classification": classification,
			"count":          count,
		})
	}

	json.NewEncoder(w).Encode(map[string]interface{}{"distribution": distribution})
}

// HandleIncidentsByType handles GET /api/dashboard/incidents-by-type
func (h *DashboardHandler) HandleIncidentsByType(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json")

	if h.db == nil {
		json.NewEncoder(w).Encode(map[string]interface{}{"by_type": []map[string]interface{}{}})
		return
	}

	rows, err := h.db.Query(`
		SELECT incident_type, COUNT(*) as count
		FROM incidents
		WHERE incident_type IS NOT NULL AND incident_type != ''
		GROUP BY incident_type
		ORDER BY count DESC`)
	if err != nil {
		json.NewEncoder(w).Encode(map[string]interface{}{"by_type": []map[string]interface{}{}})
		return
	}
	defer rows.Close()

	byType := []map[string]interface{}{}
	for rows.Next() {
		var incidentType string
		var count int
		if err := rows.Scan(&incidentType, &count); err != nil {
			continue
		}
		byType = append(byType, map[string]interface{}{
			"type":  incidentType,
			"count": count,
		})
	}

	json.NewEncoder(w).Encode(map[string]interface{}{"by_type": byType})
}

// HandleRecentActivity handles GET /api/dashboard/recent-activity
func (h *DashboardHandler) HandleRecentActivity(w http.ResponseWriter, r *http.Request) {
	limit := 20
	if l := r.URL.Query().Get("limit"); l != "" {
		if v, err := strconv.Atoi(l); err == nil && v > 0 {
			limit = v
		}
	}

	w.Header().Set("Content-Type", "application/json")

	if h.db == nil {
		json.NewEncoder(w).Encode(map[string]interface{}{"activities": []map[string]interface{}{}})
		return
	}

	rows, err := h.db.Query(`
		SELECT incident_id, timestamp, severity, username, hostname,
		       file_name, action_attempted, decision, block_reason
		FROM incidents
		ORDER BY created_at DESC
		LIMIT $1`, limit)
	if err != nil {
		json.NewEncoder(w).Encode(map[string]interface{}{"activities": []map[string]interface{}{}})
		return
	}
	defer rows.Close()

	activities := []map[string]interface{}{}
	for rows.Next() {
		var incidentID, severity, username, hostname, fileName, action, decision, blockReason string
		var timestamp time.Time
		hostname = ""
		fileName = ""
		blockReason = ""
		if err := rows.Scan(&incidentID, &timestamp, &severity, &username,
			&hostname, &fileName, &action, &decision, &blockReason); err != nil {
			continue
		}
		activities = append(activities, map[string]interface{}{
			"incident_id":  incidentID,
			"timestamp":   timestamp.Format(time.RFC3339),
			"severity":    severity,
			"username":    username,
			"hostname":    hostname,
			"file_name":   fileName,
			"action":      action,
			"decision":    decision,
			"block_reason": blockReason,
		})
	}

	json.NewEncoder(w).Encode(map[string]interface{}{"activities": activities})
}