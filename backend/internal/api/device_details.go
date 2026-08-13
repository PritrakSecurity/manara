package api

import (
	"database/sql"
	"encoding/csv"
	"encoding/json"
	"fmt"
	"log"
	"net/http"
	"strings"
	"time"
)

// DeviceDetails represents detailed information about a device
type DeviceDetails struct {
	Device
	Logs          []DeviceLog `json:"logs,omitempty"`
	RecentEvents  int         `json:"recentEvents"`
	TotalLogs     int         `json:"totalLogs"`
	UptimePercent float64     `json:"uptimePercent"`
}

// DeviceLog represents a log entry for a device
type DeviceLog struct {
	ID        int64     `json:"id"`
	DeviceID  string    `json:"device_id"`
	LogLevel  string    `json:"log_level"`
	Category  string    `json:"category"`
	Message   string    `json:"message"`
	Details   string    `json:"details,omitempty"`
	Timestamp time.Time `json:"timestamp"`
	CreatedAt time.Time `json:"created_at"`
}

// HandleGetDeviceDetails handles GET /api/devices/:id
func HandleGetDeviceDetails(w http.ResponseWriter, r *http.Request) {
	if deviceManager == nil {
		http.Error(w, "Device manager not initialized", http.StatusServiceUnavailable)
		return
	}

	// Extract device ID from URL path
	parts := strings.Split(r.URL.Path, "/")
	if len(parts) < 4 {
		http.Error(w, "Invalid device ID", http.StatusBadRequest)
		return
	}
	deviceID := parts[3]

	var device Device
	if deviceManager.db != nil {
		// Get device from database
		var lastSeen, registeredAt sql.NullTime
		err := deviceManager.db.QueryRow(`
			SELECT id, hostname, ip_address, os_version, agent_version, status, 
			       last_seen, registered_at, cpu_usage, memory_usage, disk_usage, registration_method
			FROM devices
			WHERE id = $1
		`, deviceID).Scan(
			&device.ID,
			&device.Hostname,
			&device.IPAddress,
			&device.OSVersion,
			&device.AgentVersion,
			&device.Status,
			&lastSeen,
			&registeredAt,
			&device.CPUUsage,
			&device.MemoryUsage,
			&device.DiskUsage,
			&device.RegistrationMethod,
		)

		if err == sql.ErrNoRows {
			http.Error(w, "Device not found", http.StatusNotFound)
			return
		}
		if err != nil {
			log.Printf("❌ Error fetching device details: %v", err)
			http.Error(w, "Internal server error", http.StatusInternalServerError)
			return
		}

		if lastSeen.Valid {
			device.LastSeen = lastSeen.Time
		}
		if registeredAt.Valid {
			device.RegisteredAt = registeredAt.Time
		}
	} else {
		// In-memory fallback (development mode, no database).
		d, ok := deviceManager.GetDeviceByID(deviceID)
		if !ok {
			http.Error(w, "Device not found", http.StatusNotFound)
			return
		}
		device = d
	}

	// Logs require a database; in-memory mode returns empty.
	logs := []DeviceLog{}
	totalLogs := 0
	if deviceManager.db != nil {
		var err error
		logs, err = getDeviceLogs(deviceManager.db, deviceID, 10)
		if err != nil {
			log.Printf("⚠️  Warning: Failed to fetch device logs: %v", err)
			logs = []DeviceLog{}
		}

		_ = deviceManager.db.QueryRow(`SELECT COUNT(*) FROM device_logs WHERE device_id = $1`, deviceID).Scan(&totalLogs)
	}

	// Calculate uptime percentage (simple version - devices online in last 24h)
	var uptimePercent float64 = 0.0
	if device.Status == "online" {
		uptimePercent = 100.0
	} else if device.Status == "warning" {
		uptimePercent = 75.0
	} else {
		uptimePercent = 0.0
	}

	details := DeviceDetails{
		Device:        device,
		Logs:          logs,
		RecentEvents:  len(logs),
		TotalLogs:     totalLogs,
		UptimePercent: uptimePercent,
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(details)
}

// HandleGetDeviceLogs handles GET /api/devices/:id/logs
func HandleGetDeviceLogs(w http.ResponseWriter, r *http.Request) {
	if deviceManager == nil || deviceManager.db == nil {
		http.Error(w, "Device manager or database not initialized", http.StatusServiceUnavailable)
		return
	}

	// Extract device ID from URL path
	parts := strings.Split(r.URL.Path, "/")
	if len(parts) < 4 {
		http.Error(w, "Invalid device ID", http.StatusBadRequest)
		return
	}
	deviceID := parts[3]

	// Get limit from query params (default 100)
	limit := 100
	if limitStr := r.URL.Query().Get("limit"); limitStr != "" {
		fmt.Sscanf(limitStr, "%d", &limit)
	}

	logs, err := getDeviceLogs(deviceManager.db, deviceID, limit)
	if err != nil {
		log.Printf("❌ Error fetching device logs: %v", err)
		http.Error(w, "Internal server error", http.StatusInternalServerError)
		return
	}

	response := map[string]interface{}{
		"status": "success",
		"data":   logs,
		"count":  len(logs),
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(response)
}

// HandleDownloadDeviceLogs handles GET /api/devices/:id/logs[/download]
func HandleDownloadDeviceLogs(w http.ResponseWriter, r *http.Request) {
	if deviceManager == nil {
		http.Error(w, "Device manager not initialized", http.StatusServiceUnavailable)
		return
	}

	// Extract device ID from URL path
	parts := strings.Split(r.URL.Path, "/")
	if len(parts) < 4 {
		http.Error(w, "Invalid device ID", http.StatusBadRequest)
		return
	}
	deviceID := parts[3]

	// Development mode (no database): return a placeholder file so the
	// download flow works end-to-end.
	if deviceManager.db == nil {
		w.Header().Set("Content-Type", "text/plain")
		w.Header().Set("Content-Disposition", `attachment; filename="logs_placeholder.txt"`)
		w.Write([]byte("Log retrieval not fully implemented yet.\n"))
		return
	}

	// Get all logs for device
	logs, err := getDeviceLogs(deviceManager.db, deviceID, 10000) // Max 10k logs
	if err != nil {
		log.Printf("❌ Error fetching device logs: %v", err)
		http.Error(w, "Internal server error", http.StatusInternalServerError)
		return
	}

	// Set headers for CSV download
	w.Header().Set("Content-Type", "text/csv")
	w.Header().Set("Content-Disposition", fmt.Sprintf("attachment; filename=\"device-logs-%s-%s.csv\"",
		deviceID, time.Now().Format("20060102-150405")))

	// Write CSV
	writer := csv.NewWriter(w)
	defer writer.Flush()

	// Write header
	writer.Write([]string{"Timestamp", "Level", "Category", "Message", "Details"})

	// Write data
	for _, log := range logs {
		writer.Write([]string{
			log.Timestamp.Format(time.RFC3339),
			log.LogLevel,
			log.Category,
			log.Message,
			log.Details,
		})
	}

	log.Printf("📥 Downloaded %d logs for device %s", len(logs), deviceID)
}

// getDeviceLogs fetches logs for a device from the database
func getDeviceLogs(db *sql.DB, deviceID string, limit int) ([]DeviceLog, error) {
	query := `
		SELECT id, device_id, log_level, category, message, 
		       COALESCE(details::text, '') as details, timestamp, created_at
		FROM device_logs
		WHERE device_id = $1
		ORDER BY timestamp DESC
		LIMIT $2
	`

	rows, err := db.Query(query, deviceID, limit)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var logs []DeviceLog
	for rows.Next() {
		var entry DeviceLog
		err := rows.Scan(
			&entry.ID,
			&entry.DeviceID,
			&entry.LogLevel,
			&entry.Category,
			&entry.Message,
			&entry.Details,
			&entry.Timestamp,
			&entry.CreatedAt,
		)
		if err != nil {
			log.Printf("⚠️  Warning: Failed to scan log row: %v", err)
			continue
		}
		logs = append(logs, entry)
	}

	return logs, nil
}

// AddDeviceLog adds a log entry for a device
func AddDeviceLog(db *sql.DB, deviceID, level, category, message string) error {
	if db == nil {
		return fmt.Errorf("database not initialized")
	}

	_, err := db.Exec(`
		INSERT INTO device_logs (device_id, log_level, category, message, timestamp)
		VALUES ($1, $2, $3, $4, $5)
	`, deviceID, level, category, message, time.Now())

	return err
}
