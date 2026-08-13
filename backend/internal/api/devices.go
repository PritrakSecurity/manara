package api

import (
	"database/sql"
	"encoding/json"
	"fmt"
	"log"
	"net"
	"net/http"
	"strings"
	"sync"
	"time"

	"github.com/google/uuid"
)

// Device represents a registered device
type Device struct {
	ID                 string    `json:"id"`
	Hostname           string    `json:"hostname"`
	IPAddress          string    `json:"ipAddress"`
	OSVersion          string    `json:"osVersion"`
	AgentVersion       string    `json:"agentVersion"`
	Status             string    `json:"status"` // online, offline, warning
	LastSeen           time.Time `json:"lastSeen"`
	RegisteredAt       time.Time `json:"registeredAt"`
	CPUUsage           float64   `json:"cpuUsage"`
	MemoryUsage        float64   `json:"memoryUsage"`
	DiskUsage          float64   `json:"diskUsage"`
	RegistrationMethod string    `json:"registrationMethod"`
}

// DeviceManager manages device registration and heartbeat
type DeviceManager struct {
	devices map[string]*Device
	mu      sync.RWMutex
	db      *sql.DB
}

var deviceManager *DeviceManager

// Heartbeat durations (can be overridden by server on startup)
var (
	// Warning after 90s without a heartbeat (3 missed beats @ 30s interval).
	HeartbeatWarningDuration = 90 * time.Second
	// Offline after 300s (5 minutes) without a heartbeat.
	HeartbeatOfflineDuration = 5 * time.Minute
)

// IPReclaimWindow is how long a device must be silent before its IP address
// is considered free to be reclaimed by a different hostname.
const IPReclaimWindow = 2 * time.Minute

// InitDeviceManager initializes the device manager and creates the devices table
func InitDeviceManager(db *sql.DB) {
	deviceManager = &DeviceManager{
		devices: make(map[string]*Device),
		db:      db,
	}

	// Create devices table if database is available
	if db != nil {
		if err := deviceManager.createDevicesTable(); err != nil {
			log.Printf("⚠️  Failed to create devices table: %v", err)
		} else {
			log.Println("✅ Devices table ready")
		}

		// Load existing devices from database
		if err := deviceManager.loadDevicesFromDB(); err != nil {
			log.Printf("⚠️  Failed to load devices from database: %v", err)
		}
	} else {
		log.Println("⚠️  Device manager running without database (in-memory only)")
	}

	// Start background goroutine to update device statuses
	go deviceManager.statusUpdater()

	log.Println("✅ Device manager initialized")
}

// createDevicesTable creates the devices table in the database
func (dm *DeviceManager) createDevicesTable() error {
	query := `
	CREATE TABLE IF NOT EXISTS devices (
		id VARCHAR(255) PRIMARY KEY,
		hostname VARCHAR(255) NOT NULL,
		ip_address VARCHAR(45) NOT NULL,
		os_version VARCHAR(255),
		agent_version VARCHAR(50),
		status VARCHAR(20) DEFAULT 'offline',
		last_seen TIMESTAMP,
		registered_at TIMESTAMP NOT NULL,
		cpu_usage DOUBLE PRECISION DEFAULT 0,
		memory_usage DOUBLE PRECISION DEFAULT 0,
		disk_usage DOUBLE PRECISION DEFAULT 0,
		registration_method VARCHAR(50) DEFAULT 'manual',
		created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
		updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
	);

	CREATE INDEX IF NOT EXISTS idx_devices_hostname ON devices(hostname);
	CREATE INDEX IF NOT EXISTS idx_devices_status ON devices(status);
	CREATE INDEX IF NOT EXISTS idx_devices_last_seen ON devices(last_seen);
	`

	_, err := dm.db.Exec(query)
	return err
}

// loadDevicesFromDB loads all devices from the database into memory
func (dm *DeviceManager) loadDevicesFromDB() error {
	dm.mu.Lock()
	defer dm.mu.Unlock()

	query := `
		SELECT id, hostname, ip_address, os_version, agent_version, status, 
		       last_seen, registered_at, cpu_usage, memory_usage, disk_usage, registration_method
		FROM devices
	`

	rows, err := dm.db.Query(query)
	if err != nil {
		return err
	}
	defer rows.Close()

	loadedCount := 0
	for rows.Next() {
		var device Device
		var lastSeen, registeredAt sql.NullTime

		err := rows.Scan(
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
		if err != nil {
			log.Printf("⚠️  Failed to scan device row: %v", err)
			continue
		}

		if lastSeen.Valid {
			device.LastSeen = lastSeen.Time
		}
		if registeredAt.Valid {
			device.RegisteredAt = registeredAt.Time
		}

		dm.devices[device.ID] = &device
		loadedCount++
	}

	log.Printf("✅ Loaded %d devices from database", loadedCount)
	return nil
}

// RegisterDevice registers a new device or updates an existing one
func (dm *DeviceManager) RegisterDevice(hostname, ipAddress, osVersion, agentVersion, registrationMethod string) (*Device, error) {
	dm.mu.Lock()
	defer dm.mu.Unlock()

	// Check if device already exists by hostname
	var existingDevice *Device
	for _, d := range dm.devices {
		if d.Hostname == hostname {
			existingDevice = d
			break
		}
	}

	now := time.Now()
	var device *Device

	if existingDevice != nil {
		// Update existing device
		device = existingDevice
		device.IPAddress = ipAddress
		device.OSVersion = osVersion
		device.AgentVersion = agentVersion
		device.LastSeen = now
		device.Status = "online"
		if registrationMethod != "" {
			device.RegistrationMethod = registrationMethod
		}
	} else {
		// No device with this hostname yet. Before creating a brand new record,
		// check whether this IP belongs to a stale device (no heartbeat in the
		// last IPReclaimWindow). If it does, reclaim that record for the new
		// hostname instead of creating a duplicate with the same IP.
		var staleByIP *Device
		for _, d := range dm.devices {
			if d.IPAddress != "" && d.IPAddress == ipAddress && time.Since(d.LastSeen) > IPReclaimWindow {
				staleByIP = d
				break
			}
		}
		if staleByIP != nil {
			log.Printf("♻️  Reclaiming stale IP %s: hostname %s -> %s", ipAddress, staleByIP.Hostname, hostname)
			existingDevice = staleByIP
			device = existingDevice
			device.Hostname = hostname
			device.IPAddress = ipAddress
			device.OSVersion = osVersion
			device.AgentVersion = agentVersion
			device.LastSeen = now
			device.Status = "online"
			if registrationMethod != "" {
				device.RegistrationMethod = registrationMethod
			}
		} else {
			// Create new device
			device = &Device{
				ID:                 uuid.New().String(),
				Hostname:           hostname,
				IPAddress:          ipAddress,
				OSVersion:          osVersion,
				AgentVersion:       agentVersion,
				Status:             "online",
				LastSeen:           now,
				RegisteredAt:       now,
				RegistrationMethod: registrationMethod,
			}
			dm.devices[device.ID] = device
		}
	}

	// Persist to database if available
	if dm.db != nil {
		if existingDevice != nil {
			query := `
				UPDATE devices 
				SET hostname = $1, ip_address = $2, os_version = $3, agent_version = $4,
				    status = $5, last_seen = $6, updated_at = CURRENT_TIMESTAMP,
				    registration_method = $7
				WHERE id = $8
			`
			_, err := dm.db.Exec(query,
				device.Hostname, device.IPAddress, device.OSVersion, device.AgentVersion,
				device.Status, device.LastSeen, device.RegistrationMethod, device.ID)
			if err != nil {
				log.Printf("⚠️  Failed to update device in database: %v", err)
			}
		} else {
			query := `
				INSERT INTO devices (id, hostname, ip_address, os_version, agent_version, 
				                     status, last_seen, registered_at, registration_method)
				VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9)
			`
			_, err := dm.db.Exec(query,
				device.ID, device.Hostname, device.IPAddress, device.OSVersion, device.AgentVersion,
				device.Status, device.LastSeen, device.RegisteredAt, device.RegistrationMethod)
			if err != nil {
				log.Printf("⚠️  Failed to insert device into database: %v", err)
			}
		}
	}

	return device, nil
}

// UpdateHeartbeat updates the heartbeat and metrics for a device
func (dm *DeviceManager) UpdateHeartbeat(deviceID, hostname, ipAddress string, cpuUsage, memoryUsage, diskUsage float64) error {
	dm.mu.Lock()
	defer dm.mu.Unlock()

	// Find device by hostname
	var device *Device
	// Prefer lookup by device ID if provided
	if deviceID != "" {
		if d, ok := dm.devices[deviceID]; ok {
			device = d
		}
	}
	if device == nil && hostname != "" {
		for _, d := range dm.devices {
			if d.Hostname == hostname {
				device = d
				break
			}
		}
	}

	if device == nil {
		return fmt.Errorf("device not found: %s", hostname)
	}

	// Update device
	now := time.Now()
	device.LastSeen = now
	device.Status = "online"
	device.IPAddress = ipAddress
	device.CPUUsage = cpuUsage
	device.MemoryUsage = memoryUsage
	device.DiskUsage = diskUsage

	// Update in database
	if dm.db != nil {
		query := `
			UPDATE devices 
			SET last_seen = $1, status = $2, ip_address = $3, 
				cpu_usage = $4, memory_usage = $5, disk_usage = $6,
				updated_at = CURRENT_TIMESTAMP
			WHERE id = $7
		`
		_, err := dm.db.Exec(query,
			device.LastSeen, device.Status, device.IPAddress,
			device.CPUUsage, device.MemoryUsage, device.DiskUsage, device.ID)
		if err != nil {
			return fmt.Errorf("failed to update heartbeat in database: %w", err)
		}
	}

	return nil
}

// ListDevices returns all registered devices
func (dm *DeviceManager) ListDevices() []Device {
	dm.mu.RLock()
	defer dm.mu.RUnlock()

	devices := make([]Device, 0, len(dm.devices))
	for _, d := range dm.devices {
		devices = append(devices, *d)
	}

	return devices
}

// GetDeviceByID returns a copy of a registered device, or false if not found.
func (dm *DeviceManager) GetDeviceByID(id string) (Device, bool) {
	dm.mu.RLock()
	defer dm.mu.RUnlock()

	d, ok := dm.devices[id]
	if !ok {
		return Device{}, false
	}
	return *d, true
}

// statusUpdater runs in background and updates device statuses based on last seen time
func (dm *DeviceManager) statusUpdater() {
	ticker := time.NewTicker(30 * time.Second)
	defer ticker.Stop()

	for range ticker.C {
		dm.mu.Lock()
		now := time.Now()

		for _, device := range dm.devices {
			timeSinceLastSeen := now.Sub(device.LastSeen)

			if timeSinceLastSeen > HeartbeatOfflineDuration {
				// Mark as offline if no heartbeat for configured offline duration
				if device.Status != "offline" {
					device.Status = "offline"
					if dm.db != nil {
						_, err := dm.db.Exec("UPDATE devices SET status = $1, updated_at = CURRENT_TIMESTAMP WHERE id = $2",
							device.Status, device.ID)
						if err != nil {
							log.Printf("⚠️  Failed to update device status: %v", err)
						}
					}
				}
			} else if timeSinceLastSeen > HeartbeatWarningDuration {
				// Mark as warning if no heartbeat for configured warning duration
				if device.Status == "online" {
					device.Status = "warning"
					if dm.db != nil {
						_, err := dm.db.Exec("UPDATE devices SET status = $1, updated_at = CURRENT_TIMESTAMP WHERE id = $2",
							device.Status, device.ID)
						if err != nil {
							log.Printf("⚠️  Failed to update device status: %v", err)
						}
					}
				}
			}
		}

		dm.mu.Unlock()
	}
}

// HandleDeviceRegistration handles POST /api/devices/register
func HandleDeviceRegistration(w http.ResponseWriter, r *http.Request) {
	if deviceManager == nil {
		http.Error(w, "Device manager not initialized", http.StatusInternalServerError)
		return
	}

	var req struct {
		Hostname            string `json:"hostname"`
		Hostname_           string `json:"hostname_"` // snake_case support
		IPAddress           string `json:"ipAddress"`
		IP_Address          string `json:"ip_address"` // snake_case support
		OSVersion           string `json:"osVersion"`
		OS_Version          string `json:"os_version"` // snake_case support
		AgentVersion        string `json:"agentVersion"`
		Agent_Version       string `json:"agent_version"` // snake_case support
		RegistrationMethod  string `json:"registrationMethod"`
		Registration_Method string `json:"registration_method"` // snake_case support
		InstalledAt         string `json:"installedAt"`
	}

	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		log.Printf("❌ Failed to decode registration request: %v", err)
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}

	// Normalize field names (support both camelCase and snake_case)
	if req.Hostname_ != "" {
		req.Hostname = req.Hostname_
	}
	if req.IP_Address != "" {
		req.IPAddress = req.IP_Address
	}
	if req.OS_Version != "" {
		req.OSVersion = req.OS_Version
	}
	if req.Agent_Version != "" {
		req.AgentVersion = req.Agent_Version
	}
	if req.Registration_Method != "" {
		req.RegistrationMethod = req.Registration_Method
	}

	// Validate required fields - never accept devices without a valid hostname.
	if req.Hostname == "" || strings.EqualFold(req.Hostname, "unknown") {
		http.Error(w, "A valid hostname is required", http.StatusBadRequest)
		return
	}

	// Set defaults
	if req.OSVersion == "" {
		req.OSVersion = "Unknown"
	}
	if req.AgentVersion == "" {
		req.AgentVersion = "1.2.5"
	}
	if req.IPAddress == "" || req.IPAddress == "unknown" {
		req.IPAddress = "0.0.0.0"
	}
	if req.RegistrationMethod == "" {
		req.RegistrationMethod = "manual"
	}

	log.Printf("📝 DEVICE REGISTRATION REQUEST")
	log.Printf("   Hostname: %s", req.Hostname)
	log.Printf("   IP: %s", req.IPAddress)
	log.Printf("   OS: %s", req.OSVersion)
	log.Printf("   Agent: %s", req.AgentVersion)

	device, err := deviceManager.RegisterDevice(
		req.Hostname,
		req.IPAddress,
		req.OSVersion,
		req.AgentVersion,
		req.RegistrationMethod,
	)

	if err != nil {
		log.Printf("❌ Registration failed: %v", err)
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}

	log.Printf("✅ REGISTRATION SUCCESSFUL (ID: %s)", device.ID)
	log.Printf("   Total devices: %d", len(deviceManager.devices))

	response := map[string]interface{}{
		"success":            true,
		"message":            "Device registered successfully",
		"deviceId":           device.ID,
		"device_id":          device.ID,
		"hostname":           device.Hostname,
		"status":             device.Status,
		"registered_at":      device.RegisteredAt.Format(time.RFC3339),
		"registeredAt":       device.RegisteredAt.Format(time.RFC3339),
		"agentVersion":       device.AgentVersion,
		"registrationMethod": device.RegistrationMethod,
	}

	// Issue a short-lived device bearer token so the agent can authenticate
	// subsequent API calls (e.g. event uploads) after enrollment.
	if token, err := generateToken(device.ID, device.Hostname, device.Hostname, "device"); err != nil {
		log.Printf("⚠️  Failed to generate device token: %v", err)
	} else {
		response["token"] = token
		response["deviceToken"] = token
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(response)
}

// HandleListDevices handles GET /api/devices
func HandleListDevices(w http.ResponseWriter, r *http.Request) {
	if deviceManager == nil {
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode([]interface{}{})
		return
	}

	devices := deviceManager.ListDevices()

	// Convert to API format
	apiDevices := make([]map[string]interface{}, len(devices))
	for i, d := range devices {
		apiDevices[i] = map[string]interface{}{
			"id":                 d.ID,
			"hostname":           d.Hostname,
			"ipAddress":          d.IPAddress,
			"osVersion":          d.OSVersion,
			"agentVersion":       d.AgentVersion,
			"status":             d.Status,
			"lastSeen":           d.LastSeen.Format(time.RFC3339),
			"registeredAt":       d.RegisteredAt.Format(time.RFC3339),
			"cpuUsage":           d.CPUUsage,
			"memoryUsage":        d.MemoryUsage,
			"diskUsage":          d.DiskUsage,
			"registrationMethod": d.RegistrationMethod,
		}
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(apiDevices)
}

// HandleDeviceHeartbeat handles POST /api/devices/heartbeat
func HandleDeviceHeartbeat(w http.ResponseWriter, r *http.Request) {
	if deviceManager == nil {
		http.Error(w, "Device manager not initialized", http.StatusInternalServerError)
		return
	}
	var req struct {
		DeviceID      string      `json:"device_id"`
		Hostname      string      `json:"hostname"`
		Hostname_     string      `json:"hostname_"`
		IPAddress     interface{} `json:"ipAddress"`
		IP_Address    interface{} `json:"ip_address"`
		OSVersion     string      `json:"osVersion"`
		OS_Version    string      `json:"os_version"`
		AgentVersion  string      `json:"agentVersion"`
		Agent_Version string      `json:"agent_version"`
		Timestamp     string      `json:"timestamp"`
		CPUUsage      float64     `json:"cpuUsage"`
		Cpu_Usage     float64     `json:"cpu_usage"`
		MemoryUsage   float64     `json:"memoryUsage"`
		Memory_Usage  float64     `json:"memory_usage"`
		DiskUsage     float64     `json:"diskUsage"`
		Disk_Usage    float64     `json:"disk_usage"`
	}

	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		log.Printf("❌ Failed to decode heartbeat request: %v", err)
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}

	// Normalize field names
	if req.Hostname_ != "" {
		req.Hostname = req.Hostname_
	}
	// Normalize IP address (string or array)
	normalizeIP := func(v interface{}) string {
		switch t := v.(type) {
		case string:
			return t
		case []interface{}:
			if len(t) > 0 {
				if s, ok := t[0].(string); ok {
					return s
				}
			}
		}
		return ""
	}
	ipAddress := normalizeIP(req.IPAddress)
	if ipAddress == "" {
		ipAddress = normalizeIP(req.IP_Address)
	}
	if req.OS_Version != "" {
		req.OSVersion = req.OS_Version
	}
	if req.Agent_Version != "" {
		req.AgentVersion = req.Agent_Version
	}
	if req.Cpu_Usage > 0 {
		req.CPUUsage = req.Cpu_Usage
	}
	if req.Memory_Usage > 0 {
		req.MemoryUsage = req.Memory_Usage
	}
	if req.Disk_Usage > 0 {
		req.DiskUsage = req.Disk_Usage
	}

	if req.Hostname == "" || strings.EqualFold(req.Hostname, "unknown") {
		http.Error(w, "A valid hostname is required", http.StatusBadRequest)
		return
	}

	// Use the normalized ipAddress
	if ipAddress == "" {
		// Try to extract IP from the request
		if remoteAddr := r.RemoteAddr; remoteAddr != "" {
			if host, _, err := net.SplitHostPort(remoteAddr); err == nil {
				if host != "" && host != "127.0.0.1" && host != "::1" {
					ipAddress = host
				}
			}
		}
		if ipAddress == "" {
			ipAddress = "0.0.0.0"
		}
	}

	// Ensure device exists in memory, then update metrics
	if deviceManager != nil {
		if err := deviceManager.UpdateHeartbeat(req.DeviceID, req.Hostname, ipAddress, req.CPUUsage, req.MemoryUsage, req.DiskUsage); err != nil {
			// If device wasn't found (e.g., first heartbeat), register then update
			_, _ = deviceManager.RegisterDevice(req.Hostname, ipAddress, req.OSVersion, req.AgentVersion, "heartbeat")
			_ = deviceManager.UpdateHeartbeat(req.DeviceID, req.Hostname, ipAddress, req.CPUUsage, req.MemoryUsage, req.DiskUsage)
		}
	}

	now := time.Now()

	// Persist a transactional update to database and write audit log (when DB is available)
	if deviceManager != nil && deviceManager.db != nil {
		tx, err := deviceManager.db.Begin()
		if err == nil {
			// Try update by device id first
			var rowsAffected int64 = 0
			if req.DeviceID != "" {
				res, err := tx.Exec(`
					UPDATE devices SET last_seen = $1, status = $2, ip_address = $3, os_version = $4, agent_version = $5,
						cpu_usage = $6, memory_usage = $7, disk_usage = $8, updated_at = CURRENT_TIMESTAMP
					WHERE id = $9
				`, now, "online", ipAddress, req.OSVersion, req.AgentVersion, req.CPUUsage, req.MemoryUsage, req.DiskUsage, req.DeviceID)
				if err == nil {
					if ra, _ := res.RowsAffected(); ra > 0 {
						rowsAffected = ra
					}
				}
			}

			// Fallback: update by hostname if id update didn't affect rows
			if rowsAffected == 0 && req.Hostname != "" {
				res, err := tx.Exec(`
					UPDATE devices SET last_seen = $1, status = $2, ip_address = $3, os_version = $4, agent_version = $5,
						cpu_usage = $6, memory_usage = $7, disk_usage = $8, updated_at = CURRENT_TIMESTAMP
					WHERE hostname = $9
				`, now, "online", ipAddress, req.OSVersion, req.AgentVersion, req.CPUUsage, req.MemoryUsage, req.DiskUsage, req.Hostname)
				if err == nil {
					if ra, _ := res.RowsAffected(); ra > 0 {
						rowsAffected = ra
					}
				}
			}

			// If still not updated, attempt to insert (register device)
			if rowsAffected == 0 {
				devID := req.DeviceID
				if devID == "" {
					devID = uuid.New().String()
				}
				_, _ = tx.Exec(`INSERT INTO devices (id, hostname, ip_address, os_version, agent_version, status, last_seen, registered_at, registration_method)
					VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9)
					ON CONFLICT (id) DO NOTHING`, devID, req.Hostname, ipAddress, req.OSVersion, req.AgentVersion, "online", now, now, "heartbeat")
			}

			// Insert audit log
			_, _ = tx.Exec(`INSERT INTO audit_logs (event_type, details, device_id, hostname, ip_address, agent_version, occurred_at)
				VALUES ($1,$2,$3,$4,$5,$6,$7)`, "heartbeat", "Heartbeat received", sql.NullString{String: req.DeviceID, Valid: req.DeviceID != ""}, req.Hostname, ipAddress, req.AgentVersion, now)

			tx.Commit()
		}
	}

	log.Printf("💓 Heartbeat: %s (ID: %s, IP: %s, CPU: %.1f%%, Mem: %.1f%%, Disk: %.1f%%)",
		req.Hostname, req.DeviceID, ipAddress, req.CPUUsage, req.MemoryUsage, req.DiskUsage)

	response := map[string]interface{}{
		"success": true,
		"message": "Heartbeat received",
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(response)
}

// HandleDeleteAllDevices handles DELETE /api/devices (clears all devices)
func HandleDeleteAllDevices(w http.ResponseWriter, r *http.Request) {
	if deviceManager == nil {
		http.Error(w, "Device manager not initialized", http.StatusInternalServerError)
		return
	}

	deviceManager.mu.Lock()
	defer deviceManager.mu.Unlock()

	count := len(deviceManager.devices)

	// Clear from memory
	deviceManager.devices = make(map[string]*Device)

	// Clear from database
	if deviceManager.db != nil {
		_, err := deviceManager.db.Exec("DELETE FROM devices")
		if err != nil {
			log.Printf("⚠️  Failed to delete devices from database: %v", err)
			http.Error(w, "Failed to delete devices from database", http.StatusInternalServerError)
			return
		}
	}

	log.Printf("🗑️  Deleted all %d devices", count)

	response := map[string]interface{}{
		"success": true,
		"message": fmt.Sprintf("Deleted %d device(s)", count),
		"deleted": count,
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(response)
}
