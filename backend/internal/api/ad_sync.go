package api

import (
	"database/sql"
	"encoding/json"
	"fmt"
	"log"
	"net"
	"net/http"
	"strconv"
	"strings"
	"time"

	"github.com/go-ldap/ldap/v3"
	"github.com/google/uuid"
)

// DeviceHandler handles device-related operations including AD sync
type DeviceHandler struct {
	db *sql.DB
}

// NewDeviceHandler creates a new device handler
func NewDeviceHandler(db *sql.DB) *DeviceHandler {
	return &DeviceHandler{db: db}
}

// StartADSync starts a background job to sync devices from AD
func (h *DeviceHandler) StartADSync(w http.ResponseWriter, r *http.Request) {
	var req struct {
		Server   string `json:"server"`
		Port     int    `json:"port"`
		Username string `json:"username"`
		Password string `json:"password"`
		BaseDN   string `json:"base_dn"`
	}

	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusBadRequest)
		json.NewEncoder(w).Encode(map[string]interface{}{
			"success": false,
			"message": "Invalid request",
		})
		return
	}

	// Validate
	if req.Server == "" || req.Port == 0 || req.Username == "" || req.Password == "" {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusBadRequest)
		json.NewEncoder(w).Encode(map[string]interface{}{
			"success": false,
			"message": "Missing required fields: server, port, username, password",
		})
		return
	}

	if req.BaseDN == "" {
		req.BaseDN = "CN=Computers,DC=corp,DC=local"
	}

	// If no database is configured, we can still perform a one-shot "sync" by
	// discovering devices from AD and registering them into the in-memory device manager.
	// This makes the UI's "Start Sync" button useful even in dev mode.
	if h.db == nil {
		if deviceManager == nil {
			w.Header().Set("Content-Type", "application/json")
			w.WriteHeader(http.StatusServiceUnavailable)
			json.NewEncoder(w).Encode(map[string]interface{}{
				"success": false,
				"message": "Device manager not initialized",
			})
			return
		}

		devices, err := discoverADDevicesInternal(req.Server, req.Port, req.Username, req.Password, req.BaseDN)
		if err != nil {
			w.Header().Set("Content-Type", "application/json")
			w.WriteHeader(http.StatusBadRequest)
			json.NewEncoder(w).Encode(map[string]interface{}{
				"success": false,
				"message": err.Error(),
			})
			return
		}

		added := 0
		updated := 0
		for _, d := range devices {
			// RegisterDevice upserts by hostname in memory.
			beforeCount := len(deviceManager.devices)
			_, _ = deviceManager.RegisterDevice(d.Hostname, d.IPAddress, d.OSVersion, "Not Installed", "ad_sync")
			afterCount := len(deviceManager.devices)
			if afterCount > beforeCount {
				added++
			} else {
				updated++
			}
		}

		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(map[string]interface{}{
			"success": true,
			"message": "Sync completed (in-memory mode)",
			"status":  "completed",
			"data": map[string]interface{}{
				"found":   len(devices),
				"added":   added,
				"updated": updated,
				"progress": 100,
			},
		})
		return
	}

	jobID := uuid.New().String()

	// Create sync job record
	_, err := h.db.Exec(`
		INSERT INTO sync_jobs (id, status, progress, found, added, updated, created_at, updated_at)
		VALUES ($1, 'starting', 0, 0, 0, 0, NOW(), NOW())
	`, jobID)

	if err != nil {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusInternalServerError)
		json.NewEncoder(w).Encode(map[string]interface{}{
			"success": false,
			"message": "Failed to create sync job",
		})
		return
	}

	// Start sync in background goroutine
	go h.performADSync(jobID, req.Server, req.Port, req.Username, req.Password, req.BaseDN)

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(map[string]interface{}{
		"success": true,
		"jobId":   jobID,
		"message": "Sync started",
		"status":  "syncing",
	})
}

// discoverADDevicesInternal performs an LDAP query for Windows computers and returns
// a minimal device list suitable for registration.
// This is used for "Start Sync" in DB-less mode.
func discoverADDevicesInternal(server string, port int, username, password, baseDN string) ([]Device, error) {
	addr := fmt.Sprintf("%s:%d", server, port)
	conn, err := ldap.Dial("tcp", addr)
	if err != nil {
		return nil, fmt.Errorf("failed to connect: %v", err)
	}
	defer conn.Close()

	if err := conn.Bind(username, password); err != nil {
		hint := "Try username formats: user@domain, DOMAIN\\user, or full DN"
		return nil, fmt.Errorf("failed to authenticate: %v (%s)", err, hint)
	}

	if baseDN == "" {
		baseDN = "CN=Computers,DC=corp,DC=local"
	}

	searchRequest := ldap.NewSearchRequest(
		baseDN,
		ldap.ScopeWholeSubtree,
		ldap.NeverDerefAliases,
		0,
		0,
		false,
		"(&(objectClass=computer)(operatingSystem=Windows*))",
		[]string{"cn", "dNSHostName", "operatingSystem", "ipv4Address"},
		nil,
	)

	sr, err := conn.Search(searchRequest)
	if err != nil {
		return nil, fmt.Errorf("search failed: %v", err)
	}

	devices := make([]Device, 0, len(sr.Entries))
	for _, entry := range sr.Entries {
		hostname := entry.GetAttributeValue("cn")
		if hostname == "" {
			continue
		}
		osVersion := entry.GetAttributeValue("operatingSystem")
		dnsHostName := entry.GetAttributeValue("dNSHostName")
		ipAddress := entry.GetAttributeValue("ipv4Address")

		if ipAddress == "" {
			lookupName := dnsHostName
			if lookupName == "" {
				lookupName = hostname
			}
			if lookupName != "" {
				addrs, err := net.LookupHost(lookupName)
				if err == nil {
					for _, a := range addrs {
						parsed := net.ParseIP(a)
						if parsed != nil && parsed.To4() != nil {
							ipAddress = a
							break
						}
					}
				}
			}
		}
		if ipAddress == "" {
			ipAddress = "Unknown"
		}
		if osVersion == "" {
			osVersion = "Unknown"
		}

		devices = append(devices, Device{
			Hostname:  hostname,
			IPAddress: ipAddress,
			OSVersion: osVersion,
		})
	}

	return devices, nil
}

// GetADSyncProgress returns the current progress of an AD sync job
func (h *DeviceHandler) GetADSyncProgress(w http.ResponseWriter, r *http.Request) {
	if h.db == nil {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusServiceUnavailable)
		json.NewEncoder(w).Encode(map[string]interface{}{
			"success": false,
			"message": "Database not available",
		})
		return
	}

	// Extract jobId from path
	path := r.URL.Path
	jobID := path[len("/api/devices/sync-ad/progress/"):]

	var progress, found, added, updated int
	var status string
	var startedAt, estimatedAt time.Time

	err := h.db.QueryRow(`
		SELECT progress, found, added, updated, status, created_at,
		       CASE
		           WHEN progress > 0 THEN created_at + INTERVAL '1 second' * ((100 - progress) * (EXTRACT(EPOCH FROM (NOW() - created_at)) / NULLIF(progress, 0)))
		           ELSE NOW()
		       END as estimated_completion
		FROM sync_jobs
		WHERE id = $1
	`, jobID).Scan(&progress, &found, &added, &updated, &status, &startedAt, &estimatedAt)

	if err == sql.ErrNoRows {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusNotFound)
		json.NewEncoder(w).Encode(map[string]interface{}{
			"success": false,
			"message": "Sync job not found",
		})
		return
	}

	if err != nil {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusInternalServerError)
		json.NewEncoder(w).Encode(map[string]interface{}{
			"success": false,
			"message": "Database error: " + err.Error(),
		})
		return
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(map[string]interface{}{
		"success": true,
		"data": map[string]interface{}{
			"jobId":                 jobID,
			"status":                 status,
			"progress":               progress,
			"found":                  found,
			"added":                  added,
			"updated":                updated,
			"startedAt":              startedAt,
			"estimatedCompletionAt": estimatedAt,
		},
	})
}

// performADSync actually performs the AD sync (background job)
func (h *DeviceHandler) performADSync(jobID, server string, port int, username, password, baseDN string) {
	// Update status to syncing
	h.db.Exec(`UPDATE sync_jobs SET status = $1, updated_at = NOW() WHERE id = $2`, "syncing", jobID)

	// Connect to AD
	addr := fmt.Sprintf("%s:%d", server, port)
	conn, err := ldap.Dial("tcp", addr)
	if err != nil {
		log.Printf("AD Sync error: Failed to connect: %v", err)
		h.db.Exec(`UPDATE sync_jobs SET status = $1, error_message = $2, updated_at = NOW() WHERE id = $3`,
			"failed", fmt.Sprintf("Failed to connect: %v", err), jobID)
		return
	}
	defer conn.Close()

	// Bind
	err = conn.Bind(username, password)
	if err != nil {
		log.Printf("AD Sync error: Failed to authenticate: %v", err)
		h.db.Exec(`UPDATE sync_jobs SET status = $1, error_message = $2, updated_at = NOW() WHERE id = $3`,
			"failed", fmt.Sprintf("Failed to authenticate: %v", err), jobID)
		return
	}

	if baseDN == "" {
		baseDN = "CN=Computers,DC=corp,DC=local"
	}

	// Search for computers
	searchRequest := ldap.NewSearchRequest(
		baseDN,
		ldap.ScopeWholeSubtree,
		ldap.NeverDerefAliases,
		0,
		0,
		false,
		"(&(objectClass=computer)(objectCategory=computer))",
		[]string{"cn", "dNSHostName", "operatingSystem", "ipv4Address", "lastLogonTimestamp"},
		nil,
	)

	sr, err := conn.Search(searchRequest)
	if err != nil {
		log.Printf("AD Sync error: Search failed: %v", err)
		h.db.Exec(`UPDATE sync_jobs SET status = $1, error_message = $2, updated_at = NOW() WHERE id = $3`,
			"failed", fmt.Sprintf("Search failed: %v", err), jobID)
		return
	}

	totalComputers := len(sr.Entries)
	added := 0
	updated := 0

	// Update initial progress
	h.db.Exec(`UPDATE sync_jobs SET status = $1, found = $2, progress = 1, updated_at = NOW() WHERE id = $3`,
		"syncing", totalComputers, jobID)

	// Process each computer
	for i, entry := range sr.Entries {
		deviceID := uuid.New().String()
		hostname := entry.GetAttributeValue("cn")
		osVersion := entry.GetAttributeValue("operatingSystem")
		dnsHostName := entry.GetAttributeValue("dNSHostName")
		ipAddress := entry.GetAttributeValue("ipv4Address")

		// If no IP in AD, try DNS lookup using hostname or dNSHostName
		if ipAddress == "" {
			// Try dNSHostName first (e.g., "PC-001.corp.local")
			lookupName := dnsHostName
			if lookupName == "" {
				// Fallback to cn (e.g., "PC-001")
				lookupName = hostname
			}

			if lookupName != "" {
				addrs, err := net.LookupHost(lookupName)
				if err == nil && len(addrs) > 0 {
					// Use first IPv4 address
					for _, addr := range addrs {
						parsedIP := net.ParseIP(addr)
						if parsedIP != nil && parsedIP.To4() != nil {
							ipAddress = addr
							break
						}
					}
				}
			}
		}

		// Final fallback
		if ipAddress == "" {
			ipAddress = "Unknown"
		}

		if hostname == "" {
			continue
		}

		// Check if device exists
		var exists bool
		h.db.QueryRow("SELECT EXISTS(SELECT 1 FROM devices WHERE hostname = $1)", hostname).Scan(&exists)

		if !exists {
			_, err := h.db.Exec(`
				INSERT INTO devices (id, hostname, ip_address, os_version, status, last_seen, created_at, updated_at)
				VALUES ($1, $2, $3, $4, 'offline', NOW(), NOW(), NOW())
			`, deviceID, hostname, ipAddress, osVersion)

			if err == nil {
				added++
			} else {
				log.Printf("Failed to insert device %s: %v", hostname, err)
			}
		} else {
			_, err := h.db.Exec(`
				UPDATE devices
				SET ip_address = $1, os_version = $2, updated_at = NOW(), last_seen = NOW()
				WHERE hostname = $3
			`, ipAddress, osVersion, hostname)

			if err == nil {
				updated++
			} else {
				log.Printf("Failed to update device %s: %v", hostname, err)
			}
		}

		// Update progress every 10 items or on last item
		if i%10 == 0 || i == totalComputers-1 {
			progress := ((i + 1) * 100) / totalComputers
			if progress > 100 {
				progress = 100
			}
			h.db.Exec(`UPDATE sync_jobs SET progress = $1, added = $2, updated = $3, updated_at = NOW() WHERE id = $4`,
				progress, added, updated, jobID)
		}

		// Throttle to give UI time to update
		time.Sleep(50 * time.Millisecond)
	}

	// Mark complete
	h.db.Exec(`UPDATE sync_jobs SET status = $1, progress = 100, updated_at = NOW() WHERE id = $2`, "completed", jobID)
	h.db.Exec(`UPDATE ad_configuration SET last_synced_at = NOW() WHERE is_active = true`)
}

// ListDevices returns all registered devices
func (h *DeviceHandler) ListDevices(w http.ResponseWriter, r *http.Request) {
	if h.db == nil {
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(map[string]interface{}{
			"success": true,
			"devices": []interface{}{},
		})
		return
	}

	rows, err := h.db.Query(`
		SELECT id, hostname, ip_address, os_version, status, last_seen, created_at, updated_at
		FROM devices
		ORDER BY last_seen DESC
	`)
	if err != nil {
		log.Printf("Error querying devices: %v", err)
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusInternalServerError)
		json.NewEncoder(w).Encode(map[string]interface{}{
			"success": false,
			"error":   "Failed to query devices",
		})
		return
	}
	defer rows.Close()

	var devices []map[string]interface{}
	for rows.Next() {
		var id, hostname, ipAddress, osVersion, status string
		var lastSeen, createdAt, updatedAt time.Time

		err := rows.Scan(&id, &hostname, &ipAddress, &osVersion, &status, &lastSeen, &createdAt, &updatedAt)
		if err != nil {
			log.Printf("Error scanning device: %v", err)
			continue
		}

		devices = append(devices, map[string]interface{}{
			"id":                 id,
			"hostname":           hostname,
			"ipAddress":          ipAddress,
			"osVersion":          osVersion,
			"status":             status,
			"lastSeen":           lastSeen.Format(time.RFC3339),
			"agentVersion":       "v1.2.5",
			"registrationMethod": "ad_sync",
			"installedAt":        createdAt.Format(time.RFC3339),
		})
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(map[string]interface{}{
		"success": true,
		"devices": devices,
	})
}

// TestADConnection tests LDAP connection without syncing
func (h *DeviceHandler) TestADConnection(w http.ResponseWriter, r *http.Request) {
	var req struct {
		Server   string `json:"server"`
		Port     int    `json:"port"`
		BaseDN   string `json:"baseDN"`
		Username string `json:"username"`
		Password string `json:"password"`
		UseTLS   bool   `json:"useTLS"`
	}

	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusBadRequest)
		json.NewEncoder(w).Encode(map[string]interface{}{
			"success": false,
			"error":   "Invalid request",
		})
		return
	}

	log.Printf("🔌 Testing LDAP connection to %s:%d", req.Server, req.Port)

	// Test TCP connection first (JoinHostPort handles both IPv4 and IPv6)
	address := net.JoinHostPort(req.Server, strconv.Itoa(req.Port))
	conn, err := net.DialTimeout("tcp", address, 5*time.Second)
	if err != nil {
		log.Printf("❌ LDAP connection failed: %v", err)
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusInternalServerError)
		json.NewEncoder(w).Encode(map[string]interface{}{
			"success": false,
			"error":   fmt.Sprintf("Cannot reach LDAP server: %v", err),
		})
		return
	}
	conn.Close()

	// Try LDAP bind
	var ldapConn *ldap.Conn
	if req.UseTLS {
		ldapConn, err = ldap.DialTLS("tcp", address, nil)
	} else {
		ldapConn, err = ldap.Dial("tcp", address)
	}

	if err != nil {
		log.Printf("❌ LDAP dial failed: %v", err)
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusInternalServerError)
		json.NewEncoder(w).Encode(map[string]interface{}{
			"success": false,
			"error":   fmt.Sprintf("LDAP connection failed: %v", err),
		})
		return
	}
	defer ldapConn.Close()

	// Try to bind
	err = ldapConn.Bind(req.Username, req.Password)
	if err != nil {
		// Enhanced error message with username format hints
		errorMsg := fmt.Sprintf("LDAP authentication failed: %v", err)
		
		// Check if it's an invalid credentials error
		if strings.Contains(err.Error(), "Invalid Credentials") || strings.Contains(err.Error(), "52e") {
			errorMsg = fmt.Sprintf("Invalid credentials. Please try these username formats:\n"+
				"1. User Principal Name: username@domain.com\n"+
				"2. Domain\\Username: DOMAIN\\username\n"+
				"3. Distinguished Name: CN=username,CN=Users,DC=domain,DC=com\n\n"+
				"Original error: %v", err)
		}
		
		log.Printf("❌ LDAP bind failed: %v", err)
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusUnauthorized)
		json.NewEncoder(w).Encode(map[string]interface{}{
			"success": false,
			"error":   errorMsg,
		})
		return
	}

	log.Printf("✅ LDAP connection successful")

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(map[string]interface{}{
		"success": true,
		"message": "LDAP connection successful",
	})
}

// DiscoverADDevices discovers devices from AD without syncing
func (h *DeviceHandler) DiscoverADDevices(w http.ResponseWriter, r *http.Request) {
	var req struct {
		Server   string `json:"server"`
		Port     int    `json:"port"`
		BaseDN   string `json:"baseDN"`
		Username string `json:"username"`
		Password string `json:"password"`
		Filter   string `json:"filter"`
	}

	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusBadRequest)
		json.NewEncoder(w).Encode(map[string]interface{}{
			"success": false,
			"error":   "Invalid request",
		})
		return
	}

	// Connect to AD
	addr := fmt.Sprintf("%s:%d", req.Server, req.Port)
	conn, err := ldap.Dial("tcp", addr)
	if err != nil {
		log.Printf("AD Discovery error: Failed to connect: %v", err)
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusInternalServerError)
		json.NewEncoder(w).Encode(map[string]interface{}{
			"success": false,
			"error":   fmt.Sprintf("Failed to connect: %v", err),
		})
		return
	}
	defer conn.Close()

	// Bind
	err = conn.Bind(req.Username, req.Password)
	if err != nil {
		// Enhanced error message with username format hints
		errorMsg := fmt.Sprintf("Failed to authenticate: %v", err)
		
		if strings.Contains(err.Error(), "Invalid Credentials") || strings.Contains(err.Error(), "52e") {
			errorMsg = fmt.Sprintf("Invalid credentials. Please try these username formats:\n"+
				"1. User Principal Name: username@domain.com\n"+
				"2. Domain\\Username: DOMAIN\\username\n"+
				"3. Distinguished Name: CN=username,CN=Users,DC=domain,DC=com\n\n"+
				"Original error: %v", err)
		}
		
		log.Printf("AD Discovery error: Failed to authenticate: %v", err)
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusUnauthorized)
		json.NewEncoder(w).Encode(map[string]interface{}{
			"success": false,
			"error":   errorMsg,
		})
		return
	}

	if req.BaseDN == "" {
		req.BaseDN = "CN=Computers,DC=corp,DC=local"
	}

	filter := req.Filter
	if filter == "" {
		filter = "(&(objectClass=computer)(operatingSystem=Windows*))"
	}

	// Search for computers
	searchRequest := ldap.NewSearchRequest(
		req.BaseDN,
		ldap.ScopeWholeSubtree,
		ldap.NeverDerefAliases,
		0,
		0,
		false,
		filter,
		[]string{"cn", "dNSHostName", "operatingSystem", "ipv4Address"},
		nil,
	)

	sr, err := conn.Search(searchRequest)
	if err != nil {
		log.Printf("AD Discovery error: Search failed: %v", err)
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusInternalServerError)
		json.NewEncoder(w).Encode(map[string]interface{}{
			"success": false,
			"error":   fmt.Sprintf("Search failed: %v", err),
		})
		return
	}

	var devices []map[string]interface{}
	for _, entry := range sr.Entries {
		hostname := entry.GetAttributeValue("cn")
		dnsHostName := entry.GetAttributeValue("dNSHostName")
		osVersion := entry.GetAttributeValue("operatingSystem")
		ipAddress := entry.GetAttributeValue("ipv4Address")

		if hostname == "" {
			continue
		}

		// If no IP in AD, try DNS lookup
		if ipAddress == "" {
			lookupName := dnsHostName
			if lookupName == "" {
				lookupName = hostname
			}

			if lookupName != "" {
				addrs, err := net.LookupHost(lookupName)
				if err == nil && len(addrs) > 0 {
					for _, addr := range addrs {
						parsedIP := net.ParseIP(addr)
						if parsedIP != nil && parsedIP.To4() != nil {
							ipAddress = addr
							break
						}
					}
				}
			}
		}

		if ipAddress == "" {
			ipAddress = "Unknown"
		}

		devices = append(devices, map[string]interface{}{
			"hostname":  hostname,
			"ipAddress": ipAddress,
			"osVersion": osVersion,
		})
	}

	log.Printf("✅ Found %d devices in Active Directory", len(devices))

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(map[string]interface{}{
		"success": true,
		"devices": devices,
	})
}
