package api

import (
	"bytes"
	"context"
	"encoding/json"
	"io"
	"log"
	"net"
	"net/http"
	"strconv"
	"strings"
	"time"

	"manara-dlp/internal/alerts"
	"manara-dlp/internal/approval"
	"manara-dlp/internal/classification"
	"manara-dlp/internal/db"
	"manara-dlp/internal/discovery"
	"manara-dlp/internal/endpoints"
	"manara-dlp/internal/incidents"
	"manara-dlp/internal/keywords"
	"manara-dlp/internal/ownership"
	"manara-dlp/internal/policy"
	"manara-dlp/internal/telemetry"
	"manara-dlp/internal/websocket"

	"github.com/google/uuid"
)

// Global WebSocket hub for real-time event broadcasting
var GlobalWSHub *websocket.Hub

// AllowedCORSOrigins is the allowlist of origins the API accepts for browser
// requests. It is populated from the ALLOWED_ORIGINS (or legacy
// ALLOWED_WEBSOCKET_ORIGINS) environment variable in main.go.
var AllowedCORSOrigins []string

// isAllowedCORSOrigin reports whether an Origin header matches the allowlist.
// Trailing slashes are ignored so "http://localhost:5173/" matches
// "http://localhost:5173".
func isAllowedCORSOrigin(origin string) bool {
	for _, allowed := range AllowedCORSOrigins {
		if strings.TrimRight(allowed, "/") == strings.TrimRight(origin, "/") {
			return true
		}
	}
	return false
}

func init() {
	GlobalWSHub = websocket.NewHub()
	go GlobalWSHub.Run()
}

// global events handler used by telemetry endpoint
var globalEventsHandler interface {
	ReceiveEventBatch(http.ResponseWriter, *http.Request)
	ListEventLogs(http.ResponseWriter, *http.Request)
	ListIncidents(http.ResponseWriter, *http.Request)
	ResolveIncident(http.ResponseWriter, *http.Request)
	ClassifyFile(http.ResponseWriter, *http.Request)
}

// claimsContextKey is the context key under which validated identity claims
// are exposed to downstream handlers.
type claimsContextKey struct{}

// isPublicPath reports whether a request path is exempt from authentication.
// Only agent-facing bootstrap, health, authentication and streaming endpoints
// are exempt; every administrative endpoint requires a valid Bearer token.
func isPublicPath(path string) bool {
	publicExact := map[string]bool{
		"/api/health":            true,
		"/api/auth/login":        true,
		"/api/auth/ldap":         true,
		"/api/agents/download":   true,
		"/api/agent/install":     true,
		"/api/devices/register":  true,
		"/api/devices/heartbeat": true,
		"/api/telemetry":         true,
		"/api/v1/events/batch":   true,
		"/api/classify":          true,
	}
	if publicExact[path] {
		return true
	}

	publicPrefixes := []string{
		"/api/install/",
		"/api/v1/install/",
		"/api/drivers/",
		"/downloads/",
	}
	for _, p := range publicPrefixes {
		if strings.HasPrefix(path, p) {
			return true
		}
	}

	return false
}

// isAdminEndpoint reports whether the request path targets an administrative
// endpoint reserved for admin-console tokens. Device tokens (role == "device")
// are denied these paths; they are only permitted on the agent-facing
// heartbeat, telemetry and enrollment routes, which are public paths and never
// reach the role check in AuthMiddleware.
func isAdminEndpoint(path string) bool {
	adminExact := map[string]bool{
		"/api/devices":   true,
		"/api/events":    true,
		"/api/incidents": true,
		"/api/settings":  true,
	}
	if adminExact[path] {
		return true
	}

	adminPrefixes := []string{
		"/api/devices/",       // device list/details/logs/discovery (heartbeat & register are public)
		"/api/policies",       // policy management
		"/api/v1/users",       // user management
		"/api/v1/roles",       // role management
		"/api/v1/permissions", // permission management
		"/api/v1/dspm",        // DSPM inventory
		"/api/v1/event-logs",  // event logs
		"/api/v1/incidents",   // incidents
		"/api/v1/ad/",         // AD users
		"/api/events",         // event logs
		"/api/incidents",      // incidents
		"/api/keywords",       // keyword management
		"/api/files/",         // classified files
		"/api/approvals",      // approval workflow
		"/api/rules",          // classification rules
		"/api/dashboard",      // dashboard stats
		"/api/ad/",            // AD management
		"/api/settings",       // settings
	}
	for _, p := range adminPrefixes {
		if strings.HasPrefix(path, p) {
			return true
		}
	}

	return false
}

// AuthMiddleware validates the JWT bearer token on all administrative
// endpoints. Requests without a token, or with an invalid/expired token, are
// rejected with HTTP 401. Authenticated identity claims are stored on the
// request context for downstream handlers.
func AuthMiddleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if isPublicPath(r.URL.Path) {
			next.ServeHTTP(w, r)
			return
		}

		authHeader := r.Header.Get("Authorization")
		if authHeader == "" || !strings.HasPrefix(authHeader, "Bearer ") {
			w.Header().Set("Content-Type", "application/json")
			w.WriteHeader(http.StatusUnauthorized)
			json.NewEncoder(w).Encode(map[string]interface{}{
				"error":   "Unauthorized",
				"message": "missing or malformed Authorization header",
			})
			return
		}

		tokenStr := strings.TrimPrefix(authHeader, "Bearer ")
		claims, err := validateToken(tokenStr)
		if err != nil || claims == nil {
			w.Header().Set("Content-Type", "application/json")
			w.WriteHeader(http.StatusUnauthorized)
			json.NewEncoder(w).Encode(map[string]interface{}{
				"error":   "Unauthorized",
				"message": "invalid or expired token",
			})
			return
		}

		// Enforce role-based authorization: device tokens (minted by the
		// public device-enrollment endpoint) must never access administrative
		// endpoints. They are only allowed on the heartbeat, telemetry and
		// enrollment routes, which are public paths handled above.
		if claims.Role == "device" && isAdminEndpoint(r.URL.Path) {
			w.Header().Set("Content-Type", "application/json")
			w.WriteHeader(http.StatusForbidden)
			json.NewEncoder(w).Encode(map[string]interface{}{
				"error":   "Forbidden",
				"message": "device tokens cannot access administrative endpoints",
			})
			return
		}

		ctx := context.WithValue(r.Context(), claimsContextKey{}, claims)
		next.ServeHTTP(w, r.WithContext(ctx))
	})
}

// isPrivateNetworkOrigin checks if origin is from localhost or private IP
func isPrivateNetworkOrigin(origin string) bool {
	if origin == "" {
		return false
	}

	// Extract hostname from origin (e.g., "http://192.168.1.101:5173")
	if !strings.Contains(origin, "://") {
		return false
	}

	parts := strings.Split(origin, "://")
	if len(parts) != 2 {
		return false
	}

	hostPort := parts[1]
	host := strings.Split(hostPort, ":")[0]

	// Check for localhost
	if host == "localhost" || host == "127.0.0.1" {
		return true
	}

	// Check for private IPs
	ip := net.ParseIP(host)
	if ip == nil {
		return false
	}

	return ip.IsPrivate()
}

// Router creates HTTP REST API router
func NewRouter(
	policyService *policy.Service,
	telemetryService *telemetry.Service,
	endpointService *endpoints.Service,
	alertService *alerts.Service,
	database *db.Connection,
	startTime time.Time,
) http.Handler {
	// Handle nil services (when database is not available)
	mux := http.NewServeMux()

	// ========================================
	// UNCONDITIONALLY REGISTERED ENDPOINTS
	// Authentication, health and real-time events are available even when the
	// database is unreachable, so operators can always log in and monitor.
	// (Moved below the corsHandler definition so the closure is in scope.)
	// ========================================

	// Initialize handlers (need database connection)
	var settingsHandler *SettingsHandler
	var deviceHandler *DeviceHandler
	discoveryService := discovery.NewService()

	// In-memory fallback for settings when DB is not available (development)
	var inMemorySettings map[string]interface{} = map[string]interface{}{
		"systemName": "PRITRAK DLP",
		"timezone":   "UTC",
	}
	var inMemoryADConfig map[string]interface{} = nil

	// CORS middleware - only echoes back an Origin that is in the configured
	// allowlist (ALLOWED_ORIGINS / ALLOWED_WEBSOCKET_ORIGINS). Requests without
	// an Origin header (curl, agents, same-origin fetches) receive no CORS
	// header, which is correct for non-browser clients.
	corsHandler := func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			origin := r.Header.Get("Origin")

			allowOrigin := ""
			if origin != "" && isAllowedCORSOrigin(origin) {
				allowOrigin = origin
			}

			// Set CORS headers
			if allowOrigin != "" {
				w.Header().Set("Access-Control-Allow-Origin", allowOrigin)
			}

			w.Header().Set("Access-Control-Allow-Methods", "GET, POST, PUT, DELETE, PATCH, OPTIONS, HEAD")
			w.Header().Set("Access-Control-Allow-Headers", "Content-Type, Authorization, X-Requested-With")
			w.Header().Set("Access-Control-Allow-Credentials", "true")
			w.Header().Set("Access-Control-Max-Age", "3600")
			w.Header().Set("Access-Control-Expose-Headers", "Content-Length, Content-Disposition")

			if r.Method == "OPTIONS" {
				w.WriteHeader(http.StatusOK)
				return
			}

			next.ServeHTTP(w, r)
		})
	}

	// WebSocket endpoint for real-time events — validates JWT from query param
	mux.HandleFunc("/ws/events", func(w http.ResponseWriter, r *http.Request) {
		// Reuse the existing JWT validation from auth.go. Browser WebSocket
		// clients cannot set custom headers, so the token is passed via
		// the "token" query parameter.
		token := r.URL.Query().Get("token")
		if token == "" {
			http.Error(w, "Unauthorized: missing token", http.StatusUnauthorized)
			return
		}
		claims, err := validateToken(token)
		if err != nil || claims == nil {
			http.Error(w, "Unauthorized: invalid token", http.StatusUnauthorized)
			return
		}

		log.Printf("WebSocket connection request from %s (user: %s)", r.RemoteAddr, claims.Email)
		websocket.ServeWs(GlobalWSHub, w, r)
	})

	// Auth endpoints (rate-limited to slow down brute-force attempts)
	mux.HandleFunc("/api/auth/login", corsHandler(rateLimitAuth(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method == "POST" {
			handleLogin(w, r, database)
		} else {
			http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		}
	}))).ServeHTTP)

	mux.HandleFunc("/api/auth/ldap", corsHandler(rateLimitAuth(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method == "POST" {
			handleLDAPLogin(w, r)
		} else {
			http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		}
	}))).ServeHTTP)

	// Health endpoint - no authentication required
	mux.HandleFunc("/api/health", corsHandler(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method != "GET" {
			http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
			return
		}

		// Check database connectivity
		dbStatus := "disconnected"
		if database != nil {
			if err := database.DB.Ping(); err == nil {
				dbStatus = "connected"
			}
		}

		// Calculate uptime
		uptime := time.Since(startTime).Seconds()

		// Prepare response
		health := map[string]interface{}{
			"status":         "healthy",
			"version":        "dev",
			"database":       dbStatus,
			"uptime_seconds": int64(uptime),
			"timestamp":      time.Now().Format(time.RFC3339),
		}

		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(health)
	})).ServeHTTP)

	// Agent installer endpoint (one-line install)
	mux.HandleFunc("/api/install/agent.ps1", GetAgentInstaller)

	// Agent DLP v2 endpoint (with file blocking + UI)
	mux.HandleFunc("/api/install/agent-dlp-v2.ps1", GetAgentDLPv2)

	// Agent DLP v3 Enterprise endpoint (TRUE file blocking with ACL, locks, backup)
	mux.HandleFunc("/api/install/agent-dlp-v3-enterprise.ps1", GetAgentDLPv3Enterprise)

	// Agent v3 Enterprise installer (one-line install for v3)
	mux.HandleFunc("/api/install/agent-v3.ps1", GetAgentInstallerV3)

	// Kernel mode agent installer (TRUE kernel-level blocking)
	mux.HandleFunc("/api/install/agent-kernel.ps1", GetAgentKernelInstaller)
	mux.HandleFunc("/api/install/kernel", GetAgentKernelInstaller)

	// Driver download endpoints
	mux.HandleFunc("/api/drivers/minifilter.sys", GetMinifilterDriver)
	mux.HandleFunc("/api/drivers/wfp.sys", GetWfpDriver)

	// Agent artifact manifest + download (used by the bootstrap installer)
	mux.HandleFunc("/api/v1/install/manifest", GetManifest)
	mux.HandleFunc("/api/v1/install/artifacts/", DownloadArtifact)

	// Agent bootstrap installer (enterprise one-liner deployment:
	// irm http://<server>/api/v1/install/bootstrap.ps1 | iex)
	mux.HandleFunc("/api/v1/install/bootstrap.ps1", GetBootstrapScript)

	if database != nil {
		settingsHandler = NewSettingsHandler(database.DB)
		deviceHandler = NewDeviceHandler(database.DB)
	} else {
		// Development fallback: provide lightweight in-memory responses for users/roles/permissions
		// so the frontend can operate without a database.
		log.Println("[DEV] Starting in-memory user/role handler (database unavailable)")
		inMemoryRoles := []map[string]interface{}{
			{"id": "role-admin", "name": "Admin", "description": "Full system access", "is_system": true, "permissions": []interface{}{} },
			{"id": "role-security", "name": "Security Officer", "description": "Manage policies and incidents", "is_system": true, "permissions": []interface{}{} },
		}
		inMemoryPermissions := []map[string]interface{}{
			{"id": "perm-policies-read", "name": "policies.read", "resource": "Policies", "action": "read", "description": "View DLP policies"},
			{"id": "perm-incidents-read", "name": "incidents.read", "resource": "Incidents", "action": "read", "description": "View incidents"},
		}
		inMemoryUsers := map[string]map[string]interface{}{}

		// Register lightweight roles endpoint
		mux.HandleFunc("/api/v1/roles", corsHandler(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			if r.Method == "GET" {
				w.Header().Set("Content-Type", "application/json")
				json.NewEncoder(w).Encode(map[string]interface{}{"roles": inMemoryRoles})
				return
			}
			http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		})).ServeHTTP)

		// Register lightweight permissions endpoint
		mux.HandleFunc("/api/v1/permissions", corsHandler(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			if r.Method == "GET" {
				w.Header().Set("Content-Type", "application/json")
				json.NewEncoder(w).Encode(map[string]interface{}{"permissions": inMemoryPermissions})
				return
			}
			http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		})).ServeHTTP)

		// Lightweight users endpoints (GET list and POST create)
		mux.HandleFunc("/api/v1/users", corsHandler(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			if r.Method == "GET" {
				usersArr := []interface{}{}
				for _, u := range inMemoryUsers {
					usersArr = append(usersArr, u)
				}
				w.Header().Set("Content-Type", "application/json")
				json.NewEncoder(w).Encode(map[string]interface{}{"users": usersArr, "total": len(usersArr)})
				return
			}
			if r.Method == "POST" {
				var req map[string]interface{}
				if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
					http.Error(w, "invalid request", http.StatusBadRequest)
					return
				}
				username, _ := req["username"].(string)
				if strings.TrimSpace(username) == "" {
					http.Error(w, "username required", http.StatusBadRequest)
					return
				}
				id := uuid.New().String()
				now := time.Now().Format(time.RFC3339)
				userObj := map[string]interface{}{
					"id": id,
					"username": username,
					"email": req["email"],
					"first_name": req["first_name"],
					"last_name": req["last_name"],
					"is_active": true,
					"is_ad_synced": false,
					"roles": []interface{}{},
					"created_at": now,
					"updated_at": now,
				}
				inMemoryUsers[id] = userObj
				w.Header().Set("Content-Type", "application/json")
				w.WriteHeader(http.StatusCreated)
				json.NewEncoder(w).Encode(map[string]interface{}{"message": "user created", "user": userObj})
				return
			}
			http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		})).ServeHTTP)

		// Lightweight AD list: return empty with message
		mux.HandleFunc("/api/v1/ad/users", corsHandler(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			w.Header().Set("Content-Type", "application/json")
			json.NewEncoder(w).Encode(map[string]interface{}{"success": false, "message": "AD not configured in development mode", "data": []interface{}{} })
		})).ServeHTTP)

		// Device registration endpoint (agent enrollment, works without a database)
		mux.HandleFunc("/api/devices/register", corsHandler(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			if r.Method == "POST" {
				HandleDeviceRegistration(w, r)
			} else {
				http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
			}
		})).ServeHTTP)

		// Device heartbeat endpoint (works without a database)
		mux.HandleFunc("/api/devices/heartbeat", corsHandler(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			if r.Method == "POST" {
				HandleDeviceHeartbeat(w, r)
			} else {
				http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
			}
		})).ServeHTTP)

		// Device list endpoint (dashboard, works without a database)
		mux.HandleFunc("/api/devices", corsHandler(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			if r.Method == "GET" {
				HandleListDevices(w, r)
			} else {
				http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
			}
		})).ServeHTTP)

		// Device details + logs endpoints (works without a database)
		mux.HandleFunc("/api/devices/", corsHandler(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			path := r.URL.Path
			if strings.HasSuffix(path, "/logs/download") && r.Method == "GET" {
				HandleDownloadDeviceLogs(w, r)
				return
			}
			if strings.HasSuffix(path, "/logs") && r.Method == "GET" {
				HandleDownloadDeviceLogs(w, r)
				return
			}
			if r.Method == "GET" {
				HandleGetDeviceDetails(w, r)
				return
			}
			http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		})).ServeHTTP)

		// Event logs endpoint (works without a database; returns no events)
		mux.HandleFunc("/api/v1/event-logs", corsHandler(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			if r.Method != "GET" {
				http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
				return
			}
			w.Header().Set("Content-Type", "application/json")
			json.NewEncoder(w).Encode(map[string]interface{}{"events": []interface{}{}})
		})).ServeHTTP)

		// DSPM inventory endpoints (works without a database; returns empty data)
		mux.HandleFunc("/api/v1/dspm/inventory", corsHandler(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			w.Header().Set("Content-Type", "application/json")
			if r.Method == "POST" {
				json.NewEncoder(w).Encode(map[string]string{"status": "ok"})
				return
			}
			if r.Method == "GET" {
				json.NewEncoder(w).Encode(map[string]interface{}{"data": []interface{}{}, "total": 0, "limit": 50, "offset": 0})
				return
			}
			http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		})).ServeHTTP)

		mux.HandleFunc("/api/v1/dspm/stats", corsHandler(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			if r.Method != "GET" {
				http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
				return
			}
			w.Header().Set("Content-Type", "application/json")
			json.NewEncoder(w).Encode(map[string]interface{}{"TOTAL": 0})
		})).ServeHTTP)

		// Incidents endpoint (works without a database; returns no incidents)
		mux.HandleFunc("/api/v1/incidents", corsHandler(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			if r.Method != "GET" {
				http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
				return
			}
			w.Header().Set("Content-Type", "application/json")
			json.NewEncoder(w).Encode(map[string]interface{}{"incidents": []interface{}{}, "total": 0, "limit": 50, "offset": 0})
		})).ServeHTTP)

	// Return the in-memory router for development. Even the degraded path is
	// behind the JWT authentication middleware - it is never silently
	// unauthenticated.
	return corsHandler(AuthMiddleware(mux))
	}

	// Policies endpoints
	mux.HandleFunc("/api/policies", corsHandler(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.Method {
		case "GET":
			listPolicies(w, r, policyService)
		case "POST":
			createPolicy(w, r, policyService)
		default:
			http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		}
	})).ServeHTTP)

	mux.HandleFunc("/api/policies/", corsHandler(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.Method {
		case "GET":
			getPolicy(w, r, policyService)
		case "PUT":
			updatePolicy(w, r, policyService)
		case "DELETE":
			deletePolicy(w, r, policyService)
		default:
			http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		}
	})).ServeHTTP)

	// Endpoints endpoints
	mux.HandleFunc("/api/endpoints", corsHandler(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if endpointService == nil {
			// Return empty array if database not available
			w.Header().Set("Content-Type", "application/json")
			json.NewEncoder(w).Encode([]interface{}{})
			return
		}
		if r.Method == "GET" {
			listEndpoints(w, r, endpointService)
		} else {
			http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		}
	})).ServeHTTP)

	// Device registration endpoint
	mux.HandleFunc("/api/devices/register", corsHandler(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method == "POST" {
			HandleDeviceRegistration(w, r)
		} else {
			http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		}
	})).ServeHTTP)

	// Device heartbeat endpoint
	mux.HandleFunc("/api/devices/heartbeat", corsHandler(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method == "POST" {
			HandleDeviceHeartbeat(w, r)
		} else {
			http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		}
	})).ServeHTTP)

	// Device details endpoints
	mux.HandleFunc("/api/devices/", corsHandler(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// Parse path to determine action
		path := r.URL.Path

		// Handle /api/devices/:id/logs/download
		if strings.HasSuffix(path, "/logs/download") && r.Method == "GET" {
			HandleDownloadDeviceLogs(w, r)
			return
		}

		// Handle /api/devices/:id/logs
		if strings.HasSuffix(path, "/logs") && r.Method == "GET" {
			HandleGetDeviceLogs(w, r)
			return
		}

		// Handle /api/devices/:id (device details)
		if r.Method == "GET" {
			HandleGetDeviceDetails(w, r)
			return
		}

		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
	})).ServeHTTP)

	// Telemetry ingestion endpoint (used by Windows agent)
	mux.HandleFunc("/api/telemetry", corsHandler(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method != "POST" {
			http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
			return
		}

		// Read raw body for parsing
		bodyBytes, err := io.ReadAll(r.Body)
		if err != nil {
			log.Printf("[ERROR] Failed to read telemetry body: %v", err)
			http.Error(w, "failed to read body", http.StatusBadRequest)
			return
		}

		var payload struct {
			Hostname  string                 `json:"hostname"`
			Timestamp string                 `json:"timestamp"`
			EventType string                 `json:"eventType"`
			Data      map[string]interface{} `json:"data"`
		}
		if err := json.Unmarshal(bodyBytes, &payload); err != nil {
			log.Printf("[ERROR] Invalid telemetry payload: %v", err)
			http.Error(w, "invalid payload", http.StatusBadRequest)
			return
		}
		// Forward to global events handler if available
		if globalEventsHandler != nil {
			var ts time.Time
			if t, err := time.Parse(time.RFC3339, payload.Timestamp); err == nil {
				ts = t
			} else {
				ts = time.Now()
			}
			fe := FileEvent{EventType: payload.EventType, Timestamp: ts}
			if u, ok := payload.Data["user"].(string); ok {
				fe.Username = u
				log.Printf("[TELEMETRY] Username: %s", u)
			} else {
				log.Printf("[TELEMETRY] WARNING: No username in payload")
			}
			if fp, ok := payload.Data["filePath"].(string); ok {
				fe.FilePath = fp
			}
			if fn, ok := payload.Data["fileName"].(string); ok {
				fe.FileName = fn
			}
			// Extract classification from agent if provided
			if cls, ok := payload.Data["classification"].(string); ok && cls != "" {
				fe.Classification = cls
				log.Printf("[TELEMETRY] Agent classification: %s", cls)
			}

			// Extract file content if provided by agent
			var fileContent string
			if fc, ok := payload.Data["fileContent"].(string); ok {
				fileContent = fc
				log.Printf("[TELEMETRY] Received fileContent for %s: %d bytes", fe.FileName, len(fileContent))
			} else {
				log.Printf("[TELEMETRY] NO fileContent for %s (type=%s)", fe.FileName, fe.EventType)
			}

			if fe.EventType == "file_renamed" {
				if np, ok := payload.Data["newPath"].(string); ok && np != "" {
					fe.FilePath = np
				}
				if nn, ok := payload.Data["newName"].(string); ok && nn != "" {
					fe.FileName = nn
				}
			}
			batch := EventBatch{DeviceID: payload.Hostname, Events: []FileEvent{fe}}
			buf, _ := json.Marshal(batch)
			req, _ := http.NewRequest("POST", "/api/v1/events/batch", bytes.NewReader(buf))
			req.Header.Set("X-File-Content", fileContent) // Pass content via header
			globalEventsHandler.ReceiveEventBatch(w, req)
			return
		}
		// Fallback: accept and log only
		log.Printf("[TELEMETRY] host=%s type=%s dataKeys=%d", payload.Hostname, payload.EventType, len(payload.Data))
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(map[string]interface{}{"success": true, "message": "telemetry accepted"})
	})).ServeHTTP)

	// Settings endpoints (always registered). If DB-backed handler exists, delegate; otherwise use in-memory fallbacks.
	mux.HandleFunc("/api/settings", corsHandler(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method == "GET" {
			if settingsHandler != nil {
				settingsHandler.GetSettings(w, r)
				return
			}
			w.Header().Set("Content-Type", "application/json")
			json.NewEncoder(w).Encode(map[string]interface{}{"success": true, "data": inMemorySettings})
			return
		}
		if r.Method == "PUT" {
			if settingsHandler != nil {
				settingsHandler.UpdateSettings(w, r)
				return
			}
			var payload map[string]interface{}
			if err := json.NewDecoder(r.Body).Decode(&payload); err != nil {
				http.Error(w, "Invalid request body", http.StatusBadRequest)
				return
			}
			// merge into inMemorySettings
			for k, v := range payload {
				inMemorySettings[k] = v
			}
			w.Header().Set("Content-Type", "application/json")
			json.NewEncoder(w).Encode(map[string]interface{}{"success": true, "message": "Settings saved"})
			return
		}
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
	})).ServeHTTP)

	mux.HandleFunc("/api/settings/ad", corsHandler(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method == "GET" {
			if settingsHandler != nil {
				settingsHandler.GetADConfiguration(w, r)
				return
			}
			w.Header().Set("Content-Type", "application/json")
			if inMemoryADConfig == nil {
				json.NewEncoder(w).Encode(map[string]interface{}{"success": false, "message": "No AD configuration found"})
			} else {
				json.NewEncoder(w).Encode(map[string]interface{}{"success": true, "data": inMemoryADConfig})
			}
			return
		}
		if r.Method == "POST" {
			if settingsHandler != nil {
				settingsHandler.CreateADConfiguration(w, r)
				return
			}
			var req map[string]interface{}
			if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
				http.Error(w, "Invalid request body", http.StatusBadRequest)
				return
			}
			inMemoryADConfig = req
			w.Header().Set("Content-Type", "application/json")
			w.WriteHeader(http.StatusCreated)
			json.NewEncoder(w).Encode(map[string]interface{}{"success": true, "message": "AD configuration saved", "data": map[string]interface{}{"id": "in-memory"}})
			return
		}
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
	})).ServeHTTP)

	mux.HandleFunc("/api/settings/ad/test", corsHandler(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method == "POST" {
			if settingsHandler != nil {
				settingsHandler.TestADConnection(w, r)
				return
			}
			// In-memory test always returns not connected (safe default)
			w.Header().Set("Content-Type", "application/json")
			json.NewEncoder(w).Encode(map[string]interface{}{"success": true, "connected": false, "message": "AD test not available in dev mode"})
			return
		}
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
	})).ServeHTTP)

	mux.HandleFunc("/api/settings/ad/status", corsHandler(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method == "GET" {
			if settingsHandler != nil {
				settingsHandler.GetADConfigurationStatus(w, r)
				return
			}
			w.Header().Set("Content-Type", "application/json")
			json.NewEncoder(w).Encode(map[string]interface{}{"success": true, "data": map[string]interface{}{"isConfigured": inMemoryADConfig != nil}})
			return
		}
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
	})).ServeHTTP)

	// Device management endpoints
	mux.HandleFunc("/api/devices", corsHandler(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method == "GET" {
			if deviceHandler != nil {
				deviceHandler.ListDevices(w, r)
			} else {
				// Fallback to in-memory devices
				HandleListDevices(w, r)
			}
		} else if r.Method == "DELETE" {
			HandleDeleteAllDevices(w, r)
		} else {
			http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		}
	})).ServeHTTP)

	// AD Sync endpoints - Always register, but return error if no database
	mux.HandleFunc("/api/devices/sync-ad/start", corsHandler(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method == "POST" {
			if deviceHandler != nil {
				deviceHandler.StartADSync(w, r)
			} else {
				// Create temporary handler for DB-less sync (register into in-memory device manager)
				tempHandler := NewDeviceHandler(nil)
				tempHandler.StartADSync(w, r)
			}
		} else {
			http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		}
	})).ServeHTTP)

	mux.HandleFunc("/api/devices/sync-ad/progress/", corsHandler(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method == "GET" {
			if deviceHandler != nil {
				deviceHandler.GetADSyncProgress(w, r)
			} else {
				w.Header().Set("Content-Type", "application/json")
				w.WriteHeader(http.StatusServiceUnavailable)
				json.NewEncoder(w).Encode(map[string]interface{}{
					"success": false,
					"error":   "Database not available. Please configure PostgreSQL connection.",
				})
			}
		} else {
			http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		}
	})).ServeHTTP)

	// AD connection testing - Works WITHOUT database (only tests LDAP connection)
	mux.HandleFunc("/api/ad/test", corsHandler(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method == "POST" {
			if deviceHandler != nil {
				deviceHandler.TestADConnection(w, r)
			} else {
				// Create temporary handler for testing (doesn't need DB)
				tempHandler := NewDeviceHandler(nil)
				tempHandler.TestADConnection(w, r)
			}
		} else {
			http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		}
	})).ServeHTTP)

	// AD device discovery - Works WITHOUT database (only queries LDAP)
	mux.HandleFunc("/api/ad/discover", corsHandler(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method == "POST" {
			if deviceHandler != nil {
				deviceHandler.DiscoverADDevices(w, r)
			} else {
				// Create temporary handler for discovery (doesn't need DB)
				tempHandler := NewDeviceHandler(nil)
				tempHandler.DiscoverADDevices(w, r)
			}
		} else {
			http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		}
	})).ServeHTTP)

	// Network Discovery endpoints
	mux.HandleFunc("/api/devices/discover", corsHandler(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method == "POST" {
			handleStartDiscovery(w, r, discoveryService)
		} else {
			http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		}
	})).ServeHTTP)

	mux.HandleFunc("/api/devices/discover/progress", corsHandler(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method == "GET" {
			handleGetDiscoveryProgress(w, r, discoveryService)
		} else {
			http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		}
	})).ServeHTTP)

	// Support discovery ID in path for compatibility
	mux.HandleFunc("/api/devices/discovery/", corsHandler(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method == "GET" {
			// Extract ID from path: /api/devices/discovery/{id}/progress
			path := r.URL.Path
			if strings.Contains(path, "/progress") {
				handleGetDiscoveryProgress(w, r, discoveryService)
			} else {
				http.Error(w, "Not found", http.StatusNotFound)
			}
		} else {
			http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		}
	})).ServeHTTP)

	mux.HandleFunc("/api/devices/discover/stop", corsHandler(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method == "POST" {
			handleStopDiscovery(w, r, discoveryService)
		} else {
			http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		}
	})).ServeHTTP)

	// Agent download endpoint (legacy)
	mux.HandleFunc("/api/agents/download", corsHandler(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method == "GET" {
			handleAgentDownload(w, r)
		} else {
			http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		}
	})).ServeHTTP)

	// Agent install script endpoint - serves PowerShell installer
	mux.HandleFunc("/api/agent/install", corsHandler(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method == "GET" {
			handleAgentInstallScript(w, r)
		} else {
			http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		}
	})).ServeHTTP)

	// Static file serving for agent installer downloads
	mux.HandleFunc("/downloads/", corsHandler(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method == "GET" || r.Method == "HEAD" {
			handleInstallerDownload(w, r)
		} else {
			http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		}
	})).ServeHTTP)

	// Events endpoints
	mux.HandleFunc("/api/events", corsHandler(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if telemetryService == nil {
			w.Header().Set("Content-Type", "application/json")
			json.NewEncoder(w).Encode([]interface{}{})
			return
		}
		if r.Method == "GET" {
			listEvents(w, r, telemetryService)
		} else {
			http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		}
	})).ServeHTTP)

	// Incidents endpoints
	mux.HandleFunc("/api/incidents", corsHandler(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if alertService == nil {
			// Return empty array if database not available
			w.Header().Set("Content-Type", "application/json")
			json.NewEncoder(w).Encode([]interface{}{})
			return
		}
		if r.Method == "GET" {
			listIncidents(w, r, alertService)
		} else {
			http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		}
	})).ServeHTTP)

	mux.HandleFunc("/api/incidents/", corsHandler(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method == "PATCH" {
			resolveIncident(w, r, alertService)
		} else {
			http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		}
	})).ServeHTTP)

	// ========================================
	// NEW ENTERPRISE DLP API ENDPOINTS
	// ========================================

	// Initialize new services if database is available
	var keywordsHandler *KeywordsHandler
	var filesHandler *FilesHandler
	var approvalsHandler *ApprovalsHandler
	var incidentsHandler *IncidentsHandler
	var dashboardHandler *DashboardHandler
	var usersHandler *UsersHandler
	var dspmHandler *DSPMHandler
	var eventsHandler interface {
		ReceiveEventBatch(http.ResponseWriter, *http.Request)
		ListEventLogs(http.ResponseWriter, *http.Request)
		ListIncidents(http.ResponseWriter, *http.Request)
		ResolveIncident(http.ResponseWriter, *http.Request)
		ClassifyFile(http.ResponseWriter, *http.Request)
	}

	if database != nil {
		// Initialize services
		keywordService := keywords.NewService(database.DB)
		classifier := classification.NewClassifier(database.DB, keywordService)
		_ = ownership.NewTracker(database.DB) // Used by policy engine when integrated
		approvalNotifier := approval.NewNotifier()
		approvalService := approval.NewWorkflowService(database.DB, approvalNotifier)
		incidentManager := incidents.NewManager(database.DB)

		// Initialize handlers
		keywordsHandler = NewKeywordsHandler(keywordService)
		filesHandler = NewFilesHandler(classifier)
		approvalsHandler = NewApprovalsHandler(approvalService)
		incidentsHandler = NewIncidentsHandler(incidentManager)
		dashboardHandler = NewDashboardHandler(database.DB)
		usersHandler = NewUsersHandler(database.DB)
		eventsHandler = NewEventsHandler(database.DB)
		dspmHandler = NewDSPMHandler(database.DB)
	} else {
		// Initialize dashboard handler even without database (uses in-memory device manager)
		dashboardHandler = NewDashboardHandler(nil)
	}
	if eventsHandler == nil {
		// No database available — fall back to in-memory handler for development/testing
		inMemHandler := NewInMemoryEventsHandler()
		if database != nil {
			inMemHandler.SetRuleEngine(classification.NewRuleEngine(database.DB))
		}
		eventsHandler = inMemHandler
	}
	if inMemHandler, ok := eventsHandler.(*InMemoryEventsHandler); ok && database != nil {
		inMemHandler.SetRuleEngine(classification.NewRuleEngine(database.DB))
	}
	// Expose eventsHandler to telemetry endpoint
	globalEventsHandler = eventsHandler

	// Keywords endpoints
	mux.HandleFunc("/api/keywords", corsHandler(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if keywordsHandler == nil {
			w.Header().Set("Content-Type", "application/json")
			json.NewEncoder(w).Encode(map[string]interface{}{"keywords": []interface{}{}, "total": 0})
			return
		}
		switch r.Method {
		case "GET":
			keywordsHandler.HandleList(w, r)
		case "POST":
			keywordsHandler.HandleCreate(w, r)
		default:
			http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		}
	})).ServeHTTP)

	mux.HandleFunc("/api/keywords/test", corsHandler(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if keywordsHandler == nil {
			http.Error(w, "Service unavailable", http.StatusServiceUnavailable)
			return
		}
		if r.Method == "POST" {
			keywordsHandler.HandleTest(w, r)
		} else {
			http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		}
	})).ServeHTTP)

	mux.HandleFunc("/api/keywords/import", corsHandler(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if keywordsHandler == nil {
			http.Error(w, "Service unavailable", http.StatusServiceUnavailable)
			return
		}
		if r.Method == "POST" {
			keywordsHandler.HandleImport(w, r)
		} else {
			http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		}
	})).ServeHTTP)

	mux.HandleFunc("/api/keywords/export", corsHandler(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if keywordsHandler == nil {
			http.Error(w, "Service unavailable", http.StatusServiceUnavailable)
			return
		}
		if r.Method == "GET" {
			keywordsHandler.HandleExport(w, r)
		} else {
			http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		}
	})).ServeHTTP)

	mux.HandleFunc("/api/keywords/groups", corsHandler(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if keywordsHandler == nil {
			w.Header().Set("Content-Type", "application/json")
			json.NewEncoder(w).Encode(map[string]interface{}{"groups": []interface{}{}})
			return
		}
		if r.Method == "GET" {
			keywordsHandler.HandleGroups(w, r)
		} else {
			http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		}
	})).ServeHTTP)

	mux.HandleFunc("/api/keywords/validate-regex", corsHandler(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if keywordsHandler == nil {
			http.Error(w, "Service unavailable", http.StatusServiceUnavailable)
			return
		}
		if r.Method == "POST" {
			keywordsHandler.HandleValidateRegex(w, r)
		} else {
			http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		}
	})).ServeHTTP)

	// Classified files endpoints
	mux.HandleFunc("/api/files/classified", corsHandler(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if filesHandler == nil {
			w.Header().Set("Content-Type", "application/json")
			json.NewEncoder(w).Encode(map[string]interface{}{"files": []interface{}{}, "total": 0})
			return
		}
		if r.Method == "GET" {
			filesHandler.HandleList(w, r)
		} else {
			http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		}
	})).ServeHTTP)

	mux.HandleFunc("/api/files/classify", corsHandler(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if filesHandler == nil {
			http.Error(w, "Service unavailable", http.StatusServiceUnavailable)
			return
		}
		if r.Method == "POST" {
			filesHandler.HandleClassify(w, r)
		} else {
			http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		}
	})).ServeHTTP)

	mux.HandleFunc("/api/files/stats", corsHandler(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if filesHandler == nil {
			w.Header().Set("Content-Type", "application/json")
			json.NewEncoder(w).Encode(map[string]interface{}{})
			return
		}
		if r.Method == "GET" {
			filesHandler.HandleStats(w, r)
		} else {
			http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		}
	})).ServeHTTP)

	// DSPM inventory endpoints (data discovery pipeline)
	mux.HandleFunc("/api/v1/dspm/inventory", corsHandler(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if dspmHandler == nil {
			http.Error(w, "database unavailable", http.StatusServiceUnavailable)
			return
		}
		switch r.Method {
		case "POST":
			dspmHandler.HandleInventoryUpsert(w, r)
		case "GET":
			dspmHandler.HandleInventoryList(w, r)
		default:
			http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		}
	})).ServeHTTP)

	mux.HandleFunc("/api/v1/dspm/stats", corsHandler(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if dspmHandler == nil {
			http.Error(w, "database unavailable", http.StatusServiceUnavailable)
			return
		}
		if r.Method == "GET" {
			dspmHandler.HandleInventoryStats(w, r)
		} else {
			http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		}
	})).ServeHTTP)

	// Approvals endpoints
	mux.HandleFunc("/api/approvals", corsHandler(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if approvalsHandler == nil {
			w.Header().Set("Content-Type", "application/json")
			json.NewEncoder(w).Encode(map[string]interface{}{"requests": []interface{}{}, "total": 0})
			return
		}
		switch r.Method {
		case "GET":
			approvalsHandler.HandleList(w, r)
		case "POST":
			approvalsHandler.HandleCreate(w, r)
		default:
			http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		}
	})).ServeHTTP)

	mux.HandleFunc("/api/approvals/pending", corsHandler(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if approvalsHandler == nil {
			w.Header().Set("Content-Type", "application/json")
			json.NewEncoder(w).Encode(map[string]interface{}{"requests": []interface{}{}, "count": 0})
			return
		}
		if r.Method == "GET" {
			approvalsHandler.HandleGetPending(w, r)
		} else {
			http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		}
	})).ServeHTTP)

	mux.HandleFunc("/api/approvals/history", corsHandler(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if approvalsHandler == nil {
			w.Header().Set("Content-Type", "application/json")
			json.NewEncoder(w).Encode(map[string]interface{}{"requests": []interface{}{}, "total": 0})
			return
		}
		if r.Method == "GET" {
			approvalsHandler.HandleHistory(w, r)
		} else {
			http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		}
	})).ServeHTTP)

	// Enhanced incidents endpoints
	mux.HandleFunc("/api/incidents/enhanced", corsHandler(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if incidentsHandler == nil {
			w.Header().Set("Content-Type", "application/json")
			json.NewEncoder(w).Encode(map[string]interface{}{"incidents": []interface{}{}, "total": 0})
			return
		}
		switch r.Method {
		case "GET":
			incidentsHandler.HandleList(w, r)
		case "POST":
			incidentsHandler.HandleCreate(w, r)
		default:
			http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		}
	})).ServeHTTP)

	mux.HandleFunc("/api/incidents/stats", corsHandler(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if incidentsHandler == nil {
			w.Header().Set("Content-Type", "application/json")
			json.NewEncoder(w).Encode(map[string]interface{}{})
			return
		}
		if r.Method == "GET" {
			incidentsHandler.HandleStats(w, r)
		} else {
			http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		}
	})).ServeHTTP)

	// Dashboard endpoints
	mux.HandleFunc("/api/dashboard/stats", corsHandler(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if dashboardHandler == nil {
			w.Header().Set("Content-Type", "application/json")
			json.NewEncoder(w).Encode(map[string]interface{}{
				"endpoints":         map[string]interface{}{"total": 0, "online": 0, "offline": 0},
				"policies":          map[string]interface{}{"active": 0, "total": 0},
				"incidents":         map[string]interface{}{"today": 0, "critical": 0, "trend": 0},
				"files_classified":  0,
				"open_incidents":    0,
				"pending_approvals": 0,
			})
			return
		}
		if r.Method == "GET" {
			dashboardHandler.HandleStats(w, r)
		} else {
			http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		}
	})).ServeHTTP)

	// Classification Rules endpoints (V3.0)
	// Use database-backed handler when available, otherwise fall back to in-memory
	var dbRulesHandler *ClassificationRulesHandler
	var inMemoryRulesHandler *InMemoryRulesHandler
	var classificationRuleEngine *classification.RuleEngine

	if database != nil {
		// Create database-backed rule engine that loads rules from DB
		classificationRuleEngine = classification.NewRuleEngine(database.DB)
		dbRulesHandler = NewClassificationRulesHandler(classificationRuleEngine)
		log.Printf("[INFO] Using database-backed classification rules (loaded from DB)")
	} else {
		// Use in-memory when no database is available
		inMemoryRulesHandler = NewInMemoryRulesHandler()
		classificationRuleEngine = inMemoryRulesHandler.GetRuleEngine()
		log.Println("[INFO] Using in-memory storage for classification rules (database not available)")
	}

	// Wire the rule engine to events handler for classification
	if inMemHandler, ok := eventsHandler.(*InMemoryEventsHandler); ok {
		inMemHandler.SetRuleEngine(classificationRuleEngine)
		log.Println("[INFO] Wired classification rule engine to events handler (in-memory events handler)")
	}
	if dbHandler, ok := eventsHandler.(*EventsHandler); ok {
		dbHandler.SetRuleEngine(classificationRuleEngine)
		log.Println("[INFO] Wired classification rule engine to events handler (db-backed)")
	}

	mux.HandleFunc("/api/rules", corsHandler(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.Method {
		case "GET":
			if dbRulesHandler != nil {
				dbRulesHandler.HandleGetRules(w, r)
			} else if inMemoryRulesHandler != nil {
				inMemoryRulesHandler.HandleGetRules(w, r)
			} else {
				http.Error(w, "Rules service unavailable", http.StatusServiceUnavailable)
			}
		case "POST":
			if dbRulesHandler != nil {
				dbRulesHandler.HandleCreateRule(w, r)
			} else if inMemoryRulesHandler != nil {
				inMemoryRulesHandler.HandleCreateRule(w, r)
			} else {
				http.Error(w, "Rules service unavailable", http.StatusServiceUnavailable)
			}
		default:
			http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		}
	})).ServeHTTP)

	mux.HandleFunc("/api/rules/", corsHandler(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		idStr := r.URL.Path[len("/api/rules/"):]
		ruleID, err := strconv.Atoi(idStr)
		if err != nil {
			http.Error(w, "Invalid rule ID", http.StatusBadRequest)
			return
		}

		switch r.Method {
		case "PUT":
			if dbRulesHandler != nil {
				dbRulesHandler.HandleUpdateRule(w, r, ruleID)
			} else if inMemoryRulesHandler != nil {
				inMemoryRulesHandler.HandleUpdateRule(w, r, ruleID)
			} else {
				http.Error(w, "Rules service unavailable", http.StatusServiceUnavailable)
			}
		case "DELETE":
			if dbRulesHandler != nil {
				dbRulesHandler.HandleDeleteRule(w, r, ruleID)
			} else if inMemoryRulesHandler != nil {
				inMemoryRulesHandler.HandleDeleteRule(w, r, ruleID)
			} else {
				http.Error(w, "Rules service unavailable", http.StatusServiceUnavailable)
			}
		default:
			http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		}
	})).ServeHTTP)

	// Users, Roles, Permissions (v1) — always register so CORS headers are returned even if DB is unavailable
	mux.HandleFunc("/api/v1/users", corsHandler(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if usersHandler == nil {
			http.Error(w, "User service unavailable", http.StatusServiceUnavailable)
			return
		}
		switch r.Method {
		case "GET":
			usersHandler.ListUsers(w, r)
		case "POST":
			usersHandler.CreateUser(w, r)
		default:
			http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		}
	})).ServeHTTP)

	mux.HandleFunc("/api/v1/users/from-ad", corsHandler(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if usersHandler == nil {
			http.Error(w, "User service unavailable", http.StatusServiceUnavailable)
			return
		}
		if r.Method == "POST" {
			usersHandler.CreateUserFromAD(w, r)
			return
		}
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
	})).ServeHTTP)

	mux.HandleFunc("/api/v1/users/", corsHandler(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if usersHandler == nil {
			http.Error(w, "User service unavailable", http.StatusServiceUnavailable)
			return
		}
		switch r.Method {
		case "PUT":
			usersHandler.UpdateUser(w, r)
		case "DELETE":
			usersHandler.DeleteUser(w, r)
		default:
			http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		}
	})).ServeHTTP)

	mux.HandleFunc("/api/v1/ad/users", corsHandler(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if usersHandler == nil {
			http.Error(w, "User service unavailable", http.StatusServiceUnavailable)
			return
		}
		if r.Method == "GET" {
			usersHandler.ListADUsers(w, r)
			return
		}
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
	})).ServeHTTP)

	mux.HandleFunc("/api/v1/roles", corsHandler(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if usersHandler == nil {
			http.Error(w, "User service unavailable", http.StatusServiceUnavailable)
			return
		}
		if r.Method == "GET" {
			usersHandler.ListRoles(w, r)
			return
		}
		if r.Method == "POST" {
			usersHandler.CreateRole(w, r)
			return
		}
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
	})).ServeHTTP)

	mux.HandleFunc("/api/v1/roles/", corsHandler(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if usersHandler == nil {
			http.Error(w, "User service unavailable", http.StatusServiceUnavailable)
			return
		}
		switch r.Method {
		case "GET":
			usersHandler.GetRole(w, r)
		case "PUT":
			usersHandler.UpdateRole(w, r)
		case "DELETE":
			usersHandler.DeleteRole(w, r)
		default:
			http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		}
	})).ServeHTTP)

	mux.HandleFunc("/api/v1/permissions", corsHandler(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if usersHandler == nil {
			http.Error(w, "User service unavailable", http.StatusServiceUnavailable)
			return
		}
		if r.Method == "GET" {
			usersHandler.ListPermissions(w, r)
			return
		}
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
	})).ServeHTTP)

	// Event logging endpoints (v1)

	// Discovery v1 API (nmap)
	var discoveryHandler *DiscoveryHandler
	if database != nil {
		discoveryHandler = NewDiscoveryHandler(database.DB)
	}

	// GET/PUT discovery config, POST scan, GET history
	mux.HandleFunc("/api/v1/discovery/config", corsHandler(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method == "GET" {
			if discoveryHandler == nil {
				w.Header().Set("Content-Type", "application/json")
				w.WriteHeader(http.StatusServiceUnavailable)
				json.NewEncoder(w).Encode(map[string]interface{}{"error": "database unavailable"})
				return
			}
			discoveryHandler.GetConfig(w, r)
			return
		}
		if r.Method == "PUT" {
			if discoveryHandler == nil {
				http.Error(w, "database unavailable", http.StatusServiceUnavailable)
				return
			}
			discoveryHandler.UpdateConfig(w, r)
			return
		}
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
	})).ServeHTTP)

	mux.HandleFunc("/api/v1/discovery/scan", corsHandler(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method == "POST" {
			if discoveryHandler == nil {
				http.Error(w, "database unavailable", http.StatusServiceUnavailable)
				return
			}
			discoveryHandler.TriggerScan(w, r)
			return
		}
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
	})).ServeHTTP)

	mux.HandleFunc("/api/v1/discovery/history", corsHandler(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method == "GET" {
			if discoveryHandler == nil {
				w.Header().Set("Content-Type", "application/json")
				json.NewEncoder(w).Encode(map[string]interface{}{"history": []interface{}{}})
				return
			}
			discoveryHandler.GetScanHistory(w, r)
			return
		}
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
	})).ServeHTTP)
	if eventsHandler != nil {
		mux.HandleFunc("/api/v1/events/batch", corsHandler(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			if r.Method == "POST" {
				eventsHandler.ReceiveEventBatch(w, r)
				return
			}
			http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		})).ServeHTTP)

		// Classification endpoint for testing
		mux.HandleFunc("/api/classify", corsHandler(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			if r.Method == "POST" {
				eventsHandler.ClassifyFile(w, r)
				return
			}
			http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		})).ServeHTTP)

		mux.HandleFunc("/api/v1/event-logs", corsHandler(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			if r.Method == "GET" {
				eventsHandler.ListEventLogs(w, r)
				return
			}
			http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		})).ServeHTTP)

		mux.HandleFunc("/api/v1/incidents", corsHandler(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			if r.Method == "GET" {
				eventsHandler.ListIncidents(w, r)
				return
			}
			http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		})).ServeHTTP)

		mux.HandleFunc("/api/v1/incidents/", corsHandler(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			// supports PUT /api/v1/incidents/{id}/resolve
			if r.Method == "PUT" {
				eventsHandler.ResolveIncident(w, r)
				return
			}
			http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		})).ServeHTTP)
	}

	mux.HandleFunc("/api/dashboard/incidents-trend", corsHandler(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if dashboardHandler == nil {
			w.Header().Set("Content-Type", "application/json")
			json.NewEncoder(w).Encode(map[string]interface{}{"trend": []interface{}{}, "days": 7})
			return
		}
		if r.Method == "GET" {
			dashboardHandler.HandleIncidentsTrend(w, r)
		} else {
			http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		}
	})).ServeHTTP)

	mux.HandleFunc("/api/dashboard/top-violators", corsHandler(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if dashboardHandler == nil {
			w.Header().Set("Content-Type", "application/json")
			json.NewEncoder(w).Encode(map[string]interface{}{"violators": []interface{}{}})
			return
		}
		if r.Method == "GET" {
			dashboardHandler.HandleTopViolators(w, r)
		} else {
			http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		}
	})).ServeHTTP)

	mux.HandleFunc("/api/dashboard/top-destinations", corsHandler(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if dashboardHandler == nil {
			w.Header().Set("Content-Type", "application/json")
			json.NewEncoder(w).Encode(map[string]interface{}{"destinations": []interface{}{}})
			return
		}
		if r.Method == "GET" {
			dashboardHandler.HandleTopDestinations(w, r)
		} else {
			http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		}
	})).ServeHTTP)

	mux.HandleFunc("/api/dashboard/classification-distribution", corsHandler(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if dashboardHandler == nil {
			w.Header().Set("Content-Type", "application/json")
			json.NewEncoder(w).Encode(map[string]interface{}{"distribution": []interface{}{}})
			return
		}
		if r.Method == "GET" {
			dashboardHandler.HandleClassificationDistribution(w, r)
		} else {
			http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		}
	})).ServeHTTP)

	mux.HandleFunc("/api/dashboard/incidents-by-type", corsHandler(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if dashboardHandler == nil {
			w.Header().Set("Content-Type", "application/json")
			json.NewEncoder(w).Encode(map[string]interface{}{"by_type": []interface{}{}})
			return
		}
		if r.Method == "GET" {
			dashboardHandler.HandleIncidentsByType(w, r)
		} else {
			http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		}
	})).ServeHTTP)

	mux.HandleFunc("/api/dashboard/recent-activity", corsHandler(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if dashboardHandler == nil {
			w.Header().Set("Content-Type", "application/json")
			json.NewEncoder(w).Encode(map[string]interface{}{"activities": []interface{}{}})
			return
		}
		if r.Method == "GET" {
			dashboardHandler.HandleRecentActivity(w, r)
		} else {
			http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		}
	})).ServeHTTP)

	// Wrap the entire mux with CORS and JWT authentication. Every
	// administrative endpoint is protected; only the public paths listed in
	// isPublicPath are reachable without a valid Bearer token.
	return corsHandler(AuthMiddleware(mux))
}

func listPolicies(w http.ResponseWriter, r *http.Request, s *policy.Service) {
	if s == nil {
		// Return mock default policy if database not available
		mockPolicy := map[string]interface{}{
			"id":          "policy-usb-default-001",
			"name":        "USB Transfer Prevention",
			"description": "Prevent copying sensitive files to USB drives",
			"rules": []map[string]interface{}{
				{
					"id":          "rule-usb-block",
					"type":        "file-transfer-block",
					"source":      "local-machine",
					"destination": "removable-media",
					"action":      "block",
					"fileTypes": []string{
						".pdf", ".xlsx", ".xls", ".txt", ".doc", ".docx",
						".ppt", ".pptx", ".csv", ".json", ".xml", ".png", ".jpg", ".jpeg",
					},
					"logging":      true,
					"notification": true,
					"severity":     "high",
				},
			},
			"priority":   100,
			"enabled":    true,
			"is_default": true,
			"created_at": time.Now().Format(time.RFC3339),
			"updated_at": time.Now().Format(time.RFC3339),
		}
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode([]interface{}{mockPolicy})
		return
	}

	limit := 100
	offset := 0

	if l := r.URL.Query().Get("limit"); l != "" {
		if li, err := strconv.Atoi(l); err == nil {
			limit = li
		}
	}
	if o := r.URL.Query().Get("offset"); o != "" {
		if oi, err := strconv.Atoi(o); err == nil {
			offset = oi
		}
	}

	policies, err := s.ListPolicies(r.Context(), limit, offset)
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}

	// Convert to API format with is_default field
	type PolicyResponse struct {
		ID          string          `json:"id"`
		Name        string          `json:"name"`
		Description string          `json:"description"`
		Rules       json.RawMessage `json:"rules"`
		Priority    int             `json:"priority"`
		Enabled     bool            `json:"enabled"`
		IsDefault   bool            `json:"is_default"`
		CreatedAt   string          `json:"created_at"`
		UpdatedAt   string          `json:"updated_at"`
	}

	var response []PolicyResponse
	for _, p := range policies {
		// Check if policy is default (by name for now, or add to Policy struct)
		isDefault := p.Name == "USB Transfer Prevention"

		response = append(response, PolicyResponse{
			ID:          p.ID.String(),
			Name:        p.Name,
			Description: p.Description,
			Rules:       p.Rules,
			Priority:    p.Priority,
			Enabled:     p.Enabled,
			IsDefault:   isDefault,
			CreatedAt:   p.CreatedAt.Format(time.RFC3339),
			UpdatedAt:   p.UpdatedAt.Format(time.RFC3339),
		})
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(response)
}

// Discovery handlers
func handleStartDiscovery(w http.ResponseWriter, r *http.Request, discoveryService *discovery.Service) {
	if discoveryService.IsScanInProgress() {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusConflict)
		json.NewEncoder(w).Encode(map[string]interface{}{
			"error": "Discovery scan already in progress",
		})
		return
	}

	// Generate discovery ID
	discoveryID := uuid.New().String()

	// Start discovery in background goroutine
	ctx, cancel := context.WithCancel(context.Background())
	discoveryService.SetCancelFunc(cancel)

	go func() {
		if err := discoveryService.DiscoverDevices(ctx); err != nil {
			if err != context.Canceled {
				log.Printf("Discovery error: %v", err)
			}
		}
	}()

	response := map[string]interface{}{
		"success":      true,
		"discoveryId":  discoveryID,
		"status":       "started",
		"message":      "Network discovery initiated",
		"pollInterval": 1000,
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(response)
}

func handleGetDiscoveryProgress(w http.ResponseWriter, r *http.Request, discoveryService *discovery.Service) {
	progress := discoveryService.GetProgress()

	w.Header().Set("Content-Type", "application/json")
	if err := json.NewEncoder(w).Encode(map[string]interface{}{
		"data": progress,
	}); err != nil {
		log.Printf("Error encoding discovery progress: %v", err)
		http.Error(w, "Internal server error", http.StatusInternalServerError)
	}
}

func handleStopDiscovery(w http.ResponseWriter, r *http.Request, discoveryService *discovery.Service) {
	discoveryService.StopScan()

	response := map[string]interface{}{
		"status":  "stopped",
		"message": "Discovery scan stopped",
	}

	w.Header().Set("Content-Type", "application/json")
	if err := json.NewEncoder(w).Encode(response); err != nil {
		log.Printf("Error encoding discovery stop response: %v", err)
		http.Error(w, "Internal server error", http.StatusInternalServerError)
	}
}

func createPolicy(w http.ResponseWriter, r *http.Request, s *policy.Service) {
	var p policy.Policy
	if err := json.NewDecoder(r.Body).Decode(&p); err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}

	if err := s.CreatePolicy(r.Context(), &p); err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(p)
}

func getPolicy(w http.ResponseWriter, r *http.Request, s *policy.Service) {
	idStr := r.URL.Path[len("/api/policies/"):]
	id, err := uuid.Parse(idStr)
	if err != nil {
		http.Error(w, "Invalid policy ID", http.StatusBadRequest)
		return
	}

	p, err := s.GetPolicyByID(r.Context(), id)
	if err != nil {
		http.Error(w, err.Error(), http.StatusNotFound)
		return
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(p)
}

func updatePolicy(w http.ResponseWriter, r *http.Request, s *policy.Service) {
	if s == nil {
		http.Error(w, "Database not available", http.StatusServiceUnavailable)
		return
	}

	idStr := r.URL.Path[len("/api/policies/"):]
	id, err := uuid.Parse(idStr)
	if err != nil {
		http.Error(w, "Invalid policy ID", http.StatusBadRequest)
		return
	}

	var req struct {
		Enabled     *bool  `json:"enabled"`
		Name        string `json:"name"`
		Description string `json:"description"`
		Rules       string `json:"rules"`
		Priority    *int   `json:"priority"`
	}

	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}

	// Get existing policy
	existingPolicy, err := s.GetPolicyByID(r.Context(), id)
	if err != nil {
		http.Error(w, "Policy not found", http.StatusNotFound)
		return
	}

	// Update fields
	if req.Enabled != nil {
		existingPolicy.Enabled = *req.Enabled
	}
	if req.Name != "" {
		existingPolicy.Name = req.Name
	}
	if req.Description != "" {
		existingPolicy.Description = req.Description
	}
	if req.Rules != "" {
		existingPolicy.Rules = json.RawMessage(req.Rules)
	}
	if req.Priority != nil {
		existingPolicy.Priority = *req.Priority
	}

	if err := s.UpdatePolicy(r.Context(), existingPolicy); err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(map[string]interface{}{
		"success": true,
		"message": "Policy updated",
	})
}

func deletePolicy(w http.ResponseWriter, r *http.Request, s *policy.Service) {
	idStr := r.URL.Path[len("/api/policies/"):]
	id, err := uuid.Parse(idStr)
	if err != nil {
		http.Error(w, "Invalid policy ID", http.StatusBadRequest)
		return
	}

	if err := s.DeletePolicy(r.Context(), id); err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}

	w.WriteHeader(http.StatusNoContent)
}

func listEndpoints(w http.ResponseWriter, r *http.Request, s *endpoints.Service) {
	limit := 100
	offset := 0

	if l := r.URL.Query().Get("limit"); l != "" {
		if li, err := strconv.Atoi(l); err == nil {
			limit = li
		}
	}
	if o := r.URL.Query().Get("offset"); o != "" {
		if oi, err := strconv.Atoi(o); err == nil {
			offset = oi
		}
	}

	endpoints, err := s.ListEndpoints(r.Context(), limit, offset)
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(endpoints)
}

func listEvents(w http.ResponseWriter, r *http.Request, s *telemetry.Service) {
	filters := telemetry.EventFilters{
		Limit:  100,
		Offset: 0,
	}

	if l := r.URL.Query().Get("limit"); l != "" {
		if li, err := strconv.Atoi(l); err == nil {
			filters.Limit = li
		}
	}
	if o := r.URL.Query().Get("offset"); o != "" {
		if oi, err := strconv.Atoi(o); err == nil {
			filters.Offset = oi
		}
	}
	if agentID := r.URL.Query().Get("agent_id"); agentID != "" {
		filters.AgentID = agentID
	}
	if eventType := r.URL.Query().Get("event_type"); eventType != "" {
		filters.EventType = eventType
	}
	if severity := r.URL.Query().Get("severity"); severity != "" {
		filters.Severity = severity
	}

	events, err := s.GetEvents(r.Context(), filters)
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(events)
}

func listIncidents(w http.ResponseWriter, r *http.Request, s *alerts.Service) {
	limit := 100
	offset := 0
	var resolved *bool

	if l := r.URL.Query().Get("limit"); l != "" {
		if li, err := strconv.Atoi(l); err == nil {
			limit = li
		}
	}
	if o := r.URL.Query().Get("offset"); o != "" {
		if oi, err := strconv.Atoi(o); err == nil {
			offset = oi
		}
	}
	if r := r.URL.Query().Get("resolved"); r != "" {
		if b, err := strconv.ParseBool(r); err == nil {
			resolved = &b
		}
	}

	incidents, err := s.GetIncidents(r.Context(), limit, offset, resolved)
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(incidents)
}

func resolveIncident(w http.ResponseWriter, r *http.Request, s *alerts.Service) {
	idStr := r.URL.Path[len("/api/incidents/"):]
	id, err := strconv.ParseInt(idStr, 10, 64)
	if err != nil {
		http.Error(w, "Invalid incident ID", http.StatusBadRequest)
		return
	}

	var req struct {
		ResolvedBy string `json:"resolved_by"`
		Notes      string `json:"notes"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}

	if err := s.ResolveIncident(r.Context(), id, req.ResolvedBy, req.Notes); err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}

	w.WriteHeader(http.StatusNoContent)
}
