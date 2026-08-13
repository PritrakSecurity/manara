package api

import (
	"crypto/aes"
	"crypto/cipher"
	"database/sql"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"net/http"
	"time"

	"github.com/go-ldap/ldap/v3"
	"github.com/google/uuid"
)

// AESEncryptKey is the AES-256 key used to encrypt AD passwords at rest.
// It is injected from config at startup (see main.go) and must be 32 bytes.
var AESEncryptKey string

// SettingsHandler handles AD configuration and settings
type SettingsHandler struct {
	db *sql.DB
}

// NewSettingsHandler creates a new settings handler
func NewSettingsHandler(db *sql.DB) *SettingsHandler {
	return &SettingsHandler{db: db}
}

// ADConfig represents Active Directory configuration
type ADConfig struct {
	ID                string     `json:"id"`
	Server            string     `json:"server"`
	Port              int        `json:"port"`
	Username          string     `json:"username"`
	BaseDN            string     `json:"base_dn"`
	TestResultStatus  string     `json:"test_result_status"`
	TestResultMessage string     `json:"test_result_message"`
	LastTestedAt      *time.Time `json:"last_tested_at"`
	LastSyncedAt      *time.Time `json:"last_synced_at"`
	CreatedAt         time.Time  `json:"created_at"`
	UpdatedAt         time.Time  `json:"updated_at"`
}

// CreateADConfigRequest is the request body for creating/updating AD config
type CreateADConfigRequest struct {
	Server   string `json:"server"`
	Port     int    `json:"port"`
	Username string `json:"username"`
	Password string `json:"password"`
	BaseDN   string `json:"base_dn"`
}

// TestADConnectionRequest is the request body for testing AD connection
type TestADConnectionRequest struct {
	Server   string `json:"server"`
	Port     int    `json:"port"`
	Username string `json:"username"`
	Password string `json:"password"`
	BaseDN   string `json:"base_dn"`
}

// Helper function to encrypt password (use environment variable for key in production)
func encryptPassword(password string) (string, error) {
	block, err := aes.NewCipher([]byte(AESEncryptKey))
	if err != nil {
		return "", err
	}

	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return "", err
	}

	nonce := make([]byte, gcm.NonceSize())
	ciphertext := gcm.Seal(nonce, nonce, []byte(password), nil)

	return hex.EncodeToString(ciphertext), nil
}

// Helper function to decrypt password
func decryptPassword(encryptedHex string) (string, error) {
	ciphertext, err := hex.DecodeString(encryptedHex)
	if err != nil {
		return "", err
	}

	block, err := aes.NewCipher([]byte(AESEncryptKey))
	if err != nil {
		return "", err
	}

	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return "", err
	}

	nonceSize := gcm.NonceSize()
	nonce, ciphertext := ciphertext[:nonceSize], ciphertext[nonceSize:]

	plaintext, err := gcm.Open(nil, nonce, ciphertext, nil)
	if err != nil {
		return "", err
	}

	return string(plaintext), nil
}

// GetADConfiguration retrieves the current AD configuration
func (h *SettingsHandler) GetADConfiguration(w http.ResponseWriter, r *http.Request) {
	if h.db == nil {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusNotFound)
		json.NewEncoder(w).Encode(map[string]interface{}{
			"success": false,
			"message": "Database not available",
		})
		return
	}

	var config ADConfig

	err := h.db.QueryRow(`
		SELECT id, server, port, username, base_dn,
		       test_result_status, test_result_message,
		       last_tested_at, last_synced_at, created_at, updated_at
		FROM ad_configuration
		WHERE is_active = true
		ORDER BY created_at DESC
		LIMIT 1
	`).Scan(
		&config.ID, &config.Server, &config.Port, &config.Username, &config.BaseDN,
		&config.TestResultStatus, &config.TestResultMessage,
		&config.LastTestedAt, &config.LastSyncedAt, &config.CreatedAt, &config.UpdatedAt,
	)

	if err == sql.ErrNoRows {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusNotFound)
		json.NewEncoder(w).Encode(map[string]interface{}{
			"success": false,
			"message": "No AD configuration found",
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
		"data":    config,
	})
}

// CreateADConfiguration saves AD configuration to database
func (h *SettingsHandler) CreateADConfiguration(w http.ResponseWriter, r *http.Request) {
	if h.db == nil {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusServiceUnavailable)
		json.NewEncoder(w).Encode(map[string]interface{}{
			"success": false,
			"message": "Database not available",
		})
		return
	}

	var req CreateADConfigRequest

	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusBadRequest)
		json.NewEncoder(w).Encode(map[string]interface{}{
			"success": false,
			"message": "Invalid request body",
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
		req.BaseDN = "DC=corp,DC=example,DC=com" // Default
	}

	// Encrypt password before storing
	encryptedPassword, err := encryptPassword(req.Password)
	if err != nil {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusInternalServerError)
		json.NewEncoder(w).Encode(map[string]interface{}{
			"success": false,
			"message": "Failed to encrypt password",
		})
		return
	}

	// Deactivate existing configs
	_, err = h.db.Exec("UPDATE ad_configuration SET is_active = false WHERE is_active = true")
	if err != nil {
		// Log but don't fail
		fmt.Printf("Warning: Failed to deactivate existing configs: %v\n", err)
	}

	configID := uuid.New().String()

	_, err = h.db.Exec(`
		INSERT INTO ad_configuration
		(id, server, port, username, password_encrypted, base_dn,
		 test_result_status, is_active, created_at, updated_at)
		VALUES ($1, $2, $3, $4, $5, $6, 'untested', true, NOW(), NOW())
	`, configID, req.Server, req.Port, req.Username, encryptedPassword, req.BaseDN)

	if err != nil {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusInternalServerError)
		json.NewEncoder(w).Encode(map[string]interface{}{
			"success": false,
			"message": "Failed to save configuration: " + err.Error(),
		})
		return
	}

	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusCreated)
	json.NewEncoder(w).Encode(map[string]interface{}{
		"success": true,
		"message": "AD configuration saved successfully",
		"data": map[string]interface{}{
			"id":     configID,
			"server": req.Server,
			"port":   req.Port,
		},
	})
}

// TestADConnection tests LDAP connection with provided credentials
func (h *SettingsHandler) TestADConnection(w http.ResponseWriter, r *http.Request) {
	var req TestADConnectionRequest

	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusBadRequest)
		json.NewEncoder(w).Encode(map[string]interface{}{
			"success": false,
			"message": "Invalid request body",
		})
		return
	}

	// Validate
	if req.Server == "" || req.Port == 0 || req.Username == "" || req.Password == "" {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusBadRequest)
		json.NewEncoder(w).Encode(map[string]interface{}{
			"success": false,
			"message": "Missing required fields",
		})
		return
	}

	// Connect to AD
	addr := fmt.Sprintf("%s:%d", req.Server, req.Port)
	conn, err := ldap.Dial("tcp", addr)
	if err != nil {
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(map[string]interface{}{
			"success":   false,
			"connected": false,
			"message":   "Failed to connect to AD server: " + err.Error(),
		})
		return
	}
	defer conn.Close()

	// Try to bind with credentials
	err = conn.Bind(req.Username, req.Password)
	if err != nil {
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(map[string]interface{}{
			"success":   false,
			"connected": false,
			"message":   "Failed to authenticate: " + err.Error(),
		})
		return
	}

	// Search for computers
	baseDN := req.BaseDN
	if baseDN == "" {
		baseDN = "DC=corp,DC=example,DC=com"
	}

	searchRequest := ldap.NewSearchRequest(
		baseDN,
		ldap.ScopeWholeSubtree,
		ldap.NeverDerefAliases,
		0,
		0,
		false,
		"(&(objectClass=computer)(objectCategory=computer))",
		[]string{"cn", "operatingSystem", "ipv4Address", "lastLogonTimestamp"},
		nil,
	)

	sr, err := conn.Search(searchRequest)
	if err != nil {
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(map[string]interface{}{
			"success":   false,
			"connected": false,
			"message":   "Failed to search for computers: " + err.Error(),
		})
		return
	}

	computerCount := len(sr.Entries)

	// Update test result in database if config exists and db is available
	if h.db != nil {
		h.db.Exec(`
			UPDATE ad_configuration
			SET test_result_status = 'success',
			    test_result_message = $1,
			    last_tested_at = NOW()
			WHERE is_active = true
		`, fmt.Sprintf("Connected successfully. Found %d computers.", computerCount))
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(map[string]interface{}{
		"success":       true,
		"connected":     true,
		"message":       "Connection successful!",
		"computerCount": computerCount,
		"details": map[string]interface{}{
			"server":         req.Server,
			"baseDN":         baseDN,
			"foundComputers": computerCount,
		},
	})
}

// GetADConfigurationStatus gets the status of AD configuration
func (h *SettingsHandler) GetADConfigurationStatus(w http.ResponseWriter, r *http.Request) {
	if h.db == nil {
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(map[string]interface{}{
			"success": true,
			"data": map[string]interface{}{
				"isConfigured": false,
			},
		})
		return
	}

	var isConfigured bool
	var server string
	var port int
	var lastTestResult sql.NullString
	var lastTestedAt sql.NullTime
	var lastSyncedAt sql.NullTime
	var devicesSynced int

	err := h.db.QueryRow(`
		SELECT
			COALESCE(server, '') != '' as is_configured,
			COALESCE(server, ''),
			COALESCE(port, 389),
			test_result_status,
			last_tested_at,
			last_synced_at,
			COALESCE((SELECT COUNT(*) FROM devices), 0)
		FROM ad_configuration
		WHERE is_active = true
		LIMIT 1
	`).Scan(&isConfigured, &server, &port, &lastTestResult, &lastTestedAt, &lastSyncedAt, &devicesSynced)

	if err == sql.ErrNoRows {
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(map[string]interface{}{
			"success": true,
			"data": map[string]interface{}{
				"isConfigured": false,
			},
		})
		return
	}

	if err != nil {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusInternalServerError)
		json.NewEncoder(w).Encode(map[string]interface{}{
			"success": false,
			"message": "Database error",
		})
		return
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(map[string]interface{}{
		"success": true,
		"data": map[string]interface{}{
			"isConfigured":   isConfigured,
			"server":         server,
			"port":           port,
			"lastTestResult": lastTestResult.String,
			"lastTestedAt":   lastTestedAt.Time,
			"lastSyncedAt":   lastSyncedAt.Time,
			"devicesSynced":  devicesSynced,
		},
	})
}

// GetSettings returns application settings stored in the settings table (key = 'system')
func (h *SettingsHandler) GetSettings(w http.ResponseWriter, r *http.Request) {
	if h.db == nil {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusServiceUnavailable)
		json.NewEncoder(w).Encode(map[string]interface{}{"success": false, "message": "Database not available"})
		return
	}

	var valueBytes []byte
	err := h.db.QueryRow(`SELECT value FROM settings WHERE key = 'system' LIMIT 1`).Scan(&valueBytes)
	if err == sql.ErrNoRows {
		// Return defaults if not present
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(map[string]interface{}{"success": true, "data": map[string]interface{}{"systemName":"PRITRAK DLP","timezone":"UTC"}})
		return
	}
	if err != nil {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusInternalServerError)
		json.NewEncoder(w).Encode(map[string]interface{}{"success": false, "message": "Database error"})
		return
	}

	var out interface{}
	if err := json.Unmarshal(valueBytes, &out); err != nil {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusInternalServerError)
		json.NewEncoder(w).Encode(map[string]interface{}{"success": false, "message": "Failed to parse settings"})
		return
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(map[string]interface{}{"success": true, "data": out})
}

// UpdateSettings upserts the system settings
func (h *SettingsHandler) UpdateSettings(w http.ResponseWriter, r *http.Request) {
	if h.db == nil {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusServiceUnavailable)
		json.NewEncoder(w).Encode(map[string]interface{}{"success": false, "message": "Database not available"})
		return
	}

	var payload map[string]interface{}
	if err := json.NewDecoder(r.Body).Decode(&payload); err != nil {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusBadRequest)
		json.NewEncoder(w).Encode(map[string]interface{}{"success": false, "message": "Invalid request body"})
		return
	}

	bytes, err := json.Marshal(payload)
	if err != nil {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusInternalServerError)
		json.NewEncoder(w).Encode(map[string]interface{}{"success": false, "message": "Failed to encode settings"})
		return
	}

	// Upsert
	_, err = h.db.Exec(`INSERT INTO settings (id, key, value, created_at, updated_at)
		VALUES ($1,'system',$2,NOW(),NOW())
		ON CONFLICT (key) DO UPDATE SET value = $2, updated_at = NOW()`, uuid.New().String(), string(bytes))

	if err != nil {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusInternalServerError)
		json.NewEncoder(w).Encode(map[string]interface{}{"success": false, "message": "Failed to save settings"})
		return
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(map[string]interface{}{"success": true, "message": "Settings saved"})
}
