package api

import (
	"database/sql"
	"encoding/json"
	"fmt"
	"log"
	"net/http"
	"strings"
	"time"

	"github.com/google/uuid"
	"golang.org/x/crypto/bcrypt"
)

type User struct {
	ID         string    `json:"id"`
	Username   string    `json:"username"`
	Email      string    `json:"email"`
	FirstName  string    `json:"first_name"`
	LastName   string    `json:"last_name"`
	IsActive   bool      `json:"is_active"`
	IsADSynced bool      `json:"is_ad_synced"`
	Roles      []Role    `json:"roles,omitempty"`
	CreatedAt  time.Time `json:"created_at"`
	UpdatedAt  time.Time `json:"updated_at"`
}

type Role struct {
	ID          string       `json:"id"`
	Name        string       `json:"name"`
	Description string       `json:"description"`
	Permissions []Permission `json:"permissions,omitempty"`
	CreatedAt   time.Time    `json:"created_at"`
	UpdatedAt   time.Time    `json:"updated_at"`
}

type Permission struct {
	ID          string `json:"id"`
	Name        string `json:"name"`
	Resource    string `json:"resource"`
	Action      string `json:"action"`
	Description string `json:"description"`
}

type UsersHandler struct {
	db *sql.DB
}

func NewUsersHandler(db *sql.DB) *UsersHandler {
	return &UsersHandler{db: db}
}

// GET /api/v1/users
func (h *UsersHandler) ListUsers(w http.ResponseWriter, r *http.Request) {
	limit := 50
	offset := 0
	q := r.URL.Query()
	if l := q.Get("limit"); l != "" {
		fmt.Sscanf(l, "%d", &limit)
	}
	if o := q.Get("offset"); o != "" {
		fmt.Sscanf(o, "%d", &offset)
	}

	query := `
        SELECT id, username, email, first_name, last_name, is_active, is_ad_synced, created_at, updated_at
        FROM users
        WHERE is_active = true
        ORDER BY created_at DESC
        LIMIT $1 OFFSET $2
    `

	rows, err := h.db.Query(query, limit, offset)
	if err != nil {
		http.Error(w, "database error", http.StatusInternalServerError)
		log.Printf("[ERROR] Failed to list users: %v", err)
		return
	}
	defer rows.Close()

	users := []User{}
	for rows.Next() {
		var u User
		if err := rows.Scan(&u.ID, &u.Username, &u.Email, &u.FirstName, &u.LastName, &u.IsActive, &u.IsADSynced, &u.CreatedAt, &u.UpdatedAt); err != nil {
			continue
		}
		u.Roles = h.getUserRoles(u.ID)
		users = append(users, u)
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(map[string]interface{}{
		"users":  users,
		"total":  len(users),
		"limit":  limit,
		"offset": offset,
	})
}

// POST /api/v1/users
func (h *UsersHandler) CreateUser(w http.ResponseWriter, r *http.Request) {
	var req struct {
		Username           string   `json:"username"`
		Email              string   `json:"email"`
		FirstName          string   `json:"first_name"`
		LastName           string   `json:"last_name"`
		RoleIDs            []string `json:"role_ids"`
		Password           string   `json:"password,omitempty"`
		ForcePasswordChange bool    `json:"force_password_change,omitempty"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		http.Error(w, "invalid request", http.StatusBadRequest)
		return
	}
	if strings.TrimSpace(req.Username) == "" {
		http.Error(w, "username required", http.StatusBadRequest)
		return
	}

	userID := uuid.New().String()
	now := time.Now()

	// Check if users table has password_hash and password_reset_required columns
	hasPasswordCol := h.hasColumn("users", "password_hash")
	hasResetCol := h.hasColumn("users", "password_reset_required")

	if hasPasswordCol && req.Password != "" {
		// Hash password using bcrypt
		hash, err := bcrypt.GenerateFromPassword([]byte(req.Password), bcrypt.DefaultCost)
		if err != nil {
			http.Error(w, "failed to hash password", http.StatusInternalServerError)
			log.Printf("[ERROR] Failed to hash password: %v", err)
			return
		}

		if hasResetCol {
			insertQuery := `INSERT INTO users (id, username, email, first_name, last_name, password_hash, is_active, is_ad_synced, created_at, updated_at, password_reset_required)
        VALUES ($1,$2,$3,$4,$5,$6,true,false,$7,$8,$9)`

			// Execute insert with password and reset flag
			if _, err := h.db.Exec(insertQuery, userID, req.Username, req.Email, req.FirstName, req.LastName, string(hash), now, now, req.ForcePasswordChange); err != nil {
				http.Error(w, "failed to create user", http.StatusInternalServerError)
				log.Printf("[ERROR] Failed to create user: %v", err)
				return
			}
		} else {
			// Insert without reset flag
			insertQuery := `INSERT INTO users (id, username, email, first_name, last_name, password_hash, is_active, is_ad_synced, created_at, updated_at)
        VALUES ($1,$2,$3,$4,$5,$6,true,false,$7,$8)`

			if _, err := h.db.Exec(insertQuery, userID, req.Username, req.Email, req.FirstName, req.LastName, string(hash), now, now); err != nil {
				http.Error(w, "failed to create user", http.StatusInternalServerError)
				log.Printf("[ERROR] Failed to create user: %v", err)
				return
			}
		}
	} else {
		insertQuery := `INSERT INTO users (id, username, email, first_name, last_name, is_active, is_ad_synced, created_at, updated_at)
        VALUES ($1,$2,$3,$4,$5,true,false,$6,$7)`

		if _, err := h.db.Exec(insertQuery, userID, req.Username, req.Email, req.FirstName, req.LastName, now, now); err != nil {
			http.Error(w, "failed to create user", http.StatusInternalServerError)
			log.Printf("[ERROR] Failed to create user: %v", err)
			return
		}
	}

	if len(req.RoleIDs) > 0 {
		h.assignRolesToUser(userID, req.RoleIDs)
	}

	user := User{
		ID:         userID,
		Username:   req.Username,
		Email:      req.Email,
		FirstName:  req.FirstName,
		LastName:   req.LastName,
		IsActive:   true,
		IsADSynced: false,
		Roles:      h.getUserRoles(userID),
		CreatedAt:  now,
		UpdatedAt:  now,
	}

	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusCreated)
	json.NewEncoder(w).Encode(map[string]interface{}{"message": "user created", "user": user})
	log.Printf("[USER] Created user: %s (%s)", req.Username, userID)
}

// PUT /api/v1/users/{id}
func (h *UsersHandler) UpdateUser(w http.ResponseWriter, r *http.Request) {
	id := strings.TrimPrefix(r.URL.Path, "/api/v1/users/")
	if id == "" {
		http.Error(w, "missing user id", http.StatusBadRequest)
		return
	}

	var req struct {
		Email              string   `json:"email"`
		FirstName          string   `json:"first_name"`
		LastName           string   `json:"last_name"`
		IsActive           *bool    `json:"is_active"`
		RoleIDs            []string `json:"role_ids"`
		Password           string   `json:"password,omitempty"`
		ForcePasswordChange *bool   `json:"force_password_change,omitempty"`
	}

	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		http.Error(w, "invalid request", http.StatusBadRequest)
		return
	}

	// Use COALESCE pattern
	updateQuery := `
        UPDATE users
        SET email = COALESCE(NULLIF($1, ''), email),
            first_name = COALESCE(NULLIF($2, ''), first_name),
            last_name = COALESCE(NULLIF($3, ''), last_name),
            is_active = COALESCE($4, is_active),
            updated_at = NOW()
        WHERE id = $5
    `

	isActiveVal := true
	if req.IsActive != nil {
		isActiveVal = *req.IsActive
	}

	if _, err := h.db.Exec(updateQuery, req.Email, req.FirstName, req.LastName, isActiveVal, id); err != nil {
		http.Error(w, "failed to update user", http.StatusInternalServerError)
		return
	}

	// If password update is requested and database supports password_hash, update it.
	if strings.TrimSpace(req.Password) != "" {
		if h.hasColumn("users", "password_hash") {
			hash, err := bcrypt.GenerateFromPassword([]byte(req.Password), bcrypt.DefaultCost)
			if err != nil {
				log.Printf("[ERROR] Failed to hash password on update: %v", err)
			} else {
				reset := false
				if req.ForcePasswordChange != nil {
					reset = *req.ForcePasswordChange
				}
				_, err := h.db.Exec("UPDATE users SET password_hash=$1, password_reset_required=$2, updated_at=NOW() WHERE id=$3", string(hash), reset, id)
				if err != nil {
					log.Printf("[ERROR] Failed to update password: %v", err)
				}
			}
		} else {
			log.Printf("[WARN] Password update requested but users.password_hash column not found. Skipping.")
		}
	}

	if len(req.RoleIDs) > 0 {
		h.db.Exec("DELETE FROM user_roles WHERE user_id = $1", id)
		h.assignRolesToUser(id, req.RoleIDs)
	}

	user, _ := h.getFullUser(id)
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(map[string]interface{}{"message": "user updated", "user": user})
}

// DELETE /api/v1/users/{id}
func (h *UsersHandler) DeleteUser(w http.ResponseWriter, r *http.Request) {
	id := strings.TrimPrefix(r.URL.Path, "/api/v1/users/")
	if id == "" {
		http.Error(w, "missing user id", http.StatusBadRequest)
		return
	}

	query := "UPDATE users SET is_active = false, updated_at = NOW() WHERE id = $1"
	result, err := h.db.Exec(query, id)
	if err != nil {
		http.Error(w, "failed to delete user", http.StatusInternalServerError)
		return
	}
	rowsAffected, _ := result.RowsAffected()
	if rowsAffected == 0 {
		http.Error(w, "user not found", http.StatusNotFound)
		return
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(map[string]interface{}{"message": "user deleted"})
}

// GET /api/v1/roles
func (h *UsersHandler) ListRoles(w http.ResponseWriter, r *http.Request) {
	rows, err := h.db.Query(`SELECT id, name, description, created_at, updated_at FROM roles ORDER BY name`)
	if err != nil {
		http.Error(w, "database error", http.StatusInternalServerError)
		return
	}
	defer rows.Close()

	roles := []Role{}
	for rows.Next() {
		var rle Role
		if err := rows.Scan(&rle.ID, &rle.Name, &rle.Description, &rle.CreatedAt, &rle.UpdatedAt); err != nil {
			continue
		}
		rle.Permissions = h.getRolePermissions(rle.ID)
		roles = append(roles, rle)
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(map[string]interface{}{"roles": roles})
}

// POST /api/v1/roles
func (h *UsersHandler) CreateRole(w http.ResponseWriter, r *http.Request) {
	var req struct {
		Name          string   `json:"name"`
		Description   string   `json:"description"`
		PermissionIDs []string `json:"permission_ids"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		http.Error(w, "invalid request", http.StatusBadRequest)
		return
	}
	if strings.TrimSpace(req.Name) == "" {
		http.Error(w, "name required", http.StatusBadRequest)
		return
	}

	roleID := uuid.New().String()
	now := time.Now()

	if _, err := h.db.Exec(`INSERT INTO roles (id, name, description, created_at, updated_at) VALUES ($1,$2,$3,$4,$5)`, roleID, req.Name, req.Description, now, now); err != nil {
		http.Error(w, "failed to create role", http.StatusInternalServerError)
		return
	}

	for _, permID := range req.PermissionIDs {
		h.db.Exec(`INSERT INTO role_permissions (id, role_id, permission_id, assigned_at) VALUES ($1,$2,$3,NOW())`, uuid.New().String(), roleID, permID)
	}

	role := Role{ID: roleID, Name: req.Name, Description: req.Description, Permissions: h.getRolePermissions(roleID), CreatedAt: now, UpdatedAt: now}
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusCreated)
	json.NewEncoder(w).Encode(map[string]interface{}{"message": "role created", "role": role})
}

// GET /api/v1/roles/:id
func (h *UsersHandler) GetRole(w http.ResponseWriter, r *http.Request) {
	id := strings.TrimPrefix(r.URL.Path, "/api/v1/roles/")
	if id == "" {
		http.Error(w, "missing role id", http.StatusBadRequest)
		return
	}

	var role Role
	query := `SELECT id, name, description, created_at, updated_at FROM roles WHERE id = $1`
	err := h.db.QueryRow(query, id).Scan(&role.ID, &role.Name, &role.Description, &role.CreatedAt, &role.UpdatedAt)
	if err == sql.ErrNoRows {
		http.Error(w, "role not found", http.StatusNotFound)
		return
	}
	if err != nil {
		http.Error(w, "database error", http.StatusInternalServerError)
		return
	}

	role.Permissions = h.getRolePermissions(role.ID)

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(map[string]interface{}{"role": role})
}

// PUT /api/v1/roles/:id
func (h *UsersHandler) UpdateRole(w http.ResponseWriter, r *http.Request) {
	id := strings.TrimPrefix(r.URL.Path, "/api/v1/roles/")
	if id == "" {
		http.Error(w, "missing role id", http.StatusBadRequest)
		return
	}

	// Check if role is system role
	var isSystem bool
	err := h.db.QueryRow("SELECT COALESCE(is_system, FALSE) FROM roles WHERE id = $1", id).Scan(&isSystem)
	if err == sql.ErrNoRows {
		http.Error(w, "role not found", http.StatusNotFound)
		return
	}
	if err != nil {
		http.Error(w, "database error", http.StatusInternalServerError)
		return
	}

	if isSystem {
		http.Error(w, "cannot edit system role", http.StatusForbidden)
		return
	}

	var req struct {
		Name          string   `json:"name"`
		Description   string   `json:"description"`
		PermissionIDs []string `json:"permission_ids"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		http.Error(w, "invalid request", http.StatusBadRequest)
		return
	}

	// Update role details
	if req.Name != "" || req.Description != "" {
		updateQuery := `UPDATE roles SET updated_at = NOW()`
		args := []interface{}{id}
		argIdx := 2

		if req.Name != "" {
			updateQuery += fmt.Sprintf(", name = $%d", argIdx)
			args = append(args, req.Name)
			argIdx++
		}
		if req.Description != "" {
			updateQuery += fmt.Sprintf(", description = $%d", argIdx)
			args = append(args, req.Description)
			argIdx++
		}

		updateQuery += " WHERE id = $1"
		if _, err := h.db.Exec(updateQuery, args...); err != nil {
			http.Error(w, "failed to update role", http.StatusInternalServerError)
			return
		}
	}

	// Update permissions if provided
	if len(req.PermissionIDs) > 0 {
		// Delete existing permissions
		h.db.Exec("DELETE FROM role_permissions WHERE role_id = $1", id)

		// Insert new permissions
		for _, permID := range req.PermissionIDs {
			h.db.Exec(`INSERT INTO role_permissions (id, role_id, permission_id, assigned_at) VALUES ($1,$2,$3,NOW())`,
				uuid.New().String(), id, permID)
		}
	}

	// Fetch updated role
	role, err := h.getFullRole(id)
	if err != nil {
		http.Error(w, "failed to fetch updated role", http.StatusInternalServerError)
		return
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(map[string]interface{}{"message": "role updated", "role": role})
}

// DELETE /api/v1/roles/:id
func (h *UsersHandler) DeleteRole(w http.ResponseWriter, r *http.Request) {
	id := strings.TrimPrefix(r.URL.Path, "/api/v1/roles/")
	if id == "" {
		http.Error(w, "missing role id", http.StatusBadRequest)
		return
	}

	// Check if role is system role
	var isSystem bool
	err := h.db.QueryRow("SELECT COALESCE(is_system, FALSE) FROM roles WHERE id = $1", id).Scan(&isSystem)
	if err == sql.ErrNoRows {
		http.Error(w, "role not found", http.StatusNotFound)
		return
	}
	if err != nil {
		http.Error(w, "database error", http.StatusInternalServerError)
		return
	}

	if isSystem {
		http.Error(w, "cannot delete system role", http.StatusForbidden)
		return
	}

	// Delete role (CASCADE will delete role_permissions and user_roles)
	result, err := h.db.Exec("DELETE FROM roles WHERE id = $1", id)
	if err != nil {
		http.Error(w, "failed to delete role", http.StatusInternalServerError)
		return
	}

	rowsAffected, _ := result.RowsAffected()
	if rowsAffected == 0 {
		http.Error(w, "role not found", http.StatusNotFound)
		return
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(map[string]interface{}{"message": "role deleted"})
}

// POST /api/v1/users/from-ad
func (h *UsersHandler) CreateUserFromAD(w http.ResponseWriter, r *http.Request) {
	var req struct {
		ADDistinguishedName string   `json:"ad_distinguished_name"`
		RoleIDs             []string `json:"role_ids"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		http.Error(w, "invalid request", http.StatusBadRequest)
		return
	}
	if strings.TrimSpace(req.ADDistinguishedName) == "" {
		http.Error(w, "ad_distinguished_name required", http.StatusBadRequest)
		return
	}
	if len(req.RoleIDs) == 0 {
		http.Error(w, "at least one role required", http.StatusBadRequest)
		return
	}

	// Fetch AD user details from ad_users table (from AD sync)
	var adUsername, adEmail, adDisplayName sql.NullString
	query := `SELECT username, email, display_name FROM ad_users WHERE distinguished_name = $1`
	err := h.db.QueryRow(query, req.ADDistinguishedName).Scan(&adUsername, &adEmail, &adDisplayName)
	if err == sql.ErrNoRows {
		http.Error(w, "AD user not found. Please sync AD users first.", http.StatusNotFound)
		return
	}
	if err != nil {
		http.Error(w, "failed to query AD user", http.StatusInternalServerError)
		log.Printf("[ERROR] Failed to query AD user: %v", err)
		return
	}

	// Check if user already exists
	var existingUserID string
	err = h.db.QueryRow("SELECT id FROM users WHERE ad_distinguished_name = $1", req.ADDistinguishedName).Scan(&existingUserID)
	if err == nil {
		http.Error(w, "user already exists", http.StatusConflict)
		return
	}

	// Create user from AD
	userID := uuid.New().String()
	now := time.Now()

	// Split display name into first and last name (simple split)
	firstName := ""
	lastName := ""
	if adDisplayName.Valid && adDisplayName.String != "" {
		parts := strings.Fields(adDisplayName.String)
		if len(parts) > 0 {
			firstName = parts[0]
		}
		if len(parts) > 1 {
			lastName = strings.Join(parts[1:], " ")
		}
	}

	insertQuery := `
        INSERT INTO users (
            id, username, email, first_name, last_name, 
            is_active, is_ad_synced, source, ad_distinguished_name,
            status, created_at, updated_at, last_ad_sync
        ) VALUES ($1,$2,$3,$4,$5,true,true,'ad',$6,'active',$7,$8,$9)
    `

	username := adUsername.String
	if username == "" {
		username = strings.Split(req.ADDistinguishedName, ",")[0]
		username = strings.TrimPrefix(username, "CN=")
	}

	email := adEmail.String
	if email == "" {
		email = username + "@domain.local" // Fallback email
	}

	if _, err := h.db.Exec(insertQuery, userID, username, email, firstName, lastName,
		req.ADDistinguishedName, now, now, now); err != nil {
		http.Error(w, "failed to create user", http.StatusInternalServerError)
		log.Printf("[ERROR] Failed to create AD user: %v", err)
		return
	}

	// Assign roles
	if len(req.RoleIDs) > 0 {
		h.assignRolesToUser(userID, req.RoleIDs)
	}

	user, _ := h.getFullUser(userID)

	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusCreated)
	json.NewEncoder(w).Encode(map[string]interface{}{
		"message": "user added from Active Directory",
		"user":    user,
	})
	log.Printf("[USER] Added AD user: %s (%s)", username, userID)
}

// GET /api/v1/ad/users
func (h *UsersHandler) ListADUsers(w http.ResponseWriter, r *http.Request) {
	query := `
        SELECT 
            ad.distinguished_name,
            ad.username,
            ad.email,
            ad.display_name,
            COALESCE(ad.department, '') as department,
            CASE WHEN u.id IS NOT NULL THEN TRUE ELSE FALSE END as is_already_added
        FROM ad_users ad
        LEFT JOIN users u ON ad.distinguished_name = u.ad_distinguished_name
        ORDER BY ad.display_name
    `

	rows, err := h.db.Query(query)
	if err != nil {
		http.Error(w, "database error", http.StatusInternalServerError)
		log.Printf("[ERROR] Failed to query AD users: %v", err)
		return
	}
	defer rows.Close()

	type ADUser struct {
		DistinguishedName string `json:"distinguished_name"`
		Username          string `json:"username"`
		Email             string `json:"email"`
		FullName          string `json:"full_name"`
		Department        string `json:"department,omitempty"`
		IsAlreadyAdded    bool   `json:"is_already_added"`
	}

	adUsers := []ADUser{}
	for rows.Next() {
		var adUser ADUser
		if err := rows.Scan(&adUser.DistinguishedName, &adUser.Username, &adUser.Email,
			&adUser.FullName, &adUser.Department, &adUser.IsAlreadyAdded); err != nil {
			continue
		}
		adUsers = append(adUsers, adUser)
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(map[string]interface{}{
		"success": true,
		"data":    adUsers,
	})
}

// GET /api/v1/permissions
func (h *UsersHandler) ListPermissions(w http.ResponseWriter, r *http.Request) {
	rows, err := h.db.Query(`SELECT id, name, resource, action, description FROM permissions ORDER BY resource, action`)
	if err != nil {
		http.Error(w, "database error", http.StatusInternalServerError)
		return
	}
	defer rows.Close()

	perms := []Permission{}
	for rows.Next() {
		var p Permission
		if err := rows.Scan(&p.ID, &p.Name, &p.Resource, &p.Action, &p.Description); err != nil {
			continue
		}
		perms = append(perms, p)
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(map[string]interface{}{"permissions": perms})
}

// Helper functions
// hasColumn checks information_schema for a given column
func (h *UsersHandler) hasColumn(tableName, columnName string) bool {
	var exists bool
	query := `SELECT EXISTS (
		SELECT 1 FROM information_schema.columns
		WHERE table_name = $1 AND column_name = $2
	)`
	err := h.db.QueryRow(query, tableName, columnName).Scan(&exists)
	if err != nil {
		return false
	}
	return exists
}

func (h *UsersHandler) getUserRoles(userID string) []Role {
	rows, err := h.db.Query(`
        SELECT r.id, r.name, r.description, r.created_at, r.updated_at
        FROM roles r
        JOIN user_roles ur ON r.id = ur.role_id
        WHERE ur.user_id = $1
    `, userID)
	if err != nil {
		return []Role{}
	}
	defer rows.Close()

	roles := []Role{}
	for rows.Next() {
		var r Role
		if err := rows.Scan(&r.ID, &r.Name, &r.Description, &r.CreatedAt, &r.UpdatedAt); err != nil {
			continue
		}
		r.Permissions = h.getRolePermissions(r.ID)
		roles = append(roles, r)
	}
	return roles
}

func (h *UsersHandler) getRolePermissions(roleID string) []Permission {
	rows, err := h.db.Query(`
        SELECT p.id, p.name, p.resource, p.action, p.description
        FROM permissions p
        JOIN role_permissions rp ON p.id = rp.permission_id
        WHERE rp.role_id = $1
    `, roleID)
	if err != nil {
		return []Permission{}
	}
	defer rows.Close()

	perms := []Permission{}
	for rows.Next() {
		var p Permission
		if err := rows.Scan(&p.ID, &p.Name, &p.Resource, &p.Action, &p.Description); err != nil {
			continue
		}
		perms = append(perms, p)
	}
	return perms
}

func (h *UsersHandler) assignRolesToUser(userID string, roleIDs []string) {
	for _, roleID := range roleIDs {
		h.db.Exec(`INSERT INTO user_roles (id, user_id, role_id, assigned_at) VALUES ($1,$2,$3,NOW())`, uuid.New().String(), userID, roleID)
	}
}

func (h *UsersHandler) getFullUser(userID string) (*User, error) {
	var u User
	query := `SELECT id, username, email, first_name, last_name, is_active, is_ad_synced, created_at, updated_at FROM users WHERE id = $1`
	err := h.db.QueryRow(query, userID).Scan(&u.ID, &u.Username, &u.Email, &u.FirstName, &u.LastName, &u.IsActive, &u.IsADSynced, &u.CreatedAt, &u.UpdatedAt)
	if err != nil {
		return nil, err
	}
	u.Roles = h.getUserRoles(userID)
	return &u, nil
}

func (h *UsersHandler) getFullRole(roleID string) (*Role, error) {
	var role Role
	query := `SELECT id, name, description, created_at, updated_at FROM roles WHERE id = $1`
	err := h.db.QueryRow(query, roleID).Scan(&role.ID, &role.Name, &role.Description, &role.CreatedAt, &role.UpdatedAt)
	if err != nil {
		return nil, err
	}
	role.Permissions = h.getRolePermissions(roleID)
	return &role, nil
}
