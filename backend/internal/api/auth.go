package api

import (
	"database/sql"
	"encoding/json"
	"errors"
	"log"
	"net/http"
	"os"
	"strings"
	"time"

	"golang.org/x/crypto/bcrypt"

	"github.com/golang-jwt/jwt/v5"

	"enterprise-dlp-backend/internal/db"
)

// JWTSecret is the server-side HMAC signing secret. It is sourced from the
// environment variable JWT_SECRET, or injected by main from configuration.
// Login and token validation fail fast (they never silently fall back to an
// unauthenticated state) when no secret is configured.
var JWTSecret string

// jwtKey returns the HMAC signing/validation key. Prefers the environment so
// deployments can rotate the secret without recompiling.
func jwtKey() []byte {
	if s := os.Getenv("JWT_SECRET"); s != "" {
		return []byte(s)
	}
	return []byte(JWTSecret)
}

// Claims carries the identity of an authenticated administrator.
type Claims struct {
	UserID string `json:"uid"`
	Email  string `json:"email"`
	Name   string `json:"name"`
	Role   string `json:"role"`

	jwt.RegisteredClaims
}

// generateToken signs a fresh JWT access token for the given identity.
func generateToken(userID, email, name, role string) (string, error) {
	secret := jwtKey()
	if len(secret) == 0 {
		return "", errors.New("JWT_SECRET is not configured")
	}

	now := time.Now()
	claims := Claims{
		UserID: userID,
		Email:  email,
		Name:   name,
		Role:   role,
		RegisteredClaims: jwt.RegisteredClaims{
			Subject:   userID,
			Issuer:    "pritrak-dlp",
			IssuedAt:  jwt.NewNumericDate(now),
			NotBefore: jwt.NewNumericDate(now),
			ExpiresAt: jwt.NewNumericDate(now.Add(24 * time.Hour)),
		},
	}

	token := jwt.NewWithClaims(jwt.SigningMethodHS256, claims)
	return token.SignedString(secret)
}

// validateToken verifies the signature, signing method, expiry and issuer of a
// bearer token and returns the identity claims.
func validateToken(tokenStr string) (*Claims, error) {
	secret := jwtKey()
	if len(secret) == 0 {
		return nil, errors.New("JWT_SECRET is not configured")
	}

	claims := &Claims{}
	token, err := jwt.ParseWithClaims(tokenStr, claims, func(t *jwt.Token) (interface{}, error) {
		if _, ok := t.Method.(*jwt.SigningMethodHMAC); !ok {
			return nil, errors.New("unexpected token signing method")
		}
		return secret, nil
	})
	if err != nil {
		return nil, err
	}
	if !token.Valid {
		return nil, errors.New("invalid token")
	}
	if claims.Issuer != "pritrak-dlp" {
		return nil, errors.New("unexpected token issuer")
	}
	return claims, nil
}

// handleLogin validates local user credentials against the database. The
// password must be stored as a bcrypt hash (see ensureAdminUser in main.go and
// the user management handlers). No hardcoded credentials are accepted.
func handleLogin(w http.ResponseWriter, r *http.Request, database *db.Connection) {
	w.Header().Set("Content-Type", "application/json")

	// Handle OPTIONS preflight (CORS headers are applied by the router
	// middleware from the configured allowed origins).
	if r.Method == "OPTIONS" {
		w.WriteHeader(http.StatusOK)
		return
	}

	var req struct {
		Email    string `json:"email"`
		Password string `json:"password"`
	}

	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		log.Printf("Login decode error: %v", err)
		w.WriteHeader(http.StatusBadRequest)
		json.NewEncoder(w).Encode(map[string]interface{}{
			"error":   "Invalid request format",
			"message": err.Error(),
		})
		return
	}

	log.Printf("Login attempt for email: %s", req.Email)

	if database == nil {
		log.Printf("Login failed for: %s (authentication not configured)", req.Email)
		w.WriteHeader(http.StatusServiceUnavailable)
		json.NewEncoder(w).Encode(map[string]interface{}{
			"error":   "Authentication not configured",
			"message": "No database is available and no admin account is configured. Set DATABASE_URL and ADMIN_EMAIL/ADMIN_PASSWORD.",
		})
		return
	}

	// Look up the local user by email and fetch its bcrypt password hash and role.
	var userID, username, firstName, lastName, passwordHash, roleName string
	err := database.QueryRow(`
		SELECT u.id, u.username, COALESCE(u.first_name, ''), COALESCE(u.last_name, ''),
		       COALESCE(u.password_hash, ''), COALESCE(r.name, '')
		FROM users u
		LEFT JOIN user_roles ur ON ur.user_id = u.id
		LEFT JOIN roles r ON r.id = ur.role_id
		WHERE LOWER(u.email) = LOWER($1) AND u.is_active = true
		LIMIT 1`, req.Email).Scan(&userID, &username, &firstName, &lastName, &passwordHash, &roleName)

	if err == sql.ErrNoRows || passwordHash == "" {
		log.Printf("Login failed for: %s (invalid credentials)", req.Email)
		w.WriteHeader(http.StatusUnauthorized)
		json.NewEncoder(w).Encode(map[string]interface{}{
			"error":   "Invalid credentials",
			"message": "Email or password is incorrect",
		})
		return
	}
	if err != nil {
		log.Printf("Login error for: %s: %v", req.Email, err)
		w.WriteHeader(http.StatusInternalServerError)
		json.NewEncoder(w).Encode(map[string]interface{}{
			"error":   "Internal server error",
			"message": "Failed to query user",
		})
		return
	}

	if bcrypt.CompareHashAndPassword([]byte(passwordHash), []byte(req.Password)) != nil {
		log.Printf("Login failed for: %s (invalid credentials)", req.Email)
		w.WriteHeader(http.StatusUnauthorized)
		json.NewEncoder(w).Encode(map[string]interface{}{
			"error":   "Invalid credentials",
			"message": "Email or password is incorrect",
		})
		return
	}

	role := "viewer"
	if roleName != "" {
		role = strings.ToLower(roleName)
	}
	name := strings.TrimSpace(firstName + " " + lastName)
	if name == "" {
		name = username
	}

	// Issue a real, signed JWT (never a mock token).
	token, err := generateToken(userID, req.Email, name, role)
	if err != nil {
		log.Printf("Login failed: could not sign token: %v", err)
		w.WriteHeader(http.StatusInternalServerError)
		json.NewEncoder(w).Encode(map[string]interface{}{
			"error":   "JWT_SECRET not configured",
			"message": "Server authentication is not configured. Set the JWT_SECRET environment variable.",
		})
		return
	}

	// Short-lived refresh token for the admin client.
	refreshToken, err := generateToken(userID, req.Email, name, role)
	if err != nil {
		refreshToken = ""
	}

	response := map[string]interface{}{
		"token":        token,
		"refreshToken": refreshToken,
		"user": map[string]interface{}{
			"id":         userID,
			"email":      req.Email,
			"name":       name,
			"role":       role,
			"department": "IT",
		},
	}

	log.Printf("Login successful for: %s", req.Email)
	if err := json.NewEncoder(w).Encode(response); err != nil {
		log.Printf("Error encoding login response: %v", err)
		w.WriteHeader(http.StatusInternalServerError)
		json.NewEncoder(w).Encode(map[string]interface{}{
			"error":   "Internal server error",
			"message": "Failed to generate response",
		})
	}
}

func handleLDAPLogin(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json")

	// Handle OPTIONS preflight
	if r.Method == "OPTIONS" {
		w.WriteHeader(http.StatusOK)
		return
	}

	var req struct {
		Username string `json:"username"`
		Password string `json:"password"`
	}

	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		w.WriteHeader(http.StatusBadRequest)
		json.NewEncoder(w).Encode(map[string]interface{}{
			"error":   "Invalid request format",
			"message": err.Error(),
		})
		return
	}

	// For now, return error - AD integration needs backend LDAP client
	// In production, this would:
	// 1. Connect to AD server
	// 2. Bind with credentials
	// 3. Search for user
	// 4. Return user info and JWT token

	w.WriteHeader(http.StatusNotImplemented)
	json.NewEncoder(w).Encode(map[string]interface{}{
		"error":   "Not implemented",
		"message": "Active Directory integration not yet configured. Please configure AD settings first.",
	})
}
