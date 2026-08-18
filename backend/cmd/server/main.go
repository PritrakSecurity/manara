package main

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"database/sql"
	"flag"
	"fmt"
	"log"
	"net"
	"net/http"
	"os"
	"os/signal"
	"syscall"
	"time"

	"github.com/google/uuid"
	"golang.org/x/crypto/bcrypt"
	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials"

	"manara-dlp/internal/api"
	"manara-dlp/internal/config"
	"manara-dlp/internal/db"
	"manara-dlp/internal/endpoints"
	"manara-dlp/internal/license"
	"manara-dlp/internal/policy"
	"manara-dlp/internal/telemetry"
	"manara-dlp/internal/alerts"
	"manara-dlp/internal/websocket"
)

var (
	port         = flag.Int("port", 50051, "gRPC server port")
	httpPort     = flag.Int("http-port", 8080, "HTTP gateway port")
	dbConnString = flag.String("db", "", "Database connection string")
	certFile     = flag.String("cert", "certs/server.crt", "TLS certificate file")
	keyFile      = flag.String("key", "certs/server.key", "TLS key file")
	caFile       = flag.String("ca", "certs/ca.crt", "CA certificate file")
)

// Heartbeat timeouts (can adjust for enterprise env)
var (
	// Warning after 90s without a heartbeat (3 missed beats @ 30s interval).
	HeartbeatWarningDuration = 90 * time.Second
	HeartbeatOfflineDuration = 5 * time.Minute
	HeartbeatDeleteAfter      = 24 * time.Hour
)

// Server startup time (for health endpoint)
var serverStartTime time.Time

func main() {
	flag.Parse()

	// Record server startup time
	serverStartTime = time.Now()

	// Load configuration from environment. JWT_SECRET is mandatory; the server
	// fails fast at startup if it is missing in a non-development environment.
	cfg, err := config.LoadFromEnv()
	if err != nil {
		log.Fatal("FATAL: ", err)
	}

	// Propagate the JWT signing secret to the API package. Token issuance and
	// validation share this secret; it is never silently defaulted.
	api.JWTSecret = cfg.JWTSecret

	// Restrict browser CORS to the configured allowed origins.
	api.AllowedCORSOrigins = cfg.AllowedOrigins

	// AES encryption key for AD credential storage — required, no default.
	if cfg.AESEncryptionKey == "" {
		log.Fatal("FATAL: AES_ENCRYPTION_KEY environment variable is not set. " +
			"AD passwords cannot be encrypted without it. Set it to a 32-byte hex string.")
	}
	if len(cfg.AESEncryptionKey) != 32 {
		log.Fatal("FATAL: AES_ENCRYPTION_KEY must be exactly 32 bytes (AES-256). Current length: ", len(cfg.AESEncryptionKey))
	}
	api.AESEncryptKey = cfg.AESEncryptionKey

	// WebSocket origin allowlist
	websocket.AllowedOrigins = cfg.AllowedWSOrigins

	// Build the license feature gate from server configuration. Cloud DSPM is
	// enabled by listing it in LICENSE_FEATURES (e.g. LICENSE_FEATURES=cloud-dspm).
	licSvc := license.NewService(cfg.EnabledFeatures)
	log.Printf("Enabled license features: %v", licSvc.FeatureNames())

	// Allow local AWS profile authentication for Cloud DSPM only when the server
	// operator explicitly opts in (local development/tests). Clients can never
	// enable this themselves.
	api.AllowAWSProfile = cfg.AllowAWSProfile

	// Determine the database connection string: the -db flag overrides the
	// DATABASE_URL environment variable. A database is REQUIRED — the server
	// refuses to start without one.
	dbConnString := *dbConnString
	if dbConnString == "" {
		dbConnString = cfg.DatabaseURL
	}
	if dbConnString == "" {
		log.Fatal("FATAL: DATABASE_URL environment variable is required")
	}

	// Initialize the database connection. A working PostgreSQL connection is
	// required: the server fails fast instead of running in a degraded
	// "no database" mode that hides production problems.
	database, err := db.NewConnection(dbConnString)
	if err != nil {
		log.Fatalf("FATAL: failed to connect to database: %v", err)
	}
	defer database.Close()

	// Run migrations
	if err := db.RunMigrations(database); err != nil {
		log.Printf("WARNING: Failed to run migrations: %v", err)
	}
	// Initialize default policies
	if err := policy.InitializeDefaultPolicies(database.DB); err != nil {
		log.Printf("WARNING: Failed to initialize default policies: %v", err)
	}

	// Load TLS certificates for mTLS (optional for development)
	var tlsConfig *tls.Config
	tlsCfg, err := loadTLSConfig(*certFile, *keyFile, *caFile)
	if err != nil {
		log.Printf("WARNING: Failed to load TLS config: %v", err)
		log.Printf("Starting server without TLS (development mode)")
		tlsConfig = nil
	} else {
		tlsConfig = tlsCfg
	}

	// Initialize services backed by the database.
	policyService := policy.NewService(database.DB)
	alertService := alerts.NewService(database.DB)
	telemetryService := telemetry.NewService(database.DB, alertService)
	endpointService := endpoints.NewService(database.DB)

	// Initialize device manager
	api.InitDeviceManager(database.DB)
	log.Println("✅ Device manager initialized")

	// Bootstrap the admin account from ADMIN_EMAIL / ADMIN_PASSWORD. If they are
	// not set, the server still starts but login will be unavailable until an
	// admin account is created.
	adminEmail := cfg.AdminEmail
	adminPassword := cfg.AdminPassword
	if adminEmail != "" && adminPassword != "" {
		if err := ensureAdminUser(database.DB, adminEmail, adminPassword); err != nil {
			log.Printf("WARNING: Failed to seed admin user %s: %v", adminEmail, err)
		} else {
			log.Printf("Admin user configured: %s", adminEmail)
		}
	} else {
		log.Printf("WARNING: ADMIN_EMAIL / ADMIN_PASSWORD are not set. No admin account is configured; login will be unavailable until an admin is created (see backend/.env.example).")
	}

	// Propagate heartbeat duration configuration to API package
	api.HeartbeatWarningDuration = HeartbeatWarningDuration
	api.HeartbeatOfflineDuration = HeartbeatOfflineDuration

	// Create gRPC server (with or without TLS)
	var grpcServer *grpc.Server
	if tlsConfig != nil {
		creds := credentials.NewTLS(tlsConfig)
		grpcServer = grpc.NewServer(grpc.Creds(creds))
	} else {
		grpcServer = grpc.NewServer() // No TLS for development
	}

	// Register gRPC services via api package
	api.RegisterServices(grpcServer, policyService, telemetryService, endpointService)

	// Start gRPC server (optional - skip if port in use)
	grpcLis, err := net.Listen("tcp", fmt.Sprintf(":%d", *port))
	var grpcRunning bool
	if err != nil {
		log.Printf("WARNING: Failed to listen on gRPC port %d: %v", *port, err)
		log.Printf("Continuing without gRPC server (HTTP API will still work)")
		grpcLis = nil
		grpcRunning = false
	} else {
		grpcRunning = true
	}

	// Initialize the websocket hub exactly once (package-level singleton) and
	// the HTTP REST API router exactly once. There is no duplicate port-8080
	// listener: a single HTTP server is bound on the configured http-port.
	router := api.NewRouter(policyService, telemetryService, endpointService, alertService, database, serverStartTime, licSvc)

	httpServer := &http.Server{
		Addr:    fmt.Sprintf(":%d", *httpPort),
		Handler: router,
	}

	// Start servers in goroutines
	if grpcRunning {
		go func() {
			log.Printf("Starting gRPC server on :%d", *port)
			if err := grpcServer.Serve(grpcLis); err != nil {
				log.Printf("gRPC server error: %v", err)
			}
		}()
	}

	go func() {
		log.Printf("Starting HTTP server on :%d", *httpPort)
		// Do not exit the process on a transient HTTP error; log it so the
		// operator can see the degraded state instead of a silent failure.
		if err := httpServer.ListenAndServe(); err != nil && err != http.ErrServerClosed {
			log.Printf("HTTP server error on :%d: %v", *httpPort, err)
		}
	}()

	// Graceful shutdown
	sigChan := make(chan os.Signal, 1)
	signal.Notify(sigChan, os.Interrupt, syscall.SIGTERM)
	<-sigChan

	log.Println("Shutting down...")
	if grpcRunning {
		grpcServer.GracefulStop()
	}

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	httpServer.Shutdown(ctx)

	log.Println("Server stopped")
}

// ensureAdminUser creates or updates the local admin account with the provided
// email/password. The password is stored as a bcrypt hash and the user is
// assigned the "Admin" role so it can sign in to the admin console.
func ensureAdminUser(dbConn *sql.DB, email, password string) error {
	hash, err := bcrypt.GenerateFromPassword([]byte(password), bcrypt.DefaultCost)
	if err != nil {
		return fmt.Errorf("failed to hash admin password: %w", err)
	}

	var existingID string
	err = dbConn.QueryRow(`SELECT id FROM users WHERE LOWER(email) = LOWER($1)`, email).Scan(&existingID)
	switch {
	case err == sql.ErrNoRows:
		userID := uuid.New().String()
		now := time.Now()
		if _, err := dbConn.Exec(`
			INSERT INTO users (id, username, email, first_name, last_name, password_hash,
				is_active, is_ad_synced, source, status, created_at, updated_at, password_reset_required)
			VALUES ($1, $2, $3, $4, '', $5, true, false, 'local', 'active', $6, $6, false)`,
			userID, email, email, "Admin", string(hash), now); err != nil {
			return fmt.Errorf("failed to create admin user: %w", err)
		}

		// Assign the built-in Admin role if it exists so the account has full
		// console access.
		var roleID string
		if err := dbConn.QueryRow(`SELECT id FROM roles WHERE name = 'Admin' LIMIT 1`).Scan(&roleID); err == nil {
			if _, err := dbConn.Exec(`INSERT INTO user_roles (id, user_id, role_id, assigned_at) VALUES ($1, $2, $3, $4) ON CONFLICT DO NOTHING`,
				uuid.New().String(), userID, roleID, time.Now()); err != nil {
				log.Printf("WARNING: Failed to assign Admin role to %s: %v", email, err)
			}
		}
		return nil
	case err != nil:
		return fmt.Errorf("failed to query admin user: %w", err)
	default:
		// Update the existing user's password and ensure the account is active.
		if _, err := dbConn.Exec(`UPDATE users SET password_hash = $1, is_active = true, updated_at = NOW() WHERE id = $2`,
			string(hash), existingID); err != nil {
			return fmt.Errorf("failed to update admin user password: %w", err)
		}
		return nil
	}
}

func loadTLSConfig(certFile, keyFile, caFile string) (*tls.Config, error) {
	// Load server certificate
	cert, err := tls.LoadX509KeyPair(certFile, keyFile)
	if err != nil {
		return nil, fmt.Errorf("failed to load server cert: %w", err)
	}

	// Load CA certificate for client verification
	caCert, err := os.ReadFile(caFile)
	if err != nil {
		return nil, fmt.Errorf("failed to load CA cert: %w", err)
	}

	caCertPool := x509.NewCertPool()
	if !caCertPool.AppendCertsFromPEM(caCert) {
		return nil, fmt.Errorf("failed to parse CA cert")
	}

	return &tls.Config{
		Certificates: []tls.Certificate{cert},
		ClientAuth:   tls.RequireAndVerifyClientCert,
		ClientCAs:    caCertPool,
		MinVersion:   tls.VersionTLS13,
	}, nil
}
