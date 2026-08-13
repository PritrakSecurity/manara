package api

import (
	"encoding/json"
	"fmt"
	"log"
	"net/http"
	"os"
	"path/filepath"
	"strings"
)

// handleDeviceRegister is a backward compatibility wrapper that delegates to HandleDeviceRegistration
func handleDeviceRegister(w http.ResponseWriter, r *http.Request, endpointService interface{}) {
	HandleDeviceRegistration(w, r)
}

func handleAgentDownload(w http.ResponseWriter, r *http.Request) {
	// In production, serve the actual agent binary or ZIP file
	// For now, return a placeholder response

	w.Header().Set("Content-Type", "application/zip")
	w.Header().Set("Content-Disposition", "attachment; filename=pritrak-dlp-agent.zip")

	// Return empty ZIP for now (in production, serve actual file)
	w.WriteHeader(http.StatusOK)
	w.Write([]byte("PK\x03\x04")) // Minimal ZIP header
}

// handleInstallerDownload serves the agent installer executable
func handleInstallerDownload(w http.ResponseWriter, r *http.Request) {
	// Get the installer path
	// Try multiple possible locations
	possiblePaths := []string{
		"./installers/pritrak-agent-installer.exe",
		"./backend/installers/pritrak-agent-installer.exe",
		"../installers/pritrak-agent-installer.exe",
		"../../installers/pritrak-agent-installer.exe",
	}

	var installerPath string
	for _, path := range possiblePaths {
		if absPath, err := filepath.Abs(path); err == nil {
			if _, err := os.Stat(absPath); err == nil {
				installerPath = absPath
				break
			}
		}
	}

	// If no installer found, return helpful error
	if installerPath == "" {
		log.Printf("❌ Installer not found. Searched paths: %v", possiblePaths)

		// For HEAD requests, just return 404
		if r.Method == "HEAD" {
			w.WriteHeader(http.StatusNotFound)
			return
		}

		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusNotFound)
		json.NewEncoder(w).Encode(map[string]interface{}{
			"error":   "Installer not found",
			"message": "Agent installer is not available. Please contact administrator.",
			"details": "The installer file should be placed in: backend/installers/pritrak-agent-installer.exe",
		})
		return
	}

	log.Printf("📦 Serving installer to: %s (File: %s)", r.RemoteAddr, installerPath)

	// Get file info
	fileInfo, err := os.Stat(installerPath)
	if err != nil {
		log.Printf("❌ Error reading installer: %v", err)
		w.WriteHeader(http.StatusInternalServerError)
		return
	}

	// Set proper headers for download
	w.Header().Set("Content-Description", "File Transfer")
	w.Header().Set("Content-Transfer-Encoding", "binary")
	w.Header().Set("Content-Disposition", fmt.Sprintf("attachment; filename=pritrak-agent-installer.exe"))
	w.Header().Set("Content-Type", "application/octet-stream")
	w.Header().Set("Content-Length", fmt.Sprintf("%d", fileInfo.Size()))
	w.Header().Set("Cache-Control", "no-cache, no-store, must-revalidate")
	w.Header().Set("Pragma", "no-cache")
	w.Header().Set("Expires", "0")

	// For HEAD requests, just send headers
	if r.Method == "HEAD" {
		w.WriteHeader(http.StatusOK)
		return
	}

	// Serve the file
	http.ServeFile(w, r, installerPath)
}

// handleAgentInstallScript serves the PowerShell agent installer script
// This endpoint allows one-line installation:
// Set-ExecutionPolicy Bypass -Scope Process -Force; iex ((New-Object Net.WebClient).DownloadString('http://SERVER:8080/api/agent/install'))
func handleAgentInstallScript(w http.ResponseWriter, r *http.Request) {
	// Get the server's IP from the request or use provided host
	serverHost := r.Host
	if serverHost == "" {
		serverHost = "localhost:8080"
	}

	// Extract just the IP/hostname without port for the script
	serverIP := serverHost
	if idx := strings.Index(serverHost, ":"); idx > 0 {
		serverIP = serverHost[:idx]
	}

	log.Printf("📦 Serving agent install script to: %s (Server IP: %s)", r.RemoteAddr, serverIP)

	// Try to read the agent script from file - prefer v4 blocking agent
	possiblePaths := []string{
		"./internal/api/agent-dlp-v4-blocking.ps1",
		"../internal/api/agent-dlp-v4-blocking.ps1",
		"../../internal/api/agent-dlp-v4-blocking.ps1",
		"./agent-dlp-v4-blocking.ps1",
		"./internal/api/agent-dlp-v3-enterprise.ps1",
		"../internal/api/agent-dlp-v3-enterprise.ps1",
	}

	var agentScript string
	for _, path := range possiblePaths {
		if absPath, err := filepath.Abs(path); err == nil {
			if content, err := os.ReadFile(absPath); err == nil {
				agentScript = string(content)
				log.Printf("✅ Loaded agent script from: %s", absPath)
				break
			}
		}
	}

	if agentScript == "" {
		// Use embedded minimal script if file not found
		agentScript = getEmbeddedAgentScript()
		log.Printf("⚠️ Using embedded agent script (file not found)")
	}

	// Replace placeholder with actual server IP
	agentScript = strings.ReplaceAll(agentScript, "YOURSERVERIP", serverIP)
	agentScript = strings.ReplaceAll(agentScript, `$SIP = "localhost"`, fmt.Sprintf(`$SIP = "%s"`, serverIP))
	agentScript = strings.ReplaceAll(agentScript, `[string]$SIP = "localhost"`, fmt.Sprintf(`[string]$SIP = "%s"`, serverIP))

	// Set content type for PowerShell script
	w.Header().Set("Content-Type", "text/plain; charset=utf-8")
	w.Header().Set("Content-Disposition", "inline; filename=pritrak-agent-install.ps1")
	w.WriteHeader(http.StatusOK)
	w.Write([]byte(agentScript))
}

// getEmbeddedAgentScript returns a minimal embedded agent script
func getEmbeddedAgentScript() string {
	// Note: Due to Go string limitations with backticks, we return a simple bootstrap script
	// that instructs the user to download the full agent
	return "# PRITRAK DLP Agent Bootstrap\n" +
		"# ERROR: Full agent script not found on server\n" +
		"# Please ensure agent-dlp-v3-enterprise.ps1 is deployed to the backend/internal/api folder\n" +
		"\n" +
		"Write-Host 'ERROR: Agent script not found on server.' -ForegroundColor Red\n" +
		"Write-Host 'Please contact your administrator to deploy the agent script.' -ForegroundColor Yellow\n" +
		"Write-Host 'Expected location: backend/internal/api/agent-dlp-v3-enterprise.ps1' -ForegroundColor Gray\n"
}
