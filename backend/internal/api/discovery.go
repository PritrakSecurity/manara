package api

import (
    "context"
    "database/sql"
    "encoding/json"
    "log"
    "net/http"
    "time"

    "github.com/lib/pq"
    "enterprise-dlp-backend/internal/discovery"
)

// DiscoveryHandler manages nmap-based discovery API
type DiscoveryHandler struct {
    db       *sql.DB
    nmapSvc  *discovery.NmapDiscoveryService
}

func NewDiscoveryHandler(db *sql.DB) *DiscoveryHandler {
    cfg := discovery.NmapConfig{
        BinaryPath: "/usr/bin/nmap",
        ScanMode:   "balanced",
        MaxHosts:   256,
        Timeout:    time.Minute * 30,
    }
    return &DiscoveryHandler{db: db, nmapSvc: discovery.NewNmapDiscoveryService(db, cfg)}
}

// GetConfig returns discovery_config
func (h *DiscoveryHandler) GetConfig(w http.ResponseWriter, r *http.Request) {
    if h.db == nil {
        http.Error(w, "database not available", http.StatusServiceUnavailable)
        return
    }
    var enabled bool
    var binPath, scanMode string
    var interval int
    var subs []string
    err := h.db.QueryRow(`SELECT nmap_enabled, nmap_binary_path, scan_mode, scan_interval_hours, monitored_subnets FROM discovery_config LIMIT 1`).Scan(&enabled, &binPath, &scanMode, &interval, &subs)
    if err != nil {
        http.Error(w, "failed to load config", http.StatusInternalServerError)
        return
    }
    writeJSON(w, map[string]interface{}{"nmap_enabled": enabled, "nmap_binary_path": binPath, "scan_mode": scanMode, "scan_interval_hours": interval, "monitored_subnets": subs})
}

// UpdateConfig updates discovery_config
func (h *DiscoveryHandler) UpdateConfig(w http.ResponseWriter, r *http.Request) {
    if h.db == nil {
        http.Error(w, "database not available", http.StatusServiceUnavailable)
        return
    }
    var req struct {
        NmapEnabled       bool     `json:"nmap_enabled"`
        ScanMode          string   `json:"scan_mode"`
        ScanIntervalHours int      `json:"scan_interval_hours"`
        MonitoredSubnets  []string `json:"monitored_subnets"`
    }
    if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
        http.Error(w, "invalid request", http.StatusBadRequest)
        return
    }
    _, err := h.db.Exec(`UPDATE discovery_config SET nmap_enabled=$1, scan_mode=$2, scan_interval_hours=$3, monitored_subnets=$4, updated_at=NOW()`, req.NmapEnabled, req.ScanMode, req.ScanIntervalHours, pq.Array(req.MonitoredSubnets))
    if err != nil {
        http.Error(w, "failed to update config", http.StatusInternalServerError)
        return
    }
    writeJSON(w, map[string]interface{}{"message": "configuration updated"})
}

// TriggerScan starts an asynchronous nmap scan on provided subnet
func (h *DiscoveryHandler) TriggerScan(w http.ResponseWriter, r *http.Request) {
    if h.nmapSvc == nil {
        http.Error(w, "nmap service not available", http.StatusServiceUnavailable)
        return
    }
    var req struct{ Subnet string `json:"subnet"` }
    if err := json.NewDecoder(r.Body).Decode(&req); err != nil || req.Subnet == "" {
        http.Error(w, "subnet is required", http.StatusBadRequest)
        return
    }

    go func(sub string) {
        ctx, cancel := context.WithTimeout(context.Background(), 30*time.Minute)
        defer cancel()
        start := time.Now()
        hosts, err := h.nmapSvc.DiscoverNetwork(ctx, sub)
        duration := time.Since(start).Seconds()
        status := "success"
        errMsg := ""
        if err != nil {
            status = "failed"
            errMsg = err.Error()
            log.Printf("[NMAP] manual scan failed: %v", err)
        }
        if h.db != nil {
            h.db.Exec(`INSERT INTO scan_history (id, scan_type, subnet, hosts_discovered, scan_duration_seconds, status, error_message, started_at, completed_at) VALUES (gen_random_uuid(), 'manual', $1, $2, $3, $4, $5, $6, NOW())`, sub, len(hosts), duration, status, errMsg, start)
        }
    }(req.Subnet)

    writeJSON(w, map[string]interface{}{"message": "scan started", "subnet": req.Subnet})
}

// GetScanHistory returns recent scans
func (h *DiscoveryHandler) GetScanHistory(w http.ResponseWriter, r *http.Request) {
    if h.db == nil {
        writeJSON(w, map[string]interface{}{"history": []interface{}{}})
        return
    }
    rows, err := h.db.Query(`SELECT id, scan_type, subnet, hosts_discovered, scan_duration_seconds, status, started_at, completed_at FROM scan_history ORDER BY started_at DESC LIMIT 50`)
    if err != nil {
        http.Error(w, "database error", http.StatusInternalServerError)
        return
    }
    defer rows.Close()
    var history []map[string]interface{}
    for rows.Next() {
        var id, scanType, subnet, status string
        var hostsDiscovered int
        var duration float64
        var startedAt, completedAt time.Time
        rows.Scan(&id, &scanType, &subnet, &hostsDiscovered, &duration, &status, &startedAt, &completedAt)
        history = append(history, map[string]interface{}{"id": id, "scan_type": scanType, "subnet": subnet, "hosts_discovered": hostsDiscovered, "scan_duration_seconds": duration, "status": status, "started_at": startedAt, "completed_at": completedAt})
    }
    writeJSON(w, map[string]interface{}{"history": history})
}

// small helpers to avoid pulling heavy packages repeatedly
func writeJSON(w http.ResponseWriter, v interface{}) {
    w.Header().Set("Content-Type", "application/json")
    _ = json.NewEncoder(w).Encode(v)
}
