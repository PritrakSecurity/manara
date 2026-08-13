package discovery

import (
    "context"
    "database/sql"
    "fmt"
    "log"
    "strings"
    "time"

    nmap "github.com/Ullaakut/nmap/v3"
    "github.com/google/uuid"
)

// NmapConfig contains nmap options
type NmapConfig struct {
    BinaryPath string
    ScanMode   string
    MaxHosts   int
    Timeout    time.Duration
}

// NmapDiscoveryService wraps nmap scanner
type NmapDiscoveryService struct {
    db     *sql.DB
    config NmapConfig
}

// NewNmapDiscoveryService creates a new NmapDiscoveryService
func NewNmapDiscoveryService(db *sql.DB, cfg NmapConfig) *NmapDiscoveryService {
    return &NmapDiscoveryService{db: db, config: cfg}
}

// DiscoverNetwork runs an nmap scan on the provided subnet and returns discovered WindowsDevice-like entries
func (s *NmapDiscoveryService) DiscoverNetwork(ctx context.Context, subnet string) ([]WindowsDevice, error) {
    log.Printf("[NMAP] Starting discovery on %s (mode=%s)", subnet, s.config.ScanMode)

    scanner, err := s.buildScanner(ctx, subnet)
    if err != nil {
        return nil, fmt.Errorf("failed to build nmap scanner: %w", err)
    }

    result, warnings, err := scanner.Run()
    if warnings != nil && len(*warnings) > 0 {
        log.Printf("[NMAP] Warnings: %v", *warnings)
    }
    if err != nil {
        return nil, fmt.Errorf("nmap scan failed: %w", err)
    }

    hosts := s.parseNmapResults(result)

    if s.db != nil {
        // Sync into devices table where possible (best-effort)
        go func() { _ = s.syncDiscoveredHosts(hosts) }()
    }

    return hosts, nil
}

func (s *NmapDiscoveryService) buildScanner(ctx context.Context, subnet string) (*nmap.Scanner, error) {
    var opts []nmap.Option
    // Context is already passed to NewScanner; remove deprecated WithContext option
    opts = append(opts, nmap.WithTargets(subnet))

    switch s.config.ScanMode {
    case "conservative":
        opts = append(opts, nmap.WithPingScan(), nmap.WithTimingTemplate(nmap.TimingPolite), nmap.WithMaxRetries(1), nmap.WithMaxHostgroup(16))
    case "balanced":
        opts = append(opts, nmap.WithSYNScan(), nmap.WithPorts("22,80,135,139,443,445,3389,5900,8080,8443"), nmap.WithServiceInfo(), nmap.WithOSDetection(), nmap.WithTimingTemplate(nmap.TimingNormal), nmap.WithMaxRetries(2), nmap.WithMaxHostgroup(64))
    case "aggressive":
        opts = append(opts, nmap.WithSYNScan(), nmap.WithPorts("1-65535"), nmap.WithServiceInfo(), nmap.WithOSDetection(), nmap.WithScripts("default,discovery,safe"), nmap.WithTimingTemplate(nmap.TimingAggressive), nmap.WithMaxRetries(1), nmap.WithMaxHostgroup(256))
    default:
        return nil, fmt.Errorf("invalid scan mode: %s", s.config.ScanMode)
    }

    opts = append(opts, nmap.WithMaxRTTTimeout(time.Second*10), nmap.WithHostTimeout(time.Minute*15))
    return nmap.NewScanner(ctx, opts...)
}

func (s *NmapDiscoveryService) parseNmapResults(result *nmap.Run) []WindowsDevice {
    var out []WindowsDevice
    for _, h := range result.Hosts {
        if len(h.Addresses) == 0 {
            continue
        }
        wd := WindowsDevice{
            ID:        uuid.New().String(),
            Hostname:  "",
            IPAddress: "",
            OS:        "",
            OSVersion: "",
            MACAddress: "",
            IsOnline:  true,
            LastSeen:  time.Now().Format(time.RFC3339),
            Domain:    "",
            Username:  "",
            Status:    "eligible",
        }

        for _, a := range h.Addresses {
            switch strings.ToLower(a.AddrType) {
            case "ipv4", "ipv6":
                wd.IPAddress = a.Addr
            case "mac":
                wd.MACAddress = a.Addr
            }
        }

        if len(h.Hostnames) > 0 {
            wd.Hostname = h.Hostnames[0].Name
        }
        if wd.Hostname == "" {
            wd.Hostname = wd.IPAddress
        }

        if len(h.OS.Matches) > 0 {
            wd.OS = h.OS.Matches[0].Name
            wd.OSVersion = fmt.Sprintf("%d%% accuracy", h.OS.Matches[0].Accuracy)
        }

        // If no OS info and common ports indicate Windows, mark as Windows
        if wd.OS == "" {
            for _, p := range h.Ports {
                if p.ID == 445 || p.ID == 3389 || p.ID == 135 { wd.OS = "Windows (likely)"; break }
            }
        }

        out = append(out, wd)
    }
    return out
}

// syncDiscoveredHosts writes discovered hosts into devices and device_ports tables (best-effort)
func (s *NmapDiscoveryService) syncDiscoveredHosts(hosts []WindowsDevice) error {
    if s.db == nil { return nil }
    for _, h := range hosts {
        var existing string
        err := s.db.QueryRow(`SELECT id FROM devices WHERE ip_address = $1 OR mac_address = $2`, h.IPAddress, h.MACAddress).Scan(&existing)
        if err == sql.ErrNoRows || err != nil {
            id := uuid.New().String()
            _, err := s.db.Exec(`INSERT INTO devices (id, hostname, ip_address, mac_address, os, os_version, status, last_seen, agent_installed, agent_version, discovery_method, created_at) VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,NOW())`, id, h.Hostname, h.IPAddress, h.MACAddress, h.OS, h.OSVersion, "online", h.LastSeen, false, "", "nmap")
            if err != nil {
                log.Printf("[NMAP] failed to insert device: %v", err)
                continue
            }
        }
    }
    return nil
}
