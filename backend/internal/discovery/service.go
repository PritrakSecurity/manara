package discovery

import (
	"context"
	"encoding/json"
	"fmt"
	"log"
	"net"
	"os/exec"
	"runtime"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/google/uuid"
)

// WindowsDevice represents a discovered Windows device
type WindowsDevice struct {
	ID         string `json:"id"`
	Hostname   string `json:"hostname"`
	IPAddress  string `json:"ipAddress"`
	OS         string `json:"os"`
	OSVersion  string `json:"osVersion"`
	MACAddress string `json:"macAddress"`
	IsOnline   bool   `json:"isOnline"`
	LastSeen  string `json:"lastSeen"`
	Domain     string `json:"domain"`
	Username   string `json:"username"`
	Status     string `json:"status"` // "eligible" or "ineligible"
}

// DiscoveryProgress tracks the current discovery scan progress
type DiscoveryProgress struct {
	Status        string         `json:"status"` // "discovering", "completed", "failed"
	Progress      int            `json:"progress"`
	Message       string         `json:"message"`
	FoundDevices  []WindowsDevice `json:"foundDevices"`
	TotalScanned  int            `json:"totalScanned"`
	TotalEligible int            `json:"totalEligible"`
	ScanDuration  int            `json:"scanDuration"`
}

// Service handles network device discovery
type Service struct {
	mu              sync.RWMutex
	scanInProgress  bool
	currentProgress DiscoveryProgress
	cancelFunc      context.CancelFunc
}

// NewService creates a new discovery service
func NewService() *Service {
	return &Service{
		currentProgress: DiscoveryProgress{
			Status:       "discovering",
			Progress:     0,
			Message:      "Initializing network discovery",
			FoundDevices: []WindowsDevice{},
		},
	}
}

// GetNetworkRange detects the local network CIDR range
func (s *Service) GetNetworkRange() string {
	interfaces, err := net.Interfaces()
	if err != nil {
		return "192.168.1.0/24" // Default fallback
	}

	for _, iface := range interfaces {
		// Skip loopback and down interfaces
		if iface.Flags&net.FlagLoopback != 0 || iface.Flags&net.FlagUp == 0 {
			continue
		}

		addrs, err := iface.Addrs()
		if err != nil {
			continue
		}

		for _, addr := range addrs {
			ipNet, ok := addr.(*net.IPNet)
			if !ok {
				continue
			}

			ip := ipNet.IP
			if ip == nil || ip.IsLoopback() {
				continue
			}

			ipv4 := ip.To4()
			if ipv4 == nil {
				continue
			}

			// Calculate CIDR notation
			mask := ipNet.Mask
			ones, bits := mask.Size()

			// Get network address (not host IP)
			networkIP := ipNet.IP.Mask(mask)
			networkIPv4 := networkIP.To4()
			if networkIPv4 == nil {
				continue
			}

			cidr := fmt.Sprintf("%s/%d", networkIPv4.String(), ones)
			log.Printf("         ✅ Valid IPv4 interface found!")
			log.Printf("         Interface IP: %s", ipv4.String())
			log.Printf("         Network IP: %s", networkIPv4.String())
			log.Printf("         Mask: %d/%d", ones, bits)
			log.Printf("         CIDR: %s", cidr)
			return cidr
		}
	}

	return "192.168.1.0/24" // Default fallback
}

// GenerateIPRange generates all IP addresses in a CIDR range
func (s *Service) GenerateIPRange(cidr string) []string {
	log.Printf("🔍 GenerateIPRange called with CIDR: %s", cidr)

	// Validate CIDR format
	if cidr == "" {
		log.Printf("❌ Empty CIDR string")
		return []string{}
	}

	if !strings.Contains(cidr, "/") {
		log.Printf("❌ CIDR missing '/' separator: %s", cidr)
		return []string{}
	}

	_, ipNet, err := net.ParseCIDR(cidr)
	if err != nil {
		log.Printf("❌ Error parsing CIDR %s: %v", cidr, err)
		log.Printf("   CIDR format should be: X.X.X.X/Y (e.g., 192.168.1.0/24)")
		return []string{}
	}
	log.Printf("   ✅ CIDR parsed successfully")

	// Get network IP and mask
	networkIP := ipNet.IP.To4()
	if networkIP == nil {
		log.Printf("❌ Invalid IPv4 network: %s (not IPv4)", cidr)
		log.Printf("   Network IP: %v", ipNet.IP)
		return []string{}
	}
	log.Printf("   ✅ Network IP: %s", networkIP.String())

	ones, bits := ipNet.Mask.Size()
	log.Printf("   Mask: %d/%d (ones/bits)", ones, bits)
	if ones < 0 || ones > 32 {
		log.Printf("❌ Invalid mask bits: %d (must be 0-32)", ones)
		return []string{}
	}

	// Calculate number of possible hosts
	hostBits := bits - ones
	if hostBits > 24 {
		log.Printf("⚠️  Large subnet detected (%d host bits), limiting to 256 hosts", hostBits)
	}

	hostCount := int64(1) << uint(hostBits) // 2^hostBits
	log.Printf("   Host bits: %d", hostBits)
	log.Printf("   Total possible hosts: %d", hostCount)

	// Limit to avoid timeout (max 256 hosts for /24 subnet)
	maxHosts := int64(256)
	actualCount := hostCount - 2 // Subtract network and broadcast
	if actualCount > maxHosts {
		log.Printf("   Limiting to %d hosts (from %d)", maxHosts, actualCount)
		actualCount = maxHosts
	} else if actualCount < 0 {
		log.Printf("❌ Invalid host count: %d", actualCount)
		return []string{}
	}

	log.Printf("📊 Generating IP range: %s", cidr)
	log.Printf("   Possible hosts: %d, Actual scan: %d", hostCount-2, actualCount)

	// Convert network IP to 32-bit integer
	baseNum := uint32(networkIP[0])<<24 | uint32(networkIP[1])<<16 | uint32(networkIP[2])<<8 | uint32(networkIP[3])
	log.Printf("   Base IP as uint32: %d (0x%08X)", baseNum, baseNum)

	ips := make([]string, 0, int(actualCount))

	// Generate IP addresses (skip network address, start from +1)
	// Calculate broadcast address
	broadcastNum := baseNum + uint32(hostCount-1)
	log.Printf("   Broadcast address: %d (0x%08X)", broadcastNum, broadcastNum)

	for offset := uint32(1); offset <= uint32(actualCount); offset++ {
		ipNum := baseNum + offset

		// Skip broadcast address
		if ipNum == broadcastNum {
			log.Printf("   Skipping broadcast address at offset %d", offset)
			continue
		}

		// Convert back to IP address
		a := byte((ipNum >> 24) & 0xFF)
		b := byte((ipNum >> 16) & 0xFF)
		c := byte((ipNum >> 8) & 0xFF)
		d := byte(ipNum & 0xFF)

		ipStr := fmt.Sprintf("%d.%d.%d.%d", a, b, c, d)
		ips = append(ips, ipStr)
	}

	log.Printf("✅ Generated %d IP addresses", len(ips))
	if len(ips) > 0 {
		log.Printf("   First IP: %s", ips[0])
		log.Printf("   Last IP: %s", ips[len(ips)-1])
	}
	return ips
}

// Helper function for min
func min(a, b int) int {
	if a < b {
		return a
	}
	return b
}

func max(a, b int) int {
	if a > b {
		return a
	}
	return b
}

func incrementIP(ip net.IP) {
	for j := len(ip) - 1; j >= 0; j-- {
		ip[j]++
		if ip[j] > 0 {
			break
		}
	}
}

func isNetworkOrBroadcast(ip net.IP, ipNet *net.IPNet) bool {
	ones, bits := ipNet.Mask.Size()
	hostBits := bits - ones

	// Network address (all host bits are 0)
	// Broadcast address (all host bits are 1)
	ipInt := ipToInt(ip)
	networkInt := ipToInt(ipNet.IP)
	mask := uint32((1 << hostBits) - 1)

	return (ipInt-networkInt == 0) || (ipInt-networkInt == mask)
}

func ipToInt(ip net.IP) uint32 {
	ipv4 := ip.To4()
	if ipv4 == nil {
		return 0
	}
	return uint32(ipv4[0])<<24 | uint32(ipv4[1])<<16 | uint32(ipv4[2])<<8 | uint32(ipv4[3])
}

// PingHost checks if a host is online using ICMP ping
func (s *Service) PingHost(ip string, timeout time.Duration) bool {
	var cmd *exec.Cmd

	if runtime.GOOS == "windows" {
		cmd = exec.Command("ping", "-n", "1", "-w", fmt.Sprintf("%d", int(timeout.Milliseconds())), ip)
	} else {
		cmd = exec.Command("ping", "-c", "1", "-W", fmt.Sprintf("%d", int(timeout.Seconds())), ip)
	}

	ctx, cancel := context.WithTimeout(context.Background(), timeout+time.Second)
	defer cancel()

	cmd = exec.CommandContext(ctx, cmd.Path, cmd.Args[1:]...)
	err := cmd.Run()

	return err == nil
}

// CheckPort checks if a TCP port is open
func (s *Service) CheckPort(ip string, port int, timeout time.Duration) bool {
	conn, err := net.DialTimeout("tcp", fmt.Sprintf("%s:%d", ip, port), timeout)
	if err != nil {
		return false
	}
	conn.Close()
	return true
}

// GetWindowsDeviceInfo retrieves Windows device information via PowerShell/WMI
func (s *Service) GetWindowsDeviceInfo(ip string) *WindowsDevice {
	// PowerShell script reads the IP from $args[0] to avoid command injection
	// via string interpolation. WMI uses the service account's default
	// credentials (no passwords on the command line).
	psScript := `
		$ip = $args[0]
		try {
			$computerSystem = Get-WmiObject -ComputerName $ip -Class Win32_ComputerSystem -ErrorAction Stop
			$operatingSystem = Get-WmiObject -ComputerName $ip -Class Win32_OperatingSystem -ErrorAction Stop
			$networkAdapter = Get-WmiObject -ComputerName $ip -Class Win32_NetworkAdapterConfiguration -Filter "IPEnabled=true" -ErrorAction Stop | Select-Object -First 1

			$result = @{
				hostname = $computerSystem.Name
				domain = $computerSystem.Domain
				username = $computerSystem.UserName
				os = $operatingSystem.Caption
				osVersion = $operatingSystem.Version
				macAddress = if ($networkAdapter.MACAddress) { $networkAdapter.MACAddress } else { "Unknown" }
			}
			$result | ConvertTo-Json
		} catch {
			Write-Output "{}"
		}
	`

	var cmd *exec.Cmd
	if runtime.GOOS == "windows" {
		cmd = exec.Command("powershell", "-NoProfile", "-Command", psScript, ip)
	} else {
		// On Linux/Mac, we can't use WMI, so return basic info
		return &WindowsDevice{
			ID:         uuid.New().String(),
			Hostname:   "UNKNOWN",
			IPAddress:  ip,
			OS:         "Windows",
			OSVersion:   "Unknown",
			MACAddress:  "Unknown",
			IsOnline:   true,
			LastSeen:   time.Now().Format(time.RFC3339),
			Domain:     "WORKGROUP",
			Username:   "Unknown",
			Status:     "ineligible",
		}
	}

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	cmd = exec.CommandContext(ctx, cmd.Path, cmd.Args...)
	output, err := cmd.CombinedOutput()
	if err != nil {
		return nil
	}

	var info map[string]interface{}
	if err := json.Unmarshal(output, &info); err != nil {
		return nil
	}

	hostname, _ := info["hostname"].(string)
	domain, _ := info["domain"].(string)
	username, _ := info["username"].(string)
	os, _ := info["os"].(string)
	osVersion, _ := info["osVersion"].(string)
	macAddress, _ := info["macAddress"].(string)

	if hostname == "" {
		return nil
	}

	device := &WindowsDevice{
		ID:         uuid.New().String(),
		Hostname:   hostname,
		IPAddress:  ip,
		OS:         os,
		OSVersion:  osVersion,
		MACAddress: macAddress,
		IsOnline:   true,
		LastSeen:   time.Now().Format(time.RFC3339),
		Domain:     domain,
		Username:   username,
		Status:     "eligible",
	}

	// Validate eligibility
	if !s.isEligible(device) {
		device.Status = "ineligible"
	}

	return device
}

// isEligible checks if a device is eligible for DLP agent installation
func (s *Service) isEligible(device *WindowsDevice) bool {
	// Check if Windows OS
	windowsOSPatterns := []string{"Windows", "Server 2008", "Server 2012", "Server 2016", "Server 2019", "Server 2022"}
	isWindowsOS := false
	for _, pattern := range windowsOSPatterns {
		if strings.Contains(device.OS, pattern) {
			isWindowsOS = true
			break
		}
	}

	if !isWindowsOS {
		return false
	}

	// Check if online
	if !device.IsOnline {
		return false
	}

	// Check if has valid info
	if device.Hostname == "UNKNOWN" || device.MACAddress == "Unknown" {
		return false
	}

	return true
}

// DiscoverDevices performs network discovery scan
func (s *Service) DiscoverDevices(ctx context.Context) error {
	s.mu.Lock()
	if s.scanInProgress {
		s.mu.Unlock()
		return fmt.Errorf("discovery scan already in progress")
	}
	s.scanInProgress = true
	s.currentProgress = DiscoveryProgress{
		Status:       "discovering",
		Progress:     0,
		Message:      "Initializing network discovery",
		FoundDevices: []WindowsDevice{},
		TotalScanned: 0,
		TotalEligible: 0,
		ScanDuration: 0,
	}
	s.mu.Unlock()

	startTime := time.Now()

	// Phase 1: Detect network range
	log.Printf("🔍 STEP 1: Getting network range...")
	s.updateProgress(5, "Detecting network range", 0, 0)
	cidr := s.GetNetworkRange()
	log.Printf("   ✅ CIDR returned: %s", cidr)
	log.Printf("   Type: string")
	log.Printf("   Contains '/': %v", strings.Contains(cidr, "/"))
	log.Printf("   Length: %d", len(cidr))

	// Phase 2: Generate IP addresses
	log.Printf("🔍 STEP 2: Generating IP range...")
	log.Printf("   Input CIDR: %s", cidr)
	s.updateProgress(10, "Generating IP addresses", 0, 0)
	ips := s.GenerateIPRange(cidr)
	log.Printf("   ✅ IPs generated")
	log.Printf("   Count: %d", len(ips))
	if len(ips) > 0 {
		log.Printf("   First 5: %v", ips[:min(5, len(ips))])
	} else {
		log.Printf("   ⚠️ No IPs generated!")
	}

	if len(ips) == 0 {
		s.updateProgress(0, fmt.Sprintf("Failed to generate IP range for %s", cidr), 0, 0)
		s.mu.Lock()
		s.scanInProgress = false
		s.currentProgress.Status = "failed"
		s.currentProgress.Message = fmt.Sprintf("Failed to generate IP range for %s. Check backend logs for details.", cidr)
		s.mu.Unlock()
		return fmt.Errorf("failed to generate IP range for %s", cidr)
	}

	// Limit to /24 subnet (254 hosts) for performance
	if len(ips) > 254 {
		ips = ips[:254]
	}

	// Phase 3: Ping hosts (parallel batch processing)
	s.updateProgress(15, "Pinging hosts (this may take 1-2 minutes)", 0, 0)
	onlineHosts := make([]string, 0)
	batchSize := 10
	pingTimeout := 2 * time.Second

	for i := 0; i < len(ips); i += batchSize {
		select {
		case <-ctx.Done():
			s.mu.Lock()
			s.scanInProgress = false
			s.currentProgress.Status = "failed"
			s.currentProgress.Message = "Discovery cancelled"
			s.mu.Unlock()
			return ctx.Err()
		default:
		}

		end := i + batchSize
		if end > len(ips) {
			end = len(ips)
		}

		batch := ips[i:end]
		var wg sync.WaitGroup
		results := make([]bool, len(batch))

		for j, ip := range batch {
			wg.Add(1)
			go func(idx int, ipAddr string) {
				defer wg.Done()
				results[idx] = s.PingHost(ipAddr, pingTimeout)
			}(j, ip)
		}

		wg.Wait()

		for j, isOnline := range results {
			if isOnline {
				onlineHosts = append(onlineHosts, batch[j])
			}
		}

		progress := 15 + int((float64(i)/float64(len(ips)))*35)
		s.updateProgress(progress, fmt.Sprintf("Found %d online hosts", len(onlineHosts)), i+len(batch), len(onlineHosts))
	}

	// Phase 4: Identify Windows devices (check SMB/RDP ports)
	s.updateProgress(50, "Identifying Windows devices", len(onlineHosts), 0)
	windowsHosts := make([]string, 0)

	// Perform port checks in parallel with a worker pool to avoid long sequential waits.
	portTimeout := 1 * time.Second
	maxConcurrency := min(100, max(10, len(onlineHosts)/2))

	var wg sync.WaitGroup
	sem := make(chan struct{}, maxConcurrency)
	var mu sync.Mutex
	var processed int32 = 0

	for _, ip := range onlineHosts {
		select {
		case <-ctx.Done():
			s.mu.Lock()
			s.scanInProgress = false
			s.currentProgress.Status = "failed"
			s.currentProgress.Message = "Discovery cancelled"
			s.mu.Unlock()
			return ctx.Err()
		default:
		}

		wg.Add(1)
		sem <- struct{}{}
		go func(ipAddr string) {
			defer wg.Done()
			defer func() { <-sem }()

			hasSMB := s.CheckPort(ipAddr, 445, portTimeout)
			hasRDP := s.CheckPort(ipAddr, 3389, portTimeout)

			if hasSMB || hasRDP {
				mu.Lock()
				windowsHosts = append(windowsHosts, ipAddr)
				mu.Unlock()
			}

			// update progress occasionally
			now := int(atomic.AddInt32(&processed, 1))
			if now%10 == 0 || now == len(onlineHosts) {
				percent := 50 + int((float64(now)/float64(max(1, len(onlineHosts))))*20)
				s.updateProgress(percent, "Identifying Windows devices", len(onlineHosts), 0)
			}
		}(ip)
	}

	wg.Wait()

	// Phase 5: Get device information
	s.updateProgress(70, "Retrieving device information", len(onlineHosts), 0)
	devices := make([]WindowsDevice, 0)

	for i, ip := range windowsHosts {
		select {
		case <-ctx.Done():
			s.mu.Lock()
			s.scanInProgress = false
			s.currentProgress.Status = "failed"
			s.currentProgress.Message = "Discovery cancelled"
			s.mu.Unlock()
			return ctx.Err()
		default:
		}

		deviceInfo := s.GetWindowsDeviceInfo(ip)
		if deviceInfo != nil {
			// Update or add device in live list
			s.mu.Lock()
			found := false
			for idx := range s.currentProgress.FoundDevices {
				if s.currentProgress.FoundDevices[idx].IPAddress == ip {
					// Update existing device
					s.currentProgress.FoundDevices[idx] = *deviceInfo
					found = true
					break
				}
			}
			if !found {
				// Add new device
				s.currentProgress.FoundDevices = append(s.currentProgress.FoundDevices, *deviceInfo)
			}
			s.mu.Unlock()

			if deviceInfo.Status == "eligible" {
				devices = append(devices, *deviceInfo)
			}
		}

		progress := 70 + int((float64(i)/float64(len(windowsHosts)))*25)
		s.updateProgress(progress, fmt.Sprintf("Found %d eligible devices", len(devices)), len(onlineHosts), len(devices))
	}

	// Complete - merge eligible devices into the live foundDevices list (avoid wiping temporary 'scanning' entries)
	s.mu.Lock()
	// Build map of IP -> index for existing found devices
	ipIndex := make(map[string]bool)
	for _, fd := range s.currentProgress.FoundDevices {
		ipIndex[fd.IPAddress] = true
	}

	// Append eligible devices that are not already present
	for _, d := range devices {
		if !ipIndex[d.IPAddress] {
			s.currentProgress.FoundDevices = append(s.currentProgress.FoundDevices, d)
			ipIndex[d.IPAddress] = true
		} else {
			// Update existing entry with richer info
			for i := range s.currentProgress.FoundDevices {
				if s.currentProgress.FoundDevices[i].IPAddress == d.IPAddress {
					s.currentProgress.FoundDevices[i] = d
					break
				}
			}
		}
	}

	s.scanInProgress = false
	s.currentProgress.Status = "completed"
	s.currentProgress.Progress = 100
	s.currentProgress.Message = fmt.Sprintf("Discovery complete. Found %d eligible devices.", len(devices))
	s.currentProgress.TotalEligible = len(devices)
	s.currentProgress.ScanDuration = int(time.Since(startTime).Seconds())
	s.mu.Unlock()

	return nil
}

// updateProgress updates the current discovery progress
func (s *Service) updateProgress(progress int, message string, totalScanned, totalEligible int) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.currentProgress.Progress = progress
	s.currentProgress.Message = message
	s.currentProgress.TotalScanned = totalScanned
	s.currentProgress.TotalEligible = totalEligible
	// Keep existing FoundDevices (updated in real-time)
}

// GetProgress returns the current discovery progress
func (s *Service) GetProgress() DiscoveryProgress {
	s.mu.RLock()
	defer s.mu.RUnlock()
	return s.currentProgress
}

// IsScanInProgress checks if a scan is currently running
func (s *Service) IsScanInProgress() bool {
	s.mu.RLock()
	defer s.mu.RUnlock()
	return s.scanInProgress
}

// SetCancelFunc sets the cancel function for the current scan
func (s *Service) SetCancelFunc(cancel context.CancelFunc) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.cancelFunc = cancel
}

// StopScan stops the current discovery scan
func (s *Service) StopScan() {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.cancelFunc != nil {
		s.cancelFunc()
	}
	s.scanInProgress = false
	s.currentProgress.Status = "failed"
	s.currentProgress.Message = "Discovery scan stopped by user"
}
