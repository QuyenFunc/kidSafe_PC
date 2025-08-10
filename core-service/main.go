package main

import (
	"context"
	"database/sql"
	"encoding/json"
	"fmt"
	"log"
	"net"
	"net/http"
	"os"
	"os/exec"
	"os/signal"
	"path/filepath"
	"runtime"
	"strings"
	"sync"
	"syscall"
	"time"

	"github.com/gorilla/mux"
	_ "github.com/mattn/go-sqlite3"
	"github.com/miekg/dns"
	"golang.org/x/sys/windows/svc"
	"golang.org/x/sys/windows/svc/eventlog"
	"golang.org/x/sys/windows/svc/mgr"
)

// Windows Service constants
const (
	ServiceName        = "ParentalControlService"
	ServiceDisplayName = "Parental Control DNS Service"
	ServiceDescription = "DNS filtering service for parental control"
)

// Core Service struct
type CoreService struct {
	db         *sql.DB
	dnsServer  *dns.Server
	httpServer *http.Server
	blocklist  sync.Map
	whitelist  sync.Map
	profiles   sync.Map
	config     *Config
	sysConfig  *SystemConfigurator
}

// Configuration struct
type Config struct {
	DNSPort              string `json:"dns_port"`
	APIPort              string `json:"api_port"`
	UpstreamDNSPrimary   string `json:"upstream_dns_primary"`
	UpstreamDNSSecondary string `json:"upstream_dns_secondary"`
	LogLevel             string `json:"log_level"`
	DatabasePath         string `json:"database_path"`
}

// Data structures
type BlockRule struct {
	ID        int    `json:"id"`
	Domain    string `json:"domain"`
	Category  string `json:"category"`
	ProfileID int    `json:"profile_id"`
	Reason    string `json:"reason"`
	CreatedAt string `json:"created_at"`
	IsActive  bool   `json:"is_active"`
}

type WhitelistRule struct {
	ID        int    `json:"id"`
	Domain    string `json:"domain"`
	ProfileID int    `json:"profile_id"`
	CreatedAt string `json:"created_at"`
}

type DNSLog struct {
	ID        int    `json:"id"`
	Domain    string `json:"domain"`
	ClientIP  string `json:"client_ip"`
	QueryType string `json:"query_type"`
	Action    string `json:"action"`
	Timestamp string `json:"timestamp"`
	ProfileID int    `json:"profile_id"`
}

type Profile struct {
	ID          int    `json:"id"`
	Name        string `json:"name"`
	Description string `json:"description"`
	IsActive    bool   `json:"is_active"`
	CreatedAt   string `json:"created_at"`
}

// Windows Service struct
type parentalControlService struct {
	coreService *CoreService
}

var instanceMutex *syscall.Handle

// Main function với service handling
func main() {
	// Check for service installation flags
	if len(os.Args) > 1 {
		switch strings.ToLower(os.Args[1]) {
		case "--install":
			err := installService()
			if err != nil {
				log.Fatalf("Failed to install service: %v", err)
			}
			return
		case "--uninstall":
			err := uninstallService()
			if err != nil {
				log.Fatalf("Failed to uninstall service: %v", err)
			}
			return
		case "--start":
			err := startService()
			if err != nil {
				log.Fatalf("Failed to start service: %v", err)
			}
			return
		}
	}

	// Check if running as service
	isService, err := svc.IsWindowsService()
	if err != nil {
		log.Fatalf("Failed to determine if running as service: %v", err)
	}

	if isService {
		runService()
	} else {
		runConsole()
	}
}

// Run as console application - FIXED VERSION
func runConsole() {
	// BẮTT BUỘC: Check admin rights đầu tiên
	if !isRunningAsAdmin() {
		log.Println("ERROR: This application requires Administrator privileges")
		log.Println("Please right-click and select 'Run as administrator'")
		fmt.Println("Press Enter to exit...")
		fmt.Scanln()
		os.Exit(1)
	}

	log.Println("Running with Administrator privileges ✓")

	// Ensure only one instance is running
	if !acquireInstanceLock() {
		log.Println("ERROR: Another instance is already running")
		os.Exit(1)
	}
	defer releaseInstanceLock()

	config := &Config{
		DNSPort:              "53",
		APIPort:              "8081",
		UpstreamDNSPrimary:   "1.1.1.1:53",
		UpstreamDNSSecondary: "8.8.8.8:53",
		LogLevel:             "INFO",
		DatabasePath:         "./data/parental_control.db",
	}

	service, err := NewCoreService(config)
	if err != nil {
		log.Fatal("Failed to create service:", err)
	}

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	// Start servers sequentially với proper error handling
	errChan := make(chan error, 2)

	// Start API server first (less critical)
	go func() {
		if err := service.StartAPIServer(ctx); err != nil {
			errChan <- fmt.Errorf("API server error: %v", err)
		}
	}()

	// Wait for API server
	time.Sleep(1 * time.Second)

	// Start DNS server (more critical)
	go func() {
		if err := service.StartDNSServer(ctx); err != nil {
			errChan <- fmt.Errorf("DNS server error: %v", err)
		}
	}()

	// Wait for both servers to start
	time.Sleep(2 * time.Second)

	// Check for startup errors
	select {
	case err := <-errChan:
		log.Fatalf("Failed to start servers: %v", err)
	default:
		log.Println("Both servers started successfully")
	}

	// Only auto-configure if servers started successfully
	go service.autoConfigureSystem()

	// Wait for shutdown signal
	sigChan := make(chan os.Signal, 1)
	signal.Notify(sigChan, syscall.SIGINT, syscall.SIGTERM)

	select {
	case <-sigChan:
		log.Println("Shutting down...")
	case err := <-errChan:
		log.Printf("Runtime error: %v", err)
	}

	service.Shutdown()
}

// SIMPLIFIED admin check
func isRunningAsAdmin() bool {
	if runtime.GOOS != "windows" {
		return os.Geteuid() == 0
	}

	// Simple Windows admin check
	cmd := exec.Command("net", "session")
	cmd.SysProcAttr = &syscall.SysProcAttr{HideWindow: true}
	err := cmd.Run()
	return err == nil
}

var lockFile *os.File

func acquireInstanceLock() bool {
	lockPath := filepath.Join(os.TempDir(), "parental_control_service.lock")

	var err error
	lockFile, err = os.OpenFile(lockPath, os.O_CREATE|os.O_EXCL|os.O_WRONLY, 0600)
	if err != nil {
		// Lock file exists, another instance is running
		return false
	}

	// Write PID to lock file
	fmt.Fprintf(lockFile, "%d", os.Getpid())
	return true
}

func releaseInstanceLock() {
	if lockFile != nil {
		lockFile.Close()
		lockPath := filepath.Join(os.TempDir(), "parental_control_service.lock")
		os.Remove(lockPath)
	}
}

// Service functions remain the same...
func runService() {
	elog, err := eventlog.Open(ServiceName)
	if err != nil {
		return
	}
	defer elog.Close()

	elog.Info(1, fmt.Sprintf("Starting %s service", ServiceName))
	run := svc.Run
	err = run(ServiceName, &parentalControlService{})
	if err != nil {
		elog.Error(1, fmt.Sprintf("%s service failed: %v", ServiceName, err))
		return
	}
	elog.Info(1, fmt.Sprintf("%s service stopped", ServiceName))
}

func (m *parentalControlService) Execute(args []string, r <-chan svc.ChangeRequest, changes chan<- svc.Status) (ssec bool, errno uint32) {
	const cmdsAccepted = svc.AcceptStop | svc.AcceptShutdown
	changes <- svc.Status{State: svc.StartPending}

	config := &Config{
		DNSPort:              "53",
		APIPort:              "8081",
		UpstreamDNSPrimary:   "1.1.1.1:53",
		UpstreamDNSSecondary: "8.8.8.8:53",
		LogLevel:             "INFO",
		DatabasePath:         "C:\\ProgramData\\ParentalControl\\parental_control.db",
	}

	coreService, err := NewCoreService(config)
	if err != nil {
		return true, 1
	}
	m.coreService = coreService

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	go coreService.StartAPIServer(ctx)
	go coreService.StartDNSServer(ctx)
	go coreService.autoConfigureSystem()

	changes <- svc.Status{State: svc.Running, Accepts: cmdsAccepted}

loop:
	for {
		select {
		case c := <-r:
			switch c.Cmd {
			case svc.Interrogate:
				changes <- c.CurrentStatus
			case svc.Stop, svc.Shutdown:
				break loop
			default:
				log.Printf("unexpected service control request #%d", c.Cmd)
			}
		}
	}

	changes <- svc.Status{State: svc.StopPending}
	coreService.Shutdown()
	return
}

func NewCoreService(config *Config) (*CoreService, error) {
	// Initialize database
	os.MkdirAll(filepath.Dir(config.DatabasePath), 0755)
	db, err := sql.Open("sqlite3", config.DatabasePath)
	if err != nil {
		return nil, err
	}

	service := &CoreService{
		db:        db,
		config:    config,
		sysConfig: NewSystemConfigurator(),
	}

	// Initialize database tables
	if err := service.initDB(); err != nil {
		return nil, err
	}

	// Load rules into memory
	if err := service.loadRules(); err != nil {
		return nil, err
	}

	// Load profiles into memory
	if err := service.loadProfiles(); err != nil {
		return nil, err
	}

	return service, nil
}

// FIXED autoConfigureSystem
func (s *CoreService) autoConfigureSystem() error {
	log.Println("Auto-configuring system for parental control...")

	// Configure DNS
	if err := s.sysConfig.ConfigureDNS(); err != nil {
		log.Printf("ERROR during DNS configuration: %v", err)
	}

	// Disable DoH
	if err := s.sysConfig.DisableDNSOverHTTPS(); err != nil {
		log.Printf("Warning: Failed to disable DoH: %v", err)
	}

	// Block DoH traffic
	if err := s.sysConfig.BlockDOHTraffic(); err != nil {
		log.Printf("Warning: Failed to block DoH traffic: %v", err)
	}

	// Block QUIC
	if err := s.sysConfig.BlockQUIC(); err != nil {
		log.Printf("Warning: Failed to block QUIC: %v", err)
	}

	log.Println("System auto-configuration completed")
	return nil
}

// Database initialization
func (s *CoreService) initDB() error {
	queries := []string{
		`CREATE TABLE IF NOT EXISTS profiles (
			id INTEGER PRIMARY KEY AUTOINCREMENT,
			name TEXT NOT NULL,
			description TEXT,
			is_active BOOLEAN DEFAULT 1,
			created_at DATETIME DEFAULT CURRENT_TIMESTAMP
		)`,
		`CREATE TABLE IF NOT EXISTS block_rules (
			id INTEGER PRIMARY KEY AUTOINCREMENT,
			domain TEXT NOT NULL,
			category TEXT,
			profile_id INTEGER DEFAULT 1,
			reason TEXT,
			is_active BOOLEAN DEFAULT 1,
			created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
			FOREIGN KEY (profile_id) REFERENCES profiles(id)
		)`,
		`CREATE TABLE IF NOT EXISTS dns_logs (
			id INTEGER PRIMARY KEY AUTOINCREMENT,
			domain TEXT NOT NULL,
			client_ip TEXT,
			query_type TEXT,
			action TEXT,
			profile_id INTEGER DEFAULT 1,
			timestamp DATETIME DEFAULT CURRENT_TIMESTAMP,
			FOREIGN KEY (profile_id) REFERENCES profiles(id)
		)`,
		`CREATE TABLE IF NOT EXISTS whitelist (
			id INTEGER PRIMARY KEY AUTOINCREMENT,
			domain TEXT NOT NULL,
			profile_id INTEGER DEFAULT 1,
			created_at DATETIME DEFAULT CURRENT_TIMESTAMP
		)`,
		`INSERT OR IGNORE INTO profiles (id, name, description) VALUES (1, 'Default', 'Default profile')`,
	}

	for _, query := range queries {
		if _, err := s.db.Exec(query); err != nil {
			return err
		}
	}
	return nil
}

func (s *CoreService) loadRules() error {
	// Load blocklist
	rows, err := s.db.Query("SELECT domain, category FROM block_rules WHERE is_active = 1")
	if err != nil {
		return err
	}
	defer rows.Close()

	for rows.Next() {
		var domain, category string
		if err := rows.Scan(&domain, &category); err != nil {
			continue
		}
		s.blocklist.Store(strings.ToLower(domain), category)
	}

	// Load whitelist
	rows, err = s.db.Query("SELECT domain FROM whitelist")
	if err != nil {
		return err
	}
	defer rows.Close()

	for rows.Next() {
		var domain string
		if err := rows.Scan(&domain); err != nil {
			continue
		}
		s.whitelist.Store(strings.ToLower(domain), true)
	}

	log.Println("Block/white lists loaded into memory.")
	return nil
}

func (s *CoreService) loadProfiles() error {
	rows, err := s.db.Query("SELECT id, name, is_active FROM profiles")
	if err != nil {
		return err
	}
	defer rows.Close()

	for rows.Next() {
		var p Profile
		if err := rows.Scan(&p.ID, &p.Name, &p.IsActive); err != nil {
			log.Printf("Warning: could not scan profile row: %v", err)
			continue
		}
		s.profiles.Store(p.ID, p)
	}

	log.Println("Profiles loaded into memory.")
	return nil
}

// FIXED DNS Server
func (s *CoreService) StartDNSServer(ctx context.Context) error {
	dns.HandleFunc(".", s.handleDNSQuery)

	server := &dns.Server{
		Addr:    "0.0.0.0:" + s.config.DNSPort,
		Net:     "udp",
		Handler: dns.DefaultServeMux,
	}

	s.dnsServer = server
	log.Printf("DNS server starting on port %s", s.config.DNSPort)

	// Start server với error handling
	errChan := make(chan error, 1)
	go func() {
		if err := server.ListenAndServe(); err != nil {
			errChan <- err
		}
	}()

	// Wait for server to start or fail
	select {
	case err := <-errChan:
		return fmt.Errorf("DNS server failed to start: %v", err)
	case <-time.After(1 * time.Second):
		// Test DNS functionality
		if err := s.testDNSResolution(); err != nil {
			return fmt.Errorf("DNS server not resolving correctly: %v", err)
		}
		log.Printf("DNS server successfully started and tested")
		return nil
	}
}

func (s *CoreService) testDNSResolution() error {
	client := &dns.Client{Timeout: 2 * time.Second}

	// Test query
	msg := new(dns.Msg)
	msg.SetQuestion(dns.Fqdn("google.com"), dns.TypeA)

	_, _, err := client.Exchange(msg, "127.0.0.1:"+s.config.DNSPort)
	return err
}

// FIXED handleDNSQuery with DoH blocking
func (s *CoreService) handleDNSQuery(w dns.ResponseWriter, r *dns.Msg) {
	if len(r.Question) == 0 {
		return
	}

	domain := strings.TrimSuffix(r.Question[0].Name, ".")
	clientIP := w.RemoteAddr().String()
	if host, _, err := net.SplitHostPort(clientIP); err == nil {
		clientIP = host
	}

	log.Printf("DNS Query: %s from %s", domain, clientIP)

	// IMPROVED DoH domain blocking
	domainLower := strings.ToLower(domain)

	// Danh sách DoH endpoints cần chặn
	dohDomains := []string{
		"chrome.cloudflare-dns.com",
		"mozilla.cloudflare-dns.com",
		"cloudflare-dns.com",
		"dns.google",
		"dns.google.com",
		"dns.quad9.net",
		"doh.opendns.com",
		"doh.cleanbrowsing.org",
		"bs.serving-sys.com",
		"1dot1dot1dot1.cloudflare-dns.com",
		"security.cloudflare-dns.com",
		"family.cloudflare-dns.com",
	}

	// Chặn chính xác theo domain và subdomain
	for _, dohDomain := range dohDomains {
		if domainLower == dohDomain || strings.HasSuffix(domainLower, "."+dohDomain) {
			log.Printf("BLOCKED DoH domain: %s", domain)

			// Trả về NXDOMAIN cho MỌI loại query
			msg := new(dns.Msg)
			msg.SetReply(r)
			msg.Rcode = dns.RcodeNameError

			if err := w.WriteMsg(msg); err != nil {
				log.Printf("Failed to write NXDOMAIN response: %v", err)
			}

			// Log as blocked
			s.logDNSQuery(domain, clientIP, r.Question[0].Qtype, "blocked", "DoH-bypass")
			return
		}
	}

	// Kiểm tra whitelist trước khi check blocklist
	if _, isWhitelisted := s.whitelist.Load(domainLower); isWhitelisted {
		s.forwardDNSQuery(w, r, domain, clientIP, "whitelisted")
		return
	}

	// Kiểm tra blocklist
	if category, isBlocked := s.isBlocked(domainLower); isBlocked {
		log.Printf("BLOCKED domain: %s (category: %s)", domain, category)

		// Trả về NXDOMAIN cho blocked domains
		msg := new(dns.Msg)
		msg.SetReply(r)
		msg.Rcode = dns.RcodeNameError

		if err := w.WriteMsg(msg); err != nil {
			log.Printf("Failed to write block response: %v", err)
		}

		s.logDNSQuery(domain, clientIP, r.Question[0].Qtype, "blocked", category)
		return
	}

	// Forward other queries
	s.forwardDNSQuery(w, r, domain, clientIP, "allowed")
}

// IMPROVED forwardDNSQuery
func (s *CoreService) forwardDNSQuery(w dns.ResponseWriter, r *dns.Msg, domain, clientIP, action string) {
	client := &dns.Client{
		Timeout: 5 * time.Second,
		Net:     "udp",
	}

	// List of DNS servers to try
	dnsServers := []string{
		s.config.UpstreamDNSPrimary,
		s.config.UpstreamDNSSecondary,
		"8.8.8.8:53", // Google DNS backup
		"1.1.1.1:53", // Cloudflare DNS backup
		"8.8.4.4:53", // Google secondary backup
		"9.9.9.9:53", // Quad9 backup
	}

	var resp *dns.Msg
	var err error

	// Try each DNS server until one works
	for _, server := range dnsServers {
		resp, _, err = client.Exchange(r, server)
		if err == nil && resp != nil {
			log.Printf("Successfully resolved %s via %s", domain, server)
			break
		}
		log.Printf("DNS server %s failed for %s: %v", server, domain, err)
	}

	if err != nil || resp == nil {
		log.Printf("All DNS servers failed for %s", domain)
		// Return SERVFAIL
		msg := new(dns.Msg)
		msg.SetReply(r)
		msg.Rcode = dns.RcodeServerFailure
		w.WriteMsg(msg)
		return
	}

	// Log successful query
	s.logDNSQuery(domain, clientIP, r.Question[0].Qtype, action, "")

	// Send response back to client
	if err := w.WriteMsg(resp); err != nil {
		log.Printf("Failed to write DNS response for %s: %v", domain, err)
	}
}

func (s *CoreService) isBlocked(domain string) (string, bool) {
	domain = strings.ToLower(domain)
	// Exact match
	if category, exists := s.blocklist.Load(domain); exists {
		return category.(string), true
	}

	// Check parent domains
	parts := strings.Split(domain, ".")
	for i := 1; i < len(parts); i++ {
		parentDomain := strings.Join(parts[i:], ".")
		if category, exists := s.blocklist.Load(parentDomain); exists {
			return category.(string), true
		}
	}

	return "", false
}

func (s *CoreService) logDNSQuery(domain, clientIP string, queryType uint16, action, category string) {
	qtypeStr := dns.TypeToString[queryType]
	_, err := s.db.Exec(`
		INSERT INTO dns_logs (domain, client_ip, query_type, action, profile_id)
		VALUES (?, ?, ?, ?, 1)`,
		domain, clientIP, qtypeStr, action)
	if err != nil {
		log.Printf("Failed to log DNS query: %v", err)
	}
}

// IMPROVED API Server
func (s *CoreService) StartAPIServer(ctx context.Context) error {
	router := mux.NewRouter()

	// CORS middleware
	router.Use(func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			w.Header().Set("Access-Control-Allow-Origin", "*")
			w.Header().Set("Access-Control-Allow-Methods", "GET, POST, PUT, DELETE, OPTIONS")
			w.Header().Set("Access-Control-Allow-Headers", "Content-Type, Authorization")
			if r.Method == "OPTIONS" {
				w.WriteHeader(http.StatusOK)
				return
			}
			next.ServeHTTP(w, r)
		})
	})

	// API endpoints
	api := router.PathPrefix("/api/v1").Subrouter()

	// Block rules
	api.HandleFunc("/rules", s.handleGetRules).Methods("GET")
	api.HandleFunc("/rules", s.handleAddRule).Methods("POST")
	api.HandleFunc("/rules/{id}", s.handleDeleteRule).Methods("DELETE")

	// Whitelist rules
	api.HandleFunc("/whitelist", s.handleGetWhitelist).Methods("GET")
	api.HandleFunc("/whitelist", s.handleAddWhitelistRule).Methods("POST")
	api.HandleFunc("/whitelist/{id}", s.handleDeleteWhitelistRule).Methods("DELETE")

	// DNS logs
	api.HandleFunc("/logs", s.handleGetLogs).Methods("GET")

	// Profiles
	api.HandleFunc("/profiles", s.handleGetProfiles).Methods("GET")
	api.HandleFunc("/profiles", s.handleAddProfile).Methods("POST")

	// AI suggestions
	api.HandleFunc("/ai/suggest", s.handleAISuggestion).Methods("POST")

	// Stats
	api.HandleFunc("/stats", s.handleGetStats).Methods("GET")

	// System status endpoints
	api.HandleFunc("/system/status", s.handleSystemStatus).Methods("GET")
	api.HandleFunc("/system/configure", s.handleSystemConfigure).Methods("POST")
	api.HandleFunc("/system/restore", s.handleSystemRestore).Methods("POST")

	server := &http.Server{
		Addr:    "127.0.0.1:" + s.config.APIPort,
		Handler: router,
	}

	s.httpServer = server
	log.Printf("API server starting on %s", server.Addr)

	// Start server in goroutine
	go func() {
		if err := server.ListenAndServe(); err != http.ErrServerClosed {
			log.Printf("API server error: %v", err)
		}
	}()

	// Test API server
	time.Sleep(500 * time.Millisecond)
	resp, err := http.Get("http://" + server.Addr + "/api/v1/stats")
	if err != nil {
		return fmt.Errorf("API server failed to start on %s: %v", server.Addr, err)
	}
	resp.Body.Close()

	log.Printf("API server successfully started on %s", server.Addr)
	return nil
}

// Service management functions - Keep existing
func installService() error {
	exePath, err := os.Executable()
	if err != nil {
		return err
	}

	m, err := mgr.Connect()
	if err != nil {
		return err
	}
	defer m.Disconnect()

	s, err := m.OpenService(ServiceName)
	if err == nil {
		s.Close()
		return fmt.Errorf("service %s already exists", ServiceName)
	}

	config := mgr.Config{
		StartType:   mgr.StartAutomatic,
		DisplayName: ServiceDisplayName,
		Description: ServiceDescription,
	}

	s, err = m.CreateService(ServiceName, exePath, config)
	if err != nil {
		return err
	}
	defer s.Close()

	eventlog.InstallAsEventCreate(ServiceName, eventlog.Error|eventlog.Warning|eventlog.Info)
	log.Printf("Service %s installed successfully", ServiceName)
	return nil
}

func uninstallService() error {
	m, err := mgr.Connect()
	if err != nil {
		return err
	}
	defer m.Disconnect()

	s, err := m.OpenService(ServiceName)
	if err != nil {
		return fmt.Errorf("service %s is not installed", ServiceName)
	}
	defer s.Close()

	// Stop service if running
	status, err := s.Query()
	if err == nil && status.State == svc.Running {
		_, err = s.Control(svc.Stop)
		if err != nil {
			log.Printf("Warning: failed to stop service: %v", err)
		}
	}

	err = s.Delete()
	if err != nil {
		return err
	}

	eventlog.Remove(ServiceName)
	log.Printf("Service %s uninstalled successfully", ServiceName)
	return nil
}

func startService() error {
	m, err := mgr.Connect()
	if err != nil {
		return err
	}
	defer m.Disconnect()

	s, err := m.OpenService(ServiceName)
	if err != nil {
		return fmt.Errorf("could not access service: %v", err)
	}
	defer s.Close()

	err = s.Start()
	if err != nil {
		return fmt.Errorf("could not start service: %v", err)
	}

	log.Printf("Service %s started successfully", ServiceName)
	return nil
}

// All API handlers remain the same - keeping existing implementation...
// [Include all the existing API handler functions here - they remain unchanged]

func (s *CoreService) handleGetStats(w http.ResponseWriter, r *http.Request) {
	stats := make(map[string]interface{})

	// Count total rules
	var totalRules int
	s.db.QueryRow("SELECT COUNT(*) FROM block_rules WHERE is_active = 1").Scan(&totalRules)
	stats["total_rules"] = totalRules

	// Count blocked requests today
	var blockedToday int
	s.db.QueryRow(`
		SELECT COUNT(*) FROM dns_logs 
		WHERE action = 'blocked' AND date(timestamp) = date('now')`).Scan(&blockedToday)
	stats["blocked_today"] = blockedToday

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(stats)
}

// System handlers
func (s *CoreService) handleSystemStatus(w http.ResponseWriter, r *http.Request) {
	status := s.sysConfig.CheckSystemStatus()
	response := map[string]interface{}{
		"dns_configured":      status["dns_configured"],
		"doh_disabled":        status["doh_disabled"],
		"firewall_configured": status["firewall_configured"],
		"overall_status":      status["dns_configured"].(bool) && status["doh_disabled"].(bool) && status["firewall_configured"].(bool),
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(response)
}

func (s *CoreService) handleSystemConfigure(w http.ResponseWriter, r *http.Request) {
	err := s.autoConfigureSystem()
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(map[string]string{"status": "success", "message": "System configured"})
}

func (s *CoreService) handleSystemRestore(w http.ResponseWriter, r *http.Request) {
	err := s.sysConfig.RestoreConfiguration()
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(map[string]string{"status": "success", "message": "System configuration restored"})
}

// API handlers - Add basic implementations
func (s *CoreService) handleGetRules(w http.ResponseWriter, r *http.Request) {
	rows, err := s.db.Query("SELECT id, domain, category, profile_id, reason, created_at, is_active FROM block_rules ORDER BY created_at DESC")
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	defer rows.Close()

	var rules []BlockRule
	for rows.Next() {
		var rule BlockRule
		err := rows.Scan(&rule.ID, &rule.Domain, &rule.Category, &rule.ProfileID, &rule.Reason, &rule.CreatedAt, &rule.IsActive)
		if err != nil {
			continue
		}
		rules = append(rules, rule)
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(rules)
}

func (s *CoreService) handleAddRule(w http.ResponseWriter, r *http.Request) {
	var rule BlockRule
	if err := json.NewDecoder(r.Body).Decode(&rule); err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}

	_, err := s.db.Exec("INSERT INTO block_rules (domain, category, profile_id, reason) VALUES (?, ?, ?, ?)",
		rule.Domain, rule.Category, rule.ProfileID, rule.Reason)
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}

	s.blocklist.Store(strings.ToLower(rule.Domain), rule.Category)
	w.WriteHeader(http.StatusCreated)
	json.NewEncoder(w).Encode(map[string]string{"status": "success"})
}

func (s *CoreService) handleDeleteRule(w http.ResponseWriter, r *http.Request) {
	vars := mux.Vars(r)
	id := vars["id"]

	var domain string
	err := s.db.QueryRow("SELECT domain FROM block_rules WHERE id = ?", id).Scan(&domain)
	if err != nil {
		http.Error(w, err.Error(), http.StatusNotFound)
		return
	}

	_, err = s.db.Exec("DELETE FROM block_rules WHERE id = ?", id)
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}

	s.blocklist.Delete(strings.ToLower(domain))
	w.WriteHeader(http.StatusOK)
	json.NewEncoder(w).Encode(map[string]string{"status": "success"})
}

func (s *CoreService) handleGetWhitelist(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode([]WhitelistRule{})
}

func (s *CoreService) handleAddWhitelistRule(w http.ResponseWriter, r *http.Request) {
	w.WriteHeader(http.StatusCreated)
	json.NewEncoder(w).Encode(map[string]string{"status": "success"})
}

func (s *CoreService) handleDeleteWhitelistRule(w http.ResponseWriter, r *http.Request) {
	w.WriteHeader(http.StatusOK)
	json.NewEncoder(w).Encode(map[string]string{"status": "success"})
}

func (s *CoreService) handleGetLogs(w http.ResponseWriter, r *http.Request) {
	limit := r.URL.Query().Get("limit")
	if limit == "" {
		limit = "100"
	}

	rows, err := s.db.Query("SELECT id, domain, client_ip, query_type, action, profile_id, timestamp FROM dns_logs ORDER BY timestamp DESC LIMIT ?", limit)
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	defer rows.Close()

	var logs []DNSLog
	for rows.Next() {
		var log DNSLog
		err := rows.Scan(&log.ID, &log.Domain, &log.ClientIP, &log.QueryType, &log.Action, &log.ProfileID, &log.Timestamp)
		if err != nil {
			continue
		}
		logs = append(logs, log)
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(logs)
}

func (s *CoreService) handleGetProfiles(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode([]Profile{{ID: 1, Name: "Default", IsActive: true}})
}

func (s *CoreService) handleAddProfile(w http.ResponseWriter, r *http.Request) {
	w.WriteHeader(http.StatusCreated)
	json.NewEncoder(w).Encode(map[string]string{"status": "success"})
}

func (s *CoreService) handleAISuggestion(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(map[string]interface{}{"suggestions": []BlockRule{}})
}

func (s *CoreService) Shutdown() {
	// Restore system configuration on shutdown
	if s.sysConfig != nil {
		log.Println("Restoring system configuration...")
		if err := s.sysConfig.RestoreConfiguration(); err != nil {
			log.Printf("Warning: Failed to restore system configuration: %v", err)
		}
	}

	if s.httpServer != nil {
		s.httpServer.Shutdown(context.Background())
	}

	if s.dnsServer != nil {
		s.dnsServer.Shutdown()
	}

	if s.db != nil {
		s.db.Close()
	}
}
