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
	"os/signal"
	"path/filepath"
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
	DNSPort      string `json:"dns_port"`
	APIPort      string `json:"api_port"`
	UpstreamDNS  string `json:"upstream_dns"`
	LogLevel     string `json:"log_level"`
	DatabasePath string `json:"database_path"`
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

type DNSLog struct {
	ID        int    `json:"id"`
	Domain    string `json:"domain"`
	ClientIP  string `json:"client_ip"`
	QueryType string `json:"query_type"`
	Action    string `json:"action"` // blocked/allowed
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
		// Running as console application
		runConsole()
	}
}

// Run as console application
func runConsole() {
	config := &Config{
		DNSPort:      "5353",
		APIPort:      "8081",
		UpstreamDNS:  "1.1.1.1:53",
		LogLevel:     "INFO",
		DatabasePath: "./data/parental_control.db",
	}

	service, err := NewCoreService(config)
	if err != nil {
		log.Fatal("Failed to create service:", err)
	}

	// Start service
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	// go service.StartDNSServer(ctx)
	go service.StartAPIServer(ctx)

	// Wait for shutdown signal
	sigChan := make(chan os.Signal, 1)
	signal.Notify(sigChan, syscall.SIGINT, syscall.SIGTERM)
	<-sigChan

	log.Println("Shutting down service...")
	service.Shutdown()
}

// Run as Windows Service
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

// Windows Service Execute method
func (m *parentalControlService) Execute(args []string, r <-chan svc.ChangeRequest, changes chan<- svc.Status) (ssec bool, errno uint32) {
	const cmdsAccepted = svc.AcceptStop | svc.AcceptShutdown
	changes <- svc.Status{State: svc.StartPending}

	// Initialize core service
	config := &Config{
		DNSPort:      "5353",
		APIPort:      "8081",
		UpstreamDNS:  "1.1.1.1:53",
		LogLevel:     "INFO",
		DatabasePath: "C:\\ProgramData\\ParentalControl\\parental_control.db",
	}

	coreService, err := NewCoreService(config)
	if err != nil {
		return true, 1
	}
	m.coreService = coreService

	// Start core service
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	go coreService.StartDNSServer(ctx)
	go coreService.StartAPIServer(ctx)

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
				// Unexpected control request
			}
		}
	}

	changes <- svc.Status{State: svc.StopPending}
	coreService.Shutdown()
	return
}

// Service management functions
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

	// Set up event log
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

func NewCoreService(config *Config) (*CoreService, error) {
	// Initialize database
	// Sửa thành (đúng)
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

	// Auto-configure system if needed
	if err := service.autoConfigureSystem(); err != nil {
		log.Printf("Warning: Failed to auto-configure system: %v", err)
	}
	return service, nil
}

func (s *CoreService) autoConfigureSystem() error {
	log.Println("Auto-configuring system for parental control...")

	// Configure DNS
	if err := s.sysConfig.ConfigureDNS(); err != nil {
		log.Printf("Failed to configure DNS: %v", err)
	}

	// Disable DoH
	if err := s.sysConfig.DisableDNSOverHTTPS(); err != nil {
		log.Printf("Failed to disable DoH: %v", err)
	}

	// Block QUIC
	if err := s.sysConfig.BlockQUIC(); err != nil {
		log.Printf("Failed to block QUIC: %v", err)
	}

	log.Println("System auto-configuration completed")
	return nil
}

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

	return nil
}

// DNS Server
func (s *CoreService) StartDNSServer(ctx context.Context) {
	dns.HandleFunc(".", s.handleDNSQuery)

	server := &dns.Server{
		Addr: "127.0.0.1:" + s.config.DNSPort,
		Net:  "udp",
	}
	s.dnsServer = server

	log.Printf("DNS server starting on %s", server.Addr)
	if err := server.ListenAndServe(); err != nil {
		log.Printf("DNS server error: %v", err)
	}
}

func (s *CoreService) handleDNSQuery(w dns.ResponseWriter, r *dns.Msg) {
	msg := new(dns.Msg)
	msg.SetReply(r)

	if len(r.Question) == 0 {
		w.WriteMsg(msg)
		return
	}

	question := r.Question[0]
	domain := strings.TrimSuffix(question.Name, ".")
	clientIP := w.RemoteAddr().(*net.UDPAddr).IP.String()

	// Check whitelist first
	if _, whitelisted := s.whitelist.Load(strings.ToLower(domain)); whitelisted {
		s.forwardDNSQuery(w, r, domain, clientIP, "allowed")
		return
	}

	// Check if domain should be blocked
	if category, blocked := s.isBlocked(domain); blocked {
		// Block the domain - return NXDOMAIN or null route
		msg.Rcode = dns.RcodeNameError
		s.logDNSQuery(domain, clientIP, question.Qtype, "blocked", category)
		w.WriteMsg(msg)
		return
	}

	// Forward to upstream DNS
	s.forwardDNSQuery(w, r, domain, clientIP, "allowed")
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

func (s *CoreService) forwardDNSQuery(w dns.ResponseWriter, r *dns.Msg, domain, clientIP, action string) {
	// Forward to upstream DNS
	client := &dns.Client{
		Timeout: 5 * time.Second,
	}

	resp, _, err := client.Exchange(r, s.config.UpstreamDNS)
	if err != nil {
		log.Printf("DNS forward error: %v", err)
		msg := new(dns.Msg)
		msg.SetReply(r)
		msg.Rcode = dns.RcodeServerFailure
		w.WriteMsg(msg)
		return
	}

	s.logDNSQuery(domain, clientIP, r.Question[0].Qtype, action, "")
	w.WriteMsg(resp)
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

// REST API Server
func (s *CoreService) StartAPIServer(ctx context.Context) {
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
	if err := server.ListenAndServe(); err != http.ErrServerClosed {
		log.Printf("API server error: %v", err)
	}
}

// System API handlers
func (s *CoreService) handleSystemStatus(w http.ResponseWriter, r *http.Request) {
	status := s.sysConfig.CheckSystemStatus()

	response := map[string]interface{}{
		"dns_configured":      status["dns_configured"],
		"doh_disabled":        status["doh_disabled"],
		"firewall_configured": status["firewall_configured"],
		"overall_status":      status["dns_configured"] && status["doh_disabled"] && status["firewall_configured"],
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

// API Handlers
func (s *CoreService) handleGetRules(w http.ResponseWriter, r *http.Request) {
	rows, err := s.db.Query(`
        SELECT id, domain, category, profile_id, reason, created_at, is_active 
        FROM block_rules ORDER BY created_at DESC`)
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	defer rows.Close()

	var rules []BlockRule
	for rows.Next() {
		var rule BlockRule
		err := rows.Scan(&rule.ID, &rule.Domain, &rule.Category,
			&rule.ProfileID, &rule.Reason, &rule.CreatedAt, &rule.IsActive)
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

	_, err := s.db.Exec(`
        INSERT INTO block_rules (domain, category, profile_id, reason) 
        VALUES (?, ?, ?, ?)`,
		rule.Domain, rule.Category, rule.ProfileID, rule.Reason)

	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}

	// Update in-memory cache
	s.blocklist.Store(strings.ToLower(rule.Domain), rule.Category)

	w.WriteHeader(http.StatusCreated)
	json.NewEncoder(w).Encode(map[string]string{"status": "success"})
}

func (s *CoreService) handleDeleteRule(w http.ResponseWriter, r *http.Request) {
	vars := mux.Vars(r)
	id := vars["id"]

	// Get domain before deleting
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

	// Remove from in-memory cache
	s.blocklist.Delete(strings.ToLower(domain))

	w.WriteHeader(http.StatusOK)
	json.NewEncoder(w).Encode(map[string]string{"status": "success"})
}

func (s *CoreService) handleGetLogs(w http.ResponseWriter, r *http.Request) {
	limit := r.URL.Query().Get("limit")
	if limit == "" {
		limit = "100"
	}

	rows, err := s.db.Query(`
        SELECT id, domain, client_ip, query_type, action, profile_id, timestamp 
        FROM dns_logs ORDER BY timestamp DESC LIMIT ?`, limit)
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	defer rows.Close()

	var logs []DNSLog
	for rows.Next() {
		var log DNSLog
		err := rows.Scan(&log.ID, &log.Domain, &log.ClientIP,
			&log.QueryType, &log.Action, &log.ProfileID, &log.Timestamp)
		if err != nil {
			continue
		}
		logs = append(logs, log)
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(logs)
}

func (s *CoreService) handleGetProfiles(w http.ResponseWriter, r *http.Request) {
	rows, err := s.db.Query(`
        SELECT id, name, description, is_active, created_at 
        FROM profiles ORDER BY created_at`)
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	defer rows.Close()

	var profiles []Profile
	for rows.Next() {
		var profile Profile
		err := rows.Scan(&profile.ID, &profile.Name, &profile.Description,
			&profile.IsActive, &profile.CreatedAt)
		if err != nil {
			continue
		}
		profiles = append(profiles, profile)
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(profiles)
}

func (s *CoreService) handleAddProfile(w http.ResponseWriter, r *http.Request) {
	var profile Profile
	if err := json.NewDecoder(r.Body).Decode(&profile); err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}

	_, err := s.db.Exec(`
        INSERT INTO profiles (name, description) VALUES (?, ?)`,
		profile.Name, profile.Description)

	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}

	w.WriteHeader(http.StatusCreated)
	json.NewEncoder(w).Encode(map[string]string{"status": "success"})
}

// AI Suggestion Handler
func (s *CoreService) handleAISuggestion(w http.ResponseWriter, r *http.Request) {
	var request struct {
		Topic    string `json:"topic"`
		Category string `json:"category"`
	}

	if err := json.NewDecoder(r.Body).Decode(&request); err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}

	suggestions := s.generateAISuggestions(request.Topic, request.Category)

	response := struct {
		Suggestions []BlockRule `json:"suggestions"`
		Topic       string      `json:"topic"`
		Category    string      `json:"category"`
	}{
		Suggestions: suggestions,
		Topic:       request.Topic,
		Category:    request.Category,
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(response)
}

func (s *CoreService) generateAISuggestions(topic, category string) []BlockRule {
	// AI suggestion logic - này có thể tích hợp với API như OpenAI
	// Tạm thời dùng rules cố định cho demo

	suggestions := make(map[string][]string)

	suggestions["game bạo lực"] = []string{
		"violent-games.com", "brutalgames.net", "bloodygames.org",
		"warfare-online.com", "shooter-games.net",
	}
	suggestions["cờ bạc"] = []string{
		"casino-online.com", "betting365.com", "pokerstars.com",
		"gambling-sites.net", "slot-machines.org",
	}
	suggestions["khiêu dâm"] = []string{
		"adult-content.com", "xxx-sites.net", "porn-videos.org",
		"explicit-content.com", "adult-entertainment.net",
	}
	suggestions["mạng xã hội"] = []string{
		"facebook.com", "instagram.com", "tiktok.com",
		"snapchat.com", "twitter.com",
	}

	domains, exists := suggestions[strings.ToLower(topic)]
	if !exists {
		// Fallback to generic suggestions
		domains = []string{
			"example-" + strings.ReplaceAll(topic, " ", "-") + ".com",
		}
	}

	var rules []BlockRule
	for i, domain := range domains {
		rules = append(rules, BlockRule{
			ID:       i + 1,
			Domain:   domain,
			Category: category,
			Reason:   fmt.Sprintf("AI suggested for topic: %s", topic),
		})
	}

	return rules
}

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

	// Top blocked domains
	rows, err := s.db.Query(`
        SELECT domain, COUNT(*) as count 
        FROM dns_logs 
        WHERE action = 'blocked' AND date(timestamp) >= date('now', '-7 days')
        GROUP BY domain ORDER BY count DESC LIMIT 10`)

	if err == nil {
		var topBlocked []map[string]interface{}
		for rows.Next() {
			var domain string
			var count int
			rows.Scan(&domain, &count)
			topBlocked = append(topBlocked, map[string]interface{}{
				"domain": domain,
				"count":  count,
			})
		}
		rows.Close()
		stats["top_blocked"] = topBlocked
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(stats)
}

func (s *CoreService) Shutdown() {
	if s.httpServer != nil {
		s.httpServer.Shutdown(context.Background())
	}
	if s.dnsServer != nil {
		s.dnsServer.Shutdown()
	}

	// Optionally restore system configuration on shutdown
	// s.sysConfig.RestoreConfiguration()

	if s.db != nil {
		s.db.Close()
	}
}
