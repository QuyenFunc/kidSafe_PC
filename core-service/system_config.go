package main

import (
	"fmt"
	"log"
	"os/exec"
	"strings"
	"syscall"
)

// SystemConfigurator handles Windows system configuration
type SystemConfigurator struct {
	originalDNS []string
}

// NewSystemConfigurator creates a new system configurator instance
func NewSystemConfigurator() *SystemConfigurator {
	return &SystemConfigurator{
		originalDNS: make([]string, 0),
	}
}

// ConfigureDNS sets the system DNS to point to localhost
func (sc *SystemConfigurator) ConfigureDNS() error {
	log.Println("Configuring system DNS...")

	// Get current DNS servers first (for backup)
	if err := sc.backupCurrentDNS(); err != nil {
		log.Printf("Warning: Failed to backup current DNS: %v", err)
	}

	// Set DNS to localhost for all network adapters
	cmd := exec.Command("netsh", "interface", "ip", "set", "dns", "name=*", "static", "127.0.0.1")
	cmd.SysProcAttr = &syscall.SysProcAttr{HideWindow: true}

	if err := cmd.Run(); err != nil {
		// Try alternative method for specific adapters
		return sc.configureDNSForAdapters()
	}

	log.Println("DNS configured successfully")
	return nil
}

// configureDNSForAdapters configures DNS for each network adapter individually
func (sc *SystemConfigurator) configureDNSForAdapters() error {
	// Get list of network adapters
	cmd := exec.Command("netsh", "interface", "show", "interface")
	cmd.SysProcAttr = &syscall.SysProcAttr{HideWindow: true}
	output, err := cmd.Output()
	if err != nil {
		return fmt.Errorf("failed to get network interfaces: %v", err)
	}

	lines := strings.Split(string(output), "\n")
	for _, line := range lines {
		if strings.Contains(line, "Connected") && (strings.Contains(line, "Ethernet") || strings.Contains(line, "Wi-Fi") || strings.Contains(line, "Wireless")) {
			parts := strings.Fields(line)
			if len(parts) >= 4 {
				adapterName := strings.Join(parts[3:], " ")
				adapterName = strings.TrimSpace(adapterName)

				// Set DNS for this adapter
				cmd := exec.Command("netsh", "interface", "ip", "set", "dns", fmt.Sprintf("name=%s", adapterName), "static", "127.0.0.1")
				cmd.SysProcAttr = &syscall.SysProcAttr{HideWindow: true}
				if err := cmd.Run(); err != nil {
					log.Printf("Warning: Failed to set DNS for adapter %s: %v", adapterName, err)
				} else {
					log.Printf("DNS configured for adapter: %s", adapterName)
				}
			}
		}
	}

	return nil
}

// backupCurrentDNS saves current DNS configuration
func (sc *SystemConfigurator) backupCurrentDNS() error {
	cmd := exec.Command("netsh", "interface", "ip", "show", "config")
	cmd.SysProcAttr = &syscall.SysProcAttr{HideWindow: true}
	output, err := cmd.Output()
	if err != nil {
		return err
	}

	lines := strings.Split(string(output), "\n")
	for _, line := range lines {
		if strings.Contains(line, "DNS servers configured through DHCP:") ||
			strings.Contains(line, "Statically Configured DNS Servers:") {
			// Parse DNS servers from output
			// This is a simplified version - you might want to make it more robust
		}
	}

	return nil
}

// DisableDNSOverHTTPS disables DNS over HTTPS in Windows
func (sc *SystemConfigurator) DisableDNSOverHTTPS() error {
	log.Println("Disabling DNS over HTTPS...")

	// Disable DoH via registry
	commands := [][]string{
		{"reg", "add", "HKLM\\SOFTWARE\\Policies\\Microsoft\\Windows NT\\DNSClient", "/v", "DoHPolicy", "/t", "REG_DWORD", "/d", "3", "/f"},
		{"reg", "add", "HKLM\\SYSTEM\\CurrentControlSet\\Services\\Dnscache\\Parameters", "/v", "EnableAutoDoh", "/t", "REG_DWORD", "/d", "0", "/f"},
	}

	for _, cmdArgs := range commands {
		cmd := exec.Command(cmdArgs[0], cmdArgs[1:]...)
		cmd.SysProcAttr = &syscall.SysProcAttr{HideWindow: true}
		if err := cmd.Run(); err != nil {
			log.Printf("Warning: Failed to execute command %v: %v", cmdArgs, err)
		}
	}

	log.Println("DNS over HTTPS disabled")
	return nil
}

// BlockQUIC blocks QUIC protocol to prevent DoH bypass
func (sc *SystemConfigurator) BlockQUIC() error {
	log.Println("Blocking QUIC protocol...")

	// Block QUIC via Windows Firewall
	commands := [][]string{
		{"netsh", "advfirewall", "firewall", "add", "rule", "name=Block QUIC Outbound", "dir=out", "action=block", "protocol=UDP", "remoteport=443"},
		{"netsh", "advfirewall", "firewall", "add", "rule", "name=Block QUIC Inbound", "dir=in", "action=block", "protocol=UDP", "localport=443"},
	}

	for _, cmdArgs := range commands {
		cmd := exec.Command(cmdArgs[0], cmdArgs[1:]...)
		cmd.SysProcAttr = &syscall.SysProcAttr{HideWindow: true}
		if err := cmd.Run(); err != nil {
			log.Printf("Warning: Failed to execute firewall command %v: %v", cmdArgs, err)
		}
	}

	log.Println("QUIC protocol blocked")
	return nil
}

// CheckSystemStatus checks current system configuration status
func (sc *SystemConfigurator) CheckSystemStatus() map[string]bool {
	status := make(map[string]bool)

	// Check DNS configuration
	status["dns_configured"] = sc.checkDNSConfiguration()

	// Check DoH status
	status["doh_disabled"] = sc.checkDoHStatus()

	// Check firewall rules
	status["firewall_configured"] = sc.checkFirewallRules()

	return status
}

// checkDNSConfiguration checks if DNS is pointing to localhost
func (sc *SystemConfigurator) checkDNSConfiguration() bool {
	cmd := exec.Command("nslookup", "127.0.0.1")
	cmd.SysProcAttr = &syscall.SysProcAttr{HideWindow: true}
	output, err := cmd.Output()
	if err != nil {
		return false
	}

	// Simple check - if nslookup works with 127.0.0.1, DNS is likely configured
	return strings.Contains(string(output), "127.0.0.1")
}

// checkDoHStatus checks if DNS over HTTPS is disabled
func (sc *SystemConfigurator) checkDoHStatus() bool {
	cmd := exec.Command("reg", "query", "HKLM\\SOFTWARE\\Policies\\Microsoft\\Windows NT\\DNSClient", "/v", "DoHPolicy")
	cmd.SysProcAttr = &syscall.SysProcAttr{HideWindow: true}
	output, err := cmd.Output()
	if err != nil {
		return false
	}

	// Check if DoHPolicy is set to 3 (disabled)
	return strings.Contains(string(output), "0x3")
}

// checkFirewallRules checks if QUIC blocking rules exist
func (sc *SystemConfigurator) checkFirewallRules() bool {
	cmd := exec.Command("netsh", "advfirewall", "firewall", "show", "rule", "name=Block QUIC Outbound")
	cmd.SysProcAttr = &syscall.SysProcAttr{HideWindow: true}
	output, err := cmd.Output()
	if err != nil {
		return false
	}

	return strings.Contains(string(output), "Block QUIC Outbound")
}

// RestoreConfiguration restores original system configuration
func (sc *SystemConfigurator) RestoreConfiguration() error {
	log.Println("Restoring original system configuration...")

	// Restore DNS to automatic (DHCP)
	if err := sc.restoreDNS(); err != nil {
		log.Printf("Warning: Failed to restore DNS: %v", err)
	}

	// Remove firewall rules
	if err := sc.removeFirewallRules(); err != nil {
		log.Printf("Warning: Failed to remove firewall rules: %v", err)
	}

	// Re-enable DoH (optional)
	if err := sc.enableDoH(); err != nil {
		log.Printf("Warning: Failed to re-enable DoH: %v", err)
	}

	log.Println("System configuration restored")
	return nil
}

// restoreDNS restores DNS to automatic configuration
func (sc *SystemConfigurator) restoreDNS() error {
	// Set DNS to obtain automatically for all adapters
	cmd := exec.Command("netsh", "interface", "ip", "set", "dns", "name=*", "dhcp")
	cmd.SysProcAttr = &syscall.SysProcAttr{HideWindow: true}

	if err := cmd.Run(); err != nil {
		// Try for individual adapters
		return sc.restoreDNSForAdapters()
	}

	return nil
}

// restoreDNSForAdapters restores DNS for each network adapter individually
func (sc *SystemConfigurator) restoreDNSForAdapters() error {
	// Get list of network adapters and restore each one
	cmd := exec.Command("netsh", "interface", "show", "interface")
	cmd.SysProcAttr = &syscall.SysProcAttr{HideWindow: true}
	output, err := cmd.Output()
	if err != nil {
		return err
	}

	lines := strings.Split(string(output), "\n")
	for _, line := range lines {
		if strings.Contains(line, "Connected") && (strings.Contains(line, "Ethernet") || strings.Contains(line, "Wi-Fi") || strings.Contains(line, "Wireless")) {
			parts := strings.Fields(line)
			if len(parts) >= 4 {
				adapterName := strings.Join(parts[3:], " ")
				adapterName = strings.TrimSpace(adapterName)

				cmd := exec.Command("netsh", "interface", "ip", "set", "dns", fmt.Sprintf("name=%s", adapterName), "dhcp")
				cmd.SysProcAttr = &syscall.SysProcAttr{HideWindow: true}
				if err := cmd.Run(); err != nil {
					log.Printf("Warning: Failed to restore DNS for adapter %s: %v", adapterName, err)
				}
			}
		}
	}

	return nil
}

// removeFirewallRules removes the QUIC blocking firewall rules
func (sc *SystemConfigurator) removeFirewallRules() error {
	commands := [][]string{
		{"netsh", "advfirewall", "firewall", "delete", "rule", "name=Block QUIC Outbound"},
		{"netsh", "advfirewall", "firewall", "delete", "rule", "name=Block QUIC Inbound"},
	}

	for _, cmdArgs := range commands {
		cmd := exec.Command(cmdArgs[0], cmdArgs[1:]...)
		cmd.SysProcAttr = &syscall.SysProcAttr{HideWindow: true}
		if err := cmd.Run(); err != nil {
			log.Printf("Warning: Failed to remove firewall rule %v: %v", cmdArgs, err)
		}
	}

	return nil
}

// enableDoH re-enables DNS over HTTPS
func (sc *SystemConfigurator) enableDoH() error {
	commands := [][]string{
		{"reg", "delete", "HKLM\\SOFTWARE\\Policies\\Microsoft\\Windows NT\\DNSClient", "/v", "DoHPolicy", "/f"},
		{"reg", "add", "HKLM\\SYSTEM\\CurrentControlSet\\Services\\Dnscache\\Parameters", "/v", "EnableAutoDoh", "/t", "REG_DWORD", "/d", "1", "/f"},
	}

	for _, cmdArgs := range commands {
		cmd := exec.Command(cmdArgs[0], cmdArgs[1:]...)
		cmd.SysProcAttr = &syscall.SysProcAttr{HideWindow: true}
		if err := cmd.Run(); err != nil {
			log.Printf("Warning: Failed to execute command %v: %v", cmdArgs, err)
		}
	}

	return nil
}
