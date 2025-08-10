package main

import (
	"bytes"
	"fmt"
	"log"
	"os/exec"
	"strings"
	"syscall"
)

// SystemConfigurator handles Windows system configuration
type SystemConfigurator struct {
	originalDNS map[string][]string // Map to store original DNS for each interface
}

// NewSystemConfigurator creates a new system configurator instance
func NewSystemConfigurator() *SystemConfigurator {
	return &SystemConfigurator{
		originalDNS: make(map[string][]string),
	}
}

// runPosh executes a PowerShell command.
// It assumes the parent Go process is already running with administrator privileges.
func runPosh(command string) ([]byte, error) {
	cmd := exec.Command("powershell", "-NoProfile", "-ExecutionPolicy", "Bypass", "-Command", command)
	cmd.SysProcAttr = &syscall.SysProcAttr{HideWindow: true}
	var out bytes.Buffer
	var stderr bytes.Buffer
	cmd.Stdout = &out
	cmd.Stderr = &stderr
	err := cmd.Run()
	if err != nil {
		// Log the full error from PowerShell for better debugging
		return nil, fmt.Errorf("command failed: %v, stderr: %s", err, stderr.String())
	}
	return out.Bytes(), nil
}

// getActiveInterfaces finds active network interfaces like Wi-Fi and Ethernet.
func (sc *SystemConfigurator) getActiveInterfaces() ([]string, error) {
	// This command gets interfaces that are connected.
	command := `Get-NetAdapter -Physical | Where-Object { $_.Status -eq 'Up' } | ForEach-Object { $_.Name }`
	out, err := runPosh(command)
	if err != nil {
		return nil, fmt.Errorf("failed to get network interfaces: %v", err)
	}

	interfaces := strings.Split(strings.TrimSpace(string(out)), "\r\n")
	if len(interfaces) == 0 || (len(interfaces) == 1 && interfaces[0] == "") {
		return nil, fmt.Errorf("no active network interfaces found")
	}
	return interfaces, nil
}

// ConfigureDNS sets the system DNS to point to localhost
func (sc *SystemConfigurator) ConfigureDNS() error {
	log.Println("Configuring system DNS using PowerShell...")

	interfaces, err := sc.getActiveInterfaces()
	if err != nil {
		log.Printf("Warning: Could not get active interfaces: %v", err)
		return err
	}

	var success bool
	for _, iface := range interfaces {
		iface = strings.TrimSpace(iface)
		if iface == "" {
			continue
		}
		log.Printf("Attempting to configure DNS for interface: '%s'", iface)
		// Set DNS to 127.0.0.1
		command := fmt.Sprintf(`Set-DnsClientServerAddress -InterfaceAlias '%s' -ServerAddresses '127.0.0.1'`, iface)
		_, err := runPosh(command)
		if err != nil {
			log.Printf("Warning: Failed to set DNS for adapter '%s': %v", iface, err)
			continue // Try next interface
		}
		log.Printf("Successfully set DNS for adapter: %s", iface)
		success = true
	}

	if !success {
		return fmt.Errorf("failed to configure DNS for any active adapter")
	}

	// Flush DNS cache
	runPosh("Clear-DnsClientCache")
	log.Println("DNS configured successfully")
	return nil
}

// DisableDNSOverHTTPS disables DNS over HTTPS in Windows browsers via registry
func (sc *SystemConfigurator) DisableDNSOverHTTPS() error {
	log.Println("Disabling DNS over HTTPS...")

	commands := []string{
		`$path = "HKLM:\SOFTWARE\Policies\Microsoft\Windows NT\DNSClient"; if (-not (Test-Path $path)) { New-Item -Path $path -Force | Out-Null }; Set-ItemProperty -Path $path -Name "EnableRedirection" -Value 1 -Type DWord -Force`,
		`$path = "HKLM:\SOFTWARE\Policies\Google\Chrome"; if (-not (Test-Path $path)) { New-Item -Path $path -Force | Out-Null }; Set-ItemProperty -Path $path -Name "DnsOverHttpsMode" -Value "off" -Type String -Force`,
		`$path = "HKLM:\SOFTWARE\Policies\Microsoft\Edge"; if (-not (Test-Path $path)) { New-Item -Path $path -Force | Out-Null }; Set-ItemProperty -Path $path -Name "DnsOverHttpsMode" -Value "off" -Type String -Force`,
	}

	for _, cmd := range commands {
		if _, err := runPosh(cmd); err != nil {
			log.Printf("Warning: Failed to execute DoH command: %v", err)
		}
	}

	log.Println("DNS over HTTPS disable policies applied.")
	return nil
}

// BlockQUIC blocks QUIC protocol to prevent DoH bypass
func (sc *SystemConfigurator) BlockQUIC() error {
	log.Println("Blocking QUIC protocol via Firewall...")
	commands := []string{
		`if (-not (Get-NetFirewallRule -DisplayName "Block QUIC Outbound" -ErrorAction SilentlyContinue)) { New-NetFirewallRule -DisplayName "Block QUIC Outbound" -Direction Outbound -Action Block -Protocol UDP -RemotePort 443 }`,
		`if (-not (Get-NetFirewallRule -DisplayName "Block QUIC Inbound" -ErrorAction SilentlyContinue)) { New-NetFirewallRule -DisplayName "Block QUIC Inbound" -Direction Inbound -Action Block -Protocol UDP -LocalPort 443 }`,
	}
	for _, cmd := range commands {
		if _, err := runPosh(cmd); err != nil {
			log.Printf("Warning: Failed to execute firewall command: %v", err)
		}
	}
	log.Println("QUIC protocol blocking rules applied.")
	return nil
}

// RestoreConfiguration restores original system configuration
func (sc *SystemConfigurator) RestoreConfiguration() error {
	log.Println("Restoring original system configuration...")

	// Restore DNS to automatic (DHCP)
	interfaces, err := sc.getActiveInterfaces()
	if err == nil {
		for _, iface := range interfaces {
			iface = strings.TrimSpace(iface)
			if iface == "" {
				continue
			}
			command := fmt.Sprintf(`Set-DnsClientServerAddress -InterfaceAlias '%s' -ResetServerAddresses`, iface)
			if _, err := runPosh(command); err != nil {
				log.Printf("Warning: Failed to restore DNS for adapter '%s': %v", iface, err)
			}
		}
	}

	// Remove firewall rules
	runPosh(`Remove-NetFirewallRule -DisplayName "Block QUIC Outbound" -ErrorAction SilentlyContinue`)
	runPosh(`Remove-NetFirewallRule -DisplayName "Block QUIC Inbound" -ErrorAction SilentlyContinue`)

	// Re-enable DoH (optional, by removing keys)
	runPosh(`Remove-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Google\Chrome" -Name "DnsOverHttpsMode" -ErrorAction SilentlyContinue`)
	runPosh(`Remove-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Edge" -Name "DnsOverHttpsMode" -ErrorAction SilentlyContinue`)

	runPosh("Clear-DnsClientCache")
	log.Println("System configuration restored.")
	return nil
}

// CheckSystemStatus is simplified, can be expanded later
func (sc *SystemConfigurator) CheckSystemStatus() map[string]bool {
	// This is a placeholder. A full check would be more complex.
	status := make(map[string]bool)
	status["dns_configured"] = true // Assume true for now
	status["doh_disabled"] = true
	status["firewall_configured"] = true
	return status
}
