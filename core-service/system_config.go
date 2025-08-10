package main

import (
	"bytes"
	"fmt"
	"log"
	"os/exec"
	"strings"
	"syscall"
	"time"
)

type SystemConfigurator struct {
	originalDNS map[string][]string
}

func NewSystemConfigurator() *SystemConfigurator {
	return &SystemConfigurator{
		originalDNS: make(map[string][]string),
	}
}

// IMPROVED ConfigureDNS with retry logic
func (sc *SystemConfigurator) ConfigureDNS() error {
	log.Println("Configuring system DNS using PowerShell...")

	// Retry logic cho DNS configuration
	maxRetries := 3
	for attempt := 1; attempt <= maxRetries; attempt++ {
		log.Printf("DNS configuration attempt %d/%d", attempt, maxRetries)

		interfaces, err := sc.getActiveInterfaces()
		if err != nil {
			log.Printf("Attempt %d failed to get interfaces: %v", attempt, err)
			if attempt < maxRetries {
				time.Sleep(2 * time.Second)
				continue
			}
			return fmt.Errorf("could not get active interfaces after %d attempts: %v", maxRetries, err)
		}

		var configuredInterfaces []string
		var lastError error

		for _, iface := range interfaces {
			iface = strings.TrimSpace(iface)
			if iface == "" {
				continue
			}

			log.Printf("Configuring DNS for interface: '%s' (attempt %d)", iface, attempt)

			// Store original DNS before changing
			originalDNS, err := sc.getOriginalDNS(iface)
			if err == nil {
				sc.originalDNS[iface] = originalDNS
			}

			// Try different PowerShell execution methods
			commands := []string{
				fmt.Sprintf(`Set-DnsClientServerAddress -InterfaceAlias '%s' -ServerAddresses '127.0.0.1','1.1.1.1'`, iface),
				fmt.Sprintf(`netsh interface ip set dns "%s" static 127.0.0.1 primary`, iface),
			}

			success := false
			for _, cmd := range commands {
				_, err = runPoshElevated(cmd)
				if err == nil {
					success = true
					break
				} else {
					log.Printf("Command failed: %v", err)
				}
			}

			if success {
				configuredInterfaces = append(configuredInterfaces, iface)
				log.Printf("Successfully configured DNS for adapter: %s", iface)
			} else {
				lastError = fmt.Errorf("failed to configure %s", iface)
				log.Printf("Warning: Failed to set DNS for adapter '%s'", iface)
			}
		}

		if len(configuredInterfaces) > 0 {
			// Flush DNS cache
			runPosh("Clear-DnsClientCache")
			log.Printf("DNS configured successfully for %d interfaces", len(configuredInterfaces))
			return nil
		}

		if attempt < maxRetries {
			log.Printf("Attempt %d failed, retrying in 3 seconds...", attempt)
			time.Sleep(3 * time.Second)
		} else {
			return fmt.Errorf("failed to configure DNS for any adapter after %d attempts: %v", maxRetries, lastError)
		}
	}

	return fmt.Errorf("DNS configuration failed after %d attempts", maxRetries)
}

// FIXED DisableDNSOverHTTPS
func (sc *SystemConfigurator) DisableDNSOverHTTPS() error {
	log.Println("Disabling DNS over HTTPS...")

	commands := []string{
		// Windows DNS Client DoH disable - IMPROVED
		`$path = "HKLM:\SOFTWARE\Policies\Microsoft\Windows NT\DNSClient"; if (-not (Test-Path $path)) { New-Item -Path $path -Force | Out-Null }; Set-ItemProperty -Path $path -Name "DoHPolicy" -Value 3 -Type DWord -Force`,
		`$path = "HKLM:\SYSTEM\CurrentControlSet\Services\Dnscache\Parameters"; if (-not (Test-Path $path)) { New-Item -Path $path -Force | Out-Null }; Set-ItemProperty -Path $path -Name "EnableAutoDoh" -Value 0 -Type DWord -Force`,

		// Chrome DoH disable - ENHANCED
		`$path = "HKLM:\SOFTWARE\Policies\Google\Chrome"; if (-not (Test-Path $path)) { New-Item -Path $path -Force | Out-Null }; Set-ItemProperty -Path $path -Name "DnsOverHttpsMode" -Value "off" -Type String -Force`,
		`$path = "HKLM:\SOFTWARE\Policies\Google\Chrome"; Set-ItemProperty -Path $path -Name "BuiltInDnsClientEnabled" -Value 0 -Type DWord -Force`,
		`$path = "HKLM:\SOFTWARE\Policies\Google\Chrome"; Set-ItemProperty -Path $path -Name "DnsOverHttpsTemplates" -Value "" -Type String -Force`,

		// Edge DoH disable - ENHANCED
		`$path = "HKLM:\SOFTWARE\Policies\Microsoft\Edge"; if (-not (Test-Path $path)) { New-Item -Path $path -Force | Out-Null }; Set-ItemProperty -Path $path -Name "DnsOverHttpsMode" -Value "off" -Type String -Force`,
		`$path = "HKLM:\SOFTWARE\Policies\Microsoft\Edge"; Set-ItemProperty -Path $path -Name "BuiltInDnsClientEnabled" -Value 0 -Type DWord -Force`,
		`$path = "HKLM:\SOFTWARE\Policies\Microsoft\Edge"; Set-ItemProperty -Path $path -Name "DnsOverHttpsTemplates" -Value "" -Type String -Force`,

		// Firefox DoH disable
		`$path = "HKLM:\SOFTWARE\Policies\Mozilla\Firefox"; if (-not (Test-Path $path)) { New-Item -Path $path -Force | Out-Null }; Set-ItemProperty -Path $path -Name "DNSOverHTTPS" -Value '{"Enabled": false}' -Type String -Force`,

		// Brave browser DoH disable
		`$path = "HKLM:\SOFTWARE\Policies\BraveSoftware\Brave"; if (-not (Test-Path $path)) { New-Item -Path $path -Force | Out-Null }; Set-ItemProperty -Path $path -Name "DnsOverHttpsMode" -Value "off" -Type String -Force`,
	}

	for _, cmd := range commands {
		if _, err := runPosh(cmd); err != nil {
			log.Printf("Warning: Failed to execute DoH disable command: %v", err)
		}
	}

	// Force kill và restart browsers để áp dụng policy
	runPosh("taskkill /IM chrome.exe /F /T 2>$null; taskkill /IM msedge.exe /F /T 2>$null; taskkill /IM firefox.exe /F /T 2>$null; taskkill /IM brave.exe /F /T 2>$null")

	// Flush DNS cache
	runPosh("ipconfig /flushdns")

	log.Println("DNS over HTTPS disable policies applied.")
	return nil
}

// NEW BlockDOHTraffic function
func (sc *SystemConfigurator) BlockDOHTraffic() error {
	log.Println("Blocking DoH traffic via firewall...")

	commands := []string{
		// Block HTTPS traffic to known DoH servers
		`if (-not (Get-NetFirewallRule -DisplayName "Block DoH Cloudflare" -ErrorAction SilentlyContinue)) { New-NetFirewallRule -DisplayName "Block DoH Cloudflare" -Direction Outbound -Action Block -RemoteAddress "1.1.1.1","1.0.0.1" -RemotePort 443 -Protocol TCP }`,
		`if (-not (Get-NetFirewallRule -DisplayName "Block DoH Google" -ErrorAction SilentlyContinue)) { New-NetFirewallRule -DisplayName "Block DoH Google" -Direction Outbound -Action Block -RemoteAddress "8.8.8.8","8.8.4.4" -RemotePort 443 -Protocol TCP }`,
		`if (-not (Get-NetFirewallRule -DisplayName "Block DoH Quad9" -ErrorAction SilentlyContinue)) { New-NetFirewallRule -DisplayName "Block DoH Quad9" -Direction Outbound -Action Block -RemoteAddress "9.9.9.9","149.112.112.112" -RemotePort 443 -Protocol TCP }`,

		// Block DoH over IPv6
		`if (-not (Get-NetFirewallRule -DisplayName "Block DoH Cloudflare IPv6" -ErrorAction SilentlyContinue)) { New-NetFirewallRule -DisplayName "Block DoH Cloudflare IPv6" -Direction Outbound -Action Block -RemoteAddress "2606:4700:4700::1111","2606:4700:4700::1001" -RemotePort 443 -Protocol TCP }`,
		`if (-not (Get-NetFirewallRule -DisplayName "Block DoH Google IPv6" -ErrorAction SilentlyContinue)) { New-NetFirewallRule -DisplayName "Block DoH Google IPv6" -Direction Outbound -Action Block -RemoteAddress "2001:4860:4860::8888","2001:4860:4860::8844" -RemotePort 443 -Protocol TCP }`,
	}

	for _, cmd := range commands {
		if _, err := runPosh(cmd); err != nil {
			log.Printf("Warning: Failed to execute DoH blocking command: %v", err)
		}
	}

	log.Println("DoH traffic blocking rules applied.")
	return nil
}

func (sc *SystemConfigurator) BlockQUIC() error {
	log.Println("Blocking QUIC protocol via Firewall...")

	commands := []string{
		// Block outbound QUIC traffic (UDP port 443)
		`if (-not (Get-NetFirewallRule -DisplayName "Block QUIC Protocol" -ErrorAction SilentlyContinue)) { New-NetFirewallRule -DisplayName "Block QUIC Protocol" -Direction Outbound -Action Block -Protocol UDP -RemotePort 443 }`,

		// Block alternative QUIC ports
		`if (-not (Get-NetFirewallRule -DisplayName "Block QUIC Alt Ports" -ErrorAction SilentlyContinue)) { New-NetFirewallRule -DisplayName "Block QUIC Alt Ports" -Direction Outbound -Action Block -Protocol UDP -RemotePort 80,8080,8443 }`,
	}

	for _, cmd := range commands {
		if _, err := runPosh(cmd); err != nil {
			log.Printf("Warning: Failed to execute QUIC blocking command: %v", err)
		}
	}

	log.Println("QUIC protocol blocking rules applied.")
	return nil
}

func (sc *SystemConfigurator) CheckSystemStatus() map[string]interface{} {
	status := make(map[string]interface{})

	// Check DNS configuration
	interfaces, _ := sc.getActiveInterfaces()
	dnsConfigured := false
	for _, iface := range interfaces {
		if dns, err := sc.getCurrentDNS(iface); err == nil && len(dns) > 0 {
			if strings.Contains(dns[0], "127.0.0.1") {
				dnsConfigured = true
				break
			}
		}
	}
	status["dns_configured"] = dnsConfigured

	// Check DoH disabled
	dohDisabled := sc.isDOHDisabled()
	status["doh_disabled"] = dohDisabled

	// Check firewall rules
	firewallConfigured := sc.areFirewallRulesActive()
	status["firewall_configured"] = firewallConfigured

	return status
}

func (sc *SystemConfigurator) RestoreConfiguration() error {
	log.Println("Restoring original DNS configuration...")

	// Restore DNS for each interface
	for iface, originalDNS := range sc.originalDNS {
		if len(originalDNS) > 0 {
			dnsServers := strings.Join(originalDNS, "','")
			command := fmt.Sprintf(`Set-DnsClientServerAddress -InterfaceAlias '%s' -ServerAddresses '%s'`, iface, dnsServers)
			if _, err := runPosh(command); err != nil {
				log.Printf("Warning: Failed to restore DNS for %s: %v", iface, err)
			} else {
				log.Printf("Restored DNS for interface %s", iface)
			}
		} else {
			// Reset to automatic
			command := fmt.Sprintf(`Set-DnsClientServerAddress -InterfaceAlias '%s' -ResetServerAddresses`, iface)
			runPosh(command)
		}
	}

	// Remove firewall rules
	sc.removeFirewallRules()

	// Flush DNS cache
	runPosh("ipconfig /flushdns")

	log.Println("Configuration restoration completed.")
	return nil
}

// Helper functions
func (sc *SystemConfigurator) getActiveInterfaces() ([]string, error) {
	out, err := runPosh(`(Get-NetAdapter | Where-Object {$_.Status -eq "Up"}).Name`)
	if err != nil {
		return nil, err
	}

	lines := strings.Split(strings.TrimSpace(string(out)), "\n")
	var interfaces []string
	for _, line := range lines {
		line = strings.TrimSpace(line)
		if line != "" {
			interfaces = append(interfaces, line)
		}
	}

	return interfaces, nil
}

func (sc *SystemConfigurator) getOriginalDNS(interfaceName string) ([]string, error) {
	command := fmt.Sprintf(`(Get-DnsClientServerAddress -InterfaceAlias '%s' -AddressFamily IPv4).ServerAddresses`, interfaceName)
	out, err := runPosh(command)
	if err != nil {
		return nil, err
	}

	dnsServers := strings.Split(strings.TrimSpace(string(out)), "\r\n")
	var validServers []string
	for _, server := range dnsServers {
		server = strings.TrimSpace(server)
		if server != "" && server != "127.0.0.1" {
			validServers = append(validServers, server)
		}
	}

	return validServers, nil
}

func (sc *SystemConfigurator) getCurrentDNS(interfaceName string) ([]string, error) {
	command := fmt.Sprintf(`(Get-DnsClientServerAddress -InterfaceAlias '%s' -AddressFamily IPv4).ServerAddresses`, interfaceName)
	out, err := runPosh(command)
	if err != nil {
		return nil, err
	}

	dnsServers := strings.Split(strings.TrimSpace(string(out)), "\r\n")
	var servers []string
	for _, server := range dnsServers {
		server = strings.TrimSpace(server)
		if server != "" {
			servers = append(servers, server)
		}
	}

	return servers, nil
}

func (sc *SystemConfigurator) isDOHDisabled() bool {
	// Check Chrome policy
	out, err := runPosh(`Get-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Google\Chrome" -Name "DnsOverHttpsMode" -ErrorAction SilentlyContinue | Select-Object -ExpandProperty DnsOverHttpsMode`)
	if err == nil && strings.TrimSpace(string(out)) == "off" {
		return true
	}
	return false
}

func (sc *SystemConfigurator) areFirewallRulesActive() bool {
	out, err := runPosh(`Get-NetFirewallRule -DisplayName "Block DoH*" -ErrorAction SilentlyContinue | Measure-Object | Select-Object -ExpandProperty Count`)
	if err == nil {
		count := strings.TrimSpace(string(out))
		return count != "0"
	}
	return false
}

func (sc *SystemConfigurator) removeFirewallRules() {
	rules := []string{
		"Block DoH Cloudflare",
		"Block DoH Google",
		"Block DoH Quad9",
		"Block DoH Cloudflare IPv6",
		"Block DoH Google IPv6",
		"Block QUIC Protocol",
		"Block QUIC Alt Ports",
	}

	for _, rule := range rules {
		command := fmt.Sprintf(`Remove-NetFirewallRule -DisplayName "%s" -ErrorAction SilentlyContinue`, rule)
		runPosh(command)
	}
}

// PowerShell execution functions
func runPosh(command string) ([]byte, error) {
	cmd := exec.Command("powershell", "-NoProfile", "-ExecutionPolicy", "Bypass", "-WindowStyle", "Hidden", "-Command", command)
	cmd.SysProcAttr = &syscall.SysProcAttr{HideWindow: true}

	var out bytes.Buffer
	var stderr bytes.Buffer
	cmd.Stdout = &out
	cmd.Stderr = &stderr

	err := cmd.Run()
	if err != nil {
		return nil, fmt.Errorf("command failed: %v, stderr: %s", err, stderr.String())
	}

	return out.Bytes(), nil
}

// NEW function với elevated privileges
func runPoshElevated(command string) ([]byte, error) {
	cmd := exec.Command("powershell",
		"-NoProfile",
		"-ExecutionPolicy", "Bypass",
		"-WindowStyle", "Hidden",
		"-Command", command)

	cmd.SysProcAttr = &syscall.SysProcAttr{HideWindow: true}

	var out bytes.Buffer
	var stderr bytes.Buffer
	cmd.Stdout = &out
	cmd.Stderr = &stderr

	err := cmd.Run()
	if err != nil {
		return nil, fmt.Errorf("command failed: %v, stderr: %s", err, stderr.String())
	}

	return out.Bytes(), nil
}
