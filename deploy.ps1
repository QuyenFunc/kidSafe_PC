# Parental Control Deployment Script
# Run as Administrator

Write-Host "Deploying Parental Control System..." -ForegroundColor Green

# Check if running as administrator
if (-NOT ([Security.Principal.WindowsPrincipal] [Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole] "Administrator")) {
    Write-Error "This script must be run as Administrator"
    exit 1
}

# Create application directory
$InstallDir = "$env:ProgramFiles\Parental Control"
New-Item -ItemType Directory -Force -Path $InstallDir

# Copy files
Copy-Item "core-service\core-service.exe" -Destination $InstallDir
Copy-Item "ui-admin\dist\*" -Destination $InstallDir -Recurse -Force

# Install Windows Service
& "$InstallDir\core-service.exe" --install-service
Start-Service "ParentalControlService"

# Configure DNS
netsh interface ip set dns "Local Area Connection" static 127.0.0.1
netsh interface ip add dns "Local Area Connection" 8.8.8.8 index=2

# Configure browser policies (Disable DoH)
New-Item -Path "HKLM:\SOFTWARE\Policies\Google\Chrome" -Force
Set-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Google\Chrome" -Name "DnsOverHttpsMode" -Value "off"

New-Item -Path "HKLM:\SOFTWARE\Policies\Microsoft\Edge" -Force  
Set-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Edge" -Name "DnsOverHttpsMode" -Value "off"

# Configure Windows Firewall
New-NetFirewallRule -DisplayName "Block QUIC (UDP 443)" -Direction Outbound -Protocol UDP -LocalPort 443 -Action Block
New-NetFirewallRule -DisplayName "Allow Parental Control DNS" -Direction Inbound -Protocol UDP -LocalPort 53 -Action Allow

# Create desktop shortcut
$WshShell = New-Object -comObject WScript.Shell
$Shortcut = $WshShell.CreateShortcut("$env:PUBLIC\Desktop\Parental Control.lnk")
$Shortcut.TargetPath = "$InstallDir\parental-control-ui.exe"
$Shortcut.Save()

Write-Host "Deployment completed successfully!" -ForegroundColor Green
Write-Host "Parental Control is now active. DNS filtering: 127.0.0.1:53" -ForegroundColor Yellow
