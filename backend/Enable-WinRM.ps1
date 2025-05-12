# Enable-WinRM.ps1
# This script configures WinRM on a Windows server for secure remote management
# Run this script on the target Windows server before scanning with Server Security Audit

# Requires administrator privileges to run
if (-NOT ([Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)) {
    Write-Warning "Script must be run as Administrator. Right-click the script and select 'Run as Administrator'."
    exit
}

# Configure Windows Remote Management (WinRM)
Write-Host "Configuring Windows Remote Management (WinRM)..." -ForegroundColor Green

# Enable the WinRM service
Enable-PSRemoting -Force -SkipNetworkProfileCheck

# Configure Basic authentication
Set-Item -Path WSMan:\localhost\Service\Auth\Basic -Value $true

# Allow unencrypted traffic (for testing - remove this in production)
Set-Item -Path WSMan:\localhost\Service\AllowUnencrypted -Value $true

# Add server to trusted hosts (replace * with specific IPs in production)
Set-Item -Path WSMan:\localhost\Client\TrustedHosts -Value "*" -Force

# Open firewall ports for WinRM
Write-Host "Configuring firewall rules..." -ForegroundColor Green
$FirewallParams = @{
    DisplayName = "Windows Remote Management (HTTP-In)"
    Direction = "Inbound"
    LocalPort = 5985
    Protocol = "TCP"
    Action = "Allow"
    Program = "System"
}
New-NetFirewallRule @FirewallParams

$FirewallParams = @{
    DisplayName = "Windows Remote Management (HTTPS-In)"
    Direction = "Inbound"
    LocalPort = 5986
    Protocol = "TCP"
    Action = "Allow"
    Program = "System"
}
New-NetFirewallRule @FirewallParams

# Restart the WinRM service
Write-Host "Restarting WinRM service..." -ForegroundColor Green
Restart-Service WinRM

# Set the WinRM service to start automatically
Set-Service -Name "WinRM" -StartupType Automatic

# Test WinRM configuration
Write-Host "Testing WinRM configuration..." -ForegroundColor Green
$TestResult = Test-WSMan -ComputerName localhost

if ($TestResult) {
    Write-Host "WinRM is now configured and ready for remote connections!" -ForegroundColor Green
    Write-Host "Server IP Address: $((Get-NetIPAddress -AddressFamily IPv4 | Where-Object {$_.InterfaceAlias -like "*Ethernet*"}).IPAddress)" -ForegroundColor Cyan
    
    Write-Host "`nImportant Security Notes:" -ForegroundColor Yellow
    Write-Host "1. For production use, consider using HTTPS instead of HTTP for WinRM" -ForegroundColor Yellow
    Write-Host "2. Limit TrustedHosts to specific IP addresses instead of '*'" -ForegroundColor Yellow
    Write-Host "3. Disable Basic authentication and use Kerberos or NTLM in production environments" -ForegroundColor Yellow
} else {
    Write-Host "WinRM configuration failed. Please check for any errors." -ForegroundColor Red
}