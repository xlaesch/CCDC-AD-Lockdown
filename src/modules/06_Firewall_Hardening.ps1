# 06_Firewall_Hardening.ps1
# Handles Local Firewall Rules for Domain Controllers and Domain Members
# Based on legacy dcFirewall.bat and GPFirewalls.ps1

param(
    [string]$LogFile
)

if (-not (Get-Command Write-Log -ErrorAction SilentlyContinue)) {
    . "$PSScriptRoot/../functions/Write-Log.ps1"
}

Write-Log -Message "Starting Firewall Hardening..." -Level "INFO" -LogFile $LogFile

# Helper function to add rule safely
function Add-FirewallRule {
    param(
        [string]$DisplayName,
        [string]$Direction,
        [string]$Protocol,
        [string]$LocalPort,
        [string]$RemotePort,
        [string]$RemoteAddress,
        [string]$Program,
        [string]$Service
    )
    
    try {
        $params = @{
            DisplayName = $DisplayName
            Direction = $Direction
            Action = "Allow"
            Profile = "Any"
        }
        if ($Protocol) { $params.Add("Protocol", $Protocol) }
        if ($LocalPort) { $params.Add("LocalPort", $LocalPort) }
        if ($RemotePort) { $params.Add("RemotePort", $RemotePort) }
        if ($RemoteAddress) { $params.Add("RemoteAddress", $RemoteAddress) }
        if ($Program) { $params.Add("Program", $Program) }
        if ($Service) { $params.Add("Service", $Service) }

        # Check if rule exists to avoid duplicates (simple check by name)
        if (-not (Get-NetFirewallRule -DisplayName $DisplayName -ErrorAction SilentlyContinue)) {
            New-NetFirewallRule @params | Out-Null
            Write-Log -Message "Added Firewall Rule: $DisplayName" -Level "SUCCESS" -LogFile $LogFile
        } else {
            Write-Log -Message "Firewall Rule already exists: $DisplayName" -Level "INFO" -LogFile $LogFile
        }
    } catch {
        Write-Log -Message "Failed to add rule '$DisplayName': $_" -Level "ERROR" -LogFile $LogFile
    }
}

# --- 1. Identify Role ---
$isDC = (Get-WmiObject -Class Win32_ComputerSystem).DomainRole -ge 4
$role = if ($isDC) { "Domain Controller" } else { "Member Server/Workstation" }
Write-Log -Message "Detected Role: $role" -Level "INFO" -LogFile $LogFile

# --- 2. Common Rules (All Systems) ---
Write-Log -Message "Applying Common Firewall Rules..." -Level "INFO" -LogFile $LogFile

# Ping (ICMPv4) - Restricted to internal subnet example (10.120.0.0/16 from legacy)
# We will use LocalSubnet instead for safety unless specific IP provided
Add-FirewallRule -DisplayName "Ping In (LocalSubnet)" -Direction "Inbound" -Protocol "ICMPv4" -RemoteAddress "LocalSubnet"

# RDP (TCP 3389)
Add-FirewallRule -DisplayName "RDP In" -Direction "Inbound" -Protocol "TCP" -LocalPort "3389" -Service "TermService"

# --- 3. Domain Controller Specific Rules ---
if ($isDC) {
    Write-Log -Message "Applying Domain Controller Firewall Rules..." -Level "INFO" -LogFile $LogFile

    # DNS (UDP 53)
    Add-FirewallRule -DisplayName "DNS In (UDP)" -Direction "Inbound" -Protocol "UDP" -LocalPort "53" -RemoteAddress "LocalSubnet"
    Add-FirewallRule -DisplayName "DNS Out (UDP)" -Direction "Outbound" -Protocol "UDP" -RemotePort "53"

    # Kerberos (TCP/UDP 88)
    Add-FirewallRule -DisplayName "Kerberos TCP In" -Direction "Inbound" -Protocol "TCP" -LocalPort "88" -RemoteAddress "LocalSubnet"
    Add-FirewallRule -DisplayName "Kerberos UDP In" -Direction "Inbound" -Protocol "UDP" -LocalPort "88" -RemoteAddress "LocalSubnet"
    Add-FirewallRule -DisplayName "Kerberos UDP Out" -Direction "Outbound" -Protocol "UDP" -RemotePort "88" -RemoteAddress "LocalSubnet"

    # LDAP (TCP/UDP 389)
    Add-FirewallRule -DisplayName "LDAP TCP In" -Direction "Inbound" -Protocol "TCP" -LocalPort "389" -RemoteAddress "LocalSubnet"
    Add-FirewallRule -DisplayName "LDAP UDP In" -Direction "Inbound" -Protocol "UDP" -LocalPort "389" -RemoteAddress "LocalSubnet"

    # SMB (TCP 445)
    Add-FirewallRule -DisplayName "SMB In" -Direction "Inbound" -Protocol "TCP" -LocalPort "445" -RemoteAddress "LocalSubnet"
    Add-FirewallRule -DisplayName "SMB Out" -Direction "Outbound" -Protocol "TCP" -RemotePort "445" -RemoteAddress "LocalSubnet"

    # RPC Endpoint Mapper (TCP 135)
    Add-FirewallRule -DisplayName "RPC Map In" -Direction "Inbound" -Protocol "TCP" -LocalPort "135" -RemoteAddress "LocalSubnet"
    Add-FirewallRule -DisplayName "RPC Map Out" -Direction "Outbound" -Protocol "TCP" -RemotePort "135" -RemoteAddress "LocalSubnet"

    # W32Time (UDP 123)
    Add-FirewallRule -DisplayName "W32Time In" -Direction "Inbound" -Protocol "UDP" -LocalPort "123" -RemoteAddress "LocalSubnet"

    # DFSR / File Replication (TCP 139, UDP 138) - Legacy script had these
    Add-FirewallRule -DisplayName "NetBIOS Session In" -Direction "Inbound" -Protocol "TCP" -LocalPort "139" -RemoteAddress "LocalSubnet"
    Add-FirewallRule -DisplayName "NetBIOS Datagram In" -Direction "Inbound" -Protocol "UDP" -LocalPort "138" -RemoteAddress "LocalSubnet"
    
    # Global Catalog (TCP 3268/3269) - Not in legacy but critical for multi-domain
    Add-FirewallRule -DisplayName "Global Catalog TCP In" -Direction "Inbound" -Protocol "TCP" -LocalPort "3268" -RemoteAddress "LocalSubnet"
    Add-FirewallRule -DisplayName "Global Catalog SSL TCP In" -Direction "Inbound" -Protocol "TCP" -LocalPort "3269" -RemoteAddress "LocalSubnet"

    # AD Web Services (TCP 9389) - For AD PowerShell module/ADAC
    Add-FirewallRule -DisplayName "AD Web Services In" -Direction "Inbound" -Protocol "TCP" -LocalPort "9389" -RemoteAddress "LocalSubnet"
}

# --- 4. Member Server Rules (If not DC) ---
if (-not $isDC) {
    Write-Log -Message "Applying Member Server Firewall Rules..." -Level "INFO" -LogFile $LogFile
    
    # Allow communication TO Domain Controllers
    # We can't easily know DC IPs dynamically without querying AD, which might be blocked if we lock down too hard first.
    # Assuming LocalSubnet is safe for now.
    
    Add-FirewallRule -DisplayName "Kerberos to DC" -Direction "Outbound" -Protocol "TCP" -RemotePort "88" -RemoteAddress "LocalSubnet"
    Add-FirewallRule -DisplayName "LDAP to DC" -Direction "Outbound" -Protocol "TCP" -RemotePort "389" -RemoteAddress "LocalSubnet"
    Add-FirewallRule -DisplayName "SMB to DC" -Direction "Outbound" -Protocol "TCP" -RemotePort "445" -RemoteAddress "LocalSubnet"
    Add-FirewallRule -DisplayName "DNS to DC" -Direction "Outbound" -Protocol "UDP" -RemotePort "53" -RemoteAddress "LocalSubnet"
}

# --- 5. Block Script Engines Outbound ---
Write-Log -Message "Blocking Script Engines Outbound..." -Level "INFO" -LogFile $LogFile
$scriptEngines = @("powershell.exe", "powershell_ise.exe", "cscript.exe", "wscript.exe", "cmd.exe")
foreach ($engine in $scriptEngines) {
    try {
        New-NetFirewallRule -DisplayName "Block Outbound $engine" -Direction Outbound -Program "%SystemRoot%\System32\$engine" -Action Block -Profile Any -ErrorAction SilentlyContinue | Out-Null
        New-NetFirewallRule -DisplayName "Block Outbound $engine (SysWOW64)" -Direction Outbound -Program "%SystemRoot%\SysWOW64\$engine" -Action Block -Profile Any -ErrorAction SilentlyContinue | Out-Null
        Write-Log -Message "Blocked outbound traffic for $engine" -Level "SUCCESS" -LogFile $LogFile
    } catch {
        Write-Log -Message "Failed to block ${engine}: $_" -Level "WARNING" -LogFile $LogFile
    }
}

Write-Log -Message "Firewall Hardening Complete." -Level "SUCCESS" -LogFile $LogFile
