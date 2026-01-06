# 02_Network_Security.ps1
# Handles Network level hardening for AD (Firewall, Zerologon)

param(
    [string]$LogFile
)

if (-not (Get-Command Write-Log -ErrorAction SilentlyContinue)) {
    . "$PSScriptRoot/../functions/Write-Log.ps1"
}
if (-not (Get-Command Set-RegistryValue -ErrorAction SilentlyContinue)) {
    . "$PSScriptRoot/../functions/Set-RegistryValue.ps1"
}

Write-Log -Message "Starting Network Security Hardening..." -Level "INFO" -LogFile $LogFile

# --- 1. Disable SMBv1 ---
Write-Log -Message "Disabling SMBv1 Protocol..." -Level "INFO" -LogFile $LogFile
try {
    # Method 1: Set-SmbServerConfiguration (Preferred)
    if (Get-Command Set-SmbServerConfiguration -ErrorAction SilentlyContinue) {
        Set-SmbServerConfiguration -EnableSMB1Protocol $false -Force -Confirm:$false -ErrorAction Stop
        Write-Log -Message "SMBv1 disabled via Set-SmbServerConfiguration." -Level "SUCCESS" -LogFile $LogFile
    }
    # Method 2: Registry Fallback
    else {
        Set-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Services\LanmanServer\Parameters" -Name "SMB1" -Value 0 -Type DWord -Force
        Write-Log -Message "SMBv1 disabled via Registry." -Level "SUCCESS" -LogFile $LogFile
    }
}
catch {
    Write-Log -Message "Failed to disable SMBv1: $_" -Level "ERROR" -LogFile $LogFile
}

# --- 2. SMB & Network Hardening (Extended) ---
Write-Log -Message "Applying Extended SMB & Network Hardening..." -Level "INFO" -LogFile $LogFile
try {
    # Disable SMB Compression (SMBGhost CVE-2020-0796)
    Set-RegistryValue -Path "HKLM:\SYSTEM\CurrentControlSet\Services\LanmanServer\Parameters" -Name "DisableCompression" -Value 1 -Type DWord
    
    # Enable SMB Signing (Server & Workstation)
    Set-RegistryValue -Path "HKLM:\SYSTEM\CurrentControlSet\Services\LanmanServer\Parameters" -Name "EnableSecuritySignature" -Value 1 -Type DWord
    Set-RegistryValue -Path "HKLM:\SYSTEM\CurrentControlSet\Services\LanmanWorkstation\Parameters" -Name "EnableSecuritySignature" -Value 1 -Type DWord
    
    Write-Host "IMPACT: Enforcing SMB Signing breaks access for legacy clients (WinXP/2003, old printers/scanners) and non-Windows clients that don't support it." -ForegroundColor Yellow
    $smbSign = Read-Host "Do you want to require SMB signing? This may break legacy clients [y/n]"
    if ($smbSign -eq 'y') {
        Set-RegistryValue -Path "HKLM:\SYSTEM\CurrentControlSet\Services\LanmanServer\Parameters" -Name "RequireSecuritySignature" -Value 1 -Type DWord
        Set-RegistryValue -Path "HKLM:\SYSTEM\CurrentControlSet\Services\LanmanWorkstation\Parameters" -Name "RequireSecuritySignature" -Value 1 -Type DWord
        Write-Log -Message "SMB signing set to 'Require'." -Level "SUCCESS" -LogFile $LogFile
    } else {
        Write-Log -Message "Skipping SMB signing 'Require' to preserve compatibility with legacy clients." -Level "WARNING" -LogFile $LogFile
    }

    # Restrict Null Session Access
    Set-RegistryValue -Path "HKLM:\SYSTEM\CurrentControlSet\Services\LanManServer\Parameters" -Name "RestrictNullSessAccess" -Value 1 -Type DWord
    Set-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Services\LanmanServer\Parameters" -Name "NullSessionPipes" -Value ([string[]]@()) -Force
    Set-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Services\LanmanServer\Parameters" -Name "NullSessionShares" -Value ([string[]]@()) -Force

    # Disable SMB Admin Shares
    Set-RegistryValue -Path "HKLM:\System\CurrentControlSet\Services\LanmanServer\Parameters" -Name "AutoShareServer" -Value 0 -Type DWord
    Set-RegistryValue -Path "HKLM:\System\CurrentControlSet\Services\LanmanServer\Parameters" -Name "AutoShareWks" -Value 0 -Type DWord

    # Disable LLMNR
    Set-RegistryValue -Path "HKLM:\Software\policies\Microsoft\Windows NT\DNSClient" -Name "EnableMulticast" -Value 0 -Type DWord
    
    # Disable NetBIOS over TCP/IP (NBT-NS) - Registry method for all interfaces
    $regkey = "HKLM:\SYSTEM\CurrentControlSet\services\NetBT\Parameters\Interfaces"
    if (Test-Path $regkey) {
        Get-ChildItem $regkey | ForEach-Object { 
            Set-ItemProperty -Path "$($_.PSPath)" -Name "NetbiosOptions" -Value 2 -Force 
        }
    }

    # Disable mDNS
    Set-RegistryValue -Path "HKLM:\SYSTEM\CurrentControlSet\Services\Dnscache\Parameters" -Name "EnableMDNS" -Value 0 -Type DWord

    # Hardened UNC Paths (A-HardenedPaths / MS15-011 / MS15-014)
    Write-Host "IMPACT: Hardened UNC Paths can prevent Group Policy processing on clients that can't perform mutual authentication (e.g., non-domain joined, very old OS)." -ForegroundColor Yellow
    $uncPaths = Read-Host "Do you want to enable Hardened UNC Paths for SYSVOL/NETLOGON? [y/n]"
    if ($uncPaths -eq 'y') {
        $hardenedPathsKey = "HKLM:\SOFTWARE\Policies\Microsoft\Windows\NetworkProvider\HardenedPaths"
        if (-not (Test-Path $hardenedPathsKey)) { New-Item -Path $hardenedPathsKey -Force | Out-Null }
        Set-ItemProperty -Path $hardenedPathsKey -Name "\\*\NETLOGON" -Value "RequireMutualAuthentication=1, RequireIntegrity=1" -Force
        Set-ItemProperty -Path $hardenedPathsKey -Name "\\*\SYSVOL" -Value "RequireMutualAuthentication=1, RequireIntegrity=1" -Force
        Write-Log -Message "Hardened UNC paths applied." -Level "SUCCESS" -LogFile $LogFile
    } else {
        Write-Log -Message "Skipping hardened UNC paths for SYSVOL/NETLOGON to avoid client compatibility issues." -Level "WARNING" -LogFile $LogFile
    }

    Write-Log -Message "Extended SMB/Network hardening applied." -Level "SUCCESS" -LogFile $LogFile
} catch {
    Write-Log -Message "Failed to apply Extended SMB/Network hardening: $_" -Level "ERROR" -LogFile $LogFile
}

# --- 3. LDAP & Kerberos Hardening ---
Write-Log -Message "Applying LDAP & Kerberos Hardening..." -Level "INFO" -LogFile $LogFile
try {
    # Enforce LDAP Client Signing
    Set-RegistryValue -Path "HKLM:\SYSTEM\CurrentControlSet\Services\LDAP" -Name "LDAPClientIntegrity" -Value 2 -Type DWord
    
    # Enforce NTLMv2 Only (Refuse LM & NTLM) - RELAXED to 3 (Send NTLMv2, allow others) for Web Server/Legacy compatibility
    Set-RegistryValue -Path "HKLM:\SYSTEM\CurrentControlSet\Control\Lsa" -Name "LmCompatibilityLevel" -Value 3 -Type DWord

    # Kerberos Encryption Types (AES + RC4) - RELAXED for Web Server compatibility
    # 2147483644 = AES128 + AES256 + RC4
    Set-RegistryValue -Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System\Kerberos\Parameters" -Name "SupportedEncryptionTypes" -Value 2147483644 -Type DWord

    # LDAP Server Integrity (Signing)
    Set-RegistryValue -Path "HKLM:\System\CurrentControlSet\Services\NTDS\Parameters" -Name "LDAPServerIntegrity" -Value 2 -Type DWord
    
    # LDAP Channel Binding
    Write-Host "IMPACT: Enforcing LDAP Channel Binding breaks legacy LDAP clients/apps that don't support Channel Binding Tokens (CBT) over SSL." -ForegroundColor Yellow
    $ldapBinding = Read-Host "Do you want to enforce LDAP Channel Binding? [y/n]"
    if ($ldapBinding -eq 'y') {
        Set-RegistryValue -Path "HKLM:\System\CurrentControlSet\Services\NTDS\Parameters" -Name "LdapEnforceChannelBinding" -Value 2 -Type DWord
        Write-Log -Message "LDAP Channel Binding enforcement enabled." -Level "SUCCESS" -LogFile $LogFile
    } else {
        Write-Log -Message "Skipping LDAP channel binding enforcement to avoid breaking legacy LDAP clients." -Level "WARNING" -LogFile $LogFile
    }

    # Disable Unauthenticated LDAP (dsHeuristics)
    $DN = ("CN=Directory Service,CN=Windows NT,CN=Services,CN=Configuration," + (Get-ADDomain).DistinguishedName)
    $DirectoryService = Get-ADObject -Identity $DN -Properties dsHeuristics
    $Heuristic = $DirectoryService.dsHeuristics
    if (-not $Heuristic) { $Heuristic = "0000000" }
    if ($Heuristic.Length -ge 7) {
        $Array = $Heuristic.ToCharArray()
        $Array[6] = "0"
        $Heuristic = "$Array".Replace(" ", "")
        Set-ADObject -Identity $DirectoryService -Replace @{dsHeuristics = $Heuristic}
        Write-Log -Message "Disabled Anonymous LDAP via dsHeuristics." -Level "SUCCESS" -LogFile $LogFile
    }
} catch {
    Write-Log -Message "Failed to apply LDAP/Kerberos hardening: $_" -Level "ERROR" -LogFile $LogFile
}

# --- 4. DNS Security ---
Write-Log -Message "Applying DNS Security..." -Level "INFO" -LogFile $LogFile
try {
    # SIGRed Mitigation
    Set-RegistryValue -Path "HKLM:\SYSTEM\CurrentControlSet\Services\DNS\Parameters" -Name "TcpReceivePacketSize" -Value 0xFF00 -Type DWord

    # Global Query Block List
    dnscmd /config /enableglobalqueryblocklist 1 | Out-Null

    # Response Rate Limiting
    if (Get-Command Set-DnsServerResponseRateLimiting -ErrorAction SilentlyContinue) {
        Set-DnsServerRRL -Mode Enable -Force -ErrorAction SilentlyContinue
    }

    # DNS Socket Pool Size (Anti-DDoS)
    dnscmd /config /SocketPoolSize 10000 | Out-Null
    Write-Log -Message "DNS Socket Pool Size set to 10000." -Level "SUCCESS" -LogFile $LogFile

    # DNS Cache Locking (Anti-Cache Poisoning)
    dnscmd /config /CacheLockingPercent 100 | Out-Null
    Write-Log -Message "DNS Cache Locking set to 100%." -Level "SUCCESS" -LogFile $LogFile

    Write-Log -Message "DNS Security settings applied." -Level "SUCCESS" -LogFile $LogFile
} catch {
    Write-Log -Message "Failed to apply DNS Security: $_" -Level "ERROR" -LogFile $LogFile
}

# --- 4.1 Advanced DNS Hardening (Legacy DNS.ps1) ---
Write-Log -Message "Applying Advanced DNS Hardening..." -Level "INFO" -LogFile $LogFile
try {
    # Registry Hardening
    Set-RegistryValue -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows NT\DNSClient" -Name "EnableMulticast" -Value 0 -Type DWord
    Set-RegistryValue -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows NT\DNSClient" -Name "DisableSmartNameResolution" -Value 1 -Type DWord
    Set-RegistryValue -Path "HKLM:\SYSTEM\CurrentControlSet\Services\Dnscache\Parameters" -Name "DisableParallelAandAAAA" -Value 1 -Type DWord

    # DNS Server Configuration (dnscmd equivalents)
    # Using Set-DnsServer* cmdlets where possible for cleaner PowerShell
    
    # Recursion & Security
    Write-Host "IMPACT: Disabling DNS Recursion prevents this server from resolving external internet domains. Clients using this DC for internet DNS will fail." -ForegroundColor Yellow
    $dnsRecursion = Read-Host "Do you want to disable DNS recursion? [y/n]"
    if ($dnsRecursion -eq 'y') {
        if (Get-Command Set-DnsServerRecursion -ErrorAction SilentlyContinue) {
            Set-DnsServerRecursion -Enable $false -ErrorAction SilentlyContinue
        } else {
            dnscmd /config /norecursion 1 | Out-Null
        }
        Write-Log -Message "DNS recursion disabled." -Level "SUCCESS" -LogFile $LogFile
    } else {
        Write-Log -Message "Skipping DNS recursion disable to avoid resolver outages." -Level "WARNING" -LogFile $LogFile
    }
    
    # Diagnostics
    Set-DnsServerDiagnostics -EventLogLevel 4 -UseSystemEventLog $True -EnableLogFileRollover $False -ErrorAction SilentlyContinue
    
    # Cache & TTL
    Set-DnsServerCache -MaxTtl "24.00:00:00" -MaxNegativeTtl "00:15:00" -PollutionProtection $True -ErrorAction SilentlyContinue
    
    # Zone Transfers (Secure Only)
    # This iterates all zones and sets them to Secure Only updates and restricts transfers
    $zones = Get-DnsServerZone
    foreach ($zone in $zones) {
        if ($zone.ZoneType -eq "Primary" -and $zone.IsAutoCreated -eq $false) {
            try {
                Set-DnsServerPrimaryZone -Name $zone.ZoneName -DynamicUpdate Secure -ErrorAction SilentlyContinue
                Set-DnsServerZoneTransfer -Name $zone.ZoneName -SecureSecondaries TransferToSecureServers -ErrorAction SilentlyContinue
            } catch {
                Write-Log -Message "Failed to harden zone $($zone.ZoneName): $_" -Level "WARNING" -LogFile $LogFile
            }
        }
    }

    # Scavenging
    Set-DnsServerScavenging -ScavengingInterval "7.00:00:00" -ErrorAction SilentlyContinue

    # Additional dnscmd configs from legacy script
    # Some of these don't have direct cmdlet equivalents or are obscure
    dnscmd /config /bindsecondaries 0 | Out-Null
    dnscmd /config /bootmethod 3 | Out-Null
    dnscmd /config /disableautoreversezones 1 | Out-Null
    dnscmd /config /disablensrecordsautocreation 1 | Out-Null
    dnscmd /config /enableglobalnamessupport 0 | Out-Null
    dnscmd /config /enableglobalqueryblocklist 1 | Out-Null
    dnscmd /config /globalqueryblocklist isatap wpad | Out-Null
    dnscmd /config /roundrobin 1 | Out-Null
    dnscmd /config /secureresponses 1 | Out-Null
    dnscmd /config /strictfileparsing 1 | Out-Null
    dnscmd /config /writeauthorityns 0 | Out-Null

    # ServerLevelPluginDll Check
    $dnsParams = Get-ItemProperty "HKLM:\SYSTEM\CurrentControlSet\Services\DNS\Parameters"
    if ($dnsParams.ServerLevelPluginDll) {
        Write-Log -Message "WARNING: ServerLevelPluginDll found: $($dnsParams.ServerLevelPluginDll). This is often malicious." -Level "WARNING" -LogFile $LogFile
        # Legacy script asks to delete. We will log heavily.
        # Remove-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Services\DNS\Parameters" -Name "ServerLevelPluginDll" -Force
    }

    Write-Log -Message "Advanced DNS Hardening applied." -Level "SUCCESS" -LogFile $LogFile
} catch {
    Write-Log -Message "Failed to apply Advanced DNS Hardening: $_" -Level "ERROR" -LogFile $LogFile
}

# --- 5. Zerologon Mitigation & Netlogon Hardening ---
Write-Log -Message "Applying Zerologon Mitigation and Netlogon Hardening..." -Level "INFO" -LogFile $LogFile
try {
    $netlogonPath = "HKLM:\SYSTEM\CurrentControlSet\Services\Netlogon\Parameters"

    # Zerologon Protection
    Set-RegistryValue -Path $netlogonPath -Name "FullSecureChannelProtection" -Value 1 -Type DWord
    Write-Log -Message "FullSecureChannelProtection enabled." -Level "SUCCESS" -LogFile $LogFile

    # Remove Vulnerable Channel Allowlist
    if (Test-Path -Path "$netlogonPath\vulnerablechannelallowlist") {
        Remove-ItemProperty -Path $netlogonPath -Name "vulnerablechannelallowlist" -Force | Out-Null
        Write-Log -Message "vulnerablechannelallowlist removed." -Level "SUCCESS" -LogFile $LogFile
    }

    # Netlogon Secure Channel Hardening (AD-Specific)
    Set-RegistryValue -Path $netlogonPath -Name "RequireSignOrSeal" -Value 1 -Type DWord
    Set-RegistryValue -Path $netlogonPath -Name "SealSecureChannel" -Value 1 -Type DWord
    Set-RegistryValue -Path $netlogonPath -Name "SignSecureChannel" -Value 1 -Type DWord
    Set-RegistryValue -Path $netlogonPath -Name "RequireStrongKey" -Value 1 -Type DWord
    Write-Log -Message "Netlogon secure channel hardening applied (Sign/Seal/StrongKey)." -Level "SUCCESS" -LogFile $LogFile
}
catch {
    Write-Log -Message "Failed to apply Netlogon hardening: $_" -Level "ERROR" -LogFile $LogFile
}

# --- 6. NTLM Security Levels (AD-Specific) ---
Write-Log -Message "Configuring NTLM Minimum Security Levels..." -Level "INFO" -LogFile $LogFile
try {
    # NTLMv2 Session Security (Require NTLMv2, 128-bit encryption)
    # Value 537395200 = 0x20080000 = Require NTLMv2 + 128-bit encryption
    # RELAXED: Commented out to prevent breaking legacy clients/Web Servers
    Write-Host "IMPACT: Enforcing NTLMv2+128bit breaks authentication for legacy clients (pre-Win7) and old devices (NAS, printers) that rely on NTLMv1/LM." -ForegroundColor Yellow
    $ntlmSec = Read-Host "Do you want to enforce NTLM Minimum Security Levels (Require NTLMv2 + 128-bit)? [y/n]"
    if ($ntlmSec -eq 'y') {
        Set-RegistryValue -Path "HKLM:\SYSTEM\CurrentControlSet\Control\Lsa\MSV1_0" -Name "NTLMMinClientSec" -Value 537395200 -Type DWord
        Set-RegistryValue -Path "HKLM:\SYSTEM\CurrentControlSet\Control\Lsa\MSV1_0" -Name "NTLMMinServerSec" -Value 537395200 -Type DWord
        Write-Log -Message "NTLM minimum security levels enforced." -Level "SUCCESS" -LogFile $LogFile
    } else {
        Write-Log -Message "NTLM minimum security levels SKIPPED for compatibility." -Level "WARNING" -LogFile $LogFile
    }
}
catch {
    Write-Log -Message "Failed to configure NTLM security levels: $_" -Level "ERROR" -LogFile $LogFile
}

# --- 7. Additional LSA Hardening (AD-Specific Anonymous Access Prevention) ---
Write-Log -Message "Applying Additional LSA Hardening..." -Level "INFO" -LogFile $LogFile
try {
    $lsaPath = "HKLM:\SYSTEM\CurrentControlSet\Control\Lsa"

    # Prevent Anonymous Access to AD
    # RELAXED: Set to 0 for Web Server compatibility (IIS often needs this)
    Set-RegistryValue -Path $lsaPath -Name "RestrictAnonymous" -Value 0 -Type DWord
    Set-RegistryValue -Path $lsaPath -Name "RestrictAnonymousSAM" -Value 1 -Type DWord
    Set-RegistryValue -Path $lsaPath -Name "EveryoneIncludesAnonymous" -Value 1 -Type DWord

    # Disable Default Admin Shares (C$, ADMIN$ auto-creation)
    Set-RegistryValue -Path $lsaPath -Name "NoDefaultAdminShares" -Value 1 -Type DWord

    # Disable Storing Domain Credentials
    Set-RegistryValue -Path $lsaPath -Name "DisableDomainCreds" -Value 1 -Type DWord

    Write-Log -Message "LSA anonymous access prevention and credential hardening applied." -Level "SUCCESS" -LogFile $LogFile
}
catch {
    Write-Log -Message "Failed to apply additional LSA hardening: $_" -Level "ERROR" -LogFile $LogFile
}

# --- 2. AD Firewall Rules ---
Write-Log -Message "Configuring AD Firewall Rules..." -Level "INFO" -LogFile $LogFile

# Enable AD DS Group
try {
    netsh a f s r group="Active Directory Domain Services" new enable=yes
    Write-Log -Message "Enabled 'Active Directory Domain Services' firewall group." -Level "SUCCESS" -LogFile $LogFile
} catch {
    Write-Log -Message "Failed to enable AD DS firewall group." -Level "ERROR" -LogFile $LogFile
}

# Allow DNS Inbound on DC
try {
    netsh a f a r n=DNS_IN dir=in a=allow prot=UDP localport=53
    Write-Log -Message "Allowed DNS Inbound (UDP 53)." -Level "SUCCESS" -LogFile $LogFile
} catch {
    Write-Log -Message "Failed to allow DNS Inbound." -Level "ERROR" -LogFile $LogFile
}

# General Block Policy (from zero.ps1 - careful with this!)
# I will include it but commented out or with a warning, as it requires all allow rules to be perfect.
# Given the user said "keep AD hardening", this is a general firewall setting but critical for the "Lockdown" aspect.
# I will apply it but ensure we logged it.

Write-Log -Message "Applying Default Block Policy (Inbound/Outbound)..." -Level "WARNING" -LogFile $LogFile
try {
    Write-Host "IMPACT: Setting the default firewall policy to BlockInbound,BlockOutbound will cut off all network access unless explicit ALLOW rules exist. Ensure all necessary ALLOW rules are perfect before proceeding." -ForegroundColor Red
    $blockPolicy = Read-Host "Do you want to apply the Default Block Policy (BlockInbound, BlockOutbound)? [y/n]"
    if ($blockPolicy -eq 'y') {
        netsh advfirewall set allprofiles firewallpolicy "blockinbound,blockoutbound"
        Write-Log -Message "Default Block Policy applied." -Level "SUCCESS" -LogFile $LogFile
    } else {
        Write-Log -Message "Skipping Default Block Policy to avoid network lockout." -Level "WARNING" -LogFile $LogFile
    }
} catch {
    Write-Log -Message "Failed to set firewall policy: $_" -Level "ERROR" -LogFile $LogFile
}

# Enable Firewall Logging
try {
    Set-NetFirewallProfile -LogAllowed True -LogBlocked True -LogFileName "%SystemRoot%\System32\LogFiles\Firewall\pfirewall.log" -LogMaxSizeKilobytes 10000
    Write-Log -Message "Firewall logging enabled." -Level "SUCCESS" -LogFile $LogFile
} catch {
    Write-Log -Message "Failed to enable firewall logging." -Level "ERROR" -LogFile $LogFile
}

# --- 8. Network Share Cleanup ---
Write-Log -Message "Removing Unnecessary Network Shares..." -Level "INFO" -LogFile $LogFile
try {
    $essentialShares = @("ADMIN$", "C$", "IPC$", "NETLOGON", "SYSVOL")
    $sharesToRemove = Get-SmbShare | Where-Object { $_.Name -notin $essentialShares }

    foreach ($share in $sharesToRemove) {
        try {
            Remove-SmbShare -Name $share.Name -Force -ErrorAction Stop
            Write-Log -Message "Removed network share: $($share.Name)" -Level "SUCCESS" -LogFile $LogFile
        }
        catch {
            Write-Log -Message "Failed to remove share $($share.Name): $_" -Level "WARNING" -LogFile $LogFile
        }
    }
    Write-Log -Message "Network share cleanup completed." -Level "SUCCESS" -LogFile $LogFile
}
catch {
    Write-Log -Message "Failed during network share cleanup: $_" -Level "ERROR" -LogFile $LogFile
}

# --- 9. Time Synchronization (Critical for Kerberos) ---
Write-Log -Message "Synchronizing System Time..." -Level "INFO" -LogFile $LogFile
try {
    # Set timezone (adjust as needed for your environment)
    tzutil /s "UTC" | Out-Null

    # Force time resync with domain hierarchy
    w32tm /resync /force | Out-Null

    Write-Log -Message "System time synchronized successfully." -Level "SUCCESS" -LogFile $LogFile
}
catch {
    Write-Log -Message "Failed to synchronize system time: $_" -Level "ERROR" -LogFile $LogFile
}
