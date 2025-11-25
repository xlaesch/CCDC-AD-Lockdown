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
    Set-RegistryValue -Path "HKLM:\SYSTEM\CurrentControlSet\Services\LanmanServer\Parameters" -Name "RequireSecuritySignature" -Value 1 -Type DWord
    Set-RegistryValue -Path "HKLM:\SYSTEM\CurrentControlSet\Services\LanmanWorkstation\Parameters" -Name "EnableSecuritySignature" -Value 1 -Type DWord
    Set-RegistryValue -Path "HKLM:\SYSTEM\CurrentControlSet\Services\LanmanWorkstation\Parameters" -Name "RequireSecuritySignature" -Value 1 -Type DWord

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
    $hardenedPathsKey = "HKLM:\SOFTWARE\Policies\Microsoft\Windows\NetworkProvider\HardenedPaths"
    if (-not (Test-Path $hardenedPathsKey)) {
        New-Item -Path $hardenedPathsKey -Force | Out-Null
    }
    # Require Mutual Authentication and Integrity for NETLOGON and SYSVOL
    Set-ItemProperty -Path $hardenedPathsKey -Name "\\*\NETLOGON" -Value "RequireMutualAuthentication=1, RequireIntegrity=1" -Type String -Force
    Set-ItemProperty -Path $hardenedPathsKey -Name "\\*\SYSVOL" -Value "RequireMutualAuthentication=1, RequireIntegrity=1" -Type String -Force
    
    Write-Log -Message "Hardened UNC Paths configured (Integrity/MutualAuth)." -Level "SUCCESS" -LogFile $LogFile

    Write-Log -Message "Extended SMB/Network hardening applied." -Level "SUCCESS" -LogFile $LogFile
} catch {
    Write-Log -Message "Failed to apply Extended SMB/Network hardening: $_" -Level "ERROR" -LogFile $LogFile
}

# --- 3. LDAP & Kerberos Hardening ---
Write-Log -Message "Applying LDAP & Kerberos Hardening..." -Level "INFO" -LogFile $LogFile
try {
    # Enforce LDAP Client Signing
    Set-RegistryValue -Path "HKLM:\SYSTEM\CurrentControlSet\Services\LDAP" -Name "LDAPClientIntegrity" -Value 2 -Type DWord
    
    # Enforce NTLMv2 Only (Refuse LM & NTLM)
    Set-RegistryValue -Path "HKLM:\SYSTEM\CurrentControlSet\Control\Lsa" -Name "LmCompatibilityLevel" -Value 5 -Type DWord

    # Kerberos Encryption Types (AES only)
    Set-RegistryValue -Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System\Kerberos\Parameters" -Name "SupportedEncryptionTypes" -Value 2147483640 -Type DWord

    if (Get-WmiObject -Query "select * from Win32_OperatingSystem where ProductType='2'") {
        # LDAP Server Integrity (Signing)
        Set-RegistryValue -Path "HKLM:\System\CurrentControlSet\Services\NTDS\Parameters" -Name "LDAPServerIntegrity" -Value 2 -Type DWord
        
        # LDAP Channel Binding
        Set-RegistryValue -Path "HKLM:\System\CurrentControlSet\Services\NTDS\Parameters" -Name "LdapEnforceChannelBinding" -Value 2 -Type DWord

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
    }
} catch {
    Write-Log -Message "Failed to apply LDAP/Kerberos hardening: $_" -Level "ERROR" -LogFile $LogFile
}

# --- 4. DNS Security (DC Only) ---
if (Get-WmiObject -Query "select * from Win32_OperatingSystem where ProductType='2'") {
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
        Set-DnsServerRecursion -Enable $False -SecureResponse $True -ErrorAction SilentlyContinue
        
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
}

# --- 5. Zerologon Mitigation ---
Write-Log -Message "Applying Zerologon Mitigation..." -Level "INFO" -LogFile $LogFile
try {
    $regResult = Set-RegistryValue -Path "HKLM:\SYSTEM\CurrentControlSet\Services\Netlogon\Parameters" -Name "FullSecureChannelProtection" -Value 1 -Type DWord
    if ($regResult) {
        Write-Log -Message "FullSecureChannelProtection enabled." -Level "SUCCESS" -LogFile $LogFile
    }

    $regPath = "HKLM:\SYSTEM\CurrentControlSet\Services\Netlogon\Parameters"
    $regName = "vulnerablechannelallowlist"
    if (Test-Path -Path "$regPath\$regName") {
        Remove-ItemProperty -Path $regPath -Name $regName -Force | Out-Null
        Write-Log -Message "vulnerablechannelallowlist removed." -Level "SUCCESS" -LogFile $LogFile
    } else {
        Write-Log -Message "vulnerablechannelallowlist does not exist, no action needed." -Level "INFO" -LogFile $LogFile
    }
}
catch {
    Write-Log -Message "Failed to apply Zerologon mitigation: $_" -Level "ERROR" -LogFile $LogFile
}

# --- 2. AD Firewall Rules ---
Write-Log -Message "Configuring AD Firewall Rules..." -Level "INFO" -LogFile $LogFile

# Only run on DC or where AD services are present
if (Get-WmiObject -Query "select * from Win32_OperatingSystem where ProductType='2'") {
    
    # Enable AD DS Group
    try {
        netsh a f s r group="Active Directory Domain Services" new enable=yes
        Write-Log -Message "Enabled 'Active Directory Domain Services' firewall group." -Level "SUCCESS" -LogFile $LogFile
    } catch {
        Write-Log -Message "Failed to enable AD DS firewall group." -Level "ERROR" -LogFile $LogFile
    }

    # Restrict AD DS to Local Subnet (Logic from zero.ps1)
    # Note: $localsubnet needs to be defined. In zero.ps1 it was empty initially. 
    # We will assume we want to restrict to local subnet if possible, but without a defined subnet variable, 
    # we might break things if we just pass empty string. 
    # For now, I will comment out the restriction part unless we have a config for it, 
    # but I will keep the structure as requested from zero.ps1.
    
    # In zero.ps1: $localsubnet="" (at top). 
    # If we want to implement this, we need to calculate the subnet or read from config.
    # I will skip the specific subnet restriction to avoid locking out legitimate traffic without config.
    
    # Allow DNS Inbound on DC
    try {
        netsh a f a r n=DNS_IN dir=in a=allow prot=UDP localport=53
        Write-Log -Message "Allowed DNS Inbound (UDP 53)." -Level "SUCCESS" -LogFile $LogFile
    } catch {
        Write-Log -Message "Failed to allow DNS Inbound." -Level "ERROR" -LogFile $LogFile
    }
}

# General Block Policy (from zero.ps1 - careful with this!)
# netsh a s allp firewallpolicy "blockinbound,blockoutbound" 
# The above line is very aggressive. zero.ps1 had it at the end. 
# I will include it but commented out or with a warning, as it requires all allow rules to be perfect.
# Given the user said "keep AD hardening", this is a general firewall setting but critical for the "Lockdown" aspect.
# I will apply it but ensure we logged it.

Write-Log -Message "Applying Default Block Policy (Inbound/Outbound)..." -Level "WARNING" -LogFile $LogFile
try {
    # netsh a s allp firewallpolicy "blockinbound,blockoutbound"
    # Commenting out for safety in this refactor step. Uncomment to enable full lockdown.
    Write-Log -Message "Default Block Policy is currently COMMENTED OUT in script for safety." -Level "INFO" -LogFile $LogFile
} catch {
    Write-Log -Message "Failed to set firewall policy." -Level "ERROR" -LogFile $LogFile
}

# Enable Firewall Logging
try {
    Set-NetFirewallProfile -LogAllowed True -LogBlocked True -LogFileName "%SystemRoot%\System32\LogFiles\Firewall\pfirewall.log" -LogMaxSizeKilobytes 10000
    Write-Log -Message "Firewall logging enabled." -Level "SUCCESS" -LogFile $LogFile
} catch {
    Write-Log -Message "Failed to enable firewall logging." -Level "ERROR" -LogFile $LogFile
}
