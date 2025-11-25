# 04_Audit_Logging.ps1
# Handles Audit Policy and Logging configurations

param(
    [string]$LogFile
)

if (-not (Get-Command Write-Log -ErrorAction SilentlyContinue)) {
    . "$PSScriptRoot/../functions/Write-Log.ps1"
}
if (-not (Get-Command Set-RegistryValue -ErrorAction SilentlyContinue)) {
    . "$PSScriptRoot/../functions/Set-RegistryValue.ps1"
}

Write-Log -Message "Starting Audit Logging Configuration..." -Level "INFO" -LogFile $LogFile

# --- 1. LSASS Audit Level ---
Write-Log -Message "Configuring LSASS Audit Level..." -Level "INFO" -LogFile $LogFile
try {
    # AuditLevel 8 (Log all access to LSASS)
    $regResult = Set-RegistryValue -Path "HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Image File Execution Options\LSASS.exe" -Name "AuditLevel" -Value 8 -Type DWord
    if ($regResult) {
        Write-Log -Message "LSASS AuditLevel set to 8." -Level "SUCCESS" -LogFile $LogFile
    }
}
catch {
    Write-Log -Message "Failed to set LSASS AuditLevel: $_" -Level "ERROR" -LogFile $LogFile
}

# --- 2. LSA Protection (RunAsPPL) ---
# This was in zero.ps1 under PTH Mitigation, but fits well with security config/auditing context
Write-Log -Message "Configuring LSA Protection (RunAsPPL)..." -Level "INFO" -LogFile $LogFile
try {
    $regResult = Set-RegistryValue -Path "HKLM:\SYSTEM\CurrentControlSet\Control\Lsa" -Name "RunAsPPL" -Value 1 -Type DWord
    if ($regResult) {
        Write-Log -Message "RunAsPPL enabled." -Level "SUCCESS" -LogFile $LogFile
    }
}
catch {
    Write-Log -Message "Failed to set RunAsPPL: $_" -Level "ERROR" -LogFile $LogFile
}

# --- 3. Logon/Logoff Audit Policy (Advanced) ---
Write-Log -Message "Configuring Advanced Audit Policy..." -Level "INFO" -LogFile $LogFile
try {
    # Force Advanced Audit Policy
    Set-RegistryValue -Path "HKLM:\System\CurrentControlSet\Control\Lsa" -Name "SCENoApplyLegacyAuditPolicy" -Value 1 -Type DWord

    $auditRules = @(
        "Account Logon,Kerberos Authentication Service,Success and Failure",
        "Account Logon,Kerberos Service Ticket Operations,Success and Failure",
        "Account Management,Computer Account Management,Success and Failure",
        "Account Management,Security Group Management,Success and Failure",
        "Account Management,User Account Management,Success and Failure",
        "Detailed Tracking,DPAPI Activity,Success and Failure",
        "Detailed Tracking,Process Creation,Success and Failure",
        "Logon/Logoff,Logoff,Success and Failure",
        "Logon/Logoff,Logon,Success and Failure",
        "Logon/Logoff,Special Logon,Success and Failure",
        "Object Access,Detailed File Share,Failure", # Good for noise reduction, but useful
        "Policy Change,Authentication Policy Change,Success and Failure",
        "Privilege Use,Sensitive Privilege Use,Success and Failure",
        "System,Security System Extension,Success and Failure"
    )

    foreach ($rule in $auditRules) {
        $parts = $rule -split ","
        $category = $parts[0]
        $subcategory = $parts[1]
        $setting = $parts[2]
        
        $cmd = "auditpol /set /subcategory:`"$subcategory`" /success:enable /failure:enable"
        if ($setting -eq "Failure") { $cmd = "auditpol /set /subcategory:`"$subcategory`" /success:disable /failure:enable" }
        if ($setting -eq "Success") { $cmd = "auditpol /set /subcategory:`"$subcategory`" /success:enable /failure:disable" }

        Invoke-Expression $cmd | Out-Null
        Write-Log -Message "Configured Audit: $subcategory -> $setting" -Level "SUCCESS" -LogFile $LogFile
    }
}
catch {
    Write-Log -Message "Exception configuring audit policy: $_" -Level "ERROR" -LogFile $LogFile
}

# --- 4. LSASS & WDigest Hardening ---
Write-Log -Message "Configuring LSASS & WDigest Hardening..." -Level "INFO" -LogFile $LogFile
try {
    # WDigest - Disable UseLogonCredential
    Set-RegistryValue -Path "HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\WDigest" -Name "UseLogonCredential" -Value 0 -Type DWord
    Set-RegistryValue -Path "HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\WDigest" -Name "Negotiate" -Value 0 -Type DWord

    # LSASS - LimitBlankPasswordUse
    Set-RegistryValue -Path "HKLM:\SYSTEM\CurrentControlSet\Control\Lsa" -Name "LimitBlankPasswordUse" -Value 1 -Type DWord
    
    # LSASS - NoLMHash
    Set-RegistryValue -Path "HKLM:\SYSTEM\CurrentControlSet\Control\Lsa" -Name "NoLMHash" -Value 1 -Type DWord

    Write-Log -Message "LSASS & WDigest settings configured." -Level "SUCCESS" -LogFile $LogFile
} catch {
    Write-Log -Message "Failed to configure LSASS/WDigest: $_" -Level "ERROR" -LogFile $LogFile
}

# --- 5. Advanced AD Object Auditing (DC Only) ---
if (Get-WmiObject -Query "select * from Win32_OperatingSystem where ProductType='2'") {
    Write-Log -Message "Configuring Advanced AD Object Auditing..." -Level "INFO" -LogFile $LogFile
    
    function Set-ADObjectAudit {
        param($DistinguishedName, $AuditRules)
        try {
            $Acl = Get-Acl -Path "AD:\$DistinguishedName" -Audit
            if ($Acl) {
                foreach ($Rule in $AuditRules) {
                    $Acl.AddAuditRule($Rule)
                }
                Set-Acl -Path "AD:\$DistinguishedName" -AclObject $Acl
                return $true
            }
        } catch {
            Write-Log -Message "Failed to set audit on $DistinguishedName : $_" -Level "WARNING" -LogFile $LogFile
        }
        return $false
    }

    try {
        $DomainDN = (Get-ADDomain).DistinguishedName
        $Everyone = New-Object System.Security.Principal.SecurityIdentifier([System.Security.Principal.WellKnownSidType]::WorldSid, $null)
        
        # 1. RID Manager Auditing
        $RidManagerDN = "CN=RID Manager$,CN=System,$DomainDN"
        $RidRule = New-Object System.DirectoryServices.ActiveDirectoryAuditRule($Everyone, [System.DirectoryServices.ActiveDirectoryRights]::GenericAll, [System.Security.AccessControl.AuditFlags]::Failure, [System.DirectoryServices.ActiveDirectorySecurityInheritance]::None)
        Set-ADObjectAudit -DistinguishedName $RidManagerDN -AuditRules @($RidRule)

        # 2. AdminSDHolder Auditing
        $AdminSDHolderDN = "CN=AdminSDHolder,CN=System,$DomainDN"
        $AdminSDRule = New-Object System.DirectoryServices.ActiveDirectoryAuditRule($Everyone, [System.DirectoryServices.ActiveDirectoryRights]::GenericAll, [System.Security.AccessControl.AuditFlags]::Failure, [System.DirectoryServices.ActiveDirectorySecurityInheritance]::None)
        Set-ADObjectAudit -DistinguishedName $AdminSDHolderDN -AuditRules @($AdminSDRule)

        # 3. Domain Controllers OU Auditing
        $DCOU_DN = "OU=Domain Controllers,$DomainDN"
        $DCRule = New-Object System.DirectoryServices.ActiveDirectoryAuditRule($Everyone, [System.DirectoryServices.ActiveDirectoryRights]::WriteDacl, [System.Security.AccessControl.AuditFlags]::Success, [System.DirectoryServices.ActiveDirectorySecurityInheritance]::None)
        Set-ADObjectAudit -DistinguishedName $DCOU_DN -AuditRules @($DCRule)

        Write-Log -Message "Advanced AD Object Auditing configured." -Level "SUCCESS" -LogFile $LogFile
    } catch {
        Write-Log -Message "Failed to configure Advanced AD Auditing: $_" -Level "ERROR" -LogFile $LogFile
    }
}

# --- 6. GPO Permission Check (Reporting) ---
Write-Log -Message "Checking for insecure GPO permissions (Authenticated Users)..." -Level "INFO" -LogFile $LogFile
try {
    $insecureGPOs = @()
    Get-GPO -All | ForEach-Object {
        $gpoName = $_.DisplayName
        Get-GPPermissions -Guid $_.Id -All | ForEach-Object {
            if ($_.Trustee.Name -eq "Authenticated Users" -and $_.Permission -ne "GpoRead") {
                 # GpoRead is normal for Auth Users (to apply policy). Anything else (Edit, etc.) is bad.
                 # The legacy script just checks if Trustee is "Authenticated Users" and prints it.
                 # We will log it if found.
                 $insecureGPOs += "$gpoName ($($_.Permission))"
            }
        }
    }
    
    if ($insecureGPOs.Count -gt 0) {
        Write-Log -Message "Found GPOs with potentially insecure 'Authenticated Users' permissions:" -Level "WARNING" -LogFile $LogFile
        foreach ($gpo in $insecureGPOs) {
            Write-Log -Message "  - $gpo" -Level "WARNING" -LogFile $LogFile
        }
    } else {
        Write-Log -Message "No obvious GPO permission issues found for Authenticated Users." -Level "SUCCESS" -LogFile $LogFile
    }
} catch {
    Write-Log -Message "Failed to check GPO permissions: $_" -Level "ERROR" -LogFile $LogFile
}

