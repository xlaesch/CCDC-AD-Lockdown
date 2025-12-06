# 03_Service_Hardening.ps1
# Handles Service disabling (Print Spooler)

param(
    [string]$LogFile
)

if (-not (Get-Command Write-Log -ErrorAction SilentlyContinue)) {
    . "$PSScriptRoot/../functions/Write-Log.ps1"
}
if (-not (Get-Command Set-RegistryValue -ErrorAction SilentlyContinue)) {
    . "$PSScriptRoot/../functions/Set-RegistryValue.ps1"
}

Write-Log -Message "Starting Service Hardening..." -Level "INFO" -LogFile $LogFile

# --- 1. Print Spooler (Critical for DCs) ---
Write-Log -Message "Disabling Print Spooler..." -Level "INFO" -LogFile $LogFile
try {
    Stop-Service -Name "Spooler" -Force -ErrorAction SilentlyContinue
    Set-Service -Name "Spooler" -StartupType Disabled
    Write-Log -Message "Print Spooler service has been disabled." -Level "SUCCESS" -LogFile $LogFile
}
catch {
    Write-Log -Message "Failed to disable Print Spooler service: $_" -Level "ERROR" -LogFile $LogFile
}

# --- 2. DSRM Admin Logon Behavior ---
Write-Log -Message "Configuring DSRM Admin Logon Behavior..." -Level "INFO" -LogFile $LogFile
try {
    # 1 = Only allow DSRM admin to log on when AD DS is stopped
    Set-RegistryValue -Path "HKLM:\System\CurrentControlSet\Control\Lsa" -Name "DsrmAdminLogonBehavior" -Value 1 -Type DWord
    Write-Log -Message "DSRM Admin Logon Behavior set to 1." -Level "SUCCESS" -LogFile $LogFile
}
catch {
    Write-Log -Message "Failed to set DSRM Admin Logon Behavior: $_" -Level "ERROR" -LogFile $LogFile
}

# --- 3. NTDS File Permissions (DC Only) ---
if (Get-WmiObject -Query "select * from Win32_OperatingSystem where ProductType='2'") {
    Write-Log -Message "Hardening NTDS File Permissions..." -Level "INFO" -LogFile $LogFile
    try {
        $NTDS = Get-ItemProperty -Path "HKLM:\System\CurrentControlSet\Services\NTDS\Parameters" -ErrorAction SilentlyContinue
        if ($NTDS) {
            $DSA = $NTDS.'DSA Database File'
            $Logs = $NTDS.'Database log files path'
            
            if ($DSA -and $Logs) {
                $DSA_Folder = Split-Path -Parent $DSA
                $Logs_Folder = $Logs # Usually a folder path

                # Define Principals
                $Admins = New-Object Security.Principal.SecurityIdentifier([System.Security.Principal.WellKnownSidType]::BuiltinAdministratorsSid, $null)
                $System = New-Object Security.Principal.SecurityIdentifier([System.Security.Principal.WellKnownSidType]::LocalSystemSid, $null)
                
                # Create Access Rules
                $FullControl = [System.Security.AccessControl.FileSystemRights]::FullControl
                $Inheritance = @([System.Security.AccessControl.InheritanceFlags]::ObjectInherit, [System.Security.AccessControl.InheritanceFlags]::ContainerInherit)
                $Propagation = [System.Security.AccessControl.PropagationFlags]::None
                $Allow = [System.Security.AccessControl.AccessControlType]::Allow

                $AdminRule = New-Object System.Security.AccessControl.FileSystemAccessRule($Admins, $FullControl, $Inheritance, $Propagation, $Allow)
                $SystemRule = New-Object System.Security.AccessControl.FileSystemAccessRule($System, $FullControl, $Inheritance, $Propagation, $Allow)

                # Apply to DSA Folder
                if (Test-Path $DSA_Folder) {
                    $Acl = Get-Acl -Path $DSA_Folder
                    # Clear existing rules (careful!) - actually, let's just ensure Admins/System have FullControl and remove inheritance if needed.
                    # whoo.ps1 removes all rules and adds specific ones. We will follow that pattern but safer.
                    $Acl.SetAccessRuleProtection($true, $false) # Disable inheritance, remove inherited rules
                    $Acl.AddAccessRule($AdminRule)
                    $Acl.AddAccessRule($SystemRule)
                    Set-Acl -Path $DSA_Folder -AclObject $Acl
                    Write-Log -Message "Secured NTDS Database Folder: $DSA_Folder" -Level "SUCCESS" -LogFile $LogFile
                }

                # Apply to Logs Folder
                if (Test-Path $Logs_Folder) {
                    $Acl = Get-Acl -Path $Logs_Folder
                    $Acl.SetAccessRuleProtection($true, $false)
                    $Acl.AddAccessRule($AdminRule)
                    $Acl.AddAccessRule($SystemRule)
                    Set-Acl -Path $Logs_Folder -AclObject $Acl
                    Write-Log -Message "Secured NTDS Logs Folder: $Logs_Folder" -Level "SUCCESS" -LogFile $LogFile
                }
            }
        }
    }
    catch {
        Write-Log -Message "Failed to harden NTDS permissions: $_" -Level "ERROR" -LogFile $LogFile
    }

    # --- 4. LDAP Connection Limits ---
    Write-Log -Message "Configuring LDAP Connection Limits (MaxConnIdleTime)..." -Level "INFO" -LogFile $LogFile
    try {
        $DomainDN = (Get-ADDomain).DistinguishedName
        $SearchBase = "CN=Query-Policies,CN=Directory Service,CN=Windows NT,CN=Services,CN=Configuration,$DomainDN"
        $Policies = Get-ADObject -SearchBase $SearchBase -Filter 'ObjectClass -eq "queryPolicy" -and Name -eq "Default Query Policy"' -Properties lDAPAdminLimits
        
        if ($Policies) {
            $AdminLimits = $Policies.lDAPAdminLimits
            $NewLimit = "MaxConnIdleTime=180"
            
            # Remove existing if present
            $AdminLimits = @($AdminLimits) | Where-Object { $_ -notmatch "MaxConnIdleTime=*" }
            # Add new
            $AdminLimits += $NewLimit
            
            Set-ADObject -Identity $Policies -Replace @{lDAPAdminLimits=[string[]]$AdminLimits}
            Write-Log -Message "Set MaxConnIdleTime to 180 seconds." -Level "SUCCESS" -LogFile $LogFile
        }
    } catch {
        Write-Log -Message "Failed to set LDAP limits: $_" -Level "ERROR" -LogFile $LogFile
    }
}

# --- 5. Remote Desktop Services (Ensure Enabled) ---
Write-Log -Message "Ensuring Remote Desktop Services are enabled..." -Level "INFO" -LogFile $LogFile
try {
    # Enable RDP in Registry
    Set-RegistryValue -Path "HKLM:\System\CurrentControlSet\Control\Terminal Server" -Name "fDenyTSConnections" -Value 0 -Type DWord
    Write-Log -Message "RDP Connections allowed in Registry (fDenyTSConnections = 0)." -Level "SUCCESS" -LogFile $LogFile
    
    # Ensure Service is Running
    $termService = Get-Service -Name "TermService" -ErrorAction SilentlyContinue
    if ($termService) {
        if ($termService.StartType -ne 'Automatic') {
            Set-Service -Name "TermService" -StartupType Automatic
            Write-Log -Message "Set TermService startup type to Automatic." -Level "SUCCESS" -LogFile $LogFile
        }
        if ($termService.Status -ne 'Running') {
            Start-Service -Name "TermService"
            Write-Log -Message "Started TermService." -Level "SUCCESS" -LogFile $LogFile
        }
    } else {
        Write-Log -Message "TermService not found." -Level "WARNING" -LogFile $LogFile
    }
} catch {
    Write-Log -Message "Failed to enable Remote Desktop Services: $_" -Level "ERROR" -LogFile $LogFile
}
