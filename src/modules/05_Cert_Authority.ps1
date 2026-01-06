# 05_Cert_Authority.ps1
# Handles Active Directory Certificate Services (ADCS) Hardening

param(
    [string]$LogFile
)

if (-not (Get-Command Write-Log -ErrorAction SilentlyContinue)) {
    . "$PSScriptRoot/../functions/Write-Log.ps1"
}

Write-Log -Message "Starting ADCS Hardening..." -Level "INFO" -LogFile $LogFile

# --- 1. Install/Verify ADCS Tools ---
Write-Log -Message "Verifying ADCS Management Tools..." -Level "INFO" -LogFile $LogFile
try {
    $feature = Get-WindowsFeature -Name Adcs-Cert-Authority
    if (-not $feature.Installed) {
        $installAdcs = Read-Host "ADCS Role is not installed. Do you want to install and harden ADCS? This is required for Locksmith. [y/n]"
        if ($installAdcs -ne 'y') {
            Write-Log -Message "User chose not to install ADCS. Skipping ADCS hardening and Locksmith." -Level "WARNING" -LogFile $LogFile
            $Global:SkipLocksmith = $true
            return
        }

        Write-Log -Message "Installing ADCS Management Tools..." -Level "INFO" -LogFile $LogFile
        Add-WindowsFeature Adcs-Cert-Authority -IncludeManagementTools
        Write-Log -Message "ADCS Management Tools installed." -Level "SUCCESS" -LogFile $LogFile
    } else {
        Write-Log -Message "ADCS Management Tools already installed." -Level "INFO" -LogFile $LogFile
    }
} catch {
    Write-Log -Message "Failed to check/install ADCS tools: $_" -Level "ERROR" -LogFile $LogFile
}

# --- 2. Install Enterprise Root CA (Conditional) ---
# Note: Installing a CA is a major change. We should only do this if explicitly intended or if the role is already present but not configured.
# The legacy script just ran Install-AdcsCertificationAuthority. We will be cautious.
Write-Log -Message "Checking Enterprise Root CA status..." -Level "INFO" -LogFile $LogFile
try {
    # Check if CA is already configured
    $caConfig = Get-Command Get-CertificationAuthority -ErrorAction SilentlyContinue
    if ($caConfig) {
        $cas = Get-CertificationAuthority -ErrorAction SilentlyContinue
        if ($cas) {
             Write-Log -Message "Certification Authority is already configured: $($cas.Name)" -Level "INFO" -LogFile $LogFile
        } else {
            # CA tools installed but no CA configured.
            # The legacy script forced installation. We will log a warning instead of auto-installing a full CA in a hardening script unless the user specifically uncommented it.
            # However, to follow the user's legacy script intent:
            Write-Log -Message "CA Tools installed but no CA found. Attempting to install Enterprise Root CA (per legacy script)..." -Level "WARNING" -LogFile $LogFile
            # Install-AdcsCertificationAuthority -CAtype EnterpriseRootCA -Force
            Write-Host "IMPACT: Installing an Enterprise Root CA is a major infrastructure change. It introduces significant new attack surfaces (ADCS abuse) if not strictly managed." -ForegroundColor Yellow
            $installCA = Read-Host "Do you want to install Enterprise Root CA? [y/n]"
            if ($installCA -eq 'y') {
                Install-AdcsCertificationAuthority -CAtype EnterpriseRootCA -Force
                Write-Log -Message "Enterprise Root CA installed." -Level "SUCCESS" -LogFile $LogFile
            } else {
                Write-Log -Message "Skipped automatic CA installation for safety." -Level "WARNING" -LogFile $LogFile
            }
        }
    }
} catch {
    Write-Log -Message "Error checking CA status: $_" -Level "ERROR" -LogFile $LogFile
}

# --- 3. Restart NTDS (Aggressive!) ---
# The legacy script restarts NTDS. This is very disruptive on a DC.
Write-Host "IMPACT: Restarting NTDS stops all authentication and directory services on this DC temporarily. If this is the only DC, the domain will go offline." -ForegroundColor Yellow
$restartNTDS = Read-Host "Do you want to restart NTDS service? This will cause DC downtime! [y/n]"
if ($restartNTDS -eq 'y') {
    Restart-Service -Name ntds -Force
    Write-Log -Message "NTDS service restarted." -Level "SUCCESS" -LogFile $LogFile
} else {
    Write-Log -Message "Legacy script requested NTDS restart. Skipping for safety to prevent DC downtime." -Level "WARNING" -LogFile $LogFile
}

# --- 4. Audit and Revoke Certificates ---
Write-Log -Message "Auditing Issued Certificates..." -Level "INFO" -LogFile $LogFile

try {
    $ca = Get-CertificationAuthority -ErrorAction SilentlyContinue
    if ($ca) {
        Write-Host "`n--- Issued Certificates on $($ca.Name) ---" -ForegroundColor Cyan
        
        # Fetch and display certificates
        $certs = certutil -view -restrict "Disposition=20" -out "RequestID,RequesterName,CommonName,CertificateTemplate,NotAfter" csv
        $certs | ForEach-Object { 
            # Simple filter to show CSV data rows
            if ($_ -match '^\s*"?\d+"?,') { Write-Host $_ }
        }

        Write-Host "`nWARNING: Revoking certificates will break authentication for services relying on them until new ones are issued." -ForegroundColor Red
        $response = Read-Host "Do you want to REVOKE all these certificates to force re-issuance? (y/n)"
        
        if ($response -eq 'y') {
            Write-Log -Message "User confirmed revocation. Proceeding..." -Level "WARNING" -LogFile $LogFile
            
            # Get just IDs for processing
            $idList = certutil -view -restrict "Disposition=20" -out "RequestID" csv
            
            foreach ($line in $idList) {
                # Match ID in quotes "10" or plain 10
                if ($line -match '^\s*"?(\d+)"?') {
                    $reqId = $matches[1]
                    Write-Log -Message "Revoking Request ID: $reqId" -Level "INFO" -LogFile $LogFile
                    certutil -revoke $reqId
                }
            }
            Write-Log -Message "All issued certificates have been revoked." -Level "SUCCESS" -LogFile $LogFile
            
            Write-Log -Message "Publishing new CRL..." -Level "INFO" -LogFile $LogFile
            certutil -crl
        } else {
            Write-Log -Message "User cancelled certificate revocation." -Level "INFO" -LogFile $LogFile
        }
    } else {
        Write-Log -Message "No Certification Authority found. Skipping audit." -Level "INFO" -LogFile $LogFile
    }
} catch {
    Write-Log -Message "Error during certificate audit: $_" -Level "ERROR" -LogFile $LogFile
}


