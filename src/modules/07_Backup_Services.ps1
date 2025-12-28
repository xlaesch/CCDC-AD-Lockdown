# 07_Backup_Services.ps1
# DNS and Active Directory Backup Services

param(
    [string]$LogFile
)

if (-not (Get-Command Write-Log -ErrorAction SilentlyContinue)) {
    . "$PSScriptRoot/../functions/Write-Log.ps1"
}

Write-Log -Message "Starting Backup Services..." -Level "INFO" -LogFile $LogFile

# --- 1. Create Backup Directory Structure ---
Write-Log -Message "Creating backup directory structure..." -Level "INFO" -LogFile $LogFile
$backupRoot = "C:\Program Files\Windows Mail_Backup"
try {
    if (-not (Test-Path $backupRoot)) {
        New-Item -Path $backupRoot -ItemType Directory -Force | Out-Null
        Write-Log -Message "Created backup root directory: $backupRoot" -Level "SUCCESS" -LogFile $LogFile
    }

    $dnsBackupPath = "$backupRoot\DNS"
    $adBackupPath = "$backupRoot\AD"

    foreach ($path in @($dnsBackupPath, $adBackupPath)) {
        if (-not (Test-Path $path)) {
            New-Item -Path $path -ItemType Directory -Force | Out-Null
        }
    }
    Write-Log -Message "Backup directories created." -Level "SUCCESS" -LogFile $LogFile
}
catch {
    Write-Log -Message "Failed to create backup directories: $_" -Level "ERROR" -LogFile $LogFile
    return
}

# --- 2. DNS Zone Backup ---
Write-Log -Message "Backing up DNS zones..." -Level "INFO" -LogFile $LogFile
try {
    Import-Module DnsServer -ErrorAction Stop

    $zones = Get-DnsServerZone | Where-Object { -not $_.IsAutoCreated -and $_.ZoneType -eq "Primary" }
    $exportedCount = 0

    foreach ($zone in $zones) {
        try {
            $zoneName = $zone.ZoneName
            $exportFileName = "$zoneName.dns"

            # Export zone using dnscmd
            $exportResult = dnscmd /ZoneExport $zoneName $exportFileName 2>&1

            # Copy from DNS directory to backup location
            $dnsDataPath = "$env:SystemRoot\System32\dns\$exportFileName"
            $backupFilePath = "$dnsBackupPath\$exportFileName"

            if (Test-Path $dnsDataPath) {
                Copy-Item -Path $dnsDataPath -Destination $backupFilePath -Force -ErrorAction Stop
                Write-Log -Message "Exported DNS zone: $zoneName to $backupFilePath" -Level "SUCCESS" -LogFile $LogFile
                $exportedCount++
            }
            else {
                Write-Log -Message "DNS export file not found for zone: $zoneName" -Level "WARNING" -LogFile $LogFile
            }
        }
        catch {
            Write-Log -Message "Failed to export DNS zone $($zone.ZoneName): $_" -Level "WARNING" -LogFile $LogFile
        }
    }

    Write-Log -Message "DNS backup completed. Exported $exportedCount zones." -Level "SUCCESS" -LogFile $LogFile
}
catch {
    Write-Log -Message "Failed to backup DNS zones: $_" -Level "ERROR" -LogFile $LogFile
}

# --- 3. Active Directory Backup (IFM - Install From Media) ---
Write-Log -Message "Creating Active Directory IFM backup..." -Level "INFO" -LogFile $LogFile
try {
    $timestamp = Get-Date -Format "yyyyMMdd_HHmmss"
    $adBackupFullPath = "$adBackupPath\ADBackup_$timestamp"

    New-Item -Path $adBackupFullPath -ItemType Directory -Force | Out-Null

    # Create IFM backup using ntdsutil
    # This creates a full backup that can be used for IFM RODC/DC installation
    $ntdsutilScript = @"
activate instance ntds
ifm
create full `"$adBackupFullPath`"
quit
quit
"@

    Write-Log -Message "Running ntdsutil to create IFM backup (this may take several minutes)..." -Level "INFO" -LogFile $LogFile

    $ntdsutilScript | ntdsutil 2>&1 | Out-Null

    # Verify backup was created
    if (Test-Path "$adBackupFullPath\Active Directory") {
        $backupSize = (Get-ChildItem -Path $adBackupFullPath -Recurse | Measure-Object -Property Length -Sum).Sum / 1MB
        Write-Log -Message "Active Directory IFM backup created successfully at: $adBackupFullPath (Size: $([math]::Round($backupSize, 2)) MB)" -Level "SUCCESS" -LogFile $LogFile
    }
    else {
        Write-Log -Message "AD backup directory structure not found. Backup may have failed." -Level "ERROR" -LogFile $LogFile
    }
}
catch {
    Write-Log -Message "Failed to create AD backup: $_" -Level "ERROR" -LogFile $LogFile
}

# --- 4. SYSVOL Backup (Critical for GPO recovery) ---
Write-Log -Message "Backing up SYSVOL policies..." -Level "INFO" -LogFile $LogFile
try {
    $sysvolBackupPath = "$backupRoot\SYSVOL"
    if (-not (Test-Path $sysvolBackupPath)) {
        New-Item -Path $sysvolBackupPath -ItemType Directory -Force | Out-Null
    }

    $domain = (Get-ADDomain).DNSRoot
    $sysvolSource = "C:\Windows\SYSVOL\sysvol\$domain\Policies"

    if (Test-Path $sysvolSource) {
        $timestamp = Get-Date -Format "yyyyMMdd_HHmmss"
        $sysvolBackupDest = "$sysvolBackupPath\Policies_$timestamp"

        Copy-Item -Path $sysvolSource -Destination $sysvolBackupDest -Recurse -Force -ErrorAction Stop
        Write-Log -Message "SYSVOL Policies backed up to: $sysvolBackupDest" -Level "SUCCESS" -LogFile $LogFile
    }
    else {
        Write-Log -Message "SYSVOL source path not found: $sysvolSource" -Level "WARNING" -LogFile $LogFile
    }
}
catch {
    Write-Log -Message "Failed to backup SYSVOL: $_" -Level "ERROR" -LogFile $LogFile
}

# --- 5. Backup Summary ---
Write-Log -Message "=== Backup Summary ===" -Level "INFO" -LogFile $LogFile
try {
    $totalSize = (Get-ChildItem -Path $backupRoot -Recurse -File | Measure-Object -Property Length -Sum).Sum / 1GB
    Write-Log -Message "Total backup size: $([math]::Round($totalSize, 2)) GB" -Level "INFO" -LogFile $LogFile
    Write-Log -Message "Backup location: $backupRoot" -Level "INFO" -LogFile $LogFile
}
catch {
    Write-Log -Message "Could not calculate backup size." -Level "WARNING" -LogFile $LogFile
}

Write-Log -Message "Backup Services completed." -Level "INFO" -LogFile $LogFile
