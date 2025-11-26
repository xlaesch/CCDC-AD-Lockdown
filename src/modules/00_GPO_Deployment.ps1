# 08_GPO_Deployment.ps1
# Deploy Hardened Group Policy Objects from Legacy GPO Backups

param(
    [string]$LogFile
)

if (-not (Get-Command Write-Log -ErrorAction SilentlyContinue)) {
    . "$PSScriptRoot/../functions/Write-Log.ps1"
}

Write-Log -Message "Starting GPO Deployment..." -Level "INFO" -LogFile $LogFile

# Only run on Domain Controllers
if (-not (Get-WmiObject -Query "select * from Win32_OperatingSystem where ProductType='2'")) {
    Write-Log -Message "Not a Domain Controller. Skipping GPO deployment." -Level "WARNING" -LogFile $LogFile
    return
}

# --- 1. Detect Windows Server Version ---
Write-Log -Message "Detecting Windows Server version..." -Level "INFO" -LogFile $LogFile
try {
    $osInfo = Get-CimInstance Win32_OperatingSystem
    $osVersion = $osInfo.Version
    $osCaption = $osInfo.Caption

    Write-Log -Message "Detected OS: $osCaption (Version: $osVersion)" -Level "INFO" -LogFile $LogFile

    # Map version to GPO folder
    $gpoFolder = $null
    switch -Regex ($osVersion) {
        "^6\.0\."   { $gpoFolder = "Windows Server 2008"; break }  # 2008
        "^6\.1\."   { $gpoFolder = "Windows Server 2008"; break }  # 2008 R2 (use 2008 GPO)
        "^6\.2\."   { $gpoFolder = "Windows Server 2012"; break }  # 2012
        "^6\.3\."   { $gpoFolder = "Windows Server 2012"; break }  # 2012 R2 (use 2012 GPO)
        "^10\.0\.14393\." { $gpoFolder = "Windows Server 2016"; break }  # 2016
        "^10\.0\.17763\." { $gpoFolder = "Windows Server 2019"; break }  # 2019
        "^10\.0\.20348\." { $gpoFolder = "Windows Server 2022"; break }  # 2022
        default {
            Write-Log -Message "Unknown Windows Server version: $osVersion. Attempting to use Windows Server 2022 GPO." -Level "WARNING" -LogFile $LogFile
            $gpoFolder = "Windows Server 2022"
        }
    }

    Write-Log -Message "Selected GPO folder: $gpoFolder" -Level "INFO" -LogFile $LogFile
}
catch {
    Write-Log -Message "Failed to detect OS version: $_" -Level "ERROR" -LogFile $LogFile
    return
}

# --- 2. Locate GPO Backup ---
$scriptRoot = Split-Path -Parent (Split-Path -Parent $PSScriptRoot)
$gpoBackupPath = Join-Path $scriptRoot "legacy\GPO\$gpoFolder"

if (-not (Test-Path $gpoBackupPath)) {
    Write-Log -Message "GPO backup path not found: $gpoBackupPath" -Level "ERROR" -LogFile $LogFile
    return
}

Write-Log -Message "GPO backup path: $gpoBackupPath" -Level "INFO" -LogFile $LogFile

# Find the GPO backup folder (contains GUID)
$gpoBackupFolder = Get-ChildItem -Path $gpoBackupPath -Directory | Where-Object { $_.Name -match '^\{[A-F0-9\-]+\}$' } | Select-Object -First 1

if (-not $gpoBackupFolder) {
    Write-Log -Message "No GPO backup folder found in: $gpoBackupPath" -Level "ERROR" -LogFile $LogFile
    return
}

$gpoBackupId = $gpoBackupFolder.Name
Write-Log -Message "Found GPO Backup ID: $gpoBackupId" -Level "INFO" -LogFile $LogFile

# --- 3. Read GPO Backup Metadata ---
try {
    $backupXmlPath = Join-Path $gpoBackupFolder.FullName "Backup.xml"
    if (-not (Test-Path $backupXmlPath)) {
        Write-Log -Message "Backup.xml not found in GPO backup folder." -Level "ERROR" -LogFile $LogFile
        return
    }

    [xml]$backupXml = Get-Content $backupXmlPath
    $gpoDisplayName = $backupXml.GroupPolicyBackupScheme.GroupPolicyObject.GroupPolicyCoreSettings.DisplayName

    if (-not $gpoDisplayName) {
        Write-Log -Message "Could not determine GPO display name from backup. Using 'CCDC-Hardening-GPO'." -Level "WARNING" -LogFile $LogFile
        $gpoDisplayName = "CCDC-Hardening-GPO"
    }

    Write-Log -Message "GPO Display Name: $gpoDisplayName" -Level "INFO" -LogFile $LogFile
}
catch {
    Write-Log -Message "Failed to read GPO backup metadata: $_" -Level "ERROR" -LogFile $LogFile
    $gpoDisplayName = "CCDC-Hardening-GPO"
}

# --- 4. Import GPO Module ---
try {
    Import-Module GroupPolicy -ErrorAction Stop
    Write-Log -Message "GroupPolicy module loaded." -Level "SUCCESS" -LogFile $LogFile
}
catch {
    Write-Log -Message "Failed to load GroupPolicy module: $_" -Level "ERROR" -LogFile $LogFile
    return
}

# --- 5. Check if GPO Already Exists ---
$existingGpo = $null
try {
    $existingGpo = Get-GPO -Name $gpoDisplayName -ErrorAction SilentlyContinue
    if ($existingGpo) {
        Write-Log -Message "GPO '$gpoDisplayName' already exists. Skipping import." -Level "WARNING" -LogFile $LogFile
        Write-Log -Message "To re-import, manually delete the existing GPO first." -Level "INFO" -LogFile $LogFile
        return
    }
}
catch {
    # GPO doesn't exist, continue
}

# --- 6. Create New GPO ---
Write-Log -Message "Creating new GPO: $gpoDisplayName" -Level "INFO" -LogFile $LogFile
try {
    $newGpo = New-GPO -Name $gpoDisplayName -Comment "Hardening GPO imported from legacy backup - Created $(Get-Date)" -ErrorAction Stop
    Write-Log -Message "GPO created successfully: $($newGpo.Id)" -Level "SUCCESS" -LogFile $LogFile
}
catch {
    Write-Log -Message "Failed to create GPO: $_" -Level "ERROR" -LogFile $LogFile
    return
}

# --- 7. Import Settings from Backup ---
Write-Log -Message "Importing GPO settings from backup..." -Level "INFO" -LogFile $LogFile
try {
    # Import-GPO expects the parent directory containing the GUID folder
    Import-GPO -BackupId $gpoBackupId.Trim('{}') -TargetName $gpoDisplayName -Path $gpoBackupPath -ErrorAction Stop
    Write-Log -Message "GPO settings imported successfully from backup." -Level "SUCCESS" -LogFile $LogFile
}
catch {
    Write-Log -Message "Failed to import GPO settings: $_" -Level "ERROR" -LogFile $LogFile
    Write-Log -Message "Attempting cleanup of created GPO..." -Level "INFO" -LogFile $LogFile
    try {
        Remove-GPO -Name $gpoDisplayName -ErrorAction SilentlyContinue
    }
    catch {
        Write-Log -Message "Failed to cleanup GPO after import failure." -Level "WARNING" -LogFile $LogFile
    }
    return
}

# --- 8. Link GPO to Domain ---
Write-Log -Message "Linking GPO to domain..." -Level "INFO" -LogFile $LogFile
try {
    $domain = Get-ADDomain
    $domainDN = $domain.DistinguishedName

    # Check if link already exists
    $existingLink = Get-GPInheritance -Target $domainDN | Select-Object -ExpandProperty GpoLinks | Where-Object { $_.DisplayName -eq $gpoDisplayName }

    if ($existingLink) {
        Write-Log -Message "GPO is already linked to domain." -Level "INFO" -LogFile $LogFile
    }
    else {
        # Link GPO to domain root with high priority (Order 1)
        New-GPLink -Name $gpoDisplayName -Target $domainDN -LinkEnabled Yes -ErrorAction Stop | Out-Null
        Write-Log -Message "GPO linked to domain: $domainDN" -Level "SUCCESS" -LogFile $LogFile

        # Set link order to highest priority (Order 1)
        try {
            Set-GPLink -Name $gpoDisplayName -Target $domainDN -Order 1 -ErrorAction Stop
            Write-Log -Message "GPO link order set to 1 (highest priority)." -Level "SUCCESS" -LogFile $LogFile
        }
        catch {
            Write-Log -Message "Failed to set GPO link order: $_" -Level "WARNING" -LogFile $LogFile
        }
    }
}
catch {
    Write-Log -Message "Failed to link GPO to domain: $_" -Level "ERROR" -LogFile $LogFile
}

# --- 9. Force Group Policy Update ---
Write-Log -Message "Forcing Group Policy update..." -Level "INFO" -LogFile $LogFile
try {
    gpupdate /force | Out-Null
    Write-Log -Message "Group Policy update initiated." -Level "SUCCESS" -LogFile $LogFile
}
catch {
    Write-Log -Message "Failed to force GP update: $_" -Level "WARNING" -LogFile $LogFile
}

# --- 10. GPO Deployment Summary ---
Write-Log -Message "=== GPO Deployment Summary ===" -Level "INFO" -LogFile $LogFile
Write-Log -Message "GPO Name: $gpoDisplayName" -Level "INFO" -LogFile $LogFile
Write-Log -Message "GPO ID: $($newGpo.Id)" -Level "INFO" -LogFile $LogFile
Write-Log -Message "Source Backup: $gpoFolder" -Level "INFO" -LogFile $LogFile
Write-Log -Message "Linked to: $domainDN" -Level "INFO" -LogFile $LogFile
Write-Log -Message "GPO deployment completed successfully." -Level "SUCCESS" -LogFile $LogFile