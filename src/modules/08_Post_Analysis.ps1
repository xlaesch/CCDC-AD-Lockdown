# 08_Post_Analysis.ps1
# Runs post-hardening analysis tools like PingCastle and BloodHound (SharpHound)

param(
    [string]$LogFile
)

# Import helper functions if running standalone
if (-not (Get-Command Write-Log -ErrorAction SilentlyContinue)) {
    . "$PSScriptRoot/../functions/Write-Log.ps1"
}

Write-Log -Message "Starting Post-Hardening Analysis..." -Level "INFO" -LogFile $LogFile

# --- 0. Unzip Tools ---
$ToolsDir = "$PSScriptRoot/../../tools"
if (Test-Path $ToolsDir) {
    $ZipFiles = Get-ChildItem -Path $ToolsDir -Filter "*.zip"
    foreach ($Zip in $ZipFiles) {
        $MarkerFile = "$($Zip.FullName).extracted"
        if (-not (Test-Path $MarkerFile)) {
            Write-Log -Message "Extracting $($Zip.Name)..." -Level "INFO" -LogFile $LogFile
            try {
                Expand-Archive -Path $Zip.FullName -DestinationPath $ToolsDir -Force
                New-Item -Path $MarkerFile -ItemType File -Force | Out-Null
                Write-Log -Message "Extracted $($Zip.Name) to $ToolsDir" -Level "INFO" -LogFile $LogFile
            } catch {
                Write-Log -Message "Failed to extract $($Zip.Name): $_" -Level "ERROR" -LogFile $LogFile
            }
        }
    }
}

# --- 1. Vulnerable Certificate Check (Certify.exe) ---
$CertifyPath = "$PSScriptRoot/../../tools/certify.exe"
if (-not (Test-Path $CertifyPath)) { $CertifyPath = "$PSScriptRoot/../../tools/Certify/Certify.exe" }

if (Test-Path $CertifyPath) {
    try {
        Write-Log -Message "Found Certify at $CertifyPath. Running check..." -Level "INFO" -LogFile $LogFile
        $output = & $CertifyPath find /vulnerable 2>&1
        Write-Log -Message "Certify Output:`n$output" -Level "INFO" -LogFile $LogFile
        Write-Log -Message "Review the log above for vulnerable certificates." -Level "WARNING" -LogFile $LogFile
    } catch {
        Write-Log -Message "Failed to run Certify.exe: $_" -Level "ERROR" -LogFile $LogFile
    }
} else {
    Write-Log -Message "Certify.exe not found. Skipping vulnerable certificate check." -Level "WARNING" -LogFile $LogFile
}

# --- 2. PingCastle ---
$PingCastlePath = "$PSScriptRoot/../../tools/PingCastle.exe"
# Check if it might be in a subfolder
if (-not (Test-Path $PingCastlePath)) {
    $PingCastlePath = "$PSScriptRoot/../../tools/PingCastle/PingCastle.exe"
}

if (Test-Path $PingCastlePath) {
        Write-Log -Message "Found PingCastle at $PingCastlePath. Running health check..." -Level "INFO" -LogFile $LogFile
    try {
        # Run PingCastle with --healthcheck (default) and --no-prompt
        # Adjust arguments as needed for the specific version/needs
        $ReportDir = "$PSScriptRoot/../../reports/PingCastle"
        if (-not (Test-Path $ReportDir)) { New-Item -ItemType Directory -Path $ReportDir -Force | Out-Null }
        
        # PingCastle usually generates an HTML report in the current directory or specified one
        # We'll run it and capture output
        $proc = Start-Process -FilePath $PingCastlePath -ArgumentList "--healthcheck --server $env:COMPUTERNAME --no-prompt" -PassThru -Wait -WindowStyle Hidden
        
        if ($proc.ExitCode -eq 0) {
            Write-Log -Message "PingCastle execution completed." -Level "INFO" -LogFile $LogFile
            # Move reports if they are generated in the tools dir
            $GeneratedReports = Get-ChildItem -Path (Split-Path $PingCastlePath) -Filter "*.html"
            foreach ($report in $GeneratedReports) {
                Move-Item -Path $report.FullName -Destination $ReportDir -Force
                Write-Log -Message "Report moved to $ReportDir/$($report.Name)" -Level "INFO" -LogFile $LogFile
            }
        } else {
            Write-Log -Message "PingCastle exited with code $($proc.ExitCode)." -Level "WARNING" -LogFile $LogFile
        }
    } catch {
        Write-Log -Message "Failed to run PingCastle: $_" -Level "ERROR" -LogFile $LogFile
    }
} else {
    Write-Log -Message "PingCastle not found. Skipping." -Level "WARNING" -LogFile $LogFile
}

# --- 3. BloodHound (SharpHound) ---
$SharpHoundPath = "$PSScriptRoot/../../tools/SharpHound.exe"
if (-not (Test-Path $SharpHoundPath)) { $SharpHoundPath = "$PSScriptRoot/../../tools/SharpHound/SharpHound.exe" }

if (Test-Path $SharpHoundPath) {
    Write-Log -Message "Found SharpHound at $SharpHoundPath. Running collection..." -Level "INFO" -LogFile $LogFile
    try {
        $ReportDir = "$PSScriptRoot/../../reports/BloodHound"
        if (-not (Test-Path $ReportDir)) { New-Item -ItemType Directory -Path $ReportDir -Force | Out-Null }

        # Run SharpHound
        # -c All : Collection Method All
        # --outputdirectory : Output directory
        $proc = Start-Process -FilePath $SharpHoundPath -ArgumentList "-c All --outputdirectory `"$ReportDir`" --zipfilename BloodHound_Collection" -PassThru -Wait -WindowStyle Hidden
        
        if ($proc.ExitCode -eq 0) {
            Write-Log -Message "SharpHound collection completed. Data saved to $ReportDir" -Level "INFO" -LogFile $LogFile
        } else {
            Write-Log -Message "SharpHound exited with code $($proc.ExitCode)." -Level "WARNING" -LogFile $LogFile
        }
    } catch {
        Write-Log -Message "Failed to run SharpHound: $_" -Level "ERROR" -LogFile $LogFile
    }
} else {
    Write-Log -Message "SharpHound not found. Skipping." -Level "WARNING" -LogFile $LogFile
}

Write-Log -Message "Post-Hardening Analysis Complete." -Level "INFO" -LogFile $LogFile
