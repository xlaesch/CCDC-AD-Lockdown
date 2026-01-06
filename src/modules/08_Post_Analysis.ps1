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

# --- 0. Locksmith ---
if ($Global:SkipLocksmith) {
    Write-Log -Message "Skipping Locksmith as ADCS hardening was skipped." -Level "WARNING" -LogFile $LogFile
} else {
    $LocksmithPath = "$PSScriptRoot/../../tools/Invoke-Locksmith.ps1"
    if (-not (Test-Path $LocksmithPath)) {
        $LocksmithPath = "$PSScriptRoot/../../tools/Locksmith/Invoke-Locksmith.ps1"
    }

    if (Test-Path $LocksmithPath) {
        Write-Log -Message "Found Locksmith at $LocksmithPath. Running in Mode 4..." -Level "INFO" -LogFile $LogFile
        try {
            $output = & $LocksmithPath -Mode 4 2>&1 | Out-String
            Write-Log -Message "Locksmith Output:`n$output" -Level "INFO" -LogFile $LogFile
        } catch {
            Write-Log -Message "Failed to run Locksmith: $_" -Level "ERROR" -LogFile $LogFile
        }
    } else {
        Write-Log -Message "Locksmith not found. Skipping." -Level "WARNING" -LogFile $LogFile
    }
}

# --- 1. Vulnerable Certificate Check (Certify.exe) ---
$CertifyPath = "$PSScriptRoot/../../tools/certify.exe"

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
$PingCastlePath = Join-Path -Path $PSScriptRoot -ChildPath "..\\..\\tools\\PingCastle.exe"

if (Test-Path $PingCastlePath) {
    Write-Log -Message "Found PingCastle at $PingCastlePath. Running health check..." -Level "INFO" -LogFile $LogFile
    try {
        # Run PingCastle with --healthcheck (default)
        # Adjust arguments as needed for the specific version/needs
        $ReportDir = Join-Path -Path $PSScriptRoot -ChildPath "..\\..\\reports\\PingCastle"
        if (-not (Test-Path $ReportDir)) { New-Item -ItemType Directory -Path $ReportDir -Force | Out-Null }
        $ReportDir = (Resolve-Path -Path $ReportDir -ErrorAction Stop).Path

        $PingCastlePath = (Resolve-Path -Path $PingCastlePath -ErrorAction Stop).Path

        $Arguments = @("--healthcheck")
        if (-not [string]::IsNullOrWhiteSpace($env:COMPUTERNAME)) {
            $Arguments += @("--server", $env:COMPUTERNAME)
        }

        # PingCastle usually generates reports in the current directory.
        $OriginalDir = (Get-Location).Path
        Push-Location -Path $ReportDir
        try {
            $Output = & $PingCastlePath @Arguments 2>&1
            $ExitCode = $LASTEXITCODE
        } finally {
            Pop-Location
        }

        if ($ExitCode -eq 0) {
            Write-Log -Message "PingCastle execution completed." -Level "INFO" -LogFile $LogFile
            $ReportExtensions = @(".html", ".htm", ".xml")
            $GeneratedReports = Get-ChildItem -Path $ReportDir -File -ErrorAction SilentlyContinue |
                Where-Object { $ReportExtensions -contains $_.Extension.ToLowerInvariant() }
            if (-not $GeneratedReports) {
                # Fall back to tools dir in case PingCastle writes reports next to the EXE.
                $FallbackDirs = @(
                    (Split-Path -Parent $PingCastlePath),
                    $OriginalDir
                ) | Select-Object -Unique

                foreach ($FallbackDir in $FallbackDirs) {
                    if (-not (Test-Path $FallbackDir)) { continue }
                    $FallbackReports = Get-ChildItem -Path $FallbackDir -File -ErrorAction SilentlyContinue |
                        Where-Object { $ReportExtensions -contains $_.Extension.ToLowerInvariant() }
                    foreach ($report in $FallbackReports) {
                        Move-Item -Path $report.FullName -Destination $ReportDir -Force
                        Write-Log -Message "Report moved to $ReportDir/$($report.Name)" -Level "INFO" -LogFile $LogFile
                    }
                }

                $GeneratedReports = Get-ChildItem -Path $ReportDir -File -ErrorAction SilentlyContinue |
                    Where-Object { $ReportExtensions -contains $_.Extension.ToLowerInvariant() }
            }

            if (-not $GeneratedReports) {
                $OutputText = $Output | Out-String
                if (-not [string]::IsNullOrWhiteSpace($OutputText)) {
                    Write-Log -Message "PingCastle Output:`n$OutputText" -Level "WARNING" -LogFile $LogFile
                }
                Write-Log -Message "PingCastle completed but no reports were found in $ReportDir." -Level "WARNING" -LogFile $LogFile
            }
        } else {
            Write-Log -Message "PingCastle exited with code $ExitCode." -Level "WARNING" -LogFile $LogFile
            $OutputText = $Output | Out-String
            if (-not [string]::IsNullOrWhiteSpace($OutputText)) {
                Write-Log -Message "PingCastle Output:`n$OutputText" -Level "WARNING" -LogFile $LogFile
            }
        }
    } catch {
        Write-Log -Message "Failed to run PingCastle: $_" -Level "ERROR" -LogFile $LogFile
    }
} else {
    Write-Log -Message "PingCastle not found. Skipping." -Level "WARNING" -LogFile $LogFile
}

# --- 3. BloodHound (SharpHound) ---
$SharpHoundPath = "$PSScriptRoot/../../tools/SharpHound.exe"

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

# --- 4. HardenAD ---
$ToolsDir = Join-Path -Path $PSScriptRoot -ChildPath "../../tools"
if (-not (Test-Path $ToolsDir)) {
    New-Item -ItemType Directory -Path $ToolsDir -Force | Out-Null
}

$HardenADDir = Join-Path -Path $ToolsDir -ChildPath "HardenAD"
$HardenADScript = Join-Path -Path $HardenADDir -ChildPath "HardenAD.ps1"

if (-not (Test-Path $HardenADDir)) {
    Write-Log -Message "HardenAD not found in $HardenADDir. Cloning from GitHub..." -Level "INFO" -LogFile $LogFile
    try {
        git clone https://github.com/LoicVeirman/HardenAD.git $HardenADDir 2>&1 | Out-Null
    } catch {
        Write-Log -Message "Git clone failed: $_" -Level "ERROR" -LogFile $LogFile
    }
    
    if (-not (Test-Path $HardenADDir)) {
         Write-Log -Message "Failed to clone HardenAD. Please ensure git is installed and internet is accessible." -Level "ERROR" -LogFile $LogFile
    }
}

if (Test-Path $HardenADScript) {
    Write-Log -Message "HardenAD is available at $HardenADScript. Skipping execution." -Level "INFO" -LogFile $LogFile
} else {
    Write-Log -Message "HardenAD script not found at $HardenADScript." -Level "WARNING" -LogFile $LogFile
}

Write-Log -Message "Post-Hardening Analysis Complete." -Level "INFO" -LogFile $LogFile

