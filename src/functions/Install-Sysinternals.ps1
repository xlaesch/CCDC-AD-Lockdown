function Install-Sysinternals {
    param (
        [string]$DestinationPath = "C:\Sysinternals",
        [string]$LogFile
    )

    if (-not (Test-Path $DestinationPath)) {
        New-Item -ItemType Directory -Path $DestinationPath -Force | Out-Null
    }

    # Check if PsExec exists to avoid overwriting in use files or redundant downloads
    if (Test-Path (Join-Path $DestinationPath "PsExec.exe")) {
        if ($LogFile) { Write-Log -Message "Sysinternals (PsExec) already installed at $DestinationPath. Skipping download." -Level "INFO" -LogFile $LogFile }
        return
    }

    $ZipPath = Join-Path $DestinationPath "SysinternalsSuite.zip"
    $Url = "https://download.sysinternals.com/files/SysinternalsSuite.zip"

    try {
        if ($LogFile) { Write-Log -Message "Downloading Sysinternals Suite to $ZipPath..." -Level "INFO" -LogFile $LogFile }
        Invoke-WebRequest -Uri $Url -OutFile $ZipPath -UseBasicParsing
        
        if ($LogFile) { Write-Log -Message "Extracting Sysinternals Suite..." -Level "INFO" -LogFile $LogFile }
        Expand-Archive -Path $ZipPath -DestinationPath $DestinationPath -Force
        
        Remove-Item -Path $ZipPath -Force
        
        # Add to PATH if not present
        $CurrentPath = [Environment]::GetEnvironmentVariable("Path", "Machine")
        if ($CurrentPath -notlike "*$DestinationPath*") {
            [Environment]::SetEnvironmentVariable("Path", "$CurrentPath;$DestinationPath", "Machine")
            if ($LogFile) { Write-Log -Message "Added $DestinationPath to System PATH." -Level "INFO" -LogFile $LogFile }
        }
        
        if ($LogFile) { Write-Log -Message "Sysinternals installed successfully." -Level "INFO" -LogFile $LogFile }
    }
    catch {
        if ($LogFile) { Write-Log -Message "Failed to install Sysinternals: $_" -Level "ERROR" -LogFile $LogFile }
        # Don't throw, just log error so script can continue if needed, or maybe we should stop? 
        # User said "Before any of the scripts start I want it to download sysinternals". 
        # I'll assume it's a prerequisite.
        throw $_
    }
}
