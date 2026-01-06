<#
.SYNOPSIS
    AD Hardening Controller Script
.DESCRIPTION
    Orchestrates the execution of hardening modules for Active Directory environments.
#>

param (
    [string[]]$IncludeModule,
    [switch]$All,
    [Alias("debug")]
    [switch]$DebugMode
)

$ScriptRoot = $PSScriptRoot
$LogDir = "$ScriptRoot/logs"
$LogFile = "$LogDir/hardening_$(Get-Date -Format 'yyyy-MM-dd').log"

# Ensure Log Directory Exists
if (-not (Test-Path $LogDir)) {
    New-Item -ItemType Directory -Path $LogDir -Force | Out-Null
}

# Import Functions
. "$ScriptRoot/src/functions/Write-Log.ps1"
. "$ScriptRoot/src/functions/Set-RegistryValue.ps1"
. "$ScriptRoot/src/functions/New-RandomPassword.ps1"
. "$ScriptRoot/src/functions/Read-ConfirmedPassword.ps1"
. "$ScriptRoot/src/functions/Protect-SecretsFile.ps1"

function Install-Sysinternals {
    param (
        [string]$DestinationPath = "C:\Sysinternals",
        [string]$SourceZipPath = (Join-Path $PSScriptRoot "tools.zip"),
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

    try {
        if (-not (Test-Path $SourceZipPath)) {
            if ($LogFile) { Write-Log -Message "Sysinternals bundle not found at $SourceZipPath. Skipping install." -Level "WARNING" -LogFile $LogFile }
            return
        }

        if ($LogFile) { Write-Log -Message "Extracting Sysinternals bundle from $SourceZipPath..." -Level "INFO" -LogFile $LogFile }
        Expand-Archive -Path $SourceZipPath -DestinationPath $DestinationPath -Force
        if ($LogFile) { Write-Log -Message "Sysinternals bundle extracted successfully." -Level "INFO" -LogFile $LogFile }
    }
    catch {
        if ($LogFile) { Write-Log -Message "Failed to install PSTools: $_" -Level "ERROR" -LogFile $LogFile }
        throw $_
    }
}

function Select-ArrowMenu {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)]
        [string]$Title,
        [Parameter(Mandatory = $true)]
        [string[]]$Options,
        [switch]$MultiSelect,
        [switch]$AllowSelectAll
    )

    if (-not $Options -or $Options.Count -eq 0) {
        return @()
    }

    Write-Host $Title -ForegroundColor Cyan
    for ($i = 0; $i -lt $Options.Count; $i++) {
        Write-Host "[$($i + 1)] $($Options[$i])"
    }

    if ($MultiSelect) {
        $prompt = "Selection (comma-separated numbers"
        if ($AllowSelectAll) {
            $prompt += " or 'all'"
        }
        $prompt += ", 'q' to cancel)"

        while ($true) {
            $selection = Read-Host $prompt
            if ($selection -match '^\s*(q|quit|exit)\s*$') {
                return @()
            }
            if ($AllowSelectAll -and $selection -match '^\s*all\s*$') {
                return $Options
            }

            $indices = $selection -split "[,\\s]+" |
                ForEach-Object { $_.Trim() } |
                Where-Object { $_ -match '^\d+$' } |
                ForEach-Object { [int]$_ - 1 } |
                Where-Object { $_ -ge 0 -and $_ -lt $Options.Count } |
                Sort-Object -Unique

            if ($indices.Count -gt 0) {
                return $indices | ForEach-Object { $Options[$_] }
            }

            Write-Warning "Invalid selection. Enter numbers from 1 to $($Options.Count)."
        }
    }

    $prompt = "Selection (number, 'q' to cancel)"
    while ($true) {
        $selection = Read-Host $prompt
        if ($selection -match '^\s*(q|quit|exit)\s*$') {
            return $null
        }
        if ($selection -match '^\d+$') {
            $index = [int]$selection - 1
            if ($index -ge 0 -and $index -lt $Options.Count) {
                return $Options[$index]
            }
        }

        Write-Warning "Invalid selection. Enter a number from 1 to $($Options.Count)."
    }
}

Write-Log -Message "=== Starting AD Hardening Process ===" -Level "INFO" -LogFile $LogFile

# Extract tool bundles before elevation attempts
$ToolsDir = "$PSScriptRoot/tools"
if (-not (Test-Path $ToolsDir)) {
    New-Item -ItemType Directory -Path $ToolsDir -Force | Out-Null
}

$RootToolsZip = "$PSScriptRoot/tools.zip"
if (Test-Path $RootToolsZip) {
    $MarkerFile = "$ToolsDir/tools.zip.extracted"
    if (-not (Test-Path $MarkerFile)) {
        Write-Log -Message "Extracting tools.zip..." -Level "INFO" -LogFile $LogFile
        try {
            Expand-Archive -Path $RootToolsZip -DestinationPath $ToolsDir -Force
            New-Item -Path $MarkerFile -ItemType File -Force | Out-Null
            Write-Log -Message "Extracted tools.zip to $ToolsDir" -Level "INFO" -LogFile $LogFile
        } catch {
            Write-Log -Message "Failed to extract tools.zip: $_" -Level "ERROR" -LogFile $LogFile
        }
    }
}

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

# Debug mode skips DC validation and Sysinternals download.
if ($DebugMode) {
    Write-Log -Message "Debug mode enabled: skipping DC validation and Sysinternals download." -Level "WARNING" -LogFile $LogFile
} else {
    $isDomainController = (Get-WmiObject -Query "select * from Win32_OperatingSystem where ProductType='2'")
    if (-not $isDomainController) {
        Write-Log -Message "This tool must be run on a Domain Controller. Exiting." -Level "ERROR" -LogFile $LogFile
        exit
    }
}

# Install Sysinternals
$SysinternalsDir = "$PSScriptRoot/tools"
if (-not $DebugMode) {
    try {
        Install-Sysinternals -DestinationPath $SysinternalsDir -LogFile $LogFile
    }
    catch {
        Write-Warning "Sysinternals (PSTools) installation failed. Check logs for details."
    }
}

# Check for SYSTEM privileges and Relaunch if needed
$id = [System.Security.Principal.WindowsIdentity]::GetCurrent()
$p = New-Object System.Security.Principal.WindowsPrincipal($id)
# Use SID for LocalSystem (S-1-5-18) to avoid enum resolution issues
$IsSystem = $p.IsInRole([System.Security.Principal.SecurityIdentifier]"S-1-5-18")

if (-not $IsSystem) {
    if ($DebugMode) {
        Write-Log -Message "Debug mode: skipping SYSTEM elevation." -Level "WARNING" -LogFile $LogFile
    } else {
    Write-Log -Message "Not running as SYSTEM. Attempting to elevate using PsExec..." -Level "INFO" -LogFile $LogFile
    
    $PsExecPath = Join-Path $SysinternalsDir "PsExec.exe"
    if (-not (Test-Path $PsExecPath)) {
         Write-Warning "PsExec not found at $PsExecPath. Cannot elevate."
         exit
    }
    
    # Reconstruct arguments
    $ScriptPath = $PSCommandPath
    $ArgsString = ""
    if ($All) { $ArgsString += " -All" }
    if ($IncludeModule) { 
         $modules = $IncludeModule -join ","
         $ArgsString += " -IncludeModule $modules" 
    }
    if ($DebugMode) { $ArgsString += " -DebugMode" }
    
    # Launch as SYSTEM
    # -i: Interactive (so we can see the menu if needed)
    # -s: System account
    # -accepteula: Accept EULA automatically
    # -w: Working directory
    
    $CmdArgs = "-i -s -accepteula -w `"$PSScriptRoot`" powershell.exe -ExecutionPolicy Bypass -File `"$ScriptPath`"$ArgsString"
    
    Write-Log -Message "Relaunching as SYSTEM: $PsExecPath $CmdArgs" -Level "INFO" -LogFile $LogFile
    
    Start-Process -FilePath $PsExecPath -ArgumentList $CmdArgs -Wait
    
    Write-Log -Message "Child process finished." -Level "INFO" -LogFile $LogFile

    # Cleanup Prompt
    Write-Host "Hardening complete." -ForegroundColor Green
    $response = Read-Host "Do you want to remove the extracted tools directory at $SysinternalsDir? (Y/N)"
    if ($response -eq "Y") {
        if (Test-Path $SysinternalsDir) {
            Remove-Item -Path $SysinternalsDir -Recurse -Force -ErrorAction SilentlyContinue
            Write-Log -Message "Removed tools directory $SysinternalsDir" -Level "INFO" -LogFile $LogFile
        }
        Write-Host "Cleanup complete." -ForegroundColor Green
    }

    Write-Log -Message "Exiting parent process." -Level "INFO" -LogFile $LogFile
    exit
    }
}

Write-Log -Message "Running as SYSTEM. Proceeding with hardening..." -Level "INFO" -LogFile $LogFile

# Define Available Modules
$AvailableModules = @(
    "00_Password_Rotation.ps1",
    "01_Account_Policies.ps1",
    "02_Network_Security.ps1",
    "03_Service_Hardening.ps1",
    "04_Audit_Logging.ps1",
    "05_Cert_Authority.ps1",
    "06_Firewall_Hardening.ps1",
    "07_Backup_Services.ps1",
    "08_Post_Analysis.ps1"
)

$ModulesToExecute = @()

if ($All) {
    $ModulesToExecute = $AvailableModules
}
elseif ($IncludeModule) {
    foreach ($m in $IncludeModule) {
        $match = $AvailableModules | Where-Object { $_ -like "*$m*" }
        if ($match) {
            $ModulesToExecute += $match
        } else {
            Write-Warning "Module '$m' not found."
        }
    }
}
else {
    $ModulesToExecute = Select-ArrowMenu -Title "Select modules to run" -Options $AvailableModules -MultiSelect -AllowSelectAll
}

# Remove duplicates
$ModulesToExecute = $ModulesToExecute | Select-Object -Unique

if ($ModulesToExecute.Count -eq 0) {
    Write-Warning "No modules selected. Exiting."
    exit
}

$SecretsModules = @(
    "00_Password_Rotation.ps1",
    "01_Account_Policies.ps1"
)

if ($ModulesToExecute | Where-Object { $SecretsModules -contains $_ }) {
    $global:SecretsEncryptionDeferred = $true
    $global:SecretsFilePassword = Read-ConfirmedPassword -Prompt "Enter secrets file password" -ConfirmPrompt "Confirm secrets file password"
    Write-Log -Message "Secrets output will be encrypted after module execution." -Level "INFO" -LogFile $LogFile
}

foreach ($Module in $ModulesToExecute) {
    $ModulePath = "$ScriptRoot/src/modules/$Module"
    if (Test-Path $ModulePath) {
        Write-Log -Message "Executing module: $Module" -Level "INFO" -LogFile $LogFile
        try {
            & $ModulePath -LogFile $LogFile
        }
        catch {
            Write-Log -Message "Error executing module $Module : $_" -Level "ERROR" -LogFile $LogFile
        }
    } else {
        Write-Log -Message "Module not found: $Module" -Level "WARNING" -LogFile $LogFile
    }
}

if ($global:SecretsFilePassword -and $global:RotatedPasswordFile) {
    Protect-SecretsFile -FilePath $global:RotatedPasswordFile -Password $global:SecretsFilePassword -LogFile $LogFile
}

Write-Log -Message "=== AD Hardening Process Complete ===" -Level "INFO" -LogFile $LogFile
