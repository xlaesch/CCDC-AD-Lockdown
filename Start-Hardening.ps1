<#
.SYNOPSIS
    AD Hardening Controller Script
.DESCRIPTION
    Orchestrates the execution of hardening modules for Active Directory environments.
.PARAMETER ConfigFile
    Path to the configuration file (default: conf/defaults.json)
#>

param (
    [string]$ConfigFile = "conf/defaults.json",
    [string[]]$IncludeModule,
    [switch]$All
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
. "$ScriptRoot/src/functions/Install-Sysinternals.ps1"

Write-Log -Message "=== Starting AD Hardening Process ===" -Level "INFO" -LogFile $LogFile

# Install Sysinternals
try {
    Install-Sysinternals -LogFile $LogFile
}
catch {
    Write-Warning "Sysinternals installation failed. Check logs for details."
}

# Check for SYSTEM privileges and Relaunch if needed
$id = [System.Security.Principal.WindowsIdentity]::GetCurrent()
$p = New-Object System.Security.Principal.WindowsPrincipal($id)
# Use SID for LocalSystem (S-1-5-18) to avoid enum resolution issues
$IsSystem = $p.IsInRole([System.Security.Principal.SecurityIdentifier]"S-1-5-18")

if (-not $IsSystem) {
    Write-Log -Message "Not running as SYSTEM. Attempting to elevate using PsExec..." -Level "INFO" -LogFile $LogFile
    
    $PsExecPath = "C:\Sysinternals\PsExec.exe"
    if (-not (Test-Path $PsExecPath)) {
         Write-Warning "PsExec not found at $PsExecPath. Cannot elevate."
         exit
    }
    
    # Reconstruct arguments
    $ScriptPath = $PSCommandPath
    $ArgsString = ""
    if ($ConfigFile -ne "conf/defaults.json") { $ArgsString += " -ConfigFile `"$ConfigFile`"" }
    if ($All) { $ArgsString += " -All" }
    if ($IncludeModule) { 
         $modules = $IncludeModule -join ","
         $ArgsString += " -IncludeModule $modules" 
    }
    
    # Launch as SYSTEM
    # -i: Interactive (so we can see the menu if needed)
    # -s: System account
    # -accepteula: Accept EULA automatically
    # -w: Working directory
    
    $CmdArgs = "-i -s -accepteula -w `"$PSScriptRoot`" powershell.exe -ExecutionPolicy Bypass -File `"$ScriptPath`"$ArgsString"
    
    Write-Log -Message "Relaunching as SYSTEM: $PsExecPath $CmdArgs" -Level "INFO" -LogFile $LogFile
    
    Start-Process -FilePath $PsExecPath -ArgumentList $CmdArgs -Wait
    
    Write-Log -Message "Child process finished. Exiting parent." -Level "INFO" -LogFile $LogFile
    exit
}

Write-Log -Message "Running as SYSTEM. Proceeding with hardening..." -Level "INFO" -LogFile $LogFile

# Define Available Modules
$AvailableModules = @(
    "01_Account_Policies.ps1",
    "02_Network_Security.ps1",
    "03_Service_Hardening.ps1",
    "04_Audit_Logging.ps1",
    "05_Cert_Authority.ps1",
    "06_Firewall_Hardening.ps1"
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
    # Interactive Menu
    Write-Host "Select modules to run (comma-separated numbers, or 'all'):" -ForegroundColor Cyan
    for ($i = 0; $i -lt $AvailableModules.Count; $i++) {
        Write-Host "[$($i+1)] $($AvailableModules[$i])"
    }
    
    $selection = Read-Host "Selection"
    if ($selection -eq "all") {
        $ModulesToExecute = $AvailableModules
    } else {
        $indices = $selection -split ","
        foreach ($index in $indices) {
            if ($index -match "^\d+$" -and [int]$index -le $AvailableModules.Count -and [int]$index -gt 0) {
                $ModulesToExecute += $AvailableModules[[int]$index - 1]
            }
        }
    }
}

# Remove duplicates
$ModulesToExecute = $ModulesToExecute | Select-Object -Unique

if ($ModulesToExecute.Count -eq 0) {
    Write-Warning "No modules selected. Exiting."
    exit
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

Write-Log -Message "=== AD Hardening Process Complete ===" -Level "INFO" -LogFile $LogFile
