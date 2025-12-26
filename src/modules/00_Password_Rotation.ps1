# 00_Password_Rotation.ps1
# Handles manual and bulk domain user password rotation

param(
    [string]$LogFile
)

# Import helper functions if running standalone (optional check)
if (-not (Get-Command Write-Log -ErrorAction SilentlyContinue)) {
    . "$PSScriptRoot/../functions/Write-Log.ps1"
}
if (-not (Get-Command New-RandomPassword -ErrorAction SilentlyContinue)) {
    . "$PSScriptRoot/../functions/New-RandomPassword.ps1"
}
if (-not (Get-Command Select-ArrowMenu -ErrorAction SilentlyContinue)) {
    throw "Select-ArrowMenu is not loaded. Run Start-Hardening.ps1 or load the function before running this module."
}

Write-Log -Message "Starting Password Rotation..." -Level "INFO" -LogFile $LogFile

# Setup Secrets Directory & File
$SecretsDir = "$PSScriptRoot/../../secrets"
if (-not (Test-Path $SecretsDir)) { New-Item -ItemType Directory -Path $SecretsDir -Force | Out-Null }
$PasswordFile = "$SecretsDir/rotated_passwords_$(Get-Date -Format 'yyyy-MM-dd_HH-mm').csv"
if (-not (Test-Path $PasswordFile)) {
    "SamAccountName,Password" | Out-File -FilePath $PasswordFile -Encoding ASCII
}
Write-Log -Message "Passwords will be saved to $PasswordFile" -Level "INFO" -LogFile $LogFile
$global:RotatedPasswordFile = $PasswordFile

$rotationOptions = @(
    "Rotate ALL domain user passwords",
    "Rotate selected domain user accounts",
    "Skip password rotation"
)

$rotationChoice = Select-ArrowMenu -Title "Password rotation options" -Options $rotationOptions
if (-not $rotationChoice) {
    $rotationChoice = "Skip password rotation"
}

switch ($rotationChoice) {
    "Rotate ALL domain user passwords" {
        Write-Log -Message "Rotating Domain User Passwords..." -Level "INFO" -LogFile $LogFile
        try {
            Import-Module ActiveDirectory -ErrorAction Stop
            
            $excludedGroups = @("Domain Admins", "Enterprise Admins")
            $excludedUsers = foreach ($group in $excludedGroups) {
                Get-ADGroupMember -Identity $group -Recursive | Select-Object -ExpandProperty SamAccountName
            }
            $excludedUsers = $excludedUsers | Select-Object -Unique
            $excludedUsers += @("Administrator", "krbtgt", "Guest", "DefaultAccount")
            
            $users = Get-ADUser -Filter * | Where-Object {
                ($_.SamAccountName -notin $excludedUsers)
            }

            $GroupUserMap = @{}

            foreach ($user in $users) {
                try {
                    $newPassword    = New-RandomPassword -Length 16
                    $securePassword = ConvertTo-SecureString -String $newPassword -AsPlainText -Force
                    Set-ADAccountPassword -Identity $user.SamAccountName -NewPassword $securePassword -Reset
                    
                    Write-Log -Message "Password changed for user: $($user.SamAccountName)" -Level "SUCCESS" -LogFile $LogFile
                    Write-Host "$($user.SamAccountName),$newPassword" # Output for operator visibility
                    "$($user.SamAccountName),$newPassword" | Out-File -FilePath $PasswordFile -Append -Encoding ASCII
                    
                    # Track group membership for reporting
                    $usersgroups = Get-ADPrincipalGroupMembership -Identity $user | Select-Object -ExpandProperty Name
                    if ($usersgroups) {
                        foreach ($groupName in $usersgroups) {
                            if(!($GroupUserMap.ContainsKey($groupName))) {
                                $GroupUserMap[$groupName] = New-Object System.Collections.ArrayList
                            }
                            $null = $GroupUserMap[$groupName].Add([PSCustomObject]@{
                                User     = $user.SamAccountName
                                Password = $newPassword
                            })
                        }
                    }
                } 
                catch {
                    Write-Log -Message "Failed to set password for user $($user.SamAccountName): $_" -Level "ERROR" -LogFile $LogFile
                }
            }
        }
        catch {
            Write-Log -Message "Failed to load ActiveDirectory module or query users: $_" -Level "ERROR" -LogFile $LogFile
        }
    }
    "Rotate selected domain user accounts" {
        Write-Log -Message "Rotating Selected Domain User Passwords..." -Level "INFO" -LogFile $LogFile
        try {
            Import-Module ActiveDirectory -ErrorAction Stop

            $userList = Get-ADUser -Filter * | Sort-Object SamAccountName
            if (-not $userList) {
                Write-Log -Message "No domain users found for selected-account rotation." -Level "WARNING" -LogFile $LogFile
            } else {
                $userOptions = $userList | ForEach-Object { $_.SamAccountName }
                $selectedUsers = Select-ArrowMenu -Title "Select accounts to rotate" -Options $userOptions -MultiSelect -AllowSelectAll

                if (-not $selectedUsers -or $selectedUsers.Count -eq 0) {
                    Write-Log -Message "No users selected for password rotation." -Level "WARNING" -LogFile $LogFile
                } else {
                    foreach ($samAccountName in $selectedUsers) {
                        try {
                            $newPassword    = New-RandomPassword -Length 16
                            $securePassword = ConvertTo-SecureString -String $newPassword -AsPlainText -Force
                            Set-ADAccountPassword -Identity $samAccountName -NewPassword $securePassword -Reset

                            Write-Log -Message "Password changed for user: $samAccountName" -Level "SUCCESS" -LogFile $LogFile
                            Write-Host "$samAccountName,$newPassword"
                            "$samAccountName,$newPassword" | Out-File -FilePath $PasswordFile -Append -Encoding ASCII
                        } catch {
                            Write-Log -Message "Failed to set password for user $($samAccountName): $_" -Level "ERROR" -LogFile $LogFile
                        }
                    }
                }
            }
        }
        catch {
            Write-Log -Message "Failed to load ActiveDirectory module or query users for selected rotation: $_" -Level "ERROR" -LogFile $LogFile
        }
    }
    default {
        Write-Log -Message "Skipping domain user password rotation per user request." -Level "INFO" -LogFile $LogFile
    }
}
