# 01_Account_Policies.ps1
# Handles User Passwords, Group Memberships, and Account Controls

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
Write-Log -Message "Starting Account Policies Hardening..." -Level "INFO" -LogFile $LogFile

# Setup Secrets Directory & File
    $SecretsDir = "$PSScriptRoot/../../secrets"
    if (-not (Test-Path $SecretsDir)) { New-Item -ItemType Directory -Path $SecretsDir -Force | Out-Null }
    $PasswordFile = $global:RotatedPasswordFile
    if ([string]::IsNullOrWhiteSpace($PasswordFile)) {
        $PasswordFile = "$SecretsDir/rotated_passwords_$(Get-Date -Format 'yyyy-MM-dd_HH-mm').csv"
    }
    if (-not (Test-Path $PasswordFile)) {
        "SamAccountName,Password" | Out-File -FilePath $PasswordFile -Encoding ASCII
    }
    Write-Log -Message "Passwords will be saved to $PasswordFile" -Level "INFO" -LogFile $LogFile

    # --- 1. KRBTGT Password Reset (Golden Ticket Mitigation) ---
    Write-Log -Message "Resetting KRBTGT password..." -Level "INFO" -LogFile $LogFile
    try {
        # Reset 1
        $newPassword1 = New-RandomPassword -Length 32
        $securePassword1 = ConvertTo-SecureString -String $newPassword1 -AsPlainText -Force
        Set-ADAccountPassword -Identity "krbtgt" -NewPassword $securePassword1 -Reset
        Write-Log -Message "KRBTGT password reset once." -Level "INFO" -LogFile $LogFile
        "krbtgt (Reset 1),$newPassword1" | Out-File -FilePath $PasswordFile -Append -Encoding ASCII
        
        # Reset 2 (Invalidate history)
        $newPassword2 = New-RandomPassword -Length 32
        $securePassword2 = ConvertTo-SecureString -String $newPassword2 -AsPlainText -Force
        Set-ADAccountPassword -Identity "krbtgt" -NewPassword $securePassword2 -Reset
        Write-Log -Message "KRBTGT password reset twice (History invalidated)." -Level "SUCCESS" -LogFile $LogFile
        "krbtgt (Reset 2),$newPassword2" | Out-File -FilePath $PasswordFile -Append -Encoding ASCII
    }
    catch {
        Write-Log -Message "Failed to reset KRBTGT password: $_" -Level "ERROR" -LogFile $LogFile
    }



    # --- 2. Privileged Group Cleanup ---
    Write-Log -Message "Skipping privileged group member cleanup to avoid breaking delegated/admin access." -Level "WARNING" -LogFile $LogFile

    # --- 3. Kerberos Pre-authentication ---
    Write-Log -Message "Enabling Kerberos Pre-authentication..." -Level "INFO" -LogFile $LogFile
    try {
        Get-ADUser -Filter {DoesNotRequirePreAuth -eq $true} | Set-ADAccountControl -DoesNotRequirePreAuth $false
        Write-Log -Message "Kerberos Pre-authentication enabled for applicable users." -Level "SUCCESS" -LogFile $LogFile
    }
    catch {
        Write-Log -Message "Failed to enable Kerberos Pre-authentication: $_" -Level "ERROR" -LogFile $LogFile
    }

    # --- 4. Disable Guest Account ---
    Write-Log -Message "Disabling Guest Account..." -Level "INFO" -LogFile $LogFile
    try {
        $guestAccount = Get-ADUser -Identity "Guest" -ErrorAction Stop
        Disable-ADAccount -Identity $guestAccount.SamAccountName
        Write-Log -Message "Guest account has been disabled." -Level "SUCCESS" -LogFile $LogFile
    }
    catch {
        Write-Log -Message "Failed to disable Guest account." -Level "ERROR" -LogFile $LogFile
    }

    # --- 5. noPac Mitigation (MachineAccountQuota) ---
    Write-Log -Message "Setting ms-DS-MachineAccountQuota to 0..." -Level "INFO" -LogFile $LogFile
    try {
        $domainDN = (Get-ADDomain).DistinguishedName
        Set-ADObject -Identity $domainDN -Replace @{"ms-DS-MachineAccountQuota" = 0 }
        Write-Log -Message "ms-DS-MachineAccountQuota set to 0." -Level "SUCCESS" -LogFile $LogFile
    }
    catch {
        Write-Log -Message "Failed to apply noPac mitigation: $_" -Level "ERROR" -LogFile $LogFile
    }

    # --- 6. Administrator Password Policy & Domain Password Policy ---
    Write-Log -Message "Enforcing Password Policy..." -Level "INFO" -LogFile $LogFile
    try {
        # Set Default Domain Password Policy (Min Length 15, Complexity Enabled, Lockout)
        Set-ADDefaultDomainPasswordPolicy -Identity $env:USERDNSDOMAIN `
            -MinPasswordLength 15 `
            -ComplexityEnabled $true `
            -LockoutDuration "00:30:00" `
            -LockoutObservationWindow "00:30:00" `
            -LockoutThreshold 10 `
            -MaxPasswordAge "365.00:00:00" `
            -MinPasswordAge "1.00:00:00" `
            -PasswordHistoryCount 24 `
            -ErrorAction SilentlyContinue
        Write-Log -Message "Default Domain Password Policy updated (MinLen: 15)." -Level "SUCCESS" -LogFile $LogFile

        $adminUser = $null
        try {
            # Find Administrator by well-known SID (DomainSID-500) to handle renamed accounts
            $domainSid = (Get-ADDomain).DomainSID.Value
            $adminUser = Get-ADUser -Identity "$domainSid-500" -Properties PasswordNeverExpires -ErrorAction Stop
        } catch {
            Write-Log -Message "Could not find built-in Administrator account by SID." -Level "WARNING" -LogFile $LogFile
        }

        if ($adminUser) {
            if ($adminUser.PasswordNeverExpires -eq $true) {
                Set-ADUser -Identity $adminUser -PasswordNeverExpires $false
                Write-Log -Message "PasswordNeverExpires set to false for Administrator ($($adminUser.SamAccountName))." -Level "SUCCESS" -LogFile $LogFile
            } else {
                Write-Log -Message "Administrator ($($adminUser.SamAccountName)) already has PasswordNeverExpires set to false." -Level "INFO" -LogFile $LogFile
            }
        }
    }
    catch {
        Write-Log -Message "Failed to update Password Policy: $_" -Level "ERROR" -LogFile $LogFile
    }

    # --- 6.1 Pre-Windows 2000 Compatible Access Cleanup ---
    Write-Log -Message "Cleaning up 'Pre-Windows 2000 Compatible Access' group..." -Level "INFO" -LogFile $LogFile
    try {
        $pre2000Group = "Pre-Windows 2000 Compatible Access"
        $members = Get-ADGroupMember -Identity $pre2000Group -ErrorAction SilentlyContinue
        foreach ($member in $members) {
            if ($member.SID.Value -ne "S-1-5-11") { # S-1-5-11 is Authenticated Users
                Remove-ADGroupMember -Identity $pre2000Group -Members $member -Confirm:$false -ErrorAction SilentlyContinue
                Write-Log -Message "Removed $($member.Name) from $pre2000Group." -Level "SUCCESS" -LogFile $LogFile
            }
        }
        # Ensure Authenticated Users is present (per recommendation) using SID
        try {
            Add-ADGroupMember -Identity $pre2000Group -Members "S-1-5-11" -ErrorAction Stop
            Write-Log -Message "Verified 'Pre-Windows 2000 Compatible Access' membership." -Level "SUCCESS" -LogFile $LogFile
        } catch {
            # Ignore if already exists
            if ($_ -notmatch "already a member") {
                 Write-Log -Message "Failed to add Authenticated Users to Pre-2000 group: $_" -Level "WARNING" -LogFile $LogFile
            }
        }
    } catch {
        Write-Log -Message "Failed to clean up Pre-Windows 2000 group: $_" -Level "ERROR" -LogFile $LogFile
    }

    # --- 7. Account Cleanup & Hardening (Extended) ---
    Write-Log -Message "Starting Extended Account Cleanup & Hardening..." -Level "INFO" -LogFile $LogFile
    
    # Unlock all accounts
    try {
        Get-ADUser -Filter * | Unlock-ADAccount -ErrorAction SilentlyContinue
        Write-Log -Message "Unlocked all AD accounts." -Level "SUCCESS" -LogFile $LogFile
    } catch {
        Write-Log -Message "Failed to unlock accounts: $_" -Level "ERROR" -LogFile $LogFile
    }

    # Set Primary Group to Domain Users
    try {
        $domainUsersGroup = Get-ADGroup "Domain Users" -Properties primaryGroupToken
        if ($domainUsersGroup) {
            Get-ADUser -Filter * | ForEach-Object {
                try {
                    # Ensure user is a member of Domain Users before setting primary group
                    Add-ADGroupMember -Identity $domainUsersGroup -Members $_ -ErrorAction SilentlyContinue
                    Set-ADUser $_ -Replace @{primaryGroupID=$domainUsersGroup.primaryGroupToken} -ErrorAction Stop
                } catch {
                    Write-Log -Message "Failed to set primary group for $($_.SamAccountName): $_" -Level "WARNING" -LogFile $LogFile
                }
            }
            Write-Log -Message "Set Primary Group to 'Domain Users' for all users." -Level "SUCCESS" -LogFile $LogFile
        }
    } catch {
        Write-Log -Message "Failed to set primary group: $_" -Level "ERROR" -LogFile $LogFile
    }

    # Clear ManagedBy Delegations
    try {
        Get-ADComputer -Filter * | Set-ADComputer -Clear ManagedBy -ErrorAction SilentlyContinue
        Get-ADDomain | Set-ADDomain -Clear ManagedBy -ErrorAction SilentlyContinue
        Get-ADOrganizationalUnit -Filter * | Set-ADOrganizationalUnit -Clear ManagedBy -ErrorAction SilentlyContinue
        Get-ADGroup -Filter * | Set-ADGroup -Clear ManagedBy -ErrorAction SilentlyContinue
        Write-Log -Message "Cleared 'ManagedBy' attribute from all objects." -Level "SUCCESS" -LogFile $LogFile
    } catch {
        Write-Log -Message "Failed to clear ManagedBy: $_" -Level "ERROR" -LogFile $LogFile
    }

    # Reset ACLs on Common Objects (Aggressive)
    Write-Log -Message "Skipping aggressive ACL resets to avoid removing delegated permissions." -Level "WARNING" -LogFile $LogFile

    # Mark non-DC computers as not trusted for delegation
    try {
        $dcs = Get-ADDomainController | Select-Object -ExpandProperty Name
        Get-ADComputer -Filter {TrustedForDelegation -eq $true} | ForEach-Object {
            if ($_.Name -notin $dcs) {
                Set-ADComputer $_ -TrustedForDelegation $false
                Write-Log -Message "Removed TrustedForDelegation from computer: $($_.Name)" -Level "SUCCESS" -LogFile $LogFile
            }
        }
    } catch {
        Write-Log -Message "Failed to check delegation trust: $_" -Level "ERROR" -LogFile $LogFile
    }

    # Delete fake computer accounts (No OS defined)
    try {
        Get-ADComputer -Filter * -Properties OperatingSystem | Where-Object { -not $_.OperatingSystem } | Remove-ADComputer -Confirm:$false -ErrorAction SilentlyContinue
        Write-Log -Message "Deleted computer accounts with no Operating System defined." -Level "SUCCESS" -LogFile $LogFile
    } catch {
        Write-Log -Message "Failed to delete fake computers: $_" -Level "ERROR" -LogFile $LogFile
    }

    # User Property Hardening (AES256, No Delegation, etc.)
    Write-Log -Message "Skipping user property hardening that forces delegation/encryption changes." -Level "WARNING" -LogFile $LogFile

    # Clear SID History & SPNs
    try {
        Get-ADUser -Filter {SIDHistory -like "*"} | Set-ADUser -Clear SIDHistory
        Get-ADGroup -Filter {SIDHistory -like "*"} | Set-ADGroup -Clear SIDHistory
        Write-Log -Message "Cleared SIDHistory from Users and Groups." -Level "SUCCESS" -LogFile $LogFile
    } catch {
        Write-Log -Message "Failed to clear SIDHistory: $_" -Level "ERROR" -LogFile $LogFile
    }

    # Mitigate RID Hijacking (ResetData)
    try {
        $usersKey = "HKLM:\SAM\SAM\Domains\Account\Users"
        if (Test-Path $usersKey -ErrorAction SilentlyContinue) {
            Get-ChildItem $usersKey -ErrorAction Stop | ForEach-Object {
                $name = $_.PSChildName
                if ((Get-ItemProperty -Path "$usersKey\$name" -ErrorAction SilentlyContinue).ResetData) {
                    Remove-ItemProperty -Path "$usersKey\$name" -Name "ResetData" -Force -ErrorAction SilentlyContinue
                }
            }
            Write-Log -Message "Removed ResetData registry keys (RID Hijacking mitigation)." -Level "SUCCESS" -LogFile $LogFile
        }
    } catch {
        Write-Log -Message "Failed to mitigate RID Hijacking (Requires SYSTEM privileges): $_" -Level "WARNING" -LogFile $LogFile
    }

    # --- 10. AdminSDHolder ACL Reset (Hardened SDDL) ---
    Write-Log -Message "Resetting AdminSDHolder ACL to hardened defaults..." -Level "INFO" -LogFile $LogFile
    try {
        $osVersion = (Get-CimInstance Win32_OperatingSystem).Version
        $is2019 = $osVersion -like "10.0.17763*"
        $is2022 = $osVersion -like "10.0.20348*"
        
        # SDDLs from legacy script
        $server19ACL = "O:DAG:DAD:PAI(A;;LCRPLORC;;;AU)(A;;CCDCLCSWRPWPDTLOCRSDRCWDWO;;;SY)(A;;CCDCLCSWRPWPLOCRSDRCWDWO;;;BA)(A;;CCDCLCSWRPWPLOCRRCWDWO;;;DA)(A;;CCDCLCSWRPWPLOCRRCWDWO;;;S-1-5-21-501019241-1888531994-2123242318-519)(OA;;CR;ab721a53-1e2f-11d0-9819-00aa0040529b;;WD)(OA;CI;RPWPCR;91e647de-d96f-4b70-9557-d63ff4f3ccd8;;PS)(OA;;CR;ab721a53-1e2f-11d0-9819-00aa0040529b;;PS)(OA;;RP;4c164200-20c0-11d0-a768-00aa006e0529;bf967aba-0de6-11d0-a285-00aa003049e2;RU)(OA;;RP;5f202010-79a5-11d0-9020-00c04fc2d4cf;bf967aba-0de6-11d0-a285-00aa003049e2;RU)(OA;;LCRPLORC;;bf967aba-0de6-11d0-a285-00aa003049e2;RU)(OA;;RP;bc0ac240-79a9-11d0-9020-00c04fc2d4cf;bf967aba-0de6-11d0-a285-00aa003049e2;RU)(OA;;RP;037088f8-0ae1-11d2-b422-00a0c968f939;bf967aba-0de6-11d0-a285-00aa003049e2;RU)(OA;;RP;037088f8-0ae1-11d2-b422-00a0c968f939;4828cc14-1437-45bc-9b07-ad6f015e5f28;RU)(OA;;RP;59ba2f42-79a2-11d0-9020-00c04fc2d3cf;4828cc14-1437-45bc-9b07-ad6f015e5f28;RU)(OA;;RP;bc0ac240-79a9-11d0-9020-00c04fc2d4cf;4828cc14-1437-45bc-9b07-ad6f015e5f28;RU)(OA;;RP;4c164200-20c0-11d0-a768-00aa006e0529;4828cc14-1437-45bc-9b07-ad6f015e5f28;RU)(OA;;RP;5f202010-79a5-11d0-9020-00c04fc2d4cf;4828cc14-1437-45bc-9b07-ad6f015e5f28;RU)(OA;;LCRPLORC;;4828cc14-1437-45bc-9b07-ad6f015e5f28;RU)(OA;;RP;46a9b11d-60ae-405a-b7e8-ff8a58d456d2;;S-1-5-32-560)(OA;;RPWP;6db69a1c-9422-11d1-aebd-0000f80367c1;;S-1-5-32-561)(OA;;RPWP;5805bc62-bdc9-4428-a5e2-856a0f4c185e;;S-1-5-32-561)(OA;;RPWP;bf967a7f-0de6-11d0-a285-00aa003049e2;;CA)"
        $server22ACL = "O:DAG:DAD:PAI(A;;LCRPLORC;;;AU)(A;;CCDCLCSWRPWPDTLOCRSDRCWDWO;;;SY)(A;;CCDCLCSWRPWPLOCRSDRCWDWO;;;BA)(A;;CCDCLCSWRPWPLOCRRCWDWO;;;DA)(A;;CCDCLCSWRPWPLOCRRCWDWO;;;S-1-5-21-3344319829-3580194437-357835383-519)(OA;;CR;ab721a53-1e2f-11d0-9819-00aa0040529b;;WD)(OA;CI;RPWPCR;91e647de-d96f-4b70-9557-d63ff4f3ccd8;;PS)(OA;;CR;ab721a53-1e2f-11d0-9819-00aa0040529b;;PS)(OA;;RP;4c164200-20c0-11d0-a768-00aa006e0529;bf967aba-0de6-11d0-a285-00aa003049e2;RU)(OA;;RP;5f202010-79a5-11d0-9020-00c04fc2d4cf;bf967aba-0de6-11d0-a285-00aa003049e2;RU)(OA;;LCRPLORC;;bf967aba-0de6-11d0-a285-00aa003049e2;RU)(OA;;RP;bc0ac240-79a9-11d0-9020-00c04fc2d4cf;bf967aba-0de6-11d0-a285-00aa003049e2;RU)(OA;;RP;037088f8-0ae1-11d2-b422-00a0c968f939;bf967aba-0de6-11d0-a285-00aa003049e2;RU)(OA;;RP;037088f8-0ae1-11d2-b422-00a0c968f939;4828cc14-1437-45bc-9b07-ad6f015e5f28;RU)(OA;;RP;59ba2f42-79a2-11d0-9020-00c04fc2d3cf;4828cc14-1437-45bc-9b07-ad6f015e5f28;RU)(OA;;RP;bc0ac240-79a9-11d0-9020-00c04fc2d4cf;4828cc14-1437-45bc-9b07-ad6f015e5f28;RU)(OA;;RP;4c164200-20c0-11d0-a768-00aa006e0529;4828cc14-1437-45bc-9b07-ad6f015e5f28;RU)(OA;;RP;5f202010-79a5-11d0-9020-00c04fc2d4cf;4828cc14-1437-45bc-9b07-ad6f015e5f28;RU)(OA;;LCRPLORC;;4828cc14-1437-45bc-9b07-ad6f015e5f28;RU)(OA;;RP;46a9b11d-60ae-405a-b7e8-ff8a58d456d2;;S-1-5-32-560)(OA;;RPWP;6db69a1c-9422-11d1-aebd-0000f80367c1;;S-1-5-32-561)(OA;;RPWP;5805bc62-bdc9-4428-a5e2-856a0f4c185e;;S-1-5-32-561)(OA;;RPWP;bf967a7f-0de6-11d0-a285-00aa003049e2;;CA)"

        $targetSDDL = $null
        if ($is2019) {
            $targetSDDL = $server19ACL
            Write-Log -Message "Detected Server 2019. Using 2019 SDDL." -Level "INFO" -LogFile $LogFile
        } elseif ($is2022) {
            $targetSDDL = $server22ACL
            Write-Log -Message "Detected Server 2022. Using 2022 SDDL." -Level "INFO" -LogFile $LogFile
        } else {
            Write-Log -Message "OS Version $osVersion not explicitly matched to 2019/2022. Skipping AdminSDHolder SDDL reset to avoid breakage." -Level "WARNING" -LogFile $LogFile
        }

        if ($targetSDDL) {
            $adminSDHolderPath = "AD:CN=AdminSDHolder,CN=System,$((Get-ADRootDSE).rootDomainNamingContext)"
            $acl = Get-Acl -Path $adminSDHolderPath
            $acl.SetSecurityDescriptorSddlForm($targetSDDL)
            Set-Acl -Path $adminSDHolderPath -AclObject $acl
            Write-Log -Message "AdminSDHolder ACL reset to hardened SDDL." -Level "SUCCESS" -LogFile $LogFile
        }
    } catch {
        Write-Log -Message "Failed to reset AdminSDHolder ACL: $_" -Level "ERROR" -LogFile $LogFile
    }

    # --- 11. Require DC Authentication (ForceUnlockLogon) ---
    Write-Log -Message "Configuring ForceUnlockLogon..." -Level "INFO" -LogFile $LogFile
    try {
        Set-RegistryValue -Path "HKLM:\Software\Microsoft\Windows NT\CurrentVersion\Winlogon" -Name "ForceUnlockLogon" -Value 1 -Type DWord
        Write-Log -Message "ForceUnlockLogon set to 1." -Level "SUCCESS" -LogFile $LogFile
    } catch {
        Write-Log -Message "Failed to set ForceUnlockLogon: $_" -Level "ERROR" -LogFile $LogFile
    }

    # --- 12. Enable AD Recycle Bin ---
    Write-Log -Message "Enabling AD Recycle Bin..." -Level "INFO" -LogFile $LogFile
    try {
        Enable-ADOptionalFeature -Identity 'Recycle Bin Feature' -Scope ForestOrConfigurationSet -Target $env:USERDNSDOMAIN -Confirm:$false -ErrorAction SilentlyContinue
        Write-Log -Message "AD Recycle Bin enabled." -Level "SUCCESS" -LogFile $LogFile
    } catch {
        Write-Log -Message "Failed to enable Recycle Bin (or already enabled): $_" -Level "INFO" -LogFile $LogFile
    }

    # --- 13. Protected Users Group (Privileged Accounts) ---
    Write-Log -Message "Skipping Protected Users mass-add to avoid authentication breakage." -Level "WARNING" -LogFile $LogFile

    # --- 14. Clear RODC Allowed Group ---
    Write-Log -Message "Clearing 'Allowed RODC Password Replication Group'..." -Level "INFO" -LogFile $LogFile
    try {
        $rodcGroup = "Allowed RODC Password Replication Group"
        $members = Get-ADGroupMember -Identity $rodcGroup -ErrorAction SilentlyContinue
        if ($members) {
            Remove-ADGroupMember -Identity $rodcGroup -Members $members -Confirm:$false -ErrorAction SilentlyContinue
            Write-Log -Message "Cleared members from '$rodcGroup'." -Level "SUCCESS" -LogFile $LogFile
        }
    } catch {
        Write-Log -Message "Failed to clear RODC group: $_" -Level "ERROR" -LogFile $LogFile
    }

    # --- 15. Cleanup Orphaned SIDs and Dangerous Delegations on OUs ---
    Write-Log -Message "Cleaning up Orphaned SIDs and Dangerous Delegations on OUs..." -Level "INFO" -LogFile $LogFile
    try {
        # Groups to remove dangerous permissions from (Dynamic check)
        $targetGroups = @(
            "Everyone",
            "Authenticated Users",
            "BUILTIN\Users",
            "Domain Users"
        )

        # Dangerous permissions to look for
        $dangerousRights = @(
            "GenericAll",
            "GenericWrite",
            "WriteDacl",
            "WriteOwner",
            "CreateChild",
            "ExtendedRight",
            "WriteProperty"
        )

        $ous = Get-ADOrganizationalUnit -Filter *
        foreach ($ou in $ous) {
            $acl = Get-Acl -Path "AD:\$($ou.DistinguishedName)"
            $needsUpdate = $false
            
            # Create a copy of rules to iterate safely
            $rules = $acl.GetAccessRules($true, $true, [System.Security.Principal.SecurityIdentifier])
            
            foreach ($rule in $rules) {
                # Check for Orphaned SIDs (IdentityReference fails to translate)
                try {
                    $sid = $rule.IdentityReference
                    $obj = $sid.Translate([System.Security.Principal.NTAccount])
                    $identityName = $obj.Value
                } catch {
                    # Translation failed -> Orphaned SID
                    $acl.RemoveAccessRule($rule) | Out-Null
                    $needsUpdate = $true
                    Write-Log -Message "Removed Orphaned SID $($rule.IdentityReference) from $($ou.DistinguishedName)" -Level "SUCCESS" -LogFile $LogFile
                    continue
                }

                # Dynamic Cleanup: Check if Identity matches target groups and has dangerous rights
                $isTargetGroup = $false
                foreach ($group in $targetGroups) {
                    if ($identityName -like "*$group*") {
                        $isTargetGroup = $true
                        break
                    }
                }

                if ($isTargetGroup) {
                    $rights = $rule.ActiveDirectoryRights.ToString()
                    foreach ($danger in $dangerousRights) {
                        if ($rights -match $danger) {
                            $acl.RemoveAccessRule($rule) | Out-Null
                            $needsUpdate = $true
                            Write-Log -Message "Removed dangerous permission '$danger' for '$identityName' on '$($ou.DistinguishedName)'" -Level "SUCCESS" -LogFile $LogFile
                            break
                        }
                    }
                }
            }
            
            if ($needsUpdate) {
                Set-Acl -Path "AD:\$($ou.DistinguishedName)" -AclObject $acl
            }
        }
    } catch {
        Write-Log -Message "Failed to clean delegations: $_" -Level "ERROR" -LogFile $LogFile
    }

    # --- 16. DCSync Attack Mitigation ---
    Write-Log -Message "Skipping DCSync permission pruning to avoid breaking replication tooling." -Level "WARNING" -LogFile $LogFile


