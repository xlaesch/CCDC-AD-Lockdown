# AD-Lockdown

## Overview
AD-Lockdown is an Active Directory hardening toolkit intended to run on Windows Domain Controllers. `Start-Hardening.ps1` orchestrates a set of modules that apply security controls, logging all actions to a daily log file.

## Requirements and assumptions
- Must run on a Domain Controller (the controller script exits if not).
- Default run path is to elevate to SYSTEM using Sysinternals PsExec (unless `-DebugMode` is used).
- Modules rely on Windows Server roles and PowerShell modules such as ActiveDirectory, DnsServer, GroupPolicy, and ADCS cmdlets where available.

## Running
- Run all modules: `.\Start-Hardening.ps1 -All`
- Run selected modules: `.\Start-Hardening.ps1 -IncludeModule 02_Network_Security`
- Debug mode: `.\Start-Hardening.ps1 -DebugMode` (skips DC validation, Sysinternals download, and SYSTEM elevation)

## Outputs and artifacts
- Logs: `logs/hardening_YYYY-MM-DD.log`
- Secrets (password rotations): `secrets/rotated_passwords_YYYY-MM-DD_HH-mm.csv`
- Reports: `reports/PingCastle`, `reports/BloodHound`
- Backups: `C:\Program Files\Windows Mail_Backup\DNS`, `C:\Program Files\Windows Mail_Backup\AD`, `C:\Program Files\Windows Mail_Backup\SYSVOL`

## Control catalog
Status legend:
- APPLIED: runs by default when a module executes.
- CONDITIONAL: runs only if a prerequisite is met (tool, feature, or object present).
- INTERACTIVE: requires operator choice or confirmation.
- AUDIT-ONLY: reports findings without modifying configuration.
- SKIPPED: explicitly skipped or commented out in code.

### Execution gates (Start-Hardening.ps1)
- [CONDITIONAL] Extract `tools.zip` to `tools\` on first run.
- [CONDITIONAL] Extract any `*.zip` files found in `tools\` on first run.
- [SKIPPED] DC validation and Sysinternals download are skipped when `-DebugMode` is used.
- [CONDITIONAL] Validate this host is a Domain Controller using Win32_OperatingSystem ProductType=2; exit if not.
- [CONDITIONAL] Install Sysinternals (PsExec) from `tools.zip` to `tools\` if not already present.
- [CONDITIONAL] Relaunch as SYSTEM with PsExec if not already SYSTEM (skipped in DebugMode).
- [INTERACTIVE] Prompt to remove the extracted `tools\` directory after the elevated run completes.
- [INTERACTIVE] Module selection menu when neither `-All` nor `-IncludeModule` is specified.

### 00 Password Rotation (src/modules/00_Password_Rotation.ps1)
- [INTERACTIVE] Choose rotation mode: rotate all domain users, rotate selected users, or skip.
- [CONDITIONAL] Rotate all domain user passwords except members of Domain Admins, Enterprise Admins, and the accounts Administrator, krbtgt, Guest, DefaultAccount; new 16 char passwords saved to `secrets` CSV.
- [CONDITIONAL] Rotate selected domain user passwords; new 16 char passwords saved to `secrets` CSV.
- [SKIPPED] Password rotation is skipped when the operator selects "Skip password rotation" or cancels selection.

### 01 Account Policies (src/modules/01_Account_Policies.ps1)
- [APPLIED] Reset the KRBTGT password twice (random 32 char values) and record in the secrets CSV.
- [APPLIED] Rotate the current DC machine account password using `Reset-ComputerMachinePassword`.
- [APPLIED] Enable Kerberos pre-authentication for users with `DoesNotRequirePreAuth` set.
- [APPLIED] Disable the Guest account.
- [APPLIED] Set `ms-DS-MachineAccountQuota` to 0.
- [APPLIED] Set default domain password policy: MinLen 15, Complexity enabled, LockoutDuration 30m, LockoutObservationWindow 30m, LockoutThreshold 10, MaxAge 365d, MinAge 1d, History 24.
- [CONDITIONAL] Ensure the built-in Administrator account (SID ending in -500) has `PasswordNeverExpires` set to false when found.
- [APPLIED] Clean "Pre-Windows 2000 Compatible Access" membership: remove all members except Authenticated Users and ensure Authenticated Users is present.
- [APPLIED] Unlock all user accounts in AD.
- [APPLIED] Set primary group to Domain Users for all users and ensure membership.
- [APPLIED] Clear the `ManagedBy` attribute on computers, the domain object, OUs, and groups.
- [APPLIED] Remove `TrustedForDelegation` from non-DC computer accounts.
- [APPLIED] Delete computer accounts that have no `OperatingSystem` attribute.
- [SKIPPED] User property hardening that forces delegation and encryption changes is skipped.
- [APPLIED] Clear `SIDHistory` on users and groups.
- [CONDITIONAL] Remove RID hijacking `ResetData` values under `HKLM:\SAM\SAM\Domains\Account\Users` (requires SYSTEM).
- [CONDITIONAL] Reset AdminSDHolder ACL to hardened SDDL for Server 2019 or Server 2022 only; skipped on other OS versions.
- [APPLIED] Set `HKLM:\Software\Microsoft\Windows NT\CurrentVersion\Winlogon\ForceUnlockLogon=1`.
- [APPLIED] Enable the AD Recycle Bin.
- [APPLIED] Clear all members of "Allowed RODC Password Replication Group".
- [APPLIED] Remove orphaned SIDs and dangerous ACEs on OUs for Everyone, Authenticated Users, BUILTIN\Users, and Domain Users with rights GenericAll, GenericWrite, WriteDacl, WriteOwner, CreateChild, ExtendedRight, WriteProperty.
- [SKIPPED] DCSync permission pruning is skipped to avoid breaking replication tooling.
- [AUDIT-ONLY] Review AdminSDHolder permissions for risky rights granted to non-safe principals.
- [AUDIT-ONLY] Review domain root ACL for GenericAll or WriteDacl granted to non-safe principals.
- [AUDIT-ONLY] Review adminCount=1 groups for risky rights granted to non-safe principals.
- [APPLIED] Trigger LAPS password resets by clearing `ms-Mcs-AdmPwdExpirationTime` and `msLAPS-PasswordExpirationTime` on all computers (if attributes exist).
- [AUDIT-ONLY] Audit RBCD backdoors by listing objects with `msDS-AllowedToActOnBehalfOfOtherIdentity` and logging SDDL.

### 02 Network Security (src/modules/02_Network_Security.ps1)
- [APPLIED] Disable SMBv1 via Set-SmbServerConfiguration or `HKLM:\SYSTEM\CurrentControlSet\Services\LanmanServer\Parameters\SMB1=0`.
- [APPLIED] Disable SMB compression: `HKLM:\SYSTEM\CurrentControlSet\Services\LanmanServer\Parameters\DisableCompression=1`.
- [APPLIED] Enable SMB signing (server and workstation): `EnableSecuritySignature=1`.
- [SKIPPED] Require SMB signing is skipped to preserve legacy client compatibility.
- [APPLIED] Restrict null session access: `RestrictNullSessAccess=1`, clear `NullSessionPipes` and `NullSessionShares`.
- [APPLIED] Disable SMB admin shares: `AutoShareServer=0`, `AutoShareWks=0`.
- [APPLIED] Disable LLMNR: `HKLM:\Software\Policies\Microsoft\Windows NT\DNSClient\EnableMulticast=0`.
- [APPLIED] Disable NetBIOS over TCP/IP by setting `NetbiosOptions=2` on all NetBT interfaces.
- [APPLIED] Disable mDNS: `HKLM:\SYSTEM\CurrentControlSet\Services\Dnscache\Parameters\EnableMDNS=0`.
- [SKIPPED] Hardened UNC paths for SYSVOL and NETLOGON are skipped to avoid client compatibility issues.
- [APPLIED] Enforce LDAP client signing: `HKLM:\SYSTEM\CurrentControlSet\Services\LDAP\LDAPClientIntegrity=2`.
- [APPLIED] Set NTLM compatibility level to 3 (send NTLMv2, allow others): `HKLM:\SYSTEM\CurrentControlSet\Control\Lsa\LmCompatibilityLevel=3`.
- [APPLIED] Set Kerberos encryption types to AES128 + AES256 + RC4: `SupportedEncryptionTypes=2147483644`.
- [APPLIED] Enforce LDAP server signing: `HKLM:\System\CurrentControlSet\Services\NTDS\Parameters\LDAPServerIntegrity=2`.
- [SKIPPED] LDAP channel binding enforcement is skipped to avoid breaking legacy LDAP clients.
- [APPLIED] Disable anonymous LDAP by setting dsHeuristics 7th character to 0 on `CN=Directory Service,...`.
- [APPLIED] DNS SIGRed mitigation: `HKLM:\SYSTEM\CurrentControlSet\Services\DNS\Parameters\TcpReceivePacketSize=0xFF00`.
- [APPLIED] Enable DNS global query block list: `dnscmd /config /enableglobalqueryblocklist 1`.
- [CONDITIONAL] Enable DNS Response Rate Limiting if `Set-DnsServerResponseRateLimiting` exists.
- [APPLIED] Set DNS socket pool size to 10000.
- [APPLIED] Set DNS cache locking to 100 percent.
- [APPLIED] Re-apply DNS client hardening: `EnableMulticast=0`, `DisableSmartNameResolution=1`, `DisableParallelAandAAAA=1`.
- [SKIPPED] DNS recursion disable is skipped to avoid resolver outages.
- [APPLIED] Set DNS diagnostics logging: `Set-DnsServerDiagnostics -EventLogLevel 4 -UseSystemEventLog True -EnableLogFileRollover False`.
- [APPLIED] Set DNS cache behavior: MaxTtl 24 days, MaxNegativeTtl 15 minutes, PollutionProtection True.
- [APPLIED] For each primary non-auto zone, set DynamicUpdate Secure and restrict zone transfers to secure servers only.
- [APPLIED] Set DNS scavenging interval to 7 days.
- [APPLIED] Apply additional dnscmd settings: bindsecondaries 0, bootmethod 3, disableautoreversezones 1, disablensrecordsautocreation 1, enableglobalnamessupport 0, enableglobalqueryblocklist 1, globalqueryblocklist isatap wpad, roundrobin 1, secureresponses 1, strictfileparsing 1, writeauthorityns 0.
- [AUDIT-ONLY] Detect `ServerLevelPluginDll` in DNS parameters and warn; removal is commented out.
- [APPLIED] Zerologon mitigation: `FullSecureChannelProtection=1` and remove `vulnerablechannelallowlist` if present.
- [APPLIED] Netlogon secure channel hardening: `RequireSignOrSeal=1`, `SealSecureChannel=1`, `SignSecureChannel=1`, `RequireStrongKey=1`.
- [SKIPPED] NTLM minimum security levels (`NTLMMinClientSec`, `NTLMMinServerSec`) are commented out for compatibility.
- [APPLIED] LSA hardening (relaxed): `RestrictAnonymous=0`, `RestrictAnonymousSAM=1`, `EveryoneIncludesAnonymous=1`.
- [APPLIED] Disable default admin shares: `HKLM:\SYSTEM\CurrentControlSet\Control\Lsa\NoDefaultAdminShares=1`.
- [APPLIED] Disable stored domain credentials: `HKLM:\SYSTEM\CurrentControlSet\Control\Lsa\DisableDomainCreds=1`.
- [APPLIED] Enable Windows Firewall group "Active Directory Domain Services".
- [APPLIED] Allow inbound DNS (UDP 53) via netsh rule.
- [APPLIED] Set firewall policy to `blockinbound,blockoutbound` using `netsh a s allp firewallpolicy` (note the script logs that this is commented out, but the command executes).
- [APPLIED] Enable firewall logging for allowed and blocked traffic to `%SystemRoot%\System32\LogFiles\Firewall\pfirewall.log` with 10000 KB max size.
- [APPLIED] Remove SMB shares except ADMIN$, C$, IPC$, NETLOGON, SYSVOL.
- [APPLIED] Set timezone to UTC and force time resync with `w32tm /resync /force`.

### 03 Service Hardening (src/modules/03_Service_Hardening.ps1)
- [APPLIED] Disable the Print Spooler service (stop and set StartupType Disabled).
- [APPLIED] Set `HKLM:\System\CurrentControlSet\Control\Lsa\DsrmAdminLogonBehavior=1`.
- [APPLIED] Harden NTDS database and log folder ACLs to allow only Builtin Administrators and SYSTEM with inheritance; remove inherited permissions.
- [APPLIED] Set LDAP MaxConnIdleTime to 180 seconds in the Default Query Policy (`lDAPAdminLimits`).
- [APPLIED] Enable RDP: set `HKLM:\System\CurrentControlSet\Control\Terminal Server\fDenyTSConnections=0`, set TermService to Automatic and start if stopped.

### 04 Audit Logging (src/modules/04_Audit_Logging.ps1)
- [APPLIED] Set LSASS AuditLevel to 8 under `HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Image File Execution Options\LSASS.exe`.
- [APPLIED] Enable LSA protection: `HKLM:\SYSTEM\CurrentControlSet\Control\Lsa\RunAsPPL=1`.
- [APPLIED] Force advanced audit policy: `HKLM:\System\CurrentControlSet\Control\Lsa\SCENoApplyLegacyAuditPolicy=1`.
- [APPLIED] Configure audit policy: Kerberos Authentication Service (Success and Failure).
- [APPLIED] Configure audit policy: Kerberos Service Ticket Operations (Success and Failure).
- [APPLIED] Configure audit policy: Credential Validation (Success and Failure).
- [APPLIED] Configure audit policy: Computer Account Management (Success and Failure).
- [APPLIED] Configure audit policy: Security Group Management (Success and Failure).
- [APPLIED] Configure audit policy: User Account Management (Success and Failure).
- [APPLIED] Configure audit policy: Directory Service Access (Success and Failure).
- [APPLIED] Configure audit policy: Directory Service Changes (Success and Failure).
- [APPLIED] Configure audit policy: DPAPI Activity (Success and Failure).
- [APPLIED] Configure audit policy: Process Creation (Success and Failure).
- [APPLIED] Configure audit policy: Logoff (Success and Failure).
- [APPLIED] Configure audit policy: Logon (Success and Failure).
- [APPLIED] Configure audit policy: Special Logon (Success and Failure).
- [APPLIED] Configure audit policy: Detailed File Share (Failure only).
- [APPLIED] Configure audit policy: Authentication Policy Change (Success and Failure).
- [APPLIED] Configure audit policy: Audit Policy Change (Success and Failure).
- [APPLIED] Configure audit policy: Sensitive Privilege Use (Success and Failure).
- [APPLIED] Configure audit policy: Security System Extension (Success and Failure).
- [APPLIED] Configure audit policy: Security State Change (Success and Failure).
- [APPLIED] Disable WDigest credential use: `UseLogonCredential=0`, `Negotiate=0`.
- [APPLIED] Set `LimitBlankPasswordUse=1` and `NoLMHash=1`.
- [APPLIED] Add AD object audit rules: RID Manager$ (Failure GenericAll for Everyone), AdminSDHolder (Failure GenericAll for Everyone), Domain Controllers OU (Success WriteDacl for Everyone).
- [AUDIT-ONLY] Report GPOs where Authenticated Users has permissions beyond GpoRead.

### 05 Certificate Authority (src/modules/05_Cert_Authority.ps1)
- [CONDITIONAL] Install ADCS management tools if the Adcs-Cert-Authority feature is not installed.
- [SKIPPED] Auto-install of Enterprise Root CA is skipped (command is commented out when tools are present but no CA is configured).
- [SKIPPED] NTDS service restart is skipped for safety.
- [CONDITIONAL] If a CA exists, list issued certificates (certutil) and prompt for mass revocation.
- [INTERACTIVE] If operator confirms, revoke all issued certificates and publish a new CRL; otherwise no revocations are performed.
- [CONDITIONAL] If no CA exists, certificate auditing is skipped.

### 06 Firewall Hardening (src/modules/06_Firewall_Hardening.ps1)
- [INTERACTIVE] Prompt for trusted subnets; blank or "any" means allow from any remote address.
- [APPLIED] Allow inbound ICMPv4 (Ping) from trusted subnets.
- [APPLIED] Allow inbound RDP TCP 3389 from trusted subnets.
- [APPLIED] Allow inbound DNS UDP 53 from trusted subnets.
- [APPLIED] Allow outbound DNS UDP 53.
- [APPLIED] Allow inbound Kerberos TCP 88 from trusted subnets.
- [APPLIED] Allow inbound Kerberos UDP 88 from trusted subnets.
- [APPLIED] Allow outbound Kerberos UDP 88 to trusted subnets.
- [APPLIED] Allow inbound LDAP TCP 389 from trusted subnets.
- [APPLIED] Allow inbound LDAP UDP 389 from trusted subnets.
- [APPLIED] Allow inbound SMB TCP 445 from trusted subnets.
- [APPLIED] Allow outbound SMB TCP 445 to trusted subnets.
- [APPLIED] Allow inbound RPC Endpoint Mapper TCP 135 from trusted subnets.
- [APPLIED] Allow outbound RPC Endpoint Mapper TCP 135 to trusted subnets.
- [APPLIED] Allow inbound W32Time UDP 123 from trusted subnets.
- [APPLIED] Allow inbound NetBIOS Session TCP 139 from trusted subnets.
- [APPLIED] Allow inbound NetBIOS Datagram UDP 138 from trusted subnets.
- [APPLIED] Allow inbound Global Catalog TCP 3268 from trusted subnets.
- [APPLIED] Allow inbound Global Catalog SSL TCP 3269 from trusted subnets.
- [APPLIED] Allow inbound AD Web Services TCP 9389 from trusted subnets.
- [APPLIED] Block outbound traffic for script engines from System32 and SysWOW64: powershell.exe, powershell_ise.exe, cscript.exe, wscript.exe, cmd.exe.

### 07 Backup Services (src/modules/07_Backup_Services.ps1)
- [APPLIED] Create backup root directory `C:\Program Files\Windows Mail_Backup` and subfolders DNS and AD.
- [APPLIED] Export primary non-auto DNS zones using `dnscmd /ZoneExport` and copy to `...\DNS`.
- [APPLIED] Create AD IFM full backup using `ntdsutil` into `...\AD\ADBackup_<timestamp>`.
- [APPLIED] Backup SYSVOL policies to `...\SYSVOL\Policies_<timestamp>`.
- [APPLIED] Log total backup size and backup location.

### 08 Post Analysis (src/modules/08_Post_Analysis.ps1)
- [CONDITIONAL] Run Locksmith in Mode 4 if `tools\Invoke-Locksmith.ps1` or `tools\Locksmith\Invoke-Locksmith.ps1` exists.
- [SKIPPED] Locksmith analysis is skipped if the script is not found.
- [CONDITIONAL] Run Certify.exe `find /vulnerable` if `tools\certify.exe` exists.
- [SKIPPED] Vulnerable certificate check is skipped if Certify.exe is not found.
- [CONDITIONAL] Run PingCastle healthcheck if `tools\PingCastle.exe` exists and save reports to `reports\PingCastle`.
- [SKIPPED] PingCastle analysis is skipped if PingCastle.exe is not found.
- [CONDITIONAL] Run SharpHound `-c All` and save output zip to `reports\BloodHound`.
- [SKIPPED] SharpHound collection is skipped if SharpHound.exe is not found.
