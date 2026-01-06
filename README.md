# AD-Lockdown

## TODO
- [x] Lock the secrets file with a password
- [] Understand what installing an enterprise root CA means on an environment with no ADCS

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
- Secrets (password rotations): `secrets/rotated_passwords_YYYY-MM-DD_HH-mm.csv.enc` (AES-256 encrypted; password required)
- Reports: `reports/PingCastle`, `reports/BloodHound`
- Backups: `C:\Program Files\Windows Mail_Backup\DNS`, `C:\Program Files\Windows Mail_Backup\AD`, `C:\Program Files\Windows Mail_Backup\SYSVOL`

## Decrypting secrets
- Decrypt a secrets file: `.\Decrypt-Secrets.ps1 -EncryptedPath secrets\rotated_passwords_YYYY-MM-DD_HH-mm.csv.enc`
- Optional: `-OutputPath` to set destination, `-RemoveEncrypted` to delete the `.enc` after decrypting.

## Control catalog
Status legend: APPLIED, CONDITIONAL, INTERACTIVE, AUDIT-ONLY, SKIPPED.

### 00 Password Rotation (src/modules/00_Password_Rotation.ps1)
| Vulnerability addressed | What the vuln can lead to | The control mitigating it |
| --- | --- | --- |
| Stale or compromised domain user passwords (bulk) | Account takeover, lateral movement | [INTERACTIVE] Rotate all domain user passwords except Domain Admins, Enterprise Admins, and Administrator/krbtgt/Guest/DefaultAccount; write secrets CSV. |
| Stale or compromised passwords on selected accounts | Targeted account takeover | [INTERACTIVE] Rotate selected domain user passwords; write secrets CSV. |
| Password rotation not performed | Compromised credentials persist | [SKIPPED] Operator selects 'Skip password rotation' or cancels selection. |

### 01 Account Policies (src/modules/01_Account_Policies.ps1)
| Vulnerability addressed | What the vuln can lead to | The control mitigating it |
| --- | --- | --- |
| KRBTGT secret compromise (Golden Ticket) | Persistent domain compromise via forged tickets | [APPLIED] Reset KRBTGT twice with random 32 character passwords; record in secrets CSV. |
| DC computer account secret compromise | Ticket forgery or replication abuse | [APPLIED] Rotate DC machine account password with `Reset-ComputerMachinePassword`. |
| Kerberos pre-authentication disabled (AS-REP roasting) | Offline hash cracking | [APPLIED] Enable Kerberos pre-authentication for users with `DoesNotRequirePreAuth`. |
| Guest account enabled | Unauthenticated access | [APPLIED] Disable the Guest account. |
| Excessive MachineAccountQuota (noPac) | Rogue computer creation and privilege escalation | [APPLIED] Set `ms-DS-MachineAccountQuota` to 0. |
| Weak domain password policy | Password guessing and account compromise | [APPLIED] Set default domain password policy (MinLen 15, complexity, lockout, max/min age, history). |
| Administrator password never expires | Stale privileged credential | [CONDITIONAL] Set `PasswordNeverExpires` to false on built-in Administrator (SID ending in -500) if found. |
| Pre-Windows 2000 Compatible Access contains anonymous or everyone | Anonymous AD enumeration | [APPLIED] Remove all members except Authenticated Users; ensure Authenticated Users is present. |
| Account lockouts reduce availability | User/admin lockout and delays | [APPLIED] Unlock all AD user accounts. |
| Incorrect primary group assignments | Privilege anomalies or access issues | [APPLIED] Set primary group to Domain Users for all users and ensure membership. |
| ManagedBy delegation creates hidden admin paths | Unauthorized delegated control | [APPLIED] Clear `ManagedBy` on computers, the domain object, OUs, and groups. |
| Non-DC computers trusted for delegation | Kerberos delegation abuse | [APPLIED] Remove `TrustedForDelegation` from non-DC computer accounts. |
| Rogue computer accounts with no OS value | Persistence or unauthorized machines | [APPLIED] Delete computer accounts missing the `OperatingSystem` attribute. |
| Weak user encryption or delegation settings | Kerberos downgrade or delegation abuse | [SKIPPED] User property hardening enforcing delegation/encryption changes is skipped. |
| SIDHistory abuse | Privilege escalation via historical SIDs | [APPLIED] Clear `SIDHistory` on users and groups. |
| RID hijacking via ResetData | Privilege escalation | [CONDITIONAL] Remove `ResetData` values under `HKLM:\SAM\SAM\Domains\Account\Users` (requires SYSTEM). |
| AdminSDHolder ACL tampering | Protected group compromise | [CONDITIONAL] Reset AdminSDHolder ACL to hardened SDDL on Server 2019/2022; skipped on other OS versions. |
| Console unlock without re-authentication | Session hijacking | [APPLIED] Set `HKLM:\Software\Microsoft\Windows NT\CurrentVersion\Winlogon\ForceUnlockLogon=1`. |
| Accidental deletion of AD objects | Irrecoverable AD data loss | [APPLIED] Enable the AD Recycle Bin. |
| RODC password replication of privileged accounts | Credential exposure | [APPLIED] Clear 'Allowed RODC Password Replication Group' membership. |
| Orphaned SIDs or dangerous OU ACEs | Unauthorized OU control | [APPLIED] Remove orphaned SIDs and dangerous ACEs for Everyone, Authenticated Users, BUILTIN\Users, and Domain Users. |
| Excessive DCSync rights | Credential dumping from directory replication | [SKIPPED] DCSync permission pruning is skipped to avoid breaking replication tooling. |
| Risky AdminSDHolder permissions | Privilege escalation | [AUDIT-ONLY] Log risky AdminSDHolder ACL entries for non-safe principals. |
| Risky domain root permissions | Privilege escalation | [AUDIT-ONLY] Log Domain Root ACL entries with GenericAll or WriteDacl for non-safe principals. |
| Risky ACLs on protected groups | Privilege escalation | [AUDIT-ONLY] Log risky ACL entries on adminCount=1 groups. |
| Stale local admin passwords (LAPS) | Lateral movement using local admin creds | [APPLIED] Trigger Legacy and Windows LAPS resets by clearing expiration attributes. |
| RBCD backdoors | Impersonation and lateral movement | [AUDIT-ONLY] Log objects with `msDS-AllowedToActOnBehalfOfOtherIdentity` and their SDDL. |

### 02 Network Security (src/modules/02_Network_Security.ps1)
| Vulnerability addressed | What the vuln can lead to | The control mitigating it |
| --- | --- | --- |
| SMBv1 enabled | Wormable exploits and remote code execution | [APPLIED] Disable SMBv1 via `Set-SmbServerConfiguration` or registry. |
| SMB compression vulnerabilities | Remote code execution (SMBGhost) | [APPLIED] Set `DisableCompression=1`. |
| SMB signing disabled | MITM or SMB relay | [APPLIED] Set `EnableSecuritySignature=1` on server and workstation. |
| SMB signing not required | MITM or SMB relay risk remains | [INTERACTIVE] Prompt to require SMB signing (Impact: breaks legacy clients). |
| Null session access | Anonymous enumeration and access | [APPLIED] Set `RestrictNullSessAccess=1` and clear `NullSessionPipes` and `NullSessionShares`. |
| Auto-created admin shares | Remote admin abuse | [APPLIED] Set `AutoShareServer=0` and `AutoShareWks=0`. |
| LLMNR poisoning | Credential theft | [APPLIED] Disable LLMNR via `EnableMulticast=0`. |
| NetBIOS over TCP/IP | Name poisoning and spoofing | [APPLIED] Set `NetbiosOptions=2` on all NetBT interfaces. |
| mDNS spoofing | Name poisoning and MITM | [APPLIED] Set `EnableMDNS=0`. |
| Unhardened UNC paths for SYSVOL and NETLOGON | MITM against SYSVOL or NETLOGON access | [INTERACTIVE] Prompt to enable Hardened UNC paths (Impact: GPO processing issues on legacy clients). |
| LDAP client signing disabled | MITM and credential relay | [APPLIED] Set `LDAPClientIntegrity=2`. |
| Weak NTLM compatibility | Downgrade to weaker auth | [APPLIED] Set `LmCompatibilityLevel=3` (relaxed for legacy). |
| Weak Kerberos encryption types | Cipher downgrade | [APPLIED] Set `SupportedEncryptionTypes=2147483644` (AES + RC4). |
| LDAP server signing disabled | MITM and credential relay | [APPLIED] Set `LDAPServerIntegrity=2`. |
| LDAP channel binding not enforced | NTLM relay to LDAP | [INTERACTIVE] Prompt to enforce LDAP channel binding (Impact: breaks legacy LDAP apps). |
| Anonymous LDAP allowed | Directory enumeration | [APPLIED] Set dsHeuristics to disable anonymous LDAP. |
| SIGRed DNS vulnerability | Remote code execution | [APPLIED] Set `TcpReceivePacketSize=0xFF00`. |
| DNS global query block list disabled | WPAD and ISATAP abuse | [APPLIED] Enable global query block list via `dnscmd`. |
| DNS amplification and abuse | Reflection attacks | [CONDITIONAL] Enable DNS response rate limiting if cmdlet exists. |
| DNS cache poisoning (port predictability) | Cache poisoning | [APPLIED] Set DNS socket pool size to 10000. |
| DNS cache poisoning | Cache poisoning | [APPLIED] Set cache locking to 100 percent. |
| Smart name resolution abuse | Name spoofing | [APPLIED] Set `DisableSmartNameResolution=1`. |
| Parallel A/AAAA query races | DNS spoofing | [APPLIED] Set `DisableParallelAandAAAA=1`. |
| DNS recursion open | Abuse as open resolver | [INTERACTIVE] Prompt to disable DNS recursion (Impact: breaks external resolution). |
| Limited DNS visibility | Undetected DNS abuse | [APPLIED] Enable DNS diagnostics logging. |
| DNS cache pollution | Cache poisoning | [APPLIED] Set MaxTtl, MaxNegativeTtl, and PollutionProtection. |
| Insecure dynamic updates or zone transfers | Zone tampering or data exfiltration | [APPLIED] Enforce secure updates and restrict zone transfers per zone. |
| Stale DNS records | Stale records used for spoofing | [APPLIED] Set DNS scavenging interval to 7 days. |
| Insecure DNS server defaults | DNS abuse or misconfiguration | [APPLIED] Apply dnscmd hardening settings (bindsecondaries, bootmethod, disableautoreversezones, disablensrecordsautocreation, enableglobalnamessupport, enableglobalqueryblocklist, globalqueryblocklist isatap wpad, roundrobin, secureresponses, strictfileparsing, writeauthorityns). |
| Malicious DNS ServerLevelPluginDll | Code execution in DNS service | [AUDIT-ONLY] Detect and warn if `ServerLevelPluginDll` is set. |
| Zerologon | Domain takeover | [APPLIED] Set `FullSecureChannelProtection=1`. |
| Vulnerable channel allowlist | Zerologon bypass | [APPLIED] Remove `vulnerablechannelallowlist` if present. |
| Weak Netlogon secure channel | Secure channel tampering | [APPLIED] Set `RequireSignOrSeal=1`, `SealSecureChannel=1`, `SignSecureChannel=1`, `RequireStrongKey=1`. |
| Weak NTLM session security | MITM and weak encryption | [INTERACTIVE] Prompt to enforce NTLMv2+128bit (Impact: breaks legacy NTLM clients). |
| Anonymous SAM enumeration | Information disclosure | [APPLIED] Set `RestrictAnonymousSAM=1` with `RestrictAnonymous=0` and `EveryoneIncludesAnonymous=1` (relaxed for compatibility). |
| Default admin shares | Remote admin abuse | [APPLIED] Set `NoDefaultAdminShares=1`. |
| Stored domain credentials | Pass-the-hash reuse | [APPLIED] Set `DisableDomainCreds=1`. |
| AD DS firewall group disabled | AD services blocked or unmanaged | [APPLIED] Enable firewall group 'Active Directory Domain Services'. |
| DNS inbound blocked | Name resolution failures | [APPLIED] Allow inbound DNS UDP 53 via netsh rule. |
| Broad firewall exposure | Increased attack surface | [APPLIED] Set firewall policy to `blockinbound,blockoutbound` via netsh (script logs it as commented, but command runs). |
| Firewall logging disabled | Reduced visibility | [APPLIED] Enable firewall logging for allowed and blocked traffic. |
| Unnecessary SMB shares | Data exposure | [APPLIED] Remove SMB shares except ADMIN$, C$, IPC$, NETLOGON, SYSVOL. |
| Time skew | Kerberos authentication failures | [APPLIED] Set timezone to UTC and force time resync. |

### 03 Service Hardening (src/modules/03_Service_Hardening.ps1)
| Vulnerability addressed | What the vuln can lead to | The control mitigating it |
| --- | --- | --- |
| Print Spooler enabled | PrintNightmare and remote code execution | [APPLIED] Stop and disable the Print Spooler service. |
| DSRM logon allowed while AD is running | Local bypass using DSRM credentials | [APPLIED] Set `DsrmAdminLogonBehavior=1`. |
| Weak NTDS database/log ACLs | AD database theft or tampering | [APPLIED] Restrict NTDS database and log folders to Administrators and SYSTEM; remove inheritance. |
| Long-lived LDAP admin connections | Resource exhaustion or lingering sessions | [APPLIED] Set `MaxConnIdleTime=180` in Default Query Policy. |
| RDP disabled for admin access | Delayed incident response | [APPLIED] Enable RDP and set TermService to Automatic and running. |

### 04 Audit Logging (src/modules/04_Audit_Logging.ps1)
| Vulnerability addressed | What the vuln can lead to | The control mitigating it |
| --- | --- | --- |
| LSASS access unmonitored | Undetected credential dumping | [APPLIED] Set `LSASS.exe` AuditLevel to 8. |
| LSASS not protected | Credential theft from memory | [APPLIED] Set `RunAsPPL=1`. |
| Legacy audit policy overrides advanced settings | Missing audit coverage | [APPLIED] Set `SCENoApplyLegacyAuditPolicy=1`. |
| Missing Kerberos Authentication Service audits | Undetected ticket requests | [APPLIED] Enable audit for Kerberos Authentication Service (Success and Failure). |
| Missing Kerberos Service Ticket audits | Undetected service ticket abuse | [APPLIED] Enable audit for Kerberos Service Ticket Operations (Success and Failure). |
| Missing Credential Validation audits | Undetected NTLM logons | [APPLIED] Enable audit for Credential Validation (Success and Failure). |
| Missing Computer Account Management audits | Undetected computer account changes | [APPLIED] Enable audit for Computer Account Management (Success and Failure). |
| Missing Security Group Management audits | Undetected group membership changes | [APPLIED] Enable audit for Security Group Management (Success and Failure). |
| Missing User Account Management audits | Undetected user account changes | [APPLIED] Enable audit for User Account Management (Success and Failure). |
| Missing Directory Service Access audits | Undetected AD object access | [APPLIED] Enable audit for Directory Service Access (Success and Failure). |
| Missing Directory Service Changes audits | Undetected AD object changes | [APPLIED] Enable audit for Directory Service Changes (Success and Failure). |
| Missing DPAPI Activity audits | Undetected DPAPI usage | [APPLIED] Enable audit for DPAPI Activity (Success and Failure). |
| Missing Process Creation audits | Undetected process execution | [APPLIED] Enable audit for Process Creation (Success and Failure). |
| Missing Logoff audits | Undetected session activity | [APPLIED] Enable audit for Logoff (Success and Failure). |
| Missing Logon audits | Undetected logon activity | [APPLIED] Enable audit for Logon (Success and Failure). |
| Missing Special Logon audits | Undetected privileged logons | [APPLIED] Enable audit for Special Logon (Success and Failure). |
| Missing Detailed File Share audits | Undetected share access failures | [APPLIED] Enable audit for Detailed File Share (Failure only). |
| Missing Authentication Policy Change audits | Undetected auth policy changes | [APPLIED] Enable audit for Authentication Policy Change (Success and Failure). |
| Missing Audit Policy Change audits | Undetected audit tampering | [APPLIED] Enable audit for Audit Policy Change (Success and Failure). |
| Missing Sensitive Privilege Use audits | Undetected privilege escalation | [APPLIED] Enable audit for Sensitive Privilege Use (Success and Failure). |
| Missing Security System Extension audits | Undetected security extension changes | [APPLIED] Enable audit for Security System Extension (Success and Failure). |
| Missing Security State Change audits | Undetected startup/shutdown or time changes | [APPLIED] Enable audit for Security State Change (Success and Failure). |
| WDigest stores logon credentials | Credential theft from memory | [APPLIED] Set `UseLogonCredential=0` and `Negotiate=0`. |
| Blank password remote logon | Unauthorized access | [APPLIED] Set `LimitBlankPasswordUse=1`. |
| LM hashes stored | Weak credential exposure | [APPLIED] Set `NoLMHash=1`. |
| Missing RID Manager auditing | Undetected RID abuse | [APPLIED] Add failure audit rule for RID Manager$ GenericAll. |
| Missing AdminSDHolder auditing | Undetected ACL tampering on protected objects | [APPLIED] Add failure audit rule for AdminSDHolder GenericAll. |
| Missing Domain Controllers OU auditing | Undetected OU ACL changes | [APPLIED] Add success audit rule for Domain Controllers OU WriteDacl. |
| Insecure GPO permissions | GPO abuse and privilege escalation | [AUDIT-ONLY] Report GPOs where Authenticated Users has permissions beyond GpoRead. |

### 05 Certificate Authority (src/modules/05_Cert_Authority.ps1)
| Vulnerability addressed | What the vuln can lead to | The control mitigating it |
| --- | --- | --- |
| Missing ADCS management tools | Inability to audit or manage CA securely | [CONDITIONAL] Install Adcs-Cert-Authority management tools if missing. |
| Unmanaged or absent internal PKI baseline | Inconsistent certificate issuance | [INTERACTIVE] Prompt to install Enterprise Root CA (Impact: major infrastructure change). |
| Changes requiring NTDS restart | Inconsistent state if restart is required | [INTERACTIVE] Prompt to restart NTDS service (Impact: DC downtime). |
| Misissued or compromised certificates | Impersonation and privilege escalation | [CONDITIONAL] If a CA exists, list issued certificates and prompt for mass revocation. |
| Compromised certificates remain valid | Continued misuse of issued certs | [INTERACTIVE] Revoke all issued certificates and publish a new CRL when confirmed. |
| No CA present | No certificate audit performed | [CONDITIONAL] Certificate auditing is skipped if no CA is found. |

### 06 Firewall Hardening (src/modules/06_Firewall_Hardening.ps1)
| Vulnerability addressed | What the vuln can lead to | The control mitigating it |
| --- | --- | --- |
| DC services exposed to untrusted networks | Unauthorized access to DC ports | [INTERACTIVE] Prompt for trusted subnets and apply them to inbound rules. |
| Uncontrolled ICMP access | Untrusted network probing | [APPLIED] Allow inbound ICMPv4 (Ping) from trusted subnets. |
| RDP exposed to untrusted networks | Brute force or admin compromise | [APPLIED] Allow inbound RDP TCP 3389 from trusted subnets. |
| DNS service exposed to untrusted networks | DNS abuse from untrusted hosts | [APPLIED] Allow inbound DNS UDP 53 from trusted subnets. |
| DNS outbound blocked under default-deny | Name resolution failures | [APPLIED] Allow outbound DNS UDP 53. |
| Kerberos exposed to untrusted networks | Ticket abuse from untrusted hosts | [APPLIED] Allow inbound Kerberos TCP 88 from trusted subnets. |
| Kerberos exposed to untrusted networks | Ticket abuse from untrusted hosts | [APPLIED] Allow inbound Kerberos UDP 88 from trusted subnets. |
| Kerberos outbound blocked under default-deny | Authentication failures | [APPLIED] Allow outbound Kerberos UDP 88 to trusted subnets. |
| LDAP exposed to untrusted networks | Directory abuse from untrusted hosts | [APPLIED] Allow inbound LDAP TCP 389 from trusted subnets. |
| LDAP exposed to untrusted networks | Directory abuse from untrusted hosts | [APPLIED] Allow inbound LDAP UDP 389 from trusted subnets. |
| SMB exposed to untrusted networks | SMB abuse from untrusted hosts | [APPLIED] Allow inbound SMB TCP 445 from trusted subnets. |
| SMB outbound blocked under default-deny | Replication or file access failures | [APPLIED] Allow outbound SMB TCP 445 to trusted subnets. |
| RPC exposed to untrusted networks | RPC abuse from untrusted hosts | [APPLIED] Allow inbound RPC Endpoint Mapper TCP 135 from trusted subnets. |
| RPC outbound blocked under default-deny | AD service failures | [APPLIED] Allow outbound RPC Endpoint Mapper TCP 135 to trusted subnets. |
| Time sync blocked under default-deny | Kerberos time skew | [APPLIED] Allow inbound W32Time UDP 123 from trusted subnets. |
| Legacy NetBIOS blocked under default-deny | Legacy client failures | [APPLIED] Allow inbound NetBIOS Session TCP 139 from trusted subnets. |
| Legacy NetBIOS blocked under default-deny | Legacy client failures | [APPLIED] Allow inbound NetBIOS Datagram UDP 138 from trusted subnets. |
| Global Catalog blocked under default-deny | Domain logon and GC lookup failures | [APPLIED] Allow inbound Global Catalog TCP 3268 from trusted subnets. |
| Global Catalog SSL blocked under default-deny | Secure GC lookup failures | [APPLIED] Allow inbound Global Catalog SSL TCP 3269 from trusted subnets. |
| AD Web Services blocked under default-deny | AD PowerShell and ADAC failures | [APPLIED] Allow inbound AD Web Services TCP 9389 from trusted subnets. |
| Script engine egress | Malware C2 or data exfiltration | [APPLIED] Block outbound `powershell.exe`, `powershell_ise.exe`, `cscript.exe`, `wscript.exe`, `cmd.exe` in System32 and SysWOW64. |

### 07 Backup Services (src/modules/07_Backup_Services.ps1)
| Vulnerability addressed | What the vuln can lead to | The control mitigating it |
| --- | --- | --- |
| No defined backup location | Unreliable backups | [APPLIED] Create `C:\Program Files\Windows Mail_Backup` with DNS and AD subfolders. |
| DNS zone data loss | DNS outage and service failures | [APPLIED] Export primary non-auto zones via `dnscmd /ZoneExport` and copy to backup. |
| AD database loss | Inability to recover AD | [APPLIED] Create AD IFM full backup using `ntdsutil`. |
| SYSVOL policy loss | GPO loss and inconsistent policy | [APPLIED] Back up SYSVOL policies. |
| Backup success not verified | Silent backup failures | [APPLIED] Log total backup size and backup location. |

### 08 Post Analysis (src/modules/08_Post_Analysis.ps1)
| Vulnerability addressed | What the vuln can lead to | The control mitigating it |
| --- | --- | --- |
| ADCS or AD privilege misconfigurations | Certificate-based compromise paths | [CONDITIONAL] Run Locksmith Mode 4 if present; skipped if not found. |
| Vulnerable certificate templates | Privilege escalation via ADCS | [CONDITIONAL] Run `Certify.exe find /vulnerable` if present; skipped if not found. |
| AD security weaknesses not assessed | Undetected misconfigurations | [CONDITIONAL] Run PingCastle healthcheck if present; skipped if not found. |
| Unknown AD attack paths | Undetected lateral movement paths | [CONDITIONAL] Run SharpHound `-c All` if present; skipped if not found. |
| HardenAD baseline not applied | Missing rigorous security baseline | [INTERACTIVE] Prompt to run HardenAD if present (Impact: potential overlap/breakage). |
