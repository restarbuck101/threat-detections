# 🔨 BlueHammer — Windows Zero-Day LPE

![Status](https://img.shields.io/badge/Patch%20Status-UNPATCHED-critical?style=flat-square)
![CVE](https://img.shields.io/badge/CVE-Not%20Assigned-red?style=flat-square)
![Platform](https://img.shields.io/badge/Platform-Microsoft%20Sentinel%20%2B%20MDE-0078D4?style=flat-square&logo=microsoft)
![ATT&CK](https://img.shields.io/badge/MITRE%20ATT%26CK-T1003.002%20%7C%20T1068%20%7C%20T1098%20%7C%20T1543.003-orange?style=flat-square)
![Rules](https://img.shields.io/badge/Detection%20Rules-9-brightgreen?style=flat-square)
![Hunt Queries](https://img.shields.io/badge/Hunt%20Queries-8-blue?style=flat-square)

> Standard user → `NT AUTHORITY\SYSTEM` in under 60 seconds. No kernel exploit. No memory corruption. No admin rights to start.

> [!CAUTION]
> BlueHammer is **unpatched as of April 2026**. Microsoft's Defender signature (`Exploit:Win32/DfndrPEBluHmr.BB`) detects the original compiled binary only — a recompiled variant bypasses it entirely. **Behavioral detection is the primary protection layer until a patch ships.**

---

## 📖 Companion Research

This folder covers the **blue team response for Microsoft Sentinel and Azure-connected environments** — threat hunting with KQL, production-validated detection rules, FP baselines, and deployment guidance for Sentinel + Defender for Endpoint.

**[technoherder/BlueHammerFix](https://github.com/technoherder/BlueHammerFix)** is essential reading alongside this content. Their repo covers the red team and static analysis side of BlueHammer in depth — if you want to understand how the exploit actually works before you defend against it, start there:

- Full static analysis of the exploit chain (7 stages, ~3,450 lines of source)
- 9 bug fixes to the original PoC including a `--force` flag for lab testing
- Lab validation of Stages 1-5
- 7 Sigma detection rules (vendor-agnostic, convertible to any SIEM)
- 4 YARA rules for static and variant detection
- Executive summary and full technical report
- IoC observation guide for lab testing

> [!NOTE]
> If your environment runs **Splunk, Elastic, or another SIEM**, their Sigma rules are where you want to start — they convert directly via sigma-cli or pySigma. This repo is purpose-built for **Sentinel**.

The KQL rules marked **[credit: technoherder]** in the detection table below are Sentinel adaptations of their Sigma rules, back-tested against production telemetry and documented with FP guidance. All original detection concepts are theirs.

<details>
<summary><strong>What you'll find here that you won't find in the Sigma rules</strong></summary>
<br>

Sigma rules are intentionally platform-agnostic — they define the detection logic without addressing the environment-specific issues that come up when you actually deploy them. This repo fills that gap for Microsoft Sentinel specifically.

**Back-test results.** Every original rule was run against 7-30 days of live production telemetry before release. Result counts, FP rates, and time windows are documented in each YAML. This tells you what the rule actually does in a real environment, not just what it's designed to do.

**A documented FP register.** Back-testing against production data surfaces patterns the rule designer couldn't anticipate. What was found and handled here: `EventData` JSON fields that include surrounding quote characters (breaking regex silently), `TargetDomainName` vs FQDN mismatch (making Rule 2 non-functional in many environments without a fix), shared admin account patterns, hardware driver installers dropping kernel drivers from Temp paths, and enterprise software in non-standard install locations. All of it is named, explained, and scoped in the `false_positive_guidance` field of each rule.

**Sentinel-native KQL.** Sigma rules need to be converted to Sentinel KQL via sigma-cli or pySigma before you can use them. The rules here are ready to paste into Sentinel analytics. Environment-specific quirks — EventData key names, FQDN handling, table availability checks — are already handled.

**A composite correlation rule.** Rather than five separate alerts the SOC has to mentally stitch together, a sixth rule fires a single Critical alert when two or more individual indicators appear on the same host within 30 minutes.

**Hunt queries before detections.** Eight production-ready KQL hunt queries with confidence tiers and triage guidance, designed to run against live telemetry before any detection is deployed. If the environment is already compromised, you find out during the hunt rather than after the detection fires.

**A deployment checklist.** Table availability validation, FQDN behavior check, EventData structure confirmation, and tuning guidance for rules that need environment-specific exclusion lists.

</details>

---

## 🔬 The Vulnerability

BlueHammer chains four legitimate, documented Windows components. Each works exactly as designed — the vulnerability only exists when they are chained in the right sequence.

| Component | Role in Exploit |
|---|---|
| **Microsoft Defender Update Workflow** | Creates a privileged VSS snapshot during remediation |
| **Volume Shadow Copy Service (VSS)** | Mounts a snapshot exposing the normally locked SAM, SYSTEM, SECURITY registry hives |
| **Cloud Files API (`cldapi.dll`)** | `CfRegisterSyncRoot` callback identifies the Defender process by PID via `CF_CONNECT_FLAG_REQUIRE_PROCESS_INFO` and freezes it selectively |
| **Opportunistic Locks (Oplocks)** | Freezes Defender at exactly the right moment, holding the snapshot open |

> The Cloud Files API abuse is the most novel technique in this exploit. Using `CfRegisterSyncRoot` to identify and selectively freeze a specific process by PID is creative and currently undermonitored across the industry. This primitive could be reused against any process that enumerates directories. — *technoherder/BlueHammerFix*

---

## ⛓️ Kill Chain

| Step | Technique | Action | Detection |
|---|---|---|---|
| 1 | T1082 / T1068 | Enumerate `\Device\HarddiskVolumeShadowCopy*` polling for Defender update snapshot | `win_security_vss_shadow_copy_enumeration_user_space` |
| 2 | T1068 / T1562.001 | Exclusive oplock on `RstrtMgr.dll` to freeze Defender mid-remediation | ⚠️ Sysmon required |
| 3 | T1068 | Register Cloud Files sync root. Identify Defender by PID. Freeze via oplock on `.lock` file. | `win_security_cloud_files_sync_root_untrusted_process` |
| 4 | T1068 / T1574.005 | RPC to `IMpService`. NTFS junction → `\BaseNamedObjects\Restricted`. Symlink redirects read to SAM via VSS. | ⚠️ Pipe events required |
| 5 | T1003.002 / T1005 | Read SAM/SYSTEM/SECURITY from VSS. Read LSA boot key (JD/Skew1/GBG/Data). Decrypt NTLM hashes. | `win_security_vss_registry_hive_shadow_copy_access` `win_security_lsa_bootkey_registry_access_non_lsass` |
| 6 | T1003.002 / T1552.002 | Reconstruct SYSKEY. Load `samlib.dll`. Call `SamiChangePasswordUser`. | `win_security_samlib_load_non_lsass_process` |
| 7 | T1098 / T1134.001 | Reset local admin password. Authenticate. Duplicate SYSTEM token. Restore original hash. | `win_security_local_admin_password_rapid_change_restore` |
| 8 | T1543.003 / T1569.002 | Create GUID-named temp service. Spawn `conhost.exe` as SYSTEM. Delete service. | `win_security_guid_named_transient_service_creation` `win_security_service_install_non_standard_path` |
| 🔗 | Multi | 2+ indicators on same host within 30 min | `win_security_bluehammer_kill_chain_correlation` |

---

## 🛡️ Detection Rules

> [!IMPORTANT]
> Deploy individual rules (Priority 1–4) **before** the composite correlation rule (Priority 5\*). The composite queries `SecurityAlert` which is only populated once individual rules are generating alerts.

| Pri | Rule | Severity | Back-test | Source |
|---|---|---|---|---|
| 1 | `win_security_vss_registry_hive_shadow_copy_access` | 🔴 Critical | ✅ 30d | Original |
| 1 | `win_security_local_admin_password_rapid_change_restore` | 🔴 Critical | ✅ 7d | Original |
| 2 | `win_security_lsa_bootkey_registry_access_non_lsass` | 🔴 Critical | ⬜ Pending | [credit: technoherder] |
| 2 | `win_security_service_install_non_standard_path` | 🟠 High | ✅ 7d — env tuning required | Original |
| 2 | `win_security_samlib_load_non_lsass_process` | 🟠 High | ⬜ Pending | [credit: technoherder] |
| 2 | `win_security_guid_named_transient_service_creation` | 🟠 High | ⬜ Pending | [credit: technoherder] |
| 3 | `win_security_cloud_files_sync_root_untrusted_process` | 🟠 High | ✅ 7d | Original |
| 4 | `win_security_vss_shadow_copy_enumeration_user_space` | 🟠 High | ✅ 7d | Original |
| 5* | `win_security_bluehammer_kill_chain_correlation` | 🔴 Critical | N/A | Original |

<details>
<summary><strong>Rules requiring Sysmon or advanced EDR telemetry</strong></summary>
<br>

The following detection concepts from [technoherder/BlueHammerFix](https://github.com/technoherder/BlueHammerFix) require telemetry not available in standard Sentinel + MDE. If your environment has Sysmon deployed, use their Sigma rules directly.

| Sigma Rule | What It Catches | Telemetry Required |
|---|---|---|
| `bluehammer_oplock_rstrtmgr.yml` | Exclusive oplock on `RstrtMgr.dll` (Step 2) | `FSCTL_REQUEST_BATCH_OPLOCK` — Sysmon or kernel-level EDR |
| `bluehammer_junction_basenamed.yml` | NTFS junction to `\BaseNamedObjects\Restricted` (Step 4) | Reparse point events — minifilter driver or advanced EDR |
| `bluehammer_defender_rpc_call.yml` | Non-Defender RPC to `IMpService` endpoint | Named pipe events — Sysmon EventID 18 or ETW RPC tracing |

</details>

---

## 🔍 Threat Hunt

> [!WARNING]
> Run these queries against your environment **before deploying any detections**. A hit on Hunt 1 or 2 is an immediate IR escalation — not a detection project.

| Hunt | Indicator | Platform | Confidence |
|---|---|---|---|
| 1 | SAM/SYSTEM/SECURITY access via VSS path | Advanced Hunting | 🔴 Critical |
| 2 | Rapid admin password change + restore | Sentinel SecurityEvent | 🔴 Critical |
| 3 | VSS enumeration from user-space | Advanced Hunting | 🟠 High |
| 4 | `cldapi.dll` loaded by non-sync process | Advanced Hunting | 🟠 High |
| 5 | Transient service from non-standard path | Sentinel SecurityEvent | 🟠 High |
| 6 | SYSTEM shell spawned from services.exe | Advanced Hunting | 🟠 High |
| 7 | Defender update + VSS enumeration same window | Advanced Hunting | 🟡 Medium |
| 8 | Broad SYSTEM shell from non-SYSTEM parent | Advanced Hunting | 🟡 Medium |

<details>
<summary><strong>Hunt 1 — SAM/SYSTEM/SECURITY Access via VSS (Advanced Hunting)</strong></summary>

```kql
DeviceFileEvents
| where Timestamp > ago(30d)
| where FolderPath has "HarddiskVolumeShadowCopy"
| where FolderPath has_any ("\\Config\\SAM", "\\Config\\SYSTEM", "\\Config\\SECURITY")
| where InitiatingProcessAccountSid != "S-1-5-18"
| where InitiatingProcessAccountName !endswith "$"
| where isnotempty(InitiatingProcessAccountName)
| project Timestamp, DeviceName, InitiatingProcessAccountName,
    InitiatingProcessFileName, InitiatingProcessCommandLine,
    FolderPath, FileName, ActionType
```
</details>

<details>
<summary><strong>Hunt 2 — Rapid Admin Password Change + Restore (Sentinel)</strong></summary>

> [!NOTE]
> `TargetDomainName == Computer` silently fails when `Computer` is stored as FQDN. Use the fix below.

```kql
SecurityEvent
| where TimeGenerated > ago(7d)
| where EventID in (4723, 4724)
| where TargetUserName has_any ("admin", "administrator")
| where TargetDomainName =~ toupper(tostring(split(Computer, ".")[0]))
| summarize ChangeCount = count(), EventIDs = make_list(EventID),
    FirstEvent = min(TimeGenerated), LastEvent = max(TimeGenerated)
    by TargetUserName, Computer, TargetDomainName
| where ChangeCount >= 2
| extend WindowSeconds = datetime_diff('second', LastEvent, FirstEvent)
| where WindowSeconds < 120
```
</details>

<details>
<summary><strong>Hunt 3 — VSS Enumeration from User Space (Advanced Hunting)</strong></summary>

```kql
DeviceProcessEvents
| where Timestamp > ago(7d)
| where ProcessCommandLine has_any (
    "HarddiskVolumeShadowCopy", "Win32_ShadowCopy",
    @"GLOBALROOT\Device\HarddiskVolumeShadow",
    "vssadmin list shadows", "vssadmin list shadowstorage"
)
| where AccountSid != "S-1-5-18"
| where AccountName !endswith "$"
| where FileName !in~ ("wbengine.exe", "vssvc.exe")
| project Timestamp, DeviceName, AccountName, FileName,
    ProcessCommandLine, InitiatingProcessFileName,
    InitiatingProcessCommandLine
```
</details>

<details>
<summary><strong>Hunt 4 — Cloud Files API Abuse (Advanced Hunting)</strong></summary>

```kql
let ApprovedSyncProcesses = dynamic([
    "onedrive.exe", "googledrivefs.exe", "dropbox.exe",
    "boxsync.exe", "svchost.exe", "explorer.exe", "mobsync.exe"
]);
DeviceImageLoadEvents
| where Timestamp > ago(7d)
| where FileName =~ "cldapi.dll"
| where InitiatingProcessAccountSid != "S-1-5-18"
| where InitiatingProcessAccountName !endswith "$"
| where InitiatingProcessFileName !in~ (ApprovedSyncProcesses)
| project Timestamp, DeviceName, InitiatingProcessAccountName,
    InitiatingProcessFileName, InitiatingProcessFolderPath,
    InitiatingProcessCommandLine, InitiatingProcessParentFileName
```
</details>

<details>
<summary><strong>Hunt 5 — Transient Service from Non-Standard Path (Sentinel)</strong></summary>

> [!NOTE]
> `EventData` JSON key names vary by environment. Verify with: `SecurityEvent | where EventID == 4697 | project EventData | take 1`
>
> `trim('"', ...)` is required — `ServiceFileName` may include surrounding quote characters.

```kql
SecurityEvent
| where TimeGenerated > ago(7d)
| where EventID == 4697
| extend ServiceFileName = trim('"', tostring(parse_json(EventData).Service_Information_Service_File_Name))
| extend ServiceName     = tostring(parse_json(EventData).Service_Information_Service_Name)
| extend SubjectAccount  = tostring(parse_json(EventData).SubjectAccountName)
| where SubjectAccount !endswith "$"
| where isnotempty(ServiceFileName)
| where not(ServiceFileName matches regex
    @"(?i)^([A-Z]:\\(Windows|Program\sFiles(\s\(x86\))?|ProgramData|PROGRA~\d)|\\\\?SystemRoot\\|system32\\)")
| project TimeGenerated, Computer, SubjectAccount, ServiceName, ServiceFileName
```
</details>

<details>
<summary><strong>Hunt 6 — SYSTEM Shell from Service Process (Advanced Hunting)</strong></summary>

> [!NOTE]
> `LogonId 999` = built-in SYSTEM session (not escalated interactive). BlueHammer spawns into a real user session with a non-999 LogonId.

```kql
DeviceProcessEvents
| where Timestamp > ago(7d)
| where FileName in~ ("cmd.exe", "powershell.exe", "pwsh.exe")
| where AccountSid == "S-1-5-18"
| where InitiatingProcessFileName =~ "services.exe"
| where InitiatingProcessCommandLine !has "MpCmdRun"
| project Timestamp, DeviceName, AccountName, FileName,
    ProcessCommandLine, InitiatingProcessCommandLine, LogonId
```
</details>

<details>
<summary><strong>Hunt 7 — Defender Update + VSS Enumeration Same Window (Advanced Hunting)</strong></summary>

```kql
DeviceProcessEvents
| where Timestamp > ago(7d)
| where FileName =~ "MpCmdRun.exe"
| where ProcessCommandLine has_any ("SignatureUpdate", "-SignatureUpdate")
| project DeviceName, UpdateTime = Timestamp
| join kind=inner (
    DeviceProcessEvents
    | where Timestamp > ago(7d)
    | where ProcessCommandLine has "HarddiskVolumeShadowCopy"
    | where AccountSid != "S-1-5-18"
    | project DeviceName, VSSScanTime = Timestamp,
        ScanProcess = FileName, ScanAccount = AccountName
) on DeviceName
| where VSSScanTime between (UpdateTime .. UpdateTime + 5m)
| project DeviceName, UpdateTime, VSSScanTime, ScanAccount, ScanProcess
```
</details>

<details>
<summary><strong>Hunt 8 — Broad SYSTEM Shell from Non-SYSTEM Parent (Advanced Hunting)</strong></summary>

```kql
DeviceProcessEvents
| where Timestamp > ago(7d)
| where AccountSid == "S-1-5-18"
| where FileName in~ ("cmd.exe", "powershell.exe", "pwsh.exe", "wscript.exe", "cscript.exe")
| where InitiatingProcessAccountSid != "S-1-5-18"
| where InitiatingProcessFileName !in~ (
    "services.exe", "wininit.exe", "smss.exe", "csrss.exe",
    "lsass.exe", "svchost.exe", "msiexec.exe",
    "trustedinstaller.exe", "tiworker.exe"
)
| project Timestamp, DeviceName, AccountName, FileName,
    ProcessCommandLine, InitiatingProcessAccountName,
    InitiatingProcessFileName, InitiatingProcessCommandLine
```
</details>

### Hunt Triage

| Result | Action |
|---|---|
| Hit on Hunt 1 or 2 | 🔴 Stop. Escalate to IR. Isolate host via MDE immediately. |
| Hit on Hunt 3, 4, or 5 | 🟠 Escalate to IR. Pull full process tree on host. |
| Hit on Hunt 6 or 7 | 🟡 Investigate 24hr timeline. Determine if SYSTEM access obtained. |
| Hit on Hunt 8 only | 🟡 Investigate process tree. Treat as active LPE until ruled out. |
| Clean | 🟢 Document with query evidence and time ranges. Use as back-test baseline. |

---

## 📊 ATT&CK Coverage

| Technique | Description | Stage | Status |
|---|---|---|---|
| T1068 | Exploitation for Privilege Escalation | 2–4 | ✅ |
| T1003.002 | OS Credential Dumping: SAM | 5–6 | ✅ |
| T1552.002 | Credentials in Registry — LSA boot key | 6 | ✅ |
| T1098 | Account Manipulation — SamiChangePasswordUser | 7 | ✅ |
| T1134.001 | Token Impersonation/Theft | 7 | ✅ |
| T1543.003 | Windows Service — GUID-named temp service | 8 | ✅ |
| T1569.002 | Service Execution — SYSTEM shell | 8 | ✅ |
| T1562.001 | Disable or Modify Tools — Defender freeze | 3 | ✅ |
| T1574.005 | Executable Installer File Permissions Abuse | 4 | ⚠️ Partial — Sysmon required |
| T1082 | System Information Discovery — VSS recon | 1 | ✅ |
| T1490 | Inhibit System Recovery — shadow copy abuse | 1–5 | ✅ |
| T1005 | Data from Local System — SAM via VSS | 5 | ✅ |

---

## 🚀 Deployment Guide

### Prerequisites

| Requirement | Details |
|---|---|
| Microsoft Sentinel | Log Analytics workspace |
| Defender for Endpoint | MDE via XDR Connector |
| `DeviceFileEvents` | Rules 1, 3 |
| `DeviceProcessEvents` | Rules 4, 8 |
| `DeviceImageLoadEvents` | Rule 6 |
| `DeviceRegistryEvents` | Rules 4, 5 |
| `SecurityAlert` | Rule 9 (composite) only |
| Audit User Account Management | Success + Failure — Rules 2, 3 |
| Audit Security System Extension | Success — Rules 3, 9 |

### Environment Validation

<details>
<summary><strong>Validate before deploying</strong></summary>
<br>

**Registry telemetry (Rules 4, 5):**
```kql
DeviceRegistryEvents
| where RegistryKey has "Control\\Lsa"
| take 10
```

**Rule 2 — FQDN fix:**
```kql
SecurityEvent
| where TimeGenerated > ago(1d)
| where EventID in (4723, 4724)
| project Computer,
    ComputerShort    = toupper(tostring(split(Computer, ".")[0])),
    TargetDomainName = toupper(TargetDomainName)
| take 10
```
`ComputerShort` and `TargetDomainName` should match for local accounts.

**Rule 3 — EventData structure:**
```kql
SecurityEvent | where EventID == 4697 | project EventData | take 1
```

**Rule 6 — Image load telemetry:**
```kql
search in (DeviceImageLoadEvents) "*" | take 1
```

**Rule 9 — Composite dependency:**
```kql
SecurityAlert
| where TimeGenerated > ago(7d)
| where AlertName in (
    "Registry Hive Access via Volume Shadow Copy Path",
    "Local Administrator Password Rapid Change and Restore",
    "Windows Service Installed from Non-Standard Path",
    "Cloud Files Sync Root Registered by Untrusted Process",
    "Volume Shadow Copy Enumeration from User-Space Process"
)
| summarize count() by AlertName
```
All five must return results before deploying Rule 9.

</details>

### Lab Emulation

> [!TIP]
> The original BlueHammer PoC blocks at Stage 1 if no pending Defender signature update exists. **[technoherder/BlueHammerFix](https://github.com/technoherder/BlueHammerFix)** adds a `--force` flag that bypasses the Windows Update API check, enabling Stage 1–5 execution without a natural definition version gap.
>
> Build: Visual Studio 2022 + Windows SDK 10.0.26100.0, Release x64.
> ```
> FunnyApp.exe --force    # Skips update check, downloads directly from CDN
> ```

---

## 🔎 Key IOCs

*Source: technoherder/BlueHammerFix technical analysis*

> [!WARNING]
> Several IOCs below are **trivially changed by an attacker** recompiling from source. Do not rely on string-based detections alone. Behavioral rules are the durable layer.

**Structural IOCs — reliable across variants:**

| IOC | Type | Why It's Stable |
|---|---|---|
| RPC UUID `c503f532-443a-4c69-8300-ccd1fbdb3839` to `IMpService` endpoint | Process/RPC | Hardcoded interface UUID required to invoke `ServerMpUpdateEngineSignature` — changing it breaks the exploit |
| NTFS junction from `%TEMP%` to `\BaseNamedObjects\Restricted` | Filesystem | The junction target is a fixed Windows kernel object namespace — structural to the technique |
| `SamiChangePasswordUser` import from `samlib.dll` | Binary/YARA | Undocumented API required for local pass-the-hash — no substitute exists |

**Volatile IOCs — will change in modified variants:**

| IOC | Type | Why It Changes |
|---|---|---|
| `Chrome/141.0.0.0` User-Agent from non-browser to `go.microsoft.com` | Network | Single string in source — trivial one-line change |
| `IHATEMICROSOFT` Cloud Files provider name | Memory | Arbitrary string passed to `CfRegisterSyncRoot` — any value works |
| `$PWNed666!!!WDFAIL` temporary password | Memory | Arbitrary password string — any valid Windows password works |
| GUID-named directories in `%TEMP%` with `.vdm` files | Filesystem | GUID is generated at runtime — staging path is configurable |
| `%TEMP%\<GUID>\foo.exe` EICAR trigger file | Filesystem | Filename and content can be changed — any file Defender scans works |

---

## 📚 References

- **[technoherder/BlueHammerFix](https://github.com/technoherder/BlueHammerFix)** — Bug fixes, Sigma rules, YARA rules, technical report
- **[Cyderes Howler Cell](https://www.cyderes.com/howler-cell/windows-zero-day-bluehammer)** — BlueHammer technical analysis
- **[BlueHammer PoC](https://github.com/Nightmare-Eclipse/BlueHammer)** — Original exploit (Chaotic Eclipse)
- **[Microsoft Cloud Files API](https://learn.microsoft.com/en-us/windows/win32/cfapi/)** — CfRegisterSyncRoot documentation
- **[MITRE ATT&CK](https://attack.mitre.org)** — Framework reference
