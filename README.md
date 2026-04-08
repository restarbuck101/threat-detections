# BlueHammer — Windows Zero-Day Detection Rules

> **Threat Status:** Unpatched | **PoC Released:** April 3, 2026 | **CVE:** Not assigned

Detection rules, threat hunt queries, and a complete kill chain analysis for **BlueHammer** — an unpatched Windows local privilege escalation zero-day that chains Microsoft Defender's update workflow, Volume Shadow Copy, the Cloud Files API, and opportunistic locks to escalate a standard user to `NT AUTHORITY\SYSTEM` in under 60 seconds.

---

## What is BlueHammer?

BlueHammer is a design flaw and TOCTOU race condition in how four legitimate Windows components interact:

| Component | Role in Exploit |
|---|---|
| **Microsoft Defender Update Workflow** | Creates a privileged VSS snapshot during remediation |
| **Volume Shadow Copy Service (VSS)** | Mounts a snapshot exposing locked SAM, SYSTEM, SECURITY hives |
| **Cloud Files API (`cldapi.dll`)** | `CfRegisterSyncRoot` callback gives attacker a programmable pause on Defender |
| **Opportunistic Locks (Oplocks)** | Freezes Defender at the exact moment the snapshot is mounted |

No kernel exploit. No memory corruption. No admin rights required to start.

A public PoC was released on GitHub on April 3, 2026 by researcher "Chaotic Eclipse" with no coordinated disclosure. Microsoft has issued a Defender signature (`Exploit:Win32/DfndrPEBluHmr.BB`) that detects the original compiled binary only — a recompiled variant bypasses it entirely. **Behavioral detection is the primary protection layer until a patch is available.**

---

## Repository Contents

```
├── detections/
│   ├── win_security_vss_registry_hive_shadow_copy_access.yaml
│   ├── win_security_local_admin_password_rapid_change_restore.yaml
│   ├── win_security_service_install_non_standard_path.yaml
│   ├── win_security_cloud_files_sync_root_untrusted_process.yaml
│   ├── win_security_vss_shadow_copy_enumeration_user_space.yaml
│   └── win_security_bluehammer_kill_chain_correlation.yaml
└── BlueHammer_ThreatHunt_Detection_Guide_PUBLIC.docx
```

---

## ATT&CK Coverage

| Step | Technique | Rule |
|---|---|---|
| 1 — VSS Reconnaissance | T1082 / T1068 | `win_security_vss_shadow_copy_enumeration_user_space` |
| 2 — Defender Freeze | T1068 | `win_security_cloud_files_sync_root_untrusted_process` |
| 3 — Credential Dump | T1003.002 | `win_security_vss_registry_hive_shadow_copy_access` |
| 4 — Password Manipulation | T1098 / T1134.001 | `win_security_local_admin_password_rapid_change_restore` |
| 5 — SYSTEM Shell | T1543.003 | `win_security_service_install_non_standard_path` |
| Full Chain | Multi | `win_security_bluehammer_kill_chain_correlation` *(composite)* |

---

## Platform Requirements

- **Microsoft Sentinel** (Log Analytics workspace)
- **Microsoft Defender for Endpoint** (MDE) via the Microsoft Defender XDR data connector
- The following tables must be enabled in the XDR connector:
  - `DeviceFileEvents`
  - `DeviceProcessEvents`
  - `DeviceImageLoadEvents` *(Rule 4 only)*
  - `SecurityAlert` *(Rule 6 composite only)*
- Audit policy: **Audit User Account Management = Success and Failure** *(Rules 2 and 3)*
- Audit policy: **Audit Security System Extension = Success** *(Rule 3)*

---

## Deployment Guide

### Step 1 — Threat Hunt First

Before deploying detections, run the 8 threat hunt queries documented in `BlueHammer_ThreatHunt_Detection_Guide_PUBLIC.docx` to determine whether BlueHammer has already been used in your environment. The hunt queries cover 30 days of telemetry and all primary kill chain indicators.

### Step 2 — Tune Rule 3

`win_security_service_install_non_standard_path` requires environment-specific tuning before production deployment. Run it over 7-30 days and populate the `ApprovedEnterprisePaths` and `ApprovedServiceNames` lists for your environment. See the `false_positive_guidance` field in the YAML for a tuning methodology.

### Step 3 — Validate Environment-Specific Queries

Two rules require environment validation before deployment:

**Rule 2 — FQDN check:**
```kql
SecurityEvent
| where TimeGenerated > ago(1d)
| where EventID in (4723, 4724)
| project Computer,
    ComputerShort = toupper(tostring(split(Computer, ".")[0])),
    TargetDomainName = toupper(TargetDomainName)
| take 10
```
Confirm `ComputerShort` and `TargetDomainName` match for local accounts. If not, adjust the filter in the query.

**Rule 3 — EventData structure:**
```kql
SecurityEvent
| where EventID == 4697
| project EventData
| take 1
```
Confirm the JSON key names match what the query expects. Key names vary by environment.

**Rule 4 — Table availability:**
```kql
search in (DeviceImageLoadEvents) "*"
| take 1
```

### Step 4 — Deploy Individual Rules (1–5)

Deploy rules 1–5 to staging first. Observe for 24–48 hours. Promote to production.

### Step 5 — Deploy Composite Rule (6)

Deploy `win_security_bluehammer_kill_chain_correlation` **only after** individual rules are active and generating alerts. Verify dependency:

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

All five should return results before deploying the composite rule.

---

## Threat Hunt Queries

All 8 hunt queries are documented in the accompanying guide. Quick reference:

| Hunt | Indicator | Platform | Confidence |
|---|---|---|---|
| 1 | SAM/SYSTEM/SECURITY access via VSS path | Advanced Hunting | Critical |
| 2 | Rapid admin password change + restore | Sentinel SecurityEvent | Critical |
| 3 | VSS enumeration from user-space | Advanced Hunting | High |
| 4 | `cldapi.dll` loaded by non-sync process | Advanced Hunting | High |
| 5 | Transient service from non-standard path | Sentinel SecurityEvent | High |
| 6 | SYSTEM shell spawned from services.exe | Advanced Hunting | High |
| 7 | Defender update + VSS enumeration same window | Advanced Hunting | Medium |
| 8 | Broad SYSTEM shell from non-SYSTEM parent | Advanced Hunting | Medium |

---

## Known False Positive Notes

| Rule | Common FP Source | Mitigation |
|---|---|---|
| Rule 3 | Installer helpers, remote execution agents, hardware driver installers from Temp paths | Back-test and populate `ApprovedEnterprisePaths` and `ApprovedServiceNames` |
| Rule 5 | IT admins running `vssadmin` for storage management | Verify against change tickets; consider approved admin account watchlist |
| Rule 4 | New enterprise cloud sync products | Add to `ApprovedSyncProcesses` list |
| Rule 2 | LAPS rotation scripts | Filter on known LAPS service account in `SubjectAccounts` |
| Rule 6 | Isolated test environment during adversary simulation | Suppress manually during test campaigns |

---

## If This Fires on a Production Host

The composite rule (`win_security_bluehammer_kill_chain_correlation`) firing in production indicates active or recent exploitation.

**Immediate actions:**
1. Isolate the host via MDE immediately — do not wait
2. Note which individual rules fired (`FiredRules` field)
3. Escalate to IR with host name, fired rules, and window duration
4. Assume all local NTLM hashes on the affected host are compromised
5. Preserve forensic evidence before remediation

---

## Testing

All individual rules were back-tested against 7–30 days of production telemetry prior to release and confirmed clean. Unit testing and adversary simulation in an isolated environment are required before production deployment. See `testing` blocks in each YAML for specific test guidance.

The composite rule (Rule 6) cannot be back-tested against historical data — it queries `SecurityAlert` which is only populated by active analytics rule alerts. Validation is via adversary simulation.

---

## Rule Naming Convention

Rules follow the [Sigma](https://github.com/SigmaHQ/sigma) naming convention:

```
[platform_service]_[behavior_verb]_[optional_target].yaml
```

---

## Contributing

Issues and pull requests welcome. If you identify false positives, additional exclusion patterns, or improvements to the detection logic in your environment please open an issue with:
- Your environment context (Windows version, MDE version if relevant)
- The FP pattern (process name, path, or service name)
- Suggested exclusion approach

---

## References

- Cyderes Howler Cell — BlueHammer Technical Analysis: https://www.cyderes.com/howler-cell/windows-zero-day-bluehammer
- BlueHammer PoC (Chaotic Eclipse): https://github.com/Nightmare-Eclipse/BlueHammer
- MITRE ATT&CK: https://attack.mitre.org
- Sigma Rule Format: https://github.com/SigmaHQ/sigma

---

## License

Detection rules released under [MIT License](LICENSE). Use freely, contribute back.

---

*Back-tested April 2026. Unit tests and adversary simulation pending. All rules are in Testing status — validate in your environment before production deployment.*
