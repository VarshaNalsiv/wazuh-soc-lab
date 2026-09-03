# Atomic Red Team Validation

## Overview

Atomic Red Team was used to validate the detection capability of the Wazuh SOC lab using controlled, reversible security tests on the Windows endpoint.

The tests were executed on the isolated Windows 11 SOC endpoint with:

- Wazuh Agent
- Sysmon
- Wazuh Manager and Dashboard
- Windows Defender
- Atomic Red Team

No credential dumping, persistence, security-control disabling, or destructive activity was used.

---

## Test 1 — PowerShell Fileless Script Execution

**MITRE ATT&CK Technique:** T1059.001 — PowerShell  
**Atomic Test:** T1059.001-10  
**Test Name:** PowerShell Fileless Script Execution

### Objective

Validate whether PowerShell activity involving registry-stored encoded content generates useful Windows and Wazuh telemetry.

### Execution Result

The Atomic test completed successfully with:

- Exit code: `0`
- Marker file created successfully
- Registry value created successfully

The test created:

`C:\Windows\Temp\art-marker.txt`

The marker contained:

`Hello from the Atomic Red Team`

### Wazuh Detection

The activity generated Wazuh events including:

- **Rule 92041 — Value added to registry key has Base64-like pattern**
- **Rule 92027 — Powershell process spawned powershell instance**

### Cleanup

Atomic Red Team cleanup successfully removed:

- `C:\Windows\Temp\art-marker.txt`
- `HKCU:\Software\Classes\AtomicRedTeam`

---

## Test 2 — Modify Registry

**MITRE ATT&CK Technique:** T1112 — Modify Registry  
**Atomic Test:** T1112-1  
**Test Name:** Modify Registry of Current User Profile - cmd

### Objective

Validate Wazuh visibility into controlled registry modification activity.

### Execution Result

Prerequisites were met and the Atomic test completed successfully with:

- Exit code: `0`
- Registry modification successfully performed

The test modified:

`HKCU\Software\Microsoft\Windows\CurrentVersion\Explorer\Advanced`

using the `HideFileExt` value.

### Wazuh Detection

Wazuh showed activity during the test window including:

- **Rule 92052 — Windows command prompt started by an abnormal process**
- **Rule 92041 — Value added to registry key has Base64-like pattern**
- **Rule 92027 — Powershell process spawned powershell instance**

The events were used as telemetry evidence for the controlled registry activity. Exact rule causality was not assumed where the event details did not conclusively establish it.

### Cleanup

Atomic Red Team cleanup was successfully completed.

---

## Test 3 — NTFS Alternate Data Stream Access

**MITRE ATT&CK Technique:** T1059.001 — PowerShell  
**Atomic Test:** T1059.001-11  
**Test Name:** NTFS Alternate Data Stream Access

### Objective

Validate visibility into PowerShell activity associated with NTFS Alternate Data Streams.

### Execution Result

Prerequisites were met:

- System drive filesystem: NTFS
- Wazuh Agent: Running
- Sysmon: Running

The Atomic test completed successfully with:

- `Stream Data Executed`
- Exit code: `0`

### Wazuh Detection

A direct search for Sysmon Event ID 15 did not return a matching Wazuh event.

However, Wazuh did record PowerShell process activity:

- **Rule 92027 — Powershell process spawned powershell instance**

Therefore, this test demonstrated PowerShell/process telemetry visibility, but the lab configuration did not demonstrate direct Wazuh detection of the ADS itself.

### Cleanup

Atomic Red Team cleanup was successfully completed and the temporary ADS test file was removed.

---

## Detection Validation Summary

| Atomic Test | Technique | Execution | Wazuh Evidence |
|---|---|---:|---|
| T1059.001-10 | PowerShell | Successful | 92041, 92027 |
| T1112-1 | Modify Registry | Successful | 92052, 92041, 92027 |
| T1059.001-11 | NTFS ADS | Successful | 92027 |
 
---

## Key Findings

1. Atomic Red Team successfully generated controlled security telemetry on the Windows endpoint.
2. Sysmon captured process activity generated during the tests.
3. Wazuh successfully received and analyzed the resulting endpoint telemetry.
4. Existing Wazuh detection rules identified multiple suspicious PowerShell and registry-related behaviors.
5. The lab demonstrated that detection validation should distinguish between **test execution**, **telemetry generation**, and **specific detection-rule correlation**.
6. The NTFS ADS test did not produce a direct Event ID 15 match in the current Wazuh configuration, identifying an area for possible future detection engineering.

---

## Evidence

Relevant screenshots are stored in the repository's `screenshots/` directory.

The evidence demonstrates:

- Atomic test execution
- Windows/Sysmon telemetry
- Wazuh event ingestion
- Wazuh detection rules
- Detection correlation

---

## Limitations

These tests were performed in an isolated training environment.

The results demonstrate detection visibility within this specific lab configuration and should not be interpreted as complete detection coverage for the corresponding MITRE ATT&CK techniques.

Future improvements could include:

- Additional Atomic Red Team tests
- Custom detection rules for ADS activity
- Additional Sysmon telemetry
- More detailed MITRE ATT&CK correlation
- Automated detection validation
