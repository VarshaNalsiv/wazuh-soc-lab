# Atomic Red Team Validation

## Overview

Atomic Red Team was used to validate the detection pipeline of the Wazuh SOC lab using controlled, reversible security tests on the Windows endpoint.

The tests were executed on the isolated Windows 11 SOC endpoint with:

- Wazuh Agent
- Sysmon
- Wazuh Manager and Dashboard
- Windows Defender (active)

No credential dumping, persistence, security-control disabling, or destructive activity was used.

---

## Test 1 — PowerShell Fileless Script Execution

| Field | Value |
|-------|-------|
| **MITRE Technique** | T1059.001 — PowerShell |
| **Atomic Test** | T1059.001-10 |
| **Test Name** | PowerShell Fileless Script Execution |

### Objective

Validate whether PowerShell activity involving registry-stored encoded content generates useful Windows and Wazuh telemetry.

### Execution Result

The Atomic test completed successfully:

| Check | Result |
|-------|--------|
| Exit code | 0 |
| Marker file | Created successfully |
| Registry value | Created successfully |

**Marker File Created:**

```
C:\Windows\Temp\art-marker.txt
```

**Marker Content:**

```
Hello from the Atomic Red Team
```

### Wazuh Detection

The activity generated Wazuh events including:

| Rule ID | Description |
|---------|-------------|
| 92041 | Value added to registry key has Base64-like pattern |
| 92027 | Powershell process spawned powershell instance |

### Cleanup

Atomic Red Team cleanup successfully removed:

- `C:\Windows\Temp\art-marker.txt`
- `HKCU:\Software\Classes\AtomicRedTeam`

---

## Test 2 — Modify Registry

| Field | Value |
|-------|-------|
| **MITRE Technique** | T1112 — Modify Registry |
| **Atomic Test** | T1112-1 |
| **Test Name** | Modify Registry of Current User Profile - cmd |

### Objective

Validate Wazuh visibility into controlled registry modification activity.

### Execution Result

| Check | Result |
|-------|--------|
| Prerequisites | Met |
| Exit code | 0 |
| Registry modification | Successfully performed |

**Registry Key Modified:**

```
HKCU\Software\Microsoft\Windows\CurrentVersion\Explorer\Advanced
```

The test modified the `HideFileExt` value.

### Wazuh Detection

Wazuh showed activity during the test window including:

| Rule ID | Description |
|---------|-------------|
| 92052 | Windows command prompt started by an abnormal process |
| 92041 | Value added to registry key has Base64-like pattern |
| 92027 | Powershell process spawned powershell instance |

**Note on Correlation:**

The events were used as telemetry evidence for the controlled registry activity. Exact rule causality was not assumed where the event details did not conclusively establish it.

### Cleanup

Atomic Red Team cleanup was successfully completed.

---

## Test 3 — NTFS Alternate Data Stream Access

| Field | Value |
|-------|-------|
| **MITRE Technique** | T1059.001 — PowerShell |
| **Atomic Test** | T1059.001-11 |
| **Test Name** | NTFS Alternate Data Stream Access |

### Objective

Validate visibility into PowerShell activity associated with NTFS Alternate Data Streams.

### Prerequisites Check

| Check | Status |
|-------|--------|
| System drive filesystem: NTFS | ✅ Met |
| Wazuh Agent: Running | ✅ Met |
| Sysmon: Running | ✅ Met |

### Execution Result

| Check | Result |
|-------|--------|
| Stream Data Executed | ✅ Successful |
| Exit code | 0 |

### Wazuh Detection

| Finding | Result |
|---------|--------|
| Sysmon Event ID 15 (direct match) | ❌ Not observed in Wazuh |
| PowerShell process activity (Rule 92027) | ✅ Detected |

**Key Finding:**

The test demonstrated PowerShell/process telemetry visibility, but the current lab configuration did not produce a direct Wazuh alert for the ADS activity itself. This identifies a potential area for future detection engineering.

### Cleanup

Atomic Red Team cleanup was successfully completed. The temporary ADS test file was removed.

---

## Detection Validation Summary

| Atomic Test | Technique | Execution | Wazuh Evidence |
|-------------|-----------|-----------|----------------|
| T1059.001-10 | PowerShell | ✅ Successful | 92041, 92027 |
| T1112-1 | Modify Registry | ✅ Successful | 92052, 92041, 92027 |
| T1059.001-11 | NTFS ADS | ✅ Successful | 92027 only |

---

## Key Findings

1. Atomic Red Team successfully generated controlled security telemetry on the Windows endpoint.

2. Sysmon captured process and file activity generated during the tests.

3. Wazuh successfully received and analyzed the resulting endpoint telemetry.

4. Existing Wazuh rules identified multiple suspicious PowerShell and registry-related behaviors.

5. The lab demonstrated that detection validation should distinguish between test execution, telemetry generation, and specific detection-rule correlation.

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

| Limitation | Description |
|------------|-------------|
| Environment | These tests were performed in an isolated training environment |
| Coverage | Results demonstrate detection visibility within this specific lab configuration |
| Scope | Should not be interpreted as complete detection coverage for the corresponding MITRE ATT&CK techniques |
| Single endpoint | Testing was limited to one Windows endpoint |

---

## Future Improvements

| Area | Potential Enhancement |
|------|----------------------|
| Atomic tests | Additional Atomic Red Team tests for other MITRE techniques |
| Custom rules | Custom detection rules for ADS activity (Event ID 15) |
| Telemetry | Additional Sysmon telemetry configuration |
| Correlation | More detailed MITRE ATT&CK correlation |
| Automation | Automated detection validation pipeline |
| Network | Add network-level detection (Zeek/Suricata) |
| Linux | Add Linux endpoint monitoring |
