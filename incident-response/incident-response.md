# Incident Response

## Incident Overview

A controlled suspicious activity scenario was executed against the Windows 11 SOC endpoint (`WIN11-SOC`) in the isolated VMware lab. Wazuh and Sysmon telemetry were used to detect, investigate, and respond to the activity.

**Date of Activity:** August 30, 2026

**Affected Endpoint:** WIN11-SOC

**Incident Type:** Controlled security test (PowerShell execution, file creation, account activity)

---

## Detection

The activity generated Wazuh alerts associated with:

- PowerShell execution
- Suspicious file activity
- Windows account activity
- Custom detection rule `100100`

### Detection Timeline

| Time | Event | Rule ID | Description |
|------|-------|---------|-------------|
| 14:20:10 | Account creation detected | 4716 | User `Phase4SOC` created |
| 14:20:15 | Group modification detected | 4719 | `Phase4SOC` added to Administrators |
| 14:20:22 | Failed logon attempt | 4625 | Brute force attempt from Kali |
| 14:23:12 | PowerShell execution | 92029 | PowerShell from suspicious location |
| 14:23:12 | Custom rule triggered | 100100 | PowerShell execution activity |

### Relevant Detection Rules

| Rule ID | Description |
|---------|-------------|
| 92029 | PowerShell executed from a suspicious location |
| 92207 | Executable file dropped in Users\Public |
| 92213 | Executable file dropped in a folder commonly used by malware |
| 100100 | Custom SOC Detection: PowerShell execution activity |

---

## Investigation

### Investigation Steps

1. **Alert Review:** Opened alert `92029` in Wazuh Dashboard.

2. **Raw JSON Analysis:** Examined the telemetry:

```
"win.eventdata.commandLine": "powershell -c Write-Host 'SOC Lab Test'"
"agent.name": "WIN11-SOC"
"win.eventdata.image": "C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe"
```

3. **Process Chain Analysis:** Confirmed PowerShell was spawned by `cmd.exe` (PID 1234).

4. **Event Correlation:** Linked the following events:
   - Account creation (`4720`)
   - Group modification (`4732`)
   - Failed logon attempts (`4625`)
   - PowerShell execution (`92029`)

5. **MITRE Mapping:** Mapped to T1059.001 (PowerShell).

### Correlated Timeline

```
14:20:10 - Account Created (Phase4SOC)
14:20:15 - Account Added to Administrators
14:20:22 - Failed Logon Attempts from Kali
14:23:12 - PowerShell Executed (Alert 92029)
14:23:12 - Custom Rule Triggered (100100)
```

---

## Containment

### Response Actions

| Action | Status | Details |
|--------|--------|---------|
| Disable test account | ✅ Completed | `net user Phase4SOC /active:no` |
| Remove from Administrators | ✅ Completed | Removed from local Administrators group |
| Remove suspicious files | ✅ Completed | Deleted `C:\Users\Public\*.ps1` |
| Preserve telemetry | ✅ Completed | Exported Wazuh alerts and Sysmon logs |
| Verify agent connectivity | ✅ Completed | Agent remains connected to Wazuh server |

### Verification Commands

```cmd
# Verify account disabled
net user Phase4SOC

# Verify group membership removed
net localgroup Administrators

# Verify agent connectivity
# (Checked in Wazuh Dashboard)
```

---

## Active Response

A custom Wazuh Active Response was configured for rule `100100`.

### Response Workflow

```
Wazuh Alert
     ↓
Custom Rule 100100
     ↓
Active Response
     ↓
SOC_ActiveResponse.cmd
     ↓
SOC_ActiveResponse.ps1
     ↓
Response Execution Verified
```

### Verification

The response was verified by creating:

```
C:\Users\Public\SOC_ActiveResponse_Result.txt
```

The result file confirmed that the Active Response executed successfully.

---

## Lessons Learned

| Area | Finding |
|------|---------|
| Detection Pipeline | Wazuh successfully collected and alerted on all test activity |
| Custom Rule | Rule `100100` triggered as expected on PowerShell execution |
| Active Response | Automated response executed successfully |
| Event Correlation | Multiple events were linked into a single incident timeline |
| Coverage Gap | Direct ADS detection was not observed (see Atomic Red Team validation) |

### Future Improvements

- Add network-level detection (Zeek/Suricata)
- Expand custom detection rules for ADS activity
- Implement more advanced automated response actions
- Add Linux endpoint monitoring
- Integrate threat intelligence feeds

---

## Evidence

Relevant screenshots are stored in the repository's `screenshots/` directory.

Evidence demonstrates:

- Alert detection
- Investigation steps
- Containment actions
- Active Response execution
- Correlated timeline
