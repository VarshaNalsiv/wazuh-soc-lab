# Incident Response

## Incident Overview

A controlled suspicious activity scenario was executed against the Windows 11 SOC endpoint in the isolated VMware lab. Wazuh and Sysmon telemetry were used to detect, investigate, and respond to the activity.

## Detection

The activity generated Wazuh alerts associated with:

- PowerShell execution
- Suspicious file activity
- Windows account activity
- Custom detection rule `100100`

Relevant detection rules included:

- `92029` — PowerShell executed from a suspicious location
- `92207` — Executable file dropped in Users\Public
- `92213` — Executable file dropped in a folder commonly used by malware
- `100100` — Custom SOC Detection: PowerShell ExecutionPolicy Bypass

## Investigation

The investigation correlated:

1. Windows Security events
2. Sysmon process creation events
3. Sysmon file creation events
4. Wazuh detection rules
5. MITRE ATT&CK technique mappings

The investigation focused on identifying the process, affected endpoint, suspicious files, account activity, and relationships between the observed events.

## Containment

The controlled incident response included:

- Disabling the test account `Phase4SOC`
- Removing the account from the local Administrators group
- Removing temporary suspicious PowerShell test files
- Preserving relevant Wazuh and Sysmon telemetry
- Verifying that the Wazuh agent remained connected to the Wazuh server

## Active Response

A custom Wazuh Active Response was configured for rule `100100`.

The response executed:

`SOC_ActiveResponse.cmd`

which launched:

`SOC_ActiveResponse.ps1`

The response was verified by creating:

`C:\Users\Public\SOC_ActiveResponse_Result.txt`

The result file confirmed that the Active Response executed successfully.

## Response Workflow

```text
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
