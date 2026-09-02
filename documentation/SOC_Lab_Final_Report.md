# Security Operations Center (SOC) Lab Using Wazuh, Sysmon & MITRE ATT&CK

> An isolated Windows-based SOC lab demonstrating security monitoring, detection, investigation, threat hunting, incident response, custom detection engineering, and automated response.

---

## 1. Project Overview

This project implements an isolated Security Operations Center (SOC) training environment using VMware, Wazuh, Sysmon, Windows 11, and Kali Linux.

The lab was designed to simulate controlled suspicious activity against a Windows endpoint and demonstrate the complete SOC workflow:

**Activity Generation → Telemetry Collection → Detection → Investigation → MITRE ATT&CK Mapping → Threat Hunting → Incident Response → Active Response → Dashboard Visualization**

All testing was performed within an isolated VMware private network.

---

## 2. Objectives

The main objectives of the project were to:

- Build an isolated SOC monitoring environment.
- Deploy and configure Wazuh for centralized security monitoring.
- Configure a Windows 11 endpoint with Wazuh Agent and Sysmon.
- Generate controlled suspicious activity.
- Detect Windows Security and Sysmon events using Wazuh.
- Investigate alerts and correlate related events.
- Map relevant activity to MITRE ATT&CK.
- Perform threat hunting using endpoint telemetry.
- Develop a custom Wazuh detection rule.
- Configure and validate Wazuh Active Response.
- Build a SOC-focused security dashboard.
- Document the complete detection and response workflow.

---

## 3. Lab Architecture

The lab consists of three virtual machines:

| Component | Role |
|---|---|
| Wazuh Server | Central security monitoring, analysis, event storage and visualization |
| Windows 11 Endpoint | Monitored endpoint generating Windows Security and Sysmon telemetry |
| Kali Linux | Security testing and controlled activity generation |

The environment operates on an isolated VMware private network.

![SOC Lab Architecture](../architecture/architecture-diagram.png)

---

## 4. Security Telemetry

### Windows Security Events

The following Windows Security events were observed during testing:

| Event ID | Activity |
|---:|---|
| 4625 | Failed logon |
| 4720 | User account creation |
| 4732 | Member added to a security-enabled local group |

### Sysmon Events

| Event ID | Activity |
|---:|---|
| 1 | Process Create |
| 11 | File Create |

Sysmon provided detailed endpoint telemetry that supported investigation of PowerShell execution and file activity.

---

## 5. Detection Scenarios

### 5.1 Suspicious PowerShell Activity

PowerShell activity was generated in the controlled lab environment.

Wazuh rule `92029` detected PowerShell execution from a suspicious location.

The activity was mapped to:

**MITRE ATT&CK T1059.001 — PowerShell**

---

### 5.2 Suspicious File Activity

Controlled test files were created under:

`C:\Users\Public\`

Relevant Wazuh detections included:

- Rule `92207` — Executable file dropped in Users\Public folder
- Rule `92213` — Executable file dropped in a folder commonly used by malware

Sysmon Event ID 11 provided file creation telemetry.

---

### 5.3 Windows Account Activity

The lab generated and investigated:

- Event ID 4720 — account creation
- Event ID 4732 — administrator/security group modification
- Event ID 4625 — failed authentication

These events were correlated with other endpoint activity during investigation.

---

## 6. SOC Investigation

The investigation followed a structured SOC workflow:

```text
Alert Received
      ↓
Identify Detection Rule
      ↓
Review Severity and Endpoint
      ↓
Examine Windows Security / Sysmon Events
      ↓
Correlate Related Activity
      ↓
Identify Process / File / Account Activity
      ↓
Map to MITRE ATT&CK
      ↓
Assess Impact
      ↓
Contain and Respond
