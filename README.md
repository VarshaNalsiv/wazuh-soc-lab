# Security Operations Center (SOC) Lab Using Wazuh, Sysmon & MITRE ATT&CK

An isolated VMware SOC lab demonstrating **security monitoring, threat detection, alert investigation, threat hunting, MITRE ATT&CK mapping, custom detection engineering, incident response, automated response, and SOC dashboard visualization.**

![SOC Lab Architecture](architecture/architecture-diagram.png)

---

## 🔎 Project Overview

This project implements a small-scale Security Operations Center (SOC) environment using:

- **Wazuh** — Security monitoring, detection, analysis and visualization
- **Sysmon** — Windows endpoint telemetry
- **Windows 11** — Monitored SOC endpoint
- **Kali Linux** — Controlled security testing
- **MITRE ATT&CK** — Adversary technique mapping
- **VMware** — Isolated virtualization environment

The project follows an end-to-end SOC workflow:

```text
Controlled Activity
       ↓
Endpoint Telemetry
       ↓
Wazuh Detection
       ↓
Alert Investigation
       ↓
Event Correlation
       ↓
MITRE ATT&CK Mapping
       ↓
Threat Hunting
       ↓
Incident Response
       ↓
Active Response
       ↓
SOC Dashboard
---

## 🏗️ Lab Architecture

The SOC lab consists of three virtual machines running in an isolated VMware environment:

| Component | Role |
|---|---|
| **Wazuh Server** | Central security monitoring, analysis and visualization |
| **Windows 11 Endpoint** | Monitored endpoint generating Windows Security and Sysmon telemetry |
| **Kali Linux** | Controlled security testing |
| **VMware** | Isolated virtualization environment |

![SOC Lab Architecture](architecture/architecture-diagram.png)
