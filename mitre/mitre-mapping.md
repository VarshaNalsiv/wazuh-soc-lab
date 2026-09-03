# MITRE ATT&CK Mapping

## Overview

The controlled activities performed in the SOC lab were mapped to relevant MITRE ATT&CK techniques based on the observed telemetry and Wazuh detections.

**Mapping Purpose:** To demonstrate how endpoint telemetry can be aligned with adversary techniques, supporting alert triage, investigation, and detection engineering.

**Environment:** Isolated SOC lab with Windows 11 endpoint, Wazuh SIEM, and Sysmon telemetry.

---

## Technique Mapping Table

| Observed Activity | Wazuh Rule | Tactic | MITRE Technique | Technique ID |
|-------------------|------------|--------|-----------------|--------------|
| PowerShell execution | 92029 | Execution | Command and Scripting Interpreter: PowerShell | T1059.001 |
| PowerShell ExecutionPolicy Bypass | 100100 | Execution | Command and Scripting Interpreter: PowerShell | T1059.001 |
| Suspicious executable/file drop | 92207 / 92213 | Command and Control | Ingress Tool Transfer | T1105 |
| Windows account creation | 4720 | Persistence | Create Account: Local Account | T1136.001 |
| Administrator group modification | 4732 | Privilege Escalation | Account Manipulation | T1098 |
| Failed authentication | 4625 | Credential Access | Brute Force | T1110 |

---

## Key Technique Detail: T1059.001 — PowerShell

### Description

PowerShell is a scripting language and command-line interface commonly used for system administration. It is frequently abused by adversaries to execute malicious scripts, download payloads, and maintain persistence.

### Tactic

**Execution** — Adversaries may use PowerShell to execute commands, scripts, or payloads.

### Observed Activity

PowerShell execution was detected through:

- Sysmon Event ID 1 (Process Create)
- Wazuh rule `92029` (PowerShell from suspicious location)
- Custom rule `100100` (PowerShell execution activity)

### Detection Evidence

The following command line was captured:

```
powershell -c "Write-Host 'SOC Lab Test'"
```

### Procedure Example

PowerShell was used to execute a command on the Windows endpoint. The activity was generated from the Windows 11 endpoint (`WIN11-SOC`) and detected by the Wazuh agent.

### MITRE ATT&CK Details

| Attribute | Value |
|-----------|-------|
| **Technique ID** | T1059.001 |
| **Technique Name** | Command and Scripting Interpreter: PowerShell |
| **Tactic** | Execution |
| **Platforms** | Windows, macOS, Linux |
| **Permissions Required** | User |
| **Data Sources** | Process creation, PowerShell logs, command-line arguments |

### Investigation Questions

- What command was executed?
- Was the command encoded or obfuscated?
- What process spawned PowerShell?
- Was ExecutionPolicy bypassed?

---

## Technique Detail: T1105 — Ingress Tool Transfer

### Description

Adversaries may transfer tools or files into a compromised environment. This can include malware, scripts, or utilities used for further exploitation.

### Tactic

**Command and Control** — Adversaries may use file transfer protocols to move tools into the environment.

### Observed Activity

Controlled test files were created under:

```
C:\Users\Public\
```

### Detection Evidence

- Sysmon Event ID 11 (File Create)
- Wazuh rule `92207` (Executable dropped in Users\Public)
- Wazuh rule `92213` (Executable dropped in malware-common folder)

### Procedure Example

A test file (`testfile.txt`) was created in the `C:\Users\Public\` directory. This simulates an attacker dropping a malicious executable or script.

### MITRE ATT&CK Details

| Attribute | Value |
|-----------|-------|
| **Technique ID** | T1105 |
| **Technique Name** | Ingress Tool Transfer |
| **Tactic** | Command and Control |
| **Platforms** | Windows, macOS, Linux |
| **Permissions Required** | User |
| **Data Sources** | File creation, network traffic, process monitoring |

### Investigation Questions

- What files were created or modified?
- Where were they stored?
- What process created the file?
- Is the file known malware?

---

## Technique Detail: T1136.001 — Create Account: Local Account

### Description

Adversaries may create local accounts to maintain persistence and gain access. Local accounts can be used to evade detection and maintain access to a compromised system.

### Tactic

**Persistence** — Adversaries may create accounts to ensure continued access.

### Observed Activity

A test account (`Phase4SOC`) was created on the Windows 11 endpoint.

### Detection Evidence

Windows Security Event ID 4720 (Account Creation) was observed.

### Procedure Example

```cmd
net user Phase4SOC Password123! /add
```

### MITRE ATT&CK Details

| Attribute | Value |
|-----------|-------|
| **Technique ID** | T1136.001 |
| **Technique Name** | Create Account: Local Account |
| **Tactic** | Persistence |
| **Platforms** | Windows |
| **Permissions Required** | Administrator |
| **Data Sources** | Account creation logs, Windows Security events |

### Investigation Questions

- What account was created?
- When was it created?
- Who created it?
- What permissions does it have?
- Is the account still active?

---

## Technique Detail: T1098 — Account Manipulation

### Description

Adversaries may manipulate accounts to maintain or escalate access. This includes adding accounts to privileged groups.

### Tactic

**Privilege Escalation** — Adversaries may modify accounts to gain higher privileges.

### Observed Activity

The test account (`Phase4SOC`) was added to the local Administrators group.

### Detection Evidence

Windows Security Event ID 4732 (Member Added to Security-Enabled Local Group) was observed.

### Procedure Example

```cmd
net localgroup Administrators Phase4SOC /add
```

### MITRE ATT&CK Details

| Attribute | Value |
|-----------|-------|
| **Technique ID** | T1098 |
| **Technique Name** | Account Manipulation |
| **Tactic** | Privilege Escalation |
| **Platforms** | Windows, macOS, Linux |
| **Permissions Required** | Administrator |
| **Data Sources** | Group modification logs, Windows Security events |

### Investigation Questions

- What account was modified?
- When was it modified?
- What group was it added to?
- Who made the change?

---

## Technique Detail: T1110 — Brute Force

### Description

Adversaries may use brute force techniques to gain access to accounts. This involves attempting multiple passwords until the correct one is discovered.

### Tactic

**Credential Access** — Adversaries may use brute force to compromise credentials.

### Observed Activity

Multiple failed authentication attempts were observed from Kali Linux.

### Detection Evidence

Windows Security Event ID 4625 (Failed Logon) was observed.

### MITRE ATT&CK Details

| Attribute | Value |
|-----------|-------|
| **Technique ID** | T1110 |
| **Technique Name** | Brute Force |
| **Tactic** | Credential Access |
| **Platforms** | Windows, macOS, Linux |
| **Permissions Required** | User |
| **Data Sources** | Authentication logs, Windows Security events |

### Investigation Questions

- Where did the attempts come from?
- What account was being targeted?
- How many attempts were made?
- Was the account compromised?

---

## Mapping Summary

| Tactic | Techniques Demonstrated |
|--------|-------------------------|
| Execution | T1059.001 (PowerShell) |
| Persistence | T1136.001 (Local Account Creation) |
| Privilege Escalation | T1098 (Account Manipulation) |
| Credential Access | T1110 (Brute Force) |
| Command and Control | T1105 (Ingress Tool Transfer) |

---

## Investigation Approach

MITRE ATT&CK mapping was used during investigation to:

| Activity | How MITRE Helped |
|----------|------------------|
| **Alert triage** | Identified which techniques were likely involved |
| **Threat hunting** | Searched for other related techniques (e.g., T1059.001) |
| **Incident investigation** | Connected observed activity to adversary behavior |
| **Detection engineering** | Guided custom rule development for PowerShell |
| **SOC reporting** | Provided structured language for documentation |

---

## Example Investigation: PowerShell Technique (T1059.001)

1. **Alert Received:** Wazuh rule `92029` triggered on `WIN11-SOC`.

2. **Raw Telemetry Reviewed:**

```
"win.eventdata.commandLine": "powershell -c Write-Host 'SOC Lab Test'"
```

3. **MITRE Mapping:** Mapped to T1059.001 (PowerShell).

4. **Investigation Questions Asked:**
   - Was ExecutionPolicy bypassed? (Yes, via custom rule `100100`)
   - What process spawned PowerShell? (`cmd.exe`, PID 1234)
   - Were there any encoded commands? (No)

5. **Conclusion:** The activity was a controlled test. Detection pipeline validated.

---

## Limitations

| Limitation | Description |
|------------|-------------|
| Environment | These mappings are based on controlled, lab-based activity |
| Coverage | Not all techniques were observed (e.g., persistence, lateral movement) |
| Single endpoint | Mappings are limited to Windows endpoint telemetry |
| No network | Network-level techniques (e.g., C2, exfiltration) were not observed |

---

## Future Improvements

| Area | Potential Enhancement |
|------|----------------------|
| Coverage | Add additional MITRE techniques (e.g., T1003, T1547) |
| Network | Map network-level techniques using Zeek/Suricata |
| Automation | Automate MITRE mapping for detected events |
| Correlation | Link multiple techniques into full attack chains |
| Tuning | Refine detection rules for specific techniques |

---

## Note

The mappings above are based on the controlled activity and telemetry generated within this training lab. They are not intended to represent a real-world intrusion. The purpose of this mapping is to demonstrate how MITRE ATT&CK can be used to connect observed endpoint behavior with known adversary techniques.

---

## References

- [MITRE ATT&CK T1059.001 — PowerShell](https://attack.mitre.org/techniques/T1059/001/)
- [MITRE ATT&CK T1105 — Ingress Tool Transfer](https://attack.mitre.org/techniques/T1105/)
- [MITRE ATT&CK T1136.001 — Create Account: Local Account](https://attack.mitre.org/techniques/T1136/001/)
- [MITRE ATT&CK T1098 — Account Manipulation](https://attack.mitre.org/techniques/T1098/)
- [MITRE ATT&CK T1110 — Brute Force](https://attack.mitre.org/techniques/T1110/)
