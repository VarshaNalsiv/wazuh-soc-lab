# MITRE ATT&CK Mapping

The controlled activities performed in the SOC lab were mapped to relevant MITRE ATT&CK techniques based on the observed telemetry and Wazuh detections.

| Observed Activity | Wazuh Rule | MITRE ATT&CK Technique | Technique ID |
|---|---:|---|---|
| PowerShell execution | 92029 | Command and Scripting Interpreter: PowerShell | T1059.001 |
| PowerShell ExecutionPolicy Bypass | 100100 | Command and Scripting Interpreter: PowerShell | T1059.001 |
| Suspicious executable/file drop | 92207 / 92213 | Ingress Tool Transfer | T1105 |
| Windows account creation | Windows Security 4720 | Account Manipulation / Account Creation activity | — |
| Administrator group modification | Windows Security 4732 | Account Manipulation activity | — |
| Failed authentication | Windows Security 4625 | Authentication activity | — |

## Key Technique

### T1059.001 — PowerShell

PowerShell activity was detected through Sysmon and Wazuh. The custom rule `100100` specifically detected PowerShell execution involving `ExecutionPolicy Bypass`.

## Investigation Approach

MITRE ATT&CK mapping was used during investigation to connect observed endpoint behavior with known adversary techniques. The mapping supported:

- Alert triage
- Threat hunting
- Incident investigation
- Detection engineering
- SOC reporting

## Note

The mappings above are based on the controlled activity and telemetry generated within this training lab. They are not intended to represent a real-world intrusion.
