# IR-001 — Credential Access Investigation

## Executive Summary

This report documents the investigation framework for a controlled multi-stage security simulation in the NORTHGATE lab. The scenario is designed to connect suspicious PowerShell execution, credential-access behavior, Kerberos service-ticket activity, scheduled-task persistence, and event-log clearing into one analyst workflow.

The purpose of the investigation is to demonstrate how separate endpoint and authentication events can be correlated into a timeline, scoped across hosts and accounts, mapped to MITRE ATT&CK, and converted into containment and detection recommendations.

> Status: investigation framework complete; real event timestamps, screenshots, and conclusions remain pending until the Atomic Red Team tests are executed and validated in Splunk.

## Environment

The simulated environment contains a Windows Server 2022 domain controller, a Windows 11 domain workstation, and a Splunk Enterprise server. Windows Security logs, PowerShell Operational logs, and Sysmon telemetry are centrally collected in Splunk.

## Investigation Model

```text
Suspicious PowerShell
    ↓
LSASS process access
    ↓
Kerberos service-ticket activity
    ↓
Scheduled-task persistence
    ↓
Security-log clearing
```

## Scope

Primary systems:

- WS01 — domain workstation and simulated attack target
- DC01 — domain controller and Kerberos event source
- SPL01 — central SIEM

Primary identity of interest:

- `svc_sql` — lab service account associated with the Kerberos detection scenario

## Timeline

| UTC Time | Host | User | Event | Evidence |
|---|---|---|---|---|
| Pending | WS01 | Pending | Suspicious PowerShell execution | PowerShell 4104 / Sysmon 1 |
| Pending | WS01 | Pending | LSASS process access | Sysmon 10 |
| Pending | DC01 | Pending | Kerberos service-ticket activity | Security 4769 |
| Pending | WS01 | Pending | Scheduled task creation/modification | Security 4698/4702 |
| Pending | WS01 | Pending | Security audit log cleared | Security 1102 |

## Evidence Sources

- PowerShell Operational Event ID 4104
- Sysmon Event ID 1
- Sysmon Event ID 10
- Windows Security Event ID 4769
- Windows Security Event IDs 4698 and 4702
- Windows Security Event ID 1102

## Analyst Reasoning

### PowerShell Execution

PowerShell Script Block Logging provides visibility into script contents, while Sysmon process creation provides process lineage and execution context. The main analyst question is whether the command reflects normal administration or execution behavior that is inconsistent with the user and host baseline.

### LSASS Access

Access to `lsass.exe` is sensitive because LSASS holds authentication material. A process-access event alone is not enough to conclude credential theft. The source process, access rights, user context, endpoint role, and surrounding process activity must be reviewed before escalating the event.

### Kerberos Activity

Windows Event ID 4769 records Kerberos service-ticket requests. In this lab, service-account ticket activity is examined for patterns consistent with Kerberoasting. Legitimate applications also request service tickets, so the account, service name, client address, encryption type, request frequency, and preceding endpoint activity must be considered together.

### Scheduled-Task Persistence

Scheduled task creation can be legitimate or malicious. The analyst should review the task name, creating account, executed command, parent process, timing, and relationship to earlier suspicious behavior.

### Security-Log Clearing

Security Event ID 1102 is a high-signal event because clearing the audit log directly affects forensic visibility. Legitimate administrators may occasionally clear logs, but the event becomes substantially more suspicious when it follows earlier execution, credential-access, and persistence activity.

## ATT&CK Mapping

| Activity | ATT&CK Technique | Tactic |
|---|---|---|
| Suspicious PowerShell | T1059.001 | Execution |
| LSASS access | T1003.001 | Credential Access |
| Kerberoasting | T1558.003 | Credential Access |
| Scheduled Task | T1053.005 | Persistence |
| Security log clearing | T1070.001 | Defense Evasion |

## False-Positive Analysis

Potential benign explanations include software-management tooling, endpoint security products, administrators using PowerShell, legitimate service authentication, software-created scheduled tasks, and authorized log maintenance.

The investigation therefore treats each alert as evidence to be correlated rather than proof of compromise by itself.

## Containment Strategy

For a real incident with this pattern, immediate containment would focus on isolating the affected endpoint, disabling or resetting compromised credentials, reviewing privileged group membership, preserving logs, and blocking confirmed malicious execution paths.

## Eradication and Recovery

Eradication would include removing unauthorized persistence, rotating exposed credentials, validating service-account configuration, restoring affected systems from a trusted state if required, and confirming that no related malicious activity remains.

Recovery would include returning systems to service in a controlled manner, maintaining enhanced monitoring, and validating that the detections continue to fire on known test behavior.

## Detection Gaps

This lab is limited to the telemetry intentionally collected. It does not include production EDR telemetry, cloud identity logs, enterprise DNS telemetry, proxy logs, or a full network-detection stack. Those sources could provide additional context and improve confidence during a real investigation.

## Conclusion

The final conclusion will be written after the five controlled attack simulations are executed and correlated using their actual timestamps and evidence. The goal is to show analyst reasoning from real lab telemetry rather than pre-writing a conclusion that the evidence has not yet proven.
