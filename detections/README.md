# Detection Engineering

This directory contains the lab's five ATT&CK-mapped detections in two forms:

- `sigma/` contains vendor-neutral Sigma rules.
- `spl/` contains the Splunk searches used to validate the same behaviors in this environment.

| ID | Technique | Primary Log Source | Status |
|---|---|---|---|
| DET-001 | T1059.001 PowerShell | PowerShell 4104 / Sysmon 1 | Query written; lab validation pending |
| DET-002 | T1003.001 LSASS Memory | Sysmon 10 | Query written; lab validation pending |
| DET-003 | T1558.003 Kerberoasting | Security 4769 | Query written; lab validation pending |
| DET-004 | T1053.005 Scheduled Task | Security 4698/4702 | Query written; lab validation pending |
| DET-005 | T1070.001 Clear Windows Event Logs | Security 1102 | Query written; lab validation pending |

The rules are intentionally treated as starting points until they are tested against the lab's own telemetry. Final tuning notes, observed event counts, and false-positive analysis should be based on actual Splunk results rather than assumed values.
