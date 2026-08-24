# Investigation Case: Suspicious PowerShell Encoded Command (T1059.001)

## Summary
Initial triage of an alert triggered by the execution of an encoded PowerShell command. Encoded commands are frequently used to obfuscate malicious payloads, download scripts, or execute in‑memory attacks.

## Detection Trigger
Detection: PowerShell execution containing "-enc" or Base64‑encoded payloads.

## KQL Validation
(Insert KQL queries used to validate the alert.)

## Process Tree Analysis
(Identify parent process: e.g., winword.exe, outlook.exe, wscript.exe, explorer.exe.)

## User Behaviour
(Review user identity, role, recent sign‑ins, anomalies.)

## Network Activity
(Check outbound connections initiated by PowerShell.)

## Verdict
(Benign / Suspicious / Malicious)

## Escalation Notes
(If suspicious or malicious, include justification for escalation to L2.)
