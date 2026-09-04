# 🕵🏻‍♀️ Investigations & Threat Hunting

This directory contains detailed write-ups of security incidents, telemetry analysis, and threat hunting exercises. 

Each investigation outlines the initial alert, triage steps, evidence gathering (using tools like Sysmon and Event Viewer), MITRE ATT&CK mapping, and recommended response actions.

## ☑️ Completed Investigations

Here are the fully documented cases currently available for review:

### 1. [EDR Interception vs. OS Telemetry Gap (Sysmon Blindspot)](sysmon-blindspot.md)
*   **Focus:** Understanding telemetry gaps caused by kernel-level EDR prevention (Windows Filtering Platform).
*   **Techniques:** T1071.001 (Web Protocols), T1562.001 (Impair Defenses).
*   **Tools:** Microsoft Sysmon, Endpoint Security Logs.

### 2. [Suspicious PowerShell Encoded Command](powershell-encoded.md)
*   **Focus:** Triage and analysis of obfuscated PowerShell execution using Base64 encoding.
*   **Techniques:** T1059.001 (PowerShell), T1027 (Obfuscated Files or Information).
*   **Tools:** PowerShell Script Block Logging, Sysmon (Event ID 1), Base64 Decoding.


### 3. [False Positive Tuning: Lenovo Vantage OEM Telemetry](/2.investigations/sysmon-tuning-lenovo-vantage.md#-lenovo-vantage-noise-analysis)

- **Focus:** Baselining legitimate OEM software behaviour to reduce SIEM false positives and create high-fidelity detection exclusions.
- **Techniques:** Tuning benign behaviours that mimic T1055 (Process Injection).
- **Tools:** Microsoft Sysmon (Event IDs 1, 7, 8, 10), KQL Exclusion Logic.
---

## 🚧 Coming Soon (In Progress)

The following investigations are currently in the lab and will be published soon:

*   **Potential Credential Dumping:** Investigating unauthorized access to LSASS memory (T1003) and analyzing suspicious DLL injections.
*   **Authentication Anomalies:** Threat hunting for lateral movement and compromised credentials using Windows Security Event logs.

---
*Return to the [Main Portfolio Repository](../README.md).*