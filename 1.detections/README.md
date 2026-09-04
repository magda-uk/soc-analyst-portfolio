#  Detection Engineering & Logic

Welcome to the Detection Engineering section of my SOC Analyst portfolio. This directory showcases the complete lifecycle of how I research, build, and deploy detection logic for various adversary techniques.

## 📂 Directory Structure

To mirror a real-world Security Operations Center (SOC) workflow, this directory is split into three main phases:

*   **`1.threats/` (Threat Intelligence & Context):** The starting point. Contains the theoretical background, MITRE ATT&CK mapping, adversary behaviours, and baseline tuning (expected noise vs. malicious activity) for specific threats.
*   **`2.detection-logic/` (Development & Hunting):** The development phase. Contains the raw KQL (Kusto Query Language) or Sigma rules, explaining *how* the detection works, what logs are queried, and the logic behind the filters.
*   **`3.rules/` (Production Ready):** The final output. Contains the structured files (e.g., YAML, JSON) ready to be deployed into a SIEM like Microsoft Sentinel.

## 🎯 Threat Coverage Matrix

Below are the adversary techniques currently covered in this repository. 

| Threat Category | Technique | Status | Hands-on Investigation |
| :--- | :--- | :--- | :--- |
| **Process Injection (CreateRemoteThread)** | [T1055.001](./1.threats/createRemoteThread-injection/background-history.md#1-overview) | 🟢 Completed | [View Case](../3.log-analysis/sysmon/id8-electron-ipc-thread/id8-electron-ipc-thread.md#overview) |
| **Obfuscated PowerShell (Base64)** | [T1059.001 / T1027](./1.threats/powershell-encoded/threat-background.md#description) | 🟢 Completed | [View Case](../2.investigations/powershell-encoded.md#investigation-case) |
| **Registry Modification** | [T1112](./1.threats/registry-modification/threat-background.md#detection-rationale) | 🟢 Completed | [View Case](../3.log-analysis/sysmon/id13-registry-modification/multi-event-analysis.md#combined-multievent-analysis-shell-extensions-service-modification--appcompatflags) |
| **LSASS Credential Dumping** | [T1003.001](./1.threats/lsass-credential-access/README.md/) | 🟡 In Progress | *Coming Soon* |
| **Authentication Anomalies** | [T1078 / T1110](.//1.threats/authentication-anomalies/threat-background.md#authentication-anomalies-brute-force-impossible-travel-mfa-fatigue) | ⚪ Planned | *Coming Soon* |

---
*Note: For the practical triage, log analysis, and incident response of these threats, please visit the [3.log analysis](/3.log-analysis/README.md#-log-analysis--threat-triage) and [2.investigations](/2.investigations/README.md#️-investigations--threat-hunting) directory .*