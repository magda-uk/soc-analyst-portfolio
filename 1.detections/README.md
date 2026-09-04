#  Detection Engineering & Logic

Welcome to the Detection Engineering section of my SOC Analyst portfolio. This directory showcases the complete lifecycle of how I research, build, and deploy detection logic for various adversary techniques.

##  Directory Structure

To mirror a real-world Security Operations Center (SOC) workflow, this directory is split into three main phases:

*   **`1.threats/` (Threat Intelligence & Context):** The starting point. Contains the theoretical background, MITRE ATT&CK mapping, adversary behaviours, and baseline tuning (expected noise vs. malicious activity) for specific threats.
*   **`2.detection-logic/` (Development & Hunting):** The development phase. Contains the raw KQL (Kusto Query Language) or Sigma rules, explaining *how* the detection works, what logs are queried, and the logic behind the filters.
*   **`3.rules/` (Production Ready):** The final output. Contains the structured files (e.g., YAML) ready to be deployed into a SIEM like Microsoft Sentinel.




---

##  Detection Lifecycle Matrix

Below is the master tracking matrix showing the end-to-end development of each detection, from initial research to the final SIEM rule.

| Threat Category | Technique | 1. Threat Intel | 2. Detection Logic | 3. SIEM Rule | Status |
| :--- | :--- | :--- | :--- | :--- | :--- |
| **Process Injection (CreateRemoteThread)** | T1055.001 | 📖 [Research](./1.threats/createRemoteThread-injection/background-history.md#1-overview)  | 🛠️ *Pending* |  [KQL Rule](./3.rules/sentinel/create-remote-thread-injection.kql) | 🟡 Dev|
| **Obfuscated PowerShell (Base64)** | T1059.001 | 📖 [Research](./1.threats/powershell-encoded/threat-background.md#description) | 🛠️ [ Logic](./2.detection-logic/powershell-encoded.md#detection-logic-conceptual) |  [YAML Rule](/1.detections/3.rules/sigma/suspicious-powershell-execution.yml) | 🟢 Done |
| **Registry Modification** | T1112 | 📖 [Research](./1.threats/registry-modification/threat-background.md#detection-rationale) | 🛠️ *Pending*  |  *Pending* | ⚪ Planned |
| **LSASS Credential Dumping** | T1003.001 | 📖 [Research](./1.threats/lsass-credential-access/README.md/) | 🛠️ [ Logic](./2.detection-logic/LSASS-credential-dumping.md#detection-logic-lsass-credential-dumping) | [KQL Rule](./3.rules/sentinel/lsass-credential-dumping.kql) [EQL Rule](/1.detections/3.rules/elastic/lsass-credential-dumping.eql) |  🟢 Done |
| **Authentication Anomalies** | T1078/T1110 | 📖 [Research](.//1.threats/authentication-anomalies/threat-background.md#authentication-anomalies-brute-force-impossible-travel-mfa-fatigue) | 🛠️ *Pending* |  *Pending* | ⚪ Planned |

---
*Note: For the practical triage, log analysis, and incident response of these threats, please visit the [3.log analysis](/3.log-analysis/README.md#-log-analysis--threat-triage) and [2.investigations](/2.investigations/README.md#️-investigations--threat-hunting) directory .*
