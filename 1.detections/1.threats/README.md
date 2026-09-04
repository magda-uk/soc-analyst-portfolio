# Threat Intelligence & Context

Welcome to the **Threat Intelligence** phase of my Detection Engineering lifecycle. 

Before writing any detection logic (like KQL or Sigma rules), it is critical to deeply understand the adversary's behavior. This directory serves as the foundation for all detections built in this repository.

##  Purpose

In this folder, I analyse specific attack techniques to define:

🔸   **The "How":** Detailed breakdown of how adversaries execute the attack.

🔸  **MITRE ATT&CK Mapping:** Tactic and Technique categorization.

🔸  **Benign Behavior & Tuning:** Identifying legitimate system noise (like Windows Error Reporting or OEM telemetry) that mimics the attack, ensuring our future rules are high-fidelity and produce minimal false positives.

##  Investigated Threats

Navigate through the folders below to read the research and context behind each detection:

| Threat Category | Technique | Status | Hands-on Investigation |
| :--- | :--- | :--- | :--- |
| **Process Injection (CreateRemoteThread)** | [T1055.001](./1.threats/createRemoteThread-injection/background-history.md#1-overview) | 🟢 Completed | [View Case](../3.log-analysis/sysmon/id8-electron-ipc-thread/id8-electron-ipc-thread.md#overview) |
| **Obfuscated PowerShell (Base64)** | [T1059.001 / T1027](./1.threats/powershell-encoded/threat-background.md#description) | 🟢 Completed | [View Case](../2.investigations/powershell-encoded.md#investigation-case) |
| **Registry Modification** | [T1112](./1.threats/registry-modification/threat-background.md#detection-rationale) | 🟢 Completed | [View Case](../3.log-analysis/sysmon/id13-registry-modification/multi-event-analysis.md#combined-multievent-analysis-shell-extensions-service-modification--appcompatflags) |
| **LSASS Credential Dumping** | [T1003.001](./1.threats/lsass-credential-access/README.md/) | 🟢 Completed| *Coming Soon* |
| **Authentication Anomalies** | [T1078 / T1110](.//1.threats/authentication-anomalies/threat-background.md#authentication-anomalies-brute-force-impossible-travel-mfa-fatigue) | 🟡 In Progress| *Coming Soon* |



*Once the threat is understood, the actual detection code is developed in the [2.detection-logic](../2.detection-logic/) directory.*

---