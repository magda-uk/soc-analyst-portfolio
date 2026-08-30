![Sysmon](https://img.shields.io/badge/Sysmon-Endpoint%20Telemetry-blue)
![PowerShell](https://img.shields.io/badge/PowerShell-Logging-lightgrey)
![Wireshark](https://img.shields.io/badge/Wireshark-Packet%20Analysis-1679A7)
![MITRE ATT&CK](https://img.shields.io/badge/MITRE%20ATT%26CK-Tactics%20%26%20Techniques-red)
![Microsoft Entra ID](https://img.shields.io/badge/Microsoft%20Entra%20ID-Identity%20Logs-purple)
![Windows Logs](https://img.shields.io/badge/Windows-Event%20Logs-green)

# 🛣️ SOC Analyst Hands-On Roadmap
A practical, structured, and progressive training path designed to build real SOC L1 / Blue Team capability.  
This directory documents seven consecutive days of hands-on exercises, each targeting a core operational discipline in modern Security Operations Centres.

---

## 🎯 Purpose of this Hands-On Block
This section demonstrates **practical analytical capability** through reproducible telemetry analysis.  
Across seven days, realistic endpoint and identity attack paths are simulated and investigated using Sysmon, Windows Event Logs, PowerShell ScriptBlock logging, Wireshark, Microsoft Entra ID, and MITRE ATT&CK.

Each module includes:
- **Foundational Practice** (baseline telemetry capture and normalisation)
- **Advanced Investigation** (threat detection, payload decoding, and triage)
- **Key Learning Outcomes**
- **Blue Team Operational Relevance**

---
### 📊 Roadmap Status Tracker

| Day | Module / Topic | Status | Link |
| :--- | :--- | :--- | :--- |
| **Day 1** | Sysmon Baseline & Telemetry Validation | ✅ `Completed` | [View Lab](./day1-sysmon-basics/) |
| **Day 2** | Sysmon Suspicious Activity & Wireshark PCAP | ✅ `Completed` | [View Lab](./day2-sysmon-suspicious/) |
| **Day 3** | PowerShell ScriptBlock Logging & Obfuscation | 🚧 `In Progress / Coming Soon` | — |
| **Day 4** | Authentication & Identity Telemetry (Entra ID) | ⏳ `Planned` | — |
| **Day 5** | Process Trees & Attack Chain Reconstruction | ⏳ `Planned` | — |
| **Day 6** | MITRE ATT&CK Threat Mapping | ⏳ `Planned` | — |
| **Day 7** | Comprehensive Incident Triage & Reporting | ⏳ `Planned` | — |


## 🔍 Day 1: Sysmon Baseline
**Tools:** Sysmon, Windows Event Viewer  
**Focus:** Understanding normal endpoint behavior and system baseline creation.

### ✅ Basic Practice
- Deploy Sysmon with a modular baseline configuration.
- Analyze core host events:
  - **Event ID 1:** Process Creation
  - **Event ID 3:** Network Connection
  - **Event ID 11:** File Create
- Document normal system binaries, default execution paths, and standard command-line parameters.

### 🚀 Advanced Practice
- Identify deviations from verified operational baselines.
- Detect abnormal parent-child process relationships (e.g., non-standard processes spawned by system shells).
- Spot unquoted service paths and binaries executing from non-standard user directories (`Temp`, `AppData`).

###  Learning Outcome
Establish the ability to distinguish **normal administrative noise from genuine suspicious activity**, the core skill in SOC triage.

### 🛡️ Why it Matters for Blue Team
Fast, high-fidelity alert triage relies entirely on understanding what normal operating system activity looks like.

---

## 🦈 Day 2: Sysmon Suspicious Activity & Network Correlation
**Tools:** Sysmon, Event Viewer, Wireshark  
**Focus:** Detecting suspicious execution and correlating host telemetry with packet-level network data.

### ✅ Basic Practice
- Identify suspicious PowerShell command executions and parameters.
- Inspect outbound socket establishments across atypical ports and LOLBins.
- Capture network traffic using Wireshark to observe handshake mechanics (TCP SYN, HTTP, TLS).

### 🚀 Advanced Practice
- Execute a correlated multi-stage telemetry chain:
  - Process Launch (`Event ID 1`)
  - Runtime Engine Validation (`Event ID 11`)
  - Outbound Egress (`Event ID 3`)
- Correlate Sysmon socket events with full Wireshark PCAP HTTP streams (`GET`, `User-Agent`, `Server Header`).
- Distinguish legitimate OS runtime artifacts from malicious tool staging.

###  Learning Outcome
Reconstruct suspicious execution chains end-to-end using host-level telemetry and network-level packet verification.

### 🛡️ Why it Matters for Blue Team
Bridging endpoint logs with network captures eliminates blind spots, validates potential C2/staging beacons, and confirms whether network payloads were successfully delivered.

---

## 💻 Day 3: PowerShell ScriptBlock Logging & Obfuscation
**Tools:** PowerShell ScriptBlock Logging (EID 4104), Base64 Decoding  
**Focus:** Analyzing adversary execution techniques and de-obfuscating living-off-the-land commands.

### ✅ Basic Practice
- Enable and configure PowerShell ScriptBlock Logging via Group Policy / Registry.
- Compare standard administrative commands against suspicious command-line flags (`-EncodedCommand`, `-NoProfile`, `-NonInteractive`).
- Identify common adversary download strings and web clients (`DownloadString`, `Invoke-Expression`).

### 🚀 Advanced Practice
- Extract and decode nested Base64 strings to reveal raw command payloads.
- Analyze string manipulation and environment variable substitution obfuscation techniques.
- Reconstruct complete operational intent from fragmented ScriptBlock logs.

###  Learning Outcome
Gain deep analytical proficiency in triage and payload analysis of PowerShell, the most abused shell in Windows environments.

### 🛡️ Why it Matters for Blue Team
Adversaries heavily rely on PowerShell for initial execution, LOLBins exploitation, and fileless persistence. Decoupling obfuscation is mandatory for Tier 1 SOC analysts.

---

## 🔐 Day 4: Authentication & Identity Telemetry
**Tools:** Windows Security Event Log, Microsoft Entra ID (Azure AD)  
**Focus:** Investigating identity anomalies, failed authentication sprees, and sign-in telemetry.

### ✅ Basic Practice
- Audit logon events:
  - **Event ID 4624:** Successful Logon
  - **Event ID 4625:** Failed Logon
- Review Logon Types (e.g., Type 2 - Interactive, Type 3 - Network, Type 10 - RemoteInteractive).
- Interpret MFA challenge flows and sign-in status codes.

### 🚀 Advanced Practice
- Detect distributed password spraying patterns vs single-account brute-force attacks.
- Investigate Impossible Travel alerts using IP geolocation, ISP telemetry, and user-agent metadata.
- Assess risk levels in Entra ID sign-in telemetry and service principal access.

###  Learning Outcome
Master identity triage across hybrid on-premises Active Directory and cloud identity providers.

### 🛡️ Why it Matters for Blue Team
Identity is the modern security perimeter. Most initial compromises leverage credential access or identity misuse.

---

## 🌳 Day 5: Process Trees & Attack Chain Reconstruction
**Tools:** Sysmon, Process Explorer / Process Hacker  
**Focus:** Visualising process lineage and isolating anomalous execution hierarchies.

### ✅ Basic Practice
- Map parent-child process relationships (`ParentImage` vs `Image`).
- Identify anomalies in system hierarchy (e.g., `spoolsv.exe` or `explorer.exe` launching shells).

### 🚀 Advanced Practice
- Reconstruct an end-to-end simulated kill chain:
  - Ingress/Execution $\rightarrow$ Dropper Staging $\rightarrow$ Persistence $\rightarrow$ Outbound C2
- Document process trees with PID, PPID, and user SID tracking to uncover masquerading techniques.

###  Learning Outcome
Develop the ability to tell the full technical story of an incident rather than viewing logs as isolated events.

### 🛡️ Why it Matters for Blue Team
Threat actors operate in multi-step sequences. A SOC analyst must trace backward to the root cause (initial access) and forward to the blast radius.

---

## 🎯 Day 6: MITRE ATT&CK Threat Mapping
**Tools:** MITRE ATT&CK Framework, Sysmon, Sigma Rules  
**Focus:** Classifying observable log telemetry into standardized adversary tactics and techniques.

### ✅ Basic Practice
- Map common Sysmon events to Enterprise ATT&CK techniques (e.g., T1059, T1105, T1071).
- Navigate the MITRE ATT&CK Matrix across tactics from Initial Access to Impact.

### 🚀 Advanced Practice
- Build an observed-technique coverage matrix for analyzed lab attacks.
- Write detection descriptions using standardized MITRE terminology.
- Map detection logic (Sigma / YARA-L rules) to corresponding ATT&CK Technique IDs.

###  Learning Outcome
Adopt the universal cybersecurity taxonomy to communicate findings clearly with incident responders and engineering teams.

### 🛡️ Why it Matters for Blue Team
MITRE ATT&CK provides the standard framework for detection engineering, SOC reporting, and gap analysis.

---

## 🕵️ Day 7: Comprehensive Incident Triage & Reporting
**Tools:** Combined SOC Toolkit (Sysmon, Event Logs, Wireshark, MITRE)  
**Focus:** End-to-end forensic triage, incident documentation, and remediation guidance.

### ✅ Basic Practice
- Pivot from an initial SIEM-style alert to correlated log sources.
- Reconstruct an chronological incident timeline.

### 🚀 Advanced Practice
- Author a formal SOC Incident Report covering:
  - Executive Summary
  - Chronological Attack Timeline
  - Technical Evidence & Correlated Artifacts
  - MITRE ATT&CK Mapping
  - Root Cause Analysis & Containment Recommendations
- Draft a targeted triage runbook for similar future detections.

###  Learning Outcome
Execute the complete incident lifecycle from initial detection to actionable, professional reporting.

### 🛡️ Why it Matters for Blue Team
Demonstrates direct job-readiness by translating raw technical logs into structured, professional intelligence for stakeholders.

---

## 🧪 Laboratory Environment & Replication
To reproduce these exercises:
1. **Host Environment:** Windows 10/11 Enterprise Virtual Machine.
2. **Endpoint Sensor:** Sysmon installed with a refined modular configuration.
3. **Audit Policies:** Advanced Audit Policies enabled (Process Creation, ScriptBlock Logging EID 4104).
4. **Network Sensor:** Wireshark installed with Npcap for raw packet capture.
5. **Identity Tenant:** Microsoft Entra ID (Free Tier / Developer Sandbox).
6. **Documentation:** Markdown documentation supported by uncompressed forensic screenshots.

---

## 📌 Executive Summary of Capabilities
This hands-on track forms the foundation of my Blue Team portfolio, proving core competency in:

* **Endpoint Telemetry:** Deep understanding of host monitoring, process creation anomalies, and system baseline deviations.
* **Network & PCAP Forensics:** Ability to validate host-level alerts with packet captures and HTTP stream inspection.
* **Identity Investigation:** Authentication triage across Active Directory and Microsoft Entra ID telemetry.
* **PowerShell De-obfuscation:** ScriptBlock analysis to combat Living-off-the-Land (LotL) and fileless execution.
* **Threat Classification:** Applying MITRE ATT&CK taxonomy to structure technical evidence.
* **Incident Reporting:** Delivering structured, evidence-backed forensic reports for SOC operations.

---

### ✍️ **Author**
**Magda Dominguez**  
*Security Operations • Detection Engineering • Blue Team*