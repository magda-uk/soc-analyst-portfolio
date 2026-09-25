# 🛡️ SOC Analyst Portfolio 
## (Continuous Learning & Operations)

Hands-on Blue Team operations, multi-source investigations, detection engineering, and SOC-focused log analysis.

*_Translating real-world logistics investigations into Blue Team and SOC practices._*

<p align="left">
  <img src="https://img.shields.io/badge/Blue%20Team-SOC%20Analyst-blue?style=flat-square" alt="Blue Team SOC Analyst">
  <img src="https://img.shields.io/badge/Microsoft-Sentinel-0078D4?style=flat-square&logo=microsoft" alt="Microsoft Sentinel">
  <img src="https://img.shields.io/badge/Azure-Entra%20ID-0078D4?style=flat-square&logo=microsoftazure" alt="Azure Entra ID">
  <img src="https://img.shields.io/badge/Wazuh-SIEM-00AEEF?style=flat-square&logo=wazuh" alt="Wazuh SIEM">
  <img src="https://img.shields.io/badge/Sysmon-Event%20Analysis-purple?style=flat-square&logo=windows" alt="Sysmon Event Analysis">
  <img src="https://img.shields.io/badge/KQL-Queries-green?style=flat-square&logo=azuredataexplorer" alt="KQL Queries">
</p>

> ⚠️ **Recruiters & Hiring Managers:** Looking for an executive summary of my best work? Please visit my curated **[Blue Team & SOC Analyst Showcase](https://github.com/magda-uk/soc-analyst-showcase)**.

---

## ▫️The Engine Room: Blue Team & SOC Operations

This repository serves as my living knowledge base. While my *Showcase* highlights polished final reports, this repository is where the daily hands-on work happens. 

* 📈 **Living Archive:** Contains raw telemetry, configuration files, and daily exercises.
* 🔗 **MITRE Mapping:** All detections and hunts are strictly mapped to MITRE ATT&CK techniques.
* 🛡️ **Enterprise Tools:** Configured and queried using Sysmon, Sentinel, KQL, and Wazuh.
* 📚 **Full Spectrum:** Covering everything from baseline theory to advanced endpoint evasion.

---

## 📊 Knowledge Base Status

| Section | Focus Area | Status |
|---------|--------|----------|
| 🧪 [Detection Engineering](./1.detections/README.md) | Sigma & KQL Rule Creation | 🟢 Active |
| 🔎 [Investigations](/2.investigations/README.md) | Threat Triage & False Positive Tuning | 🟢 Active |
| 📊 [Log Analysis](./3.log-analysis/README.md) | Sysmon, PowerShell & Entra ID | 🟢 Active |
| 🕵️ [Threat Hunting](./4.hunting/README.md) | Playbooks for Credential & Cloud Identity Abuse | 🟢 Active |
| 🧩 [Security Labs](./5.projects/README.md) | Wazuh SIEM, FIM & Elastic Architecture | ✅ Deployed |
| 📝 [SOC Documentation](./6.documents/2.incident-response-workflow.md) | IR Workflows, Checklists & Methodologies | ✅ Established |
| 🧰 [Foundation Labs](./7.hands-on/README.md) | Core SOC Skills Bootcamp | ✅ 🟩🟩🟩🟩🟩🟩🟩 (7/7) |

---

## ▫️Featured Enterprise Lab: Wazuh SIEM & Sysmon Operations
* **Summary:** An end-to-end detection engineering lab simulating adversary tactics mapped to MITRE ATT&CK. I built the architecture to monitor host telemetry via Sysmon and the Wazuh agent, writing custom correlation rules for active attacks.
* **Tech Stack:** Wazuh Server (Ubuntu), Windows 10/11 Endpoint, Kali Linux, PowerShell, Ncrack, xfreerdp.
* **Executed Scenarios:**
  * Network Level Authentication (NLA) Evasion & RDP Brute Force (Event ID 4625).
  * Ransomware Emulation targeting Logistics Data via Python payloads.
  * File Integrity Monitoring (FIM / Syscheck) for mass encryption detection.
* 🔗 **[View Lab Architecture & Full Telemetry Documentation](/5.projects/wazuh-lab/README.md)**

---

## ▫️Core Log Analysis & Threat Hunting

*As my workflow evolves, advanced investigations are continuously consolidated into the [3.log-analysis](3.log-analysis/README.md) and [2.investigations](./2.investigations/README.md) directories.*

### ⚙️ Incident Analysis & Triage
* **[Threat Hunting: OS Credential Dumping & Data Exfiltration (T1003 & T1048)](./2.investigations/06-true-positive-procdump-exfiltration.md)**
* **[Cloud Identity: Impossible Travel & MFA Anomalies](./3.log-analysis/entra-id/EntraID-Impossible-Travel.md)**
* **[LSASS Credential Dumping via Mimikatz (Sysmon Event ID 10)](./3.log-analysis/sysmon/id10-lsass-access/evtx-mimikatz-lsass-access.md)**
* **[Suspicious PowerShell Encoded Command (T1059.001)](./2.investigations/02-threat-hunt-powershell.md)**
* **[EDR Interception vs. OS Telemetry Gap (Sysmon Blindspot)](./2.investigations/01-sysmon-edr-blindspot.md)**

### ⚙️ Detection Engineering & Alert Tuning
*  **[Special Privileges Assigned (Windows Event ID 4672)](./3.log-analysis/windows-events/4672-privilege-special-assigned.md)**
*  **[Event ID 4798: High-Velocity Group Enumeration (False Positive)](./2.investigations/04-false-positive-event4798.md)**
* **[False Positive Tuning: Lenovo Vantage OEM Telemetry](./2.investigations/03-tuning-lenovo-vantage.md)**
* **[Registry Modification & Persistence (Sysmon Event ID 13)](/3.log-analysis/sysmon/id13-registry-modification/multi-event-analysis.md)**

---

## ▫️Technology & Tools Stack

**SIEM & Telemetry:** 
Wazuh, Microsoft Sentinel, Elastic Security, Sysmon (SwiftOnSecurity Baseline), Windows Event Logs, Sysmon Event ID correlation.

**Identity & Cloud:** 
Azure AD / Microsoft Entra ID (Sign-in logs, Audit logs, MFA analysis).

**Analysis & Querying:** 
Kusto Query Language (KQL), Sigma Rules, Wireshark, Event Viewer.

**Offensive / Emulation (Red to Blue):** 
Kali Linux, Nmap, Ncrack, xfreerdp, PowerShell ScriptBlock Execution, Custom Python Payloads (Ransomware FIM emulation).

---

## ▫️Purpose & Methodology

This portfolio brings together my hands-on SOC training and the investigative skills I developed in a high-volume logistics environment. 

The same methodology I used to analyse perpetual inventory discrepancies, validate multi-source data, and reconstruct supply chain timelines now underpins my approach to detection engineering, log analysis, and structured SOC investigations.

---

## ▫️Connect with me
I’m always improving this portfolio as I grow in my SOC Analyst journey. If you have suggestions or ideas that could make it stronger, I’d be glad to hear them.

🔗 **LinkedIn:** [linkedin.com/in/magda-d-infosec](https://linkedin.com/in/magda-d-infosec)

---

## ▫️Author

**Magda Dominguez**  
*SOC Analyst (L1) - Bristol, UK*  
Blue Team operations | SOC investigations | Logistics-to-SOC analytical mindset