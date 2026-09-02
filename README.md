

#  SOC Analyst Portfolio

Hands-on Blue Team operations, multi-source investigations, detection engineering, and SOC-focused log analysis.

*_Translating real-world logistics investigations into Blue Team and SOC practices._*


<p align="left">
  <img src="https://img.shields.io/badge/Blue%20Team-SOC%20Analyst-blue?style=flat-square" alt="Blue Team SOC Analyst">
  <img src="https://img.shields.io/badge/Microsoft-Sentinel-0078D4?style=flat-square&logo=microsoft" alt="Microsoft Sentinel">
  <img src="https://img.shields.io/badge/Azure-Entra%20ID-0078D4?style=flat-square&logo=microsoftazure" alt="Azure Entra ID">
  <img src="https://img.shields.io/badge/Elastic-Security-005571?style=flat-square&logo=elastic" alt="Elastic Security">
  <img src="https://img.shields.io/badge/Sigma-Detection%20Rules-orange?style=flat-square" alt="Sigma Detection Rules">
  <img src="https://img.shields.io/badge/Sysmon-Event%20Analysis-purple?style=flat-square" alt="Sysmon Event Analysis">
  <img src="https://img.shields.io/badge/KQL-Queries-green?style=flat-square" alt="KQL Queries">
  <img src="https://img.shields.io/badge/Work%20in%20Progress-Active-yellow?style=flat-square" alt="Work in Progress">
</p>

---

## 📌 Central Hub : Blue Team & SOC operations

- ✨ *Regular Content:* New detections, analysis and practical cases each week
- 📈 *Gradual Evolution:* Empty folders you see will be filled with real evidence and practical exercises
- 🔗 *MITRE Mapping:* Each detection mapped to MITRE ATT&CK techniques
- 🛡️ *Real Tools:* Based on Sysmon, Microsoft Sentinel, Elastic Stack, Wazuh
- 📚 *Comprehensive Documentation:* From theory through to practical investigation

> This is a *live project* in constant evolution. New content, practical cases, detections and analysis are added regularly as I progress in my training as a SOC Analyst. 

> *Last updated:* September 2026

---
## 📊 Project Status

| Section | Status | Progress |
|---------|--------|----------|
| 📚 [Theory](./0.therory/glossary.md) | ✅ Foundation | Glossary completed |
| 🧪 [Detection Engineering](./1.detections/README.md) | 🔄 Active | Structure + theory, practical cases in development |
| 🔎 [Investigations](.//2.investigations/powershell-encoded.md) | 🔄 Active | 3 documented cases |
| 📊 [Log Analysis](./3.log-analysis/README.md) | 🔥 Highly Active | Sysmon (IDs 1, 2, 3, 8, 10,11,13,15,22), PowerShell (4104) & Auth triage |
| 🕵️ [Threat Hunting](./4.hunting/README.md) | ⏳ Coming Soon | Structure ready, content in development |
| 🧩 [Security Labs](./5.projects/README.md) | ⏳ Getting Started | Sysmon Lab, Elastic Stack, Wazuh Lab |
| 📝 [SOC Documentation](./6.documents/2.incident-response-workflow.md) | ✅ Foundation | Guides, methodology and checklists |
| 🧰 [Hands-On Labs](./7.hands-on/README.md) | 🔄 Active | 🟩🟩⬜⬜⬜⬜⬜⬜ (2/8 Completed) |

---

## 🛣️ Foundation Roadmap (7 Days)

Beginner-friendly labs designed to build core SOC skills:

* Sysmon baseline
* Suspicious Sysmon + Wireshark
* PowerShell ScriptBlock logging
* Authentication triage
* Process tree analysis
* MITRE ATT&CK mapping
* End-to-end mini investigation

📁 **Stored in:** [`7.hands-on`](7.hands-on/)

---
## ✨ Advanced Hands-On Labs & Log Analysis

As I progressed, some topics required deeper investigation than the foundation roadmap allowed. This section highlights my most advanced, realistic, and multi-event SOC triage cases.

It is a **highly active** project, updated regularly as I dive deeper into Blue Team operations and telemetry analysis.

### 🔥 Featured Advanced Investigations

- **Registry Modification & Persistence (Sysmon Event ID 13)** 

  *Triaging registry changes to identify potential malware persistence mechanisms or configuration tampering.*

  → Full Triage: [`multi-event-analysis.md`](./3.log-analysis/sysmon/id13-registry-modification/multi-event-analysis.md)

- **False Positive Validation: DWM to CSRSS (Sysmon Event ID 8)**

  *Documenting the normal behavior of Windows GUI subsystem thread creation to tune out process injection alerts.*

  → Full Triage: [`sysmon-8-dwm-csrss.md`](./3.log-analysis/sysmon/id8-multi-event/sysmon-8-dwm-csrss.md)

- **Network Telemetry: DNS Queries & CDN Traffic (Sysmon Event ID 22)**

  *Triaging background DNS requests to differentiate legitimate software traffic from potential C2 beaconing.*

  → Full Triage: [`sysmon-id22-webview2-analysis.md`](./3.log-analysis/sysmon/id22-dns-queries/sysmon-id22-webview2-analysis.md)

- **PowerShell Script Block Logging (Event 4104)** 🚧

  *Deobfuscation and analysis of encoded command executions.*

  → Triage notes: [`event4104-powershell-scriptblock-analysis.md`](./3.log-analysis/powershell/event4104-powershell-scriptblock-analysis.md)

> ⚠️ *Note: As my workflow evolves, advanced investigations are being consolidated into the `3.log-analysis` and `2.investigations` directories for a more streamlined SOC structure.*


> *More advanced labs will be added as I explore LSASS access, PowerShell abuse, authentication anomalies, and network-based hunting.*


---

## 🗺️ Repository Structure

### 🧪 Detection Engineering
Production-style detection rules written in YAML and KQL for:
* Microsoft Sentinel
* Elastic
* Sigma (generic format)

Each rule includes MITRE mapping, entity mappings, investigation notes and response guidance.  
📂 [`1.detections`](1.detections/)

### 🔎 Investigations
SOC-style investigations including timelines, triage notes, log evidence and MITRE mapping.  
📂 [`2.investigations`](2.investigations/)
### 📊 Log Analysis
Hands-on log analysis exercises covering Sysmon, PowerShell, authentication patterns and credential access behaviour.  
📂 [`3.log-analysis`](3.log-analysis/)

### 🕵️ Threat Hunting
Behavioural hunting playbooks, anomaly detection and pattern-based hunting.  
Each hunting case includes:
* Hypothesis
* Behavioural indicators
* Sysmon evidence
* KQL hunting queries
* MITRE mapping
* Triage notes
* Investigation guidance  
📂 [`4.hunting`](4.hunting/)

### 🧩 Security Labs
Larger SOC projects designed to build practical skills in detection engineering, log analysis, KQL and incident documentation.  
📂 [`5.projects`](5.projects/) *(Current project: Sysmon Lab Environment)*

### 📝 SOC Documentation
Operational documentation used in real SOC teams:
* SOC methodology
* Incident response workflow
* MITRE mapping guide
* Alert severity framework
* Response playbooks
* Runbooks  
📂 [`6.documents`](6.documents/)

### 🧰 Hands-On Labs
Practical SOC exercises including Sysmon baseline, suspicious activity, ScriptBlock logging, authentication triage, MITRE mapping and end-to-end investigations.  
📂 [`7.hands-on`](7.hands-on/) *(Updated daily)*

---

## 🛠️ Technologies Used

**Technologies Used:** Sysmon, Windows Event Logs, Event Viewer, PowerShell, Wireshark, KQL (Microsoft Sentinel), Sigma, Sysmon configuration (SwiftOnSecurity).

**Planned Technologies:** Entra ID (Azure AD), Microsoft Sentinel (full deployment), Wazuh, Elastic Security.


---


## 🎯Purpose

This portfolio brings together my hands-on SOC training and the investigative skills I developed in a high-volume logistics environment. 

The same methods I used to analyse discrepancies, validate multi-source data, and reconstruct timelines now underpin my approach to detection engineering, log analysis, and structured SOC investigations.


---


## 📬Feedback
I’m always improving this portfolio as I grow in my SOC Analyst journey. If you have suggestions or ideas that could make it stronger, I’d be glad to hear them.





🔗 **LinkedIn:** [linkedin.com/in/magda-d-infosec](https://linkedin.com/in/magda-d-infosec)

---

## 🪪 Author

**Magda Dominguez**  
*SOC Analyst (L1-ready) - Bristol, UK*  
Blue Team operations | SOC investigations | Logistics-to-SOC analytical mindset

---

---
