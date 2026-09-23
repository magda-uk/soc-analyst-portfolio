# 🔻 SOC Projects & Threat Detection Labs

![Wazuh](https://img.shields.io/badge/Wazuh-00AEEF?style=for-the-badge&logoColor=white)
![Sysmon](https://img.shields.io/badge/Sysmon-4B275F?style=for-the-badge&logo=windows&logoColor=white)
![Python](https://img.shields.io/badge/Python-3776AB?style=for-the-badge&logo=python&logoColor=white)
![Microsoft Sentinel](https://img.shields.io/badge/Microsoft_Sentinel-0078D4?style=for-the-badge&logo=microsoft&logoColor=white)
![KQL](https://img.shields.io/badge/KQL-0050EF?style=for-the-badge&logo=microsoft-azure&logoColor=white)
![MITRE ATT&CK](https://img.shields.io/badge/MITRE_ATT%26CK-EF3B24?style=for-the-badge)
Welcome to the core projects section of my portfolio. 

This directory contains end-to-end laboratory environments, detection engineering use cases, and comprehensive threat investigations. 

My approach to these projects bridges **Security Operations** with **Software & Data Engineering**. 

Rather than executing attacks against empty virtual machines, I build realistic corporate environments, often simulating critical business operations such as supply chain Perpetual Inventory systems and Good Faith Receiving (GFR) data pipelines. 

This methodology allows me to demonstrate not just how a technical attack works, but how threats impact actual business assets and how a SOC must prioritise its response.

## 🔻 Current & Upcoming Investigations

### 🔻 [Enterprise SOC & Threat Triage (Wazuh + Sysmon)](./wazuh-lab/README.md/)
A fully configured detection environment designed to ingest host-level telemetry, validate correlation rules, and execute complete Blue Team triage.
* **Simulated Threats:** RDP Brute Force, Network Level Authentication (NLA) Evasion, Local Account Persistence.
* **Core Technologies:** Wazuh SIEM, Sysmon (SwiftOnSecurity baseline), Windows Security Event Logs.
* **Outcomes:** High-fidelity alert correlation, MITRE ATT&CK mapping, and actionable Incident Response (IR) reporting.

### 🔻 Ransomware Simulation & File Integrity Monitoring (FIM) *(In Progress)*
An active detection engineering project focusing on data destruction and integrity monitoring within a simulated corporate network.
* **Data Engineering Preparation:** Utilising Python to dynamically generate a realistic volume of logistics data, mimicking an active warehouse environment.
* **Threat Emulation:** Executing a custom ransomware encryption routine to trigger mass modification alerts.
* **Core Technologies:** Python, Wazuh FIM (syscheck module).
* **Outcomes:** Baseline noise suppression, FIM tuning, and critical alert triage during a mass-encryption event.

---
>*More projects focusing on Microsoft Sentinel, KQL threat hunting, and automated SOAR playbooks will be added progressively as part of my ongoing development toward SOC Analyst L1 roles.*

✍️ **Authored by:** Magda Dominguez  
*Security Operations • Detection Engineering • Blue Team*