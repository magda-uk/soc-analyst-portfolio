# 0. Hands-On Evidence

## 🎯 Purpose
This folder contains all hands-on SOC investigations performed during the development of this portfolio.  
It includes real Sysmon events, screenshots, and multi-event analyses generated during practical exercises.

---

## 📌 Current Status
The folder is operational and currently includes evidence for:
* [registry-modification-multi-event-analysis.md](registry-modification/registry-modification-multi-event-analysis.md)  
Multi-event Sysmon analysis and screenshots documenting suspicious registry changes.
* [createRemoteThread.md](createRemoteThread/createRemoteThread.md)  
Sysmon Event ID 8 evidence showing legitimate CreateRemoteThread behaviour by WerFault during Windows diagnostics.

>Additional evidence for other threat categories will be added progressively as new investigations are completed.

> This section grows over time as more hands-on practice is performed.

---

## 📁 Structure
Each subfolder corresponds to a threat category from `1.detections/`.

Inside each folder you may find:
* **Multi-Event Analysis:** Breakdown of how the behaviour appears across Sysmon events.
* **Screenshots:** Visual artefacts from Sysmon, Wireshark, or Windows Event Viewer.
* **Raw Evidence:** Extracted logs or supporting files (when applicable).
* **Investigation Notes:** Short explanations of observations and SOC relevance.

---

## 🔄 Continuous Expansion
As learning progresses, new evidence folders will be added (e.g., LSASS access, authentication anomalies, PowerShell abuse).  
This section is designed to reflect real SOC analyst growth through practical investigation.
