## 🔐 Day 4: Authentication & Identity Telemetry (Entra ID)
**Tools:** Microsoft Entra ID (`SigninLogs`, `AuditLogs`), Azure Data Explorer (ADX), KQL  
**Focus:** Investigating identity anomalies, impossible travel alerts, brute-force spikes, and compromised session tokens (AiTM).

### 🔗 Case Study & Telemetry Analysis
* **[View Full Case Study & Lab Documentation](/3.log-analysis/entra-id/EntraID-Impossible-Travel.md)** 🔥
  * Complete triage of an Impossible Travel attack targeting a corporate logistics account.
  * KQL query implementation for brute-force spike isolation in [Azure Data Explorer](https://dataexplorer.azure.com/).
  * Technical mapping of MITRE ATT&CK techniques (T1110, T1078, T1566).

### 🔖 Advanced Practice & Planned Extensions (SOAR / Playbooks)
* ⏳ **Future Standalone Project (In Planning):** Implementation of an Azure Logic App (SOAR Playbook) to automatically trigger session revocations and user account containment upon detecting high-risk Impossible Travel signals in Entra ID. *(This will be documented in the `/5.projects/` directory once completed).*