
----

## 🔐 Day 4: Authentication & Identity Telemetry (Hybrid: AD & Entra ID)
**Tools:** Windows Security Event Log, Microsoft Entra ID (`SigninLogs`), Azure Data Explorer (ADX), KQL  
**Focus:** Investigating hybrid identity anomalies, ranging from local RDP brute-force attacks to cloud-based impossible travel and compromised session tokens.

### 📂 Case Studies & Lab Documentation
* **[Case Study 1: Endpoint Brute-Force & Authentication Analysis.](/3.log-analysis/windows-events/endpoint-authentication-analysis.md#security-event-analysis-endpoint-authentication--session-telemetry-event-id-4625--4624)** 
  * Triage of Event IDs 4625 and 4624 to confirm interactive RDP compromise.
* **[Case Study 2: Cloud Identity Impossible Travel & AiTM](/3.log-analysis/entra-id/EntraID-Impossible-Travel.md#-scenario-overview)** 🔥
  * KQL-driven investigation of multi-region brute-force spikes and session token compromise.


## ✅ Basic Practice (On-Premises Identity)

- **Audit Local Logon Events:** Analyse Windows Security Event logs for interactive and network authentication attempts:
  - **Event ID 4625 (Failed Logon):** Identify credential probing and analyze sub-status codes (e.g., `0xC000006A` for incorrect passwords and `0xC0000064` for invalid usernames).
  - **Event ID 4624 (Successful Logon):** Correlate with preceding events to validate expected system sessions (e.g., Service logons) or identify anomalous access.
- **Logon Type Analysis:** Differentiate access vectors by reviewing Logon Types (e.g., Type 2 - Interactive for physical access vs. Type 3 - Network for SMB probes), while understanding environment constraints (e.g., Type 10 - RemoteInteractive restrictions).

### 🚀 Advanced Practice (Cloud Identity & KQL)
- **Cloud Identity Telemetry:** Parse Microsoft Entra ID `SigninLogs` to decode authentication error codes (`50126`, `50140`).
- **KQL Query Development:** Write and execute Kusto queries in Azure Data Explorer to group sign-in events into 5-minute time bins (`bin`), successfully isolating brute-force spikes and anomalous proxy infrastructure.
- **Impossible Travel & Geo-Velocity:** Correlate disparate IP addresses and geolocation metadata to uncover distributed credential compromise (e.g., AiTM session hijacking).
- **Threat Technique Mapping:** Map behaviors to **MITRE ATT&CK** (T1110 Brute Force, T1078 Valid Accounts, T1566 Phishing).

### 🔖 Advanced Practice & Planned Extensions (SOAR / Playbooks)
* ⏳ **Future Standalone Project (In Planning):** Implementation of an Azure Logic App (SOAR Playbook) to automatically trigger session revocations and user account containment upon detecting high-risk Impossible Travel signals in Entra ID. *(This will be documented in the `/5.projects/` directory once completed).*

### 🎯 Learning Outcome
Master hybrid identity triage by transitioning seamlessly from traditional Active Directory event log correlation to advanced cloud identity hunting using analytical KQL queries.

### 🛡️ Why it Matters for Blue Team
Identity is the modern security perimeter. Threat actors frequently pivot from local endpoints to cloud infrastructure (and vice versa). Analyzing both local RDP brute-force attempts and cloud-based proxy infrastructure provides complete, end-to-end visibility for the modern SOC analyst.