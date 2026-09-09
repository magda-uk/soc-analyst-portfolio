# Log Analysis: Anomalous Cloud Sign-ins & Impossible Travel (Entra ID)

## 📌 Scenario Overview
* **Event Source:** Microsoft Entra ID (Sign-in Logs)
* **Techniques:** [T1110](/0.therory/glossary.md#-mitre-attck-techniques-common-in-this-portfolio) (Brute Force), [T1078](/0.therory/glossary.md#-mitre-attck-techniques-common-in-this-portfolio) (Valid Accounts), [T1566](/0.therory/glossary.md#-mitre-attck-techniques-common-in-this-portfolio) Phishing - Potential AiTM
* **Objective:** Detect, investigate, and hunt anomalous authentication patterns targeting a corporate logistics account using Kusto Query Language (KQL).

---

## ▶️ Telemetry & Initial Triage
This log extract from Microsoft Entra ID `SigninLogs` reveals a highly suspicious authentication pattern for the user **John Smith - Logistics**, spanning a narrow window of approximately 20 minutes (03:04 to 03:25).

![Entra ID Sign-ins](/3.log-analysis/entra-id/images/entra-id.png)

### ▶️ Key Findings (Indicators of Compromise)
A detailed review of the telemetry highlights multiple IoCs consistent with credential compromise:

* **Impossible Travel (Geo-Velocity Anomaly):** Authentication attempts originated from three geographically distant locations within minutes of each other:
  * **London, GB (IPv6):** 03:04 - 03:13
  * **Middletown, Delaware, US (IPv4):** 172.94.105.5 & 172.94.26.142 at 03:18 - 03:21
  * **Brisbane, Queensland, AU (IPv4):** 172.94.51.136 at 03:23 - 03:25
  > **Assessment:** This physical impossibility strongly suggests the use of VPNs/proxies to obfuscate the attacker's true location, or a coordinated attack by multiple threat actors sharing compromised credentials.

* **Credential Guessing & Error Codes:** Several `Failure` events are observed from the London IP address with the error code `50126` (Invalid username or password), indicating initial attempts to guess the credentials.

* **MFA Interruptions:** The logs show multiple `Interrupted` statuses with codes such as `50140` (Keep me signed in prompt), `50055`, and `50072`. These suggest the authentication flow was repeatedly halted, either by conditional access policies or the user failing/ignoring MFA prompts.

* **Successful Breach:** Most critically, despite the initial failures and physical distance, we observe `Success` (Code 0) statuses originating from the US and Australian IP addresses. The presence of successful logons from anomalous locations indicates a critical security breach, potentially involving MFA fatigue (prompt bombing), a stolen session token (AiTM - Adversary-in-the-Middle attack), or a compromised secondary device.

---

## ▶️ Log Ingestion & Normalisation
To conduct temporal analysis at scale and hunt for the distributed infrastructure, the raw JSON logs from Entra ID were ingested into a custom Azure Data Explorer (ADX) cluster. The telemetry was validated to ensure accurate mapping of key fields (`userDisplayName`, `ipAddress`, `createdDateTime`) before applying detection logic.

![KQL Query Results: Entra ID Sign-ins](/3.log-analysis/entra-id/images/azure.png)

---

## ▶️ Detection Hunt (KQL)
Applying the same analytical methodology used to resolve data discrepancies in logistics systems, a custom KQL query was developed. The query groups the login events by IP address into 5-minute time bins (`bin`), effectively exposing the brute force spikes and isolating the VPN infrastructure used in the impossible travel scenario.

```kql
// Detection of activity peaks and Brute Force (T1110)
['table-1']
| where userDisplayName has "John Smith"
| summarize TotalLogs = count() by ipAddress, bin(todatetime(createdDateTime), 5m)
| project TimeWindow = bin(todatetime(createdDateTime), 5m), ipAddress, TotalLogs
| order by TotalLogs desc
```
**Results:**
The KQL hunt successfully isolated the highest concentration of failed attempts (8 logs within a 5-minute window) originating from the Delaware proxy IP (172.94.105.5).


![KQL Query Results: Entra ID Sign-ins](/3.log-analysis/entra-id/images/query.png)

## ▶️ Security Recommendations & Incident Response
When this pattern is detected in cloud telemetry, a SOC analyst must execute immediate containment actions:

* **Revoke Sessions:** Immediately revoke all active refresh tokens and sessions for the compromised account in Entra ID to sever the attacker's connection.
* **Reset Credentials:** Force a password reset and require the user to re-register their MFA methods, as the current device or token is likely compromised.
* **Investigate Post-Compromise Activity:** Since there are successful sign-ins to "My Profile" and "My Signins", analysts must query Entra ID `AuditLogs` to ensure the attacker did not register rogue MFA devices (persistence). Additionally, O365 logs should be checked for inbox rules or data exfiltration.
* **Enhance Conditional Access:** Ensure Conditional Access Policies are configured to block sign-ins from unexpected countries (Geo-blocking) and require strict, risk-based access controls for anomalous sign-ins.



## ▶️ Authored by
Magda Dominguez  
*Security Operations • Detection Engineering • Blue Team*