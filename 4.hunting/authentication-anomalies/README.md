
---
## **Authentication Anomalies Playbook** 
 ![Entra ID](https://img.shields.io/badge/Entra_ID-B48CFF?style=flat-square&logo=microsoftazure&logoColor=white)
 ![Sentinel](https://img.shields.io/badge/Microsoft_Sentinel-SIEM-6f42c1?style=flat-square&logo=microsoftazure&logoColor=white)
 ![Sysmon](https://img.shields.io/badge/Sysmon-Event_Telemetry-CFA0FF?style=flat-square&logo=windows&logoColor=white)
 ![Windows Event Logs](https://img.shields.io/badge/Windows_Event_Logs-Event_IDs-0078D4?style=flat-square&logo=windows&logoColor=white)
 ![PowerShell Logging](https://img.shields.io/badge/PowerShell-Logging-5391FE?style=flat-square&logo=powershell&logoColor=white)
 ![KQL](https://img.shields.io/badge/KQL-Queries-6f42c1?style=flat-square)

**MITRE ATT&CK:** T1078 : Valid Accounts  
**Category:** Threat Hunting / Identity & Access  



## 🟥 Hunt Hypothesis
Threat actors are attempting to bypass perimeter defences by targeting legitimate cloud identities. We assume that compromised credentials, password spraying, or brute-force tactics are actively being used against our Entra ID environment to establish an initial foothold.

## 🟥 Attack Vector & Execution
Instead of exploiting technical vulnerabilities, modern adversaries often prefer to simply "log in" using valid accounts. Authentication anomalies are frequently the first indicator of this behaviour, as attackers rely on:
* Validating stolen credentials against corporate directories.
* Executing low-and-slow password spraying to avoid automated lockouts.
* Conducting aggressive brute-force attacks from obfuscated infrastructure.
* Moving laterally or escalating privileges immediately following a successful breach.

## 🟦 Detection Logic & Telemetry
To validate the hypothesis, we establish a baseline of Entra ID sign-in telemetry to surface accounts experiencing a high volume of failed authentications from specific IP addresses.

```q
SigninLogs
| where ResultType != 0
| summarize FailedLogins = count() by UserPrincipalName, IPAddress
| order by FailedLogins desc
```
> This query surfaces accounts experiencing a disproportionate volume of failed sign-ins from specific IP addresses, providing a starting point for deeper investigation.
---

## 🕵🏻‍♀️ Investigation Workflow 

### 1️⃣. Identify Brute Force Patterns

```kql
SigninLogs
| summarize Attempts = count() by UserPrincipalName, IPAddress, bin(TimeGenerated, 5m)
| order by Attempts desc
```
### 🟥 Red Flags


- multiple failures in short time windows  
- same IP targeting multiple accounts  
- login attempts outside working hours  

###  🟦 Simulation & Detection (Proof of Concept)

To demonstrate this hunting hypothesis in a live environment, a brute force attack was simulated against a test account (`jsmith`). The telemetry was ingested into Microsoft Sentinel via the Entra ID data connector and analysed using Kusto Query Language (KQL).

![Sentinel KQL Query - Brute Force Detection](/4.hunting/authentication-anomalies/Microsofot%20Sentinel%20Logs.png) 

**Analysis of Findings:**

* **Targeted Query:** The KQL query successfully isolates all non-success authentication attempts (`ResultType != "0"`) for the specific User Principal Name.
* **Credential Validation Failures (50126):** The logs reveal a rapid succession of 50126 error codes (Error validating credentials due to invalid username or password). This pattern is a definitive indicator of brute force or password spraying behaviour.
* **MFA Challenge (50074):** A subsequent 50074 error (Strong Authentication is required) is also visible. This demonstrates that even if an attacker guesses the correct password, robust Conditional Access policies enforcing MFA provide a critical secondary line of defence.

This proof of concept highlights the importance of monitoring raw sign-in logs. Attackers often space out their attempts to operate under the radar of automated "Smart Lockout" thresholds, making proactive hunting essential for early detection.

---

###  2️⃣. Detect Impossible Travel
### 🟥 Indicators:

- Rapid geographic jumps

* Logins from distant countries within a narrow time window

- Inconsistent device fingerprints and IP allocations

```q
SigninLogs
| extend Location = tostring(LocationDetails.city)
| summarize count() by UserPrincipalName, Location, bin(TimeGenerated, 1h)
```
###  🟦 Simulation & Detection (Proof of Concept)
For a practical demonstration of this hunt—including geo-velocity analysis across the UK, US, and Australia, alongside advanced KQL execution using the bin function. Please refer to my detailed incident report:

➡️ [Log Analysis & Event Triage: Anomalous Cloud Sign-ins & Impossible Travel](/3.log-analysis/entra-id/EntraID-Impossible-Travel.md) 

---

### 3️⃣. Investigate MFA Failures

Attackers who successfully guess or steal a password will inevitably hit the MFA prompt. Monitoring for persistent MFA failures or anomalous interruptions is critical for detecting accounts under active attack.

```kql
SigninLogs
| where AuthenticationRequirement == "multiFactorAuthentication"
| where ResultType != 0
| project TimeGenerated, UserPrincipalName, IPAddress, ResultType, ResultDescription
```




### 🟥 Red Flags:

- Repeated MFA denials (MFA Fatigue / Prompt Bombing)

- MFA failures followed immediately by a successful login

- MFA failures from unfamiliar geographic locations

###  🟦 Event Triage (Proof of Concept)
I have documented the triage and analysis of multiple MFA-related error codes (such as 50207 MFA Challenge, 50055 Expired/Invalid session, and 50072 Conditional Access blocks) across different incident scenarios.

For a practical demonstration of investigating these anomalies, please review my detailed log analysis reports:

➡️ [Log Analysis & Event Triage: Entra ID Interactive Sign-ins](/3.log-analysis/entra-id/EntraId-interactive-sign-ins.md)

➡️ [Log Analysis: Anomalous Cloud Sign-ins & Impossible Travel](/3.log-analysis/entra-id/EntraID-Impossible-Travel.md)


---

###  4️⃣. Execution & Credential Access: Pivot to Endpoint Telemetry
Once a highly suspicious anomalous sign-in is identified, the investigation must immediately pivot from cloud identity logs to endpoint telemetry. We assume the adversary has successfully bypassed the perimeter and is now attempting to execute malicious payloads, establish command and control (C2), or harvest additional credentials from the compromised host.


 > Defender for Endpoint query to trace initial post-compromise activity

```
DeviceProcessEvents
| where AccountName == "<user>"
| order by Timestamp desc
```

🟥 **Post-Compromise Red Flags:**
* Unexpected execution of PowerShell, particularly the use of obfuscated or encoded command-line arguments (e.g., `-EncodedCommand`).
* Credential dumping tools or unauthorised handles requested to `lsass.exe`.
* Execution of lateral movement binaries or system discovery commands (`whoami`, `net user`).

### 🟦 Event Triage (Proof of Concept)

A primary objective during this pivoting phase is detecting Living-off-the-Land (LotL) execution and credential theft. I have documented deep-dive investigations into these specific post-compromise behaviours using native Windows and Sysmon telemetry.

For practical demonstrations of triaging endpoint logs to confirm attacker activity, please review my incident reports:

➡️ **[Security Event Analysis: PowerShell ScriptBlock Logging & De-obfuscation (T1059.001)](https://github.com/magda-uk/soc-analyst-portfolio/blob/main/7.hands-on/day3-powershell-logging/day3-powershell-logging.md)**

➡️ **[Incident Investigation: LSASS Memory Access via Mimikatz (T1003)](/3.log-analysis/sysmon/id10-lsass-access/evtx-mimikatz-lsass-access.md)**

---
### 5. Privilege Escalation Attempts

If an adversary successfully establishes a foothold and moves laterally, their next objective is typically to elevate their access rights to execute high-impact actions, such as disabling security tooling, creating persistence, or accessing sensitive data. 

Monitoring for abnormal privilege assignments is critical for detecting this phase of the attack lifecycle.

>  Monitor for special privileges assigned to non-system accounts
```q
SecurityEvent
| where EventID == 4672
| where AccountType == "User"
| project TimeGenerated, Computer, Account, PrivilegeList
| sort by TimeGenerated desc
```


### 🟥 Privilege Escalation Red Flags:

* Assignment of highly sensitive privileges to standard user accounts (e.g., `SeDebugPrivilege`, `SeImpersonatePrivilege`).
* A sudden spike in Event ID 4672 (Special Privileges Assigned) occurring outside of normal administrative windows.
* Privilege escalation events immediately following anomalous PowerShell execution or unexpected interactive logons.

### 🟦 Event Triage (Proof of Concept)

Distinguishing between legitimate administrative actions and malicious privilege escalation requires careful baselining and context analysis. I have documented an investigation into Windows Security Event telemetry, specifically focusing on privilege assignment and abuse.

For a practical demonstration of triaging these events and reducing false positives, please review my log analysis report:

➡️ **[Security Event Analysis: Special Privileges Assigned (Event ID 4672)](/3.log-analysis/windows-events/4672-privilege-special-assigned.md)**



---



## 🟥 Indicators of Compromise (Summary)

A consolidated list of red flags indicating a potential identity compromise across cloud and endpoint environments:

* Multiple failed logins followed by a successful one (Brute Force / Password Spraying).
* Impossible travel events (Geo-velocity anomalies).
* MFA failures or interrupted prompts from unknown IP addresses (MFA Fatigue / Prompt Bombing).
* Successful login from a new device immediately followed by obfuscated PowerShell activity.
* Authentication anomalies correlated with `lsass.exe` memory access (Credential Dumping).
* Service accounts (`NT AUTHORITY\SYSTEM`) performing interactive logins or standard users receiving special privileges (Event ID 4672).

---

## 🛡️ Recommended Actions (Containment & Response)

If the above IoCs are confirmed, the following containment procedures should be executed immediately:

1. **Force Password Reset:** Immediately reset the password for all affected identities.
2. **Revoke Sessions:** Revoke all active Entra ID refresh tokens and sessions.
3. **Isolate Endpoints:** Contain the affected host via Defender for Endpoint to prevent lateral movement.
4. **Block Infrastructure:** Block the suspicious IP addresses or ASN at the firewall/conditional access level.
5. **Review Telemetry:** Check for post-compromise persistence (e.g., rogue MFA devices registered, inbox forwarding rules).
6. **Escalate:** Escalate the case to Incident Response (L2/L3) if a widespread compromise is confirmed.

---

## 📘 Analyst Notes

> **Analyst Tip:** Authentication anomalies are one of the strongest early indicators of credential compromise. Treat any unusual login pattern as a potential account takeover (ATO) until proven otherwise. Trust the telemetry, verify the context, and act swiftly to contain the threat.

---

## 🪪 Author

**Magda Dominguez**  
*SOC Analyst (L1-ready) - Bristol, UK*  
Blue Team operations | SOC investigations | Logistics-to-SOC analytical mindset