# Hunt: Authentication Anomalies  
**MITRE ATT&CK:** T1078 : Valid Accounts  
**Category:** Threat Hunting / Identity & Access  

---

## 🟥 Hunt Hypothesis
Threat actors are attempting to bypass perimeter defences by targeting legitimate cloud identities. We assume that compromised credentials, password spraying, or brute-force tactics are actively being used against our Entra ID environment to establish an initial foothold.

## 🟥 Adversary Tradecraft
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

![Sentinel KQL Query - Brute Force Detection](./images/tu-imagen-aqui.png) 
*(Note: Replace the image path with the actual location in your repository)*

**Analysis of Findings:**

* **Targeted Query:** The KQL query successfully isolates all non-success authentication attempts (`ResultType != "0"`) for the specific User Principal Name.
* **Credential Validation Failures (50126):** The logs reveal a rapid succession of 50126 error codes (Error validating credentials due to invalid username or password). This pattern is a definitive indicator of brute force or password spraying behaviour.
* **MFA Challenge (50074):** A subsequent 50074 error (Strong Authentication is required) is also visible. This demonstrates that even if an attacker guesses the correct password, robust Conditional Access policies enforcing MFA provide a critical secondary line of defence.

This proof of concept highlights the importance of monitoring raw sign-in logs. Attackers often space out their attempts to operate under the radar of automated "Smart Lockout" thresholds, making proactive hunting essential for early detection.

---

###  2️⃣. Detect Impossible Travel
Indicators:

- Rapid geographic jumps

* Logins from distant countries within a narrow time window

- Inconsistent device fingerprints and IP allocations

```kql
SigninLogs
| extend Location = tostring(LocationDetails.city)
| summarize count() by UserPrincipalName, Location, bin(TimeGenerated, 1h)
```
###  🟦 Simulation & Detection (Proof of Concept)
For a practical demonstration of this hunt—including geo-velocity analysis across the UK, US, and Australia, alongside advanced KQL execution using the bin function—please refer to my detailed incident report:

➡️ Log Analysis & Event Triage: Anomalous Cloud Sign-ins & Impossible Travel (Note: update this link with your actual file path)

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

➡️ Log Analysis & Event Triage: Entra ID Interactive Sign-ins

➡️ Log Analysis: Anomalous Cloud Sign-ins & Impossible Travel

(Note: update these links with your actual file paths)

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

### 5. Privilege escalation attempts
```
AADSpnSignInLogs
| where UserPrincipalName == "<user>"
| summarize count() by ResourceDisplayName
```
🟥**Red Flags:**

* Sudden access to high-privilege resources
* Unexpected use of admin applications
* Elevation shortly after suspicious login

---

## 🟥 Indicators of Compromise

* Multiple failed logins followed by a successful one
* Impossible travel events
* MFA failures from unknown IPs
* Successful login from a new device immediately followed by PowerShell activity
* Authentication anomalies correlated with LSASS access or encoded PowerShell
* Service accounts performing interactive logins

---

## 🛡️ Recommended Actions

1. Force password reset for affected accounts
2. Block suspicious IP addresses
3. Disable compromised accounts
4. Review lateral movement across endpoints
5. Check for privilege escalation
6. Escalate to Incident Response if compromise is confirmed

---

## 📘 Analyst Notes

> **Analyst Tip:** Authentication anomalies are one of the strongest early indicators of credential compromise. Treat any unusual login pattern as a potential account takeover until proven otherwise.