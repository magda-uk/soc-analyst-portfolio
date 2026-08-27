# Authentication Anomalies Hunting  
**MITRE ATT&CK:** T1078  Valid Accounts  
**Category:** Threat Hunting / Identity & Access  


---

## 🎯 Objective
Identify suspicious authentication patterns that may indicate credential compromise, brute force attempts, lateral movement, or privilege escalation.  
Authentication anomalies are often the **earliest indicator** of account takeover.

---

## 🔍 Primary Hunting Query (KQL)

```kql
SigninLogs
| where ResultType != 0
| summarize FailedLogins = count() by UserPrincipalName, IPAddress
| order by FailedLogins desc
```
This query highlights users experiencing repeated authentication failures — a common precursor to compromise.

## 🧠 Why This Matters

Attackers frequently rely on authentication anomalies to:

* Test stolen credentials
* Perform password spraying
* Attempt brute force attacks
* Move laterally using compromised accounts
* Escalate privileges after initial access

Any unusual authentication pattern warrants investigation.

---

## 🕵️ Investigation Workflow 

### 1. Identify Brute Force Patterns

```kql
SigninLogs
| summarize Attempts = count() by UserPrincipalName, IPAddress, bin(TimeGenerated, 5m)
| order by Attempts desc
```
### 🔴 Red Flags

- multiple failures in short time windows  
- same IP targeting multiple accounts  
- login attempts outside working hours  

---

### 2. Detect Impossible Travel
Indicators:

- rapid geographic jumps

- logins from distant countries within minutes

- inconsistent device fingerprints

```kql
SigninLogs
| extend Location = tostring(LocationDetails.city)
| summarize count() by UserPrincipalName, Location, bin(TimeGenerated, 1h)
```
### 3. Investigate MFA Failures
```
SigninLogs
| where AuthenticationRequirement == "multiFactorAuthentication"
| where ResultType != 0
| project TimeGenerated, UserPrincipalName, IPAddress, ResultType
```
Red flags:

- Repeated MFA denials

- MFA failures followed by successful login

- MFA failures from unfamiliar IPs
### 4. Pivot to Device Activity
Once a suspicious login is identified, pivot to endpoint telemetry:
```
DeviceProcessEvents
| where AccountName == "<user>"
| order by Timestamp desc
```
Look for:

- PowerShell execution

- LSASS access

- Credential dumping tools

- Lateral movement binaries

### 5.Privilege escalation attempts
```
AADSpnSignInLogs
| where UserPrincipalName == "<user>"
| summarize count() by ResourceDisplayName
```
**Red Flags:**

* Sudden access to high-privilege resources
* Unexpected use of admin applications
* Elevation shortly after suspicious login

---

## 🚨 Indicators of Compromise

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