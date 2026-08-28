# Authentication Anomalies (Brute Force, Impossible Travel, MFA Fatigue)

## Description
This Sentinel detection identifies suspicious authentication patterns associated with identity-based attacks such as brute force, password spraying, MFA fatigue (push bombing), and impossible travel.

Modern threat actors frequently target identity rather than endpoints, making authentication anomalies one of the most important early indicators of account compromise in Azure AD / Entra ID.

---

## MITRE ATT&CK
* **T1078** — Valid Accounts
* **T1110** — Brute Force
* **T1556** — Modify Authentication Process

---

## Detection Logic (Described in Plain Text)

* **Brute Force / Password Spraying:**  
  The detection monitors repeated authentication failures within short time windows. A successful login following numerous failures is treated as highly suspicious and often indicative of brute force or password spraying.
* **Impossible Travel:**  
  The detection compares the geographical locations of consecutive sign-ins. If a user signs in from two distant countries within an unrealistic timeframe, the event is flagged as impossible travel.
* **MFA Fatigue (Push Bombing):**  
  The detection identifies multiple MFA denials within a short period. If an MFA approval occurs shortly after repeated denials, this strongly suggests MFA fatigue.

---

## Detection Notes
* A successful login after many failures is a classic brute-force indicator.
* Numerous MFA denials followed by an approval often indicate push bombing.
* Logins from geographically distant locations within minutes indicate impossible travel.
* New or unusual User Agents should be treated as suspicious.

---

## Validation Steps
1. Generate benign failed logins using test accounts.
2. Simulate impossible travel using VPN endpoints.
3. Trigger multiple MFA denials to observe expected behaviour.
4. Compare legitimate authentication patterns with suspicious ones.

---

## Investigation Workflow

### 1. Confirm User Legitimacy
* Does the user recognise the login?
* Was the login expected?
* Is the device familiar?

### 2. Analyse Authentication Behaviour
* Number of failures
* Time window
* IP reputation
* Geolocation
* Device fingerprint
* User Agent

### 3. Review MFA Activity
* Was the user spammed with MFA prompts?
* Did the user approve due to fatigue?
* Was an unusual MFA method used?

### 4. Examine Post-Authentication Activity
* Email access
* SharePoint or OneDrive browsing
* Token creation
* OAuth app registration
* Privilege escalation attempts

### 5. Assess Scope
* Single account compromise
* Lateral movement
* Access to sensitive resources

---

## Response Actions
* **Reset the user’s password immediately**
* **Revoke refresh tokens** (Revoke active sessions)
* **Block suspicious IP addresses** at perimeter and conditional access levels
* **Apply Conditional Access policies** (e.g., enforce phishing-resistant MFA, compliant devices)
* **Force re-authentication**
* **Review recent cloud activity** (Unified Audit Log / CloudAppEvents)
* **Escalate to Incident Response** if sensitive data or administrative roles were accessed

---

## Evidence to Collect
* IP addresses and ASN data
* Geolocation data
* User Agents and client app details
* MFA logs and result codes (`ResultType`)
* Timestamps and correlation IDs
* Post-authentication activity logs (`CloudAppEvents`, `OfficeActivity`)
* Token creation and service principal events