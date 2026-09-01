# Authentication Anomalies (Brute Force, Impossible Travel, MFA Fatigue)

## Description
Modern attacks frequently target identity rather than endpoints. Threat actors attempt to compromise accounts through:

- Brute force attacks
- Password spraying
- MFA fatigue (push bombing)
- Impossible travel events
- Logins from unusual locations or devices

These behaviours are extremely common in cloud environments such as Azure AD.

---

## How the Attack Works
Typical attacker workflow:

1. Obtain credentials (phishing, leaks, OSINT)
2. Attempt repeated authentication
3. Trigger MFA notifications until the user approves
4. Log in from geographically impossible locations
5. Access email, SharePoint, Teams, or cloud resources
6. Move laterally using the compromised identity

---

## Why It Is Dangerous
- Identity compromise leads to full cloud compromise
- Difficult to distinguish from legitimate user behaviour
- Enables data exfiltration
- Enables persistence through OAuth apps or tokens
- Very high prevalence in real SOC operations

---

## MITRE ATT&CK
- **T1078 — Valid Accounts**
- **T1110 — Brute Force**
- **T1556 — Modify Authentication Process**

---

## Detection Guidance
Monitor for:

- Multiple failed logins in short time windows
- Successful login following many failures
- Repeated MFA denials
- MFA approval after fatigue attempts
- Impossible travel (e.g., UK → Brazil in minutes)
- Suspicious IP addresses
- Unusual User Agents

---

## Investigation Steps
Key questions:

- Does the user recognise the login?
- Was MFA spammed?
- Was the password recently changed?
- Is there suspicious activity after login?
- Are there signs of exfiltration?

---

## Mitigation
- Enforce MFA for all users
- Apply Conditional Access policies
- Block high‑risk countries
- Enable Identity Protection
- Review active sessions and revoke tokens
- Rotate credentials immediately

---

## Evidence to Collect
- IP addresses
- Geolocation data
- User Agents
- MFA logs
- Timestamps
- Post‑authentication activity
