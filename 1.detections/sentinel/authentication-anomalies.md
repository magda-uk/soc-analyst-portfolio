# Sentinel Detection Rule: Anomalous Authentication Patterns

### Description
Detects unusual authentication behaviour such as impossible travel, repeated failures, or suspicious IP activity.

### MITRE ATT&CK
- **T1078 — Valid Accounts**

### KQL Rule
```kql
SigninLogs
| summarize count() by UserPrincipalName, IPAddress
| sort by count_ desc
```
### Validation
* Simulate authentication from multiple IPs.

* Compare baseline vs anomaly.

### Investigation
* Check MFA failures.

*Review device activity.

* Investigate user behaviour.

### Response
* Enforce MFA reset.

* Review recent sign‑ins.

* Investigate potential account compromise.