# Investigation Case: Authentication Anomaly (T1110 / T1078)

## Summary
This investigation analyses unusual authentication patterns, including impossible travel and repeated failures.

## Initial Alert
- Detection: Anomalous Authentication Patterns (Sentinel)
- MITRE ATT&CK: T1078 – Valid Accounts

## Evidence
- Multiple sign-ins from geographically distant IPs.
- Repeated MFA failures.
- Unusual device activity.

## Analysis
1. Reviewed sign-in logs for impossible travel.
2. Checked MFA logs for repeated failures.
3. Correlated with device activity.
4. Investigated user behaviour and recent changes.

## Findings
- Authentication attempts from suspicious IPs.
- MFA failures consistent with brute-force or credential stuffing.
- Device activity inconsistent with user profile.

## Conclusion
Potential account compromise.

## Recommended Response
- Enforce MFA reset.
- Review recent sign-ins.
- Investigate user activity.

