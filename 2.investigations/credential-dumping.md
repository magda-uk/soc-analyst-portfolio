# Investigation: Potential Credential Dumping

## Summary
This investigation focuses on suspicious access to LSASS memory, a common technique used for credential dumping.

## Initial Alert
- Detection: LSASS Access Attempt (Elastic)
- MITRE ATT&CK: T1003 – Credential Dumping

## Evidence
- Process accessing LSASS.
- Parent process not associated with legitimate LSASS access.
- Indicators of process injection.

## Analysis
1. Reviewed DLL loads for suspicious modules.
2. Checked for process injection techniques.
3. Correlated with authentication logs for anomalies.
4. Investigated user privilege level.

## Findings
- Unauthorised LSASS access attempt.
- Suspicious DLL loaded.
- Authentication anomalies detected.

## Conclusion
High likelihood of credential dumping attempt.

## Recommended Response
- Reset affected credentials.
- Investigate privilege escalation.
- Review lateral movement.
