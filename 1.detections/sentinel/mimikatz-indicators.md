
# Sentinel Detection Rule: Mimikatz Indicators

### Description
Detects command‑line indicators associated with Mimikatz execution, commonly used for credential dumping.

### MITRE ATT&CK
- **T1003 — Credential Dumping**

### KQL Rule
```kql
DeviceProcessEvents
| where ProcessCommandLine has_any ("sekurlsa", "logonpasswords", "mimikatz")
```

### Validation
* Simulate credential dumping using a controlled test binary.

### Investigation
* Review LSASS access.

* Check for suspicious DLL loads.

* Correlate with logon anomalies.

### Response
* Reset affected credentials.

* Investigate lateral movement.

* Review privilege escalation attempts.