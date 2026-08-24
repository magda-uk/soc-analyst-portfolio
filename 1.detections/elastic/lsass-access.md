
## Elastic Detection – Potential Credential Dumping

### Description
Detects access to LSASS memory, which is commonly associated with credential dumping tools such as Mimikatz.

### MITRE ATT&CK
- **T1003 – OS Credential Dumping**

### Elastic Query (EQL)
```eql
process where event.action == "start" and
  process.name == "mimikatz.exe" or
  process.command_line contains "sekurlsa"
  ```
### Notes
This rule should be combined with Sysmon Event ID 10 (Process Access) for stronger detection.

### Response
* Isolate the host.

* Review recent authentication activity.

* Check for privilege escalation.  
