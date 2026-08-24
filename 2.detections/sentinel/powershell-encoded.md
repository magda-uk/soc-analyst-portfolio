## Sentinel Detection Rule:  Suspicious PowerShell Execution

### Description
* Detects PowerShell executions using encoded or obfuscated commands commonly associated with malware delivery, credential harvesting, and in‑memory execution.

### MITRE ATT&CK
- **T1059.001 – PowerShell**

### KQL Query
```kql
DeviceProcessEvents
| where FileName =~ "powershell.exe"
| where ProcessCommandLine has_any ("-enc", "IEX", "Invoke-WebRequest")
| project Timestamp, DeviceName, FileName, ProcessCommandLine, InitiatingProcessFileName
```
### Validation
* Execute benign PowerShell commands.

* Execute encoded commands in a controlled lab.

* Compare behavioural differences.

### Investigaton
* Review parent process.

* Check for network connections.

* Investigate user context.

### Response
* Contain the device if malicious behaviour is confirmed.

* Review user activity for lateral movement.

* Check for additional suspicious processes.

