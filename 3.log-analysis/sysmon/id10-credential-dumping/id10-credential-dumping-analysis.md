
# Credential Dumping Log Analysis (T1003)

## Relevant Event Types
- DeviceProcessEvents
- Sysmon Event ID 10 (ProcessAccess)
- Sysmon Event ID 1 (Process Creation)
- Elastic ECS: process, process.access, process.executable

## Key Fields to Review
- InitiatingProcessFileName
- TargetProcessName (lsass.exe)
- GrantedAccess
- ProcessCommandLine
- ParentProcessName
- AccountName
- DeviceName

## Common Benign Patterns
- Antivirus scanning LSASS
- Backup tools accessing LSASS memory
- Credential providers interacting with LSASS legitimately

## Common Malicious Patterns
- Mimikatz-like access patterns
- Suspicious processes opening LSASS (rundll32, powershell, wscript)
- High GrantedAccess values (0x1410, 0x1fffff)
- LSASS access from non-system processes

## Example Raw Events
(Insert Sysmon or Elastic raw logs)

## Useful Queries
```kql
DeviceProcessEvents
| where FileName =~ "lsass.exe"
| where InitiatingProcessFileName !~ "wininit.exe"
| project Timestamp, DeviceName, InitiatingProcessFileName, ProcessCommandLine, AccountName
```
```kql
DeviceProcessEvents
| where ProcessCommandLine has_any ("sekurlsa", "mimikatz", "Invoke-Mimikatz")
```
```eql
process where process.name == "lsass.exe" and
  process.parent.name != "wininit.exe"
```
