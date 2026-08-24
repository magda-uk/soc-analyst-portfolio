
# PowerShell Log Analysis (T1059.001)

## Relevant Event Types
- DeviceProcessEvents
- ScriptBlockLogging
- ModuleLogging
- Sysmon Event ID 1 (Process Creation)

## Key Fields to Review
- ProcessCommandLine
- ParentProcessName
- AccountName
- InitiatingProcessFileName
- ScriptBlockText
- DeviceName

## Common Benign Patterns
- IT admin scripts
- Scheduled tasks
- Monitoring tools
- PowerShell used for automation

## Common Malicious Patterns
- Encoded commands (-enc, -EncodedCommand)
- Download cradle (Invoke-WebRequest, IEX)
- Living-off-the-land execution (rundll32 → powershell)
- In-memory execution (reflection, Base64 payloads)

## Example Raw Events
(Insert ScriptBlockLogging or Sysmon raw logs)

## Useful Queries
```kql
DeviceProcessEvents
| where FileName =~ "powershell.exe"
| where ProcessCommandLine has_any ("-enc", "-EncodedCommand")
| project Timestamp, DeviceName, InitiatingProcessFileName, ProcessCommandLine, AccountName
```
```kql
DeviceProcessEvents
| where ProcessCommandLine has_any ("Invoke-WebRequest", "IEX", "DownloadString")
```
```kql
DeviceProcessEvents
| where ParentProcessName !~ "explorer.exe"
```
