// ==========================================
// POWERSHELL ENCODED HUNTING WORKFLOW
// Technique: T1059.001 (PowerShell)
// ==========================================

// 1. Identify encoded PowerShell execution
let EncodedPS =
DeviceProcessEvents
| where FileName =~ "powershell.exe"
| where ProcessCommandLine has_any ("-enc", "-encodedcommand", "FromBase64String")
| project PSTime = Timestamp, DeviceName, ProcessCommandLine, InitiatingProcessFileName;

// 2. Hunt for suspicious ScriptBlock activity
let ScriptBlocks =
DeviceEvents
| where ActionType == "ScriptBlockLogging"
| where AdditionalFields.ScriptBlockText has_any ("Invoke-WebRequest", "IEX", "DownloadString")
| project Timestamp, DeviceName, AdditionalFields.ScriptBlockText;

// 3. Hunt for child processes spawned by PowerShell
let ChildProcesses =
DeviceProcessEvents
| join kind=inner EncodedPS on DeviceName
| where Timestamp > PSTime and Timestamp < PSTime + 30m
| where InitiatingProcessFileName =~ "powershell.exe"
| project Timestamp, DeviceName, FileName, ProcessCommandLine;

// 4. Hunt for network activity after encoded PowerShell
let PSNetwork =
DeviceNetworkEvents
| join kind=inner EncodedPS on DeviceName
| where Timestamp > PSTime and Timestamp < PSTime + 30m
| project Timestamp, DeviceName, RemoteIP, RemotePort;

// Combine hunting results
ScriptBlocks
| union ChildProcesses
| union PSNetwork
| order by Timestamp asc
