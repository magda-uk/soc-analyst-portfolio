// ==========================================
// LSASS ACCESS HUNTING WORKFLOW
// Technique: T1003 (Credential Dumping)
// ==========================================

// 1. Identify suspicious LSASS access
let LsassAccess =
DeviceProcessEvents
| where GrantedAccess has_any ("0x40", "0x1000", "0x1FFFFF")
| where FileName =~ "lsass.exe"
| project LsassTime = Timestamp, DeviceName, InitiatingProcessFileName, GrantedAccess;

// 2. Hunt for memory read events targeting LSASS
let MemoryReads =
DeviceEvents
| where ActionType == "ProcessMemoryRead"
| where TargetProcessName =~ "lsass.exe"
| project Timestamp, DeviceName, InitiatingProcessFileName, AdditionalFields;

// 3. Hunt for known dumping tools
let DumpTools =
DeviceProcessEvents
| where FileName in ("procdump.exe", "rundll32.exe", "comsvcs.dll")
| project Timestamp, DeviceName, FileName, ProcessCommandLine;

// 4. Hunt for network activity after LSASS access
let LsassNetwork =
DeviceNetworkEvents
| join kind=inner LsassAccess on DeviceName
| where Timestamp > LsassTime and Timestamp < LsassTime + 30m
| project Timestamp, DeviceName, RemoteIP, RemotePort;

// Combine hunting results
MemoryReads
| union DumpTools
| union LsassNetwork
| order by Timestamp asc
