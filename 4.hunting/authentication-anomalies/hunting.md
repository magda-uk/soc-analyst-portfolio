// ==========================================
// AUTHENTICATION HUNTING WORKFLOW
// Techniques: T1078 (Valid Accounts), T1110 (Brute Force)
// ==========================================

// 1. Identify suspicious authentication events
let AuthAnomalies =
SigninLogs
| where ResultType == 0
| where Location != prev(Location) or IPAddress in ("185.220.101.0/24", "104.244.72.0/24")
| project AuthTime = Timestamp, UserPrincipalName, IPAddress, Location;

// 2. Hunt for post-login activity (process execution)
let PostLoginProcesses =
DeviceProcessEvents
| join kind=inner AuthAnomalies on UserPrincipalName
| where Timestamp > AuthTime and Timestamp < AuthTime + 1h
| project Timestamp, UserPrincipalName, DeviceName, FileName, ProcessCommandLine;

// 3. Hunt for lateral movement or network activity
let NetworkActivity =
DeviceNetworkEvents
| join kind=inner AuthAnomalies on UserPrincipalName
| where Timestamp > AuthTime and Timestamp < AuthTime + 1h
| project Timestamp, UserPrincipalName, DeviceName, RemoteIP, RemotePort;

// Combine hunting results
PostLoginProcesses
| union NetworkActivity
| order by Timestamp asc
