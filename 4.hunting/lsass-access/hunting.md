# 🕵️‍♀️ Threat Hunting Playbook: LSASS Access & Credential Dumping (T1003.001)

![Defender for Endpoint](https://img.shields.io/badge/Defender_for_Endpoint-Telemetry-00A4EF?style=flat-square&logo=microsoft&logoColor=white)
![KQL](https://img.shields.io/badge/KQL-Detection_Logic-6f42c1?style=flat-square)
![MITRE ATT&CK](https://img.shields.io/badge/MITRE%20ATT&CK%C2%AE-T1003.001-FF6600?style=flat-square)
![Credential Access](https://img.shields.io/badge/Credential%20Access-TA0006-red?style=flat-square)

**MITRE ATT&CK:** T1003.001 — OS Credential Dumping: LSASS Memory  
**Tactics:** Credential Access (TA0006)  
**Category:** Threat Hunting / Manual Investigation  

## ▫️ Objective

Proactively identify attempts to access, read, or dump the memory space of the Local Security Authority Subsystem Service (`lsass.exe`). Because LSASS manages local security policies, domain authentication, and stores highly sensitive material (NTLM hashes, Kerberos tickets, and occasionally plaintext credentials), any non-system interaction with this process is a critical security event indicating potential credential theft.

## ▫️ Primary Hunting Query (KQL)

```kql
DeviceProcessEvents 
| where ProcessCommandLine has_any ("lsass", "dump", "comsvcs", "minidump")
| where FileName in~ ("taskmgr.exe", "procdump.exe", "rundll32.exe", "powershell.exe", "cmd.exe") 
| project Timestamp, DeviceName, FileName, ProcessCommandLine, AccountName, InitiatingProcessFileName 
| order by Timestamp desc
```
> **Pro-Tip: Sysmon Event ID 10 (Process Access)**
> Process creation events (Event ID 1) only show the tools being executed. To catch custom malware directly reading LSASS memory without spawning known LOLBins, query `DeviceEvents` for Sysmon Event ID 10 where the `TargetImage` is `lsass.exe` and look for suspicious `GrantedAccess` codes (e.g., `0x1F0FFF` or `0x1010`).

## ▫️ Why This Matters

`lsass.exe` is the crown jewel of a Windows endpoint. Threat actors and Red Teams target LSASS memory to extract authentication material offline using tools like Mimikatz, Cobalt Strike, or custom loaders. Successfully dumping LSASS allows an attacker to:

- Perform **Pass-the-Hash (PtH)** attacks using stolen NTLM hashes.
- Execute **Pass-the-Ticket (PtT)** attacks using forged or stolen Kerberos TGTs/TGSs.
- Escalate privileges to Domain Admin if a highly privileged user recently authenticated to the compromised host.
- Move laterally across the domain undetected, completely bypassing MFA requirements.



## ▫️ Investigation Workflow

### ▫️1. Identify the Dumping Technique

Attackers leverage a mix of custom malware and native Living-off-the-Land Binaries (LOLBins) to dump memory. Look for the following specific patterns in your process telemetry:

- **The `comsvcs.dll` LOLBin Trick:** Using `rundll32.exe` to call the `MiniDump` export function of the Component Services DLL. 
  *Example:* `rundll32.exe C:\Windows\System32\comsvcs.dll, MiniDump <LSASS_PID> lsass.dmp full`
- **Sysinternals ProcDump:** A legitimate Microsoft tool frequently abused to create process dumps. 
  *Example:* `procdump.exe -accepteula -ma lsass.exe C:\Temp\lsass.dmp`
- **Task Manager (GUI Dump):** Attackers with RDP or VNC access may simply right-click `lsass.exe` in Task Manager and select "Create dump file". This writes a file named `lsass.DMP` typically in the user's `%TEMP%` directory.
- **API Reflection (PowerShell/C#):** Advanced adversaries use reflection to dynamically invoke the `MiniDumpWriteDump` Win32 API in memory, evading basic command-line monitoring.

### ▫️2. Analyse the Parent Process & Execution Lineage

Legitimate interactions with LSASS are highly restricted and typically originate from system processes like `wininit.exe`.

 **Red Flags:**

- **Shell Spawns:** `cmd.exe` or `powershell.exe` interacting with LSASS indicates hands-on-keyboard activity or script-based automation.
- **Remote Execution:** `wmiprvse.exe` (WMI) or `psexesvc.exe` spawning dump tools strongly suggests lateral movement from another compromised host.
- **Unsigned or Unknown Parents:** Any custom binary executing out of `AppData`, `Temp`, or `Public` directories that opens a handle to `lsass.exe`.

### ▫️3. Pivot to File Writes (Dump Files)

Attackers must write the dumped memory to disk before exfiltrating it. This is a massive forensic footprint (Sysmon Event ID 11 / `DeviceFileEvents`).

- **Suspicious Locations:** Search for `.dmp` files created in `C:\Windows\Temp\`, `C:\Users\Public\`, or hidden directories.
- **File Extension Masquerading:** Sophisticated attackers will rename the dump file to evade basic EDR rules. Look for large file creations (typically 40MB to 150MB+) by suspicious processes, even if named `update.log`, `backup.zip`, or `.txt`.
- **Timing:** Any `.dmp` file created immediately after a suspicious process accesses LSASS memory.

### ▫️4. Check for Network Exfiltration

Once the memory dump is written to disk, the attacker must extract it to run Mimikatz locally on their own infrastructure.

- **Immediate Outbound Connections:** Check `DeviceNetworkEvents` for connections initiated by `powershell.exe`, `curl.exe`, or `certutil.exe` targeting external IPs shortly after the file write.
- **Cloud Storage & RMMs:** Look for connections to file-sharing services (Mega, Dropbox) or the presence of unauthorized Remote Monitoring and Management (RMM) tools (AnyDesk, TeamViewer) transferring large payloads.

### ▫️5. Identify the User Context & Blast Radius

Determine which account was used to execute the attack to understand the potential "blast radius".

- **Privilege Requirements:** Dumping LSASS requires `SeDebugPrivilege` (Local Administrator or SYSTEM). If a standard user account initiated the dump, a Local Privilege Escalation (LPE) vulnerability was likely exploited first.
- **Tier-0 Compromise:** If the LSASS dump occurred on a Domain Controller or an Exchange Server, you must assume a catastrophic forest-level compromise.



## ▫️ Indicators of Compromise (IoCs)

- `rundll32.exe` executing with `comsvcs.dll` and `MiniDump` arguments.
- Creation of `lsass.dmp` or unexpectedly large files (40MB+) in `Temp` or `Public` folders.
- Sysmon Event ID 10 showing `SourceImage` as an unsigned binary and `TargetImage` as `lsass.exe` with `GrantedAccess` `0x1F0FFF` (PROCESS_ALL_ACCESS) or `0x1410` (PROCESS_VM_READ).
- Unexpected network transfers to untrusted hosting providers immediately following a process dump.



## ▫️ Recommended Actions (Incident Response)

1. **Host Containment:** Isolate the endpoint immediately via EDR to prevent the exfiltration of the dump file and to cut off lateral movement capabilities.
2. **Credential Revocation:** Reset passwords and revoke active Entra ID / AD sessions for **all** accounts that had active logon sessions on the compromised host, as their credentials must be assumed stolen.
3. **Hunt for Lateral Movement:** Search telemetry across the network for the accounts compromised on this host. Look for anomalous RDP sessions, WMI execution, or SMB share access originating from the contained machine.
4. **Forensic Preservation:** Secure the `.dmp` file (if still on disk) and collect memory/triage artifacts before wiping or reimaging the machine.
5. **Escalation:** If LSASS was dumped on a Tier-0 asset (e.g., Domain Controller), escalate immediately to DFIR for forest recovery procedures (e.g., rotating the `krbtgt` account twice to invalidate forged Golden Tickets).



## ▫️ Practical Demonstrations (PoCs)

Together, these investigations represent a complete SOC operational lifecycle; from identifying the memory dump technique, to hunting a live threat, and finally engineering a robust detection mechanism.

🧷 **[Investigation Case 1: Triage of LSASS Memory Access via Mimikatz (Sysmon Event ID 10)](/3.log-analysis/sysmon/id10-lsass-access/evtx-mimikatz-lsass-access.md)**  
*(Phase 1: Detection: Identifying credential dumping via unauthorized PROCESS_VM_READ memory handles).* 

🧷 **[Investigation Case 2: Threat Hunting Credential Dumping (Procdump) & SOAR Automation](/2.investigations/06-true-positive-procdump-exfiltration.md)**  
*(Phase 2 & 3: Triage & Automation: Detecting ProcDump evasion (explorer.exe pivot), exfiltration correlation via KQL, and automated Sentinel response).*

## ▫️ Analyst Notes

> **Analyst Tip:** LSASS access is not an early-stage warning; it is an active, high-impact compromise. If an attacker is dumping LSASS, they already have Local Admin rights and are moving to the lateral movement phase. Act decisively.

## ▫️ Connect with me   

**Magda Dominguez**

[![Magda Dominguez LinkedIn](https://img.shields.io/badge/LinkedIn-Magda_Dominguez-9370DB?style=flat-square&logo=linkedin&logoColor=white)](https://www.linkedin.com/in/magda-d-infosec)    
Blue Team operations ▫️ SOC investigations ▫️ Logistics-to-SOC analytical mindset 
