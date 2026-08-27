# LSASS Access Hunting  
**MITRE ATT&CK:** T1003 — Credential Dumping  
**Category:** Threat Hunting / Manual Investigation  


---

## 🎯 Objective
Identify attempts to access LSASS memory for credential dumping using tools such as Mimikatz, Cobalt Strike, ProcDump, or custom loaders.  
LSASS contains highly sensitive authentication material (NTLM hashes, Kerberos tickets, plaintext credentials), making any access attempt a **critical security event**.

---

## 🔍 Primary Hunting Query (KQL)

```kql
DeviceProcessEvents
| where FileName in ("taskmgr.exe", "procdump.exe", "rundll32.exe", "powershell.exe")
| where ProcessCommandLine has "lsass" or ProcessCommandLine has "dump"
| project Timestamp, DeviceName, FileName, ProcessCommandLine, AccountName, InitiatingProcessFileName
| order by Timestamp desc
```
## 🧠 Why This Matters

`lsass.exe` (Local Security Authority Subsystem Service) is one of the most sensitive processes in Windows.  
Attackers target LSASS to:

* Extract NTLM hashes
* Steal Kerberos tickets
* Obtain plaintext passwords (in legacy/misconfigured environments)
* Escalate privileges
* Move laterally across the domain

Any interaction with LSASS by a non-system process is highly suspicious.

---

## 🕵️ Investigation Workflow 

### 1. Identify the Dumping Technique

Common malicious patterns include:

* `procdump.exe -ma lsass.exe`
* `rundll32.exe comsvcs.dll, MiniDump`
* PowerShell invoking `MiniDumpWriteDump` APIs via reflection or P/Invoke
* Custom binaries/mimikatz loaders accessing LSASS memory directly

Check the command line for:

* `lsass.exe`
* `dump` / `minidump`
* `.dmp` file creation
* Suspicious native DLLs (e.g., `comsvcs.dll`)

---

### 2. Analyse the Parent Process

```kql
DeviceProcessEvents
| where FileName =~ "lsass.exe"
| project InitiatingProcessFileName, InitiatingProcessCommandLine, Timestamp
```
### 🔴 Red Flags (Parent Process Analysis)

* `cmd.exe` spawning dump tools
* `powershell.exe` accessing LSASS
* `wmiprvse.exe` spawning suspicious binaries
* `svchost.exe` spawning unexpected child processes
* Any non-system process interacting with `lsass.exe`

---

### 3. Pivot to File Writes (Dump Files)

Dump files are one of the strongest indicators of credential theft. Attackers often generate `.dmp` files to extract credentials offline.

**Look for:**

* `.dmp` files created shortly after LSASS access
* Dump files stored in unusual directories such as:
  * `C:\Windows\Temp\`
  * `C:\Users\Public\`
  * Attacker-created folders
* Dump files created by suspicious processes (`procdump.exe`, `rundll32.exe`, `powershell.exe`)

**Red flags:**

* `.dmp` files appearing without legitimate debugging activity
* Dump files created by unsigned binaries
* Dump files created during off-hours

---

### 4. Check for Network Exfiltration

After dumping LSASS, attackers frequently exfiltrate the `.dmp` file to a remote server for offline credential extraction.

**Indicators:**

* Outbound connections immediately after dump creation
* Connections to unknown IPs or non-standard ports
* `powershell.exe` or `rundll32.exe` making network requests
* Large data transfers from the compromised host

---

### 5. Identify the User Behind the Activity

Understanding who initiated the LSASS access is critical.

**Red flags:**

* Service accounts performing interactive logins
* Unexpected admin accounts accessing LSASS
* Accounts active outside normal working hours
* Accounts with recent authentication anomalies
* Accounts showing lateral movement patterns

---

## 🚨 Indicators of Compromise

* LSASS accessed by non-system processes
* `.dmp` files created on disk
* Unsigned binaries interacting with LSASS
* PowerShell spawning dump tools
* LSASS access followed by lateral movement
* LSASS access shortly after suspicious authentication events
* Dump files exfiltrated externally

---

## 🛡️ Recommended Actions

1. Immediately isolate the host
2. Secure or delete any `.dmp` files
3. Reset credentials for affected accounts
4. Review domain controller authentication logs
5. Check for persistence mechanisms
6. Escalate to Incident Response if credential theft is confirmed

---

## 📘 Analyst Notes

> **Analyst Tip:** LSASS access is one of the strongest indicators of credential theft. Treat any non-system interaction with LSASS as a high-severity incident requiring immediate investigation.