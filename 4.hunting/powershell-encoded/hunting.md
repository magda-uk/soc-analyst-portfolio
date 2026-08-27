# PowerShell Encoded Command Hunting  
**MITRE ATT&CK:** T1059.001  PowerShell  
**Category:** Threat Hunting / Manual Investigation  


---

## 🎯 Objective
Identify suspicious or malicious PowerShell activity involving encoded commands, obfuscation, or execution patterns commonly used in initial access, persistence, or lateral movement.

Encoded PowerShell is a **high‑signal behaviour**. Legitimate admin usage is rare; attackers use encoding to hide payloads, bypass logging, and execute malicious scripts.

---

## 🔍 Primary Hunting Query (KQL)

```kql
DeviceProcessEvents
| where FileName =~ "powershell.exe"
| where ProcessCommandLine has "-enc" or ProcessCommandLine has "-EncodedCommand"
| project Timestamp, DeviceName, InitiatingProcessFileName, ProcessCommandLine, AccountName
| order by Timestamp desc
```
## 🧠 Why This Matters
Attackers frequently rely on encoded PowerShell to:

- Obfuscate malicious payloads  
- Execute C2 stagers  
- Download remote scripts  
- Run credential theft modules  
- Evade basic detection rules  

Any encoded command warrants investigation.

---

## 🕵️ Investigation Workflow (SOC L2)

### 1. Decode the Payload
Extract the Base64 string from the command line and decode it:

```powershell
[System.Text.Encoding]::Unicode.GetString(
    [System.Convert]::FromBase64String("<encoded_string>")
)
```
Look for:

* `Invoke-WebRequest`
* `IEX` (`Invoke-Expression`)
* `System.Net.WebClient`
* Suspicious URLs
* Credential theft modules
* Script downloaders

---

### 2. Build a Timeline of Activity

Pivot around the execution time:

```kql
DeviceProcessEvents
| where DeviceName == "<hostname>"
| where Timestamp between (startTime .. endTime)
| order by Timestamp asc
```
Identify:

Script downloads

Privilege escalation

LSASS access

Lateral movement tools

Persistence mechanisms

3. Correlate with Sysmon / Defender Events

    Network activity:
    ```
    DeviceNetworkEvents
    | where InitiatingProcessFileName =~ "powershell.exe"
    ```
    File writes:


        DeviceFileEvents
        | where InitiatingProcessFileName =~ "powershell.exe"
    Suspicious child processes:


        DeviceProcessEvents
        | where InitiatingProcessFileName =~ "powershell.exe"
        | project FileName, ProcessCommandLine
    Red flags:
    
   -  PowerShell spawning cmd.exe, wscript.exe, rundll32.exe

    - PowerShell downloading remote payloads

    - PowerShell spawning credential theft tools

4. Identify the User Behind the Activity   
```
DeviceProcessEvents
| where ProcessCommandLine has "-enc"
| summarize count() by AccountName
```
**Red Flags:**

* Service accounts
* Unexpected admin accounts
* Accounts active outside working hours
* Accounts with recent authentication anomalies

---

## 🚨 Indicators of Compromise (IoCs)

* PowerShell launched from unusual parent processes
* Encoded commands containing URLs or downloaders
* Base64 payloads containing `IEX`
* PowerShell spawning dump tools or lateral movement binaries
* PowerShell used shortly after suspicious authentication events

---

## 🛡️ Recommended Actions

1. **Isolate the host** via EDR.
2. **Decode and analyse the payload** to extract all IoCs.
3. **Reset credentials** for affected accounts and revoke active sessions.
4. **Block malicious domains or IPs** across network and perimeter firewalls.
5. **Review lateral movement attempts** targeting internal assets.
6. **Escalate to Incident Response (L3/DFIR)** if a malicious second stage or active intrusion is confirmed.

---

## 📘 Analyst Notes

> **Analyst Tip:** Encoded PowerShell is one of the most reliable early indicators of compromise. Treat every encoded command as suspicious until proven otherwise.