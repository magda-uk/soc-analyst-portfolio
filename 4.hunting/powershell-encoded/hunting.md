#  Threat Hunting Playbook: PowerShell Encoded Commands (T1059.001)

![Defender for Endpoint](https://img.shields.io/badge/Defender_for_Endpoint-Telemetry-00A4EF?style=flat-square&logo=microsoft&logoColor=white)
![KQL](https://img.shields.io/badge/KQL-Detection_Logic-6f42c1?style=flat-square)
![MITRE ATT&CK](https://img.shields.io/badge/MITRE%20ATT&CK%C2%AE-T1059.001-FF6600?style=flat-square)
![Execution](https://img.shields.io/badge/Execution-TA0002-red?style=flat-square)
![Defense Evasion](https://img.shields.io/badge/Defense%20Evasion-TA0005-darkred?style=flat-square)

 **MITRE ATT&CK:** T1059.001  PowerShell  

**Tactics:** Execution (TA0002), Defense Evasion (TA0005)

**Category:** Threat Hunting / Manual Investigation  



## 🔸  Objective
To proactively detect and investigate the execution of obfuscated PowerShell commands (Base64 encoding) and execution policy bypasses. 

Because legitimate administrative use of `-EncodedCommand` is exceptionally rare in standard baselines, this technique serves as a high-fidelity indicator of malicious intent; typically signaling the deployment of fileless malware, C2 stagers, or evasion tactics.



## 🔸 Primary Hunting Query (KQL)

```kql
DeviceProcessEvents
| where FileName =~ "powershell.exe"
| where ProcessCommandLine has_any ("-enc", "-EncodedCommand", "-ep bypass", "-ExecutionPolicy Bypass")
// Pro-Tip: Exclude known, approved administrative automation in your specific environment to reduce noise:
// | where InitiatingProcessFileName !in~ ("sccm.exe", "taniumclient.exe", "sqlservr.exe")
| project Timestamp, DeviceName, InitiatingProcessFileName, ProcessCommandLine, AccountName
| order by Timestamp desc
```
## 🔸 Why This Matters

Threat actors and penetration testers (using frameworks like Cobalt Strike or PowerShell Empire) heavily rely on encoded PowerShell to achieve:

- **Defence Evasion:** Bypassing traditional signature-based AV and masking command-line arguments from basic logging.
- **Fileless Execution:** Running payloads directly in memory (via `IEX`) without dropping executable files onto the disk.
- **Payload Delivery:** Silently downloading secondary stages, C2 beacons, or ransomware droppers.
- **In-Memory Credential Theft:** Executing modules like `Invoke-Mimikatz` securely within the PowerShell process space.

Every instance of encoded PowerShell outside of explicitly approved IT automation warrants immediate investigation.



## 🔸Investigation Workflow 

### 🔸1. Decode the Payload
Extract the Base64 string from the command line and decode it:

```powershell
[System.Text.Encoding]::Unicode.GetString(
    [System.Convert]::FromBase64String("<encoded_string>")
)
```
> **Pro-Tip: KQL Inline Decoding**
> For rapid triage within Microsoft Sentinel or Defender, you can decode Base64 strings directly in your query to quickly spot suspicious modules or URLs without leaving the portal:
> ```kql
> extend DecodedCommand = base64_decode_tostring(EncodedString)
> ```
> *(Note: Because PowerShell uses UTF-16LE encoding, the output may appear with spaces between characters, but it remains highly readable for identifying IoCs).*

Look for:
- **Download cradles:** `Invoke-WebRequest` (or aliases `iwr`, `wget`, `curl`), `System.Net.WebClient`, and `.DownloadString()`.
- **In-memory execution:** `IEX` (`Invoke-Expression`), `Invoke-Command`, or `$ExecutionContext.InvokeCommand`.
- **External connections:** Suspicious URLs, raw GitHub gists, Pastebin links, or bare IP addresses.
- **Credential theft & malicious modules:** Strings related to dumping (e.g., `Mimikatz`, `comsvcs.dll`, `DumpCreds`, `procdump`).



### 🔸2. Build a Timeline of Activity

Pivot around the execution time:

```kql
DeviceProcessEvents
| where DeviceName == "<hostname>"
| where Timestamp between (startTime .. endTime)
| order by Timestamp asc
```
Identify:
- **Secondary payloads & downloads:** Execution of `certutil.exe -urlcache`, `bitsadmin.exe`, or subsequent PowerShell web requests.
- **Privilege escalation & enumeration:** Reconnaissance commands like `whoami /priv`, `systeminfo`, or unexpected UAC bypass attempts.
- **Credential access (LSASS):** Memory dumping via `comsvcs.dll`, `procdump.exe`, or suspicious Sysmon Event ID 10 (Process Access) targeting `lsass.exe`.
- **Lateral movement:** Usage of `psexec.exe`, WMI (`wmic.exe`), WinRM (`Enter-PSSession`), or mapping remote SMB shares (`net use`).
- **Persistence mechanisms:** Creation of scheduled tasks (`schtasks.exe`), modifying Registry Run keys (`reg add`), or adding new local admin accounts (`net user /add`).

### 🔸3. Correlate with Sysmon / Defender Events

Network activity:

 ```kql
    DeviceNetworkEvents
    | where InitiatingProcessFileName =~ "powershell.exe"
```

File writes:

```kql
    DeviceFileEvents
    | where InitiatingProcessFileName =~ "powershell.exe"
```
Suspicious child processes:
```kql
    DeviceProcessEvents
    | where InitiatingProcessFileName =~ "powershell.exe"
    | project FileName, ProcessCommandLine
```

Red flags (Suspicious Child Processes):
- **Proxy execution & LOLBins:** PowerShell spawning `rundll32.exe`, `regsvr32.exe`, or `mshta.exe` (often used to execute downloaded DLLs or bypass application control).
- **Command shell hand-offs:** Spawning `cmd.exe /c` to execute legacy batch commands, or `wscript.exe`/`cscript.exe` for VBScript/JScript execution.
- **Discovery & enumeration:** Launching built-in recon tools in rapid succession (e.g., `net.exe`, `whoami.exe`, `nltest.exe`, `ipconfig.exe`).
- **Credential theft execution:** Directly spawning known dumping tools (e.g., `procdump.exe`) or executing `rundll32.exe` with `comsvcs.dll` to target LSASS.


>🔸 **Pro-Tip: Defeating Obfuscation with AMSI & Event ID 4104**

 Relying solely on `ProcessCommandLine` can be a blind spot if the attacker employs heavy, multi-layered obfuscation. To see exactly what the encoded payload attempted to do in-memory:
 - **Script Block Logging (Event ID 4104):** When enabled, PowerShell logs the fully de-obfuscated script content just before execution. Pivot to `DeviceEvents` or the `Microsoft-Windows-PowerShell/Operational` log to read the plain-text code.
 - **AMSI (Antimalware Scan Interface):** AMSI inspects script content natively after it has been decoded but before it runs. Look for Defender alerts specifically mentioning AMSI, as these often contain the raw, unmasked payload snippets that triggered the signature.


### 🔸4. Identify the User Behind the Activity   
```kql
DeviceProcessEvents
| where ProcessCommandLine has "-enc"
| summarize count() by AccountName
```
Red Flags:
- **Interactive usage of Service Accounts:** Service accounts executing encoded PowerShell is highly anomalous, especially if associated with interactive logons (Logon Type 2 or 10) rather than standard network logons (Logon Type 3).
- **High-privileged account abuse:** Local Administrator (`RID 500`), Domain Admins, or unexpected tier-0 accounts executing commands on standard user workstations.
- **Temporal and geographic anomalies:** Execution by accounts active significantly outside normal working hours, or those currently triggering "Impossible Travel" / unfamiliar sign-in alerts in Entra ID (Azure AD).
- **Recent authentication alerts:** Execution closely following brute-force patterns (multiple Event ID 4625s followed by a successful 4624), password sprays, or MFA fatigue (MFA spam) alerts.


## 🔸Indicators of Compromise (IoCs)

- **PowerShell launched from unusual parent processes:**
  - Office applications (`winword.exe`, `excel.exe`) ➔ Highly indicative of malicious macros.
  - Scripting engines (`wscript.exe`, `cscript.exe`) ➔ Common in drive-by downloads or initial payloads.
  - Web servers (`w3wp.exe`, `httpd.exe`) ➔ Critical indicator of potential web shell exploitation.

- **Encoded commands containing URLs or downloaders:**
  - Look out for classes and methods like `Net.WebClient`, `DownloadString`, or `Invoke-WebRequest` (often using aliases such as `iwr`, `wget`, or `curl`).
  - Network connections reaching out to untrusted hosting sites (e.g., Pastebin, raw GitHub gists, ngrok domains) or bare IP addresses instead of resolved domains.

- **Base64 payloads executing in-memory (`IEX`):**
  - The classic fileless pattern: `IEX(New-Object Net.WebClient).DownloadString(...)`.
  - Watch for obfuscated `Invoke-Expression` variations using backticks (e.g., `I`e`X`) or alternatives like `$ExecutionContext.InvokeCommand.InvokeScript`.

- **PowerShell spawning credential dumpers or lateral movement binaries:**
  - LSASS memory access patterns (e.g., `rundll32.exe comsvcs.dll, MiniDump` or spawning `procdump.exe`).
  - Launching native enumeration or execution tools such as `wmic.exe`, `nltest.exe`, `net.exe`, or `vssadmin.exe` (often used to delete shadow copies).

- **Execution shortly after suspicious authentication events:**
  - Activity immediately following a successful brute-force or password spray attack (Event ID 4624 Logon Type 3 or 10).
  - Execution tied to an account triggering "Impossible Travel" alerts or logging in from an unexpected VPN IP address.





## 🔸 Recommended Actions

1. **Containment:** Isolate the host via EDR (Network Isolation) to immediately sever Command and Control (C2) beaconing and prevent lateral movement, whilst keeping the machine available for forensic analysis.
2. **Payload Triage:** Decode and analyse the payload (as detailed in Step 1) to extract all actionable IoCs, including dropped file hashes, C2 IP addresses, and malicious domains.
3. **Identity Remediation:** Reset credentials for all compromised or suspicious accounts. Crucially, revoke all active sessions and refresh tokens (e.g., via Entra ID / Azure AD) to ensure the attacker loses access.
4. **Perimeter & EDR Blocking:** Add the extracted IoCs (hashes, IPs, domains) to your EDR's Custom Indicators (Block/Remediate) and update perimeter firewall or web proxy blocklists.
5. **Scope the Blast Radius:** Hunt for the extracted IoCs and lateral movement artifacts across the broader environment to ensure no other endpoints have been compromised.
6. **Escalation:** Escalate to Incident Response (L3/DFIR) if a malicious second stage is executed, hands-on-keyboard activity is detected, or if data exfiltration is suspected. Provide them with the decoded payload and your timeline.

## 🔸 Practical Demonstrations (PoCs)

Together, these three investigations represent a complete SOC operational lifecycle - from identifying the obfuscation, to hunting a live threat, and finally engineering a robust detection mechanism to defeat the evasion at scale.

🔗 **[Investigation Case 1: Threat Hunting for PowerShell Obfuscation (Base64 Decoding)](/2.investigations/02-threat-hunt-powershell.md)**   
*(Phase 1: Identification: Understanding and manually decoding the obfuscation technique).*  
🔗 **[Investigation Case 2: Phishing via MS Word & PowerShell Execution (True Positive)](/2.investigations/05-true-positive-powershell.md)**  
*(Phase 2: Triage & Response: Detecting and isolating a live evasion attempt during a LotL malware infection).*   
🔗 **[Investigation Case 3: Defeating Obfuscation with PowerShell ScriptBlock Logging (Event ID 4104)](/7.hands-on/day3-powershell-logging/day3-powershell-logging.md)**  
*(Phase 3: Detection Engineering: Configuring advanced telemetry to automatically strip the disguise and reveal true intent).*


## 🔸 Analyst Notes

>  Encoded PowerShell is one of the most reliable early indicators of compromise. Treat every encoded command as suspicious until proven otherwise.

## 🔸 Connect with me   

**Magda Dominguez**    
Blue Team operations 🔸 SOC investigations 🔸 Logistics-to-SOC analytical mindset 

[![Magda Dominguez LinkedIn](https://img.shields.io/badge/LinkedIn-Magda_Dominguez-9370DB?style=flat-square&logo=linkedin&logoColor=white)](https://www.linkedin.com/in/magda-d-infosec)




