# Detection Logic: Encoded PowerShell Execution

##  Objective
Detect the execution of PowerShell commands using Base64 encoded payloads. This technique is frequently used by adversaries to hide malicious scripts, bypass simple string-based alerting, and obfuscate their initial commands.

##  Threat Background
PowerShell allows legitimate users to run complex scripts using the `-EncodedCommand` parameter (or its variations like `-enc`, `-e`, `-en`). While designed to avoid formatting issues with complex quotes, threat actors (and frameworks like Cobalt Strike or Empire) heavily abuse this feature to mask their intentions. By encoding the payload, the raw command line does not immediately reveal the malicious code being executed.

##  MITRE ATT&CK Mapping
➡️ **Tactic:** Execution (TA0002), Defense Evasion (TA0005)

➡️ **Technique:** Command and Scripting Interpreter: PowerShell (T1059.001), Obfuscated Files or Information (T1027)

##  Log Sources & Event IDs
➡️ **Sysmon:** Event ID 1 (Process Creation)

➡️**Windows Security:** Event ID 4688 (A new process has been created)

➡️ **PowerShell Operational:** Event ID 4104 (Execute a Remote Command / Script Block Logging) 
*Crucial for viewing the decoded payload.*

##  Detection Logic (Conceptual)
The detection triggers when a process creation event involves PowerShell and the command line includes flags associated with Base64 encoding.

➡️ **Target Process:**
   - `powershell.exe`
   - `pwsh.exe`

➡️ **Command Line Contains (regex or string match):**
   - `-EncodedCommand`
   - `-enc`, `-en`, `-e` (often combined with `-nop` or `-w hidden`)
   - `[Convert]::FromBase64String`

### Pseudo-Query
```sql
(ProcessName == 'powershell.exe' OR ProcessName == 'pwsh.exe')
AND CommandLine CONTAINS_ANY ('-EncodedCommand', '-enc ', '-en ', '-e ')
```
*(Note: A more advanced detection might use regex to specifically look for the base64 padding `==` or typical base64 character sets following the flag).*

## ⚠️ Known False Positives

➡️**RMM Tools:** Remote Monitoring and Management software (e.g., ConnectWise, Kaseya, Datto) frequently use encoded PowerShell for legitimate remote administration.

➡️ **IT Automations:** SCCM, Microsoft Intune, and Azure AD Connect scripts often run heavily obfuscated or encoded commands.

➡️ **Exchange Servers:** Microsoft Exchange heavily relies on PowerShell and sometimes uses encoded commands for internal operations.

## Basic Triage Steps

➡️ **Decode the Payload:** Extract the Base64 string from the command line and decode it (using tools like CyberChef or a safe local terminal).

➡️ **Analyze the Decoded Script:** Look for malicious indicators such as `Net.WebClient`, `DownloadString`, `Invoke-Expression` (`IEX`), or connections to external/suspicious IP addresses.

➡️ **Investigate the Parent Process:** What spawned the PowerShell session? If the parent is `winword.exe`, `excel.exe`, or `wscript.exe`, it is highly indicative of a malicious phishing payload.

➡️ **Check for Script Block Logging:** If Event ID 4104 is enabled, check it. It will automatically log the *decoded* and de-obfuscated script that PowerShell actually executed.

##  Practical Application

To see how this detection logic is applied in a real-world scenario, please review my hands-on log analysis exercise for encoded PowerShell execution:

➡️ [**Log Analysis Practice: Encoded PowerShell Execution**](/2.investigations/powershell-encoded.md#threat-hunting-for-powershell-obfuscation-t1059001)


## Author 
**Magda Dominguez**  
Security Operations 🔹 Detection Engineering 🔹 Blue Team