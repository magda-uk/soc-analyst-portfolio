
# 🟦 Sysmon Event ID 11 : FileCreate  
# PowerShell → __PSScriptPolicyTest_*.ps1 (Benign Script Policy Test)


## 🔹 Event Summary  
PowerShell created a temporary file named `__PSScriptPolicyTest_*.ps1` within the `AppData\Local\Temp` directory.  
This file is generated automatically by PowerShell as part of its internal mechanism for validating execution policies and security restrictions.  
It does not contain malicious content and is not executed.

## 🔹 Evidence Extract  

![EVENT 11](/3.log-analysis/sysmon/id11-file-create/screenshots/powershell.png)

- Image: `powershell.exe`  
- TargetFilename: `__PSScriptPolicyTest_q1hvaqtf.xlg.ps1`  
- User: `Azul_Fifty\magda`  
- Location: `AppData\Local\Temp`  
- Timestamp: `2026‑08‑28 22:59:50.604`





## 🔹 Behavioural Analysis

### 1. Suspicious Directory
`AppData\Local\Temp` is a high‑risk directory because:
* Any standard user can write to it
* Malware frequently stages payloads here
* Droppers and phishing attachments often unpack into Temp
* Script‑based attacks (PowerShell, VBS, JS) commonly use Temp for execution

This makes any executable or script creation in Temp worth reviewing, even if benign.

### 2. Suspicious File Type
The file created is a PowerShell script (`.ps1`), which is an execution‑capable format.

Attackers often drop `.ps1` files to:
* Run post‑exploitation commands
* Download additional payloads
* Execute encoded or obfuscated logic
* Bypass AMSI or logging controls

Even though this specific file is part of PowerShell’s internal policy testing mechanism, the pattern itself is identical to malicious behaviour.

### 3. Process Responsible
`powershell.exe` creating a script file is a high‑signal event.

In malicious scenarios, this may indicate:
* Script‑based malware
* Living‑off‑the‑land (LotL) execution
* Payload unpacking
* AMSI bypass attempts
* Reconnaissance or credential theft tooling

In benign scenarios, PowerShell may generate temporary files during module loading or policy evaluation — which is the case here.




## 🔹 Why It’s Benign  
- The filename matches the official pattern used by PowerShell’s Script Policy Test  
- The file is created in a standard temporary directory  
- The process is legitimate and shows no suspicious flags  
- The activity occurs under an interactive user account  
- There is no correlation with malicious Sysmon events (IDs 1, 3, 8, 10, 11)


> However, the event remains valuable because malicious activity looks almost identical.



