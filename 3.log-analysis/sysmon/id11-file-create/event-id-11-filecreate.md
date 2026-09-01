#============================================================
# 🟦 Sysmon Event ID 11 — FileCreate  
### PowerShell → __PSScriptPolicyTest_*.ps1 (Benign Script Policy Test)
#============================================================

## 🔍 Event Summary  
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



## 🟩 Why It’s Benign  
- The filename matches the official pattern used by PowerShell’s Script Policy Test  
- The file is created in a standard temporary directory  
- The process is legitimate and shows no suspicious flags  
- The activity occurs under an interactive user account  
- There is no correlation with malicious Sysmon events (IDs 1, 3, 8, 10, 11)

## My Notes  
This event demonstrates the ability to distinguish legitimate PowerShell behaviour from malicious script execution.