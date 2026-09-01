
# 🟦 Sysmon Event ID 11 : FileCreate  
### VS Code → Copilot CLI bootstrap file (copilot.bat)

## 🔹 Event Summary  
Visual Studio Code created or accessed a file named `copilot.bat` within the Copilot Chat extension’s global storage directory.  
This file is part of the GitHub Copilot CLI bootstrap mechanism and is used to support command‑line integration and extension functionality.  
The behaviour is entirely legitimate and expected when VS Code initialises or updates extensions.

## 🔹 Evidence Extract  

![EVENT-ID-11-VS](/1.detections/0.hands-on-evidence/benign-process-explained/screenshots/EVENT-11-VS.png)

- Image: `Code.exe`  
- TargetFilename: `copilot.bat`  
- Location: `AppData\Roaming\Code\User\globalStorage\github.copilot-chat\copilotCli\`  
- User: `Azul_Fifty\magda`  
- Logged Timestamp: `2026‑08‑28 23:00:06.953`  
- Original Creation Time: `2026‑04‑02 00:11:10.590`

## 🔹 Why It’s Benign  
- The file resides in a legitimate VS Code extension directory  
- The filename matches Copilot CLI bootstrap components  
- The process is a trusted application (VS Code)  
- The activity occurs under an interactive user account  
- The timestamp difference indicates the file already existed and was simply accessed  
- No correlation with malicious Sysmon events (IDs 1, 3, 8, 10)

## 🔹 My Notes  
This event demonstrates the ability to recognise legitimate application behaviour and avoid false positives.  
VS Code extensions frequently create and update files within their global storage directories, and this pattern is entirely normal.

---
### **Authored by**
**Magda Dominguez** 
 
Security Operations • Detection Engineering • Blue Team

---