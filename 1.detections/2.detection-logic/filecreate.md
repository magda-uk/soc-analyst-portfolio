# Detection Logic
# Suspicious Executable File Creation in Temp/Public Folders

## 💠 Objective
Detect the creation of executable files or scripts within commonly abused temporary or public directories, which is often an indicator of initial payload delivery or malware staging.

## 💠 Threat Background
Adversaries and commodity malware frequently drop their initial payloads, backdoors, or post-exploitation tools in directories where standard users have write permissions (e.g., `C:\Windows\Temp\` or `C:\Users\Public\`). This allows them to stage files without requiring administrative privileges and often helps evade basic directory restrictions.

## 💠 MITRE ATT&CK Mapping
🔹 **Tactic:** Execution (TA0002), Defense Evasion (TA0005)

🔹 **Technique:** User Execution: Malicious File (T1204.002)

## 💠 Log Sources & Event IDs
 🔹Sysmon: Event ID 11 (FileCreate)

 🔹Windows Security: Event ID 4663 (An attempt was made to access an object - File System)

## 💠 Detection Logic (Conceptual)
The detection triggers when a file creation event matches **both** of the following conditions:

🔹1. **Target Directory contains:**
   - `*\Windows\Temp\*`
   - `*\Users\Public\*`
   - `*\AppData\Local\Temp\*`
   - `*\ProgramData\*`

🔹2. **File Extension is one of:**
   - `.exe`, `.dll`, `.sys`, `.bat`, `.ps1`, `.vbs`, `.js`

### 💠 Pseudo-Query
```sql
EventID = 11 
AND TargetFilename CONTAINS ('\Windows\Temp\', '\Users\Public\', '\AppData\Local\Temp\', '\ProgramData\') 
AND TargetFilename ENDSWITH ('.exe', '.dll', '.bat', '.ps1', '.vbs', '.js')
```
## 💠 Known False Positives

🔹 **Software Installers:** Legitimate updaters (e.g., Chrome, Adobe, Windows Updates) frequently extract executables to `Temp` or `ProgramData` during installation.

🔹 **Security Tools:** Antivirus or EDR agents temporarily isolating files or writing diagnostic logs.

🔹 **Admin Scripts:** System administrators deploying legitimate maintenance scripts from shared/public folders.

## 💠 Basic Triage Steps

1️⃣ **Analyze the Parent Process:** What process created this file? (e.g., if `winword.exe` drops an `.exe` in `Temp`, it is highly suspicious).

2️⃣ **Examine the File:** Check the file hash against Threat Intelligence (like VirusTotal) and verify if the file is digitally signed by a trusted publisher.

3️⃣ **Follow the Execution Chain:** Was the newly created file executed shortly after creation? Did it initiate any network connections?



## 💠 Authored by
**Magda Dominguez**  
Security Operations 🔹 Detection Engineering 🔹 Blue Team