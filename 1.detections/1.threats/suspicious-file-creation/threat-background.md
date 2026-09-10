# Threat Background: Suspicious File Creation in Temporary and Public Directories

## Overview
Adversaries frequently stage payloads, droppers, post‑exploitation tooling, and malware components within directories that allow write access for standard users. These locations include:

* `C:\Windows\Temp\`
* `C:\Users\Public\`
* `C:\ProgramData\`
* `C:\Users\<User>\AppData\Local\Temp\`

These folders are commonly abused because they provide:
* Write access without administrative privileges
* Low visibility and weak monitoring
* High volume of legitimate noise, making malicious activity harder to detect
* Ideal staging points for execution, persistence, or lateral movement

This behaviour is typically observed during initial access, malware staging, or post‑exploitation activity.

## How Adversaries Use These Directories
Threat actors leverage temporary and public directories to:

* Drop malicious executables (`.exe`, `.dll`, `.sys`)
* Stage scripts (`.ps1`, `.bat`, `.vbs`, `.js`)
* Unpack payloads delivered via phishing or drive‑by downloads
* Store tools used for credential theft, reconnaissance, or persistence
* Execute malware directly from these locations to evade basic controls

Commodity malware, ransomware operators, and red‑team tooling frequently rely on these directories due to their permissive nature.

## Why This Behaviour Is Suspicious
File creation in these directories becomes high‑risk when:

* The file extension indicates execution capability
* The parent process is unexpected or suspicious (e.g., `winword.exe`, `chrome.exe`, `powershell.exe`)
* The binary is unsigned, unknown, or downloaded from the internet
* The file is executed shortly after creation
* The file triggers additional events such as network connections, process injection, or registry modification

This pattern often represents the first observable indicator of malware deployment.

## MITRE ATT&CK Mapping
* **TA0002** — Execution
* **TA0005** — Defence Evasion
* **T1204.002** — User Execution: Malicious File
* **T1059** — Command and Scripting Interpreter (when scripts are dropped)
* **T1105** — Ingress Tool Transfer (payload delivery)

## Relevant Log Sources
* **Sysmon Event ID 11 — FileCreate**  
  Primary source for detecting suspicious file creation.
* **Windows Security Event ID 4663 — Object Access**  
  Useful for correlating file system access attempts.

These logs provide visibility into file creation events, including the full path, file extension, and the process responsible.

## Indicators of Malicious File Creation
Common red flags include:

* Executables dropped into Temp, Public, or ProgramData
* Script files created by Office applications or browsers
* Files created by unsigned or unknown binaries
* Payloads appearing shortly before process execution or network activity
* Repeated file creation patterns indicating automated tooling

## Associated Threats
Suspicious file creation is often linked to:

* Phishing payload deployment
* Initial access via malicious attachments
* Malware unpacking and staging
* Ransomware pre‑execution behaviour
* Post‑exploitation tooling dropped by C2 frameworks
* Persistence mechanisms relying on dropped binaries

## Practical Example
See the hands‑on investigation:  
[**Sysmon Event ID 11 — Suspicious File Creation**](/3.log-analysis/sysmon/id11-file-create/event-id-11-filecreate.md)  
This case demonstrates how attackers drop executables into temporary directories and how these events can be used to identify early‑stage compromise.