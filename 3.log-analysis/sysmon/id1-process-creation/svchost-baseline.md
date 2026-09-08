# Security Event Analysis
# Process Baselining & Masquerading Detection (Sysmon Event ID 1)

## 🔸 Summary
In Security Operations, the ability to detect malicious activity relies heavily on understanding normal system behavior (Baselining). This document analyzes a highly common, benign **Sysmon Event ID 1 (Process Create)** involving `svchost.exe`. By deconstructing this expected behavior, analysts can effectively hunt for anomalies such as **Masquerading (MITRE ATT&CK: T1036)**, where adversaries disguise malware as legitimate system processes.

## 🔸 Case Study: Legitimate Service Host Execution

During routine telemetry review, the following process creation event was logged:

### 🔸 Raw Telemetry (Sysmon Event ID 1)

![Event 1 - Admin](/3.log-analysis/sysmon/id1-process-creation/screenshots/svchost.png)

*   **UtcTime:** `2026-09-07 23:03:51.946`
*   **Image:** `C:\Windows\System32\svchost.exe`
*   **CommandLine:** `C:\Windows\system32\svchost.exe -k GPSvcGroup`
*   **User:** `NT AUTHORITY\SYSTEM`
*   **ParentImage:** `C:\Windows\System32\services.exe`
*   **IntegrityLevel:** `System`

### 🔸 Log Deconstruction & Triage
This log represents the absolute standard behavior of the Windows Operating System. 

1.  **The Process (`svchost.exe`):** The Service Host process is designed to host multiple Windows services that run from Dynamic-Link Libraries (DLLs). It is normal to see dozens of these processes running simultaneously.
2.  **The Parent (`services.exe`):** The Service Control Manager is the only legitimate parent process that should spawn a standard system `svchost.exe`.
3.  **The Command Line (`-k`):** Windows groups similar services together to optimize memory usage. The `-k` flag specifies the service group (in this case, `GPSvcGroup` for Group Policy services). An `svchost.exe` running without this flag is highly anomalous.
4.  **The Directory:** The binary is executing from its authorized path: `C:\Windows\System32\`.

## 🔸 Threat Hunting & Detection Engineering

While the analysed event is benign, threat actors frequently exploit the ubiquity of `svchost.exe` to hide in plain sight. SOC Analysts must monitor for the following deviations from this baseline:

*   **Abnormal Path:** `svchost.exe` executing from `C:\Temp\`, `C:\Users\Public\`, or `C:\Downloads\`.
*   **Anomalous Parent Process:** `svchost.exe` spawned by `cmd.exe`, `powershell.exe`, `explorer.exe`, or Microsoft Office applications (e.g., `winword.exe`).
*   **Missing or Suspicious Flags:** Execution without the `-k` parameter, or utilizing unexpected network arguments (e.g., connecting directly to external IPs).
*   **Suspicious Child Processes:** A legitimate `svchost.exe` should rarely, if ever, spawn a command shell (`cmd.exe` or `powershell.exe`). If it does, it may indicate a service exploitation or a spawned reverse shell.

## 🔸 Conclusion
By thoroughly understanding the telemetry of legitimate Windows architecture, defenders can create robust SIEM detection rules that filter out the noise of normal operations while reliably catching Masquerading attempts.

## 🔸 Author 🔸

**Magda Dominguez**  
*SOC Analyst (L1-ready) Bristol, UK*  
Focused on Blue Team operations, detection engineering and log analysis.