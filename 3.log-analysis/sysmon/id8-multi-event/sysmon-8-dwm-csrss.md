# Sysmon Event ID 8 (CreateRemoteThread)

> Windows GUI Subsystem Baseline 

> DWM to CSRSS Thread Creation

## 📌 Executive Summary

This investigation documents a benign *Sysmon Event ID 8 (CreateRemoteThread)* telemetry capture observed between the Desktop Window Manager (`dwm.exe`) and the Client/Server Runtime Subsystem (`csrss.exe`).

While `CreateRemoteThread` is heavily monitored as a high-fidelity indicator for *Process Injection (MITRE ATT&CK T1055)*, native Windows OS components routinely leverage low-level inter-process communication for graphics rendering, session boundary management, and window messaging. Documenting this baseline behaviour is essential for detection tuning, SOC triage, and false-positive suppression.

## 📋 Evidence Extract
![EVENT 8](.//images/enhanced.png)

```text
Event Type: Sysmon Event ID 8 (CreateRemoteThread detected)
UtcTime: 2026-08-30 05:08:22.995
SourceProcessGuid: {79317113-bac1-6a93-6dad-030000005000}
SourceProcessId: 145696
SourceImage: C:\Windows\System32\dwm.exe
TargetProcessGuid: {79317113-bac1-6a93-69ad-030000005000}
TargetProcessId: 146820
TargetImage: C:\Windows\System32\csrss.exe
NewThreadId: 147904
StartAddress: 0xFFFFF8039A5BD220
StartModule: -
StartFunction: -
SourceUser: Window Manager\DWM-6
TargetUser: NT AUTHORITY\SYSTEM
```
## 📋 Technical Analysis & Process Lineage

## 1. Process Roles & Architecture
* **dwm.exe (Desktop Window Manager):** Operates as a per-session compositing manager responsible for rendering visual effects, window management, and hardware acceleration on modern Windows desktops.
* **csrss.exe (Client/Server Runtime Subsystem):** An essential user-mode subsystem handling process/thread creation routines and Win32 console maintenance.

## 2. Mechanism & Behavioral Justification
High-performance graphical pipeline operations require low-overhead synchronization between DWM and CSRSS. DWM utilizes native Windows API calls to spawn synchronization worker threads directly within the CSRSS execution boundary during desktop session lifecycle transitions.

## 3. Authentication & Privilege Verification
* **Source Context (Window Manager\DWM-6):** The source process executed under a dedicated, low-privilege virtual service account provisioned specifically for session rendering isolation.
* **Target Context (NT AUTHORITY\SYSTEM):** The target process ran in the native, high-privilege subsystem space.
* **Security Validation:** No privilege escalation indicators or cross-user context hopping were observed; the interaction adhered strictly to expected session subsystem protocols.

## 4. Memory & Path Legitimacy
* Both executables are situated strictly within the canonical path: `C:\Windows\System32\`.
* The start address (`0xFFFFF8039A5BD220`) reflects kernel/subsystem routine handling associated with Win32 graphics context switching.

## ✅ Benign Triage Criteria (False-Positive Validation)
When evaluating `CreateRemoteThread` telemetry in a SOC environment, this activity is classified as benign OEM / system noise based on the following criteria:
* [x] **Canonical Binary Paths:** Both source and target reside in verified System32 directories.
* [x] **Standard Subsystem Relationship:** Known architectural coupling between `dwm.exe` and `csrss.exe`.
* [x] **Virtual Service Principal:** Execution initiated under `Window Manager\DWM-*`, rather than an interactive user or administrative account.
* [x] **Absence of Staging Tools:** No intermediary LOLBins (`powershell.exe`, `cmd.exe`, `rundll32.exe`) or anomalous staging directories (`%TEMP%`, `%APPDATA%`) in the execution chain.

## ⚙️ Detection Engineering & SIEM / Sysmon Tuning
To prevent alert fatigue and reduce false positives in SIEM/EDR platforms, high-volume legitimate OS subsystem interactions like this one should be baseline-filtered at the Sysmon XML or SIEM query level.

> **Note:** The specific exclusion filters and XML logic rules to suppress this noise are maintained in the dedicated detection engineering rules directory of this repository.

## 🗺️ MITRE ATT&CK Mapping

| Attribute | Detail |
| :--- | :--- |
| **Tactic** | Defense Evasion (TA0005), Privilege Escalation (TA0004) |
| **Technique** | Process Injection (T1055) |
| **Sub-technique** | Process Injection: Dynamic-link Library Injection / Thread Hijacking |
| **Classification** | Benign / False-Positive Suppression Example (Subsystem Noise Baseline) |

----

*Authored by: Magda Dominguez*  
*Security Operations • Detection Engineering • Blue Team*