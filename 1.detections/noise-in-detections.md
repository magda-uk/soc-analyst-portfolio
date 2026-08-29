# 🧩 Lenovo Vantage Noise Analysis

**Understanding OEM Noise in Sysmon Telemetry**

---

## Overview

Lenovo Vantage is a pre-installed OEM application responsible for system optimisation, battery management, driver updates, diagnostics, and device-specific features. Because of its modular architecture, it generates a substantial volume of Sysmon telemetry, specifically:

* **Event ID 1** — Process Create
* **Event ID 7** — Image Loaded
* **Event ID 8** — CreateRemoteThread
* **Event ID 10** — ProcessAccess

> **Key Takeaway:** This behaviour is normal system activity and should not be mistaken for malicious adversary tradecraft.

---

## 🔹 Why Lenovo Vantage Generates Noise


Lenovo Vantage relies on a central host service:

```text
LenovoVantageService.exe
```
This core service dynamically loads multiple add-ins, each packaged and executed as an independent binary:

* `LenovoVantage-(BatteryWidgetAddin).exe`
* `LenovoVantage-(IdeaNotebookAddin).exe`
* `LenovoVantage-(SmartDisplayAddin).exe`
* `LenovoVantage-(HardwareScanAddin).exe`
* `LenovoVantage-(CompanionAppAddin).exe`

Each add-in loads its own dedicated DLL modules and performs continuous system health checks, hardware diagnostics, or UI telemetry updates. Sysmon records every discrete action across these subprocesses.

---

## 🔹 Typical Sysmon Telemetry Patterns


### 1. Process Creation (Sysmon Event ID 1)
Multiple add-ins spawn sequentially as child processes:
```yaml
Image:          LenovoVantage-(BatteryWidgetAddin).exe
ParentImage:    LenovoVantageService.exe
IntegrityLevel: Medium
User:           <user_account>
```
Context: Expected modular architecture behavior.

### 2. Image Load (Sysmon Event ID 7)
Add-ins continuously load libraries from application data directories:

`C:\ProgramData\Lenovo\Vantage\Addins\<AddinName>\`

Context: Modules are legitimately signed and verified by Lenovo.

### 3. Remote Thread Injection (Sysmon Event ID 8)
Add-ins interact directly with Windows Error Reporting (`WerFault.exe`), system diagnostics, or UI process spaces.

**Context:** Generates benign `CreateRemoteThread` telemetry that mimics thread execution/injection techniques.

### 4. Process Access (Sysmon Event ID 10) 
Add-ins query running system processes to gather battery, CPU performance, and thermal metrics.  

**Context:** Routine operational polling.

---

## 🔹 Triage Matrix: Identifying Benign OEM Artifacts

| Feature / Field | Benign Indicator |
| :--- | :--- |
| **Company** | `Lenovo` |
| **Product** | `Lenovo.Vantage.AddinHost.Amd64` |
| **Parent Process** | `LenovoVantageService.exe` (running as `SYSTEM`) |
| **Execution Paths** | • `C:\Program Files (x86)\Lenovo\VantageService\...`<br>• `C:\ProgramData\Lenovo\Vantage\Addins\...` |
| **Signature Validation** | Valid Microsoft / Lenovo digital certificates across all modules. |
| **Behavioral Profile** | • High-frequency process spawning.<br>• Routine diagnostic polling.<br>• No privilege escalation attempts across user boundaries.<br>• Standard command-line arguments. |

---

## 🔹 Detection Engineering & SOC Value

OEM software creates high-volume telemetry noise in production enterprise environments. Documenting and analyzing these baselines enables SOC analysts to:

* **Prevent False Positives:** Avoid unnecessary alerting on benign diagnostic routines.
* **Optimize Triage Time:** Quickly dismiss known OEM hooks during active investigations.
* **Refine Tuning:** Differentiate legitimate cross-process communication from hostile code injection (MITRE T1055).
* **Maintain High-Fidelity Rule Sets:** Build targeted exclusion filters without blinding the SIEM to attacker abuse.

---

## 🔹 Suggested Detection Exclusion Logic

To tune detection rules (such as SIEM KQL or Sigma rules) without creating blind spots:
```
// Filter by execution path or parent process lineage
(
    Image startswith @"C:\Program Files (x86)\Lenovo\VantageService\"
    or ParentImage endswith @"\LenovoVantageService.exe"
)
// Optional verification filters
and (
    Company == "Lenovo"
    or Description startswith "Lenovo.Vantage"
)
```
---

## 🔹 Summary

* Lenovo Vantage is a legitimate, modular OEM suite that generates heavy Sysmon telemetry.
* Add-in subprocesses naturally trigger **Events 1, 7, 8, and 10**.
* Baselining vendor signatures and execution paths is essential for maintaining accurate, low-noise threat detection.

---

**Authored by**  
Magda Dominguez  
*Security Operations • Detection Engineering • Blue Team*