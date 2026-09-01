# Sysmon Event ID 1 (Process Creation)
### Living-off-the-Land Binary (LOLBin) Execution — OEM Service Control via `sc.exe`

---

## 📌 Executive Summary

This report analyses a **Sysmon Event ID 1 (`ProcessCreate`)** event involving the execution of the Windows Service Control utility (`sc.exe`). 

While `sc.exe` is a dual-use binary frequently abused by adversaries for **Service Execution ([MITRE ATT&CK T1569.002](https://attack.mitre.org/techniques/T1569/002/))** and lateral movement, behavioural triage confirms this instance is **benign OEM maintenance activity**. The utility was spawned by a Lenovo Vantage component (`SmartPanelAddin.exe`) to start the legitimate `LenovoSensorFusion` system service under `NT AUTHORITY\SYSTEM`.

---

## 📋 Evidence Extract

![EVENT 1 LOLBIN](/3.log-analysis/sysmon/id1-process-creation/screenshots/lolbin-sc-exe.png)

---

## 🔗 Technical Analysis & Process Lineage

### 1. Process Hierarchy & Execution Lineage
* **Parent Process:** `C:\Program Files (x86)\Lenovo\VantageService\5.1.2608.14\LenovoVantage-(SmartPanelAddin).exe` (PID: `130500`).
* **Child Process (LOLBin):** `C:\Windows\System32\sc.exe` (PID: `129220`).
* **Lineage Assessment:** Instead of invoking native Win32 Service Management APIs (`OpenSCManager`, `StartService`) internally within its module code, the OEM add-in spawned the native command-line binary `sc.exe` to manage service state transitions.

### 2. Command-Line Intent & Payload Inspection
* **Command Line:** `"C:\Windows\System32\sc.exe" start LenovoSensorFusion`
* **Target Service:** `LenovoSensorFusion` (responsible for hardware sensor integration, panel orientation, and touch telemetry).
* **Execution Verb:** `start` (demands lower scrutiny compared to destructive or persistent verbs like `create`, `config`, or `delete`).

### 3. Context & Privilege Verification
* **User Context:** `NT AUTHORITY\SYSTEM` across both parent and child processes.
* **Integrity Level:** `System`.
* **Path Authenticity:** `sc.exe` executed strictly from the canonical `C:\Windows\System32\` directory.

---

## 🟢 Benign Triage Criteria (False-Positive Validation)

* [x] **Verified OEM Parentage:** Spawned directly by a signed Lenovo Vantage subsystem binary.
* [x] **Non-Destructive Command Verb:** Limited to `start` rather than modifying service configurations or binary paths (`binPath=`).
* [x] **Known Service Target:** Targets a recognised, pre-existing OEM vendor service (`LenovoSensorFusion`).
* [x] **No Intermediate Interpreters:** Executed without chaining through command shells (`cmd.exe /c`, `powershell.exe`).

---



## 🗺️ MITRE ATT&CK Mapping

| Attribute | Details |
| :--- | :--- |
| **Tactic** | Execution ([TA0002](https://attack.mitre.org/tactics/TA0002/)), Defense Evasion ([TA0005](https://attack.mitre.org/tactics/TA0005/)) |
| **Technique** | System Services: Service Execution ([T1569.002](https://attack.mitre.org/techniques/T1569/002/)) |
| **Associated LOLBin** | `sc.exe` (Windows Service Control Manager) |
| **Classification** | **Benign OEM Subprocess Invocation (LOLBin Baseline Example)** |

---

## 🛡️ **Authored by:** **Magda Dominguez**  
Security Operations • Detection Engineering • Blue Team


