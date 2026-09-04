# 🟩LSASS Credential Access & Dumping  
**Category:** Credential Access  
**MITRE ATT&CK:** T1003 (OS Credential Dumping), T1055 (Process Injection), T1036 (Masquerading)

---

## 🟩 Overview  
The Local Security Authority Subsystem Service (LSASS) is responsible for authentication, token generation, and secure credential storage on Windows systems.  
Any attempt to **access**, **read**, or **dump** LSASS memory is considered a high‑severity indicator of credential theft.

This threat consists of two related phases:

### 1) LSASS Access (Pre‑Dumping Phase)  
Attempts to open LSASS with elevated permissions to read memory.  
Typical behaviours include:

- `OpenProcess` with `PROCESS_VM_READ`
- `ReadProcessMemory`
- `DuplicateHandle`
- Pre‑dumping calls to `MiniDumpWriteDump`

### 2) LSASS Credential Dumping (Dumping Phase)  
Actions that extract credentials from LSASS memory.  
Common examples:

- Mimikatz  
- Procdump (including renamed binaries)  
- `comsvcs.dll`  
- Creation of `lsass.dmp`  
- Memory scraping via injected threads

Both phases form part of the same attack chain, but require different detection logic and triage workflows.

---

## 🟩MITRE ATT&CK Mapping  
| Phase | Technique | Description |
|-------|-----------|-------------|
| LSASS Access | T1055 | Process Injection / Handle Duplication |
| LSASS Access | T1003.001 | Attempted access to LSASS memory |
| LSASS Dumping | T1003.001 | LSASS Memory Dump |
| LSASS Dumping | T1036 | Masquerading (renamed Procdump binaries) |

---

## 🟩 Detection Logic (Global)

Detection logic for LSASS Access and LSASS Dumping is centralised in our logic directory:

 🛠️ **Completed:** [LSASS Credential Dumping - KQL Logic](../../2.detection-logic/LSASS-credential-dumping.md#detection-logic-lsass-credential-dumping)

 🛠️ **Pending:** *[Placeholder] LSASS Access - KQL Logic (Coming Soon)*

Typical rules include:
- **Sigma:** LSASS Access via suspicious OpenProcess calls
- **Sentinel:** LSASS Dumping via Procdump
- **Elastic:** LSASS Dumping via comsvcs.dll

## 🟩 Hands‑On Evidence

The practical triage and log analysis for this threat will be documented here once the simulated attack is completed in the lab environment.

-  [Incident Investigation: LSASS Credential Dumping (T1003.001) - *Coming Soon*]









> *_Coming soon_*

## 🟩 False Positives & Benign Behaviour

Detailed documentation is stored in:

1.detections/1.threats/lsass-credential-access/docs/

This includes:
* Legitimate processes accessing LSASS
* Antivirus / EDR behaviour
* Windows Error Reporting
* Debugging tools
* Recommended tuning
* Benign vs malicious behavioural indicators

## 🟩 Triage Workflow

* **Confirm LSASS Access**
  * Sysmon Event ID 10
  * Elevated permissions
  * Suspicious parent process
* **Check for Memory Dumping**
  * Sysmon Event ID 11
  * Creation of `.dmp` files
  * Calls to `MiniDumpWriteDump`
* **Correlate Access + Dumping**
  * Same process or related processes
  * Renamed binaries
  * Unexpected tools accessing LSASS
* **Validate Benign Scenarios**
  * EDR / AV
  * Debugging tools
  * WER (Windows Error Reporting)
* **Escalate if Dumping Confirmed**
  * Immediate containment
  * Credential reset
  * Host isolation


## 🟩 Summary

This folder contains only the threat‑specific documentation for LSASS Access and LSASS Credential Dumping.

Detection logic, rules, and hands‑on evidence are stored in their respective global locations:
* Detection Logic → `2.detection-logic/`
* Rules → `3.rules/`
* Evidence → *_coming soon_*
