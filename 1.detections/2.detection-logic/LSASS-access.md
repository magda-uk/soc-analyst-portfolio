# 🛡️ Detection Logic: LSASS Memory Access (Pre‑Dumping Stage)

## 🎯 Objective
Detect suspicious attempts to access LSASS (Local Security Authority Subsystem Service) memory. This behaviour is commonly observed during early‑stage credential access activity and is a precursor to full LSASS credential dumping (T1003.001).

This detection focuses on Sysmon Event ID 10 (ProcessAccess), which records when a process opens a handle to another process — a critical event when the target is `lsass.exe`.

## 🧠 Threat Background
LSASS stores sensitive authentication material including:
* NTLM hashes
* Kerberos tickets
* DPAPI secrets
* Service account credentials

Attackers frequently attempt to read LSASS memory before performing a full dump. Tools such as Mimikatz, Cobalt Strike, and custom malware often begin with a simple handle request (`PROCESS_VM_READ`) to confirm access.

> **Note:** This stage is highly suspicious, but does not yet confirm credential dumping.

## 🗺️ MITRE ATT&CK Mapping
* **Tactic:** Credential Access (TA0006)
* **Technique:** OS Credential Dumping: LSASS Memory (T1003.001) *(LSASS Access is part of the same MITRE technique as LSASS Dumping)*

## 📌 Detection Notes & Conceptual Logic

### 🔍 High‑Risk Indicators
* **TargetImage = `lsass.exe`:** Any non‑system process accessing LSASS is immediately suspicious.
* **GrantedAccess flags indicating memory read/write:**
  * `0x0010` → `PROCESS_VM_READ`
  * `0x0020` → `PROCESS_VM_WRITE`
  * `0x0008` → `PROCESS_VM_OPERATION`
  * `0x1000` → `PROCESS_QUERY_LIMITED_INFORMATION`
  * `0x1F0FFF` → Full access (extremely dangerous)
* **SourceImage anomalies:**
  * Unsigned binaries
  * Tools executed from user directories (Desktop, Downloads, AppData)
  * Scripting engines (`powershell.exe`, `cscript.exe`, `wscript.exe`)
  * LOLBins abused for access (`rundll32.exe`, `regsvr32.exe`)

### 🟩 Benign Access Examples
These should be excluded or tuned:
* `WerFault.exe` (Windows Error Reporting)
* EDR/AV agents
* Debuggers (WinDbg, Visual Studio)
* System processes (`svchost.exe`, `taskmgr.exe`)

## 🧪 Validation Steps
To validate this detection safely:
1. Trigger legitimate LSASS access using Windows Error Reporting.
2. Compare access rights with malicious tools (Mimikatz, MiniDump).
3. Observe differences in:
   * GrantedAccess values
   * Parent process lineage
   * Binary signatures
4. Ensure the rule does not fire on EDR or system diagnostic tools.

## 🔎 Investigation Workflow

### 1. Identify the source process
* Check binary signature and reputation.
* Review parent process lineage.
* Inspect command‑line arguments.

### 2. Analyse access rights
* `0x0010` (read) → suspicious
* `0x1F0FFF` (full access) → critical
* Compare with known benign baselines.

### 3. Check for follow‑up activity
* Event ID 1 → suspicious process creation
* Event ID 7 → DLL loads (e.g., `comsvcs.dll`)
* Event ID 11 → dump file creation
* Event ID 8 → remote thread creation
* Authentication anomalies (Pass‑the‑Hash / Pass‑the‑Ticket)

### 4. Assess risk
* Is this reconnaissance or active credential theft?
* Is the process unsigned or executed from a user directory?
* Is the host showing signs of lateral movement?

## 🚨 Response Actions (High Severity)
* Isolate the host if access rights indicate malicious intent.
* Review active tokens and sessions for abuse.
* Rotate credentials for accounts present on the host.
* Investigate lateral movement originating from the endpoint.
* Enable LSASS protection (Credential Guard, RunAsPPL).
* Hunt for related artefacts (dump files, suspicious DLL loads).

## 📁 Evidence to Collect
* Sysmon Event ID 10 logs
* Binary hash and signature
* Parent process metadata
* Any subsequent dump files
* Authentication logs
* Network activity following the access
* Memory forensics if needed