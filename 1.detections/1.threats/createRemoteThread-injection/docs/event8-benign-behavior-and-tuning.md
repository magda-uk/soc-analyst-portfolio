### 1. Windows Error Reporting (`WerFault.exe` / `wermgr.exe`)
* **Behavior:** Injects threads to query process state and generate crash diagnostics.
* **Tuning Attributes:**
  * `SourceImage` = `C:\Windows\System32\WerFault.exe` or `wermgr.exe`
  * `StartFunction` = `RtlpQueryProcessDebugInformationRemote`
  * `StartModule` = `C:\Windows\System32\ntdll.dll`
  * `SourceUser` == `TargetUser`

### 2. Antivirus & EDR Solutions
* **Behavior:** Endpoint protection agents inject monitoring hooks or trigger inline memory scans.
* **Tuning Attributes:**
  * `SourceImage` resides in protected vendor paths (e.g., `C:\Program Files\Windows Defender\`, `C:\Program Files\<EDR_Vendor>\`).
  * Signatures verified against Microsoft / Vendor certificates.

### 3. Developer Debuggers (Visual Studio, WinDbg)
* **Behavior:** Interactive debugging sessions injecting remote break-in routines.
* **Tuning Attributes:**
  * `SourceImage` matches verified tools (e.g., `vsjitdebugger.exe`, `devenv.exe`, `windbg.exe`).
  * `StartFunction` = `DbgUiRemoteBreakin`

### 4. Windows Telemetry & App Runtime
* **Behavior:** Diagnostic engines collecting runtime state from UWP and WinAppRuntime containers.
* **Tuning Attributes:**
  * `TargetImage` located within `C:\Program Files\WindowsApps\...` or related runtime frameworks.

### 5. Sysinternals & Administrative Diagnostics
* **Behavior:** Deep process state exploration and thread inspection utilities.
* **Tuning Attributes:**
  * `SourceImage` = `procexp.exe`, `procmon.exe` (digitally signed by Microsoft).

---

## Section Summary

* **Detection Core:** Target process criticality, `StartFunction` verification, and user integrity alignment serve as the primary filters for hostile activity.
* **Tuning Rule:** Isolate and allowlist native debugging signatures (`WerFault.exe` + `RtlpQueryProcessDebugInformationRemote`) without broadly suppressing the underlying Event ID 8 telemetry.
---

### **Authored by**
**Magda Dominguez**  
Security Operations • Detection Engineering • Blue Team

---