# Detection Logic: Suspicious Registry Modification (T1112)

##  🔸 Objective
Detect high‑risk modifications to the Windows Registry that may indicate persistence, service hijacking, or security control tampering. This detection focuses on abnormal writes to sensitive registry paths, especially by non‑trusted or non‑system processes.

##  🔸 Threat Background
Adversaries frequently modify the Windows Registry to:
* Establish persistence
* Hijack existing services
* Alter shell behaviour
* Weaken or bypass security controls

These changes often blend with legitimate activity and are rarely logged by default. Sysmon Event ID 13 (`RegistryValueSet`) provides visibility into registry value changes, including the process responsible, the key path, and the new data.

##  🔸 MITRE ATT&CK Mapping
* **Tactic:** Defence Evasion (TA0005) / Persistence (TA0003)
* **Technique:** Modify Registry (T1112)
* **Related:**
  * Boot or Logon Autostart Execution (T1547)
  * Modify Existing Service (T1031)
  * New Service (T1050)

##   🔸Detection Notes & Conceptual Logic

### 🔍 High‑Risk Registry Paths
Focus on modifications to:

* **Shell extensions (right‑click persistence):**
  * `HKCU\Software\Classes\*\shell\`
  * `HKCU\Software\Classes\Directory\shell\`
* **Service configuration and hijacking:**
  * `HKLM\System\CurrentControlSet\Services\<ServiceName>\ImagePath`
  * `HKLM\System\CurrentControlSet\Services\<ServiceName>\Parameters\`
* **AppCompat and execution shims:**
  * `HKCU\Software\Microsoft\Windows NT\CurrentVersion\AppCompatFlags\Layers`
  * `HKCU\Software\Microsoft\Windows NT\CurrentVersion\AppCompatFlags\Custom\`
* **Autoruns and logon persistence:**
  * `HKCU\Software\Microsoft\Windows\CurrentVersion\Run`
  * `HKLM\Software\Microsoft\Windows\CurrentVersion\Run`

### ⚠️ Suspicious Process Characteristics
Flag registry modifications when:
* The modifying process is unsigned or unknown.
* The binary resides in user‑writable locations (AppData, Temp, Downloads, Desktop).
* The parent process is a script engine (`powershell.exe`, `wscript.exe`, `cscript.exe`) or an Office application.
* The process is not a known installer, updater, or system component.

### ⚙️ Conceptual Logic (Sysmon‑Centric)
* **Event ID 13 (RegistryValueSet)**
* TargetObject matches high‑risk paths above
* Image not in allow‑listed system or EDR processes
* *Optional:* correlate with Event ID 1 (`ProcessCreate`) for suspicious parent/child chains

##  🔸 Validation Steps
To validate this detection safely:
1. Perform legitimate software installation and updates to observe normal registry changes.
2. Simulate persistence via test scripts modifying Run keys or shell extensions.
3. Compare process paths, signatures, and parent processes between benign and test cases.
4. Tune allow‑lists for trusted installers, updaters, and EDR agents.

##  🔸 Investigation Workflow

### 1. Review the modifying process
* Check signature, hash reputation, and file path.
* Inspect parent process and command‑line arguments.
* Determine whether the process behaviour matches its expected role.

### 2. Analyse the registry key and value
* Identify whether the key is used for persistence, service configuration, or execution shims.
* Determine if the value points to a suspicious binary or script.
* Check for redirection of legitimate services to attacker‑controlled executables.

### 3. Correlate with other activity
* Process creation events for the modified executable.
* Service start events following the change.
* Logon or autorun activity linked to the new registry value.
* Any related network or authentication anomalies.

### 4. Assess scope and impact
* Is the change user‑specific or system‑wide?
* Does it affect critical services or security tooling?
* Is this part of a broader persistence or lateral movement campaign?

##  🔸 Response Actions (High Severity)
* Revert malicious registry changes and restore legitimate values.
* Quarantine or remove the offending binary.
* Review affected services, autoruns, and shell behaviour.
* Hunt for similar modifications across other hosts.
* Strengthen application control (WDAC/AppLocker) and registry monitoring.

##  🔸 Evidence to Collect
* Sysmon Event ID 13 entries for the modification.
* Process metadata (hash, signature, path, parent).
* Before/after snapshots of the affected registry keys.
* Related process creation and service start events.
* Host‑level timeline of changes and subsequent activity.

## 🔸 Author 
**Magda Dominguez**  
Security Operations 🔹 Detection Engineering 🔹 Blue Team