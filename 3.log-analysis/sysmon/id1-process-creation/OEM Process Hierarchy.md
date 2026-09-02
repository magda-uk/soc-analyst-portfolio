# Case Study: Sysmon Event ID 1 : OEM Process Hierarchy & Addin Architecture

## Telemetry Summary
* **Event Type:** Sysmon Event ID 1 (Process Creation)
* **Timestamp (UTC):** `2026-08-29 00:25:22.857`
* **Process:** `C:\Program Files (x86)\Lenovo\VantageService\5.1.2608.14\LenovoVantage-(SmartPerformanceAddin).exe`
* **Original File Name:** `Lenovo.Vantage.AddinHost.Amd64.exe`
* **PID / GUID:** `117968` | `{79317113-26f2-6a92-2df6-020000005000}`
* **Parent Process:** `LenovoVantageService.exe` (PID: `3944`)
* **Integrity Level / User:** `System` | `NT AUTHORITY\SYSTEM` (Session 0)
* **SHA256:** `EF84AE37DDD52085DDB4FEAD43DB961D708E57CDF0BF8BF8F1FEE2DB495D07E7`

![EVENT 1 HIERARCHY](/3.log-analysis/sysmon/id1-process-creation/screenshots/hierarchy.png)
---

## Technical Investigation
### ⚙️ **Process Lineage & Tree Analysis**
* **Parent-Child Relationship:** The master background daemon (`LenovoVantageService.exe`) spawned a dedicated worker instance (`LenovoVantage-(SmartPerformanceAddin).exe`).
* **Isolation Pattern:** The OEM utilises dedicated host wrappers running under isolated processes to execute distinct modular tasks, preventing full service crashes if a single plugin encounters an unhandled exception.

### ⚙️ **Command-Line & Dynamic Assembly Loading**
* **Command Syntax:** The binary is instantiated with arguments pointing to its core dynamic assembly: `C:\ProgramData\Lenovo\Vantage\Addins\...\Lenovo.Vantage.SmartPerformanceAddin.dll`.
* **PE Header Integrity:** The `OriginalFileName` (`Lenovo.Vantage.AddinHost.Amd64.exe`) precisely aligns with the binary's internal properties and Lenovo's digital compilation footprint.

### ⚙️ **Threat Hunting & Masquerading Considerations (MITRE ATT&CK T1036)**
* **Masquerading Check:** Discrepancies between process naming conventions and internal file metadata frequently signal defence evasion techniques. Here, validation of the cryptographic hash (`EF84...`) and canonical installation path confirms authentic vendor origin.
* **Privilege Execution:** Executed within Session 0 under `NT AUTHORITY\SYSTEM` with `System` integrity level, fully consistent with standard Windows background service design.

### 🟢 **Benign Triage Criteria (False-Positive Validation)**
* [x] **Canonical Parentage:** Spawned directly by the primary verified service (`LenovoVantageService.exe`).
* [x] **Metadata Coherence:** `OriginalFileName` and `Product` values match official vendor attributes.
* [x] **Expected Context:** Runs in Session 0 as `SYSTEM`, matching legitimate background maintenance tasks.
* [x] **Controlled Module Loading:** Loads signed add-in libraries from designated application data directories.

**Result:** Meets all criteria for Benign Positive classification.

---
## 🗺️ MITRE ATT&CK Mapping

| Attribute | Details |
| :--- | :--- |
| **Tactic** | Execution ([TA0002](https://attack.mitre.org/tactics/TA0002/)), Defence Evasion ([TA0005](https://attack.mitre.org/tactics/TA0005/)) |
| **Technique** | Masquerading / Native API / System Services |
| **Classification** | **Benign Positive — OEM Modular Add-in Execution** |

---

## 🏁 Triage Conclusion
* **Classification:** Benign Positive
* **Risk Rating:** Informational (Low)
* **Action:** No remediation required. Documented as part of the normal OEM runtime execution baseline.
---

### 👩🏽‍💻 Authored by: Magda Dominguez

Security Operations • Detection Engineering • Blue Team