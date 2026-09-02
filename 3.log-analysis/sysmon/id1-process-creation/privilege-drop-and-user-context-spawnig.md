# Sysmon Event ID 1 
# Privilege Drop & User-Context Spawning

## 🔗 Overview
This case analyses a **Sysmon Event ID 1 (`ProcessCreate`)** event capturing a cross-session privilege transition. A background service running as `NT AUTHORITY\SYSTEM` instantiated an interactive child process under the standard logged-on user (`Azul_Fifty\magda`). 
While cross-session spawning from Session 0 can sometimes mimic token manipulation techniques, cryptographic verification and behavioral context confirm this is a **legitimate OEM privilege de-escalation** designed for user-facing interface tasks.

---

## 🔗 Evidence Extract

```c++
Process Create:
RuleName: -
UtcTime: 2026-08-29 00:29:47.540
ProcessGuid: {79317113-27fb-6a92-b9f7-020000005000}
ProcessId: 124140
Image: C:\Program Files (x86)\Lenovo\VantageService\5.1.2608.14\LenovoVantage-(ModernPreloadAddin).exe
OriginalFileName: Lenovo.Vantage.AddinHost.Amd64.exe
CommandLine: "C:\Program Files (x86)\Lenovo\VantageService\5.1.2608.14\LenovoVantage-(ModernPreloadAddin).exe" ...
User: Azul_Fifty\magda
TerminalSessionId: 4
IntegrityLevel: Medium
ParentImage: C:\Program Files (x86)\Lenovo\VantageService\5.1.2608.14\LenovoVantageService.exe
ParentUser: NT AUTHORITY\SYSTEM
```
![EVENT 1 PRIVILEGE DROP](/3.log-analysis/sysmon/id1-process-creation/screenshots/privilege-drop.png)

## 🔗Technical Analysis & Process Lineage
⚙️ **Privilege Context Transition (SYSTEM to User Space)**
* **Execution Lineage:** A root service (`LenovoVantageService.exe`) executing under `NT AUTHORITY\SYSTEM` instantiated a child process running within the active interactive desktop session (`Session 4`) as standard user `Azul_Fifty\magda`.
* **Security Mechanics (Privilege De-escalation):** Instead of executing user-facing tasks with full machine rights, the service drops privileges by duplicating the logged-on user's access token, adhering to the principle of least privilege.

⚙️ **Binary Reuse & Plugin Loading**
* **Hash Identity:** The SHA256 hash matches previous Vantage host instances, confirming that OEM modular architecture relies on a static host wrapper (`Lenovo.Vantage.AddinHost.Amd64.exe`) to execute disparate dynamic-link libraries (`ModernPreloadAddin.dll`).
* **Execution Path & Integrity:** Stored within administrative paths (`Program Files (x86)`), with plugin resources safely loaded from canonical vendor application directories.

⚙️ **Threat Hunting & Behavioural Anomaly Check
 ([MITRE ATT&CK T1134](https://attack.mitre.org/techniques/T1134/))**
* **Cross-Session Anomaly:** Process creation jumping from Session 0 into an interactive user session is a pattern monitored closely by blue teams, as adversaries occasionally abuse token manipulation for privilege movement.
* **Validation:** Here, cryptographic integrity and verified vendor signatures prove it is standard, secure OEM software architecture at work.

⚙️ **Benign Triage Criteria (False-Positive Validation)**
* [x] **Verified OEM Origin:** Executing from signed vendor directories with matching hashes.
* [x] **Legitimate De-escalation:** Transition from SYSTEM down to a standard user token for desktop interaction.
* [x] **Expected Target:** Interacting cleanly with the standard user session (`Session 4`).

---

## 🔗 MITRE ATT&CK Mapping

| Attribute | Details |
| :--- | :--- |
| **Tactic** | Defense Evasion ([TA0005](https://attack.mitre.org/tactics/TA0005/)), Privilege Escalation ([TA0004](https://attack.mitre.org/tactics/TA0004/)) |
| **Technique** | Access Token Manipulation: Token Impersonation/Theft ([T1134](https://attack.mitre.org/techniques/T1134/)) |
| **Classification** | **Benign Positive — OEM Privilege De-escalation Baseline** |

---

## 🔗 Triage Conclusion
* **Classification:** Benign Positive
* **Risk Rating:** Informational (Low)
* **Action:** No remediation required. Documented as an expected vendor baseline behaviour across interactive user sessions.
---

## 👩🏽‍💻 *Authored by: Magda Dominguez*  
*Security Operations • Detection Engineering • Blue Team*