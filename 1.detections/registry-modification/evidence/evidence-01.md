# Evidence : Sysmon Event ID 13 (Registry Value Set)
## Combined Multi‑Event Analysis: Shell Extensions, Service Modification & AppCompatFlags

**Summary**

Four Sysmon Event ID 13 events were observed on the analyst workstation. Although all four originate from legitimate software (NordVPN, McAfee, Windows Photos), they demonstrate three distinct categories of registry modification:

* Shell extensions (NordVPN)
* Service configuration changes (McAfee)
* AppCompatFlags compatibility metadata (`svchost.exe`)

These artefacts are extremely valuable for SOC analysis because they closely resemble attacker techniques such as persistence, service hijacking, execution via shell extensions, and registry‑based evasion. This combined evidence shows how benign activity can mimic malicious behaviour — a critical skill for SOC analysts.

---

### Event 1 NordVPN Shell Command Extension (Directory Context Menu)

**Log Artefact**

| Field | Value |
| :--- | :--- |
| **Event ID** | `13` |
| **Event Type** | `SetValue` |
| **Timestamp** | `2026-08-27 23:05:56.132` |
| **Process** | `C:\Program Files\NordVPN\NordVPN.exe` |
| **Registry Key** | `HKU\...\Directory\shell\NordVPN-file-share\command\(Default)` |
| **New Value** | `"C:\Program Files\NordVPN\NordVPN.exe" -m --send "Incorrect function."` |
| **User** | `Azul_Fifty\magda` |

**SOC Interpretation**

This modification adds a right‑click command to the Windows Explorer directory context menu. Malware frequently abuses identical registry paths to:

* Execute payloads via context menus
* Establish persistence
* Trigger malicious scripts on user interaction

Although legitimate, the pattern is identical to malicious shell extension techniques.

![event1](screenshots/event1.png)

---

### Event 2 — NordVPN Meshnet Shell Extension (File Context Menu)

**Log Artefact**

| Field | Value |
| :--- | :--- |
| **Event ID** | `13` |
| **Event Type** | `SetValue` |
| **Timestamp** | `2026-08-28 03:50:53.226` |
| **Process** | `C:\Program Files\NordVPN\NordVPN.exe` |
| **Registry Key** | `HKU\...\*\shell\NordVPN-file-share\(Default)` |
| **New Value** | `Send with NordVPN Meshnet` |
| **User** | `Azul_Fifty\magda` |

**SOC Interpretation**

This entry adds a file‑level context‑menu option. The `*\shell\...` path is commonly abused by malware to:

* Execute payloads when users open or right‑click files
* Hide malicious commands behind legitimate UI elements
* Persist through Explorer interactions

Again, legitimate — but SOC‑relevant.

![EVENT2](screenshots/EVENT2.png)
---

### Event 3 — McAfee Service ImagePath Modification (SYSTEM‑Level Service Change)

**Log Artefact**

| Field | Value |
| :--- | :--- |
| **Event ID** | `13` |
| **Event Type** | `SetValue` |
| **Timestamp** | `2026-08-28 00:06:34.296` |
| **Process** | `C:\Windows\system32\services.exe` |
| **Registry Key** | `HKLM\System\CurrentControlSet\Services\McAfee Scheduled Task - (mc-sustainability)\ImagePath` |
| **New Value** | `"C:\Program Files\McAfee\wps\1.40.161.1\sustainability\mc-sustainability.exe"` |
| **User** | `NT AUTHORITY\SYSTEM` |
| **RuleName** | `T1031, T1050` |

**SOC Interpretation**

This is high‑value evidence. Modifying `ImagePath` under `HKLM\System\CurrentControlSet\Services\...` is a recognised attacker technique:

* **T1031:** Modify Existing Service
* **T1050:** New Service

Attackers use this to:

* Replace legitimate service executables
* Gain persistence
* Escalate privileges
* Execute malware as SYSTEM

Although McAfee is legitimate, the behaviour is identical to malicious service hijacking.

![EVENT3](screenshots/EVENT3.png)
---

### Event 4 : AppCompatFlags Modification (svchost.exe - SYSTEM)

**Log Artefact**

| Field | Value |
| :--- | :--- |
| **Event ID** | `13` |
| **Event Type** | `SetValue` |
| **Timestamp** | `2026-08-28 03:32:28.095` |
| **Process** | `C:\Windows\system32\svchost.exe` |
| **Registry Key** | `HKU\...\Software\Microsoft\Windows NT\CurrentVersion\AppCompatFlags\Compatibility Assistant\Store\C:\Program Files\WindowsApps\Microsoft.Windows.Photos_2026.11060.2004.0_x64__8wekyb3d8bbwe\Photos.exe` |
| **New Value** | `Binary Data` |
| **User** | `NT AUTHORITY\SYSTEM` |
| **RuleName** | `InvDB` |

**SOC Interpretation**

This event shows Windows updating compatibility metadata for a UWP application. The `AppCompatFlags` keys are used to:

* Store compatibility decisions
* Apply execution shims
* Record application failures
* Enforce mitigations
* Track problematic binaries

Attackers sometimes manipulate these keys to:

* Bypass mitigations
* Disable warnings
* Force insecure execution modes
* Hide malicious behaviour

This adds a third category of registry modification to the evidence set.

![EVENT4](screenshots/EVENT4.png)

---

## MITRE ATT&CK Mapping (Across All Events)

* **T1112:** Modify Registry
* **T1547:** Persistence via Registry (Shell Extensions)
* **T1031:** Modify Existing Service
* **T1050:** New Service

---

## Combined SOC Interpretation

Together, these four events demonstrate:

* Registry modification across `HKU` and `HKLM`
* Activity from both user‑level and `SYSTEM`‑level processes
* Three distinct registry modification behaviours:
  * Shell extensions
  * Service configuration changes
  * AppCompatFlags compatibility metadata
* How benign software can produce artefacts identical to attacker techniques
* How Sysmon captures high‑value telemetry for SOC investigations
* How a SOC analyst correlates multiple registry events into a single coherent picture

This combined evidence supports detection logic for identifying suspicious registry activity across multiple threat categories.

---

