# 🛡️ Full Sysmon Investigation Compendium
## Complete SOC Analyst Portfolio 
###  Behavioural Analysis, DNS, OEM Noise & MITRE Mapping

This document consolidates **Sysmon** telemetry investigations, covering process creation events (**ProcessCreate**), name resolution queries (**DNS Query**), alternate data streams (**ADS / FileStreamCreated**), and the OEM noise baseline. Designed as an operational reference for **Blue Team and SOC Triage**.

---

## 🗺️ 1. Sysmon Event Map - SOC Priority Matrix

| Priority | Event ID | Event Name | Main Detection Use Case |
| :--- | :--- | :--- | :--- |
| **High** | `1` | **ProcessCreate** | Detection of anomalous CLI, LOLBins, script execution |
| **High** | `2` | **FileCreateTime** | Detection of *Timestomping* techniques (forensic evasion) |
| **High** | `3` | **NetworkConnect** | C2 traffic, data exfiltration, non-standard ports |
| **High** | `7` | **ImageLoaded** | Suspicious DLL loads, DLL Hijacking / Side-loading |
| **High** | `8` | **CreateRemoteThread** | Code injection into remote processes (Process Injection) |
| **High** | `10` | **ProcessAccess** | Credential dumping in memory (`lsass.exe`, token stealing) |
| **High** | `11` | **FileCreate** | *Drop* of executables, payload *staging* in `%TEMP%` / `%APPDATA%` |
| **High** | `13` | **RegistryEvent** | Persistence via RunKeys, services, extension hijacking |
| **High** | `22` | **DNSQuery** | C2 traceability, DGA beaconing, DNS tunneling |
| **Medium** | `15` | **FileStreamCreated** | Mark-of-the-Web (MOTW) control and Alternate Data Stream abuse |
| **Medium** | `17 / 18` | **PipeEvent** | Inter-process communication in frameworks like Cobalt Strike / Metasploit |
| **Medium** | `19 / 20 / 21` | **WMI / Tampering / FileDelete** | WMI persistence, defense disabling, evidence deletion |
| **Low** | `23 - 25` | **Advanced Tampering & Delete** | Advanced *Threat Hunting* and integrity analysis |

---

## 📄 2. Sysmon Event ID 15: Alternate Data Stream (ADS) Analysis

**Event Summary:** The `chrome.exe` process generated an attached alternate data stream named `:Zone.Identifier` when downloading a PDF file. This operation corresponds to the standard **Mark-of-the-Web (MOTW)** assignment imposed by modern browsers to restrict the execution of external files.

### 📋 Evidence Extract

| Field | Observed Value |
| :--- | :--- |
| **Image** | `C:\Program Files\Google\Chrome\Application\chrome.exe` |
| **TargetFilename** | `BRS Magdalena Dominguez Escudero_CV.pdf:Zone.Identifier` |
| **User Context** | `Azul_Fifty\magda` |
| **Stream Content** | `[ZoneTransfer] ZoneId=3` (Internet Zone) |

### 🟢 Benign Triage Criteria
* The stream identifier is strictly `Zone.Identifier` (native MOTW).
* No anomalous or arbitrary stream names are detected (e.g., `:evil.exe`, `:payload.bin`).
* No correlated events of immediate execution (`Event ID 1`) or memory injection (`Event ID 8` / `10`) exist.

---

## 🌐 3. Sysmon Event ID 22 : WPAD Resolution Attempt

**Event Summary:** The operating system executed an automatic DNS query looking for the `wpad` hostname for network proxy autoconfiguration. The resolution returned a non-existent domain error code (`NXDOMAIN`), ruling out an active proxy spoofing attack.

### 📋 Evidence Extract

| Field | Observed Value |
| :--- | :--- |
| **QueryName** | `wpad` |
| **QueryStatus** | `9003 (NXDOMAIN)` |
| **Image** | `<unknown process>` (Rapid termination / Ephemeral process) |
| **User Context** | `Azul_Fifty\magda` |

### 🟢 Benign Triage Criteria
* The `NXDOMAIN` status confirms the absence of unauthorized WPAD servers on the network segment.
* Absence of subsequent HTTP download events for `wpad.dat` / `proxy.pac` files.
* No evidence of network policy modifications in the registry or anomalous network connections (`Event ID 3`).

---

## 📡 4. Sysmon Event ID 22 : OEM CDN Resolution (Lenovo)

**Event Summary:** The `LenovoSecurityAddin.exe` module generated a query to resolve `filedownload.lenovo.com`. The resolution completed successfully through an **Akamai Edge** global CDN architecture.

### 📋 Evidence Extract

```text
QueryName:    filedownload.lenovo.com
QueryStatus:  0 (SUCCESS)
Image:        LenovoVantage-(LenovoSecurityAddin).exe
User:         Azul_Fifty\magda

QueryResults (CNAME Chain & IP):
  ├── filedownload.lenovo.com.akadns.net
  ├── filedownload.lenovo.com.edgekey.net
  ├── e7741.g.akamaiedge.net
  └── ::ffff:23.37.197.88 (IPv4-mapped IPv6)
  ```

### 🟢 Benign Triage Criteria
* The CNAME chain shows authoritative delegation towards Akamai's global infrastructure.

* The final mapped IP address corresponds to legitimate content delivery nodes.

* The source process resides in the official signed path of Lenovo Vantage.

## ⚙️ 5. Process Baseline : OEM Noise Profiling (Lenovo Vantage)
Lenovo Vantage modules run modularly and independently under the system service context. Understanding this baseline helps prevent false positive alerts in the SOC:

```
[System Context / Services]
  └── LenovoVantageService.exe
        ├── LenovoHardwareScanAddin.exe    (Physical component diagnostics)
        ├── SmartPanelAddin.exe            (Interface and touchpad management)
        ├── SmartPerformanceAddin.exe      (Power and performance profiles)
        └── LenovoSecurityAddin.exe        (OEM certificate and patch validation)
```
---
## 🔄 6. ProcessCreate : Google Updater Maintenance

**Event Summary:** Routine execution of the `updater.exe` component for the validation and downloading of patches for the Google Chrome ecosystem.

### 📋 Evidence Extract

| Field | Observed Value |
| :--- | :--- |
| **Image** | `C:\Program Files (x86)\Google\GoogleUpdater\updater.exe` |
| **Publisher** | Google LLC |
| **User Context** | `Azul_Fifty\magda` |
| **Parent Process** | `svchost.exe` (Windows Scheduled Tasks) |

### 🟢 Benign Triage Criteria
* Signed binary located in its official installation path.
* Usual command line parameters (`/c`, `/ping`, `/install`).
* Absence of direct calls to command interpreters (`cmd.exe`, `powershell.exe`) or memory injections.

---

## 🗺️ 7. MITRE ATT&CK Framework Mapping

| Sysmon Event ID | MITRE ID | Technique / Tactic | Associated Behaviour |
| :--- | :--- | :--- | :--- |
| **ID 1 (ProcessCreate)** | **T1059** / **T1204** | Command and Scripting Interpreter / User Execution | Execution of LOLBins scripts or interactive binaries |
| **ID 2 (Timestomp)** | **T1070.006** | Indicator Removal: Timestomp | Malicious alteration of file creation metadata |
| **ID 3 (NetworkConnect)** | **T1071** / **T1041** | Application Layer Protocol / Exfiltration Over C2 | Remote connections, beaconing, and data egress |
| **ID 8 (CreateRemoteThread)** | **T1055** | Process Injection | Defense evasion via memory thread injection |
| **ID 10 (ProcessAccess)** | **T1003.001** | OS Credential Dumping: LSASS Memory | Opening process handles for credential dumping |
| **ID 11 (FileCreate)** | **T1105** | Ingress Tool Transfer | Download and implantation of secondary executables |
| **ID 13 (RegistryEvent)** | **T1547.001** | Boot or Logon Autostart Execution: Registry Run Keys | Adversary persistence using Run/RunOnce keys |
| **ID 15 (FileStreamCreated)** | **T1564.004** | Hide Artifacts: Alternate Data Streams | Payload concealment or MOTW control bypass |
| **ID 22 (DNSQuery)** | **T1071.004** / **T1568** | DNS Protocol / Dynamic Resolution (DGA, Fast Flux) | Command and Control (C2) covert resolution channels |

---

## 💡8. Analyst Summary

* **Telemetry Triangulation:** Continuous correlation between process creation (`ID 1`), network traffic (`ID 3`), and name resolution (`ID 22`).
* **OEM Noise Suppression:** Precise differentiation between suspicious activity and vendor maintenance processes (Lenovo, Google).
* **DNS Structural Analysis:** Rigorous inspection of CNAME hops, DGA domains, and IPv6/IPv4 mappings before classifying an event.
* **Behaviour-Based Triage:** Validation of digital signatures, parent process lineage, and privilege context (*User vs. SYSTEM*).

---

♟️ **Authored by:** **Magda Dominguez**  
Security Operations • Detection Engineering • Blue Team