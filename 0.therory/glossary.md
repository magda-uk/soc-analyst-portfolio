# Glossary ➡️ Detection & Threat Concepts

## Purpose
This glossary provides clear definitions of key SOC, detection engineering, and threat-related terms used throughout this portfolio.  
It serves as a quick reference for understanding attacker behaviour, log artefacts, and investigation terminology.

---

## 🔐 Identity & Authentication Concepts

* **Account Takeover (ATO):**  
  Unauthorised access to a user account, typically through stolen credentials or MFA abuse.
* **Credential Stuffing:**  
  Using large sets of leaked username/password pairs to attempt logins across multiple services.
* **Password Spraying:**  
  Trying a small number of common passwords across many accounts to avoid lockouts.
* **Brute Force:**  
  High-volume password guessing against a single account.
* **MFA Fatigue (Push Bombing):**  
  Spamming MFA prompts to trick a user into approving one.
* **Impossible Travel:**  
  Logins from geographically distant locations within unrealistic timeframes.
* **Token Replay:**  
  Using a stolen authentication token to impersonate a legitimate user.
* **OAuth Abuse:**  
  Malicious use of OAuth applications to maintain persistence or bypass MFA.

---

## 📍 MITRE ATT&CK Techniques (Common in This Portfolio)

* **T1078 — Valid Accounts:**  
  Use of legitimate credentials to access systems.
* **T1110 — Brute Force:**  
  Password guessing techniques including spraying and credential stuffing.
* **T1003 — OS Credential Dumping:**  
  Extracting credentials from memory, often via LSASS.
* **T1059 — Command and Scripting Interpreter:**  
  Execution of malicious commands or scripts (PowerShell, CMD, Bash).
* **T1055 — Process Injection:**  
  Injecting code into legitimate processes to evade detection.
* **T1078 - Valid Accounts:**  
  When adversaries successfully compromise legitimate credentials (or bypass MFA via tokens), they abuse these valid accounts to blend in with normal administrative or user activity, making detection significantly harder since the user identity itself is authorised.
* **T1556 — Modify Authentication Process, Phishing & Credential      Harvesting**: 
  Manipulating authentication flows, MFA, or identity systems.
  The initial vector often responsible for capturing the user's password or triggering MFA prompts in the first place. In advanced scenarios, this evolves into Adversary-in-the-Middle (AiTM) phishing to hijack active sessions rather than just static credentials.

---

## 🖥 Endpoint & Process Concepts

* **LSASS (Local Security Authority Subsystem Service):**  
  Windows process storing credential material; a primary target for credential dumping.
* **Process Access:**  
  One process reading or interacting with another process’s memory space (e.g., Sysmon Event ID 10).
* **Encoded PowerShell:**  
  PowerShell commands obfuscated using Base64 to hide malicious intent and bypass basic filters.
* **Suspicious Child Process:**  
  A process spawned by an unexpected parent (e.g., `winword.exe` spawning `powershell.exe`).
* **Privilege Escalation:**  
  Gaining higher privileges (e.g., SYSTEM, Domain Admin) than originally granted.

---

## 📊 Log & Telemetry Concepts

* **SigninLogs:**  
  Core identity telemetry table in Microsoft Sentinel containing Entra ID authentication events.
* **Sysmon Event ID 10:**  
  Process access event log; critical for detecting memory reading or injection into `lsass.exe`.
* **Sysmon Event ID 1:**  
  Process creation event log; essential for tracking command-line arguments and parent-child process trees.
* **User Agent:**  
  Browser or application identifier passed during web/API requests; anomalies may indicate automation or scripted tools.
* **IP Reputation:**  
  Assessment of whether an IP is associated with known malicious actors, Tor exit nodes, VPNs, or proxy services.

---

## 🕵️ Investigation Concepts

* **True Positive (TP):**  
  A legitimate security alert indicating verified malicious or unauthorised activity.
* **False Positive (FP):**  
  A benign or expected event incorrectly flagged as malicious by detection logic.
* **Enrichment:**  
  Adding operational context to an alert (e.g., threat intelligence, geolocation, device compliance status, user role).
* **Baseline Behaviour:**  
  Established normal activity patterns used to distinguish standard operations from anomalies.
* **Lateral Movement:**  
  Techniques used by an attacker to extend access to additional systems or services across the network.
* **Post-Authentication Activity:**  
  Actions performed immediately following a successful login; vital for identifying account takeover indicators.

---

## 🔗 Evidence & Artefact Concepts

* **Log Artefact:**  
  Any discrete piece of telemetry supporting an investigation (timestamps, IP addresses, correlation IDs, process trees).
* **Memory Dump:**  
  A snapshot of a process's virtual memory (e.g., `.dmp` files), often extracted to harvest credentials offline.
* **Suspicious Sign-In:**  
  An authentication event deviating significantly from expected user patterns or risk policies.
* **Encoded Payload:**  
  Obfuscated malicious code delivered via scripts or CLI arguments to conceal its actual objective.
  
  ---

## 🗝️ Key Registry Concepts & Threat Vectors

 ### Registry modification across HKU and HKLM
 ---

  Registry changes can occur under `HKU` (`HKEY_USERS`) for user-level actions or `HKLM` (`HKEY_LOCAL_MACHINE`) for system-level actions.  

  **Analyst takeaway:** Understanding the difference helps identify whether a modification originated from a standard user process or a privileged/system process.

### User-level vs. SYSTEM-level processes
--- 

  Some registry changes are initiated by applications running under a standard user account, while others are performed by processes running as `NT AUTHORITY\SYSTEM`.  
  
  **Impact:** `SYSTEM`-level modifications carry a higher security impact because they can alter core operating system behaviour and system-wide services.

### Shell extensions
---
  Registry entries that add custom options or handlers to Windows Explorer context menus.  
  **Threat relevance:** Attackers abuse these keys to execute malicious payloads automatically whenever users right-click files or folders.

### Service configuration changes
---
  Modifications directly to service registry keys (such as the `ImagePath` value) can change which executable a Windows service runs.  
  **Threat relevance:** Frequently leveraged for **Persistence** (MITRE ATT&CK T1543.003) or **Privilege Escalation** by hijacking legitimate service binaries.

### AppCompatFlags
---
  Registry keys used by Windows to track compatibility settings, mitigation flags, and application execution history.  
  **Threat relevance:** Adversaries may tamper with these keys to disable OS mitigations, manipulate execution environments, or evade behavioural detection rules.

---
## 🎭 Infrastructure, Systems & Masquerading Concepts

* **Masquerading:**  
  Techniques used by adversaries to make their malicious files, processes, or artifacts appear legitimate (e.g., matching names of trusted OS utilities or changing file extensions) to evade manual review and basic detection rules.
* **Hostname:**  
  The unique label assigned to a specific machine or node on a network, used to identify individual endpoints during log triage and endpoint investigations.
* **Domain:**  
  An administrative grouping of computers, users, and resources under a single common database and security policy (such as an Active Directory domain or cloud tenant structure).
* **OEM (Original Equipment Manufacturer):**  
  The manufacturer of hardware or pre-installed software system components. In threat analysis, identifying OEM binaries or registry paths helps distinguish legitimate vendor background tasks from injected code.

---

## 🧬 Advanced Adversary Tactics (LotL & LotW)

* **Living off the Land (LotL):**  
  An adversary technique that abuses legitimate, pre-installed administrative tools and binaries native to the operating system (e.g., PowerShell, WMI, Certutil) to perform malicious actions, effectively bypassing traditional signature-based security controls.
* **Living off the Web (LotW):**  
  The practice of leveraging trusted cloud services, public code repositories, or legitimate APIs (e.g., GitHub, Discord webhooks, cloud storage buckets) for command and control (C2) communication, payload hosting, or data exfiltration to blend in with normal business traffic.