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
* **T1556 — Modify Authentication Process:**  
  Manipulating authentication flows, MFA, or identity systems.

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