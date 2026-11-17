#  SOC Glossary & MITRE ATT&CK Mapping

##  Purpose
This document serves as the theoretical foundation for my portfolio. It provides a comprehensive mapping of my investigations to the **MITRE ATT&CK / D3FEND frameworks**, alongside clear definitions of key SOC, detection engineering, and threat-related terms. 

It acts as a quick reference for understanding adversary behaviour, log artefacts, and the investigation terminology used throughout my playbooks.

---
## 🔻 MITRE ATT&CK & D3FEND Mapping 

Understanding adversary behaviour through the MITRE framework is core to my detection engineering methodology. Below is a comprehensive map of the key Tactics (The *Why*) and Techniques (The *How*) explored in my investigations, threat hunts, and emulation labs across this repository. 

*Click the 🔗 **Evidence** links to view the practical application, alert triage, or hunting playbooks for each technique.*

### 🔻 Reconnaissance (TA0043)
- **T1595 Active Scanning:** Probing enterprise networks and endpoints (e.g., using Nmap) to map open ports, vulnerabilities, and target infrastructure prior to an attack.
  - 🔗 **Evidence:** [Wazuh SIEM Enterprise Lab](../5.projects/wazuh-lab/README.md)

### 🔻 Resource Development (TA0042)
- **T1587.001 Develop Capabilities: Malware:** Authoring or modifying malicious payloads (such as custom Python ransomware scripts and obfuscated PowerShell) to execute in controlled lab environments.
  - 🔗 **Evidence:** [Ransomware Emulation & FIM](../5.projects/wazuh-lab/README.md)

### 🔻 Initial Access (TA0001)
- **T1566.001 Phishing: Spearphishing Attachment:** Delivery of malicious payloads via email attachments (e.g., weaponised Word documents spawning LolBins).
  - 🔗 **Evidence:** [Suspicious PowerShell via MS Word (True Positive)](../2.investigations/README.md)
- **T1110.001 Brute Force: Password Guessing:** Password guessing techniques targeting endpoints or cloud identities (Credential Stuffing/Spraying).
  - 🔗 **Evidence:** [RDP Brute Force & NLA Evasion](../5.projects/wazuh-lab/README.md) | [Entra ID Impossible Travel](../3.log-analysis/entra-id/EntraID-Impossible-Travel.md)

### 🔻 Execution (TA0002)
- **T1059.001 Command and Scripting Interpreter: PowerShell:** The abuse of legitimate command-line interfaces (PowerShell, CMD) to execute malicious payloads as a Living-off-the-Land (LotL) technique.
  - 🔗 **Evidence:** [Suspicious Encoded Command Triage](../2.investigations/02-threat-hunt-powershell.md) | [PowerShell Hunting Playbook](../4.hunting/powershell-encoded/README.md)

### 🔻 Persistence (TA0003)
- **T1136.001 Create Account: Local Account:** Creating a local user account on a compromised system to maintain access.
  - 🔗 **Evidence:** [Local Account Persistence (Wazuh)](../5.projects/wazuh-lab/README.md)
- **T1112 Modify Registry:** Modifying the Windows Registry to establish persistence (e.g., Run keys or services).
  - 🔗 **Evidence:** [Registry Modification (Sysmon Event 13)](../3.log-analysis/sysmon/id13-registry-modification/multi-event-analysis.md)
- **T1543.003 Create or Modify System Process: Windows Service:** Installing or modifying Windows services to maintain persistent access with elevated privileges.
  - 🔗 **Evidence:** [Windows Event Logs Analysis](../3.log-analysis/README.md)

### 🔻 Privilege Escalation (TA0004)
- **T1055.001 Process Injection: Dynamic-link Library Injection:** Injecting malicious code into legitimate, higher-privilege processes.
  - 🔗 **Evidence:** [Lenovo Vantage OEM Tuning (Mimicking Injection)](../2.investigations/03-tuning-lenovo-vantage.md)
- **T1078 Valid Accounts:** The abuse of compromised legitimate credentials to escalate privileges and blend in with normal administrative activity.
  - 🔗 **Evidence:** [Special Privileges Assigned (Event 4672)](../3.log-analysis/windows-events/4672-privilege-special-assigned.md) | [Auth Anomalies Playbook](../4.hunting/authentication-anomalies/README.md)

### 🔻 Defense Evasion (TA0005)
- **T1140 — Deobfuscate/Decode Files or Information:** Adversaries use obfuscation (like Base64 encoding) to hide malicious commands from static analysis.
  - 🔗 **Evidence:** [PowerShell Deobfuscation (Event 4104)](../2.investigations/02-threat-hunt-powershell.md)
- **T1070.006 Indicator Removal on Host: Timestomp:** Modifying file timestamps (Sysmon Event ID 2) to hide the creation of malicious files.
  - 🔗 **Evidence:** [Sysmon Priority Matrix Analysis](../3.log-analysis/README.md)
- **T1574.002 Hijack Execution Flow: DLL Side-Loading:** Exploiting how Windows loads DLLs (Sysmon Event ID 7) to execute malicious code.
  - 🔗 **Evidence:** [Sysmon Priority Matrix Analysis](../3.log-analysis/README.md)
- **T1553.005 Subvert Trust Controls: Mark-of-the-Web Bypass:** Abusing Alternate Data Streams (ADS) to bypass security warnings on downloaded files.
  - 🔗 **Evidence:** [ADS Log Analysis (Sysmon Event 15)](../3.log-analysis/README.md)
- **T1562.001 Impair Defenses: Disable or Modify Tools:** Interfering with security telemetry, such as kernel-level EDR prevention creating logging blindspots.
  - 🔗 **Evidence:** [EDR Interception vs OS Telemetry Gap](../2.investigations/01-sysmon-edr-blindspot.md)

### 🔻 Credential Access (TA0006)
- **T1003.001 OS Credential Dumping: LSASS Memory:** Extracting credentials from memory using tools like Procdump or Mimikatz.
  - 🔗 **Evidence:** [Procdump Exfiltration Triage](../2.investigations/06-true-positive-procdump-exfiltration.md) | [Mimikatz LSASS Access (Event 10)](../3.log-analysis/sysmon/id10-lsass-access/evtx-mimikatz-lsass-access.md) | [LSASS Hunting Playbook](../4.hunting/lsass-access/README.md)
- **T1556 Modify Authentication Process (Phishing & AiTM):** Manipulating authentication flows (MFA/Tokens) to harvest credentials or hijack sessions.
  - 🔗 **Evidence:** [Cloud Identity: MFA Anomalies](../3.log-analysis/entra-id/EntraID-Impossible-Travel.md)

### 🔻 Discovery (TA0007)
- **T1069 Permission Groups Discovery:** Attempting to find local system or domain-level groups (detected via rapid Windows Event ID 4798 bursts).
  - 🔗 **Evidence:** [High-Velocity Group Enumeration Tuning](../2.investigations/04-false-positive-event4798.md)

### 🔻 Lateral Movement (TA0008)
- **T1021.001 Remote Services: Remote Desktop Protocol:** Abusing RDP connections (e.g., bypassing Network Level Authentication) to move laterally across the network following initial compromise.
  - 🔗 **Evidence:** [RDP Brute Force & NLA Evasion](../5.projects/wazuh-lab/README.md)

### 🔻 Collection (TA0009)
- **T1005 Data from Local System:** Searching local system sources (such as simulated Logistics/PI datasets) to find valuable data prior to exfiltration or encryption.
  - 🔗 **Evidence:** [Ransomware Emulation: Data Collection](../5.projects/wazuh-lab/README.md)

### 🔻 Command and Control (TA0011)
- **T1105 Ingress Tool Transfer:** Transferring tools or files from an external system into a compromised environment.
  - 🔗 **Evidence:** [Suspicious Tool Transfer Analysis](../2.investigations/README.md)
- **T1568.002 Dynamic Resolution: Domain Generation Algorithms (DGA):** Using DGA beaconing or DNS tunneling (Sysmon Event ID 22) to establish resilient C2 channels.
  - 🔗 **Evidence:** [Sysmon Priority Matrix Analysis](../3.log-analysis/README.md)

### 🔻 Exfiltration (TA0010)
- **T1048 Exfiltration Over Alternative Protocol:** Stealing data by transferring it over alternative, often unencrypted, protocols (Living-off-the-Web).
  - 🔗 **Evidence:** [OS Credential Dumping & Data Exfiltration](../2.investigations/06-true-positive-procdump-exfiltration.md)

### 🔻 Impact (TA0040)
- **T1486  Data Encrypted for Impact:** Mass file extension changes and content modification (ransomware lifecycle).
  - 🔗 **Evidence:** [Ransomware Emulation & FIM](../5.projects/wazuh-lab/README.md)
- **T1485  Data Destruction:** Deletion of original system files following encryption to prevent recovery.
  - 🔗 **Evidence:** [Ransomware Emulation & FIM](../5.projects/wazuh-lab/README.md)
- **T1490  Inhibit System Recovery:** Disabling native recovery features (e.g., volume shadow copies).
  - 🔗 **Evidence:** [Ransomware Emulation & FIM](../5.projects/wazuh-lab/README.md)

### 🛡️ Active Defense (MITRE D3FEND)
- **D3-DO  Decoy Object (Honeytokens):** Deploying file-based honeytokens to generate high-fidelity, zero-false-positive alerts when adversaries attempt to access sensitive directories.
  - 🔗 **Evidence:** [Honeytokens & Cyber Deception Playbook](../4.hunting/active-defence-honeytokens/active-defence-honeytokens.md)

---

## 🔐 Identity & Authentication Concepts

- **Account Takeover (ATO):** Unauthorised access to a user account, typically through stolen credentials or MFA abuse.
- **Credential Stuffing:** Using large sets of leaked username/password pairs to attempt logins across multiple services.
- **Password Spraying:** Trying a small number of common passwords across many accounts to avoid lockouts.
- **Brute Force:** High-volume password guessing against a single account.
- **MFA Fatigue (Push Bombing):** Spamming MFA prompts to trick a user into approving one.
- **Impossible Travel:** Logins from geographically distant locations within unrealistic timeframes.
- **Token Replay:** Using a stolen authentication token to impersonate a legitimate user.
- **OAuth Abuse:** Malicious use of OAuth applications to maintain persistence or bypass MFA.

---

## 🖥 Endpoint & Process Concepts

- **LSASS (Local Security Authority Subsystem Service):** Windows process storing credential material; a primary target for credential dumping.
- **Process Access:** One process reading or interacting with another process’s memory space (e.g., Sysmon Event ID 10).
- **Encoded PowerShell:** PowerShell commands obfuscated using Base64 to hide malicious intent and bypass basic filters.
- **Suspicious Child Process:** A process spawned by an unexpected parent (e.g., `winword.exe` spawning `powershell.exe`).
- **Privilege Escalation:** Gaining higher privileges (e.g., SYSTEM, Domain Admin) than originally granted.

---

## 📊 Log & Telemetry Concepts

- **SigninLogs:** Core identity telemetry table in Microsoft Sentinel containing Entra ID authentication events.
- **Sysmon Event ID 10:** Process access event log; critical for detecting memory reading or injection into `lsass.exe`.
- **Sysmon Event ID 1:** Process creation event log; essential for tracking command-line arguments and parent-child process trees.
- **User Agent:** Browser or application identifier passed during web/API requests; anomalies may indicate automation or scripted tools.
- **IP Reputation:** Assessment of whether an IP is associated with known malicious actors, Tor exit nodes, VPNs, or proxy services.

---

## 🕵️ Investigation & Artefact Concepts

- **True Positive (TP):** A legitimate security alert indicating verified malicious or unauthorised activity.
- **False Positive (FP):** A benign or expected event incorrectly flagged as malicious by detection logic.
- **Enrichment:** Adding operational context to an alert (e.g., threat intelligence, geolocation, device compliance status, user role).
- **Baseline Behaviour:** Established normal activity patterns used to distinguish standard operations from anomalies.
- **Lateral Movement:** Techniques used by an attacker to extend access to additional systems or services across the network.
- **Post-Authentication Activity:** Actions performed immediately following a successful login; vital for identifying account takeover indicators.
- **Log Artefact:** Any discrete piece of telemetry supporting an investigation (timestamps, IP addresses, correlation IDs, process trees).
- **Memory Dump:** A snapshot of a process's virtual memory (e.g., `.dmp` files), often extracted to harvest credentials offline.
- **Suspicious Sign-In:** An authentication event deviating significantly from expected user patterns or risk policies.
- **Encoded Payload:** Obfuscated malicious code delivered via scripts or CLI arguments to conceal its actual objective.

---

## 🗝️ Key Registry Concepts & Threat Vectors

- **Registry modification across HKU and HKLM:** Registry changes can occur under `HKU` (`HKEY_USERS`) for user-level actions or `HKLM` (`HKEY_LOCAL_MACHINE`) for system-level actions.  
  *Analyst takeaway:* Understanding the difference helps identify whether a modification originated from a standard user process or a privileged/system process.
- **User-level vs. SYSTEM-level processes:** Some registry changes are initiated by applications running under a standard user account, while others are performed by processes running as `NT AUTHORITY\SYSTEM`.  
  *Impact:* `SYSTEM`-level modifications carry a higher security impact because they can alter core operating system behaviour and system-wide services.
- **Shell extensions:** Registry entries that add custom options or handlers to Windows Explorer context menus.  
  *Threat relevance:* Attackers abuse these keys to execute malicious payloads automatically whenever users right-click files or folders.
- **Service configuration changes:** Modifications directly to service registry keys (such as the `ImagePath` value) can change which executable a Windows service runs.  
  *Threat relevance:* Frequently leveraged for **Persistence** (MITRE ATT&CK T1543.003) or **Privilege Escalation** by hijacking legitimate service binaries.
- **AppCompatFlags:** Registry keys used by Windows to track compatibility settings, mitigation flags, and application execution history.  
  *Threat relevance:* Adversaries may tamper with these keys to disable OS mitigations, manipulate execution environments, or evade behavioural detection rules.

---

## 🎭 Infrastructure, Systems & Advanced Tactics

- **Masquerading:** Techniques used by adversaries to make their malicious files, processes, or artifacts appear legitimate (e.g., matching names of trusted OS utilities or changing file extensions) to evade manual review and basic detection rules.
- **Hostname:** The unique label assigned to a specific machine or node on a network, used to identify individual endpoints during log triage and endpoint investigations.
- **Domain:** An administrative grouping of computers, users, and resources under a single common database and security policy (such as an Active Directory domain or cloud tenant structure).
- **OEM (Original Equipment Manufacturer):** The manufacturer of hardware or pre-installed software system components. In threat analysis, identifying OEM binaries or registry paths helps distinguish legitimate vendor background tasks from injected code.
- **Living off the Land (LotL):** An adversary technique that abuses legitimate, pre-installed administrative tools and binaries native to the operating system (e.g., PowerShell, WMI, Certutil) to perform malicious actions, effectively bypassing traditional signature-based security controls.
- **Living off the Web (LotW):** The practice of leveraging trusted cloud services, public code repositories, or legitimate APIs (e.g., GitHub, Discord webhooks, cloud storage buckets) for command and control (C2) communication, payload hosting, or data exfiltration to blend in with normal business traffic.

## 🌐 Network & OT (Operational Technology) Concepts

- **Purdue Model:** A structural model for industrial control system (ICS) network segmentation. It separates enterprise IT networks from operational technology (OT) systems to contain breaches and protect critical infrastructure (such as supply chain refrigeration units).
- **OSI Model:** The conceptual framework used to understand, standardise, and troubleshoot network communications across seven distinct layers, from physical hardware up to application interfaces.
- **PCAP (Packet Capture):** A file containing captured network traffic data. Analysing PCAP files (e.g., via Wireshark) is essential for investigating network-based attacks, port scans, and unencrypted data exfiltration.
- **Network Segmentation:** The practice of splitting a network into smaller, isolated subnets to limit adversary lateral movement and protect sensitive domains.
- **NLA (Network Level Authentication):** A security feature in RDP that requires the connecting user to authenticate themselves before a session is established with the server, mitigating denial-of-service and brute-force risks.

---

## 🏗️ SIEM & Detection Engineering Architecture

- **Log Normalisation:** The process of parsing raw, unstructured log data from various disparate sources into a standard, readable format (schema) so the SIEM can query and correlate it efficiently.
- **Correlation Rule:** A detection logic query running in the SIEM that looks for specific sequences of events or thresholds across different log sources to identify a broader attack pattern.
- **Telemetry Ingestion:** The continuous collection and routing of log data from endpoints, cloud identities, and network sensors into a centralised SIEM for analysis.
- **Alert Fatigue:** The state of desensitisation that SOC analysts experience when exposed to a high volume of frequent, false-positive alerts, often leading to missed critical threats. 
- **Honeytoken (Decoy Object):** A digital asset (file, credential, database record) with no legitimate operational use, deployed strictly to detect unauthorised access. Any interaction with a honeytoken is an immediate, high-fidelity True Positive.

## 
[![Magda Dominguez LinkedIn](https://img.shields.io/badge/LinkedIn-Magda_Dominguez-9370DB?style=flat-square&logo=linkedin&logoColor=white)](https://www.linkedin.com/in/magda-d-infosec)