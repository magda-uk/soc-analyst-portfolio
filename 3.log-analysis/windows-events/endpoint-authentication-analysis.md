# Security Event Analysis: Endpoint Authentication & Session Telemetry (Event ID 4625 & 4624)

## 🟪 Summary
This analysis investigates Windows Security Event Logs associated with authentication attempts and session states on the endpoint `AZUL_FIFTY`. 

By examining **Event ID 4625 (Failed Logon)** and subsequent **Event ID 4624 (Successful Logon)**, this document outlines how security monitoring detects credential testing and maps the operational logon types (Interactive, Network, Service, Unlock, and Cached) to understand system activity and access vectors.

## 🟪 Case Study 1: Analysing Authentication Failures (Event ID 4625)
 
![Event 4625 - Failed Logon](/3.log-analysis/windows-events/images/4625-4.png)
![Event 4625 - Failed Logon](/3.log-analysis/windows-events/images/4625-1.png) 
![Event 4625 - Failed Logon](/3.log-analysis/windows-events/images/4625-3.png)
![Event 4625 - Failed Logon](/3.log-analysis/windows-events/images/4625-2.png) 


*(Note: Highlight fields: Logon Type, Account For Which Failed, Sub Status `0xC000006A` / `0xC0000064`, and Source Network Address)*

During baseline security monitoring and local testing on the endpoint `AZUL_FIFTY`, clusters of **Event ID 4625 (Audit Failure)** were observed. 

A detailed review of the event properties highlighted critical forensic artifacts:
*   **Logon Types Observed:** Captured under **Logon Type 2 (Interactive)** and **Logon Type 3 (Network)**, representing local authentication attempts and network/SMB probing respectively. *(Note: Environment constraints on Windows Home editions inherently restrict Remote Desktop Server roles, omitting Logon Type 10, which provides realistic context on OS-level boundary hardening).*
*   **Target Account Name:** Validated against local and Microsoft-linked user profiles (e.g., trying inputs like `magxxxxx@outlook.com` or local user profiles).
*   **Failure Reason / Sub Status:** Ranging from `0xC0000064` (User name does not exist) on local interactive vectors to `0xC000006A` (Bad password / user name correct) on network/NTLM vectors, highlighting how Windows handles status reporting across different subsystem calls.

## 🟪 Case Study 2: Correlating Legitimate Session States (Event ID 4624)

![Event 4624 - Successful Logon](/3.log-analysis/windows-events/images/4624-1.png)  


In parallel with monitoring failure conditions, successful **Event ID 4624 (Audit Success)** records were analyzed to map baseline user behavior and system state transitions on the endpoint. Focusing on system-level telemetry, the environment exhibited operational integrity through events such as:

*   **Logon Type 5 (Service):** Captured when background Windows services (such as `services.exe` utilizing `SYSTEM` credentials under an **Elevated Token: Yes**) initialized or executed. 
*   **Operational Session Mapping:** Correlating system background execution with standard workstation states (such as active service processing) allows blue teams to distinguish between background administrative integrity and external anomalies.
*   **Verdict & Correlation:** Correlating these events allows blue teams to verify that core OS components and administrative controls operate within expected parameters while managing authentication requests.

## 🟪 Security Recommendations & Hardening

Securing endpoints against unauthorized credential access and maintaining robust visibility involves several core hardening practices:

1.  **Enforce Account Lockout Policies:** Configure thresholds to temporarily lock endpoints after a specified number of consecutive failed authentication attempts (Event ID 4625), mitigating automated password guessing.
2.  **Audit Policy Tuning:** Ensure advanced audit configurations actively monitor both success and failure states for account logon and logon/logoff categories to maintain high fidelity in SIEM/Log analysis.
3.  **Network Boundary Restrictions:** Restrict unnecessary inbound SMB (Port 445) and remote management ports at the host firewall level to reduce the local attack surface.
4. **MITRE ATT&CK Mapping:** Align detection engineering and incident response playbooks with the MITRE ATT&CK framework by mapping these authentication anomalies directly to **T1110 (Brute Force)** and the potential risk of **T1078 (Valid Accounts)**.

## 🪪 Author

**Magda Dominguez**  
*SOC Analyst (L1-ready) Bristol, UK*  
Focused on Blue Team operations, detection engineering and log analysis.