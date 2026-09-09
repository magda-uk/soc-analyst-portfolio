# 🎯 Log Analysis & Threat Triage

Welcome to the **Log Analysis** section of my SOC Analyst portfolio.

This directory showcases my hands-on ability to investigate endpoint and cloud logs, differentiate between malicious activity and legitimate system noise, and apply a structured triage process. The focus here is not just on finding bad actors, but on understanding normal behaviours to reduce alert fatigue.

## 📌 Current Status

The investigations are categorised by the primary log source:

*   [**/entra-id**](/3.log-analysis/entra-id/EntraID-Impossible-Travel.md) 🔥 *NEW*
    *   Analysis of Cloud Identity telemetry, focusing on Entra ID SigninLogs and AuditLogs to detect impossible travel, MFA anomalies, and compromised credentials.
*   [**/sysmon**](/3.log-analysis/sysmon/) 🔥 *UPDATED*
    *   Endpoint visibility using Sysmon. Contains analyses of unauthorised memory access to LSASS (ID 10), process creation (ID 1), process injection (ID 8), registry modifications (ID 13), and DNS queries (ID 22).
*   [**/powershell**](/3.log-analysis/powershell/event4104-powershell-scriptblock-analysis.md) 
    *   Analysis of native PowerShell logs, specifically focusing on Script Block Logging (Event ID 4104) to review suspicious and obfuscated script executions.
*   [**/windows-events**](/3.log-analysis/windows-events/Event-ID-4672.md) 
    *   Core Windows Security Event Log investigations, focusing on authentication patterns and logon failures.

## 🔏 Triage Methodology

For the artifacts analysed in this directory, I follow a simple but effective workflow:

1.  **Log Extraction:** Gathering the raw event logs and presenting the key details clearly.
2.  **Understanding Context:** Looking at the source, target, users, and file paths involved to understand *what* happened and *why*.
3.  **Threat Triage:** Determining if the activity is normal system noise (a false positive) or a genuine threat that needs investigation.
4.  **MITRE ATT&CK Mapping:** Linking the behavior to the MITRE framework to understand potential attacker tactics and techniques.
5.  **Recommendations & Response:** Formulating immediate containment steps (e.g., revoking sessions) and suggesting ways to tune out false positives.

## ✨ Featured Investigations

If you are reviewing this portfolio, I highly recommend starting with these key case studies:

*   🆕 **[Cloud Identity: Impossible Travel & MFA Anomalies](./entra-id/EntraID-Impossible-Travel.md#-scenario-overview)**
    *   *Focus:* Triaging Entra ID logs for credential compromise, geo-velocity anomalies, and MFA bypass attempts.
*   🆕 **[Sysmon Event ID 10: LSASS Credential Dumping via Mimikatz](./sysmon/id10-lsass-access/evtx-mimikatz-lsass-access.md)**
    *   *Focus:* Analysing unauthorised memory access requests (`PROCESS_VM_READ`) to confirm credential theft.
*   **[PowerShell Event 4104: Script Block Analysis](./powershell/event4104-powershell-scriptblock-analysis.md)**
    *   *Focus:* Hunting for encoded commands and in-memory execution using native PowerShell logging.
*   **[Sysmon Event ID 13: Registry Modification Analysis](./sysmon/id13-registry-modification)** 
    *   *Focus:* System Modification & Persistence. Triaging registry changes to identify potential malware persistence mechanisms.
*   **[Sysmon Event ID 22: DNS Queries & CDN Traffic](./sysmon/id22-dns-queries)**
    *   *Focus:* Network log triage. Differentiating between legitimate WebView2 background traffic and potential suspicious connections.
---
*🔄 Continuously updated as I analyse new logs and learn new detection techniques.*

## 👩🏽‍💻 Authored by: Magda Dominguez
*Security Operations • Detection Engineering • Blue Team*