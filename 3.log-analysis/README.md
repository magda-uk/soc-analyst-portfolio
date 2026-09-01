# 🎯 Log Analysis & Threat Triage

Welcome to the **Log Analysis** section of my SOC Analyst portfolio. 

This directory showcases my hands-on ability to investigate endpoint logs, differentiate between malicious activity and legitimate system noise, and apply a structured triage process. The focus here is not just on finding bad actors, but on understanding normal OS behaviors to reduce alert fatigue.

##  📌 Current Status

The investigations are categorised by the primary log source:

*   **[`/sysmon`](./sysmon/)** 🔥 **NEW : Check it out, more analysis has been added!**
    *   Endpoint visibility using Sysmon. Contains analyses of process creation (ID 1), process injection (ID 8), registry modifications (ID 13), and DNS queries (ID 22).
*   **[`/powershell`](./powershell/)** 🚧 *(Work in Progress)*
    *   Analysis of native PowerShell logs, specifically focusing on Script Block Logging (Event ID 4104) to review suspicious script executions.
*   **[`/windows-events`](./windows-events/)** 🚧 *(Work in Progress)*
    *   Core Windows Security Event Log investigations, focusing on authentication patterns and logon failures.

## 🔏 Triage Methodology

For the artifacts analysed in this directory, I follow a simple but effective workflow:

1.  **Log Extraction:** Gathering the raw event logs and presenting the key details clearly.
2.  **Understanding Context:** Looking at the source, target, users, and file paths involved to understand *what* happened and *why*.
3.  **Threat Triage:** Determining if the activity is just normal system noise (a false positive) or a genuine threat that needs investigation.
4.  **MITRE ATT&CK Mapping:** Linking the behavior to the MITRE framework to understand potential attacker tactics and techniques.
5.  **Recommendations & Tuning (Ongoing Learning):** Whenever possible, I try to suggest ways to tune out false positives (like writing exclusion rules). This is an area I am actively learning and practicing, so you will see it applied in some of my more recent analyses.

## ✨ Featured Investigations

If you are reviewing this portfolio, I highly recommend starting with these key case studies:

*   **[Sysmon Event ID 13: Registry Modification Analysis](./sysmon/id13-registry-modification/multi-event-analysis.md)** 🔥 **(Top Pick)**
    *   *Focus:* System Modification & Persistence. Triaging registry changes to identify potential malware persistence mechanisms or configuration tampering

*   **[Sysmon Event ID 8: DWM to CSRSS Thread Creation](./sysmon/id8-multi-event/sysmon-8-dwm-csrss.md)** 
    *   *Focus:* False Positive Validation. Documenting the normal behavior of Windows GUI subsystem thread creation to tune out process injection alerts.
*   **[Sysmon Event ID 22: DNS Queries & CDN Traffic](./sysmon/id22-dns-queries/sysmon-22-webview2-appassets.md)** 
    *   *Focus:* Network log triage. Differentiating between legitimate WebView2 background traffic and potential suspicious connections.

---
🔄 *Continuously updated as I analyse new logs and learn new detection techniques.* 