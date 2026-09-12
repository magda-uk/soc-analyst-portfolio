#  Day 6: ![Frameworks](https://img.shields.io/badge/Frameworks-MITRE_ATT%26CK-orange?style=flat-square) MITRE ATT&CK 
## Threat Mapping & Coverage Matrix

## 🔸 Overview
This document serves as a centralized **Threat Coverage Matrix**, mapping the malicious behaviors, anomalies, and administrative noise observed across the hands-on laboratory exercises to the standardized **MITRE ATT&CK®** framework.

By translating raw telemetry (Sysmon, Windows Security Logs, and Entra ID) into universal adversary tactics and techniques, this matrix demonstrates a core Blue Team capability: structured detection engineering and standardized incident reporting.

---

## 🔸 Observed Technique Coverage Matrix

| ATT&CK Tactic | Technique ID & Name | Log Source / Sensor | Event ID / Artifact | Lab Reference |
| :--- | :--- | :--- | :--- | :--- |
| **Initial Access** | [T1566](https://attack.mitre.org/techniques/T1566/) Phishing (Potential AiTM) | Microsoft Entra ID | `SigninLogs` (Anomalous IP/Geo) | [Day 4: Cloud Identity](/3.log-analysis/entra-id/EntraID-Impossible-Travel.md) |
| **Execution** | [T1059.001](https://attack.mitre.org/techniques/T1059/001/) PowerShell | Sysmon | `Event ID 1` (Process Creation) | [Day 1 & 2: Sysmon Basics](/7.hands-on/day1-sysmon-basics/README.md) |
| **Defense Evasion** | [T1078](https://attack.mitre.org/techniques/T1078/) Valid Accounts | Windows Security / Entra ID | `Event ID 4624` / `SigninLogs` | [Day 4: Authentication](/3.log-analysis/windows-events/endpoint-authentication-analysis.md) |
| **Credential Access** | [T1110](https://attack.mitre.org/techniques/T1110/) Brute Force | Windows Security / Entra ID | `Event ID 4625` / `50126` Error | [Day 4: Authentication](/3.log-analysis/windows-events/endpoint-authentication-analysis.md) |
| **Command and Control**| [T1071.001](https://attack.mitre.org/techniques/T1071/001/) Web Protocols | Sysmon / Wireshark | `Event ID 3` (Network) / PCAP | [Day 2: Event Correlation](/7.hands-on/day2-sysmon-suspicious/README.md) |
| **Command and Control**| [T1105](https://attack.mitre.org/techniques/T1105/) Ingress Tool Transfer | Sysmon | `Event ID 11` (File Creation) | [Day 2: Event Correlation](/7.hands-on/day2-sysmon-suspicious/README.md) |

---

## 🔸 Blue Team Application & Detection Engineering

This matrix is not static; it is a "living document" that scales as new logging capabilities are introduced to the environment. 

### Key Takeaways from Current Coverage:
🔸1. **Endpoint Visibility:** Sysmon provides robust visibility into **Execution (T1059)** and **Command and Control (T1071)** via Process Creation (EID 1) and Network Connections (EID 3).

🔸2. **Identity as the Perimeter:** The combination of Windows Security Event Logs (Local Authentication) and Microsoft Entra ID (Cloud Sign-ins) provides end-to-end visibility against **Credential Access (T1110)**.

🔸3. **Future Expansion:** As subsequent labs are completed (e.g., PowerShell ScriptBlock logging for obfuscation), new sub-techniques will be integrated into this matrix to refine detection logic further.

---

## 🔸 Author
**Magda Dominguez**  
*Security Operations 🔸 Detection Engineering 🔸 Blue Team*