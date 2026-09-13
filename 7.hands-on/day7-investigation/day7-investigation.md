
---
# Final Incident Response Report

## 🔺 Executive Summary
Between 11 September and 13 September 2026, the Security Operations Centre (SOC) detected and contained a coordinated cyber intrusion targeting the corporate environment. 

The threat actor successfully compromised user credentials to gain initial access, subsequently utilising Living-off-the-Land (LotL) techniques via PowerShell to bypass static defenses. 

The attack was definitively identified and halted when the adversary interacted with a proactively deployed Cyber Deception asset (URL Honeytoken). No legitimate sensitive data was exfiltrated.

## 🔺 Incident Timeline
*   **11 September 2026 - Initial Access:** 

    Anomalous authentication patterns (Impossible Travel and anomalous geo-velocity) were detected via Entra ID `SigninLogs`, indicating credential compromise for the hybrid identity `Azul_Fifty\magda`.
*   **12 September 2026 (23:17 UTC) - Execution & Evasion:** 

    Sysmon (Event ID 1) and PowerShell Script Block Logging (Event ID 4104) captured the execution of a Base64-encoded payload launched by process `{79317113-dd75-6aa5-e7c3-000000005500}`. The adversary attempted to download secondary tools while evading command-line logging.
*   **13 September 2026 (01:59 UTC) - Discovery & Containment:** 

    A high-fidelity alert was triggered when the threat actor accessed a decoy URL contained within `intranet_admin_portal.txt`. The adversary's source IP was immediately identified and isolated.

## 🔺 Technical Analysis & IoCs
The investigation yielded several critical Indicators of Compromise (IoCs) across the MITRE ATT&CK framework phases:

*   **Compromised Account:** `Azul_Fifty\magda` (T1078 - Valid Accounts)

*   **Malicious Process:** `powershell.exe -EncodedCommand VwByAGkAdABl...` (T1059.001 - PowerShell)

*   **Decoded Payload Intent:** `Write-Host 'SOC-Lab-Day3...'; ping 127.0.0.1 -n 2` (T1027 - Obfuscated Files or Information)

*   **Adversary Infrastructure:** Source IP `[REDACTED FOR PRIVACY]` (Captured via Canarytoken telemetry)

## 🔺 Containment & Recommendations
To prevent recurrence, the Incident Response team recommends the following immediate actions:
1.  **Credential Reset:** Force an immediate password reset and revoke all active session tokens for the compromised Entra ID account (`magda`).

2.  **Network Isolation:** Block the adversary's IP address `[REDACTED]` at the perimeter firewall to prevent further inbound connection attempts.

3.  **Hardening:** Enforce strict Conditional Access policies requiring MFA for all administrative portals and maintain Script Block Logging (Event ID 4104) across all endpoints.

## 🔺 Author
**Magda Dominguez**

SOC Analyst (L1-ready) Bristol, UK

Focused on Blue Team operations, detection engineering and log analysis.