# Security Event Analysis: Local Brute Force Attack (Event ID 4625 & 4624)

## 🟪 Summary
This analysis investigates a sequence of Windows Security Event Logs indicative of a credential brute-force attack. By examining **Event ID 4625 (Failed Logon)** and subsequent **Event ID 4624 (Successful Logon)**, this document outlines how threat actors attempt to systematically guess passwords to gain unauthorized access to endpoints, typically via Remote Desktop Protocol (RDP) or SMB.

## 🟪 Case Study 1: The Brute Force Phase (Event ID 4625)

![Event 4625 - Failed Logon](/3.log-analysis/windows-events/images/3.log-analysis/windows-events/images/placeholder-4625.png) *

During routine monitoring, a high-velocity cluster of **Event ID 4625 (Audit Failure)** logs was detected on the endpoint `Azul_Fifty`. The telemetry revealed an aggressive attempt to authenticate to the built-in `Administrator` account within a 3-minute timeframe. 

A detailed review of the event properties highlighted the following critical artifacts:
*   **Logon Type: 10 (RemoteInteractive):** This confirms the attack was taking place over Remote Desktop Protocol (RDP), a common target for brute force. *(Note: If Logon Type was 3, it would indicate a Network/SMB attack).*
*   **Target Account Name:** `Administrator` (The attacker is targeting highly privileged default accounts).
*   **Source Network Address:** `192.168.10.45` (An unauthorized internal IP, suggesting an already compromised pivot machine on the network).
*   **Failure Reason / Sub Status:** `0xC000006A` (User name is correct, but the password is wrong). This specific sub-status confirms the attacker is actively guessing passwords against a valid account.

## 🟪 Case Study 2: The Successful Compromise (Event ID 4624)

![Event 4624 - Successful Logon](/3.log-analysis/windows-events/images/placeholder-4624.png) *(Note: Replace with your screenshot)*

Immediately following the barrage of failure events, a single **Event ID 4624 (Audit Success)** was generated. 

*   **Correlation:** The `Target Account` and `Source Network Address` matched exactly with the previous 4625 events.
*   **Verdict:** This sequence confirms that the threat actor successfully guessed the password and established an interactive remote session on `Azul_Fifty`. At this point, the brute force attack escalated into a full system compromise. 
*   **Context:** Following this 4624 event, we would expect to see an **Event ID 4672 (Special Privileges Assigned)**, as documented in previous analyses, confirming the attacker now holds administrative control.

## 🟪 Security Recommendations & Incident Response

Detecting a successful brute force attack requires immediate incident response procedures:

1.  **Containment:** Isolate the compromised endpoint (`Azul_Fifty`) and the source machine (`192.168.10.45`) from the corporate network immediately to prevent further lateral movement.
2.  **Credential Revocation:** Force a password reset for the `Administrator` account and any other accounts accessed from the attacker's IP.
3.  **Remediation (Hardening):**
    *   Implement and enforce **Account Lockout Policies** (e.g., lock the account for 30 minutes after 5 failed attempts) to mitigate future brute force efficiency.
    *   Disable the default `Administrator` account if not strictly required, or rename it.
    *   Restrict RDP access (Port 3389) at the firewall level, requiring VPN access or implementing MFA for remote sessions.

## 🪪 Author

**Magda Dominguez**  
*SOC Analyst (L1-ready) Bristol, UK*  
Focused on Blue Team operations, detection engineering and log analysis.