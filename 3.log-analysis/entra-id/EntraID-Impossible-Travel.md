## 🟪 Case Study 4: Anomalous Cloud Sign-ins & Impossible Travel (Entra ID)

![Entra ID Sign-ins](/3.log-analysis/entra-id/images/entra-id.png)


This log extract from Microsoft Entra ID `SigninLogs` reveals a highly suspicious authentication pattern for the user **John Smith - Logicstics**, spanning a narrow window of approximately 20 minutes (03:04 to 03:25). A detailed review of the telemetry highlights multiple Indicators of Compromise (IoCs) consistent with credential compromise.

### 🔍 Key Findings

*   **Impossible Travel (Geo-Velocity Anomaly):** The logs show authentication attempts originating from three geographically distant locations within minutes of each other:
    *   **London, GB** (IPv6: `2a0a:ef40:...`) at 03:04 - 03:13
    *   **Middletown, Delaware, US** (IPv4: `172.94.105.5` & `172.94.26.142`) at 03:18 - 03:21
    *   **Brisbane, Queensland, AU** (IPv4: `172.94.51.136`) at 03:23 - 03:25
    
    This physical impossibility strongly suggests the use of VPNs/proxies to obfuscate the attacker's true location, or a coordinated attack by multiple threat actors sharing compromised credentials.

*   **Credential Guessing & Error Codes:** Several `Failure` events are observed from the London IP address with the error code **50126** (Invalid username or password), indicating initial attempts to guess the credentials. 
*   **MFA Interruptions:** The logs show multiple `Interrupted` statuses with codes such as **50140** (Keep me signed in prompt) and others (50055, 50072). These suggest the authentication flow was repeatedly halted, either by conditional access policies or the user failing/ignoring MFA prompts.
*   **Successful Breach:** Most critically, despite the initial failures and physical distance, we observe `Success` (Code 0) statuses originating from the US and Australian IP addresses. The presence of successful logons from anomalous locations indicates a critical security breach, potentially involving MFA fatigue (prompt bombing), a stolen session token (AiTM - Adversary-in-the-Middle attack), or a compromised secondary device.

## 🟪 Security Recommendations & Incident Response

When this pattern is detected in cloud telemetry, a SOC analyst must execute immediate containment actions:

1.  **Revoke Sessions:** Immediately revoke all active refresh tokens and sessions for the compromised account in Entra ID to sever the attacker's connection.
2.  **Reset Credentials:** Force a password reset and require the user to re-register their MFA methods, as the current device or token is likely compromised.
3.  **Investigate Post-Compromise Activity:** Since there are successful sign-ins to "My Profile" and "My Signins", analysts must query Entra ID `AuditLogs` to ensure the attacker did not register rogue MFA devices (persistence). Additionally, O365 logs should be checked for inbox rules or data exfiltration.
4.  **Enhance Conditional Access:** Ensure Conditional Access Policies are configured to block sign-ins from unexpected countries (Geo-blocking) and require strict, risk-based access controls for anomalous sign-ins.