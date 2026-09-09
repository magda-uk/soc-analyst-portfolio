# Cloud Identity Analysis: Entra ID Interactive Sign-ins

## 🟪 Summary

This analysis explores interactive user sign-in logs within **Microsoft Entra ID (formerly Azure AD)**. Monitoring cloud identity providers is a core SOC responsibility. This document demonstrates the ability to analyze sign-in telemetry to distinguish between routine user errors, Multi-Factor Authentication (MFA) challenges, and successful access across different cloud applications.

## 🟪 Log Analysis & Event Triage

![Entra ID Interactive Sign-ins](./images/imagen%20-1.png) 

A review of the Entra ID sign-in logs over a 24-hour period for a specific user object revealed a normal, benign pattern of daily administrative activity. However, several non-success statuses were generated, requiring triage:

### Case Study 1: Invalid Credentials (Error 50126)
*   **Timestamp:** 07/09/2026, 00:33:07
*   **Status:** Failure
*   **Sign-in Error Code:** 50126 (Invalid username or password or Invalid on-premise username or password).
*   **Analysis:** A single failure event occurred for the Azure Portal using single-factor authentication. Crucially, less than a minute later (00:33:58), a "Success" event was logged for the same application requiring MFA.
*   **Verdict:** Benign user error (a typo in the password). The rapid subsequent success confirms this was not a credential stuffing or brute-force attack.

### Case Study 2: MFA Challenge (Error 50207)
*   **Timestamp:** 06/09/2026, 02:45:03
*   **Status:** Interrupted
*   **Sign-in Error Code:** 50207 (User account is required to setup MFA).
*   **Analysis:** The authentication process was paused because Conditional Access policies demanded MFA, but the user had only provided a single factor at that exact second. Two seconds later (02:45:05), the process completed successfully once the MFA token was supplied.
*   **Verdict:** Standard system behavior enforcing Conditional Access policies. 

## 🟪 Cloud Applications & Threat Hunting Context

The logs reveal access to administrative cloud tools from an IPv6 address located in London, GB:
*   **Azure Portal:** Standard management interface.
*   **Kusto Web Explorer:** Used for querying Azure Data Explorer and Sentinel logs via KQL (Kusto Query Language). 

**SOC Recommendations:**
1.  **Contextual Alerting:** Alerts for Error 50126 should be configured with thresholds (e.g., >10 failures within 5 minutes) to avoid alert fatigue from simple typos. 
2.  **Monitor Kusto Access:** Access to tools like Kusto Web Explorer should be strictly monitored, as compromised credentials could allow an attacker to query internal security telemetry and map the environment.

## 🪪 Author

**Magda Dominguez**
*SOC Analyst (L1-ready) | Bristol, UK*
Focused on Blue Team operations, detection engineering and log analysis.