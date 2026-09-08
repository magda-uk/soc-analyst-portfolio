# Security Investigation: Event ID 4798 
# (False Positive - Reconnaissance)
---

## 🔹 Incident Summary
This investigation details the triage of a high-velocity burst of **Windows Security Event ID 4798** (A user's local group membership was enumerated). While this pattern is frequently associated with malicious reconnaissance phases (such as BloodHound/SharpHound execution), our analysis confirmed this specific instance as a **False Positive** triggered by legitimate, automated Anti-Malware activity.

---

## 🔹 Alert Context & Initial Hypothesis
During routine log review on the endpoint `Azul_Fifty`, an anomaly was detected: **10 consecutive 4798 events** were generated within the exact same second. 

*   **Initial Threat Hypothesis:** A compromised account or unauthorized script is actively mapping local administrative groups to plan lateral movement or privilege escalation (MITRE ATT&CK: T1069 - Permission Groups Discovery).

---

## 🔹 Triage & Evidence Analysis

To validate the hypothesis, a detailed inspection of the event properties was conducted following a standard 3-step triage methodology:

### 1. The Caller (Who is asking?)
*   **Security ID:** `SYSTEM`
*   **Account Name:** `AZUL_FIFTY$`
*   **Assessment:** Benign. The enumeration was initiated by the local operating system account, not an interactive or remote user session.

### 2. The Process (What is executing?)
*   **Process Name:** `C:\Program Files\Malwarebytes\Anti-Malware\MBAMService.exe`
*   **Assessment:** Benign. The calling process is the legitimate service executable for Malwarebytes, the endpoint's authorized security solution.

### 3. The Target (What are they looking at?)
*   **Target Users:** `Administrator`, `DefaultAccount`, `Guest`, `magda`
*   **Assessment:** Routine. The logs show a sequential iteration through every local account on the machine. This is consistent with an AV/EDR solution performing a routine background security scan or checking account permissions.

---

## 🔹 Evidence Collection

Below is a representative sample of the telemetry. This specific event shows the enumeration of the local `Administrator` account.

![Event 4798 - Representative Sample](/2.investigations/images/4798.png) *(Note: Replace with your main screenshot)*

**Complete Event Burst (Chain of Custody)**  
While all events shared the exact same origin (`MBAMService.exe`), the complete sequence is documented below for forensic integrity, showing the sequential iteration through all local accounts.

<details>
<summary>📂 Click here to expand all 10 Event Logs (Raw Evidence)</summary>


![Event 1](/2.investigations/images/4798.png)
![Event 2](/2.investigations/images/4798-2.png)
![Event 3](/2.investigations/images/4798-3.png)
![Event 4](/2.investigations/images/4798-4.png)
![Event 5](/2.investigations/images/4798-5.png)
![Event 6](/2.investigations/images/4798-6.png)
![Event 7](/2.investigations/images/4798-7.png)
![Event 8](/2.investigations/images/4798-8.png)
![Event 9](/2.investigations/images/4798-9.png)
![Event 10](/2.investigations/images/4798-10.png)

</details>

---

## 🔹 Cross-Correlation: Sysmon Event ID 1 (Process Creation)

To definitively confirm the benign nature of the calling process and rule out **Masquerading** (a technique where malware renames itself to a legitimate Windows executable), the investigation pivoted to Sysmon telemetry. 

By correlating the timestamp and the caller Process Name (`MBAMService.exe`), we located its corresponding **Sysmon Event ID 1** (Process Create):

*   **Image Path:** `C:\Program Files\Malwarebytes\Anti-Malware\MBAMService.exe`
*   **Parent Process:** `services.exe` *(Expected behavior for a legitimate system service)*
*   **File Hash:** The SHA256 hash was extracted from the Sysmon log and queried against Threat Intelligence platforms (e.g., VirusTotal), returning **0/74 malicious hits**.

**Conclusion of Correlation:** The secondary evidence from Sysmon confirms that the binary executing the group enumeration is the genuine, cryptographically signed Malwarebytes executable, cementing the False Positive verdict.

## 🔹 Cross-Correlation: Sysmon Event ID 1 & Temporal Analysis

To confirm the legitimacy of the calling process, the investigation pivoted to Sysmon telemetry to locate the execution artifacts of Malwarebytes. 

*   **Sysmon Event ID 1 Artifact:** Captured `DDSHelper.exe` spawned by `MBAMService.exe` under `NT AUTHORITY\SYSTEM` with SHA256 hash `D2257E7643128166F46A88DA45AB9C38B7C23D0D727551DBD9F780A43F4ABD11`.
*   **Temporal Discrepancy Note:** The process creation and helper execution occurred independently from the exact moment of the 4798 group enumeration burst. This is a standard operational pattern: security services initialize or execute scheduled helper tasks (such as diagnostics) during maintenance windows, while permission checks or security audits occur dynamically later. 
*   **Verdict:** The presence of the cryptographically verified helper process (`DDSHelper.exe`) under the exact same parent service path confirms the environment is running legitimate, authorized security tooling rather than a masquerading threat.

![Event-id-1 ](/2.investigations/images/event-id-1.png)

---


## 🔹 Resolution & Recommendations
*   **Verdict:** False Positive (Expected Behavior).
*   **Action Taken:** No incident response required. The alert is closed.
*   **Detection Engineering Note:** To reduce alert fatigue, the SIEM/Detection rule for Event 4798 should be tuned to exclude (whitelist) the `MBAMService.exe` process when running strictly under the `SYSTEM` account.

---

## 🔹 Author 🔹

**Magda Dominguez**  
*SOC Analyst (L1-ready) Bristol, UK*  
Focused on Blue Team operations, detection engineering and log analysis.
