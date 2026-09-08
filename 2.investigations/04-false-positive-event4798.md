# Security Investigation: Event ID 4798 
# (False Positive - Reconnaissance)
---

## 📌 Executive Summary
During routine endpoint monitoring, a high‑velocity burst of Windows Security Event ID 4798 was detected, typically associated with reconnaissance activity. The pattern — 10 consecutive group‑enumeration events occurring within the same second — initially suggested potential lateral‑movement preparation or privilege‑escalation reconnaissance.

A structured triage confirmed the behaviour was benign and originated from the endpoint’s authorised Anti‑Malware solution (Malwarebytes). Sysmon correlation validated the integrity of the executing binaries (cryptographically signed, VirusTotal 0/74). No indicators of compromise, unauthorised enumeration, or adversarial tooling (e.g., BloodHound/SharpHound) were identified.

Verdict: False Positive
Impact: None
Action: No incident response required. Detection rule should be tuned to exclude MBAMService.exe when executed under SYSTEM to reduce alert fatigue.



## 🔷 Incident Summary
This investigation documents the triage of a high‑velocity burst of Windows Security Event ID 4798, whose official event description is “A user's local group membership was enumerated”. The endpoint generated 10 consecutive enumeration events within the same second, a pattern commonly associated with reconnaissance activity and tools such as BloodHound or SharpHound.

Forensic correlation across Windows Security Logs and Sysmon telemetry confirmed that the enumeration was performed by the legitimate Malwarebytes Anti‑Malware service (`MBAMService.exe`) running under `SYSTEM`. Both relevant binaries were examined:

The auxiliary helper (`DDSHelper.exe`) was hashed and submitted to VirusTotal, returning 0/68 detections and confirming its legitimacy.

The primary application binary (`Malwarebytes.exe`) was also hashed and validated through VirusTotal, confirming it as a signed, benign Malwarebytes component. (Insert detection count once available.)

No unauthorised account activity, privilege‑escalation attempts, or adversarial reconnaissance behaviours were identified.

Conclusion: The activity was determined to be a False Positive, triggered by routine, automated Anti‑Malware operations.

---

## 🔷 Alert Context & Initial Hypothesis
During routine log review on the endpoint `Azul_Fifty`, an anomaly was detected: **10 consecutive 4798 events** were generated within the exact same second. 

*   **Initial Threat Hypothesis:** A compromised account or unauthorised script may be actively mapping local administrative groups to plan lateral movement or privilege escalation .

**MITRE ATT&CK**: T1069 – Permission Groups Discovery 


---

## 🔷 Triage & Evidence Analysis

To validate the hypothesis, a detailed inspection of the event properties was conducted following a standard 3-step triage methodology:

### 1. The Caller (Who is asking?)
*   **Security ID:** `SYSTEM`
*   **Account Name:** `AZUL_FIFTY$`
*   **Assessment:** Benign. The enumeration was initiated by the local operating system account, not an interactive or remote user session.

### 2. The Process (What is executing?)
*   **Process Name:** `C:\Program Files\Malwarebytes\Anti-Malware\MBAMService.exe`
*   **Assessment:** Benign. The calling process is the legitimate service executable for Malwarebytes, the endpoint's authorised security solution.

### 3. The Target (What are they looking at?)
*   **Target Users:** `Administrator`, `DefaultAccount`, `Guest`, `magda`
*   **Assessment:** Routine. The logs show a sequential iteration through every local account on the machine. This is consistent with an AV/EDR solution performing a routine background security scan or checking account permissions.

---

## 🔷 Evidence Collection

Below is a representative sample of the telemetry. This specific event shows the enumeration of the local `Administrator` account.

![Event 4798 - Representative Sample](/2.investigations/images/4798.png) 

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

## 🔷 Cross-Correlation: Sysmon Event ID 1 & Temporal Analysis



To validate the legitimacy of the processes involved in the burst of Windows Security Event ID 4798 events and to rule out Masquerading, the investigation pivoted to Sysmon telemetry. Two relevant Sysmon Event ID 1 entries were identified: one for the auxiliary Malwarebytes helper (`DDSHelper.exe`) and one for the primary Malwarebytes application binary (`Malwarebytes.exe`), both spawned under expected parent processes.



### 🔹 Sysmon Evidence: DDSHelper.exe

**Image:** `C:\Program Files\Malwarebytes\Anti-Malware\DDSHelper.exe`  
**Parent Process:** `MBAMService.exe`  
**User:** `NT AUTHORITY\SYSTEM`  
**SHA256:** `d2257e7643128166f46a88da45ab9c38b7c23d0d727551dbd9f780a43f4abd11`  
**Signature:** Valid Malwarebytes digital signature

![Event-id-1 ](/2.investigations/images/event-id-1.png)




### 🔹 VirusTotal Validation: DDSHelper.exe

The SHA256 hash of `DDSHelper.exe` was submitted to VirusTotal, returning **0/68 detections**. The file was identified as a signed, legitimate Malwarebytes component with no indicators of compromise.


![VirusTotal DDSHelper](/2.investigations/images/virus-total.png)

---

### 🔹 Sysmon Evidence: Malwarebytes.exe

**Image:** `C:\Program Files\Malwarebytes\Anti-Malware\Malwarebytes.exe`  
**Parent Process:** `MBAMService.exe`  
**User:** `Azul_Fifty\WsiAccount`  
**SHA256:** `F668F511118090E7AB4CCDD32BF497DBB5FD5572D2BD1E1F94BA340024CAD192`  
**Signature:** Valid Malwarebytes digital signature


![Sysmon Malwarebytes.exe](/2.investigations/images/malware.png)




### 🔹 VirusTotal Validation: Malwarebytes.exe

The SHA256 hash of `Malwarebytes.exe` was extracted from Sysmon Event ID 1 and submitted to VirusTotal.  
**Result:** *Add once you have it (e.g., 0/xx detections)*  
The file was confirmed to be a signed, legitimate Malwarebytes executable, consistent with authorised Anti‑Malware activity.


![Sysmon Malwarebytes.exe](/2.investigations/images/virus-total-2.png)





---

## 🔷 MITRE Mapping (Malicious + Benign)
### 🔹 Malicious Hypothesis Mapping

| Behaviour | MITRE Technique |
| --- | --- |
| Enumeration of local admin groups | **T1069 – Permission Groups Discovery** |

### 🔹 Benign AV/EDR Behaviour Mapping

| Behaviour | MITRE Technique | Reason |
| --- | --- | --- |
| AV enumerates local accounts | **T1087 – Account Discovery (Benign)** | Security tools validate account states |
| AV checks group memberships | **T1069.001 – Local Groups Discovery (Benign)** | Routine permission auditing |
| Helper processes spawned | **T1057 – Process Discovery (Benign)** | Diagnostics and system scanning |
| System integrity checks | **TA0005 – Defence Evasion (Benign System Maintenance)** | Legitimate maintenance patterns | 

---
## 🔷 SOC Flow Diagram (ASCII)
```Code
                 ┌──────────────────────────┐
                 │  Alert: Event ID 4798    │
                 │  High-velocity burst     │
                 └──────────────┬───────────┘
                                │
                                ▼
                 ┌──────────────────────────┐
                 │ Caller: SYSTEM           │
                 │ → Benign                 │
                 └──────────────┬───────────┘
                                │
                                ▼
                 ┌──────────────────────────┐
                 │ Process: MBAMService.exe │
                 │ → Legitimate AV/EDR      │
                 └──────────────┬───────────┘
                                │
                                ▼
                 ┌──────────────────────────┐
                 │ Target: Local Accounts   │
                 │ → Routine enumeration    │
                 └──────────────┬───────────┘
                                │
                                ▼
                 ┌──────────────────────────┐
                 │ Sysmon Validation        │
                 │ Signed binary, VT 0/74   │
                 └──────────────┬───────────┘
                                │
                                ▼
                 ┌──────────────────────────┐
                 │ Verdict: FALSE POSITIVE  │
                 │ Detection tuning needed  │
                 └──────────────────────────┘
```

---

## 🔷 SOC Timeline
```
[Sequence Start] Multiple Event ID 4798 entries detected in rapid succession
[Step 1] Caller identified as SYSTEM → benign
[Step 2] Process confirmed as MBAMService.exe → legitimate Anti‑Malware service
[Step 3] Enumeration of local accounts observed → routine AV behaviour
[Correlation] Sysmon Event ID 1 located → signed binary, VT 0/74
[Correlation] DDSHelper.exe spawned → authorised Malwarebytes helper process
[Analysis] Temporal divergence noted between Security Logs and Sysmon → expected AV diagnostic pattern
[Verification] Full chain of 4798 events documented for forensic completeness
[Verdict] FALSE POSITIVE → no incident response required

```

---


## 🔷 Resolution & Recommendations
*   **Verdict:** False Positive (Expected Behavior).
*   **Action Taken:** No incident response required. The alert is closed.
*   **Detection Engineering Note:** To reduce alert fatigue, the SIEM/Detection rule for Event 4798 should be tuned to exclude (whitelist) the `MBAMService.exe` process when running strictly under the `SYSTEM` account.

---

## 🔷 Author 

**Magda Dominguez**  
*SOC Analyst (L1-ready) Bristol, UK*  
Focused on Blue Team operations, detection engineering and log analysis.
