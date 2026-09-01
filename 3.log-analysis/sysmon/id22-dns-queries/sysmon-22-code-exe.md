# Case Study: Sysmon Event ID 22 — DNS Query Analysis & Threat Triage

## Telemetry Summary
* **Event Type:** Sysmon Event ID 22 (DNSEvent)
* **Timestamp (UTC):** `2026-08-29 01:04:28.431`
* **Process:** `C:\Users\magda\AppData\Local\Programs\Microsoft VS Code\Code.exe`
* **Process ID / GUID:** `65732` | `{79317113-12e3-6a92-0fdd-020000005000}`
* **Query Name:** `westus-0.in.applicationinsights.azure.com`
* **Resolved Addresses:** `20.189.172.76` (CNAME: `gig-ai-prod-westus-0.trafficmanager.net`), IPv6: `2603:1030:a07:e::101`
* **User Context:** `Azul_Fifty\magda` (Standard user privileges)

---

## Log Evidence & Artifact Breakdown

![Sysmon Event 22 Analysis](/1.detections/0.hands-on-evidence/benign-process-explained/screenshots/EVENT22-CODE-EXE.png)

> **Key Forensic Highlights:**
> * 🟪 **Process Identifiers (Purple):** `ProcessGuid` & `ProcessId` used to chain telemetry back to parent execution (Event ID 1) and network connections (Event ID 3).
> * 🟨 **Target Domain (Yellow):** Destination endpoint (`westus-0.in.applicationinsights.azure.com`) associated with Microsoft telemetry ingestion.
> * 🟩 **DNS Resolution (Green):** CNAME chain and public IP infrastructure (`20.189.172.76`) belonging to Microsoft Corporation (AS8075).
> * 🟧 **Image Path (Orange):** Execution path located within `AppData\Local`—identified as standard user-space installation for Visual Studio Code.
> * 🌸 **User Context (Pink):** Standard user privilege context (`Azul_Fifty\magda`).

---

## Technical Investigation

### 1. Execution Path & Binary Verification
* **Path Context:** The executable runs from `AppData\Local\Programs\...`. In SOC investigations, user-writable directories (`AppData`, `Temp`, `Public`) are routinely prioritised as high-risk triage zones because non-elevated threat actors leverage them to drop malicious payloads without requiring administrative access.
* **Legitimacy Check:** The binary name `Code.exe` matches the official Microsoft Visual Studio Code User Installer layout, which installs directly into the user’s local profile rather than `C:\Program Files`.

### 2. Network & Destination Analysis
* **Service Identity:** The queried domain `westus-0.in.applicationinsights.azure.com` belongs to Azure Application Insights, Microsoft’s telemetry and application performance monitoring service.
* **Traffic Purpose:** VS Code routinely dispatches anonymised diagnostic telemetry, extension performance metrics, and crash reporting back to Microsoft Azure endpoints via outbound HTTPS (port 443).
* **Infrastructure Mapping:** The DNS response resolves through a typical Azure Traffic Manager CNAME chain (`ai.monitor.azure.com` → `trafficmanager.net`) terminating at IP `20.189.172.76`, owned by Microsoft Corporation (AS8075).

### 3. Threat Detection: Abuse of Trusted Services (Living off Trusted Services - LoTS)
* **The LoTS Threat Vector (MITRE ATT&CK T1102 / T1567):**
  * Threat actors frequently exploit legitimate cloud services (such as Azure Application Insights, Discord webhooks, or Telegram APIs) to bypass standard perimeter security controls.
  * Because outbound traffic destined for `*.applicationinsights.azure.com` uses valid Microsoft TLS certificates over port 443, it blends into normal business egress and routinely evades domain reputation filters.
  * An adversary can create a rogue Azure telemetry instance and embed the instrumentation key within a payload to conduct covert data exfiltration or Command & Control (C2) heartbeat beaconing.
* **High-Severity Alert Scenarios:**
  * **Script Interpreters (`powershell.exe`, `wscript.exe`):** A script calling Azure telemetry endpoints indicates potential automated staging and exfiltration of staged discovery data (e.g. `whoami`, `net user`).
  * **LOLBins (`rundll32.exe`, `mshta.exe`):** Execution proxies communicating with telemetry endpoints suggest memory injection or proxy execution of untrusted code.
  * **Unsigned / Masquerading Binaries (`update_service.exe` in `%AppData%`):** Custom payloads utilising Azure Application Insights as a resilient C2 channel.
* **SOC Triage Distinction:**
  * In this specific event, the initiating process is verified developer tooling (`Code.exe`) communicating with its proprietary telemetry sink. The risk is assessed as benign, as the process-to-destination relationship is standard baseline behaviour.

---

## Triage Conclusion
* **Classification:** Benign Positive (Legitimate Developer Telemetry)
* **Risk Rating:** Informational (Low)
* **Action:** No escalation required. Added to local baseline observations.