
# 4. Hunting & Active Defence - SOC Analyst Playbooks

This directory contains a collection of professional threat-hunting playbooks and cyber deception (honeytoken) strategies, designed to demonstrate practical SOC Analyst (Blue Team) skills using Microsoft Defender, Microsoft Sentinel, Sysmon telemetry, and MITRE frameworks (ATT&CK / D3FEND).

Rather than following a rigid template, these documents adapt to the specific nature of the threat—whether proactively hunting for compromised cloud identities or deploying active defence decoys on an endpoint. 

Across this directory, you will find a combination of:

* 🎯 **Hunt Hypotheses & Clear Objectives:** Defining what we are looking for or trapping.
* 🧠 **Attack Vectors & Impact:** Understanding how the adversary operates.
* 🔍 **Detection Logic & Decoy Setup:** Using KQL to surface anomalies or configuring high-fidelity SIEM alerts.
* 🕵️ **Investigation Workflows:** Step-by-step event triage, proof of concepts, and log correlation.
* 🔴 **Red Flags & IoCs:** Key indicators of malicious behaviour or active compromise.
* 🛡️ **Containment Procedures:** Recommended SOC response actions to isolate the threat.

---
---

## 📂 Contents

### 1. PowerShell Encoded Command Hunting
* **MITRE ATT&CK:** `T1059.001 — Command and Scripting Interpreter: PowerShell`
* **Overview:** Detects the use of Base64-encoded PowerShell commands, a common technique for hiding malicious payloads, downloading remote scripts, executing C2 stagers, and evading basic logging.
* **This playbook includes:**
  * Payload decoding guidance
  * Timeline reconstruction
  * Sysmon and Defender correlation
  * Indicators of malicious execution
  * Containment and remediation steps

### 2. LSASS Access Hunting
* **MITRE ATT&CK:** `T1003 — OS Credential Dumping: LSASS Memory`
* **Overview:** Identifies attempts to access LSASS memory using tools such as ProcDump, Mimikatz, `rundll32` MiniDump, or custom loaders. Any non-system interaction with LSASS is considered a high-severity security event.
* **This playbook includes:**
  * Detection of dumping techniques
  * Parent process analysis
  * Identification of `.dmp` files
  * Network exfiltration checks
  * Immediate response actions

### 3. Authentication Anomalies Hunting
* **MITRE ATT&CK:** `T1078 — Valid Accounts`
* **Overview:** Detects suspicious authentication patterns such as brute force, password spraying, MFA failures, impossible travel, and post-compromise behaviour.
* **This playbook includes:**
  * Brute force detection
  * Impossible travel analysis
  * MFA failure investigation
  * Endpoint activity correlation
  * Indicators of account compromise

### 4. Active Defence: Honeytokens & Cyber Deception
* **MITRE D3FEND:** `D3-DO Decoy Object`
* **Overview:** Demonstrates the deployment of file-based honeytokens (decoy files) to generate high-fidelity, zero-false-positive alerts in Microsoft Sentinel when adversaries attempt to access sensitive directories or exfiltrate data.
* **This playbook includes:**
  * Honeytoken generation and strategic placement
  * Sentinel correlation and alert logic
  * Telemetry validation
  * Active Defence methodology

---

## 🎯 Purpose of This Directory: The Analytical Mindset

This directory bridges my professional background in high-volume logistics with Blue Team operations. 

In my daily work as a Perpetual Inventory and Systems Specialist within a fast-paced distribution centre, my core responsibility is investigating complex discrepancies. This involves correlating events across multiple enterprise systems (such as WMS and ERPs), validating multi-source data, and reconstructing operational timelines to identify the root cause of an anomaly.

I have directly translated this analytical methodology into my SOC workflow. The same methodical approach I use to triage system anomalies and resolve critical discrepancies is what I apply here to:

* Conduct proactive threat-hunting investigations.
* Correlate identity, process, network, and file telemetry to uncover hidden adversary behaviours.
* Implement active defence mechanisms (honeytokens) to generate high-fidelity alerts.
* Document findings with the clarity, precision, and operational focus required in a real-world environment.

---

## 🧩 How to Use These Playbooks

These documents can be used as:

* Investigation guides
* Study material
* Interview evidence
* Foundations for detection engineering
* Practical demonstrations of Blue Team capability

---

## 📘 Analyst Notes

> **Portfolio Context:** This directory is part of my SOC Analyst Portfolio, designed to highlight hands-on skills in:
> * KQL (Kusto Query Language)
> * Microsoft Sentinel
> * Microsoft Defender for Endpoint
> * Sysmon telemetry
> * Threat Hunting & Active Defence
> * Incident Response workflows
> * MITRE ATT&CK / D3FEND mapping
>
> *More hunting playbooks and deception techniques can be added over time to expand the portfolio.*