# 4. Hunting - SOC Analyst Investigation Playbooks

This directory contains a collection of professional threat-hunting playbooks, designed to demonstrate practical SOC Analyst (Blue Team) skills using Microsoft Defender, Microsoft Sentinel, Sysmon telemetry, and MITRE ATT&CK mapping.

Each hunting playbook provides:

* 🎯 **A clear investigation objective**
* 🧠 **A "Why This Matters" section** explaining the attack impact
* 🔍 **A primary KQL query**
* 🕵️ **A structured SOC investigation workflow**
* 🔴 **Indicators of compromise**
* 🛡️ **Recommended response actions**
* 📘 **Analyst notes**

These documents showcase not only technical capability, but also analytical reasoning, investigative maturity, and real-world SOC methodology.

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

---

## 🎯 Purpose of This Directory

This directory demonstrates your ability to:

* Conduct manual threat-hunting investigations
* Correlate identity, process, network, and file telemetry
* Apply MITRE ATT&CK in real investigations
* Document findings clearly and professionally
* Think like a SOC Analyst.

It shows that you can go beyond writing queries — you can investigate, interpret, and respond to real attack behaviours.

---

## 🧩 How to Use These Playbooks

These hunting documents can be used as:

* Investigation guides
* Study material
* Interview evidence
* Foundations for detection engineering
* Practical demonstrations of Blue Team capability

---

## 📘 Analyst Notes

> **Portfolio Context:** This directory is part of your SOC Analyst Portfolio, designed to highlight hands-on skills in:
> * KQL (Kusto Query Language)
> * Microsoft Sentinel
> * Microsoft Defender for Endpoint
> * Sysmon telemetry
> * Threat Hunting & Incident Triage
> * Incident Response workflows
> * MITRE ATT&CK framework mapping
>
> *More hunting playbooks can be added over time to expand the portfolio.*