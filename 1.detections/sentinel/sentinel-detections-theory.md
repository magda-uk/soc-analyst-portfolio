# Microsoft Sentinel — Detection Engineering

## 🎯 Purpose of This Document
This document provides a clear, structured and beginner‑friendly introduction to detection engineering within **Microsoft Sentinel**, written specifically for SOC Analyst (L1) learning.

It explains:
- what a detection is  
- why detections matter in a SOC  
- how Sentinel implements detection logic  
- how KQL is used to identify suspicious behaviour  
- how identity‑based attacks appear in logs  
- how detections relate to MITRE ATT&CK  
- how SOC analysts validate, investigate and respond to alerts  

This theory file prepares you for the practical examples and evidence you will document in your portfolio.

---

# 🧠 What Is a Detection?

A **detection** is a rule that identifies suspicious or malicious behaviour in log data.

In a SOC environment, detections are the mechanism that:
- generate alerts  
- notify analysts of potential threats  
- highlight abnormal behaviour  
- trigger investigations  
- support escalation and response  

Without detections, a SOC would have **no visibility** into attacks.

---
# 🧠 Why Study Detections in a SOC L1 Portfolio?

A SOC L1 analyst must be able to:

- understand why an alert fired  
- read and interpret the detection logic  
- recognise suspicious patterns in logs  
- validate whether an alert is genuine or a false positive  
- map behaviour to MITRE ATT&CK  
- follow investigation and escalation workflows  

Documenting detections in your portfolio demonstrates:
- analytical thinking  
- understanding of attacker behaviour  
- familiarity with SIEM tools  
- readiness for real SOC work  

---

# 🧠 What Is Microsoft Sentinel?

**Microsoft Sentinel** is a cloud‑native SIEM used widely across enterprise environments.  
It provides:

- log collection from multiple sources  
- real‑time alerting  
- threat detection  
- investigation tools  
- hunting capabilities  
- automation (SOAR)  

Sentinel uses **Kusto Query Language (KQL)** to analyse logs and build detection rules.

---

# 🧠 What Is an Analytics Rule?

An **Analytics Rule** is a detection written in KQL.  
It defines the logic that determines whether an alert should fire.

A typical rule contains:

### ✔️ KQL Query  
The logic that identifies suspicious behaviour.

### ✔️ Entity Mappings  
Defines which fields represent:
- user  
- host  
- IP  
- process  

These help Sentinel enrich the alert.

### ✔️ MITRE ATT&CK Mapping  
Shows which attacker technique the behaviour corresponds to.

### ✔️ Severity  
Indicates how urgent the alert is (High, Medium, Low).

### ✔️ Alert Details  
Describes what the alert means and how analysts should respond.

---



# 🧠 Why Identity-Based Detections Matter in Sentinel

Before looking at specific examples, it is important to understand that **identity is one of the most targeted areas in modern attacks**.  
Most breaches begin with:

- stolen credentials  
- phishing  
- password spraying  
- MFA fatigue  
- session hijacking  
- OAuth abuse  

Because of this, Microsoft Sentinel provides rich telemetry for identity activity, and many SOC alerts originate from authentication anomalies.

---

# 🧠 What Are SigninLogs?

`SigninLogs` is the core Sentinel table for identity-related events.  

It contains information about:

- successful and failed sign-ins  
- MFA prompts and failures  
- IP addresses  
- geolocation  
- device and browser details  
- session tokens  
- conditional access results  

SOC analysts use this table to detect:
- brute force attempts  
- impossible travel  
- suspicious MFA behaviour  
- account takeover  
- abnormal authentication patterns  

This is why SigninLogs appears frequently in Sentinel detections.

---

# 🧠 MITRE ATT&CK Mapping for Identity Detections

Identity anomalies often map to:

### **T1078 — Valid Accounts**  
Attackers use legitimate credentials to access systems.

This technique is extremely common because once an attacker has valid credentials, they can:
- bypass perimeter controls  
- blend in with legitimate traffic  
- access cloud resources  
- escalate privileges  
- move laterally  

Identity detections help identify early signs of this technique.

---

# 🧠 What This Detection Identifies

The example detection identifies:

### ✔️ Users with unusually high sign-in attempts  
Indicating password spraying or credential stuffing.

### ✔️ IP addresses generating suspicious authentication patterns  
Suggesting enumeration or reconnaissance.

### ✔️ Potential brute-force behaviour  
High-volume attempts in a short timeframe.

### ✔️ Early signs of account compromise  
Sudden deviations from normal user behaviour.

### ✔️ Abnormal authentication baselines  
New IPs, new devices, unexpected geolocations.

This makes it a valuable baseline anomaly detection for SOC L1 analysts.

---

# 🧠 How to Validate This Detection

A SOC analyst should validate authentication anomaly alerts by reviewing:

### ✔️ MFA activity  
Repeated prompts, failures, or suspicious approvals.

### ✔️ IP reputation  
Foreign, anonymised, or previously unseen IPs.

### ✔️ Device information  
New devices, unusual OS versions, unknown browsers.

### ✔️ User behaviour  
Travel, network changes, or signs of phishing.

Validation helps distinguish genuine threats from false positives.

---

# 🧠 How to Investigate This Detection

### ✔️ Review sign-in timeline  
Look for sudden spikes or unusual patterns.

### ✔️ Check for impossible travel  
Compare geolocation data.

### ✔️ Review MFA logs  
Identify fatigue attacks or suspicious approvals.

### ✔️ Check for lateral movement  
SharePoint, Teams, Exchange access.

### ✔️ Check for risky sign-ins  
Unknown browsers, outdated OS, automation tools.

---

# 🧠 How to Respond

### ✔️ Reset MFA  
Force re-registration.

### ✔️ Invalidate sessions  
Terminate active tokens.

### ✔️ Reset password  
If compromise is suspected.

### ✔️ Escalate  
If account takeover or lateral movement is detected.

### ✔️ Notify the user  
Confirm whether the activity was legitimate.

---

# 📁 How This Fits Into Your Portfolio

This theory section demonstrates that you understand:

- how Sentinel detections work  
- why identity anomalies matter  
- how to interpret SigninLogs  
- how to apply MITRE ATT&CK  
- how to validate and investigate alerts  
- how to respond as a SOC Analyst (L1)  

Combined with your practical evidence, this forms a complete and professional detection entry suitable for SOC recruitment.
