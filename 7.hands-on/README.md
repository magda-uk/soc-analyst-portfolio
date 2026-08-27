# 🛡️ Hands-On SOC Analyst Roadmap  
A practical, structured and progressive training path designed to build real SOC L1 / Blue Team capability.  
This folder contains seven days of hands-on exercises, each focused on a core skill required in modern security operations.

---

## 🎯 Purpose of this Hands-On Block  
This section of the portfolio demonstrates **practical capability**, not theory.  
Across seven days, I recreate realistic endpoint and identity scenarios using Windows logs, Sysmon, PowerShell, Azure AD and MITRE ATT&CK.

Each day includes:
- **Basic practice** (foundation skills)  
- **Advanced practice** (realistic SOC triage and investigation)  
- **Learning outcomes**  
- **How it supports my goal of becoming a Blue Team Analyst**  

---

# 📅 Seven-Day SOC Roadmap

---

## 🔍 Day 1 — Sysmon Baseline  
**Tools:** Sysmon, Windows Event Viewer  
**Focus:** Understanding normal endpoint behaviour.

### Basic practice  
- Install Sysmon with a standard configuration.  
- Review core events:  
  - Event ID 1 (Process Creation)  
  - Event ID 3 (Network Connection)  
  - Event ID 11 (File Create)  
- Build a baseline of normal processes, paths and command lines.

### Advanced practice  
- Identify deviations from baseline.  
- Spot unusual parent-child relationships.  
- Detect processes running from non-standard directories.

### Learning outcome  
Develop the ability to distinguish **normal vs suspicious activity**, a foundational SOC skill.

### Why it matters for Blue Team  
A SOC analyst must recognise anomalies quickly.  
This day builds the mental model needed for effective triage.

---

## ⚠️ Day 2 — Sysmon Suspicious Activity  
**Tools:** Sysmon, Event Viewer, simulated malicious commands  
**Focus:** Detecting and analysing suspicious behaviour.

### Basic practice  
- Identify suspicious PowerShell or CMD execution.  
- Review unexpected network connections.  
- Spot abnormal file creation activity.

### Advanced practice  
- Simulate a simple attack chain:  
  - script execution  
  - file download  
  - outbound beaconing  
- Correlate events across process, file and network activity.

### Learning outcome  
Learn to reconstruct malicious behaviour using Sysmon telemetry.

### Why it matters for Blue Team  
This is core SOC triage: spotting and validating suspicious endpoint activity.

---

## 💻 Day 3 — PowerShell ScriptBlock Logging  
**Tools:** PowerShell, ScriptBlock Logging, Base64 decoding  
**Focus:** Analysing attacker behaviour through PowerShell logs.

### Basic practice  
- Enable ScriptBlock Logging.  
- Identify benign vs suspicious commands.  
- Recognise common attacker keywords.

### Advanced practice  
- Decode Base64 payloads.  
- Identify obfuscation techniques.  
- Reconstruct a malicious script from fragments.

### Learning outcome  
Gain confidence analysing PowerShell — one of the most abused tools in Windows attacks.

### Why it matters for Blue Team  
SOC analysts frequently triage PowerShell alerts.  
This day builds the ability to interpret real attacker behaviour.

---

## 🔐 Day 4 — Authentication & Identity Logs  
**Tools:** Windows Security Logs, Azure AD Sign-In Logs  
**Focus:** Investigating identity-based anomalies.

### Basic practice  
- Review failed logons (Event ID 4625).  
- Understand MFA flows.  
- Identify normal authentication patterns.

### Advanced practice  
- Detect password spraying.  
- Analyse impossible travel.  
- Investigate risky sign-ins in Azure AD.

### Learning outcome  
Develop the ability to triage identity alerts — the most common SOC alert category.

### Why it matters for Blue Team  
Identity is the new perimeter.  
This day builds essential skills for modern SOC environments.

---

## 🌳 Day 5 — Process Trees & Attack Chains  
**Tools:** Sysmon, process tree visualisation  
**Focus:** Reconstructing the full story behind an alert.

### Basic practice  
- Build simple process trees.  
- Identify parent-child anomalies.

### Advanced practice  
- Reconstruct a full attack chain:  
  - phishing → payload → execution → network → persistence  
- Document suspicious process lineage.

### Learning outcome  
Learn to “tell the story” of an incident using telemetry.

### Why it matters for Blue Team  
SOC analysts must understand how attacks unfold, not just individual events.

---

## 🎯 Day 6 — MITRE ATT&CK Mapping  
**Tools:** MITRE ATT&CK framework, Sysmon logs  
**Focus:** Mapping behaviour to tactics and techniques.

### Basic practice  
- Identify common techniques (e.g., T1059, T1047, T1078).  
- Map Sysmon events to MITRE.

### Advanced practice  
- Build a small heatmap of observed techniques.  
- Document detections using MITRE language.  
- Map a Sigma rule to MITRE.

### Learning outcome  
Learn to classify behaviour using a universal SOC framework.

### Why it matters for Blue Team  
MITRE is used in detection engineering, reporting and investigation.  
This day builds analytical structure.

---

## 🕵️ Day 7 — End-to-End Investigation  
**Tools:** All previous tools combined  
**Focus:** Conducting a full SOC investigation.

### Basic practice  
- Choose a simple suspicious event.  
- Build a timeline.

### Advanced practice  
- Produce a full investigation report:  
  - evidence  
  - timeline  
  - MITRE mapping  
  - conclusion  
  - recommendation  
- Create a small triage playbook.

### Learning outcome  
Learn to investigate, document and close a case — the core SOC L1 responsibility.

### Why it matters for Blue Team  
This day demonstrates readiness for real SOC work.

---

# 🧪 How to Recreate These Practices  
*(Included because it adds clarity without weight.)*

To replicate these exercises:

1. **Set up a Windows VM** (Windows 10/11).  
2. **Install Sysmon** with a community or custom configuration.  
3. **Enable PowerShell ScriptBlock Logging**.  
4. **Generate benign and suspicious activity** using controlled commands.  
5. **Use Event Viewer** to explore Windows logs.  
6. **Use Azure AD free tier** to review sign-in logs.  
7. **Document everything** using markdown and screenshots.

This setup mirrors what a SOC analyst sees daily.

---

# 🛡️ Shields  
These shields summarise the technologies used across the seven days:

![Sysmon](https://img.shields.io/badge/Sysmon-Endpoint%20Telemetry-blue)  
![PowerShell](https://img.shields.io/badge/PowerShell-Logging-lightgrey)  
![MITRE ATT&CK](https://img.shields.io/badge/MITRE%20ATT%26CK-Tactics%20%26%20Techniques-red)  
![Azure AD](https://img.shields.io/badge/Azure%20AD-Identity%20Logs-purple)  
![Windows Logs](https://img.shields.io/badge/Windows-Event%20Logs-green)

---

# 📌 Summary  
This hands-on block is the backbone of my SOC Analyst portfolio.  
It demonstrates practical capability in:

- endpoint telemetry  
- identity investigation  
- PowerShell analysis  
- MITRE mapping  
- incident reconstruction  

Each day builds a skill essential for Blue Team work, forming a complete and realistic SOC learning path.

