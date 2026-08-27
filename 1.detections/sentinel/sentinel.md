# Microsoft Sentinel : Practical Detection Engineering (Theory + Explained Examples)

This document provides practical Microsoft Sentinel detections written in **Kusto Query Language (KQL)**, each accompanied by clear explanations suitable for junior SOC Analysts.

It complements the theory file:
**sentinel-detections-theory.md**


---

# 1. Suspicious PowerShell Execution (Encoded Commands)

## 🎯 Purpose
Detect PowerShell launched with **encoded commands**, a common technique used to hide malicious behaviour.

## 🔍 Why This Matters
Attackers frequently use: `powershell.exe -enc <base64>` to execute payloads without exposing readable commands.

This is a strong indicator of:
- malware execution  
- lateral movement  
- credential theft  
- script-based attacks  

## 🧠 MITRE Mapping
- **T1059.001 — PowerShell**  
- **T1027 — Obfuscated Commands**  

## 🧪 Detection Logic (KQL)
```kql
DeviceProcessEvents
| where FileName == "powershell.exe"
| where ProcessCommandLine contains "-enc"
```
