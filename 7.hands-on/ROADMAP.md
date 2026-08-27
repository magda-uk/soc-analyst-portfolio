┌──────────────────────────────────────────────────────────────────────────┐
│                         7–DAY BLUE TEAM ROADMAP                          │
└──────────────────────────────────────────────────────────────────────────┘

DAY 1 — Sysmon Baseline
────────────────────────────────────────────────────────────────────────────
• Build a clean baseline of normal endpoint behaviour  
• Learn core Sysmon events (1, 3, 11)  
• Identify anomalies in process paths and parent-child relationships  
→ Skill gained: Recognising normal vs suspicious activity

DAY 2 — Sysmon Suspicious Activity + Wireshark
────────────────────────────────────────────────────────────────────────────
• Detect suspicious PowerShell, CMD and network activity  
• Capture outbound traffic using Wireshark  
• Correlate Sysmon Event ID 3 with real packet data  
• Simulate a simple attack chain (execution → download → beaconing)  
→ Skill gained: Host–network correlation, a key SOC investigation skill

DAY 3 — PowerShell ScriptBlock Logging
────────────────────────────────────────────────────────────────────────────
• Enable ScriptBlock Logging  
• Identify suspicious commands and attacker keywords  
• Decode Base64 and spot obfuscation  
→ Skill gained: Analysing attacker behaviour through PowerShell

DAY 4 — Authentication & Identity Logs
────────────────────────────────────────────────────────────────────────────
• Investigate Windows logons and Azure AD sign-ins  
• Detect password spraying and impossible travel  
• Understand MFA flows and risky sign-ins  
→ Skill gained: Identity triage (core SOC responsibility)

DAY 5 — Process Trees & Attack Chains
────────────────────────────────────────────────────────────────────────────
• Build process trees and identify anomalies  
• Reconstruct full attack chains  
• Document suspicious lineage  
→ Skill gained: Incident reconstruction and analytical reasoning

DAY 6 — MITRE ATT&CK Mapping
────────────────────────────────────────────────────────────────────────────
• Map Sysmon and Windows events to MITRE techniques  
• Build a small heatmap  
• Document detections using MITRE language  
→ Skill gained: Structured analysis using industry frameworks

DAY 7 — End-to-End Investigation
────────────────────────────────────────────────────────────────────────────
• Build a timeline  
• Collect evidence  
• Map behaviour to MITRE  
• Produce a full investigation report  
→ Skill gained: Closing an incident like a real SOC L1 analyst

────────────────────────────────────────────────────────────────────────────
TOOLS USED: Sysmon • Windows Event Logs • PowerShell • Azure AD • MITRE ATT&CK • Wireshark
────────────────────────────────────────────────────────────────────────────

