# 🔁 Incident Reconstruction — Cheat Sheet

## 1. Alert Fired
- SIEM / EDR / Defender
- Identify alert type, severity, source

## 2. Evidence Collection
- Sysmon (1, 3, 11)
- Windows Event Logs (4624, 4625)
- PowerShell ScriptBlock
- Wireshark captures
- Azure AD sign-ins
- Defender detections

## 3. Build Timeline
- Order events chronologically
- Identify key transitions (execution → network → persistence)

## 4. Build Process Tree
- Parent → Child → Grandchild
- Detect anomalies (LOLbins, odd paths, suspicious parents)

## 5. Behaviour Analysis
- Decode PowerShell
- Analyse outbound connections
- Check identity anomalies
- Look for persistence attempts

## 6. MITRE Mapping
- Assign tactics (TA0001–TA0014)
- Assign techniques (T1059, T1105, T1071, etc.)
- Classify each behaviour

## 7. Incident Narrative
- What happened?
- How?
- Why?
- Impact?
- Scope?

## 8. Final Report
- Evidence summary
- Timeline
- MITRE mapping
- Conclusion
- Recommendations
