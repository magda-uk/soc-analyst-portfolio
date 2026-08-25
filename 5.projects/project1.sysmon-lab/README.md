# Sysmon Lab Environment

### Objective
Build a learner‑friendly Windows telemetry lab to practice log analysis, validate detection rules and understand how real host-based events are generated.

### Setup
- Windows 10/11 virtual machine  
- Sysmon v14+  
- Custom Sysmon configuration (SwiftOnSecurity baseline)

### Activities Performed
- Executed benign and suspicious PowerShell commands  
- Simulated encoded command execution  
- Generated LSASS access events  
- Ran scripts via PowerShell and CMD to observe process behaviour

### Logs Generated
- Process creation (Event ID 1)  
- Network connections (Event ID 3)  
- DLL loads (Event ID 7)  
- Process access (Event ID 10)

### Outcome
Sysmon telemetry was used to understand normal vs suspicious behaviour and to validate Sigma, Sentinel and Elastic-compatible detection rules.
