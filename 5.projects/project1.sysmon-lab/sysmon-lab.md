# Sysmon Lab Environment

## Objective
To generate high-fidelity Windows telemetry for detection validation and log analysis.

## Setup
- Windows 10/11 VM
- Sysmon v14+
- Custom Sysmon configuration (SwiftOnSecurity baseline)

## Activities Performed
- Simulated PowerShell encoded commands.
- Generated LSASS access events.
- Executed benign and suspicious scripts.

## Logs Generated
- Process creation (Event ID 1)
- Network connections (Event ID 3)
- DLL loads (Event ID 7)
- Process access (Event ID 10)

## Outcome
Sysmon logs used to validate Sentinel, Elastic and Sigma detections.

