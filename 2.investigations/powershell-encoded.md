# Investigation Case: Suspicious PowerShell Encoded Command (T1059.001)

## Summary
This investigation analyses a suspicious PowerShell execution involving encoded or obfuscated commands. Such behaviour is commonly associated with malware delivery, credential harvesting, and in‑memory execution.

## Initial Alert
- Detection: Suspicious PowerShell Execution (Sentinel)
- MITRE ATT&CK: T1059.001 – PowerShell

## Evidence
- Process: powershell.exe
- Indicators: "-enc", "IEX", "Invoke-WebRequest"
- Parent process: Unusual (not explorer.exe or cmd.exe)

## Analysis
1. Reviewed command line for obfuscation.
2. Checked parent process for signs of compromise.
3. Correlated with network events for outbound connections.
4. Verified user context and recent activity.

## Findings
- Encoded command present.
- Network connection to external host.
- Execution triggered by an unexpected parent process.

## Conclusion
Activity is consistent with malicious PowerShell usage. Further investigation required.

## Recommended Response
- Contain device.
- Review user account for lateral movement.
- Check for additional suspicious processes.

