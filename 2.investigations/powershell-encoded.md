# 🔲Investigation Case
# Threat Hunting for PowerShell Obfuscation (T1059.001)
**Analyst:** Magdalena Domínguez 

**Date:** 03 September 2026  
**Status:** Completed  

## ▪️ 1. Summary

This investigation analyses a suspicious PowerShell execution involving encoded or obfuscated commands. Such behaviour is commonly associated with malware delivery, credential harvesting, and in-memory execution to bypass basic string-based security controls.

## ▪️ 2. Incident Context and Source
###  Detection Source:
Host-based Telemetry (Windows Event Viewer - Sysmon Operational Logs) / Proactive Threat Hunting

## ▪️3. MITRE ATT&CK Mapping
  * Execution: Command and Scripting Interpreter: PowerShell ([T1059.001](https://attack.mitre.org/techniques/T1059/001/))
  * Defense Evasion: Obfuscated Files or Information ([T1027](https://attack.mitre.org/techniques/T1027/))

## ▪️4. Evidence & Raw Telemetry (Sysmon Event ID 1)

The process creation log captured the execution of the interpreter utilizing the `-EncodedCommand` flag, which instructs PowerShell to parse a Base64-encoded Unicode payload.

```yaml
Process Create:
RuleName: -
UtcTime: 2026-09-03 16:55:06.945
ProcessGuid: {79317113-a66a-6a99-1e06-060000005000}
ProcessId: 177228
Image: C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe
CommandLine: "C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe" -EncodedCommand VwByAGkAdABlAC0ASABvAHMAdAAgACcAUwBPAEMAIABBAG4AYQBsAHkAcwB0ACAAUABvAHIAdABmAG8AbABpAG8AIABUAGUAcwB0ACAALQAgAFQAMQAwADUAOQAuADAAMAAxACcA
CurrentDirectory: C:\Users\magda\
User: Azul_Fifty\magda
ParentProcessImage: C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe
ParentCommandLine: "C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe"
```
> *Figure 1: Sysmon Event ID 1 showing the EncodedCommand execution and parent-child process details.*


![PowerShell Console execution](/2.investigations/images/investigation-2.2.png)

> *Figure 2: PowerShell console demonstrating the encoding of the test command and its subsequent execution.*

## ▪️5. Analysis & Triage Steps

 ### 1. **Command Line Inspection:** Reviewed the process creation telemetry (Sysmon Event ID 1) to identify the presence of the `-EncodedCommand` argument.

![PowerShell Console execution](/2.investigations/images/investigation-2.png)

> *Figure 3: Sysmon Event ID 1 log highlighting the presence of the -EncodedCommand flag and the Base64 payload.*



### 2. **Payload Decoding:** Decoded the observed Base64 string (`VwByAGkAdABl...`) to reveal the underlying plaintext execution payload.
 **Decoded content:** `Write-Host 'SOC Analyst Portfolio Test - T1059.001'`

![PowerShell Console execution](/2.investigations/images/investigation-2.5.png)

> *Figure 4: PowerShell console demonstrating the decoding of the Base64 string to reveal the plaintext payload.*


### 3. **Parent-Child Process Correlation:** Traced the process lineage, confirming an interactive parent instance spawning an encoded child process.

![PowerShell Console execution](/2.investigations/images/parent%204.3.png)

> *Figure 5: Sysmon log highlighting the Parent Process ID and Image, tracing the execution lineage.*


## ▪️6. Findings

- The execution successfully utilized Base64 encoding to mask the direct command string from basic static text analysis.

- Validation confirmed the behavior matches typical living-off-the-land indicator patterns for administrative script abuse or adversary initial staging.

## ▪️7. Conclusion & Response Actions

The detected activity aligns with adversarial PowerShell abuse patterns.

**Recommended Response:**

* **Telemetry Enhancement:** Ensure PowerShell Script Block Logging (Event ID 4104) is globally enabled to capture decrypted script contents regardless of command-line obfuscation.
* **Remediation:** Investigate the parent process lineage and verify user authorization for executing administrative scripting tools.