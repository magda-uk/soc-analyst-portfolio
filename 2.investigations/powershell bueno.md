# Investigation Case: Suspicious PowerShell Encoded Command (T1059.001)

**Analyst:** Magdalena Domínguez Escudero  
**Date:** 03 September 2026  
**Status:** Completed  

## 1. Executive Summary

This investigation analyses a suspicious PowerShell execution involving encoded or obfuscated commands. Such behaviour is commonly associated with malware delivery, credential harvesting, and in-memory execution to bypass basic string-based security controls.

## 2. Initial Alert & MITRE ATT&CK Mapping

* **Detection Source:** Microsoft Sentinel / SIEM Rule (Suspicious PowerShell Execution)
* **MITRE ATT&CK Tactics & Techniques:**
  * Execution: Command and Scripting Interpreter: PowerShell (T1059.001)
  * Defense Evasion: Obfuscated Files or Information (T1027)

## 3. Evidence & Raw Telemetry (Sysmon Event ID 1)

The process creation log captured the execution of the interpreter utilizing the `-EncodedCommand` flag, which instructs PowerShell to parse a Base64-encoded Unicode payload.

![Sysmon Event ID 1 Properties](/2.investigations/images/investigation-2.2.png)

> *Figure 1: Sysmon Event ID 1 showing the EncodedCommand execution and parent-child process details.*

![PowerShell Console execution](/2.investigations/images/investigation-2.3.png)

> *Figure 2: PowerShell console demonstrating the encoding of the test command and its subsequent execution.*

## 4. Analysis & Triage Steps

 ### 1.**Command Line Inspection:** Reviewed the process creation telemetry (Sysmon Event ID 1) to identify the presence of the `-EncodedCommand` argument.

![PowerShell Console execution](/2.investigations/images/investigation-2.png)



### 2. **Payload Decoding:** Decoded the observed Base64 string (`VwByAGkAdABl...`) to reveal the underlying plaintext execution payload.
 **Decoded content:** `Write-Host 'SOC Analyst Portfolio Test - T1059.001'`

![PowerShell Console execution](/2.investigations/images/investigation-2.4.png)



### 3. **Parent-Child Process Correlation:** Traced the process lineage, confirming an interactive parent instance spawning an encoded child process.

![PowerShell Console execution](/2.investigations/images/investigation-2.5.png)


## 5. Findings

* The execution successfully utilized Base64 encoding to mask the direct command string from basic static text analysis.
* Validation confirmed the behavior matches typical living-off-the-land indicator patterns for administrative script abuse or adversary initial staging.

## 6. Conclusion & Response Actions

The detected activity aligns with adversarial PowerShell abuse patterns.

**Recommended Response:**

* **Telemetry Enhancement:** Ensure PowerShell Script Block Logging (Event ID 4104) is globally enabled to capture decrypted script contents regardless of command-line obfuscation.
* **Remediation:** Investigate the parent process lineage and verify user authorization for executing administrative scripting tools.