#  Suspicious PowerShell Encoded Commands

## Description
PowerShell is one of the most powerful administrative tools in Windows, and therefore one of the most abused by threat actors. Encoded commands (`-enc`) are frequently used to conceal malicious activity such as payload execution, reconnaissance, or remote command delivery.

Attackers rely on Base64 encoding to hide intent, bypass basic detection, and execute fileless malware.

---

## How the Attack Works
A typical malicious execution looks like:
`powershell.exe -enc <base64_payload>`


The decoded payload often includes:

- Downloading remote scripts
- Executing obfuscated commands
- Establishing C2 communication
- Performing reconnaissance
- Running fileless malware

---

## Why It Is Dangerous
- Encoded commands hide malicious intent
- Common in ransomware and APT intrusions
- Enables fileless execution
- Frequently used in initial access and lateral movement
- Very high prevalence in real SOC environments

---

## MITRE ATT&CK
- **T1059.001 — PowerShell**
- **T1027 — Obfuscated/Encoded Commands**
- **T1105 — Ingress Tool Transfer**

---

## Detection Guidance
Look for the following indicators:

- **Sysmon Event ID 1** (Process Creation)
- `Image = powershell.exe`
- `CommandLine` contains:
  - `-enc`
  - `IEX`
  - `Invoke-WebRequest`
  - Long Base64 strings

---

## Investigation Steps
Key questions for analysts:

- What does the Base64 decode to?
- Does the script download or execute remote content?
- What is the parent process?
- Are there related network connections?
- Is this behaviour expected for the user or host?

---

## Mitigation
- Enable PowerShell Script Block Logging
- Enforce Constrained Language Mode
- Use AppLocker or WDAC to restrict PowerShell
- Enable AMSI (Anti-Malware Scan Interface)
- Monitor for suspicious parent-child process chains

---

## Evidence to Collect
- Full command line
- Decoded script
- Parent process details
- Network activity
- Hashes of downloaded content

