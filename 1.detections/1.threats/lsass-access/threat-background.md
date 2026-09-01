# Suspicious LSASS Access

## Description
LSASS (Local Security Authority Subsystem Service) is a critical Windows process responsible for storing and managing sensitive authentication material such as:

- NTLM hashes
- Kerberos tickets
- Plaintext credentials (in some configurations)
- Security tokens

Any attempt by a non‑system process to access LSASS memory is highly suspicious and often a precursor to credential theft.

---

## How the Attack Works
Threat actors attempt to:

- Open a handle to `lsass.exe`
- Read LSASS memory
- Request elevated access rights
- Inspect or duplicate security tokens

This behaviour typically precedes full credential dumping.

---

## Why It Is Dangerous
- Early indicator of credential theft
- Used by Mimikatz and similar tools
- Enables privilege escalation
- Enables lateral movement
- High‑severity event in SOC operations

---

## MITRE ATT&CK
- **T1055 — Process Injection**
- **T1003 — Credential Access (pre‑dumping behaviour)**

---

## Detection Guidance
Monitor for:

- **Sysmon Event ID 10 — Process Access**
- `TargetImage = lsass.exe`
- Suspicious `GrantedAccess` values:
  - `0x40`
  - `0x1FFFFF`
  - `0x1010`

---

## Investigation Steps
Key questions:

- Which process accessed LSASS?
- Is the process legitimate (AV, EDR, system)?
- What access rights were requested?
- Is this behaviour repeated?
- Are there related process creation or DLL load events?

---

## Mitigation
- Enable Windows Defender Credential Guard
- Block LSASS access for non‑signed binaries
- Monitor Sysmon Event ID 10 closely
- Use EDR solutions with LSASS protection
- Restrict administrative privileges

---

## Evidence to Collect
- Process accessing LSASS
- Access rights requested
- Parent process
- Binary hash and signature
- Correlated process creation events
