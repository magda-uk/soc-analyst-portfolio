# LSASS Credential Dumping (Mimikatz)

## Description
Credential dumping is the process of extracting authentication secrets directly from LSASS memory. This includes:

- NTLM hashes
- Kerberos tickets
- Plaintext passwords (in certain configurations)
- Service account credentials

Tools commonly used:

- Mimikatz
- procdump.exe
- comsvcs.dll MiniDump
- rundll32.exe

---

## How the Attack Works
Typical attack flow:

1. Attacker gains local privilege
2. Accesses LSASS memory
3. Creates a dump file (`lsass.dmp`)
4. Extracts credentials
5. Uses stolen credentials for lateral movement or privilege escalation

---

## Why It Is Critical
- Full compromise of the host
- Enables Domain Admin escalation
- Enables Golden Ticket attacks
- Enables long‑term persistence
- High‑impact incident requiring immediate response

---

## MITRE ATT&CK
- **T1003 — Credential Dumping**
- **T1550 — Use of Stolen Credentials**
- **T1558 — Kerberos Attacks**

---

## Detection Guidance
Look for:

- **Sysmon Event ID 1** — suspicious process creation (Mimikatz, procdump)
- **Sysmon Event ID 7** — loading of `comsvcs.dll`
- **Sysmon Event ID 10** — LSASS access
- Creation of dump files:
  - `lsass.dmp`
  - `*.dmp`

---

## Investigation Steps
Key questions:

- Which credentials were extracted?
- Were the credentials used afterwards?
- Is there evidence of lateral movement?
- Which process created the dump?
- Are there suspicious authentication events following the dump?

---

## Mitigation
- Enable Credential Guard
- Block dumping tools via AppLocker/WDAC
- Monitor MiniDump behaviour
- Rotate compromised credentials
- Review active sessions and tokens

---

## Evidence to Collect
- Dump file
- Binary hash and signature
- Parent process
- Authentication logs post‑dump
- Network activity linked to stolen credentials
