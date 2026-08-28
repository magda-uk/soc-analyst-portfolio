#  LSASS Credential Dumping (Sentinel Detection)

## Description
This Sentinel detection identifies suspicious access to LSASS memory and credential dumping behaviour commonly associated with tools such as Mimikatz, `procdump.exe`, `comsvcs.dll` MiniDump, and `rundll32.exe`.

Credential dumping is a high-impact technique that enables attackers to obtain NTLM hashes, Kerberos tickets, plaintext passwords (in some configurations), and service account credentials. This behaviour typically precedes privilege escalation, lateral movement, and domain compromise.

---

## MITRE ATT&CK
* **T1003** — OS Credential Dumping
* **T1550** — Use of Stolen Credentials
* **T1558** — Kerberos Attacks

---

## KQL Detection Logic

```kql
DeviceProcessEvents
| where FileName in~ ("mimikatz.exe", "procdump.exe", "rundll32.exe")
    or ProcessCommandLine has_any ("sekurlsa", "lsass.dmp", "comsvcs.dll")
| project Timestamp, DeviceName, FileName, ProcessCommandLine, InitiatingProcessFileName, ParentProcessName
```
## Detection Notes

* `sekurlsa` is a strong indicator of Mimikatz credential extraction.
* `lsass.dmp` or any dump file created by non-system processes is highly suspicious.
* Loading `comsvcs.dll` is a known MiniDump technique used for LSASS dumping.

---

## Validation Steps

To validate this detection safely:

1. Trigger benign LSASS dumps using Windows Error Reporting.
2. Execute MiniDump via `comsvcs.dll` in a controlled lab.
3. Compare access rights and behavioural differences between legitimate and malicious dumps.
4. Validate that the rule does not trigger on EDR/AV legitimate LSASS access.

---

## Investigation Workflow

When this alert fires, the SOC analyst should:

### 1. Identify the process accessing LSASS
* Check binary signature
* Check hash reputation
* Check parent process
* Check command line

### 2. Look for dump file creation
Common filenames:
* `lsass.dmp`
* `*.dmp`

### 3. Review authentication logs
* Were stolen credentials used?
* Any unusual Kerberos activity?
* Any privilege escalation events?

### 4. Check for lateral movement
* Remote logins
* SMB sessions
* RDP connections
* Token manipulation

### 5. Assess scope
* Single host compromise
* Domain-wide risk
* Privileged accounts involved

---

## Response Actions

This is a high-severity incident. Recommended actions:

* **Isolate the host immediately** via EDR.
* **Rotate compromised credentials** across all potentially exposed accounts.
* **Review active sessions and tokens** to revoke persistent access.
* **Investigate potential domain escalation** in Active Directory or Entra ID.
* **Enable LSASS protection** (Credential Guard, WDAC, AppLocker, RunAsPPL).
* **Check for persistence mechanisms** (Scheduled tasks, run keys, services).

---

## Evidence to Collect

* Dump file (`lsass.dmp`, `*.dmp`)
* Binary hash (SHA-256) and signature verification
* Parent process metadata and execution tree
* Authentication logs post-dump
* Network activity linked to stolen credentials
* Any related process creation or DLL load events