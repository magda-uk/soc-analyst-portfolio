# Detection Logic: LSASS Credential Dumping

## 🎯 Objective
Identify suspicious access to LSASS (Local Security Authority Subsystem Service) memory and credential dumping behaviour commonly associated with tools such as Mimikatz, `procdump.exe`, `comsvcs.dll` MiniDump, and `rundll32.exe`.

##  Threat Background
Credential dumping is a high-impact technique that enables attackers to obtain NTLM hashes, Kerberos tickets, plaintext passwords, and service account credentials from memory. This behaviour typically precedes privilege escalation, lateral movement, and domain compromise.

##  MITRE ATT&CK Mapping
- **Tactic:** Credential Access (TA0006)
- **Techniques:** 
  - OS Credential Dumping: LSASS Memory (T1003.001)
  - Use of Stolen Credentials (T1550)
  - Kerberos Attacks (T1558)

##  Detection Notes & Conceptual Logic
- **`sekurlsa`**: A strong indicator of Mimikatz credential extraction in command lines.
- **`lsass.dmp`**: Any dump file created by non-system processes is highly suspicious.
- **`comsvcs.dll`**: Loading this DLL is a known native Living-off-the-Land (LotL) MiniDump technique used to dump LSASS memory.

##  Validation Steps
To validate this detection safely in a controlled lab:
1. Trigger benign LSASS dumps using Windows Error Reporting to observe normal behaviour.
2. Execute MiniDump via `comsvcs.dll` (e.g., `rundll32.exe C:\Windows\System32\comsvcs.dll, MiniDump <lsass_pid> lsass.dmp full`).
3. Compare access rights and behavioural differences between legitimate and malicious dumps.
4. Validate that the rule does not trigger on legitimate EDR/AV LSASS access.

##  Investigation Workflow
When this alert fires, the SOC analyst should:

**1. Identify the process accessing LSASS**
- Check the binary signature and hash reputation (e.g., via VirusTotal).
- Review the parent process lineage and command-line arguments.

**2. Look for dump file creation**
- Search for common filenames: `lsass.dmp` or `*.dmp` in unexpected directories (like `Temp`).

**3. Review authentication logs**
- Were stolen credentials used shortly after the event?
- Is there any unusual Kerberos activity (e.g., Pass-the-Ticket)?
- Are there any privilege escalation events?

**4. Check for lateral movement**
- Look for remote logins, SMB sessions, RDP connections, or Token manipulation stemming from the compromised host.

**5. Assess scope**
- Is this a single host compromise or a domain-wide risk?
- Are privileged accounts (e.g., Domain Admins) involved?

##  Response Actions (High Severity)
- **Isolate the host immediately** via EDR network containment.
- **Rotate compromised credentials** across all potentially exposed accounts.
- **Review active sessions and tokens** to revoke persistent access.
- **Investigate potential domain escalation** in Active Directory or Entra ID.
- **Enable LSASS protection** (Credential Guard, WDAC, AppLocker, RunAsPPL) to prevent future attacks.
- **Check for persistence mechanisms** (Scheduled tasks, run keys, services).

##  Evidence to Collect
- Dump file (`lsass.dmp`, `*.dmp`)
- Binary hash (SHA-256) and signature verification
- Parent process metadata and execution tree
- Authentication logs post-dump
- Network activity linked to stolen credentials
- Any related process creation or DLL load events