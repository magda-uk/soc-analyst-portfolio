# Security Event Analysis: Special Privileges Assigned (Event ID 4672) 
![Windows Event Logs](https://img.shields.io/badge/Windows_Event_Logs-Event_4672-0078D4?style=flat-square&logo=windows&logoColor=white)
![Privilege Escalation](https://img.shields.io/badge/Privilege_Escalation-T1134-FF6600?style=flat-square)
![MITRE ATT&CK](https://img.shields.io/badge/MITRE%20ATT&CK%C2%AE-Mapped-FF6600?style=flat-square)


## 🟪 Summary
This analysis examines Windows Security Event ID 4672, which logs the assignment of sensitive privileges during a new logon session. 

The document evaluates two distinct scenarios: an interactive logon by a human user and a system-initiated service logon. 

While these events are often benign, they represent the granting of high-impact capabilities that must be scrutinised within the broader context of endpoint telemetry to identify potential unauthorised activity.

## 🟪 MITRE ATT&CK Mapping
While the generation of Event ID 4672 is a standard OS function, the specific privileges granted are prime targets for adversaries attempting to elevate access or evade defenses.

 The privileges observed in this analysis map to the following techniques:

*   **Privilege Escalation:** Access Token Manipulation ([T1134](https://attack.mitre.org/techniques/T1134/))
    *   *Context:* Adversaries abuse `SeImpersonatePrivilege` to duplicate tokens from higher-privileged processes (e.g., PrintSpoofer or Potato privilege escalation exploits).
*   **Credential Access:** OS Credential Dumping: LSASS Memory ([T1003.001](https://attack.mitre.org/techniques/T1003/001/))
    *   *Context:* `SeDebugPrivilege` is fundamentally required for an attacker (or tools like Mimikatz) to open a handle to `lsass.exe` and extract credentials from memory.
*   **Credential Access:** OS Credential Dumping: NTDS ([T1003.003](https://attack.mitre.org/techniques/T1003/003/))
    *   *Context:* `SeBackupPrivilege` allows adversaries to bypass file read locks and Access Control Lists (ACLs) to copy sensitive databases like the Active Directory `ntds.dit` file.

## 🟪 Case Study 1: Interactive User Logon 
## (Account: magda.*********@outlook.com)

![EVENT 4672]( /3.log-analysis/windows-events/images/Event-4672.png)

An interactive logon event was identified on the endpoint Azul_Fifty associated with the Microsoft Account magda.*********@outlook.com. This session was granted a comprehensive set of administrative rights, including:

* **SeDebugPrivilege**: Allows the user to attach to and debug system processes.
* **SeLoadDriverPrivilege**: Enables the installation and removal of kernel-mode drivers.
* **SeBackupPrivilege** and **SeRestorePrivilege**: Grants access to any file on the system, bypassing ACLs.
* **SeImpersonatePrivilege**: Permits the account to act on behalf of other users.

The assignment of these rights confirms that this was an administrator-level session. In a corporate environment, such privileges are expected for authorised technical staff but should be correlated with the user’s role and scheduled tasks.

## 🟪 Case Study 2: System-Initiated Logon 
## (Account: NT AUTHORITY\SYSTEM)
![EVENT 4672-4]( /3.log-analysis/windows-events/images/4672-4.png)


In contrast to interactive sessions, logons initiated by `services.exe` under the `NT AUTHORITY\SYSTEM` account are frequent and routine. These are typically classified as Logon Type 5 (Service). Because the SYSTEM account manages core OS functions, it is naturally assigned maximum privileges. 

This behaviour is expected system functionality and does not usually warrant individual investigation unless accompanied by anomalous service installation or modification.

## 🟪 Hunting & Correlation Logic
Identifying an Event 4672 is only the first step. To determine if the assigned privileges were abused, analysts must correlate the logon session with subsequent endpoint activity. 

Below is an example of correlation logic (KQL) designed to identify processes (Sysmon Event ID 1) spawned by a user within a tight time window immediately following a privileged logon (Event 4672).

### Correlating Privileged Logons with Process Creation (Sysmon 1)
This query hunts for high-risk binaries (like PowerShell or Command Prompt) executing right after `SeDebugPrivilege` or `SeImpersonatePrivilege` are granted:

```q
// 1. Identify high-privilege assignments
let PrivilegedLogons = SecurityEvent
| where EventID == 4672
| where PrivilegeList has_any ("SeDebugPrivilege", "SeImpersonatePrivilege")
| project LogonTime = TimeGenerated, Account, TargetLogonId, PrivilegeList;
// 2. Correlate with Process Creation (Sysmon Event ID 1)
Sysmon_Event_1_Table // (Adjust table name based on specific SIEM schema)
| where EventID == 1
| join kind=inner (PrivilegedLogons) on Account
// 3. Ensure the process occurred within 5 minutes of the privilege assignment
| where TimeGenerated between (LogonTime .. (LogonTime + 5m))
| where Image has_any ("powershell.exe", "cmd.exe", "rundll32.exe")
| project TimeGenerated, Account, PrivilegeList, Image, CommandLine, ParentImage
```

## 🟪 Security Recommendations & Conclusion
Individual Event ID 4672 entries are rarely malicious on their own but are critical indicators of elevated capability. 

To ensure these privileges are not abused for persistence or lateral movement, security teams should correlate these logons with broader telemetry:

* **Sysmon Event ID 1 (Process Creation)**: To identify what processes were launched with these new rights.
* **Sysmon Event ID 10 (Process Access)**: Specifically looking for unauthorised access to LSASS for credential theft.
* **PowerShell Event ID 4104**: To audit any administrative scripts executed during the session.
* **Sysmon Event ID 3 (Network Connections)**: To detect potential lateral movement following a privileged logon.

In conclusion, while the analysed events on Azul_Fifty appear legitimate, continuous monitoring and contextual correlation remain essential for maintaining a secure environment.

## 🪪 Author

**Magda Dominguez**  
*SOC Analyst (L1-ready)  Bristol, UK*  
Focused on Blue Team operations, detection engineering and log analysis.