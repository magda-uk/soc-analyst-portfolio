# Security Event Analysis: Special Privileges Assigned (Event ID 4672)

## 🟪 Summary
This analysis examines Windows Security Event ID 4672, which logs the assignment of sensitive privileges during a new logon session. The document evaluates two distinct scenarios: an interactive logon by a human user and a system-initiated service logon. While these events are often benign, they represent the granting of high-impact capabilities that must be scrutinised within the broader context of endpoint telemetry to identify potential unauthorised activity.

## 🟪 Case Study 1: Interactive User Logon (Account: magda.*********@outlook.com)

![EVENT 4672]( /3.log-analysis/windows-events/images/Event-4672.png)

An interactive logon event was identified on the endpoint Azul_Fifty associated with the Microsoft Account magda.*********@outlook.com. This session was granted a comprehensive set of administrative rights, including:

* **SeDebugPrivilege**: Allows the user to attach to and debug system processes.
* **SeLoadDriverPrivilege**: Enables the installation and removal of kernel-mode drivers.
* **SeBackupPrivilege** and **SeRestorePrivilege**: Grants access to any file on the system, bypassing ACLs.
* **SeImpersonatePrivilege**: Permits the account to act on behalf of other users.

The assignment of these rights confirms that this was an administrator-level session. In a corporate environment, such privileges are expected for authorised technical staff but should be correlated with the user’s role and scheduled tasks.

## 🟪 Case Study 2: System-Initiated Logon (Account: NT AUTHORITY\SYSTEM)
![EVENT 4672-4]( /3.log-analysis/windows-events/images/4672-4.png)


In contrast to interactive sessions, logons initiated by `services.exe` under the `NT AUTHORITY\SYSTEM` account are frequent and routine. These are typically classified as Logon Type 5 (Service). Because the SYSTEM account manages core OS functions, it is naturally assigned maximum privileges. This behaviour is expected system functionality and does not usually warrant individual investigation unless accompanied by anomalous service installation or modification.

## 🟪 Security Recommendations & Conclusion
Individual Event ID 4672 entries are rarely malicious on their own but are critical indicators of elevated capability. To ensure these privileges are not abused for persistence or lateral movement, security teams should correlate these logons with broader telemetry:

* **Sysmon Event ID 1 (Process Creation)**: To identify what processes were launched with these new rights.
* **Sysmon Event ID 10 (Process Access)**: Specifically looking for unauthorised access to LSASS for credential theft.
* **PowerShell Event ID 4104**: To audit any administrative scripts executed during the session.
* **Sysmon Event ID 3 (Network Connections)**: To detect potential lateral movement following a privileged logon.

In conclusion, while the analysed events on Azul_Fifty appear legitimate, continuous monitoring and contextual correlation remain essential for maintaining a secure environment.

## 🪪 Author

**Magda Dominguez**  
*SOC Analyst (L1-ready)  Bristol, UK*  
Focused on Blue Team operations, detection engineering and log analysis.