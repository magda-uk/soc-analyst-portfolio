#  Detection Logic

Welcome to the **Detection Logic** directory. This folder contains the theoretical and conceptual documentation used to detect specific threats, attacker behaviours, and malware staging techniques. 

Instead of relying on platform-specific query languages, these documents break down the core logic, required event IDs (like Sysmon), MITRE ATT&CK mappings, known false positives, and triage steps.

##  Available Content

- [**Suspicious Executable File Creation**](filecreate.md)
- [**Encoded PowerShell Execution**](powershell-encoded.md)

## 🚧 Coming Soon 

I am currently researching, testing, and documenting the detection logic for the following threats. These will be published in the near future:

- ⏳ **Authentication Anomalies** (Brute force & anomalous logons)
- ⏳ **Process Injection** (CreateRemoteThread / T1055)
- ⏳ **DNS & WPAD** (Adversary-in-the-Middle techniques)
- ⏳ **LSASS Memory Access** (Pre-dumping phase)
- ⏳ **LSASS Credential Dumping** (Memory extraction)
- ⏳ **Suspicious Registry Modifications** (Persistence mechanisms)
- ⏳ **Time Stomping** (File attribute manipulation evasion)



---
*Authored by **Magda Dominguez** : Security Operations • Detection Engineering • Blue Team*  