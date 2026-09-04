#  Detection Rules as Code

 This folder contains the actual, deployable queries and rule definitions mapped directly from the conceptual documents in the `2.detection-logic` folder. 

These rules are written in native SIEM query languages and standard formats to demonstrate practical Implementation (Detection as Code).

##  Available Rules

### 🟦 Microsoft Sentinel (KQL)
- [**LSASS Credential Dumping**](sentinel/lsass-credential-dumping.kql)
- [**CreateRemoteThread Process Injection**](sentinel/create-remote-thread-injection.kql)

### 🟩 Elastic Security (EQL)
- [**LSASS Credential Dumping**](elastic/lsass-credential-dumping.eql)

### 🟨 Sigma (YAML)
- [**Suspicious LSASS Access**](sigma/suspicious-lsass-access.yaml)
- [**Suspicious PowerShell Execution**](sigma/suspicious-powershell-execution.yaml)

## 🚧 Coming Soon (Work in Progress)

More queries and rule definitions are currently being translated from the detection logic and will be added soon:

⏳ **Suspicious File Creation** (KQL & EQL implementations)

⏳ **Authentication Anomalies** (Sentinel/KQL Analytics Rules)

⏳ **Registry Modifications** (Sigma rules for persistence tracking)

⏳ **Time Stomping Evasion** (EQL queries)

---
*Authored by **Magda Dominguez** 🔹  Security Operations 🔹 Detection Engineering 🔹 Blue Team*