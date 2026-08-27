```bash
day8-decoys/
│
├── README.md
│   ├── What is a decoy?
│   ├── Why decoys matters SOC?
│   ├── Sysmon detection #(Event ID 11)
│   ├── MITRE mapping
│   ├── Ransomware detection with decoys
│   └── Screenshots
│
├── decoy-setup.ps1
│   # Creates folder + decoy file
│
├── sysmon-config.xml
│   # Rules for detecting decoy access
│
└── screenshots/
    ├── sysmon-event11.png
    ├── ransomware-detection.png
    └── mitre-mapping.png
```
# 🪤 Day 8: Decoy‑Based Detection Lab (Honeyfiles for SOC Detection)

## 🎯 Purpose of This Lab
This day introduces **decoy files (honeyfiles)** as a defensive technique to detect suspicious behaviour, early attacker activity, and ransomware.  
A decoy file acts as a **tripwire**: legitimate users should never touch it, so **any access becomes a high‑value security signal**.

This lab teaches you how to:

- deploy decoy files on Windows  
- detect access using Sysmon  
- map behaviour to MITRE ATT&CK  
- identify early ransomware indicators  
- build detections around file access patterns  
- integrate decoys into SOC workflows  

---

# 🪤 What Is a Decoy File?

A **decoy file** is a deliberately placed, sensitive‑looking file designed to:

- attract attackers  
- generate telemetry when accessed  
- act as an early‑warning mechanism  
- reveal discovery, data theft, or ransomware behaviour  

Example decoy:
`C:\Finance\Confidential\passwords.txt`


No legitimate user should access this file.  
If someone does → **investigate immediately**.

---

# 🧪 Lab Setup

## 📁 1. Create the Decoy Folder

Use a realistic corporate path:
`C:\Finance\Confidential\`

## 📄 2. Create the Decoy File

Name it something attackers love:

`passwords.txt`

Content can be harmless (fake credentials, lorem ipsum, etc.).

## ⚙️ 3. Enable Sysmon File Monitoring

Sysmon Event ID **11** (FileCreate) and **13** (FileRename) are key for this lab.

Add rules to your Sysmon config:

```xml
<FileCreate onmatch="include">
    <TargetFilename condition="contains">passwords.txt</TargetFilename>
</FileCreate>

<FileRename onmatch="include">
    <TargetFilename condition="contains">passwords.txt</TargetFilename>
</FileRename>

<FileDelete onmatch="include">
    <TargetFilename condition="contains">passwords.txt</TargetFilename>
</FileDelete>
```
These rules generate telemetry whenever the decoy is: accessed, renamed, deleted encrypted.

| Behaviour | MITRE Technique | Description |
| --- | --- | --- |
| Directory exploration | **T1083 – File and Directory Discovery** | Attacker enumerates folders |
| Reading the decoy | **T1005 – Data from Local System** | Collecting local data |
| PowerShell touching the decoy | **T1059.001 – PowerShell** | Script‑based access |
| Renaming/encrypting the decoy | **T1486 – Data Encrypted for Impact** | Ransomware behaviour |
| Deleting the decoy | **T1070 – Indicator Removal** | Anti‑forensic behaviour |

# 🔥 Using Decoys to Detect Ransomware

Ransomware typically:

1. Enumerates directories  
2. Opens files  
3. Encrypts them  
4. Renames them  
5. Deletes originals  
6. Writes encrypted versions  

Your decoy file acts as a **high‑fidelity tripwire**.

### 🚨 Ransomware Indicators on the Decoy

- `passwords.txt` renamed to `passwords.txt.locked`  
- creation of encrypted files in the same directory  
- deletion of the original  
- rapid sequence of FileCreate → FileRename → FileDelete  
- access by unknown binaries  
- access by PowerShell with encoded commands  

### ✔️ Sysmon Events for Ransomware Detection

- **11** — encrypted file created  
- **13** — decoy renamed  
- **23** — decoy deleted  
- **1** — suspicious process execution  
- **10** — ransomware process accessing the decoy  

This is exactly how enterprise SOCs detect ransomware early.

---

#  SOC Workflow for Decoy Alerts

1. **Alert fires** (Sysmon or SIEM)  
2. **Check process tree**  
3. **Identify parent process**  
4. **Check for encoded PowerShell**  
5. **Check for rapid file operations**  
6. **Map behaviour to MITRE**  
7. **Assess ransomware likelihood**  
8. **Escalate if malicious**  

---

# 📘 What You Learned Today

- How decoys act as early‑warning sensors  
- How Sysmon detects file access  
- How to map decoy behaviour to MITRE  
- How to detect ransomware using honeyfiles  
- How to integrate decoys into SOC investigations  

---

---

# 📎 Additional Files Included in This Lab

- `decoy-setup.ps1` — PowerShell script to deploy decoys  
- `sysmon-config.xml` — Sysmon rules for decoy detection  
- `detection-flow-diagram.md` — ASCII diagram of detection flow  
- `soc-report-example.md` — Example SOC investigation report  




