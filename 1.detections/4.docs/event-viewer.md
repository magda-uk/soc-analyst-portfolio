# 🗺️ Event Viewer Investigation Map  
### A SOC Analyst’s Guide to High‑Value Windows Logs

This document maps out the most relevant Windows Event Viewer logs for SOC investigations.  
It complements existing evidence already documented in this portfolio:

- Sysmon Event ID 1 — Process Create  
- Sysmon Event ID 2 — File Creation Time Changed  
- Sysmon Event ID 8 — CreateRemoteThread  
- Sysmon Event ID 13 — RegistryEvent  
- Sysmon Event ID 3 — Pending (Network Connection + Wireshark)

The following sections outline additional logs worth investigating, why they matter, and what evidence can be produced from them.

---

## 🟦 1. Security Log (Windows Security Auditing)

The Security log is the **core of authentication triage** and identity‑related investigations.

### 🔹 High‑Value Event IDs
- **4624** — Successful logon  
- **4625** — Failed logon  
- **4634** — Logoff  
- **4672** — Special privileges assigned  
- **4688** — Process creation (Windows native)  
- **4697** — Service installation  
- **4720** — Account created  
- **4726** — Account deleted  
- **4768 / 4769 / 4771** — Kerberos authentication events

### 🔹 Why it matters
These events reveal:
- brute force attempts  
- password spraying  
- lateral movement  
- privilege escalation  
- persistence via services  
- suspicious account activity  
- Kerberos abuse (golden ticket, silver ticket, AS‑REP roasting)

### 🔹 Evidence you can produce
- Failed logon triage  
- RDP brute force detection  
- Suspicious service installation  
- Kerberos anomalies  
- Account creation/deletion investigations

---

## 🟦 2. Sysmon (Microsoft-Windows-Sysmon/Operational)

Sysmon provides **high‑fidelity host telemetry**.  
You already documented several key events.

### 🔹 Additional Sysmon Event IDs worth investigating
- **3 — Network Connection**  
  → Combine with Wireshark for host ↔ network correlation  
- **7 — Image Loaded**  
  → DLL hijacking, unsigned modules, LOLBins  
- **10 — ProcessAccess**  
  → LSASS access, credential theft  
- **11 — FileCreate**  
  → Malware dropping payloads  
- **22 — DNS Query**  
  → C2 domains, suspicious lookups  
- **23 — FileDelete**  
  → Anti‑forensics  
- **24 — ClipboardChange**  
  → Keyloggers, data theft  
- **25 — ProcessTampering**  
  → Rare but extremely valuable

### 🔹 Why it matters
Sysmon is the backbone of:
- detection engineering  
- threat hunting  
- forensic reconstruction  
- behaviour‑based analysis

### 🔹 Evidence you can produce
- DLL hijacking detection  
- LSASS access triage  
- DNS C2 investigation  
- File dropper analysis  
- Network connection mapping (Sysmon + Wireshark)

---

## 🟦 3. PowerShell Operational Log

Location:
Applications and Services Logs
→ Microsoft
→ Windows
→ PowerShell
→ Operational

### 🔹 High‑Value Event IDs
- **4103 — Module Logging**  
- **4104 — Script Block Logging**  
- **4105 — Pipeline Execution**  
- **4106 — Provider Lifecycle**

### 🔹 Why it matters
PowerShell is a favourite tool for:
- fileless malware  
- obfuscation  
- lateral movement  
- credential theft  
- AMSI bypass  
- C2 frameworks (Empire, Covenant, PowerSploit)

### 🔹 Evidence you can produce
- Script block analysis  
- Obfuscated command detection  
- PowerShell‑based malware triage  
- AMSI bypass attempts

---

## 🟦 4. Windows Defender Logs

Location:
Applications and Services Logs
→ Microsoft
→ Windows
→ Windows Defender

### 🔹 High‑Value Event IDs
- **1116 — Malware detected**  
- **5007 — Settings changed**  
- **5010 — Tampering detected**

### 🔹 Why it matters
Shows:
- real malware detections  
- attempts to disable Defender  
- suspicious configuration changes

### 🔹 Evidence you can produce
- Malware detection timeline  
- Defender tampering investigation  
- Correlation with Sysmon (file creation, process access)

---

## 🟦 5. Application Log

### 🔹 High‑Value Event IDs
- **1000 — Application Error**  
- **1026 — .NET Runtime Error**  
- **2004 — Resource Exhaustion Detector**

### 🔹 Why it matters
Useful for:
- malware causing crashes  
- .NET abuse  
- resource exhaustion attacks  
- suspicious application failures

### 🔹 Evidence you can produce
- Crash analysis  
- Suspicious .NET behaviour  
- Memory exhaustion triage

---

## 🟦 6. System Log

### 🔹 High‑Value Event IDs
- **7036 — Service state change**  
- **7000 — Service failed to start**  
- **6005 — Event Log service started**  
- **6006 — Event Log service stopped**

### 🔹 Why it matters
Shows:
- persistence via services  
- malware disabling logging  
- suspicious restarts  
- system instability caused by attacks

### 🔹 Evidence you can produce
- Service persistence investigation  
- Logging tampering  
- System restart analysis

---

## 🟦 7. Windows Error Reporting (WER)

Location:
Applications and Services Logs
→ Microsoft
→ Windows
→ Windows Error Reporting

### 🔹 Why it matters
WER interacts with:
- WerFault.exe  
- crash dumps  
- diagnostics  
- CreateRemoteThread (legitimate)

Perfect for correlating with Sysmon Event ID 8.

### 🔹 Evidence you can produce
- Legitimate vs suspicious CreateRemoteThread  
- Crash dump analysis  
- Application fault correlation

---

## 🟦 8. Additional Logs Worth Investigating

### ✔ Microsoft-Windows-TerminalServices  
RDP activity, session hijacking, remote logons.

### ✔ Microsoft-Windows-Bits-Client  
BITS abuse for malware download.

### ✔ Microsoft-Windows-TaskScheduler  
Scheduled task persistence.

### ✔ Microsoft-Windows-WMI-Activity  
WMI persistence, lateral movement.

### ✔ Microsoft-Windows-SMBClient  
SMB lateral movement, file exfiltration.

---

# 🧩 Summary — What You Should Add Next

You already have:
- Sysmon 1  
- Sysmon 2  
- Sysmon 8  
- Sysmon 13  
- Sysmon 3 (pending)

To reach **SOC Analyst professional level**, add:

### 🔥 High‑priority next investigations
- Sysmon 3 + Wireshark  
- Sysmon 7 (Image Loaded)  
- Sysmon 10 (LSASS access)  
- Sysmon 11 (FileCreate)  
- Sysmon 22 (DNS Query)  
- Security Log 4624 / 4625 / 4672  
- PowerShell 4104  
- Defender 1116  
- WER correlation with Sysmon 8


---

### **Authored by**  
**Magda Dominguez**  
Security Operations • Detection Engineering • Blue Team
