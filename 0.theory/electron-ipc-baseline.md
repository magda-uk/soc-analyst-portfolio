# Application Architecture Baseline: Electron IPC & Sysmon Event ID 8

## 🎯 Purpose
This document provides a technical baseline for analysing process behavior in desktop applications built on the Electron framework. It explains why applications like VS Code or Slack generate alerts mimicking threat activity and how to tune detections to reduce analyst fatigue.

---

## 🏗️ Core Architecture
Electron applications (such as VS Code, Slack, Microsoft Teams, and Discord) use a multi-process model derived from Chromium and Node.js:
* **Main Process:** Controls application lifecycle and core logic.
* **Renderer Processes:** Render individual windows and UI components.
* **Extension Host / GPU Process:** Handle extensions and hardware acceleration.

Because these processes need to coordinate constantly, they utilize **Inter-Process Communication (IPC)**, which inherently involves cross-process actions.

---

## ⚠️ The Detection Challenge (Sysmon Event ID 8)
Sysmon **Event ID 8 (CreateRemoteThread)** logs when one process allocates a thread in another process's virtual memory space. 
* **The Dilemma:** Sysmon cannot inherently distinguish between malicious code injection (MITRE T1055) and legitimate internal process coordination.
* **The Result:** Standard detection rules often flag Electron-based applications for creating remote threads, generating noisy false positives for SOC analysts.

---

## 🔍 Investigation & Validation (Benign vs. Malicious)

### When it is Benign (Electron IPC):
* `SourceImage == TargetImage` (The process interacts with itself or its direct child processes).
* Both processes operate under the exact same user context.
* `StartModule` points to verified legitimate binaries.
* Memory allocations do not contain `RWX` (Read-Write-Execute) permissions with `MEM_PRIVATE`.

### When to Investigate Further (True Positive):
* `SourceImage ≠ TargetImage` across completely unrelated applications.
* Privilege escalation occurs (e.g., standard user process targeting a `SYSTEM` or `LSASS` process).
* Unsigned or unexpected DLLs appear in the target memory space.

---

## 🛡️ Recommended Detection Tuning
To eliminate noise from standard developer and productivity tools, detection rules should incorporate environment-specific filters:

```kusto
SourceImage == TargetImage
AND Image in~ ("C:\\Users\\...\\AppData\\Local\\Programs\\Microsoft VS Code\\Code.exe", ...)
```
Applying this tuning, successfully cuts down alert fatigue originating from Electron-based tools like VS Code, Slack, Teams, and Discord, allowing analysts to focus on genuine threats.

## 📚 References 


* [Electron main and renderer processes](https://medium.com/cameron-nokes/deep-dive-into-electrons-main-and-renderer-processes-7a9599d5c9e2)
*  [Chromium Multi‑Process Modelext](https://www.chromium.org/developers/design-documents/multi-process-architecture/)
*  [VS Code Architecturet](https://code.visualstudio.com/api/extension-capabilities/overview)
*  [Why Electron uses multiple processes](https://www.electronjs.org/docs/latest/tutorial/process-model)