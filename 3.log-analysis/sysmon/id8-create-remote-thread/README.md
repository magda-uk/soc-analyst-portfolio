# Sysmon Event ID 8 (CreateRemoteThread)

Sysmon Event ID 8 reports **CreateRemoteThread** activity, commonly associated with **process injection** (MITRE T1055.001).  
This directory contains three complementary analyses: two based on **real endpoint evidence**, and one **conceptual detection guide**.

---

## 1) Single‑Event Analysis  
**File:** `id8-create-remote-thread/createRemoteThread.md`  
**Case:** *WerFault.exe → PushNotificationsLongRunningTask.exe*

A genuine Sysmon Event ID 8 captured on the endpoint.  
The thread creation originates from **Windows Error Reporting** performing legitimate debugging operations.  
**Classification:** Benign false positive.

---

## 2) Multi‑Event Analysis  
**File:** `id8-multi-event/analisis-conjunto-EventID-8.md`  
**Case:** *dwm.exe → csrss.exe*

Another real Sysmon Event ID 8.  
This behaviour is normal within the Windows graphical subsystem (DWM interacting with CSRSS).  
**Classification:** Benign subsystem activity.

---

## 3) Detection & Tuning Guidance  
**File:** `id8-false-positive/false-positive.md`

A conceptual SOC document explaining how to analyse, tune, and detect CreateRemoteThread activity.  
Includes examples involving LSASS, Winlogon, svchost, debugging routines, and EDR behaviour.  
**Classification:** Detection reference (not evidence).

---

## Summary

| Component | Type | Purpose |
|----------|------|---------|
| Single‑event analysis | Real Sysmon evidence | Validate a benign debugging injection |
| Multi‑event analysis | Real Sysmon evidence | Validate benign subsystem behaviour |
| False‑positive guidance | Conceptual SOC document | Provide tuning and detection strategy |

Together, these documents demonstrate practical Sysmon triage, correct false‑positive classification, understanding of Windows internals, and SOC‑ready detection logic.
