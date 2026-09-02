# Windows Security Events Log Analysis
# Windows Security Events

This directory contains structured analyses of key Windows Security Log events relevant to authentication, privilege escalation, administrative activity, and early detection of malicious behaviour. Each entry provides a clear explanation of the event, its operational context, and recommended correlation with additional telemetry used in SOC investigations.

## Purpose of This Section

The goal of this module is to build a professional, SOC‑ready reference of Windows Security Events, supporting:

* Incident triage and investigation
* Detection of suspicious authentication patterns
* Identification of privilege misuse
* Correlation with Sysmon, PowerShell, and network logs
* Development of Blue Team analytical skills
* Documentation for a security portfolio

## Directory Structure

| File | Description |
| :--- | :--- |
| `README.md` | Overview of the Windows Security Events analysis module. |
| `4672-special-privileges-assigned.md` | Analysis of Event ID 4672: Special Privileges Assigned. |
| *(Upcoming additions)* | `4624`/`4625` Logon, `4688` Process Creation, `4697` Service Installation, etc. |

## Current Event Analysis Included

### Event ID 4672 — Special Privileges Assigned

This event is generated when a user or service receives sensitive privileges during a new logon session. These privileges allow high‑impact actions such as debugging system processes, loading drivers, accessing any file regardless of ACLs, or impersonating other accounts.

The analysis in this directory covers:

* Interactive logon by a Microsoft Account with administrator‑level privileges
* Service logon by `NT AUTHORITY\SYSTEM`
* Expected behaviour vs. suspicious indicators
* Recommended correlation with Sysmon and PowerShell logs

## Recommended Correlation for SOC Workflows

To determine whether a privileged logon is legitimate or part of malicious activity, correlate Windows Security Events with:

* **Sysmon Event ID 1** — Process Creation
* **Sysmon Event ID 10** — Process Access (LSASS)
* **PowerShell Event ID 4104** — ScriptBlock Logging
* **Sysmon Event ID 3** — Network Connections

This correlation helps identify privilege abuse, credential theft attempts, persistence mechanisms, and lateral movement.

## Summary

This directory forms part of a broader SOC Analyst portfolio, documenting high‑value Windows Security Events with clear, structured, and actionable analysis. Additional event write‑ups will be added to expand coverage of authentication, process creation, service installation, and other critical security signals.